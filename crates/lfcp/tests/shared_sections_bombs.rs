//! Refused Data Units are never expanded (rw finding F1): a section replica
//! that refuses a change at SHARED-OBJECTS-PROFILE-01 §11 or §11.1 must not
//! hand its bytes to Automerge afterwards, which would expand an RLE or a
//! DEFLATE bomb before failing.

#![cfg(feature = "shared-sections")]

use std::io::Write;
use std::time::{Duration, Instant};

use automerge::transaction::Transactable;
use automerge::{legacy, ActorId, AutoCommit, Change, ObjType, ScalarValue, ROOT};
use flate2::write::DeflateEncoder;
use flate2::Compression;
use lfcp::base::{PrincipalId, ResourceId};
use lfcp::shared_objects::framing;
use lfcp::shared_sections::{self, Received, Refusal, SectionsReplica};

/// F1a: a change whose RLE run counts declare 2^24 operations, 121 bytes of
/// plaintext. Parsing it took about 13 s of CPU.
const RLE_BOMB: &str = "82015875856f4a837a0758f7016b0164216dc9d546ffb21a1cca664060ce4703b42329e8d3aef26273a1614a221d9b206c9e962e697f0691ba727ddc378cc21f9b1d580e67f7b1e7f9612ebdab63c5830202000000051506340442055605700580808008016b80808008808080080180808008008080800800";

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn uleb(mut n: usize) -> Vec<u8> {
    let mut out = vec![];
    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

fn replica() -> (SectionsReplica, PrincipalId) {
    let resource = ResourceId::from_bytes([3; 32]);
    let signer = PrincipalId::from_bytes([4; 32]);
    let _ = shared_sections::actor_id(&resource, &signer);
    (
        SectionsReplica::new(resource, ActorId::from([7u8; 32])),
        signer,
    )
}

#[test]
fn an_rle_bomb_is_refused_without_expanding_it() {
    let (mut replica, signer) = replica();
    let started = Instant::now();
    let outcome = replica.receive(&signer, &unhex(RLE_BOMB));
    assert_eq!(outcome, Received::Refused(Refusal::InvalidAutomergeBytes));
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "refused in {:?}",
        started.elapsed()
    );
}

#[test]
fn a_compressed_chunk_is_refused_without_inflating_it() {
    // F1b: a type-2 (compressed) chunk whose DEFLATE body inflates to 256 MiB:
    // it is never inflated, and no hash is recorded (§14.1).
    let mut deflate = DeflateEncoder::new(Vec::new(), Compression::fast());
    let zeros = vec![0u8; 1 << 24];
    for _ in 0..16 {
        deflate.write_all(&zeros).unwrap();
    }
    let body = deflate.finish().unwrap();
    let mut chunk = vec![0x85, 0x6f, 0x4a, 0x83, 0, 0, 0, 0, 0x02];
    chunk.extend(uleb(body.len()));
    chunk.extend(&body);
    let plaintext = framing::encode_change(&chunk);
    assert_eq!(framing::refused_change_key(&plaintext), None);
    let (mut replica, signer) = replica();
    let started = Instant::now();
    let outcome = replica.receive(&signer, &plaintext);
    assert_eq!(outcome, Received::Refused(Refusal::InvalidAutomergeBytes));
    assert!(
        replica.refused().is_empty(),
        "no change hash is recorded for it"
    );
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "refused in {:?}",
        started.elapsed()
    );
}

#[test]
fn a_compressed_change_of_the_signer_is_refused_unnamed() {
    // SHARED-SECTIONS-PROFILE-01 §14.1 (mvp-0.2-baseline.4, SS44): a valid
    // change of the signer's own actor, sent as a compressed chunk, is
    // refused and not named: naming it would mean inflating it.
    let resource = ResourceId::from_bytes([3; 32]);
    let a = PrincipalId::from_bytes([4; 32]);
    let (_, change) = shared_sections::SectionsDoc::create(
        shared_sections::actor_id(&resource, &a),
        "019a2f85-7b31-7c42-8000-000000000001",
        "Section",
        &a,
    )
    .unwrap();
    let raw = change.raw_bytes();
    // Magic, checksum, type, then the ULEB128 length of the data.
    let header = 9 + raw[9..].iter().position(|b| b & 0x80 == 0).unwrap() + 1;
    let data = &raw[header..];
    let mut stored = vec![0x01, data.len() as u8, (data.len() >> 8) as u8];
    stored.push(!(data.len() as u8));
    stored.push(!((data.len() >> 8) as u8));
    stored.extend(data);
    let mut chunk = raw[..8].to_vec();
    chunk.push(0x02);
    chunk.extend(uleb(stored.len()));
    chunk.extend(&stored);
    let plaintext = framing::encode_change(&chunk);
    assert_eq!(framing::refused_change_key(&plaintext), None);
    let mut replica = SectionsReplica::new(resource, ActorId::from([7u8; 32]));
    assert_eq!(
        replica.receive(&a, &plaintext),
        Received::Refused(Refusal::InvalidAutomergeBytes)
    );
    assert!(
        replica.refused().is_empty(),
        "the refused chunk is not named"
    );
}

#[test]
fn a_spoiled_change_forwarded_by_another_principal_blocks_nothing() {
    // B cannot block A's change by sending its bytes with a wrong checksum:
    // only a chunk whose checksum matches is named (§14.1), so B's copy is
    // refused without a name and A's genuine change is applied.
    let resource = ResourceId::from_bytes([3; 32]);
    let (a, b) = (
        PrincipalId::from_bytes([4; 32]),
        PrincipalId::from_bytes([5; 32]),
    );
    let (_, change) = shared_sections::SectionsDoc::create(
        shared_sections::actor_id(&resource, &a),
        "019a2f85-7b31-7c42-8000-000000000001",
        "Section",
        &a,
    )
    .unwrap();
    let mut spoiled = change.raw_bytes().to_vec();
    spoiled[4] ^= 0x01;
    assert_eq!(
        framing::refused_change_key(&framing::encode_change(&spoiled)),
        None
    );
    let mut replica = SectionsReplica::new(resource, ActorId::from([7u8; 32]));
    assert_eq!(
        replica.receive(&b, &framing::encode_change(&spoiled)),
        Received::Refused(Refusal::InvalidAutomergeBytes)
    );
    assert!(replica.refused().is_empty());
    assert_eq!(
        replica.receive(&a, &framing::encode_change(change.raw_bytes())),
        Received::Applied
    );
    assert!(replica.refused().is_empty());
}

#[test]
fn a_change_refused_for_its_checksum_does_not_block_its_intact_copy() {
    // rw finding C1 (SS76, SS77): A's own copy with a wrong checksum is
    // refused without a name; the intact copy A sends next is applied, and
    // so is A's change that depends on it, which waited until then.
    let resource = ResourceId::from_bytes([3; 32]);
    let a = PrincipalId::from_bytes([4; 32]);
    let (mut doc, genesis) = shared_sections::SectionsDoc::create(
        shared_sections::actor_id(&resource, &a),
        "019a2f85-7b31-7c42-8000-000000000001",
        "Section",
        &a,
    )
    .unwrap();
    let next = doc.set_title("Renamed").unwrap();
    let mut spoiled = genesis.raw_bytes().to_vec();
    spoiled[4] ^= 0x01;
    let mut replica = SectionsReplica::new(resource, ActorId::from([7u8; 32]));
    assert_eq!(
        replica.receive(&a, &framing::encode_change(&spoiled)),
        Received::Refused(Refusal::InvalidAutomergeBytes)
    );
    assert!(replica.refused().is_empty());
    assert_eq!(
        replica.receive(&a, &framing::encode_change(next.raw_bytes())),
        Received::Waiting
    );
    assert_eq!(
        replica.receive(&a, &framing::encode_change(genesis.raw_bytes())),
        Received::Applied
    );
    assert!(replica.waiting().is_empty());
    assert!(replica.refused().is_empty());
}

#[test]
fn an_intact_copy_after_a_checksum_refusal_is_checked_for_its_actor() {
    // rw finding C2 (SS78): after A's change with a wrong checksum, its
    // intact copy in a unit B signs is refused for its actor, not with the
    // checksum refusal, which has no name to be remembered by.
    let resource = ResourceId::from_bytes([3; 32]);
    let (a, b) = (
        PrincipalId::from_bytes([4; 32]),
        PrincipalId::from_bytes([5; 32]),
    );
    let (_, change) = shared_sections::SectionsDoc::create(
        shared_sections::actor_id(&resource, &a),
        "019a2f85-7b31-7c42-8000-000000000001",
        "Section",
        &a,
    )
    .unwrap();
    let mut spoiled = change.raw_bytes().to_vec();
    spoiled[4] ^= 0x01;
    for first in [&a, &b] {
        let mut replica = SectionsReplica::new(resource, ActorId::from([7u8; 32]));
        assert_eq!(
            replica.receive(first, &framing::encode_change(&spoiled)),
            Received::Refused(Refusal::InvalidAutomergeBytes)
        );
        assert_eq!(
            replica.receive(&b, &framing::encode_change(change.raw_bytes())),
            Received::Refused(Refusal::ChangeActorMismatch)
        );
        assert_eq!(
            replica.refused().iter().collect::<Vec<_>>(),
            vec![(&change.hash(), &Refusal::ChangeActorMismatch)]
        );
    }
}

#[test]
fn a_change_at_a_taken_sequence_number_is_held_before_the_section_rules() {
    // rw finding E1 (SS88): A's second change at sequence number 1 creates
    // a section with `ready` other than true, which §12.1 refuses in its own
    // (empty) causal history; the sequence is checked first, so it is held.
    let resource = ResourceId::from_bytes([3; 32]);
    let a = PrincipalId::from_bytes([4; 32]);
    let actor = shared_sections::actor_id(&resource, &a);
    let (_, genesis) = shared_sections::SectionsDoc::create(
        actor.clone(),
        "019a2f85-7b31-7c42-8000-000000000001",
        "Section",
        &a,
    )
    .unwrap();
    let mut twin = AutoCommit::new().with_actor(actor);
    let section = twin
        .put_object(ROOT, "section", automerge::ObjType::Map)
        .unwrap();
    twin.put(&section, "ready", "yes").unwrap();
    twin.commit();
    let twin = twin.get_last_local_change().unwrap().clone();
    assert_eq!((twin.seq(), twin.deps().len()), (1, 0));
    let mut replica = SectionsReplica::new(resource, ActorId::from([7u8; 32]));
    assert_eq!(
        replica.receive(&a, &framing::encode_change(genesis.raw_bytes())),
        Received::Applied
    );
    assert_eq!(
        replica.receive(&a, &framing::encode_change(twin.raw_bytes())),
        Received::Held
    );
    assert!(replica.refused().is_empty());
}

/// A's genesis and A's change that creates the item `NODE`, with `extra`
/// operations appended to the latter, re-encoded; for A5 (rw finding E2).
fn item_with(
    extra: impl Fn(&legacy::ObjectId, &legacy::OpId) -> Vec<legacy::Op>,
) -> (SectionsReplica, PrincipalId, Change, Change) {
    const NODE: &str = "019a2f85-7b31-7c42-8000-000000000020";
    let resource = ResourceId::from_bytes([3; 32]);
    let a = PrincipalId::from_bytes([4; 32]);
    let (mut doc, genesis) = shared_sections::SectionsDoc::create(
        shared_sections::actor_id(&resource, &a),
        "019a2f85-7b31-7c42-8000-000000000001",
        "Section",
        &a,
    )
    .unwrap();
    let made = doc
        .create_node(
            NODE,
            shared_sections::NewNode::Item { text: "Group A" },
            "019a2f85-7b31-7c42-8000-000000000001",
            None,
            "019a2f85-7b31-7c42-8000-000000000021",
            &a,
        )
        .unwrap();
    let mut expanded = made.decode();
    let id = |i: usize| legacy::OpId::new(expanded.start_op.get() + i as u64, &expanded.actor_id);
    let map = expanded
        .operations
        .iter()
        .position(|op| matches!(&op.key, legacy::Key::Map(k) if k == NODE))
        .map(|i| legacy::ObjectId::Id(id(i)))
        .unwrap();
    let kind = expanded
        .operations
        .iter()
        .position(|op| op.obj == map && matches!(&op.key, legacy::Key::Map(k) if k == "kind"))
        .map(id)
        .unwrap();
    let ops = extra(&map, &kind);
    expanded.operations.extend(ops);
    expanded.hash = None;
    let replica = SectionsReplica::new(resource, ActorId::from([7u8; 32]));
    (replica, a, genesis, Change::from(expanded))
}

fn op(
    obj: &legacy::ObjectId,
    key: &str,
    action: legacy::OpType,
    pred: Vec<legacy::OpId>,
) -> legacy::Op {
    legacy::Op {
        action,
        obj: obj.clone(),
        key: legacy::Key::Map(key.into()),
        pred: pred.into(),
        insert: false,
    }
}

#[test]
fn a_scalar_text_on_a_node_without_a_kind_is_refused() {
    // rw finding E2 (SS89): the change removes the item's kind and writes a
    // scalar to its text; A5 refuses the scalar whatever the node's kind.
    let (mut replica, a, genesis, change) = item_with(|map, kind| {
        vec![
            op(map, "kind", legacy::OpType::Delete, vec![kind.clone()]),
            op(
                map,
                "text",
                legacy::OpType::Put(ScalarValue::Str("item".into())),
                vec![],
            ),
        ]
    });
    assert_eq!(
        replica.receive(&a, &framing::encode_change(genesis.raw_bytes())),
        Received::Applied
    );
    assert_eq!(
        replica.receive(&a, &framing::encode_change(change.raw_bytes())),
        Received::Refused(Refusal::InvalidFieldType)
    );
}

#[test]
fn a_scalar_text_the_merge_hides_behind_text_is_refused() {
    // rw finding E2 (SS90): the change writes a scalar and then Text to the
    // item's text, both without predecessors; the Text wins the merge and
    // the scalar stays a conflicting value, which A5 still refuses.
    let (mut replica, a, genesis, change) = item_with(|map, _| {
        vec![
            op(
                map,
                "text",
                legacy::OpType::Put(ScalarValue::Str("item".into())),
                vec![],
            ),
            op(map, "text", legacy::OpType::Make(ObjType::Text), vec![]),
        ]
    });
    assert_eq!(
        replica.receive(&a, &framing::encode_change(genesis.raw_bytes())),
        Received::Applied
    );
    assert_eq!(
        replica.receive(&a, &framing::encode_change(change.raw_bytes())),
        Received::Refused(Refusal::InvalidFieldType)
    );
}
