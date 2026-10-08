//! Refused Data Units are never expanded (rw finding F1): a section replica
//! that refuses a change at SHARED-OBJECTS-PROFILE-01 §11 or §11.1 must not
//! hand its bytes to Automerge afterwards, which would expand an RLE or a
//! DEFLATE bomb before failing.

#![cfg(feature = "shared-sections")]

use std::io::Write;
use std::time::{Duration, Instant};

use automerge::ActorId;
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
    // inflation stops at the cap of 8 MiB, and no hash is recorded.
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
fn a_spoiled_change_forwarded_by_another_principal_blocks_nothing() {
    // A refusal is recorded by change hash only for the signer's own actor:
    // B cannot block A's change by sending its bytes with a wrong checksum.
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
    // A's own spoiled bytes are recorded under the change's hash.
    let mut own = SectionsReplica::new(resource, ActorId::from([7u8; 32]));
    own.receive(&a, &framing::encode_change(&spoiled));
    assert_eq!(
        own.refused().keys().collect::<Vec<_>>(),
        vec![&change.hash()]
    );
}
