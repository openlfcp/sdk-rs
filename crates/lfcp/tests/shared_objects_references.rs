//! SHARED-OBJECTS-PROFILE-01 §11.3 (canonical change encoding) and §11.4
//! (operation references): changes automerge 0.12 applies but cannot write
//! back out, or that make it abort, are refused at admission.
//!
//! The F2–F4 repros come from an external review (the Data Unit
//! plaintexts as given, in hex);
//! the other cases are built with automerge's own encoder. Every refused
//! change leaves a document that still hands out its changes, saves and
//! loads.

mod support;

use std::num::NonZeroU64;

use automerge::legacy::{ElementId, Key, ObjectId, Op, OpId, OpType, SortedVec};
use automerge::transaction::Transactable;
use automerge::{ActorId, AutoCommit, Change, ExpandedChange, ObjType, ScalarValue, ROOT};
use lfcp::shared_objects::document::{ChangeOutcome, SharedObjects};
use lfcp::shared_objects::{canonical, framing};
use lfcp::shared_objects::{Diagnostic, ProfileError};
use support::spec::Spec;

const CORPUS: &str = "test-vectors/shared-objects-01/SHARED-OBJECTS-AUTOMERGE-REFERENCE-01.json";
const INVALID: ProfileError = ProfileError::Invalid(Diagnostic::InvalidAutomergeBytes);

fn bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// F2: an object counter above 2^32 (automerge panics building its ID).
const F2: &str = concat!(
    "82015901fa856f4a834766b74501ef03017c9948439b57e1ab2be4cd6368e3e3ee1a0fac2ef0116c2308d24171c71d66",
    "d0206c9e962e697f0691ba727ddc378cc21f9b1d580e67f7b1e7f9612ebdab63c5830202000000070105028403150434",
    "024203560370030001ff01000001817e02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021",
    "22232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748492ef0116c2308d241",
    "71c71d66d0206c9e962e697f0691ba727ddc378cc21f9b1d580e67f7b1e7f9612ebdab63c58302020000000701050284",
    "03150434024203560370030001ff01001001817e02030405060708090a0b0c0d0e0f101112131415161718191abf1c1d",
    "1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d",
    "4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d",
    "7e7f80018101820183018401850186018701880189018a018b018c018d018e018f019001910192019301940195019601",
    "9701980199019a019b019c019d019e019f01a001a101a201a301ee01ef01f001f101f201f301f401f501f601f701f801",
    "f901fa01fb01fc01fd01fe01ff018002800201648002800200800200800200",
);
/// F3a: S01's profile.init with its insert column run 3 → 13.
const F3A: &str = concat!(
    "82015891856f4a83358fd6a901860100206c9e962e697f0691ba727ddc378cc21f9b1d580e67f7b1e7f9612ebdab63c5",
    "830101000c70726f66696c652e696e69740006151c340142045605571e70027d0770726f66696c65076f626a65637473",
    "0a657874656e73696f6e730d7f0102007fe60302006f72672e6f70656e6c6663702e7368617265642d6f626a65637473",
    "2e76310300",
);
/// F3c: an empty first change with start op 2.
const F3C: &str = concat!(
    "82015832856f4a83b2a92461012800206c9e962e697f0691ba727ddc378cc21f9b1d580e67f7b1e7f9612ebdab63c583",
    "010200000000",
);
/// F4: pavel puts a title on key "titl\0" with the predecessor 14@andrey,
/// the operation on "title" (after S15.base and S15.1).
const F4: &str = concat!(
    "820158b8856f4a83efe442fc01ad01019c52c9b7beaa940cdb7dfee643021b6d3bee1811fcf985d2028d6b90db096ed5",
    "207957aa8e06acc46c224685a07625acb31d6a60cee94b4c6847e74772757f1025011000055331352e3201206c9e962e",
    "697f0691ba727ddc378cc21f9b1d580e67f7b1e7f9612ebdab63c5830a01020202150734014202560357147002710273",
    "027f017f047f057469746c00017f017fc60241504920636f6e74726163742028506176656c297f017f017f0e",
);

fn receiver() -> SharedObjects {
    SharedObjects::new(ActorId::from([9u8; 32]))
}

/// `c` breaks the rule its case name starts with ("R6: ..."), is refused,
/// and the document stays sound.
fn refused(doc: &mut SharedObjects, c: Change, name: &str) {
    let rule = name.split(':').next().unwrap();
    assert_eq!(doc.broken_rule(&c), Some(rule), "{name}");
    assert_eq!(doc.apply_change(c).err(), Some(INVALID), "{name}");
    sound(doc);
}

/// The document still hands out its changes, saves and loads.
fn sound(doc: &mut SharedObjects) {
    let changes = doc.changes();
    let save = doc.save();
    let mut loaded = SharedObjects::load(&save, ActorId::from([8u8; 32])).expect("the save loads");
    assert_eq!(loaded.heads(), doc.heads());
    assert_eq!(loaded.changes().len(), changes.len());
}

#[test]
fn f2_a_counter_above_2_32_is_refused_before_automerge_parses_it() {
    assert_eq!(framing::decode_change(&bytes(F2)).err(), Some(INVALID));
}

#[test]
fn f3a_a_column_with_more_rows_than_operations_is_refused() {
    assert_eq!(framing::decode_change(&bytes(F3A)).err(), Some(INVALID));
}

#[test]
fn f3c_an_empty_change_with_a_wrong_start_op_is_refused() {
    let change = framing::decode_change(&bytes(F3C)).expect("canonical");
    refused(
        &mut receiver(),
        change,
        "R2: start op 2 on an empty history",
    );
}

#[test]
fn n1_a_start_op_of_2_32_is_refused_without_operations() {
    // §11.3 rule 8 (mvp-0.2-baseline.5, CAN-8-start-op-empty): the start op
    // is below 2^32 even when the change has no operation. F3C is a
    // canonical change without operations, framed as a Data Unit (a 4-byte
    // CBOR header); only its start op changes.
    let mut content = canonical::check(&bytes(F3C)[4..]).expect("canonical");
    assert!(content.ops.is_empty());
    content.start_op = 1 << 32;
    let n1 = canonical::encode(&content);
    assert!(canonical::check(&n1).is_err());
    assert_eq!(
        framing::decode_change(&framing::encode_change(&n1)).err(),
        Some(INVALID)
    );
    content.start_op = (1 << 32) - 1;
    assert!(canonical::check(&canonical::encode(&content)).is_ok());
}

#[test]
fn f4_a_predecessor_on_another_key_is_refused() {
    let corpus = Spec::open().read_json(CORPUS);
    let s15 = corpus["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == "S15")
        .unwrap();
    let mut doc = receiver();
    for label in ["profile.init", "S15.base", "S15.1"] {
        let entry = s15["changes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["label"] == label)
            .unwrap();
        let change = Change::from_bytes(bytes(entry["change_hex"].as_str().unwrap())).unwrap();
        assert_eq!(
            doc.apply_change(change).unwrap(),
            ChangeOutcome::Applied,
            "{label}"
        );
    }
    let change = framing::decode_change(&bytes(F4)).expect("canonical");
    refused(&mut doc, change, "R6: predecessor on another key");
}

// ---- built with automerge's encoder ---------------------------------------

fn actor(b: u8) -> ActorId {
    ActorId::from([b; 32])
}

fn id(counter: u64, a: u8) -> OpId {
    OpId(counter, actor(a))
}

fn preds(ids: Vec<OpId>) -> SortedVec<OpId> {
    ids.into_iter().collect()
}

fn op(action: OpType, obj: ObjectId, key: Key, pred: Vec<OpId>, insert: bool) -> Op {
    Op {
        action,
        obj,
        key,
        pred: preds(pred),
        insert,
    }
}

fn put(key: &str, v: i64, pred: Vec<OpId>) -> Op {
    op(
        OpType::Put(ScalarValue::Int(v)),
        ObjectId::Root,
        Key::Map(key.into()),
        pred,
        false,
    )
}

fn elem(counter: u64) -> Key {
    Key::Seq(ElementId::Id(id(counter, 1)))
}

/// A change of actor 1 built by automerge's encoder.
fn change(seq: u64, start: u64, deps: Vec<automerge::ChangeHash>, ops: Vec<Op>) -> Change {
    Change::from(ExpandedChange {
        operations: ops,
        actor_id: actor(1),
        hash: None,
        seq,
        start_op: NonZeroU64::new(start).unwrap(),
        time: 0,
        message: None,
        deps,
        extra_bytes: vec![],
        author: None,
    })
}

/// A receiver holding `base`'s history.
fn holding(base: &mut AutoCommit) -> SharedObjects {
    let mut doc = receiver();
    let waiting = doc.apply_changes(base.get_changes(&[])).unwrap();
    assert!(waiting.is_empty());
    doc
}

/// Counter `c` (1@1), `k` (2@1), then an increment of `c` (3@1).
fn counters() -> AutoCommit {
    let mut a = AutoCommit::new().with_actor(actor(1));
    a.put(ROOT, "c", ScalarValue::counter(1)).unwrap();
    a.put(ROOT, "k", 1).unwrap();
    a.commit();
    a.increment(ROOT, "c", 2).unwrap();
    a.commit();
    a
}

/// List `l` (1@1) with elements 2@1, 3@1, a put on 2@1 (4@1), and list `m`
/// (5@1) with element 6@1.
fn lists() -> AutoCommit {
    let mut a = AutoCommit::new().with_actor(actor(1));
    let l = a.put_object(ROOT, "l", ObjType::List).unwrap();
    a.insert(&l, 0, 1).unwrap();
    a.insert(&l, 1, 2).unwrap();
    a.put(&l, 0, 3).unwrap();
    let m = a.put_object(ROOT, "m", ObjType::List).unwrap();
    a.insert(&m, 0, 1).unwrap();
    a.commit();
    a
}

fn l() -> ObjectId {
    ObjectId::Id(id(1, 1))
}

fn int(v: i64) -> OpType {
    OpType::Put(ScalarValue::Int(v))
}

#[test]
fn honest_references_are_admitted() {
    let mut base = counters();
    let heads = base.get_heads();
    let cases: Vec<(&str, Change)> = vec![
        (
            "overwrite the counter",
            change(3, 4, heads.clone(), vec![put("c", 5, vec![id(1, 1)])]),
        ),
        (
            "predecessor is the increment",
            change(3, 4, heads.clone(), vec![put("c", 5, vec![id(3, 1)])]),
        ),
        (
            "predecessor earlier in the change",
            change(
                3,
                4,
                heads.clone(),
                vec![put("z", 5, vec![]), put("z", 6, vec![id(4, 1)])],
            ),
        ),
        (
            "increment of the counter",
            change(
                3,
                4,
                heads.clone(),
                vec![op(
                    OpType::Increment(1),
                    ObjectId::Root,
                    Key::Map("c".into()),
                    vec![id(1, 1)],
                    false,
                )],
            ),
        ),
    ];
    for (name, c) in cases {
        let mut doc = holding(&mut base);
        assert_eq!(doc.broken_rule(&c), None, "{name}");
        assert_eq!(
            doc.apply_change(c)
                .unwrap_or_else(|e| panic!("{name}: {e}")),
            ChangeOutcome::Applied,
            "{name}"
        );
        sound(&mut doc);
    }
    let mut base = lists();
    let heads = base.get_heads();
    let cases: Vec<(&str, Change)> = vec![
        (
            "put on an element",
            change(
                2,
                7,
                heads.clone(),
                vec![op(int(9), l(), elem(2), vec![id(4, 1)], false)],
            ),
        ),
        (
            "put on an element, predecessor its insertion",
            change(
                2,
                7,
                heads.clone(),
                vec![op(int(9), l(), elem(2), vec![id(2, 1)], false)],
            ),
        ),
        (
            "a map inserted into a list, then written",
            change(
                2,
                7,
                heads.clone(),
                vec![
                    op(OpType::Make(ObjType::Map), l(), Key::head(), vec![], true),
                    op(
                        int(1),
                        ObjectId::Id(id(7, 1)),
                        Key::Map("x".into()),
                        vec![],
                        false,
                    ),
                ],
            ),
        ),
    ];
    for (name, c) in cases {
        let mut doc = holding(&mut base);
        assert_eq!(doc.broken_rule(&c), None, "{name}");
        assert_eq!(
            doc.apply_change(c)
                .unwrap_or_else(|e| panic!("{name}: {e}")),
            ChangeOutcome::Applied,
            "{name}"
        );
        sound(&mut doc);
    }
}

#[test]
fn references_outside_the_rules_are_refused() {
    let mut base = counters();
    let heads = base.get_heads();
    let del = |key: &str, pred| {
        op(
            OpType::Delete,
            ObjectId::Root,
            Key::Map(key.into()),
            pred,
            false,
        )
    };
    let increment = |pred| {
        op(
            OpType::Increment(1),
            ObjectId::Root,
            Key::Map("c".into()),
            pred,
            false,
        )
    };
    let cases: Vec<(&str, Change)> = vec![
        (
            "R10: a table made and written into (finding D1)",
            change(
                3,
                4,
                heads.clone(),
                vec![
                    op(
                        OpType::Make(ObjType::Table),
                        ObjectId::Root,
                        Key::Map("t".into()),
                        vec![],
                        false,
                    ),
                    op(
                        OpType::Put(ScalarValue::Int(1)),
                        ObjectId::Id(id(4, 1)),
                        Key::Map("x".into()),
                        vec![],
                        false,
                    ),
                ],
            ),
        ),
        (
            "R8: increment without a predecessor",
            change(3, 4, heads.clone(), vec![increment(vec![])]),
        ),
        (
            "R8: increment naming the increment, not the counter's put",
            change(3, 4, heads.clone(), vec![increment(vec![id(3, 1)])]),
        ),
        (
            "R6: predecessor on another key",
            change(3, 4, heads.clone(), vec![put("k", 5, vec![id(1, 1)])]),
        ),
        (
            "R6: predecessor missing",
            change(3, 4, heads.clone(), vec![put("k", 5, vec![id(9, 1)])]),
        ),
        (
            "R6: predecessor later in the change",
            change(
                3,
                4,
                heads.clone(),
                vec![put("k", 5, vec![id(5, 1)]), put("k", 6, vec![])],
            ),
        ),
        (
            "R7: deletion without a predecessor",
            change(3, 4, heads.clone(), vec![del("k", vec![])]),
        ),
        (
            "R2: start op past the history",
            change(3, 6, heads.clone(), vec![put("z", 1, vec![])]),
        ),
        (
            "R2: start op reusing 3@1",
            change(3, 3, heads.clone(), vec![put("z", 1, vec![])]),
        ),
        (
            "R2: empty change past the history",
            change(3, 6, heads.clone(), vec![]),
        ),
        (
            "R2: empty change below the history",
            change(3, 2, heads.clone(), vec![]),
        ),
        (
            "R1: the previous change not in the history",
            change(3, 1, vec![], vec![put("z", 1, vec![])]),
        ),
        (
            "R3: object that is not one",
            change(
                3,
                4,
                heads.clone(),
                vec![op(
                    int(1),
                    ObjectId::Id(id(2, 1)),
                    Key::Map("x".into()),
                    vec![],
                    false,
                )],
            ),
        ),
        (
            "R4: insertion into a map",
            change(
                3,
                4,
                heads.clone(),
                vec![op(int(1), ObjectId::Root, Key::head(), vec![], true)],
            ),
        ),
    ];
    for (name, c) in cases {
        refused(&mut holding(&mut base), c, name);
    }
    let mut base = lists();
    let heads = base.get_heads();
    let cases: Vec<(&str, Change)> = vec![
        (
            "R3: property key on a list",
            change(
                2,
                7,
                heads.clone(),
                vec![op(int(1), l(), Key::Map("x".into()), vec![], false)],
            ),
        ),
        (
            "R4: insertion with a predecessor",
            change(
                2,
                7,
                heads.clone(),
                vec![op(int(1), l(), Key::head(), vec![id(2, 1)], true)],
            ),
        ),
        (
            "R4: insertion after an element that does not exist",
            change(
                2,
                7,
                heads.clone(),
                vec![op(int(1), l(), elem(70), vec![], true)],
            ),
        ),
        (
            "R4: insertion after a put, not an element",
            change(
                2,
                7,
                heads.clone(),
                vec![op(int(1), l(), elem(4), vec![], true)],
            ),
        ),
        (
            "R4: insertion after an element of another list",
            change(
                2,
                7,
                heads.clone(),
                vec![op(int(1), l(), elem(6), vec![], true)],
            ),
        ),
        (
            "R5: put on the head",
            change(
                2,
                7,
                heads.clone(),
                vec![op(int(1), l(), Key::head(), vec![], false)],
            ),
        ),
        (
            "R5: put on an element of another list",
            change(
                2,
                7,
                heads.clone(),
                vec![op(int(9), l(), elem(6), vec![id(6, 1)], false)],
            ),
        ),
        (
            "R6: predecessor on another element",
            change(
                2,
                7,
                heads.clone(),
                vec![op(int(9), l(), elem(2), vec![id(3, 1)], false)],
            ),
        ),
    ];
    for (name, c) in cases {
        refused(&mut holding(&mut base), c, name);
    }
}

#[test]
fn a_predecessor_concurrent_with_the_change_is_refused() {
    // Automerge survives it, but admission must not depend on what else a
    // replica holds: a replica without actor 2's change would refuse it.
    let mut base = counters();
    let heads = base.get_heads();
    let mut b = AutoCommit::new().with_actor(actor(2));
    b.put(ROOT, "k", 2).unwrap();
    b.commit();
    let mut doc = holding(&mut base);
    assert!(doc.apply_changes(b.get_changes(&[])).unwrap().is_empty());
    let c = change(3, 4, heads, vec![put("k", 5, vec![id(1, 2)])]);
    refused(&mut doc, c, "R6: predecessor outside the history");
}

/// From mvp-0.2-baseline.2 the Automerge corpus has a `canonical` (§11.3)
/// and a `references` (§11.4) section: each case through this admission.
/// A canonical case is the change alone, framed as a Data Unit; a
/// references case applies its history, then the change, which is admitted
/// or refused by the rule it names, leaving a sound document. At an
/// earlier baseline the sections are absent and nothing runs.
#[test]
fn the_corpus_canonical_and_references_cases() {
    let corpus = Spec::open().read_json(CORPUS);
    if let Some(cases) = corpus["canonical"]["cases"].as_array() {
        for case in cases {
            let id = case["id"].as_str().unwrap();
            let raw = bytes(case["change_hex"].as_str().unwrap());
            let canonical = framing::decode_change(&framing::encode_change(&raw)).is_ok();
            assert_eq!(
                Some(canonical),
                case["expected"]["canonical"].as_bool(),
                "{id}"
            );
        }
    }
    if let Some(cases) = corpus["references"]["cases"].as_array() {
        for case in cases {
            let id = case["id"].as_str().unwrap();
            let mut doc = receiver();
            for h in case["history_hex"].as_array().unwrap() {
                let change = Change::from_bytes(bytes(h.as_str().unwrap())).unwrap();
                assert_eq!(
                    doc.apply_change(change).unwrap(),
                    ChangeOutcome::Applied,
                    "{id} history"
                );
            }
            let change = Change::from_bytes(bytes(case["change_hex"].as_str().unwrap())).unwrap();
            let expected = &case["expected"];
            if expected["admitted"] == true {
                assert_eq!(doc.broken_rule(&change), None, "{id}");
                assert_eq!(
                    doc.apply_change(change).unwrap(),
                    ChangeOutcome::Applied,
                    "{id}"
                );
            } else {
                let rule = expected["broken_rule"].as_str().unwrap();
                refused(&mut doc, change, &format!("{rule}: {id}"));
            }
        }
    }
}
