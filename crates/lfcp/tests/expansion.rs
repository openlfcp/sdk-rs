//! The expansion check (SHARED-OBJECTS-PROFILE-01 §11.1, §13.1) against
//! automerge 0.12's own decoder; the spec's `expansion` vectors run in
//! `shared_objects_vectors`.
//!
//! - Differential: every change and save of random documents (maps, lists,
//!   Text, counters, deletes, concurrent edits merged) is within the
//!   limits, and the walker counts exactly the operations and predecessor
//!   entries Automerge decodes.
//! - Fuzz: on mutations of valid changes the walker never panics, and when
//!   it and Automerge both accept, both count the same operations.
//! - Bombs: run headers claiming 2^62 operations or 2^40 predecessors, a
//!   deflate bomb in a Snapshot, and compressed chunks are refused at once.

use automerge::transaction::Transactable;
use automerge::{AutoCommit, Change, ObjType, ReadDoc, ScalarValue, ROOT};
use lfcp::shared_objects::expansion::{
    check_change, check_snapshot, Expansion, Limits, CHANGE_LIMITS, SNAPSHOT_LIMITS_FLOOR,
};

/// A small deterministic PRNG (xorshift64*).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// What Automerge decodes from a change: its operations and the entries
/// of their predecessor lists.
fn automerge_shape(change: &Change) -> (u64, u64) {
    let expanded = change.decode();
    let preds = expanded.operations.iter().map(|op| op.pred.len() as u64);
    (expanded.operations.len() as u64, preds.sum())
}

/// The walker's operations and group sum.
fn walker_shape(e: &Expansion) -> (u64, u64) {
    (e.ops(), e.group_sum)
}

/// One random transaction of up to `max_ops` operations on `doc`.
fn random_commit(doc: &mut AutoCommit, rng: &mut Rng, max_ops: u64) {
    let objects: Vec<_> = {
        let mut out = vec![(ROOT, ObjType::Map)];
        for key in doc.keys(ROOT).collect::<Vec<_>>() {
            if let Some((automerge::Value::Object(t), id)) = doc.get(ROOT, &key).unwrap() {
                out.push((id, t));
            }
        }
        out
    };
    for _ in 0..=rng.below(max_ops) {
        let (obj, kind) = &objects[rng.below(objects.len() as u64) as usize];
        let key = format!("k{}", rng.below(6));
        match (kind, rng.below(8)) {
            (ObjType::Map | ObjType::Table, 0) => {
                doc.put_object(obj, &key, ObjType::List).unwrap();
            }
            (ObjType::Map | ObjType::Table, 1) => {
                doc.put_object(obj, &key, ObjType::Text).unwrap();
            }
            (ObjType::Map | ObjType::Table, 2) => {
                let _ = doc.delete(obj, &key);
            }
            (ObjType::Map | ObjType::Table, 3) => {
                doc.put(obj, &key, ScalarValue::counter(0)).unwrap();
            }
            (ObjType::Map | ObjType::Table, 4) => {
                let _ = doc.increment(obj, &key, 3);
            }
            (ObjType::Map | ObjType::Table, _) => {
                let value = match rng.below(5) {
                    0 => ScalarValue::Str(format!("v{}", rng.next()).into()),
                    1 => ScalarValue::Int(rng.next() as i64),
                    2 => ScalarValue::Uint(rng.next()),
                    3 => ScalarValue::Boolean(rng.below(2) == 0),
                    _ => ScalarValue::Null,
                };
                doc.put(obj, &key, value).unwrap();
            }
            (ObjType::List, n) => {
                let len = doc.length(obj);
                if n < 5 || len == 0 {
                    let at = rng.below(len as u64 + 1) as usize;
                    doc.insert(obj, at, rng.next() as i64).unwrap();
                } else {
                    doc.delete(obj, rng.below(len as u64) as usize).unwrap();
                }
            }
            (ObjType::Text, _) => {
                let len = doc.length(obj);
                let at = rng.below(len as u64 + 1) as usize;
                let del = if len > at {
                    rng.below(3).min((len - at) as u64)
                } else {
                    0
                };
                let text: String = (0..rng.below(20))
                    .map(|i| (b'a' + i as u8) as char)
                    .collect();
                doc.splice_text(obj, at, del as isize, &text).unwrap();
            }
        }
    }
    doc.commit();
}

/// The raw (uncompressed) bytes of every change of a few random replicas,
/// with concurrent edits merged so predecessors are non-trivial.
fn corpus(seed: u64, rounds: usize) -> Vec<Vec<u8>> {
    let mut rng = Rng(seed);
    let mut a = AutoCommit::new();
    for _ in 0..rounds {
        let mut b = a.fork();
        random_commit(&mut a, &mut rng, 30);
        random_commit(&mut b, &mut rng, 30);
        a.merge(&mut b).unwrap();
        random_commit(&mut a, &mut rng, 5);
    }
    a.get_changes(&[])
        .iter()
        .map(|c| c.raw_bytes().to_vec())
        .collect()
}

#[test]
fn differential_on_random_documents() {
    let mut checked = 0;
    for seed in 1..=40u64 {
        for bytes in corpus(seed, 12) {
            let change = Change::from_bytes(bytes.clone()).unwrap();
            let e = check_change(&bytes).unwrap();
            assert_eq!(walker_shape(&e), automerge_shape(&change));
            checked += 1;
        }
    }
    assert!(checked > 1_000, "{checked} changes");
}

#[test]
fn saves_of_random_documents_are_within_the_floor() {
    for seed in 1..=10u64 {
        let mut doc = AutoCommit::new();
        for bytes in corpus(seed, 12) {
            doc.apply_changes([Change::from_bytes(bytes).unwrap()])
                .unwrap();
        }
        // save() deflates large columns; save_nocompress() does not.
        for save in [doc.save(), doc.save_nocompress()] {
            let e = check_snapshot(&save, &SNAPSHOT_LIMITS_FLOOR).unwrap();
            assert!(e.column_bytes > 0);
        }
    }
}

#[test]
fn a_change_at_the_limit_and_one_over() {
    // One splice of 16,384 characters is 16,384 operations.
    let max = CHANGE_LIMITS.max_rows as usize;
    let mut doc = AutoCommit::new();
    let text = doc.put_object(ROOT, "t", ObjType::Text).unwrap();
    doc.commit();
    doc.splice_text(&text, 0, 0, &"x".repeat(max)).unwrap();
    doc.commit();
    let change = doc.get_last_local_change().unwrap().clone();
    let e = check_change(change.raw_bytes()).unwrap();
    assert_eq!(walker_shape(&e), automerge_shape(&change));
    assert_eq!(e.ops(), max as u64);
    doc.splice_text(&text, 0, 0, &"y".repeat(max + 1)).unwrap();
    doc.commit();
    let change = doc.get_last_local_change().unwrap().clone();
    assert!(check_change(change.raw_bytes()).is_err());
}

#[test]
fn a_heavy_conflict_is_within_the_limits() {
    // §11.1 rule 9: 40 replicas set the same 500 keys concurrently; the
    // merged replica overwriting them all lists 40 predecessors per
    // operation, 20,000 in all, with 40 other actors.
    let mut base = AutoCommit::new();
    base.commit();
    let mut replicas: Vec<AutoCommit> = (0..40).map(|_| base.fork()).collect();
    for (i, r) in replicas.iter_mut().enumerate() {
        for k in 0..500 {
            r.put(ROOT, format!("k{k}"), i as i64).unwrap();
        }
        r.commit();
    }
    let mut merged = base.fork();
    for r in &mut replicas {
        merged.merge(r).unwrap();
    }
    for k in 0..500 {
        merged.put(ROOT, format!("k{k}"), -1).unwrap();
    }
    merged.commit();
    let change = merged.get_last_local_change().unwrap().clone();
    let e = check_change(change.raw_bytes()).unwrap();
    assert_eq!(walker_shape(&e), (500, 20_000));
    assert_eq!(walker_shape(&e), automerge_shape(&change));
}

#[test]
fn compressed_chunks_are_refused() {
    let mut doc = AutoCommit::new();
    let text = doc.put_object(ROOT, "t", ObjType::Text).unwrap();
    doc.splice_text(&text, 0, 0, &"compressible ".repeat(100))
        .unwrap();
    doc.commit();
    let mut change = doc.get_last_local_change().unwrap().clone();
    let compressed = change.bytes().to_vec();
    assert_eq!(compressed[8], 2, "Automerge compresses above 256 bytes");
    assert!(check_change(&compressed).is_err());
    assert!(check_change(change.raw_bytes()).is_ok());
}

#[test]
fn fuzz_mutations_never_panic_and_agree() {
    let seeds = corpus(99, 6);
    let mut rng = Rng(0x5eed);
    let (mut both, mut refused) = (0, 0);
    for _ in 0..30_000 {
        let mut bytes = seeds[rng.below(seeds.len() as u64) as usize].clone();
        for _ in 0..=rng.below(4) {
            let at = rng.below(bytes.len() as u64) as usize;
            match rng.below(4) {
                0 => bytes[at] ^= 1 << rng.below(8),
                1 => bytes[at] = rng.next() as u8,
                2 => bytes.insert(at, rng.next() as u8),
                _ => {
                    bytes.remove(at);
                }
            }
        }
        match check_change(&bytes) {
            Ok(e) => {
                assert!(e.max_rows <= CHANGE_LIMITS.max_group_sum);
                assert!(e.group_sum <= CHANGE_LIMITS.max_group_sum);
                // Automerge only ever sees what the walker accepted. It
                // reads one predecessor count per operation, so the
                // walker's group sum (every row) bounds its entries.
                if let Ok(change) = Change::from_bytes(bytes) {
                    let (ops, preds) = automerge_shape(&change);
                    assert_eq!(ops, e.ops());
                    assert!(preds <= e.group_sum);
                    both += 1;
                }
            }
            Err(_) => refused += 1,
        }
    }
    assert!(
        both > 100 && refused > 100,
        "both {both}, refused {refused}"
    );
}

/// An uncompressed change chunk with `others` other actors and the given
/// columns (checksum zero: the walker leaves it to the decoder).
fn chunk(others: u8, columns: &[(u32, Vec<u8>)]) -> Vec<u8> {
    fn uleb(out: &mut Vec<u8>, mut v: u64) {
        loop {
            let byte = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(byte);
                return;
            }
            out.push(byte | 0x80);
        }
    }
    let mut body = Vec::new();
    uleb(&mut body, 0); // no dependencies
    uleb(&mut body, 16);
    body.extend([7; 16]); // actor
    uleb(&mut body, 1); // seq
    uleb(&mut body, 1); // start_op
    body.push(0); // time
    uleb(&mut body, 0); // message
    uleb(&mut body, u64::from(others)); // other actors
    for i in 0..others {
        uleb(&mut body, 16);
        body.extend([i + 10; 16]);
    }
    uleb(&mut body, columns.len() as u64);
    for (spec, data) in columns {
        uleb(&mut body, u64::from(*spec));
        uleb(&mut body, data.len() as u64);
    }
    for (_, data) in columns {
        body.extend(data);
    }
    let mut out = vec![0x85, 0x6f, 0x4a, 0x83, 0, 0, 0, 0, 1];
    uleb(&mut out, body.len() as u64);
    out.extend(body);
    out
}

const ACTION: u32 = 4 << 4 | 2;
const PRED_GROUP: u32 = 7 << 4;
const PRED_ACTOR: u32 = 7 << 4 | 1;
const OBJ_ACTOR: u32 = 1;

#[test]
fn run_headers_cannot_claim_more_than_the_limits() {
    let start = std::time::Instant::now();
    let refused =
        |others, columns: &[(u32, Vec<u8>)]| check_change(&chunk(others, columns)).is_err();
    // sleb(2^62) then the value 0: one run of 2^62 operations.
    let huge = vec![
        0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0xc0, 0x00, 0x00,
    ];
    assert!(refused(0, &[(ACTION, huge)]));
    // A null run of 65,535 values counts too.
    assert!(refused(0, &[(ACTION, vec![0x00, 0xff, 0xff, 0x03])]));
    // A literal run header of 16,385 is refused before its values are read.
    assert!(refused(0, &[(ACTION, vec![0xff, 0xff, 0x7e])]));
    // One operation with 2 predecessors and no other actor (rule 9), and
    // with one other actor.
    assert!(refused(
        0,
        &[(ACTION, vec![0x01, 0x01]), (PRED_GROUP, vec![0x01, 0x02])]
    ));
    assert!(!refused(
        1,
        &[(ACTION, vec![0x01, 0x01]), (PRED_GROUP, vec![0x01, 0x02])]
    ));
    // 2^40 predecessors in one run: over rule 9 and the group sum.
    let mut preds = vec![0x01];
    preds.extend([0x80, 0x80, 0x80, 0x80, 0x80, 0x20]);
    assert!(refused(
        0,
        &[(ACTION, vec![0x01, 0x01]), (PRED_GROUP, preds)]
    ));
    // 16,384 operations with 16 predecessors each (16 other actors) are
    // exactly the group sum limit, 262,144; with 17 each (rule 9 allows it
    // with 16 other actors) they are over it.
    assert!(!refused(16, &[(PRED_GROUP, vec![0x80, 0x80, 0x01, 16])]));
    assert!(refused(16, &[(PRED_GROUP, vec![0x80, 0x80, 0x01, 17])]));
    // The predecessors' actor column holds group entries: bounded by the
    // group sum, not by the per-column limit.
    let entries = [0x80, 0x80, 0x02, 0x00].repeat(2); // 2 * 32,768
    assert!(refused(3, &[(PRED_ACTOR, entries.clone())]));
    assert!(!refused(
        3,
        &[
            (PRED_GROUP, vec![0x80, 0x80, 0x01, 0x04]),
            (PRED_ACTOR, entries)
        ]
    ));
    // An actor index past the change's actors (rule 8).
    assert!(refused(0, &[(OBJ_ACTOR, vec![0x01, 0x01])]));
    assert!(!refused(1, &[(OBJ_ACTOR, vec![0x01, 0x01])]));
    // A deflated change column, and two columns with one specification.
    assert!(refused(0, &[(ACTION | 0b1000, vec![0x01, 0x01])]));
    assert!(refused(
        0,
        &[(ACTION, vec![0x01, 0x01]), (ACTION, vec![0x01, 0x01])]
    ));
    // Strings: 16,384 rows of a 257-byte key are over 4 MiB.
    let mut key = vec![0x80, 0x80, 0x01, 0x81, 0x02];
    key.extend([b'k'; 257]);
    assert!(refused(0, &[(1 << 4 | 5, key)]));
    // A LEB128 number of 11 bytes.
    assert!(refused(
        0,
        &[(ACTION, vec![0x81; 10].into_iter().chain([0x00]).collect())]
    ));
    assert!(start.elapsed() < std::time::Duration::from_millis(100));
}

#[test]
fn a_snapshot_deflate_bomb_is_refused_under_its_cap() {
    // A document chunk whose one column is a deflate stream of 64 MiB of
    // zeros: refused once the running total passes 32 MiB; a receiver that
    // raises its limit to 128 MiB accepts it (a raw value column has no
    // value count).
    use std::io::Write;
    let mut doc = AutoCommit::new();
    doc.put(ROOT, "k", "v").unwrap();
    let save = doc.save_nocompress();
    let mut zeros = flate_raw(&vec![0u8; 64 * 1024 * 1024]);
    let mut bomb = document_with_op_column(0x7f << 4 | 0b1000 | 7, &mut zeros);
    let start = std::time::Instant::now();
    assert!(check_snapshot(&bomb, &SNAPSHOT_LIMITS_FLOOR).is_err());
    assert!(start.elapsed() < std::time::Duration::from_secs(5));
    let roomy = Limits {
        max_inflated_bytes: 128 * 1024 * 1024,
        ..SNAPSHOT_LIMITS_FLOOR
    };
    assert!(
        check_snapshot(&bomb, &roomy).is_ok(),
        "a raw column has no count"
    );
    // Trailing bytes after the document chunk.
    bomb = save.clone();
    bomb.write_all(&save).unwrap();
    assert!(check_snapshot(&bomb, &SNAPSHOT_LIMITS_FLOOR).is_err());
}

fn uleb(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Raw DEFLATE of `data`.
fn flate_raw(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

/// A document chunk with no actors, heads or change columns and a single
/// operation column `spec` holding `data`.
fn document_with_op_column(spec: u32, data: &mut Vec<u8>) -> Vec<u8> {
    let mut body = Vec::new();
    uleb(&mut body, 0); // actors
    uleb(&mut body, 0); // heads
    uleb(&mut body, 0); // change columns
    uleb(&mut body, 1); // op columns
    uleb(&mut body, u64::from(spec));
    uleb(&mut body, data.len() as u64);
    body.append(data);
    let mut out = vec![0x85, 0x6f, 0x4a, 0x83, 0, 0, 0, 0, 0];
    uleb(&mut out, body.len() as u64);
    out.extend(body);
    out
}
