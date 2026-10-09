//! Honest histories into Shared Objects admission (SHARED-OBJECTS-PROFILE-01
//! §11.3, §11.4, §14.1): the input is a program that three Automerge writers
//! run on their own documents (every object type, every scalar type, list
//! and text edits, increments, marks, blocks, merges, empty changes). Every
//! change a writer commits on its document is canonical and refers only to
//! its own history (§11.4: "an Automerge writer that commits on its document
//! never does" break it), so admission must take all of them:
//!
//! - one at a time, in an order the input chooses, every change is Applied
//!   or waits for a dependency, never refused or held;
//! - as one batch, nothing is refused and nothing waits;
//! - both replicas end on the writers' heads, and their save loads.

#![no_main]

use automerge::marks::{ExpandMark, Mark};
use automerge::transaction::Transactable;
use automerge::{ActorId, AutoCommit, ChangeHash, ObjId, ObjType, ReadDoc, ScalarValue, ROOT};
use lfcp::shared_objects::document::{ChangeOutcome, SharedObjects};
use lfcp::shared_objects::{framing, ProfileError};
use lfcp_fuzz::*;
use libfuzzer_sys::fuzz_target;

const WRITERS: usize = 3;
const MAX_STEPS: usize = 160;
const KEYS: [&str; 4] = ["a", "b", "c", "d"];

/// Reads the program, one byte at a time; 0 once it is exhausted.
struct Program<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Program<'_> {
    fn byte(&mut self) -> u8 {
        let b = self.bytes.get(self.at).copied().unwrap_or(0);
        self.at += 1;
        b
    }
    fn done(&self) -> bool {
        self.at >= self.bytes.len()
    }
    fn pick<T: Clone>(&mut self, items: &[T]) -> T {
        items[usize::from(self.byte()) % items.len()].clone()
    }
    fn scalar(&mut self) -> ScalarValue {
        let n = i64::from(self.byte() as i8);
        match self.byte() % 9 {
            0 => ScalarValue::Str(format!("s{n}").into()),
            1 => ScalarValue::Int(n * 1000),
            2 => ScalarValue::Uint(n.unsigned_abs() * 70_000),
            3 => ScalarValue::F64(n as f64 / 3.0),
            4 => ScalarValue::Boolean(n % 2 == 0),
            5 => ScalarValue::Null,
            6 => ScalarValue::Bytes(vec![self.byte(); usize::from(self.byte() % 5)]),
            7 => ScalarValue::counter(n),
            _ => ScalarValue::Timestamp(n * 86_400_000),
        }
    }
}

/// The objects a writer may hold: the root and every object made so far.
fn objects(doc: &AutoCommit, made: &[ObjId]) -> Vec<(ObjId, ObjType)> {
    std::iter::once(ROOT)
        .chain(made.iter().cloned())
        .filter_map(|o| doc.object_type(&o).ok().map(|t| (o, t)))
        .collect()
}

/// Run one step on writer `w`; engine errors (an index past the end, …)
/// just skip the step.
fn step(p: &mut Program<'_>, docs: &mut [AutoCommit], made: &mut Vec<ObjId>) {
    let w = usize::from(p.byte()) % WRITERS;
    let op = p.byte() % 12;
    if op == 10 {
        // Merge another writer's history in.
        let from = usize::from(p.byte()) % WRITERS;
        if from != w {
            let (a, b) = if w < from {
                let (l, r) = docs.split_at_mut(from);
                (&mut l[w], &mut r[0])
            } else {
                let (l, r) = docs.split_at_mut(w);
                (&mut r[0], &mut l[from])
            };
            a.commit();
            b.commit();
            let _ = a.merge(b);
        }
        return;
    }
    if op == 11 {
        docs[w].commit();
        if p.byte() % 4 == 0 {
            docs[w].empty_change(Default::default());
        }
        return;
    }
    let doc = &mut docs[w];
    let objs = objects(doc, made);
    let (obj, ty) = p.pick(&objs);
    let len = doc.length(&obj);
    let key = p.pick(&KEYS);
    let kinds = [ObjType::Map, ObjType::List, ObjType::Text, ObjType::Table];
    let r: Result<Option<ObjId>, automerge::AutomergeError> = match (op, ty) {
        (0, ObjType::Map | ObjType::Table) => doc.put(&obj, key, p.scalar()).map(|_| None),
        (1, ObjType::Map | ObjType::Table) => {
            let kind = p.pick(&kinds);
            doc.put_object(&obj, key, kind).map(Some)
        }
        (2, ObjType::Map | ObjType::Table) => doc.delete(&obj, key).map(|_| None),
        (3, ObjType::Map | ObjType::Table) => doc.increment(&obj, key, 1).map(|_| None),
        (0, ObjType::List) => {
            let at = usize::from(p.byte()) % (len + 1);
            doc.insert(&obj, at, p.scalar()).map(|_| None)
        }
        (1, ObjType::List) => {
            let at = usize::from(p.byte()) % (len + 1);
            let kind = p.pick(&kinds);
            doc.insert_object(&obj, at, kind).map(Some)
        }
        (2, ObjType::List) if len > 0 => {
            let at = usize::from(p.byte()) % len;
            doc.delete(&obj, at).map(|_| None)
        }
        (3, ObjType::List) if len > 0 => {
            let at = usize::from(p.byte()) % len;
            doc.put(&obj, at, p.scalar()).map(|_| None)
        }
        (4, ObjType::List) if len > 0 => {
            let at = usize::from(p.byte()) % len;
            doc.increment(&obj, at, 1).map(|_| None)
        }
        (0 | 1, ObjType::Text) => {
            let at = usize::from(p.byte()) % (len + 1);
            let del = usize::from(p.byte()) % 3;
            let text = ["x", "yz", "", "é漢🙂", "line\n"][usize::from(p.byte()) % 5];
            doc.splice_text(&obj, at, del as isize, text).map(|_| None)
        }
        (2, ObjType::Text) if len > 0 => {
            let start = usize::from(p.byte()) % len;
            let end = start + 1 + usize::from(p.byte()) % (len - start);
            let expand = p.pick(&[
                ExpandMark::Before,
                ExpandMark::After,
                ExpandMark::Both,
                ExpandMark::None,
            ]);
            let mark = Mark::new(p.pick(&KEYS).to_string(), p.scalar(), start, end);
            doc.mark(&obj, mark, expand).map(|_| None)
        }
        (3, ObjType::Text) if len > 0 => {
            let start = usize::from(p.byte()) % len;
            let end = start + 1 + usize::from(p.byte()) % (len - start);
            doc.unmark(&obj, p.pick(&KEYS), start, end, ExpandMark::None)
                .map(|_| None)
        }
        (4, ObjType::Text) => {
            let at = usize::from(p.byte()) % (len + 1);
            doc.split_block(&obj, at).map(Some)
        }
        _ => Ok(None),
    };
    if let Ok(Some(o)) = r {
        made.push(o);
    }
    if p.byte() % 3 == 0 {
        doc.commit();
    }
}

fn heads(doc: &mut SharedObjects) -> Vec<ChangeHash> {
    let mut h = doc.heads();
    h.sort();
    h
}

fuzz_target!(|data: &[u8]| {
    panic_policy();
    let Some((&order_seed, program)) = data.split_first() else {
        return;
    };
    let mut p = Program {
        bytes: program,
        at: 0,
    };
    let mut docs: Vec<AutoCommit> = (0..WRITERS)
        .map(|i| AutoCommit::new().with_actor(ActorId::from([0xa0 + i as u8; 32])))
        .collect();
    let mut made = Vec::new();
    let mut steps = 0;
    while !p.done() && steps < MAX_STEPS {
        step(&mut p, &mut docs, &mut made);
        steps += 1;
    }
    // The writers' whole history: every change of every writer.
    let mut all = AutoCommit::new();
    for doc in &mut docs {
        doc.commit();
        if all.merge(doc).is_err() {
            return; // an engine limitation, not admission's
        }
    }
    let changes = all.get_changes(&[]);
    let mut want = all.get_heads();
    want.sort();

    // One at a time, in an order the input chooses.
    let mut order: Vec<usize> = (0..changes.len()).collect();
    let mut s = u64::from(order_seed) | 1;
    for i in (1..order.len()).rev() {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        order.swap(i, (s >> 33) as usize % (i + 1));
    }
    let mut one = SharedObjects::new(ActorId::from([1u8; 32]));
    let mut pending: Vec<usize> = order;
    loop {
        let mut next = Vec::new();
        for &i in &pending {
            let c = changes[i].clone();
            // Through the wire framing, as a receiver gets it.
            let decoded = framing::decode_change(&framing::encode_change(c.raw_bytes()))
                .unwrap_or_else(|e| panic!("an engine change fails decode_change: {e}"));
            match one.apply_change(decoded) {
                Ok(ChangeOutcome::Applied | ChangeOutcome::Duplicate) => {}
                Err(ProfileError::MissingDependencies(_)) => next.push(i),
                other => {
                    let rule = one.broken_rule(&c);
                    panic!(
                        "an honest change is not admitted: {other:?} (rule {rule:?}, seq {}, {} ops)",
                        c.seq(),
                        c.len()
                    );
                }
            }
        }
        if next.is_empty() || next.len() == pending.len() {
            assert!(next.is_empty(), "{} changes never admitted", next.len());
            break;
        }
        pending = next;
    }
    assert_eq!(heads(&mut one), want, "one at a time: other heads");

    // As one batch.
    let mut batch = SharedObjects::new(ActorId::from([2u8; 32]));
    match batch.apply_changes(changes.clone()) {
        Ok(waiting) => assert!(
            waiting.is_empty(),
            "{} wait in a whole history",
            waiting.len()
        ),
        Err(e) => panic!("a whole honest history is refused as a batch: {e:?}"),
    }
    assert_eq!(heads(&mut batch), want, "batch: other heads");

    // Its save loads, through the same §11.3 / §11.4 checks.
    let save = one.save();
    if let Err(e) = SharedObjects::load(&save, ActorId::from([3u8; 32])) {
        panic!("the save of an honest history does not load: {e:?}");
    }
});
