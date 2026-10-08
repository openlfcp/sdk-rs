//! A sequence of Data Unit plaintexts into one Shared Objects replica
//! (§§8, 11, 11.1, 11.2, 14.1), in the record format of `lfcp_fuzz`.
//!
//! Invariants: each verdict is deterministic (the whole run is replayed
//! into a second replica and must agree); a refused change leaves the
//! replica as it was; the same plaintext again is a Duplicate after an
//! Applied and the same verdict otherwise, with no effect; and the save of
//! a document built only from admitted changes within the §13.1 floor is a
//! valid Snapshot.

#![no_main]

use automerge::{ActorId, Change, ChangeHash};
use lfcp::shared_objects::document::{ChangeOutcome, SharedObjects};
use lfcp::shared_objects::{expansion, framing, ProfileError};
use lfcp_fuzz::*;
use libfuzzer_sys::fuzz_target;

/// What the invariants compare of a replica.
#[derive(Debug, PartialEq)]
struct State {
    heads: Vec<ChangeHash>,
    changes: usize,
    held: Vec<ChangeHash>,
}

fn state(doc: &mut SharedObjects) -> State {
    let mut heads = doc.heads();
    heads.sort();
    State {
        heads,
        changes: doc.changes().len(),
        held: doc.held().iter().map(Change::hash).collect(),
    }
}

type Verdict = Result<ChangeOutcome, ProfileError>;

fn deliver(doc: &mut SharedObjects, record: &Record<'_>, plaintext: &[u8]) -> Verdict {
    let resource = resource(OBJECTS_RESOURCE);
    if record.ctl & CTL_ORIGIN_ESTABLISHED != 0 {
        doc.apply_change(framing::decode_change(plaintext)?)
    } else {
        let signer = signer(&OBJECTS_PRINCIPALS, record.ctl);
        doc.apply_unit_change(&resource, &signer, plaintext)
    }
}

/// The expansion of everything admitted so far, summed.
#[derive(Default)]
struct Totals {
    rows: u64,
    group: u64,
    strings: u64,
}

fn run(data: &[u8]) -> (Vec<Verdict>, State) {
    let mut doc = SharedObjects::new(ActorId::from([1u8; 32]));
    let mut verdicts = Vec::new();
    let mut totals = Totals::default();
    for record in records(data) {
        let plaintext = plaintext(&record);
        if known_f2(&plaintext) {
            continue;
        }
        let before = state(&mut doc);
        let verdict = deliver(&mut doc, &record, &plaintext);
        let after = state(&mut doc);
        match &verdict {
            Ok(ChangeOutcome::Applied) => {
                assert_eq!(
                    after.changes,
                    before.changes + 1,
                    "Applied without one more change"
                );
                let raw = framing::decode_change(&plaintext).unwrap();
                let e = expansion::check_change(raw.raw_bytes()).unwrap();
                totals.rows += e.columns.iter().map(|(_, r)| *r).max().unwrap_or(0);
                totals.group += e.group_sum;
                totals.strings += e.string_bytes;
            }
            Ok(ChangeOutcome::Held) => {
                assert_eq!(
                    (&after.heads, after.changes),
                    (&before.heads, before.changes)
                );
                let hash = framing::decode_change(&plaintext).unwrap().hash();
                assert!(after.held.contains(&hash), "Held but not in held()");
            }
            Ok(ChangeOutcome::Duplicate) | Err(_) => {
                assert_eq!(after, before, "{verdict:?} altered the replica");
            }
        }
        // The same plaintext again: no second effect.
        let again = deliver(&mut doc, &record, &plaintext);
        match &verdict {
            Ok(ChangeOutcome::Applied) => assert_eq!(again, Ok(ChangeOutcome::Duplicate)),
            v => assert_eq!(&again, v, "a repeat changed the verdict"),
        }
        assert_eq!(state(&mut doc), after, "a repeat altered the replica");
        verdicts.push(verdict);
    }
    // A document of admitted changes within the floor is a Snapshot.
    let floor = expansion::SNAPSHOT_LIMITS_FLOOR;
    if totals.rows < floor.max_rows / 4
        && totals.group < floor.max_group_sum / 4
        && totals.strings < floor.max_string_bytes / 4
    {
        let save = doc.save();
        if let Err(err) = framing::decode_snapshot(&framing::encode_snapshot(&save)) {
            if known_f3(&save) {
                return (verdicts, state(&mut doc));
            }
            let limits = expansion::check_snapshot(&save, &floor).map(|_| ());
            let depth = expansion::check_snapshot_depth(&save, &floor).map(|_| ());
            let load = SharedObjects::load(&save, ActorId::from([2u8; 32])).map(|_| ());
            panic!(
                "admitted changes save to a refused Snapshot: {err} \
                 (limits {limits:?}, depth {depth:?}, load {load:?})"
            );
        }
    }
    let end = state(&mut doc);
    (verdicts, end)
}

fuzz_target!(|data: &[u8]| {
    panic_policy();
    let first = run(data);
    let second = run(data);
    assert_eq!(first, second, "admission is not deterministic");
});
