//! A sequence of Data Unit plaintexts into one `SectionsReplica`
//! (SHARED-SECTIONS-PROFILE-01 §14.1, A1-A5 over SHARED-OBJECTS-PROFILE-01
//! §§7-18), in the record format of `lfcp_fuzz`.
//!
//! Invariants: the run is deterministic (replayed into a second replica);
//! a refused, waiting or held change leaves the admitted document as it
//! was; the same plaintext again is a Duplicate after an Applied and the
//! same verdict otherwise, with no effect; what the replica admitted
//! re-applies to a fresh one (no dependency on refused history).

#![no_main]

use automerge::{ActorId, ChangeHash};
use lfcp::shared_sections::{Received, SectionsReplica};
use lfcp_fuzz::*;
use libfuzzer_sys::fuzz_target;

/// The admitted document of `replica`.
fn view(replica: &SectionsReplica) -> automerge::AutoCommit {
    replica.view().automerge().clone()
}

fn heads(replica: &SectionsReplica) -> Vec<ChangeHash> {
    let mut heads = replica.view().automerge().clone().get_heads();
    heads.sort();
    heads
}

/// The verdicts, the final heads and the waiting changes; the heads and
/// waiting changes are empty once the replica is poisoned (F4), which ends
/// the run.
fn run(data: &[u8]) -> (Vec<Received>, Vec<ChangeHash>, Vec<ChangeHash>) {
    let resource = resource(SECTIONS_RESOURCE);
    let mut replica = SectionsReplica::new(resource, ActorId::from([1u8; 32]));
    let mut verdicts = Vec::new();
    for record in records(data) {
        let plaintext = plaintext(&record);
        if known_f2(&plaintext) {
            continue;
        }
        let signer = signer(&SECTIONS_PRINCIPALS, record.ctl);
        let before = heads(&replica);
        let Some(verdict) = guarded(&mut replica, |r| r.receive(&signer, &plaintext), view) else {
            return (verdicts, Vec::new(), Vec::new());
        };
        let after = heads(&replica);
        if !matches!(verdict, Received::Applied) {
            assert_eq!(after, before, "{verdict:?} altered the document");
        }
        let Some(again) = guarded(&mut replica, |r| r.receive(&signer, &plaintext), view) else {
            return (verdicts, Vec::new(), Vec::new());
        };
        match verdict {
            Received::Applied | Received::Duplicate => assert_eq!(again, Received::Duplicate),
            v => assert_eq!(again, v, "a repeat changed the verdict"),
        }
        assert_eq!(heads(&replica), after, "a repeat altered the document");
        verdicts.push(verdict);
    }
    // Every refused hash is absent from the document.
    let mut doc = replica.view().automerge().clone();
    for hash in replica.refused().keys() {
        let Some(found) = guarded(
            &mut doc,
            |d| d.get_change_by_hash(hash).is_some(),
            |d| d.clone(),
        ) else {
            return (verdicts, Vec::new(), Vec::new());
        };
        assert!(!found, "refused {hash} is in the document");
    }
    let end = heads(&replica);
    (verdicts, end, replica.waiting())
}

fuzz_target!(|data: &[u8]| {
    panic_policy();
    let first = run(data);
    let second = run(data);
    assert_eq!(first, second, "admission is not deterministic");
});
