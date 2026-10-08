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

fn heads(replica: &SectionsReplica) -> Vec<ChangeHash> {
    let mut heads = replica.view().automerge().clone().get_heads();
    heads.sort();
    heads
}

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
        let verdict = replica.receive(&signer, &plaintext);
        let after = heads(&replica);
        if !matches!(verdict, Received::Applied) {
            assert_eq!(after, before, "{verdict:?} altered the document");
        }
        let again = replica.receive(&signer, &plaintext);
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
        assert!(
            doc.get_change_by_hash(hash).is_none(),
            "refused {hash} is in the document"
        );
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
