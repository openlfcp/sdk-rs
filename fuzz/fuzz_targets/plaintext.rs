//! Arbitrary bytes as a Data Unit and a Snapshot plaintext: CBOR framing,
//! chunk header and the §11.1 / §13.1 checks, decided twice.

#![no_main]

use lfcp::shared_objects::framing;
use lfcp::shared_sections::{Received, SectionsReplica};
use lfcp_fuzz::*;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    panic_policy();
    if known_f2(data) {
        return;
    }
    let change = framing::decode_change(data).map(|c| c.hash());
    assert_eq!(change, framing::decode_change(data).map(|c| c.hash()));
    let snapshot = framing::decode_snapshot(data);
    assert_eq!(snapshot, framing::decode_snapshot(data));

    if known_f1(data) {
        return;
    }
    // The same bytes through the sections replica: refused exactly when
    // the framing refuses them (an empty replica has no dependency, so a
    // decodable change is Applied, Waiting or refused by a rule).
    let resource = resource(SECTIONS_RESOURCE);
    let mut replica = SectionsReplica::new(resource, automerge::ActorId::from([1u8; 32]));
    let signer = signer(&SECTIONS_PRINCIPALS, 0);
    let first = replica.receive(&signer, data);
    if change.is_err() {
        assert!(matches!(first, Received::Refused(_)), "{first:?}");
    }
    let again = replica.receive(&signer, data);
    match first {
        Received::Applied | Received::Duplicate => assert_eq!(again, Received::Duplicate),
        other => assert_eq!(again, other),
    }
});
