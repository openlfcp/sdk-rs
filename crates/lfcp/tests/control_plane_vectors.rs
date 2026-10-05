//! LFCP-TEST-VECTORS-01 cases for the Control Plane: typed Control Records
//! C0–C6, the Control Chain, ownership transfer payloads and the fork case.
//!
//! The synthetic negatives at the end are built in the test from fixture
//! keys; they are not spec vectors. Every assertion names its case.

mod support;

use lfcp::base::{ChainRule, ControlRecordId, Error, ResourceId};
use lfcp::cbor;
use lfcp::cose;
use lfcp::principal::PrincipalKeys;
use lfcp::wire::control::body::{ControlBody, OwnerTransferAccept, OwnerTransferOffer};
use lfcp::wire::control::chain::{
    check_fork, validate_chain, ChainOutcome, ChainStart, SignaturesOnly,
};
use lfcp::wire::control::{ControlRecord, ControlRecordHeader, ReceivedControlRecord};
use support::vectors::{hex, Suite};

const RECORDS: [(&str, u64); 7] = [
    ("C0_genesis", 0),
    ("C1_grant_bob", 1),
    ("C2_invite_grant", 1),
    ("C3_invite_claim_carol", 3),
    ("C4_owner_transfer_commit", 6),
    ("C5_route_update", 5),
    ("C6_key_epoch_1", 4),
];

fn record_bytes(suite: &Suite, case_id: &str) -> Vec<u8> {
    hex(case_id, &suite.case(case_id)["expected"]["cose_sign1"])
}

fn signer<'a>(
    suite: &Suite,
    principals: &'a std::collections::BTreeMap<String, PrincipalKeys>,
    case_id: &str,
) -> &'a PrincipalKeys {
    &principals[suite.case(case_id)["inputs"]["signer"].as_str().unwrap()]
}

#[test]
fn records_decode_typed_and_re_encode_byte_exact() {
    let suite = Suite::load();
    let principals = suite.principals();
    for (case_id, control_type) in RECORDS {
        let expected = &suite.case(case_id)["expected"];
        let received = ReceivedControlRecord::parse(&record_bytes(&suite, case_id))
            .unwrap_or_else(|err| panic!("{case_id}: parse failed: {err}"));
        assert_eq!(
            received.body().control_type(),
            control_type,
            "{case_id}: type"
        );
        assert!(
            !matches!(received.body(), ControlBody::Extension { .. }),
            "{case_id}: typed body"
        );

        // Re-encode the typed header and body and re-sign: the result must
        // be the published record, byte for byte.
        let keys = signer(&suite, &principals, case_id);
        assert_eq!(
            &received.header().issuer,
            keys.descriptor().id(),
            "{case_id}: issuer"
        );
        let rebuilt = ControlRecord::sign(received.header().clone(), received.body().clone(), keys)
            .unwrap_or_else(|err| panic!("{case_id}: sign failed: {err}"));
        assert_eq!(
            rebuilt.signed_object().payload_bytes(),
            hex(case_id, &expected["payload_cbor"]),
            "{case_id}: payload_cbor"
        );
        assert_eq!(
            rebuilt.signed_object().bytes(),
            hex(case_id, &expected["cose_sign1"]),
            "{case_id}: cose_sign1"
        );
        assert_eq!(
            rebuilt.id().as_bytes().as_slice(),
            hex(case_id, &expected["record_id"]),
            "{case_id}: record_id"
        );
        assert_eq!(
            received.verify(keys.descriptor()).as_ref(),
            Ok(&rebuilt),
            "{case_id}: verify"
        );
    }
}

#[test]
fn chain_c0_to_c6_validates() {
    let suite = Suite::load();
    let bytes: Vec<Vec<u8>> = RECORDS
        .iter()
        .map(|(id, _)| record_bytes(&suite, id))
        .collect();
    let refs: Vec<&[u8]> = bytes.iter().map(Vec::as_slice).collect();
    // Every issuer is described by an earlier record: OWNER in Genesis,
    // BOB and INVITE as grant subjects.
    let outcome = validate_chain(&refs, ChainStart::Genesis, &mut SignaturesOnly)
        .unwrap_or_else(|f| panic!("{}: {}", RECORDS[f.index].0, f.error));
    let ChainOutcome::Linear(chain) = outcome else {
        panic!("C0-C6: unexpected conflict")
    };
    assert_eq!(chain.records.len(), 7, "C0-C6: records");
    assert_eq!(chain.head.sequence, 6, "C0-C6: head sequence");
    assert_eq!(
        chain.head.id.as_bytes().as_slice(),
        hex(
            "C6_key_epoch_1",
            &suite.case("C6_key_epoch_1")["expected"]["record_id"]
        ),
        "C0-C6: head is C6"
    );
}

#[test]
fn control_fork_c6_is_a_conflict() {
    let suite = Suite::load();
    let case_id = "control_fork_C6";
    let case = suite.case(case_id);
    let fork = hex(case_id, &case["inputs"]["cose_sign1"]);
    let mut bytes: Vec<Vec<u8>> = RECORDS
        .iter()
        .map(|(id, _)| record_bytes(&suite, id))
        .collect();
    bytes.push(fork);
    let refs: Vec<&[u8]> = bytes.iter().map(Vec::as_slice).collect();

    let outcome = validate_chain(&refs, ChainStart::Genesis, &mut SignaturesOnly)
        .unwrap_or_else(|f| panic!("{case_id}: record {} failed: {}", f.index, f.error));
    let err = outcome.error().expect("control_fork_C6: no conflict");
    assert_eq!(err, Error::ControlConflict, "{case_id}");
    assert_eq!(
        err.wire_code().map(|c| c.name()),
        case["expected"]["error"]["code"].as_str()
    );
    assert_eq!(case["expected"]["disposition"], "conflict", "{case_id}");

    let ChainOutcome::Conflict(conflict) = outcome else {
        unreachable!()
    };
    let record_id = |case: &str| hex(case, &suite.case(case)["expected"]["record_id"]);
    assert_eq!(conflict.common.len(), 6, "{case_id}: C0-C5 stay accepted");
    assert_eq!(
        conflict.common.last().unwrap().id().as_bytes().as_slice(),
        record_id("C5_route_update"),
        "{case_id}: previous_record"
    );
    assert_eq!(
        conflict.first.id().as_bytes().as_slice(),
        record_id("C6_key_epoch_1"),
        "{case_id}: competing_record"
    );
    assert_eq!(
        conflict.second.id().as_bytes().as_slice(),
        hex(case_id, &case["inputs"]["record_id"]),
        "{case_id}: record_id"
    );
    assert_eq!(
        check_fork(&conflict.first, &conflict.second),
        Err(Error::ControlConflict),
        "{case_id}: check_fork"
    );
}

#[test]
fn owner_transfer_payloads_decode_and_re_encode() {
    let suite = Suite::load();
    let case_id = "owner_transfer";
    let expected = &suite.case(case_id)["expected"];
    let principals = suite.principals();

    let offer_object = cose::parse(&hex(case_id, &expected["offer_cose_sign1"])).unwrap();
    let offer = OwnerTransferOffer::from_value(offer_object.payload())
        .unwrap_or_else(|err| panic!("{case_id}: offer: {err}"));
    assert_eq!(
        cbor::encode(&offer.to_value()).unwrap(),
        hex(case_id, &expected["offer_payload_cbor"]),
        "{case_id}: offer_payload_cbor"
    );
    assert_eq!(
        &offer.new_owner,
        principals["BOB"].descriptor(),
        "{case_id}: new owner"
    );

    let accept_object = cose::parse(&hex(case_id, &expected["accept_cose_sign1"])).unwrap();
    let accept = OwnerTransferAccept::from_value(accept_object.payload())
        .unwrap_or_else(|err| panic!("{case_id}: accept: {err}"));
    assert_eq!(
        cbor::encode(&accept.to_value()).unwrap(),
        hex(case_id, &expected["accept_payload_cbor"]),
        "{case_id}: accept_payload_cbor"
    );
    assert_eq!(
        accept.offer.as_bytes().as_slice(),
        hex(case_id, &expected["offer_id"]),
        "{case_id}: accept names the offer"
    );

    // C4 carries the exact offer and accept bytes.
    let c4 =
        ReceivedControlRecord::parse(&record_bytes(&suite, "C4_owner_transfer_commit")).unwrap();
    let ControlBody::OwnerTransferCommit(commit) = c4.body() else {
        panic!("C4_owner_transfer_commit: not a commit")
    };
    assert_eq!(
        commit.offer,
        offer_object.bytes(),
        "C4_owner_transfer_commit: offer bytes"
    );
    assert_eq!(
        commit.accept,
        accept_object.bytes(),
        "C4_owner_transfer_commit: accept bytes"
    );
    assert_eq!(
        commit.offer().unwrap().1,
        offer,
        "C4_owner_transfer_commit: offer"
    );
    assert_eq!(
        commit.accept().unwrap().1,
        accept,
        "C4_owner_transfer_commit: accept"
    );
}

/// Synthetic negatives: C0 and C1 rebuilt from fixture keys with one
/// field changed.
mod synthetic {
    use super::*;

    struct Fixture {
        owner: PrincipalKeys,
        bob: PrincipalKeys,
        c0: ReceivedControlRecord,
        c1: ReceivedControlRecord,
    }

    fn fixture() -> Fixture {
        let suite = Suite::load();
        let mut principals = suite.principals();
        Fixture {
            owner: principals.remove("OWNER").unwrap(),
            bob: principals.remove("BOB").unwrap(),
            c0: ReceivedControlRecord::parse(&record_bytes(&suite, "C0_genesis")).unwrap(),
            c1: ReceivedControlRecord::parse(&record_bytes(&suite, "C1_grant_bob")).unwrap(),
        }
    }

    fn sign(
        header: ControlRecordHeader,
        base: &ReceivedControlRecord,
        keys: &PrincipalKeys,
    ) -> Vec<u8> {
        ControlRecord::sign(header, base.body().clone(), keys)
            .unwrap()
            .signed_object()
            .bytes()
            .to_vec()
    }

    fn failure(records: &[&[u8]]) -> (usize, Error) {
        let failure = validate_chain(records, ChainStart::Genesis, &mut SignaturesOnly)
            .expect_err("synthetic chain was accepted");
        (failure.index, failure.error)
    }

    fn chain(rule: ChainRule) -> Error {
        Error::InvalidControlChain(rule)
    }

    #[test]
    fn c1_with_a_broken_previous_link() {
        let f = fixture();
        let header = ControlRecordHeader {
            previous: Some(ControlRecordId::from_bytes([0xee; 32])),
            ..f.c1.header().clone()
        };
        let c1 = sign(header, &f.c1, &f.owner);
        let c0 = record_bytes(&Suite::load(), "C0_genesis");
        assert_eq!(
            failure(&[&c0, &c1]),
            (1, chain(ChainRule::PreviousMismatch))
        );
    }

    #[test]
    fn c1_with_a_sequence_gap() {
        let f = fixture();
        let header = ControlRecordHeader {
            sequence: 2,
            ..f.c1.header().clone()
        };
        let c1 = sign(header, &f.c1, &f.owner);
        let c0 = record_bytes(&Suite::load(), "C0_genesis");
        assert_eq!(failure(&[&c0, &c1]), (1, chain(ChainRule::SequenceGap)));
    }

    #[test]
    fn c1_for_another_resource() {
        let f = fixture();
        let header = ControlRecordHeader {
            resource_id: ResourceId::from_bytes([0xee; 32]),
            ..f.c1.header().clone()
        };
        let c1 = sign(header, &f.c1, &f.owner);
        let c0 = record_bytes(&Suite::load(), "C0_genesis");
        assert_eq!(
            failure(&[&c0, &c1]),
            (1, chain(ChainRule::ResourceMismatch))
        );
    }

    #[test]
    fn genesis_at_sequence_one() {
        let f = fixture();
        let header = ControlRecordHeader {
            sequence: 1,
            ..f.c0.header().clone()
        };
        let c0 = sign(header, &f.c0, &f.owner);
        assert_eq!(failure(&[&c0]), (0, chain(ChainRule::GenesisMissing)));
    }

    #[test]
    fn genesis_issued_by_someone_other_than_its_owner() {
        let f = fixture();
        let header = ControlRecordHeader {
            issuer: *f.bob.descriptor().id(),
            ..f.c0.header().clone()
        };
        let c0 = sign(header, &f.c0, &f.bob);
        let (index, err) = failure(&[&c0]);
        assert_eq!((index, &err), (0, &Error::CoseKidMismatch));
        assert_eq!(err.wire_code().unwrap().name(), "INVALID_SIGNATURE", "S2");
    }

    #[test]
    fn c1_signed_by_bob_for_issuer_owner() {
        // G-RS1: the kid must be the issuer. BOB signs C1's exact payload.
        let f = fixture();
        let suite = Suite::load();
        let payload = hex(
            "C1_grant_bob",
            &suite.case("C1_grant_bob")["expected"]["payload_cbor"],
        );
        let c1 = cose::sign(&payload, &f.bob).unwrap();
        let c0 = record_bytes(&suite, "C0_genesis");
        let (index, err) = failure(&[&c0, c1.bytes()]);
        assert_eq!((index, &err), (1, &Error::CoseKidMismatch));
        assert_eq!(err.wire_code().unwrap().name(), "INVALID_SIGNATURE");
    }
}
