//! Data Epoch rotation and the strict cutoff on LFCP-TEST-VECTORS-01: C6,
//! D1–D4, stale_epoch, stale_epoch_absent_actor, Key Packages and Snapshots
//! by epoch; then synthetic Key Epoch negatives built from fixture keys
//! (not spec vectors).
//!
//! Every assertion names its case.

mod support;

use std::collections::BTreeMap;

use lfcp::base::{ChainRule, ControlRecordId, Error, FrontierRule, Hash32, QuarantineReason};
use lfcp::cbor::{self, Value};
use lfcp::cose;
use lfcp::principal::PrincipalKeys;
use lfcp::wire::control::authority::{
    key_package_policy, propose_transition, snapshot_policy, state_at, validate_authorized,
    ControlState,
};
use lfcp::wire::control::epoch::{client_disposition, server_accepts_data_put, Disposition};
use lfcp::wire::data_unit::{DataUnitHeader, ReceivedDataUnit};
use lfcp::wire::frontier::{ActorHave, Frontier};
use lfcp::wire::key_package::{KeyPackage, ReceivedKeyPackage};
use lfcp::wire::keys::Dek;
use lfcp::wire::snapshot::ReceivedSnapshot;
use support::vectors::{hex, hex32, principal_by_id, Suite};

const CHAIN: [&str; 7] = [
    "C0_genesis",
    "C1_grant_bob",
    "C2_invite_grant",
    "C3_invite_claim_carol",
    "C4_owner_transfer_commit",
    "C5_route_update",
    "C6_key_epoch_1",
];

struct Fixture {
    suite: Suite,
    principals: BTreeMap<String, PrincipalKeys>,
    history: Vec<ControlState>,
}

impl Fixture {
    fn load() -> Fixture {
        let suite = Suite::load();
        let bytes: Vec<Vec<u8>> = CHAIN
            .iter()
            .map(|id| hex(id, &suite.case(id)["expected"]["cose_sign1"]))
            .collect();
        let refs: Vec<&[u8]> = bytes.iter().map(Vec::as_slice).collect();
        let (_, history) = validate_authorized(&refs, None).unwrap();
        Fixture {
            principals: suite.principals(),
            suite,
            history,
        }
    }

    fn record_id(&self, case_id: &str) -> ControlRecordId {
        ControlRecordId::from_bytes(hex32(
            case_id,
            &self.suite.case(case_id)["expected"]["record_id"],
        ))
    }

    fn state(&self, case_id: &str) -> &ControlState {
        state_at(&self.history, &self.record_id(case_id)).unwrap()
    }

    fn unit(&self, case_id: &str, field: &str) -> DataUnitHeader {
        // Bytes cases publish the unit as expected output, negatives as input.
        let case = self.suite.case(case_id);
        let value = case["expected"]
            .get(field)
            .unwrap_or(&case["inputs"][field]);
        let bytes = hex(case_id, value);
        let received = ReceivedDataUnit::parse(&bytes).unwrap();
        let actor = principal_by_id(&self.principals, case_id, &received.header().actor);
        received
            .verify(actor.descriptor())
            .unwrap()
            .header()
            .clone()
    }
}

#[test]
fn c6_rotates_to_epoch_1() {
    let f = Fixture::load();
    let c5 = f.state("C5_route_update");
    assert_eq!(
        (c5.current_epoch, c5.closed_frontiers.len()),
        (0, 0),
        "C5_route_update"
    );

    let c6 = f.state("C6_key_epoch_1");
    assert_eq!(c6.current_epoch, 1, "C6_key_epoch_1: current epoch");
    assert_eq!(
        c6.dek_commitments[&1].as_bytes().as_slice(),
        hex(
            "dek_commitments",
            &f.suite.case("dek_commitments")["expected"]["dek1_commitment"]
        ),
        "C6_key_epoch_1: dek1 commitment"
    );
    let bob = *f.principals["BOB"].descriptor().id();
    let expected = Frontier::new(vec![ActorHave {
        principal: bob,
        contiguous: 2,
        extra: vec![],
    }])
    .unwrap();
    assert_eq!(
        c6.closed_frontiers[&0], expected,
        "C6_key_epoch_1: epoch 0 cutoff BOB <= 2"
    );
}

#[test]
fn d1_to_d4_by_epoch() {
    let f = Fixture::load();
    for (case_id, expected) in [
        ("D1_bob_epoch0_seq1", Disposition::Accept),
        ("D2_bob_epoch0_seq2", Disposition::Accept),
        (
            "D3_bob_epoch0_seq3_stale",
            Disposition::Quarantine(QuarantineReason::BeyondCutoff),
        ),
        ("D4_carol_epoch1_seq1", Disposition::Accept),
    ] {
        let header = f.unit(case_id, "cose_sign1");
        assert_eq!(
            client_disposition(&f.history, &header),
            Ok(expected),
            "{case_id}"
        );
    }
    // The cutoff exists only once C6 is known: with C0–C5, D3 is current
    // epoch-0 work.
    let d3 = f.unit("D3_bob_epoch0_seq3_stale", "cose_sign1");
    assert_eq!(
        client_disposition(&f.history[..6], &d3),
        Ok(Disposition::Accept),
        "D3_bob_epoch0_seq3_stale: before C6"
    );
}

#[test]
fn stale_epoch_is_a_stale_data_epoch_nack() {
    let f = Fixture::load();
    let case_id = "stale_epoch";
    let case = f.suite.case(case_id);
    // The vector names D3 by unit ID.
    assert_eq!(
        hex(case_id, &case["inputs"]["unit_id"]),
        hex(
            "D3_bob_epoch0_seq3_stale",
            &f.suite.case("D3_bob_epoch0_seq3_stale")["expected"]["unit_id"]
        ),
        "{case_id}: unit is D3"
    );
    let d3 = f.unit("D3_bob_epoch0_seq3_stale", "cose_sign1");
    let err = server_accepts_data_put(&f.history, &d3).expect_err("stale_epoch: accepted");
    assert_eq!(
        err,
        Error::StaleDataEpoch(QuarantineReason::BeyondCutoff),
        "{case_id}"
    );
    assert_eq!(
        err.wire_code().map(|c| c.name()),
        case["expected"]["error"]["code"].as_str(),
        "{case_id}"
    );
    assert_eq!(case["expected"]["valid"], false, "{case_id}");
}

#[test]
fn stale_epoch_absent_actor_is_quarantined() {
    let f = Fixture::load();
    let case_id = "stale_epoch_absent_actor";
    let case = f.suite.case(case_id);
    assert_eq!(
        case["context"]["closed_epoch"], 0,
        "{case_id}: closed epoch"
    );
    assert_eq!(
        case["context"]["cutoff_record"]["case"], "C6_key_epoch_1",
        "{case_id}: cutoff"
    );

    let unit = f.unit(case_id, "cose_sign1");
    assert_eq!(unit.data_epoch, 0, "{case_id}: epoch 0");
    assert_eq!(
        client_disposition(&f.history, &unit),
        Ok(Disposition::Quarantine(QuarantineReason::ActorAbsent)),
        "{case_id}: client"
    );
    let err = server_accepts_data_put(&f.history, &unit).unwrap_err();
    assert_eq!(
        err.wire_code().map(|c| c.name()),
        case["expected"]["error"]["code"].as_str(),
        "{case_id}"
    );
    assert_eq!(case["expected"]["disposition"], "quarantine", "{case_id}");
}

#[test]
fn key_packages_need_a_known_epoch() {
    let f = Fixture::load();
    let case_id = "KPC_carol_epoch1";
    let bytes = hex(case_id, &f.suite.case(case_id)["expected"]["cose_sign1"]);
    let received = ReceivedKeyPackage::parse(&bytes).unwrap();
    assert_eq!(received.header().data_epoch, 1, "{case_id}: epoch 1");
    let (bob, carol) = (&f.principals["BOB"], &f.principals["CAROL"]);
    received
        .verify(bob.descriptor(), key_package_policy(&f.history))
        .unwrap_or_else(|err| panic!("{case_id}: {err}"));

    // Synthetic: epoch 2 at C6, and epoch 1 at C5, where it is not known.
    let c6 = f.state("C6_key_epoch_1");
    for (label, epoch, head) in [
        ("epoch 2 at C6", 2, f.record_id("C6_key_epoch_1")),
        ("epoch 1 at C5", 1, f.record_id("C5_route_update")),
    ] {
        let package = KeyPackage::seal(
            c6.resource_id,
            epoch,
            Hash32::from_bytes(*head.as_bytes()),
            &Dek::from_bytes([5; 32]),
            carol.descriptor(),
            bob,
        )
        .unwrap();
        let received = ReceivedKeyPackage::parse(package.signed_object().bytes()).unwrap();
        assert_eq!(
            received.verify(bob.descriptor(), key_package_policy(&f.history)),
            Err(Error::UnknownDataEpoch(epoch)),
            "{label}"
        );
    }
}

#[test]
fn snapshots_need_a_known_epoch() {
    let f = Fixture::load();
    for case_id in ["SNAPSHOT-01", "SNAPSHOT-02"] {
        let bytes = hex(case_id, &f.suite.case(case_id)["expected"]["cose_sign1"]);
        let received = ReceivedSnapshot::parse(&bytes).unwrap();
        let publisher = principal_by_id(&f.principals, case_id, &received.header().publisher);
        received
            .verify_with(publisher.descriptor(), snapshot_policy(&f.history))
            .unwrap_or_else(|err| panic!("{case_id}: {err}"));
    }
}

#[test]
fn a_snapshot_beyond_a_closed_epochs_cutoff_is_stale() {
    // §29 (G-EP4): an epoch-0 Snapshot at C5 whose frontier covers BOB
    // 1..3, beyond C6's cutoff (BOB 2).
    let f = Fixture::load();
    let case_id = "snapshot_beyond_cutoff";
    let case = f.suite.case(case_id);
    assert_eq!(case["context"]["closed_epoch"], 0, "{case_id}");
    assert_eq!(
        case["context"]["cutoff_record"]["case"], "C6_key_epoch_1",
        "{case_id}"
    );
    let bytes = hex(case_id, &case["inputs"]["cose_sign1"]);
    let publisher = |received: &ReceivedSnapshot| {
        principal_by_id(&f.principals, case_id, &received.header().publisher)
            .descriptor()
            .clone()
    };
    let received = ReceivedSnapshot::parse(&bytes).unwrap();
    let signer = publisher(&received);
    let err = received
        .verify_with(&signer, snapshot_policy(&f.history))
        .unwrap_err();
    assert_eq!(
        err,
        Error::StaleDataEpoch(QuarantineReason::BeyondCutoff),
        "{case_id}"
    );
    assert_eq!(
        err.wire_code().map(|c| c.name()),
        case["expected"]["error"]["code"].as_str(),
        "{case_id}"
    );
    assert_eq!(case["expected"]["disposition"], "reject", "{case_id}");

    // G-EP1: the latest known state decides. A verifier that knows the
    // chain only up to C5, where epoch 0 is still current, accepts it.
    let c5 = CHAIN
        .iter()
        .position(|id| *id == "C5_route_update")
        .unwrap();
    let received = ReceivedSnapshot::parse(&bytes).unwrap();
    assert!(received
        .verify_with(&signer, snapshot_policy(&f.history[..=c5]))
        .is_ok());
}

/// Synthetic Key Epoch records on top of the published chain.
mod synthetic {
    use super::*;

    /// A Key Epoch payload continuing `state`, signed by `issuer`, with a
    /// raw final frontier value (so it can be non-canonical).
    fn key_epoch(
        state: &ControlState,
        issuer: &PrincipalKeys,
        epoch: u64,
        frontier: Value,
    ) -> Vec<u8> {
        let body = Value::Map(vec![
            (Value::Unsigned(0), Value::Unsigned(epoch)),
            (Value::Unsigned(1), Value::bytes(vec![7; 32])),
            (Value::Unsigned(2), frontier),
            (Value::Unsigned(3), Value::Unsigned(0)),
        ]);
        let payload = Value::Map(vec![
            (
                Value::Unsigned(0),
                Value::bytes(state.resource_id.as_bytes().to_vec()),
            ),
            (Value::Unsigned(1), Value::Unsigned(state.head.sequence + 1)),
            (
                Value::Unsigned(2),
                Value::bytes(state.head.id.as_bytes().to_vec()),
            ),
            (Value::Unsigned(3), Value::Unsigned(4)),
            (
                Value::Unsigned(4),
                Value::bytes(issuer.descriptor().id().as_bytes().to_vec()),
            ),
            (Value::Unsigned(5), body),
        ]);
        cose::sign(&cbor::encode(&payload).unwrap(), issuer)
            .unwrap()
            .bytes()
            .to_vec()
    }

    fn have(principal: &PrincipalKeys, contiguous: u64) -> Value {
        ActorHave {
            principal: *principal.descriptor().id(),
            contiguous,
            extra: vec![],
        }
        .to_value()
    }

    fn propose(state: &ControlState, bytes: &[u8]) -> Result<ControlState, Error> {
        propose_transition(state, state.head.id, bytes)
    }

    #[test]
    fn epoch_must_be_the_next_one() {
        let f = Fixture::load();
        let bob = &f.principals["BOB"];
        let c5 = f.state("C5_route_update");
        let frontier = Value::Array(vec![have(bob, 2)]);
        let err = propose(c5, &key_epoch(c5, bob, 2, frontier.clone())).unwrap_err();
        assert_eq!(
            err,
            Error::InvalidControlChain(ChainRule::EpochNotNext),
            "epoch skip 0 -> 2"
        );
        assert_eq!(
            err.wire_code().unwrap().name(),
            "INVALID_CONTROL_CHAIN",
            "epoch skip"
        );
        let c6 = f.state("C6_key_epoch_1");
        assert_eq!(
            propose(c6, &key_epoch(c6, bob, 1, frontier.clone())).unwrap_err(),
            Error::InvalidControlChain(ChainRule::EpochNotNext),
            "epoch 1 again"
        );
        let next = propose(c6, &key_epoch(c6, bob, 2, frontier)).unwrap();
        assert_eq!(next.current_epoch, 2, "epoch 2 after C6");
        assert_eq!(next.closed_frontiers.len(), 2, "epochs 0 and 1 closed");
    }

    #[test]
    fn final_frontier_must_be_canonical() {
        let f = Fixture::load();
        let (bob, carol) = (&f.principals["BOB"], &f.principals["CAROL"]);
        let c5 = f.state("C5_route_update");
        // CAROL's ID sorts after BOB's (§28.2 raw byte order).
        assert!(bob
            .descriptor()
            .id()
            .cmp_frontier_order(carol.descriptor().id())
            .is_lt());
        for (label, frontier, rule) in [
            (
                "unsorted",
                vec![have(carol, 1), have(bob, 2)],
                FrontierRule::EntriesUnsorted,
            ),
            (
                "duplicate",
                vec![have(bob, 2), have(bob, 2)],
                FrontierRule::DuplicatePrincipal,
            ),
        ] {
            let err = propose(c5, &key_epoch(c5, bob, 1, Value::Array(frontier))).unwrap_err();
            assert_eq!(err, Error::FrontierNotCanonical(rule), "{label}");
            assert_eq!(
                err.wire_code().unwrap().name(),
                "MALFORMED_MESSAGE",
                "{label}"
            );
        }
    }
}
