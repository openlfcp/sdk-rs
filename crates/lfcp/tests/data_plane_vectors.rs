//! LFCP-TEST-VECTORS-01 cases for the Data Plane: DEK commitments, Data
//! Units D1–D4, Snapshots and their negative cases.
//!
//! Every value is rebuilt from the vector inputs and compared byte for
//! byte. Every assertion names the vector case it checks.

mod support;

use lfcp::base::{DataUnitId, Error, FrontierRule, ResourceId};
use lfcp::cbor;
use lfcp::crypto;
use lfcp::wire::data_unit::{
    check_chain, check_equivocation, ChainReport, ChainStatus, DataUnit, ReceivedDataUnit,
};
use lfcp::wire::frontier::Frontier;
use lfcp::wire::keys::{dek_commitment, sequence_nonce, ActorKey, Dek, SnapshotKey};
use lfcp::wire::snapshot::{ReceivedSnapshot, Snapshot, SnapshotHeader};
use serde_json::Value as Json;
use support::vectors::{hex, hex32, id_of, principal_by_id, Suite};

fn resource(suite: &Suite) -> ResourceId {
    ResourceId::from_bytes(hex32("fixtures", &suite.json["fixtures"]["resource"]["id"]))
}

/// The fixture DEK of `epoch` (`fixtures.resource.dek0`, `dek1`).
fn dek(suite: &Suite, epoch: u64) -> Dek {
    let field = &suite.json["fixtures"]["resource"][format!("dek{epoch}")];
    Dek::from_bytes(hex32("fixtures", field))
}

/// The DEK a case names in `inputs.dek` (V3), checked to be the fixture
/// DEK of `epoch`.
fn case_dek(suite: &Suite, case: &Json, epoch: u64) -> Dek {
    let case_id = id_of(case);
    let name = case["inputs"]["dek"]
        .as_str()
        .unwrap_or_else(|| panic!("{case_id}: no inputs.dek"));
    assert_eq!(
        name,
        format!("dek{epoch}"),
        "{case_id}: inputs.dek names epoch {epoch}"
    );
    dek(suite, epoch)
}

fn input_u64(case: &Json, name: &str) -> u64 {
    case["inputs"][name]
        .as_u64()
        .unwrap_or_else(|| panic!("{}: inputs.{name} is not an integer", id_of(case)))
}

/// Parse a Data Unit and verify it against its actor, a fixture Principal.
fn verified_unit(suite: &Suite, case_id: &str, bytes: &[u8]) -> DataUnit {
    let received = ReceivedDataUnit::parse(bytes)
        .unwrap_or_else(|err| panic!("{case_id}: parse failed: {err}"));
    let principals = suite.principals();
    let actor = principal_by_id(&principals, case_id, &received.header().actor);
    received
        .verify(actor.descriptor())
        .unwrap_or_else(|err| panic!("{case_id}: verify failed: {err}"))
}

fn expect_invalid(case: &Json, disposition: &str, code: Option<&str>) {
    let case_id = id_of(case);
    let expected = &case["expected"];
    assert_eq!(expected["valid"], false, "{case_id}: valid");
    if !expected["disposition"].is_null() {
        assert_eq!(
            expected["disposition"], disposition,
            "{case_id}: disposition"
        );
    }
    assert_eq!(
        expected["error"]["code"].as_str(),
        code,
        "{case_id}: expected error code"
    );
}

#[test]
fn dek_commitments_match() {
    let suite = Suite::load();
    let case = suite.case("dek_commitments");
    for name in ["dek0", "dek1"] {
        let epoch = input_u64(case, &format!("{name}_epoch"));
        let expected = hex(
            "dek_commitments",
            &case["expected"][format!("{name}_commitment")],
        );
        assert_eq!(
            dek_commitment(&resource(&suite), epoch, &dek(&suite, epoch))
                .as_bytes()
                .as_slice(),
            expected,
            "dek_commitments: {name}"
        );
    }
}

const DATA_UNITS: [&str; 4] = [
    "D1_bob_epoch0_seq1",
    "D2_bob_epoch0_seq2",
    "D3_bob_epoch0_seq3_stale",
    "D4_carol_epoch1_seq1",
];

#[test]
fn data_units_rebuild_byte_exact() {
    let suite = Suite::load();
    let principals = suite.principals();
    let mut previous: Option<DataUnit> = None;
    for case_id in DATA_UNITS {
        let case = suite.case(case_id);
        let expected = &case["expected"];
        let field = |name: &str| hex(case_id, &expected[name]);
        let plaintext = hex(case_id, &case["inputs"]["plaintext_hex"]);
        assert_eq!(
            plaintext,
            case["inputs"]["plaintext_utf8"]
                .as_str()
                .unwrap()
                .as_bytes(),
            "{case_id}: plaintext"
        );

        // The header comes from the published payload; everything derived
        // from it is recomputed.
        let received = ReceivedDataUnit::parse(&field("cose_sign1"))
            .unwrap_or_else(|err| panic!("{case_id}: parse failed: {err}"));
        let header = received.header().clone();
        assert_eq!(header.resource_id, resource(&suite), "{case_id}: resource");
        let dek = case_dek(&suite, case, header.data_epoch);

        let actor_key =
            ActorKey::derive(&dek, &header.resource_id, header.data_epoch, &header.actor);
        assert_eq!(
            actor_key.expose_secret().as_slice(),
            field("actor_key"),
            "{case_id}: actor_key"
        );
        let nonce = sequence_nonce(header.sequence);
        assert_eq!(nonce.as_slice(), field("nonce"), "{case_id}: nonce");
        assert_eq!(header.aad(), field("aad_cbor"), "{case_id}: aad_cbor");
        let ciphertext =
            crypto::aead_seal(actor_key.expose_secret(), &nonce, &plaintext, &header.aad());
        assert_eq!(ciphertext, field("ciphertext"), "{case_id}: ciphertext");

        let signer = principal_by_id(&principals, case_id, &header.actor);
        let sealed = DataUnit::seal(header.clone(), &plaintext, &dek, signer)
            .unwrap_or_else(|err| panic!("{case_id}: seal failed: {err}"));
        assert_eq!(
            sealed.signed_object().payload_bytes(),
            field("payload_cbor"),
            "{case_id}: payload_cbor"
        );
        assert_eq!(
            sealed.signed_object().bytes(),
            field("cose_sign1"),
            "{case_id}: cose_sign1"
        );
        assert_eq!(
            sealed.id().as_bytes().as_slice(),
            field("unit_id"),
            "{case_id}: unit_id"
        );

        let unit = received
            .verify(signer.descriptor())
            .unwrap_or_else(|err| panic!("{case_id}: verify failed: {err}"));
        assert_eq!(unit, sealed, "{case_id}: received equals sealed");
        assert_eq!(unit.open(&dek).as_ref(), Ok(&plaintext), "{case_id}: open");

        // D1–D3 are one chain; D4 starts Carol's.
        let link = match &previous {
            Some(before) if before.header().actor == header.actor => Some(before),
            _ => None,
        };
        assert_eq!(
            check_chain(&unit, link),
            ChainStatus::Linked,
            "{case_id}: hash chain"
        );
        previous = Some(unit);
    }
}

#[test]
fn snapshots_rebuild_byte_exact() {
    let suite = Suite::load();
    let principals = suite.principals();
    for case_id in ["SNAPSHOT-01", "SNAPSHOT-02"] {
        let case = suite.case(case_id);
        let inputs = &case["inputs"];
        let expected = &case["expected"];
        let field = |name: &str| hex(case_id, &expected[name]);
        let signer = &principals[inputs["signer"].as_str().unwrap()];
        let plaintext = hex(case_id, &inputs["plaintext_hex"]);

        let frontier_cbor = field("frontier_cbor");
        let frontier = Frontier::from_value(&cbor::decode_strict(&frontier_cbor).unwrap())
            .unwrap_or_else(|err| panic!("{case_id}: frontier: {err}"));
        assert_eq!(
            cbor::encode(&frontier.to_value()).unwrap(),
            frontier_cbor,
            "{case_id}: frontier_cbor"
        );

        let header = SnapshotHeader {
            resource_id: resource(&suite),
            data_epoch: input_u64(case, "data_epoch"),
            publisher: *signer.descriptor().id(),
            sequence: input_u64(case, "snapshot_sequence"),
            control_head: lfcp::base::Hash32::from_bytes(hex32(case_id, &inputs["control_head"])),
            frontier,
        };
        let dek = case_dek(&suite, case, header.data_epoch);
        let key = SnapshotKey::derive(
            &dek,
            &header.resource_id,
            header.data_epoch,
            &header.publisher,
        );
        assert_eq!(
            key.expose_secret().as_slice(),
            field("snapshot_key"),
            "{case_id}: snapshot_key"
        );
        let nonce = sequence_nonce(header.sequence);
        assert_eq!(nonce.as_slice(), field("nonce"), "{case_id}: nonce");
        assert_eq!(header.aad(), field("aad_cbor"), "{case_id}: aad_cbor");
        assert_eq!(
            crypto::aead_seal(key.expose_secret(), &nonce, &plaintext, &header.aad()),
            field("ciphertext"),
            "{case_id}: ciphertext"
        );

        let sealed = Snapshot::seal(header, &plaintext, &dek, signer)
            .unwrap_or_else(|err| panic!("{case_id}: seal failed: {err}"));
        let object = sealed.signed_object();
        assert_eq!(
            object.payload_bytes(),
            field("payload_cbor"),
            "{case_id}: payload_cbor"
        );
        assert_eq!(
            object.protected_bytes(),
            field("protected_header_cbor"),
            "{case_id}: protected"
        );
        assert_eq!(
            object.sig_structure(),
            field("sig_structure_cbor"),
            "{case_id}: sig_structure"
        );
        assert_eq!(object.bytes(), field("cose_sign1"), "{case_id}: cose_sign1");
        assert_eq!(
            sealed.id().as_bytes().as_slice(),
            field("snapshot_id"),
            "{case_id}: snapshot_id"
        );

        let received = ReceivedSnapshot::parse(&field("cose_sign1"))
            .unwrap_or_else(|err| panic!("{case_id}: parse failed: {err}"));
        let snapshot = received
            .verify(signer.descriptor())
            .unwrap_or_else(|err| panic!("{case_id}: verify failed: {err}"));
        assert_eq!(snapshot, sealed, "{case_id}: received equals sealed");
        assert_eq!(
            snapshot.open(&dek).as_ref(),
            Ok(&plaintext),
            "{case_id}: open"
        );
    }
}

#[test]
fn aead_negatives_are_client_local() {
    let suite = Suite::load();
    for case_id in ["noncanonical_aad_D1", "aead_failure_D1"] {
        let case = suite.case(case_id);
        let unit = verified_unit(
            &suite,
            case_id,
            &hex(case_id, &case["inputs"]["cose_sign1"]),
        );
        let dek = dek(&suite, unit.header().data_epoch);
        let err = unit.open(&dek).expect_err(&format!("{case_id}: opened"));
        assert_eq!(err, Error::AeadFailure, "{case_id}");
        assert_eq!(err.wire_code(), None, "{case_id}: no wire code");
        assert!(err.is_client_local(), "{case_id}: client-local");
        expect_invalid(case, "reject", None);
    }

    // The mutation behind noncanonical_aad_D1: the unit was sealed under a
    // non-deterministic encoding of the real AAD. That AAD opens it, but a
    // receiver never reconstructs it.
    let case_id = "noncanonical_aad_D1";
    let case = suite.case(case_id);
    let unit = verified_unit(
        &suite,
        case_id,
        &hex(case_id, &case["inputs"]["cose_sign1"]),
    );
    let bad_aad = hex(case_id, &case["inputs"]["noncanonical_aad_cbor"]);
    assert_eq!(
        cbor::check_deterministic(&bad_aad).map(|_| ()),
        Err(Error::CborNotDeterministic),
        "{case_id}: the AAD is not deterministic"
    );
    assert_ne!(
        bad_aad,
        unit.header().aad(),
        "{case_id}: differs from the canonical AAD"
    );
    let header = unit.header();
    let key = ActorKey::derive(
        &dek(&suite, header.data_epoch),
        &header.resource_id,
        header.data_epoch,
        &header.actor,
    );
    assert!(
        crypto::aead_open(
            key.expose_secret(),
            &sequence_nonce(header.sequence),
            unit.ciphertext(),
            &bad_aad
        )
        .is_ok(),
        "{case_id}: sealed under the non-deterministic AAD"
    );
}

#[test]
fn sequence_zero_is_malformed() {
    let suite = Suite::load();
    let case_id = "actor_seq_zero_D1";
    let case = suite.case(case_id);
    let err = ReceivedDataUnit::parse(&hex(case_id, &case["inputs"]["cose_sign1"]))
        .expect_err("actor_seq_zero_D1: parsed");
    assert_eq!(err, Error::DataUnitSequenceZero, "{case_id}");
    expect_invalid(case, "reject", err.wire_code().map(|code| code.name()));
    assert_eq!(
        case["expected"]["error"]["code"], "MALFORMED_MESSAGE",
        "{case_id}"
    );
}

#[test]
fn previous_unit_at_sequence_one_is_reported() {
    let suite = Suite::load();
    let case_id = "actor_seq1_prev_not_null_D1";
    let case = suite.case(case_id);
    let unit = verified_unit(
        &suite,
        case_id,
        &hex(case_id, &case["inputs"]["cose_sign1"]),
    );
    assert_eq!(
        check_chain(&unit, None),
        ChainStatus::Report(ChainReport::PreviousAtSequenceOne),
        "{case_id}"
    );
    expect_invalid(case, "report", None);
}

#[test]
fn equivocation_is_detected() {
    let suite = Suite::load();
    let case_id = "actor_equivocation";
    let case = suite.case(case_id);
    let inputs = &case["inputs"];

    let d2 = suite.case("D2_bob_epoch0_seq2");
    let original = verified_unit(
        &suite,
        case_id,
        &hex(case_id, &d2["expected"]["cose_sign1"]),
    );
    let conflicting = verified_unit(
        &suite,
        case_id,
        &hex(case_id, &inputs["conflicting_D2_cose"]),
    );
    assert_eq!(
        original.id(),
        DataUnitId::from_bytes(hex32(case_id, &inputs["original_D2_id"])),
        "{case_id}: original_D2_id"
    );
    assert_eq!(
        conflicting.id(),
        DataUnitId::from_bytes(hex32(case_id, &inputs["conflicting_D2_id"])),
        "{case_id}: conflicting_D2_id"
    );
    let err = check_equivocation(&original, &conflicting).expect_err("actor_equivocation: missed");
    assert_eq!(err, Error::ActorEquivocation, "{case_id}");
    expect_invalid(case, "reject", err.wire_code().map(|code| code.name()));
}

#[test]
fn non_canonical_frontiers_are_malformed() {
    use FrontierRule::*;
    let suite = Suite::load();
    for (case_id, rule) in [
        ("have_empty_extra_list", EmptyExtraList),
        ("have_range_reversed", RangeReversed),
        ("have_range_not_above_contiguous", RangeNotAboveContiguous),
        // §28.1 rule 5 (W3).
        ("have_range_at_contiguous_plus_one", RangeNotAboveContiguous),
        ("have_ranges_unsorted", RangesUnsorted),
        ("have_ranges_overlapping", RangesOverlapping),
        ("have_ranges_adjacent", RangesAdjacent),
        ("frontier_duplicate_principal", DuplicatePrincipal),
        ("frontier_unsorted", EntriesUnsorted),
    ] {
        let case = suite.case(case_id);
        let err = ReceivedSnapshot::parse(&hex(case_id, &case["inputs"]["cose_sign1"]))
            .expect_err(&format!("{case_id}: parsed"));
        assert_eq!(err, Error::FrontierNotCanonical(rule), "{case_id}");
        expect_invalid(case, "reject", err.wire_code().map(|code| code.name()));
    }
}

#[test]
fn snapshot_sequence_zero_is_rejected() {
    // §29 (W5): Snapshot Sequences begin at 1. The vector names no code;
    // this crate uses MALFORMED_MESSAGE provisionally.
    let suite = Suite::load();
    let case_id = "snapshot_sequence_zero";
    let case = suite.case(case_id);
    let err = ReceivedSnapshot::parse(&hex(case_id, &case["inputs"]["cose_sign1"]))
        .expect_err("snapshot_sequence_zero: parsed");
    assert_eq!(err, Error::SnapshotSequenceZero, "{case_id}");
    expect_invalid(case, "reject", None);
}

#[test]
fn every_unit_and_snapshot_case_names_the_dek_of_its_epoch() {
    // V3: inputs.dek names fixtures.resource.dek<epoch>. Units given by
    // reference (stale_epoch) take the epoch of the referenced unit.
    let suite = Suite::load();
    // A negative whose object does not parse (a tag, a non-canonical
    // payload) has the epoch of its base case.
    let epoch_of = |case: &Json, bytes: &[u8]| -> u64 {
        let object = lfcp::cose::parse(bytes).unwrap_or_else(|_| {
            let base = suite.case(case["derivation"]["base_case"].as_str().unwrap());
            lfcp::cose::parse(&hex(id_of(base), &base["expected"]["cose_sign1"])).unwrap()
        });
        object
            .payload()
            .get_uint(1)
            .and_then(|v| v.as_u64())
            .unwrap()
    };
    let mut checked = 0;
    for case in suite
        .cases()
        .filter(|c| c["kind"] == "data_unit" || c["kind"] == "snapshot")
    {
        let case_id = id_of(case);
        let cose = case["inputs"]
            .get("cose_sign1")
            .or(case["inputs"].get("conflicting_D2_cose"))
            .or(case["expected"].get("cose_sign1"));
        let bytes = match cose {
            Some(field) => hex(case_id, field),
            None => {
                let unit = hex(case_id, &case["inputs"]["unit_id"]);
                let target = suite
                    .cases()
                    .find(|c| {
                        c["type"] == "bytes"
                            && c["kind"] == "data_unit"
                            && hex(id_of(c), &c["expected"]["unit_id"]) == unit
                    })
                    .unwrap_or_else(|| panic!("{case_id}: unit_id names no unit"));
                hex(id_of(target), &target["expected"]["cose_sign1"])
            }
        };
        case_dek(&suite, case, epoch_of(case, &bytes));
        checked += 1;
    }
    assert!(checked >= 20, "only {checked} cases");
}
