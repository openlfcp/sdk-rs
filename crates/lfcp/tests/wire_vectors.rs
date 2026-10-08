//! LFCP-TEST-VECTORS-01 cases for the protocol primitives: Principals,
//! deterministic CBOR, canonical COSE_Sign1 and base64url references.
//!
//! The vectors are read from the spec commit pinned in `spec.lock`, never
//! copied. Every assertion names the vector case it checks.

mod support;

use std::collections::BTreeMap;

use lfcp::base::{self, Error, PrincipalId};
use lfcp::cbor::{self, Value};
use lfcp::cose;
use lfcp::principal::{PrincipalDescriptor, PrincipalKeys};
use serde_json::Value as Json;
use support::vectors::{hex, hex32, id_of, principal_by_id, Suite};

fn payload_principal(case_id: &str, payload: &Value, key: u64) -> PrincipalId {
    let bytes = payload
        .get_uint(key)
        .and_then(Value::as_bytes)
        .unwrap_or_else(|| panic!("{case_id}: payload field {key} is not a byte string"));
    PrincipalId::from_slice(bytes).unwrap_or_else(|err| panic!("{case_id}: {err}"))
}

#[test]
fn principals_derive_byte_exact() {
    let suite = Suite::load();
    let mut checked = 0;
    for case in suite.cases() {
        if case["kind"] != "principal" || case["type"] != "bytes" {
            continue;
        }
        let id = id_of(case);
        let expected = &case["expected"];
        let keys = PrincipalKeys::from_secrets(
            &hex32(id, &case["inputs"]["ed25519_seed"]),
            hex32(id, &case["inputs"]["x25519_private"]),
        );
        let descriptor = keys.descriptor();
        assert_eq!(
            descriptor.ed25519_public().as_slice(),
            hex(id, &expected["ed25519_public"]),
            "{id}: ed25519_public"
        );
        assert_eq!(
            descriptor.x25519_public().as_slice(),
            hex(id, &expected["x25519_public"]),
            "{id}: x25519_public"
        );
        assert_eq!(
            descriptor.id().as_bytes().as_slice(),
            hex(id, &expected["principal_id"]),
            "{id}: principal_id"
        );
        let descriptor_cbor = hex(id, &expected["descriptor_cbor"]);
        assert_eq!(
            descriptor.encode(),
            descriptor_cbor,
            "{id}: descriptor_cbor"
        );
        assert_eq!(
            PrincipalDescriptor::decode(&descriptor_cbor).as_ref(),
            Ok(descriptor),
            "{id}: decoding descriptor_cbor"
        );
        checked += 1;
    }
    assert_eq!(checked, 4, "expected four principal_* cases");
}

/// What each signed object in a `bytes` case is checked against.
struct SignedCase<'a> {
    case_id: &'a str,
    /// The prefix of the object's field names: "" or "offer_", "accept_",
    /// "auth_proof_".
    prefix: String,
    cose: Vec<u8>,
    payload: Vec<u8>,
    id: Option<Vec<u8>>,
    protected: Option<Vec<u8>>,
    sig_structure: Option<Vec<u8>>,
}

/// Every signed object in the `bytes` cases, with its expected parts.
fn signed_cases(suite: &Suite) -> Vec<SignedCase<'_>> {
    let mut out = Vec::new();
    for case in suite.cases() {
        if case["type"] != "bytes" {
            continue;
        }
        let case_id = id_of(case);
        let expected = case["expected"].as_object().expect("expected object");
        let field = |name: &str| expected.get(name).map(|v| hex(case_id, v));
        for key in expected.keys().filter(|k| k.ends_with("cose_sign1")) {
            let prefix = key.trim_end_matches("cose_sign1");
            let payload_key = match prefix {
                "auth_proof_" => "auth_transcript_cbor".to_owned(),
                _ => format!("{prefix}payload_cbor"),
            };
            let id = match prefix {
                "" => ["record_id", "unit_id", "package_id", "snapshot_id"]
                    .iter()
                    .find_map(|name| field(name)),
                "offer_" | "accept_" => field(&format!("{prefix}id")),
                _ => None,
            };
            let unprefixed = |name: &str| if prefix.is_empty() { field(name) } else { None };
            out.push(SignedCase {
                case_id,
                prefix: prefix.to_owned(),
                cose: field(key).unwrap(),
                payload: field(&payload_key)
                    .unwrap_or_else(|| panic!("{case_id}: no {payload_key}")),
                id,
                protected: unprefixed("protected_header_cbor"),
                sig_structure: unprefixed("sig_structure_cbor"),
            });
        }
    }
    out
}

/// The Principal a signed object in a `bytes` case requires as signer.
///
/// Every case names it (G-RS3): `inputs.signer`, or `inputs.offer_signer`
/// and `inputs.accept_signer` for the two objects of `owner_transfer`.
/// The name is cross-checked with the signer the WIRE section of the
/// object type requires.
fn required_signer<'a>(
    suite: &Suite,
    principals: &'a BTreeMap<String, PrincipalKeys>,
    expected: &SignedCase<'_>,
    object: &cose::SignedObject,
) -> &'a PrincipalKeys {
    let case_id = expected.case_id;
    let case = suite.case(case_id);
    let kind = case["kind"].as_str().unwrap();
    let payload = object.payload();
    let key = match expected.prefix.as_str() {
        "offer_" | "accept_" => format!("{}signer", expected.prefix),
        _ => "signer".to_owned(),
    };
    let named = case["inputs"][key.as_str()].as_str().map(|name| {
        principals
            .get(name)
            .unwrap_or_else(|| panic!("{case_id}: unknown signer fixture {name}"))
    });
    // The payload field that names the signer, per object type.
    let from_payload = match kind {
        // §13: field 4 is the issuer.
        "control_record" => Some(4),
        // §26: "The payload is signed by the actor", field 2.
        "data_unit" => Some(2),
        // §29: "signed by the publisher", field 2.
        "snapshot" => Some(2),
        // §25: the sender, field 4.
        "key_package" => Some(4),
        _ => None,
    }
    .map(|key| {
        principal_by_id(
            principals,
            case_id,
            &payload_principal(case_id, payload, key),
        )
    });

    match (named, from_payload) {
        (Some(named), Some(from_payload)) => {
            assert_eq!(
                named.descriptor().id(),
                from_payload.descriptor().id(),
                "{case_id}: inputs.signer and the payload disagree on the signer"
            );
            named
        }
        (Some(named), None) => {
            assert_eq!(
                named.descriptor().id(),
                rule_signer(principals, case_id, kind, payload)
                    .descriptor()
                    .id(),
                "{case_id}: inputs.{key} and the WIRE rule disagree on the signer"
            );
            named
        }
        (None, _) => panic!("{case_id}: no inputs.{key} (G-RS3)"),
    }
}

/// The signer of an object whose payload has no signer field, by its WIRE
/// section.
fn rule_signer<'a>(
    principals: &'a BTreeMap<String, PrincipalKeys>,
    case_id: &str,
    kind: &str,
    payload: &Value,
) -> &'a PrincipalKeys {
    if kind == "wire_message" && case_id == "AUTH" {
        // §36: the transcript's last element is the session
        // Principal, whose key the proof demonstrates.
        let items = payload.as_array().expect("AUTH transcript array");
        let id = items
            .last()
            .and_then(Value::as_bytes)
            .expect("principal-id");
        principal_by_id(principals, case_id, &PrincipalId::from_slice(id).unwrap())
    } else if kind == "owner_transfer" && payload.get_uint(3).is_some() {
        // §23.1: the offer is signed by the current owner. Its payload
        // names no signer; the chain's owner is OWNER (C0_genesis).
        &principals["OWNER"]
    } else if kind == "owner_transfer" {
        // §23.2: the accept is signed by the new owner, field 2.
        principal_by_id(principals, case_id, &payload_principal(case_id, payload, 2))
    } else {
        panic!("{case_id}: no rule names the signer of this object")
    }
}

#[test]
fn signed_objects_parse_verify_and_resign_byte_exact() {
    let suite = Suite::load();
    let principals = suite.principals();
    let cases = signed_cases(&suite);
    for expected in &cases {
        let case_id = expected.case_id;
        let object = cose::parse(&expected.cose)
            .unwrap_or_else(|err| panic!("{case_id}: parse failed: {err}"));

        assert_eq!(
            object.bytes(),
            expected.cose.as_slice(),
            "{case_id}: exact bytes"
        );
        assert_eq!(
            object.payload_bytes(),
            expected.payload.as_slice(),
            "{case_id}: payload"
        );
        assert_eq!(
            object.id(),
            &lfcp::crypto::sha256(&expected.cose),
            "{case_id}: object ID is SHA-256 of the exact bytes"
        );
        if let Some(id) = &expected.id {
            assert_eq!(
                object.id().as_bytes().as_slice(),
                id.as_slice(),
                "{case_id}: object ID"
            );
        }
        if let Some(protected) = &expected.protected {
            assert_eq!(
                object.protected_bytes(),
                protected.as_slice(),
                "{case_id}: protected header"
            );
        }
        if let Some(sig_structure) = &expected.sig_structure {
            assert_eq!(
                &object.sig_structure(),
                sig_structure,
                "{case_id}: sig_structure"
            );
        }

        let signer = required_signer(&suite, &principals, expected, &object);
        assert_eq!(
            cose::verify(&object, signer.descriptor()),
            Ok(()),
            "{case_id}: verify against the required signer"
        );

        // Ed25519 is deterministic, so signing the same payload with the
        // same key must reproduce the vector byte for byte.
        let resigned = cose::sign(&expected.payload, signer)
            .unwrap_or_else(|err| panic!("{case_id}: sign failed: {err}"));
        assert_eq!(
            resigned.bytes(),
            expected.cose.as_slice(),
            "{case_id}: re-signed bytes"
        );
    }
    // 11 Control Records, offer + accept, 3 Key Packages, 4 Data Units,
    // 2 Snapshots and the AUTH proof.
    assert_eq!(cases.len(), 23, "signed objects in the bytes cases");
}

#[test]
fn every_named_signer_is_the_kid_of_its_object() {
    // G-RS3: a case that names inputs.signer carries a signed object whose
    // kid is that Principal (validation cases included; a negative may be
    // signed by the wrong Principal, but its kid says who).
    let suite = Suite::load();
    let principals = suite.principals();
    let mut checked = 0;
    for case in suite.cases() {
        let case_id = id_of(case);
        let Some(name) = case["inputs"]["signer"].as_str() else {
            continue;
        };
        let field = ["cose_sign1", "conflicting_D2_cose"]
            .iter()
            .find_map(|key| case["inputs"].get(*key))
            .or(case["expected"].get("cose_sign1"))
            .or(case["expected"].get("auth_proof_cose_sign1"));
        let Some(field) = field else {
            panic!("{case_id}: inputs.signer without a signed object")
        };
        // A tag 18 wrapper is not part of the object; skip it to read kid.
        let bytes = hex(case_id, field);
        let bytes = bytes.strip_prefix(&[0xd2][..]).unwrap_or(&bytes);
        let Ok(object) = cose::parse(bytes) else {
            continue; // noncanonical_payload_D1: not parseable as canonical
        };
        assert_eq!(
            object.kid(),
            principals[name].descriptor().id(),
            "{case_id}: kid is inputs.signer {name}"
        );
        checked += 1;
    }
    assert!(checked >= 50, "only {checked} cases");
}

#[test]
fn every_cbor_value_in_the_bytes_cases_is_deterministic() {
    let suite = Suite::load();
    let mut checked = 0;
    for case in suite.cases().filter(|case| case["type"] == "bytes") {
        let case_id = id_of(case);
        for (name, field) in case["expected"].as_object().unwrap() {
            if !(name.ends_with("_cbor") || name.ends_with("cose_sign1")) {
                continue;
            }
            let bytes = hex(case_id, field);
            assert_eq!(
                cbor::check_deterministic(&bytes).map(|_| ()),
                Ok(()),
                "{case_id}: {name} fails the N7 check"
            );
            let value = cbor::decode_strict(&bytes)
                .unwrap_or_else(|err| panic!("{case_id}: {name} fails decode_strict: {err}"));
            assert_eq!(
                cbor::encode(&value).unwrap(),
                bytes,
                "{case_id}: {name} re-encoding"
            );
            checked += 1;
        }
    }
    assert!(checked >= 100, "only {checked} CBOR values checked");
}

/// A negative vector this crate decides, and how.
fn expect_rejected(case: &Json, error: Error) {
    let case_id = id_of(case);
    let expected = &case["expected"];
    assert_eq!(
        expected["valid"], false,
        "{case_id}: vector is not a negative"
    );
    if let Some(code) = expected["error"]["code"].as_str() {
        assert_eq!(
            error.wire_code().map(|code| code.name()),
            Some(code),
            "{case_id}: wire code for {error:?}"
        );
    }
}

#[test]
fn in_scope_negative_vectors_are_rejected() {
    let suite = Suite::load();
    let principals = suite.principals();
    let bob = principals["BOB"].descriptor();

    for (case_id, expected) in [
        ("tagged_cose_D1", Error::CoseTagged),
        ("noncanonical_payload_D1", Error::CborNotDeterministic),
    ] {
        let case = suite.case(case_id);
        let err = cose::parse(&hex(case_id, &case["inputs"]["cose_sign1"]))
            .expect_err(&format!("{case_id}: parse accepted it"));
        assert_eq!(err, expected, "{case_id}");
        expect_rejected(case, err);
    }

    // Signature checks against the Data Unit actor, BOB (§26).
    // small_order_r_signature_D1 has R = the neutral element and S = k*a:
    // both equations accept it; only §10.5.1 rule 3 rejects it (G-RS2).
    for (case_id, expected) in [
        ("invalid_signature_D1", Error::SignatureInvalid),
        ("tampered_D1", Error::SignatureInvalid),
        ("wrong_kid_D1", Error::CoseKidMismatch),
        ("small_order_r_signature_D1", Error::SignatureInvalid),
    ] {
        let case = suite.case(case_id);
        let object = cose::parse(&hex(case_id, &case["inputs"]["cose_sign1"]))
            .unwrap_or_else(|err| panic!("{case_id}: parse failed: {err}"));
        assert_eq!(
            payload_principal(case_id, object.payload(), 2),
            *bob.id(),
            "{case_id}: actor is BOB"
        );
        let err = cose::verify(&object, bob).expect_err(&format!("{case_id}: verified"));
        assert_eq!(err, expected, "{case_id}");
        expect_rejected(case, err);
    }

    // wrong_kid_D1 is validly signed by its kid, CAROL: the rejection is
    // about the signer, not the signature.
    let case = suite.case("wrong_kid_D1");
    let object = cose::parse(&hex("wrong_kid_D1", &case["inputs"]["cose_sign1"])).unwrap();
    let carol = principals["CAROL"].descriptor();
    assert_eq!(object.kid(), carol.id(), "wrong_kid_D1: kid is CAROL");
    assert_eq!(
        cose::verify(&object, carol),
        Ok(()),
        "wrong_kid_D1: CAROL's signature"
    );

    let case = suite.case("descriptor_extra_field");
    let err = PrincipalDescriptor::decode(&hex(
        "descriptor_extra_field",
        &case["inputs"]["descriptor_cbor"],
    ))
    .expect_err("descriptor_extra_field: decoded");
    assert_eq!(err, Error::PrincipalMalformed, "descriptor_extra_field");
    expect_rejected(case, err.clone());
    assert_eq!(
        err.session_wire_code().unwrap().name(),
        "AUTH_FAILED",
        "descriptor_extra_field: in HELLO/AUTH (P3)"
    );

    // §7, §10.5.1 (G-RS2): an order-4 key with its ID recomputed.
    let case = suite.case("descriptor_small_order_key");
    let err = PrincipalDescriptor::decode(&hex(
        "descriptor_small_order_key",
        &case["inputs"]["descriptor_cbor"],
    ))
    .expect_err("descriptor_small_order_key: decoded");
    assert_eq!(
        err,
        Error::PrincipalKeyInvalid,
        "descriptor_small_order_key"
    );
    expect_rejected(case, err.clone());
    assert_eq!(
        err.session_wire_code().unwrap().name(),
        "AUTH_FAILED",
        "descriptor_small_order_key: in HELLO/AUTH"
    );
}

/// Validation vectors this crate does not decide, with the reason. A case
/// added here must still pass parse and verify at the COSE layer if it
/// carries a signed object.
const DEFERRED_NEGATIVES: &[(&str, &str)] = &[
    (
        "invite_uri_unknown_parameter",
        "sdk-rs has no invitation URI codec; invite_uri checks only the URI's components",
    ),
    (
        "invite_uri_duplicate_grant",
        "sdk-rs has no invitation URI codec; invite_uri checks only the URI's components",
    ),
];

/// Negative vectors this crate decides, in this file,
/// `data_plane_vectors.rs`, `control_plane_vectors.rs`,
/// `authority_vectors.rs`, `key_package_vectors.rs`, `message_vectors.rs`
/// or `epoch_vectors.rs`.
const IN_SCOPE_NEGATIVES: &[&str] = &[
    // Primitives (this file).
    "tagged_cose_D1",
    "noncanonical_payload_D1",
    "invalid_signature_D1",
    "tampered_D1",
    "wrong_kid_D1",
    "small_order_r_signature_D1",
    "descriptor_extra_field",
    "descriptor_small_order_key",
    // Data Plane (data_plane_vectors.rs).
    "noncanonical_aad_D1",
    "aead_failure_D1",
    "actor_seq_zero_D1",
    "actor_seq1_prev_not_null_D1",
    "actor_equivocation",
    "chain_gap_linked_seq4",
    "chain_prev_unknown_seq4",
    "put_previous_stored",
    "put_previous_unknown",
    "put_previous_same_put",
    "put_previous_same_put_reversed",
    "put_previous_equivocation_evidence",
    "put_previous_snapshot_frontier",
    "put_previous_snapshot_unit_between",
    "put_previous_null",
    "have_empty_extra_list",
    "have_range_reversed",
    "have_range_not_above_contiguous",
    "have_ranges_unsorted",
    "have_ranges_overlapping",
    "have_ranges_adjacent",
    "frontier_duplicate_principal",
    "frontier_unsorted",
    "have_range_at_contiguous_plus_one",
    "snapshot_sequence_zero",
    // Control Plane (control_plane_vectors.rs).
    "control_fork_C6",
    // Control Records with authority (authority_vectors.rs).
    "key_epoch_frontier_unsorted",
    "key_epoch_frontier_duplicate",
    "grant_duplicate_ability_C1",
    "grant_escalation_C9",
    "revoke_received_grant",
    "revoke_already_revoked",
    "revoke_unknown_grant",
    "route_version_not_increasing_C5",
    "genesis_signer_not_owner",
    "genesis_competing_root",
    "genesis_http_endpoint",
    "unknown_core_type_C1",
    "extension_type_non_owner_C1",
    // Key Packages (key_package_vectors.rs).
    "hpke_recipient_mismatch_KP0",
    "kp_enc_wrong_size_KP0",
    // Messages (message_vectors.rs).
    "stale_control_head_put",
    "unknown_message_type",
    "control_put_null_expected_head",
    "data_have_reversed_range",
    // Epochs (epoch_vectors.rs).
    "stale_epoch",
    "stale_epoch_absent_actor",
    "snapshot_beyond_cutoff",
    // Strict Ed25519 (ed25519_vectors.rs).
    "ed25519_rfc8032_test1",
    "ed25519_s_equals_l",
    "ed25519_s_plus_l",
    "ed25519_a_y_ge_p",
    "ed25519_r_y_ge_p",
    "ed25519_a_x0_sign_bit",
    "ed25519_r_x0_sign_bit",
    "ed25519_small_order_a",
    "ed25519_mixed_order_a",
    "ed25519_small_order_r",
];

#[test]
fn every_negative_vector_is_in_scope_or_deferred() {
    let suite = Suite::load();
    for case in suite.cases().filter(|case| case["type"] == "validation") {
        let case_id = id_of(case);
        let in_scope = IN_SCOPE_NEGATIVES.contains(&case_id);
        let deferred = DEFERRED_NEGATIVES.iter().any(|(id, _)| *id == case_id);
        assert!(
            in_scope != deferred,
            "{case_id}: list it exactly once, as in scope or deferred"
        );
    }
}

#[test]
fn deferred_negatives_pass_the_cose_layer() {
    let suite = Suite::load();
    let principals = suite.principals();
    for (case_id, _) in DEFERRED_NEGATIVES {
        let inputs = &suite.case(case_id)["inputs"];
        let Some(field) = inputs.get("cose_sign1") else {
            continue; // no signed object (stale_epoch)
        };
        let object = cose::parse(&hex(case_id, field))
            .unwrap_or_else(|err| panic!("{case_id}: parse failed: {err}"));
        let signer = principal_by_id(&principals, case_id, object.kid());
        assert_eq!(
            cose::verify(&object, signer.descriptor()),
            Ok(()),
            "{case_id}: signature by its kid"
        );
    }
}

#[test]
fn invite_uri_references_are_canonical_base64url() {
    let suite = Suite::load();
    let case = suite.case("invite_uri");
    let expected = &case["expected"];
    let b64 = |name: &str| {
        expected[name]["b64url"]
            .as_str()
            .unwrap_or_else(|| panic!("invite_uri: no {name}"))
    };

    let resource = hex("fixtures", &suite.json["fixtures"]["resource"]["id"]);
    assert_eq!(
        base::to_b64url(&resource),
        b64("resource_b64url"),
        "invite_uri: resource"
    );

    // V1: the case names its grant's Control Record case.
    let grant_case = case["inputs"]["grant_case"]
        .as_str()
        .expect("invite_uri: inputs.grant_case");
    assert_eq!(grant_case, "C2_invite_grant", "invite_uri: grant case");
    let grant = hex(grant_case, &suite.case(grant_case)["expected"]["record_id"]);
    assert_eq!(
        base::to_b64url(&grant),
        b64("grant_id_b64url"),
        "invite_uri: grant"
    );

    let secret_cbor = hex("invite_uri", &expected["secret_cbor"]);
    assert_eq!(
        base::to_b64url(&secret_cbor),
        b64("secret_b64url"),
        "invite_uri: secret"
    );
    assert_eq!(
        base::from_b64url(b64("secret_b64url")).as_ref(),
        Ok(&secret_cbor),
        "invite_uri: secret decoding"
    );

    // §18.2: the receiving client recomputes the Invitation Principal from
    // the secret. It must be the INVITE fixture.
    let secret = cbor::decode_strict(&secret_cbor).expect("invite_uri: secret_cbor");
    assert_eq!(
        secret.get_uint(0),
        Some(&Value::Unsigned(1)),
        "invite_uri: secret version"
    );
    let key = |n: u64| -> [u8; 32] {
        base::fixed(secret.get_uint(n).and_then(Value::as_bytes).unwrap()).unwrap()
    };
    let invite = PrincipalKeys::from_secrets(&key(1), key(2));
    assert_eq!(
        invite.descriptor(),
        suite.principals()["INVITE"].descriptor(),
        "invite_uri: Invitation Principal"
    );

    let uri = expected["uri"].as_str().unwrap();
    for part in ["resource_b64url", "grant_id_b64url", "secret_b64url"] {
        assert!(uri.contains(b64(part)), "invite_uri: uri lacks {part}");
    }
}
