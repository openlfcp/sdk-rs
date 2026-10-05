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
/// Where the vector names the signer (`inputs.signer`) that name is used
/// and cross-checked with the payload. Otherwise the signer follows from
/// the WIRE section of the object type.
fn required_signer<'a>(
    suite: &Suite,
    principals: &'a BTreeMap<String, PrincipalKeys>,
    case_id: &str,
    object: &cose::SignedObject,
) -> &'a PrincipalKeys {
    let case = suite.case(case_id);
    let kind = case["kind"].as_str().unwrap();
    let payload = object.payload();
    let named = case["inputs"]["signer"].as_str().map(|name| {
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
        // §25 names field 4 the sender but does not say who signs; see the
        // spec-gap note in the LFCP-041 report.
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
        (Some(named), None) => named,
        (None, Some(from_payload)) => from_payload,
        (None, None) => {
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

        let signer = required_signer(&suite, &principals, case_id, &object);
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
    // 7 Control Records, offer + accept, 3 Key Packages, 4 Data Units,
    // 2 Snapshots and the AUTH proof.
    assert_eq!(cases.len(), 19, "signed objects in the bytes cases");
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
    for (case_id, expected) in [
        ("invalid_signature_D1", Error::SignatureInvalid),
        ("tampered_D1", Error::SignatureInvalid),
        ("wrong_kid_D1", Error::CoseKidMismatch),
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
    expect_rejected(case, err);
}

/// Negative vectors whose rule belongs to a later task: Control Plane
/// state, HPKE or the session. Their signed objects are canonical, so they
/// must pass parse and verify here.
const DEFERRED_NEGATIVES: &[(&str, &str)] = &[
    ("stale_epoch", "042b3: previous-epoch cutoff (§19.1)"),
    (
        "stale_epoch_absent_actor",
        "042b3: previous-epoch cutoff (§19.1)",
    ),
    (
        "hpke_recipient_mismatch_KP0",
        "042c: HPKE (§25.1, §25.2), client-local",
    ),
    (
        "stale_control_head_put",
        "043: CONTROL_PUT compare-and-swap (§47)",
    ),
];

/// Negative vectors this crate decides, in this file,
/// `data_plane_vectors.rs` or `control_plane_vectors.rs`.
const IN_SCOPE_NEGATIVES: &[&str] = &[
    // Primitives (this file).
    "tagged_cose_D1",
    "noncanonical_payload_D1",
    "invalid_signature_D1",
    "tampered_D1",
    "wrong_kid_D1",
    "descriptor_extra_field",
    // Data Plane (data_plane_vectors.rs).
    "noncanonical_aad_D1",
    "aead_failure_D1",
    "actor_seq_zero_D1",
    "actor_seq1_prev_not_null_D1",
    "actor_equivocation",
    "have_empty_extra_list",
    "have_range_reversed",
    "have_range_not_above_contiguous",
    "have_ranges_unsorted",
    "have_ranges_overlapping",
    "have_ranges_adjacent",
    "frontier_duplicate_principal",
    "frontier_unsorted",
    // Control Plane (control_plane_vectors.rs).
    "control_fork_C6",
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
            continue; // no signed object (stale_epoch, stale_control_head_put)
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

    let grant = hex(
        "C2_invite_grant",
        &suite.case("C2_invite_grant")["expected"]["record_id"],
    );
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
