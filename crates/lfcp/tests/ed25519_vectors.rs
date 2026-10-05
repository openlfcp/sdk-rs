//! The shared strict-Ed25519 cases of LFCP-TEST-VECTORS-01 (LFCP-WIRE-01
//! §10.5.1, §106; ADR 0003 ED25519): RFC 8032 TEST 1 and one case per rule
//! a strict verifier applies, including signatures a cofactored verifier
//! accepts.

mod support;

use lfcp::base::Error;
use lfcp::crypto::ed25519_verify_strict;
use support::vectors::{hex, id_of, Suite};

const CASES: [&str; 10] = [
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

struct Case {
    id: String,
    public_key: [u8; 32],
    message: Vec<u8>,
    signature: [u8; 64],
    valid: bool,
}

fn cases(suite: &Suite) -> Vec<Case> {
    suite
        .cases()
        .filter(|case| case["kind"] == "ed25519_signature")
        .map(|case| {
            let id = id_of(case);
            let inputs = &case["inputs"];
            let valid = case["expected"]["valid"].as_bool().unwrap();
            if !valid {
                assert_eq!(
                    case["expected"]["error"]["code"], "INVALID_SIGNATURE",
                    "{id}"
                );
            }
            Case {
                id: id.to_owned(),
                public_key: hex(id, &inputs["public_key"]).try_into().unwrap(),
                message: hex(id, &inputs["message"]),
                signature: hex(id, &inputs["signature"]).try_into().unwrap(),
                valid,
            }
        })
        .collect()
}

#[test]
fn the_ten_cases_are_published() {
    let suite = Suite::load();
    let ids: Vec<String> = cases(&suite).into_iter().map(|c| c.id).collect();
    assert_eq!(ids, CASES);
}

#[test]
fn strict_verification_decides_every_case_as_published() {
    let suite = Suite::load();
    for case in cases(&suite) {
        let result = ed25519_verify_strict(&case.public_key, &case.message, &case.signature);
        if case.valid {
            assert_eq!(result, Ok(()), "{}", case.id);
        } else {
            assert_eq!(result, Err(Error::SignatureInvalid), "{}", case.id);
            assert_eq!(
                Error::SignatureInvalid.wire_code().unwrap().name(),
                "INVALID_SIGNATURE"
            );
        }
    }
}

/// ed25519-dalek's own `verify_strict`, without this crate's extra check of
/// `A` (§10.5.1 rule 2), already decides every published case the same
/// way: the TS/Rust divergence check of ADR 0003 (ED25519) finds none on
/// the Rust side. (The extra check still matters for encodings these
/// cases do not cover; see `crypto::tests`.)
#[test]
fn dalek_verify_strict_alone_agrees_on_every_case() {
    let suite = Suite::load();
    let mut disagreements = Vec::new();
    for case in cases(&suite) {
        let dalek = ed25519_dalek::VerifyingKey::from_bytes(&case.public_key)
            .map(|key| {
                key.verify_strict(
                    &case.message,
                    &ed25519_dalek::Signature::from_bytes(&case.signature),
                )
                .is_ok()
            })
            .unwrap_or(false);
        if dalek != case.valid {
            disagreements.push(case.id);
        }
    }
    assert_eq!(
        disagreements,
        Vec::<String>::new(),
        "dalek verify_strict alone"
    );
}
