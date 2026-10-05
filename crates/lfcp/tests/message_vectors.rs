//! LFCP-TEST-VECTORS-01 wire messages: every `wire_message` case, the AUTH
//! handshake, and stale_control_head_put; plus synthetic envelope
//! negatives built from published messages (not spec vectors).
//!
//! Every assertion names its case.

mod support;

use lfcp::base::{ControlRecordId, Error};
use lfcp::cbor::{self, Value};
use lfcp::cose;
use lfcp::wire::control::chain::check_expected_head;
use lfcp::wire::message::{Body, DecodeOptions, Message, DEFAULT_MAX_MESSAGE_BYTES};
use lfcp::wire::session::{auth_transcript, verify_auth};
use support::vectors::{hex, hex32, id_of, Suite};

/// The §33 type code each wire_message case carries.
const MESSAGES: [(&str, u64); 28] = [
    ("HELLO", 0),
    ("CHALLENGE", 1),
    ("AUTH", 2),
    ("READY", 3),
    ("ERROR_AUTH_FAILED", 4),
    ("PING", 5),
    ("PONG", 6),
    ("RESOURCE_HOST", 10),
    ("RESOURCE_HOSTED", 11),
    ("RESOURCE_OPEN", 12),
    ("RESOURCE_OPENED", 13),
    ("RESOURCE_CLOSE", 14),
    ("CONTROL_HAVE", 20),
    ("CONTROL_GET", 21),
    ("CONTROL_BATCH", 22),
    ("CONTROL_PUT", 23),
    ("DATA_HAVE_with_hole", 30),
    ("DATA_GET", 31),
    ("DATA_BATCH", 32),
    ("DATA_PUT_D1_D2", 33),
    ("KEY_PACKAGE_GET", 40),
    ("KEY_PACKAGE_BATCH", 41),
    ("KEY_PACKAGE_PUT", 42),
    ("SNAPSHOT_GET", 50),
    ("SNAPSHOT", 51),
    ("SNAPSHOT_PUT", 52),
    ("NACK_STALE_DATA_EPOCH", 91),
    ("ACK_DATA_PUT_D1_D2", 90),
];

/// Responses and the request each one correlates to.
const CORRELATIONS: [(&str, &str); 11] = [
    ("CHALLENGE", "HELLO"),
    ("AUTH", "CHALLENGE"),
    ("READY", "AUTH"),
    ("RESOURCE_HOSTED", "RESOURCE_HOST"),
    ("RESOURCE_OPENED", "RESOURCE_OPEN"),
    ("CONTROL_BATCH", "CONTROL_GET"),
    ("DATA_BATCH", "DATA_GET"),
    ("KEY_PACKAGE_BATCH", "KEY_PACKAGE_GET"),
    ("SNAPSHOT", "SNAPSHOT_GET"),
    ("PONG", "PING"),
    ("ACK_DATA_PUT_D1_D2", "DATA_PUT_D1_D2"),
];

fn bytes_of(suite: &Suite, case_id: &str) -> Vec<u8> {
    hex(case_id, &suite.case(case_id)["expected"]["message_cbor"])
}

fn message(suite: &Suite, case_id: &str) -> Message {
    Message::decode(&bytes_of(suite, case_id), &DecodeOptions::default())
        .unwrap_or_else(|err| panic!("{case_id}: decode failed: {err}"))
}

#[test]
fn every_wire_message_round_trips_typed() {
    let suite = Suite::load();
    let listed: Vec<&str> = MESSAGES.iter().map(|(id, _)| *id).collect();
    for case in suite.cases().filter(|c| c["kind"] == "wire_message") {
        assert!(
            listed.contains(&id_of(case)),
            "{}: not in MESSAGES",
            id_of(case)
        );
    }
    for (case_id, message_type) in MESSAGES {
        let bytes = bytes_of(&suite, case_id);
        let message = message(&suite, case_id);
        assert_eq!(message.body.message_type(), message_type, "{case_id}: type");
        assert!(
            !matches!(message.body, Body::Extension { .. }),
            "{case_id}: typed"
        );
        assert!(
            message.ignored_envelope_keys.is_empty(),
            "{case_id}: envelope"
        );
        assert_eq!(message.encode(), bytes, "{case_id}: re-encode");

        // Signed objects inside the body parse from their exact bytes.
        let parsed = [
            message
                .body
                .control_records()
                .map(|r| r.iter().all(Result::is_ok)),
            message.body.units().map(|u| u.iter().all(Result::is_ok)),
            message.body.packages().map(|p| p.iter().all(Result::is_ok)),
            message.body.snapshot().map(|s| s.is_ok()),
        ];
        for ok in parsed.into_iter().flatten() {
            assert!(ok, "{case_id}: embedded signed object");
        }
    }
}

#[test]
fn responses_correlate_to_their_requests() {
    let suite = Suite::load();
    for (response, request) in CORRELATIONS {
        assert_eq!(
            message(&suite, response).correlation_id,
            Some(message(&suite, request).message_id),
            "{response}: correlation id"
        );
    }
    // A1: the ACK names the §33 type of DATA_PUT and the accepted units.
    let Body::Ack(ack) = message(&suite, "ACK_DATA_PUT_D1_D2").body else {
        panic!("ACK_DATA_PUT_D1_D2: not an ACK")
    };
    assert_eq!(ack.request_type, 33, "ACK_DATA_PUT_D1_D2: request type");
    let unit_id = |case: &str| hex(case, &suite.case(case)["expected"]["unit_id"]);
    let ids: Vec<Vec<u8>> = ack
        .object_ids
        .unwrap()
        .iter()
        .map(|id| id.as_bytes().to_vec())
        .collect();
    assert_eq!(
        ids,
        vec![unit_id("D1_bob_epoch0_seq1"), unit_id("D2_bob_epoch0_seq2")],
        "ACK_DATA_PUT_D1_D2: object ids"
    );
}

#[test]
fn auth_handshake_reproduces_and_verifies() {
    let suite = Suite::load();
    let case_id = "AUTH";
    let expected = &suite.case(case_id)["expected"];
    let Body::Hello(hello) = message(&suite, "HELLO").body else {
        panic!("HELLO: not a HELLO")
    };
    let Body::Challenge(challenge) = message(&suite, "CHALLENGE").body else {
        panic!("CHALLENGE: not a CHALLENGE")
    };
    let Body::Auth(auth) = message(&suite, case_id).body else {
        panic!("AUTH: not an AUTH")
    };

    // The fixture session values are the ones the handshake carries.
    let session = &suite.json["fixtures"]["session"];
    assert_eq!(
        hello.client_nonce.as_slice(),
        hex("fixtures", &session["client_nonce"])
    );
    assert_eq!(
        challenge.server_nonce.as_slice(),
        hex("fixtures", &session["server_nonce"])
    );
    assert_eq!(
        challenge.session_id.as_slice(),
        hex("fixtures", &session["session_id"])
    );
    assert_eq!(
        challenge.server_id,
        hex32("fixtures", &session["server_id"])
    );

    let transcript = auth_transcript(&hello, &challenge);
    assert_eq!(
        transcript,
        hex(case_id, &expected["auth_transcript_cbor"]),
        "{case_id}: transcript"
    );
    let proof_bytes = hex(case_id, &expected["auth_proof_cose_sign1"]);
    assert_eq!(auth.proof, proof_bytes, "{case_id}: proof in the AUTH body");

    // The session Principal of HELLO is BOB; re-signing is byte-exact.
    let principals = suite.principals();
    let bob = &principals["BOB"];
    assert_eq!(
        &hello.principal,
        bob.descriptor(),
        "{case_id}: HELLO principal"
    );
    let resigned = cose::sign(&transcript, bob).unwrap();
    assert_eq!(resigned.bytes(), proof_bytes, "{case_id}: proof re-signed");

    let authenticated = verify_auth(&hello, &challenge, auth)
        .unwrap_or_else(|err| panic!("{case_id}: verify_auth failed: {err}"));
    assert_eq!(
        &authenticated.principal,
        bob.descriptor(),
        "{case_id}: authenticated"
    );
    assert!(
        authenticated.hosting_credential.is_none(),
        "{case_id}: no credential"
    );
}

#[test]
fn stale_control_head_put_is_a_head_mismatch() {
    let suite = Suite::load();
    let case_id = "stale_control_head_put";
    let case = suite.case(case_id);
    let current = ControlRecordId::from_bytes(hex32(
        "C5_route_update",
        &suite.case("C5_route_update")["expected"]["record_id"],
    ));

    let put = |bytes: &[u8], label: &str| match Message::decode(bytes, &DecodeOptions::default())
        .unwrap_or_else(|err| panic!("{label}: decode failed: {err}"))
        .body
    {
        Body::ControlPut { expected_head, .. } => expected_head,
        _ => panic!("{label}: not a CONTROL_PUT"),
    };

    // The published CONTROL_PUT expects C5 and passes the check.
    let fresh = put(&bytes_of(&suite, "CONTROL_PUT"), "CONTROL_PUT");
    assert_eq!(
        check_expected_head(fresh, Some(current)),
        Ok(()),
        "CONTROL_PUT"
    );

    let stale = put(&hex(case_id, &case["inputs"]["message_cbor"]), case_id);
    let err = check_expected_head(stale, Some(current)).expect_err("stale head accepted");
    assert_eq!(
        err,
        Error::ControlHeadMismatch {
            current: Some(current)
        },
        "{case_id}"
    );
    assert_eq!(
        err.wire_code().map(|c| c.name()),
        case["expected"]["error"]["code"].as_str(),
        "{case_id}: code"
    );
    assert_eq!(case["expected"]["disposition"], "reject", "{case_id}");
}

/// Synthetic negatives: published messages with the envelope or body
/// changed. Not spec vectors.
mod synthetic {
    use super::*;

    /// The envelope of a published message as entries, to change.
    fn entries(suite: &Suite, case_id: &str) -> Vec<(Value, Value)> {
        cbor::decode_strict(&bytes_of(suite, case_id))
            .unwrap()
            .as_map()
            .unwrap()
            .to_vec()
    }

    fn encode(entries: Vec<(Value, Value)>) -> Vec<u8> {
        cbor::encode(&Value::Map(entries)).unwrap()
    }

    fn set(entries: &mut Vec<(Value, Value)>, key: u64, value: Value) {
        entries.retain(|(k, _)| k != &Value::Unsigned(key));
        entries.push((Value::Unsigned(key), value));
    }

    fn decode(bytes: &[u8]) -> Result<Message, Error> {
        Message::decode(bytes, &DecodeOptions::default())
    }

    #[test]
    fn envelope_key_7_is_rejected() {
        let suite = Suite::load();
        let mut ping = entries(&suite, "PING");
        set(&mut ping, 7, Value::Unsigned(0));
        let err = decode(&encode(ping)).unwrap_err();
        assert_eq!(err, Error::MessageReservedEnvelopeKey(7));
        assert_eq!(err.wire_code().unwrap().name(), "MALFORMED_MESSAGE");
    }

    #[test]
    fn envelope_key_20_is_ignored() {
        let suite = Suite::load();
        let mut ping = entries(&suite, "PING");
        set(&mut ping, 20, Value::text("from the future"));
        let message = decode(&encode(ping)).unwrap();
        assert_eq!(message.ignored_envelope_keys, vec![20]);
        assert_eq!(
            message.encode(),
            bytes_of(&suite, "PING"),
            "dropped on re-encode"
        );
    }

    #[test]
    fn oversize_message_is_rejected_before_decoding() {
        let suite = Suite::load();
        let mut ping = entries(&suite, "PING");
        set(
            &mut ping,
            20,
            Value::bytes(vec![0; DEFAULT_MAX_MESSAGE_BYTES]),
        );
        let bytes = encode(ping);
        let err = decode(&bytes).unwrap_err();
        assert_eq!(
            err,
            Error::MessageTooLarge {
                size: bytes.len(),
                limit: DEFAULT_MAX_MESSAGE_BYTES
            }
        );
        assert_eq!(err.wire_code().unwrap().name(), "MESSAGE_TOO_LARGE");
    }

    #[test]
    fn unknown_message_type_is_unsupported() {
        let suite = Suite::load();
        let mut hello = entries(&suite, "HELLO");
        set(&mut hello, 0, Value::Unsigned(7));
        let err = decode(&encode(hello)).unwrap_err();
        assert_eq!(err, Error::UnsupportedMessageType(7));
        assert_eq!(err.wire_code().unwrap().name(), "PROTOCOL_UNSUPPORTED");
    }

    #[test]
    fn body_must_match_the_message_type() {
        let suite = Suite::load();
        // A HELLO body under the CHALLENGE type.
        let mut hello = entries(&suite, "HELLO");
        set(&mut hello, 0, Value::Unsigned(1));
        assert_eq!(
            decode(&encode(hello)),
            Err(Error::MessageMalformed),
            "HELLO body as CHALLENGE"
        );

        // wire/fixtures/invalid-hello-with-challenge-body.diag: a CHALLENGE
        // body under the HELLO type.
        let mut challenge = entries(&suite, "CHALLENGE");
        set(&mut challenge, 0, Value::Unsigned(0));
        let err = decode(&encode(challenge)).unwrap_err();
        assert_eq!(err, Error::MessageMalformed, "CHALLENGE body as HELLO");
        assert_eq!(err.wire_code().unwrap().name(), "MALFORMED_MESSAGE");
    }

    #[test]
    fn hello_with_a_wrong_principal_id_fails_authentication() {
        let suite = Suite::load();
        let mut hello = entries(&suite, "HELLO");
        let body = &mut hello
            .iter_mut()
            .find(|(k, _)| k == &Value::Unsigned(4))
            .unwrap()
            .1;
        let Value::Map(fields) = body else {
            unreachable!()
        };
        let descriptor = &mut fields
            .iter_mut()
            .find(|(k, _)| k == &Value::Unsigned(1))
            .unwrap()
            .1;
        let Value::Map(keys) = descriptor else {
            unreachable!()
        };
        keys[0].1 = Value::bytes(vec![0; 32]);
        let err = decode(&encode(hello)).unwrap_err();
        assert_eq!(err, Error::PrincipalIdMismatch);
        assert_eq!(err.session_wire_code().unwrap().name(), "AUTH_FAILED", "P2");
    }
}
