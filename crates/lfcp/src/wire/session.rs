//! The session handshake: HELLO, CHALLENGE, AUTH, READY (LFCP-WIRE-01
//! §34–§37), as pure functions without I/O or session state.
//!
//! | Step | Bytes | § |
//! | --- | --- | --- |
//! | client → HELLO | wire profiles, session Principal descriptor, client nonce, ?Data Profiles | §34 |
//! | server checks HELLO | descriptor ID recomputed on decode (mismatch → `AUTH_FAILED`, P2); a common wire profile ([`select_wire_profile`], else `PROTOCOL_UNSUPPORTED`) | §34, §7 |
//! | server → CHALLENGE | selected profile, server nonce, session ID, server ID | §35 |
//! | client checks CHALLENGE | the selected profile is one the client offered ([`check_challenge`]) | §35 |
//! | transcript | det-CBOR `["LFCP-AUTH-v1", session id, client nonce, server nonce, server id, principal id]` | §36 |
//! | client → AUTH | COSE_Sign1 over the transcript by the session Principal, ?hosting credential | §36, §10 |
//! | server verifies AUTH | canonical proof, `kid` = HELLO Principal, payload = this session's transcript byte for byte, signature; any failure → `AUTH_FAILED` | §36 |
//! | server → READY | profile, server ID, max message bytes, durability, heartbeat | §37 |
//!
//! The hosting credential is returned to the caller unchanged; it is
//! server policy and never LFCP Resource authorization (§36). Random
//! nonces and session IDs are the caller's to generate (§5.4).

use crate::base::{AuthFailure, Error};
use crate::cbor::{self, Value};
use crate::cose::{self, SignedObject};
use crate::principal::{PrincipalDescriptor, PrincipalKeys};
use crate::wire::message::{
    AuthBody, ChallengeBody, DecodeOptions, HelloBody, HostingCredential, ReadyBody,
};

/// The wire profile this crate implements.
pub const WIRE_PROFILE: &str = "LFCP-WIRE-01";

const TRANSCRIPT_LABEL: &str = "LFCP-AUTH-v1";

/// The first wire profile in the client's `HELLO` order that the server
/// supports. None in common is `PROTOCOL_UNSUPPORTED`.
pub fn select_wire_profile(hello: &HelloBody, supported: &[&str]) -> Result<String, Error> {
    hello
        .wire_profiles
        .iter()
        .find(|profile| supported.contains(&profile.as_str()))
        .cloned()
        .ok_or(Error::NoCommonWireProfile)
}

/// Check, as the client, that the server selected a profile it offered.
pub fn check_challenge(hello: &HelloBody, challenge: &ChallengeBody) -> Result<(), Error> {
    if hello.wire_profiles.contains(&challenge.wire_profile) {
        Ok(())
    } else {
        Err(Error::NoCommonWireProfile)
    }
}

/// The deterministic AUTH transcript of this session (§36).
pub fn auth_transcript(hello: &HelloBody, challenge: &ChallengeBody) -> Vec<u8> {
    let transcript = Value::Array(vec![
        Value::text(TRANSCRIPT_LABEL),
        Value::bytes(challenge.session_id.to_vec()),
        Value::bytes(hello.client_nonce.to_vec()),
        Value::bytes(challenge.server_nonce.to_vec()),
        Value::bytes(challenge.server_id.to_vec()),
        Value::bytes(hello.principal.id().as_bytes().to_vec()),
    ]);
    cbor::encode(&transcript).expect("the transcript array is always encodable")
}

/// Build the client's `AUTH` body: the transcript signed by the session
/// Principal, which must be the Principal of `hello`.
pub fn auth(
    keys: &PrincipalKeys,
    hello: &HelloBody,
    challenge: &ChallengeBody,
    hosting_credential: Option<HostingCredential>,
) -> Result<AuthBody, Error> {
    if keys.descriptor() != &hello.principal {
        return Err(Error::AuthFailed(AuthFailure::WrongSigner));
    }
    let proof = cose::sign(&auth_transcript(hello, challenge), keys)?;
    Ok(AuthBody {
        proof: proof.bytes().to_vec(),
        hosting_credential,
    })
}

/// A session whose Principal proved possession of its signing key.
#[derive(Debug)]
pub struct AuthenticatedSession {
    /// The session Principal.
    pub principal: PrincipalDescriptor,
    /// The session ID from `CHALLENGE`.
    pub session_id: [u8; 16],
    /// The verified auth proof, with its exact bytes.
    pub proof: SignedObject,
    /// The hosting credential, for server policy only; it grants no
    /// Resource authority.
    pub hosting_credential: Option<HostingCredential>,
}

/// Verify, as the server, the client's `AUTH` against the `HELLO` it
/// received and the `CHALLENGE` it sent. Every failure is `AUTH_FAILED`.
pub fn verify_auth(
    hello: &HelloBody,
    challenge: &ChallengeBody,
    auth: AuthBody,
) -> Result<AuthenticatedSession, Error> {
    let fail = |reason| Error::AuthFailed(reason);
    let proof = cose::parse(&auth.proof).map_err(|_| fail(AuthFailure::ProofMalformed))?;
    if proof.kid() != hello.principal.id() {
        return Err(fail(AuthFailure::WrongSigner));
    }
    if proof.payload_bytes() != auth_transcript(hello, challenge) {
        return Err(fail(AuthFailure::TranscriptMismatch));
    }
    cose::verify(&proof, &hello.principal).map_err(|_| fail(AuthFailure::BadSignature))?;
    Ok(AuthenticatedSession {
        principal: hello.principal.clone(),
        session_id: challenge.session_id,
        proof,
        hosting_credential: auth.hosting_credential,
    })
}

/// The decode options a client uses after `READY`: the server's advertised
/// maximum message size (§31, §37).
pub fn options_after_ready(ready: &ReadyBody) -> DecodeOptions {
    DecodeOptions {
        max_message_bytes: usize::try_from(ready.max_message_bytes).unwrap_or(usize::MAX),
        ..DecodeOptions::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(n: u8) -> PrincipalKeys {
        PrincipalKeys::from_secrets(&[n; 32], [n + 1; 32])
    }

    fn hello(keys: &PrincipalKeys) -> HelloBody {
        HelloBody {
            wire_profiles: vec![WIRE_PROFILE.into()],
            principal: keys.descriptor().clone(),
            client_nonce: [1; 16],
            data_profiles: None,
        }
    }

    fn challenge() -> ChallengeBody {
        ChallengeBody {
            wire_profile: WIRE_PROFILE.into(),
            server_nonce: [2; 16],
            session_id: [3; 16],
            server_id: [4; 32],
        }
    }

    #[test]
    fn handshake_authenticates() {
        let client = keys(1);
        let hello = hello(&client);
        assert_eq!(
            select_wire_profile(&hello, &[WIRE_PROFILE]).unwrap(),
            WIRE_PROFILE
        );
        let challenge = challenge();
        assert_eq!(check_challenge(&hello, &challenge), Ok(()));
        let credential = HostingCredential::new(b"token".to_vec());
        let auth = auth(&client, &hello, &challenge, Some(credential.clone())).unwrap();
        let session = verify_auth(&hello, &challenge, auth).unwrap();
        assert_eq!(&session.principal, client.descriptor());
        assert_eq!(session.hosting_credential, Some(credential));
    }

    #[test]
    fn auth_failures() {
        let client = keys(1);
        let hello = hello(&client);
        let challenge = challenge();
        let good = auth(&client, &hello, &challenge, None).unwrap();
        let failure = |auth: AuthBody, challenge: &ChallengeBody| {
            let err = verify_auth(&hello, challenge, auth).unwrap_err();
            assert_eq!(err.wire_code().unwrap().name(), "AUTH_FAILED");
            err
        };

        // Replayed into another session: the transcript differs.
        let other_session = ChallengeBody {
            session_id: [9; 16],
            ..challenge.clone()
        };
        assert_eq!(
            failure(good.clone(), &other_session),
            Error::AuthFailed(AuthFailure::TranscriptMismatch)
        );

        // Signed by someone else over this session's transcript.
        let stranger = keys(5);
        let proof = cose::sign(&auth_transcript(&hello, &challenge), &stranger).unwrap();
        let forged = AuthBody {
            proof: proof.bytes().to_vec(),
            hosting_credential: None,
        };
        assert_eq!(
            failure(forged, &challenge),
            Error::AuthFailed(AuthFailure::WrongSigner)
        );

        let mut tampered = good.clone();
        let last = tampered.proof.len() - 1;
        tampered.proof[last] ^= 1;
        assert_eq!(
            failure(tampered, &challenge),
            Error::AuthFailed(AuthFailure::BadSignature)
        );

        let garbage = AuthBody {
            proof: vec![0xff],
            hosting_credential: None,
        };
        assert_eq!(
            failure(garbage, &challenge),
            Error::AuthFailed(AuthFailure::ProofMalformed)
        );

        assert_eq!(
            auth(&stranger, &hello, &challenge, None),
            Err(Error::AuthFailed(AuthFailure::WrongSigner))
        );
    }

    #[test]
    fn profile_negotiation() {
        let hello = hello(&keys(1));
        let err = select_wire_profile(&hello, &["LFCP-WIRE-02"]).unwrap_err();
        assert_eq!(err.wire_code().unwrap().name(), "PROTOCOL_UNSUPPORTED");
        let other = ChallengeBody {
            wire_profile: "LFCP-WIRE-02".into(),
            ..challenge()
        };
        assert_eq!(
            check_challenge(&hello, &other),
            Err(Error::NoCommonWireProfile)
        );
    }

    #[test]
    fn descriptor_errors_fail_authentication_in_session_context() {
        assert_eq!(
            Error::PrincipalIdMismatch
                .session_wire_code()
                .unwrap()
                .name(),
            "AUTH_FAILED"
        );
        assert_eq!(
            Error::PrincipalMalformed
                .session_wire_code()
                .unwrap()
                .name(),
            "AUTH_FAILED"
        );
    }
}
