//! Thin wrappers over established cryptographic crates.
//!
//! This module exposes the primitives of the LFCP crypto profile v1
//! (LFCP-WIRE-01 §9) that the crate uses so far: SHA-256, Ed25519 and the
//! X25519 public-key derivation. It never implements a primitive itself.
//!
//! Private keys are wrapped in types whose `Debug` output is redacted and
//! which wipe their memory on drop, so they cannot leak through logs or
//! diagnostics.
//!
//! Ed25519 verification is strict ([`ed25519_verify_strict`]). LFCP-WIRE-01
//! §10.5 asks for an Ed25519 signature per RFC 8032 and states nothing
//! stricter; RFC 8032 §5.1.7 already requires rejecting a non-canonical
//! `S`. Strict verification additionally rejects small-order public keys and
//! `R` values, so a signature cannot be valid for every message, and one
//! signature has one accepted form.

use std::fmt;

use ed25519_dalek::Signer as _;
use sha2::{Digest, Sha256};

use crate::base::{Error, Hash32};

/// SHA-256 of `data`: `hash32(x)` in LFCP-WIRE-01 §5.3.
pub fn sha256(data: &[u8]) -> Hash32 {
    sha256_parts(&[data])
}

/// SHA-256 of the concatenation of `parts`, without building it.
pub fn sha256_parts(parts: &[&[u8]]) -> Hash32 {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    Hash32::from_bytes(hasher.finalize().into())
}

/// An Ed25519 signing key, made from its 32-byte RFC 8032 seed.
pub struct Ed25519SigningKey(ed25519_dalek::SigningKey);

impl Ed25519SigningKey {
    /// The key for a 32-byte seed (RFC 8032 §5.1.5).
    pub fn from_seed(seed: &[u8; 32]) -> Ed25519SigningKey {
        Ed25519SigningKey(ed25519_dalek::SigningKey::from_bytes(seed))
    }

    /// The 32-byte public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    /// The 64-byte signature of `message`. Ed25519 is deterministic: the
    /// same key and message always give the same signature.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.0.sign(message).to_bytes()
    }
}

impl fmt::Debug for Ed25519SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Ed25519SigningKey(<redacted>)")
    }
}

/// Verify an Ed25519 signature with strict rules (see the module docs).
///
/// Every failure, including a public key that is not a valid curve point,
/// is [`Error::SignatureInvalid`].
pub fn ed25519_verify_strict(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), Error> {
    let key =
        ed25519_dalek::VerifyingKey::from_bytes(public_key).map_err(|_| Error::SignatureInvalid)?;
    let signature = ed25519_dalek::Signature::from_bytes(signature);
    key.verify_strict(message, &signature)
        .map_err(|_| Error::SignatureInvalid)
}

/// Lenient RFC 8032 verification, for tests that show why strict
/// verification is used. Not used by the protocol code.
#[cfg(test)]
fn ed25519_verify_lenient(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    ed25519_dalek::VerifyingKey::from_bytes(public_key)
        .map(|key| {
            use ed25519_dalek::Verifier as _;
            key.verify(message, &ed25519_dalek::Signature::from_bytes(signature))
                .is_ok()
        })
        .unwrap_or(false)
}

/// An X25519 private key (RFC 7748).
pub struct X25519PrivateKey(x25519_dalek::StaticSecret);

impl X25519PrivateKey {
    /// The key for 32 private-key bytes. Clamping happens inside the
    /// X25519 function, as RFC 7748 §5 specifies.
    pub fn from_bytes(bytes: [u8; 32]) -> X25519PrivateKey {
        X25519PrivateKey(x25519_dalek::StaticSecret::from(bytes))
    }

    /// The 32-byte public key: X25519 of the private key and the base point.
    pub fn public_key(&self) -> [u8; 32] {
        x25519_dalek::PublicKey::from(&self.0).to_bytes()
    }
}

impl fmt::Debug for X25519PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("X25519PrivateKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::{fixed, from_hex};

    fn hex<const N: usize>(text: &str) -> [u8; N] {
        fixed(&from_hex(text).unwrap()).unwrap()
    }

    #[test]
    fn sha256_matches_fips_180_example() {
        assert_eq!(
            sha256(b"abc").to_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(sha256_parts(&[b"a", b"", b"bc"]), sha256(b"abc"));
    }

    #[test]
    fn ed25519_matches_rfc8032_test_1() {
        let key = Ed25519SigningKey::from_seed(&hex(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        ));
        let public: [u8; 32] =
            hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let signature: [u8; 64] = hex(concat!(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555",
            "fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        ));
        assert_eq!(key.public_key(), public);
        assert_eq!(key.sign(b""), signature);
        assert_eq!(ed25519_verify_strict(&public, b"", &signature), Ok(()));
        assert_eq!(
            ed25519_verify_strict(&public, b"x", &signature),
            Err(Error::SignatureInvalid)
        );
    }

    #[test]
    fn strict_verification_rejects_a_small_order_key() {
        // The identity point as public key and R, with S = 0, satisfies the
        // lenient equation for every message.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(&identity);
        assert!(ed25519_verify_lenient(
            &identity,
            b"any message",
            &signature
        ));
        assert_eq!(
            ed25519_verify_strict(&identity, b"any message", &signature),
            Err(Error::SignatureInvalid)
        );
    }

    #[test]
    fn x25519_matches_rfc7748_section_6_1() {
        let alice = X25519PrivateKey::from_bytes(hex(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        ));
        assert_eq!(
            alice.public_key(),
            hex::<32>("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );
    }

    #[test]
    fn private_keys_do_not_print() {
        let key = Ed25519SigningKey::from_seed(&[7; 32]);
        assert_eq!(format!("{key:?}"), "Ed25519SigningKey(<redacted>)");
        let key = X25519PrivateKey::from_bytes([7; 32]);
        assert_eq!(format!("{key:?}"), "X25519PrivateKey(<redacted>)");
    }
}
