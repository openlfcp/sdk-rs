//! Principals: the LFCP cryptographic identity (LFCP-WIRE-01 §7).
//!
//! A Principal is one Ed25519 signing key, one X25519 key-agreement key and
//! the Principal ID derived from them:
//!
//! ```text
//! principal_id = SHA-256("LFCP-PRINCIPAL-v1" || ed25519_public || x25519_public)
//! ```
//!
//! Its public form is the Principal Descriptor, the closed CBOR map
//! `{0: principal_id, 1: ed25519_public, 2: x25519_public}`. A received
//! descriptor always has its ID recomputed and compared.

use crate::base::{Error, PrincipalId};
use crate::cbor::{self, Value};
use crate::crypto::{self, Ed25519SigningKey, X25519PrivateKey};

const ID_DOMAIN: &[u8] = b"LFCP-PRINCIPAL-v1";

/// Derive a Principal ID from the two public keys (§7).
pub fn principal_id(ed25519_public: &[u8; 32], x25519_public: &[u8; 32]) -> PrincipalId {
    let hash = crypto::sha256_parts(&[ID_DOMAIN, ed25519_public, x25519_public]);
    PrincipalId::from_bytes(*hash.as_bytes())
}

/// A Principal Descriptor whose ID has been checked against its keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrincipalDescriptor {
    id: PrincipalId,
    ed25519_public: [u8; 32],
    x25519_public: [u8; 32],
}

impl PrincipalDescriptor {
    /// The descriptor for two public keys, with the derived ID.
    pub fn from_public_keys(
        ed25519_public: [u8; 32],
        x25519_public: [u8; 32],
    ) -> PrincipalDescriptor {
        PrincipalDescriptor {
            id: principal_id(&ed25519_public, &x25519_public),
            ed25519_public,
            x25519_public,
        }
    }

    /// Validate a received descriptor value: exactly the keys `0`, `1` and
    /// `2`, each a 32-byte byte string, and an ID equal to the one
    /// recomputed from the keys.
    pub fn from_value(value: &Value) -> Result<PrincipalDescriptor, Error> {
        let entries = value.as_map().ok_or(Error::PrincipalMalformed)?;
        if entries.len() != 3 {
            return Err(Error::PrincipalMalformed);
        }
        let field = |key: u64| -> Result<[u8; 32], Error> {
            value
                .get_uint(key)
                .and_then(Value::as_bytes)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or(Error::PrincipalMalformed)
        };
        // Three entries with keys 0, 1 and 2 present means no other key.
        let claimed = PrincipalId::from_bytes(field(0)?);
        let descriptor = PrincipalDescriptor::from_public_keys(field(1)?, field(2)?);
        if descriptor.id != claimed {
            return Err(Error::PrincipalIdMismatch);
        }
        Ok(descriptor)
    }

    /// Decode and validate a descriptor from its deterministic CBOR bytes.
    pub fn decode(bytes: &[u8]) -> Result<PrincipalDescriptor, Error> {
        PrincipalDescriptor::from_value(&cbor::decode_strict(bytes)?)
    }

    /// The descriptor as a CBOR value.
    pub fn to_value(&self) -> Value {
        Value::Map(vec![
            (
                Value::Unsigned(0),
                Value::bytes(self.id.as_bytes().to_vec()),
            ),
            (
                Value::Unsigned(1),
                Value::bytes(self.ed25519_public.to_vec()),
            ),
            (
                Value::Unsigned(2),
                Value::bytes(self.x25519_public.to_vec()),
            ),
        ])
    }

    /// The deterministic CBOR encoding of the descriptor.
    pub fn encode(&self) -> Vec<u8> {
        cbor::encode(&self.to_value()).expect("a descriptor map is always encodable")
    }

    /// The Principal ID.
    pub fn id(&self) -> &PrincipalId {
        &self.id
    }

    /// The Ed25519 signing public key.
    pub fn ed25519_public(&self) -> &[u8; 32] {
        &self.ed25519_public
    }

    /// The X25519 key-agreement public key.
    pub fn x25519_public(&self) -> &[u8; 32] {
        &self.x25519_public
    }
}

/// A Principal's private keys together with its descriptor.
#[derive(Debug)]
pub struct PrincipalKeys {
    signing: Ed25519SigningKey,
    agreement: X25519PrivateKey,
    descriptor: PrincipalDescriptor,
}

impl PrincipalKeys {
    /// The Principal for an Ed25519 seed and an X25519 private key.
    pub fn from_secrets(ed25519_seed: &[u8; 32], x25519_private: [u8; 32]) -> PrincipalKeys {
        let signing = Ed25519SigningKey::from_seed(ed25519_seed);
        let agreement = X25519PrivateKey::from_bytes(x25519_private);
        let descriptor =
            PrincipalDescriptor::from_public_keys(signing.public_key(), agreement.public_key());
        PrincipalKeys {
            signing,
            agreement,
            descriptor,
        }
    }

    /// The public descriptor.
    pub fn descriptor(&self) -> &PrincipalDescriptor {
        &self.descriptor
    }

    /// The Ed25519 signing key.
    pub fn signing_key(&self) -> &Ed25519SigningKey {
        &self.signing
    }

    /// The X25519 private key.
    pub fn agreement_key(&self) -> &X25519PrivateKey {
        &self.agreement
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PrincipalDescriptor {
        PrincipalKeys::from_secrets(&[1; 32], [2; 32])
            .descriptor()
            .clone()
    }

    fn with_entries(entries: Vec<(Value, Value)>) -> Result<PrincipalDescriptor, Error> {
        PrincipalDescriptor::decode(&cbor::encode(&Value::Map(entries)).unwrap())
    }

    #[test]
    fn descriptor_round_trips() {
        let descriptor = sample();
        assert_eq!(
            PrincipalDescriptor::decode(&descriptor.encode()),
            Ok(descriptor)
        );
    }

    #[test]
    fn descriptor_rejects_other_shapes() {
        let Value::Map(entries) = sample().to_value() else {
            unreachable!()
        };
        let mut extra = entries.clone();
        extra.push((Value::Unsigned(3), Value::bytes(vec![])));
        assert_eq!(with_entries(extra), Err(Error::PrincipalMalformed));

        let mut text_key = entries.clone();
        text_key.push((Value::text("x"), Value::Null));
        assert_eq!(with_entries(text_key), Err(Error::PrincipalMalformed));

        assert_eq!(
            with_entries(entries[..2].to_vec()),
            Err(Error::PrincipalMalformed)
        );

        let mut short_key = entries.clone();
        short_key[1].1 = Value::bytes(vec![0; 31]);
        assert_eq!(with_entries(short_key), Err(Error::PrincipalMalformed));

        let mut renamed = entries.clone();
        renamed[2].0 = Value::Unsigned(5);
        assert_eq!(with_entries(renamed), Err(Error::PrincipalMalformed));

        assert_eq!(
            PrincipalDescriptor::from_value(&Value::Array(vec![])),
            Err(Error::PrincipalMalformed)
        );
    }

    #[test]
    fn descriptor_recomputes_the_id() {
        let Value::Map(mut entries) = sample().to_value() else {
            unreachable!()
        };
        entries[0].1 = Value::bytes(vec![0; 32]);
        let err = with_entries(entries).unwrap_err();
        assert_eq!(err, Error::PrincipalIdMismatch);
        assert_eq!(err.wire_code().unwrap().name(), "MALFORMED_MESSAGE");
        assert_eq!(err.session_wire_code().unwrap().name(), "AUTH_FAILED");
    }
}
