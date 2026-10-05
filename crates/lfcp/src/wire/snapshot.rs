//! Snapshots: encrypted, signed materializations of profile state at a
//! Data frontier (LFCP-WIRE-01 §29).
//!
//! ```text
//! payload = {0: resource-id, 1: data epoch, 2: publisher, 3: snapshot sequence,
//!            4: Control Head, 5: canonical-frontier, 6: ciphertext}
//! aad     = ["LFCP-SNAPSHOT-v1", payload fields 0 to 5 in order]
//! ```
//!
//! The ciphertext is ChaCha20-Poly1305 under the publisher's Snapshot key
//! (§29.1.1) with the sequence nonce (§29.1.2) and the exact AAD
//! (§29.1.3). The publisher signs, and the Snapshot ID is the object ID.
//!
//! As for Data Units, [`ReceivedSnapshot::parse`] checks structure and the
//! canonical frontier, and [`ReceivedSnapshot::verify`] checks the
//! publisher's signature. `snapshot/publish` authority (§29.2) needs
//! Control Plane state and is not checked here.

use crate::base::{Error, Hash32, PrincipalId, ResourceId};
use crate::cbor::{self, Value};
use crate::cose::{self, SignedObject};
use crate::crypto;
use crate::principal::{PrincipalDescriptor, PrincipalKeys};
use crate::wire::frontier::Frontier;
use crate::wire::keys::{sequence_nonce, Dek, SnapshotKey};
use crate::wire::{
    bytes_field, check_closed_map, hash_field, principal_field, resource_field, uint_field,
};

const AAD_LABEL: &str = "LFCP-SNAPSHOT-v1";

/// The authenticated fields of a Snapshot: payload fields 0 to 5.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotHeader {
    /// Field 0: the Resource.
    pub resource_id: ResourceId,
    /// Field 1: the Data Epoch whose DEK the Snapshot key derives from.
    pub data_epoch: u64,
    /// Field 2: the publisher, which must sign the Snapshot.
    pub publisher: PrincipalId,
    /// Field 3: the publisher's Snapshot sequence, which is also the nonce.
    pub sequence: u64,
    /// Field 4: the Control Head.
    pub control_head: Hash32,
    /// Field 5: the included frontier, canonical.
    pub frontier: Frontier,
}

impl SnapshotHeader {
    /// Payload fields 0 to 5 as CBOR values, in order.
    fn fields(&self) -> [Value; 6] {
        [
            Value::bytes(self.resource_id.as_bytes().to_vec()),
            Value::Unsigned(self.data_epoch),
            Value::bytes(self.publisher.as_bytes().to_vec()),
            Value::Unsigned(self.sequence),
            Value::bytes(self.control_head.as_bytes().to_vec()),
            self.frontier.to_value(),
        ]
    }

    /// The exact AAD: the label, then payload fields 0 to 5 (§29.1.3).
    pub fn aad(&self) -> Vec<u8> {
        let mut items = vec![Value::text(AAD_LABEL)];
        items.extend(self.fields());
        cbor::encode(&Value::Array(items)).expect("the AAD array is always encodable")
    }

    fn payload(&self, ciphertext: Vec<u8>) -> Value {
        let mut entries: Vec<(Value, Value)> = self
            .fields()
            .into_iter()
            .enumerate()
            .map(|(key, value)| (Value::Unsigned(key as u64), value))
            .collect();
        entries.push((Value::Unsigned(6), Value::Bytes(ciphertext)));
        Value::Map(entries)
    }

    fn from_payload(payload: &Value) -> Result<(SnapshotHeader, Vec<u8>), Error> {
        let err = Error::SnapshotMalformed;
        check_closed_map(payload, &[0, 1, 2, 3, 4, 5, 6], &[], err.clone())?;
        let header = SnapshotHeader {
            resource_id: resource_field(payload, 0, &err)?,
            data_epoch: uint_field(payload, 1, &err)?,
            publisher: principal_field(payload, 2, &err)?,
            sequence: uint_field(payload, 3, &err)?,
            control_head: hash_field(payload, 4, &err)?,
            frontier: Frontier::from_value(payload.get_uint(5).ok_or(err.clone())?)?,
        };
        let ciphertext = bytes_field(payload, 6, &err)?.to_vec();
        Ok((header, ciphertext))
    }

    fn key(&self, dek: &Dek) -> SnapshotKey {
        SnapshotKey::derive(dek, &self.resource_id, self.data_epoch, &self.publisher)
    }
}

/// A structurally valid Snapshot whose signature is not yet verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivedSnapshot {
    object: SignedObject,
    header: SnapshotHeader,
    ciphertext: Vec<u8>,
}

impl ReceivedSnapshot {
    /// Parse a Snapshot from its exact signed-object bytes: canonical COSE
    /// (§10), a closed §29 payload and a canonical frontier (§28, N6).
    pub fn parse(bytes: &[u8]) -> Result<ReceivedSnapshot, Error> {
        let object = cose::parse(bytes)?;
        let (header, ciphertext) = SnapshotHeader::from_payload(object.payload())?;
        Ok(ReceivedSnapshot {
            object,
            header,
            ciphertext,
        })
    }

    /// The payload header, unauthenticated until [`verify`](Self::verify).
    pub fn header(&self) -> &SnapshotHeader {
        &self.header
    }

    /// Verify that the publisher in payload field 2 signed the Snapshot.
    /// Any other signer is [`Error::CoseKidMismatch`].
    pub fn verify(self, publisher: &PrincipalDescriptor) -> Result<Snapshot, Error> {
        if publisher.id() != &self.header.publisher {
            return Err(Error::CoseKidMismatch);
        }
        cose::verify(&self.object, publisher)?;
        Ok(Snapshot {
            object: self.object,
            header: self.header,
            ciphertext: self.ciphertext,
        })
    }
}

/// A Snapshot whose signature by its publisher has been verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    object: SignedObject,
    header: SnapshotHeader,
    ciphertext: Vec<u8>,
}

impl Snapshot {
    /// Encrypt `plaintext` and sign the Snapshot as `signer`, which must be
    /// the header's publisher (§29.1.4).
    pub fn seal(
        header: SnapshotHeader,
        plaintext: &[u8],
        dek: &Dek,
        signer: &PrincipalKeys,
    ) -> Result<Snapshot, Error> {
        if signer.descriptor().id() != &header.publisher {
            return Err(Error::CoseKidMismatch);
        }
        let ciphertext = crypto::aead_seal(
            header.key(dek).expose_secret(),
            &sequence_nonce(header.sequence),
            plaintext,
            &header.aad(),
        );
        let payload = cbor::encode(&header.payload(ciphertext.clone()))?;
        let object = cose::sign(&payload, signer)?;
        Ok(Snapshot {
            object,
            header,
            ciphertext,
        })
    }

    /// Decrypt the plaintext with the DEK of the Snapshot's epoch, using
    /// the reconstructed AAD and no alternative layout. Failure is
    /// [`Error::AeadFailure`], which is client-local (§29.1.4).
    pub fn open(&self, dek: &Dek) -> Result<Vec<u8>, Error> {
        crypto::aead_open(
            self.header.key(dek).expose_secret(),
            &sequence_nonce(self.header.sequence),
            &self.ciphertext,
            &self.header.aad(),
        )
    }

    /// The Snapshot ID: SHA-256 of the exact signed-object bytes.
    pub fn id(&self) -> &Hash32 {
        self.object.id()
    }

    /// The verified header.
    pub fn header(&self) -> &SnapshotHeader {
        &self.header
    }

    /// Payload field 6: ciphertext followed by the Poly1305 tag.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// The signed object, with its exact bytes.
    pub fn signed_object(&self) -> &SignedObject {
        &self.object
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::frontier::ActorHave;

    fn publisher() -> PrincipalKeys {
        PrincipalKeys::from_secrets(&[1; 32], [2; 32])
    }

    fn header() -> SnapshotHeader {
        SnapshotHeader {
            resource_id: ResourceId::from_bytes([7; 32]),
            data_epoch: 1,
            publisher: *publisher().descriptor().id(),
            sequence: 3,
            control_head: Hash32::from_bytes([8; 32]),
            frontier: Frontier::new(vec![ActorHave {
                principal: *publisher().descriptor().id(),
                contiguous: 2,
                extra: vec![],
            }])
            .unwrap(),
        }
    }

    #[test]
    fn seal_parse_verify_open() {
        let dek = Dek::from_bytes([3; 32]);
        let snapshot = Snapshot::seal(header(), b"state", &dek, &publisher()).unwrap();
        let received = ReceivedSnapshot::parse(snapshot.signed_object().bytes()).unwrap();
        let verified = received.verify(publisher().descriptor()).unwrap();
        assert_eq!(verified, snapshot);
        assert_eq!(verified.open(&dek).unwrap(), b"state");
        assert_eq!(
            verified.open(&Dek::from_bytes([4; 32])),
            Err(Error::AeadFailure)
        );
    }

    #[test]
    fn signer_must_be_the_publisher() {
        let other = PrincipalKeys::from_secrets(&[5; 32], [6; 32]);
        let dek = Dek::from_bytes([3; 32]);
        assert_eq!(
            Snapshot::seal(header(), b"x", &dek, &other),
            Err(Error::CoseKidMismatch)
        );
        let snapshot = Snapshot::seal(header(), b"x", &dek, &publisher()).unwrap();
        let received = ReceivedSnapshot::parse(snapshot.signed_object().bytes()).unwrap();
        assert_eq!(
            received.verify(other.descriptor()),
            Err(Error::CoseKidMismatch)
        );
    }

    #[test]
    fn aad_is_the_label_then_payload_fields_0_to_5() {
        let header = header();
        let aad = cbor::decode_strict(&header.aad()).unwrap();
        let items = aad.as_array().unwrap();
        assert_eq!(items.len(), 7);
        assert_eq!(items[0], Value::text("LFCP-SNAPSHOT-v1"));
        assert_eq!(&items[1..], &header.fields());
    }
}
