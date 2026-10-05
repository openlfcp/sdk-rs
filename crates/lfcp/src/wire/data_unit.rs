//! Data Units: the encrypted, signed unit of replication (LFCP-WIRE-01
//! §26).
//!
//! ```text
//! payload = {0: resource-id, 1: data epoch, 2: actor, 3: actor sequence,
//!            4: previous unit id / null, 5: Control Head, 6: ciphertext}
//! aad     = ["LFCP-DATA-v1", resource-id, epoch, actor, sequence, previous, control head]
//! ```
//!
//! The ciphertext is ChaCha20-Poly1305 under the actor key (§12) with the
//! sequence nonce. The payload is signed by the actor (§26), and the Data
//! Unit ID is the object ID of the signed object.
//!
//! A unit goes through two steps on receipt. [`ReceivedDataUnit::parse`]
//! checks the structure, including sequence ≥ 1 (§8, N4).
//! [`ReceivedDataUnit::verify`] checks the signature against the actor and
//! yields a [`DataUnit`], which can then be opened with the epoch's DEK.
//!
//! Epoch validity, the epoch cutoff and `data/write` authorization
//! (§26.3 steps 2–5) need Control Plane state and are not checked here.

use crate::base::{DataUnitId, Error, Hash32, PrincipalId, ResourceId};
use crate::cbor::{self, Value};
use crate::cose::{self, SignedObject};
use crate::crypto;
use crate::principal::{PrincipalDescriptor, PrincipalKeys};
use crate::wire::keys::{sequence_nonce, ActorKey, Dek};
use crate::wire::{
    bytes_field, check_closed_map, hash_field, principal_field, resource_field, uint_field,
};

const AAD_LABEL: &str = "LFCP-DATA-v1";

/// The authenticated fields of a Data Unit: payload fields 0 to 5.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataUnitHeader {
    /// Field 0: the Resource.
    pub resource_id: ResourceId,
    /// Field 1: the Data Epoch whose DEK encrypts the unit.
    pub data_epoch: u64,
    /// Field 2: the writing Principal, which must sign the unit.
    pub actor: PrincipalId,
    /// Field 3: the actor sequence, starting at 1.
    pub sequence: u64,
    /// Field 4: the actor's previous unit, `None` at sequence 1.
    pub previous: Option<DataUnitId>,
    /// Field 5: the Control Head the actor observed.
    pub control_head: Hash32,
}

impl DataUnitHeader {
    /// The deterministic AAD (§26.1).
    pub fn aad(&self) -> Vec<u8> {
        let previous = match &self.previous {
            Some(id) => Value::bytes(id.as_bytes().to_vec()),
            None => Value::Null,
        };
        let aad = Value::Array(vec![
            Value::text(AAD_LABEL),
            Value::bytes(self.resource_id.as_bytes().to_vec()),
            Value::Unsigned(self.data_epoch),
            Value::bytes(self.actor.as_bytes().to_vec()),
            Value::Unsigned(self.sequence),
            previous,
            Value::bytes(self.control_head.as_bytes().to_vec()),
        ]);
        cbor::encode(&aad).expect("the AAD array is always encodable")
    }

    fn payload(&self, ciphertext: Vec<u8>) -> Value {
        let previous = match &self.previous {
            Some(id) => Value::bytes(id.as_bytes().to_vec()),
            None => Value::Null,
        };
        Value::Map(vec![
            (
                Value::Unsigned(0),
                Value::bytes(self.resource_id.as_bytes().to_vec()),
            ),
            (Value::Unsigned(1), Value::Unsigned(self.data_epoch)),
            (
                Value::Unsigned(2),
                Value::bytes(self.actor.as_bytes().to_vec()),
            ),
            (Value::Unsigned(3), Value::Unsigned(self.sequence)),
            (Value::Unsigned(4), previous),
            (
                Value::Unsigned(5),
                Value::bytes(self.control_head.as_bytes().to_vec()),
            ),
            (Value::Unsigned(6), Value::Bytes(ciphertext)),
        ])
    }

    /// Decode payload fields 0 to 6 of a closed §26 map.
    fn from_payload(payload: &Value) -> Result<(DataUnitHeader, Vec<u8>), Error> {
        let err = Error::DataUnitMalformed;
        check_closed_map(payload, &[0, 1, 2, 3, 4, 5, 6], &[], err.clone())?;
        let previous = match payload.get_uint(4) {
            Some(Value::Null) => None,
            Some(Value::Bytes(bytes)) => {
                Some(DataUnitId::from_slice(bytes).map_err(|_| err.clone())?)
            }
            _ => return Err(err),
        };
        let header = DataUnitHeader {
            resource_id: resource_field(payload, 0, &err)?,
            data_epoch: uint_field(payload, 1, &err)?,
            actor: principal_field(payload, 2, &err)?,
            sequence: uint_field(payload, 3, &err)?,
            previous,
            control_head: hash_field(payload, 5, &err)?,
        };
        let ciphertext = bytes_field(payload, 6, &err)?.to_vec();
        if header.sequence == 0 {
            return Err(Error::DataUnitSequenceZero);
        }
        Ok((header, ciphertext))
    }

    fn actor_key(&self, dek: &Dek) -> ActorKey {
        ActorKey::derive(dek, &self.resource_id, self.data_epoch, &self.actor)
    }
}

/// A structurally valid Data Unit whose signature is not yet verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivedDataUnit {
    object: SignedObject,
    header: DataUnitHeader,
    ciphertext: Vec<u8>,
}

impl ReceivedDataUnit {
    /// Parse a Data Unit from its exact signed-object bytes: canonical
    /// COSE (§10), a closed §26 payload and sequence ≥ 1.
    pub fn parse(bytes: &[u8]) -> Result<ReceivedDataUnit, Error> {
        let object = cose::parse(bytes)?;
        let (header, ciphertext) = DataUnitHeader::from_payload(object.payload())?;
        Ok(ReceivedDataUnit {
            object,
            header,
            ciphertext,
        })
    }

    /// The payload header, unauthenticated until [`verify`](Self::verify).
    pub fn header(&self) -> &DataUnitHeader {
        &self.header
    }

    /// The Data Unit ID.
    pub fn id(&self) -> DataUnitId {
        DataUnitId::from_bytes(*self.object.id().as_bytes())
    }

    /// Verify that the actor signed the unit. `actor` must be the
    /// descriptor of the Principal in payload field 2; any other signer is
    /// [`Error::CoseKidMismatch`] (§10.5, §26).
    pub fn verify(self, actor: &PrincipalDescriptor) -> Result<DataUnit, Error> {
        if actor.id() != &self.header.actor {
            return Err(Error::CoseKidMismatch);
        }
        cose::verify(&self.object, actor)?;
        Ok(DataUnit {
            object: self.object,
            header: self.header,
            ciphertext: self.ciphertext,
        })
    }
}

/// A Data Unit whose signature by its actor has been verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataUnit {
    object: SignedObject,
    header: DataUnitHeader,
    ciphertext: Vec<u8>,
}

impl DataUnit {
    /// Encrypt `plaintext` and sign the unit as `signer`, which must be the
    /// header's actor.
    pub fn seal(
        header: DataUnitHeader,
        plaintext: &[u8],
        dek: &Dek,
        signer: &PrincipalKeys,
    ) -> Result<DataUnit, Error> {
        if signer.descriptor().id() != &header.actor {
            return Err(Error::CoseKidMismatch);
        }
        if header.sequence == 0 {
            return Err(Error::DataUnitSequenceZero);
        }
        let ciphertext = crypto::aead_seal(
            header.actor_key(dek).expose_secret(),
            &sequence_nonce(header.sequence),
            plaintext,
            &header.aad(),
        );
        let payload = cbor::encode(&header.payload(ciphertext.clone()))?;
        let object = cose::sign(&payload, signer)?;
        Ok(DataUnit {
            object,
            header,
            ciphertext,
        })
    }

    /// Decrypt the plaintext with the DEK of the unit's epoch. Failure is
    /// [`Error::AeadFailure`], which is client-local (§26.3, N3).
    pub fn open(&self, dek: &Dek) -> Result<Vec<u8>, Error> {
        crypto::aead_open(
            self.header.actor_key(dek).expose_secret(),
            &sequence_nonce(self.header.sequence),
            &self.ciphertext,
            &self.header.aad(),
        )
    }

    /// The Data Unit ID: SHA-256 of the exact signed-object bytes.
    pub fn id(&self) -> DataUnitId {
        DataUnitId::from_bytes(*self.object.id().as_bytes())
    }

    /// The verified header.
    pub fn header(&self) -> &DataUnitHeader {
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

/// The outcome of checking a unit's place in its actor's hash chain
/// (§26.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainStatus {
    /// The unit starts the chain (sequence 1, previous `null`) or links to
    /// the given previous unit.
    Linked,
    /// A gap or mismatch, which must be reported to the sync engine. This
    /// is a report, not a rejection.
    Report(ChainReport),
}

/// Why a unit does not link into its actor's hash chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainReport {
    /// Sequence 1 with a non-null previous unit (§26.2: "For sequence 1, it
    /// MUST be null").
    PreviousAtSequenceOne,
    /// Sequence above 1 and the receiver holds no unit at sequence − 1.
    Gap,
    /// The previous-unit field does not name the actor's unit at sequence
    /// − 1.
    Mismatch,
}

/// Check `unit` against its actor's hash chain. `previous` is the
/// receiver's unit for the same Resource and actor at sequence − 1, if it
/// has one; it is ignored at sequence 1.
pub fn check_chain(unit: &DataUnit, previous: Option<&DataUnit>) -> ChainStatus {
    let header = unit.header();
    if header.sequence == 1 {
        return match header.previous {
            None => ChainStatus::Linked,
            Some(_) => ChainStatus::Report(ChainReport::PreviousAtSequenceOne),
        };
    }
    let Some(previous) = previous else {
        return ChainStatus::Report(ChainReport::Gap);
    };
    let before = previous.header();
    let is_predecessor = before.resource_id == header.resource_id
        && before.actor == header.actor
        && before.sequence.checked_add(1) == Some(header.sequence);
    if is_predecessor && header.previous == Some(previous.id()) {
        ChainStatus::Linked
    } else {
        ChainStatus::Report(ChainReport::Mismatch)
    }
}

/// Detect actor equivocation: two verified units with the same
/// `(resource, actor, sequence)` but different IDs (§26.2). The client must
/// not silently choose one.
pub fn check_equivocation(a: &DataUnit, b: &DataUnit) -> Result<(), Error> {
    let (x, y) = (a.header(), b.header());
    let same_slot =
        x.resource_id == y.resource_id && x.actor == y.actor && x.sequence == y.sequence;
    if same_slot && a.id() != b.id() {
        Err(Error::ActorEquivocation)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bob() -> PrincipalKeys {
        PrincipalKeys::from_secrets(&[1; 32], [2; 32])
    }

    fn header(sequence: u64, previous: Option<DataUnitId>) -> DataUnitHeader {
        DataUnitHeader {
            resource_id: ResourceId::from_bytes([7; 32]),
            data_epoch: 0,
            actor: *bob().descriptor().id(),
            sequence,
            previous,
            control_head: Hash32::from_bytes([8; 32]),
        }
    }

    fn seal(sequence: u64, previous: Option<DataUnitId>, plaintext: &[u8]) -> DataUnit {
        DataUnit::seal(
            header(sequence, previous),
            plaintext,
            &Dek::from_bytes([3; 32]),
            &bob(),
        )
        .unwrap()
    }

    #[test]
    fn seal_parse_verify_open() {
        let unit = seal(1, None, b"hello");
        let received = ReceivedDataUnit::parse(unit.signed_object().bytes()).unwrap();
        assert_eq!(received.id(), unit.id());
        let verified = received.verify(bob().descriptor()).unwrap();
        assert_eq!(verified, unit);
        assert_eq!(verified.open(&Dek::from_bytes([3; 32])).unwrap(), b"hello");
        let err = verified.open(&Dek::from_bytes([4; 32])).unwrap_err();
        assert_eq!(err, Error::AeadFailure);
        assert_eq!(err.wire_code(), None);
    }

    #[test]
    fn verify_requires_the_actor() {
        let unit = seal(1, None, b"x");
        let carol = PrincipalKeys::from_secrets(&[5; 32], [6; 32]);
        let received = ReceivedDataUnit::parse(unit.signed_object().bytes()).unwrap();
        assert_eq!(
            received.verify(carol.descriptor()),
            Err(Error::CoseKidMismatch)
        );
        assert_eq!(
            DataUnit::seal(header(1, None), b"x", &Dek::from_bytes([3; 32]), &carol),
            Err(Error::CoseKidMismatch)
        );
    }

    #[test]
    fn sequence_zero_is_rejected() {
        assert_eq!(
            DataUnit::seal(header(0, None), b"x", &Dek::from_bytes([3; 32]), &bob()),
            Err(Error::DataUnitSequenceZero)
        );
    }

    #[test]
    fn payload_map_is_closed() {
        let unit = seal(1, None, b"x");
        let mut entries = unit.signed_object().payload().as_map().unwrap().to_vec();
        entries.push((Value::Unsigned(7), Value::Null));
        let payload = cbor::encode(&Value::Map(entries)).unwrap();
        let object = cose::sign(&payload, &bob()).unwrap();
        assert_eq!(
            ReceivedDataUnit::parse(object.bytes()),
            Err(Error::DataUnitMalformed)
        );
    }

    #[test]
    fn chain_links_and_reports() {
        let first = seal(1, None, b"1");
        let second = seal(2, Some(first.id()), b"2");
        let unlinked = seal(2, None, b"2");
        let wrong_start = seal(1, Some(first.id()), b"1");

        assert_eq!(check_chain(&first, None), ChainStatus::Linked);
        assert_eq!(check_chain(&second, Some(&first)), ChainStatus::Linked);
        assert_eq!(
            check_chain(&wrong_start, None),
            ChainStatus::Report(ChainReport::PreviousAtSequenceOne)
        );
        assert_eq!(
            check_chain(&second, None),
            ChainStatus::Report(ChainReport::Gap)
        );
        assert_eq!(
            check_chain(&unlinked, Some(&first)),
            ChainStatus::Report(ChainReport::Mismatch)
        );
        // The previous unit must be the actor's sequence − 1.
        assert_eq!(
            check_chain(&second, Some(&second)),
            ChainStatus::Report(ChainReport::Mismatch)
        );
    }

    #[test]
    fn equivocation_needs_the_same_slot_and_different_ids() {
        let first = seal(1, None, b"1");
        let other_first = seal(1, None, b"other");
        let second = seal(2, Some(first.id()), b"2");
        assert_eq!(
            check_equivocation(&first, &other_first),
            Err(Error::ActorEquivocation)
        );
        assert_eq!(check_equivocation(&first, &first.clone()), Ok(()));
        assert_eq!(check_equivocation(&first, &second), Ok(()));
    }
}
