//! The Control Plane: typed Control Records and Control Chain validation
//! (LFCP-WIRE-01 §13–§24).
//!
//! ```text
//! payload = {0: resource-id, 1: control_seq, 2: prev_control_id / null,
//!            3: control_type, 4: issuer, 5: body}
//! ```
//!
//! The record ID is the object ID of the signed object (§13, §10.6).
//!
//! - [`body`]: typed bodies of every core Control Record type.
//! - [`chain`]: Control Chain validation and fork detection.
//! - [`authority`]: the capability engine and Control transitions.
//! - [`epoch`]: Data Epochs and the strict previous-epoch cutoff.
//!
//! A record is received in two steps, as Data Units are:
//! [`ReceivedControlRecord::parse`] checks structure and the typed body,
//! and [`ReceivedControlRecord::verify`] checks the signature of the
//! issuer. Whether the issuer was authorized is evaluated separately.

pub mod authority;
pub mod body;
pub mod chain;
pub mod epoch;

use crate::base::{ControlRecordId, Error, PrincipalId, ResourceId};
use crate::cbor::{self, Value};
use crate::cose::{self, SignedObject};
use crate::principal::{PrincipalDescriptor, PrincipalKeys};
use crate::wire::{check_closed_map, hash_field, principal_field, resource_field, uint_field};

use body::ControlBody;

/// Payload fields 0 to 4 of a Control Record (§13).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlRecordHeader {
    /// Field 0: the Resource.
    pub resource_id: ResourceId,
    /// Field 1: the Control Sequence; Genesis is 0.
    pub sequence: u64,
    /// Field 2: the previous record; `None` only for Genesis.
    pub previous: Option<ControlRecordId>,
    /// Field 4: the issuing Principal, which must sign the record.
    pub issuer: PrincipalId,
}

/// A structurally valid Control Record whose signature is not yet
/// verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivedControlRecord {
    object: SignedObject,
    header: ControlRecordHeader,
    body: ControlBody,
}

fn decode_payload(payload: &Value) -> Result<(ControlRecordHeader, ControlBody), Error> {
    let err = Error::ControlRecordMalformed;
    check_closed_map(payload, &[0, 1, 2, 3, 4, 5], &[], err.clone())?;
    let previous = match payload.get_uint(2) {
        Some(Value::Null) => None,
        Some(Value::Bytes(_)) => Some(ControlRecordId::from_bytes(
            *hash_field(payload, 2, &err)?.as_bytes(),
        )),
        _ => return Err(err),
    };
    let header = ControlRecordHeader {
        resource_id: resource_field(payload, 0, &err)?,
        sequence: uint_field(payload, 1, &err)?,
        previous,
        issuer: principal_field(payload, 4, &err)?,
    };
    let control_type = uint_field(payload, 3, &err)?;
    let body = ControlBody::from_value(control_type, payload.get_uint(5).ok_or(err)?)?;
    Ok((header, body))
}

fn encode_payload(header: &ControlRecordHeader, body: &ControlBody) -> Value {
    let previous = match &header.previous {
        Some(id) => Value::bytes(id.as_bytes().to_vec()),
        None => Value::Null,
    };
    Value::Map(vec![
        (
            Value::Unsigned(0),
            Value::bytes(header.resource_id.as_bytes().to_vec()),
        ),
        (Value::Unsigned(1), Value::Unsigned(header.sequence)),
        (Value::Unsigned(2), previous),
        (Value::Unsigned(3), Value::Unsigned(body.control_type())),
        (
            Value::Unsigned(4),
            Value::bytes(header.issuer.as_bytes().to_vec()),
        ),
        (Value::Unsigned(5), body.to_value()),
    ])
}

impl ReceivedControlRecord {
    /// Parse a Control Record from its exact signed-object bytes: canonical
    /// COSE (§10), a closed §13 payload and a typed body.
    pub fn parse(bytes: &[u8]) -> Result<ReceivedControlRecord, Error> {
        let object = cose::parse(bytes)?;
        let (header, body) = decode_payload(object.payload())?;
        Ok(ReceivedControlRecord {
            object,
            header,
            body,
        })
    }

    /// The payload header, unauthenticated until [`verify`](Self::verify).
    pub fn header(&self) -> &ControlRecordHeader {
        &self.header
    }

    /// The typed body, unauthenticated until [`verify`](Self::verify).
    pub fn body(&self) -> &ControlBody {
        &self.body
    }

    /// The record ID.
    pub fn id(&self) -> ControlRecordId {
        ControlRecordId::from_bytes(*self.object.id().as_bytes())
    }

    /// Verify that the issuer in payload field 4 signed the record.
    ///
    /// §13 does not state who signs a Control Record; requiring the `kid`
    /// to be the issuer is spec gap G-RS1, which every vector agrees with.
    /// Any other signer is [`Error::CoseKidMismatch`] (`INVALID_SIGNATURE`).
    pub fn verify(self, issuer: &PrincipalDescriptor) -> Result<ControlRecord, Error> {
        if issuer.id() != &self.header.issuer {
            return Err(Error::CoseKidMismatch);
        }
        cose::verify(&self.object, issuer)?;
        Ok(ControlRecord {
            object: self.object,
            header: self.header,
            body: self.body,
        })
    }
}

/// A Control Record whose signature by its issuer has been verified. Its
/// place in the chain and its authority are not implied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlRecord {
    object: SignedObject,
    header: ControlRecordHeader,
    body: ControlBody,
}

impl ControlRecord {
    /// Sign a record as `signer`, which must be the header's issuer.
    pub fn sign(
        header: ControlRecordHeader,
        body: ControlBody,
        signer: &PrincipalKeys,
    ) -> Result<ControlRecord, Error> {
        if signer.descriptor().id() != &header.issuer {
            return Err(Error::CoseKidMismatch);
        }
        let payload = cbor::encode(&encode_payload(&header, &body))?;
        let object = cose::sign(&payload, signer)?;
        Ok(ControlRecord {
            object,
            header,
            body,
        })
    }

    /// The record ID: SHA-256 of the exact signed-object bytes.
    pub fn id(&self) -> ControlRecordId {
        ControlRecordId::from_bytes(*self.object.id().as_bytes())
    }

    /// The verified header.
    pub fn header(&self) -> &ControlRecordHeader {
        &self.header
    }

    /// The verified typed body.
    pub fn body(&self) -> &ControlBody {
        &self.body
    }

    /// The signed object, with its exact bytes.
    pub fn signed_object(&self) -> &SignedObject {
        &self.object
    }
}

#[cfg(test)]
mod tests {
    use super::body::CapabilityRevokeBody;
    use super::*;

    fn owner() -> PrincipalKeys {
        PrincipalKeys::from_secrets(&[1; 32], [2; 32])
    }

    fn header() -> ControlRecordHeader {
        ControlRecordHeader {
            resource_id: ResourceId::from_bytes([7; 32]),
            sequence: 1,
            previous: Some(ControlRecordId::from_bytes([8; 32])),
            issuer: *owner().descriptor().id(),
        }
    }

    fn revoke() -> ControlBody {
        ControlBody::CapabilityRevoke(CapabilityRevokeBody {
            grant: ControlRecordId::from_bytes([9; 32]),
        })
    }

    #[test]
    fn sign_parse_verify() {
        let record = ControlRecord::sign(header(), revoke(), &owner()).unwrap();
        let received = ReceivedControlRecord::parse(record.signed_object().bytes()).unwrap();
        assert_eq!(received.id(), record.id());
        assert_eq!(received.verify(owner().descriptor()).unwrap(), record);
    }

    #[test]
    fn signer_must_be_the_issuer() {
        let other = PrincipalKeys::from_secrets(&[3; 32], [4; 32]);
        assert_eq!(
            ControlRecord::sign(header(), revoke(), &other),
            Err(Error::CoseKidMismatch)
        );
        let record = ControlRecord::sign(header(), revoke(), &owner()).unwrap();
        let received = ReceivedControlRecord::parse(record.signed_object().bytes()).unwrap();
        assert_eq!(
            received.verify(other.descriptor()),
            Err(Error::CoseKidMismatch)
        );
    }

    #[test]
    fn payload_is_closed() {
        let record = ControlRecord::sign(header(), revoke(), &owner()).unwrap();
        let mut entries = record.signed_object().payload().as_map().unwrap().to_vec();
        entries.push((Value::Unsigned(6), Value::Null));
        let object = cose::sign(&cbor::encode(&Value::Map(entries)).unwrap(), &owner()).unwrap();
        assert_eq!(
            ReceivedControlRecord::parse(object.bytes()),
            Err(Error::ControlRecordMalformed)
        );
    }
}
