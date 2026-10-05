//! Profile plaintext framing (SHARED-OBJECTS-PROFILE-01 §11–§13).
//!
//! ```text
//! shared-objects-change   = [1, bstr]   ; exactly one Automerge change
//! shared-objects-snapshot = [1, bstr]   ; one Automerge full-save image
//! ```
//!
//! Both are deterministic CBOR. A receiver rejects plaintext that is not
//! CBOR, not a two-element array, uses another framing version, or does not
//! carry a valid Automerge change (§11). Version 1 carries one change per
//! Data Unit (§12).

use automerge::{AutoCommit, Change};

use crate::cbor::{self, Value};
use crate::shared_objects::ProfileError;

/// The framing version this module reads and writes.
pub const FRAMING_VERSION: u64 = 1;

/// `[1, bytes]` as deterministic CBOR.
fn frame(bytes: &[u8]) -> Vec<u8> {
    cbor::encode(&Value::Array(vec![
        Value::Unsigned(FRAMING_VERSION),
        Value::bytes(bytes.to_vec()),
    ]))
    .expect("an array of an integer and bytes always encodes")
}

/// The payload of `[1, bytes]`, rejecting anything else.
fn unframe(plaintext: &[u8]) -> Result<Vec<u8>, ProfileError> {
    let value = cbor::decode_strict(plaintext).map_err(|_| ProfileError::FramingInvalid)?;
    match value.as_array() {
        Some([version, payload]) => {
            let version = version.as_u64().ok_or(ProfileError::FramingInvalid)?;
            if version != FRAMING_VERSION {
                return Err(ProfileError::FramingVersionUnsupported(version));
            }
            payload
                .as_bytes()
                .map(<[u8]>::to_vec)
                .ok_or(ProfileError::FramingInvalid)
        }
        _ => Err(ProfileError::FramingInvalid),
    }
}

/// The Data Unit plaintext for the exact Automerge change bytes `change`
/// (§11). The bytes are framed as given; [`decode_change`] checks them.
pub fn encode_change(change: &[u8]) -> Vec<u8> {
    frame(change)
}

/// Decode a Data Unit plaintext into one valid Automerge change (§11).
pub fn decode_change(plaintext: &[u8]) -> Result<Change, ProfileError> {
    Change::from_bytes(unframe(plaintext)?).map_err(|err| ProfileError::Automerge(err.to_string()))
}

/// The Snapshot plaintext for the exact Automerge full-save bytes `save`
/// (§13).
pub fn encode_snapshot(save: &[u8]) -> Vec<u8> {
    frame(save)
}

/// The full-save bytes of a Snapshot plaintext (§13), checked to load.
pub fn decode_snapshot(plaintext: &[u8]) -> Result<Vec<u8>, ProfileError> {
    let save = unframe(plaintext)?;
    AutoCommit::load(&save)?;
    Ok(save)
}

/// The full-save bytes of a Snapshot plaintext, without loading them.
pub fn snapshot_payload(plaintext: &[u8]) -> Result<Vec<u8>, ProfileError> {
    unframe(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_rejects_other_shapes() {
        assert_eq!(encode_change(&[1, 2]), vec![0x82, 0x01, 0x42, 0x01, 0x02]);
        let reject = |plaintext: &[u8]| snapshot_payload(plaintext).unwrap_err();
        assert_eq!(reject(&[0xff]), ProfileError::FramingInvalid);
        assert_eq!(reject(&[0x81, 0x01]), ProfileError::FramingInvalid);
        assert_eq!(
            reject(&[0x83, 0x01, 0x40, 0x40]),
            ProfileError::FramingInvalid
        );
        assert_eq!(reject(&[0x82, 0x01, 0x60]), ProfileError::FramingInvalid);
        assert_eq!(
            reject(&[0x82, 0x02, 0x40]),
            ProfileError::FramingVersionUnsupported(2)
        );
        // Not deterministic CBOR: the version in a two-byte head.
        assert_eq!(
            reject(&[0x82, 0x18, 0x01, 0x40]),
            ProfileError::FramingInvalid
        );
        assert!(matches!(
            decode_change(&encode_change(&[0, 1, 2])),
            Err(ProfileError::Automerge(_))
        ));
    }
}
