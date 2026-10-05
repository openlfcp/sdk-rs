//! Profile plaintext framing (SHARED-OBJECTS-PROFILE-01 §11–§13).
//!
//! ```text
//! shared-objects-change   = [1, bstr]   ; exactly one Automerge change
//! shared-objects-snapshot = [1, bstr]   ; one Automerge full-save image
//! ```
//!
//! Both are deterministic CBOR. A receiver rejects plaintext that is not
//! CBOR, not a two-element array, uses another framing version, or does not
//! carry a valid Automerge chunk of the right type (§11, §13). Version 1
//! carries one change per Data Unit (§12).
//!
//! Chunks (SC-CHUNK): a Data Unit carries one change chunk (uncompressed
//! or compressed) and a Snapshot one document chunk. The chunk checksum (the
//! header's four bytes, the first four of the chunk's SHA-256 hash) must
//! match even where Automerge would parse the chunk: automerge 0.12's
//! `Change::from_bytes` does not check it, so [`decode_change`] compares it
//! with the decoded change's hash; `AutoCommit::load` checks a document's.

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

/// The Automerge storage chunk magic bytes.
const CHUNK_MAGIC: [u8; 4] = [0x85, 0x6f, 0x4a, 0x83];
/// Chunk types: a document, a change, a compressed change.
const DOCUMENT_CHUNK: u8 = 0;
const CHANGE_CHUNK: u8 = 1;
const COMPRESSED_CHANGE_CHUNK: u8 = 2;

/// An Automerge chunk header: magic, checksum, type, LEB128 length.
struct ChunkHeader {
    checksum: [u8; 4],
    chunk_type: u8,
    /// Where the chunk ends.
    end: usize,
}

fn chunk_header(bytes: &[u8]) -> Result<ChunkHeader, ProfileError> {
    let invalid = || ProfileError::Automerge("not an Automerge chunk".into());
    if bytes.len() < 9 || bytes[..4] != CHUNK_MAGIC {
        return Err(invalid());
    }
    let checksum = bytes[4..8].try_into().expect("four bytes");
    let chunk_type = bytes[8];
    let (mut length, mut shift, mut at) = (0usize, 0u32, 9);
    loop {
        let byte = *bytes.get(at).ok_or_else(invalid)?;
        at += 1;
        let part = usize::from(byte & 0x7f)
            .checked_shl(shift)
            .ok_or_else(invalid)?;
        length = length.checked_add(part).ok_or_else(invalid)?;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return Err(invalid());
        }
    }
    let end = at.checked_add(length).ok_or_else(invalid)?;
    if end > bytes.len() {
        return Err(invalid());
    }
    Ok(ChunkHeader {
        checksum,
        chunk_type,
        end,
    })
}

/// Decode a Data Unit plaintext into one valid Automerge change (§11): a
/// single change chunk (not a document chunk) whose checksum matches.
pub fn decode_change(plaintext: &[u8]) -> Result<Change, ProfileError> {
    let bytes = unframe(plaintext)?;
    let header = chunk_header(&bytes)?;
    if !matches!(header.chunk_type, CHANGE_CHUNK | COMPRESSED_CHANGE_CHUNK) {
        return Err(ProfileError::Automerge("not a change chunk".into()));
    }
    let change =
        Change::from_bytes(bytes).map_err(|err| ProfileError::Automerge(err.to_string()))?;
    // The checksum is the first four bytes of the (uncompressed) change's
    // hash, which Automerge computes from the chunk's contents.
    if change.hash().0[..4] != header.checksum {
        return Err(ProfileError::Automerge(
            "change chunk checksum mismatch".into(),
        ));
    }
    Ok(change)
}

/// The Snapshot plaintext for the exact Automerge full-save bytes `save`
/// (§13).
pub fn encode_snapshot(save: &[u8]) -> Vec<u8> {
    frame(save)
}

/// The full-save bytes of a Snapshot plaintext (§13), checked: one
/// document chunk (not a change chunk) that loads, its checksum verified
/// by the load.
pub fn decode_snapshot(plaintext: &[u8]) -> Result<Vec<u8>, ProfileError> {
    let save = unframe(plaintext)?;
    let header = chunk_header(&save)?;
    if header.chunk_type != DOCUMENT_CHUNK || header.end != save.len() {
        return Err(ProfileError::Automerge(
            "not a single document chunk".into(),
        ));
    }
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

    /// A document with one change writing `value`; its change bytes and
    /// its save.
    fn sample(value: &str) -> (Vec<u8>, Vec<u8>) {
        use automerge::transaction::Transactable;
        let mut doc = AutoCommit::new();
        doc.put(automerge::ROOT, "k", value).unwrap();
        let change = doc.get_last_local_change().unwrap().bytes().to_vec();
        (change, doc.save())
    }

    #[test]
    fn a_data_unit_carries_one_change_chunk_with_its_checksum() {
        // §11 (SC-CHUNK).
        let (change, save) = sample("small");
        assert_eq!(change[8], CHANGE_CHUNK);
        assert!(decode_change(&encode_change(&change)).is_ok());

        // A wrong checksum: Automerge alone accepts it, the profile not.
        let mut corrupt = change.clone();
        corrupt[4] ^= 0xff;
        assert!(Change::from_bytes(corrupt.clone()).is_ok());
        assert!(matches!(
            decode_change(&encode_change(&corrupt)),
            Err(ProfileError::Automerge(_))
        ));

        // A full save is a document chunk, not a change.
        assert_eq!(save[8], DOCUMENT_CHUNK);
        assert!(matches!(
            decode_change(&encode_change(&save)),
            Err(ProfileError::Automerge(_))
        ));

        // A compressed change chunk is a change too.
        let (big, _) = sample(&"x".repeat(4096));
        assert_eq!(big[8], COMPRESSED_CHANGE_CHUNK);
        assert!(decode_change(&encode_change(&big)).is_ok());
        let mut corrupt = big.clone();
        corrupt[5] ^= 0xff;
        assert!(decode_change(&encode_change(&corrupt)).is_err());
    }

    #[test]
    fn a_snapshot_carries_one_document_chunk_with_its_checksum() {
        // §13 (SC-CHUNK).
        let (change, save) = sample("v");
        assert_eq!(decode_snapshot(&encode_snapshot(&save)).unwrap(), save);
        let mut corrupt = save.clone();
        corrupt[4] ^= 0xff;
        assert!(decode_snapshot(&encode_snapshot(&corrupt)).is_err());
        // A change chunk is not a Snapshot, though Automerge loads it.
        assert!(AutoCommit::load(&change).is_ok());
        assert!(matches!(
            decode_snapshot(&encode_snapshot(&change)),
            Err(ProfileError::Automerge(_))
        ));
        // Nor is a document chunk followed by more.
        let two = [save.clone(), change].concat();
        assert!(decode_snapshot(&encode_snapshot(&two)).is_err());
    }
}
