//! Profile plaintext framing (SHARED-OBJECTS-PROFILE-01 §11–§13).
//!
//! ```text
//! shared-objects-change   = [1, bstr]   ; exactly one Automerge change
//! shared-objects-snapshot = [1, bstr]   ; one Automerge full-save image
//! ```
//!
//! Both are deterministic CBOR. A receiver rejects plaintext that is not
//! CBOR, not a two-element array, uses another framing version, or does not
//! carry a valid Automerge chunk of the right type (§11, §13), with
//! `PROFILE_INVALID` and `INVALID_AUTOMERGE_BYTES` (§74.1). Version 1
//! carries one change per Data Unit (§12).
//!
//! Chunks (SC-CHUNK): a Data Unit carries one uncompressed change chunk
//! and a Snapshot one document chunk, each checked against its expansion
//! limits before Automerge sees it (§11.1, §13.1; [`super::expansion`]).
//! Writers frame a change's raw bytes (`Change::raw_bytes`), never the
//! compressed form `Change::bytes` makes above 256 bytes. The chunk
//! checksum (the header's four bytes, the first four of the chunk's
//! SHA-256 hash) must match even where Automerge would parse the chunk:
//! automerge 0.12's `Change::from_bytes` does not check it, so
//! [`decode_change`] compares it with the decoded change's hash;
//! `AutoCommit::load` checks a document's.

use automerge::{Change, ChangeHash};
use sha2::{Digest, Sha256};

use crate::cbor::{self, Value};
use crate::shared_objects::{canonical, expansion, Diagnostic, ProfileError};

/// Every rejection here: `PROFILE_INVALID` with `INVALID_AUTOMERGE_BYTES`.
const INVALID: ProfileError = ProfileError::Invalid(Diagnostic::InvalidAutomergeBytes);

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
pub(crate) fn unframe(plaintext: &[u8]) -> Result<Vec<u8>, ProfileError> {
    let value = cbor::decode_strict(plaintext).map_err(|_| INVALID)?;
    match value.as_array() {
        Some([version, payload]) if version.as_u64() == Some(FRAMING_VERSION) => {
            payload.as_bytes().map(<[u8]>::to_vec).ok_or(INVALID)
        }
        _ => Err(INVALID),
    }
}

/// The Data Unit plaintext for the exact Automerge change bytes `change`
/// (§11). The bytes are framed as given; [`decode_change`] checks them.
pub fn encode_change(change: &[u8]) -> Vec<u8> {
    frame(change)
}

/// The Automerge storage chunk magic bytes.
const CHUNK_MAGIC: [u8; 4] = [0x85, 0x6f, 0x4a, 0x83];
/// Chunk types: a document, a change.
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
    let invalid = || INVALID;
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
/// single uncompressed change chunk within the §11.1 limits, in the
/// canonical encoding of §11.3, whose checksum matches. Both are checked
/// before Automerge parses it. The §11.4 references are checked at
/// admission, against the change's history.
pub fn decode_change(plaintext: &[u8]) -> Result<Change, ProfileError> {
    let bytes = unframe(plaintext)?;
    let header = chunk_header(&bytes)?;
    if header.chunk_type != CHANGE_CHUNK {
        return Err(INVALID);
    }
    expansion::check_change(&bytes)?;
    // §11.3: the canonical encoding, every counter below 2^32 among it,
    // before Automerge parses the change (automerge 0.12 panics on a larger
    // counter). The parse is guarded all the same.
    canonical::check(&bytes)?;
    let change = std::panic::catch_unwind(|| Change::from_bytes(bytes))
        .map_err(|_| INVALID)?
        .map_err(|_| INVALID)?;
    // The checksum is the first four bytes of the (uncompressed) change's
    // hash, which Automerge computes from the chunk's contents.
    if change.hash().0[..4] != header.checksum {
        return Err(INVALID);
    }
    Ok(change)
}

/// The Snapshot plaintext for the exact Automerge full-save bytes `save`
/// (§13).
pub fn encode_snapshot(save: &[u8]) -> Vec<u8> {
    frame(save)
}

/// How much a refused compressed change chunk may inflate to while its
/// hash is computed: more than any change within §11.1 holds.
const REFUSED_INFLATE_CAP: u64 = 8 * 1024 * 1024;

/// The change hash and actor a refused Data Unit plaintext names,
/// computed without parsing its operations: bytes that failed §11 or §11.1
/// are never handed to Automerge, which would expand them (an RLE or
/// DEFLATE bomb). Automerge hashes a change as SHA-256 of its uncompressed
/// type, length and body; the body starts with the dependencies and the
/// actor:
/// - an uncompressed change chunk (type 1) is read as it is, whatever its
///   checksum says;
/// - a compressed one (type 2) is inflated under a cap of 8 MiB first, and
///   names nothing when it inflates to more;
/// - anything else, or trailing bytes, names nothing.
pub fn refused_change_key(plaintext: &[u8]) -> Option<(ChangeHash, Vec<u8>)> {
    let bytes = unframe(plaintext).ok()?;
    let header = chunk_header(&bytes).ok()?;
    if header.end != bytes.len() {
        return None;
    }
    let body_at = 9 + leb_len(&bytes[9..])?;
    let inflated;
    let body: &[u8] = match header.chunk_type {
        CHANGE_CHUNK => &bytes[body_at..],
        COMPRESSED_CHANGE_CHUNK => {
            inflated = expansion::inflate_capped(&bytes[body_at..], REFUSED_INFLATE_CAP).ok()?;
            &inflated
        }
        _ => return None,
    };
    let mut hasher = Sha256::new();
    hasher.update([CHANGE_CHUNK]);
    hasher.update(uleb(body.len()));
    hasher.update(body);
    let hash = ChangeHash(hasher.finalize().into());
    // Dependencies: a count and 32 bytes each; then the actor, length-prefixed.
    let (deps, at) = read_uleb(body, 0)?;
    let at = at.checked_add(deps.checked_mul(32)?)?;
    let (len, at) = read_uleb(body, at)?;
    let actor = body.get(at..at.checked_add(len)?)?.to_vec();
    Some((hash, actor))
}

/// The ULEB128 number at `at` in `bytes` and the offset after it.
fn read_uleb(bytes: &[u8], at: usize) -> Option<(usize, usize)> {
    let mut value: usize = 0;
    for (i, b) in bytes.get(at..)?.iter().enumerate().take(10) {
        value |= usize::from(b & 0x7f).checked_shl(7 * i as u32)?;
        if b & 0x80 == 0 {
            return Some((value, at + i + 1));
        }
    }
    None
}

/// The length in bytes of the ULEB128 number at the start of `bytes`.
fn leb_len(bytes: &[u8]) -> Option<usize> {
    bytes.iter().position(|b| b & 0x80 == 0).map(|i| i + 1)
}

fn uleb(mut n: usize) -> Vec<u8> {
    let mut out = vec![];
    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

/// The full-save bytes of a Snapshot plaintext (§13), checked: one
/// document chunk (not a change chunk) within the floor limits of §13.1
/// and the depth bound of §11.2 that loads, its checksum verified by the
/// load.
pub fn decode_snapshot(plaintext: &[u8]) -> Result<Vec<u8>, ProfileError> {
    decode_snapshot_within(plaintext, &expansion::SNAPSHOT_LIMITS_FLOOR)
}

/// [`decode_snapshot`] with a receiver's own limits, at least
/// [`expansion::SNAPSHOT_LIMITS_FLOOR`] (§13.1). The limits and the depth
/// bound (§11.2) are checked before Automerge loads the save.
pub fn decode_snapshot_within(
    plaintext: &[u8],
    limits: &expansion::Limits,
) -> Result<Vec<u8>, ProfileError> {
    let save = unframe(plaintext)?;
    let header = chunk_header(&save)?;
    if header.chunk_type != DOCUMENT_CHUNK || header.end != save.len() {
        return Err(INVALID);
    }
    expansion::check_snapshot_depth(&save, limits)?;
    crate::shared_objects::document::load_guarded(&save)?;
    Ok(save)
}

/// The full-save bytes of a Snapshot plaintext, without checking or
/// loading them: a caller that loads them checks them first
/// ([`expansion::check_snapshot_depth`]).
pub fn snapshot_payload(plaintext: &[u8]) -> Result<Vec<u8>, ProfileError> {
    unframe(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use automerge::AutoCommit;

    #[test]
    fn framing_rejects_other_shapes() {
        assert_eq!(encode_change(&[1, 2]), vec![0x82, 0x01, 0x42, 0x01, 0x02]);
        let reject = |plaintext: &[u8]| snapshot_payload(plaintext).unwrap_err();
        assert_eq!(reject(&[0xff]), INVALID);
        assert_eq!(reject(&[0x81, 0x01]), INVALID);
        assert_eq!(reject(&[0x83, 0x01, 0x40, 0x40]), INVALID);
        assert_eq!(reject(&[0x82, 0x01, 0x60]), INVALID);
        assert_eq!(reject(&[0x82, 0x02, 0x40]), INVALID);
        // Not deterministic CBOR: the version in a two-byte head.
        assert_eq!(reject(&[0x82, 0x18, 0x01, 0x40]), INVALID);
        assert_eq!(
            decode_change(&encode_change(&[0, 1, 2])).unwrap_err(),
            INVALID
        );
    }

    /// A document with one change writing `value`; its change bytes and
    /// its save.
    fn sample(value: &str) -> (Vec<u8>, Vec<u8>) {
        use automerge::transaction::Transactable;
        let mut doc = AutoCommit::new();
        doc.put(automerge::ROOT, "k", value).unwrap();
        let change = doc.get_last_local_change().unwrap().raw_bytes().to_vec();
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
            Err(INVALID)
        ));

        // A full save is a document chunk, not a change.
        assert_eq!(save[8], DOCUMENT_CHUNK);
        assert!(matches!(decode_change(&encode_change(&save)), Err(INVALID)));

        // §11.1: a compressed change chunk (type 2) is refused, even one
        // that holds a valid change; its raw form is accepted.
        let mut doc = AutoCommit::new();
        {
            use automerge::transaction::Transactable;
            doc.put(automerge::ROOT, "k", "x".repeat(4096)).unwrap();
        }
        let mut big = doc.get_last_local_change().unwrap().clone();
        let compressed = big.bytes().to_vec();
        assert_eq!(compressed[8], 2, "Automerge compresses above 256 bytes");
        assert_eq!(
            decode_change(&encode_change(&compressed)).unwrap_err(),
            INVALID
        );
        assert!(decode_change(&encode_change(big.raw_bytes())).is_ok());
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
            Err(INVALID)
        ));
        // Nor is a document chunk followed by more.
        let two = [save.clone(), change].concat();
        assert!(decode_snapshot(&encode_snapshot(&two)).is_err());
    }
}
