//! Identifiers, errors and byte helpers shared by every layer.
//!
//! This module owns the LFCP identifier types, the crate's error type and
//! the two text encodings LFCP uses for bytes: lowercase hexadecimal and
//! unpadded base64url (LFCP-WIRE-01 §18.2). It depends on no other module of
//! this crate.
//!
//! The 32-byte identifiers are distinct types so that a Principal ID cannot
//! be passed where a Resource ID is expected. None of them implements `Ord`:
//! LFCP defines no general ordering of identifiers. The one ordering it does
//! define, raw-byte order of Principal IDs in a canonical frontier
//! (§28.2), is [`PrincipalId::cmp_frontier_order`].

use std::cmp::Ordering;
use std::fmt;

/// An error from any layer of this crate.
///
/// Every variant has a stable [`code`](Error::code). Variants that a
/// receiver reports on the wire also map to a [`WireCode`]. No variant
/// carries key material or other secrets.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A fixed-size value had the wrong number of bytes.
    InvalidLength {
        /// The required length in bytes.
        expected: usize,
        /// The length that was given.
        actual: usize,
    },
    /// Text is not lowercase hexadecimal of even length.
    InvalidHex,
    /// Text is not canonical unpadded base64url.
    InvalidBase64Url,
    /// Text is not a canonical UUIDv7 Object ID (SHARED-OBJECTS-PROFILE-01
    /// §19).
    InvalidObjectId,
    /// CBOR input ended in the middle of an item.
    CborTruncated,
    /// Bytes follow the single top-level CBOR item.
    CborTrailingBytes,
    /// An integer, length or count does not use its shortest encoding.
    CborNonShortest,
    /// An indefinite-length string, array or map.
    CborIndefiniteLength,
    /// A CBOR tag (major type 6). LFCP emits none in deterministic
    /// structures (§5.2, §10).
    CborTag,
    /// A floating-point value (§5.2, CB3).
    CborFloat,
    /// A simple value other than `false`, `true` or `null`, including
    /// `undefined` (§5.2, CB3).
    CborSimpleValue,
    /// A reserved additional-information value or a stray break byte.
    CborReserved,
    /// A text string that is not valid UTF-8.
    CborInvalidUtf8,
    /// A map key that occurs twice.
    CborDuplicateKey,
    /// Map keys out of deterministic order (length first, then bytewise;
    /// §5.2 rule 4, CB1).
    CborUnsortedKeys,
    /// A map key that is not an integer, text string or byte string (§5.2,
    /// CB2).
    CborInvalidKeyType,
    /// Arrays and maps nested deeper than [`crate::cbor::MAX_DEPTH`].
    CborDepthExceeded,
    /// Bytes that decode but are not the deterministic encoding of their
    /// own value (§5.2, N7).
    CborNotDeterministic,
}

impl Error {
    /// A stable identifier for this error, for logs and tests.
    pub fn code(&self) -> &'static str {
        match self {
            Error::InvalidLength { .. } => "INVALID_LENGTH",
            Error::InvalidHex => "INVALID_HEX",
            Error::InvalidBase64Url => "INVALID_BASE64URL",
            Error::InvalidObjectId => "INVALID_OBJECT_ID",
            Error::CborTruncated => "CBOR_TRUNCATED",
            Error::CborTrailingBytes => "CBOR_TRAILING_BYTES",
            Error::CborNonShortest => "CBOR_NON_SHORTEST",
            Error::CborIndefiniteLength => "CBOR_INDEFINITE_LENGTH",
            Error::CborTag => "CBOR_TAG",
            Error::CborFloat => "CBOR_FLOAT",
            Error::CborSimpleValue => "CBOR_SIMPLE_VALUE",
            Error::CborReserved => "CBOR_RESERVED",
            Error::CborInvalidUtf8 => "CBOR_INVALID_UTF8",
            Error::CborDuplicateKey => "CBOR_DUPLICATE_KEY",
            Error::CborUnsortedKeys => "CBOR_UNSORTED_KEYS",
            Error::CborInvalidKeyType => "CBOR_INVALID_KEY_TYPE",
            Error::CborDepthExceeded => "CBOR_DEPTH_EXCEEDED",
            Error::CborNotDeterministic => "CBOR_NOT_DETERMINISTIC",
        }
    }

    /// The LFCP-WIRE-01 §62 error code a receiver reports for this error,
    /// or `None` when the error is local (for example, parsing text a user
    /// typed).
    pub fn wire_code(&self) -> Option<WireCode> {
        match self {
            Error::InvalidLength { .. }
            | Error::InvalidHex
            | Error::InvalidBase64Url
            | Error::InvalidObjectId => None,
            Error::CborTruncated
            | Error::CborTrailingBytes
            | Error::CborNonShortest
            | Error::CborIndefiniteLength
            | Error::CborTag
            | Error::CborFloat
            | Error::CborSimpleValue
            | Error::CborReserved
            | Error::CborInvalidUtf8
            | Error::CborDuplicateKey
            | Error::CborUnsortedKeys
            | Error::CborInvalidKeyType
            | Error::CborDepthExceeded
            | Error::CborNotDeterministic => Some(WireCode::MalformedMessage),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidLength { expected, actual } => {
                write!(f, "expected {expected} bytes, got {actual}")
            }
            Error::InvalidHex => f.write_str("not lowercase hexadecimal"),
            Error::InvalidBase64Url => f.write_str("not canonical unpadded base64url"),
            Error::InvalidObjectId => f.write_str("not a canonical UUIDv7 Object ID"),
            Error::CborTruncated => f.write_str("CBOR input is truncated"),
            Error::CborTrailingBytes => f.write_str("bytes after the CBOR item"),
            Error::CborNonShortest => f.write_str("CBOR head is not in shortest form"),
            Error::CborIndefiniteLength => f.write_str("indefinite-length CBOR item"),
            Error::CborTag => f.write_str("CBOR tag"),
            Error::CborFloat => f.write_str("CBOR floating-point value"),
            Error::CborSimpleValue => {
                f.write_str("CBOR simple value other than false, true or null")
            }
            Error::CborReserved => f.write_str("reserved CBOR encoding"),
            Error::CborInvalidUtf8 => f.write_str("CBOR text string is not UTF-8"),
            Error::CborDuplicateKey => f.write_str("duplicate CBOR map key"),
            Error::CborUnsortedKeys => f.write_str("CBOR map keys out of deterministic order"),
            Error::CborInvalidKeyType => {
                f.write_str("CBOR map key is not an integer, text or byte string")
            }
            Error::CborDepthExceeded => f.write_str("CBOR nesting too deep"),
            Error::CborNotDeterministic => f.write_str("not deterministic CBOR"),
        }
    }
}

impl std::error::Error for Error {}

/// The LFCP-WIRE-01 §62 error codes this crate produces.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum WireCode {
    /// `MALFORMED_MESSAGE` (2).
    MalformedMessage,
    /// `AUTH_FAILED` (3).
    AuthFailed,
    /// `INVALID_SIGNATURE` (7).
    InvalidSignature,
}

impl WireCode {
    /// The numeric code from the §62 registry.
    pub fn number(self) -> u64 {
        match self {
            WireCode::MalformedMessage => 2,
            WireCode::AuthFailed => 3,
            WireCode::InvalidSignature => 7,
        }
    }

    /// The registry name, such as `MALFORMED_MESSAGE`.
    pub fn name(self) -> &'static str {
        match self {
            WireCode::MalformedMessage => "MALFORMED_MESSAGE",
            WireCode::AuthFailed => "AUTH_FAILED",
            WireCode::InvalidSignature => "INVALID_SIGNATURE",
        }
    }
}

/// Copy `bytes` into a fixed-size array, or fail with
/// [`Error::InvalidLength`].
pub fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], Error> {
    bytes.try_into().map_err(|_| Error::InvalidLength {
        expected: N,
        actual: bytes.len(),
    })
}

/// Encode bytes as lowercase hexadecimal.
pub fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        text.push(DIGITS[usize::from(byte >> 4)] as char);
        text.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    text
}

/// Decode lowercase hexadecimal. Uppercase digits are rejected, so every
/// byte string has exactly one accepted form.
pub fn from_hex(text: &str) -> Result<Vec<u8>, Error> {
    fn digit(c: u8) -> Result<u8, Error> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            _ => Err(Error::InvalidHex),
        }
    }
    let text = text.as_bytes();
    if !text.len().is_multiple_of(2) {
        return Err(Error::InvalidHex);
    }
    let (pairs, _) = text.as_chunks::<2>();
    pairs
        .iter()
        .map(|pair| Ok((digit(pair[0])? << 4) | digit(pair[1])?))
        .collect()
}

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encode bytes as unpadded base64url (RFC 4648 §5), as LFCP-WIRE-01 §18.2
/// uses in URIs.
pub fn to_b64url(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        // A chunk of k bytes yields k + 1 characters.
        for i in 0..=chunk.len() {
            let index = (n >> (18 - 6 * i)) & 0x3f;
            text.push(B64URL[index as usize] as char);
        }
    }
    text
}

/// Decode canonical unpadded base64url.
///
/// Rejects padding, characters outside the base64url alphabet, a length
/// that no byte string encodes to, and non-zero unused trailing bits, so
/// every byte string has exactly one accepted form.
pub fn from_b64url(text: &str) -> Result<Vec<u8>, Error> {
    fn value(c: u8) -> Result<u32, Error> {
        match c {
            b'A'..=b'Z' => Ok(u32::from(c - b'A')),
            b'a'..=b'z' => Ok(u32::from(c - b'a') + 26),
            b'0'..=b'9' => Ok(u32::from(c - b'0') + 52),
            b'-' => Ok(62),
            b'_' => Ok(63),
            _ => Err(Error::InvalidBase64Url),
        }
    }
    let text = text.as_bytes();
    if text.len() % 4 == 1 {
        return Err(Error::InvalidBase64Url);
    }
    let mut bytes = Vec::with_capacity(text.len() / 4 * 3 + 2);
    for chunk in text.chunks(4) {
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= value(c)? << (18 - 6 * i);
        }
        let len = chunk.len() - 1;
        let decoded = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        // The bits after the last whole byte must be zero.
        let unused_mask = match len {
            1 => 0x00ffff,
            2 => 0x0000ff,
            _ => 0,
        };
        if n & unused_mask != 0 {
            return Err(Error::InvalidBase64Url);
        }
        bytes.extend_from_slice(&decoded[..len]);
    }
    Ok(bytes)
}

macro_rules! id32 {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Wrap 32 bytes.
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// Wrap a slice, which must be exactly 32 bytes long.
            pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
                fixed(bytes).map(Self)
            }

            /// Parse 64 lowercase hexadecimal digits.
            pub fn from_hex(text: &str) -> Result<Self, Error> {
                Self::from_slice(&from_hex(text)?)
            }

            /// Parse canonical unpadded base64url (§18.2).
            pub fn from_b64url(text: &str) -> Result<Self, Error> {
                Self::from_slice(&from_b64url(text)?)
            }

            /// The raw bytes.
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            /// Lowercase hexadecimal.
            pub fn to_hex(&self) -> String {
                to_hex(&self.0)
            }

            /// Unpadded base64url (§18.2).
            pub fn to_b64url(&self) -> String {
                to_b64url(&self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self.to_hex())
            }
        }
    };
}

id32! {
    /// A Resource ID: 32 random bytes (LFCP-WIRE-01 §6).
    ResourceId
}

id32! {
    /// A Principal ID: SHA-256 over the Principal's public keys
    /// (LFCP-WIRE-01 §7).
    PrincipalId
}

id32! {
    /// A SHA-256 output, `hash32` in the CDDL (LFCP-WIRE-01 §5.3). Object IDs
    /// of signed objects (§10.6) are `Hash32` values.
    Hash32
}

id32! {
    /// A Control Record ID: the object ID of the record's exact COSE_Sign1
    /// bytes (LFCP-WIRE-01 §13, §10.6).
    ControlRecordId
}

id32! {
    /// A Data Unit ID: the object ID of the unit's exact COSE_Sign1 bytes
    /// (LFCP-WIRE-01 §26, §10.6).
    DataUnitId
}

impl PrincipalId {
    /// Compare two Principal IDs as raw 32-byte unsigned strings, the order
    /// of entries in a canonical frontier (LFCP-WIRE-01 §28.2).
    ///
    /// This is deliberately not an `Ord` implementation: LFCP gives
    /// Principals no general order, only this one for frontiers.
    pub fn cmp_frontier_order(&self, other: &PrincipalId) -> Ordering {
        self.0.cmp(&other.0)
    }
}

/// A Shared Object ID: a UUIDv7 in canonical lowercase string form
/// (SHARED-OBJECTS-PROFILE-01 §19).
///
/// Only parsing and validation are provided. The UUIDv7 timestamp is not an
/// LFCP ordering, so this type implements no ordering.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ObjectId(String);

impl ObjectId {
    /// Parse a canonical Object ID: lowercase hexadecimal, standard hyphen
    /// positions, version 7 and the RFC 9562 variant bits (`10`).
    pub fn parse(text: &str) -> Result<ObjectId, Error> {
        let bytes = text.as_bytes();
        if bytes.len() != 36 {
            return Err(Error::InvalidObjectId);
        }
        for (i, &c) in bytes.iter().enumerate() {
            let ok = match i {
                8 | 13 | 18 | 23 => c == b'-',
                _ => matches!(c, b'0'..=b'9' | b'a'..=b'f'),
            };
            if !ok {
                return Err(Error::InvalidObjectId);
            }
        }
        // Version nibble, then the two top variant bits.
        if bytes[14] != b'7' || !matches!(bytes[19], b'8' | b'9' | b'a' | b'b') {
            return Err(Error::InvalidObjectId);
        }
        Ok(ObjectId(text.to_owned()))
    }

    /// The canonical string form.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ObjectId({})", self.0)
    }
}

impl fmt::Display for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips_and_rejects_uppercase() {
        assert_eq!(to_hex(&[0x00, 0xab, 0xff]), "00abff");
        assert_eq!(from_hex("00abff").unwrap(), vec![0x00, 0xab, 0xff]);
        assert_eq!(from_hex(""), Ok(vec![]));
        assert_eq!(from_hex("00ABff"), Err(Error::InvalidHex));
        assert_eq!(from_hex("abc"), Err(Error::InvalidHex));
        assert_eq!(from_hex("0g"), Err(Error::InvalidHex));
    }

    #[test]
    fn b64url_matches_rfc4648_test_vectors() {
        // RFC 4648 §10, unpadded, in the URL-safe alphabet.
        let cases = [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy"),
        ];
        for (plain, encoded) in cases {
            assert_eq!(to_b64url(plain.as_bytes()), encoded);
            assert_eq!(from_b64url(encoded).unwrap(), plain.as_bytes());
        }
        assert_eq!(to_b64url(&[0xfb, 0xff]), "-_8");
    }

    #[test]
    fn b64url_rejects_non_canonical_forms() {
        // Padding, an impossible length, non-zero trailing bits, the
        // standard alphabet and whitespace.
        for bad in ["Zg==", "Z", "Zh", "Zm9vYh", "Zm+v", "Zm/v", "Zm9v YQ"] {
            assert_eq!(from_b64url(bad), Err(Error::InvalidBase64Url), "{bad}");
        }
    }

    #[test]
    fn b64url_round_trips_every_length() {
        for len in 0..64 {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            assert_eq!(from_b64url(&to_b64url(&bytes)).unwrap(), bytes);
        }
    }

    #[test]
    fn ids_check_length_and_print_hex() {
        let id = ResourceId::from_hex(&"ab".repeat(32)).unwrap();
        assert_eq!(id.as_bytes(), &[0xab; 32]);
        assert_eq!(
            format!("{id:?}"),
            format!("ResourceId({})", "ab".repeat(32))
        );
        assert_eq!(
            PrincipalId::from_slice(&[0; 31]),
            Err(Error::InvalidLength {
                expected: 32,
                actual: 31
            })
        );
    }

    #[test]
    fn frontier_order_is_raw_unsigned_bytes() {
        let low = PrincipalId::from_bytes([0x7f; 32]);
        let high = PrincipalId::from_bytes([0x80; 32]);
        assert_eq!(low.cmp_frontier_order(&high), Ordering::Less);
        assert_eq!(high.cmp_frontier_order(&low), Ordering::Greater);
    }

    #[test]
    fn object_id_accepts_only_canonical_uuidv7() {
        let good = "019a2f85-7b31-7c42-b85a-fc843e2f40ad";
        assert_eq!(ObjectId::parse(good).unwrap().as_str(), good);
        for bad in [
            "019A2F85-7B31-7C42-B85A-FC843E2F40AD", // uppercase
            "019a2f857b317c42b85afc843e2f40ad",     // no hyphens
            "019a2f85-7b31-4c42-b85a-fc843e2f40ad", // version 4
            "019a2f85-7b31-7c42-c85a-fc843e2f40ad", // variant 110
            "019a2f85-7b31-7c42-785a-fc843e2f40ad", // variant 0
            "019a2f85-7b31-7c42-b85a-fc843e2f40a",  // short
            "{019a2f85-7b31-7c42-b85a-fc843e2f40ad}",
        ] {
            assert_eq!(ObjectId::parse(bad), Err(Error::InvalidObjectId), "{bad}");
        }
    }
}
