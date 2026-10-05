//! Deterministic CBOR codec (LFCP-WIRE-01 §5.2, with CB1–CB3 and N7).
//!
//! This module encodes and decodes exactly the CBOR data model LFCP uses:
//!
//! - integers from −2^64 to 2^64−1 (major types 0 and 1);
//! - byte strings and UTF-8 text strings;
//! - arrays, and maps whose keys are integers, text strings or byte strings;
//! - `false`, `true` and `null`.
//!
//! Anything else is rejected: tags, floats, `undefined`, other simple
//! values, indefinite lengths, non-shortest heads, duplicate or unsorted map
//! keys, invalid UTF-8, truncated input and trailing bytes. Map keys sort by
//! the length of their encoding first, then bytewise (RFC 8949 §4.2.3, as
//! §5.2 rule 4 requires), not by the plain bytewise order of RFC 8949
//! §4.2.1.
//!
//! The codec is written by hand so the security-critical byte handling
//! stays small and auditable. It never repairs input.
//!
//! - [`encode`] produces the deterministic encoding of a [`Value`].
//! - [`decode_strict`] accepts only deterministic encodings.
//! - [`check_deterministic`] is the §5.2 receiver check (N7) written as the
//!   specification states it: decode, re-encode, compare byte for byte.
//!   [`is_deterministic`] is its boolean form.

use crate::base::Error;

/// The deepest nesting of arrays and maps the codec accepts. LFCP
/// structures nest a few levels; the limit only bounds recursion on hostile
/// input.
pub const MAX_DEPTH: usize = 64;

/// A value in the LFCP CBOR data model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// An unsigned integer, major type 0.
    Unsigned(u64),
    /// A negative integer, major type 1, holding `n` for the value `-1 - n`.
    Negative(u64),
    /// A byte string.
    Bytes(Vec<u8>),
    /// A UTF-8 text string.
    Text(String),
    /// An array, in its given order.
    Array(Vec<Value>),
    /// A map. [`encode`] sorts the entries; [`decode_strict`] returns them
    /// in their (already deterministic) received order.
    Map(Vec<(Value, Value)>),
    /// `false` or `true`.
    Bool(bool),
    /// `null`.
    Null,
}

impl Value {
    /// An integer value.
    pub fn int(n: i64) -> Value {
        if n >= 0 {
            Value::Unsigned(n as u64)
        } else {
            // -1 - n, which is the bitwise complement in two's complement.
            Value::Negative(!n as u64)
        }
    }

    /// A byte string value.
    pub fn bytes(bytes: impl Into<Vec<u8>>) -> Value {
        Value::Bytes(bytes.into())
    }

    /// A text string value.
    pub fn text(text: impl Into<String>) -> Value {
        Value::Text(text.into())
    }

    /// The value as an unsigned integer, if it is one.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Unsigned(n) => Some(*n),
            _ => None,
        }
    }

    /// The value as a byte string, if it is one.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(bytes) => Some(bytes),
            _ => None,
        }
    }

    /// The value as a text string, if it is one.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(text) => Some(text),
            _ => None,
        }
    }

    /// The value as an array, if it is one.
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(items) => Some(items),
            _ => None,
        }
    }

    /// The value as map entries, if it is a map.
    pub fn as_map(&self) -> Option<&[(Value, Value)]> {
        match self {
            Value::Map(entries) => Some(entries),
            _ => None,
        }
    }

    /// The value stored under `key`, if this is a map that has it.
    pub fn get(&self, key: &Value) -> Option<&Value> {
        self.as_map()?
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }

    /// The value stored under the unsigned integer key `key`, if this is a
    /// map that has it. LFCP-owned maps use small unsigned keys.
    pub fn get_uint(&self, key: u64) -> Option<&Value> {
        self.get(&Value::Unsigned(key))
    }
}

// Major types.
const UNSIGNED: u8 = 0;
const NEGATIVE: u8 = 1;
const BYTES: u8 = 2;
const TEXT: u8 = 3;
const ARRAY: u8 = 4;
const MAP: u8 = 5;
const TAG: u8 = 6;
const SIMPLE: u8 = 7;

// Simple values in major type 7.
const FALSE: u8 = 20;
const TRUE: u8 = 21;
const NULL: u8 = 22;

/// Encode `value` deterministically (§5.2).
///
/// Fails if a map has a key that is not an integer, text string or byte
/// string, has two equal keys, or if nesting exceeds [`MAX_DEPTH`].
pub fn encode(value: &Value) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    encode_into(value, &mut out, 0)?;
    Ok(out)
}

fn encode_into(value: &Value, out: &mut Vec<u8>, depth: usize) -> Result<(), Error> {
    match value {
        Value::Unsigned(n) => write_head(out, UNSIGNED, *n),
        Value::Negative(n) => write_head(out, NEGATIVE, *n),
        Value::Bytes(bytes) => {
            write_head(out, BYTES, bytes.len() as u64);
            out.extend_from_slice(bytes);
        }
        Value::Text(text) => {
            write_head(out, TEXT, text.len() as u64);
            out.extend_from_slice(text.as_bytes());
        }
        Value::Array(items) => {
            let depth = nested(depth)?;
            write_head(out, ARRAY, items.len() as u64);
            for item in items {
                encode_into(item, out, depth)?;
            }
        }
        Value::Map(entries) => {
            let depth = nested(depth)?;
            let mut encoded = Vec::with_capacity(entries.len());
            for (key, value) in entries {
                check_key_type(key)?;
                let mut key_bytes = Vec::new();
                encode_into(key, &mut key_bytes, depth)?;
                let mut value_bytes = Vec::new();
                encode_into(value, &mut value_bytes, depth)?;
                encoded.push((key_bytes, value_bytes));
            }
            encoded.sort_by(|a, b| key_order(&a.0, &b.0));
            if encoded.windows(2).any(|pair| pair[0].0 == pair[1].0) {
                return Err(Error::CborDuplicateKey);
            }
            write_head(out, MAP, encoded.len() as u64);
            for (key, value) in encoded {
                out.extend_from_slice(&key);
                out.extend_from_slice(&value);
            }
        }
        Value::Bool(false) => out.push(SIMPLE << 5 | FALSE),
        Value::Bool(true) => out.push(SIMPLE << 5 | TRUE),
        Value::Null => out.push(SIMPLE << 5 | NULL),
    }
    Ok(())
}

/// Write a head with the shortest argument encoding.
fn write_head(out: &mut Vec<u8>, major: u8, n: u64) {
    let major = major << 5;
    if n < 24 {
        out.push(major | n as u8);
    } else if n <= 0xff {
        out.push(major | 24);
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(major | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= 0xffff_ffff {
        out.push(major | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(major | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

/// Deterministic key order: shorter encoding first, then bytewise.
fn key_order(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

fn check_key_type(key: &Value) -> Result<(), Error> {
    match key {
        Value::Unsigned(_) | Value::Negative(_) | Value::Text(_) | Value::Bytes(_) => Ok(()),
        _ => Err(Error::CborInvalidKeyType),
    }
}

fn nested(depth: usize) -> Result<usize, Error> {
    if depth >= MAX_DEPTH {
        Err(Error::CborDepthExceeded)
    } else {
        Ok(depth + 1)
    }
}

/// Decode `bytes`, accepting only the deterministic encoding of a single
/// value in the LFCP data model.
pub fn decode_strict(bytes: &[u8]) -> Result<Value, Error> {
    decode(bytes, Mode::Strict)
}

/// The §5.2 receiver check (N7): decode `bytes`, re-encode the decoded value
/// deterministically and compare the result with `bytes`.
///
/// Returns the decoded value when the bytes are deterministic. Bytes that
/// decode but differ from their re-encoding fail with
/// [`Error::CborNotDeterministic`]; bytes outside the data model fail with
/// the decoding error.
pub fn check_deterministic(bytes: &[u8]) -> Result<Value, Error> {
    let value = decode(bytes, Mode::Lenient)?;
    if encode(&value)? == bytes {
        Ok(value)
    } else {
        Err(Error::CborNotDeterministic)
    }
}

/// Whether `bytes` passes [`check_deterministic`].
pub fn is_deterministic(bytes: &[u8]) -> bool {
    check_deterministic(bytes).is_ok()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Reject every non-deterministic form.
    Strict,
    /// Accept non-shortest heads and unsorted map keys, so the value can be
    /// re-encoded and compared (N7). Everything outside the data model is
    /// still rejected, and so are duplicate keys, which make the decoded
    /// value ambiguous.
    Lenient,
}

fn decode(bytes: &[u8], mode: Mode) -> Result<Value, Error> {
    let mut decoder = Decoder {
        input: bytes,
        pos: 0,
        mode,
    };
    let value = decoder.item(0)?;
    if decoder.pos != bytes.len() {
        return Err(Error::CborTrailingBytes);
    }
    Ok(value)
}

struct Decoder<'a> {
    input: &'a [u8],
    pos: usize,
    mode: Mode,
}

impl<'a> Decoder<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let end = self
            .pos
            .checked_add(len)
            .filter(|&end| end <= self.input.len())
            .ok_or(Error::CborTruncated)?;
        let slice = &self.input[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn remaining(&self) -> usize {
        self.input.len() - self.pos
    }

    /// Read a head. Returns the major type and its argument; rejects every
    /// head this data model has no use for.
    fn head(&mut self) -> Result<(u8, u64), Error> {
        let initial = self.take(1)?[0];
        let major = initial >> 5;
        let info = initial & 0x1f;

        if major == TAG {
            return Err(Error::CborTag);
        }
        if major == SIMPLE {
            return match info {
                FALSE | TRUE | NULL => Ok((SIMPLE, u64::from(info))),
                // 23 is undefined, 24 a one-byte simple value.
                0..=19 | 23 | 24 => Err(Error::CborSimpleValue),
                25..=27 => Err(Error::CborFloat),
                // 28..=30 are reserved, 31 is a break outside any
                // indefinite-length item.
                _ => Err(Error::CborReserved),
            };
        }

        let n = match info {
            0..=23 => u64::from(info),
            24 => u64::from(self.take(1)?[0]),
            25 => u64::from(u16::from_be_bytes(self.take(2)?.try_into().unwrap())),
            26 => u64::from(u32::from_be_bytes(self.take(4)?.try_into().unwrap())),
            27 => u64::from_be_bytes(self.take(8)?.try_into().unwrap()),
            28..=30 => return Err(Error::CborReserved),
            _ => {
                return Err(match major {
                    BYTES | TEXT | ARRAY | MAP => Error::CborIndefiniteLength,
                    _ => Error::CborReserved,
                })
            }
        };
        let shortest = match info {
            24 => n >= 24,
            25 => n > 0xff,
            26 => n > 0xffff,
            27 => n > 0xffff_ffff,
            _ => true,
        };
        if !shortest && self.mode == Mode::Strict {
            return Err(Error::CborNonShortest);
        }
        Ok((major, n))
    }

    /// A length or count, which must fit in the remaining input: every byte
    /// is at least one byte long, and every array element or map entry
    /// takes at least `min_item_size` bytes.
    fn length(&self, n: u64, min_item_size: usize) -> Result<usize, Error> {
        usize::try_from(n)
            .ok()
            .filter(|&len| len.saturating_mul(min_item_size) <= self.remaining())
            .ok_or(Error::CborTruncated)
    }

    fn item(&mut self, depth: usize) -> Result<Value, Error> {
        let (major, n) = self.head()?;
        match major {
            UNSIGNED => Ok(Value::Unsigned(n)),
            NEGATIVE => Ok(Value::Negative(n)),
            BYTES => {
                let len = self.length(n, 1)?;
                Ok(Value::Bytes(self.take(len)?.to_vec()))
            }
            TEXT => {
                let len = self.length(n, 1)?;
                let text =
                    std::str::from_utf8(self.take(len)?).map_err(|_| Error::CborInvalidUtf8)?;
                Ok(Value::Text(text.to_owned()))
            }
            ARRAY => {
                let depth = nested(depth)?;
                let count = self.length(n, 1)?;
                let mut items = Vec::with_capacity(count);
                for _ in 0..count {
                    items.push(self.item(depth)?);
                }
                Ok(Value::Array(items))
            }
            MAP => {
                let depth = nested(depth)?;
                let count = self.length(n, 2)?;
                self.map(count, depth)
            }
            _ => Ok(match n as u8 {
                FALSE => Value::Bool(false),
                TRUE => Value::Bool(true),
                _ => Value::Null,
            }),
        }
    }

    fn map(&mut self, count: usize, depth: usize) -> Result<Value, Error> {
        let mut entries = Vec::with_capacity(count);
        // Deterministic encoding of each key, to check order and
        // uniqueness. In strict mode it equals the received key bytes.
        let mut keys: Vec<Vec<u8>> = Vec::with_capacity(count);
        for _ in 0..count {
            let key = self.item(depth)?;
            check_key_type(&key)?;
            let key_bytes = encode(&key)?;
            if self.mode == Mode::Strict {
                if let Some(previous) = keys.last() {
                    match key_order(previous, &key_bytes) {
                        std::cmp::Ordering::Less => {}
                        std::cmp::Ordering::Equal => return Err(Error::CborDuplicateKey),
                        std::cmp::Ordering::Greater => return Err(Error::CborUnsortedKeys),
                    }
                }
            }
            keys.push(key_bytes);
            let value = self.item(depth)?;
            entries.push((key, value));
        }
        if self.mode == Mode::Lenient {
            keys.sort_by(|a, b| key_order(a, b));
            if keys.windows(2).any(|pair| pair[0] == pair[1]) {
                return Err(Error::CborDuplicateKey);
            }
        }
        Ok(Value::Map(entries))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::{from_hex, to_hex};

    fn hex(text: &str) -> Vec<u8> {
        from_hex(text).unwrap()
    }

    fn round_trip(value: Value, expected_hex: &str) {
        let bytes = encode(&value).unwrap();
        assert_eq!(to_hex(&bytes), expected_hex, "{value:?}");
        assert_eq!(decode_strict(&bytes).unwrap(), value, "{expected_hex}");
        assert!(is_deterministic(&bytes), "{expected_hex}");
    }

    #[test]
    fn integers_use_the_shortest_head() {
        // RFC 8949 Appendix A, plus the edges of each head size.
        round_trip(Value::int(0), "00");
        round_trip(Value::int(23), "17");
        round_trip(Value::int(24), "1818");
        round_trip(Value::int(255), "18ff");
        round_trip(Value::int(256), "190100");
        round_trip(Value::int(65535), "19ffff");
        round_trip(Value::int(65536), "1a00010000");
        round_trip(Value::int(4294967295), "1affffffff");
        round_trip(Value::int(4294967296), "1b0000000100000000");
        round_trip(Value::Unsigned(u64::MAX), "1bffffffffffffffff");
        round_trip(Value::int(-1), "20");
        round_trip(Value::int(-8), "27");
        round_trip(Value::int(-24), "37");
        round_trip(Value::int(-25), "3818");
        round_trip(Value::int(-1000), "3903e7");
        round_trip(Value::int(i64::MIN), "3b7fffffffffffffff");
        // -2^64, the most negative CBOR integer.
        round_trip(Value::Negative(u64::MAX), "3bffffffffffffffff");
    }

    #[test]
    fn strings_arrays_and_simple_values() {
        round_trip(Value::bytes(vec![]), "40");
        round_trip(Value::bytes(vec![1, 2, 3, 4]), "4401020304");
        round_trip(Value::text(""), "60");
        round_trip(Value::text("IETF"), "6449455446");
        round_trip(Value::text("\u{00fc}"), "62c3bc");
        round_trip(Value::Array(vec![]), "80");
        round_trip(
            Value::Array(vec![
                Value::int(1),
                Value::Array(vec![Value::int(2), Value::int(3)]),
            ]),
            "8201820203",
        );
        round_trip(Value::Bool(false), "f4");
        round_trip(Value::Bool(true), "f5");
        round_trip(Value::Null, "f6");
        let long = Value::bytes(vec![0xaa; 24]);
        round_trip(long, &format!("5818{}", "aa".repeat(24)));
    }

    #[test]
    fn map_keys_sort_length_first_then_bytewise() {
        // Under plain bytewise order (RFC 8949 §4.2.1) "a" (0x6161) would
        // sort before 100 (0x1864); length-first puts 100 first.
        let map = Value::Map(vec![
            (Value::text("a"), Value::int(1)),
            (Value::int(100), Value::int(2)),
            (Value::int(-1), Value::int(3)),
            (Value::int(10), Value::int(4)),
            (Value::bytes(vec![0]), Value::int(5)),
        ]);
        let bytes = encode(&map).unwrap();
        assert_eq!(to_hex(&bytes), "a50a042003186402410005616101");
        let decoded = decode_strict(&bytes).unwrap();
        let keys: Vec<_> = decoded
            .as_map()
            .unwrap()
            .iter()
            .map(|(k, _)| k.clone())
            .collect();
        assert_eq!(
            keys,
            vec![
                Value::int(10),
                Value::int(-1),
                Value::int(100),
                Value::bytes(vec![0]),
                Value::text("a"),
            ]
        );
    }

    #[test]
    fn encode_rejects_bad_maps() {
        let duplicate = Value::Map(vec![
            (Value::int(1), Value::Null),
            (Value::int(1), Value::Null),
        ]);
        assert_eq!(encode(&duplicate), Err(Error::CborDuplicateKey));
        let array_key = Value::Map(vec![(Value::Array(vec![]), Value::Null)]);
        assert_eq!(encode(&array_key), Err(Error::CborInvalidKeyType));
        let bool_key = Value::Map(vec![(Value::Bool(true), Value::Null)]);
        assert_eq!(encode(&bool_key), Err(Error::CborInvalidKeyType));
    }

    #[test]
    fn decode_rejects_everything_outside_the_profile() {
        let cases = [
            // Tags, including tag 18 (COSE_Sign1).
            ("d28440a04040", Error::CborTag),
            ("c11a514b67b0", Error::CborTag),
            // Floats: half, single, double.
            ("f93c00", Error::CborFloat),
            ("fa47c35000", Error::CborFloat),
            ("fb3ff199999999999a", Error::CborFloat),
            // undefined, other simple values.
            ("f7", Error::CborSimpleValue),
            ("f0", Error::CborSimpleValue),
            ("f818", Error::CborSimpleValue),
            // Indefinite lengths.
            ("5f42010243030405ff", Error::CborIndefiniteLength),
            ("7f657374726561646d696e67ff", Error::CborIndefiniteLength),
            ("9f01ff", Error::CborIndefiniteLength),
            ("bf6161 01ff", Error::CborIndefiniteLength),
            // Reserved additional information, stray break.
            ("1c", Error::CborReserved),
            ("ff", Error::CborReserved),
            ("1f", Error::CborReserved),
            // Non-shortest heads: integer, length, count.
            ("1817", Error::CborNonShortest),
            ("1900ff", Error::CborNonShortest),
            ("1a0000ffff", Error::CborNonShortest),
            ("1b00000000ffffffff", Error::CborNonShortest),
            ("3817", Error::CborNonShortest),
            ("580100", Error::CborNonShortest),
            ("980100", Error::CborNonShortest),
            // Map keys: duplicate, unsorted, wrong type.
            ("a2010001 00", Error::CborDuplicateKey),
            ("a202000100", Error::CborUnsortedKeys),
            ("a2616100186400", Error::CborUnsortedKeys),
            ("a1800 0", Error::CborInvalidKeyType),
            ("a1f500", Error::CborInvalidKeyType),
            // Invalid UTF-8.
            ("62c328", Error::CborInvalidUtf8),
            // Truncation and trailing bytes.
            ("", Error::CborTruncated),
            ("19 01", Error::CborTruncated),
            ("4401", Error::CborTruncated),
            ("8201", Error::CborTruncated),
            ("5b ffffffffffffffff", Error::CborTruncated),
            ("9b ffffffffffffffff", Error::CborTruncated),
            ("0000", Error::CborTrailingBytes),
        ];
        for (input, expected) in cases {
            let input = input.replace(' ', "");
            assert_eq!(
                decode_strict(&hex(&input)),
                Err(expected.clone()),
                "{input}"
            );
            assert!(!is_deterministic(&hex(&input)), "{input}");
        }
    }

    #[test]
    fn n7_check_separates_decodable_from_deterministic() {
        // Non-shortest and unsorted forms decode but are not deterministic.
        for input in ["1817", "a202000100", "5801ff"] {
            assert_eq!(
                check_deterministic(&hex(input)),
                Err(Error::CborNotDeterministic),
                "{input}"
            );
        }
        // Duplicate keys are rejected even by the lenient decoder.
        assert_eq!(
            check_deterministic(&hex("a201000100")),
            Err(Error::CborDuplicateKey)
        );
    }

    #[test]
    fn nesting_is_bounded() {
        let mut deep = Value::Null;
        for _ in 0..MAX_DEPTH {
            deep = Value::Array(vec![deep]);
        }
        let bytes = encode(&deep).unwrap();
        assert_eq!(decode_strict(&bytes).unwrap(), deep);

        let deeper = Value::Array(vec![deep]);
        assert_eq!(encode(&deeper), Err(Error::CborDepthExceeded));
        let mut bytes = vec![0x81; MAX_DEPTH + 1];
        bytes.push(0xf6);
        assert_eq!(decode_strict(&bytes), Err(Error::CborDepthExceeded));
    }
}
