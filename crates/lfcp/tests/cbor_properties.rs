//! Property tests for the deterministic CBOR codec.
//!
//! A small seeded PRNG (SplitMix64) drives the cases, so every run checks
//! the same inputs and a failure names the seed that reproduces it.

use lfcp::cbor::{self, Value};

/// SplitMix64: tiny, seedable and good enough to spread test inputs.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    /// Integers spread over every head size, edges included.
    fn int_arg(&mut self) -> u64 {
        match self.below(6) {
            0 => self.below(24),
            1 => self.below(0x100),
            2 => self.below(0x1_0000),
            3 => self.below(0x1_0000_0000),
            4 => self.next(),
            _ => [0, 23, 24, 0xff, 0x100, 0xffff, 0x1_0000, u64::MAX][self.below(8) as usize],
        }
    }

    fn bytes(&mut self) -> Vec<u8> {
        let len = self.below(40) as usize;
        (0..len).map(|_| self.next() as u8).collect()
    }

    fn text(&mut self) -> String {
        const PIECES: [&str; 6] = ["a", "Z", "0", "é", "ж", "🙂"];
        let len = self.below(12);
        (0..len).map(|_| PIECES[self.below(6) as usize]).collect()
    }

    fn key(&mut self) -> Value {
        match self.below(4) {
            0 => Value::Unsigned(self.int_arg()),
            1 => Value::Negative(self.int_arg()),
            2 => Value::Bytes(self.bytes()),
            _ => Value::Text(self.text()),
        }
    }

    fn value(&mut self, depth: u32) -> Value {
        let kinds = if depth == 0 { 7 } else { 9 };
        match self.below(kinds) {
            0 => Value::Unsigned(self.int_arg()),
            1 => Value::Negative(self.int_arg()),
            2 => Value::Bytes(self.bytes()),
            3 => Value::Text(self.text()),
            4 => Value::Bool(self.below(2) == 1),
            5 => Value::Null,
            6 => Value::Unsigned(self.below(24)),
            7 => {
                let len = self.below(5);
                Value::Array((0..len).map(|_| self.value(depth - 1)).collect())
            }
            _ => {
                let len = self.below(5);
                let mut entries: Vec<(Value, Value)> = Vec::new();
                for _ in 0..len {
                    let key = self.key();
                    if entries.iter().all(|(k, _)| *k != key) {
                        entries.push((key, self.value(depth - 1)));
                    }
                }
                Value::Map(entries)
            }
        }
    }
}

/// The decoder returns map entries in deterministic order; sort a generated
/// value the same way so it compares equal.
fn canonical(value: &Value) -> Value {
    cbor::decode_strict(&cbor::encode(value).unwrap()).unwrap()
}

const CASES: u64 = 2000;

#[test]
fn encoding_round_trips_and_is_deterministic() {
    for seed in 0..CASES {
        let mut rng = Rng(seed);
        let value = rng.value(4);
        let bytes = cbor::encode(&value).unwrap();
        let decoded = cbor::decode_strict(&bytes)
            .unwrap_or_else(|err| panic!("seed {seed}: decode_strict failed: {err}"));
        assert_eq!(cbor::encode(&decoded).unwrap(), bytes, "seed {seed}");
        assert!(cbor::is_deterministic(&bytes), "seed {seed}");
        // Map entry order does not change the encoding.
        if let Value::Map(mut entries) = value.clone() {
            entries.reverse();
            assert_eq!(
                cbor::encode(&Value::Map(entries)).unwrap(),
                bytes,
                "seed {seed}"
            );
        }
        assert_eq!(decoded, canonical(&value), "seed {seed}");
    }
}

/// The strict decoder and the N7 check are written independently: one
/// rejects non-deterministic forms while decoding, the other decodes
/// leniently and compares the re-encoding. On any input they must agree.
#[test]
fn strict_decoding_agrees_with_the_n7_check_on_mutated_input() {
    for seed in 0..CASES {
        let mut rng = Rng(seed);
        let mut bytes = cbor::encode(&rng.value(3)).unwrap();
        match rng.below(4) {
            // Flip one byte.
            0 if !bytes.is_empty() => {
                let i = rng.below(bytes.len() as u64) as usize;
                bytes[i] ^= 1 << rng.below(8);
            }
            // Replace one byte.
            1 if !bytes.is_empty() => {
                let i = rng.below(bytes.len() as u64) as usize;
                bytes[i] = rng.next() as u8;
            }
            // Truncate.
            2 => {
                let len = rng.below(bytes.len() as u64 + 1) as usize;
                bytes.truncate(len);
            }
            // Append a byte.
            _ => bytes.push(rng.next() as u8),
        }
        let strict = cbor::decode_strict(&bytes);
        let n7 = cbor::check_deterministic(&bytes);
        assert_eq!(
            strict.is_ok(),
            n7.is_ok(),
            "seed {seed}: {strict:?} vs {n7:?}"
        );
        if let Ok(value) = strict {
            assert_eq!(cbor::encode(&value).unwrap(), bytes, "seed {seed}");
        }
    }
}

/// Re-encoding a head in a longer form keeps the value but breaks
/// determinism; both decoders must notice.
#[test]
fn widened_integer_heads_are_rejected() {
    for seed in 0..CASES {
        let mut rng = Rng(seed);
        let n = rng.int_arg();
        let major = rng.below(2) as u8;
        let canonical = cbor::encode(&if major == 0 {
            Value::Unsigned(n)
        } else {
            Value::Negative(n)
        })
        .unwrap();
        // Widen to the 8-byte form unless it already is.
        if canonical[0] & 0x1f == 27 {
            continue;
        }
        let mut wide = vec![(major << 5) | 27];
        wide.extend_from_slice(&n.to_be_bytes());
        assert!(cbor::decode_strict(&wide).is_err(), "seed {seed}");
        assert_eq!(
            cbor::check_deterministic(&wide),
            Err(lfcp::base::Error::CborNotDeterministic),
            "seed {seed}"
        );
    }
}
