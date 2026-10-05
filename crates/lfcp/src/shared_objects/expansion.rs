//! Expansion limits of Automerge chunks (SHARED-OBJECTS-PROFILE-01 §11.1,
//! §13.1).
//!
//! Automerge's columnar format run-length encodes its columns, and a
//! Snapshot's columns may also be deflated, so a few bytes can declare
//! millions of operations or gigabytes of data. automerge 0.12 trusts the
//! run headers and inflates without a cap, all inside `Change::from_bytes`
//! and `AutoCommit::load`, and running out of memory aborts the process.
//! [`check_change`] and [`check_snapshot`] read a chunk's structure and the
//! run headers of every column, without decoding a value into a document,
//! and refuse a chunk over the limits with `PROFILE_INVALID` and
//! `INVALID_AUTOMERGE_BYTES` BEFORE the engine sees it.
//!
//! The counts (§11.1; sdk-ts counts the same way):
//! - a column's value count: an RLE run of `n` copies, a literal run of `n`
//!   values and a null run of `n` each add `n`; a boolean column adds each
//!   run length; a raw value column (type 7) adds nothing;
//! - the group sum: each group value once per row it occupies;
//! - expanded string bytes: each type-5 string's length once per row it
//!   occupies;
//! - a column that shares its id with a group column of the same section
//!   holds that group's entries: the group limit bounds its count, not the
//!   per-column limit;
//! - a number of 2^53 or more is above every limit; a LEB128 number longer
//!   than 10 bytes is invalid.
//!
//! The structural rules: one chunk of the right type with nothing after it;
//! no deflated change column; no two columns with one specification; every
//! actor-column value below the number of actors; and, in a change, no
//! group value above one plus the number of other actors (an operation's
//! predecessors have distinct actors).

use std::collections::HashSet;
use std::io::Read;

use crate::shared_objects::{Diagnostic, ProfileError};

/// Every rejection here: `PROFILE_INVALID` with `INVALID_AUTOMERGE_BYTES`.
const INVALID: ProfileError = ProfileError::Invalid(Diagnostic::InvalidAutomergeBytes);

/// The limits a chunk is checked against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Values in any one column, except a column holding a group's entries.
    pub max_rows: u64,
    /// The sum of the values of all group columns.
    pub max_group_sum: u64,
    /// Expanded string bytes.
    pub max_string_bytes: u64,
    /// Column data bytes after inflation (a Snapshot's; a change has no
    /// deflated column).
    pub max_inflated_bytes: u64,
    /// A change's dependencies, or a Snapshot's heads.
    pub max_deps: u64,
    /// A change's other actors, or a Snapshot's actors.
    pub max_actors: u64,
}

/// The exact limits of a change (§11.1): a writer never emits a change
/// above them and every receiver rejects one.
pub const CHANGE_LIMITS: Limits = Limits {
    max_rows: 16_384,
    max_group_sum: 262_144,
    max_string_bytes: 4 * 1024 * 1024,
    max_inflated_bytes: 0,
    max_deps: 1_024,
    max_actors: 1_024,
};

/// The floor of a Snapshot's limits (§13.1): every receiver accepts a
/// Snapshot within them, and MAY configure higher limits of its own.
pub const SNAPSHOT_LIMITS_FLOOR: Limits = Limits {
    max_rows: 262_144,
    max_group_sum: 262_144,
    max_string_bytes: 32 * 1024 * 1024,
    max_inflated_bytes: 32 * 1024 * 1024,
    max_deps: 1_024,
    max_actors: 1_024,
};

/// What a chunk within the limits expands to.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Expansion {
    /// The largest value count of any column.
    pub max_rows: u64,
    /// The sum of all group columns.
    pub group_sum: u64,
    /// Expanded string bytes.
    pub string_bytes: u64,
    /// Column data bytes, after inflation.
    pub column_bytes: u64,
    /// Each column's specification and value count, in chunk order.
    pub columns: Vec<(u32, u64)>,
}

impl Expansion {
    /// A change's operation count: the value count of its action column
    /// (column 4, type 2).
    pub fn ops(&self) -> u64 {
        self.columns
            .iter()
            .find(|(spec, _)| *spec == ACTION)
            .map_or(0, |(_, rows)| *rows)
    }
}

const MAGIC: [u8; 4] = [0x85, 0x6f, 0x4a, 0x83];
const DOCUMENT_CHUNK: u8 = 0;
const CHANGE_CHUNK: u8 = 1;
const DEFLATE: u32 = 0b1000;
const ACTION: u32 = 4 << 4 | 2;
const TYPE_GROUP: u32 = 0;
const TYPE_ACTOR: u32 = 1;
const TYPE_DELTA: u32 = 3;
const TYPE_BOOLEAN: u32 = 4;
const TYPE_STRING: u32 = 5;
const TYPE_RAW: u32 = 7;
/// Numbers from here on are above every limit (§11.1).
const HUGE: u64 = 1 << 53;

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Cursor { bytes, at: 0 }
    }

    fn done(&self) -> bool {
        self.at >= self.bytes.len()
    }

    fn rest(&self) -> usize {
        self.bytes.len() - self.at
    }

    /// `n` bytes; a length of [`HUGE`] or more never fits.
    fn take(&mut self, n: u64) -> Result<&'a [u8], ProfileError> {
        let n = usize::try_from(n).map_err(|_| INVALID)?;
        if n > self.rest() {
            return Err(INVALID);
        }
        let out = &self.bytes[self.at..self.at + n];
        self.at += n;
        Ok(out)
    }

    fn byte(&mut self) -> Result<u8, ProfileError> {
        Ok(self.take(1)?[0])
    }

    /// Unsigned LEB128 of at most 10 bytes; [`HUGE`] or more saturates to
    /// `u64::MAX`, above every limit.
    fn uleb(&mut self) -> Result<u64, ProfileError> {
        let mut value: u128 = 0;
        for i in 0..10 {
            let byte = self.byte()?;
            value |= u128::from(byte & 0x7f) << (7 * i);
            if byte & 0x80 == 0 {
                return Ok(if value >= u128::from(HUGE) {
                    u64::MAX
                } else {
                    value as u64
                });
            }
        }
        Err(INVALID)
    }

    /// Signed LEB128 of at most 10 bytes; a magnitude of [`HUGE`] or more
    /// saturates to `i64::MIN` or `i64::MAX`.
    fn sleb(&mut self) -> Result<i64, ProfileError> {
        let mut value: i128 = 0;
        let mut scale: i128 = 1;
        for _ in 0..10 {
            let byte = self.byte()?;
            value += i128::from(byte & 0x7f) * scale;
            scale *= 128;
            if byte & 0x80 == 0 {
                if byte & 0x40 != 0 {
                    value -= scale;
                }
                return Ok(if value >= i128::from(HUGE) {
                    i64::MAX
                } else if value <= -i128::from(HUGE) {
                    i64::MIN
                } else {
                    value as i64
                });
            }
        }
        Err(INVALID)
    }

    /// A list of `count` items (ULEB128 count first), each `fixed` bytes or
    /// ULEB128 length-prefixed; more than `limit` items is refused.
    fn list(&mut self, limit: u64, fixed: Option<u64>) -> Result<u64, ProfileError> {
        let count = self.uleb()?;
        if count > limit {
            return Err(INVALID);
        }
        for _ in 0..count {
            let len = match fixed {
                Some(n) => n,
                None => self.uleb()?,
            };
            self.take(len)?;
        }
        Ok(count)
    }
}

/// The running totals of one chunk.
struct Tally {
    limits: Limits,
    out: Expansion,
}

impl Tally {
    fn new(limits: Limits) -> Self {
        Tally {
            limits,
            out: Expansion::default(),
        }
    }

    fn group(&mut self, add: u64) -> Result<(), ProfileError> {
        self.out.group_sum = self.out.group_sum.saturating_add(add);
        if self.out.group_sum > self.limits.max_group_sum {
            return Err(INVALID);
        }
        Ok(())
    }

    fn strings(&mut self, add: u64) -> Result<(), ProfileError> {
        self.out.string_bytes = self.out.string_bytes.saturating_add(add);
        if self.out.string_bytes > self.limits.max_string_bytes {
            return Err(INVALID);
        }
        Ok(())
    }
}

/// What one column's values may be.
struct Bounds {
    /// Actor indices are below this.
    actors: u64,
    /// Group values are at most this.
    group: u64,
    /// The column holds at most this many values.
    rows: u64,
}

/// Count one column's values (and group sum and string bytes) from its run
/// headers, without expanding a run.
fn count_column(
    kind: u32,
    data: &[u8],
    tally: &mut Tally,
    bounds: &Bounds,
) -> Result<u64, ProfileError> {
    if kind == TYPE_RAW {
        return Ok(0);
    }
    let mut c = Cursor::new(data);
    let mut rows = 0u64;
    let mut add = |n: u64| -> Result<(), ProfileError> {
        rows = rows.saturating_add(n);
        if rows > bounds.rows {
            return Err(INVALID);
        }
        Ok(())
    };
    if kind == TYPE_BOOLEAN {
        while !c.done() {
            add(c.uleb()?)?;
        }
        return Ok(rows);
    }
    // One value of an RLE column: a group count, a string length, an actor
    // index, or a number that is only skipped.
    let value = |c: &mut Cursor<'_>| -> Result<u64, ProfileError> {
        match kind {
            TYPE_STRING => {
                let len = c.uleb()?;
                c.take(len)?;
                Ok(len)
            }
            TYPE_DELTA => c.sleb().map(|_| 0),
            _ => c.uleb(),
        }
    };
    let account = |tally: &mut Tally, v: u64, times: u64| -> Result<(), ProfileError> {
        match kind {
            TYPE_GROUP => {
                if v > bounds.group {
                    return Err(INVALID);
                }
                tally.group(v.saturating_mul(times))
            }
            TYPE_STRING => tally.strings(v.saturating_mul(times)),
            TYPE_ACTOR if v >= bounds.actors => Err(INVALID),
            _ => Ok(()),
        }
    };
    while !c.done() {
        match c.sleb()? {
            n if n > 0 => {
                let n = n as u64;
                add(n)?;
                let v = value(&mut c)?;
                account(tally, v, n)?;
            }
            n if n < 0 => {
                let n = n.unsigned_abs();
                // Refused before an oversized literal run is read.
                add(n)?;
                for _ in 0..n {
                    let v = value(&mut c)?;
                    account(tally, v, 1)?;
                }
            }
            _ => add(c.uleb()?)?,
        }
    }
    Ok(rows)
}

/// Column metadata: a ULEB128 count, then a ULEB128 specification and a
/// ULEB128 data length per column; two columns with one specification are
/// refused (§11.1 rule 7).
fn column_metas(c: &mut Cursor<'_>) -> Result<Vec<(u32, u64)>, ProfileError> {
    let count = c.uleb()?;
    // Each column takes at least two bytes of metadata.
    if count > (c.rest() / 2) as u64 {
        return Err(INVALID);
    }
    let mut specs = HashSet::new();
    let mut out = Vec::new();
    for _ in 0..count {
        let spec = u32::try_from(c.uleb()?).map_err(|_| INVALID)?;
        if !specs.insert(spec) {
            return Err(INVALID);
        }
        out.push((spec, c.uleb()?));
    }
    Ok(out)
}

/// Each column's value limit: a non-group column sharing its id with a
/// group column holds that group's entries, bounded by the group limit.
fn row_limit(metas: &[(u32, u64)], limits: &Limits) -> impl Fn(u32) -> u64 {
    let grouped: HashSet<u32> = metas
        .iter()
        .filter(|(spec, _)| spec & 7 == TYPE_GROUP)
        .map(|(spec, _)| spec >> 4)
        .collect();
    let limits = *limits;
    move |spec| {
        if spec & 7 != TYPE_GROUP && grouped.contains(&(spec >> 4)) {
            limits.max_group_sum
        } else {
            limits.max_rows
        }
    }
}

/// The body of the chunk `bytes`: magic, checksum, the wanted type and a
/// length equal to the rest of the input.
fn body(bytes: &[u8], want: u8) -> Result<Cursor<'_>, ProfileError> {
    let mut c = Cursor::new(bytes);
    if c.take(4)? != MAGIC {
        return Err(INVALID);
    }
    c.take(4)?; // the checksum, checked against the hash after decoding
    if c.byte()? != want {
        return Err(INVALID);
    }
    if c.uleb()? != c.rest() as u64 {
        return Err(INVALID);
    }
    Ok(c)
}

/// §11.1: check an uncompressed change chunk against the exact change
/// limits before the engine sees it.
pub fn check_change(bytes: &[u8]) -> Result<Expansion, ProfileError> {
    let limits = CHANGE_LIMITS;
    let mut c = body(bytes, CHANGE_CHUNK)?;
    c.list(limits.max_deps, Some(32))?; // dependencies
    let actor = c.uleb()?;
    c.take(actor)?;
    c.uleb()?; // sequence number
    c.uleb()?; // start op
    c.sleb()?; // time
    let message = c.uleb()?;
    c.take(message)?;
    let others = c.list(limits.max_actors, None)?;
    let metas = column_metas(&mut c)?;
    let limit_of = row_limit(&metas, &limits);
    let mut tally = Tally::new(limits);
    for (spec, len) in metas {
        if spec & DEFLATE != 0 {
            return Err(INVALID);
        }
        let data = c.take(len)?;
        let bounds = Bounds {
            actors: 1 + others,
            group: 1 + others,
            rows: limit_of(spec),
        };
        let rows = count_column(spec & 7, data, &mut tally, &bounds)?;
        tally.out.max_rows = tally.out.max_rows.max(rows);
        tally.out.column_bytes += len;
        tally.out.columns.push((spec, rows));
    }
    // The rest of the chunk is the change's extra bytes: kept, not counted.
    Ok(tally.out)
}

/// Inflate raw DEFLATE `data`, refusing as soon as the output passes
/// `budget` bytes: never more than the budget is held.
fn inflate_capped(data: &[u8], budget: u64) -> Result<Vec<u8>, ProfileError> {
    let mut out = Vec::new();
    flate2::read::DeflateDecoder::new(data)
        .take(budget.saturating_add(1))
        .read_to_end(&mut out)
        .map_err(|_| INVALID)?;
    if out.len() as u64 > budget {
        return Err(INVALID);
    }
    Ok(out)
}

/// §13.1: check a Snapshot's save, exactly one document chunk, against
/// `limits` (at least [`SNAPSHOT_LIMITS_FLOOR`]) before the engine loads
/// it, inflating deflated columns under a running cap.
pub fn check_snapshot(bytes: &[u8], limits: &Limits) -> Result<Expansion, ProfileError> {
    let mut c = body(bytes, DOCUMENT_CHUNK)?;
    let actors = c.list(limits.max_actors, None)?;
    c.list(limits.max_deps, Some(32))?; // heads
    let change_metas = column_metas(&mut c)?;
    let op_metas = column_metas(&mut c)?;
    // The grouped-column rule applies per section.
    let change_limit = row_limit(&change_metas, limits);
    let op_limit = row_limit(&op_metas, limits);
    let mut tally = Tally::new(*limits);
    let mut inflated = 0u64;
    let sections = [(change_metas, &change_limit), (op_metas, &op_limit)];
    for (metas, limit_of) in sections.iter() {
        for &(spec, len) in metas {
            let raw = c.take(len)?;
            let owned;
            let data = if spec & DEFLATE != 0 {
                owned = inflate_capped(raw, limits.max_inflated_bytes - inflated)?;
                &owned[..]
            } else {
                raw
            };
            inflated += data.len() as u64;
            if inflated > limits.max_inflated_bytes {
                return Err(INVALID);
            }
            let bounds = Bounds {
                actors,
                group: u64::MAX,
                rows: limit_of(spec),
            };
            let rows = count_column(spec & 7, data, &mut tally, &bounds)?;
            tally.out.max_rows = tally.out.max_rows.max(rows);
            tally.out.columns.push((spec, rows));
        }
    }
    tally.out.column_bytes = inflated;
    // The rest is the document's head indices: not counted.
    Ok(tally.out)
}
