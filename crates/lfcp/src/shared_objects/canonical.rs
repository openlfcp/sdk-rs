//! Canonical change encoding (SHARED-OBJECTS-PROFILE-01 §11.3).
//!
//! An Automerge engine does not keep a change's bytes: it keeps the
//! operations and writes the change again when it saves or hands changes
//! out. A change whose bytes differ from that writing is applied, but the
//! document then fails to save and load ("mismatching heads"). §11.3 makes
//! "canonical" a property of the format, not of an engine version: the
//! bytes are the one encoding of the change's content that the rules below
//! allow. [`check`] reads the content without the engine, checks the rules
//! on it, encodes it the one allowed way and compares the bytes.
//!
//! The rules (N is the row count of the action column, 0 when absent):
//! - every LEB128 number has its shortest encoding;
//! - the dependencies are strictly ascending; the sequence number and
//!   start op are at least 1; the message is UTF-8; the other actors are
//!   strictly ascending, none is the change's actor, and they are exactly
//!   the other actors the operations refer to;
//! - only the columns of [`COLUMNS`], in ascending order, each once, none
//!   empty and none deflated, each present exactly when its rule says;
//! - every present operation column has N rows, the predecessor actor and
//!   counter columns the sum of the predecessor counts, and the value bytes
//!   are exactly the lengths the value metadata gives;
//! - run-length columns use maximal runs: one null run per run of nulls, a
//!   repetition run for two or more equal values, a literal run for the
//!   single values between; boolean columns alternate from false and only
//!   their first run may be empty;
//! - values are in their shortest form (integers), 8 bytes (floats) or
//!   UTF-8 (strings); value types 10-15 are refused; make and delete carry
//!   null, increment an integer; actions above 7 are refused; a mark name,
//!   expand or a mark's insert only on a mark (action 7);
//! - objects are the root or an operation ID; keys a property, the head or
//!   an element's operation ID; every counter is below 2^32;
//! - each operation's predecessors are strictly ascending by counter, then
//!   actor ID.
//!
//! [`check`] runs after the §11.1 limits, so every column is small.

use crate::shared_objects::{Diagnostic, ProfileError};

const INVALID: ProfileError = ProfileError::Invalid(Diagnostic::InvalidAutomergeBytes);

/// Counters are below this (§11.3; automerge keeps them in 32 bits).
pub const COUNTER_LIMIT: u64 = 1 << 32;

const MAGIC: [u8; 4] = [0x85, 0x6f, 0x4a, 0x83];
const CHANGE_CHUNK: u8 = 1;

const OBJ_ACTOR: u32 = 0x01;
const OBJ_CTR: u32 = 0x02;
const KEY_ACTOR: u32 = 0x11;
const KEY_CTR: u32 = 0x13;
const KEY_STR: u32 = 0x15;
const INSERT: u32 = 0x34;
const ACTION: u32 = 0x42;
const VALUE_META: u32 = 0x56;
const VALUE: u32 = 0x57;
const PRED_GROUP: u32 = 0x70;
const PRED_ACTOR: u32 = 0x71;
const PRED_CTR: u32 = 0x73;
const EXPAND: u32 = 0x94;
const MARK_NAME: u32 = 0xa5;

/// The change columns, in their order (§11.3).
pub const COLUMNS: [u32; 14] = [
    OBJ_ACTOR, OBJ_CTR, KEY_ACTOR, KEY_CTR, KEY_STR, INSERT, ACTION, VALUE_META, VALUE, PRED_GROUP,
    PRED_ACTOR, PRED_CTR, EXPAND, MARK_NAME,
];

/// An operation ID inside a change: (actor index, counter); index 0 is the
/// change's actor, `i` its `i`-th other actor.
pub type LocalId = (u64, u64);

/// An operation's key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Key {
    /// A map property.
    Prop(String),
    /// The head of a sequence.
    Head,
    /// A sequence element: the ID of the operation that inserted it.
    Elem(LocalId),
}

/// One operation of a change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Op {
    /// `None` is the root.
    pub obj: Option<LocalId>,
    /// The key written.
    pub key: Key,
    /// Whether the operation inserts a sequence element.
    pub insert: bool,
    /// The action code.
    pub action: u64,
    /// The value's type code and bytes.
    pub value: (u8, Vec<u8>),
    /// The operations this one overwrites.
    pub preds: Vec<LocalId>,
    /// A mark's expand flag.
    pub expand: bool,
    /// A mark's name.
    pub mark_name: Option<String>,
}

/// The content of a change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Content {
    /// The dependencies.
    pub deps: Vec<[u8; 32]>,
    /// The change's actor.
    pub actor: Vec<u8>,
    /// The sequence number.
    pub seq: u64,
    /// The first operation's counter.
    pub start_op: u64,
    /// The time.
    pub time: i64,
    /// The message (empty when none).
    pub message: String,
    /// The other actors.
    pub others: Vec<Vec<u8>>,
    /// The operations, in counter order.
    pub ops: Vec<Op>,
    /// The bytes after the columns.
    pub extra: Vec<u8>,
}

impl Content {
    /// The actor bytes of actor index `i`.
    pub fn actor_of(&self, i: u64) -> &[u8] {
        if i == 0 {
            &self.actor
        } else {
            &self.others[(i - 1) as usize]
        }
    }
}

/// §11.3: the content of the change chunk `bytes`, if they are its
/// canonical encoding; otherwise `INVALID_AUTOMERGE_BYTES`. Call after the
/// §11.1 check.
pub fn check(bytes: &[u8]) -> Result<Content, ProfileError> {
    let content = parse(bytes)?;
    rules(&content).map_err(|_| INVALID)?;
    if encode(&content) != bytes {
        return Err(INVALID);
    }
    Ok(content)
}

// ---- reading -------------------------------------------------------------

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Reader { bytes, at: 0 }
    }

    fn done(&self) -> bool {
        self.at >= self.bytes.len()
    }

    fn take(&mut self, n: u64) -> Result<&'a [u8], ProfileError> {
        let n = usize::try_from(n).map_err(|_| INVALID)?;
        if n > self.bytes.len() - self.at {
            return Err(INVALID);
        }
        let out = &self.bytes[self.at..self.at + n];
        self.at += n;
        Ok(out)
    }

    fn rest(&mut self) -> &'a [u8] {
        let out = &self.bytes[self.at..];
        self.at = self.bytes.len();
        out
    }

    /// Unsigned LEB128 that fits in 64 bits. Its length is not checked
    /// here: a longer than shortest form fails the comparison of [`check`].
    fn uleb(&mut self) -> Result<u64, ProfileError> {
        let mut value: u64 = 0;
        for i in 0..10 {
            let byte = self.take(1)?[0];
            let part = u64::from(byte & 0x7f);
            if i == 9 && part > 1 {
                return Err(INVALID);
            }
            value |= part << (7 * i);
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(INVALID)
    }

    /// Signed LEB128 that fits in 64 bits.
    fn sleb(&mut self) -> Result<i64, ProfileError> {
        let mut value: i128 = 0;
        let mut shift = 0;
        for _ in 0..10 {
            let byte = self.take(1)?[0];
            value |= i128::from(byte & 0x7f) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                if byte & 0x40 != 0 {
                    value -= 1i128 << shift;
                }
                return i64::try_from(value).map_err(|_| INVALID);
            }
        }
        Err(INVALID)
    }
}

/// The rows of a run-length column, each read by `value`.
fn rle<T: Clone>(
    data: &[u8],
    mut value: impl FnMut(&mut Reader<'_>) -> Result<T, ProfileError>,
) -> Result<Vec<Option<T>>, ProfileError> {
    let mut r = Reader::new(data);
    let mut out = Vec::new();
    while !r.done() {
        let n = r.sleb()?;
        if n > 0 {
            let v = value(&mut r)?;
            out.extend(std::iter::repeat_n(Some(v), n as usize));
        } else if n < 0 {
            for _ in 0..n.unsigned_abs() {
                out.push(Some(value(&mut r)?));
            }
        } else {
            let nulls = r.uleb()?;
            out.extend(std::iter::repeat_n(None, nulls as usize));
        }
    }
    Ok(out)
}

fn uleb_col(data: &[u8]) -> Result<Vec<Option<u64>>, ProfileError> {
    rle(data, |r| r.uleb())
}

fn string_col(data: &[u8]) -> Result<Vec<Option<String>>, ProfileError> {
    rle(data, |r| {
        let len = r.uleb()?;
        String::from_utf8(r.take(len)?.to_vec()).map_err(|_| INVALID)
    })
}

/// A delta column's values: running sums of the differences, nulls
/// leaving the running value as it is.
fn delta_col(data: &[u8]) -> Result<Vec<Option<i64>>, ProfileError> {
    let mut running = 0i64;
    rle(data, |r| r.sleb())?
        .into_iter()
        .map(|d| match d {
            Some(d) => {
                running = running.checked_add(d).ok_or(INVALID)?;
                Ok(Some(running))
            }
            None => Ok(None),
        })
        .collect()
}

fn bool_col(data: &[u8]) -> Result<Vec<bool>, ProfileError> {
    let mut r = Reader::new(data);
    let mut out = Vec::new();
    let mut value = false;
    while !r.done() {
        let n = r.uleb()?;
        out.extend(std::iter::repeat_n(value, n as usize));
        value = !value;
    }
    Ok(out)
}

/// A column's rows, or `n` copies of `fill` when it is absent; any other
/// count is refused.
fn rows<T: Clone>(col: Option<Vec<T>>, n: usize, fill: T) -> Result<Vec<T>, ProfileError> {
    match col {
        Some(v) if v.len() == n => Ok(v),
        Some(_) => Err(INVALID),
        None => Ok(vec![fill; n]),
    }
}

fn parse(bytes: &[u8]) -> Result<Content, ProfileError> {
    let mut r = Reader::new(bytes);
    if r.take(4)? != MAGIC {
        return Err(INVALID);
    }
    r.take(4)?; // checksum: compared with the hash by the framing
    if r.take(1)?[0] != CHANGE_CHUNK {
        return Err(INVALID);
    }
    let len = r.uleb()?;
    if len != (bytes.len() - r.at) as u64 {
        return Err(INVALID);
    }
    let deps = (0..r.uleb()?)
        .map(|_| Ok(r.take(32)?.try_into().expect("32 bytes")))
        .collect::<Result<Vec<[u8; 32]>, ProfileError>>()?;
    let n = r.uleb()?;
    let actor = r.take(n)?.to_vec();
    let seq = r.uleb()?;
    let start_op = r.uleb()?;
    let time = r.sleb()?;
    let n = r.uleb()?;
    let message = String::from_utf8(r.take(n)?.to_vec()).map_err(|_| INVALID)?;
    let others = (0..r.uleb()?)
        .map(|_| {
            let n = r.uleb()?;
            Ok(r.take(n)?.to_vec())
        })
        .collect::<Result<Vec<_>, ProfileError>>()?;
    let metas = (0..r.uleb()?)
        .map(|_| {
            let spec = u32::try_from(r.uleb()?).map_err(|_| INVALID)?;
            Ok((spec, r.uleb()?))
        })
        .collect::<Result<Vec<_>, ProfileError>>()?;
    let mut cols: std::collections::HashMap<u32, &[u8]> = std::collections::HashMap::new();
    for (spec, len) in metas {
        if !COLUMNS.contains(&spec) || cols.insert(spec, r.take(len)?).is_some() {
            return Err(INVALID);
        }
    }
    let extra = r.rest().to_vec();
    let col = |spec| cols.get(&spec).copied();

    let action = col(ACTION).map(uleb_col).transpose()?.unwrap_or_default();
    let n = action.len();
    let action = action
        .into_iter()
        .map(|a| a.ok_or(INVALID))
        .collect::<Result<Vec<u64>, _>>()?;
    let obj_actor = rows(col(OBJ_ACTOR).map(uleb_col).transpose()?, n, None)?;
    let obj_ctr = rows(col(OBJ_CTR).map(uleb_col).transpose()?, n, None)?;
    let key_actor = rows(col(KEY_ACTOR).map(uleb_col).transpose()?, n, None)?;
    let key_ctr = rows(col(KEY_CTR).map(delta_col).transpose()?, n, None)?;
    let key_str = rows(col(KEY_STR).map(string_col).transpose()?, n, None)?;
    let insert = rows(col(INSERT).map(bool_col).transpose()?, n, false)?;
    let meta = rows(col(VALUE_META).map(uleb_col).transpose()?, n, Some(0))?;
    let group = rows(col(PRED_GROUP).map(uleb_col).transpose()?, n, Some(0))?;
    let expand = rows(col(EXPAND).map(bool_col).transpose()?, n, false)?;
    let mark = rows(col(MARK_NAME).map(string_col).transpose()?, n, None)?;
    let entries = group.iter().try_fold(0u64, |sum, g| {
        sum.checked_add(g.ok_or(INVALID)?).ok_or(INVALID)
    })?;
    let entries = usize::try_from(entries).map_err(|_| INVALID)?;
    let pred_actor = rows(col(PRED_ACTOR).map(uleb_col).transpose()?, entries, None)?;
    let pred_ctr = rows(col(PRED_CTR).map(delta_col).transpose()?, entries, None)?;
    let mut values = Reader::new(col(VALUE).unwrap_or_default());

    let mut ops = Vec::with_capacity(n);
    let mut entry = 0usize;
    for i in 0..n {
        let obj = match (obj_actor[i], obj_ctr[i]) {
            (None, None) => None,
            (Some(a), Some(c)) if c >= 1 => Some((a, c)),
            _ => return Err(INVALID),
        };
        let key = match (key_actor[i], key_ctr[i], &key_str[i]) {
            (None, None, Some(s)) => Key::Prop(s.clone()),
            (None, Some(0), None) => Key::Head,
            (Some(a), Some(c), None) if c >= 1 => Key::Elem((a, c as u64)),
            _ => return Err(INVALID),
        };
        let m = meta[i].ok_or(INVALID)?;
        let value = ((m & 0x0f) as u8, values.take(m >> 4)?.to_vec());
        let count = group[i].ok_or(INVALID)? as usize;
        let mut preds = Vec::with_capacity(count);
        for _ in 0..count {
            match (pred_actor[entry], pred_ctr[entry]) {
                (Some(a), Some(c)) if c >= 1 => preds.push((a, c as u64)),
                _ => return Err(INVALID),
            }
            entry += 1;
        }
        ops.push(Op {
            obj,
            key,
            insert: insert[i],
            action: action[i],
            value,
            preds,
            expand: expand[i],
            mark_name: mark[i].clone(),
        });
    }
    if !values.done() {
        return Err(INVALID);
    }
    Ok(Content {
        deps,
        actor,
        seq,
        start_op,
        time,
        message,
        others,
        ops,
        extra,
    })
}

// ---- rules ---------------------------------------------------------------

/// The value type codes.
const NULL: u8 = 0;
const FALSE: u8 = 1;
const TRUE: u8 = 2;
const UINT: u8 = 3;
const INT: u8 = 4;
const FLOAT: u8 = 5;
const STRING: u8 = 6;
const BYTES: u8 = 7;
const COUNTER: u8 = 8;
const TIMESTAMP: u8 = 9;

const MARK: u64 = 7;

fn value_ok((kind, bytes): &(u8, Vec<u8>)) -> bool {
    match *kind {
        NULL | FALSE | TRUE => bytes.is_empty(),
        UINT => {
            let mut r = Reader::new(bytes);
            r.uleb().is_ok_and(|v| r.done() && uleb(v) == *bytes)
        }
        INT | COUNTER | TIMESTAMP => {
            let mut r = Reader::new(bytes);
            r.sleb().is_ok_and(|v| r.done() && sleb(v) == *bytes)
        }
        FLOAT => bytes.len() == 8,
        STRING => std::str::from_utf8(bytes).is_ok(),
        BYTES => true,
        _ => false,
    }
}

/// The first rule `c` breaks, by name.
fn rules(c: &Content) -> Result<(), &'static str> {
    let ok = |b: bool, rule: &'static str| if b { Ok(()) } else { Err(rule) };
    ok(c.deps.windows(2).all(|w| w[0] < w[1]), "deps ascending")?;
    ok(c.seq >= 1 && c.start_op >= 1, "seq and start op")?;
    ok(
        c.others.windows(2).all(|w| w[0] < w[1]),
        "other actors ascending",
    )?;
    ok(
        c.others.iter().all(|o| *o != c.actor),
        "other actor is the actor",
    )?;
    let n = c.ops.len() as u64;
    ok(
        c.start_op
            .checked_add(n)
            .is_some_and(|end| end - 1 < COUNTER_LIMIT),
        "operation counter",
    )?;
    let actors = 1 + c.others.len() as u64;
    let mut used = vec![false; c.others.len() + 1];
    let mut refer = |(a, ctr): LocalId| -> Result<(), &'static str> {
        ok(a < actors, "actor index")?;
        ok(ctr < COUNTER_LIMIT, "referenced counter")?;
        used[a as usize] = true;
        Ok(())
    };
    for op in &c.ops {
        if let Some(id) = op.obj {
            refer(id)?;
        }
        if let Key::Elem(id) = op.key {
            refer(id)?;
        }
        for &p in &op.preds {
            refer(p)?;
        }
        ok(
            op.preds
                .windows(2)
                .all(|w| (w[0].1, c.actor_of(w[0].0)) < (w[1].1, c.actor_of(w[1].0))),
            "preds ascending",
        )?;
        ok(value_ok(&op.value), "value form")?;
        let mark = op.action == MARK;
        ok(
            match op.action {
                0 | 2 | 3 | 4 | 6 => op.value.0 == NULL,
                5 => matches!(op.value.0, UINT | INT),
                1 => true,
                MARK => op.insert,
                _ => false,
            },
            "action and value",
        )?;
        ok(
            mark || (op.mark_name.is_none() && !op.expand),
            "mark fields",
        )?;
    }
    ok(used[1..].iter().all(|u| *u), "unreferenced other actor")
}

// ---- writing -------------------------------------------------------------

fn uleb(mut v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

fn sleb(mut v: i64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if (v == 0 && byte & 0x40 == 0) || (v == -1 && byte & 0x40 != 0) {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

/// The one run-length encoding §11.3 allows: maximal null runs, a
/// repetition run for two or more equal values, one literal run for the
/// single values between.
fn rle_encode<T: PartialEq>(rows: &[Option<T>], value: impl Fn(&T) -> Vec<u8>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut literal: Vec<&T> = Vec::new();
    let flush = |out: &mut Vec<u8>, literal: &mut Vec<&T>| {
        if !literal.is_empty() {
            out.extend(sleb(-(literal.len() as i64)));
            for v in literal.drain(..) {
                out.extend(value(v));
            }
        }
    };
    let mut i = 0;
    while i < rows.len() {
        let mut j = i + 1;
        while j < rows.len() && rows[j] == rows[i] {
            j += 1;
        }
        match &rows[i] {
            None => {
                flush(&mut out, &mut literal);
                out.extend(sleb(0));
                out.extend(uleb((j - i) as u64));
            }
            Some(v) if j - i >= 2 => {
                flush(&mut out, &mut literal);
                out.extend(sleb((j - i) as i64));
                out.extend(value(v));
            }
            Some(v) => literal.push(v),
        }
        i = j;
    }
    flush(&mut out, &mut literal);
    out
}

fn delta_encode(rows: &[Option<i64>]) -> Vec<u8> {
    let mut running = 0i64;
    let deltas: Vec<Option<i64>> = rows
        .iter()
        .map(|v| {
            v.map(|v| {
                let d = v.wrapping_sub(running);
                running = v;
                d
            })
        })
        .collect();
    rle_encode(&deltas, |d| sleb(*d))
}

fn bool_encode(rows: &[bool]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut value = false;
    let mut count = 0u64;
    for &b in rows {
        if b == value {
            count += 1;
        } else {
            out.extend(uleb(count));
            value = b;
            count = 1;
        }
    }
    if count > 0 {
        out.extend(uleb(count));
    }
    out
}

fn string_bytes(s: &String) -> Vec<u8> {
    let mut out = uleb(s.len() as u64);
    out.extend(s.as_bytes());
    out
}

/// The canonical bytes of `c`: the change chunk, checksum included.
pub fn encode(c: &Content) -> Vec<u8> {
    let ops = &c.ops;
    let present = |b: bool, data: Vec<u8>| if b { data } else { Vec::new() };
    let some_obj = ops.iter().any(|o| o.obj.is_some());
    let some_elem = ops.iter().any(|o| matches!(o.key, Key::Elem(_)));
    let some_seq_key = ops.iter().any(|o| !matches!(o.key, Key::Prop(_)));
    let some_prop = ops.iter().any(|o| matches!(o.key, Key::Prop(_)));
    let preds: Vec<LocalId> = ops.iter().flat_map(|o| o.preds.iter().copied()).collect();
    let columns: Vec<(u32, Vec<u8>)> = vec![
        (
            OBJ_ACTOR,
            present(
                some_obj,
                rle_encode(
                    &ops.iter().map(|o| o.obj.map(|x| x.0)).collect::<Vec<_>>(),
                    |v| uleb(*v),
                ),
            ),
        ),
        (
            OBJ_CTR,
            present(
                some_obj,
                rle_encode(
                    &ops.iter().map(|o| o.obj.map(|x| x.1)).collect::<Vec<_>>(),
                    |v| uleb(*v),
                ),
            ),
        ),
        (
            KEY_ACTOR,
            present(
                some_elem,
                rle_encode(
                    &ops.iter()
                        .map(|o| match o.key {
                            Key::Elem((a, _)) => Some(a),
                            _ => None,
                        })
                        .collect::<Vec<_>>(),
                    |v| uleb(*v),
                ),
            ),
        ),
        (
            KEY_CTR,
            present(
                some_seq_key,
                delta_encode(
                    &ops.iter()
                        .map(|o| match o.key {
                            Key::Elem((_, c)) => Some(c as i64),
                            Key::Head => Some(0),
                            Key::Prop(_) => None,
                        })
                        .collect::<Vec<_>>(),
                ),
            ),
        ),
        (
            KEY_STR,
            present(
                some_prop,
                rle_encode(
                    &ops.iter()
                        .map(|o| match &o.key {
                            Key::Prop(s) => Some(s.clone()),
                            _ => None,
                        })
                        .collect::<Vec<_>>(),
                    string_bytes,
                ),
            ),
        ),
        (
            INSERT,
            bool_encode(&ops.iter().map(|o| o.insert).collect::<Vec<_>>()),
        ),
        (
            ACTION,
            rle_encode(
                &ops.iter().map(|o| Some(o.action)).collect::<Vec<_>>(),
                |v| uleb(*v),
            ),
        ),
        (
            VALUE_META,
            rle_encode(
                &ops.iter()
                    .map(|o| Some((o.value.1.len() as u64) << 4 | u64::from(o.value.0)))
                    .collect::<Vec<_>>(),
                |v| uleb(*v),
            ),
        ),
        (
            VALUE,
            ops.iter().flat_map(|o| o.value.1.iter().copied()).collect(),
        ),
        (
            PRED_GROUP,
            rle_encode(
                &ops.iter()
                    .map(|o| Some(o.preds.len() as u64))
                    .collect::<Vec<_>>(),
                |v| uleb(*v),
            ),
        ),
        (
            PRED_ACTOR,
            rle_encode(&preds.iter().map(|p| Some(p.0)).collect::<Vec<_>>(), |v| {
                uleb(*v)
            }),
        ),
        (
            PRED_CTR,
            delta_encode(&preds.iter().map(|p| Some(p.1 as i64)).collect::<Vec<_>>()),
        ),
        (
            EXPAND,
            present(
                ops.iter().any(|o| o.expand),
                bool_encode(&ops.iter().map(|o| o.expand).collect::<Vec<_>>()),
            ),
        ),
        (
            MARK_NAME,
            present(
                ops.iter().any(|o| o.mark_name.is_some()),
                rle_encode(
                    &ops.iter().map(|o| o.mark_name.clone()).collect::<Vec<_>>(),
                    string_bytes,
                ),
            ),
        ),
    ];
    // Empty columns are absent.
    let columns: Vec<(u32, Vec<u8>)> = columns
        .into_iter()
        .filter(|(_, data)| !data.is_empty())
        .collect();

    let mut body = uleb(c.deps.len() as u64);
    for d in &c.deps {
        body.extend(d);
    }
    body.extend(uleb(c.actor.len() as u64));
    body.extend(&c.actor);
    body.extend(uleb(c.seq));
    body.extend(uleb(c.start_op));
    body.extend(sleb(c.time));
    body.extend(uleb(c.message.len() as u64));
    body.extend(c.message.as_bytes());
    body.extend(uleb(c.others.len() as u64));
    for o in &c.others {
        body.extend(uleb(o.len() as u64));
        body.extend(o);
    }
    body.extend(uleb(columns.len() as u64));
    for (spec, data) in &columns {
        body.extend(uleb(u64::from(*spec)));
        body.extend(uleb(data.len() as u64));
    }
    for (_, data) in &columns {
        body.extend(data);
    }
    body.extend(&c.extra);

    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update([CHANGE_CHUNK]);
    hasher.update(uleb(body.len() as u64));
    hasher.update(&body);
    let hash = hasher.finalize();
    let mut out = MAGIC.to_vec();
    out.extend(&hash[..4]);
    out.push(CHANGE_CHUNK);
    out.extend(uleb(body.len() as u64));
    out.extend(body);
    out
}
