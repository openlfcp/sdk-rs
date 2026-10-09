//! Scale measurements of a shared section (LFCP-02-067, its SDK side):
//! reproducible numbers for the plugin's performance work and for the
//! coalescing of Text edits into changes (LFCP-02-025).
//!
//! ```text
//! cargo run --release --example section_scale --features shared-sections -- [growth|admission|authoring|all] [--quick]
//! ```
//!
//! - `growth`: one writer types into one paragraph, N characters coalesced
//!   k to a change. For each (N, k): changes (one Data Unit each), framed
//!   plaintext and sealed Data Unit bytes, the save's size and its counts
//!   of SHARED-OBJECTS-PROFILE-01 §13.1 (the largest column, the group
//!   sum), and where the section reaches the Snapshot floor (262,144).
//!   The typing writes Automerge's `splice_text` on the section document,
//!   the same operations `SectionsDoc::text_edit` writes (see `authoring`
//!   for why not through it).
//! - `admission`: `SectionsReplica::receive` over the W200 import (200 Task
//!   nodes, 200 paragraphs) and a typing history, in order, and the import
//!   reversed with duplicates.
//! - `authoring`: `SectionsDoc::text_edit`'s cost against the text's length.
//!
//! Output: a human-readable table per part, then one JSON line per part
//! (`{"part": ...}`) for the report.

use std::time::Instant;

use automerge::transaction::{CommitOptions, Transactable};
use automerge::{ActorId, AutoCommit, ObjId, ReadDoc, ROOT};
use lfcp::base::{Hash32, ResourceId};
use lfcp::principal::PrincipalKeys;
use lfcp::shared_objects::expansion::{self, Limits};
use lfcp::shared_objects::framing;
use lfcp::shared_sections::{self, NewNode, Received, SectionsDoc, SectionsReplica};
use lfcp::wire::data_unit::{DataUnit, DataUnitHeader};
use lfcp::wire::keys::Dek;
use serde_json::json;

const SECTION: &str = "019a2f85-7b31-7c42-8000-000000000001";
const PARAGRAPH: &str = "019a2f85-7b31-7c42-8003-000000000001";
const PLACEMENT: &str = "019a2f85-7b31-7c42-8004-000000000001";
const FLOOR: u64 = 262_144;
/// No limit: the counts are measured, not checked.
const MEASURE: Limits = Limits {
    max_rows: u64::MAX,
    max_group_sum: u64::MAX,
    max_string_bytes: u64::MAX,
    max_inflated_bytes: u64::MAX,
    max_deps: u64::MAX,
    max_actors: u64::MAX,
};

fn uuid(k: u16, n: u32) -> String {
    format!("019a2f85-7b31-7c42-{:04x}-{n:012x}", 0x8000 | k)
}

struct Writer {
    keys: PrincipalKeys,
    resource: ResourceId,
    dek: Dek,
    sequence: u64,
    previous: Option<lfcp::base::DataUnitId>,
}

impl Writer {
    fn new() -> Writer {
        Writer {
            keys: PrincipalKeys::from_secrets(&[1; 32], [2; 32]),
            resource: ResourceId::from_bytes([0x5e; 32]),
            dek: Dek::from_bytes([9; 32]),
            sequence: 0,
            previous: None,
        }
    }

    fn actor(&self) -> ActorId {
        shared_sections::actor_id(&self.resource, self.keys.descriptor().id())
    }

    /// The Data Unit of a change: its bytes as the server stores them.
    fn seal(&mut self, change: &[u8]) -> (usize, usize) {
        let plaintext = framing::encode_change(change);
        self.sequence += 1;
        let unit = DataUnit::seal(
            DataUnitHeader {
                resource_id: self.resource,
                data_epoch: 0,
                actor: *self.keys.descriptor().id(),
                sequence: self.sequence,
                previous: self.previous,
                control_head: Hash32::from_bytes([3; 32]),
            },
            &plaintext,
            &self.dek,
            &self.keys,
        )
        .unwrap();
        self.previous = Some(unit.id());
        (plaintext.len(), unit.signed_object().bytes().len())
    }
}

/// A new section with one empty paragraph: its document, and its changes'
/// framed plaintexts.
fn section_with_paragraph(writer: &Writer) -> (SectionsDoc, Vec<Vec<u8>>) {
    let owner = *writer.keys.descriptor().id();
    let (mut doc, first) =
        SectionsDoc::create(writer.actor(), SECTION, "Long typing", &owner).unwrap();
    let para = doc
        .create_node(
            PARAGRAPH,
            NewNode::Paragraph { text: "" },
            SECTION,
            None,
            PLACEMENT,
            &owner,
        )
        .unwrap();
    let plaintexts = [first, para]
        .iter()
        .map(|c| framing::encode_change(c.raw_bytes()))
        .collect();
    (doc, plaintexts)
}

fn text_of(doc: &AutoCommit, node: &str) -> ObjId {
    let (_, nodes) = doc.get(ROOT, "nodes").unwrap().unwrap();
    let (_, map) = doc.get(&nodes, node).unwrap().unwrap();
    let (_, text) = doc.get(&map, "text").unwrap().unwrap();
    text
}

/// Characters a writer types: words drawn from a vocabulary by a fixed
/// xorshift stream, with punctuation, so the text compresses like prose
/// (a repeated sentence would compress to almost nothing in a save).
fn typed(n: usize) -> Vec<char> {
    const WORDS: &[&str] = &[
        "the",
        "launch",
        "plan",
        "needs",
        "a",
        "review",
        "of",
        "budget",
        "and",
        "timeline",
        "before",
        "we",
        "commit",
        "to",
        "vendor",
        "contract",
        "draft",
        "is",
        "ready",
        "for",
        "legal",
        "team",
        "should",
        "check",
        "pricing",
        "risks",
        "open",
        "questions",
        "remain",
        "about",
        "hosting",
        "support",
        "migration",
        "data",
        "export",
        "schedule",
        "next",
        "meeting",
        "with",
        "Maria",
        "Pavel",
        "on",
        "Tuesday",
        "notes",
        "from",
        "call",
        "customer",
        "feedback",
        "suggests",
        "simpler",
        "onboarding",
        "flow",
        "metrics",
        "show",
        "weekly",
        "active",
        "users",
        "grew",
        "slowly",
        "after",
        "release",
        "fix",
        "bug",
        "in",
        "sync",
        "edge",
        "case",
        "when",
        "offline",
        "editing",
        "conflicts",
        "resolve",
        "later",
    ];
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut out = Vec::with_capacity(n + 16);
    while out.len() < n {
        out.extend(WORDS[(next() % WORDS.len() as u64) as usize].chars());
        out.push(match next() % 12 {
            0 => '.',
            1 => ',',
            _ => ' ',
        });
        if out.last() == Some(&'.') {
            out.push(if next() % 4 == 0 { '\n' } else { ' ' });
        }
    }
    out.truncate(n);
    out
}

struct Growth {
    chars: usize,
    per_change: usize,
    backspace_every: usize,
    changes: u64,
    plaintext_bytes: u64,
    unit_bytes: u64,
    save_bytes: u64,
    max_rows: u64,
    group_sum: u64,
    floor_at: Option<usize>,
    ms: u128,
}

/// One writer types `chars` characters, `per_change` to a change; with
/// `backspace_every` > 0, every so many keystrokes delete the previous
/// character instead (it counts as a typed character).
fn grow(chars: usize, per_change: usize, backspace_every: usize, probe_every: usize) -> Growth {
    let mut writer = Writer::new();
    let (mut section, plaintexts) = section_with_paragraph(&writer);
    let mut doc = AutoCommit::load(&section.save())
        .unwrap()
        .with_actor(writer.actor());
    let text = text_of(&doc, PARAGRAPH);
    let mut out = Growth {
        chars,
        per_change,
        backspace_every,
        changes: 0,
        plaintext_bytes: 0,
        unit_bytes: 0,
        save_bytes: 0,
        max_rows: 0,
        group_sum: 0,
        floor_at: None,
        ms: 0,
    };
    for p in &plaintexts {
        let change = framing::decode_change(p).unwrap();
        let (pt, du) = writer.seal(change.raw_bytes());
        out.changes += 1;
        out.plaintext_bytes += pt as u64;
        out.unit_bytes += du as u64;
    }
    let started = Instant::now();
    let keys = typed(chars);
    let mut len = 0usize;
    let mut pending = 0usize;
    let mut buffer = String::new();
    let commit = |doc: &mut AutoCommit, out: &mut Growth, writer: &mut Writer| {
        if doc.pending_ops() == 0 {
            return;
        }
        let hash = doc
            .commit_with(
                CommitOptions::default()
                    .with_message("text.edit")
                    .with_time(0),
            )
            .unwrap();
        let change = doc.get_change_by_hash(&hash).unwrap();
        let (pt, du) = writer.seal(change.raw_bytes());
        out.changes += 1;
        out.plaintext_bytes += pt as u64;
        out.unit_bytes += du as u64;
    };
    for (i, c) in keys.iter().enumerate() {
        if backspace_every > 0 && (i + 1) % backspace_every == 0 && (len > 0 || !buffer.is_empty())
        {
            if buffer.pop().is_none() {
                doc.splice_text(&text, len - 1, 1, "").unwrap();
                len -= 1;
            }
        } else {
            buffer.push(*c);
        }
        pending += 1;
        if pending == per_change {
            if !buffer.is_empty() {
                doc.splice_text(&text, len, 0, &buffer).unwrap();
                len += buffer.chars().count();
                buffer.clear();
            }
            commit(&mut doc, &mut out, &mut writer);
            pending = 0;
        }
        if out.floor_at.is_none() && probe_every > 0 && (i + 1) % probe_every == 0 {
            let e = expansion::check_snapshot(&doc.save(), &MEASURE).unwrap();
            if e.max_rows.max(e.group_sum) >= FLOOR {
                out.floor_at = Some(i + 1);
            }
        }
    }
    if !buffer.is_empty() {
        doc.splice_text(&text, len, 0, &buffer).unwrap();
    }
    commit(&mut doc, &mut out, &mut writer);
    out.ms = started.elapsed().as_millis();
    let save = doc.save();
    let e = expansion::check_snapshot(&save, &MEASURE).unwrap();
    out.save_bytes = save.len() as u64;
    out.max_rows = e.max_rows;
    out.group_sum = e.group_sum;
    out
}

fn growth(quick: bool) {
    let sizes: &[usize] = if quick {
        &[10_000]
    } else {
        &[10_000, 50_000, 250_000]
    };
    let coalescing: &[usize] = &[1, 16, 128, 1024, 8192];
    println!("\n# growth: one writer typing into one paragraph");
    println!(
        "{:>8} {:>6} {:>4} {:>8} {:>11} {:>11} {:>10} {:>9} {:>9} {:>9} {:>8}",
        "chars",
        "k",
        "bs",
        "changes",
        "plaintext",
        "unit bytes",
        "save",
        "max rows",
        "group",
        "floor at",
        "ms"
    );
    let mut rows = vec![];
    let mut run = |n: usize, k: usize, bs: usize| {
        let g = grow(n, k, bs, if n >= 250_000 { 5_000 } else { 0 });
        println!(
            "{:>8} {:>6} {:>4} {:>8} {:>11} {:>11} {:>10} {:>9} {:>9} {:>9} {:>8}",
            g.chars,
            g.per_change,
            g.backspace_every,
            g.changes,
            g.plaintext_bytes,
            g.unit_bytes,
            g.save_bytes,
            g.max_rows,
            g.group_sum,
            g.floor_at.map_or("-".into(), |f| f.to_string()),
            g.ms
        );
        rows.push(json!({
            "chars": g.chars, "per_change": g.per_change, "backspace_every": g.backspace_every,
            "changes": g.changes, "plaintext_bytes": g.plaintext_bytes, "unit_bytes": g.unit_bytes,
            "save_bytes": g.save_bytes, "max_rows": g.max_rows, "group_sum": g.group_sum,
            "floor_at": g.floor_at, "ms": g.ms,
        }));
    };
    for &n in sizes {
        for &k in coalescing {
            run(n, k, 0);
        }
    }
    // Editing, not only appending: every 10th keystroke is a backspace.
    run(sizes[sizes.len().min(2) - 1], 16, 10);
    println!(
        "{}",
        json!({ "part": "growth", "floor": FLOOR, "rows": rows })
    );
}

/// The W200 import: the section, then 200 Task nodes each with a paragraph
/// of about 200 characters, one change per node (the SDK's authoring).
fn import(writer: &Writer, tasks: u32) -> Vec<Vec<u8>> {
    let owner = *writer.keys.descriptor().id();
    let (mut doc, first) =
        SectionsDoc::create(writer.actor(), SECTION, "Joint launch", &owner).unwrap();
    let mut changes = vec![first];
    let mut after: Option<String> = None;
    for i in 1..=tasks {
        let task = uuid(1, i);
        changes.push(
            doc.create_node(
                &task,
                NewNode::Task {
                    title: &format!("Task {i}: prepare the launch"),
                },
                SECTION,
                after.as_deref(),
                &uuid(2, i),
                &owner,
            )
            .unwrap(),
        );
        changes.push(
            doc.create_node(
                &uuid(3, i),
                NewNode::Paragraph {
                    text: &format!("Notes {i} on the launch plan. ").repeat(7),
                },
                &task,
                None,
                &uuid(4, i),
                &owner,
            )
            .unwrap(),
        );
        after = Some(task);
    }
    changes
        .iter()
        .map(|c| framing::encode_change(c.raw_bytes()))
        .collect()
}

/// A typing history's plaintexts: `chars` characters, `k` to a change.
fn typing(writer: &Writer, chars: usize, k: usize) -> Vec<Vec<u8>> {
    let (mut section, mut plaintexts) = section_with_paragraph(writer);
    let mut doc = AutoCommit::load(&section.save())
        .unwrap()
        .with_actor(writer.actor());
    let text = text_of(&doc, PARAGRAPH);
    let keys: String = typed(chars).into_iter().collect();
    let mut at = 0;
    for chunk in keys.as_bytes().chunks(k) {
        let s = std::str::from_utf8(chunk).unwrap();
        doc.splice_text(&text, at, 0, s).unwrap();
        at += s.len();
        let hash = doc
            .commit_with(
                CommitOptions::default()
                    .with_message("text.edit")
                    .with_time(0),
            )
            .unwrap();
        plaintexts.push(framing::encode_change(
            doc.get_change_by_hash(&hash).unwrap().raw_bytes(),
        ));
    }
    plaintexts
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    sorted[((sorted.len() as f64 - 1.0) * p).round() as usize]
}

/// Receive `units` into a new replica in this order: per-unit times (µs),
/// and the changes in the replica's document at the end.
fn receive_all(writer: &Writer, units: &[Vec<u8>]) -> (Vec<f64>, usize) {
    let mut replica = SectionsReplica::new(writer.resource, ActorId::from([7u8; 32]));
    let signer = *writer.keys.descriptor().id();
    let mut times = Vec::with_capacity(units.len());
    for u in units {
        let t = Instant::now();
        let outcome = replica.receive(&signer, u);
        assert!(
            !matches!(outcome, Received::Refused(_)),
            "a unit was refused"
        );
        times.push(t.elapsed().as_secs_f64() * 1e6);
    }
    (times, replica.view().changes().len())
}

fn admission(quick: bool) {
    let writer = Writer::new();
    println!("\n# admission: SectionsReplica::receive");
    println!(
        "{:<34} {:>7} {:>8} {:>10} {:>10} {:>10} {:>10}",
        "workload", "units", "in doc", "total ms", "p50 µs", "p99 µs", "last10% µs"
    );
    let mut rows = vec![];
    let mut report = |name: &str, units: &[Vec<u8>]| {
        let (times, applied) = receive_all(&writer, units);
        let total: f64 = times.iter().sum();
        let tail = &times[times.len() * 9 / 10..];
        let tail_mean = tail.iter().sum::<f64>() / tail.len() as f64;
        let mut sorted = times.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
        println!(
            "{:<34} {:>7} {:>8} {:>10.0} {:>10.0} {:>10.0} {:>10.0}",
            name,
            units.len(),
            applied,
            total / 1e3,
            percentile(&sorted, 0.5),
            percentile(&sorted, 0.99),
            tail_mean
        );
        rows.push(json!({
            "workload": name, "units": units.len(), "changes_in_document": applied,
            "total_ms": total / 1e3, "p50_us": percentile(&sorted, 0.5),
            "p99_us": percentile(&sorted, 0.99), "last_tenth_mean_us": tail_mean,
        }));
    };
    let w200 = import(&writer, if quick { 50 } else { 200 });
    report(
        if quick {
            "W50 import, in order"
        } else {
            "W200 import, in order"
        },
        &w200,
    );
    // Reversed with duplicates: every change waits, then the whole history
    // is admitted as its dependencies arrive.
    let reversed: Vec<Vec<u8>> = w200
        .iter()
        .rev()
        .flat_map(|u| [u.clone(), u.clone()])
        .collect();
    report(
        if quick {
            "W50 import, reversed + duplicates"
        } else {
            "W200 import, reversed + duplicates"
        },
        &reversed,
    );
    for (chars, k) in if quick {
        vec![(10_000, 16)]
    } else {
        vec![(50_000, 16), (50_000, 128)]
    } {
        report(
            &format!("typing {chars} chars, k = {k}"),
            &typing(&writer, chars, k),
        );
    }
    println!("{}", json!({ "part": "admission", "rows": rows }));
}

/// `SectionsDoc::text_edit`'s cost against the length of the Text: it
/// compares the Text at `base` with the current one on every call.
fn authoring(quick: bool) {
    let writer = Writer::new();
    let owner = *writer.keys.descriptor().id();
    println!("\n# authoring: SectionsDoc::text_edit, one character per change");
    println!("{:>8} {:>12}", "length", "µs per edit");
    let mut rows = vec![];
    let lengths: &[usize] = if quick {
        &[1_000, 10_000]
    } else {
        &[1_000, 10_000, 50_000, 200_000]
    };
    for &length in lengths {
        let (mut doc, _) = SectionsDoc::create(writer.actor(), SECTION, "t", &owner).unwrap();
        let start: String = typed(length).into_iter().collect();
        // The initial text in Text-budget-sized changes (§16.2).
        doc.create_node(
            PARAGRAPH,
            NewNode::Paragraph { text: "" },
            SECTION,
            None,
            PLACEMENT,
            &owner,
        )
        .unwrap();
        let mut at = 0;
        for chunk in start.as_bytes().chunks(8_000) {
            let s = std::str::from_utf8(chunk).unwrap();
            let base = doc.heads();
            doc.text_edit(PARAGRAPH, &base, at, 0, s).unwrap();
            at += s.len();
        }
        let edits = 50;
        let t = Instant::now();
        for _ in 0..edits {
            let base = doc.heads();
            doc.text_edit(PARAGRAPH, &base, at, 0, "x").unwrap();
            at += 1;
        }
        let per = t.elapsed().as_secs_f64() * 1e6 / edits as f64;
        println!("{:>8} {:>12.0}", length, per);
        rows.push(json!({ "length": length, "us_per_edit": per }));
    }
    println!("{}", json!({ "part": "authoring", "rows": rows }));
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let quick = args.iter().any(|a| a == "--quick");
    let part = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .map(String::as_str)
        .unwrap_or("all");
    if matches!(part, "growth" | "all") {
        growth(quick);
    }
    if matches!(part, "admission" | "all") {
        admission(quick);
    }
    if matches!(part, "authoring" | "all") {
        authoring(quick);
    }
}
