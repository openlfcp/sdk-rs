//! Differential admission: sdk-rs against sdk-ts (through its public npm
//! API, `ts-oracle/oracle.mjs`, a black box) on the same bytes.
//!
//! Input: `[mode][records]` in the record format of `lfcp_fuzz`. Mode bit
//! 0: Shared Sections (each record received by a `SectionsReplica` signed by
//! the record's signer, against `SectionReplica.receiveChanges`); otherwise
//! Shared Objects (each record a Data Unit plaintext received by a
//! `SharedObjects` replica, against `SharedObjectsReplica.receive`; neither
//! side binds a signer there). Both replicas start empty.
//!
//! After each record the two verdicts (applied, duplicate, missing, held,
//! or the refusal with its diagnostic) and the two replicas' heads must be
//! the same; any difference crashes with both sides.
//!
//! Needs `LFCP_SDK_TS_DIR` (a built sdk-ts checkout) and `node` on PATH.

#![no_main]

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Mutex, OnceLock};

use automerge::ActorId;
use lfcp::shared_objects::document::{ChangeOutcome, SharedObjects};
use lfcp::shared_objects::{framing, ProfileError};
use lfcp::shared_sections::{Received, SectionsReplica};
use lfcp_fuzz::*;
use libfuzzer_sys::fuzz_target;

struct Oracle {
    _child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
    next: u64,
}

fn oracle() -> &'static Mutex<Oracle> {
    static ORACLE: OnceLock<Mutex<Oracle>> = OnceLock::new();
    ORACLE.get_or_init(|| {
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/ts-oracle/oracle.mjs");
        let mut child = Command::new("node")
            .arg(script)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("node runs (LFCP_SDK_TS_DIR set, node on PATH)");
        let input = child.stdin.take().expect("stdin");
        let output = BufReader::new(child.stdout.take().expect("stdout"));
        Mutex::new(Oracle {
            _child: child,
            input,
            output,
            next: 0,
        })
    })
}

fn b64(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The TypeScript verdicts and heads of a case.
fn ask(
    mode: &str,
    resource: &str,
    items: &[(Vec<u8>, Option<String>)],
) -> (Vec<String>, Vec<String>) {
    let mut o = oracle().lock().unwrap_or_else(|e| e.into_inner());
    o.next += 1;
    let items: Vec<String> = items
        .iter()
        .map(|(pt, signer)| {
            let signer = signer
                .as_ref()
                .map_or("null".to_owned(), |s| format!("\"{s}\""));
            format!("{{\"b64\":\"{}\",\"signer\":{signer}}}", b64(pt))
        })
        .collect();
    let line = format!(
        "{{\"id\":{},\"mode\":\"{mode}\",\"resource\":\"{resource}\",\"principal\":\"{}\",\"items\":[{}]}}\n",
        o.next,
        "09".repeat(32),
        items.join(",")
    );
    o.input
        .write_all(line.as_bytes())
        .expect("the oracle reads");
    o.input.flush().expect("the oracle reads");
    let mut answer = String::new();
    o.output.read_line(&mut answer).expect("the oracle answers");
    let list = |key: &str| -> Vec<String> {
        let start = answer
            .find(&format!("\"{key}\":["))
            .unwrap_or_else(|| panic!("oracle answer without {key}: {answer}"));
        let body = &answer[start + key.len() + 4..];
        let end = body.find(']').expect("a list");
        let body = &body[..end];
        if body.is_empty() {
            return Vec::new();
        }
        // Empty strings are entries too (no heads yet).
        body.split("\",\"")
            .map(|s| s.trim_matches('"').to_owned())
            .collect()
    };
    (list("verdicts"), list("heads"))
}

fn sorted_heads(mut heads: Vec<automerge::ChangeHash>) -> String {
    heads.sort();
    heads
        .iter()
        .map(|h| h.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn objects_verdict(r: Result<ChangeOutcome, ProfileError>) -> String {
    match r {
        Ok(ChangeOutcome::Applied) => "applied".into(),
        Ok(ChangeOutcome::Duplicate) => "duplicate".into(),
        Ok(ChangeOutcome::Held) => "held".into(),
        Err(ProfileError::MissingDependencies(_)) => "missing".into(),
        Err(ProfileError::SequenceTaken { .. }) => "held".into(),
        Err(ProfileError::Invalid(d)) => format!("invalid:{}", d.name()),
        Err(e) => format!("error:{}", e.code().unwrap_or("?")),
    }
}

fn sections_verdict(r: Received) -> String {
    match r {
        Received::Applied => "applied".into(),
        Received::Duplicate => "duplicate".into(),
        Received::Held => "held".into(),
        Received::Waiting => "missing".into(),
        Received::Refused(r) => format!("refused:{}", r.name()),
    }
}

/// The divergences already reported, by the verdicts of the two sides at
/// the first record where they differ (repro-b6/README.md). A disagreement
/// of one of these kinds ends the comparison instead of crashing, so it
/// does not hide new ones; `LFCP_FUZZ_ALL=1` reports them all. A new cause
/// with the same verdicts is hidden too: check repro-b6 after a fix.
fn known(sections: bool, ours: &str, theirs: &str) -> Option<&'static str> {
    if std::env::var_os("LFCP_FUZZ_ALL").is_some() {
        return None;
    }
    match (sections, ours, theirs) {
        // D1: a table written into: the engine aborts; sdk-ts throws.
        (_, "refused:INVALID_AUTOMERGE_BYTES" | "invalid:INVALID_AUTOMERGE_BYTES", t)
            if t.contains("Missing from Index") || t.contains("could not be restored") =>
        {
            Some("D1")
        }
        // D2: a sequence number or time of 2^53 or more; sdk-ts refuses.
        (false, "applied" | "missing", "invalid:INVALID_AUTOMERGE_BYTES")
        | (true, "applied" | "missing", "refused:INVALID_AUTOMERGE_BYTES") => Some("D2"),
        // D3: Text in a field the profile does not define (A5).
        (true, "applied", "refused:INVALID_FIELD_TYPE") => Some("D3"),
        // D4: `ready` other than true when the change creates the section.
        (true, "applied", "refused:IMMUTABLE_FIELD_MUTATED") => Some("D4"),
        // D5: an author on a change other than the actor's first.
        (_, "refused:INVALID_AUTOMERGE_BYTES" | "invalid:INVALID_AUTOMERGE_BYTES", t)
            if t.contains("change.seq() == 1") =>
        {
            Some("D5")
        }
        _ => None,
    }
}

fuzz_target!(|data: &[u8]| {
    panic_policy();
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let records = records(rest);
    if records.is_empty() {
        return;
    }
    let sections = mode & 1 != 0;
    let (resource_hex, principals) = if sections {
        (SECTIONS_RESOURCE, &SECTIONS_PRINCIPALS)
    } else {
        (OBJECTS_RESOURCE, &OBJECTS_PRINCIPALS)
    };
    let res = resource(resource_hex);
    let items: Vec<(Vec<u8>, Option<String>)> = records
        .iter()
        .map(|r| {
            let signer = sections.then(|| hex(signer(principals, r.ctl).as_bytes()));
            (plaintext(r), signer)
        })
        .collect();

    let mut ours = Vec::new();
    let mut our_heads = Vec::new();
    if sections {
        let mut replica = SectionsReplica::new(res, ActorId::from([9u8; 32]));
        for (record, (pt, _)) in records.iter().zip(&items) {
            ours.push(sections_verdict(
                replica.receive(&signer(principals, record.ctl), pt),
            ));
            our_heads.push(sorted_heads(replica.view().automerge().clone().get_heads()));
        }
    } else {
        let mut doc = SharedObjects::new(ActorId::from([9u8; 32]));
        for (pt, _) in &items {
            let r = framing::decode_change(pt).and_then(|c| doc.apply_change(c));
            ours.push(objects_verdict(r));
            our_heads.push(sorted_heads(doc.heads()));
        }
    }
    let (theirs, their_heads) = ask(if sections { "ss" } else { "so" }, resource_hex, &items);
    for i in 0..ours.len() {
        let (a, b) = (
            &ours[i],
            theirs.get(i).map(String::as_str).unwrap_or("<none>"),
        );
        if a != b && known(sections, a, b).is_some() {
            return;
        }
        if a != b || our_heads[i] != *their_heads.get(i).unwrap_or(&String::new()) {
            panic!(
                "sdk-rs and sdk-ts disagree at record {i} of {} ({}):\n  sdk-rs: {a} heads [{}]\n  sdk-ts: {b} heads [{}]\n  all sdk-rs: {ours:?}\n  all sdk-ts: {theirs:?}",
                ours.len(),
                if sections { "sections" } else { "objects" },
                our_heads[i],
                their_heads.get(i).map(String::as_str).unwrap_or("")
            );
        }
    }
});
