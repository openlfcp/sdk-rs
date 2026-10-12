//! Differential Wire codec: sdk-rs against sdk-ts (through its public npm
//! API, `ts-oracle/oracle.mjs` in its `wire` mode, a black box) on the same
//! bytes.
//!
//! Input: records in the record format of `lfcp_fuzz`, each decoded on its
//! own. Record ctl bits 1-3 pick the decoder: 0 a received WebSocket
//! message (`Message::decode_frame` against `decodeFrame`; bit 0: a text
//! frame), 1 a Control Record, 2 a Data Unit, 3 a Key Package, 4 a
//! Snapshot (`Received*::parse` against `parse*`, neither verifying the
//! signature); others a message.
//!
//! Verdicts: a decoded message is `ok:` and the hex of its re-encoding
//! (`Message::encode` against `encodeMessage`); a refused one `err:` with
//! its §62 wire code and whether the connection closes. A parsed object is
//! `ok:` and its object ID; a refused one `err` (the SDKs' error codes are
//! their own, not §62 codes: they are printed but not compared). Any other
//! difference crashes with both sides.
//!
//! Two differences are where a check runs, not what it decides, and are
//! taken as equal:
//! - sdk-ts checks the ranges of live Have Vectors (§48) as it decodes;
//!   sdk-rs when a receiver reads them (`HaveVector::from_wire`), which
//!   this target does after decoding (`DATA_HAVE`, `RESOURCE_OPEN`,
//!   `RESOURCE_OPENED` and its Snapshot summary).
//! - sdk-rs checks a Control Record body's rules (canonical frontiers,
//!   distinct abilities, endpoints) as it parses; sdk-ts later, against
//!   the chain. An object only sdk-rs refuses is not a crash; one only
//!   sdk-ts refuses, or a different ID, is.
//!
//! And two kinds the 2026-10-12 run found, where a check runs too
//! (repro-w/README.md), end the comparison unless `LFCP_FUZZ_ALL=1`:
//! W1, a HELLO whose Principal Descriptor is invalid (sdk-ts AUTH_FAILED as
//! it decodes, sdk-rs MALFORMED_MESSAGE, which a server maps to
//! AUTH_FAILED); W2, a Genesis whose `control_seq` is not 0 (sdk-ts
//! refuses it as it parses, sdk-rs when it places it in the chain).
//!
//! `LFCP_FUZZ_TRACE=1` prints both sides' verdicts of every input. Needs
//! `node` on PATH and `LFCP_SDK_TS_NPM` (a directory with
//! `@openlfcp/wire` installed) or `LFCP_SDK_TS_DIR` (a built checkout).

#![no_main]

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Mutex, OnceLock};

use lfcp::wire::control::ReceivedControlRecord;
use lfcp::wire::data_unit::ReceivedDataUnit;
use lfcp::wire::key_package::ReceivedKeyPackage;
use lfcp::wire::have::HaveVector;
use lfcp::wire::message::{Body, DecodeOptions, FrameKind, Message};
use lfcp::wire::snapshot::ReceivedSnapshot;
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
            .expect("node runs (LFCP_SDK_TS_DIR or LFCP_SDK_TS_NPM set, node on PATH)");
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The decoder a record's ctl picks, as the oracle names it.
fn kind(ctl: u8) -> &'static str {
    match (ctl >> 1) & 7 {
        1 => "control",
        2 => "unit",
        3 => "package",
        4 => "snapshot",
        _ => "message",
    }
}

fn ours(ctl: u8, bytes: &[u8]) -> String {
    let parsed = |r: Result<Vec<u8>, lfcp::base::Error>| match r {
        Ok(id) => format!("ok:{}", hex(&id)),
        Err(e) => format!("err:{}", e.code()),
    };
    match kind(ctl) {
        "control" => parsed(ReceivedControlRecord::parse(bytes).map(|o| o.id().as_bytes().to_vec())),
        "unit" => parsed(ReceivedDataUnit::parse(bytes).map(|o| o.id().as_bytes().to_vec())),
        "package" => parsed(ReceivedKeyPackage::parse(bytes).map(|o| o.id().as_bytes().to_vec())),
        "snapshot" => parsed(ReceivedSnapshot::parse(bytes).map(|o| o.id().as_bytes().to_vec())),
        _ => {
            let frame = if ctl & 1 != 0 { FrameKind::Text } else { FrameKind::Binary };
            match Message::decode_frame(frame, bytes, &DecodeOptions::default()) {
                Ok(m) if !live_haves_read(&m.body) => "err:MALFORMED_MESSAGE close=false".into(),
                Ok(m) => format!("ok:{}", hex(&m.encode())),
                Err(e) => format!(
                    "err:{} close={}",
                    e.wire_code().map_or("none", |c| c.name()),
                    e.closes_connection()
                ),
            }
        }
    }
}

/// The divergences already explained (see the module comment).
fn known(kind: &str, ours: &str, theirs: &str) -> Option<&'static str> {
    if std::env::var_os("LFCP_FUZZ_ALL").is_some() {
        return None;
    }
    match (kind, ours, theirs) {
        ("message", "err:MALFORMED_MESSAGE close=false", "err:AUTH_FAILED close=false") => Some("W1"),
        ("control", o, "err:INVALID_CONTROL_CHAIN") if o.starts_with("ok:") => Some("W2"),
        _ => None,
    }
}

/// Whether the live Have Vectors of a body read (§48).
fn live_haves_read(body: &Body) -> bool {
    let reads = |have| HaveVector::from_wire(have).is_ok();
    match body {
        Body::DataHave { have, .. } | Body::ResourceOpen { have, .. } => reads(have),
        Body::ResourceOpened { have, snapshot, .. } => {
            reads(have) && snapshot.as_ref().is_none_or(|s| reads(&s.frontier))
        }
        _ => true,
    }
}

/// The TypeScript verdicts of the records.
fn theirs(records: &[Record<'_>]) -> Vec<String> {
    let mut o = oracle().lock().unwrap_or_else(|e| e.into_inner());
    o.next += 1;
    let items: Vec<String> = records
        .iter()
        .map(|r| {
            format!(
                "{{\"hex\":\"{}\",\"kind\":\"{}\",\"text\":{}}}",
                hex(r.bytes),
                kind(r.ctl),
                r.ctl & 1 != 0
            )
        })
        .collect();
    let line = format!("{{\"id\":{},\"mode\":\"wire\",\"items\":[{}]}}\n", o.next, items.join(","));
    o.input.write_all(line.as_bytes()).expect("the oracle reads");
    o.input.flush().expect("the oracle reads");
    let mut answer = String::new();
    o.output.read_line(&mut answer).expect("the oracle answers");
    let start = answer
        .find("\"verdicts\":[")
        .unwrap_or_else(|| panic!("oracle answer without verdicts: {answer}"));
    let body = &answer[start + 12..];
    let body = &body[..body.find(']').expect("a list")];
    if body.is_empty() {
        return Vec::new();
    }
    body.split("\",\"").map(|s| s.trim_matches('"').to_owned()).collect()
}

fuzz_target!(|data: &[u8]| {
    panic_policy();
    let records = records(data);
    if records.is_empty() {
        return;
    }
    let ours: Vec<String> = records.iter().map(|r| ours(r.ctl, r.bytes)).collect();
    let theirs = theirs(&records);
    if std::env::var_os("LFCP_FUZZ_TRACE").is_some() {
        eprintln!("sdk-rs: {ours:?}\nsdk-ts: {theirs:?}");
    }
    for (i, a) in ours.iter().enumerate() {
        let b = theirs.get(i).map(String::as_str).unwrap_or("<none>");
        let object = kind(records[i].ctl) != "message";
        let bare = |v: &str| if object && v.starts_with("err:") { "err" } else { v }.to_owned();
        let stricter = object && a.starts_with("err:") && b.starts_with("ok:");
        if bare(a) != bare(b) && known(kind(records[i].ctl), a, b).is_some() {
            return;
        }
        if bare(a) != bare(b) && !stricter {
            panic!(
                "sdk-rs and sdk-ts disagree at record {i} of {} ({}):\n  sdk-rs: {a}\n  sdk-ts: {b}",
                ours.len(),
                kind(records[i].ctl)
            );
        }
    }
});
