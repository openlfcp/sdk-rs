//! §11.3 against the engine (SHARED-OBJECTS-PROFILE-01): a change chunk, as
//! is or with its header written by the harness (`[flags][bytes]`, flag bit
//! 0: the bytes are `[type][body]`).
//!
//! - What `canonical::check` accepts the engine parses without a panic, and
//!   writes back to exactly the same bytes: the property §11.3 exists for
//!   (otherwise the document's save fails, F3a).
//! - What the engine writes back to exactly the same bytes and §11.1
//!   admits, §11.3 accepts unless a rule beyond the encoding refuses it (the
//!   rules a writer cannot break by committing: an action above 7, value
//!   types 10-15, …); any other refusal is reported (a false refusal).
//! - `decode_change` agrees with §11.1 + §11.3 + the engine's parse.

#![no_main]

use std::panic::{catch_unwind, AssertUnwindSafe};

use automerge::Change;
use lfcp::shared_objects::{canonical, expansion, framing};
use lfcp_fuzz::*;
use libfuzzer_sys::fuzz_target;

/// The engine's own writing of `bytes`, when it parses them; `None` when it
/// refuses or panics.
fn engine_rewrite(bytes: &[u8]) -> Option<Vec<u8>> {
    catch_unwind(AssertUnwindSafe(|| {
        let change = Change::from_bytes(bytes.to_vec()).ok()?;
        Some(Change::from(change.clone().decode()).raw_bytes().to_vec())
    }))
    .ok()
    .flatten()
}

/// The §11.3 rules beyond the encoding that a writer committing on its
/// document always keeps (rules 2, 6, 7, 8): a refusal of a change that
/// keeps them all, and that the engine round-trips, is a false refusal.
fn writer_invariants(change: &Change) -> bool {
    use automerge::legacy::{ElementId, Key, ObjectId, OpId, OpType};
    let c = change.clone().decode();
    let me = c.actor_id.to_bytes().to_vec();
    let limit = canonical::COUNTER_LIMIT;
    if c.seq < 1 || c.deps.windows(2).any(|w| w[0] >= w[1]) {
        return false;
    }
    let others: Vec<Vec<u8>> = change
        .other_actor_ids()
        .iter()
        .map(|a| a.to_bytes().to_vec())
        .collect();
    if others.windows(2).any(|w| w[0] >= w[1]) || others.contains(&me) {
        return false;
    }
    if c.start_op.get() + c.operations.len() as u64 - 1 >= limit && !c.operations.is_empty() {
        return false;
    }
    let mut used = std::collections::BTreeSet::new();
    let id_ok = |id: &OpId, used: &mut std::collections::BTreeSet<Vec<u8>>| {
        used.insert(id.1.to_bytes().to_vec());
        id.0 >= 1 && id.0 < limit
    };
    for op in &c.operations {
        if let ObjectId::Id(id) = &op.obj {
            if !id_ok(id, &mut used) {
                return false;
            }
        }
        if let Key::Seq(ElementId::Id(id)) = &op.key {
            if !id_ok(id, &mut used) {
                return false;
            }
        }
        for p in op.pred.iter() {
            if !id_ok(p, &mut used) {
                return false;
            }
        }
        let mark = matches!(op.action, OpType::MarkBegin(_) | OpType::MarkEnd(_));
        if mark && !op.insert {
            return false;
        }
        if let OpType::Put(v) = &op.action {
            if format!("{v:?}").contains("Unknown") {
                return false;
            }
        }
    }
    used.remove(&me);
    used.into_iter().collect::<Vec<_>>() == others
}

fuzz_target!(|data: &[u8]| {
    panic_policy();
    let Some((&flags, rest)) = data.split_first() else {
        return;
    };
    let bytes = if flags & 1 != 0 {
        match rest.split_first() {
            Some((&t, body)) => chunk(t, body),
            None => return,
        }
    } else {
        rest.to_vec()
    };
    // §11.3 is checked after §11.1 (its columns are then small).
    if bytes.len() < 9 || bytes[8] != 1 || expansion::check_change(&bytes).is_err() {
        return;
    }
    let canon = canonical::check(&bytes);
    assert_eq!(canon, canonical::check(&bytes), "not deterministic");
    let engine = engine_rewrite(&bytes);

    if let Ok(content) = &canon {
        match &engine {
            Some(rewritten) if *rewritten == bytes => {}
            // The engine's legacy model (`Change::decode`) drops the value
            // of a mark without a name; the document itself keeps it (its
            // save and hashes match). Only that difference is forgiven.
            Some(rewritten)
                if {
                    let mut lossy = content.clone();
                    for op in &mut lossy.ops {
                        if op.action == 7 && op.mark_name.is_none() {
                            op.value = (0, Vec::new());
                        }
                    }
                    canonical::encode(&lossy) == *rewritten
                } => {}
            Some(rewritten) => panic!(
                "§11.3 accepts a change the engine writes differently ({} vs {} bytes)",
                bytes.len(),
                rewritten.len()
            ),
            // N1: a change without operations whose start op is 2^32 keeps
            // rule 8 (its last counter, start op - 1, is below 2^32), but
            // automerge 0.12 refuses the start op itself (CounterTooLarge);
            // decode_change then refuses it. Reported as a spec edge.
            None if content.ops.is_empty()
                && content.start_op >= canonical::COUNTER_LIMIT
                && std::env::var_os("LFCP_FUZZ_N1").is_none() => {}
            None => panic!("§11.3 accepts a change the engine cannot parse"),
        }
        assert_eq!(canonical::encode(content), bytes, "encode(check(x)) != x");
    } else if engine.as_deref() == Some(&bytes[..])
        && std::env::var_os("LFCP_FUZZ_CANON_LENIENT").is_none()
    {
        // The engine round-trips it, yet §11.3 refuses it: a false refusal,
        // unless a rule beyond the encoding refuses it (triaged by hand).
        let copy = Change::from_bytes(bytes.clone()).expect("parsed above");
        if !writer_invariants(&copy) {
            return;
        }
        let raw = format!("{:?}", copy.decode());
        panic!(
            "§11.3 refuses a change the engine round-trips: {}",
            &raw[..raw.len().min(800)]
        );
    }

    // decode_change: the framing, §11.1, §11.3, the parse and the checksum.
    let decoded = framing::decode_change(&frame(&bytes));
    if decoded.is_ok() {
        assert!(canon.is_ok(), "decode_change accepts what §11.3 refuses");
    }
});
