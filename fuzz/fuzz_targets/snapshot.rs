//! A Snapshot plaintext (§13) against the §13.1 floor limits and the §11.2
//! depth bound: decided twice, monotone in the limits, and what it accepts
//! loads as both profiles' documents and round-trips through a save.
//!
//! Input: `[flags][bytes]`. Flag bit 0: the bytes are a document chunk
//! body and the harness writes its header (type 0, length, checksum).
//! Flag bit 1: the bytes are the whole plaintext, not framed by the harness.

#![no_main]

use lfcp::shared_objects::document::SharedObjects;
use lfcp::shared_objects::expansion::{self, Limits, SNAPSHOT_LIMITS_FLOOR};
use lfcp::shared_objects::framing;
use lfcp::shared_sections::SectionsDoc;
use lfcp_fuzz::*;
use libfuzzer_sys::fuzz_target;

/// Twice the floor in every dimension: a receiver's own, higher limits.
const DOUBLE: Limits = Limits {
    max_rows: SNAPSHOT_LIMITS_FLOOR.max_rows * 2,
    max_group_sum: SNAPSHOT_LIMITS_FLOOR.max_group_sum * 2,
    max_string_bytes: SNAPSHOT_LIMITS_FLOOR.max_string_bytes * 2,
    max_inflated_bytes: SNAPSHOT_LIMITS_FLOOR.max_inflated_bytes * 2,
    max_deps: SNAPSHOT_LIMITS_FLOOR.max_deps * 2,
    max_actors: SNAPSHOT_LIMITS_FLOOR.max_actors * 2,
};

/// One document chunk filling `save` (the header rules of §13).
fn header_ok(save: &[u8]) -> bool {
    if save.len() < 10 || save[..4] != [0x85, 0x6f, 0x4a, 0x83] || save[8] != 0 {
        return false;
    }
    let (mut len, mut shift, mut at) = (0u64, 0u32, 9usize);
    loop {
        let Some(&b) = save.get(at) else { return false };
        at += 1;
        if shift > 63 {
            return false;
        }
        len |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    (at as u64).checked_add(len) == Some(save.len() as u64)
}

fuzz_target!(|data: &[u8]| {
    panic_policy();
    let Some((&flags, bytes)) = data.split_first() else {
        return;
    };
    let chunk_bytes = if flags & 1 != 0 {
        chunk(0, bytes)
    } else {
        bytes.to_vec()
    };
    let plaintext = if flags & 2 != 0 {
        chunk_bytes
    } else {
        frame(&chunk_bytes)
    };

    let verdict = framing::decode_snapshot(&plaintext);
    assert_eq!(
        verdict,
        framing::decode_snapshot(&plaintext),
        "not deterministic"
    );
    let Ok(save) = framing::snapshot_payload(&plaintext) else {
        assert!(
            verdict.is_err(),
            "a Snapshot without the framing is accepted"
        );
        return;
    };

    let floor = expansion::check_snapshot(&save, &SNAPSHOT_LIMITS_FLOOR);
    let floor_depth = expansion::check_snapshot_depth(&save, &SNAPSHOT_LIMITS_FLOOR);
    assert_eq!(
        floor,
        expansion::check_snapshot(&save, &SNAPSHOT_LIMITS_FLOOR)
    );
    if floor_depth.is_ok() {
        assert_eq!(floor_depth, floor, "the depth check changed the expansion");
    }
    if let Ok(within) = &floor {
        // Higher limits accept what the floor accepts, with the same count.
        assert_eq!(
            expansion::check_snapshot(&save, &DOUBLE).as_ref(),
            Ok(within)
        );
    }
    // decode_snapshot is the header rules, the depth-checked limits and
    // the load; a chunk the header rules accept is decided by the other two.
    if verdict.is_ok() || floor_depth.is_err() {
        assert!(
            verdict.is_err() || floor_depth.is_ok(),
            "accepted over the limits"
        );
    } else if header_ok(&save) {
        assert_eq!(
            verdict.is_ok(),
            SharedObjects::load(&save, automerge::ActorId::from([1u8; 32])).is_ok(),
            "decode_snapshot disagrees with check_snapshot_depth + load"
        );
    }
    let Ok(accepted) = verdict else {
        return;
    };
    assert_eq!(accepted, save);
    // What the Snapshot check admits, both profiles load.
    let mut doc = SharedObjects::load(&accepted, automerge::ActorId::from([1u8; 32]))
        .expect("an accepted Snapshot loads as Shared Objects");
    SectionsDoc::load(&accepted).expect("an accepted Snapshot loads as Shared Sections");
    // Its re-save is a Snapshot again (same document, same counts).
    let resaved = doc.save();
    if let Err(err) = framing::decode_snapshot(&framing::encode_snapshot(&resaved)) {
        panic!("the save of an accepted Snapshot is refused: {err}");
    }
});
