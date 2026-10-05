//! Receiving cost of a Shared Objects document at scale (the sdk-rs perf
//! follow-up of the E4 fix). Ignored by default; run in release:
//!
//!     cargo test --release --features shared-objects --test apply_perf -- --ignored --nocapture
//!
//! Measured on an M-series Mac (10 000 changes): one change per call (a
//! live Data Unit) is ~8 s in total, quadratic, almost all of it the
//! engine's own per-call cost (bare automerge: ~5.7 s; the rollback clone
//! adds ~2 s); a batch (store replay, catch-up) is ~50 ms in any order.

#![cfg(feature = "shared-objects")]
use automerge::ActorId;
use lfcp::base::ObjectId;
use lfcp::shared_objects::document::{NewTask, SharedObjects};
use std::time::Instant;

#[test]
#[ignore]
fn bench_receive() {
    for n in [1000usize, 5000, 10000] {
        let mut w = SharedObjects::new(ActorId::from(vec![1u8; 16]));
        w.initialize().unwrap();
        let id = ObjectId::parse("019a2f85-7b31-7c42-b85a-fc843e2f40ad").unwrap();
        w.create_task(&NewTask::new(
            id.clone(),
            lfcp::base::PrincipalId::from_bytes([3; 32]),
            "t",
        ))
        .unwrap();
        for i in 0..n {
            w.set_title(id.as_str(), &format!("t{i}")).unwrap();
        }
        let changes = w.changes();
        let mut r = SharedObjects::new(ActorId::from(vec![2u8; 16]));
        let t = Instant::now();
        for c in changes {
            assert!(r.apply_changes(vec![c]).unwrap().is_empty());
        }
        let el = t.elapsed();
        eprintln!(
            "n={n}: {:?} total, {:?} per change",
            el,
            el / (n as u32 + 2)
        );
    }
}

#[test]
#[ignore]
fn bench_raw() {
    for n in [1000usize, 5000, 10000] {
        let mut w = SharedObjects::new(ActorId::from(vec![1u8; 16]));
        w.initialize().unwrap();
        let id = ObjectId::parse("019a2f85-7b31-7c42-b85a-fc843e2f40ad").unwrap();
        w.create_task(&NewTask::new(
            id.clone(),
            lfcp::base::PrincipalId::from_bytes([3; 32]),
            "t",
        ))
        .unwrap();
        for i in 0..n {
            w.set_title(id.as_str(), &format!("t{i}")).unwrap();
        }
        let changes = w.changes();
        let mut r = automerge::AutoCommit::new();
        let t = Instant::now();
        for c in changes.clone() {
            r.apply_changes(vec![c]).unwrap();
        }
        let raw = t.elapsed();
        let mut r2 = automerge::AutoCommit::new();
        let t = Instant::now();
        for c in changes.clone() {
            let _b = r2.clone();
            r2.apply_changes(vec![c]).unwrap();
        }
        let cloned = t.elapsed();
        let mut r3 = automerge::AutoCommit::new();
        let t = Instant::now();
        for c in changes {
            let h = c.hash();
            let _ = r3.get_change_by_hash(&h);
            for d in c.deps() {
                let _ = r3.get_change_by_hash(d);
            }
            r3.apply_changes(vec![c]).unwrap();
        }
        let lookups = t.elapsed();
        eprintln!("n={n}: raw {raw:?}, +clone {cloned:?}, +hash lookups {lookups:?}");
    }
}

#[test]
#[ignore]
fn bench_batch() {
    for n in [1000usize, 5000, 10000] {
        let mut w = SharedObjects::new(ActorId::from(vec![1u8; 16]));
        w.initialize().unwrap();
        let id = ObjectId::parse("019a2f85-7b31-7c42-b85a-fc843e2f40ad").unwrap();
        w.create_task(&NewTask::new(
            id.clone(),
            lfcp::base::PrincipalId::from_bytes([3; 32]),
            "t",
        ))
        .unwrap();
        for i in 0..n {
            w.set_title(id.as_str(), &format!("t{i}")).unwrap();
        }
        let changes = w.changes();
        let mut r = automerge::AutoCommit::new();
        let t = Instant::now();
        r.apply_changes(changes).unwrap();
        eprintln!("n={n}: raw batch {:?}", t.elapsed());
    }
}

#[test]
#[ignore]
fn bench_profile_batch() {
    for n in [1000usize, 5000, 10000] {
        let mut w = SharedObjects::new(ActorId::from(vec![1u8; 16]));
        w.initialize().unwrap();
        let id = ObjectId::parse("019a2f85-7b31-7c42-b85a-fc843e2f40ad").unwrap();
        w.create_task(&NewTask::new(
            id.clone(),
            lfcp::base::PrincipalId::from_bytes([3; 32]),
            "t",
        ))
        .unwrap();
        for i in 0..n {
            w.set_title(id.as_str(), &format!("t{i}")).unwrap();
        }
        let mut changes = w.changes();
        changes.reverse(); // worst order: every dependency arrives last
        let mut r = SharedObjects::new(ActorId::from(vec![2u8; 16]));
        let t = Instant::now();
        assert!(r.apply_changes(changes).unwrap().is_empty());
        eprintln!("n={n}: profile batch (reversed) {:?}", t.elapsed());
    }
}
