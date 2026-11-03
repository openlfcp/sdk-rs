//! Review P1-2: complete replay by roots holding only data/read, retaining all
//! historical heads. Run offline in release with --ignored --nocapture.
mod support;

use lfcp::base::PrincipalId;
use lfcp::principal::PrincipalKeys;
use lfcp::wire::control::authority::validate_authorized;
use lfcp::wire::control::body::{CapabilityGrantBody, ControlBody, DeviceGrantBody};
use lfcp::wire::control::chain::ChainOutcome;
use lfcp::wire::control::device::{
    CertificateChain, DeviceCertificate, DeviceCertificatePayload, DeviceKind,
};
use lfcp::wire::control::{ControlRecord, ControlRecordHeader};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicUsize, Ordering},
    time::Instant,
};
use support::identity::{genesis, keys, RESOURCE};

struct CountLive;
static LIVE: AtomicUsize = AtomicUsize::new(0);
// Accounting only: the allocator contract is delegated unchanged to System.
unsafe impl GlobalAlloc for CountLive {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            LIVE.fetch_add(layout.size(), Ordering::Relaxed);
        }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) };
    }
}
#[global_allocator]
static ALLOCATOR: CountLive = CountLive;

fn records(count: usize, recertify: bool) -> (Vec<Vec<u8>>, PrincipalId) {
    let owner = keys(1);
    let genesis = genesis(1, 1, None);
    let mut previous = genesis.id();
    let mut bytes = vec![genesis.signed_object().bytes().to_vec()];
    // Each read-only root stays within 32 bindings / 8 grants per pair.
    // This fixture grants explicit membership to each additional root.
    let grants_per_device = if recertify { 8 } else { 1 };
    let records_per_root = 32 * grants_per_device;
    let mut root = None;
    let mut first = None;
    for n in 0..count {
        if n % records_per_root == 0 {
            let mut seed = [66; 32];
            seed[..8].copy_from_slice(&(n as u64).to_be_bytes());
            let next_root = PrincipalKeys::from_secrets(&seed, [67; 32]);
            let membership = ControlRecord::sign(
                ControlRecordHeader {
                    resource_id: RESOURCE,
                    sequence: bytes.len() as u64,
                    previous: Some(previous),
                    issuer: *owner.descriptor().id(),
                },
                ControlBody::CapabilityGrant(CapabilityGrantBody {
                    subject: next_root.descriptor().clone(),
                    abilities: vec![1],
                    delegable: vec![],
                    parent: None,
                    claim_limit: None,
                }),
                &owner,
            )
            .unwrap();
            previous = membership.id();
            bytes.push(membership.signed_object().bytes().to_vec());
            root = Some(next_root);
        }
        let root = root.as_ref().unwrap();
        let mut seed = [44; 32];
        seed[..8].copy_from_slice(&((n / grants_per_device) as u64).to_be_bytes());
        let device = PrincipalKeys::from_secrets(&seed, [45; 32]);
        first.get_or_insert(*device.descriptor().id());
        let mut serial = [0; 16];
        serial[..8].copy_from_slice(&(n as u64).to_be_bytes());
        let cert = DeviceCertificate::sign(
            DeviceCertificatePayload {
                root: *root.descriptor().id(),
                device: device.descriptor().clone(),
                kind: DeviceKind::Personal,
                mask: vec![1],
                scope: vec![],
                serial,
            },
            root,
        )
        .unwrap();
        let chain = CertificateChain::new(vec![cert], root.descriptor().id()).unwrap();
        let record = ControlRecord::sign(
            ControlRecordHeader {
                resource_id: RESOURCE,
                sequence: bytes.len() as u64,
                previous: Some(previous),
                issuer: *root.descriptor().id(),
            },
            ControlBody::DeviceGrant(DeviceGrantBody {
                root: *root.descriptor().id(),
                chain,
                pairing_device: None,
            }),
            root,
        )
        .unwrap();
        previous = record.id();
        bytes.push(record.signed_object().bytes().to_vec());
    }
    (bytes, first.unwrap())
}

#[test]
#[ignore = "manual 1600-record replay benchmark; run in release with --nocapture"]
fn identity_replay_1600_records_has_bounded_per_record_storage() {
    for recertify in [false, true] {
        let mut previous_bytes = None;
        for count in [400, 800, 1600] {
            let (records, first) = records(count, recertify);
            let refs: Vec<_> = records.iter().map(Vec::as_slice).collect();
            let before = LIVE.load(Ordering::Relaxed);
            let started = Instant::now();
            let (outcome, history) = validate_authorized(&refs, None).unwrap();
            let elapsed = started.elapsed();
            let retained = LIVE.load(Ordering::Relaxed) - before;
            assert!(matches!(outcome, ChainOutcome::Linear(_)));
            assert_eq!(history.len(), records.len());
            assert_eq!(
                history.last().unwrap().devices().count(),
                if recertify { count / 8 } else { count }
            );
            assert!(history[1].device(&first).is_none());
            // Sharing must include certificate bytes, not just map metadata.
            if !recertify {
                let early = history[2].device(&first).unwrap().chain.as_ref().unwrap();
                let late = history
                    .last()
                    .unwrap()
                    .device(&first)
                    .unwrap()
                    .chain
                    .as_ref()
                    .unwrap();
                assert!(std::sync::Arc::ptr_eq(early, late));
            }
            if let Some(previous) = previous_bytes {
                // Reject the old ~4x growth on doubling. Patricia path widths
                // are fixed; practical doubling is ~2x with a small depth cost.
                assert!(
                    retained < previous * 26 / 10,
                    "quadratic storage: {previous} -> {retained}"
                );
            }
            eprintln!("recertify={recertify} records={count}: replay={elapsed:?}, retained={retained} bytes, bytes/record={}",retained/count);
            previous_bytes = Some(retained);
            drop((outcome, history));
        }
    }
}
