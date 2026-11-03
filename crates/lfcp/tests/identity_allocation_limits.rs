//! Hostile advertised lengths must fail before any heap allocation. The
//! counter is thread-local so the required two-thread test run is safe.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use lfcp::base::{PrincipalId, WireCode};
use lfcp::cbor::{self, Value};
use lfcp::cose;
use lfcp::principal::PrincipalKeys;
use lfcp::wire::control::device::{CertificateChain, DeviceCertificate, CERTIFICATE_DOMAIN};
use lfcp::wire::control::ReceivedControlRecord;

struct Counted;
thread_local! {
    static ALLOCATIONS: Cell<Option<usize>> = const { Cell::new(None) };
}
fn allocated() {
    let _ = ALLOCATIONS.try_with(|count| {
        if let Some(n) = count.get() {
            count.set(Some(n + 1));
        }
    });
}
unsafe impl GlobalAlloc for Counted {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        allocated();
        // SAFETY: forward the allocator contract unchanged to System.
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        allocated();
        // SAFETY: forward the allocator contract unchanged to System.
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        allocated();
        // SAFETY: the pointer/layout originate from this System allocator.
        unsafe { System.realloc(ptr, layout, size) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the pointer/layout originate from this System allocator.
        unsafe { System.dealloc(ptr, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: Counted = Counted;

fn no_alloc<T: std::fmt::Debug>(f: impl FnOnce() -> Result<T, lfcp::base::Error>) {
    ALLOCATIONS.with(|n| n.set(Some(0)));
    let result = f();
    let count = ALLOCATIONS.with(|n| n.replace(None).unwrap());
    assert_eq!(count, 0);
    assert_eq!(
        result.unwrap_err().wire_code(),
        Some(WireCode::MalformedMessage)
    );
}

fn envelope(payload: Vec<u8>) -> Vec<u8> {
    let key = PrincipalKeys::from_secrets(&[1; 32], [2; 32]);
    cbor::encode(&Value::Array(vec![
        Value::bytes(cose::protected_header(key.descriptor().id())),
        Value::Map(vec![]),
        Value::bytes(payload),
        Value::bytes(vec![0; 64]),
    ]))
    .unwrap()
}

#[test]
fn chain_length_is_checked_before_even_decoding_the_first_certificate() {
    for bytes in [
        vec![0x80],
        vec![0x85],
        vec![0x9b, 255, 255, 255, 255, 255, 255, 255, 255],
        cbor::encode(&Value::Array(vec![Value::bytes(vec![0; 1024]); 5])).unwrap(),
    ] {
        no_alloc(|| CertificateChain::parse(&bytes, &PrincipalId::from_bytes([1; 32])));
    }
}

#[test]
fn certificate_mask_and_scope_counts_are_checked_before_cbor_allocation() {
    let device = PrincipalKeys::from_secrets(&[3; 32], [4; 32]);
    for (mask_len, scope_len) in [(33, 0), (1, 65)] {
        let payload = cbor::encode(&Value::Array(vec![
            Value::text(CERTIFICATE_DOMAIN),
            Value::bytes(vec![1; 32]),
            device.descriptor().to_value(),
            Value::Unsigned(1),
            Value::Array(vec![Value::Unsigned(1); mask_len]),
            Value::Array(vec![Value::bytes(vec![1; 32]); scope_len]),
            Value::bytes(vec![0; 16]),
        ]))
        .unwrap();
        let bytes = envelope(payload);
        no_alloc(|| DeviceCertificate::parse(&bytes));
        let chain_bytes = cbor::encode(&Value::Array(vec![Value::bytes(bytes.clone())])).unwrap();
        no_alloc(|| CertificateChain::parse(&chain_bytes, &PrincipalId::from_bytes([1; 32])));
        for (control_type, key) in [(0, 5), (6, 2), (9, 1)] {
            // Other fields are irrelevant: this preflight must run before
            // the outer payload/body is allocated or semantically checked.
            let payload = cbor::encode(&Value::Map(vec![
                (Value::Unsigned(3), Value::Unsigned(control_type)),
                (
                    Value::Unsigned(5),
                    Value::Map(vec![(
                        Value::Unsigned(key),
                        Value::Array(vec![Value::bytes(bytes.clone())]),
                    )]),
                ),
            ]))
            .unwrap();
            let record = envelope(payload);
            no_alloc(|| ReceivedControlRecord::parse(&record));
        }
    }
}

#[test]
fn embedded_chain_count_is_checked_before_outer_payload_allocation() {
    for (control_type, key) in [(0, 5), (6, 2), (9, 1)] {
        let payload = cbor::encode(&Value::Map(vec![
            (Value::Unsigned(3), Value::Unsigned(control_type)),
            (
                Value::Unsigned(5),
                Value::Map(vec![(
                    Value::Unsigned(key),
                    Value::Array(vec![Value::bytes(vec![0; 1024]); 5]),
                )]),
            ),
        ]))
        .unwrap();
        let record = envelope(payload);
        no_alloc(|| ReceivedControlRecord::parse(&record));
    }
}

#[test]
fn managing_leaf_depth_limit_is_checked_before_decoding_certificates() {
    use lfcp::wire::control::device::{DeviceCertificatePayload, DeviceKind};
    let root = PrincipalKeys::from_secrets(&[1; 32], [2; 32]);
    let certificates: Vec<_> = (3..7)
        .map(|n| {
            DeviceCertificate::sign(
                DeviceCertificatePayload {
                    root: *root.descriptor().id(),
                    device: PrincipalKeys::from_secrets(&[n; 32], [n + 1; 32])
                        .descriptor()
                        .clone(),
                    kind: DeviceKind::Personal,
                    mask: vec![1, 2, 12],
                    scope: vec![],
                    serial: [n; 16],
                },
                &root,
            )
            .unwrap()
        })
        .map(|cert| Value::bytes(cert.signed_object().bytes().to_vec()))
        .collect();
    let chain = Value::Array(certificates);
    no_alloc(|| CertificateChain::from_value(&chain, root.descriptor().id()));
    let bytes = cbor::encode(&chain).unwrap();
    no_alloc(|| CertificateChain::parse(&bytes, root.descriptor().id()));
    let payload = cbor::encode(&Value::Map(vec![
        (Value::Unsigned(3), Value::Unsigned(9)),
        (
            Value::Unsigned(5),
            Value::Map(vec![(Value::Unsigned(1), chain)]),
        ),
    ]))
    .unwrap();
    let record = envelope(payload);
    no_alloc(|| ReceivedControlRecord::parse(&record));
}
