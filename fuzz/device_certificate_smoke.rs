//! Standalone fallback when cargo-fuzz/nightly are unavailable. Compile with
//! rustc against the already built lfcp rlib (see fuzz/README.md).

#[path = "src/device_certificate.rs"]
mod device_certificate;

use lfcp::base::{ControlRecordId, ResourceId};
use lfcp::principal::PrincipalKeys;
use lfcp::wire::control::body::{ControlBody, DeviceGrantBody};
use lfcp::wire::control::device::{
    CertificateChain, DeviceCertificate, DeviceCertificatePayload, DeviceKind,
};
use lfcp::wire::control::{ControlRecord, ControlRecordHeader};

fn main() {
    let root = PrincipalKeys::from_secrets(&[1; 32], [101; 32]);
    let device = PrincipalKeys::from_secrets(&[2; 32], [102; 32]);
    let mut seeds = Vec::new();
    // All kinds and the integer-head boundaries exercise the scanner's
    // mask/scope branches against the independent full-parser verdict.
    for (kind, mask, scope) in [
        (DeviceKind::Personal, vec![1, 2, 12, 13], vec![]),
        (
            DeviceKind::Service,
            vec![1, 23, 24, 255, 256, 65535, 65536, u64::MAX],
            vec![ResourceId::from_bytes([77; 32])],
        ),
        (
            DeviceKind::Pairing,
            vec![1, 2],
            vec![ResourceId::from_bytes([77; 32])],
        ),
    ] {
        let certificate = DeviceCertificate::sign(
            DeviceCertificatePayload {
                root: *root.descriptor().id(),
                device: device.descriptor().clone(),
                kind,
                mask,
                scope,
                serial: [1; 16],
            },
            &root,
        )
        .unwrap();
        let chain =
            CertificateChain::new(vec![certificate.clone()], root.descriptor().id()).unwrap();
        let record = ControlRecord::sign(
            ControlRecordHeader {
                resource_id: ResourceId::from_bytes([77; 32]),
                sequence: 1,
                previous: Some(ControlRecordId::from_bytes([8; 32])),
                issuer: *root.descriptor().id(),
            },
            ControlBody::DeviceGrant(DeviceGrantBody {
                root: *root.descriptor().id(),
                chain: chain.clone(),
                pairing_device: None,
            }),
            &root,
        )
        .unwrap();
        seeds.extend([
            certificate.signed_object().bytes().to_vec(),
            chain.encode(),
            record.signed_object().bytes().to_vec(),
        ]);
    }
    let mut count = 0;
    for seed in seeds {
        device_certificate::check(&seed);
        for i in 0..seed.len() {
            device_certificate::check(&seed[..i]);
            count += 1;
            for bit in 0..8 {
                let mut mutated = seed.clone();
                mutated[i] ^= 1 << bit;
                device_certificate::check(&mutated);
                count += 1;
            }
        }
    }
    println!("{count} truncations and single-bit mutations passed");
}
