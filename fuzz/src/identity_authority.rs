//! Shared stateful identity harness: full replay vs resume, immutable historical
//! heads, deterministic errors, byte replays, binding invariants and exposure.
//! Bounded programs retain valid outer signatures so mutations reach authority.

use lfcp::base::{Hash32, PrincipalId, ResourceId};
use lfcp::principal::PrincipalKeys;
use lfcp::wire::control::authority::{validate_authorized, ControlState};
use lfcp::wire::control::body::*;
use lfcp::wire::control::chain::ChainOutcome;
use lfcp::wire::control::device::*;
use lfcp::wire::control::{ControlRecord, ControlRecordHeader};
use lfcp::{cbor, cose};

const RESOURCE: ResourceId = ResourceId::from_bytes([77; 32]);
fn keys(n: u8) -> PrincipalKeys {
    PrincipalKeys::from_secrets(&[n; 32], [n + 100; 32])
}
fn id(n: u8) -> PrincipalId {
    *keys(n).descriptor().id()
}
fn payload(root: u8, device: u8, kind: DeviceKind, serial: u8) -> DeviceCertificatePayload {
    DeviceCertificatePayload {
        root: id(root),
        device: keys(device).descriptor().clone(),
        kind,
        mask: if kind == DeviceKind::Personal {
            vec![1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 13]
        } else {
            vec![1, 2]
        },
        scope: if kind == DeviceKind::Personal {
            vec![]
        } else {
            vec![RESOURCE]
        },
        serial: [serial; 16],
    }
}
fn certificate(p: DeviceCertificatePayload, signer: u8) -> DeviceCertificate {
    DeviceCertificate::sign(p, &keys(signer)).unwrap()
}
fn chain(certs: Vec<DeviceCertificate>) -> CertificateChain {
    let root = certs[0].payload().root;
    CertificateChain::new(certs, &root).unwrap()
}
fn corrupt(bytes: &[u8]) -> Vec<u8> {
    let mut bytes = bytes.to_vec();
    *bytes.last_mut().unwrap() ^= 1;
    bytes
}

fn genesis(device: bool) -> Vec<u8> {
    ControlRecord::sign(
        ControlRecordHeader {
            resource_id: RESOURCE,
            sequence: 0,
            previous: None,
            issuer: id(if device { 3 } else { 1 }),
        },
        ControlBody::Genesis(GenesisBody {
            data_profile: "org.openlfcp.identity.v1".into(),
            owner: keys(1).descriptor().clone(),
            dek_commitment: Hash32::from_bytes([0; 32]),
            endpoints: vec![Endpoint {
                url: "wss://example.test/".into(),
                priority: 0,
                flags: None,
            }],
            coordinator: "wss://example.test/".into(),
            device_chain: device
                .then(|| chain(vec![certificate(payload(1, 3, DeviceKind::Personal, 3), 1)])),
        }),
        &keys(if device { 3 } else { 1 }),
    )
    .unwrap()
    .signed_object()
    .bytes()
    .to_vec()
}

fn sign(state: &ControlState, body: ControlBody, signer: u8) -> Vec<u8> {
    ControlRecord::sign(
        ControlRecordHeader {
            resource_id: RESOURCE,
            sequence: state.head.sequence + 1,
            previous: Some(state.head.id),
            issuer: id(signer),
        },
        body,
        &keys(signer),
    )
    .unwrap()
    .signed_object()
    .bytes()
    .to_vec()
}

fn candidate(state: &ControlState, c: &[u8; 8]) -> Vec<u8> {
    let root = 1 + c[1] % 2;
    let device = 3 + c[2] % 6;
    let signer = 1 + c[3] % 8;
    let kind = match c[4] % 3 {
        0 => DeviceKind::Personal,
        1 => DeviceKind::Service,
        _ => DeviceKind::Pairing,
    };
    let mut p = payload(root, device, kind, c[5]);
    let body = match c[0] % 8 {
        0 => {
            if c[6] & 1 != 0 && kind == DeviceKind::Personal {
                p.mask = vec![1];
            }
            if c[6] & 8 != 0 && kind != DeviceKind::Personal {
                p.scope = vec![ResourceId::from_bytes([88; 32])];
            }
            let nested = c[6] & 4 != 0 && device != 3;
            let mut cert = certificate(p, if nested { 3 } else { root });
            if c[7] & 4 != 0 {
                cert = DeviceCertificate::parse(&corrupt(cert.signed_object().bytes())).unwrap();
            }
            let mut certs = vec![cert];
            if nested {
                certs.push(certificate(payload(root, 3, DeviceKind::Personal, 3), root));
            }
            ControlBody::DeviceGrant(DeviceGrantBody {
                root: id(root),
                chain: chain(certs),
                pairing_device: (kind != DeviceKind::Pairing && c[6] & 2 != 0).then(|| id(5)),
            })
        }
        1 => {
            let reason = c[4] as u64 % 5;
            ControlBody::DeviceRevoke(DeviceRevokeBody {
                root: id(root),
                device: id(device),
                reason,
                approval: (reason == 3).then(|| {
                    payload(root, 4, DeviceKind::Personal, c[5])
                        .digest()
                        .unwrap()
                }),
            })
        }
        2 => ControlBody::CapabilityGrant(CapabilityGrantBody {
            subject: keys(root).descriptor().clone(),
            abilities: vec![1, 2, 4, 5],
            delegable: vec![1, 2],
            parent: None,
            claim_limit: None,
        }),
        3 => ControlBody::CapabilityRevoke(CapabilityRevokeBody {
            grant: state.grants().next().map_or(state.head.id, |g| g.id),
        }),
        4 => ControlBody::RouteUpdate(RouteUpdateBody {
            version: state.route_version + 1,
            endpoints: vec![Endpoint {
                url: "wss://example.test/".into(),
                priority: 0,
                flags: None,
            }],
            coordinator: "wss://example.test/".into(),
        }),
        5 => ControlBody::KeyEpoch(KeyEpochBody {
            epoch: state.current_epoch + 1,
            dek_commitment: Hash32::from_bytes([c[5]; 32]),
            final_frontier: lfcp::wire::frontier::Frontier::new(vec![]).unwrap(),
            reason: 2,
        }),
        6 => {
            let mut offer = cose::sign(
                &cbor::encode(
                    &OwnerTransferOffer {
                        resource_id: RESOURCE,
                        control_head: Hash32::from_bytes(*state.head.id.as_bytes()),
                        next_sequence: state.head.sequence + 1,
                        new_owner: keys(root).descriptor().clone(),
                        nonce: [c[5]; 16],
                    }
                    .to_value(),
                )
                .unwrap(),
                &keys(1),
            )
            .unwrap()
            .bytes()
            .to_vec();
            let offer_id = lfcp::crypto::sha256(&offer);
            let certificates = (c[6] & 1 != 0).then(|| {
                chain(vec![certificate(
                    payload(root, device, DeviceKind::Personal, c[5]),
                    root,
                )])
            });
            let mut accept = cose::sign(
                &cbor::encode(
                    &OwnerTransferAccept {
                        resource_id: RESOURCE,
                        offer: offer_id,
                        new_owner: id(root),
                    }
                    .to_value(),
                )
                .unwrap(),
                &keys(if certificates.is_some() { device } else { root }),
            )
            .unwrap()
            .bytes()
            .to_vec();
            if c[7] & 4 != 0 {
                offer = corrupt(&offer);
            }
            if c[7] & 8 != 0 {
                accept = corrupt(&accept);
            }
            ControlBody::OwnerTransferCommit(OwnerTransferCommitBody {
                offer,
                accept,
                device_chain: certificates,
            })
        }
        _ => return genesis(c[6] & 1 != 0),
    };
    let bytes = sign(state, body, signer);
    if c[7] & 1 != 0 {
        corrupt(&bytes)
    } else {
        bytes
    }
}

fn replay(records: &[Vec<u8>]) -> (ChainOutcome, Vec<ControlState>) {
    validate_authorized(&records.iter().map(Vec::as_slice).collect::<Vec<_>>(), None).unwrap()
}

/// Byte 0: bit 0 selects a bounded signed program, bit 1 device Genesis.
/// Programs consist of eight-byte commands (at most 24); raw mode treats the
/// remaining bytes as one untrusted candidate on a valid Genesis prefix.
pub fn check(data: &[u8]) {
    let Some(&mode) = data.first() else {
        return;
    };
    let mut records = vec![genesis(mode & 2 != 0)];
    let (_, mut states) = replay(&records);
    let candidates: Vec<_> = if mode & 1 == 0 {
        vec![data[1..].to_vec()]
    } else {
        vec![]
    };
    let steps = if mode & 1 == 0 {
        1
    } else {
        (data.len() - 1).div_ceil(8).min(24)
    };
    for step in 0..steps {
        let previous = states.last().unwrap();
        let unchanged = previous.clone();
        let bytes = if mode & 1 == 0 {
            candidates[0].clone()
        } else {
            let mut c = [0; 8];
            let input = &data[1 + step * 8..(1 + (step + 1) * 8).min(data.len())];
            c[..input.len()].copy_from_slice(input);
            candidate(previous, &c)
        };
        let result = validate_authorized(&[&bytes], Some(previous.clone()));
        assert_eq!(
            result,
            validate_authorized(&[&bytes], Some(previous.clone()))
        );
        assert_eq!(previous, &unchanged);
        if let Ok((ChainOutcome::Linear(_), next)) = result {
            let next = next.into_iter().next().unwrap();
            for (id, d) in next.devices() {
                assert!(!next.holds(&id, 11));
                assert!(d.grants_accepted <= 8);
                if let Some(old) = previous.device(&id) {
                    assert!(d.grants_accepted >= old.grants_accepted);
                    assert_eq!(
                        (&old.root, &old.kind, &old.mask, &old.scope),
                        (&d.root, &d.kind, &d.mask, &d.scope)
                    );
                }
                if next.revocation(&d.root, &id).is_some() {
                    assert!(next.active_device(&id).is_none());
                }
            }
            for (root, device, revoke) in previous.revocations() {
                assert_eq!(next.revocation(&root, &device), Some(revoke));
            }
            if matches!(
                lfcp::wire::control::ReceivedControlRecord::parse(&bytes)
                    .unwrap()
                    .body(),
                ControlBody::DeviceRevoke(_)
            ) {
                let lost = previous
                    .devices()
                    .any(|(id, d)| d.registered && previous.holds(&id, 1) && !next.holds(&id, 1));
                assert_eq!(next.last_exposing_revocation == Some(next.head), lost);
            }
            records.push(bytes);
            states.push(next);
            let (_, rebuilt) = replay(&records);
            assert_eq!(rebuilt, states);
            let mut repeated = records.clone();
            repeated.push(records.last().unwrap().clone());
            assert_eq!(replay(&repeated).1, states);
        }
    }
}

/// Valid commands exercise approval, cascade, re-certification and transfers
/// from the first mutation run, without requiring discovery of signatures.
#[allow(dead_code)] // Used by the standalone driver, not the libFuzzer entry point.
pub fn seeds() -> Vec<Vec<u8>> {
    let commands: [u8; 64] = [
        0, 0, 3, 0, 0, 6, 4, 0, // register leaf 6 through manager 3
        0, 0, 2, 0, 2, 5, 0, 0, // register pairing 5
        1, 0, 2, 0, 3, 4, 0, 0, // consume 5, approving leaf 4's payload
        0, 0, 1, 0, 0, 4, 2, 0, // register approved leaf 4
        1, 0, 0, 0, 2, 0, 0, 0, // revoke manager 3, suspending leaf 6
        0, 0, 3, 0, 0, 9, 0, 0, // re-certify leaf 6 directly from root
        6, 1, 3, 1, 0, 6, 1, 0, // transfer with a device chain (wrong commit signer)
        1, 0, 1, 0, 2, 0, 0, 0, // revoke leaf 4
    ];
    let mut program = vec![3];
    program.extend(commands);
    let (_, history) = replay(&[genesis(false)]);
    let mut raw = vec![0];
    raw.extend(candidate(
        history.last().unwrap(),
        &[0, 0, 1, 0, 0, 4, 0, 0],
    ));
    let mut grant_limit = vec![1];
    for serial in 1..=9 {
        grant_limit.extend([0, 0, 1, 0, 0, serial, 0, 0]);
    }
    vec![program, raw, grant_limit]
}
