//! Local vectors for identity draft rev. 3. Official vectors and the new
//! normative baseline will be supplied by LFCP-04-401; the existing pin stays.

use lfcp::base::{
    AuthorityRule, ControlRecordId, Error, Hash32, PrincipalId, ResourceId, WireCode,
};
use lfcp::cbor::{self, Value};
use lfcp::cose;
use lfcp::crypto;
use lfcp::principal::{principal_id, PrincipalKeys};
use lfcp::wire::control::body::*;
use lfcp::wire::control::device::*;
use lfcp::wire::control::{ControlRecord, ControlRecordHeader, ReceivedControlRecord};

fn keys(n: u8) -> PrincipalKeys {
    PrincipalKeys::from_secrets(&[n; 32], [n + 100; 32])
}
fn root() -> PrincipalId {
    *keys(1).descriptor().id()
}
fn resource() -> ResourceId {
    ResourceId::from_bytes([77; 32])
}
fn payload(
    device: u8,
    kind: DeviceKind,
    mask: &[u64],
    scope: &[ResourceId],
) -> DeviceCertificatePayload {
    DeviceCertificatePayload {
        root: root(),
        device: keys(device).descriptor().clone(),
        kind,
        mask: mask.to_vec(),
        scope: scope.to_vec(),
        serial: [device; 16],
    }
}
fn personal(device: u8, mask: &[u64]) -> DeviceCertificatePayload {
    payload(device, DeviceKind::Personal, mask, &[])
}
fn cert(payload: DeviceCertificatePayload, signer: u8) -> DeviceCertificate {
    DeviceCertificate::sign(payload, &keys(signer)).unwrap()
}
fn chain(certs: Vec<DeviceCertificate>) -> CertificateChain {
    CertificateChain::new(certs, &root()).unwrap()
}
fn signed(value: &Value, signer: u8) -> Vec<u8> {
    cose::sign(&cbor::encode(value).unwrap(), &keys(signer))
        .unwrap()
        .bytes()
        .to_vec()
}
fn replace(value: &Value, index: usize, replacement: Value) -> Value {
    let mut fields = value.as_array().unwrap().to_vec();
    fields[index] = replacement;
    Value::Array(fields)
}
fn field(value: &Value, key: u64, replacement: Option<Value>) -> Value {
    let mut fields = value.as_map().unwrap().to_vec();
    fields.retain(|(k, _)| k != &Value::Unsigned(key));
    if let Some(v) = replacement {
        fields.push((Value::Unsigned(key), v));
    }
    Value::Map(fields)
}
fn wire<T: std::fmt::Debug>(result: Result<T, Error>, code: WireCode) {
    assert_eq!(result.unwrap_err().wire_code(), Some(code));
}
fn broken_signature(cert: &DeviceCertificate) -> DeviceCertificate {
    let object = cbor::decode_strict(cert.signed_object().bytes()).unwrap();
    let mut signature = cert.signed_object().signature().to_vec();
    signature[0] ^= 1;
    DeviceCertificate::parse(&cbor::encode(&replace(&object, 3, Value::bytes(signature))).unwrap())
        .unwrap()
}
fn header(issuer: u8, genesis: bool) -> ControlRecordHeader {
    ControlRecordHeader {
        resource_id: resource(),
        sequence: if genesis { 0 } else { 1 },
        previous: if genesis {
            None
        } else {
            Some(ControlRecordId::from_bytes([8; 32]))
        },
        issuer: *keys(issuer).descriptor().id(),
    }
}
fn record_body(body: ControlBody, issuer: u8) -> ControlRecord {
    ControlRecord::sign(
        header(issuer, matches!(body, ControlBody::Genesis(_))),
        body,
        &keys(issuer),
    )
    .unwrap()
}
fn raw_record(control_type: u64, body: Value) -> Vec<u8> {
    signed(
        &Value::Map(vec![
            (
                Value::Unsigned(0),
                Value::bytes(resource().as_bytes().to_vec()),
            ),
            (Value::Unsigned(1), Value::Unsigned(1)),
            (Value::Unsigned(2), Value::bytes(vec![8; 32])),
            (Value::Unsigned(3), Value::Unsigned(control_type)),
            (Value::Unsigned(4), Value::bytes(root().as_bytes().to_vec())),
            (Value::Unsigned(5), body),
        ]),
        1,
    )
}
fn grant(chain: CertificateChain) -> ControlBody {
    ControlBody::DeviceGrant(DeviceGrantBody {
        root: root(),
        chain,
        pairing_device: None,
    })
}

#[test]
fn certificates_round_trip_all_kinds_and_exact_digests() {
    for p in [
        personal(2, &[13, 12, 2, 1, 9, 11, u64::MAX]),
        payload(2, DeviceKind::Service, &[1, 2], &[resource()]),
        payload(2, DeviceKind::Pairing, &[2, 1], &[resource()]),
    ] {
        let expected_digest = p.digest().unwrap();
        let certificate = cert(p.clone(), 1);
        let bytes = certificate.signed_object().bytes();
        assert_eq!(DeviceCertificate::parse(bytes).unwrap(), certificate);
        assert_eq!(certificate.id(), crypto::sha256(bytes));
        assert_eq!(certificate.payload_digest(), expected_digest);
        assert_ne!(certificate.id(), expected_digest);
        assert_eq!(
            certificate.signed_object().payload_bytes(),
            p.encode().unwrap()
        );
        let c = chain(vec![certificate]);
        assert_eq!(CertificateChain::parse(&c.encode(), &root()).unwrap(), c);
        assert!(
            verify_chain(
                &c,
                &root(),
                Some(keys(1).descriptor()),
                &resource(),
                &EmptyChainState
            )
            .unwrap()
            .in_scope
        );
        let mut next = p;
        next.serial[0] ^= 1;
        assert_ne!(cert(next, 1).id(), c.leaf().id());
    }
}

#[test]
fn payload_shapes_and_every_field_are_closed_and_typed() {
    let good = personal(2, &[1, 2]).to_value();
    let mut cases = vec![
        Value::Map(vec![]),
        Value::Array(vec![]),
        replace(&good, 0, Value::text("LFCP-DEVICE-CERT-v2")),
    ];
    let mut extra = good.as_array().unwrap().to_vec();
    extra.push(Value::Null);
    cases.push(Value::Array(extra));
    for (i, v) in [
        (0, Value::bytes(CERTIFICATE_DOMAIN.as_bytes().to_vec())),
        (1, Value::bytes(vec![0; 31])),
        (1, Value::Unsigned(1)),
        (2, Value::Array(vec![])),
        (3, Value::Unsigned(3)),
        (3, Value::int(-1)),
        (3, Value::text("0")),
        (4, Value::Null),
        (5, Value::Null),
        (6, Value::bytes(vec![0; 15])),
        (6, Value::bytes(vec![0; 17])),
        (6, Value::text("0123456789abcdef")),
    ] {
        cases.push(replace(&good, i, v));
    }
    let descriptor = keys(2).descriptor().to_value();
    cases.push(replace(&good, 2, field(&descriptor, 3, Some(Value::Null))));
    cases.push(replace(&good, 2, field(&descriptor, 1, None)));
    cases.push(replace(
        &good,
        2,
        field(&descriptor, 0, Some(Value::bytes(vec![0; 32]))),
    ));
    // A small-order Ed25519 key with a correctly recomputed ID is still malformed.
    let invalid = field(
        &field(&descriptor, 1, Some(Value::bytes(vec![0; 32]))),
        0,
        Some(Value::bytes(
            principal_id(&[0; 32], keys(2).descriptor().x25519_public())
                .as_bytes()
                .to_vec(),
        )),
    );
    cases.push(replace(&good, 2, invalid));
    cases.push(replace(
        &good,
        1,
        Value::bytes(keys(2).descriptor().id().as_bytes().to_vec()),
    ));
    for (i, value) in cases.iter().enumerate() {
        let error = DeviceCertificate::parse(&signed(value, 1)).unwrap_err();
        assert_eq!(
            error.wire_code(),
            Some(WireCode::MalformedMessage),
            "case {i}: {error:?}"
        );
    }
}

#[test]
fn kind_mask_scope_rules_and_limits_apply_to_readers_and_writers() {
    let mut cases = vec![
        personal(2, &[]),
        personal(2, &[1, 1]),
        personal(2, &[12]),
        personal(2, &[1, 12]),
        personal(2, &[2, 12]),
        payload(2, DeviceKind::Personal, &[1], &[resource()]),
        payload(2, DeviceKind::Service, &[1], &[]),
        payload(2, DeviceKind::Service, &[1, 2, 12], &[resource()]),
        payload(2, DeviceKind::Service, &[13], &[resource()]),
        payload(2, DeviceKind::Pairing, &[1], &[]),
        payload(
            2,
            DeviceKind::Pairing,
            &[1],
            &[resource(), ResourceId::from_bytes([9; 32])],
        ),
        payload(2, DeviceKind::Pairing, &[1, 2, 12], &[resource()]),
        payload(2, DeviceKind::Pairing, &[3], &[resource()]),
        payload(2, DeviceKind::Service, &[1], &[resource(), resource()]),
    ];
    cases.push(personal(2, &(100..133).collect::<Vec<_>>()));
    cases.push(payload(
        2,
        DeviceKind::Service,
        &[1],
        &(0..65)
            .map(|n| ResourceId::from_bytes([n; 32]))
            .collect::<Vec<_>>(),
    ));
    for p in cases {
        wire(p.check(), WireCode::MalformedMessage);
        wire(
            DeviceCertificate::sign(p.clone(), &keys(1)),
            WireCode::MalformedMessage,
        );
        wire(
            DeviceCertificate::parse(&signed(&p.to_value(), 1)),
            WireCode::MalformedMessage,
        );
    }
    let max = payload(
        2,
        DeviceKind::Service,
        &(100..132).collect::<Vec<_>>(),
        &(0..64)
            .map(|n| ResourceId::from_bytes([n; 32]))
            .collect::<Vec<_>>(),
    );
    let cert = cert(max, 1);
    assert_eq!(
        DeviceCertificate::parse(cert.signed_object().bytes()).unwrap(),
        cert
    );
    for (index, item) in [
        (4, Value::text("1")),
        (4, Value::int(-1)),
        (5, Value::bytes(vec![1; 31])),
        (5, Value::Unsigned(0)),
    ] {
        wire(
            DeviceCertificate::parse(&signed(
                &replace(
                    &personal(2, &[1]).to_value(),
                    index,
                    Value::Array(vec![item]),
                ),
                1,
            )),
            WireCode::MalformedMessage,
        );
    }
}

#[test]
fn canonical_nested_bytes_and_cose_shape_are_required() {
    let cert = cert(personal(2, &[1]), 1);
    let object = cbor::decode_strict(cert.signed_object().bytes()).unwrap();
    let mut tagged = vec![0xd2];
    tagged.extend_from_slice(cert.signed_object().bytes());
    let mut trailing = cert.signed_object().bytes().to_vec();
    trailing.push(0);
    let payload = cert.signed_object().payload_bytes();
    let mut long_array = vec![0x98, 7];
    long_array.extend_from_slice(&payload[1..]);
    let protected = cert.signed_object().protected_bytes();
    let mut long_map = vec![0xb8, 2];
    long_map.extend_from_slice(&protected[1..]);
    let protected_value = cbor::decode_strict(protected).unwrap();
    let mut cases = vec![tagged, trailing];
    for (index, part) in [
        (0, Value::bytes(long_map)),
        (2, Value::bytes(long_array)),
        (
            0,
            Value::bytes(cbor::encode(&field(&protected_value, 1, Some(Value::int(-7)))).unwrap()),
        ),
        (
            0,
            Value::bytes(
                cbor::encode(&field(&protected_value, 4, Some(Value::bytes(vec![0; 31])))).unwrap(),
            ),
        ),
        (
            0,
            Value::bytes(cbor::encode(&field(&protected_value, 5, Some(Value::Null))).unwrap()),
        ),
        (1, Value::Map(vec![(Value::Unsigned(1), Value::Null)])),
        (2, Value::Null),
        (3, Value::bytes(vec![0; 63])),
    ] {
        cases.push(cbor::encode(&replace(&object, index, part)).unwrap());
    }
    for bytes in cases {
        wire(DeviceCertificate::parse(&bytes), WireCode::MalformedMessage);
        let body = Value::Map(vec![
            (Value::Unsigned(0), Value::bytes(root().as_bytes().to_vec())),
            (Value::Unsigned(1), Value::Array(vec![Value::bytes(bytes)])),
        ]);
        wire(
            ReceivedControlRecord::parse(&raw_record(9, body)),
            WireCode::MalformedMessage,
        );
    }
}

fn deep_chain(managing_leaf: bool) -> Vec<DeviceCertificate> {
    vec![
        cert(
            personal(5, if managing_leaf { &[1, 2, 12] } else { &[1, 2] }),
            4,
        ),
        cert(personal(4, &[1, 2, 12]), 3),
        cert(personal(3, &[1, 2, 12]), 2),
        cert(personal(2, &[1, 2, 12]), 1),
    ]
}

#[test]
fn chain_structure_root_uniqueness_and_depth_boundaries() {
    wire(
        CertificateChain::new(vec![], &root()),
        WireCode::MalformedMessage,
    );
    wire(
        CertificateChain::parse(&[0x80], &root()),
        WireCode::MalformedMessage,
    );
    wire(
        CertificateChain::from_value(&Value::Array(vec![Value::Null]), &root()),
        WireCode::MalformedMessage,
    );
    let mut too_deep = deep_chain(false);
    too_deep.push(cert(personal(6, &[1]), 1));
    wire(
        CertificateChain::new(too_deep, &root()),
        WireCode::MalformedMessage,
    );
    wire(
        CertificateChain::new(deep_chain(true), &root()),
        WireCode::MalformedMessage,
    );
    let one = cert(personal(2, &[1, 2, 12]), 1);
    wire(
        CertificateChain::new(vec![one.clone(), one], &root()),
        WireCode::MalformedMessage,
    );
    let mut foreign = personal(2, &[1]);
    foreign.root = *keys(9).descriptor().id();
    wire(
        CertificateChain::new(vec![cert(foreign, 9)], &root()),
        WireCode::MalformedMessage,
    );
    let c = chain(deep_chain(false));
    let verified = verify_chain(
        &c,
        &root(),
        Some(keys(1).descriptor()),
        &resource(),
        &EmptyChainState,
    )
    .unwrap();
    assert!(verified.in_scope);
    assert_eq!(
        verified.chain.issuers().copied().collect::<Vec<_>>(),
        [4, 3, 2].map(|n| *keys(n).descriptor().id())
    );
    let c = chain(deep_chain(true)[1..].to_vec());
    verify_chain(
        &c,
        &root(),
        Some(keys(1).descriptor()),
        &resource(),
        &EmptyChainState,
    )
    .unwrap();
}

#[test]
fn signatures_kids_dependencies_and_all_intrinsic_authority_errors() {
    let root_keys = keys(1);
    let check = |c: &CertificateChain| {
        verify_chain(
            c,
            &root(),
            Some(root_keys.descriptor()),
            &resource(),
            &EmptyChainState,
        )
        .map(|v| v.in_scope)
    };
    let valid = chain(deep_chain(false));
    assert_eq!(
        valid.verify_signatures(None),
        Err(Error::IssuerUnknown(root()))
    );
    wire(valid.verify_signatures(None), WireCode::MissingDependency);
    assert_eq!(
        valid.verify_signatures(Some(keys(9).descriptor())),
        Err(Error::CoseKidMismatch)
    );
    for index in 0..valid.certificates().len() {
        let mut certs = valid.certificates().to_vec();
        certs[index] = broken_signature(&certs[index]);
        assert_eq!(check(&chain(certs)), Err(Error::SignatureInvalid));
    }
    let wrong_leaf_kid = chain(vec![
        cert(personal(3, &[1]), 1),
        cert(personal(2, &[1, 2, 12]), 1),
    ]);
    assert_eq!(check(&wrong_leaf_kid), Err(Error::CoseKidMismatch));
    let wrong_root_kid = chain(vec![cert(personal(2, &[1]), 3)]);
    assert_eq!(check(&wrong_root_kid), Err(Error::CoseKidMismatch));
    for issuer in [
        personal(2, &[1, 2]),
        payload(2, DeviceKind::Service, &[1], &[resource()]),
        payload(2, DeviceKind::Pairing, &[1], &[resource()]),
    ] {
        let c = chain(vec![cert(personal(3, &[1]), 2), cert(issuer, 1)]);
        assert_eq!(
            check(&c),
            Err(Error::AuthorizationFailed(
                AuthorityRule::DeviceIssuerNotManaging
            ))
        );
    }
    for extra in [13, 9, 11, u64::MAX] {
        let c = chain(vec![
            cert(personal(3, &[1, extra]), 2),
            cert(personal(2, &[1, 2, 12]), 1),
        ]);
        assert_eq!(
            check(&c),
            Err(Error::AuthorizationFailed(
                AuthorityRule::DeviceMaskEscalation
            ))
        );
    }
    let c = chain(vec![cert(
        payload(
            2,
            DeviceKind::Pairing,
            &[1],
            &[ResourceId::from_bytes([0; 32])],
        ),
        1,
    )]);
    assert_eq!(
        check(&c),
        Err(Error::AuthorizationFailed(
            AuthorityRule::DevicePairingOutOfScope
        ))
    );
    wire(check(&c), WireCode::AuthorizationFailed);
    let c = chain(vec![cert(
        payload(
            2,
            DeviceKind::Service,
            &[1],
            &[ResourceId::from_bytes([0; 32])],
        ),
        1,
    )]);
    assert_eq!(check(&c), Ok(false));
}

#[test]
fn error_classes_are_global_not_per_certificate() {
    // A bad leaf signature never hides a malformed later certificate.
    let first = broken_signature(&cert(personal(3, &[13]), 2));
    let malformed = signed(&personal(2, &[]).to_value(), 1);
    let bytes = cbor::encode(&Value::Array(vec![
        Value::bytes(first.signed_object().bytes().to_vec()),
        Value::bytes(malformed),
    ]))
    .unwrap();
    wire(
        CertificateChain::parse(&bytes, &root()),
        WireCode::MalformedMessage,
    );
    // Missing dependency precedes bad signatures and authority.
    let c = chain(vec![first, cert(personal(2, &[1]), 1)]);
    wire(
        verify_chain(&c, &root(), None, &resource(), &EmptyChainState),
        WireCode::MissingDependency,
    );
    // A later signature failure precedes c3/c4 failures at the leaf link.
    let c = chain(vec![
        cert(personal(3, &[13]), 2),
        broken_signature(&cert(personal(2, &[1]), 1)),
    ]);
    assert_eq!(
        verify_chain(
            &c,
            &root(),
            Some(keys(1).descriptor()),
            &resource(),
            &EmptyChainState
        )
        .unwrap_err(),
        Error::SignatureInvalid
    );
    // Structural mismatch of the requested root precedes missing dependency.
    wire(
        verify_chain(
            &c,
            keys(8).descriptor().id(),
            None,
            &resource(),
            &EmptyChainState,
        ),
        WireCode::MalformedMessage,
    );
    // Within authority c3 wins over c4, then c4 wins over c6.
    let c = chain(vec![
        cert(
            payload(
                3,
                DeviceKind::Pairing,
                &[1],
                &[ResourceId::from_bytes([0; 32])],
            ),
            2,
        ),
        cert(personal(2, &[2]), 1),
    ]);
    assert_eq!(
        c.check_authority(&resource()),
        Err(Error::AuthorizationFailed(
            AuthorityRule::DeviceIssuerNotManaging
        ))
    );
}

#[test]
fn unsigned_preflight_rejects_n07_before_consume_or_leaf_signature() {
    let issuers = deep_chain(true)[1..].to_vec();
    wire(
        preflight_issuance(
            &personal(5, &[1, 2, 12]),
            &issuers,
            Some(keys(1).descriptor()),
            &resource(),
        ),
        WireCode::MalformedMessage,
    );
    for mask in [&[1, 2][..], &[1][..]] {
        assert_eq!(
            preflight_issuance(
                &personal(5, mask),
                &issuers,
                Some(keys(1).descriptor()),
                &resource()
            ),
            Ok(true)
        );
    }
    let service = payload(5, DeviceKind::Service, &[1], &[]);
    wire(
        preflight_issuance(&service, &issuers, None, &resource()),
        WireCode::MalformedMessage,
    );
    wire(
        preflight_issuance(&personal(5, &[1]), &deep_chain(false), None, &resource()),
        WireCode::MalformedMessage,
    );
    wire(
        preflight_issuance(&personal(5, &[1]), &issuers, None, &resource()),
        WireCode::MissingDependency,
    );
    wire(
        preflight_issuance(
            &personal(5, &[13]),
            &issuers,
            Some(keys(1).descriptor()),
            &resource(),
        ),
        WireCode::AuthorizationFailed,
    );
    let bad_issuers = vec![broken_signature(&cert(personal(2, &[1, 2, 12]), 1))];
    wire(
        preflight_issuance(
            &personal(5, &[1]),
            &bad_issuers,
            Some(keys(1).descriptor()),
            &resource(),
        ),
        WireCode::InvalidSignature,
    );
    assert_eq!(
        preflight_issuance(
            &personal(5, &[13]),
            &[],
            Some(keys(1).descriptor()),
            &resource()
        ),
        Ok(true)
    );
}

#[test]
fn device_grant_round_trip_approval_rules_and_closed_map() {
    for pairing_device in [None, Some(*keys(9).descriptor().id())] {
        let body = ControlBody::DeviceGrant(DeviceGrantBody {
            root: root(),
            chain: chain(vec![cert(personal(2, &[1]), 1)]),
            pairing_device,
        });
        let record = record_body(body.clone(), 1);
        let parsed = ReceivedControlRecord::parse(record.signed_object().bytes()).unwrap();
        assert_eq!(parsed.body(), &body);
        assert_eq!(parsed.verify(keys(1).descriptor()).unwrap(), record);
    }
    let body = grant(chain(vec![cert(personal(2, &[1]), 1)]));
    for malformed in [
        field(&body.to_value(), 0, None),
        field(&body.to_value(), 1, None),
        field(&body.to_value(), 2, Some(Value::bytes(vec![0; 31]))),
        field(&body.to_value(), 3, Some(Value::Null)),
        field(&body.to_value(), 1, Some(Value::Array(vec![]))),
        field(&body.to_value(), 0, Some(Value::bytes(vec![9; 32]))),
    ] {
        wire(
            ReceivedControlRecord::parse(&raw_record(9, malformed)),
            WireCode::MalformedMessage,
        );
    }
    let pairing = chain(vec![cert(
        payload(2, DeviceKind::Pairing, &[1], &[resource()]),
        1,
    )]);
    let bad = ControlBody::DeviceGrant(DeviceGrantBody {
        root: root(),
        chain: pairing,
        pairing_device: Some(*keys(9).descriptor().id()),
    });
    wire(bad.check_writable(), WireCode::MalformedMessage);
    wire(
        ControlBody::from_value(9, &bad.to_value()),
        WireCode::MalformedMessage,
    );
}

#[test]
fn device_revoke_reason_approval_reserved_field_and_unknown_type() {
    for reason in [0, 1, 2, 3, 4, u64::MAX] {
        let body = ControlBody::DeviceRevoke(DeviceRevokeBody {
            root: root(),
            device: *keys(2).descriptor().id(),
            reason,
            approval: (reason == 3).then_some(Hash32::from_bytes([9; 32])),
        });
        let record = record_body(body.clone(), 1);
        assert_eq!(
            ReceivedControlRecord::parse(record.signed_object().bytes())
                .unwrap()
                .body(),
            &body
        );
        for key in [0, 1, 2] {
            wire(
                ControlBody::from_value(10, &field(&body.to_value(), key, None)),
                WireCode::MalformedMessage,
            );
        }
        for value in [Value::Null, Value::Array(vec![]), Value::Unsigned(0)] {
            wire(
                ControlBody::from_value(10, &field(&body.to_value(), 3, Some(value))),
                WireCode::MalformedMessage,
            );
        }
        let wrong_approval = if reason == 3 {
            None
        } else {
            Some(Value::bytes(vec![0; 32]))
        };
        wire(
            ControlBody::from_value(10, &field(&body.to_value(), 4, wrong_approval)),
            WireCode::MalformedMessage,
        );
        wire(
            ControlBody::from_value(
                10,
                &field(
                    &body.to_value(),
                    1,
                    Some(Value::bytes(root().as_bytes().to_vec())),
                ),
            ),
            WireCode::MalformedMessage,
        );
    }
    assert_eq!(
        ControlBody::from_value(11, &Value::Map(vec![])),
        Err(Error::ControlUnknownCoreType(11))
    );
    assert_eq!(
        ControlBody::Extension {
            control_type: 11,
            body: Value::Null
        }
        .check_writable(),
        Err(Error::ControlUnknownCoreType(11))
    );
    wire(
        ReceivedControlRecord::parse(&raw_record(11, Value::Null)),
        WireCode::InvalidControlChain,
    );
}

fn genesis(device_chain: Option<CertificateChain>) -> ControlBody {
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
        device_chain,
    })
}

fn commit(device_chain: Option<CertificateChain>) -> ControlBody {
    let offer = signed(
        &OwnerTransferOffer {
            resource_id: resource(),
            control_head: Hash32::from_bytes([8; 32]),
            next_sequence: 1,
            new_owner: keys(1).descriptor().clone(),
            nonce: [9; 16],
        }
        .to_value(),
        8,
    );
    let accept = signed(
        &OwnerTransferAccept {
            resource_id: resource(),
            offer: crypto::sha256(&offer),
            new_owner: root(),
        }
        .to_value(),
        2,
    );
    ControlBody::OwnerTransferCommit(OwnerTransferCommitBody {
        offer,
        accept,
        device_chain,
    })
}

#[test]
fn genesis_and_commit_optional_chains_preserve_bytes_and_legacy_shape() {
    for chain in [None, Some(chain(vec![cert(personal(2, &[13]), 1)]))] {
        for (body, optional_key) in [(genesis(chain.clone()), 5), (commit(chain.clone()), 2)] {
            let record = record_body(body.clone(), 2);
            let parsed = ReceivedControlRecord::parse(record.signed_object().bytes()).unwrap();
            assert_eq!(parsed.body(), &body);
            assert_eq!(parsed.verify(keys(2).descriptor()).unwrap(), record);
            assert_eq!(
                body.to_value().get_uint(optional_key).is_some(),
                chain.is_some()
            );
            for bad in [
                Value::Null,
                Value::Array(vec![]),
                Value::Array(vec![Value::bytes(vec![])]),
            ] {
                wire(
                    ControlBody::from_value(
                        body.control_type(),
                        &field(&body.to_value(), optional_key, Some(bad)),
                    ),
                    WireCode::MalformedMessage,
                );
            }
        }
    }
}

#[test]
fn embedded_transfer_structure_precedes_outer_signature_with_or_without_chain() {
    for chain in [None, Some(chain(vec![cert(personal(2, &[13]), 1)]))] {
        let good = commit(chain);
        for key in [0, 1] {
            let bad = field(
                &good.to_value(),
                key,
                Some(Value::bytes(signed(&Value::Null, 1))),
            );
            let bytes = raw_record(6, bad);
            let mut object = cbor::decode_strict(&bytes)
                .unwrap()
                .as_array()
                .unwrap()
                .to_vec();
            object[3] = Value::bytes(vec![0; 64]);
            wire(
                ReceivedControlRecord::parse(&cbor::encode(&Value::Array(object)).unwrap()),
                WireCode::MalformedMessage,
            );
        }
    }
}

#[test]
fn codec_support_does_not_silently_enable_identity_transitions() {
    use lfcp::wire::control::authority::validate_authorized;
    let g = record_body(genesis(None), 1);
    let grant = record_body(grant(chain(vec![cert(personal(2, &[1]), 1)])), 1);
    let mut h = grant.header().clone();
    h.previous = Some(g.id());
    let grant = ControlRecord::sign(h, grant.body().clone(), &keys(1)).unwrap();
    let failure = validate_authorized(
        &[g.signed_object().bytes(), grant.signed_object().bytes()],
        None,
    )
    .unwrap_err();
    assert_eq!(failure.error, Error::UnsupportedInMvp(9));
    // An owner-signed Genesis must not silently ignore a supplied device chain.
    let g = record_body(genesis(Some(chain(vec![cert(personal(2, &[13]), 1)]))), 1);
    assert_eq!(
        validate_authorized(&[g.signed_object().bytes()], None)
            .unwrap_err()
            .error,
        Error::UnsupportedInMvp(0)
    );
}

#[test]
fn state_predicates_follow_all_signatures_and_intrinsic_rules_in_spec_order() {
    use std::cell::RefCell;
    #[derive(Default)]
    struct State {
        root_denied: bool,
        binding_denied: Option<PrincipalId>,
        revoked: Option<PrincipalId>,
        calls: RefCell<Vec<(&'static str, PrincipalId)>>,
    }
    impl ChainStateChecks for State {
        fn root_allowed(&self, root: &PrincipalId) -> bool {
            self.calls.borrow_mut().push(("root", *root));
            !self.root_denied
        }
        fn binding_matches(&self, cert: &DeviceCertificatePayload) -> bool {
            self.calls.borrow_mut().push(("binding", *cert.device.id()));
            self.binding_denied.as_ref() != Some(cert.device.id())
        }
        fn is_revoked(&self, root_id: &PrincipalId, device: &PrincipalId) -> bool {
            assert_eq!(*root_id, root());
            self.calls.borrow_mut().push(("revoked", *device));
            self.revoked.as_ref() == Some(device)
        }
    }
    let c = chain(deep_chain(false));
    let root_keys = keys(1);
    let check = |state: &State| {
        verify_chain(
            &c,
            &root(),
            Some(root_keys.descriptor()),
            &resource(),
            state,
        )
        .map(|_| ())
    };
    let state = State::default();
    check(&state).unwrap();
    let labels: Vec<_> = state
        .calls
        .borrow()
        .iter()
        .map(|(label, _)| *label)
        .collect();
    assert_eq!(
        labels,
        [
            "root", "binding", "binding", "binding", "binding", "revoked", "revoked", "revoked",
            "revoked"
        ]
    );
    let state = State {
        root_denied: true,
        ..State::default()
    };
    assert_eq!(
        check(&state),
        Err(Error::AuthorizationFailed(AuthorityRule::DeviceRootRole))
    );
    assert_eq!(state.calls.borrow().len(), 1);
    // A later binding conflict beats an earlier leaf revocation.
    let state = State {
        binding_denied: Some(*keys(2).descriptor().id()),
        revoked: Some(*keys(5).descriptor().id()),
        ..State::default()
    };
    assert_eq!(
        check(&state),
        Err(Error::AuthorizationFailed(
            AuthorityRule::DeviceBindingConflict
        ))
    );
    assert_eq!(state.calls.borrow().len(), 5);
    // Every position, including intermediates, is checked for revocation.
    for n in 2..=5 {
        let state = State {
            revoked: Some(*keys(n).descriptor().id()),
            ..State::default()
        };
        assert_eq!(
            check(&state),
            Err(Error::AuthorizationFailed(AuthorityRule::DeviceRevoked))
        );
        wire(check(&state), WireCode::AuthorizationFailed);
    }
    let state = State::default();
    let broken = chain(vec![broken_signature(c.leaf())]);
    wire(
        verify_chain(
            &broken,
            &root(),
            Some(root_keys.descriptor()),
            &resource(),
            &state,
        ),
        WireCode::InvalidSignature,
    );
    assert!(state.calls.borrow().is_empty());
    let invalid = chain(vec![cert(personal(3, &[1]), 2), cert(personal(2, &[1]), 1)]);
    wire(
        verify_chain(
            &invalid,
            &root(),
            Some(root_keys.descriptor()),
            &resource(),
            &state,
        ),
        WireCode::AuthorizationFailed,
    );
    assert!(state.calls.borrow().is_empty());
}
