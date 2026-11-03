//! Shared by the libFuzzer target and the dependency-free mutation smoke run.

use lfcp::base::ResourceId;
use lfcp::cbor;
use lfcp::cose;
use lfcp::principal::PrincipalKeys;
use lfcp::wire::control::device::{
    verify_chain, CertificateChain, DeviceCertificate, DeviceCertificatePayload, EmptyChainState,
};
use lfcp::wire::control::ReceivedControlRecord;

pub fn check(data: &[u8]) {
    let root = PrincipalKeys::from_secrets(&[1; 32], [101; 32]);
    let resource = ResourceId::from_bytes([77; 32]);
    let certificate = DeviceCertificate::parse(data);
    assert_eq!(certificate, DeviceCertificate::parse(data));
    // Bypass the allocation-free scanner: accepting and rejecting the same
    // bytes as the full COSE/payload parser catches false scanner refusals.
    // Local diagnostic variants can differ; the payload or wire code cannot.
    let full_certificate =
        cose::parse(data).and_then(|object| DeviceCertificatePayload::from_value(object.payload()));
    assert_eq!(
        certificate
            .as_ref()
            .map(DeviceCertificate::payload)
            .map_err(|e| e.wire_code()),
        full_certificate.as_ref().map_err(|e| e.wire_code()),
    );
    if let Ok(cert) = certificate {
        assert_eq!(cert.signed_object().bytes(), data);
        assert_eq!(
            cert.payload().encode().unwrap(),
            cert.signed_object().payload_bytes()
        );
        assert_eq!(cert.payload().digest().unwrap(), cert.payload_digest());
    }
    let chain = CertificateChain::parse(data, root.descriptor().id());
    assert_eq!(chain, CertificateChain::parse(data, root.descriptor().id()));
    let full_chain = cbor::decode_strict(data)
        .and_then(|value| CertificateChain::from_value(&value, root.descriptor().id()));
    assert_eq!(
        chain.as_ref().map_err(|e| e.wire_code()),
        full_chain.as_ref().map_err(|e| e.wire_code()),
    );
    if let Ok(chain) = chain {
        assert_eq!(chain.encode(), data);
        let verdict = || {
            verify_chain(
                &chain,
                root.descriptor().id(),
                Some(root.descriptor()),
                &resource,
                &EmptyChainState,
            )
            .map(|v| v.in_scope)
        };
        assert_eq!(verdict(), verdict());
    }
    let record = ReceivedControlRecord::parse(data);
    assert_eq!(record, ReceivedControlRecord::parse(data));
    if let Ok(record) = record {
        let bytes = cbor::encode(&record.body().to_value()).unwrap();
        let decoded = lfcp::wire::control::body::ControlBody::from_value(
            record.body().control_type(),
            &cbor::decode_strict(&bytes).unwrap(),
        )
        .unwrap();
        assert_eq!(&decoded, record.body());
    }
}
