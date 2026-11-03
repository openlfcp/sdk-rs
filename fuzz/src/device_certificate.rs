//! Shared by the libFuzzer target and the dependency-free mutation smoke run.

use lfcp::base::ResourceId;
use lfcp::cbor;
use lfcp::principal::PrincipalKeys;
use lfcp::wire::control::device::{
    verify_chain, CertificateChain, DeviceCertificate, EmptyChainState,
};
use lfcp::wire::control::ReceivedControlRecord;

pub fn check(data: &[u8]) {
    let root = PrincipalKeys::from_secrets(&[1; 32], [101; 32]);
    let resource = ResourceId::from_bytes([77; 32]);
    let certificate = DeviceCertificate::parse(data);
    assert_eq!(certificate, DeviceCertificate::parse(data));
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
