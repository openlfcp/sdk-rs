//! Multi-fault cases: §62's global order (draft §3.10), including legacy
//! transfers and competing records. Each case asserts the decisive diagnostic.
mod support;

use lfcp::base::{AuthorityRule as Rule, ChainRule, Error, Hash32, WireCode};
use lfcp::cbor::{self, Value};
use lfcp::cose;
use lfcp::wire::control::authority::validate_authorized_with;
use lfcp::wire::control::body::*;
use lfcp::wire::control::chain::{validate_chain, ChainOutcome, ChainStart, SignaturesOnly};
use lfcp::wire::control::device::*;
use lfcp::wire::control::{ControlRecord, ControlRecordHeader};
use support::identity::*;

fn bad_signature(bytes: &[u8]) -> Vec<u8> {
    let mut fields = cbor::decode_strict(bytes)
        .unwrap()
        .as_array()
        .unwrap()
        .to_vec();
    fields[3] = Value::bytes(vec![0; 64]);
    cbor::encode(&Value::Array(fields)).unwrap()
}

fn bad_certificate(cert: DeviceCertificate) -> DeviceCertificate {
    DeviceCertificate::parse(&bad_signature(cert.signed_object().bytes())).unwrap()
}

#[test]
fn all_dependencies_precede_outer_or_embedded_signature_failures() {
    let f = Fixture::new();
    let unknown_root = chain(vec![bad_certificate(personal(10, 2, &[1], 10, 2))]);
    let candidate = record(f.state(), 1, device_grant(unknown_root, None));
    let damaged = bad_signature(candidate.signed_object().bytes());
    assert_eq!(
        transition(f.state(), &damaged),
        Err(Error::IssuerUnknown(id(10)))
    );
    // Externally supplied descriptors do not establish Resource-local roots.
    assert_eq!(
        validate_authorized_with(
            &[&damaged],
            Some(f.state().clone()),
            &[keys(10).descriptor().clone()]
        )
        .unwrap_err()
        .error,
        Error::IssuerUnknown(id(10))
    );
    let known_root = chain(vec![bad_certificate(personal(1, 2, &[1], 1, 2))]);
    let candidate = record(f.state(), 8, device_grant(known_root, None));
    assert_eq!(
        transition(f.state(), &bad_signature(candidate.signed_object().bytes())),
        Err(Error::IssuerUnknown(id(8)))
    );

    // Offer signer is also a dependency: an invalid outer signature cannot hide it.
    for certificates in [None, Some(chain(vec![personal(10, 3, &[13], 10, 3)]))] {
        let signer = if certificates.is_some() { 3 } else { 10 };
        let body = transfer(f.state(), 10, 8, signer, certificates);
        let candidate = record(f.state(), signer, body);
        assert_eq!(
            transition(f.state(), &bad_signature(candidate.signed_object().bytes())),
            Err(Error::IssuerUnknown(id(8)))
        );
    }
}

#[test]
fn placement_precedes_dependencies_signatures_and_authority() {
    let f = Fixture::new();
    let body = device_grant(
        chain(vec![bad_certificate(personal(10, 2, &[1], 10, 2))]),
        None,
    );
    let candidate = ControlRecord::sign(
        ControlRecordHeader {
            resource_id: RESOURCE,
            sequence: 42,
            previous: Some(f.state().head.id),
            issuer: id(1),
        },
        body,
        &keys(1),
    )
    .unwrap();
    assert_eq!(
        transition(f.state(), &bad_signature(candidate.signed_object().bytes())),
        Err(Error::InvalidControlChain(ChainRule::SequenceGap))
    );
}

#[test]
fn every_signature_precedes_standing_binding_revocation_and_transfer_state() {
    let mut f = Fixture::new();
    f.push(1, grant(10, &[11], &[], None, Some(1))); // descriptor known, no standing
    f.denied(
        10,
        device_grant(chain(vec![personal(10, 2, &[1], 10, 2)]), None),
        Rule::DeviceRootNotStanding,
    );
    let candidate = record(
        f.state(),
        10,
        device_grant(
            chain(vec![bad_certificate(personal(10, 2, &[1], 10, 2))]),
            None,
        ),
    );
    assert_eq!(
        transition(f.state(), candidate.signed_object().bytes()),
        Err(Error::SignatureInvalid)
    );
    f.push(1, grant(3, &[1], &[], None, None)); // device/non-device conflict
    let candidate = record(
        f.state(),
        1,
        device_grant(
            chain(vec![bad_certificate(personal(1, 3, &[1], 1, 3))]),
            None,
        ),
    );
    assert_eq!(
        transition(f.state(), candidate.signed_object().bytes()),
        Err(Error::SignatureInvalid)
    );
    f.push(1, revoke(1, 2, 2, None));
    let candidate = record(
        f.state(),
        1,
        device_grant(
            chain(vec![bad_certificate(personal(1, 2, &[1], 1, 2))]),
            None,
        ),
    );
    assert_eq!(
        transition(f.state(), candidate.signed_object().bytes()),
        Err(Error::SignatureInvalid)
    );
    // A cryptographically broken accept precedes a stale offer, with or without chain.
    for certificates in [None, Some(chain(vec![personal(10, 4, &[13], 10, 4)]))] {
        let signer = if certificates.is_some() { 4 } else { 10 };
        let ControlBody::OwnerTransferCommit(mut body) =
            transfer(f.state(), 10, 1, signer, certificates)
        else {
            unreachable!()
        };
        body.accept = bad_signature(&body.accept);
        let mut later = f.clone();
        later.push(1, grant(9, &[1], &[], None, None));
        let result = later.propose(signer, ControlBody::OwnerTransferCommit(body));
        assert_eq!(result, Err(Error::SignatureInvalid));
    }
}

#[test]
fn device_grant_authority_order_is_standing_intrinsics_binding_revocation_repeat_issuer_approval() {
    let mut f = Fixture::new();
    f.push(1, grant(10, &[11], &[], None, None));
    let invalid = chain(vec![
        personal(10, 3, &[1, 2], 2, 3),
        personal(10, 2, &[1], 10, 2),
    ]);
    f.denied(
        10,
        device_grant(invalid.clone(), None),
        Rule::DeviceRootNotStanding,
    );
    f.push(1, grant(10, &[1], &[], None, None));
    f.denied(
        10,
        device_grant(invalid, None),
        Rule::DeviceIssuerNotManaging,
    );
    let exceeds = chain(vec![
        personal(10, 3, &[1, 2, 3], 2, 3),
        personal(10, 2, &[1, 2, 12], 10, 2),
    ]);
    f.denied(10, device_grant(exceeds, None), Rule::DeviceMaskEscalation);
    let outside = DeviceCertificate::sign(
        payload(
            10,
            5,
            DeviceKind::Pairing,
            &[1, 2],
            &[lfcp::base::ResourceId::from_bytes([88; 32])],
            5,
        ),
        &keys(10),
    )
    .unwrap();
    f.denied(
        10,
        device_grant(chain(vec![outside]), None),
        Rule::DevicePairingOutOfScope,
    );
    // Revoke an unknown device, then introduce it as a grant subject: role
    // assignment is legal because DEVICE_REVOKE assigns no role. A certificate
    // fails on the binding/role class before the revocation class.
    f.push(1, revoke(10, 4, 2, None));
    f.push(1, grant(4, &[1], &[], None, None));
    f.denied(
        10,
        device_grant(chain(vec![personal(10, 4, &[1], 10, 4)]), None),
        Rule::DeviceBindingConflict,
    );
    let certificates = chain(vec![personal(10, 3, &[1], 10, 3)]);
    f.push(10, device_grant(certificates.clone(), None));
    f.denied(
        4,
        device_grant(certificates, Some(9)),
        Rule::DeviceAlreadyBound,
    );
    f.denied(
        4,
        device_grant(chain(vec![personal(10, 3, &[1], 10, 9)]), Some(9)),
        Rule::DeviceGrantIssuer,
    );
    f.push(10, revoke(10, 3, 2, None));
    f.denied(
        4,
        device_grant(chain(vec![personal(10, 3, &[1], 10, 3)]), Some(9)),
        Rule::DeviceRevoked,
    );
}

#[test]
fn accept_and_commit_must_use_leaf_and_all_signatures_only_policies_enforce_it() {
    let f = Fixture::new();
    let certificates = chain(vec![personal(10, 3, &[13], 10, 3)]);
    for (acceptor, committer) in [(10, 3), (3, 10), (1, 3), (3, 1)] {
        let candidate = record(
            f.state(),
            committer,
            transfer(f.state(), 10, 1, acceptor, Some(certificates.clone())),
        );
        assert_eq!(
            transition(f.state(), candidate.signed_object().bytes()),
            Err(Error::CoseKidMismatch)
        );
        let bytes = [f.records[0].as_slice(), candidate.signed_object().bytes()];
        assert_eq!(
            validate_chain(&bytes, ChainStart::Genesis, &mut SignaturesOnly)
                .unwrap_err()
                .error,
            Error::CoseKidMismatch
        );
    }
}

#[test]
fn competing_record_cannot_learn_a_root_or_issuer_from_the_later_branch() {
    let mut f = Fixture::new();
    let at_genesis = f.state().clone();
    f.push(1, grant(10, &[1, 2], &[], None, None));
    f.register(10, 2, &[1, 2]);
    let candidate = record(
        &at_genesis,
        2,
        device_grant(chain(vec![personal(10, 2, &[1, 2], 10, 2)]), None),
    );
    let mut records = f.records.clone();
    records.push(candidate.signed_object().bytes().to_vec());
    assert_eq!(
        validate(&records).unwrap_err().error,
        Error::IssuerUnknown(id(10))
    );
    let candidate = record(&at_genesis, 10, revoke(10, 3, 2, None));
    records.pop();
    records.push(candidate.signed_object().bytes().to_vec());
    assert_eq!(
        validate(&records).unwrap_err().error,
        Error::IssuerUnknown(id(10))
    );
}

#[test]
fn pairing_consume_competitors_are_forks_and_stale_retries_are_not_transitions() {
    let mut f = Fixture::new();
    let session = DeviceCertificate::sign(
        payload(1, 5, DeviceKind::Pairing, &[1, 2], &[RESOURCE], 5),
        &keys(1),
    )
    .unwrap();
    f.push(1, device_grant(chain(vec![session]), None));
    let predecessor = f.state().clone();
    let first = record(
        &predecessor,
        1,
        revoke(1, 5, 3, Some(Hash32::from_bytes([3; 32]))),
    );
    let second = record(
        &predecessor,
        1,
        revoke(1, 5, 3, Some(Hash32::from_bytes([4; 32]))),
    );
    let mut records = f.records.clone();
    records.push(first.signed_object().bytes().to_vec());
    records.push(second.signed_object().bytes().to_vec());
    let (outcome, history) = validate(&records).unwrap();
    assert!(matches!(outcome, ChainOutcome::Conflict(_)));
    assert_eq!(history.len(), f.states.len() + 1);
    let state = transition(&predecessor, first.signed_object().bytes()).unwrap();
    let stale = lfcp::wire::control::authority::propose_transition(
        &state,
        predecessor.head.id,
        second.signed_object().bytes(),
    )
    .unwrap_err();
    assert_eq!(stale.wire_code(), Some(WireCode::ControlHeadMismatch));
    let fresh = record(
        &state,
        1,
        revoke(1, 5, 3, Some(Hash32::from_bytes([4; 32]))),
    );
    assert_eq!(
        transition(&state, fresh.signed_object().bytes()),
        Err(Error::AuthorizationFailed(Rule::DeviceAlreadyRevoked))
    );
}

#[test]
fn payload_acceptor_mismatch_is_authority_after_valid_required_signatures() {
    let f = Fixture::new();
    let ControlBody::OwnerTransferCommit(mut body) = transfer(f.state(), 10, 1, 10, None) else {
        unreachable!()
    };
    let (_, mut accept) = body.accept().unwrap();
    accept.new_owner = id(9);
    body.accept = cose::sign(&cbor::encode(&accept.to_value()).unwrap(), &keys(10))
        .unwrap()
        .bytes()
        .to_vec();
    f.denied(
        10,
        ControlBody::OwnerTransferCommit(body),
        Rule::TransferAcceptorMismatch,
    );
}

#[test]
fn public_apply_also_checks_embedded_signatures_before_authority() {
    use lfcp::wire::control::authority::apply;
    let f = Fixture::new();
    let record = record(
        f.state(),
        1,
        device_grant(
            chain(vec![bad_certificate(personal(1, 2, &[1], 1, 2))]),
            None,
        ),
    );
    assert_eq!(
        apply(Some(f.state()), &record),
        Err(Error::SignatureInvalid)
    );
    assert_eq!(apply(None, &genesis(1, 1, None)), Ok(f.state().clone()));
    assert_eq!(
        apply(
            None,
            &genesis(1, 1, Some(chain(vec![personal(1, 2, &[13], 1, 2)])))
        ),
        Err(Error::CoseKidMismatch)
    );
}
