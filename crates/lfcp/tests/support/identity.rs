//! Identity transition harness. R3 can feed exact vector bytes through
//! `validate`/`transition` and assert the same public post-state as local cases.
//! No profile document, server table, clock or external descriptor is an input.

use lfcp::base::{AuthorityRule, Error, Hash32, PrincipalId, ResourceId};
use lfcp::cbor;
use lfcp::cose;
use lfcp::principal::PrincipalKeys;
use lfcp::wire::control::authority::{propose_transition, validate_authorized, ControlState};
use lfcp::wire::control::body::*;
use lfcp::wire::control::chain::{ChainFailure, ChainOutcome};
use lfcp::wire::control::device::*;
use lfcp::wire::control::{ControlRecord, ControlRecordHeader};

pub const RESOURCE: ResourceId = ResourceId::from_bytes([77; 32]);
pub const FULL: &[u64] = &[1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 13];

pub fn keys(n: u8) -> PrincipalKeys {
    PrincipalKeys::from_secrets(&[n; 32], [n + 100; 32])
}

pub fn id(n: u8) -> PrincipalId {
    *keys(n).descriptor().id()
}

pub fn payload(
    root: u8,
    device: u8,
    kind: DeviceKind,
    mask: &[u64],
    scope: &[ResourceId],
    serial: u8,
) -> DeviceCertificatePayload {
    DeviceCertificatePayload {
        root: id(root),
        device: keys(device).descriptor().clone(),
        kind,
        mask: mask.to_vec(),
        scope: scope.to_vec(),
        serial: [serial; 16],
    }
}

pub fn personal(root: u8, device: u8, mask: &[u64], signer: u8, serial: u8) -> DeviceCertificate {
    DeviceCertificate::sign(
        payload(root, device, DeviceKind::Personal, mask, &[], serial),
        &keys(signer),
    )
    .unwrap()
}

pub fn chain(certificates: Vec<DeviceCertificate>) -> CertificateChain {
    let root = certificates[0].payload().root;
    CertificateChain::new(certificates, &root).unwrap()
}

pub fn device_grant(chain: CertificateChain, session: Option<u8>) -> ControlBody {
    ControlBody::DeviceGrant(DeviceGrantBody {
        root: *chain.root(),
        chain,
        pairing_device: session.map(id),
    })
}

pub fn revoke(root: u8, device: u8, reason: u64, approval: Option<Hash32>) -> ControlBody {
    ControlBody::DeviceRevoke(DeviceRevokeBody {
        root: id(root),
        device: id(device),
        reason,
        approval,
    })
}

pub fn grant(
    subject: u8,
    abilities: &[u64],
    delegable: &[u64],
    parent: Option<lfcp::base::ControlRecordId>,
    limit: Option<u64>,
) -> ControlBody {
    ControlBody::CapabilityGrant(CapabilityGrantBody {
        subject: keys(subject).descriptor().clone(),
        abilities: abilities.to_vec(),
        delegable: delegable.to_vec(),
        parent,
        claim_limit: limit,
    })
}

pub fn genesis_body(owner: u8, device_chain: Option<CertificateChain>) -> ControlBody {
    ControlBody::Genesis(GenesisBody {
        data_profile: "org.openlfcp.identity.v1".into(),
        owner: keys(owner).descriptor().clone(),
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

pub fn genesis(owner: u8, signer: u8, chain: Option<CertificateChain>) -> ControlRecord {
    ControlRecord::sign(
        ControlRecordHeader {
            resource_id: RESOURCE,
            sequence: 0,
            previous: None,
            issuer: id(signer),
        },
        genesis_body(owner, chain),
        &keys(signer),
    )
    .unwrap()
}

pub fn record(state: &ControlState, signer: u8, body: ControlBody) -> ControlRecord {
    ControlRecord::sign(
        ControlRecordHeader {
            resource_id: state.resource_id,
            sequence: state.head.sequence + 1,
            previous: Some(state.head.id),
            issuer: id(signer),
        },
        body,
        &keys(signer),
    )
    .unwrap()
}

pub fn transfer(
    state: &ControlState,
    new_owner: u8,
    offer_signer: u8,
    accept_signer: u8,
    device_chain: Option<CertificateChain>,
) -> ControlBody {
    let offer = cose::sign(
        &cbor::encode(
            &OwnerTransferOffer {
                resource_id: state.resource_id,
                control_head: Hash32::from_bytes(*state.head.id.as_bytes()),
                next_sequence: state.head.sequence + 1,
                new_owner: keys(new_owner).descriptor().clone(),
                nonce: [44; 16],
            }
            .to_value(),
        )
        .unwrap(),
        &keys(offer_signer),
    )
    .unwrap();
    let accept = cose::sign(
        &cbor::encode(
            &OwnerTransferAccept {
                resource_id: state.resource_id,
                offer: *offer.id(),
                new_owner: id(new_owner),
            }
            .to_value(),
        )
        .unwrap(),
        &keys(accept_signer),
    )
    .unwrap();
    ControlBody::OwnerTransferCommit(OwnerTransferCommitBody {
        offer: offer.bytes().to_vec(),
        accept: accept.bytes().to_vec(),
        device_chain,
    })
}

/// Entry point for an external vector's ordered exact context bytes.
pub fn validate(records: &[Vec<u8>]) -> Result<(ChainOutcome, Vec<ControlState>), ChainFailure> {
    validate_authorized(&records.iter().map(Vec::as_slice).collect::<Vec<_>>(), None)
}

/// Entry point for a candidate at a vector's exact previous state.
pub fn transition(state: &ControlState, bytes: &[u8]) -> Result<ControlState, Error> {
    propose_transition(state, state.head.id, bytes)
}

#[derive(Clone)]
pub struct Fixture {
    pub records: Vec<Vec<u8>>,
    pub states: Vec<ControlState>,
}

impl Fixture {
    pub fn from_genesis(record: ControlRecord) -> Self {
        let records = vec![record.signed_object().bytes().to_vec()];
        let (_, states) = validate(&records).unwrap();
        Self { records, states }
    }
    pub fn new() -> Self {
        Self::from_genesis(genesis(1, 1, None))
    }
    pub fn state(&self) -> &ControlState {
        self.states.last().unwrap()
    }
    pub fn push(&mut self, signer: u8, body: ControlBody) {
        let record = record(self.state(), signer, body);
        let state = transition(self.state(), record.signed_object().bytes()).unwrap();
        self.records.push(record.signed_object().bytes().to_vec());
        self.states.push(state);
    }
    pub fn propose(&self, signer: u8, body: ControlBody) -> Result<ControlState, Error> {
        transition(
            self.state(),
            record(self.state(), signer, body).signed_object().bytes(),
        )
    }
    pub fn denied(&self, signer: u8, body: ControlBody, rule: AuthorityRule) {
        let result = self.propose(signer, body);
        assert_eq!(result, Err(Error::AuthorizationFailed(rule)));
    }
    pub fn register(&mut self, root: u8, device: u8, mask: &[u64]) {
        self.push(
            root,
            device_grant(
                chain(vec![personal(root, device, mask, root, device)]),
                None,
            ),
        );
    }
    /// Whole-chain replay must equal per-record resume, including proof reads.
    pub fn replay(&self) {
        let (outcome, states) = validate(&self.records).unwrap();
        assert!(matches!(outcome, ChainOutcome::Linear(_)));
        assert_eq!(states, self.states);
    }
}
