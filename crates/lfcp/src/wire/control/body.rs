//! Typed Control Record bodies (LFCP-WIRE-01 §14–§24).
//!
//! Every core type 0–8 decodes from, and encodes to, a closed map with the
//! field types its CDDL gives. Only structure is checked here; what a body
//! means for authority, routes, epochs or ownership is evaluated elsewhere.
//!
//! | Code | Type | Body fields | § |
//! | ---: | --- | --- | --- |
//! | 0 | Genesis | 0 data profile, 1 owner descriptor, 2 epoch-0 DEK commitment, 3 endpoints (≥ 1), 4 coordinator URL | §15 |
//! | 1 | Capability Grant | 0 subject descriptor, 1 abilities (≥ 1), 2 delegable abilities, ?3 parent grant id, ?4 claim limit | §17.2 |
//! | 2 | Capability Revoke | 0 grant id | §17.3 |
//! | 3 | Capability Claim | 0 invitation grant id, 1 claimant descriptor, 2 abilities (≥ 1) | §18.1 |
//! | 4 | Key Epoch | 0 new epoch, 1 new DEK commitment, 2 final frontier, 3 reason | §19 |
//! | 5 | Route Update | 0 route version, 1 endpoints (≥ 1), 2 coordinator URL | §20 |
//! | 6 | Owner Transfer Commit | 0 offer COSE bytes, 1 accept COSE bytes | §23.3 |
//! | 7 | Coordinator Recovery | 0 route version, 1 endpoints (≥ 1), 2 coordinator URL, 3 reason (≤ 256 bytes) | §22 |
//! | 8 | Resource Tombstone | 0 reason, ?1 note (≤ 256 bytes) | §24 |
//! | 9–31 | reserved | rejected | §14 |
//! | ≥ 32 | extension | kept opaque | §14 |
//!
//! An endpoint is `{0: URL, 1: priority, ?2: flags}` (§16).

use crate::base::{ControlRecordId, Error, Hash32, PrincipalId, ResourceId};
use crate::cbor::Value;
use crate::cose::{self, SignedObject};
use crate::principal::PrincipalDescriptor;
use crate::wire::frontier::ActorHave;
use crate::wire::{
    bytes_field, check_closed_map, hash_field, principal_field, resource_field, text_field,
    uint_array, uint_array_field, uint_field,
};

/// Longest human-readable reason or note, in UTF-8 bytes (§22, §24).
pub const MAX_NOTE_BYTES: usize = 256;

/// First Control Record type of the extension space (§14).
pub const FIRST_EXTENSION_TYPE: u64 = 32;

const MALFORMED: Error = Error::ControlRecordMalformed;

/// A sync endpoint (§16).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    /// Field 0: the absolute `wss://` (or loopback `ws://`) URL.
    pub url: String,
    /// Field 1: priority; lower is preferred.
    pub priority: u64,
    /// Field 2: flag bits, when present.
    pub flags: Option<u64>,
}

impl Endpoint {
    fn from_value(value: &Value) -> Result<Endpoint, Error> {
        check_closed_map(value, &[0, 1], &[2], MALFORMED)?;
        Ok(Endpoint {
            url: text_field(value, 0, &MALFORMED)?.to_owned(),
            priority: uint_field(value, 1, &MALFORMED)?,
            flags: match value.get_uint(2) {
                Some(_) => Some(uint_field(value, 2, &MALFORMED)?),
                None => None,
            },
        })
    }

    fn to_value(&self) -> Value {
        let mut entries = vec![
            (Value::Unsigned(0), Value::text(self.url.clone())),
            (Value::Unsigned(1), Value::Unsigned(self.priority)),
        ];
        if let Some(flags) = self.flags {
            entries.push((Value::Unsigned(2), Value::Unsigned(flags)));
        }
        Value::Map(entries)
    }
}

/// Genesis (§15).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenesisBody {
    /// Field 0: the Data Profile identifier.
    pub data_profile: String,
    /// Field 1: the owner, who must sign Genesis.
    pub owner: PrincipalDescriptor,
    /// Field 2: the epoch-0 DEK commitment.
    pub dek_commitment: Hash32,
    /// Field 3: the initial sync endpoints.
    pub endpoints: Vec<Endpoint>,
    /// Field 4: the initial Control Coordinator URL.
    pub coordinator: String,
}

/// Capability Grant (§17.2), including invite grants (§18).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityGrantBody {
    /// Field 0: the grantee.
    pub subject: PrincipalDescriptor,
    /// Field 1: granted ability codes (§17.1).
    pub abilities: Vec<u64>,
    /// Field 2: abilities the subject may delegate.
    pub delegable: Vec<u64>,
    /// Field 3: the parent grant, for a delegated grant.
    pub parent: Option<ControlRecordId>,
    /// Field 4: the claim limit, for an Invitation Principal.
    pub claim_limit: Option<u64>,
}

/// Capability Revocation (§17.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityRevokeBody {
    /// Field 0: the revoked grant.
    pub grant: ControlRecordId,
}

/// Capability Claim (§18.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityClaimBody {
    /// Field 0: the invitation grant being claimed.
    pub invitation_grant: ControlRecordId,
    /// Field 1: the claimant's normal Principal.
    pub claimant: PrincipalDescriptor,
    /// Field 2: the abilities to transfer.
    pub abilities: Vec<u64>,
}

/// Key Epoch (§19). The cutoff semantics of the final frontier are applied
/// elsewhere.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyEpochBody {
    /// Field 0: the new Data Epoch.
    pub epoch: u64,
    /// Field 1: the new DEK commitment.
    pub dek_commitment: Hash32,
    /// Field 2: the accepted final frontier of the previous epoch.
    pub final_frontier: Vec<ActorHave>,
    /// Field 3: the reason code.
    pub reason: u64,
}

/// Route Update (§20).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteUpdateBody {
    /// Field 0: the route version.
    pub version: u64,
    /// Field 1: the endpoints.
    pub endpoints: Vec<Endpoint>,
    /// Field 2: the Control Coordinator URL.
    pub coordinator: String,
}

/// Owner Transfer Commit (§23.3): the exact bytes of the offer and the
/// accept, never re-encoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerTransferCommitBody {
    /// Field 0: the transfer offer's exact COSE_Sign1 bytes.
    pub offer: Vec<u8>,
    /// Field 1: the transfer accept's exact COSE_Sign1 bytes.
    pub accept: Vec<u8>,
}

/// Coordinator Recovery (§22).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoordinatorRecoveryBody {
    /// Field 0: the new route version.
    pub version: u64,
    /// Field 1: the endpoints.
    pub endpoints: Vec<Endpoint>,
    /// Field 2: the new coordinator URL.
    pub coordinator: String,
    /// Field 3: human-readable reason, at most 256 UTF-8 bytes.
    pub reason: String,
}

/// Resource Tombstone (§24).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceTombstoneBody {
    /// Field 0: the reason code.
    pub reason: u64,
    /// Field 1: optional note, at most 256 UTF-8 bytes.
    pub note: Option<String>,
}

/// A typed Control Record body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControlBody {
    /// Type 0.
    Genesis(GenesisBody),
    /// Type 1.
    CapabilityGrant(CapabilityGrantBody),
    /// Type 2.
    CapabilityRevoke(CapabilityRevokeBody),
    /// Type 3.
    CapabilityClaim(CapabilityClaimBody),
    /// Type 4.
    KeyEpoch(KeyEpochBody),
    /// Type 5.
    RouteUpdate(RouteUpdateBody),
    /// Type 6.
    OwnerTransferCommit(OwnerTransferCommitBody),
    /// Type 7.
    CoordinatorRecovery(CoordinatorRecoveryBody),
    /// Type 8.
    ResourceTombstone(ResourceTombstoneBody),
    /// A type ≥ 32, retained but not interpreted (§14). Its body is kept
    /// as decoded; the record's exact bytes stay in the signed object.
    Extension {
        /// The type code.
        control_type: u64,
        /// The opaque body.
        body: Value,
    },
}

impl ControlBody {
    /// The §14 type code.
    pub fn control_type(&self) -> u64 {
        match self {
            ControlBody::Genesis(_) => 0,
            ControlBody::CapabilityGrant(_) => 1,
            ControlBody::CapabilityRevoke(_) => 2,
            ControlBody::CapabilityClaim(_) => 3,
            ControlBody::KeyEpoch(_) => 4,
            ControlBody::RouteUpdate(_) => 5,
            ControlBody::OwnerTransferCommit(_) => 6,
            ControlBody::CoordinatorRecovery(_) => 7,
            ControlBody::ResourceTombstone(_) => 8,
            ControlBody::Extension { control_type, .. } => *control_type,
        }
    }

    /// Decode the body of a record of type `control_type`.
    pub fn from_value(control_type: u64, body: &Value) -> Result<ControlBody, Error> {
        let m = &MALFORMED;
        Ok(match control_type {
            0 => {
                check_closed_map(body, &[0, 1, 2, 3, 4], &[], MALFORMED)?;
                ControlBody::Genesis(GenesisBody {
                    data_profile: text_field(body, 0, m)?.to_owned(),
                    owner: descriptor_field(body, 1)?,
                    dek_commitment: hash_field(body, 2, m)?,
                    endpoints: endpoints_field(body, 3)?,
                    coordinator: text_field(body, 4, m)?.to_owned(),
                })
            }
            1 => {
                check_closed_map(body, &[0, 1, 2], &[3, 4], MALFORMED)?;
                ControlBody::CapabilityGrant(CapabilityGrantBody {
                    subject: descriptor_field(body, 0)?,
                    abilities: non_empty(abilities(body, 1)?)?,
                    delegable: abilities(body, 2)?,
                    parent: match body.get_uint(3) {
                        Some(_) => Some(record_id_field(body, 3)?),
                        None => None,
                    },
                    claim_limit: match body.get_uint(4) {
                        Some(_) => Some(uint_field(body, 4, m)?),
                        None => None,
                    },
                })
            }
            2 => {
                check_closed_map(body, &[0], &[], MALFORMED)?;
                ControlBody::CapabilityRevoke(CapabilityRevokeBody {
                    grant: record_id_field(body, 0)?,
                })
            }
            3 => {
                check_closed_map(body, &[0, 1, 2], &[], MALFORMED)?;
                ControlBody::CapabilityClaim(CapabilityClaimBody {
                    invitation_grant: record_id_field(body, 0)?,
                    claimant: descriptor_field(body, 1)?,
                    abilities: non_empty(abilities(body, 2)?)?,
                })
            }
            4 => {
                check_closed_map(body, &[0, 1, 2, 3], &[], MALFORMED)?;
                // The CDDL types the final frontier as [* actor-have], not
                // canonical-frontier: each entry is held to §28.1 (it is
                // inside a persistent object), but entry order and duplicate
                // Principals are not checked. See spec gap G-CP1.
                let final_frontier = body
                    .get_uint(2)
                    .and_then(Value::as_array)
                    .ok_or(MALFORMED)?
                    .iter()
                    .map(ActorHave::from_value)
                    .collect::<Result<_, _>>()?;
                ControlBody::KeyEpoch(KeyEpochBody {
                    epoch: uint_field(body, 0, m)?,
                    dek_commitment: hash_field(body, 1, m)?,
                    final_frontier,
                    reason: uint_field(body, 3, m)?,
                })
            }
            5 => {
                check_closed_map(body, &[0, 1, 2], &[], MALFORMED)?;
                ControlBody::RouteUpdate(RouteUpdateBody {
                    version: uint_field(body, 0, m)?,
                    endpoints: endpoints_field(body, 1)?,
                    coordinator: text_field(body, 2, m)?.to_owned(),
                })
            }
            6 => {
                check_closed_map(body, &[0, 1], &[], MALFORMED)?;
                ControlBody::OwnerTransferCommit(OwnerTransferCommitBody {
                    offer: bytes_field(body, 0, m)?.to_vec(),
                    accept: bytes_field(body, 1, m)?.to_vec(),
                })
            }
            7 => {
                check_closed_map(body, &[0, 1, 2, 3], &[], MALFORMED)?;
                ControlBody::CoordinatorRecovery(CoordinatorRecoveryBody {
                    version: uint_field(body, 0, m)?,
                    endpoints: endpoints_field(body, 1)?,
                    coordinator: text_field(body, 2, m)?.to_owned(),
                    reason: note(text_field(body, 3, m)?)?,
                })
            }
            8 => {
                check_closed_map(body, &[0], &[1], MALFORMED)?;
                ControlBody::ResourceTombstone(ResourceTombstoneBody {
                    reason: uint_field(body, 0, m)?,
                    note: match body.get_uint(1) {
                        Some(_) => Some(note(text_field(body, 1, m)?)?),
                        None => None,
                    },
                })
            }
            9..=31 => return Err(Error::ControlUnknownCoreType(control_type)),
            _ => ControlBody::Extension {
                control_type,
                body: body.clone(),
            },
        })
    }

    /// The body as a CBOR value.
    pub fn to_value(&self) -> Value {
        let uint = Value::Unsigned;
        let bytes32 = |b: &[u8; 32]| Value::bytes(b.to_vec());
        let entries: Vec<(u64, Value)> = match self {
            ControlBody::Genesis(b) => vec![
                (0, Value::text(b.data_profile.clone())),
                (1, b.owner.to_value()),
                (2, bytes32(b.dek_commitment.as_bytes())),
                (3, endpoints(&b.endpoints)),
                (4, Value::text(b.coordinator.clone())),
            ],
            ControlBody::CapabilityGrant(b) => {
                let mut entries = vec![
                    (0, b.subject.to_value()),
                    (1, uint_array(&b.abilities)),
                    (2, uint_array(&b.delegable)),
                ];
                if let Some(parent) = &b.parent {
                    entries.push((3, bytes32(parent.as_bytes())));
                }
                if let Some(limit) = b.claim_limit {
                    entries.push((4, uint(limit)));
                }
                entries
            }
            ControlBody::CapabilityRevoke(b) => vec![(0, bytes32(b.grant.as_bytes()))],
            ControlBody::CapabilityClaim(b) => vec![
                (0, bytes32(b.invitation_grant.as_bytes())),
                (1, b.claimant.to_value()),
                (2, uint_array(&b.abilities)),
            ],
            ControlBody::KeyEpoch(b) => vec![
                (0, uint(b.epoch)),
                (1, bytes32(b.dek_commitment.as_bytes())),
                (
                    2,
                    Value::Array(b.final_frontier.iter().map(ActorHave::to_value).collect()),
                ),
                (3, uint(b.reason)),
            ],
            ControlBody::RouteUpdate(b) => vec![
                (0, uint(b.version)),
                (1, endpoints(&b.endpoints)),
                (2, Value::text(b.coordinator.clone())),
            ],
            ControlBody::OwnerTransferCommit(b) => vec![
                (0, Value::bytes(b.offer.clone())),
                (1, Value::bytes(b.accept.clone())),
            ],
            ControlBody::CoordinatorRecovery(b) => vec![
                (0, uint(b.version)),
                (1, endpoints(&b.endpoints)),
                (2, Value::text(b.coordinator.clone())),
                (3, Value::text(b.reason.clone())),
            ],
            ControlBody::ResourceTombstone(b) => {
                let mut entries = vec![(0, uint(b.reason))];
                if let Some(note) = &b.note {
                    entries.push((1, Value::text(note.clone())));
                }
                entries
            }
            ControlBody::Extension { body, .. } => return body.clone(),
        };
        Value::Map(entries.into_iter().map(|(k, v)| (uint(k), v)).collect())
    }
}

fn descriptor_field(body: &Value, key: u64) -> Result<PrincipalDescriptor, Error> {
    PrincipalDescriptor::from_value(body.get_uint(key).ok_or(MALFORMED)?)
}

fn record_id_field(body: &Value, key: u64) -> Result<ControlRecordId, Error> {
    hash_field(body, key, &MALFORMED).map(|h| ControlRecordId::from_bytes(*h.as_bytes()))
}

fn endpoints_field(body: &Value, key: u64) -> Result<Vec<Endpoint>, Error> {
    let items = body
        .get_uint(key)
        .and_then(Value::as_array)
        .ok_or(MALFORMED)?;
    non_empty(
        items
            .iter()
            .map(Endpoint::from_value)
            .collect::<Result<_, _>>()?,
    )
}

fn endpoints(endpoints: &[Endpoint]) -> Value {
    Value::Array(endpoints.iter().map(Endpoint::to_value).collect())
}

/// CDDL `[1* …]`: at least one element.
/// An ability-code list (§17.1, §17.2, §18.1).
fn abilities(body: &Value, key: u64) -> Result<Vec<u64>, Error> {
    let codes = uint_array_field(body, key, &MALFORMED)?;
    // PROVISIONAL (G-CP6): a code repeated within one list makes the
    // record malformed. Unknown codes are kept; they confer nothing.
    let mut seen = std::collections::BTreeSet::new();
    if codes.iter().all(|code| seen.insert(*code)) {
        Ok(codes)
    } else {
        Err(MALFORMED)
    }
}

fn non_empty<T>(items: Vec<T>) -> Result<Vec<T>, Error> {
    if items.is_empty() {
        Err(MALFORMED)
    } else {
        Ok(items)
    }
}

fn note(text: &str) -> Result<String, Error> {
    if text.len() > MAX_NOTE_BYTES {
        Err(MALFORMED)
    } else {
        Ok(text.to_owned())
    }
}

/// An ownership Transfer Offer payload (§23.1), signed by the current
/// owner. Its checks against the chain are applied elsewhere.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerTransferOffer {
    /// Field 0: the Resource.
    pub resource_id: ResourceId,
    /// Field 1: the Control Head the offer is made at.
    pub control_head: Hash32,
    /// Field 2: the expected sequence of the commit.
    pub next_sequence: u64,
    /// Field 3: the proposed new owner.
    pub new_owner: PrincipalDescriptor,
    /// Field 4: a 16-byte nonce.
    pub nonce: [u8; 16],
}

/// An ownership Transfer Accept payload (§23.2), signed by the new owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerTransferAccept {
    /// Field 0: the Resource.
    pub resource_id: ResourceId,
    /// Field 1: the transfer offer ID.
    pub offer: Hash32,
    /// Field 2: the accepting new owner.
    pub new_owner: PrincipalId,
}

impl OwnerTransferOffer {
    /// Decode an offer payload.
    pub fn from_value(payload: &Value) -> Result<OwnerTransferOffer, Error> {
        let m = &MALFORMED;
        check_closed_map(payload, &[0, 1, 2, 3, 4], &[], MALFORMED)?;
        Ok(OwnerTransferOffer {
            resource_id: resource_field(payload, 0, m)?,
            control_head: hash_field(payload, 1, m)?,
            next_sequence: uint_field(payload, 2, m)?,
            new_owner: descriptor_field(payload, 3)?,
            nonce: bytes_field(payload, 4, m)?
                .try_into()
                .map_err(|_| MALFORMED)?,
        })
    }

    /// The payload as a CBOR value.
    pub fn to_value(&self) -> Value {
        Value::Map(vec![
            (
                Value::Unsigned(0),
                Value::bytes(self.resource_id.as_bytes().to_vec()),
            ),
            (
                Value::Unsigned(1),
                Value::bytes(self.control_head.as_bytes().to_vec()),
            ),
            (Value::Unsigned(2), Value::Unsigned(self.next_sequence)),
            (Value::Unsigned(3), self.new_owner.to_value()),
            (Value::Unsigned(4), Value::bytes(self.nonce.to_vec())),
        ])
    }
}

impl OwnerTransferAccept {
    /// Decode an accept payload.
    pub fn from_value(payload: &Value) -> Result<OwnerTransferAccept, Error> {
        let m = &MALFORMED;
        check_closed_map(payload, &[0, 1, 2], &[], MALFORMED)?;
        Ok(OwnerTransferAccept {
            resource_id: resource_field(payload, 0, m)?,
            offer: hash_field(payload, 1, m)?,
            new_owner: principal_field(payload, 2, m)?,
        })
    }

    /// The payload as a CBOR value.
    pub fn to_value(&self) -> Value {
        Value::Map(vec![
            (
                Value::Unsigned(0),
                Value::bytes(self.resource_id.as_bytes().to_vec()),
            ),
            (
                Value::Unsigned(1),
                Value::bytes(self.offer.as_bytes().to_vec()),
            ),
            (
                Value::Unsigned(2),
                Value::bytes(self.new_owner.as_bytes().to_vec()),
            ),
        ])
    }
}

impl OwnerTransferCommitBody {
    /// Parse the embedded offer: canonical COSE and a typed payload. The
    /// signature is not verified here.
    pub fn offer(&self) -> Result<(SignedObject, OwnerTransferOffer), Error> {
        let object = cose::parse(&self.offer)?;
        let offer = OwnerTransferOffer::from_value(object.payload())?;
        Ok((object, offer))
    }

    /// Parse the embedded accept: canonical COSE and a typed payload. The
    /// signature is not verified here.
    pub fn accept(&self) -> Result<(SignedObject, OwnerTransferAccept), Error> {
        let object = cose::parse(&self.accept)?;
        let accept = OwnerTransferAccept::from_value(object.payload())?;
        Ok((object, accept))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor;
    use crate::principal::PrincipalKeys;

    fn descriptor() -> PrincipalDescriptor {
        PrincipalKeys::from_secrets(&[1; 32], [2; 32])
            .descriptor()
            .clone()
    }

    fn endpoint() -> Endpoint {
        Endpoint {
            url: "wss://a.example/ws".into(),
            priority: 0,
            flags: Some(3),
        }
    }

    fn round_trip(body: ControlBody) {
        let bytes = cbor::encode(&body.to_value()).unwrap();
        let decoded =
            ControlBody::from_value(body.control_type(), &cbor::decode_strict(&bytes).unwrap())
                .unwrap();
        assert_eq!(decoded, body);
    }

    #[test]
    fn every_core_body_round_trips() {
        let id = ControlRecordId::from_bytes([4; 32]);
        round_trip(ControlBody::Genesis(GenesisBody {
            data_profile: "lfcp.tasks.v1".into(),
            owner: descriptor(),
            dek_commitment: Hash32::from_bytes([5; 32]),
            endpoints: vec![endpoint()],
            coordinator: "wss://a.example/ws".into(),
        }));
        round_trip(ControlBody::CapabilityGrant(CapabilityGrantBody {
            subject: descriptor(),
            abilities: vec![1, 2],
            delegable: vec![],
            parent: Some(id),
            claim_limit: Some(1),
        }));
        round_trip(ControlBody::CapabilityRevoke(CapabilityRevokeBody {
            grant: id,
        }));
        round_trip(ControlBody::CapabilityClaim(CapabilityClaimBody {
            invitation_grant: id,
            claimant: descriptor(),
            abilities: vec![1],
        }));
        round_trip(ControlBody::KeyEpoch(KeyEpochBody {
            epoch: 1,
            dek_commitment: Hash32::from_bytes([6; 32]),
            final_frontier: vec![ActorHave {
                principal: *descriptor().id(),
                contiguous: 2,
                extra: vec![(4, 5)],
            }],
            reason: 1,
        }));
        round_trip(ControlBody::RouteUpdate(RouteUpdateBody {
            version: 2,
            endpoints: vec![Endpoint {
                flags: None,
                ..endpoint()
            }],
            coordinator: "wss://a.example/ws".into(),
        }));
        round_trip(ControlBody::OwnerTransferCommit(OwnerTransferCommitBody {
            offer: vec![1, 2],
            accept: vec![3],
        }));
        round_trip(ControlBody::CoordinatorRecovery(CoordinatorRecoveryBody {
            version: 3,
            endpoints: vec![endpoint()],
            coordinator: "wss://a.example/ws".into(),
            reason: "coordinator lost".into(),
        }));
        round_trip(ControlBody::ResourceTombstone(ResourceTombstoneBody {
            reason: 0,
            note: None,
        }));
        round_trip(ControlBody::Extension {
            control_type: 40,
            body: Value::Array(vec![Value::Null]),
        });
    }

    #[test]
    fn bodies_are_closed_and_typed() {
        let revoke =
            |entries: Vec<(Value, Value)>| ControlBody::from_value(2, &Value::Map(entries));
        let id = Value::bytes(vec![0; 32]);
        assert!(revoke(vec![(Value::Unsigned(0), id.clone())]).is_ok());
        assert_eq!(
            revoke(vec![
                (Value::Unsigned(0), id.clone()),
                (Value::Unsigned(1), Value::Null)
            ]),
            Err(MALFORMED)
        );
        assert_eq!(
            revoke(vec![(Value::Unsigned(0), Value::bytes(vec![0; 31]))]),
            Err(MALFORMED)
        );
        assert_eq!(revoke(vec![]), Err(MALFORMED));
        assert_eq!(ControlBody::from_value(2, &Value::Null), Err(MALFORMED));
    }

    #[test]
    fn required_lists_are_non_empty() {
        let grant = ControlBody::CapabilityGrant(CapabilityGrantBody {
            subject: descriptor(),
            abilities: vec![],
            delegable: vec![],
            parent: None,
            claim_limit: None,
        });
        assert_eq!(
            ControlBody::from_value(1, &grant.to_value()),
            Err(MALFORMED)
        );
        let route = ControlBody::RouteUpdate(RouteUpdateBody {
            version: 1,
            endpoints: vec![],
            coordinator: String::new(),
        });
        assert_eq!(
            ControlBody::from_value(5, &route.to_value()),
            Err(MALFORMED)
        );
    }

    #[test]
    fn repeated_ability_codes_are_malformed() {
        let grant = |abilities: Vec<u64>, delegable: Vec<u64>| {
            ControlBody::CapabilityGrant(CapabilityGrantBody {
                subject: descriptor(),
                abilities,
                delegable,
                parent: None,
                claim_limit: None,
            })
            .to_value()
        };
        assert!(ControlBody::from_value(1, &grant(vec![1, 2, 99], vec![2])).is_ok());
        assert_eq!(
            ControlBody::from_value(1, &grant(vec![1, 2, 1], vec![])),
            Err(MALFORMED)
        );
        assert_eq!(
            ControlBody::from_value(1, &grant(vec![1], vec![2, 2])),
            Err(MALFORMED)
        );
        let claim = ControlBody::CapabilityClaim(CapabilityClaimBody {
            invitation_grant: ControlRecordId::from_bytes([1; 32]),
            claimant: descriptor(),
            abilities: vec![2, 2],
        });
        assert_eq!(
            ControlBody::from_value(3, &claim.to_value()),
            Err(MALFORMED)
        );
    }

    #[test]
    fn notes_are_limited_to_256_bytes() {
        let tombstone = |note: String| {
            ControlBody::ResourceTombstone(ResourceTombstoneBody {
                reason: 0,
                note: Some(note),
            })
            .to_value()
        };
        assert!(ControlBody::from_value(8, &tombstone("é".repeat(128))).is_ok());
        assert_eq!(
            ControlBody::from_value(8, &tombstone(format!("{}x", "é".repeat(128)))),
            Err(MALFORMED)
        );
    }

    #[test]
    fn reserved_core_types_are_rejected_and_extensions_kept() {
        for code in [9, 20, 31] {
            assert_eq!(
                ControlBody::from_value(code, &Value::Map(vec![])),
                Err(Error::ControlUnknownCoreType(code))
            );
        }
        assert!(matches!(
            ControlBody::from_value(FIRST_EXTENSION_TYPE, &Value::Null),
            Ok(ControlBody::Extension {
                control_type: 32,
                ..
            })
        ));
    }
}
