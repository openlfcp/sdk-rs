//! LFCP messages: the envelope and every typed body (LFCP-WIRE-01 §31–§61).
//!
//! ```text
//! lfcp-message = {0: type, 1: message id (16 bytes), ?2: correlation id,
//!                 ?3: flags, 4: body, * (uint .gt 15) => any}
//! ```
//!
//! A message is one deterministic CBOR map in one binary WebSocket message
//! (§31, §32). [`Message::decode`] enforces the size limit, deterministic
//! CBOR, the closed envelope (unknown keys 0–15 are rejected; unknown keys
//! above 15 are ignored and dropped, see [`Message::ignored_envelope_keys`])
//! and the closed body of the message type.
//!
//! | Code | Type | Body | § |
//! | ---: | --- | --- | --- |
//! | 0 | HELLO | wire profiles [1*], session descriptor, client nonce, ?data profiles | §34 |
//! | 1 | CHALLENGE | wire profile, server nonce, session id, server id | §35 |
//! | 2 | AUTH | auth proof COSE bytes, ?hosting credential | §36 |
//! | 3 | READY | wire profile, server id, max message bytes, durability, heartbeat ms, ?extensions | §37 |
//! | 4 | ERROR | code, ?diagnostic, ?details | §61 |
//! | 5, 6 | PING, PONG | 8-byte payload | §38 |
//! | 10 | RESOURCE_HOST | Genesis COSE bytes, ?hosting credential | §39 |
//! | 11 | RESOURCE_HOSTED | resource, durability | §40 |
//! | 12 | RESOURCE_OPEN | resource, control heads, actor-haves, ?grant ids, ?flags | §41 |
//! | 13 | RESOURCE_OPENED | resource, control heads, actor-haves, ?snapshot summary, ?route version, ?coordinator | §42 |
//! | 14 | RESOURCE_CLOSE | resource | §43 |
//! | 20 | CONTROL_HAVE | resource, control heads | §44 |
//! | 21 | CONTROL_GET | resource, start, end | §45 |
//! | 22 | CONTROL_BATCH | resource, Control Record COSE bytes [*] | §46 |
//! | 23 | CONTROL_PUT | resource, expected head (never null), Control Record COSE bytes | §47 |
//! | 30 | DATA_HAVE | resource, actor-haves | §48 |
//! | 31 | DATA_GET | resource, data ranges [1*] | §49 |
//! | 32 | DATA_BATCH | resource, Data Unit COSE bytes [*] | §50 |
//! | 33 | DATA_PUT | resource, Data Unit COSE bytes [1*] | §51 |
//! | 40 | KEY_PACKAGE_GET | resource, recipient, epochs [1*] | §52 |
//! | 41 | KEY_PACKAGE_BATCH | resource, Key Package COSE bytes [*] | §53 |
//! | 42 | KEY_PACKAGE_PUT | resource, Key Package COSE bytes [1*] | §54 |
//! | 50 | SNAPSHOT_GET | resource, ?Snapshot ID | §55 |
//! | 51, 52 | SNAPSHOT, SNAPSHOT_PUT | resource, Snapshot COSE bytes | §56, §57 |
//! | 60 | PRESENCE | resource, principal, TTL ms, payload | §58.1 |
//! | 61 | PRESENCE_LEAVE | resource, principal | §58.2 |
//! | 90 | ACK | acknowledged §33 type, ?object ids, ?durable | §59 |
//! | 91 | NACK | code, ?diagnostic, ?details | §60 |
//! | 128+ | extension | opaque body, only when negotiated | §33 |
//!
//! Signed objects inside bodies are kept as their exact bytes and parsed
//! only on request, with the parsers of their own modules; they are never
//! re-encoded.

use std::fmt;

use crate::base::{ControlRecordId, Error, Hash32, PrincipalId, ResourceId};
use crate::cbor::{self, Value};
use crate::principal::PrincipalDescriptor;
use crate::wire::check_closed_map;
use crate::wire::control::ReceivedControlRecord;
use crate::wire::data_unit::ReceivedDataUnit;
use crate::wire::frontier::ActorHave;
use crate::wire::key_package::ReceivedKeyPackage;
use crate::wire::snapshot::ReceivedSnapshot;

/// The default maximum message size, 8 MiB, unless the server advertises
/// another value in `READY` (§31).
pub const DEFAULT_MAX_MESSAGE_BYTES: usize = 8 * 1024 * 1024;

/// The first message type of the extension space (§33).
pub const FIRST_EXTENSION_TYPE: u64 = 128;

const MALFORMED: Error = Error::MessageMalformed;

/// The kind of a received WebSocket data message (§31).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameKind {
    /// A binary message: the only kind that carries LFCP.
    Binary,
    /// A text message: a protocol error.
    Text,
}

/// What a receiver accepts beyond the core message types.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodeOptions {
    /// The maximum message size this receiver enforces (§31).
    pub max_message_bytes: usize,
    /// Extension message types (≥ 128) negotiated for this session (§33).
    pub extension_types: Vec<u64>,
}

impl Default for DecodeOptions {
    fn default() -> Self {
        DecodeOptions {
            max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
            extension_types: Vec::new(),
        }
    }
}

/// An opaque hosting or account credential (§36, §39). It is server
/// policy, not LFCP Resource authorization, and it is secret: its `Debug`
/// output is redacted.
#[derive(Clone, PartialEq, Eq)]
pub struct HostingCredential(Vec<u8>);

impl HostingCredential {
    /// Wrap credential bytes.
    pub fn new(bytes: Vec<u8>) -> HostingCredential {
        HostingCredential(bytes)
    }

    /// The raw credential. Callers must not log it.
    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for HostingCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HostingCredential(<redacted>)")
    }
}

impl Drop for HostingCredential {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

/// A Control Head as messages carry it (§41).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlHead {
    /// Field 0: the Control Sequence.
    pub sequence: u64,
    /// Field 1: the Control Record ID.
    pub id: ControlRecordId,
}

/// An `actor-have` as messages carry it (§28, §41, §48).
///
/// Live messages are neither persistent objects nor cryptographic inputs,
/// so the §28.1 canonical rules are not applied on decode, and key 2 keeps
/// its presence exactly as received. [`WireActorHave::canonical`] applies
/// them when a caller needs a canonical entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireActorHave {
    /// Field 0: the actor.
    pub principal: PrincipalId,
    /// Field 1: the highest contiguous sequence.
    pub contiguous: u64,
    /// Field 2: extra ranges, when the field is present.
    pub extra: Option<Vec<(u64, u64)>>,
}

impl WireActorHave {
    /// The entry as a canonical [`ActorHave`], checked against §28.1.
    pub fn canonical(&self) -> Result<ActorHave, Error> {
        ActorHave::from_value(&self.to_value())
    }

    fn from_value(value: &Value) -> Result<WireActorHave, Error> {
        closed(value, &[0, 1], &[2])?;
        Ok(WireActorHave {
            principal: PrincipalId::from_bytes(bytes_n(value, 0)?),
            contiguous: uint(value, 1)?,
            extra: optional(value, 2, |ranges| {
                array_of(ranges, |range| match range.as_array() {
                    Some([start, end]) => Ok((as_uint(start)?, as_uint(end)?)),
                    _ => Err(MALFORMED),
                })
            })?,
        })
    }

    fn to_value(&self) -> Value {
        map(vec![
            (0, Some(bytes32(self.principal.as_bytes()))),
            (1, Some(Value::Unsigned(self.contiguous))),
            (
                2,
                self.extra.as_ref().map(|ranges| {
                    Value::Array(
                        ranges
                            .iter()
                            .map(|&(s, e)| {
                                Value::Array(vec![Value::Unsigned(s), Value::Unsigned(e)])
                            })
                            .collect(),
                    )
                }),
            ),
        ])
    }
}

/// A Data Plane range request (§49).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataRange {
    /// Field 0: the actor.
    pub principal: PrincipalId,
    /// Field 1: inclusive start.
    pub start: u64,
    /// Field 2: inclusive end.
    pub end: u64,
}

/// A Snapshot summary in `RESOURCE_OPENED` (§42).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotSummary {
    /// Field 0: the Snapshot ID.
    pub snapshot_id: Hash32,
    /// Field 1: the Data Epoch.
    pub data_epoch: u64,
    /// Field 2: the Snapshot frontier.
    pub frontier: Vec<WireActorHave>,
}

/// `HELLO` (§34).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HelloBody {
    /// Field 0: supported wire profiles, such as `LFCP-WIRE-01`.
    pub wire_profiles: Vec<String>,
    /// Field 1: the session Principal, its ID already recomputed.
    pub principal: PrincipalDescriptor,
    /// Field 2: the client nonce.
    pub client_nonce: [u8; 16],
    /// Field 3: supported application Data Profiles.
    pub data_profiles: Option<Vec<String>>,
}

/// `CHALLENGE` (§35).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChallengeBody {
    /// Field 0: the selected wire profile.
    pub wire_profile: String,
    /// Field 1: the server nonce.
    pub server_nonce: [u8; 16],
    /// Field 2: the session ID.
    pub session_id: [u8; 16],
    /// Field 3: the stable server ID.
    pub server_id: [u8; 32],
}

/// `AUTH` (§36).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthBody {
    /// Field 0: the exact COSE_Sign1 bytes of the auth proof.
    pub proof: Vec<u8>,
    /// Field 1: an opaque hosting credential.
    pub hosting_credential: Option<HostingCredential>,
}

/// `READY` (§37).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadyBody {
    /// Field 0: the selected wire profile.
    pub wire_profile: String,
    /// Field 1: the server ID.
    pub server_id: [u8; 32],
    /// Field 2: the maximum LFCP message size in bytes.
    pub max_message_bytes: u64,
    /// Field 3: the durability level (0–3).
    pub durability: u64,
    /// Field 4: the heartbeat interval in ms; 0 disables it.
    pub heartbeat_ms: u64,
    /// Field 5: supported server extensions.
    pub extensions: Option<Vec<String>>,
}

/// `ERROR` (§61) and `NACK` (§60) share one body shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErrorBody {
    /// Field 0: the §62 error code.
    pub code: u64,
    /// Field 1: a human-readable diagnostic, never containing secrets.
    pub diagnostic: Option<String>,
    /// Field 2: machine-readable details.
    pub details: Option<Value>,
}

impl ErrorBody {
    /// The `NACK` or `ERROR` body for `error`, if it has a wire code (see
    /// [`Error::wire_code`]): the code, no diagnostic, and the details §47
    /// defines for `CONTROL_HEAD_MISMATCH`, the current head's Control
    /// Record ID. Use [`Error::session_wire_code`] instead for `HELLO` and
    /// `AUTH`.
    pub fn for_error(error: &Error) -> Option<ErrorBody> {
        let code = error.wire_code()?;
        let details = match error {
            Error::ControlHeadMismatch { current } => {
                Some(Value::bytes(current.as_bytes().to_vec()))
            }
            _ => None,
        };
        Some(ErrorBody {
            code: code.number(),
            diagnostic: None,
            details,
        })
    }

    /// The registered code, if the number is in the §62 registry.
    pub fn wire_code(&self) -> Option<crate::base::WireCode> {
        crate::base::WireCode::from_number(self.code)
    }
}

/// `ACK` (§59).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AckBody {
    /// Field 0: the §33 type code of the acknowledged request (A1).
    pub request_type: u64,
    /// Field 1: IDs of the committed objects.
    pub object_ids: Option<Vec<Hash32>>,
    /// Field 2: durable under the advertised server policy.
    pub durable: Option<bool>,
}

/// A typed message body. Bodies with signed objects keep their exact
/// bytes; the `*_records`, `units`, `packages` and `snapshot` accessors
/// parse them.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(missing_docs)] // Each field is documented in the type table above.
pub enum Body {
    Hello(HelloBody),
    Challenge(ChallengeBody),
    Auth(AuthBody),
    Ready(ReadyBody),
    Error(ErrorBody),
    Ping([u8; 8]),
    Pong([u8; 8]),
    ResourceHost {
        genesis: Vec<u8>,
        hosting_credential: Option<HostingCredential>,
    },
    ResourceHosted {
        resource_id: ResourceId,
        durability: u64,
    },
    ResourceOpen {
        resource_id: ResourceId,
        control_heads: Vec<ControlHead>,
        have: Vec<WireActorHave>,
        grant_ids: Option<Vec<Hash32>>,
        flags: Option<u64>,
    },
    ResourceOpened {
        resource_id: ResourceId,
        control_heads: Vec<ControlHead>,
        have: Vec<WireActorHave>,
        snapshot: Option<SnapshotSummary>,
        route_version: Option<u64>,
        coordinator: Option<String>,
    },
    ResourceClose {
        resource_id: ResourceId,
    },
    ControlHave {
        resource_id: ResourceId,
        control_heads: Vec<ControlHead>,
    },
    ControlGet {
        resource_id: ResourceId,
        start: u64,
        end: u64,
    },
    ControlBatch {
        resource_id: ResourceId,
        records: Vec<Vec<u8>>,
    },
    ControlPut {
        resource_id: ResourceId,
        expected_head: ControlRecordId,
        record: Vec<u8>,
    },
    DataHave {
        resource_id: ResourceId,
        have: Vec<WireActorHave>,
    },
    DataGet {
        resource_id: ResourceId,
        ranges: Vec<DataRange>,
    },
    DataBatch {
        resource_id: ResourceId,
        units: Vec<Vec<u8>>,
    },
    DataPut {
        resource_id: ResourceId,
        units: Vec<Vec<u8>>,
    },
    KeyPackageGet {
        resource_id: ResourceId,
        recipient: PrincipalId,
        epochs: Vec<u64>,
    },
    KeyPackageBatch {
        resource_id: ResourceId,
        packages: Vec<Vec<u8>>,
    },
    KeyPackagePut {
        resource_id: ResourceId,
        packages: Vec<Vec<u8>>,
    },
    SnapshotGet {
        resource_id: ResourceId,
        snapshot_id: Option<Hash32>,
    },
    Snapshot {
        resource_id: ResourceId,
        snapshot: Vec<u8>,
    },
    SnapshotPut {
        resource_id: ResourceId,
        snapshot: Vec<u8>,
    },
    Presence {
        resource_id: ResourceId,
        principal: PrincipalId,
        ttl_ms: u64,
        payload: Vec<u8>,
    },
    PresenceLeave {
        resource_id: ResourceId,
        principal: PrincipalId,
    },
    Ack(AckBody),
    Nack(ErrorBody),
    /// A negotiated extension type (≥ 128) with an opaque body.
    Extension {
        message_type: u64,
        body: Value,
    },
}

impl Body {
    /// The §33 message type code.
    pub fn message_type(&self) -> u64 {
        match self {
            Body::Hello(_) => 0,
            Body::Challenge(_) => 1,
            Body::Auth(_) => 2,
            Body::Ready(_) => 3,
            Body::Error(_) => 4,
            Body::Ping(_) => 5,
            Body::Pong(_) => 6,
            Body::ResourceHost { .. } => 10,
            Body::ResourceHosted { .. } => 11,
            Body::ResourceOpen { .. } => 12,
            Body::ResourceOpened { .. } => 13,
            Body::ResourceClose { .. } => 14,
            Body::ControlHave { .. } => 20,
            Body::ControlGet { .. } => 21,
            Body::ControlBatch { .. } => 22,
            Body::ControlPut { .. } => 23,
            Body::DataHave { .. } => 30,
            Body::DataGet { .. } => 31,
            Body::DataBatch { .. } => 32,
            Body::DataPut { .. } => 33,
            Body::KeyPackageGet { .. } => 40,
            Body::KeyPackageBatch { .. } => 41,
            Body::KeyPackagePut { .. } => 42,
            Body::SnapshotGet { .. } => 50,
            Body::Snapshot { .. } => 51,
            Body::SnapshotPut { .. } => 52,
            Body::Presence { .. } => 60,
            Body::PresenceLeave { .. } => 61,
            Body::Ack(_) => 90,
            Body::Nack(_) => 91,
            Body::Extension { message_type, .. } => *message_type,
        }
    }

    /// Parse the Control Records a `CONTROL_BATCH` or `CONTROL_PUT`
    /// carries, from their exact bytes.
    pub fn control_records(&self) -> Option<Vec<Result<ReceivedControlRecord, Error>>> {
        match self {
            Body::ControlBatch { records, .. } => Some(
                records
                    .iter()
                    .map(|r| ReceivedControlRecord::parse(r))
                    .collect(),
            ),
            Body::ControlPut { record, .. } => Some(vec![ReceivedControlRecord::parse(record)]),
            Body::ResourceHost { genesis, .. } => Some(vec![ReceivedControlRecord::parse(genesis)]),
            _ => None,
        }
    }

    /// Parse the Data Units a `DATA_BATCH` or `DATA_PUT` carries.
    pub fn units(&self) -> Option<Vec<Result<ReceivedDataUnit, Error>>> {
        match self {
            Body::DataBatch { units, .. } | Body::DataPut { units, .. } => {
                Some(units.iter().map(|u| ReceivedDataUnit::parse(u)).collect())
            }
            _ => None,
        }
    }

    /// Parse the Key Packages a `KEY_PACKAGE_BATCH` or `KEY_PACKAGE_PUT`
    /// carries.
    pub fn packages(&self) -> Option<Vec<Result<ReceivedKeyPackage, Error>>> {
        match self {
            Body::KeyPackageBatch { packages, .. } | Body::KeyPackagePut { packages, .. } => Some(
                packages
                    .iter()
                    .map(|p| ReceivedKeyPackage::parse(p))
                    .collect(),
            ),
            _ => None,
        }
    }

    /// Parse the Snapshot a `SNAPSHOT` or `SNAPSHOT_PUT` carries.
    pub fn snapshot(&self) -> Option<Result<ReceivedSnapshot, Error>> {
        match self {
            Body::Snapshot { snapshot, .. } | Body::SnapshotPut { snapshot, .. } => {
                Some(ReceivedSnapshot::parse(snapshot))
            }
            _ => None,
        }
    }

    fn from_value(message_type: u64, b: &Value, options: &DecodeOptions) -> Result<Body, Error> {
        let resource = |key| bytes_n(b, key).map(ResourceId::from_bytes);
        let principal = |key| bytes_n(b, key).map(PrincipalId::from_bytes);
        Ok(match message_type {
            0 => {
                closed(b, &[0, 1, 2], &[3])?;
                Body::Hello(HelloBody {
                    wire_profiles: non_empty(texts(field(b, 0)?)?)?,
                    principal: PrincipalDescriptor::from_value(field(b, 1)?)?,
                    client_nonce: bytes_n(b, 2)?,
                    data_profiles: optional(b, 3, texts)?,
                })
            }
            1 => {
                closed(b, &[0, 1, 2, 3], &[])?;
                Body::Challenge(ChallengeBody {
                    wire_profile: text(b, 0)?,
                    server_nonce: bytes_n(b, 1)?,
                    session_id: bytes_n(b, 2)?,
                    server_id: bytes_n(b, 3)?,
                })
            }
            2 => {
                closed(b, &[0], &[1])?;
                Body::Auth(AuthBody {
                    proof: bytes(b, 0)?,
                    hosting_credential: optional(b, 1, |v| Ok(HostingCredential(as_bytes(v)?)))?,
                })
            }
            3 => {
                closed(b, &[0, 1, 2, 3, 4], &[5])?;
                Body::Ready(ReadyBody {
                    wire_profile: text(b, 0)?,
                    server_id: bytes_n(b, 1)?,
                    max_message_bytes: uint(b, 2)?,
                    durability: uint(b, 3)?,
                    heartbeat_ms: uint(b, 4)?,
                    extensions: optional(b, 5, texts)?,
                })
            }
            4 => Body::Error(ErrorBody::from_value(b)?),
            5 | 6 => {
                closed(b, &[0], &[])?;
                let payload = bytes_n(b, 0)?;
                if message_type == 5 {
                    Body::Ping(payload)
                } else {
                    Body::Pong(payload)
                }
            }
            10 => {
                closed(b, &[0], &[1])?;
                Body::ResourceHost {
                    genesis: bytes(b, 0)?,
                    hosting_credential: optional(b, 1, |v| Ok(HostingCredential(as_bytes(v)?)))?,
                }
            }
            11 => {
                closed(b, &[0, 1], &[])?;
                Body::ResourceHosted {
                    resource_id: resource(0)?,
                    durability: uint(b, 1)?,
                }
            }
            12 => {
                closed(b, &[0, 1, 2], &[3, 4])?;
                Body::ResourceOpen {
                    resource_id: resource(0)?,
                    control_heads: control_heads(field(b, 1)?)?,
                    have: haves(field(b, 2)?)?,
                    grant_ids: optional(b, 3, hashes)?,
                    flags: optional(b, 4, as_uint)?,
                }
            }
            13 => {
                closed(b, &[0, 1, 2], &[3, 4, 5])?;
                Body::ResourceOpened {
                    resource_id: resource(0)?,
                    control_heads: control_heads(field(b, 1)?)?,
                    have: haves(field(b, 2)?)?,
                    snapshot: optional(b, 3, |v| {
                        closed(v, &[0, 1, 2], &[])?;
                        Ok(SnapshotSummary {
                            snapshot_id: Hash32::from_bytes(bytes_n(v, 0)?),
                            data_epoch: uint(v, 1)?,
                            frontier: haves(field(v, 2)?)?,
                        })
                    })?,
                    route_version: optional(b, 4, as_uint)?,
                    coordinator: optional(b, 5, as_text)?,
                }
            }
            14 => {
                closed(b, &[0], &[])?;
                Body::ResourceClose {
                    resource_id: resource(0)?,
                }
            }
            20 => {
                closed(b, &[0, 1], &[])?;
                Body::ControlHave {
                    resource_id: resource(0)?,
                    control_heads: control_heads(field(b, 1)?)?,
                }
            }
            21 => {
                closed(b, &[0, 1, 2], &[])?;
                Body::ControlGet {
                    resource_id: resource(0)?,
                    start: uint(b, 1)?,
                    end: uint(b, 2)?,
                }
            }
            22 => {
                closed(b, &[0, 1], &[])?;
                Body::ControlBatch {
                    resource_id: resource(0)?,
                    records: byte_list(field(b, 1)?)?,
                }
            }
            23 => {
                closed(b, &[0, 1, 2], &[])?;
                // §47: the expected head is a hash32; null is invalid.
                Body::ControlPut {
                    resource_id: resource(0)?,
                    expected_head: ControlRecordId::from_bytes(bytes_n(b, 1)?),
                    record: bytes(b, 2)?,
                }
            }
            30 => {
                closed(b, &[0, 1], &[])?;
                Body::DataHave {
                    resource_id: resource(0)?,
                    have: haves(field(b, 1)?)?,
                }
            }
            31 => {
                closed(b, &[0, 1], &[])?;
                let ranges = array_of(field(b, 1)?, |r| {
                    closed(r, &[0, 1, 2], &[])?;
                    Ok(DataRange {
                        principal: PrincipalId::from_bytes(bytes_n(r, 0)?),
                        start: uint(r, 1)?,
                        end: uint(r, 2)?,
                    })
                })?;
                Body::DataGet {
                    resource_id: resource(0)?,
                    ranges: non_empty(ranges)?,
                }
            }
            32 | 33 => {
                closed(b, &[0, 1], &[])?;
                let units = byte_list(field(b, 1)?)?;
                if message_type == 32 {
                    Body::DataBatch {
                        resource_id: resource(0)?,
                        units,
                    }
                } else {
                    Body::DataPut {
                        resource_id: resource(0)?,
                        units: non_empty(units)?,
                    }
                }
            }
            40 => {
                closed(b, &[0, 1, 2], &[])?;
                Body::KeyPackageGet {
                    resource_id: resource(0)?,
                    recipient: principal(1)?,
                    epochs: non_empty(array_of(field(b, 2)?, as_uint)?)?,
                }
            }
            41 | 42 => {
                closed(b, &[0, 1], &[])?;
                let packages = byte_list(field(b, 1)?)?;
                if message_type == 41 {
                    Body::KeyPackageBatch {
                        resource_id: resource(0)?,
                        packages,
                    }
                } else {
                    Body::KeyPackagePut {
                        resource_id: resource(0)?,
                        packages: non_empty(packages)?,
                    }
                }
            }
            50 => {
                closed(b, &[0], &[1])?;
                Body::SnapshotGet {
                    resource_id: resource(0)?,
                    snapshot_id: optional(b, 1, |v| as_bytes_n(v).map(Hash32::from_bytes))?,
                }
            }
            51 | 52 => {
                closed(b, &[0, 1], &[])?;
                let (resource_id, snapshot) = (resource(0)?, bytes(b, 1)?);
                if message_type == 51 {
                    Body::Snapshot {
                        resource_id,
                        snapshot,
                    }
                } else {
                    Body::SnapshotPut {
                        resource_id,
                        snapshot,
                    }
                }
            }
            60 => {
                closed(b, &[0, 1, 2, 3], &[])?;
                Body::Presence {
                    resource_id: resource(0)?,
                    principal: principal(1)?,
                    ttl_ms: uint(b, 2)?,
                    payload: bytes(b, 3)?,
                }
            }
            61 => {
                closed(b, &[0, 1], &[])?;
                Body::PresenceLeave {
                    resource_id: resource(0)?,
                    principal: principal(1)?,
                }
            }
            90 => {
                closed(b, &[0], &[1, 2])?;
                Body::Ack(AckBody {
                    request_type: uint(b, 0)?,
                    object_ids: optional(b, 1, hashes)?,
                    durable: optional(b, 2, |v| match v {
                        Value::Bool(flag) => Ok(*flag),
                        _ => Err(MALFORMED),
                    })?,
                })
            }
            91 => Body::Nack(ErrorBody::from_value(b)?),
            t if t >= FIRST_EXTENSION_TYPE && options.extension_types.contains(&t) => {
                Body::Extension {
                    message_type: t,
                    body: b.clone(),
                }
            }
            t => return Err(Error::UnsupportedMessageType(t)),
        })
    }

    fn to_value(&self) -> Value {
        let id = |r: &ResourceId| Some(bytes32(r.as_bytes()));
        let u = |n: u64| Some(Value::Unsigned(n));
        let bytes = |b: &[u8]| Some(Value::bytes(b.to_vec()));
        let byte_list = |items: &[Vec<u8>]| {
            Some(Value::Array(
                items.iter().map(|i| Value::bytes(i.clone())).collect(),
            ))
        };
        let entries: Vec<(u64, Option<Value>)> = match self {
            Body::Hello(h) => vec![
                (0, Some(texts_value(&h.wire_profiles))),
                (1, Some(h.principal.to_value())),
                (2, bytes(&h.client_nonce)),
                (3, h.data_profiles.as_deref().map(texts_value)),
            ],
            Body::Challenge(c) => vec![
                (0, Some(Value::text(c.wire_profile.clone()))),
                (1, bytes(&c.server_nonce)),
                (2, bytes(&c.session_id)),
                (3, bytes(&c.server_id)),
            ],
            Body::Auth(a) => vec![
                (0, bytes(&a.proof)),
                (1, a.hosting_credential.as_ref().and_then(|c| bytes(&c.0))),
            ],
            Body::Ready(r) => vec![
                (0, Some(Value::text(r.wire_profile.clone()))),
                (1, bytes(&r.server_id)),
                (2, u(r.max_message_bytes)),
                (3, u(r.durability)),
                (4, u(r.heartbeat_ms)),
                (5, r.extensions.as_deref().map(texts_value)),
            ],
            Body::Error(e) | Body::Nack(e) => vec![
                (0, u(e.code)),
                (1, e.diagnostic.clone().map(Value::Text)),
                (2, e.details.clone()),
            ],
            Body::Ping(p) | Body::Pong(p) => vec![(0, bytes(p))],
            Body::ResourceHost {
                genesis,
                hosting_credential,
            } => vec![
                (0, bytes(genesis)),
                (1, hosting_credential.as_ref().and_then(|c| bytes(&c.0))),
            ],
            Body::ResourceHosted {
                resource_id,
                durability,
            } => vec![(0, id(resource_id)), (1, u(*durability))],
            Body::ResourceOpen {
                resource_id,
                control_heads,
                have,
                grant_ids,
                flags,
            } => vec![
                (0, id(resource_id)),
                (1, Some(control_heads_value(control_heads))),
                (2, Some(haves_value(have))),
                (3, grant_ids.as_deref().map(hashes_value)),
                (4, flags.map(Value::Unsigned)),
            ],
            Body::ResourceOpened {
                resource_id,
                control_heads,
                have,
                snapshot,
                route_version,
                coordinator,
            } => vec![
                (0, id(resource_id)),
                (1, Some(control_heads_value(control_heads))),
                (2, Some(haves_value(have))),
                (
                    3,
                    snapshot.as_ref().map(|s| {
                        map(vec![
                            (0, Some(bytes32(s.snapshot_id.as_bytes()))),
                            (1, Some(Value::Unsigned(s.data_epoch))),
                            (2, Some(haves_value(&s.frontier))),
                        ])
                    }),
                ),
                (4, route_version.map(Value::Unsigned)),
                (5, coordinator.clone().map(Value::Text)),
            ],
            Body::ResourceClose { resource_id } => vec![(0, id(resource_id))],
            Body::ControlHave {
                resource_id,
                control_heads,
            } => vec![
                (0, id(resource_id)),
                (1, Some(control_heads_value(control_heads))),
            ],
            Body::ControlGet {
                resource_id,
                start,
                end,
            } => vec![(0, id(resource_id)), (1, u(*start)), (2, u(*end))],
            Body::ControlBatch {
                resource_id,
                records,
            } => vec![(0, id(resource_id)), (1, byte_list(records))],
            Body::ControlPut {
                resource_id,
                expected_head,
                record,
            } => vec![
                (0, id(resource_id)),
                (1, Some(bytes32(expected_head.as_bytes()))),
                (2, bytes(record)),
            ],
            Body::DataHave { resource_id, have } => {
                vec![(0, id(resource_id)), (1, Some(haves_value(have)))]
            }
            Body::DataGet {
                resource_id,
                ranges,
            } => vec![
                (0, id(resource_id)),
                (
                    1,
                    Some(Value::Array(
                        ranges
                            .iter()
                            .map(|r| {
                                map(vec![
                                    (0, Some(bytes32(r.principal.as_bytes()))),
                                    (1, Some(Value::Unsigned(r.start))),
                                    (2, Some(Value::Unsigned(r.end))),
                                ])
                            })
                            .collect(),
                    )),
                ),
            ],
            Body::DataBatch { resource_id, units } | Body::DataPut { resource_id, units } => {
                vec![(0, id(resource_id)), (1, byte_list(units))]
            }
            Body::KeyPackageGet {
                resource_id,
                recipient,
                epochs,
            } => vec![
                (0, id(resource_id)),
                (1, Some(bytes32(recipient.as_bytes()))),
                (2, Some(crate::wire::uint_array(epochs))),
            ],
            Body::KeyPackageBatch {
                resource_id,
                packages,
            }
            | Body::KeyPackagePut {
                resource_id,
                packages,
            } => vec![(0, id(resource_id)), (1, byte_list(packages))],
            Body::SnapshotGet {
                resource_id,
                snapshot_id,
            } => vec![
                (0, id(resource_id)),
                (1, snapshot_id.map(|s| bytes32(s.as_bytes()))),
            ],
            Body::Snapshot {
                resource_id,
                snapshot,
            }
            | Body::SnapshotPut {
                resource_id,
                snapshot,
            } => vec![(0, id(resource_id)), (1, bytes(snapshot))],
            Body::Presence {
                resource_id,
                principal,
                ttl_ms,
                payload,
            } => vec![
                (0, id(resource_id)),
                (1, Some(bytes32(principal.as_bytes()))),
                (2, u(*ttl_ms)),
                (3, bytes(payload)),
            ],
            Body::PresenceLeave {
                resource_id,
                principal,
            } => vec![
                (0, id(resource_id)),
                (1, Some(bytes32(principal.as_bytes()))),
            ],
            Body::Ack(a) => vec![
                (0, u(a.request_type)),
                (1, a.object_ids.as_deref().map(hashes_value)),
                (2, a.durable.map(Value::Bool)),
            ],
            Body::Extension { body, .. } => return body.clone(),
        };
        map(entries)
    }
}

impl ErrorBody {
    fn from_value(b: &Value) -> Result<ErrorBody, Error> {
        closed(b, &[0], &[1, 2])?;
        Ok(ErrorBody {
            code: uint(b, 0)?,
            diagnostic: optional(b, 1, as_text)?,
            details: b.get_uint(2).cloned(),
        })
    }
}

/// One LFCP message: envelope and typed body (§32).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    /// Field 1: a random 128-bit message ID.
    pub message_id: [u8; 16],
    /// Field 2: the request's message ID, on a response.
    pub correlation_id: Option<[u8; 16]>,
    /// Field 3: flags; currently 0.
    pub flags: Option<u64>,
    /// Fields 0 and 4: the type and its body.
    pub body: Body,
    /// Envelope keys above 15 that were present but are not understood.
    /// They are ignored, as §32 allows, and not re-encoded.
    pub ignored_envelope_keys: Vec<u64>,
}

impl Message {
    /// A message with no correlation ID or flags.
    pub fn new(message_id: [u8; 16], body: Body) -> Message {
        Message {
            message_id,
            correlation_id: None,
            flags: None,
            body,
            ignored_envelope_keys: Vec::new(),
        }
    }

    /// Decode one received WebSocket data message. A text message is
    /// [`Error::TextFrame`]: the receiver sends `ERROR(MALFORMED_MESSAGE)`
    /// and closes the connection (§31; see [`Error::closes_connection`]).
    pub fn decode_frame(
        kind: FrameKind,
        bytes: &[u8],
        options: &DecodeOptions,
    ) -> Result<Message, Error> {
        match kind {
            FrameKind::Binary => Message::decode(bytes, options),
            FrameKind::Text => Err(Error::TextFrame),
        }
    }

    /// Decode one received LFCP message.
    pub fn decode(bytes: &[u8], options: &DecodeOptions) -> Result<Message, Error> {
        if bytes.len() > options.max_message_bytes {
            return Err(Error::MessageTooLarge {
                size: bytes.len(),
                limit: options.max_message_bytes,
            });
        }
        let envelope = cbor::decode_strict(bytes)?;
        let entries = envelope.as_map().ok_or(MALFORMED)?;
        let mut ignored_envelope_keys = Vec::new();
        for (key, _) in entries {
            match key.as_u64() {
                Some(0..=4) => {}
                Some(key @ 5..=15) => return Err(Error::MessageReservedEnvelopeKey(key)),
                Some(key) => ignored_envelope_keys.push(key),
                None => return Err(MALFORMED),
            }
        }
        let message_type = uint(&envelope, 0)?;
        let body = Body::from_value(message_type, field(&envelope, 4)?, options)?;
        Ok(Message {
            message_id: bytes_n(&envelope, 1)?,
            correlation_id: optional(&envelope, 2, as_bytes_n)?,
            flags: optional(&envelope, 3, as_uint)?,
            body,
            ignored_envelope_keys,
        })
    }

    /// The deterministic encoding of the message. Ignored envelope keys
    /// are not included.
    pub fn encode(&self) -> Vec<u8> {
        let envelope = map(vec![
            (0, Some(Value::Unsigned(self.body.message_type()))),
            (1, Some(Value::bytes(self.message_id.to_vec()))),
            (2, self.correlation_id.map(|c| Value::bytes(c.to_vec()))),
            (3, self.flags.map(Value::Unsigned)),
            (4, Some(self.body.to_value())),
        ]);
        cbor::encode(&envelope).expect("message bodies only hold encodable values")
    }
}

// Decoding helpers. Every failure is MALFORMED_MESSAGE.

fn closed(value: &Value, required: &[u64], optional: &[u64]) -> Result<(), Error> {
    check_closed_map(value, required, optional, MALFORMED)
}

fn field(value: &Value, key: u64) -> Result<&Value, Error> {
    value.get_uint(key).ok_or(MALFORMED)
}

fn optional<T>(
    value: &Value,
    key: u64,
    decode: impl FnOnce(&Value) -> Result<T, Error>,
) -> Result<Option<T>, Error> {
    value.get_uint(key).map(decode).transpose()
}

fn as_uint(value: &Value) -> Result<u64, Error> {
    value.as_u64().ok_or(MALFORMED)
}

fn as_text(value: &Value) -> Result<String, Error> {
    value.as_text().map(str::to_owned).ok_or(MALFORMED)
}

fn as_bytes(value: &Value) -> Result<Vec<u8>, Error> {
    value.as_bytes().map(<[u8]>::to_vec).ok_or(MALFORMED)
}

fn as_bytes_n<const N: usize>(value: &Value) -> Result<[u8; N], Error> {
    value
        .as_bytes()
        .and_then(|b| b.try_into().ok())
        .ok_or(MALFORMED)
}

fn uint(value: &Value, key: u64) -> Result<u64, Error> {
    as_uint(field(value, key)?)
}

fn text(value: &Value, key: u64) -> Result<String, Error> {
    as_text(field(value, key)?)
}

fn bytes(value: &Value, key: u64) -> Result<Vec<u8>, Error> {
    as_bytes(field(value, key)?)
}

fn bytes_n<const N: usize>(value: &Value, key: u64) -> Result<[u8; N], Error> {
    as_bytes_n(field(value, key)?)
}

fn array_of<T>(value: &Value, item: impl Fn(&Value) -> Result<T, Error>) -> Result<Vec<T>, Error> {
    value
        .as_array()
        .ok_or(MALFORMED)?
        .iter()
        .map(item)
        .collect()
}

fn non_empty<T>(items: Vec<T>) -> Result<Vec<T>, Error> {
    if items.is_empty() {
        Err(MALFORMED)
    } else {
        Ok(items)
    }
}

fn texts(value: &Value) -> Result<Vec<String>, Error> {
    array_of(value, as_text)
}

fn byte_list(value: &Value) -> Result<Vec<Vec<u8>>, Error> {
    array_of(value, as_bytes)
}

fn hashes(value: &Value) -> Result<Vec<Hash32>, Error> {
    array_of(value, |v| as_bytes_n(v).map(Hash32::from_bytes))
}

fn haves(value: &Value) -> Result<Vec<WireActorHave>, Error> {
    array_of(value, WireActorHave::from_value)
}

fn control_heads(value: &Value) -> Result<Vec<ControlHead>, Error> {
    array_of(value, |h| {
        closed(h, &[0, 1], &[])?;
        Ok(ControlHead {
            sequence: uint(h, 0)?,
            id: ControlRecordId::from_bytes(bytes_n(h, 1)?),
        })
    })
}

// Encoding helpers.

/// A map of unsigned keys; `None` entries are omitted.
fn map(entries: Vec<(u64, Option<Value>)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .filter_map(|(k, v)| v.map(|v| (Value::Unsigned(k), v)))
            .collect(),
    )
}

fn bytes32(bytes: &[u8; 32]) -> Value {
    Value::bytes(bytes.to_vec())
}

fn texts_value(items: &[String]) -> Value {
    Value::Array(items.iter().map(|t| Value::text(t.clone())).collect())
}

fn hashes_value(items: &[Hash32]) -> Value {
    Value::Array(items.iter().map(|h| bytes32(h.as_bytes())).collect())
}

fn haves_value(items: &[WireActorHave]) -> Value {
    Value::Array(items.iter().map(WireActorHave::to_value).collect())
}

fn control_heads_value(items: &[ControlHead]) -> Value {
    Value::Array(
        items
            .iter()
            .map(|h| {
                map(vec![
                    (0, Some(Value::Unsigned(h.sequence))),
                    (1, Some(bytes32(h.id.as_bytes()))),
                ])
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(entries: Vec<(u64, Value)>) -> Vec<u8> {
        cbor::encode(&Value::Map(
            entries
                .into_iter()
                .map(|(k, v)| (Value::Unsigned(k), v))
                .collect(),
        ))
        .unwrap()
    }

    fn ping_entries() -> Vec<(u64, Value)> {
        vec![
            (0, Value::Unsigned(5)),
            (1, Value::bytes(vec![1; 16])),
            (
                4,
                Value::Map(vec![(Value::Unsigned(0), Value::bytes(vec![2; 8]))]),
            ),
        ]
    }

    fn decode(bytes: &[u8]) -> Result<Message, Error> {
        Message::decode(bytes, &DecodeOptions::default())
    }

    fn control_put(expected_head: Value) -> Vec<u8> {
        envelope(vec![
            (0, Value::Unsigned(23)),
            (1, Value::bytes(vec![1; 16])),
            (
                4,
                Value::Map(vec![
                    (Value::Unsigned(0), Value::bytes(vec![7; 32])),
                    (Value::Unsigned(1), expected_head),
                    (Value::Unsigned(2), Value::bytes(vec![0x80])),
                ]),
            ),
        ])
    }

    #[test]
    fn control_put_needs_an_expected_head() {
        // §47 (G-MSG5): null is invalid; Genesis uses RESOURCE_HOST.
        let put = decode(&control_put(Value::bytes(vec![3; 32]))).unwrap();
        assert!(matches!(
            put.body,
            Body::ControlPut { expected_head, .. } if expected_head == ControlRecordId::from_bytes([3; 32])
        ));
        let err = decode(&control_put(Value::Null)).unwrap_err();
        assert_eq!(err, Error::MessageMalformed);
        assert_eq!(err.wire_code().unwrap().name(), "MALFORMED_MESSAGE");
    }

    #[test]
    fn head_mismatch_nack_carries_the_current_head() {
        let current = ControlRecordId::from_bytes([4; 32]);
        let body = ErrorBody::for_error(&Error::ControlHeadMismatch { current }).unwrap();
        assert_eq!(body.code, 10);
        assert_eq!(body.diagnostic, None);
        assert_eq!(body.details, Some(Value::bytes(vec![4; 32])));
        let other = ErrorBody::for_error(&Error::MessageMalformed).unwrap();
        assert_eq!((other.code, other.details), (2, None));
        assert_eq!(
            ErrorBody::for_error(&Error::AeadFailure),
            None,
            "client-local"
        );
    }

    #[test]
    fn text_frames_are_malformed_and_close() {
        // §31 (G-MSG7): ERROR(MALFORMED_MESSAGE), then close.
        let ping = envelope(ping_entries());
        let options = DecodeOptions::default();
        assert!(Message::decode_frame(FrameKind::Binary, &ping, &options).is_ok());
        let err = Message::decode_frame(FrameKind::Text, &ping, &options).unwrap_err();
        assert_eq!(err, Error::TextFrame);
        assert_eq!(err.wire_code().unwrap().name(), "MALFORMED_MESSAGE");
        assert!(err.closes_connection());
        // §34: no common profile is ERROR(PROTOCOL_UNSUPPORTED), then close.
        assert!(Error::NoCommonWireProfile.closes_connection());
        assert!(!Error::MessageMalformed.closes_connection());
    }

    #[test]
    fn ping_round_trips() {
        let bytes = envelope(ping_entries());
        let message = decode(&bytes).unwrap();
        assert_eq!(message.body, Body::Ping([2; 8]));
        assert_eq!(message.encode(), bytes);
    }

    #[test]
    fn envelope_keys_above_15_are_ignored_and_reserved_keys_rejected() {
        let mut entries = ping_entries();
        entries.push((20, Value::text("future")));
        let message = decode(&envelope(entries)).unwrap();
        assert_eq!(message.ignored_envelope_keys, vec![20]);
        assert_eq!(message.encode(), envelope(ping_entries()));

        let mut entries = ping_entries();
        entries.push((7, Value::Null));
        let err = decode(&envelope(entries)).unwrap_err();
        assert_eq!(err, Error::MessageReservedEnvelopeKey(7));
        assert_eq!(err.wire_code().unwrap().name(), "MALFORMED_MESSAGE");
    }

    #[test]
    fn message_types_outside_the_registry() {
        for code in [7, 92, 127, 128] {
            let mut entries = ping_entries();
            entries[0].1 = Value::Unsigned(code);
            let err = decode(&envelope(entries)).unwrap_err();
            assert_eq!(err, Error::UnsupportedMessageType(code), "{code}");
            assert_eq!(err.wire_code().unwrap().name(), "PROTOCOL_UNSUPPORTED");
        }
        let mut entries = ping_entries();
        entries[0].1 = Value::Unsigned(200);
        let options = DecodeOptions {
            extension_types: vec![200],
            ..DecodeOptions::default()
        };
        let message = Message::decode(&envelope(entries.clone()), &options).unwrap();
        assert_eq!(message.body.message_type(), 200);
        assert_eq!(message.encode(), envelope(entries));
    }

    #[test]
    fn size_limit_and_shape() {
        let bytes = envelope(ping_entries());
        let options = DecodeOptions {
            max_message_bytes: bytes.len() - 1,
            ..DecodeOptions::default()
        };
        let err = Message::decode(&bytes, &options).unwrap_err();
        assert_eq!(err.wire_code().unwrap().name(), "MESSAGE_TOO_LARGE");

        let mut short_payload = ping_entries();
        short_payload[2].1 = Value::Map(vec![(Value::Unsigned(0), Value::bytes(vec![2; 7]))]);
        assert_eq!(decode(&envelope(short_payload)), Err(MALFORMED));
        let mut no_body = ping_entries();
        no_body.pop();
        assert_eq!(decode(&envelope(no_body)), Err(MALFORMED));
        assert_eq!(decode(&[0xa0]), Err(MALFORMED));
    }

    #[test]
    fn hosting_credentials_do_not_print() {
        let credential = HostingCredential::new(b"hunter2".to_vec());
        assert_eq!(format!("{credential:?}"), "HostingCredential(<redacted>)");
    }
}
