//! The Rust side of the cross-language conformance harness (LFCP-070).
//!
//! ```text
//! cargo run --example interop --features shared-objects -- produce <dir>
//! cargo run --example interop --features shared-objects -- consume <dir>
//! ```
//!
//! `produce` writes `<dir>/bundle.json`: freshly generated protocol objects
//! (production randomness: keys, DEKs, HPKE, nonces) with the semantics a
//! consumer must derive from them. `consume` reads a bundle produced by any
//! implementation and writes `<dir>/results-rust.json`: one PASS/FAIL per
//! check. The exchange is the protocol bytes themselves (hex in JSON);
//! nothing is shared in memory. Keys are synthetic, made for this run.
//!
//! The bundle format (`lfcp-interop-bundle/1`) and the check IDs are shared
//! with the TypeScript adapter in openlfcp/examples (conformance/).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use lfcp::base::{
    to_hex, ControlRecordId, DataUnitId, Error, Hash32, ObjectId, PrincipalId, ResourceId,
};
use lfcp::cbor::Value;
use lfcp::principal::{PrincipalDescriptor, PrincipalKeys};
use lfcp::shared_objects::document::{NewTask, SharedObjects};
use lfcp::shared_objects::framing;
use lfcp::shared_objects::identity::{actor_id, principal_ref};
use lfcp::shared_objects::values::Plain;
use lfcp::wire::control::authority::{
    data_unit_policy, key_package_policy, snapshot_policy, validate_authorized, ControlState,
};
use lfcp::wire::control::body::{
    CapabilityClaimBody, CapabilityGrantBody, CapabilityRevokeBody, ControlBody, Endpoint,
    GenesisBody, KeyEpochBody,
};
use lfcp::wire::control::chain::ChainOutcome;
use lfcp::wire::control::{ControlRecord, ControlRecordHeader};
use lfcp::wire::data_unit::{check_equivocation, DataUnit, DataUnitHeader, ReceivedDataUnit};
use lfcp::wire::frontier::{ActorHave, Frontier};
use lfcp::wire::key_package::{KeyPackage, ReceivedKeyPackage};
use lfcp::wire::keys::{dek_commitment, Dek};
use lfcp::wire::message::{
    AckBody, Body, ChallengeBody, ControlHead, DecodeOptions, ErrorBody, HelloBody, Message,
    ReadyBody, WireActorHave,
};
use lfcp::wire::session::{auth, verify_auth, WIRE_PROFILE};
use lfcp::wire::snapshot::{ReceivedSnapshot, Snapshot, SnapshotHeader};
use serde_json::{json, Value as Json};

const FORMAT: &str = "lfcp-interop-bundle/1";
const PROFILE: &str = "org.openlfcp.shared-objects.v1";
const URL: &str = "wss://interop.example.test/v1/ws";
const PRINCIPALS: [&str; 5] = ["owner", "bob", "carol", "invite", "dave"];
const SCALAR_FIELDS: [&str; 7] = [
    "lifecycle",
    "title",
    "status",
    "due",
    "scheduled",
    "completion_date",
    "priority",
];

fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).expect("OS randomness");
    bytes
}

fn hex(bytes: &[u8]) -> Json {
    json!(to_hex(bytes))
}

fn unhex(value: &Json) -> Vec<u8> {
    lfcp::base::from_hex(value.as_str().expect("a hex string")).expect("hex")
}

fn unhex32(value: &Json) -> [u8; 32] {
    unhex(value).try_into().expect("32 bytes")
}

/// A fresh canonical UUIDv7-shaped Object ID.
fn object_id() -> ObjectId {
    let b: [u8; 16] = random();
    let mut b = b;
    b[6] = 0x70 | (b[6] & 0x0f);
    b[8] = 0x80 | (b[8] & 0x3f);
    let h = to_hex(&b);
    ObjectId::parse(&format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    ))
    .expect("a UUIDv7")
}

fn h32(id: &ControlRecordId) -> Hash32 {
    Hash32::from_bytes(*id.as_bytes())
}

// ---------------------------------------------------------------- produce

struct Producer {
    resource: ResourceId,
    keys: BTreeMap<&'static str, PrincipalKeys>,
    secrets: BTreeMap<&'static str, ([u8; 32], [u8; 32])>,
    records: Vec<ControlRecord>,
}

impl Producer {
    fn id(&self, name: &str) -> PrincipalId {
        *self.keys[name].descriptor().id()
    }

    fn desc(&self, name: &str) -> PrincipalDescriptor {
        self.keys[name].descriptor().clone()
    }

    fn head(&self) -> ControlRecordId {
        self.records.last().unwrap().id()
    }

    fn sign(
        &self,
        issuer: &str,
        sequence: u64,
        previous: ControlRecordId,
        body: ControlBody,
    ) -> ControlRecord {
        ControlRecord::sign(
            ControlRecordHeader {
                resource_id: self.resource,
                sequence,
                previous: Some(previous),
                issuer: self.id(issuer),
            },
            body,
            &self.keys[issuer],
        )
        .unwrap()
    }

    fn append(&mut self, issuer: &str, body: ControlBody) -> ControlRecordId {
        let record = self.sign(issuer, self.records.len() as u64, self.head(), body);
        let id = record.id();
        self.records.push(record);
        id
    }

    fn grant(&self, subject: &str, abilities: &[u64], claim_limit: Option<u64>) -> ControlBody {
        ControlBody::CapabilityGrant(CapabilityGrantBody {
            subject: self.desc(subject),
            abilities: abilities.to_vec(),
            delegable: vec![],
            parent: None,
            claim_limit,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn unit(
        &self,
        actor: &str,
        epoch: u64,
        sequence: u64,
        previous: Option<DataUnitId>,
        head: ControlRecordId,
        plaintext: &[u8],
        dek: &Dek,
    ) -> DataUnit {
        DataUnit::seal(
            DataUnitHeader {
                resource_id: self.resource,
                data_epoch: epoch,
                actor: self.id(actor),
                sequence,
                previous,
                control_head: h32(&head),
            },
            plaintext,
            dek,
            &self.keys[actor],
        )
        .unwrap()
    }

    fn frontier(&self, entries: &[(&str, u64)]) -> Frontier {
        Frontier::new(
            entries
                .iter()
                .map(|(name, contiguous)| ActorHave {
                    principal: self.id(name),
                    contiguous: *contiguous,
                    extra: vec![],
                })
                .collect(),
        )
        .unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn snapshot(
        &self,
        publisher: &str,
        epoch: u64,
        sequence: u64,
        head: ControlRecordId,
        frontier: Frontier,
        plaintext: &[u8],
        dek: &Dek,
    ) -> Snapshot {
        Snapshot::seal(
            SnapshotHeader {
                resource_id: self.resource,
                data_epoch: epoch,
                publisher: self.id(publisher),
                sequence,
                control_head: h32(&head),
                frontier,
            },
            plaintext,
            dek,
            &self.keys[publisher],
        )
        .unwrap()
    }

    fn package(
        &self,
        sender: &str,
        recipient: &str,
        epoch: u64,
        head: ControlRecordId,
        dek: &Dek,
    ) -> KeyPackage {
        KeyPackage::seal(
            self.resource,
            epoch,
            h32(&head),
            dek,
            self.keys[recipient].descriptor(),
            &self.keys[sender],
        )
        .unwrap()
    }
}

fn plain_json(p: &Plain) -> Json {
    match p {
        Plain::Null | Plain::Unknown => Json::Null,
        Plain::Bool(b) => json!(b),
        Plain::Int(i) | Plain::Counter(i) | Plain::Timestamp(i) => json!(i),
        Plain::Uint(u) => json!(u),
        Plain::F64(f) => json!(f),
        Plain::Str(s) | Plain::Text(s) => json!(s),
        Plain::Bytes(b) => hex(b),
        Plain::Map(m) => Json::Object(m.iter().map(|(k, v)| (k.clone(), plain_json(v))).collect()),
        Plain::List(l) => Json::Array(l.iter().map(plain_json).collect()),
    }
}

/// The logical view both implementations compare: the root with each
/// field's winning value, and the conflicted scalar fields of every object
/// with their values, sorted by their JSON text.
fn view(doc: &SharedObjects) -> Json {
    let mut conflicts = serde_json::Map::new();
    for key in doc.object_keys().unwrap() {
        let mut fields = serde_json::Map::new();
        for (field, values) in doc.conflicts(&key).unwrap() {
            if !SCALAR_FIELDS.contains(&field.as_str()) {
                continue;
            }
            let mut values: Vec<Json> = values.iter().map(plain_json).collect();
            values.sort_by_key(|v| v.to_string());
            fields.insert(field, Json::Array(values));
        }
        if !fields.is_empty() {
            conflicts.insert(key, Json::Object(fields));
        }
    }
    json!({ "root": plain_json(&doc.plain().unwrap()), "conflicts": conflicts })
}

fn produce(dir: &Path) {
    let resource = ResourceId::from_bytes(random());
    let mut keys = BTreeMap::new();
    let mut secrets = BTreeMap::new();
    for name in PRINCIPALS {
        let (seed, x): ([u8; 32], [u8; 32]) = (random(), random());
        keys.insert(name, PrincipalKeys::from_secrets(&seed, x));
        secrets.insert(name, (seed, x));
    }
    let dek0 = Dek::from_bytes(random());
    let dek1 = Dek::from_bytes(random());
    let mut p = Producer {
        resource,
        keys,
        secrets,
        records: vec![],
    };

    // Control: Genesis, grants, an invitation and its claim, a revoked
    // grant, and a Key Epoch closing epoch 0 at BOB's sequence 2.
    let genesis = ControlRecord::sign(
        ControlRecordHeader {
            resource_id: resource,
            sequence: 0,
            previous: None,
            issuer: p.id("owner"),
        },
        ControlBody::Genesis(GenesisBody {
            data_profile: PROFILE.into(),
            owner: p.desc("owner"),
            dek_commitment: dek_commitment(&resource, 0, &dek0),
            endpoints: vec![Endpoint {
                url: URL.into(),
                priority: 0,
                flags: None,
            }],
            coordinator: URL.into(),
        }),
        &p.keys["owner"],
    )
    .unwrap();
    p.records.push(genesis);
    let c1 = p.append("owner", p.grant("bob", &[1, 2, 3, 6], None));
    let c2 = p.append("owner", p.grant("invite", &[1, 2, 11], Some(1)));
    let claim = ControlBody::CapabilityClaim(CapabilityClaimBody {
        invitation_grant: c2,
        claimant: p.desc("carol"),
        abilities: vec![1, 2],
    });
    let c3 = p.append("invite", claim);
    let c4 = p.append("owner", p.grant("dave", &[1], None));
    let c5 = p.append(
        "owner",
        ControlBody::CapabilityRevoke(CapabilityRevokeBody { grant: c4 }),
    );
    let cutoff = p.frontier(&[("bob", 2)]);
    let c6 = p.append(
        "owner",
        ControlBody::KeyEpoch(KeyEpochBody {
            epoch: 1,
            dek_commitment: dek_commitment(&resource, 1, &dek1),
            final_frontier: cutoff,
            reason: 1,
        }),
    );

    // Data Units, Key Packages, a Snapshot.
    let u1 = p.unit("bob", 0, 1, None, c1, b"unit 1 from bob", &dek0);
    let u2 = p.unit("bob", 0, 2, Some(u1.id()), c3, b"unit 2 from bob", &dek0);
    let u3 = p.unit("carol", 1, 1, None, c6, b"unit 1 from carol", &dek1);
    let u4 = p.unit("bob", 1, 3, Some(u2.id()), c6, b"unit 3 from bob", &dek1);
    let units = [
        ("u1", &u1, 0, "unit 1 from bob"),
        ("u2", &u2, 0, "unit 2 from bob"),
        ("u3", &u3, 1, "unit 1 from carol"),
        ("u4", &u4, 1, "unit 3 from bob"),
    ];
    let packages = [
        (
            "kp_bob_e0",
            p.package("owner", "bob", 0, c1, &dek0),
            "bob",
            0,
        ),
        (
            "kp_invite_e0",
            p.package("owner", "invite", 0, c2, &dek0),
            "invite",
            0,
        ),
        (
            "kp_bob_e1",
            p.package("owner", "bob", 1, c6, &dek1),
            "bob",
            1,
        ),
        (
            "kp_carol_e1",
            p.package("bob", "carol", 1, c6, &dek1),
            "carol",
            1,
        ),
    ];
    let s1 = p.snapshot(
        "bob",
        1,
        1,
        c6,
        p.frontier_sorted(&[("bob", 3), ("carol", 1)]),
        b"snapshot 1",
        &dek1,
    );

    // Wire messages.
    let bob = &p.keys["bob"];
    let hello = HelloBody {
        wire_profiles: vec![WIRE_PROFILE.into()],
        principal: bob.descriptor().clone(),
        client_nonce: random(),
        data_profiles: None,
    };
    let challenge = ChallengeBody {
        wire_profile: WIRE_PROFILE.into(),
        server_nonce: random(),
        session_id: random(),
        server_id: random(),
    };
    let auth_body = auth(bob, &hello, &challenge, None).unwrap();
    let message = |body: Body| Message::new(random(), body).encode();
    let have = vec![
        WireActorHave {
            principal: p.id("bob"),
            contiguous: 3,
            extra: None,
        },
        WireActorHave {
            principal: p.id("carol"),
            contiguous: 1,
            extra: None,
        },
    ];
    let messages = vec![
        ("HELLO", message(Body::Hello(hello))),
        ("CHALLENGE", message(Body::Challenge(challenge.clone()))),
        ("AUTH", message(Body::Auth(auth_body))),
        (
            "READY",
            message(Body::Ready(ReadyBody {
                wire_profile: WIRE_PROFILE.into(),
                server_id: challenge.server_id,
                max_message_bytes: 8 * 1024 * 1024,
                durability: 2,
                heartbeat_ms: 30_000,
                extensions: Some(vec![]),
            })),
        ),
        (
            "RESOURCE_OPEN",
            message(Body::ResourceOpen {
                resource_id: resource,
                control_heads: vec![ControlHead {
                    sequence: 6,
                    id: c6,
                }],
                have,
                grant_ids: None,
                flags: Some(3),
            }),
        ),
        (
            "CONTROL_BATCH",
            message(Body::ControlBatch {
                resource_id: resource,
                records: p
                    .records
                    .iter()
                    .map(|r| r.signed_object().bytes().to_vec())
                    .collect(),
            }),
        ),
        (
            "DATA_BATCH",
            message(Body::DataBatch {
                resource_id: resource,
                units: units
                    .iter()
                    .map(|(_, u, _, _)| u.signed_object().bytes().to_vec())
                    .collect(),
            }),
        ),
        (
            "KEY_PACKAGE_BATCH",
            message(Body::KeyPackageBatch {
                resource_id: resource,
                packages: packages
                    .iter()
                    .map(|(_, k, _, _)| k.signed_object().bytes().to_vec())
                    .collect(),
            }),
        ),
        (
            "SNAPSHOT",
            message(Body::Snapshot {
                resource_id: resource,
                snapshot: s1.signed_object().bytes().to_vec(),
            }),
        ),
        (
            "ACK",
            message(Body::Ack(AckBody {
                request_type: 33,
                object_ids: Some(
                    units
                        .iter()
                        .map(|(_, u, _, _)| Hash32::from_bytes(*u.id().as_bytes()))
                        .collect(),
                ),
                durable: Some(true),
            })),
        ),
        (
            "NACK",
            message(Body::Nack(ErrorBody {
                code: 10,
                diagnostic: None,
                details: Some(Value::bytes(c6.as_bytes().to_vec())),
            })),
        ),
        (
            "ERROR",
            message(Body::Error(ErrorBody {
                code: 3,
                diagnostic: None,
                details: None,
            })),
        ),
    ];

    // Negatives with the code a receiver must reach.
    let mut tampered = u1.signed_object().bytes().to_vec();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    let unit_bytes = |u: &DataUnit| u.signed_object().bytes().to_vec();
    let u4b = p.unit("bob", 1, 3, Some(u2.id()), c6, b"a different unit 3", &dek1);
    let negatives = vec![
        json!({ "name": "unit_tampered", "kind": "unit", "bytes": hex(&tampered), "expect": "INVALID_SIGNATURE" }),
        json!({ "name": "unit_unauthorized", "kind": "unit",
                "bytes": hex(&unit_bytes(&p.unit("dave", 0, 1, None, c4, b"dave", &dek0))), "expect": "AUTHORIZATION_FAILED" }),
        json!({ "name": "unit_stale", "kind": "unit",
                "bytes": hex(&unit_bytes(&p.unit("bob", 0, 7, Some(u2.id()), c3, b"stale", &dek0))), "expect": "STALE_DATA_EPOCH" }),
        json!({ "name": "unit_unknown_epoch", "kind": "unit",
                "bytes": hex(&unit_bytes(&p.unit("bob", 5, 8, Some(u4.id()), c6, b"future", &dek1))), "expect": "MISSING_DEPENDENCY" }),
        json!({ "name": "unit_aead", "kind": "unit",
                "bytes": hex(&unit_bytes(&p.unit("bob", 1, 9, Some(u4.id()), c6, b"wrong key", &Dek::from_bytes(random())))), "expect": "AEAD" }),
        json!({ "name": "unit_equivocation", "kind": "unit_pair",
                "pair": [hex(&unit_bytes(&u4)), hex(&unit_bytes(&u4b))], "expect": "ACTOR_EQUIVOCATION" }),
        json!({ "name": "record_unauthorized", "kind": "record",
                "bytes": hex(p.sign("bob", 7, c6, p.grant("dave", &[1], None)).signed_object().bytes()), "expect": "AUTHORIZATION_FAILED" }),
        json!({ "name": "record_claim_used", "kind": "record",
                "bytes": hex(p.sign("invite", 7, c6, ControlBody::CapabilityClaim(CapabilityClaimBody {
                    invitation_grant: c2, claimant: p.desc("dave"), abilities: vec![1] })).signed_object().bytes()),
                "expect": "AUTHORIZATION_FAILED" }),
        json!({ "name": "record_fork", "kind": "record",
                "bytes": hex(p.sign("owner", 6, c5, p.grant("dave", &[1], None)).signed_object().bytes()), "expect": "CONTROL_CONFLICT" }),
        json!({ "name": "kp_unauthorized", "kind": "key_package",
                "bytes": hex(p.package("carol", "bob", 1, c6, &dek1).signed_object().bytes()), "expect": "AUTHORIZATION_FAILED" }),
        json!({ "name": "snapshot_unauthorized", "kind": "snapshot",
                "bytes": hex(p.snapshot("carol", 1, 1, c6, p.frontier_sorted(&[("carol", 1)]), b"carol", &dek1).signed_object().bytes()),
                "expect": "AUTHORIZATION_FAILED" }),
        json!({ "name": "snapshot_beyond_cutoff", "kind": "snapshot",
                "bytes": hex(p.snapshot("bob", 0, 2, c6, p.frontier_sorted(&[("bob", 3)]), b"too much", &dek0).signed_object().bytes()),
                "expect": "STALE_DATA_EPOCH" }),
    ];

    let shared = produce_shared_objects(&p);

    let state = validate_authorized(
        &p.records
            .iter()
            .map(|r| r.signed_object().bytes())
            .collect::<Vec<_>>(),
        None,
    )
    .unwrap()
    .1
    .pop()
    .unwrap();
    let bundle = json!({
        "format": FORMAT,
        "producer": "rust",
        "resource_id": hex(resource.as_bytes()),
        "principals": PRINCIPALS.iter().map(|n| (n.to_string(), json!({
            "descriptor": hex(&p.keys[n].descriptor().encode()),
            "ed25519_seed": hex(&p.secrets[n].0),
            "x25519_private": hex(&p.secrets[n].1),
        }))).collect::<serde_json::Map<_, _>>(),
        "control": {
            "records": p.records.iter().map(|r| hex(r.signed_object().bytes())).collect::<Vec<_>>(),
            "expect": control_expect(&p, &state),
        },
        "units": units.iter().map(|(n, u, e, t)| json!({
            "name": n, "bytes": hex(u.signed_object().bytes()), "epoch": e, "plaintext": hex(t.as_bytes()),
        })).collect::<Vec<_>>(),
        "key_packages": packages.iter().map(|(n, k, r, e)| json!({
            "name": n, "bytes": hex(k.signed_object().bytes()), "recipient": r, "epoch": e,
        })).collect::<Vec<_>>(),
        "snapshots": [ { "name": "s1", "bytes": hex(s1.signed_object().bytes()), "epoch": 1, "plaintext": hex(b"snapshot 1") } ],
        "messages": messages.iter().map(|(n, b)| json!({ "name": n, "bytes": hex(b) })).collect::<Vec<_>>(),
        "negatives": negatives,
        "shared_objects": shared,
    });
    std::fs::write(
        dir.join("bundle.json"),
        serde_json::to_vec_pretty(&bundle).unwrap(),
    )
    .unwrap();
}

impl Producer {
    /// A frontier with its entries in canonical (raw Principal ID) order.
    fn frontier_sorted(&self, entries: &[(&str, u64)]) -> Frontier {
        let mut entries: Vec<(&str, u64)> = entries.to_vec();
        entries.sort_by(|a, b| self.id(a.0).as_bytes().cmp(self.id(b.0).as_bytes()));
        self.frontier(&entries)
    }
}

fn control_expect(p: &Producer, state: &ControlState) -> Json {
    let name_of = |id: &PrincipalId| PRINCIPALS.iter().find(|n| p.id(n) == *id).copied().unwrap();
    json!({
        "head_seq": state.head.sequence,
        "head_id": hex(state.head.id.as_bytes()),
        "owner": name_of(state.owner.id()),
        "current_epoch": state.current_epoch,
        "abilities": PRINCIPALS.iter().map(|n| (n.to_string(), json!(state.abilities(&p.id(n)).into_iter().collect::<Vec<_>>()))).collect::<serde_json::Map<_, _>>(),
        "dek_commitments": state.dek_commitments.iter().map(|(e, c)| (e.to_string(), hex(c.as_bytes()))).collect::<serde_json::Map<_, _>>(),
        "closed_frontiers": state.closed_frontiers.iter().map(|(e, f)| (e.to_string(), json!(f.entries().iter().map(|a| json!({
            "principal": name_of(&a.principal), "contiguous": a.contiguous, "extra": a.extra,
        })).collect::<Vec<_>>()))).collect::<serde_json::Map<_, _>>(),
    })
}

/// A Shared Objects history by three writers: two Tasks, a concurrent
/// title conflict, tags added and removed, an edit under a tombstone, an
/// unknown Task field and an object of an unknown type.
fn produce_shared_objects(p: &Producer) -> Json {
    let r = p.resource;
    let actor = |n: &str| actor_id(&r, &p.id(n));
    let mut owner = SharedObjects::new(actor("owner"));
    owner.initialize().unwrap();
    let t1 = object_id();
    let t2 = object_id();
    owner
        .create_task(&NewTask::new(t1.clone(), p.id("owner"), "Plan the release"))
        .unwrap();
    owner
        .create_task(&NewTask::new(t2.clone(), p.id("owner"), "Draft notes"))
        .unwrap();
    // A change large enough that Automerge stores it as a compressed
    // (type 2) change chunk.
    let t3 = object_id();
    owner
        .create_task(&NewTask::new(t3, p.id("owner"), "Long notes ".repeat(300)))
        .unwrap();
    let mut bob = owner.fork(actor("bob"));
    // Another first change by bob on the same state: equivocation (§26.2).
    let mut bob_twin = owner.fork(actor("bob"));
    let twin = bob_twin
        .set_title(t1.as_str(), "Plan the release (bob, twin)")
        .unwrap();
    let mut carol = owner.fork(actor("carol"));
    bob.set_title(t1.as_str(), "Plan the release (bob)")
        .unwrap();
    carol
        .set_title(t1.as_str(), "Plan the release (carol)")
        .unwrap();
    bob.add_tag(t1.as_str(), "urgent").unwrap();
    carol.add_tag(t1.as_str(), "later").unwrap();
    owner.delete(t2.as_str()).unwrap();
    carol.set_title(t2.as_str(), "Draft notes, edited").unwrap();
    // The owner takes bob's changes, removes bob's tag, then takes carol's:
    // the title conflict arrives last, in the same order as the TypeScript
    // producer.
    owner.merge(&mut bob).unwrap();
    owner.remove_tag(t1.as_str(), "urgent").unwrap();
    owner.merge(&mut carol).unwrap();
    owner
        .write_field(
            "x.custom",
            t1.as_str(),
            "x_custom_note",
            &Plain::Str("kept".into()),
        )
        .unwrap();
    let poll = object_id();
    let mut fields = BTreeMap::new();
    fields.insert("id".to_owned(), Plain::Str(poll.as_str().into()));
    fields.insert("type".to_owned(), Plain::Str("com.example.poll".into()));
    fields.insert("lifecycle".to_owned(), Plain::Str("active".into()));
    fields.insert(
        "created_by".to_owned(),
        Plain::Str(principal_ref(&p.id("owner"))),
    );
    fields.insert("extensions".to_owned(), Plain::Map(BTreeMap::new()));
    fields.insert("question".to_owned(), Plain::Str("Ship on Friday?".into()));
    owner
        .insert_object(
            "com.example.poll.create",
            poll.as_str(),
            &Plain::Map(fields),
        )
        .unwrap();

    let signer_of = |a: &automerge::ActorId| -> &str {
        ["owner", "bob", "carol"]
            .into_iter()
            .find(|n| actor(n) == *a)
            .unwrap()
    };
    let changes = owner.changes();
    let first_bob = changes
        .iter()
        .find(|c| signer_of(c.actor_id()) == "bob")
        .unwrap()
        .clone();
    let entries: Vec<Json> = changes
        .iter()
        .map(|c| json!({ "plaintext": hex(&framing::encode_change(c.raw_bytes())), "signer": signer_of(c.actor_id()) }))
        .collect();
    // The chunk types this producer emitted (byte 8 of each chunk).
    let chunk_types: BTreeSet<u8> = changes.iter().map(|c| c.raw_bytes()[8]).collect();
    let expect = view(&owner);
    let snapshot = framing::encode_snapshot(&owner.save());

    // Negatives.
    let raw = first_bob.raw_bytes().to_vec();
    let mut corrupt = raw.clone();
    corrupt[4] ^= 0xff;
    let mut invalid = owner.fork(actor("owner"));
    invalid
        .write_field("mutation", t1.as_str(), "status", &Plain::Int(7))
        .unwrap();
    let mut tags = BTreeMap::new();
    tags.insert("#bad".to_owned(), Plain::Bool(true));
    let bad_tags = invalid
        .write_field("mutation", t1.as_str(), "tags", &Plain::Map(tags))
        .unwrap();
    let _ = bad_tags;
    let invalid_changes: Vec<Json> = invalid
        .changes()
        .iter()
        .skip(changes.len())
        .map(|c| json!({ "plaintext": hex(&framing::encode_change(c.raw_bytes())), "signer": "owner" }))
        .collect();
    let t1p = format!("/objects/{}", t1.as_str());
    json!({
        "changes": entries,
        "change_chunk_types": chunk_types.into_iter().collect::<Vec<_>>(),
        "snapshot": hex(&snapshot),
        "expect": expect,
        "negatives": [
            { "name": "change_signer", "kind": "change", "plaintext": hex(&framing::encode_change(&raw)), "signer": "carol",
              "expect": "CHANGE_ACTOR_MISMATCH" },
            { "name": "change_checksum", "kind": "change", "plaintext": hex(&framing::encode_change(&corrupt)), "signer": "bob",
              "expect": "INVALID_AUTOMERGE_BYTES" },
            { "name": "snapshot_change_chunk", "kind": "snapshot", "plaintext": hex(&framing::encode_snapshot(&raw)),
              "expect": "INVALID_AUTOMERGE_BYTES" },
            { "name": "change_equivocation", "kind": "change", "plaintext": hex(&framing::encode_change(twin.raw_bytes())), "signer": "bob",
              "expect": "ACTOR_EQUIVOCATION" },
            { "name": "state_problems", "kind": "state", "changes": invalid_changes,
              "expect": [ { "pointer": format!("{t1p}/status"), "diagnostic": "INVALID_ENUM_VALUE" },
                          { "pointer": format!("{t1p}/tags/#bad"), "diagnostic": "INVALID_TAG" } ] },
        ],
    })
}

// ---------------------------------------------------------------- consume

struct Results(Vec<Json>);

impl Results {
    fn check(&mut self, id: impl Into<String>, category: &str, outcome: Result<(), String>) {
        let id = id.into();
        let (result, detail) = match outcome {
            Ok(()) => ("PASS", String::new()),
            Err(detail) => ("FAIL", detail),
        };
        self.0
            .push(json!({ "id": id, "category": category, "result": result, "detail": detail }));
    }
}

fn ensure(condition: bool, detail: impl FnOnce() -> String) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(detail())
    }
}

/// The §62 code of an error, or a local category for client-local
/// failures.
fn code_of(error: &Error) -> String {
    if error.is_client_local() {
        return "AEAD".into();
    }
    error
        .wire_code()
        .map(|c| c.name().to_owned())
        .unwrap_or_else(|| format!("UNMAPPED:{}", error.code()))
}

struct Consumer {
    resource: ResourceId,
    keys: BTreeMap<String, PrincipalKeys>,
    history: Vec<ControlState>,
    deks: BTreeMap<u64, Dek>,
}

impl Consumer {
    fn principal(&self, id: &PrincipalId) -> Option<PrincipalDescriptor> {
        self.history.last().and_then(|s| s.principal(id).cloned())
    }

    fn name_of(&self, id: &PrincipalId) -> String {
        self.keys
            .iter()
            .find(|(_, k)| k.descriptor().id() == id)
            .map(|(n, _)| n.clone())
            .unwrap_or_else(|| id.to_hex())
    }

    /// Verify a Data Unit against the chain: signature, data/write at its
    /// head, epoch and cutoff.
    fn unit(&self, bytes: &[u8]) -> Result<DataUnit, Error> {
        let unit = ReceivedDataUnit::parse(bytes)?;
        let actor = self
            .principal(&unit.header().actor)
            .ok_or(Error::IssuerUnknown(unit.header().actor))?;
        unit.verify_with(&actor, data_unit_policy(&self.history))
    }

    fn package(&self, bytes: &[u8]) -> Result<KeyPackage, Error> {
        let package = ReceivedKeyPackage::parse(bytes)?;
        let sender = self
            .principal(&package.header().sender)
            .ok_or(Error::IssuerUnknown(package.header().sender))?;
        package.verify(&sender, key_package_policy(&self.history))
    }

    fn snapshot(&self, bytes: &[u8]) -> Result<Snapshot, Error> {
        let snapshot = ReceivedSnapshot::parse(bytes)?;
        let publisher = self
            .principal(&snapshot.header().publisher)
            .ok_or(Error::IssuerUnknown(snapshot.header().publisher))?;
        snapshot.verify_with(&publisher, snapshot_policy(&self.history))
    }
}

fn consume(dir: &Path) {
    let bundle: Json =
        serde_json::from_slice(&std::fs::read(dir.join("bundle.json")).unwrap()).unwrap();
    assert_eq!(bundle["format"], FORMAT, "bundle format");
    let mut results = Results(vec![]);
    let resource = ResourceId::from_bytes(unhex32(&bundle["resource_id"]));

    // Principals.
    let mut keys = BTreeMap::new();
    for (name, p) in bundle["principals"].as_object().unwrap() {
        let decoded = PrincipalDescriptor::decode(&unhex(&p["descriptor"]));
        let k = PrincipalKeys::from_secrets(
            &unhex32(&p["ed25519_seed"]),
            unhex32(&p["x25519_private"]),
        );
        results.check(
            format!("principal.{name}"),
            "principal",
            match decoded {
                Ok(d) => ensure(&d == k.descriptor(), || {
                    "descriptor does not match its keys".into()
                }),
                Err(e) => Err(format!("decode: {e}")),
            },
        );
        keys.insert(name.clone(), k);
    }

    // Control.
    let records: Vec<Vec<u8>> = bundle["control"]["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(unhex)
        .collect();
    let refs: Vec<&[u8]> = records.iter().map(Vec::as_slice).collect();
    let expect = &bundle["control"]["expect"];
    let history = match validate_authorized(&refs, None) {
        Ok((ChainOutcome::Linear(_), history)) => {
            results.check("control.chain", "control", Ok(()));
            history
        }
        other => {
            results.check("control.chain", "control", Err(format!("{other:?}")));
            vec![]
        }
    };
    let c = Consumer {
        resource,
        keys,
        history,
        deks: BTreeMap::new(),
    };
    if let Some(state) = c.history.last() {
        results.check(
            "control.head",
            "control",
            ensure(
                json!(state.head.sequence) == expect["head_seq"]
                    && hex(state.head.id.as_bytes()) == expect["head_id"],
                || format!("head {} {}", state.head.sequence, state.head.id.to_hex()),
            ),
        );
        results.check(
            "control.owner",
            "control",
            ensure(
                json!(c.name_of(state.owner.id())) == expect["owner"],
                || "owner".into(),
            ),
        );
        for (name, k) in &c.keys {
            let got: Vec<u64> = state.abilities(k.descriptor().id()).into_iter().collect();
            results.check(
                format!("control.abilities.{name}"),
                "control",
                ensure(json!(got) == expect["abilities"][name], || {
                    format!("{got:?}")
                }),
            );
        }
        results.check(
            "control.epoch",
            "control",
            ensure(
                json!(state.current_epoch) == expect["current_epoch"],
                || state.current_epoch.to_string(),
            ),
        );
        let commitments: serde_json::Map<String, Json> = state
            .dek_commitments
            .iter()
            .map(|(e, h)| (e.to_string(), hex(h.as_bytes())))
            .collect();
        results.check(
            "control.dek_commitments",
            "control",
            ensure(
                Json::Object(commitments) == expect["dek_commitments"],
                || "commitments".into(),
            ),
        );
        let cutoffs: serde_json::Map<String, Json> = state
            .closed_frontiers
            .iter()
            .map(|(e, f)| {
                (
                    e.to_string(),
                    json!(f.entries().iter().map(|a| json!({
                "principal": c.name_of(&a.principal), "contiguous": a.contiguous, "extra": a.extra,
            })).collect::<Vec<_>>()),
                )
            })
            .collect();
        results.check(
            "control.cutoff",
            "control",
            ensure(Json::Object(cutoffs) == expect["closed_frontiers"], || {
                "cutoff".into()
            }),
        );
    }
    let mut c = c;

    // Key Packages: open as the recipient, check the commitment.
    for k in bundle["key_packages"].as_array().unwrap() {
        let name = k["name"].as_str().unwrap();
        let epoch = k["epoch"].as_u64().unwrap();
        let recipient = &c.keys[k["recipient"].as_str().unwrap()];
        let outcome = c
            .package(&unhex(&k["bytes"]))
            .map_err(|e| code_of(&e))
            .and_then(|package| {
                let commitment = c
                    .history
                    .last()
                    .and_then(|s| s.dek_commitments.get(&epoch).copied())
                    .ok_or("no commitment")?;
                package
                    .open(recipient, &commitment)
                    .map_err(|e| code_of(&e))
            });
        match outcome {
            Ok(dek) => {
                let consistent = c
                    .deks
                    .get(&epoch)
                    .is_none_or(|d| d.expose_secret() == dek.expose_secret());
                c.deks.insert(epoch, dek);
                results.check(
                    format!("key_package.{name}"),
                    "hpke",
                    ensure(consistent, || "packages disagree".into()),
                );
            }
            Err(e) => results.check(format!("key_package.{name}"), "hpke", Err(e)),
        }
    }

    // Data Units: verify, then decrypt with the DEK of their epoch.
    for u in bundle["units"].as_array().unwrap() {
        let name = u["name"].as_str().unwrap();
        let epoch = u["epoch"].as_u64().unwrap();
        let outcome = c
            .unit(&unhex(&u["bytes"]))
            .map_err(|e| code_of(&e))
            .and_then(|unit| {
                let dek = c.deks.get(&epoch).ok_or("no DEK")?;
                let plaintext = unit.open(dek).map_err(|e| code_of(&e))?;
                ensure(plaintext == unhex(&u["plaintext"]), || {
                    "plaintext differs".into()
                })
            });
        results.check(format!("data_unit.{name}"), "data", outcome);
    }

    // Snapshots.
    for s in bundle["snapshots"].as_array().unwrap() {
        let name = s["name"].as_str().unwrap();
        let epoch = s["epoch"].as_u64().unwrap();
        let outcome = c
            .snapshot(&unhex(&s["bytes"]))
            .map_err(|e| code_of(&e))
            .and_then(|snapshot| {
                let dek = c.deks.get(&epoch).ok_or("no DEK")?;
                let plaintext = snapshot.open(dek).map_err(|e| code_of(&e))?;
                ensure(plaintext == unhex(&s["plaintext"]), || {
                    "plaintext differs".into()
                })
            });
        results.check(format!("snapshot.{name}"), "snapshot", outcome);
    }

    // Messages: decode, re-encode to the same bytes; AUTH verifies.
    let mut decoded = BTreeMap::new();
    for m in bundle["messages"].as_array().unwrap() {
        let name = m["name"].as_str().unwrap().to_owned();
        let bytes = unhex(&m["bytes"]);
        let outcome = match Message::decode(&bytes, &DecodeOptions::default()) {
            Ok(message) => {
                let same = message.encode() == bytes;
                decoded.insert(name.clone(), message);
                ensure(same, || "re-encoding differs".into())
            }
            Err(e) => Err(format!("decode: {e}")),
        };
        results.check(format!("message.{name}"), "message", outcome);
    }
    let auth_ok = match (
        decoded.get("HELLO"),
        decoded.get("CHALLENGE"),
        decoded.get("AUTH"),
    ) {
        (Some(h), Some(ch), Some(a)) => match (&h.body, &ch.body, &a.body) {
            (Body::Hello(h), Body::Challenge(ch), Body::Auth(a)) => verify_auth(h, ch, a.clone())
                .map_err(|e| code_of(&e))
                .and_then(|s| {
                    ensure(s.principal.id() == c.keys["bob"].descriptor().id(), || {
                        "principal".into()
                    })
                }),
            _ => Err("message types".into()),
        },
        _ => Err("missing handshake messages".into()),
    };
    results.check("message.AUTH.verify", "message", auth_ok);

    // Negatives.
    for n in bundle["negatives"].as_array().unwrap() {
        let name = n["name"].as_str().unwrap();
        let expect = n["expect"].as_str().unwrap();
        let got: String = match n["kind"].as_str().unwrap() {
            "unit" => match c.unit(&unhex(&n["bytes"])) {
                Err(e) => code_of(&e),
                Ok(unit) => match c.deks.get(&unit.header().data_epoch) {
                    Some(dek) => unit
                        .open(dek)
                        .map(|_| "ACCEPTED".to_owned())
                        .unwrap_or_else(|e| code_of(&e)),
                    None => "NO_DEK".into(),
                },
            },
            "unit_pair" => {
                let pair: Vec<Vec<u8>> = n["pair"].as_array().unwrap().iter().map(unhex).collect();
                match (c.unit(&pair[0]), c.unit(&pair[1])) {
                    (Ok(a), Ok(b)) => check_equivocation(&a, &b)
                        .map(|_| "ACCEPTED".to_owned())
                        .unwrap_or_else(|e| code_of(&e)),
                    (Err(e), _) | (_, Err(e)) => code_of(&e),
                }
            }
            "record" => {
                let candidate = unhex(&n["bytes"]);
                let mut all = refs.clone();
                all.push(&candidate);
                match validate_authorized(&all, None) {
                    Ok((ChainOutcome::Conflict(_), _)) => "CONTROL_CONFLICT".into(),
                    Ok((ChainOutcome::Linear(_), _)) => "ACCEPTED".into(),
                    Err(failure) => code_of(&failure.error),
                }
            }
            "key_package" => c
                .package(&unhex(&n["bytes"]))
                .map(|_| "ACCEPTED".to_owned())
                .unwrap_or_else(|e| code_of(&e)),
            "snapshot" => c
                .snapshot(&unhex(&n["bytes"]))
                .map(|_| "ACCEPTED".to_owned())
                .unwrap_or_else(|e| code_of(&e)),
            other => format!("UNKNOWN_KIND:{other}"),
        };
        results.check(
            format!("negative.{name}"),
            "negative",
            ensure(got == expect, || format!("got {got}")),
        );
    }

    consume_shared_objects(&bundle["shared_objects"], &c, &mut results);

    let out = json!({
        "format": "lfcp-interop-results/1",
        "consumer": "rust",
        "producer": bundle["producer"],
        "checks": results.0,
    });
    std::fs::write(
        dir.join("results-rust.json"),
        serde_json::to_vec_pretty(&out).unwrap(),
    )
    .unwrap();
}

fn consume_shared_objects(so: &Json, c: &Consumer, results: &mut Results) {
    let signer = |name: &Json| *c.keys[name.as_str().unwrap()].descriptor().id();
    let fresh = || SharedObjects::new(actor_id(&c.resource, &PrincipalId::from_bytes(random())));
    let apply_all = |doc: &mut SharedObjects, changes: &Json| -> Result<(), String> {
        for (i, change) in changes.as_array().unwrap().iter().enumerate() {
            doc.apply_unit_change(
                &c.resource,
                &signer(&change["signer"]),
                &unhex(&change["plaintext"]),
            )
            .map_err(|e| format!("change {i}: {e}"))?;
        }
        Ok(())
    };
    let expect = &so["expect"];

    let mut doc = fresh();
    let outcome = apply_all(&mut doc, &so["changes"]).and_then(|()| {
        let got = view(&doc);
        ensure(&got == expect, || format!("view differs: {got}"))
    });
    results.check("shared_objects.changes", "shared_objects", outcome);
    results.check(
        "shared_objects.validate",
        "shared_objects",
        doc.problems()
            .map_err(|e| e.to_string())
            .and_then(|p| ensure(p.is_empty(), || format!("{p:?}"))),
    );

    let outcome = framing::decode_snapshot(&unhex(&so["snapshot"]))
        .and_then(|save| {
            SharedObjects::load(
                &save,
                actor_id(&c.resource, &PrincipalId::from_bytes(random())),
            )
        })
        .map_err(|e| e.to_string())
        .and_then(|loaded| {
            let got = view(&loaded);
            ensure(&got == expect, || format!("view differs: {got}"))
        });
    results.check("shared_objects.snapshot", "shared_objects", outcome);

    for n in so["negatives"].as_array().unwrap() {
        let name = n["name"].as_str().unwrap();
        let outcome = match n["kind"].as_str().unwrap() {
            "change" => {
                let mut fresh_doc = fresh();
                let _ = apply_all(&mut fresh_doc, &so["changes"]);
                let got = match fresh_doc.apply_unit_change(
                    &c.resource,
                    &signer(&n["signer"]),
                    &unhex(&n["plaintext"]),
                ) {
                    Ok(()) => "ACCEPTED".to_owned(),
                    Err(e) => e.diagnostic().map_or_else(
                        || e.code().map_or_else(|| e.to_string(), str::to_owned),
                        |d| d.name().to_owned(),
                    ),
                };
                ensure(json!(got) == n["expect"], || format!("got {got}"))
            }
            "snapshot" => {
                let got = match framing::decode_snapshot(&unhex(&n["plaintext"])) {
                    Ok(_) => "ACCEPTED".to_owned(),
                    Err(e) => e
                        .diagnostic()
                        .map_or_else(|| e.to_string(), |d| d.name().to_owned()),
                };
                ensure(json!(got) == n["expect"], || format!("got {got}"))
            }
            "state" => {
                let mut state_doc = fresh();
                apply_all(&mut state_doc, &so["changes"])
                    .and_then(|()| apply_all(&mut state_doc, &n["changes"]))
                    .and_then(|()| {
                        let got: BTreeSet<(String, String)> = state_doc
                            .problems()
                            .map_err(|e| e.to_string())?
                            .into_iter()
                            .map(|p| (p.pointer, p.diagnostic.name().to_owned()))
                            .collect();
                        let want: BTreeSet<(String, String)> = n["expect"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|p| {
                                (
                                    p["pointer"].as_str().unwrap().to_owned(),
                                    p["diagnostic"].as_str().unwrap().to_owned(),
                                )
                            })
                            .collect();
                        ensure(got == want, || format!("got {got:?}"))
                    })
            }
            other => Err(format!("unknown kind {other}")),
        };
        results.check(
            format!("shared_objects.negative.{name}"),
            "shared_objects",
            outcome,
        );
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [command, dir] if command == "produce" => produce(Path::new(dir)),
        [command, dir] if command == "consume" => consume(Path::new(dir)),
        _ => {
            eprintln!("usage: interop (produce|consume) <dir>");
            std::process::exit(2);
        }
    }
}
