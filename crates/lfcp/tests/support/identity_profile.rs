#![allow(dead_code)]
use super::identity_corpus::*;
use automerge::{AutoCommit, Change, ChangeHash, ObjId, ObjType, ReadDoc, Value, ROOT};
use lfcp::{
    base::{PrincipalId, ResourceId},
    identity::{
        links::{fingerprint, PairingLink},
        IdentityDoc, IdentityReplica, Received, UnitContext, WriterClass,
    },
    shared_objects::{framing, identity::parse_principal_ref, values::Plain},
};
use serde_json::{json, Value as J};
use std::collections::{BTreeMap, BTreeSet};

pub struct Profile {
    pub corpus: Corpus,
    pub resource: ResourceId,
    pub owner: PrincipalId,
}
impl Profile {
    pub fn load() -> Self {
        let corpus = Corpus::load(PROFILE);
        let resource =
            ResourceId::from_slice(&bytes(&corpus.data["fixtures"]["identity_resource"])).unwrap();
        let owner = parse_principal_ref(s(&corpus.data["fixtures"]["owner_ref"])).unwrap();
        Self {
            corpus,
            resource,
            owner,
        }
    }
    pub fn replica(&self) -> IdentityReplica {
        IdentityReplica::new(self.resource, self.owner)
    }
    pub fn change_case(&self, name: &str) -> &J {
        self.corpus.case(&format!(
            "change.{}",
            name.strip_prefix("change.").unwrap_or(name)
        ))
    }
    pub fn unit(&self, c: &J) -> (UnitContext, Vec<u8>) {
        let i = &c["inputs"];
        let writer = s(&i["writer"]);
        let signer = parse_principal_ref(
            i.get("writer_ref")
                .unwrap_or(&self.corpus.data["fixtures"]["refs"][writer])
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let class = match i
            .get("writer_class")
            .map(s)
            .unwrap_or(if writer == "OWNER" {
                "root"
            } else if writer.starts_with("PAIR_") {
                "pairing"
            } else {
                "personal"
            }) {
            "root" => WriterClass::Root,
            "personal" => WriterClass::Personal,
            "pairing" => WriterClass::Pairing,
            _ => WriterClass::Other,
        };
        let raw = bytes(
            i.get("automerge_change")
                .unwrap_or(&i["automerge_change_hex"]),
        );
        (
            UnitContext {
                signer,
                class,
                actor_sequence: i["unit_actor_seq"].as_u64().unwrap(),
            },
            framing::encode_change(&raw),
        )
    }
    pub fn deliver(&self, r: &mut IdentityReplica, name: &str) -> Received {
        let (u, p) = self.unit(self.change_case(name));
        r.receive(u, &p)
    }
    pub fn snapshot_witnesses(&self, snapshot: &[u8]) -> Vec<(UnitContext, Vec<u8>)> {
        let mut doc = automerge::AutoCommit::load(snapshot).unwrap();
        let hashes: BTreeSet<_> = doc
            .get_changes(&[])
            .iter()
            .map(|c| c.hash().to_string())
            .collect();
        let mut seen = BTreeSet::new();
        self.corpus
            .cases
            .values()
            .filter(|c| {
                s(&c["id"]).starts_with("change.")
                    && hashes.contains(s(&c["inputs"]["change_hash"]))
                    && seen.insert(s(&c["inputs"]["change_hash"]).to_string())
            })
            .map(|c| self.unit(c))
            .collect()
    }
    pub fn run(&self, c: &J) -> J {
        let i = &c["inputs"];
        let e = &c["expected"];
        let id = s(&c["id"]);
        match s(&c["kind"]) {
            "profile_change_framing" => {
                expected_fields(c, &["framed_cbor", "sha256"]);
                let raw = bytes(&i["automerge_change_hex"]);
                let framed = framing::encode_change(&raw);
                assert_eq!(framed, bytes(&e["framed_cbor"]), "{id}");
                assert_eq!(
                    lfcp::crypto::sha256(&framed).to_hex(),
                    s(&e["sha256"]["hex"]),
                    "{id}"
                );
                let ch = Change::from_bytes(raw).unwrap();
                assert_eq!(ch.hash().to_string(), s(&i["change_hash"]), "{id}");
                accepted(vec![ch.hash().to_string()], J::Null)
            }
            "profile_change" => {
                let mut r = self.replica();
                for reference in c["context"]["history"].as_array().unwrap() {
                    let outcome = self.deliver(&mut r, s(&reference["case"]));
                    assert!(
                        matches!(outcome, Received::Applied | Received::Duplicate),
                        "{id} history: {outcome:?}"
                    );
                }
                let (u, p) = self.unit(c);
                assert_eq!(p, bytes(&i["framed_plaintext"]));
                let outcome = r.receive(u, &p);
                match outcome {
                    Received::Refused(d) => refused("PROFILE_INVALID", Some(d.name())),
                    Received::Applied | Received::Duplicate => accepted(
                        r.accepted().iter().map(ToString::to_string).collect(),
                        plain(&r.view().plain().unwrap()),
                    ),
                    other => panic!("{id}: {other:?}"),
                }
            }
            "profile_entry" => {
                let view = IdentityDoc::inspect(&bytes(&i["snapshot"]), self.owner).unwrap();
                let d = view.entry_diagnostic(s(&i["container"]), s(&i["key"]));
                if let Some(d) = d {
                    assert!(!view
                        .entries(s(&i["container"]))
                        .unwrap()
                        .contains_key(s(&i["key"])));
                    let mut result = refused("PROFILE_INVALID", Some(d.name()));
                    if e["error"].get("detail").is_some() {
                        let parent = view
                            .automerge()
                            .get(ROOT, s(&i["container"]))
                            .unwrap()
                            .unwrap()
                            .1;
                        let entries = view.automerge().get_all(parent, s(&i["key"])).unwrap();
                        assert!(
                            entries.len() > 1
                                || entries
                                    .iter()
                                    .any(|(_, obj)| has_conflict(view.automerge(), obj))
                        );
                        result["detail"] = json!("conflicted entry (§4 rule 2)");
                    }
                    result
                } else {
                    let entries = view.entries(s(&i["container"])).unwrap();
                    assert!(entries.contains_key(s(&i["key"])));
                    accepted(vec![], plain(&entries[s(&i["key"])]))
                }
            }
            "pair_uri" => {
                if c["type"] == "bytes" {
                    expected_fields(c, &["secret_cbor", "uri", "recomputed_principal_id"]);
                    let ed: [u8; 32] = bytes(&i["ed25519_seed"]).try_into().unwrap();
                    let x: [u8; 32] = bytes(&i["x25519_private"]).try_into().unwrap();
                    let resource = ResourceId::from_slice(&bytes(&i["identity_resource"])).unwrap();
                    let link = PairingLink::new(resource, vec![s(&i["endpoint"]).into()], &ed, &x)
                        .unwrap();
                    assert_eq!(&*link.encode(), s(&e["uri"]), "{id}");
                    let encoded = link.encode();
                    let secret = encoded.split_once("#secret=").unwrap().1;
                    assert_eq!(
                        lfcp::base::from_b64url(secret).unwrap(),
                        bytes(&e["secret_cbor"])
                    );
                    let decoded = PairingLink::parse(s(&e["uri"])).unwrap();
                    assert_eq!(
                        decoded.device.to_hex(),
                        s(&e["recomputed_principal_id"]["hex"])
                    );
                    assert_eq!(decoded.identity, resource);
                    assert!(!format!("{decoded:?}").contains("secret="));
                    accepted(vec![decoded.device.to_hex()], J::Null)
                } else if i.get("binding_head").is_some() {
                    self.check_link(c)
                } else if i["parser"] == "join" {
                    json!({"outcome":"N/A","accepted_ids":[],"post_state":null,"not_applicable":"IDENTITY-PROFILE-01 §5.2 / LFCP-WIRE-01 §18.2: sdk-rs has no invitation-URI parser; rejecting pair links in that parser cannot be exercised."})
                } else {
                    let uri = s(&i["uri"]);
                    assert!(PairingLink::parse(uri).is_err(), "{id}");
                    let mut result = refused("PAIRING_LINK_REJECTED", None);
                    let detail = if !uri.starts_with("lfcp://pair/") {
                        "not a pairing link"
                    } else {
                        let (public, encoded) = uri.split_once("#secret=").unwrap();
                        let secret =
                            lfcp::cbor::decode_strict(&lfcp::base::from_b64url(encoded).unwrap())
                                .unwrap();
                        let ed = secret
                            .get(&lfcp::cbor::Value::Unsigned(1))
                            .unwrap()
                            .as_bytes()
                            .unwrap();
                        let x = secret
                            .get(&lfcp::cbor::Value::Unsigned(2))
                            .unwrap()
                            .as_bytes()
                            .unwrap();
                        let keys = lfcp::principal::PrincipalKeys::from_secrets(
                            ed.try_into().unwrap(),
                            x.try_into().unwrap(),
                        );
                        let claimed = public.split_once("&device=").unwrap().1;
                        let recomputed = keys.descriptor().id().to_b64url();
                        assert_ne!(claimed, recomputed);
                        // The same link with the recomputed device parses, isolating
                        // the failure from an unrelated malformed URI/secret.
                        assert!(PairingLink::parse(&uri.replace(
                            &format!("&device={claimed}#"),
                            &format!("&device={recomputed}#")
                        ))
                        .is_ok());
                        "the secret's Principal is not device"
                    };
                    result["detail"] = json!(detail);
                    result
                }
            }
            "device_fingerprint" => {
                expected_fields(c, &["digest_prefix", "fingerprint"]);
                let id = PrincipalId::from_slice(&bytes(&i["principal_id"])).unwrap();
                let mut preimage = b"LFCP-DEVICE-FP-v1".to_vec();
                preimage.extend_from_slice(id.as_bytes());
                assert_eq!(
                    &lfcp::crypto::sha256(&preimage).as_bytes()[..10],
                    bytes(&e["digest_prefix"])
                );
                let fp = fingerprint(&id);
                assert_eq!(fp, e["fingerprint"]);
                accepted(vec![], json!({"fingerprint":fp}))
            }
            "approval_digest" => {
                expected_fields(
                    c,
                    &["payload_digest", "consuming_record", "consuming_record_id"],
                );
                let cert =
                    lfcp::wire::control::device::DeviceCertificate::parse(&bytes(&i["cose_sign1"]))
                        .unwrap();
                assert_eq!(
                    cert.payload_digest().to_hex(),
                    s(&e["payload_digest"]["hex"])
                );
                let mut wire = super::identity_wire::Wire::load();
                let record = lfcp::wire::control::ReceivedControlRecord::parse(
                    &wire.record_bytes(s(&e["consuming_record"])),
                )
                .unwrap();
                assert_eq!(
                    record.id().as_bytes().as_slice(),
                    bytes(&e["consuming_record_id"])
                );
                let state = wire.at(s(&e["consuming_record"]));
                let lfcp::wire::control::body::ControlBody::DeviceRevoke(revoke) = record.body()
                else {
                    panic!("consuming record must be a revocation");
                };
                assert_eq!(revoke.reason, 3);
                assert_eq!(
                    state
                        .revocation(&revoke.root, &revoke.device)
                        .unwrap()
                        .approval,
                    Some(cert.payload_digest())
                );
                accepted(
                    vec![cert.id().to_hex()],
                    json!({"payload_digest":cert.payload_digest().to_hex()}),
                )
            }
            "identity_document" => self.document(c),
            other => panic!("unsupported profile kind {other}"),
        }
    }
    /// IDENTITY-PROFILE-01 §5.2, the checks a client makes on a pairing link
    /// before it writes a request: (1) `PairingLink::parse` recomputes J's
    /// descriptor from the secret; (2) J opens the Resource (W §41,
    /// `ControlState::may_read` at the binding head: a revoked reader opens
    /// through the Control prefix); (3) the Genesis profile is
    /// `org.openlfcp.identity.v1`; (4) J is a registered, active kind-2 device
    /// of the owner. sdk-rs has no client that composes these over a session;
    /// this runner composes them from the public parser and authority state.
    fn check_link(&self, c: &J) -> J {
        use lfcp::wire::control::{
            authority::ReadAccess, body::ControlBody, device::DeviceKind, ReceivedControlRecord,
        };
        let i = &c["inputs"];
        let id = s(&c["id"]);
        let link = PairingLink::parse(s(&i["uri"])).unwrap_or_else(|_| panic!("{id}: check 1"));
        let mut wire = super::identity_wire::Wire::load();
        assert_eq!(wire.name(&link.device), s(&i["device"]), "{id}");
        let state = wire.at(s(&i["binding_head"]));
        assert_eq!(state.resource_id, link.identity, "{id}");
        let genesis = ReceivedControlRecord::parse(&wire.record_bytes(s(&i["genesis"]))).unwrap();
        assert_eq!(genesis.header().resource_id, link.identity, "{id}");
        let ControlBody::Genesis(genesis) = genesis.body() else {
            panic!("{id}: not a Genesis");
        };
        let j = link.device;
        let rejected = |detail: String| {
            let mut result = refused("PAIRING_LINK_REJECTED", None);
            result["detail"] = json!(detail);
            result
        };
        if state.may_read(&j) == ReadAccess::Denied {
            return rejected(
                "check 2: the session as J is refused (W §41): J is not a reader".into(),
            );
        }
        if genesis.data_profile != lfcp::identity::PROFILE {
            return rejected(format!(
                "check 3: the Genesis profile is {}",
                genesis.data_profile
            ));
        }
        let d = state.device(&j).unwrap();
        let active = state.active_device(&j).is_some();
        if !(d.kind == DeviceKind::Pairing && d.registered && active && d.root == *state.owner.id())
        {
            return rejected(format!(
                "check 4: J is not a registered, active kind-2 device of the owner (kind {}, active {active}, root {}, owner {})",
                d.kind as u8,
                wire.name(&d.root),
                wire.name(state.owner.id()),
            ));
        }
        accepted(vec![j.to_hex()], J::Null)
    }
    fn names(&self, hashes: Vec<ChangeHash>) -> Vec<String> {
        hashes
            .into_iter()
            .map(|h| {
                self.corpus
                    .cases
                    .values()
                    .find(|c| {
                        s(&c["id"]).starts_with("change.")
                            && c["inputs"]["change_hash"] == h.to_string()
                    })
                    .map(|c| s(&c["id"])[7..].to_string())
                    .unwrap()
            })
            .collect()
    }
    fn initial(&self, r: &mut IdentityReplica) -> String {
        let mut doc = AutoCommit::load(&r.save()).unwrap();
        let initial: Vec<_> = doc
            .get_changes(&[])
            .iter()
            .filter(|c| c.deps().is_empty())
            .map(|c| c.hash())
            .collect();
        assert_eq!(initial.len(), 1);
        self.names(initial).pop().unwrap()
    }
    fn history_state(&self, r: &mut IdentityReplica) -> J {
        let refused: BTreeMap<_, _> = r
            .refused()
            .iter()
            .map(|(h, d)| {
                (
                    self.names(vec![*h])[0].clone(),
                    json!({"code":"PROFILE_INVALID","diagnostic":d.name()}),
                )
            })
            .collect();
        json!({"admitted":self.names(r.accepted()),"refused":refused,"pending":self.names(r.waiting()),"state":state(r.view().automerge(), &ROOT)})
    }
    fn document(&self, c: &J) -> J {
        let i = &c["inputs"];
        let e = &c["expected"];
        let id = s(&c["id"]);
        let mut r = self.replica();
        let actual = match id {
            "identity_doc_second_initial_other_unit" => {
                let mut results = BTreeMap::new();
                for (name, order) in i["orders"].as_object().unwrap() {
                    let mut replica = self.replica();
                    for name in order
                        .as_array()
                        .unwrap_or_else(|| order["order"].as_array().unwrap())
                    {
                        self.deliver(&mut replica, s(name));
                    }
                    let refused: BTreeMap<_, _> = replica
                        .refused()
                        .iter()
                        .map(|(h, d)| (self.names(vec![*h])[0].clone(), d.name()))
                        .collect();
                    results.insert(name, json!({"initial_change":self.initial(&mut replica),"refused":refused,"held":self.names(replica.held()),"pending":self.names(replica.waiting())}));
                }
                let snapshot = bytes(&i["snapshot"]);
                assert!(!r
                    .receive_snapshot(&framing::encode_snapshot(&snapshot), &[])
                    .unwrap());
                let used = r
                    .receive_snapshot(
                        &framing::encode_snapshot(&snapshot),
                        &self.snapshot_witnesses(&snapshot),
                    )
                    .unwrap();
                json!({"by_order":results,"snapshot":{"initial_change":self.initial(&mut r),"used":used}})
            }
            _ if id.starts_with("identity_doc_initial_") && id.ends_with("_list.snapshot") => {
                // §4 after loading the Snapshot: a list where the root needs a map makes the
                // root invalid and every reader unusable. The Snapshot is not admitted either:
                // its only witness, the initial change, is refused as INVALID_ROOT.
                let snapshot = bytes(&i["snapshot"]);
                let view = IdentityDoc::inspect(&snapshot, self.owner).unwrap();
                let root = view.validate_root().err();
                // Every reader is unusable, including the containers that are maps.
                for container in ["roster", "devices", "requests"] {
                    assert_eq!(view.entries(container).err(), root, "{id} {container}");
                }
                assert_eq!(view.extension_diagnostic("any"), root, "{id} extensions");
                let witness = self.unit(self.change_case(s(&i["change"]["case"])));
                assert!(!r
                    .receive_snapshot(
                        &framing::encode_snapshot(&snapshot),
                        std::slice::from_ref(&witness)
                    )
                    .unwrap());
                assert!(r.accepted().is_empty());
                json!({"root_diagnostic":root.map_or("valid", |d| d.name()),"document_usable":root.is_none()})
            }
            "identity_doc_initial_without_unit_1" => {
                let witness = self.unit(self.change_case(s(&i["root_unit_1"]["case"])));
                let used = r
                    .receive_snapshot(
                        &framing::encode_snapshot(&bytes(&i["snapshot"])),
                        std::slice::from_ref(&witness),
                    )
                    .unwrap();
                assert!(r.accepted().is_empty());
                r.receive(witness.0, &witness.1);
                json!({"snapshot_used":used,"initial_change":self.initial(&mut r)})
            }
            "identity_doc_initial_then_fill" | "identity_snapshot_equivalence" => {
                let snapshot = bytes(&i["snapshot"]);
                let witnesses = self.snapshot_witnesses(&snapshot);
                let describe = |replica: &mut IdentityReplica| {
                    let view = replica.view();
                    let mut entries = BTreeMap::new();
                    for container in e["entries"].as_object().unwrap().keys() {
                        let parent = view
                            .automerge()
                            .get(ROOT, container.as_str())
                            .unwrap()
                            .unwrap()
                            .1;
                        let validity: BTreeMap<_, _> = view
                            .automerge()
                            .keys(parent)
                            .map(|key| {
                                let diagnostic = view
                                    .entry_diagnostic(container, &key)
                                    .map_or("valid", |d| d.name());
                                (key, diagnostic)
                            })
                            .collect();
                        entries.insert(container, validity);
                    }
                    let mut actual = json!({"state":state(view.automerge(), &ROOT),"root_valid":view.validate_root().is_ok(),"entries":entries});
                    if e.get("admitted").is_some() {
                        actual["admitted"] = json!(self.names(replica.accepted()));
                    }
                    actual
                };
                for units in [witnesses.clone(), witnesses.iter().cloned().rev().collect()] {
                    let mut replay = self.replica();
                    for (u, p) in units {
                        replay.receive(u, &p);
                    }
                    assert_document(c, &describe(&mut replay));
                }
                assert!(r
                    .receive_snapshot(&framing::encode_snapshot(&snapshot), &witnesses)
                    .unwrap());
                describe(&mut r)
            }
            "pairing_concurrent_same_key" => {
                for reference in i["history"].as_array().unwrap() {
                    self.deliver(&mut r, s(&reference["case"]));
                }
                let before: BTreeSet<_> = r.accepted().into_iter().collect();
                let changes = i["changes"].as_array().unwrap();
                for reference in changes {
                    self.deliver(&mut r, s(&reference["case"]));
                }
                let admitted = self.names(
                    r.accepted()
                        .into_iter()
                        .filter(|h| !before.contains(h))
                        .collect(),
                );
                let mut change = Change::from_bytes(bytes(
                    &self.change_case(s(&changes[0]["case"]))["inputs"]["automerge_change_hex"],
                ))
                .unwrap()
                .decode()
                .operations
                .into_iter();
                let entry = change
                    .find_map(|op| match (op.key, op.action) {
                        (
                            automerge::legacy::Key::Map(k),
                            automerge::legacy::OpType::Make(ObjType::Map),
                        ) => Some(k.to_string()),
                        _ => None,
                    })
                    .unwrap();
                let view = r.view();
                let requests = view.automerge().get(ROOT, "requests").unwrap().unwrap().1;
                let conflicted = view.automerge().get_all(requests, &entry).unwrap().len() > 1;
                let diagnostic = view.entry_diagnostic("requests", &entry);
                json!({"admitted":admitted,"entry":entry,"entry_conflicted":conflicted,"entry_valid":diagnostic.is_none(),"entry_diagnostic":diagnostic.map(|d| d.name())})
            }
            "device_entry_missing_keys_union" => {
                // This is a §4 state-inspection fixture. Its historical root hints
                // violate AI5, so baseline.2 must not admit this save as a Snapshot.
                let snapshot = bytes(&i["snapshot"]);
                let view = IdentityDoc::inspect(&snapshot, self.owner).unwrap();
                let key = s(&self.corpus.data["fixtures"]["refs"]["DEV_B"]);
                let actual = hints(&view, key);
                assert!(!r
                    .receive_snapshot(
                        &framing::encode_snapshot(&snapshot),
                        &self.snapshot_witnesses(&snapshot)
                    )
                    .unwrap());
                assert!(r.accepted().is_empty());
                actual
            }
            "missing_keys_concurrent_device_and_root" | "missing_keys_hidden_entry_resolution" => {
                let mut results = BTreeMap::new();
                for (name, order) in i["orders"].as_object().unwrap() {
                    let mut replica = self.replica();
                    for name in order.as_array().unwrap() {
                        self.deliver(&mut replica, s(name));
                    }
                    let mut actual = self.history_state(&mut replica);
                    if id == "missing_keys_concurrent_device_and_root" {
                        let key = s(&self.corpus.data["fixtures"]["refs"]["DEV_B"]);
                        actual["state"] = hints(&replica.view(), key);
                        actual["state"]["entry"] = json!(key);
                        assert_document(c, &actual);
                    }
                    results.insert(name.clone(), actual);
                    r = replica;
                }
                if id == "missing_keys_concurrent_device_and_root" {
                    results.into_values().next().unwrap()
                } else {
                    json!(results)
                }
            }
            _ => panic!("wire-dependent profile behavior: {id}"),
        };
        assert_document(c, &actual);
        accepted(
            r.accepted().iter().map(ToString::to_string).collect(),
            actual,
        )
    }
}
pub fn plain(p: &Plain) -> J {
    match p {
        Plain::Null => J::Null,
        Plain::Bool(b) => json!(b),
        Plain::Uint(n) => json!(n),
        Plain::Int(n) => json!(n),
        Plain::Str(s) | Plain::Text(s) => json!(s),
        Plain::List(l) => J::Array(l.iter().map(plain).collect()),
        Plain::Map(m) => J::Object(m.iter().map(|(k, v)| (k.clone(), plain(v))).collect()),
        other => panic!("unrepresentable {other:?}"),
    }
}

// SOP §45 fixture notation retains every distinct concurrent value, recursively.
fn state(doc: &AutoCommit, obj: &ObjId) -> J {
    match doc.object_type(obj).unwrap() {
        ObjType::Map => {
            let mut map = serde_json::Map::new();
            for key in doc.keys(obj) {
                let mut values: Vec<_> = doc
                    .get_all(obj, &key)
                    .unwrap()
                    .iter()
                    .map(|(v, id)| state_value(doc, v, id))
                    .collect();
                values.sort_by_key(J::to_string);
                values.dedup();
                if values.len() == 1 {
                    map.insert(key, values.pop().unwrap());
                } else {
                    map.insert(format!("{key}_conflict_set"), json!(values));
                }
            }
            J::Object(map)
        }
        ObjType::List => json!((0..doc.length(obj))
            .map(|i| {
                let (v, id) = doc.get(obj, i).unwrap().unwrap();
                state_value(doc, &v, &id)
            })
            .collect::<Vec<_>>()),
        other => panic!("unsupported state object {other:?}"),
    }
}
fn state_value(doc: &AutoCommit, value: &Value<'_>, id: &ObjId) -> J {
    match value {
        Value::Object(ObjType::Map | ObjType::List) => state(doc, id),
        _ => plain(&lfcp::shared_objects::values::read(doc, value, id).unwrap()),
    }
}
fn hints(view: &IdentityDoc, key: &str) -> J {
    let doc = view.automerge();
    let devices = doc.get(ROOT, "devices").unwrap().unwrap().1;
    let mut conflicts = Vec::new();
    for (_, entry) in doc.get_all(devices, key).unwrap() {
        conflicts.extend(
            doc.get_all(entry, "missing_keys")
                .unwrap()
                .iter()
                .map(|(v, id)| state_value(doc, v, id)),
        );
    }
    conflicts.sort_by_key(J::to_string);
    conflicts.dedup();
    json!({"entry_valid":view.entry_diagnostic("devices",key).is_none(),"missing_keys_conflict_set":conflicts,"missing_keys_read":view.missing_keys(key).unwrap()})
}
fn has_conflict(doc: &AutoCommit, obj: &ObjId) -> bool {
    let props: Vec<automerge::Prop> = match doc.object_type(obj).unwrap() {
        ObjType::Map => doc.keys(obj).map(automerge::Prop::Map).collect(),
        ObjType::List => (0..doc.length(obj)).map(automerge::Prop::Seq).collect(),
        _ => return false,
    };
    props.into_iter().any(|prop| {
        let values = doc.get_all(obj, prop).unwrap();
        let distinct = lfcp::shared_objects::values::distinct(
            values
                .iter()
                .map(|(v, id)| lfcp::shared_objects::values::read(doc, v, id).unwrap())
                .collect(),
        );
        distinct.len() > 1
            || values
                .iter()
                .any(|(v, id)| matches!(v, Value::Object(_)) && has_conflict(doc, id))
    })
}
fn assert_document(c: &J, actual: &J) {
    fn normalized(mut value: J) -> J {
        if let Some(map) = value.as_object_mut() {
            for (key, v) in map {
                *v = normalized(v.take());
                if matches!(key.as_str(), "admitted" | "pending" | "held")
                    || key.ends_with("_conflict_set")
                {
                    v.as_array_mut().unwrap().sort_by_key(J::to_string);
                }
            }
        } else if let Some(array) = value.as_array_mut() {
            for v in array {
                *v = normalized(v.take());
            }
        }
        value
    }
    assert_eq!(
        normalized(actual.clone()),
        normalized(c["expected"].clone()),
        "{}",
        c["id"]
    );
}
