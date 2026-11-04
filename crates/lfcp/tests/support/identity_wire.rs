//! Every ID-01..ID-04 case is decided by the public Rust implementation.
#![allow(dead_code)]
use super::identity_corpus::*;
use lfcp::{
    base::{ControlRecordId, Error, PrincipalId, ResourceId},
    cose,
    principal::{PrincipalDescriptor, PrincipalKeys},
    wire::{
        control::{
            authority::{self, ControlState, ReadAccess, Role},
            chain::ChainOutcome,
            device::{verify_chain, CertificateChain, DeviceCertificate},
            ReceivedControlRecord,
        },
        data_unit::ReceivedDataUnit,
        key_package::ReceivedKeyPackage,
        keys::Dek,
        snapshot::ReceivedSnapshot,
    },
};
use serde_json::{json, Value as J};
use std::collections::{BTreeMap, HashMap};

pub struct Wire {
    pub corpus: Corpus,
    pub principals: BTreeMap<String, PrincipalDescriptor>,
    pub names: HashMap<PrincipalId, String>,
    pub states: HashMap<ControlRecordId, ControlState>,
    certificate_names: BTreeMap<String, String>,
    record_names: HashMap<ControlRecordId, String>,
    resources: HashMap<ResourceId, String>,
}
impl Wire {
    pub fn load() -> Self {
        let corpus = Corpus::load(WIRE);
        let mut principals = BTreeMap::new();
        let mut certificate_names = BTreeMap::new();
        let mut record_names = HashMap::new();
        let mut resources = HashMap::new();
        for c in corpus.cases.values() {
            if c["kind"] == "principal" {
                principals.insert(
                    s(&c["inputs"]["label"]).into(),
                    PrincipalDescriptor::decode(&bytes(&c["expected"]["descriptor_cbor"])).unwrap(),
                );
            }
            if c["kind"] == "control_record" {
                if let Ok(r) = ReceivedControlRecord::parse(&bytes(&c["inputs"]["cose_sign1"])) {
                    record_names
                        .entry(r.id())
                        .or_insert_with(|| s(&c["id"]).to_string());
                }
            }
        }
        for (name, v) in corpus.data["fixtures"]["fill_principals"]
            .as_object()
            .unwrap()
        {
            principals.insert(
                name.clone(),
                PrincipalDescriptor::decode(&bytes(&v["descriptor_cbor"])).unwrap(),
            );
        }
        for (name, v) in corpus.data["fixtures"]["certificates"].as_object().unwrap() {
            let cert = DeviceCertificate::parse(&bytes(&v["cose_sign1"])).unwrap();
            certificate_names.insert(cert.id().to_hex(), name.clone());
        }
        for (name, v) in corpus.data["fixtures"]["resources"].as_object().unwrap() {
            resources.insert(
                ResourceId::from_slice(&bytes(&v["id"])).unwrap(),
                name.clone(),
            );
        }
        let names = principals
            .iter()
            .map(|(n, p)| (*p.id(), n.clone()))
            .collect();
        Self {
            corpus,
            principals,
            names,
            states: HashMap::new(),
            certificate_names,
            record_names,
            resources,
        }
    }
    pub fn id(&self, name: &str) -> PrincipalId {
        *self
            .principals
            .get(name)
            .unwrap_or_else(|| panic!("principal {name}"))
            .id()
    }
    pub fn name(&self, id: &PrincipalId) -> String {
        self.names.get(id).cloned().unwrap_or_else(|| id.to_hex())
    }
    pub fn record_name(&self, id: &ControlRecordId) -> String {
        self.record_names
            .get(id)
            .cloned()
            .unwrap_or_else(|| id.to_hex())
    }
    pub fn record_bytes(&self, name: &str) -> Vec<u8> {
        bytes(&self.corpus.case(name)["inputs"]["cose_sign1"])
    }
    pub fn context_bytes(&self, context: &J) -> Vec<Vec<u8>> {
        let mut records: Vec<_> = context["records"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|r| self.corpus.ref_bytes(r))
            .collect();
        if let Some(set) = context.get("record_set") {
            records.extend(
                self.corpus.data["fixtures"]["record_sets"][s(set)]["records"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(bytes),
            );
        }
        records.extend(
            context["records_after_set"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|r| self.corpus.ref_bytes(r)),
        );
        records
    }
    pub fn history(&mut self, context: &J) -> Vec<ControlState> {
        let mut history = Vec::new();
        for bytes in self.context_bytes(context) {
            let record = ReceivedControlRecord::parse(&bytes).unwrap();
            let id = record.id();
            let state = if let Some(state) = self.states.get(&id) {
                state.clone()
            } else {
                let (_, mut next) =
                    authority::validate_authorized(&[&bytes], history.last().cloned())
                        .unwrap_or_else(|e| panic!("context {}: {e:?}", self.record_name(&id)));
                let state = next.pop().unwrap();
                self.states.insert(id, state.clone());
                state
            };
            history.push(state);
        }
        history
    }
    pub fn at(&mut self, name: &str) -> ControlState {
        let c = self.corpus.case(name).clone();
        let mut history = self.history(&c["context"]);
        let bytes = self.record_bytes(name);
        let record = ReceivedControlRecord::parse(&bytes).unwrap();
        if let Some(state) = self.states.get(&record.id()) {
            return state.clone();
        }
        let (_, next) = authority::validate_authorized(&[&bytes], history.pop())
            .unwrap_or_else(|e| panic!("at {name}: {e:?}"));
        let state = next.last().unwrap().clone();
        self.states.insert(state.head.id, state.clone());
        state
    }
    pub fn queries(&self, state: &ControlState, labels: impl Iterator<Item = String>) -> J {
        J::Object(labels.map(|label|{let id=self.id(&label);(label,json!({"rootOf":self.name(&state.root_of(&id)),"actsFor":self.name(&state.acts_for(&id)),"bound":state.bound(&id),"active":state.active_device(&id).is_some()}))}).collect())
    }
    pub fn state(&self, state: &ControlState) -> J {
        let roles: BTreeMap<_, _> = state
            .roles()
            .map(|(id, r)| {
                (
                    self.name(&id),
                    match r {
                        Role::Device => "device",
                        Role::NonDevice => "non-device",
                    },
                )
            })
            .collect();
        let devices:BTreeMap<_,_>=state.devices().map(|(id,d)|{
   let active=state.active_device(&id).is_some();let suspended=d.registered && state.revocation(&d.root,&id).is_none() && d.issuers.iter().any(|i|state.revocation(&d.root,i).is_some());
   let leaf=d.leaf_id.map(|h|self.certificate_names.get(&h.to_hex()).cloned().unwrap_or_else(||h.to_hex()));
   (self.name(&id),json!({"root":self.name(&d.root),"kind":d.kind as u8,"mask":d.mask,"scope":d.scope.iter().map(|r|self.resources.get(r).cloned().unwrap_or_else(||r.to_b64url())).collect::<Vec<_>>(),"registered":d.registered,"leaf":leaf,"issuers":d.issuers.iter().map(|i|self.name(i)).collect::<Vec<_>>(),"active":active,"suspended":suspended,"reads":state.holds(&id,1)}))
  }).collect();
        let revoked: BTreeMap<_, _> = state
            .revocations()
            .map(|(root, device, r)| {
                let mut v = json!({"reason":r.reason});
                if let Some(h) = r.approval {
                    v["approval"] = json!({"hex":h.to_hex()});
                }
                (format!("{}/{}", self.name(&root), self.name(&device)), v)
            })
            .collect();
        let mut standing: Vec<_> = state
            .roles()
            .filter(|(_, role)| *role == Role::NonDevice)
            .filter(|(id, _)| state.root_standing(id))
            .map(|(id, _)| self.name(&id))
            .collect();
        standing.sort();
        json!({"owner":self.name(state.owner.id()),"control_seq":state.head.sequence,"epoch":state.current_epoch,"roles":roles,"devices":devices,"revoked":revoked,"standing":standing})
    }
    pub fn run(&mut self, c: &J) -> J {
        let id = s(&c["id"]);
        let i = &c["inputs"];
        let e = &c["expected"];
        let result: Result<J, Error> = (|| match s(&c["kind"]) {
            "principal" => {
                expected_fields(
                    c,
                    &[
                        "ed25519_public",
                        "x25519_public",
                        "principal_id",
                        "descriptor_cbor",
                    ],
                );
                let ed = bytes(&i["ed25519_seed"]);
                let x = bytes(&i["x25519_private"]);
                let keys = PrincipalKeys::from_secrets(
                    ed.as_slice().try_into().unwrap(),
                    x.try_into().unwrap(),
                );
                let d = keys.descriptor();
                assert_eq!(d.ed25519_public().as_slice(), bytes(&e["ed25519_public"]));
                assert_eq!(d.x25519_public().as_slice(), bytes(&e["x25519_public"]));
                assert_eq!(d.encode(), bytes(&e["descriptor_cbor"]), "{id}");
                assert_eq!(d.id().to_hex(), s(&e["principal_id"]["hex"]));
                Ok(accepted(
                    vec![d.id().to_hex()],
                    json!({"descriptor_cbor":lfcp::base::to_hex(&d.encode())}),
                ))
            }
            "device_certificate" => {
                let object = if c["type"] == "bytes" {
                    &e["cose_sign1"]
                } else {
                    &i["cose_sign1"]
                };
                let cert = DeviceCertificate::parse(&bytes(object))?;
                cose::verify(cert.signed_object(), &self.principals[s(&i["signer"])])?;
                if c["type"] == "bytes" {
                    self.check_object(cert.signed_object(), e);
                    let signed =
                        DeviceCertificate::sign(cert.payload().clone(), &keys(s(&i["signer"])))?;
                    assert_eq!(signed.signed_object().bytes(), cert.signed_object().bytes());
                    assert_eq!(
                        cert.payload_digest().to_hex(),
                        s(&e["payload_digest"]["hex"])
                    );
                }
                Ok(accepted(
                    vec![cert.id().to_hex()],
                    json!({"payload_digest":cert.payload_digest().to_hex()}),
                ))
            }
            "signed_object" => {
                let o = cose::parse(&bytes(&e["cose_sign1"]))?;
                cose::verify(&o, &self.principals[s(&i["signer"])])?;
                self.check_object(&o, e);
                let recreated = cose::sign(o.payload_bytes(), &keys(s(&i["signer"])))?;
                assert_eq!(recreated.bytes(), o.bytes());
                Ok(accepted(vec![o.id().to_hex()], J::Null))
            }
            "certificate_chain" => {
                let root = self.id(s(&i["root"]));
                let value = lfcp::cbor::Value::Array(
                    i["chain"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| lfcp::cbor::Value::bytes(bytes(v)))
                        .collect(),
                );
                let chain = CertificateChain::from_value(&value, &root)?;
                let history = self.history(&c["context"]);
                let state = history.last().unwrap();
                let verified = verify_chain(
                    &chain,
                    &root,
                    state.principal(&root),
                    &state.resource_id,
                    state,
                )?;
                let p = chain.leaf().payload();
                let leaf = self
                    .certificate_names
                    .get(&chain.leaf().id().to_hex())
                    .cloned()
                    .unwrap_or_default();
                let post = json!({"leaf":self.name(p.device.id()),"leaf_certificate":leaf,"kind":p.kind as u8,"mask":p.mask,"issuers":chain.issuers().map(|id|self.name(id)).collect::<Vec<_>>(),"in_scope":verified.in_scope,"new_bindings":chain.certificates().iter().filter(|c|!state.bound(c.payload().device.id())).map(|c|self.name(c.payload().device.id())).collect::<Vec<_>>()});
                if let Some(expected) = e.get("post_state") {
                    subset(&post, expected, id);
                }
                Ok(accepted(
                    chain
                        .certificates()
                        .iter()
                        .map(|c| c.id().to_hex())
                        .collect(),
                    post,
                ))
            }
            "control_record" => {
                let bytes = bytes(&i["cose_sign1"]);
                let received = ReceivedControlRecord::parse(&bytes)?;
                let mut history = self.history(&c["context"]);
                let duplicate = history.iter().any(|s| s.head.id == received.id());
                let state = if duplicate {
                    let all = self.context_bytes(&c["context"]);
                    let mut refs: Vec<_> = all.iter().map(Vec::as_slice).collect();
                    refs.push(&bytes);
                    let (outcome, states) =
                        authority::validate_authorized(&refs, None).map_err(|e| e.error)?;
                    assert!(matches!(outcome, ChainOutcome::Linear(_)));
                    assert_eq!(states, history);
                    history.pop().unwrap()
                } else {
                    let (_, states) =
                        authority::validate_authorized(&[&bytes], history.last().cloned())
                            .map_err(|e| e.error)?;
                    let state = states.last().unwrap().clone();
                    self.states.insert(state.head.id, state.clone());
                    state
                };
                let mut post = self.state(&state);
                if duplicate {
                    post = json!({"already_in_chain":true,"ack_record":self.record_name(&received.id()),"control_seq":state.head.sequence,"state_unchanged":true});
                }
                if let Some(expected) = e.get("post_state") {
                    if expected.get("issuer_root").is_some() {
                        post["issuer_root"] =
                            json!(self.name(&state.grant(&state.head.id).unwrap().issuer_root));
                    }
                    if expected.get("in_scope").is_some() {
                        post["in_scope"] = json!(received
                            .body()
                            .device_chain()
                            .unwrap()
                            .check_authority(&state.resource_id)?);
                    }
                    if expected.get("exposing").is_some() {
                        post["exposing"] =
                            json!(state.last_exposing_revocation == Some(state.head));
                    }
                    if let Some(q) = expected.get("queries") {
                        post["queries"] =
                            self.queries(&state, q.as_object().unwrap().keys().cloned());
                    }
                    subset(&post, expected, id);
                }
                Ok(accepted(vec![received.id().to_hex()], post))
            }
            "data_unit" | "key_package" | "snapshot" | "session_upload" => {
                let history = self.history(&c["context"]);
                let raw = bytes(&i["cose_sign1"]);
                let kind = if c["kind"] == "session_upload" {
                    if i["request"] == "KEY_PACKAGE_PUT" {
                        "key_package"
                    } else {
                        "data_unit"
                    }
                } else {
                    s(&c["kind"])
                };
                match kind {
                    "data_unit" => {
                        let received = ReceivedDataUnit::parse(&raw)?;
                        let header = received.header();
                        let head = ControlRecordId::from_bytes(*header.control_head.as_bytes());
                        let state = authority::state_at(&history, &head)
                            .ok_or(Error::UnknownControlHead)?;
                        let actor = state
                            .principal(&header.actor)
                            .ok_or(Error::IssuerUnknown(header.actor))?;
                        let unit =
                            received.verify_with(actor, authority::data_unit_policy(&history))?;
                        if let Some(previous) = c["context"].get("accepted_unit") {
                            let prior = ReceivedDataUnit::parse(&self.corpus.ref_bytes(previous))?
                                .verify(actor)?;
                            lfcp::wire::data_unit::check_equivocation(&unit, &prior)?;
                        }
                        let plain =
                            unit.open(&self.dek(s(&i["resource"]), unit.header().data_epoch))?;
                        if let Some(expected) = i.get("plaintext_utf8") {
                            assert_eq!(plain, s(expected).as_bytes(), "{id}");
                        }
                        assert_eq!(unit.id().to_hex(), s(&i["object_id"]["hex"]));
                        Ok(accepted(
                            vec![unit.id().to_hex()],
                            json!({"plaintext_hex":lfcp::base::to_hex(&plain)}),
                        ))
                    }
                    "key_package" => {
                        let received = ReceivedKeyPackage::parse(&raw)?;
                        let header = received.header();
                        let head = ControlRecordId::from_bytes(*header.control_head.as_bytes());
                        let state = authority::state_at(&history, &head)
                            .ok_or(Error::UnknownControlHead)?;
                        let signer = state
                            .principal(&header.sender)
                            .ok_or(Error::IssuerUnknown(header.sender))?;
                        let package =
                            received.verify(signer, authority::key_package_policy(&history))?;
                        assert_eq!(package.id().to_hex(), s(&i["object_id"]["hex"]));
                        let h = package.header();
                        let dek = package.open(
                            &keys(s(&i["recipient"])),
                            &state.dek_commitments[&h.data_epoch],
                        )?;
                        assert_eq!(
                            dek.expose_secret(),
                            self.dek(s(&i["resource"]), h.data_epoch).expose_secret()
                        );
                        let mut post = json!({});
                        if let Some(fields) = e.get("post_state") {
                            for key in fields.as_object().unwrap().keys() {
                                let value = if let Some(rest) = key
                                    .strip_prefix("holds_")
                                    .or_else(|| key.strip_prefix("direct_"))
                                {
                                    let (name, ability) = rest.rsplit_once('_').unwrap();
                                    // These direct queries name unbound roots, whose holds
                                    // path is the direct-authority calculation.
                                    if key.starts_with("direct_") {
                                        assert!(!state.bound(&self.id(name)));
                                    }
                                    state.holds(&self.id(name), ability.parse().unwrap())
                                } else if let Some(name) = key.strip_prefix("invitation_exception_")
                                {
                                    let principal = self.id(name);
                                    !state.bound(&principal) && state.holds(&principal, 11)
                                } else {
                                    panic!("unchecked key-package query {key}");
                                };
                                post[key] = json!(value);
                            }
                        }
                        Ok(accepted(vec![package.id().to_hex()], post))
                    }
                    _ => {
                        let received = ReceivedSnapshot::parse(&raw)?;
                        let header = received.header();
                        let head = ControlRecordId::from_bytes(*header.control_head.as_bytes());
                        let state = authority::state_at(&history, &head)
                            .ok_or(Error::UnknownControlHead)?;
                        let signer = state
                            .principal(&header.publisher)
                            .ok_or(Error::IssuerUnknown(header.publisher))?;
                        let snapshot =
                            received.verify_with(signer, authority::snapshot_policy(&history))?;
                        let plaintext = snapshot
                            .open(&self.dek(s(&i["resource"]), snapshot.header().data_epoch))?;
                        assert_eq!(plaintext, s(&i["plaintext_utf8"]).as_bytes());
                        Ok(accepted(vec![snapshot.id().to_hex()], J::Null))
                    }
                }
            }
            "session_read" => {
                let history = self.history(&c["context"]);
                let state = history.last().unwrap();
                let access = state.may_read(&self.id(s(&i["session"])));
                let (read, head) = match access {
                    ReadAccess::Full => ("full", state.head),
                    ReadAccess::ControlPrefix(h) if i["request"] == "CONTROL_GET" => ("prefix", h),
                    _ => {
                        return Err(Error::AuthorizationFailed(
                            lfcp::base::AuthorityRule::MissingAbility(1),
                        ))
                    }
                };
                let mut post = json!({"read":read,"control_head":self.record_name(&head.id)});
                if read == "prefix" {
                    post["records"] = json!(history
                        .iter()
                        .filter(|s| s.head.sequence <= head.sequence)
                        .map(|s| self.record_name(&s.head.id))
                        .collect::<Vec<_>>());
                    post["refused_reads"] = json!([
                        ("later Control Records", Some(head.sequence + 1)),
                        ("DATA_HAVE", None),
                        ("DATA_GET", None),
                        ("KEY_PACKAGE_GET", None),
                        ("SNAPSHOT_GET", None),
                        ("presence", None),
                    ]
                    .into_iter()
                    .filter(|(_, sequence)| !read_allowed(access, *sequence))
                    .map(|(name, _)| name)
                    .collect::<Vec<_>>());
                }
                subset(&post, &e["post_state"], id);
                Ok(accepted(vec![head.id.to_hex()], post))
            }
            "key_package_matrix" => {
                expected_fields(c, &["outcome_by_head_sender_recipient"]);
                let mut tables = BTreeMap::new();
                for (name, head) in i["heads"].as_object().unwrap() {
                    let state = self.at(s(head));
                    let mut senders = BTreeMap::new();
                    for sender in i["principals"].as_array().unwrap() {
                        let mut recipients = BTreeMap::new();
                        for recipient in i["principals"].as_array().unwrap() {
                            let sender_id = self.id(s(sender));
                            let result = state
                                .principal(&sender_id)
                                .ok_or(Error::IssuerUnknown(sender_id))
                                .and_then(|_| {
                                    authority::can_distribute_key(
                                        &state,
                                        &sender_id,
                                        &self.id(s(recipient)),
                                    )
                                });
                            recipients.insert(s(recipient), code(result.as_ref().err()));
                        }
                        senders.insert(s(sender), recipients);
                    }
                    tables.insert(name, senders);
                }
                assert_eq!(json!(tables), e["outcome_by_head_sender_recipient"], "{id}");
                Ok(accepted(vec![], json!(tables)))
            }
            "rotator_test" => {
                expected_fields(c, &["tables"]);
                let mut tables = BTreeMap::new();
                for (label, expected) in e["tables"].as_object().unwrap() {
                    let resource = label.split_once(' ').unwrap().0;
                    let state = self.at(s(&i["heads"][resource]));
                    let mut readers: Vec<_> = self
                        .principals
                        .iter()
                        .filter(|(_, d)| state.holds(d.id(), 1))
                        .map(|(n, _)| n.clone())
                        .collect();
                    readers.sort();
                    let mut candidates = BTreeMap::new();
                    for candidate in expected["candidates"].as_object().unwrap().keys() {
                        let id = self.id(candidate);
                        let all = readers
                            .iter()
                            .all(|r| state.root_of(&self.id(r)) == state.root_of(&id));
                        candidates.insert(candidate,json!({"holds_6":state.holds(&id,6),"holds_7":state.holds(&id,7),"every_reader_of_own_root":all,"rotator":state.holds(&id,7) && (state.holds(&id,6)||all)}));
                    }
                    tables.insert(label, json!({"readers":readers,"candidates":candidates}));
                }
                assert_eq!(json!(tables), e["tables"]);
                Ok(accepted(vec![], json!(tables)))
            }
            "wire_message" => {
                expected_fields(c, &["message_cbor"]);
                let raw = bytes(&e["message_cbor"]);
                let message = lfcp::wire::message::Message::decode(&raw, &Default::default())?;
                let lfcp::wire::message::Body::Ready(body) = &message.body else {
                    panic!("{id}: not a READY message");
                };
                assert_eq!(message.message_id.as_slice(), bytes(&i["message_id"]));
                assert_eq!(
                    message.correlation_id.unwrap().as_slice(),
                    bytes(&i["correlation"])
                );
                assert_eq!(body.wire_profile, i["wire_profile"]);
                assert_eq!(body.server_id.as_slice(), bytes(&i["server_id"]));
                assert_eq!(json!(body.max_message_bytes), i["max_message_bytes"]);
                assert_eq!(json!(body.durability), i["durability"]);
                assert_eq!(json!(body.heartbeat_ms), i["heartbeat_ms"]);
                assert_eq!(
                    body.extensions.as_deref(),
                    Some([s(&i["extension"]).to_owned()].as_slice())
                );
                assert_eq!(message.encode(), raw);
                Ok(accepted(
                    vec![],
                    json!({"message_hex":lfcp::base::to_hex(&raw)}),
                ))
            }
            other => panic!("unsupported wire kind {other}"),
        })();
        match result {
            Ok(v) => v,
            Err(e) => {
                let mut result = refused(code(Some(&e)), None);
                if matches!(e, Error::StaleDataEpoch(_)) {
                    result["disposition"] = json!("quarantine");
                }
                result
            }
        }
    }
    fn check_object(&self, o: &cose::SignedObject, e: &J) {
        for key in e.as_object().unwrap().keys() {
            assert!(
                [
                    "payload_cbor",
                    "protected_header_cbor",
                    "sig_structure_cbor",
                    "signature",
                    "cose_sign1",
                    "object_id",
                    "certificate_id",
                    "payload_digest"
                ]
                .contains(&key.as_str()),
                "unchecked signed object field {key}"
            );
        }
        for (field, actual) in [
            ("payload_cbor", o.payload_bytes().to_vec()),
            ("protected_header_cbor", o.protected_bytes().to_vec()),
            ("sig_structure_cbor", o.sig_structure()),
            ("signature", o.signature().to_vec()),
            ("cose_sign1", o.bytes().to_vec()),
            ("object_id", o.id().as_bytes().to_vec()),
            ("certificate_id", o.id().as_bytes().to_vec()),
            (
                "payload_digest",
                lfcp::crypto::sha256(o.payload_bytes()).as_bytes().to_vec(),
            ),
        ] {
            if let Some(expected) = e.get(field) {
                assert_eq!(actual, bytes(expected), "{field}");
            }
        }
    }
    pub fn dek(&self, resource: &str, epoch: u64) -> Dek {
        let data = lfcp::crypto::sha256(
            format!("LFCP-TV-IDENTITY-DEK-{resource}-EPOCH-{epoch}").as_bytes(),
        );
        Dek::from_bytes(*data.as_bytes())
    }
}
fn read_allowed(access: ReadAccess, control_sequence: Option<u64>) -> bool {
    match access {
        ReadAccess::Full => true,
        ReadAccess::ControlPrefix(head) => control_sequence.is_some_and(|seq| seq <= head.sequence),
        ReadAccess::Denied => false,
    }
}
pub fn keys(label: &str) -> PrincipalKeys {
    let ed = lfcp::crypto::sha256(format!("LFCP-TV-{label}-ED25519").as_bytes());
    let x = lfcp::crypto::sha256(format!("LFCP-TV-{label}-X25519").as_bytes());
    PrincipalKeys::from_secrets(ed.as_bytes(), *x.as_bytes())
}
pub fn code(error: Option<&Error>) -> &'static str {
    error.map_or("accept", |e| {
        e.wire_code()
            .unwrap_or_else(|| panic!("no wire code: {e:?}"))
            .name()
    })
}
pub fn subset(actual: &J, expected: &J, context: &str) {
    if let Some(fields) = expected.as_object() {
        if [".devices", ".roles", ".revoked"]
            .iter()
            .any(|suffix| context.ends_with(suffix))
        {
            assert_eq!(
                actual.as_object().unwrap().keys().collect::<Vec<_>>(),
                fields.keys().collect::<Vec<_>>(),
                "{context} keys"
            );
        }
        for (key, e) in fields {
            let value = actual
                .get(key)
                .unwrap_or_else(|| panic!("{context}: missing {key}"));
            subset(value, e, &format!("{context}.{key}"));
        }
    } else {
        assert_eq!(actual, expected, "{context}");
    }
}
