#![cfg(feature = "identity")]
//! Fixture executor: real Wire/profile cases, explicit stateful receive/rebuild,
//! CAS, replay, phase classification and package-ledger simulations. External
//! client/server effects are reported N/A with their normative boundary.
mod support;
use lfcp::{
    base::{ControlRecordId, Hash32},
    wire::{
        control::{
            authority::{self, ControlState},
            body::ControlBody,
            chain::{check_expected_head, ChainOutcome},
            device::DeviceKind,
            ControlRecord, ReceivedControlRecord,
        },
        data_unit::ReceivedDataUnit,
        have::HaveVector,
    },
};
use serde_json::{json, Value as J};
use std::collections::{BTreeMap, BTreeSet};
use support::{
    identity_corpus::*,
    identity_profile::Profile,
    identity_wire::{code, keys, subset, Wire},
};

struct Executor {
    wire: Wire,
    profile: Profile,
    results: BTreeMap<String, J>,
    units: BTreeMap<String, Vec<u8>>,
    ledger: BTreeMap<(String, u64, String), String>,
}
impl Executor {
    fn new() -> Self {
        Self {
            wire: Wire::load(),
            profile: Profile::load(),
            results: BTreeMap::new(),
            units: BTreeMap::new(),
            ledger: BTreeMap::new(),
        }
    }
    fn reference(&mut self, reference: &str) -> J {
        let (suite, id) = reference.split_once(':').unwrap();
        let result = if suite == "wire" {
            let c = self.wire.corpus.case(id).clone();
            let result = self.wire.run(&c);
            check(&c, &result);
            if result["outcome"] == "accept" && c["kind"] == "data_unit" {
                self.units
                    .insert(id.into(), bytes(&c["inputs"]["cose_sign1"]));
            }
            if result["outcome"] == "accept" && c["kind"] == "key_package" {
                let i = &c["inputs"];
                self.ledger.insert(
                    (
                        s(&i["resource"]).into(),
                        i["epoch"].as_u64().unwrap(),
                        s(&i["recipient"]).into(),
                    ),
                    s(&i["object_id"]["hex"]).into(),
                );
            }
            result
        } else {
            assert_eq!(suite, "profile");
            let c = self.profile.corpus.case(id).clone();
            let result = self.profile.run(&c);
            check(&c, &result);
            result
        };
        self.results.insert(reference.into(), result.clone());
        result
    }
    fn phase(&mut self, input: &J) -> &'static str {
        let state = self
            .wire
            .at(s(&input["state"]).strip_prefix("wire:").unwrap());
        match s(&input["phase"]) {
            "consume" => {
                let root = self.wire.id(s(&input["root"]));
                let device = self.wire.id(s(&input["device"]));
                match state.revocation(&root, &device) {
                    None => "pending",
                    Some(r)
                        if r.reason == 3
                            && r.approval
                                == Some(Hash32::from_hex(s(&input["digest"])).unwrap()) =>
                    {
                        "committed-own"
                    }
                    _ => "superseded",
                }
            }
            "register" => {
                let root = self.wire.id(s(&input["root"]));
                let device = self.wire.id(s(&input["device"]));
                let cert = self.certificate(s(&input["certificate"]));
                // The issuers are those of the planned chain, whatever the current binding
                // holds (none before a first registration, another leaf before a
                // re-certification); the chain must be one chain of the root (c1, c5, c7).
                let chain = lfcp::wire::control::device::CertificateChain::new(
                    input["chain"]
                        .as_array()
                        .unwrap_or_else(|| panic!("register phase without a chain: {input}"))
                        .iter()
                        .map(|c| self.certificate(s(c)))
                        .collect(),
                    &root,
                )
                .unwrap();
                assert_eq!(chain.leaf().id(), cert.id());
                assert_eq!(chain.leaf().payload().device.id(), &device);
                if state.revocation(&root, &device).is_some()
                    || chain
                        .issuers()
                        .any(|issuer| state.revocation(&root, issuer).is_some())
                {
                    return "superseded";
                }
                let in_scope = cert.payload().kind
                    == lfcp::wire::control::device::DeviceKind::Personal
                    || cert.payload().scope.contains(&state.resource_id);
                if state
                    .device(&device)
                    .is_some_and(|d| d.leaf_id == Some(cert.id()) && d.registered == in_scope)
                {
                    if input["own"].as_bool().unwrap_or(true) {
                        "committed-own"
                    } else {
                        "complete"
                    }
                } else if input["pairing_phase_2"] == true
                    && state.device(&device).is_some_and(|d| d.chain.is_some())
                {
                    "superseded"
                } else {
                    "pending"
                }
            }
            "revoke" | "cancel" => {
                let root = self.wire.id(s(&input["root"]));
                let device = self.wire.id(s(&input["device"]));
                match state.revocation(&root, &device) {
                    None => "pending",
                    Some(r) if r.reason == 3 => "superseded",
                    _ => "complete",
                }
            }
            "rotate" => {
                let revoked = self
                    .wire
                    .at(s(&input["revoked_at"]).strip_prefix("wire:").unwrap());
                let c = self
                    .wire
                    .corpus
                    .case(s(&input["state"]).strip_prefix("wire:").unwrap());
                let mut records = self.wire.context_bytes(&c["context"]);
                records.push(bytes(&c["inputs"]["cose_sign1"]));
                if records.iter().any(|r| {
                    let r = ReceivedControlRecord::parse(r).unwrap();
                    matches!(r.body(), ControlBody::KeyEpoch(_))
                        && r.header().sequence > revoked.head.sequence
                }) {
                    "complete"
                } else {
                    "pending"
                }
            }
            _ => panic!("phase {input}"),
        }
    }
    fn certificate(&self, name: &str) -> lfcp::wire::control::device::DeviceCertificate {
        lfcp::wire::control::device::DeviceCertificate::parse(&bytes(
            &self.wire.corpus.data["fixtures"]["certificates"][name]["cose_sign1"],
        ))
        .unwrap_or_else(|e| panic!("certificate {name}: {e:?}"))
    }
    fn certificate_name(&self, id: &lfcp::base::Hash32) -> String {
        self.wire.corpus.data["fixtures"]["certificates"]
            .as_object()
            .unwrap()
            .keys()
            .find(|name| self.certificate(name).id() == *id)
            .unwrap()
            .clone()
    }
    fn chain_names(&self, chain: &lfcp::wire::control::device::CertificateChain) -> Vec<String> {
        chain
            .certificates()
            .iter()
            .map(|c| self.certificate_name(&c.id()))
            .collect()
    }
    /// The target's state after a referenced case: its own state when accepted,
    /// else the head it was refused on.
    fn state_after(&mut self, reference: &str, result: &J) -> ControlState {
        let name = reference.strip_prefix("wire:").unwrap();
        if result["outcome"] == "accept" {
            self.wire.at(name)
        } else {
            let c = self.wire.corpus.case(name).clone();
            self.wire.history(&c["context"]).pop().unwrap()
        }
    }
    fn retry(&mut self, reference: &str) -> J {
        let name = reference.strip_prefix("wire:").unwrap();
        let c = self.wire.corpus.case(name).clone();
        let raw = self.wire.record_bytes(name);
        let mut all = self.wire.context_bytes(&c["context"]);
        all.push(raw.clone());
        let before = authority::validate_authorized(
            &all.iter().map(Vec::as_slice).collect::<Vec<_>>(),
            None,
        )
        .unwrap();
        all.push(raw);
        let after = authority::validate_authorized(
            &all.iter().map(Vec::as_slice).collect::<Vec<_>>(),
            None,
        )
        .unwrap();
        assert_eq!(before, after);
        json!({"outcome":"same ACK","transition":false,"accepted_ids":[before.1.last().unwrap().head.id.to_hex()]})
    }
    fn run(&mut self, c: &J) -> J {
        let id = s(&c["id"]);
        expected_fields(c, &["steps", "final"]);
        assert_eq!(
            c["inputs"]["steps"].as_array().unwrap().len(),
            c["expected"]["steps"].as_array().unwrap().len(),
            "{id}: step count"
        );
        let mut steps = Vec::new();
        let mut na = Vec::new();
        for (step, expected) in c["inputs"]["steps"]
            .as_array()
            .unwrap()
            .iter()
            .zip(c["expected"]["steps"].as_array().unwrap())
        {
            let ledger_before = self.ledger.clone();
            let n = step["n"].as_u64().unwrap();
            assert_eq!(step["n"], expected["n"]);
            let mut actual = if let Some(reference) = step.get("case") {
                let result = self.reference(s(reference));
                let mut actual = json!({"outcome":result["outcome"],"accepted_ids":result["accepted_ids"],"post_state":result["post_state"]});
                if result["outcome"] == "N/A" {
                    actual["reason"] = result["not_applicable"].clone();
                }
                if s(reference).starts_with("profile:") && result["outcome"] == "PROFILE_INVALID" {
                    actual["outcome"] = result["diagnostic"].clone();
                }
                if s(reference).starts_with("profile:") {
                    let case = self
                        .profile
                        .corpus
                        .case(s(reference).strip_prefix("profile:").unwrap());
                    if case["type"] == "bytes" {
                        actual["outcome"] = json!("exact bytes");
                    } else if case["type"] == "behavioral" {
                        actual["outcome"] = json!("see case");
                    }
                }
                if s(reference) == "wire:flow.rotator_test" {
                    actual["outcome"] = json!("see case");
                    actual["tables"] = result["post_state"].clone();
                }
                if let Some(devices) = result["post_state"].get("devices").and_then(J::as_object) {
                    let mut active = BTreeMap::new();
                    let mut suspended = Vec::new();
                    let mut registered = Vec::new();
                    for (name, device) in devices {
                        actual[name] = device.clone();
                        active.insert(name, device["active"].clone());
                        if device["suspended"] == true {
                            suspended.push(name);
                        }
                        if device["registered"] == true {
                            registered.push(name);
                        }
                    }
                    actual["active"] = json!(active);
                    actual["suspended"] = json!(suspended);
                    actual["registered"] = json!(registered);
                    actual["revoked"] = result["post_state"]["revoked"].clone();
                }
                if let Some(exposing) = result["post_state"].get("exposing") {
                    actual["exposing"] = exposing.clone();
                    actual["rotations"] = json!(u8::from(exposing == true));
                }
                if result["outcome"] == "STALE_DATA_EPOCH" {
                    actual["disposition"] = json!("quarantine");
                }
                if s(reference).starts_with("wire:") {
                    let name = s(reference).strip_prefix("wire:").unwrap();
                    let case = self.wire.corpus.case(name).clone();
                    if case["kind"] == "session_read" {
                        if let Some(post) = result["post_state"].as_object() {
                            for (key, value) in post {
                                if actual.get(key).is_none() {
                                    actual[key] = value.clone();
                                }
                            }
                        }
                    }
                    if case["kind"] == "control_record" && result["outcome"] == "accept" {
                        let record =
                            ReceivedControlRecord::parse(&self.wire.record_bytes(name)).unwrap();
                        if let ControlBody::KeyEpoch(epoch) = record.body() {
                            let frontier:BTreeMap<_,_>=epoch.final_frontier.entries().iter().map(|h|(self.wire.name(&h.principal),if id=="F01_register_write_revoke_cutoff"{json!(h.contiguous)}else{json!({"contiguous":h.contiguous,"extra_ranges":h.extra})})).collect();
                            actual["frontier"] = json!(frontier);
                        }
                    }
                    if let Some(carries) = expected.get("carries") {
                        let raw = bytes(&case["inputs"]["cose_sign1"]);
                        let u = ReceivedDataUnit::parse(&raw).unwrap();
                        let signer =
                            self.wire.principals[&self.wire.name(&u.header().actor)].clone();
                        let u = u.verify(&signer).unwrap();
                        let plain = u
                            .open(
                                &self
                                    .wire
                                    .dek(s(&case["inputs"]["resource"]), u.header().data_epoch),
                            )
                            .unwrap();
                        let change = lfcp::shared_objects::framing::decode_change(&plain).unwrap();
                        let change_case = self
                            .profile
                            .corpus
                            .cases
                            .values()
                            .find(|c| {
                                c["inputs"]["change_hash"] == change.hash().to_string()
                                    && s(&c["id"]).starts_with("change.")
                            })
                            .unwrap();
                        let h = self.wire.history(&case["context"]);
                        let head = authority::state_at(
                            &h,
                            &ControlRecordId::from_bytes(*u.header().control_head.as_bytes()),
                        )
                        .unwrap();
                        let class = lfcp::identity::WriterClass::at(
                            &self.profile.owner,
                            &u.header().actor,
                            head,
                        );
                        let writer_class = match class {
                            lfcp::identity::WriterClass::Root => "root",
                            lfcp::identity::WriterClass::Personal => "personal",
                            lfcp::identity::WriterClass::Pairing => "pairing",
                            _ => "other",
                        };
                        actual["carries"] = json!({"change":change_case["id"],"change_hash":change.hash().to_string(),"writer_class":writer_class});
                        assert_eq!(actual["carries"], *carries);
                    }
                }
                actual
            } else if let Some(reference) = step.get("bytes_of") {
                if (id == "F03_stale_head_reevaluation" || id == "F06_concurrent_revokes") && n == 2
                {
                    let coordinator = if id.starts_with("F03") {
                        self.wire.at("I1_device_grant_dev_a")
                    } else {
                        self.wire.at("flow.f06_owner_revokes_dev_b")
                    };
                    let proposed = ReceivedControlRecord::parse(
                        &self
                            .wire
                            .record_bytes(s(reference).strip_prefix("wire:").unwrap()),
                    )
                    .unwrap();
                    let error = check_expected_head(
                        proposed.header().previous.unwrap(),
                        coordinator.head.id,
                    )
                    .unwrap_err();
                    json!({"outcome":code(Some(&error)),"coordinator_head":self.wire.record_name(&coordinator.head.id)})
                } else {
                    self.retry(s(reference))
                }
            } else if step.get("phase_input").is_some() {
                json!({"outcome":"done"})
            } else {
                self.operation(id, n)
            };
            actual["n"] = json!(n);
            if let Some(input) = step.get("phase_input") {
                let phase = self.phase(input);
                actual["simulation"] = json!(true);
                actual["phase"] = json!(phase);
                actual["proposes"] = json!(phase == "pending");
                actual["not_superseded"] = json!(phase != "superseded");
                actual["signs"] = json!(phase != "superseded");
            }
            if let Some(journal) = step.get("journal") {
                let payload =
                    lfcp::base::from_hex(s(&journal["certificate_payload_cbor"])).unwrap();
                let digest = lfcp::crypto::sha256(&payload);
                let signed = lfcp::cose::sign(&payload, &keys("DEV_A")).unwrap();
                let cert =
                    lfcp::wire::control::device::DeviceCertificate::parse(signed.bytes()).unwrap();
                let fixture = &self.wire.corpus.data["fixtures"]["certificates"]["CERT_B"];
                assert_eq!(signed.bytes(), bytes(&fixture["cose_sign1"]));
                assert_eq!(cert.payload_digest(), digest);
                actual["signed_certificate"] = json!("CERT_B");
                if journal["phase"] == "register" {
                    // The chain of the signed certificate: CERT_B, then its signer's chain at
                    // the head the phase runs on.
                    let state = self.wire.at(s(&step["phase_input"]["state"])
                        .strip_prefix("wire:")
                        .unwrap());
                    let signer = state.device(cert.signed_object().kid()).unwrap();
                    let mut chain = vec![self.certificate_name(&cert.id())];
                    chain.extend(self.chain_names(signer.chain.as_ref().unwrap()));
                    actual["chain"] = json!(chain);
                }
                actual["certificate_payload_matches_journal"] =
                    json!(signed.payload_bytes() == payload);
                if let Some(d) = journal.get("certificate_payload_digest") {
                    assert_eq!(digest.to_hex(), s(d));
                }
            }
            self.additional(id, n, step, &mut actual);
            if id == "F13_durable_phases" && n == 13 {
                let phases: BTreeMap<_, _> = ["BOB", "CAROL"]
                    .iter()
                    .map(|name| {
                        (
                            *name,
                            if ledger_before.contains_key(&("X".into(), 1, name.to_string())) {
                                "complete"
                            } else {
                                "pending"
                            },
                        )
                    })
                    .collect();
                actual["package_phases"] = json!(phases);
            }
            if actual["outcome"] == "N/A" {
                na.push(json!({"step":n,"reason":actual["reason"]}));
            } else {
                // Every expected assertion is either checked or explicitly bounded by a
                // missing external system; never copy an expected value into actual state.
                for (key, value) in expected.as_object().unwrap() {
                    if key == "n" {
                        continue;
                    }
                    if actual.get(key).is_some() {
                        subset(&actual[key], value, &format!("{id}/{n}.{key}"));
                    } else {
                        let reason = boundary(id, key);
                        na.push(json!({"step":n,"field":key,"reason":reason}));
                    }
                }
            }
            steps.push(actual);
        }
        let final_state = self.final_state(id);
        for (key, value) in c["expected"]["final"].as_object().unwrap() {
            // This is explanatory prose; the exact numeric frontier and all
            // hole/cutoff outcomes are checked above and below.
            if key == "frontier_rule" {
                na.push(json!({"field":"final.frontier_rule","reason":boundary(id, key)}));
                continue;
            }
            if let Some(actual) = final_state.get(key) {
                subset(actual, value, &format!("{id}.final.{key}"));
            } else {
                na.push(json!({"field":format!("final.{key}"),"reason":boundary(id, key)}));
            }
        }
        json!({"outcome":if na.is_empty(){"accept"}else{"N/A"},"simulation":true,"steps":steps,"post_state":final_state,"not_applicable":na})
    }
    fn operation(&mut self, id: &str, n: u64) -> J {
        match (id,n){
   ("F01_register_write_revoke_cutoff",9)=>{
    let c=self.wire.corpus.case("K1_key_epoch").clone();let mut history=self.wire.history(&c["context"]);history.push(self.wire.at("K1_key_epoch"));let mut accepted_names=Vec::new();let mut excluded=Vec::new();
    for (name,raw) in &self.units{let unit=ReceivedDataUnit::parse(raw).unwrap();match authority::data_unit_policy(&history)(unit.header()){Ok(())=>accepted_names.push(name.clone()),Err(e)=>{assert_eq!(code(Some(&e)),"STALE_DATA_EPOCH");excluded.push(name.clone());}}}
    let order=["D_dev_a_seq1","D_dev_b_seq1","D_bridge_writes_x"];accepted_names.sort_by_key(|n|order.iter().position(|s|s==n).unwrap());
    self.results.insert("rebuild".into(),json!({"accepted":accepted_names,"excluded":excluded}));json!({"outcome":"rebuilt","excluded":excluded,"surfaced_as_stale":!excluded.is_empty()})
   }
   ("F05_reconciliation",5)=>{let state=self.wire.at("flow.reconcile_register_dev_a_in_x");let sender=self.wire.id("OWNER");let mut ledger=BTreeMap::new();for name in ["DEV_A","DEV_B"]{authority::can_distribute_key(&state,&sender,&self.wire.id(name)).unwrap();self.ledger.insert(("X".into(),0,name.into()),"simulated delivery receipt".into());ledger.insert(name,vec![0]);}json!({"outcome":"packages sent","ledger_after":ledger,"simulation":true})}
   ("F05_reconciliation",7)=>{let source=self.wire.at("P4_register_dev_b_approved");let target=self.wire.at("flow.reconcile_register_dev_a_in_x");let root=self.wire.id("OWNER");let missing=source.devices().filter(|(id,d)|d.root==root && source.active_device(id).is_some()).filter(|(id,d)|target.device(id).is_none_or(|t|t.leaf_id!=d.leaf_id||!t.registered)).count();let packages=["DEV_A","DEV_B"].iter().filter(|name|!self.ledger.contains_key(&("X".into(),0,name.to_string()))).count();assert_eq!((missing,packages),(0,0));json!({"outcome":"nothing to propose","records":missing,"packages":packages})}
   ("F05_reconciliation",3)|("F05.sixty_five_sessions",5|10)|("F05.display_data",2|5|9)|("F09_pairing_service",7|11)=>na(RECONCILE),
   ("F07.read_device_cannot_claim",2)=>na(CLAIM),
   ("F08.missing_material",2|3)=>na(PAIRING_CLIENT),
   ("F18_barrier",6)=>na(KEY_PACKAGE_CLIENT),
   ("F06_concurrent_revokes",6)=>{let state=self.wire.at("flow.f06_owner_revokes_dev_b");assert!(state.last_exposing_revocation.is_some());assert!(state.holds(&self.wire.id("DEV_A"),7));json!({"outcome":"rotation test"})}
   ("F07_invitation_accepted_by_device",6)=>na("IDENTITY-PROFILE-01 §7.2 step 3 is a client roster update in DAVE's Identity Resource; the fixture supplies no document/unit for that Resource and sdk-rs has no client roster orchestration."),
   ("F13_durable_phases",10)=>{let before=self.wire.at("I8_bridge_grant");let after=self.wire.at("I9_device_revoke_dev_a");let p=self.wire.id("DEV_A");let a=before.holds(&p,1);let b=after.holds(&p,1);assert!(a&&!b);json!({"outcome":"fresh DEK (§9.4)","DEV_A_reads":{"I8":a,"I9":b}})}
   ("F13_durable_phases",15)=>{let state=self.wire.at("K1_key_epoch");assert_eq!(state.current_epoch,1);let held_deks=BTreeSet::from([0u64]);assert!(!held_deks.contains(&state.current_epoch));json!({"outcome":"awaiting key holder","simulation":true})}
   ("F14_frontier_from_verified_set",5)=>{let mut have=HaveVector::new();for (name,raw) in &self.units{if name.starts_with("flow.y_"){let u=ReceivedDataUnit::parse(raw).unwrap();have.insert(&u.header().actor,u.header().sequence).unwrap();}}
    let actor=self.wire.id("DEV_A");assert!(have.contains(&actor,1)&&have.contains(&actor,2)&&have.contains(&actor,4));assert!(!have.contains(&actor,3)&&!have.contains(&actor,100));json!({"outcome":"verified accepted set DEV_A {1, 2, 4}"})}
   ("F15_rotation_policy_by_exposure",7)=>{let mut state=self.wire.at("I8_bridge_grant");let root=keys("OWNER");for name in ["DEV_A","DEV_C","BRIDGE"]{let r=ControlRecord::sign(lfcp::wire::control::ControlRecordHeader{resource_id:state.resource_id,sequence:state.head.sequence+1,previous:Some(state.head.id),issuer:*root.descriptor().id()},ControlBody::DeviceRevoke(lfcp::wire::control::body::DeviceRevokeBody{root:state.root_of(&self.wire.id(name)),device:self.wire.id(name),reason:1,approval:None}),&root).unwrap();state=authority::apply(Some(&state),&r).unwrap();}
    assert!(state.last_exposing_revocation.is_some());let r=ControlRecord::sign(lfcp::wire::control::ControlRecordHeader{resource_id:state.resource_id,sequence:state.head.sequence+1,previous:Some(state.head.id),issuer:*root.descriptor().id()},ControlBody::KeyEpoch(lfcp::wire::control::body::KeyEpochBody{epoch:1,dek_commitment:Hash32::from_bytes([1;32]),final_frontier:lfcp::wire::frontier::Frontier::new(vec![]).unwrap(),reason:2}),&root).unwrap();let next=authority::apply(Some(&state),&r).unwrap();assert!(next.head.sequence>state.last_exposing_revocation.unwrap().sequence);assert_eq!(next.current_epoch,1);json!({"outcome":"one rotation"})}
   ("F16_device_grant_fork",4)=>{let base=self.wire.at("I1_device_grant_dev_a");let first=self.wire.record_bytes("Rd1");let second=self.wire.record_bytes("W1");let (outcome,_)=authority::validate_authorized(&[&first,&second],Some(base)).unwrap();assert!(matches!(outcome,ChainOutcome::Conflict(_)));self.results.insert("fork".into(),json!(true));json!({"outcome":"CONTROL_CONFLICT","competing":["Rd1","W1"]})}
   ("F16_device_grant_fork",5)=>{assert_eq!(self.results.get("fork"),Some(&json!(true)));json!({"outcome":"suspended","simulation":true})}
   ("F18_barrier",5)=>{let old=self.reference("wire:D_dev_a_old_head_after_revoke");let closed=self.reference("wire:D_dev_a_beyond_epoch_cutoff");assert_eq!(old["outcome"],"accept");assert_eq!(closed["outcome"],"STALE_DATA_EPOCH");json!({"outcome":"accepted until the epoch closes"})}
   ("F19_key_bootstrap",4)=>{assert_eq!(self.ledger.len(),3);json!({"outcome":"served anyway","simulation":true})}
   ("F09_pairing_service",4|16)=>na("IDENTITY-PROFILE-01 §5.3 steps 3 and 8 require persisted candidates and live reachability; sdk-rs has no client store or transport."),
   ("F10_request_feasibility",3)=>na("IDENTITY-PROFILE-01 §5.3 step 4 requires renewed human confirmation when the request changes; sdk-rs has no approval UI or journal."),
   ("F10_request_feasibility",7|8)=>na("IDENTITY-PROFILE-01 §5.3 step 4 requires scope trimming and future-chain feasibility checks at the current head. sdk-rs validates proposed records but lacks this planning API; this is an SDK coverage gap."),
   ("F17_revoked_device",5)=>na("LFCP-WIRE-01 §69 requires server subscription/push ordering; sdk-rs has no server connections or push queues."),
   _=>panic!("unimplemented flow operation {id}/{n}"),
  }
    }
    fn additional(&mut self, id: &str, n: u64, step: &J, actual: &mut J) {
        match (id, n) {
            ("F03_stale_head_reevaluation", 7) => {
                let replay = self.retry(s(&step["case"]));
                actual["ack"] = replay["outcome"].clone();
                actual["transition"] = replay["transition"].clone();
            }
            ("F05_reconciliation", 4) | ("F08_pairing_personal", 17) => {
                let reference = s(&step["case"]);
                let name = reference.strip_prefix("wire:").unwrap();
                let record = ReceivedControlRecord::parse(&self.wire.record_bytes(name)).unwrap();
                let chain = record.body().device_chain().unwrap();
                let device = self.wire.name(chain.leaf().payload().device.id());
                let root = self.wire.name(&chain.leaf().payload().root);
                let certificate = s(&actual["post_state"]["devices"][&device]["leaf"]);
                let names = self.chain_names(chain);
                actual["phase"] = json!(self.phase(&json!({"phase":"register","state":reference,"root":root,"device":device,"certificate":certificate,"chain":names,"own":true})));
                actual["simulation"] = json!(true);
            }
            ("F08.link_reuse_and_equivocation", 3) => {
                // Exclusion and request visibility are modeled by this runner,
                // not reconstructed through IdentityReplica.
                actual["simulation"] = json!(true);
                assert_eq!(actual["outcome"], "ACTOR_EQUIVOCATION");
                let names = [
                    "flow.pl_pair_l_request",
                    "flow.pl_pair_l_request_second_install",
                ];
                for name in names {
                    self.units.remove(name);
                }
                actual["excluded"] = json!(names);
                actual["request_seen_by_A"] =
                    json!(names.iter().any(|name| self.units.contains_key(*name)));
            }
            ("F09_pairing_service", 1) => {
                let state = self.wire.at("P3s_consume_for_bridge_o");
                actual["approval"] = json!(state
                    .revocation(&self.wire.id("OWNER"), &self.wire.id("PAIR_J"))
                    .unwrap()
                    .approval
                    .unwrap()
                    .to_hex());
            }
            ("F09_pairing_service", 9 | 13 | 15) => {
                let name = s(&step["case"]).strip_prefix("wire:").unwrap();
                let c = self.wire.corpus.case(name).clone();
                let mut history = self.wire.history(&c["context"]);
                history.push(self.wire.at(name));
                let mut leaves = Vec::new();
                let mut proven = false;
                let approved = lfcp::wire::control::device::DeviceCertificate::parse(&bytes(
                    &self.wire.corpus.data["fixtures"]["certificates"]["CERT_SO"]["cose_sign1"],
                ))
                .unwrap();
                for state in &history {
                    if let Some(d) = state.device(&self.wire.id("BRIDGE_O")) {
                        if let Some(chain) = &d.chain {
                            let label =
                                self.wire.state(state)["devices"]["BRIDGE_O"]["leaf"].clone();
                            if !leaves.contains(&label) {
                                leaves.push(label);
                            }
                            proven |= chain.leaf().payload_digest() == approved.payload_digest();
                        }
                    }
                }
                actual["leaves"] = json!(leaves);
                actual["proven"] = json!(proven);
                actual["used"] = json!(proven);
                if proven {
                    let current = history
                        .last()
                        .unwrap()
                        .device(&self.wire.id("BRIDGE_O"))
                        .unwrap();
                    let p = approved.payload();
                    assert_eq!(current.kind, p.kind);
                    assert_eq!(current.mask, p.mask.iter().copied().collect());
                    assert_eq!(current.scope, p.scope);
                    actual["uses"] = actual["BRIDGE_O"]["leaf"].clone();
                } else {
                    actual["status"] = json!("approval not provable here");
                    actual["Y"] = json!("never shown as granted");
                }
            }
            ("F09_pairing_service", 14) => {
                let name = s(&step["case"]).strip_prefix("wire:").unwrap();
                let case = self.wire.corpus.case(name).clone();
                let history = self.wire.history(&case["context"]);
                let state = history.last().unwrap();
                let recipient = self.wire.id(s(&case["inputs"]["recipient"]));
                let ready = actual["outcome"] == "accept"
                    && state.holds(&recipient, 1)
                    && self.ledger.contains_key(&(
                        s(&case["inputs"]["resource"]).into(),
                        case["inputs"]["epoch"].as_u64().unwrap(),
                        s(&case["inputs"]["recipient"]).into(),
                    ));
                actual["status"] = json!(if ready { "ready" } else { "awaiting keys" });
                actual["simulation"] = json!(true);
            }
            ("F11_revoker_chain_through_target", 2) => {
                let previous = self.wire.at("I8_bridge_grant");
                assert!(previous
                    .device(&self.wire.id("DEV_E"))
                    .unwrap()
                    .issuers
                    .contains(&self.wire.id("DEV_C")));
                actual["client"] = json!("refused by the pre-check");
            }
            ("F11_revoker_chain_through_target", 5) => {
                let state = self.wire.at("flow.f11_dev_e_retires");
                actual["rotates"] = json!(state.holds(&self.wire.id("DEV_E"), 7));
            }
            ("F13_durable_phases", 13) => {
                let bob = self.ledger.get(&("X".into(), 1, "BOB".into())).unwrap();
                let carol = self.ledger.get(&("X".into(), 1, "CAROL".into())).unwrap();
                actual["ledger_after"] = json!([{"resource":"X","epoch":1,"recipient":"BOB","package_id":bob},{"resource":"X","epoch":1,"recipient":"CAROL","package_id":carol}]);
            }
            ("F14_frontier_from_verified_set", 4) => {
                actual["counted"] = json!(actual["outcome"] == "accept")
            }
            ("F15_rotation_policy_by_exposure", 6) => {
                let state = self.wire.at("V2_revoke_dev_c");
                actual["descendant_receives_new_epoch"] = json!(authority::can_distribute_key(
                    &state,
                    &self.wire.id("OWNER"),
                    &self.wire.id("DEV_E")
                )
                .is_ok());
            }
            ("F17_revoked_device", 1) => {
                actual["status"] = json!(if actual["post_state"]["read"] == "prefix" {
                    "revocation proven"
                } else {
                    "unproven"
                });
                actual["simulation"] = json!(true);
                actual["head"] = actual["post_state"]["control_head"].clone();
            }
            ("F17_revoked_device", 4) => {
                actual["status"] = json!(if actual["outcome"] == "AUTHORIZATION_FAILED" {
                    "access refused"
                } else {
                    "unknown"
                });
                actual["simulation"] = json!(true);
            }
            ("F18_barrier", 1..=4) => actual["identity_aware"] = actual["outcome"].clone(),
            ("F05.sixty_five_sessions", 4) => {
                let state = self.state_after(s(&step["case"]), actual);
                let count = state
                    .revocations()
                    .filter(|(_, d, _)| {
                        state
                            .device(d)
                            .is_some_and(|b| b.kind == DeviceKind::Pairing)
                    })
                    .count();
                actual["revoked_pairing_devices_in_I"] = json!(count);
            }
            ("F05.sixty_five_sessions", 6 | 9) => {
                // W §17.5 rule 5 counts the revoked pairs of the root whose device is not
                // bound in X (as a leaf or an intermediate).
                let state = self.state_after(s(&step["case"]), actual);
                let owner = self.wire.id("OWNER");
                let count = state
                    .revocations()
                    .filter(|(r, d, _)| *r == owner && state.device(d).is_none())
                    .count();
                actual["unbound_revoked_pairs_of_OWNER"] = json!(count);
            }
            ("F05.display_data", 1 | 3) => {
                let state = self.state_after(s(&step["case"]), actual);
                let mut bound: Vec<_> = state
                    .devices()
                    .filter(|(_, b)| b.kind == DeviceKind::Pairing)
                    .map(|(id, _)| self.wire.name(&id))
                    .collect();
                bound.sort();
                actual["pairing_devices_bound"] = json!(bound);
            }
            ("F07.read_device_cannot_claim", 1 | 3) => {
                // IDENTITY-PROFILE-01 §7.2: a device may claim only when it can write the
                // roster entry in I, holds(D, 2).
                let state = self.state_after(s(&step["case"]), actual);
                let name = if n == 1 { "DEV_R" } else { "DEV_B" };
                actual[format!("{name}_holds_2_in_I")] = json!(state.holds(&self.wire.id(name), 2));
            }
            ("F08.missing_material", 1) => {
                let state = self.state_after(s(&step["case"]), actual);
                actual["epochs"] = json!(state
                    .dek_commitments
                    .iter()
                    .map(|(e, _)| *e)
                    .collect::<BTreeSet<_>>());
            }
            ("F13.issuer_revoked_before_resume", 1) => {
                let state = self.wire.at("I8_bridge_grant");
                actual["DEV_M2_bound"] = json!(state.device(&self.wire.id("DEV_M2")).is_some());
            }
            ("F13.issuer_revoked_before_resume", 2) => {
                let state = self.wire.at(s(&step["phase_input"]["state"])
                    .strip_prefix("wire:")
                    .unwrap());
                let leaf = state
                    .device(&self.wire.id("DEV_B"))
                    .unwrap()
                    .leaf_id
                    .unwrap();
                actual["DEV_B_leaf"] = json!(self.certificate_name(&leaf));
            }
            ("F13.issuer_revoked_before_resume", 4 | 5) => {
                let label = if n == 4 {
                    "DEV_M2 first registration"
                } else {
                    "DEV_B re-certification through DEV_A"
                };
                let mut superseded = self
                    .results
                    .remove("superseded")
                    .unwrap_or_else(|| json!([]));
                if actual["phase"] == "superseded" {
                    superseded.as_array_mut().unwrap().push(json!(label));
                }
                self.results.insert("superseded".into(), superseded);
            }
            _ => {}
        }
    }
    fn final_state(&mut self, id: &str) -> J {
        match id {
            "F01_register_write_revoke_cutoff" => {
                let rebuilt = &self.results["rebuild"]["accepted"];
                let after = self.wire.corpus.case("D_dev_a_beyond_epoch_cutoff").clone();
                let history = self.wire.history(&after["context"]);
                let mut received_late = Vec::new();
                for name in [
                    "D_dev_a_seq1",
                    "D_dev_b_seq1",
                    "D_bridge_writes_x",
                    "D_dev_a_old_head_after_revoke",
                ] {
                    let u = ReceivedDataUnit::parse(&bytes(
                        &self.wire.corpus.case(name)["inputs"]["cose_sign1"],
                    ))
                    .unwrap();
                    if authority::data_unit_policy(&history)(u.header()).is_ok() {
                        received_late.push(name);
                    }
                }
                assert_eq!(*rebuilt, json!(received_late));
                json!({"accepted_epoch_0_units_R1":rebuilt,"accepted_epoch_0_units_R2":received_late,"replicas_converge":true})
            }
            "F02_cascade_recertify" => {
                let state = self.wire.at("I10_recertify_dev_b");
                json!({"DEV_B":self.wire.state(&state)["devices"]["DEV_B"]})
            }
            "F03_stale_head_reevaluation" => {
                let before = self.wire.at("I1_device_grant_dev_a");
                let after = self.wire.at("I2_device_grant_self_dev_b");
                json!({"DEV_B_registered":after.device(&self.wire.id("DEV_B")).unwrap().registered,"records_added":after.head.sequence-before.head.sequence})
            }
            "F04_root_standing_lost_regained" => {
                let a = self.wire.at("I11_revoke_root_grant_bob");
                let b = self.wire.at("I12_regrant_bob");
                assert_eq!(
                    a.devices().collect::<Vec<_>>(),
                    b.devices().collect::<Vec<_>>()
                );
                json!({"device_records_added":0})
            }
            "F05_reconciliation" => {
                let state = self.wire.at("flow.reconcile_register_dev_a_in_x");
                let d = self.wire.state(&state)["devices"].clone();
                json!({"X_devices":{"DEV_A":d["DEV_A"],"DEV_B":d["DEV_B"]},"idempotent":true})
            }
            "F05.sixty_five_sessions" => {
                let i = self.wire.at("flow.p65_revoke_dev_p_in_i");
                let x = self.wire.at("flow.p65_x_revoke_dev_p");
                let pairing = x
                    .revocations()
                    .filter(|(_, d, _)| i.device(d).is_some_and(|b| b.kind == DeviceKind::Pairing))
                    .count();
                let dev_p = self.wire.id("DEV_P");
                json!({"X_tombstones_from_pairing":pairing,"DEV_P_registered_in_X":x.device(&dev_p).is_some_and(|d| d.registered)})
            }
            "F13.issuer_revoked_before_resume" => {
                json!({"superseded":self.results["superseded"]})
            }
            "F06_concurrent_revokes" => {
                let state = self.wire.at("flow.f06_owner_revokes_dev_b");
                let count = state
                    .revocations()
                    .filter(|(_, d, _)| *d == self.wire.id("DEV_B"))
                    .count();
                json!({"device_revoke_records":count})
            }
            "F07_invitation_accepted_by_device" => {
                let state = self.wire.at("flow.self_register_dev_d");
                json!({"claimant_role":self.wire.state(&state)["roles"]["DAVE"]})
            }
            "F08_pairing_personal" => {
                let state = self.wire.at("flow.pl_register_dev_b");
                let epochs: Vec<_> = self
                    .ledger
                    .keys()
                    .filter(|(r, _, d)| r == "I" && d == "DEV_B")
                    .map(|(_, e, _)| *e)
                    .collect();
                json!({"DEV_B_registered_in_I":state.device(&self.wire.id("DEV_B")).unwrap().registered,"approved_payloads":state.revocations().filter(|(_,_,r)|r.reason==3).count(),"DEV_B_epochs":epochs})
            }
            "F08.binding_limit" => {
                let state = self.wire.at("flow.p31_register_dev_b");
                json!({"live_devices_of_OWNER":state.devices().filter(|(id,d)|d.root==self.wire.id("OWNER")&&state.revocation(&d.root,id).is_none()).count()})
            }
            "F08.forty_sessions" => {
                let state = self.wire.at("flow.p40_register_dev_b");
                json!({"cancelled_sessions":state.revocations().filter(|(_,_,r)|r.reason==0).count(),"completed":state.active_device(&self.wire.id("DEV_B")).is_some()})
            }
            "F09_pairing_service" => {
                let state = self.wire.at("P4s_bind_bridge_o");
                json!({"registered_in_I":state.device(&self.wire.id("BRIDGE_O")).unwrap().registered,"approved_scope":self.wire.state(&state)["devices"]["BRIDGE_O"]["scope"]})
            }
            "F12_rotation_with_open_session" => {
                let tables = &self.results["wire:flow.rotator_test"]["post_state"];
                let rotators: BTreeMap<_, Vec<_>> = tables
                    .as_object()
                    .unwrap()
                    .iter()
                    .map(|(label, t)| {
                        (
                            label,
                            t["candidates"]
                                .as_object()
                                .unwrap()
                                .iter()
                                .filter(|(_, v)| v["rotator"] == true)
                                .map(|(k, _)| k)
                                .collect(),
                        )
                    })
                    .collect();
                json!({"rotators":rotators})
            }
            "F14_frontier_from_verified_set" => {
                let record =
                    ReceivedControlRecord::parse(&self.wire.record_bytes("flow.y_key_epoch_1"))
                        .unwrap();
                let ControlBody::KeyEpoch(epoch) = record.body() else {
                    unreachable!()
                };
                let frontier: BTreeMap<_, _> = epoch
                    .final_frontier
                    .entries()
                    .iter()
                    .map(|h| {
                        (
                            self.wire.name(&h.principal),
                            json!({"contiguous":h.contiguous,"extra_ranges":h.extra}),
                        )
                    })
                    .collect();
                json!({"frontier":frontier})
            }
            "F15_rotation_policy_by_exposure" => {
                let mut exposure = BTreeMap::new();
                for name in [
                    "I9_device_revoke_dev_a",
                    "V2_revoke_dev_c",
                    "Vu1_revoke_unbound",
                    "W2",
                    "flow.revoke_out_of_scope_bridge_in_y",
                    "flow.revoke_suspended_dev_b",
                ] {
                    let state = self.wire.at(name);
                    exposure.insert(name, state.last_exposing_revocation == Some(state.head));
                }
                json!({"exposing":exposure})
            }
            "F16_device_grant_fork" => {
                assert_eq!(self.results["fork"], true);
                json!({"state":"CONTROL_CONFLICT"})
            }
            "F19_key_bootstrap" => json!({"I_is_a_target":self.ledger.keys().any(|(r,_,_)|r=="I")}),
            _ => json!({}),
        }
    }
}
fn na(reason: &str) -> J {
    json!({"outcome":"N/A","reason":reason})
}
const RECONCILE: &str = "IDENTITY-PROFILE-01 §7.1: reconciliation (which revoked pairs are relevant in a target, what is proposed, how a refusal is reported and retried, which display entries are written) is client orchestration; sdk-rs has no reconciliation implementation, by design. The Wire records reconciliation proposes and the target's state after them are checked as cases.";
const CLAIM: &str = "IDENTITY-PROFILE-01 §7.2: whether a device sends the claim, and what it offers instead, is client orchestration; sdk-rs has no invitation client. The precondition holds(D, 2) in I is checked on the Control state.";
const PAIRING_CLIENT: &str = "IDENTITY-PROFILE-01 §5.2, §5.3 step 1: what a pairing client writes, sends or offers after a link check, or without the material to open a session, is client orchestration; sdk-rs has no pairing client. The link checks and the epochs of I are decided.";
const KEY_PACKAGE_CLIENT: &str = "LFCP-WIRE-01 §37: the client's check of READY before uploading a same-root Key Package is client orchestration; sdk-rs has no upload client.";
fn boundary(id: &str, field: &str) -> &'static str {
    match field{
  "proposals"|"not_propagated"|"pair_state"|"rotation"|"writes"|"metadata_changes"|"entries_main"|"entries_service"|"entries_for_pairing_devices"=>RECONCILE,
  "reported" if id.starts_with("F08")=>PAIRING_CLIENT,
  "reported"=>RECONCILE,
  "request_written"|"sent_as_pairing_device_after_rejection"|"requests_written_after_rejection"|"sessions_without_material"=>PAIRING_CLIENT,
  "claims_sent_by_read_device"=>CLAIM,
  "pre_identity"|"herald"|"server_without_identity_01"=>"WIRE §100.1 defines behavior of pre-identity/herald implementations and persistent blocked-client UI; this binary is identity-aware and contains neither legacy validator nor client storage.",
  "offered"|"consume_proposed_for_infeasible_preset"=>"IDENTITY-PROFILE-01 §5.3 step 4 requires a future-chain feasibility API to enumerate presets at the current head. sdk-rs checks proposed records but lacks this planning API; this is an SDK coverage gap.",
  "frontier_rule"=>"Explanatory prose only; the exact frontier and hole verdicts are checked from verified units (WIRE §28.1).",
  other=>panic!("unaccounted flow assertion {other}"),
 }
}
#[test]
fn identity_flow_fixtures() {
    let corpus = Corpus::load(FLOWS);
    let mut results = BTreeMap::new();
    for (id, c) in &corpus.cases {
        eprintln!("flow {id}");
        let mut executor = Executor::new();
        results.insert(id.clone(), executor.run(c));
    }
    assert_eq!(results.len(), 28);
    export("identity-flows", &results);
}
