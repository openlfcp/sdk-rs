#![allow(dead_code)]
use super::identity_corpus::*;
use automerge::Change;
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
            .with_missing_keys_check(false)
            .unwrap()
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
                    refused("PROFILE_INVALID", Some(d.name()))
                } else {
                    let entries = view.entries(s(&i["container"])).unwrap();
                    assert!(entries.contains_key(s(&i["key"])));
                    accepted(vec![], plain(&entries[s(&i["key"])]))
                }
            }
            "pair_uri" => {
                if c["type"] == "bytes" {
                    let ed: [u8; 32] = bytes(&i["ed25519_seed"]).try_into().unwrap();
                    let x: [u8; 32] = bytes(&i["x25519_private"]).try_into().unwrap();
                    let resource = ResourceId::from_slice(&bytes(&i["identity_resource"])).unwrap();
                    let link = PairingLink::new(resource, vec![s(&i["endpoint"]).into()], &ed, &x)
                        .unwrap();
                    assert_eq!(&*link.encode(), s(&e["uri"]), "{id}");
                    let decoded = PairingLink::parse(s(&e["uri"])).unwrap();
                    assert_eq!(
                        decoded.device.to_hex(),
                        s(&e["recomputed_principal_id"]["hex"])
                    );
                    assert_eq!(decoded.identity, resource);
                    assert!(!format!("{decoded:?}").contains("secret="));
                    accepted(vec![decoded.device.to_hex()], J::Null)
                } else if i["parser"] == "join" {
                    // The SDK has no invitation-URI codec (README scope). Verify the common
                    // disjoint dispatch prefix mandated by W §18.2 before that absent codec.
                    assert!(!s(&i["uri"]).starts_with("lfcp://join/"));
                    refused("PAIRING_LINK_REJECTED", None)
                } else {
                    assert!(PairingLink::parse(s(&i["uri"])).is_err(), "{id}");
                    refused("PAIRING_LINK_REJECTED", None)
                }
            }
            "device_fingerprint" => {
                let id = PrincipalId::from_slice(&bytes(&i["principal_id"])).unwrap();
                let fp = fingerprint(&id);
                assert_eq!(fp, e["fingerprint"]);
                accepted(vec![], json!({"fingerprint":fp}))
            }
            "approval_digest" => {
                let cert =
                    lfcp::wire::control::device::DeviceCertificate::parse(&bytes(&i["cose_sign1"]))
                        .unwrap();
                assert_eq!(
                    cert.payload_digest().to_hex(),
                    s(&e["payload_digest"]["hex"])
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
    fn document(&self, c: &J) -> J {
        let i = &c["inputs"];
        let e = &c["expected"];
        let id = s(&c["id"]);
        match id {
            "identity_doc_second_initial_other_unit" => {
                let mut results = BTreeMap::new();
                for (name, order) in i["orders"].as_object().unwrap() {
                    let mut r = self.replica();
                    for name in order
                        .as_array()
                        .unwrap_or_else(|| order["order"].as_array().unwrap())
                    {
                        self.deliver(&mut r, s(name));
                    }
                    let names = |hashes: Vec<automerge::ChangeHash>| -> Vec<String> {
                        hashes
                            .iter()
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
                    };
                    let refused: BTreeMap<_, _> = r
                        .refused()
                        .iter()
                        .map(|(h, d)| (names(vec![*h])[0].clone(), d.name()))
                        .collect();
                    let actual = json!({"initial_change":names(r.accepted())[0],"refused":refused,"held":names(r.held()),"pending":names(r.waiting())});
                    assert_eq!(actual, e["by_order"][name], "{id}/{name}");
                    results.insert(name, actual);
                }
                let snapshot = bytes(&i["snapshot"]);
                let mut r = self.replica();
                assert!(!r
                    .receive_snapshot(&framing::encode_snapshot(&snapshot), &[])
                    .unwrap());
                assert!(r
                    .receive_snapshot(
                        &framing::encode_snapshot(&snapshot),
                        &self.snapshot_witnesses(&snapshot)
                    )
                    .unwrap());
                accepted(
                    r.accepted().iter().map(ToString::to_string).collect(),
                    json!(results),
                )
            }
            "identity_doc_initial_without_unit_1" => {
                let mut r = self.replica();
                let witness = self.unit(self.change_case("C0_initial"));
                assert!(!r
                    .receive_snapshot(
                        &framing::encode_snapshot(&bytes(&i["snapshot"])),
                        &[witness]
                    )
                    .unwrap());
                assert!(r.accepted().is_empty());
                self.deliver(&mut r, "C0_initial");
                accepted(
                    r.accepted().iter().map(ToString::to_string).collect(),
                    json!({"snapshot_used":false}),
                )
            }
            "identity_doc_initial_then_fill" | "identity_snapshot_equivalence" => {
                let snapshot = bytes(&i["snapshot"]);
                let witnesses = self.snapshot_witnesses(&snapshot);
                let mut final_ids = Vec::new();
                for units in [witnesses.clone(), witnesses.iter().cloned().rev().collect()] {
                    let mut r = self.replica();
                    for (u, p) in units {
                        r.receive(u, &p);
                    }
                    assert_eq!(plain(&r.view().plain().unwrap()), e["state"], "{id}");
                    r.view().validate_root().unwrap();
                    final_ids = r.accepted().iter().map(ToString::to_string).collect();
                }
                let mut r = self.replica();
                assert!(r
                    .receive_snapshot(&framing::encode_snapshot(&snapshot), &witnesses)
                    .unwrap());
                assert_eq!(plain(&r.view().plain().unwrap()), e["state"]);
                accepted(final_ids, plain(&r.view().plain().unwrap()))
            }
            "pairing_concurrent_same_key" => {
                let mut r = self.replica();
                for reference in i["history"].as_array().unwrap() {
                    self.deliver(&mut r, s(&reference["case"]));
                }
                for reference in i["changes"].as_array().unwrap() {
                    assert_eq!(
                        self.deliver(&mut r, s(&reference["case"])),
                        Received::Applied
                    );
                }
                assert_eq!(
                    r.view()
                        .entry_diagnostic("requests", s(&e["entry"]))
                        .unwrap()
                        .name(),
                    s(&e["entry_diagnostic"])
                );
                accepted(
                    r.accepted().iter().map(ToString::to_string).collect(),
                    json!({"entry_valid":false,"entry_diagnostic":"INVALID_FIELD_TYPE"}),
                )
            }
            "device_entry_missing_keys_union" => {
                let snapshot = bytes(&i["snapshot"]);
                let view = IdentityDoc::inspect(&snapshot, self.owner).unwrap();
                let key = s(&self.corpus.data["fixtures"]["refs"]["DEV_B"]);
                let union = view.missing_keys(key).unwrap();
                assert_eq!(json!(union), e["missing_keys_read"]);
                let witnesses = self.snapshot_witnesses(&snapshot);
                let mut r = self.replica();
                assert!(r
                    .receive_snapshot(&framing::encode_snapshot(&snapshot), &witnesses)
                    .unwrap());
                assert_eq!(
                    json!(r.view().missing_keys(key).unwrap()),
                    e["missing_keys_read"]
                );
                accepted(
                    r.accepted().iter().map(ToString::to_string).collect(),
                    json!({"missing_keys_read":union}),
                )
            }
            _ => panic!("wire-dependent profile behavior: {id}"),
        }
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
