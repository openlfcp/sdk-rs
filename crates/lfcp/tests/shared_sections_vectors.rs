//! SHARED-SECTIONS-TEST-VECTORS-01 through the Shared Sections schema
//! (LFCP-02-019): profile dispatch, actor IDs with the profile's domain,
//! and, for every case's reference save image, the root rules, the typed
//! view of the section, nodes and placements, Text versus scalar fields,
//! readiness and the per-node problems of SHARED-SECTIONS-PROFILE-01 §14.2.
//!
//! The corpus is read at the spec-sections.lock pin. Only the profile, its
//! Markdown grammar and the JSON corpus are sources; the corpus generator
//! is not (independence rule).

#![cfg(feature = "shared-sections")]

mod support;

use std::collections::BTreeMap;

use automerge::Change;
use lfcp::base::{self, PrincipalId, ResourceId};
use lfcp::shared_sections::{self, DataProfile, NodeKind, SectionsDoc};
use serde_json::Value as Json;
use support::spec::Spec;

const CORPUS: &str = "test-vectors/shared-sections-01/SHARED-SECTIONS-TEST-VECTORS-01.json";

fn corpus() -> Json {
    Spec::open_sections().read_json(CORPUS)
}

/// Standard base64 with padding, as the corpus stores bytes.
fn base64(text: &str) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0);
    for c in text.bytes().filter(|&c| c != b'=') {
        let v = ALPHABET.iter().position(|&a| a == c).expect("base64 digit") as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

fn bytes_of(record: &Json) -> Vec<u8> {
    let bytes = base64(record["base64"].as_str().unwrap());
    assert_eq!(bytes.len() as u64, record["length"].as_u64().unwrap());
    assert_eq!(
        base::to_hex(lfcp::crypto::sha256(&bytes).as_bytes()),
        record["sha256"].as_str().unwrap()
    );
    bytes
}

#[test]
fn profiles_dispatch_from_genesis() {
    assert_eq!(
        DataProfile::of("org.openlfcp.shared-sections.v1"),
        DataProfile::SharedSections
    );
    assert_eq!(
        DataProfile::of("org.openlfcp.shared-objects.v1"),
        DataProfile::SharedObjects
    );
    assert_eq!(
        DataProfile::of("org.example.unknown.v1"),
        DataProfile::Unsupported("org.example.unknown.v1".into())
    );
}

#[test]
fn actors_use_the_sections_domain() {
    let corpus = corpus();
    let ids = &corpus["identities"];
    let resource = ResourceId::from_bytes(
        base::fixed(&base::from_hex(ids["resource_hex"].as_str().unwrap()).unwrap()).unwrap(),
    );
    let mut actors = BTreeMap::new();
    for (name, a) in ids["actors"].as_object().unwrap() {
        let principal = PrincipalId::from_bytes(
            base::fixed(&base::from_hex(a["principal_hex"].as_str().unwrap()).unwrap()).unwrap(),
        );
        let actor = shared_sections::actor_id_bytes(&resource, &principal);
        assert_eq!(
            base::to_hex(&actor),
            a["actor_hex"].as_str().unwrap(),
            "actor {name}"
        );
        // A different actor from the same Principal's Shared Objects one.
        assert_ne!(
            actor,
            lfcp::shared_objects::identity::actor_id_bytes(&resource, &principal),
            "actor {name}: domains differ"
        );
        actors.insert(name.clone(), base::to_hex(&actor));
    }
    // Every recorded change is a change of the actor its branch names.
    for case in corpus["cases"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        for (branch, name) in [("A", "A"), ("B", "B")] {
            for record in case["branches"][branch].as_array().unwrap() {
                let change = Change::from_bytes(bytes_of(record)).unwrap();
                assert_eq!(
                    change.actor_id().to_hex_string(),
                    actors[name],
                    "{id}: branch {branch}"
                );
                assert_eq!(
                    change.hash().to_string(),
                    record["change_hash"].as_str().unwrap(),
                    "{id}"
                );
            }
        }
        for record in case["after_merge"].as_array().unwrap() {
            let change = Change::from_bytes(bytes_of(record)).unwrap();
            assert_eq!(
                change.actor_id().to_hex_string(),
                actors["C"],
                "{id}: after merge"
            );
        }
    }
}

#[test]
fn reference_documents_read_through_the_schema() {
    let corpus = corpus();
    let cases = corpus["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 41);
    for case in cases {
        let id = case["id"].as_str().unwrap();
        let expected = &case["expected"];
        let doc = SectionsDoc::load(&bytes_of(&case["reference_snapshot"]))
            .unwrap_or_else(|e| panic!("{id}: load: {e}"));
        assert_eq!(doc.validate_root(), Ok(()), "{id}: root");
        let section = doc.section().unwrap();
        assert_eq!(
            section.ready,
            expected["classification"] != "IMPORTING",
            "{id}: ready"
        );
        let nodes = doc.nodes();
        assert_eq!(
            nodes.len() as u64,
            expected["nodeCount"].as_u64().unwrap(),
            "{id}: nodes"
        );
        assert_eq!(
            doc.placements().len() as u64,
            expected["slotCount"].as_u64().unwrap(),
            "{id}: placements"
        );
        // Text: paragraph, item and raw nodes, as the corpus normalizes them.
        for (node, text) in expected["texts"].as_object().unwrap() {
            assert_eq!(
                nodes[node].text.as_deref(),
                Some(text.as_str().unwrap()),
                "{id}: text of {node}"
            );
            assert_ne!(
                nodes[node].kind,
                Some(NodeKind::Task),
                "{id}: {node} has Text"
            );
        }
        for (task, fields) in expected["tasks"].as_object().unwrap() {
            assert_eq!(
                doc.task_title(task).as_deref(),
                fields["title"].as_str(),
                "{id}: title of {task}"
            );
            assert!(
                doc.task_fields_are_scalar(task),
                "{id}: {task} scalar fields"
            );
        }
        // §14.2: per-node problems, as the corpus lists them.
        let problems: BTreeMap<String, String> = doc
            .node_problems()
            .into_iter()
            .map(|(n, d)| (n, d.name().to_owned()))
            .collect();
        let want: BTreeMap<String, String> = expected["invalid"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| {
                (
                    x["id"].as_str().unwrap().to_owned(),
                    x["diagnostic"].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        assert_eq!(problems, want, "{id}: invalid nodes");
    }
}

#[test]
fn a_document_of_another_profile_has_an_invalid_root() {
    // A Shared Objects save image is profile-invalid as a section, not an
    // unsupported profile: dispatch happens on the Genesis profile first.
    let mut doc =
        lfcp::shared_objects::document::SharedObjects::new(automerge::ActorId::from([1u8; 32]));
    doc.initialize().unwrap();
    let sections = SectionsDoc::load(&doc.save()).unwrap();
    assert_eq!(
        sections.validate_root(),
        Err(shared_sections::Diagnostic::InvalidRoot)
    );
}

#[test]
fn the_effective_tree_matches_every_case() {
    // §7, §9, §14.3: tree in scan order, hidden nodes and structural facts.
    let corpus = corpus();
    for case in corpus["cases"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        let expected = &case["expected"];
        let doc = SectionsDoc::load(&bytes_of(&case["reference_snapshot"])).unwrap();
        let effective = doc.effective();
        let kind = |k: Option<NodeKind>| match k {
            Some(NodeKind::Task) => "task",
            Some(NodeKind::Paragraph) => "paragraph",
            Some(NodeKind::Item) => "item",
            Some(NodeKind::Raw) => "raw",
            None => "?",
        };
        let tree: Vec<(String, String, u64, String)> = effective
            .tree
            .iter()
            .map(|t| {
                (
                    t.id.clone(),
                    t.parent.clone(),
                    t.depth as u64,
                    kind(t.kind).to_owned(),
                )
            })
            .collect();
        let want: Vec<(String, String, u64, String)> = expected["tree"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| {
                (
                    t["id"].as_str().unwrap().to_owned(),
                    t["parent"].as_str().unwrap().to_owned(),
                    t["depth"].as_u64().unwrap(),
                    t["kind"].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        assert_eq!(tree, want, "{id}: tree");
        let hidden: Vec<&str> = effective.hidden.iter().map(String::as_str).collect();
        let want_hidden: Vec<&str> = expected["hidden"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| h.as_str().unwrap())
            .collect();
        assert_eq!(hidden, want_hidden, "{id}: hidden");
        let recovery: Vec<(String, &str)> = effective
            .recovery
            .iter()
            .map(|(n, f)| (n.clone(), f.name()))
            .collect();
        let want_recovery: Vec<(String, &str)> = expected["recovery"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                (
                    r["id"].as_str().unwrap().to_owned(),
                    r["code"].as_str().unwrap(),
                )
            })
            .collect();
        assert_eq!(recovery, want_recovery, "{id}: recovery");
    }
}
