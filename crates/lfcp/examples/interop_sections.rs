//! The Rust side of the cross-language shared sections exchange
//! (LFCP-02-023, LFCP-02-024).
//!
//! ```text
//! cargo run --example interop_sections --features shared-sections -- produce <dir>
//! cargo run --example interop_sections --features shared-sections -- consume <dir>
//! ```
//!
//! `produce` writes `<dir>/sections.json` (`lfcp-interop-sections/1`):
//! scenarios of SHARED-SECTIONS-TEST-VECTORS-01 written with this SDK's
//! authoring API, each a list of changes in their application plaintext
//! framing with the Principal that signs each, and the summary this SDK
//! derives from them after admission. `consume` replays every scenario
//! through its own section admission, in order and in reverse with
//! duplicates, and writes `<dir>/sections-results-rust.json`: one PASS/FAIL
//! per scenario, PASS when its summary equals the producer's. Changes are
//! compared by what they mean (tree, facts, diagnostics, refusals, texts),
//! never by their bytes. The format and the check IDs are shared with the
//! TypeScript adapter in openlfcp/examples (conformance/).

use std::collections::BTreeMap;
use std::path::Path;

use automerge::transaction::Transactable;
use automerge::{ActorId, AutoCommit, Change, ObjType, ReadDoc, Value, ROOT};
use lfcp::base::{PrincipalId, ResourceId};
use lfcp::shared_objects::framing;
use lfcp::shared_sections::{self, NewNode, NodeKind, SectionsDoc, SectionsReplica};
use serde_json::{json, Value as Json};

const FORMAT: &str = "lfcp-interop-sections/1";
const SECTION: &str = "019a2f85-7b31-7c42-8000-000000000001";

fn random<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).expect("OS randomness");
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

/// A canonical UUIDv7 for object `n` of kind `k` in scenario `s`.
fn uuid(s: u16, k: u16, n: u32) -> String {
    format!("019a2f85-{s:04x}-7c42-{:04x}-{n:012x}", 0x8000 | k)
}

/// One scenario being written: its changes, each with its signer's name.
struct Scenario {
    id: &'static str,
    description: &'static str,
    resource: ResourceId,
    principals: BTreeMap<&'static str, PrincipalId>,
    changes: Vec<(&'static str, Change)>,
}

impl Scenario {
    fn new(id: &'static str, description: &'static str) -> Scenario {
        let principals = ["A", "B"]
            .into_iter()
            .map(|n| (n, PrincipalId::from_bytes(random())))
            .collect();
        Scenario {
            id,
            description,
            resource: ResourceId::from_bytes(random()),
            principals,
            changes: vec![],
        }
    }

    fn p(&self, name: &str) -> PrincipalId {
        self.principals[name]
    }

    fn actor(&self, name: &str) -> ActorId {
        shared_sections::actor_id(&self.resource, &self.p(name))
    }

    /// A's section with Task T (paragraph P under it) and items X, Y after it.
    fn seeded(&mut self, s: u16) -> SectionsDoc {
        let a = self.p("A");
        let (mut doc, first) =
            SectionsDoc::create(self.actor("A"), SECTION, "Joint launch", &a).unwrap();
        self.changes.push(("A", first));
        let t = uuid(s, 1, 1);
        let mut add =
            |doc: &mut SectionsDoc, id: String, node, parent: &str, after: Option<&str>, slot| {
                let c = doc
                    .create_node(&id, node, parent, after, &uuid(s, 9, slot), &a)
                    .unwrap();
                self.changes.push(("A", c));
            };
        add(
            &mut doc,
            t.clone(),
            NewNode::Task {
                title: "Prepare contract",
            },
            SECTION,
            None,
            1,
        );
        add(
            &mut doc,
            uuid(s, 2, 1),
            NewNode::Paragraph {
                text: "Draft contract",
            },
            &t,
            None,
            2,
        );
        add(
            &mut doc,
            uuid(s, 3, 1),
            NewNode::Item { text: "Group X" },
            SECTION,
            Some(&t),
            3,
        );
        add(
            &mut doc,
            uuid(s, 3, 2),
            NewNode::Item { text: "Group Y" },
            SECTION,
            Some(&uuid(s, 3, 1)),
            4,
        );
        doc
    }

    /// B's replica of `doc`, writing as B.
    fn fork_b(&self, doc: &mut SectionsDoc) -> SectionsDoc {
        SectionsDoc::load_as(&doc.save(), self.actor("B")).unwrap()
    }

    fn push(&mut self, signer: &'static str, change: Change) {
        self.changes.push((signer, change));
    }

    fn to_json(&self) -> Json {
        let replica = replay(
            self.resource,
            &self.principals,
            self.changes
                .iter()
                .map(|(s, c)| (*s, framing::encode_change(c.raw_bytes()))),
        );
        json!({
            "id": self.id,
            "description": self.description,
            "resource_id": hex(self.resource.as_bytes()),
            "principals": self.principals.iter().map(|(n, p)| (n.to_string(), json!(hex(p.as_bytes())))).collect::<serde_json::Map<_, _>>(),
            "changes": self.changes.iter().map(|(s, c)| json!({
                "signer": s,
                "framed_plaintext": hex(&framing::encode_change(c.raw_bytes())),
            })).collect::<Vec<_>>(),
            "expected": summary(&replica),
        })
    }
}

/// Every change through a fresh replica's admission, in the given order.
fn replay<'a>(
    resource: ResourceId,
    principals: &BTreeMap<&'a str, PrincipalId>,
    changes: impl IntoIterator<Item = (&'a str, Vec<u8>)>,
) -> SectionsReplica {
    let mut replica = SectionsReplica::new(resource, ActorId::from([7u8; 32]));
    for (signer, plaintext) in changes {
        replica.receive(&principals[signer], &plaintext);
    }
    replica
}

fn kind_name(kind: Option<NodeKind>) -> &'static str {
    match kind {
        Some(NodeKind::Task) => "task",
        Some(NodeKind::Paragraph) => "paragraph",
        Some(NodeKind::Item) => "item",
        Some(NodeKind::Raw) => "raw",
        None => "unknown",
    }
}

/// What a scenario means after admission, in a language-neutral form.
fn summary(replica: &SectionsReplica) -> Json {
    let mut doc = replica.view();
    let effective = doc.effective();
    let ready = doc.section().is_some_and(|s| s.ready);
    let classification = if doc.validate_root().is_err() {
        "PROFILE_INVALID"
    } else if !ready {
        "IMPORTING"
    } else if effective.recovery.is_empty()
        && effective.invalid.is_empty()
        && effective.collisions.is_empty()
    {
        "VALID"
    } else {
        "STRUCTURAL_ATTENTION"
    };
    let texts: BTreeMap<String, String> = doc
        .nodes()
        .into_iter()
        .filter_map(|(id, n)| n.text.map(|t| (id, t)))
        .collect();
    let titles: BTreeMap<String, String> = doc
        .task_ids()
        .into_iter()
        .filter_map(|id| doc.task_title(&id).map(|t| (id, t)))
        .collect();
    json!({
        "classification": classification,
        "tree": effective.tree.iter().map(|t| json!([t.id, t.parent, t.depth, kind_name(t.kind)])).collect::<Vec<_>>(),
        "hidden": effective.hidden,
        "recovery": effective.recovery.iter().map(|(n, f)| (n.clone(), json!(f.name()))).collect::<serde_json::Map<_, _>>(),
        "invalid": effective.invalid.iter().map(|(n, d)| (n.clone(), json!(d.name()))).collect::<serde_json::Map<_, _>>(),
        "collisions": effective.collisions,
        "refused": replica.refused().iter().map(|(h, r)| (h.to_string(), json!(r.name()))).collect::<serde_json::Map<_, _>>(),
        "waiting": replica.waiting().iter().map(|h| h.to_string()).collect::<Vec<_>>(),
        "retained_concurrent_edits": doc.retained_concurrent_edits(),
        "texts": texts,
        "titles": titles,
    })
}

// ---------------------------------------------------------------- produce

fn scenarios() -> Vec<Scenario> {
    let mut out = vec![];

    let mut s = Scenario::new(
        "basic",
        "A section with a Task, its paragraph and two items",
    );
    s.seeded(1);
    out.push(s);

    let mut s = Scenario::new(
        "concurrent_insert",
        "A and B insert a paragraph after the same Task",
    );
    let mut a = s.seeded(2);
    let mut b = s.fork_b(&mut a);
    let (pa, pb, t) = (s.p("A"), s.p("B"), uuid(2, 1, 1));
    let ca = a
        .create_node(
            &uuid(2, 2, 7),
            NewNode::Paragraph { text: "From A" },
            SECTION,
            Some(&t),
            &uuid(2, 9, 7),
            &pa,
        )
        .unwrap();
    let cb = b
        .create_node(
            &uuid(2, 2, 8),
            NewNode::Paragraph { text: "From B" },
            SECTION,
            Some(&t),
            &uuid(2, 9, 8),
            &pb,
        )
        .unwrap();
    s.push("A", ca);
    s.push("B", cb);
    out.push(s);

    let mut s = Scenario::new("placement_conflict", "A moves the Task under X, B under Y");
    let mut a = s.seeded(3);
    let mut b = s.fork_b(&mut a);
    let (pa, pb) = (s.p("A"), s.p("B"));
    let ca = a
        .move_node(&uuid(3, 1, 1), &uuid(3, 3, 1), None, &uuid(3, 9, 7), &pa)
        .unwrap();
    let cb = b
        .move_node(&uuid(3, 1, 1), &uuid(3, 3, 2), None, &uuid(3, 9, 8), &pb)
        .unwrap();
    s.push("A", ca);
    s.push("B", cb);
    out.push(s);

    let mut s = Scenario::new("parent_cycle", "A moves X under Y while B moves Y under X");
    let mut a = s.seeded(4);
    let mut b = s.fork_b(&mut a);
    let (pa, pb) = (s.p("A"), s.p("B"));
    let ca = a
        .move_node(&uuid(4, 3, 1), &uuid(4, 3, 2), None, &uuid(4, 9, 7), &pa)
        .unwrap();
    let cb = b
        .move_node(&uuid(4, 3, 2), &uuid(4, 3, 1), None, &uuid(4, 9, 8), &pb)
        .unwrap();
    s.push("A", ca);
    s.push("B", cb);
    out.push(s);

    let mut s = Scenario::new(
        "delete_vs_edit",
        "A deletes the Task while B edits its paragraph",
    );
    let mut a = s.seeded(5);
    let mut b = s.fork_b(&mut a);
    let base = b.heads();
    let ca = a.delete_node(&uuid(5, 1, 1)).unwrap();
    let cb = b
        .text_edit(&uuid(5, 2, 1), &base, 0, 0, "Retained ")
        .unwrap();
    s.push("A", ca);
    s.push("B", cb);
    out.push(s);

    let mut s = Scenario::new("split_join", "A splits the paragraph, then joins the items");
    let mut a = s.seeded(6);
    let pa = s.p("A");
    let c1 = a
        .split(&uuid(6, 2, 1), 6, &uuid(6, 2, 2), &uuid(6, 9, 7), &pa)
        .unwrap();
    let c2 = a.join(&uuid(6, 3, 1), &uuid(6, 3, 2), "\n").unwrap();
    s.push("A", c1);
    s.push("A", c2);
    out.push(s);

    let mut s = Scenario::new(
        "text_unicode",
        "Concurrent edits around an emoji and Cyrillic text",
    );
    let mut a = s.seeded(7);
    let base = a.heads();
    let p = uuid(7, 2, 1);
    let c0 = a.text_edit(&p, &base, 0, 14, "А😀Б").unwrap();
    s.push("A", c0);
    let mut b = s.fork_b(&mut a);
    let base = a.heads();
    let ca = a.text_edit(&p, &base, 2, 0, "!").unwrap();
    let cb = b.text_edit(&p, &base, 0, 0, "Я: ").unwrap();
    s.push("A", ca);
    s.push("B", cb);
    out.push(s);

    let mut s = Scenario::new(
        "refused_children_mutated",
        "A change removes an entry of the section's children list",
    );
    let mut a = s.seeded(8);
    let mut raw = AutoCommit::load(&a.save())
        .unwrap()
        .with_actor(s.actor("A"));
    let section = match raw.get(&ROOT, "section").unwrap() {
        Some((Value::Object(ObjType::Map), id)) => id,
        other => panic!("section: {other:?}"),
    };
    let children = match raw.get(&section, "children").unwrap() {
        Some((Value::Object(ObjType::List), id)) => id,
        other => panic!("children: {other:?}"),
    };
    raw.delete(&children, 0).unwrap();
    raw.commit();
    let change = raw.get_last_local_change().unwrap().clone();
    s.push("A", change);
    // A's next change depends on the refused one: held behind it.
    let mut after = raw.fork().with_actor(s.actor("A"));
    after.put(&section, "title", "Held").unwrap();
    after.commit();
    let held = after.get_last_local_change().unwrap().clone();
    s.push("A", held);
    out.push(s);

    let mut s = Scenario::new(
        "refused_actor_mismatch",
        "A's change in a Data Unit signed by B",
    );
    let mut a = s.seeded(9);
    let c = a.set_title("Signed by another").unwrap();
    s.push("B", c);
    out.push(s);

    let mut s = Scenario::new("id_collision", "A and B create the same node ID");
    let mut a = s.seeded(10);
    let mut b = s.fork_b(&mut a);
    let (pa, pb, y) = (s.p("A"), s.p("B"), uuid(10, 3, 2));
    let id = uuid(10, 2, 9);
    let ca = a
        .create_node(
            &id,
            NewNode::Paragraph { text: "From A" },
            SECTION,
            Some(&y),
            &uuid(10, 9, 7),
            &pa,
        )
        .unwrap();
    let cb = b
        .create_node(
            &id,
            NewNode::Item { text: "From B" },
            SECTION,
            Some(&y),
            &uuid(10, 9, 8),
            &pb,
        )
        .unwrap();
    s.push("A", ca);
    s.push("B", cb);
    out.push(s);

    out
}

fn produce(dir: &Path) {
    let bundle = json!({
        "format": FORMAT,
        "producer": "rust",
        "scenarios": scenarios().iter().map(Scenario::to_json).collect::<Vec<_>>(),
    });
    std::fs::write(
        dir.join("sections.json"),
        serde_json::to_vec_pretty(&bundle).unwrap(),
    )
    .unwrap();
}

// ---------------------------------------------------------------- consume

fn consume(dir: &Path) {
    let path = dir.join("sections.json");
    let mut checks = vec![];
    // A producer without shared sections writes no scenarios: no checks.
    if let Ok(bytes) = std::fs::read(&path) {
        let bundle: Json = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(bundle["format"], FORMAT, "sections bundle format");
        for s in bundle["scenarios"].as_array().unwrap() {
            let id = s["id"].as_str().unwrap();
            let outcome = check(s);
            checks.push(json!({
                "id": format!("sections.{id}"),
                "category": "shared_sections",
                "result": if outcome.is_ok() { "PASS" } else { "FAIL" },
                "detail": outcome.err().unwrap_or_default(),
            }));
        }
    }
    std::fs::write(
        dir.join("sections-results-rust.json"),
        serde_json::to_vec_pretty(&json!({ "consumer": "rust", "checks": checks })).unwrap(),
    )
    .unwrap();
}

/// The scenario's summary, replayed in order and in reverse with duplicates,
/// against the producer's.
fn check(s: &Json) -> Result<(), String> {
    let resource = ResourceId::from_bytes(
        unhex(s["resource_id"].as_str().unwrap())
            .try_into()
            .unwrap(),
    );
    let names: Vec<String> = s["principals"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    let principals: BTreeMap<&str, PrincipalId> = names
        .iter()
        .map(|n| {
            let bytes = unhex(s["principals"][n].as_str().unwrap());
            (
                n.as_str(),
                PrincipalId::from_bytes(bytes.try_into().unwrap()),
            )
        })
        .collect();
    let changes: Vec<(&str, Vec<u8>)> = s["changes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            let signer = names
                .iter()
                .find(|n| *n == c["signer"].as_str().unwrap())
                .unwrap();
            (
                signer.as_str(),
                unhex(c["framed_plaintext"].as_str().unwrap()),
            )
        })
        .collect();
    let want = &s["expected"];
    let forward = summary(&replay(resource, &principals, changes.clone()));
    if &forward != want {
        return Err(format!("in order: {}", difference(want, &forward)));
    }
    let backward = changes.iter().rev().flat_map(|c| [c.clone(), c.clone()]);
    let reverse = summary(&replay(resource, &principals, backward));
    if &reverse != want {
        return Err(format!(
            "reversed with duplicates: {}",
            difference(want, &reverse)
        ));
    }
    Ok(())
}

/// The first summary field that differs, for the report.
fn difference(want: &Json, got: &Json) -> String {
    for (key, value) in want.as_object().unwrap() {
        if got.get(key) != Some(value) {
            return format!(
                "{key}: expected {value}, got {}",
                got.get(key).unwrap_or(&Json::Null)
            );
        }
    }
    "an extra field".into()
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [command, dir] if command == "produce" => produce(Path::new(dir)),
        [command, dir] if command == "consume" => consume(Path::new(dir)),
        _ => {
            eprintln!("usage: interop_sections (produce|consume) <dir>");
            std::process::exit(2);
        }
    }
}
