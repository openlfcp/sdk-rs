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

/// A scenario of a bundle, decoded.
struct Parsed {
    resource: ResourceId,
    principals: BTreeMap<String, PrincipalId>,
    /// (signer, framed plaintext), in the producer's (causal) order.
    changes: Vec<(String, Vec<u8>)>,
    /// Explicit delivery orders: indices into `changes`, repeats allowed.
    deliveries: Vec<Vec<usize>>,
}

fn parse(s: &Json) -> Parsed {
    let resource = ResourceId::from_bytes(
        unhex(s["resource_id"].as_str().unwrap())
            .try_into()
            .unwrap(),
    );
    let principals: BTreeMap<String, PrincipalId> = s["principals"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(n, p)| {
            let bytes = unhex(p.as_str().unwrap());
            (
                n.clone(),
                PrincipalId::from_bytes(bytes.try_into().unwrap()),
            )
        })
        .collect();
    let changes = s["changes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            (
                c["signer"].as_str().unwrap().to_owned(),
                unhex(c["framed_plaintext"].as_str().unwrap()),
            )
        })
        .collect();
    let deliveries = s
        .get("deliveries")
        .and_then(Json::as_array)
        .map(|ds| {
            ds.iter()
                .map(|d| {
                    d.as_array()
                        .unwrap()
                        .iter()
                        .map(|i| i.as_u64().unwrap() as usize)
                        .collect()
                })
                .collect()
        })
        .unwrap_or_default();
    Parsed {
        resource,
        principals,
        changes,
        deliveries,
    }
}

impl Parsed {
    /// The summary after delivering `order` (indices into the changes).
    fn deliver(&self, order: &[usize]) -> Json {
        let principals: BTreeMap<&str, PrincipalId> = self
            .principals
            .iter()
            .map(|(n, p)| (n.as_str(), *p))
            .collect();
        summary(&replay(
            self.resource,
            &principals,
            order.iter().map(|&i| {
                let (signer, bytes) = &self.changes[i];
                (signer.as_str(), bytes.clone())
            }),
        ))
    }
}

/// The scenario's summary, replayed in order, in reverse with duplicates and
/// in each of its explicit deliveries, against the producer's.
fn check(s: &Json) -> Result<(), String> {
    let p = parse(s);
    let want = &s["expected"];
    let n = p.changes.len();
    let in_order: Vec<usize> = (0..n).collect();
    let forward = p.deliver(&in_order);
    if &forward != want {
        return Err(format!("in order: {}", difference(want, &forward)));
    }
    let backward: Vec<usize> = (0..n).rev().flat_map(|i| [i, i]).collect();
    let reverse = p.deliver(&backward);
    if &reverse != want {
        return Err(format!(
            "reversed with duplicates: {}",
            difference(want, &reverse)
        ));
    }
    for (k, order) in p.deliveries.iter().enumerate() {
        let got = p.deliver(order);
        if &got != want {
            return Err(format!("delivery {k}: {}", difference(want, &got)));
        }
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

// ---------------------------------------------------------------- schedules
//
// LFCP-02-024: deterministic concurrency schedules. The generator in
// openlfcp/examples (conformance/src/schedules.ts) writes `schedules.json`:
// per seed, three authors' steps (an intent with numbers that pick its
// nodes from the author's current view, or a sync from one author to
// another) and the delivery orders to replay. `produce-schedules` runs each
// schedule with this SDK's authoring API and writes `sections-schedules.json`
// in the sections bundle format, the deliveries made explicit (repeats are
// duplicates; a prefix delivered twice is a dropped connection resumed).
// `consume-schedules` checks every scenario like `consume` and minimizes a
// failing delivery into a regression fixture under `<dir>/regressions/`.

const AUTHORS: [&str; 3] = ["A", "B", "C"];

/// A deterministic generator for delivery orders (mulberry32).
struct Rng(u32);

impl Rng {
    fn next(&mut self) -> u32 {
        self.0 = self.0.wrapping_add(0x6d2b_79f5);
        let mut t = self.0;
        t = (t ^ (t >> 15)).wrapping_mul(t | 1);
        t ^= t.wrapping_add((t ^ (t >> 7)).wrapping_mul(t | 61));
        t ^ (t >> 14)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() as usize) % n.max(1)
    }
}

/// One author: its replica and the changes it wrote.
struct Author {
    doc: SectionsDoc,
    principal: PrincipalId,
}

/// The numbers of a step, as the generator wrote them.
fn nums(op: &Json) -> Vec<usize> {
    op["n"]
        .as_array()
        .map(|a| a.iter().map(|x| x.as_u64().unwrap() as usize).collect())
        .unwrap_or_default()
}

/// The visible nodes of `doc`, in tree order, with their parent and kind.
fn visible(doc: &SectionsDoc) -> Vec<(String, String, Option<NodeKind>)> {
    doc.effective()
        .tree
        .into_iter()
        .map(|t| (t.id, t.parent, t.kind))
        .collect()
}

/// Runs one step of `author`; an intent its view refuses is skipped.
fn step(author: &mut Author, op: &Json, ids: &mut impl FnMut(u16) -> String) -> Option<Change> {
    let n = nums(op);
    let at = |i: usize| n.get(i).copied().unwrap_or(0);
    let view = visible(&author.doc);
    let parents: Vec<String> = std::iter::once(SECTION.to_owned())
        .chain(
            view.iter()
                .filter(|(_, _, k)| k.is_some_and(NodeKind::can_parent))
                .map(|(id, _, _)| id.clone()),
        )
        .collect();
    let after_in = |parent: &str, pick: usize| -> Option<String> {
        let children: Vec<&String> = view
            .iter()
            .filter(|(_, p, _)| p == parent)
            .map(|(id, _, _)| id)
            .collect();
        match pick % (children.len() + 1) {
            0 => None,
            k => Some(children[k - 1].clone()),
        }
    };
    let pick = |i: usize| {
        view.get(at(i) % view.len().max(1))
            .map(|(id, _, _)| id.clone())
    };
    let texts: Vec<String> = view
        .iter()
        .filter(|(_, _, k)| !matches!(k, Some(NodeKind::Task) | None))
        .map(|(id, _, _)| id.clone())
        .collect();
    let text_pick = |i: usize| texts.get(at(i) % texts.len().max(1)).cloned();
    let me = author.principal;
    let words = ["alpha", "Задача", "😀 emoji", "β", "line\nbreak"];
    let result = match op["kind"].as_str().unwrap() {
        "create" => {
            let parent = parents[at(1) % parents.len()].clone();
            let after = after_in(&parent, at(2));
            let text = words[at(3) % words.len()];
            let node = match at(0) % 3 {
                0 => NewNode::Task { title: text },
                1 => NewNode::Paragraph { text },
                _ => NewNode::Item { text },
            };
            let (id, slot) = (ids(1), ids(2));
            author
                .doc
                .create_node(&id, node, &parent, after.as_deref(), &slot, &me)
        }
        "move" => {
            let node = pick(0)?;
            let parent = parents[at(1) % parents.len()].clone();
            let after = after_in(&parent, at(2));
            let slot = ids(2);
            author
                .doc
                .move_node(&node, &parent, after.as_deref(), &slot, &me)
        }
        "delete" => author.doc.delete_node(&pick(0)?),
        "restore" => {
            let all: Vec<String> = author.doc.nodes().into_keys().collect();
            let node = all.get(at(0) % all.len().max(1))?.clone();
            author.doc.restore_node(&node)
        }
        "text" => {
            let node = text_pick(0)?;
            let len = author.doc.nodes()[&node]
                .text
                .as_deref()
                .map_or(0, |t| t.chars().count());
            let index = at(1) % (len + 1);
            let delete = at(2) % (len - index + 1).min(4);
            let base = author.doc.heads();
            author
                .doc
                .text_edit(&node, &base, index, delete, words[at(3) % words.len()])
        }
        "split" => {
            let node = text_pick(0)?;
            let len = author.doc.nodes()[&node]
                .text
                .as_deref()
                .map_or(0, |t| t.chars().count());
            let (id, slot) = (ids(3), ids(4));
            author.doc.split(&node, at(1) % (len + 1), &id, &slot, &me)
        }
        "join" => {
            let first = text_pick(0)?;
            let (_, parent, _) = view.iter().find(|(id, _, _)| *id == first)?.clone();
            let siblings: Vec<&String> = view
                .iter()
                .filter(|(_, p, _)| *p == parent)
                .map(|(id, _, _)| id)
                .collect();
            let at_first = siblings.iter().position(|id| **id == first)?;
            let second = (*siblings.get(at_first + 1)?).clone();
            author.doc.join(&first, &second, "\n")
        }
        "title" => author.doc.set_title(words[at(0) % words.len()]),
        other => panic!("unknown schedule step {other}"),
    };
    result.ok()
}

/// Runs a schedule: returns the scenario in the bundle format.
fn run_schedule(schedule: &Json) -> Json {
    let seed = schedule["seed"].as_u64().unwrap();
    let resource = ResourceId::from_bytes(random());
    let principals: BTreeMap<&str, PrincipalId> = AUTHORS
        .iter()
        .map(|a| (*a, PrincipalId::from_bytes(random())))
        .collect();
    let actor = |a: &str| shared_sections::actor_id(&resource, &principals[a]);
    let mut counter = 0u32;
    let mut ids = |purpose: u16| {
        counter += 1;
        uuid((seed & 0xffff) as u16, purpose, counter)
    };
    // A creates the section; B and C start from it.
    let (mut first, genesis) =
        SectionsDoc::create(actor("A"), SECTION, "Schedule", &principals["A"]).unwrap();
    let save = first.save();
    let mut authors: BTreeMap<&str, Author> = AUTHORS
        .iter()
        .map(|a| {
            let doc = if *a == "A" {
                SectionsDoc::load_as(&save, actor("A")).unwrap()
            } else {
                SectionsDoc::load_as(&save, actor(a)).unwrap()
            };
            (
                *a,
                Author {
                    doc,
                    principal: principals[a],
                },
            )
        })
        .collect();
    let mut changes: Vec<(&str, Change)> = vec![("A", genesis)];
    let mut skipped = 0usize;
    for st in schedule["steps"].as_array().unwrap() {
        if let Some(sync) = st.get("sync") {
            let from = AUTHORS
                .iter()
                .find(|a| **a == sync["from"].as_str().unwrap())
                .unwrap();
            let to = AUTHORS
                .iter()
                .find(|a| **a == sync["to"].as_str().unwrap())
                .unwrap();
            let theirs = authors.get_mut(from).unwrap().doc.changes();
            authors
                .get_mut(to)
                .unwrap()
                .doc
                .apply_changes(theirs)
                .unwrap();
            continue;
        }
        let who = AUTHORS
            .iter()
            .find(|a| **a == st["actor"].as_str().unwrap())
            .unwrap();
        match step(authors.get_mut(who).unwrap(), &st["op"], &mut ids) {
            Some(change) => changes.push((who, change)),
            None => skipped += 1,
        }
    }
    // The causal order: every change after its dependencies.
    let mut all = SectionsDoc::new(ActorId::from([1u8; 32]));
    for a in AUTHORS {
        let theirs = authors.get_mut(a).unwrap().doc.changes();
        all.apply_changes(theirs).unwrap();
    }
    let order: BTreeMap<_, usize> = all
        .changes()
        .iter()
        .enumerate()
        .map(|(i, c)| (c.hash(), i))
        .collect();
    changes.sort_by_key(|(_, c)| order[&c.hash()]);
    let framed: Vec<(&str, Vec<u8>)> = changes
        .iter()
        .map(|(s, c)| (*s, framing::encode_change(c.raw_bytes())))
        .collect();
    let replica = replay(resource, &principals, framed.clone());
    // Deliveries: a shuffle, a shuffle with duplicates, and a dropped
    // connection (a prefix delivered, then everything again).
    let mut rng = Rng(seed as u32 ^ 0x9e37_79b9);
    let n = framed.len();
    let deliveries: Vec<Vec<usize>> = (0..schedule["deliveries"].as_u64().unwrap_or(3))
        .map(|k| {
            let mut order: Vec<usize> = (0..n).collect();
            for i in (1..n).rev() {
                order.swap(i, rng.below(i + 1));
            }
            match k % 3 {
                1 => {
                    let mut with: Vec<usize> = vec![];
                    for i in order {
                        with.push(i);
                        if rng.below(3) == 0 {
                            with.push(i);
                        }
                    }
                    with
                }
                2 => {
                    let cut = rng.below(n + 1);
                    order[..cut].iter().chain(order.iter()).copied().collect()
                }
                _ => order,
            }
        })
        .collect();
    json!({
        "id": format!("seed-{seed}"),
        "description": format!("schedule seed {seed}: {} steps, {} changes, {skipped} intents skipped", schedule["steps"].as_array().unwrap().len(), n),
        "resource_id": hex(resource.as_bytes()),
        "principals": principals.iter().map(|(n, p)| (n.to_string(), json!(hex(p.as_bytes())))).collect::<serde_json::Map<_, _>>(),
        "changes": framed.iter().map(|(s, b)| json!({ "signer": s, "framed_plaintext": hex(b) })).collect::<Vec<_>>(),
        "deliveries": deliveries,
        "expected": summary(&replica),
    })
}

fn produce_schedules(dir: &Path) {
    let input: Json =
        serde_json::from_slice(&std::fs::read(dir.join("schedules.json")).unwrap()).unwrap();
    let scenarios: Vec<Json> = input["schedules"]
        .as_array()
        .unwrap()
        .iter()
        .map(run_schedule)
        .collect();
    let bundle = json!({ "format": FORMAT, "producer": "rust", "scenarios": scenarios });
    std::fs::write(
        dir.join("sections-schedules.json"),
        serde_json::to_vec_pretty(&bundle).unwrap(),
    )
    .unwrap();
}

/// The smallest sublist of `items` for which `fails` still holds, by
/// removing ever smaller chunks (delta debugging); `fails(items)` holds.
fn minimize(items: Vec<usize>, fails: impl Fn(&[usize]) -> bool) -> Vec<usize> {
    let mut items = items;
    let mut chunk = items.len().div_ceil(2).max(1);
    loop {
        let mut removed = false;
        let mut start = 0;
        while start < items.len() {
            let candidate: Vec<usize> = items[..start]
                .iter()
                .chain(items[(start + chunk).min(items.len())..].iter())
                .copied()
                .collect();
            if !candidate.is_empty() && fails(&candidate) {
                items = candidate;
                removed = true;
            } else {
                start += chunk;
            }
        }
        if chunk == 1 && !removed {
            return items;
        }
        if !removed {
            chunk = chunk.div_ceil(2);
        }
    }
}

/// A failing delivery of `s`, minimized into a regression scenario: the
/// changes it delivers, in causal order, and the delivery that diverges
/// from that order.
fn regression(s: &Json) -> Option<Json> {
    let p = parse(s);
    let n = p.changes.len();
    let mut candidates: Vec<Vec<usize>> = vec![(0..n).rev().flat_map(|i| [i, i]).collect()];
    candidates.extend(p.deliveries.iter().cloned());
    let fails = |order: &[usize]| {
        let mut causal: Vec<usize> = order.to_vec();
        causal.sort_unstable();
        causal.dedup();
        p.deliver(order) != p.deliver(&causal)
    };
    let failing = candidates.into_iter().find(|d| fails(d))?;
    let minimal = minimize(failing, fails);
    let mut kept: Vec<usize> = minimal.clone();
    kept.sort_unstable();
    kept.dedup();
    let position = |i: &usize| kept.iter().position(|k| k == i).unwrap();
    let mut out = s.clone();
    out["id"] = json!(format!("{}-minimized", s["id"].as_str().unwrap()));
    out["changes"] = json!(kept
        .iter()
        .map(|&i| s["changes"][i].clone())
        .collect::<Vec<_>>());
    out["deliveries"] = json!([minimal.iter().map(position).collect::<Vec<_>>()]);
    out["expected"] = p.deliver(&kept);
    Some(out)
}

fn consume_schedules(dir: &Path) {
    let mut checks = vec![];
    // The minimizer on a known predicate: the smallest order holding 3 and 7.
    let found = minimize((0..20).collect(), |o| o.contains(&3) && o.contains(&7));
    checks.push(json!({
        "id": "schedules.minimizer",
        "category": "schedules",
        "result": if found == vec![3, 7] { "PASS" } else { "FAIL" },
        "detail": if found == vec![3, 7] { String::new() } else { format!("minimized to {found:?}") },
    }));
    if let Ok(bytes) = std::fs::read(dir.join("sections-schedules.json")) {
        let bundle: Json = serde_json::from_slice(&bytes).unwrap();
        let mut failures = vec![];
        for s in bundle["scenarios"].as_array().unwrap() {
            if let Err(detail) = check(s) {
                let id = s["id"].as_str().unwrap();
                if let Some(fixture) = regression(s) {
                    std::fs::create_dir_all(dir.join("regressions")).unwrap();
                    std::fs::write(
                        dir.join("regressions").join(format!("{id}.json")),
                        serde_json::to_vec_pretty(&fixture).unwrap(),
                    )
                    .unwrap();
                }
                failures.push(format!("{id}: {detail}"));
            }
        }
        let total = bundle["scenarios"].as_array().unwrap().len();
        checks.push(json!({
            "id": "schedules.random",
            "category": "schedules",
            "result": if failures.is_empty() { "PASS" } else { "FAIL" },
            "detail": if failures.is_empty() { format!("{total} schedules converge") } else { failures.join("; ") },
        }));
    }
    // Minimized failures kept as fixtures (examples/conformance/regressions).
    if let Ok(bytes) = std::fs::read(dir.join("sections-regressions.json")) {
        let bundle: Json = serde_json::from_slice(&bytes).unwrap();
        let failures: Vec<String> = bundle["scenarios"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|s| {
                check(s)
                    .err()
                    .map(|d| format!("{}: {d}", s["id"].as_str().unwrap()))
            })
            .collect();
        checks.push(json!({
            "id": "schedules.regressions",
            "category": "schedules",
            "result": if failures.is_empty() { "PASS" } else { "FAIL" },
            "detail": failures.join("; "),
        }));
    }
    std::fs::write(
        dir.join("schedules-results-rust.json"),
        serde_json::to_vec_pretty(&json!({ "consumer": "rust", "checks": checks })).unwrap(),
    )
    .unwrap();
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [command, dir] if command == "produce" => produce(Path::new(dir)),
        [command, dir] if command == "consume" => consume(Path::new(dir)),
        [command, dir] if command == "produce-schedules" => produce_schedules(Path::new(dir)),
        [command, dir] if command == "consume-schedules" => consume_schedules(Path::new(dir)),
        _ => {
            eprintln!("usage: interop_sections (produce|consume|produce-schedules|consume-schedules) <dir>");
            std::process::exit(2);
        }
    }
}
