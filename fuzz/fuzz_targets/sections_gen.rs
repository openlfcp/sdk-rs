//! Honest section histories into `SectionsReplica` (SHARED-SECTIONS-PROFILE-01
//! §7, §9, §10, §14.1, and SHARED-OBJECTS-PROFILE-01 §11.3, §11.4): the
//! input is a program three writers (the corpus Principals A, B, C) run with
//! the authoring API on their own copies of one section, merging each
//! other's changes now and then.
//!
//! - Every change the authoring API makes is admitted: one at a time, in an
//!   order the input chooses, through the Data Unit framing and signed by
//!   its writer, none is refused; the replica ends on the writers' heads.
//! - §7.6: a node whose lifecycle has concurrent distinct values is blocked
//!   (a structural fact), not hidden as deleted.
//! - The replica's view and a document loaded from the writers' history
//!   agree on the effective tree.

#![no_main]

use automerge::{ActorId, AutoCommit, ChangeHash};
use lfcp::base::PrincipalId;
use lfcp::shared_objects::framing;
use lfcp::shared_sections::{self, NewNode, NodeKind, Received, SectionsDoc, SectionsReplica};
use lfcp_fuzz::*;
use libfuzzer_sys::fuzz_target;

const WRITERS: usize = 3;
const MAX_STEPS: usize = 80;

fn uuid(n: u32) -> String {
    format!("0192e4a0-0000-7000-8000-{n:012x}")
}

struct Program<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Program<'_> {
    fn byte(&mut self) -> u8 {
        let b = self.bytes.get(self.at).copied().unwrap_or(0);
        self.at += 1;
        b
    }
    fn done(&self) -> bool {
        self.at >= self.bytes.len()
    }
    fn pick<T: Clone>(&mut self, items: &[T]) -> Option<T> {
        (!items.is_empty()).then(|| items[usize::from(self.byte()) % items.len()].clone())
    }
}

fn principal(i: usize) -> PrincipalId {
    signer(&SECTIONS_PRINCIPALS, i as u8)
}

fuzz_target!(|data: &[u8]| {
    panic_policy();
    let Some((&order_seed, program)) = data.split_first() else {
        return;
    };
    let mut p = Program {
        bytes: program,
        at: 0,
    };
    let resource = resource(SECTIONS_RESOURCE);
    let actors: Vec<ActorId> = (0..WRITERS)
        .map(|i| shared_sections::actor_id(&resource, &principal(i)))
        .collect();
    let section = uuid(1);
    let Ok((first, _genesis)) =
        SectionsDoc::create(actors[0].clone(), &section, "S", &principal(0))
    else {
        return;
    };
    let mut docs = vec![first];
    for actor in actors.iter().skip(1) {
        let mut d = SectionsDoc::new(actor.clone());
        let base = docs[0].changes();
        if d.apply_changes(base).is_err() {
            return;
        }
        docs.push(d);
    }
    let mut next_id = 100u32;
    let mut steps = 0;
    while !p.done() && steps < MAX_STEPS {
        steps += 1;
        let w = usize::from(p.byte()) % WRITERS;
        let op = p.byte() % 10;
        let nodes: Vec<(String, Option<NodeKind>)> = docs[w]
            .nodes()
            .into_iter()
            .map(|(id, n)| (id, n.kind))
            .collect();
        let ids: Vec<String> = nodes.iter().map(|(id, _)| id.clone()).collect();
        let parents: Vec<String> = std::iter::once(section.clone())
            .chain(
                nodes
                    .iter()
                    .filter(|(_, k)| k.is_some_and(|k| k.can_parent()))
                    .map(|(id, _)| id.clone()),
            )
            .collect();
        let me = principal(w);
        let mut fresh = || {
            next_id += 1;
            uuid(next_id)
        };
        let doc = &mut docs[w];
        let _ = match op {
            0 => {
                let parent = p.pick(&parents).unwrap();
                let content = match p.byte() % 4 {
                    0 => NewNode::Task { title: "t" },
                    1 => NewNode::Paragraph { text: "para" },
                    2 => NewNode::Item { text: "item" },
                    _ => NewNode::Raw { text: "raw" },
                };
                let (node, placement) = (fresh(), fresh());
                doc.create_node(&node, content, &parent, None, &placement, &me)
                    .map(|_| ())
            }
            1 | 2 => match (p.pick(&ids), p.pick(&parents)) {
                (Some(node), Some(parent)) => {
                    let placement = fresh();
                    if op == 1 {
                        doc.move_node(&node, &parent, None, &placement, &me)
                            .map(|_| ())
                    } else {
                        doc.resolve_placement(&node, &parent, None, &placement, &me)
                            .map(|_| ())
                    }
                }
                _ => Ok(()),
            },
            3 => match p.pick(&ids) {
                Some(n) => doc.delete_node(&n).map(|_| ()),
                None => Ok(()),
            },
            4 => match p.pick(&ids) {
                Some(n) => doc.restore_node(&n).map(|_| ()),
                None => Ok(()),
            },
            5 => match p.pick(&ids) {
                Some(n) => {
                    let base = doc.heads();
                    let (at, del) = (usize::from(p.byte() % 6), usize::from(p.byte() % 3));
                    doc.text_edit(
                        &n,
                        &base,
                        at,
                        del,
                        ["x", "", "é漢"][usize::from(p.byte() % 3)],
                    )
                    .map(|_| ())
                }
                None => Ok(()),
            },
            6 => match p.pick(&ids) {
                Some(n) => {
                    let (node, placement) = (fresh(), fresh());
                    doc.split(&n, usize::from(p.byte() % 5), &node, &placement, &me)
                        .map(|_| ())
                }
                None => Ok(()),
            },
            7 => match (p.pick(&ids), p.pick(&ids)) {
                (Some(a), Some(b)) => doc.join(&a, &b, " ").map(|_| ()),
                _ => Ok(()),
            },
            8 => doc
                .set_title(["S", "T", "S2"][usize::from(p.byte() % 3)])
                .map(|_| ()),
            _ => {
                // Merge another writer's history in.
                let from = usize::from(p.byte()) % WRITERS;
                if from != w {
                    let theirs = docs[from].changes();
                    let _ = docs[w].apply_changes(theirs);
                }
                Ok(())
            }
        };
    }

    // The writers' whole history.
    let mut all = AutoCommit::new();
    for doc in &mut docs {
        if all.apply_changes(doc.changes()).is_err() {
            return;
        }
    }
    let changes = all.get_changes(&[]);
    let mut want: Vec<ChangeHash> = all.get_heads();
    want.sort();

    // One at a time, signed by each change's writer, in an order the input
    // chooses.
    let mut order: Vec<usize> = (0..changes.len()).collect();
    let mut s = u64::from(order_seed) | 1;
    for i in (1..order.len()).rev() {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        order.swap(i, (s >> 33) as usize % (i + 1));
    }
    let mut replica = SectionsReplica::new(resource, ActorId::from([1u8; 32]));
    for &i in &order {
        let c = &changes[i];
        let w = actors
            .iter()
            .position(|a| a == c.actor_id())
            .expect("a writer's change");
        let verdict = replica.receive(&principal(w), &framing::encode_change(c.raw_bytes()));
        if let Received::Refused(r) = verdict {
            panic!(
                "an honest change is refused: {} (seq {}, {} ops, message {:?})",
                r.name(),
                c.seq(),
                c.len(),
                c.message()
            );
        }
    }
    assert!(replica.waiting().is_empty(), "honest changes still wait");
    let view = replica.view();
    let mut got = view.automerge().clone().get_heads();
    got.sort();
    assert_eq!(got, want, "the replica ends elsewhere");

    // §7.6: a lifecycle in conflict blocks the node; it is not hidden as
    // deleted.
    let effective = view.effective();
    for (id, node) in view.nodes() {
        let mut lifecycles = match node.kind {
            Some(NodeKind::Task) => node
                .task_id
                .as_deref()
                .map(|t| view.task_lifecycles(t))
                .unwrap_or_default(),
            _ => node.lifecycles.clone(),
        };
        lifecycles.sort();
        lifecycles.dedup();
        if lifecycles.len() > 1
            && !effective.invalid.contains_key(&id)
            && !effective.collisions.contains(&id)
        {
            assert!(
                effective.recovery.contains_key(&id),
                "§7.6: node {id} with lifecycles {lifecycles:?} is not blocked"
            );
        }
    }

    // The same history loaded as a document projects the same tree.
    let mut whole = all.clone();
    let loaded = SectionsDoc::load(&whole.save())
        .unwrap_or_else(|e| panic!("the writers' history does not load: {e:?}"));
    assert_eq!(loaded.effective(), effective, "replica and load disagree");
});
