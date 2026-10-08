//! Shared Sections authoring in Rust (LFCP-02-020): nodes, moves, structural
//! conflicts and explicit resolution, written with this SDK and checked
//! with its own effective-tree derivation (SHARED-SECTIONS-PROFILE-01 §4–§8).

#![cfg(feature = "shared-sections")]

use automerge::ActorId;
use lfcp::base::{PrincipalId, ResourceId};
use lfcp::shared_sections::{self, AuthoringError, Fact, NewNode, SectionsDoc};

const SECTION: &str = "019a2f85-7b31-7c42-8000-000000000001";
const T: &str = "019a2f85-7b31-7c42-8000-000000000010";
const P: &str = "019a2f85-7b31-7c42-8000-000000000011";
const X: &str = "019a2f85-7b31-7c42-8000-000000000012";
const Y: &str = "019a2f85-7b31-7c42-8000-000000000013";
const A1: &str = "019a2f85-7b31-7c42-8000-000000000014";
const B1: &str = "019a2f85-7b31-7c42-8000-000000000015";

/// A fresh placement ID per call.
fn slot(n: u32) -> String {
    format!("019a2f85-7b31-7c42-9000-{n:012x}")
}

fn principal(b: u8) -> PrincipalId {
    PrincipalId::from_bytes([b; 32])
}

fn actor(b: u8) -> ActorId {
    shared_sections::actor_id(&ResourceId::from_bytes([9; 32]), &principal(b))
}

/// A section with Task T (child paragraph P) and items X, Y after it.
fn seeded() -> SectionsDoc {
    let (mut doc, _) =
        SectionsDoc::create(actor(1), SECTION, "Joint launch", &principal(1)).unwrap();
    let a = principal(1);
    doc.create_node(
        T,
        NewNode::Task {
            title: "Prepare contract",
        },
        SECTION,
        None,
        &slot(1),
        &a,
    )
    .unwrap();
    doc.create_node(
        P,
        NewNode::Paragraph {
            text: "Draft contract",
        },
        T,
        None,
        &slot(2),
        &a,
    )
    .unwrap();
    doc.create_node(
        X,
        NewNode::Item { text: "Group X" },
        SECTION,
        Some(T),
        &slot(3),
        &a,
    )
    .unwrap();
    doc.create_node(
        Y,
        NewNode::Item { text: "Group Y" },
        SECTION,
        Some(X),
        &slot(4),
        &a,
    )
    .unwrap();
    doc
}

fn fork(doc: &mut SectionsDoc, b: u8) -> SectionsDoc {
    SectionsDoc::load_as(&doc.save(), actor(b)).unwrap()
}

/// Merge `a` and `b` into each other.
fn merge(a: &mut SectionsDoc, b: &mut SectionsDoc) {
    let (ca, cb) = (a.changes(), b.changes());
    a.apply_changes(cb).unwrap();
    b.apply_changes(ca).unwrap();
}

fn tree(doc: &SectionsDoc) -> Vec<(String, String)> {
    doc.effective()
        .tree
        .into_iter()
        .map(|t| (t.id, t.parent))
        .collect()
}

#[test]
fn a_seeded_section_is_valid_and_ready() {
    let doc = seeded();
    assert_eq!(doc.validate_root(), Ok(()));
    assert!(doc.section().unwrap().ready);
    assert!(doc.node_problems().is_empty());
    assert_eq!(
        tree(&doc),
        [
            (T.into(), SECTION.into()),
            (P.into(), T.into()),
            (X.into(), SECTION.into()),
            (Y.into(), SECTION.into())
        ]
    );
    assert_eq!(doc.nodes()[P].text.as_deref(), Some("Draft contract"));
    assert_eq!(doc.task_title(T).as_deref(), Some("Prepare contract"));
    assert!(doc.task_fields_are_scalar(T));
}

#[test]
fn concurrent_sibling_inserts_both_survive_in_one_order() {
    let mut a = seeded();
    let mut b = fork(&mut a, 2);
    a.create_node(
        A1,
        NewNode::Paragraph { text: "A note" },
        SECTION,
        Some(T),
        &slot(10),
        &principal(1),
    )
    .unwrap();
    b.create_node(
        B1,
        NewNode::Paragraph { text: "B note" },
        SECTION,
        Some(T),
        &slot(11),
        &principal(2),
    )
    .unwrap();
    merge(&mut a, &mut b);
    assert_eq!(tree(&a), tree(&b), "same order on both replicas");
    let ids: Vec<String> = tree(&a).into_iter().map(|(id, _)| id).collect();
    assert!(ids.contains(&A1.to_owned()) && ids.contains(&B1.to_owned()));
    assert_eq!(ids.len(), 6);
}

#[test]
fn repeated_moves_keep_one_identity_and_every_slot() {
    let mut doc = seeded();
    let me = principal(1);
    doc.move_node(T, X, None, &slot(20), &me).unwrap();
    doc.move_node(T, Y, None, &slot(21), &me).unwrap();
    doc.move_node(T, SECTION, Some(Y), &slot(22), &me).unwrap();
    let t: Vec<_> = doc
        .effective()
        .tree
        .into_iter()
        .filter(|e| e.id == T)
        .collect();
    assert_eq!(t.len(), 1, "one visible T");
    assert_eq!(t[0].parent, SECTION);
    assert_eq!(doc.placements().len(), 4 + 3, "historical slots remain");
    // Its child moved with it.
    assert!(tree(&doc).contains(&(P.into(), T.into())));
}

#[test]
fn concurrent_moves_conflict_whether_parents_differ_or_not() {
    for same_parent in [false, true] {
        let mut a = seeded();
        let mut b = fork(&mut a, 2);
        a.move_node(T, X, None, &slot(30), &principal(1)).unwrap();
        let other = if same_parent { X } else { Y };
        b.move_node(T, other, None, &slot(31), &principal(2))
            .unwrap();
        merge(&mut a, &mut b);
        let effective = a.effective();
        assert_eq!(
            effective.recovery.get(T),
            Some(&Fact::PlacementConflict),
            "same parent: {same_parent}"
        );
        assert_eq!(effective.recovery.get(P), Some(&Fact::BlockedParent));
        assert!(
            !tree(&a).iter().any(|(id, _)| id == T),
            "no arbitrary winner"
        );
        // Explicit resolution by a third replica.
        let mut c = fork(&mut a, 3);
        c.resolve_placement(T, SECTION, None, &slot(32), &principal(3))
            .unwrap();
        let effective = c.effective();
        assert!(effective.recovery.is_empty(), "resolved");
        assert_eq!(tree(&c)[0], (T.into(), SECTION.into()));
    }
}

#[test]
fn opposing_moves_make_a_cycle_that_resolution_breaks() {
    let mut a = seeded();
    let mut b = fork(&mut a, 2);
    a.move_node(X, Y, None, &slot(40), &principal(1)).unwrap();
    b.move_node(Y, X, None, &slot(41), &principal(2)).unwrap();
    merge(&mut a, &mut b);
    let effective = a.effective();
    assert_eq!(effective.recovery.get(X), Some(&Fact::ParentCycle));
    assert_eq!(effective.recovery.get(Y), Some(&Fact::ParentCycle));
    assert_eq!(
        a.nodes()[X].text.as_deref(),
        Some("Group X"),
        "text retained"
    );
    let mut c = fork(&mut a, 3);
    c.resolve_placement(X, SECTION, Some(T), &slot(42), &principal(3))
        .unwrap();
    let effective = c.effective();
    assert!(effective.recovery.is_empty());
    assert!(
        tree(&c).contains(&(Y.into(), X.into())),
        "Y under X once X is resolved"
    );
}

#[test]
fn invalid_intents_are_refused_before_writing() {
    let mut doc = seeded();
    let me = principal(1);
    let before = doc.changes().len();
    assert_eq!(
        doc.move_node(X, X, None, &slot(50), &me),
        Err(AuthoringError::WouldCycle)
    );
    doc.move_node(Y, X, None, &slot(51), &me).unwrap();
    assert_eq!(
        doc.move_node(X, Y, None, &slot(52), &me),
        Err(AuthoringError::WouldCycle)
    );
    assert_eq!(
        doc.move_node(X, P, None, &slot(53), &me),
        Err(AuthoringError::InvalidParent)
    );
    assert_eq!(
        doc.move_node(X, SECTION, Some(P), &slot(54), &me),
        Err(AuthoringError::InvalidPredecessor)
    );
    assert_eq!(
        doc.move_node(X, SECTION, None, &slot(1), &me),
        Err(AuthoringError::InvalidId)
    );
    assert_eq!(
        doc.create_node(
            "not-a-uuid",
            NewNode::Paragraph { text: "" },
            SECTION,
            None,
            &slot(55),
            &me
        ),
        Err(AuthoringError::InvalidId)
    );
    assert_eq!(
        doc.changes().len(),
        before + 1,
        "only the valid move was written"
    );
}
