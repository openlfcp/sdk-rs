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

// ---------------------------------------------------------------- LFCP-02-021

fn hidden(doc: &SectionsDoc) -> Vec<String> {
    doc.effective().hidden.into_iter().collect()
}

#[test]
fn deleting_a_parent_hides_a_concurrently_edited_child_and_keeps_the_edit() {
    let mut a = seeded();
    let mut b = fork(&mut a, 2);
    a.delete_node(T).unwrap();
    let base = b.heads();
    b.text_edit(P, &base, 0, 0, "Edited: ").unwrap();
    merge(&mut a, &mut b);
    assert_eq!(hidden(&a), [T.to_owned(), P.to_owned()]);
    assert_eq!(a.nodes()[P].text.as_deref(), Some("Edited: Draft contract"));
    assert!(
        a.retained_concurrent_edits().contains(P),
        "EDIT_UNDER_DELETED_ANCESTOR"
    );
}

#[test]
fn a_child_moved_out_of_a_deleted_parent_stays_visible() {
    let mut a = seeded();
    let mut b = fork(&mut a, 2);
    a.delete_node(T).unwrap();
    b.move_node(P, SECTION, None, &slot(60), &principal(2))
        .unwrap();
    merge(&mut a, &mut b);
    assert!(tree(&a).contains(&(P.into(), SECTION.into())));
    assert!(!tree(&a).iter().any(|(id, _)| id == T));
}

#[test]
fn delete_versus_restore_conflicts_and_a_fresh_restore_resolves_it() {
    let mut a = seeded();
    let mut b = fork(&mut a, 2);
    a.delete_node(T).unwrap();
    // T is visibly active for B: a plain same-value write would be skipped
    // by the engine; the restore intent still writes an operation.
    let restore = b.restore_node(T).unwrap();
    assert!(
        restore.len() > 0,
        "the explicit restore is a fresh assignment"
    );
    merge(&mut a, &mut b);
    assert_eq!(
        a.effective().recovery.get(T),
        Some(&Fact::LifecycleConflict)
    );
    let mut c = fork(&mut a, 3);
    c.restore_node(T).unwrap();
    assert!(c.effective().recovery.is_empty());
    assert!(tree(&c).iter().any(|(id, _)| id == T));
}

#[test]
fn restoring_a_parent_leaves_an_independently_deleted_child_hidden() {
    let mut doc = seeded();
    doc.delete_node(P).unwrap();
    doc.delete_node(T).unwrap();
    doc.restore_node(T).unwrap();
    assert!(tree(&doc).iter().any(|(id, _)| id == T));
    assert_eq!(hidden(&doc), [P.to_owned()]);
}

#[test]
fn concurrent_unicode_text_edits_converge() {
    let mut a = seeded();
    let base = a.heads();
    a.text_edit(P, &base, 0, 14, "А😀Б").unwrap();
    let mut b = fork(&mut a, 2);
    // Scalar indices: the emoji is one position.
    let base_a = a.heads();
    a.text_edit(P, &base_a, 2, 0, "!").unwrap();
    let base_b = b.heads();
    b.text_edit(P, &base_b, 0, 0, "Я: ").unwrap();
    merge(&mut a, &mut b);
    assert_eq!(a.nodes()[P].text.as_deref(), Some("Я: А😀!Б"));
    assert_eq!(b.nodes()[P].text, a.nodes()[P].text);
}

#[test]
fn an_edit_on_a_stale_base_is_refused() {
    let mut doc = seeded();
    let base = doc.heads();
    doc.text_edit(P, &base, 0, 0, "x").unwrap();
    assert_eq!(
        doc.text_edit(P, &base, 0, 0, "y"),
        Err(AuthoringError::StaleBase)
    );
    let task_base = doc.heads();
    assert_eq!(
        doc.text_edit(T, &task_base, 0, 0, "y"),
        Err(AuthoringError::NotApplicable)
    );
}

#[test]
fn split_and_join_keep_identities() {
    let mut doc = seeded();
    let base = doc.heads();
    doc.text_edit(P, &base, 0, 14, "Черновик договора 😀")
        .unwrap();
    let suffix = "019a2f85-7b31-7c42-8000-000000000020";
    doc.split(P, 8, suffix, &slot(70), &principal(1)).unwrap();
    assert_eq!(doc.nodes()[P].text.as_deref(), Some("Черновик"));
    assert_eq!(doc.nodes()[suffix].text.as_deref(), Some(" договора 😀"));
    let order: Vec<String> = tree(&doc).into_iter().map(|(id, _)| id).collect();
    let at = order.iter().position(|id| id == P).unwrap();
    assert_eq!(order[at + 1], suffix, "the suffix follows the original");
    doc.join(P, suffix, "").unwrap();
    assert_eq!(doc.nodes()[P].text.as_deref(), Some("Черновик договора 😀"));
    assert!(
        hidden(&doc).contains(&suffix.to_owned()),
        "the joined node is tombstoned"
    );
    assert_eq!(
        doc.nodes()[suffix].text.as_deref(),
        Some(" договора 😀"),
        "its Text is retained"
    );
    assert_eq!(doc.join(P, X, ""), Err(AuthoringError::NotApplicable));
}

#[test]
fn automerge_skips_a_plain_same_value_write() {
    // Why §9 asks for a fresh assignment: automerge 0.12 commits nothing for
    // a put of the value already there, so an explicit restore of a visibly
    // active node must write differently (restore_node does).
    use automerge::transaction::Transactable;
    use automerge::{AutoCommit, ScalarValue, ROOT};
    let mut doc = AutoCommit::new();
    doc.put(ROOT, "lifecycle", ScalarValue::Str("active".into()))
        .unwrap();
    assert!(doc.commit().is_some());
    doc.put(ROOT, "lifecycle", ScalarValue::Str("active".into()))
        .unwrap();
    assert!(doc.commit().is_none(), "the same-value put is suppressed");
}
