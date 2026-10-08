//! The Shared Sections profile `org.openlfcp.shared-sections.v1`
//! (SHARED-SECTIONS-PROFILE-01, Working Draft for MVP 0.2; ADR 0009).
//!
//! One shared section per Resource: an ordered, nested collection of Task
//! references, paragraphs, list items and raw blocks. This module reads a
//! section document and checks its values (§3, §4, §14.2); the Automerge
//! engine, framing, limits and replica rules are those of
//! SHARED-OBJECTS-PROFILE-01 §§7-18, which the profile inherits unchanged.
//!
//! | Part | Item | § |
//! | --- | --- | --- |
//! | profile dispatch from Genesis | [`DataProfile`] | §1, §17 |
//! | actor IDs with this profile's domain | [`actor_id`] | §2 |
//! | the document and its typed view | [`SectionsDoc`], [`Section`], [`Node`], [`Placement`] | §3, §4 |
//! | per-node value checks | [`SectionsDoc::node_problems`], [`Diagnostic`] | §14.2 |
//! | the effective tree, structural conflicts and visibility | [`SectionsDoc::effective`], [`Effective`] | §7, §9, §14.3 |
//! | authoring: section, nodes, moves, explicit resolution | [`SectionsDoc::create`], [`SectionsDoc::create_node`], [`SectionsDoc::move_node`], [`SectionsDoc::resolve_placement`] | §4–§8, §11 |

use std::collections::{BTreeMap, BTreeSet, HashSet};

use automerge::transaction::{CommitOptions, Transactable};
use automerge::{ActorId, AutoCommit, Change, ObjId, ObjType, ReadDoc, ScalarValue, Value, ROOT};

use crate::base::{ObjectId, PrincipalId, ResourceId};
use crate::crypto;
use crate::shared_objects::document::load_guarded;
use crate::shared_objects::ProfileError;

/// The profile identifier a section Resource's Genesis declares (§1).
pub const PROFILE: &str = "org.openlfcp.shared-sections.v1";

/// The actor domain of this profile (§2).
pub const ACTOR_DOMAIN: &[u8] = b"OPENLFCP-SHARED-SECTIONS-ACTOR-v1";

/// The 32-byte Automerge actor of `principal` in the section Resource
/// `resource` (§2): `SHA-256(domain || resource_id || principal_id)`. It
/// differs from the Principal's Shared Objects actor.
pub fn actor_id_bytes(resource: &ResourceId, principal: &PrincipalId) -> [u8; 32] {
    *crypto::sha256_parts(&[ACTOR_DOMAIN, resource.as_bytes(), principal.as_bytes()]).as_bytes()
}

/// [`actor_id_bytes`] as an Automerge [`ActorId`].
pub fn actor_id(resource: &ResourceId, principal: &PrincipalId) -> ActorId {
    ActorId::from(actor_id_bytes(resource, principal))
}

/// The application profile of a Resource, from its validated Genesis
/// (§17): a client dispatches on it before interpreting anything.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DataProfile {
    /// `org.openlfcp.shared-objects.v1` (SHARED-OBJECTS-PROFILE-01).
    SharedObjects,
    /// `org.openlfcp.shared-sections.v1` (this profile).
    SharedSections,
    /// Any other profile: `PROFILE_UNSUPPORTED` (LFCP-WIRE-01 §62). Its
    /// units are neither interpreted nor written.
    Unsupported(String),
}

impl DataProfile {
    /// The profile a Genesis `data_profile` names.
    pub fn of(data_profile: &str) -> DataProfile {
        match data_profile {
            crate::shared_objects::PROFILE => DataProfile::SharedObjects,
            PROFILE => DataProfile::SharedSections,
            other => DataProfile::Unsupported(other.to_owned()),
        }
    }
}

/// A value problem of the §14.2 registry. Each failing value reports one;
/// when a value breaks several rules, the first in this order applies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Diagnostic {
    /// `profile` differs, or a root container of §3 is missing or not a map.
    InvalidRoot,
    /// An ID, or a map key holding one, is not a canonical UUIDv7.
    InvalidObjectId,
    /// An object's `id` differs from its map key, or a Task node's `id`
    /// from its `task_id`.
    ObjectIdMismatch,
    /// A required field is absent.
    MissingRequiredField,
    /// A field has the wrong type, e.g. Text where a scalar string is
    /// required, or a node's `text` that is not Text.
    InvalidFieldType,
    /// `kind`, `lifecycle` or `list_style` is outside its domain.
    InvalidEnumValue,
    /// A `created_by` is not `p:` + base64url of 32 bytes.
    InvalidPrincipalRef,
    /// A node's placement, a placement's node or parent, or a Task node's
    /// Task does not exist, or a parent is a paragraph or raw node.
    InvalidReference,
}

impl Diagnostic {
    /// The registry name, such as `INVALID_REFERENCE`.
    pub fn name(self) -> &'static str {
        match self {
            Diagnostic::InvalidRoot => "INVALID_ROOT",
            Diagnostic::InvalidObjectId => "INVALID_OBJECT_ID",
            Diagnostic::ObjectIdMismatch => "OBJECT_ID_MISMATCH",
            Diagnostic::MissingRequiredField => "MISSING_REQUIRED_FIELD",
            Diagnostic::InvalidFieldType => "INVALID_FIELD_TYPE",
            Diagnostic::InvalidEnumValue => "INVALID_ENUM_VALUE",
            Diagnostic::InvalidPrincipalRef => "INVALID_PRINCIPAL_REF",
            Diagnostic::InvalidReference => "INVALID_REFERENCE",
        }
    }
}

/// The kind of a node (§4.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeKind {
    /// A reference to a Task of the Resource.
    Task,
    /// A paragraph of collaborative Text; it has no children.
    Paragraph,
    /// A list item of collaborative Text.
    Item,
    /// A Markdown block carried verbatim as Text; it has no children.
    Raw,
}

impl NodeKind {
    fn parse(s: &str) -> Option<NodeKind> {
        Some(match s {
            "task" => NodeKind::Task,
            "paragraph" => NodeKind::Paragraph,
            "item" => NodeKind::Item,
            "raw" => NodeKind::Raw,
            _ => return None,
        })
    }

    /// Whether a node of this kind may have children (§4.2).
    pub fn can_parent(self) -> bool {
        matches!(self, NodeKind::Task | NodeKind::Item)
    }
}

/// The section map (§4.1), as read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Section {
    /// `id`.
    pub id: String,
    /// `title` (the engine-selected value of a conflict).
    pub title: Option<String>,
    /// `created_by`.
    pub created_by: Option<String>,
    /// Whether `ready` is `true` (§12.1); a section without it is being
    /// imported.
    pub ready: bool,
    /// `children`: PlacementIds in list order.
    pub children: Vec<String>,
}

/// A node (§4.2), as read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    /// The map key.
    pub id: String,
    /// `kind`, when it is a known kind.
    pub kind: Option<NodeKind>,
    /// Every concurrent value of the `placement` register (§7: more than
    /// one is a placement conflict).
    pub placements: Vec<String>,
    /// Every concurrent value of `lifecycle`.
    pub lifecycles: Vec<String>,
    /// `task_id`, for a Task node.
    pub task_id: Option<String>,
    /// The current string of `text`, when it is Text.
    pub text: Option<String>,
    /// `children`: PlacementIds in list order.
    pub children: Vec<String>,
}

/// A placement (§4.3), as read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Placement {
    /// The map key.
    pub id: String,
    /// `node_id`.
    pub node_id: Option<String>,
    /// `parent_id`: the section or a Task/item node.
    pub parent_id: Option<String>,
}

/// The Automerge document of one section Resource.
#[derive(Debug)]
pub struct SectionsDoc {
    doc: AutoCommit,
}

const ROOT_MAPS: [&str; 5] = ["section", "objects", "nodes", "placements", "extensions"];

/// The scalar string at `key` of `obj`, if it is one.
fn scalar(doc: &AutoCommit, obj: &ObjId, key: &str) -> Option<String> {
    match doc.get(obj, key).ok().flatten()? {
        (Value::Scalar(s), _) => match s.as_ref() {
            ScalarValue::Str(s) => Some(s.to_string()),
            _ => None,
        },
        _ => None,
    }
}

/// Every concurrent value at `key` of `obj` that is a scalar string.
fn scalars(doc: &AutoCommit, obj: &ObjId, key: &str) -> Vec<String> {
    let mut out: Vec<String> = doc
        .get_all(obj, key)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(v, _)| match v {
            Value::Scalar(s) => match s.as_ref() {
                ScalarValue::Str(s) => Some(s.to_string()),
                _ => None,
            },
            _ => None,
        })
        .collect();
    out.sort();
    out
}

/// The object of type `ty` at `key` of `obj`.
fn object(doc: &AutoCommit, obj: &ObjId, key: &str, ty: ObjType) -> Option<ObjId> {
    match doc.get(obj, key).ok().flatten()? {
        (Value::Object(t), id) if t == ty => Some(id),
        _ => None,
    }
}

/// The scalar strings of the list `list`, in order.
fn list_strings(doc: &AutoCommit, list: &ObjId) -> Vec<String> {
    (0..doc.length(list))
        .filter_map(|i| match doc.get(list, i).ok().flatten()? {
            (Value::Scalar(s), _) => match s.as_ref() {
                ScalarValue::Str(s) => Some(s.to_string()),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

/// Whether the value at `key` of `obj` is present but not a scalar string
/// (for example collaborative Text).
fn not_scalar(doc: &AutoCommit, obj: &ObjId, key: &str) -> bool {
    doc.get(obj, key).ok().flatten().is_some() && scalar(doc, obj, key).is_none()
}

fn is_uuidv7(s: &str) -> bool {
    ObjectId::parse(s).is_ok()
}

impl SectionsDoc {
    /// Load a full-save image (§2, SHARED-OBJECTS-PROFILE-01 §13). A save
    /// that does not load is `PROFILE_INVALID` with `INVALID_AUTOMERGE_BYTES`.
    pub fn load(save: &[u8]) -> Result<SectionsDoc, ProfileError> {
        Ok(SectionsDoc {
            doc: load_guarded(save)?,
        })
    }

    /// The underlying Automerge document, for reading.
    pub fn automerge(&self) -> &AutoCommit {
        &self.doc
    }

    /// The root rules (§3): `profile` is this profile, and the root
    /// containers exist as maps.
    pub fn validate_root(&self) -> Result<(), Diagnostic> {
        if scalar(&self.doc, &ROOT, "profile").as_deref() != Some(PROFILE) {
            return Err(Diagnostic::InvalidRoot);
        }
        for key in ROOT_MAPS {
            if object(&self.doc, &ROOT, key, ObjType::Map).is_none() {
                return Err(Diagnostic::InvalidRoot);
            }
        }
        let section = object(&self.doc, &ROOT, "section", ObjType::Map).unwrap();
        if object(&self.doc, &section, "children", ObjType::List).is_none() {
            return Err(Diagnostic::InvalidRoot);
        }
        Ok(())
    }

    fn root_map(&self, key: &str) -> Option<ObjId> {
        object(&self.doc, &ROOT, key, ObjType::Map)
    }

    /// The section map, or `None` when the root is not valid.
    pub fn section(&self) -> Option<Section> {
        let s = self.root_map("section")?;
        let ready = matches!(
            self.doc.get(&s, "ready").ok().flatten(),
            Some((Value::Scalar(v), _)) if matches!(v.as_ref(), ScalarValue::Boolean(true))
        );
        Some(Section {
            id: scalar(&self.doc, &s, "id")?,
            title: scalar(&self.doc, &s, "title"),
            created_by: scalar(&self.doc, &s, "created_by"),
            ready,
            children: object(&self.doc, &s, "children", ObjType::List)
                .map(|l| list_strings(&self.doc, &l))
                .unwrap_or_default(),
        })
    }

    fn keys(&self, map: &str) -> Vec<String> {
        match self.root_map(map) {
            Some(m) => self.doc.keys(&m).collect(),
            None => Vec::new(),
        }
    }

    /// Every node, by NodeId.
    pub fn nodes(&self) -> BTreeMap<String, Node> {
        let Some(nodes) = self.root_map("nodes") else {
            return BTreeMap::new();
        };
        self.keys("nodes")
            .into_iter()
            .filter_map(|k| {
                let n = object(&self.doc, &nodes, &k, ObjType::Map)?;
                let text = object(&self.doc, &n, "text", ObjType::Text)
                    .and_then(|t| self.doc.text(&t).ok());
                Some((
                    k.clone(),
                    Node {
                        id: k,
                        kind: scalar(&self.doc, &n, "kind").and_then(|s| NodeKind::parse(&s)),
                        placements: scalars(&self.doc, &n, "placement"),
                        lifecycles: scalars(&self.doc, &n, "lifecycle"),
                        task_id: scalar(&self.doc, &n, "task_id"),
                        text,
                        children: object(&self.doc, &n, "children", ObjType::List)
                            .map(|l| list_strings(&self.doc, &l))
                            .unwrap_or_default(),
                    },
                ))
            })
            .collect()
    }

    /// Every placement, by PlacementId.
    pub fn placements(&self) -> BTreeMap<String, Placement> {
        let Some(placements) = self.root_map("placements") else {
            return BTreeMap::new();
        };
        self.keys("placements")
            .into_iter()
            .filter_map(|k| {
                let p = object(&self.doc, &placements, &k, ObjType::Map)?;
                Some((
                    k.clone(),
                    Placement {
                        id: k,
                        node_id: scalar(&self.doc, &p, "node_id"),
                        parent_id: scalar(&self.doc, &p, "parent_id"),
                    },
                ))
            })
            .collect()
    }

    /// The IDs of the Task objects.
    pub fn task_ids(&self) -> HashSet<String> {
        self.keys("objects").into_iter().collect()
    }

    /// The scalar title of the Task `id`, if it is a scalar string.
    pub fn task_title(&self, id: &str) -> Option<String> {
        let objects = self.root_map("objects")?;
        let task = object(&self.doc, &objects, id, ObjType::Map)?;
        scalar(&self.doc, &task, "title")
    }

    /// Whether every string field of the Task `id` that is present is a
    /// scalar string (SHARED-OBJECTS-PROFILE-01 §30).
    pub fn task_fields_are_scalar(&self, id: &str) -> bool {
        let Some(objects) = self.root_map("objects") else {
            return false;
        };
        let Some(task) = object(&self.doc, &objects, id, ObjType::Map) else {
            return false;
        };
        [
            "id",
            "type",
            "created_by",
            "lifecycle",
            "title",
            "status",
            "priority",
        ]
        .iter()
        .all(|k| !not_scalar(&self.doc, &task, k))
    }

    /// §14.2: the invalid nodes with their diagnostic. An invalid node is
    /// not projected; its descendants are blocked, and the rest of the
    /// section is projected. Placement conflicts are model facts, not
    /// problems: a conflicted node's references are not checked here.
    pub fn node_problems(&self) -> BTreeMap<String, Diagnostic> {
        let Some(nodes_map) = self.root_map("nodes") else {
            return BTreeMap::new();
        };
        let nodes = self.nodes();
        let placements = self.placements();
        let tasks = self.task_ids();
        let section_id = self.section().map(|s| s.id);
        let mut out = BTreeMap::new();
        for (id, node) in &nodes {
            let n = object(&self.doc, &nodes_map, id, ObjType::Map).expect("listed node");
            let mut found: Vec<Diagnostic> = Vec::new();
            if !is_uuidv7(id) {
                found.push(Diagnostic::InvalidObjectId);
            }
            match scalar(&self.doc, &n, "id") {
                Some(own) if own != *id => found.push(Diagnostic::ObjectIdMismatch),
                Some(_) => {}
                None => found.push(Diagnostic::MissingRequiredField),
            }
            for key in ["kind", "created_by", "lifecycle", "placement"] {
                if self.doc.get(&n, key).ok().flatten().is_none() {
                    found.push(Diagnostic::MissingRequiredField);
                }
            }
            for key in [
                "id",
                "kind",
                "created_by",
                "lifecycle",
                "placement",
                "task_id",
                "list_style",
            ] {
                if not_scalar(&self.doc, &n, key) {
                    found.push(Diagnostic::InvalidFieldType);
                }
            }
            if object(&self.doc, &n, "children", ObjType::List).is_none() {
                found.push(Diagnostic::InvalidFieldType);
            }
            match node.kind {
                None => found.push(Diagnostic::InvalidEnumValue),
                Some(NodeKind::Task) => {
                    if node.task_id.as_deref() != Some(id.as_str()) {
                        found.push(Diagnostic::ObjectIdMismatch);
                    }
                    if !tasks.contains(id) {
                        found.push(Diagnostic::InvalidReference);
                    }
                }
                Some(_) => {
                    if object(&self.doc, &n, "text", ObjType::Text).is_none() {
                        found.push(Diagnostic::InvalidFieldType);
                    }
                }
            }
            if node
                .lifecycles
                .iter()
                .any(|l| l != "active" && l != "deleted")
            {
                found.push(Diagnostic::InvalidEnumValue);
            }
            if node.placements.len() == 1 {
                match placements.get(&node.placements[0]) {
                    Some(p) if p.node_id.as_deref() == Some(id.as_str()) => {
                        let parent = p.parent_id.as_deref();
                        let ok = parent.is_some() && parent == section_id.as_deref()
                            || parent
                                .and_then(|p| nodes.get(p))
                                .and_then(|p| p.kind)
                                .is_some_and(NodeKind::can_parent);
                        if !ok {
                            found.push(Diagnostic::InvalidReference);
                        }
                    }
                    _ => found.push(Diagnostic::InvalidReference),
                }
            }
            if let Some(first) = found.into_iter().min() {
                out.insert(id.clone(), first);
            }
        }
        out
    }

    /// Every concurrent value of the Task `id`'s `lifecycle`.
    pub fn task_lifecycles(&self, id: &str) -> Vec<String> {
        let Some(objects) = self.root_map("objects") else {
            return Vec::new();
        };
        match object(&self.doc, &objects, id, ObjType::Map) {
            Some(task) => scalars(&self.doc, &task, "lifecycle"),
            None => Vec::new(),
        }
    }

    /// §7: the effective tree, its structural facts and visibility.
    pub fn effective(&self) -> Effective {
        let nodes = self.nodes();
        let placements = self.placements();
        let invalid = self.node_problems();
        let section = self.section();
        let section_id = section.as_ref().map(|s| s.id.clone()).unwrap_or_default();
        let lifecycles = |id: &str, node: &Node| match node.kind {
            Some(NodeKind::Task) => self.task_lifecycles(id),
            _ => node.lifecycles.clone(),
        };
        // Steps 2-3: placement conflicts and the selected parent of every
        // node whose selected placement resolves (the engine-selected value
        // of the register, used only to follow the graph).
        let mut blocked: BTreeMap<String, Fact> = BTreeMap::new();
        let mut parents: BTreeMap<String, String> = BTreeMap::new();
        for (id, node) in &nodes {
            if node.placements.len() > 1 {
                blocked.insert(id.clone(), Fact::PlacementConflict);
            }
            let selected = self.selected_placement(id);
            if let Some(p) = selected.and_then(|p| placements.get(&p)) {
                if p.node_id.as_deref() == Some(id.as_str()) {
                    if let Some(parent) = &p.parent_id {
                        parents.insert(id.clone(), parent.clone());
                    }
                }
            }
            if !blocked.contains_key(id) && lifecycles(id, node).len() > 1 {
                blocked.insert(id.clone(), Fact::LifecycleConflict);
            }
        }
        for id in invalid.keys() {
            blocked.remove(id);
        }
        // Step 4: every member of a cycle in the selected parent graph,
        // among nodes not already blocked or invalid.
        let eligible = |n: &str, blocked: &BTreeMap<String, Fact>| {
            nodes.contains_key(n) && !blocked.contains_key(n) && !invalid.contains_key(n)
        };
        let mut cycle: BTreeSet<String> = BTreeSet::new();
        for start in nodes.keys() {
            let mut path: Vec<String> = Vec::new();
            let mut seen: BTreeMap<String, usize> = BTreeMap::new();
            let mut n = start.clone();
            while n != section_id && eligible(&n, &blocked) {
                if let Some(&at) = seen.get(&n) {
                    cycle.extend(path[at..].iter().cloned());
                    break;
                }
                seen.insert(n.clone(), path.len());
                path.push(n.clone());
                match parents.get(&n) {
                    Some(p) => n = p.clone(),
                    None => break,
                }
            }
        }
        for n in cycle {
            blocked.insert(n, Fact::ParentCycle);
        }
        // Step 5: descendants of blocked or invalid nodes, to a fixed point.
        let out = |n: &str, blocked: &BTreeMap<String, Fact>| {
            blocked.contains_key(n) || invalid.contains_key(n)
        };
        loop {
            let more: Vec<String> = nodes
                .keys()
                .filter(|n| !out(n, &blocked) && parents.get(*n).is_some_and(|p| out(p, &blocked)))
                .cloned()
                .collect();
            if more.is_empty() {
                break;
            }
            for n in more {
                blocked.insert(n, Fact::BlockedParent);
            }
        }
        // Step 6: a node is hidden when it, or an ancestor along the
        // selected parents, is deleted.
        let deleted = |n: &str| {
            nodes.get(n).is_some_and(|node| {
                lifecycles(n, node).iter().any(|l| l == "deleted") && lifecycles(n, node).len() == 1
            })
        };
        let mut hidden: BTreeSet<String> = BTreeSet::new();
        for start in nodes.keys() {
            let mut n = start.clone();
            let mut seen: HashSet<String> = HashSet::new();
            while n != section_id && nodes.contains_key(&n) && seen.insert(n.clone()) {
                if deleted(&n) {
                    hidden.insert(start.clone());
                    break;
                }
                match parents.get(&n) {
                    Some(p) => n = p.clone(),
                    None => break,
                }
            }
        }
        // Step 7: scan the children lists from the section, emitting a node
        // only from the placement it selects. Iterative, so depth does not
        // depend on the call stack.
        let mut tree = Vec::new();
        if section.as_ref().is_some_and(|s| s.ready) {
            let mut stack: Vec<(String, usize, Vec<String>)> = Vec::new();
            stack.push((section_id.clone(), 0, section.unwrap().children));
            while let Some((parent, depth, mut lane)) = stack.pop() {
                if lane.is_empty() {
                    continue;
                }
                let slot = lane.remove(0);
                stack.push((parent.clone(), depth, lane));
                let Some(node_id) = placements.get(&slot).and_then(|p| p.node_id.clone()) else {
                    continue;
                };
                let Some(node) = nodes.get(&node_id) else {
                    continue;
                };
                if out(&node_id, &blocked)
                    || hidden.contains(&node_id)
                    || self.selected_placement(&node_id).as_deref() != Some(slot.as_str())
                {
                    continue;
                }
                tree.push(TreeEntry {
                    id: node_id.clone(),
                    parent,
                    depth,
                    kind: node.kind,
                });
                stack.push((node_id, depth + 1, node.children.clone()));
            }
        }
        Effective {
            tree,
            hidden,
            recovery: blocked,
            invalid,
        }
    }

    /// The engine-selected value of the node's placement register.
    fn selected_placement(&self, id: &str) -> Option<String> {
        let nodes = self.root_map("nodes")?;
        let n = object(&self.doc, &nodes, id, ObjType::Map)?;
        scalar(&self.doc, &n, "placement")
    }
}

/// A structural fact of §14.3: the history is valid, and a user resolves it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fact {
    /// Concurrent location assignments of one node.
    PlacementConflict,
    /// A cycle in the selected parent graph.
    ParentCycle,
    /// A node under a conflicted, cyclic or invalid parent.
    BlockedParent,
    /// Concurrent active and deleted values.
    LifecycleConflict,
}

impl Fact {
    /// The fact's name, such as `PLACEMENT_CONFLICT`.
    pub fn name(self) -> &'static str {
        match self {
            Fact::PlacementConflict => "PLACEMENT_CONFLICT",
            Fact::ParentCycle => "PARENT_CYCLE",
            Fact::BlockedParent => "BLOCKED_PARENT",
            Fact::LifecycleConflict => "LIFECYCLE_CONFLICT",
        }
    }
}

/// One node of the effective tree, in scan order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeEntry {
    /// The node.
    pub id: String,
    /// Its parent: the SectionId or a NodeId.
    pub parent: String,
    /// Its depth below the section, from 0.
    pub depth: usize,
    /// Its kind.
    pub kind: Option<NodeKind>,
}

/// The effective structure of a section (§7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Effective {
    /// The projected nodes, in scan order. Empty while the section is being
    /// imported (§12.1).
    pub tree: Vec<TreeEntry>,
    /// Nodes hidden by their own or an ancestor's deletion, retained.
    pub hidden: BTreeSet<String>,
    /// Structural facts by NodeId (§14.3).
    pub recovery: BTreeMap<String, Fact>,
    /// Invalid nodes by NodeId (§14.2).
    pub invalid: BTreeMap<String, Diagnostic>,
}

/// Why an authoring intent was refused before anything was written (§6).
#[derive(Clone, Debug, PartialEq)]
pub enum AuthoringError {
    /// The node does not exist.
    UnknownNode,
    /// The parent is not the section or a valid, visible, unconflicted Task
    /// or item node.
    InvalidParent,
    /// The preceding sibling is not a visible child of the parent.
    InvalidPredecessor,
    /// A node would become its own ancestor (a self-, descendant- or
    /// self-predecessor move).
    WouldCycle,
    /// An ID is not a canonical UUIDv7, or is already used.
    InvalidId,
    /// The engine refused the write.
    Profile(ProfileError),
}

impl From<automerge::AutomergeError> for AuthoringError {
    fn from(e: automerge::AutomergeError) -> AuthoringError {
        AuthoringError::Profile(ProfileError::Automerge(e.to_string()))
    }
}

/// A new node's content (§4.2): a Task's title, or the Text of another kind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NewNode<'a> {
    /// A Task node with its Task (SHARED-OBJECTS-PROFILE-01 §31 fields).
    Task {
        /// The Task title.
        title: &'a str,
    },
    /// A paragraph.
    Paragraph {
        /// Its Text.
        text: &'a str,
    },
    /// A list item.
    Item {
        /// Its Text.
        text: &'a str,
    },
    /// A raw Markdown block.
    Raw {
        /// Its Text.
        text: &'a str,
    },
}

fn put_str(
    doc: &mut AutoCommit,
    obj: &ObjId,
    key: &str,
    value: &str,
) -> Result<(), AuthoringError> {
    doc.put(obj, key, ScalarValue::Str(value.into()))?;
    Ok(())
}

impl SectionsDoc {
    /// An empty document writing as `actor`, for applying a Resource's
    /// changes.
    pub fn new(actor: ActorId) -> SectionsDoc {
        SectionsDoc {
            doc: AutoCommit::new().with_actor(actor),
        }
    }

    /// Load a full-save image and continue writing as `actor`.
    pub fn load_as(save: &[u8], actor: ActorId) -> Result<SectionsDoc, ProfileError> {
        Ok(SectionsDoc {
            doc: load_guarded(save)?.with_actor(actor),
        })
    }

    /// A full-save image (SHARED-OBJECTS-PROFILE-01 §13).
    pub fn save(&mut self) -> Vec<u8> {
        self.doc.save()
    }

    /// Apply changes whose admission is established (§14.1 checks belong
    /// to the receiver; see LFCP-02-022).
    pub fn apply_changes(&mut self, changes: Vec<Change>) -> Result<(), ProfileError> {
        self.doc
            .apply_changes(changes)
            .map_err(|e| ProfileError::Automerge(e.to_string()))
    }

    /// Every change of the document, dependencies first.
    pub fn changes(&mut self) -> Vec<Change> {
        self.doc.get_changes(&[])
    }

    /// Commit the pending operations as one change named `intent`.
    fn commit(&mut self, intent: &str) -> Change {
        let hash = self
            .doc
            .commit_with(
                CommitOptions::default()
                    .with_message(intent.to_owned())
                    .with_time(0),
            )
            .expect("an intent writes at least one operation");
        self.doc
            .get_change_by_hash(&hash)
            .expect("the committed change")
            .clone()
    }

    /// Run `write`; roll back on failure, commit on success (one change).
    fn transact(
        &mut self,
        intent: &str,
        write: impl FnOnce(&mut SectionsDoc) -> Result<(), AuthoringError>,
    ) -> Result<Change, AuthoringError> {
        if let Err(e) = write(self) {
            self.doc.rollback();
            return Err(e);
        }
        Ok(self.commit(intent))
    }

    /// `section.create` (§4.1, §11, §12.1): a new section document in one
    /// change, written by `creator` as `actor`, ready at once.
    pub fn create(
        actor: ActorId,
        section_id: &str,
        title: &str,
        creator: &PrincipalId,
    ) -> Result<(SectionsDoc, Change), AuthoringError> {
        if !is_uuidv7(section_id) {
            return Err(AuthoringError::InvalidId);
        }
        let mut doc = SectionsDoc::new(actor);
        let created_by = crate::shared_objects::identity::principal_ref(creator);
        let change = doc.transact("section.create", |d| {
            let doc = &mut d.doc;
            put_str(doc, &ROOT, "profile", PROFILE)?;
            let section = doc.put_object(ROOT, "section", ObjType::Map)?;
            put_str(doc, &section, "id", section_id)?;
            put_str(doc, &section, "title", title)?;
            put_str(doc, &section, "created_by", &created_by)?;
            doc.put_object(&section, "children", ObjType::List)?;
            doc.put_object(&section, "extensions", ObjType::Map)?;
            doc.put(&section, "ready", ScalarValue::Boolean(true))?;
            for key in ["objects", "nodes", "placements", "extensions"] {
                doc.put_object(ROOT, key, ObjType::Map)?;
            }
            Ok(())
        })?;
        Ok((doc, change))
    }

    /// `section.set_title` (§11): a scalar title.
    pub fn set_title(&mut self, title: &str) -> Result<Change, AuthoringError> {
        let section = self
            .root_map("section")
            .ok_or(AuthoringError::UnknownNode)?;
        self.transact("section.set_title", |d| {
            put_str(&mut d.doc, &section, "title", title)
        })
    }

    /// The children list of `parent` (the section or a node).
    fn lane(&self, parent: &str) -> Option<ObjId> {
        if self.section().is_some_and(|s| s.id == parent) {
            let section = self.root_map("section")?;
            return object(&self.doc, &section, "children", ObjType::List);
        }
        let nodes = self.root_map("nodes")?;
        let node = object(&self.doc, &nodes, parent, ObjType::Map)?;
        object(&self.doc, &node, "children", ObjType::List)
    }

    /// §6 steps 2 and 4-5: the index in `parent`'s list after which a new
    /// placement goes, checking the parent and the preceding sibling.
    fn insertion_index(
        &self,
        parent: &str,
        after: Option<&str>,
    ) -> Result<(ObjId, usize), AuthoringError> {
        let effective = self.effective();
        let section_id = self
            .section()
            .map(|s| s.id)
            .ok_or(AuthoringError::InvalidParent)?;
        if parent != section_id {
            let node = self
                .nodes()
                .get(parent)
                .cloned()
                .ok_or(AuthoringError::InvalidParent)?;
            let visible = effective.tree.iter().any(|t| t.id == parent);
            if !node.kind.is_some_and(NodeKind::can_parent) || !visible {
                return Err(AuthoringError::InvalidParent);
            }
        }
        let lane = self.lane(parent).ok_or(AuthoringError::InvalidParent)?;
        let entries = list_strings(&self.doc, &lane);
        let index = match after {
            None => 0,
            Some(sibling) => {
                let visible_child = effective
                    .tree
                    .iter()
                    .any(|t| t.id == sibling && t.parent == parent);
                let slot = self.selected_placement(sibling);
                match (
                    visible_child,
                    slot.and_then(|s| entries.iter().position(|e| *e == s)),
                ) {
                    (true, Some(i)) => i + 1,
                    _ => return Err(AuthoringError::InvalidPredecessor),
                }
            }
        };
        Ok((lane, index))
    }

    /// Write a new placement of `node` under `parent` at `index` of `lane`
    /// and select it (§4.3, §5: created, inserted and assigned at once).
    fn place(
        &mut self,
        node: &str,
        parent: &str,
        lane: &ObjId,
        index: usize,
        placement_id: &str,
        author: &str,
    ) -> Result<(), AuthoringError> {
        let placements = self
            .root_map("placements")
            .ok_or(AuthoringError::InvalidParent)?;
        let nodes = self
            .root_map("nodes")
            .ok_or(AuthoringError::InvalidParent)?;
        let doc = &mut self.doc;
        let p = doc.put_object(&placements, placement_id, ObjType::Map)?;
        put_str(doc, &p, "id", placement_id)?;
        put_str(doc, &p, "node_id", node)?;
        put_str(doc, &p, "parent_id", parent)?;
        put_str(doc, &p, "created_by", author)?;
        doc.insert(lane, index, ScalarValue::Str(placement_id.into()))?;
        let n = object(doc, &nodes, node, ObjType::Map).ok_or(AuthoringError::UnknownNode)?;
        put_str(doc, &n, "placement", placement_id)?;
        Ok(())
    }

    fn fresh(&self, id: &str) -> bool {
        is_uuidv7(id)
            && !self.nodes().contains_key(id)
            && !self.placements().contains_key(id)
            && !self.task_ids().contains(id)
    }

    /// `task.create_in_section`, `paragraph.create`, `item.create`,
    /// `raw.create` (§11): a node, its Task or Text, its children list and
    /// its placement, in one change. `after` is the preceding visible
    /// sibling; `None` inserts first.
    pub fn create_node(
        &mut self,
        node_id: &str,
        content: NewNode<'_>,
        parent: &str,
        after: Option<&str>,
        placement_id: &str,
        author: &PrincipalId,
    ) -> Result<Change, AuthoringError> {
        if !self.fresh(node_id) || !self.fresh(placement_id) || node_id == placement_id {
            return Err(AuthoringError::InvalidId);
        }
        let (lane, index) = self.insertion_index(parent, after)?;
        let author = crate::shared_objects::identity::principal_ref(author);
        let (intent, kind) = match content {
            NewNode::Task { .. } => ("task.create_in_section", "task"),
            NewNode::Paragraph { .. } => ("paragraph.create", "paragraph"),
            NewNode::Item { .. } => ("item.create", "item"),
            NewNode::Raw { .. } => ("raw.create", "raw"),
        };
        let nodes = self
            .root_map("nodes")
            .ok_or(AuthoringError::InvalidParent)?;
        let objects = self
            .root_map("objects")
            .ok_or(AuthoringError::InvalidParent)?;
        self.transact(intent, |d| {
            let doc = &mut d.doc;
            let n = doc.put_object(&nodes, node_id, ObjType::Map)?;
            put_str(doc, &n, "id", node_id)?;
            put_str(doc, &n, "kind", kind)?;
            put_str(doc, &n, "created_by", &author)?;
            put_str(doc, &n, "lifecycle", "active")?;
            doc.put_object(&n, "children", ObjType::List)?;
            doc.put_object(&n, "extensions", ObjType::Map)?;
            match content {
                NewNode::Task { title } => {
                    put_str(doc, &n, "task_id", node_id)?;
                    put_str(doc, &n, "list_style", "bullet")?;
                    let t = doc.put_object(&objects, node_id, ObjType::Map)?;
                    for (key, value) in [
                        ("id", node_id),
                        ("type", "task"),
                        ("created_by", author.as_str()),
                        ("lifecycle", "active"),
                        ("title", title),
                        ("status", "todo"),
                        ("priority", "normal"),
                    ] {
                        put_str(doc, &t, key, value)?;
                    }
                    for key in ["tags", "assignees", "extensions"] {
                        doc.put_object(&t, key, ObjType::Map)?;
                    }
                }
                NewNode::Paragraph { text } | NewNode::Item { text } | NewNode::Raw { text } => {
                    if kind == "item" {
                        put_str(doc, &n, "list_style", "bullet")?;
                    }
                    let t = doc.put_object(&n, "text", ObjType::Text)?;
                    doc.splice_text(&t, 0, 0, text)?;
                }
            }
            d.place(node_id, parent, &lane, index, placement_id, &author)
        })
    }

    /// Whether `ancestor` is `node` or one of its selected ancestors.
    fn is_ancestor(&self, ancestor: &str, node: &str) -> bool {
        let placements = self.placements();
        let mut n = node.to_owned();
        let mut seen = HashSet::new();
        while seen.insert(n.clone()) {
            if n == ancestor {
                return true;
            }
            match self
                .selected_placement(&n)
                .and_then(|p| placements.get(&p).and_then(|p| p.parent_id.clone()))
            {
                Some(p) => n = p,
                None => return false,
            }
        }
        false
    }

    /// `node.move` (§5, §6): a new placement under `parent` after `after`,
    /// selected by the node's register; the node keeps its identity and
    /// descendants, and the old placement stays as an invisible slot.
    pub fn move_node(
        &mut self,
        node: &str,
        parent: &str,
        after: Option<&str>,
        placement_id: &str,
        author: &PrincipalId,
    ) -> Result<Change, AuthoringError> {
        self.relocate("node.move", node, parent, after, placement_id, author)
    }

    /// `node.resolve_placement` (§8): a fresh placement at the chosen valid
    /// location, superseding every placement observed in the register.
    pub fn resolve_placement(
        &mut self,
        node: &str,
        parent: &str,
        after: Option<&str>,
        placement_id: &str,
        author: &PrincipalId,
    ) -> Result<Change, AuthoringError> {
        self.relocate(
            "node.resolve_placement",
            node,
            parent,
            after,
            placement_id,
            author,
        )
    }

    fn relocate(
        &mut self,
        intent: &str,
        node: &str,
        parent: &str,
        after: Option<&str>,
        placement_id: &str,
        author: &PrincipalId,
    ) -> Result<Change, AuthoringError> {
        if !self.nodes().contains_key(node) {
            return Err(AuthoringError::UnknownNode);
        }
        if after == Some(node) || self.is_ancestor(node, parent) {
            return Err(AuthoringError::WouldCycle);
        }
        if !self.fresh(placement_id) {
            return Err(AuthoringError::InvalidId);
        }
        let (lane, index) = self.insertion_index(parent, after)?;
        let author = crate::shared_objects::identity::principal_ref(author);
        self.transact(intent, |d| {
            d.place(node, parent, &lane, index, placement_id, &author)
        })
    }
}
