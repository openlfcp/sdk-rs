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
//! | admission of received changes (SOP §§7–18, then A1–A5) | [`SectionsReplica`], [`Refusal`] | §2, §14.1 |
//! | lifecycle, Text, split and join, retained concurrent edits | [`SectionsDoc::delete_node`], [`SectionsDoc::restore_node`], [`SectionsDoc::text_edit`], [`SectionsDoc::split`], [`SectionsDoc::join`], [`SectionsDoc::retained_concurrent_edits`] | §9, §10 |

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use automerge::transaction::{CommitOptions, Transactable};
use automerge::{
    ActorId, AutoCommit, Change, ChangeHash, ObjId, ObjType, ReadDoc, ScalarValue, Value, ROOT,
};

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
            .filter_map(|k| Some((k.clone(), self.node_in(&nodes, k)?)))
            .collect()
    }

    /// The node `id` of the `nodes` map, as read.
    fn node_in(&self, nodes: &ObjId, id: String) -> Option<Node> {
        let n = object(&self.doc, nodes, &id, ObjType::Map)?;
        let text =
            object(&self.doc, &n, "text", ObjType::Text).and_then(|t| self.doc.text(&t).ok());
        Some(Node {
            id,
            kind: scalar(&self.doc, &n, "kind").and_then(|s| NodeKind::parse(&s)),
            placements: scalars(&self.doc, &n, "placement"),
            lifecycles: scalars(&self.doc, &n, "lifecycle"),
            task_id: scalar(&self.doc, &n, "task_id"),
            text,
            children: object(&self.doc, &n, "children", ObjType::List)
                .map(|l| list_strings(&self.doc, &l))
                .unwrap_or_default(),
        })
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

    /// §14.2: the IDs under which `nodes`, `objects` or `placements` holds
    /// concurrent values, an `OBJECT_ID_COLLISION` (SOP §21).
    pub fn collisions(&self) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for key in ["nodes", "objects", "placements"] {
            let Some(map) = self.root_map(key) else {
                continue;
            };
            for k in self.doc.keys(&map) {
                if self.doc.get_all(&map, &k).map_or(0, |v| v.len()) > 1 {
                    out.insert(k);
                }
            }
        }
        out
    }

    /// The nodes whose own ID, Task ID or selected PlacementId collides:
    /// they are not validated or projected, and no value is chosen (§14.2).
    fn collided(&self, collisions: &BTreeSet<String>) -> BTreeSet<String> {
        self.keys("nodes")
            .into_iter()
            .filter(|n| {
                collisions.contains(n)
                    || self
                        .selected_placement(n)
                        .is_some_and(|p| collisions.contains(&p))
            })
            .collect()
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
        let collided = self.collided(&self.collisions());
        let mut out = BTreeMap::new();
        for (id, node) in &nodes {
            if collided.contains(id) {
                continue;
            }
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
        let collisions = self.collisions();
        let collided = self.collided(&collisions);
        let section = self.section();
        let section_id = section.as_ref().map(|s| s.id.clone()).unwrap_or_default();
        // §14.3: the distinct concurrent values; equal values agree.
        let lifecycles = |id: &str, node: &Node| {
            let mut values = match node.kind {
                Some(NodeKind::Task) => self.task_lifecycles(id),
                _ => node.lifecycles.clone(),
            };
            values.dedup();
            values
        };
        // Steps 2-3: placement conflicts and the selected parent of every
        // node whose selected placement resolves (the engine-selected value
        // of the register, used only to follow the graph).
        let mut blocked: BTreeMap<String, Fact> = BTreeMap::new();
        let mut parents: BTreeMap<String, String> = BTreeMap::new();
        for (id, node) in &nodes {
            if collided.contains(id) {
                continue;
            }
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
            nodes.contains_key(n)
                && !blocked.contains_key(n)
                && !invalid.contains_key(n)
                && !collided.contains(n)
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
            blocked.contains_key(n) || invalid.contains_key(n) || collided.contains(n)
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
            collisions,
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
    /// The colliding IDs, `OBJECT_ID_COLLISION` (§14.2).
    pub collisions: BTreeSet<String>,
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
    /// An ID is not a canonical UUIDv7.
    InvalidId,
    /// A new ID is already used in the Resource (§3).
    IdInUse,
    /// The node's Text changed since the base the edit was computed on
    /// (§10): its offsets must be rebased first.
    StaleBase,
    /// The intent does not apply to this node: a Text edit of a Task, a
    /// split of a conflicted node, or a join of non-adjacent, different or
    /// parenting nodes (§10).
    NotApplicable,
    /// The engine refused the write.
    Profile(ProfileError),
}

impl AuthoringError {
    /// The refusal code of SDK-SECTIONS-INTEGRATION-01 §3.6, the same in
    /// every SDK.
    pub fn code(&self) -> &'static str {
        match self {
            AuthoringError::UnknownNode => "UNKNOWN_NODE",
            AuthoringError::InvalidParent | AuthoringError::WouldCycle => "INVALID_PARENT",
            AuthoringError::InvalidPredecessor => "INVALID_PREDECESSOR",
            AuthoringError::InvalidId | AuthoringError::NotApplicable => "INVALID_INTENT",
            AuthoringError::IdInUse => "ID_IN_USE",
            AuthoringError::StaleBase => "STALE_BASE",
            AuthoringError::Profile(_) => "PROFILE_INVALID",
        }
    }
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

    /// `ids` are new IDs for one intent: canonical UUIDv7s
    /// ([`AuthoringError::InvalidId`]) not used in the Resource nor twice
    /// among themselves ([`AuthoringError::IdInUse`], §3).
    fn check_new(&self, ids: &[&str]) -> Result<(), AuthoringError> {
        if ids.iter().any(|id| !is_uuidv7(id)) {
            return Err(AuthoringError::InvalidId);
        }
        let (nodes, placements, tasks) = (self.nodes(), self.placements(), self.task_ids());
        let mut seen = HashSet::new();
        for id in ids {
            let used =
                nodes.contains_key(*id) || placements.contains_key(*id) || tasks.contains(*id);
            if used || !seen.insert(*id) {
                return Err(AuthoringError::IdInUse);
            }
        }
        Ok(())
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
        self.check_new(&[node_id, placement_id])?;
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
        self.check_new(&[placement_id])?;
        let (lane, index) = self.insertion_index(parent, after)?;
        let author = crate::shared_objects::identity::principal_ref(author);
        self.transact(intent, |d| {
            d.place(node, parent, &lane, index, placement_id, &author)
        })
    }
}

impl SectionsDoc {
    /// The map holding `node`'s lifecycle: the Task object for a Task
    /// node, the node map otherwise (§4.2, §9).
    fn lifecycle_map(&self, node: &str) -> Result<ObjId, AuthoringError> {
        let n = self
            .nodes()
            .get(node)
            .cloned()
            .ok_or(AuthoringError::UnknownNode)?;
        let map = if n.kind == Some(NodeKind::Task) {
            "objects"
        } else {
            "nodes"
        };
        let root = self.root_map(map).ok_or(AuthoringError::UnknownNode)?;
        object(&self.doc, &root, node, ObjType::Map).ok_or(AuthoringError::UnknownNode)
    }

    /// Write `value` to a lifecycle register as a fresh causal assignment
    /// (§9): when the visible value already equals it, the engine would
    /// skip the write, so the other valid value is written first in the
    /// same change.
    fn assign_lifecycle(&mut self, map: &ObjId, value: &str) -> Result<(), AuthoringError> {
        if scalar(&self.doc, map, "lifecycle").as_deref() == Some(value) {
            let other = if value == "active" {
                "deleted"
            } else {
                "active"
            };
            put_str(&mut self.doc, map, "lifecycle", other)?;
        }
        put_str(&mut self.doc, map, "lifecycle", value)
    }

    /// `node.delete` (§9): the node's lifecycle, or its Task's, becomes
    /// `deleted`. Descendants are not rewritten; they are hidden and kept.
    pub fn delete_node(&mut self, node: &str) -> Result<Change, AuthoringError> {
        let map = self.lifecycle_map(node)?;
        self.transact("node.delete", |d| d.assign_lifecycle(&map, "deleted"))
    }

    /// `node.restore` (§9): the node's lifecycle, or its Task's, becomes
    /// `active` as a fresh assignment, so it also resolves a concurrent
    /// delete. Descendants with their own tombstones stay deleted.
    pub fn restore_node(&mut self, node: &str) -> Result<Change, AuthoringError> {
        let map = self.lifecycle_map(node)?;
        self.transact("node.restore", |d| d.assign_lifecycle(&map, "active"))
    }

    /// The Text object of a paragraph, item or raw node.
    fn text_of(&self, node: &str) -> Result<ObjId, AuthoringError> {
        let nodes = self.root_map("nodes").ok_or(AuthoringError::UnknownNode)?;
        let n = object(&self.doc, &nodes, node, ObjType::Map).ok_or(AuthoringError::UnknownNode)?;
        object(&self.doc, &n, "text", ObjType::Text).ok_or(AuthoringError::NotApplicable)
    }

    /// The document heads, a base for [`SectionsDoc::text_edit`].
    pub fn heads(&mut self) -> Vec<ChangeHash> {
        self.doc.get_heads()
    }

    /// `text.edit` (§10): delete `delete` and insert `insert` at `index`,
    /// both in Unicode scalar values, in the node's existing Text. `base`
    /// is the heads the offsets were computed at; if the node's Text has
    /// changed since, the edit is refused ([`AuthoringError::StaleBase`])
    /// rather than applied to a different text. Callers keep each change
    /// within the Text budget of §16.2 by splitting long edits (§12.3).
    pub fn text_edit(
        &mut self,
        node: &str,
        base: &[ChangeHash],
        index: usize,
        delete: usize,
        insert: &str,
    ) -> Result<Change, AuthoringError> {
        let text = self.text_of(node)?;
        let then = self
            .doc
            .text_at(&text, base)
            .map_err(|_| AuthoringError::StaleBase)?;
        if then != self.doc.text(&text)? {
            return Err(AuthoringError::StaleBase);
        }
        self.transact("text.edit", |d| {
            d.doc.splice_text(&text, index, delete as isize, insert)?;
            Ok(())
        })
    }

    /// `paragraph.split` / `item.split` (§10): the node keeps the prefix up
    /// to `index` (Unicode scalar values); a new node of the same kind,
    /// right after it under the same parent, takes the suffix. An item's
    /// children stay with the original. One change.
    pub fn split(
        &mut self,
        node: &str,
        index: usize,
        new_node: &str,
        placement_id: &str,
        author: &PrincipalId,
    ) -> Result<Change, AuthoringError> {
        let current = self
            .nodes()
            .get(node)
            .cloned()
            .ok_or(AuthoringError::UnknownNode)?;
        if !matches!(current.kind, Some(NodeKind::Paragraph | NodeKind::Item))
            || current.placements.len() != 1
        {
            return Err(AuthoringError::NotApplicable);
        }
        self.check_new(&[new_node, placement_id])?;
        let parent = self
            .placements()
            .get(&current.placements[0])
            .and_then(|p| p.parent_id.clone())
            .ok_or(AuthoringError::NotApplicable)?;
        let (lane, at) = self.insertion_index(&parent, Some(node))?;
        let text = self.text_of(node)?;
        let whole = self.doc.text(&text)?;
        let length = whole.chars().count();
        if index > length {
            return Err(AuthoringError::NotApplicable);
        }
        let suffix: String = whole.chars().skip(index).collect();
        let kind = if current.kind == Some(NodeKind::Item) {
            "item"
        } else {
            "paragraph"
        };
        let nodes = self.root_map("nodes").ok_or(AuthoringError::UnknownNode)?;
        let author = crate::shared_objects::identity::principal_ref(author);
        let intent = if kind == "item" {
            "item.split"
        } else {
            "paragraph.split"
        };
        self.transact(intent, |d| {
            d.doc
                .splice_text(&text, index, (length - index) as isize, "")?;
            let doc = &mut d.doc;
            let n = doc.put_object(&nodes, new_node, ObjType::Map)?;
            put_str(doc, &n, "id", new_node)?;
            put_str(doc, &n, "kind", kind)?;
            put_str(doc, &n, "created_by", &author)?;
            put_str(doc, &n, "lifecycle", "active")?;
            if kind == "item" {
                put_str(doc, &n, "list_style", "bullet")?;
            }
            doc.put_object(&n, "children", ObjType::List)?;
            doc.put_object(&n, "extensions", ObjType::Map)?;
            let t = doc.put_object(&n, "text", ObjType::Text)?;
            doc.splice_text(&t, 0, 0, &suffix)?;
            d.place(new_node, &parent, &lane, at, placement_id, &author)
        })
    }

    /// `node.join` (§10): `second`, the next visible sibling of `first`, of
    /// the same kind and with no children like `first`, is appended to
    /// `first` after `separator` and tombstoned; its own Text stays under
    /// the tombstone. One change.
    pub fn join(
        &mut self,
        first: &str,
        second: &str,
        separator: &str,
    ) -> Result<Change, AuthoringError> {
        let nodes = self.nodes();
        let (a, b) = match (nodes.get(first), nodes.get(second)) {
            (Some(a), Some(b)) => (a.clone(), b.clone()),
            _ => return Err(AuthoringError::UnknownNode),
        };
        let effective = self.effective();
        let pos = |id: &str| effective.tree.iter().position(|t| t.id == id);
        let adjacent = match (pos(first), pos(second)) {
            (Some(i), Some(j)) => {
                j == i + 1 && effective.tree[i].parent == effective.tree[j].parent
            }
            _ => false,
        };
        if !adjacent
            || a.kind != b.kind
            || !matches!(a.kind, Some(NodeKind::Paragraph | NodeKind::Item))
            || !a.children.is_empty()
            || !b.children.is_empty()
        {
            return Err(AuthoringError::NotApplicable);
        }
        let target = self.text_of(first)?;
        let appended = format!("{separator}{}", b.text.clone().unwrap_or_default());
        let length = self.doc.text(&target)?.chars().count();
        let map = self.lifecycle_map(second)?;
        self.transact("node.join", |d| {
            d.doc.splice_text(&target, length, 0, &appended)?;
            d.assign_lifecycle(&map, "deleted")
        })
    }

    /// §9: nodes whose content changed concurrently with the deletion of
    /// the node itself or an ancestor, while they are hidden
    /// (`EDIT_UNDER_DELETED_ANCESTOR`). A content change is a node's
    /// creation, an edit of its Text, or of its Task's title or status;
    /// concurrency is decided from the changes' dependencies. It does not
    /// alter convergence.
    pub fn retained_concurrent_edits(&mut self) -> BTreeSet<String> {
        let effective = self.effective();
        let changes = self.doc.get_changes(&[]);
        let mut deps: BTreeMap<ChangeHash, Vec<ChangeHash>> = BTreeMap::new();
        let mut contents: Vec<(ChangeHash, String)> = Vec::new();
        let mut deletes: Vec<(ChangeHash, String)> = Vec::new();
        // Which node each object belongs to: its map, its Text, its Task.
        // Automerge object IDs are the same in every replica of the history.
        let owners = self.node_objects();
        let nodes_map = self.root_map("nodes").map(|o| o.to_string());
        let objects_map = self.root_map("objects").map(|o| o.to_string());
        // Replay change by change and compare, for the nodes a change
        // touches, their state before and after it.
        let mut replay = SectionsDoc::new(ActorId::from([0u8; 32]));
        for change in changes {
            let hash = change.hash();
            deps.insert(hash, change.deps().to_vec());
            let mut touched: BTreeSet<String> = BTreeSet::new();
            for op in change.decode().operations {
                let obj = op.obj.to_string();
                if let Some(node) = owners.get(&obj) {
                    touched.insert(node.clone());
                } else if Some(&obj) == nodes_map.as_ref() || Some(&obj) == objects_map.as_ref() {
                    if let automerge::legacy::Key::Map(key) = &op.key {
                        touched.insert(key.to_string());
                    }
                }
            }
            let before = replay.node_states(&touched);
            replay
                .doc
                .apply_changes(vec![change])
                .expect("a change of this document");
            for (n, now) in replay.node_states(&touched) {
                let old = before.get(&n);
                if old.is_none_or(|o| o.content != now.content) {
                    contents.push((hash, n.clone()));
                }
                if now.deleted && !old.is_some_and(|o| o.deleted) {
                    deletes.push((hash, n));
                }
            }
        }
        let ancestor = |a: &ChangeHash, b: &ChangeHash| -> bool {
            let mut stack = vec![*b];
            let mut seen = HashSet::new();
            while let Some(h) = stack.pop() {
                if h == *a {
                    return true;
                }
                if seen.insert(h) {
                    stack.extend(deps.get(&h).cloned().unwrap_or_default());
                }
            }
            false
        };
        let parents: BTreeMap<String, String> = {
            let placements = self.placements();
            self.nodes()
                .keys()
                .filter_map(|n| {
                    let p = self.selected_placement(n)?;
                    Some((n.clone(), placements.get(&p)?.parent_id.clone()?))
                })
                .collect()
        };
        let mut out = BTreeSet::new();
        for (edit, node) in &contents {
            if !effective.hidden.contains(node) {
                continue;
            }
            let known = self.nodes();
            let mut p = node.clone();
            let mut seen = HashSet::new();
            while known.contains_key(&p) && seen.insert(p.clone()) {
                for (delete, deleted) in &deletes {
                    if *deleted == p && !ancestor(delete, edit) && !ancestor(edit, delete) {
                        out.insert(node.clone());
                    }
                }
                match parents.get(&p) {
                    Some(next) => p = next.clone(),
                    None => break,
                }
            }
        }
        out
    }

    /// The node each node map, node Text and Task map belongs to, by
    /// Automerge object ID.
    fn node_objects(&self) -> HashMap<String, String> {
        let mut out = HashMap::new();
        let (Some(nodes), objects) = (self.root_map("nodes"), self.root_map("objects")) else {
            return out;
        };
        for id in self.keys("nodes") {
            if let Some(n) = object(&self.doc, &nodes, &id, ObjType::Map) {
                if let Some(text) = object(&self.doc, &n, "text", ObjType::Text) {
                    out.insert(text.to_string(), id.clone());
                }
                out.insert(n.to_string(), id.clone());
            }
            if let Some(task) = objects
                .as_ref()
                .and_then(|o| object(&self.doc, o, &id, ObjType::Map))
            {
                out.insert(task.to_string(), id.clone());
            }
        }
        out
    }

    /// For the nodes of `ids` that exist: their content (Text, or Task
    /// title and status) and whether they are deleted, for
    /// [`SectionsDoc::retained_concurrent_edits`].
    fn node_states(&self, ids: &BTreeSet<String>) -> BTreeMap<String, NodeState> {
        let Some(nodes) = self.root_map("nodes") else {
            return BTreeMap::new();
        };
        ids.iter()
            .filter_map(|id| Some((id.clone(), self.node_in(&nodes, id.clone())?)))
            .map(|(id, node)| {
                let (content, lifecycle) = if node.kind == Some(NodeKind::Task) {
                    let objects = self.root_map("objects");
                    let task = objects.and_then(|o| object(&self.doc, &o, &id, ObjType::Map));
                    let field = |k| task.as_ref().and_then(|t| scalar(&self.doc, t, k));
                    (
                        format!("{:?}|{:?}", field("title"), field("status")),
                        field("lifecycle"),
                    )
                } else {
                    let nodes = self.root_map("nodes").expect("nodes");
                    let n = object(&self.doc, &nodes, &id, ObjType::Map).expect("node");
                    (
                        node.text.clone().unwrap_or_default(),
                        scalar(&self.doc, &n, "lifecycle"),
                    )
                };
                (
                    id,
                    NodeState {
                        content,
                        deleted: lifecycle.as_deref() == Some("deleted"),
                    },
                )
            })
            .collect()
    }
}

/// A node's content and deletion at one point of the history.
struct NodeState {
    content: String,
    deleted: bool,
}

/// Why a received change was refused at admission (§14.1). The first two
/// are SHARED-OBJECTS-PROFILE-01's (§11, §11.1, §11.2, §14.1, §8); the
/// others are this profile's structural rules A1-A5, in this order of
/// precedence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Refusal {
    /// Not a valid change chunk within the limits, or a sequence gap, an
    /// unknown actor or an object too deep.
    InvalidAutomergeBytes,
    /// The change is not a change of the signer's actor (§2).
    ChangeActorMismatch,
    /// A4: a container is replaced or deleted.
    ContainerReplaced,
    /// A1: an element of a children list is deleted or replaced.
    ChildrenListMutated,
    /// A2: a placement is not created, inserted once and assigned together.
    PlacementNotAtomic,
    /// A3: an immutable field or placement is written, or `ready` against §12.1.
    ImmutableFieldMutated,
    /// A5: Text where a scalar is required, or the reverse.
    InvalidFieldType,
}

impl Refusal {
    /// The diagnostic name, such as `CHILDREN_LIST_MUTATED`.
    pub fn name(self) -> &'static str {
        match self {
            Refusal::InvalidAutomergeBytes => "INVALID_AUTOMERGE_BYTES",
            Refusal::ChangeActorMismatch => "CHANGE_ACTOR_MISMATCH",
            Refusal::ContainerReplaced => "CONTAINER_REPLACED",
            Refusal::ChildrenListMutated => "CHILDREN_LIST_MUTATED",
            Refusal::PlacementNotAtomic => "PLACEMENT_NOT_ATOMIC",
            Refusal::ImmutableFieldMutated => "IMMUTABLE_FIELD_MUTATED",
            Refusal::InvalidFieldType => "INVALID_FIELD_TYPE",
        }
    }
}

/// What became of one received Data Unit plaintext.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Received {
    /// The change entered the document (with any waiting changes it
    /// released).
    Applied,
    /// The document already holds it.
    Duplicate,
    /// Its actor sequence is taken (POST-001): held until a rebuild.
    Held,
    /// A dependency is not in the document yet: kept and retried.
    Waiting,
    /// Refused at admission; never merged.
    Refused(Refusal),
}

/// A receiving replica of one section Resource: every change goes through
/// SHARED-OBJECTS-PROFILE-01's admission (§§7-18, shared with the Shared
/// Objects profile, not copied) and then this profile's structural rules,
/// decided against the change's causal history (§14.1).
#[derive(Debug)]
pub struct SectionsReplica {
    resource: ResourceId,
    engine: crate::shared_objects::document::SharedObjects,
    waiting: Vec<Change>,
    refused: BTreeMap<ChangeHash, Refusal>,
}

impl SectionsReplica {
    /// An empty replica of `resource`, writing as `actor` if ever.
    pub fn new(resource: ResourceId, actor: ActorId) -> SectionsReplica {
        SectionsReplica {
            resource,
            engine: crate::shared_objects::document::SharedObjects::new(actor),
            waiting: Vec::new(),
            refused: BTreeMap::new(),
        }
    }

    /// Receive the plaintext of a Data Unit signed by `signer`.
    pub fn receive(&mut self, signer: &PrincipalId, plaintext: &[u8]) -> Received {
        let change = match crate::shared_objects::framing::decode_change(plaintext) {
            Ok(c) => c,
            Err(_) => {
                // Recorded by its hash when the bytes still parse as a change
                // (for example one above the §11.1 limits).
                let parsed = crate::shared_objects::framing::unframe(plaintext)
                    .ok()
                    .and_then(|b| Change::from_bytes(b).ok());
                return match parsed {
                    Some(c) => self.refuse(c.hash(), Refusal::InvalidAutomergeBytes),
                    None => Received::Refused(Refusal::InvalidAutomergeBytes),
                };
            }
        };
        if change.actor_id().to_bytes() != actor_id_bytes(&self.resource, signer) {
            // Recorded, but not held against the change: the same change
            // under its own actor's signature is still admitted, so another
            // Principal cannot block a change by forwarding it.
            let hash = change.hash();
            if self.engine.automerge().get_change_by_hash(&hash).is_some() {
                return Received::Refused(Refusal::ChangeActorMismatch);
            }
            return self
                .refused
                .get(&hash)
                .copied()
                .map(Received::Refused)
                .unwrap_or_else(|| self.refuse(hash, Refusal::ChangeActorMismatch));
        }
        let outcome = self.admit(change);
        if outcome == Received::Applied {
            self.retry_waiting();
        }
        outcome
    }

    fn admit(&mut self, change: Change) -> Received {
        let hash = change.hash();
        match self.refused.get(&hash) {
            Some(Refusal::ChangeActorMismatch) => {
                self.refused.remove(&hash);
            }
            Some(r) => return Received::Refused(*r),
            None => {}
        }
        let doc = self.engine.automerge();
        if doc.get_change_by_hash(&hash).is_some() {
            return Received::Duplicate;
        }
        if change
            .deps()
            .iter()
            .any(|d| doc.get_change_by_hash(d).is_none())
        {
            if !self.waiting.iter().any(|c| c.hash() == hash) {
                self.waiting.push(change);
            }
            return Received::Waiting;
        }
        // The state of the change's causal history, before and after it.
        // When the change depends on exactly the current heads, that state
        // is the document itself; otherwise it is rebuilt from the history.
        let mut current = doc.clone();
        let mut heads = current.get_heads();
        heads.sort();
        let mut deps = change.deps().to_vec();
        deps.sort();
        let (prev, mut probe) = if deps == heads {
            (current, self.engine.fork(ActorId::from([0u8; 32])))
        } else {
            let Ok(prev) = current.fork_at(change.deps()) else {
                return self.refuse(hash, Refusal::InvalidAutomergeBytes);
            };
            let mut probe =
                crate::shared_objects::document::SharedObjects::new(ActorId::from([0u8; 32]));
            if probe
                .apply_changes(prev.clone().get_changes(&[]).into_iter().collect())
                .is_err()
            {
                return self.refuse(hash, Refusal::InvalidAutomergeBytes);
            }
            (prev, probe)
        };
        // SOP's admission first: sequence, actors, depth, held (POST-001).
        match probe.apply_change(change.clone()) {
            Ok(crate::shared_objects::document::ChangeOutcome::Applied) => {}
            Ok(_) => {}
            Err(_) => return self.refuse(hash, Refusal::InvalidAutomergeBytes),
        }
        let next = probe.automerge();
        if let Some(r) = structural_refusal(&prev, next, &change, &self.resource) {
            return self.refuse(hash, r);
        }
        match self.engine.apply_change(change) {
            Ok(crate::shared_objects::document::ChangeOutcome::Applied) => Received::Applied,
            Ok(crate::shared_objects::document::ChangeOutcome::Duplicate) => Received::Duplicate,
            Ok(crate::shared_objects::document::ChangeOutcome::Held) => Received::Held,
            Err(_) => self.refuse(hash, Refusal::InvalidAutomergeBytes),
        }
    }

    fn refuse(&mut self, hash: ChangeHash, refusal: Refusal) -> Received {
        self.refused.insert(hash, refusal);
        Received::Refused(refusal)
    }

    fn retry_waiting(&mut self) {
        loop {
            let ready: Vec<Change> = {
                let doc = self.engine.automerge();
                self.waiting
                    .iter()
                    .filter(|c| c.deps().iter().all(|d| doc.get_change_by_hash(d).is_some()))
                    .cloned()
                    .collect()
            };
            if ready.is_empty() {
                return;
            }
            self.waiting
                .retain(|c| !ready.iter().any(|r| r.hash() == c.hash()));
            for change in ready {
                self.admit(change);
            }
        }
    }

    /// The refused changes with their refusal.
    pub fn refused(&self) -> &BTreeMap<ChangeHash, Refusal> {
        &self.refused
    }

    /// The changes still waiting for a dependency: in particular every
    /// change that depends on a refused one.
    pub fn waiting(&self) -> Vec<ChangeHash> {
        let mut out: Vec<ChangeHash> = self.waiting.iter().map(Change::hash).collect();
        out.sort();
        out
    }

    /// A read view of the admitted document.
    pub fn view(&self) -> SectionsDoc {
        SectionsDoc {
            doc: self.engine.automerge().clone(),
        }
    }
}

/// The object at `key` of `obj`, as its ID.
fn object_id(doc: &AutoCommit, obj: &ObjId, key: &str) -> Option<ObjId> {
    match doc.get(obj, key).ok().flatten()? {
        (Value::Object(_), id) => Some(id),
        _ => None,
    }
}

/// Whether `before` is a subsequence of `after`.
fn is_subsequence(before: &[String], after: &[String]) -> bool {
    let mut i = 0;
    for x in after {
        if i < before.len() && *x == before[i] {
            i += 1;
        }
    }
    i == before.len()
}

/// A Text object at `key` of `obj`.
fn is_text(doc: &AutoCommit, obj: &ObjId, key: &str) -> bool {
    matches!(
        doc.get(obj, key).ok().flatten(),
        Some((Value::Object(ObjType::Text), _))
    )
}

/// Every value of a list, scalar strings as themselves and anything else
/// as `None`.
fn list_values(doc: &AutoCommit, list: &ObjId) -> Vec<Option<String>> {
    (0..doc.length(list))
        .map(|i| match doc.get(list, i).ok().flatten() {
            Some((Value::Scalar(s), _)) => match s.as_ref() {
                ScalarValue::Str(s) => Some(s.to_string()),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

/// §14.1: the structural refusal of `change`, given the state `prev` of its
/// causal history and the state `next` after it, or `None`.
fn structural_refusal(
    prev: &AutoCommit,
    next: &AutoCommit,
    change: &Change,
    resource: &ResourceId,
) -> Option<Refusal> {
    let mut found: BTreeSet<Refusal> = BTreeSet::new();
    let a = SectionsDoc { doc: prev.clone() };
    let b = SectionsDoc { doc: next.clone() };
    let initialized = object_id(prev, &ROOT, "section").is_some();
    // A4: root containers and the profile.
    if initialized {
        for key in ROOT_MAPS {
            if object_id(prev, &ROOT, key) != object_id(next, &ROOT, key) {
                found.insert(Refusal::ContainerReplaced);
            }
        }
        if scalar(prev, &ROOT, "profile") != scalar(next, &ROOT, "profile") {
            found.insert(Refusal::ContainerReplaced);
        }
    }
    let ps = object_id(prev, &ROOT, "section");
    let ns = object_id(next, &ROOT, "section");
    if let (Some(ps), Some(ns)) = (&ps, &ns) {
        for key in ["children", "extensions"] {
            if object_id(prev, ps, key).is_some()
                && object_id(prev, ps, key) != object_id(next, ns, key)
            {
                found.insert(Refusal::ContainerReplaced);
            }
        }
        // A3: the section's immutable fields and readiness (§12.1).
        for key in ["id", "created_by"] {
            if scalar(prev, ps, key).is_some() && scalar(prev, ps, key) != scalar(next, ns, key) {
                found.insert(Refusal::ImmutableFieldMutated);
            }
        }
        let ready = |d: &AutoCommit, s: &ObjId| -> Vec<String> {
            let mut v: Vec<String> = d
                .get_all(s, "ready")
                .unwrap_or_default()
                .into_iter()
                .map(|(v, _)| format!("{v:?}"))
                .collect();
            v.sort();
            v
        };
        let (before, after) = (ready(prev, ps), ready(next, ns));
        if before != after {
            let values = next.get_all(ns, "ready").unwrap_or_default();
            let all_true = !values.is_empty()
                && values.iter().all(|(v, _)| matches!(v, Value::Scalar(s) if matches!(s.as_ref(), ScalarValue::Boolean(true))));
            let creator = scalar(next, ns, "created_by")
                .and_then(|r| crate::shared_objects::identity::parse_principal_ref(&r).ok());
            let by_creator = creator
                .is_some_and(|p| change.actor_id().to_bytes() == actor_id_bytes(resource, &p));
            if !all_true || !by_creator {
                found.insert(Refusal::ImmutableFieldMutated);
            }
        }
    }
    // Existing nodes: their maps, containers and immutable fields.
    let (pn, nn) = (
        object_id(prev, &ROOT, "nodes"),
        object_id(next, &ROOT, "nodes"),
    );
    if let (Some(pn), Some(nn)) = (&pn, &nn) {
        for id in prev.keys(pn).collect::<Vec<_>>() {
            let (Some(old), Some(new)) = (object_id(prev, pn, &id), object_id(next, nn, &id))
            else {
                found.insert(Refusal::ContainerReplaced);
                continue;
            };
            if old != new {
                found.insert(Refusal::ContainerReplaced);
                continue;
            }
            for key in ["children", "text", "extensions"] {
                if object_id(prev, &old, key).is_some()
                    && object_id(prev, &old, key) != object_id(next, &new, key)
                {
                    found.insert(Refusal::ContainerReplaced);
                }
            }
            for key in ["id", "kind", "created_by", "task_id"] {
                if scalar(prev, &old, key) != scalar(next, &new, key) {
                    found.insert(Refusal::ImmutableFieldMutated);
                }
            }
        }
    }
    let (po, no) = (
        object_id(prev, &ROOT, "objects"),
        object_id(next, &ROOT, "objects"),
    );
    if let (Some(po), Some(no)) = (&po, &no) {
        for id in prev.keys(po).collect::<Vec<_>>() {
            if let (Some(old), Some(new)) = (object_id(prev, po, &id), object_id(next, no, &id)) {
                for key in ["id", "type", "created_by"] {
                    if scalar(prev, &old, key) != scalar(next, &new, key) {
                        found.insert(Refusal::ImmutableFieldMutated);
                    }
                }
            }
        }
    }
    // A3: placements are immutable once created.
    let (old_placements, new_placements) = (a.placements(), b.placements());
    for (id, p) in &old_placements {
        if new_placements.get(id) != Some(p) {
            found.insert(Refusal::ImmutableFieldMutated);
        }
    }
    // A1, A2, A5 on the children lists.
    let section_id = b.section().map(|s| s.id);
    let mut lanes: Vec<(String, Option<ObjId>, ObjId)> = Vec::new();
    if let (Some(sid), Some(ns)) = (&section_id, &ns) {
        if let Some(l) = object_id(next, ns, "children") {
            lanes.push((
                sid.clone(),
                ps.as_ref().and_then(|p| object_id(prev, p, "children")),
                l,
            ));
        }
    }
    if let Some(nn) = &nn {
        for id in next.keys(nn).collect::<Vec<_>>() {
            let Some(n) = object_id(next, nn, &id) else {
                continue;
            };
            let Some(l) = object_id(next, &n, "children") else {
                continue;
            };
            let old = pn
                .as_ref()
                .and_then(|pn| object_id(prev, pn, &id))
                .and_then(|o| object_id(prev, &o, "children"));
            lanes.push((id, old, l));
        }
    }
    let created: BTreeSet<String> = new_placements
        .keys()
        .filter(|k| !old_placements.contains_key(*k))
        .cloned()
        .collect();
    let mut inserted_into: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (owner, old, new) in &lanes {
        let after = list_values(next, new);
        let before: Vec<String> = match old {
            Some(o) => list_strings(prev, o),
            None => Vec::new(),
        };
        let after_strings: Vec<String> = after
            .iter()
            .map(|v| v.clone().unwrap_or_default())
            .collect();
        if old.is_some() && !is_subsequence(&before, &after_strings) {
            found.insert(Refusal::ChildrenListMutated);
        }
        // The entries `after` adds to `before`, as a multiset.
        let mut left: BTreeMap<String, usize> = BTreeMap::new();
        for x in &before {
            *left.entry(x.clone()).or_default() += 1;
        }
        for v in &after {
            let key = v.clone().unwrap_or_default();
            match left.get_mut(&key) {
                Some(k) if *k > 0 => *k -= 1,
                _ => match v {
                    None => {
                        found.insert(Refusal::InvalidFieldType);
                    }
                    Some(id) if created.contains(id) => {
                        inserted_into
                            .entry(id.clone())
                            .or_default()
                            .push(owner.clone());
                    }
                    Some(_) => {
                        found.insert(Refusal::PlacementNotAtomic);
                    }
                },
            }
        }
    }
    let new_nodes = b.nodes();
    for id in &created {
        let p = &new_placements[id];
        let owners = inserted_into.get(id).cloned().unwrap_or_default();
        if owners.len() != 1 || Some(&owners[0]) != p.parent_id.as_ref() {
            found.insert(Refusal::PlacementNotAtomic);
        }
        let selected = p
            .node_id
            .as_ref()
            .and_then(|n| new_nodes.get(n))
            .is_some_and(|n| n.placements.contains(id));
        if !selected {
            found.insert(Refusal::PlacementNotAtomic);
        }
    }
    // A5: scalars stay scalar; a paragraph, item or raw node's text is Text.
    if let Some(nn) = &nn {
        for id in next.keys(nn).collect::<Vec<_>>() {
            let Some(n) = object_id(next, nn, &id) else {
                continue;
            };
            let old = pn.as_ref().and_then(|pn| object_id(prev, pn, &id));
            for key in [
                "id",
                "kind",
                "created_by",
                "lifecycle",
                "placement",
                "task_id",
                "list_style",
            ] {
                let changed =
                    old.as_ref().map(|o| object_id(prev, o, key)) != Some(object_id(next, &n, key));
                if is_text(next, &n, key) && (old.is_none() || changed) {
                    found.insert(Refusal::InvalidFieldType);
                }
            }
            let kind = scalar(next, &n, "kind");
            if matches!(kind.as_deref(), Some("paragraph" | "item" | "raw"))
                && next.get(&n, "text").ok().flatten().is_some()
                && !is_text(next, &n, "text")
            {
                found.insert(Refusal::InvalidFieldType);
            }
        }
    }
    if let Some(no) = &no {
        for id in next.keys(no).collect::<Vec<_>>() {
            let Some(t) = object_id(next, no, &id) else {
                continue;
            };
            let old = po.as_ref().and_then(|po| object_id(prev, po, &id));
            for key in [
                "id",
                "type",
                "created_by",
                "lifecycle",
                "title",
                "status",
                "priority",
                "due",
                "scheduled",
                "completion_date",
                "created_at",
            ] {
                let changed =
                    old.as_ref().map(|o| object_id(prev, o, key)) != Some(object_id(next, &t, key));
                if is_text(next, &t, key) && (old.is_none() || changed) {
                    found.insert(Refusal::InvalidFieldType);
                }
            }
        }
    }
    found.into_iter().next()
}
