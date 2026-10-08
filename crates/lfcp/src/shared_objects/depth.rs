//! Document depth (SHARED-OBJECTS-PROFILE-01 §11.2).
//!
//! The document root has depth 0; an object (map, list, text or table)
//! created by an operation has the depth of the object the operation writes
//! into, plus one, and keeps it even after it is deleted or becomes
//! unreachable. No object may be deeper than [`MAX_DEPTH`]: Automerge JS
//! 3.5.0 traps applying a change about 6,500 levels below the root, and
//! its wasm module stops for the whole process. Total depth is what
//! matters, so a document keeps the depth of every object it holds and
//! checks each change, and each Snapshot, without recursion.

use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};

use automerge::legacy::{ObjectId, OpType};
use automerge::{ActorId, AutoCommit, Change};

use crate::shared_objects::{Diagnostic, ProfileError};

/// The deepest an object of a document may be (§11.2).
pub const MAX_DEPTH: u32 = 256;

const INVALID: ProfileError = ProfileError::Invalid(Diagnostic::InvalidAutomergeBytes);

/// An object's ID: the counter and actor of the operation that created it.
pub(crate) type ObjKey = (u64, ActorId);

/// The depth of every object of a document.
pub(crate) type Depths = HashMap<ObjKey, u32>;

/// The objects `change` creates, with their depths, in operation order.
///
/// `known` gives the depth of an object the document (or an earlier change
/// of a batch) already holds. An operation writing into an object neither
/// known nor created earlier in the change is `INVALID_AUTOMERGE_BYTES`; so
/// is an object deeper than `limit` (`None`: no limit, for history already
/// held).
pub(crate) fn created_objects(
    change: &Change,
    known: impl Fn(&ObjKey) -> Option<u32>,
    limit: Option<u32>,
) -> Result<Vec<(ObjKey, u32)>, ProfileError> {
    // The expansion check has run, so every actor index is in range; any
    // decoding failure is still caught.
    let expanded = catch_unwind(AssertUnwindSafe(|| change.decode())).map_err(|_| INVALID)?;
    let start = expanded.start_op.get();
    let mut created: HashMap<ObjKey, u32> = HashMap::new();
    let mut out = Vec::new();
    for (i, op) in expanded.operations.iter().enumerate() {
        let parent = match &op.obj {
            ObjectId::Root => 0,
            ObjectId::Id(id) => {
                let key = (id.0, id.1.clone());
                match created.get(&key).copied().or_else(|| known(&key)) {
                    Some(depth) => depth,
                    None => return Err(INVALID),
                }
            }
        };
        if let OpType::Make(_) = op.action {
            let depth = parent + 1;
            if limit.is_some_and(|limit| depth > limit) {
                return Err(INVALID);
            }
            let key = (start + i as u64, expanded.actor_id.clone());
            created.insert(key.clone(), depth);
            out.push((key, depth));
        }
    }
    Ok(out)
}

/// The depth of every object of `doc`, from its history in causal order.
/// History already held is not limited: the limit applies at admission.
pub(crate) fn depths_of(doc: &mut AutoCommit) -> Result<Depths, ProfileError> {
    let mut depths = Depths::new();
    for change in crate::shared_objects::document::all_changes(doc)? {
        let objects = created_objects(&change, |key| depths.get(key).copied(), None)?;
        depths.extend(objects);
    }
    Ok(depths)
}

/// The object, operation ID and action of every operation of a Snapshot's
/// document (its operation columns), as indices into its actors.
pub(crate) struct DocumentOps {
    /// The object each operation writes into: `None` is the root.
    pub objects: Vec<Option<(u64, u64)>>,
    /// Each operation's ID: (actor index, counter).
    pub ids: Vec<(u64, u64)>,
    /// Each operation's action.
    pub actions: Vec<u64>,
}

/// §11.2: every object of a Snapshot's document is at most [`MAX_DEPTH`]
/// deep. Depths are computed iteratively from the parent links of the
/// object-creating operations; a missing parent or a cycle means the depths
/// cannot be established, and the Snapshot is rejected.
pub(crate) fn check_document_depth(ops: &DocumentOps) -> Result<(), ProfileError> {
    let n = ops.actions.len();
    if ops.objects.len() != n || ops.ids.len() != n {
        return Err(INVALID);
    }
    // Object (actor index, counter) -> the object it was created in.
    let mut parent: HashMap<(u64, u64), Option<(u64, u64)>> = HashMap::new();
    for i in 0..n {
        if matches!(ops.actions[i], 0 | 2 | 4 | 6)
            && parent.insert(ops.ids[i], ops.objects[i]).is_some()
        {
            return Err(INVALID);
        }
    }
    let mut depth: HashMap<(u64, u64), u32> = HashMap::new();
    let mut chain = Vec::new();
    for &object in parent.keys() {
        // Walk up to the root or an object of known depth, then assign the
        // chain's depths on the way back down.
        let mut at = Some(object);
        let mut base = 0u32;
        while let Some(obj) = at {
            if let Some(&d) = depth.get(&obj) {
                base = d;
                break;
            }
            // A chain longer than the objects is a cycle.
            if chain.len() > parent.len() {
                return Err(INVALID);
            }
            chain.push(obj);
            at = *parent.get(&obj).ok_or(INVALID)?;
        }
        while let Some(obj) = chain.pop() {
            base += 1;
            if base > MAX_DEPTH {
                return Err(INVALID);
            }
            depth.insert(obj, base);
        }
    }
    // Every operation writes into the root or an object the document has.
    if ops
        .objects
        .iter()
        .flatten()
        .any(|obj| !parent.contains_key(obj))
    {
        return Err(INVALID);
    }
    Ok(())
}
