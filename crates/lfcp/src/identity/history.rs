//! Immutable object membership, independent of Automerge's visible projection.
use automerge::{
    legacy::{Key, ObjectId, OpId, OpType},
    Change, ObjType,
};
use std::collections::HashMap;

#[derive(Debug)]
struct Created {
    parent: ObjectId,
    key: Key,
    kind: ObjType,
}

/// Only accepted changes enter this index. SOP R3/R6 check that each reference
/// belongs to the candidate's causal history before admission consults it, so
/// concurrent accepted objects cannot affect the decision.
#[derive(Debug, Default)]
pub(super) struct Objects(HashMap<OpId, Created>);

impl Objects {
    pub(super) fn of(change: &Change) -> Self {
        Self(
            change
                .decode()
                .operations
                .into_iter()
                .enumerate()
                .filter_map(|(i, op)| match op.action {
                    OpType::Make(kind) => Some((
                        OpId::new(change.start_op().get() + i as u64, change.actor_id()),
                        Created {
                            parent: op.obj,
                            key: op.key,
                            kind,
                        },
                    )),
                    _ => None,
                })
                .collect(),
        )
    }

    pub(super) fn extend(&mut self, added: Self) {
        self.0.extend(added.0);
    }

    fn get<'a>(&'a self, id: &OpId, added: &'a Self) -> Option<&'a Created> {
        added.0.get(id).or_else(|| self.0.get(id))
    }

    pub(super) fn is_container(&self, id: &OpId, added: &Self) -> bool {
        self.get(id, added)
            .is_some_and(|o| matches!(o.kind, ObjType::Map | ObjType::List))
    }

    pub(super) fn is_map(&self, id: &OpId, added: &Self) -> bool {
        self.get(id, added)
            .is_some_and(|o| matches!(o.kind, ObjType::Map))
    }

    pub(super) fn path<'a>(
        &'a self,
        mut obj: &'a ObjectId,
        added: &'a Self,
    ) -> Option<Vec<String>> {
        let mut path = Vec::new();
        while let ObjectId::Id(id) = obj {
            let created = self.get(id, added)?;
            path.push(match &created.key {
                Key::Map(key) => key.to_string(),
                // Membership, not a mutable list index: every descendant stays
                // under the field even after replacement or deletion.
                Key::Seq(_) => "[]".into(),
            });
            obj = &created.parent;
        }
        path.reverse();
        Some(path)
    }
}
