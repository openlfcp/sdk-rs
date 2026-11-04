use super::{
    document::{map, scalar_strings},
    history::Objects,
    Diagnostic as D, IdentityDoc, WriterClass, CONTAINERS,
};
use crate::base::{PrincipalId, ResourceId};
use crate::shared_objects::{
    document::{ChangeOutcome, SharedObjects},
    framing,
    identity::{actor_id_bytes, principal_ref},
};
use automerge::legacy::{Key, OpType};
use automerge::{
    ActorId, AutoCommit, Change, ChangeHash, ObjType, ReadDoc, ScalarValue, Value, ROOT,
};
use std::collections::{BTreeMap, BTreeSet};

/// Metadata of an already Wire-verified and decrypted Data Unit. Derive the
/// class at this unit's `control_ref`, even when delivery happens after revoke.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnitContext {
    /// Verified Data Unit signer.
    pub signer: PrincipalId,
    /// Signer class at `control_ref`.
    pub class: WriterClass,
    /// LFCP actor sequence, distinct from the Automerge sequence.
    pub actor_sequence: u64,
}
/// Result of receiving one Identity change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Received {
    /// Applied, with any waiting dependants released.
    Applied,
    /// Already applied.
    Duplicate,
    /// Waiting for a missing or refused dependency.
    Waiting,
    /// Actor sequence taken; held until rebuild.
    Held,
    /// Refused without modifying the admitted document.
    Refused(D),
}
/// Identity receive engine. The caller enforces Wire authorization, epochs and
/// equivocation, and supplies immutable unit metadata (§2.2–§2.3).
#[derive(Debug)]
pub struct IdentityReplica {
    resource: ResourceId,
    owner: PrincipalId,
    engine: SharedObjects,
    waiting: BTreeMap<ChangeHash, (Change, UnitContext)>,
    refused: BTreeMap<ChangeHash, D>,
    forwarded: BTreeSet<ChangeHash>,
    objects: Objects,
}
impl IdentityReplica {
    /// Empty Identity Resource, enforcing baseline.2 admission AI0–AI5.
    pub fn new(resource: ResourceId, owner: PrincipalId) -> Self {
        Self {
            resource,
            owner,
            engine: SharedObjects::new(ActorId::from([0u8; 32])),
            waiting: BTreeMap::new(),
            refused: BTreeMap::new(),
            forwarded: BTreeSet::new(),
            objects: Objects::default(),
        }
    }
    /// Receive framed plaintext, bound to an already verified unit.
    pub fn receive(&mut self, unit: UnitContext, plaintext: &[u8]) -> Received {
        let change = match framing::decode_change(plaintext) {
            Ok(c) => c,
            Err(_) => {
                if let Some((hash, actor)) = framing::refused_change_key(plaintext) {
                    if actor
                        .as_deref()
                        .is_some_and(|a| a != actor_id_bytes(&self.resource, &unit.signer))
                    {
                        self.forwarded.insert(hash);
                    }
                    return self.refuse(hash, D::InvalidAutomergeBytes);
                }
                return Received::Refused(D::InvalidAutomergeBytes);
            }
        };
        if change.actor_id().to_bytes() != actor_id_bytes(&self.resource, &unit.signer) {
            if !self.engine.has_change(&change.hash()) && !self.refused.contains_key(&change.hash())
            {
                self.forwarded.insert(change.hash());
                self.refused.insert(change.hash(), D::ChangeActorMismatch);
            }
            return Received::Refused(D::ChangeActorMismatch);
        }
        // R1 precedes AI0, and AI0 eligibility precedes the taken-sequence hold.
        if change.deps().is_empty() {
            if self.engine.broken_rule(&change).is_some() {
                return self.refuse(change.hash(), D::InvalidAutomergeBytes);
            }
            if unit.signer != self.owner
                || unit.actor_sequence != 1
                || unit.class != WriterClass::Root
            {
                // Carrier-specific failure cannot poison the same bytes in the
                // actual root unit 1, just as an actor-mismatched forward cannot.
                if !self.refused.contains_key(&change.hash()) {
                    self.forwarded.insert(change.hash());
                }
                return self.refuse(change.hash(), D::InvalidRoot);
            }
        }
        let result = self.admit(change, unit);
        if result == Received::Applied {
            self.retry();
        }
        result
    }
    fn refuse(&mut self, hash: ChangeHash, d: D) -> Received {
        self.refused.insert(hash, d);
        Received::Refused(d)
    }
    fn admit(&mut self, change: Change, unit: UnitContext) -> Received {
        let hash = change.hash();
        if self.forwarded.remove(&hash) {
            self.refused.remove(&hash);
        }
        if let Some(d) = self.refused.get(&hash) {
            return Received::Refused(*d);
        }
        if self.engine.has_change(&hash) {
            return Received::Duplicate;
        }
        if change.deps().iter().any(|d| !self.engine.has_change(d)) {
            self.waiting.entry(hash).or_insert((change, unit));
            return Received::Waiting;
        }
        if self.engine.sequence_taken(&change) {
            return match self.engine.apply_change(change) {
                Ok(ChangeOutcome::Held) => Received::Held,
                _ => self.refuse(hash, D::InvalidAutomergeBytes),
            };
        }
        let mut heads = self.engine.heads();
        heads.sort();
        let mut deps = change.deps().to_vec();
        deps.sort();
        let owner = self.owner;
        let added = Objects::of(&change);
        let objects = &self.objects;
        let checked = change.clone();
        let result = if heads == deps {
            self.engine.apply_change_checked(change, |before, next| {
                structural(next, before, &checked, unit, owner, objects, &added)
            })
        } else {
            // Concurrent changes are checked solely against their causal past.
            let mut doc = self.engine.automerge().clone();
            let mut past = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                doc.fork_at(change.deps())
            })) {
                Ok(Ok(d)) => d,
                _ => return self.refuse(hash, D::InvalidAutomergeBytes),
            };
            let mut probe = match SharedObjects::load(&past.save(), ActorId::from([0u8; 32])) {
                Ok(p) => p,
                Err(_) => return self.refuse(hash, D::InvalidAutomergeBytes),
            };
            match probe.apply_change_checked(change.clone(), |before, next| {
                structural(next, before, &checked, unit, owner, objects, &added)
            }) {
                Ok(Ok(ChangeOutcome::Applied)) => self.engine.apply_change(change).map(Ok),
                other => other,
            }
        };
        match result {
            Ok(Ok(ChangeOutcome::Applied)) => {
                self.objects.extend(added);
                Received::Applied
            }
            Ok(Ok(ChangeOutcome::Duplicate)) => Received::Duplicate,
            Ok(Ok(ChangeOutcome::Held)) => Received::Held,
            Ok(Err(d)) => self.refuse(hash, d),
            Err(_) => self.refuse(hash, D::InvalidAutomergeBytes),
        }
    }
    fn retry(&mut self) {
        loop {
            let ready: Vec<_> = self
                .waiting
                .iter()
                .filter(|(_, (c, _))| c.deps().iter().all(|d| self.engine.has_change(d)))
                .map(|(h, _)| *h)
                .collect();
            if ready.is_empty() {
                break;
            }
            for hash in ready {
                let (c, u) = self.waiting.remove(&hash).unwrap();
                self.admit(c, u);
            }
        }
    }
    /// Refused hashes and diagnostics, including carrier-specific refusals.
    pub fn refused(&self) -> &BTreeMap<ChangeHash, D> {
        &self.refused
    }
    /// Changes waiting for dependencies.
    pub fn waiting(&self) -> Vec<ChangeHash> {
        self.waiting.keys().copied().collect()
    }
    /// Changes held by another change at the same actor sequence.
    pub fn held(&self) -> Vec<ChangeHash> {
        let mut h: Vec<_> = self.engine.held().iter().map(Change::hash).collect();
        h.sort();
        h
    }
    /// Accepted change hashes, in hash order for differential comparisons.
    pub fn accepted(&mut self) -> Vec<ChangeHash> {
        let mut h: Vec<_> = self.engine.changes().iter().map(Change::hash).collect();
        h.sort();
        h
    }
    /// Read admitted state (the view's root is invalid until initialisation).
    pub fn view(&self) -> IdentityDoc {
        IdentityDoc {
            doc: self.engine.automerge().clone(),
            owner: self.owner,
        }
    }
    /// Save the admitted document as raw Automerge bytes.
    pub fn save(&mut self) -> Vec<u8> {
        self.engine.save()
    }
    /// Import a framed Snapshot only when all its changes can be replayed from
    /// verified unit witnesses, including the root's unit 1. Missing witnesses
    /// return `false` without changing state. This deliberately conservative
    /// API also rechecks writer classes and admission (§§2.2, 3; SOP §14).
    pub fn receive_snapshot(
        &mut self,
        plaintext: &[u8],
        units: &[(UnitContext, Vec<u8>)],
    ) -> Result<bool, D> {
        let save = framing::decode_snapshot(plaintext).map_err(|_| D::InvalidAutomergeBytes)?;
        let mut snapshot = SharedObjects::load(&save, ActorId::from([0u8; 32]))
            .map_err(|_| D::InvalidAutomergeBytes)?;
        let mut hashes: Vec<_> = snapshot.changes().iter().map(Change::hash).collect();
        hashes.sort();
        let mut replay = Self::new(self.resource, self.owner);
        for (unit, bytes) in units {
            replay.receive(*unit, bytes);
        }
        if hashes.is_empty() || replay.accepted() != hashes {
            return Ok(false);
        }
        // Merge verified witnesses through normal admission; retain local work.
        for (unit, bytes) in units {
            self.receive(*unit, bytes);
        }
        Ok(true)
    }
}

fn structural(
    next: &AutoCommit,
    before: &[ChangeHash],
    change: &Change,
    unit: UnitContext,
    owner: PrincipalId,
    objects: &Objects,
    added: &Objects,
) -> Option<D> {
    if change.deps().is_empty() {
        let view = IdentityDoc {
            doc: next.clone(),
            owner,
        };
        let mut keys: Vec<_> = next.keys(ROOT).collect();
        keys.sort();
        if view.validate_root().is_err()
            || keys
                != [
                    "devices",
                    "extensions",
                    "identity",
                    "profile",
                    "requests",
                    "roster",
                ]
        {
            return Some(D::InvalidRoot);
        }
        let identity = map(next, &ROOT, "identity")?;
        if next.keys(identity).collect::<Vec<_>>() != ["root"]
            || CONTAINERS
                .iter()
                .any(|k| map(next, &ROOT, k).is_none_or(|id| next.length(id) != 0))
        {
            return Some(D::InvalidRoot);
        }
        // Check operations as well as the final shape: a transient roster
        // entry or unknown key belongs in a later change (§2.2).
        for op in change.decode().operations {
            let Some(parent) = objects.path(&op.obj, added) else {
                return Some(D::InvalidAutomergeBytes);
            };
            let Key::Map(key) = op.key else {
                return Some(D::InvalidRoot);
            };
            let allowed = if parent.is_empty() {
                match key.as_str() {
                    "profile" => {
                        matches!(op.action, OpType::Put(ScalarValue::Str(ref s)) if s.as_str() == super::PROFILE)
                    }
                    "identity" | "roster" | "devices" | "requests" | "extensions" => {
                        matches!(op.action, OpType::Make(ObjType::Map))
                    }
                    _ => false,
                }
            } else {
                parent == ["identity"]
                    && key == "root"
                    && matches!(op.action, OpType::Put(ScalarValue::Str(ref s)) if s.as_str() == principal_ref(&owner))
            };
            if !allowed {
                return Some(D::InvalidRoot);
            }
        }
        return None;
    }
    let mut container = false;
    let mut immutable = false;
    let mut unauthorized = false;
    let mut bad_type = false;
    let restricted = matches!(unit.class, WriterClass::Pairing | WriterClass::Other);
    let mut request_key: Option<String> = None;
    let operations = change.decode().operations;
    for op in operations {
        let mut p = match objects.path(&op.obj, added) {
            Some(p) => p,
            None => return Some(D::InvalidAutomergeBytes),
        };
        let key = match &op.key {
            Key::Map(k) => Some(k.to_string()),
            _ => None,
        };
        if let Some(k) = &key {
            p.push(k.clone());
        }
        let root = p.first().map(String::as_str).unwrap_or("");
        if root == "identity" || root == "profile" {
            immutable = true;
        }
        if p.len() == 1 && CONTAINERS.contains(&root) {
            container = true;
        }
        if key.is_some()
            && matches!(p.len(), 2 | 3)
            && ["roster", "devices", "requests"].contains(&root)
            && matches!(op.action, OpType::Put(_))
            && op.pred.iter().any(|id| objects.is_container(id, added))
        {
            container = true;
        }
        if matches!(op.action, OpType::Make(ObjType::Text)) {
            bad_type = true;
        }
        let defined = p.len() <= 2 && CONTAINERS.contains(&root)
            || p.get(2).is_some_and(|field| match root {
                "roster" => ["profile", "endpoints", "coordinator", "name", "archived"]
                    .contains(&field.as_str()),
                "devices" => [
                    "label",
                    "kind",
                    "platform",
                    "added_at",
                    "revoked",
                    "missing_keys",
                ]
                .contains(&field.as_str()),
                "requests" => [
                    "descriptor",
                    "pairing",
                    "label",
                    "kind",
                    "scope",
                    "platform",
                    "requested_at",
                ]
                .contains(&field.as_str()),
                _ => false,
            });
        if defined
            && matches!(&op.action,OpType::Put(v) if !matches!(v,ScalarValue::Str(_)|ScalarValue::Uint(_)|ScalarValue::Boolean(_)))
        {
            bad_type = true;
        }
        if root == "devices"
            && p.get(2).is_some_and(|k| k == "missing_keys")
            && p.get(1) != Some(&principal_ref(&unit.signer))
        {
            unauthorized = true;
        }
        if restricted {
            if root != "requests" || p.len() < 2 || matches!(op.action, OpType::Delete) {
                unauthorized = true;
                continue;
            }
            if request_key.as_ref().is_some_and(|k| k != &p[1]) {
                unauthorized = true;
            }
            request_key = Some(p[1].clone());
            let requests = match map(next, &ROOT, "requests") {
                Some(id) => id,
                None => {
                    unauthorized = true;
                    continue;
                }
            };
            let old = next
                .get_all_at(&requests, &p[1], before)
                .unwrap_or_default();
            if !old.is_empty() {
                if p.len() == 2 {
                    unauthorized = true;
                }
                match old.as_slice() {
                    [(Value::Object(ObjType::Map), id)] => {
                        // Object IDs carry the actor of the map's creation.
                        let created_by_writer = id
                            .to_string()
                            .split_once('@')
                            .is_some_and(|(_, a)| a == change.actor_id().to_hex_string());
                        let values = next.get_all_at(id, "pairing", before).unwrap_or_default();
                        let own = values.len() == 1
                            && matches!(&values[0].0,Value::Scalar(s) if matches!(s.as_ref(),ScalarValue::Str(s) if s.as_str()==principal_ref(&unit.signer)));
                        if !created_by_writer || !own {
                            unauthorized = true;
                        }
                    }
                    _ => unauthorized = true,
                }
            } else if p.len() == 2 && !matches!(op.action, OpType::Make(ObjType::Map)) {
                unauthorized = true;
            }
            let own = map(next, &requests, &p[1]).is_some_and(|id| {
                scalar_strings(next, &id, "pairing") == [principal_ref(&unit.signer)]
            });
            if !own {
                unauthorized = true;
            }
        }
    }
    if container {
        Some(D::ContainerReplaced)
    } else if immutable {
        Some(D::ImmutableFieldMutated)
    } else if unauthorized {
        Some(D::UnauthorizedWriter)
    } else if bad_type {
        Some(D::InvalidFieldType)
    } else {
        None
    }
}
