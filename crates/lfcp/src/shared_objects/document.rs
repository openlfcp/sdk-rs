//! A Shared Objects document: the Automerge document of one Resource, its
//! intents (SHARED-OBJECTS-PROFILE-01 §57–§69) and its conflicts (§44–§52).
//!
//! Every intent is one Automerge change (§10) by the document's actor
//! (§8), returned so the caller can frame it into a Data Unit
//! ([`super::framing::encode_change`]). Changes carry a fixed time, 0 by
//! default: Automerge change times are informational, and a wall clock
//! would only leak when the user edited.
//!
//! | Intent | Writes | § |
//! | --- | --- | --- |
//! | [`SharedObjects::initialize`] | `profile`, `objects {}`, `extensions {}` | §16 |
//! | [`SharedObjects::create_task`] | the Task map with every required field | §53, §60 |
//! | [`SharedObjects::set_title`] | `title` | §61 |
//! | [`SharedObjects::set_status`] | `status` | §62 |
//! | [`SharedObjects::complete`] | `status = done`, `completion_date` if given | §63 |
//! | [`SharedObjects::reopen`] | `status = todo`, delete `completion_date` | §64 |
//! | [`SharedObjects::cancel`] | `status = cancelled`, delete `completion_date` | §65 |
//! | [`SharedObjects::set_date`], [`SharedObjects::clear_date`] | `due`, `scheduled` (and `completion_date`) | §66, §36 |
//! | [`SharedObjects::set_priority`] | `priority` | §38 |
//! | [`SharedObjects::add_tag`], [`SharedObjects::remove_tag`] | `tags[tag] = true`, delete | §67 |
//! | [`SharedObjects::add_assignee`], [`SharedObjects::remove_assignee`] | `assignees[ref] = true`, delete | §68 |
//! | [`SharedObjects::delete`], [`SharedObjects::restore`] | `lifecycle` | §54, §55 |
//! | [`SharedObjects::resolve_field_conflict`] | the chosen value, after merging | §47, §69 |
//! | [`SharedObjects::insert_object`] | any object, e.g. of another type | §25, §71 |
//!
//! §58 (G-SC4): a write always produces an operation. Automerge
//! implementations may skip an assignment of the value already present, so
//! a value equal to the current one is deleted and put again in the same
//! change; a concurrent add then beats a remove (§41, §43) and a restore
//! conflicts with a concurrent delete (§52).
//!
//! §30 (G-SC3): every string is written as an Automerge scalar string,
//! never as Text.
//!
//! Objects are never removed from `objects` (§54, §56), and fields the
//! document does not understand are never touched (§70–§72): intents write
//! single properties, not whole objects.

use std::collections::{BTreeMap, HashMap};
use std::panic::{catch_unwind, AssertUnwindSafe};

use automerge::transaction::{CommitOptions, Transactable};
use automerge::{
    ActorId, AutoCommit, Change, ChangeHash, ObjId, ObjType, ReadDoc, ScalarValue, Value, ROOT,
};

use crate::base::{ObjectId, PrincipalId, ResourceId};
use crate::shared_objects::depth::{self, Depths, ObjKey};
use crate::shared_objects::expansion;
use crate::shared_objects::framing::decode_change;
use crate::shared_objects::history::{Additions, History, Overlay};
use crate::shared_objects::identity::actor_id_bytes;
use crate::shared_objects::identity::principal_ref;
use crate::shared_objects::validate::{self, values_of, ObjectStatus};
use crate::shared_objects::values::{self, Plain};
use crate::shared_objects::{Diagnostic, ProfileError, PROFILE};

/// The fields of a new Task (§60). Defaults: `status = todo`,
/// `priority = normal`, `lifecycle = active`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewTask {
    /// The client-generated UUIDv7 (§19).
    pub id: ObjectId,
    /// The creating Principal (§27).
    pub created_by: PrincipalId,
    /// An RFC 3339 UTC timestamp, if a reliable clock is available (§28).
    pub created_at: Option<String>,
    /// The title (§32).
    pub title: String,
    /// The status; `todo` when `None`.
    pub status: Option<String>,
    /// The priority; `normal` when `None`.
    pub priority: Option<String>,
    /// The due date (§35).
    pub due: Option<String>,
    /// The scheduled date (§35).
    pub scheduled: Option<String>,
    /// Initial tags (§39).
    pub tags: Vec<String>,
    /// Initial assignees (§42).
    pub assignees: Vec<PrincipalId>,
}

impl NewTask {
    /// A Task with the defaults and no optional fields.
    pub fn new(id: ObjectId, created_by: PrincipalId, title: impl Into<String>) -> NewTask {
        NewTask {
            id,
            created_by,
            created_at: None,
            title: title.into(),
            status: None,
            priority: None,
            due: None,
            scheduled: None,
            tags: Vec::new(),
            assignees: Vec::new(),
        }
    }

    /// The Task object as plain data (§53), validated.
    pub fn to_plain(&self) -> Result<Plain, ProfileError> {
        let status = self.status.as_deref().unwrap_or("todo");
        let priority = self.priority.as_deref().unwrap_or("normal");
        require(values::is_status(status), Diagnostic::InvalidEnumValue)?;
        require(values::is_priority(priority), Diagnostic::InvalidEnumValue)?;
        let mut fields = BTreeMap::from([
            ("id".to_owned(), Plain::str(self.id.as_str())),
            ("type".to_owned(), Plain::str("task")),
            ("lifecycle".to_owned(), Plain::str("active")),
            (
                "created_by".to_owned(),
                Plain::str(principal_ref(&self.created_by)),
            ),
            ("title".to_owned(), Plain::str(&self.title)),
            ("status".to_owned(), Plain::str(status)),
            ("priority".to_owned(), Plain::str(priority)),
            ("extensions".to_owned(), Plain::map::<String>([])),
        ]);
        if let Some(at) = &self.created_at {
            require(values::is_utc_timestamp(at), Diagnostic::InvalidTimestamp)?;
            fields.insert("created_at".into(), Plain::str(at));
        }
        for (field, date) in [("due", &self.due), ("scheduled", &self.scheduled)] {
            if let Some(date) = date {
                require(values::is_local_date(date), Diagnostic::InvalidLocalDate)?;
                fields.insert(field.into(), Plain::str(date));
            }
        }
        for tag in &self.tags {
            require(values::is_tag(tag), Diagnostic::InvalidTag)?;
        }
        fields.insert(
            "tags".into(),
            Plain::map(self.tags.iter().map(|t| (t.clone(), Plain::Bool(true)))),
        );
        fields.insert(
            "assignees".into(),
            Plain::map(
                self.assignees
                    .iter()
                    .map(|p| (principal_ref(p), Plain::Bool(true))),
            ),
        );
        Ok(Plain::Map(fields))
    }
}

fn require(ok: bool, diagnostic: Diagnostic) -> Result<(), ProfileError> {
    if ok {
        Ok(())
    } else {
        Err(diagnostic.into())
    }
}

/// The Automerge document of one Resource under this profile.
///
/// §14.1 (baseline.6): a change reaches the Automerge engine only when
/// every dependency is in the document and its sequence number is exactly
/// one more than its actor's latest change here (or 1). Automerge keeps no
/// pending changes for this document: a change with a missing dependency is
/// handed back ([`ProfileError::MissingDependencies`]) for the caller to
/// hold, and a sequence gap is `INVALID_AUTOMERGE_BYTES` before the engine
/// sees it (automerge 0.12 aborts on one, and a JavaScript engine corrupts
/// the document). As defense in depth, an engine error or panic during an
/// apply restores the document as it was before the apply.
#[derive(Debug)]
pub struct SharedObjects {
    doc: AutoCommit,
    time: i64,
    /// The latest sequence number of each actor in `doc`.
    seqs: HashMap<ActorId, u64>,
    /// The depth of every object in `doc` (§11.2).
    depths: Depths,
    /// The operations and causal clocks of `doc`'s history (§11.4).
    history: History,
    /// §14.1 (POST-001): received changes whose actor and sequence number
    /// another change in `doc` holds, in arrival order. Retried after every
    /// rebuild that removes changes ([`SharedObjects::exclude`]).
    held: Vec<Change>,
}

/// What became of one received change (§14.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangeOutcome {
    /// It entered the document.
    Applied,
    /// The document already holds it; nothing changed.
    Duplicate,
    /// Another change in the document holds its actor and sequence number.
    /// It is held, not merged and not profile-invalid; its Data Unit stays
    /// accepted. It is retried after every rebuild that removes changes
    /// ([`SharedObjects::exclude`]).
    Held,
}

/// What a rebuild without excluded changes did ([`SharedObjects::exclude`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Excluded {
    /// The changes removed: the excluded ones and every change that
    /// depends on one, in no particular order.
    pub removed: Vec<ChangeHash>,
    /// Held changes that applied after the rebuild, in the order applied.
    pub applied: Vec<ChangeHash>,
}

/// `AutoCommit::load`, with an engine abort reported as
/// `INVALID_AUTOMERGE_BYTES`. Sound: on a panic the half-built document is
/// dropped, never used.
pub(crate) fn load_guarded(save: &[u8]) -> Result<AutoCommit, ProfileError> {
    match catch_unwind(|| AutoCommit::load(save)) {
        Ok(Ok(doc)) => Ok(doc),
        Ok(Err(_)) | Err(_) => Err(ProfileError::Invalid(Diagnostic::InvalidAutomergeBytes)),
    }
}

/// Every change of `doc`, dependencies first, with an engine abort
/// reported as `INVALID_AUTOMERGE_BYTES`. Defense in depth: admission
/// (§11.3, §11.4) keeps out the changes automerge 0.12 cannot write back
/// out. Sound: on a panic nothing of the call is used.
pub(crate) fn all_changes(doc: &mut AutoCommit) -> Result<Vec<Change>, ProfileError> {
    catch_unwind(AssertUnwindSafe(|| doc.get_changes(&[])))
        .map_err(|_| ProfileError::Invalid(Diagnostic::InvalidAutomergeBytes))
}

/// Whether `doc` holds the change `hash`, read from its metadata: unlike
/// `get_change_by_hash`, nothing is written out.
fn holds(doc: &mut AutoCommit, hash: &ChangeHash) -> bool {
    doc.get_change_meta_by_hash(hash).is_some()
}

/// Empties the document's patch log (LFCP-02-111). This crate reads no
/// patches, yet automerge 0.12 records some events even in an inactive
/// log; kept, they grow with every apply and are copied by every clone of
/// the document.
pub(crate) fn drop_patch_log(doc: &mut AutoCommit) {
    doc.reset_diff_cursor();
}

/// The latest sequence number of every actor of `doc`.
fn seqs_of(doc: &mut AutoCommit) -> Result<HashMap<ActorId, u64>, ProfileError> {
    let mut seqs = HashMap::new();
    for change in all_changes(doc)? {
        let latest = seqs.entry(change.actor_id().clone()).or_insert(0);
        *latest = (*latest).max(change.seq());
    }
    Ok(seqs)
}

/// Changes admitted earlier in an [`SharedObjects::apply_changes`] batch.
#[derive(Default)]
struct Batch {
    hashes: std::collections::HashSet<ChangeHash>,
    seqs: HashMap<ActorId, u64>,
    depths: Depths,
    history: Overlay,
}

/// What an admitted change adds: the objects it creates, with their
/// depths (§11.2), and its operations (§11.4).
#[derive(Clone, Debug, Default)]
struct Created {
    objects: Vec<(ObjKey, u32)>,
    history: Additions,
}

/// What the §14.1 check decides for one received change.
enum Admission {
    /// Every dependency is here and the sequence is the actor's next one;
    /// the change creates these objects.
    Apply(Created),
    /// The document already holds this change.
    Duplicate,
}

impl SharedObjects {
    /// An empty document writing as `actor` (see
    /// [`super::identity::actor_id`]). Call [`SharedObjects::initialize`]
    /// to create a Resource's document, or apply its changes.
    pub fn new(actor: ActorId) -> SharedObjects {
        SharedObjects {
            doc: AutoCommit::new().with_actor(actor),
            time: 0,
            seqs: HashMap::new(),
            depths: Depths::new(),
            history: History::default(),
            held: Vec::new(),
        }
    }

    fn with_doc(mut doc: AutoCommit, time: i64) -> Result<SharedObjects, ProfileError> {
        let seqs = seqs_of(&mut doc)?;
        let depths = depth::depths_of(&mut doc)?;
        // A document holding a change §11.3 or §11.4 refuses is refused
        // whole: its changes could not be written back out.
        let history = History::of(&mut doc)?;
        Ok(SharedObjects {
            doc,
            time,
            seqs,
            depths,
            history,
            held: Vec::new(),
        })
    }

    /// Load a full-save image (§13) and continue writing as `actor`. A
    /// save that does not load, or that makes the engine abort, is
    /// `PROFILE_INVALID` with `INVALID_AUTOMERGE_BYTES`; the half-built
    /// document is dropped.
    pub fn load(save: &[u8], actor: ActorId) -> Result<SharedObjects, ProfileError> {
        let doc = load_guarded(save)?.with_actor(actor);
        SharedObjects::with_doc(doc, 0)
    }

    /// Set the time recorded in the changes this document writes.
    pub fn set_change_time(&mut self, time: i64) {
        self.time = time;
    }

    /// A full-save image of the document (§13).
    pub fn save(&mut self) -> Vec<u8> {
        self.doc.save()
    }

    /// Apply Automerge changes whose origin is already established, such
    /// as changes from a trusted local store. Changes received in Data Units
    /// go through [`SharedObjects::apply_unit_change`], which checks their
    /// actor against the signer.
    ///
    /// The changes may come in any order: each is applied once its
    /// dependencies are in the document. Those still missing a dependency
    /// are returned, never handed to the engine (§14.1). A change whose
    /// actor and sequence number another change holds is held (§14.1,
    /// [`SharedObjects::held`]), and the changes that depend on it are
    /// returned with the others still waiting. Any other refusal stops the
    /// call with its error; changes applied before it stay applied.
    pub fn apply_changes(&mut self, changes: Vec<Change>) -> Result<Vec<Change>, ProfileError> {
        // Admit the whole batch first (§14.1), counting the changes admitted
        // before as present, then hand them to the engine in one call:
        // Automerge applies a batch in near-linear time, while one change at
        // a time is quadratic (10 000 changes: about 40 ms against 6 s).
        //
        // The batch may come in any order: a change is considered once its
        // dependencies inside the batch are admitted (Kahn's order), so a
        // reversed history costs no more than an ordered one.
        let mut seen = std::collections::HashSet::new();
        let changes: Vec<Change> = changes
            .into_iter()
            .filter(|c| seen.insert(c.hash()))
            .collect();
        let mut batch = Batch::default();
        let mut admitted = Vec::new();
        let mut refused = None;
        let in_batch: HashMap<ChangeHash, usize> = changes
            .iter()
            .enumerate()
            .map(|(i, c)| (c.hash(), i))
            .collect();
        let mut blocking = vec![0usize; changes.len()];
        let mut unreachable = vec![false; changes.len()];
        let mut children: HashMap<ChangeHash, Vec<usize>> = HashMap::new();
        for (i, change) in changes.iter().enumerate() {
            for dep in change.deps() {
                if holds(&mut self.doc, dep) {
                    continue;
                }
                if in_batch.contains_key(dep) {
                    blocking[i] += 1;
                    children.entry(*dep).or_default().push(i);
                } else {
                    unreachable[i] = true;
                }
            }
        }
        let mut ready: std::collections::VecDeque<usize> = (0..changes.len())
            .filter(|&i| blocking[i] == 0 && !unreachable[i])
            .collect();
        let mut done = vec![false; changes.len()];
        while let Some(i) = ready.pop_front() {
            if done[i] {
                continue;
            }
            done[i] = true;
            let change = &changes[i];
            match self.admit_in(change, &batch) {
                Ok(Admission::Duplicate) => {}
                Ok(Admission::Apply(created)) => {
                    batch.seqs.insert(change.actor_id().clone(), change.seq());
                    batch.hashes.insert(change.hash());
                    batch.depths.extend(created.objects.iter().cloned());
                    batch.history.add(&created.history);
                    admitted.push((change.clone(), created));
                }
                Err(ProfileError::MissingDependencies(_)) => {
                    done[i] = false;
                    continue;
                }
                Err(ProfileError::SequenceTaken { .. }) => {
                    self.hold(change.clone());
                    continue;
                }
                Err(err) => {
                    refused = Some(err);
                    break;
                }
            }
            for &child in children
                .get(&change.hash())
                .map(Vec::as_slice)
                .unwrap_or(&[])
            {
                blocking[child] -= 1;
                if blocking[child] == 0 && !unreachable[child] {
                    ready.push_back(child);
                }
            }
        }
        let held: std::collections::HashSet<ChangeHash> =
            self.held.iter().map(Change::hash).collect();
        let waiting: Vec<Change> = changes
            .into_iter()
            .zip(done)
            .filter(|(c, d)| !d && !batch.hashes.contains(&c.hash()) && !held.contains(&c.hash()))
            .map(|(c, _)| c)
            .collect();
        // Changes admitted before a refusal stay applied, as documented.
        if !admitted.is_empty() {
            self.engine_apply_all(admitted)?;
        }
        match refused {
            Some(err) => Err(err),
            None => Ok(waiting),
        }
    }

    /// §14.1: whether `change` may enter the engine now.
    fn admit(&mut self, change: &Change) -> Result<Admission, ProfileError> {
        self.admit_in(change, &Batch::default())
    }

    /// [`Self::admit`], with the changes of `batch` counted as if they were
    /// already in the document.
    fn admit_in(&mut self, change: &Change, batch: &Batch) -> Result<Admission, ProfileError> {
        let hash = change.hash();
        if batch.hashes.contains(&hash) || holds(&mut self.doc, &hash) {
            return Ok(Admission::Duplicate);
        }
        let missing: Vec<ChangeHash> = change
            .deps()
            .iter()
            .filter(|d| !batch.hashes.contains(*d) && !holds(&mut self.doc, d))
            .copied()
            .collect();
        if !missing.is_empty() {
            return Err(ProfileError::MissingDependencies(missing));
        }
        let latest = batch
            .seqs
            .get(change.actor_id())
            .or_else(|| self.seqs.get(change.actor_id()))
            .copied()
            .unwrap_or(0);
        if change.seq() <= latest {
            // Another change already holds this actor sequence: equivocation
            // (LFCP-WIRE-01 §26.2) or a reused sequence (§9).
            return Err(ProfileError::SequenceTaken {
                seq: change.seq(),
                latest,
            });
        }
        // A gap, or an author on a change other than the actor's first: the
        // engine would abort (automerge 0.12 change_graph asserts both).
        if change.seq() != latest + 1 || (change.author().is_some() && change.seq() != 1) {
            return Err(ProfileError::Invalid(Diagnostic::InvalidAutomergeBytes));
        }
        // §11.1: every other actor the change lists is already an actor of
        // the document (or of a change admitted before it in the batch). A
        // valid change refers only to its own history; automerge 0.12
        // panics on an unknown one.
        let known =
            |actor: &ActorId| self.seqs.contains_key(actor) || batch.seqs.contains_key(actor);
        if !change.other_actor_ids().iter().all(known) {
            return Err(ProfileError::Invalid(Diagnostic::InvalidAutomergeBytes));
        }
        // §11.2: no object deeper than 256, counting the objects of the
        // changes admitted before it in the batch; a change writing into an
        // object the document lacks is refused too.
        let known = |key: &ObjKey| {
            batch
                .depths
                .get(key)
                .or_else(|| self.depths.get(key))
                .copied()
        };
        // §11.3, §11.4: canonical bytes, and operations that refer only to
        // the change's own history. Checked before the depth walk decodes
        // the change.
        let history = self.history.check_change(change, &batch.history)?;
        let objects = depth::created_objects(change, known, Some(depth::MAX_DEPTH))?;
        Ok(Admission::Apply(Created { objects, history }))
    }

    /// Hand admitted changes to the engine in one call, with one backup. If
    /// the engine fails anyway, the document is restored and the changes
    /// are applied one at a time, so the failing one is isolated and those
    /// before it stay applied.
    fn engine_apply_all(&mut self, changes: Vec<(Change, Created)>) -> Result<(), ProfileError> {
        let backup = self.doc.clone();
        let doc = &mut self.doc;
        let batch: Vec<Change> = changes.iter().map(|(c, _)| c.clone()).collect();
        match catch_unwind(AssertUnwindSafe(|| doc.apply_changes(batch))) {
            Ok(Ok(())) => {
                for (c, created) in changes {
                    self.seqs.insert(c.actor_id().clone(), c.seq());
                    self.add(created);
                }
                Ok(())
            }
            Ok(Err(_)) | Err(_) => {
                self.doc = backup;
                for (change, created) in changes {
                    self.engine_apply(change, created)?;
                }
                Ok(())
            }
        }
    }

    /// Apply one change whose origin is already established (see
    /// [`SharedObjects::apply_changes`]): applied, a duplicate, or held
    /// because another change holds its actor and sequence number (§14.1).
    /// A change missing a dependency is
    /// [`ProfileError::MissingDependencies`].
    pub fn apply_change(&mut self, change: Change) -> Result<ChangeOutcome, ProfileError> {
        match self.admit(&change) {
            Ok(Admission::Duplicate) => Ok(ChangeOutcome::Duplicate),
            Ok(Admission::Apply(created)) => {
                self.engine_apply(change, created)?;
                Ok(ChangeOutcome::Applied)
            }
            Err(ProfileError::SequenceTaken { .. }) => {
                self.hold(change);
                Ok(ChangeOutcome::Held)
            }
            Err(err) => Err(err),
        }
    }

    /// Record what an admitted change added.
    fn add(&mut self, created: Created) {
        drop_patch_log(&mut self.doc);
        self.depths.extend(created.objects);
        self.history.add(created.history);
    }

    /// The §11.3 or §11.4 rule `change` breaks against this document's
    /// history ("C", "R1" to "R7"), or `None` when it keeps them. For
    /// tests and vectors; admission refuses such a change with
    /// `INVALID_AUTOMERGE_BYTES`.
    #[doc(hidden)]
    pub fn broken_rule(&mut self, change: &Change) -> Option<&'static str> {
        self.history.rule_of(change, &Overlay::default()).err()
    }

    /// [`SharedObjects::apply_change`], with one more check of the document
    /// before and after `change`: when `verdict` returns a refusal, the
    /// document is restored as it was and the refusal is returned. The
    /// document is copied once, as for any apply, and the change applied
    /// once. `verdict` runs only when the change enters the document.
    pub fn apply_change_checked<R>(
        &mut self,
        change: Change,
        verdict: impl FnOnce(&AutoCommit, &AutoCommit) -> Option<R>,
    ) -> Result<Result<ChangeOutcome, R>, ProfileError> {
        let created = match self.admit(&change) {
            Ok(Admission::Duplicate) => return Ok(Ok(ChangeOutcome::Duplicate)),
            Ok(Admission::Apply(created)) => created,
            Err(ProfileError::SequenceTaken { .. }) => {
                self.hold(change);
                return Ok(Ok(ChangeOutcome::Held));
            }
            Err(err) => return Err(err),
        };
        let backup = self.doc.clone();
        let (actor, seq) = (change.actor_id().clone(), change.seq());
        let doc = &mut self.doc;
        match catch_unwind(AssertUnwindSafe(|| doc.apply_changes(vec![change]))) {
            Ok(Ok(())) => {}
            Ok(Err(_)) | Err(_) => {
                self.doc = backup;
                return Err(ProfileError::Invalid(Diagnostic::InvalidAutomergeBytes));
            }
        }
        if let Some(refusal) = verdict(&backup, &self.doc) {
            self.doc = backup;
            return Ok(Err(refusal));
        }
        self.seqs.insert(actor, seq);
        self.add(created);
        Ok(Ok(ChangeOutcome::Applied))
    }

    /// Keep `change` held, once.
    fn hold(&mut self, change: Change) {
        if !self.held.iter().any(|c| c.hash() == change.hash()) {
            self.held.push(change);
        }
    }

    /// The changes held because another change holds their actor and
    /// sequence number (§14.1), in arrival order.
    pub fn held(&self) -> &[Change] {
        &self.held
    }

    /// §14.1: rebuild the document without the changes `hashes` and every
    /// change that depends on one, as a replica does when LFCP excludes
    /// their units (a cutoff, LFCP-WIRE-01 §19.1, or an equivocating pair,
    /// §26.2). Then retry the held changes: each whose actor and sequence
    /// number are free again and whose dependencies are all here applies;
    /// the others stay held. Hashes the document does not hold are ignored.
    pub fn exclude(&mut self, hashes: &[ChangeHash]) -> Result<Excluded, ProfileError> {
        let all = all_changes(&mut self.doc)?;
        let mut removed: std::collections::HashSet<ChangeHash> = hashes
            .iter()
            .filter(|h| holds(&mut self.doc, h))
            .copied()
            .collect();
        // Dependencies come first, so one pass finds every dependent.
        for change in &all {
            if change.deps().iter().any(|d| removed.contains(d)) {
                removed.insert(change.hash());
            }
        }
        if !removed.is_empty() {
            let keep: Vec<Change> = all
                .into_iter()
                .filter(|c| !removed.contains(&c.hash()))
                .collect();
            let mut doc = AutoCommit::new().with_actor(self.doc.get_actor().clone());
            doc.apply_changes(keep)?;
            drop_patch_log(&mut doc);
            self.doc = doc;
            self.seqs = seqs_of(&mut self.doc)?;
            self.depths = depth::depths_of(&mut self.doc)?;
            self.history = History::of(&mut self.doc)?;
        }
        let mut applied = Vec::new();
        loop {
            let mut progressed = false;
            for change in std::mem::take(&mut self.held) {
                match self.admit(&change) {
                    Ok(Admission::Apply(created)) => {
                        let hash = change.hash();
                        self.engine_apply(change, created)?;
                        applied.push(hash);
                        progressed = true;
                    }
                    Ok(Admission::Duplicate) => progressed = true,
                    Err(_) => self.held.push(change),
                }
            }
            if !progressed {
                break;
            }
        }
        Ok(Excluded {
            removed: removed.into_iter().collect(),
            applied,
        })
    }

    /// Hand `change` to the engine. Defense in depth: on an engine error or
    /// panic the document is restored as it was before, and the change is
    /// `INVALID_AUTOMERGE_BYTES`. The admission check makes this
    /// unreachable for the known abort; a panicked document is never kept.
    fn engine_apply(&mut self, change: Change, created: Created) -> Result<(), ProfileError> {
        let backup = self.doc.clone();
        let (actor, seq) = (change.actor_id().clone(), change.seq());
        let doc = &mut self.doc;
        let outcome = catch_unwind(AssertUnwindSafe(|| doc.apply_changes(vec![change])));
        match outcome {
            Ok(Ok(())) => {
                self.seqs.insert(actor, seq);
                self.add(created);
                Ok(())
            }
            Ok(Err(_)) | Err(_) => {
                self.doc = backup;
                Err(ProfileError::Invalid(Diagnostic::InvalidAutomergeBytes))
            }
        }
    }

    /// Apply the change carried by a Data Unit plaintext (§11) of
    /// `resource`, whose verified signer is `signer` (the unit's actor).
    ///
    /// §11 (SC-CHUNK, SO-SEC1): the plaintext must carry one change chunk
    /// with a valid checksum, and the change's Automerge actor must be the
    /// §8 actor of (`resource`, `signer`); otherwise `PROFILE_INVALID` with
    /// `CHANGE_ACTOR_MISMATCH` and nothing is applied: a Principal must not
    /// write into another Principal's Automerge history.
    ///
    /// §14.1: a change missing a dependency is
    /// [`ProfileError::MissingDependencies`] (hold the unit and offer it
    /// again); a sequence gap is `INVALID_AUTOMERGE_BYTES`; a change whose
    /// actor and sequence number another change holds is
    /// [`ChangeOutcome::Held`] (POST-001). None of them reaches the
    /// engine. A change already here is [`ChangeOutcome::Duplicate`].
    pub fn apply_unit_change(
        &mut self,
        resource: &ResourceId,
        signer: &PrincipalId,
        plaintext: &[u8],
    ) -> Result<ChangeOutcome, ProfileError> {
        let change = decode_change(plaintext)?;
        check_change_actor(resource, signer, &change)?;
        self.apply_change(change)
    }

    /// A copy writing as `actor`, sharing this document's history.
    pub fn fork(&mut self, actor: ActorId) -> SharedObjects {
        SharedObjects {
            doc: self.doc.fork().with_actor(actor),
            time: self.time,
            seqs: self.seqs.clone(),
            depths: self.depths.clone(),
            history: self.history.clone(),
            held: Vec::new(),
        }
    }

    /// Merge another replica's changes into this one.
    ///
    /// The other replica's changes go through the same §14.1 admission and
    /// guarded engine call as [`SharedObjects::apply_changes`]: two
    /// histories each sound on their own can still disagree, such as two
    /// changes of one actor at one sequence. Such a change is held (§14.1,
    /// POST-001); the changes of `other` that depend on a held one are
    /// returned, not merged.
    pub fn merge(&mut self, other: &mut SharedObjects) -> Result<Vec<Change>, ProfileError> {
        let new: Vec<Change> = all_changes(&mut other.doc)?
            .into_iter()
            .filter(|c| !holds(&mut self.doc, &c.hash()))
            .collect();
        let waiting = self.apply_changes(new)?;
        // A whole history has every dependency: what is left waits for a
        // held change, or the history was not whole.
        let mut blocked: std::collections::HashSet<ChangeHash> =
            self.held.iter().map(Change::hash).collect();
        for change in &waiting {
            let waits_on_held = change
                .deps()
                .iter()
                .all(|d| blocked.contains(d) || holds(&mut self.doc, d));
            if !waits_on_held {
                return Err(ProfileError::MissingDependencies(change.deps().to_vec()));
            }
            blocked.insert(change.hash());
        }
        Ok(waiting)
    }

    /// Whether the document holds the change `hash`.
    pub fn has_change(&mut self, hash: &ChangeHash) -> bool {
        holds(&mut self.doc, hash)
    }

    /// The current heads.
    pub fn heads(&mut self) -> Vec<ChangeHash> {
        self.doc.get_heads()
    }

    /// Every change of the document, dependencies first.
    pub fn changes(&mut self) -> Vec<Change> {
        self.doc.get_changes(&[])
    }

    /// The underlying Automerge document, for reading.
    pub fn automerge(&self) -> &AutoCommit {
        &self.doc
    }

    /// The root rules (§15).
    pub fn validate_root(&self) -> Result<(), ProfileError> {
        validate::validate_root(&self.doc)
    }

    fn objects(&self) -> Result<ObjId, ProfileError> {
        match self.doc.get(ROOT, "objects")? {
            Some((Value::Object(ObjType::Map), id)) => Ok(id),
            _ => Err(Diagnostic::InvalidRoot.into()),
        }
    }

    /// The keys of `objects`, including invalid ones.
    pub fn object_keys(&self) -> Result<Vec<String>, ProfileError> {
        Ok(self.doc.keys(self.objects()?).collect())
    }

    /// The profile state of the object under `key` (§74–§77, §21).
    pub fn object_status(&self, key: &str) -> Result<ObjectStatus, ProfileError> {
        validate::object_status(&self.doc, &self.objects()?, key)
    }

    /// Every profile problem of the document, per invalid value (§74.1):
    /// the root's, then each object's.
    pub fn problems(&self) -> Result<Vec<validate::Problem>, ProfileError> {
        let mut problems = validate::root_problems(&self.doc)?;
        if let Ok(objects) = self.objects() {
            for key in self.doc.keys(&objects) {
                problems.extend(validate::object_problems(&self.doc, &objects, &key)?);
            }
        }
        Ok(problems)
    }

    /// The whole document as plain data, each conflicted property showing
    /// Automerge's deterministic choice (§45).
    pub fn plain(&self) -> Result<Plain, ProfileError> {
        values::read(&self.doc, &Value::Object(ObjType::Map), &ROOT)
    }

    /// The object under `key` as plain data.
    pub fn object(&self, key: &str) -> Result<Plain, ProfileError> {
        let (value, id) = self
            .doc
            .get(self.objects()?, key)?
            .ok_or(ProfileError::UnknownObject)?;
        values::read(&self.doc, &value, &id)
    }

    /// The map of the object under `key`, refusing a collision.
    fn object_id(&self, key: &str) -> Result<ObjId, ProfileError> {
        let all = self.doc.get_all(self.objects()?, key)?;
        match all.as_slice() {
            [] => Err(ProfileError::UnknownObject),
            [(Value::Object(ObjType::Map), id)] => Ok(id.clone()),
            [_] => Err(Diagnostic::InvalidFieldType.into()),
            _ => Err(ProfileError::ObjectIdCollision),
        }
    }

    /// The map of the Task under `key`.
    fn task_id(&self, key: &str) -> Result<ObjId, ProfileError> {
        let id = self.object_id(key)?;
        let is_task = values_of(&self.doc, &id, "type")?
            .iter()
            .any(|p| p.as_str() == Some("task"));
        if is_task {
            Ok(id)
        } else {
            Err(ProfileError::NotATask)
        }
    }

    /// Every concurrent value of a property of an object (§45), in
    /// Automerge's order.
    pub fn values(&self, key: &str, field: &str) -> Result<Vec<Plain>, ProfileError> {
        values_of(&self.doc, &self.object_id(key)?, field)
    }

    /// The concurrent values of a scalar field, when there is more than
    /// one: the field is conflicted and must not be shown as resolved
    /// (§45, §46).
    pub fn conflict(&self, key: &str, field: &str) -> Result<Option<Vec<Plain>>, ProfileError> {
        let all = self.values(key, field)?;
        Ok((all.len() > 1).then_some(all))
    }

    /// Every conflicted field of an object, with its concurrent values
    /// (§44–§46). Collections (`tags`, `assignees`) merge and are not
    /// listed (§44).
    pub fn conflicts(&self, key: &str) -> Result<BTreeMap<String, Vec<Plain>>, ProfileError> {
        let id = self.object_id(key)?;
        let mut out = BTreeMap::new();
        for field in self.doc.keys(&id) {
            let all = self.doc.get_all(&id, field.as_str())?;
            if all.len() > 1 && all.iter().all(|(v, _)| matches!(v, Value::Scalar(_))) {
                out.insert(field.clone(), values_of(&self.doc, &id, &field)?);
            }
        }
        Ok(out)
    }

    /// Run `write` as one change named `intent` (§10). `None` when it
    /// changed nothing.
    fn transact(
        &mut self,
        intent: &str,
        write: impl FnOnce(&mut AutoCommit) -> Result<(), ProfileError>,
    ) -> Result<Option<Change>, ProfileError> {
        if let Err(err) = write(&mut self.doc) {
            self.doc.rollback();
            return Err(err);
        }
        // §11.1: a writer never emits a change above the limits. Every
        // operation column has one value per operation, so the pending
        // operations decide the per-column limit before anything commits.
        if self.doc.pending_ops() as u64 > expansion::CHANGE_LIMITS.max_rows {
            self.doc.rollback();
            return Err(ProfileError::ChangeTooLarge);
        }
        let options = CommitOptions::default()
            .with_message(intent.to_owned())
            .with_time(self.time);
        let change = match self.doc.commit_with(options) {
            Some(hash) => self.doc.get_change_by_hash(&hash),
            None => None,
        };
        if let Some(c) = &change {
            // The other limits (predecessors, key bytes) are only known once
            // the change is encoded; one above them is taken back out.
            if expansion::check_change(c.raw_bytes()).is_err() {
                self.remove_change(&c.hash())?;
                return Err(ProfileError::ChangeTooLarge);
            }
            // §11.2: a writer never creates an object deeper than 256.
            let known = |key: &ObjKey| self.depths.get(key).copied();
            match depth::created_objects(c, known, Some(depth::MAX_DEPTH)) {
                Ok(created) => self.depths.extend(created),
                Err(_) => {
                    self.remove_change(&c.hash())?;
                    return Err(ProfileError::ObjectTooDeep);
                }
            }
            // §11.3, §11.4: the engine writes canonical changes that refer
            // to their own history; one that does not is taken back out.
            match self.history.check_change(c, &Overlay::default()) {
                Ok(added) => self.history.add(added),
                Err(err) => {
                    self.remove_change(&c.hash())?;
                    return Err(err);
                }
            }
            self.seqs.insert(c.actor_id().clone(), c.seq());
        }
        Ok(change)
    }

    /// Rebuild the document without the change `hash`, which has no
    /// dependents (the last local change). The writer's next change takes
    /// the same sequence number (§9).
    fn remove_change(&mut self, hash: &ChangeHash) -> Result<(), ProfileError> {
        let keep: Vec<Change> = all_changes(&mut self.doc)?
            .into_iter()
            .filter(|c| c.hash() != *hash)
            .collect();
        let mut doc = AutoCommit::new().with_actor(self.doc.get_actor().clone());
        doc.apply_changes(keep)?;
        drop_patch_log(&mut doc);
        self.doc = doc;
        self.seqs = seqs_of(&mut self.doc)?;
        self.depths = depth::depths_of(&mut self.doc)?;
        self.history = History::of(&mut self.doc)?;
        Ok(())
    }

    /// §16: the initial document, in one change.
    pub fn initialize(&mut self) -> Result<Change, ProfileError> {
        self.transact("profile.init", |doc| {
            doc.put(ROOT, "profile", PROFILE)?;
            doc.put_object(ROOT, "objects", ObjType::Map)?;
            doc.put_object(ROOT, "extensions", ObjType::Map)?;
            Ok(())
        })?
        .ok_or(ProfileError::Automerge("empty change".into()))
    }

    /// §53, §60: create a Task in one change. An Object ID already present
    /// is refused (§21).
    pub fn create_task(&mut self, task: &NewTask) -> Result<Change, ProfileError> {
        let plain = task.to_plain()?;
        self.insert_object("task.create", task.id.as_str(), &plain)
    }

    /// Create any object under `key` in one change, written as given
    /// (strings as scalar strings, `Plain::Text` as Text). Used for other
    /// object types (§25) and for importing state. Refuses a key already
    /// present.
    pub fn insert_object(
        &mut self,
        intent: &str,
        key: &str,
        object: &Plain,
    ) -> Result<Change, ProfileError> {
        let objects = self.objects()?;
        if !self.doc.get_all(&objects, key)?.is_empty() {
            return Err(ProfileError::ObjectIdCollision);
        }
        self.transact(intent, |doc| put_plain(doc, &objects, key, object))?
            .ok_or(ProfileError::Automerge("empty change".into()))
    }

    /// Write scalar `fields` of the Task `key` (`None` deletes, §36) as one
    /// change.
    fn write_task(
        &mut self,
        intent: &str,
        key: &str,
        fields: &[(&str, Option<ScalarValue>)],
    ) -> Result<Change, ProfileError> {
        let task = self.task_id(key)?;
        self.transact(intent, |doc| {
            for (field, value) in fields {
                match value {
                    Some(value) => write_scalar(doc, &task, field, value.clone())?,
                    None => {
                        if !doc.get_all(&task, *field)?.is_empty() {
                            doc.delete(&task, *field)?;
                        }
                    }
                }
            }
            Ok(())
        })?
        .ok_or(ProfileError::Automerge("empty change".into()))
    }

    /// §61: set the title.
    pub fn set_title(&mut self, key: &str, title: &str) -> Result<Change, ProfileError> {
        self.write_task("task.set_title", key, &[("title", Some(title.into()))])
    }

    /// §62: set a standard or extension status.
    pub fn set_status(&mut self, key: &str, status: &str) -> Result<Change, ProfileError> {
        require(values::is_status(status), Diagnostic::InvalidEnumValue)?;
        self.write_task("task.set_status", key, &[("status", Some(status.into()))])
    }

    /// §63: `status = done`, and `completion_date` when given.
    pub fn complete(
        &mut self,
        key: &str,
        completion_date: Option<&str>,
    ) -> Result<Change, ProfileError> {
        let mut fields = vec![("status", Some("done".into()))];
        if let Some(date) = completion_date {
            require(values::is_local_date(date), Diagnostic::InvalidLocalDate)?;
            fields.push(("completion_date", Some(date.into())));
        }
        self.write_task("task.complete", key, &fields)
    }

    /// §64: `status = todo` and no `completion_date`.
    pub fn reopen(&mut self, key: &str) -> Result<Change, ProfileError> {
        self.write_task(
            "task.reopen",
            key,
            &[("status", Some("todo".into())), ("completion_date", None)],
        )
    }

    /// §65: `status = cancelled`; `completion_date` is cleared.
    pub fn cancel(&mut self, key: &str) -> Result<Change, ProfileError> {
        self.write_task(
            "task.cancel",
            key,
            &[
                ("status", Some("cancelled".into())),
                ("completion_date", None),
            ],
        )
    }

    /// §66: set `due` or `scheduled` (or `completion_date`) to a Local
    /// Date.
    pub fn set_date(&mut self, key: &str, field: &str, date: &str) -> Result<Change, ProfileError> {
        require(
            validate::DATE_FIELDS.contains(&field),
            Diagnostic::InvalidFieldType,
        )?;
        require(values::is_local_date(date), Diagnostic::InvalidLocalDate)?;
        self.write_task(
            &format!("task.set_{field}"),
            key,
            &[(field, Some(date.into()))],
        )
    }

    /// §66, §36: clear a date field by deleting the property.
    pub fn clear_date(&mut self, key: &str, field: &str) -> Result<Change, ProfileError> {
        require(
            validate::DATE_FIELDS.contains(&field),
            Diagnostic::InvalidFieldType,
        )?;
        self.write_task(&format!("task.clear_{field}"), key, &[(field, None)])
    }

    /// §38: set a standard or extension priority.
    pub fn set_priority(&mut self, key: &str, priority: &str) -> Result<Change, ProfileError> {
        require(values::is_priority(priority), Diagnostic::InvalidEnumValue)?;
        self.write_task(
            "task.set_priority",
            key,
            &[("priority", Some(priority.into()))],
        )
    }

    /// §54: `lifecycle = deleted`; the object stays in `objects`.
    pub fn delete(&mut self, key: &str) -> Result<Change, ProfileError> {
        let id = self.object_id(key)?;
        self.transact("task.delete", |doc| {
            write_scalar(doc, &id, "lifecycle", "deleted".into())
        })?
        .ok_or(ProfileError::Automerge("empty change".into()))
    }

    /// §55: `lifecycle = active`.
    pub fn restore(&mut self, key: &str) -> Result<Change, ProfileError> {
        let id = self.object_id(key)?;
        self.transact("task.restore", |doc| {
            write_scalar(doc, &id, "lifecycle", "active".into())
        })?
        .ok_or(ProfileError::Automerge("empty change".into()))
    }

    /// §47, §69: write the chosen value of a conflicted field. Call it on a
    /// document that has merged every locally available head; the write
    /// supersedes every value visible here.
    pub fn resolve_field_conflict(
        &mut self,
        key: &str,
        field: &str,
        value: &str,
    ) -> Result<Change, ProfileError> {
        let id = self.object_id(key)?;
        self.transact("task.resolve_field_conflict", |doc| {
            write_scalar(doc, &id, field, value.into())
        })?
        .ok_or(ProfileError::Automerge("empty change".into()))
    }

    fn collection(
        &mut self,
        intent: &str,
        key: &str,
        field: &str,
        member: &str,
        add: bool,
    ) -> Result<Option<Change>, ProfileError> {
        let task = self.task_id(key)?;
        let map = match self.doc.get(&task, field)? {
            Some((Value::Object(ObjType::Map), id)) => id,
            _ => return Err(Diagnostic::InvalidCollectionRepresentation.into()),
        };
        self.transact(intent, |doc| {
            if add {
                write_scalar(doc, &map, member, ScalarValue::Boolean(true))
            } else {
                if !doc.get_all(&map, member)?.is_empty() {
                    doc.delete(&map, member)?;
                }
                Ok(())
            }
        })
    }

    /// Write any value at `field` of the object under `key`, as one
    /// change named `intent`. Not a profile intent: it does no validation
    /// and exists to import or repair state and to build test states. A
    /// result that breaks the profile shows in
    /// [`SharedObjects::object_status`].
    pub fn write_field(
        &mut self,
        intent: &str,
        key: &str,
        field: &str,
        value: &Plain,
    ) -> Result<Change, ProfileError> {
        let id = self.object_id(key)?;
        self.transact(intent, |doc| match value {
            Plain::Map(_) | Plain::List(_) | Plain::Text(_) => put_plain(doc, &id, field, value),
            scalar => write_scalar(doc, &id, field, scalar_of(scalar)),
        })?
        .ok_or(ProfileError::Automerge("empty change".into()))
    }

    /// §67: add a tag (NFC normalization is the caller's, §40). A tag
    /// already present is written again, so it survives a concurrent
    /// removal (§41).
    pub fn add_tag(&mut self, key: &str, tag: &str) -> Result<Change, ProfileError> {
        require(values::is_tag(tag), Diagnostic::InvalidTag)?;
        self.collection("task.add_tag", key, "tags", tag, true)?
            .ok_or(ProfileError::Automerge("empty change".into()))
    }

    /// §67: remove a tag. `None` when it was not present.
    pub fn remove_tag(&mut self, key: &str, tag: &str) -> Result<Option<Change>, ProfileError> {
        self.collection("task.remove_tag", key, "tags", tag, false)
    }

    /// §68: add an assignee (§43: survives a concurrent removal).
    pub fn add_assignee(
        &mut self,
        key: &str,
        principal: &PrincipalId,
    ) -> Result<Change, ProfileError> {
        self.collection(
            "task.add_assignee",
            key,
            "assignees",
            &principal_ref(principal),
            true,
        )?
        .ok_or(ProfileError::Automerge("empty change".into()))
    }

    /// §68: remove an assignee. `None` when it was not assigned.
    pub fn remove_assignee(
        &mut self,
        key: &str,
        principal: &PrincipalId,
    ) -> Result<Option<Change>, ProfileError> {
        self.collection(
            "task.remove_assignee",
            key,
            "assignees",
            &principal_ref(principal),
            false,
        )
    }
}

/// §8, §11 (SO-SEC1): whether `change` was written by the §8 actor of
/// (`resource`, `signer`), the Principal that signed the Data Unit carrying
/// it; otherwise `PROFILE_INVALID` with `CHANGE_ACTOR_MISMATCH`. Any path
/// that accepts a change together with its LFCP signer must call this
/// before applying it.
pub fn check_change_actor(
    resource: &ResourceId,
    signer: &PrincipalId,
    change: &Change,
) -> Result<(), ProfileError> {
    if change.actor_id().to_bytes() == actor_id_bytes(resource, signer) {
        Ok(())
    } else {
        Err(Diagnostic::ChangeActorMismatch.into())
    }
}

/// Put `value` at `obj[field]` as a real operation. §58 (G-SC4):
/// when the single current value already equals `value`, delete it first so
/// the write is a new operation rather than nothing.
fn write_scalar(
    doc: &mut AutoCommit,
    obj: &ObjId,
    field: &str,
    value: ScalarValue,
) -> Result<(), ProfileError> {
    let current = doc.get_all(obj, field)?;
    if let [(Value::Scalar(existing), _)] = current.as_slice() {
        if existing.as_ref() == &value {
            doc.delete(obj, field)?;
        }
    }
    doc.put(obj, field, value)?;
    Ok(())
}

/// Write `value` at `obj[key]`, creating maps and lists as needed.
fn put_plain(
    doc: &mut AutoCommit,
    obj: &ObjId,
    key: &str,
    value: &Plain,
) -> Result<(), ProfileError> {
    match value {
        Plain::Map(entries) => {
            let map = doc.put_object(obj, key, ObjType::Map)?;
            for (k, v) in entries {
                put_plain(doc, &map, k, v)?;
            }
        }
        Plain::List(items) => {
            let list = doc.put_object(obj, key, ObjType::List)?;
            for (index, item) in items.iter().enumerate() {
                insert_plain(doc, &list, index, item)?;
            }
        }
        Plain::Text(text) => {
            let id = doc.put_object(obj, key, ObjType::Text)?;
            doc.splice_text(&id, 0, 0, text)?;
        }
        scalar => {
            doc.put(obj, key, scalar_of(scalar))?;
        }
    }
    Ok(())
}

fn insert_plain(
    doc: &mut AutoCommit,
    list: &ObjId,
    index: usize,
    value: &Plain,
) -> Result<(), ProfileError> {
    match value {
        Plain::Map(entries) => {
            let map = doc.insert_object(list, index, ObjType::Map)?;
            for (k, v) in entries {
                put_plain(doc, &map, k, v)?;
            }
        }
        Plain::List(items) => {
            let inner = doc.insert_object(list, index, ObjType::List)?;
            for (i, item) in items.iter().enumerate() {
                insert_plain(doc, &inner, i, item)?;
            }
        }
        Plain::Text(text) => {
            let id = doc.insert_object(list, index, ObjType::Text)?;
            doc.splice_text(&id, 0, 0, text)?;
        }
        scalar => {
            doc.insert(list, index, scalar_of(scalar))?;
        }
    }
    Ok(())
}

fn scalar_of(value: &Plain) -> ScalarValue {
    match value {
        Plain::Null | Plain::Unknown => ScalarValue::Null,
        Plain::Bool(b) => ScalarValue::Boolean(*b),
        Plain::Int(i) => ScalarValue::Int(*i),
        Plain::Uint(u) => ScalarValue::Uint(*u),
        Plain::F64(f) => ScalarValue::F64(*f),
        Plain::Str(s) => ScalarValue::Str(s.as_str().into()),
        Plain::Bytes(b) => ScalarValue::Bytes(b.clone()),
        Plain::Counter(c) => ScalarValue::counter(*c),
        Plain::Timestamp(t) => ScalarValue::Timestamp(*t),
        Plain::Map(_) | Plain::List(_) | Plain::Text(_) => {
            unreachable!("objects are written by put_plain")
        }
    }
}

#[cfg(test)]
mod admission_tests {
    //! §14.1 (baseline.6) and the E4 crash: a change whose sequence skips
    //! its actor's next number, with every dependency present, makes
    //! automerge 0.12 abort (change_graph assert). It must be refused
    //! before the engine, and the document must stay usable.

    use super::*;

    fn put_root(doc: &mut SharedObjects, key: &str, value: &str) -> Change {
        doc.transact("test", |d| {
            d.put(ROOT, key, value)?;
            Ok(())
        })
        .unwrap()
        .unwrap()
    }

    fn actor(n: u8) -> ActorId {
        ActorId::from(vec![n; 16])
    }

    /// A writer's first change (init) and a second one, re-encoded with
    /// sequence 3: its only dependency is the first change, so a receiver
    /// holding the first has every dependency and sees a gap.
    fn crafted() -> (Change, Change, Change) {
        let mut writer = SharedObjects::new(actor(1));
        let first = writer.initialize().unwrap();
        let second = put_root(&mut writer, "note", "hello");
        let mut expanded = second.decode();
        expanded.seq = 3;
        expanded.hash = None;
        let gapped = Change::from(expanded);
        assert_eq!(gapped.deps(), &[first.hash()]);
        assert_eq!(gapped.seq(), 3);
        (first, second, gapped)
    }

    fn state(doc: &mut SharedObjects) -> (Vec<ChangeHash>, Vec<u8>) {
        (doc.heads(), doc.save())
    }

    #[test]
    fn a_sequence_gap_is_refused_before_the_engine() {
        let (first, second, gapped) = crafted();
        let mut receiver = SharedObjects::new(actor(2));
        assert!(receiver
            .apply_changes(vec![first.clone()])
            .unwrap()
            .is_empty());
        let before = state(&mut receiver);

        assert_eq!(
            receiver.apply_changes(vec![gapped.clone()]),
            Err(ProfileError::Invalid(Diagnostic::InvalidAutomergeBytes))
        );
        // Nothing changed; the document still takes the real change, a local
        // write, and saves and loads.
        assert_eq!(state(&mut receiver), before);
        assert!(receiver.apply_changes(vec![second]).unwrap().is_empty());
        put_root(&mut receiver, "mine", "ok");
        let save = receiver.save();
        let mut loaded = SharedObjects::load(&save, actor(2)).unwrap();
        assert_eq!(loaded.heads(), receiver.heads());
    }

    #[test]
    fn the_engine_path_restores_the_document_if_it_ever_fails() {
        // The admission check bypassed: the engine's abort is caught and the
        // document as it was before is kept, never the half-applied one.
        let (first, _, gapped) = crafted();
        // The crafted change really aborts the bare engine (E4).
        let raw = catch_unwind(AssertUnwindSafe(|| {
            let mut doc = AutoCommit::new();
            doc.apply_changes(vec![first.clone()]).unwrap();
            doc.apply_changes(vec![gapped.clone()])
        }));
        assert!(raw.is_err(), "automerge 0.12 aborts on a sequence gap");
        let mut receiver = SharedObjects::new(actor(2));
        receiver.apply_changes(vec![first]).unwrap();
        let before = state(&mut receiver);
        assert_eq!(
            receiver.engine_apply(gapped, Created::default()),
            Err(ProfileError::Invalid(Diagnostic::InvalidAutomergeBytes))
        );
        assert_eq!(state(&mut receiver), before);
        put_root(&mut receiver, "after", "ok");
        SharedObjects::load(&receiver.save(), actor(2)).unwrap();
    }

    #[test]
    fn missing_dependencies_never_enter_the_engine() {
        let (first, second, _) = crafted();
        let mut receiver = SharedObjects::new(actor(2));
        // Alone, the second change waits outside the document.
        assert_eq!(
            receiver.apply_changes(vec![second.clone()]).unwrap(),
            vec![second.clone()]
        );
        assert!(receiver.heads().is_empty());
        assert!(receiver.changes().is_empty());
        // In any order, both apply once the dependency is there.
        assert!(receiver
            .apply_changes(vec![second.clone(), first.clone()])
            .unwrap()
            .is_empty());
        assert_eq!(receiver.heads(), vec![second.hash()]);
        // Again: duplicates change nothing.
        assert!(receiver
            .apply_changes(vec![first, second])
            .unwrap()
            .is_empty());
    }

    #[test]
    fn a_taken_sequence_is_held_before_the_engine() {
        // §14.1 (POST-001): another sequence-2 change by the same actor is
        // held, not merged and not refused; excluding the change that holds
        // the sequence applies it.
        let (first, second, _) = crafted();
        let mut twin = SharedObjects::new(actor(1));
        twin.apply_changes(vec![first.clone()]).unwrap();
        let other = put_root(&mut twin, "note", "other");
        assert_eq!(other.seq(), 2);
        let mut receiver = SharedObjects::new(actor(2));
        receiver.apply_changes(vec![first, second.clone()]).unwrap();
        let before = state(&mut receiver);
        assert!(receiver
            .apply_changes(vec![other.clone()])
            .unwrap()
            .is_empty());
        assert_eq!(receiver.held(), std::slice::from_ref(&other));
        assert_eq!(state(&mut receiver), before);
        // Held once, however often it arrives.
        assert_eq!(
            receiver.apply_change(other.clone()),
            Ok(ChangeOutcome::Held)
        );
        assert_eq!(receiver.held().len(), 1);
        // A rebuild that removes nothing leaves it held.
        assert_eq!(receiver.exclude(&[]).unwrap(), Excluded::default());
        assert_eq!(receiver.held().len(), 1);
        // Excluding the change that holds the sequence applies it.
        let excluded = receiver.exclude(&[second.hash()]).unwrap();
        assert_eq!(excluded.removed, vec![second.hash()]);
        assert_eq!(excluded.applied, vec![other.hash()]);
        assert!(receiver.held().is_empty());
        assert_eq!(receiver.heads(), vec![other.hash()]);
        assert_eq!(receiver.apply_change(other), Ok(ChangeOutcome::Duplicate));
    }

    #[test]
    fn an_unknown_other_actor_is_refused_before_the_engine() {
        // §11.1 (SO-UNKNOWN-ACTOR): actor 4 overwrites a key actor 3 wrote,
        // so its change lists actor 3 among its other actors; re-encoded to
        // depend on the first change only, it reaches a receiver that has
        // never seen actor 3, with every dependency present.
        let (first, _, _) = crafted();
        let mut third = SharedObjects::new(actor(3));
        third.apply_changes(vec![first.clone()]).unwrap();
        let by_third = put_root(&mut third, "note", "three");
        let mut fourth = SharedObjects::new(actor(4));
        fourth.apply_changes(vec![first.clone(), by_third]).unwrap();
        let overwrite = put_root(&mut fourth, "note", "four");
        assert_eq!(overwrite.other_actor_ids(), [actor(3)]);
        let mut expanded = overwrite.decode();
        expanded.deps = vec![first.hash()];
        expanded.hash = None;
        let unknown = Change::from(expanded);
        assert_eq!(unknown.other_actor_ids(), [actor(3)]);

        // The bare engine panics on it.
        let raw = catch_unwind(AssertUnwindSafe(|| {
            let mut doc = AutoCommit::new();
            doc.apply_changes(vec![first.clone()]).unwrap();
            doc.apply_changes(vec![unknown.clone()])
        }));
        assert!(!matches!(raw, Ok(Ok(()))), "automerge 0.12 refuses it");

        let mut receiver = SharedObjects::new(actor(2));
        receiver.apply_changes(vec![first]).unwrap();
        let before = state(&mut receiver);
        assert!(matches!(
            receiver.admit(&unknown),
            Err(ProfileError::Invalid(Diagnostic::InvalidAutomergeBytes))
        ));
        assert_eq!(
            receiver.apply_changes(vec![unknown]),
            Err(ProfileError::Invalid(Diagnostic::InvalidAutomergeBytes))
        );
        assert_eq!(state(&mut receiver), before);
    }

    #[test]
    fn a_transaction_above_the_change_limits_fails_locally() {
        // §11.1: a writer never emits a change above the limits.
        let mut doc = SharedObjects::new(actor(1));
        doc.initialize().unwrap();
        let before = state(&mut doc);
        // 17,001 operations: refused before anything commits.
        let many = Plain::Map(
            (0..17_000)
                .map(|i| (format!("k{i}"), Plain::Int(i)))
                .collect(),
        );
        assert_eq!(
            doc.insert_object("big", "many", &many),
            Err(ProfileError::ChangeTooLarge)
        );
        assert_eq!(state(&mut doc), before);
        // 16,001 operations writing 16,000 keys of 300 bytes: 4.8 MB of
        // strings, only known once encoded; the change is taken back out.
        let keys = Plain::Map(
            (0..16_000)
                .map(|i| (format!("{i:0>300}"), Plain::Bool(true)))
                .collect(),
        );
        assert_eq!(
            doc.insert_object("keys", "map", &keys),
            Err(ProfileError::ChangeTooLarge)
        );
        assert_eq!(state(&mut doc), before);
        // The writer goes on with the next sequence number.
        let next = put_root(&mut doc, "after", "ok");
        assert_eq!(next.seq(), 2);
        SharedObjects::load(&doc.save(), actor(1)).unwrap();
    }

    /// A map nesting `levels` maps in all (itself included).
    fn nested(levels: usize) -> Plain {
        let mut value = Plain::Map(BTreeMap::new());
        for _ in 1..levels {
            value = Plain::Map(BTreeMap::from([("d".to_owned(), value)]));
        }
        value
    }

    #[test]
    fn a_writer_never_creates_an_object_deeper_than_256() {
        // §11.2: the root is depth 0, `objects` 1, an object 2; an object
        // nesting 255 maps reaches 256, one more 257.
        let mut doc = SharedObjects::new(actor(1));
        doc.initialize().unwrap();
        let before = state(&mut doc);
        assert_eq!(
            doc.insert_object("deep", "over", &nested(256)),
            Err(ProfileError::ObjectTooDeep)
        );
        assert_eq!(state(&mut doc), before);
        let at_limit = doc.insert_object("deep", "limit", &nested(255)).unwrap();
        assert_eq!(at_limit.seq(), 2, "the refused change was taken back out");

        // The depths survive a reload and a fork: the next level is
        // refused there too, whether written locally or received.
        let deepest = |doc: &SharedObjects| {
            let mut obj = doc.object_id("limit").unwrap();
            while let Some((_, child)) = doc.doc.get(&obj, "d").unwrap() {
                obj = child;
            }
            obj
        };
        let mut loaded = SharedObjects::load(&doc.save(), actor(1)).unwrap();
        let obj = deepest(&loaded);
        assert_eq!(
            loaded.transact("deeper", |d| {
                d.put_object(&obj, "d", ObjType::Text)?;
                Ok(())
            }),
            Err(ProfileError::ObjectTooDeep)
        );
        let mut writer = doc.fork(actor(2));
        let obj = deepest(&writer);
        let deeper = writer
            .doc
            .put_object(&obj, "d", ObjType::List)
            .map(|_| writer.doc.commit())
            .unwrap()
            .unwrap();
        let deeper = writer.doc.get_change_by_hash(&deeper).unwrap().clone();
        let before = state(&mut loaded);
        assert_eq!(
            loaded.apply_changes(vec![deeper]),
            Err(ProfileError::Invalid(Diagnostic::InvalidAutomergeBytes))
        );
        assert_eq!(state(&mut loaded), before);
    }

    #[test]
    fn merge_goes_through_admission() {
        // M8: a replica whose history equivocates with ours goes through
        // merge as through apply_changes: its change is held (§14.1), and
        // the document stays as it was.
        let (first, second, _) = crafted();
        let mut twin = SharedObjects::new(actor(1));
        twin.apply_changes(vec![first.clone()]).unwrap();
        put_root(&mut twin, "note", "other");
        let mut receiver = SharedObjects::new(actor(2));
        receiver
            .apply_changes(vec![first.clone(), second.clone()])
            .unwrap();
        let before = state(&mut receiver);
        assert!(receiver.merge(&mut twin).unwrap().is_empty());
        assert_eq!(receiver.held().len(), 1, "the twin's change is held");
        assert_eq!(state(&mut receiver), before);
        put_root(&mut receiver, "after", "ok");
        SharedObjects::load(&receiver.save(), actor(2)).unwrap();

        // A sound replica merges: its changes, ours, and a later write.
        let mut peer = SharedObjects::new(actor(3));
        peer.apply_changes(vec![first, second]).unwrap();
        let theirs = put_root(&mut peer, "theirs", "yes");
        receiver.merge(&mut peer).unwrap();
        assert!(receiver.changes().iter().any(|c| c.hash() == theirs.hash()));
        assert_eq!(put_root(&mut receiver, "next", "ok").seq(), 2);
        // Merging again changes nothing.
        let heads = receiver.heads();
        receiver.merge(&mut peer).unwrap();
        assert_eq!(receiver.heads(), heads);
    }

    #[test]
    fn after_a_rebuild_without_its_own_change_a_writer_reuses_the_sequence() {
        // §9 (baseline.6): the rebuilt document is the same history; the
        // writer's next change takes the actor's next sequence there, which
        // equals that of the removed change.
        let (first, second, _) = crafted();
        let mut rebuilt = SharedObjects::new(actor(1));
        assert!(rebuilt
            .apply_changes(vec![first.clone()])
            .unwrap()
            .is_empty());
        let again = put_root(&mut rebuilt, "note", "rewritten");
        assert_eq!(again.seq(), second.seq());
        assert_ne!(again.hash(), second.hash());
        // A receiver that also excluded the removed change takes it.
        let mut receiver = SharedObjects::new(actor(2));
        receiver.apply_changes(vec![first]).unwrap();
        assert!(receiver
            .apply_changes(vec![again.clone()])
            .unwrap()
            .is_empty());
        // One that still holds it holds the new change (§14.1), before the
        // engine, until it rebuilds the same way.
        let mut stale = SharedObjects::new(actor(3));
        stale
            .apply_changes(vec![crafted().0, second.clone()])
            .unwrap();
        assert_eq!(stale.apply_change(again.clone()), Ok(ChangeOutcome::Held));
        assert_eq!(
            stale.exclude(&[second.hash()]).unwrap().applied,
            vec![again.hash()]
        );
    }

    #[test]
    fn a_batch_in_any_order_with_duplicates_converges() {
        let mut writer = SharedObjects::new(actor(1));
        writer.initialize().unwrap();
        let mut history = vec![];
        for i in 0..20 {
            history.push(put_root(&mut writer, "n", &format!("v{i}")));
        }
        let mut all = writer.changes();
        all.reverse();
        all.extend(all.clone()); // every change twice
        let mut receiver = SharedObjects::new(actor(2));
        assert!(receiver.apply_changes(all).unwrap().is_empty());
        assert_eq!(receiver.heads(), writer.heads());
        // A batch missing its root waits whole, outside the engine.
        let mut late = SharedObjects::new(actor(3));
        let tail: Vec<Change> = writer.changes().into_iter().skip(1).collect();
        assert_eq!(late.apply_changes(tail.clone()).unwrap().len(), tail.len());
        assert!(late.changes().is_empty());
    }

    #[test]
    fn a_batch_stops_at_a_refused_change_and_keeps_what_came_before() {
        let (first, second, gapped) = crafted();
        let mut receiver = SharedObjects::new(actor(2));
        // The gap is refused before the engine; the first change, admitted
        // before it, is applied; the document stays usable.
        assert_eq!(
            receiver.apply_changes(vec![first.clone(), gapped]),
            Err(ProfileError::Invalid(Diagnostic::InvalidAutomergeBytes))
        );
        assert_eq!(receiver.heads(), vec![first.hash()]);
        assert!(receiver.apply_changes(vec![second]).unwrap().is_empty());
        SharedObjects::load(&receiver.save(), actor(2)).unwrap();
        // Two changes for one actor sequence in one batch: the later one is
        // held (§14.1), the batch goes on.
        let mut twin = SharedObjects::new(actor(1));
        twin.apply_changes(vec![first.clone()]).unwrap();
        let other = put_root(&mut twin, "note", "other");
        let (_, second, _) = crafted();
        let mut fresh = SharedObjects::new(actor(4));
        assert!(fresh
            .apply_changes(vec![first, second.clone(), other.clone()])
            .unwrap()
            .is_empty());
        assert_eq!(fresh.heads(), vec![second.hash()]);
        assert_eq!(fresh.held(), std::slice::from_ref(&other));
    }

    #[test]
    fn a_save_that_aborts_the_engine_is_invalid_bytes() {
        // Loading is guarded the same way (a Snapshot carries a save image).
        assert_eq!(
            load_guarded(&[0x85, 0x6f, 0x4a, 0x83, 0, 0, 0, 0, 0, 1, 0]).map(|_| ()),
            Err(ProfileError::Invalid(Diagnostic::InvalidAutomergeBytes))
        );
    }
}
