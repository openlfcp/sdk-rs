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
//! PROVISIONAL (G-SC4): a write always produces an operation. Automerge
//! implementations may skip an assignment of the value already present, so
//! a value equal to the current one is deleted and put again in the same
//! change; a concurrent add then beats a remove (§41, §43) and a restore
//! conflicts with a concurrent delete (§52).
//!
//! PROVISIONAL (G-SC3): every string is written as an Automerge scalar
//! string, never as Text.
//!
//! Objects are never removed from `objects` (§54, §56), and fields the
//! document does not understand are never touched (§70–§72): intents write
//! single properties, not whole objects.

use std::collections::BTreeMap;

use automerge::transaction::{CommitOptions, Transactable};
use automerge::{
    ActorId, AutoCommit, Change, ChangeHash, ObjId, ObjType, ReadDoc, ScalarValue, Value, ROOT,
};

use crate::base::{ObjectId, PrincipalId};
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
#[derive(Debug)]
pub struct SharedObjects {
    doc: AutoCommit,
    time: i64,
}

impl SharedObjects {
    /// An empty document writing as `actor` (see
    /// [`super::identity::actor_id`]). Call [`SharedObjects::initialize`]
    /// to create a Resource's document, or apply its changes.
    pub fn new(actor: ActorId) -> SharedObjects {
        SharedObjects {
            doc: AutoCommit::new().with_actor(actor),
            time: 0,
        }
    }

    /// Load a full-save image (§13) and continue writing as `actor`.
    pub fn load(save: &[u8], actor: ActorId) -> Result<SharedObjects, ProfileError> {
        Ok(SharedObjects {
            doc: AutoCommit::load(save)?.with_actor(actor),
            time: 0,
        })
    }

    /// Set the time recorded in the changes this document writes.
    pub fn set_change_time(&mut self, time: i64) {
        self.time = time;
    }

    /// A full-save image of the document (§13).
    pub fn save(&mut self) -> Vec<u8> {
        self.doc.save()
    }

    /// Apply received Automerge changes (§11).
    pub fn apply_changes(&mut self, changes: Vec<Change>) -> Result<(), ProfileError> {
        Ok(self.doc.apply_changes(changes)?)
    }

    /// A copy writing as `actor`, sharing this document's history.
    pub fn fork(&mut self, actor: ActorId) -> SharedObjects {
        SharedObjects {
            doc: self.doc.fork().with_actor(actor),
            time: self.time,
        }
    }

    /// Merge another replica's changes into this one.
    pub fn merge(&mut self, other: &mut SharedObjects) -> Result<(), ProfileError> {
        self.doc.merge(&mut other.doc)?;
        Ok(())
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
        let options = CommitOptions::default()
            .with_message(intent.to_owned())
            .with_time(self.time);
        Ok(match self.doc.commit_with(options) {
            Some(hash) => self.doc.get_change_by_hash(&hash),
            None => None,
        })
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

/// Put `value` at `obj[field]` as a real operation. PROVISIONAL (G-SC4):
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
