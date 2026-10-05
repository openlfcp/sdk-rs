//! Profile validation (SHARED-OBJECTS-PROFILE-01 §74–§77).
//!
//! Validation is per object: one invalid object never makes the Resource
//! or another object unusable (§77). Each failure is `PROFILE_INVALID` with
//! exactly one [`Diagnostic`] (§74.1). Every rule below is checked, and the
//! diagnostic reported is the first broken one in the order of the §74.1
//! table (structure and values first, `IMMUTABLE_FIELD_MUTATED` last,
//! SOG-2); [`Diagnostic`] is declared in that order. The rules:
//!
//! | # | Rule | Diagnostic | § |
//! | --- | --- | --- | --- |
//! | 1 | concurrent objects under one key | `OBJECT_ID_COLLISION` (not a diagnostic) | §21 |
//! | 2 | the key is a canonical UUIDv7 | `INVALID_OBJECT_ID` | §19 |
//! | 3 | the object is a map | `INVALID_FIELD_TYPE` | §23 |
//! | 4 | `id`, `type`, `lifecycle`, `created_by`, `extensions` present | `MISSING_REQUIRED_FIELD` | §23 |
//! | 5 | `id` is a canonical UUIDv7 equal to the key | `INVALID_OBJECT_ID`, `OBJECT_ID_MISMATCH` | §19, §20, §24 |
//! | 6 | `type` is text | `INVALID_FIELD_TYPE` | §25 |
//! | 7 | `lifecycle` is the string `active` or `deleted` | `INVALID_ENUM_VALUE` | §26 |
//! | 8 | `created_by` is a Principal reference | `INVALID_PRINCIPAL_REF` | §27 |
//! | 9 | `created_at`, if present, is an RFC 3339 UTC timestamp naming a real date and time, for every type | `INVALID_TIMESTAMP` | §28 |
//! | 10 | `extensions` is a map of reverse-domain keys | `INVALID_FIELD_TYPE`, `INVALID_EXTENSION_NAMESPACE` | §18, §29 |
//! | 11 | Task: `title`, `status`, `priority`, `tags`, `assignees` present | `MISSING_REQUIRED_FIELD` | §31 |
//! | 12 | Task: `title` is text | `INVALID_FIELD_TYPE` | §32 |
//! | 13 | Task: `status`, `priority` permitted string values | `INVALID_ENUM_VALUE` | §33, §38 |
//! | 14 | Task: `due`, `scheduled`, `completion_date` absent, null or a Local Date string | `INVALID_LOCAL_DATE` | §35, §36 |
//! | 15 | Task: `tags` a map of `true`, tags non-empty without `#` | `INVALID_COLLECTION_REPRESENTATION`, `INVALID_TAG` | §39, §40 |
//! | 16 | Task: `assignees` a map of `true`, keys Principal references | `INVALID_COLLECTION_REPRESENTATION`, `INVALID_PRINCIPAL_REF` | §42 |
//! | 17 | `id`, `type`, `created_by` equal their values at creation | `IMMUTABLE_FIELD_MUTATED` | §75 |
//!
//! "Text" means an Automerge scalar string. A field held as collaborative
//! Text is `INVALID_FIELD_TYPE` (§30, G-SC3). A conflicted field is valid
//! only if every concurrent value is (§74.1). An object of an unknown type
//! gets rules 1–10 and 17 (§71). The immutability check compares the
//! current values with those written by the change that created the object
//! map (§53: creation is one change), so it needs no earlier state.

use automerge::{AutoCommit, ObjId, ObjType, ReadDoc, Value, ROOT};

use crate::base::ObjectId;
use crate::shared_objects::identity::parse_principal_ref;
use crate::shared_objects::values::{self, Plain};
use crate::shared_objects::{Diagnostic, ProfileError, PROFILE};

/// The profile state of one object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObjectStatus {
    /// The object is valid and can be interpreted.
    Ready,
    /// `PROFILE_INVALID`: quarantine it from normal mutation (§76).
    Invalid(Diagnostic),
    /// `OBJECT_ID_COLLISION`: concurrent objects under one Object ID (§21).
    Collision,
}

/// The base fields every object has (§23).
pub const BASE_FIELDS: [&str; 5] = ["id", "type", "lifecycle", "created_by", "extensions"];
/// The fields every Task has besides the base fields (§31).
pub const TASK_FIELDS: [&str; 5] = ["title", "status", "priority", "tags", "assignees"];
/// The optional Local Date fields of a Task (§35).
pub const DATE_FIELDS: [&str; 3] = ["due", "scheduled", "completion_date"];
/// The immutable fields (§75).
pub const IMMUTABLE_FIELDS: [&str; 3] = ["id", "type", "created_by"];

/// Every concurrent value of `field` of `obj`, as plain data.
pub(crate) fn values_of(
    doc: &AutoCommit,
    obj: &ObjId,
    field: &str,
) -> Result<Vec<Plain>, ProfileError> {
    doc.get_all(obj, field)?
        .iter()
        .map(|(value, id)| values::read(doc, value, id))
        .collect()
}

/// The root rules (§15, §18, §74): `profile` is the profile identifier,
/// `objects` and `extensions` are maps (else `INVALID_ROOT`), and every
/// root `extensions` key is a reverse-domain name (else
/// `INVALID_EXTENSION_NAMESPACE`).
pub fn validate_root(doc: &AutoCommit) -> Result<(), ProfileError> {
    let profile = values_of(doc, &ROOT, "profile")?;
    let is_map = |key: &str| -> Result<bool, ProfileError> {
        let all = doc.get_all(ROOT, key)?;
        Ok(!all.is_empty()
            && all
                .iter()
                .all(|(v, _)| matches!(v, Value::Object(ObjType::Map))))
    };
    let profile_ok = !profile.is_empty() && profile.iter().all(|p| p.as_str() == Some(PROFILE));
    if !(profile_ok && is_map("objects")? && is_map("extensions")?) {
        return Err(Diagnostic::InvalidRoot.into());
    }
    for (_, extensions) in doc.get_all(ROOT, "extensions")? {
        if !doc.keys(&extensions).all(|k| values::is_reverse_domain(&k)) {
            return Err(Diagnostic::InvalidExtensionNamespace.into());
        }
    }
    Ok(())
}

/// The profile state of the object stored under `key` in `objects`.
pub fn object_status(
    doc: &AutoCommit,
    objects: &ObjId,
    key: &str,
) -> Result<ObjectStatus, ProfileError> {
    let entries = doc.get_all(objects, key)?;
    if entries.len() > 1 {
        return Ok(ObjectStatus::Collision);
    }
    let Some((value, obj)) = entries.into_iter().next() else {
        return Err(ProfileError::UnknownObject);
    };
    Ok(match check_object(doc, key, &value, &obj)? {
        Ok(()) => ObjectStatus::Ready,
        Err(diagnostic) => ObjectStatus::Invalid(diagnostic),
    })
}

/// Rules 2–17 for one object. The outer `Result` carries Automerge
/// failures, the inner one the diagnostic: every failure is collected, and
/// the one reported is the first in the §74.1 table order, so a value that
/// breaks several rules, or a field whose concurrent values break
/// different ones, gets the earliest diagnostic (SOG-2).
fn check_object(
    doc: &AutoCommit,
    key: &str,
    value: &Value<'_>,
    obj: &ObjId,
) -> Result<Result<(), Diagnostic>, ProfileError> {
    use Diagnostic::*;
    let mut failures: Vec<Diagnostic> = Vec::new();
    // Every value of `field` must pass `check`; an absent field passes.
    let each = |failures: &mut Vec<Diagnostic>,
                field: &str,
                check: &dyn Fn(&Plain) -> Result<(), Diagnostic>|
     -> Result<(), ProfileError> {
        for value in values_of(doc, obj, field)? {
            if let Err(d) = check(&value) {
                failures.push(d);
            }
        }
        Ok(())
    };
    let text = |p: &Plain| -> Result<String, Diagnostic> {
        p.as_str().map(str::to_owned).ok_or(InvalidFieldType)
    };
    // §26, §33, §38 (SOG-2): a non-string enum value is INVALID_ENUM_VALUE.
    let enumerated = |p: &Plain, valid: fn(&str) -> bool| -> Result<(), Diagnostic> {
        match p.as_str() {
            Some(s) if valid(s) => Ok(()),
            _ => Err(InvalidEnumValue),
        }
    };

    if ObjectId::parse(key).is_err() {
        failures.push(InvalidObjectId);
    }
    // §15, §74.1 (SOG-2): an `objects` entry that is not a map.
    if !matches!(value, Value::Object(ObjType::Map)) {
        failures.push(InvalidFieldType);
        return Ok(first(failures));
    }
    let present =
        |field: &str| -> Result<bool, ProfileError> { Ok(!doc.get_all(obj, field)?.is_empty()) };
    for field in BASE_FIELDS {
        if !present(field)? {
            failures.push(MissingRequiredField);
        }
    }
    each(&mut failures, "id", &|p| {
        let id = text(p)?;
        ObjectId::parse(&id).map_err(|_| InvalidObjectId)?;
        if id == key {
            Ok(())
        } else {
            Err(ObjectIdMismatch)
        }
    })?;
    each(&mut failures, "type", &|p| text(p).map(|_| ()))?;
    each(&mut failures, "lifecycle", &|p| {
        enumerated(p, values::is_lifecycle)
    })?;
    each(&mut failures, "created_by", &|p| {
        parse_principal_ref(&text(p)?).map(|_| ())
    })?;
    // §28 (SOG-1): a real date and time, for every object type.
    each(&mut failures, "created_at", &|p| {
        values::is_utc_timestamp(&text(p)?)
            .then_some(())
            .ok_or(InvalidTimestamp)
    })?;
    // §29 (SOG-2): an object's `extensions` that is not a map.
    each(&mut failures, "extensions", &|p| match p.as_map() {
        None => Err(InvalidFieldType),
        Some(map) if map.keys().all(|k| values::is_reverse_domain(k)) => Ok(()),
        Some(_) => Err(InvalidExtensionNamespace),
    })?;

    let is_task = values_of(doc, obj, "type")?
        .iter()
        .any(|p| p.as_str() == Some("task"));
    if is_task {
        for field in TASK_FIELDS {
            if !present(field)? {
                failures.push(MissingRequiredField);
            }
        }
        each(&mut failures, "title", &|p| text(p).map(|_| ()))?;
        each(&mut failures, "status", &|p| {
            enumerated(p, values::is_status)
        })?;
        each(&mut failures, "priority", &|p| {
            enumerated(p, values::is_priority)
        })?;
        for field in DATE_FIELDS {
            // §35, §36 (SOG-2): null is "no date"; anything but a valid
            // Local Date string, a non-string included, is
            // INVALID_LOCAL_DATE.
            each(&mut failures, field, &|p| match p {
                Plain::Null => Ok(()),
                Plain::Str(s) if values::is_local_date(s) => Ok(()),
                _ => Err(InvalidLocalDate),
            })?;
        }
        let tag_ok = |tag: &str| values::is_tag(tag).then_some(()).ok_or(InvalidTag);
        let ref_ok = |r: &str| parse_principal_ref(r).map(|_| ());
        each(&mut failures, "tags", &|p| collection(p, &tag_ok))?;
        each(&mut failures, "assignees", &|p| collection(p, &ref_ok))?;
        // A collection member written concurrently by two peers has two
        // `true` values; any non-true one is invalid.
        for field in ["tags", "assignees"] {
            if let Some((Value::Object(ObjType::Map), map)) = doc.get(obj, field)? {
                for member in doc.keys(&map) {
                    if let Err(d) = each_member(doc, &map, &member)? {
                        failures.push(d);
                    }
                }
            }
        }
    }

    // Rule 17: immutable fields keep the values the creating change wrote.
    if let Some(created) = doc.hash_for_opid(obj) {
        for field in IMMUTABLE_FIELDS {
            let at_creation: Vec<Plain> = doc
                .get_all_at(obj, field, &[created])?
                .iter()
                .map(|(v, id)| values::read(doc, v, id))
                .collect::<Result<_, _>>()?;
            if at_creation != values_of(doc, obj, field)? {
                failures.push(ImmutableFieldMutated);
            }
        }
    }
    Ok(first(failures))
}

/// The diagnostic first in the §74.1 table order, if any (SOG-2).
fn first(failures: Vec<Diagnostic>) -> Result<(), Diagnostic> {
    failures.into_iter().min().map_or(Ok(()), Err)
}

/// A collection (§39, §42): a map whose members are `true` and whose keys
/// pass `key_ok`.
fn collection(
    p: &Plain,
    key_ok: &dyn Fn(&str) -> Result<(), Diagnostic>,
) -> Result<(), Diagnostic> {
    let map = p
        .as_map()
        .ok_or(Diagnostic::InvalidCollectionRepresentation)?;
    for (key, member) in map {
        if *member != Plain::Bool(true) {
            return Err(Diagnostic::InvalidCollectionRepresentation);
        }
        key_ok(key)?;
    }
    Ok(())
}

fn each_member(
    doc: &AutoCommit,
    map: &ObjId,
    member: &str,
) -> Result<Result<(), Diagnostic>, ProfileError> {
    let all = values_of(doc, map, member)?;
    Ok(if all.iter().all(|v| *v == Plain::Bool(true)) {
        Ok(())
    } else {
        Err(Diagnostic::InvalidCollectionRepresentation)
    })
}
