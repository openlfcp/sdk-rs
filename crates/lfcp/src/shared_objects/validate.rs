//! Profile validation (SHARED-OBJECTS-PROFILE-01 §74–§77).
//!
//! Validation is per object: one invalid object never makes the Resource
//! or another object unusable (§77). Each failure is `PROFILE_INVALID` with
//! exactly one [`Diagnostic`] (§74.1), the first rule broken in this order:
//!
//! | # | Rule | Diagnostic | § |
//! | --- | --- | --- | --- |
//! | 1 | concurrent objects under one key | `OBJECT_ID_COLLISION` (not a diagnostic) | §21 |
//! | 2 | the key is a canonical UUIDv7 | `INVALID_OBJECT_ID` | §19 |
//! | 3 | the object is a map | `INVALID_FIELD_TYPE` | §23 |
//! | 4 | `id`, `type`, `lifecycle`, `created_by`, `extensions` present | `MISSING_REQUIRED_FIELD` | §23 |
//! | 5 | `id` is a canonical UUIDv7 equal to the key | `INVALID_OBJECT_ID`, `OBJECT_ID_MISMATCH` | §19, §20, §24 |
//! | 6 | `type` is text | `INVALID_FIELD_TYPE` | §25 |
//! | 7 | `lifecycle` is `active` or `deleted` | `INVALID_ENUM_VALUE` | §26 |
//! | 8 | `created_by` is a Principal reference | `INVALID_PRINCIPAL_REF` | §27 |
//! | 9 | `created_at`, if present, is an RFC 3339 UTC timestamp | `INVALID_TIMESTAMP` | §28 |
//! | 10 | `extensions` is a map of reverse-domain keys | `INVALID_FIELD_TYPE`, `INVALID_EXTENSION_NAMESPACE` | §18, §29 |
//! | 11 | Task: `title`, `status`, `priority`, `tags`, `assignees` present | `MISSING_REQUIRED_FIELD` | §31 |
//! | 12 | Task: `title` is text | `INVALID_FIELD_TYPE` | §32 |
//! | 13 | Task: `status`, `priority` permitted values | `INVALID_ENUM_VALUE` | §33, §38 |
//! | 14 | Task: `due`, `scheduled`, `completion_date` absent, null or a Local Date | `INVALID_LOCAL_DATE` | §35, §36 |
//! | 15 | Task: `tags` a map of `true`, tags non-empty without `#` | `INVALID_COLLECTION_REPRESENTATION`, `INVALID_TAG` | §39, §40 |
//! | 16 | Task: `assignees` a map of `true`, keys Principal references | `INVALID_COLLECTION_REPRESENTATION`, `INVALID_PRINCIPAL_REF` | §42 |
//! | 17 | `id`, `type`, `created_by` equal their values at creation | `IMMUTABLE_FIELD_MUTATED` | §75 |
//!
//! "Text" means an Automerge scalar string. A field held as collaborative
//! Text is `INVALID_FIELD_TYPE` (PROVISIONAL, G-SC3). A conflicted field is
//! valid only if every concurrent value is. An object of an unknown type
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

/// The root rules (§15, §74): `profile` is the profile identifier, and
/// `objects` and `extensions` are maps.
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
    if profile_ok && is_map("objects")? && is_map("extensions")? {
        Ok(())
    } else {
        Err(Diagnostic::InvalidRoot.into())
    }
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
/// failures, the inner one the diagnostic.
fn check_object(
    doc: &AutoCommit,
    key: &str,
    value: &Value<'_>,
    obj: &ObjId,
) -> Result<Result<(), Diagnostic>, ProfileError> {
    use Diagnostic::*;
    // Every value of `field` must pass `check`; an absent field passes.
    let each = |field: &str,
                check: &dyn Fn(&Plain) -> Result<(), Diagnostic>|
     -> Result<Result<(), Diagnostic>, ProfileError> {
        Ok(values_of(doc, obj, field)?.iter().try_for_each(check))
    };
    let text = |p: &Plain| -> Result<String, Diagnostic> {
        p.as_str().map(str::to_owned).ok_or(InvalidFieldType)
    };
    macro_rules! check {
        ($result:expr) => {
            if let Err(d) = $result? {
                return Ok(Err(d));
            }
        };
    }

    if ObjectId::parse(key).is_err() {
        return Ok(Err(InvalidObjectId));
    }
    if !matches!(value, Value::Object(ObjType::Map)) {
        return Ok(Err(InvalidFieldType));
    }
    let present =
        |field: &str| -> Result<bool, ProfileError> { Ok(!doc.get_all(obj, field)?.is_empty()) };
    for field in BASE_FIELDS {
        if !present(field)? {
            return Ok(Err(MissingRequiredField));
        }
    }
    check!(each("id", &|p| {
        let id = text(p)?;
        ObjectId::parse(&id).map_err(|_| InvalidObjectId)?;
        if id == key {
            Ok(())
        } else {
            Err(ObjectIdMismatch)
        }
    }));
    check!(each("type", &|p| text(p).map(|_| ())));
    check!(each("lifecycle", &|p| {
        values::is_lifecycle(&text(p)?)
            .then_some(())
            .ok_or(InvalidEnumValue)
    }));
    check!(each("created_by", &|p| {
        parse_principal_ref(&text(p)?).map(|_| ())
    }));
    check!(each("created_at", &|p| {
        values::is_utc_timestamp(&text(p)?)
            .then_some(())
            .ok_or(InvalidTimestamp)
    }));
    check!(each("extensions", &|p| match p.as_map() {
        None => Err(InvalidFieldType),
        Some(map) if map.keys().all(|k| values::is_reverse_domain(k)) => Ok(()),
        Some(_) => Err(InvalidExtensionNamespace),
    }));

    let is_task = values_of(doc, obj, "type")?
        .iter()
        .any(|p| p.as_str() == Some("task"));
    if is_task {
        for field in TASK_FIELDS {
            if !present(field)? {
                return Ok(Err(MissingRequiredField));
            }
        }
        check!(each("title", &|p| text(p).map(|_| ())));
        check!(each("status", &|p| {
            values::is_status(&text(p)?)
                .then_some(())
                .ok_or(InvalidEnumValue)
        }));
        check!(each("priority", &|p| {
            values::is_priority(&text(p)?)
                .then_some(())
                .ok_or(InvalidEnumValue)
        }));
        for field in DATE_FIELDS {
            check!(each(field, &|p| match p {
                // §36: null is "no date".
                Plain::Null => Ok(()),
                Plain::Str(s) if values::is_local_date(s) => Ok(()),
                _ => Err(InvalidLocalDate),
            }));
        }
        let tag_ok = |tag: &str| values::is_tag(tag).then_some(()).ok_or(InvalidTag);
        let ref_ok = |r: &str| parse_principal_ref(r).map(|_| ());
        check!(each("tags", &|p| collection(p, &tag_ok)));
        check!(each("assignees", &|p| collection(p, &ref_ok)));
        // A collection member written concurrently by two peers has two
        // `true` values; any non-true one is invalid.
        for field in ["tags", "assignees"] {
            if let Some((_, map)) = doc.get(obj, field)? {
                for member in doc.keys(&map) {
                    check!(each_member(doc, &map, &member));
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
                return Ok(Err(ImmutableFieldMutated));
            }
        }
    }
    Ok(Ok(()))
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
