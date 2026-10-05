//! Profile validation (SHARED-OBJECTS-PROFILE-01 §74–§77).
//!
//! Validation is per object: one invalid object never makes the Resource
//! or another object unusable (§77). Each failure is `PROFILE_INVALID` with
//! exactly one [`Diagnostic`] per invalid value (§74.1, SOG-2):
//! [`object_problems`] and [`root_problems`] return one [`Problem`] per
//! broken field, member or key, as a JSON Pointer with the first broken
//! rule in the order of the §74.1 table (structure and values first,
//! `IMMUTABLE_FIELD_MUTATED` last; [`Diagnostic`] is declared in that
//! order). A field with concurrent values gets the earliest diagnostic
//! over its values. [`object_status`] condenses an object to its first
//! diagnostic, for callers that only quarantine. The rules:
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
//! "Text" means an Automerge scalar string. A value held as collaborative
//! Text anywhere in an object (any field, `extensions`, nested maps and
//! lists) is `INVALID_FIELD_TYPE` at its own pointer (§30, G-SC3,
//! SO-STRINGS); by §74.1 order it comes before the field's other rules. A conflicted field is valid
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

/// [`values_of`] for the rules: a value nested too deep reads as
/// [`Plain::Unknown`] (see [`values::read_truncated`]) instead of failing.
fn field_values(doc: &AutoCommit, obj: &ObjId, field: &str) -> Result<Vec<Plain>, ProfileError> {
    doc.get_all(obj, field)?
        .iter()
        .map(|(value, id)| values::read_truncated(doc, value, id))
        .collect()
}

/// One profile-invalid value (§74.1): where it is, as an RFC 6901 JSON
/// Pointer into the document, and its diagnostic.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Problem {
    /// The JSON Pointer of the invalid value (or of the object, for a
    /// missing field).
    pub pointer: String,
    /// The diagnostic: for a value that breaks several rules, or a field
    /// whose concurrent values break different ones, the first in §74.1
    /// table order.
    pub diagnostic: Diagnostic,
}

/// `segments` as an RFC 6901 JSON Pointer.
fn pointer(segments: &[&str]) -> String {
    segments
        .iter()
        .map(|s| format!("/{}", s.replace('~', "~0").replace('/', "~1")))
        .collect()
}

/// Problems gathered for pointers; each pointer keeps its earliest
/// diagnostic in §74.1 table order (SOG-2).
#[derive(Default)]
struct Problems(std::collections::BTreeMap<String, Diagnostic>);

impl Problems {
    fn add(&mut self, segments: &[&str], diagnostic: Diagnostic) {
        let entry = self.0.entry(pointer(segments)).or_insert(diagnostic);
        *entry = (*entry).min(diagnostic);
    }

    fn into_vec(self) -> Vec<Problem> {
        self.0
            .into_iter()
            .map(|(pointer, diagnostic)| Problem {
                pointer,
                diagnostic,
            })
            .collect()
    }
}

/// `INVALID_FIELD_TYPE` for every value under the map or list `obj` (at
/// `path`) that is collaborative Text, however deep (§30, SO-STRINGS), and
/// for every map or list more than [`values::MAX_VALUE_DEPTH`] levels
/// below the object, whose contents are not walked.
fn text_problems(
    doc: &AutoCommit,
    obj: &ObjId,
    path: &mut Vec<String>,
    problems: &mut Problems,
) -> Result<(), ProfileError> {
    let entries: Vec<(String, Vec<(Value<'_>, ObjId)>)> = match doc.object_type(obj) {
        Ok(ObjType::List) => (0..doc.length(obj))
            .map(|i| Ok((i.to_string(), doc.get_all(obj, i)?)))
            .collect::<Result<_, ProfileError>>()?,
        Ok(ObjType::Map | ObjType::Table) => doc
            .keys(obj)
            .map(|k| Ok((k.clone(), doc.get_all(obj, k.as_str())?)))
            .collect::<Result<_, ProfileError>>()?,
        _ => return Ok(()),
    };
    for (segment, values) in entries {
        path.push(segment);
        for (value, child) in values {
            match value {
                Value::Object(ObjType::Text) => {
                    let segments: Vec<&str> = path.iter().map(String::as_str).collect();
                    problems.add(&segments, Diagnostic::InvalidFieldType);
                }
                // `path` is `objects`, the key, then one segment per level.
                Value::Object(_) if path.len() - 2 > values::MAX_VALUE_DEPTH => {
                    let segments: Vec<&str> = path.iter().map(String::as_str).collect();
                    problems.add(&segments, Diagnostic::InvalidFieldType);
                }
                Value::Object(_) => text_problems(doc, &child, path, problems)?,
                Value::Scalar(_) => {}
            }
        }
        path.pop();
    }
    Ok(())
}

/// The root problems (§15, §18, §74): `profile` that is not the profile
/// identifier, `objects` or `extensions` missing or not a map
/// (`INVALID_ROOT`), and every root `extensions` key that is not a
/// reverse-domain name (`INVALID_EXTENSION_NAMESPACE`).
pub fn root_problems(doc: &AutoCommit) -> Result<Vec<Problem>, ProfileError> {
    let mut problems = Problems::default();
    let profile = field_values(doc, &ROOT, "profile")?;
    if profile.is_empty() || profile.iter().any(|p| p.as_str() != Some(PROFILE)) {
        problems.add(&["profile"], Diagnostic::InvalidRoot);
    }
    for key in ["objects", "extensions"] {
        let all = doc.get_all(ROOT, key)?;
        if all.is_empty()
            || all
                .iter()
                .any(|(v, _)| !matches!(v, Value::Object(ObjType::Map)))
        {
            problems.add(&[key], Diagnostic::InvalidRoot);
        }
    }
    for (value, extensions) in doc.get_all(ROOT, "extensions")? {
        if matches!(value, Value::Object(ObjType::Map)) {
            for key in doc.keys(&extensions) {
                if !values::is_reverse_domain(&key) {
                    problems.add(&["extensions", &key], Diagnostic::InvalidExtensionNamespace);
                }
            }
        }
    }
    Ok(problems.into_vec())
}

/// The root rules as one result: `Ok`, or the first root problem's
/// diagnostic in §74.1 table order.
pub fn validate_root(doc: &AutoCommit) -> Result<(), ProfileError> {
    match root_problems(doc)?.into_iter().map(|p| p.diagnostic).min() {
        None => Ok(()),
        Some(diagnostic) => Err(diagnostic.into()),
    }
}

/// The profile state of the object stored under `key` in `objects`: a
/// convenience over [`object_problems`], whose first diagnostic in §74.1
/// table order it reports.
pub fn object_status(
    doc: &AutoCommit,
    objects: &ObjId,
    key: &str,
) -> Result<ObjectStatus, ProfileError> {
    let entries = doc.get_all(objects, key)?;
    if entries.len() > 1 {
        return Ok(ObjectStatus::Collision);
    }
    if entries.is_empty() {
        return Err(ProfileError::UnknownObject);
    }
    Ok(
        match object_problems(doc, objects, key)?
            .into_iter()
            .map(|p| p.diagnostic)
            .min()
        {
            None => ObjectStatus::Ready,
            Some(diagnostic) => ObjectStatus::Invalid(diagnostic),
        },
    )
}

/// Rules 2–17 for the object stored under `key` in `objects`: one
/// [`Problem`] per invalid value (SOG-2). Pointers are
/// `/objects/<key>[/<field>[/<member>]]`; a missing field points at the
/// object. Concurrent objects under one key (rule 1, `OBJECT_ID_COLLISION`)
/// are not a diagnostic: use [`object_status`].
pub fn object_problems(
    doc: &AutoCommit,
    objects: &ObjId,
    key: &str,
) -> Result<Vec<Problem>, ProfileError> {
    use Diagnostic::*;
    let mut problems = Problems::default();
    let entries = doc.get_all(objects, key)?;
    let Some((value, obj)) = entries.into_iter().next() else {
        return Err(ProfileError::UnknownObject);
    };
    fn at<'a>(key: &'a str, field: &'a str) -> [&'a str; 3] {
        ["objects", key, field]
    }

    if ObjectId::parse(key).is_err() {
        problems.add(&["objects", key], InvalidObjectId);
    }
    // §15, §74.1 (SOG-2): an `objects` entry that is not a map.
    if !matches!(value, Value::Object(ObjType::Map)) {
        problems.add(&["objects", key], InvalidFieldType);
        return Ok(problems.into_vec());
    }
    let obj = &obj;
    let present =
        |field: &str| -> Result<bool, ProfileError> { Ok(!doc.get_all(obj, field)?.is_empty()) };
    // Every value of `field` must pass `check`; an absent field passes.
    let each = |problems: &mut Problems,
                field: &str,
                check: &dyn Fn(&Plain) -> Result<(), Diagnostic>|
     -> Result<(), ProfileError> {
        for value in field_values(doc, obj, field)? {
            if let Err(d) = check(&value) {
                problems.add(&at(key, field), d);
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

    for field in BASE_FIELDS {
        if !present(field)? {
            problems.add(&["objects", key], MissingRequiredField);
        }
    }
    each(&mut problems, "id", &|p| {
        let id = text(p)?;
        ObjectId::parse(&id).map_err(|_| InvalidObjectId)?;
        if id == key {
            Ok(())
        } else {
            Err(ObjectIdMismatch)
        }
    })?;
    each(&mut problems, "type", &|p| text(p).map(|_| ()))?;
    each(&mut problems, "lifecycle", &|p| {
        enumerated(p, values::is_lifecycle)
    })?;
    each(&mut problems, "created_by", &|p| {
        parse_principal_ref(&text(p)?).map(|_| ())
    })?;
    // §28 (SOG-1): a real date and time, for every object type.
    each(&mut problems, "created_at", &|p| {
        values::is_utc_timestamp(&text(p)?)
            .then_some(())
            .ok_or(InvalidTimestamp)
    })?;
    // §29 (SOG-2): an object's `extensions` that is not a map; §18: each
    // key a reverse-domain name, pointed at by key.
    for (value, extensions) in doc.get_all(obj, "extensions")? {
        if matches!(value, Value::Object(ObjType::Map)) {
            for name in doc.keys(&extensions) {
                if !values::is_reverse_domain(&name) {
                    problems.add(
                        &["objects", key, "extensions", &name],
                        InvalidExtensionNamespace,
                    );
                }
            }
        } else {
            problems.add(&at(key, "extensions"), InvalidFieldType);
        }
    }

    let is_task = field_values(doc, obj, "type")?
        .iter()
        .any(|p| p.as_str() == Some("task"));
    if is_task {
        for field in TASK_FIELDS {
            if !present(field)? {
                problems.add(&["objects", key], MissingRequiredField);
            }
        }
        each(&mut problems, "title", &|p| text(p).map(|_| ()))?;
        each(&mut problems, "status", &|p| {
            enumerated(p, values::is_status)
        })?;
        each(&mut problems, "priority", &|p| {
            enumerated(p, values::is_priority)
        })?;
        for field in DATE_FIELDS {
            // §35, §36 (SOG-2): null is "no date"; anything but a valid
            // Local Date string, a non-string included, is
            // INVALID_LOCAL_DATE.
            each(&mut problems, field, &|p| match p {
                Plain::Null => Ok(()),
                Plain::Str(s) if values::is_local_date(s) => Ok(()),
                _ => Err(InvalidLocalDate),
            })?;
        }
        // §39, §40, §42: a collection is a map whose members are `true`
        // (every concurrent value of a member) and whose keys are valid
        // tags or Principal references; problems point at the member.
        let tag_ok = |tag: &str| values::is_tag(tag).then_some(()).ok_or(InvalidTag);
        let ref_ok = |r: &str| parse_principal_ref(r).map(|_| ());
        for (field, key_ok) in [
            ("tags", &tag_ok as &dyn Fn(&str) -> Result<(), Diagnostic>),
            ("assignees", &ref_ok),
        ] {
            for (value, map) in doc.get_all(obj, field)? {
                if !matches!(value, Value::Object(ObjType::Map)) {
                    problems.add(&at(key, field), InvalidCollectionRepresentation);
                    continue;
                }
                for member in doc.keys(&map) {
                    let here = ["objects", key, field, member.as_str()];
                    if let Err(d) = key_ok(&member) {
                        problems.add(&here, d);
                    }
                    if field_values(doc, &map, &member)?
                        .iter()
                        .any(|v| *v != Plain::Bool(true))
                    {
                        problems.add(&here, InvalidCollectionRepresentation);
                    }
                }
            }
        }
    }

    // §30 (SO-STRINGS): a string anywhere in the object, unknown fields,
    // `extensions` and nested maps and lists included, held as Text.
    text_problems(
        doc,
        obj,
        &mut vec!["objects".into(), key.into()],
        &mut problems,
    )?;

    // Rule 17: immutable fields keep the values the creating change wrote.
    if let Some(created) = doc.hash_for_opid(obj) {
        for field in IMMUTABLE_FIELDS {
            let at_creation: Vec<Plain> = doc
                .get_all_at(obj, field, &[created])?
                .iter()
                .map(|(v, id)| values::read_truncated(doc, v, id))
                .collect::<Result<_, _>>()?;
            if at_creation != field_values(doc, obj, field)? {
                problems.add(&at(key, field), ImmutableFieldMutated);
            }
        }
    }
    Ok(problems.into_vec())
}
