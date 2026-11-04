use super::{parse_resource_ref, Diagnostic as D, CONTAINERS, PROFILE};
use crate::shared_objects::{
    document::SharedObjects,
    identity::parse_principal_ref,
    identity::principal_ref,
    values::{self, Plain},
};
use crate::{
    base::{from_b64url, PrincipalId},
    principal::PrincipalDescriptor,
};
use automerge::{AutoCommit, ObjId, ObjType, Prop, ReadDoc, Value, ROOT};
use std::collections::{BTreeMap, BTreeSet};

/// Read view of an Identity document. Invalid entries are omitted by
/// [`Self::entries`]; raw data remains available for preserving unknown fields.
#[derive(Debug, Clone)]
pub struct IdentityDoc {
    pub(super) doc: AutoCommit,
    pub(super) owner: PrincipalId,
}
impl IdentityDoc {
    /// Inspect a structurally checked Automerge save. This is state validation,
    /// not Snapshot admission: use `IdentityReplica::receive_snapshot` before
    /// trusting a Snapshot as replicated state (§2.2).
    pub fn inspect(save: &[u8], owner: PrincipalId) -> Result<Self, D> {
        let engine = SharedObjects::load(save, automerge::ActorId::from([0u8; 32]))
            .map_err(|_| D::InvalidAutomergeBytes)?;
        Ok(Self {
            doc: engine.automerge().clone(),
            owner,
        })
    }
    /// The underlying document, including unknown and invalid entries.
    pub fn automerge(&self) -> &AutoCommit {
        &self.doc
    }
    /// Validate the root; failure makes every reader unusable (§4 rule 1).
    pub fn validate_root(&self) -> Result<(), D> {
        if scalar_strings(&self.doc, &ROOT, "profile") != [PROFILE.to_string()] {
            return Err(D::InvalidRoot);
        }
        for key in CONTAINERS.into_iter().chain(["identity"]) {
            let id = map(&self.doc, &ROOT, key).ok_or(D::InvalidRoot)?;
            if key == "identity"
                && scalar_strings(&self.doc, &id, "root") != [principal_ref(&self.owner)]
            {
                return Err(D::InvalidRoot);
            }
        }
        Ok(())
    }
    /// Validate one extension key without disabling unrelated document readers.
    /// Unknown extension values are preserved and not interpreted (§4; SOP §18).
    pub fn extension_diagnostic(&self, key: &str) -> Option<D> {
        if let Err(d) = self.validate_root() {
            return Some(d);
        }
        if !values::is_reverse_domain(key) {
            return Some(D::InvalidExtensionNamespace);
        }
        let extensions = map(&self.doc, &ROOT, "extensions").unwrap();
        self.doc
            .get_all(extensions, key)
            .unwrap_or_default()
            .is_empty()
            .then_some(D::MissingRequiredField)
    }
    /// Full plain state, preserving unknown fields (Automerge-selected values).
    pub fn plain(&self) -> Result<Plain, D> {
        values::read(&self.doc, &Value::Object(ObjType::Map), &ROOT)
            .map_err(|_| D::InvalidFieldType)
    }
    /// Validate all concurrent maps and field values of one entry (§4).
    pub fn entry_diagnostic(&self, container: &str, key: &str) -> Option<D> {
        if let Err(d) = self.validate_root() {
            return Some(d);
        }
        let Some(parent) = map(&self.doc, &ROOT, container) else {
            return Some(D::InvalidRoot);
        };
        let vals = self.doc.get_all(&parent, key).unwrap_or_default();
        if vals.is_empty() {
            return Some(D::MissingRequiredField);
        }
        let mut errors = BTreeSet::new();
        if container == "roster" {
            if parse_resource_ref(key).is_err() {
                errors.insert(D::InvalidResourceRef);
            }
        } else if parse_principal_ref(key).is_err() {
            errors.insert(D::InvalidPrincipalRef);
        }
        let conflicted_maps = container == "requests" && vals.len() > 1;
        for (v, id) in vals {
            if v != Value::Object(ObjType::Map) {
                errors.insert(D::InvalidFieldType);
                continue;
            }
            validate_entry(&self.doc, container, key, &id, &mut errors);
        }
        if errors.is_empty() && conflicted_maps {
            errors.insert(D::InvalidFieldType);
        }
        errors.into_iter().next()
    }
    /// Valid entries only. Unknown fields are retained. `missing_keys` is
    /// replaced by the union of all concurrent hints (§4 rule 2).
    pub fn entries(&self, container: &str) -> Result<BTreeMap<String, Plain>, D> {
        self.validate_root()?;
        if !["roster", "devices", "requests"].contains(&container) {
            return Err(D::InvalidRoot);
        }
        let parent = map(&self.doc, &ROOT, container).ok_or(D::InvalidRoot)?;
        let mut result = BTreeMap::new();
        for key in self.doc.keys(&parent) {
            if self.entry_diagnostic(container, &key).is_some() {
                continue;
            }
            let (v, id) = self
                .doc
                .get(&parent, &key)
                .ok()
                .flatten()
                .ok_or(D::InvalidFieldType)?;
            let mut value = values::read(&self.doc, &v, &id).map_err(|_| D::InvalidFieldType)?;
            if container == "devices" {
                if let Plain::Map(ref mut entry) = value {
                    let hints = self.missing_keys(&key)?;
                    if !hints.is_empty() || entry.contains_key("missing_keys") {
                        entry.insert(
                            "missing_keys".into(),
                            Plain::Map(
                                hints
                                    .into_iter()
                                    .map(|(r, epochs)| {
                                        (
                                            r,
                                            Plain::List(
                                                epochs.into_iter().map(Plain::Uint).collect(),
                                            ),
                                        )
                                    })
                                    .collect(),
                            ),
                        );
                    }
                }
            }
            result.insert(key, value);
        }
        Ok(result)
    }
    /// The union of every concurrent `missing_keys` map and epoch list.
    pub fn missing_keys(&self, device: &str) -> Result<BTreeMap<String, BTreeSet<u64>>, D> {
        if let Some(d) = self.entry_diagnostic("devices", device) {
            return Err(d);
        }
        let parent = map(&self.doc, &ROOT, "devices").ok_or(D::InvalidRoot)?;
        let mut result = BTreeMap::new();
        for (_, entry) in self.doc.get_all(&parent, device).unwrap_or_default() {
            collect_hints(&self.doc, &entry, &mut result, &mut BTreeSet::new());
        }
        Ok(result)
    }
}

pub(super) fn map(doc: &AutoCommit, obj: &ObjId, key: &str) -> Option<ObjId> {
    let values = doc.get_all(obj, key).ok()?;
    match values.as_slice() {
        [(Value::Object(ObjType::Map), id)] => Some(id.clone()),
        _ => None,
    }
}
fn vals(doc: &AutoCommit, obj: &ObjId, prop: impl Into<Prop>) -> Vec<Plain> {
    let mut out = Vec::new();
    for (v, id) in doc.get_all(obj, prop).unwrap_or_default() {
        let p = values::read(doc, &v, &id).unwrap_or(Plain::Unknown);
        if !out.iter().any(|old: &Plain| old.agrees_with(&p)) {
            out.push(p);
        }
    }
    out
}
pub(super) fn scalar_strings(doc: &AutoCommit, obj: &ObjId, key: &str) -> Vec<String> {
    vals(doc, obj, key)
        .into_iter()
        .map(|p| match p {
            Plain::Str(s) => s,
            _ => String::new(),
        })
        .collect()
}
fn conflict_under(doc: &AutoCommit, obj: &ObjId, depth: usize) -> bool {
    if depth > values::MAX_READ_DEPTH {
        return true;
    }
    let props: Vec<Prop> = match doc.object_type(obj) {
        Ok(ObjType::List) => (0..doc.length(obj)).map(Prop::Seq).collect(),
        _ => doc.keys(obj).map(Prop::Map).collect(),
    };
    props.into_iter().any(|p| {
        vals(doc, obj, p.clone()).len() > 1
            || doc
                .get_all(obj, p)
                .unwrap_or_default()
                .into_iter()
                .any(|(v, id)| matches!(v, Value::Object(_)) && conflict_under(doc, &id, depth + 1))
    })
}
fn validate_entry(
    doc: &AutoCommit,
    container: &str,
    key: &str,
    obj: &ObjId,
    errors: &mut BTreeSet<D>,
) {
    let required = match container {
        "roster" => &["profile", "endpoints", "coordinator"][..],
        "devices" => &["label", "kind"][..],
        "requests" => &["descriptor", "pairing", "label", "kind"][..],
        _ => {
            errors.insert(D::InvalidRoot);
            return;
        }
    };
    for field in required {
        if vals(doc, obj, *field).is_empty() {
            errors.insert(D::MissingRequiredField);
        }
    }
    let kinds = vals(doc, obj, "kind");
    let scope = vals(doc, obj, "scope");
    if container == "requests" {
        if kinds.contains(&Plain::Uint(1)) && scope.is_empty() {
            errors.insert(D::MissingRequiredField);
        }
        if kinds.contains(&Plain::Uint(0)) && !scope.is_empty() {
            errors.insert(D::InvalidFieldType);
        }
        // The conflict fallback is applied only after invalid-value diagnostics.
    }
    for field in doc.keys(obj) {
        for value in vals(doc, obj, &field) {
            let string_field = match container {
                "roster" => ["profile", "coordinator", "name"].contains(&field.as_str()),
                "devices" => ["label", "platform"].contains(&field.as_str()),
                _ => ["descriptor", "pairing", "label", "platform"].contains(&field.as_str()),
            };
            if string_field && !matches!(value, Plain::Str(_)) {
                errors.insert(D::InvalidFieldType);
                continue;
            }
            match (container, field.as_str(), &value) {
                ("devices" | "requests", "kind", Plain::Uint(n)) => {
                    if *n > 1 {
                        errors.insert(D::InvalidEnumValue);
                    }
                }
                ("devices" | "requests", "kind", _) => {
                    errors.insert(D::InvalidFieldType);
                }
                ("devices", "revoked", _) | ("roster", "archived", _)
                    if !matches!(value, Plain::Bool(_)) =>
                {
                    errors.insert(D::InvalidFieldType);
                }
                ("devices", "added_at", _) | ("requests", "requested_at", _) => {
                    if let Plain::Str(s) = &value {
                        if !values::is_utc_timestamp(s) {
                            errors.insert(D::InvalidTimestamp);
                        }
                    } else {
                        errors.insert(D::InvalidFieldType);
                    }
                }
                ("requests", "pairing", Plain::Str(s)) => {
                    if parse_principal_ref(s).is_err() {
                        errors.insert(D::InvalidPrincipalRef);
                    }
                }
                ("requests", "descriptor", Plain::Str(s)) => {
                    let descriptor = from_b64url(s)
                        .ok()
                        .and_then(|b| PrincipalDescriptor::decode(&b).ok());
                    if !descriptor.is_some_and(|d| principal_ref(d.id()) == key) {
                        errors.insert(D::InvalidDescriptor);
                    }
                }
                ("requests", "scope", Plain::List(items)) => {
                    if items.is_empty()
                        || items.len() > 64
                        || (0..items.len()).any(|i| items[..i].contains(&items[i]))
                    {
                        errors.insert(D::InvalidFieldType);
                    }
                    for item in items {
                        match item {
                            Plain::Str(s) => {
                                if parse_resource_ref(s).is_err() {
                                    errors.insert(D::InvalidResourceRef);
                                }
                            }
                            _ => {
                                errors.insert(D::InvalidFieldType);
                            }
                        }
                    }
                }
                ("requests", "scope", _) => {
                    errors.insert(D::InvalidFieldType);
                }
                ("roster", "endpoints", Plain::List(items)) => {
                    if items.iter().any(|p| !matches!(p, Plain::Str(_))) {
                        errors.insert(D::InvalidFieldType);
                    }
                }
                ("roster", "endpoints", _) => {
                    errors.insert(D::InvalidFieldType);
                }
                _ => {}
            }
        }
    }
    // Lists have registers too: validate hidden concurrent element values,
    // not just the Automerge-selected rendering of a list.
    let list_field = match container {
        "roster" => Some("endpoints"),
        "requests" => Some("scope"),
        _ => None,
    };
    if let Some(field) = list_field {
        for (value, list) in doc.get_all(obj, field).unwrap_or_default() {
            if value != Value::Object(ObjType::List) {
                continue;
            }
            for index in 0..doc.length(&list) {
                for value in vals(doc, &list, index) {
                    match value {
                        Plain::Str(s) => {
                            if field == "scope" && parse_resource_ref(&s).is_err() {
                                errors.insert(D::InvalidResourceRef);
                            }
                        }
                        _ => {
                            errors.insert(D::InvalidFieldType);
                        }
                    }
                }
            }
        }
    }
    if container == "devices" {
        collect_hints(doc, obj, &mut BTreeMap::new(), errors);
    }
    // A kind conflict invalidates devices too. Only use the generic conflict
    // diagnostic when all values were valid in their own right (§4 rule 2).
    if errors.is_empty()
        && ((container == "requests" && conflict_under(doc, obj, 0))
            || (container == "devices" && kinds.len() > 1))
    {
        errors.insert(D::InvalidFieldType);
    }
}
fn collect_hints(
    doc: &AutoCommit,
    entry: &ObjId,
    out: &mut BTreeMap<String, BTreeSet<u64>>,
    errors: &mut BTreeSet<D>,
) {
    for (v, id) in doc.get_all(entry, "missing_keys").unwrap_or_default() {
        if v != Value::Object(ObjType::Map) {
            errors.insert(D::InvalidFieldType);
            continue;
        }
        for key in doc.keys(&id) {
            if parse_resource_ref(&key).is_err() {
                errors.insert(D::InvalidResourceRef);
            }
            for (v, list) in doc.get_all(&id, &key).unwrap_or_default() {
                if v != Value::Object(ObjType::List) {
                    errors.insert(D::InvalidFieldType);
                    continue;
                }
                for i in 0..doc.length(&list) {
                    for value in vals(doc, &list, i) {
                        if let Plain::Uint(n) = value {
                            out.entry(key.clone()).or_default().insert(n);
                        } else {
                            errors.insert(D::InvalidFieldType);
                        }
                    }
                }
            }
        }
    }
}
