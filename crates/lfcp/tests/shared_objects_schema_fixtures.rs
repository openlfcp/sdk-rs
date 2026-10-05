//! The SHARED-OBJECTS-PROFILE-01 state fixtures
//! (`profiles/shared-objects-01/schema/fixtures`) against this crate's
//! profile validation: every valid fixture validates, and every invalid one
//! reports exactly the pointers `expected.json` lists, each with the §74.1
//! diagnostic it names (SOG-1, SOG-2 included).

#![cfg(feature = "shared-objects")]

mod support;

use std::collections::BTreeMap;

use automerge::transaction::Transactable;
use automerge::{AutoCommit, ObjId, ObjType, ReadDoc, ScalarValue, ROOT};
use lfcp::shared_objects::validate::{object_problems, object_status, root_problems, ObjectStatus};
use lfcp::shared_objects::Diagnostic;
use serde_json::Value as Json;
use support::spec::Spec;

const DIR: &str = "profiles/shared-objects-01/schema/fixtures";

/// Write JSON as profile data: strings are scalar strings, integers
/// Automerge `int` values, objects maps (the corpus convention). Keys
/// starting with `$` are fixture metadata.
fn write(doc: &mut AutoCommit, obj: &ObjId, key: &str, value: &Json) {
    match value {
        Json::Null => doc.put(obj, key, ScalarValue::Null).unwrap(),
        Json::Bool(b) => doc.put(obj, key, *b).unwrap(),
        Json::Number(n) => doc
            .put(obj, key, ScalarValue::Int(n.as_i64().expect("integer")))
            .unwrap(),
        Json::String(s) => doc.put(obj, key, s.as_str()).unwrap(),
        Json::Array(items) => {
            let list = doc.put_object(obj, key, ObjType::List).unwrap();
            for (i, item) in items.iter().enumerate() {
                match item {
                    Json::String(s) => doc.insert(&list, i, s.as_str()).unwrap(),
                    other => panic!("list item {other}"),
                }
            }
        }
        Json::Object(map) => {
            let child = doc.put_object(obj, key, ObjType::Map).unwrap();
            for (k, v) in map {
                write(doc, &child, k, v);
            }
        }
    }
}

fn load(state: &Json) -> AutoCommit {
    let mut doc = AutoCommit::new();
    for (key, value) in state.as_object().unwrap() {
        if !key.starts_with('$') {
            write(&mut doc, &ROOT, key, value);
        }
    }
    doc.commit();
    doc
}

fn diagnostic(name: &str) -> Diagnostic {
    use Diagnostic::*;
    [
        InvalidRoot,
        InvalidObjectId,
        ObjectIdMismatch,
        MissingRequiredField,
        InvalidFieldType,
        InvalidEnumValue,
        InvalidExtensionNamespace,
        InvalidPrincipalRef,
        InvalidTimestamp,
        InvalidLocalDate,
        InvalidCollectionRepresentation,
        InvalidTag,
        ImmutableFieldMutated,
        ChangeActorMismatch,
    ]
    .into_iter()
    .find(|d| d.name() == name)
    .unwrap_or_else(|| panic!("unknown diagnostic {name}"))
}

/// Every problem of the document, root and objects, as (pointer,
/// diagnostic), and every object's status.
fn validate(doc: &AutoCommit) -> (BTreeMap<String, Diagnostic>, BTreeMap<String, ObjectStatus>) {
    let mut problems: BTreeMap<String, Diagnostic> = root_problems(doc)
        .unwrap()
        .into_iter()
        .map(|p| (p.pointer, p.diagnostic))
        .collect();
    let mut objects = BTreeMap::new();
    if let Some((automerge::Value::Object(ObjType::Map), obj)) = doc.get(ROOT, "objects").unwrap() {
        for key in doc.keys(&obj) {
            for p in object_problems(doc, &obj, &key).unwrap() {
                problems.insert(p.pointer, p.diagnostic);
            }
            objects.insert(key.clone(), object_status(doc, &obj, &key).unwrap());
        }
    }
    (problems, objects)
}

#[test]
fn every_state_fixture_reports_exactly_its_pointers() {
    // §74.1 (SOG-2): one diagnostic per invalid value; the set of
    // pointers equals expected.json's, each with the named diagnostic.
    let spec = Spec::open();
    let expected = spec.read_json(&format!("{DIR}/expected.json"));
    let cases = expected["cases"].as_object().unwrap();
    let mut checked = 0;
    for name in spec.list(DIR) {
        if name == "expected.json" {
            continue;
        }
        let state = spec.read_json(&format!("{DIR}/{name}"));
        let (problems, objects) = validate(&load(&state));
        if name.starts_with("valid-") {
            assert!(!cases.contains_key(&name), "{name}");
            assert_eq!(problems, BTreeMap::new(), "{name}");
            for (key, status) in &objects {
                assert_eq!(*status, ObjectStatus::Ready, "{name}: {key}");
            }
        } else {
            assert!(name.starts_with("invalid-"), "{name}");
            let case = &cases[&name];
            let wanted = diagnostic(case["diagnostic"].as_str().unwrap());
            let pointers: BTreeMap<String, Diagnostic> = case["pointers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| (p.as_str().unwrap().to_owned(), wanted))
                .collect();
            assert_eq!(problems, pointers, "{name}");
            // The object-level convenience agrees.
            for (key, status) in &objects {
                let prefix = format!("/objects/{key}");
                let own = pointers
                    .keys()
                    .any(|p| p == &prefix || p.starts_with(&format!("{prefix}/")));
                let want = if own {
                    ObjectStatus::Invalid(wanted)
                } else {
                    ObjectStatus::Ready
                };
                assert_eq!(*status, want, "{name}: {key}");
            }
        }
        checked += 1;
    }
    assert_eq!(checked, cases.len() + 10, "every fixture");
}

#[test]
fn the_baseline_4_fixtures_are_present() {
    // SOG-1 and SOG-2 (ADR 0003).
    let names = Spec::open().list(DIR);
    for fixture in [
        "invalid-unknown-type-created-at-hour-25.json",
        "invalid-date-not-string.json",
        "invalid-status-not-string.json",
        "invalid-object-extensions-not-map.json",
        "invalid-objects-entry-not-map.json",
    ] {
        assert!(names.iter().any(|n| n == fixture), "{fixture}");
    }
}

#[test]
fn several_failures_report_one_diagnostic_per_field() {
    // §74.1 (SOG-2): one diagnostic per invalid value; the object-level
    // status is the first in table order.
    let spec = Spec::open();
    let mut state = spec.read_json(&format!("{DIR}/valid-typical-task.json"));
    let objects = state["objects"].as_object_mut().unwrap();
    let key = objects.keys().next().unwrap().clone();
    let task = objects.get_mut(&key).unwrap();
    task["tags"] = serde_json::json!({ "#bad": true, "ok": false }); // INVALID_TAG, INVALID_COLLECTION_REPRESENTATION
    task["status"] = serde_json::json!(7); // INVALID_ENUM_VALUE
    task["created_by"] = serde_json::json!("p:short"); // INVALID_PRINCIPAL_REF
    let (problems, statuses) = validate(&load(&state));
    let at = |field: &str| format!("/objects/{key}/{field}");
    let expected: BTreeMap<String, Diagnostic> = [
        (at("tags/#bad"), Diagnostic::InvalidTag),
        (at("tags/ok"), Diagnostic::InvalidCollectionRepresentation),
        (at("status"), Diagnostic::InvalidEnumValue),
        (at("created_by"), Diagnostic::InvalidPrincipalRef),
    ]
    .into_iter()
    .collect();
    assert_eq!(problems, expected);
    assert_eq!(
        statuses[&key],
        ObjectStatus::Invalid(Diagnostic::InvalidEnumValue)
    );
}

#[test]
fn a_value_that_breaks_several_rules_gets_the_earliest() {
    // A tag both badly named and not `true`: INVALID_COLLECTION_REPRESENTATION
    // comes before INVALID_TAG in the table.
    let spec = Spec::open();
    let mut state = spec.read_json(&format!("{DIR}/valid-typical-task.json"));
    let objects = state["objects"].as_object_mut().unwrap();
    let key = objects.keys().next().unwrap().clone();
    objects.get_mut(&key).unwrap()["tags"] = serde_json::json!({ "#x": 1 });
    let (problems, _) = validate(&load(&state));
    assert_eq!(
        problems.into_iter().collect::<Vec<_>>(),
        vec![(
            format!("/objects/{key}/tags/#x"),
            Diagnostic::InvalidCollectionRepresentation
        )]
    );
}
