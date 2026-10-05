//! The SHARED-OBJECTS-PROFILE-01 state fixtures
//! (`profiles/shared-objects-01/schema/fixtures`) against this crate's
//! profile validation: every valid fixture validates, and every invalid one
//! fails exactly where `expected.json` points, with its §74.1 diagnostic
//! (SOG-1, SOG-2 included). `expected.json` asserts pointers; this test
//! also asserts the diagnostic it names.

#![cfg(feature = "shared-objects")]

mod support;

use std::collections::BTreeMap;

use automerge::transaction::Transactable;
use automerge::{AutoCommit, ObjId, ObjType, ReadDoc, ScalarValue, ROOT};
use lfcp::shared_objects::validate::{object_status, validate_root, ObjectStatus};
use lfcp::shared_objects::{Diagnostic, ProfileError};
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

/// The root result and every object's status.
fn validate(doc: &AutoCommit) -> (Result<(), ProfileError>, BTreeMap<String, ObjectStatus>) {
    let root = validate_root(doc);
    let mut objects = BTreeMap::new();
    if let Some((_, obj)) = doc.get(ROOT, "objects").unwrap() {
        for key in doc.keys(&obj) {
            objects.insert(key.clone(), object_status(doc, &obj, &key).unwrap());
        }
    }
    (root, objects)
}

#[test]
fn every_state_fixture_validates_as_expected() {
    let spec = Spec::open();
    let expected = spec.read_json(&format!("{DIR}/expected.json"));
    let cases = expected["cases"].as_object().unwrap();
    let mut checked = 0;
    for name in spec.list(DIR) {
        if name == "expected.json" {
            continue;
        }
        let state = spec.read_json(&format!("{DIR}/{name}"));
        let (root, objects) = validate(&load(&state));
        if name.starts_with("valid-") {
            assert!(!cases.contains_key(&name), "{name}");
            assert_eq!(root, Ok(()), "{name}: root");
            for (key, status) in &objects {
                assert_eq!(*status, ObjectStatus::Ready, "{name}: {key}");
            }
        } else {
            assert!(name.starts_with("invalid-"), "{name}");
            let case = &cases[&name];
            let wanted = diagnostic(case["diagnostic"].as_str().unwrap());
            // The objects and the root the pointers name.
            let mut bad_objects = Vec::new();
            let mut bad_root = false;
            for pointer in case["pointers"].as_array().unwrap() {
                let parts: Vec<&str> = pointer.as_str().unwrap().split('/').collect();
                if parts[1] == "objects" {
                    bad_objects.push(parts[2].to_owned());
                } else {
                    bad_root = true;
                }
            }
            if bad_root {
                assert_eq!(root, Err(wanted.into()), "{name}: root");
            } else {
                assert_eq!(root, Ok(()), "{name}: root");
            }
            for (key, status) in &objects {
                if bad_objects.contains(key) {
                    assert_eq!(*status, ObjectStatus::Invalid(wanted), "{name}: {key}");
                } else {
                    assert_eq!(*status, ObjectStatus::Ready, "{name}: {key}");
                }
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
fn several_failures_report_the_first_in_table_order() {
    // §74.1 (SOG-2): structure and values first, immutability last.
    let spec = Spec::open();
    let mut state = spec.read_json(&format!("{DIR}/valid-typical-task.json"));
    let objects = state["objects"].as_object_mut().unwrap();
    let key = objects.keys().next().unwrap().clone();
    let task = objects.get_mut(&key).unwrap();
    task["tags"] = serde_json::json!({ "#bad": true }); // INVALID_TAG
    task["status"] = serde_json::json!(7); // INVALID_ENUM_VALUE
    task["created_by"] = serde_json::json!("p:short"); // INVALID_PRINCIPAL_REF
    let (_, statuses) = validate(&load(&state));
    assert_eq!(
        statuses[&key],
        ObjectStatus::Invalid(Diagnostic::InvalidEnumValue)
    );
    assert!(Diagnostic::InvalidObjectId < Diagnostic::ImmutableFieldMutated);
}
