//! SHARED-OBJECTS-TEST-VECTORS-01 and the Automerge reference corpus
//! against `lfcp::shared_objects`.
//!
//! - D01–D08: exact (actor IDs, Principal references, framing, Object IDs);
//! - I01–I07: the expected `PROFILE_INVALID` diagnostic after the mutation;
//! - S01–S14: each scenario's branches are run through this crate's
//!   intents, merged, and compared with the expected logical state and
//!   conflict sets, and with the corpus' converged state;
//! - the corpus: every change applies and every save image loads, giving
//!   the corpus' logical state and conflicts.
//!
//! The vectors and the corpus are read at the `spec.lock` pin
//! (mvp-0.1-baseline.4).

mod support;

use std::collections::BTreeMap;

use automerge::Change;
use lfcp::base::{self, ObjectId, PrincipalId, ResourceId};
use lfcp::shared_objects::document::{NewTask, SharedObjects};
use lfcp::shared_objects::framing;
use lfcp::shared_objects::identity::{
    actor_id, actor_id_bytes, parse_principal_ref, principal_ref,
};
use lfcp::shared_objects::validate::ObjectStatus;
use lfcp::shared_objects::values::Plain;
use lfcp::shared_objects::{Diagnostic, ProfileError};
use serde_json::Value as Json;
use support::spec::Spec;
use support::vectors::{hex, id_of};

const SUITE: &str = "test-vectors/shared-objects-01/SHARED-OBJECTS-TEST-VECTORS-01.json";
const CORPUS: &str = "test-vectors/shared-objects-01/SHARED-OBJECTS-AUTOMERGE-REFERENCE-01.json";

fn suite() -> Json {
    Spec::open().read_json(SUITE)
}

fn corpus() -> Json {
    Spec::open().read_json(CORPUS)
}

fn case<'a>(suite: &'a Json, id: &str) -> &'a Json {
    suite["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id)
        .unwrap_or_else(|| panic!("case {id} is missing"))
}

/// JSON as profile data: strings are scalar strings, integers Automerge
/// `int` values (the corpus convention).
fn plain(json: &Json) -> Plain {
    match json {
        Json::Null => Plain::Null,
        Json::Bool(b) => Plain::Bool(*b),
        Json::Number(n) => n
            .as_i64()
            .map(Plain::Int)
            .unwrap_or_else(|| Plain::F64(n.as_f64().unwrap())),
        Json::String(s) => Plain::str(s),
        Json::Array(items) => Plain::List(items.iter().map(plain).collect()),
        Json::Object(map) => Plain::map(map.iter().map(|(k, v)| (k.clone(), plain(v)))),
    }
}

fn text(p: &Plain) -> String {
    p.as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| panic!("not a scalar string: {p:?}"))
}

/// The fixture Principals by name: (Principal ID, resource-A actor).
struct Fixtures {
    resource: ResourceId,
    principals: BTreeMap<String, (PrincipalId, [u8; 32])>,
}

impl Fixtures {
    fn load(suite: &Json) -> Fixtures {
        let f = &suite["fixtures"];
        let resource = ResourceId::from_hex(f["resource_a_hex"].as_str().unwrap()).unwrap();
        let principals = f["principals"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(name, p)| {
                let id = PrincipalId::from_hex(p["id_hex"].as_str().unwrap()).unwrap();
                let actor: [u8; 32] =
                    base::fixed(&base::from_hex(p["actor_a_hex"].as_str().unwrap()).unwrap())
                        .unwrap();
                // §8: the fixture actor is the derived one.
                assert_eq!(
                    actor_id_bytes(&resource, &id),
                    actor,
                    "fixtures: actor of {name}"
                );
                assert_eq!(
                    p["ref"].as_str().unwrap(),
                    principal_ref(&id),
                    "fixtures: ref of {name}"
                );
                (name.clone(), (id, actor))
            })
            .collect();
        Fixtures {
            resource,
            principals,
        }
    }

    fn doc(&self, name: &str) -> SharedObjects {
        let (id, _) = self.principals[name];
        SharedObjects::new(actor_id(&self.resource, &id))
    }

    fn actor(&self, name: &str) -> automerge::ActorId {
        actor_id(&self.resource, &self.principals[name].0)
    }
}

#[test]
fn deterministic_vectors_match_exactly() {
    let suite = suite();
    let mut checked = 0;
    for c in suite["cases"].as_array().unwrap() {
        let id = id_of(c);
        let inputs = &c["inputs"];
        let expected = &c["expected"];
        match c["kind"].as_str().unwrap() {
            "actor_id" => {
                let resource = ResourceId::from_slice(&hex(id, &inputs["resource_hex"])).unwrap();
                let principal =
                    PrincipalId::from_slice(&hex(id, &inputs["principal_hex"])).unwrap();
                assert_eq!(
                    actor_id_bytes(&resource, &principal).as_slice(),
                    hex(id, &expected["actor_id"]),
                    "{id}"
                );
            }
            "principal_ref" => {
                let principal = PrincipalId::from_slice(&hex(id, &inputs["principal_id"])).unwrap();
                let reference = expected["principal_ref"].as_str().unwrap();
                assert_eq!(principal_ref(&principal), reference, "{id}");
                assert_eq!(parse_principal_ref(reference), Ok(principal), "{id}: parse");
            }
            "profile_change_framing" | "profile_snapshot_framing" => {
                let payload = hex(
                    id,
                    inputs
                        .get("automerge_change_hex")
                        .unwrap_or(&inputs["automerge_save_hex"]),
                );
                let framed = if c["kind"] == "profile_change_framing" {
                    framing::encode_change(&payload)
                } else {
                    framing::encode_snapshot(&payload)
                };
                assert_eq!(
                    framed,
                    hex(id, &expected["framed_cbor"]),
                    "{id}: framed_cbor"
                );
                assert_eq!(
                    lfcp::crypto::sha256(&framed).as_bytes().as_slice(),
                    hex(id, &expected["sha256"]),
                    "{id}: sha256"
                );
                // The payload is synthetic, not Automerge (vector note), so
                // only the frame is checked on the way back.
                assert_eq!(
                    framing::snapshot_payload(&framed),
                    Ok(payload),
                    "{id}: unframe"
                );
            }
            "object_id_validation" => {
                let result = ObjectId::parse(inputs["object_id"].as_str().unwrap());
                if expected["valid"] == true {
                    assert!(result.is_ok(), "{id}");
                } else {
                    // §19, §74.1: INVALID_OBJECT_ID.
                    assert!(result.is_err(), "{id}");
                    assert_eq!(expected["error"]["code"], "PROFILE_INVALID", "{id}");
                    assert_eq!(
                        expected["error"]["diagnostic"],
                        Diagnostic::InvalidObjectId.name(),
                        "{id}"
                    );
                }
            }
            _ => continue,
        }
        checked += 1;
    }
    assert_eq!(checked, 8, "D01-D08");
}

/// S01's Task, created through this crate's intent by ANDREY.
fn s01_document(suite: &Json, f: &Fixtures) -> (SharedObjects, String) {
    let args = &case(suite, "S01")["inputs"]["branches"][0]["args"];
    let mut doc = f.doc("andrey");
    doc.initialize().unwrap();
    let key = args["id"].as_str().unwrap().to_owned();
    doc.create_task(&new_task(args)).unwrap();
    assert_eq!(doc.object(&key).unwrap(), plain(args), "S01: created Task");
    (doc, key)
}

/// The `NewTask` of a `task.create` argument object.
fn new_task(args: &Json) -> NewTask {
    let s = |k: &str| args[k].as_str().map(str::to_owned);
    let mut task = NewTask::new(
        ObjectId::parse(args["id"].as_str().unwrap()).unwrap(),
        parse_principal_ref(args["created_by"].as_str().unwrap()).unwrap(),
        args["title"].as_str().unwrap(),
    );
    task.created_at = s("created_at");
    task.status = s("status");
    task.priority = s("priority");
    task.due = s("due");
    task.scheduled = s("scheduled");
    task.tags = args["tags"]
        .as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    task.assignees = args["assignees"]
        .as_object()
        .map(|m| m.keys().map(|r| parse_principal_ref(r).unwrap()).collect())
        .unwrap_or_default();
    task
}

#[test]
fn invalid_states_report_their_diagnostic() {
    let suite = suite();
    let f = Fixtures::load(&suite);
    let mut checked = 0;
    for c in suite["cases"].as_array().unwrap() {
        if c["kind"] != "profile_validation" {
            continue;
        }
        let id = id_of(c);
        let mutation = &c["inputs"]["mutation"];
        let key = mutation["object_key"].as_str().unwrap();
        let (doc, task_key) = s01_document(&suite, &f);
        // A remote peer (PAVEL) makes the mutation.
        let mut doc = {
            let mut d = doc;
            d.fork(f.actor("pavel"))
        };
        match mutation.get("field") {
            Some(field) => {
                assert_eq!(key, task_key, "{id}: mutates S01's Task");
                doc.write_field(
                    "mutation",
                    key,
                    field.as_str().unwrap(),
                    &plain(&mutation["value"]),
                )
                .unwrap_or_else(|err| panic!("{id}: {err}"));
            }
            None => {
                doc.insert_object("mutation", key, &plain(&mutation["value"]))
                    .unwrap_or_else(|err| panic!("{id}: {err}"));
            }
        }
        let expected = &c["expected"]["error"];
        assert_eq!(expected["code"], "PROFILE_INVALID", "{id}");
        let status = doc.object_status(key).unwrap();
        assert_eq!(
            status.clone(),
            ObjectStatus::Invalid(diagnostic(expected["diagnostic"].as_str().unwrap())),
            "{id}"
        );
        // §77: the Resource stays usable and S01's Task, when untouched,
        // stays ready.
        assert_eq!(doc.validate_root(), Ok(()), "{id}: root");
        if key != task_key {
            assert_eq!(
                doc.object_status(&task_key).unwrap(),
                ObjectStatus::Ready,
                "{id}: other object"
            );
        }
        checked += 1;
    }
    assert_eq!(checked, 7, "I01-I07");
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
    ]
    .into_iter()
    .find(|d| d.name() == name)
    .unwrap_or_else(|| panic!("unknown diagnostic {name}"))
}

/// A scenario run through this crate: the converged document and, for
/// S14, the Snapshot image.
struct Run {
    doc: SharedObjects,
    snapshot: Option<Vec<u8>>,
}

/// The objects a `base_state` holds.
fn base_objects(base: &Json) -> BTreeMap<String, Json> {
    if base.get("type").is_some() {
        BTreeMap::from([(base["id"].as_str().unwrap().to_owned(), base.clone())])
    } else if let Some(task) = base.get("task") {
        BTreeMap::from([(task["id"].as_str().unwrap().to_owned(), task.clone())])
    } else if let Some(objects) = base.get("objects") {
        objects
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    } else {
        BTreeMap::new()
    }
}

/// One branch through this crate's intents (§59–§69).
fn apply_branch(doc: &mut SharedObjects, branch: &Json, task: &str, label: &str) {
    let intent = branch["intent"].as_str().unwrap_or("");
    let writes = &branch["writes"];
    let w = |field: &str| {
        writes[field]
            .as_str()
            .unwrap_or_else(|| panic!("{label}: no write of {field}"))
    };
    let result = match (intent, branch["operation"].as_str()) {
        (_, Some("create")) => {
            let object = &branch["object"];
            doc.create_task(&new_task(object)).map(|_| ())
        }
        ("task.create", _) => doc.create_task(&new_task(&branch["args"])).map(|_| ()),
        ("task.complete", _) => doc
            .complete(task, writes["completion_date"].as_str())
            .map(|_| ()),
        ("task.cancel", _) => doc.cancel(task).map(|_| ()),
        ("task.set_title", _) => doc.set_title(task, w("title")).map(|_| ()),
        ("task.set_status", _) => doc.set_status(task, w("status")).map(|_| ()),
        ("task.set_due", _) => doc.set_date(task, "due", w("due")).map(|_| ()),
        ("task.delete", _) => doc.delete(task).map(|_| ()),
        ("task.restore", _) => doc.restore(task).map(|_| ()),
        // §69: the field is the one the branch writes.
        ("task.resolve_field_conflict", _) => {
            let fields = writes.as_object().unwrap();
            assert_eq!(fields.len(), 1, "{label}: one field");
            let field = fields.keys().next().unwrap();
            doc.resolve_field_conflict(task, field, w(field))
                .map(|_| ())
        }
        ("task.add_tag", _) => doc
            .add_tag(task, branch["tag"].as_str().unwrap())
            .map(|_| ()),
        ("task.remove_tag", _) => doc
            .remove_tag(task, branch["tag"].as_str().unwrap())
            .map(|_| ()),
        // §68.
        ("task.add_assignee", _) => {
            let p = parse_principal_ref(branch["principal"].as_str().unwrap()).unwrap();
            doc.add_assignee(task, &p).map(|_| ())
        }
        ("task.remove_assignee", _) => {
            let p = parse_principal_ref(branch["principal"].as_str().unwrap()).unwrap();
            doc.remove_assignee(task, &p).map(|_| ())
        }
        other => panic!("{label}: unsupported branch {other:?}"),
    };
    result.unwrap_or_else(|err| panic!("{label}: {err}"));
    // The intent wrote exactly the vector's writes.
    if let Some(writes) = writes.as_object() {
        for (field, value) in writes {
            assert!(
                doc.values(task, field).unwrap().contains(&plain(value)),
                "{label}: {field} written"
            );
        }
    }
}

fn run(suite: &Json, f: &Fixtures, id: &str) -> Run {
    let scenario = case(suite, id);
    let base = &scenario["inputs"]["base_state"];
    let task = suite["fixtures"]["objects"]["task_1"].as_str().unwrap();
    let mut snapshot = None;
    let mut doc = if let Some(source) = base["derived_from"].as_str() {
        run(suite, f, source.split_whitespace().next().unwrap()).doc
    } else if base.get("build").is_some() {
        // S14: "Apply S01 then S06": S06's branches on S01's state.
        let mut doc = run(suite, f, "S01").doc;
        let mut forks: Vec<SharedObjects> = case(suite, "S06")["inputs"]["branches"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| {
                let mut fork = doc.fork(f.actor(b["actor"].as_str().unwrap()));
                apply_branch(&mut fork, b, task, "S14/S06");
                fork
            })
            .collect();
        doc = forks.remove(0);
        for mut other in forks {
            doc.merge(&mut other).unwrap();
        }
        doc
    } else {
        let mut doc = f.doc("andrey");
        doc.initialize().unwrap();
        for (key, object) in base_objects(base) {
            doc.insert_object("base", &key, &plain(&object)).unwrap();
        }
        doc
    };

    let mut forks = Vec::new();
    for (i, branch) in scenario["inputs"]["branches"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        let label = format!("{id}.{}", i + 1);
        match branch["operation"].as_str() {
            Some("load-save-roundtrip-without-understanding-type") => {
                doc = SharedObjects::load(&doc.save(), f.actor(branch["actor"].as_str().unwrap()))
                    .unwrap();
                continue;
            }
            Some("snapshot_save_load_roundtrip") => {
                let image = doc.save();
                doc = SharedObjects::load(&image, f.actor("andrey")).unwrap();
                snapshot = Some(image);
                continue;
            }
            _ => {}
        }
        let mut fork = doc.fork(f.actor(branch["actor"].as_str().unwrap()));
        apply_branch(&mut fork, branch, task, &label);
        if branch["from"] == "base" {
            forks.push(fork);
        } else {
            doc = fork;
        }
    }
    if !forks.is_empty() {
        doc = forks.remove(0);
        for mut other in forks {
            doc.merge(&mut other).unwrap();
        }
    }
    Run { doc, snapshot }
}

/// Scalar conflicts: object key → field → sorted concurrent values.
type Conflicts = BTreeMap<String, BTreeMap<String, Vec<String>>>;

/// The corpus' conflicts of one scenario, in this crate's form.
fn corpus_conflicts(entry: &Json) -> Conflicts {
    entry["conflicts"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(object, fields)| {
            let fields = fields
                .as_object()
                .unwrap()
                .iter()
                .filter(|(field, _)| !field.is_empty())
                .map(|(field, values)| {
                    let values = values
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_str().unwrap().to_owned())
                        .collect();
                    (field.clone(), values)
                })
                .collect();
            (object.clone(), fields)
        })
        .collect()
}

/// This document's scalar conflicts, values sorted, collisions apart.
fn conflicts_of(doc: &SharedObjects) -> (Conflicts, Vec<String>) {
    let mut conflicts = BTreeMap::new();
    let mut collisions = Vec::new();
    for key in doc.object_keys().unwrap() {
        if doc.object_status(&key).unwrap() == ObjectStatus::Collision {
            collisions.push(key.clone());
            conflicts.insert(key, BTreeMap::new());
            continue;
        }
        let fields: BTreeMap<String, Vec<String>> = doc
            .conflicts(&key)
            .unwrap()
            .into_iter()
            .map(|(field, values)| {
                let mut values: Vec<String> = values.iter().map(text).collect();
                values.sort();
                (field, values)
            })
            .collect();
        if !fields.is_empty() {
            conflicts.insert(key, fields);
        }
    }
    (conflicts, collisions)
}

/// The sorted concurrent values of a field, as strings.
fn values(doc: &SharedObjects, key: &str, field: &str) -> Vec<String> {
    let mut out: Vec<String> = doc.values(key, field).unwrap().iter().map(text).collect();
    out.sort();
    out
}

/// A value at a dotted path such as `extensions.com.example.tracker.ticket`:
/// the longest key that matches is taken at each level.
fn at_path<'a>(mut value: &'a Plain, path: &str) -> Option<&'a Plain> {
    let mut rest = path;
    while !rest.is_empty() {
        let map = value.as_map()?;
        let (key, tail) = map
            .keys()
            .filter(|k| rest == k.as_str() || rest.starts_with(&format!("{k}.")))
            .max_by_key(|k| k.len())
            .map(|k| (k.clone(), rest[k.len()..].trim_start_matches('.')))?;
        value = &map[&key];
        rest = tail;
    }
    Some(value)
}

#[test]
fn behavioral_scenarios_converge_to_the_expected_state() {
    let suite = suite();
    let corpus = corpus();
    let f = Fixtures::load(&suite);
    let task = suite["fixtures"]["objects"]["task_1"].as_str().unwrap();
    let mut checked = 0;
    for scenario in suite["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["type"] == "behavioral")
    {
        let id = id_of(scenario);
        let Run { mut doc, snapshot } = run(&suite, &f, id);
        let expected = &scenario["expected"];
        assert_eq!(doc.validate_root(), Ok(()), "{id}: root");

        for (name, want) in expected.as_object().unwrap() {
            match name.as_str() {
                "objects" => {
                    for (key, object) in want.as_object().unwrap() {
                        assert_eq!(
                            doc.object(key).unwrap(),
                            plain(object),
                            "{id}: object {key}"
                        );
                        assert_eq!(
                            doc.object_status(key).unwrap(),
                            ObjectStatus::Ready,
                            "{id}: {key} ready"
                        );
                    }
                }
                "conflicts" => {
                    let wanted: BTreeMap<String, Json> =
                        want.as_object().unwrap().clone().into_iter().collect();
                    assert!(wanted.is_empty(), "{id}: only empty conflicts are stated");
                    assert!(conflicts_of(&doc).0.is_empty(), "{id}: no conflicts");
                }
                "tags" | "assignees" => {
                    let mut members: Vec<String> = doc.object(task).unwrap().as_map().unwrap()
                        [name.as_str()]
                    .as_map()
                    .unwrap()
                    .keys()
                    .cloned()
                    .collect();
                    members.sort();
                    let mut wanted: Vec<String> = want
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_str().unwrap().to_owned())
                        .collect();
                    wanted.sort();
                    assert_eq!(members, wanted, "{id}: {name}");
                }
                "must_report_conflict" => {
                    let conflicted = !doc.conflicts(task).unwrap().is_empty();
                    assert_eq!(conflicted, want == true, "{id}: conflict reported");
                }
                "completion_date_values_may_include" => {
                    for v in want.as_array().unwrap() {
                        assert!(
                            values(&doc, task, "completion_date")
                                .contains(&v.as_str().unwrap().to_owned()),
                            "{id}: completion_date"
                        );
                    }
                }
                "object_present" => {
                    assert_eq!(
                        doc.object_keys().unwrap().contains(&task.to_owned()),
                        want == true,
                        "{id}"
                    );
                }
                "preserve" => {
                    let object = doc.object(task).unwrap();
                    for (path, value) in want.as_object().unwrap() {
                        assert_eq!(
                            at_path(&object, path),
                            Some(&plain(value)),
                            "{id}: preserves {path}"
                        );
                    }
                }
                "profile_error" => {
                    assert_eq!(want, "OBJECT_ID_COLLISION", "{id}");
                    assert_eq!(
                        doc.object_status(task).unwrap(),
                        ObjectStatus::Collision,
                        "{id}"
                    );
                    assert_eq!(
                        ProfileError::ObjectIdCollision.code(),
                        Some("OBJECT_ID_COLLISION")
                    );
                }
                "must_not_silently_treat_as_same_object" => {
                    // Intents refuse the object rather than pick one (§21).
                    let mut doc = SharedObjects::load(&doc.save(), f.actor("masha")).unwrap();
                    assert_eq!(
                        doc.set_title(task, "x").unwrap_err(),
                        ProfileError::ObjectIdCollision,
                        "{id}"
                    );
                }
                "task_status" => assert_eq!(
                    values(&doc, task, "status"),
                    vec![want.as_str().unwrap()],
                    "{id}"
                ),
                "snapshot_roundtrip_preserves_objects" => {
                    let image = snapshot.as_ref().expect("S14: snapshot");
                    let loaded = SharedObjects::load(image, f.actor("masha")).unwrap();
                    assert_eq!(
                        loaded.object_keys().unwrap(),
                        vec![task.to_owned()],
                        "{id}: snapshot objects"
                    );
                }
                field if field.ends_with("_conflict_set") => {
                    let field = field.trim_end_matches("_conflict_set");
                    let mut wanted: Vec<String> = want
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_str().unwrap().to_owned())
                        .collect();
                    wanted.sort();
                    assert_eq!(values(&doc, task, field), wanted, "{id}: {field} values");
                }
                field => {
                    // A visible scalar value: title, status, lifecycle, …
                    assert_eq!(
                        values(&doc, task, field),
                        vec![want.as_str().unwrap()],
                        "{id}: {field}"
                    );
                }
            }
        }

        // The same scenario in the JS reference corpus converges to the
        // same logical state and conflicts.
        let entry = corpus["scenarios"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["id"] == id)
            .unwrap();
        assert_eq!(
            doc.plain().unwrap(),
            plain(&entry["state"]),
            "{id}: state equals the corpus'"
        );
        assert_eq!(
            conflicts_of(&doc).0,
            corpus_conflicts(entry),
            "{id}: conflicts equal the corpus'"
        );
        checked += 1;
    }
    assert_eq!(checked, 14, "S01-S14");
}

#[test]
fn every_corpus_change_applies_and_every_save_loads() {
    let corpus = corpus();
    assert_eq!(corpus["automerge_version"], "3.5.0");
    let suite = suite();
    let f = Fixtures::load(&suite);
    let mut changes_applied = 0;
    for entry in corpus["scenarios"].as_array().unwrap() {
        let id = entry["id"].as_str().unwrap();
        // Every change parses, survives §11 framing, and applies in order.
        let mut doc = f.doc("masha");
        for (n, c) in entry["changes"].as_array().unwrap().iter().enumerate() {
            let bytes = base::from_hex(c["change_hex"].as_str().unwrap()).unwrap();
            let change = framing::decode_change(&framing::encode_change(&bytes))
                .unwrap_or_else(|err| panic!("{id} change {n}: {err}"));
            assert_eq!(
                change.hash().to_string(),
                c["hash"].as_str().unwrap(),
                "{id} change {n}: hash"
            );
            assert_eq!(
                change.actor_id().to_hex_string(),
                c["actor_hex"].as_str().unwrap(),
                "{id} change {n}: actor"
            );
            assert_eq!(
                change.actor_id().to_bytes(),
                f.principals[c["actor"].as_str().unwrap()].1,
                "{id} change {n}: §8 actor of {}",
                c["actor"]
            );
            doc.apply_changes(vec![change])
                .unwrap_or_else(|err| panic!("{id} change {n}: {err}"));
            changes_applied += 1;
        }
        let heads: Vec<String> = doc.heads().iter().map(|h| h.to_string()).collect();
        let want_heads: Vec<String> = entry["heads"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| h.as_str().unwrap().to_owned())
            .collect();
        let mut sorted = heads.clone();
        sorted.sort();
        assert_eq!(sorted, want_heads, "{id}: heads");

        // The save image loads (§13, §14) to the same state.
        let save = base::from_hex(entry["save_hex"].as_str().unwrap()).unwrap();
        let framed = framing::encode_snapshot(&save);
        let mut loaded = SharedObjects::load(
            &framing::decode_snapshot(&framed).unwrap(),
            f.actor("masha"),
        )
        .unwrap_or_else(|err| panic!("{id}: load: {err}"));
        assert_eq!(loaded.validate_root(), Ok(()), "{id}: root");
        assert_eq!(
            loaded.plain().unwrap(),
            plain(&entry["state"]),
            "{id}: loaded state"
        );
        assert_eq!(
            doc.plain().unwrap(),
            plain(&entry["state"]),
            "{id}: applied state"
        );
        assert_eq!(
            conflicts_of(&loaded).0,
            corpus_conflicts(entry),
            "{id}: conflicts"
        );
        for key in loaded.object_keys().unwrap() {
            let want = if id == "S13" {
                ObjectStatus::Collision
            } else {
                ObjectStatus::Ready
            };
            assert_eq!(loaded.object_status(&key).unwrap(), want, "{id}: {key}");
        }

        // Not normative (§14 requires only that the image loads): Automerge
        // 0.12.0 is the core of the JS reference, so re-saving reproduces
        // the image byte for byte.
        assert_eq!(loaded.save(), save, "{id}: re-save (informative)");

        if let Some(snapshot) = entry.get("snapshot") {
            // S14: load the Snapshot, then apply the changes it lacks.
            let image = base::from_hex(snapshot["save_hex"].as_str().unwrap()).unwrap();
            let mut from_snapshot = SharedObjects::load(&image, f.actor("masha")).unwrap();
            let missing: Vec<Change> = doc
                .changes()
                .into_iter()
                .filter(|c| !snapshot_contains(&image, c))
                .collect();
            assert!(!missing.is_empty(), "{id}: changes after the snapshot");
            from_snapshot.apply_changes(missing).unwrap();
            assert_eq!(
                from_snapshot.plain().unwrap(),
                plain(&entry["state"]),
                "{id}: snapshot + changes"
            );
        }
    }
    assert_eq!(changes_applied, 52, "corpus changes");
}

fn snapshot_contains(image: &[u8], change: &Change) -> bool {
    let mut doc = automerge::AutoCommit::load(image).unwrap();
    doc.get_change_by_hash(&change.hash()).is_some()
}

#[test]
fn tombstones_keep_the_object_and_can_be_restored() {
    // §26, §51, §54–§56 through the intents, beyond S09/S10.
    let suite = suite();
    let f = Fixtures::load(&suite);
    let (mut doc, key) = s01_document(&suite, &f);
    doc.delete(&key).unwrap();
    assert_eq!(values(&doc, &key, "lifecycle"), vec!["deleted"]);
    assert!(
        doc.object_keys().unwrap().contains(&key),
        "never removed from objects"
    );
    doc.set_title(&key, "edited while deleted").unwrap();
    doc.restore(&key).unwrap();
    assert_eq!(values(&doc, &key, "lifecycle"), vec!["active"]);
    assert_eq!(values(&doc, &key, "title"), vec!["edited while deleted"]);
    assert_eq!(doc.object_status(&key).unwrap(), ObjectStatus::Ready);
}

#[test]
fn text_strings_are_profile_invalid() {
    // §30 (G-SC3): a field held as collaborative Text is
    // INVALID_FIELD_TYPE.
    let suite = suite();
    let f = Fixtures::load(&suite);
    let (mut doc, key) = s01_document(&suite, &f);
    doc.write_field("mutation", &key, "title", &Plain::Text("as text".into()))
        .unwrap();
    assert_eq!(
        doc.object_status(&key).unwrap(),
        ObjectStatus::Invalid(Diagnostic::InvalidFieldType)
    );
}

#[test]
fn the_corpus_change_actor_negative_is_not_merged() {
    // SO-SEC1-change-actor-mismatch: on top of S01, a Data Unit signed by
    // andrey carrying pavel's change.
    let corpus = corpus();
    let negatives = corpus["negatives"].as_array().unwrap();
    assert_eq!(negatives.len(), 1);
    let negative = &negatives[0];
    let id = negative["id"].as_str().unwrap();
    assert_eq!(id, "SO-SEC1-change-actor-mismatch");
    let suite = suite();
    let f = Fixtures::load(&suite);
    assert_eq!(
        ResourceId::from_hex(corpus["resource_hex"].as_str().unwrap()).unwrap(),
        f.resource,
        "{id}: the corpus Resource"
    );

    // The base scenario's changes.
    let base = negative["base_scenario"].as_str().unwrap();
    let scenario = corpus["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == base)
        .unwrap();
    let mut receiver = f.doc("masha");
    for c in scenario["changes"].as_array().unwrap() {
        let bytes = base::from_hex(c["change_hex"].as_str().unwrap()).unwrap();
        receiver
            .apply_changes(vec![framing::decode_change(&framing::encode_change(
                &bytes,
            ))
            .unwrap()])
            .unwrap();
    }
    let heads = receiver.heads();

    let plaintext = base::from_hex(negative["plaintext_hex"].as_str().unwrap()).unwrap();
    let signer = negative["signer"].as_str().unwrap();
    let (signer_id, signer_actor) = f.principals[signer];
    assert_eq!(
        base::to_hex(&signer_actor),
        negative["signer_actor_hex"].as_str().unwrap(),
        "{id}: §8 actor of the signer"
    );
    let err = receiver
        .apply_unit_change(&f.resource, &signer_id, &plaintext)
        .unwrap_err();
    let expected = &negative["expected"];
    assert_eq!(expected["disposition"], "reject", "{id}");
    assert_eq!(err.code(), expected["error"]["code"].as_str(), "{id}");
    assert_eq!(
        err.diagnostic().map(Diagnostic::name),
        expected["error"]["diagnostic"].as_str(),
        "{id}"
    );
    assert_eq!(receiver.heads(), heads, "{id}: nothing merged");

    // The same plaintext signed by its actor's Principal is a valid change.
    let change = framing::decode_change(&plaintext).unwrap();
    let (pavel, pavel_actor) = f.principals["pavel"];
    assert_eq!(change.actor_id().to_bytes(), pavel_actor, "{id}");
    assert_eq!(
        receiver.apply_unit_change(&f.resource, &pavel, &plaintext),
        Ok(())
    );
}

#[test]
fn a_change_must_carry_the_signers_actor() {
    // §8, §11 (SO-SEC1): ANDREY writes a change; a Data Unit signed by
    // PAVEL carrying it must not enter the document.
    let suite = suite();
    let f = Fixtures::load(&suite);
    let mut andrey = f.doc("andrey");
    let mut change = andrey.initialize().unwrap();
    let plaintext = framing::encode_change(&change.bytes());
    let (pavel, _) = f.principals["pavel"];
    let (andrey_id, _) = f.principals["andrey"];

    let mut receiver = f.doc("masha");
    assert_eq!(
        receiver.apply_unit_change(&f.resource, &pavel, &plaintext),
        Err(ProfileError::Invalid(Diagnostic::ChangeActorMismatch))
    );
    assert!(receiver.heads().is_empty(), "nothing applied");
    assert_eq!(
        lfcp::shared_objects::document::check_change_actor(&f.resource, &pavel, &change),
        Err(ProfileError::Invalid(Diagnostic::ChangeActorMismatch))
    );

    assert_eq!(
        receiver.apply_unit_change(&f.resource, &andrey_id, &plaintext),
        Ok(())
    );
    assert_eq!(receiver.heads(), vec![change.hash()]);
    // The check is per Resource: the same Principal's actor in another
    // Resource does not match.
    let other = ResourceId::from_bytes([9; 32]);
    assert_eq!(
        f.doc("masha")
            .apply_unit_change(&other, &andrey_id, &plaintext),
        Err(ProfileError::Invalid(Diagnostic::ChangeActorMismatch))
    );
}
