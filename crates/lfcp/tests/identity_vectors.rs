#![cfg(feature = "identity")]
mod support;
use std::collections::BTreeMap;
use support::{identity_corpus::*, identity_profile::Profile};
#[test]
fn id05_profile_vectors() {
    let p = Profile::load();
    let mut results = BTreeMap::new();
    for (id, c) in &p.corpus.cases {
        if ["root_of_corpus", "assignee_root_ref"].contains(&id.as_str()) {
            let mut wire = support::identity_wire::Wire::load();
            let result = wire_profile(&mut wire, c);
            results.insert(id.clone(), result);
            continue;
        }
        eprintln!("profile {id}");
        let result = p.run(c);
        check(c, &result);
        results.insert(id.clone(), result);
    }
    assert_eq!(results.len(), 271);
    export("identity-profile", &results);
}

#[test]
fn ai5_is_mandatory_and_foreign_forwarding_cannot_poison_initialisation() {
    use lfcp::identity::{Diagnostic, IdentityReplica, Received};
    let p = Profile::load();
    let mut strict = IdentityReplica::new(p.resource, p.owner);
    let snapshot = bytes(&p.corpus.case("device_entry_missing_keys_union")["inputs"]["snapshot"]);
    let witnesses = p.snapshot_witnesses(&snapshot);
    for (u, plaintext) in &witnesses {
        strict.receive(*u, plaintext);
    }
    assert!(strict
        .refused()
        .values()
        .any(|d| *d == Diagnostic::UnauthorizedWriter));
    let mut baseline = p.replica();
    assert!(!baseline
        .receive_snapshot(
            &lfcp::shared_objects::framing::encode_snapshot(&snapshot),
            &witnesses
        )
        .unwrap());
    assert!(baseline.refused().is_empty());
    let (unit, plaintext) = p.unit(p.change_case("C0_initial"));
    let mut r = p.replica();
    let mut wrong = unit;
    wrong.actor_sequence = 2;
    assert_eq!(
        r.receive(wrong, &plaintext),
        Received::Refused(Diagnostic::InvalidRoot)
    );
    assert_eq!(r.receive(unit, &plaintext), Received::Applied);
    assert_eq!(r.receive(unit, &plaintext), Received::Duplicate);
    wrong.signer = lfcp::base::PrincipalId::from_bytes([99; 32]);
    assert_eq!(
        r.receive(wrong, &plaintext),
        Received::Refused(Diagnostic::ChangeActorMismatch)
    );
    assert_eq!(r.receive(unit, &plaintext), Received::Duplicate);
    assert_eq!(r.accepted().len(), 1);
}

#[test]
fn pairing_link_checks_unknown_parameter_encoding_and_keeps_the_secret_redacted() {
    use lfcp::identity::links::PairingLink;
    let p = Profile::load();
    let uri = s(&p.corpus.case("pair_uri_roundtrip")["expected"]["uri"]);
    for suffix in ["%", "%0", "%GG"] {
        assert!(PairingLink::parse(&uri.replace('#', &format!("&future={suffix}#"))).is_err());
    }
    let link = PairingLink::parse(&uri.replace('#', "&future=allowed#")).unwrap();
    assert_eq!(&*link.encode(), uri);
    assert!(!format!("{link:?}").contains(uri.split_once("#secret=").unwrap().1));
    assert!(PairingLink::parse(&uri.replace("&device=", "&device=bad&device=")).is_err());
}

#[test]
fn id01_through_id04_wire_vectors() {
    let mut wire = support::identity_wire::Wire::load();
    let cases = wire.corpus.cases.clone();
    let mut results = BTreeMap::new();
    for (id, c) in &cases {
        eprintln!("wire {id}");
        let result = wire.run(c);
        check(c, &result);
        results.insert(id.clone(), result);
    }
    assert_eq!(results.len(), 424);
    export("identity-wire", &results);
}

fn wire_profile(
    wire: &mut support::identity_wire::Wire,
    c: &serde_json::Value,
) -> serde_json::Value {
    use lfcp::shared_objects::identity::parse_principal_ref;
    use serde_json::json;
    let i = &c["inputs"];
    let e = &c["expected"];
    if c["id"] == "root_of_corpus" {
        let mut tables = BTreeMap::new();
        for (label, head) in i["heads"].as_object().unwrap() {
            let state = wire.at(s(head));
            let table = wire.queries(&state, e[label].as_object().unwrap().keys().cloned());
            assert_eq!(table, e[label]);
            tables.insert(label, table);
        }
        assert_eq!(json!(tables), *e);
        accepted(vec![], json!(tables))
    } else {
        let state = wire.at(s(&i["head"]));
        let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut refs: Vec<_> = i["assignees"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| s(r).to_string())
            .collect();
        refs.sort();
        for r in &refs {
            let root = state.root_of(&parse_principal_ref(r).unwrap());
            groups.entry(wire.name(&root)).or_default().push(r.clone());
        }
        let mut humans: Vec<_> = groups.keys().cloned().collect();
        humans.sort_by_key(|label| wire.id(label).to_hex());
        let merged: BTreeMap<_, _> = groups
            .into_iter()
            .filter(|(_, refs)| refs.len() > 1)
            .collect();
        let post = json!({"crdt_set":refs,"display_humans":humans,"merged":merged});
        assert_eq!(post, *e);
        accepted(vec![], post)
    }
}

#[test]
fn list_validation_checks_hidden_values_and_roster_unknown_conflicts_are_ignored() {
    use automerge::{transaction::Transactable, ActorId, AutoCommit, ReadDoc, ROOT};
    use lfcp::identity::{Diagnostic, IdentityDoc};
    let p = Profile::load();
    let save = bytes(&p.corpus.case("identity_doc_initial_then_fill")["inputs"]["snapshot"]);
    let mut base = AutoCommit::load(&save).unwrap();
    let roster = base.get(ROOT, "roster").unwrap().unwrap().1;
    let key = s(&p.corpus.data["fixtures"]["resource_refs"]["X"]);
    let entry = base.get(roster, key).unwrap().unwrap().1;
    let mut a = base.fork().with_actor(ActorId::from([1u8; 32]));
    let mut b = base.fork().with_actor(ActorId::from([2u8; 32]));
    a.put(&entry, "kind", "unknown A").unwrap();
    a.commit();
    b.put(&entry, "kind", "unknown B").unwrap();
    b.commit();
    a.merge(&mut b).unwrap();
    let view = IdentityDoc::inspect(&a.save(), p.owner).unwrap();
    assert_eq!(view.entry_diagnostic("roster", key), None);
    let endpoints = a.get(&entry, "endpoints").unwrap().unwrap().1;
    let mut b = a.fork().with_actor(ActorId::from([2u8; 32]));
    a.put(&endpoints, 0, 99u64).unwrap();
    a.commit();
    b.put(&endpoints, 0, "wss://valid.test/ws").unwrap();
    b.commit();
    a.merge(&mut b).unwrap();
    assert_eq!(
        IdentityDoc::inspect(&a.save(), p.owner)
            .unwrap()
            .entry_diagnostic("roster", key),
        Some(Diagnostic::InvalidFieldType)
    );
}

#[test]
fn replacing_a_container_created_in_the_same_change_is_refused() {
    use automerge::{transaction::Transactable, AutoCommit, ObjType, ReadDoc, ROOT};
    use lfcp::{
        identity::{Diagnostic, Received, UnitContext, WriterClass},
        shared_objects::{framing, identity::actor_id},
    };
    let p = Profile::load();
    let mut r = p.replica();
    p.deliver(&mut r, "C0_initial");
    p.deliver(&mut r, "C1_fill");
    let mut d = AutoCommit::load(&r.save())
        .unwrap()
        .with_actor(actor_id(&p.resource, &p.owner));
    let roster = d.get(ROOT, "roster").unwrap().unwrap().1;
    d.put_object(&roster, "temporary", ObjType::Map).unwrap();
    d.put(&roster, "temporary", "scalar").unwrap();
    d.commit();
    let raw = d.get_last_local_change().unwrap().raw_bytes().to_vec();
    let unit = UnitContext {
        signer: p.owner,
        class: WriterClass::Root,
        actor_sequence: 3,
    };
    assert_eq!(
        r.receive(unit, &framing::encode_change(&raw)),
        Received::Refused(Diagnostic::ContainerReplaced)
    );
}

#[test]
fn profile_runner_checks_all_document_assertions() {
    let p = Profile::load();
    for (id, pointer, wrong) in [
        (
            "identity_doc_initial_then_fill",
            "/expected/admitted",
            serde_json::json!([]),
        ),
        (
            "identity_doc_initial_then_fill",
            "/expected/entries/roster",
            serde_json::json!({}),
        ),
        (
            "identity_snapshot_equivalence",
            "/expected/entries/requests",
            serde_json::json!({}),
        ),
        (
            "identity_doc_second_initial_other_unit",
            "/expected/snapshot/initial_change",
            serde_json::json!("C0s_second_initial"),
        ),
        (
            "device_entry_missing_keys_union",
            "/expected/missing_keys_conflict_set",
            serde_json::json!([]),
        ),
        (
            "missing_keys_concurrent_device_and_root",
            "/expected/pending",
            serde_json::json!([]),
        ),
        (
            "missing_keys_hidden_entry_resolution",
            "/expected/foreign/state/devices",
            serde_json::json!({}),
        ),
    ] {
        let mut case = p.corpus.case(id).clone();
        *case.pointer_mut(pointer).unwrap() = wrong;
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| p.run(&case))).is_err(),
            "unchecked {id}{pointer}"
        );
    }
}

#[test]
fn ai5_precedes_type_errors_but_follows_container_replacement() {
    use automerge::{transaction::Transactable, AutoCommit, ReadDoc, ROOT};
    use lfcp::{
        identity::{Diagnostic, Received, UnitContext, WriterClass},
        shared_objects::{
            framing,
            identity::{actor_id, parse_principal_ref},
        },
    };
    let p = Profile::load();
    let key = s(&p.corpus.data["fixtures"]["refs"]["DEV_B"]);
    for (existing_hint, own, diagnostic) in [
        (false, false, Diagnostic::UnauthorizedWriter),
        (false, true, Diagnostic::InvalidFieldType),
        (true, false, Diagnostic::ContainerReplaced),
    ] {
        let mut r = p.replica();
        for name in ["C0_initial", "C1_fill", "M0_entry_dev_b"] {
            assert_eq!(p.deliver(&mut r, name), Received::Applied);
        }
        if existing_hint {
            assert_eq!(p.deliver(&mut r, "M1_dev_b_writes_hint"), Received::Applied);
        }
        let before = r.save();
        let signer = if own {
            parse_principal_ref(key).unwrap()
        } else {
            p.owner
        };
        let mut doc = AutoCommit::load(&before)
            .unwrap()
            .with_actor(actor_id(&p.resource, &signer));
        let devices = doc.get(ROOT, "devices").unwrap().unwrap().1;
        let entry = doc.get(devices, key).unwrap().unwrap().1;
        doc.put(entry, "missing_keys", -1i64).unwrap();
        doc.commit();
        let change = doc.get_last_local_change().unwrap();
        assert_eq!(
            r.receive(
                UnitContext {
                    signer,
                    class: if own {
                        WriterClass::Personal
                    } else {
                        WriterClass::Root
                    },
                    actor_sequence: change.seq(),
                },
                &framing::encode_change(change.raw_bytes())
            ),
            Received::Refused(diagnostic)
        );
        assert_eq!(r.save(), before);
    }
}
