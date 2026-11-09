#![cfg(feature = "identity")]
mod support;

use automerge::{transaction::Transactable, AutoCommit, ObjId, ObjType, ReadDoc, ROOT};
use lfcp::{
    base::PrincipalId,
    identity::{Diagnostic, IdentityReplica, Received, UnitContext, WriterClass},
    shared_objects::{
        framing,
        identity::{actor_id, parse_principal_ref},
    },
};
use support::{identity_corpus::s, identity_profile::Profile};

fn write(
    profile: &Profile,
    replica: &mut IdentityReplica,
    signer: PrincipalId,
    class: WriterClass,
    edit: impl FnOnce(&mut AutoCommit),
) -> Received {
    let mut doc = AutoCommit::load(&replica.save())
        .unwrap()
        .with_actor(actor_id(&profile.resource, &signer));
    edit(&mut doc);
    doc.commit();
    let change = doc.get_last_local_change().unwrap();
    replica.receive(
        UnitContext {
            signer,
            class,
            actor_sequence: change.seq(),
        },
        &framing::encode_change(change.raw_bytes()),
    )
}

fn object(doc: &AutoCommit, path: &[&str]) -> ObjId {
    path.iter()
        .fold(ROOT, |obj, key| doc.get(obj, *key).unwrap().unwrap().1)
}

#[test]
fn replacing_own_nested_hint_list_is_admitted_then_invalid_for_readers() {
    let p = Profile::load();
    let device = s(&p.corpus.data["fixtures"]["refs"]["DEV_B"]);
    let resource = s(&p.corpus.data["fixtures"]["resource_refs"]["X"]);
    let mut replica = p.replica();
    for name in [
        "C0_initial",
        "C1_fill",
        "M0_entry_dev_b",
        "M1_dev_b_writes_hint",
    ] {
        assert_eq!(p.deliver(&mut replica, name), Received::Applied);
    }
    assert_eq!(replica.view().entry_diagnostic("devices", device), None);

    // Review A: depth 4 is below the entry's immediate fields. AI5 permits
    // the device's own hint; the resulting field type is checked by §4.
    assert_eq!(
        write(
            &p,
            &mut replica,
            parse_principal_ref(device).unwrap(),
            WriterClass::Personal,
            |doc| {
                let hints = object(doc, &["devices", device, "missing_keys"]);
                doc.put(hints, resource, 7u64).unwrap();
            }
        ),
        Received::Applied,
    );
    let view = replica.view();
    assert_eq!(
        view.entry_diagnostic("devices", device),
        Some(Diagnostic::InvalidFieldType)
    );
    assert!(!view.entries("devices").unwrap().contains_key(device));
    assert!(replica.waiting().is_empty());
}

#[test]
fn nested_unknown_map_can_be_replaced_but_its_entry_field_cannot() {
    let p = Profile::load();
    let resource = s(&p.corpus.data["fixtures"]["resource_refs"]["X"]);
    let mut replica = p.replica();
    for name in ["C0_initial", "C1_fill"] {
        assert_eq!(p.deliver(&mut replica, name), Received::Applied);
    }
    assert_eq!(
        write(&p, &mut replica, p.owner, WriterClass::Root, |doc| {
            let entry = object(doc, &["roster", resource]);
            let ext = doc.put_object(entry, "ext", ObjType::Map).unwrap();
            doc.put_object(ext, "a", ObjType::Map).unwrap();
        }),
        Received::Applied,
    );

    // Review B: preserve forward compatibility for unknown fields at depth 4.
    assert_eq!(
        write(&p, &mut replica, p.owner, WriterClass::Root, |doc| {
            let ext = object(doc, &["roster", resource, "ext"]);
            doc.put(ext, "a", "s").unwrap();
        }),
        Received::Applied,
    );
    let view = replica.view();
    assert_eq!(view.entry_diagnostic("roster", resource), None);
    assert!(view.entries("roster").unwrap().contains_key(resource));

    // Review B2: the map in the immediate entry field (depth 3) is protected.
    let before = replica.save();
    assert_eq!(
        write(&p, &mut replica, p.owner, WriterClass::Root, |doc| {
            let entry = object(doc, &["roster", resource]);
            doc.put(entry, "ext", "s").unwrap();
        }),
        Received::Refused(Diagnostic::ContainerReplaced),
    );
    assert_eq!(replica.save(), before);
}

/// AI3 positions (IDENTITY-PROFILE-01 §3, decision I27) that the profile
/// corpus does not reach: a list or a signed int as a list element or hint
/// entry, and values below a hint entry or a list held where §2.1
/// defines a map, which AI3 does not check.
#[test]
fn ai3_checks_only_the_positions_the_profile_defines() {
    use automerge::ScalarValue;
    let p = Profile::load();
    let owner = p.owner;
    let device = s(&p.corpus.data["fixtures"]["refs"]["DEV_B"]);
    let x = s(&p.corpus.data["fixtures"]["resource_refs"]["X"]);
    let y = s(&p.corpus.data["fixtures"]["resource_refs"]["Y"]);
    let base = [
        "C0_initial",
        "C1_fill",
        "M0_entry_dev_b",
        "M1_dev_b_writes_hint",
    ];
    let fresh = || {
        let mut replica = p.replica();
        for name in base {
            assert_eq!(p.deliver(&mut replica, name), Received::Applied);
        }
        replica
    };
    let refused = Received::Refused(Diagnostic::InvalidFieldType);
    type Edit<'a> = Box<dyn FnOnce(&mut AutoCommit) + 'a>;
    let by_root: Vec<(&str, Edit<'_>, Received)> = vec![
        (
            "a list as an element of endpoints",
            Box::new(move |doc| {
                let list = object(doc, &["roster", x, "endpoints"]);
                doc.insert_object(&list, 0, ObjType::List).unwrap();
            }),
            refused,
        ),
        (
            "a signed int as an element of endpoints",
            Box::new(move |doc| {
                let list = object(doc, &["roster", x, "endpoints"]);
                doc.insert(&list, 0, ScalarValue::Int(1)).unwrap();
            }),
            refused,
        ),
        (
            "a counter in extensions[ns]",
            Box::new(|doc| {
                let ext = object(doc, &["extensions"]);
                doc.put(&ext, "com.example.c", ScalarValue::counter(1))
                    .unwrap();
            }),
            Received::Applied,
        ),
        (
            "a signed int in a list below the scalar field name",
            Box::new(move |doc| {
                let entry = object(doc, &["roster", x]);
                let list = doc.put_object(&entry, "name", ObjType::List).unwrap();
                doc.insert(&list, 0, ScalarValue::Int(-1)).unwrap();
            }),
            Received::Applied,
        ),
        (
            "a map key \"[]\" below an unknown field",
            Box::new(move |doc| {
                let entry = object(doc, &["roster", x]);
                let ext = doc.put_object(&entry, "ext", ObjType::Map).unwrap();
                doc.put(&ext, "[]", ScalarValue::F64(1.5)).unwrap();
            }),
            Received::Applied,
        ),
    ];
    for (name, edit, want) in by_root {
        let mut replica = fresh();
        assert_eq!(
            write(&p, &mut replica, owner, WriterClass::Root, edit),
            want,
            "{name}"
        );
    }
    let dev_b = parse_principal_ref(device).unwrap();
    let by_device: Vec<(&str, Edit<'_>, Received)> = vec![
        (
            "a signed int as an element of its own missing_keys[X]",
            Box::new(move |doc| {
                let list = object(doc, &["devices", device, "missing_keys", x]);
                doc.insert(&list, 0, ScalarValue::Int(3)).unwrap();
            }),
            refused,
        ),
        (
            "a signed int as its own hint entry missing_keys[Y]",
            Box::new(move |doc| {
                let hints = object(doc, &["devices", device, "missing_keys"]);
                doc.put(&hints, y, ScalarValue::Int(3)).unwrap();
            }),
            refused,
        ),
        (
            "a map holding a signed int as its own hint entry",
            Box::new(move |doc| {
                let hints = object(doc, &["devices", device, "missing_keys"]);
                let m = doc.put_object(&hints, y, ObjType::Map).unwrap();
                doc.put(&m, "a", ScalarValue::Int(-1)).unwrap();
            }),
            Received::Applied,
        ),
        (
            "a list in place of its missing_keys map, holding a map",
            Box::new(move |doc| {
                let entry = object(doc, &["devices", device]);
                let list = doc
                    .put_object(&entry, "missing_keys", ObjType::List)
                    .unwrap();
                doc.insert_object(&list, 0, ObjType::Map).unwrap();
            }),
            Received::Applied,
        ),
    ];
    for (name, edit, want) in by_device {
        let mut replica = fresh();
        assert_eq!(
            write(&p, &mut replica, dev_b, WriterClass::Personal, edit),
            want,
            "{name}"
        );
    }
}
