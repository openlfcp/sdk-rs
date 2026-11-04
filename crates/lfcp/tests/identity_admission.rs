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
