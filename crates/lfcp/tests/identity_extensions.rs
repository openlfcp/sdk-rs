#![cfg(feature = "identity")]
mod support;

use automerge::{transaction::Transactable, AutoCommit, ObjType, ReadDoc, ROOT};
use lfcp::{
    identity::{Diagnostic, Received, UnitContext, WriterClass},
    shared_objects::{framing, identity::actor_id},
};
use support::identity_profile::Profile;

#[test]
fn invalid_extension_namespace_does_not_disable_identity_entries() {
    let p = Profile::load();
    let mut replica = p.replica();
    for change in ["C0_initial", "C1_fill", "J1_own_request"] {
        assert_eq!(p.deliver(&mut replica, change), Received::Applied);
    }
    let before = replica.view();
    let mut doc = AutoCommit::load(&replica.save())
        .unwrap()
        .with_actor(actor_id(&p.resource, &p.owner));
    let extensions = doc.get(ROOT, "extensions").unwrap().unwrap().1;
    doc.put_object(&extensions, "Bad_NS", ObjType::Map).unwrap();
    doc.put(&extensions, "com.example.app", "preserved")
        .unwrap();
    doc.commit();
    let change = doc.get_last_local_change().unwrap();
    assert_eq!(
        replica.receive(
            UnitContext {
                signer: p.owner,
                class: WriterClass::Root,
                actor_sequence: 3,
            },
            &framing::encode_change(change.raw_bytes()),
        ),
        Received::Applied,
    );
    let view = replica.view();
    assert_eq!(view.validate_root(), Ok(()));
    assert_eq!(
        view.extension_diagnostic("Bad_NS"),
        Some(Diagnostic::InvalidExtensionNamespace),
    );
    assert_eq!(view.extension_diagnostic("com.example.app"), None);
    assert_eq!(view.extension_diagnostic("com.example.absent"), None);
    assert_eq!(view.extension_diagnostic("Absent_NS"), None);
    for container in ["roster", "devices", "requests"] {
        let entries = before.entries(container).unwrap();
        assert!(!entries.is_empty());
        assert_eq!(view.entries(container).unwrap(), entries);
        for key in entries.keys() {
            assert_eq!(view.entry_diagnostic(container, key), None);
        }
    }
    // Preserve even the invalid namespace for round trips and raw diagnostics.
    assert!(view
        .automerge()
        .get(&extensions, "Bad_NS")
        .unwrap()
        .is_some());
    let restored = lfcp::identity::IdentityDoc::inspect(&replica.save(), p.owner).unwrap();
    assert_eq!(restored.plain().unwrap(), view.plain().unwrap());
    assert_eq!(restored.validate_root(), Ok(()));
}
