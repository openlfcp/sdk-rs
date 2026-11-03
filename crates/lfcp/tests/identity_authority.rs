//! Resource-local R2 transitions against spec-pr2 WIRE §§7.3, 17.4–17.5,
//! 23.3, 25.2, 41, 62 and 80.1. Exact vector corpora are supplied by R3.
mod support;

use lfcp::base::{AuthorityRule as Rule, Error, Hash32, ResourceId, WireCode};
use lfcp::wire::control::authority::{can_distribute_key, can_write, ReadAccess, Role};
use lfcp::wire::control::body::*;
use lfcp::wire::control::chain::{
    validate_chain, ChainOutcome, ChainStart, ResolveWith, SignaturesOnly,
};
use lfcp::wire::control::device::*;
use support::identity::*;

#[test]
fn genesis_device_requires_leaf_signature_and_owner_act() {
    let certificates = chain(vec![personal(1, 2, &[13], 1, 1)]);
    for signer in [1, 8] {
        let bytes = genesis(1, signer, Some(certificates.clone()))
            .signed_object()
            .bytes()
            .to_vec();
        assert_eq!(
            validate(&[bytes]).unwrap_err().error,
            Error::CoseKidMismatch
        );
    }
    let f = Fixture::from_genesis(genesis(1, 2, Some(certificates)));
    assert_eq!(f.state().owner.id(), &id(1));
    assert_eq!(f.state().role(&id(1)), Some(Role::NonDevice));
    assert_eq!(f.state().role(&id(2)), Some(Role::Device));
    assert!(f.state().owner_action(&id(2)));
    assert!(f.state().holds(&id(2), 1)); // owner/act overrides mask
    for code in [9, 11, 12, 13, 99] {
        assert!(!f.state().holds(&id(2), code));
    }
    for (kind, mask, scope) in [
        (DeviceKind::Personal, vec![1], vec![]),
        (DeviceKind::Service, vec![1], vec![RESOURCE]),
        (DeviceKind::Pairing, vec![1, 2], vec![RESOURCE]),
    ] {
        let c = chain(vec![DeviceCertificate::sign(
            payload(1, 2, kind, &mask, &scope, 1),
            &keys(1),
        )
        .unwrap()]);
        assert_eq!(
            validate(&[genesis(1, 2, Some(c)).signed_object().bytes().to_vec()])
                .unwrap_err()
                .error,
            Error::AuthorizationFailed(Rule::DeviceCannotActAsOwner)
        );
    }
}

#[test]
fn embedded_issuers_and_all_intermediates_are_learned_but_only_leaf_registered() {
    for signer in [1, 2, 3] {
        let mut f = Fixture::new();
        let certificates = chain(vec![
            personal(1, 3, &[1, 2], 2, 3),
            personal(1, 2, FULL, 1, 2),
        ]);
        f.push(signer, device_grant(certificates, None));
        assert!(f.state().active_device(&id(3)).is_some());
        assert!(f.state().active_device(&id(2)).is_none());
        assert!(!f.state().device(&id(2)).unwrap().registered);
        assert!(f.state().principal(&id(2)).is_some());
        assert_eq!(f.state().acts_for(&id(3)), id(1));
        assert_eq!(f.state().root_of(&id(2)), id(1));
        assert_eq!(f.state().acts_for(&id(2)), id(2));
        // Becoming a leaf later registers the already bound intermediate.
        f.register(1, 2, FULL);
        assert!(f.state().active_device(&id(2)).is_some());
        f.replay();
    }
}

#[test]
fn masks_scope_and_binding_equality_are_sets_and_immutable() {
    let mut f = Fixture::new();
    f.register(1, 2, &[1, 2, 99]);
    f.push(
        1,
        device_grant(chain(vec![personal(1, 2, &[99, 2, 1], 1, 4)]), None),
    );
    f.denied(
        1,
        device_grant(chain(vec![personal(1, 2, &[1, 2, 3, 99], 1, 5)]), None),
        Rule::DeviceBindingConflict,
    );
    f.denied(
        1,
        device_grant(chain(vec![personal(1, 2, &[1], 1, 5)]), None),
        Rule::DeviceBindingConflict,
    );
    let other = ResourceId::from_bytes([78; 32]);
    let service = |scope: &[ResourceId], serial| {
        chain(vec![DeviceCertificate::sign(
            payload(1, 6, DeviceKind::Service, &[1], scope, serial),
            &keys(1),
        )
        .unwrap()])
    };
    f.push(1, device_grant(service(&[other, RESOURCE], 1), None));
    f.push(1, device_grant(service(&[RESOURCE, other], 2), None));
    f.denied(
        1,
        device_grant(service(&[RESOURCE], 3), None),
        Rule::DeviceBindingConflict,
    );
    let mut outside = Fixture::new();
    outside.push(1, device_grant(service(&[other], 1), None));
    assert!(outside.state().bound(&id(6)));
    assert!(!outside.state().device(&id(6)).unwrap().registered);
    assert_eq!(outside.state().may_read(&id(6)), ReadAccess::Denied);
    outside.denied(
        1,
        device_grant(service(&[other], 1), None),
        Rule::DeviceAlreadyBound,
    );
    f.replay();
}

#[test]
fn root_standing_uses_non_invitation_grants_and_returns_without_reregistration() {
    let mut f = Fixture::new();
    f.push(1, grant(10, &[1, 2, 11], &[], None, Some(0)));
    let certs = chain(vec![personal(10, 2, &[1, 2], 10, 2)]);
    assert!(!f.state().root_standing(&id(10)));
    f.denied(
        10,
        device_grant(certs.clone(), None),
        Rule::DeviceRootNotStanding,
    );
    f.push(1, grant(10, &[1, 2], &[], None, None));
    let standing_grant = f.state().head.id;
    f.push(2, device_grant(certs, None));
    assert!(f.state().holds(&id(2), 2));
    f.push(
        1,
        ControlBody::CapabilityRevoke(CapabilityRevokeBody {
            grant: standing_grant,
        }),
    );
    assert!(f.state().active_device(&id(2)).is_none());
    assert_eq!(f.state().may_read(&id(2)), ReadAccess::Denied);
    f.denied(10, revoke(10, 2, 2, None), Rule::DeviceRevokeIssuer);
    f.push(1, grant(10, &[1, 2], &[], None, None));
    assert!(f.state().holds(&id(2), 2));
    f.replay();
}

#[test]
fn role_exclusivity_survives_revocation_for_subject_claimant_and_transferee() {
    let mut f = Fixture::new();
    f.register(1, 2, &[1, 2]);
    f.denied(1, grant(2, &[1], &[], None, None), Rule::SubjectIsDevice);
    f.push(1, grant(8, &[1, 11], &[], None, Some(1)));
    let invite = f.state().head.id;
    f.denied(
        8,
        ControlBody::CapabilityClaim(CapabilityClaimBody {
            invitation_grant: invite,
            claimant: keys(2).descriptor().clone(),
            abilities: vec![1],
        }),
        Rule::SubjectIsDevice,
    );
    f.denied(2, transfer(f.state(), 2, 1, 2, None), Rule::SubjectIsDevice);
    f.push(1, revoke(1, 2, 2, None));
    f.denied(1, grant(2, &[1], &[], None, None), Rule::SubjectIsDevice);
    // A revoked grant never frees the non-device role either.
    f.push(1, grant(3, &[1], &[], None, None));
    let granted = f.state().head.id;
    f.push(
        1,
        ControlBody::CapabilityRevoke(CapabilityRevokeBody { grant: granted }),
    );
    f.denied(
        1,
        device_grant(chain(vec![personal(1, 3, &[1], 1, 3)]), None),
        Rule::DeviceBindingConflict,
    );
    // Same exclusion for intermediate devices.
    f.denied(
        1,
        device_grant(
            chain(vec![personal(1, 4, &[1], 3, 4), personal(1, 3, FULL, 1, 3)]),
            None,
        ),
        Rule::DeviceBindingConflict,
    );
}

#[test]
fn cascade_recertification_keeps_bindings_but_never_clears_a_revocation() {
    let mut f = Fixture::new();
    let manager = personal(1, 2, FULL, 1, 2);
    let leaf = personal(1, 3, &[1, 2], 2, 3);
    f.push(1, device_grant(chain(vec![leaf, manager]), None));
    let before = f.state().clone();
    f.push(1, revoke(1, 2, 2, None)); // intermediate-only manager suspends a reader
    assert_eq!(f.state().last_exposing_revocation, Some(f.state().head));
    assert_eq!(f.state().may_read(&id(2)), ReadAccess::Denied);
    assert_eq!(f.state().may_read(&id(3)), ReadAccess::Denied); // cascade has no proof read
    assert!(before.holds(&id(3), 2));
    assert!(!f.state().holds(&id(3), 2));
    assert_eq!(f.state().root_of(&id(3)), id(1));
    f.denied(
        3,
        device_grant(chain(vec![personal(1, 3, &[1, 2], 1, 9)]), None),
        Rule::DeviceGrantIssuer,
    );
    f.push(
        1,
        device_grant(chain(vec![personal(1, 3, &[1, 2], 1, 9)]), None),
    );
    assert!(f.state().active_device(&id(3)).is_some());
    assert!(f.state().device(&id(3)).unwrap().issuers.is_empty());
    f.push(1, revoke(1, 3, 2, None));
    let proof = f.state().head;
    f.denied(
        1,
        device_grant(chain(vec![personal(1, 3, &[1, 2], 1, 10)]), None),
        Rule::DeviceRevoked,
    );
    f.push(1, grant(9, &[1], &[], None, None));
    assert_eq!(f.state().may_read(&id(3)), ReadAccess::ControlPrefix(proof));
    f.replay();
}

#[test]
fn two_phase_pairing_matches_payload_digest_and_consumes_once() {
    let mut f = Fixture::new();
    f.register(1, 2, FULL);
    let session = DeviceCertificate::sign(
        payload(1, 5, DeviceKind::Pairing, &[1, 2], &[RESOURCE], 5),
        &keys(2),
    )
    .unwrap();
    let manager = f
        .state()
        .device(&id(2))
        .unwrap()
        .chain
        .as_ref()
        .unwrap()
        .leaf()
        .clone();
    f.push(2, device_grant(chain(vec![session, manager.clone()]), None));
    let candidate = payload(1, 3, DeviceKind::Personal, &[1, 2], &[], 3);
    let approved = candidate.digest().unwrap();
    // Only the unsigned payload digest exists in phase 1.
    f.push(2, revoke(1, 5, 3, Some(approved)));
    let proof = f.state().head;
    assert_eq!(
        f.state().revocation(&id(1), &id(5)).unwrap().approval,
        Some(approved)
    );
    f.denied(
        2,
        revoke(1, 5, 3, Some(Hash32::from_bytes([1; 32]))),
        Rule::DeviceAlreadyRevoked,
    );
    f.denied(
        2,
        device_grant(
            chain(vec![personal(1, 4, &[1, 2], 2, 4), manager.clone()]),
            Some(5),
        ),
        Rule::DeviceApprovalMismatch,
    );
    let certificate = DeviceCertificate::sign(candidate, &keys(2)).unwrap();
    assert_ne!(certificate.id(), approved);
    let approved_chain = chain(vec![certificate, manager]);
    f.push(2, device_grant(approved_chain.clone(), Some(5)));
    f.denied(
        2,
        device_grant(approved_chain, None),
        Rule::DeviceAlreadyBound,
    );
    assert!(f.state().active_device(&id(3)).is_some());
    assert_eq!(f.state().may_read(&id(5)), ReadAccess::ControlPrefix(proof));
    let mut repeated = f.records.clone();
    repeated.push(f.records.last().unwrap().clone());
    assert_eq!(validate(&repeated).unwrap().1, f.states); // byte replay is not re-registration
    f.replay();
}

#[test]
fn delegation_mask_and_sibling_revoke_coverage_use_issuer_root() {
    let mut f = Fixture::new();
    f.push(
        1,
        grant(
            10,
            &[1, 2, 4, 5],
            &[1, 2, 4, 5, 9, 11, 12, 13, 99],
            None,
            None,
        ),
    );
    let parent = f.state().head.id;
    f.register(10, 2, &[1, 4, 5]);
    f.register(10, 3, &[1, 5]);
    f.denied(
        2,
        grant(7, &[1, 2], &[], Some(parent), None),
        Rule::DeviceDelegationMask,
    );
    f.denied(
        2,
        grant(7, &[1], &[2], Some(parent), None),
        Rule::DeviceDelegationMask,
    );
    f.denied(
        2,
        grant(7, &[1, 9], &[], Some(parent), None),
        Rule::DeviceDelegationMask,
    );
    f.push(
        2,
        grant(
            7,
            &[1, 11, 12, 13, 99],
            &[11, 12, 13, 99],
            Some(parent),
            Some(1),
        ),
    );
    let issued = f.state().head.id;
    assert_eq!(f.state().grant(&issued).unwrap().issuer, id(2));
    assert_eq!(f.state().grant(&issued).unwrap().issuer_root, id(10));
    f.push(
        3,
        ControlBody::CapabilityRevoke(CapabilityRevokeBody { grant: issued }),
    );
    assert!(!f.state().is_active(&issued));
    f.denied(
        3,
        grant(7, &[1], &[], Some(parent), None),
        Rule::MissingAbility(4),
    );
    f.replay();
}

#[test]
fn same_root_packages_require_an_active_endpoint_and_a_reading_recipient() {
    let mut f = Fixture::new();
    f.push(1, grant(10, &[1, 2], &[], None, None));
    f.register(10, 2, &[1, 2]);
    f.register(10, 3, &[1]);
    f.register(10, 4, &[2]);
    for (sender, recipient) in [(2, 10), (10, 2), (2, 3), (2, 2)] {
        assert_eq!(
            can_distribute_key(f.state(), &id(sender), &id(recipient)),
            Ok(())
        );
    }
    assert_eq!(
        can_distribute_key(f.state(), &id(10), &id(10)),
        Err(Error::AuthorizationFailed(Rule::MissingAbility(6)))
    );
    assert_eq!(
        can_distribute_key(f.state(), &id(2), &id(4)),
        Err(Error::AuthorizationFailed(Rule::MissingAbility(1)))
    );
    assert_eq!(
        can_distribute_key(f.state(), &id(2), &id(1)),
        Err(Error::AuthorizationFailed(Rule::MissingAbility(6)))
    );
    f.push(10, revoke(10, 3, 0, None));
    assert!(!f.state().same_root(&id(2), &id(3)));
    assert!(!f.state().same_root(&id(3), &id(10)));
    assert_eq!(can_write(f.state(), &id(2)), Ok(()));
}

#[test]
fn transfer_accepts_through_device_and_preserves_existing_registration() {
    let mut f = Fixture::new();
    f.register(1, 2, &[13]);
    f.push(1, grant(10, &[1], &[], None, None));
    let certs = chain(vec![personal(10, 3, &[13], 10, 3)]);
    f.push(3, device_grant(certs.clone(), None));
    let binding = f.state().device(&id(3)).unwrap().clone();
    f.push(3, transfer(f.state(), 10, 2, 3, Some(certs)));
    assert_eq!(f.state().device(&id(3)), Some(&binding));
    assert_eq!(f.state().owner.id(), &id(10));
    assert!(f.state().owner_action(&id(3)));
    assert!(!f.state().owner_action(&id(2)));
    assert!(!f.state().holds(&id(2), 1));
    f.replay();
}

#[test]
fn signatures_only_and_resolve_with_check_nested_signatures_without_authority() {
    let certificate = chain(vec![personal(1, 2, &[13], 1, 2)]);
    let g = genesis(1, 2, Some(certificate));
    let bytes = [g.signed_object().bytes()];
    assert!(matches!(
        validate_chain(&bytes, ChainStart::Genesis, &mut SignaturesOnly),
        Ok(ChainOutcome::Linear(_))
    ));
    assert!(validate_chain(
        &bytes,
        ChainStart::Genesis,
        &mut ResolveWith(|_: &lfcp::base::PrincipalId| None)
    )
    .is_ok());
    let invalid = genesis(1, 1, Some(chain(vec![personal(1, 2, &[13], 1, 2)])));
    let failure = validate_chain(
        &[invalid.signed_object().bytes()],
        ChainStart::Genesis,
        &mut SignaturesOnly,
    )
    .unwrap_err();
    assert_eq!(failure.error.wire_code(), Some(WireCode::InvalidSignature));
}

#[test]
fn grant_issuer_alternatives_and_service_pairing_restrictions() {
    for kind in [DeviceKind::Service, DeviceKind::Pairing] {
        let mut f = Fixture::new();
        let manager = personal(1, 2, FULL, 1, 2);
        let scoped =
            DeviceCertificate::sign(payload(1, 6, kind, &[1, 2], &[RESOURCE], 6), &keys(2))
                .unwrap();
        let certificates = chain(vec![scoped, manager.clone()]);
        // The leaf and an unregistered intermediate may self-register personal
        // leaves only. Their descriptors are nevertheless resolved from the body.
        for issuer in [2, 6] {
            f.denied(
                issuer,
                device_grant(certificates.clone(), None),
                Rule::DeviceGrantIssuer,
            );
        }
        f.push(1, device_grant(chain(vec![manager]), None));
        f.push(2, device_grant(certificates, None));
        assert!(f.state().active_device(&id(6)).is_some());
        f.denied(
            6,
            device_grant(chain(vec![personal(1, 7, &[1], 1, 7)]), None),
            Rule::DeviceGrantIssuer,
        );
    }
    let mut f = Fixture::new();
    f.register(1, 2, &[13]); // owner-acting, not managing
    let cert = DeviceCertificate::sign(
        payload(1, 6, DeviceKind::Service, &[1], &[RESOURCE], 6),
        &keys(1),
    )
    .unwrap();
    f.push(2, device_grant(chain(vec![cert]), None));
    f.push(1, grant(10, &[1], &[], None, None));
    f.denied(
        2,
        device_grant(chain(vec![personal(10, 3, &[1], 10, 3)]), None),
        Rule::DeviceGrantIssuer,
    );
    // Even the Resource owner cannot register a device of a different root.
    f.denied(
        1,
        device_grant(chain(vec![personal(10, 3, &[1], 10, 3)]), None),
        Rule::DeviceGrantIssuer,
    );
}

#[test]
fn revocation_consistency_issuer_and_duplicate_rules_run_in_order() {
    let mut f = Fixture::new();
    f.push(1, grant(10, &[1], &[], None, None));
    f.register(10, 2, FULL);
    f.register(10, 3, &[1]);
    f.register(1, 4, &[13]);
    f.push(1, grant(7, &[99], &[], None, None));
    f.denied(7, revoke(1, 3, 2, None), Rule::DeviceRevokeRootMismatch);
    f.denied(7, revoke(1, 10, 2, None), Rule::DeviceRevokeRole);
    f.denied(7, revoke(2, 9, 2, None), Rule::DeviceRootRole);
    f.denied(
        7,
        revoke(10, 3, 3, Some(Hash32::from_bytes([0; 32]))),
        Rule::DeviceConsumeNotPairing,
    );
    f.denied(
        7,
        revoke(10, 9, 3, Some(Hash32::from_bytes([0; 32]))),
        Rule::DeviceConsumeNotPairing,
    );
    f.denied(7, revoke(10, 3, 2, None), Rule::DeviceRevokeIssuer);
    f.denied(3, revoke(10, 3, 1, None), Rule::DeviceRevokeIssuer); // self-retire only 0
    f.push(2, revoke(10, 3, 2, None)); // active manager
    f.denied(7, revoke(10, 3, 2, None), Rule::DeviceRevokeIssuer); // before duplicate
    f.denied(10, revoke(10, 3, 2, None), Rule::DeviceAlreadyRevoked);
    f.push(4, revoke(10, 2, 99, None)); // owner's device expels another root's manager
    assert_eq!(f.state().revocation(&id(10), &id(2)).unwrap().reason, 99);
    f.replay();
}

#[test]
fn suspended_or_standingless_registered_device_can_self_retire_but_cannot_manage() {
    for lose_standing in [false, true] {
        let mut f = Fixture::new();
        f.push(1, grant(10, &[1, 2], &[], None, None));
        let membership = f.state().head.id;
        f.register(10, 2, FULL);
        let manager = f
            .state()
            .device(&id(2))
            .unwrap()
            .chain
            .as_ref()
            .unwrap()
            .leaf()
            .clone();
        f.push(
            2,
            device_grant(chain(vec![personal(10, 3, &[1, 2], 2, 3), manager]), None),
        );
        if lose_standing {
            f.push(
                1,
                ControlBody::CapabilityRevoke(CapabilityRevokeBody { grant: membership }),
            );
        } else {
            f.push(10, revoke(10, 2, 2, None));
        }
        f.denied(3, revoke(10, 3, 2, None), Rule::DeviceRevokeIssuer);
        f.push(3, revoke(10, 3, 0, None));
        assert_eq!(f.state().may_read(&id(3)), ReadAccess::Denied); // wasn't a reader immediately before
        f.replay();
    }
}

#[test]
fn unbound_revocation_binds_nothing_and_other_root_pairs_do_not_cascade() {
    let mut f = Fixture::new();
    f.push(1, revoke(10, 2, 2, None));
    assert!(f.state().device(&id(2)).is_none());
    assert_eq!(f.state().role(&id(2)), None);
    assert!(f.state().principal(&id(2)).is_none());
    assert_eq!(f.state().last_exposing_revocation, None);
    f.push(1, grant(10, &[1, 2], &[], None, None));
    f.denied(
        10,
        device_grant(chain(vec![personal(10, 2, &[1], 10, 2)]), None),
        Rule::DeviceRevoked,
    );
    f.push(
        1,
        device_grant(
            chain(vec![personal(1, 3, &[1], 2, 3), personal(1, 2, FULL, 1, 2)]),
            None,
        ),
    );
    assert!(f.state().holds(&id(3), 1));
    assert_eq!(f.state().root_of(&id(2)), id(1));
    f.denied(
        10,
        device_grant(chain(vec![personal(10, 2, FULL, 10, 9)]), None),
        Rule::DeviceBindingConflict,
    );
    f.replay();
}

#[test]
fn proof_read_and_exposure_exclude_never_readers_and_keep_invitation_reads() {
    let mut f = Fixture::new();
    f.register(1, 2, &[2]);
    f.push(1, revoke(1, 2, 0, None));
    assert_eq!(f.state().may_read(&id(2)), ReadAccess::Denied);
    assert_eq!(f.state().last_exposing_revocation, None);
    f.register(1, 3, &[1]);
    f.push(3, revoke(1, 3, 0, None));
    let proof = f.state().head;
    assert_eq!(f.state().last_exposing_revocation, Some(proof));
    f.push(1, grant(8, &[11, 99], &[], None, Some(1)));
    let invitation = f.state().head.id;
    assert_eq!(f.state().may_read(&id(8)), ReadAccess::Full);
    f.push(
        8,
        ControlBody::CapabilityClaim(CapabilityClaimBody {
            invitation_grant: invitation,
            claimant: keys(9).descriptor().clone(),
            abilities: vec![99],
        }),
    );
    assert_eq!(f.state().may_read(&id(8)), ReadAccess::Denied);
    assert_eq!(f.state().may_read(&id(3)), ReadAccess::ControlPrefix(proof));
    f.replay();
}

#[test]
fn cancelled_missing_and_wrong_root_pairing_approvals_are_refused() {
    let mut f = Fixture::new();
    let leaf = chain(vec![personal(1, 3, &[1, 2], 1, 3)]);
    f.denied(
        1,
        device_grant(leaf.clone(), Some(5)),
        Rule::DeviceApprovalMismatch,
    );
    let session = DeviceCertificate::sign(
        payload(1, 5, DeviceKind::Pairing, &[1, 2], &[RESOURCE], 5),
        &keys(1),
    )
    .unwrap();
    f.push(1, device_grant(chain(vec![session]), None));
    f.denied(
        1,
        device_grant(leaf.clone(), Some(5)),
        Rule::DeviceApprovalMismatch,
    );
    f.push(1, revoke(1, 5, 0, None));
    f.denied(1, device_grant(leaf, Some(5)), Rule::DeviceApprovalMismatch);
    f.push(1, grant(10, &[1, 2], &[], None, None));
    let foreign_leaf = chain(vec![personal(10, 4, &[1], 10, 4)]);
    f.denied(
        10,
        device_grant(foreign_leaf, Some(5)),
        Rule::DeviceApprovalMismatch,
    );
}

#[test]
fn transfer_registers_new_leaf_recertifies_suspended_leaf_and_refuses_revoked_paths() {
    let mut f = Fixture::new();
    let first = chain(vec![personal(10, 3, &[13], 10, 3)]);
    f.push(3, transfer(f.state(), 10, 1, 3, Some(first))); // root descriptor from offer
    assert_eq!(f.state().role(&id(10)), Some(Role::NonDevice));
    assert!(f.state().active_device(&id(3)).is_some());
    // Transfer back; grants preserve standing for testing suspension.
    f.push(10, grant(10, &[1], &[], None, None));
    f.push(1, transfer(f.state(), 1, 3, 1, None));
    let manager = personal(10, 2, FULL, 10, 2);
    f.push(
        10,
        device_grant(chain(vec![personal(10, 3, &[13], 2, 9), manager]), None),
    );
    f.push(1, revoke(10, 2, 2, None));
    assert!(f.state().active_device(&id(3)).is_none());
    let fresh = chain(vec![personal(10, 3, &[13], 10, 10)]);
    f.push(3, transfer(f.state(), 10, 1, 3, Some(fresh)));
    assert!(f.state().active_device(&id(3)).is_some());
    f.push(10, revoke(10, 3, 2, None));
    let next = chain(vec![personal(10, 3, &[13], 10, 11)]);
    f.denied(
        3,
        transfer(f.state(), 10, 10, 3, Some(next)),
        Rule::DeviceRevoked,
    );
    f.replay();
}

#[test]
fn owner_act_bypasses_grant_mask_but_not_parent_bounds_and_extension_requires_owner_action() {
    let mut f = Fixture::new();
    f.register(1, 2, &[13]);
    f.push(2, grant(10, &[1, 2, 11, 99], &[], None, Some(1)));
    assert_eq!(
        f.state().grant(&f.state().head.id).unwrap().issuer_root,
        id(1)
    );
    f.push(
        2,
        ControlBody::Extension {
            control_type: 32,
            body: lfcp::cbor::Value::Null,
        },
    );
    f.register(1, 3, &[1, 2, 4, 5]);
    f.denied(
        3,
        ControlBody::Extension {
            control_type: 32,
            body: lfcp::cbor::Value::Null,
        },
        Rule::NotOwner,
    );
    f.denied(3, grant(7, &[1], &[], None, None), Rule::NotOwner);
    f.push(1, grant(1, &[1], &[1], None, None));
    let parent = f.state().head.id;
    f.denied(2, grant(7, &[2], &[], Some(parent), None), Rule::Escalation);
}

#[test]
fn old_head_data_and_snapshots_survive_revocation_only_within_the_epoch_cutoff() {
    use lfcp::wire::control::authority::{data_unit_policy, key_package_policy, snapshot_policy};
    use lfcp::wire::data_unit::DataUnitHeader;
    use lfcp::wire::frontier::{ActorHave, Frontier};
    use lfcp::wire::key_package::KeyPackageHeader;
    use lfcp::wire::snapshot::SnapshotHeader;
    let mut f = Fixture::new();
    f.register(1, 2, &[1, 2, 3]);
    let head = Hash32::from_bytes(*f.state().head.id.as_bytes());
    let mut unit = DataUnitHeader {
        resource_id: RESOURCE,
        data_epoch: 0,
        actor: id(2),
        sequence: 2,
        previous: None,
        control_head: head,
    };
    let frontier = Frontier::new(vec![ActorHave {
        principal: id(2),
        contiguous: 2,
        extra: vec![],
    }])
    .unwrap();
    let snapshot = SnapshotHeader {
        resource_id: RESOURCE,
        data_epoch: 0,
        publisher: id(2),
        sequence: 1,
        control_head: head,
        frontier: frontier.clone(),
    };
    let package = KeyPackageHeader {
        resource_id: RESOURCE,
        data_epoch: 0,
        recipient: id(1),
        sender: id(2),
        control_head: head,
    };
    f.push(1, revoke(1, 2, 2, None));
    assert_eq!(data_unit_policy(&f.states)(&unit), Ok(()));
    assert_eq!(snapshot_policy(&f.states)(&snapshot), Ok(()));
    assert_eq!(key_package_policy(&f.states)(&package), Ok(())); // authorization at old head
    let mut after = unit.clone();
    after.control_head = Hash32::from_bytes(*f.state().head.id.as_bytes());
    assert_eq!(
        data_unit_policy(&f.states)(&after),
        Err(Error::AuthorizationFailed(Rule::MissingAbility(2)))
    );
    f.push(
        1,
        ControlBody::KeyEpoch(KeyEpochBody {
            epoch: 1,
            dek_commitment: Hash32::from_bytes([1; 32]),
            final_frontier: frontier,
            reason: 2,
        }),
    );
    assert_eq!(data_unit_policy(&f.states)(&unit), Ok(()));
    assert_eq!(snapshot_policy(&f.states)(&snapshot), Ok(()));
    assert_eq!(key_package_policy(&f.states)(&package), Ok(())); // closed epoch still distributable
    unit.sequence = 3;
    assert_eq!(
        data_unit_policy(&f.states)(&unit),
        Err(Error::StaleDataEpoch(
            lfcp::base::QuarantineReason::BeyondCutoff
        ))
    );
    f.replay();
}

#[test]
fn identical_transfer_leaf_does_not_replace_its_registered_issuing_path() {
    let mut f = Fixture::new();
    f.push(1, grant(10, &[1], &[], None, None));
    let leaf = personal(10, 3, &[13], 2, 3);
    f.push(
        10,
        device_grant(
            chain(vec![
                leaf.clone(),
                personal(10, 2, FULL, 4, 2),
                personal(10, 4, FULL, 10, 4),
            ]),
            None,
        ),
    );
    f.push(1, revoke(10, 4, 2, None));
    let previous_binding = f.state().device(&id(3)).unwrap().clone();
    let path = chain(vec![leaf, personal(10, 2, FULL, 10, 9)]);
    f.push(3, transfer(f.state(), 10, 1, 3, Some(path)));
    // §23.3 explicitly leaves an already registered same-ID leaf unchanged.
    assert_eq!(f.state().device(&id(3)), Some(&previous_binding));
    assert!(f.state().active_device(&id(3)).is_none());
    f.push(
        10,
        device_grant(chain(vec![personal(10, 3, &[13], 10, 10)]), None),
    );
    assert!(f.state().active_device(&id(3)).is_some());
    f.replay();
}

#[test]
fn revocation_of_one_resource_does_not_affect_genesis_in_another() {
    let certificate = chain(vec![personal(1, 2, &[13], 1, 2)]);
    let mut f = Fixture::from_genesis(genesis(1, 2, Some(certificate.clone())));
    f.push(1, revoke(1, 2, 2, None));
    let new_genesis = lfcp::wire::control::ControlRecord::sign(
        lfcp::wire::control::ControlRecordHeader {
            resource_id: ResourceId::from_bytes([88; 32]),
            sequence: 0,
            previous: None,
            issuer: id(2),
        },
        genesis_body(1, Some(certificate)),
        &keys(2),
    )
    .unwrap();
    let other = Fixture::from_genesis(new_genesis);
    assert!(other.state().owner_action(&id(2)));
    assert!(!f.state().owner_action(&id(2)));
    other.replay();
}

#[test]
fn mask_reservations_do_not_become_grants_and_a_bound_root_cannot_accept_through_a_device() {
    let mut f = Fixture::new();
    f.register(1, 2, &[1, 9, 11, 99]);
    assert_eq!(f.state().abilities(&id(2)), [1].into_iter().collect());
    assert!(f.state().device(&id(2)).unwrap().mask.contains(&11));
    f.denied(
        3,
        transfer(
            f.state(),
            2,
            1,
            3,
            Some(chain(vec![personal(2, 3, &[13], 2, 3)])),
        ),
        Rule::DeviceRootRole,
    );
    f.push(1, grant(10, &[1, 11], &[], None, Some(1)));
    f.push(1, grant(10, &[1], &[], None, None));
    f.register(10, 4, &[1, 11]);
    assert!(f.state().holds(&id(10), 11));
    assert!(!f.state().holds(&id(4), 11)); // §7.3 mask code 11 confers nothing
}

#[test]
fn owner_act_never_confers_invite_claim_even_with_root_invitation_grants() {
    use lfcp::wire::control::authority::abilities_at;
    for mask in [&[13][..], &[11, 13][..]] {
        let mut f = Fixture::new();
        f.push(1, grant(1, &[1, 11], &[], None, Some(1)));
        f.register(1, 2, mask);
        assert!(f.state().owner_action(&id(2)));
        assert!(!f.state().holds(&id(2), 11));
        let expected = [1, 2, 3, 4, 5, 6, 7, 8, 10].into_iter().collect();
        assert_eq!(f.state().abilities(&id(2)), expected);
        assert_eq!(
            abilities_at(&f.states, &f.state().head.id, &id(2)),
            Some(expected)
        );
        f.replay();
    }
}

#[test]
fn exposure_matches_reader_loss_and_shares_unaffected_certificates() {
    use std::sync::Arc;
    let mut f = Fixture::new();
    // Manager and child both have 13 but only the leaf is registered. The
    // intermediate's revocation removes a reader through the cascade alone.
    f.push(
        1,
        device_grant(
            chain(vec![
                personal(1, 3, &[13], 2, 3),
                personal(1, 2, FULL, 1, 2),
            ]),
            None,
        ),
    );
    f.register(1, 4, &[1]);
    let previous = f.state().clone();
    f.push(1, revoke(1, 2, 2, None));
    assert_eq!(f.state().last_exposing_revocation, Some(f.state().head));
    assert!(!previous.device(&id(2)).unwrap().registered);
    assert!(previous.holds(&id(3), 1));
    assert!(!f.state().holds(&id(3), 1));
    assert_eq!(f.state().may_read(&id(3)), ReadAccess::Denied);
    let old = previous.device(&id(4)).unwrap().chain.as_ref().unwrap();
    let new = f.state().device(&id(4)).unwrap().chain.as_ref().unwrap();
    assert!(Arc::ptr_eq(old, new));
    // The reference definition remains true for each Device Revoke in history.
    for pair in f.states.windows(2) {
        if pair[1].last_exposing_revocation == Some(pair[1].head) {
            assert!(pair[0]
                .devices()
                .any(|(p, d)| d.registered && pair[0].holds(&p, 1) && !pair[1].holds(&p, 1)));
        }
    }
    f.replay();
}
