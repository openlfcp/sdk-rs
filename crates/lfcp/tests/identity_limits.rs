//! §17.4 rule 8 and §17.5 rule 5: deterministic, historical per-root limits.
mod support;

use lfcp::base::{AuthorityRule as Rule, Error, ResourceId, WireCode};
use lfcp::wire::control::authority::ControlState;
use lfcp::wire::control::body::ControlBody;
use lfcp::wire::control::chain::ChainOutcome;
use lfcp::wire::control::device::*;
use support::identity::*;

fn denied(f: &Fixture, signer: u8, body: ControlBody, rule: Rule) {
    let error = f.propose(signer, body).unwrap_err();
    assert_eq!(error.wire_code(), Some(WireCode::AuthorizationFailed));
    assert_eq!(error, Error::AuthorizationFailed(rule));
}

fn assert_grants(state: &ControlState, device: u8, expected: u8) {
    assert_eq!(state.device(&id(device)).unwrap().grants_accepted, expected);
}

#[test]
fn binding_limit_counts_new_intermediates_and_releases_directly_revoked_slots() {
    let mut f = Fixture::new();
    f.push(1, grant(10, &[1], &[], None, None)); // read-only roots have standing
    for d in 20..51 {
        f.register(10, d, &[1]);
    } // 31 bindings
    let at_31 = f.state().clone();
    let manager = personal(10, 2, FULL, 10, 2);
    let two_new = chain(vec![personal(10, 3, &[1], 2, 3), manager.clone()]);
    denied(
        &f,
        10,
        device_grant(two_new, None),
        Rule::DeviceBindingLimit,
    );
    assert!(!f.state().bound(&id(2)));
    f.push(10, device_grant(chain(vec![manager]), None)); // 32nd
    denied(
        &f,
        10,
        device_grant(chain(vec![personal(10, 3, &[1], 10, 3)]), None),
        Rule::DeviceBindingLimit,
    );
    f.push(10, revoke(10, 20, 0, None));
    f.register(10, 3, &[1]); // retired binding frees a place, but stays in history
    assert!(f.state().bound(&id(20)));
    assert_eq!(f.state().devices().count(), 33);
    denied(
        &f,
        10,
        device_grant(chain(vec![personal(10, 4, &[1], 10, 4)]), None),
        Rule::DeviceBindingLimit,
    );
    // Re-certification adds no binding. Another root has its own allowance.
    f.push(
        10,
        device_grant(chain(vec![personal(10, 21, &[1], 10, 99)]), None),
    );
    f.register(1, 4, &[1]);
    assert_eq!(at_31.devices().count(), 31);
    assert!(!at_31.bound(&id(2)));
    f.replay();
}

#[test]
fn consumed_and_cancelled_pairing_devices_release_the_last_live_slot() {
    let mut f = Fixture::new();
    for d in 20..50 {
        f.register(1, d, &[1]);
    }
    f.register(1, 2, FULL); // 31 live devices
    let pairing = |d| {
        device_grant(
            chain(vec![DeviceCertificate::sign(
                payload(1, d, DeviceKind::Pairing, &[1, 2], &[RESOURCE], d),
                &keys(1),
            )
            .unwrap()]),
            None,
        )
    };
    f.push(2, pairing(3)); // 32nd slot
    let approved = personal(1, 4, &[1], 1, 4);
    denied(
        &f,
        1,
        device_grant(chain(vec![approved.clone()]), None),
        Rule::DeviceBindingLimit,
    );
    f.push(2, revoke(1, 3, 3, Some(approved.payload_digest())));
    f.push(2, device_grant(chain(vec![approved]), Some(3))); // approval replaces J
    f.push(2, revoke(1, 4, 0, None));
    f.push(2, pairing(5));
    f.push(2, revoke(1, 5, 0, None)); // cancellation also frees a place
    f.register(1, 6, &[1]);
    assert_eq!(f.state().devices().count(), 35);
    denied(
        &f,
        1,
        device_grant(chain(vec![personal(1, 7, &[1], 1, 7)]), None),
        Rule::DeviceBindingLimit,
    );
    f.replay();
}

#[test]
fn cascade_suspension_keeps_live_slots_and_forks_use_the_previous_count() {
    let mut f = Fixture::new();
    for d in 20..49 {
        f.register(1, d, &[1]);
    } // 29
    let manager = personal(1, 2, FULL, 1, 2);
    for d in [3, 4] {
        f.push(
            1,
            device_grant(
                chain(vec![personal(1, d, &[1], 2, d), manager.clone()]),
                None,
            ),
        );
    }
    let full = f.clone(); // 32: manager plus two descendants
    f.push(1, revoke(1, 2, 2, None));
    assert!(f.state().active_device(&id(3)).is_none());
    assert!(f.state().active_device(&id(4)).is_none());
    f.register(1, 5, &[1]); // only the manager's slot was freed
    denied(
        &f,
        1,
        device_grant(chain(vec![personal(1, 6, &[1], 1, 6)]), None),
        Rule::DeviceBindingLimit,
    );
    let candidate = record(
        full.state(),
        1,
        device_grant(chain(vec![personal(1, 6, &[1], 1, 6)]), None),
    );
    let mut fork = full.records.clone();
    fork.push(f.records[full.records.len()].clone()); // revoke in the other branch
    fork.push(candidate.signed_object().bytes().to_vec());
    assert_eq!(
        validate(&fork).unwrap_err().error,
        Error::AuthorizationFailed(Rule::DeviceBindingLimit)
    );
    f.replay();
}

#[test]
fn transfer_can_exceed_32_but_subsequent_device_grants_count_its_live_bindings() {
    let mut f = Fixture::new();
    f.push(1, grant(10, &[1], &[], None, None));
    for d in 20..52 {
        f.register(10, d, &[1]);
    }
    let certs = chain(vec![personal(10, 2, &[13], 10, 2)]);
    f.push(2, transfer(f.state(), 10, 1, 2, Some(certs)));
    assert_eq!(f.state().devices().count(), 33);
    assert_grants(f.state(), 2, 0);
    let recertify = || device_grant(chain(vec![personal(10, 2, &[13], 10, 3)]), None);
    denied(&f, 10, recertify(), Rule::DeviceBindingLimit);
    f.push(10, revoke(10, 20, 0, None)); // 32 live, re-certification now fits
    f.push(10, recertify());
    denied(
        &f,
        10,
        device_grant(chain(vec![personal(10, 3, &[1], 10, 3)]), None),
        Rule::DeviceBindingLimit,
    );
    f.push(10, revoke(10, 21, 0, None));
    f.register(10, 3, &[1]);
    f.replay();
}

#[test]
fn preemptive_limit_never_blocks_revoking_bound_devices() {
    let mut f = Fixture::new();
    f.register(1, 9, FULL); // active manager
    f.push(
        1,
        device_grant(
            chain(vec![personal(1, 3, &[1], 2, 3), personal(1, 2, FULL, 1, 2)]),
            None,
        ),
    );
    f.register(1, 4, &[1]);
    for (d, kind, scope) in [
        (5, DeviceKind::Service, ResourceId::from_bytes([88; 32])),
        (6, DeviceKind::Pairing, RESOURCE),
    ] {
        let cert =
            DeviceCertificate::sign(payload(1, d, kind, &[1], &[scope], d), &keys(1)).unwrap();
        f.push(1, device_grant(chain(vec![cert]), None));
    }
    for d in 20..84 {
        f.push(1, revoke(1, d, 0, None));
    }
    denied(&f, 1, revoke(1, 84, 0, None), Rule::DeviceRevocationLimit);
    f.push(1, revoke(1, 2, 2, None)); // intermediate-only manager
    assert!(f.state().active_device(&id(3)).is_none());
    f.push(9, revoke(1, 3, 2, None)); // suspended device
    f.push(4, revoke(1, 4, 0, None)); // active self-retirement
    f.push(9, revoke(1, 5, 0, None)); // out-of-scope binding
    f.push(
        9,
        revoke(1, 6, 3, Some(personal(1, 7, &[1], 1, 7).payload_digest())),
    );
    f.push(1, revoke(1, 9, 0, None));
    assert_eq!(f.state().revocations().count(), 70);
    denied(&f, 1, revoke(1, 84, 0, None), Rule::DeviceRevocationLimit);
    denied(&f, 1, revoke(1, 2, 2, None), Rule::DeviceAlreadyRevoked);
    f.replay();
}

#[test]
fn more_than_64_bound_revocations_do_not_spend_preemptive_allowance() {
    let mut f = Fixture::new();
    for d in 2..67 {
        f.register(1, d, &[1]);
        f.push(1, revoke(1, d, 0, None));
    }
    for d in 68..132 {
        f.push(1, revoke(1, d, 0, None));
    }
    assert_eq!(f.state().revocations().count(), 129);
    denied(&f, 1, revoke(1, 132, 0, None), Rule::DeviceRevocationLimit);
    f.register(1, 133, &[1]);
    f.push(1, revoke(1, 133, 0, None));
    f.replay();
}

#[test]
fn foreign_root_binding_releases_every_affected_preemptive_allowance_once() {
    let mut base = Fixture::new();
    for root in [10, 11] {
        base.push(1, grant(root, &[1], &[], None, None));
        for d in 20..84 {
            base.push(root, revoke(root, d, 0, None));
        }
        denied(
            &base,
            root,
            revoke(root, 84, 0, None),
            Rule::DeviceRevocationLimit,
        );
    }
    for via_transfer in [false, true] {
        let mut f = base.clone();
        // E=20 becomes an intermediate binding, still without registration.
        let certs = chain(vec![
            personal(1, 2, &[13], 20, 2),
            personal(1, 20, FULL, 1, 20),
        ]);
        if via_transfer {
            f.push(2, transfer(f.state(), 1, 1, 2, Some(certs)));
        } else {
            f.push(1, device_grant(certs, None));
        }
        assert!(!f.state().device(&id(20)).unwrap().registered);
        for root in [10, 11] {
            f.push(root, revoke(root, 84, 0, None));
        }
        // Registering an already bound intermediate must not release another slot.
        f.push(
            1,
            device_grant(chain(vec![personal(1, 20, FULL, 1, 99)]), None),
        );
        for root in [10, 11] {
            denied(
                &f,
                root,
                revoke(root, 85, 0, None),
                Rule::DeviceRevocationLimit,
            );
            assert!(f.state().revocation(&id(root), &id(20)).is_some());
        }
        assert!(!base.state().bound(&id(20)));
        f.replay();
    }
}

#[test]
fn out_of_scope_leaf_and_intermediate_only_bindings_count_towards_32() {
    let mut f = Fixture::new();
    for d in 20..50 {
        f.register(1, d, &[1]);
    } // 30
    let service = DeviceCertificate::sign(
        payload(
            1,
            3,
            DeviceKind::Service,
            &[1],
            &[ResourceId::from_bytes([88; 32])],
            3,
        ),
        &keys(2),
    )
    .unwrap();
    f.push(
        1,
        device_grant(chain(vec![service, personal(1, 2, FULL, 1, 2)]), None),
    );
    assert_eq!(f.state().devices().count(), 32);
    for d in [2, 3] {
        assert!(!f.state().device(&id(d)).unwrap().registered);
    }
    denied(
        &f,
        1,
        device_grant(chain(vec![personal(1, 4, &[1], 1, 4)]), None),
        Rule::DeviceBindingLimit,
    );
    // An intermediate with no leaf chain can still submit its first registration.
    f.push(
        2,
        device_grant(chain(vec![personal(1, 2, FULL, 1, 2)]), None),
    );
    assert_grants(f.state(), 2, 1);
    f.replay();
}

#[test]
fn eighth_grant_is_allowed_ninth_is_denied_after_repeat_issuer_and_approval() {
    let mut f = Fixture::new();
    f.push(1, grant(10, &[1], &[], None, None));
    for serial in 1..=8 {
        f.push(
            10,
            device_grant(chain(vec![personal(10, 2, &[1], 10, serial)]), None),
        );
        assert_grants(f.state(), 2, serial);
    }
    let ninth = chain(vec![personal(10, 2, &[1], 10, 9)]);
    denied(
        &f,
        10,
        device_grant(ninth.clone(), None),
        Rule::DeviceGrantLimit,
    );
    denied(
        &f,
        10,
        device_grant(chain(vec![personal(10, 2, &[1], 10, 8)]), None),
        Rule::DeviceAlreadyBound,
    );
    denied(
        &f,
        2,
        device_grant(ninth.clone(), None),
        Rule::DeviceGrantIssuer,
    );
    denied(
        &f,
        10,
        device_grant(ninth, Some(9)),
        Rule::DeviceApprovalMismatch,
    );
    assert_grants(&f.states[2], 2, 1);
    let mut replayed = f.records.clone();
    replayed.push(f.records.last().unwrap().clone());
    assert_eq!(validate(&replayed).unwrap().1, f.states);
    f.register(10, 3, &[1]); // same root, separate pair
    f.replay();
}

#[test]
fn fork_competitors_use_the_predecessors_grant_allowance() {
    let mut f = Fixture::new();
    for serial in 1..8 {
        f.push(
            1,
            device_grant(chain(vec![personal(1, 2, &[1], 1, serial)]), None),
        );
    }
    for serial in [8, 9] {
        let candidate = record(
            f.state(),
            1,
            device_grant(chain(vec![personal(1, 2, &[1], 1, serial)]), None),
        );
        f.records.push(candidate.signed_object().bytes().to_vec());
    }
    let (outcome, _) = validate(&f.records).unwrap();
    assert!(matches!(outcome, ChainOutcome::Conflict(_)));
    assert_grants(f.state(), 2, 7);
}

#[test]
fn out_of_scope_grants_also_exhaust_the_pair_allowance() {
    let mut f = Fixture::new();
    for serial in 1..=9 {
        let cert = DeviceCertificate::sign(
            payload(
                1,
                2,
                DeviceKind::Service,
                &[1],
                &[ResourceId::from_bytes([88; 32])],
                serial,
            ),
            &keys(1),
        )
        .unwrap();
        let body = device_grant(chain(vec![cert]), None);
        if serial <= 8 {
            f.push(1, body);
        } else {
            denied(&f, 1, body, Rule::DeviceGrantLimit);
        }
    }
    assert!(!f.state().device(&id(2)).unwrap().registered);
    f.replay();
}

#[test]
fn genesis_and_transfer_bindings_count_but_do_not_consume_device_grants() {
    for via_transfer in [false, true] {
        let certs = chain(vec![
            personal(10, 2, &[13], 3, 2),
            personal(10, 3, FULL, 10, 3),
        ]);
        let mut f = if via_transfer {
            let mut f = Fixture::new();
            f.push(2, transfer(f.state(), 10, 1, 2, Some(certs)));
            f
        } else {
            Fixture::from_genesis(genesis(10, 2, Some(certs)))
        };
        assert_grants(f.state(), 2, 0);
        assert_grants(f.state(), 3, 0);
        for d in 20..50 {
            f.register(10, d, &[1]);
        }
        denied(
            &f,
            10,
            device_grant(chain(vec![personal(10, 4, &[1], 10, 4)]), None),
            Rule::DeviceBindingLimit,
        );
        for serial in 10..18 {
            f.push(
                10,
                device_grant(chain(vec![personal(10, 2, &[13], 10, serial)]), None),
            );
        }
        assert_grants(f.state(), 2, 8);
        // Transfer re-certification neither spends nor resets the grant count.
        let certs = chain(vec![personal(10, 2, &[13], 10, 30)]);
        f.push(2, transfer(f.state(), 10, 10, 2, Some(certs)));
        assert_grants(f.state(), 2, 8);
        denied(
            &f,
            10,
            device_grant(chain(vec![personal(10, 2, &[13], 10, 31)]), None),
            Rule::DeviceGrantLimit,
        );
        f.replay();
    }
}

#[test]
fn revocation_limit_counts_unbound_pairs_and_survives_resume() {
    let mut f = Fixture::new();
    f.push(1, grant(10, &[1], &[], None, None));
    for d in 20..84 {
        f.push(10, revoke(10, d, 0, None));
    }
    assert_eq!(f.state().revocations().count(), 64);
    assert_eq!(f.state().devices().count(), 0);
    denied(&f, 10, revoke(10, 84, 0, None), Rule::DeviceRevocationLimit);
    // Owner expulsion has the same limit. Duplicate and issuer checks stay first.
    denied(&f, 1, revoke(10, 84, 0, None), Rule::DeviceRevocationLimit);
    denied(&f, 10, revoke(10, 20, 0, None), Rule::DeviceAlreadyRevoked);
    f.push(1, grant(9, &[1], &[], None, None));
    denied(&f, 9, revoke(10, 84, 0, None), Rule::DeviceRevokeIssuer);
    f.push(1, revoke(1, 20, 0, None)); // same device, different root
    assert_eq!(f.state().revocations().count(), 65);
    assert_eq!(f.states[2].revocations().count(), 1);
    f.replay();
}

#[test]
fn first_self_registration_only_even_for_active_managing_and_owner_devices() {
    for mask in [&[1][..], &[1, 2, 12][..], &[13][..], FULL] {
        let mut f = Fixture::new();
        let first = chain(vec![personal(1, 2, mask, 1, 2)]);
        f.push(2, device_grant(first.clone(), None));
        let second = chain(vec![personal(1, 2, mask, 1, 3)]);
        denied(
            &f,
            2,
            device_grant(second.clone(), None),
            Rule::DeviceGrantIssuer,
        );
        f.push(1, device_grant(second, None));
        // A different, previously used certificate is not a first registration.
        denied(&f, 2, device_grant(first, None), Rule::DeviceGrantIssuer);
        f.replay();
    }
}

#[test]
fn suspended_device_cannot_restore_old_path_but_root_or_active_manager_can() {
    let mut f = Fixture::new();
    let old = chain(vec![personal(1, 3, &[1], 1, 3)]);
    f.push(3, device_grant(old.clone(), None));
    f.push(
        1,
        device_grant(
            chain(vec![personal(1, 3, &[1], 2, 4), personal(1, 2, FULL, 1, 2)]),
            None,
        ),
    );
    f.push(1, revoke(1, 2, 2, None));
    assert!(f.state().active_device(&id(3)).is_none());
    denied(
        &f,
        3,
        device_grant(old.clone(), None),
        Rule::DeviceGrantIssuer,
    );
    f.register(1, 4, &[1, 2, 12]);
    for signer in [1, 4] {
        let restored = f.propose(signer, device_grant(old.clone(), None)).unwrap();
        assert!(restored.active_device(&id(3)).is_some());
        assert!(restored.revocation(&id(1), &id(2)).is_some());
    }
    f.push(4, device_grant(old, None));
    f.replay();
}
