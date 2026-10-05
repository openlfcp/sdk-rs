//! Authority on LFCP-TEST-VECTORS-01: the chain C0–C6 with the capability
//! engine, the authority matrix at C3–C6, Key Packages under §25.2 and
//! Data Units under §26.3; then synthetic negatives built from fixture
//! keys on top of the published chain (not spec vectors).
//!
//! Every assertion names its case.

mod support;

use std::collections::{BTreeMap, BTreeSet};

use lfcp::base::{AuthorityRule, ControlRecordId, Error, Hash32};
use lfcp::cbor;
use lfcp::cose;
use lfcp::principal::PrincipalKeys;
use lfcp::wire::control::authority::{
    abilities_at, data_unit_policy, key_package_policy, propose_transition, state_at,
    validate_authorized, ControlState,
};
use lfcp::wire::control::body::{
    CapabilityClaimBody, CapabilityGrantBody, CapabilityRevokeBody, ControlBody, KeyEpochBody,
    OwnerTransferAccept, OwnerTransferCommitBody, OwnerTransferOffer, ResourceTombstoneBody,
    RouteUpdateBody,
};
use lfcp::wire::control::chain::ChainOutcome;
use lfcp::wire::control::{ControlRecord, ControlRecordHeader};
use lfcp::wire::data_unit::ReceivedDataUnit;
use lfcp::wire::key_package::ReceivedKeyPackage;
use support::vectors::{hex, principal_by_id, Suite};

const CHAIN: [&str; 7] = [
    "C0_genesis",
    "C1_grant_bob",
    "C2_invite_grant",
    "C3_invite_claim_carol",
    "C4_owner_transfer_commit",
    "C5_route_update",
    "C6_key_epoch_1",
];

struct Fixture {
    suite: Suite,
    principals: BTreeMap<String, PrincipalKeys>,
    history: Vec<ControlState>,
}

impl Fixture {
    fn load() -> Fixture {
        let suite = Suite::load();
        let principals = suite.principals();
        let bytes: Vec<Vec<u8>> = CHAIN.iter().map(|id| record_bytes(&suite, id)).collect();
        let refs: Vec<&[u8]> = bytes.iter().map(Vec::as_slice).collect();
        let (outcome, history) = validate_authorized(&refs, None)
            .unwrap_or_else(|f| panic!("{}: {}", CHAIN[f.index], f.error));
        assert!(matches!(outcome, ChainOutcome::Linear(_)), "C0-C6: linear");
        Fixture {
            suite,
            principals,
            history,
        }
    }

    fn keys(&self, name: &str) -> &PrincipalKeys {
        &self.principals[name]
    }

    fn record_id(&self, case_id: &str) -> ControlRecordId {
        ControlRecordId::from_bytes(
            hex(case_id, &self.suite.case(case_id)["expected"]["record_id"])
                .try_into()
                .unwrap(),
        )
    }

    /// The state after the record `case_id`.
    fn state(&self, case_id: &str) -> &ControlState {
        state_at(&self.history, &self.record_id(case_id)).unwrap()
    }
}

fn record_bytes(suite: &Suite, case_id: &str) -> Vec<u8> {
    hex(case_id, &suite.case(case_id)["expected"]["cose_sign1"])
}

#[test]
fn chain_validates_with_authority() {
    let f = Fixture::load();
    assert_eq!(f.history.len(), 7, "C0-C6: states");
    let owner_id = |name: &str| *f.keys(name).descriptor().id();
    for (i, case_id) in CHAIN.iter().enumerate() {
        let expected_owner = if i < 4 { "OWNER" } else { "BOB" };
        assert_eq!(
            f.history[i].owner.id(),
            &owner_id(expected_owner),
            "{case_id}: owner"
        );
        assert_eq!(
            f.history[i].head.id,
            f.record_id(case_id),
            "{case_id}: head"
        );
    }
    let c6 = f.state("C6_key_epoch_1");
    assert_eq!(c6.route_version, 1, "C5_route_update: route version");
    let commitment = |name: &str| {
        Hash32::from_bytes(
            hex(
                "dek_commitments",
                &f.suite.case("dek_commitments")["expected"][name],
            )
            .try_into()
            .unwrap(),
        )
    };
    assert_eq!(
        c6.dek_commitments,
        BTreeMap::from([
            (0, commitment("dek0_commitment")),
            (1, commitment("dek1_commitment"))
        ]),
        "C6_key_epoch_1: commitments"
    );
    let invite = c6.grant(&f.record_id("C2_invite_grant")).unwrap();
    assert_eq!(
        (invite.claims_used, invite.claim_limit),
        (1, Some(1)),
        "C3: claim consumed"
    );
}

#[test]
fn control_fork_c6_stays_a_conflict() {
    let f = Fixture::load();
    let case_id = "control_fork_C6";
    let mut bytes: Vec<Vec<u8>> = CHAIN.iter().map(|id| record_bytes(&f.suite, id)).collect();
    bytes.push(hex(case_id, &f.suite.case(case_id)["inputs"]["cose_sign1"]));
    let refs: Vec<&[u8]> = bytes.iter().map(Vec::as_slice).collect();
    let (outcome, history) = validate_authorized(&refs, None).unwrap();
    assert_eq!(outcome.error(), Some(Error::ControlConflict), "{case_id}");
    assert_eq!(history.len(), 7, "{case_id}: the fork never becomes a head");
}

/// Each Principal's abilities at one head.
type MatrixRow = [(&'static str, BTreeSet<u64>); 4];

#[test]
fn authority_matrix_at_c3_to_c6() {
    let f = Fixture::load();
    let all: BTreeSet<u64> = (1..=11).collect();
    let set = |codes: &[u64]| codes.iter().copied().collect::<BTreeSet<u64>>();
    let expected: [(&str, MatrixRow); 4] = [
        (
            "C3_invite_claim_carol",
            [
                ("OWNER", all.clone()),
                ("BOB", set(&[1, 2, 3])),
                ("INVITE", set(&[1, 2, 11])),
                ("CAROL", set(&[1, 2])),
            ],
        ),
        (
            "C4_owner_transfer_commit",
            [
                ("OWNER", set(&[])),
                ("BOB", all.clone()),
                ("INVITE", set(&[1, 2, 11])),
                ("CAROL", set(&[1, 2])),
            ],
        ),
        (
            "C5_route_update",
            [
                ("OWNER", set(&[])),
                ("BOB", all.clone()),
                ("INVITE", set(&[1, 2, 11])),
                ("CAROL", set(&[1, 2])),
            ],
        ),
        (
            "C6_key_epoch_1",
            [
                ("OWNER", set(&[])),
                ("BOB", all.clone()),
                ("INVITE", set(&[1, 2, 11])),
                ("CAROL", set(&[1, 2])),
            ],
        ),
    ];
    for (case_id, row) in expected {
        for (name, abilities) in row {
            let held = abilities_at(
                &f.history,
                &f.record_id(case_id),
                f.keys(name).descriptor().id(),
            )
            .unwrap_or_else(|| panic!("{case_id}: head not in history"));
            assert_eq!(held, abilities, "{case_id}: {name}");
        }
    }
}

#[test]
fn key_packages_pass_the_section_25_2_hook() {
    let f = Fixture::load();
    for case_id in ["KP0_bob_epoch0", "KPI_invite_epoch0", "KPC_carol_epoch1"] {
        let bytes = hex(case_id, &f.suite.case(case_id)["expected"]["cose_sign1"]);
        let received = ReceivedKeyPackage::parse(&bytes).unwrap();
        let sender = principal_by_id(&f.principals, case_id, &received.header().sender);
        received
            .verify(sender.descriptor(), key_package_policy(&f.history))
            .unwrap_or_else(|err| panic!("{case_id}: {err}"));
    }
}

#[test]
fn data_units_pass_the_section_26_3_hook() {
    // Every unit's actor may write at its head; D3 is then held back by
    // the C6 cutoff (BOB <= 2), which the epoch tests cover in full.
    let f = Fixture::load();
    for (case_id, expected) in [
        ("D1_bob_epoch0_seq1", Ok(())),
        ("D2_bob_epoch0_seq2", Ok(())),
        (
            "D3_bob_epoch0_seq3_stale",
            Err(Error::StaleDataEpoch(
                lfcp::base::QuarantineReason::BeyondCutoff,
            )),
        ),
        ("D4_carol_epoch1_seq1", Ok(())),
    ] {
        let bytes = hex(case_id, &f.suite.case(case_id)["expected"]["cose_sign1"]);
        let received = ReceivedDataUnit::parse(&bytes).unwrap();
        let actor = principal_by_id(&f.principals, case_id, &received.header().actor);
        let result = received
            .verify_with(actor.descriptor(), data_unit_policy(&f.history))
            .map(|_| ());
        assert_eq!(result, expected, "{case_id}");
    }
}

/// Synthetic records on top of the published chain.
mod synthetic {
    use super::*;

    /// A record continuing `state`, issued and signed by `issuer`.
    fn record(state: &ControlState, issuer: &PrincipalKeys, body: ControlBody) -> Vec<u8> {
        let header = ControlRecordHeader {
            resource_id: state.resource_id,
            sequence: state.head.sequence + 1,
            previous: Some(state.head.id),
            issuer: *issuer.descriptor().id(),
        };
        ControlRecord::sign(header, body, issuer)
            .unwrap()
            .signed_object()
            .bytes()
            .to_vec()
    }

    fn propose(state: &ControlState, bytes: &[u8]) -> Result<ControlState, Error> {
        propose_transition(state, Some(state.head.id), bytes)
    }

    fn denied(result: Result<ControlState, Error>, rule: AuthorityRule, label: &str) {
        let err = result.err().unwrap_or_else(|| panic!("{label}: accepted"));
        assert_eq!(err, Error::AuthorizationFailed(rule), "{label}");
        assert_eq!(
            err.wire_code().unwrap().name(),
            "AUTHORIZATION_FAILED",
            "{label}"
        );
    }

    fn grant(
        subject: &PrincipalKeys,
        abilities: &[u64],
        delegable: &[u64],
        parent: Option<ControlRecordId>,
    ) -> ControlBody {
        ControlBody::CapabilityGrant(CapabilityGrantBody {
            subject: subject.descriptor().clone(),
            abilities: abilities.to_vec(),
            delegable: delegable.to_vec(),
            parent,
            claim_limit: None,
        })
    }

    fn claim(
        invitation: ControlRecordId,
        claimant: &PrincipalKeys,
        abilities: &[u64],
    ) -> ControlBody {
        ControlBody::CapabilityClaim(CapabilityClaimBody {
            invitation_grant: invitation,
            claimant: claimant.descriptor().clone(),
            abilities: abilities.to_vec(),
        })
    }

    /// OWNER grants BOB [read, write, capability/grant] with [read]
    /// delegable on top of C2; returns the state and the grant's ID.
    fn delegating_bob(f: &Fixture) -> (ControlState, ControlRecordId) {
        let c2 = f.state("C2_invite_grant");
        let bytes = record(
            c2,
            f.keys("OWNER"),
            grant(f.keys("BOB"), &[1, 2, 4], &[1], None),
        );
        let state = propose(c2, &bytes).unwrap();
        let id = state.head.id;
        (state, id)
    }

    #[test]
    fn delegation_without_escalation() {
        let f = Fixture::load();
        let (state, parent) = delegating_bob(&f);
        let (bob, carol) = (f.keys("BOB"), f.keys("CAROL"));
        let ok = propose(
            &state,
            &record(&state, bob, grant(carol, &[1], &[], Some(parent))),
        );
        assert!(ok.is_ok(), "delegated read: {ok:?}");
        denied(
            propose(
                &state,
                &record(&state, bob, grant(carol, &[2], &[], Some(parent))),
            ),
            AuthorityRule::Escalation,
            "escalation to write",
        );
        denied(
            propose(
                &state,
                &record(&state, bob, grant(carol, &[1], &[2], Some(parent))),
            ),
            AuthorityRule::DelegableEscalation,
            "delegable escalation",
        );
        denied(
            propose(&state, &record(&state, bob, grant(carol, &[1], &[], None))),
            AuthorityRule::NotOwner,
            "non-owner grant without parent",
        );
        let c2 = f.state("C2_invite_grant");
        denied(
            propose(
                c2,
                &record(
                    c2,
                    bob,
                    grant(carol, &[1], &[], Some(f.record_id("C1_grant_bob"))),
                ),
            ),
            AuthorityRule::MissingAbility(4),
            "grant without capability/grant",
        );
    }

    #[test]
    fn revoked_parent_and_cascade() {
        let f = Fixture::load();
        let (state, parent) = delegating_bob(&f);
        let (owner, bob, carol) = (f.keys("OWNER"), f.keys("BOB"), f.keys("CAROL"));
        let with_child = propose(
            &state,
            &record(&state, bob, grant(carol, &[1], &[], Some(parent))),
        )
        .unwrap();
        assert!(
            with_child.holds(carol.descriptor().id(), 1),
            "child grant active"
        );

        let revoke = ControlBody::CapabilityRevoke(CapabilityRevokeBody { grant: parent });
        let revoked = propose(&with_child, &record(&with_child, owner, revoke)).unwrap();
        assert!(
            !revoked.holds(carol.descriptor().id(), 1),
            "cascade: child inactive"
        );
        assert!(!revoked.holds(bob.descriptor().id(), 4), "parent inactive");
        denied(
            propose(
                &revoked,
                &record(&revoked, bob, grant(carol, &[1], &[], Some(parent))),
            ),
            AuthorityRule::MissingAbility(4),
            "revoked parent: BOB lost capability/grant",
        );
    }

    #[test]
    fn revoke_authority() {
        let f = Fixture::load();
        let c3 = f.state("C3_invite_claim_carol");
        let (owner, bob, carol) = (f.keys("OWNER"), f.keys("BOB"), f.keys("CAROL"));
        let revoke_c1 = ControlBody::CapabilityRevoke(CapabilityRevokeBody {
            grant: f.record_id("C1_grant_bob"),
        });
        denied(
            propose(c3, &record(c3, carol, revoke_c1.clone())),
            AuthorityRule::MissingAbility(5),
            "revoke without capability/revoke",
        );
        // BOB may revoke, but not grants he did not issue.
        let with_revoke = propose(c3, &record(c3, owner, grant(bob, &[5], &[], None))).unwrap();
        let revoke_c2 = ControlBody::CapabilityRevoke(CapabilityRevokeBody {
            grant: f.record_id("C2_invite_grant"),
        });
        denied(
            propose(&with_revoke, &record(&with_revoke, bob, revoke_c2)),
            AuthorityRule::RevokeNotCovered,
            "revoke not covered",
        );
        let unknown = ControlBody::CapabilityRevoke(CapabilityRevokeBody {
            grant: ControlRecordId::from_bytes([7; 32]),
        });
        denied(
            propose(c3, &record(c3, owner, unknown)),
            AuthorityRule::RevokeTargetUnknown,
            "revoke of an unknown grant",
        );
    }

    #[test]
    fn claim_rules() {
        let f = Fixture::load();
        let c2 = f.state("C2_invite_grant");
        let invitation = f.record_id("C2_invite_grant");
        let (invite, bob, carol) = (f.keys("INVITE"), f.keys("BOB"), f.keys("CAROL"));
        denied(
            propose(c2, &record(c2, bob, claim(invitation, carol, &[1, 2]))),
            AuthorityRule::ClaimIssuerNotInvitation,
            "wrong claim issuer",
        );
        denied(
            propose(
                c2,
                &record(c2, invite, claim(invitation, carol, &[1, 2, 11])),
            ),
            AuthorityRule::ClaimAbilitiesExceed,
            "claiming invite/claim",
        );
        denied(
            propose(c2, &record(c2, invite, claim(invitation, carol, &[3]))),
            AuthorityRule::ClaimAbilitiesExceed,
            "claiming snapshot/publish",
        );
        let c3 = f.state("C3_invite_claim_carol");
        denied(
            propose(c3, &record(c3, invite, claim(invitation, bob, &[1]))),
            AuthorityRule::ClaimLimitExhausted,
            "claim limit exceeded",
        );
    }

    #[test]
    fn double_claim_from_the_same_head_is_serialized() {
        let f = Fixture::load();
        let c2 = f.state("C2_invite_grant");
        let invitation = f.record_id("C2_invite_grant");
        let (invite, bob, carol) = (f.keys("INVITE"), f.keys("BOB"), f.keys("CAROL"));
        let first = record(c2, invite, claim(invitation, carol, &[1, 2]));
        let second = record(c2, invite, claim(invitation, bob, &[1]));

        let after_first = propose(c2, &first).unwrap();
        // The second was made at C2; the coordinator's head has moved.
        assert_eq!(
            propose_transition(&after_first, Some(c2.head.id), &second),
            Err(Error::ControlHeadMismatch {
                current: Some(after_first.head.id)
            }),
            "second claim at a stale head"
        );
        // Re-made at the new head, the invitation has no claim left.
        denied(
            propose(
                &after_first,
                &record(&after_first, invite, claim(invitation, bob, &[1])),
            ),
            AuthorityRule::ClaimLimitExhausted,
            "second claim re-made",
        );
        // Order decides: had the second come first, it would have won.
        assert!(propose(c2, &second).is_ok(), "either claim alone is valid");
    }

    /// A Transfer Commit body built from its parts.
    struct Transfer<'a> {
        offer_signer: &'a PrincipalKeys,
        head: Hash32,
        next_sequence: u64,
        new_owner: &'a PrincipalKeys,
        accept_signer: &'a PrincipalKeys,
    }

    impl Transfer<'_> {
        fn body(&self, state: &ControlState) -> ControlBody {
            let offer = OwnerTransferOffer {
                resource_id: state.resource_id,
                control_head: self.head,
                next_sequence: self.next_sequence,
                new_owner: self.new_owner.descriptor().clone(),
                nonce: [9; 16],
            };
            let offer =
                cose::sign(&cbor::encode(&offer.to_value()).unwrap(), self.offer_signer).unwrap();
            let accept = OwnerTransferAccept {
                resource_id: state.resource_id,
                offer: *offer.id(),
                new_owner: *self.accept_signer.descriptor().id(),
            };
            let accept = cose::sign(
                &cbor::encode(&accept.to_value()).unwrap(),
                self.accept_signer,
            )
            .unwrap();
            ControlBody::OwnerTransferCommit(OwnerTransferCommitBody {
                offer: offer.bytes().to_vec(),
                accept: accept.bytes().to_vec(),
            })
        }
    }

    #[test]
    fn ownership_transfer_rules() {
        let f = Fixture::load();
        let c3 = f.state("C3_invite_claim_carol");
        let (owner, bob, carol) = (f.keys("OWNER"), f.keys("BOB"), f.keys("CAROL"));
        let head = Hash32::from_bytes(*c3.head.id.as_bytes());
        let good = Transfer {
            offer_signer: owner,
            head,
            next_sequence: 4,
            new_owner: carol,
            accept_signer: carol,
        };
        let accepted = propose(c3, &record(c3, carol, good.body(c3))).unwrap();
        assert_eq!(
            accepted.owner.id(),
            carol.descriptor().id(),
            "transfer to CAROL"
        );

        let cases: [(&str, Transfer, &PrincipalKeys, AuthorityRule); 5] = [
            (
                "offer by a non-owner",
                Transfer {
                    offer_signer: bob,
                    ..good
                },
                carol,
                AuthorityRule::TransferOfferNotByOwner,
            ),
            (
                "stale offer head",
                Transfer {
                    head: Hash32::from_bytes(*f.record_id("C2_invite_grant").as_bytes()),
                    ..good
                },
                carol,
                AuthorityRule::TransferOfferStaleHead,
            ),
            (
                "wrong acceptor",
                Transfer {
                    accept_signer: bob,
                    ..good
                },
                carol,
                AuthorityRule::TransferAcceptorMismatch,
            ),
            (
                "wrong expected sequence",
                Transfer {
                    next_sequence: 5,
                    ..good
                },
                carol,
                AuthorityRule::TransferSequenceMismatch,
            ),
            (
                "commit by another Principal",
                good,
                bob,
                AuthorityRule::TransferCommitIssuer,
            ),
        ];
        for (label, transfer, committer, rule) in cases {
            denied(
                propose(c3, &record(c3, committer, transfer.body(c3))),
                rule,
                label,
            );
        }
    }

    #[test]
    fn other_record_rules() {
        let f = Fixture::load();
        let c5 = f.state("C5_route_update");
        let (bob, carol) = (f.keys("BOB"), f.keys("CAROL"));
        let route = |version| {
            ControlBody::RouteUpdate(RouteUpdateBody {
                version,
                endpoints: vec![lfcp::wire::control::body::Endpoint {
                    url: "wss://sync-c.example.test/v1/ws".into(),
                    priority: 0,
                    flags: None,
                }],
                coordinator: "wss://sync-c.example.test/v1/ws".into(),
            })
        };
        denied(
            propose(c5, &record(c5, bob, route(1))),
            AuthorityRule::RouteVersionNotIncreasing,
            "route version not increasing",
        );
        assert!(
            propose(c5, &record(c5, bob, route(2))).is_ok(),
            "route version 2"
        );
        denied(
            propose(c5, &record(c5, carol, route(2))),
            AuthorityRule::MissingAbility(8),
            "route update without route/update",
        );
        let epoch = ControlBody::KeyEpoch(KeyEpochBody {
            epoch: 1,
            dek_commitment: Hash32::from_bytes([1; 32]),
            final_frontier: lfcp::wire::frontier::Frontier::new(vec![]).unwrap(),
            reason: 0,
        });
        denied(
            propose(c5, &record(c5, carol, epoch)),
            AuthorityRule::MissingAbility(7),
            "key epoch without key/rotate",
        );
        let tombstone = ControlBody::ResourceTombstone(ResourceTombstoneBody {
            reason: 0,
            note: None,
        });
        let err = propose(c5, &record(c5, bob, tombstone)).unwrap_err();
        assert_eq!(err, Error::UnsupportedInMvp(8), "tombstone");
        assert_eq!(
            err.wire_code().unwrap().name(),
            "PROTOCOL_UNSUPPORTED",
            "tombstone"
        );
    }
}
