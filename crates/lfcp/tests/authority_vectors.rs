//! Authority on LFCP-TEST-VECTORS-01: the chain C0–C10 with the capability
//! engine, the authority matrix at C3–C10, Key Packages under §25.2, Data
//! Units under §26.3, and every Control Record negative of the suite
//! except control_fork_C6 (`control_plane_vectors.rs`); then synthetic
//! negatives built from fixture keys on top of the published chain (not
//! spec vectors).
//!
//! Every assertion names its case.

mod support;

use std::collections::{BTreeMap, BTreeSet};

use lfcp::base::{AuthorityRule, ControlRecordId, Error, Hash32};
use lfcp::cbor;
use lfcp::cose;
use lfcp::principal::{PrincipalDescriptor, PrincipalKeys};
use lfcp::wire::control::authority::{
    abilities_at, data_unit_policy, key_package_policy, propose_transition, state_at,
    validate_authorized, validate_authorized_with, ControlState,
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

const CHAIN: [&str; 11] = [
    "C0_genesis",
    "C1_grant_bob",
    "C2_invite_grant",
    "C3_invite_claim_carol",
    "C4_owner_transfer_commit",
    "C5_route_update",
    "C6_key_epoch_1",
    "C7_grant_carol_delegator",
    "C8_grant_owner_delegated",
    "C9_grant_invite_grandchild",
    "C10_revoke_grandchild",
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
        assert!(matches!(outcome, ChainOutcome::Linear(_)), "C0-C10: linear");
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
    assert_eq!(f.history.len(), 11, "C0-C10: states");
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

    // §17.2, §17.3: C7 lets CAROL delegate; C8 is CAROL's grant to the
    // former owner, C9 its grandchild to INVITE; C10 revokes C9, covered
    // because CAROL issued its parent C8.
    let c9_id = f.record_id("C9_grant_invite_grandchild");
    let c9 = f.state("C9_grant_invite_grandchild");
    let c10 = f.state("C10_revoke_grandchild");
    let c9_grant = c9.grant(&c9_id).unwrap();
    assert_eq!(
        c9_grant.parent,
        Some(f.record_id("C8_grant_owner_delegated")),
        "C9_grant_invite_grandchild: parent"
    );
    assert!(c9.is_active(&c9_id), "C9_grant_invite_grandchild: active");
    assert!(!c10.is_active(&c9_id), "C10_revoke_grandchild: C9 revoked");
    assert!(
        c10.is_active(&f.record_id("C8_grant_owner_delegated")),
        "C10_revoke_grandchild: C8 stays"
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
    assert_eq!(
        history.len(),
        CHAIN.len(),
        "{case_id}: the fork never becomes a head"
    );
    assert!(
        !history.iter().any(|state| state.head.sequence == 6
            && state.head.id != f.record_id("C6_key_epoch_1")),
        "{case_id}: no state at the competing record"
    );
}

/// Each Principal's abilities at one head.
type MatrixRow = [(&'static str, BTreeSet<u64>); 4];

#[test]
fn authority_matrix_at_c3_to_c10() {
    let f = Fixture::load();
    // §17.1: the owner holds every standard ability except the reserved
    // 9, which confers nothing.
    let all: BTreeSet<u64> = (1..=11).filter(|&code| code != 9).collect();
    let set = |codes: &[u64]| codes.iter().copied().collect::<BTreeSet<u64>>();
    let expected: [(&str, MatrixRow); 8] = [
        (
            "C3_invite_claim_carol",
            [
                ("OWNER", all.clone()),
                ("BOB", set(&[1, 2, 3])),
                ("INVITE", set(&[1, 2])),
                ("CAROL", set(&[1, 2])),
            ],
        ),
        (
            "C4_owner_transfer_commit",
            [
                ("OWNER", set(&[])),
                ("BOB", all.clone()),
                ("INVITE", set(&[1, 2])),
                ("CAROL", set(&[1, 2])),
            ],
        ),
        (
            "C5_route_update",
            [
                ("OWNER", set(&[])),
                ("BOB", all.clone()),
                ("INVITE", set(&[1, 2])),
                ("CAROL", set(&[1, 2])),
            ],
        ),
        (
            "C6_key_epoch_1",
            [
                ("OWNER", set(&[])),
                ("BOB", all.clone()),
                ("INVITE", set(&[1, 2])),
                ("CAROL", set(&[1, 2])),
            ],
        ),
        (
            "C7_grant_carol_delegator",
            [
                ("OWNER", set(&[])),
                ("BOB", all.clone()),
                ("INVITE", set(&[1, 2])),
                ("CAROL", set(&[1, 2, 4, 5])),
            ],
        ),
        (
            // §23.3: the former owner has only what a grant gives it.
            "C8_grant_owner_delegated",
            [
                ("OWNER", set(&[1, 4])),
                ("BOB", all.clone()),
                ("INVITE", set(&[1, 2])),
                ("CAROL", set(&[1, 2, 4, 5])),
            ],
        ),
        (
            "C9_grant_invite_grandchild",
            [
                ("OWNER", set(&[1, 4])),
                ("BOB", all.clone()),
                ("INVITE", set(&[1, 2])),
                ("CAROL", set(&[1, 2, 4, 5])),
            ],
        ),
        (
            "C10_revoke_grandchild",
            [
                ("OWNER", set(&[1, 4])),
                ("BOB", all.clone()),
                ("INVITE", set(&[1, 2])),
                ("CAROL", set(&[1, 2, 4, 5])),
            ],
        ),
    ];
    // §18.1: C3 used the single claim of C2, so from C3 on INVITE's grant
    // confers no invite/claim.
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

/// How the suite's Control Record negatives are decided.
enum Outcome {
    /// The candidate fails with this error.
    Rejected(Error),
    /// The candidate competes with an accepted record (§13.2).
    Conflict,
}

/// Every Control Record negative, validated with authority on the
/// published chain up to the record its context names (or on its own),
/// with the outcome this crate decides.
fn control_record_negatives() -> Vec<(&'static str, Outcome)> {
    use lfcp::base::FrontierRule;
    use Outcome::*;
    let denied = |rule| Rejected(Error::AuthorizationFailed(rule));
    vec![
        // §19 (G-CP1).
        (
            "key_epoch_frontier_unsorted",
            Rejected(Error::FrontierNotCanonical(FrontierRule::EntriesUnsorted)),
        ),
        (
            "key_epoch_frontier_duplicate",
            Rejected(Error::FrontierNotCanonical(
                FrontierRule::DuplicatePrincipal,
            )),
        ),
        // §17.1 (G-CP6).
        (
            "grant_duplicate_ability_C1",
            Rejected(Error::ControlRecordMalformed),
        ),
        // §17.2 (G-CAP4): C8 delegates only read.
        ("grant_escalation_C9", denied(AuthorityRule::Escalation)),
        // §17.3 (DV4): C7 is a grant CAROL received.
        (
            "revoke_received_grant",
            denied(AuthorityRule::RevokeNotCovered),
        ),
        // §17.3 (DV3).
        (
            "revoke_already_revoked",
            denied(AuthorityRule::RevokeAlreadyRevoked),
        ),
        // §17.3 rule 1 (CODE-REVOKE): a target that names no grant.
        (
            "revoke_unknown_grant",
            denied(AuthorityRule::RevokeTargetUnknown),
        ),
        // §20 (CODE): route version 0 does not advance past Genesis.
        (
            "route_version_not_increasing_C5",
            denied(AuthorityRule::RouteVersionNotIncreasing),
        ),
        // §15 (S2).
        ("genesis_signer_not_owner", Rejected(Error::CoseKidMismatch)),
        // §13.2 (G-CP5): a second Genesis is a root fork.
        ("genesis_competing_root", Conflict),
        // §16 (G-CP4).
        (
            "genesis_http_endpoint",
            Rejected(Error::ControlRecordMalformed),
        ),
        // §14 (W1).
        (
            "unknown_core_type_C1",
            Rejected(Error::ControlUnknownCoreType(9)),
        ),
        // §14 (DV2).
        (
            "extension_type_non_owner_C1",
            denied(AuthorityRule::NotOwner),
        ),
    ]
}

#[test]
fn control_record_negatives_are_rejected() {
    let f = Fixture::load();
    for (case_id, outcome) in control_record_negatives() {
        let case = f.suite.case(case_id);
        let candidate = hex(case_id, &case["inputs"]["cose_sign1"]);
        let context = &case["context"];
        // The chain the candidate is offered on: up to its previous record,
        // up to Genesis for a competing root, or nothing for a Genesis.
        let last = context["previous_record"]["case"]
            .as_str()
            .or(context["competing_record"]["case"].as_str());
        let prefix: Vec<Vec<u8>> = match last {
            Some(last) => {
                let n = CHAIN.iter().position(|id| *id == last).unwrap() + 1;
                CHAIN[..n]
                    .iter()
                    .map(|id| record_bytes(&f.suite, id))
                    .collect()
            }
            None => Vec::new(),
        };
        let mut records: Vec<&[u8]> = prefix.iter().map(Vec::as_slice).collect();
        records.push(&candidate);
        // An issuer the chain does not describe yet comes with the case's
        // context (C1-CONTEXT): descriptors are self-certifying, so a
        // receiver may learn them from anywhere (§13.1, §10.5); without one
        // it is MISSING_DEPENDENCY.
        let known: Vec<PrincipalDescriptor> = match context["issuer_descriptor"]["case"].as_str() {
            Some(principal_case) => {
                let field = &f.suite.case(principal_case)["expected"]["descriptor_cbor"];
                vec![PrincipalDescriptor::decode(&hex(principal_case, field)).unwrap()]
            }
            None => Vec::new(),
        };
        let result = validate_authorized_with(&records, None, &known);

        let expected = &case["expected"];
        assert_eq!(expected["valid"], false, "{case_id}");
        let error = match (outcome, result) {
            (Outcome::Rejected(error), Err(failure)) => {
                assert_eq!(
                    failure.index,
                    prefix.len(),
                    "{case_id}: the candidate fails"
                );
                assert_eq!(failure.error, error, "{case_id}");
                assert_eq!(expected["disposition"], "reject", "{case_id}");
                error
            }
            (Outcome::Conflict, Ok((outcome, _))) => {
                let error = outcome.error().expect("no conflict");
                assert_eq!(expected["disposition"], "conflict", "{case_id}");
                error
            }
            (_, other) => panic!("{case_id}: unexpected {other:?}"),
        };
        // Every negative names its code at baseline.4 (§62 general rule).
        let code = expected["error"]["code"]
            .as_str()
            .unwrap_or_else(|| panic!("{case_id}: no code"));
        assert_eq!(
            error.wire_code().map(|c| c.name()),
            Some(code),
            "{case_id}: code for {error:?}"
        );
    }
}

/// The Control Record negatives this file decides.
pub const CONTROL_RECORD_NEGATIVES: [&str; 13] = [
    "key_epoch_frontier_unsorted",
    "key_epoch_frontier_duplicate",
    "grant_duplicate_ability_C1",
    "grant_escalation_C9",
    "revoke_received_grant",
    "revoke_already_revoked",
    "revoke_unknown_grant",
    "route_version_not_increasing_C5",
    "genesis_signer_not_owner",
    "genesis_competing_root",
    "genesis_http_endpoint",
    "unknown_core_type_C1",
    "extension_type_non_owner_C1",
];

#[test]
fn an_issuer_the_chain_does_not_describe_is_a_missing_dependency() {
    // §13.1 (G-CP3): extension_type_non_owner_C1 is issued by BOB right
    // after Genesis, before any record describes BOB. Without an outside
    // descriptor the receiver cannot check the signature.
    let f = Fixture::load();
    let case_id = "extension_type_non_owner_C1";
    let candidate = hex(case_id, &f.suite.case(case_id)["inputs"]["cose_sign1"]);
    let c0 = record_bytes(&f.suite, "C0_genesis");
    let failure = validate_authorized(&[&c0, &candidate], None).unwrap_err();
    assert_eq!(
        (failure.index, &failure.error),
        (1, &Error::IssuerUnknown(*f.keys("BOB").descriptor().id())),
        "{case_id}"
    );
    assert_eq!(
        failure.error.wire_code().unwrap().name(),
        "MISSING_DEPENDENCY",
        "{case_id}"
    );
}

#[test]
fn the_negatives_table_is_complete() {
    let ids: Vec<&str> = control_record_negatives()
        .iter()
        .map(|(id, _)| *id)
        .collect();
    assert_eq!(ids, CONTROL_RECORD_NEGATIVES);
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
        propose_transition(state, state.head.id, bytes)
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
    fn revoking_a_revoked_grant_fails() {
        // §17.3 (DV3): the second revoke of C1 is AUTHORIZATION_FAILED,
        // also for the owner, who may revoke any grant.
        let f = Fixture::load();
        let c3 = f.state("C3_invite_claim_carol");
        let owner = f.keys("OWNER");
        let revoke_c1 = ControlBody::CapabilityRevoke(CapabilityRevokeBody {
            grant: f.record_id("C1_grant_bob"),
        });
        let revoked = propose(c3, &record(c3, owner, revoke_c1.clone())).unwrap();
        assert!(!revoked.is_active(&f.record_id("C1_grant_bob")));
        denied(
            propose(&revoked, &record(&revoked, owner, revoke_c1)),
            AuthorityRule::RevokeAlreadyRevoked,
            "second revoke",
        );
    }

    #[test]
    fn invitation_grants_need_a_claim_limit_and_lose_invite_claim_when_used_up() {
        let f = Fixture::load();
        let c2 = f.state("C2_invite_grant");
        let (owner, invite, carol) = (f.keys("OWNER"), f.keys("INVITE"), f.keys("CAROL"));
        // §18: an invitation grant without claim_limit is not claimable.
        let unlimited =
            propose(c2, &record(c2, owner, grant(invite, &[1, 11], &[], None))).unwrap();
        let unlimited_id = unlimited.head.id;
        denied(
            propose(
                &unlimited,
                &record(&unlimited, invite, claim(unlimited_id, carol, &[1])),
            ),
            AuthorityRule::ClaimNotClaimable,
            "claim on a grant without claim_limit",
        );
        // §18 (INVITE): not being claimable affects claims only; the grant
        // still confers invite/claim, so its subject qualifies for the
        // §25.2 Key Package exception.
        let unlimited_grant = unlimited.grant(&unlimited_id).unwrap();
        assert!(unlimited.confers_invite(unlimited_grant));

        // §18.1: C2 confers invite/claim until its one claim is used (C3).
        let c3 = f.state("C3_invite_claim_carol");
        let invitation = f.record_id("C2_invite_grant");
        let invite_id = invite.descriptor().id();
        assert!(c2.holds(invite_id, 11), "C2: invite/claim");
        assert!(!c3.holds(invite_id, 11), "C3: claims used up");
        assert!(c3.holds(invite_id, 1), "C3: other abilities stay");
        let grant_c2 = c3.grant(&invitation).unwrap();
        assert!(c3.is_active(&invitation) && !c3.confers_invite(grant_c2));

        // §25.2 (G-CAP9): the invitation exception ends with it. INVITE
        // holds data/read anyway, so test a recipient without it.
        let only_invite = propose(c2, &record(c2, owner, grant(carol, &[11], &[], None))).unwrap();
        let distribute = |state: &ControlState| {
            lfcp::wire::control::authority::can_distribute_key(
                state,
                owner.descriptor().id(),
                carol.descriptor().id(),
            )
        };
        assert_eq!(
            distribute(&only_invite),
            Ok(()),
            "subject of an active grant conferring invite/claim"
        );
        // claim_limit 0: used up from the start, so no invite/claim.
        let exhausted = ControlBody::CapabilityGrant(CapabilityGrantBody {
            subject: carol.descriptor().clone(),
            abilities: vec![11],
            delegable: vec![],
            parent: None,
            claim_limit: Some(0),
        });
        let exhausted = propose(c2, &record(c2, owner, exhausted)).unwrap();
        assert_eq!(
            distribute(&exhausted),
            Err(Error::AuthorizationFailed(AuthorityRule::MissingAbility(1))),
            "used-up invitation grant"
        );
    }

    #[test]
    fn ability_9_and_unknown_codes_confer_nothing() {
        // §17.1, §23.1: a grant of 9 or of an unknown code is kept as
        // written and confers nothing.
        let f = Fixture::load();
        let c2 = f.state("C2_invite_grant");
        let carol = f.keys("CAROL");
        let state = propose(
            c2,
            &record(c2, f.keys("OWNER"), grant(carol, &[9, 200], &[], None)),
        )
        .unwrap();
        assert_eq!(state.grant(&state.head.id).unwrap().abilities, vec![9, 200]);
        assert!(state.abilities(carol.descriptor().id()).is_empty());
        assert!(!state.holds(f.keys("OWNER").descriptor().id(), 9));
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
            propose_transition(&after_first, c2.head.id, &second),
            Err(Error::ControlHeadMismatch {
                current: after_first.head.id
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
