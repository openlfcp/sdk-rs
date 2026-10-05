//! The capability engine: Control state derived from a chain, and the
//! authority each record, Key Package and Data Unit needs (LFCP-WIRE-01
//! §17–§26).
//!
//! | Record or object | Required authority | § |
//! | --- | --- | --- |
//! | Genesis | self-signed by the owner in its body (chain rule) | §15 |
//! | Capability Grant, no parent | owner; a non-owner cannot prove authority without a parent | §17.2 |
//! | Capability Grant, with parent | parent exists and is active; issuer is its subject; abilities ⊆ parent delegable; delegable ⊆ parent delegable; a non-owner also holds `capability/grant` | §17.2 |
//! | Capability Revoke | owner, or `capability/revoke` covering the grant (issued by the revoker or delegated from a grant it issued); the grant is not already revoked | §17.3 |
//! | Capability Claim | §18.1 rules 1–5: invitation grant active, grants `invite/claim`, has a `claim_limit` with claims remaining, abilities ⊆ invitation abilities (minus `invite/claim` unless delegable), issuer is the Invitation Principal; consumes one claim | §18, §18.1 |
//! | Key Epoch | `key/rotate`; new epoch = current + 1; closes the current epoch with its final frontier | §19 |
//! | Route Update | `route/update`; route version strictly above the current one (0 after Genesis) | §15, §20 |
//! | Owner Transfer Commit | §23.3 rules 1–6 and §23.2: offer by the current owner at the current head, accept by the named Principal for this offer, commit by that Principal at the offered sequence | §23 |
//! | Coordinator Recovery, Resource Tombstone | refused: not applied in MVP 0.1 | §22, §24, MVP-SCOPE §4 |
//! | extension type | owner only | §14 |
//! | Key Package | epoch known, sender holds `key/distribute`, recipient holds `data/read` or is the subject of an active grant that includes and still confers `invite/claim`, at the package's Control Head | §25.2, §19 |
//! | Data Unit | actor holds `data/write` at the unit's Control Head; epoch per [`super::epoch`] | §26.3 |
//! | Snapshot | epoch known and publisher holds `snapshot/publish` at its Control Head | §29, §29.2 |
//!
//! The owner implicitly holds every standard ability (§15, §17.1); ability
//! 9 is reserved and confers nothing, and unknown codes confer nothing
//! (§17.1). A grant is active while it is not revoked and, when it has a
//! parent, while the parent is active (§17.2). An invitation grant whose
//! claims are used up confers no `invite/claim` (§18.1). After an
//! ownership transfer the former owner keeps no implicit authority, and
//! the grants it issued stay active (§23.3).
//!
//! Unauthorized records are `AUTHORIZATION_FAILED`: §14 (a non-owner
//! extension record), §17.2 (grant rules, escalation), §17.3 (revocation,
//! in order: target exists, authority covers it, not already revoked),
//! §20 (route update ability and version), §23.3 (transfers) and the §62
//! general rule for authority failures.
//!
//! [`CapabilityEngine`] is the [`ChainPolicy`] for full validation: it
//! derives a [`ControlState`] after every accepted record, so authority can
//! be evaluated at any historical head ([`state_at`], [`abilities_at`]).

use std::collections::{BTreeMap, BTreeSet};

use crate::base::{AuthorityRule, ControlRecordId, Error, Hash32, PrincipalId, ResourceId};
use crate::cose;
use crate::principal::PrincipalDescriptor;
use crate::wire::control::body::{CapabilityGrantBody, ControlBody, OwnerTransferCommitBody};
use crate::wire::control::chain::{
    check_expected_head, validate_chain, ChainFailure, ChainHead, ChainOutcome, ChainPolicy,
    ChainStart,
};
use crate::wire::control::ControlRecord;
use crate::wire::data_unit::DataUnitHeader;
use crate::wire::frontier::Frontier;
use crate::wire::key_package::KeyPackageHeader;

/// Standard ability codes (§17.1).
pub mod ability {
    /// `data/read`
    pub const DATA_READ: u64 = 1;
    /// `data/write`
    pub const DATA_WRITE: u64 = 2;
    /// `snapshot/publish`
    pub const SNAPSHOT_PUBLISH: u64 = 3;
    /// `capability/grant`
    pub const CAPABILITY_GRANT: u64 = 4;
    /// `capability/revoke`
    pub const CAPABILITY_REVOKE: u64 = 5;
    /// `key/distribute`
    pub const KEY_DISTRIBUTE: u64 = 6;
    /// `key/rotate`
    pub const KEY_ROTATE: u64 = 7;
    /// `route/update`
    pub const ROUTE_UPDATE: u64 = 8;
    /// `owner/transfer-offer`: reserved, confers nothing in WIRE-01; only
    /// the current owner creates offers (§17.1, §23.1).
    pub const OWNER_TRANSFER_OFFER: u64 = 9;
    /// `resource/tombstone`
    pub const RESOURCE_TOMBSTONE: u64 = 10;
    /// `invite/claim`
    pub const INVITE_CLAIM: u64 = 11;
    /// Every standard ability, as the owner holds them.
    pub const STANDARD: std::ops::RangeInclusive<u64> = 1..=11;

    /// Whether `code` confers anything: a standard ability other than the
    /// reserved `owner/transfer-offer` (§17.1, §23.1).
    pub fn confers(code: u64) -> bool {
        STANDARD.contains(&code) && code != OWNER_TRANSFER_OFFER
    }
}

fn deny(rule: AuthorityRule) -> Error {
    Error::AuthorizationFailed(rule)
}

/// A capability grant, from a Capability Grant record or a successful
/// claim. Its ID is the record ID that created it (§17.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    /// The creating record's ID.
    pub id: ControlRecordId,
    /// Who issued the record.
    pub issuer: PrincipalId,
    /// Who holds the grant.
    pub subject: PrincipalId,
    /// Granted ability codes, as written (unknown codes included).
    pub abilities: Vec<u64>,
    /// Abilities the subject may delegate.
    pub delegable: Vec<u64>,
    /// The parent grant.
    pub parent: Option<ControlRecordId>,
    /// The claim limit, for an invitation grant.
    pub claim_limit: Option<u64>,
    /// Claims consumed so far, in chain order.
    pub claims_used: u64,
    /// Whether a Capability Revoke has named this grant.
    pub revoked: bool,
}

/// The Control state after a record: owner, grants, route and DEK
/// commitments, at one Control Head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlState {
    /// The Resource.
    pub resource_id: ResourceId,
    /// The head this state is at.
    pub head: ChainHead,
    /// The current owner.
    pub owner: PrincipalDescriptor,
    /// The current route version; Genesis is version 0 (§15).
    pub route_version: u64,
    /// DEK commitments by Data Epoch: Genesis for epoch 0, then Key Epochs.
    pub dek_commitments: BTreeMap<u64, Hash32>,
    /// The current Data Epoch: 0 at Genesis, then each Key Epoch's.
    pub current_epoch: u64,
    /// The final frontier of each closed epoch, from the Key Epoch that
    /// closed it (§19, §19.1).
    pub closed_frontiers: BTreeMap<u64, Frontier>,
    grants: BTreeMap<[u8; 32], Grant>,
    principals: BTreeMap<[u8; 32], PrincipalDescriptor>,
}

impl ControlState {
    /// The grant created by `id`.
    pub fn grant(&self, id: &ControlRecordId) -> Option<&Grant> {
        self.grants.get(id.as_bytes())
    }

    /// All grants, in record-ID order.
    pub fn grants(&self) -> impl Iterator<Item = &Grant> {
        self.grants.values()
    }

    /// A Principal descriptor seen in the chain.
    pub fn principal(&self, id: &PrincipalId) -> Option<&PrincipalDescriptor> {
        self.principals.get(id.as_bytes())
    }

    /// Whether `principal` is the current owner.
    pub fn is_owner(&self, principal: &PrincipalId) -> bool {
        self.owner.id() == principal
    }

    /// Whether the grant exists, is not revoked, and its parents are
    /// active.
    pub fn is_active(&self, id: &ControlRecordId) -> bool {
        match self.grant(id) {
            None => false,
            Some(grant) if grant.revoked => false,
            // §17.2: a child grant is active only while its parent is.
            Some(Grant {
                parent: Some(parent),
                ..
            }) => self.is_active(parent),
            Some(_) => true,
        }
    }

    /// The abilities `principal` holds: every conferring standard ability
    /// for the owner, otherwise the union of what its active grants confer.
    pub fn abilities(&self, principal: &PrincipalId) -> BTreeSet<u64> {
        if self.is_owner(principal) {
            return ability::STANDARD.filter(|&c| ability::confers(c)).collect();
        }
        self.grants
            .values()
            .filter(|g| &g.subject == principal && self.is_active(&g.id))
            .flat_map(|g| self.conferred(g))
            .collect()
    }

    /// What one grant confers, active or not: its abilities that confer
    /// anything (§17.1: unknown codes and ability 9 are kept but confer
    /// nothing), without `invite/claim` once its claims are used up
    /// (§18.1).
    pub fn conferred(&self, grant: &Grant) -> BTreeSet<u64> {
        let exhausted = grant
            .claim_limit
            .is_some_and(|limit| grant.claims_used >= limit);
        grant
            .abilities
            .iter()
            .copied()
            .filter(|&code| ability::confers(code))
            .filter(|&code| !(exhausted && code == ability::INVITE_CLAIM))
            .collect()
    }

    /// Whether `grant` is active and still confers `invite/claim`: what
    /// makes its subject an Invitation Principal for §25.2. A grant without
    /// `claim_limit` is not claimable but still confers it (§18, INVITE);
    /// one whose claims are used up does not (§18.1).
    pub fn confers_invite(&self, grant: &Grant) -> bool {
        self.is_active(&grant.id) && self.conferred(grant).contains(&ability::INVITE_CLAIM)
    }

    /// Whether `principal` holds `code`.
    pub fn holds(&self, principal: &PrincipalId, code: u64) -> bool {
        self.abilities(principal).contains(&code)
    }

    fn require(&self, principal: &PrincipalId, code: u64) -> Result<(), Error> {
        if self.holds(principal, code) {
            Ok(())
        } else {
            Err(deny(AuthorityRule::MissingAbility(code)))
        }
    }

    fn learn(&mut self, descriptor: &PrincipalDescriptor) {
        self.principals
            .insert(*descriptor.id().as_bytes(), descriptor.clone());
    }

    /// Whether some ancestor of `grant` (or the grant itself) was issued
    /// by `issuer`.
    fn issued_in_line(&self, grant: &Grant, issuer: &PrincipalId) -> bool {
        let mut current = Some(grant);
        while let Some(g) = current {
            if &g.issuer == issuer {
                return true;
            }
            current = g.parent.as_ref().and_then(|p| self.grant(p));
        }
        false
    }
}

/// The state after `record`, given the state after the previous record
/// (`None` before Genesis). The record's signature and chain placement are
/// already checked; this checks its authority and applies it.
pub fn apply(
    previous: Option<&ControlState>,
    record: &ControlRecord,
) -> Result<ControlState, Error> {
    let header = record.header();
    let head = ChainHead {
        resource_id: header.resource_id,
        id: record.id(),
        sequence: header.sequence,
    };
    let previous = match (previous, record.body()) {
        (None, ControlBody::Genesis(genesis)) => {
            let mut state = ControlState {
                resource_id: header.resource_id,
                head,
                owner: genesis.owner.clone(),
                // §15: Genesis implies route version 0.
                route_version: 0,
                dek_commitments: BTreeMap::from([(0, genesis.dek_commitment)]),
                current_epoch: 0,
                closed_frontiers: BTreeMap::new(),
                grants: BTreeMap::new(),
                principals: BTreeMap::new(),
            };
            state.learn(&genesis.owner);
            return Ok(state);
        }
        (Some(previous), _) => previous,
        // Chain placement rejects these before authority is evaluated.
        (None, _) => {
            return Err(Error::InvalidControlChain(
                crate::base::ChainRule::GenesisMissing,
            ))
        }
    };
    let mut state = previous.clone();
    let issuer = header.issuer;
    let is_owner = state.is_owner(&issuer);

    match record.body() {
        ControlBody::Genesis(_) => {
            return Err(Error::InvalidControlChain(
                crate::base::ChainRule::GenesisNotFirst,
            ))
        }
        ControlBody::CapabilityGrant(grant) => {
            check_grant(&state, &issuer, is_owner, grant)?;
            state.learn(&grant.subject);
            state.grants.insert(
                *record.id().as_bytes(),
                Grant {
                    id: record.id(),
                    issuer,
                    subject: *grant.subject.id(),
                    abilities: grant.abilities.clone(),
                    delegable: grant.delegable.clone(),
                    parent: grant.parent,
                    claim_limit: grant.claim_limit,
                    claims_used: 0,
                    revoked: false,
                },
            );
        }
        ControlBody::CapabilityRevoke(revoke) => {
            // §17.3, in order, each AUTHORIZATION_FAILED: 1. the target
            // names a grant of this chain;
            let target = state
                .grant(&revoke.grant)
                .ok_or(deny(AuthorityRule::RevokeTargetUnknown))?;
            // 2. the issuer is the owner, or holds capability/revoke that
            // covers the target (a grant it issued, or one delegated from a
            // grant it issued);
            if !is_owner {
                state.require(&issuer, ability::CAPABILITY_REVOKE)?;
                if !state.issued_in_line(target, &issuer) {
                    return Err(deny(AuthorityRule::RevokeNotCovered));
                }
            }
            // 3. the target is not already revoked.
            if target.revoked {
                return Err(deny(AuthorityRule::RevokeAlreadyRevoked));
            }
            state
                .grants
                .get_mut(revoke.grant.as_bytes())
                .unwrap()
                .revoked = true;
        }
        ControlBody::CapabilityClaim(claim) => {
            let invitation = state
                .grant(&claim.invitation_grant)
                .ok_or(deny(AuthorityRule::ClaimGrantUnknown))?;
            if !state.is_active(&invitation.id) {
                return Err(deny(AuthorityRule::ClaimGrantInactive));
            }
            if !invitation.abilities.contains(&ability::INVITE_CLAIM) {
                return Err(deny(AuthorityRule::ClaimNotInvite));
            }
            // §18: an invitation grant without claim_limit is not
            // claimable; §18.1 rule 3: claims must remain.
            let Some(limit) = invitation.claim_limit else {
                return Err(deny(AuthorityRule::ClaimNotClaimable));
            };
            if invitation.claims_used >= limit {
                return Err(deny(AuthorityRule::ClaimLimitExhausted));
            }
            let claimable = |code: &u64| {
                invitation.abilities.contains(code)
                    && (*code != ability::INVITE_CLAIM || invitation.delegable.contains(code))
            };
            if !claim.abilities.iter().all(claimable) {
                return Err(deny(AuthorityRule::ClaimAbilitiesExceed));
            }
            if invitation.subject != issuer {
                return Err(deny(AuthorityRule::ClaimIssuerNotInvitation));
            }
            state
                .grants
                .get_mut(claim.invitation_grant.as_bytes())
                .unwrap()
                .claims_used += 1;
            state.learn(&claim.claimant);
            // §18.1: the claim's grant has the claim record's ID, no parent
            // and an empty delegable list, so revoking the invitation
            // afterwards does not revoke the claimant.
            state.grants.insert(
                *record.id().as_bytes(),
                Grant {
                    id: record.id(),
                    issuer,
                    subject: *claim.claimant.id(),
                    abilities: claim.abilities.clone(),
                    delegable: Vec::new(),
                    parent: None,
                    claim_limit: None,
                    claims_used: 0,
                    revoked: false,
                },
            );
        }
        ControlBody::KeyEpoch(epoch) => {
            state.require(&issuer, ability::KEY_ROTATE)?;
            // §19: exactly the previous Data Epoch plus one, else the
            // record breaks the chain: INVALID_CONTROL_CHAIN (G-EP3).
            if state.current_epoch.checked_add(1) != Some(epoch.epoch) {
                return Err(Error::InvalidControlChain(
                    crate::base::ChainRule::EpochNotNext,
                ));
            }
            state
                .dek_commitments
                .insert(epoch.epoch, epoch.dek_commitment);
            state
                .closed_frontiers
                .insert(state.current_epoch, epoch.final_frontier.clone());
            state.current_epoch = epoch.epoch;
        }
        ControlBody::RouteUpdate(route) => {
            state.require(&issuer, ability::ROUTE_UPDATE)?;
            // §20: each Route Update strictly increases the route version,
            // from Genesis's implied 0 (§15); a version that does not is
            // AUTHORIZATION_FAILED.
            if route.version <= state.route_version {
                return Err(deny(AuthorityRule::RouteVersionNotIncreasing));
            }
            state.route_version = route.version;
        }
        ControlBody::OwnerTransferCommit(commit) => {
            let new_owner = check_transfer(&state, record, commit)?;
            state.learn(&new_owner);
            state.owner = new_owner;
        }
        ControlBody::CoordinatorRecovery(_) | ControlBody::ResourceTombstone(_) => {
            return Err(Error::UnsupportedInMvp(record.body().control_type()));
        }
        ControlBody::Extension { .. } => {
            // §14: an extension record requires owner authority, whether or
            // not the extension is supported (AUTHORIZATION_FAILED); it is
            // retained, not interpreted.
            if !is_owner {
                return Err(deny(AuthorityRule::NotOwner));
            }
        }
    }
    state.head = head;
    Ok(state)
}

fn check_grant(
    state: &ControlState,
    issuer: &PrincipalId,
    is_owner: bool,
    grant: &CapabilityGrantBody,
) -> Result<(), Error> {
    // §17.2: the owner may grant without a parent; a non-owner must hold
    // capability/grant and reference a parent it is the subject of. Any
    // failure, escalation included, is AUTHORIZATION_FAILED.
    let Some(parent_id) = &grant.parent else {
        return if is_owner {
            Ok(())
        } else {
            Err(deny(AuthorityRule::NotOwner))
        };
    };
    if !is_owner {
        state.require(issuer, ability::CAPABILITY_GRANT)?;
    }
    let parent = state
        .grant(parent_id)
        .ok_or(deny(AuthorityRule::ParentUnknown))?;
    if !state.is_active(parent_id) {
        return Err(deny(AuthorityRule::ParentInactive));
    }
    if &parent.subject != issuer {
        return Err(deny(AuthorityRule::NotParentSubject));
    }
    if !grant.abilities.iter().all(|a| parent.delegable.contains(a)) {
        return Err(deny(AuthorityRule::Escalation));
    }
    // §17.2: every delegable ability of the new grant is delegable by the
    // parent.
    if !grant.delegable.iter().all(|a| parent.delegable.contains(a)) {
        return Err(deny(AuthorityRule::DelegableEscalation));
    }
    Ok(())
}

/// Verify §23.1–§23.3 for a Transfer Commit applied on `state` and return
/// the new owner.
fn check_transfer(
    state: &ControlState,
    record: &ControlRecord,
    commit: &OwnerTransferCommitBody,
) -> Result<PrincipalDescriptor, Error> {
    let (offer_object, offer) = commit.offer()?;
    let (accept_object, accept) = commit.accept()?;
    if offer.resource_id != state.resource_id || accept.resource_id != state.resource_id {
        return Err(deny(AuthorityRule::TransferResourceMismatch));
    }
    // Rule 1: the offer is signed by the current owner.
    if offer_object.kid() != state.owner.id() {
        return Err(deny(AuthorityRule::TransferOfferNotByOwner));
    }
    cose::verify(&offer_object, &state.owner)?;
    // Rule 2: the offer references the current Control Head.
    if offer.control_head.as_bytes() != state.head.id.as_bytes() {
        return Err(deny(AuthorityRule::TransferOfferStaleHead));
    }
    // Rule 3: the offer names the accepting Principal.
    let new_owner = offer.new_owner;
    if &accept.new_owner != new_owner.id() {
        return Err(deny(AuthorityRule::TransferAcceptorMismatch));
    }
    // §23.2: the accept names this offer by its object ID.
    if &accept.offer != offer_object.id() {
        return Err(deny(AuthorityRule::TransferAcceptNotForOffer));
    }
    // Rule 4: the acceptance is signed by that Principal.
    if accept_object.kid() != new_owner.id() {
        return Err(deny(AuthorityRule::TransferAcceptorMismatch));
    }
    cose::verify(&accept_object, &new_owner)?;
    // Rule 5: the commit is signed by that Principal (its signature by the
    // issuer is already verified).
    if &record.header().issuer != new_owner.id() {
        return Err(deny(AuthorityRule::TransferCommitIssuer));
    }
    // Rule 6: the expected next sequence is the commit's.
    if offer.next_sequence != record.header().sequence {
        return Err(deny(AuthorityRule::TransferSequenceMismatch));
    }
    Ok(new_owner)
}

/// The [`ChainPolicy`] that enforces authority, keeping the state after
/// every accepted record.
#[derive(Clone, Debug, Default)]
pub struct CapabilityEngine {
    base: Option<ControlState>,
    history: Vec<ControlState>,
    known: Vec<PrincipalDescriptor>,
}

impl CapabilityEngine {
    /// An engine for a chain validated from Genesis.
    pub fn new() -> CapabilityEngine {
        CapabilityEngine::default()
    }

    /// An engine for records that continue a chain whose state is `state`.
    pub fn resume(state: ControlState) -> CapabilityEngine {
        CapabilityEngine {
            base: Some(state),
            history: Vec::new(),
            known: Vec::new(),
        }
    }

    /// Also resolve issuers from `descriptors`, learned outside the chain.
    /// A descriptor is self-certifying, so any source will do (§13.1: an
    /// issuer the receiver cannot resolve is `MISSING_DEPENDENCY`).
    pub fn knowing(mut self, descriptors: &[PrincipalDescriptor]) -> CapabilityEngine {
        self.known.extend_from_slice(descriptors);
        self
    }

    /// The state after each record accepted so far, in order.
    pub fn history(&self) -> &[ControlState] {
        &self.history
    }

    fn latest(&self) -> Option<&ControlState> {
        self.history.last().or(self.base.as_ref())
    }
}

impl ChainPolicy for CapabilityEngine {
    fn resolve_issuer(&mut self, issuer: &PrincipalId) -> Option<PrincipalDescriptor> {
        self.latest()
            .and_then(|state| state.principal(issuer))
            .or_else(|| self.known.iter().find(|d| d.id() == issuer))
            .cloned()
    }

    fn authorize(
        &mut self,
        accepted: &[ControlRecord],
        record: &ControlRecord,
    ) -> Result<(), Error> {
        let previous = match accepted.len() {
            0 => self.base.as_ref(),
            n => self.history.get(n - 1),
        };
        let next = apply(previous, record)?;
        // A competing record of a fork is authorized at its slot but not
        // recorded: it never becomes a head.
        if accepted.len() == self.history.len() {
            self.history.push(next);
        }
        Ok(())
    }
}

/// Validate a chain with authority enforced, from Genesis, or after the
/// head of `resume`. Returns the outcome and the state after every
/// accepted record.
pub fn validate_authorized(
    records: &[&[u8]],
    resume: Option<ControlState>,
) -> Result<(ChainOutcome, Vec<ControlState>), ChainFailure> {
    validate_authorized_with(records, resume, &[])
}

/// [`validate_authorized`], also resolving issuers from `known`
/// descriptors learned outside the chain ([`CapabilityEngine::knowing`]).
pub fn validate_authorized_with(
    records: &[&[u8]],
    resume: Option<ControlState>,
    known: &[PrincipalDescriptor],
) -> Result<(ChainOutcome, Vec<ControlState>), ChainFailure> {
    let (start, engine) = match resume {
        None => (ChainStart::Genesis, CapabilityEngine::new()),
        Some(state) => (
            ChainStart::After(state.head),
            CapabilityEngine::resume(state),
        ),
    };
    let mut engine = engine.knowing(known);
    let outcome = validate_chain(records, start, &mut engine)?;
    Ok((outcome, engine.history))
}

/// The state at the Control Head `head`, if `history` reaches it.
pub fn state_at<'a>(
    history: &'a [ControlState],
    head: &ControlRecordId,
) -> Option<&'a ControlState> {
    history.iter().find(|state| &state.head.id == head)
}

/// The standard abilities `principal` holds at `head`.
pub fn abilities_at(
    history: &[ControlState],
    head: &ControlRecordId,
    principal: &PrincipalId,
) -> Option<BTreeSet<u64>> {
    state_at(history, head).map(|state| state.abilities(principal))
}

/// §25.2: whether `sender` may deliver a DEK to `recipient` in `state`.
/// The sender holds `key/distribute`; the recipient holds `data/read` or is
/// the subject of an active grant that includes and still confers
/// `invite/claim`.
pub fn can_distribute_key(
    state: &ControlState,
    sender: &PrincipalId,
    recipient: &PrincipalId,
) -> Result<(), Error> {
    state.require(sender, ability::KEY_DISTRIBUTE)?;
    let invited = state
        .grants()
        .any(|g| &g.subject == recipient && state.confers_invite(g));
    if state.holds(recipient, ability::DATA_READ) || invited {
        Ok(())
    } else {
        Err(deny(AuthorityRule::MissingAbility(ability::DATA_READ)))
    }
}

/// §26.3: whether `actor` may write Data Units in `state`.
pub fn can_write(state: &ControlState, actor: &PrincipalId) -> Result<(), Error> {
    state.require(actor, ability::DATA_WRITE)
}

/// A Key Package authorization hook evaluating §25.2 at the package's
/// Control Head, for [`crate::wire::key_package::ReceivedKeyPackage::verify`].
pub fn key_package_policy(
    history: &[ControlState],
) -> impl FnOnce(&KeyPackageHeader) -> Result<(), Error> + '_ {
    move |header| {
        let head = ControlRecordId::from_bytes(*header.control_head.as_bytes());
        let state = state_at(history, &head).ok_or(Error::UnknownControlHead)?;
        // §25.2 with §19: the package's epoch must be known at its head.
        if !state.dek_commitments.contains_key(&header.data_epoch) {
            return Err(Error::UnknownDataEpoch(header.data_epoch));
        }
        can_distribute_key(state, &header.sender, &header.recipient)
    }
}

/// A Data Unit hook for [`crate::wire::data_unit::ReceivedDataUnit::verify_with`]:
/// `data/write` at the unit's Control Head (§26.3 steps 2–3), then its
/// epoch (steps 4–5). A unit held back by the cutoff fails with
/// [`Error::StaleDataEpoch`]; the client keeps it in quarantine (§19.1).
pub fn data_unit_policy(
    history: &[ControlState],
) -> impl FnOnce(&DataUnitHeader) -> Result<(), Error> + '_ {
    move |header| {
        let head = ControlRecordId::from_bytes(*header.control_head.as_bytes());
        let state = state_at(history, &head).ok_or(Error::UnknownControlHead)?;
        can_write(state, &header.actor)?;
        match crate::wire::control::epoch::client_disposition(history, header)? {
            crate::wire::control::epoch::Disposition::Accept => Ok(()),
            crate::wire::control::epoch::Disposition::Quarantine(reason) => {
                Err(Error::StaleDataEpoch(reason))
            }
        }
    }
}

/// A Snapshot hook for [`crate::wire::snapshot::ReceivedSnapshot::verify_with`]:
/// the Snapshot's epoch is known at its Control Head, the publisher holds
/// `snapshot/publish` there (§29, §29.2), and, when the latest known state
/// has closed the Snapshot's epoch, every sequence its frontier covers lies
/// within that epoch's final frontier (§29, §19.1, G-EP4): otherwise
/// `STALE_DATA_EPOCH`.
pub fn snapshot_policy(
    history: &[ControlState],
) -> impl FnOnce(&crate::wire::snapshot::SnapshotHeader) -> Result<(), Error> + '_ {
    move |header| {
        let head = ControlRecordId::from_bytes(*header.control_head.as_bytes());
        let state = state_at(history, &head).ok_or(Error::UnknownControlHead)?;
        if !state.dek_commitments.contains_key(&header.data_epoch) {
            return Err(Error::UnknownDataEpoch(header.data_epoch));
        }
        state.require(&header.publisher, ability::SNAPSHOT_PUBLISH)?;
        let latest = history.last().ok_or(Error::UnknownControlHead)?;
        snapshot_within_cutoff(latest, header)
    }
}

/// §29 (G-EP4): a Snapshot of an epoch that `latest` has closed must not
/// cover any unit beyond the epoch's final frontier.
pub fn snapshot_within_cutoff(
    latest: &ControlState,
    header: &crate::wire::snapshot::SnapshotHeader,
) -> Result<(), Error> {
    use crate::base::QuarantineReason;
    use crate::wire::have::{difference, HaveVector};
    let Some(cutoff) = latest.closed_frontiers.get(&header.data_epoch) else {
        return Ok(());
    };
    let beyond = difference(
        &HaveVector::from_frontier(cutoff),
        &HaveVector::from_frontier(&header.frontier),
    )
    .request;
    match beyond.first() {
        None => Ok(()),
        Some(range) => Err(Error::StaleDataEpoch(
            if cutoff
                .entries()
                .iter()
                .any(|e| e.principal == range.principal)
            {
                QuarantineReason::BeyondCutoff
            } else {
                QuarantineReason::ActorAbsent
            },
        )),
    }
}

/// The coordinator's decision on a `CONTROL_PUT` (§21, §47), as a pure
/// function: the expected head must be the current head, and the record
/// must continue the chain at that head with valid signature and
/// authority. Returns the state after the record. Committing it durably
/// and atomically is the server's job; serializing puts through this
/// function is what makes one-time claims one-time (§18.1 rule 6).
pub fn propose_transition(
    current: &ControlState,
    expected_head: ControlRecordId,
    record: &[u8],
) -> Result<ControlState, Error> {
    check_expected_head(expected_head, current.head.id)?;
    let (outcome, history) =
        validate_authorized(&[record], Some(current.clone())).map_err(|failure| failure.error)?;
    match (outcome, history.into_iter().next()) {
        (ChainOutcome::Linear(_), Some(next)) => Ok(next),
        // A single record continuing the current head cannot fork, and a
        // repeat of the head itself is no transition.
        _ => Err(Error::ControlHeadMismatch {
            current: current.head.id,
        }),
    }
}
