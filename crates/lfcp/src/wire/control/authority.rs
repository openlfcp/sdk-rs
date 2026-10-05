//! The capability engine: Control state derived from a chain, and the
//! authority each record, Key Package and Data Unit needs (LFCP-WIRE-01
//! §17–§26).
//!
//! | Record or object | Required authority | § |
//! | --- | --- | --- |
//! | Genesis | self-signed by the owner in its body (chain rule) | §15 |
//! | Capability Grant, no parent | owner; a non-owner cannot prove authority without a parent | §17.2 |
//! | Capability Grant, with parent | parent exists and is active; issuer is its subject; abilities ⊆ parent delegable; delegable ⊆ parent delegable; a non-owner also holds `capability/grant` | §17.2 |
//! | Capability Revoke | owner, or `capability/revoke` covering the grant | §17.3 |
//! | Capability Claim | §18.1 rules 1–5: invitation grant active, grants `invite/claim`, claims remain, abilities ⊆ invitation abilities (minus `invite/claim` unless delegable), issuer is the Invitation Principal; consumes one claim | §18.1 |
//! | Key Epoch | `key/rotate`; new epoch = current + 1; closes the current epoch with its final frontier | §19 |
//! | Route Update | `route/update`; route version increases | §20 |
//! | Owner Transfer Commit | §23.3 rules 1–6 and §23.2: offer by the current owner at the current head, accept by the named Principal for this offer, commit by that Principal at the offered sequence | §23 |
//! | Coordinator Recovery, Resource Tombstone | refused: not applied in MVP 0.1 | §22, §24, MVP-SCOPE §4 |
//! | extension type | owner only (provisional) | §14 |
//! | Key Package | sender holds `key/distribute`; recipient holds `data/read` or is the subject of an active invite grant, at the package's Control Head | §25.2 |
//! | Data Unit | actor holds `data/write` at the unit's Control Head | §26.3 |
//!
//! The owner implicitly holds every standard ability (§15, §17.1). A
//! grant is active while it is not revoked and, provisionally, while its
//! parent is active. Unauthorized records are `AUTHORIZATION_FAILED`.
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
    /// `owner/transfer-offer`
    pub const OWNER_TRANSFER_OFFER: u64 = 9;
    /// `resource/tombstone`
    pub const RESOURCE_TOMBSTONE: u64 = 10;
    /// `invite/claim`
    pub const INVITE_CLAIM: u64 = 11;
    /// Every standard ability, as the owner holds them.
    pub const STANDARD: std::ops::RangeInclusive<u64> = 1..=11;
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
    /// The current route version; Genesis is version 0 (provisional, G-CP2).
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
            // PROVISIONAL (revocation cascade): §17.3 does not say whether
            // revoking a grant revokes grants delegated from it. A child
            // grant is active only while its parent is active.
            Some(Grant {
                parent: Some(parent),
                ..
            }) => self.is_active(parent),
            Some(_) => true,
        }
    }

    /// The standard abilities `principal` holds: all of them for the owner,
    /// otherwise the union over its active grants.
    pub fn abilities(&self, principal: &PrincipalId) -> BTreeSet<u64> {
        if self.is_owner(principal) {
            return ability::STANDARD.collect();
        }
        self.grants
            .values()
            .filter(|g| &g.subject == principal && self.is_active(&g.id))
            .flat_map(|g| g.abilities.iter().copied())
            // PROVISIONAL (G-CP6): unknown codes are kept in the grant but
            // confer nothing and are never held.
            .filter(|code| ability::STANDARD.contains(code))
            .collect()
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
                // PROVISIONAL (G-CP2): Genesis implies route version 0.
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
            let target = state
                .grant(&revoke.grant)
                .ok_or(deny(AuthorityRule::RevokeTargetUnknown))?;
            if !is_owner {
                state.require(&issuer, ability::CAPABILITY_REVOKE)?;
                // PROVISIONAL (G-CAP1): §17.3 does not define when revoke
                // authority "covers" a grant. It covers grants the issuer
                // issued and grants delegated from them.
                if !state.issued_in_line(target, &issuer) {
                    return Err(deny(AuthorityRule::RevokeNotCovered));
                }
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
            let limit = invitation.claim_limit.unwrap_or(0);
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
            // PROVISIONAL (G-CAP2): §18.1 says a claim "creates a new
            // capability grant to the claimant" without its delegable set or
            // parent. It has none, so revoking the invitation afterwards
            // does not revoke the claimant.
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
            // §19: "exactly the previous Data Epoch plus one". Provisional
            // code: §19 names none; a skipped or repeated epoch breaks the
            // chain's epoch sequence, so INVALID_CONTROL_CHAIN.
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
            // PROVISIONAL (G-CP2): each Route Update strictly increases the
            // route version, starting from Genesis's implied 0.
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
            // PROVISIONAL (G-CAP3): §14 lets an unknown extension record be
            // retained but not interpreted, and names no authority for it.
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
    let Some(parent_id) = &grant.parent else {
        // §17.2: a non-owner must prove authority to grant every ability;
        // without a parent grant there is nothing to prove it with.
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
    // Inferred no-escalation: a child may not make delegable what its
    // parent cannot delegate.
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
        }
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
        self.latest()?.principal(issuer).cloned()
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
    let (start, mut engine) = match resume {
        None => (ChainStart::Genesis, CapabilityEngine::new()),
        Some(state) => (
            ChainStart::After(state.head),
            CapabilityEngine::resume(state),
        ),
    };
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
/// the subject of an active invite grant.
pub fn can_distribute_key(
    state: &ControlState,
    sender: &PrincipalId,
    recipient: &PrincipalId,
) -> Result<(), Error> {
    state.require(sender, ability::KEY_DISTRIBUTE)?;
    let invited = state.grants().any(|g| {
        &g.subject == recipient
            && g.abilities.contains(&ability::INVITE_CLAIM)
            && state.is_active(&g.id)
    });
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
        can_distribute_key(state, &header.sender, &header.recipient)
    }
}

/// A Data Unit authorization hook evaluating §26.3 at the unit's Control
/// Head, for [`crate::wire::data_unit::ReceivedDataUnit::verify_with`].
pub fn data_unit_policy(
    history: &[ControlState],
) -> impl FnOnce(&DataUnitHeader) -> Result<(), Error> + '_ {
    move |header| {
        let head = ControlRecordId::from_bytes(*header.control_head.as_bytes());
        let state = state_at(history, &head).ok_or(Error::UnknownControlHead)?;
        can_write(state, &header.actor)
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
    expected_head: Option<ControlRecordId>,
    record: &[u8],
) -> Result<ControlState, Error> {
    check_expected_head(expected_head, Some(current.head.id))?;
    let (outcome, history) =
        validate_authorized(&[record], Some(current.clone())).map_err(|failure| failure.error)?;
    match (outcome, history.into_iter().next()) {
        (ChainOutcome::Linear(_), Some(next)) => Ok(next),
        // A single record continuing the current head cannot fork, and a
        // repeat of the head itself is no transition.
        _ => Err(Error::ControlHeadMismatch {
            current: Some(current.head.id),
        }),
    }
}
