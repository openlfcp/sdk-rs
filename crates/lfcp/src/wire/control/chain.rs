//! Control Chain validation and fork detection (LFCP-WIRE-01 §13, §15).
//!
//! | Rule | § |
//! | --- | --- |
//! | The chain starts with Genesis: type 0, sequence 0, previous `null` | §13.1, §15 |
//! | Genesis is signed by its owner, or by the leaf when field 5 is present | §15 |
//! | Genesis occurs only at the start | §13.1, §15 |
//! | `control_seq = previous.control_seq + 1` | §13.1 |
//! | `prev_control_id = previous.record_id` | §13.1 |
//! | One Resource ID throughout | §13 |
//! | Every record parses and is signed by its issuer (`kid` = field 4), else `INVALID_SIGNATURE` | §10, §13 |
//! | An issuer with no known descriptor is `MISSING_DEPENDENCY` | §13.1 |
//! | Any other structure violation is `INVALID_CONTROL_CHAIN` | §13.1 |
//! | Two valid records with one predecessor are a fork: `CONTROL_CONFLICT`, no winner | §13.2 |
//!
//! [`validate_chain`] is a pure function over records in chain order. It
//! checks structure and signatures; whether each issuer had the authority
//! for its record is delegated to [`ChainPolicy::authorize`].

use std::collections::HashMap;

use crate::base::{AuthorityRule, ChainRule, ControlRecordId, Error, PrincipalId, ResourceId};
use crate::cose;
use crate::principal::PrincipalDescriptor;
use crate::wire::control::body::ControlBody;
use crate::wire::control::{ControlRecord, ReceivedControlRecord};

/// The head of a Control Chain: its last accepted record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainHead {
    /// The Resource.
    pub resource_id: ResourceId,
    /// The head record's ID.
    pub id: ControlRecordId,
    /// The head record's Control Sequence.
    pub sequence: u64,
}

/// Where the records given to [`validate_chain`] start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainStart {
    /// The first record is Genesis.
    Genesis,
    /// The records continue an already validated chain with this head.
    After(ChainHead),
}

/// What [`validate_chain`] needs from the caller beyond the records.
pub trait ChainPolicy {
    /// Current epoch at this prefix, for the class-2 KEY_EPOCH check.
    /// A policy resuming without Genesis must supply the starting epoch.
    fn previous_epoch(&mut self, accepted: &[ControlRecord]) -> Option<u64> {
        prefix_epoch(accepted)
    }

    /// The descriptor of an issuer that no earlier record in the chain
    /// describes. Descriptors are self-certifying (their ID is the hash of
    /// their keys), so any source will do.
    fn resolve_issuer(&mut self, _issuer: &PrincipalId) -> Option<PrincipalDescriptor> {
        None
    }

    /// Resolve at the prefix being validated, including a fork's predecessor.
    /// The default delegates to the stateless external resolver.
    fn resolve_at(
        &mut self,
        _accepted: &[ControlRecord],
        issuer: &PrincipalId,
    ) -> Option<PrincipalDescriptor> {
        self.resolve_issuer(issuer)
    }

    /// Resolve a Device Grant root from the previous Control state (§17.4).
    /// Unlike an ordinary signer, it must be known to that Resource's chain.
    /// Policies resuming a chain supply descriptors from the resume state.
    fn resolve_root(
        &mut self,
        accepted: &[ControlRecord],
        root: &PrincipalId,
    ) -> Option<PrincipalDescriptor> {
        self.resolve_at(accepted, root)
    }

    /// §62 class 4: return the offer signer's descriptor only if it is the
    /// current owner or a device bound to that owner at this prefix. Activity
    /// and owner/act are checked later, in the authority class.
    ///
    /// The default derives ownership/bindings from the accepted records.
    /// Policies resuming a chain must also consult their previous state.
    fn resolve_offer_signer(
        &mut self,
        accepted: &[ControlRecord],
        signer: &PrincipalId,
    ) -> Option<PrincipalDescriptor> {
        let owner = accepted
            .iter()
            .rev()
            .find_map(|record| match record.body() {
                ControlBody::Genesis(b) => Some(b.owner.clone()),
                ControlBody::OwnerTransferCommit(b) => b.offer().ok().map(|(_, o)| o.new_owner),
                _ => None,
            })?;
        if owner.id() == signer {
            return Some(owner);
        }
        accepted
            .iter()
            .filter_map(|r| r.body().device_chain())
            .filter(|chain| chain.root() == owner.id())
            .flat_map(|chain| chain.certificates())
            .find(|cert| cert.payload().device.id() == signer)
            .map(|cert| cert.payload().device.clone())
    }

    /// Whether `record`'s issuer had the authority for it, given the
    /// records accepted before it. All outer/embedded signatures and chain
    /// placement are already checked. The default accepts every record: authority is
    /// evaluated by the capability engine.
    fn authorize(
        &mut self,
        _accepted: &[ControlRecord],
        _record: &ControlRecord,
    ) -> Result<(), Error> {
        Ok(())
    }
}

/// A policy that resolves no external issuer and checks no authority.
pub struct SignaturesOnly;

impl ChainPolicy for SignaturesOnly {}

/// A policy that resolves external issuers with a closure and checks no
/// authority.
pub struct ResolveWith<F>(pub F);

impl<F> ResolveWith<F> {
    /// Resume signature validation with ownership, bindings and epoch from
    /// an already validated state. Authority checks remain disabled.
    pub fn after(self, state: super::authority::ControlState) -> ResumePolicy<Self> {
        ResumePolicy {
            policy: self,
            state,
        }
    }
}

/// A signature policy with the state preceding a resumed suffix.
pub struct ResumePolicy<P> {
    policy: P,
    state: super::authority::ControlState,
}

impl<P: ChainPolicy> ChainPolicy for ResumePolicy<P> {
    fn previous_epoch(&mut self, accepted: &[ControlRecord]) -> Option<u64> {
        prefix_epoch(accepted).or(Some(self.state.current_epoch))
    }

    fn resolve_issuer(&mut self, issuer: &PrincipalId) -> Option<PrincipalDescriptor> {
        self.state
            .principal(issuer)
            .cloned()
            .or_else(|| self.policy.resolve_issuer(issuer))
    }

    fn resolve_offer_signer(
        &mut self,
        accepted: &[ControlRecord],
        signer: &PrincipalId,
    ) -> Option<PrincipalDescriptor> {
        let owner = accepted
            .iter()
            .rev()
            .find_map(|r| match r.body() {
                ControlBody::OwnerTransferCommit(b) => b.offer().ok().map(|(_, o)| o.new_owner),
                ControlBody::Genesis(b) => Some(b.owner.clone()),
                _ => None,
            })
            .unwrap_or_else(|| self.state.owner.clone());
        if owner.id() == signer {
            return Some(owner);
        }
        accepted
            .iter()
            .filter_map(|r| r.body().device_chain())
            .filter(|c| c.root() == owner.id())
            .flat_map(|c| c.certificates())
            .find(|c| c.payload().device.id() == signer)
            .map(|c| c.payload().device.clone())
            .or_else(|| {
                self.state
                    .device(signer)
                    .filter(|d| &d.root == owner.id())
                    .and_then(|_| self.state.principal(signer).cloned())
            })
    }
}

fn prefix_epoch(accepted: &[ControlRecord]) -> Option<u64> {
    accepted.iter().rev().find_map(|r| match r.body() {
        ControlBody::Genesis(_) => Some(0),
        ControlBody::KeyEpoch(b) => Some(b.epoch),
        _ => None,
    })
}

fn check_epoch(
    record: &ReceivedControlRecord,
    accepted: &[ControlRecord],
    policy: &mut impl ChainPolicy,
) -> Result<(), Error> {
    if let ControlBody::KeyEpoch(b) = record.body() {
        if let Some(epoch) = policy.previous_epoch(accepted) {
            if epoch.checked_add(1) != Some(b.epoch) {
                return Err(Error::InvalidControlChain(ChainRule::EpochNotNext));
            }
        }
    }
    Ok(())
}

impl<F: FnMut(&PrincipalId) -> Option<PrincipalDescriptor>> ChainPolicy for ResolveWith<F> {
    fn resolve_issuer(&mut self, issuer: &PrincipalId) -> Option<PrincipalDescriptor> {
        (self.0)(issuer)
    }
}

/// A validated linear Control Chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlChain {
    /// The accepted records, in order.
    pub records: Vec<ControlRecord>,
    /// The head: the last record, or the start head if no record was given.
    pub head: ChainHead,
}

/// The result of validating records that are each valid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChainOutcome {
    /// The records form one linear chain.
    Linear(ControlChain),
    /// Two valid records share a predecessor (§13.2). Neither is accepted
    /// as head and no winner is chosen; the Resource is in
    /// `CONTROL_CONFLICT`.
    Conflict(Box<ChainConflict>),
}

/// A Control Fork found while validating a chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainConflict {
    /// The records accepted before the fork point, in order.
    pub common: Vec<ControlRecord>,
    /// The record the chain first continued with.
    pub first: ControlRecord,
    /// The competing record.
    pub second: ControlRecord,
}

impl ChainOutcome {
    /// The wire error for a conflict, if this is one.
    pub fn error(&self) -> Option<Error> {
        match self {
            ChainOutcome::Linear(_) => None,
            ChainOutcome::Conflict(_) => Some(Error::ControlConflict),
        }
    }
}

/// A record that could not be accepted, by its position in the input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainFailure {
    /// The index of the offending record.
    pub index: usize,
    /// Why it was rejected.
    pub error: Error,
}

/// Two verified records are a Control Fork when they name the same Resource,
/// sequence and previous record but have different IDs (§13.2).
pub fn check_fork(a: &ControlRecord, b: &ControlRecord) -> Result<(), Error> {
    let (x, y) = (a.header(), b.header());
    let same_slot =
        x.resource_id == y.resource_id && x.sequence == y.sequence && x.previous == y.previous;
    if same_slot && a.id() != b.id() {
        Err(Error::ControlConflict)
    } else {
        Ok(())
    }
}

/// The coordinator's compare-and-swap check for `CONTROL_PUT` (§47): the
/// expected head must equal the current head, or the put is rejected with
/// `NACK(CONTROL_HEAD_MISMATCH)` carrying the current head. A `CONTROL_PUT`
/// always names an expected head; Genesis uses `RESOURCE_HOST`. Committing
/// the record atomically with this check is the coordinator's job.
pub fn check_expected_head(
    expected: ControlRecordId,
    current: ControlRecordId,
) -> Result<(), Error> {
    if expected == current {
        Ok(())
    } else {
        Err(Error::ControlHeadMismatch { current })
    }
}

/// Validate `records`, given as exact signed-object bytes in chain order,
/// starting at `start`.
///
/// Records that repeat an accepted record are skipped. A valid record that
/// competes with an accepted one ends validation with
/// [`ChainOutcome::Conflict`]. Any invalid record ends it with a
/// [`ChainFailure`].
///
/// All embedded signatures are checked before the authority policy (§62).
/// Use the capability engine for complete validation: `SignaturesOnly` and
/// `ResolveWith` intentionally do not check authority or apply transitions.
pub fn validate_chain(
    records: &[&[u8]],
    start: ChainStart,
    policy: &mut impl ChainPolicy,
) -> Result<ChainOutcome, ChainFailure> {
    let mut accepted: Vec<ControlRecord> = Vec::new();
    let mut positions: HashMap<ControlRecordId, usize> = HashMap::new();
    // Descriptors found in accepted records, by Principal ID.
    let mut directory: HashMap<PrincipalId, PrincipalDescriptor> = HashMap::new();
    let start_head = match start {
        ChainStart::Genesis => None,
        ChainStart::After(head) => Some(head),
    };

    for (index, bytes) in records.iter().enumerate() {
        let fail = |error| ChainFailure { index, error };
        let record = ReceivedControlRecord::parse(bytes).map_err(fail)?;

        // The slot this record claims: the position after its predecessor.
        let slot = match record.header().previous {
            None => Some(0),
            Some(previous) if start_head.is_some_and(|h| h.id == previous) => Some(0),
            Some(previous) => positions.get(&previous).map(|k| k + 1),
        };
        let slot = slot.filter(|&s| s < accepted.len());
        if let Some(slot) = slot {
            if accepted[slot].id() == record.id() {
                continue; // a repeat of an accepted record
            }
            // A competitor: it must be valid in that slot to be a fork.
            let predecessor = slot
                .checked_sub(1)
                .map(|k| head_of(&accepted[k]))
                .or(start_head);
            check_placement(&record, predecessor).map_err(fail)?;
            check_epoch(&record, &accepted[..slot], policy).map_err(fail)?;
            // A later descriptor is not a dependency at the fork's previous
            // head. Rebuild only the common prefix, never the losing suffix.
            let mut prefix_directory = HashMap::new();
            for previous in &accepted[..slot] {
                learn_descriptors(previous, &mut prefix_directory);
            }
            let second =
                verify(record, &accepted[..slot], &prefix_directory, policy).map_err(fail)?;
            policy.authorize(&accepted[..slot], &second).map_err(fail)?;
            let first = accepted[slot].clone();
            accepted.truncate(slot);
            return Ok(ChainOutcome::Conflict(Box::new(ChainConflict {
                common: accepted,
                first,
                second,
            })));
        }

        let predecessor = accepted.last().map(head_of).or(start_head);
        check_placement(&record, predecessor).map_err(fail)?;
        check_epoch(&record, &accepted, policy).map_err(fail)?;
        let record = verify(record, &accepted, &directory, policy).map_err(fail)?;
        policy.authorize(&accepted, &record).map_err(fail)?;
        learn_descriptors(&record, &mut directory);
        positions.insert(record.id(), accepted.len());
        accepted.push(record);
    }

    let head = accepted
        .last()
        .map(head_of)
        .or(start_head)
        .ok_or(ChainFailure {
            index: 0,
            error: Error::InvalidControlChain(ChainRule::GenesisMissing),
        })?;
    Ok(ChainOutcome::Linear(ControlChain {
        records: accepted,
        head,
    }))
}

fn head_of(record: &ControlRecord) -> ChainHead {
    ChainHead {
        resource_id: record.header().resource_id,
        id: record.id(),
        sequence: record.header().sequence,
    }
}

/// Check §13.1 and §15 placement against the predecessor, or against the
/// start of the chain when there is none.
fn check_placement(
    record: &ReceivedControlRecord,
    predecessor: Option<ChainHead>,
) -> Result<(), Error> {
    let header = record.header();
    let broken = |rule| Err(Error::InvalidControlChain(rule));
    let is_genesis = matches!(record.body(), ControlBody::Genesis(_));
    let Some(predecessor) = predecessor else {
        // The first record of a chain is Genesis.
        if !is_genesis || header.sequence != 0 {
            return broken(ChainRule::GenesisMissing);
        }
        if header.previous.is_some() {
            return broken(ChainRule::GenesisPrevious);
        }
        return Ok(());
    };
    if is_genesis {
        return broken(ChainRule::GenesisNotFirst);
    }
    if header.resource_id != predecessor.resource_id {
        return broken(ChainRule::ResourceMismatch);
    }
    if predecessor.sequence.checked_add(1) != Some(header.sequence) {
        return broken(ChainRule::SequenceGap);
    }
    if header.previous != Some(predecessor.id) {
        return broken(ChainRule::PreviousMismatch);
    }
    Ok(())
}

/// Resolve all dependencies, then verify the record and every embedded
/// signed object (§62). Genesis/transfer device chains supply a required
/// leaf signer; a different issuer fails with `INVALID_SIGNATURE`.
fn verify(
    record: ReceivedControlRecord,
    accepted: &[ControlRecord],
    directory: &HashMap<PrincipalId, PrincipalDescriptor>,
    policy: &mut impl ChainPolicy,
) -> Result<ControlRecord, Error> {
    let body = record.body();
    let offer = match body {
        ControlBody::OwnerTransferCommit(commit) => Some(commit.offer()?),
        _ => None,
    };
    let accept = match body {
        ControlBody::OwnerTransferCommit(commit) => Some(commit.accept()?),
        _ => None,
    };
    let chain = body.device_chain();
    // Class 3: resolve *every* dependency before the outer signature.
    let root = match body {
        ControlBody::Genesis(b) => Some(b.owner.clone()),
        ControlBody::OwnerTransferCommit(_) => Some(offer.as_ref().unwrap().1.new_owner.clone()),
        ControlBody::DeviceGrant(b) => Some(
            directory
                .get(&b.root)
                .cloned()
                .or_else(|| policy.resolve_root(accepted, &b.root))
                .ok_or(Error::IssuerUnknown(b.root))?,
        ),
        _ => None,
    };
    if let Some(chain) = chain {
        chain.require_root(root.as_ref())?;
    }
    let issuer = record.header().issuer;
    let required = match body {
        ControlBody::Genesis(b) => Some(chain.map_or(&b.owner, |c| &c.leaf().payload().device)),
        ControlBody::OwnerTransferCommit(_) if chain.is_some() => {
            Some(&chain.unwrap().leaf().payload().device)
        }
        _ => None,
    };
    let descriptor = required
        .cloned()
        .or_else(|| directory.get(&issuer).cloned())
        .or_else(|| {
            chain.and_then(|c| {
                c.certificates()
                    .iter()
                    .find(|cert| cert.payload().device.id() == &issuer)
                    .map(|cert| cert.payload().device.clone())
            })
        })
        .or_else(|| {
            offer
                .as_ref()
                .map(|(_, offer)| &offer.new_owner)
                .filter(|d| d.id() == &issuer)
                .cloned()
        })
        .or_else(|| {
            if matches!(
                body,
                ControlBody::DeviceGrant(_) | ControlBody::DeviceRevoke(_)
            ) {
                // §17.4/17.5: known to S or the grant's chain, not external
                // descriptors. N3 includes the rejection class, not just admission.
                policy.resolve_root(accepted, &issuer)
            } else {
                policy.resolve_at(accepted, &issuer)
            }
        })
        .ok_or(Error::IssuerUnknown(issuer))?;
    // §23.3/§62: an offer signer is never a dependency. Verify its signature
    // only for the current owner or a device bound to it (even if inactive).
    // Any other kid fails authority after the remaining signatures, whether
    // or not an external resolver knows its descriptor.
    let offer_signer = offer
        .as_ref()
        .and_then(|(object, _)| policy.resolve_offer_signer(accepted, object.kid()));

    // Class 4: outer record, certificates, then embedded offer and accept.
    let record = record.verify(&descriptor)?;
    let chain = record.body().device_chain();
    if let Some(chain) = chain {
        chain.verify_signatures(root.as_ref().unwrap())?;
    }
    if let (Some((offer_object, offer)), Some((accept_object, _))) = (&offer, &accept) {
        if let Some(signer) = &offer_signer {
            cose::verify(offer_object, signer)?;
        }
        let acceptor = chain.map_or(&offer.new_owner, |c| &c.leaf().payload().device);
        cose::verify(accept_object, acceptor)?;
        if offer_signer.is_none() {
            // Also fail closed for SignaturesOnly/ResolveWith: an unchecked
            // outsider's offer must never be returned as a verified record.
            return Err(Error::AuthorizationFailed(
                AuthorityRule::TransferOfferNotByOwner,
            ));
        }
    }
    Ok(record)
}

/// Record the descriptors a verified record carries: the Genesis owner,
/// grant subjects, claimants and a transfer offer's new owner.
fn learn_descriptors(
    record: &ControlRecord,
    directory: &mut HashMap<PrincipalId, PrincipalDescriptor>,
) {
    let mut learn = |d: &PrincipalDescriptor| {
        directory.insert(*d.id(), d.clone());
    };
    match record.body() {
        ControlBody::Genesis(b) => learn(&b.owner),
        ControlBody::CapabilityGrant(b) => learn(&b.subject),
        ControlBody::CapabilityClaim(b) => learn(&b.claimant),
        ControlBody::OwnerTransferCommit(b) => {
            if let Ok((_, offer)) = b.offer() {
                learn(&offer.new_owner);
            }
        }
        _ => {}
    }
    if let Some(chain) = record.body().device_chain() {
        for certificate in chain.certificates() {
            learn(&certificate.payload().device);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::Hash32;
    use crate::principal::PrincipalKeys;
    use crate::wire::control::body::{CapabilityRevokeBody, Endpoint, GenesisBody};
    use crate::wire::control::ControlRecordHeader;

    fn owner() -> PrincipalKeys {
        PrincipalKeys::from_secrets(&[1; 32], [2; 32])
    }

    const RESOURCE: ResourceId = ResourceId::from_bytes([7; 32]);

    fn genesis() -> ControlRecord {
        let body = ControlBody::Genesis(GenesisBody {
            device_chain: None,
            data_profile: "lfcp.tasks.v1".into(),
            owner: owner().descriptor().clone(),
            dek_commitment: Hash32::from_bytes([5; 32]),
            endpoints: vec![Endpoint {
                url: "wss://a.example/ws".into(),
                priority: 0,
                flags: None,
            }],
            coordinator: "wss://a.example/ws".into(),
        });
        record(0, None, body)
    }

    fn record(
        sequence: u64,
        previous: Option<ControlRecordId>,
        body: ControlBody,
    ) -> ControlRecord {
        let header = ControlRecordHeader {
            resource_id: RESOURCE,
            sequence,
            previous,
            issuer: *owner().descriptor().id(),
        };
        ControlRecord::sign(header, body, &owner()).unwrap()
    }

    fn revoke(sequence: u64, previous: &ControlRecord, grant: u8) -> ControlRecord {
        let body = ControlBody::CapabilityRevoke(CapabilityRevokeBody {
            grant: ControlRecordId::from_bytes([grant; 32]),
        });
        record(sequence, Some(previous.id()), body)
    }

    fn validate(records: &[&ControlRecord]) -> Result<ChainOutcome, ChainFailure> {
        let bytes: Vec<&[u8]> = records.iter().map(|r| r.signed_object().bytes()).collect();
        validate_chain(&bytes, ChainStart::Genesis, &mut SignaturesOnly)
    }

    #[test]
    fn expected_head_must_be_current() {
        let a = ControlRecordId::from_bytes([1; 32]);
        let b = ControlRecordId::from_bytes([2; 32]);
        assert_eq!(check_expected_head(a, a), Ok(()));
        let err = check_expected_head(a, b).unwrap_err();
        assert_eq!(err, Error::ControlHeadMismatch { current: b });
        assert_eq!(err.wire_code().unwrap().name(), "CONTROL_HEAD_MISMATCH");
    }

    #[test]
    fn linear_chain_validates() {
        let g = genesis();
        let r1 = revoke(1, &g, 1);
        let r2 = revoke(2, &r1, 2);
        let ChainOutcome::Linear(chain) = validate(&[&g, &r1, &r2, &r2]).unwrap() else {
            panic!("expected a linear chain")
        };
        assert_eq!(chain.records.len(), 3);
        assert_eq!(chain.head.id, r2.id());
        assert_eq!(chain.head.sequence, 2);
    }

    #[test]
    fn competing_records_are_a_conflict() {
        let g = genesis();
        let r1 = revoke(1, &g, 1);
        let r1b = revoke(1, &g, 9);
        let r2 = revoke(2, &r1, 2);
        let outcome = validate(&[&g, &r1, &r2, &r1b]).unwrap();
        assert_eq!(outcome.error(), Some(Error::ControlConflict));
        let ChainOutcome::Conflict(conflict) = outcome else {
            unreachable!()
        };
        let ChainConflict {
            common,
            first,
            second,
        } = *conflict;
        assert_eq!(common, vec![g]);
        assert_eq!((first.id(), second.id()), (r1.id(), r1b.id()));
        assert_eq!(check_fork(&first, &second), Err(Error::ControlConflict));
        assert_eq!(check_fork(&first, &first.clone()), Ok(()));
    }

    fn rule(result: Result<ChainOutcome, ChainFailure>) -> (usize, Error) {
        let failure = result.unwrap_err();
        (failure.index, failure.error)
    }

    #[test]
    fn chain_rules() {
        use ChainRule::*;
        let g = genesis();
        let r1 = revoke(1, &g, 1);
        let chain = |rule| Error::InvalidControlChain(rule);

        assert_eq!(rule(validate(&[])), (0, chain(GenesisMissing)));
        assert_eq!(rule(validate(&[&r1])), (0, chain(GenesisMissing)));
        assert_eq!(
            rule(validate(&[&g, &revoke(2, &g, 1)])),
            (1, chain(SequenceGap))
        );
        let broken_link = record(
            1,
            Some(ControlRecordId::from_bytes([3; 32])),
            r1.body().clone(),
        );
        assert_eq!(
            rule(validate(&[&g, &broken_link])),
            (1, chain(PreviousMismatch))
        );
        // A second, different Genesis competes with the first at the root.
        let other_genesis = {
            let ControlBody::Genesis(mut body) = g.body().clone() else {
                unreachable!()
            };
            body.data_profile = "lfcp.other.v1".into();
            record(0, None, ControlBody::Genesis(body))
        };
        let ChainOutcome::Conflict(conflict) = validate(&[&g, &r1, &other_genesis]).unwrap() else {
            panic!("expected a root conflict")
        };
        assert!(conflict.common.is_empty());
        assert_eq!(conflict.second.id(), other_genesis.id());

        let late_genesis = record(1, Some(g.id()), g.body().clone());
        assert_eq!(
            rule(validate(&[&g, &late_genesis])),
            (1, chain(GenesisNotFirst))
        );
    }

    #[test]
    fn unknown_issuer_needs_the_resolver() {
        let g = genesis();
        let stranger = PrincipalKeys::from_secrets(&[3; 32], [4; 32]);
        let header = ControlRecordHeader {
            resource_id: RESOURCE,
            sequence: 1,
            previous: Some(g.id()),
            issuer: *stranger.descriptor().id(),
        };
        let r1 = ControlRecord::sign(header, revoke(1, &g, 1).body().clone(), &stranger).unwrap();
        let bytes = [g.signed_object().bytes(), r1.signed_object().bytes()];
        assert_eq!(
            rule(validate_chain(
                &bytes,
                ChainStart::Genesis,
                &mut SignaturesOnly
            )),
            (1, Error::IssuerUnknown(*stranger.descriptor().id()))
        );
        let known = stranger.descriptor().clone();
        let mut policy = ResolveWith(|id: &PrincipalId| (id == known.id()).then(|| known.clone()));
        assert!(matches!(
            validate_chain(&bytes, ChainStart::Genesis, &mut policy),
            Ok(ChainOutcome::Linear(_))
        ));
    }

    #[test]
    fn authorize_hook_can_reject() {
        struct DenyRevokes;
        impl ChainPolicy for DenyRevokes {
            fn authorize(
                &mut self,
                _: &[ControlRecord],
                record: &ControlRecord,
            ) -> Result<(), Error> {
                match record.body() {
                    ControlBody::CapabilityRevoke(_) => Err(Error::ControlRecordMalformed),
                    _ => Ok(()),
                }
            }
        }
        let g = genesis();
        let r1 = revoke(1, &g, 1);
        let bytes = [g.signed_object().bytes(), r1.signed_object().bytes()];
        assert_eq!(
            rule(validate_chain(
                &bytes,
                ChainStart::Genesis,
                &mut DenyRevokes
            )),
            (1, Error::ControlRecordMalformed)
        );
    }

    #[test]
    fn validation_can_continue_from_a_known_head() {
        let g = genesis();
        let r1 = revoke(1, &g, 1);
        let r2 = revoke(2, &r1, 2);
        let head = ChainHead {
            resource_id: RESOURCE,
            id: r1.id(),
            sequence: 1,
        };
        // The owner's descriptor is in Genesis, which is not given here.
        let known = owner().descriptor().clone();
        let mut policy = ResolveWith(|id: &PrincipalId| (id == known.id()).then(|| known.clone()));
        let outcome = validate_chain(
            &[r2.signed_object().bytes()],
            ChainStart::After(head),
            &mut policy,
        )
        .unwrap();
        let ChainOutcome::Linear(chain) = outcome else {
            panic!("expected a linear chain")
        };
        assert_eq!(chain.head.id, r2.id());
        let empty = validate_chain(&[], ChainStart::After(head), &mut SignaturesOnly).unwrap();
        assert_eq!(
            empty,
            ChainOutcome::Linear(ControlChain {
                records: vec![],
                head
            })
        );
    }
}
