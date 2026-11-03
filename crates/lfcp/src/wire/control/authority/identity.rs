//! Resource-local identity state and transitions (§7.3, §17.4–17.5, §80.1).

use super::{ability, deny, ControlState, PersistentMap};
use crate::base::{AuthorityRule, Error, Hash32, PrincipalId, ResourceId};
use crate::wire::control::body::{DeviceGrantBody, DeviceRevokeBody};
use crate::wire::control::chain::ChainHead;
use crate::wire::control::device::{
    CertificateChain, ChainStateChecks, DeviceCertificatePayload, DeviceKind, DEVICE_MANAGE,
    OWNER_ACT,
};
use std::{collections::BTreeSet, sync::Arc};

const MAX_LIVE_DEVICES: usize = 32;
const MAX_DEVICE_GRANTS: u8 = 8;
const MAX_PREEMPTIVE_REVOCATIONS: usize = 64;

/// Cached Resource-local totals; all binding paths contribute, including
/// Genesis and transfers. A direct revocation releases one live binding slot;
/// a cascade does not. Only currently unbound targets spend the revocation quota.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct DeviceCounts {
    live_bound: usize,
    preemptive_revocations: usize,
}

/// A permanent role in one Resource (§79).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Appeared as a leaf or intermediate in an accepted certificate chain.
    Device,
    /// Owner, grant subject, claimant or transferee (invitations included).
    NonDevice,
}

/// The binding of a device in this Resource (§79). Revocation never erases it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceBinding {
    /// Immutable human root.
    pub root: PrincipalId,
    /// Immutable device kind.
    pub kind: DeviceKind,
    /// Immutable mask, including unknown codes, compared as a set.
    pub mask: BTreeSet<u64>,
    /// Immutable scope, normalized to raw Resource-ID order for set equality.
    pub scope: Vec<ResourceId>,
    /// Whether an accepted record registered this device as an in-scope leaf.
    pub registered: bool,
    /// Latest chain accepted with this device as its leaf, exact bytes retained.
    pub chain: Option<Arc<CertificateChain>>,
    /// Certificate ID of that chain's leaf (not its payload digest).
    pub leaf_id: Option<Hash32>,
    /// Accepted DEVICE_GRANT records for this leaf, including out-of-scope
    /// registrations. Genesis, transfer and intermediate bindings do not count.
    pub grants_accepted: u8,
    /// Device issuers in the current chain, nearest first; excludes the root.
    pub issuers: Vec<PrincipalId>,
}

/// A permanent revocation of an exact (root, device) pair (§17.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceRevocation {
    /// Received reason, including unknown values.
    pub reason: u64,
    /// Approved payload digest, present exactly for reason 3.
    pub approval: Option<Hash32>,
}

/// Session read authority at the accepted head (§41). Uploads are independent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadAccess {
    /// Ordinary reader or the active invitation-subject exception.
    Full,
    /// Only Control Records through this head, inclusive. No data, keys,
    /// snapshots, presence or live pushes, and no later Control Records.
    ControlPrefix(ChainHead),
    /// No read authority.
    Denied,
}

fn scope_set(scope: &[ResourceId]) -> Vec<ResourceId> {
    let mut scope = scope.to_vec();
    scope.sort_unstable_by_key(|id| *id.as_bytes());
    scope
}

impl ControlState {
    fn device_counts_mut(&mut self, root: &PrincipalId) -> &mut DeviceCounts {
        if !self.device_counts.contains_key(root.as_bytes()) {
            self.device_counts
                .insert(*root.as_bytes(), DeviceCounts::default());
        }
        self.device_counts.get_mut(root.as_bytes()).unwrap()
    }

    /// The Principal's permanent Resource-local role, if assigned.
    pub fn role(&self, principal: &PrincipalId) -> Option<Role> {
        self.roles.get(principal.as_bytes()).copied()
    }

    /// All roles, in raw Principal-ID order.
    pub fn roles(&self) -> impl Iterator<Item = (PrincipalId, Role)> + '_ {
        self.roles
            .iter()
            .map(|(id, role)| (PrincipalId::from_bytes(*id), *role))
    }

    /// The binding, whether active, intermediate-only, suspended or revoked.
    pub fn device(&self, principal: &PrincipalId) -> Option<&DeviceBinding> {
        self.devices.get(principal.as_bytes())
    }

    /// Every binding, in raw Principal-ID order.
    pub fn devices(&self) -> impl Iterator<Item = (PrincipalId, &DeviceBinding)> {
        self.devices
            .iter()
            .map(|(id, binding)| (PrincipalId::from_bytes(*id), binding))
    }

    /// The revocation of this exact pair, including unbound devices.
    pub fn revocation(
        &self,
        root: &PrincipalId,
        device: &PrincipalId,
    ) -> Option<&DeviceRevocation> {
        self.revoked.get(&(*root.as_bytes(), *device.as_bytes()))
    }

    /// Every revocation, in raw (root, device) order.
    pub fn revocations(
        &self,
    ) -> impl Iterator<Item = (PrincipalId, PrincipalId, &DeviceRevocation)> {
        self.revoked.iter().map(|((root, device), value)| {
            (
                PrincipalId::from_bytes(*root),
                PrincipalId::from_bytes(*device),
                value,
            )
        })
    }

    /// Whether this Principal has ever been bound as a device here.
    pub fn bound(&self, principal: &PrincipalId) -> bool {
        self.device(principal).is_some()
    }

    /// Ownership or an active grant not listing invite/claim (§17.5).
    /// An exhausted invitation still does not establish standing.
    pub fn root_standing(&self, root: &PrincipalId) -> bool {
        self.is_owner(root)
            || self.grants().any(|grant| {
                &grant.subject == root
                    && !grant.abilities.contains(&ability::INVITE_CLAIM)
                    && self.is_active(&grant.id)
            })
    }

    /// An active binding: registered, with standing, and no revoked pair
    /// for the leaf or any issuer in its latest chain (§17.5).
    pub fn active_device(&self, principal: &PrincipalId) -> Option<&DeviceBinding> {
        self.device(principal).filter(|device| {
            device.registered
                && self.revocation(&device.root, principal).is_none()
                && device
                    .issuers
                    .iter()
                    .all(|issuer| self.revocation(&device.root, issuer).is_none())
                && self.root_standing(&device.root)
        })
    }

    /// The root of an active device, otherwise the Principal itself (§80.1).
    pub fn acts_for(&self, principal: &PrincipalId) -> PrincipalId {
        self.active_device(principal).map_or(*principal, |d| d.root)
    }

    /// Stable historical attribution, also for revoked/suspended devices.
    pub fn root_of(&self, principal: &PrincipalId) -> PrincipalId {
        self.device(principal).map_or(*principal, |d| d.root)
    }

    /// Authority for owner-only actions (§80.1), distinct from a mask ability.
    pub fn owner_action(&self, principal: &PrincipalId) -> bool {
        if self.bound(principal) {
            self.active_device(principal)
                .is_some_and(|d| self.is_owner(&d.root) && d.mask.contains(&OWNER_ACT))
        } else {
            self.is_owner(principal)
        }
    }

    /// §25.2 same-root exception: at least one endpoint is an active device.
    pub fn same_root(&self, a: &PrincipalId, b: &PrincipalId) -> bool {
        self.acts_for(a) == self.acts_for(b)
            && (self.active_device(a).is_some() || self.active_device(b).is_some())
    }

    /// §41 read decision, including the exact proof prefix for a revoked reader.
    /// This is derived entirely from accepted transitions, survives resume,
    /// and must not be used to authorize uploads (§84).
    pub fn may_read(&self, principal: &PrincipalId) -> ReadAccess {
        if self.holds(principal, ability::DATA_READ)
            || self
                .grants()
                .any(|g| &g.subject == principal && self.confers_invite(g))
        {
            ReadAccess::Full
        } else if let Some(head) = self.revoked_read_heads.get(principal.as_bytes()) {
            ReadAccess::ControlPrefix(*head)
        } else {
            ReadAccess::Denied
        }
    }

    pub(super) fn non_device(&mut self, principal: &PrincipalId) -> Result<(), Error> {
        if self.bound(principal) {
            return Err(deny(AuthorityRule::SubjectIsDevice));
        }
        if self.role(principal).is_none() {
            self.roles.insert(*principal.as_bytes(), Role::NonDevice);
        }
        Ok(())
    }

    /// Apply already checked bindings. Intermediates keep their own current
    /// leaf chains and registration flags; only the leaf is re-certified.
    pub(super) fn bind_chain(
        &mut self,
        chain: &CertificateChain,
        in_scope: bool,
        keep_registered_leaf: bool,
    ) {
        for cert in chain.certificates() {
            let p = cert.payload();
            if !self.bound(p.device.id()) {
                // A foreign-root tombstone cannot prevent this binding, but
                // its target is no longer unbound anywhere in this Resource.
                // Use the reverse index rather than scan the revoked history.
                if let Some(roots) = self
                    .preemptive_revokers
                    .get(p.device.id().as_bytes())
                    .cloned()
                {
                    for (root, ()) in roots.iter() {
                        self.device_counts_mut(&PrincipalId::from_bytes(*root))
                            .preemptive_revocations -= 1;
                    }
                }
                self.devices.insert(
                    *p.device.id().as_bytes(),
                    DeviceBinding {
                        root: p.root,
                        kind: p.kind,
                        mask: p.mask.iter().copied().collect(),
                        scope: scope_set(&p.scope),
                        registered: false,
                        chain: None,
                        leaf_id: None,
                        grants_accepted: 0,
                        issuers: Vec::new(),
                    },
                );
                self.roles.insert(*p.device.id().as_bytes(), Role::Device);
                // Chain state checks reject every directly revoked chain pair.
                self.device_counts_mut(&p.root).live_bound += 1;
            }
            self.learn(&p.device);
        }
        let leaf = self
            .devices
            .get_mut(chain.leaf().payload().device.id().as_bytes())
            .unwrap();
        if keep_registered_leaf && leaf.registered && leaf.leaf_id == Some(chain.leaf().id()) {
            return;
        }
        leaf.chain = Some(Arc::new(chain.clone()));
        leaf.leaf_id = Some(chain.leaf().id());
        leaf.issuers = chain.issuers().copied().collect();
        leaf.registered |= in_scope;
    }

    pub(super) fn check_owner_leaf(&self, chain: &CertificateChain) -> Result<(), Error> {
        let leaf = chain.leaf().payload();
        if leaf.kind == DeviceKind::Personal && leaf.mask.contains(&OWNER_ACT) {
            Ok(())
        } else {
            Err(deny(AuthorityRule::DeviceCannotActAsOwner))
        }
    }

    fn manages(&self, issuer: &PrincipalId, root: &PrincipalId) -> bool {
        self.active_device(issuer)
            .is_some_and(|d| &d.root == root && d.mask.contains(&DEVICE_MANAGE))
    }

    pub(super) fn grant_device(
        &mut self,
        issuer: &PrincipalId,
        grant: &DeviceGrantBody,
    ) -> Result<(), Error> {
        // §17.4 rules 4–8, after every dependency and signature.
        if !self.root_standing(&grant.root) {
            return Err(deny(AuthorityRule::DeviceRootNotStanding));
        }
        let chain = &grant.chain;
        let in_scope = chain.check_authority(&self.resource_id)?;
        chain.check_state(self)?;
        let leaf = chain.leaf();
        let p = leaf.payload();
        if self
            .device(p.device.id())
            .is_some_and(|d| d.leaf_id == Some(leaf.id()))
        {
            return Err(deny(AuthorityRule::DeviceAlreadyBound));
        }
        let allowed = if issuer == p.device.id() {
            // Self-submission is only a first leaf registration, including an
            // intermediate-only binding. Management/owner masks do not allow
            // a previously registered device to re-certify itself.
            p.kind == DeviceKind::Personal && self.device(issuer).is_none_or(|d| d.chain.is_none())
        } else {
            issuer == &grant.root
                || (p.kind == DeviceKind::Personal && chain.issuers().any(|id| id == issuer))
                || self.manages(issuer, &grant.root)
                || (self.is_owner(&grant.root) && self.owner_action(issuer))
        };
        if !allowed {
            return Err(deny(AuthorityRule::DeviceGrantIssuer));
        }
        if let Some(session) = &grant.pairing_device {
            let approved = self
                .device(session)
                .is_some_and(|d| d.kind == DeviceKind::Pairing && d.root == grant.root)
                && self
                    .revocation(&grant.root, session)
                    .is_some_and(|r| r.reason == 3 && r.approval == Some(leaf.payload_digest()));
            if !approved {
                return Err(deny(AuthorityRule::DeviceApprovalMismatch));
            }
        }
        let live_bound = self
            .device_counts
            .get(grant.root.as_bytes())
            .map_or(0, |c| c.live_bound);
        let new_bindings = chain
            .certificates()
            .iter()
            .filter(|cert| !self.bound(cert.payload().device.id()))
            .count();
        if live_bound + new_bindings > MAX_LIVE_DEVICES {
            return Err(deny(AuthorityRule::DeviceBindingLimit));
        }
        if self
            .device(p.device.id())
            .is_some_and(|d| d.grants_accepted >= MAX_DEVICE_GRANTS)
        {
            return Err(deny(AuthorityRule::DeviceGrantLimit));
        }
        self.bind_chain(chain, in_scope, false);
        self.devices
            .get_mut(p.device.id().as_bytes())
            .unwrap()
            .grants_accepted += 1;
        Ok(())
    }

    pub(super) fn revoke_device(
        &mut self,
        issuer: &PrincipalId,
        revoke: &DeviceRevokeBody,
        head: ChainHead,
    ) -> Result<(), Error> {
        // §17.5 rule 3: consistency, before rights and duplicate detection.
        let binding = self.device(&revoke.device);
        if binding.is_some_and(|d| d.root != revoke.root) {
            return Err(deny(AuthorityRule::DeviceRevokeRootMismatch));
        }
        if self.role(&revoke.device) == Some(Role::NonDevice) {
            return Err(deny(AuthorityRule::DeviceRevokeRole));
        }
        if self.role(&revoke.root) == Some(Role::Device) {
            return Err(deny(AuthorityRule::DeviceRootRole));
        }
        if revoke.reason == 3 && !binding.is_some_and(|d| d.kind == DeviceKind::Pairing) {
            return Err(deny(AuthorityRule::DeviceConsumeNotPairing));
        }
        let existing = self.revocation(&revoke.root, &revoke.device).is_some();
        let allowed = (issuer == &revoke.root && self.root_standing(&revoke.root))
            || self.manages(issuer, &revoke.root)
            || self.owner_action(issuer)
            || (issuer == &revoke.device
                && revoke.reason == 0
                && binding.is_some_and(|d| d.registered)
                && !existing);
        if !allowed {
            return Err(deny(AuthorityRule::DeviceRevokeIssuer));
        }
        if existing {
            return Err(deny(AuthorityRule::DeviceAlreadyRevoked));
        }
        let bound = binding.is_some();
        if !bound
            && self
                .device_counts
                .get(revoke.root.as_bytes())
                .is_some_and(|c| c.preemptive_revocations >= MAX_PREEMPTIVE_REVOCATIONS)
        {
            return Err(deny(AuthorityRule::DeviceRevocationLimit));
        }
        // This transition cannot change standing, root abilities or other
        // roots. Compute these once, not once for every device's holds().
        let standing = self.root_standing(&revoke.root);
        let root_reads = self.direct(&revoke.root, ability::DATA_READ);
        let root_owns = self.is_owner(&revoke.root);
        let was_reader = |id: &PrincipalId, d: &DeviceBinding| {
            standing
                && d.root == revoke.root
                && d.registered
                && ((root_owns && d.mask.contains(&OWNER_ACT))
                    || (root_reads && d.mask.contains(&ability::DATA_READ)))
                && self.revocation(&d.root, id).is_none()
                && d.issuers
                    .iter()
                    .all(|issuer| self.revocation(&d.root, issuer).is_none())
        };
        let proof_read = binding.is_some_and(|d| was_reader(&revoke.device, d));
        // Only readers whose current path includes this pair can be removed.
        let exposing = proof_read
            || (standing
                && self
                    .devices()
                    .any(|(id, d)| d.issuers.contains(&revoke.device) && was_reader(&id, d)));
        // Only a direct revocation of a registered reader grants proof read.
        // A cascade or loss of root standing does not (§41).
        if proof_read {
            self.revoked_read_heads
                .insert(*revoke.device.as_bytes(), head);
        }
        self.revoked.insert(
            (*revoke.root.as_bytes(), *revoke.device.as_bytes()),
            DeviceRevocation {
                reason: revoke.reason,
                approval: revoke.approval,
            },
        );
        if bound {
            self.device_counts_mut(&revoke.root).live_bound -= 1;
        } else {
            self.device_counts_mut(&revoke.root).preemptive_revocations += 1;
            let device = *revoke.device.as_bytes();
            if !self.preemptive_revokers.contains_key(&device) {
                self.preemptive_revokers
                    .insert(device, PersistentMap::new());
            }
            self.preemptive_revokers
                .get_mut(&device)
                .unwrap()
                .insert(*revoke.root.as_bytes(), ());
        }
        if exposing {
            self.last_exposing_revocation = Some(head);
        }
        Ok(())
    }
}

impl ChainStateChecks for ControlState {
    fn root_allowed(&self, root: &PrincipalId) -> bool {
        self.role(root) != Some(Role::Device)
    }

    fn binding_matches(&self, p: &DeviceCertificatePayload) -> bool {
        self.role(p.device.id()) != Some(Role::NonDevice)
            && self.device(p.device.id()).is_none_or(|d| {
                d.root == p.root
                    && d.kind == p.kind
                    && d.mask == p.mask.iter().copied().collect()
                    && d.scope == scope_set(&p.scope)
            })
    }

    fn is_revoked(&self, root: &PrincipalId, device: &PrincipalId) -> bool {
        self.revocation(root, device).is_some()
    }
}
