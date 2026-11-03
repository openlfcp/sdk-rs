//! Device Certificates and leaf-first chains (identity draft rev. 3,
//! §§2.1–2.2, 3.2, 3.10; LFCP-04-402 / R1).
//!
//! Parsing checks the complete structure before dependency resolution or
//! signatures. [`verify_chain`] checks every signature before intrinsic
//! chain authority. Control validators can use the separate signature and
//! authority methods to interleave outer-object checks in §3.10 order.
//! [`ChainStateChecks`] supplies state predicates without defining or mutating
//! the authority engine (LFCP-04-404). A verified certificate chain alone never
//! establishes standing or authorizes a Control transition.
//!
//! [`preflight_issuance`] checks a prospective unsigned leaf before a pairing
//! approval is consumed (review N07, normative clarification pending in 401).
//! Callers must also preflight state authority and recheck it at the new head.

pub(crate) mod scan;

use crate::base::{AuthorityRule, Error, Hash32, PrincipalId, ResourceId};
use crate::cbor::{self, Value};
use crate::cose::{self, SignedObject};
use crate::crypto;
use crate::principal::{PrincipalDescriptor, PrincipalKeys};

/// Domain and version label of the seven-element certificate payload.
pub const CERTIFICATE_DOMAIN: &str = "LFCP-DEVICE-CERT-v1";
/// Maximum certificates in a chain, including the leaf.
pub const MAX_CHAIN_DEPTH: usize = 4;
/// A managing leaf must leave room to issue one more certificate.
pub const MAX_MANAGING_DEPTH: usize = 3;
/// Maximum entries in a mask (unknown codes count too).
pub const MAX_MASK_ENTRIES: usize = 32;
/// Maximum Resources in a service scope.
pub const MAX_SCOPE_ENTRIES: usize = 64;
/// The device/manage ability code.
pub const DEVICE_MANAGE: u64 = 12;
/// The owner/act ability code.
pub const OWNER_ACT: u64 = 13;

const MALFORMED: Error = Error::DeviceCertificateMalformed;

/// Certificate field 3; all other values are reserved and rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceKind {
    /// An installation of the human, with an empty scope.
    Personal = 0,
    /// A service, restricted to its nonempty Resource scope.
    Service = 1,
    /// A temporary pairing device, restricted to one Resource and read/write.
    Pairing = 2,
}

/// Unsigned certificate fields. Order in mask/scope is retained on the wire;
/// their meaning is a set. The writer supplies a random 16-byte serial.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceCertificatePayload {
    /// Field 1: the human root.
    pub root: PrincipalId,
    /// Field 2: the device's self-certifying descriptor.
    pub device: PrincipalDescriptor,
    /// Field 3: personal, service or pairing.
    pub kind: DeviceKind,
    /// Field 4: 1–32 distinct ability codes. Unknown codes confer nothing.
    pub mask: Vec<u64>,
    /// Field 5: distinct Resource IDs, subject to the kind rules.
    pub scope: Vec<ResourceId>,
    /// Field 6: random serial, carrying no order or time.
    pub serial: [u8; 16],
}

impl DeviceCertificatePayload {
    /// Check all §2.1 structural rules without signing or allocating.
    pub fn check(&self) -> Result<(), Error> {
        if self.root == *self.device.id()
            || !(1..=MAX_MASK_ENTRIES).contains(&self.mask.len())
            || self.scope.len() > MAX_SCOPE_ENTRIES
            || repeats(&self.mask)
            || repeats(&self.scope)
            || (self.mask.contains(&DEVICE_MANAGE)
                && !(self.mask.contains(&1) && self.mask.contains(&2)))
        {
            return Err(MALFORMED);
        }
        crypto::ed25519_public_key_check(self.device.ed25519_public())
            .map_err(|_| Error::PrincipalKeyInvalid)?;
        let valid = match self.kind {
            DeviceKind::Personal => self.scope.is_empty(),
            DeviceKind::Service => {
                !self.scope.is_empty()
                    && !self.mask.contains(&DEVICE_MANAGE)
                    && !self.mask.contains(&OWNER_ACT)
            }
            DeviceKind::Pairing => {
                self.scope.len() == 1 && self.mask.iter().all(|code| matches!(code, 1 | 2))
            }
        };
        if valid {
            Ok(())
        } else {
            Err(MALFORMED)
        }
    }

    /// Decode the closed seven-element payload, preserving mask/scope order.
    pub fn from_value(value: &Value) -> Result<Self, Error> {
        let fields: &[Value; 7] = value
            .as_array()
            .and_then(|a| a.try_into().ok())
            .ok_or(MALFORMED)?;
        if fields[0].as_text() != Some(CERTIFICATE_DOMAIN) {
            return Err(MALFORMED);
        }
        let root = PrincipalId::from_slice(fields[1].as_bytes().ok_or(MALFORMED)?)
            .map_err(|_| MALFORMED)?;
        let device = PrincipalDescriptor::from_value(&fields[2])?;
        let kind = match fields[3].as_u64() {
            Some(0) => DeviceKind::Personal,
            Some(1) => DeviceKind::Service,
            Some(2) => DeviceKind::Pairing,
            _ => return Err(MALFORMED),
        };
        let mask = fields[4].as_array().ok_or(MALFORMED)?;
        let scope = fields[5].as_array().ok_or(MALFORMED)?;
        if !(1..=MAX_MASK_ENTRIES).contains(&mask.len()) || scope.len() > MAX_SCOPE_ENTRIES {
            return Err(MALFORMED);
        }
        let payload = Self {
            root,
            device,
            kind,
            mask: mask
                .iter()
                .map(|v| v.as_u64().ok_or(MALFORMED))
                .collect::<Result<_, _>>()?,
            scope: scope
                .iter()
                .map(|v| {
                    ResourceId::from_slice(v.as_bytes().ok_or(MALFORMED)?).map_err(|_| MALFORMED)
                })
                .collect::<Result<_, _>>()?,
            serial: fields[6]
                .as_bytes()
                .and_then(|b| b.try_into().ok())
                .ok_or(MALFORMED)?,
        };
        payload.check()?;
        Ok(payload)
    }

    /// The payload value. Call [`check`](Self::check) before writing it.
    pub fn to_value(&self) -> Value {
        Value::Array(vec![
            Value::text(CERTIFICATE_DOMAIN),
            Value::bytes(self.root.as_bytes().to_vec()),
            self.device.to_value(),
            Value::Unsigned(self.kind as u64),
            Value::Array(self.mask.iter().copied().map(Value::Unsigned).collect()),
            Value::Array(
                self.scope
                    .iter()
                    .map(|id| Value::bytes(id.as_bytes().to_vec()))
                    .collect(),
            ),
            Value::bytes(self.serial.to_vec()),
        ])
    }

    /// Deterministic payload bytes, suitable for a later signature.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.check()?;
        cbor::encode(&self.to_value())
    }

    /// The digest an approval commits to, computable before signing (N9).
    pub fn digest(&self) -> Result<Hash32, Error> {
        Ok(crypto::sha256(&self.encode()?))
    }
}

fn repeats<T: PartialEq>(items: &[T]) -> bool {
    items
        .iter()
        .enumerate()
        .any(|(i, item)| items[..i].contains(item))
}

/// A structurally checked certificate with its exact signed bytes. Its
/// signer and authority are established only in a chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceCertificate {
    object: SignedObject,
    payload: DeviceCertificatePayload,
}

impl DeviceCertificate {
    /// Parse without verifying a signature. Schema bounds are scanned before
    /// any CBOR allocation, including nested mask/scope collections.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        scan::certificate(bytes)?;
        let object = cose::parse(bytes)?;
        let payload = DeviceCertificatePayload::from_value(object.payload())?;
        Ok(Self { object, payload })
    }

    /// Sign a structurally valid payload. This does not authorize the issuer;
    /// use [`preflight_issuance`] before consuming a pairing approval.
    pub fn sign(payload: DeviceCertificatePayload, signer: &PrincipalKeys) -> Result<Self, Error> {
        let object = cose::sign(&payload.encode()?, signer)?;
        Ok(Self { object, payload })
    }

    /// The parsed fields (not yet authenticated).
    pub fn payload(&self) -> &DeviceCertificatePayload {
        &self.payload
    }
    /// The exact signed object; nested encoders copy its bytes unchanged.
    pub fn signed_object(&self) -> &SignedObject {
        &self.object
    }
    /// SHA-256 of the exact COSE bytes, distinct from the payload digest.
    pub fn id(&self) -> Hash32 {
        *self.object.id()
    }
    /// SHA-256 of the exact received payload byte string (§2.1 rule 6).
    pub fn payload_digest(&self) -> Hash32 {
        crypto::sha256(self.object.payload_bytes())
    }
}

/// A structurally valid, nonempty, leaf-first chain with one root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateChain {
    certificates: Vec<DeviceCertificate>,
}

impl CertificateChain {
    /// Construct from certificates, checking c1, c5 and c7.
    pub fn new(certificates: Vec<DeviceCertificate>, root: &PrincipalId) -> Result<Self, Error> {
        check_structure(
            certificates.iter().map(DeviceCertificate::payload),
            certificates.len(),
            root,
        )?;
        Ok(Self { certificates })
    }

    /// Decode a CBOR chain with length checked before CBOR allocation.
    pub fn parse(bytes: &[u8], root: &PrincipalId) -> Result<Self, Error> {
        scan::chain(bytes)?;
        Self::from_value(&cbor::decode_strict(bytes)?, root)
    }

    /// Decode an already allocated CBOR value. Check the count before parsing
    /// any certificate or allocating its decoded representation.
    pub fn from_value(value: &Value, root: &PrincipalId) -> Result<Self, Error> {
        let items = value.as_array().ok_or(MALFORMED)?;
        if !(1..=MAX_CHAIN_DEPTH).contains(&items.len()) {
            return Err(MALFORMED);
        }
        // Scan all bounds before allocating even the first certificate.
        for (index, item) in items.iter().enumerate() {
            let manages = scan::certificate_manages(item.as_bytes().ok_or(MALFORMED)?)?;
            if index == 0 && manages && items.len() > MAX_MANAGING_DEPTH {
                return Err(MALFORMED);
            }
        }
        let certificates = items
            .iter()
            .map(|v| DeviceCertificate::parse(v.as_bytes().ok_or(MALFORMED)?))
            .collect::<Result<_, _>>()?;
        Self::new(certificates, root)
    }

    /// Exact COSE bytes in received order, never reconstructed from fields.
    pub fn to_value(&self) -> Value {
        Value::Array(
            self.certificates
                .iter()
                .map(|c| Value::bytes(c.object.bytes().to_vec()))
                .collect(),
        )
    }
    /// Deterministic chain encoding, preserving every embedded byte string.
    pub fn encode(&self) -> Vec<u8> {
        cbor::encode(&self.to_value()).expect("a checked chain is encodable")
    }
    /// Certificates, leaf first. Always contains 1–4 entries.
    pub fn certificates(&self) -> &[DeviceCertificate] {
        &self.certificates
    }
    /// The leaf certificate.
    pub fn leaf(&self) -> &DeviceCertificate {
        &self.certificates[0]
    }
    /// The chain's root ID.
    pub fn root(&self) -> &PrincipalId {
        &self.leaf().payload.root
    }
    /// Issuing device IDs, nearest issuer first; excludes the root.
    pub fn issuers(&self) -> impl Iterator<Item = &PrincipalId> {
        self.certificates[1..].iter().map(|c| c.payload.device.id())
    }

    /// Class 3 of verifyChain: the root descriptor must be available.
    /// Class 4: verify all certificate kids/signatures, leaf first.
    /// No authority checks run here, allowing outer-object class ordering.
    pub fn verify_signatures(&self, root: Option<&PrincipalDescriptor>) -> Result<(), Error> {
        let root = root.ok_or(Error::IssuerUnknown(*self.root()))?;
        if root.id() != self.root() {
            return Err(Error::CoseKidMismatch);
        }
        verify_signatures(&self.certificates, root)
    }

    /// Intrinsic class-5 checks c3, c4 and c6, in that order. Returns false
    /// only for an out-of-scope service leaf (which may still be bound).
    /// Roles, bindings and revocations must be checked by the Control state.
    pub fn check_authority(&self, resource: &ResourceId) -> Result<bool, Error> {
        check_authority(
            self.certificates.iter().map(DeviceCertificate::payload),
            resource,
        )
    }

    /// Remaining class-5 checks (§3.2 step 4.2–4.4), in global order: root,
    /// every binding, then every revocation. This method never mutates state.
    pub fn check_state(&self, state: &impl ChainStateChecks) -> Result<(), Error> {
        if !state.root_allowed(self.root()) {
            return Err(Error::AuthorizationFailed(AuthorityRule::DeviceRootRole));
        }
        for cert in &self.certificates {
            if !state.binding_matches(cert.payload()) {
                return Err(Error::AuthorizationFailed(
                    AuthorityRule::DeviceBindingConflict,
                ));
            }
        }
        for cert in &self.certificates {
            if state.is_revoked(self.root(), cert.payload().device.id()) {
                return Err(Error::AuthorizationFailed(AuthorityRule::DeviceRevoked));
            }
        }
        Ok(())
    }
}

/// Read-only integration boundary for §3.2 step 4.2–4.4. Implemented by the
/// Resource's previous Control state in LFCP-04-404; no role/binding storage
/// or transition logic lives in the codec. Mask/scope comparisons are set
/// equality, independent of received order; serial and issuer may change.
pub trait ChainStateChecks {
    /// True if the root has no role or the non-device role (step 4.2).
    fn root_allowed(&self, root: &PrincipalId) -> bool;
    /// True if the device has no role or the device role, and any existing
    /// binding has the same root, kind, mask and scope (step 4.3).
    fn binding_matches(&self, certificate: &DeviceCertificatePayload) -> bool;
    /// Whether this exact (root, device) pair is revoked (step 4.4).
    fn is_revoked(&self, root: &PrincipalId, device: &PrincipalId) -> bool;
}

/// The empty state used only for Genesis or standalone certificate checks.
/// A non-Genesis Control validator must supply its actual previous state.
#[derive(Clone, Copy, Debug, Default)]
pub struct EmptyChainState;

impl ChainStateChecks for EmptyChainState {
    fn root_allowed(&self, _: &PrincipalId) -> bool {
        true
    }
    fn binding_matches(&self, _: &DeviceCertificatePayload) -> bool {
        true
    }
    fn is_revoked(&self, _: &PrincipalId, _: &PrincipalId) -> bool {
        false
    }
}

fn check_structure<'a>(
    fields: impl Iterator<Item = &'a DeviceCertificatePayload>,
    len: usize,
    root: &PrincipalId,
) -> Result<(), Error> {
    if !(1..=MAX_CHAIN_DEPTH).contains(&len) {
        return Err(MALFORMED);
    }
    let mut seen = [None; MAX_CHAIN_DEPTH];
    for (i, payload) in fields.enumerate() {
        payload.check()?;
        if &payload.root != root
            || seen[..i].contains(&Some(payload.device.id()))
            || (i == 0 && payload.mask.contains(&DEVICE_MANAGE) && len > MAX_MANAGING_DEPTH)
        {
            return Err(MALFORMED);
        }
        seen[i] = Some(payload.device.id());
    }
    Ok(())
}

fn verify_signatures(
    certificates: &[DeviceCertificate],
    root: &PrincipalDescriptor,
) -> Result<(), Error> {
    for (i, cert) in certificates.iter().enumerate() {
        let signer = certificates.get(i + 1).map_or(root, |c| &c.payload.device);
        cose::verify(&cert.object, signer)?;
    }
    Ok(())
}

fn check_authority<'a>(
    fields: impl Iterator<Item = &'a DeviceCertificatePayload> + Clone,
    resource: &ResourceId,
) -> Result<bool, Error> {
    for issuer in fields.clone().skip(1) {
        if issuer.kind != DeviceKind::Personal || !issuer.mask.contains(&DEVICE_MANAGE) {
            return Err(Error::AuthorizationFailed(
                AuthorityRule::DeviceIssuerNotManaging,
            ));
        }
    }
    for (child, issuer) in fields.clone().zip(fields.clone().skip(1)) {
        if !child.mask.iter().all(|code| issuer.mask.contains(code)) {
            return Err(Error::AuthorizationFailed(
                AuthorityRule::DeviceMaskEscalation,
            ));
        }
    }
    let leaf = fields.clone().next().expect("checked nonempty chain");
    if leaf.kind == DeviceKind::Pairing && !leaf.scope.contains(resource) {
        return Err(Error::AuthorizationFailed(
            AuthorityRule::DevicePairingOutOfScope,
        ));
    }
    Ok(leaf.kind != DeviceKind::Service || leaf.scope.contains(resource))
}

/// Authenticated chain and its Resource scope result. This is evidence for
/// the state validator, not a grant of permission or a state transition.
#[derive(Clone, Copy, Debug)]
pub struct VerifiedChain<'a> {
    /// Includes the leaf descriptor, ID, kind, mask, scope and all bindings.
    pub chain: &'a CertificateChain,
    /// False only for an out-of-scope service leaf.
    pub in_scope: bool,
}

/// verifyChain's structure → dependencies → signatures → intrinsic authority
/// → state checks (§3.2, §3.10). State is supplied through read-only predicates;
/// no external lookup, clock, or state mutation is performed by this module.
pub fn verify_chain<'a>(
    chain: &'a CertificateChain,
    root: &PrincipalId,
    root_descriptor: Option<&PrincipalDescriptor>,
    resource: &ResourceId,
    state: &impl ChainStateChecks,
) -> Result<VerifiedChain<'a>, Error> {
    if chain.root() != root {
        return Err(MALFORMED);
    }
    chain.verify_signatures(root_descriptor)?;
    let in_scope = chain.check_authority(resource)?;
    chain.check_state(state)?;
    Ok(VerifiedChain { chain, in_scope })
}

/// Preflight an unsigned prospective leaf plus the issuer's leaf-first chain.
/// An empty issuer chain means root issuance. All structure, existing issuer
/// signatures and c3/c4/c6 are checked without signing the leaf (N07/N9).
/// The caller must check current state authority before consuming approval.
pub fn preflight_issuance(
    leaf: &DeviceCertificatePayload,
    issuers: &[DeviceCertificate],
    root_descriptor: Option<&PrincipalDescriptor>,
    resource: &ResourceId,
) -> Result<bool, Error> {
    // Avoid overflow and any work on attacker-sized issuer slices.
    if issuers.len() >= MAX_CHAIN_DEPTH {
        return Err(MALFORMED);
    }
    let fields = std::iter::once(leaf).chain(issuers.iter().map(DeviceCertificate::payload));
    check_structure(fields.clone(), issuers.len() + 1, &leaf.root)?;
    let root = root_descriptor.ok_or(Error::IssuerUnknown(leaf.root))?;
    if root.id() != &leaf.root {
        return Err(Error::CoseKidMismatch);
    }
    verify_signatures(issuers, root)?;
    check_authority(fields, resource)
}
