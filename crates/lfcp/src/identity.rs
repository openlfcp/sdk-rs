//! Identity Resource profile (IDENTITY-PROFILE-01 §§2–5).
//!
//! Authority always comes from validated Control state. Document entries are
//! display data and hints. Admission reuses Shared Objects' byte, history,
//! sequence, expansion and depth checks, then applies AI0–AI4 causally.
use crate::base::{PrincipalId, ResourceId};
use crate::wire::control::{authority::ControlState, device::DeviceKind};
use std::fmt;

mod admission;
mod document;
pub mod links;
pub use admission::{IdentityReplica, Received, UnitContext};
pub use document::IdentityDoc;

/// Genesis data profile and immutable document `profile`.
pub const PROFILE: &str = "org.openlfcp.identity.v1";
/// The four mutable root containers.
pub const CONTAINERS: [&str; 4] = ["roster", "devices", "requests", "extensions"];

/// Identity profile diagnostic. State diagnostics are ordered as §4's table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Diagnostic {
    /// AI0 or an unusable root.
    InvalidRoot,
    /// A required entry field is absent.
    MissingRequiredField,
    /// Wrong value type or conflicting request.
    InvalidFieldType,
    /// Not a canonical ResourceRef.
    InvalidResourceRef,
    /// Not a canonical PrincipalRef.
    InvalidPrincipalRef,
    /// Invalid descriptor or descriptor/key mismatch.
    InvalidDescriptor,
    /// Kind is neither personal nor service.
    InvalidEnumValue,
    /// Invalid UTC timestamp.
    InvalidTimestamp,
    /// Invalid extension namespace.
    InvalidExtensionNamespace,
    /// Shared Objects byte, sequence, reference or expansion violation.
    InvalidAutomergeBytes,
    /// Signer and Automerge actor differ.
    ChangeActorMismatch,
    /// AI2: a container was replaced.
    ContainerReplaced,
    /// AI1: an immutable field was written.
    ImmutableFieldMutated,
    /// AI4: a restricted writer wrote outside its own request.
    UnauthorizedWriter,
    /// Owner decision I8; provisional until assigned by the specification.
    MissingKeysWriterMismatch,
}
impl Diagnostic {
    /// Application diagnostic name; these are not Wire error codes.
    pub fn name(self) -> &'static str {
        match self {
            Self::InvalidRoot => "INVALID_ROOT",
            Self::MissingRequiredField => "MISSING_REQUIRED_FIELD",
            Self::InvalidFieldType => "INVALID_FIELD_TYPE",
            Self::InvalidResourceRef => "INVALID_RESOURCE_REF",
            Self::InvalidPrincipalRef => "INVALID_PRINCIPAL_REF",
            Self::InvalidDescriptor => "INVALID_DESCRIPTOR",
            Self::InvalidEnumValue => "INVALID_ENUM_VALUE",
            Self::InvalidTimestamp => "INVALID_TIMESTAMP",
            Self::InvalidExtensionNamespace => "INVALID_EXTENSION_NAMESPACE",
            Self::InvalidAutomergeBytes => "INVALID_AUTOMERGE_BYTES",
            Self::ChangeActorMismatch => "CHANGE_ACTOR_MISMATCH",
            Self::ContainerReplaced => "CONTAINER_REPLACED",
            Self::ImmutableFieldMutated => "IMMUTABLE_FIELD_MUTATED",
            Self::UnauthorizedWriter => "UNAUTHORIZED_WRITER",
            Self::MissingKeysWriterMismatch => "MISSING_KEYS_WRITER_MISMATCH",
        }
    }
}
impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PROFILE_INVALID: {}", self.name())
    }
}
impl std::error::Error for Diagnostic {}

/// Signer classification at the carrying Data Unit's `control_ref` (§2.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriterClass {
    /// The Genesis owner.
    Root,
    /// A bound personal device.
    Personal,
    /// A bound pairing device.
    Pairing,
    /// Any other signer, including a service device.
    Other,
}
impl WriterClass {
    /// Classify using the validated state at the unit's head, not the latest
    /// head. Wire authorization must already have accepted the unit.
    pub fn at(genesis_owner: &PrincipalId, signer: &PrincipalId, state: &ControlState) -> Self {
        if signer == genesis_owner {
            return Self::Root;
        }
        match state.device(signer).map(|d| d.kind) {
            Some(DeviceKind::Personal) => Self::Personal,
            Some(DeviceKind::Pairing) => Self::Pairing,
            _ => Self::Other,
        }
    }
}

/// Parse a canonical 43-character ResourceRef (§2.1).
pub fn parse_resource_ref(value: &str) -> Result<ResourceId, Diagnostic> {
    ResourceId::from_b64url(value).map_err(|_| Diagnostic::InvalidResourceRef)
}
