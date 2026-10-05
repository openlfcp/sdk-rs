//! The Shared Objects profile `org.openlfcp.shared-objects.v1`
//! (SHARED-OBJECTS-PROFILE-01) on Automerge.
//!
//! | Part | Module | § |
//! | --- | --- | --- |
//! | actor IDs and Principal references | [`identity`] | §8, §27 |
//! | Data Unit and Snapshot plaintext framing | [`framing`] | §11–§13 |
//! | values: Local Dates, timestamps, enums, namespaces, plain values | [`values`] | §18, §26, §28, §33, §35, §38 |
//! | profile validation and diagnostics | [`validate`] | §15–§43, §74–§77 |
//! | the document, intents and conflicts | [`document`] | §10, §15–§16, §44–§69 |
//!
//! The profile's errors are application-level codes, not LFCP Wire codes
//! (§74.1), so they have their own [`ProfileError`] type.
//!
//! Four rules bind the profile to Automerge (ADR 0003, ADR 0004):
//!
//! - every profile string is written as an Automerge scalar string, and a
//!   field found as collaborative Text is `PROFILE_INVALID` with
//!   `INVALID_FIELD_TYPE` (§30, G-SC3);
//! - an intent that writes always produces a real operation: a value equal
//!   to the current one is deleted and put again in the same change (§58,
//!   G-SC4);
//! - a received change is applied only when it is a change chunk with a
//!   valid checksum whose Automerge actor is the §8 actor of the Principal
//!   that signed the Data Unit carrying it; another actor is
//!   `PROFILE_INVALID` with `CHANGE_ACTOR_MISMATCH` (§8, §11, SO-SEC1,
//!   [`document::SharedObjects::apply_unit_change`]);
//! - a Data Unit or Snapshot plaintext that is not the §11 or §13 framing
//!   of a valid chunk of the right type, with a matching checksum, that
//!   Automerge parses or loads, is `PROFILE_INVALID` with
//!   `INVALID_AUTOMERGE_BYTES` ([`framing`]).

use std::fmt;

pub mod document;
pub mod expansion;
pub mod framing;
pub mod identity;
pub mod validate;
pub mod values;

/// The profile identifier (§6) and the value of the root `profile` key (§15).
pub const PROFILE: &str = "org.openlfcp.shared-objects.v1";

/// A `PROFILE_INVALID` diagnostic (§74.1): exactly one names what is wrong.
/// Declared in the order of the §74.1 table, which is the precedence when a
/// value breaks several rules (SOG-2): `Ord` follows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Diagnostic {
    /// `profile` differs, or `objects` or `extensions` is missing or not a
    /// map (§15).
    InvalidRoot,
    /// An Object ID or `objects` key is not a canonical UUIDv7 (§19).
    InvalidObjectId,
    /// An object's `id` differs from its `objects` key (§20, §24).
    ObjectIdMismatch,
    /// A required base or Task field is absent (§23, §31).
    MissingRequiredField,
    /// A field has the wrong type (§32, §76).
    InvalidFieldType,
    /// `lifecycle`, `status` or `priority` is not a permitted value (§26,
    /// §33, §38).
    InvalidEnumValue,
    /// An `extensions` key is not a reverse-domain name (§18).
    InvalidExtensionNamespace,
    /// A Principal reference is not `p:` + base64url of 32 bytes (§27, §42).
    InvalidPrincipalRef,
    /// `created_at` is not an RFC 3339 UTC timestamp (§28).
    InvalidTimestamp,
    /// A date field is not a valid Gregorian `YYYY-MM-DD` (§35).
    InvalidLocalDate,
    /// `tags` or `assignees` is not a map, or a member is not `true` (§39,
    /// §42).
    InvalidCollectionRepresentation,
    /// A tag is empty or starts with `#` (§40).
    InvalidTag,
    /// `id`, `type` or `created_by` changed (§75).
    ImmutableFieldMutated,
    /// A Data Unit's Automerge change is not a change of the §8 actor of
    /// the unit's signer; it is not merged (§8, §11, SO-SEC1).
    ChangeActorMismatch,
    /// A Data Unit or Snapshot plaintext is not the §11 or §13 framing, or
    /// its Automerge bytes are not a valid chunk of the required type with
    /// a matching checksum, or cannot be parsed or loaded; nothing is
    /// merged (§11, §13).
    InvalidAutomergeBytes,
}

impl Diagnostic {
    /// The registry name, such as `INVALID_OBJECT_ID`.
    pub fn name(self) -> &'static str {
        match self {
            Diagnostic::InvalidRoot => "INVALID_ROOT",
            Diagnostic::InvalidObjectId => "INVALID_OBJECT_ID",
            Diagnostic::ObjectIdMismatch => "OBJECT_ID_MISMATCH",
            Diagnostic::MissingRequiredField => "MISSING_REQUIRED_FIELD",
            Diagnostic::InvalidFieldType => "INVALID_FIELD_TYPE",
            Diagnostic::InvalidEnumValue => "INVALID_ENUM_VALUE",
            Diagnostic::InvalidExtensionNamespace => "INVALID_EXTENSION_NAMESPACE",
            Diagnostic::InvalidPrincipalRef => "INVALID_PRINCIPAL_REF",
            Diagnostic::InvalidTimestamp => "INVALID_TIMESTAMP",
            Diagnostic::InvalidLocalDate => "INVALID_LOCAL_DATE",
            Diagnostic::InvalidCollectionRepresentation => "INVALID_COLLECTION_REPRESENTATION",
            Diagnostic::InvalidTag => "INVALID_TAG",
            Diagnostic::ImmutableFieldMutated => "IMMUTABLE_FIELD_MUTATED",
            Diagnostic::ChangeActorMismatch => "CHANGE_ACTOR_MISMATCH",
            Diagnostic::InvalidAutomergeBytes => "INVALID_AUTOMERGE_BYTES",
        }
    }
}

/// A Shared Objects profile error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProfileError {
    /// `PROFILE_INVALID` with its diagnostic (§74.1).
    Invalid(Diagnostic),
    /// `OBJECT_ID_COLLISION`: concurrent creations used one Object ID (§21).
    ObjectIdCollision,
    /// A local Automerge operation that failed. Carries Automerge's
    /// message. Received bytes that are not valid are
    /// [`Diagnostic::InvalidAutomergeBytes`] instead.
    Automerge(String),
    /// §14.1: the change's dependencies (listed) are not in the document
    /// yet. It was not applied; hold it and offer it again once they are.
    MissingDependencies(Vec<automerge::ChangeHash>),
    /// §14.1: the actor already has a change at this sequence number
    /// (equivocation, §26.2 of LFCP-WIRE-01, or a reused sequence). Not
    /// applied.
    SequenceTaken {
        /// The change's sequence number.
        seq: u64,
        /// The actor's latest sequence number in the document.
        latest: u64,
    },
    /// No object with this ID in the document.
    UnknownObject,
    /// The object is not a Task.
    NotATask,
    /// A value nests maps and lists deeper than
    /// [`values::MAX_READ_DEPTH`]; nothing was read. The validator reports
    /// such a value as `INVALID_FIELD_TYPE` instead.
    ValueTooDeep,
}

impl ProfileError {
    /// The profile-level code (§21, §74.1), or the LFCP code a profile
    /// error stands for (ACTOR_EQUIVOCATION), when there is one.
    pub fn code(&self) -> Option<&'static str> {
        match self {
            ProfileError::Invalid(_) => Some("PROFILE_INVALID"),
            ProfileError::ObjectIdCollision => Some("OBJECT_ID_COLLISION"),
            // §14.1 / LFCP-WIRE-01 §26.2: another change holds the actor's
            // sequence; the same code as sdk-ts and the server report.
            ProfileError::SequenceTaken { .. } => Some("ACTOR_EQUIVOCATION"),
            _ => None,
        }
    }

    /// The `PROFILE_INVALID` diagnostic, when there is one.
    pub fn diagnostic(&self) -> Option<Diagnostic> {
        match self {
            ProfileError::Invalid(d) => Some(*d),
            _ => None,
        }
    }
}

impl From<Diagnostic> for ProfileError {
    fn from(diagnostic: Diagnostic) -> ProfileError {
        ProfileError::Invalid(diagnostic)
    }
}

impl From<automerge::AutomergeError> for ProfileError {
    fn from(err: automerge::AutomergeError) -> ProfileError {
        ProfileError::Automerge(err.to_string())
    }
}

impl fmt::Display for ProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProfileError::Invalid(d) => write!(f, "PROFILE_INVALID: {}", d.name()),
            ProfileError::ObjectIdCollision => f.write_str("OBJECT_ID_COLLISION"),
            ProfileError::Automerge(message) => write!(f, "Automerge: {message}"),
            ProfileError::MissingDependencies(missing) => {
                write!(
                    f,
                    "{} dependencies are not in the document yet",
                    missing.len()
                )
            }
            ProfileError::SequenceTaken { seq, latest } => {
                write!(f, "actor sequence {seq} is taken (latest {latest})")
            }
            ProfileError::UnknownObject => f.write_str("no such object"),
            ProfileError::NotATask => f.write_str("the object is not a Task"),
            ProfileError::ValueTooDeep => f.write_str("a value nests too deep to read"),
        }
    }
}

impl std::error::Error for ProfileError {}
