//! Independent Rust implementation of LFCP.
//!
//! The crate is written against the LFCP specifications and test vectors in
//! `openlfcp/spec` at the pinned baseline (see `spec.lock` at the repository
//! root), not ported from another implementation.
//!
//! Modules, in dependency order (a module only uses the ones above it):
//!
//! - [`base`]: identifiers, errors and byte helpers shared by every layer;
//! - [`crypto`]: thin wrappers over established cryptographic crates;
//! - [`cbor`]: the deterministic CBOR codec;
//! - [`principal`]: Principal IDs, descriptors and keys;
//! - [`cose`]: canonical COSE structures;
//! - [`wire`]: LFCP Wire structures and messages;
//! - `shared_objects` (feature `shared-objects`): the Shared Objects profile
//!   on Automerge (SHARED-OBJECTS-PROFILE-01), carried in Data Units and
//!   Snapshots. The default build is the protocol core only, without
//!   Automerge;
//! - `shared_sections` (feature `shared-sections`): the Shared Sections
//!   profile (SHARED-SECTIONS-PROFILE-01, Working Draft for MVP 0.2), which
//!   inherits the Shared Objects engine rules.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod base;
pub mod cbor;
pub mod cose;
pub mod crypto;
pub mod principal;
#[cfg(feature = "shared-objects")]
pub mod shared_objects;
#[cfg(feature = "shared-sections")]
pub mod shared_sections;
pub mod wire;
