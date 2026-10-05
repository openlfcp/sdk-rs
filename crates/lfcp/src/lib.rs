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
//! - [`shared_objects`]: the Shared Objects profile on Automerge
//!   (SHARED-OBJECTS-PROFILE-01), carried in Data Units and Snapshots.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod base;
pub mod cbor;
pub mod cose;
pub mod crypto;
pub mod principal;
pub mod shared_objects;
pub mod wire;
