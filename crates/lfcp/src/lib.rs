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
//! - [`wire`]: LFCP Wire structures and messages.
//!
//! `wire` is still empty: Control Plane, Data Plane and session code arrive
//! in LFCP-042 and LFCP-043.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod base;
pub mod cbor;
pub mod cose;
pub mod crypto;
pub mod principal;
pub mod wire;
