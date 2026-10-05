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
//! - [`cose`]: canonical COSE structures;
//! - [`wire`]: LFCP Wire structures and messages.
//!
//! No module contains protocol code yet: the primitives arrive in LFCP-041.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod base;
pub mod cbor;
pub mod cose;
pub mod crypto;
pub mod wire;
