//! LFCP Wire structures and messages.
//!
//! This module holds the LFCP-WIRE-01 data model and its validation. It is
//! application-agnostic: it knows nothing about Shared Objects, Markdown or
//! any editor. Data Unit plaintexts are opaque bytes (§27).
//!
//! - [`keys`]: DEKs, commitments, actor and Snapshot keys, nonces.
//! - [`data_unit`]: Data Units: payload, AAD, seal and open, actor hash
//!   chain and equivocation.
//! - [`frontier`]: Actor Have entries and canonical frontiers.
//!
//! Control Records arrive in LFCP-042b, Key Packages in LFCP-042c and
//! session messages in LFCP-043.

pub mod data_unit;
pub mod frontier;
pub mod keys;

use crate::base::{Error, Hash32, PrincipalId, ResourceId};
use crate::cbor::Value;

/// Check that `value` is a map whose keys are exactly the unsigned integers
/// in `required`, plus any of those in `optional`. LFCP payload maps are
/// closed: any other key fails with `err`.
pub(crate) fn check_closed_map(
    value: &Value,
    required: &[u64],
    optional: &[u64],
    err: Error,
) -> Result<(), Error> {
    let entries = value.as_map().ok_or(err.clone())?;
    let allowed = |key: &Value| {
        key.as_u64()
            .is_some_and(|k| required.contains(&k) || optional.contains(&k))
    };
    let present = |k: u64| value.get_uint(k).is_some();
    if entries.iter().all(|(key, _)| allowed(key)) && required.iter().all(|&k| present(k)) {
        Ok(())
    } else {
        Err(err)
    }
}

/// Field `key` as an unsigned integer.
pub(crate) fn uint_field(value: &Value, key: u64, err: &Error) -> Result<u64, Error> {
    value
        .get_uint(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| err.clone())
}

/// Field `key` as a byte string.
pub(crate) fn bytes_field<'a>(value: &'a Value, key: u64, err: &Error) -> Result<&'a [u8], Error> {
    value
        .get_uint(key)
        .and_then(Value::as_bytes)
        .ok_or_else(|| err.clone())
}

/// Field `key` as a 32-byte byte string.
pub(crate) fn bytes32_field(value: &Value, key: u64, err: &Error) -> Result<[u8; 32], Error> {
    bytes_field(value, key, err)?
        .try_into()
        .map_err(|_| err.clone())
}

pub(crate) fn resource_field(value: &Value, key: u64, err: &Error) -> Result<ResourceId, Error> {
    bytes32_field(value, key, err).map(ResourceId::from_bytes)
}

pub(crate) fn principal_field(value: &Value, key: u64, err: &Error) -> Result<PrincipalId, Error> {
    bytes32_field(value, key, err).map(PrincipalId::from_bytes)
}

pub(crate) fn hash_field(value: &Value, key: u64, err: &Error) -> Result<Hash32, Error> {
    bytes32_field(value, key, err).map(Hash32::from_bytes)
}
