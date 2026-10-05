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
//! - [`snapshot`]: Snapshots: payload, key, AAD, seal and open.
//! - [`control`]: typed Control Records and Control Chain validation.
//! - [`key_package`]: HPKE Key Packages that deliver a DEK.
//! - [`message`]: the message envelope and every typed body.
//! - [`session`]: the HELLO / CHALLENGE / AUTH / READY handshake.
//!
//! Capability evaluation arrives in LFCP-042b2 and epoch cutoff in
//! LFCP-042b3.

pub mod control;
pub mod data_unit;
pub mod frontier;
pub mod key_package;
pub mod keys;
pub mod message;
pub mod session;
pub mod snapshot;

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

/// Field `key` as a text string.
pub(crate) fn text_field<'a>(value: &'a Value, key: u64, err: &Error) -> Result<&'a str, Error> {
    value
        .get_uint(key)
        .and_then(Value::as_text)
        .ok_or_else(|| err.clone())
}

/// Field `key` as an array of unsigned integers.
pub(crate) fn uint_array_field(value: &Value, key: u64, err: &Error) -> Result<Vec<u64>, Error> {
    value
        .get_uint(key)
        .and_then(Value::as_array)
        .ok_or_else(|| err.clone())?
        .iter()
        .map(|item| item.as_u64().ok_or_else(|| err.clone()))
        .collect()
}

/// Unsigned integers as a CBOR array.
pub(crate) fn uint_array(items: &[u64]) -> Value {
    Value::Array(items.iter().map(|&n| Value::Unsigned(n)).collect())
}
