//! Deterministic CBOR codec.
//!
//! This module encodes and decodes the CBOR subset LFCP uses, with the
//! deterministic serialization the specification requires, and rejects
//! input that is not in that form instead of repairing it. It is written by
//! hand so the security-critical byte handling stays small and auditable.
//!
//! Placeholder: the codec arrives in LFCP-041.
