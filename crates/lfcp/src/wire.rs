//! LFCP Wire structures and messages.
//!
//! This module holds the LFCP-WIRE-01 data model and its validation. It is
//! application-agnostic: it knows nothing about Shared Objects, Markdown or
//! any editor. Data Unit plaintexts are opaque bytes (§27).
//!
//! - [`keys`]: DEKs, commitments, actor and Snapshot keys, nonces.
//!
//! Control Records arrive in LFCP-042b, Key Packages in LFCP-042c and
//! session messages in LFCP-043.

pub mod keys;
