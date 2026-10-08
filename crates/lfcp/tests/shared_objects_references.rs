//! SHARED-OBJECTS-PROFILE-01 §11.3 (canonical change encoding): changes
//! automerge 0.12 cannot write back out, or that make it abort, are
//! refused before it parses them.
//!
//! The repros come from an external review (the Data Unit plaintexts as
//! given, in hex).

use lfcp::shared_objects::framing;
use lfcp::shared_objects::{Diagnostic, ProfileError};

const INVALID: ProfileError = ProfileError::Invalid(Diagnostic::InvalidAutomergeBytes);

fn bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// F2: an object counter above 2^32 (automerge panics building its ID).
const F2: &str = concat!(
    "82015901fa856f4a834766b74501ef03017c9948439b57e1ab2be4cd6368e3e3ee1a0fac2ef0116c2308d24171c71d66",
    "d0206c9e962e697f0691ba727ddc378cc21f9b1d580e67f7b1e7f9612ebdab63c5830202000000070105028403150434",
    "024203560370030001ff01000001817e02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021",
    "22232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748492ef0116c2308d241",
    "71c71d66d0206c9e962e697f0691ba727ddc378cc21f9b1d580e67f7b1e7f9612ebdab63c58302020000000701050284",
    "03150434024203560370030001ff01001001817e02030405060708090a0b0c0d0e0f101112131415161718191abf1c1d",
    "1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d",
    "4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d",
    "7e7f80018101820183018401850186018701880189018a018b018c018d018e018f019001910192019301940195019601",
    "9701980199019a019b019c019d019e019f01a001a101a201a301ee01ef01f001f101f201f301f401f501f601f701f801",
    "f901fa01fb01fc01fd01fe01ff018002800201648002800200800200800200",
);
/// F3a: S01's profile.init with its insert column run 3 → 13.
const F3A: &str = concat!(
    "82015891856f4a83358fd6a901860100206c9e962e697f0691ba727ddc378cc21f9b1d580e67f7b1e7f9612ebdab63c5",
    "830101000c70726f66696c652e696e69740006151c340142045605571e70027d0770726f66696c65076f626a65637473",
    "0a657874656e73696f6e730d7f0102007fe60302006f72672e6f70656e6c6663702e7368617265642d6f626a65637473",
    "2e76310300",
);
#[test]
fn f2_a_counter_above_2_32_is_refused_before_automerge_parses_it() {
    assert_eq!(framing::decode_change(&bytes(F2)).err(), Some(INVALID));
}

#[test]
fn f3a_a_column_with_more_rows_than_operations_is_refused() {
    assert_eq!(framing::decode_change(&bytes(F3A)).err(), Some(INVALID));
}
