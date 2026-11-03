#![no_main]
#[path = "../src/identity_authority.rs"]
mod identity_authority;
libfuzzer_sys::fuzz_target!(|data: &[u8]| identity_authority::check(data));
