#![no_main]

#[path = "../src/device_certificate.rs"]
mod device_certificate;

libfuzzer_sys::fuzz_target!(|data: &[u8]| device_certificate::check(data));
