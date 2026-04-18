#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = jsonwebtoken::EncodingKey::from_rsa_pem(data);
});
