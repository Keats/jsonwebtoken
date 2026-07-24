#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = jsonwebtoken::DecodingKey::from_ec_pem(data);
});
