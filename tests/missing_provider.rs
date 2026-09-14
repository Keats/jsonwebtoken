//! Isolated integration test: only meaningful when neither backend feature is on.
//! `cargo test --no-default-features --test missing_provider`
//! Installs a process default, so it must stay in its own test binary.

#![cfg(not(any(feature = "aws_lc_rs", feature = "rust_crypto")))]

use jsonwebtoken::crypto::{CryptoProvider, KeyUtils};
use jsonwebtoken::errors::{ErrorKind, new_error};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde::Serialize;

#[derive(Serialize)]
struct Claims {
    sub: &'static str,
}

static TEST_PROVIDER: CryptoProvider = CryptoProvider {
    signer_factory: |_, _| Err(new_error(ErrorKind::Provider("installed-test".to_string()))),
    verifier_factory: |_, _| Err(new_error(ErrorKind::Provider("installed-test".to_string()))),
    key_utils: KeyUtils::new_unimplemented(),
};

/// A caught panic must not consume the `install_default` slot.
#[test]
fn caught_panic_leaves_the_install_slot_free() {
    assert!(CryptoProvider::try_get_default().is_none());

    std::panic::set_hook(Box::new(|_| {}));
    let caught = std::panic::catch_unwind(|| {
        let _ = encode(
            &Header::default(),
            &Claims { sub: "b@b.com" },
            &EncodingKey::from_secret(b"secret"),
        );
    });
    let _ = std::panic::take_hook();
    assert!(caught.is_err(), "a missing provider should still panic");

    TEST_PROVIDER.install_default().expect("a caught panic must not consume the install slot");

    assert!(CryptoProvider::try_get_default().is_some());

    let err = encode(
        &Header::default(),
        &Claims { sub: "b@b.com" },
        &EncodingKey::from_secret(b"secret"),
    )
    .expect_err("the test provider is installed but does not sign");
    match err.kind() {
        ErrorKind::Provider(msg) => assert!(msg.contains("installed-test")),
        other => panic!("expected Provider after install_default, got {other:?}"),
    }
}
