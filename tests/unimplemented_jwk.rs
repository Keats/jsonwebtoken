//! A `CryptoProvider` that opts out of JWK support reports that through the
//! `Result` these functions already return, rather than panicking.

use jsonwebtoken::crypto::KeyUtils;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::jwk::ThumbprintHash;

#[test]
fn unimplemented_jwk_utils_return_a_provider_error() {
    let utils = KeyUtils::new_unimplemented();

    let err = (utils.compute_digest)(&[], ThumbprintHash::SHA256).unwrap_err();
    match err.kind() {
        ErrorKind::Provider(msg) => assert!(msg.contains("JWKs"), "unexpected message: {msg}"),
        other => panic!("expected Provider, got {other:?}"),
    }

    assert!(matches!(
        (utils.rsa_pub_components_from_private_key)(&[]).unwrap_err().kind(),
        ErrorKind::Provider(_)
    ));
    assert!(matches!(
        (utils.rsa_pub_components_from_public_key)(&[]).unwrap_err().kind(),
        ErrorKind::Provider(_)
    ));
}
