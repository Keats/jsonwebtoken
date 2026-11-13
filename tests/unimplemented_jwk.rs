//! `KeyUtils::new_unimplemented` returns `ErrorKind::Provider`.

use jsonwebtoken::Algorithm;
use jsonwebtoken::crypto::KeyUtils;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::jwk::{EllipticCurve, ThumbprintHash};

const UNIMPLEMENTED_ERROR: &str = "This CryptoProvider does not support JWKs";

#[test]
fn unimplemented_jwk_utils_return_a_provider_error() {
    let utils = KeyUtils::new_unimplemented();
    let curve = EllipticCurve::Ed25519;

    let cases = [
        (utils.compute_digest)(&[], ThumbprintHash::SHA256).unwrap_err(),
        (utils.rsa_pub_components_from_private_key)(&[]).unwrap_err(),
        (utils.rsa_pub_components_from_public_key)(&[]).unwrap_err(),
        (utils.ec_pub_components_from_private_key)(&[], Algorithm::ES256).unwrap_err(),
        (utils.ed_pub_components_from_private_key)(&[], &curve).unwrap_err(),
    ];
    for err in cases {
        match err.kind() {
            ErrorKind::Provider(msg) => assert_eq!(msg, UNIMPLEMENTED_ERROR),
            other => panic!("expected Provider, got {other:?}"),
        }
    }
}
