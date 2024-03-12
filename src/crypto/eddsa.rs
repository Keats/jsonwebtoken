#[cfg(feature = "fips")]
use aws_lc_rs as ring;

#[cfg(not(feature = "fips"))]
use ring;

use crate::algorithms::Algorithm;
use crate::errors::Result;
use crate::serialization::b64_encode;

/// Only used internally when signing or validating EdDSA, to map from our enum to the Ring EdDSAParameters structs.
pub(crate) fn alg_to_ec_verification(alg: Algorithm) -> &'static ring::signature::EdDSAParameters {
    // To support additional key subtypes, like Ed448, we would need to match on the JWK's ("crv")
    // parameter.
    match alg {
        Algorithm::EdDSA => &ring::signature::ED25519,
        _ => unreachable!("Tried to get EdDSA alg for a non-EdDSA algorithm"),
    }
}

/// The actual EdDSA signing + encoding
/// The key needs to be in PKCS8 format
pub fn sign(key: &[u8], message: &[u8]) -> Result<String> {
    let signing_key = ring::signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(key)?;
    let out = signing_key.sign(message);
    Ok(b64_encode(out))
}
