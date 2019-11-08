use serde::de::DeserializeOwned;

use crate::validation::{Validation, validate};
use crate::header::Header;
use crate::errors::{new_error, ErrorKind, Result};
use crate::serialization::{from_jwt_part_claims, TokenData};


pub fn decode_rsa_jwk<T: DeserializeOwned>(
    token: &str,
    modulus: &[u8],
    exponent: &[u8],
    validation: &Validation,
) -> Result<TokenData<T>> {
    let (signature, signing_input) = expect_two!(token.rsplitn(2, '.'));
    let (claims, header) = expect_two!(signing_input.rsplitn(2, '.'));
    let header = Header::from_encoded(header)?;

    if !verify(signature, signing_input, key, header.alg)? {
        return Err(new_error(ErrorKind::InvalidSignature));
    }

    if !validation.algorithms.contains(&header.alg) {
        return Err(new_error(ErrorKind::InvalidAlgorithm));
    }

    let (decoded_claims, claims_map): (T, _) = from_jwt_part_claims(claims)?;
    validate(&claims_map, validation)?;

    Ok(TokenData { header, claims: decoded_claims })
}
