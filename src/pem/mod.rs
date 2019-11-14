pub(crate) mod decoder;
mod encoder;

use crate::errors::Result;

/// Encode (n, e) components into the public PKCS1 PEM format
pub fn encode_rsa_public_pkcs1_pem(modulus: &[u8], exponent: &[u8]) -> Result<String> {
    encoder::encode_rsa_public_pkcs1_pem(modulus, exponent)
}

/// Encode (n, e) components into the public PKCS1 PEM format
pub fn encode_rsa_public_pkcs1_der(modulus: &[u8], exponent: &[u8]) -> Result<Vec<u8>> {
    encoder::encode_rsa_public_pkcs1_der(modulus, exponent)
}

/// TODO
pub fn encode_rsa_public_pkcs8_pem(modulus: &[u8], exponent: &[u8]) -> Result<String> {
    encoder::encode_rsa_public_pkcs8_pem(modulus, exponent)
}

/// TODO
pub fn encode_rsa_public_pkcs8_der(modulus: &[u8], exponent: &[u8]) -> Result<Vec<u8>> {
    encoder::encode_rsa_public_pkcs8_der(modulus, exponent)
}

/// TODO
pub fn encode_ec_public_pem(x_coordinate: &[u8]) -> Result<String> {
    encoder::encode_ec_public_pem(x_coordinate)
}

/// TODO
pub fn encode_ec_public_der(x_coordinate: &[u8]) -> Result<Vec<u8>> {
    encoder::encode_ec_public_der(x_coordinate)
}
