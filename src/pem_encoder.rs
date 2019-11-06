use crate::errors::{ErrorKind, Result};
use simple_asn1::{ASN1Block, BigUint, BigInt, OID};
use pem::{Pem};

extern crate base64;
extern crate pem;
extern crate simple_asn1;

pub fn encode_rsa_public_pkcs1_pem(modulus: &[u8], exponent: &[u8]) -> Result<String> {
    Ok(pem::encode(&Pem {
        contents: encode_rsa_public_pkcs1_der(modulus, exponent)?,
        tag: "RSA PUBLIC KEY".to_string(),
    }))
}

pub fn encode_rsa_public_pkcs1_der(modulus: &[u8], exponent: &[u8]) -> Result<Vec<u8>> {
    match simple_asn1::to_der(&encode_rsa_public_pksc1_asn1(modulus, exponent)) {
        Ok(bytes) => Ok(bytes),
        Err(_) => return Err(ErrorKind::InvalidRsaKey)?,
    }
}

pub fn encode_rsa_public_pkcs8_pem(modulus: &[u8], exponent: &[u8]) -> Result<String> {
    Ok(pem::encode(&Pem {
        contents: encode_rsa_public_pkcs8_der(modulus, exponent)?,
        tag: "PUBLIC KEY".to_string(),
    }))
}

pub fn encode_rsa_public_pkcs8_der(modulus: &[u8], exponent: &[u8]) -> Result<Vec<u8>> {
    match simple_asn1::to_der(&encode_rsa_public_pksc8_asn1(modulus, exponent)?) {
        Ok(bytes) => Ok(bytes),
        Err(_) => return Err(ErrorKind::InvalidRsaKey)?,
    }
}

pub fn encode_ec_public_pem(x: &[u8]) -> Result<String> {
    Ok(pem::encode(&Pem {
        contents: encode_ec_public_der(x)?,
        tag: "PUBLIC KEY".to_string(),
    }))
}

pub fn encode_ec_public_der(x: &[u8]) -> Result<Vec<u8>> {
    match simple_asn1::to_der(&encode_ec_public_asn1(x)) {
        Ok(bytes) => Ok(bytes),
        Err(_) => return Err(ErrorKind::InvalidEcdsaKey)?,
    }
}

fn encode_rsa_public_pksc8_asn1(modulus: &[u8], exponent: &[u8]) -> Result<ASN1Block> {
    let pksc1 = match simple_asn1::to_der(&encode_rsa_public_pksc1_asn1(modulus, exponent)) {
        Ok(bytes) => bytes,
        Err(_) => return Err(ErrorKind::InvalidRsaKey)?,
    };
    Ok(ASN1Block::Sequence(
        0,
        vec![
            ASN1Block::Sequence(
                0,
                vec![
                    // rsaEncryption (PKCS #1)
                    ASN1Block::ObjectIdentifier(0, simple_asn1::oid!(1,2,840,113549,1,1,1)),
                    ASN1Block::Null(0)
                ]
            ),
            // the second parameter takes the count of bits
            ASN1Block::BitString(0, pksc1.len() * 8, pksc1)
        ],
    ))
}

fn encode_rsa_public_pksc1_asn1(modulus: &[u8], exponent: &[u8]) -> ASN1Block {
    ASN1Block::Sequence(
        0,
        vec![
            ASN1Block::Integer(0, BigInt::from_signed_bytes_be(modulus)),
            ASN1Block::Integer(0, BigInt::from_signed_bytes_be(exponent)),
        ],
    )
}

fn encode_ec_public_asn1(x: &[u8]) -> ASN1Block {
    ASN1Block::Sequence(
        0,
        vec![
            ASN1Block::Sequence(
                0,
                vec![
                    // ecPublicKey (ANSI X9.62 public key type)
                    ASN1Block::ObjectIdentifier(0, simple_asn1::oid!(1, 2, 840, 10045, 2, 1)),
                    // prime256v1 (ANSI X9.62 named elliptic curve)
                    ASN1Block::ObjectIdentifier(0, simple_asn1::oid!(1, 2, 840, 10045, 3, 1, 7)),
                ],
            ),
            // the second parameter takes the count of bits
            ASN1Block::BitString(0, x.len() * 8, x.to_vec()),
        ],
    )
}
