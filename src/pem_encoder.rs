use crate::errors::{ErrorKind, Result};
use pem::Pem;
use simple_asn1::{ASN1Block, BigInt, BigUint, OID};

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
        Err(_) => Err(ErrorKind::InvalidRsaKey.into()),
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
        Err(_) => Err(ErrorKind::InvalidRsaKey.into()),
    }
}

pub fn encode_ec_public_pem(x: &[u8]) -> Result<String> {
    Ok(pem::encode(&Pem { contents: encode_ec_public_der(x)?, tag: "PUBLIC KEY".to_string() }))
}

pub fn encode_ec_public_der(x: &[u8]) -> Result<Vec<u8>> {
    match simple_asn1::to_der(&encode_ec_public_asn1(x)) {
        Ok(bytes) => Ok(bytes),
        Err(_) => Err(ErrorKind::InvalidEcdsaKey.into()),
    }
}

fn encode_rsa_public_pksc8_asn1(modulus: &[u8], exponent: &[u8]) -> Result<ASN1Block> {
    let pksc1 = match simple_asn1::to_der(&encode_rsa_public_pksc1_asn1(modulus, exponent)) {
        Ok(bytes) => bytes,
        Err(_) => return Err(ErrorKind::InvalidRsaKey.into()),
    };
    Ok(ASN1Block::Sequence(
        0,
        vec![
            ASN1Block::Sequence(
                0,
                vec![
                    // rsaEncryption (PKCS #1)
                    ASN1Block::ObjectIdentifier(0, simple_asn1::oid!(1, 2, 840, 113_549, 1, 1, 1)),
                    ASN1Block::Null(0),
                ],
            ),
            // the second parameter takes the count of bits
            ASN1Block::BitString(0, pksc1.len() * 8, pksc1),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode_pem;
    use crate::keys::Key;
    use ring::{signature, signature::KeyPair};

    #[test]
    fn public_key_encoding_pkcs1() {
        let privkey_pem =
            decode_pem(include_str!("../tests/rsa/private_rsa_key_pkcs8.pem")).unwrap();
        let privkey = privkey_pem.as_key().unwrap();
        let ring_key = signature::RsaKeyPair::from_der(match privkey {
            Key::Der(bytes) => bytes,
            _ => panic!("Unexpected"),
        })
        .unwrap();
        let mut modulus = vec![0];
        modulus.extend(ring_key.public_key().modulus().big_endian_without_leading_zero());
        let exponent = ring_key.public_key().exponent();

        let public_key_pkcs1_pem = encode_rsa_public_pkcs1_pem(
            modulus.as_ref(),
            exponent.big_endian_without_leading_zero(),
        )
        .unwrap();
        assert_eq!(
            include_str!("../tests/rsa/public_rsa_key_pkcs1.pem").trim(),
            public_key_pkcs1_pem.replace('\r', "").trim()
        );

        let public_key_pkcs1_der = encode_rsa_public_pkcs1_der(
            modulus.as_ref(),
            exponent.big_endian_without_leading_zero(),
        )
        .unwrap();
        assert_eq!(
            include_bytes!("../tests/rsa/public_rsa_key.der").to_vec(),
            public_key_pkcs1_der
        );
    }

    #[test]
    fn public_key_encoding_pkcs8() {
        let privkey_pem =
            decode_pem(include_str!("../tests/rsa/private_rsa_key_pkcs8.pem")).unwrap();
        let privkey = privkey_pem.as_key().unwrap();
        let ring_key = signature::RsaKeyPair::from_der(match privkey {
            Key::Der(bytes) => bytes,
            _ => panic!("Unexpected"),
        })
        .unwrap();
        let mut modulus = vec![0];
        modulus.extend(ring_key.public_key().modulus().big_endian_without_leading_zero());
        let exponent = ring_key.public_key().exponent();

        let public_key_pkcs8 = encode_rsa_public_pkcs8_pem(
            modulus.as_ref(),
            exponent.big_endian_without_leading_zero(),
        )
        .unwrap();
        assert_eq!(
            include_str!("../tests/rsa/public_rsa_key_pkcs8.pem").trim(),
            public_key_pkcs8.replace('\r', "").trim()
        );
    }

    #[test]
    fn public_key_encoding() {
        let privkey_pem = decode_pem(include_str!("../tests/ec/private_ecdsa_key.pem")).unwrap();
        let privkey = privkey_pem.as_key().unwrap();
        let alg = &signature::ECDSA_P256_SHA256_FIXED_SIGNING;
        let ring_key = signature::EcdsaKeyPair::from_pkcs8(
            alg,
            match privkey {
                Key::Pkcs8(bytes) => bytes,
                _ => panic!("Unexpected"),
            },
        )
        .unwrap();

        let public_key_pem = encode_ec_public_pem(ring_key.public_key().as_ref()).unwrap();
        assert_eq!(
            include_str!("../tests/ec/public_ecdsa_key.pem").trim(),
            public_key_pem.replace('\r', "").trim()
        );

        let public_key_der = encode_ec_public_der(ring_key.public_key().as_ref()).unwrap();
        // The stored ".pk8" key is just the x coordinate of the EC key
        // It's not truly a pkcs8 formatted DER
        // To get around that, a prepended binary specifies the EC key, EC name,
        // and X coordinate length. The length is unlikely to change.. in the
        // event that it does, look at the pem file (convert base64 to hex) and find
        // where 0x03, 0x42 don't match up. 0x42 is the length.
        let mut stored_pk8_der = vec![
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06,
            0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        ];
        stored_pk8_der.extend(include_bytes!("../tests/ec/public_ecdsa_key.pk8").to_vec());
        assert_eq!(stored_pk8_der, public_key_der);
    }
}
