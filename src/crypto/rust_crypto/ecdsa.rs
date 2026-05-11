//! Implementations of the [`JwtSigner`] and [`JwtVerifier`] traits for the
//! ECDSA family of algorithms using RustCrypto
use crate::algorithms::AlgorithmFamily;
use crate::crypto::{JwtSigner, JwtVerifier};
use crate::errors::{ErrorKind, Result, new_error};
use crate::{Algorithm, DecodingKey, EncodingKey};
use p256::ecdsa::{
    Signature as Signature256, SigningKey as SigningKey256, VerifyingKey as VerifyingKey256,
};
use p384::ecdsa::{
    Signature as Signature384, SigningKey as SigningKey384, VerifyingKey as VerifyingKey384,
};
use p521::ecdsa::{
    Signature as Signature521, SigningKey as SigningKey521, VerifyingKey as VerifyingKey521,
};
use pkcs8::DecodePrivateKey;
use signature::{Error, Signer, Verifier};

macro_rules! define_ecdsa_signer {
    ($name:ident, $alg:expr, $signing_key:ty) => {
        pub struct $name($signing_key);

        impl $name {
            pub(crate) fn new(encoding_key: &EncodingKey) -> Result<Self> {
                if encoding_key.family() != AlgorithmFamily::Ec {
                    return Err(new_error(ErrorKind::InvalidKeyFormat));
                }

                Ok(Self(
                    <$signing_key>::from_pkcs8_der(encoding_key.inner())
                        .map_err(|_| ErrorKind::InvalidEcdsaKey)?,
                ))
            }
        }

        impl Signer<Vec<u8>> for $name {
            fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, Error> {
                let signature = self.0.sign_recoverable(msg).map_err(Error::from_source)?.0;
                Ok(signature.to_vec())
            }
        }

        impl JwtSigner for $name {
            fn algorithm(&self) -> Algorithm {
                $alg
            }
        }
    };
}

macro_rules! define_ecdsa_verifier {
    ($name:ident, $alg:expr, $verifying_key:ty, $signature:ty) => {
        pub struct $name($verifying_key);

        impl $name {
            pub(crate) fn new(decoding_key: &DecodingKey) -> Result<Self> {
                if decoding_key.family() != AlgorithmFamily::Ec {
                    return Err(new_error(ErrorKind::InvalidKeyFormat));
                }

                Ok(Self(
                    <$verifying_key>::from_sec1_bytes(decoding_key.as_bytes())
                        .map_err(|_| ErrorKind::InvalidEcdsaKey)?,
                ))
            }
        }

        impl Verifier<Vec<u8>> for $name {
            fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), Error> {
                self.0
                    .verify(msg, &<$signature>::from_slice(signature).map_err(Error::from_source)?)
                    .map_err(Error::from_source)?;
                Ok(())
            }
        }

        impl JwtVerifier for $name {
            fn algorithm(&self) -> Algorithm {
                $alg
            }
        }
    };
}

define_ecdsa_signer!(Es256Signer, Algorithm::ES256, SigningKey256);
define_ecdsa_signer!(Es384Signer, Algorithm::ES384, SigningKey384);

define_ecdsa_verifier!(Es256Verifier, Algorithm::ES256, VerifyingKey256, Signature256);
define_ecdsa_verifier!(Es384Verifier, Algorithm::ES384, VerifyingKey384, Signature384);

// P521 (ES512) signer - uses sign() instead of sign_recoverable() since P521 doesn't support it
pub struct Es512Signer(SigningKey521);

impl Es512Signer {
    pub(crate) fn new(encoding_key: &EncodingKey) -> Result<Self> {
        if encoding_key.family() != AlgorithmFamily::Ec {
            return Err(new_error(ErrorKind::InvalidKeyFormat));
        }

        // Use pkcs8 to parse the PKCS8 wrapper and extract the ECPrivateKey DER
        use pkcs8::PrivateKeyInfo;
        let private_key_info = PrivateKeyInfo::try_from(encoding_key.inner())
            .map_err(|_| ErrorKind::InvalidKeyFormat)?;

        // The private_key field contains the DER-encoded ECPrivateKey
        let ec_private_key_der = private_key_info.private_key;

        // Use simple_asn1 to parse the ECPrivateKey structure
        use simple_asn1::ASN1Block;
        let asn1_blocks =
            simple_asn1::from_der(ec_private_key_der).map_err(|_| ErrorKind::InvalidKeyFormat)?;

        // Find the OCTET STRING containing the 66-byte private key
        for block in asn1_blocks {
            if let ASN1Block::Sequence(_, entries) = block {
                // ECPrivateKey ::= SEQUENCE {
                //   version        INTEGER,
                //   privateKey     OCTET STRING,  // This is what we need (index 1)
                //   parameters [0] ECParameters OPTIONAL,
                //   publicKey  [1] BIT STRING OPTIONAL
                // }
                if entries.len() >= 2 {
                    if let ASN1Block::OctetString(_, key_bytes) = &entries[1] {
                        if key_bytes.len() == 66 {
                            let mut field_bytes = p521::FieldBytes::default();
                            field_bytes.copy_from_slice(key_bytes);
                            return Ok(Self(
                                SigningKey521::from_bytes(&field_bytes)
                                    .map_err(|_| ErrorKind::InvalidEcdsaKey)?,
                            ));
                        }
                    }
                }
            }
        }

        Err(new_error(ErrorKind::InvalidKeyFormat))
    }
}

impl Signer<Vec<u8>> for Es512Signer {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, Error> {
        let signature: Signature521 = self.0.sign(msg);
        Ok(signature.to_vec())
    }
}

impl JwtSigner for Es512Signer {
    fn algorithm(&self) -> Algorithm {
        Algorithm::ES512
    }
}

define_ecdsa_verifier!(Es512Verifier, Algorithm::ES512, VerifyingKey521, Signature521);
