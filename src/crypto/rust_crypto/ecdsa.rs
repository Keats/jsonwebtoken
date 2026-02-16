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
use rsa::pkcs8::DecodePrivateKey;
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

// P521 (ES512) requires custom macros instead of the generic ones because:
// 1. SigningKey521 doesn't implement DecodePrivateKey (no from_pkcs8_der), so we manually extract the key
// 2. SigningKey521 doesn't have sign_recoverable(), only the regular sign() method
// These API differences in the p521 crate necessitate separate implementations.
// P521 (ES512) signer - requires PKCS8 extraction
macro_rules! define_p521_signer {
    ($name:ident, $alg:expr) => {
        pub struct $name(SigningKey521);

        impl $name {
            pub(crate) fn new(encoding_key: &EncodingKey) -> Result<Self> {
                if encoding_key.family() != AlgorithmFamily::Ec {
                    return Err(new_error(ErrorKind::InvalidKeyFormat));
                }

                // For P521, we need to extract the 66-byte key from PKCS8 DER format
                let pkcs8_der = encoding_key.inner();
                let key_bytes = extract_p521_key_from_pkcs8(pkcs8_der)?;

                // Convert to FieldBytes and create SigningKey
                let field_bytes: &p521::FieldBytes = key_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| ErrorKind::InvalidEcdsaKey)?;
                
                Ok(Self(
                    SigningKey521::from_bytes(field_bytes)
                        .map_err(|_| ErrorKind::InvalidEcdsaKey)?,
                ))
            }
        }

        impl Signer<Vec<u8>> for $name {
            fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, Error> {
                let signature: Signature521 = self.0.sign(msg);
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

// P521 (ES512) verifier
macro_rules! define_p521_verifier {
    ($name:ident, $alg:expr) => {
        pub struct $name(VerifyingKey521);

        impl $name {
            pub(crate) fn new(decoding_key: &DecodingKey) -> Result<Self> {
                if decoding_key.family() != AlgorithmFamily::Ec {
                    return Err(new_error(ErrorKind::InvalidKeyFormat));
                }

                Ok(Self(
                    VerifyingKey521::from_sec1_bytes(decoding_key.as_bytes())
                        .map_err(|_| ErrorKind::InvalidEcdsaKey)?,
                ))
            }
        }

        impl Verifier<Vec<u8>> for $name {
            fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), Error> {
                self.0
                    .verify(msg, &Signature521::from_slice(signature).map_err(Error::from_source)?)
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

define_p521_signer!(Es512Signer, Algorithm::ES512);
define_p521_verifier!(Es512Verifier, Algorithm::ES512);

/// Extract the 66-byte P-521 private key from PKCS8 DER format
fn extract_p521_key_from_pkcs8(pkcs8_der: &[u8]) -> Result<Vec<u8>> {
    use rsa::pkcs8::PrivateKeyInfo;

    // Decode as PKCS8 structure
    let private_key_info = PrivateKeyInfo::try_from(pkcs8_der)
        .map_err(|_| ErrorKind::InvalidKeyFormat)?;

    // The private key bytes should be in the private_key field
    // For P-521 in PKCS8, this is a DER-encoded ECPrivateKey which contains the 66-byte key
    let private_key_bytes = private_key_info.private_key;

    // Parse the ECPrivateKey structure (which is a SEQUENCE with the key as an OCTET STRING)
    use simple_asn1::ASN1Block;
    let asn1_blocks = simple_asn1::from_der(private_key_bytes)
        .map_err(|_| ErrorKind::InvalidKeyFormat)?;

    for block in asn1_blocks {
        if let ASN1Block::Sequence(_, entries) = block {
            // ECPrivateKey ::= SEQUENCE {
            //   version        INTEGER { ecPrivkeyVer1(0) }
            //   privateKey     OCTET STRING,
            //   parameters [0] ECParameters OPTIONAL,
            //   publicKey  [1] BIT STRING OPTIONAL
            // }
            if entries.len() >= 2 {
                // The second element (index 1) should be the privateKey OCTET STRING
                if let ASN1Block::OctetString(_, key_bytes) = &entries[1] {
                    if key_bytes.len() == 66 {
                        return Ok(key_bytes.clone());
                    }
                }
            }
        }
    }

    Err(new_error(ErrorKind::InvalidKeyFormat))
}
