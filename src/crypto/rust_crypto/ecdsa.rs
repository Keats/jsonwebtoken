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
                if encoding_key.family != AlgorithmFamily::Ec {
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
                if decoding_key.family != AlgorithmFamily::Ec {
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

// P521 (ES512) signer - uses different API (no sign_recoverable, different PKCS8 extraction)
macro_rules! define_p521_signer {
    ($name:ident, $alg:expr) => {
        pub struct $name(SigningKey521);

        impl $name {
            pub(crate) fn new(encoding_key: &EncodingKey) -> Result<Self> {
                if encoding_key.family != AlgorithmFamily::Ec {
                    return Err(new_error(ErrorKind::InvalidKeyFormat));
                }

                // Extract the raw 66-byte key from PKCS8 DER format
                let pkcs8_der = encoding_key.inner();
                let key_bytes = extract_p521_key_from_pkcs8(pkcs8_der)?;

                // Verify correct length and convert to fixed-size array safely
                if key_bytes.len() != 66 {
                    return Err(new_error(ErrorKind::InvalidEcdsaKey));
                }
                
                // Safe conversion using slice_as_array pattern
                let mut key_array = [0u8; 66];
                key_array.copy_from_slice(&key_bytes);
                
                // Convert array to GenericArray reference using From trait
                let field_bytes: &p521::FieldBytes = key_array.as_slice().try_into()
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
                if decoding_key.family != AlgorithmFamily::Ec {
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
/// 
/// P-521 keys in PKCS8 format have a different structure than the standard P256/P384:
/// PKCS8 ::= SEQUENCE {
///   version INTEGER,
///   algorithm AlgorithmIdentifier,
///   PrivateKey OCTET STRING
/// }
/// The PrivateKey octet string contains a DER-encoded ECPrivateKey SEQUENCE:
/// ECPrivateKey ::= SEQUENCE {
///   version INTEGER,
///   privateKey OCTET STRING (66 bytes for P-521)
/// }
fn extract_p521_key_from_pkcs8(pkcs8_der: &[u8]) -> Result<Vec<u8>> {
    let asn1_blocks = simple_asn1::from_der(pkcs8_der)
        .map_err(|_| ErrorKind::InvalidKeyFormat)?;

    for block in asn1_blocks {
        if let simple_asn1::ASN1Block::Sequence(_, entries) = block {
            // The third element (index 2) should be the privateKey OCTET STRING
            if entries.len() >= 3 {
                if let simple_asn1::ASN1Block::OctetString(_, value) = &entries[2] {
                    // The value is DER-encoded and contains a SEQUENCE with the actual key
                    if let Ok(inner_blocks) = simple_asn1::from_der(value) {
                        for inner_block in inner_blocks {
                            if let simple_asn1::ASN1Block::Sequence(_, inner_entries) = inner_block {
                                // Look for the OCTET STRING within this sequence
                                for inner_entry in inner_entries {
                                    if let simple_asn1::ASN1Block::OctetString(_, key_value) = inner_entry {
                                        // This should be our 66-byte key
                                        if key_value.len() == 66 {
                                            return Ok(key_value.to_vec());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Err(new_error(ErrorKind::InvalidKeyFormat))
}
