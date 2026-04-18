use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::errors::{ErrorKind, Result};

/// Supported PEM files for EC and RSA Public and Private Keys
#[derive(Debug, PartialEq)]
enum PemType {
    EcPublic,
    EcPrivate,
    RsaPublic,
    RsaPrivate,
    EdPublic,
    EdPrivate,
}

#[derive(Debug, PartialEq)]
enum Standard {
    // Only for RSA
    Pkcs1,
    // RSA/EC
    Pkcs8,
}

#[derive(Debug, PartialEq)]
enum Classification {
    Ec,
    Ed,
    Rsa,
}

/// The return type of a successful PEM encoded key with `decode_pem`
///
/// This struct gives a way to parse a string to a key for use in jsonwebtoken.
/// A struct is necessary as it provides the lifetime of the key
///
/// PEM public private keys are encoded PKCS#1 or PKCS#8
/// You will find that with PKCS#8 RSA keys that the PKCS#1 content
/// is embedded inside. This is what is provided to ring via `Key::Der`
/// For EC keys, they are always PKCS#8 on the outside but like RSA keys
/// EC keys contain a section within that ultimately has the configuration
/// that ring uses.
/// Documentation about these formats is at
/// PKCS#1: https://tools.ietf.org/html/rfc8017
/// PKCS#8: https://tools.ietf.org/html/rfc5958
#[derive(Debug, ZeroizeOnDrop, Zeroize)]
pub(crate) struct PemEncodedKey {
    content: Vec<u8>,
    #[zeroize(skip)]
    pem_type: PemType,
    #[zeroize(skip)]
    standard: Standard,
}

impl PemEncodedKey {
    /// Read the PEM file for later key use
    pub fn new(input: &[u8]) -> Result<PemEncodedKey> {
        match pem::parse(input) {
            Ok(content) => {
                match content.tag() {
                    // This handles a PKCS#1 RSA Private key
                    "RSA PRIVATE KEY" => Ok(PemEncodedKey {
                        content: content.into_contents(),
                        pem_type: PemType::RsaPrivate,
                        standard: Standard::Pkcs1,
                    }),
                    "RSA PUBLIC KEY" => Ok(PemEncodedKey {
                        content: content.into_contents(),
                        pem_type: PemType::RsaPublic,
                        standard: Standard::Pkcs1,
                    }),

                    // No "EC PRIVATE KEY"
                    // https://security.stackexchange.com/questions/84327/converting-ecc-private-key-to-pkcs1-format
                    // "there is no such thing as a "PKCS#1 format" for elliptic curve (EC) keys"

                    // This handles PKCS#8 certificates and public & private keys
                    tag @ "PRIVATE KEY" | tag @ "PUBLIC KEY" | tag @ "CERTIFICATE" => {
                        let is_private = tag == "PRIVATE KEY";
                        let pem_type = match classify_der(content.contents())
                            .ok_or(ErrorKind::InvalidKeyFormat)?
                        {
                            Classification::Ec if is_private => PemType::EcPrivate,
                            Classification::Ec => PemType::EcPublic,
                            Classification::Ed if is_private => PemType::EdPrivate,
                            Classification::Ed => PemType::EdPublic,
                            Classification::Rsa if is_private => PemType::RsaPrivate,
                            Classification::Rsa => PemType::RsaPublic,
                        };
                        Ok(PemEncodedKey {
                            content: content.into_contents(),
                            pem_type,
                            standard: Standard::Pkcs8,
                        })
                    }

                    // Unknown/unsupported type
                    _ => Err(ErrorKind::InvalidKeyFormat.into()),
                }
            }
            Err(_) => Err(ErrorKind::InvalidKeyFormat.into()),
        }
    }

    /// Can only be PKCS8
    pub fn as_ec_private_key(&self) -> Result<&[u8]> {
        match self.standard {
            Standard::Pkcs1 => Err(ErrorKind::InvalidKeyFormat.into()),
            Standard::Pkcs8 => match self.pem_type {
                PemType::EcPrivate => Ok(self.content.as_slice()),
                _ => Err(ErrorKind::InvalidKeyFormat.into()),
            },
        }
    }

    /// Can only be PKCS8
    pub fn as_ec_public_key(&self) -> Result<&[u8]> {
        match self.standard {
            Standard::Pkcs1 => Err(ErrorKind::InvalidKeyFormat.into()),
            Standard::Pkcs8 => match self.pem_type {
                PemType::EcPublic => extract_first_bitstring_der(&self.content)
                    .ok_or_else(|| ErrorKind::InvalidKeyFormat.into()),
                _ => Err(ErrorKind::InvalidKeyFormat.into()),
            },
        }
    }

    /// Can only be PKCS8
    pub fn as_ed_private_key(&self) -> Result<&[u8]> {
        match self.standard {
            Standard::Pkcs1 => Err(ErrorKind::InvalidKeyFormat.into()),
            Standard::Pkcs8 => match self.pem_type {
                PemType::EdPrivate => Ok(self.content.as_slice()),
                _ => Err(ErrorKind::InvalidKeyFormat.into()),
            },
        }
    }

    /// Can only be PKCS8
    pub fn as_ed_public_key(&self) -> Result<&[u8]> {
        match self.standard {
            Standard::Pkcs1 => Err(ErrorKind::InvalidKeyFormat.into()),
            Standard::Pkcs8 => match self.pem_type {
                PemType::EdPublic => extract_first_bitstring_der(&self.content)
                    .ok_or_else(|| ErrorKind::InvalidKeyFormat.into()),
                _ => Err(ErrorKind::InvalidKeyFormat.into()),
            },
        }
    }

    /// Can be PKCS1 or PKCS8
    pub fn as_rsa_key(&self) -> Result<&[u8]> {
        match self.standard {
            Standard::Pkcs1 => Ok(self.content.as_slice()),
            Standard::Pkcs8 => match self.pem_type {
                PemType::RsaPrivate | PemType::RsaPublic => {
                    extract_first_bitstring_der(&self.content)
                        .ok_or_else(|| ErrorKind::InvalidKeyFormat.into())
                }
                _ => Err(ErrorKind::InvalidKeyFormat.into()),
            },
        }
    }
}

const TAG_BIT_STRING: u8 = 0x03;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_OID: u8 = 0x06;
const TAG_SEQUENCE: u8 = 0x30;

// This really just finds and returns the first bitstring or octet string
// Which is the x coordinate for EC public keys
// And the DER contents of an RSA key
// Though PKCS#11 keys shouldn't have anything else.
// It will get confusing with certificates.
fn extract_first_bitstring_der(bytes: &[u8]) -> Option<&[u8]> {
    let mut stack = vec![bytes];

    while let Some(bytes) = stack.pop() {
        let Some((tag, value, rest)) = read_tlv(bytes) else {
            continue; // Skip invalid TLV
        };

        if !rest.is_empty() {
            stack.push(rest);
        }

        match tag {
            TAG_BIT_STRING => {
                if value.is_empty() {
                    return None; // Missing padding length
                } else if value[0] != 0 {
                    return None; // Padding length must be zero for cryptographic keys
                }
                return Some(&value[1..]);
            }
            TAG_OCTET_STRING => return Some(value),
            TAG_SEQUENCE => {
                stack.push(value);
            }
            _ => {}
        }
    }

    None
}

/// Find whether this is EC, RSA, or Ed
fn classify_der(bytes: &[u8]) -> Option<Classification> {
    const EC_PUBLIC_KEY_OID: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]; // 1.2.840.10045.2.1
    const RSA_PUBLIC_KEY_OID: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]; // 1.2.840.113549.1.1.1
    const ED25519_OID: &[u8] = &[0x2B, 0x65, 0x70]; // 1.3.101.112

    let mut stack = vec![bytes];

    while let Some(bytes) = stack.pop() {
        let Some((tag, value, rest)) = read_tlv(bytes) else {
            continue; // Skip invalid TLV
        };

        if !rest.is_empty() {
            stack.push(rest);
        }

        if tag == TAG_OID {
            match value {
                EC_PUBLIC_KEY_OID => return Some(Classification::Ec),
                RSA_PUBLIC_KEY_OID => return Some(Classification::Rsa),
                ED25519_OID => return Some(Classification::Ed),
                _ => {}
            }
        } else if tag == TAG_SEQUENCE {
            stack.push(value);
        }
    }

    None
}

/// Returns `Some((tag, value, rest))` or `None` if the TLV is invalid.
fn read_tlv(mut bytes: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    if bytes.len() < 2 {
        return None;
    }

    let tag = bytes[0];
    let len = bytes[1];
    bytes = &bytes[2..];

    let len = if len < 0x80 {
        len as usize
    } else {
        let len_len = (len & 0x7f) as usize;
        if len_len == 0 {
            return None; // Indefinite length
        } else if size_of::<usize>() < len_len {
            return None; // Too long; prevents usize overflow
        } else if bytes.len() < len_len {
            return None; // Not enough bytes
        }
        let (len_bytes, rest) = bytes.split_at(len_len);
        bytes = rest;
        len_bytes.iter().fold(0, |acc, &x| acc * 256 + x as usize)
    };

    if bytes.len() < len {
        return None; // Not enough bytes
    }

    let (value, rest) = bytes.split_at(len);
    Some((tag, value, rest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_ec_key() {
        let pem = pem::parse(include_bytes!("../../tests/ecdsa/public_ecdsa_key.pem")).unwrap();
        assert_eq!(classify_der(pem.contents()), Some(Classification::Ec));
    }

    #[test]
    fn classify_rsa_key() {
        let pem = pem::parse(include_bytes!("../../tests/rsa/public_rsa_key_pkcs8.pem")).unwrap();
        assert_eq!(classify_der(pem.contents()), Some(Classification::Rsa));
    }

    #[test]
    fn classify_ed25519_key() {
        let pem = pem::parse(include_bytes!("../../tests/eddsa/public_ed25519_key.pem")).unwrap();
        assert_eq!(classify_der(pem.contents()), Some(Classification::Ed));
    }

    #[test]
    fn ec_public_key_extraction() {
        let key =
            PemEncodedKey::new(include_bytes!("../../tests/ecdsa/public_ecdsa_key.pem")).unwrap();
        let bytes = key.as_ec_public_key().unwrap();
        assert_eq!(bytes[0], 0x04); // uncompressed point
        assert_eq!(bytes.len(), 65); // 1 + 32 + 32 for P-256
    }

    #[test]
    fn ed_public_key_extraction() {
        let key =
            PemEncodedKey::new(include_bytes!("../../tests/eddsa/public_ed25519_key.pem")).unwrap();
        let bytes = key.as_ed_public_key().unwrap();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn rsa_pkcs8_key_extraction() {
        let key =
            PemEncodedKey::new(include_bytes!("../../tests/rsa/public_rsa_key_pkcs8.pem")).unwrap();
        let bytes = key.as_rsa_key().unwrap();
        assert_eq!(bytes[0], 0x30); // SEQUENCE
    }
    #[test]
    fn rsa_pkcs1_key() {
        let key = PemEncodedKey::new(include_bytes!("../../tests/rsa/private_rsa_key_pkcs1.pem"))
            .unwrap();
        let bytes = key.as_rsa_key().unwrap();
        assert_eq!(bytes[0], 0x30); // SEQUENCE
    }
}
