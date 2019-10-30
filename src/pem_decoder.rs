use crate::keys::Key;
use crate::algorithms::Algorithm;
use crate::errors::{Result, ErrorKind};

extern crate pem;
extern crate simple_asn1;

use simple_asn1::{OID, BigUint};

#[derive(Debug)]
#[derive(PartialEq)]
pub enum PemType {
  ECPublicKey,
  ECPrivateKey,
  RSAPublicKey,
  RSAPrivateKey,
}

#[derive(Debug)]
#[derive(PartialEq)]
pub enum PemEncodedWith {
  PKCS1,
  PKCS8,
}

/// TODO
#[derive(Debug)]
#[derive(PartialEq)]
pub struct PemEncodedKey {
  content: Vec<u8>,
  asn1: Vec<simple_asn1::ASN1Block>,
  pem_type: PemType,
  classification: Classification,
  encoded_with: PemEncodedWith,
}

impl PemEncodedKey {
  /// TODO
  pub fn read(input: &str) -> Result<PemEncodedKey> {
    match pem::parse(input) {
      Ok(content) => {
        let asn1_content = match simple_asn1::from_der(content.contents.as_slice()) {
          Ok(asn1) => asn1,
          Err(_) => return Err(ErrorKind::InvalidKeyFormat)?,
        };
        
        match content.tag.as_ref() {
          // This handles a PKCS#1 RSA Private key
          "RSA PRIVATE KEY" => Ok(PemEncodedKey {
            content: content.contents,
            asn1: asn1_content,
            pem_type: PemType::RSAPrivateKey,
            classification: Classification::RSA,
            encoded_with: PemEncodedWith::PKCS1,
          }),
          "RSA PUBLIC KEY" => Ok(PemEncodedKey {
            content: content.contents,
            asn1: asn1_content,
            pem_type: PemType::RSAPublicKey,
            classification: Classification::RSA,
            encoded_with: PemEncodedWith::PKCS1,
          }),
          
          // No "EC PRIVATE KEY"
          // https://security.stackexchange.com/questions/84327/converting-ecc-private-key-to-pkcs1-format
          // "there is no such thing as a "PKCS#1 format" for elliptic curve (EC) keys"

          // This handles PKCS#8 private keys
          "PRIVATE KEY" => {
            match classify_pem(&asn1_content) {
              Option::Some(Classification::EC) => Ok(PemEncodedKey {
                content: content.contents,
                asn1: asn1_content,
                pem_type: PemType::ECPrivateKey,
                classification: Classification::EC,
                encoded_with: PemEncodedWith::PKCS8,
              }),
              Option::Some(Classification::RSA) => Ok(PemEncodedKey {
                content: content.contents,
                asn1: asn1_content,
                pem_type: PemType::RSAPrivateKey,
                classification: Classification::RSA,
                encoded_with: PemEncodedWith::PKCS8,
              }),
              _ => return Err(ErrorKind::InvalidKeyFormat)?,
            }
          }

          // This handles PKCS#8 public keys
          "PUBLIC KEY" => {
            match classify_pem(&asn1_content) {
              Option::Some(Classification::EC) => Ok(PemEncodedKey {
                content: content.contents,
                asn1: asn1_content,
                pem_type: PemType::ECPublicKey,
                classification: Classification::EC,
                encoded_with: PemEncodedWith::PKCS8,
              }),
              Option::Some(Classification::RSA) => Ok(PemEncodedKey {
                content: content.contents,
                asn1: asn1_content,
                pem_type: PemType::RSAPublicKey,
                classification: Classification::RSA,
                encoded_with: PemEncodedWith::PKCS8,
              }),
              _ => return Err(ErrorKind::InvalidKeyFormat)?,
            }
          }

          // Unknown type
          _ => return Err(ErrorKind::InvalidKeyFormat)?,
        }
      },
      Err(_) => return Err(ErrorKind::InvalidKeyFormat)?,
    }
  }

  /// TODO
  pub fn as_key(&self, algorithm: Algorithm) -> Result<Key> {
    match self.classification {
      Classification::RSA => {
        let key = match self.encoded_with {
          PemEncodedWith::PKCS1 => Key::Der(self.content.as_slice()),
          // Convert to DER for ring
          PemEncodedWith::PKCS8 => Key::Der(extract_first_bitstring(&self.asn1)?)
        };
        match algorithm {
          Algorithm::RS256 => Ok(key),
          Algorithm::RS384 => Ok(key),
          Algorithm::RS512 => Ok(key),
          Algorithm::PS256 => Ok(key),
          Algorithm::PS384 => Ok(key),
          Algorithm::PS512 => Ok(key),
          _ => return Err(ErrorKind::InvalidAlgorithm)?,
        }
      },
      Classification::EC => {
        let key = match self.pem_type {
          PemType::ECPrivateKey => Key::Pkcs8(self.content.as_slice()),
          // I'm not sure why EC is a special case with ring
          PemType::ECPublicKey => Key::Pkcs8(extract_first_bitstring(&self.asn1)?),
          _ => return Err(ErrorKind::InvalidAlgorithm)?,
        };
        match algorithm {
          Algorithm::ES256 => Ok(key),
          Algorithm::ES384 => Ok(key),
          _ => return Err(ErrorKind::InvalidAlgorithm)?,
        }
      },
    }
  }
}

#[derive(Debug)]
#[derive(PartialEq)]
enum Classification {
  EC,
  RSA,
}

// This really just finds and returns the first bitstring or octet string
// Which is the x coordinate for EC public keys
// And the DER contents of an RSA key
// Though PKCS#11 keys shouldn't have anything else. 
// It will get confusing with certificates.
fn extract_first_bitstring(asn1: &Vec<simple_asn1::ASN1Block>) -> Result<&[u8]> {
  for asn1_entry in asn1.iter() {
    match asn1_entry {
      simple_asn1::ASN1Block::Sequence(_, entries) => {
        if let Ok(result) = extract_first_bitstring(entries) {
          return Ok(result);
        }
      }
      simple_asn1::ASN1Block::BitString(_, _, value) => {
        return Ok(value.as_ref());
      }
      simple_asn1::ASN1Block::OctetString(_, value) => {
        return Ok(value.as_ref());
      }
      _ => ()
    }
  }
  return Err(ErrorKind::InvalidEcdsaKey)?
}

fn classify_pem(asn1: &Vec<simple_asn1::ASN1Block>) -> Option<Classification> {
  // These should be constant but the macro requires
  // #![feature(const_vec_new)]
  let ec_public_key_oid = simple_asn1::oid!(1,2,840,10045,2,1);
  let rsa_public_key_oid = simple_asn1::oid!(1,2,840,113549,1,1,1);

  for asn1_entry in asn1.iter() {
    match asn1_entry {
      simple_asn1::ASN1Block::Sequence(_, entries) => {
        if let Some(classification) = classify_pem(entries) {
          return Some(classification);
        }
      }
      simple_asn1::ASN1Block::ObjectIdentifier(_, oid) => {
        if oid == ec_public_key_oid {
          return Option::Some(Classification::EC);
        } else if oid == rsa_public_key_oid {
          return Option::Some(Classification::RSA);
        }
      }
      _ => {
        println!("Ignoring {:?}", asn1_entry);
      }
    }
  }
  return Option::default();
}