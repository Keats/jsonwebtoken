use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation,
    crypto::{CryptoProvider, JwkUtils, JwtSigner, JwtVerifier},
    decode, encode,
    errors::Error,
};
use serde::{Deserialize, Serialize};
use signature::{Signer, Verifier};

fn new_signer(algorithm: &Algorithm, key: &EncodingKey) -> Result<Box<dyn JwtSigner>, Error> {
    let jwt_signer = match algorithm {
        Algorithm::EdDSA => Box::new(CustomEdDSASigner::new(key)?) as Box<dyn JwtSigner>,
        _ => unimplemented!(),
    };

    Ok(jwt_signer)
}

fn new_verifier(algorithm: &Algorithm, key: &DecodingKey) -> Result<Box<dyn JwtVerifier>, Error> {
    let jwt_verifier = match algorithm {
        Algorithm::EdDSA => Box::new(CustomEdDSAVerifier::new(key)?) as Box<dyn JwtVerifier>,
        _ => unimplemented!(),
    };

    Ok(jwt_verifier)
}

pub struct CustomEdDSASigner;

impl CustomEdDSASigner {
    fn new(_: &EncodingKey) -> Result<Self, Error> {
        Ok(CustomEdDSASigner)
    }
}

// WARNING: This is obviously not secure at all and should NEVER be done in practice!
impl Signer<Vec<u8>> for CustomEdDSASigner {
    fn try_sign(&self, _: &[u8]) -> Result<Vec<u8>, signature::Error> {
        Ok(vec![0; 16])
    }
}

impl JwtSigner for CustomEdDSASigner {
    fn algorithm(&self) -> Algorithm {
        Algorithm::EdDSA
    }
}

pub struct CustomEdDSAVerifier;

impl CustomEdDSAVerifier {
    fn new(_: &DecodingKey) -> Result<Self, Error> {
        Ok(CustomEdDSAVerifier)
    }
}

impl Verifier<Vec<u8>> for CustomEdDSAVerifier {
    fn verify(&self, _: &[u8], signature: &Vec<u8>) -> Result<(), signature::Error> {
        if signature == &vec![0; 16] { Ok(()) } else { Err(signature::Error::new()) }
    }
}

impl JwtVerifier for CustomEdDSAVerifier {
    fn algorithm(&self) -> Algorithm {
        Algorithm::EdDSA
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Claims {
    sub: String,
    exp: u64,
}

fn main() {
    // create and install our custom provider
    let my_crypto_provider = CryptoProvider {
        signer_factory: new_signer,
        verifier_factory: new_verifier,
        // the default impl uses dummy functions that panic, but we don't need them here
        jwk_utils: JwkUtils::default(),
    };
    my_crypto_provider.install_default().unwrap();

    // for an actual EdDSA implementation, this would be some private key
    let key = b"secret";
    let my_claims = Claims { sub: "me".to_owned(), exp: 10000000000 };

    // our crypto provider only supports EdDSA
    let header = Header::new(Algorithm::EdDSA);

    let token = match encode(&header, &my_claims, &EncodingKey::from_ed_der(key)) {
        Ok(t) => t,
        Err(_) => panic!(), // in practice you would return an error
    };

    let claims = match decode::<Claims>(
        token,
        &DecodingKey::from_ed_der(key),
        &Validation::new(Algorithm::EdDSA),
    ) {
        Ok(c) => c.claims,
        Err(_) => panic!(),
    };

    assert_eq!(my_claims, claims);
}
