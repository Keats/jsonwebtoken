use jsonwebtoken::{
    Algorithm, AlgorithmFamily, DecodingKey, EncodingKey, Header, Validation,
    crypto::{CryptoProvider, JwkUtils, JwtSigner, JwtVerifier},
    decode, encode,
    errors::{Error, ErrorKind},
    signature::{Error as SigError, Signer, Verifier},
};
use serde::{Deserialize, Serialize};

fn new_signer(algorithm: &Algorithm, key: &EncodingKey) -> Result<Box<dyn JwtSigner>, Error> {
    let jwt_signer = match algorithm {
        Algorithm::EdDSA => Box::new(EdDSASigner::new(key)?) as Box<dyn JwtSigner>,
        _ => unimplemented!(),
    };

    Ok(jwt_signer)
}

fn new_verifier(algorithm: &Algorithm, key: &DecodingKey) -> Result<Box<dyn JwtVerifier>, Error> {
    let jwt_verifier = match algorithm {
        Algorithm::EdDSA => Box::new(EdDSAVerifier::new(key)?) as Box<dyn JwtVerifier>,
        _ => unimplemented!(),
    };

    Ok(jwt_verifier)
}

struct EdDSASigner(botan::Privkey);

impl EdDSASigner {
    fn new(encoding_key: &EncodingKey) -> Result<Self, Error> {
        if encoding_key.family() != AlgorithmFamily::Ed {
            return Err(ErrorKind::InvalidKeyFormat.into());
        }

        Ok(Self(
            botan::Privkey::load_der(encoding_key.inner())
                .map_err(|_| ErrorKind::InvalidEddsaKey)?,
        ))
    }
}

impl Signer<Vec<u8>> for EdDSASigner {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, SigError> {
        let mut rng = botan::RandomNumberGenerator::new_system().map_err(SigError::from_source)?;
        let mut signer = botan::Signer::new(&self.0, "Pure").map_err(SigError::from_source)?;
        signer.update(msg).map_err(SigError::from_source)?;
        signer.finish(&mut rng).map_err(SigError::from_source)
    }
}

impl JwtSigner for EdDSASigner {
    fn algorithm(&self) -> Algorithm {
        Algorithm::EdDSA
    }
}

struct EdDSAVerifier(botan::Pubkey);

impl EdDSAVerifier {
    fn new(decoding_key: &DecodingKey) -> Result<Self, Error> {
        if decoding_key.family() != AlgorithmFamily::Ed {
            return Err(ErrorKind::InvalidKeyFormat.into());
        }

        Ok(Self(
            botan::Pubkey::load_ed25519(decoding_key.as_bytes())
                .map_err(|_| ErrorKind::InvalidEddsaKey)?,
        ))
    }
}

impl Verifier<Vec<u8>> for EdDSAVerifier {
    fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), SigError> {
        let mut verifier = botan::Verifier::new(&self.0, "Pure").map_err(SigError::from_source)?;
        verifier.update(msg).map_err(SigError::from_source)?;
        verifier
            .finish(signature)
            .map_err(SigError::from_source)?
            .then_some(())
            .ok_or(SigError::new())
    }
}

impl JwtVerifier for EdDSAVerifier {
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

    // generate a new key
    let (privkey, pubkey) = {
        let key = botan::Privkey::create(
            "Ed25519",
            "",
            &mut botan::RandomNumberGenerator::new_system().unwrap(),
        )
        .unwrap();
        (key.pem_encode().unwrap(), key.pubkey().unwrap().pem_encode().unwrap())
    };
    let my_claims = Claims { sub: "me".to_owned(), exp: 10000000000 };

    // our crypto provider only supports EdDSA
    let header = Header::new(Algorithm::EdDSA);

    let token =
        match encode(&header, &my_claims, &EncodingKey::from_ed_pem(privkey.as_bytes()).unwrap()) {
            Ok(t) => t,
            Err(_) => panic!(), // in practice you would return an error
        };

    let claims = match decode::<Claims>(
        token,
        &DecodingKey::from_ed_pem(pubkey.as_bytes()).unwrap(),
        &Validation::new(Algorithm::EdDSA),
    ) {
        Ok(c) => c.claims,
        Err(_) => panic!(),
    };

    assert_eq!(my_claims, claims);
}
