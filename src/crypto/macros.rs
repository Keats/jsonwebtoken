#[cfg(any(feature = "rust_crypto", feature = "aws_lc_rs"))]
macro_rules! define_default_provider {
    ($name:literal, $link:literal) => {
        #[doc = "The default [`CryptoProvider`] backed by [`"]
        #[doc = $name]
        #[doc = "`]"]
        #[doc = concat!("The default [`CryptoProvider`] backed by [`", $name, "`]")]
        #[doc = ""]
        #[doc = concat!("[`", $name, "`]: ", $link)]
        pub const DEFAULT_PROVIDER: CryptoProvider = CryptoProvider {
            signer_factory: new_signer,
            verifier_factory: new_verifier,
            jwk_utils: JwkUtils {
                extract_rsa_public_key_components,
                extract_ec_public_key_coordinates,
                compute_digest,
            },
        };

        #[doc = "Create a new [`JwtSigner`] for a given [`Algorithm`]."]
        pub fn new_signer(
            algorithm: &Algorithm,
            key: &EncodingKey,
        ) -> Result<Box<dyn JwtSigner>, Error> {
            let jwt_signer = match algorithm {
                Algorithm::HS256 => Box::new(hmac::Hs256Signer::new(key)?) as Box<dyn JwtSigner>,
                Algorithm::HS384 => Box::new(hmac::Hs384Signer::new(key)?) as Box<dyn JwtSigner>,
                Algorithm::HS512 => Box::new(hmac::Hs512Signer::new(key)?) as Box<dyn JwtSigner>,
                Algorithm::ES256 => Box::new(ecdsa::Es256Signer::new(key)?) as Box<dyn JwtSigner>,
                Algorithm::ES384 => Box::new(ecdsa::Es384Signer::new(key)?) as Box<dyn JwtSigner>,
                Algorithm::RS256 => Box::new(rsa::Rsa256Signer::new(key)?) as Box<dyn JwtSigner>,
                Algorithm::RS384 => Box::new(rsa::Rsa384Signer::new(key)?) as Box<dyn JwtSigner>,
                Algorithm::RS512 => Box::new(rsa::Rsa512Signer::new(key)?) as Box<dyn JwtSigner>,
                Algorithm::PS256 => Box::new(rsa::RsaPss256Signer::new(key)?) as Box<dyn JwtSigner>,
                Algorithm::PS384 => Box::new(rsa::RsaPss384Signer::new(key)?) as Box<dyn JwtSigner>,
                Algorithm::PS512 => Box::new(rsa::RsaPss512Signer::new(key)?) as Box<dyn JwtSigner>,
                Algorithm::EdDSA => Box::new(eddsa::EdDSASigner::new(key)?) as Box<dyn JwtSigner>,
            };

            Ok(jwt_signer)
        }

        #[doc = "Create a new [`JwtVerifier`] for a given [`Algorithm`]."]
        pub fn new_verifier(
            algorithm: &Algorithm,
            key: &DecodingKey,
        ) -> Result<Box<dyn super::JwtVerifier>, Error> {
            let jwt_encoder = match algorithm {
                Algorithm::HS256 => {
                    Box::new(hmac::Hs256Verifier::new(key)?) as Box<dyn JwtVerifier>
                }
                Algorithm::HS384 => {
                    Box::new(hmac::Hs384Verifier::new(key)?) as Box<dyn JwtVerifier>
                }
                Algorithm::HS512 => {
                    Box::new(hmac::Hs512Verifier::new(key)?) as Box<dyn JwtVerifier>
                }
                Algorithm::ES256 => {
                    Box::new(ecdsa::Es256Verifier::new(key)?) as Box<dyn JwtVerifier>
                }
                Algorithm::ES384 => {
                    Box::new(ecdsa::Es384Verifier::new(key)?) as Box<dyn JwtVerifier>
                }
                Algorithm::RS256 => {
                    Box::new(rsa::Rsa256Verifier::new(key)?) as Box<dyn JwtVerifier>
                }
                Algorithm::RS384 => {
                    Box::new(rsa::Rsa384Verifier::new(key)?) as Box<dyn JwtVerifier>
                }
                Algorithm::RS512 => {
                    Box::new(rsa::Rsa512Verifier::new(key)?) as Box<dyn JwtVerifier>
                }
                Algorithm::PS256 => {
                    Box::new(rsa::RsaPss256Verifier::new(key)?) as Box<dyn JwtVerifier>
                }
                Algorithm::PS384 => {
                    Box::new(rsa::RsaPss384Verifier::new(key)?) as Box<dyn JwtVerifier>
                }
                Algorithm::PS512 => {
                    Box::new(rsa::RsaPss512Verifier::new(key)?) as Box<dyn JwtVerifier>
                }
                Algorithm::EdDSA => {
                    Box::new(eddsa::EdDSAVerifier::new(key)?) as Box<dyn JwtVerifier>
                }
            };

            Ok(jwt_encoder)
        }
    };
}
