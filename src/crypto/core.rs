#[cfg(all(feature = "aws_lc_rs", not(any(target_arch = "wasm32", target_os = "windows"))))]
pub(crate) mod dep {
    pub(crate) use ::aws_lc_rs::{constant_time, error, hmac, rand};

    pub(crate) mod signature {
        pub(crate) use ::aws_lc_rs::signature::*;

        #[inline]
        pub(crate) fn ecdsa_key_pair_from_pkcs8(
            alg: &'static EcdsaSigningAlgorithm,
            pkcs8: &[u8],
            _rng: &dyn ::aws_lc_rs::rand::SecureRandom,
        ) -> Result<EcdsaKeyPair, ::aws_lc_rs::error::KeyRejected> {
            EcdsaKeyPair::from_pkcs8(alg, pkcs8)
        }

        #[inline]
        pub(crate) fn rsa_key_pair_public_modulus_len(key_pair: &RsaKeyPair) -> usize {
            key_pair.public_modulus_len()
        }
    }
}

#[cfg(not(all(feature = "aws_lc_rs", not(any(target_arch = "wasm32", target_os = "windows")))))]
pub(crate) mod dep {
    pub(crate) use ::ring::{constant_time, error, hmac, rand};

    pub(crate) mod signature {
        pub(crate) use ::ring::signature::*;

        #[inline]
        pub(crate) fn ecdsa_key_pair_from_pkcs8(
            alg: &'static EcdsaSigningAlgorithm,
            pkcs8: &[u8],
            rng: &dyn ::ring::rand::SecureRandom,
        ) -> Result<EcdsaKeyPair, ::ring::error::KeyRejected> {
            EcdsaKeyPair::from_pkcs8(alg, pkcs8, rng)
        }

        #[inline]
        pub(crate) fn rsa_key_pair_public_modulus_len(key_pair: &RsaKeyPair) -> usize {
            key_pair.public().modulus_len()
        }
    }
}

pub(crate) use dep::*;
