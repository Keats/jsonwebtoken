use base64;
use serde_json;
use ring;

error_chain! {
    errors {
        /// When a token doesn't have a valid token shape
        InvalidToken {
            description("invalid token")
            display("Invalid token")
        }
        /// When the signature doesn't match
        InvalidSignature {
            description("invalid signature")
            display("Invalid signature")
        }
        /// When the algorithm in the header doesn't match the one passed to `decode`
        WrongAlgorithmHeader {
            description("wrong algorithm header")
            display("Wrong Algorithm Header")
        }
        /// When the secret given is not a valid RSA key
        InvalidKey {
            description("invalid key")
            display("Invalid Key")
        }

        /// When a token’s `exp` claim indicates that it has expired
        ExpiredSignature {
            description("expired signature")
            display("Expired Signature")
        }
        /// When a token’s `iss` claim does not match the expected issuer
        InvalidIssuer {
            description("invalid issuer")
            display("Invalid Issuer")
        }
        /// When a token’s `aud` claim does not match one of the expected audience values
        InvalidAudience {
            description("invalid audience")
            display("Invalid Audience")
        }
        /// When a token’s `iat` claim is in the future
        InvalidIssuedAt {
            description("invalid issued at")
            display("Invalid Issued At")
        }
        /// When a token’s nbf claim represents a time in the future
        ImmatureSignature {
            description("immature signature")
            display("Immature Signature")
        }
    }

    foreign_links {
        Unspecified(ring::error::Unspecified);
        Base64(base64::Base64Error);
        Json(serde_json::Error);
        Utf8(::std::string::FromUtf8Error);
    }
}
