use base64;
use serde_json;

error_chain! {
    errors {
        InvalidToken {
            description("invalid token")
            display("Invalid token")
        }
        InvalidSignature {
            description("invalid signature")
            display("Invalid signature")
        }
        WrongAlgorithmHeader {
            description("Wrong Algorithm Header")
            display("Wrong Algorithm Header")
        }
    }

    foreign_links {
        Base64(base64::Base64Error);
        Json(serde_json::Error);
        Utf8(::std::string::FromUtf8Error);
    }
}
