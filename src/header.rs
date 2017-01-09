use crypto::Algorithm;


/// A basic JWT header, the alg defaults to HS256 and typ is automatically
/// set to `JWT`. All the other fields are optional
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Header {
    typ: String,
    pub alg: Algorithm,
    pub jku: Option<String>,
    pub kid: Option<String>,
    pub x5u: Option<String>,
    pub x5t: Option<String>
}

impl Header {
    pub fn new(algorithm: Algorithm) -> Header {
        Header {
            typ: "JWT".to_string(),
            alg: algorithm,
            jku: None,
            kid: None,
            x5u: None,
            x5t: None
        }
    }
}

impl Default for Header {
    fn default() -> Header {
        Header::new(Algorithm::HS256)
    }
}
