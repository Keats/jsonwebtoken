extern crate jsonwebtoken as jwt;
#[macro_use] extern crate serde_derive;

use jwt::{encode, decode, Header, Algorithm};
use jwt::errors::{ErrorKind};


#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    company: String
}

// Example validation implementation
impl Claims {
    fn is_valid(&self) -> bool {
        if self.company != "ACME" {
            return false;
        }
        // expiration etc

        true
    }
}

fn main() {
    let my_claims = Claims {
        sub: "b@b.com".to_owned(),
        company: "ACME".to_owned()
    };
    let key = "secret";
    let token = match encode(Header::default(), &my_claims, key.as_ref()) {
        Ok(t) => t,
        Err(_) => panic!() // in practice you would return the error
    };

    println!("{:?}", token);

    let token_data = match decode::<Claims>(&token, key.as_ref(), Algorithm::HS256) {
        Ok(c) => c,
        Err(err) => match *err.kind() {
            ErrorKind::InvalidToken => panic!(), // Example on how to handle a specific error
            _ => panic!()
        }
    };
    println!("{:?}", token_data.claims);
    println!("{:?}", token_data.header);
    println!("{:?}", token_data.claims.is_valid());
}
