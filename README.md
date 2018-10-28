# jsonwebtoken

[![Build Status](https://travis-ci.org/Keats/jsonwebtoken.svg)](https://travis-ci.org/Keats/jsonwebtoken)

[API documentation on docs.rs](https://docs.rs/jsonwebtoken/)

## Installation
Add the following to Cargo.toml:

```toml
jsonwebtoken = "5"
serde_derive = "1"
serde = "1"
```

## How to use
Complete examples are available in the examples directory: a basic one and one with a custom header.

In terms of imports and structs:
```rust
extern crate jsonwebtoken as jwt;
#[macro_use]
extern crate serde_derive;

use jwt::{encode, decode, Header, Algorithm, Validation};

/// Our claims struct, it needs to derive `Serialize` and/or `Deserialize`
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    company: String,
    exp: usize,
}
```

### Encoding
The default algorithm is HS256.

```rust
let token = encode(&Header::default(), &my_claims, "secret".as_ref())?;
```

#### Custom headers & changing algorithm
All the parameters from the RFC are supported but the default header only has `typ` and `alg` set.
If you want to set the `kid` parameter or change the algorithm for example:

```rust
let mut header = Header::default();
header.kid = Some("blabla".to_owned());
header.alg = Algorithm::HS512;
let token = encode(&header, &my_claims, "secret".as_ref())?;
```
Look at `examples/custom_header.rs` for a full working example.

### Decoding
```rust
let token = decode::<Claims>(&token, "secret".as_ref(), &Validation::default())?;
// token is a struct with 2 params: header and claims
```
`decode` can error for a variety of reasons:

- the token or its signature is invalid
- error while decoding base64 or the result of decoding base64 is not valid UTF-8
- validation of at least one reserved claim failed

In some cases, for example if you don't know the algorithm used, you will want to only decode the header:

```rust
let header = decode_header(&token)?;
```

This does not perform any validation on the token.

#### Validation
This library validates automatically the `iat`, `exp` and `nbf` claims if present. You can also validate the `sub`, `iss` and `aud` but
those require setting the expected value in the `Validation` struct.

Since validating time fields is always a bit tricky due to clock skew, 
you can add some leeway to the `iat`, `exp` and `nbf` validation by setting a `leeway` parameter.

Last but not least, you will need to set the algorithm(s) allowed for this token if you are not using `HS256`.

```rust
use jsonwebtoken::{Validation, Algorithm};

// Default validation: the only algo allowed is HS256
let validation = Validation::default();
// Quick way to setup a validation where only the algorithm changes
let validation = Validation::new(Algorithm::HS512);
// Adding some leeway (in seconds) for iat, exp and nbf checks
let mut validation = Validation {leeway: 60, ..Default::default()};
// Checking issuer
let mut validation = Validation {iss: Some("issuer".to_string()), ..Default::default()};
// Setting audience
let mut validation = Validation::default();
validation.set_audience(&"Me"); // string
validation.set_audience(&["Me", "You"]); // array of strings
```

## Algorithms
This library currently supports the following:

- HS256
- HS384
- HS512
- RS256
- RS384
- RS512

### RSA
`jsonwebtoken` can only read DER encoded keys currently. If you have openssl installed,
you can run the following commands to obtain the DER keys from PKCS#1 (ie with `BEGIN RSA PUBLIC KEY`) .pem.
If you have a PKCS#8 pem file (ie starting with `BEGIN PUBLIC KEY`), you will need to first convert it to PKCS#1:
`openssl rsa -pubin -in <filename> -RSAPublicKey_out -out <filename>`.

```bash
// private key
$ openssl rsa -in private_rsa_key.pem -outform DER -out private_rsa_key.der
// public key
$ openssl rsa -in private_rsa_key.der -inform DER -RSAPublicKey_out -outform DER -out public_key.der
```

If you are getting an error with your public key, make sure you get it by using the command above to ensure
it is in the right format.
