# jsonwebtoken

[![Build Status](https://travis-ci.org/Keats/rust-jwt.svg)](https://travis-ci.org/Keats/rust-jwt)

## Installation
Add the following to Cargo.toml:

```toml
jsonwebtoken = "2"
serde_derive = "0.9"
```

## How to use
There is a complete example in `examples/claims.rs` but here's a quick one.

In terms of imports:
```rust
extern crate jsonwebtoken as jwt;
#[macro_use]
extern crate serde_derive;

use jwt::{encode, decode, Header, Algorithm, Validation};
```

Look at the examples directory for 2 examples: a basic one and one with a custom
header.

### Encoding
```rust
let token = encode(&Header::default(), &my_claims, "secret".as_ref()).unwrap();
```
In that example, `my_claims` is an instance of a Claims struct that derives `Serialize` and `Deserialize`.
The default algorithm is HS256.
Look at custom headers section to see how to change that.

### Decoding
```rust
let token = decode::<Claims>(&token, "secret", Algorithm::HS256, &Validation::default()).unwrap();
// token is a struct with 2 params: header and claims
```
`decode` can error for a variety of reasons:

- the token or its signature is invalid
- error while decoding base64 or the result of decoding base64 is not valid UTF-8
- validation of at least one reserved claim failed

### Validation
This library validates automatically the `iat`, `exp` and `nbf` claims if found. You can also validate the `sub`, `iss` and `aud` but
those require setting the expected value.
You can add some leeway to the `iat`, `exp` and `nbf` validation by setting the `leeway` parameter as shown in the example below.

```rust
use jsonwebtoken::Validation;

// Default valuation
let validation = Validation::default();
// Adding some leeway (in ms) for iat, exp and nbf checks
let mut validation = Validation {leeway: 1000 * 60, ..Default::default()};
// Checking issuer
let mut validation = Validation {iss: Some("issuer".to_string()), ..Default::default()};
// Setting audience
let mut validation = Validation::default();
validation.set_audience(&"Me"); // string
validation.set_audience(&["Me", "You"]); // array of strings
```

It's also possible to disable verifying the signature of a token by setting the `validate_signature` to `false`. This should
only be done if you know what you are doing.

### Custom headers
All the parameters from the RFC are supported but the default header only has `typ` and `alg` set: all the other fields are optional.
If you want to set the `kid` parameter for example:

```rust
let mut header = Header::default();
header.kid = Some("blabla".to_owned());
header.alg = Algorithm::HS512;
let token = encode(&header, &my_claims, "secret".as_ref()).unwrap();
```
Look at `examples/custom_header.rs` for a full working example.

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
you can run the following commands to obtain the DER keys from .pem:

```bash
// private key
$ openssl rsa -in private_rsa_key.pem -outform DER -out private_rsa_key.der
// public key
$ openssl rsa -in private_rsa_key.der -inform DER -RSAPublicKey_out -outform DER -out public_key.der
```

If you are getting an error with your public key, make sure you get it by using the command above to ensure
it is in the right format.
