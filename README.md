# jsonwebtoken

[![Build Status](https://travis-ci.org/Keats/rust-jwt.svg)](https://travis-ci.org/Keats/rust-jwt)

## Installation
Add the following to Cargo.toml:

```toml
jsonwebtoken = "1"
rustc-serialize = "0.3"
```

## How to use
There is a complete example in `examples/claims.rs` but here's a quick one.

In terms of imports:
```rust
extern crate jsonwebtoken as jwt;
extern crate rustc_serialize;

use jwt::{encode, decode, Header, Algorithm};
```

Look at the examples directory for 2 examples: a basic one and one with a custom
header.

### Encoding
```rust
let token = encode(&Header::default(), &my_claims, "secret".as_ref()).unwrap();
```
In that example, `my_claims` is an instance of a Claims struct that derives `RustcEncodable` and `RustcDecodable`.
The default algorithm is HS256.
Look at custom headers section to see how to change that.

### Decoding
```rust
let token = decode::<Claims>(&token, "secret", Algorithm::HS256).unwrap();
// token is a struct with 2 params: header and claims
```
In addition to the normal base64/json decoding errors, `decode` can return two custom errors:

- **InvalidToken**: if the token is not a valid JWT
- **InvalidSignature**: if the signature doesn't match
- **WrongAlgorithmHeader**: if the alg in the header doesn't match the one given to decode

### Validation
The library only validates the algorithm type used but does not verify claims such as expiration.
Feel free to add a `validate` method to your claims struct to handle that: there is an example of that in `examples/claims.rs`.

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
The HMAC SHA family is supported: HMAC SHA256, HMAC SHA384 and HMAC SHA512 as well as the RSA PKCS1: RSA_PKCS1_SHA256,
RSA_PKCS1_SHA384 and RSA_PKCS1_SHA512.
