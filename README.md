# jsonwebtoken

[![Build Status](https://travis-ci.org/Keats/rust-jwt.svg)](https://travis-ci.org/Keats/rust-jwt)

## Installation
Add the following to Cargo.toml:

```toml
jsonwebtoken = "0.1"
rustc-serialize = "0.3"
```

## How to use
There is a complete example in examples/claims.rs but here's a quick one.

### Encoding
```rust
// encode<T: Part>(claims: T, secret: String, algorithm: Algorithm) -> Result<String, Error>
let token = encode::<Claims>(my_claims, "secret".to_owned(), Algorithm::HS256);
```
In that example, `my_claims` is an instance of the Claims struct.  
The struct you are using for your claims should derive `RustcEncodable` and `RustcDecodable`.

### Decoding
```rust
// decode<T: Part>(token: String, secret: String, algorithm: Algorithm) -> Result<T, Error>
let claims = decode::<Claims>(token.to_owned(), "secret".to_owned(), Algorithm::HS256);
```
In addition to the normal base64/json decoding errors, `decode` can return two custom errors:

- **InvalidToken**: if the token is not a valid JWT
- **InvalidSignature**: if the signature doesn't match
- **WrongAlgorithmHeader**: if the alg in the header doesn't match the one given to decode

## Algorithms
Right now, only SHA family is supported: SHA256, SHA384 and SHA512.

## Missing
The header is currently not customisable and therefore does not support things like kid right now.

## Performance
On my thinkpad 440s for a 2 claims struct using SHA256:

```
test bench_decode ... bench:       7,106 ns/iter (+/- 5,354)
test bench_encode ... bench:       3,453 ns/iter (+/- 140)
```
