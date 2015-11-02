# JWT

[![Build Status](https://travis-ci.org/Keats/rust-jwt.svg)](https://travis-ci.org/Keats/rust-jwt)

## Dependencies
You will need to add `rustc-serialize` to your Cargo.toml in order to use this crate.

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

## Algorithms
Right now, only SHA256 is supported.

## Missing
The header is currently not customisable and therefore does not support things like kid right now.

## Performance
On my thinkpad 440s:

```
test tests::bench_decode ... bench:       5,578 ns/iter (+/- 307)
test tests::bench_encode ... bench:       3,542 ns/iter (+/- 416)
```
