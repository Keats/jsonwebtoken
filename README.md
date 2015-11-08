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

In terms of imports:
```rust
extern crate jsonwebtoken as jwt;
extern crate rustc_serialize;

use jwt::{encode, decode, Algorithm};
```

### Encoding
```rust
let token = encode(&my_claims, "secret", Algorithm::HS256);
```
In that example, `my_claims` is an instance of the Claims struct.  
The struct you are using for your claims should derive `RustcEncodable` and `RustcDecodable`.

### Decoding
```rust
let claims = decode::<Claims>(&token, "secret", Algorithm::HS256);
```
In addition to the normal base64/json decoding errors, `decode` can return two custom errors:

- **InvalidToken**: if the token is not a valid JWT
- **InvalidSignature**: if the signature doesn't match
- **WrongAlgorithmHeader**: if the alg in the header doesn't match the one given to decode

### Validation
Right now, the library only validates the algorithm type used but does not verify claims such as expiration.
Feel free to add a `validate` method to your claims struct to handle that.

## Algorithms
Right now, only SHA family is supported: SHA256, SHA384 and SHA512.

## Missing
The header is currently not customisable and therefore does not support things like kid right now.

## Performance
On my thinkpad 440s for a 2 claims struct using SHA256:

```
test bench_decode ... bench:       2,537 ns/iter (+/- 813)
test bench_encode ... bench:       2,847 ns/iter (+/- 131)
```
