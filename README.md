# jsonwebtoken

[![Build Status](https://travis-ci.org/Keats/jsonwebtoken.svg)](https://travis-ci.org/Keats/jsonwebtoken)

[API documentation on docs.rs](https://docs.rs/jsonwebtoken/)

See [JSON Web Tokens](https://en.wikipedia.org/wiki/JSON_Web_Token) for more information on what JSON Web Tokens are.

## Installation
Add the following to Cargo.toml:

```toml
jsonwebtoken = "7"
serde = {version = "1.0", features = ["derive"] }
```

The minimum required Rust version is 1.36.

## Algorithms
This library currently supports the following:

- HS256
- HS384
- HS512
- RS256
- RS384
- RS512
- PS256
- PS384
- PS512
- ES256
- ES384


## How to use
Complete examples are available in the examples directory: a basic one and one with a custom header.

In terms of imports and structs:
```rust
use serde::{Serialize, Deserialize};
use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey};

/// Our claims struct, it needs to derive `Serialize` and/or `Deserialize`
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    company: String,
    exp: usize,
}
```

### Claims
The claims fields which can be validated. (see [validation](#validation))
```rust
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    aud: String         // Optional. Audience
    exp: DateTime<Utc>, // Required (validate_exp defaults to true in validation). Expiration time
    iat: DateTime<Utc>  // Optional. Issued at
    iss: String         // Optional. Issuer
    nbf: DateTime<Utc>  // Optional. Not Before
    sub: String,        // Optional. Subject (whom token refers to)
}
```

### Header
The default algorithm is HS256, which uses a shared secret.

```rust
let token = encode(&Header::default(), &my_claims, &EncodingKey::from_secret("secret".as_ref()))?;
```

#### Custom headers & changing algorithm
All the parameters from the RFC are supported but the default header only has `typ` and `alg` set.
If you want to set the `kid` parameter or change the algorithm for example:

```rust
let mut header = Header::new(Algorithm::HS512);
header.kid = Some("blabla".to_owned());
let token = encode(&header, &my_claims, &EncodingKey::from_secret("secret".as_ref()))?;
```
Look at `examples/custom_header.rs` for a full working example.

### Encoding

```rust
// HS256
let token = encode(&Header::default(), &my_claims, &EncodingKey::from_secret("secret".as_ref()))?;
// RSA
let token = encode(&Header::new(Algorithm::RS256), &my_claims, &EncodingKey::from_rsa_pem(include_bytes!("privkey.pem"))?)?;
```
Encoding a JWT takes 3 parameters:

- a header: the `Header` struct
- some claims: your own struct
- a key/secret

When using HS256, HS2384 or HS512, the key is always a shared secret like in the example above. When using
RSA/EC, the key should always be the content of the private key in the PEM or DER format.

If your key is in PEM format, it is better performance wise to generate the `EncodingKey` once in a `lazy_static` or
something similar and reuse it.

### Decoding

```rust
// `token` is a struct with 2 fields: `header` and `claims` where `claims` is your own struct.
let token = decode::<Claims>(&token, &DecodingKey::from_secret("secret".as_ref()), &Validation::default())?;
```
`decode` can error for a variety of reasons:

- the token or its signature is invalid
- the token had invalid base64
- validation of at least one reserved claim failed

As with encoding, when using HS256, HS2384 or HS512, the key is always a shared secret like in the example above. When using
RSA/EC, the key should always be the content of the public key in the PEM or DER format.

In some cases, for example if you don't know the algorithm used or need to grab the `kid`, you can choose to decode only the header:

```rust
let header = decode_header(&token)?;
```

This does not perform any signature verification or validate the token claims.

You can also decode a token using the public key components of a RSA key in base64 format.
The main use-case is for JWK where your public key is in a JSON format like so:

```json
{
   "kty":"RSA",
   "e":"AQAB",
   "kid":"6a7a119f-0876-4f7e-8d0f-bf3ea1391dd8",
   "n":"yRE6rHuNR0QbHO3H3Kt2pOKGVhQqGZXInOduQNxXzuKlvQTLUTv4l4sggh5_CYYi_cvI-SXVT9kPWSKXxJXBXd_4LkvcPuUakBoAkfh-eiFVMh2VrUyWyj3MFl0HTVF9KwRXLAcwkREiS3npThHRyIxuy0ZMeZfxVL5arMhw1SRELB8HoGfG_AtH89BIE9jDBHZ9dLelK9a184zAf8LwoPLxvJb3Il5nncqPcSfKDDodMFBIMc4lQzDKL5gvmiXLXB1AGLm8KBjfE8s3L5xqi-yUod-j8MtvIj812dkS4QMiRVN_by2h3ZY8LYVGrqZXZTcgn2ujn8uKjXLZVD5TdQ"
}
```

```rust
// `token` is a struct with 2 fields: `header` and `claims` where `claims` is your own struct.
let token = decode::<Claims>(&token, &DecodingKey::from_rsa_components(jwk["n"], jwk["e"]), &Validation::new(Algorithm::RS256))?;
```

If your key is in PEM format, it is better performance wise to generate the `DecodingKey` once in a `lazy_static` or
something similar and reuse it.

### Convert SEC1 private key to PKCS8
`jsonwebtoken` currently only supports PKCS8 format for private EC keys. If your key has `BEGIN EC PRIVATE KEY` at the top,
this is a SEC1 type and can be converted to PKCS8 like so:

```bash
openssl pkcs8 -topk8 -nocrypt -in sec1.pem -out pkcs8.pem
```


## Validation
This library validates automatically the `exp` claim and `nbf` is validated if present. You can also validate the `sub`, `iss` and `aud` but
those require setting the expected value in the `Validation` struct.

Since validating time fields is always a bit tricky due to clock skew,
you can add some leeway to the `iat`, `exp` and `nbf` validation by setting the `leeway` field.

Last but not least, you will need to set the algorithm(s) allowed for this token if you are not using `HS256`.

```rust
#[derive(Debug, Clone, PartialEq)]
struct Validation {
    pub leeway: u64,                    // Default: 0
    pub validate_exp: bool,             // Default: true
    pub validate_nbf: bool,             // Default: false
    pub aud: Option<HashSet<String>>,   // Default: None
    pub iss: Option<String>,            // Default: None
    pub sub: Option<String>,            // Default: None
    pub algorithms: Vec<Algorithm>,     // Default: vec![Algorithm::HS256]
}
```

```rust
use jsonwebtoken::{Validation, Algorithm};

// Default validation: the only algo allowed is HS256
let validation = Validation::default();
// Quick way to setup a validation where only the algorithm changes
let validation = Validation::new(Algorithm::HS512);
// Adding some leeway (in seconds) for exp and nbf checks
let mut validation = Validation {leeway: 60, ..Default::default()};
// Checking issuer
let mut validation = Validation {iss: Some("issuer".to_string()), ..Default::default()};
// Setting audience
let mut validation = Validation::default();
validation.set_audience(&"Me"); // string
validation.set_audience(&["Me", "You"]); // array of strings
```

Look at `examples/validation.rs` for a full working example.
