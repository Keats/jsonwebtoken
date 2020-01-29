# Changelog

# 7.0.0 (2020-01-28)

- Add support for PS256, PS384 and PS512
- Add support for verifying with modulus/exponent components for RSA
- Update to 2018 edition
- Changed aud field type in Validation to `Option<HashSet<String>>`.  Audience 
  validation now tests for "any-of-these" audience membership.
- Add support for keys in PEM format
- Add EncodingKey/DecodingKey API to improve performance and UX

## 6.0.1 (2019-05-10)

- Fix Algorithm mapping in FromStr for RSA

## 6.0.0 (2019-04-21)

- Update Ring to 0.14
- Remove `iat` check to match the JWT spec
- Add ES256 and ES384 signing decoding

## 5.0.1 (2018-09-10)

- Add implementation of FromStr for Algorithm

## 5.0.0 (2018-08-13)

- Update ring
- Change error handling to be based on simple struct/enum rather than error-chain
- Fix validations not being called properly in some cases
- Default validation is not checking `iat` and `nbf` anymore

## 4.0.1 (2018-03-19)

- Add method to decode a token without signature verification

## 4.0.0 (2017-11-22)

### Breaking changes

- Make it mandatory to specify the algorithm in `decode`

## 3.0.0 (2017-09-08)

### Breaking changes
- Remove `validate_signature` from `Validation`, use `decode_header` instead if you don't know the alg used
- Make `typ` optional in header, some providers apparently don't use it

### Others

- Update ring & error-chain
- Fix documentation about `leeway` being in seconds and not milliseconds
- Add `decode_header` to only decode the header: replaces the use case of `validate_signature`

## 2.0.3 (2017-07-18)

- Make `TokenData` public

## 2.0.2 (2017-06-24)

- Update ring & chrono

## 2.0.1 (2017-05-09)

- Update ring

## 2.0.0 (2017-04-23)

- Use Serde instead of rustc_serialize
- Add RSA support
- API overhaul, see README for new usage
- Add validation
- Update all dependencies

## Previous

- 1.1.7: update ring
- 1.1.6: update ring
- 1.1.5: update ring version
- 1.1.4: use ring instead of rust-crypto
- 1.1.3: Make sign and verify public
- 1.1.2: Update rust-crypto to 0.2.35
- 1.1.1: Don't serialize empty fields in header
- 1.1.0: Impl Error for jsonwebtoken errors
- 1.0: Initial release
