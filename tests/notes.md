# Generating RSA keys

Using `openssl`

## PEM
`openssl genrsa -out private_rsa_key.pem 2048`

Getting public key:
`openssl rsa -in private_rsa_key.pem -outform PEM -pubout -out public_rsa_key.pem`

## DER
Same as PEM but replace `PEM` by `DER`.
`openssl rsa -in private_rsa_key.pem -outform DER -pubout -out public_rsa_key.der`

## Converting private PEM to DER
`openssl rsa -in private_rsa_key.pem -outform DER -out private_rsa_key.der`

## Converting private DER to PEM
`openssl rsa -in private_rsa_key.der -inform DER -outform PEM -out private_rsa_key.pem`

## Generating public key
`openssl rsa -in private_rsa_key.der -inform DER -RSAPublicKey_out -outform DER -out public_key.der`
