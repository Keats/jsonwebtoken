/// The supported RSA key formats, see the documentation for ring::signature::RsaKeyPair
/// for more information
pub enum Key<'a> {
    /// An unencrypted PKCS#8-encoded key. Can be used with both ECDSA and RSA
    /// algorithms when signing. See ring for information.
    Pkcs8(&'a [u8]),
    /// A binary DER-encoded ASN.1 key. Can only be used with RSA algorithms
    /// when signing. See ring for more information
    Der(&'a [u8]),
    /// This is not a key format, but provided for convenience since HMAC is
    /// a supported signing algorithm.
    Hmac(&'a [u8]),
    /// A Modulus/exponent for a RSA public key
    ModulusExponent(&'a [u8], &'a [u8]),
}
