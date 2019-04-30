#![allow(missing_docs)]
use base64::decode; 
use errors::Result;

/// This function does no check if the pem is valid, only converts the PEM 
/// to an Vec<u8> in order to be used as a DER in the RSA signature verifying. 
/// ```rust
/// use jsonwebtoken::utils::pem_to_der;
/// 
/// let key = "-----BEGIN PUBLIC KEY-----\nAaAaAaAa\n-----END PUBLIC KEY-----";
/// let der_bytes = pem_to_der(key).expect("Unable to convert key"); 
/// 
/// assert_eq!(der_bytes, vec![0x01, 0xa0, 0x1a, 0x01, 0xa0, 0x1a]);
/// ```
pub fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    // Split on lines and discard first. (-----BEGIN PUBLIC KEY-----)
    let mut pem_iter = pem.trim_end().split('\n').skip(1).peekable(); 
    
    // Build return str before conversion. 
    let mut tmp_str = String::new(); 
    while let Some(pem_part) = pem_iter.next() {
        // Discard the last chunk (-----END PUBLIC KEY-----) 
        if pem_iter.peek().is_some() {
            tmp_str.push_str(pem_part);
        }
    }
    // Return bytes from encoded text 
    Ok(decode(&tmp_str)?)
}