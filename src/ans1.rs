use crate::{errors::ErrorKind, jwk::EllipticCurve};

/// Classify the curve type of an ED curve using the asn1 block
pub(crate) fn classify_ed_curve(
    asn1: &Vec<simple_asn1::ASN1Block>,
) -> Result<EllipticCurve, ErrorKind> {
    // These should be constant but the macro requires
    // Defined: https://datatracker.ietf.org/doc/html/rfc8410#section-3 id-Ed25519)
    let ed25519_oid = simple_asn1::oid!(1, 3, 101, 112);
    // Defined: https://datatracker.ietf.org/doc/html/rfc8410#section-3 (id-Ed448)
    let ed448_oid = simple_asn1::oid!(1, 3, 101, 113);

    for asn1_entry in asn1 {
        match asn1_entry {
            simple_asn1::ASN1Block::Sequence(_, entries) => {
                if let Ok(classification) = classify_ed_curve(entries) {
                    return Ok(classification);
                }
            }
            simple_asn1::ASN1Block::ObjectIdentifier(_, oid) => {
                if oid == ed25519_oid {
                    return Ok(EllipticCurve::Ed25519);
                }
                if oid == ed448_oid {
                    return Ok(EllipticCurve::Ed448);
                }
            }
            _ => {}
        }
    }
    Err(ErrorKind::InvalidEddsaKey)
}
