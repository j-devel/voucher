#[cfg(feature = "std")]
use std::{println, vec, vec::Vec};
#[cfg(not(feature = "std"))]
use mcu_if::{println, alloc::{vec, vec::Vec}};

use cose::{decoder::*, unpack};
pub use cose::decoder::{CoseSignature, SignatureAlgorithm};

pub const COSE_HEADER_VOUCHER_PUBKEY: u64 = 60299;

pub enum CoseData {
    CoseSign(Vec<CoseSignature>),
    CoseSignOne(CoseSignature),
}

impl CoseData {
    pub fn decode(bytes: &[u8]) -> Result<Self, CoseError> {
        let (tag, array) = get_cose_sign_array(bytes)?;

        // println!("@@ decode():");
        // array.iter().enumerate().for_each(|(i, cbor)| {
        //     println!("  array[{}]: {:?}", i, cbor);
        // });

        Ok(match tag {
            COSE_SIGN_TAG => Self::CoseSign(Self::decode_cose_sign(&array)?),
            COSE_SIGN_ONE_TAG => Self::CoseSignOne(Self::decode_cose_sign_one(&array)?),
            _ => return Err(CoseError::UnexpectedTag),
        })
    }

    pub fn dump(sg: &CoseSignature) {
        println!("======== cose dump");
        println!("  signature_type: {:?}", sg.signature_type);
        println!("  signature: [len={}] {:?}", sg.signature.len(), sg.signature);
        println!("  signer_cert: [len={}] {:?}", sg.signer_cert.len(), sg.signer_cert);
        println!("  to_verify: [len={}] {:?}", sg.to_verify.len(), sg.to_verify);
        println!("  ====");
    }

    fn decode_cose_sign(cose_sign_array: &[CborType]) -> Result<Vec<CoseSignature>, CoseError> {
        decode_signature_multiple(cose_sign_array, &vec![0]) // dummy
    }

    fn decode_cose_sign_one(cose_sign_array: &[CborType]) -> Result<CoseSignature, CoseError> {
        let bytes_from = |cbor: &CborType| Ok(unpack!(Bytes, cbor).clone());
        let map_value_from =
            |cbor: &CborType, key| get_map_value(unpack!(Map, cbor), key);
        let debug_permissive = true; // TODO kludge

        //

        let protected_bucket = &cose_sign_array[0];
        let signature_type = if let Ok(pb) = &cose::decoder::decode(&bytes_from(protected_bucket)?) {
            if let Ok(alg) = map_value_from(pb, &CborType::Integer(COSE_HEADER_ALG)) {
                resolve_alg(&alg)?
            } else if debug_permissive {
                println!("⚠️ debug_permissive: missing `signature_type` patched with `SignatureAlgorithm::ES256`");
                SignatureAlgorithm::ES256 // kludge
            } else {
                return Err(CoseError::MissingHeader);
            }
        } else {
            return Err(CoseError::DecodingFailure);
        };

        //

        let unprotected_bucket = &cose_sign_array[1];
        let val = map_value_from(unprotected_bucket, &CborType::Integer(COSE_HEADER_VOUCHER_PUBKEY));
        let signer_cert = if let Ok(val) = val { bytes_from(&val)? } else { Vec::new() };

        //

        let signature = bytes_from(&cose_sign_array[3])?;
        let payload = bytes_from(&cose_sign_array[2])?;

        Ok(CoseSignature {
            signature_type,
            signature,
            signer_cert,
            certs: vec![],
            to_verify: get_sig_one_struct_bytes(protected_bucket.clone(), &payload)
        })
    }
}
