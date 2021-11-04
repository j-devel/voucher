#[cfg(feature = "std")]
use std::{println, boxed::Box, vec, vec::Vec, collections::BTreeMap};
#[cfg(not(feature = "std"))]
use mcu_if::{println, alloc::{boxed::Box, vec, vec::Vec, collections::BTreeMap}};

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

    pub fn new_cose_signature() -> CoseSignature {
        CoseSignature {
            signature_type: SignatureAlgorithm::ES256, // default
            signature: vec![],
            signer_cert: vec![],
            certs: vec![],
            to_verify: vec![]
        }
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
        decode_signature_multiple(cose_sign_array, &vec![0u8]) // dummy
    }

    fn decode_cose_sign_one(cose_sign_array: &[CborType]) -> Result<CoseSignature, CoseError> {
        let bytes_from = |cbor: &CborType| Ok(unpack!(Bytes, cbor).clone());
        let map_value_from =
            |cbor: &CborType, key| get_map_value(unpack!(Map, cbor), key);
        let debug_permissive = true;

        //

        let protected_bucket = &cose_sign_array[0];
        let signature_type = if let Ok(pb) = &cose::decoder::decode(&bytes_from(protected_bucket)?) {
            if let Ok(alg) = map_value_from(pb, &CborType::Integer(COSE_HEADER_ALG)) {
                resolve_alg(&alg)?
            } else if debug_permissive {
                println!("⚠️ debug_permissive: missing `signature_type` patched with `SignatureAlgorithm::ES256`");
                SignatureAlgorithm::ES256
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
        let content = bytes_from(&cose_sign_array[2])?;

        Ok(CoseSignature {
            signature_type,
            signature,
            signer_cert,
            certs: vec![],
            to_verify: get_sig_one_struct_bytes(protected_bucket.clone(), &content)
        })
    }

    pub fn sig_one_struct_bytes_from(content: &[u8]) -> Vec<u8> {
        let protected_bucket: BTreeMap<CborType, CborType> = BTreeMap::new(); // empty

        let protected_bucket = CborType::Map(protected_bucket).serialize();
        assert_eq!(vec![0xa0], protected_bucket);

        get_sig_one_struct_bytes(CborType::Bytes(protected_bucket), content)
    }

    pub fn serialize(cose_sig: &CoseSignature) -> Result<Vec<u8>, CoseError> {
        // TODO generic !!!!
        let protected_bucket: BTreeMap<CborType, CborType> = BTreeMap::new();

        let array = vec![
            CborType::Bytes(CborType::Map(protected_bucket).serialize()),
            CborType::Map(BTreeMap::new()), // TODO generic !!!!
            CborType::Bytes(Self::get_content(cose_sig).unwrap()),
            CborType::Bytes(cose_sig.signature.clone())];

        Ok(CborType::Tag(COSE_SIGN_ONE_TAG, Box::new(CborType::Array(array))).serialize())
    }

    pub fn get_content(cose_sig: &CoseSignature) -> Option<Vec<u8>> {
        let _tv = &cose_sig.to_verify;

        // WIP

        // Some(vec![43u8])
        Some(vec![161, 26, 0, 15, 70, 194, 164, 1, 105, 112, 114, 111, 120, 105, 109, 105, 116, 121, 2, 193, 26, 97, 119, 115, 164, 10, 81, 48, 48, 45, 68, 48, 45, 69, 53, 45, 48, 50, 45, 48, 48, 45, 50, 69, 7, 118, 114, 72, 103, 99, 66, 86, 78, 86, 97, 70, 109, 66, 87, 98, 84, 77, 109, 101, 79, 75, 117, 103])
    }
}
