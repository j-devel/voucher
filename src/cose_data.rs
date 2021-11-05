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
        //Self::dump_cose_sign_array(&array);

        Ok(match tag {
            COSE_SIGN_TAG => Self::CoseSign(Self::decode_cose_sign(&array)?),
            COSE_SIGN_ONE_TAG => Self::CoseSignOne(Self::decode_cose_sign_one(&array)?),
            _ => {
                Self::dump_cose_sign_array(&array);
                return Err(CoseError::UnexpectedTag)
            },
        })
    }

    fn dump_cose_sign_array(array: &[CborType]) {
        array.iter().enumerate().for_each(|(i, cbor)| {
            println!("  array[{}]: {:?}", i, cbor);
        });
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
        let is_permissive = true;
        let protected_bucket = &cose_sign_array[0];

        // TODO -- not only `alg`, keep all pairs found in map; like 'cose_sign1.rb'
        //```
        // CBOR::Unpacker.new(StringIO.new(@encoded_protected_bucket)).each { |thing|
        //   @protected_bucket = thing
        // }
        //```
        let signature_type = if let Ok(pb) = &cose::decoder::decode(&Self::bytes_from(protected_bucket)?) {
            if let Ok(alg) = Self::map_value_from(pb, &CborType::Integer(COSE_HEADER_ALG)) {
                resolve_alg(&alg)?
            } else if is_permissive {
                println!("⚠️ missing `signature_type`; ES256 is assumed");
                SignatureAlgorithm::ES256
            } else {
                return Err(CoseError::MissingHeader);
            }
        } else {
            return Err(CoseError::DecodingFailure);
        };

        //

        // TODO -- not only `signer_cert`, keep all pairs found in map; like 'cose_sign1.rb'
        //```
        // if(@raw_cbor.value[1].class == Hash)
        // @unprotected_bucket = @raw_cbor.value[1]
        // end
        //```
        let unprotected_bucket = &cose_sign_array[1];
        let val = Self::map_value_from(unprotected_bucket, &CborType::Integer(COSE_HEADER_VOUCHER_PUBKEY));
        let signer_cert = if let Ok(val) = val { Self::bytes_from(&val)? } else { Vec::new() };

        //

        let signature = Self::bytes_from(&cose_sign_array[3])?;
        let content = Self::bytes_from(&cose_sign_array[2])?;

        Ok(CoseSignature {
            signature_type,
            signature,
            signer_cert,
            certs: vec![],
            to_verify: get_sig_one_struct_bytes(protected_bucket.clone(), &content)
        })
    }

    pub fn sig_one_struct_bytes_from(content: &[u8]) -> Vec<u8> {
        // TODO generic !!!!
        let protected_bucket: BTreeMap<CborType, CborType> = BTreeMap::new();

        let protected_bucket = CborType::Map(protected_bucket).serialize();
        assert_eq!(vec![0xa0], protected_bucket);

        get_sig_one_struct_bytes(CborType::Bytes(protected_bucket), content)
    }

    pub fn set_content(cose_sig: &mut CoseSignature, content: &[u8]) {
        cose_sig.to_verify = Self::sig_one_struct_bytes_from(content);
    }

    pub fn serialize(cose_sig: &CoseSignature) -> Result<Vec<u8>, CoseError> {
        // TODO generic !!!!
        let protected_bucket = CborType::Map(BTreeMap::new());

        // TODO generic !!!!
        let unprotected_bucket = CborType::Map(BTreeMap::new());

        let array = vec![
            CborType::Bytes(protected_bucket.serialize()), // `@encoded_protected_bucket`
            unprotected_bucket,                            // `@unprotected_bucket`
            CborType::Bytes(Self::get_content(cose_sig).unwrap()),
            CborType::Bytes(cose_sig.signature.clone())];

        Ok(CborType::Tag(COSE_SIGN_ONE_TAG, Box::new(CborType::Array(array))).serialize())
    }

    pub fn get_content(cose_sig: &CoseSignature) -> Option<Vec<u8>> {
        if let Ok(CborType::Array(values)) = decode(&cose_sig.to_verify) {
            if values.len() != 4 {
                return None;
            }

            Self::bytes_from(&values[3]).ok()
        } else {
            None
        }
    }

    fn bytes_from(cbor: &CborType) -> Result<Vec<u8>, CoseError> {
        Ok(unpack!(Bytes, cbor).clone())
    }

    fn map_value_from(cbor: &CborType, key: &CborType) -> Result<CborType, CoseError> {
        get_map_value(unpack!(Map, cbor), key)
    }
}
