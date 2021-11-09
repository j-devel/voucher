#[cfg(feature = "std")]
use std::{println, boxed::Box, vec, vec::Vec, collections::BTreeMap};
#[cfg(not(feature = "std"))]
use mcu_if::{println, alloc::{boxed::Box, vec, vec::Vec, collections::BTreeMap}};

use cose::{decoder::*, unpack};
pub use cose::decoder::{SignatureAlgorithm, COSE_SIGN_ONE_TAG};

pub const COSE_HEADER_VOUCHER_PUBKEY: u64 = 60299;

type BTMCC = BTreeMap<CborType, CborType>;

pub struct CoseData {
    protected_bucket: BTMCC,
    unprotected_bucket: BTMCC,
    inner: CoseDataInner,
}

enum CoseDataInner {
    CoseSignOne(CoseSignature),
    CoseSign(Vec<CoseSignature>),
}

impl CoseData {
    pub fn sig(&self) -> &CoseSignature {
        if let CoseDataInner::CoseSignOne(ref sig) = self.inner {
            sig
        } else {
            unimplemented!();
        }
    }

    pub fn sig_mut(&mut self) -> &mut CoseSignature {
        if let CoseDataInner::CoseSignOne(ref mut sig) = self.inner {
            sig
        } else {
            unimplemented!();
        }
    }

    pub fn new(is_sign1: bool) -> Self {
        if !is_sign1 { unimplemented!(); }

        Self {
            protected_bucket: BTreeMap::new(),
            unprotected_bucket: BTreeMap::new(),
            inner: CoseDataInner::CoseSignOne(CoseSignature {
                signature_type: SignatureAlgorithm::ES256, // default
                signature: vec![],
                signer_cert: vec![],
                certs: vec![],
                to_verify: vec![],
            }),
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<(u64, Self), CoseError> {
        match get_cose_sign_array(bytes)? {
            (COSE_SIGN_ONE_TAG, ref array) => {
                let (protected_bucket, unprotected_bucket, sig) = Self::decode_cose_sign_one(array)?;

                Ok((COSE_SIGN_ONE_TAG, Self {
                    protected_bucket,
                    unprotected_bucket,
                    inner: CoseDataInner::CoseSignOne(sig),
                }))
            },
            (COSE_SIGN_TAG, ref array) => {
                let (protected_bucket, unprotected_bucket, sigs) = Self::decode_cose_sign(array)?;

                Ok((COSE_SIGN_TAG, Self {
                    protected_bucket,
                    unprotected_bucket,
                    inner: CoseDataInner::CoseSign(sigs),
                }))
            },
            (_, ref array) => {
                Self::dump_cose_sign_array(array);
                Err(CoseError::UnexpectedTag)
            },
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, CoseError> {
        if let CoseDataInner::CoseSignOne(sig) = &self.inner {
            utils::encode(sig, &self.protected_bucket, &self.unprotected_bucket)
        } else {
            unimplemented!();
        }
    }

    pub fn dump(&self) {
        match &self.inner {
            CoseDataInner::CoseSignOne(sig) => utils::dump(sig),
            CoseDataInner::CoseSign(sigs) => sigs.iter().for_each(|sig| utils::dump(sig)),
        }
    }

    pub fn get_content(&self) -> Option<Vec<u8>>{
        match &self.inner {
            CoseDataInner::CoseSignOne(sig) => utils::get_content(sig),
            CoseDataInner::CoseSign(_) => unimplemented!(),
        }
    }

    pub fn set_content(&mut self, content: &[u8]) {
        match &mut self.inner {
            CoseDataInner::CoseSignOne(sig) => utils::set_content(
                sig, content, &self.protected_bucket),
            CoseDataInner::CoseSign(_) => unimplemented!(),
        }
    }

    fn dump_cose_sign_array(array: &[CborType]) {
        array.iter().enumerate().for_each(|(i, cbor)| {
            println!("  array[{}]: {:?}", i, cbor);
        });
    }

    fn decode_cose_sign(cose_sign_array: &[CborType]) -> Result<(BTMCC, BTMCC, Vec<CoseSignature>), CoseError> {
        Ok(( // dummy
            BTreeMap::new(),
            BTreeMap::new(),
            decode_signature_multiple(cose_sign_array, &vec![0u8])?
        ))
    }

    fn decode_cose_sign_one(cose_sign_array: &[CborType]) -> Result<(BTMCC, BTMCC, CoseSignature), CoseError> {
        let is_permissive = true;
        let pb_cbor_serialized = &cose_sign_array[0];

        //

        let mut pb = None;
        let mut ty = None;

        if let Ok(ref pb_cbor) = cose::decoder::decode(&utils::bytes_from(pb_cbor_serialized)?) {
            pb.replace(unpack!(Map, pb_cbor).clone());

            if let Ok(alg) = utils::map_value_from(pb_cbor, &CborType::Integer(COSE_HEADER_ALG)) {
                ty.replace(resolve_alg(&alg)?);
            } else if is_permissive {
                println!("⚠️ missing `signature_type`; ES256 is assumed");
                ty.replace(SignatureAlgorithm::ES256);
            } else {
                return Err(CoseError::MissingHeader);
            }
        } else {
            return Err(CoseError::DecodingFailure);
        }

        let pb = pb.unwrap();
        let signature_type = ty.unwrap();

        //

        let upb_cbor = &cose_sign_array[1];
        let upb = unpack!(Map, upb_cbor).clone();

        let val = utils::map_value_from(upb_cbor, &CborType::Integer(COSE_HEADER_VOUCHER_PUBKEY));
        let signer_cert = if let Ok(val) = val { utils::bytes_from(&val)? } else { Vec::new() };

        //

        let signature = utils::bytes_from(&cose_sign_array[3])?;
        let content = utils::bytes_from(&cose_sign_array[2])?;

        let sig = CoseSignature {
            signature_type,
            signature,
            signer_cert,
            certs: vec![],
            to_verify: get_sig_one_struct_bytes(pb_cbor_serialized.clone(), &content)
        };

        Ok((pb, upb, sig))
    }
}

pub mod utils { // TODO -- probably detached as 'signature.rs' (for `Signature(CoseSignature)`) eventually
    use super::*;

    pub fn bytes_from(cbor: &CborType) -> Result<Vec<u8>, CoseError> {
        Ok(unpack!(Bytes, cbor).clone())
    }

    pub fn map_value_from(cbor: &CborType, key: &CborType) -> Result<CborType, CoseError> {
        get_map_value(unpack!(Map, cbor), key)
    }

    pub fn sig_one_struct_bytes_from(
        protected_bucket: &BTMCC,
        content: &[u8]
    ) -> Vec<u8> {
        let empty = protected_bucket.is_empty();
        let protected_bucket = CborType::Map(protected_bucket.clone()).serialize();
        if empty {
            assert_eq!(vec![0xa0], protected_bucket);
        }

        get_sig_one_struct_bytes(CborType::Bytes(protected_bucket), content)
    }

    //
    // w.r.t. `CoseSignature`
    //

    pub fn encode(
        sig: &CoseSignature,
        protected_bucket: &BTMCC,
        unprotected_bucket: &BTMCC
    ) -> Result<Vec<u8>, CoseError> {
        let array = vec![
            CborType::Bytes(CborType::Map(protected_bucket.clone()).serialize()),
            CborType::Map(unprotected_bucket.clone()),
            CborType::Bytes(utils::get_content(sig).unwrap()),
            CborType::Bytes(sig.signature.clone())];

        Ok(CborType::Tag(COSE_SIGN_ONE_TAG, Box::new(CborType::Array(array))).serialize())
    }

    pub fn dump(sig: &CoseSignature) {
        println!("======== `CoseSignature` dump");
        println!("  signature_type: {:?}", sig.signature_type);
        println!("  signature: [len={}] {:?}", sig.signature.len(), sig.signature);
        println!("  signer_cert: [len={}] {:?}", sig.signer_cert.len(), sig.signer_cert);
        println!("  to_verify: [len={}] {:?}", sig.to_verify.len(), sig.to_verify);
        println!("  ====");
    }

    pub fn get_content(sig: &CoseSignature) -> Option<Vec<u8>> {
        if let Ok(CborType::Array(values)) = decode(&sig.to_verify) {
            if values.len() != 4 {
                return None;
            }

            bytes_from(&values[3]).ok()
        } else {
            None
        }
    }

    pub fn set_content(
        sig: &mut CoseSignature,
        content: &[u8],
        protected_bucket: &BTMCC
    ) {
        sig.to_verify = sig_one_struct_bytes_from(protected_bucket, content);
    }
}