#[cfg(feature = "std")]
use std::{println, boxed::Box, vec, vec::Vec, collections::BTreeMap};
#[cfg(not(feature = "std"))]
use mcu_if::{println, alloc::{boxed::Box, vec, vec::Vec, collections::BTreeMap}};

use cose::{decoder::*, unpack};
pub use cose::decoder::{CoseSignature, SignatureAlgorithm};

pub const COSE_HEADER_VOUCHER_PUBKEY: u64 = 60299;

pub struct CoseData {
    pub tag: u64,
    protected_bucket: BTreeMap<CborType, CborType>,
    unprotected_bucket: BTreeMap<CborType, CborType>,
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
            tag: COSE_SIGN_ONE_TAG,
            protected_bucket: BTreeMap::new(),
            unprotected_bucket: BTreeMap::new(),
            inner: CoseDataInner::CoseSignOne(CoseSignature {
                signature_type: SignatureAlgorithm::ES256, // default
                signature: vec![],
                signer_cert: vec![],
                certs: vec![],
                to_verify: vec![]
            }),
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CoseError> {
        let (tag, array) = get_cose_sign_array(bytes)?;

        Ok(match tag {
            COSE_SIGN_ONE_TAG => Self {
                tag: COSE_SIGN_ONE_TAG,
                protected_bucket: BTreeMap::new(), // !!
                unprotected_bucket: BTreeMap::new(), // !!
                inner: CoseDataInner::CoseSignOne(Self::decode_cose_sign_one(&array)?),
            },
            COSE_SIGN_TAG => Self {
                tag: COSE_SIGN_TAG,
                protected_bucket: BTreeMap::new(), // !!
                unprotected_bucket: BTreeMap::new(), // !!
                inner: CoseDataInner::CoseSign(Self::decode_cose_sign(&array)?),
            },
            _ => {
                Self::dump_cose_sign_array(&array);
                return Err(CoseError::UnexpectedTag)
            },
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, CoseError> {
        if let CoseDataInner::CoseSignOne(sig) = &self.inner {
            utils::encode(sig)
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
            CoseDataInner::CoseSignOne(sig) => utils::set_content(sig, content),
            CoseDataInner::CoseSign(_) => unimplemented!(),
        }
    }

    fn dump_cose_sign_array(array: &[CborType]) {
        array.iter().enumerate().for_each(|(i, cbor)| {
            println!("  array[{}]: {:?}", i, cbor);
        });
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
        let signature_type = if let Ok(pb) = &cose::decoder::decode(&utils::bytes_from(protected_bucket)?) {
            if let Ok(alg) = utils::map_value_from(pb, &CborType::Integer(COSE_HEADER_ALG)) {
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
        let val = utils::map_value_from(unprotected_bucket, &CborType::Integer(COSE_HEADER_VOUCHER_PUBKEY));
        let signer_cert = if let Ok(val) = val { utils::bytes_from(&val)? } else { Vec::new() };

        //

        let signature = utils::bytes_from(&cose_sign_array[3])?;
        let content = utils::bytes_from(&cose_sign_array[2])?;

        Ok(CoseSignature {
            signature_type,
            signature,
            signer_cert,
            certs: vec![],
            to_verify: get_sig_one_struct_bytes(protected_bucket.clone(), &content)
        })
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

    pub fn sig_one_struct_bytes_from(content: &[u8]) -> Vec<u8> {
        // TODO generic !!!!
        let protected_bucket: BTreeMap<CborType, CborType> = BTreeMap::new();

        let protected_bucket = CborType::Map(protected_bucket).serialize();
        assert_eq!(vec![0xa0], protected_bucket);

        get_sig_one_struct_bytes(CborType::Bytes(protected_bucket), content)
    }

    //
    // w.r.t. `CoseSignature`
    //

    pub fn encode(sig: &CoseSignature) -> Result<Vec<u8>, CoseError> {
        // TODO generic !!!!
        let protected_bucket = CborType::Map(BTreeMap::new());

        // TODO generic !!!!
        let unprotected_bucket = CborType::Map(BTreeMap::new());

        let array = vec![
            CborType::Bytes(protected_bucket.serialize()), // `@encoded_protected_bucket`
            unprotected_bucket,                            // `@unprotected_bucket`
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

    pub fn set_content(sig: &mut CoseSignature, content: &[u8]) {
        sig.to_verify = sig_one_struct_bytes_from(content);
    }
}