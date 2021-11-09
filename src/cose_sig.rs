#[cfg(feature = "std")]
use std::{println, boxed::Box, vec, vec::Vec, collections::BTreeMap};
#[cfg(not(feature = "std"))]
use mcu_if::{println, alloc::{boxed::Box, vec, vec::Vec, collections::BTreeMap}};

use cose::{decoder::*, unpack};

//

pub fn bytes_from(cbor: &CborType) -> Result<Vec<u8>, CoseError> {
    Ok(unpack!(Bytes, cbor).clone())
}

pub fn map_value_from(cbor: &CborType, key: &CborType) -> Result<CborType, CoseError> {
    get_map_value(unpack!(Map, cbor), key)
}

pub fn sig_one_struct_bytes_from(
    protected_bucket: &BTreeMap<CborType, CborType>,
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

pub struct CoseSig;

impl CoseSig {

    //
    // w.r.t. `CoseSignature`
    //

    pub fn encode(
        sig: &CoseSignature,
        protected_bucket: &BTreeMap<CborType, CborType>,
        unprotected_bucket: &BTreeMap<CborType, CborType>
    ) -> Result<Vec<u8>, CoseError> {
        let array = vec![
            CborType::Bytes(CborType::Map(protected_bucket.clone()).serialize()),
            CborType::Map(unprotected_bucket.clone()),
            CborType::Bytes(Self::get_content(sig).unwrap()),
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
        protected_bucket: &BTreeMap<CborType, CborType>
    ) {
        sig.to_verify = sig_one_struct_bytes_from(protected_bucket, content);
    }
}