use crate::{println, Box, vec, Vec, BTreeMap};
use crate::debug_println;
use cose::{decoder::*, unpack};
pub use cose::decoder::{CborType, decode};

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

#[derive(PartialEq, Debug)]
pub struct CoseSig(CoseSignature);

impl core::ops::Deref for CoseSig {
    type Target = CoseSignature;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl core::ops::DerefMut for CoseSig {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl CoseSig {
    pub fn new(inner: CoseSignature) -> Self {
        CoseSig(inner)
    }

    pub fn new_default() -> Self {
        CoseSig(CoseSignature {
            signature_type: SignatureAlgorithm::ES256,
            signature: vec![],
            signer_cert: vec![],
            certs: vec![],
            to_verify: vec![],
        })
    }

    pub fn encode(&self,
        protected_bucket: &BTreeMap<CborType, CborType>,
        unprotected_bucket: &BTreeMap<CborType, CborType>,
        content: Vec<u8>
    ) -> Result<Vec<u8>, CoseError> {
        let array = vec![
            CborType::Bytes(CborType::Map(protected_bucket.clone()).serialize()),
            CborType::Map(unprotected_bucket.clone()),
            CborType::Bytes(content),
            CborType::Bytes(self.signature.clone())];

        Ok(CborType::Tag(COSE_SIGN_ONE_TAG, Box::new(CborType::Array(array))).serialize())
    }

    pub fn dump(&self) {
        println!("==== CoseSig::dump()");
        println!("signature_type: {:?}", self.signature_type);
        println!("signature: [len={}] {:?}", self.signature.len(), self.signature);
        println!("signer_cert: [len={}] {:?}", self.signer_cert.len(), self.signer_cert);
        println!("to_verify: [len={}] {:?}", self.to_verify.len(), self.to_verify);
        println!("====");
    }

    pub fn extract_content(&self) -> Result<Vec<u8>, CoseError> {
        if let Ok(CborType::Array(values)) = decode(&self.to_verify) {
            if values.len() != 4 {
                return Err(CoseError::MalformedInput);
            }

            bytes_from(&values[3]).or_else(|ce| {
                debug_println!("extract_content(): ce: {:?}", ce);
                Err(ce)
            })
        } else {
            debug_println!("extract_content(): failed to decode content");
            Err(CoseError::DecodingFailure)
        }
    }

    pub fn set_content(&mut self, content: &[u8], protected_bucket: &BTreeMap<CborType, CborType>) -> &mut Self {
        self.to_verify = sig_one_struct_bytes_from(protected_bucket, content);

        self
    }
}
