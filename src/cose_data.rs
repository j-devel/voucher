use crate::{vec, Vec, BTreeMap};
use crate::debug_println;

use cose::{decoder::*, unpack};
pub use cose::decoder::{SignatureAlgorithm, COSE_SIGN_ONE_TAG};

use super::cose_sig::{CoseSig, bytes_from, map_value_from};

//

pub const COSE_HEADER_VOUCHER_PUBKEY: u64 = 60299;

#[derive(PartialEq, Debug)]
pub struct CoseData {
    protected_bucket: BTreeMap<CborType, CborType>,
    unprotected_bucket: BTreeMap<CborType, CborType>,
    inner: CoseDataInner,
}

#[derive(PartialEq, Debug)]
enum CoseDataInner {
    CoseSignOne(CoseSig),
    CoseSign(Vec<CoseSig>),
}

impl CoseData {
    pub fn sig(&self) -> &CoseSig {
        if let CoseDataInner::CoseSignOne(ref sig) = self.inner {
            sig
        } else {
            unimplemented!();
        }
    }

    pub fn sig_mut(&mut self) -> &mut CoseSig {
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
            inner: CoseDataInner::CoseSignOne(CoseSig::new(CoseSignature {
                signature_type: SignatureAlgorithm::ES256, // default
                signature: vec![],
                signer_cert: vec![],
                certs: vec![],
                to_verify: vec![],
            })),
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<(u64, Self), CoseError> {
        match get_cose_sign_array(bytes)? {
            (COSE_SIGN_ONE_TAG, ref array) => {
                let (pb, upb, sig) = Self::decode_cose_sign_one(array)?;

                Ok((COSE_SIGN_ONE_TAG, Self {
                    protected_bucket: pb,
                    unprotected_bucket: upb,
                    inner: CoseDataInner::CoseSignOne(sig),
                }))
            },
            (COSE_SIGN_TAG, ref array) => {
                let (pb, upb, sigs) = Self::decode_cose_sign(array)?;

                Ok((COSE_SIGN_TAG, Self {
                    protected_bucket: pb,
                    unprotected_bucket: upb,
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
            CoseSig::encode(sig, &self.protected_bucket, &self.unprotected_bucket)
        } else {
            unimplemented!();
        }
    }

    pub fn dump(&self) {
        match &self.inner {
            CoseDataInner::CoseSignOne(sig) => CoseSig::dump(sig),
            CoseDataInner::CoseSign(sigs) => sigs.iter().for_each(|sig| CoseSig::dump(sig)),
        }
    }

    pub fn get_content(&self) -> Option<Vec<u8>>{
        match &self.inner {
            CoseDataInner::CoseSignOne(sig) => CoseSig::get_content(sig),
            CoseDataInner::CoseSign(_) => unimplemented!(),
        }
    }

    pub fn set_content(&mut self, content: &[u8]) {
        match &mut self.inner {
            CoseDataInner::CoseSignOne(sig) => CoseSig::set_content(
                sig, content, &self.protected_bucket),
            CoseDataInner::CoseSign(_) => unimplemented!(),
        }
    }

    fn dump_cose_sign_array(array: &[CborType]) {
        array.iter().enumerate().for_each(|(i, cbor)| {
            debug_println!("  array[{}]: {:?}", i, cbor);
        });
    }

    fn decode_cose_sign(cose_sign_array: &[CborType]
    ) -> Result<(BTreeMap<CborType, CborType>,
                 BTreeMap<CborType, CborType>,
                 Vec<CoseSig>), CoseError> {
        Ok((
            BTreeMap::new(), // dummy
            BTreeMap::new(), // dummy
            decode_signature_multiple(cose_sign_array, &vec![0u8])? // dummy
                .into_iter()
                .map(|inner| CoseSig::new(inner))
                .collect()
        ))
    }

    fn decode_cose_sign_one(cose_sign_array: &[CborType]
    ) -> Result<(BTreeMap<CborType, CborType>,
                 BTreeMap<CborType, CborType>,
                 CoseSig), CoseError> {
        let is_permissive = true;
        let pb_cbor_serialized = &cose_sign_array[0];

        //

        let mut pb = None;
        let mut ty = None;

        if let Ok(ref pb_cbor) = cose::decoder::decode(&bytes_from(pb_cbor_serialized)?) {
            pb.replace(unpack!(Map, pb_cbor).clone());

            if let Ok(alg) = map_value_from(pb_cbor, &CborType::Integer(COSE_HEADER_ALG)) {
                ty.replace(resolve_alg(&alg)?);
            } else if is_permissive {
                debug_println!("⚠️ missing `signature_type`; ES256 is assumed");
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

        let val = map_value_from(upb_cbor, &CborType::Integer(COSE_HEADER_VOUCHER_PUBKEY));
        let signer_cert = if let Ok(val) = val { bytes_from(&val)? } else { Vec::new() };

        //

        let signature = bytes_from(&cose_sign_array[3])?;
        let content = bytes_from(&cose_sign_array[2])?;

        let sig = CoseSig::new(CoseSignature {
            signature_type,
            signature,
            signer_cert,
            certs: vec![],
            to_verify: get_sig_one_struct_bytes(pb_cbor_serialized.clone(), &content)
        });

        Ok((pb, upb, sig))
    }
}
