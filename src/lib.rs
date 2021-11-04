#![no_std]

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

//

#[cfg(test)]
mod tests;

mod cose_data;
use cose_data::CoseSignature;
pub use cose_data::{CoseData, SignatureAlgorithm};

pub struct Voucher(CoseSignature);

pub trait Sign {
    fn sign(&mut self, privkey_pem: &[u8], alg: SignatureAlgorithm);
}

pub trait Validate {
    fn validate(&self, pubkey_pem: Option<&[u8]>) -> bool;
}

#[cfg(any(feature = "sign", feature = "validate-lts"))]
mod sign;

#[cfg(any(feature = "validate", feature = "validate-lts"))]
mod validate;

//

#[cfg(feature = "std")]
use std::vec::Vec;
#[cfg(not(feature = "std"))]
use mcu_if::alloc::vec::Vec;

//

impl Voucher {
    pub fn new() -> Self {
        Self(CoseData::new_cose_signature())
    }

    pub fn from(raw: &[u8]) -> Self {
        if let Ok(cose_data) = CoseData::decode(raw) {
            match cose_data {
                CoseData::CoseSignOne(cose_signature) => return Self(cose_signature),
                CoseData::CoseSign(_) => unimplemented!("Only `CoseSign1` vouchers are supported"),
            }
        } else {
            panic!("Failed to decode raw voucher");
        };
    }

    /// Interface with meta data to be used in ECDSA based signing
    pub fn to_sign(&mut self) -> (&mut Vec<u8>, &mut SignatureAlgorithm, &[u8]) {
        (&mut self.0.signature, &mut self.0.signature_type, &self.0.to_verify)
    }

    /// Interface with meta data to be used in ECDSA based validation
    pub fn to_validate(&self) -> (Option<&[u8]>, &[u8], &SignatureAlgorithm, &[u8]) {
        let (signature, alg) = self.get_signature();

        (self.get_signer_cert(), signature, alg, &self.0.to_verify)
    }

    pub fn serialize(&self) -> Vec<u8> {
        vec![42u8/* ... */] // WIP
    }

    pub fn get_content(&self) -> Option<Vec<u8>> {

        //Some(vec![42u8]) // WIP
        None
    }

    pub fn set_content(&mut self, content: &[u8]) -> &mut Self {
        self.0.to_verify = CoseData::sig_one_struct_bytes_from(content);

        self
    }

    pub fn get_signature(&self) -> (&[u8], &SignatureAlgorithm) {
        (&self.0.signature, &self.0.signature_type)
    }

    pub fn get_signer_cert(&self) -> Option<&[u8]> {
        let signer_cert = &self.0.signer_cert;

        if signer_cert.len() > 0 { Some(signer_cert) } else { None }
    }

    pub fn dump(&self) {
        CoseData::dump(&self.0);
    }
}
