#![no_std]

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

//

#[cfg(test)]
mod tests;

mod cose_data;
use cose_data::{CoseData, CoseSignature};
pub use cose_data::SignatureAlgorithm;

pub mod debug {
    pub use super::cose_data::utils::sig_one_struct_bytes_from;
}

pub struct Voucher(CoseData);

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
use std::{println, vec::Vec};
#[cfg(not(feature = "std"))]
use mcu_if::{println, alloc::vec::Vec};

//

impl Voucher {
    pub fn new() -> Self {
        Self(CoseData::new(true))
    }

    pub fn from(raw: &[u8]) -> Option<Self> {
        if let Ok(data) = CoseData::decode(raw) {
            match data.tag {
                COSE_SIGN_ONE_TAG => Some(Self(data)),
                COSE_SIGN_TAG => {
                    println!("Only `CoseSign1` vouchers are supported");
                    None
                },
            }
        } else {
            println!("Failed to decode raw voucher");
            None
        }
    }

    pub fn serialize(&self) -> Option<Vec<u8>> {
        CoseData::encode(&self.0).ok()
    }

    /// Interface with meta data to be used in ECDSA based signing
    pub fn to_sign(&mut self) -> (&mut Vec<u8>, &mut SignatureAlgorithm, &[u8]) {
        let sig = self.0.sig_mut();

        (&mut sig.signature, &mut sig.signature_type, &sig.to_verify)
    }

    /// Interface with meta data to be used in ECDSA based validation
    pub fn to_validate(&self) -> (Option<&[u8]>, &[u8], &SignatureAlgorithm, &[u8]) {
        let (signature, alg) = self.get_signature();

        (self.get_signer_cert(), signature, alg, &self.0.sig().to_verify)
    }

    pub fn get_content(&self) -> Option<Vec<u8>> {
        self.0.get_content()
    }

    pub fn set_content(&mut self, content: &[u8]) -> &mut Self {
        self.0.set_content(content);

        self
    }

    pub fn get_signature(&self) -> (&[u8], &SignatureAlgorithm) {
        let sig = self.0.sig();

        (&sig.signature, &sig.signature_type)
    }

    pub fn get_signer_cert(&self) -> Option<&[u8]> {
        let signer_cert = &self.0.sig().signer_cert;

        if signer_cert.len() > 0 { Some(signer_cert) } else { None }
    }

    pub fn dump(&self) {
        self.0.dump();
    }
}