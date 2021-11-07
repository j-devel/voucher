#![no_std]

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

//

#[cfg(test)]
mod tests;

mod cose_data;
use cose_data::CoseData;
pub use cose_data::SignatureAlgorithm;

pub mod debug {
    pub use super::cose_data::CoseData;
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
        if let Ok(cose_data) = CoseData::decode(raw) {
            match cose_data {
                CoseData::CoseSignOne(_) => Some(Self(cose_data)),
                CoseData::CoseSign(_) => {
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
        if let CoseData::CoseSignOne(ref mut sig) = self.0 {
            (&mut sig.signature, &mut sig.signature_type, &sig.to_verify)
        } else {
            unimplemented!();
        }
    }

    /// Interface with meta data to be used in ECDSA based validation
    pub fn to_validate(&self) -> (Option<&[u8]>, &[u8], &SignatureAlgorithm, &[u8]) {
        if let CoseData::CoseSignOne(ref sig) = self.0 {
            let (signature, alg) = self.get_signature();

            (self.get_signer_cert(), signature, alg, &sig.to_verify)
        } else {
            unimplemented!();
        }
    }

    pub fn get_content(&self) -> Option<Vec<u8>> {
        if let CoseData::CoseSignOne(ref sig) = self.0 {
            CoseData::get_content(sig)
        } else {
            unimplemented!();
        }
    }

    pub fn set_content(&mut self, content: &[u8]) -> &mut Self {
        if let CoseData::CoseSignOne(ref mut sig) = self.0 {
            CoseData::cs_set_content(sig, content);
        } else {
            unimplemented!();
        }

        self
    }

    pub fn get_signature(&self) -> (&[u8], &SignatureAlgorithm) {
        if let CoseData::CoseSignOne(ref sig) = self.0 {
            (&sig.signature, &sig.signature_type)
        } else {
            unimplemented!();
        }
    }

    pub fn get_signer_cert(&self) -> Option<&[u8]> {
        if let CoseData::CoseSignOne(ref sig) = self.0 {
            let signer_cert = &sig.signer_cert;

            if signer_cert.len() > 0 { Some(signer_cert) } else { None }
        } else {
            unimplemented!();
        }
    }

    pub fn dump(&self) {
        self.0.dump();
    }
}
