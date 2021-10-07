#![no_std]

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

//

mod cose_data;
use cose_data::{CoseData, CoseSignature};
pub use cose_data::SignatureAlgorithm;

pub struct Voucher(CoseSignature);

pub trait Validate {
    fn validate(&self, masa_pem: Option<&[u8]>) -> bool;
}

#[cfg(feature = "minerva-voucher-validate")]
mod validate;

#[cfg(feature = "minerva-voucher-validate")]
impl Validate for Voucher {
    fn validate(&self, masa_pem: Option<&[u8]>) -> bool {
        validate::validate(masa_pem, self.to_validate())
    }
}

impl Voucher {
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

    pub fn to_validate(&self) -> (Option<&[u8]>, &[u8], &SignatureAlgorithm, &[u8]) {
        let (signature, alg) = self.get_signature();

        (self.get_signer_cert(), signature, alg, &self.0.to_verify)
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

//

#[cfg(feature = "std")]
use std::{println, vec, vec::Vec};
#[cfg(not(feature = "std"))]
use mcu_if::{println, alloc::{vec, vec::Vec}};

pub fn foo() {
    let v = vec![0, 1, 2];
    println!("v: {:?}", v);
    assert_eq!(v, Vec::from([0, 1, 2]));
}

#[test]
fn test_foo() {
    foo();
}
