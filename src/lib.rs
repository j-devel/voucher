#![no_std]

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

#[cfg(feature = "std")]
use std::{println, boxed::Box, vec, vec::Vec, collections::BTreeMap};
#[cfg(not(feature = "std"))]
use mcu_if::{println, alloc::{boxed::Box, vec, vec::Vec, collections::BTreeMap}};

//

#[cfg(test)]
mod tests;

mod cose_data;
use cose_data::{CoseData, COSE_SIGN_ONE_TAG};
pub use cose_data::SignatureAlgorithm;

pub mod debug {
    pub use super::cose_sig::{sig_one_struct_bytes_from, CborType, decode};
}

mod cose_sig;

pub struct Voucher(CoseData);

pub trait Sign {
    fn sign(&mut self, privkey_pem: &[u8], alg: SignatureAlgorithm);
}

pub trait Validate {
    fn validate(&self, pem: Option<&[u8]>) -> bool;
}

#[cfg(any(feature = "sign", feature = "sign-lts"))]
mod sign;

#[cfg(any(feature = "validate", feature = "validate-lts"))]
mod validate;

//

impl Voucher {
    pub fn new() -> Self {
        Self(CoseData::new(true))
    }

    pub fn from(raw: &[u8]) -> Option<Self> {
        if let Ok((tag, data)) = CoseData::decode(raw) {
            if tag == COSE_SIGN_ONE_TAG {
                Some(Self(data))
            } else {
                println!("Only `CoseSign1` vouchers are supported");
                None
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
        use core::ops::DerefMut;
        let sig = self.0.sig_mut().deref_mut();

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

//

#[cfg(any(feature = "sign", feature = "sign-lts", feature = "validate", feature = "validate-lts"))]
mod minerva_mbedtls_utils {
    use super::*;
    use minerva_mbedtls::ifce::*;
    use core::ffi::c_void;

    pub fn compute_digest(msg: &[u8], alg: &SignatureAlgorithm) -> (md_type, Vec<u8>) {
        let ty = match *alg {
            SignatureAlgorithm::ES256 => md_type::MBEDTLS_MD_SHA256,
            SignatureAlgorithm::ES384 => md_type::MBEDTLS_MD_SHA384,
            SignatureAlgorithm::ES512 => md_type::MBEDTLS_MD_SHA512,
            SignatureAlgorithm::PS256 => unimplemented!("TODO: handle PS256"),
        };

        (ty, md_info::from_type(ty).md(msg))
    }

    pub fn pk_from_privkey_pem(privkey_pem: &[u8], f_rng: *const c_void) -> Result<pk_context, mbedtls_error> {
        let mut pk = pk_context::new();

        #[cfg(any(feature = "validate-lts", feature = "sign-lts"))]
        {
            let _ = f_rng;
            pk.parse_key_lts(privkey_pem, None)?;
        }
        #[cfg(not(any(feature = "validate-lts", feature = "sign-lts")))]
        {
            pk.parse_key(privkey_pem, None, f_rng, core::ptr::null())?;
        }

        Ok(pk)
    }
}

//

pub fn wip_vrhash_sidhash_content() -> Vec<u8> {
    let content = [161, 26, 0, 15, 70, 194, 164, 1, 105, 112, 114, 111, 120, 105, 109, 105, 116, 121, 2, 193, 26, 97, 119, 115, 164, 10, 81, 48, 48, 45, 68, 48, 45, 69, 53, 45, 48, 50, 45, 48, 48, 45, 50, 69, 7, 118, 114, 72, 103, 99, 66, 86, 78, 86, 97, 70, 109, 66, 87, 98, 84, 77, 109, 101, 79, 75, 117, 103]
        .to_vec();

    content
}
