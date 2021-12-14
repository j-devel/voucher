#![no_std]

#![feature(arbitrary_enum_discriminant)]
#![feature(core_intrinsics)]

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

#[cfg(feature = "std")]
use std::{println, boxed::Box, string, vec, vec::Vec, collections::{BTreeMap, BTreeSet}};
#[cfg(not(feature = "std"))]
use mcu_if::{println, alloc::{boxed::Box, string, vec, vec::Vec, collections::{BTreeMap, BTreeSet}}};

//

#[cfg(test)]
mod tests;

//

mod sid_data;
use sid_data::SidData;
pub use sid_data::{Sid, TopLevel, YangEnum};

mod cose_data;
use cose_data::{CoseData, COSE_SIGN_ONE_TAG};
pub use cose_data::SignatureAlgorithm;

mod cose_sig;

pub mod debug {
    pub use super::cose_sig::{sig_one_struct_bytes_from, CborType, decode};
    pub use super::sid_data::{content_comp, vrhash_sidhash_content_02_00_2e};
}

//

#[derive(PartialEq)]
pub struct Voucher {
    sid: SidData,
    cose: CoseData,
}

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

//---- TODO
// ```
// let vch = Voucher::new().set(Sid::xx0(yy0)).set(Sid::xx1(yy1)).unset(Sid::xx1(yy1)) ...
// ```

use core::convert::TryFrom;

//---- TODO ??
impl TryFrom<&[Sid]> for Voucher {
    type Error = &'static str;

    fn try_from(_content: &[Sid]) -> Result<Self, Self::Error> {
        Err("WIP")
    }
}
//----
impl TryFrom<&[u8]> for Voucher {
    type Error = &'static str;

    fn try_from(raw: &[u8]) -> Result<Self, Self::Error> {
        if let Ok((tag, cose)) = CoseData::decode(raw) {
            if tag == COSE_SIGN_ONE_TAG {
                let sid = SidData::new_vch(); // dummy; TODO reflect the ty decoded !!!!
                Ok(Self { sid, cose })
            } else {
                Err("Only `CoseSign1` vouchers are supported")
            }
        } else {
            Err("Failed to decode raw voucher")
        }
    }
}

//

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum VoucherType {
    Vch, // 'voucher'
    Vrq, // 'voucher request'
}

impl Voucher {
    pub fn new(ty: VoucherType) -> Self {
        Self {
            sid: match ty {
                VoucherType::Vch => SidData::new_vch(),
                VoucherType::Vrq => SidData::new_vrq(),
            },
            cose: CoseData::new(true),
        }
    }

    pub fn get_voucher_type(&self) -> VoucherType {
        VoucherType::Vch // TODO // matches!(self.sid, ...)
    }

    pub fn serialize(&self) -> Option<Vec<u8>> {
        CoseData::encode(&self.cose).ok()
    }

    pub fn set(&mut self, sid: Sid) -> &mut Self {
        self.sid.replace(sid);

        self
    }

    /// Interface with meta data to be used in ECDSA based signing
    pub fn to_sign(&mut self) -> (&mut Vec<u8>, &mut SignatureAlgorithm, &[u8]) {
        use core::ops::DerefMut;

        let sig = self
            .update_cose_content()
            .cose.sig_mut().deref_mut();

        (&mut sig.signature, &mut sig.signature_type, &sig.to_verify)
    }

    /// Interface with meta data to be used in ECDSA based validation
    pub fn to_validate(&self) -> (Option<&[u8]>, &[u8], &SignatureAlgorithm, &[u8]) {
        let (signature, alg) = self.get_signature();

        (self.get_signer_cert(), signature, alg, &self.cose.sig().to_verify)
    }

    fn update_cose_content(&mut self) -> &mut Self {
        use sid_data::Cbor;

        let content = if let Some(cbor) = self.sid.serialize() {
            cbor
        } else {
            println!("update_cose_content(): Failed to generate `content`");

            vec![]
        };

        self.cose.set_content(&content);

        self
    }

    pub fn get_content_debug(&self) -> Option<Vec<u8>> {
        println!("get_content_debug(): self.sid: {:?}", self.sid);

        let content = self.cose.get_content();
        println!("get_content_debug(): content: {:?}", content);

        content
    }

    pub fn get_signature(&self) -> (&[u8], &SignatureAlgorithm) {
        let sig = self.cose.sig();

        (&sig.signature, &sig.signature_type)
    }

    pub fn get_signer_cert(&self) -> Option<&[u8]> {
        let signer_cert = &self.cose.sig().signer_cert;

        if signer_cert.len() > 0 { Some(signer_cert) } else { None }
    }

    pub fn dump(&self) {
        self.cose.dump();
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