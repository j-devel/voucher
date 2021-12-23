#![no_std]

#![feature(arbitrary_enum_discriminant)]
#![feature(core_intrinsics)]

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

#[cfg(feature = "std")]
use std::{println, self as alloc};
#[cfg(not(feature = "std"))]
use mcu_if::{println, alloc};

use alloc::{boxed::Box, string::{self, String}, vec, vec::Vec, collections::{BTreeMap, BTreeSet}};

//

#[cfg(test)]
mod tests;

//

mod yang;
mod sid_data;
use sid_data::{SidData, Sid, Yang, YangEnum};

mod cose_sig;
mod cose_data;
use cose_data::{CoseData, COSE_SIGN_ONE_TAG};
pub use cose_data::SignatureAlgorithm;

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
    fn sign(&mut self, privkey_pem: &[u8], alg: SignatureAlgorithm) -> Result<&mut Self, ()>;
}

pub trait Validate {
    fn validate(&self, pem: Option<&[u8]>) -> Result<&Self, ()>;
}

#[cfg(any(feature = "sign", feature = "sign-lts"))]
mod sign;

#[cfg(any(feature = "validate", feature = "validate-lts"))]
mod validate;

//

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum VoucherType {
    Vch, // 'voucher'
    Vrq, // 'voucher request'
}

#[derive(Copy, Clone, PartialEq)]
pub enum Assertion {
    Verified,
    Logged,
    Proximity,
}

pub enum Attr {
    Assertion(Assertion),
    CreatedOn(u64),
    DomainCertRevocationChecks(bool),
    ExpiresOn(u64),
    IdevidIssuer(Vec<u8>),
    LastRenewalDate(u64),
    Nonce(Vec<u8>),
    PinnedDomainCert(Vec<u8>),
    PinnedDomainSubjectPublicKeyInfo(Vec<u8>),        // vch only
    ProximityRegistrarSubjectPublicKeyInfo(Vec<u8>),  // vrq only
    PriorSignedVoucherRequest(Vec<u8>),               // vrq only
    ProximityRegistrarCert(Vec<u8>),                  // vrq only
    SerialNumber(String),
}

impl Voucher {
    pub fn new(ty: VoucherType) -> Self {
        Self {
            sid: match ty {
                VoucherType::Vch => SidData::new_vch_cbor(),
                VoucherType::Vrq => SidData::new_vrq_cbor(),
            },
            cose: CoseData::new(true),
        }
    }

    pub fn new_vch() -> Self {
        Self::new(VoucherType::Vch)
    }

    pub fn new_vrq() -> Self {
        Self::new(VoucherType::Vrq)
    }

    pub fn new_vch_with(attrs: Vec<Attr>) -> Self {
        let mut vch = Self::new_vch();
        attrs.into_iter()
            .for_each(|attr| { vch.set(attr); });

        vch
    }

    pub fn new_vrq_with(attrs: Vec<Attr>) -> Self {
        let mut vrq = Self::new_vrq();
        attrs.into_iter()
            .for_each(|attr| { vrq.set(attr); });

        vrq
    }

    pub fn serialize(&self) -> Option<Vec<u8>> {
        CoseData::encode(&self.cose).ok()
    }

    pub fn get_voucher_type(&self) -> VoucherType {
        if self.sid.is_vrq() { VoucherType::Vrq } else { VoucherType::Vch }
    }

    pub fn set(&mut self, attr: Attr) -> &mut Self {
        use Yang::*;

        let is_vrq = self.sid.is_vrq();
        let sid_assertion = |x| if is_vrq { Sid::VrqAssertion(x) } else { Sid::VchAssertion(x) };

        let sid = match attr {
            Attr::Assertion(inner) => match inner {
                Assertion::Verified => sid_assertion(Enumeration(YangEnum::Verified)),
                Assertion::Logged => sid_assertion(Enumeration(YangEnum::Logged)),
                Assertion::Proximity => sid_assertion(Enumeration(YangEnum::Proximity)),
            },
            Attr::DomainCertRevocationChecks(x) => if is_vrq { Sid::VrqDomainCertRevocationChecks(Boolean(x)) } else { Sid::VchDomainCertRevocationChecks(Boolean(x)) },
            Attr::CreatedOn(x) => if is_vrq { Sid::VrqCreatedOn(DateAndTime(x)) } else { Sid::VchCreatedOn(DateAndTime(x)) },
            Attr::ExpiresOn(x) => if is_vrq { Sid::VrqExpiresOn(DateAndTime(x)) } else { Sid::VchExpiresOn(DateAndTime(x)) },
            Attr::LastRenewalDate(x) => if is_vrq { Sid::VrqLastRenewalDate(DateAndTime(x)) } else { Sid::VchLastRenewalDate(DateAndTime(x)) },
            Attr::IdevidIssuer(x) => if is_vrq { Sid::VrqIdevidIssuer(Binary(x)) } else { Sid::VchIdevidIssuer(Binary(x)) },
            Attr::Nonce(x) => if is_vrq { Sid::VrqNonce(Binary(x)) } else { Sid::VchNonce(Binary(x)) },
            Attr::PinnedDomainCert(x) => if is_vrq { Sid::VrqPinnedDomainCert(Binary(x)) } else { Sid::VchPinnedDomainCert(Binary(x)) },
            Attr::SerialNumber(x) => if is_vrq { Sid::VrqSerialNumber(String(x.as_bytes().to_vec())) } else { Sid::VchSerialNumber(String(x.as_bytes().to_vec())) },
            Attr::PinnedDomainSubjectPublicKeyInfo(x) => { assert!(!is_vrq); Sid::VchPinnedDomainSubjectPublicKeyInfo(Binary(x)) },
            Attr::ProximityRegistrarSubjectPublicKeyInfo(x) => { assert!(is_vrq); Sid::VrqProximityRegistrarSubjectPublicKeyInfo(Binary(x)) },
            Attr::PriorSignedVoucherRequest(x) => { assert!(is_vrq); Sid::VrqPriorSignedVoucherRequest(Binary(x)) },
            Attr::ProximityRegistrarCert(x) => { assert!(is_vrq); Sid::VrqProximityRegistrarCert(Binary(x)) },
        };

        self.set_sid(sid);

        self
    }

    fn set_sid(&mut self, sid: Sid) -> &mut Self {
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

use core::convert::TryFrom;

impl TryFrom<&[u8]> for Voucher {
    type Error = &'static str;

    fn try_from(raw: &[u8]) -> Result<Self, Self::Error> {
        let (tag, cose) = if let Ok(decoded) = CoseData::decode(raw) { decoded } else {
            return Err("Failed to decode raw voucher");
        };

        if tag != COSE_SIGN_ONE_TAG {
            return Err("Only `CoseSign1` vouchers are supported");
        }

        let content = if let Some(content) = cose.get_content() { content } else {
            return Err("Invalid `content`");
        };

        let sidhash = if let Ok(sidhash) = cose_sig::decode(&content) { sidhash } else {
            return Err("Failed to decode `content`");
        };
        println!("sidhash: {:?}", sidhash);

        if let Ok(sd) = SidData::try_from(sidhash) {
            //use sid_data::Cbor; panic!("sd.to_cbor(): {:?}", sd.to_cbor()); // check!!
            Ok(Self { sid: sd, cose })
        } else {
            Err("Filed to decode `sidhash`")
        }
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
            SignatureAlgorithm::PS256 => unimplemented!("handle PS256"),
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