#![no_std]

#![feature(arbitrary_enum_discriminant)]
#![feature(core_intrinsics)]

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

#[cfg(feature = "std")]
use std::{println, boxed::Box, string::{self, String}, vec, vec::Vec, collections::{BTreeMap, BTreeSet}};
#[cfg(not(feature = "std"))]
use mcu_if::{println, alloc::{boxed::Box, string::{self, String}, vec, vec::Vec, collections::{BTreeMap, BTreeSet}}};

//

#[cfg(test)]
mod tests;

//

mod sid_data;
use sid_data::SidData;
pub use sid_data::{Sid, YangEnum, Yang::{self, *}};

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

use core::convert::TryFrom;

impl TryFrom<&[u8]> for Voucher {
    type Error = &'static str;

    fn try_from(raw: &[u8]) -> Result<Self, Self::Error> {
        if let Ok((tag, cose)) = CoseData::decode(raw) {
            if tag == COSE_SIGN_ONE_TAG {
                //======== begin WIP - to be refactored
                use cose::decoder::CborType;
                use cose_sig::{decode, map_value_from};
                use sid_data::Cbor;

                let content = {
                    if let Some(content) = cose.get_content() {
                        content
                    } else {
                        return Err("Invalid `content`");
                    }
                };
                let sidhash = if let Ok(sidhash) = decode(&content) {
                    sidhash
                } else {
                    return Err("Failed to decode `content`");
                };

                //

                let is_permissive = true; // !!!!
                let msg = "Neither `SID_VCH_TOP_LEVEL` nor `SID_VRQ_TOP_LEVEL` found";
                let mut sd_opt = None;

                if let Ok(CborType::Map(ref vch_map)) = map_value_from(&sidhash, &CborType::Integer(sid_data::SID_VCH_TOP_LEVEL)) {
                    let mut sd = SidData::vch_from(
                        BTreeSet::from([Sid::VchTopLevel(sid_data::TopLevel::VoucherVoucher)]));

                    vch_map.iter() // TODO !! cbor -> sid convesion
                        .for_each(|(k, v)| {
                            println!("[vch] k: {:?} v: {:?}", k, v);

                            if let Yang::DateAndTime(val) = Yang::try_from(v).unwrap() {
                                println!("!!!! Yang::DateAndTime: {}", val);
                            }
                        });
                    //if 1 == 1 { panic!(); } // !!!! !!!! !!!! !!!!

                    // if let Integer(delta) = k {
                    //     match (delta + SID_VCH_TOP_LEVEL) {
                    //         SID_VCH_ASSERTION => set_sid_assoc(&mut sd, Sid::VchCreatedOn(resolve_yang_dat(v)),
                    //

                    //
                    sd_opt.replace(sd);
                } else if let Ok(CborType::Map(ref vrq_map)) = map_value_from(&sidhash, &CborType::Integer(sid_data::SID_VRQ_TOP_LEVEL)) {
                    let mut sd = SidData::vrq_from(
                        BTreeSet::from([Sid::VrqTopLevel(sid_data::TopLevel::VoucherRequestVoucher)]));

                    vrq_map.iter() // TODO !! cbor -> sid
                        .for_each(|(k, v)| {
                            println!("[vrq] k: {:?} v: {:?}", k, v);
                        });

                    //
                    sd_opt.replace(sd);
                } else if is_permissive {
                    println!("⚠️ warning: {}", msg);
                } else {
                    return Err(msg);
                }

                if let Some(sd) = sd_opt {
//                    panic!("sd.to_cbor(): {:?}", sd.to_cbor()); // check!
                }

                // content bytes
                // -> sidhash (CborType Map) .... check TopLevel type (vch or vrq)
                // -> attr set
                // -> populate `self.sid` (sid_data) .... `.get_attrs()` API
                //======== end WIP
                let sd = SidData::new_vch(); // !!!! dummy !!!!

                Ok(Self { sid: sd, cose })
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

    pub fn new_vch() -> Self { Self::new(VoucherType::Vch) }
    pub fn new_vrq() -> Self { Self::new(VoucherType::Vrq) }

    pub fn serialize(&self) -> Option<Vec<u8>> {
        CoseData::encode(&self.cose).ok()
    }

    pub fn get_voucher_type(&self) -> VoucherType {
        if self.sid.is_vrq() { VoucherType::Vrq } else { VoucherType::Vch }
    }

    pub fn set(&mut self, attr: Attr) -> &mut Self {
        let is_vrq = self.sid.is_vrq();
        let sid_assertion = |val| if is_vrq { Sid::VrqAssertion(val) } else { Sid::VchAssertion(val) };

        let sid = match attr {
            Attr::Assertion(inner) => match inner {
                Assertion::Verified => sid_assertion(YangEnum::Verified),
                Assertion::Logged => sid_assertion(YangEnum::Logged),
                Assertion::Proximity => sid_assertion(YangEnum::Proximity),
            },
            Attr::DomainCertRevocationChecks(val) => if is_vrq { Sid::VrqDomainCertRevocationChecks(val) } else { Sid::VchDomainCertRevocationChecks(val) },
            Attr::CreatedOn(val) => if is_vrq { Sid::VrqCreatedOn(val) } else { Sid::VchCreatedOn(val) },
            Attr::ExpiresOn(val) => if is_vrq { Sid::VrqExpiresOn(val) } else { Sid::VchExpiresOn(val) },
            Attr::LastRenewalDate(val) => if is_vrq { Sid::VrqLastRenewalDate(val) } else { Sid::VchLastRenewalDate(val) },
            Attr::IdevidIssuer(val) => if is_vrq { Sid::VrqIdevidIssuer(val) } else { Sid::VchIdevidIssuer(val) },
            Attr::Nonce(val) => if is_vrq { Sid::VrqNonce(val) } else { Sid::VchNonce(val) },
            Attr::PinnedDomainCert(val) => if is_vrq { Sid::VrqPinnedDomainCert(val) } else { Sid::VchPinnedDomainCert(val) },
            Attr::SerialNumber(val) => if is_vrq { Sid::VrqSerialNumber(val) } else { Sid::VchSerialNumber(val) },
            Attr::PinnedDomainSubjectPublicKeyInfo(val) => { assert!(!is_vrq); Sid::VchPinnedDomainSubjectPublicKeyInfo(val) },
            Attr::ProximityRegistrarSubjectPublicKeyInfo(val) => { assert!(is_vrq); Sid::VrqProximityRegistrarSubjectPublicKeyInfo(val) },
            Attr::PriorSignedVoucherRequest(val) => { assert!(is_vrq); Sid::VrqPriorSignedVoucherRequest(val) },
            Attr::ProximityRegistrarCert(val) => { assert!(is_vrq); Sid::VrqProximityRegistrarCert(val) },
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