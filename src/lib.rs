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

// TODO Add the `debug` feature for conditional build
pub mod debug {
    pub use super::cose_sig::{sig_one_struct_bytes_from, CborType, decode};
    pub use super::sid_data::{content_comp, content_comp_permissive,
                              CONTENT_VCH_JADA, CONTENT_VCH_F2_00_02, CONTENT_VRQ_F2_00_02};
}

/// A compact CBOR-encoded voucher defined by [Constrained BRSKI].
///
///
/// # Examples (!! WIP !!)
///
/// ```ignore
/// use minerva_voucher::{Voucher, Sign, Validate};
///
/// // (Add notes on the PSA crypto context ...)
/// #[cfg(feature = "v3")]
/// init_psa_crypto();
///
/// let mut vrq = Voucher::new_vrq();
///
/// // ...
///
/// ```
///
/// A `Voucher` with a known list of voucher attributes can be initialized from a vector:
///
/// ```ignore
/// use minerva_voucher::Voucher;
///
/// let vrq = Voucher::new_vrq_with(vec![
///     Attr::Assertion(Assertion::Proximity),
///     Attr::SerialNumber(String::from("00-11-22-33-44-55")),
/// ]);
/// ```
///
/// A raw CBOR-encoded voucher can be decoded into a [`Voucher`] through the `TryFrom` and/or `TryInto`
/// traits.
///
/// ```ignore
/// use core::convert::{TryFrom, TryInto};
///
/// let vch = Voucher::try_from(VCH_JADA).unwrap();
///
/// let result: Result<Voucher, _> = VCH_JADA.try_into();
/// assert!(result.is_ok());
///
/// // (Add how to access the voucher attributes ...)
///
/// ```
///
/// [Constrained BRSKI]: https://www.ietf.org/archive/id/draft-ietf-anima-constrained-voucher-15.html

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

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum Assertion {
    Verified,
    Logged,
    Proximity,
}

pub type AttrDisc = u8;
pub const ATTR_ASSERTION: AttrDisc =                         0x00;
pub const ATTR_CREATED_ON: AttrDisc =                        0x01;
pub const ATTR_DOMAIN_CERT_REVOCATION_CHECKS: AttrDisc =     0x02;
pub const ATTR_EXPIRES_ON: AttrDisc =                        0x03;
pub const ATTR_IDEVID_ISSUER: AttrDisc =                     0x04;
pub const ATTR_LAST_RENEWAL_DATE: AttrDisc =                 0x05;
pub const ATTR_NONCE: AttrDisc =                             0x06;
pub const ATTR_PINNED_DOMAIN_CERT: AttrDisc =                0x07;
pub const ATTR_PINNED_DOMAIN_PUBK: AttrDisc =                0x20;
pub const ATTR_PINNED_DOMAIN_PUBK_SHA256: AttrDisc =         0x21;
pub const ATTR_PRIOR_SIGNED_VOUCHER_REQUEST: AttrDisc =      0x40;
pub const ATTR_PROXIMITY_REGISTRAR_CERT: AttrDisc =          0x41;
pub const ATTR_PROXIMITY_REGISTRAR_PUBK: AttrDisc =          0x42;
pub const ATTR_PROXIMITY_REGISTRAR_PUBK_SHA256: AttrDisc =   0x43;
pub const ATTR_SERIAL_NUMBER: AttrDisc =                     0x08;

#[repr(u8)]
#[derive(PartialEq, Debug)]
pub enum Attr {
    Assertion(Assertion) =                   ATTR_ASSERTION,
    CreatedOn(u64) =                         ATTR_CREATED_ON,
    DomainCertRevocationChecks(bool) =       ATTR_DOMAIN_CERT_REVOCATION_CHECKS,
    ExpiresOn(u64) =                         ATTR_EXPIRES_ON,
    IdevidIssuer(Vec<u8>) =                  ATTR_IDEVID_ISSUER,
    LastRenewalDate(u64) =                   ATTR_LAST_RENEWAL_DATE,
    Nonce(Vec<u8>) =                         ATTR_NONCE,
    PinnedDomainCert(Vec<u8>) =              ATTR_PINNED_DOMAIN_CERT,
    PinnedDomainPubk(Vec<u8>) =              ATTR_PINNED_DOMAIN_PUBK,              // vch only
    PinnedDomainPubkSha256(Vec<u8>) =        ATTR_PINNED_DOMAIN_PUBK_SHA256,       // vch only
    PriorSignedVoucherRequest(Vec<u8>) =     ATTR_PRIOR_SIGNED_VOUCHER_REQUEST,    // vrq only
    ProximityRegistrarCert(Vec<u8>) =        ATTR_PROXIMITY_REGISTRAR_CERT,        // vrq only
    ProximityRegistrarPubk(Vec<u8>) =        ATTR_PROXIMITY_REGISTRAR_PUBK,        // vrq only
    ProximityRegistrarPubkSha256(Vec<u8>) =  ATTR_PROXIMITY_REGISTRAR_PUBK_SHA256, // vrq only
    SerialNumber(String) =                   ATTR_SERIAL_NUMBER,
}

impl Voucher {
    /// Creates an empty `Voucher`.
    ///
    /// (Add notes on voucher types...)
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use minerva_voucher::{Voucher,VoucherType};
    ///
    /// let vrq = HashSet::new(VoucherType::Vrq);
    /// let vch = HashSet::new(VoucherType::Vch);
    /// ```
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

    pub fn remove(&mut self, attr_disc: AttrDisc) -> Option<Attr> {
        None // dummy; todo
    }

    pub fn get(&self, attr_disc: AttrDisc) -> Option<Attr> {
        use core::intrinsics::discriminant_value as disc;

        let (set, is_vrq) = self.sid.inner();
        let sid_disc = sid_data::SID_VRQ_CREATED_ON; // <- attr_disc, is_vrq; todo !!!!

        let mut out: Vec<_> = set.iter()
            .filter_map(|sid| if disc(sid) == sid_disc { Some(Attr::CreatedOn(1635218340)) } else { None })
// /* todo */ .filter_map(|sid| if disc(sid) == sid_disc { Some(Attr::try_from(sid)) } else { None })
            .collect();
        println!("out: {:?}", out);
        if out.len() == 1 { out.pop() } else { None }
    }

    pub fn set(&mut self, attr: Attr) -> &mut Self {
        use Sid::*;
        use Yang::*;

        let is_vrq = self.sid.is_vrq();
        let is_vch = !is_vrq;
        let sid_assertion = |x| if is_vrq { VrqAssertion(x) } else { VchAssertion(x) };

        let sid = match attr {
            Attr::Assertion(inner) => match inner {
                Assertion::Verified => sid_assertion(Enumeration(YangEnum::Verified)),
                Assertion::Logged => sid_assertion(Enumeration(YangEnum::Logged)),
                Assertion::Proximity => sid_assertion(Enumeration(YangEnum::Proximity)),
            },
            Attr::DomainCertRevocationChecks(x) => if is_vrq { VrqDomainCertRevocationChecks(Boolean(x)) } else { VchDomainCertRevocationChecks(Boolean(x)) },
            Attr::CreatedOn(x) => if is_vrq { VrqCreatedOn(DateAndTime(x)) } else { VchCreatedOn(DateAndTime(x)) },
            Attr::ExpiresOn(x) => if is_vrq { VrqExpiresOn(DateAndTime(x)) } else { VchExpiresOn(DateAndTime(x)) },
            Attr::LastRenewalDate(x) => if is_vrq { VrqLastRenewalDate(DateAndTime(x)) } else { VchLastRenewalDate(DateAndTime(x)) },
            Attr::IdevidIssuer(x) => if is_vrq { VrqIdevidIssuer(Binary(x)) } else { VchIdevidIssuer(Binary(x)) },
            Attr::Nonce(x) => if is_vrq { VrqNonce(Binary(x)) } else { VchNonce(Binary(x)) },
            Attr::PinnedDomainCert(x) => if is_vrq { VrqPinnedDomainCert(Binary(x)) } else { VchPinnedDomainCert(Binary(x)) },
            Attr::PinnedDomainPubk(x) => { assert!(is_vch); VchPinnedDomainPubk(Binary(x)) },
            Attr::PinnedDomainPubkSha256(x) => { assert!(is_vch); VchPinnedDomainPubkSha256(Binary(x)) },
            Attr::PriorSignedVoucherRequest(x) => { assert!(is_vrq); VrqPriorSignedVoucherRequest(Binary(x)) },
            Attr::ProximityRegistrarCert(x) => { assert!(is_vrq); VrqProximityRegistrarCert(Binary(x)) },
            Attr::ProximityRegistrarPubk(x) => { assert!(is_vrq); VrqProximityRegistrarPubk(Binary(x)) },
            Attr::ProximityRegistrarPubkSha256(x) => { assert!(is_vrq); VrqProximityRegistrarPubkSha256(Binary(x)) },
            Attr::SerialNumber(x) => if is_vrq { VrqSerialNumber(String(x.as_bytes().to_vec())) } else { VchSerialNumber(String(x.as_bytes().to_vec())) },
        };

        self.set_sid(sid);

        self
    }

    // pub fn print(&self) -> { // ??
    //     self.sid.dump();
    //     self.cose.dump();
    // }
    //----^^^^ Attr layer API

    //----vvvv SID/YANG layer API
    // pub fn sid_iter(&self) -> xx {}
    // pub fn sid_iter_mut(&mut self) -> xx {}
    // pub fn sid_remove() -> {}
    // pub fn sid_get() -> &Sid {}
    // pub fn sid_get_mut() -> &mut Sid {}
    /* (pub sid_set(..) -> */ fn set_sid(&mut self, sid: Sid) -> &mut Self {
        self.sid.replace(sid);

        self
    }
    //----vvvv COSE layer API
    // pub fn cose_content() -> Option<Vec<u8>> {} // <<? `pub fn get_content_debug(&self)`
    // pub fn cose_signature() -> xx {} // <<? `pub fn get_signature(&self)`

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
        let (tag, cose) = if let Ok(x) = CoseData::decode(raw) { x } else {
            return Err("Failed to decode raw voucher");
        };

        if tag != COSE_SIGN_ONE_TAG {
            return Err("Only `CoseSign1` vouchers are supported");
        }

        let content = if let Some(x) = cose.get_content() { x } else {
            return Err("Invalid `content`");
        };

        let sidhash = if let Ok(x) = cose_sig::decode(&content) { x } else {
            return Err("Failed to decode `content`");
        };

        #[cfg(debug_assertions)]
        println!("sidhash: {:?}", sidhash);

        if let Ok(sd) = SidData::try_from(sidhash) {
            #[cfg(debug_assertions)]
            println!("sd: {:?}", sd);

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