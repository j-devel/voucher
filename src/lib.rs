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

use alloc::{boxed::Box, vec, vec::Vec, collections::{BTreeMap, BTreeSet}};

use core::convert::TryFrom;

#[cfg(test)]
mod tests;

mod utils;

pub mod attr;
use attr::*;

mod yang;

mod sid;
use sid::{Sid, SidDisc};

mod sid_data;
use sid_data::SidData;

mod cose_sig;
mod cose_data;
use cose_data::{CoseData, COSE_SIGN_ONE_TAG};
pub use cose_data::SignatureAlgorithm;

#[cfg(debug_assertions)]
pub mod debug {
    pub use super::cose_sig::{sig_one_struct_bytes_from, CborType, decode};
    pub use super::sid_data::{content_comp, content_comp_permissive};
}

//

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
/// A `Voucher` with a known list of attributes can be initialized from a vector:
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
    sd: SidData,
    cd: CoseData,
}

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum VoucherType {
    Vch, // 'voucher'
    Vrq, // 'voucher request'
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
    /// let vrq = Voucher::new(VoucherType::Vrq);
    /// let vch = Voucher::new(VoucherType::Vch);
    /// ```
    pub fn new(ty: VoucherType) -> Self {
        Self {
            sd: match ty {
                VoucherType::Vch => SidData::new_vch_cbor(),
                VoucherType::Vrq => SidData::new_vrq_cbor(),
            },
            cd: CoseData::new(true),
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
        CoseData::encode(&self.cd).ok()
    }

    pub fn get_voucher_type(&self) -> VoucherType {
        if self.sd.is_vrq() { VoucherType::Vrq } else { VoucherType::Vch }
    }

    /// Removes an attribute from the voucher. Returns whether the attribute was present in the voucher.
    ///
    /// # Examples
    ///
    /// ```
    /// use minerva_voucher::{Voucher, attr::*};
    ///
    /// let mut vrq = Voucher::new_vrq();
    /// vrq.set(Attr::CreatedOn(1475868702));
    ///
    /// assert_eq!(vrq.remove(ATTR_CREATED_ON), true);
    /// assert_eq!(vrq.remove(ATTR_CREATED_ON), false);
    /// ```
    pub fn remove(&mut self, adisc: AttrDisc) -> bool {
        self.take(adisc).is_some()
    }

    /// Removes and returns the attribute in the voucher, if any, that corresponds to the given attribute discriminant value.
    ///
    /// # Examples
    ///
    /// ```
    /// use minerva_voucher::{Voucher, attr::*};
    ///
    /// let mut vrq = Voucher::new_vrq();
    ///
    /// vrq.set(Attr::CreatedOn(1475868702));
    /// assert_eq!(vrq.take(ATTR_CREATED_ON), Some(Attr::CreatedOn(1475868702)));
    /// assert_eq!(vrq.take(ATTR_CREATED_ON), None);
    ///
    /// let sn = "00-D0-E5-F2-00-02".as_bytes();
    /// vrq.set(Attr::SerialNumber(sn.to_vec()));
    /// assert_eq!(vrq.take(ATTR_SERIAL_NUMBER), Some(Attr::SerialNumber(sn.to_vec())));
    /// assert_eq!(vrq.take(ATTR_SERIAL_NUMBER), None);
    /// ```
    pub fn take(&mut self, adisc: AttrDisc) -> Option<Attr> {
        let dummy = Sid::try_from((
            yang::Yang::DateAndTime(Attr::CreatedOn(0)) /* dummy */,
            self.to_sid_disc(adisc)?)).ok()?;

        let dc = &dummy.clone();
        let removed = self.sd.replace(dummy);
        let dummy_removal = self.sd.remove(dc);
        assert!(dummy_removal);

        removed.and_then(Attr::from_sid)
    }

    /// Returns a reference to the attribute in the voucher, if any, that corresponds to the given attribute discriminant value.
    ///
    /// # Examples
    ///
    /// ```
    /// use minerva_voucher::{Voucher, attr::*};
    ///
    /// let mut vrq = Voucher::new_vrq();
    /// vrq.set(Attr::CreatedOn(1475868702));
    ///
    /// assert_eq!(vrq.get(ATTR_CREATED_ON), Some(&Attr::CreatedOn(1475868702)));
    /// assert_eq!(vrq.get(ATTR_SERIAL_NUMBER), None);
    /// ```
    pub fn get(&self, adisc: AttrDisc) -> Option<&Attr> {
        self.get_sid(adisc).and_then(Attr::from_sid_ref)
    }

    fn to_sid_disc(&self, adisc: AttrDisc) -> Option<SidDisc> {
        Attr::to_sid_disc(adisc, self.sd.is_vrq())
    }

    fn get_sid(&self, adisc: AttrDisc) -> Option<&Sid> {
        let sdisc = self.to_sid_disc(adisc)?;
        for sid in self.sd.iter() {
            if sid.disc() == sdisc {
                return Some(sid);
            }
        }

        None
    }

    /// Adds an attribute to the voucher, replacing the existing attribute, if any, that corresponds to the given one. Returns a `mut` reference to the voucher.
    ///
    /// # Examples
    ///
    /// ```
    /// use minerva_voucher::{Voucher, attr::*};
    ///
    /// let mut vrq = Voucher::new_vrq();
    /// assert_eq!(vrq.get(ATTR_CREATED_ON), None);
    ///
    /// vrq.set(Attr::CreatedOn(1475868702));
    /// assert_eq!(vrq.get(ATTR_CREATED_ON), Some(&Attr::CreatedOn(1475868702)));
    ///
    /// vrq.set(Attr::CreatedOn(1599086034));
    /// assert_eq!(vrq.get(ATTR_CREATED_ON), Some(&Attr::CreatedOn(1599086034)));
    /// ```
    pub fn set(&mut self, attr: Attr) -> &mut Self {
        let sdisc = self.to_sid_disc(attr.disc()).unwrap();
        self.set_sid(Sid::try_from((attr.into_yang(), sdisc)).unwrap());

        self
    }

    /// Returns the number of attributes in the voucher.
    ///
    /// # Examples
    ///
    /// ```
    /// use minerva_voucher::{Voucher, attr::Attr};
    ///
    /// let mut vrq = Voucher::new_vrq();
    /// assert_eq!(vrq.len(), 0);
    /// vrq.set(Attr::CreatedOn(1475868702));
    /// assert_eq!(vrq.len(), 1);
    /// ```
    pub fn len(&self) -> usize {
        self.iter().count()
    }

    /// Gets an iterator that visits the attributes in the voucher.
    ///
    /// # Examples
    ///
    /// ```
    /// use minerva_voucher::{Voucher, attr::{Attr, Assertion}};
    ///
    /// let mut vrq = Voucher::new_vrq();
    ///
    /// vrq.set(Attr::Assertion(Assertion::Proximity))
    ///     .set(Attr::CreatedOn(1599086034))
    ///     .set(Attr::SerialNumber("00-D0-E5-F2-00-02".as_bytes().to_vec()));
    ///
    /// let mut vrq_iter = vrq.iter();
    /// assert!(vrq_iter.next().is_some());
    /// assert!(vrq_iter.next().is_some());
    /// assert!(vrq_iter.next().is_some());
    /// assert!(vrq_iter.next().is_none());
    /// ```
    pub fn iter(&self) -> impl Iterator<Item = &Attr> + '_ {
        self.iter_with_sid()
            .map(|(attr, _)| attr)
    }

    pub fn iter_with_sid(&self) -> impl Iterator<Item = (&Attr, sid::SidDisc)> + '_ {
        self.sd.iter()
            .filter_map(|sid| if let Some(attr) = Attr::from_sid_ref(sid) { Some((attr, sid.disc())) } else { None })
    }

    // pub fn print(&self) -> { // ??
    //     self.sd.dump();
    //     self.cd.dump();
    // }
    //----^^^^ Attr layer API

    fn set_sid(&mut self, sid: Sid) -> &mut Self {
        self.sd.replace(sid);

        self
    }

    //----vvvv COSE layer API
    // pub fn cose_content() -> Option<Vec<u8>> {} // <<? `pub fn extract_cose_content(&self)`
    // pub fn cose_signature() -> xx {} // <<? `pub fn get_signature(&self)`

    /// Interface with meta data to be used in ECDSA based signing
    pub fn to_sign(&mut self) -> (&mut Vec<u8>, &mut SignatureAlgorithm, &[u8]) {
        use core::ops::DerefMut;

        let sig = self
            .update_cose_content()
            .cd.sig_mut().deref_mut();

        (&mut sig.signature, &mut sig.signature_type, &sig.to_verify)
    }

    /// Interface with meta data to be used in ECDSA based validation
    pub fn to_validate(&self) -> (Option<&[u8]>, &[u8], &SignatureAlgorithm, &[u8]) {
        let (signature, alg) = self.get_signature();

        (self.get_signer_cert(), signature, alg, &self.cd.sig().to_verify)
    }

    fn update_cose_content(&mut self) -> &mut Self {
        use sid::Cbor;

        let content = if let Some(cbor) = self.sd.serialize() { cbor } else {
            println!("update_cose_content(): Failed to generate `content`");

            vec![]
        };

        self.cd.set_content(&content);

        self
    }

    pub fn extract_cose_content(&self) -> Option<Vec<u8>> {
        debug_println!("extract_cose_content(): self.sd: {:?}", self.sd);

        let content = self.cd.get_content();
        debug_println!("extract_cose_content(): content: {:?}", content);

        content
    }

    pub fn get_signature(&self) -> (&[u8], &SignatureAlgorithm) {
        let sig = self.cd.sig();

        (&sig.signature, &sig.signature_type)
    }

    pub fn get_signer_cert(&self) -> Option<&[u8]> {
        let signer_cert = &self.cd.sig().signer_cert;

        if signer_cert.len() > 0 { Some(signer_cert) } else { None }
    }

    pub fn dump(&self) {
        self.cd.dump();
    }
}

impl TryFrom<&[u8]> for Voucher {
    type Error = &'static str;

    fn try_from(raw: &[u8]) -> Result<Self, Self::Error> {
        let (tag, cd) = if let Ok(x) = CoseData::decode(raw) { x } else {
            return Err("Failed to decode raw voucher");
        };

        if tag != COSE_SIGN_ONE_TAG {
            return Err("Only `CoseSign1` vouchers are supported");
        }

        let content = if let Some(x) = cd.get_content() { x } else {
            return Err("Invalid `content`");
        };

        let sidhash = if let Ok(x) = cose_sig::decode(&content) { x } else {
            return Err("Failed to decode `content`");
        };

        debug_println!("sidhash: {:?}", sidhash);

        if let Ok(sd) = SidData::try_from(sidhash) {
            debug_println!("sd: {:?}", sd);

            Ok(Self { sd, cd })
        } else {
            Err("Filed to decode `sidhash`")
        }
    }
}
