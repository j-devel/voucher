//! This crate implements a compact CBOR-encoded voucher defined by [Constrained BRSKI].
//!
//! # Examples
//!
//! In this section, we first introduce the [`Voucher`] abstraction offered by this crate,
//! along with its API methods used when dealing with the BRSKI voucher attributes.
//! We then present some practical examples on how to perfrom CBOR encoding/decoding of BRSKI vouchers
//! with the underlying COSE signing and validation operations also considered.
//!
//! ## 1. Using the `Voucher` struct
//!
//! The [`Voucher`] struct abstracts both
//! ["Voucher Request"](https://www.ietf.org/archive/id/draft-ietf-anima-constrained-voucher-15.html#name-voucher-request-artifact)
//! and ["Voucher"](https://www.ietf.org/archive/id/draft-ietf-anima-constrained-voucher-15.html#name-voucher-artifact)
//! artifacts of Constrained BRSKI. Once a `Voucher` is instatiated, we can manage its attributes
//! using the dedicated API methods (`get()`, `set()`, `remove()`, etc.).
//! These methods operate on the [`Attr`] enum (occasionally through
//! its discriminant constants [`ATTR_*`](`attr`)) that represents the BRSKI voucher attributes.
//!
//! In this example, we demonstrate how to use the `Voucher` struct with a "voucher request" instance
//! created by `Voucher::new_vrq()`.
//!
//! #### Notes
//!
//! All of the `Voucher` struct's methods shown below can also be called by a "voucher" instance
//! created by `Voucher::new_vch()`.
//!
//! ```rust
//! use minerva_voucher::{Voucher, attr::*};
//!
//! // Create an empty voucher request.
//! let mut vrq = Voucher::new_vrq();
//!
//! // Add some attributes.
//! vrq.set(Attr::Assertion(Assertion::Proximity))
//!     .set(Attr::CreatedOn(1599086034))
//!     .set(Attr::SerialNumber("00-D0-E5-F2-00-02".as_bytes().to_vec()));
//!
//! // Count attributes.
//! assert_eq!(vrq.len(), 3);
//!
//! // Check for specific ones.
//! assert_eq!(vrq.get(ATTR_CREATED_ON), Some(&Attr::CreatedOn(1599086034)));
//! assert_eq!(vrq.get(ATTR_EXPIRES_ON), None);
//!
//! // Remove a specific one.
//! assert_eq!(vrq.remove(ATTR_CREATED_ON), true);
//!
//! // Count attributes again.
//! assert_eq!(vrq.len(), 2);
//!
//! // Iterate over everything.
//! for attr in vrq.iter() {
//!     println!("attr: {:?}", attr);
//! }
//! ```
//!
//! Using the [`vrq`]/[`vch`] declarative macros, a [`Voucher`] with a known list of attributes can be
//! conveniently created as:
//!
//! ```rust
//! use minerva_voucher::{Voucher, attr::*, vrq, vch};
//!
//! let vrq = vrq![
//!     Attr::Assertion(Assertion::Proximity),
//!     Attr::SerialNumber("00-11-22-33-44-55".as_bytes().to_vec())];
//!
//! assert!(vrq.is_vrq());
//! assert_eq!(vrq.len(), 2);
//!
//! let vch = vch![
//!     Attr::Assertion(Assertion::Logged),
//!     Attr::SerialNumber("00-11-22-33-44-55".as_bytes().to_vec())];
//!
//! assert!(vch.is_vch());
//! assert_eq!(vch.len(), 2);
//! ```
//!
//! ## 2. Encoding a `Voucher` into CBOR
//!
//! To encode a [`Voucher`] into a compact CBOR-encoded voucher, use the `serialize()` method.
//! Before calling `serialize()`, however, the `Voucher` must be COSE-signed using its `sign()` method.
//!
//! In this example, we instantiate a new voucher request, populate it with some attributes,
//! COSE-sign it, and finally encode it into a CBOR byte string.
//!
//! ```rust
//! use minerva_voucher::{Voucher, attr::*, SignatureAlgorithm, Sign};
//!
//! static KEY_PEM_F2_00_02: &[u8] = core::include_bytes!(
//!     concat!(env!("CARGO_MANIFEST_DIR"), "/data/00-D0-E5-F2-00-02/key.pem"));
//!
//! // This is required when the `Sign` trait is backed by mbedtls v3.
//! #[cfg(feature = "v3")]
//! minerva_voucher::init_psa_crypto();
//!
//! // Create a voucher request with five attributes and COSE-sign it.
//! let mut vrq = Voucher::new_vrq();
//! assert!(vrq
//!     .set(Attr::Assertion(Assertion::Proximity))
//!     .set(Attr::CreatedOn(1599086034))
//!     .set(Attr::Nonce(vec![48, 130, 1, 216, 48, 130, 1, 94, 160, 3, 2, 1, 2, 2, 1, 1, 48, 10, 6, 8, 42, 134, 72, 206, 61, 4, 3, 2, 48, 115, 49, 18, 48, 16, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 2, 99, 97, 49, 25, 48, 23, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 9, 115, 97, 110, 100, 101, 108, 109, 97, 110, 49, 66, 48, 64, 6, 3, 85, 4, 3, 12, 57, 35, 60, 83, 121, 115, 116, 101, 109, 86, 97, 114, 105, 97, 98, 108, 101, 58, 48, 120, 48, 48, 48, 48, 53, 53, 98, 56, 50, 53, 48, 99, 48, 100, 98, 56, 62, 32, 85, 110, 115, 116, 114, 117, 110, 103, 32, 70, 111, 117, 110, 116, 97, 105, 110, 32, 67, 65, 48, 30, 23, 13, 50, 48, 48, 56, 50, 57, 48, 52, 48, 48, 49, 54, 90, 23, 13, 50, 50, 48, 56, 50, 57, 48, 52, 48, 48, 49, 54, 90, 48, 70, 49, 18, 48, 16, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 2, 99, 97, 49, 25, 48, 23, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 9, 115, 97, 110, 100, 101, 108, 109, 97, 110, 49, 21, 48, 19, 6, 3, 85, 4, 3, 12, 12, 85, 110, 115, 116, 114, 117, 110, 103, 32, 74, 82, 67, 48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3, 1, 7, 3, 66, 0, 4, 150, 101, 80, 114, 52, 186, 159, 229, 221, 230, 95, 246, 240, 129, 111, 233, 72, 158, 129, 12, 18, 7, 59, 70, 143, 151, 100, 43, 99, 0, 141, 2, 15, 87, 201, 124, 148, 127, 132, 140, 178, 14, 97, 214, 201, 136, 141, 21, 180, 66, 31, 215, 242, 106, 183, 228, 206, 5, 248, 167, 76, 211, 139, 58, 163, 16, 48, 14, 48, 12, 6, 3, 85, 29, 19, 1, 1, 255, 4, 2, 48, 0, 48, 10, 6, 8, 42, 134, 72, 206, 61, 4, 3, 2, 3, 104, 0, 48, 101, 2, 49, 0, 135, 158, 205, 227, 138, 5, 18, 46, 182, 247, 44, 178, 27, 195, 210, 92, 190, 230, 87, 55, 112, 86, 156, 236, 35, 12, 164, 140, 57, 241, 64, 77, 114, 212, 215, 85, 5, 155, 128, 130, 2, 14, 212, 29, 79, 17, 159, 231, 2, 48, 60, 20, 216, 138, 10, 252, 64, 71, 207, 31, 135, 184, 115, 193, 106, 40, 191, 184, 60, 15, 136, 67, 77, 157, 243, 247, 168, 110, 45, 198, 189, 136, 149, 68, 47, 32, 55, 237, 204, 228, 133, 91, 17, 218, 154, 25, 228, 232]))
//!     .set(Attr::ProximityRegistrarCert(vec![102, 114, 118, 85, 105, 90, 104, 89, 56, 80, 110, 86, 108, 82, 75, 67, 73, 83, 51, 113, 77, 81]))
//!     .set(Attr::SerialNumber("00-D0-E5-F2-00-02".as_bytes().to_vec()))
//!     .sign(KEY_PEM_F2_00_02, SignatureAlgorithm::ES256)
//!     .is_ok());
//!
//! // Encode the voucher request.
//! let cbor = vrq.serialize().unwrap();
//!
//! assert_eq!(cbor.len(), 630);
//! ```
//!
//! ## 3. Decoding a CBOR-encoded voucher into a `Voucher`
//!
//! To decode a COSE-signed CBOR-encoded voucher, use the `TryFrom` trait that is implemented
//! for the [`Voucher`] struct.
//!
//! In this example, we decode the `VCH_F2_00_02` constrained voucher sample into a `Voucher` instance,
//! COSE-validate it, and iterate through each attribute in the voucher.
//!
//! ```rust
//! use minerva_voucher::{Voucher, attr::*, Validate};
//! use core::convert::TryFrom;
//!
//! static VCH_F2_00_02: &[u8] = core::include_bytes!(
//!     concat!(env!("CARGO_MANIFEST_DIR"), "/data/00-D0-E5-F2-00-02/voucher_00-D0-E5-F2-00-02.vch"));
//! static MASA_CRT_F2_00_02: &[u8] = core::include_bytes!(
//!     concat!(env!("CARGO_MANIFEST_DIR"), "/data/00-D0-E5-F2-00-02/masa.crt"));
//!
//! // This is required when the `Validate` trait is backed by mbedtls v3.
//! #[cfg(feature = "v3")]
//! minerva_voucher::init_psa_crypto();
//!
//! // Decode the voucher.
//! let vch = Voucher::try_from(VCH_F2_00_02).unwrap();
//!
//! // COSE-validate the voucher.
//! assert!(vch.validate(Some(MASA_CRT_F2_00_02)).is_ok());
//!
//! // This voucher has five attributes.
//! assert_eq!(vch.len(), 5);
//!
//! for attr in vch.iter() {
//!     println!("attr: {:?}", attr);
//!
//!     // Check data belonging to the attribute.
//!     match attr {
//!         Attr::Assertion(x) => assert_eq!(x, &Assertion::Logged),
//!         Attr::CreatedOn(x) => assert_eq!(x, &1599525239),
//!         Attr::Nonce(x) => assert_eq!(x, &[88, 83, 121, 70, 52, 76, 76, 73, 105, 113, 85, 50, 45, 79, 71, 107, 54, 108, 70, 67, 65, 103]),
//!         Attr::PinnedDomainCert(x) => assert_eq!(x[0..4], [77, 73, 73, 66]),
//!         Attr::SerialNumber(x) => assert_eq!(x, "00-D0-E5-F2-00-02".as_bytes()),
//!         _ => panic!(),
//!     }
//! }
//! ```
//! #### Notes
//!
//! Instead of `TryFrom`, we could use `TryInto` (via `use core::convert::TryInto;`) to
//! decode the same voucher as
//!
//! `let vch: Voucher = VCH_F2_00_02.try_into().unwrap();`
//!
//! In this case, the type annotation `: Voucher` is needed.
//!
//!
//! [Constrained BRSKI]: https://www.ietf.org/archive/id/draft-ietf-anima-constrained-voucher-15.html
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

#[cfg(feature = "v3")]
pub use utils::minerva_mbedtls_utils::init_psa_crypto;

pub mod attr;
use attr::*;

mod yang;

mod sid;
use sid::{Sid, SidDisc};

mod sid_data;
use sid_data::SidData;

mod cose_sig;
mod cose_data;
use cose_data::{CoseError, CborError, CoseData, COSE_SIGN_ONE_TAG};
pub use cose_data::SignatureAlgorithm;

#[cfg(debug_assertions)]
pub mod debug {
    pub use super::cose_sig::{sig_one_struct_bytes_from, CborType, decode};
    pub use super::sid_data::{content_comp, content_comp_permissive};
}

//

pub trait Sign {
    fn sign(&mut self, privkey_pem: &[u8], alg: SignatureAlgorithm) -> Result<&mut Self, VoucherError>;
}

pub trait Validate {
    fn validate(&self, pem: Option<&[u8]>) -> Result<&Self, VoucherError>;
}

#[cfg(any(feature = "sign", feature = "sign-lts"))]
mod sign;

#[cfg(any(feature = "validate", feature = "validate-lts"))]
mod validate;

//

#[derive(PartialEq, Debug)]
pub enum VoucherError {
    CborFailure(CborError),
    CoseFailure(CoseError),
    InvalidArgument,
    MalformedInput,
    MissingAttributes,
    SigningFailed,
    UnexpectedCborType,
    ValidationFailed,
}

#[derive(PartialEq, Debug)]
pub struct Voucher {
    sd: SidData,
    cd: CoseData,
}

#[derive(Copy, Clone, PartialEq, Debug)]
enum VoucherType {
    Vch, // 'voucher'
    Vrq, // 'voucher request'
}

impl Voucher {
    pub fn new_vrq() -> Self {
        Self::new(VoucherType::Vrq)
    }

    pub fn new_vch() -> Self {
        Self::new(VoucherType::Vch)
    }

    pub fn is_vrq(&self) -> bool {
        self.sd.is_vrq()
    }

    pub fn is_vch(&self) -> bool {
        !self.is_vrq()
    }

    fn new(ty: VoucherType) -> Self {
        Self {
            sd: match ty {
                VoucherType::Vrq => SidData::new_vrq_cbor(),
                VoucherType::Vch => SidData::new_vch_cbor(),
            },
            cd: CoseData::new(true),
        }
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
        let sdisc = self.to_sid_disc(adisc)?;
        for sid in self.sd.iter() {
            if sid.disc() == sdisc {
                return sid.as_attr();
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
        let sdisc = self.to_sid_disc(attr.disc())
            .ok_or(VoucherError::InvalidArgument)
            .unwrap();
        self.set_sid(Sid::try_from((attr.into_yang(), sdisc)).unwrap());

        self
    }

    fn set_sid(&mut self, sid: Sid) -> &mut Self {
        self.sd.replace(sid);

        self
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
        if let Some(sdisc) = self.to_sid_disc(adisc) {
            self.sd.remove(sdisc)
        } else {
            false
        }
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
        self.sd
            .take(self.to_sid_disc(adisc)?)
            .and_then(|sid| sid.into_attr())
    }

    fn to_sid_disc(&self, adisc: AttrDisc) -> Option<SidDisc> {
        Attr::to_sid_disc(adisc, self.is_vrq())
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

    fn iter_with_sid(&self) -> impl Iterator<Item = (&Attr, sid::SidDisc)> + '_ {
        self.sd.iter()
            .filter_map(|sid| Some((sid.as_attr()?, sid.disc())))
    }

    /// ...
    ///
    /// # Examples
    ///
    /// ```
    /// ;
    /// ```
    pub fn get_signature(&self) -> (&[u8], &SignatureAlgorithm) {
        let sig = self.cd.sig();

        (&sig.signature, &sig.signature_type)
    }

    /// ...
    ///
    /// # Examples
    ///
    /// ```
    /// ;
    /// ```
    pub fn serialize(&self) -> Result<Vec<u8>, VoucherError> {
        if self.get(ATTR_ASSERTION).is_none() {
            debug_println!("serialize(): `Attr::Assertion` is mandatory; but missing");
            return Err(VoucherError::MissingAttributes);
        }

        if self.get(ATTR_SERIAL_NUMBER).is_none() {
            debug_println!("serialize(): `Attr::SerialNumber` is mandatory; but missing");
            return Err(VoucherError::MissingAttributes);
        }

        CoseData::encode(&self.cd).or_else(|ce| {
            debug_println!("serialize(): `CoseData::encode()` failed.  (Maybe, voucher not signed yet?)");

            Err(VoucherError::CoseFailure(ce))
        })
    }

    /// ...
    ///
    /// # Examples
    ///
    /// ```
    /// ;
    /// ```
    pub fn get_signer_cert(&self) -> Option<&[u8]> {
        self.cd.get_signer_cert()
    }

    /// ...
    ///
    /// # Examples
    ///
    /// ```
    /// ;
    /// ```
    pub fn set_signer_cert(&mut self, cert: &[u8]) -> &mut Self {
        self.cd.set_signer_cert(cert);

        self
    }

    #[cfg(test)]
    fn get_cose_content(&self) -> Option<Vec<u8>> {
        self.cd.get_content().ok()
    }

    fn update_cose_content(&mut self) -> &mut Self {
        use sid::Cbor;
        self.cd.set_content(&self.sd.serialize().unwrap());

        self
    }

    /// Interfaces with meta data to be used in ECDSA based signing.
    ///
    /// # Examples
    ///
    /// ```
    /// ;
    /// ```
    pub fn to_sign(&mut self, alg: SignatureAlgorithm) -> (&mut Vec<u8>, &[u8]) {
        self.cd.set_alg(alg);

        use core::ops::DerefMut;
        let sig = self.update_cose_content()
            .cd.sig_mut().deref_mut();

        (&mut sig.signature, &sig.to_verify)
    }

    /// Interfaces with meta data to be used in ECDSA based validation.
    ///
    /// # Examples
    ///
    /// ```
    /// ;
    /// ```
    pub fn to_validate(&self) -> (Option<&[u8]>, &[u8], &SignatureAlgorithm, &[u8]) {
        let (signature, alg) = self.get_signature();

        (self.get_signer_cert(), signature, alg, &self.cd.sig().to_verify)
    }

    /// ...
    ///
    /// # Examples
    ///
    /// ```
    /// ;
    /// ```
    pub fn dump(&self) {
        println!("======== Voucher::dump()");
        self.sd.dump();
        self.cd.dump();
        println!("========");
    }

    #[cfg(test)]
    pub fn dump_and_panic(&self) {
        self.dump();
        panic!();
    }
}

/// ...
///
/// # Examples
///
/// ```
/// ;
/// ```
impl TryFrom<&[u8]> for Voucher {
    type Error = VoucherError;

    fn try_from(raw: &[u8]) -> Result<Self, Self::Error> {
        let (tag, cd) = CoseData::decode(raw).or_else(|ce| {
            debug_println!("Failed to decode raw voucher");
            Err(VoucherError::CoseFailure(ce))
        })?;

        if tag != COSE_SIGN_ONE_TAG {
            debug_println!("Only `CoseSign1` vouchers are supported");
            return Err(VoucherError::CoseFailure(CoseError::UnexpectedTag));
        }

        let content = cd.get_content().or_else(|ce| {
            debug_println!("Failed to get `content`");
            Err(VoucherError::CoseFailure(ce))
        })?;

        let sidhash = cose_sig::decode(&content).or_else(|ce| {
            debug_println!("Failed to decode `content`");
            Err(VoucherError::CborFailure(ce))
        })?;
        //debug_println!("sidhash: {:?}", sidhash);

        SidData::try_from(sidhash)
            .and_then(|sd| Ok(Self { sd, cd }))
    }
}

//

macro_rules! debug_println {
    ( $( $x:expr ),* ) => {
        if cfg!(debug_assertions) {
            crate::println!( $( $x ),* );
        }
    };
}

use debug_println;

//

/// Creates a voucher request with a known list of attributes.
///
/// # Examples
///
/// ```
/// ;
/// ```
#[macro_export]
macro_rules! vrq {
    ( ) => (Voucher::new_vrq());
    ( $( $attr:expr ),* ) => {
        {
            let mut voucher = Voucher::new_vrq();
            $(
                voucher.set($attr);
            )*
            voucher
        }
    };
}

/// Creates a voucher with a known list of attributes.
///
/// # Examples
///
/// ```
/// ;
/// ```
#[macro_export]
macro_rules! vch {
    ( ) => (Voucher::new_vch());
    ( $( $attr:expr ),* ) => {
        {
            let mut voucher = Voucher::new_vch();
            $(
                voucher.set($attr);
            )*
            voucher
        }
    };
}
