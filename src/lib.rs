//! This crate implements a compact CBOR-encoded voucher defined by [Constrained BRSKI].
//!
//! <a href="https://github.com/AnimaGUS-minerva/voucher/blob/master/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" /></a>
//! <a href="https://github.com/AnimaGUS-minerva/voucher"><img src="https://img.shields.io/github/languages/code-size/AnimaGUS-minerva/voucher" /></a>
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
//! The [`Voucher`] struct abstracts both ["Voucher Request"] and ["Voucher"] artifacts of
//! Constrained BRSKI. Once a `Voucher` is instatiated, we can manage its attributes
//! using the dedicated API methods ([`get`](Voucher::get), [`set`](Voucher::set), [`remove`](Voucher::remove), etc.).
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
//!     .set(Attr::SerialNumber(b"00-D0-E5-F2-00-02".to_vec()));
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
//! let v = vrq![
//!     Attr::Assertion(Assertion::Proximity),
//!     Attr::SerialNumber(b"00-11-22-33-44-55".to_vec())];
//!
//! assert!(v.is_vrq());
//! assert_eq!(v.len(), 2);
//!
//! let v = vch![
//!     Attr::Assertion(Assertion::Logged),
//!     Attr::SerialNumber(b"00-11-22-33-44-55".to_vec())];
//!
//! assert!(v.is_vch());
//! assert_eq!(v.len(), 2);
//! ```
//!
//! ## 2. Encoding a `Voucher` into CBOR
//!
//! To encode a [`Voucher`] into a compact CBOR-encoded voucher, use [`Voucher::serialize`].
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
//!     .set(Attr::SerialNumber(b"00-D0-E5-F2-00-02".to_vec()))
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
//! To decode a COSE-signed CBOR-encoded voucher, use the
//! [`TryFrom<&u8>`](struct.Voucher.html#impl-TryFrom<%26%27_%20%5Bu8%5D>)
//! trait implemented for the [`Voucher`] struct.
//!
//! In this example, we decode a "voucher" sample in the
//! [00-D0-E5-F2-00-02 constrained voucher directory](https://github.com/AnimaGUS-minerva/voucher/tree/master/data/00-D0-E5-F2-00-02)
//! into a `Voucher` instance,
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
//!         Attr::SerialNumber(x) => assert_eq!(x, b"00-D0-E5-F2-00-02"),
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
//! ["Voucher Request"]: https://www.ietf.org/archive/id/draft-ietf-anima-constrained-voucher-15.html#name-voucher-request-artifact
//! ["Voucher"]: https://www.ietf.org/archive/id/draft-ietf-anima-constrained-voucher-15.html#name-voucher-artifact
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

//

#[cfg(test)]
mod tests;

//

mod utils;

#[cfg(feature = "v3")]
pub use utils::minerva_mbedtls_utils::init_psa_crypto;

//

pub mod attr;
use attr::*;

mod yang;
mod sid;
mod sid_data;
mod cose_sig;
mod cose_data;

#[cfg(debug_assertions)]
pub mod debug {
    pub use super::cose_sig::{sig_one_struct_bytes_from, CborType, decode};
    pub use super::cose_data::CoseError;
    pub use super::sid_data::{content_comp, content_comp_permissive};
}

mod voucher;
pub use voucher::{Voucher, VoucherError, SignatureAlgorithm};

//

/// Used to COSE-sign a `Voucher`.
pub trait Sign {
    fn sign(&mut self, privkey_pem: &[u8], alg: SignatureAlgorithm) -> Result<&mut Self, VoucherError>;
}

/// Used to COSE-validate a `Voucher`.
pub trait Validate {
    fn validate(&self, pem: Option<&[u8]>) -> Result<&Self, VoucherError>;
}

#[cfg(any(feature = "sign", feature = "sign-lts"))]
mod sign;

#[cfg(any(feature = "validate", feature = "validate-lts"))]
mod validate;

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

/// Creates a ["Voucher Request"](https://www.ietf.org/archive/id/draft-ietf-anima-constrained-voucher-15.html#name-voucher-request-artifact) instance with a known list of attributes.
///
/// # Examples
///
/// ```
/// use minerva_voucher::{Voucher, attr::*, vrq};
///
/// let v = vrq![
///     Attr::Assertion(Assertion::Proximity),
///     Attr::SerialNumber(b"00-11-22-33-44-55".to_vec())];
///
/// assert!(v.is_vrq());
/// assert_eq!(v.len(), 2);
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

/// Creates a ["Voucher"](https://www.ietf.org/archive/id/draft-ietf-anima-constrained-voucher-15.html#name-voucher-artifact) instance with a known list of attributes.
///
/// # Examples
///
/// ```
/// use minerva_voucher::{Voucher, attr::*, vch};
///
/// let v = vch![
///     Attr::Assertion(Assertion::Logged),
///     Attr::SerialNumber(b"00-11-22-33-44-55".to_vec())];
///
/// assert!(v.is_vch());
/// assert_eq!(v.len(), 2);
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
