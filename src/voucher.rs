use crate::{println, Vec, debug_println};
use super::attr::*;
use super::sid::{self, Sid, SidDisc};
use super::sid_data::SidData;
use super::cose_sig;
use super::cose_data::{CoseError, CborError, CoseData, COSE_SIGN_ONE_TAG};
pub use super::cose_data::SignatureAlgorithm;
use core::convert::TryFrom;

/// Errors that can be returned from `Voucher` functions.
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

/// A structure implementing both
/// ["Voucher Request"](https://www.ietf.org/archive/id/draft-ietf-anima-constrained-voucher-15.html#name-voucher-request-artifact)
/// and
/// ["Voucher"](https://www.ietf.org/archive/id/draft-ietf-anima-constrained-voucher-15.html#name-voucher-artifact)
/// artifacts of
/// [Constrained BRSKI](https://www.ietf.org/archive/id/draft-ietf-anima-constrained-voucher-15.html).
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
    /// Creates a new, empty ["Voucher Request"](https://www.ietf.org/archive/id/draft-ietf-anima-constrained-voucher-15.html#name-voucher-request-artifact) instance.
    ///
    /// # Examples
    ///
    /// ```
    /// use minerva_voucher::Voucher;
    ///
    /// let mut vrq = Voucher::new_vrq();
    /// ```
    pub fn new_vrq() -> Self {
        Self::new(VoucherType::Vrq)
    }

    /// Creates a new, empty ["Voucher"](https://www.ietf.org/archive/id/draft-ietf-anima-constrained-voucher-15.html#name-voucher-artifact) instance.
    ///
    /// # Examples
    ///
    /// ```
    /// use minerva_voucher::Voucher;
    ///
    /// let mut vch = Voucher::new_vch();
    /// ```
    pub fn new_vch() -> Self {
        Self::new(VoucherType::Vch)
    }

    /// Returns `true` if the voucher is a ["Voucher Request"](https://www.ietf.org/archive/id/draft-ietf-anima-constrained-voucher-15.html#name-voucher-request-artifact) instance.
    ///
    /// # Examples
    ///
    /// ```
    /// use minerva_voucher::Voucher;
    ///
    /// let mut v = Voucher::new_vrq();
    /// assert!(v.is_vrq());
    /// ```
    pub fn is_vrq(&self) -> bool {
        self.sd.is_vrq()
    }

    /// Returns `true` if the voucher is a ["Voucher"](https://www.ietf.org/archive/id/draft-ietf-anima-constrained-voucher-15.html#name-voucher-artifact) instance.
    ///
    /// # Examples
    ///
    /// ```
    /// use minerva_voucher::Voucher;
    ///
    /// let mut v = Voucher::new_vch();
    /// assert!(v.is_vch());
    /// ```
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
    /// # Panics
    ///
    /// Panics if an invalid voucher attribute is being set.
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
    ///
    /// // Panics because `Attr::PinnedDomainPubk` is invalid for a "voucher request".
    /// // vrq.set(Attr::PinnedDomainPubk(vec![]));
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
    /// let sn = b"00-D0-E5-F2-00-02";
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
    ///     .set(Attr::SerialNumber(b"00-D0-E5-F2-00-02".to_vec()));
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

    /// Returns a tuple of references to the signature and its corresponding algorithm in the voucher, if any.
    ///
    /// # Examples
    ///
    /// ```
    /// use minerva_voucher::{Voucher, SignatureAlgorithm};
    /// use core::convert::TryFrom;
    ///
    /// static VCH_F2_00_02: &[u8] = core::include_bytes!(
    ///     concat!(env!("CARGO_MANIFEST_DIR"), "/data/00-D0-E5-F2-00-02/voucher_00-D0-E5-F2-00-02.vch"));
    ///
    /// let vch = Voucher::new_vch();
    /// assert_eq!(vch.get_signature(), None);
    ///
    /// let vch = Voucher::try_from(VCH_F2_00_02).unwrap();
    /// let (signature, alg) = vch.get_signature().unwrap();
    /// assert_eq!(signature.len(), 64);
    /// assert_eq!(*alg, SignatureAlgorithm::ES256);
    /// ```
    pub fn get_signature(&self) -> Option<(&[u8], &SignatureAlgorithm)> {
        let sig = self.cd.sig();

        if sig.signature.len() > 0 {
            Some((&sig.signature, &sig.signature_type))
        } else {
            None
        }
    }

    /// Encodes the voucher into CBOR.
    /// Before calling this function, the voucher must be already COSE-signed.
    /// Returns a CBOR byte string.
    ///
    /// # Errors
    ///
    /// If the voucher is missing any mandatory attributes, or not COSE-signed, then an error is returned.
    ///
    /// # Examples
    ///
    /// See [Encoding a `Voucher` into CBOR](index.html#2-encoding-a-voucher-into-cbor).
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

    /// Returns a reference to the signer certificate in the voucher, if any.
    ///
    /// # Examples
    ///
    /// ```
    /// use minerva_voucher::Voucher;
    ///
    /// let mut vrq = Voucher::new_vrq();
    ///
    /// assert_eq!(vrq.get_signer_cert(), None);
    /// vrq.set_signer_cert(&[4, 186, 197, 177, 28, 173, 143, 153, 249, 199, 43, 5, 207, 75, 158, 38, 210, 68, 220, 24, 159, 116, 82, 40, 37, 90, 33, 154, 134, 214, 160, 158, 255, 32, 19, 139, 248, 45, 193, 182, 213, 98, 190, 15, 165, 74, 183, 128, 74, 58, 100, 182, 215, 44, 207, 237, 107, 111, 182, 237, 40, 187, 252, 17, 126]);
    /// assert_eq!(vrq.get_signer_cert().unwrap().len(), 65);
    /// ```
    pub fn get_signer_cert(&self) -> Option<&[u8]> {
        self.cd.get_signer_cert()
    }

    /// Adds a singer certificate to the voucher. Returns a `mut` reference to the voucher.
    ///
    /// # Examples
    ///
    /// ```
    /// use minerva_voucher::Voucher;
    ///
    /// let mut vrq = Voucher::new_vrq();
    ///
    /// assert_eq!(vrq.get_signer_cert(), None);
    /// vrq.set_signer_cert(&[4, 186, 197, 177, 28, 173, 143, 153, 249, 199, 43, 5, 207, 75, 158, 38, 210, 68, 220, 24, 159, 116, 82, 40, 37, 90, 33, 154, 134, 214, 160, 158, 255, 32, 19, 139, 248, 45, 193, 182, 213, 98, 190, 15, 165, 74, 183, 128, 74, 58, 100, 182, 215, 44, 207, 237, 107, 111, 182, 237, 40, 187, 252, 17, 126]);
    /// assert_eq!(vrq.get_signer_cert().unwrap().len(), 65);
    /// ```
    pub fn set_signer_cert(&mut self, cert: &[u8]) -> &mut Self {
        self.cd.set_signer_cert(cert);

        self
    }

    #[cfg(test)]
    pub fn get_cose_content(&self) -> Option<Vec<u8>> {
        self.cd.get_content().ok()
    }

    fn update_cose_content(&mut self) -> &mut Self {
        use sid::Cbor;
        self.cd.set_content(&self.sd.serialize().unwrap());

        self
    }

    /// Interfaces with meta data required for signing the voucher.
    /// This method needs to be used when implementing the [`Sign`](crate::Sign) trait.
    ///
    /// Returns a tuple of
    /// - a `mut` reference to the `Vec<u8>` data where a new signature is being written, and
    /// - a reference to [the CBOR-encoded `COSE_Sign1` structure](https://datatracker.ietf.org/doc/html/rfc8152#section-4.2) for which signing is performed.
    ///
    /// # Examples
    ///
    /// See [the default implementation of the `Sign` trait](../src/minerva_voucher/sign.rs.html).
    pub fn to_sign(&mut self, alg: SignatureAlgorithm) -> (&mut Vec<u8>, &[u8]) {
        self.cd.set_alg(alg);

        use core::ops::DerefMut;
        let sig = self.update_cose_content()
            .cd.sig_mut().deref_mut();

        (&mut sig.signature, &sig.to_verify)
    }

    /// Interfaces with meta data required for validating the voucher.
    /// This method needs to be used when implementing the [`Validate`](crate::Validate) trait.
    ///
    /// Returns a tuple of
    /// - a reference to the signer certificate in the voucher, if any,
    /// - a tuple of references to the signature and its corresponding algorithm in the voucher, if any, and
    /// - a reference to [the CBOR-encoded `COSE_Sign1` structure](https://datatracker.ietf.org/doc/html/rfc8152#section-4.2) for which validation is performed.
    ///
    /// # Examples
    ///
    /// See [the default implementation of the `Validate` trait](../src/minerva_voucher/validate.rs.html).
    pub fn to_validate(&self) -> (Option<&[u8]>, Option<(&[u8], &SignatureAlgorithm)>, &[u8]) {
        (self.get_signer_cert(), self.get_signature(), &self.cd.sig().to_verify)
    }

    /// Prints internal representation of the voucher for debugging purposes.
    ///
    /// # Examples
    ///
    /// ```
    /// use minerva_voucher::Voucher;
    /// use core::convert::TryFrom;
    ///
    /// static VCH_JADA: &[u8] = core::include_bytes!(
    ///     concat!(env!("CARGO_MANIFEST_DIR"), "/data/jada/voucher_jada123456789.vch"));
    ///
    /// let vch = Voucher::try_from(VCH_JADA).unwrap();
    ///
    /// vch.dump();
    /// /* stdout:
    /// ======== Voucher::dump()
    /// ==== SidData::dump()
    /// Voucher({VchTopLevel(VoucherVoucher), VchAssertion(Enumeration(Assertion(Proximity))), VchCreatedOn(DateAndTime(CreatedOn(1475868702))), VchExpiresOn(DateAndTime(ExpiresOn(1506816000))), VchNonce(Binary(Nonce([97, 98, 99, 100, 49, 50, 51, 52, 53]))), VchPinnedDomainPubk(Binary(PinnedDomainPubk([77, 70, 107, 119, 69, 119, 89, 72, 75, 111, 90, 73, 122, 106, 48, 67, 65, 81, 89, 73, 75, 111, 90, 73, 122, 106, 48, 68, 65, 81, 99, 68, 81, 103, 65, 69, 108, 109, 86, 81, 99, 106, 83, 54, 110, 43, 88, 100, 53, 108, 47, 50, 56, 73, 70, 118, 54, 85, 105, 101, 103, 81, 119, 83, 66, 122, 116, 71, 106, 53, 100, 107, 75, 50, 77, 65, 106, 81, 73, 80, 86, 56, 108, 56, 108, 72, 43, 69, 106, 76, 73, 79, 89, 100, 98, 74, 105, 73, 48, 86, 116, 69, 73, 102, 49, 47, 74, 113, 116, 43, 84, 79, 66, 102, 105, 110, 84, 78, 79, 76, 79, 103, 61, 61]))), VchSerialNumber(String(SerialNumber([74, 65, 68, 65, 49, 50, 51, 52, 53, 54, 55, 56, 57])))})
    /// ====
    /// ==== CoseSig::dump()
    /// signature_type: ES256
    /// signature: [len=64] [234, 232, 104, 236, 193, 118, 136, 55, 102, 197, 220, 91, 165, 184, 220, 162, 93, 171, 60, 46, 86, 165, 81, 206, 87, 5, 183, 147, 145, 67, 72, 225, 217, 85, 56, 95, 66, 111, 229, 137, 148, 12, 142, 214, 58, 86, 83, 68, 254, 186, 154, 162, 228, 175, 25, 168, 102, 60, 251, 36, 170, 105, 99, 194]
    /// signer_cert: [len=65] [4, 186, 197, 177, 28, 173, 143, 153, 249, 199, 43, 5, 207, 75, 158, 38, 210, 68, 220, 24, 159, 116, 82, 40, 37, 90, 33, 154, 134, 214, 160, 158, 255, 32, 19, 139, 248, 45, 193, 182, 213, 98, 190, 15, 165, 74, 183, 128, 74, 58, 100, 182, 215, 44, 207, 237, 107, 111, 182, 237, 40, 187, 252, 17, 126]
    /// to_verify: [len=202] [132, 106, 83, 105, 103, 110, 97, 116, 117, 114, 101, 49, 67, 161, 1, 38, 64, 88, 183, 161, 25, 9, 147, 166, 1, 105, 112, 114, 111, 120, 105, 109, 105, 116, 121, 2, 193, 26, 87, 247, 248, 30, 4, 193, 26, 89, 208, 48, 0, 11, 109, 74, 65, 68, 65, 49, 50, 51, 52, 53, 54, 55, 56, 57, 7, 105, 97, 98, 99, 100, 49, 50, 51, 52, 53, 9, 120, 124, 77, 70, 107, 119, 69, 119, 89, 72, 75, 111, 90, 73, 122, 106, 48, 67, 65, 81, 89, 73, 75, 111, 90, 73, 122, 106, 48, 68, 65, 81, 99, 68, 81, 103, 65, 69, 108, 109, 86, 81, 99, 106, 83, 54, 110, 43, 88, 100, 53, 108, 47, 50, 56, 73, 70, 118, 54, 85, 105, 101, 103, 81, 119, 83, 66, 122, 116, 71, 106, 53, 100, 107, 75, 50, 77, 65, 106, 81, 73, 80, 86, 56, 108, 56, 108, 72, 43, 69, 106, 76, 73, 79, 89, 100, 98, 74, 105, 73, 48, 86, 116, 69, 73, 102, 49, 47, 74, 113, 116, 43, 84, 79, 66, 102, 105, 110, 84, 78, 79, 76, 79, 103, 61, 61]
    /// ====
    /// ========
    ///  */
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

impl TryFrom<&[u8]> for Voucher {
    type Error = VoucherError;

    /// Decodes a COSE-signed CBOR-encoded voucher.  Returns a `Voucher`.
    ///
    /// # Errors
    ///
    /// If the voucher cannot be decoded, then an error is returned.
    ///
    /// # Examples
    ///
    /// See [Decoding a CBOR-encoded voucher into a `Voucher`](index.html#3-decoding-a-cbor-encoded-voucher-into-a-voucher).
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

        SidData::try_from(sidhash)
            .and_then(|sd| Ok(Self { sd, cd }))
    }
}
