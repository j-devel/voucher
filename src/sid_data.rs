use crate::{println, Box, string::String, vec, Vec, BTreeMap, BTreeSet};
use cose::decoder::CborType;

//

pub type YangDateAndTime = u64;  // 'yang:date-and-time'
pub type YangString = String;    // 'string'
pub type YangBinary = Vec<u8>;   // 'binary'
pub type YangBool = bool;        // 'boolean'

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum YangEnum {              // 'enumeration'
    Verified,
    Logged,
    Proximity,
}

impl YangEnum {
    const fn value(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Logged => "logged",
            Self::Proximity => "proximity",
        }
    }
}

//

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum TopLevel {
    CwtVoucher,
    VoucherVoucher,
    CwtVoucherRequest,
    CwtVoucherRequestVoucher,
    VoucherRequestVoucher,
}

impl TopLevel {
    const fn value(self) -> &'static str {
        match self {
            Self::CwtVoucher => "ietf-cwt-voucher",
            Self::VoucherVoucher => "ietf-voucher:voucher",
            Self::CwtVoucherRequest => "ietf-cwt-voucher-request",
            Self::CwtVoucherRequestVoucher => "ietf-cwt-voucher-request:voucher",
            Self::VoucherRequestVoucher=> "ietf-voucher-request:voucher",
        }
    }
}

pub trait Cbor {
    fn to_cbor(&self) -> Option<CborType>;

    fn serialize(&self) -> Option<Vec<u8>> {
        self.to_cbor().and_then(|c| Some(c.serialize()))
    }
}

//

#[repr(u64)]
#[derive(Clone, Eq, Debug)]
pub enum Sid {
    VchTopLevel(TopLevel) =                                 1001100, // 'voucher' <- ['ietf-cwt-voucher', 'ietf-voucher:voucher']
    VchAssertion(YangEnum) =                                1001105, // 'assertion'
    VchCreatedOn(YangDateAndTime) =                         1001106, // 'created-on'
    VchDomainCertRevocationChecks(YangBool) =               1001107, // 'domain-cert-revocation-checks'
    VchExpiresOn(YangDateAndTime) =                         1001108, // 'expires-on'
    VchIdevidIssuer(YangBinary) =                           1001109, // 'idevid-issuer'
    VchLastRenewalDate(YangDateAndTime) =                   1001110, // 'last-renewal-date'
    VchNonce(YangBinary) =                                  1001111, // 'nonce'
    VchPinnedDomainCert(YangBinary) =                       1001112, // 'pinned-domain-cert'
    VchPinnedDomainSubjectPublicKeyInfo(YangBinary) =       1001113, // 'pinned-domain-subject-public-key-info'
    VchSerialNumber(YangString) =                           1001114, // 'serial-number'
    VrqTopLevel(TopLevel) =                                 1001154, // 'voucher' <- ['ietf-cwt-voucher-request', 'ietf-cwt-voucher-request:voucher', 'ietf-voucher-request:voucher']
    VrqAssertion(YangEnum) =                                1001155, // 'assertion'
    VrqCreatedOn(YangDateAndTime) =                         1001156, // 'created-on'
    VrqDomainCertRevocationChecks(YangBool) =               1001157, // 'domain-cert-revocation-checks'
    VrqExpiresOn(YangDateAndTime) =                         1001158, // 'expires-on'
    VrqIdevidIssuer(YangBinary) =                           1001159, // 'idevid-issuer'
    VrqLastRenewalDate(YangDateAndTime) =                   1001160, // 'last-renewal-date'
    VrqNonce(YangBinary) =                                  1001161, // 'nonce'
    VrqPinnedDomainCert(YangBinary) =                       1001162, // 'pinned-domain-cert'
    VrqProximityRegistrarSubjectPublicKeyInfo(YangBinary) = 1001163, // 'proximity-registrar-subject-public-key-info'
    VrqSerialNumber(YangString) =                           1001164, // 'serial-number'
    VrqPriorSignedVoucherRequest(YangBinary) =              1001165, // 'prior-signed-voucher-request'
    VrqProximityRegistrarCert(YangBinary) =                 1001166, // 'proximity-registrar-cert'
}

impl Ord for Sid {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        use core::intrinsics::discriminant_value as disc;

        disc(self).cmp(&disc(other))
    }
}

impl PartialOrd for Sid {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Sid {
    fn eq(&self, other: &Self) -> bool {
        use core::intrinsics::discriminant_value as disc;

        disc(self) == disc(other)
    }
}

impl Cbor for Sid {
    fn to_cbor(&self) -> Option<CborType> {
        use Sid::*;
        use CborType::*;

        match self {
            VchTopLevel(_) => None,
            VchAssertion(yg) => Some(StringAsBytes(yg.value().as_bytes().to_vec())),
            VchDomainCertRevocationChecks(yg) => None, // dummy; TODO !!
            VchCreatedOn(yg) | VchExpiresOn(yg) | VchLastRenewalDate(yg) => Some(Tag(0x01, Box::new(Integer(*yg)))),
            VchIdevidIssuer(yg) | VchNonce(yg) | VchPinnedDomainCert(yg) |
            VchPinnedDomainSubjectPublicKeyInfo(yg) => Some(StringAsBytes(yg.clone())),
            VchSerialNumber(yg) => Some(Bytes(yg.as_bytes().to_vec())),
            VrqTopLevel(_) => None,
            VrqAssertion(yg) => Some(StringAsBytes(yg.value().as_bytes().to_vec())),
            VrqDomainCertRevocationChecks(yg) => None, // dummy; TODO !!
            VrqCreatedOn(yg) | VrqExpiresOn(yg) | VrqLastRenewalDate(yg) => Some(Tag(0x01, Box::new(Integer(*yg)))),
            VrqIdevidIssuer(yg) | VrqNonce(yg) | VrqPinnedDomainCert(yg) |
            VrqProximityRegistrarSubjectPublicKeyInfo(yg) |
            VrqPriorSignedVoucherRequest(yg) | VrqProximityRegistrarCert(yg) => Some(StringAsBytes(yg.clone())),
            VrqSerialNumber(yg) => Some(Bytes(yg.as_bytes().to_vec())),
        }
    }
}

//

#[derive(Clone, PartialEq, Debug)]
pub enum SidData {
    Voucher(BTreeSet<Sid>),
    VoucherRequest(BTreeSet<Sid>),
}

// WIP
// - high-level getter/setter interface
// - top level attr integrity checker
// - misc attr checker
// #   +---- voucher
// #      +---- created-on?                      yang:date-and-time
// #      +---- expires-on?                      yang:date-and-time
// #      +---- assertion                        enumeration
// #      +---- serial-number                    string
// #      +---- idevid-issuer?                   binary
// #      +---- pinned-domain-cert?              binary
// #      +---- domain-cert-revocation-checks?   boolean
// #      +---- nonce?                           binary
// #      +---- last-renewal-date?               yang:date-and-time
// #      +---- prior-signed-voucher-request?    binary
// #      +---- proximity-registrar-cert?        binary
impl SidData {
    pub fn new_vch() -> Self { Self::Voucher(BTreeSet::new()) }
    pub fn new_vrq() -> Self { Self::VoucherRequest(BTreeSet::new()) }
    pub fn vch_from(set: BTreeSet<Sid>) -> Self { Self::Voucher(set) }
    pub fn vrq_from(set: BTreeSet<Sid>) -> Self { Self::VoucherRequest(set) }
}

impl Cbor for SidData {
    fn to_cbor(&self) -> Option<CborType> {
        use core::intrinsics::discriminant_value as disc;
        use CborType::*;

        let (set, ref top_level) = match self {
            Self::Voucher(set) => (set, Sid::VchTopLevel(TopLevel::VoucherVoucher)),
            Self::VoucherRequest(set) => (set, Sid::VrqTopLevel(TopLevel::VoucherRequestVoucher)),
        };

        if set.contains(top_level) {
            Some(Map(BTreeMap::from([(Integer(disc(top_level)), {
                let mut inner = BTreeMap::new();
                set.iter()
                    .filter(|sid| !matches!(*sid, Sid::VchTopLevel(_) | Sid::VrqTopLevel(_)))
                    .for_each(|sid| {
                        let delta = disc(sid) - disc(top_level);
                        inner.insert(Integer(delta), sid.to_cbor().unwrap());
                    });

                Map(inner)
            })])))
        } else {
            println!("to_cbor(): not a CBOR instance");

            None
        }
    }
}
