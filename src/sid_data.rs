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

//

pub fn content_comp(a: &[u8], b: &[u8]) -> bool {
    let sum = |v: &[u8]| -> u32 { v.iter().map(|b| *b as u32).sum() };

    a.len() == b.len() && sum(a) == sum(b)
}

pub fn vrhash_sidhash_content_02_00_2e() -> Vec<u8> {
    vec![161, 26, 0, 15, 70, 194, 164, 1, 105, 112, 114, 111, 120, 105, 109, 105, 116, 121, 2, 193, 26, 97, 119, 115, 164, 10, 81, 48, 48, 45, 68, 48, 45, 69, 53, 45, 48, 50, 45, 48, 48, 45, 50, 69, 7, 118, 114, 72, 103, 99, 66, 86, 78, 86, 97, 70, 109, 66, 87, 98, 84, 77, 109, 101, 79, 75, 117, 103]
}

#[test]
fn test_sid_02_00_2e() {
    use core::intrinsics::discriminant_value as disc;
    use YangEnum::*;

    assert_eq!(disc(&Sid::VrqTopLevel(TopLevel::VoucherRequestVoucher)), 1001154);
    assert_eq!(disc(&Sid::VrqAssertion(Proximity)), 1001155);
    assert_eq!(disc(&Sid::VrqCreatedOn(1635218340)), 1001156);
    assert_eq!(disc(&Sid::VrqNonce(vec![114, 72, 103, 99, 66, 86, 78, 86, 97, 70, 109, 66, 87, 98, 84, 77, 109, 101, 79, 75, 117, 103])),
               1001161);

    let serial_02_00_2e = String::from("00-D0-E5-02-00-2E");
    assert_eq!(serial_02_00_2e.as_bytes(), [48, 48, 45, 68, 48, 45, 69, 53, 45, 48, 50, 45, 48, 48, 45, 50, 69]);
    assert_eq!(disc(&Sid::VrqSerialNumber(serial_02_00_2e)), 1001164);
}

#[test]
fn test_sid_data_vch_02_00_2e() {
    let _sd_vch = SidData::Voucher(BTreeSet::from([
        // ...
    ]));

    // TODO
}

#[test]
fn test_sid_data_vrq_02_00_2e() {
    let sd_vrq = SidData::vrq_from(BTreeSet::from([
        Sid::VrqTopLevel(TopLevel::VoucherRequestVoucher),
        Sid::VrqAssertion(YangEnum::Proximity),
        Sid::VrqCreatedOn(1635218340),
        Sid::VrqNonce(vec![114, 72, 103, 99, 66, 86, 78, 86, 97, 70, 109, 66, 87, 98, 84, 77, 109, 101, 79, 75, 117, 103]),
        Sid::VrqSerialNumber(String::from("00-D0-E5-02-00-2E")),
    ]));

    println!("sd_vrq: {:?}", sd_vrq);
    assert!(content_comp(&sd_vrq.serialize().unwrap(),
                         &vrhash_sidhash_content_02_00_2e()));
}
