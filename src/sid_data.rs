use crate::{println, Box, string::String, vec, Vec, BTreeMap, BTreeSet};
use cose::decoder::CborType;
use core::convert::TryFrom;

const CBOR_TAG_UNIX_TIME: u64 = 0x01;

//

// TODO 'yang.rs'

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Yang {
    DateAndTime(u64),       // 'yang:date-and-time'
    String(String),         // 'string'
    Binary(Vec<u8>),        // 'binary'
    Boolean(bool),          // 'boolean'
    Enumeration(YangEnum),  // 'enumeration'
}

impl TryFrom<&CborType> for Yang {
    type Error = ();

    fn try_from(cbor: &CborType) -> Result<Self, Self::Error> {
        println!("!!!! cbor: {:?}", cbor);

        // WIP
        match cbor {
            CborType::Tag(val, bx) => {
                assert_eq!(*val, CBOR_TAG_UNIX_TIME); // !!
                if let CborType::Integer(time) = **bx {
                    Ok(Yang::DateAndTime(time))
                } else {
                    Err(())
                }
            },
            _ => Ok(Yang::DateAndTime(42)), // dummy
            //_ => Err(),
        }
    }
}

#[test]
fn test_yang_conversion() {
    use core::convert::TryInto;

    let ref cbor = CborType::Tag(CBOR_TAG_UNIX_TIME, Box::new(CborType::Integer(42)));
    assert_eq!(Yang::try_from(cbor), Ok(Yang::DateAndTime(42)));

    let result: Result<Yang, ()> = cbor.try_into();
    assert_eq!(result, Ok(Yang::DateAndTime(42)));

    // TODO tests for other Yang variants
}

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

//

pub const SID_VCH_TOP_LEVEL: u64 = 1001100;
// ...
pub const SID_VCH_ASSERTION: u64 = 1001106;


pub const SID_VRQ_TOP_LEVEL: u64 = 1001154;
// ...

#[repr(u64)]
#[derive(Clone, Eq, Debug)]
pub enum Sid {
    VchTopLevel(TopLevel) =                       SID_VCH_TOP_LEVEL, // 'voucher' <- ['ietf-cwt-voucher', 'ietf-voucher:voucher']
    VchAssertion(YangEnum) =                                1001105, // 'assertion'
    VchCreatedOn(Yang) =                          SID_VCH_ASSERTION, // 'created-on'
    VchDomainCertRevocationChecks(Yang) =               1001107, // 'domain-cert-revocation-checks'
    VchExpiresOn(Yang) =                         1001108, // 'expires-on'
    VchIdevidIssuer(Yang) =                           1001109, // 'idevid-issuer'
    VchLastRenewalDate(Yang) =                   1001110, // 'last-renewal-date'
    VchNonce(Yang) =                                  1001111, // 'nonce'
    VchPinnedDomainCert(Yang) =                       1001112, // 'pinned-domain-cert'
    VchPinnedDomainSubjectPublicKeyInfo(Yang) =       1001113, // 'pinned-domain-subject-public-key-info'
    VchSerialNumber(Yang) =                           1001114, // 'serial-number'
    VrqTopLevel(TopLevel) =                       SID_VRQ_TOP_LEVEL, // 'voucher' <- ['ietf-cwt-voucher-request', 'ietf-cwt-voucher-request:voucher', 'ietf-voucher-request:voucher']
    VrqAssertion(YangEnum) =                                1001155, // 'assertion'
    VrqCreatedOn(Yang) =                         1001156, // 'created-on'
    VrqDomainCertRevocationChecks(Yang) =               1001157, // 'domain-cert-revocation-checks'
    VrqExpiresOn(Yang) =                         1001158, // 'expires-on'
    VrqIdevidIssuer(Yang) =                           1001159, // 'idevid-issuer'
    VrqLastRenewalDate(Yang) =                   1001160, // 'last-renewal-date'
    VrqNonce(Yang) =                                  1001161, // 'nonce'
    VrqPinnedDomainCert(Yang) =                       1001162, // 'pinned-domain-cert'
    VrqProximityRegistrarSubjectPublicKeyInfo(Yang) = 1001163, // 'proximity-registrar-subject-public-key-info'
    VrqSerialNumber(Yang) =                           1001164, // 'serial-number'
    VrqPriorSignedVoucherRequest(Yang) =              1001165, // 'prior-signed-voucher-request'
    VrqProximityRegistrarCert(Yang) =                 1001166, // 'proximity-registrar-cert'
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

pub trait Cbor {
    fn to_cbor(&self) -> Option<CborType>;

    fn serialize(&self) -> Option<Vec<u8>> {
        self.to_cbor().and_then(|c| Some(c.serialize()))
    }
}

// TODO 'yang.rs'
fn cbor_from_yang(yg: &Yang, ty: &str) -> Option<CborType> {
    use CborType::*;

    assert!(matches!(ty, "tag" | "bytes" | "string" | "bool"));
    match (yg, ty) {
        (Yang::DateAndTime(x), "tag") => Some(Tag(CBOR_TAG_UNIX_TIME, Box::new(Integer(*x)))),
        (Yang::String(x), "bytes") => Some(Bytes(x.as_bytes().to_vec())),
        (Yang::Binary(x), "string") => Some(StringAsBytes(x.clone())),
        (Yang::Boolean(x), "bool") => Some(if *x { True } else { False }),
        _ => None,
    }
}

impl Cbor for Sid {

    fn to_cbor(&self) -> Option<CborType> {
        use Sid::*;
        use CborType::*;

        match self {
            VchTopLevel(_) => None,
            VchAssertion(yg) => Some(StringAsBytes(yg.value().as_bytes().to_vec())),
            VchDomainCertRevocationChecks(yg) => cbor_from_yang(yg, "bool"),
            VchCreatedOn(yg) | VchExpiresOn(yg) | VchLastRenewalDate(yg) => cbor_from_yang(yg, "tag"),
            VchIdevidIssuer(yg) | VchNonce(yg) | VchPinnedDomainCert(yg) |
            VchPinnedDomainSubjectPublicKeyInfo(yg) => cbor_from_yang(yg, "string"),
            VchSerialNumber(yg) => cbor_from_yang(yg, "bytes"),
            VrqTopLevel(_) => None,
            VrqAssertion(yg) => Some(StringAsBytes(yg.value().as_bytes().to_vec())),
            VrqDomainCertRevocationChecks(yg) => cbor_from_yang(yg, "bool"),
            VrqCreatedOn(yg) | VrqExpiresOn(yg) | VrqLastRenewalDate(yg) => cbor_from_yang(yg, "tag"),
            VrqIdevidIssuer(yg) | VrqNonce(yg) | VrqPinnedDomainCert(yg) |
            VrqProximityRegistrarSubjectPublicKeyInfo(yg) |
            VrqPriorSignedVoucherRequest(yg) | VrqProximityRegistrarCert(yg) => cbor_from_yang(yg, "string"),
            VrqSerialNumber(yg) => cbor_from_yang(yg, "bytes"),
        }
    }
}

//

#[derive(Clone, PartialEq, Debug)]
pub enum SidData {
    Voucher(BTreeSet<Sid>),
    VoucherRequest(BTreeSet<Sid>),
}

// TODO - checker on serialize/sign/****
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

    pub fn new_vch_cbor() -> Self { Self::Voucher(BTreeSet::from([
        Sid::VchTopLevel(TopLevel::VoucherVoucher)])) }
    pub fn new_vrq_cbor() -> Self { Self::VoucherRequest(BTreeSet::from([
        Sid::VrqTopLevel(TopLevel::VoucherRequestVoucher)])) }

    pub fn replace(&mut self, sid: Sid) {
        self.inner_mut().replace(sid);
    }

    fn inner_mut(&mut self) -> &mut BTreeSet<Sid> {
        match self {
            Self::Voucher(set) => set,
            Self::VoucherRequest(set) => set,
        }
    }

    fn inner(&self) -> (&BTreeSet<Sid>, bool /* is_vrq */) {
        match self {
            Self::Voucher(set) => (set, false),
            Self::VoucherRequest(set) => (set, true),
        }
    }

    pub fn is_vrq(&self) -> bool {
        self.inner().1
    }
}

impl Cbor for SidData {
    fn to_cbor(&self) -> Option<CborType> {
        use core::intrinsics::discriminant_value as disc;
        use CborType::*;

        let (set, is_vrq) = self.inner();
        let top_level = if is_vrq {
            &Sid::VrqTopLevel(TopLevel::VoucherRequestVoucher)
        } else {
            &Sid::VchTopLevel(TopLevel::VoucherVoucher)
        };

        if set.contains(top_level) {
            Some(Map(BTreeMap::from([(Integer(disc(top_level)), {
                let mut attrs = BTreeMap::new();
                set.iter()
                    .filter(|sid| !matches!(*sid, Sid::VchTopLevel(_) | Sid::VrqTopLevel(_)))
                    .for_each(|sid| {
                        let delta = disc(sid) - disc(top_level);
                        attrs.insert(Integer(delta), sid.to_cbor().unwrap());
                    });

                Map(attrs)
            })])))
        } else {
            println!("to_cbor(): not a CBOR vch/vrq instance");

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
    assert_eq!(disc(&Sid::VrqCreatedOn(Yang::DateAndTime(1635218340))), 1001156);
    assert_eq!(disc(&Sid::VrqNonce(Yang::Binary(vec![114, 72, 103, 99, 66, 86, 78, 86, 97, 70, 109, 66, 87, 98, 84, 77, 109, 101, 79, 75, 117, 103]))),
               1001161);

    let serial_02_00_2e = String::from("00-D0-E5-02-00-2E");
    assert_eq!(serial_02_00_2e.as_bytes(), [48, 48, 45, 68, 48, 45, 69, 53, 45, 48, 50, 45, 48, 48, 45, 50, 69]);
    assert_eq!(disc(&Sid::VrqSerialNumber(Yang::String(serial_02_00_2e))), 1001164);
}

#[test]
fn test_sid_data_vch_02_00_2e() {
    let _sd_vch = SidData::vch_from(BTreeSet::from([
        // ...
    ]));

    // TODO
}

#[test]
fn test_sid_data_vrq_02_00_2e() {
    let sd_vrq = SidData::vrq_from(BTreeSet::from([
        Sid::VrqTopLevel(TopLevel::VoucherRequestVoucher),
        Sid::VrqAssertion(YangEnum::Proximity),
        Sid::VrqCreatedOn(Yang::DateAndTime(1635218340)),
        Sid::VrqNonce(Yang::Binary(vec![114, 72, 103, 99, 66, 86, 78, 86, 97, 70, 109, 66, 87, 98, 84, 77, 109, 101, 79, 75, 117, 103])),
        Sid::VrqSerialNumber(Yang::String(String::from("00-D0-E5-02-00-2E"))),
    ]));

    println!("sd_vrq: {:?}", sd_vrq);
    assert!(content_comp(&sd_vrq.serialize().unwrap(),
                         &vrhash_sidhash_content_02_00_2e()));
}

#[test]
fn test_sid_cbor_boolean() {
    let sid = Sid::VchDomainCertRevocationChecks(Yang::Boolean(false));
    assert_eq!(sid.to_cbor(), Some(CborType::False));
    assert_eq!(sid.serialize(), Some(vec![244]));

    let sid = Sid::VchDomainCertRevocationChecks(Yang::Boolean(true));
    assert_eq!(sid.to_cbor(), Some(CborType::True));
    assert_eq!(sid.serialize(), Some(vec![245]));

    let sid = Sid::VrqDomainCertRevocationChecks(Yang::Boolean(false));
    assert_eq!(sid.to_cbor(), Some(CborType::False));
    assert_eq!(sid.serialize(), Some(vec![244]));

    let sid = Sid::VrqDomainCertRevocationChecks(Yang::Boolean(true));
    assert_eq!(sid.to_cbor(), Some(CborType::True));
    assert_eq!(sid.serialize(), Some(vec![245]));

    assert_eq!(CborType::Null.serialize(), vec![246]); // FYI
}
