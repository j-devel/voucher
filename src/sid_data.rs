use crate::{println, vec, Vec, BTreeMap, BTreeSet};
pub use cose::decoder::CborType;

pub use super::yang::{Yang, YangEnum};
use super::yang;

use core::intrinsics::discriminant_value as disc;
use core::convert::TryFrom;

pub trait Cbor {
    fn to_cbor(&self) -> Option<CborType>;

    fn serialize(&self) -> Option<Vec<u8>> {
        self.to_cbor().and_then(|c| Some(c.serialize()))
    }
}

pub type SidDisc = u64;

pub const SID_VCH_TOP_LEVEL: SidDisc =                                   2451; // 'voucher' <- ['ietf-cwt-voucher', 'ietf-voucher-constrained:voucher']
pub const SID_VCH_ASSERTION: SidDisc =                                   2452; // 'assertion'
pub const SID_VCH_CREATED_ON: SidDisc =                                  2453; // 'created-on'
pub const SID_VCH_DOMAIN_CERT_REVOCATION_CHECKS: SidDisc =               2454; // 'domain-cert-revocation-checks'
pub const SID_VCH_EXPIRES_ON: SidDisc =                                  2455; // 'expires-on'
pub const SID_VCH_IDEVID_ISSUER: SidDisc =                               2456; // 'idevid-issuer'
pub const SID_VCH_LAST_RENEWAL_DATE: SidDisc =                           2457; // 'last-renewal-date'
pub const SID_VCH_NONCE: SidDisc =                                       2458; // 'nonce'
pub const SID_VCH_PINNED_DOMAIN_CERT: SidDisc =                          2459; // 'pinned-domain-cert'
pub const SID_VCH_PINNED_DOMAIN_PUBK: SidDisc =                          2460; // 'pinned-domain-pubk'
pub const SID_VCH_PINNED_DOMAIN_PUBK_SHA256: SidDisc =                   2461; // 'pinned-domain-pubk-sha256'
pub const SID_VCH_SERIAL_NUMBER: SidDisc =                               2462; // 'serial-number'

pub const SID_VRQ_TOP_LEVEL: SidDisc =                                   2501; // 'voucher' <- ['ietf-cwt-voucher-request', 'ietf-cwt-voucher-request:voucher', 'ietf-voucher-request-constrained:voucher']
pub const SID_VRQ_ASSERTION: SidDisc =                                   2502; // 'assertion'
pub const SID_VRQ_CREATED_ON: SidDisc =                                  2503; // 'created-on'
pub const SID_VRQ_DOMAIN_CERT_REVOCATION_CHECKS: SidDisc =               2504; // 'domain-cert-revocation-checks'
pub const SID_VRQ_EXPIRES_ON: SidDisc =                                  2505; // 'expires-on'
pub const SID_VRQ_IDEVID_ISSUER: SidDisc =                               2506; // 'idevid-issuer'
pub const SID_VRQ_LAST_RENEWAL_DATE: SidDisc =                           2507; // 'last-renewal-date'
pub const SID_VRQ_NONCE: SidDisc =                                       2508; // 'nonce'
pub const SID_VRQ_PINNED_DOMAIN_CERT: SidDisc =                          2509; // 'pinned-domain-cert'
pub const SID_VRQ_PRIOR_SIGNED_VOUCHER_REQUEST: SidDisc =                2510; // 'prior-signed-voucher-request'
pub const SID_VRQ_PROXIMITY_REGISTRAR_CERT: SidDisc =                    2511; // 'proximity-registrar-cert'
pub const SID_VRQ_PROXIMITY_REGISTRAR_PUBK: SidDisc =                    2513; // 'proximity-registrar-pubk'
pub const SID_VRQ_PROXIMITY_REGISTRAR_PUBK_SHA256: SidDisc =             2512; // 'proximity-registrar-pubk-sha256'
pub const SID_VRQ_SERIAL_NUMBER: SidDisc =                               2514; // 'serial-number'

#[repr(u64)]
#[derive(Clone, Eq, Debug)]
pub enum Sid {
    VchTopLevel(TopLevel) =                           SID_VCH_TOP_LEVEL,
    VchAssertion(Yang) =                              SID_VCH_ASSERTION,
    VchCreatedOn(Yang) =                              SID_VCH_CREATED_ON,
    VchDomainCertRevocationChecks(Yang) =             SID_VCH_DOMAIN_CERT_REVOCATION_CHECKS,
    VchExpiresOn(Yang) =                              SID_VCH_EXPIRES_ON,
    VchIdevidIssuer(Yang) =                           SID_VCH_IDEVID_ISSUER,
    VchLastRenewalDate(Yang) =                        SID_VCH_LAST_RENEWAL_DATE,
    VchNonce(Yang) =                                  SID_VCH_NONCE,
    VchPinnedDomainCert(Yang) =                       SID_VCH_PINNED_DOMAIN_CERT,
    VchPinnedDomainPubk(Yang) =                       SID_VCH_PINNED_DOMAIN_PUBK,
    VchPinnedDomainPubkSha256(Yang) =                 SID_VCH_PINNED_DOMAIN_PUBK_SHA256,
    VchSerialNumber(Yang) =                           SID_VCH_SERIAL_NUMBER,
    VrqTopLevel(TopLevel) =                           SID_VRQ_TOP_LEVEL,
    VrqAssertion(Yang) =                              SID_VRQ_ASSERTION,
    VrqCreatedOn(Yang) =                              SID_VRQ_CREATED_ON,
    VrqDomainCertRevocationChecks(Yang) =             SID_VRQ_DOMAIN_CERT_REVOCATION_CHECKS,
    VrqExpiresOn(Yang) =                              SID_VRQ_EXPIRES_ON,
    VrqIdevidIssuer(Yang) =                           SID_VRQ_IDEVID_ISSUER,
    VrqLastRenewalDate(Yang) =                        SID_VRQ_LAST_RENEWAL_DATE,
    VrqNonce(Yang) =                                  SID_VRQ_NONCE,
    VrqPinnedDomainCert(Yang) =                       SID_VRQ_PINNED_DOMAIN_CERT,
    VrqPriorSignedVoucherRequest(Yang) =              SID_VRQ_PRIOR_SIGNED_VOUCHER_REQUEST,
    VrqProximityRegistrarCert(Yang) =                 SID_VRQ_PROXIMITY_REGISTRAR_CERT,
    VrqProximityRegistrarPubk(Yang) =                 SID_VRQ_PROXIMITY_REGISTRAR_PUBK,
    VrqProximityRegistrarPubkSha256(Yang) =           SID_VRQ_PROXIMITY_REGISTRAR_PUBK_SHA256,
    VrqSerialNumber(Yang) =                           SID_VRQ_SERIAL_NUMBER,
}

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

impl Ord for Sid {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
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
        disc(self) == disc(other)
    }
}

impl Cbor for Sid {
    fn to_cbor(&self) -> Option<CborType> {
        use Sid::*;
        use yang::*;

        let yang_to_cbor =
            |yg: &Yang, ygd| if disc(yg) == ygd { yg.to_cbor() } else { None };

        match self {
            VchTopLevel(_) |
            VrqTopLevel(_) =>
                None,
            VchAssertion(yg) |
            VrqAssertion(yg) =>
                yang_to_cbor(yg, YANG_ENUMERATION),
            VchDomainCertRevocationChecks(yg) |
            VrqDomainCertRevocationChecks(yg) =>
                yang_to_cbor(yg, YANG_BOOLEAN),
            VchCreatedOn(yg) |
            VchExpiresOn(yg) |
            VchLastRenewalDate(yg) |
            VrqCreatedOn(yg) |
            VrqExpiresOn(yg) |
            VrqLastRenewalDate(yg) =>
                yang_to_cbor(yg, YANG_DATE_AND_TIME),
            VchIdevidIssuer(yg) |
            VchNonce(yg) |
            VchPinnedDomainCert(yg) |
            VchPinnedDomainPubk(yg) |
            VchPinnedDomainPubkSha256(yg) |
            VrqIdevidIssuer(yg) |
            VrqNonce(yg) |
            VrqPinnedDomainCert(yg) |
            VrqPriorSignedVoucherRequest(yg) |
            VrqProximityRegistrarCert(yg) |
            VrqProximityRegistrarPubk(yg) |
            VrqProximityRegistrarPubkSha256(yg) =>
                yang_to_cbor(yg, YANG_BINARY),
            VchSerialNumber(yg) |
            VrqSerialNumber(yg) =>
                yang_to_cbor(yg, YANG_STRING),
        }
    }
}

impl TryFrom<(Yang, SidDisc)> for Sid {
    type Error = ();

    fn try_from(input: (Yang, SidDisc)) -> Result<Self, Self::Error> {
        let (yg, sid_disc) = input;
        match sid_disc {
            SID_VCH_TOP_LEVEL => Err(()),
            SID_VCH_ASSERTION => Ok(Sid::VchAssertion(yg)),
            SID_VCH_CREATED_ON => Ok(Sid::VchCreatedOn(yg)),
            SID_VCH_DOMAIN_CERT_REVOCATION_CHECKS => Ok(Sid::VchDomainCertRevocationChecks(yg)),
            SID_VCH_EXPIRES_ON => Ok(Sid::VchExpiresOn(yg)),
            SID_VCH_IDEVID_ISSUER => Ok(Sid::VchIdevidIssuer(yg)),
            SID_VCH_LAST_RENEWAL_DATE => Ok(Sid::VchLastRenewalDate(yg)),
            SID_VCH_NONCE => Ok(Sid::VchNonce(yg)),
            SID_VCH_PINNED_DOMAIN_CERT => Ok(Sid::VchPinnedDomainCert(yg)),
            SID_VCH_PINNED_DOMAIN_PUBK => Ok(Sid::VchPinnedDomainPubk(yg)),
            SID_VCH_PINNED_DOMAIN_PUBK_SHA256 => Ok(Sid::VchPinnedDomainPubkSha256(yg)),
            SID_VCH_SERIAL_NUMBER => Ok(Sid::VchSerialNumber(yg)),
            SID_VRQ_TOP_LEVEL => Err(()),
            SID_VRQ_ASSERTION => Ok(Sid::VrqAssertion(yg)),
            SID_VRQ_CREATED_ON => Ok(Sid::VrqCreatedOn(yg)),
            SID_VRQ_DOMAIN_CERT_REVOCATION_CHECKS => Ok(Sid::VrqDomainCertRevocationChecks(yg)),
            SID_VRQ_EXPIRES_ON => Ok(Sid::VrqExpiresOn(yg)),
            SID_VRQ_IDEVID_ISSUER => Ok(Sid::VrqIdevidIssuer(yg)),
            SID_VRQ_LAST_RENEWAL_DATE => Ok(Sid::VrqLastRenewalDate(yg)),
            SID_VRQ_NONCE => Ok(Sid::VrqNonce(yg)),
            SID_VRQ_PINNED_DOMAIN_CERT => Ok(Sid::VrqPinnedDomainCert(yg)),
            SID_VRQ_PRIOR_SIGNED_VOUCHER_REQUEST => Ok(Sid::VrqPriorSignedVoucherRequest(yg)),
            SID_VRQ_PROXIMITY_REGISTRAR_CERT => Ok(Sid::VrqProximityRegistrarCert(yg)),
            SID_VRQ_PROXIMITY_REGISTRAR_PUBK => Ok(Sid::VrqProximityRegistrarPubk(yg)),
            SID_VRQ_PROXIMITY_REGISTRAR_PUBK_SHA256 => Ok(Sid::VrqProximityRegistrarPubkSha256(yg)),
            SID_VRQ_SERIAL_NUMBER => Ok(Sid::VrqSerialNumber(yg)),
            _ => Err(()),
        }
    }
}

//

#[derive(Clone, PartialEq, Debug)]
pub enum SidData {
    Voucher(BTreeSet<Sid>),
    VoucherRequest(BTreeSet<Sid>),
}

// TODO - update according to 'draft-ietf-anima-constrained-voucher-15'
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

    pub fn new_vch_cbor() -> Self {
        Self::Voucher(BTreeSet::from([Sid::VchTopLevel(TopLevel::VoucherVoucher)]))
    }

    pub fn new_vrq_cbor() -> Self {
        Self::VoucherRequest(BTreeSet::from([Sid::VrqTopLevel(TopLevel::VoucherRequestVoucher)]))
    }

    pub fn replace(&mut self, sid: Sid) {
        self.inner_mut().replace(sid);
    }

    fn inner_mut(&mut self) -> &mut BTreeSet<Sid> {
        match self {
            Self::Voucher(set) => set,
            Self::VoucherRequest(set) => set,
        }
    }

    pub fn inner(&self) -> (&BTreeSet<Sid>, bool /* is_vrq */) {
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
        use CborType::*;

        let (set, is_vrq) = self.inner();
        let tl = if is_vrq {
            &Sid::VrqTopLevel(TopLevel::VoucherRequestVoucher)
        } else {
            &Sid::VchTopLevel(TopLevel::VoucherVoucher)
        };

        if set.contains(tl) {
            Some(Map(BTreeMap::from([(Integer(disc(tl)), {
                let mut attrs = BTreeMap::new();
                set.iter()
                    .filter(|sid| !matches!(*sid, Sid::VchTopLevel(_) | Sid::VrqTopLevel(_)))
                    .for_each(|sid| {
                        let delta = disc(sid) - disc(tl);
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

impl TryFrom<CborType> for SidData {
    type Error = ();

    fn try_from(sidhash: CborType) -> Result<Self, Self::Error> {
        from_sidhash(sidhash).ok_or(())
    }
}

fn from_sidhash(sidhash: CborType) -> Option<SidData> {
    use super::cose_sig::map_value_from;
    use CborType::*;

    let (is_vrq, btmap, sid_tl_disc, sid_tl) =
        if let Ok(Map(btmap)) = map_value_from(&sidhash, &Integer(SID_VCH_TOP_LEVEL)) {
            (false, btmap, SID_VCH_TOP_LEVEL, Sid::VchTopLevel(TopLevel::VoucherVoucher))
        } else if let Ok(Map(btmap)) = map_value_from(&sidhash, &Integer(SID_VRQ_TOP_LEVEL)) {
            (true, btmap, SID_VRQ_TOP_LEVEL, Sid::VrqTopLevel(TopLevel::VoucherRequestVoucher))
        } else {
            return None;
        };

    let mut sd = if is_vrq { SidData::new_vrq() } else { SidData::new_vch() };
    sd.replace(sid_tl);

    btmap.iter()
        .filter_map(|(k, v)| if let Integer(delta) = k { Some((sid_tl_disc + delta, v)) } else { None })
        .map(|(sid_disc, v)| Sid::try_from(
            (Yang::try_from((v, sid_disc)).unwrap(), sid_disc)).unwrap())
        .for_each(|sid| sd.replace(sid));

    Some(sd)
}

//

pub fn content_comp(a: &[u8], b: &[u8]) -> bool {
    let sum = |v: &[u8]| -> u32 { v.iter().map(|b| *b as u32).sum() };
    println!("content_comp(): {} {} {} {}", a.len(), b.len(), sum(a), sum(b));

    a.len() == b.len() && sum(a) == sum(b)
}

pub fn content_vch_f2_00_02() -> Vec<u8> {
    vec![161, 25, 9, 147, 165, 1, 102, 108, 111, 103, 103, 101, 100, 2, 193, 26, 95, 86, 209, 119, 11, 113, 48, 48, 45, 68, 48, 45, 69, 53, 45, 70, 50, 45, 48, 48, 45, 48, 50, 7, 118, 88, 83, 121, 70, 52, 76, 76, 73, 105, 113, 85, 50, 45, 79, 71, 107, 54, 108, 70, 67, 65, 103, 8, 121, 2, 116, 77, 73, 73, 66, 48, 84, 67, 67, 65, 86, 97, 103, 65, 119, 73, 66, 65, 103, 73, 66, 65, 106, 65, 75, 66, 103, 103, 113, 104, 107, 106, 79, 80, 81, 81, 68, 65, 122, 66, 120, 77, 82, 73, 119, 69, 65, 89, 75, 67, 90, 73, 109, 105, 90, 80, 121, 76, 71, 81, 66, 71, 82, 89, 67, 89, 50, 69, 120, 71, 84, 65, 88, 66, 103, 111, 74, 107, 105, 97, 74, 107, 47, 73, 115, 90, 65, 69, 90, 70, 103, 108, 122, 89, 87, 53, 107, 90, 87, 120, 116, 89, 87, 52, 120, 81, 68, 65, 43, 66, 103, 78, 86, 66, 65, 77, 77, 78, 121, 77, 56, 85, 51, 108, 122, 100, 71, 86, 116, 86, 109, 70, 121, 97, 87, 70, 105, 98, 71, 85, 54, 77, 72, 103, 119, 77, 68, 65, 119, 77, 68, 65, 119, 78, 71, 89, 53, 77, 84, 70, 104, 77, 68, 52, 103, 86, 87, 53, 122, 100, 72, 74, 49, 98, 109, 99, 103, 82, 109, 57, 49, 98, 110, 82, 104, 97, 87, 52, 103, 81, 48, 69, 119, 72, 104, 99, 78, 77, 84, 99, 120, 77, 84, 65, 51, 77, 106, 77, 48, 78, 84, 73, 52, 87, 104, 99, 78, 77, 84, 107, 120, 77, 84, 65, 51, 77, 106, 77, 48, 78, 84, 73, 52, 87, 106, 66, 68, 77, 82, 73, 119, 69, 65, 89, 75, 67, 90, 73, 109, 105, 90, 80, 121, 76, 71, 81, 66, 71, 82, 89, 67, 89, 50, 69, 120, 71, 84, 65, 88, 66, 103, 111, 74, 107, 105, 97, 74, 107, 47, 73, 115, 90, 65, 69, 90, 70, 103, 108, 122, 89, 87, 53, 107, 90, 87, 120, 116, 89, 87, 52, 120, 69, 106, 65, 81, 66, 103, 78, 86, 66, 65, 77, 77, 67, 87, 120, 118, 89, 50, 70, 115, 97, 71, 57, 122, 100, 68, 66, 90, 77, 66, 77, 71, 66, 121, 113, 71, 83, 77, 52, 57, 65, 103, 69, 71, 67, 67, 113, 71, 83, 77, 52, 57, 65, 119, 69, 72, 65, 48, 73, 65, 66, 74, 90, 108, 85, 72, 73, 48, 117, 112, 47, 108, 51, 101, 90, 102, 57, 118, 67, 66, 98, 43, 108, 73, 110, 111, 69, 77, 69, 103, 99, 55, 82, 111, 43, 88, 90, 67, 116, 106, 65, 73, 48, 67, 68, 49, 102, 74, 102, 74, 82, 47, 104, 73, 121, 121, 68, 109, 72, 87, 121, 89, 105, 78, 70, 98, 82, 67, 72, 57, 102, 121, 97, 114, 102, 107, 122, 103, 88, 52, 112, 48, 122, 84, 105, 122, 113, 106, 68, 84, 65, 76, 77, 65, 107, 71, 65, 49, 85, 100, 69, 119, 81, 67, 77, 65, 65, 119, 67, 103, 89, 73, 75, 111, 90, 73, 122, 106, 48, 69, 65, 119, 77, 68, 97, 81, 65, 119, 90, 103, 73, 120, 65, 76, 81, 77, 78, 117, 114, 102, 56, 116, 118, 53, 48, 108, 82, 79, 68, 53, 68, 81, 88, 72, 69, 79, 74, 74, 78, 87, 51, 81, 86, 50, 103, 57, 81, 69, 100, 68, 83, 107, 50, 77, 89, 43, 65, 111, 83, 114, 66, 83, 109, 71, 83, 78, 106, 104, 52, 111, 108, 69, 79, 104, 69, 117, 76, 103, 73, 120, 65, 74, 52, 110, 87, 102, 78, 119, 43, 66, 106, 98, 90, 109, 75, 105, 73, 105, 85, 69, 99, 84, 119, 72, 77, 104, 71, 86, 88, 97, 77, 72, 89, 47, 70, 55, 110, 51, 57, 119, 119, 75, 99, 66, 66, 83, 79, 110, 100, 78, 80, 113, 67, 112, 79, 69, 76, 108, 54, 98, 113, 51, 67, 90, 113, 81, 61, 61]
}

#[test]
fn test_sid_vch_f2_00_02() {
    assert_eq!(disc(&Sid::VchTopLevel(TopLevel::VoucherVoucher)), SID_VCH_TOP_LEVEL);
    assert_eq!(disc(&Sid::VchAssertion(Yang::Enumeration(YangEnum::Logged))), SID_VCH_ASSERTION);
    assert_eq!(disc(&Sid::VchCreatedOn(Yang::DateAndTime(1599525239))), SID_VCH_CREATED_ON);
    assert_eq!(disc(&Sid::VchNonce(Yang::Binary(vec![88, 83, 121, 70, 52, 76, 76, 73, 105, 113, 85, 50, 45, 79, 71, 107, 54, 108, 70, 67, 65, 103]))),
               SID_VCH_NONCE);
    assert_eq!(disc(&Sid::VchPinnedDomainCert(Yang::Binary("MIIB0TCCAVagAwIBAgIBAjAKBggqhkjOPQQDAzBxMRIwEAYKCZImiZPyLGQBGRYCY2ExGTAXBgoJkiaJk/IsZAEZFglzYW5kZWxtYW4xQDA+BgNVBAMMNyM8U3lzdGVtVmFyaWFibGU6MHgwMDAwMDAwNGY5MTFhMD4gVW5zdHJ1bmcgRm91bnRhaW4gQ0EwHhcNMTcxMTA3MjM0NTI4WhcNMTkxMTA3MjM0NTI4WjBDMRIwEAYKCZImiZPyLGQBGRYCY2ExGTAXBgoJkiaJk/IsZAEZFglzYW5kZWxtYW4xEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJZlUHI0up/l3eZf9vCBb+lInoEMEgc7Ro+XZCtjAI0CD1fJfJR/hIyyDmHWyYiNFbRCH9fyarfkzgX4p0zTizqjDTALMAkGA1UdEwQCMAAwCgYIKoZIzj0EAwMDaQAwZgIxALQMNurf8tv50lROD5DQXHEOJJNW3QV2g9QEdDSk2MY+AoSrBSmGSNjh4olEOhEuLgIxAJ4nWfNw+BjbZmKiIiUEcTwHMhGVXaMHY/F7n39wwKcBBSOndNPqCpOELl6bq3CZqQ=="
        .as_bytes().to_vec()))), SID_VCH_PINNED_DOMAIN_CERT);

    let serial = "00-D0-E5-F2-00-02".as_bytes();
    assert_eq!(serial, [48, 48, 45, 68, 48, 45, 69, 53, 45, 70, 50, 45, 48, 48, 45, 48, 50]);
    assert_eq!(disc(&Sid::VchSerialNumber(Yang::String(serial.to_vec()))), SID_VCH_SERIAL_NUMBER);
}

#[test]
fn test_sid_data_vch_f2_00_02() {
    let sd = SidData::vch_from(BTreeSet::from([
        Sid::VchTopLevel(TopLevel::VoucherVoucher),
        Sid::VchAssertion(Yang::Enumeration(YangEnum::Logged)),
        Sid::VchCreatedOn(Yang::DateAndTime(1599525239)),
        Sid::VchNonce(Yang::Binary(vec![88, 83, 121, 70, 52, 76, 76, 73, 105, 113, 85, 50, 45, 79, 71, 107, 54, 108, 70, 67, 65, 103])),
        Sid::VchPinnedDomainCert(Yang::Binary("MIIB0TCCAVagAwIBAgIBAjAKBggqhkjOPQQDAzBxMRIwEAYKCZImiZPyLGQBGRYCY2ExGTAXBgoJkiaJk/IsZAEZFglzYW5kZWxtYW4xQDA+BgNVBAMMNyM8U3lzdGVtVmFyaWFibGU6MHgwMDAwMDAwNGY5MTFhMD4gVW5zdHJ1bmcgRm91bnRhaW4gQ0EwHhcNMTcxMTA3MjM0NTI4WhcNMTkxMTA3MjM0NTI4WjBDMRIwEAYKCZImiZPyLGQBGRYCY2ExGTAXBgoJkiaJk/IsZAEZFglzYW5kZWxtYW4xEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJZlUHI0up/l3eZf9vCBb+lInoEMEgc7Ro+XZCtjAI0CD1fJfJR/hIyyDmHWyYiNFbRCH9fyarfkzgX4p0zTizqjDTALMAkGA1UdEwQCMAAwCgYIKoZIzj0EAwMDaQAwZgIxALQMNurf8tv50lROD5DQXHEOJJNW3QV2g9QEdDSk2MY+AoSrBSmGSNjh4olEOhEuLgIxAJ4nWfNw+BjbZmKiIiUEcTwHMhGVXaMHY/F7n39wwKcBBSOndNPqCpOELl6bq3CZqQ==".as_bytes().to_vec())),
        Sid::VchSerialNumber(Yang::String("00-D0-E5-F2-00-02".as_bytes().to_vec())),
    ]));

    println!("sd: {:?}", sd);

    // TODO check; `sum()`s not agree ....
    assert!(content_comp(&sd.serialize().unwrap(), &content_vch_f2_00_02()));
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
}
