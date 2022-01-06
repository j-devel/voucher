use crate::Vec;
use super::yang::{self, Yang};
use core::convert::TryFrom;

pub use cose::decoder::CborType;
pub trait Cbor {
    fn to_cbor(&self) -> Option<CborType>;

    fn serialize(&self) -> Option<Vec<u8>> {
        self.to_cbor().and_then(|c| Some(c.serialize()))
    }
}

pub type SidDisc = u64;
pub const SID_VCH_TOP_LEVEL: SidDisc =                        2451;
pub const SID_VCH_ASSERTION: SidDisc =                        2452;
pub const SID_VCH_CREATED_ON: SidDisc =                       2453;
pub const SID_VCH_DOMAIN_CERT_REVOCATION_CHECKS: SidDisc =    2454;
pub const SID_VCH_EXPIRES_ON: SidDisc =                       2455;
pub const SID_VCH_IDEVID_ISSUER: SidDisc =                    2456;
pub const SID_VCH_LAST_RENEWAL_DATE: SidDisc =                2457;
pub const SID_VCH_NONCE: SidDisc =                            2458;
pub const SID_VCH_PINNED_DOMAIN_CERT: SidDisc =               2459;
pub const SID_VCH_PINNED_DOMAIN_PUBK: SidDisc =               2460;
pub const SID_VCH_PINNED_DOMAIN_PUBK_SHA256: SidDisc =        2461;
pub const SID_VCH_SERIAL_NUMBER: SidDisc =                    2462;
pub const SID_VRQ_TOP_LEVEL: SidDisc =                        2501;
pub const SID_VRQ_ASSERTION: SidDisc =                        2502;
pub const SID_VRQ_CREATED_ON: SidDisc =                       2503;
pub const SID_VRQ_DOMAIN_CERT_REVOCATION_CHECKS: SidDisc =    2504;
pub const SID_VRQ_EXPIRES_ON: SidDisc =                       2505;
pub const SID_VRQ_IDEVID_ISSUER: SidDisc =                    2506;
pub const SID_VRQ_LAST_RENEWAL_DATE: SidDisc =                2507;
pub const SID_VRQ_NONCE: SidDisc =                            2508;
pub const SID_VRQ_PINNED_DOMAIN_CERT: SidDisc =               2509;
pub const SID_VRQ_PRIOR_SIGNED_VOUCHER_REQUEST: SidDisc =     2510;
pub const SID_VRQ_PROXIMITY_REGISTRAR_CERT: SidDisc =         2511;
pub const SID_VRQ_PROXIMITY_REGISTRAR_PUBK: SidDisc =         2513;
pub const SID_VRQ_PROXIMITY_REGISTRAR_PUBK_SHA256: SidDisc =  2512;
pub const SID_VRQ_SERIAL_NUMBER: SidDisc =                    2514;

#[repr(u64)]
#[derive(Clone, Eq, Debug)]
pub enum Sid {
    VchTopLevel(TopLevel) =                  SID_VCH_TOP_LEVEL,
    VchAssertion(Yang) =                     SID_VCH_ASSERTION,
    VchCreatedOn(Yang) =                     SID_VCH_CREATED_ON,
    VchDomainCertRevocationChecks(Yang) =    SID_VCH_DOMAIN_CERT_REVOCATION_CHECKS,
    VchExpiresOn(Yang) =                     SID_VCH_EXPIRES_ON,
    VchIdevidIssuer(Yang) =                  SID_VCH_IDEVID_ISSUER,
    VchLastRenewalDate(Yang) =               SID_VCH_LAST_RENEWAL_DATE,
    VchNonce(Yang) =                         SID_VCH_NONCE,
    VchPinnedDomainCert(Yang) =              SID_VCH_PINNED_DOMAIN_CERT,
    VchPinnedDomainPubk(Yang) =              SID_VCH_PINNED_DOMAIN_PUBK,
    VchPinnedDomainPubkSha256(Yang) =        SID_VCH_PINNED_DOMAIN_PUBK_SHA256,
    VchSerialNumber(Yang) =                  SID_VCH_SERIAL_NUMBER,
    VrqTopLevel(TopLevel) =                  SID_VRQ_TOP_LEVEL,
    VrqAssertion(Yang) =                     SID_VRQ_ASSERTION,
    VrqCreatedOn(Yang) =                     SID_VRQ_CREATED_ON,
    VrqDomainCertRevocationChecks(Yang) =    SID_VRQ_DOMAIN_CERT_REVOCATION_CHECKS,
    VrqExpiresOn(Yang) =                     SID_VRQ_EXPIRES_ON,
    VrqIdevidIssuer(Yang) =                  SID_VRQ_IDEVID_ISSUER,
    VrqLastRenewalDate(Yang) =               SID_VRQ_LAST_RENEWAL_DATE,
    VrqNonce(Yang) =                         SID_VRQ_NONCE,
    VrqPinnedDomainCert(Yang) =              SID_VRQ_PINNED_DOMAIN_CERT,
    VrqPriorSignedVoucherRequest(Yang) =     SID_VRQ_PRIOR_SIGNED_VOUCHER_REQUEST,
    VrqProximityRegistrarCert(Yang) =        SID_VRQ_PROXIMITY_REGISTRAR_CERT,
    VrqProximityRegistrarPubk(Yang) =        SID_VRQ_PROXIMITY_REGISTRAR_PUBK,
    VrqProximityRegistrarPubkSha256(Yang) =  SID_VRQ_PROXIMITY_REGISTRAR_PUBK_SHA256,
    VrqSerialNumber(Yang) =                  SID_VRQ_SERIAL_NUMBER,
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
        self.disc().cmp(&other.disc())
    }
}

impl PartialOrd for Sid {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Sid {
    fn eq(&self, other: &Self) -> bool {
        self.disc() == other.disc()
    }
}

impl Sid {
    pub fn disc(&self) -> SidDisc {
        core::intrinsics::discriminant_value(self)
    }
}

impl Cbor for Sid {
    fn to_cbor(&self) -> Option<CborType> {
        use Sid::*;
        use yang::*;

        let yang_to_cbor =
            |yg: &Yang, ygd| if yg.disc() == ygd { yg.to_cbor() } else { None };

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

#[test]
fn test_sid_vch_f2_00_02() {
    use crate::{vec, attr::{Attr, Assertion}};

    assert_eq!(Sid::VchTopLevel(TopLevel::VoucherVoucher).disc(), SID_VCH_TOP_LEVEL);
    assert_eq!(Sid::VchAssertion(Yang::Enumeration(Attr::Assertion(Assertion::Logged))).disc(), SID_VCH_ASSERTION);
    assert_eq!(Sid::VchCreatedOn(Yang::DateAndTime(Attr::CreatedOn(1599525239))).disc(), SID_VCH_CREATED_ON);
    assert_eq!(Sid::VchNonce(Yang::Binary(Attr::Nonce(vec![88, 83, 121, 70, 52, 76, 76, 73, 105, 113, 85, 50, 45, 79, 71, 107, 54, 108, 70, 67, 65, 103])))
                   .disc(), SID_VCH_NONCE);
    assert_eq!(Sid::VchPinnedDomainCert(Yang::Binary(Attr::PinnedDomainCert("MIIB0TCCAVagAwIBAgIBAjAKBggqhkjOPQQDAzBxMRIwEAYKCZImiZPyLGQBGRYCY2ExGTAXBgoJkiaJk/IsZAEZFglzYW5kZWxtYW4xQDA+BgNVBAMMNyM8U3lzdGVtVmFyaWFibGU6MHgwMDAwMDAwNGY5MTFhMD4gVW5zdHJ1bmcgRm91bnRhaW4gQ0EwHhcNMTcxMTA3MjM0NTI4WhcNMTkxMTA3MjM0NTI4WjBDMRIwEAYKCZImiZPyLGQBGRYCY2ExGTAXBgoJkiaJk/IsZAEZFglzYW5kZWxtYW4xEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJZlUHI0up/l3eZf9vCBb+lInoEMEgc7Ro+XZCtjAI0CD1fJfJR/hIyyDmHWyYiNFbRCH9fyarfkzgX4p0zTizqjDTALMAkGA1UdEwQCMAAwCgYIKoZIzj0EAwMDaQAwZgIxALQMNurf8tv50lROD5DQXHEOJJNW3QV2g9QEdDSk2MY+AoSrBSmGSNjh4olEOhEuLgIxAJ4nWfNw+BjbZmKiIiUEcTwHMhGVXaMHY/F7n39wwKcBBSOndNPqCpOELl6bq3CZqQ=="
        .as_bytes().to_vec()))).disc(), SID_VCH_PINNED_DOMAIN_CERT);

    let serial = "00-D0-E5-F2-00-02".as_bytes();
    assert_eq!(serial, [48, 48, 45, 68, 48, 45, 69, 53, 45, 70, 50, 45, 48, 48, 45, 48, 50]);
    assert_eq!(Sid::VchSerialNumber(Yang::String(Attr::SerialNumber(serial.to_vec()))).disc(), SID_VCH_SERIAL_NUMBER);
}
/* zzz ccc
#[test]
fn test_sid_cbor_boolean() {
    use crate::{vec, attr::Attr::DomainCertRevocationChecks as Checks};

    let sid = Sid::VchDomainCertRevocationChecks(Yang::Boolean(Checks(false)));
    assert_eq!(sid.to_cbor(), Some(CborType::False));
    assert_eq!(sid.serialize(), Some(vec![244]));

    let sid = Sid::VchDomainCertRevocationChecks(Yang::Boolean(Checks(true)));
    assert_eq!(sid.to_cbor(), Some(CborType::True));
    assert_eq!(sid.serialize(), Some(vec![245]));

    let sid = Sid::VrqDomainCertRevocationChecks(Yang::Boolean(Checks(false)));
    assert_eq!(sid.to_cbor(), Some(CborType::False));
    assert_eq!(sid.serialize(), Some(vec![244]));

    let sid = Sid::VrqDomainCertRevocationChecks(Yang::Boolean(Checks(true)));
    assert_eq!(sid.to_cbor(), Some(CborType::True));
    assert_eq!(sid.serialize(), Some(vec![245]));
}
*/