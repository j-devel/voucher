use crate::Vec;
use super::sid::{self, Sid, SidDisc};
use super::yang::{Yang, YangEnum};
use core::convert::TryFrom;


pub type AttrDisc = u8;
pub const ATTR_ASSERTION: AttrDisc =                         0x00;
pub const ATTR_CREATED_ON: AttrDisc =                        0x01;
pub const ATTR_DOMAIN_CERT_REVOCATION_CHECKS: AttrDisc =     0x02;
pub const ATTR_EXPIRES_ON: AttrDisc =                        0x03;
pub const ATTR_IDEVID_ISSUER: AttrDisc =                     0x04;
pub const ATTR_LAST_RENEWAL_DATE: AttrDisc =                 0x05;
pub const ATTR_NONCE: AttrDisc =                             0x06;
pub const ATTR_PINNED_DOMAIN_CERT: AttrDisc =                0x07;
pub const ATTR_PINNED_DOMAIN_PUBK: AttrDisc =                0x20; // vch only
pub const ATTR_PINNED_DOMAIN_PUBK_SHA256: AttrDisc =         0x21; // vch only
pub const ATTR_PRIOR_SIGNED_VOUCHER_REQUEST: AttrDisc =      0x40; // vrq only
pub const ATTR_PROXIMITY_REGISTRAR_CERT: AttrDisc =          0x41; // vrq only
pub const ATTR_PROXIMITY_REGISTRAR_PUBK: AttrDisc =          0x42; // vrq only
pub const ATTR_PROXIMITY_REGISTRAR_PUBK_SHA256: AttrDisc =   0x43; // vrq only
pub const ATTR_SERIAL_NUMBER: AttrDisc =                     0x08;

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum Assertion {
    Verified,
    Logged,
    Proximity,
}

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
    SerialNumber(Vec<u8>) =                  ATTR_SERIAL_NUMBER,
}

impl TryFrom<&Sid> for Attr {
    type Error = ();

    fn try_from(sid: &Sid) -> Result<Self, Self::Error> {
        use Sid::*;


        let info = Self::resolve_sid(sid);
        if info.is_none() { return Err(()) }
        let (adisc, yg) = info.unwrap();

        let _: Result<Self, Self::Error> = match adisc {
            ATTR_CREATED_ON => Ok(Attr::CreatedOn(yg.to_dat().unwrap())),
            // !!!!!!!! ....
            _ => Err(()),
        };
        //====
        match sid {
            VchTopLevel(_) | VrqTopLevel(_) => Err(()),
            VchAssertion(yg) | VrqAssertion(yg) => match yg {
                Yang::Enumeration(YangEnum::Verified) => Ok(Attr::Assertion(Assertion::Verified)),
                Yang::Enumeration(YangEnum::Logged) => Ok(Attr::Assertion(Assertion::Logged)),
                Yang::Enumeration(YangEnum::Proximity) => Ok(Attr::Assertion(Assertion::Proximity)),
                _ => Err(()),
            },
            VchCreatedOn(yg) | VrqCreatedOn(yg) =>
                Ok(Attr::CreatedOn(yg.to_dat().unwrap())),
            VchDomainCertRevocationChecks(yg) | VrqDomainCertRevocationChecks(yg) =>
                Ok(Attr::DomainCertRevocationChecks(yg.to_boolean().unwrap())),
            VchExpiresOn(yg) | VrqExpiresOn(yg) =>
                Ok(Attr::ExpiresOn(yg.to_dat().unwrap())),
            VchIdevidIssuer(yg) | VrqIdevidIssuer(yg) =>
                Ok(Attr::IdevidIssuer(yg.to_binary().unwrap())),
            VchLastRenewalDate(yg) | VrqLastRenewalDate(yg) =>
                Ok(Attr::LastRenewalDate(yg.to_dat().unwrap())),
            VchNonce(yg) | VrqNonce(yg) =>
                Ok(Attr::Nonce(yg.to_binary().unwrap())),
            VchPinnedDomainCert(yg) | VrqPinnedDomainCert(yg) =>
                Ok(Attr::PinnedDomainCert(yg.to_binary().unwrap())),
            VchPinnedDomainPubk(yg) =>
                Ok(Attr::PinnedDomainPubk(yg.to_binary().unwrap())),
            VchPinnedDomainPubkSha256(yg) =>
                Ok(Attr::PinnedDomainPubkSha256(yg.to_binary().unwrap())),
            VrqPriorSignedVoucherRequest(yg) =>
                Ok(Attr::PriorSignedVoucherRequest(yg.to_binary().unwrap())),
            VrqProximityRegistrarCert(yg) =>
                Ok(Attr::ProximityRegistrarCert(yg.to_binary().unwrap())),
            VrqProximityRegistrarPubk(yg) =>
                Ok(Attr::ProximityRegistrarPubk(yg.to_binary().unwrap())),
            VrqProximityRegistrarPubkSha256(yg) =>
                Ok(Attr::ProximityRegistrarPubkSha256(yg.to_binary().unwrap())),
            VchSerialNumber(yg) | VrqSerialNumber(yg) =>
                Ok(Attr::SerialNumber(yg.to_string().unwrap())),
        }
    }
}

impl Attr {
    pub fn into_yang(self) -> Yang {
        match self {
            Attr::Assertion(x) => match x {
                Assertion::Verified => Yang::Enumeration(YangEnum::Verified),
                Assertion::Logged => Yang::Enumeration(YangEnum::Logged),
                Assertion::Proximity => Yang::Enumeration(YangEnum::Proximity),
            },
            Attr::DomainCertRevocationChecks(x) => Yang::Boolean(x),
            Attr::CreatedOn(x) |
            Attr::ExpiresOn(x) |
            Attr::LastRenewalDate(x) => Yang::DateAndTime(x),
            Attr::IdevidIssuer(x) |
            Attr::Nonce(x) |
            Attr::PinnedDomainCert(x) |
            Attr::PinnedDomainPubk(x) |
            Attr::PinnedDomainPubkSha256(x) |
            Attr::PriorSignedVoucherRequest(x) |
            Attr::ProximityRegistrarCert(x) |
            Attr::ProximityRegistrarPubk(x) |
            Attr::ProximityRegistrarPubkSha256(x) => Yang::Binary(x),
            Attr::SerialNumber(x) => Yang::String(x),
        }
    }

    pub fn resolve_sid(sid: &Sid) -> Option<(AttrDisc, &Yang)> {
        use Sid::*;

        match sid {
            VchTopLevel(_) | VrqTopLevel(_) => None,
            //....
            VchCreatedOn(yg) | VrqCreatedOn(yg) => Some((ATTR_CREATED_ON, yg)),
            // !!!!!!!!!!! todo
            _ => None,
        }
    }

    pub fn to_sid_disc(adisc: AttrDisc, is_vrq: bool) -> Option<SidDisc> {
        use sid::*;

        let sdisc_none: SidDisc = 0;
        let sdisc = match adisc {
            ATTR_ASSERTION => if is_vrq { SID_VRQ_ASSERTION } else { SID_VCH_ASSERTION },
            ATTR_CREATED_ON => if is_vrq { SID_VRQ_CREATED_ON } else { SID_VCH_CREATED_ON },
            ATTR_DOMAIN_CERT_REVOCATION_CHECKS => if is_vrq { SID_VRQ_DOMAIN_CERT_REVOCATION_CHECKS } else { SID_VCH_DOMAIN_CERT_REVOCATION_CHECKS },
            ATTR_EXPIRES_ON => if is_vrq { SID_VRQ_EXPIRES_ON } else { SID_VCH_EXPIRES_ON },
            ATTR_IDEVID_ISSUER => if is_vrq { SID_VRQ_IDEVID_ISSUER } else { SID_VCH_IDEVID_ISSUER },
            ATTR_LAST_RENEWAL_DATE => if is_vrq { SID_VRQ_LAST_RENEWAL_DATE } else { SID_VCH_LAST_RENEWAL_DATE },
            ATTR_NONCE => if is_vrq { SID_VRQ_NONCE } else { SID_VCH_NONCE },
            ATTR_PINNED_DOMAIN_CERT => if is_vrq { SID_VRQ_PINNED_DOMAIN_CERT } else { SID_VCH_PINNED_DOMAIN_CERT },
            ATTR_PINNED_DOMAIN_PUBK => if is_vrq { sdisc_none } else { SID_VCH_PINNED_DOMAIN_PUBK },
            ATTR_PINNED_DOMAIN_PUBK_SHA256 => if is_vrq { sdisc_none } else { SID_VCH_PINNED_DOMAIN_PUBK_SHA256 },
            ATTR_PRIOR_SIGNED_VOUCHER_REQUEST => if is_vrq { SID_VRQ_PRIOR_SIGNED_VOUCHER_REQUEST } else { sdisc_none },
            ATTR_PROXIMITY_REGISTRAR_CERT => if is_vrq { SID_VRQ_PROXIMITY_REGISTRAR_CERT } else { sdisc_none },
            ATTR_PROXIMITY_REGISTRAR_PUBK => if is_vrq { SID_VRQ_PROXIMITY_REGISTRAR_PUBK } else { sdisc_none },
            ATTR_PROXIMITY_REGISTRAR_PUBK_SHA256 => if is_vrq { SID_VRQ_PROXIMITY_REGISTRAR_PUBK_SHA256 } else { sdisc_none },
            ATTR_SERIAL_NUMBER => if is_vrq { SID_VRQ_SERIAL_NUMBER } else { SID_VCH_SERIAL_NUMBER },
            _ => sdisc_none,
        };

        if sdisc == sdisc_none { None } else { Some(sdisc) }
    }
}
