use crate::{Vec, string::String};
use super::sid_data::{self, Sid};
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
pub const ATTR_PINNED_DOMAIN_PUBK: AttrDisc =                0x20;
pub const ATTR_PINNED_DOMAIN_PUBK_SHA256: AttrDisc =         0x21;
pub const ATTR_PRIOR_SIGNED_VOUCHER_REQUEST: AttrDisc =      0x40;
pub const ATTR_PROXIMITY_REGISTRAR_CERT: AttrDisc =          0x41;
pub const ATTR_PROXIMITY_REGISTRAR_PUBK: AttrDisc =          0x42;
pub const ATTR_PROXIMITY_REGISTRAR_PUBK_SHA256: AttrDisc =   0x43;
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
    SerialNumber(String) =                   ATTR_SERIAL_NUMBER,
}

impl TryFrom<&Sid> for Attr {
    type Error = ();

    fn try_from(sid: &Sid) -> Result<Self, Self::Error> {
        Ok(Attr::CreatedOn(43))
    }
}

pub fn attr_disc_to_sid_disc(attr_disc: AttrDisc, is_vrq: bool) -> sid_data::SidDisc {
    use sid_data::*;

    match attr_disc {
        ATTR_ASSERTION => if is_vrq { SID_VRQ_ASSERTION } else { SID_VCH_ASSERTION },
        ATTR_CREATED_ON => if is_vrq { SID_VRQ_CREATED_ON } else { SID_VCH_CREATED_ON },
        ATTR_DOMAIN_CERT_REVOCATION_CHECKS => if is_vrq { SID_VRQ_DOMAIN_CERT_REVOCATION_CHECKS } else { SID_VCH_DOMAIN_CERT_REVOCATION_CHECKS },
        ATTR_EXPIRES_ON => if is_vrq { SID_VRQ_EXPIRES_ON } else { SID_VCH_EXPIRES_ON },
        ATTR_IDEVID_ISSUER => if is_vrq { SID_VRQ_IDEVID_ISSUER } else { SID_VCH_IDEVID_ISSUER },
        ATTR_LAST_RENEWAL_DATE => if is_vrq { SID_VRQ_LAST_RENEWAL_DATE } else { SID_VCH_LAST_RENEWAL_DATE },
        ATTR_NONCE => if is_vrq { SID_VRQ_NONCE } else { SID_VCH_NONCE },
        ATTR_PINNED_DOMAIN_CERT => if is_vrq { SID_VRQ_PINNED_DOMAIN_CERT } else { SID_VCH_PINNED_DOMAIN_CERT },
        ATTR_PINNED_DOMAIN_PUBK => if is_vrq { panic!() } else { SID_VCH_PINNED_DOMAIN_PUBK },
        ATTR_PINNED_DOMAIN_PUBK_SHA256 => if is_vrq { panic!() } else { SID_VCH_PINNED_DOMAIN_PUBK_SHA256 },
        ATTR_PRIOR_SIGNED_VOUCHER_REQUEST => if is_vrq { SID_VRQ_PRIOR_SIGNED_VOUCHER_REQUEST } else { panic!() },
        ATTR_PROXIMITY_REGISTRAR_CERT => if is_vrq { SID_VRQ_PROXIMITY_REGISTRAR_CERT } else { panic!() },
        ATTR_PROXIMITY_REGISTRAR_PUBK => if is_vrq { SID_VRQ_PROXIMITY_REGISTRAR_PUBK } else { panic!() },
        ATTR_PROXIMITY_REGISTRAR_PUBK_SHA256 => if is_vrq { SID_VRQ_PROXIMITY_REGISTRAR_PUBK_SHA256 } else { panic!() },
        ATTR_SERIAL_NUMBER => if is_vrq { SID_VRQ_SERIAL_NUMBER } else { SID_VCH_SERIAL_NUMBER },
        _ => panic!(),
    }
}

pub fn attr_to_yang(attr: Attr) -> Yang {
    match attr {
        Attr::Assertion(inner) => match inner {
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
        Attr::SerialNumber(x) => Yang::String(x.as_bytes().to_vec()),
    }
}
