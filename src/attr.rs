//! Enums and constants for voucher attributes.
use crate::Vec;
use super::sid::{self, SidDisc};
use super::yang::Yang;

/// The voucher attribute enum discriminant type.
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

/// An enum identifying values of the "assertion" field defined in [RFC8995](https://datatracker.ietf.org/doc/html/rfc8995).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Assertion {
    Verified,
    Logged,
    Proximity,
}

impl Assertion {
    pub const fn value(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Logged => "logged",
            Self::Proximity => "proximity",
        }
    }
}

/// An enum identifying voucher attributes.
#[repr(u8)]
#[derive(Clone, PartialEq, Eq, Debug)]
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

impl Attr {
    pub fn disc(&self) -> AttrDisc {
        core::intrinsics::discriminant_value(self)
    }

    pub fn into_yang(self) -> Yang {
        match self {
            Attr::Assertion(_) => Yang::Enumeration(self),
            Attr::DomainCertRevocationChecks(_) => Yang::Boolean(self),
            Attr::CreatedOn(_) |
            Attr::ExpiresOn(_) |
            Attr::LastRenewalDate(_) => Yang::DateAndTime(self),
            Attr::IdevidIssuer(_) |
            Attr::Nonce(_) |
            Attr::PinnedDomainCert(_) |
            Attr::PinnedDomainPubk(_) |
            Attr::PinnedDomainPubkSha256(_) |
            Attr::PriorSignedVoucherRequest(_) |
            Attr::ProximityRegistrarCert(_) |
            Attr::ProximityRegistrarPubk(_) |
            Attr::ProximityRegistrarPubkSha256(_) => Yang::Binary(self),
            Attr::SerialNumber(_) => Yang::String(self),
        }
    }

    pub fn to_sid_disc(adisc: AttrDisc, is_vrq: bool) -> Option<SidDisc> {
        use sid::*;

        let sdisc_none = 0;
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
            _ => unreachable!(),
        };

        if sdisc == sdisc_none { None } else { Some(sdisc) }
    }
}
