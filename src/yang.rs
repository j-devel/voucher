use crate::{Box, Vec};
use super::sid::{self, CborType, Cbor, SidDisc};
use core::convert::TryFrom;

use super::attr::{self, Attr};

pub type YangDisc = u8;
pub const YANG_DATE_AND_TIME: YangDisc =  0x00; // 'yang:date-and-time'
pub const YANG_STRING: YangDisc =         0x01; // 'string'
pub const YANG_BINARY: YangDisc =         0x02; // 'binary'
pub const YANG_BOOLEAN: YangDisc =        0x03; // 'boolean'
pub const YANG_ENUMERATION: YangDisc =    0x04; // 'enumeration'

#[repr(u8)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Yang {
    DateAndTime(Attr) =  YANG_DATE_AND_TIME,
    String(Attr) =       YANG_STRING,
    Binary(Attr) =       YANG_BINARY,
    Boolean(Attr) =      YANG_BOOLEAN,
    Enumeration(Attr) =  YANG_ENUMERATION,
}

impl Yang {
    pub fn disc(&self) -> YangDisc {
        core::intrinsics::discriminant_value(self)
    }

    fn raw_enumeration(cbor: &CborType) -> Result<attr::Assertion, ()> {
        if let CborType::StringAsBytes(x) = cbor {
            for a in [
                attr::Assertion::Verified,
                attr::Assertion::Logged,
                attr::Assertion::Proximity,
            ] { if a.value().as_bytes() == x { return Ok(a); } }

            Err(())
        } else { Err(()) }
    }

    fn raw_dat(cbor: &CborType) -> Result<u64, ()> {
        if let CborType::Tag(tag, bx) = cbor {
            if *tag != CBOR_TAG_UNIX_TIME { return Err(()) }
            if let CborType::Integer(dat) = **bx { Ok(dat) } else { Err(()) }
        } else { Err(()) }
    }

    fn raw_boolean(cbor: &CborType) -> Result<bool, ()> {
        match cbor {
            CborType::True => Ok(true),
            CborType::False => Ok(false),
            _ => Err(()),
        }
    }

    fn raw_binary(cbor: &CborType) -> Result<Vec<u8>, ()> {
        if let CborType::Bytes(x) | CborType::StringAsBytes(x) /* permissive */ = cbor {
            Ok(x.to_vec()) } else { Err(()) }

    }

    fn raw_string(cbor: &CborType) -> Result<Vec<u8>, ()> {
        if let CborType::StringAsBytes(x) | CborType::Bytes(x) /* permissive */ = cbor {
            Ok(x.to_vec()) } else { Err(()) }
    }
}

const CBOR_TAG_UNIX_TIME: u64 = 0x01;

impl Cbor for Yang {
    fn to_cbor(&self) -> Option<CborType> {
        use CborType::*;

        match self {
            Yang::DateAndTime(attr) => match attr {
                Attr::CreatedOn(x) |
                Attr::ExpiresOn(x) |
                Attr::LastRenewalDate(x) => Some(Tag(CBOR_TAG_UNIX_TIME, Box::new(Integer(*x)))),
                _ => unreachable!(),
            },
            Yang::String(attr) => if let Attr::SerialNumber(x) = attr {
                Some(StringAsBytes(x.clone())) } else { unreachable!() },
            Yang::Binary(attr) => match attr {
                Attr::IdevidIssuer(x) |
                Attr::Nonce(x) |
                Attr::PinnedDomainCert(x) |
                Attr::PinnedDomainPubk(x) |
                Attr::PinnedDomainPubkSha256(x) |
                Attr::PriorSignedVoucherRequest(x) |
                Attr::ProximityRegistrarCert(x) |
                Attr::ProximityRegistrarPubk(x) |
                Attr::ProximityRegistrarPubkSha256(x) => Some(Bytes(x.clone())),
                _ => unreachable!(),
            },
            Yang::Boolean(attr) => if let Attr::DomainCertRevocationChecks(x) = attr {
                Some(if *x { True } else { False }) } else { unreachable!() },
            Yang::Enumeration(attr) => if let Attr::Assertion(x) = attr {
                Some(StringAsBytes(x.value().as_bytes().to_vec())) } else { unreachable!() },
        }
    }
}

impl TryFrom<(&CborType, SidDisc)> for Yang {
    type Error = ();

    fn try_from(input: (&CborType, SidDisc)) -> Result<Self, Self::Error> {
        use sid::*;

        let (cbor, sid_disc) = input;
        let yg = match sid_disc {
            SID_VCH_ASSERTION | SID_VRQ_ASSERTION =>
                Self::Enumeration(Attr::Assertion(Self::raw_enumeration(cbor)?)),
            SID_VCH_CREATED_ON | SID_VRQ_CREATED_ON =>
                Self::DateAndTime(Attr::CreatedOn(Self::raw_dat(cbor)?)),
            SID_VCH_DOMAIN_CERT_REVOCATION_CHECKS | SID_VRQ_DOMAIN_CERT_REVOCATION_CHECKS =>
                Self::Boolean(Attr::DomainCertRevocationChecks(Self::raw_boolean(cbor)?)),
            SID_VCH_EXPIRES_ON | SID_VRQ_EXPIRES_ON =>
                Self::DateAndTime(Attr::ExpiresOn(Self::raw_dat(cbor)?)),
            SID_VCH_IDEVID_ISSUER | SID_VRQ_IDEVID_ISSUER =>
                Self::Binary(Attr::IdevidIssuer(Self::raw_binary(cbor)?)),
            SID_VCH_LAST_RENEWAL_DATE | SID_VRQ_LAST_RENEWAL_DATE =>
                Self::DateAndTime(Attr::LastRenewalDate(Self::raw_dat(cbor)?)),
            SID_VCH_NONCE | SID_VRQ_NONCE =>
                Self::Binary(Attr::Nonce(Self::raw_binary(cbor)?)),
            SID_VCH_PINNED_DOMAIN_CERT | SID_VRQ_PINNED_DOMAIN_CERT =>
                Self::Binary(Attr::PinnedDomainCert(Self::raw_binary(cbor)?)),
            SID_VCH_PINNED_DOMAIN_PUBK =>
                Self::Binary(Attr::PinnedDomainPubk(Self::raw_binary(cbor)?)),
            SID_VCH_PINNED_DOMAIN_PUBK_SHA256 =>
                Self::Binary(Attr::PinnedDomainPubkSha256(Self::raw_binary(cbor)?)),
            SID_VRQ_PRIOR_SIGNED_VOUCHER_REQUEST =>
                Self::Binary(Attr::PriorSignedVoucherRequest(Self::raw_binary(cbor)?)),
            SID_VRQ_PROXIMITY_REGISTRAR_CERT =>
                Self::Binary(Attr::ProximityRegistrarCert(Self::raw_binary(cbor)?)),
            SID_VRQ_PROXIMITY_REGISTRAR_PUBK =>
                Self::Binary(Attr::ProximityRegistrarPubk(Self::raw_binary(cbor)?)),
            SID_VRQ_PROXIMITY_REGISTRAR_PUBK_SHA256 =>
                Self::Binary(Attr::ProximityRegistrarPubkSha256(Self::raw_binary(cbor)?)),
            SID_VCH_SERIAL_NUMBER | SID_VRQ_SERIAL_NUMBER =>
                Self::Binary(Attr::SerialNumber(Self::raw_string(cbor)?)),
            _ => unreachable!(),
        };

        Ok(yg)
    }
}
