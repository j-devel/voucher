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

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum YangEnum {
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

impl TryFrom<(&CborType, SidDisc)> for Yang {
    type Error = ();

    fn try_from(input: (&CborType, SidDisc)) -> Result<Self, Self::Error> {
        use attr::*;
        use sid::*;

        let (cbor, sid_disc) = input;
        let yg = match sid_disc {
            SID_VCH_ASSERTION | SID_VRQ_ASSERTION =>
                Yang::Enumeration(Attr::try_from((cbor, ATTR_ASSERTION))?),
            SID_VCH_CREATED_ON | SID_VRQ_CREATED_ON =>
                Yang::DateAndTime(Attr::try_from((cbor, ATTR_CREATED_ON))?),
            SID_VCH_DOMAIN_CERT_REVOCATION_CHECKS | SID_VRQ_DOMAIN_CERT_REVOCATION_CHECKS =>
                Yang::Boolean(Attr::try_from((cbor, ATTR_DOMAIN_CERT_REVOCATION_CHECKS))?),
            SID_VCH_EXPIRES_ON | SID_VRQ_EXPIRES_ON =>
                Yang::DateAndTime(Attr::try_from((cbor, ATTR_EXPIRES_ON))?),
            SID_VCH_IDEVID_ISSUER | SID_VRQ_IDEVID_ISSUER =>
                Yang::Binary(Attr::try_from((cbor, ATTR_IDEVID_ISSUER))?),
            SID_VCH_LAST_RENEWAL_DATE | SID_VRQ_LAST_RENEWAL_DATE =>
                Yang::DateAndTime(Attr::try_from((cbor, ATTR_LAST_RENEWAL_DATE))?),
            SID_VCH_NONCE | SID_VRQ_NONCE =>
                Yang::Binary(Attr::try_from((cbor, ATTR_NONCE))?),
            SID_VCH_PINNED_DOMAIN_CERT | SID_VRQ_PINNED_DOMAIN_CERT =>
                Yang::Binary(Attr::try_from((cbor, ATTR_PINNED_DOMAIN_CERT))?),
            SID_VCH_PINNED_DOMAIN_PUBK =>
                Yang::Binary(Attr::try_from((cbor, ATTR_PINNED_DOMAIN_PUBK))?),
            SID_VCH_PINNED_DOMAIN_PUBK_SHA256 =>
                Yang::Binary(Attr::try_from((cbor, ATTR_PINNED_DOMAIN_PUBK_SHA256))?),
            SID_VRQ_PRIOR_SIGNED_VOUCHER_REQUEST =>
                Yang::Binary(Attr::try_from((cbor, ATTR_PRIOR_SIGNED_VOUCHER_REQUEST))?),
            SID_VRQ_PROXIMITY_REGISTRAR_CERT =>
                Yang::Binary(Attr::try_from((cbor, ATTR_PROXIMITY_REGISTRAR_CERT))?),
            SID_VRQ_PROXIMITY_REGISTRAR_PUBK =>
                Yang::Binary(Attr::try_from((cbor, ATTR_PROXIMITY_REGISTRAR_PUBK))?),
            SID_VRQ_PROXIMITY_REGISTRAR_PUBK_SHA256 =>
                Yang::Binary(Attr::try_from((cbor, ATTR_PROXIMITY_REGISTRAR_PUBK_SHA256))?),
            SID_VCH_SERIAL_NUMBER | SID_VRQ_SERIAL_NUMBER =>
                Yang::String(Attr::try_from((cbor, ATTR_SERIAL_NUMBER))?),
            _ => return Err(()),
        };

        Ok(yg)
    }
}

impl Cbor for Yang {
    fn to_cbor(&self) -> Option<CborType> {
        use CborType::*;

        let cbor = Tag(0x01, Box::new(Integer(4242))); // todo: delegate "Cbor for Attr"

        Some(cbor)
    }
}
