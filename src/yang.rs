use crate::{Box, Vec};
use super::sid_data::{CborType, Cbor, SidDisc};
use core::convert::TryFrom;

pub type YangDisc = u8;
pub const YANG_DATE_AND_TIME: YangDisc = 0; // 'yang:date-and-time'
pub const YANG_STRING: YangDisc =        1; // 'string'
pub const YANG_BINARY: YangDisc =        2; // 'binary'
pub const YANG_BOOLEAN: YangDisc =       3; // 'boolean'
pub const YANG_ENUMERATION: YangDisc =   4; // 'enumeration'

#[repr(u8)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Yang {
    DateAndTime(u64) =      YANG_DATE_AND_TIME,
    String(Vec<u8>) =       YANG_STRING,
    Binary(Vec<u8>) =       YANG_BINARY,
    Boolean(bool) =         YANG_BOOLEAN,
    Enumeration(YangEnum) = YANG_ENUMERATION,
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

const CBOR_TAG_UNIX_TIME: u64 = 0x01;

impl TryFrom<(&CborType, YangDisc)> for Yang {
    type Error = ();

    fn try_from(input: (&CborType, YangDisc)) -> Result<Self, Self::Error> {
        use CborType::*;

        match input {
            (Tag(tag, bx), YANG_DATE_AND_TIME) => {
                assert_eq!(*tag, CBOR_TAG_UNIX_TIME); // !!
                if let Integer(dat) = **bx { Ok(Yang::DateAndTime(dat)) } else { Err(()) }
            },
            (Bytes(x), YANG_STRING) |          // vrq samples {Rust,Ruby}-generated
            (StringAsBytes(x), YANG_STRING) => // vch samples (old?)
                Ok(Yang::String(x.to_vec())),
            (StringAsBytes(x), YANG_BINARY) => Ok(Yang::Binary(x.to_vec())),
            (True, YANG_BOOLEAN) => Ok(Yang::Boolean(true)),
            (False, YANG_BOOLEAN) => Ok(Yang::Boolean(false)),
            (StringAsBytes(x), YANG_ENUMERATION) => {
                let cands = [
                    YangEnum::Verified,
                    YangEnum::Logged,
                    YangEnum::Proximity,
                ];
                let residue: Vec<_> = cands.iter()
                    .enumerate()
                    .filter_map(|(i, ye)| if ye.value().as_bytes() == x { Some(cands[i]) } else { None })
                    .collect();
                if residue.len() == 1 { Ok(Yang::Enumeration(residue[0])) } else { Err(()) }
            },
            _ => Err(()),
        }
    }
}

impl TryFrom<(&CborType, SidDisc)> for Yang {
    type Error = ();

    fn try_from(input: (&CborType, SidDisc)) -> Result<Self, Self::Error> {
        use super::sid_data::*;

        let (cbor, sid_disc) = input;
        match sid_disc {
            SID_VCH_ASSERTION |
            SID_VRQ_ASSERTION =>
                Yang::try_from((cbor, YANG_ENUMERATION)),
            SID_VCH_DOMAIN_CERT_REVOCATION_CHECKS |
            SID_VRQ_DOMAIN_CERT_REVOCATION_CHECKS =>
                Yang::try_from((cbor, YANG_BOOLEAN)),
            SID_VCH_CREATED_ON |
            SID_VCH_EXPIRES_ON |
            SID_VCH_LAST_RENEWAL_DATE |
            SID_VRQ_CREATED_ON |
            SID_VRQ_EXPIRES_ON |
            SID_VRQ_LAST_RENEWAL_DATE =>
                Yang::try_from((cbor, YANG_DATE_AND_TIME)),
            SID_VCH_IDEVID_ISSUER |
            SID_VCH_NONCE |
            SID_VCH_PINNED_DOMAIN_CERT |
            SID_VCH_PINNED_DOMAIN_PUBK |
            SID_VCH_PINNED_DOMAIN_PUBK_SHA256 |
            SID_VRQ_IDEVID_ISSUER |
            SID_VRQ_NONCE |
            SID_VRQ_PINNED_DOMAIN_CERT |
            SID_VRQ_PRIOR_SIGNED_VOUCHER_REQUEST |
            SID_VRQ_PROXIMITY_REGISTRAR_CERT |
            SID_VRQ_PROXIMITY_REGISTRAR_PUBK |
            SID_VRQ_PROXIMITY_REGISTRAR_PUBK_SHA256 =>
                Yang::try_from((cbor, YANG_BINARY)),
            SID_VCH_SERIAL_NUMBER |
            SID_VRQ_SERIAL_NUMBER =>
                Yang::try_from((cbor, YANG_STRING)),
            _ => Err(()),
        }
    }
}

impl Cbor for Yang {
    fn to_cbor(&self) -> Option<CborType> {
        use CborType::*;

        let cbor = match self {
            Yang::DateAndTime(x) => Tag(CBOR_TAG_UNIX_TIME, Box::new(Integer(*x))),
            Yang::String(x) => Bytes(x.clone()),
            Yang::Binary(x) => StringAsBytes(x.clone()),
            Yang::Boolean(x) => if *x { True } else { False },
            Yang::Enumeration(x) => StringAsBytes(x.value().as_bytes().to_vec()),
        };

        Some(cbor)
    }
}

#[test]
fn test_yang_conversion() {
    use core::convert::TryInto;

    let ref cbor = CborType::Tag(CBOR_TAG_UNIX_TIME, Box::new(CborType::Integer(42)));
    assert_eq!(Yang::try_from((cbor, YANG_DATE_AND_TIME)), Ok(Yang::DateAndTime(42)));

    let result: Result<Yang, ()> = (cbor, YANG_DATE_AND_TIME).try_into();
    assert_eq!(result, Ok(Yang::DateAndTime(42)));

    // TODO tests for other YANG variants
}
