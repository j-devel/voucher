use crate::{println, Box, string::String, Vec};
use super::sid_data::{CborType, Cbor};
use core::convert::TryFrom;

pub type YangDisc = u8;
pub const YANG_DISC_DATE_AND_TIME: YangDisc = 0; // 'yang:date-and-time'
pub const YANG_DISC_STRING: YangDisc =        1; // 'string'
pub const YANG_DISC_BINARY: YangDisc =        2; // 'binary'
pub const YANG_DISC_BOOLEAN: YangDisc =       3; // 'boolean'
pub const YANG_DISC_ENUMERATION: YangDisc =   4; // 'enumeration'

#[repr(u8)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Yang {
    DateAndTime(u64) =      YANG_DISC_DATE_AND_TIME,
    String(String) =        YANG_DISC_STRING,
    Binary(Vec<u8>) =       YANG_DISC_BINARY,
    Boolean(bool) =         YANG_DISC_BOOLEAN,
    Enumeration(YangEnum) = YANG_DISC_ENUMERATION,
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

const CBOR_TAG_UNIX_TIME: u64 = 0x01;

impl TryFrom<(&CborType, YangDisc)> for Yang {
    type Error = ();

    fn try_from(input: (&CborType, YangDisc)) -> Result<Self, Self::Error> {
        use CborType::*;

        match input {
            (Tag(tag, bx), YANG_DISC_DATE_AND_TIME) => {
                assert_eq!(*tag, CBOR_TAG_UNIX_TIME); // !!
                if let Integer(dat) = **bx { Ok(Yang::DateAndTime(dat)) } else { Err(()) }
            },
            (Bytes(x), YANG_DISC_STRING) => {
                // !!!! check; not observing this arm in voucher samples??!!

                use crate::std::string::ToString; // !!!!
                // !!!! fixme; adapt `no_std` cases
                Ok(Yang::String(crate::String::from_utf8_lossy(x).to_string())) // !!!!
            },
            (StringAsBytes(x), YANG_DISC_BINARY) => {
                Ok(Yang::Binary(x.to_vec()))
            },
            (True, YANG_DISC_BOOLEAN) => {
                Ok(Yang::Boolean(true))
            },
            (False, YANG_DISC_BOOLEAN) => {
                Ok(Yang::Boolean(false))
            },
            (StringAsBytes(x), YANG_DISC_ENUMERATION) => {
                let cands = [YangEnum::Verified, YangEnum::Logged, YangEnum::Proximity];
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

impl Cbor for Yang {
    fn to_cbor(&self) -> Option<CborType> {
        use CborType::*;

        let cbor = match self {
            Yang::DateAndTime(x) => Tag(CBOR_TAG_UNIX_TIME, Box::new(Integer(*x))),
            Yang::String(x) => Bytes(x.as_bytes().to_vec()),
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
    assert_eq!(Yang::try_from((cbor, YANG_DISC_DATE_AND_TIME)), Ok(Yang::DateAndTime(42)));

    let result: Result<Yang, ()> = (cbor, YANG_DISC_DATE_AND_TIME).try_into();
    assert_eq!(result, Ok(Yang::DateAndTime(42)));

    // TODO tests for other Yang variants
}
