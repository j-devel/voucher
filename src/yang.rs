use crate::{println, Box, string::String, Vec};
use super::sid_data::{CborType, Cbor};
use core::convert::TryFrom;

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Yang {
    DateAndTime(u64),         // 'yang:date-and-time'
    String(String),           // 'string'
    Binary(Vec<u8>),          // 'binary'
    Boolean(bool),            // 'boolean'
    Enumeration(YangEnum),    // 'enumeration'
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
    assert_eq!(Yang::try_from(cbor), Ok(Yang::DateAndTime(42)));

    let result: Result<Yang, ()> = cbor.try_into();
    assert_eq!(result, Ok(Yang::DateAndTime(42)));

    // TODO tests for other Yang variants
}
