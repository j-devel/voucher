use crate::{println, /* Box, vec, */ Vec, BTreeMap};

//use cose::decoder::CborType;

#[derive(PartialEq)]
pub struct SidData(BTreeMap<u8, u8>); // !!!! dummy

impl SidData {
    pub fn new() -> Self { Self(BTreeMap::new()) }

    pub fn insert(&mut self, key: u8, val: u8) {
        self.0.insert(key, val);
    }

    pub fn to_cbor(&self) -> Vec<u8> {
        println!("sid data: {:?}", self.0);

        crate::debug_vrhash_sidhash_content_02_00_2e()
    }
}
