use crate::{println, /* Box, vec, */ Vec, BTreeSet};

//use cose::decoder::CborType;

type Sid = u8; // !!!!

#[derive(Clone, PartialEq, Debug)]
pub enum SidData {
    Voucher(BTreeSet<Sid>),
    VoucherRequest(BTreeSet<Sid>),
}

// WIP
// - getter/setter
// - top level field integrity checker
// - misc field checker
impl SidData {
    pub fn new_vch() -> Self { Self::Voucher(BTreeSet::new()) }
    pub fn new_vrq() -> Self { Self::VoucherRequest(BTreeSet::new()) }
    pub fn vch_from(set: BTreeSet<Sid>) -> Self { Self::Voucher(set) }
    pub fn vrq_from(set: BTreeSet<Sid>) -> Self { Self::VoucherRequest(set) }

    // !!!!
    pub fn to_cbor(&self) -> Vec<u8> {
        crate::debug_vrhash_sidhash_content_02_00_2e()
    }

}
