mod custom_voucher;
mod utils;

use custom_voucher::{CustomVoucher as Voucher, VoucherError, Validate};
use std::convert::TryFrom;

fn main() -> Result<(), VoucherError> {
    static VCH_JADA: &[u8] = core::include_bytes!(
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../data/jada/voucher_jada123456789.vch"));
    static VCH_F2_00_02: &[u8] = core::include_bytes!(
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../data/00-D0-E5-F2-00-02/voucher_00-D0-E5-F2-00-02.vch"));
    static MASA_CRT_F2_00_02: &[u8] = core::include_bytes!(
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../data/00-D0-E5-F2-00-02/masa.crt"));

    assert!(Voucher::try_from(VCH_JADA)?.validate(None).is_ok());

    let vch = Voucher::try_from(VCH_F2_00_02)?;
    assert_eq!(vch.len(), 5);
    assert!(vch.validate(Some(MASA_CRT_F2_00_02)).is_ok());

    Ok(())
}