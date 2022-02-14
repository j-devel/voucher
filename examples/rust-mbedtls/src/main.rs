mod custom_voucher;
mod support_rand;
mod utils;

use custom_voucher::{CustomVoucher as Voucher, *};
use std::convert::TryFrom;

fn main() -> Result<(), VoucherError> {
    static VCH_JADA: &[u8] = core::include_bytes!(
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../data/jada/voucher_jada123456789.vch"));
    static VCH_F2_00_02: &[u8] = core::include_bytes!(
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../data/00-D0-E5-F2-00-02/voucher_00-D0-E5-F2-00-02.vch"));
    static MASA_CRT_F2_00_02: &[u8] = core::include_bytes!(
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../data/00-D0-E5-F2-00-02/masa.crt"));
    static DEVICE_CRT_F2_00_02: &[u8] = core::include_bytes!(
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../data/00-D0-E5-F2-00-02/device.crt"));
    static KEY_PEM_F2_00_02: &[u8] = core::include_bytes!(
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../data/00-D0-E5-F2-00-02/key.pem"));

    assert!(Voucher::try_from(VCH_JADA)?
        .validate(None)
        .is_ok());

    assert!(Voucher::try_from(VCH_F2_00_02)?
        .validate(Some(MASA_CRT_F2_00_02))
        .is_ok());

    // Create, sign, serialize, and validate a new voucher request.

    let cbor = Voucher::new_vrq()
        .set(Attr::Assertion(Assertion::Proximity))
        .set(Attr::SerialNumber(b"00-D0-E5-F2-00-02".to_vec()))
        .sign(KEY_PEM_F2_00_02, SignatureAlgorithm::ES256)?
        .serialize()?;

    assert!(Voucher::try_from(cbor.as_slice())?
        .validate(Some(DEVICE_CRT_F2_00_02))
        .is_ok());

    Ok(())
}