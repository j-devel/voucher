use crate::{Voucher, SignatureAlgorithm, Sign, Validate};

static VOUCHER_JADA: &[u8] = core::include_bytes!(
    concat!(env!("CARGO_MANIFEST_DIR"), "/data/jada/voucher_jada123456789.vch"));

static VOUCHER_F2_00_02: &[u8] = core::include_bytes!(
    concat!(env!("CARGO_MANIFEST_DIR"), "/data/00-D0-E5-F2-00-02/voucher_00-D0-E5-F2-00-02.vch"));

static MASA_CRT_F2_00_02: &[u8] = core::include_bytes!(
    concat!(env!("CARGO_MANIFEST_DIR"), "/data/00-D0-E5-F2-00-02/masa.crt"));

static KEY_PEM_02_00_2E: &[u8] = core::include_bytes!(
    concat!(env!("CARGO_MANIFEST_DIR"), "/data/00-D0-E5-02-00-2E/key.pem"));

static DEVICE_CRT_02_00_2E: &[u8] = core::include_bytes!(
    concat!(env!("CARGO_MANIFEST_DIR"), "/data/00-D0-E5-02-00-2E/device.crt"));


//

pub fn misc() {
    #[cfg(feature = "std")]
    use std::{println, vec, vec::Vec};
    #[cfg(not(feature = "std"))]
    use mcu_if::{println, alloc::{vec, vec::Vec}};

    let v = vec![0, 1, 2];
    println!("v: {:?}", v);
    assert_eq!(v, Vec::from([0, 1, 2]));
}

#[test]
fn test_misc() {
    misc();
}
