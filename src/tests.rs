use crate::{Voucher, SignatureAlgorithm, Sign, Validate};

#[cfg(feature = "v3")]
pub fn init_psa_crypto() {
    use minerva_mbedtls::psa_crypto;

    psa_crypto::init().unwrap();
    psa_crypto::initialized().unwrap();
}

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

#[test]
fn test_voucher_decode_jada() {
    #[cfg(feature = "v3")]
    init_psa_crypto();

    let vch = Voucher::from(VOUCHER_JADA).unwrap();

    let (sig, alg) = vch.get_signature();
    assert_eq!(sig.len(), 64);
    assert_eq!(*alg, SignatureAlgorithm::ES256);

    assert_eq!(vch.get_signer_cert().unwrap().len(), 65);
}

#[test]
fn test_voucher_validate_jada() {
    #[cfg(feature = "v3")]
    init_psa_crypto();

    let vch = Voucher::from(VOUCHER_JADA).unwrap();

    assert!(vch.validate(None)); // Use `signer_cert` embedded in COSE unprotected
}

#[test]
fn test_voucher_serialize_jada() {
    #[cfg(feature = "v3")]
    init_psa_crypto();

    assert_eq!(
        Voucher::from(VOUCHER_JADA).unwrap().serialize().unwrap(),
        VOUCHER_JADA);
}

//

#[test]
fn test_voucher_decode_f2_00_02() {
    #[cfg(feature = "v3")]
    init_psa_crypto();

    let vch = Voucher::from(VOUCHER_F2_00_02).unwrap();

    let (sig, alg) = vch.get_signature();
    assert_eq!(sig.len(), 64);
    assert_eq!(*alg, SignatureAlgorithm::ES256);

    assert_eq!(vch.get_signer_cert(), None);
}

#[test]
fn test_voucher_validate_f2_00_02() {
    #[cfg(feature = "v3")]
    init_psa_crypto();

    let vch = Voucher::from(VOUCHER_F2_00_02).unwrap();

    let masa_pem = MASA_CRT_F2_00_02;
    assert_eq!(masa_pem.len(), 684);

    assert!(vch.validate(Some(masa_pem)));
}

#[test]
fn test_voucher_serialize_f2_00_02() {
    #[cfg(feature = "v3")]
    init_psa_crypto();

    assert_eq!(
        Voucher::from(VOUCHER_F2_00_02).unwrap().serialize().unwrap(),
        VOUCHER_F2_00_02);
}

//



//

fn misc() {
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
