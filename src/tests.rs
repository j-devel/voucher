use crate::{Voucher, SignatureAlgorithm, Sign, Validate};

#[cfg(feature = "v3")]
fn init_psa_crypto() {
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

use core::convert::{TryFrom, TryInto};

#[test]
fn test_voucher_conversion() {
    assert!(Voucher::try_from(VOUCHER_JADA).is_ok());

    let dummy: &[u8] = &[0, 1, 2];
    assert!(Voucher::try_from(dummy).is_err());

    let result: Result<Voucher, &str> = VOUCHER_JADA.try_into();
    assert!(result.is_ok());

    let result: Result<Voucher, &str> = dummy.try_into();
    assert!(result.is_err());
}

#[test]
fn test_voucher_decode_jada() {
    #[cfg(feature = "v3")]
    init_psa_crypto();

    let vch = Voucher::try_from(VOUCHER_JADA).unwrap();

    let (sig, alg) = vch.get_signature();
    assert_eq!(sig.len(), 64);
    assert_eq!(*alg, SignatureAlgorithm::ES256);

    assert_eq!(vch.get_signer_cert().unwrap().len(), 65);
}

#[test]
fn test_voucher_validate_jada() {
    #[cfg(feature = "v3")]
    init_psa_crypto();

    let vch = Voucher::try_from(VOUCHER_JADA).unwrap();

    assert!(vch.validate(None)); // Use `signer_cert` embedded in COSE unprotected
}

#[test]
fn test_voucher_serialize_jada() {
    #[cfg(feature = "v3")]
    init_psa_crypto();

    assert_eq!(
        Voucher::try_from(VOUCHER_JADA).unwrap().serialize().unwrap(),
        VOUCHER_JADA);
}

//

#[test]
fn test_voucher_decode_f2_00_02() {
    #[cfg(feature = "v3")]
    init_psa_crypto();

    let vch = Voucher::try_from(VOUCHER_F2_00_02).unwrap();

    let (sig, alg) = vch.get_signature();
    assert_eq!(sig.len(), 64);
    assert_eq!(*alg, SignatureAlgorithm::ES256);

    assert_eq!(vch.get_signer_cert(), None);
}

#[test]
fn test_voucher_validate_f2_00_02() {
    #[cfg(feature = "v3")]
    init_psa_crypto();

    let vch = Voucher::try_from(VOUCHER_F2_00_02).unwrap();

    let masa_pem = MASA_CRT_F2_00_02;
    assert_eq!(masa_pem.len(), 684);

    assert!(vch.validate(Some(masa_pem)));
}

#[test]
fn test_voucher_serialize_f2_00_02() {
    #[cfg(feature = "v3")]
    init_psa_crypto();

    assert_eq!(
        Voucher::try_from(VOUCHER_F2_00_02).unwrap().serialize().unwrap(),
        VOUCHER_F2_00_02);
}

//

#[test]
fn test_pledge_vr_sign_02_00_2e() {
    #[cfg(feature = "v3")]
    init_psa_crypto();

    let content = &crate::debug_vrhash_sidhash_content_02_00_2e(); // WIP !!

    let mut vch = Voucher::new();
    vch.set_content_debug(content);

    assert!(! vch.validate(Some(DEVICE_CRT_02_00_2E))); // "validating an unsigned voucher" should fail

    vch.sign(KEY_PEM_02_00_2E, SignatureAlgorithm::ES256);

    let (sig, ty) = vch.get_signature();
    assert_eq!(sig, /* asn1 */ [48, 70, 2, 33, 0, 226, 133, 204, 212, 146, 54, 173, 224, 191, 137, 104, 146, 5, 43, 216, 61, 167, 219, 192, 125, 138, 167, 160, 145, 26, 197, 52, 17, 94, 97, 210, 115, 2, 33, 0, 149, 230, 42, 127, 120, 31, 10, 28, 154, 2, 82, 16, 154, 165, 201, 129, 133, 192, 49, 15, 44, 159, 165, 129, 124, 210, 216, 67, 144, 174, 77, 107]);
    assert_eq!(ty, &SignatureAlgorithm::ES256);

    assert!(vch.validate(Some(DEVICE_CRT_02_00_2E))); // via public key
    assert!(vch.validate(Some(KEY_PEM_02_00_2E))); // via private key

    // #[cfg(feature = "std")]
    // assert!(std::panic::catch_unwind(|| { // dev !!
    //     panic!();
    // }).is_err());
}

// The COSE bytes generated by pure Ruby `test_vr_cose` via 'minerva_xstd.rb' (as of 5ca0d394)
static VR_COSE_BYTES: &[u8] = &[210, 132, 65, 160, 160, 88, 68, 161, 26, 0, 15, 70, 194, 164, 1, 105, 112, 114, 111, 120, 105, 109, 105, 116, 121, 2, 193, 26, 97, 119, 115, 164, 10, 81, 48, 48, 45, 68, 48, 45, 69, 53, 45, 48, 50, 45, 48, 48, 45, 50, 69, 7, 118, 114, 72, 103, 99, 66, 86, 78, 86, 97, 70, 109, 66, 87, 98, 84, 77, 109, 101, 79, 75, 117, 103, 88, 64, 213, 235, 111, 50, 190, 110, 39, 125, 24, 10, 108, 112, 208, 115, 138, 149, 12, 183, 237, 34, 220, 209, 168, 239, 185, 5, 170, 145, 221, 42, 135, 70, 13, 231, 183, 48, 88, 32, 174, 78, 146, 46, 72, 206, 11, 103, 80, 17, 80, 62, 17, 101, 155, 78, 7, 1, 87, 177, 172, 192, 118, 31, 116, 214];

#[test]
fn test_pledge_vr_validate_02_00_2e() {
    #[cfg(feature = "v3")]
    init_psa_crypto();

    assert!(Voucher::try_from(VR_COSE_BYTES)
        .unwrap()
        .validate(Some(DEVICE_CRT_02_00_2E)));
}

#[test]
fn test_pledge_vr_serialize_02_00_2e() {
    #[cfg(feature = "v3")]
    init_psa_crypto();

    let vch = Voucher::try_from(VR_COSE_BYTES).unwrap();
    assert_eq!(vch.get_content_debug().unwrap(), [161, 26, 0, 15, 70, 194, 164, 1, 105, 112, 114, 111, 120, 105, 109, 105, 116, 121, 2, 193, 26, 97, 119, 115, 164, 10, 81, 48, 48, 45, 68, 48, 45, 69, 53, 45, 48, 50, 45, 48, 48, 45, 50, 69, 7, 118, 114, 72, 103, 99, 66, 86, 78, 86, 97, 70, 109, 66, 87, 98, 84, 77, 109, 101, 79, 75, 117, 103]);
    assert_eq!(vch.get_signature().0, [213, 235, 111, 50, 190, 110, 39, 125, 24, 10, 108, 112, 208, 115, 138, 149, 12, 183, 237, 34, 220, 209, 168, 239, 185, 5, 170, 145, 221, 42, 135, 70, 13, 231, 183, 48, 88, 32, 174, 78, 146, 46, 72, 206, 11, 103, 80, 17, 80, 62, 17, 101, 155, 78, 7, 1, 87, 177, 172, 192, 118, 31, 116, 214]);

    assert_eq!(vch.serialize().unwrap(), VR_COSE_BYTES);
}

//

use crate::{println, vec, Vec};

fn misc() {
    let v = vec![0, 1, 2];
    println!("v: {:?}", v);
    assert_eq!(v, Vec::from([0, 1, 2]));
}

#[test]
fn test_misc() {
    misc();
}
