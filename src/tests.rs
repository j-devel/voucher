use crate::{*, string::String};

#[cfg(feature = "v3")]
fn init_psa_crypto() {
    use minerva_mbedtls::psa_crypto;

    psa_crypto::init().unwrap();
    psa_crypto::initialized().unwrap();
}

static VCH_JADA: &[u8] = core::include_bytes!(
    concat!(env!("CARGO_MANIFEST_DIR"), "/data/jada/voucher_jada123456789.vch"));

static VCH_F2_00_02: &[u8] = core::include_bytes!(
    concat!(env!("CARGO_MANIFEST_DIR"), "/data/00-D0-E5-F2-00-02/voucher_00-D0-E5-F2-00-02.vch"));

static VRQ_F2_00_02: &[u8] = core::include_bytes!(
    concat!(env!("CARGO_MANIFEST_DIR"), "/data/00-D0-E5-F2-00-02/vr_00-D0-E5-F2-00-02.vrq"));

static MASA_CRT_F2_00_02: &[u8] = core::include_bytes!(
    concat!(env!("CARGO_MANIFEST_DIR"), "/data/00-D0-E5-F2-00-02/masa.crt"));

// DEPRECATED !!
static KEY_PEM_02_00_2E: &[u8] = core::include_bytes!(
    concat!(env!("CARGO_MANIFEST_DIR"), "/data/00-D0-E5-02-00-2E/key.pem"));

// DEPRECATED !!
static DEVICE_CRT_02_00_2E: &[u8] = core::include_bytes!(
    concat!(env!("CARGO_MANIFEST_DIR"), "/data/00-D0-E5-02-00-2E/device.crt"));

//

use core::convert::{TryFrom, TryInto};

#[test]
fn test_voucher_conversion() {
    assert!(Voucher::try_from(VCH_JADA).is_ok());
    assert!(Voucher::try_from(VCH_F2_00_02).is_ok());
    assert!(Voucher::try_from(VRQ_F2_00_02).is_ok());

    let dummy: &[u8] = &[0, 1, 2];
    assert!(Voucher::try_from(dummy).is_err());

    let result: Result<Voucher, _> = VCH_JADA.try_into();
    assert!(result.is_ok());
    let result: Result<Voucher, _> = VCH_F2_00_02.try_into();
    assert!(result.is_ok());
    let result: Result<Voucher, _> = VRQ_F2_00_02.try_into();
    assert!(result.is_ok());

    let result: Result<Voucher, _> = dummy.try_into();
    assert!(result.is_err());
}

#[test]
fn test_decode_vch_jada() {
    #[cfg(feature = "v3")]
    init_psa_crypto();

    let vch = Voucher::try_from(VCH_JADA).unwrap();

    let (sig, alg) = vch.get_signature();
    assert_eq!(sig.len(), 64);
    assert_eq!(*alg, SignatureAlgorithm::ES256);

    assert_eq!(vch.get_signer_cert().unwrap().len(), 65);
    assert_eq!(vch.get_content_debug().unwrap(), debug::CONTENT_VCH_JADA);
}

#[test]
fn test_validate_vch_jada() {
    #[cfg(feature = "v3")]
    init_psa_crypto();

    let vch = Voucher::try_from(VCH_JADA).unwrap();

    assert!(vch.validate(None).is_ok()); // Use `signer_cert` embedded in COSE unprotected
}

#[test]
fn test_serialize_vch_jada() {
    #[cfg(feature = "v3")]
    init_psa_crypto();

    assert_eq!(
        Voucher::try_from(VCH_JADA).unwrap().serialize().unwrap(),
        VCH_JADA);
}

//

#[test]
fn test_decode_vch_f2_00_02() {
    #[cfg(feature = "v3")]
    init_psa_crypto();

    let vch = Voucher::try_from(VCH_F2_00_02).unwrap();

    let (sig, alg) = vch.get_signature();
    assert_eq!(sig.len(), 64);
    assert_eq!(*alg, SignatureAlgorithm::ES256);

    assert_eq!(vch.get_signer_cert(), None);
    assert_eq!(vch.get_content_debug().unwrap(), debug::CONTENT_VCH_F2_00_02);
}

#[test]
fn test_validate_vch_f2_00_02() {
    #[cfg(feature = "v3")]
    init_psa_crypto();

    let vch = Voucher::try_from(VCH_F2_00_02).unwrap();

    let masa_pem = MASA_CRT_F2_00_02;
    assert_eq!(masa_pem.len(), 684);

    assert!(vch.validate(Some(masa_pem)).is_ok());
}

#[test]
fn test_serialize_vch_f2_00_02() {
    #[cfg(feature = "v3")]
    init_psa_crypto();

    assert_eq!(
        Voucher::try_from(VCH_F2_00_02).unwrap().serialize().unwrap(),
        VCH_F2_00_02);
}

//

#[test]
fn test_pledge_vr_unsigned_02_00_2e() {
//fn test_unsigned_vrq_f2_00_02() { // !! TODO
    #[cfg(feature = "v3")]
    init_psa_crypto();

    let mut vrq = Voucher::new(VoucherType::Vrq);

    vrq.set_sid(Sid::VrqAssertion(Yang::Enumeration(YangEnum::Proximity)))
        .set_sid(Sid::VrqCreatedOn(Yang::DateAndTime(1635218340)))
        .set_sid(Sid::VrqNonce(Yang::Binary(vec![114, 72, 103, 99, 66, 86, 78, 86, 97, 70, 109, 66, 87, 98, 84, 77, 109, 101, 79, 75, 117, 103])))
        .set_sid(Sid::VrqSerialNumber(Yang::String("00-D0-E5-02-00-2E".as_bytes().to_vec())));

    // "validating an unsigned voucher" should fail
    assert!(vrq.validate(Some(DEVICE_CRT_02_00_2E)).is_err());

    vrq.sign(KEY_PEM_02_00_2E, SignatureAlgorithm::ES256).unwrap();

    assert!(vrq.validate(Some(DEVICE_CRT_02_00_2E)).is_ok());
}

#[test]
fn test_sign_vrq_f2_00_02() {
    #[cfg(feature = "v3")]
    init_psa_crypto();

    let mut vrq = Voucher::new(VoucherType::Vrq);

    assert!(vrq
        .set_sid(Sid::VrqAssertion(Yang::Enumeration(YangEnum::Proximity)))
        .set_sid(Sid::VrqCreatedOn(Yang::DateAndTime(1599086034)))
        .set_sid(Sid::VrqNonce(Yang::Binary(vec![48, 130, 1, 216, 48, 130, 1, 94, 160, 3, 2, 1, 2, 2, 1, 1, 48, 10, 6, 8, 42, 134, 72, 206, 61, 4, 3, 2, 48, 115, 49, 18, 48, 16, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 2, 99, 97, 49, 25, 48, 23, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 9, 115, 97, 110, 100, 101, 108, 109, 97, 110, 49, 66, 48, 64, 6, 3, 85, 4, 3, 12, 57, 35, 60, 83, 121, 115, 116, 101, 109, 86, 97, 114, 105, 97, 98, 108, 101, 58, 48, 120, 48, 48, 48, 48, 53, 53, 98, 56, 50, 53, 48, 99, 48, 100, 98, 56, 62, 32, 85, 110, 115, 116, 114, 117, 110, 103, 32, 70, 111, 117, 110, 116, 97, 105, 110, 32, 67, 65, 48, 30, 23, 13, 50, 48, 48, 56, 50, 57, 48, 52, 48, 48, 49, 54, 90, 23, 13, 50, 50, 48, 56, 50, 57, 48, 52, 48, 48, 49, 54, 90, 48, 70, 49, 18, 48, 16, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 2, 99, 97, 49, 25, 48, 23, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 9, 115, 97, 110, 100, 101, 108, 109, 97, 110, 49, 21, 48, 19, 6, 3, 85, 4, 3, 12, 12, 85, 110, 115, 116, 114, 117, 110, 103, 32, 74, 82, 67, 48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3, 1, 7, 3, 66, 0, 4, 150, 101, 80, 114, 52, 186, 159, 229, 221, 230, 95, 246, 240, 129, 111, 233, 72, 158, 129, 12, 18, 7, 59, 70, 143, 151, 100, 43, 99, 0, 141, 2, 15, 87, 201, 124, 148, 127, 132, 140, 178, 14, 97, 214, 201, 136, 141, 21, 180, 66, 31, 215, 242, 106, 183, 228, 206, 5, 248, 167, 76, 211, 139, 58, 163, 16, 48, 14, 48, 12, 6, 3, 85, 29, 19, 1, 1, 255, 4, 2, 48, 0, 48, 10, 6, 8, 42, 134, 72, 206, 61, 4, 3, 2, 3, 104, 0, 48, 101, 2, 49, 0, 135, 158, 205, 227, 138, 5, 18, 46, 182, 247, 44, 178, 27, 195, 210, 92, 190, 230, 87, 55, 112, 86, 156, 236, 35, 12, 164, 140, 57, 241, 64, 77, 114, 212, 215, 85, 5, 155, 128, 130, 2, 14, 212, 29, 79, 17, 159, 231, 2, 48, 60, 20, 216, 138, 10, 252, 64, 71, 207, 31, 135, 184, 115, 193, 106, 40, 191, 184, 60, 15, 136, 67, 77, 157, 243, 247, 168, 110, 45, 198, 189, 136, 149, 68, 47, 32, 55, 237, 204, 228, 133, 91, 17, 218, 154, 25, 228, 232])))
        .set_sid(Sid::VrqProximityRegistrarCert(Yang::Binary(vec![102, 114, 118, 85, 105, 90, 104, 89, 56, 80, 110, 86, 108, 82, 75, 67, 73, 83, 51, 113, 77, 81])))
        .set_sid(Sid::VrqSerialNumber(Yang::String("00-D0-E5-F2-00-02".as_bytes().to_vec())))
        .sign(KEY_PEM_02_00_2E, SignatureAlgorithm::ES256) // !! todo KEY_PEM_F2_00_02
        .unwrap()
        .validate(Some(DEVICE_CRT_02_00_2E)) // via public key // !! todo _F2_00_02
        .is_ok());

    assert!(vrq.validate(Some(KEY_PEM_02_00_2E)).is_ok()); // via private key // !! todo _F2_00_02

    let vrq_gt = Voucher::try_from(VRQ_F2_00_02).unwrap();
    assert!(debug::content_comp_permissive(
        &vrq_gt.get_content_debug().unwrap(),
        &vrq.get_content_debug().unwrap()));


    let (sig, ty) = vrq.get_signature();
    assert!(sig.len() > 0);
    assert_eq!(ty, &SignatureAlgorithm::ES256);
}

//#[test]
fn test_pledge_vr_validate_02_00_2e() {
//fn test_validate_vrq_f2_00_02() { // !! TODO
    #[cfg(feature = "v3")]
    init_psa_crypto();

    // assert!(Voucher::try_from(debug::COSE_VRQ_02_00_2E)
    //     .unwrap()
    //     .validate(Some(DEVICE_CRT_02_00_2E))
    //     .is_ok());
}

//#[test]
fn test_pledge_vr_serialize_02_00_2e() {
//fn test_serialize_vrq_f2_00_02() { // !! TODO
    #[cfg(feature = "v3")]
    init_psa_crypto();

//    let vrq = Voucher::try_from(debug::COSE_VRQ_02_00_2E).unwrap();
//    assert_eq!(vrq.get_content_debug().unwrap(),
//               debug::CONTENT_VRQ_02_00_2E);
//    assert_eq!(vrq.get_signature().0, /* bare */ [213, 235, 111, 50, 190, 110, 39, 125, 24, 10, 108, 112, 208, 115, 138, 149, 12, 183, 237, 34, 220, 209, 168, 239, 185, 5, 170, 145, 221, 42, 135, 70, 13, 231, 183, 48, 88, 32, 174, 78, 146, 46, 72, 206, 11, 103, 80, 17, 80, 62, 17, 101, 155, 78, 7, 1, 87, 177, 172, 192, 118, 31, 116, 214]);
//    assert_eq!(vrq.serialize().unwrap(), debug::COSE_VRQ_02_00_2E);
}

//

//#[test]
fn test_highlevel_interface() {
    #[cfg(feature = "v3")]
    init_psa_crypto();

    let mut vrq = Voucher::new_vrq();

    assert!(vrq
        .set(Attr::Assertion(Assertion::Proximity))
        .set(Attr::CreatedOn(1635218340))
        .set(Attr::Nonce(vec![114, 72, 103, 99, 66, 86, 78, 86, 97, 70, 109, 66, 87, 98, 84, 77, 109, 101, 79, 75, 117, 103]))
        .set(Attr::SerialNumber(String::from("00-D0-E5-02-00-2E")))
        .sign(KEY_PEM_02_00_2E, SignatureAlgorithm::ES256)
        .unwrap()
        .validate(Some(DEVICE_CRT_02_00_2E))
        .is_ok());

    // assert!(debug::content_comp(&vrq.get_content_debug().unwrap(),
    //                             debug::CONTENT_VRQ_02_00_2E));
    assert_eq!(vrq.get_signature().0, /* asn1 */ [48, 69, 2, 32, 110, 143, 135, 7, 170, 12, 231, 167, 243, 130, 212, 214, 122, 23, 71, 106, 100, 76, 173, 196, 236, 73, 58, 126, 151, 8, 46, 127, 206, 190, 196, 66, 2, 33, 0, 217, 20, 0, 2, 48, 18, 151, 42, 133, 159, 125, 145, 86, 197, 138, 227, 30, 64, 230, 164, 214, 125, 78, 62, 183, 48, 179, 249, 79, 147, 36, 112]);
    assert_eq!(vrq.serialize().unwrap().len(), 148);

    /* WIP */ assert_eq!(vrq.get(ATTR_CREATED_ON), Some(Attr::CreatedOn(1635218340)));

    // vrq.iter().for_each(|attr_disc| {
    //    let attr = vrq.get(attr_disc); // cloned
    //    println!("cloned attr: {:?}", attr); // Some(....)
    // })


    //

    let _ = Voucher::new_vch_with(vec![
        Attr::Assertion(Assertion::Logged),
        Attr::SerialNumber(String::from("00-11-22-33-44-55")),
    ]);

    let _ = Voucher::new_vrq_with(vec![
        Attr::Assertion(Assertion::Proximity),
        Attr::SerialNumber(String::from("00-D0-E5-02-00-2E")),
    ]);
}

#[test]
#[cfg(feature = "std")]
fn test_highlevel_attr_integrity() {
    assert!(std::panic::catch_unwind(|| {
        Voucher::new_vrq().set(Attr::PinnedDomainPubk(vec![]));
    }).is_err());

    assert!(std::panic::catch_unwind(|| {
        Voucher::new_vrq().set(Attr::PinnedDomainPubkSha256(vec![]));
    }).is_err());

    assert!(std::panic::catch_unwind(|| {
        Voucher::new_vch().set(Attr::PriorSignedVoucherRequest(vec![]));
    }).is_err());

    assert!(std::panic::catch_unwind(|| {
        Voucher::new_vch().set(Attr::ProximityRegistrarCert(vec![]));
    }).is_err());

    assert!(std::panic::catch_unwind(|| {
        Voucher::new_vch().set(Attr::ProximityRegistrarPubk(vec![]));
    }).is_err());

    assert!(std::panic::catch_unwind(|| {
        Voucher::new_vch().set(Attr::ProximityRegistrarPubkSha256(vec![]));
    }).is_err());
}
