use crate::*;
use super::yang::Yang;

static VCH_JADA: &[u8] = core::include_bytes!(
    concat!(env!("CARGO_MANIFEST_DIR"), "/data/jada/voucher_jada123456789.vch"));

static VCH_F2_00_02: &[u8] = core::include_bytes!(
    concat!(env!("CARGO_MANIFEST_DIR"), "/data/00-D0-E5-F2-00-02/voucher_00-D0-E5-F2-00-02.vch"));

static VRQ_F2_00_02: &[u8] = core::include_bytes!(
    concat!(env!("CARGO_MANIFEST_DIR"), "/data/00-D0-E5-F2-00-02/vr_00-D0-E5-F2-00-02.vrq"));

static MASA_CRT_F2_00_02: &[u8] = core::include_bytes!(
    concat!(env!("CARGO_MANIFEST_DIR"), "/data/00-D0-E5-F2-00-02/masa.crt"));

static DEVICE_CRT_F2_00_02: &[u8] = core::include_bytes!(
    concat!(env!("CARGO_MANIFEST_DIR"), "/data/00-D0-E5-F2-00-02/device.crt"));

static KEY_PEM_F2_00_02: &[u8] = core::include_bytes!(
    concat!(env!("CARGO_MANIFEST_DIR"), "/data/00-D0-E5-F2-00-02/key.pem"));

//

fn content_from_voucher(raw: &[u8]) -> Vec<u8> {
    Voucher::try_from(raw).unwrap().extract_cose_content().unwrap()
}

pub fn content_vch_jada() -> Vec<u8> { content_from_voucher(VCH_JADA) }
pub fn content_vch_f2_00_02() -> Vec<u8> { content_from_voucher(VCH_F2_00_02) }
pub fn content_vrq_f2_00_02() -> Vec<u8> { content_from_voucher(VRQ_F2_00_02) }

#[cfg(feature = "v3")]
fn init_psa_crypto() {
    use minerva_mbedtls::psa_crypto;

    psa_crypto::init().unwrap();
    psa_crypto::initialized().unwrap();
}

//

use core::convert::{TryFrom, TryInto};

#[test]
fn test_voucher_conversion() {
    let dummy: &[u8] = &[0, 1, 2];

    assert!(Voucher::try_from(VCH_JADA).is_ok());
    assert!(Voucher::try_from(VCH_F2_00_02).is_ok());
    assert!(Voucher::try_from(VRQ_F2_00_02).is_ok());
    assert!(Voucher::try_from(dummy).is_err());

    //

    let vch: Voucher = VCH_JADA.try_into().unwrap();
    assert_eq!(vch.len(), 6);
    if 0 == 1 { vch.dump_and_panic(); }

    vch.iter().for_each(|attr| {
        println!("attr: {:?}", attr);
        match attr {
            Attr::Assertion(x) => assert_eq!(x, &Assertion::Proximity),
            Attr::CreatedOn(x) => assert_eq!(x, &1475868702),
            Attr::ExpiresOn(x) => assert_eq!(x, &1506816000),
            Attr::Nonce(x) => assert_eq!(x, &[97, 98, 99, 100, 49, 50, 51, 52, 53]),
            Attr::PinnedDomainPubk(x) => assert_eq!(x[0..4], [77, 70, 107, 119]),
            Attr::SerialNumber(x) => assert_eq!(x, "JADA123456789".as_bytes()),
            _ => panic!(),
        }
    });

    //

    let vch: Voucher = VCH_F2_00_02.try_into().unwrap();
    assert_eq!(vch.len(), 5);

    vch.iter().for_each(|attr| {
        println!("attr: {:?}", attr);
        match attr {
            Attr::Assertion(x) => assert_eq!(x, &Assertion::Logged),
            Attr::CreatedOn(x) => assert_eq!(x, &1599525239),
            Attr::Nonce(x) => assert_eq!(x, &[88, 83, 121, 70, 52, 76, 76, 73, 105, 113, 85, 50, 45, 79, 71, 107, 54, 108, 70, 67, 65, 103]),
            Attr::PinnedDomainCert(x) => assert_eq!(x[0..4], [77, 73, 73, 66]),
            Attr::SerialNumber(x) => assert_eq!(x, "00-D0-E5-F2-00-02".as_bytes()),
            _ => panic!(),
        }
    });

    //

    let vrq: Voucher = VRQ_F2_00_02.try_into().unwrap();
    assert_eq!(vrq.len(), 5);

    vrq.iter().for_each(|attr| {
        println!("attr: {:?}", attr);
        match attr {
            Attr::Assertion(x) => assert_eq!(x, &Assertion::Proximity),
            Attr::CreatedOn(x) => assert_eq!(x, &1599086034),
            Attr::Nonce(x) => assert_eq!(x, &[102, 114, 118, 85, 105, 90, 104, 89, 56, 80, 110, 86, 108, 82, 75, 67, 73, 83, 51, 113, 77, 81]),
            Attr::ProximityRegistrarCert(x) => assert_eq!(x[0..4], [48, 130, 1, 216]),
            Attr::SerialNumber(x) => assert_eq!(x, "00-D0-E5-F2-00-02".as_bytes()),
            _ => panic!(),
        }
    });

    //

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
    assert!(vch.extract_cose_content().unwrap().len() > 0);
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
    assert!(vch.extract_cose_content().unwrap().len() > 0);
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

fn build_vrq_f2_00_02() -> Voucher {
    let mut vrq = Voucher::new(VoucherType::Vrq);
    vrq.set_sid(Sid::VrqAssertion(Yang::Enumeration(Attr::Assertion(Assertion::Proximity))))
        .set_sid(Sid::VrqCreatedOn(Yang::DateAndTime(Attr::CreatedOn(1599086034))))
        .set_sid(Sid::VrqNonce(Yang::Binary(Attr::Nonce(vec![48, 130, 1, 216, 48, 130, 1, 94, 160, 3, 2, 1, 2, 2, 1, 1, 48, 10, 6, 8, 42, 134, 72, 206, 61, 4, 3, 2, 48, 115, 49, 18, 48, 16, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 2, 99, 97, 49, 25, 48, 23, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 9, 115, 97, 110, 100, 101, 108, 109, 97, 110, 49, 66, 48, 64, 6, 3, 85, 4, 3, 12, 57, 35, 60, 83, 121, 115, 116, 101, 109, 86, 97, 114, 105, 97, 98, 108, 101, 58, 48, 120, 48, 48, 48, 48, 53, 53, 98, 56, 50, 53, 48, 99, 48, 100, 98, 56, 62, 32, 85, 110, 115, 116, 114, 117, 110, 103, 32, 70, 111, 117, 110, 116, 97, 105, 110, 32, 67, 65, 48, 30, 23, 13, 50, 48, 48, 56, 50, 57, 48, 52, 48, 48, 49, 54, 90, 23, 13, 50, 50, 48, 56, 50, 57, 48, 52, 48, 48, 49, 54, 90, 48, 70, 49, 18, 48, 16, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 2, 99, 97, 49, 25, 48, 23, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 9, 115, 97, 110, 100, 101, 108, 109, 97, 110, 49, 21, 48, 19, 6, 3, 85, 4, 3, 12, 12, 85, 110, 115, 116, 114, 117, 110, 103, 32, 74, 82, 67, 48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3, 1, 7, 3, 66, 0, 4, 150, 101, 80, 114, 52, 186, 159, 229, 221, 230, 95, 246, 240, 129, 111, 233, 72, 158, 129, 12, 18, 7, 59, 70, 143, 151, 100, 43, 99, 0, 141, 2, 15, 87, 201, 124, 148, 127, 132, 140, 178, 14, 97, 214, 201, 136, 141, 21, 180, 66, 31, 215, 242, 106, 183, 228, 206, 5, 248, 167, 76, 211, 139, 58, 163, 16, 48, 14, 48, 12, 6, 3, 85, 29, 19, 1, 1, 255, 4, 2, 48, 0, 48, 10, 6, 8, 42, 134, 72, 206, 61, 4, 3, 2, 3, 104, 0, 48, 101, 2, 49, 0, 135, 158, 205, 227, 138, 5, 18, 46, 182, 247, 44, 178, 27, 195, 210, 92, 190, 230, 87, 55, 112, 86, 156, 236, 35, 12, 164, 140, 57, 241, 64, 77, 114, 212, 215, 85, 5, 155, 128, 130, 2, 14, 212, 29, 79, 17, 159, 231, 2, 48, 60, 20, 216, 138, 10, 252, 64, 71, 207, 31, 135, 184, 115, 193, 106, 40, 191, 184, 60, 15, 136, 67, 77, 157, 243, 247, 168, 110, 45, 198, 189, 136, 149, 68, 47, 32, 55, 237, 204, 228, 133, 91, 17, 218, 154, 25, 228, 232]))))
        .set_sid(Sid::VrqProximityRegistrarCert(Yang::Binary(Attr::ProximityRegistrarCert(vec![102, 114, 118, 85, 105, 90, 104, 89, 56, 80, 110, 86, 108, 82, 75, 67, 73, 83, 51, 113, 77, 81]))))
        .set_sid(Sid::VrqSerialNumber(Yang::String(Attr::SerialNumber("00-D0-E5-F2-00-02".as_bytes().to_vec()))));

    vrq
}

#[test]
fn test_unsigned_vrq_f2_00_02() {
    #[cfg(feature = "v3")]
    init_psa_crypto();

    let mut vrq = build_vrq_f2_00_02();

    // "validating an unsigned voucher" should fail
    assert!(vrq.validate(Some(DEVICE_CRT_F2_00_02)).is_err());

    vrq.sign(KEY_PEM_F2_00_02, SignatureAlgorithm::ES256).unwrap();

    assert!(vrq.validate(Some(DEVICE_CRT_F2_00_02)).is_ok());
}

#[test]
fn test_validate_vrq_f2_00_02() {
    #[cfg(feature = "v3")]
    init_psa_crypto();

    assert!(Voucher::try_from(VRQ_F2_00_02)
        .unwrap()
        .validate(Some(DEVICE_CRT_F2_00_02))
        .is_ok());
}

#[test]
fn test_sign_vrq_f2_00_02() {
    #[cfg(feature = "v3")]
    init_psa_crypto();

    let mut vrq = build_vrq_f2_00_02();

    assert!(vrq
        .sign(KEY_PEM_F2_00_02, SignatureAlgorithm::ES256)
        .unwrap()
        .validate(Some(DEVICE_CRT_F2_00_02)) // via public key
        .is_ok());

    assert!(vrq.validate(Some(KEY_PEM_F2_00_02)).is_ok()); // via private key

    assert!(debug::content_comp_permissive(
        &vrq.extract_cose_content().unwrap(), &content_vrq_f2_00_02()));

    let (sig, ty) = vrq.get_signature();
    assert!(sig.len() > 0);
    assert_eq!(ty, &SignatureAlgorithm::ES256);
}

#[test]
fn test_serialize_vrq_f2_00_02() {
    #[cfg(feature = "v3")]
    init_psa_crypto();

    let vrq = Voucher::try_from(VRQ_F2_00_02).unwrap();

    assert_eq!(vrq.extract_cose_content().unwrap(), hex_literal::hex!("
A1                                      # map(1)
   19 09C5                              # unsigned(2501)
   A5                                   # map(5)
      01                                # unsigned(1)
      69                                # text(9)
         70726F78696D697479             # \"proximity\"
      02                                # unsigned(2)
      C1                                # tag(1)
         1A 5F501DD2                    # unsigned(1599086034)
      0D                                # unsigned(13)
      51                                # bytes(17)
         30302D44302D45352D46322D30302D3032 # \"00-D0-E5-F2-00-02\"
      07                                # unsigned(7)
      76                                # text(22)
         66727655695A685938506E566C524B43495333714D51 # \"frvUiZhY8PnVlRKCIS3qMQ\"
      0A                                # unsigned(10)
      59 01DC                           # bytes(476)
         308201D83082015EA003020102020101300A06082A8648CE3D040302307331123010060A0992268993F22C6401191602636131193017060A0992268993F22C640119160973616E64656C6D616E3142304006035504030C39233C53797374656D5661726961626C653A3078303030303535623832353063306462383E20556E737472756E6720466F756E7461696E204341301E170D3230303832393034303031365A170D3232303832393034303031365A304631123010060A0992268993F22C6401191602636131193017060A0992268993F22C640119160973616E64656C6D616E3115301306035504030C0C556E737472756E67204A52433059301306072A8648CE3D020106082A8648CE3D030107034200049665507234BA9FE5DDE65FF6F0816FE9489E810C12073B468F97642B63008D020F57C97C947F848CB20E61D6C9888D15B4421FD7F26AB7E4CE05F8A74CD38B3AA310300E300C0603551D130101FF04023000300A06082A8648CE3D0403020368003065023100879ECDE38A05122EB6F72CB21BC3D25CBEE6573770569CEC230CA48C39F1404D72D4D755059B8082020ED41D4F119FE702303C14D88A0AFC4047CF1F87B873C16A28BFB83C0F88434D9DF3F7A86E2DC6BD8895442F2037EDCCE4855B11DA9A19E4E8 #
# python3: `bytes([161, 25, ... 228, 232]).hex()` > https://cbor.me/
"));
    assert_eq!(vrq.get_signature().0, /* bare */ [242, 113, 238, 15, 125, 71, 169, 233, 252, 219, 95, 74, 88, 238, 47, 97, 183, 138, 84, 131, 159, 203, 164, 31, 34, 135, 174, 129, 228, 47, 180, 129, 171, 146, 165, 162, 167, 222, 82, 112, 125, 198, 7, 254, 142, 250, 108, 214, 194, 253, 235, 104, 154, 68, 171, 179, 127, 93, 192, 158, 174, 24, 23, 8]);
    assert_eq!(vrq.serialize().unwrap(), VRQ_F2_00_02);
}

//

#[test]
fn test_highlevel_interface() {
    #[cfg(feature = "v3")]
    init_psa_crypto();

    let mut vrq = Voucher::new_vrq();

    assert!(vrq
        .set(Attr::Assertion(Assertion::Proximity))
        .set(Attr::CreatedOn(1599086034))
        .set(Attr::Nonce(vec![48, 130, 1, 216, 48, 130, 1, 94, 160, 3, 2, 1, 2, 2, 1, 1, 48, 10, 6, 8, 42, 134, 72, 206, 61, 4, 3, 2, 48, 115, 49, 18, 48, 16, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 2, 99, 97, 49, 25, 48, 23, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 9, 115, 97, 110, 100, 101, 108, 109, 97, 110, 49, 66, 48, 64, 6, 3, 85, 4, 3, 12, 57, 35, 60, 83, 121, 115, 116, 101, 109, 86, 97, 114, 105, 97, 98, 108, 101, 58, 48, 120, 48, 48, 48, 48, 53, 53, 98, 56, 50, 53, 48, 99, 48, 100, 98, 56, 62, 32, 85, 110, 115, 116, 114, 117, 110, 103, 32, 70, 111, 117, 110, 116, 97, 105, 110, 32, 67, 65, 48, 30, 23, 13, 50, 48, 48, 56, 50, 57, 48, 52, 48, 48, 49, 54, 90, 23, 13, 50, 50, 48, 56, 50, 57, 48, 52, 48, 48, 49, 54, 90, 48, 70, 49, 18, 48, 16, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 2, 99, 97, 49, 25, 48, 23, 6, 10, 9, 146, 38, 137, 147, 242, 44, 100, 1, 25, 22, 9, 115, 97, 110, 100, 101, 108, 109, 97, 110, 49, 21, 48, 19, 6, 3, 85, 4, 3, 12, 12, 85, 110, 115, 116, 114, 117, 110, 103, 32, 74, 82, 67, 48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3, 1, 7, 3, 66, 0, 4, 150, 101, 80, 114, 52, 186, 159, 229, 221, 230, 95, 246, 240, 129, 111, 233, 72, 158, 129, 12, 18, 7, 59, 70, 143, 151, 100, 43, 99, 0, 141, 2, 15, 87, 201, 124, 148, 127, 132, 140, 178, 14, 97, 214, 201, 136, 141, 21, 180, 66, 31, 215, 242, 106, 183, 228, 206, 5, 248, 167, 76, 211, 139, 58, 163, 16, 48, 14, 48, 12, 6, 3, 85, 29, 19, 1, 1, 255, 4, 2, 48, 0, 48, 10, 6, 8, 42, 134, 72, 206, 61, 4, 3, 2, 3, 104, 0, 48, 101, 2, 49, 0, 135, 158, 205, 227, 138, 5, 18, 46, 182, 247, 44, 178, 27, 195, 210, 92, 190, 230, 87, 55, 112, 86, 156, 236, 35, 12, 164, 140, 57, 241, 64, 77, 114, 212, 215, 85, 5, 155, 128, 130, 2, 14, 212, 29, 79, 17, 159, 231, 2, 48, 60, 20, 216, 138, 10, 252, 64, 71, 207, 31, 135, 184, 115, 193, 106, 40, 191, 184, 60, 15, 136, 67, 77, 157, 243, 247, 168, 110, 45, 198, 189, 136, 149, 68, 47, 32, 55, 237, 204, 228, 133, 91, 17, 218, 154, 25, 228, 232]))
        .set(Attr::ProximityRegistrarCert(vec![102, 114, 118, 85, 105, 90, 104, 89, 56, 80, 110, 86, 108, 82, 75, 67, 73, 83, 51, 113, 77, 81]))
        .set(Attr::SerialNumber("00-D0-E5-F2-00-02".as_bytes().to_vec()))
        .sign(KEY_PEM_F2_00_02, SignatureAlgorithm::ES256)
        .unwrap()
        .validate(Some(DEVICE_CRT_F2_00_02))
        .is_ok());

    assert!(debug::content_comp_permissive(
        &vrq.extract_cose_content().unwrap(), &content_vrq_f2_00_02()));

    assert_eq!(vrq.get_signature().0, /* asn1 */ [48, 70, 2, 33, 0, 164, 97, 9, 44, 103, 141, 55, 95, 230, 60, 165, 83, 63, 61, 81, 133, 98, 207, 213, 159, 74, 67, 180, 113, 158, 8, 220, 210, 48, 177, 185, 211, 2, 33, 0, 161, 49, 250, 154, 96, 186, 186, 87, 188, 188, 67, 249, 31, 177, 104, 160, 65, 12, 62, 87, 233, 231, 105, 58, 29, 215, 16, 227, 162, 179, 209, 110]);
    assert_eq!(vrq.serialize().unwrap().len(), 628);


    assert_eq!(vrq.get(ATTR_CREATED_ON), Some(&Attr::CreatedOn(1599086034)));
    assert_eq!(vrq.get(ATTR_EXPIRES_ON), None);

    //

    let vch = vch![
        Attr::Assertion(Assertion::Logged),
        Attr::SerialNumber("00-11-22-33-44-55".as_bytes().to_vec())];
    assert!(vch.is_vch());
    assert_eq!(vch.len(), 2);

    let vrq = vrq![
        Attr::Assertion(Assertion::Proximity),
        Attr::SerialNumber("00-11-22-33-44-55".as_bytes().to_vec())];
    assert!(vrq.is_vrq());
    assert_eq!(vrq.len(), 2);

    //

    assert_eq!(vch![].len(), 0);
    assert_eq!(vrq![].len(), 0);
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
