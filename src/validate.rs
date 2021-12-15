use crate::println;

use crate::{SignatureAlgorithm, minerva_mbedtls_utils::*};
use minerva_mbedtls::ifce::*;
use core::ffi::c_void;

impl crate::Validate for crate::Voucher {
    fn validate(&self, pem: Option<&[u8]>) -> Result<&Self, ()> {
        let f_rng = pk_context::test_f_rng_ptr(); // !! TODO refactor into `self` logic

        match validate(pem, self.to_validate(), f_rng) {
            Ok(tf) => if tf { Ok(self) } else { Err(()) },
            Err(err) => {
                println!("validate(): mbedtls_error: {}", err);

                Err(())
            },
        }
    }
}

fn validate(
    pem: Option<&[u8]>,
    (signer_cert, signature, alg, msg): (Option<&[u8]>, &[u8], &SignatureAlgorithm, &[u8]),
    f_rng: *const c_void
) -> Result<bool, mbedtls_error> {
    if signature.is_empty() { return Ok(false); }

    // @@ ==== debug
    // let _ = pk_context::new().verify_debug_esp32_a(42, &[2; 16], &[4; 16], &[8; 16]);
    // let _ = pk_context::new().verify_debug_esp32_b(    &[2; 16], &[4; 16], &[8; 16]);
    // if 1 == 1 { panic!("@@ broken sig len -- on xtensa; need adjusting the stack size? or..."); }
    // @@ ====

    let (md_ty, ref hash) = compute_digest(msg, alg);

    if let Some(pem) = pem {
        if let Ok(mut pk) = pk_from_privkey_pem(pem, f_rng) {
            return pk.verify(md_ty, hash, signature);
        }

        x509_crt::new()
            .parse(pem)?
            .pk_mut()
            .verify(md_ty, hash, signature)
    } else if let Some(cert) = signer_cert {
        let grp = ecp_group::from_id(ecp_group_id::MBEDTLS_ECP_DP_SECP256R1);
        let mut pt = ecp_point::new();
        pt.read_binary(&grp, cert);

        pk_context::new()
            .setup(pk_type::MBEDTLS_PK_ECKEY)?
            .set_grp(grp)
            .set_q(pt)
            .verify(md_ty, hash, signature)
    } else {
        println!("validate(): Neither external masa cert nor signer cert is available.");
        Ok(false)
    }
}
