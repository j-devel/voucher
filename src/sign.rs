use crate::{vec, Vec};
use crate::{VoucherError, SignatureAlgorithm};
use crate::debug_println;
use super::utils::minerva_mbedtls_utils::*;

use minerva_mbedtls::ifce::*;
use core::ffi::c_void;

impl crate::Sign for crate::Voucher {
    fn sign(&mut self, privkey_pem: &[u8], alg: SignatureAlgorithm) -> Result<&mut Self, VoucherError> {
        let f_rng = pk_context::test_f_rng_ptr(); // TODO refactor

        if let Err(err) = sign_with_mbedtls(privkey_pem, alg, self.to_sign(alg), f_rng) {
            debug_println!("sign(): mbedtls_error: {}", err);
            Err(VoucherError::SigningFailed)
        } else {
            Ok(self)
        }
    }
}

fn sign_with_mbedtls(
    privkey_pem: &[u8],
    alg: SignatureAlgorithm,
    (sig_out, sig_struct): (&mut Vec<u8>, &[u8]),
    f_rng: *const c_void
) -> Result<(), mbedtls_error> {
    let mut sig = vec![];
    let (md_ty, ref hash) = compute_digest(sig_struct, &alg);

    let mut pk = pk_from_privkey_pem(privkey_pem, f_rng)?;
    pk.sign(md_ty, hash, &mut sig, f_rng, core::ptr::null())?;

    *sig_out = sig;

    Ok(())
}
