#[cfg(feature = "std")]
use std::{vec, vec::Vec};
#[cfg(not(feature = "std"))]
use mcu_if::alloc::{vec, vec::Vec};

use crate::{SignatureAlgorithm, minerva_mbedtls_utils::*};
use minerva_mbedtls::ifce::*;
use core::ffi::c_void;

impl crate::Sign for crate::Voucher {
    fn sign(&mut self, privkey_pem: &[u8], alg: SignatureAlgorithm) {
        sign(privkey_pem, alg, self.to_sign(),
             pk_context::test_f_rng_ptr()); // !! TODO refactor into `self`
    }
}

fn sign(
    privkey_pem: &[u8],
    alg: SignatureAlgorithm,
    (sig_out, alg_out, sig_struct): (&mut Vec<u8>, &mut SignatureAlgorithm, &[u8]),
    f_rng: *const c_void
) {
    let mut sig = vec![];
    let (md_ty, ref hash) = compute_digest(sig_struct, &alg);

    if let Ok(mut pk) = pk_from_privkey_pem(privkey_pem, f_rng) {
        pk.sign(md_ty, hash, &mut sig, f_rng, core::ptr::null());
        *alg_out = alg;
        *sig_out = sig;
    }
}