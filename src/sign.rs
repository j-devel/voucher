#[cfg(feature = "std")]
use std::{vec, vec::Vec};
#[cfg(not(feature = "std"))]
use mcu_if::alloc::{vec, vec::Vec};

use crate::{SignatureAlgorithm, minerva_mbedtls_utils::compute_digest};
use minerva_mbedtls::ifce::*;

impl crate::Sign for crate::Voucher {
    fn sign(&mut self, privkey_pem: &[u8], alg: SignatureAlgorithm) {
        sign(privkey_pem, alg, self.to_sign());
    }
}

fn sign(
    privkey_pem: &[u8],
    alg: SignatureAlgorithm,
    (sig_out, alg_out, sig_struct): (&mut Vec<u8>, &mut SignatureAlgorithm, &[u8])
) {
    let mut pk = pk_context::new();
    let f_rng = pk_context::test_f_rng_ptr();

    #[cfg(feature = "sign-lts")]
    {
        pk.parse_key_lts(privkey_pem, None);
    }
    #[cfg(not(feature = "sign-lts"))]
    {
        pk.parse_key(privkey_pem, None, f_rng, core::ptr::null());
    }

    let mut sig = vec![];
    let (md_ty, ref hash) = compute_digest(sig_struct, &alg);
    pk.sign(md_ty, hash, &mut sig, f_rng, core::ptr::null());

    *alg_out = alg;
    *sig_out = sig;
}