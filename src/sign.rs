#![allow(unused_imports, unused_variables)] // TEMP !!

#[cfg(feature = "std")]
use std::{println, vec::Vec};
#[cfg(not(feature = "std"))]
use mcu_if::{println, alloc::vec::Vec};

use crate::SignatureAlgorithm;
use minerva_mbedtls::ifce::*;

impl crate::Sign for crate::Voucher {
    fn sign(&mut self, privkey_pem: &[u8], alg: SignatureAlgorithm) {
        sign(privkey_pem, alg, self.to_sign());
    }
}

fn sign(
    privkey_pem: &[u8],
    alg: SignatureAlgorithm,
    to_sign: (&mut [u8], &mut SignatureAlgorithm, &[u8])
) {
    unimplemented!("WIP !!");
}