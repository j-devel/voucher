#[cfg(feature = "std")]
use std::println;
#[cfg(not(feature = "std"))]
use mcu_if::println;

use crate::{SignatureAlgorithm, utils::compute_digest};
use minerva_mbedtls::ifce::*;

impl crate::Validate for crate::Voucher {
    fn validate(&self, pubkey_pem: Option<&[u8]>) -> bool {
        validate(pubkey_pem, self.to_validate())
    }
}

fn validate(
    pubkey_pem: Option<&[u8]>,
    (signer_cert, signature, alg, msg): (Option<&[u8]>, &[u8], &SignatureAlgorithm, &[u8])
) -> bool {
    let (md_ty, ref hash) = compute_digest(msg, alg);

    if let Some(pem) = pubkey_pem {
        x509_crt::new()
            .parse(pem)
            .pk_mut()
            .verify(md_ty, hash, signature)
    } else if let Some(cert) = signer_cert {
        let grp = ecp_group::from_id(ecp_group_id::MBEDTLS_ECP_DP_SECP256R1);
        let mut pt = ecp_point::new();
        pt.read_binary(&grp, cert);

        pk_context::new()
            .setup(pk_type::MBEDTLS_PK_ECKEY)
            .set_grp(grp)
            .set_q(pt)
            .verify(md_ty, hash, signature)
    } else {
        println!("validate(): Neither external masa cert nor signer cert is available.");
        false
    }
}