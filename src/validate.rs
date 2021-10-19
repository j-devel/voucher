#[cfg(feature = "std")]
use std::{println, vec::Vec};
#[cfg(not(feature = "std"))]
use mcu_if::{println, alloc::vec::Vec};

use crate::SignatureAlgorithm;
use minerva_mbedtls::ifce::*;

pub fn validate(
    masa_pem: Option<&[u8]>,
    (signer_cert, signature, alg, msg): (Option<&[u8]>, &[u8], &SignatureAlgorithm, &[u8])
) -> bool {
    let (md_ty, ref hash) = compute_digest(msg, alg);

    if let Some(pem) = masa_pem {
        #[cfg(not(feature = "validate-lts-xtensa-kludge"))]
        {
            x509_crt::new()
                .parse(pem)
                .pk_mut()
                .verify(md_ty, hash, signature)
        }
        #[cfg(feature = "validate-lts-xtensa-kludge")]
        {
            let _ = pem;
            println!("⚠️ FIXME -- linker errors on `x509_crt` related symbols on `xtensa`; validation fails for now!!");
            false
        }
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

fn compute_digest(msg: &[u8], alg: &SignatureAlgorithm) -> (md_type, Vec<u8>) {
    let ty = match *alg {
        SignatureAlgorithm::ES256 => md_type::MBEDTLS_MD_SHA256,
        SignatureAlgorithm::ES384 => md_type::MBEDTLS_MD_SHA384,
        SignatureAlgorithm::ES512 => md_type::MBEDTLS_MD_SHA512,
        SignatureAlgorithm::PS256 => unimplemented!("TODO: handle PS256"),
    };

    (ty, md_info::from_type(ty).md(msg))
}
