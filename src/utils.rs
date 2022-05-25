use crate::{Vec, SignatureAlgorithm};

#[cfg(any(feature = "mbedtls-backend", feature = "sign", feature = "validate"))]
pub mod minerva_mbedtls_utils {
    use super::*;
    use minerva_mbedtls::ifce::*;
    use core::ffi::c_void;

    /// Initializes the [PSA cryptography API](https://armmbed.github.io/mbed-crypto/html/)
    /// context.  Call this function when using the `Sign`/`Validate` trait backed by mbedtls.
    pub fn init_psa_crypto() {
        use minerva_mbedtls::psa_crypto;

        psa_crypto::init().unwrap();
        psa_crypto::initialized().unwrap();
    }

    pub fn compute_digest(msg: &[u8], alg: &SignatureAlgorithm) -> (md_type, Vec<u8>) {
        let ty = match *alg {
            SignatureAlgorithm::ES256 => md_type::MBEDTLS_MD_SHA256,
            SignatureAlgorithm::ES384 => md_type::MBEDTLS_MD_SHA384,
            SignatureAlgorithm::ES512 => md_type::MBEDTLS_MD_SHA512,
            SignatureAlgorithm::PS256 => unimplemented!("handle PS256"),
        };

        (ty, md_info::from_type(ty).md(msg))
    }

    pub fn pk_from_privkey_pem(privkey_pem: &[u8], f_rng: *const c_void) -> Result<pk_context, mbedtls_error> {
        let mut pk = pk_context::new();

        pk.parse_key(privkey_pem, None, f_rng, core::ptr::null())?;

        Ok(pk)
    }
}
