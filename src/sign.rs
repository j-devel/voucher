use crate::{vec, Vec};
use crate::{VoucherError, SignatureAlgorithm};
use crate::debug_println;
use super::utils::minerva_mbedtls_utils::*;
use minerva_mbedtls::ifce::*;

impl crate::Sign for crate::Voucher {
    /// Signs the voucher using a PEM-encoded private key
    /// based on the signature algorithm `alg`.
    ///
    /// Returns a `&mut Self` reference if the voucher is signed.
    ///
    /// # Errors
    ///
    /// If the voucher is not signed, or the internal signing function fails, a `VoucherError::SigningFailed` is returned.
    ///
    /// # Examples
    ///
    /// ```
    /// use minerva_voucher::{Voucher, attr::*, SignatureAlgorithm, Sign};
    ///
    /// static KEY_PEM_F2_00_02: &[u8] = core::include_bytes!(
    ///     concat!(env!("CARGO_MANIFEST_DIR"), "/data/00-D0-E5-F2-00-02/key.pem"));
    ///
    /// // This is required when the `Sign` trait is backed by mbedtls v3.
    /// #[cfg(feature = "v3")]
    /// minerva_voucher::init_psa_crypto();
    ///
    /// let mut vrq = Voucher::new_vrq();
    ///
    /// vrq.set(Attr::Assertion(Assertion::Proximity))
    ///     .set(Attr::SerialNumber(b"00-D0-E5-F2-00-02".to_vec()));
    ///
    /// assert!(vrq.get_signature().is_none());
    /// vrq.sign(KEY_PEM_F2_00_02, SignatureAlgorithm::ES256).unwrap();
    /// assert!(vrq.get_signature().is_some());
    /// ```
    fn sign(&mut self, privkey_pem: &[u8], alg: SignatureAlgorithm) -> Result<&mut Self, VoucherError> {
        if let Err(err) = sign_with_mbedtls(privkey_pem, alg, self.to_sign(alg)) {
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
    (sig_out, sig_struct): (&mut Vec<u8>, &[u8])
) -> Result<(), mbedtls_error> {
    let mut sig = vec![];
    let (md_ty, ref hash) = compute_digest(sig_struct, &alg);

    let f_rng = pk_context::test_f_rng_ptr(); // TODO refactor
    let mut pk = pk_from_privkey_pem(privkey_pem, f_rng)?;
    pk.sign(md_ty, hash, &mut sig, f_rng, core::ptr::null())?;

    *sig_out = sig;

    Ok(())
}
