use crate::{Voucher, Validate, VoucherError, SignatureAlgorithm};
use crate::debug_println;
use super::utils::minerva_mbedtls_utils::*;
use minerva_mbedtls::ifce::*;

impl Validate for Voucher {
    /// Validates the voucher using a PEM-encoded certificate.
    /// If the certificate `pem` is `None`, `signer_cert` attached to the voucher (see [`Voucher::set_signer_cert`](crate::Voucher::set_signer_cert)), if any, is used instead.
    ///
    /// Returns a `&Self` reference if the voucher is validated.
    ///
    /// # Errors
    ///
    /// If the voucher is not validated, or the internal validation function fails, a `VoucherError::ValidationFailed` is returned.
    ///
    /// # Examples
    ///
    /// ```
    /// use minerva_voucher::{Voucher, Validate};
    /// use core::convert::TryFrom;
    ///
    /// static VCH_F2_00_02: &[u8] = core::include_bytes!(
    ///     concat!(env!("CARGO_MANIFEST_DIR"), "/data/00-D0-E5-F2-00-02/voucher_00-D0-E5-F2-00-02.vch"));
    /// static MASA_CRT_F2_00_02: &[u8] = core::include_bytes!(
    ///     concat!(env!("CARGO_MANIFEST_DIR"), "/data/00-D0-E5-F2-00-02/masa.crt"));
    ///
    /// // This is required when the `Validate` trait is backed by mbedtls.
    /// minerva_voucher::init_psa_crypto();
    ///
    /// let vch = Voucher::try_from(VCH_F2_00_02).unwrap();
    ///
    /// assert!(vch.validate(Some(MASA_CRT_F2_00_02)).is_ok());
    /// ```
    fn validate(&self, pem: Option<&[u8]>) -> Result<&Self, VoucherError> {
        let err = Err(VoucherError::ValidationFailed);
        validate_with_mbedtls(pem, self.to_validate())
            .map_or_else(|e| {
                debug_println!("validate(): mbedtls_error: {}", e);
                err
            }, |x| if x { Ok(self) } else { err })
    }
}

pub fn validate_with_mbedtls(
    pem: Option<&[u8]>,
    (signer_cert, sig_alg, msg): (Option<&[u8]>, Option<(&[u8], &SignatureAlgorithm)>, &[u8])
) -> Result<bool, mbedtls_error> {
    if sig_alg.is_none() { return Ok(false); }
    let (signature, alg) = sig_alg.unwrap();
    let (md_ty, ref hash) = compute_digest(msg, alg);

    if let Some(pem) = pem {
        let f_rng = pk_context::test_f_rng_ptr(); // TODO refactor
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
        debug_println!("validate(): Neither external masa cert nor signer cert is available.");
        Ok(false)
    }
}
