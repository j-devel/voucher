use crate::Vec;
use super::sid::{self, CborType, Cbor, Sid, SidDisc};
use super::yang::{Yang, YangEnum};
use core::convert::TryFrom;


pub type AttrDisc = u8;
pub const ATTR_ASSERTION: AttrDisc =                         0x00;
pub const ATTR_CREATED_ON: AttrDisc =                        0x01;
pub const ATTR_DOMAIN_CERT_REVOCATION_CHECKS: AttrDisc =     0x02;
pub const ATTR_EXPIRES_ON: AttrDisc =                        0x03;
pub const ATTR_IDEVID_ISSUER: AttrDisc =                     0x04;
pub const ATTR_LAST_RENEWAL_DATE: AttrDisc =                 0x05;
pub const ATTR_NONCE: AttrDisc =                             0x06;
pub const ATTR_PINNED_DOMAIN_CERT: AttrDisc =                0x07;
pub const ATTR_PINNED_DOMAIN_PUBK: AttrDisc =                0x20; // vch only
pub const ATTR_PINNED_DOMAIN_PUBK_SHA256: AttrDisc =         0x21; // vch only
pub const ATTR_PRIOR_SIGNED_VOUCHER_REQUEST: AttrDisc =      0x40; // vrq only
pub const ATTR_PROXIMITY_REGISTRAR_CERT: AttrDisc =          0x41; // vrq only
pub const ATTR_PROXIMITY_REGISTRAR_PUBK: AttrDisc =          0x42; // vrq only
pub const ATTR_PROXIMITY_REGISTRAR_PUBK_SHA256: AttrDisc =   0x43; // vrq only
pub const ATTR_SERIAL_NUMBER: AttrDisc =                     0x08;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Assertion {
    Verified,
    Logged,
    Proximity,
}

#[repr(u8)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Attr {
    Assertion(Assertion) =                   ATTR_ASSERTION,
    CreatedOn(u64) =                         ATTR_CREATED_ON,
    DomainCertRevocationChecks(bool) =       ATTR_DOMAIN_CERT_REVOCATION_CHECKS,
    ExpiresOn(u64) =                         ATTR_EXPIRES_ON,
    IdevidIssuer(Vec<u8>) =                  ATTR_IDEVID_ISSUER,
    LastRenewalDate(u64) =                   ATTR_LAST_RENEWAL_DATE,
    Nonce(Vec<u8>) =                         ATTR_NONCE,
    PinnedDomainCert(Vec<u8>) =              ATTR_PINNED_DOMAIN_CERT,
    PinnedDomainPubk(Vec<u8>) =              ATTR_PINNED_DOMAIN_PUBK,              // vch only
    PinnedDomainPubkSha256(Vec<u8>) =        ATTR_PINNED_DOMAIN_PUBK_SHA256,       // vch only
    PriorSignedVoucherRequest(Vec<u8>) =     ATTR_PRIOR_SIGNED_VOUCHER_REQUEST,    // vrq only
    ProximityRegistrarCert(Vec<u8>) =        ATTR_PROXIMITY_REGISTRAR_CERT,        // vrq only
    ProximityRegistrarPubk(Vec<u8>) =        ATTR_PROXIMITY_REGISTRAR_PUBK,        // vrq only
    ProximityRegistrarPubkSha256(Vec<u8>) =  ATTR_PROXIMITY_REGISTRAR_PUBK_SHA256, // vrq only
    SerialNumber(Vec<u8>) =                  ATTR_SERIAL_NUMBER,
}

const CBOR_TAG_UNIX_TIME: u64 = 0x01;

/* zzz ttt // todo: "Cbor for Attr" to be called from `impl Cbor for Yang {` of 'yang.rs'
let cbor = match self {
    Yang::DateAndTime(x) => Tag(CBOR_TAG_UNIX_TIME, Box::new(Integer(*x))),
    Yang::String(x) => StringAsBytes(x.clone()),
    Yang::Binary(x) => Bytes(x.clone()),
    Yang::Boolean(x) => if *x { True } else { False },
    Yang::Enumeration(x) => StringAsBytes(x.value().as_bytes().to_vec()),
};
 */

impl TryFrom<(&CborType, AttrDisc)> for Attr {
    type Error = ();

    fn try_from(input: (&CborType, AttrDisc)) -> Result<Self, Self::Error> {
        use CborType::*;

        let (cbor, adisc) = input;

/* zzz ttt
        match cbor { // !!!! adapt !!!!
            (Tag(tag, bx), YANG_DATE_AND_TIME) => {
                if *tag != CBOR_TAG_UNIX_TIME { return Err(()) }
                if let Integer(dat) = **bx { Ok(Yang::DateAndTime(dat)) } else { Err(()) }
            },
            (Bytes(x), YANG_STRING) /* permissive */ | (StringAsBytes(x), YANG_STRING) =>
                Ok(Yang::String(x.to_vec())),
            (StringAsBytes(x), YANG_BINARY) /* permissive */ | (Bytes(x), YANG_BINARY) =>
                Ok(Yang::Binary(x.to_vec())),
            (True, YANG_BOOLEAN) => Ok(Yang::Boolean(true)),
            (False, YANG_BOOLEAN) => Ok(Yang::Boolean(false)),
            (StringAsBytes(x), YANG_ENUMERATION) => {
                let cands = [
                    YangEnum::Verified,
                    YangEnum::Logged,
                    YangEnum::Proximity,
                ];
                let residue: Vec<_> = cands.iter()
                    .enumerate()
                    .filter_map(|(i, ye)| if ye.value().as_bytes() == x { Some(cands[i]) } else { None })
                    .collect();
                if residue.len() == 1 { Ok(Yang::Enumeration(residue[0])) } else { Err(()) }
            },
            _ => Err(()),
        }
*/
        let yang_enumeration = |_| Ok(Assertion::Proximity);
        let yang_dat = |_| Ok(42);
        let yang_boolean = |_| Ok(true);
        let yang_binary = |_| Ok(Vec::new());
        let yang_string = |_| Ok(Vec::new());

        let attr = match adisc {
            ATTR_ASSERTION => Attr::Assertion(yang_enumeration(cbor)?),
            ATTR_CREATED_ON => Attr::CreatedOn(yang_dat(cbor)?),
            ATTR_DOMAIN_CERT_REVOCATION_CHECKS => Attr::DomainCertRevocationChecks(yang_boolean(cbor)?),
            ATTR_EXPIRES_ON => Attr::ExpiresOn(yang_dat(cbor)?),
            ATTR_IDEVID_ISSUER => Attr::IdevidIssuer(yang_binary(cbor)?),
            ATTR_LAST_RENEWAL_DATE => Attr::LastRenewalDate(yang_dat(cbor)?),
            ATTR_NONCE => Attr::Nonce(yang_binary(cbor)?),
            ATTR_PINNED_DOMAIN_CERT => Attr::PinnedDomainCert(yang_binary(cbor)?),
            ATTR_PINNED_DOMAIN_PUBK => Attr::PinnedDomainPubk(yang_binary(cbor)?),
            ATTR_PINNED_DOMAIN_PUBK_SHA256 => Attr::PinnedDomainPubkSha256(yang_binary(cbor)?),
            ATTR_PRIOR_SIGNED_VOUCHER_REQUEST => Attr::PriorSignedVoucherRequest(yang_binary(cbor)?),
            ATTR_PROXIMITY_REGISTRAR_CERT => Attr::ProximityRegistrarCert(yang_binary(cbor)?),
            ATTR_PROXIMITY_REGISTRAR_PUBK => Attr::ProximityRegistrarPubk(yang_binary(cbor)?),
            ATTR_PROXIMITY_REGISTRAR_PUBK_SHA256 => Attr::ProximityRegistrarPubkSha256(yang_binary(cbor)?),
            ATTR_SERIAL_NUMBER => Attr::SerialNumber(yang_string(cbor)?),
            _ => return Err(()),
        };

        Ok(attr)
    }
}

impl Attr {
    pub fn into_yang(self) -> Yang {
        match self {
            Attr::Assertion(_) => Yang::Enumeration(self),
            Attr::DomainCertRevocationChecks(_) => Yang::Boolean(self),
            Attr::CreatedOn(_) |
            Attr::ExpiresOn(_) |
            Attr::LastRenewalDate(_) => Yang::DateAndTime(self),
            Attr::IdevidIssuer(_) |
            Attr::Nonce(_) |
            Attr::PinnedDomainCert(_) |
            Attr::PinnedDomainPubk(_) |
            Attr::PinnedDomainPubkSha256(_) |
            Attr::PriorSignedVoucherRequest(_) |
            Attr::ProximityRegistrarCert(_) |
            Attr::ProximityRegistrarPubk(_) |
            Attr::ProximityRegistrarPubkSha256(_) => Yang::Binary(self),
            Attr::SerialNumber(_) => Yang::String(self),
        }
    }

    pub fn resolve_sid(sid: &Sid) -> Option<(AttrDisc, &Yang)> {
        use Sid::*;

        match sid {
            VchTopLevel(_) | VrqTopLevel(_) => None,
            VchAssertion(yg) | VrqAssertion(yg) => Some((ATTR_ASSERTION, yg)),
            VchCreatedOn(yg) | VrqCreatedOn(yg) => Some((ATTR_CREATED_ON, yg)),
            VchDomainCertRevocationChecks(yg) | VrqDomainCertRevocationChecks(yg) => Some((ATTR_DOMAIN_CERT_REVOCATION_CHECKS, yg)),
            VchExpiresOn(yg) | VrqExpiresOn(yg) => Some((ATTR_EXPIRES_ON, yg)),
            VchIdevidIssuer(yg) | VrqIdevidIssuer(yg) => Some((ATTR_IDEVID_ISSUER, yg)),
            VchLastRenewalDate(yg) | VrqLastRenewalDate(yg) => Some((ATTR_LAST_RENEWAL_DATE, yg)),
            VchNonce(yg) | VrqNonce(yg) => Some((ATTR_NONCE, yg)),
            VchPinnedDomainCert(yg) | VrqPinnedDomainCert(yg) => Some((ATTR_PINNED_DOMAIN_CERT, yg)),
            VchPinnedDomainPubk(yg) => Some((ATTR_PINNED_DOMAIN_PUBK, yg)),
            VchPinnedDomainPubkSha256(yg) => Some((ATTR_PINNED_DOMAIN_PUBK_SHA256, yg)),
            VrqPriorSignedVoucherRequest(yg) => Some((ATTR_PRIOR_SIGNED_VOUCHER_REQUEST, yg)),
            VrqProximityRegistrarCert(yg) => Some((ATTR_PROXIMITY_REGISTRAR_CERT, yg)),
            VrqProximityRegistrarPubk(yg) => Some((ATTR_PROXIMITY_REGISTRAR_PUBK, yg)),
            VrqProximityRegistrarPubkSha256(yg) => Some((ATTR_PROXIMITY_REGISTRAR_PUBK_SHA256, yg)),
            VchSerialNumber(yg) | VrqSerialNumber(yg) => Some((ATTR_SERIAL_NUMBER, yg)),
        }
    }

    pub fn to_sid_disc(adisc: AttrDisc, is_vrq: bool) -> Option<SidDisc> {
        use sid::*;

        let sdisc_none: SidDisc = 0;
        let sdisc = match adisc {
            ATTR_ASSERTION => if is_vrq { SID_VRQ_ASSERTION } else { SID_VCH_ASSERTION },
            ATTR_CREATED_ON => if is_vrq { SID_VRQ_CREATED_ON } else { SID_VCH_CREATED_ON },
            ATTR_DOMAIN_CERT_REVOCATION_CHECKS => if is_vrq { SID_VRQ_DOMAIN_CERT_REVOCATION_CHECKS } else { SID_VCH_DOMAIN_CERT_REVOCATION_CHECKS },
            ATTR_EXPIRES_ON => if is_vrq { SID_VRQ_EXPIRES_ON } else { SID_VCH_EXPIRES_ON },
            ATTR_IDEVID_ISSUER => if is_vrq { SID_VRQ_IDEVID_ISSUER } else { SID_VCH_IDEVID_ISSUER },
            ATTR_LAST_RENEWAL_DATE => if is_vrq { SID_VRQ_LAST_RENEWAL_DATE } else { SID_VCH_LAST_RENEWAL_DATE },
            ATTR_NONCE => if is_vrq { SID_VRQ_NONCE } else { SID_VCH_NONCE },
            ATTR_PINNED_DOMAIN_CERT => if is_vrq { SID_VRQ_PINNED_DOMAIN_CERT } else { SID_VCH_PINNED_DOMAIN_CERT },
            ATTR_PINNED_DOMAIN_PUBK => if is_vrq { sdisc_none } else { SID_VCH_PINNED_DOMAIN_PUBK },
            ATTR_PINNED_DOMAIN_PUBK_SHA256 => if is_vrq { sdisc_none } else { SID_VCH_PINNED_DOMAIN_PUBK_SHA256 },
            ATTR_PRIOR_SIGNED_VOUCHER_REQUEST => if is_vrq { SID_VRQ_PRIOR_SIGNED_VOUCHER_REQUEST } else { sdisc_none },
            ATTR_PROXIMITY_REGISTRAR_CERT => if is_vrq { SID_VRQ_PROXIMITY_REGISTRAR_CERT } else { sdisc_none },
            ATTR_PROXIMITY_REGISTRAR_PUBK => if is_vrq { SID_VRQ_PROXIMITY_REGISTRAR_PUBK } else { sdisc_none },
            ATTR_PROXIMITY_REGISTRAR_PUBK_SHA256 => if is_vrq { SID_VRQ_PROXIMITY_REGISTRAR_PUBK_SHA256 } else { sdisc_none },
            ATTR_SERIAL_NUMBER => if is_vrq { SID_VRQ_SERIAL_NUMBER } else { SID_VCH_SERIAL_NUMBER },
            _ => sdisc_none,
        };

        if sdisc == sdisc_none { None } else { Some(sdisc) }
    }
}
