use crate::{println, Vec, BTreeMap, BTreeSet};
use crate::debug_println;
use super::sid::{CborType, Cbor, Sid, SidDisc, TopLevel, SID_VCH_TOP_LEVEL, SID_VRQ_TOP_LEVEL};
use super::yang::Yang;
use core::convert::TryFrom;

#[derive(Clone, PartialEq, Debug)]
pub enum SidData {
    Voucher(BTreeSet<Sid>),
    VoucherRequest(BTreeSet<Sid>),
}

// TODO - checker on serialize/sign/****
// #   +---- voucher
// #      +---- created-on?                      yang:date-and-time
// #      +---- expires-on?                      yang:date-and-time
// #      +---- assertion                        enumeration
// #      +---- serial-number                    string
// #      +---- idevid-issuer?                   binary
// #      +---- pinned-domain-cert?              binary
// #      +---- domain-cert-revocation-checks?   boolean
// #      +---- nonce?                           binary
// #      +---- last-renewal-date?               yang:date-and-time
// #      +---- prior-signed-voucher-request?    binary
// #      +---- proximity-registrar-cert?        binary
impl SidData {
    pub fn new_vch() -> Self {
        Self::Voucher(BTreeSet::new())
    }

    pub fn new_vrq() -> Self {
        Self::VoucherRequest(BTreeSet::new())
    }

    pub fn new_vch_cbor() -> Self {
        Self::Voucher(BTreeSet::from([Sid::VchTopLevel(TopLevel::VoucherVoucher)]))
    }

    pub fn new_vrq_cbor() -> Self {
        Self::VoucherRequest(BTreeSet::from([Sid::VrqTopLevel(TopLevel::VoucherRequestVoucher)]))
    }

    pub fn replace(&mut self, sid: Sid) -> Option<Sid> {
        self.inner_mut().replace(sid)
    }

    pub fn remove(&mut self, sdisc: SidDisc) -> bool {
        self.take(sdisc).is_some()
    }

    pub fn take(&mut self, sdisc: SidDisc) -> Option<Sid> {
        let yg_dummy = Yang::DateAndTime(crate::Attr::CreatedOn(0));
        let sid = Sid::try_from((yg_dummy, sdisc)).ok()?;

        self.inner_mut().take(&sid)
    }

    fn inner_mut(&mut self) -> &mut BTreeSet<Sid> {
        match self {
            Self::Voucher(set) => set,
            Self::VoucherRequest(set) => set,
        }
    }

    fn inner(&self) -> (&BTreeSet<Sid>, bool /* is_vrq */) {
        match self {
            Self::Voucher(set) => (set, false),
            Self::VoucherRequest(set) => (set, true),
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &Sid> + '_ {
        self.inner().0.iter()
    }

    pub fn is_vrq(&self) -> bool {
        self.inner().1
    }

    pub fn dump(&self) {
        println!("==== SidData::dump()");
        println!("  {:?}", self);
        println!("====");
    }
}

impl Cbor for SidData {
    fn to_cbor(&self) -> Option<CborType> {
        use CborType::*;

        let (set, is_vrq) = self.inner();
        let tl = if is_vrq {
            &Sid::VrqTopLevel(TopLevel::VoucherRequestVoucher)
        } else {
            &Sid::VchTopLevel(TopLevel::VoucherVoucher)
        };

        if set.contains(tl) {
            Some(Map(BTreeMap::from([(Integer(tl.disc()), {
                let mut attrs = BTreeMap::new();
                set.iter()
                    .filter(|sid| !matches!(*sid, Sid::VchTopLevel(_) | Sid::VrqTopLevel(_)))
                    .for_each(|sid| {
                        let delta = sid.disc() - tl.disc();
                        attrs.insert(Integer(delta), sid.to_cbor().unwrap());
                    });

                Map(attrs)
            })])))
        } else {
            println!("to_cbor(): not a CBOR vch/vrq instance");

            None
        }
    }
}

impl TryFrom<CborType> for SidData {
    type Error = ();

    fn try_from(sidhash: CborType) -> Result<Self, Self::Error> {
        from_sidhash(sidhash).ok_or(())
    }
}

fn from_sidhash(sidhash: CborType) -> Option<SidData> {
    use super::cose_sig::map_value_from;
    use CborType::*;

    let (is_vrq, btmap, sid_tl_disc, sid_tl) =
        if let Ok(Map(btmap)) = map_value_from(&sidhash, &Integer(SID_VCH_TOP_LEVEL)) {
            (false, btmap, SID_VCH_TOP_LEVEL, Sid::VchTopLevel(TopLevel::VoucherVoucher))
        } else if let Ok(Map(btmap)) = map_value_from(&sidhash, &Integer(SID_VRQ_TOP_LEVEL)) {
            (true, btmap, SID_VRQ_TOP_LEVEL, Sid::VrqTopLevel(TopLevel::VoucherRequestVoucher))
        } else {
            return None;
        };

    let mut sd = if is_vrq { SidData::new_vrq() } else { SidData::new_vch() };
    sd.replace(sid_tl);

    btmap.iter()
        .filter_map(|(k, v)| if let Integer(delta) = k { Some((sid_tl_disc + delta, v)) } else { None })
        .map(|(sid_disc, v)| Sid::try_from(
            (Yang::try_from((v, sid_disc)).unwrap(), sid_disc)).unwrap())
        .for_each(|sid| { sd.replace(sid); });

    Some(sd)
}

pub fn content_comp(a: &[u8], b: &[u8]) -> bool {
    debug_println!("content_comp(): {} {}", a.len(), b.len());
    if a.len() != b.len() { return false; }

    let mut a = a.to_vec();
    let mut b = b.to_vec();
    a.sort();
    b.sort();

    a == b
}

pub fn content_comp_permissive<'x>(a: &'x[u8], b: &'x[u8]) -> bool {
    let mask = |s: &'x[u8]| {
        // Mask CBOR `CborType::{StringAsBytes,Bytes}` header bytes (including some false positives)
        move |(i, val): (usize, &u8)| {
            if i == 0 { *val } else {
                match s[i - 1] { // "maybe" SID delta
                    5 /* idevid-issuer */ | 7..=13 => 0,
                    _ => *val,
                }
            }
        }
    };

    content_comp(
        &a.iter().enumerate().map(mask(a)).collect::<Vec<_>>(),
        &b.iter().enumerate().map(mask(b)).collect::<Vec<_>>())
}

#[test]
fn test_sid_data_vch_f2_00_02() {
    use crate::{vec, attr::{Attr, Assertion}};
    use super::yang::Yang;

    let sd = SidData::Voucher(BTreeSet::from([
        Sid::VchTopLevel(TopLevel::VoucherVoucher),
        Sid::VchAssertion(Yang::Enumeration(Attr::Assertion(Assertion::Logged))),
        Sid::VchCreatedOn(Yang::DateAndTime(Attr::CreatedOn(1599525239))),
        Sid::VchNonce(Yang::Binary(Attr::Nonce(vec![88, 83, 121, 70, 52, 76, 76, 73, 105, 113, 85, 50, 45, 79, 71, 107, 54, 108, 70, 67, 65, 103]))),
        Sid::VchPinnedDomainCert(Yang::Binary(Attr::PinnedDomainCert("MIIB0TCCAVagAwIBAgIBAjAKBggqhkjOPQQDAzBxMRIwEAYKCZImiZPyLGQBGRYCY2ExGTAXBgoJkiaJk/IsZAEZFglzYW5kZWxtYW4xQDA+BgNVBAMMNyM8U3lzdGVtVmFyaWFibGU6MHgwMDAwMDAwNGY5MTFhMD4gVW5zdHJ1bmcgRm91bnRhaW4gQ0EwHhcNMTcxMTA3MjM0NTI4WhcNMTkxMTA3MjM0NTI4WjBDMRIwEAYKCZImiZPyLGQBGRYCY2ExGTAXBgoJkiaJk/IsZAEZFglzYW5kZWxtYW4xEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJZlUHI0up/l3eZf9vCBb+lInoEMEgc7Ro+XZCtjAI0CD1fJfJR/hIyyDmHWyYiNFbRCH9fyarfkzgX4p0zTizqjDTALMAkGA1UdEwQCMAAwCgYIKoZIzj0EAwMDaQAwZgIxALQMNurf8tv50lROD5DQXHEOJJNW3QV2g9QEdDSk2MY+AoSrBSmGSNjh4olEOhEuLgIxAJ4nWfNw+BjbZmKiIiUEcTwHMhGVXaMHY/F7n39wwKcBBSOndNPqCpOELl6bq3CZqQ==".as_bytes().to_vec()))),
        Sid::VchSerialNumber(Yang::String(Attr::SerialNumber("00-D0-E5-F2-00-02".as_bytes().to_vec()))),
    ]));
    println!("sd: {:?}", sd);

    use super::tests::content_vch_f2_00_02;
    assert!(content_comp_permissive(&sd.serialize().unwrap(), &content_vch_f2_00_02()));
}

#[test]
fn test_sid_data_vch_jada() {
    use crate::{vec, attr::{Attr, Assertion}};
    use super::yang::Yang;

    let sd = SidData::Voucher(BTreeSet::from([
        Sid::VchTopLevel(TopLevel::VoucherVoucher),
        Sid::VchAssertion(Yang::Enumeration(Attr::Assertion(Assertion::Proximity))),
        Sid::VchCreatedOn(Yang::DateAndTime(Attr::CreatedOn(1475868702))),
        Sid::VchExpiresOn(Yang::DateAndTime(Attr::ExpiresOn(1506816000))),
        Sid::VchNonce(Yang::Binary(Attr::Nonce(vec![97, 98, 99, 100, 49, 50, 51, 52, 53]))),
        Sid::VchPinnedDomainPubk(Yang::Binary(Attr::PinnedDomainPubk(vec![77, 70, 107, 119, 69, 119, 89, 72, 75, 111, 90, 73, 122, 106, 48, 67, 65, 81, 89, 73, 75, 111, 90, 73, 122, 106, 48, 68, 65, 81, 99, 68, 81, 103, 65, 69, 108, 109, 86, 81, 99, 106, 83, 54, 110, 43, 88, 100, 53, 108, 47, 50, 56, 73, 70, 118, 54, 85, 105, 101, 103, 81, 119, 83, 66, 122, 116, 71, 106, 53, 100, 107, 75, 50, 77, 65, 106, 81, 73, 80, 86, 56, 108, 56, 108, 72, 43, 69, 106, 76, 73, 79, 89, 100, 98, 74, 105, 73, 48, 86, 116, 69, 73, 102, 49, 47, 74, 113, 116, 43, 84, 79, 66, 102, 105, 110, 84, 78, 79, 76, 79, 103, 61, 61]))),
        Sid::VchSerialNumber(Yang::String(Attr::SerialNumber("JADA123456789".as_bytes().to_vec()))),
    ]));
    println!("sd: {:?}", sd);

    use super::tests::content_vch_jada;
    assert!(content_comp_permissive(&sd.serialize().unwrap(), &content_vch_jada()));
}
