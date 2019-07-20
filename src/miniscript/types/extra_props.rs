//! Other miscellaneous type properties which are not related to
//! correctness or malleability.

use super::{ErrorKind, Property, Error};
use AstElem;

/// Whether a fragment is OK to be used in non-segwit scripts
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum LegacySafe {
    /// The fragment can be used in pre-segwit contexts without concern
    /// about malleability attacks/unbounded 3rd-party fee stuffing. This
    /// means it has no `pk_h` constructions (cannot estimate public key
    /// size from a hash) and no `d:`/`or_i` constructions (cannot control
    /// the size of the switch input to `OP_IF`)
    LegacySafe,
    /// This fragment can only be safely used with Segwit
    SegwitOnly,
}

/// Structure representing the extra type properties of a fragment which are
/// relevant to legacy(pre-segwit) safety and fee estimation. If a fragment is
/// used in pre-segwit transactions it will only be malleable but still is
/// correct and sound.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct ExtData{
    ///enum sorting whether the fragment is safe to be in used in pre-segwit context
    legacy_safe: LegacySafe,
    /// The number of bytes needed to encode its scriptpubkey
    pk_cost: usize,
    /// Whether this fragment can be verify-wrapped for free
    has_verify_form: bool,
}

impl Property for ExtData {
    fn sanity_checks(&self) {
        //No sanity checks
    }

    fn from_true() -> Self {
        ExtData {
            legacy_safe: LegacySafe::LegacySafe,
            pk_cost: 1,
            has_verify_form: false,
        }
    }

    fn from_false() -> Self {
        ExtData {
            legacy_safe: LegacySafe::LegacySafe,
            pk_cost: 1,
            has_verify_form: false,
        }
    }

    fn from_pk() -> Self {
        ExtData {
            legacy_safe: LegacySafe::LegacySafe,
            pk_cost: 34,
            has_verify_form: false,
        }
    }

    fn from_pk_h() -> Self {
        ExtData {
            legacy_safe: LegacySafe::SegwitOnly,
            pk_cost: 24,
            has_verify_form: false,
        }
    }

    fn from_multi(k: usize, n: usize) -> Self {
        let num_cost = match(k > 16, n > 16) {
            (true, true) => 4,
            (false, true) => 3,
            (true, false) => 3,
            (false, false) => 2,
        };
        ExtData {
            legacy_safe: LegacySafe::LegacySafe,
            pk_cost: num_cost + 34 * n + 1,
            has_verify_form: true,
        }
    }

    fn from_hash() -> Self {
        //never called directly
        unreachable!()
    }

    fn from_sha256() -> Self {
        ExtData {
            legacy_safe: LegacySafe::LegacySafe,
            pk_cost: 33 + 6,
            has_verify_form: true,
        }
    }

    fn from_hash256() -> Self {
        ExtData {
            legacy_safe: LegacySafe::LegacySafe,
            pk_cost: 33 + 6,
            has_verify_form: true,
        }
    }

    fn from_ripemd160() -> Self {
        ExtData {
            legacy_safe: LegacySafe::LegacySafe,
            pk_cost: 21 + 6,
            has_verify_form: true,
        }
    }

    fn from_hash160() -> Self {
        ExtData {
            legacy_safe: LegacySafe::LegacySafe,
            pk_cost: 21 + 6,
            has_verify_form: true,
        }
    }

    fn from_time(t: u32) -> Self {
        ExtData {
            legacy_safe: LegacySafe::LegacySafe,
            pk_cost: script_num_cost(t) + 1,
            has_verify_form: false,
        }
    }
    fn cast_alt(self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            legacy_safe: self.legacy_safe,
            pk_cost: self.pk_cost + 2,
            has_verify_form: false,
        })
    }

    fn cast_swap(self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            legacy_safe: self.legacy_safe,
            pk_cost: self.pk_cost + 1,
            has_verify_form: self.has_verify_form,
        })
    }

    fn cast_check(self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            legacy_safe: self.legacy_safe,
            pk_cost: self.pk_cost + 1,
            has_verify_form: true,
        })
    }

    fn cast_dupif(self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            legacy_safe: LegacySafe::SegwitOnly,
            pk_cost: self.pk_cost + 3,
            has_verify_form: false,
        })
    }

    fn cast_verify(self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            legacy_safe: self.legacy_safe,
            pk_cost: self.pk_cost + if self.has_verify_form { 0 } else { 1 },
            has_verify_form: false,
        })
    }

    fn cast_nonzero(self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            legacy_safe: self.legacy_safe,
            pk_cost: self.pk_cost + 4,
            has_verify_form: false,
        })
    }

    fn cast_zeronotequal(self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            legacy_safe: self.legacy_safe,
            pk_cost: self.pk_cost + 1,
            has_verify_form: false,
        })
    }

    fn cast_true(self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            legacy_safe: self.legacy_safe,
            pk_cost: self.pk_cost + 1,
            has_verify_form: false,
        })
    }

    fn cast_or_i_false(self) -> Result<Self, ErrorKind> {
        // never called directly
        unreachable!()
    }

    fn cast_unlikely(self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            legacy_safe: self.legacy_safe,
            pk_cost: self.pk_cost + 4,
            has_verify_form: false,
        })
    }

    fn cast_likely(self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            legacy_safe: self.legacy_safe,
            pk_cost: self.pk_cost + 4,
            has_verify_form: false,
        })
    }

    fn and_b(l: Self, r: Self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            legacy_safe: legacy_safe2(l.legacy_safe, r.legacy_safe),
            pk_cost: l.pk_cost + r.pk_cost + 1,
            has_verify_form: false,
        })
    }

    fn and_v(l: Self, r: Self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            legacy_safe: legacy_safe2(l.legacy_safe, r.legacy_safe),
            pk_cost: l.pk_cost + r.pk_cost,
            has_verify_form: r.has_verify_form,
        })
    }

    fn or_b(l: Self, r: Self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            legacy_safe: legacy_safe2(l.legacy_safe, r.legacy_safe),
            pk_cost: l.pk_cost + r.pk_cost + 1,
            has_verify_form: false,
        })
    }

    fn or_d(l: Self, r: Self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            legacy_safe: LegacySafe::SegwitOnly,
            pk_cost: l.pk_cost + r.pk_cost + 3,
            has_verify_form: l.has_verify_form && r.has_verify_form,
        })
    }

    fn or_c(l: Self, r: Self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            legacy_safe: legacy_safe2(l.legacy_safe, r.legacy_safe),
            pk_cost: l.pk_cost + r.pk_cost + 2,
            has_verify_form: false,
        })
    }

    fn or_i(l: Self, r: Self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            legacy_safe: legacy_safe2(l.legacy_safe, r.legacy_safe),
            pk_cost: l.pk_cost + r.pk_cost + 3,
            has_verify_form: l.has_verify_form && r.has_verify_form,
        })
    }

    fn and_or(_a: Self, _b: Self, _c: Self) -> Result<Self, ErrorKind> {
        unimplemented!("compiler doesn't support andor yet")
    }

    fn threshold<S>(
        k: usize,
        n: usize,
        mut sub_ck: S,
    ) -> Result<Self, ErrorKind>
        where S: FnMut(usize) -> Result<Self, ErrorKind>
    {
        let mut pk_cost = 1 + script_num_cost(k as u32);
        let mut legacy_safe = LegacySafe::LegacySafe;
        for i in 0..n {

            let sub = sub_ck(i)?;
            pk_cost += sub.pk_cost;
            legacy_safe = legacy_safe2(legacy_safe, sub.legacy_safe);
        }
        Ok(ExtData {
            legacy_safe: legacy_safe,
            pk_cost: pk_cost,
            has_verify_form: true,
        })
    }

    /// Compute the type of a fragment assuming all the children of
    /// Miniscript have been computed already.
    fn type_check<Pk, Pkh, C>(
        fragment: &AstElem<Pk, Pkh>,
        mut child: C,
    ) -> Result<Self, Error<Pk, Pkh>>
        where
            C: FnMut(usize) -> Option<Self>,
            Pk: Clone,
            Pkh: Clone,
    {
        let wrap_err = |result: Result<Self, ErrorKind>| result
            .map_err(|kind| Error {
                fragment: fragment.clone(),
                error: kind,
            });

        let ret = match *fragment {
            AstElem::True => Ok(Self::from_true()),
            AstElem::False => Ok(Self::from_false()),
            AstElem::Pk(..) => Ok(Self::from_pk()),
            AstElem::PkH(..) => Ok(Self::from_pk_h()),
            AstElem::ThreshM(k, ref pks) => {
                if k == 0 {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::ZeroThreshold,
                    });
                }
                if k > pks.len() {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::OverThreshold(k, pks.len()),
                    });
                }
                Ok(Self::from_multi(k, pks.len()))
            },
            AstElem::After(t) => {
                if t == 0 {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::ZeroTime,
                    });
                }
                Ok(Self::from_after(t))
            },
            AstElem::Older(t) => {
                // FIXME check if t > 2^31 - 1
                if t == 0 {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::ZeroTime,
                    });
                }
                Ok(Self::from_older(t))
            },
            AstElem::Sha256(..) => Ok(Self::from_sha256()),
            AstElem::Hash256(..) => Ok(Self::from_hash256()),
            AstElem::Ripemd160(..) => Ok(Self::from_ripemd160()),
            AstElem::Hash160(..) => Ok(Self::from_hash160()),
            AstElem::Alt(ref sub) =>
                wrap_err(Self::cast_alt(sub.ext.clone())),
            AstElem::Swap(ref sub) =>
                wrap_err(Self::cast_swap(sub.ext.clone())),
            AstElem::Check(ref sub) =>
                wrap_err(Self::cast_check(sub.ext.clone())),
            AstElem::DupIf(ref sub) =>
                wrap_err(Self::cast_dupif(sub.ext.clone())),
            AstElem::Verify(ref sub) =>
                wrap_err(Self::cast_verify(sub.ext.clone())),
            AstElem::NonZero(ref sub) =>
                wrap_err(Self::cast_nonzero(sub.ext.clone())),
            AstElem::ZeroNotEqual(ref sub) =>
                wrap_err(Self::cast_zeronotequal(sub.ext.clone())),
            AstElem::AndB(ref l, ref r) => {
                let ltype = l.ext.clone();
                let rtype = r.ext.clone();
                wrap_err(Self::and_b(ltype, rtype))
            },
            AstElem::AndV(ref l, ref r) => {
                let ltype = l.ext.clone();
                let rtype = r.ext.clone();
                wrap_err(Self::and_v(ltype, rtype))
            },
            AstElem::OrB(ref l, ref r) => {
                let ltype = l.ext.clone();
                let rtype = r.ext.clone();
                wrap_err(Self::or_b(ltype, rtype))
            },
            AstElem::OrD(ref l, ref r) => {
                let ltype = l.ext.clone();
                let rtype = r.ext.clone();
                wrap_err(Self::or_d(ltype, rtype))
            },
            AstElem::OrC(ref l, ref r) => {
                let ltype = l.ext.clone();
                let rtype = r.ext.clone();
                wrap_err(Self::or_c(ltype, rtype))
            },
            AstElem::OrI(ref l, ref r) => {
                let ltype = l.ext.clone();
                let rtype = r.ext.clone();
                wrap_err(Self::or_i(ltype, rtype))
            },
            AstElem::AndOr(ref a, ref b, ref c) => {
                let atype = a.ext.clone();
                let btype = b.ext.clone();
                let ctype = c.ext.clone();
                wrap_err(Self::and_or(atype, btype, ctype))
            },
            AstElem::Thresh(k, ref subs) => {
                if k == 0 {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::ZeroThreshold,
                    });
                }
                if k > subs.len() {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::OverThreshold(k, subs.len()),
                    });
                }

                let mut last_err_frag = None;
                let res = Self::threshold(
                    k,
                    subs.len(),
                    |n| Ok(subs[n].ext.clone())
                );

                res.map_err(|kind| Error {
                    fragment: last_err_frag.unwrap_or(fragment.clone()),
                    error: kind,
                })
            },
        };
        if let Ok(ref ret) = ret {
            ret.sanity_checks()
        }
        ret
    }
}

fn legacy_safe2(a: LegacySafe, b: LegacySafe) -> LegacySafe{
    match (a,b){
        (LegacySafe::LegacySafe, LegacySafe::LegacySafe) => LegacySafe::LegacySafe,
        _ => LegacySafe::SegwitOnly
    }
}

fn script_num_cost(n: u32) -> usize {
    if n <= 16 {
        1
    } else if n < 0x80 {
        2
    } else if n < 0x8000 {
        3
    } else if n < 0x800000 {
        4
    } else {
        5
    }
}
