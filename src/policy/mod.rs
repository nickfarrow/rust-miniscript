// Miniscript
// Written in 2018 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//!  Script Policies
//!
//! Tools for representing Bitcoin scriptpubkeys as abstract spending policies.
//! These may be compiled to Miniscript, which contains extra information to
//! describe the exact representation as Bitcoin script.
//!
//! The format represents EC public keys abstractly to allow wallets to replace
//! these with BIP32 paths, pay-to-contract instructions, etc.
//!

#[cfg(feature = "compiler")]
pub mod compiler;
pub mod concrete;
pub mod semantic;

use descriptor::Descriptor;
use miniscript::Miniscript;
use Terminal;

pub use self::concrete::Policy as Concrete;
/// Semantic policies are "abstract" policies elsewhere; but we
/// avoid this word because it is a reserved keyword in Rust
pub use self::semantic::Policy as Semantic;
use MiniscriptKey;

/// Trait describing script representations which can be lifted into
/// an abstract policy, by discarding information.
/// After Lifting all policies are converted into `KeyHash(Pk::HasH)` to
/// maintain the following invariant:
/// `Lift(Concrete) == Concrete -> Miniscript -> Script -> Miniscript -> Semantic`
pub trait Liftable<Pk: MiniscriptKey> {
    /// Convert the object into an abstract policy
    fn lift(&self) -> Semantic<Pk>;
}

impl<Pk: MiniscriptKey> Liftable<Pk> for Miniscript<Pk> {
    fn lift(&self) -> Semantic<Pk> {
        self.as_inner().lift()
    }
}

impl<Pk: MiniscriptKey> Liftable<Pk> for Terminal<Pk> {
    fn lift(&self) -> Semantic<Pk> {
        match *self {
            Terminal::Pk(ref pk) => Semantic::KeyHash(pk.to_pubkeyhash()),
            Terminal::PkH(ref pkh) => Semantic::KeyHash(pkh.clone()),
            Terminal::After(t) => Semantic::After(t),
            Terminal::Older(t) => Semantic::Older(t),
            Terminal::Sha256(h) => Semantic::Sha256(h),
            Terminal::Hash256(h) => Semantic::Hash256(h),
            Terminal::Ripemd160(h) => Semantic::Ripemd160(h),
            Terminal::Hash160(h) => Semantic::Hash160(h),
            Terminal::True => Semantic::Trivial,
            Terminal::False => Semantic::Unsatisfiable,
            Terminal::Alt(ref sub)
            | Terminal::Swap(ref sub)
            | Terminal::Check(ref sub)
            | Terminal::DupIf(ref sub)
            | Terminal::Verify(ref sub)
            | Terminal::NonZero(ref sub)
            | Terminal::ZeroNotEqual(ref sub) => sub.node.lift(),
            Terminal::AndV(ref left, ref right) | Terminal::AndB(ref left, ref right) => {
                Semantic::And(vec![left.node.lift(), right.node.lift()])
            }
            Terminal::AndOr(ref a, ref b, ref c) => Semantic::Or(vec![
                Semantic::And(vec![a.node.lift(), c.node.lift()]),
                b.node.lift(),
            ]),
            Terminal::OrB(ref left, ref right)
            | Terminal::OrD(ref left, ref right)
            | Terminal::OrC(ref left, ref right)
            | Terminal::OrI(ref left, ref right) => {
                Semantic::Or(vec![left.node.lift(), right.node.lift()])
            }
            Terminal::Thresh(k, ref subs) => {
                Semantic::Threshold(k, subs.into_iter().map(|s| s.node.lift()).collect())
            }
            Terminal::ThreshM(k, ref keys) => Semantic::Threshold(
                k,
                keys.into_iter()
                    .map(|k| Semantic::KeyHash(k.to_pubkeyhash()))
                    .collect(),
            ),
        }
        .normalized()
    }
}

impl<Pk: MiniscriptKey> Liftable<Pk> for Descriptor<Pk> {
    fn lift(&self) -> Semantic<Pk> {
        match *self {
            Descriptor::Bare(ref d)
            | Descriptor::Sh(ref d)
            | Descriptor::Wsh(ref d)
            | Descriptor::ShWsh(ref d) => d.node.lift(),
            Descriptor::Pk(ref p)
            | Descriptor::Pkh(ref p)
            | Descriptor::Wpkh(ref p)
            | Descriptor::ShWpkh(ref p) => Semantic::KeyHash(p.to_pubkeyhash()),
        }
    }
}

impl<Pk: MiniscriptKey> Liftable<Pk> for Semantic<Pk> {
    fn lift(&self) -> Semantic<Pk> {
        self.clone()
    }
}

impl<Pk: MiniscriptKey> Liftable<Pk> for Concrete<Pk> {
    fn lift(&self) -> Semantic<Pk> {
        match *self {
            Concrete::Key(ref pk) => Semantic::KeyHash(pk.to_pubkeyhash()),
            Concrete::After(t) => Semantic::After(t),
            Concrete::Older(t) => Semantic::Older(t),
            Concrete::Sha256(h) => Semantic::Sha256(h),
            Concrete::Hash256(h) => Semantic::Hash256(h),
            Concrete::Ripemd160(h) => Semantic::Ripemd160(h),
            Concrete::Hash160(h) => Semantic::Hash160(h),
            Concrete::And(ref subs) => Semantic::And(subs.iter().map(Liftable::lift).collect()),
            Concrete::Or(ref subs) => {
                Semantic::Or(subs.iter().map(|&(_, ref sub)| sub.lift()).collect())
            }
            Concrete::Threshold(k, ref subs) => {
                Semantic::Threshold(k, subs.iter().map(Liftable::lift).collect())
            }
        }
        .normalized()
    }
}
