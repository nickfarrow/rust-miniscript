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

//! # Output Descriptors
//!
//! Tools for representing Bitcoin output's scriptPubKeys as abstract spending
//! policies known as "output descriptors". These include a Miniscript which
//! describes the actual signing policy, as well as the blockchain format (P2SH,
//! Segwit v0, etc.)
//!
//! The format represents EC public keys abstractly to allow wallets to replace these with
//! BIP32 paths, pay-to-contract instructions, etc.
//!

use bitcoin::{self, Script, SigHashType};
use bitcoin::blockdata::script;
use bitcoin_hashes::{sha256};
use secp256k1;
use std::fmt;
use std::str::{self, FromStr};

use expression;
use miniscript::Miniscript;
use policy::AbstractPolicy;
use miniscript::evaluate::{Primitives, StackElement, verify_sersig};
use Error;
use pubkey_size;
use ToPublicKey;
use secp256k1::VerifyOnly;

mod create_descriptor;
pub use self::create_descriptor::witness_stack;

/// Script descriptor
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Descriptor<P> {
    /// A raw scriptpubkey (including pay-to-pubkey)
    Bare(Miniscript<P>),
    /// Pay-to-PubKey-Hash
    Pkh(P),
    /// Pay-to-Witness-PubKey-Hash
    Wpkh(P),
    /// Pay-to-Witness-PubKey-Hash inside P2SH
    ShWpkh(P),
    /// Pay-to-ScriptHash
    Sh(Miniscript<P>),
    /// Pay-to-Witness-ScriptHash
    Wsh(Miniscript<P>),
    /// P2SH-P2WSH
    ShWsh(Miniscript<P>),
}

impl<P> Descriptor<P> {
    /// Convert a descriptor using abstract keys to one using specific keys
    pub fn translate<F, Q, E>(&self, mut translatefn: F) -> Result<Descriptor<Q>, E>
        where F: FnMut(&P) -> Result<Q, E>
    {
        match *self {
            Descriptor::Bare(ref descript) => {
                Ok(Descriptor::Bare(descript.translate(translatefn)?))
            }
            Descriptor::Pkh(ref pk) => {
                translatefn(pk).map(Descriptor::Pkh)
            }
            Descriptor::Wpkh(ref pk) => {
                translatefn(pk).map(Descriptor::Wpkh)
            }
            Descriptor::ShWpkh(ref pk) => {
                translatefn(pk).map(Descriptor::ShWpkh)
            }
            Descriptor::Sh(ref descript) => {
                Ok(Descriptor::Sh(descript.translate(translatefn)?))
            }
            Descriptor::Wsh(ref descript) => {
                Ok(Descriptor::Wsh(descript.translate(translatefn)?))
            }
            Descriptor::ShWsh(ref descript) => {
                Ok(Descriptor::ShWsh(descript.translate(translatefn)?))
            }
        }
    }
}

impl<P: Clone> Descriptor<P> {
    /// Abstract the script into an "abstract policy" which can be filtered and analyzed
    pub fn abstract_policy(&self) -> AbstractPolicy<P> {
        match *self {
            Descriptor::Bare(ref d) |
            Descriptor::Sh(ref d) |
            Descriptor::Wsh(ref d) |
            Descriptor::ShWsh(ref d) => d.abstract_policy(),
            Descriptor::Pkh(ref p) |
            Descriptor::Wpkh(ref p) |
            Descriptor::ShWpkh(ref p) => AbstractPolicy::Key(p.clone()),
        }
    }
}

impl<P: ToPublicKey> Descriptor<P> {
    /// Computes the Bitcoin address of the descriptor, if one exists
    pub fn address(&self, network: bitcoin::Network) -> Option<bitcoin::Address> {
        match *self {
            Descriptor::Bare(..) => None,
            Descriptor::Pkh(ref pk) => {
                Some(bitcoin::Address::p2pkh(
                    &pk.to_public_key(),
                    network,
                ))
            },
            Descriptor::Wpkh(ref pk) => {
                Some(bitcoin::Address::p2wpkh(
                    &pk.to_public_key(),
                    network,
                ))
            },
            Descriptor::ShWpkh(ref pk) => {
                Some(bitcoin::Address::p2shwpkh(
                    &pk.to_public_key(),
                    network,
                ))
            },
            Descriptor::Sh(ref miniscript) => {
                Some(bitcoin::Address::p2sh(
                    &miniscript.encode(),
                    network,
                ))
            },
            Descriptor::Wsh(ref miniscript) => {
                Some(bitcoin::Address::p2wsh(
                    &miniscript.encode(),
                    network,
                ))
            },
            Descriptor::ShWsh(ref miniscript) => {
                Some(bitcoin::Address::p2shwsh(
                    &miniscript.encode(),
                    network,
                ))
            },
        }
    }

    /// Computes the scriptpubkey of the descriptor
    pub fn script_pubkey(&self) -> Script {
        match *self {
            Descriptor::Bare(ref d) => d.encode(),
            Descriptor::Pkh(ref pk) => {
                let addr = bitcoin::Address::p2pkh(
                    &pk.to_public_key(),
                    bitcoin::Network::Bitcoin,
                );
                addr.script_pubkey()
            },
            Descriptor::Wpkh(ref pk) => {
                let addr = bitcoin::Address::p2wpkh(
                    &pk.to_public_key(),
                    bitcoin::Network::Bitcoin,
                );
                addr.script_pubkey()
            },
            Descriptor::ShWpkh(ref pk) => {
                let addr = bitcoin::Address::p2shwpkh(
                    &pk.to_public_key(),
                    bitcoin::Network::Bitcoin,
                );
                addr.script_pubkey()
            },
            Descriptor::Sh(ref miniscript) => miniscript.encode().to_p2sh(),
            Descriptor::Wsh(ref miniscript) => miniscript.encode().to_v0_p2wsh(),
            Descriptor::ShWsh(ref miniscript) => miniscript.encode().to_v0_p2wsh().to_p2sh(),
        }
    }

    /// Computes the scriptSig that will be in place for an unsigned
    /// input spending an output with this descriptor. For pre-segwit
    /// descriptors, which use the scriptSig for signatures, this
    /// returns the empty script.
    ///
    /// This is used in Segwit transactions to produce an unsigned
    /// transaction whose txid will not change during signing (since
    /// only the witness data will change).
    pub fn unsigned_script_sig(&self) -> Script {
        match *self {
            // non-segwit
            Descriptor::Bare(..) |
            Descriptor::Pkh(..) |
            Descriptor::Sh(..) => Script::new(),
            // pure segwit, empty scriptSig
            Descriptor::Wsh(..) |
            Descriptor::Wpkh(..) => Script::new(),
            // segwit+p2sh
            Descriptor::ShWpkh(ref pk) => {
                let addr = bitcoin::Address::p2wpkh(
                    &pk.to_public_key(),
                    bitcoin::Network::Bitcoin,
                );
                let redeem_script = addr.script_pubkey();
                script::Builder::new()
                    .push_slice(&redeem_script[..])
                    .into_script()
            },
            Descriptor::ShWsh(ref d) => {
                let witness_script = d.encode();
                script::Builder::new()
                    .push_slice(&witness_script.to_v0_p2wsh()[..])
                    .into_script()
            },
        }
    }

    /// Computes the "witness script" of the descriptor, i.e. the underlying
    /// script before any hashing is done. For `Bare`, `Pkh` and `Wpkh` this
    /// is the scriptPubkey; for `ShWpkh` and `Sh` this is the redeemScript;
    /// for the others it is the witness script.
    pub fn witness_script(&self) -> Script {
        match *self {
            Descriptor::Bare(..) |
            Descriptor::Pkh(..) |
            Descriptor::Wpkh(..) => self.script_pubkey(),
            Descriptor::ShWpkh(ref pk) => {
                let addr = bitcoin::Address::p2wpkh(
                    &pk.to_public_key(),
                    bitcoin::Network::Bitcoin,
                );
                addr.script_pubkey()
            }
            Descriptor::Sh(ref d) |
            Descriptor::Wsh(ref d) |
            Descriptor::ShWsh(ref d) => d.encode(),
        }
    }

    /// Attempts to produce a satisfying witness or scriptSig, as the case may be,
    /// for the descriptor, and add it to a `TxIn` object in the appropriate place
    pub fn satisfy<F, H>(
        &self,
        txin: &mut bitcoin::TxIn,
        sigfn: Option<F>,
        hashfn: Option<H>,
        age: u32,
    ) -> Result<(), Error>
        where F: FnMut(&P) -> Option<(secp256k1::Signature, SigHashType)>,
              H: FnMut(sha256::Hash) -> Option<[u8; 32]>
    {
        fn witness_to_scriptsig(witness: &[Vec<u8>]) -> Script {
            let mut b = script::Builder::new();
            for wit in witness {
                if let Ok(n) = script::read_scriptint(wit) {
                    b = b.push_int(n);
                } else {
                    b = b.push_slice(wit);
                }
            }
            b.into_script()
        }

        match *self {
            Descriptor::Bare(ref d) => {
                txin.script_sig = witness_to_scriptsig(
                    &d.satisfy(sigfn, hashfn, age)?,
                );
                txin.witness = vec![];
                Ok(())
            },
            Descriptor::Pkh(ref pk) => {
                if let Some(mut f) = sigfn {
                    match f(pk) {
                        Some((sig, hashtype)) => {
                            let mut sigser = sig.serialize_der();
                            let hashtypebyte = hashtype.as_u32() as u8;
                            sigser.push(hashtypebyte);
                            txin.script_sig = script::Builder::new()
                                .push_slice(&sigser)
                                .push_key(&pk.to_public_key())
                                .into_script();
                            txin.witness = vec![];
                            Ok(())
                        },
                        None => Err(Error::MissingSig(pk.to_public_key())),
                    }
                } else {
                    Err(Error::MissingSig(pk.to_public_key()))
                }
            },
            Descriptor::Wpkh(ref pk) => {
                if let Some(mut f) = sigfn {
                    match f(pk) {
                        Some((sig, hashtype)) => {
                            let mut sigser = sig.serialize_der();
                            let hashtypebyte = hashtype.as_u32() as u8;
                            sigser.push(hashtypebyte);
                            txin.script_sig = Script::new();
                            txin.witness = vec![
                                sigser,
                                pk.to_public_key().to_bytes(),
                            ];
                            Ok(())
                        },
                        None => Err(Error::MissingSig(pk.to_public_key())),
                    }
                } else {
                    Err(Error::MissingSig(pk.to_public_key()))
                }
            },
            Descriptor::ShWpkh(ref pk) => {
                if let Some(mut f) = sigfn {
                    match f(pk) {
                        Some((sig, hashtype)) => {
                            let addr = bitcoin::Address::p2wpkh(
                                &pk.to_public_key(),
                                bitcoin::Network::Bitcoin,
                            );
                            let redeem_script = addr.script_pubkey();

                            let mut sigser = sig.serialize_der();
                            let hashtypebyte = hashtype.as_u32() as u8;
                            sigser.push(hashtypebyte);
                            txin.script_sig = script::Builder::new()
                                .push_slice(&redeem_script[..])
                                .into_script();
                            txin.witness = vec![
                                sigser,
                                pk.to_public_key().to_bytes(),
                            ];
                            Ok(())
                        },
                        None => Err(Error::MissingSig(pk.to_public_key())),
                    }
                } else {
                    Err(Error::MissingSig(pk.to_public_key()))
                }
            },
            Descriptor::Sh(ref d) => {
                let mut witness = d.satisfy(sigfn, hashfn, age)?;
                witness.push(d.encode().into_bytes());
                txin.script_sig = witness_to_scriptsig(&witness);
                txin.witness = vec![];
                Ok(())
            },
            Descriptor::Wsh(ref d) => {
                let mut witness = d.satisfy(sigfn, hashfn, age)?;
                witness.push(d.encode().into_bytes());
                txin.script_sig = Script::new();
                txin.witness = witness;
                Ok(())
            },
            Descriptor::ShWsh(ref d) => {
                let witness_script = d.encode();
                txin.script_sig = script::Builder::new()
                    .push_slice(&witness_script.to_v0_p2wsh()[..])
                    .into_script();

                let mut witness = d.satisfy(sigfn, hashfn, age)?;
                witness.push(witness_script.into_bytes());
                txin.witness = witness;
                Ok(())
            },
        }
    }

    /// Computes an upper bound on the weight of a satisfying witness to the
    /// transaction. Assumes all signatures are 73 bytes, including push opcode
    /// and sighash suffix. Includes the weight of the VarInts encoding the
    /// scriptSig and witness stack length.
    pub fn max_satisfaction_weight(&self) -> usize {
        fn varint_len(n: usize) -> usize {
            bitcoin::VarInt(n as u64).encoded_length() as usize
        }

        match *self {
            Descriptor::Bare(ref ms) => {
                let scriptsig_len = ms.max_satisfaction_size(1);
                4 * (varint_len(scriptsig_len) + scriptsig_len)
            }
            Descriptor::Pkh(ref pk) => 4 * (1 + 73 + pubkey_size(pk)),
            Descriptor::Wpkh(ref pk) => 4 + 1 + 73 + pubkey_size(pk),
            Descriptor::ShWpkh(ref pk) => 4 * 24 + 1 + 73 + pubkey_size(pk),
            Descriptor::Sh(ref ms) => {
                let ss = ms.script_size();
                let push_size = if ss < 76 {
                    1
                } else if ss < 0x100 {
                    2
                } else if ss < 0x10000 {
                    3
                } else {
                    5
                };

                let scriptsig_len = push_size + ss + ms.max_satisfaction_size(1);
                4 * (varint_len(scriptsig_len) + scriptsig_len)
            },
            Descriptor::Wsh(ref ms) => {
                let script_size = ms.script_size();
                4 +  // scriptSig length byte
                    varint_len(script_size) +
                    script_size +
                    varint_len(ms.max_satisfaction_witness_elements()) +
                    ms.max_satisfaction_size(2)
            },
            Descriptor::ShWsh(ref ms) => {
                let script_size = ms.script_size();
                4 * 36 +
                    varint_len(script_size) +
                    script_size +
                    varint_len(ms.max_satisfaction_witness_elements()) +
                    ms.max_satisfaction_size(2)
            },
        }
    }
}

impl<P: ToPublicKey + Clone> Descriptor<P> {
    pub fn interpret(
        &self,
        secp: &secp256k1::Secp256k1<VerifyOnly>,
        stack: &mut Vec<StackElement>,
        sighash: &secp256k1::Message,
        age: u32,
    ) -> Result<Primitives, Error>
    {
        match *self {
            Descriptor::Bare(ref d) |
            Descriptor::Sh(ref d) |
            Descriptor::ShWsh(ref d) |
            Descriptor::Wsh(ref d) => {
                d.interpret(secp, stack, sighash, age)
            },
            Descriptor::Pkh(ref pk) |
            Descriptor::ShWpkh(ref pk) |
            Descriptor::Wpkh(ref pk) => {
                let sig = stack.pop().expect("Signature").is_witness_or_err()?;
                verify_sersig(secp, sighash, &pk.to_public_key(), &sig)?;
                if stack.is_empty() {
                    Ok(Primitives {pks: vec![pk.to_public_key()], hashlocks: vec![], timelocks: vec![]})
                }else{
                    Err(Error::CouldnotEvaluate)
                }
            }
        }
    }
}

impl<P: fmt::Debug + FromStr> expression::FromTree for Descriptor<P>
    where <P as FromStr>::Err: ToString,
{
    /// Parse an expression tree into a descriptor
    fn from_tree(top: &expression::Tree) -> Result<Descriptor<P>, Error> {
        match (top.name, top.args.len() as u32) {
            ("pkh", 1) => expression::terminal(
                &top.args[0],
                |pk| P::from_str(pk).map(Descriptor::Pkh)
            ),
            ("wpkh", 1) => expression::terminal(
                &top.args[0],
                |pk| P::from_str(pk).map(Descriptor::Wpkh)
            ),
            ("sh", 1) => {
                let newtop = &top.args[0];
                match (newtop.name, newtop.args.len()) {
                    ("wsh", 1) => {
                        let sub = Miniscript::from_tree(&newtop.args[0])?;
                        Ok(Descriptor::ShWsh(sub))
                    }
                    ("wpkh", 1) => expression::terminal(
                        &newtop.args[0],
                        |pk| P::from_str(pk).map(Descriptor::ShWpkh)
                    ),
                    _ => {
                        let sub = Miniscript::from_tree(&top.args[0])?;
                        Ok(Descriptor::Sh(sub))
                    }
                }
            }
            ("wsh", 1) => expression::unary(top, Descriptor::Wsh),
            _ => {
                let sub = expression::FromTree::from_tree(&top)?;
                Ok(Descriptor::Bare(sub))
            }
        }
    }
}

impl<P: fmt::Debug + FromStr> FromStr for Descriptor<P>
    where <P as FromStr>::Err: ToString,
{
    type Err = Error;

    fn from_str(s: &str) -> Result<Descriptor<P>, Error> {
        for ch in s.as_bytes() {
            if *ch < 20 || *ch > 127 {
                return Err(Error::Unprintable(*ch));
            }
        }

        let top = expression::Tree::from_str(s)?;
        expression::FromTree::from_tree(&top)
    }
}

impl <P: fmt::Debug> fmt::Debug for Descriptor<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Descriptor::Bare(ref sub) => write!(f, "{:?}", sub),
            Descriptor::Pkh(ref p) => write!(f, "pkh({:?})", p),
            Descriptor::Wpkh(ref p) => write!(f, "wpkh({:?})", p),
            Descriptor::ShWpkh(ref p) => write!(f, "sh(wpkh({:?}))", p),
            Descriptor::Sh(ref sub) => write!(f, "sh({:?})", sub),
            Descriptor::Wsh(ref sub) => write!(f, "wsh({:?})", sub),
            Descriptor::ShWsh(ref sub) => write!(f, "sh(wsh({:?}))", sub),
        }
    }
}

impl <P: fmt::Display> fmt::Display for Descriptor<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Descriptor::Bare(ref sub) => write!(f, "{}", sub),
            Descriptor::Pkh(ref p) => write!(f, "pkh({})", p),
            Descriptor::Wpkh(ref p) => write!(f, "wpkh({})", p),
            Descriptor::ShWpkh(ref p) => write!(f, "sh(wpkh({}))", p),
            Descriptor::Sh(ref sub) => write!(f, "sh({})", sub),
            Descriptor::Wsh(ref sub) => write!(f, "wsh({})", sub),
            Descriptor::ShWsh(ref sub) => write!(f, "sh(wsh({}))", sub),
        }
    }
}

#[cfg(feature = "serde")]
impl<P: fmt::Display> ::serde::Serialize for Descriptor<P> {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}


#[cfg(feature = "serde")]
impl<'de, P: fmt::Debug + str::FromStr> ::serde::Deserialize<'de> for Descriptor<P>
    where <P as str::FromStr>::Err: ToString,
{
    fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<Descriptor<P>, D::Error> {
        use std::str::FromStr;
        use std::marker::PhantomData;

        struct StrVisitor<Q>(PhantomData<Q>);

        impl<'de, Q: fmt::Debug + str::FromStr> ::serde::de::Visitor<'de> for StrVisitor<Q>
            where <Q as str::FromStr>::Err: ToString,
        {
            type Value = Descriptor<Q>;

            fn expecting(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                formatter.write_str("an ASCII miniscript string")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: ::serde::de::Error,
            {
                if let Ok(s) = ::std::str::from_utf8(v) {
                    Descriptor::from_str(s).map_err(E::custom)
                } else {
                    return Err(E::invalid_value(::serde::de::Unexpected::Bytes(v), &self));
                }
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: ::serde::de::Error,
            {
                Descriptor::from_str(v).map_err(E::custom)
            }
        }

        d.deserialize_str(StrVisitor(PhantomData))
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{self, PublicKey};
    use bitcoin::blockdata::{opcodes, script};
    use bitcoin_hashes::{hash160, sha256};
    use bitcoin_hashes::hex::FromHex;
    use secp256k1;
    use bitcoin_hashes::Hash;

    use std::str::FromStr;

    use miniscript::astelem;
    use miniscript::evaluate::{Primitives, StackElement};
    use Miniscript;
    use Descriptor;
    use NO_HASHES;
    use secp256k1::{Secp256k1, VerifyOnly};

    #[test]
    fn parse_descriptor() {
        assert!(Descriptor::<PublicKey>::from_str("(").is_err());
        assert!(Descriptor::<PublicKey>::from_str("(x()").is_err());
        assert!(Descriptor::<PublicKey>::from_str("(\u{7f}()3").is_err());
        assert!(Descriptor::<PublicKey>::from_str("pk()").is_err());

        assert!(Descriptor::<PublicKey>::from_str("pk(020000000000000000000000000000000000000000000000000000000000000002)").is_ok());
    }

    #[test]
    pub fn script_pubkey() {
        let bare = Descriptor::<PublicKey>::from_str(
            "time(1000)"
        ).unwrap();
        assert_eq!(
            bare.script_pubkey(),
            bitcoin::Script::from(vec![0x02, 0xe8, 0x03, 0xb2])
        );
        assert_eq!(bare.address(bitcoin::Network::Bitcoin), None);

        let pk = Descriptor::<PublicKey>::from_str(
            "pk(020000000000000000000000000000000000000000000000000000000000000002)"
        ).unwrap();
        assert_eq!(
            pk.script_pubkey(),
            bitcoin::Script::from(vec![
                0x21,
                0x02,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
                0xac,
            ])
        );

        let pkh = Descriptor::<PublicKey>::from_str(
            "pkh(020000000000000000000000000000000000000000000000000000000000000002)"
        ).unwrap();
        assert_eq!(
            pkh.script_pubkey(),
            script::Builder::new()
                .push_opcode(opcodes::all::OP_DUP)
                .push_opcode(opcodes::all::OP_HASH160)
                .push_slice(&hash160::Hash::from_hex(
                    "84e9ed95a38613f0527ff685a9928abe2d4754d4",
                ).unwrap()[..])
                .push_opcode(opcodes::all::OP_EQUALVERIFY)
                .push_opcode(opcodes::all::OP_CHECKSIG)
                .into_script()
        );
        assert_eq!(
            pkh.address(bitcoin::Network::Bitcoin).unwrap().to_string(),
            "1D7nRvrRgzCg9kYBwhPH3j3Gs6SmsRg3Wq"
        );

        let wpkh = Descriptor::<PublicKey>::from_str(
            "wpkh(020000000000000000000000000000000000000000000000000000000000000002)"
        ).unwrap();
        assert_eq!(
            wpkh.script_pubkey(),
            script::Builder::new()
                .push_opcode(opcodes::all::OP_PUSHBYTES_0)
                .push_slice(&hash160::Hash::from_hex(
                    "84e9ed95a38613f0527ff685a9928abe2d4754d4",
                ).unwrap()[..])
                .into_script()
        );
        assert_eq!(
            wpkh.address(bitcoin::Network::Bitcoin).unwrap().to_string(),
            "bc1qsn57m9drscflq5nl76z6ny52hck5w4x5wqd9yt"
        );

        let shwpkh = Descriptor::<PublicKey>::from_str(
            "sh(wpkh(020000000000000000000000000000000000000000000000000000000000000002))"
        ).unwrap();
        assert_eq!(
            shwpkh.script_pubkey(),
            script::Builder::new()
                .push_opcode(opcodes::all::OP_HASH160)
                .push_slice(&hash160::Hash::from_hex(
                    "f1c3b9a431134cb90a500ec06e0067cfa9b8bba7",
                ).unwrap()[..])
                .push_opcode(opcodes::all::OP_EQUAL)
                .into_script()
        );
        assert_eq!(
            shwpkh.address(bitcoin::Network::Bitcoin).unwrap().to_string(),
            "3PjMEzoveVbvajcnDDuxcJhsuqPHgydQXq"
        );

        let sh = Descriptor::<PublicKey>::from_str(
            "sh(pk(020000000000000000000000000000000000000000000000000000000000000002))"
        ).unwrap();
        assert_eq!(
            sh.script_pubkey(),
            script::Builder::new()
                .push_opcode(opcodes::all::OP_HASH160)
                .push_slice(&hash160::Hash::from_hex(
                    "aa5282151694d3f2f32ace7d00ad38f927a33ac8",
                ).unwrap()[..])
                .push_opcode(opcodes::all::OP_EQUAL)
                .into_script()
        );
        assert_eq!(
            sh.address(bitcoin::Network::Bitcoin).unwrap().to_string(),
            "3HDbdvM9CQ6ASnQFUkWw6Z4t3qNwMesJE9"
        );

        let wsh = Descriptor::<PublicKey>::from_str(
            "wsh(pk(020000000000000000000000000000000000000000000000000000000000000002))"
        ).unwrap();
        assert_eq!(
            wsh.script_pubkey(),
            script::Builder::new()
                .push_opcode(opcodes::all::OP_PUSHBYTES_0)
                .push_slice(&sha256::Hash::from_hex(
                    "f9379edc8983152dc781747830075bd53896e4b0ce5bff73777fd77d124ba085",
                ).unwrap()[..])
                .into_script()
        );
        assert_eq!(
            wsh.address(bitcoin::Network::Bitcoin).unwrap().to_string(),
            "bc1qlymeahyfsv2jm3upw3urqp6m65ufde9seedl7umh0lth6yjt5zzsk33tv6"
        );

        let shwsh = Descriptor::<PublicKey>::from_str(
            "sh(wsh(pk(020000000000000000000000000000000000000000000000000000000000000002)))"
        ).unwrap();
        assert_eq!(
            shwsh.script_pubkey(),
            script::Builder::new()
                .push_opcode(opcodes::all::OP_HASH160)
                .push_slice(&hash160::Hash::from_hex(
                    "4bec5d7feeed99e1d0a23fe32a4afe126a7ff07e",
                ).unwrap()[..])
                .push_opcode(opcodes::all::OP_EQUAL)
                .into_script()
        );
        assert_eq!(
            shwsh.address(bitcoin::Network::Bitcoin).unwrap().to_string(),
            "38cTksiyPT2b1uGRVbVqHdDhW9vKs84N6Z"
        );
    }

    #[test]
    fn satisfy() {
        let secp = secp256k1::Secp256k1::new();
        let sk = secp256k1::SecretKey::from_slice(
            &b"sally was a secret key, she said"[..]
        ).unwrap();
        let pk = bitcoin::PublicKey {
            key: secp256k1::PublicKey::from_secret_key(&secp, &sk),
            compressed: true,
        };
        let msg = secp256k1::Message::from_slice(
            &b"michael was a message, amusingly"[..]
        ).expect("32 bytes");
        let sig = secp.sign(&msg, &sk);
        let mut sigser = sig.serialize_der();
        sigser.push(0x01); // sighash_all

        let sigfn = |key: &bitcoin::PublicKey| {
            if *key == pk {
                Some((sig, bitcoin::SigHashType::All))
            } else {
                None
            }
        };

        let ms = Miniscript(astelem::AstElem::Pk(pk));

        let mut txin = bitcoin::TxIn {
            previous_output: bitcoin::OutPoint::default(),
            script_sig: bitcoin::Script::new(),
            sequence: 100,
            witness: vec![],
        };
        let bare = Descriptor::Bare(ms.clone());

        bare.satisfy(
            &mut txin,
            Some(&sigfn),
            NO_HASHES,
            0,
        ).expect("satisfaction to succeed");
        assert_eq!(
            txin,
            bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::default(),
                script_sig: script::Builder::new()
                    .push_slice(&sigser[..])
                    .into_script(),
                sequence: 100,
                witness: vec![],
            }
        );
        assert_eq!(bare.unsigned_script_sig(), bitcoin::Script::new());

        let pkh = Descriptor::Pkh(pk);
        pkh.satisfy(
            &mut txin,
            Some(&sigfn),
            NO_HASHES,
            0,
        ).expect("satisfaction to succeed");
        assert_eq!(
            txin,
            bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::default(),
                script_sig: script::Builder::new()
                    .push_slice(&sigser[..])
                    .push_key(&pk)
                    .into_script(),
                sequence: 100,
                witness: vec![],
            }
        );
        assert_eq!(pkh.unsigned_script_sig(), bitcoin::Script::new());

        let wpkh = Descriptor::Wpkh(pk);
        wpkh.satisfy(
            &mut txin,
            Some(&sigfn),
            NO_HASHES,
            0,
        ).expect("satisfaction to succeed");
        assert_eq!(
            txin,
            bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::default(),
                script_sig: bitcoin::Script::new(),
                sequence: 100,
                witness: vec![
                    sigser.clone(),
                    pk.to_bytes(),
                ],
            }
        );
        assert_eq!(wpkh.unsigned_script_sig(), bitcoin::Script::new());

        let shwpkh = Descriptor::ShWpkh(pk);
        shwpkh.satisfy(
            &mut txin,
            Some(&sigfn),
            NO_HASHES,
            0,
        ).expect("satisfaction to succeed");
        let redeem_script = script::Builder::new()
            .push_opcode(opcodes::all::OP_PUSHBYTES_0)
            .push_slice(&hash160::Hash::from_hex(
                "d1b2a1faf62e73460af885c687dee3b7189cd8ab",
            ).unwrap()[..])
            .into_script();
        assert_eq!(
            txin,
            bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::default(),
                script_sig: script::Builder::new()
                    .push_slice(&redeem_script[..])
                    .into_script(),
                sequence: 100,
                witness: vec![
                    sigser.clone(),
                    pk.to_bytes(),
                ],
            }
        );
        assert_eq!(
            shwpkh.unsigned_script_sig(),
            script::Builder::new()
                .push_slice(&redeem_script[..])
                .into_script()
        );

        let sh = Descriptor::Sh(ms.clone());
        sh.satisfy(
            &mut txin,
            Some(&sigfn),
            NO_HASHES,
            0,
        ).expect("satisfaction to succeed");
        assert_eq!(
            txin,
            bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::default(),
                script_sig: script::Builder::new()
                    .push_slice(&sigser[..])
                    .push_slice(&ms.encode()[..])
                    .into_script(),
                sequence: 100,
                witness: vec![],
            }
        );
        assert_eq!(sh.unsigned_script_sig(), bitcoin::Script::new());

        let wsh = Descriptor::Wsh(ms.clone());
        wsh.satisfy(
            &mut txin,
            Some(&sigfn),
            NO_HASHES,
            0,
        ).expect("satisfaction to succeed");
        assert_eq!(
            txin,
            bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::default(),
                script_sig: bitcoin::Script::new(),
                sequence: 100,
                witness: vec![
                    sigser.clone(),
                    ms.encode().into_bytes(),
                ],
            }
        );
        assert_eq!(wsh.unsigned_script_sig(), bitcoin::Script::new());

        let shwsh = Descriptor::ShWsh(ms.clone());
        shwsh.satisfy(
            &mut txin,
            Some(&sigfn),
            NO_HASHES,
            0,
        ).expect("satisfaction to succeed");
        assert_eq!(
            txin,
            bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::default(),
                script_sig: script::Builder::new()
                    .push_slice(&ms.encode().to_v0_p2wsh()[..])
                    .into_script(),
                sequence: 100,
                witness: vec![
                    sigser.clone(),
                    ms.encode().into_bytes(),
                ],
            }
        );
        assert_eq!(
            shwsh.unsigned_script_sig(),
            script::Builder::new()
                .push_slice(&ms.encode().to_v0_p2wsh()[..])
                .into_script()
        );
    }

    #[test]
    fn interpret()
    {
        fn setup_keys_sigs(n: usize)
                           -> ( Vec<PublicKey>, Vec<Vec<u8> >, secp256k1::Message, Secp256k1<VerifyOnly>) {
            let secp_sign = secp256k1::Secp256k1::signing_only();
            let secp_verify = secp256k1::Secp256k1::verification_only();
            let sighash = secp256k1::Message::from_slice(
                &b"Yoda: btc, I trust. HODL I must!"[..]
            ).expect("32 bytes");
            let mut pks = vec![];
            let mut sigs = vec![];
            let mut sk = [0; 32];
            for i in 1..n+1 {
                sk[0] = i as u8;
                sk[1] = (i >> 8) as u8;
                sk[2] = (i >> 16) as u8;

                let sk = secp256k1::SecretKey::from_slice(&sk[..]).expect("secret key");
                let pk = PublicKey {
                    key: secp256k1::PublicKey::from_secret_key(
                        &secp_sign,
                        &sk,
                    ),
                    compressed: true,
                };
                let sig = secp_sign.sign(&sighash, &sk);
                let mut sigser = sig.serialize_der();
                sigser.push(0x01); // sighash_all
                pks.push(pk);
                sigs.push(sigser);
            }
            (pks, sigs, sighash, secp_verify)
        }

        let (pks,sigs, sighash, secp) = setup_keys_sigs(10);

        //check satisfied case Pk
        let ms = Miniscript(astelem::AstElem::Pk(pks[0].clone()));
        let bare = Descriptor::Bare(ms.clone());
        let mut stack = vec![StackElement::Witness(sigs[0].clone())];
        let res = bare.interpret(
            &secp,
            &mut stack,
            &sighash,
            0,
        ).expect("Interpretation to succeed");
        assert_eq!(res, Primitives{pks: vec![pks[0]], hashlocks: vec![], timelocks: vec![]});
        assert_eq!(stack, vec![StackElement::Satisfied]);

        //check Non-sat case Pk
        stack = vec![StackElement::Dissatisfied];
        let res = bare.interpret(
            &secp,
            &mut stack,
            &sighash,
            0,
        ).expect("Interpretation to succeed");
        assert_eq!(stack, vec![StackElement::Dissatisfied]);
        assert_eq!(res, Primitives{pks: vec![], hashlocks: vec![], timelocks: vec![]});

        //check error case: Pk
        stack = vec![StackElement::Witness(sigs[1].clone())];
        assert!(bare.interpret(
            &secp,
            &mut stack,
            &sighash,
            0,
        ).is_err());

        //Check Multi Node: Sat case
        stack = vec![StackElement::Dissatisfied,
                       StackElement::Witness(sigs[2].clone()),
                       StackElement::Witness(sigs[3].clone())];
        let ms = Miniscript(astelem::AstElem::Multi(2, pks[2..5].to_owned()));
        let bare = Descriptor::Bare(ms.clone());
        let res = bare.interpret(
            &secp,
            &mut stack,
            &sighash,
            0,
        ).expect("Interpretation to succeed");
        assert_eq!(stack, vec![StackElement::Satisfied]);
        assert_eq!(res, Primitives{pks: pks[2..4].to_owned(), hashlocks: vec![], timelocks: vec![]});

        //Check Multi Node: Non-sat Case
        stack = vec![StackElement::Dissatisfied,
                       StackElement::Dissatisfied,
                       StackElement::Dissatisfied];
        let ms = Miniscript(astelem::AstElem::Multi(2, pks[2..5].to_owned()));
        let bare = Descriptor::Bare(ms.clone());
        let res = bare.interpret(
            &secp,
            &mut stack,
            &sighash,
            0,
        ).expect("Interpretation to succeed");
        assert_eq!(stack, vec![StackElement::Dissatisfied]);
        assert_eq!(res, Primitives{pks: vec![], hashlocks: vec![], timelocks: vec![]});

        //Multi Node: Error case, wrong signatures.
        let ms = Miniscript(astelem::AstElem::Multi(2, pks[2..5].to_owned()));
        stack = vec![StackElement::Dissatisfied,
                       StackElement::Witness(sigs[4].clone()),
                       StackElement::Witness(sigs[5].clone())];//only 1 sig valid
        let bare = Descriptor::Bare(ms.clone());
        assert!(bare.interpret(
            &secp,
            &mut stack,
            &sighash,
            0,
        ).is_err());

        //Time Node: Sat case
        let ms : Miniscript<PublicKey> = Miniscript(astelem::AstElem::TimeE(240));
        stack = vec![StackElement::Satisfied];
        let bare = Descriptor::Bare(ms.clone());
        let res = bare.interpret(
            &secp,
            &mut stack,
            &sighash,
            241,
        ).expect("Interpretation to succeed");
        assert_eq!(stack, vec![StackElement::Satisfied]);
        assert_eq!(res, Primitives{pks: vec![], hashlocks: vec![], timelocks: vec![240]});

        //Time Node: Unsat case
        stack = vec![StackElement::Dissatisfied];//only 1 sig valid
        let bare = Descriptor::Bare(ms.clone());
        let res = bare.interpret(
            &secp,
            &mut stack,
            &sighash,
            239,
        ).expect("Interpretation to succeed");
        assert_eq!(stack, vec![StackElement::Dissatisfied]);
        assert_eq!(res, Primitives{pks: vec![], hashlocks: vec![], timelocks: vec![]});

        //Time Node: err case
        stack = vec![StackElement::Satisfied];//only 1 sig valid
        let bare = Descriptor::Bare(ms.clone());
        assert!(bare.interpret(
            &secp,
            &mut stack,
            &sighash,
            0,
        ).is_err());

        //Hash Node test
        let preimage = vec![0xab as u8; 32];
        stack = vec![StackElement::Witness(preimage.clone())];
        let hash = sha256::Hash::hash(&preimage);
        let ms : Miniscript<PublicKey> = Miniscript(astelem::AstElem::Hash(hash));
        let bare = Descriptor::Bare(ms.clone());
        let res = bare.interpret(
            &secp,
            &mut stack,
            &sighash,
            0,
        ).expect("Interpretation to succeed");
        assert_eq!(stack, vec![StackElement::Satisfied]);
        assert_eq!(res, Primitives{pks: vec![], hashlocks: vec![preimage.clone()], timelocks: vec![]});

        //Hash Node fail test
        stack = vec![StackElement::Witness(vec![0xaa as u8; 32])];
        let hash = sha256::Hash::hash(&preimage);
        let ms : Miniscript<PublicKey> = Miniscript(astelem::AstElem::Hash(hash));
        let bare = Descriptor::Bare(ms.clone());
        assert!(bare.interpret(
            &secp,
            &mut stack,
            &sighash,
            0,
        ).is_err());

        //AndBool Test
        let ms = Miniscript(astelem::AstElem::AndBool(
            Box::new(astelem::AstElem::Pk(pks[0].clone())),
            Box::new(astelem::AstElem::PkW(pks[1].clone()))));
        stack = vec![StackElement::Witness(sigs[1].clone()),
                               StackElement::Witness(sigs[0].clone())];
        let bare = Descriptor::Bare(ms.clone());
        let res = bare.interpret(
            &secp,
            &mut stack,
            &sighash,
            0,
        ).expect("Interpretation to succeed");
        assert_eq!(stack, vec![StackElement::Satisfied]);
        assert_eq!(res, Primitives{pks: vec![pks[0].clone(), pks[1].clone()], hashlocks: vec![], timelocks: vec![]});

        //AndCat Test
        let ms = Miniscript(astelem::AstElem::AndCat(
            Box::new(astelem::AstElem::PkV(pks[0].clone())),
            Box::new(astelem::AstElem::Pk(pks[1].clone()))));
        stack = vec![StackElement::Witness(sigs[1].clone()),
                       StackElement::Witness(sigs[0].clone())];
        let bare = Descriptor::Bare(ms.clone());
        let res = bare.interpret(
            &secp,
            &mut stack,
            &sighash,
            0,
        ).expect("Interpretation to succeed");
        assert_eq!(stack, vec![StackElement::Satisfied]);
        assert_eq!(res, Primitives{pks: vec![pks[0].clone(), pks[1].clone()], hashlocks: vec![], timelocks: vec![]});

        //Andcasc Test
        let ms = Miniscript(astelem::AstElem::AndCasc(
            Box::new(astelem::AstElem::Pk(pks[0].clone())),
            Box::new(astelem::AstElem::TimeF(1000))));
        stack = vec![StackElement::Witness(sigs[0].clone())];
        let bare = Descriptor::Bare(ms.clone());
        let res = bare.interpret(
            &secp,
            &mut stack,
            &sighash,
            1010,
        ).expect("Interpretation to succeed");
        assert_eq!(stack, vec![StackElement::Satisfied]);
        assert_eq!(res, Primitives{pks: vec![pks[0].clone()], hashlocks: vec![], timelocks: vec![1000]});

        //Or Bool
        let ms = Miniscript(astelem::AstElem::OrBool(
            Box::new(astelem::AstElem::Pk(pks[0].clone())),
            Box::new(astelem::AstElem::PkW(pks[1].clone()))));
        stack = vec![StackElement::Dissatisfied,
                               StackElement::Witness(sigs[0].clone())];
        let bare = Descriptor::Bare(ms.clone());
        let res = bare.interpret(
            &secp,
            &mut stack,
            &sighash,
            0,
        ).expect("Interpretation to succeed");
        assert_eq!(stack, vec![StackElement::Satisfied]);
        assert_eq!(res, Primitives{pks: vec![pks[0].clone()], hashlocks: vec![], timelocks: vec![]});

        //Orcasc Test
        let ms = Miniscript(astelem::AstElem::OrCasc(
            Box::new(astelem::AstElem::Pk(pks[0].clone())),
            Box::new(astelem::AstElem::Pk(pks[1].clone()))));
        stack = vec![StackElement::Witness(sigs[0].clone())];
        let bare = Descriptor::Bare(ms.clone());
        let res = bare.interpret(
            &secp,
            &mut stack,
            &sighash,
            0,
        ).expect("Interpretation to succeed");
        assert_eq!(stack, vec![StackElement::Satisfied]);
        assert_eq!(res, Primitives{pks: vec![pks[0].clone()], hashlocks: vec![], timelocks: vec![]});

        //Or-cont Test
        let ms = Miniscript(astelem::AstElem::OrCont(
            Box::new(astelem::AstElem::Pk(pks[0].clone())),
            Box::new(astelem::AstElem::PkV(pks[1].clone()))));
        stack = vec![StackElement::Witness(sigs[1].clone()),
                       StackElement::Dissatisfied];
        let bare = Descriptor::Bare(ms.clone());
        let res = bare.interpret(
            &secp,
            &mut stack,
            &sighash,
            0,
        ).expect("Interpretation to succeed");
        assert_eq!(stack, vec![] as Vec<StackElement>);
        assert_eq!(res, Primitives{pks: vec![pks[1].clone()], hashlocks: vec![], timelocks: vec![]});

        //Or-key Test
        let ms = Miniscript(astelem::AstElem::OrKey(
        Box::new(astelem::AstElem::PkQ(pks[0].clone())),
        Box::new(astelem::AstElem::PkQ(pks[1].clone()))));
        stack = vec![StackElement::Witness(sigs[1].clone()),
                       StackElement::Dissatisfied];
        let bare = Descriptor::Bare(ms.clone());
        let res = bare.interpret(
            &secp,
            &mut stack,
            &sighash,
            0,
        ).expect("Interpretation to succeed");
        assert_eq!(stack, vec![StackElement::Satisfied]);
        assert_eq!(res, Primitives{pks: vec![pks[1].clone()], hashlocks: vec![], timelocks: vec![]});

        //Or-keyV
        let ms = Miniscript(astelem::AstElem::OrKeyV(
            Box::new(astelem::AstElem::PkQ(pks[0].clone())),
            Box::new(astelem::AstElem::PkQ(pks[1].clone()))));
        stack = vec![StackElement::Witness(sigs[0].clone()),
                       StackElement::Satisfied];
        let bare = Descriptor::Bare(ms.clone());
        let res = bare.interpret(
            &secp,
            &mut stack,
            &sighash,
            0,
        ).expect("Interpretation to succeed");
        assert_eq!(stack, vec![] as Vec<StackElement>);
        assert_eq!(res, Primitives{pks: vec![pks[0].clone()], hashlocks: vec![], timelocks: vec![]});

        //Or If
        let ms = Miniscript(astelem::AstElem::OrIf(
            Box::new(astelem::AstElem::Pk(pks[0].clone())),
            Box::new(astelem::AstElem::Pk(pks[1].clone()))));
        stack = vec![StackElement::Witness(sigs[0].clone()),
                       StackElement::Satisfied];
        let bare = Descriptor::Bare(ms.clone());
        let res = bare.interpret(
            &secp,
            &mut stack,
            &sighash,
            0,
        ).expect("Interpretation to succeed");
        assert_eq!(stack, vec![StackElement::Satisfied]);
        assert_eq!(res, Primitives{pks: vec![pks[0].clone()], hashlocks: vec![], timelocks: vec![]});

        //Or-ifV
        let ms = Miniscript(astelem::AstElem::OrIfV(
            Box::new(astelem::AstElem::Pk(pks[0].clone())),
            Box::new(astelem::AstElem::Pk(pks[1].clone()))));
        stack = vec![StackElement::Witness(sigs[1].clone()),
                       StackElement::Dissatisfied];
        let bare = Descriptor::Bare(ms.clone());
        let res = bare.interpret(
            &secp,
            &mut stack,
            &sighash,
            0,
        ).expect("Interpretation to succeed");
        assert_eq!(stack, vec![] as Vec<StackElement>);
        assert_eq!(res, Primitives{pks: vec![pks[1].clone()], hashlocks: vec![], timelocks: vec![]});

        //Or Not If
        let ms = Miniscript(astelem::AstElem::OrNotif(
            Box::new(astelem::AstElem::Pk(pks[0].clone())),
            Box::new(astelem::AstElem::Pk(pks[1].clone()))));
        stack = vec![StackElement::Witness(sigs[0].clone()),
                       StackElement::Dissatisfied];
        let bare = Descriptor::Bare(ms.clone());
        let res = bare.interpret(
            &secp,
            &mut stack,
            &sighash,
            0,
        ).expect("Interpretation to succeed");
        assert_eq!(stack, vec![StackElement::Satisfied]);
        assert_eq!(res, Primitives{pks: vec![pks[0].clone()], hashlocks: vec![], timelocks: vec![]});


        //Thres
        let astvec = vec![astelem::AstElem::Pk(pks[0]),
                          astelem::AstElem::Pk(pks[1]),
                          astelem::AstElem::Pk(pks[2]),
                          astelem::AstElem::Pk(pks[3]),
                          astelem::AstElem::Pk(pks[4])];
        let ms = Miniscript(astelem::AstElem::Thresh(3, astvec.clone()));
        stack = vec![
            StackElement::Witness(sigs[4].clone()),
            StackElement::Dissatisfied,
            StackElement::Witness(sigs[2].clone()),
            StackElement::Dissatisfied,
            StackElement::Witness(sigs[0].clone())];
        let bare = Descriptor::Bare(ms.clone());
        let res = bare.interpret(
            &secp,
            &mut stack,
            &sighash,
            0,
        ).expect("Interpretation to succeed");
        assert_eq!(stack, vec![StackElement::Satisfied]);
        assert_eq!(res, Primitives{pks: vec![pks[0].clone(), pks[2].clone(), pks[4].clone()], hashlocks: vec![], timelocks: vec![]});

        //ThresV
        let ms = Miniscript(astelem::AstElem::ThreshV(3, astvec.clone()));
        stack = vec![
            StackElement::Witness(sigs[4].clone()),
            StackElement::Dissatisfied,
            StackElement::Witness(sigs[2].clone()),
            StackElement::Dissatisfied,
            StackElement::Witness(sigs[0].clone())];
        let bare = Descriptor::Bare(ms.clone());
        let res = bare.interpret(
            &secp,
            &mut stack,
            &sighash,
            0,
        ).expect("Interpretation to succeed");
        assert_eq!(stack, vec![] as Vec<StackElement>);
        assert_eq!(res, Primitives{pks: vec![pks[0].clone(), pks[2].clone(), pks[4].clone()], hashlocks: vec![], timelocks: vec![]});

        //Descriptors without miniscript
        let shwpkh = Descriptor::ShWpkh(pks[0].clone());
        stack = vec![StackElement::Witness(sigs[0].clone())];
        let res = shwpkh.interpret(
            &secp,
            &mut stack,
            &sighash,
            0,
        ).expect("Interpretation to succeed");
        assert_eq!(stack, vec![] as Vec<StackElement>);
        assert_eq!(res, Primitives{pks: vec![pks[0].clone()], hashlocks: vec![], timelocks: vec![]});
    }


}

