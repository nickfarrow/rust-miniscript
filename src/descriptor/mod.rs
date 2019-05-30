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
use bitcoin_hashes::sha256;
use secp256k1;
use std::fmt;
use std::str::{self, FromStr};

use expression;
use miniscript::Miniscript;
use policy::AbstractPolicy;
use Error;
use pubkey_size;
use ToPublicKey;

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
//                println!("{:?}",Script::new();
                let addr = bitcoin::Address::p2wpkh(
                    &pk.to_public_key(),
                    bitcoin::Network::Bitcoin,
                );
//                println!("{:?}", addr);
                let redeem_script = addr.script_pubkey();
//                println!("{:?}", redeem_script);
                let temp = script::Builder::new()
                    .push_slice(&redeem_script[..]);
//                println!("{:?}", temp);
                let temp = temp.into_script();
//                println!("{:?}", temp);
                temp
            },
            Descriptor::ShWsh(ref d) => {
                //println!("{:?}",d);
                let witness_script = d.encode();
//                println!("{:?}",witness_script);
                let temp = script::Builder::new()
                    .push_slice(&witness_script.to_v0_p2wsh()[..]);
//                println!("{:?}", temp);
                let temp = temp.into_script();
//                println!("{:?}",temp);
                temp
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
//            println!("{:?} is witness", witness);
            for wit in witness {
                if let Ok(n) = script::read_scriptint(wit) {
                    b = b.push_int(n);
                    println!("{:?}",wit);
                } else {
                    b = b.push_slice(wit);
                }
            }
            let temp = b.into_script();
            temp
        }

        match *self {
            Descriptor::Bare(ref d) => {
                txin.script_sig = witness_to_scriptsig(
                    &d.satisfy(sigfn, hashfn, age)?,
                );
//                println!("{:?} is script sig", txin.script_sig);
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

impl<P: fmt::Debug + FromStr> expression::FromTree for Descriptor<P>
    where <P as FromStr>::Err: ToString,
{
    /// Parse an expression tree into a descriptor
    fn from_tree(top: &expression::Tree) -> Result<Descriptor<P>, Error> {
//        println!("{:?}", top);
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
//                println!("{:?} s", sub);
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
        let temp = expression::FromTree::from_tree(&top);
//        println!("{:?} te", temp);
        temp
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

    use std::str::FromStr;

    use miniscript::astelem;
    use Miniscript;
    use Descriptor;
    use NO_HASHES;

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
            "time_t(1000)"
        ).unwrap();
        assert_eq!(
            bare.script_pubkey(),
            bitcoin::Script::from(vec![0x02, 0xe8, 0x03, 0xb2])
        );
        assert_eq!(bare.address(bitcoin::Network::Bitcoin), None);

        let pk = Descriptor::<PublicKey>::from_str(
            "pk(020000000000000000000000000000000000000000000000000000000000000002)"
        ).unwrap();
        println!("{:?} pk", pk);
        println!("{:?} pubkey", pk.script_pubkey());
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
        println!("{:?} pkh", pkh);
        println!("{:?} pubhkey", pkh.script_pubkey());
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
        println!("{:?} wpkh",wpkh);
        println!("{:?} wpkh pubkey",wpkh.script_pubkey());
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

        println!("{:?} shwpkh", shwpkh);
        println!("{:?} shwpkh pubkey", shwpkh.script_pubkey());
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
        println!("{:?} sh", sh);
        println!("{:?} sh pubkey", sh.script_pubkey());
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
        println!("{:?} wsh", wsh);
        println!("{:?} wsh pubkey", wsh.script_pubkey());
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
        println!("{:?} shwsh", shwsh);
        println!("{:?} shwsh pubkey", shwsh.script_pubkey());
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

        println!("{:?} is sig", sig);
        println!("{:?} is sigser", sigser);
        let ms = Miniscript(astelem::AstElem::Pk(pk));
        println!("{:?} is ms encoded",ms.encode());
        println!("{:?} is ms", ms);
        let mut txin = bitcoin::TxIn {
            previous_output: bitcoin::OutPoint::default(),
            script_sig: bitcoin::Script::new(),
            sequence: 100,
            witness: vec![],
        };
        let bare = Descriptor::Bare(ms.clone());
        println!("{:?} is bare", bare);

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
        println!("{:?} pk script sig", txin.script_sig);
        assert_eq!(bare.unsigned_script_sig(), bitcoin::Script::new());

        let pkh = Descriptor::Pkh(pk);
        println!("{:?} is pkh", pkh);
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
        println!("{:?} pkh script sig", txin.script_sig);
        assert_eq!(pkh.unsigned_script_sig(), bitcoin::Script::new());

        let wpkh = Descriptor::Wpkh(pk);
        println!("{:?} is wpkh", wpkh);
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

        println!("{:?} wpkh witness", txin.witness);
        assert_eq!(wpkh.unsigned_script_sig(), bitcoin::Script::new());

        let shwpkh = Descriptor::ShWpkh(pk);
        println!("{:?} is shwpkh", shwpkh);
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

        println!("{:?} shwpkh witness", txin.witness);
        println!("{:?} shwpkh script sig", txin.script_sig);

        let sh = Descriptor::Sh(ms.clone());
        println!("{:?} is sh", sh);
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
        println!("{:?} sh witness", txin.witness);
        println!("{:?} sh script sig", txin.script_sig);

        let wsh = Descriptor::Wsh(ms.clone());

        println!("{:?} is wsh", wsh);
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

        println!("{:?} wsh witness", txin.witness);
        println!("{:?} wsh script sig", txin.script_sig);

        let shwsh = Descriptor::ShWsh(ms.clone());
        println!("{:?} is shwsh", shwsh);
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
        println!("{:?} shwsh witness", txin.witness);
        println!("{:?} shwsh script sig", txin.script_sig);
    }
}

