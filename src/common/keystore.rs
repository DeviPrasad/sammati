#![allow(dead_code)]

use bytes::Bytes;
use log::error;
use serde::Serialize;
use std::collections::HashMap;
use std::result::Result;
use uuid::Uuid;

use crate::mutter::Mutter;

pub trait Signer {
    // fn init(&self, kd: &KeyDesc) -> Result<bool, Mutter>;
    fn sign(&self, m: &str) -> Result<Bytes, Mutter>;
}


pub struct HmacSha<const S: u16> {}
impl<const S: u16> Signer for HmacSha<S> {
    fn sign(&self, _m: &str) -> Result<Bytes, Mutter> {
        error!("HmacSha<{}>::Signer::sign", S);
        Err(Mutter::NotImplemented)
    }

    /*fn init(&self, kd: &KeyDesc) -> Result<bool, Mutter> {
        error!("HmacSha<{}>::Signer::init", S);
        Err(Mutter::NotImplemented)
    }*/
}

pub struct ECDSA<const S: u16> {
    pub kd: KeyDesc,
}
impl<const S: u16> Signer for ECDSA<S> {
    fn sign(&self, _m: &str) -> Result<Bytes, Mutter> {
        error!("ECDSA<{}>::Signer::sign", S);
        Err(Mutter::NotImplemented)
    }
}

impl<'a, const S: u16> ECDSA<S> {
    fn signer(kd: &KeyDesc) -> Result<Box<dyn Signer>, Mutter> {
        error!("ECDSA<{}>::Signer::init", S);
        if kd.kus != KeyUse::Sig || kd.sk.is_none() || kd.fmt != KeyFormat::Pem {
            Err(Mutter::BadKeyDesc)
        } else {
            let _k = kd.sk.as_ref().unwrap();
            Err(Mutter::NotImplemented)
            //let ec: Box<dyn Signer> = Box::new(ECDSA::<S> { kd: kd.to_owned() });
            //Ok(ec)
        }
    }
}
// public and private keys are 256 bits (32 octets) long and signatures are 512 bits (64 octets) long.
pub struct Ed25519 {}
impl Signer for Ed25519 {
    fn sign(&self, _m: &str) -> Result<Bytes, Mutter> {
        error!("Ed25519::sign");
        Err(Mutter::NotImplemented)
    }

    /*fn init(&self, kd: &KeyDesc) -> Result<bool, Mutter> {
        todo!()
    }*/
}

pub struct AesGcm<const S: u16> {}

pub struct Chacha20Poly1305 {}

#[derive(Hash, Eq, PartialEq, Debug, Clone)]
pub enum SigAlg {
    Ed25519,
    ES256,
    ES384,
    ES512,
    HS256,
    HS384,
    HS512,
}

#[derive(Hash, Eq, PartialEq, Debug, Clone)]
pub enum Cipher {
    A128GCM,
    A192GCM,
    A256GCM,
    Chacha20Poly1305,
}

#[derive(Clone, Debug, PartialEq)]
pub enum KeyType {
    EC,
    Oct,
    OKP,
}

impl KeyType {
    pub fn from(alg: &SigAlg) -> KeyType {
        match alg {
            SigAlg::ES256 | SigAlg::ES384 | SigAlg::ES512 => KeyType::EC,
            SigAlg::Ed25519 => KeyType::OKP,
            SigAlg::HS256 | SigAlg::HS384 | SigAlg::HS512 => KeyType::Oct,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum KeyUse {
    Sig,
    Enc,
}

#[derive(Clone, Debug, PartialEq)]
pub enum KeyOp {
    Sign,
    Verify,
    Encrypt,
    Decrypt,
}

#[derive(Clone, Debug, PartialEq)]
pub enum KeyFormat {
    Pem,
    Der,
    Octets,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct DenyParam {
    alg: Vec<String>,
    api_keys: Vec<String>,
    kid: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct KeyStoreParam {
    pub addr: String,
    pub port: u16,
    pub host: String,
    pub desc: String,
    #[serde(flatten)]
    pub deny: DenyParam,
}

pub trait Keystore {
    fn signer(&self, kid: &str) -> Result<Box<dyn Signer>, Mutter>;
    fn verifier(&self, kid: &str) -> Result<Box<dyn Signer>, Mutter>;
}

#[derive(Debug, Clone)]
pub struct KeyDesc {
    pub kid: String,
    alg: SigAlg,
    kty: KeyType,
    kus: KeyUse,
    ops: Vec<KeyOp>,
    fmt: KeyFormat,
    sk: Option<Bytes>,
    vk: Option<Bytes>,
}

impl KeyDesc {
    pub const KEY_OP_SIGN: u8 = 1;
    pub const KEY_OP_VERIFY: u8 = 2;
    pub const KEY_OP_SIGN_AND_VERIFY: u8 = 3;

    pub fn new(
        kid: &Uuid,
        alg: SigAlg,
        ops: u8,
        fmt: &KeyFormat,
        sk: Option<Bytes>,
        vk: Option<Bytes>,
    ) -> Result<Self, Mutter> {
        if ops < 1 || ops > 3 {
            return Err(Mutter::BadRequestArgs);
        }
        let can_sign = ops & KeyDesc::KEY_OP_SIGN > 0;
        let can_verify = ops & KeyDesc::KEY_OP_VERIFY > 0;
        if (can_sign && sk.is_none()) || (!can_sign && sk.is_some()) {
            return Err(Mutter::BadRequestArgs);
        }
        if (can_verify && vk.is_none()) || (!can_verify && vk.is_some()) {
            return Err(Mutter::BadRequestArgs);
        }
        let mut key_ops = Vec::<KeyOp>::new();
        if can_sign {
            key_ops.push(KeyOp::Sign);
        }
        if can_verify {
            key_ops.push(KeyOp::Verify);
        }
        Ok(KeyDesc {
            kid: kid.to_string(),
            kty: KeyType::from(&alg),
            alg,
            kus: KeyUse::Sig,
            ops: key_ops,
            fmt: fmt.clone(),
            sk,
            vk,
        })
    }

    pub fn signer(&self) -> Result<Box<dyn Signer>, Mutter> {
        if self.kus != KeyUse::Sig || self.sk.is_none() {
            return Err(Mutter::BadKeyDesc);
        }
        /* match self.alg {
            SigAlg::ES256 | SigAlg::ES384 | SigAlg::ES512 => {
                if self.kty != KeyType::EC {
                    return Err(Mutter::BadKeyDesc);
                }
            }
            SigAlg::Ed25519 => {
                if self.kty != KeyType::OKP {
                    return Err(Mutter::BadKeyDesc);
                }
            }
            SigAlg::HS256 | SigAlg::HS384 | SigAlg::HS512 => {
                if self.kty != KeyType::Oct {
                    return Err(Mutter::BadKeyDesc);
                }
            }
        }*/
        match self.alg {
            SigAlg::ES256 => ECDSA::<256>::signer(self),
            SigAlg::ES384 => ECDSA::<384>::signer(self),
            SigAlg::ES512 => ECDSA::<512>::signer(self),
            SigAlg::Ed25519 => todo!(),
            SigAlg::HS256 => todo!(),
            SigAlg::HS384 => todo!(),
            SigAlg::HS512 => todo!(),
        }
    }
}

// an in-memory (volatile) keystore mostly used for trivial caching/testing.
#[derive(Debug)]
pub struct Wola {
    pub(crate) keys: HashMap<String, KeyDesc>,
}

impl Wola {
    fn new() -> Wola {
        Wola {
            keys: HashMap::<String, KeyDesc>::new(),
        }
    }
}

impl Keystore for Wola {
    fn signer(&self, kid: &str) -> Result<Box<dyn Signer>, Mutter> {
        match self.keys.get(kid) {
            Some(kd) => kd.signer(),
            _ => Err(Mutter::SigningKeyNotFound),
        }
    }

    fn verifier(&self, _kid: &str) -> Result<Box<dyn Signer>, Mutter> {
        Err(Mutter::NotImplemented)
    }
}

//
// cargo test keystore:: --lib  -- --show-output
#[cfg(test)]
mod keystore {
    use crate::keystore::KeyFormat;

    use super::{KeyDesc, Wola};

    #[test]
    fn good_test_001() {
        let mut wks: Wola = Wola::new();
        let res = wks.keys.insert(
            "bb906ca2-bfea-4532-b63f-b0e6aef9d02a".to_string(),
            KeyDesc {
                kid: "bb906ca2-bfea-4532-b63f-b0e6aef9d02a".to_string(),
                alg: super::SigAlg::ES256,
                kty: super::KeyType::EC,
                kus: super::KeyUse::Sig,
                ops: [super::KeyOp::Sign, super::KeyOp::Verify].into(),
                fmt: KeyFormat::Pem,
                sk: None,
                vk: None,
            },
        );
        assert!(matches!(res, None));

        assert!(wks
            .keys
            .contains_key(&"bb906ca2-bfea-4532-b63f-b0e6aef9d02a".to_string()));
    }
}
