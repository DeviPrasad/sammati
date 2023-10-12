#![allow(dead_code)]

use crate::fip::AccDiscoveryReq;
use crate::mutter::Mutter;
use data_encoding::BASE64URL_NOPAD;
use dull::jws::SigVerifier;
use dull::jwt::DullJwtHeaderRep;
use dull::jwt::JwsHeaderDeserializer;
// use dull_jwt::jws;

/*
impl<T> ToString for DetachedContent<T>
where
    T: ToString,
{
    fn to_string(&self) -> String {
        self.data.to_string()
    }
}

impl<const S1: u16, const S2: u16, T: Serialize> DetachedSig<S1, S2> for DetachedContent<T> {
    fn sign(m: &str, _sk: &dyn Signer) -> Result<Bytes, Mutter> {
        error!("DetachedContent::sign {}", m);
        Err(Mutter::NotImplemented)
    }

    fn verify(m: &str, t: &Bytes, _vk: &dyn DetachedSigVerifier) -> Result<bool, Mutter> {
        error!("DetachedContent::verify plaintext {}", m);
        error!("DetachedContent::verify sig {:#?}", t);
        Err(Mutter::NotImplemented)
    }
}
*/

pub trait DetachedSigChecker {
    fn verify(&self, h: &[u8], t: &[u8], m: &str) -> Result<bool, Mutter>;
}

pub struct SigChecker {
    pub nks: dull::nickel::NickelKeyStore,
}

impl Default for SigChecker {
    fn default() -> Self {
        Self {
            nks: dull::nickel::NickelKeyStore::default(),
        }
    }
}

impl DetachedSigChecker for SigChecker {
    fn verify(&self, _h: &[u8], _t: &[u8], _m: &str) -> Result<bool, Mutter> {
        //dull::jwt::DullJwtHeaderRep::default()
        let _jv: dull::jws::DullJwsVerifier<'_> =
            dull::jws::DullJwsVerifier::from_key_resolver(&self.nks);

        Err(Mutter::BadBase64Encoding)
    }
}

// https://cryptobook.nakov.com/digital-signatures/ecdsa-sign-verify-messages#ecdsa-sign
// ECDSA signatures are 2 times longer than the signer's private key for the curve used.
// For example, for 256-bit elliptic curves (like secp256k1) the signature is 512 bits (64 bytes),
// and for 521-bit curves (like secp521r1) the signature is 1042 bits.
// ES256: 2 * CEIL(256/8) = 2 * 32 = 64 bytes ==> BASE64_URLENCODE(64_bytes) = 86 bytes
// ES384: 2 * CEIL(384/8) = 2 * 48 = 96 bytes ==> BASE64_URLENCODE(96_bytes) = 128 bytes
// ES512 has a private key size of 521 bits.
//     2 * CEIL(521/8) = 2 * 66 = 132 bytes
//     BASE64_URLENCODE(132_bytes) = 176 bytes.
#[derive(Clone, Debug)]
pub struct DetachedSignature {}
impl DetachedSignature {
    // 'dhs' is |BASE64-ENCODE(header).sig|
    // 'm'maybe plaintext - maybe vanilla json, or it could be base64-encoded claims/payload.
    pub fn verify(dhs: &[u8], m: &str) -> Result<bool, Mutter> {
        let mut iter = dhs.split(|c| *c == '.' as u8);
        log::info!("DetachedSignature::verify - start");
        let b64_header = iter
            .next()
            .ok_or_else(|| Mutter::InvalidDetachedSignature)?;
        log::info!("DetachedSignature::verify - base64 header found");
        // tag length cannot be greater than 176 bytes.
        // for ES512 alg, |sig| = |BASE64(r.s)| = |BASE64(132-bytes)| = 176 bytes.
        // for all other algs that we care about, this length will be smaller than 176 bytes.
        let tag = iter
            .next()
            .and_then(|sig| {
                if sig.len() < 86 || sig.len() > 176 {
                    None
                } else {
                    Some(sig)
                }
            })
            .ok_or_else(|| Mutter::InvalidDetachedSignature)?;
        log::info!("DetachedSignature::verify - tag found");
        if let Some(_) = iter.next() {
            return Err(Mutter::InvalidDetachedSignature);
        }
        log::info!("DetachedSignature::verify - header and tag extracted");
        let djh = DullJwtHeaderRep::default()
            .deserialize(b64_header)
            .map_err(|_e| {
                log::error!("DetachedSignature::verify - bad header {:#?}", _e);
                Mutter::BadBase64Encoding
            })?;
        log::info!(
            "DetachedSignature::verify - headerbase64-encoding good: {:#?}",
            djh
        );
        let ks = dull::nickel::NickelKeyStore::default();
        let jv: &dyn SigVerifier<'_, AccDiscoveryReq, 4096> =
            &dull::jws::DullJwsVerifier::from_key_resolver(&ks);
        let compact = [
            b64_header,
            ".".as_bytes(),
            BASE64URL_NOPAD.encode(m.as_bytes()).as_bytes(),
            ".".as_bytes(),
            tag,
        ]
        .concat();
        jv.verify(&(String::from_utf8(compact).unwrap()))
            .map(|adr| {
                log::info!("DetachedSignature::verify - verified: {:#?}", adr);
                true
            })
            .map_err(|_e| {
                log::info!("DetachedSignature::verify - failed: {:#?}", _e);
                Mutter::SignatureVerificationFailed
            })

        //SigChecker::default()
        //    .verify(&hv, tag, m)
        //    .and_then(|b: bool| match b {
        //        true => Ok(true),
        //        _ => Err(Mutter::SignatureVerificationFailed),
        //     })
    }
}
/*
pub fn verified(json: &str, sig: &Bytes) -> Result<T, Mutter> {
    let verifier = SigChecker::default();
    match serde_json::from_str::<T>(json) {
        Ok(t) => verifier.verify(json, sig)
            .and_then(|b: bool| {
                match b {
                    true => Ok(t),
                    _ => Err(Mutter::BadSignature)
                }
            }),
        _ => Err(Mutter::BadDetachedContent)
    }
}
*/

#[cfg(test)]
mod test_detached_sig {
    #[cfg(test)]
    //
    // RUSTFLAGS=${RUST_FLAGS} RUST_BACKTRACE=1 RUST_LOG=info cargo test --lib test_detached_sig -- --show-output
    //
    // Public and Private keys for ES512.
    // openssl ecparam -genkey -name secp521r1 -noout -out ec512-key-pair.pem
    // openssl ec -in ec512-key-pair.pem -pubout -out ec512-pub-key.pem
    // openssl pkcs8 -topk8 -nocrypt -in ec512-key-pair.pem -out ec512-pr-key.pem
    //
    // create a 64 byte (512-bit) value and base64 encode it.
    // import secrets
    // secrets.token_urlsafe(64)

    // verified with jwt.io
    // 256-bit (32 byte) random 'kid'
    // base64 url-encoded 512-bit (64 byte) key - 86 bytes in size here.
    use dull::jwa::SignatureAlgorithm;
    use dull::jws::{DullJwsVerifier, JWSigner, SigVerifier};
    use dull::jwt::JwseHeader;
    use dull::nickel::NickelKeyStore;
    use dull::webkey::{KeyDesc, KeyStore};

    use crate::fip::AccDiscoveryReq;
    const KID_ES512_PUBLIC_KEY_01: &[u8] = br#"LYD3GHRJgIOF5iQ3rvKdO48xoN1UfuuU1pQjJQEO0tk"#;
    const KID_ES512_PRIVATE_KEY_01: &[u8] = br#"Lr6-6i4ZXSACbZmfALwI-YjYGzKTIBwLfe7rvw1HlnI"#;
    const KID_ES512_PUBLIC_KEY_02: &[u8] = br#"F82YdM6XKOb6EqLByCbSiwGN0Ffbf-ADewYG8dGA3_c"#;
    const KID_ES512_PRIVATE_KEY_02: &[u8] = br#"yn4UTjbL3JfWhJj46GDaLc8MQFB6Pt23AA3bxH6e6Ow"#;
    #[test]
    pub fn test_es512_01() {
        let pub_key_pem = br#"-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAM+8WH9kliR1002mLgpHl+Q1e17/t
Rf9lOYUcLc21IFGt51zw7Jh3koF9UfWouNCYqnUspmA9U3AD5RDKOQmgtTcB0dv7
e3A26jrter5EQcGCUwSb/+Iro1e31P+hTAguwmgRcR/g5WGbzj2vJqYZGKiPSiNv
rFDkSniwjaEwEQ98KDo=
-----END PUBLIC KEY-----"#;
        let pr_key_pem = br#"-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBcPHRDLia3pjuxBjF
wiaB40FHrHQqfDD+imAt5ncXCoVUqEzHxzs0BQYRYnz9NE5WF9j9Ai8abydGtk3S
aBk7nKKhgYkDgYYABAAz7xYf2SWJHXTTaYuCkeX5DV7Xv+1F/2U5hRwtzbUgUa3n
XPDsmHeSgX1R9ai40JiqdSymYD1TcAPlEMo5CaC1NwHR2/t7cDbqOu16vkRBwYJT
BJv/4iujV7fU/6FMCC7CaBFxH+DlYZvOPa8mphkYqI9KI2+sUORKeLCNoTARD3wo
Og==
-----END PRIVATE KEY-----"#;
        let mut nks = NickelKeyStore::default();
        {
            let ks: &mut dyn KeyStore = &mut nks;
            let res = ks.add_sig_ec_public_key_pem(
                SignatureAlgorithm::ES512,
                &String::from_utf8(KID_ES512_PUBLIC_KEY_01.to_vec()).unwrap(),
                pub_key_pem,
            );
            assert!(res);
            let res = ks.add_sig_ec_private_key_pem(
                SignatureAlgorithm::ES512,
                &String::from_utf8(KID_ES512_PRIVATE_KEY_01.to_vec()).unwrap(),
                pr_key_pem,
            );
            assert!(res);
        }
        {
            let jws = JWSigner::for_nickel(&nks);
            let claims_json = br#"{"ver":"2.0.0","timestamp":"2023-10-10T22:23:01.104Z","txnid":"f35761ac-4a18-11e8-96ff-0277a9fbfedc","Customer":{"id":"https://sammati.org/v2/aa/vid/62415073905193203","Identifiers":[{"category":"STRONG","type":"AADHAAR","value":"150739051932"},{"category":"STRONG","type":"MOBILE","value":"9234567890"}]},"FITypes":["DEPOSIT","EDUCATION_LOAN","HOME_LOAN"]}"#;
            let kd = KeyDesc::from_alg_kid_type(
                SignatureAlgorithm::ES512,
                &String::from_utf8(KID_ES512_PRIVATE_KEY_01.to_vec()).unwrap(),
                "AT+JWT",
            );
            let header = JwseHeader::from_alg_type_kid(
                SignatureAlgorithm::ES512,
                "AT+JWT",
                &String::from_utf8(KID_ES512_PUBLIC_KEY_01.to_vec()).unwrap(),
            );
            let res = jws.signed_jwt_public_key_embedded(&kd, &header, claims_json);
            //println!("{:#?}", res);
            assert!(res.is_ok());
            println!("{:#?}", String::from_utf8(res.unwrap()).unwrap());
        }
    }
    #[test]
    pub fn test_es512_02() {
        let pub_key_pem = br#"-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAIhg9CZqpfVkZ2R8sgsfQxD+yr6dd
zGuAkCVQnNgd+gazK7s7bNBebR3O2WKp7RzmREeEyZLZsCttPraE2DYt4voAeTPK
oPCVdQSXCp/bllC2CilKZB9eV8Kc63CJQWCtCx+wFnvgtz31I8s4fyl0RLup8MsM
+qIzKdpFXXD9dGqGWBI=
-----END PUBLIC KEY-----"#;
        let pr_key_pem = br#"-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIANme+u5jHfsxd4GST
L8VtavJS4fPiM+XstAWwG1i3IjNqK1yL2VVM/o6fyMi4sFa0s+TfWlEFJa/+diKh
khdz79mhgYkDgYYABAAiGD0Jmql9WRnZHyyCx9DEP7Kvp13Ma4CQJVCc2B36BrMr
uzts0F5tHc7ZYqntHOZER4TJktmwK20+toTYNi3i+gB5M8qg8JV1BJcKn9uWULYK
KUpkH15XwpzrcIlBYK0LH7AWe+C3PfUjyzh/KXREu6nwywz6ojMp2kVdcP10aoZY
Eg==
-----END PRIVATE KEY-----"#;
        let mut nks = NickelKeyStore::default();

        {
            let ks: &mut dyn KeyStore = &mut nks;
            let res = ks.add_sig_ec_public_key_pem(
                SignatureAlgorithm::ES512,
                &String::from_utf8(KID_ES512_PUBLIC_KEY_02.to_vec()).unwrap(),
                pub_key_pem,
            );
            assert!(res);
            let res = ks.add_sig_ec_private_key_pem(
                SignatureAlgorithm::ES512,
                &String::from_utf8(KID_ES512_PRIVATE_KEY_02.to_vec()).unwrap(),
                pr_key_pem,
            );
            assert!(res);
        }
        {
            let jws = JWSigner::for_nickel(&nks);
            let claims_json = br#"{"ver":"2.0.0","timestamp":"2023-10-10T22:23:01.104Z","txnid":"f35761ac-4a18-11e8-96ff-0277a9fbfedc","Customer":{"id":"https://sammati.org/v2/aa/vid/62415073905193203","Identifiers":[{"category":"STRONG","type":"AADHAAR","value":"150739051932"},{"category":"STRONG","type":"MOBILE","value":"9234567890"}]},"FITypes":["DEPOSIT","EDUCATION_LOAN","HOME_LOAN"]}"#;
            let kd = KeyDesc::from_alg_kid_type(
                SignatureAlgorithm::ES512,
                &String::from_utf8(KID_ES512_PRIVATE_KEY_02.to_vec()).unwrap(),
                "DPOP+JWT",
            );
            let header = JwseHeader::from_alg_type_kid(
                SignatureAlgorithm::ES512,
                "DPOP+JWT",
                &String::from_utf8(KID_ES512_PUBLIC_KEY_02.to_vec()).unwrap(),
            );
            // sign
            let signed_jwt = jws.signed_jwt_public_key_embedded(&kd, &header, claims_json);
            assert!(signed_jwt.is_ok());
            // verify the JWT
            let jwt = signed_jwt.unwrap();
            println!("{:#?}", String::from_utf8(jwt.clone()).unwrap());

            let djv: DullJwsVerifier<'_> = DullJwsVerifier::from_key_resolver(&nks);
            let dv: &dyn SigVerifier<AccDiscoveryReq, 8092> =
                &djv as &dyn SigVerifier<AccDiscoveryReq, 8092>;
            let res = dv.verify(&String::from_utf8(jwt.clone()).unwrap());
            assert!(res.is_ok());
        }
    }
}
