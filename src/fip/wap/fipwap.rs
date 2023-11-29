#![allow(dead_code)]

use std::{pin::Pin, sync::OnceLock};

use dull::{jws::DetachedSig, jwt::Grumble};
use hyper::{Body, Request};
use serde::{Deserialize, Serialize};

use common::{
    cfg::Config,
    fip,
    hs::{self, BodyTrait, Headers, HttpEndpoint, HttpMethod, InfallibleResult, HTTP_PROC},
    mutter::{self, Mutter},
    ts::UtcTs,
    types::{
        ErrResp, ErrorCode, FIPAccLinkReqRefNum, FIPAccLinkStatus, FIPAccLinkingAuthType,
        InterfaceResponse, Type, ValidationError,
    },
    CommandlineArgs,
};

#[derive(Debug)]
pub struct HttpReqProc {}

// endpoint config for shared access
pub static EP_CFG: OnceLock<Box<Config>> = OnceLock::<Box<Config>>::new();
pub static JWS: OnceLock<Pin<Box<dyn dull::jws::JwsDetachedSigVerifier>>> =
    OnceLock::<Pin<Box<dyn dull::jws::JwsDetachedSigVerifier>>>::new();
// _NICKEL_KEY_STORE_ is an implementation detail. It is used to construct 'JWS' defined above.
pub static _NICKEL_KEY_STORE_: OnceLock<dull::nickel::NickelKeyStore> =
    OnceLock::<dull::nickel::NickelKeyStore>::new();

pub static BAD_CONTENT_TYPE: &'static str = "content-type value must be application/json";
pub static MISSING_CONTENT_TYPE: &'static str = "missing content-type header parameter";
pub static JWS_KEYSTORE_ACCESS: &'static str = "JWS keystore access error";
pub static INVALID_DETACHED_SIG: &'static str = "Invalid detached signature";
pub static MISSING_DETACHED_SIG: &'static str = "Signature missing - cannot authenticate request";
pub static ERROR_READING_HTTP_BODY: &'static str = "Error in reading body content";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Kube {
    pid: String,
    tid: String,
    url: String,
    cid: u32,
}

impl Default for Kube {
    fn default() -> Self {
        let (url, cid) = match EP_CFG.get() {
            Some(cfg) => (cfg.host.url.to_owned(), cfg.host.cid),
            _ => ("https://sammati.in/aa/eco".to_string(), 0),
        };
        Kube {
            pid: format!("pid_{:?}", std::process::id()),
            tid: format!("tid_{:?}", std::thread::current().id()),
            url,
            cid,
        }
    }
}

impl HttpMethod for HttpReqProc {
    fn get(&self, req: Request<Body>) -> InfallibleResult {
        log::info!("FIP App Proxy - HttpMethod::HttpPost::proc GET {req:#?}");
        let (head, body) = req.into_parts();
        match body.size_ok(0) {
            Ok(_) => {
                let (uri, _headers) = (head.uri.clone(), Headers::from(head.headers));
                match uri.path() {
                    "/Heartbeat" => hs::answer_health_ok(),
                    p => hs::flag(hs::error_unsupported_request(p)),
                }
            }
            // non-empty body in HTTP GET is considered an error.
            _ => hs::flag(hs::error_nonempty_body()),
        }
    }

    fn post(&self, req: Request<Body>) -> InfallibleResult {
        log::info!("FIP App Proxy - HttpMethod::HttpPost");
        let (head, body) = req.into_parts();
        let (uri, hp) = (head.uri.clone(), Headers::from(head.headers));
        // 'content-type' must be 'application/json'
        match check_content_type_application_json(&hp) {
            Ok(_) => match unpack_body(body) {
                Ok(body_json) => match __unauthenticated_dispatch__(&uri, &hp, &body_json) {
                    Ok(good) => hs::answer(good),
                    Err(bad) => hs::flag(bad),
                },
                Err(ValidationError(ec, em)) => {
                    hs::flag_error_ext(ec.to_http_status_code(), ec, &em)
                }
            },
            Err(ValidationError(ec, em)) => hs::flag_error_ext(ec.to_http_status_code(), ec, &em),
        }
    }
}

fn __unauthenticated_dispatch__(
    uri: &hyper::Uri,
    hp: &Headers,
    json: &String,
) -> Result<Box<dyn InterfaceResponse>, Box<dyn InterfaceResponse>> {
    dispatch(&uri, &hp, &json)
}

fn authenticated_dispatch(
    uri: &hyper::Uri,
    hp: &Headers,
    json: &String,
) -> Result<Box<dyn InterfaceResponse>, Box<dyn InterfaceResponse>> {
    match authenticate_request(&hp, &json) {
        Ok(_) => dispatch(&uri, &hp, &json),
        Err(ValidationError(ec, em)) => {
            // invalid API key, invalid x-jws-signature, invalid dpop
            Err(Box::new(ErrResp::<Kube>::v2(
                &hp.tx_id(),
                &UtcTs::now(),
                &ec,
                &em,
                ec.to_http_status_code(),
                None,
            )))
        }
    }
}

fn unpack_body(b: Body) -> Result<String, ValidationError> {
    match b.size_ok(Body::POST_REQUEST_PAYLOAD_SIZE_MAX) {
        Ok(_) => Body::read(b).map_err(|_| {
            ValidationError(
                ErrorCode::ErrorReadingRequestBody,
                ERROR_READING_HTTP_BODY.to_owned(),
            )
        }),
        _ => Err(ValidationError(
            ErrorCode::PayloadTooLarge,
            format!(
                "Max permitted size of the payload is {} bytes",
                Body::POST_REQUEST_PAYLOAD_SIZE_MAX
            ),
        )),
    }
}

fn dispatch(
    uri: &hyper::Uri,
    hp: &Headers,
    json: &String,
) -> Result<Box<dyn InterfaceResponse>, Box<dyn InterfaceResponse>> {
    log::info!(
        "FIP App Proxy - HttpMethod::HttpPost::proc {hp:#?} {:#?}",
        uri.path()
    );
    match uri.path() {
        "/Accounts/discover" => {
            log::info!("FIP POST /Accounts/discover");
            let adr: fip::AccDiscoveryReq = Type::from_json::<fip::AccDiscoveryReq>(&json, &hp)?;
            log::info!("/Accounts/discover {:#?}", adr);
            Ok(Box::new(fip::AccDiscoveryResp::new(&adr, &Vec::new())))
        }
        "/Accounts/link" => {
            log::info!("FIP POST /Accounts/link");
            let alr = Type::from_json::<fip::AccLinkReq>(&json, &hp)?;
            log::info!("/Accounts/link {alr:#?}");
            let at: FIPAccLinkingAuthType = FIPAccLinkingAuthType::DIRECT;
            let acc_ref_num = FIPAccLinkReqRefNum::from("f6b1482e-8f08-11e8-862a-02552b0d3c36")
                .expect("account link ref number");
            Ok(Box::new(fip::AccLinkResp::new(&alr, &at, &acc_ref_num)))
        }
        "/Accounts/delink" => {
            log::info!("FIP POST /Accounts/delink");
            let alr = Type::from_json::<fip::AccDelinkReq>(&json, &hp)?;
            log::info!("/Accounts/delink {alr:#?}");
            Ok(Box::new(fip::AccDelinkResp::new(
                &alr,
                FIPAccLinkStatus::PENDING,
            )))
        }
        "/Accounts/link/verify" => {
            log::info!("FIP POST /Accounts/link/verify");
            let lvr = Type::from_json::<fip::FIPAccLinkVerifyReq>(&json, &hp)?;
            log::info!("/Accounts/link/verify {lvr:#?}");
            Ok(Box::new(fip::FIPAccLinkVerifyResp::mock_response(&lvr)))
        }
        "/FI/request" => {
            let fir = Type::from_json::<fip::FIRequest>(&json, &hp)?;
            log::info!("FIP POST /FI/request {fir:#?}");
            Ok(Box::new(fip::FIResp::mock_response(&fir)))
        }
        "/FI/fetch" => {
            let fi_fetch_req = Type::from_json::<fip::FIFetchReq>(&json, &hp)?;
            log::info!("FIP POST /FI/request {fi_fetch_req:#?}");
            Ok(Box::new(fip::FIFetchResp::mock_response(&fi_fetch_req)))
        }
        "/Consent/Notification" => {
            log::info!("FIP POST /Consent/Notification");
            Err(hs::error_unimplemented_request("/Consent/Notification"))
        }
        "/Consent" => {
            // once the AA obtains a consent artefact, AA shared it with FIP here.
            log::info!("FIP POST /Consent");
            let cr = Type::from_json::<fip::ConsentArtefactReq>(&json, &hp)?;
            log::info!("{:#?}", cr);
            Ok(Box::new(fip::ConsentArtefactResp::new(&cr)))
        }
        _ => {
            log::error!("FIP unsupported request {}", uri.path());
            Err(hs::error_unsupported_request(uri.path()))
        }
    }
}

fn check_content_type_application_json(hp: &Headers) -> Result<(), ValidationError> {
    let ct = hp.probe("Content-Type");
    if ct.is_none()
        || ct.is_some_and(|ct| {
            let mut s = ct.split(";");
            let ct = s.next().unwrap();
            ct.eq_ignore_ascii_case("application/json")
        })
    {
        Ok(())
    } else {
        Err(ValidationError(
            ErrorCode::InvalidRequest,
            BAD_CONTENT_TYPE.to_owned(),
        ))
    }
}

fn authenticate_request(hp: &Headers, body_json: &String) -> Result<(), ValidationError> {
    let _dpop = hp.probe("DPoP");
    let api_key = hp.probe("x-sammati-api-key");
    let x_jws_sig = hp.probe("x-jws-signature");

    // check if api_key looks ok
    if api_key.is_none() || api_key.as_ref().is_some_and(|s| s.len() < 16) {
        Err(ValidationError(
            ErrorCode::Unauthorized,
            "Bad API Key".to_owned(),
        ))
    } else if let Some(ds) = x_jws_sig {
        // validate the detached signature and the content payload.
        match JWS.get() {
            Some(djv) => djv
                .verify(&DetachedSig::from(&ds.as_bytes()), &body_json.as_bytes())
                .map(|_| log::info!("Message signature verified. Request authenticated."))
                .map_err(|e| {
                    log::error!("Message signature verification failed");
                    ValidationError(
                        match e {
                            Grumble::Base64EncodingBad => ErrorCode::InvalidBase64Encoding,
                            Grumble::BadDetachedSignature => ErrorCode::InvalidDetachedSignature,
                            _ => ErrorCode::SignatureDoesNotMatch,
                        },
                        INVALID_DETACHED_SIG.to_owned(),
                    )
                }),
            _ => Err(hs::internal_error(JWS_KEYSTORE_ACCESS)),
        }
    } else {
        log::error!("Message signature missing - forbidden request");
        Err(ValidationError(
            ErrorCode::Unauthorized,
            MISSING_DETACHED_SIG.to_owned(),
        ))
    }
}

// run as
// RUST_LOG=debug cargo run --bin fip_wap -- --config mock/config/fip-wap-cfg.json
// RUSTFLAGS='--cfg production' cargo  run --bin fip_wap -- --config mock/config/fip-wap-cfg.json
// cargo run --bin fip_wap -- --config mock/config/fip-wap-cfg.json
// dev_test conditional compilation
// RUSTFLAGS='--cfg dev_test' cargo  run --bin fip_wap -- --config mock/config/fip-wap-cfg.json
#[tokio::main]
async fn main() {
    mutter::init_log();
    log::info!("FIP App Proxy");

    let s = HttpReqProc {};
    let _ = HTTP_PROC.set(Box::pin(s));

    let cmd: Result<Config, Mutter> = CommandlineArgs::config();
    log::info!("Commandline arg: {:#?}", cmd);
    match cmd {
        Ok(cfg) => {
            log::info!("Try FIP App Proxy init...");
            EP_CFG
                .set(Box::<Config>::new(cfg.clone()))
                .expect("kube config");

            //#[cfg(not(dev_test))]
            #[cfg(production)]
            {
                let nks = dull::nickel::NickelKeyStore::default();
                _NICKEL_KEY_STORE_.set(nks).expect("nickel keystore");
                let _ = JWS.set(Box::pin(dull::jws::SigVerifier::new(
                    _NICKEL_KEY_STORE_.get().unwrap(),
                )));
            }
            #[cfg(not(production))]
            {
                let mut nks = dull::nickel::NickelKeyStore::default();
                nickel_cache_init_well_known_sig_keys(&mut nks);
                _NICKEL_KEY_STORE_.set(nks).expect("nickel keystore");
                let _ = JWS.set(Box::pin(dull::jws::SigVerifier::new(
                    _NICKEL_KEY_STORE_.get().unwrap(),
                )));
            }
            let _ = HttpEndpoint::start(&cfg).await;
        }
        _ => {
            log::error!("Error - FIP App Proxy initialization failed. Quitting.");
            std::process::exit(2);
        }
    }
}

// dev_test conditional compilation
// RUSTFLAGS='--cfg dev_test' cargo  run --bin fip_wap -- --config mock/config/fip-wap-cfg.json
#[cfg(not(production))]
fn nickel_cache_init_well_known_sig_keys(nks: &mut dull::nickel::NickelKeyStore) {
    const FIP_WAP_HS512_KID_01: &str = "GRVj3Kqoq2Qe7WLqI0dKSecjMJdcpLOaXVXfwQekkDc";
    const FIP_WAP_HS256_KID_02: &str = "iMqHlCcok0lLZfphYdjh-HaBlb0T8hCcGQf4skWcf8g";
    const FIP_WAP_HS512_KEY: &str =
        "x4w7vzRFbvbrZ1IArIKKDgHQ3p6XC7CF5AowbojVCbcQIgexHwefDrYyUw0T43hnWsBJBcj5jD11hPgBHCJXIQ";
    const FIP_WAP_HS256_KEY: &str = "U9DayvJzo8hXTvDpy_psbaRDjcGUukmUR6oFfj7CURPBrPOC3ZL-6cO363dg";
    const SAMMATI_AA_ES256_PUB_KEY: &[u8] = br#"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
-----END PUBLIC KEY-----"#;
    const SAMMATI_AA_ES256_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2
OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r
1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G
-----END PRIVATE KEY-----";
    const SAMMATI_AA_ES256_PRIVATE_KEY_KID: &str = "vPfRqE60B33tzVlF5E6OA2mKK17sGRXsfrI9obBEjL5";
    const SAMMATI_AA_ES256_PUBKEY_KID_25: &str = "RP4J7WDWoT-JP00a81lOIn-6q1LkscQ-r-IoyWPS-Nk";

    const SAMMATI_AA_ED25519_PUB_KEY_PEM_02: &[u8] = br#"-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA+hf401REYXC81NHtQr9PfEQh0SXNE1vng+WRqT8CRvg=
-----END PUBLIC KEY-----"#;
    const SAMMATI_AA_KID_ED25519_PUBLIC_KEY_02: &str =
        "KICAgICAgICAgICAgInVuaXQiOiAiTU9OVEgiLA0KIC";

    //let mut nks = NickelKeyStore::default();
    {
        let ks: &mut dyn dull::webkey::KeyStore = nks;
        let res = ks.add_sig_hmac_key(
            dull::jwa::SignatureAlgorithm::HS512,
            FIP_WAP_HS512_KID_01,
            FIP_WAP_HS512_KEY.as_bytes(),
        );
        assert!(res);
        let res = ks.add_sig_hmac_key(
            dull::jwa::SignatureAlgorithm::HS256,
            FIP_WAP_HS256_KID_02,
            // key size is 45 bytes (suitable for HS256; not for HS384, which requires min length of 48 bytes)
            FIP_WAP_HS256_KEY.as_bytes(),
        );
        assert!(res);
        // add ES256 public key to the cache
        let res = ks.add_sig_ec_public_key_pem(
            dull::jwa::SignatureAlgorithm::ES256,
            SAMMATI_AA_ES256_PUBKEY_KID_25,
            SAMMATI_AA_ES256_PUB_KEY,
        );
        assert!(res);
        // add Ed25519 public key to the cache
        let res = ks.add_sig_ed25519_public_key_pem(
            SAMMATI_AA_KID_ED25519_PUBLIC_KEY_02,
            SAMMATI_AA_ED25519_PUB_KEY_PEM_02,
        );
        assert!(res);
    }
}

// quick test
// curl -v -H"Accept: application/json" -X GET http://fip-wap.sammati.web3pleb.org:40601/Heartbeat
// curl -v -H"Accept: application/json" -X POST http://fip-wap.sammati.web3pleb.org:40601/FI/fetch
//
#[cfg(test)]
mod tests {
    use std::fmt::Debug;

    use dull::jwa::SignatureAlgorithm;
    use dull::jws::JWSigner;
    use dull::jwt::JwsHeaderBuilder;
    use dull::nickel::NickelKeyStore;
    use dull::webkey::{KeyDesc, KeyStore};
    use serde::{Deserialize, Serialize};

    use common::ts::UtcTs;
    use common::types::HealthOkResp;
    use common::types::{Empty, ServiceHealthStatus};

    #[test]
    fn simple_ok_response() {
        let resp: HealthOkResp<Empty> =
            HealthOkResp::<Empty>::v2(&UtcTs::now(), ServiceHealthStatus::DOWN, None);
        //eprintln!("simple_ok_response object: {:#?}", resp);
        let json = serde_json::to_string(&resp);
        //eprintln!("simple_ok_response json: {:#?}", json);
        assert!(matches!(json, Ok(_)));
    }

    #[test]
    fn simple_ok_response_round_trip() {
        let serialized_okr = serde_json::to_string(&HealthOkResp::<Empty>::v2(
            &UtcTs::now(),
            ServiceHealthStatus::DOWN,
            Some(Empty::default()),
        ));
        let okr_json_str: String = serialized_okr.unwrap();
        //eprintln!("json = {}", okr_json_str);
        let deserialized_okr = serde_json::from_str(&okr_json_str);
        //eprintln!("serialization result = {:#?}", deserialized_okr);
        let okr: HealthOkResp<Empty> = deserialized_okr.unwrap();
        //eprintln!("version = {:#?}", okr);
        assert_eq!(okr.ver, "2.0.0");
        let serialized_okr_2 = serde_json::to_string(&okr);
        //eprintln!("json = {:#?}", serialized_okr_2);
        assert_eq!(okr_json_str, serialized_okr_2.unwrap())
    }

    const FIP_WAP_HS512_KID_01: &str = "GRVj3Kqoq2Qe7WLqI0dKSecjMJdcpLOaXVXfwQekkDc";
    const FIP_WAP_HS512_KEY: &str =
        "x4w7vzRFbvbrZ1IArIKKDgHQ3p6XC7CF5AowbojVCbcQIgexHwefDrYyUw0T43hnWsBJBcj5jD11hPgBHCJXIQ";

    #[test]
    fn simple_ok_response_custom() {
        #[derive(Debug, Clone, Serialize, Deserialize)]
        struct FipNode {
            pid: String,
            tid: String,
            url: String,
        }
        impl Default for FipNode {
            fn default() -> Self {
                FipNode {
                    pid: format!("pid_{:?}", std::process::id()),
                    tid: format!("tid_{:?}", std::thread::current().id()),
                    url: "https://fip-wap.sammati.in/Heartbeat".to_string(),
                }
            }
        }
        let resp: HealthOkResp<FipNode> = HealthOkResp::<FipNode>::v2(
            &UtcTs::now(),
            ServiceHealthStatus::DOWN,
            Some(FipNode::default()),
        );
        //eprintln!("simple_ok_response object: {:#?}", resp);
        let json = serde_json::to_string(&resp);
        //eprintln!("simple_ok_response json: {:#?}", json);
        assert!(matches!(json, Ok(_)))
    }

    const SAMMATI_AA_ES256_PUBLIC_KEY: &[u8] = br#"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
-----END PUBLIC KEY-----"#;
    const SAMMATI_AA_ES256_PRIVATE_KEY: &[u8] = br#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2
OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r
1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G
-----END PRIVATE KEY-----"#;
    const KID_SAMMATI_AA_ES256_PRIVATE_KEY: &str = "vPfRqE60B33tzVlF5E6OA2mKK17sGRXsfrI9obBEjL5";
    const KID_SAMMATI_AA_ES256_PUBLIC_KEY: &str = "RP4J7WDWoT-JP00a81lOIn-6q1LkscQ-r-IoyWPS-Nk";

    #[test]
    pub fn test_unencoded_sammati_accounts_link_ed25519() {
        let ed25519_pub_key_pem_02 = br#"-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA+hf401REYXC81NHtQr9PfEQh0SXNE1vng+WRqT8CRvg=
-----END PUBLIC KEY-----"#;
        let ed25519_pr_key_pem_02 = br#"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEILISPPYTpXnbOO1z7CyMOM32H5Mw0VmMsstn36dH0l+P
-----END PRIVATE KEY-----"#;
        let mut nks = NickelKeyStore::default();
        const KID_ED25519_PUBLIC_KEY_02: &str = "KICAgICAgICAgICAgInVuaXQiOiAiTU9OVEgiLA0KIC";
        const KID_ED25519_PRIVATE_KEY_02: &[u8] = br#"B7DQogICAgICAgICAgICAgICAgInR5cGUiOiAicHVyc"#;
        {
            let ks: &mut dyn KeyStore = &mut nks;
            let res = ks.add_sig_ed25519_private_key_pem(
                &String::from_utf8(KID_ED25519_PRIVATE_KEY_02.to_vec()).unwrap(),
                ed25519_pr_key_pem_02,
            );
            assert!(res);
            let res = ks.add_sig_ed25519_public_key_pem(
                &String::from_utf8(KID_ED25519_PUBLIC_KEY_02.into()).unwrap(),
                ed25519_pub_key_pem_02,
            );
            assert!(res);
            let res = ks.add_sig_hmac_key(
                dull::jwa::SignatureAlgorithm::HS512,
                FIP_WAP_HS512_KID_01,
                FIP_WAP_HS512_KEY.as_bytes(),
            );
            assert!(res);
            let res = ks.add_sig_ec_private_key_pem(
                dull::jwa::SignatureAlgorithm::ES256,
                KID_SAMMATI_AA_ES256_PRIVATE_KEY,
                SAMMATI_AA_ES256_PRIVATE_KEY,
            );
            assert!(res);
            let res = ks.add_sig_ec_public_key_pem(
                dull::jwa::SignatureAlgorithm::ES256,
                KID_SAMMATI_AA_ES256_PUBLIC_KEY,
                SAMMATI_AA_ES256_PUBLIC_KEY,
            );
            assert!(res);
        }
        let jws = JWSigner::for_nickel(&nks);
        let accounts_link_req_json = br#"{"ver":"2.1.0","timestamp":"2023-11-10T17:51:18.412Z","txnid":"f35761ac-4a18-11e8-96ff-0277a9fbfedc","Customer":{"id":"sammati.in/aa/uid/62415273490451973263","Accounts":[{"FIType":"DEPOSIT","accType":"SAVINGS","accRefNumber":"NADB0000570926453147364217812345","maskedAccNumber":"XXXXXXXXXXXXX0753468"},{"FIType":"DEPOSIT","accType":"SAVINGS","accRefNumber":"NADB0000570926453147364217812345","maskedAccNumber":"XXXXXXXXXXXXX2853165"}]}}"#;
        {
            let kd = KeyDesc::from_alg_kid(
                SignatureAlgorithm::EdDSA,
                &String::from_utf8(KID_ED25519_PRIVATE_KEY_02.to_vec()).unwrap(),
            );
            let header_ed25519 = JwsHeaderBuilder::new()
                .alg(SignatureAlgorithm::EdDSA)
                .unencoded()
                .kid(KID_ED25519_PUBLIC_KEY_02)
                .critical(vec!["b64".to_owned()])
                .build()
                .unwrap();

            // sign
            let ds = jws.sign(&kd, &header_ed25519, accounts_link_req_json);
            // let jws = jws.sign(&kd, &header, consent_req_json);
            if ds.is_err() {
                eprintln!(
                    "test_unencoded_sammati_accounts_link_ed25519 - unencoded-jws[1] {:#?}",
                    ds
                );
            }
            assert!(ds.is_ok());
            /*let ds = ds.unwrap();
            eprintln!(
                "test_unencoded_sammati_accounts_link_ed25519 - unencoded-jws[2] {:#?}",
                String::from_utf8(ds.clone()).unwrap()
            );*/
        }
        {
            let kd = KeyDesc::from_alg_kid(SignatureAlgorithm::HS512, FIP_WAP_HS512_KID_01);
            let header_hs512 = JwsHeaderBuilder::new()
                .alg(SignatureAlgorithm::HS512)
                .unencoded()
                .kid(FIP_WAP_HS512_KID_01)
                .critical(vec!["b64".to_owned()])
                .build()
                .unwrap();
            let jws = jws.sign(&kd, &header_hs512, accounts_link_req_json);
            // let jws = jws.sign(&kd, &header, consent_req_json);
            if jws.is_err() {
                eprintln!(
                    "test_unencoded_sammati_accounts_link_hs512 - unencoded-jws[1] {:#?}",
                    jws
                );
            }
            assert!(jws.is_ok());
            /*let jws = jws.unwrap();
            eprintln!(
                "test_unencoded_sammati_accounts_link_hs512 - unencoded-jws[2] {:#?}",
                String::from_utf8(jws.clone()).unwrap()
            );*/
        }
        //
        let accounts_delink_req_json=br#"{"ver":"2.1.0","timestamp":"2023-11-10T17:51:18.412Z","txnid":"f35761ac-4a18-11e8-96ff-0277a9fbfedc","Account":{"customerAddress":"sammati.in/aa/uid/62415273490451973263","linkRefNumber":"14c3c1ee8b7a8e54fef456c4d6eb7b2b"}}"#;
        {
            let kd = KeyDesc::from_alg_kid(SignatureAlgorithm::HS512, FIP_WAP_HS512_KID_01);
            let header_hs512 = JwsHeaderBuilder::new()
                .alg(SignatureAlgorithm::HS512)
                .unencoded()
                .kid(FIP_WAP_HS512_KID_01)
                .critical(vec!["b64".to_owned()])
                .build()
                .unwrap();
            let jws = jws.sign(&kd, &header_hs512, accounts_delink_req_json);
            if jws.is_err() {
                eprintln!(
                    "test_unencoded_sammati_accounts_delink_hs512 - unencoded-jws[1] {:#?}",
                    jws
                );
            }
            assert!(jws.is_ok());
            /*let jws = jws.unwrap();
            eprintln!(
                "test_unencoded_sammati_accounts_delink_hs512 - unencoded-jws[2] {:#?}",
                String::from_utf8(jws.clone()).unwrap()
            );*/
        }
        {
            let kd = KeyDesc::from_alg_kid(
                SignatureAlgorithm::EdDSA,
                &String::from_utf8(KID_ED25519_PRIVATE_KEY_02.to_vec()).unwrap(),
            );
            let header_ed25519 = JwsHeaderBuilder::new()
                .alg(SignatureAlgorithm::EdDSA)
                .unencoded()
                .kid(KID_ED25519_PUBLIC_KEY_02)
                .critical(vec!["b64".to_owned()])
                .build()
                .unwrap();

            let jws = jws.sign(&kd, &header_ed25519, accounts_delink_req_json);
            if jws.is_err() {
                eprintln!(
                    "test_unencoded_sammati_accounts_delink_ed25519 - unencoded-jws[1] {:#?}",
                    jws
                );
            }
            assert!(jws.is_ok());
            /*let jws = jws.unwrap();
            eprintln!(
                "test_unencoded_sammati_accounts_delink_ed25519 - unencoded-jws[2] {:#?}",
                String::from_utf8(jws.clone()).unwrap()
            );*/
        }
        //
        let accounts_link_verify_req_json=br#"{"ver":"2.1.0","timestamp":"2023-11-10T17:51:18.412Z","txnid":"f35761ac-4a18-11e8-96ff-351804dfcdc5","refNumber":"mNyaXQiOlsiYjY0Il0sImtpZCItJQ0Fn","token":"165023"}"#;
        {
            let kd = KeyDesc::from_alg_kid(SignatureAlgorithm::HS512, FIP_WAP_HS512_KID_01);
            let header_hs512 = JwsHeaderBuilder::new()
                .alg(SignatureAlgorithm::HS512)
                .unencoded()
                .kid(FIP_WAP_HS512_KID_01)
                .critical(vec!["b64".to_owned()])
                .build()
                .unwrap();
            let jws = jws.sign(&kd, &header_hs512, accounts_link_verify_req_json);
            if jws.is_err() {
                eprintln!(
                    "test_unencoded_sammati_accounts_link_verify_req_hs512 - unencoded-jws[1] {:#?}",
                    jws
                );
            }
            assert!(jws.is_ok());
            /*let jws = jws.unwrap();
            eprintln!(
                "test_unencoded_sammati_accounts_link_verify_req_hs512 - unencoded-jws[2] {:#?}",
                String::from_utf8(jws.clone()).unwrap()
            );*/
        }
        {
            let kd = KeyDesc::from_alg_kid(
                SignatureAlgorithm::EdDSA,
                &String::from_utf8(KID_ED25519_PRIVATE_KEY_02.to_vec()).unwrap(),
            );
            let header_ed25519 = JwsHeaderBuilder::new()
                .alg(SignatureAlgorithm::EdDSA)
                .unencoded()
                .kid(KID_ED25519_PUBLIC_KEY_02)
                .critical(vec!["b64".to_owned()])
                .build()
                .unwrap();

            let jws = jws.sign(&kd, &header_ed25519, accounts_link_verify_req_json);
            if jws.is_err() {
                eprintln!(
                    "test_unencoded_sammati_accounts_link_verify_req_ed25519 - unencoded-jws[1] {:#?}",
                    jws
                );
            }
            assert!(jws.is_ok());
            /*let jws = jws.unwrap();
            eprintln!(
                "test_unencoded_sammati_accounts_link_verify_req_ed25519 - unencoded-jws[2] {:#?}",
                String::from_utf8(jws.clone()).unwrap()
            );*/
        }
        //
        //
        let fi_req_json=br#"{"ver":"2.0.0","timestamp":"2023-11-13T19:01:05.505Z","txnid":"fcd8ca5c-f791-4a4f-967e-fc8a5a34a93d","Consent":{"id":"cid_eLQuFAB1QRyWY_DHYxUX4Q","digitalSignature":"O3KPh-eTpW2w47QXYidOBe1Hk2y7djVAEcOnZyRRvxQ3cY18-9ZWiodF16jff-e7yNQgsYZpAy95Fx2Fft8LoYugkYh9_6qHiG_7LCtW8Ng4nCMgZM3Wwsj11ks1msrK5C1ksPrGlTkFhm9-FufNkPTAlW76_5Sb8G_lOsIj1lB8TrvKpOvPlhEIgsS4WBNdPfv3SBqTV2suw2LvkX3QTilqwuMgXMkrm9-RYL90fweX_yyoyaBWHOJNQaKNuQWPpoRRNHGOx3v4_QiwgrELdfeTVtKn6R_AsfaBoEthQ3wrc8tY1q0Wx5j0x18NdU2R2C26dHyZ9M11dEH99psA1A"},"FIDataRange":{"from":"2023-04-01T00:00:00.000Z","to":"2024-03-31T23:59:59.000Z"},"KeyMaterial":{"cryptoAlg":"ECDH","curve":"X25519","params":"cipher=AES/GCM/NoPadding;KeyPairGenerator=ECDH","DHPublicKey":{"expiry":"2024-04-01T00:00:00.000Z","Parameters":"publicKeyEncoding=HEX;nonceEncoding=HEX;nonceLen=12","KeyValue":"e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"},"Nonce":"46474a88a0c66a38e70c0629"}}"#;
        {
            let kd = KeyDesc::from_alg_kid(SignatureAlgorithm::HS512, FIP_WAP_HS512_KID_01);
            let header_hs512 = JwsHeaderBuilder::new()
                .alg(SignatureAlgorithm::HS512)
                .unencoded()
                .kid(FIP_WAP_HS512_KID_01)
                .critical(vec!["b64".to_owned()])
                .build()
                .unwrap();
            let jws = jws.sign(&kd, &header_hs512, fi_req_json);
            if jws.is_err() {
                eprintln!(
                    "test_unencoded_sammati_fi_req_hs512 - unencoded-jws[1] {:#?}",
                    jws
                );
            }
            assert!(jws.is_ok());
            let jws = jws.unwrap();
            eprintln!(
                "test_unencoded_sammati_fi_req_hs512 - unencoded-jws[2] {:#?}",
                String::from_utf8(jws.clone()).unwrap()
            );
        }
        {
            let kd = KeyDesc::from_alg_kid(
                SignatureAlgorithm::EdDSA,
                &String::from_utf8(KID_ED25519_PRIVATE_KEY_02.to_vec()).unwrap(),
            );
            let header_ed25519 = JwsHeaderBuilder::new()
                .alg(SignatureAlgorithm::EdDSA)
                .unencoded()
                .kid(KID_ED25519_PUBLIC_KEY_02)
                .critical(vec!["b64".to_owned()])
                .build()
                .unwrap();

            let jws = jws.sign(&kd, &header_ed25519, fi_req_json);
            if jws.is_err() {
                eprintln!(
                    "test_unencoded_sammati_fi_req_ed25519 - unencoded-jws[1] {:#?}",
                    jws
                );
            }
            assert!(jws.is_ok());
            let jws = jws.unwrap();
            eprintln!(
                "test_unencoded_sammati_fi_req_ed25519 - unencoded-jws[2] {:#?}",
                String::from_utf8(jws.clone()).unwrap()
            );
        }
        {
            let signing_kd =
                KeyDesc::from_alg_kid(SignatureAlgorithm::ES256, KID_SAMMATI_AA_ES256_PRIVATE_KEY);
            let header_es256_pub = JwsHeaderBuilder::new()
                .alg(SignatureAlgorithm::ES256)
                .unencoded()
                .kid(KID_SAMMATI_AA_ES256_PUBLIC_KEY)
                .critical(vec!["b64".to_owned()])
                .build()
                .unwrap();

            let jws = jws.sign(&signing_kd, &header_es256_pub, fi_req_json);
            if jws.is_err() {
                eprintln!(
                    "test_unencoded_sammati_fi_req_es256 - unencoded-jws[1] {:#?}",
                    jws
                );
            }
            assert!(jws.is_ok());
            let jws = jws.unwrap();
            eprintln!(
                "test_unencoded_sammati_fi_req_es256 - unencoded-jws[2] {:#?}",
                String::from_utf8(jws.clone()).unwrap()
            );
        }
        //
        //
        let fi_fetch_req_json=br#"{"ver":"2.0.0","timestamp":"2023-11-23T19:23:05.505Z","txnid":"fcd8ca5c-f791-4a4f-967e-fc8a5a34a93d","sessionId":"zfjGs2BVS9GQq4imZzpuig","fipId":"fip_a32ef1af-18c0-471d-b494-6e918fa8ba00_AlphaDigiFinBank","linkRefNumber":["SqrVhuCsQlmoiiIn5Pgpiw","R_0tJRgqQDGGVT4kXFli_A"]}"#;
        {
            let kd = KeyDesc::from_alg_kid(SignatureAlgorithm::HS512, FIP_WAP_HS512_KID_01);
            let header_hs512 = JwsHeaderBuilder::new()
                .alg(SignatureAlgorithm::HS512)
                .unencoded()
                .kid(FIP_WAP_HS512_KID_01)
                .critical(vec!["b64".to_owned()])
                .build()
                .unwrap();
            let jws = jws.sign(&kd, &header_hs512, fi_fetch_req_json);
            if jws.is_err() {
                eprintln!(
                    "test_unencoded_sammati_fi_fetch_req_hs512 - unencoded-jws[1] {:#?}",
                    jws
                );
            }
            assert!(jws.is_ok());
            let jws = jws.unwrap();
            eprintln!(
                "test_unencoded_sammati_fi_fetch_req_hs512 - unencoded-jws[2] {:#?}",
                String::from_utf8(jws.clone()).unwrap()
            );
        }
        {
            let kd = KeyDesc::from_alg_kid(
                SignatureAlgorithm::EdDSA,
                &String::from_utf8(KID_ED25519_PRIVATE_KEY_02.to_vec()).unwrap(),
            );
            let header_ed25519 = JwsHeaderBuilder::new()
                .alg(SignatureAlgorithm::EdDSA)
                .unencoded()
                .kid(KID_ED25519_PUBLIC_KEY_02)
                .critical(vec!["b64".to_owned()])
                .build()
                .unwrap();

            let jws = jws.sign(&kd, &header_ed25519, fi_fetch_req_json);
            if jws.is_err() {
                eprintln!(
                    "test_unencoded_sammati_fi_fetch_req_ed25519 - unencoded-jws[1] {:#?}",
                    jws
                );
            }
            assert!(jws.is_ok());
            let jws = jws.unwrap();
            eprintln!(
                "test_unencoded_sammati_fi_fetch_req_ed25519 - unencoded-jws[2] {:#?}",
                String::from_utf8(jws.clone()).unwrap()
            );
        }
    }
}
