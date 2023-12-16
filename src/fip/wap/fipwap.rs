#![allow(dead_code)]

use std::{pin::Pin, sync::OnceLock};

use hyper::{body::Incoming as IncomingBody, Request};

use common::{
    cfg::Config,
    fip,
    hs::{
        self, BodyTrait, Headers, HttpCmdDispatcher, HttpEndpoint, HttpMethod, InfallibleResult,
        HTTP_PROC,
    },
    mutter::{self, Mutter},
    ts::UtcTs,
    types::{
        Empty, ErrResp, FIPAccLinkReqRefNum, FIPAccLinkStatus, FIPAccLinkingAuthType,
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

impl HttpMethod for HttpReqProc {
    fn get(&self, req: Request<IncomingBody>) -> InfallibleResult {
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

    fn post(&self, req: Request<IncomingBody>) -> InfallibleResult {
        log::info!("FIP App Proxy - HttpMethod::HttpPost");
        let (head, body) = req.into_parts();
        let (uri, hp) = (head.uri.clone(), Headers::from(head.headers));
        // 'content-type' must be 'application/json'
        match hs::HttpReq::check_content_type_application_json(&hp) {
            Ok(_) => match hs::HttpReq::unpack_body(body) {
                Ok(body_json) => {
                    match FipHttpCmdDispatcher::new().dispatch(&uri, &hp, &body_json.to_string()) {
                        Ok(good) => hs::answer(good),
                        Err(bad) => hs::flag(bad),
                    }
                }
                Err(ValidationError(ec, em)) => {
                    hs::flag_error_ext(ec.to_http_status_code(), ec, &em)
                }
            },
            Err(ValidationError(ec, em)) => hs::flag_error_ext(ec.to_http_status_code(), ec, &em),
        }
    }
}

#[derive(Debug, Default)]
struct FipHttpCmdDispatcher {}
impl FipHttpCmdDispatcher {
    pub fn new() -> Self {
        Default::default()
    }
}

impl HttpCmdDispatcher for FipHttpCmdDispatcher {
    fn dispatch(
        &self,
        uri: &hyper::Uri,
        hp: &Headers,
        json: &String,
    ) -> Result<Box<dyn InterfaceResponse>, Box<dyn InterfaceResponse>> {
        match hs::HttpReq::authenticate_request(&hp, &json, JWS.get()) {
            Ok(_) => FipCmd::execute(&uri, &hp, &json),
            Err(ValidationError(ec, em)) => {
                // invalid API key, invalid x-jws-signature, invalid dpop
                Err(Box::new(ErrResp::<Empty>::v2(
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
}

#[derive(Debug, Default)]
struct UnauthenticatedHttpPostReqDispatcher {}
impl UnauthenticatedHttpPostReqDispatcher {
    pub fn new() -> Self {
        Default::default()
    }
}

impl HttpCmdDispatcher for UnauthenticatedHttpPostReqDispatcher {
    fn dispatch(
        &self,
        uri: &hyper::Uri,
        hp: &Headers,
        json: &String,
    ) -> Result<Box<dyn InterfaceResponse>, Box<dyn InterfaceResponse>> {
        FipCmd::execute(&uri, &hp, &json)
    }
}

struct FipCmd();
impl FipCmd {
    fn execute(
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
                let adr: fip::AccDiscoveryReq =
                    Type::from_json::<fip::AccDiscoveryReq>(&json, &hp)?;
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
                log::info!("FIP POST /FI/fetch {fi_fetch_req:#?}");
                let resp = fip::FIFetchResp::mock_response(&fi_fetch_req);
                Ok(Box::new(resp))
            }
            "/Consent/Notification" => {
                log::info!("FIP POST /Consent/Notification");
                Err(hs::error_unimplemented_request("/Consent/Notification"))
            }
            "/Consent" => {
                // once the AA obtains a consent artefact, AA shares it with FIP here.
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
                log::warn!("Warning: running non-production instance...");
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
