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
    ts::MsgUTCTs,
    types::{ErrResp, ErrorCode, ServiceHealthStatus},
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Kube {
    pid: String,
    tid: String,
    url: String,
    cid: u32,
}

pub fn read_body_sync(body: Body) -> Result<String, Mutter> {
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(async {
            return hs::read_body_string(body).await;
        })
    })
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
        log::info!("FIP App Proxy - HttpMethod::HttpPost::proc {:#?}", req);
        let (head, body) = req.into_parts();
        match body.payload(0) {
            Ok(_) => {
                let (uri, _headers) = (head.uri.clone(), Headers::from(head.headers));
                match uri.path() {
                    "/Heartbeat" => answer_health_ok(),
                    p => flag_unrecognized(p),
                }
            }
            // non-empty body in HTTP GET is considered an error.
            _ => flag_nonempty_body(),
        }
    }

    fn post(&self, req: Request<Body>) -> InfallibleResult {
        log::info!("FIP App Proxy - HttpMethod::HttpPost");
        let (head, body) = req.into_parts();
        let res_body = body.payload(Body::POST_REQUEST_PAYLOAD_SIZE_MAX);
        if res_body.is_err() {
            return flag_payload_too_large(
                ErrorCode::PayloadTooLarge,
                &format!(
                    "Max permitted size of the payload is {} bytes",
                    Body::POST_REQUEST_PAYLOAD_SIZE_MAX
                ),
            );
        }
        let rb = read_body_sync(body);
        if let Err(e) = rb {
            log::error!("Bad account discovery request: {:#?}", e);
            return flag_incomplete_content(
                ErrorCode::ErrorReadingRequestBody,
                "Error in reading body content",
            );
        }
        let body_json = rb.unwrap();
        log::info!(
            "FIP App Proxy - HttpMethod::HttpPost::proc {:#?} {:#?}",
            head,
            body_json.len()
        );
        let (uri, hp) = (head.uri.clone(), Headers::from(head.headers));
        match hp.probe("Content-Type") {
            Some(ct) => {
                if !ct.eq_ignore_ascii_case("application/json") {
                    return flag_error(
                        hyper::StatusCode::BAD_REQUEST,
                        ErrorCode::InvalidRequest,
                        "content-type value must be application/json",
                    );
                }
            }
            _ => {
                return flag_error(
                    hyper::StatusCode::BAD_REQUEST,
                    ErrorCode::InvalidRequest,
                    "missing content-type header parameter",
                )
            }
        }
        let _dpop = hp.probe("DPoP");
        let _sammati_api_key = hp.probe("x-sammati-api-key");
        let x_jws_sig = hp.probe("x-jws-signature");

        if let Some(ds) = x_jws_sig {
            //let djv = JWS.get().unwrap();
            match JWS.get() {
                Some(djv) => {
                    if let Err(e) =
                        djv.verify(&DetachedSig::from(&ds.as_bytes()), &body_json.as_bytes())
                    {
                        log::error!("Message signature verification failed");
                        return flag_error(
                            hyper::StatusCode::UNAUTHORIZED,
                            match e {
                                Grumble::Base64EncodingBad => ErrorCode::InvalidBase64Encoding,
                                Grumble::BadDetachedSignature => {
                                    ErrorCode::InvalidDetachedSignature
                                }
                                _ => ErrorCode::SignatureDoesNotMatch,
                            },
                            "Invalid detached signature",
                        );
                    }
                }
                _ => return flag_internal_error("JWS keystore access error"),
            }
        } else {
            log::error!("Signature missing - cannot authenticate request");
            return flag_error(
                hyper::StatusCode::FORBIDDEN,
                ErrorCode::Unauthorized,
                "Signature missing - cannot authenticate request",
            );
        }

        match uri.path() {
            "/Accounts/discover" => {
                log::info!("FIP POST /Accounts/discover");
                return match serde_json::from_str::<fip::AccDiscoveryReq>(&body_json) {
                    Ok(adr) => {
                        log::info!("{:#?}", adr);
                        hs::answer(Some(fip::AccDiscoveryResp::v2(&adr.tx_id, &Vec::new())))
                    }
                    _ => flag_invalid_content(
                        ErrorCode::InvalidRequest,
                        "Account Discovery request is not well-formed",
                    ),
                };
            }
            "/Accounts/link" => {
                log::info!("FIP POST /Accounts/link");
                flag_unimplemented("/Accounts/link")
            }
            "/Accounts/delink" => {
                log::info!("FIP POST /Accounts/delink");
                flag_unimplemented("/Accounts/delink")
            }
            "/Accounts/link/verify" => {
                log::info!("FIP POST /Accounts/link/verify");
                flag_unimplemented("/Accounts/link/verify")
            }
            "/FI/request" => {
                log::info!("FIP POST /FI/request");
                flag_unimplemented("/FI/request")
            }
            "/FI/fetch" => {
                log::info!("FIP POST /FI/fetch");
                flag_unimplemented("/FI/fetch")
            }
            "/Consent/Notification" => {
                log::info!("FIP POST /Consent/Notification");
                flag_unimplemented("/Consent/Notification")
            }
            "/Consent" => {
                log::info!("FIP POST /Consent");
                flag_unimplemented("/Consent")
            }
            _ => {
                log::error!("FIP unsupported request {}", uri.path());
                flag_unrecognized(uri.path())
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
                let _ = JWS.set(Box::pin(dull::jws::JWS::new(
                    _NICKEL_KEY_STORE_.get().unwrap(),
                )));
            }
            #[cfg(not(production))]
            {
                let mut nks = dull::nickel::NickelKeyStore::default();
                nickel_cache_init_well_known_sig_keys(&mut nks);
                _NICKEL_KEY_STORE_.set(nks).expect("nickel keystore");
                let _ = JWS.set(Box::pin(dull::jws::JWS::new(
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

fn answer_health_ok() -> InfallibleResult {
    hs::answer(fip::HealthOkResp::<Kube>::v2(
        &MsgUTCTs::now(),
        ServiceHealthStatus::UP,
        Some(Kube::default()),
    ))
}

fn flag_internal_error(p: &str) -> InfallibleResult {
    flag_error(
        hyper::StatusCode::INTERNAL_SERVER_ERROR,
        ErrorCode::InternalError,
        &("Unrecoverable internal error (".to_string() + p + ")"),
    )
}

fn flag_service_unavailable(p: &str) -> InfallibleResult {
    flag_error(
        hyper::StatusCode::SERVICE_UNAVAILABLE,
        ErrorCode::ServiceUnavailable,
        &("Requested service is unavailable (".to_string() + p + ")"),
    )
}

fn flag_nonempty_body() -> InfallibleResult {
    flag_error(
        hyper::StatusCode::FORBIDDEN,
        ErrorCode::NonEmptyBodyForGetRequest,
        "GET request body should be empty",
    )
}

fn flag_unrecognized(p: &str) -> InfallibleResult {
    flag_error(
        hyper::StatusCode::NOT_FOUND,
        ErrorCode::InvalidRequest,
        &("Invalid request (".to_string() + p + ")"),
    )
}

fn flag_unimplemented(p: &str) -> InfallibleResult {
    flag_error(
        hyper::StatusCode::NOT_IMPLEMENTED,
        ErrorCode::NotImplemented,
        &("Not implemented (".to_string() + p + ")"),
    )
}

fn flag_payload_too_large(ec: ErrorCode, em: &str) -> InfallibleResult {
    flag_error(hyper::StatusCode::PAYLOAD_TOO_LARGE, ec, em)
}

fn flag_incomplete_content(ec: ErrorCode, em: &str) -> InfallibleResult {
    flag_error(hyper::StatusCode::BAD_REQUEST, ec, em)
}

fn flag_error(sc: hyper::StatusCode, ec: ErrorCode, em: &str) -> InfallibleResult {
    hs::flag(
        sc,
        ErrResp::<Kube>::v2(None, &MsgUTCTs::now(), ec, em, Some(Kube::default())),
    )
}

fn flag_invalid_content(ec: ErrorCode, em: &str) -> InfallibleResult {
    flag_error(hyper::StatusCode::BAD_REQUEST, ec, em)
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

    //let mut nks = NickelKeyStore::default();
    {
        let ks: &mut dyn dull::webkey::KeyStore = nks;
        let res = ks.add_sig_hmac_key(
            dull::jwa::SignatureAlgorithm::HS512,
            FIP_WAP_HS512_KID_01,
            FIP_WAP_HS512_KEY.as_bytes(), // "x4w7vzRFbvbrZ1IArIKKDgHQ3p6XC7CF5AowbojVCbcQIgexHwefDrYyUw0T43hnWsBJBcj5jD11hPgBHCJXIQ".as_bytes(),
        );
        assert!(res);
        let res = ks.add_sig_hmac_key(
            dull::jwa::SignatureAlgorithm::HS256,
            FIP_WAP_HS256_KID_02,
            // key size is 45 bytes (suitable for HS256; not for HS384, which requires min length of 48 bytes)
            FIP_WAP_HS256_KEY.as_bytes(), //"U9DayvJzo8hXTvDpy_psbaRDjcGUukmUR6oFfj7CURPBrPOC3ZL-6cO363dg".as_bytes(),
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

    use serde::{Deserialize, Serialize};

    use common::fip::HealthOkResp;
    use common::ts::MsgUTCTs;
    use common::types::{Empty, ServiceHealthStatus};

    #[test]
    fn simple_ok_response() {
        let resp: HealthOkResp<Empty> =
            HealthOkResp::<Empty>::v2(&MsgUTCTs::now(), ServiceHealthStatus::DOWN, None);
        //eprintln!("simple_ok_response object: {:#?}", resp);
        let json = serde_json::to_string(&resp);
        //eprintln!("simple_ok_response json: {:#?}", json);
        assert!(matches!(json, Ok(_)));
    }

    #[test]
    fn simple_ok_response_round_trip() {
        let serialized_okr = serde_json::to_string(&HealthOkResp::<Empty>::v2(
            &MsgUTCTs::now(),
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
            &MsgUTCTs::now(),
            ServiceHealthStatus::DOWN,
            Some(FipNode::default()),
        );
        eprintln!("simple_ok_response object: {:#?}", resp);
        let json = serde_json::to_string(&resp);
        eprintln!("simple_ok_response json: {:#?}", json);
        assert!(matches!(json, Ok(_)))
    }
}
