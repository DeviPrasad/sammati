#![allow(dead_code)]

use std::sync::OnceLock;

use bytes::Bytes;
use hyper::{Body, Request};
use serde::{Deserialize, Serialize};

use common::{
    cfg::Config,
    detached, fip,
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
        let jws_sig = hp.probe("x-jws-signature");

        if jws_sig.is_none() {
            log::error!("Signature missing - cannot authenticate request");
            return flag_error(
                hyper::StatusCode::FORBIDDEN,
                ErrorCode::Unauthorized,
                "Signature missing - cannot authenticate request",
            );
        }
        let detached_sig: Bytes = jws_sig.unwrap().into();
        let res_ds = detached::DetachedSignature::verify(&detached_sig, &body_json);
        if let Some(err) = res_ds.err() {
            log::error!("Message signature verification failed");
            return flag_error(
                hyper::StatusCode::UNAUTHORIZED,
                match err {
                    Mutter::BadBase64Encoding => ErrorCode::InvalidBase64Encoding,
                    Mutter::InvalidDetachedSignature => ErrorCode::InvalidDetachedSignature,
                    Mutter::SignatureVerificationFailed => ErrorCode::SignatureDoesNotMatch,
                    _ => ErrorCode::SignatureDoesNotMatch,
                },
                "Invalid detached signature",
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
//
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
                .expect("host config");
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
