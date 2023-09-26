#![allow(dead_code)]

use common::{
    cfg::Config,
    fip,
    hs::{self, BodyTrait, Headers, HttpEndpoint, HttpMethod, InfallibleResult, HTTP_PROC},
    mutter::{self, Mutter},
    ts::Timestamp,
    types::{ErrResp, ErrorCode, ServiceHealthStatus},
    CommandlineArgs,
};
use hyper::{Body, Request};
use log::{error, info};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
#[derive(Debug)]
pub struct HttpReqProc {}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FipNode {
    pid: String,
    tid: String,
    url: String,
    cid: u32,
}
impl Default for FipNode {
    fn default() -> Self {
        let (url, cid) = match EP_CFG.get() {
            Some(cfg) => (cfg.host.url.to_owned(), cfg.host.cid),
            _ => ("https://fip-wap.sammati.in/".to_string(), 0),
        };
        FipNode {
            pid: format!("pid_{:?}", std::process::id()),
            tid: format!("tid_{:?}", std::thread::current().id()),
            url: url,
            cid: cid,
        }
    }
}

impl HttpMethod for HttpReqProc {
    fn get(&self, req: Request<Body>) -> InfallibleResult {
        info!("FIP App Proxy - HttpMethod::HttpPost::proc {:#?}", req);
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
            _ => flag_invalid_body_get_request(),
        }
    }

    fn post(&self, req: Request<Body>) -> InfallibleResult {
        info!("FIP App Proxy - HttpMethod::HttpPost::proc {:#?}", req);
        let (head, body) = req.into_parts();
        match body.payload(Body::POST_REQUEST_PAYLOAD_SIZE_MAX) {
            Ok(_) => {
                let (uri, _headers) = (head.uri.clone(), Headers::from(head.headers));
                match uri.path() {
                    "/Accounts/discover" => {
                        info!("FIP POST /Accounts/discover");
                        flag_unimplemented("/Accounts/discover")
                    }
                    "/Accounts/link" => {
                        info!("FIP POST /Accounts/link");
                        flag_unimplemented("/Accounts/link")
                    }
                    "/Accounts/delink" => {
                        info!("FIP POST /Accounts/delink");
                        flag_unimplemented("/Accounts/delink")
                    }
                    "/Accounts/link/verify" => {
                        info!("FIP POST /Accounts/link/verify");
                        flag_unimplemented("/Accounts/link/verify")
                    }
                    "/FI/request" => {
                        info!("FIP POST /FI/request");
                        flag_unimplemented("/FI/request")
                    }
                    "/FI/fetch" => {
                        info!("FIP POST /FI/fetch");
                        flag_unimplemented("/FI/fetch")
                    }
                    "/Consent/Notification" => {
                        info!("FIP POST /Consent/Notification");
                        flag_unimplemented("/Consent/Notification")
                    }
                    "/Consent" => {
                        info!("FIP POST /Consent");
                        flag_unimplemented("/Consent")
                    }
                    _ => {
                        error!("FIP unsupported request {}", uri.path());
                        flag_unrecognized(uri.path())
                    }
                }
            }
            _ => flag_bad_request(
                ErrorCode::PayloadTooLarge,
                &format!(
                    "Max permitted size of the payload is {} bytes",
                    Body::POST_REQUEST_PAYLOAD_SIZE_MAX
                ),
            ),
        }
    }
}

// endpoint config for shared access
pub static EP_CFG: OnceLock<Box<Config>> = OnceLock::<Box<Config>>::new();

// run as
// RUST_LOG=debug cargo run --bin fipwap -- --config mock/config/fip-wap-cfg.json
//
#[tokio::main]
async fn main() {
    mutter::init_log();
    info!("FIP App Proxy");

    let s = HttpReqProc {};
    let _ = HTTP_PROC.set(Box::pin(s));

    let cmd: Result<Config, Mutter> = CommandlineArgs::config();
    info!("Commandline arg: {:#?}", cmd);
    match cmd {
        Ok(cfg) => {
            info!("Try FIP App Proxy init...");
            EP_CFG
                .set(Box::<Config>::new(cfg.clone()))
                .expect("host config");
            let _ = HttpEndpoint::start(&cfg).await;
        }
        _ => {
            error!("Error - FIP App Proxy initialization failed. Quitting.");
            std::process::exit(2);
        }
    }
}

fn answer_health_ok() -> InfallibleResult {
    hs::answer(fip::HealthOkResp::<FipNode>::v2(
        &Timestamp::now(),
        ServiceHealthStatus::UP,
        Some(FipNode::default()),
    ))
}

fn flag_invalid_body_get_request() -> InfallibleResult {
    hs::flag(ErrResp::<FipNode>::v2(
        None,
        &Timestamp::now(),
        ErrorCode::NonEmptyBodyForGetRequest,
        "GET request body should be empty",
        Some(FipNode::default()),
    ))
}

fn flag_unrecognized(p: &str) -> InfallibleResult {
    hs::flag(ErrResp::<FipNode>::v2(
        None,
        &Timestamp::now(),
        ErrorCode::InvalidRequest,
        &("Invalid request '".to_string() + p + "'"),
        Some(FipNode::default()),
    ))
}

fn flag_unimplemented(p: &str) -> InfallibleResult {
    hs::flag(ErrResp::<FipNode>::v2(
        None,
        &Timestamp::now(),
        ErrorCode::NotImplemented,
        &("Not implemented '".to_string() + p + "'"),
        Some(FipNode::default()),
    ))
}

fn flag_bad_request(ec: ErrorCode, em: &str) -> InfallibleResult {
    hs::flag(ErrResp::<FipNode>::v2(
        None,
        &Timestamp::now(),
        ec,
        em,
        Some(FipNode::default()),
    ))
}

// quick test
// curl -v -H"Accept: application/json" -X GET http://fip-wap.sammati.web3pleb.org:40601/Heartbeat
// curl -v -H"Accept: application/json" -X POST http://fip-wap.sammati.web3pleb.org:40601/FI/fetch
//
#[cfg(test)]
mod tests {
    use common::fip::HealthOkResp;
    use common::ts::Timestamp;
    use common::types::{Empty, ServiceHealthStatus};
    use serde::{Deserialize, Serialize};
    use std::fmt::Debug;
    #[test]
    fn simple_ok_response() {
        let resp: HealthOkResp<Empty> =
            HealthOkResp::<Empty>::v2(&Timestamp::now(), ServiceHealthStatus::DOWN, None);
        //eprintln!("simple_ok_response object: {:#?}", resp);
        let json = serde_json::to_string(&resp);
        //eprintln!("simple_ok_response json: {:#?}", json);
        assert!(matches!(json, Ok(_)));
    }
    #[test]
    fn simple_ok_response_round_trip() {
        let serialized_okr = serde_json::to_string(&HealthOkResp::<Empty>::v2(
            &Timestamp::now(),
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
            &Timestamp::now(),
            ServiceHealthStatus::DOWN,
            Some(FipNode::default()),
        );
        eprintln!("simple_ok_response object: {:#?}", resp);
        let json = serde_json::to_string(&resp);
        eprintln!("simple_ok_response json: {:#?}", json);
        assert!(matches!(json, Ok(_)))
    }
}
