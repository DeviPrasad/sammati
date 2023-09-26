#![allow(dead_code)]

use common::{
    cfg::Config,
    err, fip,
    hs::{self, BodyTrait, Headers, HttpEndpoint, HttpMethod, InfallibleResult, HTTP_PROC},
    mutter::{self, Mutter},
    ts::Timestamp,
    types::ServiceHealthStatus,
    CommandlineArgs,
};
use hyper::{Body, Request, StatusCode};
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
                    "/Heartbeat" => {
                        info!("FIP GET /Heartbeat");
                        hs::answer(fip::HealthOkResp::<FipNode>::v2(
                            &Timestamp::now(),
                            ServiceHealthStatus::UP,
                            Some(FipNode::default()),
                        ))
                    }
                    _ => {
                        error!("FIP GET request unsupported ({})", uri.path());
                        Ok(err::response(
                            StatusCode::BAD_REQUEST,
                            Mutter::UnknownPostRequest,
                            Some(&format!("FIP unsupported request ({})", uri.path())),
                        ))
                    }
                }
            }
            _ => Ok(err::response(
                StatusCode::BAD_REQUEST,
                Mutter::BadHttpBodyForGetRequest,
                Some(format!("Non-empty HTTP GET request body").as_str()),
            )),
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
                        Ok(err::response(
                            StatusCode::OK,
                            Mutter::None,
                            Some(format!("accounts discovery").as_str()),
                        ))
                    }
                    "/Accounts/link" => {
                        info!("FIP POST /Accounts/link");
                        Ok(err::response(
                            StatusCode::OK,
                            Mutter::None,
                            Some(format!("accounts linking").as_str()),
                        ))
                    }
                    "/Accounts/delink" => {
                        info!("FIP POST /Accounts/delink");
                        Ok(err::response(
                            StatusCode::OK,
                            Mutter::None,
                            Some(format!("accounts delink").as_str()),
                        ))
                    }
                    "/Accounts/link/verify" => {
                        info!("FIP POST /Accounts/link/verify");
                        Ok(err::response(
                            StatusCode::OK,
                            Mutter::None,
                            Some(format!("accounts link verify").as_str()),
                        ))
                    }
                    "/FI/request" => {
                        info!("FIP POST /FI/request");
                        Ok(err::response(
                            StatusCode::OK,
                            Mutter::None,
                            Some(format!("FI request").as_str()),
                        ))
                    }
                    "/FI/fetch" => {
                        info!("FIP POST /FI/fetch");
                        Ok(err::response(
                            StatusCode::OK,
                            Mutter::None,
                            Some(format!("FI fetch").as_str()),
                        ))
                    }
                    "/Consent/Notification" => {
                        info!("FIP POST /Consent/Notification");
                        Ok(err::response(
                            StatusCode::OK,
                            Mutter::None,
                            Some(format!("Consent Notification").as_str()),
                        ))
                    }
                    "/Consent" => {
                        info!("FIP POST /Consent");
                        Ok(err::response(
                            StatusCode::OK,
                            Mutter::None,
                            Some(format!("Consent").as_str()),
                        ))
                    }
                    _ => {
                        error!("FIP unsupported request {}", uri.path());
                        Ok(err::response(
                            StatusCode::BAD_REQUEST,
                            Mutter::UnknownPostRequest,
                            Some(&format!("({})", uri.path())),
                        ))
                    }
                }
            }
            _ => Ok(err::response(
                StatusCode::PAYLOAD_TOO_LARGE,
                Mutter::PostRequestPayloadTooLarge,
                Some(format!("Permitted {} bytes", Body::POST_REQUEST_PAYLOAD_SIZE_MAX).as_str()),
            )),
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
