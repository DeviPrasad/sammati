use std::convert::Infallible;
use hyper::{Body, Request, Response, StatusCode};
use log::{error, info};
use common::{err, logger};
use common::CommandlineArgs;
use common::mutter::Mutter;
use common::cfg::Config;
use common::http_server::{HttpEndpoint, HttpPost};
use common::http_server::HTTP_PROC;
use common::hprb::{BodyTrait, Headers};

#[derive(Debug)]
pub struct HttpReqProc {
}

impl HttpPost for HttpReqProc {
    fn get(&self, req: Request<Body>) -> Result<Response<Body>, Infallible> {
        info!("FIP App Proxy - HttpMethod::HttpPost::proc {:#?}", req);
        let (head, body) = req.into_parts();
        match body.payload(0) {
            Ok(_) => {
                let (uri, _headers) = (
                    head.uri.clone(),
                    Headers::from(head.headers),
                );
                match uri.path() {
                    "/Heartbeat" => {
                        info!("FIP GET /Heartbeat");
                        Ok(err::response(
                            StatusCode::OK,
                            Mutter::None,
                            Some(format!("FIP heartbeat").as_str())))
                    },
                    _ => {
                        error!("FIP GET request unsupported ({})", uri.path());
                        Ok(err::response(
                            StatusCode::BAD_REQUEST,
                            Mutter::UnknownPostRequest,
                            Some(&format!("FIP unsupported request ({})", uri.path()))))
                    }
                }
            },
            _ => Ok(err::response(
                    StatusCode::BAD_REQUEST,
                    Mutter::BadHttpBodyForGetRequest,
                    Some(format!("Non-empty HTTP GET request body").as_str()))),
        }
    }
    fn post(&self, req: Request<Body>) -> Result<Response<Body>, Infallible> {
        info!("FIP App Proxy - HttpMethod::HttpPost::proc {:#?}", req);
        let (head, body) = req.into_parts();
        match body.payload(Body::POST_REQUEST_PAYLOAD_SIZE_MAX) {
            Ok(_) => {
                let (uri, _headers) = (
                    head.uri.clone(),
                    Headers::from(head.headers),
                );
                match uri.path() {
                    "/Accounts/discover" => {
                        info!("FIP POST /Accounts/discover");
                        Ok(err::response(
                            StatusCode::OK,
                            Mutter::None,
                            Some(format!("accounts discovery").as_str())))
                    },
                    "/Accounts/link" => {
                        info!("FIP POST /Accounts/link");
                        Ok(err::response(
                            StatusCode::OK,
                            Mutter::None,
                            Some(format!("accounts linking").as_str())))
                    },
                    "/Accounts/delink" => {
                        info!("FIP POST /Accounts/delink");
                        Ok(err::response(
                            StatusCode::OK,
                            Mutter::None,
                            Some(format!("accounts delink").as_str())))
                    },
                    "/Accounts/link/verify" => {
                        info!("FIP POST /Accounts/link/verify");
                        Ok(err::response(
                            StatusCode::OK,
                            Mutter::None,
                            Some(format!("accounts link verify").as_str())))
                    },
                    "/FI/request" => {
                        info!("FIP POST /FI/request");
                        Ok(err::response(
                            StatusCode::OK,
                            Mutter::None,
                            Some(format!("FI request").as_str())))
                    },
                    "/FI/fetch" => {
                        info!("FIP POST /FI/fetch");
                        Ok(err::response(
                            StatusCode::OK,
                            Mutter::None,
                            Some(format!("FI fetch").as_str())))
                    },
                    "/Consent/Notification" => {
                        info!("FIP POST /Consent/Notification");
                        Ok(err::response(
                            StatusCode::OK,
                            Mutter::None,
                            Some(format!("Consent Notification").as_str())))
                    },
                    "/Consent" => {
                        info!("FIP POST /Consent");
                        Ok(err::response(
                            StatusCode::OK,
                            Mutter::None,
                            Some(format!("Consent").as_str())))
                    },
                    _ => {
                        error!("FIP unsupported request {}", uri.path());
                        Ok(err::response(
                            StatusCode::BAD_REQUEST,
                            Mutter::UnknownPostRequest,
                            Some(&format!("({})", uri.path()))))
                    }
                }
            }
            _ => Ok(err::response(
                StatusCode::PAYLOAD_TOO_LARGE,
                Mutter::PostRequestPayloadTooLarge,
                Some(format!("Permitted {} bytes", Body::POST_REQUEST_PAYLOAD_SIZE_MAX).as_str()))),
        }
    }
}

// RUST_LOG=debug cargo run --bin fipwap -- --config mock/config/fip-wap-cfg.json
#[tokio::main]
async fn main() {
    logger::init();
    info!("FIP App Proxy");

    let s = HttpReqProc{};
    let _ = HTTP_PROC.set(Box::pin(s));

    let cmd: Result<Config, Mutter> = CommandlineArgs::config();
    info!("Commandline arg: {:#?}", cmd);
    match cmd {
        Ok(cfg) => {
            info!("Try FIP App Proxy init...");
            let _ = HttpEndpoint::start(&cfg).await;
        }
        _ => {
            error!("Error - FIP App Proxy initialization failed. Quitting.");
            std::process::exit(2);
        }
    }
}
