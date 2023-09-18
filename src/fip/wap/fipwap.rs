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
                    "/heartbeat" => {
                        info!("FIP POST /heartbeat");
                        Ok(err::response(
                            StatusCode::OK,
                            Mutter::None,
                            Some(format!("heartbeat message").as_str())))
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
        //Ok(Response::builder().body(Body::empty()).unwrap())
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
