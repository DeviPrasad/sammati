use std::convert::Infallible;
use hyper::{Body, Request, Response};
use log::{error, info};
use common::logger;
use common::CommandlineArgs;
use common::mutter::Mutter;
use common::cfg::Config;
use common::http_server::{HttpEndpoint, HttpPost};
use common::http_server::HTTP_PROC;

#[derive(Debug)]
pub struct HttpReqProc {
}

impl HttpPost for HttpReqProc {
    fn post(&self, req: Request<Body>) -> Result<Response<Body>, Infallible> {
        info!("FIP App Proxy - HttpMethod::HttpPost::proc {:#?}", req);
        Ok(Response::builder().body(Body::empty()).unwrap())
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
