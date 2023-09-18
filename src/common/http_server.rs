use std::convert::Infallible;
use std::net::{SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use crate::cfg::Config;
use crate::mutter::Mutter;
use hyper::{Body, Method, Request, Response, Server};
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use log::{error, info, warn};
use std::sync::{OnceLock};
use async_trait::async_trait;

pub static HTTP_PROC: OnceLock<Pin<Box<dyn HttpPost>>> = OnceLock::new();

#[async_trait]
pub trait HttpPost : Sync + Send {
     fn delete(&self, req: Request<Body>) -> Result<Response<Body>, Infallible> {
         info!("HttpMethod::HttpPost::delete (default impl) {:#?}", req);
         Ok(Response::builder().body(Body::empty()).unwrap())
     }
    fn get(&self, req: Request<Body>) -> Result<Response<Body>, Infallible> {
        info!("HttpMethod::HttpPost::get (default impl) {:#?}", req);
        Ok(Response::builder().body(Body::empty()).unwrap())
    }
    fn head(&self, req: Request<Body>) -> Result<Response<Body>, Infallible> {
        info!("HttpMethod::HttpPost::head (default impl) {:#?}", req);
        Ok(Response::builder().body(Body::empty()).unwrap())
    }
    fn options(&self, req: Request<Body>) -> Result<Response<Body>, Infallible> {
        info!("HttpMethod::HttpPost::options (default impl) {:#?}", req);
        Ok(Response::builder().body(Body::empty()).unwrap())
    }
    fn patch(&self, req: Request<Body>) -> Result<Response<Body>, Infallible> {
        info!("HttpMethod::HttpPost::patch (default impl) {:#?}", req);
        Ok(Response::builder().body(Body::empty()).unwrap())
    }
    fn post(&self, req: Request<Body>) -> Result<Response<Body>, Infallible> {
        info!("HttpMethod::HttpPost::post (default impl) {:#?}", req);
        Ok(Response::builder().body(Body::empty()).unwrap())
    }
     fn put(&self, req: Request<Body>) -> Result<Response<Body>, Infallible> {
         info!("HttpMethod::HttpPost::put (default impl) {:#?}", req);
         Ok(Response::builder().body(Body::empty()).unwrap())
     }
}

#[derive(Debug, Clone)]
pub struct HttpEndpoint
{
    mutter: Mutter,
    host_port: String,
    sock: Option<SocketAddr>,
    // cfg: Config,
}
#[allow(dead_code)]
impl HttpEndpoint
{
    fn new(
        err: Mutter,
        host_port: &str,
        sock: Option<SocketAddr>,
        // config: &Config,

    ) -> HttpEndpoint {
        HttpEndpoint {
            mutter: err,
            host_port: host_port.to_string(),
            sock,
            // cfg: config.clone(),
        }
    }
    fn init(cfg: &Config) -> HttpEndpoint {
        let host_addr = cfg.host.address.as_str();
        let sock_addresses = host_addr.to_socket_addrs();
        let mut err = Mutter::BadAddrString;
        let mut sock = None;
        if sock_addresses.is_ok() {
            let mut addr_iter = sock_addresses.unwrap();
            err = Mutter::BadSocket;
            sock = addr_iter.next();
            if sock.is_some() {
                err = Mutter::None;
            }
        }
        HttpEndpoint::new(err, host_addr, sock)
    }
    async fn run(self: &HttpEndpoint)
    {
        let new_service = make_service_fn(|_conn: &AddrStream| async {
            Ok::<_, Infallible>(service_fn(|req| HttpEndpoint::http_req_proc(req)))
        });
        info!("HttpServer trying to bind {}...", self.sock.unwrap());
        let server =
            Server::try_bind(&self.sock.unwrap())
                .map(|builder| builder.serve(new_service));
        if server.is_err() {
            error!("HttpServer Server failed to bind to the interface.")
        } else {
            warn!("HttpServer Endpoint is active.");
            let _ = server.unwrap().await;
        }
    }
    pub async fn start(cfg: &Config) -> Result<(), Mutter> {
        info!("HttpServer::start()");
        let hs: HttpEndpoint = HttpEndpoint::init(cfg);
        match hs.mutter {
            Mutter::None => {
                info!(
                    "Initializing the HttpServer Endpoint <{}>",
                    hs.sock.unwrap()
                );
                hs.run().await;
                info!(
                    "Stopped HttpServer Endpoint <{}>",
                    hs.sock.unwrap()
                )
            }
            _ => {
                error!(
                    "HttpServer Endpoint Failed to Start <{}>:<{:#?}>",
                    hs.host_port, hs.mutter
                );
            }
        }
        error!("Quitting...");
        Err(Mutter::Quit)
    }
    async fn http_req_proc(req: Request<Body>) -> Result<Response<Body>, Infallible> {
        if let Some(hp) = HTTP_PROC.get() {
            match req.method() {
                &Method::GET => hp.get(req),
                &Method::POST => hp.post(req),
                &Method::DELETE => hp.delete(req),
                &Method::OPTIONS => hp.options(req),
                &Method::PUT => hp.put(req),
                &Method::PATCH => hp.patch(req),
                &Method::HEAD => hp.head(req),
                _ => Ok(Response::builder().body(Body::empty()).unwrap())
            }

        } else {
            error!("Uninitialized http endpoint {:#?}", req.headers().get("HOST").unwrap());
            Ok(Response::builder().body(Body::empty()).unwrap())
        }
    }
}

