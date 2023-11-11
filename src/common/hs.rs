use crate::mutter::Mutter;
use crate::{cfg::Config, types::ValidationError};
use async_trait::async_trait;
use data_encoding::BASE64;
use hyper::{
    body::HttpBody,
    header,
    server::conn::AddrStream,
    service::{make_service_fn, service_fn},
    Body, HeaderMap, Method, Request, Response, Server,
};
use log::{error, info, warn};
use std::{
    convert::Infallible,
    fmt,
    net::{SocketAddr, ToSocketAddrs},
    pin::Pin,
    str::{self, SplitAsciiWhitespace},
    sync::OnceLock,
};

use crate::ts::UtcTs;
use crate::types::{
    Empty, ErrResp, ErrorCode, HealthOkResp, InterfaceResponse, ServiceHealthStatus,
};

pub type InfallibleResult = Result<Response<Body>, Infallible>;

pub static HTTP_PROC: OnceLock<Pin<Box<dyn HttpMethod>>> = OnceLock::new();

pub fn flag_http_method_forbidden(em: &str) -> InfallibleResult {
    flag(Box::new(ErrResp::<Empty>::v2(
        None,
        &UtcTs::now(),
        &ErrorCode::Unauthorized,
        em,
        hyper::StatusCode::FORBIDDEN.as_u16(),
        None,
    )))
}

#[async_trait]
pub trait HttpMethod: Sync + Send {
    fn delete(&self, _: Request<Body>) -> InfallibleResult {
        flag_http_method_forbidden("HTTP method DELETE not supported")
    }
    fn get(&self, _: Request<Body>) -> InfallibleResult {
        flag_http_method_forbidden("HTTP method GET not supported")
    }
    fn head(&self, _: Request<Body>) -> InfallibleResult {
        flag_http_method_forbidden("HTTP method HEAD not supported")
    }
    fn options(&self, _: Request<Body>) -> InfallibleResult {
        flag_http_method_forbidden("HTTP method OPTIONS not supported")
    }
    fn patch(&self, _: Request<Body>) -> InfallibleResult {
        flag_http_method_forbidden("HTTP method PATCH not supported")
    }
    fn post(&self, _: Request<Body>) -> InfallibleResult {
        flag_http_method_forbidden("HTTP method POST not supported")
    }
    fn put(&self, _: Request<Body>) -> InfallibleResult {
        flag_http_method_forbidden("HTTP method PUT not supported")
    }
}

#[derive(Debug, Clone)]
pub struct HttpEndpoint {
    mutter: Mutter,
    host_port: String,
    sock: Option<SocketAddr>,
    // cfg: Config,
}
#[allow(dead_code)]
impl HttpEndpoint {
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
    async fn run(self: &HttpEndpoint) {
        let new_service = make_service_fn(|_conn: &AddrStream| async {
            Ok::<_, Infallible>(service_fn(|req| HttpEndpoint::http_req_proc(req)))
        });
        info!("HttpServer trying to bind {}...", self.sock.unwrap());
        let server =
            Server::try_bind(&self.sock.unwrap()).map(|builder| builder.serve(new_service));
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
                info!("Stopped HttpServer Endpoint <{}>", hs.sock.unwrap())
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
    async fn http_req_proc(req: Request<Body>) -> InfallibleResult {
        if let Some(hp) = HTTP_PROC.get() {
            match req.method() {
                &Method::GET => hp.get(req),
                &Method::POST => hp.post(req),
                &Method::DELETE => hp.delete(req),
                &Method::OPTIONS => hp.options(req),
                &Method::PUT => hp.put(req),
                &Method::PATCH => hp.patch(req),
                &Method::HEAD => hp.head(req),
                _ => Ok(Response::builder().body(Body::empty()).unwrap()),
            }
        } else {
            error!(
                "Uninitialized http endpoint {:#?}",
                req.headers().get("HOST").unwrap()
            );
            Ok(Response::builder().body(Body::empty()).unwrap())
        }
    }
}

#[derive(Debug, Default)]
pub enum ContentType {
    Unspecified,
    FormUrlencoded,
    TextPlain,
    #[default]
    Json,
    Unsupported,
}

#[derive(Debug, Clone)]
pub struct Headers {
    pub(self) headers: HeaderMap,
}

impl fmt::Display for Headers {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (name, val) in &self.headers {
            if !val.is_empty() {
                if let Ok(s) = str::from_utf8(val.as_bytes()) {
                    write!(f, "({} : {})", name.as_str(), s).unwrap();
                }
            }
        }
        Ok(())
    }
}

impl Headers {
    pub fn from(hm: HeaderMap) -> Headers {
        Headers { headers: hm }
    }
    pub fn probe(&self, name: &str) -> Option<String> {
        for (key, val) in &self.headers {
            if name == key {
                return str::from_utf8(val.as_bytes()).map(|s| s.to_owned()).ok();
            }
        }
        None
    }
    pub fn content_type_param(&self) -> Option<String> {
        self.headers
            .get(header::CONTENT_TYPE)
            .and_then(|ct| str::from_utf8(ct.as_bytes()).ok())
            .and_then(|ct: &str| Some(ct.to_ascii_lowercase()))
    }
    pub fn content_type(&self) -> ContentType {
        let ct: Option<String> = self.content_type_param();
        match ct {
            Some(s) => {
                if s.eq_ignore_ascii_case("application/x-www-form-urlencoded") {
                    ContentType::FormUrlencoded
                } else if s.eq_ignore_ascii_case("application/json") {
                    ContentType::Json
                } else if s.eq_ignore_ascii_case("text/plain") {
                    ContentType::TextPlain
                } else {
                    ContentType::Unsupported
                }
            }
            None => ContentType::Unspecified,
        }
    }
    pub fn app_x_www_form_urlencoded(&self) -> Result<bool, Mutter> {
        let ct: Option<String> = self.content_type_param();
        match ct {
            Some(s) => {
                if s.eq_ignore_ascii_case("application/x-www-form-urlencoded") {
                    Ok(true)
                } else {
                    Err(Mutter::BadFormUrlEncoding)
                }
            }
            None => Err(Mutter::MissingContentTypeFormUrlEncoding),
        }
    }
    pub fn authorization_basic(&self) -> Result<Option<(String, String)>, Mutter> {
        let authz_type: Option<SplitAsciiWhitespace> = self
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|hv| str::from_utf8(hv.as_bytes()).ok())
            .and_then(|hvs: &str| Some(hvs.split_ascii_whitespace()));
        if let Some(mut it) = authz_type {
            let cred = match it
                .next()
                .filter(|s| s.eq_ignore_ascii_case("BASIC"))
                .is_some()
            {
                true => it.next(),
                false => return Err(Mutter::ClientAuthenticationMethodNotBasic),
            };
            if cred.is_none() {
                return Err(Mutter::MissingClientCredentials);
            }
            if it.count() != 0 {
                return Err(Mutter::TooManyAuthenticationParameters);
            }
            let res = BASE64.decode(cred.unwrap().as_bytes());
            if res.is_err() {
                return Err(Mutter::BadBase64Encoding);
            }
            let st = String::from_utf8(res.unwrap())?;
            let np: Vec<&str> = st.split(':').collect();
            if np.len() != 2 {
                return Err(Mutter::InvalidBasicAuthorizationHeaderValue);
            }
            let cid = np.get(0).unwrap();
            let secret = np.get(1).unwrap();
            warn!("authorization_basic: {:#?} {:#?}", cid, secret);
            Ok(Some((cid.to_string(), secret.to_string())))
        } else {
            Ok(None)
        }
    }
}

pub trait BodyTrait: Sync + Send {
    const POST_REQUEST_PAYLOAD_SIZE_MAX: u64 = (32 * 1024);
    fn size_ok(&self, max_size: u64) -> Result<u64, u64>;
    fn read(body: Body) -> Result<String, Mutter>;
}

impl BodyTrait for Body {
    fn size_ok(&self, size_max: u64) -> Result<u64, u64> {
        match self.size_hint().upper() {
            Some(v) => {
                if v <= size_max {
                    Ok(v)
                } else {
                    Err(v)
                }
            }
            None => Err(size_max + 1),
        }
    }

    fn read(body: Body) -> Result<String, Mutter> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                return read_body_string(body).await;
            })
        })
    }
}
async fn read_body_string(body: Body) -> Result<String, Mutter> {
    match hyper::body::to_bytes(body).await {
        Ok(bytes) => match String::from_utf8(bytes.to_vec()) {
            Ok(body_str) => Ok(body_str),
            _ => Err(Mutter::HttpBodyStrUtf8Bad),
        },
        _ => Err(Mutter::HttpBodyReadingError),
    }
}

#[derive(Clone, Debug)]
pub enum RespCode {
    Ok = 200,
    BadRequest = 400,
    UnauthorizedAccess = 401,
    Forbidden = 403,
    NotFound = 404,
    MethodNotAllowed = 405,
    RequestTimeout = 408,
    Conflict = 409,
    Gone = 410,
    PreconditionFailed = 412,
    ContentTooLarge = 413,
    URITooLong = 414,
    UnsupportedMediaType = 415,
    InternalServerError = 500,
    NotImplemented = 501,
    ServiceUnavailable = 503,
}

/*
pub fn answer<T>(t: T) -> InfallibleResult
where
    T: serde::Serialize + types::Interface,
{
    let rb = Response::builder()
        .header("Content-Type", "application/json")
        .header("Cache-Control", "no-store no-cache");
    // if let Ok(s) = serde_json::to_string::<T>(&t) {
    if let Ok(s) = t.json() {
        Ok(rb
            .status(hyper::StatusCode::OK)
            .body(Body::from(s))
            .expect("ok"))
    } else {
        Ok(rb
            .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::from("unexpected json serialization error"))
            .expect("internal server error"))
    }
}
*/

pub fn answer(t: Box<dyn InterfaceResponse>) -> InfallibleResult {
    let rb = Response::builder()
        .header("Content-Type", "application/json")
        .header("Cache-Control", "no-store no-cache");
    Ok(rb
        .status(hyper::StatusCode::OK)
        .body(Body::from(t.json()))
        .expect("non-empty "))
}

pub fn flag(t: Box<dyn InterfaceResponse>) -> InfallibleResult {
    let rb = Response::builder()
        .header("Content-Type", "application/json")
        .header("Cache-Control", "no-store no-cache");
    Ok(rb
        .status(t.code() as u16)
        .body(Body::from(t.json()))
        .expect("non-empty error response"))
}

pub fn answer_health_ok() -> InfallibleResult {
    answer(Box::new(HealthOkResp::<Empty>::v2(
        &UtcTs::now(),
        ServiceHealthStatus::UP,
        None,
    )))
}

pub fn internal_error(p: &str) -> ValidationError {
    ValidationError(
        ErrorCode::InternalError,
        ("Unrecoverable internal error (".to_string() + p + ")").to_owned(),
    )
}

pub fn error_nonempty_body() -> Box<dyn InterfaceResponse> {
    Box::new(ErrResp::<Empty>::v2(
        None,
        &UtcTs::now(),
        &ErrorCode::NonEmptyBodyForGetRequest,
        &("GET request body should be empty"),
        hyper::StatusCode::FORBIDDEN.as_u16(),
        None,
    ))
}

pub fn error_unsupported_request(p: &str) -> Box<dyn InterfaceResponse> {
    Box::new(ErrResp::<Empty>::v2(
        None,
        &UtcTs::now(),
        &ErrorCode::InvalidRequest,
        &("Invalid request (".to_string() + p + ")"),
        hyper::StatusCode::NOT_FOUND.as_u16(),
        None,
    ))
}

pub fn error_unimplemented_request(p: &str) -> Box<dyn InterfaceResponse> {
    Box::new(ErrResp::<Empty>::v2(
        None,
        &UtcTs::now(),
        &ErrorCode::NotImplemented,
        &("Not implemented (".to_string() + p + ")"),
        hyper::StatusCode::NOT_IMPLEMENTED.as_u16(),
        None,
    ))
}

pub fn flag_error(hsc: hyper::StatusCode, ec: ErrorCode, em: &str) -> InfallibleResult {
    flag(Box::new(ErrResp::<Empty>::v2(
        None,
        &UtcTs::now(),
        &ec,
        em,
        hsc.as_u16(),
        None,
    )))
}

pub fn flag_error_ext(hsc: u16, ec: ErrorCode, em: &str) -> InfallibleResult {
    flag(Box::new(ErrResp::<Empty>::v2(
        None,
        &UtcTs::now(),
        &ec,
        em,
        hsc,
        None,
    )))
}
