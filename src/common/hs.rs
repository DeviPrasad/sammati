use crate::mutter::Mutter;
use crate::tokiort;
use crate::{cfg::Config, types::ValidationError};

use async_trait::async_trait;
use bytes::{Buf, Bytes};
use data_encoding::BASE64;
use dull::jws::DetachedSig;
use dull::jwt::Grumble;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::header;
use hyper::{body::Incoming as IncomingBody, HeaderMap, Method, Request, Response};

use hyper::service::service_fn;
use tokio::net::TcpListener;

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

pub type InfallibleResult = Result<Response<BoxBody<Bytes, Infallible>>, Infallible>;

pub static BAD_CONTENT_TYPE: &'static str = "content-type value must be application/json";
pub static MISSING_CONTENT_TYPE: &'static str = "missing content-type header parameter";
pub static JWS_KEYSTORE_ACCESS: &'static str = "JWS keystore access error";
pub static INVALID_DETACHED_SIG: &'static str = "Invalid detached signature";
pub static MISSING_DETACHED_SIG: &'static str = "Signature missing - cannot authenticate request";
pub static ERROR_READING_HTTP_BODY: &'static str = "Error in reading body content";

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, Infallible> {
    Full::new(chunk.into()).map_err(|e| e).boxed()
}

pub static HTTP_PROC: OnceLock<Pin<Box<dyn HttpMethod>>> = OnceLock::new();

pub fn flag_http_method_forbidden(em: &str) -> InfallibleResult {
    flag(Box::new(ErrResp::<Empty>::v2(
        &None,
        &UtcTs::now(),
        &ErrorCode::Unauthorized,
        em,
        hyper::StatusCode::FORBIDDEN.as_u16(),
        None,
    )))
}

#[async_trait]
pub trait HttpMethod: Sync + Send {
    fn delete(&self, _: Request<IncomingBody>) -> InfallibleResult {
        flag_http_method_forbidden("HTTP method DELETE not supported")
    }
    fn get(&self, _: Request<IncomingBody>) -> InfallibleResult {
        flag_http_method_forbidden("HTTP method GET not supported")
    }
    fn head(&self, _: Request<IncomingBody>) -> InfallibleResult {
        flag_http_method_forbidden("HTTP method HEAD not supported")
    }
    fn options(&self, _: Request<IncomingBody>) -> InfallibleResult {
        flag_http_method_forbidden("HTTP method OPTIONS not supported")
    }
    fn patch(&self, _: Request<IncomingBody>) -> InfallibleResult {
        flag_http_method_forbidden("HTTP method PATCH not supported")
    }
    fn post(&self, _: Request<IncomingBody>) -> InfallibleResult {
        flag_http_method_forbidden("HTTP method POST not supported")
    }
    fn put(&self, _: Request<IncomingBody>) -> InfallibleResult {
        flag_http_method_forbidden("HTTP method PUT not supported")
    }
}

#[async_trait]
pub trait HttpCmdDispatcher: Sync + Send {
    fn dispatch(
        &self,
        uri: &hyper::Uri,
        hp: &Headers,
        json: &String,
    ) -> Result<Box<dyn InterfaceResponse>, Box<dyn InterfaceResponse>>;
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

    async fn run(self: &HttpEndpoint) -> std::io::Result<()> {
        log::info!("HttpServer trying to bind {}...", self.sock.unwrap());
        let listener = TcpListener::bind(&self.sock.unwrap()).await?;
        log::warn!("HttpServer Endpoint is active.");
        loop {
            let (stream, _) = listener.accept().await?;
            let io = tokiort::TokioIo::new(stream);
            tokio::task::spawn(async move {
                let service = service_fn(move |req| HttpEndpoint::http_req_proc(req));
                let conn = hyper::server::conn::http1::Builder::new()
                    .max_buf_size(32 * 1024)
                    .preserve_header_case(true)
                    .serve_connection(io, service);
                match conn.await {
                    Ok(_) => log::info!("Completed serving one request"),
                    Err(e) => log::error!("Failed to serve HTTP connection: {:?}", e),
                }
            });
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
                let _ = hs.run().await;
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

    async fn http_req_proc(req: Request<IncomingBody>) -> InfallibleResult {
        if let Some(hp) = HTTP_PROC.get() {
            match req.method() {
                &Method::GET => hp.get(req),
                &Method::POST => hp.post(req),
                &Method::DELETE => hp.delete(req),
                &Method::OPTIONS => hp.options(req),
                &Method::PUT => hp.put(req),
                &Method::PATCH => hp.patch(req),
                &Method::HEAD => hp.head(req),
                _ => Ok(Response::builder().body(full("")).unwrap()),
            }
        } else {
            error!(
                "Uninitialized http endpoint {:#?}",
                req.headers().get("HOST").unwrap()
            );
            Ok(Response::builder().body(full("")).unwrap())
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

#[derive(Debug, Default)]
pub struct HttpReq {}

impl HttpReq {
    pub fn check_content_type_application_json(hp: &Headers) -> Result<(), ValidationError> {
        let ct = hp.probe("Content-Type");
        if ct.is_none()
            || ct.is_some_and(|ct| {
                let mut s = ct.split(";");
                let ct = s.next().unwrap();
                ct.eq_ignore_ascii_case("application/json")
            })
        {
            Ok(())
        } else {
            Err(ValidationError(
                ErrorCode::InvalidRequest,
                BAD_CONTENT_TYPE.to_owned(),
            ))
        }
    }

    pub fn unpack_body(b: IncomingBody) -> Result<String, ValidationError> {
        match b.size_ok(IncomingBody::POST_REQUEST_PAYLOAD_SIZE_MAX) {
            Ok(_) => IncomingBody::read(b).map_err(|_| {
                ValidationError(
                    ErrorCode::ErrorReadingRequestBody,
                    ERROR_READING_HTTP_BODY.to_owned(),
                )
            }),
            _ => Err(ValidationError(
                ErrorCode::PayloadTooLarge,
                format!(
                    "Max permitted size of the payload is {} bytes",
                    IncomingBody::POST_REQUEST_PAYLOAD_SIZE_MAX
                ),
            )),
        }
    }

    pub fn authenticate_request(
        hp: &Headers,
        body_json: &String,
        jdsv: Option<&Pin<Box<dyn dull::jws::JwsDetachedSigVerifier>>>,
    ) -> Result<(), ValidationError> {
        let _dpop = hp.probe("DPoP");
        let api_key = hp.probe("x-sammati-api-key");
        let x_jws_sig = hp.probe("x-jws-signature");

        // check if api_key looks ok
        if api_key.is_none() || api_key.as_ref().is_some_and(|s| s.len() < 16) {
            Err(ValidationError(
                ErrorCode::Unauthorized,
                "Bad API Key".to_owned(),
            ))
        } else if let Some(ds) = x_jws_sig {
            // validate the detached signature and the content payload.
            match jdsv {
                Some(djv) => djv
                    .verify(&DetachedSig::new(&ds.as_bytes()), &body_json.as_bytes())
                    .map(|_| log::info!("Message signature verified. Request authenticated."))
                    .map_err(|e| {
                        log::error!("Message signature verification failed");
                        ValidationError(
                            match e {
                                Grumble::Base64EncodingBad => ErrorCode::InvalidBase64Encoding,
                                Grumble::BadDetachedSignature => {
                                    ErrorCode::InvalidDetachedSignature
                                }
                                _ => ErrorCode::SignatureDoesNotMatch,
                            },
                            INVALID_DETACHED_SIG.to_owned(),
                        )
                    }),
                _ => Err(internal_error(JWS_KEYSTORE_ACCESS)),
            }
        } else {
            log::error!("Message signature missing - forbidden request");
            Err(ValidationError(
                ErrorCode::Unauthorized,
                MISSING_DETACHED_SIG.to_owned(),
            ))
        }
    }
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

pub trait BodyTrait {
    const POST_REQUEST_PAYLOAD_SIZE_MAX: u64 = (32 * 1024);
    fn size_ok(&self, max_size: u64) -> Result<u64, u64>;
    fn read(body: IncomingBody) -> Result<String, Mutter>;
}

impl BodyTrait for IncomingBody {
    const POST_REQUEST_PAYLOAD_SIZE_MAX: u64 = (32 * 1024);
    fn size_ok(&self, size_max: u64) -> Result<u64, u64> {
        if size_max <= Self::POST_REQUEST_PAYLOAD_SIZE_MAX {
            Ok(size_max)
        } else {
            Err(Self::POST_REQUEST_PAYLOAD_SIZE_MAX)
        }
    }

    fn read(body: IncomingBody) -> Result<String, Mutter> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                return read_body_string(body).await;
            })
        })
    }
}

async fn read_body_string(body: IncomingBody) -> Result<String, Mutter> {
    if let Ok(collected_bytes) = body.collect().await {
        if let Ok(content) = std::io::read_to_string(collected_bytes.aggregate().reader()) {
            log::warn!("read_body_string: {:#?}", content);
            return Ok(content);
        }
    }
    Err(Mutter::HttpBodyReadingError)
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

pub fn answer(t: Box<dyn InterfaceResponse>) -> InfallibleResult {
    let rb = Response::builder()
        .header("Content-Type", "application/json")
        .header("Cache-Control", "no-store no-cache");
    Ok(rb
        .status(hyper::StatusCode::OK)
        .body(full(t.json()))
        .expect("non-empty "))
}

pub fn flag(t: Box<dyn InterfaceResponse>) -> InfallibleResult {
    let rb = Response::builder()
        .header("Content-Type", "application/json")
        .header("Cache-Control", "no-store no-cache");
    Ok(rb
        .status(t.code() as u16)
        .body(full(t.json()))
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
        &None,
        &UtcTs::now(),
        &ErrorCode::NonEmptyBodyForGetRequest,
        &("GET request body should be empty"),
        hyper::StatusCode::FORBIDDEN.as_u16(),
        None,
    ))
}

pub fn error_unsupported_request(p: &str) -> Box<dyn InterfaceResponse> {
    Box::new(ErrResp::<Empty>::v2(
        &None,
        &UtcTs::now(),
        &ErrorCode::InvalidRequest,
        &("Invalid request (".to_string() + p + ")"),
        hyper::StatusCode::NOT_FOUND.as_u16(),
        None,
    ))
}

pub fn error_unimplemented_request(p: &str) -> Box<dyn InterfaceResponse> {
    Box::new(ErrResp::<Empty>::v2(
        &None,
        &UtcTs::now(),
        &ErrorCode::NotImplemented,
        &("Not implemented (".to_string() + p + ")"),
        hyper::StatusCode::NOT_IMPLEMENTED.as_u16(),
        None,
    ))
}

pub fn flag_error(hsc: hyper::StatusCode, ec: ErrorCode, em: &str) -> InfallibleResult {
    flag(Box::new(ErrResp::<Empty>::v2(
        &None,
        &UtcTs::now(),
        &ec,
        em,
        hsc.as_u16(),
        None,
    )))
}

pub fn flag_error_ext(hsc: u16, ec: ErrorCode, em: &str) -> InfallibleResult {
    flag(Box::new(ErrResp::<Empty>::v2(
        &None,
        &UtcTs::now(),
        &ec,
        em,
        hsc,
        None,
    )))
}
