use std::fmt;
use std::str;
use std::str::SplitAsciiWhitespace;
use data_encoding::BASE64;
use hyper::{Body, header, HeaderMap};
use hyper::body::HttpBody;
use crate::mutter::Mutter;

#[derive(Debug, Default)]
pub enum ContentType {
    Unspecified,
    FormUrlencoded,
    #[default]
    TextPlain,
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
    pub fn probe(&self, name: &str) -> Option<&str> {
        for (key, val) in &self.headers {
            if name == key {
                return str::from_utf8(val.as_bytes()).ok();
            }
        }
        None
    }

    pub fn content_type_param(&self) -> Option<String> {
        self
            .headers
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
            log::warn!("authorization_basic: {:#?} {:#?}", cid, secret);
            Ok(Some((cid.to_string(), secret.to_string())))
        } else {
            Ok(None)
        }
    }
}

pub trait BodyTrait {
    const POST_REQUEST_PAYLOAD_SIZE_MAX: u64 = (32 * 1024);
    fn payload(&self, max_size: u64) -> Result<u64, u64>;
}
impl BodyTrait for Body {
    fn payload(&self, size_max: u64) -> Result<u64, u64> {
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
}
pub async fn read_body_string(body: Body) -> Result<String, Mutter> {
    match hyper::body::to_bytes(body).await {
        Ok(bytes) => match String::from_utf8(bytes.to_vec()) {
            Ok(body_str) => {
                println!("body string {:#?}", body_str);
                Ok(body_str)
            }
            _ => Err(Mutter::HttpBodyStrUtf8Bad),
        },
        _ => Err(Mutter::HttpBodyReadingError),
    }
}
