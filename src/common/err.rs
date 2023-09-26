use hyper::{Body, Response, StatusCode};
use crate::mutter::Mutter;

#[derive(Clone, Debug)]
pub struct ErrorResponse {
    http_status_code: StatusCode,
    custom_error_code: Mutter,
    error_code: String,
    error: String,
    desc: String,
}

pub fn response(status: StatusCode, mutter: Mutter, st: Option<&str>) -> Response<Body> {
    Response::builder()
        .header("Content-Type", "application/json")
        .header("Cache-Control", "no-store")
        .header("Pragma", "no-cache")
        .header("X-Custom-FIP-ErrorCode", mutter.as_u16())
        .status(status)
        .body(Body::from(
            ErrorResponse::from_status_mutter(status, &mutter, st.map(|s| s.to_owned()))
                .to_json()
                .to_string(),
        ))
        .unwrap()
}

#[allow(dead_code)]
impl ErrorResponse {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "http_status_code": self.http_status_code.as_u16(),
            "custom_error_code": self.custom_error_code.as_u16(),
            "error": self.error,
            "error_code": self.error_code,
            "desc": self.desc,
        })
    }

    pub fn from_error(ec: Mutter, err_code: &str, err: &str, desc: &str) -> Self {
        ErrorResponse {
            http_status_code: StatusCode::BAD_REQUEST,
            custom_error_code: ec,
            error_code: err_code.to_string(),
            error: err.to_string(),
            desc: desc.to_string(),
        }
    }

    pub fn from_status_mutter(sc: StatusCode, err: &Mutter, st: Option<String>) -> Self {
        ErrorResponse {
            http_status_code: sc,
            custom_error_code: *err,
            error_code: err.to_code(),
            error: err.to_string(),
            desc: ErrorResponse::custom_error_desc(err).to_string()
                + ". "
                + &st.unwrap_or("".to_string()),
        }
    }

    pub fn custom_error_desc(e: &Mutter) -> &str {
        match e {
            _ => "Bad request"
        }
    }

    pub fn none(s: &str) -> Self {
        Self {
            http_status_code: StatusCode::OK,
            custom_error_code: Mutter::None,
            error_code: "no_error".to_string(),
            error: "none".to_string(),
            desc: s.to_string(),
        }
    }
    pub fn internal_server_error(s: &str) -> Self {
        Self {
            http_status_code: StatusCode::INTERNAL_SERVER_ERROR,
            custom_error_code: Mutter::InternalServerError,
            error_code: "internal_server_error".to_string(),
            error: s.to_string(),
            desc: s.to_string(),
        }
    }

    pub fn to_hyper_body(&self) -> Body {
        Body::from(self.to_json().to_string())
    }
}
