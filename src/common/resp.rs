#![allow(dead_code)]
use super::types::TxId;
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
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

#[derive(Clone, Debug, Serialize)]
pub enum ErrorCode {
    InvalidRequest,             // RespCode::BadRequest
    InvalidURI,                 // RespCode::BadRequest
    InvalidSecurity,            // RespCode::BadRequest
    SignatureDoesNotMatch,      // RespCode::BadRequest
    InvalidLinkRefNumber,       // RespCode::BadRequest
    NoSuchVersion,              // RespCode::NotFound
    IdempotencyError,           // RespCode::Conflict
    ServiceUnavailable,         // RespCode::ServiceUnavailable
    PreconditionFailed,         // RespCode::PreconditionFailed
    InternalError,              // RespCode::InternalServerError
    NotImplemented,             // RespCode::NotImplemented
    Unauthorized,               // RespCode::UnauthorizedAccess
    InvalidNotifier,            // RespCode::BadRequest
    InvalidConsentId,           // RespCode::BadRequest
    InvalidConsentStatus,       // RespCode::BadRequest
    InvalidSessionId,           // RespCode::BadRequest
    InvalidSessionStatus,       // RespCode::BadRequest
    InvalidFIStatus,            // RespCode::BadRequest
    AccountNotFound,            // RespCode::BadRequest
    InvalidLinkToken,           // RespCode::BadRequest
    LinkTokenExpired,           // RespCode::BadRequest
    InvalidKey,                 // RespCode::BadRequest
    InvalidDateRange,           // RespCode::BadRequest
    InvalidConsentDetail,       // RespCode::BadRequest
    InvalidConsentUse,          // RespCode::BadRequest
    ConsentExpired,             // RespCode::Forbidden
    ConsentRevoked,             // RespCode::Forbidden
    ConsentPaused,              // RespCode::Forbidden
    DataFetchRequestInProgress, // RespCode::Forbidden
    ExpiredKeyMaterial,         // RespCode::NotFound
    NoDataFound,                // RespCode::NotFound
    DataGone,                   // RespCode::Gone
}

pub struct ErrResp {
    pub ver: &'static str,
    pub timestamp: String,
    pub tx_id: String,
    /// error code pertaining to the invalid request
    pub err_code: ErrorCode,
    /// error message with additional details.
    /// NOTE: Ensure no sensitive information is included in the error message.
    pub err_msg: String,
}

impl<'a> ErrResp {
    pub fn v2_new(ts: &str, tx_id: &TxId, err_code: ErrorCode, err_msg: &str) -> ErrResp {
        ErrResp {
            ver: "2.0.0",
            timestamp: String::from(ts),
            tx_id: tx_id.to_string(),
            err_code,
            err_msg: String::from(err_msg),
        }
    }
}
