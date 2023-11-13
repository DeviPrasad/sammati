use chrono::Local;
use data_encoding::DecodeError;
use env_logger::Builder;
use log::LevelFilter;
use serde::{Deserialize, Serialize};
use std::{fmt, io::Write, string::FromUtf8Error};

pub fn init_log() {
    Builder::new()
        .format(|buf, record| {
            writeln!(
                buf,
                "{} [{}] - {}",
                Local::now().format("%Y-%m-%dT%H:%M:%S"),
                record.level(),
                record.args()
            )
        })
        .filter(None, LevelFilter::Info)
        .init();
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Deserialize, Serialize)]
#[allow(dead_code)]
pub enum Mutter {
    None = 0,

    Quit = 41000,
    #[default]
    Unspecified = 41001,
    UnspecifiedError = 41002,
    Uninitialized = 41003,
    NotImplemented = 41005,
    MockErrValue = 41007,
    MockUnspecified = 41010,
    BadArgVal = 41011,
    ConnectionCreationError = 41020,

    BadConfigFilePath = 42001,
    BadConfigJson = 42002,
    UnsupportedConfigDiscoveryRequest = 42003,
    MissingConfigParameters = 42004,

    UnspecifiedAuthorizationFlow = 40000,
    UnknownGetRequest = 40001,
    UnknownPostRequest = 40002,
    UnknownPutRequest = 40003,
    UnknownDeleteRequest = 40004,
    UnsupportedHttpMethod = 40005,
    BadFormUrlEncoding = 40006,
    UnsupportedClientAuthenticationMethod = 40007,
    ArgumentMismatch = 40008,
    BadBase64Encoding = 40009,
    TooManyAuthenticationParameters = 40010,
    InvalidBasicAuthorizationHeaderValue = 40011,
    MissingClientCredentials = 40012,
    MissingContentTypeFormUrlEncoding = 40013,
    MissingContentTypeJson = 40014,
    ClientAuthenticationMethodNotBasic = 40015,
    InternalServerError = 40022,
    InvalidRequest = 40023,

    BadDetachedContent = 40051,
    SigningKeyNotFound = 40052,
    VerificationKeyNotFound = 40053,
    UnsupportedKeyType = 40054,
    BadAlgorithmArgument = 40055,
    BadKeyDesc = 40056,
    BadRequestArgs = 40057,
    SignatureVerificationFailed = 40062,
    InvalidDetachedSignature = 40065,

    BadSocket = 40080,
    BadAddrString = 40081,
    DuplicateResponseParameterName = 40082,
    EmptyResponseParameterName = 40083,
    EmptyAccessTokenScopeString = 40084,
    BadScopeString = 40085,
    UnsupportedResponseType = 40086,
    PayloadTooLarge = 40087,
    PostRequestPayloadTooLarge = 40088,
    CodeStoreResponsePayloadTooLarge = 40089,
    HttpBodyStrUtf8Bad = 40092,
    HttpBodyReadingError = 40093,
    BadHttpBodyForGetRequest = 40094,

    InvalidTxId = 40030,
    InvalidConsentId = 40032,
    InvalidOneTimeToken = 40033,
}

impl Mutter {
    pub fn as_u16(&self) -> u16 {
        *self as u16
    }
    pub fn to_code(&self) -> String {
        let s = match self {
            Mutter::Unspecified => "Unspecified",
            Mutter::UnspecifiedError => "UnspecifiedError",
            Mutter::MissingContentTypeFormUrlEncoding => "MissingContentTypeFormUrlEncoding",
            Mutter::MissingContentTypeJson => "MissingContentTypeJson",
            Mutter::None => "None",
            Mutter::NotImplemented => "NotImplemented",
            Mutter::UnsupportedHttpMethod => "UnsupportedHttpMethod",
            Mutter::UnknownGetRequest => "UnknownGetRequest",
            Mutter::InvalidRequest => "InvalidRequest",
            Mutter::UnknownPostRequest => "UnknownPostRequest",
            Mutter::UnknownDeleteRequest => "UnknownDeleteRequest",
            Mutter::UnknownPutRequest => "UnknownPutRequest",
            Mutter::InvalidTxId => "InvalidTxId",
            Mutter::InvalidConsentId => "InvalidConsentId",
            _ => "Unspecified error",
        };
        s.to_string()
    }
}

impl fmt::Display for Mutter {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            Mutter::MissingContentTypeFormUrlEncoding => {
                "Content-Type MUST be 'application/x-www-form-urlencoded'"
            }
            Mutter::MissingContentTypeJson => "Content-Type MUST be 'application/json'",
            Mutter::None => "Operation successful",
            Mutter::NotImplemented => "Not implemented",
            Mutter::UnsupportedHttpMethod => "Unsupported Http Method",
            Mutter::InvalidTxId => "Invalid TxId",
            Mutter::InvalidConsentId => "Invalid ConsentId",
            _ => "Unspecified error",
        };
        write!(f, "{:?}", s)
    }
}
impl From<DecodeError> for Mutter {
    fn from(_: DecodeError) -> Self {
        Mutter::BadBase64Encoding
    }
}

impl From<FromUtf8Error> for Mutter {
    fn from(_: FromUtf8Error) -> Self {
        Mutter::BadBase64Encoding
    }
}
