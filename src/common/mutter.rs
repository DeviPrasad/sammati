use data_encoding::DecodeError;
use serde::{Deserialize, Serialize};
use std::string::FromUtf8Error;

#[derive(Clone, Copy, Debug, Default, PartialEq, Deserialize, Serialize)]
#[allow(dead_code)]
pub enum Mutter {
    None = 0,
    #[default]
    Unspecified = 41001,
    UnspecifiedError = 41002,
    Uninitialized = 41003,
    NotImplemented = 41005,
    MockErrValue = 41007,
    MockUnspecified = 41010,
    ConnectionCreationError = 41020,

    BadConfigFilePath = 42001,
    BadConfigJson = 42002,
    UnsupportedConfigDiscoveryRequest = 42003,
    MissingConfigParameters = 42004,

    UnspecifiedAuthorizationFlow = 4000,
    UnknownGetRequest = 4001,
    UnknownPostRequest = 4002,
    UnknownPutRequest = 4003,
    UnknownDeleteRequest = 4004,
    UnsupportedHttpMethod = 4005,
    BadFormUrlEncoding = 4006,
    UnsupportedClientAuthenticationMethod = 4007,
    ArgumentMismatch = 4008,
    BadBase64Encoding = 4009,
    TooManyAuthenticationParameters = 4010,
    InvalidBasicAuthorizationHeaderValue = 4011,
    MissingClientCredentials = 4012,
    MissingContentTypeFormUrlEncoding = 4013,
    MissingContentTypeJson = 4014,
    ClientAuthenticationMethodNotBasic = 4015,
}

impl Mutter {
    pub fn as_u16(&self) -> u16 {
        *self as u16
    }
}
impl ToString for Mutter {
    fn to_string(&self) -> String {
        match self {
            Mutter::MissingContentTypeFormUrlEncoding => {
                "Content-Type MUST be 'application/x-www-form-urlencoded'".to_string()
            }
            Mutter::MissingContentTypeJson => "Content-Type MUST be 'application/json'".to_string(),
            Mutter::None => "Operation successful".to_string(),
            _ => panic!("Mutter::to_string() - Unimplemented for {}", self.as_u16()),
        }
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
