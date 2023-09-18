use data_encoding::DecodeError;
use serde::{Deserialize, Serialize};
use std::string::FromUtf8Error;

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
