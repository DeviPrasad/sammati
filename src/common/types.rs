#![allow(dead_code)]

use crate::hs::Headers;
use crate::mutter::Mutter;
use crate::ts::{ConsentUtc, UtcTs};
//
// changelogs from 1.2.0
// https://specifications.rebit.org.in/api_schema/account_aggregator/AA_ChangeLog_2_0_0.txt
// https://specifications.rebit.org.in/api_schema/account_aggregator/FIP_ChangeLog_2_0_0.txt
// https://specifications.rebit.org.in/api_schema/account_aggregator/FIU_ChangeLog_2_0_0.txt
//
// API specs
// https://specifications.rebit.org.in/api_specifications/account_aggregator/AA_2_0_0.yaml
// https://specifications.rebit.org.in/api_specifications/account_aggregator/FIP_2_0_0.yaml
// https://specifications.rebit.org.in/api_specifications/account_aggregator/FIU_2_0_0.yaml
//
use bytes::Bytes;
use data_encoding::BASE64_NOPAD;
use dull::hex;
use serde::de::Error;
use serde::ser::SerializeStruct as _;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::fmt::{Debug, Write as _};
use std::str::FromStr;
use uuid::Uuid;

// An API or HTTP Url of any request or response has an unique path component.
pub trait Interface {
    fn path() -> &'static str;
    fn txid_as_string(&self) -> String;
}

// Interface response bears an (http) status code, and is json-encoded.
pub trait InterfaceResponse {
    fn code(&self) -> u32;
    fn json(&self) -> String;
}

// a request-type in the system must be 'DeserializeOwned' and also be an 'Interface'.
pub struct Type {}
impl Type {
    pub fn from_json<T: serde::de::DeserializeOwned + Interface>(
        json: &String,
        hp: &Headers,
    ) -> Result<T, Box<dyn InterfaceResponse>> {
        match serde_json::from_str::<T>(&json) {
            Ok(t) => {
                let x_tx_id = &hp.tx_id();
                if x_tx_id.is_none()
                    || x_tx_id
                        .as_ref()
                        .is_some_and(|s| s.to_string() == t.txid_as_string())
                {
                    Ok(t)
                } else {
                    Err(Box::new(ErrResp::<Empty>::v2(
                        //x_tx_id,
                        &TxId::from_ascii(&t.txid_as_string()).ok(),
                        &UtcTs::now(),
                        &ErrorCode::Unauthorized,
                        &[
                            "txn_id values in the header parameter and request body do not match (",
                            T::path(),
                            ")",
                        ]
                        .concat(),
                        ErrorCode::Unauthorized.to_http_status_code(),
                        None,
                    )))
                }
            }
            Err(_e) => {
                log::error!("Type::from_josn {_e:#?}");
                Err(Box::new(ErrResp::<Empty>::v2(
                    &None,
                    &UtcTs::now(),
                    &ErrorCode::InvalidRequest,
                    &["Invalid JSON payload in the requst body (", T::path(), ")"].concat(),
                    ErrorCode::InvalidRequest.to_http_status_code(),
                    None,
                )))
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HealthOkResp<T: serde::Serialize> {
    #[serde(rename = "version")]
    pub ver: String,
    #[serde(rename = "txnid", skip_serializing_if = "Option::is_none")]
    pub tx_id: Option<String>,
    #[serde(rename = "timestamp")]
    pub ts: String,
    #[serde(rename = "Status")]
    pub status: String,
    #[serde(rename = "response")]
    pub resp: String,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub custom: Option<T>,
}

impl<T> HealthOkResp<T>
where
    T: Default + serde::Serialize,
{
    pub fn v2(ts: &UtcTs, status: ServiceHealthStatus, cx: Option<T>) -> Self {
        HealthOkResp {
            ver: "2.0.0".to_string(),
            tx_id: None,
            ts: ts.to_string(),
            status: status.to_string(),
            resp: "OK".to_string(),
            custom: cx,
        }
    }
}

impl<T> Interface for HealthOkResp<T>
where
    T: Default + serde::Serialize,
{
    fn path() -> &'static str {
        "/Heartbeat"
    }
    fn txid_as_string(&self) -> String {
        match &self.tx_id {
            Some(s) => s.to_owned(),
            _ => "".to_owned(),
        }
    }
}

impl<T> InterfaceResponse for HealthOkResp<T>
where
    T: Default + serde::Serialize,
{
    fn code(&self) -> u32 {
        200 as u32
    }
    fn json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

#[derive(Clone, Debug)]
pub struct ValidationError(pub ErrorCode, pub String);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ServiceHealthStatus {
    UP,
    DOWN,
}

impl ToString for ServiceHealthStatus {
    fn to_string(&self) -> String {
        String::from(match self {
            ServiceHealthStatus::UP => "UP",
            ServiceHealthStatus::DOWN => "DOWN",
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ErrorCode {
    None,
    Good,
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
    NonEmptyBodyForGetRequest,
    PayloadTooLarge,
    ErrorReadingRequestBody,
    DetachedSignatureMissing,
    InvalidDetachedSignature,
    InvalidBase64Encoding,
}

impl ToString for ErrorCode {
    fn to_string(&self) -> String {
        String::from(match self {
            ErrorCode::None | ErrorCode::Good => "Successful. No Errors.",
            ErrorCode::InvalidRequest => "InvalidRequest",
            ErrorCode::InvalidURI => "InvalidURI",
            ErrorCode::InvalidSecurity => "InvalidSecurity",
            ErrorCode::SignatureDoesNotMatch => "SignatureDoesNotMatch",
            ErrorCode::InvalidLinkRefNumber => "InvalidLinkRefNumber",
            ErrorCode::NoSuchVersion => "NoSuchVersion",
            ErrorCode::IdempotencyError => "IdempotencyError",
            ErrorCode::ServiceUnavailable => "ServiceUnavailable",
            ErrorCode::PreconditionFailed => "PreconditionFailed",
            ErrorCode::InternalError => "InternalError",
            ErrorCode::NotImplemented => "DOWN",
            ErrorCode::Unauthorized => "Unauthorized",
            ErrorCode::InvalidNotifier => "InvalidNotifier",
            ErrorCode::InvalidConsentId => "InvalidConsentId",
            ErrorCode::InvalidConsentStatus => "InvalidConsentStatus",
            ErrorCode::InvalidSessionId => "InvalidSessionId",
            ErrorCode::InvalidSessionStatus => "InvalidSessionStatus",
            ErrorCode::InvalidFIStatus => "InvalidFIStatus",
            ErrorCode::AccountNotFound => "AccountNotFound",
            ErrorCode::InvalidLinkToken => "InvalidLinkToken",
            ErrorCode::LinkTokenExpired => "LinkTokenExpired",
            ErrorCode::InvalidKey => "InvalidKey",
            ErrorCode::InvalidDateRange => "InvalidDateRange",
            ErrorCode::InvalidConsentDetail => "InvalidConsentDetail",
            ErrorCode::InvalidConsentUse => "InvalidConsentUse",
            ErrorCode::ConsentExpired => "ConsentExpired",
            ErrorCode::ConsentRevoked => "ConsentRevoked",
            ErrorCode::ConsentPaused => "ConsentPaused",
            ErrorCode::DataFetchRequestInProgress => "DataFetchRequestInProgress",
            ErrorCode::ExpiredKeyMaterial => "ExpiredKeyMaterial",
            ErrorCode::NoDataFound => "NoDataFound",
            ErrorCode::DataGone => "DataGone",
            ErrorCode::NonEmptyBodyForGetRequest => "NonEmptyBodyForGetRequest",
            ErrorCode::PayloadTooLarge => "PayloadTooLarge",
            ErrorCode::ErrorReadingRequestBody => "ErrorReadingRequestBody",
            ErrorCode::DetachedSignatureMissing => "DetachedSignatureMissing",
            ErrorCode::InvalidDetachedSignature => "InvalidDetachedSignature",
            ErrorCode::InvalidBase64Encoding => "InvalidBase64Encoding",
        })
    }
}

impl ErrorCode {
    pub fn to_http_status_code(&self) -> u16 {
        (match self {
            ErrorCode::Good | ErrorCode::None => hyper::StatusCode::OK,
            ErrorCode::InvalidRequest | ErrorCode::InvalidURI => hyper::StatusCode::BAD_REQUEST,
            ErrorCode::Unauthorized
            | ErrorCode::SignatureDoesNotMatch
            | ErrorCode::InvalidDetachedSignature => hyper::StatusCode::UNAUTHORIZED,
            ErrorCode::InvalidSecurity | ErrorCode::InvalidKey => hyper::StatusCode::FORBIDDEN,
            ErrorCode::InternalError => hyper::StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::InvalidBase64Encoding | ErrorCode::ErrorReadingRequestBody => {
                hyper::StatusCode::BAD_REQUEST
            }
            ErrorCode::PayloadTooLarge => hyper::StatusCode::PAYLOAD_TOO_LARGE,
            ErrorCode::NotImplemented => hyper::StatusCode::NOT_IMPLEMENTED,
            _ => hyper::StatusCode::BAD_REQUEST,
        })
        .as_u16()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum UserConsentStatus {
    ACTIVE,
    PAUSED,
    REVOKED,
    EXPIRED,
    PENDING,
    REJECTED,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum UserConsentMode {
    VIEW,
    STORE,
    QUERY,
    STREAM,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FISessionStatus {
    ACTIVE,
    COMPLETED,
    EXPIRED,
    FAILED,
}

// fetch-status of Financial Information
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AccountFIStatus {
    READY,
    DENIED,
    PENDING,
    DELIVERED,
    TIMEOUT,
}

// There are two kinds of authentications that the FIP may support
// (1) Direct Authentication - FIP obtains confirmation directly interacting with the resource owner.
// (2) Token-based Authentication - FIP issues a token, which is to be included in the subsequent interaction
//     between AA and FIP. The token may be directly issued to the resource owner/customer.
// A token may be nonce, or a short-lived one-time password.
#[derive(Clone, Debug, Serialize)]
pub enum FIPAccLinkingAuthType {
    DIRECT,
    TOKEN,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FIPAccLinkStatus {
    LINKED,
    DELINKED,
    PENDING,
    FAILED,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum EncryptAlg {
    ECDH,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Curve {
    Curve25519,
    X25519,
}

#[derive(Clone, Debug, Serialize)]
pub struct FIPAccLinkReqRefNum {
    #[serde(rename = "RefNumber")]
    val: String,
}

impl FIPAccLinkReqRefNum {
    pub fn from(s: &str) -> Result<Self, Mutter> {
        if s.len() >= 16 {
            Ok(Self { val: s.to_owned() })
        } else {
            Err(Mutter::BadArgVal)
        }
    }

    pub fn deserialize_from_str<'de, D>(deserializer: D) -> Result<FIPAccLinkReqRefNum, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if let Ok(t) = String::deserialize(deserializer) {
            if let Ok(tok) = Self::from(&t) {
                return Ok(tok);
            }
        }
        Err(crate::mutter::Mutter::InvalidOneTimeToken).map_err(D::Error::custom)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct FIPAccLinkToken {
    #[serde(rename = "token")]
    val: String,
}

impl FIPAccLinkToken {
    pub fn from(s: &str) -> Result<Self, Mutter> {
        if s.len() >= 6 {
            Ok(Self { val: s.to_owned() })
        } else {
            Err(Mutter::BadArgVal)
        }
    }

    pub fn deserialize_from_str<'de, D>(deserializer: D) -> Result<FIPAccLinkToken, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if let Ok(t) = String::deserialize(deserializer) {
            if let Ok(tok) = Self::from(&t) {
                return Ok(tok);
            }
        }
        Err(crate::mutter::Mutter::InvalidOneTimeToken).map_err(D::Error::custom)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FIType {
    #[serde(rename = "DEPOSIT")]
    DEPOSIT,
    #[serde(rename = "TERM_DEPOSIT")]
    TermDeposit,
    #[serde(rename = "RECURRING_DEPOSIT")]
    RecurringDeposit,
    #[serde(rename = "SIP")]
    SIP,
    #[serde(rename = "CP")]
    CP,
    #[serde(rename = "GOVT_SECURITIES")]
    GovtSecurities,
    #[serde(rename = "EQUITIES")]
    EQUITIES,
    #[serde(rename = "BONDS")]
    BONDS,
    #[serde(rename = "DEBENTURES")]
    DEBENTURES,
    #[serde(rename = "MUTUAL_FUNDS")]
    MutualFunds,
    #[serde(rename = "ETF")]
    ETF,
    #[serde(rename = "IDR")]
    IDR,
    #[serde(rename = "CIS")]
    CIS,
    #[serde(rename = "AIF")]
    AIF,
    #[serde(rename = "INSURANCE_POLICIES")]
    InsurancePolicies,
    #[serde(rename = "NPS")]
    NPS,
    #[serde(rename = "INVIT")]
    INVIT,
    #[serde(rename = "REIT")]
    REIT,
    #[serde(rename = "GSTR1_3B")]
    GSTR1_3B,
    #[serde(rename = "LIFE_INSURANCE")]
    LifeInsurance,
    #[serde(rename = "GENERAL_INSURANCE")]
    GeneralInsurance,
    #[serde(rename = "OTHER")]
    OTHER,

    // sammati
    #[serde(rename = "HOME_LOAN")]
    HomeLoan,
    #[serde(rename = "GOLD_LOAN")]
    GoldLoan,
    #[serde(rename = "VEHICLE_LOAN")]
    VehicleLoan,
    #[serde(rename = "LA_FIXED_DEPOSIT")]
    LAFixedDeposit,
    #[serde(rename = "LA_INSURANCE_POLICIES")]
    LAInsurancePolicies,
    #[serde(rename = "LA_MUTUAL_FUNDS")]
    LAMF, // loan against mutual funds
    #[serde(rename = "LA_SHARES")]
    LAShares,
    #[serde(rename = "LA_PROPERTY")]
    LAProperty,
    #[serde(rename = "LA_PF")]
    LAPF,
    #[serde(rename = "LA_EPF")]
    LAEPF,
    #[serde(rename = "PERSONAL_LOAN")]
    PersonalLoan, // demand promissory notes (DPN loans), mostly NBFCs
    #[serde(rename = "CREDITCARD_LOAN")]
    CreditCardLoan,
    #[serde(rename = "EDUCATION_LOAN")]
    EducationLoan,
    #[serde(rename = "BUSINESS_LOAN")]
    BusinessLoan, // repayable in 36 months
}

/*
impl ToString for FIType {
    fn to_string(&self) -> String {
        String::from(match self {
            FIType::Deposit => "DEPOSIT",
            FIType::TermDeposit => "TERM_DEPOSIT",
            FIType::RecurringDeposit => "RECURRING_DEPOSIT",
            FIType::SIP => "SIP",
            FIType::CP => "CP",
            FIType::GovtSecurities => "GOVT_SECURITIES",
            FIType::Equities => "EQUITIES",
            FIType::Bonds => "BONDS",
            FIType::Debentures => "DEBENTURES",
            FIType::MutualFunds => "MUTUAL_FUNDS",
            FIType::ETF => "ETF",
            FIType::IDR => "IDR",
            FIType::CIS => "CIS",
            FIType::AIF => "AIF",
            FIType::InsurancePolicies => "INSURANCE_POLICIES",
            FIType::NPS => "NPS",
            FIType::INVIT => "INVIT",
            FIType::REIT => "REIT",
            FIType::GSTR1_3B => "GSTR1_3B",
            FIType::LifeInsurance => "LIFE_INSURANCE",
            FIType::GeneralInsurance => "GENERAL_INSURANCE",
            FIType::HomeLoan => "HOME_LOAN",
            FIType::GoldLoan => "GOLD_LOAN",
            FIType::VehicleLoan => "VEHICLE_LOAN",
            FIType::LAFixedDeposit => "LA_FIXED_DEPOSIT",
            FIType::LAInsurancePolicies => "LA_INSURANCE_POLICIES",
            FIType::LAMF => "LA_MUTUAL_FUNDS", // loan against mutual funds
            FIType::LAShares => "LA_SHARES",
            FIType::LAProperty => "LA_PROPERTY",
            FIType::LAPF => "LA_PF",
            FIType::LAEPF => "LA_EPF",
            FIType::PersonalLoan => "PERSONAL_LOAN", // demand promissory notes (DPN loans), mostly NBFCs
            FIType::CreditCardLoan => "CREDITCARD_LOAN",
            FIType::EducationLoan => "EDUCATION_LOAN",
            FIType::BusinessLoan => "BUSINESS_LOAN",
            FIType::Other => "OTHER",
        })
    }
}

impl FromStr for FIType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "DEPOSIT" => Ok(FIType::Deposit),
            /*FIType::TermDeposit => "TERM_DEPOSIT",
            FIType::RecurringDeposit => "RECURRING_DEPOSIT",
            FIType::SIP => "SIP",
            FIType::CP => "CP",
            FIType::GovtSecurities => "GOVT_SECURITIES",
            FIType::Equities => "EQUITIES",
            FIType::Bonds => "BONDS",
            FIType::Debentures => "DEBENTURES",
            FIType::MutualFunds => "MUTUAL_FUNDS",
            FIType::ETF => "ETF",
            FIType::IDR => "IDR",
            FIType::CIS => "CIS",
            FIType::AIF => "AIF",
            FIType::InsurancePolicies => "INSURANCE_POLICIES",
            FIType::NPS => "NPS",
            FIType::INVIT => "INVIT",
            FIType::REIT => "REIT",
            FIType::GSTR1_3B => "GSTR1_3B",
            "LIFE_INSURANCE" => FIType::LifeInsurance,
            "GENERAL_INSURANCE" => FIType::GeneralInsurance,
            "HOME_LOAN" => FIType::HomeLoan,
            FIType::GoldLoan => "GOLD_LOAN",
            FIType::VehicleLoan => "VEHICLE_LOAN",
            FIType::LAFixedDeposit => "LA_FIXED_DEPOSIT",
            FIType::LAInsurancePolicies => "LA_INSURANCE_POLICIES",
            FIType::LAMF => "LA_MUTUAL_FUNDS", // loan against mutual funds
            FIType::LAShares => "LA_SHARES",
            FIType::LAProperty => "LA_PROPERTY",
            FIType::LAPF => "LA_PF",
            FIType::LAEPF => "LA_EPF",
            FIType::PersonalLoan => "PERSONAL_LOAN", // demand promissory notes (DPN loans), mostly NBFCs
            FIType::CreditCardLoan => "CREDITCARD_LOAN",
            FIType::EducationLoan => "EDUCATION_LOAN",
            FIType::BusinessLoan => "BUSINESS_LOAN",
            FIType::Other => "OTHER",*/
            _ => Ok(FIType::Other),
        }
    }
}
*/

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FinAccType {
    #[serde(rename = "SAVINGS")]
    Savings,
    #[serde(rename = "CURRENT")]
    Current,
    #[serde(rename = "DEFAULT")]
    Default,
    #[serde(rename = "NRE")]
    NRE,
    #[serde(rename = "NRO")]
    NRO,
    #[serde(rename = "LOAN")]
    Loan,
}

impl ToString for FinAccType {
    fn to_string(&self) -> String {
        String::from(match self {
            FinAccType::Savings => "SAVINGS",
            FinAccType::Current => "CURRENT",
            FinAccType::Default => "DEFAULT",
            FinAccType::NRE => "NRE",
            FinAccType::NRO => "NRO",
            FinAccType::Loan => "LOAN",
        })
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct TxId {
    #[serde(rename = "txnid")]
    pub val: String,
}

impl ToString for TxId {
    fn to_string(&self) -> String {
        self.val.to_owned()
    }
}

impl crate::hs::Headers {
    pub fn tx_id(&self) -> Option<TxId> {
        let x_tx_id = self.probe("x-tx-id");
        if let Some(s) = x_tx_id {
            TxId::from_ascii(&s).ok()
        } else {
            None
        }
    }
}

impl TxId {
    pub fn from_uuid(s: &str) -> Result<TxId, bool> {
        match Uuid::parse_str(s) {
            Ok(_uuid) => Ok(TxId {
                val: s.to_lowercase(),
            }),
            _ => Err(false),
        }
    }
    #[allow(dead_code)]
    pub fn from_ascii(s: &str) -> Result<TxId, bool> {
        if s.len() > 0 && s.is_ascii() {
            Ok(TxId {
                val: s.to_lowercase(),
            })
        } else {
            Err(false)
        }
    }

    pub fn deserialize_from_str<'de, D>(deserializer: D) -> Result<TxId, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer).and_then(|id| {
            if id.len() > 0 {
                Ok(TxId { val: id.to_owned() })
            } else {
                Err(crate::mutter::Mutter::InvalidTxId).map_err(D::Error::custom)
            }
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct SessionId {
    //#[serde(skip)]
    pub rb: [u8; 16],
    pub es: String,
}

pub type UuidRep = ([u8; 16], String);

#[derive(Clone, Debug, PartialEq)]
pub enum Base64EncUuidErr {
    BadBase64,
    BadByteArray,
    BadUuidStr,
    ExpectedVersionV4,
}

impl ToString for SessionId {
    fn to_string(&self) -> String {
        self.es.to_string()
    }
}

impl FromStr for SessionId {
    type Err = bool;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        SessionId::from_str(s)
    }
}

impl Serialize for SessionId {
    fn serialize<S>(&self, ss: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        let mut st = ss.serialize_struct("Base64EncUuid", 1)?;
        st.serialize_field("sessionId", &self.to_string())?;
        st.end()
    }
}

impl SessionId {
    pub fn new() -> SessionId {
        let rb: [u8; 16] = Uuid::new_v4().into_bytes();
        let es: String = BASE64_NOPAD.encode(&rb);
        SessionId {
            rb,
            es: ["sid_", &es].concat(),
        }
    }

    pub fn from_str(s: &str) -> Result<Self, bool> {
        Self::decode(s)
            .map(|r| Self { rb: r.0, es: r.1 })
            .map_err(|_| false)
    }

    pub fn from_uuid_v4(s: &str) -> Result<SessionId, Base64EncUuidErr> {
        match Uuid::from_str(s) {
            Ok(uuid) => {
                return if uuid.get_version_num() == 4 {
                    Ok(SessionId {
                        rb: *uuid.as_bytes(),
                        es: BASE64_NOPAD.encode(uuid.as_bytes()),
                    })
                } else {
                    Err(Base64EncUuidErr::ExpectedVersionV4)
                }
            }
            _ => Err(Base64EncUuidErr::BadUuidStr),
        }
    }

    pub fn copy_enc(&self, t: &mut String) -> bool {
        t.write_str(&self.es).is_ok()
    }

    pub fn decode(s: &str) -> Result<UuidRep, Base64EncUuidErr> {
        match BASE64_NOPAD.decode(s.as_bytes()) {
            Ok(vec) => {
                let res: Result<[u8; 16], _> = vec.try_into();
                match res {
                    Ok(rb) => Ok((rb, Uuid::from_bytes(rb).to_string())),
                    _ => Err(Base64EncUuidErr::BadByteArray),
                }
            }
            _ => Err(Base64EncUuidErr::BadBase64),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsentHandle {
    pub val: String,
}

// consentId is a 128-bit number, represented as 32 hex chars.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsentId {
    pub val: String,
}

impl ConsentId {
    pub fn deserialize_from_str<'de, D>(d: D) -> Result<ConsentId, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let cs = String::deserialize(d)?;
        if let Some(s) = <Vec<u8> as hex::Hex>::from_hex(&cs) {
            if cs.to_ascii_uppercase() == cs && cs.len() == 32 {
                return Ok(ConsentId { val: cs });
            } else {
                log::error!("{cs} {s:#?} {:#?}", cs.to_ascii_uppercase())
            }
        }
        Err(crate::mutter::Mutter::InvalidConsentId).map_err(D::Error::custom)
    }
}

// (mandatory)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserConsent {
    // Unique ID generated by AA after consent approval is given by the customer.
    pub id: Option<ConsentId>,
    // Unique ID generated by AA after receiving the consent request.
    // Consent Handle can be used by FIU/AA Client to check the consent status and
    // also to retrieve the consent ID once consent is approved by the customer.
    pub handle: Option<ConsentHandle>,
    // (required) status of consent artefact
    pub status: UserConsentStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AccOwnerIdCategory {
    #[serde(rename = "STRONG")]
    Strong,
    #[serde(rename = "WEAK")]
    Weak,
    #[serde(rename = "ANCILLARY")]
    Ancillary,
}

impl ToString for AccOwnerIdCategory {
    fn to_string(&self) -> String {
        String::from(match self {
            AccOwnerIdCategory::Strong => "STRONG",
            AccOwnerIdCategory::Weak => "WEAK",
            AccOwnerIdCategory::Ancillary => "ANCILLARY",
        })
    }
}

impl FromStr for AccOwnerIdCategory {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "STRONG" => Ok(AccOwnerIdCategory::Strong),
            "WEAK" => Ok(AccOwnerIdCategory::Weak),
            "ANCILLARY" => Ok(AccOwnerIdCategory::Ancillary),
            _ => Err(()),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FIPId {
    val: String,
}

// discovered account information.
//  + used in FIP::AccLinkRequest accounts to be linked.
//  + used in SignedConsentDetail
// best viewed as a virtualized account descriptor representing a real/concrete FIP account.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FIPAccDesc {
    // type of financial information
    #[serde(rename = "FIType")]
    fi_type: FIType,
    // account Type or Sub FI Type
    #[serde(rename = "accType")]
    acc_type: FinAccType,
    // unique FIP account reference number linked with the masked account number.
    #[serde(
        rename = "accRefNumber",
        deserialize_with = "FIPAccLinkRef::deserialize_from_str"
    )]
    acc_ref_num: FIPAccLinkRef,
    #[serde(
        rename = "maskedAccNumber",
        deserialize_with = "FIPMaskedAccNum::deserialize_from_str"
    )]
    masked_acc_num: FIPMaskedAccNum,
}

// used in SignedConsentDetail::Accounts
// best viewed as a virtualized account descriptor representing a real/concrete FIP account.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FIPLinkedAccDesc {
    // type of financial information
    #[serde(rename = "FIType")]
    fi_type: FIType,
    // FIP ID as defined in the Account Aggregator Ecosystem.
    #[serde(rename = "fipId")]
    fip_id: FIPId,
    // account Type or Sub FI Type
    #[serde(rename = "accType")]
    acc_type: FinAccType,
    // unique FIP account reference number linked with the masked account number.
    #[serde(rename = "linkRefNumber")]
    acc_link_ref_num: FIPAccLinkRef,
    #[serde(rename = "maskedAccNumber")]
    masked_acc_num: FIPMaskedAccNum,
}

// Unique FIP Account Reference Number which will be usually linked with a masked account number.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FIPAccLinkRef {
    #[serde(rename = "linkRefNumber")]
    val: String,
}

impl FIPAccLinkRef {
    pub fn from(s: &str) -> Self {
        Self { val: s.to_string() }
    }

    pub fn deserialize_from_str<'de, D>(d: D) -> Result<FIPAccLinkRef, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(d).map(|id| FIPAccLinkRef { val: id.to_owned() })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FIPMaskedAccNum {
    val: String,
}

impl FIPMaskedAccNum {
    pub fn from(s: &str) -> Self {
        Self { val: s.to_string() }
    }

    pub fn deserialize_from_str<'de, D>(d: D) -> Result<FIPMaskedAccNum, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(d).map(|id| FIPMaskedAccNum { val: id.to_owned() })
    }
}

// Unique FIP account reference number which is linked with the masked account number.
#[derive(Clone, Debug, Serialize)]
pub struct FIPMaskedAccRefNum {
    #[serde(rename = "accRefNumber")]
    val: String,
}

impl FIPMaskedAccRefNum {
    pub fn from(s: &str) -> Self {
        Self { val: s.to_string() }
    }

    pub fn deserialize_from_str<'de, D>(d: D) -> Result<FIPMaskedAccRefNum, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(d).map(|id| FIPMaskedAccRefNum { val: id.to_owned() })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum KeyMaterialFormat {
    #[serde(rename = "BASE64_NOPAD")]
    Base64NoPadding,
    #[serde(rename = "BASE64_URL_NOPAD")]
    Base64UrlNoPadding,
    #[serde(rename = "HEX")]
    HEX,
    #[serde(rename = "PEM")]
    PEM,
    #[serde(rename = "DER")]
    DER,
}

#[derive(Clone, Debug, Serialize)]
pub struct LinkedAccEncData {
    // reference number assigned by FIP as part of Account Linking Process.
    pub link_ref_num: FIPAccLinkRef,
    pub masked_acc_num: FIPMaskedAccNum,
    // end-to-end encrypted financial information
    pub encrypted_fi: Bytes,
}

// contains the public information for performing the ECDH key exchange.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DHPublicKey {
    // expiration of the public key.
    #[serde(rename = "expiry", deserialize_with = "UtcTs::deserialize_from_str")]
    expiry: UtcTs,
    // defines public parameters used to calculate session key (for data encryption and decryption).
    // ex: cipher=AES/GCM/NoPadding;KeyPairGenerator=ECDH"
    #[serde(rename = "Parameters", skip_serializing_if = "Option::is_none")]
    params: Option<String>,
    // the value of ephemeral public key
    #[serde(rename = "KeyValue")]
    pub val_ephemeral_pub_key: Bytes,
}

// cryptographic parameters for end-to-end data encryption.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyMaterial {
    // Currently, only ECDH is supported.
    #[serde(rename = "cryptoAlg")]
    pub crypto_alg: EncryptAlg,
    #[serde(rename = "curve")]
    pub curve: Curve,
    // specifies the secure standard cryptographic primitives to perform end to end encryption.
    // Use key-value pair separated by a semicolon.
    // ex: cipher=AES/GCM/NoPadding;KeyPairGenerator=ECDH - symmetric encryption(AES-256 bits, GCM-128 bits and No Padding) and key exchange protocol(ECDH).
    #[serde(rename = "params", skip_serializing_if = "Option::is_none")]
    pub params: Option<String>,
    #[serde(rename = "DHPublicKey")]
    pub dh_pub_key: DHPublicKey,
    // ref: https://tools.ietf.org/html/rfc5116 - An Interface and Algorithms for Authenticated Encryption. January 2008.
    #[serde(rename = "Nonce")]
    pub nonce: Bytes,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AccOwnerConsentProof {
    // unique id generated by AA after the account holder authorizes the consent request.
    #[serde(rename = "id")]
    consent_id: String,
    // signature part of the consent JWS.
    // The receiver has to verify if the given signature matches the signature in the original consent JWS.
    #[serde(rename = "digitalSignature")]
    signature: Bytes,
}

impl AccOwnerConsentProof {
    pub fn consent_id(&self) -> String {
        self.consent_id.clone()
    }
    pub fn signature(&self) -> &[u8] {
        self.signature.as_ref()
    }
}

// linked account's metadata and the encrypted data for accessing the finanical informati
#[derive(Clone, Debug, Serialize)]
pub struct FinInfo {
    // FIP ID as defined in the Account Aggregator Ecosystem.
    pub fip_id: FIPId,
    pub data: Vec<LinkedAccEncData>,
    pub key_material: KeyMaterial,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AccOwnerIdType {
    #[serde(rename = "MOBILE")]
    Mobile,
    #[serde(rename = "AADHAAR")]
    Aadhaar,
    #[serde(rename = "EMAIL")]
    Email,
    #[serde(rename = "PAN")]
    PAN,
    #[serde(rename = "DOB")]
    DOB,
    #[serde(rename = "ACCNUM")]
    AccNum, // ACCNO
    #[serde(rename = "CRN")]
    CRN,
    #[serde(rename = "PPAN")]
    PPAN,
    #[serde(rename = "OTHERS")]
    Others,
}

impl ToString for AccOwnerIdType {
    fn to_string(&self) -> String {
        String::from(match self {
            AccOwnerIdType::Mobile => "MOBILE",
            AccOwnerIdType::Aadhaar => "AADHAAR",
            AccOwnerIdType::Email => "EMAIL",
            AccOwnerIdType::PAN => "PAN",
            AccOwnerIdType::DOB => "DOB",
            AccOwnerIdType::AccNum => "ACCNUM",
            AccOwnerIdType::CRN => "CRN",
            AccOwnerIdType::PPAN => "PPAN",
            AccOwnerIdType::Others => "OTHERS",
        })
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct AccOwnerId {
    val: String,
}

impl AccOwnerId {
    pub fn deserialize_from_str<'de, D>(d: D) -> Result<AccOwnerId, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(d).map(|id| AccOwnerId { val: id.to_owned() })
    }
}
// Set of Identifiers required for discovering the accounts of a customer at the FIP.
// It is mandatory to provide at the least one STRONG category identifier.
// FIPs must employ KYC to ensure identitifiers are verified and authenticated.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FIPAccOwnerIdentifier {
    // category of identifiers based on the ability to perform online authenticity
    #[serde(rename = "category")]
    pub id_category: AccOwnerIdCategory,
    // type of identifier
    #[serde(rename = "type")]
    pub id_type: AccOwnerIdType,
    // value/number of the selected identifier
    #[serde(
        rename = "value",
        deserialize_with = "AccOwnerId::deserialize_from_str"
    )]
    pub id_val: AccOwnerId,
}

// identifier of the Customer generated during the registration with AA.
#[derive(Clone, Debug, Serialize)]
pub struct FIPAccOwnerAAId {
    #[serde(rename = "customerAddress")]
    val: String,
}

impl FIPAccOwnerAAId {
    pub fn from(s: &str) -> Self {
        Self { val: s.to_string() }
    }

    pub fn deserialize_from_str<'de, D>(deserializer: D) -> Result<FIPAccOwnerAAId, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer).map(|id| FIPAccOwnerAAId { val: id.to_owned() })
    }
}

// identifier of the Customer generated during the registration with AA.
#[derive(Clone, Debug, Serialize)]
pub struct CustomerAddressFIPAccOwnerAAId {
    #[serde(rename = "customerAddress")]
    val: String,
}

impl CustomerAddressFIPAccOwnerAAId {
    pub fn deserialize_from_str<'de, D>(
        deserializer: D,
    ) -> Result<CustomerAddressFIPAccOwnerAAId, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer)
            .map(|id| CustomerAddressFIPAccOwnerAAId { val: id.to_owned() })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FIPAccOwner {
    // example: alice@sammati_aa_id
    #[serde(
        rename = "id",
        deserialize_with = "FIPAccOwnerAAId::deserialize_from_str"
    )]
    ro_aa_id: FIPAccOwnerAAId,
    #[serde(rename = "Identifiers")]
    identifiers: Vec<FIPAccOwnerIdentifier>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FIPAccOwnerAccDescriptors {
    // Identifier of the Customer generated during the registration with AA.
    // Customer identifiers including AA virtual address.
    // example: alex@sammati_aa_id
    #[serde(
        rename = "id",
        deserialize_with = "FIPAccOwnerAAId::deserialize_from_str"
    )]
    pub ao_aa_id: FIPAccOwnerAAId,
    // list of customer's accounts to be linked
    #[serde(rename = "Accounts")]
    pub accounts: Vec<FIPAccDesc>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct FIPAccOwnerLinkedAccRef {
    // Identifier of the customer generated during the registration with AA.
    // example: alex@sammati_aa_id.
    #[serde(
        rename = "customerAddress",
        deserialize_with = "CustomerAddressFIPAccOwnerAAId::deserialize_from_str"
    )]
    pub customer_address: CustomerAddressFIPAccOwnerAAId,
    // An account's ref num at FIP - used in the delink_account request.
    // Reference number assigned by FIP in the account linking flow.
    #[serde(
        rename = "linkRefNumber",
        deserialize_with = "FIPAccLinkRef::deserialize_from_str"
    )]
    pub link_ref_num: FIPAccLinkRef,
}

#[derive(Clone, Debug, Serialize)]
pub struct FIPAccOwnerLinkedAccStatus {
    // Identifier of the customer generated during the registration with AA.
    // example: alex@sammati_aa_id.
    #[serde(rename = "customerAddress", flatten)]
    pub customer_address: CustomerAddressFIPAccOwnerAAId,
    // An account's ref num at FIP - used in the delink_account request.
    // Reference number assigned by FIP in the account linking flow.
    #[serde(rename = "linkRefNumber", flatten)]
    pub link_ref_num: FIPAccLinkRef,
    // tells if the account is still linked.
    #[serde(rename = "status")]
    pub status: FIPAccLinkStatus,
}

#[derive(Clone, Debug, Serialize)]
pub struct FIPConfirmAccLinkingStatus {
    // Identifier of the customer generated during the registration with AA.
    // example: alice@sammati_aa_id.
    #[serde(rename = "customerAddress", flatten)]
    pub customer_address: FIPAccOwnerAAId,
    // An account's ref num at FIP - used in the delink_account request.
    // Reference number assigned by FIP in the account linking flow.
    #[serde(rename = "linkRefNumber", flatten)]
    pub link_ref_num: FIPAccLinkRef,
    // Unique FIP account reference number which is linked with the masked account number.
    #[serde(rename = "accRefNumber", flatten)]
    pub acc_ref_num: FIPMaskedAccRefNum,
    // tells if the account is still linked.
    #[serde(rename = "status")]
    pub status: FIPAccLinkStatus,
}

impl FIPConfirmAccLinkingStatus {
    pub fn _mock_from_(
        addr: &str,
        link_ref_num: &str,
        masked_acc_ref_num: &str,
        status: FIPAccLinkStatus,
    ) -> Self {
        Self {
            customer_address: FIPAccOwnerAAId::from(addr),
            link_ref_num: FIPAccLinkRef::from(link_ref_num),
            acc_ref_num: FIPMaskedAccRefNum::from(masked_acc_ref_num),
            status,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Notifier {
    // (required) type of the notifier entity; example: AA
    pub typ: String,
    // (required) unique ID to identify this entity acting as the notifier.
    pub id: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct FinAccount {
    // reference number assigned by FIP as part of the account linking process
    pub link_ref_num: String,
    // fetch status of the Financial Information.
    pub fi_status: AccountFIStatus,
    pub desc: String,
}

// (mandatory)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FIPAccOwnerConsentStatus {
    // Unique ID generated by AA after consent approval is given by the account holder.
    pub id: Option<ConsentId>,
    // (required) status of consent artefact
    pub status: UserConsentStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedConsentDetail {
    // start date-time of the consent. This field would allow for Post-Dated consent.
    #[serde(
        rename = "consentStart",
        deserialize_with = "UtcTs::deserialize_from_str"
    )]
    pub consent_start: ConsentUtc,
    //Expiry date-time for the consent
    #[serde(
        rename = "consentExpiry",
        deserialize_with = "UtcTs::deserialize_from_str"
    )]
    pub consent_exp: ConsentUtc,

    // consent mode as defined in the AA tech spec - view/store/query/stream
    #[serde(rename = "consentMode")]
    pub consent_mode: UserConsentMode,

    // FI Fetch type - ONETIME or PERIODIC
    #[serde(rename = "fetchType")]
    pub fetch_type: FetchType,

    // what's the consent for? Fetching FI of PROFILE/SUMMARY/TRANSACTIONS
    #[serde(rename = "consentTypes")]
    pub consent_types: Vec<ConsentType>,

    #[serde(rename = "fiTypes")]
    pub fi_types: Vec<FIType>,

    // entity which receives data.
    // for a consent between FIP & AA, DataConsumer would be AA.
    // for a consent between FIU-Application/AA-Application & AA, DataConsumer would be FIU-Client/AA-Client.
    // { AA_ID, FIU_Client_ID, AA_Client_ID }
    #[serde(rename = "DataConsumer")]
    pub data_consumer: DataConsumerIdType,

    // The entity which provides data.
    // for a consent between FIP & AA, DataProvider would be FIP.
    // for a consent between FIU-Client/AA-Client & AA, DataProvider would be AA.
    #[serde(rename = "DataProvider")]
    pub data_provider: DataProviderIdType,

    /* Identifier of the Customer generated during the registration with AA. */
    #[serde(rename = "Customer")]
    pub customer: Customer,

    // List of accounts for which the account holder has already consented.
    // The 'FIPLinkedAccDesc::fipId' field identifies the FIP.
    // For a consent between FIU & AA, this list could have accounts from multiple FIP.
    // For a consent between FIP & AA, only accounts from particular FIP must be present in this section.
    #[serde(rename = "Accounts")]
    pub accounts: Vec<FIPLinkedAccDesc>,

    // 	purpose of the consent (Defined in AA Technical Specification)
    #[serde(rename = "Purpose")]
    pub purpose: Purpose,

    #[serde(rename = "FIDataRange")]
    pub fi_data_range: FIPeriod,
    #[serde(rename = "DataLife")]
    // how long the FIU/AA Client can store the data
    pub data_life: DataLife,
    // frequency of FI data fetch within the defined time unit. E.g.HOURLY,DAILY,MONTHLY,YEARLY.
    #[serde(rename = "Frequency")]
    pub frequency: DataFetchFrequency,
    #[serde(rename = "DataFilter", skip_serializing_if = "Option::is_none")]
    pub data_filter: Option<DataFilter>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FIPeriod {
    // Date-time from which the financial information is requested
    #[serde(rename = "from", deserialize_with = "UtcTs::deserialize_from_str")]
    pub from: UtcTs,
    // Date-time till which the financial information is requested
    #[serde(rename = "to", deserialize_with = "UtcTs::deserialize_from_str")]
    pub to: UtcTs,
}

// parameters for consent tracking
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Purpose {
    #[serde(rename = "code")]
    code: String,
    // URL where the purpose is further defined
    #[serde(rename = "refUri", skip_serializing_if = "Option::is_none")]
    ref_uri: Option<String>,
    // textual description
    #[serde(rename = "count", skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    // most recent timestamp when the consent was used
    #[serde(rename = "Category", skip_serializing_if = "Option::is_none")]
    category: Option<PurposeCategory>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PurposeCategory {
    #[serde(rename = "type")]
    pc_type: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Customer {
    #[serde(rename = "id")]
    id: String, /* customer_identifier@AA_identifier */
}

// The entity which provides data.
// for a consent between FIP & AA, DataProvider would be FIP.
// for a consent between FIU-Client/AA-Client & AA, DataProvider would be AA.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DataProviderIdType {
    #[serde(rename = "id")]
    provider_id: String, /* Data Provider ID - FIP_ID */
    #[serde(rename = "type")]
    provider_type: String, /* 'FIP' */
}

// entity which receives data.
// for a consent between FIP & AA, DataConsumer would be AA.
// for a consent between FIU-Application/AA-Application & AA, DataConsumer would be FIU-Client/AA-Client.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DataConsumerIdType {
    #[serde(rename = "id")]
    consumer_id: String, /* Data Consumer ID - AA_ID or FIU_Client_ID or AA_Client_ID */
    #[serde(rename = "type")]
    consumer_type: String, /* AA */
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ConsentType {
    PROFILE,
    SUMMARY,
    TRANSACTIONS,
}

impl ToString for ConsentType {
    fn to_string(&self) -> String {
        String::from(match self {
            ConsentType::PROFILE => "PROFILE",
            ConsentType::SUMMARY => "SUMMARY",
            ConsentType::TRANSACTIONS => "TRANSACTIONS",
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FetchType {
    ONETIME,
    PERIODIC,
}

impl ToString for FetchType {
    fn to_string(&self) -> String {
        String::from(match self {
            FetchType::ONETIME => "ONETIME",
            FetchType::PERIODIC => "PERIODIC",
        })
    }
}

// rules for filtering FI at FIP
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DataFilter {
    // filter mode - tx_type or tx_amount
    #[serde(rename = "type")]
    filter_type: DataFilterType,
    #[serde(rename = "operator")]
    op: RelOp,
    // Value to filter data
    #[serde(rename = "value")]
    val: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DataFilterType {
    TRANSACTIONTYPE,
    TRANSACTIONAMOUNT,
}

impl ToString for DataFilterType {
    fn to_string(&self) -> String {
        String::from(match self {
            DataFilterType::TRANSACTIONTYPE => "TRANSACTIONTYPE",
            DataFilterType::TRANSACTIONAMOUNT => "TRANSACTIONAMOUNT",
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RelOp {
    EQ,
    NEQ,
    GT,
    LT,
    GTE,
    LTE,
}

impl ToString for RelOp {
    fn to_string(&self) -> String {
        String::from(match self {
            RelOp::EQ => "=",
            RelOp::NEQ => "!=",
            RelOp::GT => ">",
            RelOp::LT => "<",
            RelOp::GTE => ">=",
            RelOp::LTE => "<=",
        })
    }
}

// how long the FIU/AA Client can store the data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DataLife {
    DAY,
    MONTH,
    YEAR,
    INF,
}

impl ToString for DataLife {
    fn to_string(&self) -> String {
        String::from(match self {
            DataLife::DAY => "DAY",
            DataLife::MONTH => "MONTH",
            DataLife::YEAR => "YEAR",
            DataLife::INF => "INF",
        })
    }
}

// frequency of FI data fetch within the defined time unit
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DataFetchFrequency {
    HOUR,
    DAY,
    MONTH,
    YEAR,
}

impl ToString for DataFetchFrequency {
    fn to_string(&self) -> String {
        String::from(match self {
            DataFetchFrequency::HOUR => "HOUR",
            DataFetchFrequency::DAY => "DAY",
            DataFetchFrequency::MONTH => "MONTH",
            DataFetchFrequency::YEAR => "YEAR",
        })
    }
}

pub struct Frequency {
    pub unit: DataFetchFrequency,
}

// parameters for consent tracking
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsentUse {
    // logUri can be any valid URI including an email address
    #[serde(rename = "logUri")]
    log_uri: String,
    // number of times the consent has been used
    #[serde(rename = "count")]
    count: u64,
    // most recent timestamp when the consent was used
    #[serde(
        rename = "lastUseDateTime",
        deserialize_with = "UtcTs::deserialize_from_str"
    )]
    last_use_timestamp: UtcTs,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Empty {}
impl Interface for Empty {
    fn path() -> &'static str {
        "Context::Empty"
    }
    fn txid_as_string(&self) -> String {
        "".to_owned()
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ErrResp<T> {
    #[serde(rename = "version")]
    ver: String,
    #[serde(rename = "txnid", skip_serializing_if = "Option::is_none")]
    tx_id: Option<String>,
    #[serde(rename = "timestamp")]
    ts: String,
    #[serde(rename = "uts")]
    uts: i64,
    // error code pertaining to the invalid request
    #[serde(rename = "errorCode")]
    err_code: String,
    // error message with additional details.
    // NOTE: Ensure no sensitive information is included in the error message.
    #[serde(rename = "errorMsg")]
    err_msg: String,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    custom: Option<T>,
    #[serde(rename = "http_status_code")]
    hsc: u16,
}

impl<T> ErrResp<T>
where
    T: Default + serde::Serialize,
{
    pub fn v2(
        tx_id: &Option<TxId>,
        t: &UtcTs,
        ec: &ErrorCode,
        em: &str,
        hsc: u16,
        cx: Option<T>,
    ) -> Self {
        ErrResp {
            ver: "2.0.0".to_string(),
            tx_id: if tx_id.as_ref().is_some_and(|t| t.val.len() > 0) {
                Some(tx_id.as_ref().unwrap().val.clone())
            } else {
                None
            },
            ts: t.to_string(),
            uts: t.ts,
            err_code: ec.to_string(),
            err_msg: em.to_string(),
            custom: cx,
            hsc: if hsc >= 200 && hsc < 500 {
                hsc as u16
            } else {
                ec.to_http_status_code() as u16
            },
        }
    }
}

impl<T> InterfaceResponse for ErrResp<T>
where
    T: Default + serde::Serialize,
{
    fn json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    fn code(&self) -> u32 {
        self.hsc as u32
    }
}

#[cfg(test)]
mod types {
    use super::Base64EncUuidErr;
    use super::SessionId;

    #[test]
    fn good_base64_uuid_decode_01() {
        let enc_uuid = SessionId::decode("za7VbYcSQU2zRgGQXQAm/g");
        assert!(enc_uuid.is_ok());
        let (_, uuid) = enc_uuid.unwrap();
        assert_eq!(uuid, "cdaed56d-8712-414d-b346-01905d0026fe");
    }
    #[test]
    fn good_base64_uuid_from_uuidv4_str_01() {
        let res = SessionId::from_uuid_v4("d8f9b1d6-c513-4587-8337-38c5dd6ae009");
        assert!(res.is_ok());
        let uuid_enc = res.unwrap();
        assert_eq!(uuid_enc.es.len(), 22);
    }
    #[test]

    fn good_base64_uuid_from_uuidv4_str_02() {
        let res = SessionId::from_uuid_v4("cdaed56d-8712-414d-b346-01905d0026fe");
        assert!(res.is_ok());
        let uuid_enc = res.unwrap();
        assert_eq!(uuid_enc.es, "za7VbYcSQU2zRgGQXQAm/g");
    }
    #[test]
    fn good_base64_uuid_from_uuidv4_str_03() {
        let res = SessionId::from_uuid_v4("6fcb514b-b878-4c9d-95b7-8dc3a7ce6fd8");
        assert!(res.is_ok());
        let uuid_enc = res.unwrap();
        assert_eq!(uuid_enc.es, "b8tRS7h4TJ2Vt43Dp85v2A");
    }
    #[test]
    fn good_base64_uuid_decode_03() {
        let enc_uuid = SessionId::decode("b8tRS7h4TJ2Vt43Dp85v2A");
        assert!(enc_uuid.is_ok());
        let (_, uuid) = enc_uuid.unwrap();
        assert_eq!(uuid, "6fcb514b-b878-4c9d-95b7-8dc3a7ce6fd8");
    }
    #[test]
    fn fail_base64_uuid_decode_bad_bytes() {
        let enc_uuid = SessionId::decode("za7VbYcSQU2zRgGQXQAm");
        assert!(enc_uuid.is_err());
        assert_eq!(enc_uuid, Err(Base64EncUuidErr::BadByteArray));
    }
    #[test]
    fn fail_base64_uuid_decode_bad_base64() {
        let enc_uuid = SessionId::decode("za7VbYcSQU2zRgGQXQAm/s");
        assert!(enc_uuid.is_err());
        assert_eq!(enc_uuid, Err(Base64EncUuidErr::BadBase64));
    }
    #[test]
    fn fail_base64_uuid_from_uuidv5_str() {
        let res = SessionId::from_uuid_v4("74738ff5-5367-5958-9aee-98fffdcd1876");
        assert!(res.is_err());
        assert_eq!(res, Err(Base64EncUuidErr::ExpectedVersionV4))
    }
    #[test]
    fn fail_base64_uuid_from_uuidv3_str() {
        let res = SessionId::from_uuid_v4("faf9b6a6-b660-3457-83aa-a8873179edfd");
        assert!(res.is_err());
        assert_eq!(res, Err(Base64EncUuidErr::ExpectedVersionV4))
    }
}
