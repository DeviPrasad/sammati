#![allow(dead_code)]

use crate::ts::{ConsentUtc, UtcTs};
///
/// changelogs from 1.2.0
/// https://specifications.rebit.org.in/api_schema/account_aggregator/AA_ChangeLog_2_0_0.txt
/// https://specifications.rebit.org.in/api_schema/account_aggregator/FIP_ChangeLog_2_0_0.txt
/// https://specifications.rebit.org.in/api_schema/account_aggregator/FIU_ChangeLog_2_0_0.txt
///
/// API specs
/// https://specifications.rebit.org.in/api_specifications/account_aggregator/AA_2_0_0.yaml
/// https://specifications.rebit.org.in/api_specifications/account_aggregator/FIP_2_0_0.yaml
/// https://specifications.rebit.org.in/api_specifications/account_aggregator/FIU_2_0_0.yaml
///
use bytes::Bytes;
use data_encoding::BASE64_NOPAD;
use dull::hex;
use serde::de::Error;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::fmt::{Debug, Write as _};
use std::str::FromStr;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct ValidationError(pub hyper::StatusCode, pub ErrorCode, pub String);

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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum UserConsentStatus {
    ACTIVE,
    PAUSED,
    REVOKED,
    EXPIRED,
    PENDING,
    REJECTED,
}

impl ToString for UserConsentStatus {
    fn to_string(&self) -> String {
        String::from(match self {
            UserConsentStatus::ACTIVE => "ACTIVE",
            UserConsentStatus::PAUSED => "PAUSED",
            UserConsentStatus::REVOKED => "REVOKED",
            UserConsentStatus::EXPIRED => "EXPIRED",
            UserConsentStatus::PENDING => "PENDING",
            UserConsentStatus::REJECTED => "REJECTED",
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum UserConsentMode {
    View,
    Store,
    Query,
    Stream,
}

impl ToString for UserConsentMode {
    fn to_string(&self) -> String {
        String::from(match self {
            UserConsentMode::View => "VIEW",
            UserConsentMode::Store => "STORE",
            UserConsentMode::Query => "QUERY",
            UserConsentMode::Stream => "STREAM",
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FISessionStatus {
    Active,
    Completed,
    Expired,
    Failed,
}

impl ToString for FISessionStatus {
    fn to_string(&self) -> String {
        String::from(match self {
            FISessionStatus::Active => "ACTIVE",
            FISessionStatus::Completed => "COMPLETED",
            FISessionStatus::Expired => "EXPIRED",
            FISessionStatus::Failed => "FAILED",
        })
    }
}

/// fetch-status of Financial Information
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AccountFIStatus {
    Ready,
    Denied,
    Pending,
    Delivered,
    Timeout,
}

impl ToString for AccountFIStatus {
    fn to_string(&self) -> String {
        String::from(match self {
            AccountFIStatus::Ready => "READY",
            AccountFIStatus::Denied => "DENIED",
            AccountFIStatus::Pending => "PENDING",
            AccountFIStatus::Delivered => "DELIVERED",
            AccountFIStatus::Timeout => "TIMEOUT",
        })
    }
}

/// There are two kinds of authentications that the FIP may support
/// (1) Direct Authentication - FIP obtains confirmation directly interacting with the resource owner.
/// (2) Token-based Authentication - FIP issues a token, which is to be included in the subsequent interaction
///     between AA and FIP. The token may be directly issued to the resource owner/customer.
/// A token may be nonce, or a short-lived one-time password.
#[derive(Clone, Debug, Serialize)]
pub enum FIPAccLinkingAuthType {
    Direct,
    Token,
}

impl ToString for FIPAccLinkingAuthType {
    fn to_string(&self) -> String {
        String::from(match self {
            FIPAccLinkingAuthType::Direct => "DIRECT",
            FIPAccLinkingAuthType::Token => "TOKEN",
        })
    }
}

#[derive(Clone, Debug, Serialize)]
pub enum FIPAccLinkStatus {
    Linked,
    Delinked,
    Pending,
    Failed,
}

impl ToString for FIPAccLinkStatus {
    fn to_string(&self) -> String {
        String::from(match self {
            FIPAccLinkStatus::Linked => "LINKED",
            FIPAccLinkStatus::Delinked => "DELINKED",
            FIPAccLinkStatus::Pending => "PENDING",
            FIPAccLinkStatus::Failed => "FAILED",
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum EncryptAlg {
    ECDH,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Curve {
    Curve25519,
}

#[derive(Clone, Debug, Serialize)]
pub struct FIPAccLinkReqRefNum {
    val: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct FIPAccLinkToken {
    val: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FIType {
    #[serde(rename = "DEPOSIT")]
    Deposit,
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
    Equities,
    #[serde(rename = "BONDS")]
    Bonds,
    #[serde(rename = "DEBENTURES")]
    Debentures,
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
    Other,

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
        if s.is_ascii() {
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
        String::deserialize(deserializer).map(|id| TxId { val: id.to_owned() })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Base64EncUuid {
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

impl Base64EncUuid {
    pub fn new() -> Base64EncUuid {
        let rb: [u8; 16] = Uuid::new_v4().into_bytes();
        let es: String = BASE64_NOPAD.encode(&rb);
        Base64EncUuid { rb, es }
    }

    pub fn from_uuid_v4(s: &str) -> Result<Base64EncUuid, Base64EncUuidErr> {
        match Uuid::from_str(s) {
            Ok(uuid) => {
                return if uuid.get_version_num() == 4 {
                    Ok(Base64EncUuid {
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

/// (mandatory)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserConsent {
    /// Unique ID generated by AA after consent approval is given by the customer.
    pub id: Option<ConsentId>,
    /// Unique ID generated by AA after receiving the consent request.
    /// Consent Handle can be used by FIU/AA Client to check the consent status and
    /// also to retrieve the consent ID once consent is approved by the customer.
    pub handle: Option<ConsentHandle>,
    /// (required) status of consent artefact
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
    #[serde(rename = "accRefNumber")]
    acc_ref_num: FIPAccLinkRef,
    #[serde(rename = "maskedAccNumber")]
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
    val: String,
}

impl FIPAccLinkRef {
    pub fn deser_from_str<'de, D>(d: D) -> Result<FIPAccLinkRef, D::Error>
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
    pub fn deser_from_str<'de, D>(d: D) -> Result<FIPMaskedAccNum, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(d).map(|id| FIPMaskedAccNum { val: id.to_owned() })
    }
}

/// Unique FIP account reference number which is linked with the masked account number.
#[derive(Clone, Debug, Serialize)]
pub struct FIPMaskedAccRefNum {
    val: String,
}

impl FIPMaskedAccRefNum {
    pub fn deser_from_str<'de, D>(d: D) -> Result<FIPMaskedAccRefNum, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(d).map(|id| FIPMaskedAccRefNum { val: id.to_owned() })
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct SessionCipherParam {
    val: String, // ex: cipher=AES/GCM/NoPadding;KeyPairGenerator=ECDH"
}

impl SessionCipherParam {
    pub fn deser_from_str<'de, D>(d: D) -> Result<SessionCipherParam, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(d).map(|id| SessionCipherParam { val: id.to_owned() })
    }
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
#[derive(Clone, Debug, Serialize)]
pub struct DHPublicKey {
    // expiration of the public key.
    expiry: UtcTs,
    // defines public parameters used to calculate session key (for data encryption and decryption).
    // ex: cipher=AES/GCM/NoPadding;KeyPairGenerator=ECDH"
    params: Option<SessionCipherParam>,
    // the value of ephemeral public key
    pub val_ephemeral_pub_key: Bytes,
}

// cryptographic parameters for end-to-end data encryption.
#[derive(Clone, Debug, Serialize)]
pub struct KeyMaterial {
    // Currently, only ECDH is supported.
    pub crypto_alg: EncryptAlg,
    pub curve: Curve,
    // specifies the secure standard cryptographic primitives to perform end to end encryption.
    // Use key-value pair separated by a semicolon.
    // ex: cipher=AES/GCM/NoPadding;KeyPairGenerator=ECDH - symmetric encryption(AES-256 bits, GCM-128 bits and No Padding) and key exchange protocol(ECDH).
    pub params: Option<String>,
    pub dh_pub_key: DHPublicKey,
    // ref: https://tools.ietf.org/html/rfc5116 - An Interface and Algorithms for Authenticated Encryption. January 2008.
    pub nonce: Bytes,
}

#[derive(Clone, Debug, Serialize)]
pub struct AccOwnerConsentProof {
    /// unique id generated by AA after the account holder authorizes the consent request.
    consent_id: Bytes,
    /// signature part of the consent JWS.
    /// The receiver has to verify if the given signature matches the signature in the original consent JWS.
    signature: Bytes,
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
/// Set of Identifiers required for discovering the accounts of a customer at the FIP.
/// It is mandatory to provide at the least one STRONG category identifier.
/// FIPs must employ KYC to ensure identitifiers are verified and authenticated.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FIPAccOwnerIdentifier {
    // category of identifiers based on the ability to perform online authenticity
    #[serde(rename = "category")]
    pub id_category: AccOwnerIdCategory,
    /// type of identifier
    #[serde(rename = "type")]
    pub id_type: AccOwnerIdType,
    /// value/number of the selected identifier
    #[serde(
        rename = "value",
        deserialize_with = "AccOwnerId::deserialize_from_str"
    )]
    pub id_val: AccOwnerId,
}

#[derive(Clone, Debug, Serialize)]
pub struct FIPAccOwnerAAId {
    val: String,
}

impl FIPAccOwnerAAId {
    pub fn deserialize_from_str<'de, D>(deserializer: D) -> Result<FIPAccOwnerAAId, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer).map(|id| FIPAccOwnerAAId { val: id.to_owned() })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FIPAccOwner {
    /// example: alice@sammati_aa_id
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
    /// example: bob@sammati_aa_id
    #[serde(
        rename = "id",
        deserialize_with = "FIPAccOwnerAAId::deserialize_from_str"
    )]
    pub ao_aa_id: FIPAccOwnerAAId,
    /// list of customer's accounts to be linked
    pub accounts: Vec<FIPAccDesc>,
}

#[derive(Clone, Debug, Serialize)]
pub struct FIPAccOwnerLinkedAccRef {
    // Identifier of the customer generated during the registration with AA.
    /// example: alice@sammati_aa_id.
    pub ao_aa_id: FIPAccOwnerAAId,
    /// An account's ref num at FIP - used in the delink_account request.
    /// Reference number assigned by FIP in the account linking flow.
    pub link_ref_num: FIPAccLinkRef,
}

#[derive(Clone, Debug, Serialize)]
pub struct FIPAccOwnerLinkedAccStatus {
    // Identifier of the customer generated during the registration with AA.
    /// example: alice@sammati_aa_id.
    pub ro_aa_id: FIPAccOwnerAAId,
    /// An account's ref num at FIP - used in the delink_account request.
    /// Reference number assigned by FIP in the account linking flow.
    pub link_ref_num: FIPAccLinkRef,
    /// tells if the account is still linked.
    pub status: FIPAccLinkStatus,
}

#[derive(Clone, Debug, Serialize)]
pub struct FIPVerifiedLinkedAccStatus {
    // Identifier of the customer generated during the registration with AA.
    /// example: alice@sammati_aa_id.
    pub ro_aa_id: FIPAccOwnerAAId,
    /// An account's ref num at FIP - used in the delink_account request.
    /// Reference number assigned by FIP in the account linking flow.
    pub link_ref_num: FIPAccLinkRef,
    /// Unique FIP account reference number which is linked with the masked account number.
    pub acc_ref_num: FIPMaskedAccRefNum,
    /// tells if the account is still linked.
    pub status: FIPAccLinkStatus,
}

#[derive(Clone, Debug, Serialize)]
pub struct Notifier {
    /// (required) type of the notifier entity; example: AA
    pub typ: String,
    /// (required) unique ID to identify this entity acting as the notifier.
    pub id: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct FinAccount {
    /// reference number assigned by FIP as part of the account linking process
    pub link_ref_num: String,
    /// fetch status of the Financial Information.
    pub fi_status: AccountFIStatus,
    pub desc: String,
}

/// (mandatory)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FIPAccOwnerConsentStatus {
    /// Unique ID generated by AA after consent approval is given by the account holder.
    pub id: Option<ConsentId>,
    /// (required) status of consent artefact
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

#[derive(Clone, Debug, Serialize)]
pub struct ErrResp<T> {
    #[serde(rename = "version")]
    ver: String,
    #[serde(rename = "txnid")]
    tx_id: String,
    #[serde(rename = "timestamp")]
    ts: String,
    #[serde(rename = "uts")]
    uts: i64,
    /// error code pertaining to the invalid request
    #[serde(rename = "errorCode")]
    err_code: String,
    /// error message with additional details.
    /// NOTE: Ensure no sensitive information is included in the error message.
    #[serde(rename = "errorMsg")]
    err_msg: String,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    custom: Option<T>,
}

impl<T> ErrResp<T>
where
    T: Default,
{
    pub fn v2(tx_id: Option<TxId>, t: &UtcTs, ec: ErrorCode, em: &str, cx: Option<T>) -> Self {
        ErrResp {
            ver: "2.0.0".to_string(),
            tx_id: match tx_id {
                Some(t) => t.to_string(),
                None => "".to_string(),
            },
            ts: t.to_string(),
            uts: t.ts,
            err_code: ec.to_string(),
            err_msg: em.to_string(),
            custom: cx,
        }
    }
}

#[cfg(test)]
mod types {
    use super::Base64EncUuid;
    use super::Base64EncUuidErr;

    #[test]
    fn good_base64_uuid_decode_01() {
        let enc_uuid = Base64EncUuid::decode("za7VbYcSQU2zRgGQXQAm/g");
        assert!(enc_uuid.is_ok());
        let (_, uuid) = enc_uuid.unwrap();
        assert_eq!(uuid, "cdaed56d-8712-414d-b346-01905d0026fe");
    }
    #[test]
    fn good_base64_uuid_from_uuidv4_str_01() {
        let res = Base64EncUuid::from_uuid_v4("d8f9b1d6-c513-4587-8337-38c5dd6ae009");
        assert!(res.is_ok());
        let uuid_enc = res.unwrap();
        assert_eq!(uuid_enc.es.len(), 22);
    }
    #[test]

    fn good_base64_uuid_from_uuidv4_str_02() {
        let res = Base64EncUuid::from_uuid_v4("cdaed56d-8712-414d-b346-01905d0026fe");
        assert!(res.is_ok());
        let uuid_enc = res.unwrap();
        assert_eq!(uuid_enc.es, "za7VbYcSQU2zRgGQXQAm/g");
    }
    #[test]
    fn good_base64_uuid_from_uuidv4_str_03() {
        let res = Base64EncUuid::from_uuid_v4("6fcb514b-b878-4c9d-95b7-8dc3a7ce6fd8");
        assert!(res.is_ok());
        let uuid_enc = res.unwrap();
        assert_eq!(uuid_enc.es, "b8tRS7h4TJ2Vt43Dp85v2A");
    }
    #[test]
    fn good_base64_uuid_decode_03() {
        let enc_uuid = Base64EncUuid::decode("b8tRS7h4TJ2Vt43Dp85v2A");
        assert!(enc_uuid.is_ok());
        let (_, uuid) = enc_uuid.unwrap();
        assert_eq!(uuid, "6fcb514b-b878-4c9d-95b7-8dc3a7ce6fd8");
    }
    #[test]
    fn fail_base64_uuid_decode_bad_bytes() {
        let enc_uuid = Base64EncUuid::decode("za7VbYcSQU2zRgGQXQAm");
        assert!(enc_uuid.is_err());
        assert_eq!(enc_uuid, Err(Base64EncUuidErr::BadByteArray));
    }
    #[test]
    fn fail_base64_uuid_decode_bad_base64() {
        let enc_uuid = Base64EncUuid::decode("za7VbYcSQU2zRgGQXQAm/s");
        assert!(enc_uuid.is_err());
        assert_eq!(enc_uuid, Err(Base64EncUuidErr::BadBase64));
    }
    #[test]
    fn fail_base64_uuid_from_uuidv5_str() {
        let res = Base64EncUuid::from_uuid_v4("74738ff5-5367-5958-9aee-98fffdcd1876");
        assert!(res.is_err());
        assert_eq!(res, Err(Base64EncUuidErr::ExpectedVersionV4))
    }
    #[test]
    fn fail_base64_uuid_from_uuidv3_str() {
        let res = Base64EncUuid::from_uuid_v4("faf9b6a6-b660-3457-83aa-a8873179edfd");
        assert!(res.is_err());
        assert_eq!(res, Err(Base64EncUuidErr::ExpectedVersionV4))
    }
}
