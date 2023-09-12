#![allow(dead_code)]
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
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::fmt::Write as _;
use std::str::FromStr;
use uuid::Uuid;

use crate::ets::Timestamp;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UserConsentStatus {
    Active,
    Paused,
    Revoked,
    Expired,
    Pending,
    Rejected,
}

impl ToString for UserConsentStatus {
    fn to_string(&self) -> String {
        String::from(match self {
            UserConsentStatus::Active => "ACTIVE",
            UserConsentStatus::Pending => "PENDING",
            UserConsentStatus::Revoked => "REVOKED",
            UserConsentStatus::Paused => "PAUSED",
            UserConsentStatus::Rejected => "REJECTED",
            UserConsentStatus::Expired => "EXPIRED",
        })
    }
}

#[derive(Clone, Debug, Serialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize)]
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

#[derive(Debug, Clone, Serialize)]
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

#[derive(Debug, Clone, Serialize)]
pub struct FIPAccLinkReqRefNum {
    val: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FIPAccLinkToken {
    val: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FIType {
    Deposit,
    TermDeposit,
    RecurringDeposit,
    SIP,
    CP,
    GovtSecurities,
    Equities,
    Bonds,
    Debentures,
    MutualFunds,
    ETF,
    IDR,
    CIS,
    AIF,
    InsurancePolicies,
    NPS,
    INVIT,
    REIT,
    GSTR1_3B,
    // sammati
    HomeLoan,
    GoldLoan,
    VehicleLoan,
    LAFixedDeposit,
    LAInsurancePolicies,
    LAMF, // loan against mutual funds
    LAShares,
    LAProperty,
    LAPF,
    LAEPF,
    PersonalLoan, // demand promissory notes (DPN loans), mostly NBFCs
    CreditCardLoan,
    EducationLoan,
    BusinessLoan, // repayable in 36 months
    Other,
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FinAccType {
    Savings,
    Current,
    Default,
    NRE,
    NRO,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxId {
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
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Base64EncUuid {
    pub rb: [u8; 16],
    pub es: String,
}

pub type UuidRep = ([u8; 16], String);

#[derive(Debug, Clone, PartialEq)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentHandle {
    pub val: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentId {
    pub val: String,
}

/// (mandatory)
#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone)]
pub enum AccOwnerIdCategory {
    Strong,
    Weak,
    Ancillary,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FIPId {
    val: String,
}

// discovered account information.
// also used in FIP::AccLinkRequest accounts to be linked.
// best viewed as a virualized account descriptor representing a real/concrete FIP account.
#[derive(Clone, Debug, Serialize)]
pub struct FIPAccDesc {
    /// type of financial information
    fi_type: FIType,
    // account Type or Sub FI Type
    acc_type: FinAccType,
    // unique FIP account reference number linked with the masked account number.
    acc_ref_num: FIPAccLinkRef,
    masked_acc_num: FIPMaskedAccNum,
}

// Unique FIP Account Reference Number which will be usually linked with a masked account number.
#[derive(Clone, Debug, Serialize)]
pub struct FIPAccLinkRef {
    val: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct FIPMaskedAccNum {
    val: String,
}

/// Unique FIP account reference number which is linked with the masked account number.
#[derive(Clone, Debug, Serialize)]
pub struct FIPMaskedAccRefNum {
    val: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct SessionCipherParam {
    val: String, // ex: cipher=AES/GCM/NoPadding;KeyPairGenerator=ECDH"
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
    expiry: crate::ets::Timestamp,
    // defines public parameters used to calculate session key (for data encryption and decryption).
    // ex: cipher=AES/GCM/NoPadding;KeyPairGenerator=ECDH"
    params: Option<SessionCipherParam>,
    // the value of emphemeral public key
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
pub struct AccHolderConsentProof {
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

#[derive(Debug, Clone)]
pub enum AccOwnerIdType {
    Mobile,
    Aadhar,
    Email,
    PAN,
    DOB,
    AccNum, // ACCNO
    CRN,
    PPAN,
    Others,
}

/// Set of Identifiers required for discovering the accounts of a customer at the FIP.
/// It is mandatory to provide at the least one STRONG category identifier.
/// FIPs must employ KYC to ensure identitifers are verified and authenticated.
#[derive(Debug, Clone)]
pub struct FIPAccHolderIdentifer {
    // category of identifiers based on the ability to perform online authenticity
    pub id_category: AccOwnerIdCategory,
    /// type of identifier
    pub id_type: AccOwnerIdType,
    /// value/number of the selected identifer
    pub id_val: Bytes,
}

#[derive(Debug, Clone)]
pub struct FIPAccHolderAAId {
    id: String,
}
#[derive(Debug, Clone)]
pub struct FIPAccHolder {
    /// example: alice@sammati_aa_id
    ro_aa_id: FIPAccHolderAAId,
    identifiers: Vec<FIPAccHolderIdentifer>,
}

#[derive(Debug, Clone)]
pub struct FIPAccHolderAccDescriptors {
    /// example: alice@sammati_aa_id
    pub ro_aa_id: FIPAccHolderAAId,
    /// list of customer's accounts to be linked
    ///
    pub accounts: Vec<FIPAccDesc>,
}

#[derive(Debug, Clone)]
pub struct FIPAccHolderLinkedAccRef {
    // Identifier of the customer generated during the registration with AA.
    /// example: alice@sammati_aa_id.
    pub ro_aa_id: FIPAccHolderAAId,
    /// An account's ref num at FIP - used in the delink_account request.
    /// Reference number assigned by FIP in the account linking flow.
    pub link_ref_num: FIPAccLinkRef,
}

#[derive(Debug, Clone)]
pub struct FIPAccHolderLinkedAccStatus {
    // Identifier of the customer generated during the registration with AA.
    /// example: alice@sammati_aa_id.
    pub ro_aa_id: FIPAccHolderAAId,
    /// An account's ref num at FIP - used in the delink_account request.
    /// Reference number assigned by FIP in the account linking flow.
    pub link_ref_num: FIPAccLinkRef,
    /// tells if the account is still linked.
    pub status: FIPAccLinkStatus,
}

#[derive(Debug, Clone)]
pub struct FIPVerifiedLinkedAccStatus {
    // Identifier of the customer generated during the registration with AA.
    /// example: alice@sammati_aa_id.
    pub ro_aa_id: FIPAccHolderAAId,
    /// An account's ref num at FIP - used in the delink_account request.
    /// Reference number assigned by FIP in the account linking flow.
    pub link_ref_num: FIPAccLinkRef,
    /// Unique FIP account reference number which is linked with the masked account number.
    pub acc_ref_num: FIPMaskedAccRefNum,
    /// tells if the account is still linked.
    pub status: FIPAccLinkStatus,
}

#[derive(Debug, Clone)]
pub struct Notifier {
    /// (required) type of the notifier entity; example: AA
    pub typ: String,
    /// (required) unique ID to identify this entity acting as the notifier.
    pub id: String,
}

#[derive(Debug, Clone)]
pub struct FinAccount {
    /// reference number assigned by FIP as part of the account linking process
    pub link_refnum: String,
    /// fetch status of the Financial Information.
    pub fi_status: AccountFIStatus,
    pub desc: String,
}

/// (mandatory)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FIPAccHolderConsentStatus {
    /// Unique ID generated by AA after consent approval is given by the account holder.
    pub id: Option<ConsentId>,
    /// (required) status of consent artefact
    pub status: UserConsentStatus,
}

#[derive(Debug, Clone, Serialize)]
pub struct SignedConsentDetail {
    pub consent_start: Timestamp,
    pub consent_exp: Timestamp,
    pub consent_mode: UserConsentMode,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConsentUse {}

#[cfg(test)]
mod tests {
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
