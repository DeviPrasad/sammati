#![allow(dead_code)]

// https://api.rebit.org.in/viewSpec/FIP_2_0_0.yaml
use crate::ts::{TimePeriod, UtcTs};
use crate::types::{
    AccOwnerConsentProof, Base64EncUuid, ConsentId, ConsentUse, FIPAccDesc, FIPAccLinkRef,
    FIPAccLinkReqRefNum, FIPAccLinkToken, FIPAccLinkingAuthType, FIPAccOwner,
    FIPAccOwnerAccDescriptors, FIPAccOwnerConsentStatus, FIPAccOwnerLinkedAccRef,
    FIPAccOwnerLinkedAccStatus, FIPId, FIPVerifiedLinkedAccStatus, FIType, FinInfo, Interface,
    InterfaceResponse, KeyMaterial, Notifier, TxId, UserConsentStatus,
};
use bytes::Bytes;
use serde::{Deserialize, Serialize};

// API managed by FIP
trait AccDiscoveryFlow {
    // This API enables an AA to discover accounts belonging to a customer based on the customer identifiers.
    // A list of masked account information and corresponding linkRefNumber for each discovered account
    // is returned based on the identifier matching logic at FIP.
    // POST .../Accounts/discover
    fn discover_account();
}

// API managed by FIP
trait AccLinkingFlow {
    // This initiates an account link request to link selected account/s with the AA customer address.
    // POST .../Accounts/link
    // async request and response FIP --POST--> <AA> .../Account/link/Notification
    //     FIP sends account linking status to AA when direct-authentication method is used for account linking.
    fn link_account();
    // This is used to delete a previously established account link to the user's profile.
    // Once deleted, the financial information can not be retrieved for that account through Account Aggregator.
    // POST .../Accounts/delink
    // synchronous request and response.
    fn delink_account();
    // This is used to submit the token/OTP received from the account holder back to FIP so that
    // account linking can be completed. It is used only in case of token-based authentication for linking accounts.
    // POST .../Accounts/link/verify
    fn verify_account();
}

// API managed by FIP
trait DataFlow {
    // This API is used by the AA to request for financial information from the FIP.
    // The FIP will validate the request against the signed consent and
    // return a session id which can then be used by the AA to fetch the required data.
    // POST .../FI/request
    fn request_fi();
    // This API is used to fetch financial information from FIP once AA recieves the data ready notification.
    // POST ../FI/fetch
    fn fetch_fi();
}

// API managed by FIP
trait ConsentFlow {
    // This API will be used by the AA to send the consent artefact to the FIP on creation.
    // POST .../Consent
    fn create_consent_artefact();
    // This API is intended to be used by AA to notify the change in consent status due to
    // the consent management operations performed by the customer.
    // POST ../Consent/Notification
    fn update_consent_status();
}
// APIs to check the availability of FIP service.
trait Monitor {
    // GET .../Heartbeat
    fn heartbeat();
}

// Information of the resource-owner (RO, aka customer) for discovering account(s) at the FIP.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccDiscoveryReq {
    // (required) API version = "2.0.0"
    #[serde(rename = "ver")]
    pub ver: String,
    // (required) creation timestamp of the message.
    #[serde(rename = "timestamp", deserialize_with = "UtcTs::deserialize_from_str")]
    pub timestamp: UtcTs,
    // unique transaction identifier used for providing end-to-end traceability.
    #[serde(rename = "txnid", deserialize_with = "TxId::deserialize_from_str")]
    pub tx_id: TxId,
    // customer/RO identifiers & the customer address at the AA.
    #[serde(rename = "Customer")]
    pub customer: FIPAccOwner,
    // list of financial information types.
    #[serde(rename = "FITypes")]
    pub fi_types: Vec<FIType>,
}

#[derive(Clone, Debug, Serialize)]
pub struct AccDiscoveryResp {
    // (required) API version = "2.0.0"
    #[serde(rename = "ver")]
    pub ver: String,
    // (required) creation timestamp of the message.
    #[serde(rename = "timestamp", flatten)]
    pub timestamp: UtcTs,
    #[serde(rename = "uts")]
    pub uts: i64,
    // unique transaction identifier used for providing end-to-end traceability.
    #[serde(rename = "txnid", flatten)]
    pub tx_id: TxId,
    // A list of discovered accounts.
    #[serde(rename = "DiscoveredAccounts")]
    pub accounts: Vec<FIPAccDesc>,
}

impl AccDiscoveryResp {
    pub fn new(adr: &AccDiscoveryReq, accounts: &Vec<FIPAccDesc>) -> Self {
        Self::v2(&adr.tx_id, &accounts)
    }
    pub fn v2(tx_id: &TxId, accounts: &Vec<FIPAccDesc>) -> Self {
        let t: UtcTs = UtcTs::now();
        AccDiscoveryResp {
            ver: "2.0.0".to_string(),
            uts: t.ts,
            timestamp: t,
            tx_id: tx_id.clone(),
            accounts: accounts.clone(),
        }
    }
}

impl Interface for AccDiscoveryReq {
    fn path() -> &'static str {
        "Accounts/discover"
    }
    fn tx_id(&self) -> String {
        self.tx_id.to_string()
    }
}

impl InterfaceResponse for AccDiscoveryResp {
    fn code(&self) -> u32 {
        200 as u32
    }
    fn json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccLinkReq {
    // (required) API version = "2.0.0"
    #[serde(rename = "ver")]
    pub ver: String,
    // (required) creation timestamp of the message.
    #[serde(rename = "timestamp", deserialize_with = "UtcTs::deserialize_from_str")]
    pub timestamp: UtcTs,
    // unique transaction identifier used for providing end-to-end traceability.
    #[serde(rename = "txnid", deserialize_with = "TxId::deserialize_from_str")]
    pub tx_id: TxId,
    // customer identifiers including AA id (virtual id/address).
    #[serde(rename = "Customer")]
    pub customer_accounts: FIPAccOwnerAccDescriptors,
}

impl Interface for AccLinkReq {
    fn path() -> &'static str {
        "Accounts/link"
    }
    fn tx_id(&self) -> String {
        self.tx_id.to_string()
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct AccLinkResp {
    // (required) API version = "2.0.0"
    #[serde(rename = "ver")]
    pub ver: String,
    // (required) creation timestamp of the message.
    pub timestamp: UtcTs,
    #[serde(rename = "uts")]
    pub uts: i64,
    // unique transaction identifier used for providing end-to-end traceability.
    pub tx_id: TxId,
    // the type of authenticator used by FIP - interactive (direct) authentication or Token-based authentication.
    authenticator_type: FIPAccLinkingAuthType,
    // Temporary reference number generated by FIP for account linking request.
    // FIP eventually notifies AA about the actual result of this request by a POST /Account/link/Notification message.
    ref_num: FIPAccLinkReqRefNum,
}

impl InterfaceResponse for AccLinkResp {
    fn code(&self) -> u32 {
        200 as u32
    }
    fn json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

impl AccLinkResp {
    pub fn new(
        adr: &AccLinkReq,
        at: &FIPAccLinkingAuthType,
        acc_ref_num: &FIPAccLinkReqRefNum,
    ) -> Self {
        Self::v2(&adr.tx_id, &at, acc_ref_num)
    }
    pub fn v2(tx_id: &TxId, at: &FIPAccLinkingAuthType, acc_ref_num: &FIPAccLinkReqRefNum) -> Self {
        let t: UtcTs = UtcTs::now();
        AccLinkResp {
            ver: "2.0.0".to_string(),
            uts: t.ts,
            timestamp: t,
            tx_id: tx_id.clone(),
            authenticator_type: at.clone(),
            ref_num: acc_ref_num.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct AccDelinkReq {
    // (required) API version = "2.0.0"
    pub ver: String,
    // (required) creation timestamp of the message.
    pub timestamp: UtcTs,
    // unique transaction identifier used for providing end-to-end traceability.
    pub tx_id: TxId,
    // account holder's AA-identifier, and the linked account's referece number at FIP.
    pub account: FIPAccOwnerLinkedAccRef,
}

#[derive(Clone, Debug, Serialize)]
pub struct AccDelinkResp {
    // (required) API version = "2.0.0"
    pub ver: String,
    // (required) creation timestamp of the message.
    pub timestamp: UtcTs,
    // unique transaction identifier used for providing end-to-end traceability.
    pub tx_id: TxId,
    // account holder's AA-identifier, linked account's referece number at FIP, and its current status.
    pub acc_link_details: FIPAccOwnerLinkedAccStatus,
}

// A request for linking account with a link reference number for future identification.
// The call originates from AA client or FIU.
// FIP doc calls this 'LinkDelinkTokenRequest'.
#[derive(Clone, Debug, Serialize)]
pub struct AccMgmtTokenSubmitReq {
    // (required) API version = "2.0.0"
    pub ver: String,
    // (required) creation timestamp of the message.
    pub timestamp: UtcTs,
    // unique transaction identifier used for providing end-to-end traceability.
    pub tx_id: TxId,
    // account holder's AA-identifier, linked account's reference number at FIP, and its current status.
    pub ref_num: FIPAccLinkReqRefNum,
    // the token which FIP sent to the account holder.
    pub token: FIPAccLinkToken,
}

// FIP doc calls this 'LinkDelinkTokenResponse'.
#[derive(Clone, Debug, Serialize)]
pub struct AccMgmtTokenSubmitResp {
    // (required) API version = "2.0.0"
    pub ver: String,
    // (required) creation timestamp of the message.
    pub timestamp: UtcTs,
    // unique transaction identifier used for providing end-to-end traceability.
    pub tx_id: TxId,
    pub linked_accounts: Vec<FIPVerifiedLinkedAccStatus>,
}

// AA requests financial information from FIP.
// FIP validates the request using the signed consent and
// returns a session id which can then be used by AA to fetch required FI.
#[derive(Clone, Debug, Serialize)]
pub struct FIRequest {
    // (required) API version = "2.0.0"
    pub ver: String,
    // (required) creation timestamp of the message.
    pub timestamp: UtcTs,
    // unique transaction identifier used for providing end-to-end traceability.
    pub tx_id: TxId,
    // consent artefact details.
    pub consent_proof: AccOwnerConsentProof,
    // the date-time range for which the financial information is requested
    pub fi_data_range: TimePeriod,
    // cryptographic parameters required to perform end-to-end encryption.
    pub key_material: KeyMaterial,
}
#[derive(Clone, Debug, Serialize)]
pub struct FIResp {
    // (required) API version = "2.0.0"
    pub ver: String,
    // (required) creation timestamp of the message.
    pub timestamp: UtcTs,
    // unique transaction identifier used for providing end-to-end traceability.
    pub tx_id: TxId,
    // unique id generated by AA after the account holder authorizes the consent request.
    // this must match the value AA supplies (to FIP) in its previous/linked FIRequest.
    pub consent_id: Bytes,
    // A session is is a base-64 encoded UUID number.
    // A session is generally valid for the time period indicated in the FIRequest.
    // Consent revocation may terminate the session, however.
    // FIP allocates a fresh session id for each FI request.
    // AA includes this session id in subsequent data requests to FIP.
    pub session_id: Base64EncUuid,
}

// API to fetch financial information from FIP once AA receives the data ready notification.
// request to fetch FI data from FIP with a session id.
#[derive(Clone, Debug, Serialize)]
pub struct FIFetchReq {
    // (required) API version = "2.0.0"
    pub ver: String,
    // (required) creation timestamp of the message
    pub timestamp: UtcTs,
    // unique transaction identifier used for providing end-to-end traceability.
    pub tx_id: TxId,
    // A session ID is a base64 encoded UUID number.
    // FIP gives out a fresh session id for each financial information access request from AA.
    pub session_id: Base64EncUuid,
    // FIP ID as defined in the Account Aggregator Ecosystem.
    // optional feild.
    pub fip_id: Option<FIPId>,
    // Unique reference number assigned by FIP as part of Account Linking Process.
    // optional feild.
    pub link_ref_num: Option<Vec<FIPAccLinkRef>>,
}

#[derive(Clone, Debug, Serialize)]
pub struct FIFetchResp {
    // (required) API version = "2.0.0"
    pub ver: String,
    // (required) creation timestamp of the message.
    pub timestamp: UtcTs,
    // unique transaction identifier used for providing end-to-end traceability.
    pub tx_id: TxId,
    // account-specific metadata and encrypted FI of the account
    pub fi: Vec<FinInfo>,
}

// Notification about the status of consent
#[derive(Clone, Debug, Serialize)]
struct FIPAccHolderConsentStatusNotification {
    // (required) API version = 2.0.0
    pub ver: String,
    // (required) creation timestamp of the message
    pub timestamp: UtcTs,
    // unique transaction identifier used for providing end-to-end traceability.
    pub txid: TxId,
    // (required)
    pub notifer: Notifier,
    // consent id and the consent status.
    // consent id is a unique is generated by AA after the account holder authorizes the request.
    pub consent: FIPAccOwnerConsentStatus,
}

// used by AA to send consent status update notifications to FIP.
// POST .../Consent/Notification
#[derive(Clone, Debug, Serialize)]
struct FIPAccHolderConsentNotificationResp {
    // (required) API version = 2.0.0
    pub ver: String,
    // (required) creation timestamp of the message
    pub timestamp: UtcTs,
    // unique transaction identifier used for providing end-to-end traceability.
    pub txid: TxId,
    // response description
    pub response: String,
}

// used by the AA to send the consent artefact to the FIP on creation
// POST .../Consent
//
#[derive(Clone, Debug, Deserialize)]
pub struct ConsentArtefactReq {
    // (required) API version = 2.1.0
    #[serde(rename = "ver")]
    pub ver: String,
    // timestamp of this message
    #[serde(rename = "timestamp", deserialize_with = "UtcTs::deserialize_from_str")]
    pub timestamp: UtcTs,
    // unique transaction identifier used for providing end-to-end traceability.
    #[serde(rename = "txnid", deserialize_with = "TxId::deserialize_from_str")]
    pub tx_id: TxId,
    // unique ID generated by AA after the account holder authorizes the request.
    #[serde(
        rename = "consentId",
        deserialize_with = "ConsentId::deserialize_from_str"
    )]
    pub consent_id: ConsentId,
    #[serde(rename = "status")]
    pub status: UserConsentStatus,
    // creation time of the Consent Artefact
    #[serde(
        rename = "createTimestamp",
        deserialize_with = "UtcTs::deserialize_from_str"
    )]
    pub creation_timestamp: UtcTs,
    // consent artefact signed using JWS. See SignedConsentDetail model for consent format.
    #[serde(rename = "signedConsent")]
    pub signed_consent_jws: Bytes,
    // parameters for consent tracking
    #[serde(rename = "ConsentUse")]
    pub consent_use: ConsentUse,
}

impl Interface for ConsentArtefactReq {
    fn path() -> &'static str {
        "Consent"
    }

    fn tx_id(&self) -> String {
        self.tx_id.to_string()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsentArtefactResp {
    // (required) API version = "2.0.0"
    #[serde(rename = "ver")]
    pub ver: String,
    // unique transaction identifier used for providing end-to-end traceability.
    #[serde(rename = "txnid", deserialize_with = "TxId::deserialize_from_str")]
    pub tx_id: TxId,
    // (required) creation timestamp of the message.
    #[serde(rename = "timestamp", deserialize_with = "UtcTs::deserialize_from_str")]
    pub timestamp: UtcTs,
    #[serde(rename = "uts")]
    pub uts: i64,
    #[serde(rename = "response")]
    pub resp: String,
}

impl ConsentArtefactResp {
    pub fn new(cr: &ConsentArtefactReq) -> Self {
        Self::v2(&cr.tx_id)
    }

    pub fn v2(tx_id: &TxId) -> Self {
        let t: UtcTs = UtcTs::now();
        ConsentArtefactResp {
            ver: "2.0.0".to_string(),
            uts: t.ts,
            timestamp: t.clone(),
            tx_id: tx_id.clone(),
            resp: "OK".to_owned(),
        }
    }
}

impl InterfaceResponse for ConsentArtefactResp {
    fn code(&self) -> u32 {
        200 as u32
    }
    fn json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

/* example ConsentArtefactReq
{
    "consentStart": "2019-05-28T11:38:20.380+0000",
    "consentExpiry": "2020-05-28T11:38:20.381+0000",
    "consentMode": "VIEW",
    "fetchType": "ONETIME",
    "consentTypes": [
        "PROFILE",
        "SUMMARY",
        "TRANSACTIONS"
    ],
    "fiTypes": [
        "DEPOSIT",
        "TERM-DEPOSIT"
    ],
    "DataConsumer": {
        "id": "cookiejar-aa@finvu.in",
        "type": "AA"
    },
    "DataProvider": {
        "id": "BARB0KIMXXX",
        "type": "FIP"
    },
    "Customer": {
        "id": "demo@finvu"
    },
    "Accounts": [
        {
            "fiType": "DEPOSIT",
            "fipId": "BARB0KIMXXX",
            "accType": "SAVINGS",
            "linkRefNumber": "UBI485964579",
            "maskedAccNumber": "UBI85217881279"
        },
        {
            "fiType": "DEPOSIT",
            "fipId": "BARB0KIMXXX",
            "accType": "SAVINGS",
            "linkRefNumber": "UBI4859645",
            "maskedAccNumber": "UBI852178812"
        }
    ],
    "Purpose": {
        "code": "101",
        "refUri": "https://api.rebit.org.in/aa/purpose/101.xml",
        "text": "Wealth management service",
        "Category": {
            "type": "purposeCategoryType"
        }
    },
    "FIDataRange": {
        "from": "2019-05-28T11:38:20.383+0000",
        "to": "2020-05-28T11:38:20.381+0000"
    },
    "DataLife": {
        "unit": "MONTH",
        "value": 4
    },
    "Frequency": {
        "unit": "HOUR",
        "value": 4
    },
    "DataFilter": [
        {
            "type": "TRANSACTIONAMOUNT",
            "operator": ">",
            "value": "20000"
        }
    ]
}
*/
