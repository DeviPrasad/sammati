#![allow(dead_code)]

use crate::ts::UtcTs;
use crate::types::{Base64EncUuid, FIPAccLinkRef, FIPId, FinInfo, TxId};
use serde::Serialize;

/// API managed by AA
/// https://api.rebit.org.in/viewSpec/AA_2_0_0.yaml
/// used by FIU once it recieves the data ready notification. FIU asks AA to fetch FI.
#[derive(Clone, Debug, Serialize)]
pub struct FIFetchRequest {
    /// API version = "2.0.0"
    pub ver: String,
    /// creation timestamp of the message
    pub timestamp: UtcTs,
    /// unique transaction identifier used for providing end-to-end traceability.
    pub tx_id: TxId,
    /// A session ID is a base64 encoded UUID number.
    /// AA creates a fresh session_id value for each FI access request made by FIU or AA Client.
    pub session_id: Base64EncUuid,
    // FIP ID as defined in the Account Aggregator Ecosystem.
    pub fip_id: Option<FIPId>,
    // Unique reference number assigned by FIP as part of Account Linking Process.
    pub link_ref_num: Option<Vec<FIPAccLinkRef>>,
}

#[derive(Clone, Debug, Serialize)]
pub struct FiFetchResponse {
    /// API version = "2.0.0"
    pub ver: String,
    /// creation timestamp of the message
    pub timestamp: UtcTs,
    /// unique transaction identifier used for providing end-to-end traceability.
    pub tx_id: TxId,
    // Account-specific metadata with corresponding encrypted data for accessing the finanical information
    pub fi: Vec<FinInfo>,
}
// API managed by AA
trait ConsentFlow {
    /// This API is intended for AA Client to request generation of digitally signed consent artefacts.
    /// The customer has to use the AA application to select accounts and approve consent generation.
    /// Once the customer approves the consent request on the AA application,
    /// AA generates the digitally signed consent artefacts.
    /// Note - The AA Client never sees the account of the customer or directly participates in consent generation.
    /// POST .../Consent
    fn create_consent_artefact();
    /// This API is intended to be used by FIU/AA Client to check the consent status and
    /// retrieve the consent ID from AA once the consent is approved by customer.
    /// POST .../Consent/handle
    fn check_consent_status();
    /// This API is intended for fetching the information associated with the specific consent.
    /// POST .../Consent/fetch
    fn fetch_consent();
    /// This API can be used by AA Client, FIU and FIP to place a request for consent status
    /// update to AA in specific use cases. For more details, please refer FAQ section.
    /// POST .../Consent/Notification
    fn update_consent_status();
}

// API managed by AA
trait DataFlow {
    /// This API is used by the FIU to request for financial information from the AA.
    /// The AA will validate the request against the signed consent and
    /// return a sessionID which can then be used by the FIU to fetch the required data.
    /// POST .../FI/request
    fn request_fi();
    /// This API is used to fetch financial information from AA once FIU recieves the data ready notification.
    /// POST .../FI/fetch
    fn fetch_fi();
    /// This API can be used by AA Client, FIU and FIP to send notifications
    /// related to Financial Information (FI) fetch to AA.
    /// POST .../FI/Notification
    fn update_fi_status();
}

// API managed by AA
trait AccountLinkingFlow {
    /// This API can be used by FIP to send account linking related notifications
    /// to AA in case of direct authentication method of account linking.
    /// POST .../Account/link/Notification
    fn update_account_linking_status();
}

/// FIPs and FIUs may use this to check the availability of AA service.
trait Monitor {
    /// GET .../Heartbeat
    fn heartbeat();
}
