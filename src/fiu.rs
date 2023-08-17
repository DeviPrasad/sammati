#![allow(dead_code)]

use crate::ets::Timestamp;
/// https://api.rebit.org.in/viewSpec/FIU_2_0_0.yaml
use crate::types::FISessionStatus;
use crate::types::FinAccount;
use crate::types::Notifier;
use crate::types::TxId;
use crate::types::UserConsent;

/// Notification about the status of consent
#[derive(Debug, Clone)]
pub struct ConsentStatusNotification {
    /// (required) API version = 2.0.0
    pub ver: String,
    /// (required) creation timestamp of the message
    pub timestamp: Timestamp,
    /// unique transaction identifier used for providing end-to-end traceability.
    pub txid: TxId,
    /// (required)
    pub notifer: Notifier,
    /// (required)
    pub consent: UserConsent,
}

#[derive(Debug, Clone)]
pub struct FIStatusResponse {
    /// FIP ID as defined in the account aggregator ecosystem
    pub fip_id: String,
    pub accounts: Vec<FinAccount>,
}

// Contains the financial information fetch session id and session status details
#[derive(Debug, Clone)]
pub struct FISessionStatusResponse {
    /// (required) type of the notifier entity; example: AA
    pub session_id: String,
    /// (required) unique ID to identify the entity
    pub session_status: FISessionStatus,
    pub fi_status_response: Vec<FIStatusResponse>,
}

#[derive(Debug, Clone)]
pub struct FIStatusNotification {
    /// (required) API version = 2.0.0
    pub ver: String,
    /// (required) creation timestamp of the message
    pub timestamp: Timestamp,
    /// unique transaction identifier used for providing end-to-end traceability.
    pub txid: TxId,
    /// (required)
    pub notifer: Notifier,
    /// (required)
    pub status_response: FISessionStatusResponse,
}

trait ConsentNotification {
    /// This API is intended to be used by AA to notify FIU about the change in consent status
    /// due to the consent management operations performed by the Customer.
    /// POST .../Consent/Notification
    fn update_consent_status();
    /// This API can be used by AAs to send notifications related to Financial Information (FI) fetch to FIU/AA Client.
    /// POST .../FI/Notification
    fn update_fi_status();
}
#[cfg(test)]
mod tests {
    use crate::ets::Timestamp;
    use crate::fiu::ConsentStatusNotification;
    use crate::types::Notifier;
    use crate::types::{ConsentHandle, ConsentId, TxId, UserConsent, UserConsentStatus};

    #[test]
    fn pass_fiu_consent_status_notification_01() {
        // let _ts = Timestamp::from_str("2023-08-15T12:07:53");
        let ts = Timestamp::from_str("2023-08-15T12:07:53.153Z");
        println!("{:#?}", ts);
        let csn = ConsentStatusNotification {
            ver: "2.0.0".to_owned(),
            /// timestamp: DateTime::<FixedOffset>::parse_from_rfc3339("2023-08-15T11:39:57.153Z").unwrap(),
            timestamp: ts.unwrap(),
            txid: TxId::from_uuid("0b811819-9044-4856-b0ee-8c88035f8858").unwrap(),
            notifer: Notifier {
                typ: "AA".to_owned(),
                id: "Sammati-AA".to_owned(),
            },
            consent: UserConsent {
                id: Some(ConsentId {
                    val: "XXXX0-XXXX-XXXX".to_owned(),
                }),
                handle: Some(ConsentHandle {
                    val: "XXXX0-XXXX-XXXX".to_owned(),
                }),
                status: UserConsentStatus::Paused,
            },
        };
        std::println!("aa {:#?}", csn);
    }
}
