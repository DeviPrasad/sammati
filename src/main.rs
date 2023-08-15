mod eco;
use crate::eco::{fiu, ConsentHandle, ConsentId, Timestamp, UserConsent, UserConsentStatus};

fn main() {}

#[test]
fn test_fiu_ds_001() {
    let _ts = Timestamp::from_str("2023-08-15T12:07:53");
    let _ts = Timestamp::from_str("2023-08-15T12:07:53");
    let ts = Timestamp::from_str("2023-08-15 12:07:53.153Z");
    println!("{:#?}", ts);
    let csn = fiu::ConsentStatusNotification {
        ver: "2.0.0".to_owned(),
        /// timestamp: DateTime::<FixedOffset>::parse_from_rfc3339("2023-08-15T11:39:57.153Z").unwrap(),
        timestamp: ts.unwrap(),
        txid: eco::TxId::from_uuid("0b811819-9044-4856-b0ee-8c88035f8858").unwrap(),
        notifer: fiu::Notifier {
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
            status: UserConsentStatus::PAUSED,
        },
    };
    std::println!("aa {:#?}", csn);
}
