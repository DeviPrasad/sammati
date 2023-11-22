//! Deposit FI Schema per rebit speification.
//! https://specifications.rebit.org.in/api_schema/account_aggregator/examples/Deposit_v1.2.xml
//! https://specifications.rebit.org.in/api_schema/account_aggregator/ReleaseNotes/Deposit_release_note_v1.2.0.txt
//! FI Type - Deposit
//! Version - 1.2
//! https://specifications.rebit.org.in/api_schema/account_aggregator/documentation/deposit_v1.2.html

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

use crate::ts::{DepositAccTxTimestamp, UtcTs};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DepositAccount {
    #[serde(rename = "deposit")]
    Deposit,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DepositAccountType {
    #[serde(rename = "SAVINGS")]
    Savings,
    #[serde(rename = "CURRENT")]
    Current,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TransactionType {
    #[serde(rename = "CREDIT")]
    Credit,
    #[serde(rename = "DEBIT")]
    Debit,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TransactionMode {
    #[serde(rename = "CASH")]
    Cash,
    #[serde(rename = "ATM")]
    ATM,
    #[serde(rename = "CARD")]
    Card,
    #[serde(rename = "UPI")]
    UPI,
    #[serde(rename = "FT")]
    FundTransfer,
    #[serde(rename = "OTHERS")]
    Others,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AccHolderType {
    #[serde(rename = "signle")]
    Single,
    #[serde(rename = "joint")]
    Joint,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SummaryFacility {
    #[serde(rename = "OD")]
    OD,
    #[serde(rename = "CC")]
    CC,
    #[serde(rename = "")]
    None,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AccountStatus {
    #[serde(rename = "ACTIVE")]
    Active,
    #[serde(rename = "INACTIVE")]
    Inactive,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum HoldingNominee {
    #[serde(rename = "REGISTERED")]
    Registered,
    #[serde(rename = "NOT-REGISTERED")]
    NotRegistered,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DepositAccountFI {
    #[serde(rename = "version")]
    version: String,
    #[serde(rename = "type")]
    pub acc_type: DepositAccount,
    #[serde(rename = "maskedAccNumber")]
    pub masked_acc_num: String,
    #[serde(rename = "linkedAccRef")]
    pub linked_acc_ref: String,
    #[serde(rename = "Profile")]
    pub profile: AccountHolderProfile,
    #[serde(rename = "Summary")]
    summary: AccSummary,
    #[serde(rename = "Transactions")]
    pub txs: AccTxStatement,
}

// NOTE
// We believe there's a tiny error, very minor defect in 'Summary' element definition.
// https://specifications.rebit.org.in/api_schema/account_aggregator/documentation/deposit_v1.2.html#Summary
// It lists 'currency' and 'exchgeRate' as part of the Summary definition.
// We have moved these two properties under 'Transaction' element for obvious reasons.
//
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccSummary {
    #[serde(rename = "currentBalance")]
    current_balance: String,
    #[serde(rename = "balanceDateTime")]
    balance_ts: String,
    #[serde(rename = "type")]
    acc_type: DepositAccountType,
    #[serde(rename = "branch")]
    branch: String,
    // additional facility like Overdraft or Sweep, if applicable for the given account.
    #[serde(rename = "facility")]
    facility: SummaryFacility,
    #[serde(rename = "ifscCode")]
    ifsc_code: String,
    #[serde(rename = "micrCode")]
    micr_code: String,
    #[serde(rename = "openingDate")]
    opening_date: NaiveDate,
    #[serde(rename = "currentODLimit")]
    cur_overdraft_limit: String,
    #[serde(rename = "drawingLimit")]
    drawing_limit: String,
    #[serde(rename = "status")]
    status: AccountStatus,
    #[serde(rename = "Pending")]
    pending: Vec<AccPendingTx>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountHolderProfile {
    #[serde(rename = "Holders")]
    pub holders: AccHolderProfileData,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccHolderProfileData {
    #[serde(rename = "type")]
    pub holder_type: AccHolderType,
    #[serde(rename = "Holder")]
    pub holder: Vec<AccHolderProfile>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccHolderProfile {
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "ckycCompliance")]
    pub ckyc_compliance: bool,
    #[serde(rename = "dob")]
    pub dob: NaiveDate,
    #[serde(rename = "mobile")]
    pub mobile: String,
    #[serde(rename = "nominee")]
    pub nominee: HoldingNominee,
    #[serde(rename = "address", skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(rename = "landline", skip_serializing_if = "Option::is_none")]
    pub landline: Option<String>,
    #[serde(rename = "email", skip_serializing_if = "Option::is_none")]
    // pattern: [^@]+@[^\.]+\..+
    pub email: Option<String>,
    #[serde(rename = "pan", skip_serializing_if = "Option::is_none")]
    // pattern: [a-zA-Z][a-zA-Z][a-zA-Z][a-zA-Z][a-zA-Z][0-9][0-9][0-9][0-9][a-zA-Z]
    pub pan: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccBalance {
    #[serde(rename = "currentBalance")]
    current_balance: String,
    #[serde(
        rename = "balanceDateTime",
        deserialize_with = "UtcTs::deserialize_from_str"
    )]
    ts: UtcTs,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccPendingTx {
    #[serde(rename = "amount")]
    amount: f64,
    #[serde(rename = "type")]
    tx_type: Option<TransactionType>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccTxStatement {
    #[serde(rename = "startDate")]
    start_date: NaiveDate,
    #[serde(rename = "endDate")]
    end_date: NaiveDate,
    #[serde(rename = "Transaction")]
    txs: Vec<AccTx>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccTx {
    #[serde(rename = "amount")]
    amount: f64,
    #[serde(rename = "type")]
    tx_type: TransactionType,
    #[serde(rename = "mode")]
    mode: TransactionMode,
    #[serde(rename = "currentBalance")]
    cur_balance: String,
    #[serde(
        rename = "transactionTimestamp",
        flatten,
        deserialize_with = "DepositAccTxTimestamp::deserialize_from_str"
    )]
    tx_ts: DepositAccTxTimestamp,
    #[serde(rename = "valueDate")]
    // the date when the entry to an account is considered effective in accounting.
    // value_date MUST NOT BE prior to the 'tx_ts'
    value_date: NaiveDate,
    #[serde(rename = "txnId")]
    tx_id: String,
    #[serde(rename = "narration")]
    narration: String,
    #[serde(rename = "reference")]
    // cheque number or reference number for the transaction
    reference: String,
    // Currency in which transaction taken place.
    #[serde(rename = "currency", skip_serializing_if = "Option::is_none")]
    currency: Option<String>,
    // Currency conversion exchange rate for the day
    #[serde(rename = "exchgeRate", skip_serializing_if = "Option::is_none")]
    exchagne_rate: Option<String>,
}

#[cfg(test)]
mod fi_schema_deposit {
    use chrono::NaiveDate;

    use crate::{
        deposit::{
            AccHolderProfile, AccHolderProfileData, AccHolderType, AccSummary, AccTxStatement,
            AccountHolderProfile, AccountStatus, DepositAccount, DepositAccountFI,
            DepositAccountType, HoldingNominee, SummaryFacility,
        },
        mutter,
        ts::{DepositAccTxTimestamp, UtcTs},
    };

    use super::{AccTx, TransactionMode, TransactionType};

    #[test]
    fn profile_001() {
        mutter::init_log();
        let dr_upi_tx_01 = AccTx {
            amount: 2500.00,
            tx_type: TransactionType::Debit,
            mode: TransactionMode::UPI,
            cur_balance: "72961.37".to_string(),
            tx_ts: DepositAccTxTimestamp(UtcTs::from_str("2023-09-01 10:12:52Z").unwrap()),
            value_date: NaiveDate::parse_from_str("01-09-2023", "%d-%m-%Y").unwrap(),
            tx_id: "f4184fc596403b9d638783cf57adfe4c".to_string(),
            narration: "UPI-SATISH KUMAR MUDIPU-q602152501@ ybl-UBIN0988891-324513654321-UPI Value Dt 01/09/2023 Ref 655513691567".to_string(),
            reference: "1234484525682".to_string(),
            currency: Some("INR".to_string()),
            exchagne_rate: None,
        };
        let dr_upi_tx_02 = AccTx {
            amount: 431.53,
            tx_type: TransactionType::Debit,
            mode: TransactionMode::UPI,
            cur_balance: "72529.84".to_string(),
            tx_ts: DepositAccTxTimestamp(UtcTs::from_str("2023-09-02 16:34:31Z").unwrap()),
            value_date: NaiveDate::parse_from_str("02-09-2023", "%d-%m-%Y").unwrap(),
            tx_id: "c75c605f6356fbc91338530e9831e9e1".to_string(),
            narration: "UPI-Tall Fig Tree Entertainment-tallfigtreeentertainmentltd.rzp@icici-ICIC0DC0011-324567898555-Pay via Sharppay Value Dt 02/09/2023 Ref 324567898555".to_string(),
            reference: "884501777322".to_string(),
            currency: Some("INR".to_string()),
            exchagne_rate: None,
        };
        let cr_neft_tx_01 = AccTx {
            amount: 20000.00,
            tx_type: TransactionType::Credit,
            mode: TransactionMode::FundTransfer,
            cur_balance: "92529.84".to_string(),
            tx_ts: DepositAccTxTimestamp(UtcTs::from_str("2023-09-05 11:04:28Z").unwrap()),
            value_date: NaiveDate::parse_from_str("05-09-2023", "%d-%m-%Y").unwrap(),
            tx_id: "4cfead57cf8387639d3b4096c54f18f4".to_string(),
            narration: "NEFT Cr-ECOB0014222-MEDIUM BUCKS FINANCE Ltd-Devi Prasad-P255980233152930 Value Dt 05/09/2023 Ref P345189234567890".to_string(),
            reference: "P345189234567890".to_string(),
            currency: Some("INR".to_string()),
            exchagne_rate: None,
        };
        let dr_card_tx_03 = AccTx {
            amount: 10459.00,
            tx_type: TransactionType::Debit,
            mode: TransactionMode::Card,
            cur_balance: "82070.84".to_string(),
            tx_ts: DepositAccTxTimestamp(UtcTs::from_str("2023-10-07 16:34:31Z").unwrap()),
            value_date: NaiveDate::parse_from_str("07-10-2023", "%d-%m-%Y").unwrap(),
            tx_id: "c75c605f6356fbc91338530e9831e9e1".to_string(),
            narration: "CC 000185432XXXXXX5274 Autopay SI-TAD Value Dt 07/10/2023 Ref 619839568"
                .to_string(),
            reference: "619839568".to_string(),
            currency: Some("INR".to_string()),
            exchagne_rate: None,
        };
        let dr_atm_tx_04 = AccTx {
            amount: 3500.00,
            tx_type: TransactionType::Debit,
            mode: TransactionMode::ATM,
            cur_balance: "78570.84".to_string(),
            tx_ts: DepositAccTxTimestamp(UtcTs::from_str("2023-10-29 10:50:18Z").unwrap()),
            value_date: NaiveDate::parse_from_str("29-10-2023", "%d-%m-%Y").unwrap(),
            tx_id: "a17b6714ee1f0e68bebb44a74b1efd51".to_string(),
            narration: "ATW-512967XXXXXX0618-S1ACMN04-KARKTI Value Dt 29/10/2023 Ref 8743"
                .to_string(),
            reference: "8743".to_string(),
            currency: Some("INR".to_string()),
            exchagne_rate: None,
        };
        // Credit Interest Capitalised
        let cr_other_tx_02 = AccTx {
            amount: 6186.12,
            tx_type: TransactionType::Credit,
            mode: TransactionMode::Others,
            cur_balance: "84756.96".to_string(),
            tx_ts: DepositAccTxTimestamp(UtcTs::from_str("2023-10-31 11:04:28Z").unwrap()),
            value_date: NaiveDate::parse_from_str("31-10-2023", "%d-%m-%Y").unwrap(),
            tx_id: "4b8a0e3e2357e806b6cdb1f70b54c3a3".to_string(),
            narration: "Credit Interest Capitalised Value Dt 31/10/2023".to_string(),
            reference: "".to_string(),
            currency: Some("INR".to_string()),
            exchagne_rate: None,
        };
        let _jdtx01 = serde_json::to_string(&dr_upi_tx_01);
        let _jdtx02 = serde_json::to_string(&dr_upi_tx_02);
        let _jctx01 = serde_json::to_string(&cr_neft_tx_01);
        let _jdtx03 = serde_json::to_string(&dr_card_tx_03);
        let _jdtx04 = serde_json::to_string(&dr_atm_tx_04);
        let _jctx02 = serde_json::to_string(&cr_other_tx_02);

        let acc_tx_stmt = AccTxStatement {
            start_date: NaiveDate::parse_from_str("01-09-2023", "%d-%m-%Y").unwrap(),
            end_date: NaiveDate::parse_from_str("31-10-2023", "%d-%m-%Y").unwrap(),
            txs: vec![
                dr_upi_tx_01,
                dr_upi_tx_02,
                cr_neft_tx_01,
                dr_card_tx_03,
                dr_atm_tx_04,
                cr_other_tx_02,
            ],
        };

        let dp_linked_acc_summary = AccSummary {
            current_balance: "20152.47".into(),
            balance_ts: "2023-11-21 15:27:31Z".into(),
            acc_type: DepositAccountType::Savings,
            branch: "MAIN BRANCH, NAMMA NAGARA".into(),
            facility: SummaryFacility::None,
            ifsc_code: "DIGI0000981".into(),
            micr_code: "462400091".into(),
            opening_date: NaiveDate::parse_from_str("01-01-2000", "%d-%m-%Y").unwrap(),
            cur_overdraft_limit: "".into(),
            drawing_limit: "".into(),
            status: AccountStatus::Active,
            pending: vec![],
        };

        let dp_profile = AccHolderProfile {
            name: "Devi Prasad M".into(),
            ckyc_compliance: true,
            dob: NaiveDate::parse_from_str("12-04-1967", "%d-%m-%Y").unwrap(),
            mobile: "9990000222".into(),
            nominee: HoldingNominee::Registered,
            address: Some("HOUSE NO: 2/B01/D4, Tall Tree Apartments. LOCATION: Bright Avenue, Busy Road, New Town. CITY: Namma Nagara. PINCODE: 876543. STATE: Karunadu.".into()),
            landline: None,
            email: Some("tiny_rust_box@monad.io".into()),
            pan: Some("RUSTY0224Z".to_string()),
        };

        let dp_profile_details = AccountHolderProfile {
            holders: AccHolderProfileData {
                holder_type: AccHolderType::Single,
                holder: vec![dp_profile],
            },
        };

        let dp_linked_acc_fi = DepositAccountFI {
            version: "2.0.0".into(),
            acc_type: DepositAccount::Deposit,
            masked_acc_num: "XXXXINBBNNXXXXXX3280753468".into(),
            linked_acc_ref: "adB0000570926453147364ebfc812345".into(),
            profile: dp_profile_details,
            summary: dp_linked_acc_summary,
            txs: acc_tx_stmt,
        };

        log::info!("{:#?}", dp_linked_acc_fi);
        log::info!("");
        log::info!("{:#?}", serde_json::to_string(&dp_linked_acc_fi));
    }
}
