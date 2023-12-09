#![allow(dead_code)]

use chrono::{DateTime, FixedOffset, LocalResult, NaiveDateTime, SecondsFormat, TimeZone, Utc};
use serde::de::Error;
use serde::{ser::SerializeStruct, Deserialize, Serialize};
use std::fmt::Debug;
use std::str::FromStr;
use std::{
    fmt::Formatter,
    time::{Duration, SystemTime, SystemTimeError, UNIX_EPOCH},
};

pub type ConsentUtc = UtcTs;

#[derive(Debug, Clone)]
pub struct UtcTs {
    pub ts: i64,
    pub rep: String,
}

impl ToString for UtcTs {
    fn to_string(&self) -> String {
        self.rep.to_string()
    }
}

impl FromStr for UtcTs {
    type Err = bool;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        UtcTs::from_str(s)
    }
}

impl Serialize for UtcTs {
    fn serialize<S>(&self, ss: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        let mut st = ss.serialize_struct("Timestamp", 1)?;
        st.serialize_field("timestamp", &self.to_string())?;
        st.end()
    }
}

#[derive(Debug, Clone)]
pub struct ExpiryTimestamp {
    pub expiry: UtcTs,
}

impl Serialize for ExpiryTimestamp {
    fn serialize<S>(&self, ss: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        let mut st = ss.serialize_struct("ExpiryTimestamp", 1)?;
        st.serialize_field("expiry", &self.expiry.to_string())?;
        st.end()
    }
}

impl ExpiryTimestamp {
    pub fn deserialize_from_str<'de, D>(deserializer: D) -> Result<ExpiryTimestamp, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        UtcTs::from_str(&s)
            .map(|ts| Self { expiry: ts })
            .map_err(Error::custom)
    }
}

#[derive(Debug, Clone)]
pub struct DepositAccTxTimestamp(pub UtcTs);
impl Serialize for DepositAccTxTimestamp {
    fn serialize<S>(&self, ss: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        let mut st = ss.serialize_struct("DepositAccTxTimestamp", 1)?;
        st.serialize_field("transactionTimestamp", &self.0.to_string())?;
        st.end()
    }
}
impl DepositAccTxTimestamp {
    pub fn deserialize_from_str<'de, D>(deserializer: D) -> Result<DepositAccTxTimestamp, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        UtcTs::from_str(&s)
            .map(|ts| Self(ts))
            .map_err(Error::custom)
    }
}

impl UtcTs {
    pub fn deserialize_from_str<'de, D>(deserializer: D) -> Result<UtcTs, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_str(&s).map_err(Error::custom)
    }

    pub fn from_unix_timestamp(ts: i64) -> Result<UtcTs, bool> {
        match Utc.timestamp_opt(ts, 0) {
            LocalResult::Single(dt) => Ok(UtcTs {
                ts: dt.timestamp(),
                rep: dt.to_rfc3339_opts(SecondsFormat::Millis, false),
            }),
            _ => Err(false),
        }
    }
    pub fn from_str(s: &str) -> Result<UtcTs, bool> {
        if let Ok(dt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S.fZ") {
            Ok(UtcTs {
                ts: dt.timestamp(),
                rep: dt.to_string(),
            })
        } else if let Ok(dt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%SZ") {
            Ok(UtcTs {
                ts: dt.timestamp(),
                rep: dt.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            })
        } else if let Ok(dt) = DateTime::<FixedOffset>::parse_from_rfc3339(s) {
            Ok(UtcTs {
                ts: dt.timestamp(),
                rep: dt.to_string(),
            })
        } else {
            log::error!("{:#?}", DateTime::<FixedOffset>::parse_from_rfc3339(s));
            Err(false)
        }
    }

    // produces a string of the form "2023-10-07T15:46:26.200+05:30"
    // 'tz' could be chrono_tz::Asia::Kolkata
    pub fn now_with_timezone_offset_str(tz: chrono_tz::Tz) -> Self {
        let _dt_local: DateTime<chrono::Local> = chrono::Local::now();
        let _ndt_local: NaiveDateTime = _dt_local.naive_local();
        let _ts_with_tz: DateTime<chrono_tz::Tz> = tz.from_local_datetime(&_ndt_local).unwrap();
        Self {
            ts: _ts_with_tz.timestamp(),
            rep: _ts_with_tz.to_rfc3339_opts(SecondsFormat::Millis, false),
        }
    }

    // produces a string of the form "2023-10-07T15:46:26.200+05:30"
    pub fn localtime_with_offset_str() -> Self {
        let _dt_local: DateTime<chrono::Local> = chrono::Local::now();
        Self {
            ts: _dt_local.timestamp(),
            rep: _dt_local.to_rfc3339_opts(SecondsFormat::Millis, false),
        }
    }

    // if 'with_z' is true, produces a string of the form ""2023-10-07T10:25:48.686Z"
    // if 'with_z' is false, produces a string of the form "2023-10-07T10:25:48.686+00:00"
    pub fn now_utc_str(with_z: bool) -> Self {
        let _ndt_local: NaiveDateTime = Utc::now().naive_local();
        let _utc_tz: DateTime<chrono_tz::Tz> =
            chrono_tz::UTC.from_local_datetime(&_ndt_local).unwrap();
        Self {
            ts: _utc_tz.timestamp(),
            rep: _utc_tz.to_rfc3339_opts(SecondsFormat::Millis, with_z),
        }
    }

    pub fn now() -> Self {
        Self::now_utc_str(true)
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct TimePeriod {
    #[serde(rename = "from", deserialize_with = "UtcTs::deserialize_from_str")]
    pub from: UtcTs,
    #[serde(rename = "to", deserialize_with = "UtcTs::deserialize_from_str")]
    pub to: UtcTs,
}

#[inline]
pub fn unix_timestamp() -> u64 {
    let r: Result<Duration, SystemTimeError> = SystemTime::now().duration_since(UNIX_EPOCH);
    match r {
        Ok(t) => t.as_secs(),
        _ => 0,
    }
}

#[inline]
pub fn past_within_allowed_skew(
    past: u64,
    past_skew_sec_max: u64,
    future_skew_sec_max: u64,
) -> bool {
    if let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) {
        // past event should NOT be way too past! there's a permitted freshness period.
        // is (past + skew_sec_max) < now?
        if Duration::new(past, 0)
            .saturating_add(Duration::new(past_skew_sec_max, 0))
            .lt(&now)
        {
            false
        } else if now
            .saturating_add(Duration::new(future_skew_sec_max, 0))
            .lt(&Duration::new(past, 0))
        {
            // past shout NOT be ahead of our 'now'!
            false
        } else {
            true
        }
    } else {
        false
    }
}

#[inline]
pub fn unix_timestamp_add_seconds(seconds: u64) -> u64 {
    let r: Result<Duration, SystemTimeError> = SystemTime::now().duration_since(UNIX_EPOCH);
    match r {
        Ok(t) => t.saturating_add(Duration::new(seconds, 0)).as_secs(),
        _ => 0,
    }
}

#[inline]
pub fn unix_timestamp_sub_seconds(past: u64) -> u64 {
    let r: Result<Duration, SystemTimeError> = SystemTime::now().duration_since(UNIX_EPOCH);
    match r {
        Ok(t) => t.saturating_sub(Duration::new(past, 0)).as_secs(),
        _ => 0,
    }
}

#[inline]
pub fn unix_timestamp_add_minutes(minutes: u64) -> u64 {
    unix_timestamp_add_seconds(minutes * 60)
}

#[inline]
pub fn unix_timestamp_add_hours(hrs: u64) -> u64 {
    unix_timestamp_add_seconds(hrs * 60 * 60)
}

#[inline]
pub fn unix_timestamp_add_days(days: u64) -> u64 {
    unix_timestamp_add_seconds(days * 24 * 60 * 60)
}

#[derive(Default, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UnixTimeStamp(i64);

impl std::fmt::Display for UnixTimeStamp {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        writeln!(f, "time_stamp: {:?}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use crate::ts::UtcTs;

    #[test]
    fn good_timestamp_naive_01() {
        let ts = UtcTs::from_str("2010-08-15T12:07:53Z");
        assert!(ts.is_ok());
        let s = ts.unwrap().to_string();
        assert_ne!(s, "2010-08-15 12:07:53");
        assert_eq!(s, "2010-08-15T12:07:53Z");
    }
    #[test]
    fn good_timestamp_naive_02() {
        let ts = UtcTs::from_str("2011-08-15T12:07:49.153Z");
        assert!(ts.is_ok());
        let s = ts.unwrap().to_string();
        assert_eq!(s, "2011-08-15 12:07:49.153 +00:00");
    }
    #[test]
    fn good_timestamp_naive_03() {
        let ts = UtcTs::from_str("2012-08-15T12:07:53.153");
        assert!(!ts.is_ok());
        // let s = ts.unwrap().to_string();
        // assert_eq!(s, "2012-08-15 12:07:53.153");
    }
    #[test]
    fn good_timestamp_naive_04() {
        let ts = UtcTs::from_str("2013-09-07T15:50:00Z");
        assert!(ts.is_ok());
        let s = ts.unwrap().to_string();
        assert_eq!(s, "2013-09-07T15:50:00Z");
    }
    #[test]
    fn good_timestamp_rfc3339_01() {
        let ts = UtcTs::from_str("2014-08-15T12:07:53.153Z");
        // let ts = Timestamp::from_str("");
        // let ts = Timestamp::from_str("2023-08-15T12:07:53.153 +05:30");
        assert!(ts.is_ok());
        let s = ts.unwrap().to_string();
        assert_eq!(s, "2014-08-15 12:07:53.153 +00:00");
    }
    #[test]
    fn good_timestamp_rfc3339_02() {
        let ts = UtcTs::from_str("2015-08-15T12:07:53Z");
        // let ts = Timestamp::from_str("");
        // let ts = Timestamp::from_str("2023-08-15T12:07:53.153 +05:30");
        assert!(ts.is_ok());
        let s = ts.unwrap().to_string();
        assert_eq!(s, "2015-08-15T12:07:53Z");
    }
    #[test]
    fn good_timestamp_rfc3339_03() {
        let ts = UtcTs::from_str("2016-03-12T17:56:22+05:30");
        // let ts = Timestamp::from_str("");
        // let ts = Timestamp::from_str("2023-08-15T12:07:53.153 +05:30");
        assert!(ts.is_ok());
        let s = ts.unwrap().to_string();
        assert_eq!(s, "2016-03-12 17:56:22 +05:30");
    }
    #[test]
    fn good_timestamp_rfc3339_04() {
        let ts = UtcTs::from_str("2017-10-15T12:07:53.153+05:30");
        // let ts = Timestamp::from_str("");
        // let ts = Timestamp::from_str("2023-08-15T12:07:53.153 +05:30");
        assert!(ts.is_ok());
        let s = ts.unwrap().to_string();
        assert_eq!(s, "2017-10-15 12:07:53.153 +05:30");
    }
    #[test]
    fn good_timestamp_rfc3339_05() {
        let ts = UtcTs::from_str("2018-10-15T12:00:00-05:30");
        assert!(ts.is_ok());
        let s = ts.unwrap().to_string();
        assert_eq!(s, "2018-10-15 12:00:00 -05:30");
    }
}
