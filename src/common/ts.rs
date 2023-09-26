#![allow(dead_code)]

use chrono::{DateTime, FixedOffset, NaiveDateTime, SecondsFormat, TimeZone, Utc};
use serde::{ser::SerializeStruct, Deserialize, Serialize};
use std::fmt::Debug;
use std::str::FromStr;
use std::{
    fmt::Formatter,
    time::{Duration, SystemTime, SystemTimeError, UNIX_EPOCH},
};

#[derive(Debug, Clone, Deserialize)]
pub struct Timestamp {
    pub rep: String,
}

impl ToString for Timestamp {
    fn to_string(&self) -> String {
        self.rep.to_string()
    }
}

impl FromStr for Timestamp {
    type Err = bool;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Timestamp::from_str(s)
    }
}

impl Serialize for Timestamp {
    fn serialize<S>(&self, ss: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        let mut st = ss.serialize_struct("Timestamp", 1)?;
        st.serialize_field("timestamp", &self.to_string())?;
        st.end()
    }
}

impl Timestamp {
    pub fn from_str(s: &str) -> Result<Timestamp, bool> {
        if let Ok(dt) = DateTime::<FixedOffset>::parse_from_rfc3339(s) {
            Ok(Timestamp {
                rep: dt.to_string(),
            })
        } else if let Ok(dt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
            Ok(Timestamp {
                rep: dt.to_string(),
            })
        } else if let Ok(dt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f") {
            Ok(Timestamp {
                rep: dt.to_string(),
            })
        } else {
            Err(false)
        }
    }

    pub fn now_as_str() -> String {
        Utc::now().to_rfc3339_opts(SecondsFormat::Millis, false)
    }
    pub fn now() -> Self {
        let _l: NaiveDateTime = Utc::now().naive_local();
        let _tn: DateTime<chrono_tz::Tz> =
            chrono_tz::Asia::Kolkata.from_local_datetime(&_l).unwrap();
        Self {
            rep: _tn.fixed_offset().to_string(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct TimePeriod {
    pub from: Timestamp,
    pub to: Timestamp,
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
    use crate::ts::Timestamp;

    #[test]
    fn good_timestamp_naive_01() {
        let ts = Timestamp::from_str("2010-08-15T12:07:53");
        assert!(ts.is_ok());
        let s = ts.unwrap().to_string();
        assert_eq!(s, "2010-08-15 12:07:53");
    }
    #[test]
    fn good_timestamp_naive_02() {
        let ts = Timestamp::from_str("2011-08-15T12:07:49.153Z");
        assert!(ts.is_ok());
        let s = ts.unwrap().to_string();
        assert_eq!(s, "2011-08-15T12:07:49.153+00:00");
    }
    #[test]
    fn good_timestamp_naive_03() {
        let ts = Timestamp::from_str("2012-08-15T12:07:53.153");
        assert!(ts.is_ok());
        let s = ts.unwrap().to_string();
        assert_eq!(s, "2012-08-15 12:07:53.153");
    }
    #[test]
    fn good_timestamp_naive_04() {
        let ts = Timestamp::from_str("2013-09-07T15:50:00Z");
        assert!(ts.is_ok());
        let s = ts.unwrap().to_string();
        assert_eq!(s, "2013-09-07T15:50:00+00:00");
    }
    #[test]
    fn good_timestamp_rfc3339_01() {
        let ts = Timestamp::from_str("2014-08-15T12:07:53.153Z");
        // let ts = Timestamp::from_str("");
        // let ts = Timestamp::from_str("2023-08-15T12:07:53.153 +05:30");
        assert!(ts.is_ok());
        let s = ts.unwrap().to_string();
        assert_eq!(s, "2014-08-15T12:07:53.153+00:00");
    }
    #[test]
    fn good_timestamp_rfc3339_02() {
        let ts = Timestamp::from_str("2015-08-15T12:07:53Z");
        // let ts = Timestamp::from_str("");
        // let ts = Timestamp::from_str("2023-08-15T12:07:53.153 +05:30");
        assert!(ts.is_ok());
        let s = ts.unwrap().to_string();
        assert_eq!(s, "2015-08-15T12:07:53+00:00");
    }
    #[test]
    fn good_timestamp_rfc3339_03() {
        let ts = Timestamp::from_str("2016-03-12T17:56:22+05:30");
        // let ts = Timestamp::from_str("");
        // let ts = Timestamp::from_str("2023-08-15T12:07:53.153 +05:30");
        assert!(ts.is_ok());
        let s = ts.unwrap().to_string();
        assert_eq!(s, "2016-03-12T17:56:22+05:30");
    }
    #[test]
    fn good_timestamp_rfc3339_04() {
        let ts = Timestamp::from_str("2017-10-15T12:07:53.153+05:30");
        // let ts = Timestamp::from_str("");
        // let ts = Timestamp::from_str("2023-08-15T12:07:53.153 +05:30");
        assert!(ts.is_ok());
        let s = ts.unwrap().to_string();
        assert_eq!(s, "2017-10-15T12:07:53.153+05:30");
    }
    #[test]
    fn good_timestamp_rfc3339_05() {
        let ts = Timestamp::from_str("2018-10-15T12:00:00-05:30");
        assert!(ts.is_ok());
        let s = ts.unwrap().to_string();
        assert_eq!(s, "2018-10-15T12:00:00-05:30");
    }
}
