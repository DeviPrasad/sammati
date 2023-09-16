#![allow(dead_code)]

use chrono::DateTime;
use chrono::FixedOffset;
use chrono::NaiveDateTime;
use chrono::SecondsFormat;
use serde::Serialize;

#[derive(Debug, Clone)]
pub enum TimestampFormat {
    /// RFC 3339 date-and-time string
    FixedOffset(DateTime<FixedOffset>),
    Naive(NaiveDateTime),
}

#[derive(Debug, Clone)]
pub struct Timestamp {
    pub val: String,
    pub rep: TimestampFormat,
}

impl ToString for Timestamp {
    fn to_string(&self) -> String {
        match self.rep {
            TimestampFormat::Naive(dt) => dt.to_string(),
            TimestampFormat::FixedOffset(dt) => dt.to_rfc3339(),
        }
    }
}

use serde::ser::SerializeStruct;
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
                val: s.to_owned(),
                rep: TimestampFormat::FixedOffset(dt),
            })
        } else if let Ok(dt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
            Ok(Timestamp {
                val: s.to_owned(),
                rep: TimestampFormat::Naive(dt),
            })
        } else if let Ok(dt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f") {
            Ok(Timestamp {
                val: s.to_owned(),
                rep: TimestampFormat::Naive(dt),
            })
        } else {
            Err(false)
        }
    }

    pub fn now() -> String {
        chrono::offset::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, false)
    }
}

#[derive(Clone, Debug)]
pub struct TimePeriod {
    pub from: Timestamp,
    pub to: Timestamp,
}

#[cfg(test)]
mod tests {
    use crate::ets::Timestamp;

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
