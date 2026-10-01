//! Timestamp handling for FILETIME, FAT (DOS) date/time and OLE dates.
//!
//! All timestamps are normalised to FILETIME ticks (100 ns intervals since
//! 1601-01-01 UTC) so they can be compared, sorted and rendered uniformly
//! without pulling in a calendar crate.

use serde::{Serialize, Serializer};
use std::fmt;

/// Seconds between 1601-01-01 and 1970-01-01.
const EPOCH_DIFF_SECS: i64 = 11_644_473_600;
const TICKS_PER_SEC: u64 = 10_000_000;

/// Resolution/provenance of a timestamp, so analysts know how much to trust it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Precision {
    /// 100 ns FILETIME.
    FileTime,
    /// FAT/DOS date-time, 2 second resolution.
    Fat,
    /// OLE automation date (VT_DATE).
    OleDate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Timestamp {
    ticks: u64,
    precision: Precision,
}

impl Timestamp {
    /// Builds a timestamp from FILETIME ticks. Zero and absurd values (after
    /// year 9999) yield `None`.
    pub fn from_filetime(ft: u64) -> Option<Timestamp> {
        // 9999-12-31T23:59:59 is 0x24C85A5ED1C018F0 (2650467743999999999).
        if ft == 0 || ft >= 2_650_467_743_990_000_000 {
            return None;
        }
        Some(Timestamp {
            ticks: ft,
            precision: Precision::FileTime,
        })
    }

    /// Decodes a 32-bit FAT date/time value as stored in shell items:
    /// the low word is the date, the high word is the time.
    pub fn from_fat(v: u32) -> Option<Timestamp> {
        let date = (v & 0xFFFF) as u16;
        let time = (v >> 16) as u16;
        Self::from_fat_parts(date, time)
    }

    pub fn from_fat_parts(date: u16, time: u16) -> Option<Timestamp> {
        if date == 0 && time == 0 {
            return None;
        }
        let day = (date & 0x1F) as u32;
        let month = ((date >> 5) & 0x0F) as u32;
        let year = 1980 + (date >> 9) as i64;
        let sec = ((time & 0x1F) as u32) * 2;
        let min = ((time >> 5) & 0x3F) as u32;
        let hour = ((time >> 11) & 0x1F) as u32;
        if !(1..=12).contains(&month) || day == 0 || day > days_in_month(year, month) {
            return None;
        }
        if hour > 23 || min > 59 || sec > 59 {
            return None;
        }
        let days = days_from_civil(year, month, day);
        let unix = days * 86_400 + (hour * 3600 + min * 60 + sec) as i64;
        let ticks = ((unix + EPOCH_DIFF_SECS) as u64) * TICKS_PER_SEC;
        Some(Timestamp {
            ticks,
            precision: Precision::Fat,
        })
    }

    /// OLE automation date: days since 1899-12-30 as f64.
    pub fn from_ole_date(d: f64) -> Option<Timestamp> {
        if !d.is_finite() || d == 0.0 {
            return None;
        }
        // 1899-12-30 is 109205 days after 1601-01-01.
        let ticks = (d + 109_205.0) * 86_400.0 * TICKS_PER_SEC as f64;
        if ticks <= 0.0 || ticks > 2.6e18 {
            return None;
        }
        Some(Timestamp {
            ticks: ticks as u64,
            precision: Precision::OleDate,
        })
    }

    /// Parses `YYYY-MM-DD`, `YYYY-MM-DD HH:MM[:SS]` or the `T`/`Z` ISO forms
    /// (interpreted as UTC). Used for CLI `--since`/`--until` filters.
    pub fn parse(s: &str) -> Option<Timestamp> {
        let s = s.trim().trim_end_matches('Z');
        let (date, time) = match s.split_once(['T', ' ']) {
            Some((d, t)) => (d, Some(t)),
            None => (s, None),
        };
        let mut dp = date.split('-');
        let y: i64 = dp.next()?.parse().ok()?;
        let m: u32 = dp.next()?.parse().ok()?;
        let d: u32 = dp.next()?.parse().ok()?;
        if !(1601..=9999).contains(&y)
            || !(1..=12).contains(&m)
            || d == 0
            || d > days_in_month(y, m)
        {
            return None;
        }
        let (mut hh, mut mm, mut ss, mut frac) = (0u32, 0u32, 0u32, 0u64);
        if let Some(t) = time {
            let mut tp = t.split(':');
            hh = tp.next()?.parse().ok()?;
            mm = tp.next().unwrap_or("0").parse().ok()?;
            if let Some(sec) = tp.next() {
                let (whole, f) = sec.split_once('.').unwrap_or((sec, ""));
                ss = whole.parse().ok()?;
                let f: String = f.chars().take(7).collect();
                if !f.is_empty() {
                    frac = format!("{f:0<7}").parse().ok()?;
                }
            }
        }
        if hh > 23 || mm > 59 || ss > 60 {
            return None;
        }
        let unix = days_from_civil(y, m, d) * 86_400 + (hh * 3600 + mm * 60 + ss) as i64;
        let ticks = ((unix + EPOCH_DIFF_SECS) as u64) * TICKS_PER_SEC + frac;
        Timestamp::from_filetime(ticks)
    }

    pub fn filetime(&self) -> u64 {
        self.ticks
    }

    pub fn precision(&self) -> Precision {
        self.precision
    }

    pub fn unix_seconds(&self) -> i64 {
        (self.ticks / TICKS_PER_SEC) as i64 - EPOCH_DIFF_SECS
    }

    /// Calendar components (UTC): year, month, day, hour, minute, second, ticks-in-second.
    pub fn components(&self) -> (i64, u32, u32, u32, u32, u32, u64) {
        let secs = self.unix_seconds();
        let frac = self.ticks % TICKS_PER_SEC;
        let days = secs.div_euclid(86_400);
        let sod = secs.rem_euclid(86_400) as u32;
        let (y, m, d) = civil_from_days(days);
        (y, m, d, sod / 3600, (sod / 60) % 60, sod % 60, frac)
    }

    /// ISO-8601 / RFC 3339 with 7 fractional digits for FILETIME precision.
    pub fn to_iso(&self) -> String {
        let (y, m, d, hh, mm, ss, frac) = self.components();
        match self.precision {
            Precision::FileTime | Precision::OleDate => {
                format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}.{frac:07}Z")
            }
            Precision::Fat => format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z"),
        }
    }

    /// Compact human form used by table output.
    pub fn to_short(&self) -> String {
        let (y, m, d, hh, mm, ss, _) = self.components();
        format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02}:{ss:02}")
    }

    /// Absolute difference in seconds.
    pub fn abs_diff_secs(&self, other: &Timestamp) -> u64 {
        self.ticks.abs_diff(other.ticks) / TICKS_PER_SEC
    }

    pub fn add_secs(&self, secs: i64) -> Timestamp {
        let delta = secs.unsigned_abs() * TICKS_PER_SEC;
        let ticks = if secs >= 0 {
            self.ticks.saturating_add(delta)
        } else {
            self.ticks.saturating_sub(delta)
        };
        Timestamp {
            ticks,
            precision: self.precision,
        }
    }

    /// Orders by instant only (ignores precision).
    pub fn cmp_instant(&self, other: &Timestamp) -> std::cmp::Ordering {
        self.ticks.cmp(&other.ticks)
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_iso())
    }
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_iso())
    }
}

pub fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

pub fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(y) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Days since 1970-01-01 for a proleptic Gregorian date (H. Hinnant).
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m = m as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Inverse of [`days_from_civil`].
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetime_roundtrip() {
        // 2016-10-09T20:04:37.8092483Z (plaso test value)
        let ts = Timestamp::parse("2016-10-09T20:04:37.8092483Z").unwrap();
        assert_eq!(ts.to_iso(), "2016-10-09T20:04:37.8092483Z");
        assert_eq!(Timestamp::from_filetime(ts.filetime()).unwrap(), ts);
    }

    #[test]
    fn unix_epoch() {
        let ts = Timestamp::from_filetime(116_444_736_000_000_000).unwrap();
        assert_eq!(ts.to_iso(), "1970-01-01T00:00:00.0000000Z");
        assert_eq!(ts.unix_seconds(), 0);
    }

    #[test]
    fn fat_decoding() {
        // 2010-04-11 13:22:30 -> date = (30<<9)|(4<<5)|11, time = (13<<11)|(22<<5)|15
        let date: u32 = (30 << 9) | (4 << 5) | 11;
        let time: u32 = (13 << 11) | (22 << 5) | 15;
        let ts = Timestamp::from_fat(date | (time << 16)).unwrap();
        assert_eq!(ts.to_iso(), "2010-04-11T13:22:30Z");
        assert_eq!(ts.precision(), Precision::Fat);
        assert!(Timestamp::from_fat(0).is_none());
        // month 13 is invalid
        assert!(Timestamp::from_fat((30 << 9) | (13 << 5) | 1).is_none());
    }

    #[test]
    fn ole_date() {
        // 2.0 => 1900-01-01
        let ts = Timestamp::from_ole_date(2.0).unwrap();
        assert_eq!(ts.to_short(), "1900-01-01 00:00:00");
    }

    #[test]
    fn civil_roundtrip() {
        for days in [-719_162i64, -1, 0, 1, 11_016, 20_000, 2_932_896] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days);
        }
    }
}
