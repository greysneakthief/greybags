//! Serialized property store (SPS, "1SPS") and WPD property array parsing.

use super::dissect::Dis;
use crate::util::bytes::{self, f64_at, i16_at, u16_at, u32_at, u64_at};
use crate::util::known;
use crate::util::{Guid, Timestamp};
use serde::Serialize;
use std::fmt;

/// FMTID whose records are keyed by name instead of numeric id.
const FMTID_USER_DEFINED: &str = "d5cdd505-2e9c-101b-9397-08002b2cf9ae";
const SPS_MAGIC: &[u8; 4] = b"1SPS";

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum PropValue {
    Str(String),
    Int(i64),
    UInt(u64),
    Bool(bool),
    Time(Timestamp),
    Guid(Guid),
    Float(f64),
    Bytes(String),
    List(Vec<PropValue>),
    Unsupported(String),
}

impl fmt::Display for PropValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PropValue::Str(s) => write!(f, "{s}"),
            PropValue::Int(v) => write!(f, "{v}"),
            PropValue::UInt(v) => write!(f, "{v}"),
            PropValue::Bool(v) => write!(f, "{v}"),
            PropValue::Time(t) => write!(f, "{t}"),
            PropValue::Guid(g) => write!(f, "{g}"),
            PropValue::Float(v) => write!(f, "{v}"),
            PropValue::Bytes(h) => write!(f, "0x{h}"),
            PropValue::List(l) => {
                let parts: Vec<String> = l.iter().map(|v| v.to_string()).collect();
                write!(f, "[{}]", parts.join(", "))
            }
            PropValue::Unsupported(s) => write!(f, "<{s}>"),
        }
    }
}

impl PropValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            PropValue::Str(s) => Some(s),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Property {
    pub fmtid: Guid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Canonical property key name, e.g. `System.ItemNameDisplay`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<&'static str>,
    pub vt: u16,
    pub value: PropValue,
}

impl Property {
    pub fn label(&self) -> String {
        if let Some(k) = self.key {
            return k.to_string();
        }
        match (&self.name, self.id) {
            (Some(n), _) => format!("{{{}}}/{n}", self.fmtid),
            (None, Some(id)) => format!("{{{}}}/{id}", self.fmtid),
            _ => format!("{{{}}}", self.fmtid),
        }
    }

    pub fn is(&self, key: &str) -> bool {
        self.key == Some(key)
    }
}

/// Decodes a typed value whose data begins at `off` (after the VARTYPE).
/// Returns the value and the number of data bytes consumed.
pub fn typed_value(b: &[u8], off: usize, vt: u16) -> (PropValue, usize) {
    if vt & 0x1000 != 0 {
        // VT_VECTOR | base type
        let base = vt & 0x0FFF;
        let Some(count) = u32_at(b, off) else {
            return (PropValue::Unsupported("truncated vector".into()), 0);
        };
        let mut pos = off + 4;
        let mut items = Vec::new();
        for _ in 0..count.min(1024) {
            let (v, n) = typed_value(b, pos, base);
            if n == 0 {
                break;
            }
            items.push(v);
            pos += n;
            if base == 0x1F || base == 0x1E {
                pos = (pos + 3) & !3; // string vector elements are 4-byte aligned
            }
        }
        return (PropValue::List(items), pos - off);
    }
    let r = match vt {
        0x0000 | 0x0001 => (
            PropValue::Unsupported(if vt == 0 { "VT_EMPTY" } else { "VT_NULL" }.into()),
            0,
        ),
        0x0002 => (i16_at(b, off).map(|v| PropValue::Int(v as i64)), 2).into_pair(),
        0x0012 => (u16_at(b, off).map(|v| PropValue::UInt(v as u64)), 2).into_pair(),
        0x0003 | 0x0016 => (u32_at(b, off).map(|v| PropValue::Int(v as i32 as i64)), 4).into_pair(),
        0x0013 | 0x0017 | 0x000A => {
            (u32_at(b, off).map(|v| PropValue::UInt(v as u64)), 4).into_pair()
        }
        0x0014 => (u64_at(b, off).map(|v| PropValue::Int(v as i64)), 8).into_pair(),
        0x0015 => (u64_at(b, off).map(PropValue::UInt), 8).into_pair(),
        0x0010 => (b.get(off).map(|&v| PropValue::Int(v as i8 as i64)), 1).into_pair(),
        0x0011 => (b.get(off).map(|&v| PropValue::UInt(v as u64)), 1).into_pair(),
        0x000B => (i16_at(b, off).map(|v| PropValue::Bool(v != 0)), 2).into_pair(),
        0x0004 => (
            u32_at(b, off).map(|v| PropValue::Float(f32::from_bits(v) as f64)),
            4,
        )
            .into_pair(),
        0x0005 => (f64_at(b, off).map(PropValue::Float), 8).into_pair(),
        0x0007 => (
            f64_at(b, off).map(|d| match Timestamp::from_ole_date(d) {
                Some(t) => PropValue::Time(t),
                None => PropValue::Float(d),
            }),
            8,
        )
            .into_pair(),
        0x0040 => (
            u64_at(b, off).map(|v| match Timestamp::from_filetime(v) {
                Some(t) => PropValue::Time(t),
                None => PropValue::UInt(v),
            }),
            8,
        )
            .into_pair(),
        0x0048 => (Guid::at(b, off).map(PropValue::Guid), 16).into_pair(),
        0x001F => {
            // VT_LPWSTR: character count (including NUL) then UTF-16LE.
            match u32_at(b, off) {
                Some(n) if (n as usize) * 2 <= b.len().saturating_sub(off + 4) => {
                    let s = bytes::utf16n_at(b, off + 4, n as usize).unwrap_or_default();
                    (PropValue::Str(s), 4 + n as usize * 2)
                }
                _ => (PropValue::Unsupported("truncated VT_LPWSTR".into()), 0),
            }
        }
        0x0008 => {
            // VT_BSTR: byte length then UTF-16LE.
            match u32_at(b, off) {
                Some(n) if (n as usize) <= b.len().saturating_sub(off + 4) => {
                    let s = bytes::utf16le_lossy(&b[off + 4..off + 4 + (n as usize & !1)]);
                    (
                        PropValue::Str(s.trim_end_matches('\0').to_string()),
                        4 + n as usize,
                    )
                }
                _ => (PropValue::Unsupported("truncated VT_BSTR".into()), 0),
            }
        }
        0x001E => match u32_at(b, off) {
            Some(n) if (n as usize) <= b.len().saturating_sub(off + 4) => {
                let s = bytes::latin1(&b[off + 4..off + 4 + n as usize]);
                (
                    PropValue::Str(s.trim_end_matches('\0').to_string()),
                    4 + n as usize,
                )
            }
            _ => (PropValue::Unsupported("truncated VT_LPSTR".into()), 0),
        },
        0x0041 | 0x0046 => match u32_at(b, off) {
            Some(n) if (n as usize) <= b.len().saturating_sub(off + 4) => {
                let shown = &b[off + 4..off + 4 + (n as usize).min(256)];
                (PropValue::Bytes(bytes::to_hex(shown)), 4 + n as usize)
            }
            _ => (PropValue::Unsupported("truncated VT_BLOB".into()), 0),
        },
        other => (PropValue::Unsupported(format!("VT 0x{other:04x}")), 0),
    };
    r
}

trait IntoPair {
    fn into_pair(self) -> (PropValue, usize);
}

impl IntoPair for (Option<PropValue>, usize) {
    fn into_pair(self) -> (PropValue, usize) {
        match self.0 {
            Some(v) => (v, self.1),
            None => (PropValue::Unsupported("truncated".into()), 0),
        }
    }
}

/// Parses consecutive property sets starting at `off` (each beginning with
/// its 4-byte size followed by "1SPS"). Stops at a zero size or garbage.
/// Returns the properties and the end offset reached.
pub fn parse_sets(d: &mut Dis, off: usize) -> (Vec<Property>, usize) {
    let mut props = Vec::new();
    let mut pos = off;
    for _ in 0..64 {
        let Some(size) = u32_at(d.data, pos) else {
            break;
        };
        if size == 0 {
            d.note(pos, 4, "Property store terminator", "0");
            pos += 4;
            break;
        }
        let size = size as usize;
        if size < 24 || pos + size > d.len() || d.data.get(pos + 4..pos + 8) != Some(SPS_MAGIC) {
            break;
        }
        d.u32(pos, "Property set size");
        d.sig(pos + 4, "Property set version (1SPS)");
        let Some(fmtid) = d.guid(pos + 8, "Format identifier (FMTID)") else {
            break;
        };
        let named = fmtid.to_string() == FMTID_USER_DEFINED;
        let mut rpos = pos + 24;
        let set_end = pos + size;
        while rpos + 4 <= set_end {
            let rsize = u32_at(d.data, rpos).unwrap_or(0) as usize;
            if rsize == 0 {
                d.note(rpos, 4, "Property record terminator", "0");
                break;
            }
            if rsize < 9 || rpos + rsize > set_end {
                d.note(rpos, 4, "Invalid property record size", rsize.to_string());
                break;
            }
            let rec = &d.data[rpos..rpos + rsize];
            let (id, name, tv_off) = if named {
                let nlen = u32_at(rec, 4).unwrap_or(0) as usize;
                let name = bytes::utf16le_lossy(rec.get(9..9 + nlen).unwrap_or(&[]))
                    .trim_end_matches('\0')
                    .to_string();
                (None, Some(name), 9 + nlen)
            } else {
                (u32_at(rec, 4), None, 9)
            };
            let vt = u16_at(rec, tv_off).unwrap_or(0);
            let (value, _) = typed_value(rec, tv_off + 4, vt);
            let key = id.and_then(|i| known::property_name(&fmtid, i));
            let prop = Property {
                fmtid,
                id,
                name,
                key,
                vt,
                value,
            };
            d.note(
                rpos,
                rsize,
                &format!("Property {}", prop.label()),
                format!("VT 0x{vt:04x} = {}", prop.value),
            );
            props.push(prop);
            rpos += rsize;
        }
        pos = set_end;
    }
    (props, pos)
}

/// Locates every serialized property set ("1SPS") in a buffer and parses
/// it, skipping ranges already consumed. Used as a generic fallback for
/// shell items whose exact layout is undocumented.
pub fn scan(d: &mut Dis, from: usize, skip: &[(usize, usize)]) -> Vec<Property> {
    let mut out = Vec::new();
    let mut search = from;
    while let Some(p) = bytes::find(d.data, SPS_MAGIC, search) {
        search = p + 4;
        if p < 4 || skip.iter().any(|&(s, e)| p >= s && p < e) {
            continue;
        }
        let (props, end) = parse_sets(d, p - 4);
        if !props.is_empty() {
            out.extend(props);
            search = end.max(search);
        }
    }
    out
}

/// Parses a WPD/PortableDeviceValues property array:
/// count(4) followed by {FMTID(16), PID(4), VT(4), value}.
pub fn parse_wpd_array(d: &mut Dis, off: usize) -> (Vec<Property>, usize) {
    let mut out = Vec::new();
    let Some(count) = u32_at(d.data, off) else {
        return (out, off);
    };
    if count > 256 {
        return (out, off);
    }
    d.u32(off, "Number of WPD properties");
    let mut pos = off + 4;
    for _ in 0..count {
        let Some(fmtid) = Guid::at(d.data, pos) else {
            break;
        };
        let Some(pid) = u32_at(d.data, pos + 16) else {
            break;
        };
        let Some(vt) = u32_at(d.data, pos + 20) else {
            break;
        };
        let (value, n) = typed_value(d.data, pos + 24, vt as u16);
        if n == 0 {
            break;
        }
        let key = known::property_name(&fmtid, pid);
        let prop = Property {
            fmtid,
            id: Some(pid),
            name: None,
            key,
            vt: vt as u16,
            value,
        };
        let len = 24 + n;
        d.note(
            pos,
            len,
            &format!("WPD property {}", prop.label()),
            prop.value.to_string(),
        );
        out.push(prop);
        pos += len;
        pos = (pos + 3) & !3;
    }
    (out, pos)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_users_property_view_store() {
        // From a Windows 7 NTUSER.DAT (plaso test data): property set with
        // System.ItemNameDisplay = "controller".
        let mut b = Vec::new();
        let name: Vec<u8> = "controller\0"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let mut rec = Vec::new();
        rec.extend_from_slice(&0u32.to_le_bytes()); // size placeholder
        rec.extend_from_slice(&10u32.to_le_bytes());
        rec.push(0);
        rec.extend_from_slice(&0x1Fu16.to_le_bytes());
        rec.extend_from_slice(&0u16.to_le_bytes());
        rec.extend_from_slice(&11u32.to_le_bytes());
        rec.extend_from_slice(&name);
        let rlen = rec.len() as u32;
        rec[0..4].copy_from_slice(&rlen.to_le_bytes());
        let fmtid = Guid::parse("b725f130-47ef-101a-a5f1-02608c9eebac").unwrap();
        let set_len = 24 + rec.len() + 4;
        b.extend_from_slice(&(set_len as u32).to_le_bytes());
        b.extend_from_slice(b"1SPS");
        b.extend_from_slice(&fmtid.0);
        b.extend_from_slice(&rec);
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        let mut d = Dis::new(&b, true);
        let props = scan(&mut d, 0, &[]);
        assert_eq!(props.len(), 1);
        assert_eq!(props[0].key, Some("System.ItemNameDisplay"));
        assert_eq!(props[0].value.as_str(), Some("controller"));
    }
}
