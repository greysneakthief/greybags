//! Windows GUID (mixed-endian) handling.

use serde::{Serialize, Serializer};
use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Guid(pub [u8; 16]);

impl Guid {
    /// Reads a GUID in Windows on-disk layout (Data1..Data3 little-endian).
    pub fn from_le_bytes(b: &[u8]) -> Option<Guid> {
        let s = b.get(..16)?;
        let mut a = [0u8; 16];
        a.copy_from_slice(s);
        Some(Guid(a))
    }

    pub fn at(b: &[u8], off: usize) -> Option<Guid> {
        Guid::from_le_bytes(b.get(off..)?)
    }

    /// Parses the canonical textual form, with or without braces.
    pub fn parse(s: &str) -> Option<Guid> {
        let s = s.trim().trim_start_matches('{').trim_end_matches('}');
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 5
            || parts[0].len() != 8
            || parts[1].len() != 4
            || parts[2].len() != 4
            || parts[3].len() != 4
            || parts[4].len() != 12
        {
            return None;
        }
        let d1 = u32::from_str_radix(parts[0], 16).ok()?;
        let d2 = u16::from_str_radix(parts[1], 16).ok()?;
        let d3 = u16::from_str_radix(parts[2], 16).ok()?;
        let tail = format!("{}{}", parts[3], parts[4]);
        let mut a = [0u8; 16];
        a[0..4].copy_from_slice(&d1.to_le_bytes());
        a[4..6].copy_from_slice(&d2.to_le_bytes());
        a[6..8].copy_from_slice(&d3.to_le_bytes());
        for i in 0..8 {
            a[8 + i] = u8::from_str_radix(&tail[i * 2..i * 2 + 2], 16).ok()?;
        }
        Some(Guid(a))
    }

    /// Like [`Guid::parse`] but panics; for compile-time-known constants.
    pub fn must(s: &str) -> Guid {
        Guid::parse(s).unwrap_or_else(|| panic!("invalid GUID literal {s}"))
    }

    pub fn is_nil(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }

    pub fn to_bytes(&self) -> [u8; 16] {
        self.0
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let a = &self.0;
        write!(
            f,
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            u32::from_le_bytes([a[0], a[1], a[2], a[3]]),
            u16::from_le_bytes([a[4], a[5]]),
            u16::from_le_bytes([a[6], a[7]]),
            a[8],
            a[9],
            a[10],
            a[11],
            a[12],
            a[13],
            a[14],
            a[15]
        )
    }
}

impl fmt::Debug for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{{self}}}")
    }
}

impl Serialize for Guid {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn my_computer_layout() {
        // Bytes as they appear in the classic "My Computer" root shell item.
        let raw = [
            0xE0, 0x4F, 0xD0, 0x20, 0xEA, 0x3A, 0x69, 0x10, 0xA2, 0xD8, 0x08, 0x00, 0x2B, 0x30,
            0x30, 0x9D,
        ];
        let g = Guid::from_le_bytes(&raw).unwrap();
        assert_eq!(g.to_string(), "20d04fe0-3aea-1069-a2d8-08002b30309d");
        assert_eq!(
            Guid::parse("{20D04FE0-3AEA-1069-A2D8-08002B30309D}"),
            Some(g)
        );
    }
}
