//! Field-level annotation ("dissection") of binary structures.
//!
//! Every parser reads through a [`Dis`] cursor, which both decodes values and
//! optionally records `(offset, size, name, value)` tuples. The recorded
//! fields drive the `greybags item` hex-annotated view, the same way a packet
//! dissector labels bytes on the wire.

use crate::util::bytes::{self, u16_at, u32_at, u64_at, u8_at};
use crate::util::{Guid, Timestamp};
use encoding_rs::Encoding;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Field {
    pub offset: usize,
    pub size: usize,
    pub name: String,
    pub value: String,
}

pub struct Dis<'a> {
    pub data: &'a [u8],
    /// Absolute offset (within the shell item) of `data[0]`.
    pub base: usize,
    pub enabled: bool,
    pub fields: Vec<Field>,
}

impl<'a> Dis<'a> {
    pub fn new(data: &'a [u8], enabled: bool) -> Dis<'a> {
        Dis {
            data,
            base: 0,
            enabled,
            fields: Vec::new(),
        }
    }

    /// A cursor over `data[start..start+len]` whose recorded offsets remain
    /// absolute. Merge it back with [`Dis::absorb`].
    pub fn sub(&self, start: usize, len: usize) -> Dis<'a> {
        let end = (start + len).min(self.data.len());
        let start = start.min(end);
        Dis {
            data: &self.data[start..end],
            base: self.base + start,
            enabled: self.enabled,
            fields: Vec::new(),
        }
    }

    pub fn absorb(&mut self, other: Dis<'_>) {
        self.fields.extend(other.fields);
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn note(&mut self, off: usize, size: usize, name: &str, value: impl Into<String>) {
        if self.enabled {
            self.fields.push(Field {
                offset: self.base + off,
                size,
                name: name.to_string(),
                value: value.into(),
            });
        }
    }

    pub fn u8(&mut self, off: usize, name: &str) -> Option<u8> {
        let v = u8_at(self.data, off)?;
        self.note(off, 1, name, format!("0x{v:02x} ({v})"));
        Some(v)
    }

    pub fn u16(&mut self, off: usize, name: &str) -> Option<u16> {
        let v = u16_at(self.data, off)?;
        self.note(off, 2, name, format!("0x{v:04x} ({v})"));
        Some(v)
    }

    pub fn u32(&mut self, off: usize, name: &str) -> Option<u32> {
        let v = u32_at(self.data, off)?;
        self.note(off, 4, name, format!("0x{v:08x} ({v})"));
        Some(v)
    }

    pub fn u64(&mut self, off: usize, name: &str) -> Option<u64> {
        let v = u64_at(self.data, off)?;
        self.note(off, 8, name, format!("0x{v:016x} ({v})"));
        Some(v)
    }

    pub fn sig(&mut self, off: usize, name: &str) -> Option<u32> {
        let v = u32_at(self.data, off)?;
        let ascii: String = v
            .to_le_bytes()
            .iter()
            .map(|&c| {
                if (0x20..0x7f).contains(&c) {
                    c as char
                } else {
                    '.'
                }
            })
            .collect();
        self.note(off, 4, name, format!("0x{v:08x} \"{ascii}\""));
        Some(v)
    }

    pub fn guid(&mut self, off: usize, name: &str) -> Option<Guid> {
        let g = Guid::at(self.data, off)?;
        let label = crate::util::known::shell_folder(&g)
            .or_else(|| crate::util::known::folder_type(&g))
            .map(|n| format!(" ({n})"))
            .unwrap_or_default();
        self.note(off, 16, name, format!("{g}{label}"));
        Some(g)
    }

    pub fn fat(&mut self, off: usize, name: &str) -> Option<Timestamp> {
        let raw = u32_at(self.data, off)?;
        let ts = Timestamp::from_fat(raw);
        let shown = match ts {
            Some(t) => t.to_iso(),
            None if raw == 0 => "not set".to_string(),
            None => "invalid".to_string(),
        };
        self.note(off, 4, name, format!("0x{raw:08x} -> {shown}"));
        ts
    }

    pub fn filetime(&mut self, off: usize, name: &str) -> Option<Timestamp> {
        let raw = u64_at(self.data, off)?;
        let ts = Timestamp::from_filetime(raw);
        let shown = match ts {
            Some(t) => t.to_iso(),
            None if raw == 0 => "not set".to_string(),
            None => "invalid".to_string(),
        };
        self.note(off, 8, name, format!("0x{raw:016x} -> {shown}"));
        ts
    }

    /// NUL-terminated UTF-16LE string. Returns (string, bytes consumed).
    pub fn utf16z(&mut self, off: usize, name: &str) -> Option<(String, usize)> {
        let (s, n) = bytes::utf16z_at(self.data, off)?;
        self.note(off, n, name, format!("\"{s}\""));
        Some((s, n))
    }

    /// Fixed-length UTF-16LE string of `chars` code units.
    pub fn utf16n(&mut self, off: usize, chars: usize, name: &str) -> Option<String> {
        let s = bytes::utf16n_at(self.data, off, chars)?;
        self.note(off, chars * 2, name, format!("\"{s}\""));
        Some(s)
    }

    /// NUL-terminated code-page string. Returns (string, bytes consumed).
    pub fn ansiz(
        &mut self,
        off: usize,
        name: &str,
        enc: &'static Encoding,
    ) -> Option<(String, usize)> {
        let (s, n) = bytes::ansiz_at(self.data, off, enc)?;
        self.note(off, n, name, format!("\"{s}\""));
        Some((s, n))
    }
}
