//! Parsers for individual cell records (nk, vk, subkey lists, db).
//!
//! These operate on raw cell data slices so they can be reused both for
//! normal tree traversal and for carving remnants out of unallocated cells.

use super::error::{RegfError, Result};
use crate::util::bytes::{latin1, u16_at, u32_at, u64_at, utf16le_lossy};
use crate::util::Timestamp;

pub const NONE_OFFSET: u32 = 0xFFFF_FFFF;

pub const KEY_HIVE_ENTRY: u16 = 0x0004;
pub const KEY_COMP_NAME: u16 = 0x0020;
pub const VALUE_COMP_NAME: u16 = 0x0001;

#[derive(Debug, Clone)]
pub struct KeyNode {
    /// Offset of the cell (relative to hive bins data).
    pub offset: u32,
    pub allocated: bool,
    pub flags: u16,
    pub last_written_raw: u64,
    pub access_bits: u32,
    pub parent: u32,
    pub subkey_count: u32,
    pub subkeys_list: u32,
    pub value_count: u32,
    pub values_list: u32,
    pub security: u32,
    pub class_name_offset: u32,
    pub class_name_len: u16,
    pub name: String,
}

impl KeyNode {
    /// Minimum fixed-size portion of an nk record.
    pub const FIXED: usize = 76;

    pub fn parse(data: &[u8], offset: u32, allocated: bool) -> Result<KeyNode> {
        if data.len() < Self::FIXED {
            return Err(RegfError::BadCell {
                offset,
                reason: "nk record truncated".into(),
            });
        }
        if &data[0..2] != b"nk" {
            return Err(RegfError::BadRecord {
                offset,
                expected: "nk",
                found: [data[0], data[1]],
            });
        }
        let flags = u16_at(data, 2).unwrap_or(0);
        let name_len = u16_at(data, 72).unwrap_or(0) as usize;
        let name_bytes = data
            .get(76..76 + name_len)
            .ok_or_else(|| RegfError::BadCell {
                offset,
                reason: "nk name truncated".into(),
            })?;
        let name = if flags & KEY_COMP_NAME != 0 {
            latin1(name_bytes)
        } else {
            utf16le_lossy(name_bytes)
        };
        let r = |o| u32_at(data, o).unwrap_or(0);
        Ok(KeyNode {
            offset,
            allocated,
            flags,
            last_written_raw: u64_at(data, 4).unwrap_or(0),
            access_bits: r(12),
            parent: r(16),
            subkey_count: r(20),
            subkeys_list: r(28),
            value_count: r(36),
            values_list: r(40),
            security: r(44),
            class_name_offset: r(48),
            class_name_len: u16_at(data, 74).unwrap_or(0),
            name,
        })
    }

    pub fn last_written(&self) -> Option<Timestamp> {
        Timestamp::from_filetime(self.last_written_raw)
    }

    pub fn is_root(&self) -> bool {
        self.flags & KEY_HIVE_ENTRY != 0
    }
}

#[derive(Debug, Clone)]
pub struct ValueNode {
    pub offset: u32,
    pub allocated: bool,
    pub name: String,
    pub data_size_raw: u32,
    pub data_offset: u32,
    pub data_type: u32,
    pub flags: u16,
}

impl ValueNode {
    pub const FIXED: usize = 20;

    pub fn parse(data: &[u8], offset: u32, allocated: bool) -> Result<ValueNode> {
        if data.len() < Self::FIXED {
            return Err(RegfError::BadCell {
                offset,
                reason: "vk record truncated".into(),
            });
        }
        if &data[0..2] != b"vk" {
            return Err(RegfError::BadRecord {
                offset,
                expected: "vk",
                found: [data[0], data[1]],
            });
        }
        let name_len = u16_at(data, 2).unwrap_or(0) as usize;
        let flags = u16_at(data, 16).unwrap_or(0);
        let name_bytes = data
            .get(20..20 + name_len)
            .ok_or_else(|| RegfError::BadCell {
                offset,
                reason: "vk name truncated".into(),
            })?;
        let name = if flags & VALUE_COMP_NAME != 0 {
            latin1(name_bytes)
        } else {
            utf16le_lossy(name_bytes)
        };
        Ok(ValueNode {
            offset,
            allocated,
            name,
            data_size_raw: u32_at(data, 4).unwrap_or(0),
            data_offset: u32_at(data, 8).unwrap_or(0),
            data_type: u32_at(data, 12).unwrap_or(0),
            flags,
        })
    }

    pub fn data_size(&self) -> u32 {
        self.data_size_raw & 0x7FFF_FFFF
    }

    pub fn is_resident(&self) -> bool {
        self.data_size_raw & 0x8000_0000 != 0
    }

    /// Display name: the unnamed default value is shown as "(default)".
    pub fn display_name(&self) -> &str {
        if self.name.is_empty() {
            "(default)"
        } else {
            &self.name
        }
    }
}

pub fn data_type_name(t: u32) -> &'static str {
    match t {
        0 => "REG_NONE",
        1 => "REG_SZ",
        2 => "REG_EXPAND_SZ",
        3 => "REG_BINARY",
        4 => "REG_DWORD",
        5 => "REG_DWORD_BIG_ENDIAN",
        6 => "REG_LINK",
        7 => "REG_MULTI_SZ",
        8 => "REG_RESOURCE_LIST",
        9 => "REG_FULL_RESOURCE_DESCRIPTOR",
        10 => "REG_RESOURCE_REQUIREMENTS_LIST",
        11 => "REG_QWORD",
        _ => "REG_UNKNOWN",
    }
}

/// Kind of subkey list record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListKind {
    /// li: plain offsets.
    IndexLeaf,
    /// lf: offset + 4-byte name hint.
    FastLeaf,
    /// lh: offset + 4-byte name hash.
    HashLeaf,
    /// ri: offsets of other lists.
    IndexRoot,
}

/// Parses a subkey list cell, returning its kind and element offsets.
pub fn parse_subkey_list(data: &[u8], offset: u32) -> Result<(ListKind, Vec<u32>)> {
    if data.len() < 4 {
        return Err(RegfError::BadCell {
            offset,
            reason: "subkey list truncated".into(),
        });
    }
    let kind = match &data[0..2] {
        b"li" => ListKind::IndexLeaf,
        b"lf" => ListKind::FastLeaf,
        b"lh" => ListKind::HashLeaf,
        b"ri" => ListKind::IndexRoot,
        other => {
            return Err(RegfError::BadRecord {
                offset,
                expected: "li/lf/lh/ri",
                found: [other[0], other[1]],
            })
        }
    };
    let count = u16_at(data, 2).unwrap_or(0) as usize;
    let stride = match kind {
        ListKind::FastLeaf | ListKind::HashLeaf => 8,
        _ => 4,
    };
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        match u32_at(data, 4 + i * stride) {
            Some(v) => out.push(v),
            None => break,
        }
    }
    Ok((kind, out))
}

/// Windows "lh" name hash (used by the test hive writer).
pub fn lh_hash(name: &str) -> u32 {
    let mut h: u32 = 0;
    for c in name.to_uppercase().encode_utf16() {
        h = h.wrapping_mul(37).wrapping_add(c as u32);
    }
    h
}
