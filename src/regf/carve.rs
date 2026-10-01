//! Recovery of deleted key (nk) and value (vk) records from unallocated
//! hive cells.
//!
//! When Windows frees a cell it flips the size to positive and may coalesce
//! it with neighbours, so one free cell can hold several remnant records.
//! Every remnant still starts on an 8-byte cell boundary, so we probe each
//! boundary inside free cells for an `nk`/`vk` signature and validate the
//! candidate structurally before accepting it.

use super::hive::Hive;
use super::records::{KeyNode, ValueNode, NONE_OFFSET};
use crate::util::bytes::{i32_at, u32_at};
use crate::util::Timestamp;

#[derive(Debug, Clone)]
pub struct RecoveredKey {
    pub node: KeyNode,
    /// Value records reachable from the remnant's value list.
    pub values: Vec<RecoveredValue>,
}

#[derive(Debug, Clone)]
pub struct RecoveredValue {
    pub node: ValueNode,
    pub data: Option<Vec<u8>>,
    /// True if the vk record itself sits in an allocated cell.
    pub vk_allocated: bool,
}

#[derive(Debug, Default)]
pub struct CarveResult {
    pub keys: Vec<RecoveredKey>,
    /// Free vk records not referenced by any recovered key.
    pub orphan_values: Vec<RecoveredValue>,
}

/// Plausible key timestamps: 1995 .. 2100.
fn plausible_time(raw: u64) -> bool {
    match Timestamp::from_filetime(raw) {
        Some(t) => {
            let (y, ..) = t.components();
            (1995..=2100).contains(&y)
        }
        None => false,
    }
}

fn plausible_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 512 && s.chars().all(|c| !c.is_control()) && !s.contains('\u{FFFD}')
}

/// Scans all free cells for remnant nk/vk records.
pub fn carve(hive: &Hive) -> CarveResult {
    let mut keys = Vec::new();
    let mut values = Vec::new();
    let data = &hive.data;
    for cell in hive.cells() {
        if cell.allocated {
            continue;
        }
        let cell_start = cell.offset as usize;
        let cell_end = cell_start + 4 + cell.data.len();
        let mut pos = cell_start;
        while pos + 8 <= cell_end {
            let sig = &data[pos + 4..pos + 6];
            // Remnant header: the original size (either sign) bounded by the free cell.
            let rem_size = i32_at(data, pos).unwrap_or(0).unsigned_abs() as usize;
            let rec_end = if rem_size >= 8 && pos + rem_size <= cell_end {
                pos + rem_size
            } else {
                cell_end
            };
            let rec = &data[pos + 4..rec_end];
            if sig == b"nk" {
                if let Ok(node) = KeyNode::parse(rec, pos as u32, false) {
                    if plausible_name(&node.name) && plausible_time(node.last_written_raw) {
                        keys.push(node);
                    }
                }
            } else if sig == b"vk" {
                if let Ok(node) = ValueNode::parse(rec, pos as u32, false) {
                    if node.data_type <= 11 && (node.name.is_empty() || plausible_name(&node.name))
                    {
                        values.push(node);
                    }
                }
            }
            pos += 8;
        }
    }

    let mut used_values = std::collections::HashSet::new();
    let mut out_keys = Vec::new();
    for node in keys {
        let mut vals = Vec::new();
        if node.value_count > 0 && node.value_count < 4096 && node.values_list != NONE_OFFSET {
            if let Some(list) = raw_cell(hive, node.values_list) {
                for i in 0..(node.value_count as usize).min(list.len() / 4) {
                    let off = u32_at(list, i * 4).unwrap_or(NONE_OFFSET);
                    if let Some((vnode, allocated)) = vk_at(hive, off) {
                        used_values.insert(off);
                        let data = read_data(hive, &vnode);
                        vals.push(RecoveredValue {
                            node: vnode,
                            data,
                            vk_allocated: allocated,
                        });
                    }
                }
            }
        }
        out_keys.push(RecoveredKey { node, values: vals });
    }
    let orphan_values = values
        .into_iter()
        .filter(|v| !used_values.contains(&v.offset))
        .map(|v| {
            let data = read_data(hive, &v);
            RecoveredValue {
                node: v,
                data,
                vk_allocated: false,
            }
        })
        .collect();
    CarveResult {
        keys: out_keys,
        orphan_values,
    }
}

/// Cell data regardless of allocation state.
fn raw_cell(hive: &Hive, offset: u32) -> Option<&[u8]> {
    if offset == NONE_OFFSET {
        return None;
    }
    let o = offset as usize;
    let size = i32_at(&hive.data, o)?.unsigned_abs() as usize;
    if size < 8 || o + size > hive.data.len() {
        return None;
    }
    Some(&hive.data[o + 4..o + size])
}

fn vk_at(hive: &Hive, offset: u32) -> Option<(ValueNode, bool)> {
    let o = offset as usize;
    let allocated = i32_at(&hive.data, o)? < 0;
    let rec = raw_cell(hive, offset)?;
    ValueNode::parse(rec, offset, allocated)
        .ok()
        .filter(|v| v.data_type <= 11)
        .map(|v| (v, allocated))
}

/// Best-effort data read for a remnant value. Returns None when the data
/// cell has obviously been reused.
fn read_data(hive: &Hive, v: &ValueNode) -> Option<Vec<u8>> {
    let size = v.data_size() as usize;
    if size == 0 {
        return Some(Vec::new());
    }
    if v.is_resident() {
        return Some(v.data_offset.to_le_bytes()[..size.min(4)].to_vec());
    }
    if size > 16_344 {
        return None;
    }
    let cell = raw_cell(hive, v.data_offset)?;
    if cell.len() < size {
        return None;
    }
    Some(cell[..size].to_vec())
}
