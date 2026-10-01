//! In-memory registry hive with key/value navigation.

use super::base::{BaseBlock, BASE_BLOCK_SIZE};
use super::error::{RegfError, Result};
use super::log::{self, LogFile, RecoveryReport};
use super::records::{parse_subkey_list, KeyNode, ListKind, ValueNode, NONE_OFFSET};
use crate::util::bytes::{i32_at, u16_at, u32_at, utf16le_lossy};
use crate::util::Timestamp;
use serde::Serialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Big-data threshold: values larger than this use a `db` record (v1.4+).
const BIG_DATA_THRESHOLD: u32 = 16_344;
/// Defensive cap on list sizes and recursion.
const MAX_LIST_DEPTH: usize = 8;

#[derive(Debug, Clone, Serialize)]
pub struct HiveBin {
    pub offset: u32,
    pub size: u32,
    #[serde(skip)]
    pub timestamp_raw: u64,
}

#[derive(Debug, Clone, Default)]
pub struct OpenOptions {
    /// Replay transaction logs found next to the hive when it is dirty.
    pub apply_logs: bool,
    /// Explicit transaction log paths (overrides auto-discovery).
    pub log_paths: Vec<PathBuf>,
}

impl OpenOptions {
    pub fn with_logs() -> Self {
        OpenOptions {
            apply_logs: true,
            log_paths: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub struct Hive {
    pub path: Option<PathBuf>,
    pub base: BaseBlock,
    /// Hive bins data (file offset 4096 onwards, possibly recovered).
    pub data: Vec<u8>,
    pub bins: Vec<HiveBin>,
    /// True if the primary file was dirty when opened.
    pub was_dirty: bool,
    pub recovery: Option<RecoveryReport>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct CellRef<'h> {
    pub offset: u32,
    pub allocated: bool,
    /// Cell data without the 4-byte size header.
    pub data: &'h [u8],
}

impl Hive {
    /// Opens a hive file. When `opts.apply_logs` is set and the hive is dirty,
    /// sibling `.LOG`, `.LOG1` and `.LOG2` files are replayed in memory (the
    /// evidence file is never modified).
    pub fn open(path: &Path, opts: &OpenOptions) -> Result<Hive> {
        let bytes = std::fs::read(path)?;
        let mut logs = Vec::new();
        if opts.apply_logs {
            let candidates = if opts.log_paths.is_empty() {
                log::discover_logs(path)
            } else {
                opts.log_paths.clone()
            };
            for p in candidates {
                match std::fs::read(&p) {
                    Ok(b) if !b.is_empty() => logs.push((p.display().to_string(), b)),
                    _ => {}
                }
            }
        }
        let mut hive = Hive::from_bytes_with_logs(bytes, logs, opts.apply_logs)?;
        hive.path = Some(path.to_path_buf());
        Ok(hive)
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Hive> {
        Hive::from_bytes_with_logs(bytes, Vec::new(), false)
    }

    pub fn from_bytes_with_logs(
        mut bytes: Vec<u8>,
        logs: Vec<(String, Vec<u8>)>,
        apply_logs: bool,
    ) -> Result<Hive> {
        if bytes.len() < 512 {
            return Err(RegfError::TooSmall(bytes.len()));
        }
        let mut warnings = Vec::new();
        let mut base = BaseBlock::parse(&bytes)?;
        if base.is_log() {
            return Err(RegfError::Other(format!(
                "file is a transaction log (file type {}), not a primary hive",
                base.file_type
            )));
        }
        if bytes.len() < BASE_BLOCK_SIZE {
            bytes.resize(BASE_BLOCK_SIZE, 0);
        }
        let mut data = bytes.split_off(BASE_BLOCK_SIZE);
        let was_dirty = base.is_dirty();
        if !base.checksum_valid() {
            warnings.push(format!(
                "base block checksum mismatch (stored 0x{:08x}, computed 0x{:08x})",
                base.stored_checksum, base.computed_checksum
            ));
        }
        let mut recovery = None;
        if was_dirty {
            if apply_logs && !logs.is_empty() {
                let parsed: Vec<LogFile> = logs
                    .into_iter()
                    .filter_map(|(n, b)| LogFile::parse(n, b).ok())
                    .collect();
                let report = log::recover(&mut base, &mut data, &parsed);
                warnings.extend(report.warnings.iter().cloned());
                recovery = Some(report);
            } else if apply_logs {
                warnings.push(format!(
                    "hive is dirty ({}) and no transaction logs were found; recent changes may be missing",
                    dirty_reason(&base)
                ));
            } else {
                warnings.push(format!(
                    "hive is dirty ({}); transaction logs were not applied",
                    dirty_reason(&base)
                ));
            }
        }
        // Trust the declared hive bins size only if the file actually holds it.
        let declared = base.hive_bins_data_size as usize;
        if declared > 0 && declared < data.len() {
            // Remnant data after the last bin is ignored for navigation but
            // kept out of the cell space.
            data.truncate(declared);
        } else if declared > data.len() {
            warnings.push(format!(
                "hive bins data size 0x{declared:x} exceeds file size (0x{:x}); hive is truncated",
                data.len()
            ));
        }
        let bins = scan_bins(&data, &mut warnings);
        Ok(Hive {
            path: None,
            base,
            data,
            bins,
            was_dirty,
            recovery,
            warnings,
        })
    }

    /// Returns the cell at `offset` (relative to hive bins data).
    pub fn cell(&self, offset: u32) -> Result<CellRef<'_>> {
        if offset == NONE_OFFSET {
            return Err(RegfError::OffsetOutOfRange(offset));
        }
        let o = offset as usize;
        let size = i32_at(&self.data, o).ok_or(RegfError::OffsetOutOfRange(offset))?;
        let allocated = size < 0;
        let abs = size.unsigned_abs() as usize;
        if abs < 8 {
            return Err(RegfError::BadCell {
                offset,
                reason: format!("implausible cell size {size}"),
            });
        }
        let end = o
            .checked_add(abs)
            .ok_or(RegfError::OffsetOutOfRange(offset))?;
        let end = if end > self.data.len() {
            if o + 4 >= self.data.len() {
                return Err(RegfError::OffsetOutOfRange(offset));
            }
            self.data.len()
        } else {
            end
        };
        Ok(CellRef {
            offset,
            allocated,
            data: &self.data[o + 4..end],
        })
    }

    pub fn root(&self) -> Result<Key<'_>> {
        self.key_at(self.base.root_cell_offset)
    }

    pub fn key_at(&self, offset: u32) -> Result<Key<'_>> {
        let cell = self.cell(offset)?;
        let node = KeyNode::parse(cell.data, offset, cell.allocated)?;
        Ok(Key { hive: self, node })
    }

    pub fn value_at(&self, offset: u32) -> Result<Value<'_>> {
        let cell = self.cell(offset)?;
        let node = ValueNode::parse(cell.data, offset, cell.allocated)?;
        Ok(Value { hive: self, node })
    }

    /// Opens a key by backslash-separated path relative to the root key
    /// (case-insensitive). A leading root key name is tolerated.
    pub fn open_key(&self, path: &str) -> Result<Option<Key<'_>>> {
        let mut key = self.root()?;
        for (i, comp) in path.split('\\').filter(|c| !c.is_empty()).enumerate() {
            if i == 0 && comp.eq_ignore_ascii_case(&key.node.name) && key.subkey(comp)?.is_none() {
                continue;
            }
            match key.subkey(comp)? {
                Some(k) => key = k,
                None => return Ok(None),
            }
        }
        Ok(Some(key))
    }

    /// Iterates every cell in every hive bin (allocated and free).
    pub fn cells(&self) -> impl Iterator<Item = CellRef<'_>> + '_ {
        self.bins.iter().flat_map(move |bin| CellIter {
            hive: self,
            pos: bin.offset as usize + 32,
            end: (bin.offset + bin.size) as usize,
        })
    }

    /// Reads the data for a value node (handles resident and big data).
    pub fn value_data(&self, v: &ValueNode) -> Result<Vec<u8>> {
        let size = v.data_size();
        if size == 0 {
            return Ok(Vec::new());
        }
        if v.is_resident() {
            let bytes = v.data_offset.to_le_bytes();
            return Ok(bytes[..(size as usize).min(4)].to_vec());
        }
        let cell = self.cell(v.data_offset)?;
        if size > BIG_DATA_THRESHOLD && cell.data.len() >= 8 && &cell.data[0..2] == b"db" {
            return self.big_data(cell.data, size, v.data_offset);
        }
        let n = (size as usize).min(cell.data.len());
        Ok(cell.data[..n].to_vec())
    }

    fn big_data(&self, db: &[u8], size: u32, offset: u32) -> Result<Vec<u8>> {
        let segments = u16_at(db, 2).unwrap_or(0) as usize;
        let list_off = u32_at(db, 4).unwrap_or(NONE_OFFSET);
        let list = self.cell(list_off)?;
        let mut out = Vec::with_capacity(size as usize);
        for i in 0..segments {
            let seg_off = u32_at(list.data, i * 4).ok_or_else(|| RegfError::BadCell {
                offset,
                reason: "big data segment list truncated".into(),
            })?;
            let seg = self.cell(seg_off)?;
            let remaining = size as usize - out.len();
            let take = remaining
                .min(BIG_DATA_THRESHOLD as usize)
                .min(seg.data.len());
            out.extend_from_slice(&seg.data[..take]);
            if out.len() >= size as usize {
                break;
            }
        }
        Ok(out)
    }

    /// Collects subkey offsets from a (possibly nested) subkey list.
    fn subkey_offsets(
        &self,
        list_offset: u32,
        depth: usize,
        out: &mut Vec<u32>,
        seen: &mut HashSet<u32>,
    ) -> Result<()> {
        if list_offset == NONE_OFFSET || depth > MAX_LIST_DEPTH || !seen.insert(list_offset) {
            return Ok(());
        }
        let cell = self.cell(list_offset)?;
        let (kind, elems) = parse_subkey_list(cell.data, list_offset)?;
        if kind == ListKind::IndexRoot {
            for e in elems {
                self.subkey_offsets(e, depth + 1, out, seen)?;
            }
        } else {
            out.extend(elems);
        }
        Ok(())
    }

    /// Best guess at the account that owns this hive, from the base block's
    /// embedded file name (e.g. `\??\C:\Users\alice\ntuser.dat`).
    pub fn embedded_user(&self) -> Option<String> {
        user_from_path(&self.base.file_name)
    }
}

fn dirty_reason(base: &BaseBlock) -> String {
    if base.primary_seq != base.secondary_seq {
        format!(
            "sequence numbers {} != {}",
            base.primary_seq, base.secondary_seq
        )
    } else {
        "base block checksum invalid".to_string()
    }
}

/// Extracts `<name>` from `...\Users\<name>\...` or `...\Documents and Settings\<name>\...`.
pub fn user_from_path(p: &str) -> Option<String> {
    let parts: Vec<&str> = p.split(['\\', '/']).filter(|s| !s.is_empty()).collect();
    for (i, part) in parts.iter().enumerate() {
        let l = part.to_ascii_lowercase();
        if (l == "users" || l == "documents and settings") && i + 1 < parts.len() {
            let candidate = parts[i + 1];
            let cl = candidate.to_ascii_lowercase();
            if !cl.ends_with(".dat") && cl != "appdata" {
                return Some(candidate.to_string());
            }
        }
    }
    None
}

struct CellIter<'h> {
    hive: &'h Hive,
    pos: usize,
    end: usize,
}

impl<'h> Iterator for CellIter<'h> {
    type Item = CellRef<'h>;
    fn next(&mut self) -> Option<CellRef<'h>> {
        let data = &self.hive.data;
        let end = self.end.min(data.len());
        if self.pos + 4 > end {
            return None;
        }
        let size = i32_at(data, self.pos)?;
        let abs = size.unsigned_abs() as usize;
        if abs < 8 || abs & 7 != 0 || self.pos + abs > end {
            // Corrupt cell chain inside this bin: stop iterating it.
            return None;
        }
        let cell = CellRef {
            offset: self.pos as u32,
            allocated: size < 0,
            data: &data[self.pos + 4..self.pos + abs],
        };
        self.pos += abs;
        Some(cell)
    }
}

fn scan_bins(data: &[u8], warnings: &mut Vec<String>) -> Vec<HiveBin> {
    let mut bins = Vec::new();
    let mut off = 0usize;
    while off + 32 <= data.len() {
        if &data[off..off + 4] != b"hbin" {
            // Resynchronise on the next 4 KiB boundary carrying a bin header.
            let next = (off + 4096..data.len().saturating_sub(32))
                .step_by(4096)
                .find(|&o| &data[o..o + 4] == b"hbin");
            warnings.push(format!(
                "missing hbin signature at 0x{off:x}{}",
                match next {
                    Some(n) => format!(", resynchronised at 0x{n:x}"),
                    None => String::new(),
                }
            ));
            match next {
                Some(n) => {
                    off = n;
                    continue;
                }
                None => break,
            }
        }
        let size = u32_at(data, off + 8).unwrap_or(0) as usize;
        if size < 4096 || size & 0xFFF != 0 {
            warnings.push(format!("hive bin at 0x{off:x} has invalid size 0x{size:x}"));
            off += 4096;
            continue;
        }
        let size = size.min(data.len() - off);
        bins.push(HiveBin {
            offset: off as u32,
            size: size as u32,
            timestamp_raw: crate::util::bytes::u64_at(data, off + 20).unwrap_or(0),
        });
        off += size;
    }
    bins
}

/// A registry key bound to its hive.
#[derive(Debug, Clone)]
pub struct Key<'h> {
    pub hive: &'h Hive,
    pub node: KeyNode,
}

impl<'h> Key<'h> {
    pub fn name(&self) -> &str {
        &self.node.name
    }

    pub fn offset(&self) -> u32 {
        self.node.offset
    }

    pub fn last_written(&self) -> Option<Timestamp> {
        self.node.last_written()
    }

    pub fn subkeys(&self) -> Result<Vec<Key<'h>>> {
        let mut offsets = Vec::new();
        if self.node.subkey_count > 0 {
            self.hive.subkey_offsets(
                self.node.subkeys_list,
                0,
                &mut offsets,
                &mut HashSet::new(),
            )?;
        }
        let mut out = Vec::with_capacity(offsets.len());
        for o in offsets {
            out.push(self.hive.key_at(o)?);
        }
        Ok(out)
    }

    /// Like [`Key::subkeys`] but skips unreadable children instead of failing.
    pub fn subkeys_lossy(&self) -> (Vec<Key<'h>>, Vec<String>) {
        let mut offsets = Vec::new();
        let mut errs = Vec::new();
        if self.node.subkey_count > 0 {
            if let Err(e) = self.hive.subkey_offsets(
                self.node.subkeys_list,
                0,
                &mut offsets,
                &mut HashSet::new(),
            ) {
                errs.push(format!("subkey list of '{}': {e}", self.node.name));
            }
        }
        let mut out = Vec::with_capacity(offsets.len());
        for o in offsets {
            match self.hive.key_at(o) {
                Ok(k) => out.push(k),
                Err(e) => errs.push(format!("subkey of '{}' at 0x{o:x}: {e}", self.node.name)),
            }
        }
        (out, errs)
    }

    pub fn subkey(&self, name: &str) -> Result<Option<Key<'h>>> {
        Ok(self
            .subkeys()?
            .into_iter()
            .find(|k| k.node.name.eq_ignore_ascii_case(name)))
    }

    pub fn values(&self) -> Result<Vec<Value<'h>>> {
        let (vals, errs) = self.values_lossy();
        if let Some(e) = errs.into_iter().next() {
            if vals.is_empty() {
                return Err(RegfError::Other(e));
            }
        }
        Ok(vals)
    }

    pub fn values_lossy(&self) -> (Vec<Value<'h>>, Vec<String>) {
        let mut out = Vec::new();
        let mut errs = Vec::new();
        let count = self.node.value_count as usize;
        if count == 0 || self.node.values_list == NONE_OFFSET {
            return (out, errs);
        }
        let list = match self.hive.cell(self.node.values_list) {
            Ok(c) => c,
            Err(e) => {
                errs.push(format!("value list of '{}': {e}", self.node.name));
                return (out, errs);
            }
        };
        for i in 0..count.min(list.data.len() / 4) {
            let off = u32_at(list.data, i * 4).unwrap_or(NONE_OFFSET);
            match self.hive.value_at(off) {
                Ok(v) => out.push(v),
                Err(e) => errs.push(format!("value {i} of '{}': {e}", self.node.name)),
            }
        }
        (out, errs)
    }

    pub fn value(&self, name: &str) -> Result<Option<Value<'h>>> {
        Ok(self
            .values_lossy()
            .0
            .into_iter()
            .find(|v| v.node.name.eq_ignore_ascii_case(name)))
    }

    pub fn parent(&self) -> Option<Key<'h>> {
        if self.node.is_root() {
            return None;
        }
        self.hive.key_at(self.node.parent).ok()
    }

    /// Full path from the hive root (excluding the root key's own name).
    pub fn path(&self) -> String {
        let mut parts = vec![self.node.name.clone()];
        let mut cur = self.clone();
        let mut seen = HashSet::new();
        while let Some(p) = cur.parent() {
            if !seen.insert(p.node.offset) || parts.len() > 512 {
                break;
            }
            if p.node.is_root() {
                break;
            }
            parts.push(p.node.name.clone());
            cur = p;
        }
        if self.node.is_root() {
            return String::new();
        }
        parts.reverse();
        parts.join("\\")
    }

    pub fn class_name(&self) -> Option<String> {
        if self.node.class_name_offset == NONE_OFFSET || self.node.class_name_len == 0 {
            return None;
        }
        let cell = self.hive.cell(self.node.class_name_offset).ok()?;
        let n = (self.node.class_name_len as usize).min(cell.data.len());
        Some(utf16le_lossy(&cell.data[..n]))
    }
}

/// A registry value bound to its hive.
#[derive(Debug, Clone)]
pub struct Value<'h> {
    pub hive: &'h Hive,
    pub node: ValueNode,
}

impl<'h> Value<'h> {
    pub fn name(&self) -> &str {
        &self.node.name
    }

    pub fn data_type(&self) -> u32 {
        self.node.data_type
    }

    pub fn data(&self) -> Result<Vec<u8>> {
        self.hive.value_data(&self.node)
    }

    pub fn as_u32(&self) -> Option<u32> {
        let d = self.data().ok()?;
        match self.node.data_type {
            5 => d
                .get(..4)
                .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]])),
            _ => u32_at(&d, 0),
        }
    }

    pub fn as_string(&self) -> Option<String> {
        let d = self.data().ok()?;
        match self.node.data_type {
            1 | 2 | 6 => Some(
                utf16le_lossy(&d[..d.len() & !1])
                    .trim_end_matches('\0')
                    .to_string(),
            ),
            7 => Some(
                utf16le_lossy(&d[..d.len() & !1])
                    .split('\0')
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
                    .join("; "),
            ),
            4 | 5 => self.as_u32().map(|v| v.to_string()),
            11 => crate::util::bytes::u64_at(&d, 0).map(|v| v.to_string()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_extraction() {
        assert_eq!(
            user_from_path("\\??\\C:\\Users\\alice\\ntuser.dat"),
            Some("alice".into())
        );
        assert_eq!(
            user_from_path("/mnt/img/Users/bob/AppData/Local/Microsoft/Windows/UsrClass.dat"),
            Some("bob".into())
        );
        assert_eq!(
            user_from_path("C:\\Documents and Settings\\Joe\\NTUSER.DAT"),
            Some("Joe".into())
        );
        assert_eq!(
            user_from_path("ocal\\Microsoft\\Windows\\UsrClass.dat"),
            None
        );
    }
}
