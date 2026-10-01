//! Transaction log (.LOG/.LOG1/.LOG2) parsing and replay.
//!
//! Implements both formats described in Maxim Suhanov's "Windows registry
//! file format specification":
//!
//! * old format (Windows XP – 8.0): base block copy, `DIRT` dirty vector
//!   (one bit per 512-byte page) and the dirty pages themselves;
//! * new format (Windows 8.1+): a sequence of `HvLE` log entries, each
//!   protected by two Marvin32 hashes.
//!
//! Replay happens purely in memory; evidence files are never written.

use super::base::BaseBlock;
use super::marvin::marvin32;
use crate::util::bytes::{u32_at, u64_at};
use serde::Serialize;
use std::path::{Path, PathBuf};

const LOG_SEED: u64 = 0x82EF_4D88_7A4E_55C5;
const SECTOR: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    Old,
    New,
}

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub file_offset: usize,
    pub size: u32,
    pub flags: u32,
    pub sequence: u32,
    pub hive_bins_data_size: u32,
    /// (offset relative to hive bins data, size, start in log file)
    pub pages: Vec<(u32, u32, usize)>,
}

#[derive(Debug, Clone)]
pub struct LogFile {
    pub name: String,
    pub base: BaseBlock,
    pub base_valid: bool,
    pub format: LogFormat,
    pub entries: Vec<LogEntry>,
    pub entry_errors: Vec<String>,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct RecoveryReport {
    pub logs_examined: Vec<String>,
    pub logs_applied: Vec<String>,
    pub entries_applied: usize,
    pub pages_applied: usize,
    pub first_sequence: Option<u32>,
    pub last_sequence: Option<u32>,
    pub warnings: Vec<String>,
}

/// Finds `<hive>.LOG`, `<hive>.LOG1`, `<hive>.LOG2` next to a hive,
/// case-insensitively (images mounted with ntfs-3g preserve case).
pub fn discover_logs(hive: &Path) -> Vec<PathBuf> {
    let Some(dir) = hive.parent() else {
        return Vec::new();
    };
    let Some(stem) = hive.file_name().and_then(|n| n.to_str()) else {
        return Vec::new();
    };
    let wanted: Vec<String> = ["log", "log1", "log2"]
        .iter()
        .map(|s| format!("{}.{s}", stem.to_lowercase()))
        .collect();
    let dir = if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    };
    let mut out: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .map(|n| wanted.contains(&n.to_lowercase()))
                        .unwrap_or(false)
                })
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

impl LogFile {
    pub fn parse(name: String, data: Vec<u8>) -> Result<LogFile, String> {
        if data.len() < SECTOR {
            return Err(format!("{name}: too small for a transaction log"));
        }
        let base = BaseBlock::parse(&data[..SECTOR]).map_err(|e| format!("{name}: {e}"))?;
        let base_valid = base.checksum_valid() && base.primary_seq == base.secondary_seq;
        let format = match base.file_type {
            6 => LogFormat::New,
            1 | 2 => LogFormat::Old,
            t => return Err(format!("{name}: unexpected file type {t} for a log")),
        };
        let mut lf = LogFile {
            name,
            base,
            base_valid,
            format,
            entries: Vec::new(),
            entry_errors: Vec::new(),
            data,
        };
        if lf.format == LogFormat::New {
            lf.parse_entries();
        }
        Ok(lf)
    }

    fn parse_entries(&mut self) {
        let mut off = SECTOR;
        let d = &self.data;
        while off + 40 <= d.len() {
            if &d[off..off + 4] != b"HvLE" {
                break;
            }
            let size = u32_at(d, off + 4).unwrap_or(0) as usize;
            if size < 40 || size & (SECTOR - 1) != 0 || off + size > d.len() {
                self.entry_errors.push(format!(
                    "{}: log entry at 0x{off:x} has invalid size 0x{size:x}",
                    self.name
                ));
                break;
            }
            let hbins = u32_at(d, off + 16).unwrap_or(0);
            if hbins & 0xFFF != 0 {
                self.entry_errors.push(format!(
                    "{}: log entry at 0x{off:x} has bad hive bins size",
                    self.name
                ));
                break;
            }
            let hash1 = u64_at(d, off + 24).unwrap_or(0);
            let hash2 = u64_at(d, off + 32).unwrap_or(0);
            let calc1 = marvin32(LOG_SEED, &d[off + 40..off + size]);
            let calc2 = marvin32(LOG_SEED, &d[off..off + 32]);
            if hash1 != calc1 || hash2 != calc2 {
                self.entry_errors.push(format!(
                    "{}: log entry at 0x{off:x} failed hash validation",
                    self.name
                ));
                break;
            }
            let count = u32_at(d, off + 20).unwrap_or(0) as usize;
            let refs_end = off + 40 + count * 8;
            if refs_end > off + size {
                self.entry_errors.push(format!(
                    "{}: log entry at 0x{off:x} page references overflow",
                    self.name
                ));
                break;
            }
            let mut pages = Vec::with_capacity(count);
            let mut data_pos = refs_end;
            let mut ok = true;
            for i in 0..count {
                let p_off = u32_at(d, off + 40 + i * 8).unwrap_or(0);
                let p_size = u32_at(d, off + 44 + i * 8).unwrap_or(0);
                if data_pos + p_size as usize > off + size {
                    ok = false;
                    break;
                }
                pages.push((p_off, p_size, data_pos));
                data_pos += p_size as usize;
            }
            if !ok {
                self.entry_errors.push(format!(
                    "{}: log entry at 0x{off:x} dirty pages overflow",
                    self.name
                ));
                break;
            }
            self.entries.push(LogEntry {
                file_offset: off,
                size: size as u32,
                flags: u32_at(d, off + 8).unwrap_or(0),
                sequence: u32_at(d, off + 12).unwrap_or(0),
                hive_bins_data_size: hbins,
                pages,
            });
            off += size;
        }
    }
}

/// Replays applicable logs onto `data` (hive bins) and updates `base`.
pub fn recover(base: &mut BaseBlock, data: &mut Vec<u8>, logs: &[LogFile]) -> RecoveryReport {
    let mut report = RecoveryReport {
        logs_examined: logs.iter().map(|l| l.name.clone()).collect(),
        ..Default::default()
    };
    for l in logs {
        report.warnings.extend(l.entry_errors.iter().cloned());
    }
    let new_logs: Vec<&LogFile> = logs.iter().filter(|l| l.format == LogFormat::New).collect();
    let old_logs: Vec<&LogFile> = logs.iter().filter(|l| l.format == LogFormat::Old).collect();
    if !new_logs.is_empty() {
        recover_new(base, data, &new_logs, &mut report);
    } else if !old_logs.is_empty() {
        recover_old(base, data, &old_logs, &mut report);
    } else {
        report.warnings.push("no usable transaction logs".into());
    }
    if report.entries_applied == 0 {
        report
            .warnings
            .push("hive is dirty but no log data could be applied".into());
    }
    report
}

fn apply_page(data: &mut Vec<u8>, offset: usize, page: &[u8]) {
    let end = offset + page.len();
    if data.len() < end {
        data.resize(end, 0);
    }
    data[offset..end].copy_from_slice(page);
}

fn recover_new(
    base: &mut BaseBlock,
    data: &mut Vec<u8>,
    logs: &[&LogFile],
    report: &mut RecoveryReport,
) {
    let primary_valid = base.checksum_valid();
    // Order logs so the one holding earlier entries is applied first.
    let mut ordered: Vec<&LogFile> = logs
        .iter()
        .copied()
        .filter(|l| !l.entries.is_empty())
        .collect();
    ordered.sort_by_key(|l| l.entries.first().map(|e| e.sequence).unwrap_or(u32::MAX));
    if !primary_valid {
        // Only the log with the latest entries is used when the primary base
        // block is unusable; take its base block as the starting point.
        ordered
            .sort_by_key(|l| std::cmp::Reverse(l.entries.last().map(|e| e.sequence).unwrap_or(0)));
        ordered.truncate(1);
        if let Some(l) = ordered.first() {
            if l.base_valid {
                let mut nb = l.base.clone();
                nb.raw[..512].copy_from_slice(&l.data[..512]);
                *base = nb;
                report.warnings.push(format!(
                    "primary base block invalid; using base block from {}",
                    l.name
                ));
            }
        }
    }
    let mut expected: Option<u32> = None;
    let mut last_size = base.hive_bins_data_size;
    let min_seq = base.secondary_seq;
    for log in ordered {
        let mut applied_here = 0;
        for e in &log.entries {
            if e.sequence < min_seq {
                continue; // already reconciled into the primary file
            }
            match expected {
                None => {
                    // The first applicable entry must continue the primary's state.
                    if primary_valid && e.sequence != min_seq && e.sequence != log.base.primary_seq
                    {
                        report.warnings.push(format!(
                            "{}: first applicable entry has sequence {} (expected {})",
                            log.name, e.sequence, min_seq
                        ));
                    }
                }
                Some(n) if e.sequence != n => break,
                _ => {}
            }
            let hb = e.hive_bins_data_size as usize;
            if data.len() < hb {
                data.resize(hb, 0);
            }
            for &(p_off, p_size, start) in &e.pages {
                apply_page(
                    data,
                    p_off as usize,
                    &log.data[start..start + p_size as usize],
                );
                report.pages_applied += 1;
            }
            report.first_sequence.get_or_insert(e.sequence);
            report.last_sequence = Some(e.sequence);
            report.entries_applied += 1;
            applied_here += 1;
            last_size = e.hive_bins_data_size;
            expected = Some(e.sequence.wrapping_add(1));
        }
        if applied_here > 0 {
            report.logs_applied.push(log.name.clone());
        }
    }
    if let Some(seq) = report.last_sequence {
        base.set_recovered(seq, last_size);
        data.truncate(last_size as usize);
    }
}

fn recover_old(
    base: &mut BaseBlock,
    data: &mut Vec<u8>,
    logs: &[&LogFile],
    report: &mut RecoveryReport,
) {
    // Prefer a valid log whose timestamp matches the primary; otherwise the
    // most recent valid log.
    let mut candidates: Vec<&LogFile> = logs.iter().copied().filter(|l| l.base_valid).collect();
    candidates.sort_by_key(|l| std::cmp::Reverse(l.base.last_written_raw));
    let chosen = candidates
        .iter()
        .find(|l| l.base.last_written_raw == base.last_written_raw)
        .or_else(|| candidates.first())
        .copied();
    let Some(log) = chosen else {
        report
            .warnings
            .push("no valid old-format transaction log".into());
        return;
    };
    if log.base.last_written_raw != base.last_written_raw {
        report.warnings.push(format!(
            "{}: log timestamp does not match primary; applying most recent log",
            log.name
        ));
    }
    let sector = SECTOR * (log.base.clustering_factor.clamp(1, 8) as usize);
    let d = &log.data;
    if d.len() < sector + 4 || &d[sector..sector + 4] != b"DIRT" {
        report
            .warnings
            .push(format!("{}: missing DIRT dirty vector", log.name));
        return;
    }
    let size = log.base.hive_bins_data_size as usize;
    let bitmap_len = size / SECTOR / 8;
    let bitmap_start = sector + 4;
    if bitmap_start + bitmap_len > d.len() {
        report
            .warnings
            .push(format!("{}: dirty vector truncated", log.name));
        return;
    }
    let bitmap = &d[bitmap_start..bitmap_start + bitmap_len];
    let pages_start = (bitmap_start + bitmap_len).div_ceil(sector) * sector;
    let mut src = pages_start;
    if data.len() < size {
        data.resize(size, 0);
    }
    for (byte_idx, &byte) in bitmap.iter().enumerate() {
        if byte == 0 {
            continue;
        }
        for bit in 0..8 {
            if byte & (1 << bit) == 0 {
                continue;
            }
            let page = byte_idx * 8 + bit;
            if src + SECTOR > d.len() {
                report
                    .warnings
                    .push(format!("{}: dirty pages truncated", log.name));
                return finish_old(base, data, log, report, size);
            }
            apply_page(data, page * SECTOR, &d[src..src + SECTOR]);
            src += SECTOR;
            report.pages_applied += 1;
        }
    }
    finish_old(base, data, log, report, size);
}

fn finish_old(
    base: &mut BaseBlock,
    data: &mut Vec<u8>,
    log: &LogFile,
    report: &mut RecoveryReport,
    size: usize,
) {
    if report.pages_applied > 0 {
        report.entries_applied = 1;
        report.logs_applied.push(log.name.clone());
        report.first_sequence = Some(log.base.primary_seq);
        report.last_sequence = Some(log.base.primary_seq);
        base.set_recovered(log.base.primary_seq.max(base.primary_seq), size as u32);
        data.truncate(size);
    }
}
