//! ShellBags extraction: hive discovery, BagMRU traversal, Bags
//! correlation and deleted-entry recovery.

pub mod bags;
pub mod model;
pub mod recover;
pub mod walker;

pub use model::{BagInfo, EntryStatus, HiveKind, HiveReport, ScanResult, ShellBagEntry};

use crate::regf::{hive::user_from_path, Hive, OpenOptions};
use crate::shellitem::ParseOptions;
use recover::RecoverOptions;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use walker::Walker;

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub apply_logs: bool,
    pub recover_deleted: bool,
    pub include_duplicates: bool,
    pub include_orphan_values: bool,
    pub parse: ParseOptions,
    /// Remove entries that are byte-identical across sources (e.g. the same
    /// hive taken from several shadow copies).
    pub dedupe: bool,
    /// When scanning directories, test every file's signature instead of
    /// only names containing "ntuser" or "usrclass".
    pub scan_all_files: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions {
            apply_logs: true,
            recover_deleted: true,
            include_duplicates: false,
            include_orphan_values: false,
            parse: ParseOptions::default(),
            dedupe: false,
            scan_all_files: false,
        }
    }
}

/// Expands files and directories into a list of primary hive files.
pub fn discover(inputs: &[PathBuf], scan_all: bool) -> (Vec<PathBuf>, Vec<String>) {
    let mut out = Vec::new();
    let mut warnings = Vec::new();
    for input in inputs {
        if input.is_file() {
            if crate::regf::is_primary_hive(input) {
                out.push(input.clone());
            } else {
                warnings.push(format!(
                    "{}: not a primary registry hive (or a transaction log); skipped",
                    input.display()
                ));
            }
        } else if input.is_dir() {
            for entry in walkdir::WalkDir::new(input)
                .follow_links(false)
                .max_depth(32)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if !entry.file_type().is_file() {
                    continue;
                }
                let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
                if name.contains(".log") {
                    continue;
                }
                let likely = name.contains("ntuser") || name.contains("usrclass");
                if (likely || scan_all) && crate::regf::is_primary_hive(entry.path()) {
                    out.push(entry.path().to_path_buf());
                }
            }
        } else {
            warnings.push(format!("{}: no such file or directory", input.display()));
        }
    }
    out.sort();
    out.dedup();
    (out, warnings)
}

/// Classifies a hive by its content (with the file name as a fallback).
pub fn hive_kind(hive: &Hive, path: Option<&Path>) -> HiveKind {
    let has = |p: &str| matches!(hive.open_key(p), Ok(Some(_)));
    if has("Local Settings") || has("Wow6432Node\\Local Settings") {
        return HiveKind::UsrClass;
    }
    if has("Software\\Microsoft\\Windows")
        && (has("Environment") || has("Control Panel") || has("Software"))
    {
        return HiveKind::NtUser;
    }
    let name = path
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    if name.contains("usrclass") {
        HiveKind::UsrClass
    } else if name.contains("ntuser") {
        HiveKind::NtUser
    } else {
        HiveKind::Unknown
    }
}

/// Scans one already-opened hive.
pub fn scan_hive(
    hive: &Hive,
    source: &str,
    opts: &ScanOptions,
    first_id: usize,
) -> (HiveReport, Vec<ShellBagEntry>) {
    let path = hive.path.clone();
    let kind = hive_kind(hive, path.as_deref());
    let user = user_from_path(source).or_else(|| hive.embedded_user());
    let mut w = Walker::new(
        hive,
        opts.parse,
        source.to_string(),
        kind,
        user.clone(),
        first_id,
    );
    w.walk_all();
    let active = w.entries.len();
    if opts.recover_deleted {
        w.recover_deleted(&RecoverOptions {
            include_duplicates: opts.include_duplicates,
            include_orphan_values: opts.include_orphan_values,
        });
    }
    let recovered = w.entries.len() - active;
    let mut warnings = hive.warnings.clone();
    warnings.extend(w.warnings);
    let report = HiveReport {
        path: source.to_string(),
        kind,
        user,
        embedded_file_name: hive.base.file_name.clone(),
        last_written: hive.base.last_written,
        dirty: hive.was_dirty,
        recovery: hive.recovery.clone(),
        locations: w.locations,
        entries: w.entries.len(),
        recovered,
        warnings,
    };
    (report, w.entries)
}

/// Discovers and scans every hive under `inputs`.
pub fn scan_inputs(inputs: &[PathBuf], opts: &ScanOptions) -> ScanResult {
    let (files, mut errors) = discover(inputs, opts.scan_all_files);
    let mut result = ScanResult::default();
    let open = OpenOptions {
        apply_logs: opts.apply_logs,
        log_paths: Vec::new(),
    };
    for f in files {
        let hive = match Hive::open(&f, &open) {
            Ok(h) => h,
            Err(e) => {
                errors.push(format!("{}: {e}", f.display()));
                continue;
            }
        };
        let (report, entries) =
            scan_hive(&hive, &f.display().to_string(), opts, result.entries.len());
        result.hives.push(report);
        result.entries.extend(entries);
    }
    if opts.dedupe {
        dedupe(&mut result);
    }
    result.errors = errors;
    result
}

/// Drops entries that are identical (same user, path, item bytes and key
/// timestamp) to an earlier one, e.g. when the same hive is supplied from
/// several shadow copies.
pub fn dedupe(result: &mut ScanResult) {
    let mut seen = HashSet::new();
    result.entries.retain(|e| {
        seen.insert((
            e.user.clone(),
            e.absolute_path.to_lowercase(),
            e.item.raw.clone(),
            e.key_last_written.map(|t| t.filetime()),
            e.status,
        ))
    });
}

#[cfg(test)]
mod tests {
    use super::walker::{join, next_fs};
    use crate::shellitem::{build, parse_item, ParseOptions};

    #[test]
    fn fs_paths() {
        let o = ParseOptions::default();
        let vol = parse_item(&build::volume("E:\\"), &o, None);
        assert_eq!(next_fs(None, &vol).as_deref(), Some("E:"));
        let dir = parse_item(&build::dir("Tools", 0, 0, 1, 1), &o, None);
        assert_eq!(next_fs(Some("E:"), &dir).as_deref(), Some("E:\\Tools"));
        assert_eq!(join("", "a"), "a");
        assert_eq!(join("a", "b"), "a\\b");
    }
}
