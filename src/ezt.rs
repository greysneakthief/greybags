//! Integration with Eric Zimmerman's SBECmd (ShellBags Explorer CLI).
//!
//! SBECmd is a .NET application. On Debian/Ubuntu it runs under the
//! `dotnet` runtime (`dotnet SBECmd.dll`); `scripts/install-sbecmd.sh`
//! installs both. greybags can run it on the same evidence and diff the
//! results, which is a useful cross-validation step in casework (two
//! independent parsers agreeing raises confidence; disagreements point at
//! parser edge cases worth a manual look).

use crate::shellbags::{EntryStatus, ShellBagEntry};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;

pub const ENV_SBECMD: &str = "GREYBAGS_SBECMD";

/// Finds SBECmd: explicit path, `$GREYBAGS_SBECMD`, `$PATH`, then the
/// locations used by `install-sbecmd.sh`.
pub fn locate(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        return p.exists().then(|| p.to_path_buf());
    }
    if let Ok(p) = std::env::var(ENV_SBECMD) {
        let p = PathBuf::from(p);
        if p.exists() {
            return Some(p);
        }
    }
    if let Ok(path) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path) {
            for n in ["SBECmd", "sbecmd", "SBECmd.dll"] {
                let c = dir.join(n);
                if c.is_file() {
                    return Some(c);
                }
            }
        }
    }
    let mut candidates = vec![
        PathBuf::from("/opt/eztools/SBECmd/SBECmd.dll"),
        PathBuf::from("/opt/eztools/SBECmd.dll"),
    ];
    if let Ok(home) = std::env::var("HOME") {
        candidates.insert(
            0,
            PathBuf::from(&home).join(".local/share/greybags/eztools/SBECmd/SBECmd.dll"),
        );
        candidates.insert(
            1,
            PathBuf::from(&home).join(".local/share/greybags/eztools/SBECmd.dll"),
        );
    }
    candidates.into_iter().find(|c| c.is_file())
}

/// Builds the command used to launch SBECmd.
pub fn command(sbecmd: &Path, dotnet: Option<&Path>) -> Result<Command, String> {
    let ext = sbecmd
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase());
    let dll = match ext.as_deref() {
        Some("dll") => Some(sbecmd.to_path_buf()),
        Some("exe") => {
            let sibling = sbecmd.with_extension("dll");
            if sibling.is_file() {
                Some(sibling)
            } else {
                return Err(format!(
                    "{} is a Windows executable and no SBECmd.dll was found next to it; download the .NET \
                     (cross-platform) build of SBECmd (see scripts/install-sbecmd.sh)",
                    sbecmd.display()
                ));
            }
        }
        _ => None,
    };
    let mut cmd = match dll {
        Some(d) => {
            let mut c = Command::new(
                dotnet
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| PathBuf::from("dotnet")),
            );
            c.arg(d);
            c
        }
        None => Command::new(sbecmd),
    };
    // Lets builds targeting an older .NET major version run on a newer runtime.
    if std::env::var_os("DOTNET_ROLL_FORWARD").is_none() {
        cmd.env("DOTNET_ROLL_FORWARD", "Major");
    }
    // Avoid ICU dependency problems on minimal containers.
    if std::env::var_os("DOTNET_SYSTEM_GLOBALIZATION_INVARIANT").is_none() {
        cmd.env("DOTNET_SYSTEM_GLOBALIZATION_INVARIANT", "1");
    }
    Ok(cmd)
}

/// Runs SBECmd against a directory of hives and returns the CSV files it wrote.
pub fn run(
    sbecmd: &Path,
    dotnet: Option<&Path>,
    input_dir: &Path,
    out_dir: &Path,
    extra: &[String],
) -> Result<Vec<PathBuf>, String> {
    std::fs::create_dir_all(out_dir)
        .map_err(|e| format!("cannot create {}: {e}", out_dir.display()))?;
    let before: HashSet<PathBuf> = list_csv(out_dir).into_iter().collect();
    let mut cmd = command(sbecmd, dotnet)?;
    cmd.arg("-d")
        .arg(input_dir)
        .arg("--csv")
        .arg(out_dir)
        .args(extra);
    let status = cmd.status().map_err(|e| {
        format!("failed to start SBECmd ({e}); is the .NET runtime installed? Try scripts/install-sbecmd.sh")
    })?;
    if !status.success() {
        return Err(format!("SBECmd exited with {status}"));
    }
    let after: Vec<PathBuf> = list_csv(out_dir)
        .into_iter()
        .filter(|p| !before.contains(p))
        .collect();
    if after.is_empty() {
        return Err(format!(
            "SBECmd finished but wrote no CSV to {}",
            out_dir.display()
        ));
    }
    Ok(after)
}

fn list_csv(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| {
                    p.extension()
                        .and_then(|e| e.to_str())
                        .map(|e| e.eq_ignore_ascii_case("csv"))
                        .unwrap_or(false)
                })
                .collect()
        })
        .unwrap_or_default()
}

#[derive(Debug, Clone, Serialize)]
pub struct SbeRow {
    pub absolute_path: String,
    pub shell_type: String,
    pub value: String,
    pub mft_entry: Option<u64>,
    pub mft_sequence: Option<u16>,
    pub source_file: String,
    pub bag_path: String,
}

/// Reads an SBECmd CSV. Columns are located by header name so that minor
/// layout changes between SBECmd versions do not break ingestion.
pub fn read_csv(path: &Path) -> Result<Vec<SbeRow>, String> {
    let data = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let data = data.strip_prefix(&[0xEF, 0xBB, 0xBF][..]).unwrap_or(&data);
    let mut rdr = csv::ReaderBuilder::new().flexible(true).from_reader(data);
    let headers: Vec<String> = rdr
        .headers()
        .map_err(|e| e.to_string())?
        .iter()
        .map(|h| h.trim().to_ascii_lowercase())
        .collect();
    let col = |names: &[&str]| {
        names
            .iter()
            .find_map(|n| headers.iter().position(|h| h == n))
    };
    let abs = col(&["absolutepath", "absolute path"])
        .ok_or("CSV has no AbsolutePath column; is this SBECmd output?")?;
    let st = col(&["shelltype", "shell type"]);
    let val = col(&["value"]);
    let mft = col(&["mftentry", "mft entry"]);
    let seq = col(&["mftsequencenumber", "mft sequence number"]);
    let src = col(&["sourcefile", "source file", "source"]);
    let bag = col(&["bagpath", "bag path"]);
    let mut out = Vec::new();
    for rec in rdr.records() {
        let rec = rec.map_err(|e| e.to_string())?;
        let g = |i: Option<usize>| i.and_then(|i| rec.get(i)).unwrap_or("").trim().to_string();
        out.push(SbeRow {
            absolute_path: g(Some(abs)),
            shell_type: g(st),
            value: g(val),
            mft_entry: g(mft).parse().ok(),
            mft_sequence: g(seq).parse().ok(),
            source_file: g(src),
            bag_path: g(bag),
        });
    }
    Ok(out)
}

/// Normalises a namespace path for cross-tool comparison.
pub fn normalize(p: &str) -> String {
    let mut s = p.to_lowercase();
    for (from, to) in [("this pc", "my computer"), ("computer\\", "my computer\\")] {
        if s.starts_with(from) && !s.starts_with("my computer") {
            s = format!("{to}{}", &s[from.len()..]);
        }
    }
    let parts: Vec<&str> = s.split('\\').filter(|x| !x.is_empty()).collect();
    parts.join("\\")
}

#[derive(Debug, Clone, Serialize)]
pub struct Comparison {
    pub greybags_entries: usize,
    pub sbecmd_entries: usize,
    pub matched: usize,
    pub only_in_greybags: Vec<String>,
    pub only_in_sbecmd: Vec<String>,
    /// (path, greybags MFT ref, SBECmd MFT ref)
    pub mft_mismatches: Vec<(String, String, String)>,
}

impl Comparison {
    pub fn agreement(&self) -> f64 {
        let total = self.greybags_entries.max(self.sbecmd_entries);
        if total == 0 {
            1.0
        } else {
            self.matched as f64 / total as f64
        }
    }
}

pub fn compare(ours: &[ShellBagEntry], theirs: &[SbeRow], include_recovered: bool) -> Comparison {
    let ours: Vec<&ShellBagEntry> = ours
        .iter()
        .filter(|e| include_recovered || e.status == EntryStatus::Active)
        .collect();
    let mut their_map: HashMap<String, Vec<&SbeRow>> = HashMap::new();
    for r in theirs {
        their_map
            .entry(normalize(&r.absolute_path))
            .or_default()
            .push(r);
    }
    let mut our_set: HashSet<String> = HashSet::new();
    let mut matched = 0;
    let mut only_ours = Vec::new();
    let mut mft_mismatches = Vec::new();
    for e in &ours {
        // Try both our namespace path and the UNC-preserving variant.
        let keys = [
            normalize(&e.absolute_path),
            normalize(&raw_namespace_path(e, &ours)),
        ];
        let hit = keys.iter().find(|k| their_map.contains_key(*k)).cloned();
        match hit {
            Some(k) => {
                matched += 1;
                our_set.insert(k.clone());
                if let (Some(me), Some(ms)) = (e.item.mft_entry, e.item.mft_sequence) {
                    if let Some(r) = their_map[&k].iter().find(|r| r.mft_entry.is_some()) {
                        if r.mft_entry != Some(me) || r.mft_sequence != Some(ms) {
                            mft_mismatches.push((
                                e.absolute_path.clone(),
                                format!("{me}-{ms}"),
                                format!(
                                    "{}-{}",
                                    r.mft_entry.unwrap_or(0),
                                    r.mft_sequence.unwrap_or(0)
                                ),
                            ));
                        }
                    }
                }
            }
            None => {
                our_set.insert(keys[0].clone());
                only_ours.push(e.absolute_path.clone());
            }
        }
    }
    let mut only_theirs: Vec<String> = theirs
        .iter()
        .filter(|r| !our_set.contains(&normalize(&r.absolute_path)))
        .map(|r| r.absolute_path.clone())
        .collect();
    only_theirs.sort();
    only_theirs.dedup();
    Comparison {
        greybags_entries: ours.len(),
        sbecmd_entries: theirs.len(),
        matched,
        only_in_greybags: only_ours,
        only_in_sbecmd: only_theirs,
        mft_mismatches,
    }
}

/// Rebuilds the path using raw item names (keeps `\\server\share` forms),
/// which is closer to how some tools render network paths.
fn raw_namespace_path(e: &ShellBagEntry, all: &[&ShellBagEntry]) -> String {
    let by_id: HashMap<usize, &&ShellBagEntry> = all.iter().map(|x| (x.id, x)).collect();
    let mut segs = vec![e.item.segment()];
    let mut cur = e.parent_id;
    let mut guard = 0;
    while let Some(id) = cur {
        let Some(p) = by_id.get(&id) else { break };
        segs.push(p.item.segment());
        cur = p.parent_id;
        guard += 1;
        if guard > 256 {
            break;
        }
    }
    segs.reverse();
    segs.join("\\")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalisation() {
        assert_eq!(normalize("This PC\\C:\\Users\\"), "my computer\\c:\\users");
        assert_eq!(normalize("Network\\\\\\srv\\share"), "network\\srv\\share");
    }

    #[test]
    fn reads_sbecmd_like_csv() {
        let dir = std::env::temp_dir().join(format!("gb-sbe-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("x.csv");
        std::fs::write(&p, "\u{feff}BagPath,Slot,NodeSlot,MRUPosition,AbsolutePath,ShellType,Value,MFTEntry,MFTSequenceNumber\r\nBagMRU\\0,0,1,0,My Computer,Root folder: GUID,My Computer,,\r\nBagMRU\\0\\0,0,2,0,My Computer\\C:,Drive letter,C:,,\r\n").unwrap();
        let rows = read_csv(&p).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].absolute_path, "My Computer\\C:");
        std::fs::remove_dir_all(dir).ok();
    }
}
