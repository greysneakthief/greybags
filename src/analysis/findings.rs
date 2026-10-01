//! Triage heuristics over parsed ShellBags.
//!
//! Every finding states *why* it was raised and which entries support it.
//! These are leads for an analyst, not verdicts: corroborate with other
//! artifacts (USBSTOR, MountedDevices, LNK/JumpLists, event logs, MFT).

use super::watchlist::WatchRule;
use crate::shellbags::{EntryStatus, HiveReport, ShellBagEntry};
use crate::shellitem::Category;
use crate::util::Timestamp;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn parse(s: &str) -> Option<Severity> {
        match s.to_ascii_lowercase().as_str() {
            "info" | "informational" => Some(Severity::Info),
            "low" => Some(Severity::Low),
            "medium" | "med" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            _ => None,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    /// Stable rule identifier, e.g. `network.admin_share`.
    pub rule: &'static str,
    pub title: String,
    pub rationale: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<Timestamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<Timestamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    pub entry_ids: Vec<usize>,
    /// Representative paths (capped).
    pub paths: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct FindingOptions {
    pub watchlist: Vec<WatchRule>,
    /// Drive letter treated as the system volume.
    pub system_drive: char,
    /// Tolerance before target timestamps are considered inconsistent.
    pub skew_secs: i64,
}

impl Default for FindingOptions {
    fn default() -> Self {
        FindingOptions {
            watchlist: super::watchlist::builtin(),
            system_drive: 'C',
            skew_secs: 86_400,
        }
    }
}

const MAX_PATHS: usize = 12;

struct Group<'a> {
    entries: Vec<&'a ShellBagEntry>,
}

impl<'a> Group<'a> {
    fn new() -> Self {
        Group {
            entries: Vec::new(),
        }
    }

    fn finding(
        &self,
        severity: Severity,
        rule: &'static str,
        title: String,
        rationale: String,
    ) -> Finding {
        let times: Vec<Timestamp> = self
            .entries
            .iter()
            .filter_map(|e| e.activity_time())
            .collect();
        let mut paths: Vec<String> = self.entries.iter().map(|e| display_path(e)).collect();
        paths.dedup();
        let total = paths.len();
        paths.truncate(MAX_PATHS);
        if total > MAX_PATHS {
            paths.push(format!("... and {} more", total - MAX_PATHS));
        }
        let users: Vec<&str> = {
            let mut u: Vec<&str> = self
                .entries
                .iter()
                .filter_map(|e| e.user.as_deref())
                .collect();
            u.sort();
            u.dedup();
            u
        };
        Finding {
            severity,
            rule,
            title,
            rationale,
            first_seen: times.iter().min().copied(),
            last_seen: times.iter().max().copied(),
            user: if users.is_empty() {
                None
            } else {
                Some(users.join(", "))
            },
            entry_ids: self.entries.iter().map(|e| e.id).collect(),
            paths,
        }
    }
}

fn display_path(e: &ShellBagEntry) -> String {
    e.fs_path.clone().unwrap_or_else(|| e.absolute_path.clone())
}

fn lower_fs(e: &ShellBagEntry) -> String {
    display_path(e).to_lowercase()
}

/// Root ancestor id for an entry (used to group subtrees).
fn ancestor_with<'a>(
    e: &'a ShellBagEntry,
    by_id: &HashMap<usize, &'a ShellBagEntry>,
    pred: impl Fn(&ShellBagEntry) -> bool,
) -> Option<&'a ShellBagEntry> {
    let mut cur = Some(e);
    let mut guard = 0;
    while let Some(c) = cur {
        if pred(c) {
            return Some(c);
        }
        guard += 1;
        if guard > 256 {
            break;
        }
        cur = c.parent_id.and_then(|p| by_id.get(&p).copied());
    }
    None
}

pub fn evaluate(
    entries: &[ShellBagEntry],
    hives: &[HiveReport],
    opts: &FindingOptions,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let by_id: HashMap<usize, &ShellBagEntry> = entries.iter().map(|e| (e.id, e)).collect();

    volumes(entries, &by_id, opts, &mut out);
    mtp(entries, &by_id, &mut out);
    network(entries, &mut out);
    uris(entries, &mut out);
    archives(entries, &mut out);
    locations(entries, &mut out);
    watchlist(entries, opts, &mut out);
    cloud(entries, &mut out);
    control_panel(entries, &mut out);
    status(entries, &mut out);
    timestamps(entries, opts, &mut out);
    mft(entries, &mut out);
    hive_health(hives, &mut out);

    out.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(b.last_seen.cmp(&a.last_seen))
            .then(a.title.cmp(&b.title))
    });
    out
}

/// Non-system drive letters: removable media, mounted images, mapped drives.
fn volumes<'a>(
    entries: &'a [ShellBagEntry],
    by_id: &HashMap<usize, &'a ShellBagEntry>,
    opts: &FindingOptions,
    out: &mut Vec<Finding>,
) {
    let mut groups: BTreeMap<(Option<String>, char), Group> = BTreeMap::new();
    for e in entries {
        let Some(vol) = ancestor_with(e, by_id, |x| x.item.drive_letter().is_some()) else {
            continue;
        };
        let letter = vol.item.drive_letter().unwrap();
        if letter == opts.system_drive.to_ascii_uppercase() && !vol.item.is_removable() {
            continue;
        }
        groups
            .entry((e.user.clone(), letter))
            .or_insert_with(Group::new)
            .entries
            .push(e);
    }
    for ((_, letter), g) in groups {
        let sub = g.entries.len().saturating_sub(1);
        let removable = g.entries.iter().any(|e| e.item.is_removable());
        out.push(g.finding(
            Severity::Medium,
            "volume.non_system",
            format!("Non-system volume {letter}: browsed ({sub} folder(s) beneath it)"),
            format!(
                "Drive {letter}: is not the system drive{}. Such letters are typically USB/removable media, optical \
                 or mounted disk images (ISO/VHD), or mapped/redirected drives. Correlate with USBSTOR, \
                 MountedDevices, Partition/Diagnostic logs and setupapi.dev.log to identify the device.",
                if removable { " and was reached via the Removable Drives delegate" } else { "" }
            ),
        ));
    }
}

fn mtp<'a>(
    entries: &'a [ShellBagEntry],
    by_id: &HashMap<usize, &'a ShellBagEntry>,
    out: &mut Vec<Finding>,
) {
    let mut groups: BTreeMap<String, (Group, Option<String>)> = BTreeMap::new();
    for e in entries {
        let Some(dev) = ancestor_with(e, by_id, |x| x.item.category == Category::MtpDevice) else {
            continue;
        };
        let g = groups
            .entry(dev.item.name.clone())
            .or_insert_with(|| (Group::new(), None));
        g.1 =
            g.1.clone()
                .or_else(|| dev.item.detail("device_serial").map(str::to_string));
        g.0.entries.push(e);
    }
    for (name, (g, serial)) in groups {
        out.push(g.finding(
            Severity::Medium,
            "device.mtp",
            format!("Portable device (MTP) browsed: {name}"),
            format!(
                "Phones, cameras and media players attached over MTP/PTP appear as portable devices and do not \
                 get a drive letter or USBSTOR entry.{} Files may have been copied to or from the device.",
                serial.map(|s| format!(" Device serial from the WPD identifier: {s}.")).unwrap_or_default()
            ),
        ));
    }
}

fn share_of(path: &str) -> Option<(String, Option<String>)> {
    let p = path.strip_prefix("\\\\")?;
    let mut it = p.split('\\');
    let server = it.next()?.to_string();
    let share = it.next().map(str::to_string);
    Some((server, share))
}

fn network(entries: &[ShellBagEntry], out: &mut Vec<Finding>) {
    let mut servers: BTreeMap<String, Group> = BTreeMap::new();
    let mut admin: BTreeMap<String, Group> = BTreeMap::new();
    let mut tsclient = Group::new();
    let mut loopback = Group::new();
    let mut webdav = Group::new();
    for e in entries {
        let Some(fs) = &e.fs_path else { continue };
        let Some((server, share)) = share_of(fs) else {
            continue;
        };
        let ls = server.to_lowercase();
        if ls == "tsclient" {
            tsclient.entries.push(e);
            continue;
        }
        if ls.contains('@')
            || ls.contains("davwwwroot")
            || share
                .as_deref()
                .is_some_and(|s| s.eq_ignore_ascii_case("DavWWWRoot"))
        {
            webdav.entries.push(e);
        }
        if matches!(ls.as_str(), "localhost" | "127.0.0.1" | "::1" | "[::1]") {
            loopback.entries.push(e);
        }
        if let Some(sh) = &share {
            if sh.ends_with('$') && !sh.eq_ignore_ascii_case("print$") {
                admin
                    .entry(format!("\\\\{server}\\{sh}"))
                    .or_insert_with(Group::new)
                    .entries
                    .push(e);
                continue;
            }
        }
        servers.entry(ls).or_insert_with(Group::new).entries.push(e);
    }
    for (share, g) in admin {
        out.push(g.finding(
            Severity::High,
            "network.admin_share",
            format!("Administrative share browsed: {share}"),
            "Hidden administrative shares (C$, ADMIN$, D$ ...) require local administrator rights on the \
             remote host and are a hallmark of lateral movement and remote staging. Check the remote host's \
             Security log (4624 type 3, 5140/5145) for the same time window."
                .into(),
        ));
    }
    if !tsclient.entries.is_empty() {
        out.push(tsclient.finding(
            Severity::High,
            "network.rdp_drive_redirection",
            "RDP client drive redirection used (\\\\tsclient)".into(),
            "\\\\tsclient\\<drive> exposes the connecting RDP client's local disks inside the session. Browsing it \
             indicates files could be moved between this host and the remote client — a common tool-transfer \
             and exfiltration path. Correlate with TerminalServices-RemoteConnectionManager / LocalSessionManager \
             logs."
                .into(),
        ));
    }
    if !loopback.entries.is_empty() {
        out.push(loopback.finding(
            Severity::Medium,
            "network.loopback_share",
            "Share accessed via loopback (\\\\localhost / \\\\127.0.0.1)".into(),
            "Accessing local disks through UNC loopback paths is unusual for normal users and is used by some \
             tooling to bypass path-based controls or to access administrative shares locally."
                .into(),
        ));
    }
    if !webdav.entries.is_empty() {
        out.push(webdav.finding(
            Severity::Medium,
            "network.webdav",
            "WebDAV location browsed".into(),
            "WebDAV paths (server@SSL, DavWWWRoot) reach HTTP(S) servers through the file-system namespace and \
             are frequently abused for payload delivery and data exfiltration."
                .into(),
        ));
    }
    for (server, g) in servers {
        out.push(g.finding(
            Severity::Info,
            "network.server",
            format!("Network server browsed: \\\\{server}"),
            "UNC locations show which file servers and shares the user browsed. Review share names and \
             sub-folders for sensitive data access."
                .into(),
        ));
    }
}

fn uris(entries: &[ShellBagEntry], out: &mut Vec<Finding>) {
    let mut g_ftp = Group::new();
    let mut g_other = Group::new();
    for e in entries.iter().filter(|e| e.item.category == Category::Uri) {
        if e.item.name.to_lowercase().starts_with("ftp") {
            g_ftp.entries.push(e);
        } else {
            g_other.entries.push(e);
        }
    }
    if !g_ftp.entries.is_empty() {
        out.push(g_ftp.finding(
            Severity::Medium,
            "remote.ftp",
            "FTP site browsed in Explorer".into(),
            "Explorer's built-in FTP client leaves URI shell items. FTP is a classic exfiltration channel; check \
             the URI for user names and the host for reputation."
                .into(),
        ));
    }
    if !g_other.entries.is_empty() {
        out.push(g_other.finding(
            Severity::Low,
            "remote.uri",
            "Remote URI location browsed".into(),
            "URI shell items record web or other remote namespaces opened in Explorer.".into(),
        ));
    }
}

const ARCHIVE_EXT: [&str; 9] = [
    ".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".cab", ".zipx", ".jar",
];
const IMAGE_EXT: [&str; 5] = [".iso", ".img", ".vhd", ".vhdx", ".dmg"];

fn archives(entries: &[ShellBagEntry], out: &mut Vec<Finding>) {
    let mut arch = Group::new();
    let mut imgs = Group::new();
    for e in entries {
        let seg = e.item.segment().to_lowercase();
        if e.item.category == Category::CompressedFolder
            || e.item.category == Category::Cabinet
            || ARCHIVE_EXT.iter().any(|x| seg.ends_with(x))
        {
            arch.entries.push(e);
        } else if IMAGE_EXT.iter().any(|x| seg.ends_with(x)) {
            imgs.entries.push(e);
        }
    }
    if !arch.entries.is_empty() {
        out.push(arch.finding(
            Severity::Low,
            "content.archive_browsing",
            "Archive contents browsed in Explorer".into(),
            "Opening ZIP/CAB archives as folders creates shell bags for the archive and its internal folders. \
             This shows the user looked inside archives even if they were later deleted; archive names can \
             reveal staged or downloaded data."
                .into(),
        ));
    }
    if !imgs.entries.is_empty() {
        out.push(imgs.finding(
            Severity::Medium,
            "content.disk_image",
            "Disk image file browsed (ISO/IMG/VHD)".into(),
            "Disk images are commonly used to deliver malware (bypassing Mark-of-the-Web) and to move data.".into(),
        ));
    }
}

struct LocRule {
    needle: &'static str,
    severity: Severity,
    rule: &'static str,
    title: &'static str,
    why: &'static str,
}

const LOCATION_RULES: &[LocRule] = &[
    LocRule { needle: "\\windows\\system32\\config", severity: Severity::High, rule: "location.registry_hives", title: "Registry hive directory browsed (System32\\config)", why: "This folder holds SAM/SECURITY/SYSTEM; interactive browsing is rare outside credential theft or forensic collection." },
    LocRule { needle: "\\windows\\ntds", severity: Severity::High, rule: "location.ntds", title: "NTDS directory browsed", why: "NTDS.dit contains all domain credentials; access outside administration is a strong credential-theft indicator." },
    LocRule { needle: "\\$recycle.bin", severity: Severity::Medium, rule: "location.recycle_bin", title: "Recycle Bin internals browsed", why: "Browsing $Recycle.Bin directly (rather than via the Recycle Bin shell folder) suggests inspection or manipulation of deleted files." },
    LocRule { needle: "\\recycler", severity: Severity::Medium, rule: "location.recycle_bin", title: "Recycle Bin internals browsed", why: "Browsing RECYCLER directly suggests inspection or manipulation of deleted files." },
    LocRule { needle: "\\system volume information", severity: Severity::Medium, rule: "location.svi", title: "System Volume Information browsed", why: "Holds restore points and VSS data; normally inaccessible to users." },
    LocRule { needle: "\\perflogs", severity: Severity::Medium, rule: "location.perflogs", title: "PerfLogs folder browsed", why: "PerfLogs is rarely used legitimately and is a favourite staging directory for intruders." },
    LocRule { needle: "\\windows\\temp", severity: Severity::Low, rule: "location.temp", title: "Windows temp folder browsed", why: "Temporary folders are common tool/staging locations." },
    LocRule { needle: "\\appdata\\local\\temp", severity: Severity::Low, rule: "location.temp", title: "User temp folder browsed", why: "Temporary folders are common tool/staging locations." },
    LocRule { needle: "\\windows\\tasks", severity: Severity::Medium, rule: "location.tasks", title: "Scheduled task store browsed", why: "Scheduled task definitions are a persistence mechanism." },
    LocRule { needle: "\\system32\\tasks", severity: Severity::Medium, rule: "location.tasks", title: "Scheduled task store browsed", why: "Scheduled task definitions are a persistence mechanism." },
    LocRule { needle: "\\inetpub\\wwwroot", severity: Severity::Medium, rule: "location.webroot", title: "IIS web root browsed", why: "Web roots are where web shells are planted." },
    LocRule { needle: "\\users\\public", severity: Severity::Low, rule: "location.public", title: "Public profile folder browsed", why: "World-writable and frequently used for staging by intruders." },
    LocRule { needle: "\\programdata\\", severity: Severity::Info, rule: "location.programdata", title: "ProgramData sub-folder browsed", why: "Hidden by default; occasionally used to hide tooling." },
    LocRule { needle: "\\microsoft\\windows\\start menu\\programs\\startup", severity: Severity::Medium, rule: "location.startup", title: "Startup folder browsed", why: "Items placed here run at logon (persistence)." },
];

fn locations(entries: &[ShellBagEntry], out: &mut Vec<Finding>) {
    let mut groups: BTreeMap<&'static str, (Group, &LocRule)> = BTreeMap::new();
    for e in entries {
        let p = format!("{}\\", lower_fs(e));
        for r in LOCATION_RULES {
            if p.contains(&format!("{}\\", r.needle.trim_end_matches('\\'))) {
                groups
                    .entry(r.title)
                    .or_insert_with(|| (Group::new(), r))
                    .0
                    .entries
                    .push(e);
                break;
            }
        }
    }
    for (_, (g, r)) in groups {
        out.push(g.finding(r.severity, r.rule, r.title.to_string(), r.why.to_string()));
    }
}

fn watchlist(entries: &[ShellBagEntry], opts: &FindingOptions, out: &mut Vec<Finding>) {
    let mut groups: BTreeMap<(usize, String), (Group, &WatchRule)> = BTreeMap::new();
    for e in entries {
        let mut names = vec![e.item.segment()];
        if let Some(s) = &e.item.short_name {
            names.push(s.clone());
        }
        for (i, r) in opts.watchlist.iter().enumerate() {
            if names.iter().any(|n| r.matches(n)) {
                groups
                    .entry((i, e.item.segment().to_lowercase()))
                    .or_insert_with(|| (Group::new(), r))
                    .0
                    .entries
                    .push(e);
                break;
            }
        }
    }
    for ((_, seg), (g, r)) in groups {
        out.push(g.finding(
            r.severity,
            "watchlist.match",
            format!("Watchlist: '{seg}' — {}", r.label),
            format!("Folder name matched watchlist pattern '{}'. Verify the folder's contents and origin.", r.pattern),
        ));
    }
}

fn cloud(entries: &[ShellBagEntry], out: &mut Vec<Finding>) {
    const NAMES: [&str; 9] = [
        "onedrive",
        "dropbox",
        "google drive",
        "my drive",
        "box",
        "mega",
        "icloud drive",
        "pcloud drive",
        "nextcloud",
    ];
    let mut groups: BTreeMap<String, Group> = BTreeMap::new();
    for e in entries {
        let seg = e.item.segment().to_lowercase();
        if let Some(n) = NAMES
            .iter()
            .find(|n| seg == **n || seg.starts_with(&format!("{n} -")))
        {
            groups
                .entry(n.to_string())
                .or_insert_with(Group::new)
                .entries
                .push(e);
        }
    }
    for (n, g) in groups {
        out.push(g.finding(
            Severity::Info,
            "cloud.sync_folder",
            format!("Cloud storage folder browsed: {n}"),
            "Cloud sync folders are a convenient exfiltration channel; review what was browsed beneath them.".into(),
        ));
    }
}

fn control_panel(entries: &[ShellBagEntry], out: &mut Vec<Finding>) {
    const INTEREST: [&str; 7] = [
        "BitLocker Drive Encryption",
        "Credential Manager",
        "Windows Firewall",
        "User Accounts",
        "Security and Maintenance",
        "Programs and Features",
        "Backup and Restore",
    ];
    let mut g = Group::new();
    for e in entries {
        if matches!(
            e.item.category,
            Category::ControlPanelItem | Category::RootFolder
        ) && INTEREST.contains(&e.item.name.as_str())
        {
            g.entries.push(e);
        }
    }
    if !g.entries.is_empty() {
        out.push(g.finding(
            Severity::Info,
            "control_panel.security_applet",
            "Security-relevant Control Panel applets opened".into(),
            "Shows interaction with encryption, credential, firewall, account or software-management settings.".into(),
        ));
    }
}

fn status(entries: &[ShellBagEntry], out: &mut Vec<Finding>) {
    let mut rec = Group::new();
    let mut orph = Group::new();
    let mut mru = Group::new();
    for e in entries {
        match e.status {
            EntryStatus::Recovered => rec.entries.push(e),
            EntryStatus::Orphaned => orph.entries.push(e),
            EntryStatus::Active => {}
        }
        if e.notes.iter().any(|n| n.contains("MRUListEx")) {
            mru.entries.push(e);
        }
    }
    if !rec.entries.is_empty() {
        out.push(rec.finding(
            Severity::Medium,
            "integrity.recovered_entries",
            format!("{} deleted ShellBag record(s) recovered from unallocated hive space", rec.entries.len()),
            "BagMRU keys/values were deleted. Windows prunes old bags itself, but deletion can also come from \
             privacy cleaners or deliberate anti-forensics. Recovered paths show folders the user browsed that \
             no longer appear in the live tree."
                .into(),
        ));
    }
    if !orph.entries.is_empty() {
        out.push(orph.finding(
            Severity::Low,
            "integrity.orphaned_bags",
            "Orphaned BagMRU keys (no matching shell item value)".into(),
            "A numbered BagMRU subkey exists without the parent value describing it — consistent with partial \
             deletion or manual editing of the registry."
                .into(),
        ));
    }
    if !mru.entries.is_empty() {
        out.push(mru.finding(
            Severity::Info,
            "integrity.mru_inconsistency",
            "BagMRU values missing from MRUListEx".into(),
            "Values not referenced by the parent's MRUListEx can result from interrupted writes or tampering.".into(),
        ));
    }
}

fn timestamps(entries: &[ShellBagEntry], opts: &FindingOptions, out: &mut Vec<Finding>) {
    let max_key = entries
        .iter()
        .filter_map(|e| e.key_last_written.or(e.parent_last_written))
        .max();
    let mut later_than_key = Group::new();
    let mut future = Group::new();
    for e in entries {
        let target = [e.item.created, e.item.modified]
            .into_iter()
            .flatten()
            .max();
        let Some(t) = target else { continue };
        let reference = e.key_last_written.or(e.parent_last_written);
        if let Some(k) = reference {
            if t.unix_seconds() > k.unix_seconds() + opts.skew_secs {
                later_than_key.entries.push(e);
                continue;
            }
        }
        if let Some(m) = max_key {
            if t.unix_seconds() > m.unix_seconds() + opts.skew_secs {
                future.entries.push(e);
            }
        }
    }
    if !later_than_key.entries.is_empty() {
        out.push(later_than_key.finding(
            Severity::Low,
            "time.target_after_key",
            "Target timestamps later than the BagMRU key LastWrite".into(),
            format!(
                "A shell item snapshots the folder's times when it is registered, so they should not be later than \
                 the BagMRU key's LastWrite (tolerance {} h for FAT precision/time zones). Possible causes: \
                 clock changes, timestomping of the folder, or registry tampering.",
                opts.skew_secs / 3600
            ),
        ));
    }
    if !future.entries.is_empty() {
        out.push(future.finding(
            Severity::Low,
            "time.target_after_hive",
            "Target timestamps later than any registry activity".into(),
            "Folder timestamps postdate the newest BagMRU key write — suggests clock manipulation or a \
             timestamp-altered folder."
                .into(),
        ));
    }
}

fn mft(entries: &[ShellBagEntry], out: &mut Vec<Finding>) {
    // Same MFT entry with different sequence numbers on the same volume.
    let mut by_entry: BTreeMap<(String, Option<String>, String, u64), Vec<&ShellBagEntry>> =
        BTreeMap::new();
    for e in entries {
        if let (Some(n), Some(_)) = (e.item.mft_entry, e.item.mft_sequence) {
            let vol = e
                .fs_path
                .as_deref()
                .and_then(|p| p.split('\\').next())
                .unwrap_or("")
                .to_lowercase();
            by_entry
                .entry((e.source.clone(), e.user.clone(), vol, n))
                .or_default()
                .push(e);
        }
    }
    let mut g = Group::new();
    for (_, list) in by_entry {
        let mut seqs: Vec<u16> = list.iter().filter_map(|e| e.item.mft_sequence).collect();
        seqs.sort();
        seqs.dedup();
        if seqs.len() > 1 {
            g.entries.extend(list);
        }
    }
    if !g.entries.is_empty() {
        out.push(g.finding(
            Severity::Info,
            "mft.entry_reuse",
            "MFT entry reused by different folders".into(),
            "The same MFT record number appears with different sequence numbers: the original folder was \
             deleted and the record reallocated. Older shell bags therefore describe folders that no longer exist."
                .into(),
        ));
    }
}

fn hive_health(hives: &[HiveReport], out: &mut Vec<Finding>) {
    for h in hives {
        if h.dirty {
            let applied = h.recovery.as_ref().map(|r| r.entries_applied).unwrap_or(0);
            let (sev, title, why) = if applied > 0 {
                (
                    Severity::Info,
                    format!("Dirty hive reconciled with transaction logs: {}", h.path),
                    "The hive had unflushed changes; transaction logs were replayed in memory so recent ShellBag \
                     activity is included."
                        .to_string(),
                )
            } else {
                (
                    Severity::Medium,
                    format!("Dirty hive parsed WITHOUT transaction logs: {}", h.path),
                    "The hive's sequence numbers or checksum show unflushed changes, but no usable .LOG1/.LOG2 \
                     were found. The most recent ShellBag activity may be missing — collect the transaction logs."
                        .to_string(),
                )
            };
            out.push(Finding {
                severity: sev,
                rule: "hive.dirty",
                title,
                rationale: why,
                first_seen: None,
                last_seen: None,
                user: h.user.clone(),
                entry_ids: Vec::new(),
                paths: vec![h.path.clone()],
            });
        }
    }
}
