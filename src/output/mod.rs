//! Output writers for entries and timelines.

use crate::analysis::timeline::TimelineEvent;
use crate::shellbags::{ScanResult, ShellBagEntry};
use crate::shellitem::attribute_names;
use crate::util::bytes::to_hex;
use crate::util::Timestamp;
use std::io::{self, Write};

fn t(v: Option<Timestamp>) -> String {
    v.map(|t| t.to_iso()).unwrap_or_default()
}

fn opt<T: ToString>(v: Option<T>) -> String {
    v.map(|x| x.to_string()).unwrap_or_default()
}

#[derive(Debug, Clone, Copy, Default)]
pub struct EntryOutputOptions {
    pub raw: bool,
    pub fields: bool,
}

pub const CSV_HEADER: &[&str] = &[
    "Id",
    "ParentId",
    "Status",
    "Source",
    "HiveType",
    "User",
    "Location",
    "BagPath",
    "ValueName",
    "MRUPosition",
    "NodeSlot",
    "Depth",
    "AbsolutePath",
    "FsPath",
    "ShellType",
    "Category",
    "Name",
    "ShortName",
    "ChildCount",
    "KeyLastWritten",
    "FirstInteracted",
    "LastInteracted",
    "LastExplored",
    "Created",
    "Modified",
    "Accessed",
    "ExtCreated",
    "ExtModified",
    "ExtAccessed",
    "MFTEntry",
    "MFTSequence",
    "FileSize",
    "Attributes",
    "ExtVersion",
    "ExtensionBlocks",
    "GUID",
    "FolderType",
    "BagLastWritten",
    "Details",
    "Notes",
];

pub fn write_csv<W: Write>(
    w: W,
    entries: &[ShellBagEntry],
    o: EntryOutputOptions,
) -> io::Result<()> {
    let mut c = csv::Writer::from_writer(w);
    let mut header: Vec<&str> = CSV_HEADER.to_vec();
    if o.raw {
        header.push("Raw");
    }
    c.write_record(&header)?;
    for e in entries {
        let it = &e.item;
        let blocks: Vec<String> = it
            .extension_blocks
            .iter()
            .map(|b| format!("0x{:08x}", b.signature))
            .collect();
        let mut details: Vec<String> = it.details.iter().map(|(k, v)| format!("{k}={v}")).collect();
        details.extend(
            it.properties
                .iter()
                .map(|p| format!("{}={}", p.label(), p.value)),
        );
        let mut rec = vec![
            e.id.to_string(),
            opt(e.parent_id),
            e.status.label().to_string(),
            e.source.clone(),
            e.hive_kind.label().to_string(),
            e.user.clone().unwrap_or_default(),
            e.location.clone(),
            e.bag_path.clone(),
            e.value_name.clone(),
            opt(e.mru_position),
            opt(e.node_slot),
            e.depth.to_string(),
            e.absolute_path.clone(),
            e.fs_path.clone().unwrap_or_default(),
            it.type_name.clone(),
            it.category.label().to_string(),
            it.name.clone(),
            it.short_name.clone().unwrap_or_default(),
            e.child_count.to_string(),
            t(e.key_last_written),
            t(e.first_interacted),
            t(e.last_interacted),
            t(e.last_explored),
            t(it.created),
            t(it.modified),
            t(it.accessed),
            t(it.ext_created),
            t(it.ext_modified),
            t(it.ext_accessed),
            opt(it.mft_entry),
            opt(it.mft_sequence),
            opt(it.file_size),
            it.attributes
                .map(|a| attribute_names(a).join("|"))
                .unwrap_or_default(),
            opt(it.ext_version),
            blocks.join(" "),
            it.guid.map(|g| g.to_string()).unwrap_or_default(),
            e.bag
                .as_ref()
                .map(|b| b.folder_types.join("; "))
                .unwrap_or_default(),
            t(e.bag
                .as_ref()
                .and_then(|b| b.view_last_written.or(b.last_written))),
            details.join("; "),
            e.notes.join("; "),
        ];
        if o.raw {
            rec.push(to_hex(&it.raw));
        }
        c.write_record(&rec)?;
    }
    c.flush()
}

/// Column layout modelled on Eric Zimmerman's SBECmd CSV so existing
/// Timeline Explorer layouts and habits carry over. Values are produced by
/// greybags, not SBECmd.
pub fn write_csv_sbe<W: Write>(w: W, entries: &[ShellBagEntry]) -> io::Result<()> {
    let mut c = csv::Writer::from_writer(w);
    c.write_record([
        "BagPath",
        "Slot",
        "NodeSlot",
        "MRUPosition",
        "AbsolutePath",
        "ShellType",
        "Value",
        "ChildBags",
        "CreatedOn",
        "ModifiedOn",
        "AccessedOn",
        "LastWriteTime",
        "MFTEntry",
        "MFTSequenceNumber",
        "ExtensionBlockCount",
        "FirstInteracted",
        "LastInteracted",
        "HasExplored",
        "Miscellaneous",
        "SourceFile",
    ])?;
    let sbe_time = |v: Option<Timestamp>| v.map(|t| t.to_short()).unwrap_or_default();
    for e in entries {
        let it = &e.item;
        let slot = e.value_name.clone();
        let bag_path = format!(
            "{}\\{}",
            e.location,
            e.bag_path
                .trim_start_matches("BagMRU")
                .trim_start_matches('\\')
        );
        let mut misc: Vec<String> = it
            .details
            .iter()
            .map(|(k, v)| format!("{k}: {v}"))
            .collect();
        if e.status != crate::shellbags::EntryStatus::Active {
            misc.insert(0, format!("Status: {}", e.status.label()));
        }
        c.write_record([
            bag_path.trim_end_matches('\\').to_string(),
            slot,
            opt(e.node_slot),
            opt(e.mru_position),
            e.absolute_path.clone(),
            it.type_name.clone(),
            it.name.clone(),
            e.child_count.to_string(),
            sbe_time(it.created.or(it.ext_created)),
            sbe_time(it.modified.or(it.ext_modified)),
            sbe_time(it.accessed.or(it.ext_accessed)),
            sbe_time(e.key_last_written),
            opt(it.mft_entry),
            opt(it.mft_sequence),
            it.extension_blocks.len().to_string(),
            sbe_time(e.first_interacted),
            sbe_time(e.last_interacted),
            (e.last_explored.is_some()).to_string(),
            misc.join(", "),
            e.source.clone(),
        ])?;
    }
    c.flush()
}

fn strip_for_json(e: &ShellBagEntry, o: EntryOutputOptions) -> ShellBagEntry {
    let mut e = e.clone();
    if !o.fields {
        e.item.fields.clear();
        for x in &mut e.extra_items {
            x.fields.clear();
        }
    }
    if !o.raw {
        e.item.raw.clear();
        for x in &mut e.extra_items {
            x.raw.clear();
        }
    }
    e
}

pub fn write_json<W: Write>(mut w: W, scan: &ScanResult, o: EntryOutputOptions) -> io::Result<()> {
    let entries: Vec<ShellBagEntry> = scan.entries.iter().map(|e| strip_for_json(e, o)).collect();
    let doc = serde_json::json!({
        "generated_by": format!("greybags {}", env!("CARGO_PKG_VERSION")),
        "hives": scan.hives,
        "errors": scan.errors,
        "entries": entries,
    });
    serde_json::to_writer_pretty(&mut w, &doc)?;
    writeln!(w)
}

pub fn write_jsonl<W: Write>(
    mut w: W,
    entries: &[ShellBagEntry],
    o: EntryOutputOptions,
) -> io::Result<()> {
    for e in entries {
        serde_json::to_writer(&mut w, &strip_for_json(e, o))?;
        writeln!(w)?;
    }
    Ok(())
}

pub fn write_table<W: Write>(mut w: W, entries: &[ShellBagEntry]) -> io::Result<()> {
    writeln!(
        w,
        "{:<19}  {:<3}  {:<9}  {:<24}  PATH",
        "LAST ACTIVITY (UTC)", "MRU", "STATUS", "TYPE"
    )?;
    writeln!(w, "{}", "-".repeat(110))?;
    for e in entries {
        let when = e
            .activity_time()
            .map(|t| t.to_short())
            .unwrap_or_else(|| "-".into());
        let mut ty: String = e.item.type_name.chars().take(24).collect();
        if e.item.type_name.chars().count() > 24 {
            ty.pop();
            ty.push('…');
        }
        writeln!(
            w,
            "{:<19}  {:<3}  {:<9}  {:<24}  {}",
            when,
            opt(e.mru_position),
            e.status.label(),
            ty,
            e.fs_path.as_deref().unwrap_or(&e.absolute_path)
        )?;
    }
    Ok(())
}

/// Hierarchical view. Entries are grouped per hive/location and printed
/// depth-first, so recovered entries appear under their surviving parents.
pub fn write_tree<W: Write>(mut w: W, scan: &ScanResult) -> io::Result<()> {
    use std::collections::{BTreeMap, HashMap, HashSet};
    let ids: HashSet<usize> = scan.entries.iter().map(|e| e.id).collect();
    let mut children: HashMap<usize, Vec<&ShellBagEntry>> = HashMap::new();
    let mut roots: BTreeMap<(String, String), Vec<&ShellBagEntry>> = BTreeMap::new();
    for e in &scan.entries {
        match e.parent_id.filter(|p| ids.contains(p)) {
            Some(p) => children.entry(p).or_default().push(e),
            None => roots
                .entry((e.source.clone(), e.location.clone()))
                .or_default()
                .push(e),
        }
    }
    fn node<W: Write>(
        w: &mut W,
        e: &ShellBagEntry,
        level: usize,
        children: &HashMap<usize, Vec<&ShellBagEntry>>,
    ) -> io::Result<()> {
        let marker = match e.status {
            crate::shellbags::EntryStatus::Active => "",
            crate::shellbags::EntryStatus::Orphaned => " [ORPHANED]",
            crate::shellbags::EntryStatus::Recovered => " [RECOVERED]",
        };
        let when = e
            .activity_time()
            .map(|t| format!("  @ {}", t.to_short()))
            .unwrap_or_default();
        writeln!(
            w,
            "{}{} <{}>{marker}{when}",
            "  ".repeat(level + 1),
            e.item.segment(),
            e.item.type_name
        )?;
        if level < 256 {
            if let Some(kids) = children.get(&e.id) {
                for k in kids {
                    node(w, k, level + 1, children)?;
                }
            }
        }
        Ok(())
    }
    for ((source, location), list) in &roots {
        let user = list.iter().find_map(|e| e.user.clone());
        writeln!(
            w,
            "\n{source} :: {location}{}",
            user.map(|u| format!("  (user {u})")).unwrap_or_default()
        )?;
        for e in list {
            node(&mut w, e, 0, &children)?;
        }
    }
    Ok(())
}

pub const TIMELINE_HEADER: &[&str] = &[
    "Timestamp",
    "Event",
    "Description",
    "User",
    "Path",
    "FsPath",
    "ShellType",
    "Status",
    "MFTReference",
    "BagPath",
    "Source",
    "EntryId",
];

pub fn write_timeline_csv<W: Write>(w: W, events: &[TimelineEvent]) -> io::Result<()> {
    let mut c = csv::Writer::from_writer(w);
    c.write_record(TIMELINE_HEADER)?;
    for ev in events {
        c.write_record([
            ev.timestamp.to_iso(),
            ev.event.code().to_string(),
            ev.description.to_string(),
            ev.user.clone().unwrap_or_default(),
            ev.path.clone(),
            ev.fs_path.clone().unwrap_or_default(),
            ev.shell_type.clone(),
            ev.status.label().to_string(),
            ev.mft_reference.clone().unwrap_or_default(),
            ev.bag_path.clone(),
            ev.source.clone(),
            ev.entry_id.to_string(),
        ])?;
    }
    c.flush()
}

pub fn write_timeline_jsonl<W: Write>(mut w: W, events: &[TimelineEvent]) -> io::Result<()> {
    for ev in events {
        serde_json::to_writer(&mut w, ev)?;
        writeln!(w)?;
    }
    Ok(())
}

/// Sleuth Kit bodyfile (mactime 3.x): MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime.
/// Each event becomes one line with all four times set to the event time,
/// so `mactime -b file -z UTC` renders it as a "macb" row.
pub fn write_bodyfile<W: Write>(mut w: W, events: &[TimelineEvent]) -> io::Result<()> {
    for ev in events {
        let secs = ev.timestamp.unix_seconds();
        let name = format!(
            "[ShellBag:{}] {}{}",
            ev.event.code(),
            ev.fs_path.as_deref().unwrap_or(&ev.path),
            ev.user
                .as_ref()
                .map(|u| format!(" (user {u})"))
                .unwrap_or_default()
        )
        .replace('|', "/");
        let inode = ev.mft_reference.clone().unwrap_or_else(|| "0".into());
        writeln!(w, "0|{name}|{inode}|0|0|0|0|{secs}|{secs}|{secs}|{secs}")?;
    }
    Ok(())
}
