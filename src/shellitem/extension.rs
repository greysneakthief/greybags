//! Shell item extension blocks (0xbeefXXXX).

use super::dissect::Dis;
use super::propstore::{self, Property};
use super::ShellItem;
use crate::util::bytes::{u16_at, u32_at};
use crate::util::known;
use crate::util::Guid;
use serde::{Serialize, Serializer};

#[derive(Debug, Clone, Serialize)]
pub struct ExtensionBlock {
    pub offset: usize,
    pub size: u16,
    pub version: u16,
    #[serde(serialize_with = "hex32")]
    pub signature: u32,
    pub name: &'static str,
    #[serde(
        skip_serializing_if = "Vec::is_empty",
        serialize_with = "super::pairs_as_map"
    )]
    pub details: Vec<(String, String)>,
}

fn hex32<S: Serializer>(v: &u32, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&format!("0x{v:08x}"))
}

pub fn block_name(sig: u32) -> &'static str {
    match sig {
        0xbeef0000 => "Folder type / merged folder",
        0xbeef0001 => "CFileUrlStub",
        0xbeef0003 => "Shell folder identifier",
        0xbeef0004 => "File entry extension",
        0xbeef0005 => "Embedded shell item list (CFindFolder)",
        0xbeef0006 => "Personalized name / user name",
        0xbeef0008 => "Recycle bin information",
        0xbeef000a => "Merged folder source",
        0xbeef000b => "Application/command data",
        0xbeef000e => "Sub shell item list",
        0xbeef0010 => "Property store",
        0xbeef0013 => "Unknown (0xbeef0013)",
        0xbeef0014 => "Class data (CUri)",
        0xbeef0016 => "String data",
        0xbeef0017 => "Search folder data",
        0xbeef0019 => "Folder type identifier",
        0xbeef001a => "Document type / embedded list",
        0xbeef0021 => "Property store",
        0xbeef0025 => "Timestamps (0xbeef0025)",
        0xbeef0026 => "Timestamps (0xbeef0026)",
        0xbeef0027 => "Property store",
        0xbeef0029 => "Unknown (0xbeef0029)",
        _ => "Unknown extension block",
    }
}

fn is_block_at(b: &[u8], off: usize) -> bool {
    match (u16_at(b, off), u32_at(b, off + 4)) {
        (Some(size), Some(sig)) => {
            size >= 8 && off + size as usize <= b.len() && sig & 0xFFFF_0000 == 0xBEEF_0000
        }
        _ => false,
    }
}

/// Finds the first extension block at or after `from`. Prefers the
/// "first extension block offset" stored in the item's last two bytes,
/// then falls back to a scan for the 0xbeef signature.
pub fn locate_first(raw: &[u8], from: usize) -> Option<usize> {
    if raw.len() >= 4 {
        if let Some(ptr) = u16_at(raw, raw.len() - 2) {
            let p = ptr as usize;
            if p >= from && is_block_at(raw, p) {
                return Some(p);
            }
        }
    }
    let mut p = from;
    while p + 8 <= raw.len() {
        if raw[p + 6] == 0xef && raw[p + 7] == 0xbe && is_block_at(raw, p) {
            return Some(p);
        }
        p += 1;
    }
    None
}

/// Parses all chained extension blocks starting at `start`, applying their
/// information to `item`.
pub fn parse_chain(item: &mut ShellItem, d: &mut Dis, start: usize, depth: usize) -> usize {
    let mut pos = start;
    let mut count = 0;
    while pos + 8 <= d.len() && count < 32 {
        let size = u16_at(d.data, pos).unwrap_or(0) as usize;
        if size == 0 {
            break;
        }
        if !is_block_at(d.data, pos) {
            break;
        }
        let mut sub = d.sub(pos, size);
        let block = parse_block(item, &mut sub, depth);
        d.absorb(sub);
        let mut block = block;
        block.offset = d.base + pos;
        item.extension_blocks.push(block);
        pos += size;
        count += 1;
    }
    pos
}

fn parse_block(item: &mut ShellItem, d: &mut Dis, depth: usize) -> ExtensionBlock {
    let size = d.u16(0, "Extension block size").unwrap_or(0);
    let version = d.u16(2, "Extension block version").unwrap_or(0);
    let signature = d.sig(4, "Extension block signature").unwrap_or(0);
    let mut details = Vec::new();
    let len = d.len();
    match signature {
        0xbeef0004 => parse_beef0004(item, d, version, &mut details),
        0xbeef0003 => {
            if let Some(g) = d.guid(8, "Shell folder identifier") {
                details.push(("shell_folder".into(), describe_guid(&g)));
            }
        }
        0xbeef0000 if len >= 40 => {
            if let Some(g) = d.guid(8, "Folder type identifier") {
                details.push(("folder_type".into(), describe_folder_type(&g)));
            }
            d.guid(24, "Unknown identifier (TopViews?)");
        }
        0xbeef0019 => {
            if let Some(g) = d.guid(8, "Folder type identifier") {
                details.push(("folder_type".into(), describe_folder_type(&g)));
            }
            d.guid(24, "Unknown identifier (TopViews?)");
        }
        0xbeef0006 => {
            if let Some((s, _)) = d.utf16z(8, "User name") {
                details.push(("user_name".into(), s.clone()));
                item.details.push(("ext_user_name".into(), s));
            }
        }
        0xbeef0008 => {
            if let Some(t) = d.filetime(16, "Deletion time (?)") {
                details.push(("deletion_time".into(), t.to_iso()));
            }
            if let Some((s, _)) = d.utf16z(24, "Original path (?)") {
                details.push(("original_path".into(), s.clone()));
                item.details.push(("recycle_original_path".into(), s));
            }
        }
        0xbeef0005 if depth < 4 && len > 26 => {
            let list = super::parse_list_inner(&d.data[24..len - 2], depth + 1);
            let names: Vec<String> = list.iter().map(|i| i.name.clone()).collect();
            d.note(24, len - 26, "Embedded shell item list", names.join("\\"));
            details.push(("embedded_list".into(), names.join("\\")));
        }
        0xbeef000e if depth < 4 && len > 10 => {
            let list = super::parse_list_inner(&d.data[8..len - 2], depth + 1);
            let names: Vec<String> = list.iter().map(|i| i.name.clone()).collect();
            d.note(8, len - 10, "Sub shell item list", names.join("\\"));
            details.push(("sub_list".into(), names.join("\\")));
        }
        0xbeef001a => {
            if let Some((s, _)) = d.utf16z(10, "Document type") {
                details.push(("document_type".into(), s));
            }
        }
        0xbeef0014 => parse_beef0014(d, &mut details),
        0xbeef0025 => {
            let t1 = d.filetime(12, "FILETIME 1");
            let t2 = d.filetime(20, "FILETIME 2");
            if let Some(t) = t1 {
                details.push(("filetime1".into(), t.to_iso()));
                item.details.push(("beef0025_filetime1".into(), t.to_iso()));
            }
            if let Some(t) = t2 {
                details.push(("filetime2".into(), t.to_iso()));
                item.details.push(("beef0025_filetime2".into(), t.to_iso()));
            }
        }
        0xbeef0026 => {
            let flag = d.u32(8, "Unknown (flags)").unwrap_or(0);
            if matches!(flag & 0xFF, 0x10 | 0x11 | 0x12 | 0x31 | 0x34) || len >= 36 {
                let c = d.filetime(12, "Created (FILETIME)");
                let m = d.filetime(20, "Modified (FILETIME)");
                let a = d.filetime(28, "Accessed (FILETIME)");
                for (k, v) in [("created", c), ("modified", m), ("accessed", a)] {
                    if let Some(t) = v {
                        details.push((k.into(), t.to_iso()));
                    }
                }
                item.ext_created = c.or(item.ext_created);
                item.ext_modified = m.or(item.ext_modified);
                item.ext_accessed = a.or(item.ext_accessed);
            }
        }
        0xbeef0010 => {
            let (props, _) = propstore::parse_sets(d, 16);
            push_props(item, &mut details, props);
        }
        0xbeef0021 => {
            let (props, _) = propstore::parse_sets(d, 8);
            push_props(item, &mut details, props);
        }
        0xbeef0027 => {
            let (props, _) = propstore::parse_sets(d, 10);
            push_props(item, &mut details, props);
        }
        _ => {}
    }
    if len >= 10 {
        d.u16(len - 2, "First extension block offset");
    }
    ExtensionBlock {
        offset: 0,
        size,
        version,
        signature,
        name: block_name(signature),
        details,
    }
}

fn push_props(item: &mut ShellItem, details: &mut Vec<(String, String)>, props: Vec<Property>) {
    for p in props {
        details.push((p.label(), p.value.to_string()));
        item.properties.push(p);
    }
}

/// File entry extension block: creation/access times, NTFS reference,
/// long (Unicode) name and localized name.
fn parse_beef0004(
    item: &mut ShellItem,
    d: &mut Dis,
    version: u16,
    details: &mut Vec<(String, String)>,
) {
    let created = d.fat(8, "Creation time (FAT)");
    let accessed = d.fat(12, "Last access time (FAT)");
    let long_off = d.u16(16, "Long name offset").unwrap_or(0) as usize;
    let mut localized_off = 0usize;
    if version >= 7 {
        d.u16(18, "Unknown (empty)");
        let entry = crate::util::bytes::u48_at(d.data, 20);
        let seq = u16_at(d.data, 26);
        if let (Some(e), Some(s)) = (entry, seq) {
            d.note(20, 6, "MFT entry index", e.to_string());
            d.note(26, 2, "MFT sequence number", s.to_string());
            if e != 0 || s != 0 {
                item.mft_entry = Some(e);
                item.mft_sequence = Some(s);
                details.push(("mft_reference".into(), format!("{e}-{s}")));
            }
        }
        d.u64(28, "Unknown");
        localized_off = d.u16(36, "Localized name offset").unwrap_or(0) as usize;
        if version >= 9 {
            d.u32(38, "Unknown (empty)");
        }
        if version >= 8 {
            d.u32(if version >= 9 { 42 } else { 38 }, "Unknown");
        }
    } else if version >= 3 {
        localized_off = d.u16(18, "Localized name offset").unwrap_or(0) as usize;
    }
    // Long name: honour the stored offset, fall back to the version layout.
    let fallback = match version {
        v if v >= 9 => 46,
        8 => 42,
        7 => 38,
        _ => 20,
    };
    let lo = if long_off >= 18 && long_off + 2 <= d.len() {
        long_off
    } else {
        fallback
    };
    if let Some((s, _)) = d.utf16z(lo, "Long name") {
        if !s.is_empty() {
            details.push(("long_name".into(), s.clone()));
            item.long_name = Some(s);
        }
    }
    if localized_off >= 18 && localized_off + 2 <= d.len() {
        let loc = if version >= 7 {
            d.utf16z(localized_off, "Localized name").map(|x| x.0)
        } else {
            d.ansiz(localized_off, "Localized name", encoding_rs::WINDOWS_1252)
                .map(|x| x.0)
        };
        if let Some(s) = loc.filter(|s| !s.is_empty()) {
            details.push(("localized_name".into(), s.clone()));
            item.localized_name = Some(s);
        }
    }
    item.created = created.or(item.created);
    item.accessed = accessed.or(item.accessed);
    item.ext_version = Some(version);
    if let Some(t) = created {
        details.push(("created".into(), t.to_iso()));
    }
    if let Some(t) = accessed {
        details.push(("accessed".into(), t.to_iso()));
    }
}

/// CUri properties (extension block 0xbeef0014 with the CUri CLSID).
fn parse_beef0014(d: &mut Dis, details: &mut Vec<(String, String)>) {
    let Some(clsid) = d.guid(8, "Class identifier") else {
        return;
    };
    if clsid.to_string() != known::CURI_CLSID {
        return;
    }
    let base = 24;
    d.u32(base, "CUri data size");
    let Some(count) = d.u32(base + 24, "Number of CUri properties") else {
        return;
    };
    let mut pos = base + 28;
    for _ in 0..count.min(32) {
        let (Some(ptype), Some(psize)) = (u32_at(d.data, pos), u32_at(d.data, pos + 4)) else {
            break;
        };
        let psize = psize as usize;
        if pos + 8 + psize > d.len() {
            break;
        }
        let name = match ptype {
            0 => "absolute_uri",
            1 => "authority",
            2 => "display_uri",
            3 => "domain",
            4 => "extension",
            5 => "fragment",
            6 => "host",
            7 => "password",
            8 => "path",
            9 => "path_and_query",
            10 => "query",
            11 => "raw_uri",
            12 => "scheme_name",
            13 => "user_info",
            14 => "user_name",
            15 => "host_type",
            16 => "port",
            17 => "scheme",
            18 => "zone",
            _ => "unknown",
        };
        let val = if (15..=18).contains(&ptype) && psize == 4 {
            u32_at(d.data, pos + 8)
                .map(|v| v.to_string())
                .unwrap_or_default()
        } else {
            crate::util::bytes::utf16le_lossy(&d.data[pos + 8..pos + 8 + (psize & !1)])
                .trim_end_matches('\0')
                .to_string()
        };
        d.note(pos, 8 + psize, &format!("CUri {name}"), val.clone());
        if !val.is_empty() {
            details.push((name.into(), val));
        }
        pos += 8 + psize;
        pos = (pos + 3) & !3;
    }
}

pub fn describe_guid(g: &Guid) -> String {
    match known::shell_folder(g) {
        Some(n) => format!("{g} ({n})"),
        None => g.to_string(),
    }
}

pub fn describe_folder_type(g: &Guid) -> String {
    match known::folder_type(g) {
        Some(n) => format!("{g} ({n})"),
        None => g.to_string(),
    }
}
