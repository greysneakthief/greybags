//! Class-type-indicator based shell items.

use super::dissect::Dis;
use super::extension::{self, describe_guid};
use super::{attribute_names, Category, ParseOptions, ShellItem};
use crate::util::bytes::u32_at;
use crate::util::known;

/// Dispatches on the class type indicator. Returns false if unhandled.
pub fn parse(item: &mut ShellItem, d: &mut Dis, opts: &ParseOptions, depth: usize) -> bool {
    let class = item.class_type;
    match class {
        0x1f => root_folder(item, d),
        c if c & 0x70 == 0x20 => volume(item, d, opts),
        c if c & 0x70 == 0x30 => file_entry(item, d, opts, 0, depth),
        c if c & 0x70 == 0x40 => network(item, d, opts),
        0x61 => uri(item, d),
        0x71 => control_panel_item(item, d),
        _ => return false,
    }
    true
}

pub fn root_folder(item: &mut ShellItem, d: &mut Dis) {
    item.category = Category::RootFolder;
    let sort = d.u8(3, "Sort index").unwrap_or(0);
    if let Some(s) = known::sort_index(sort) {
        item.details
            .push(("sort_index".into(), format!("0x{sort:02x} ({s})")));
    }
    item.type_name = "Root folder".into();
    if let Some(g) = d.guid(4, "Shell folder identifier") {
        set_guid(item, g);
        item.type_name = match item.guid_name.as_deref() {
            Some(n) => format!("Root folder: {n}"),
            None => "Root folder: GUID".into(),
        };
    }
    if d.len() > 22 {
        if let Some(start) = extension::locate_first(d.data, 20) {
            extension::parse_chain(item, d, start, 0);
        }
    }
}

pub fn set_guid(item: &mut ShellItem, g: crate::util::Guid) {
    item.guid_name = known::shell_folder(&g).map(str::to_string);
    item.guid = Some(g);
}

pub fn volume(item: &mut ShellItem, d: &mut Dis, opts: &ParseOptions) {
    item.category = Category::Volume;
    let class = item.class_type;
    let has_name = class & 0x01 != 0;
    // libfwsi documents bit 0x08 as "removable media", but Windows sets it
    // on fixed C: volumes too (class 0x2f), so it is reported, not trusted.
    item.details
        .push(("class_flags".into(), format!("0x{:x}", class & 0x0f)));
    if has_name {
        let field = d.data.get(3..23.min(d.len())).unwrap_or(&[]);
        let name = crate::util::bytes::ansi_fixed(field, opts.codepage);
        d.note(3, field.len(), "Volume name", format!("\"{name}\""));
        item.name = name;
        item.type_name = "Drive letter".into();
        if d.len() >= 25 {
            d.u16(23, "Unknown");
        }
        if d.len() >= 41 {
            if let Some(g) = crate::util::Guid::at(d.data, 25) {
                if !g.is_nil() {
                    d.guid(25, "Shell folder identifier");
                    set_guid(item, g);
                }
            }
        }
        if let Some(start) = extension::locate_first(d.data, 25) {
            extension::parse_chain(item, d, start, 0);
        }
    } else {
        d.u8(3, "Unknown (flags)");
        item.type_name = "Volume (GUID)".into();
        if let Some(g) = d.guid(4, "Volume / shell folder identifier") {
            set_guid(item, g);
            if let Some(n) = &item.guid_name {
                item.type_name = format!("Volume: {n}");
                item.name = n.clone();
            }
        }
        if let Some(start) = extension::locate_first(d.data, 20) {
            extension::parse_chain(item, d, start, 0);
        }
    }
}

/// File entry shell item (also used for the file entry embedded in
/// delegate items, where `base` is the offset of the embedded item).
pub fn file_entry(
    item: &mut ShellItem,
    d: &mut Dis,
    opts: &ParseOptions,
    base: usize,
    depth: usize,
) {
    let class = d.data.get(base + 2).copied().unwrap_or(item.class_type);
    let is_dir = class & 0x01 != 0;
    let is_file = class & 0x02 != 0;
    let unicode = class & 0x04 != 0;
    item.category = if is_dir {
        Category::Directory
    } else if is_file {
        Category::File
    } else {
        Category::FileEntry
    };
    item.type_name = match (is_dir, is_file) {
        (true, _) => "Directory".into(),
        (_, true) => "File".into(),
        _ => format!("File entry (class 0x{class:02x})"),
    };
    if base > 0 {
        d.u8(base + 2, "Embedded class type indicator");
    }
    d.u8(base + 3, "Unknown (empty)");
    if let Some(sz) = d.u32(base + 4, "File size") {
        if is_file || sz > 0 {
            item.file_size = Some(sz as u64);
        }
    }
    item.modified = d.fat(base + 8, "Last modification time (FAT)");
    if let Some(attr) = d.u16(base + 12, "File attribute flags") {
        item.attributes = Some(attr as u32);
        let names = attribute_names(attr as u32);
        if !names.is_empty() {
            item.details.push(("attributes".into(), names.join("|")));
        }
    }
    let name_off = base + 14;
    let (primary, consumed) = if unicode {
        d.utf16z(name_off, "Primary name (UTF-16)")
            .unwrap_or_default()
    } else {
        d.ansiz(name_off, "Primary name", opts.codepage)
            .unwrap_or_default()
    };
    item.short_name = Some(primary.clone()).filter(|s| !s.is_empty());
    let mut after = name_off + consumed;
    if after % 2 == 1 {
        after += 1; // 16-bit alignment
    }
    if class & 0x80 != 0 && after + 16 <= d.len() {
        // Pre-XP layout may carry a CLSID here; on XP+ it is in 0xbeef0003.
        if let Some(g) = crate::util::Guid::at(d.data, after) {
            if known::shell_folder(&g).is_some() {
                d.guid(after, "Class identifier");
                set_guid(item, g);
            }
        }
    }
    match extension::locate_first(d.data, after) {
        Some(start) => {
            extension::parse_chain(item, d, start, depth);
        }
        None => {
            // Pre-XP: an optional secondary (short) name follows.
            if after + 1 < d.len() && d.data[after] != 0 {
                let sec = if unicode {
                    d.utf16z(after, "Secondary name")
                } else {
                    d.ansiz(after, "Secondary name", opts.codepage)
                };
                if let Some((s, _)) =
                    sec.filter(|(s, _)| !s.is_empty() && crate::util::bytes::is_printable(s))
                {
                    item.details.push(("secondary_name".into(), s));
                }
            }
        }
    }
    item.name = item
        .long_name
        .clone()
        .or_else(|| item.short_name.clone())
        .unwrap_or_default();
    if let Some(sz) = item.file_size.filter(|_| is_file) {
        item.details.push(("file_size".into(), sz.to_string()));
    }
    if item.ext_version.is_none() && is_dir {
        item.details.push((
            "format".into(),
            "no 0xbeef0004 block (pre-XP or minimal item)".into(),
        ));
    }
}

pub fn network(item: &mut ShellItem, d: &mut Dis, opts: &ParseOptions) {
    item.category = Category::NetworkLocation;
    let sub = item.class_type & 0x0F;
    item.type_name = match sub {
        0x01 => "Network domain/workgroup",
        0x02 => "Network server",
        0x03 => "Network share",
        0x06 => "Microsoft Windows Network",
        0x07 => "Entire Network",
        0x0c => "Network place (web folder)",
        0x0d | 0x0e => "Network place",
        _ => "Network location",
    }
    .to_string();
    if item.class_type == 0x4c || item.class_type == 0x4e {
        // Undocumented variants: 0x4e carries a GUID, 0x4c counted strings.
        if item.class_type == 0x4e {
            if let Some(g) = d.guid(4, "Shell folder identifier") {
                set_guid(item, g);
            }
        }
        let strings: Vec<String> = crate::util::bytes::utf16_strings(d.data, 3)
            .into_iter()
            .map(|(_, s)| s)
            .filter(|s| crate::util::bytes::is_printable(s))
            .collect();
        if let Some(first) = strings.first() {
            item.name = first.clone();
        }
        if strings.len() > 1 {
            item.details.push(("url".into(), strings[1].clone()));
        }
        return;
    }
    d.u8(3, "Unknown");
    let flags = d.u8(4, "Flags").unwrap_or(0);
    let mut pos = 5;
    if let Some((loc, n)) = d.ansiz(pos, "Location", opts.codepage) {
        item.name = loc.clone();
        item.details.push(("location".into(), loc));
        pos += n;
    }
    if flags & 0x80 != 0 {
        if let Some((desc, n)) = d.ansiz(pos, "Description", opts.codepage) {
            if !desc.is_empty() {
                item.details.push(("description".into(), desc));
            }
            pos += n;
        }
    }
    if flags & 0x40 != 0 {
        if let Some((c, n)) = d.ansiz(pos, "Comments", opts.codepage) {
            if !c.is_empty() {
                item.details.push(("comments".into(), c));
            }
            pos += n;
        }
    }
    if pos < d.len() {
        d.note(
            pos,
            d.len() - pos,
            "Trailing data",
            crate::util::bytes::to_hex(&d.data[pos..]),
        );
    }
    if item.name.starts_with("\\\\") {
        item.details.push(("unc".into(), item.name.clone()));
    }
}

pub fn uri(item: &mut ShellItem, d: &mut Dis) {
    item.category = Category::Uri;
    item.type_name = "URI".into();
    let flags = d.u8(3, "Flags").unwrap_or(0);
    let unicode = flags & 0x80 != 0;
    let data_size = d.u16(4, "Data size").unwrap_or(0) as usize;
    let mut pos = 6;
    if data_size > 0 && 6 + data_size <= d.len() {
        d.u32(6, "Unknown");
        d.u32(10, "Unknown");
        if let Some(t) = d.filetime(14, "Connection time (FILETIME)") {
            item.details.push(("connected".into(), t.to_iso()));
            item.accessed = Some(t);
        }
        d.u32(22, "Unknown");
        // Three counted strings (FTP host, user, password), 4-byte aligned.
        let mut spos = 42;
        for label in [
            "String 1 (host)",
            "String 2 (user name)",
            "String 3 (password)",
        ] {
            let Some(sz) = u32_at(d.data, spos) else {
                break;
            };
            let sz = sz as usize;
            if sz > data_size || spos + 4 + sz > 6 + data_size {
                break;
            }
            d.u32(spos, &format!("{label} size"));
            let s = if unicode {
                crate::util::bytes::utf16le_lossy(&d.data[spos + 4..spos + 4 + (sz & !1)])
            } else {
                crate::util::bytes::latin1(&d.data[spos + 4..spos + 4 + sz])
            };
            let s = s.trim_end_matches('\0').to_string();
            d.note(spos + 4, sz, label, format!("\"{s}\""));
            if !s.is_empty() {
                let key = match label.chars().nth(7) {
                    Some('1') => "ftp_host",
                    Some('2') => "ftp_user",
                    _ => "ftp_password_present",
                };
                let val = if key == "ftp_password_present" {
                    "true".to_string()
                } else {
                    s
                };
                item.details.push((key.into(), val));
            }
            spos += 4 + ((sz + 3) & !3);
        }
        pos = 6 + data_size;
    }
    let uri = if unicode {
        d.utf16z(pos, "URI")
    } else {
        d.ansiz(pos, "URI", encoding_rs::WINDOWS_1252)
    };
    match uri {
        Some((s, _)) if !s.is_empty() && crate::util::bytes::is_printable(&s) => item.name = s,
        _ => {
            // Fall back to anything that looks like a URL.
            let cands = crate::util::bytes::utf16_strings(d.data, 6)
                .into_iter()
                .chain(crate::util::bytes::ascii_strings(d.data, 6))
                .map(|(_, s)| s)
                .find(|s| s.contains("://") || s.starts_with("ftp") || s.starts_with("http"));
            if let Some(s) = cands {
                item.name = s;
                item.warnings.push("URI located heuristically".into());
            }
        }
    }
    if let Some(start) = extension::locate_first(d.data, pos) {
        extension::parse_chain(item, d, start, 0);
    }
}

pub fn control_panel_item(item: &mut ShellItem, d: &mut Dis) {
    item.category = Category::ControlPanelItem;
    item.type_name = "Control panel item".into();
    d.u8(3, "Unknown (sort order?)");
    if let Some(g) = d.guid(14, "Control panel item identifier") {
        set_guid(item, g);
        if item.guid_name.is_none() {
            item.guid_name = control_panel_item_name(&g).map(str::to_string);
        }
        item.details
            .push(("control_panel_item".into(), describe_guid(&g)));
    }
    if let Some(start) = extension::locate_first(d.data, 30) {
        extension::parse_chain(item, d, start, 0);
    }
}

/// Control panel item CLSIDs that are not also shell folders.
fn control_panel_item_name(g: &crate::util::Guid) -> Option<&'static str> {
    Some(match g.to_string().as_str() {
        "ed834ed6-4b5a-4bfe-8f11-a626dcb6a921" => "Personalization",
        "c555438b-3c23-4769-a71f-b6d3d9b6053a" => "Display",
        "f2ddfc82-8f12-4cdd-b7dc-d4fe1425aa4d" => "Sound",
        "87d66a43-7b11-4a28-9811-c86ee395acf7" => "Indexing Options",
        "40419485-c444-4567-851a-2dd7bfa1684d" => "Phone and Modem",
        "6c8eec18-8d75-41b2-a177-8831d59d2d50" => "Mouse",
        "725be8f7-668e-4c7b-8f90-46bdb0936430" => "Keyboard",
        "62d8ed13-c9d0-4ce8-a914-47dd628fb1b0" => "Region and Language",
        "80f3f1d5-feca-45f3-bc32-752c152e456e" => "Tablet PC Settings",
        "a304259d-52b8-4526-8b1a-a1d6cecc8243" => "iSCSI Initiator",
        "d9ef8727-cac2-4e60-809e-86f80a666c91" => "BitLocker Drive Encryption",
        "1206f5f1-0569-412c-8fec-3204630dfb70" => "Credential Manager",
        "7b81be6a-ce2b-4676-a29e-eb907a5126c5" => "Programs and Features",
        _ => return None,
    })
}
