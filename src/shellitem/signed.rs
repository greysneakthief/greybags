//! Signature-based shell items: delegate items, users property views, MTP
//! (portable device) items, control panel categories and friends.

use super::dissect::Dis;
use super::extension::{self, describe_guid};
use super::items::{self, set_guid};
use super::propstore;
use super::{Category, ParseOptions, ShellItem};
use crate::util::bytes::{self, u16_at, u32_at};
use crate::util::{known, Guid};

const SIG_CP_CATEGORY: u32 = 0x39de_2184;
const SIG_GAME_FOLDER: u32 = 0x4953_4647; // "GFSI"
const SIG_CDBURN: u32 = 0x4d67_7541; // "AugM"
const SIG_MTP_VOLUME: u32 = 0x1031_2005;
const SIG_MTP_FILE: u32 = 0x0719_2006;
const SIG_APPS: u32 = 0x5350_5041; // "APPS"
const SIG_CFSF: u32 = 0x4653_4643; // "CFSF"
const SIG_REMOVABLE_DELEGATE: u32 = 0xf5a6_b710;
const SIG_CABINET: u32 = 0x9e5a_5871;
const SIG_ACRONIS: u32 = 0xacb1_6752;

/// Users property view data signatures (libfwsi).
const PROPVIEW_SIGS: [u32; 6] = [
    0x1014_1981,
    0x23a3_dfd5,
    0x23fe_bbee,
    0x3b93_afbb,
    0x4950_5241,
    0xbeeb_ee00,
];

const CPL_SIGS: [u32; 9] = [
    0x0000_0000,
    0xffff_ee79,
    0xffff_f444,
    0xffff_ff36,
    0xffff_ff37,
    0xffff_ff38,
    0xffff_ff9a,
    0xffff_ff9c,
    0xffff_ffff,
];

pub fn parse(item: &mut ShellItem, d: &mut Dis, opts: &ParseOptions, depth: usize) -> bool {
    let len = d.len();
    let class = item.class_type;
    if let Some(pos) = delegate_position(d.data) {
        delegate(item, d, opts, pos, depth);
        return true;
    }
    let sig2 = u32_at(d.data, 2);
    let sig4 = u32_at(d.data, 4);
    let sig6 = u32_at(d.data, 6);
    let sig8 = u32_at(d.data, 8);
    if sig4 == Some(SIG_CP_CATEGORY) && len >= 12 {
        control_panel_category(item, d);
        return true;
    }
    if sig4 == Some(SIG_GAME_FOLDER) && len >= 24 {
        item.category = Category::GameFolder;
        item.type_name = "Game folder".into();
        d.sig(4, "Signature (GFSI)");
        if let Some(g) = d.guid(8, "Game identifier") {
            item.guid = Some(g);
            item.details.push(("game_id".into(), g.to_string()));
        }
        return true;
    }
    if sig4 == Some(SIG_CDBURN) {
        item.category = Category::CdBurn;
        item.type_name = "CD burning staging item".into();
        d.sig(4, "Signature (AugM)");
        let names: Vec<String> = bytes::utf16_strings(d.data, 2)
            .into_iter()
            .map(|(_, s)| s)
            .collect();
        if let Some(n) = names.first() {
            item.name = n.clone();
        }
        return true;
    }
    if sig2 == Some(SIG_ACRONIS) {
        item.category = Category::AcronisImage;
        item.type_name = "Acronis True Image archive".into();
        d.sig(2, "Signature");
        let strings: Vec<String> = bytes::utf16_strings(d.data, 2)
            .into_iter()
            .map(|(_, s)| s)
            .collect();
        if let Some(full) = strings.iter().find(|s| s.contains('\\')) {
            item.details.push(("full_path".into(), full.clone()));
        }
        if let Some(n) = strings.first() {
            item.name = n.clone();
        }
        return true;
    }
    if sig8 == Some(SIG_CABINET) {
        item.category = Category::Cabinet;
        item.type_name = "Cabinet (.cab) contents".into();
        d.sig(8, "Signature");
        if let Some((n, _)) = d.utf16z(16, "Name") {
            item.name = n;
        }
        return true;
    }
    // The following share the "size(2) + signature(4)" inner data header.
    let header_ok = u16_at(d.data, 4)
        .map(|s| 6 + s as usize <= len + 2)
        .unwrap_or(false);
    if header_ok && matches!(class, 0x00 | 0x01 | 0x1f | 0x2e | 0x74 | 0x2f) {
        match sig6 {
            Some(SIG_MTP_VOLUME) => {
                mtp_volume(item, d);
                return true;
            }
            Some(SIG_MTP_FILE) => {
                mtp_file(item, d);
                return true;
            }
            Some(SIG_APPS) => {
                item.category = Category::Application;
                item.type_name = "Application (APPS)".into();
                d.u16(4, "Data size");
                d.sig(6, "Signature (APPS)");
                let props = propstore::scan(d, 10, &[]);
                item.properties.extend(props);
                if let Some(id) = item
                    .property("System.AppUserModel.ID")
                    .and_then(|p| p.value.as_str())
                {
                    item.name = id.to_string();
                }
                return true;
            }
            Some(SIG_CFSF) => {
                // Users files folder item without the delegate trailer.
                item.type_name = "Users files folder".into();
                d.u16(4, "Inner data size");
                d.sig(6, "Signature (CFSF)");
                items::file_entry(item, d, opts, 10, depth);
                item.type_name = format!("{} (CFSF)", item.type_name);
                return true;
            }
            Some(s) if PROPVIEW_SIGS.contains(&s) => {
                users_property_view(item, d, 4);
                if let Some(start) =
                    extension::locate_first(d.data, 6 + u16_at(d.data, 4).unwrap_or(0) as usize)
                {
                    extension::parse_chain(item, d, start, depth);
                }
                return true;
            }
            _ => {}
        }
    }
    if class == 0x00
        && len >= 26
        && sig4.map(|s| CPL_SIGS.contains(&s)).unwrap_or(false)
        && cpl_file(item, d)
    {
        return true;
    }
    false
}

/// If this item ends with the delegate CLSID + folder CLSID pair, returns
/// the offset of the delegate CLSID.
fn delegate_position(b: &[u8]) -> Option<usize> {
    let inner = u16_at(b, 4)? as usize;
    let pos = 6 + inner;
    let g = Guid::at(b, pos)?;
    (g.to_string() == known::DELEGATE_ITEM_CLSID && pos + 32 <= b.len()).then_some(pos)
}

fn delegate(item: &mut ShellItem, d: &mut Dis, opts: &ParseOptions, pos: usize, depth: usize) {
    item.category = Category::Delegate;
    d.u8(3, "Unknown");
    d.u16(4, "Inner data size");
    d.guid(pos, "Delegate class identifier");
    let folder = d.guid(pos + 16, "Delegate folder identifier");
    let folder_name = folder
        .and_then(|g| known::shell_folder(&g))
        .unwrap_or("delegate folder");
    item.type_name = format!("Delegate: {folder_name}");
    if let Some(g) = folder {
        item.details
            .push(("delegate_folder".into(), describe_guid(&g)));
    }
    let sig = u32_at(d.data, 6);
    let after = pos + 32;
    match sig {
        Some(SIG_CFSF) => {
            d.sig(6, "Signature (CFSF)");
            items::file_entry(item, d, opts, 10, depth);
            item.type_name = format!("{} ({folder_name})", item.type_name);
            // file_entry() already chased extension blocks after the name;
            // make sure we also cover blocks after the delegate trailer.
            if item.ext_version.is_none() {
                if let Some(start) = extension::locate_first(d.data, after) {
                    extension::parse_chain(item, d, start, depth);
                }
            }
            return;
        }
        Some(SIG_REMOVABLE_DELEGATE) => {
            d.sig(6, "Signature (removable drive delegate)");
            let size = u16_at(d.data, 10).unwrap_or(0) as usize;
            if size >= 3 {
                let mut tmp = ShellItem::new(&d.data[10..(10 + size + 2).min(d.len())], 10);
                tmp.class_type = d.data.get(12).copied().unwrap_or(0);
                let mut sub = d.sub(10, size + 2);
                items::volume(&mut tmp, &mut sub, opts);
                d.absorb(sub);
                item.name = tmp.name;
                item.details.extend(tmp.details);
                item.details.push(("removable".into(), "true".into()));
                item.type_name = "Removable drive (delegate)".into();
                item.category = Category::Volume;
            }
        }
        Some(s) if PROPVIEW_SIGS.contains(&s) => {
            users_property_view(item, d, 4);
            item.category = Category::Delegate;
            item.type_name = format!("Delegate: {folder_name} (property view)");
        }
        _ => {
            let fname = folder.map(|g| g.to_string()).unwrap_or_default();
            if fname == "35786d3c-b075-49b9-88dd-029876e11c01" {
                portable_device_delegate(item, d, pos);
            } else if fname == "59031a47-3f72-44a7-89c5-5595fe6b30ee"
                && d.u32(6, "Unknown") == Some(2)
            {
                if let Some((u, _)) = d.utf16z(10, "User name") {
                    item.name = u;
                }
            }
        }
    }
    if item.name.is_empty() {
        item.name = folder_name.to_string();
    }
    if let Some(start) = extension::locate_first(d.data, after) {
        extension::parse_chain(item, d, start, depth);
    }
}

fn control_panel_category(item: &mut ShellItem, d: &mut Dis) {
    item.category = Category::ControlPanelCategory;
    item.type_name = "Control panel category".into();
    d.u8(3, "Unknown");
    d.sig(4, "Signature (0x39de2184)");
    if let Some(id) = d.u32(8, "Category identifier") {
        let name = known::control_panel_category(id)
            .map(str::to_string)
            .unwrap_or_else(|| format!("Category {id}"));
        item.details.push(("category_id".into(), id.to_string()));
        item.name = name;
    }
}

fn cpl_file(item: &mut ShellItem, d: &mut Dis) -> bool {
    let Some((path, n)) = bytes::utf16z_at(d.data, 24) else {
        return false;
    };
    if !path.to_ascii_lowercase().contains(".cpl") {
        return false;
    }
    item.category = Category::ControlPanelCpl;
    item.type_name = "Control panel CPL file".into();
    d.sig(4, "Signature");
    d.u16(20, "Name offset (characters)");
    d.u16(22, "Comments offset (characters)");
    d.note(24, n, "CPL path", format!("\"{path}\""));
    let mut pos = 24 + n;
    if let Some((name, n2)) = d.utf16z(pos, "Name") {
        pos += n2;
        item.name = name;
    }
    if let Some((c, _)) = d.utf16z(pos, "Comments") {
        if !c.is_empty() {
            item.details.push(("comments".into(), c));
        }
    }
    item.details.push(("cpl_path".into(), path.clone()));
    if item.name.is_empty() {
        item.name = path;
    }
    true
}

/// Users property view data at `p`: size(2) sig(4) store-size(2) id-size(2) id store.
fn users_property_view(item: &mut ShellItem, d: &mut Dis, p: usize) {
    item.category = Category::UsersPropertyView;
    let size = d.u16(p, "Property view data size").unwrap_or(0) as usize;
    let sig = d.sig(p + 2, "Property view signature").unwrap_or(0);
    item.type_name = format!("Users property view (0x{sig:08x})");
    item.details
        .push(("property_view_signature".into(), format!("0x{sig:08x}")));
    let ps_size = d.u16(p + 6, "Property store size").unwrap_or(0) as usize;
    let id_size = d.u16(p + 8, "Identifier size").unwrap_or(0) as usize;
    let id_off = p + 10;
    if id_size == 16 {
        if let Some(g) = d.guid(id_off, "Known folder identifier") {
            set_guid(item, g);
            if let Some(n) = known::known_folder(&g).or_else(|| known::shell_folder(&g)) {
                item.guid_name = Some(n.to_string());
                item.type_name = format!("Users property view: known folder {n}");
            }
        }
    } else if id_size > 0 {
        let end = (id_off + id_size).min(d.len());
        d.note(
            id_off,
            end - id_off,
            "Identifier data",
            bytes::to_hex(&d.data[id_off..end]),
        );
    }
    let ps_off = id_off + id_size;
    if ps_size > 0 && ps_off < d.len() {
        let (props, _) = propstore::parse_sets(d, ps_off);
        item.properties.extend(props);
    }
    if size > 0 && p + 2 + size > d.len() {
        item.warnings
            .push("property view data size exceeds item".into());
    }
    if let Some(path) = item
        .property("System.ParsingPath")
        .and_then(|p| p.value.as_str())
    {
        item.details.push(("parsing_path".into(), path.to_string()));
    }
}

fn mtp_volume(item: &mut ShellItem, d: &mut Dis) {
    item.category = Category::MtpDevice;
    item.type_name = "MTP storage device".into();
    d.u16(4, "Data size");
    d.sig(6, "Signature (MTP volume)");
    let n_name = d.u32(38, "Name length (chars)").unwrap_or(0) as usize;
    let n_id = d.u32(42, "Identifier length (chars)").unwrap_or(0) as usize;
    let n_fs = d.u32(46, "File system length (chars)").unwrap_or(0) as usize;
    let n_guids = d.u32(50, "Number of GUID strings").unwrap_or(0) as usize;
    let mut pos = 54;
    let read = |d: &mut Dis, n: usize, label: &str, pos: &mut usize| -> Option<String> {
        if n == 0 || n > 4096 || *pos + n * 2 > d.len() {
            return None;
        }
        let s = d.utf16n(*pos, n, label);
        *pos += n * 2;
        s
    };
    let name = read(d, n_name, "Storage name", &mut pos);
    let ident = read(d, n_id, "Storage identifier", &mut pos);
    let fs = read(d, n_fs, "File system", &mut pos);
    if let Some(n) = &name {
        item.name = n.clone();
    }
    if let Some(i) = ident {
        item.details.push(("storage_id".into(), i.clone()));
        if let Some(serial) = wpd_serial(&i) {
            item.details.push(("device_serial".into(), serial));
        }
    }
    if let Some(f) = fs {
        item.details.push(("file_system".into(), f));
    }
    if n_guids < 64 {
        for i in 0..n_guids {
            if pos + 78 > d.len() {
                break;
            }
            d.utf16n(pos, 39, &format!("WPD handler GUID string {i}"));
            pos += 78;
        }
    }
    mtp_trailer(item, d, pos);
}

fn mtp_file(item: &mut ShellItem, d: &mut Dis) {
    item.category = Category::MtpFolder;
    item.type_name = "MTP file/folder".into();
    d.u16(4, "Data size");
    d.sig(6, "Signature (MTP file entry)");
    item.modified = d.filetime(26, "Modification time (FILETIME)");
    item.created = d.filetime(34, "Creation time (FILETIME)");
    if let Some(g) = d.guid(42, "Content type") {
        item.details.push(("content_type".into(), g.to_string()));
    }
    let s1 = d.u32(62, "String 1 length (chars)").unwrap_or(0) as usize;
    let s2 = d.u32(66, "String 2 length (chars)").unwrap_or(0) as usize;
    let s3 = d.u32(70, "String 3 length (chars)").unwrap_or(0) as usize;
    let mut pos = 74;
    let mut strings = Vec::new();
    for (n, label) in [
        (s1, "Name"),
        (s2, "Display name"),
        (s3, "Object identifier"),
    ] {
        if n == 0 || n > 4096 || pos + n * 2 > d.len() {
            strings.push(None);
            continue;
        }
        strings.push(d.utf16n(pos, n, label));
        pos += n * 2;
    }
    if let Some(Some(n)) = strings.first() {
        item.name = n.clone();
    } else if let Some(Some(n)) = strings.get(1) {
        item.name = n.clone();
    }
    if let Some(Some(id)) = strings.get(2) {
        item.details.push(("object_id".into(), id.clone()));
    }
    mtp_trailer(item, d, pos);
}

/// 0xd marker, PortableDeviceValues CLSID and property array.
fn mtp_trailer(item: &mut ShellItem, d: &mut Dis, from: usize) {
    let Some(mark) = (from..d.len().saturating_sub(24)).find(|&p| u32_at(d.data, p) == Some(0xd))
    else {
        return;
    };
    d.u32(mark, "Unknown (0xd)");
    d.guid(mark + 4, "Class identifier (PortableDeviceValues)");
    let (props, _) = propstore::parse_wpd_array(d, mark + 20);
    for p in &props {
        if p.is("WPD_OBJECT_DATE_CREATED") || p.is("WPD_OBJECT_DATE_MODIFIED") {
            if let propstore::PropValue::Time(t) = p.value {
                if p.is("WPD_OBJECT_DATE_CREATED") {
                    item.created = item.created.or(Some(t));
                } else {
                    item.modified = item.modified.or(Some(t));
                }
            }
        }
    }
    item.properties.extend(props);
}

/// Portable Devices delegate (35786d3c-...): two counted strings at 40.
fn portable_device_delegate(item: &mut ShellItem, d: &mut Dis, end: usize) {
    item.category = Category::MtpDevice;
    item.type_name = "Portable device".into();
    let n1 = d.u32(30, "String 1 length (chars)").unwrap_or(0) as usize;
    let n2 = d.u32(34, "String 2 length (chars)").unwrap_or(0) as usize;
    let mut pos = 40;
    if n1 > 0 && n1 < 2048 && pos + n1 * 2 <= end {
        if let Some(s) = d.utf16n(pos, n1, "Device name") {
            item.name = s;
        }
        pos += n1 * 2;
    }
    if n2 > 0 && n2 < 2048 && pos + n2 * 2 <= end {
        if let Some(s) = d.utf16n(pos, n2, "Device identifier") {
            if let Some(serial) = wpd_serial(&s) {
                item.details.push(("device_serial".into(), serial));
            }
            item.details.push(("device_id".into(), s));
        }
        pos += n2 * 2;
    }
    mtp_trailer(item, d, pos);
}

/// Pulls a USB serial number out of a WPD/PnP device path such as
/// `\\?\usb#vid_04e8&pid_6860#R58M12345#{6ac27878-...}`.
pub fn wpd_serial(id: &str) -> Option<String> {
    let l = id.to_ascii_lowercase();
    if !l.contains("usb#vid_") && !l.contains("usbstor#") && !l.contains("swd#wpdbusenum") {
        return None;
    }
    let parts: Vec<&str> = id.split('#').collect();
    if parts.len() >= 3 {
        let serial = parts[2];
        if !serial.is_empty() && !serial.starts_with('{') {
            return Some(serial.to_string());
        }
    }
    None
}
