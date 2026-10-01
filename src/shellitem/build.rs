//! Builders that synthesise shell items in the on-disk layouts Windows
//! writes. Used by tests, `greybags demo-hive` and training material.

use crate::util::Guid;

/// Encodes a FAT date/time as stored in shell items (date low, time high).
pub fn fat(y: u16, mo: u16, d: u16, h: u16, mi: u16, s: u16) -> u32 {
    let date = ((y - 1980) << 9) | (mo << 5) | d;
    let time = (h << 11) | (mi << 5) | (s / 2);
    date as u32 | ((time as u32) << 16)
}

/// Encodes a UTC date/time as FILETIME ticks.
pub fn filetime(y: i64, mo: u32, d: u32, h: u32, mi: u32, s: u32) -> u64 {
    let days = crate::util::time::days_from_civil(y, mo, d);
    let unix = days * 86_400 + (h * 3600 + mi * 60 + s) as i64;
    ((unix + 11_644_473_600) as u64) * 10_000_000
}

fn finish(mut body: Vec<u8>) -> Vec<u8> {
    let size = (body.len() + 2) as u16;
    let mut out = size.to_le_bytes().to_vec();
    out.append(&mut body);
    out
}

fn utf16z(s: &str) -> Vec<u8> {
    let mut v: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    v.extend_from_slice(&[0, 0]);
    v
}

/// Root folder item (class 0x1f) for a shell folder GUID.
pub fn root(guid: &str, sort_index: u8) -> Vec<u8> {
    let mut b = vec![0x1f, sort_index];
    b.extend_from_slice(&Guid::must(guid).0);
    finish(b)
}

pub fn my_computer() -> Vec<u8> {
    root("20d04fe0-3aea-1069-a2d8-08002b30309d", 0x50)
}

/// Volume item with a drive letter ("C:\"), class 0x2f.
pub fn volume(drive: &str) -> Vec<u8> {
    volume_class(0x2f, drive)
}

pub fn volume_class(class: u8, drive: &str) -> Vec<u8> {
    let mut b = vec![class];
    let mut name = drive.as_bytes().to_vec();
    name.resize(20, 0);
    b.extend_from_slice(&name);
    b.extend_from_slice(&[0, 0]);
    finish(b)
}

/// Options for a file entry item with a version 9 0xbeef0004 block.
#[derive(Debug, Clone)]
pub struct FileEntry<'a> {
    pub long_name: &'a str,
    pub short_name: &'a str,
    pub is_dir: bool,
    pub file_size: u32,
    pub modified: u32,
    pub created: u32,
    pub accessed: u32,
    pub mft_entry: u64,
    pub mft_seq: u16,
    pub attributes: u16,
}

impl<'a> FileEntry<'a> {
    pub fn dir(name: &'a str) -> FileEntry<'a> {
        FileEntry {
            long_name: name,
            short_name: name,
            is_dir: true,
            file_size: 0,
            modified: fat(2024, 1, 2, 3, 4, 6),
            created: fat(2024, 1, 2, 3, 4, 6),
            accessed: fat(2024, 1, 2, 3, 4, 6),
            mft_entry: 0,
            mft_seq: 0,
            attributes: 0x10,
        }
    }
}

pub fn file_entry(f: &FileEntry) -> Vec<u8> {
    let mut b = vec![if f.is_dir { 0x31 } else { 0x32 }, 0];
    b.extend_from_slice(&f.file_size.to_le_bytes());
    b.extend_from_slice(&f.modified.to_le_bytes());
    b.extend_from_slice(&f.attributes.to_le_bytes());
    b.extend_from_slice(f.short_name.as_bytes());
    b.push(0);
    if (b.len() + 2) % 2 == 1 {
        b.push(0);
    }
    let ext_off = (b.len() + 2) as u16;
    let mut ext = Vec::new();
    ext.extend_from_slice(&0u16.to_le_bytes()); // size placeholder
    ext.extend_from_slice(&9u16.to_le_bytes());
    ext.extend_from_slice(&0xbeef_0004u32.to_le_bytes());
    ext.extend_from_slice(&f.created.to_le_bytes());
    ext.extend_from_slice(&f.accessed.to_le_bytes());
    ext.extend_from_slice(&46u16.to_le_bytes());
    ext.extend_from_slice(&0u16.to_le_bytes());
    ext.extend_from_slice(&f.mft_entry.to_le_bytes()[..6]);
    ext.extend_from_slice(&f.mft_seq.to_le_bytes());
    ext.extend_from_slice(&0u64.to_le_bytes());
    ext.extend_from_slice(&0u16.to_le_bytes()); // localized name offset
    ext.extend_from_slice(&0u32.to_le_bytes());
    ext.extend_from_slice(&0u32.to_le_bytes());
    ext.extend_from_slice(&utf16z(f.long_name));
    ext.extend_from_slice(&ext_off.to_le_bytes());
    let len = ext.len() as u16;
    ext[0..2].copy_from_slice(&len.to_le_bytes());
    b.extend_from_slice(&ext);
    finish(b)
}

pub fn dir(name: &str, created: u32, modified: u32, mft_entry: u64, mft_seq: u16) -> Vec<u8> {
    let short = if name.len() > 12 { "LONGNA~1" } else { name };
    file_entry(&FileEntry {
        long_name: name,
        short_name: short,
        is_dir: true,
        file_size: 0,
        modified,
        created,
        accessed: modified,
        mft_entry,
        mft_seq,
        attributes: 0x10,
    })
}

/// Network location item (0x41 domain, 0x42 server, 0xc3 share...).
pub fn network(class: u8, location: &str, description: Option<&str>) -> Vec<u8> {
    let flags: u8 = if description.is_some() { 0x80 } else { 0 };
    let mut b = vec![class, 0x01, flags];
    b.extend_from_slice(location.as_bytes());
    b.push(0);
    if let Some(dsc) = description {
        b.extend_from_slice(dsc.as_bytes());
        b.push(0);
    }
    b.extend_from_slice(&[0, 0]);
    finish(b)
}

/// ZIP contents item in the Windows 10 layout.
pub fn zip_item(name: &str, date: &str) -> Vec<u8> {
    let mut b = vec![0u8; 92 - 2];
    let d = utf16z(date);
    let n = d.len().min(42);
    b[36 - 2..36 - 2 + n].copy_from_slice(&d[..n]);
    let chars = name.encode_utf16().count() as u32;
    b[84 - 2..88 - 2].copy_from_slice(&chars.to_le_bytes());
    b[88 - 2..92 - 2].copy_from_slice(&0u32.to_le_bytes());
    b[0] = 0x52; // conventional class byte for ZIP contents items
    b.extend_from_slice(&utf16z(name));
    b.extend_from_slice(&utf16z(""));
    b.extend_from_slice(&[0, 0, 0, 0]);
    finish(b)
}

/// URI item (0x61) with an ASCII URI.
pub fn uri(u: &str) -> Vec<u8> {
    let mut b = vec![0x61, 0x00, 0x00, 0x00];
    b.extend_from_slice(u.as_bytes());
    b.push(0);
    b.extend_from_slice(&[0, 0]);
    finish(b)
}

pub fn control_panel_category(id: u32) -> Vec<u8> {
    let mut b = vec![0x01, 0x00];
    b.extend_from_slice(&0x39de_2184u32.to_le_bytes());
    b.extend_from_slice(&id.to_le_bytes());
    finish(b)
}

pub fn control_panel_item(guid: &str) -> Vec<u8> {
    let mut b = vec![0x71, 0x80];
    b.extend_from_slice(&[0u8; 10]);
    b.extend_from_slice(&Guid::must(guid).0);
    finish(b)
}

/// MTP storage volume item (signature 0x10312005).
pub fn mtp_volume(name: &str, ident: &str, fs: &str) -> Vec<u8> {
    let mut b = vec![0u8; 54 - 2];
    b[0] = 0x00; // class
    b[6 - 2..10 - 2].copy_from_slice(&0x1031_2005u32.to_le_bytes());
    let n = |s: &str| (s.encode_utf16().count() + 1) as u32;
    b[38 - 2..42 - 2].copy_from_slice(&n(name).to_le_bytes());
    b[42 - 2..46 - 2].copy_from_slice(&n(ident).to_le_bytes());
    b[46 - 2..50 - 2].copy_from_slice(&n(fs).to_le_bytes());
    b.extend_from_slice(&utf16z(name));
    b.extend_from_slice(&utf16z(ident));
    b.extend_from_slice(&utf16z(fs));
    b.extend_from_slice(&[0, 0]);
    let data_size = (b.len() + 2 - 6) as u16;
    b[2..4].copy_from_slice(&data_size.to_le_bytes());
    finish(b)
}

/// Users files folder delegate (0x74 + CFSF + delegate trailer).
pub fn users_files_delegate(name: &str, modified: u32, mft_entry: u64, mft_seq: u16) -> Vec<u8> {
    // Build an ordinary directory entry and splice it into the delegate layout.
    let inner = dir(name, modified, modified, mft_entry, mft_seq);
    let ext_pos = crate::util::bytes::find(&inner, &0xbeef_0004u32.to_le_bytes(), 0).unwrap() - 4;
    let head = &inner[..ext_pos]; // size + class + ... + name
    let mut ext = inner[ext_pos..].to_vec();
    let mut body = vec![0x74, 0x00];
    let mut inner_data = Vec::new();
    inner_data.extend_from_slice(b"CFSF");
    inner_data.extend_from_slice(&((head.len() - 2) as u16).to_le_bytes());
    inner_data.extend_from_slice(&head[2..]);
    inner_data.extend_from_slice(&[0, 0]);
    body.extend_from_slice(&(inner_data.len() as u16).to_le_bytes());
    body.extend_from_slice(&inner_data);
    body.extend_from_slice(&Guid::must(crate::util::known::DELEGATE_ITEM_CLSID).0);
    body.extend_from_slice(&Guid::must("dffacdc5-679f-4156-8947-c5c76bc0b67f").0);
    let ext_off = (body.len() + 2) as u16;
    let n = ext.len();
    ext[n - 2..].copy_from_slice(&ext_off.to_le_bytes());
    body.extend_from_slice(&ext);
    finish(body)
}

/// Concatenates items into an ITEMIDLIST with terminator.
pub fn list(items: &[Vec<u8>]) -> Vec<u8> {
    let mut v: Vec<u8> = items.concat();
    v.extend_from_slice(&[0, 0]);
    v
}

/// MRUListEx value data from MRU order.
pub fn mru_list_ex(order: &[u32]) -> Vec<u8> {
    let mut v: Vec<u8> = order.iter().flat_map(|i| i.to_le_bytes()).collect();
    v.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    v
}
