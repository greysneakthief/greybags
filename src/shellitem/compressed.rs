//! Compressed (ZIP) folder content items. These are "ancestor based": their
//! class byte is not distinctive, so they are recognised either because the
//! parent item is a .zip file or by the embedded date/time string.

use super::dissect::Dis;
use super::{Category, ShellItem};
use crate::util::bytes::{u32_at, utf16n_at, utf16z_at};

/// "mm/dd/yy  HH:MM" (XP) or "mm/dd/yyyy  HH:MM:SS" (Win10) or "N/A".
fn looks_like_zip_date(s: &str) -> bool {
    if s == "N/A" {
        return true;
    }
    let b = s.as_bytes();
    b.len() >= 14
        && b[2] == b'/'
        && b[5] == b'/'
        && s.contains(':')
        && b[0].is_ascii_digit()
        && b[1].is_ascii_digit()
}

pub fn parse(item: &mut ShellItem, d: &mut Dis) -> bool {
    // Windows 10 layout: date string at 36, name sizes at 84/88, name at 92.
    // Windows XP layout: date string at 24, name sizes at 60/64, name at 68.
    for (date_off, size_off, name_off, layout) in [
        (36usize, 84usize, 92usize, "Windows 10"),
        (24, 60, 68, "Windows XP"),
    ] {
        let Some((date, _)) = utf16z_at(d.data, date_off) else {
            continue;
        };
        if !looks_like_zip_date(&date) {
            continue;
        }
        let Some(n1) = u32_at(d.data, size_off) else {
            continue;
        };
        let n1 = n1 as usize;
        if n1 == 0 || n1 > 2048 || name_off + n1 * 2 > d.len() {
            continue;
        }
        let Some(name) = utf16n_at(d.data, name_off, n1) else {
            continue;
        };
        if name.is_empty() || !crate::util::bytes::is_printable(&name) {
            continue;
        }
        item.category = Category::CompressedFolder;
        item.type_name = "ZIP archive contents".into();
        if layout == "Windows 10" {
            if let Some(v) = d.u64(8, "Uncompressed size") {
                item.file_size = Some(v);
            }
            d.u64(16, "Compressed size");
            d.u16(24, "Compression method");
            d.u32(28, "CRC-32");
        }
        d.note(
            date_off,
            (date.len() + 1) * 2,
            "Last modification time (string)",
            format!("\"{date}\""),
        );
        d.u32(size_off, "Name length (chars)");
        let n2 = d
            .u32(size_off + 4, "Secondary name length (chars)")
            .unwrap_or(0) as usize;
        d.note(name_off, n1 * 2, "Name", format!("\"{name}\""));
        let sec_off = name_off + (n1 + 1) * 2;
        if n2 > 0 && n2 < 2048 {
            if let Some(s) = d.utf16n(sec_off, n2, "Secondary name") {
                if !s.is_empty() && s != name {
                    item.details.push(("secondary_name".into(), s));
                }
            }
        }
        item.details.push(("zip_modified".into(), date));
        item.details.push(("layout".into(), layout.into()));
        item.name = name;
        return true;
    }
    false
}
