//! Bounds-checked little-endian readers and string decoders.
//!
//! Every reader returns `Option` so that malformed or truncated forensic data
//! never panics; callers decide whether a missing field is fatal.

use encoding_rs::Encoding;

#[inline]
pub fn u8_at(b: &[u8], off: usize) -> Option<u8> {
    b.get(off).copied()
}

#[inline]
pub fn u16_at(b: &[u8], off: usize) -> Option<u16> {
    let s = b.get(off..off.checked_add(2)?)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

#[inline]
pub fn i16_at(b: &[u8], off: usize) -> Option<i16> {
    u16_at(b, off).map(|v| v as i16)
}

#[inline]
pub fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off.checked_add(4)?)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

#[inline]
pub fn i32_at(b: &[u8], off: usize) -> Option<i32> {
    u32_at(b, off).map(|v| v as i32)
}

#[inline]
pub fn u64_at(b: &[u8], off: usize) -> Option<u64> {
    let s = b.get(off..off.checked_add(8)?)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(s);
    Some(u64::from_le_bytes(a))
}

#[inline]
pub fn f64_at(b: &[u8], off: usize) -> Option<f64> {
    u64_at(b, off).map(f64::from_bits)
}

/// Reads a 48-bit little-endian integer (used by NTFS file references).
#[inline]
pub fn u48_at(b: &[u8], off: usize) -> Option<u64> {
    let s = b.get(off..off.checked_add(6)?)?;
    let mut a = [0u8; 8];
    a[..6].copy_from_slice(s);
    Some(u64::from_le_bytes(a))
}

#[inline]
pub fn slice(b: &[u8], off: usize, len: usize) -> Option<&[u8]> {
    b.get(off..off.checked_add(len)?)
}

/// Decodes UTF-16LE code units, replacing unpaired surrogates with U+FFFD.
pub fn utf16le_lossy(b: &[u8]) -> String {
    let units: Vec<u16> = b
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

/// Reads a NUL-terminated UTF-16LE string starting at `off`.
///
/// Returns the string and the number of bytes consumed *including* the
/// terminator. If no terminator is found the remainder of the buffer is used
/// and the consumed length equals the remaining length.
pub fn utf16z_at(b: &[u8], off: usize) -> Option<(String, usize)> {
    let rest = b.get(off..)?;
    if rest.len() < 2 {
        return None;
    }
    let mut end = None;
    let mut i = 0;
    while i + 1 < rest.len() {
        if rest[i] == 0 && rest[i + 1] == 0 {
            end = Some(i);
            break;
        }
        i += 2;
    }
    match end {
        Some(e) => Some((utf16le_lossy(&rest[..e]), e + 2)),
        None => {
            let even = rest.len() & !1;
            Some((utf16le_lossy(&rest[..even]), even))
        }
    }
}

/// Reads `nchars` UTF-16 code units at `off`, trimming trailing NULs.
pub fn utf16n_at(b: &[u8], off: usize, nchars: usize) -> Option<String> {
    let s = slice(b, off, nchars.checked_mul(2)?)?;
    Some(utf16le_lossy(s).trim_end_matches('\0').to_string())
}

/// Reads a NUL-terminated single-byte string decoded with `enc`.
/// Returns the string and bytes consumed including the terminator.
pub fn ansiz_at(b: &[u8], off: usize, enc: &'static Encoding) -> Option<(String, usize)> {
    let rest = b.get(off..)?;
    if rest.is_empty() {
        return None;
    }
    let (end, consumed) = match rest.iter().position(|&c| c == 0) {
        Some(p) => (p, p + 1),
        None => (rest.len(), rest.len()),
    };
    let (s, _, _) = enc.decode(&rest[..end]);
    Some((s.into_owned(), consumed))
}

/// Decodes a fixed-size single-byte buffer, stopping at the first NUL.
pub fn ansi_fixed(b: &[u8], enc: &'static Encoding) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    let (s, _, _) = enc.decode(&b[..end]);
    s.into_owned()
}

/// Latin-1 decode used for "compressed" registry key/value names.
pub fn latin1(b: &[u8]) -> String {
    b.iter().map(|&c| c as char).collect()
}

/// True if every char is printable (no control characters other than tab).
pub fn is_printable(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| !c.is_control() || c == '\t') && !s.contains('\u{FFFD}')
}

/// Extracts runs of printable UTF-16LE characters of at least `min_chars`.
/// Scans both even and odd alignments. Returns (offset, string).
pub fn utf16_strings(b: &[u8], min_chars: usize) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for align in 0..2 {
        let mut i = align;
        let mut start = None;
        let mut cur = String::new();
        while i + 1 < b.len() {
            let u = u16::from_le_bytes([b[i], b[i + 1]]);
            let ch = char::from_u32(u as u32).filter(|c| {
                !c.is_control() && !(0xD800..=0xDFFF).contains(&u) && u != 0xFFFF && u != 0xFFFE
            });
            // Restrict to "text like" code points to reduce noise. The odd
            // alignment pass only accepts ASCII, otherwise every ASCII string
            // also shows up as CJK garbage one byte over.
            let ch = ch.filter(|c| {
                let v = *c as u32;
                if align == 1 {
                    (0x20..0x7f).contains(&v)
                } else {
                    (0x20..0x7f).contains(&v)
                        || (0xa0..0x2000).contains(&v)
                        || (v >= 0x3000 && c.is_alphabetic())
                }
            });
            match ch {
                Some(c) => {
                    if start.is_none() {
                        start = Some(i);
                    }
                    cur.push(c);
                }
                None => {
                    if let Some(s) = start.take() {
                        if cur.chars().count() >= min_chars {
                            out.push((s, std::mem::take(&mut cur)));
                        }
                    }
                    cur.clear();
                }
            }
            i += 2;
        }
        if let Some(s) = start {
            if cur.chars().count() >= min_chars {
                out.push((s, cur));
            }
        }
    }
    out.sort_by_key(|(o, _)| *o);
    out
}

/// Extracts runs of printable ASCII of at least `min_len` bytes.
pub fn ascii_strings(b: &[u8], min_len: usize) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut start = None;
    for (i, &c) in b.iter().enumerate() {
        if (0x20..0x7f).contains(&c) {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start.take() {
            if i - s >= min_len {
                out.push((s, String::from_utf8_lossy(&b[s..i]).into_owned()));
            }
        }
    }
    if let Some(s) = start {
        if b.len() - s >= min_len {
            out.push((s, String::from_utf8_lossy(&b[s..]).into_owned()));
        }
    }
    out
}

/// Classic 16-bytes-per-line hex dump with an ASCII gutter.
pub fn hexdump(b: &[u8], base: usize) -> String {
    let mut out = String::new();
    for (row, chunk) in b.chunks(16).enumerate() {
        let off = base + row * 16;
        out.push_str(&format!("{off:08x}  "));
        for i in 0..16 {
            if i < chunk.len() {
                out.push_str(&format!("{:02x} ", chunk[i]));
            } else {
                out.push_str("   ");
            }
            if i == 7 {
                out.push(' ');
            }
        }
        out.push_str(" |");
        for &c in chunk {
            out.push(if (0x20..0x7f).contains(&c) {
                c as char
            } else {
                '.'
            });
        }
        out.push_str("|\n");
    }
    out
}

pub fn to_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for c in b {
        s.push_str(&format!("{c:02x}"));
    }
    s
}

/// Parses hex text, ignoring whitespace, `0x` prefixes, commas, colons and
/// dashes (so `regedit` exports and `xxd` output can be pasted directly).
pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    let cleaned: String = s
        .replace("0x", "")
        .replace("0X", "")
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();
    if cleaned.is_empty() || cleaned.len() & 1 != 0 {
        return None;
    }
    (0..cleaned.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).ok())
        .collect()
}

/// Finds the first occurrence of `needle` in `hay` at or after `from`.
pub fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() || from > hay.len() - needle.len() {
        return None;
    }
    (from..=hay.len() - needle.len()).find(|&i| &hay[i..i + needle.len()] == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readers_are_bounds_checked() {
        let b = [1u8, 2, 3];
        assert_eq!(u16_at(&b, 0), Some(0x0201));
        assert_eq!(u16_at(&b, 2), None);
        assert_eq!(u32_at(&b, 0), None);
        assert_eq!(u64_at(&b, usize::MAX), None);
    }

    #[test]
    fn utf16z() {
        let b = [b'h', 0, b'i', 0, 0, 0, b'x', 0];
        assert_eq!(utf16z_at(&b, 0), Some(("hi".to_string(), 6)));
    }

    #[test]
    fn hex_roundtrip() {
        assert_eq!(from_hex("0x14,00 1F-50"), Some(vec![0x14, 0, 0x1f, 0x50]));
        assert_eq!(to_hex(&[0xde, 0xad]), "dead");
        assert_eq!(from_hex("abc"), None);
    }

    #[test]
    fn string_extraction() {
        let mut b = vec![0xffu8, 0xff];
        for c in "Hello".encode_utf16() {
            b.extend_from_slice(&c.to_le_bytes());
        }
        b.extend_from_slice(&[0, 0]);
        let s = utf16_strings(&b, 3);
        assert_eq!(s, vec![(2, "Hello".to_string())]);
    }
}
