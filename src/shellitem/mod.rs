//! Windows shell item (SHITEMID / ITEMIDLIST) dissector.
//!
//! Detection follows the libfwsi taxonomy: signature-based items are tried
//! first (their class byte is unreliable), then class-type-based items, then
//! ancestor-based items (ZIP contents). Anything left over is parsed
//! heuristically (property stores, UTF-16 strings) so no item is ever
//! silently dropped.

pub mod build;
mod compressed;
pub mod dissect;
pub mod extension;
mod items;
pub mod propstore;
mod signed;

use crate::util::bytes::{self, u16_at};
use crate::util::{Guid, Timestamp};
use dissect::{Dis, Field};
use encoding_rs::Encoding;
use extension::ExtensionBlock;
use propstore::Property;
use serde::{Serialize, Serializer};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    RootFolder,
    Volume,
    Directory,
    File,
    FileEntry,
    NetworkLocation,
    Uri,
    ControlPanel,
    ControlPanelCategory,
    ControlPanelItem,
    ControlPanelCpl,
    Delegate,
    UsersPropertyView,
    MtpDevice,
    MtpFolder,
    CompressedFolder,
    GameFolder,
    Cabinet,
    Application,
    CdBurn,
    AcronisImage,
    Unknown,
}

impl Category {
    pub fn label(&self) -> &'static str {
        match self {
            Category::RootFolder => "Root folder",
            Category::Volume => "Volume",
            Category::Directory => "Directory",
            Category::File => "File",
            Category::FileEntry => "File entry",
            Category::NetworkLocation => "Network location",
            Category::Uri => "URI",
            Category::ControlPanel => "Control panel",
            Category::ControlPanelCategory => "Control panel category",
            Category::ControlPanelItem => "Control panel item",
            Category::ControlPanelCpl => "Control panel CPL file",
            Category::Delegate => "Delegate item",
            Category::UsersPropertyView => "Users property view",
            Category::MtpDevice => "MTP device/storage",
            Category::MtpFolder => "MTP folder",
            Category::CompressedFolder => "Compressed folder (ZIP) contents",
            Category::GameFolder => "Game folder",
            Category::Cabinet => "Cabinet file contents",
            Category::Application => "Application",
            Category::CdBurn => "CD burning",
            Category::AcronisImage => "Acronis True Image",
            Category::Unknown => "Unknown",
        }
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ShellItem {
    /// Offset of the item within the containing item list / value data.
    pub offset: usize,
    pub size: u16,
    #[serde(serialize_with = "hex8")]
    pub class_type: u8,
    pub category: Category,
    /// Specific type description, e.g. "Directory", "Drive letter", "Network share".
    pub type_name: String,
    /// Display name used as the path segment.
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub short_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub long_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub localized_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guid: Option<Guid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guid_name: Option<String>,
    /// Target timestamps captured in the item (FAT 2 s precision for file
    /// entries, FILETIME for MTP items).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<Timestamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified: Option<Timestamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accessed: Option<Timestamp>,
    /// FILETIMEs from extension block 0xbeef0026.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ext_created: Option<Timestamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ext_modified: Option<Timestamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ext_accessed: Option<Timestamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mft_entry: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mft_sequence: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ext_version: Option<u16>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub extension_blocks: Vec<ExtensionBlock>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub properties: Vec<Property>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub details: Vec<(String, String)>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<Field>,
    #[serde(serialize_with = "hex_bytes")]
    pub raw: Vec<u8>,
}

fn hex8<S: Serializer>(v: &u8, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&format!("0x{v:02x}"))
}

fn hex_bytes<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&bytes::to_hex(v))
}

impl ShellItem {
    fn new(raw: &[u8], offset: usize) -> ShellItem {
        ShellItem {
            offset,
            size: u16_at(raw, 0).unwrap_or(raw.len() as u16),
            class_type: raw.get(2).copied().unwrap_or(0),
            category: Category::Unknown,
            type_name: String::new(),
            name: String::new(),
            short_name: None,
            long_name: None,
            localized_name: None,
            guid: None,
            guid_name: None,
            created: None,
            modified: None,
            accessed: None,
            ext_created: None,
            ext_modified: None,
            ext_accessed: None,
            mft_entry: None,
            mft_sequence: None,
            file_size: None,
            attributes: None,
            ext_version: None,
            extension_blocks: Vec::new(),
            properties: Vec::new(),
            details: Vec::new(),
            warnings: Vec::new(),
            fields: Vec::new(),
            raw: raw.to_vec(),
        }
    }

    /// Stand-in for an item whose data is unavailable (orphaned or
    /// recovered keys whose shell item value is gone).
    pub fn placeholder(name: &str, type_name: &str) -> ShellItem {
        let mut it = ShellItem::new(&[], 0);
        it.name = name.to_string();
        it.type_name = type_name.to_string();
        it
    }

    pub fn detail(&self, key: &str) -> Option<&str> {
        self.details
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    pub fn property(&self, key: &str) -> Option<&Property> {
        self.properties.iter().find(|p| p.is(key))
    }

    pub fn is_directory(&self) -> bool {
        self.category == Category::Directory
    }

    /// Drive letter for volume items ("C").
    pub fn drive_letter(&self) -> Option<char> {
        if self.category != Category::Volume {
            return None;
        }
        let mut chars = self.name.chars();
        match (chars.next(), chars.next()) {
            (Some(c), Some(':')) if c.is_ascii_alphabetic() => Some(c.to_ascii_uppercase()),
            _ => None,
        }
    }

    pub fn is_removable(&self) -> bool {
        self.detail("removable") == Some("true")
    }

    /// Path segment used when building absolute paths.
    pub fn segment(&self) -> String {
        let s = self.name.trim_end_matches('\\');
        if s.is_empty() {
            format!("<unnamed 0x{:02x}>", self.class_type)
        } else {
            s.to_string()
        }
    }

    /// Short single-line description of the most relevant data.
    pub fn summary(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if let Some(g) = &self.guid {
            parts.push(format!("GUID {g}"));
        }
        if let (Some(e), Some(s)) = (self.mft_entry, self.mft_sequence) {
            parts.push(format!("MFT {e}-{s}"));
        }
        for (k, v) in &self.details {
            if parts.len() >= 6 {
                break;
            }
            parts.push(format!("{k}={v}"));
        }
        parts.join("; ")
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ParseOptions {
    /// ANSI code page for non-Unicode names (default Windows-1252).
    pub codepage: &'static Encoding,
    /// Record field-level dissection annotations.
    pub dissect: bool,
}

impl Default for ParseOptions {
    fn default() -> Self {
        ParseOptions {
            codepage: encoding_rs::WINDOWS_1252,
            dissect: false,
        }
    }
}

/// Hint about the previous item in the chain (for ancestor-based items).
#[derive(Debug, Clone, Default)]
pub struct ParentHint {
    pub category: Option<Category>,
    pub name: String,
}

impl ParentHint {
    pub fn from_item(i: &ShellItem) -> ParentHint {
        ParentHint {
            category: Some(i.category),
            name: i.segment(),
        }
    }

    fn is_archive_container(&self) -> bool {
        let n = self.name.to_ascii_lowercase();
        self.category == Some(Category::CompressedFolder)
            || (matches!(
                self.category,
                Some(Category::File | Category::FileEntry | Category::Directory)
            ) && (n.ends_with(".zip") || n.ends_with(".zipx") || n.ends_with(".jar")))
    }
}

/// Parses a single shell item (including its 2-byte size prefix).
pub fn parse_item(raw: &[u8], opts: &ParseOptions, parent: Option<&ParentHint>) -> ShellItem {
    parse_item_at(raw, 0, opts, parent, 0)
}

fn parse_item_at(
    raw: &[u8],
    offset: usize,
    opts: &ParseOptions,
    parent: Option<&ParentHint>,
    depth: usize,
) -> ShellItem {
    let mut item = ShellItem::new(raw, offset);
    let mut d = Dis::new(raw, opts.dissect);
    d.u16(0, "Shell item size");
    if raw.len() < 3 {
        item.warnings.push("item too small".into());
        item.type_name = "Truncated".into();
        item.name = "<truncated>".into();
        item.fields = d.fields;
        return item;
    }
    d.u8(2, "Class type indicator");
    let handled = signed::parse(&mut item, &mut d, opts, depth)
        || (parent.map(|p| p.is_archive_container()).unwrap_or(false)
            && compressed::parse(&mut item, &mut d))
        || items::parse(&mut item, &mut d, opts, depth);
    if !handled {
        if compressed::parse(&mut item, &mut d) {
            item.warnings
                .push("identified as ZIP contents by structure (no archive parent)".into());
        } else {
            parse_unknown(&mut item, &mut d);
        }
    }
    finalize(&mut item, &mut d);
    item.fields = d.fields;
    item.fields
        .sort_by_key(|f| (f.offset, std::cmp::Reverse(f.size)));
    item
}

/// Generic post-processing: property stores and name fallbacks.
fn finalize(item: &mut ShellItem, d: &mut Dis) {
    if item.properties.is_empty() {
        let props = propstore::scan(d, 3, &[]);
        item.properties.extend(props);
    }
    if item.name.is_empty() {
        let prefer = [
            "System.ItemNameDisplay",
            "WPD_OBJECT_NAME",
            "WPD_OBJECT_ORIGINAL_FILE_NAME",
            "System.ParsingName",
        ];
        for key in prefer {
            if let Some(v) = item
                .property(key)
                .and_then(|p| p.value.as_str())
                .filter(|s| !s.is_empty())
            {
                item.name = v.to_string();
                break;
            }
        }
    }
    if item.name.is_empty() {
        if let Some(p) = item
            .property("System.ParsingPath")
            .and_then(|p| p.value.as_str())
        {
            item.name = p.rsplit('\\').next().unwrap_or(p).to_string();
        }
    }
    if item.name.is_empty() {
        if let Some(n) = &item.guid_name {
            item.name = n.clone();
        } else if let Some(g) = &item.guid {
            item.name = format!("{{{g}}}");
        }
    }
    if item.name.is_empty() {
        let s = bytes::utf16_strings(&item.raw, 3);
        if let Some((_, s)) = s.into_iter().find(|(_, s)| bytes::is_printable(s)) {
            item.name = s;
            item.warnings
                .push("name recovered heuristically from UTF-16 string".into());
        }
    }
    if item.name.is_empty() {
        item.name = format!("<unknown 0x{:02x}>", item.class_type);
    }
    if item.type_name.is_empty() {
        item.type_name = item.category.label().to_string();
    }
}

fn parse_unknown(item: &mut ShellItem, d: &mut Dis) {
    item.category = Category::Unknown;
    item.type_name = format!("Unknown (class 0x{:02x})", item.class_type);
    if let Some(start) = extension::locate_first(d.data, 4) {
        extension::parse_chain(item, d, start, 0);
    }
    let strings: Vec<String> = bytes::utf16_strings(d.data, 4)
        .into_iter()
        .filter(|(_, s)| bytes::is_printable(s))
        .map(|(_, s)| s)
        .take(4)
        .collect();
    if !strings.is_empty() {
        item.details.push(("strings".into(), strings.join(" | ")));
    }
}

/// Parses an ITEMIDLIST (sequence of items terminated by a zero size).
pub fn parse_list(data: &[u8], opts: &ParseOptions) -> Vec<ShellItem> {
    parse_list_opts(data, opts, 0, None)
}

/// Like [`parse_list`] but with a hint about the item preceding the list
/// (BagMRU values hold one item each; the ancestor lives in the parent key).
pub fn parse_list_with_parent(
    data: &[u8],
    opts: &ParseOptions,
    parent: Option<&ParentHint>,
) -> Vec<ShellItem> {
    parse_list_opts(data, opts, 0, parent)
}

pub(crate) fn parse_list_inner(data: &[u8], depth: usize) -> Vec<ShellItem> {
    parse_list_opts(data, &ParseOptions::default(), depth, None)
}

fn parse_list_opts(
    data: &[u8],
    opts: &ParseOptions,
    depth: usize,
    first_parent: Option<&ParentHint>,
) -> Vec<ShellItem> {
    let mut out: Vec<ShellItem> = Vec::new();
    let mut pos = 0;
    while pos + 2 <= data.len() && out.len() < 128 {
        let size = u16_at(data, pos).unwrap_or(0) as usize;
        if size == 0 {
            break;
        }
        if size < 3 || pos + size > data.len() {
            // Truncated trailing item: parse what we have.
            let mut it = parse_item_at(
                &data[pos..],
                pos,
                opts,
                out.last().map(ParentHint::from_item).as_ref(),
                depth,
            );
            it.warnings.push(format!(
                "item size {size} exceeds available data ({})",
                data.len() - pos
            ));
            out.push(it);
            break;
        }
        let hint = out
            .last()
            .map(ParentHint::from_item)
            .or_else(|| first_parent.cloned());
        out.push(parse_item_at(
            &data[pos..pos + size],
            pos,
            opts,
            hint.as_ref(),
            depth,
        ));
        pos += size;
    }
    out
}

/// File attribute flag names.
pub fn attribute_names(a: u32) -> Vec<&'static str> {
    const FLAGS: [(u32, &str); 15] = [
        (0x1, "READONLY"),
        (0x2, "HIDDEN"),
        (0x4, "SYSTEM"),
        (0x8, "VOLUME_LABEL"),
        (0x10, "DIRECTORY"),
        (0x20, "ARCHIVE"),
        (0x40, "DEVICE"),
        (0x80, "NORMAL"),
        (0x100, "TEMPORARY"),
        (0x200, "SPARSE"),
        (0x400, "REPARSE_POINT"),
        (0x800, "COMPRESSED"),
        (0x1000, "OFFLINE"),
        (0x2000, "NOT_CONTENT_INDEXED"),
        (0x4000, "ENCRYPTED"),
    ];
    FLAGS
        .iter()
        .filter(|(m, _)| a & m != 0)
        .map(|(_, n)| *n)
        .collect()
}
