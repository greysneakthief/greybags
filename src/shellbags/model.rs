//! Data model for parsed ShellBags.

use crate::regf::log::RecoveryReport;
use crate::shellitem::ShellItem;
use crate::util::Timestamp;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HiveKind {
    NtUser,
    UsrClass,
    Unknown,
}

impl HiveKind {
    pub fn label(&self) -> &'static str {
        match self {
            HiveKind::NtUser => "NTUSER.DAT",
            HiveKind::UsrClass => "UsrClass.dat",
            HiveKind::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryStatus {
    /// Normal, allocated BagMRU entry.
    Active,
    /// A numbered BagMRU subkey without a matching shell item value.
    Orphaned,
    /// Carved from unallocated hive space (deleted).
    Recovered,
}

impl EntryStatus {
    pub fn label(&self) -> &'static str {
        match self {
            EntryStatus::Active => "active",
            EntryStatus::Orphaned => "orphaned",
            EntryStatus::Recovered => "recovered",
        }
    }
}

/// View settings stored under `Bags\<NodeSlot>`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct BagInfo {
    pub slot: u32,
    pub key_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_written: Option<Timestamp>,
    /// Subkeys such as `Shell`, `ComDlg`, `ComDlgLegacy`, `Desktop`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub views: Vec<String>,
    /// Folder type GUIDs (Vista+) or `FolderType` strings (XP).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub folder_types: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub view_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon_size: Option<u32>,
    /// Latest LastWrite among the bag's view subkeys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub view_last_written: Option<Timestamp>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ShellBagEntry {
    pub id: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<usize>,
    pub status: EntryStatus,
    /// Hive file the entry came from.
    pub source: String,
    pub hive_kind: HiveKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// BagMRU root key path inside the hive.
    pub location: String,
    /// Key path of this item relative to the location, e.g. `BagMRU\1\0\3`.
    pub bag_path: String,
    pub value_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mru_position: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_slot: Option<u32>,
    pub depth: usize,
    /// Shell namespace path, e.g. `My Computer\C:\Users\bob\Documents`.
    pub absolute_path: String,
    /// File-system style path when the chain is anchored to a drive, UNC or
    /// user profile folder (`C:\Users\bob`, `\\srv\share\x`, `%USERPROFILE%\Downloads`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fs_path: Option<String>,
    pub child_count: usize,
    /// LastWrite of this item's own BagMRU subkey.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_last_written: Option<Timestamp>,
    /// LastWrite of the parent BagMRU key (which holds this item's value).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_last_written: Option<Timestamp>,
    /// Own key LastWrite when the folder never had children registered:
    /// approximately when the folder was first interacted with.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_interacted: Option<Timestamp>,
    /// Parent key LastWrite when this item is MRU position 0: when the
    /// folder was most recently interacted with.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_interacted: Option<Timestamp>,
    /// Own key LastWrite when it has children: when a child of this folder
    /// was last registered (i.e. the folder was being browsed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_explored: Option<Timestamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bag: Option<BagInfo>,
    pub item: ShellItem,
    /// Additional items if the value held more than one (uncommon).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub extra_items: Vec<ShellItem>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

impl ShellBagEntry {
    /// The most recent timestamp attributable to user activity.
    pub fn activity_time(&self) -> Option<Timestamp> {
        [
            self.last_interacted,
            self.last_explored,
            self.first_interacted,
            self.key_last_written,
        ]
        .into_iter()
        .flatten()
        .max()
    }

    pub fn shell_type(&self) -> &str {
        &self.item.type_name
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct LocationSummary {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_written: Option<Timestamp>,
    pub entries: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desktop_bag: Option<BagInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HiveReport {
    pub path: String,
    pub kind: HiveKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    pub embedded_file_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_written: Option<Timestamp>,
    pub dirty: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery: Option<RecoveryReport>,
    pub locations: Vec<LocationSummary>,
    pub entries: usize,
    pub recovered: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ScanResult {
    pub hives: Vec<HiveReport>,
    pub entries: Vec<ShellBagEntry>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
}
