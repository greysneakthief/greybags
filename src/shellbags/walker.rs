//! Recursive BagMRU traversal.

use super::bags::read_bag;
use super::model::{EntryStatus, HiveKind, LocationSummary, ShellBagEntry};
use crate::regf::{Hive, Key};
use crate::shellitem::{parse_list_with_parent, Category, ParentHint, ParseOptions, ShellItem};
use crate::util::bytes::u32_at;
use std::collections::{HashMap, HashSet};

/// BagMRU locations relative to the hive root, with their Bags sibling.
pub const LOCATIONS: &[&str] = &[
    // UsrClass.dat (Vista and later)
    "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
    "Wow6432Node\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
    // NTUSER.DAT (XP: both; Vista+: network/remote folders in Shell\BagMRU)
    "Software\\Microsoft\\Windows\\Shell\\BagMRU",
    "Software\\Microsoft\\Windows\\ShellNoRoam\\BagMRU",
    "Software\\Wow6432Node\\Microsoft\\Windows\\Shell\\BagMRU",
    "Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
];

const MAX_DEPTH: usize = 128;

/// Per-BagMRU-key context, indexed by nk cell offset. Used to attach
/// recovered (deleted) keys to their surviving parents.
#[derive(Debug, Clone)]
pub struct KeyCtx {
    pub location: String,
    pub abs: String,
    pub fs: Option<String>,
    pub bag_path: String,
    pub depth: usize,
    pub entry_id: Option<usize>,
    pub hint: Option<ParentHint>,
    /// value name -> entry id
    pub slots: HashMap<String, usize>,
}

pub struct Walker<'h> {
    pub hive: &'h Hive,
    pub opts: ParseOptions,
    pub source: String,
    pub kind: HiveKind,
    pub user: Option<String>,
    pub next_id: usize,
    pub entries: Vec<ShellBagEntry>,
    pub key_ctx: HashMap<u32, KeyCtx>,
    /// Offsets of the parent keys of BagMRU roots (`...\Shell`), so a
    /// wholesale-deleted BagMRU tree can still be re-attached.
    pub shell_parents: HashMap<u32, String>,
    pub warnings: Vec<String>,
    pub locations: Vec<LocationSummary>,
}

pub fn parse_mru_list_ex(data: &[u8]) -> Vec<u32> {
    let mut out = Vec::new();
    for i in 0..data.len() / 4 {
        match u32_at(data, i * 4) {
            Some(0xFFFF_FFFF) | None => break,
            Some(v) => out.push(v),
        }
    }
    out
}

impl<'h> Walker<'h> {
    pub fn new(
        hive: &'h Hive,
        opts: ParseOptions,
        source: String,
        kind: HiveKind,
        user: Option<String>,
        first_id: usize,
    ) -> Self {
        Walker {
            hive,
            opts,
            source,
            kind,
            user,
            next_id: first_id,
            entries: Vec::new(),
            key_ctx: HashMap::new(),
            shell_parents: HashMap::new(),
            warnings: Vec::new(),
            locations: Vec::new(),
        }
    }

    pub fn walk_all(&mut self) {
        let mut seen = HashSet::new();
        for loc in LOCATIONS {
            let parent_path = loc.rsplit_once('\\').map(|(p, _)| p).unwrap_or("");
            if let Ok(Some(pk)) = self.hive.open_key(parent_path) {
                self.shell_parents.insert(pk.offset(), loc.to_string());
            }
            let key = match self.hive.open_key(loc) {
                Ok(Some(k)) => k,
                Ok(None) => continue,
                Err(e) => {
                    self.warnings.push(format!("{loc}: {e}"));
                    continue;
                }
            };
            // Software\Classes in NTUSER can alias UsrClass content; skip
            // a location we already walked via another path.
            if !seen.insert(key.offset()) {
                continue;
            }
            let bags = self
                .hive
                .open_key(&format!("{parent_path}\\Bags"))
                .ok()
                .flatten();
            let desktop_bag = key
                .value("NodeSlot")
                .ok()
                .flatten()
                .and_then(|v| v.as_u32())
                .and_then(|slot| bags.as_ref().and_then(|b| read_bag(b, slot)));
            let before = self.entries.len();
            self.walk_key(&key, loc, bags.as_ref(), None, "", None, "BagMRU", 0, None);
            self.locations.push(LocationSummary {
                path: loc.to_string(),
                last_written: key.last_written(),
                entries: self.entries.len() - before,
                desktop_bag,
            });
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn walk_key(
        &mut self,
        key: &Key<'h>,
        location: &str,
        bags: Option<&Key<'h>>,
        parent_id: Option<usize>,
        parent_abs: &str,
        parent_fs: Option<String>,
        bag_path: &str,
        depth: usize,
        hint: Option<ParentHint>,
    ) {
        if depth > MAX_DEPTH {
            self.warnings
                .push(format!("{bag_path}: maximum depth exceeded"));
            return;
        }
        let (values, verrs) = key.values_lossy();
        let (subkeys, serrs) = key.subkeys_lossy();
        self.warnings.extend(verrs);
        self.warnings.extend(serrs);
        let mru: Vec<u32> = values
            .iter()
            .find(|v| v.name().eq_ignore_ascii_case("MRUListEx"))
            .and_then(|v| v.data().ok())
            .map(|d| parse_mru_list_ex(&d))
            .unwrap_or_default();
        let mru_pos: HashMap<u32, u32> = mru
            .iter()
            .enumerate()
            .map(|(i, &s)| (s, i as u32))
            .collect();
        let mut slots: Vec<(u32, crate::regf::Value)> = values
            .into_iter()
            .filter_map(|v| {
                v.name()
                    .parse::<u32>()
                    .ok()
                    .filter(|_| !v.name().is_empty())
                    .map(|n| (n, v))
            })
            .collect();
        slots.sort_by_key(|(n, _)| *n);
        let sub_by_name: HashMap<String, Key<'h>> = subkeys
            .into_iter()
            .map(|k| (k.name().to_ascii_lowercase(), k))
            .collect();

        let mut ctx = KeyCtx {
            location: location.to_string(),
            abs: parent_abs.to_string(),
            fs: parent_fs.clone(),
            bag_path: bag_path.to_string(),
            depth,
            entry_id: parent_id,
            hint: hint.clone(),
            slots: HashMap::new(),
        };

        for &m in &mru {
            if !slots.iter().any(|(n, _)| *n == m) {
                self.warnings.push(format!(
                    "{location}\\{}: MRUListEx references missing value {m}",
                    strip(bag_path)
                ));
            }
        }

        let mut handled_subkeys = HashSet::new();
        for (slot, value) in &slots {
            let data = match value.data() {
                Ok(d) => d,
                Err(e) => {
                    self.warnings.push(format!("{bag_path}\\{slot}: {e}"));
                    continue;
                }
            };
            let mut items = parse_list_with_parent(&data, &self.opts, hint.as_ref());
            if items.is_empty() {
                items.push(ShellItem::placeholder(
                    &format!("<empty value {slot}>"),
                    "Empty",
                ));
            }
            let item = items.pop().unwrap();
            let extra = items;
            let child = sub_by_name.get(&slot.to_string());
            if child.is_some() {
                handled_subkeys.insert(slot.to_string());
            }
            let id = self.alloc_id();
            let mut notes = Vec::new();
            if !mru.is_empty() && !mru_pos.contains_key(slot) {
                notes.push("value not referenced by parent MRUListEx".to_string());
            }
            let (abs, fs) = build_paths(parent_abs, parent_fs.as_deref(), &extra, &item);
            let child_bag_path = format!("{bag_path}\\{slot}");
            let mut entry = ShellBagEntry {
                id,
                parent_id,
                status: EntryStatus::Active,
                source: self.source.clone(),
                hive_kind: self.kind,
                user: self.user.clone(),
                location: location.to_string(),
                bag_path: child_bag_path.clone(),
                value_name: value.name().to_string(),
                mru_position: mru_pos.get(slot).copied(),
                node_slot: None,
                depth,
                absolute_path: abs.clone(),
                fs_path: fs.clone(),
                child_count: 0,
                key_last_written: None,
                parent_last_written: key.last_written(),
                first_interacted: None,
                last_interacted: if mru_pos.get(slot) == Some(&0) {
                    key.last_written()
                } else {
                    None
                },
                last_explored: None,
                bag: None,
                item,
                extra_items: extra,
                notes,
            };
            if let Some(ck) = child {
                self.fill_child_info(&mut entry, ck, bags);
            } else {
                entry.notes.push("no BagMRU subkey for this value".into());
            }
            let child_hint = ParentHint::from_item(&entry.item);
            ctx.slots.insert(value.name().to_string(), id);
            self.entries.push(entry);
            if let Some(ck) = child {
                self.walk_key(
                    ck,
                    location,
                    bags,
                    Some(id),
                    &abs,
                    fs,
                    &child_bag_path,
                    depth + 1,
                    Some(child_hint),
                );
            }
        }

        // Numbered subkeys with no shell item value: orphaned bags.
        let mut orphan_names: Vec<&String> = sub_by_name
            .keys()
            .filter(|n| n.parse::<u32>().is_ok() && !handled_subkeys.contains(*n))
            .collect();
        orphan_names.sort();
        for name in orphan_names {
            let ck = &sub_by_name[name];
            let id = self.alloc_id();
            let seg = format!("<orphaned bag {name}>");
            let abs = join(parent_abs, &seg);
            let child_bag_path = format!("{bag_path}\\{name}");
            let mut entry = ShellBagEntry {
                id,
                parent_id,
                status: EntryStatus::Orphaned,
                source: self.source.clone(),
                hive_kind: self.kind,
                user: self.user.clone(),
                location: location.to_string(),
                bag_path: child_bag_path.clone(),
                value_name: name.clone(),
                mru_position: mru_pos.get(&name.parse().unwrap_or(u32::MAX)).copied(),
                node_slot: None,
                depth,
                absolute_path: abs.clone(),
                fs_path: None,
                child_count: 0,
                key_last_written: None,
                parent_last_written: key.last_written(),
                first_interacted: None,
                last_interacted: None,
                last_explored: None,
                bag: None,
                item: ShellItem::placeholder(&seg, "Orphaned BagMRU key"),
                extra_items: Vec::new(),
                notes: vec![
                    "BagMRU subkey exists but the parent has no shell item value for it".into(),
                ],
            };
            self.fill_child_info(&mut entry, ck, bags);
            ctx.slots.insert(name.clone(), id);
            self.entries.push(entry);
            self.walk_key(
                ck,
                location,
                bags,
                Some(id),
                &abs,
                None,
                &child_bag_path,
                depth + 1,
                None,
            );
        }
        self.key_ctx.insert(key.offset(), ctx);
    }

    fn fill_child_info(&self, entry: &mut ShellBagEntry, ck: &Key<'h>, bags: Option<&Key<'h>>) {
        entry.key_last_written = ck.last_written();
        let (cvals, _) = ck.values_lossy();
        entry.child_count = cvals
            .iter()
            .filter(|v| !v.name().is_empty() && v.name().chars().all(|c| c.is_ascii_digit()))
            .count();
        entry.node_slot = cvals
            .iter()
            .find(|v| v.name().eq_ignore_ascii_case("NodeSlot"))
            .and_then(|v| v.as_u32());
        if entry.child_count == 0 {
            entry.first_interacted = ck.last_written();
        } else {
            entry.last_explored = ck.last_written();
        }
        if let (Some(slot), Some(b)) = (entry.node_slot, bags) {
            entry.bag = read_bag(b, slot);
            if entry.bag.is_none() {
                entry
                    .notes
                    .push(format!("NodeSlot {slot} has no Bags subkey"));
            }
        }
    }

    pub fn alloc_id(&mut self) -> usize {
        let id = self.next_id;
        self.next_id += 1;
        id
    }
}

fn strip(bag_path: &str) -> &str {
    bag_path
        .strip_prefix("BagMRU")
        .map(|s| s.trim_start_matches('\\'))
        .unwrap_or(bag_path)
}

pub fn join(parent: &str, seg: &str) -> String {
    if parent.is_empty() {
        seg.to_string()
    } else {
        format!("{parent}\\{seg}")
    }
}

/// Builds the namespace path and (if anchored) the file-system path.
pub fn build_paths(
    parent_abs: &str,
    parent_fs: Option<&str>,
    extra: &[ShellItem],
    item: &ShellItem,
) -> (String, Option<String>) {
    let mut abs = parent_abs.to_string();
    let mut fs = parent_fs.map(str::to_string);
    for it in extra.iter().chain(std::iter::once(item)) {
        let seg = display_segment(fs.as_deref(), it);
        abs = join(&abs, &seg);
        fs = next_fs(fs.as_deref(), it);
    }
    (abs, fs)
}

/// Namespace path segment. UNC names are shortened so that
/// `Network > \\srv > \\srv\share` reads `Network\srv\share` (the full UNC
/// is kept in `fs_path`).
pub fn display_segment(parent_fs: Option<&str>, it: &ShellItem) -> String {
    let seg = it.segment();
    if it.category == Category::NetworkLocation && seg.starts_with("\\\\") {
        if let Some(rest) = parent_fs
            .and_then(|p| seg.strip_prefix(p))
            .and_then(|r| r.strip_prefix('\\'))
        {
            if !rest.is_empty() {
                return rest.to_string();
            }
        }
        return seg.trim_start_matches('\\').to_string();
    }
    seg
}

/// Computes the file-system anchor or continuation for one item.
pub fn next_fs(parent_fs: Option<&str>, it: &ShellItem) -> Option<String> {
    if let Some(d) = it.drive_letter() {
        return Some(format!("{d}:"));
    }
    match it.category {
        Category::NetworkLocation if it.name.starts_with("\\\\") => {
            return Some(it.name.trim_end_matches('\\').to_string())
        }
        Category::RootFolder | Category::Volume | Category::UsersPropertyView => {
            let anchor = match it.guid_name.as_deref().unwrap_or(it.name.as_str()) {
                "Users Files" | "User profile" | "Users Files (delegate)" => {
                    Some("%USERPROFILE%".to_string())
                }
                n @ ("Desktop" | "Documents" | "Downloads" | "Music" | "Pictures" | "Videos"
                | "3D Objects" | "Saved Games" | "Contacts" | "Favorites" | "Links"
                | "Searches" | "OneDrive" | "Dropbox") => Some(format!("%USERPROFILE%\\{n}")),
                "My Documents" => Some("%USERPROFILE%\\Documents".to_string()),
                "Public" => Some("%PUBLIC%".to_string()),
                _ => None,
            };
            if anchor.is_some() {
                return anchor;
            }
            if it.category == Category::UsersPropertyView {
                if let Some(p) = it
                    .property("System.ParsingPath")
                    .and_then(|p| p.value.as_str())
                {
                    if p.len() > 2 && (p.as_bytes()[1] == b':' || p.starts_with("\\\\")) {
                        return Some(p.trim_end_matches('\\').to_string());
                    }
                }
            }
            return None;
        }
        Category::Directory
        | Category::File
        | Category::FileEntry
        | Category::CompressedFolder
        | Category::Delegate
        | Category::Cabinet => {}
        _ => return None,
    }
    parent_fs.map(|p| format!("{p}\\{}", it.segment()))
}
