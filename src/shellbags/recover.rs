//! Re-attaches deleted BagMRU keys and values carved from unallocated cells.

use super::model::{EntryStatus, ShellBagEntry};
use super::walker::{build_paths, join, parse_mru_list_ex, KeyCtx, Walker};
use crate::regf::carve::{self, RecoveredKey};
use crate::regf::records::NONE_OFFSET;
use crate::shellitem::{parse_list_with_parent, Category, ParentHint, ShellItem};
use std::collections::{HashMap, HashSet};

struct Resolver<'a> {
    by_offset: &'a HashMap<u32, &'a RecoveredKey>,
    resolved: &'a mut HashMap<u32, KeyCtx>,
    live_raw: &'a HashSet<Vec<u8>>,
    ropts: &'a RecoverOptions,
    orphans: &'a HashMap<String, Vec<(u32, ShellItem)>>,
    used: &'a mut HashSet<u32>,
}

pub struct RecoverOptions {
    /// Keep recovered items whose bytes are identical to a live entry.
    pub include_duplicates: bool,
    /// Report free value cells that cannot be tied to any BagMRU key.
    pub include_orphan_values: bool,
}

impl Walker<'_> {
    pub fn recover_deleted(&mut self, ropts: &RecoverOptions) {
        let carved = carve::carve(self.hive);
        let live_raw: HashSet<Vec<u8>> = self.entries.iter().map(|e| e.item.raw.clone()).collect();
        let by_offset: HashMap<u32, &RecoveredKey> =
            carved.keys.iter().map(|k| (k.node.offset, k)).collect();

        // Resolve each recovered key to a context, walking parents through
        // other recovered keys until we reach a live BagMRU key.
        let mut resolved: HashMap<u32, KeyCtx> = HashMap::new();
        let mut order: Vec<u32> = carved.keys.iter().map(|k| k.node.offset).collect();
        order.sort_by_key(|o| by_offset[o].node.offset);
        // Unlinked value records that parse as shell items, by value name:
        // used to infer the item of a deleted key when unambiguous.
        let attached_vk: HashSet<u32> = carved
            .keys
            .iter()
            .flat_map(|k| k.values.iter().map(|v| v.node.offset))
            .collect();
        let mut orphans: HashMap<String, Vec<(u32, ShellItem)>> = HashMap::new();
        for v in &carved.orphan_values {
            if attached_vk.contains(&v.node.offset)
                || v.node.data_type != 3
                || v.node.name.parse::<u32>().is_err()
            {
                continue;
            }
            let Some(data) = v.data.as_deref() else {
                continue;
            };
            if let Some(item) = parse_list_with_parent(data, &self.opts, None).pop() {
                if item.category != Category::Unknown && !live_raw.contains(&item.raw) {
                    orphans
                        .entry(v.node.name.clone())
                        .or_default()
                        .push((v.node.offset, item));
                }
            }
        }
        let mut used_orphans: HashSet<u32> = HashSet::new();
        for &off in &order {
            let mut r = Resolver {
                by_offset: &by_offset,
                resolved: &mut resolved,
                live_raw: &live_raw,
                ropts,
                orphans: &orphans,
                used: &mut used_orphans,
            };
            self.resolve(off, &mut r, 0);
        }

        if ropts.include_orphan_values {
            let attached: HashSet<u32> = carved
                .keys
                .iter()
                .flat_map(|k| k.values.iter().map(|v| v.node.offset))
                .collect();
            for v in carved.orphan_values {
                if attached.contains(&v.node.offset)
                    || used_orphans.contains(&v.node.offset)
                    || v.node.data_type != 3
                    || v.node.name.parse::<u32>().is_err()
                {
                    continue;
                }
                let Some(data) = v.data else { continue };
                let items = parse_list_with_parent(&data, &self.opts, None);
                let Some(item) = items.last().cloned() else {
                    continue;
                };
                if item.category == Category::Unknown
                    || (!ropts.include_duplicates && live_raw.contains(&item.raw))
                {
                    continue;
                }
                let id = self.alloc_id();
                let seg = item.segment();
                self.entries.push(self.recovered_entry(
                    id,
                    None,
                    "<unknown location>",
                    "<unallocated>",
                    &v.node.name,
                    0,
                    join("<unknown parent>", &seg),
                    None,
                    item,
                    vec![format!(
                        "orphan value record carved at hive offset 0x{:x}; parent key unknown",
                        v.node.offset
                    )],
                ));
            }
        }
    }

    fn resolve(&mut self, off: u32, r: &mut Resolver<'_>, depth: usize) -> Option<KeyCtx> {
        if let Some(c) = r.resolved.get(&off) {
            return Some(c.clone());
        }
        if depth > 64 {
            return None;
        }
        let rk = *r.by_offset.get(&off)?;
        let parent_off = rk.node.parent;
        if parent_off == NONE_OFFSET || parent_off == off {
            return None;
        }
        // Parent is either a live BagMRU key, a live "...\Shell" key (whole
        // BagMRU tree deleted), or another recovered key.
        let parent_ctx: KeyCtx = if let Some(c) = self.key_ctx.get(&parent_off) {
            c.clone()
        } else if let Some(loc) = self.shell_parents.get(&parent_off).cloned() {
            if !rk.node.name.eq_ignore_ascii_case("BagMRU") {
                return None;
            }
            // The deleted key *is* a BagMRU root.
            let ctx = KeyCtx {
                location: format!("{loc} (deleted)"),
                abs: String::new(),
                fs: None,
                bag_path: "BagMRU".into(),
                depth: 0,
                entry_id: None,
                hint: None,
                slots: HashMap::new(),
            };
            let ctx = self.emit_values(rk, ctx, r.live_raw, r.ropts);
            r.resolved.insert(off, ctx.clone());
            return Some(ctx);
        } else if r.by_offset.contains_key(&parent_off) {
            self.resolve(parent_off, r, depth + 1)?
        } else {
            return None;
        };

        // Identify this key's own shell item from the parent's values.
        let name = rk.node.name.clone();
        if name.parse::<u32>().is_err() {
            return None;
        }
        let bag_path = format!("{}\\{name}", parent_ctx.bag_path);
        let (id, abs, fs, hint) = if let Some(&eid) = parent_ctx.slots.get(&name) {
            // Live (or already recovered) item; only its subkey was freed.
            let e = self.entries.iter().find(|e| e.id == eid)?;
            (
                Some(eid),
                e.absolute_path.clone(),
                e.fs_path.clone(),
                Some(ParentHint::from_item(&e.item)),
            )
        } else {
            let id = self.alloc_id();
            // Infer the item only when exactly one unlinked value record
            // carries this slot name (otherwise the identity is ambiguous).
            let candidates: Vec<&(u32, ShellItem)> = r
                .orphans
                .get(&name)
                .map(|v| v.iter().filter(|(o, _)| !r.used.contains(o)).collect())
                .unwrap_or_default();
            let (item, abs, fs, hint, mut notes) = if candidates.len() == 1 {
                let (voff, item) = candidates[0].clone();
                r.used.insert(voff);
                let (abs, fs) = build_paths(&parent_ctx.abs, parent_ctx.fs.as_deref(), &[], &item);
                let hint = Some(ParentHint::from_item(&item));
                let note = format!(
                    "item inferred from the only unlinked value record named \"{name}\" (hive offset 0x{voff:x})"
                );
                (item, abs, fs, hint, vec![note])
            } else {
                let seg = format!("<deleted item {name}>");
                let abs = join(&parent_ctx.abs, &seg);
                let note = "its shell item value no longer exists in the parent key".to_string();
                (
                    ShellItem::placeholder(&seg, "Deleted BagMRU key"),
                    abs,
                    None,
                    None,
                    vec![note],
                )
            };
            notes.insert(
                0,
                format!(
                    "deleted BagMRU key carved at hive offset 0x{:x}",
                    rk.node.offset
                ),
            );
            let mut entry = self.recovered_entry(
                id,
                parent_ctx.entry_id,
                &parent_ctx.location,
                &bag_path,
                &name,
                parent_ctx.depth,
                abs.clone(),
                fs.clone(),
                item,
                notes,
            );
            entry.key_last_written = rk.node.last_written();
            entry.child_count = rk
                .values
                .iter()
                .filter(|v| v.node.name.parse::<u32>().is_ok())
                .count();
            if entry.child_count == 0 {
                entry.first_interacted = entry.key_last_written;
            } else {
                entry.last_explored = entry.key_last_written;
            }
            self.entries.push(entry);
            (Some(id), abs, fs, hint)
        };
        let ctx = KeyCtx {
            location: parent_ctx.location.clone(),
            abs,
            fs,
            bag_path,
            depth: parent_ctx.depth + 1,
            entry_id: id,
            hint,
            slots: HashMap::new(),
        };
        let ctx = self.emit_values(rk, ctx, r.live_raw, r.ropts);
        r.resolved.insert(off, ctx.clone());
        Some(ctx)
    }

    /// Emits recovered entries for the numbered values of a recovered key.
    fn emit_values(
        &mut self,
        rk: &RecoveredKey,
        mut ctx: KeyCtx,
        live_raw: &HashSet<Vec<u8>>,
        ropts: &RecoverOptions,
    ) -> KeyCtx {
        let mru: Vec<u32> = rk
            .values
            .iter()
            .find(|v| v.node.name.eq_ignore_ascii_case("MRUListEx"))
            .and_then(|v| v.data.as_deref())
            .map(parse_mru_list_ex)
            .unwrap_or_default();
        let mut vals: Vec<_> = rk
            .values
            .iter()
            .filter(|v| v.node.name.parse::<u32>().is_ok())
            .collect();
        vals.sort_by_key(|v| v.node.name.parse::<u32>().unwrap_or(u32::MAX));
        for v in vals {
            let Some(data) = v.data.as_deref() else {
                continue;
            };
            let mut items = parse_list_with_parent(data, &self.opts, ctx.hint.as_ref());
            let Some(item) = items.pop() else { continue };
            if !ropts.include_duplicates && live_raw.contains(&item.raw) {
                continue;
            }
            let slot: u32 = v.node.name.parse().unwrap_or(0);
            let (abs, fs) = build_paths(&ctx.abs, ctx.fs.as_deref(), &items, &item);
            let id = self.alloc_id();
            let mut entry = self.recovered_entry(
                id,
                ctx.entry_id,
                &ctx.location,
                &format!("{}\\{}", ctx.bag_path, v.node.name),
                &v.node.name,
                ctx.depth,
                abs,
                fs,
                item,
                vec![format!(
                    "value carved at hive offset 0x{:x} (key node at 0x{:x}{})",
                    v.node.offset,
                    rk.node.offset,
                    if v.vk_allocated {
                        ", value cell still allocated"
                    } else {
                        ""
                    }
                )],
            );
            entry.mru_position = mru.iter().position(|&m| m == slot).map(|p| p as u32);
            entry.parent_last_written = rk.node.last_written();
            if entry.mru_position == Some(0) {
                entry.last_interacted = rk.node.last_written();
            }
            entry.extra_items = items;
            ctx.slots.insert(v.node.name.clone(), id);
            self.entries.push(entry);
        }
        ctx
    }

    #[allow(clippy::too_many_arguments)]
    fn recovered_entry(
        &self,
        id: usize,
        parent_id: Option<usize>,
        location: &str,
        bag_path: &str,
        value_name: &str,
        depth: usize,
        abs: String,
        fs: Option<String>,
        item: ShellItem,
        notes: Vec<String>,
    ) -> ShellBagEntry {
        ShellBagEntry {
            id,
            parent_id,
            status: EntryStatus::Recovered,
            source: self.source.clone(),
            hive_kind: self.kind,
            user: self.user.clone(),
            location: location.to_string(),
            bag_path: bag_path.to_string(),
            value_name: value_name.to_string(),
            mru_position: None,
            node_slot: None,
            depth,
            absolute_path: abs,
            fs_path: fs,
            child_count: 0,
            key_last_written: None,
            parent_last_written: None,
            first_interacted: None,
            last_interacted: None,
            last_explored: None,
            bag: None,
            item,
            extra_items: Vec::new(),
            notes,
        }
    }
}
