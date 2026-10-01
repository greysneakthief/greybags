//! Minimal registry hive writer.
//!
//! Produces structurally valid REGF files for tests, demos and training
//! exercises (e.g. `greybags demo-hive`). Keys can be marked as deleted, in
//! which case their records are written into *unallocated* cells and
//! unlinked from the parent, mimicking what Windows leaves behind.

use super::base::checksum;
use super::records::lh_hash;

#[derive(Debug, Clone)]
struct BKey {
    name: String,
    last_written: u64,
    values: Vec<BValue>,
    children: Vec<usize>,
    deleted: bool,
}

#[derive(Debug, Clone)]
struct BValue {
    name: String,
    data_type: u32,
    data: Vec<u8>,
    deleted: bool,
}

pub type KeyId = usize;

#[derive(Debug, Clone)]
pub struct HiveBuilder {
    keys: Vec<BKey>,
    file_name: String,
    last_written: u64,
    sequence: (u32, u32),
}

struct Alloc {
    data: Vec<u8>,
    /// Offsets of cells that must be flipped to "free" at the end.
    free: Vec<u32>,
}

impl Alloc {
    fn alloc(&mut self, payload: &[u8]) -> u32 {
        let total = (payload.len() + 4).div_ceil(8) * 8;
        let off = self.data.len() as u32;
        self.data
            .extend_from_slice(&(-(total as i32)).to_le_bytes());
        self.data.extend_from_slice(payload);
        self.data.resize(off as usize + total, 0);
        off
    }

    fn patch_u32(&mut self, cell: u32, field: usize, v: u32) {
        let p = cell as usize + 4 + field;
        self.data[p..p + 4].copy_from_slice(&v.to_le_bytes());
    }
}

impl HiveBuilder {
    pub fn new(root_name: &str, last_written: u64) -> HiveBuilder {
        HiveBuilder {
            keys: vec![BKey {
                name: root_name.into(),
                last_written,
                values: vec![],
                children: vec![],
                deleted: false,
            }],
            file_name: "\\??\\C:\\Users\\analyst\\ntuser.dat".into(),
            last_written,
            sequence: (1, 1),
        }
    }

    pub const ROOT: KeyId = 0;

    pub fn file_name(mut self, name: &str) -> Self {
        self.file_name = name.into();
        self
    }

    /// Sets primary/secondary sequence numbers (unequal = dirty hive).
    pub fn sequence(mut self, primary: u32, secondary: u32) -> Self {
        self.sequence = (primary, secondary);
        self
    }

    pub fn add_key(&mut self, parent: KeyId, name: &str, last_written: u64) -> KeyId {
        let id = self.keys.len();
        self.keys.push(BKey {
            name: name.into(),
            last_written,
            values: vec![],
            children: vec![],
            deleted: false,
        });
        self.keys[parent].children.push(id);
        id
    }

    /// Writes the key (and its whole subtree) into free cells instead.
    pub fn delete_key(&mut self, key: KeyId) {
        self.keys[key].deleted = true;
    }

    pub fn add_value(&mut self, key: KeyId, name: &str, data_type: u32, data: &[u8]) {
        self.keys[key].values.push(BValue {
            name: name.into(),
            data_type,
            data: data.to_vec(),
            deleted: false,
        });
    }

    /// Adds a value that is written to free cells and not linked to the key.
    pub fn add_deleted_value(&mut self, key: KeyId, name: &str, data_type: u32, data: &[u8]) {
        self.keys[key].values.push(BValue {
            name: name.into(),
            data_type,
            data: data.to_vec(),
            deleted: true,
        });
    }

    pub fn add_binary(&mut self, key: KeyId, name: &str, data: &[u8]) {
        self.add_value(key, name, 3, data);
    }

    pub fn add_dword(&mut self, key: KeyId, name: &str, v: u32) {
        self.add_value(key, name, 4, &v.to_le_bytes());
    }

    pub fn add_string(&mut self, key: KeyId, name: &str, s: &str) {
        let mut d: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        d.extend_from_slice(&[0, 0]);
        self.add_value(key, name, 1, &d);
    }

    /// Serialises the hive to bytes (base block + one hive bin).
    pub fn build(&self) -> Vec<u8> {
        let mut a = Alloc {
            data: vec![0u8; 32],
            free: vec![],
        };
        let root = self.write_key(&mut a, 0, 0xFFFF_FFFF, false);
        // Pad the bin to a 4 KiB multiple, leaving one trailing free cell.
        let mut len = a.data.len();
        if len & 0xFFF > 4096 - 8 || len & 0xFFF == 0 {
            len += 8;
        }
        let bin_size = len.div_ceil(4096) * 4096;
        let free_len = bin_size - a.data.len();
        if free_len >= 8 {
            let off = a.data.len();
            a.data.extend_from_slice(&(free_len as i32).to_le_bytes());
            a.data.resize(off + free_len, 0);
        }
        for &f in &a.free {
            let p = f as usize;
            let v = i32::from_le_bytes([a.data[p], a.data[p + 1], a.data[p + 2], a.data[p + 3]]);
            a.data[p..p + 4].copy_from_slice(&v.unsigned_abs().to_le_bytes());
        }
        // hbin header
        a.data[0..4].copy_from_slice(b"hbin");
        a.data[4..8].copy_from_slice(&0u32.to_le_bytes());
        a.data[8..12].copy_from_slice(&(bin_size as u32).to_le_bytes());
        a.data[20..28].copy_from_slice(&self.last_written.to_le_bytes());

        let mut base = vec![0u8; 4096];
        base[0..4].copy_from_slice(b"regf");
        base[4..8].copy_from_slice(&self.sequence.0.to_le_bytes());
        base[8..12].copy_from_slice(&self.sequence.1.to_le_bytes());
        base[12..20].copy_from_slice(&self.last_written.to_le_bytes());
        base[20..24].copy_from_slice(&1u32.to_le_bytes());
        base[24..28].copy_from_slice(&5u32.to_le_bytes());
        base[28..32].copy_from_slice(&0u32.to_le_bytes());
        base[32..36].copy_from_slice(&1u32.to_le_bytes());
        base[36..40].copy_from_slice(&root.to_le_bytes());
        base[40..44].copy_from_slice(&(bin_size as u32).to_le_bytes());
        base[44..48].copy_from_slice(&1u32.to_le_bytes());
        let name: Vec<u8> = self
            .file_name
            .encode_utf16()
            .take(31)
            .flat_map(|u| u.to_le_bytes())
            .collect();
        base[48..48 + name.len()].copy_from_slice(&name);
        let c = checksum(&base[..508]);
        base[508..512].copy_from_slice(&c.to_le_bytes());
        base.extend_from_slice(&a.data);
        base
    }

    fn write_key(&self, a: &mut Alloc, id: KeyId, parent: u32, inherited_deleted: bool) -> u32 {
        let k = &self.keys[id];
        let deleted = inherited_deleted || k.deleted;
        let comp = k.name.chars().all(|c| (c as u32) < 256);
        let name_bytes: Vec<u8> = if comp {
            k.name.chars().map(|c| c as u8).collect()
        } else {
            k.name
                .encode_utf16()
                .flat_map(|u| u.to_le_bytes())
                .collect()
        };
        let mut nk = vec![0u8; 76];
        nk[0..2].copy_from_slice(b"nk");
        let mut flags: u16 = if comp { 0x20 } else { 0 };
        if id == 0 {
            flags |= 0x0004 | 0x0008;
        }
        nk[2..4].copy_from_slice(&flags.to_le_bytes());
        nk[4..12].copy_from_slice(&k.last_written.to_le_bytes());
        nk[16..20].copy_from_slice(&parent.to_le_bytes());
        for f in [28usize, 32, 40, 44, 48] {
            nk[f..f + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        }
        nk[72..74].copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        nk.extend_from_slice(&name_bytes);
        let nk_off = a.alloc(&nk);
        if deleted {
            a.free.push(nk_off);
        }

        // Values
        let mut live = Vec::new();
        for v in &k.values {
            let vdeleted = deleted || v.deleted;
            let comp = v.name.chars().all(|c| (c as u32) < 256);
            let vname: Vec<u8> = if comp {
                v.name.chars().map(|c| c as u8).collect()
            } else {
                v.name
                    .encode_utf16()
                    .flat_map(|u| u.to_le_bytes())
                    .collect()
            };
            let (size_field, data_field) = if v.data.len() <= 4 {
                let mut d = [0u8; 4];
                d[..v.data.len()].copy_from_slice(&v.data);
                (v.data.len() as u32 | 0x8000_0000, u32::from_le_bytes(d))
            } else {
                let off = a.alloc(&v.data);
                if vdeleted {
                    a.free.push(off);
                }
                (v.data.len() as u32, off)
            };
            let mut vk = vec![0u8; 20];
            vk[0..2].copy_from_slice(b"vk");
            vk[2..4].copy_from_slice(&(vname.len() as u16).to_le_bytes());
            vk[4..8].copy_from_slice(&size_field.to_le_bytes());
            vk[8..12].copy_from_slice(&data_field.to_le_bytes());
            vk[12..16].copy_from_slice(&v.data_type.to_le_bytes());
            vk[16..18].copy_from_slice(&(if comp { 1u16 } else { 0 }).to_le_bytes());
            vk.extend_from_slice(&vname);
            let vk_off = a.alloc(&vk);
            if vdeleted {
                a.free.push(vk_off);
            }
            if !v.deleted {
                live.push(vk_off);
            }
        }
        if !live.is_empty() {
            let list: Vec<u8> = live.iter().flat_map(|o| o.to_le_bytes()).collect();
            let list_off = a.alloc(&list);
            if deleted {
                a.free.push(list_off);
            }
            a.patch_u32(nk_off, 36, live.len() as u32);
            a.patch_u32(nk_off, 40, list_off);
        }

        // Subkeys (deleted children are written but not linked).
        let mut linked = Vec::new();
        for &c in &k.children {
            let child_off = self.write_key(a, c, nk_off, deleted);
            if !self.keys[c].deleted || deleted {
                linked.push((child_off, lh_hash(&self.keys[c].name)));
            }
        }
        if !linked.is_empty() {
            let mut lh = Vec::with_capacity(4 + linked.len() * 8);
            lh.extend_from_slice(b"lh");
            lh.extend_from_slice(&(linked.len() as u16).to_le_bytes());
            for (o, h) in &linked {
                lh.extend_from_slice(&o.to_le_bytes());
                lh.extend_from_slice(&h.to_le_bytes());
            }
            let lh_off = a.alloc(&lh);
            if deleted {
                a.free.push(lh_off);
            }
            a.patch_u32(nk_off, 20, linked.len() as u32);
            a.patch_u32(nk_off, 28, lh_off);
        }
        nk_off
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::regf::{carve, Hive};

    #[test]
    fn roundtrip() {
        let mut b = HiveBuilder::new("ROOT", 132_000_000_000_000_000);
        let sw = b.add_key(HiveBuilder::ROOT, "Software", 132_000_000_000_000_001);
        b.add_dword(sw, "Answer", 42);
        b.add_string(sw, "Name", "greybags");
        b.add_binary(sw, "Blob", &[1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let gone = b.add_key(sw, "Gone", 132_000_000_000_000_002);
        b.add_binary(gone, "0", &[9u8; 24]);
        b.delete_key(gone);
        let hive = Hive::from_bytes(b.build()).unwrap();
        assert!(hive.warnings.is_empty(), "{:?}", hive.warnings);
        let k = hive.open_key("Software").unwrap().unwrap();
        assert_eq!(k.value("Answer").unwrap().unwrap().as_u32(), Some(42));
        assert_eq!(
            k.value("Name").unwrap().unwrap().as_string().as_deref(),
            Some("greybags")
        );
        assert_eq!(k.value("Blob").unwrap().unwrap().data().unwrap().len(), 9);
        assert!(k.subkey("Gone").unwrap().is_none());
        let c = carve::carve(&hive);
        let rk = c
            .keys
            .iter()
            .find(|k| k.node.name == "Gone")
            .expect("deleted key recovered");
        assert_eq!(rk.node.parent, k.offset());
        assert_eq!(rk.values.len(), 1);
        assert_eq!(rk.values[0].data.as_deref(), Some(&[9u8; 24][..]));
    }
}
