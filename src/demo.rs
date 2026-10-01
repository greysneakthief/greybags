//! Synthetic training hive.
//!
//! Builds a fictional `UsrClass.dat` for user "jdoe" with a realistic mix of
//! shell items and a few planted artifacts (USB exfil folder, admin share,
//! RDP-redirected drive, archive browsing, a deleted BagMRU key, an orphaned
//! bag and a timestamp inconsistency). Every value is generated, none of it
//! comes from a real system. Used by `greybags demo-hive` and the tests.

use crate::regf::writer::{HiveBuilder, KeyId};
use crate::shellitem::build::{self, fat, filetime};

const LOC: [&str; 6] = [
    "Local Settings",
    "Software",
    "Microsoft",
    "Windows",
    "Shell",
    "BagMRU",
];

struct Ctx {
    b: HiveBuilder,
    bags: KeyId,
    next_slot: u32,
}

impl Ctx {
    /// Adds a child item under `parent` at value `slot`, creates its subkey,
    /// a NodeSlot and a matching Bags entry. Returns the new subkey.
    fn child(
        &mut self,
        parent: KeyId,
        slot: u32,
        item: &[u8],
        key_time: u64,
        folder_type: Option<&str>,
    ) -> KeyId {
        let mut v = item.to_vec();
        v.extend_from_slice(&[0, 0]);
        self.b.add_binary(parent, &slot.to_string(), &v);
        let k = self.b.add_key(parent, &slot.to_string(), key_time);
        let node_slot = self.next_slot;
        self.next_slot += 1;
        self.b.add_dword(k, "NodeSlot", node_slot);
        let bag = self
            .b
            .add_key(self.bags, &node_slot.to_string(), key_time + 10_000_000);
        let shell = self.b.add_key(bag, "Shell", key_time + 10_000_000);
        if let Some(ft) = folder_type {
            let g = self.b.add_key(shell, ft, key_time + 10_000_000);
            self.b.add_dword(g, "LogicalViewMode", 1);
            self.b.add_dword(g, "Mode", 4);
        }
        k
    }

    fn mru(&mut self, key: KeyId, order: &[u32]) {
        self.b
            .add_binary(key, "MRUListEx", &build::mru_list_ex(order));
    }
}

const GENERIC: &str = "{5C4F28B5-F869-4E84-8E60-F11DB97C5CC7}";
const DOCUMENTS: &str = "{7D49D726-3C21-4F05-99AA-FDC2C9474656}";
const DOWNLOADS: &str = "{885A186E-A440-4ADA-812B-DB871B942259}";

/// Returns the bytes of the demo UsrClass.dat.
pub fn demo_usrclass() -> Vec<u8> {
    let t = |d: u32, h: u32, m: u32, s: u32| filetime(2024, 3, d, h, m, s) + 1_234_567;
    let mut b = HiveBuilder::new(
        "S-1-5-21-1111111111-2222222222-3333333333-1001_Classes",
        t(20, 18, 0, 0),
    )
    .file_name("\\??\\C:\\Users\\jdoe\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat");
    let mut k = HiveBuilder::ROOT;
    let mut shell = 0;
    for (i, name) in LOC.iter().enumerate() {
        let when = if i == LOC.len() - 1 {
            t(19, 23, 0, 0)
        } else {
            t(1, 9, 0, 0)
        };
        k = b.add_key(k, name, when);
        if i == 4 {
            shell = k;
        }
    }
    let bagmru = k;
    let bags = b.add_key(shell, "Bags", t(1, 9, 0, 0));
    let mut c = Ctx {
        b,
        bags,
        next_slot: 1,
    };
    c.b.add_dword(bagmru, "NodeSlot", 0);

    // --- My Computer -------------------------------------------------------
    let mycomp = c.child(bagmru, 0, &build::my_computer(), t(19, 22, 41, 7), None);
    let cdrive = c.child(mycomp, 0, &build::volume("C:\\"), t(19, 9, 12, 0), None);
    let users = c.child(
        cdrive,
        0,
        &build::dir(
            "Users",
            fat(2019, 12, 7, 9, 3, 44),
            fat(2024, 3, 2, 8, 0, 0),
            4_517,
            1,
        ),
        t(18, 21, 4, 59),
        Some(GENERIC),
    );
    let jdoe = c.child(
        users,
        0,
        &build::users_files_delegate("jdoe", fat(2023, 1, 9, 14, 20, 0), 88_210, 2),
        t(18, 21, 5, 0),
        Some(GENERIC),
    );
    let downloads = c.child(
        jdoe,
        0,
        &build::dir(
            "Downloads",
            fat(2023, 1, 9, 14, 20, 2),
            fat(2024, 3, 18, 21, 4, 58),
            88_241,
            2,
        ),
        t(18, 21, 6, 30),
        Some(DOWNLOADS),
    );
    let mimi = c.child(
        downloads,
        0,
        &build::dir(
            "mimikatz_trunk",
            fat(2024, 3, 18, 21, 4, 40),
            fat(2024, 3, 18, 21, 4, 52),
            140_993,
            4,
        ),
        t(18, 21, 6, 30),
        Some(GENERIC),
    );
    c.child(
        mimi,
        0,
        &build::dir(
            "x64",
            fat(2024, 3, 18, 21, 4, 41),
            fat(2024, 3, 18, 21, 4, 50),
            141_002,
            4,
        ),
        t(18, 21, 6, 10),
        Some(GENERIC),
    );
    c.mru(mimi, &[0]);
    let archive = build::dir(
        "Q1_payroll_export.zip",
        fat(2024, 3, 18, 21, 0, 0),
        fat(2024, 3, 18, 21, 0, 0),
        141_100,
        1,
    );
    let zip = c.child(downloads, 1, &archive, t(18, 21, 2, 0), None);
    c.child(
        zip,
        0,
        &build::zip_item("payroll", "03/18/2024  20:55:12"),
        t(18, 21, 2, 15),
        None,
    );
    c.mru(zip, &[0]);
    c.mru(downloads, &[0, 1]);
    let docs = c.child(
        jdoe,
        1,
        &build::dir(
            "Documents",
            fat(2023, 1, 9, 14, 20, 2),
            fat(2024, 3, 11, 16, 2, 10),
            88_244,
            2,
        ),
        t(11, 16, 3, 0),
        Some(DOCUMENTS),
    );
    // Timestamp inconsistency: item "created" well after its key was last written.
    c.child(
        docs,
        0,
        &build::dir(
            "Projects",
            fat(2024, 6, 1, 12, 0, 0),
            fat(2024, 6, 1, 12, 0, 0),
            90_002,
            3,
        ),
        t(11, 16, 3, 0),
        Some(DOCUMENTS),
    );
    c.mru(docs, &[0]);
    c.mru(jdoe, &[0, 1]);
    c.mru(users, &[0]);
    let windows = c.child(
        cdrive,
        1,
        &build::dir(
            "Windows",
            fat(2019, 12, 7, 9, 3, 44),
            fat(2024, 2, 20, 3, 0, 0),
            2_316,
            1,
        ),
        t(19, 9, 12, 0),
        Some(GENERIC),
    );
    let temp = c.child(
        windows,
        0,
        &build::dir(
            "Temp",
            fat(2019, 12, 7, 9, 3, 50),
            fat(2024, 3, 19, 9, 11, 0),
            2_901,
            1,
        ),
        t(19, 9, 12, 0),
        Some(GENERIC),
    );
    c.child(
        temp,
        0,
        &build::dir(
            "staging",
            fat(2024, 3, 19, 9, 10, 2),
            fat(2024, 3, 19, 9, 11, 30),
            151_222,
            1,
        ),
        t(19, 9, 12, 0),
        Some(GENERIC),
    );
    c.mru(temp, &[0]);
    c.mru(windows, &[0]);
    // Deleted subtree under C:\ (slot 2): written to unallocated cells.
    let gone = {
        let mut v = build::dir(
            "SecretProject",
            fat(2024, 3, 5, 10, 0, 0),
            fat(2024, 3, 6, 11, 30, 0),
            120_001,
            5,
        );
        v.extend_from_slice(&[0, 0]);
        c.b.add_deleted_value(cdrive, "2", 3, &v);
        let k = c.b.add_key(cdrive, "2", t(6, 11, 31, 0));
        c.b.add_dword(k, "NodeSlot", 99);
        let mut child = build::dir(
            "blueprints",
            fat(2024, 3, 6, 11, 0, 0),
            fat(2024, 3, 6, 11, 29, 0),
            120_007,
            5,
        );
        child.extend_from_slice(&[0, 0]);
        c.b.add_binary(k, "0", &child);
        c.b.add_binary(k, "MRUListEx", &build::mru_list_ex(&[0]));
        k
    };
    c.b.delete_key(gone);
    c.mru(cdrive, &[1, 0]);

    // Removable volume with an exfil-looking folder.
    let edrive = c.child(mycomp, 1, &build::volume("E:\\"), t(19, 22, 41, 7), None);
    let exfil = c.child(
        edrive,
        0,
        &build::dir(
            "Exfil",
            fat(2024, 3, 19, 22, 30, 0),
            fat(2024, 3, 19, 22, 40, 2),
            37,
            1,
        ),
        t(19, 22, 41, 7),
        Some(GENERIC),
    );
    c.mru(exfil, &[]);
    c.mru(edrive, &[0]);
    // Phone over MTP.
    let phone = build::mtp_volume(
        "Internal shared storage",
        "\\\\?\\usb#vid_18d1&pid_4ee1#9A221FFAZ003TX#{6ac27878-a6fa-4155-ba85-f98f491d4f33}",
        "FAT32",
    );
    c.child(mycomp, 2, &phone, t(15, 13, 37, 0), None);
    c.mru(mycomp, &[1, 0, 2]);

    // --- Network -----------------------------------------------------------
    let net = c.child(
        bagmru,
        1,
        &build::root("f02c1a0d-be21-4350-88b0-7367fc96ef3c", 0x58),
        t(19, 2, 15, 0),
        None,
    );
    let srv = c.child(
        net,
        0,
        &build::network(0x42, "\\\\FILESRV01", None),
        t(19, 2, 15, 0),
        None,
    );
    let share = c.child(
        srv,
        0,
        &build::network(0xc3, "\\\\FILESRV01\\C$", Some("Microsoft Network")),
        t(19, 2, 15, 0),
        Some(GENERIC),
    );
    c.child(
        share,
        0,
        &build::dir(
            "Windows",
            fat(2020, 1, 1, 0, 0, 0),
            fat(2024, 3, 1, 0, 0, 0),
            2_316,
            1,
        ),
        t(19, 2, 15, 0),
        Some(GENERIC),
    );
    c.mru(share, &[0]);
    c.mru(srv, &[0]);
    let ts = c.child(
        net,
        1,
        &build::network(0xc3, "\\\\tsclient\\C", Some("Terminal Services")),
        t(17, 23, 1, 0),
        None,
    );
    c.child(
        ts,
        0,
        &build::dir(
            "Users",
            fat(2020, 1, 1, 0, 0, 0),
            fat(2024, 3, 1, 0, 0, 0),
            0,
            0,
        ),
        t(17, 23, 1, 0),
        None,
    );
    c.mru(ts, &[0]);
    c.mru(net, &[0, 1]);

    // --- Control panel -----------------------------------------------------
    let cp = c.child(
        bagmru,
        2,
        &build::root("26ee0668-a00a-44d7-9371-beb064c98683", 0x70),
        t(2, 8, 0, 0),
        None,
    );
    let cat = c.child(
        cp,
        0,
        &build::control_panel_category(5),
        t(2, 8, 0, 0),
        None,
    );
    c.child(
        cat,
        0,
        &build::control_panel_item("d9ef8727-cac2-4e60-809e-86f80a666c91"),
        t(2, 8, 0, 30),
        None,
    );
    c.mru(cat, &[0]);
    c.mru(cp, &[0]);

    // --- FTP ---------------------------------------------------------------
    c.child(
        bagmru,
        3,
        &build::uri("ftp://203.0.113.50/upload"),
        t(19, 23, 0, 0),
        None,
    );

    // Orphaned bag: subkey 7 without a value.
    let orphan = c.b.add_key(bagmru, "7", t(10, 7, 7, 7));
    c.b.add_dword(orphan, "NodeSlot", 77);

    c.mru(bagmru, &[3, 0, 1, 2]);
    c.b.build()
}

#[cfg(test)]
mod tests {
    #[test]
    fn demo_builds_and_parses() {
        let h = crate::regf::Hive::from_bytes(super::demo_usrclass()).unwrap();
        assert!(h.warnings.is_empty(), "{:?}", h.warnings);
    }
}
