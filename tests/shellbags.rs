//! End-to-end tests of BagMRU traversal, recovery and analysis using the
//! synthetic training hive and purpose-built hives.

use greybags::analysis::{self, AnalysisOptions};
use greybags::regf::writer::HiveBuilder;
use greybags::regf::Hive;
use greybags::shellbags::{
    scan_hive, scan_inputs, EntryStatus, HiveKind, ScanOptions, ShellBagEntry,
};
use greybags::shellitem::build;

fn demo_entries() -> Vec<ShellBagEntry> {
    let hive = Hive::from_bytes(greybags::demo::demo_usrclass()).unwrap();
    let (report, entries) = scan_hive(
        &hive,
        "/case/Users/jdoe/AppData/Local/Microsoft/Windows/UsrClass.dat",
        &ScanOptions::default(),
        0,
    );
    assert_eq!(report.kind, HiveKind::UsrClass);
    assert_eq!(report.user.as_deref(), Some("jdoe"));
    entries
}

fn find<'a>(entries: &'a [ShellBagEntry], fs: &str) -> &'a ShellBagEntry {
    entries
        .iter()
        .find(|e| e.fs_path.as_deref() == Some(fs))
        .unwrap_or_else(|| panic!("no entry with fs_path {fs}"))
}

#[test]
fn paths_and_mru_semantics() {
    let entries = demo_entries();
    let dl = find(&entries, "C:\\Users\\jdoe\\Downloads");
    assert_eq!(dl.absolute_path, "My Computer\\C:\\Users\\jdoe\\Downloads");
    assert_eq!(dl.mru_position, Some(0));
    // MRU 0 => last_interacted is the parent key's LastWrite.
    assert_eq!(dl.last_interacted, dl.parent_last_written);
    // Has children => last_explored is its own key LastWrite.
    assert!(dl.child_count >= 2);
    assert_eq!(dl.last_explored, dl.key_last_written);
    assert!(dl.first_interacted.is_none());

    let x64 = find(&entries, "C:\\Users\\jdoe\\Downloads\\mimikatz_trunk\\x64");
    assert_eq!(x64.child_count, 0);
    assert_eq!(x64.first_interacted, x64.key_last_written);
    assert_eq!(x64.item.mft_entry, Some(141_002));

    let zip = find(
        &entries,
        "C:\\Users\\jdoe\\Downloads\\Q1_payroll_export.zip",
    );
    assert_eq!(zip.mru_position, Some(1));
    assert!(zip.last_interacted.is_none());
    let inner = find(
        &entries,
        "C:\\Users\\jdoe\\Downloads\\Q1_payroll_export.zip\\payroll",
    );
    assert_eq!(
        inner.item.category,
        greybags::shellitem::Category::CompressedFolder
    );
}

#[test]
fn bags_correlation() {
    let entries = demo_entries();
    let dl = find(&entries, "C:\\Users\\jdoe\\Downloads");
    let bag = dl.bag.as_ref().expect("Downloads has a Bags entry");
    assert_eq!(Some(bag.slot), dl.node_slot);
    assert!(bag.folder_types.iter().any(|f| f.contains("Downloads")));
    assert_eq!(bag.view_mode.as_deref(), Some("Details"));
}

#[test]
fn network_paths() {
    let entries = demo_entries();
    let share = find(&entries, "\\\\FILESRV01\\C$");
    assert_eq!(share.absolute_path, "Network\\FILESRV01\\C$");
    let child = find(&entries, "\\\\FILESRV01\\C$\\Windows");
    assert_eq!(child.parent_id, Some(share.id));
    find(&entries, "\\\\tsclient\\C\\Users");
}

#[test]
fn deleted_and_orphaned_entries() {
    let entries = demo_entries();
    let secret = find(&entries, "C:\\SecretProject");
    assert_eq!(secret.status, EntryStatus::Recovered);
    assert!(secret.notes.iter().any(|n| n.contains("inferred")));
    let bp = find(&entries, "C:\\SecretProject\\blueprints");
    assert_eq!(bp.status, EntryStatus::Recovered);
    assert_eq!(bp.parent_id, Some(secret.id));
    assert_eq!(bp.mru_position, Some(0));
    assert!(entries
        .iter()
        .any(|e| e.status == EntryStatus::Orphaned && e.value_name == "7"));

    // Recovery can be disabled.
    let hive = Hive::from_bytes(greybags::demo::demo_usrclass()).unwrap();
    let opts = ScanOptions {
        recover_deleted: false,
        ..Default::default()
    };
    let (_, live) = scan_hive(&hive, "x", &opts, 0);
    assert!(live.iter().all(|e| e.status != EntryStatus::Recovered));
}

#[test]
fn analysis_flags_planted_artifacts() {
    let hive = Hive::from_bytes(greybags::demo::demo_usrclass()).unwrap();
    let (report, entries) = scan_hive(&hive, "demo", &ScanOptions::default(), 0);
    let scan = greybags::shellbags::ScanResult {
        hives: vec![report],
        entries,
        errors: vec![],
    };
    let an = analysis::analyze(
        &scan,
        &AnalysisOptions {
            include_timeline: true,
            ..Default::default()
        },
    );
    let rules: Vec<&str> = an.findings.iter().map(|f| f.rule).collect();
    for expected in [
        "network.admin_share",
        "network.rdp_drive_redirection",
        "volume.non_system",
        "device.mtp",
        "remote.ftp",
        "content.archive_browsing",
        "integrity.recovered_entries",
        "integrity.orphaned_bags",
        "time.target_after_key",
        "watchlist.match",
        "location.temp",
    ] {
        assert!(
            rules.contains(&expected),
            "missing finding {expected}; got {rules:?}"
        );
    }
    let mtp = an.findings.iter().find(|f| f.rule == "device.mtp").unwrap();
    assert!(mtp.rationale.contains("9A221FFAZ003TX"));
    // Timeline is sorted.
    assert!(an
        .timeline
        .windows(2)
        .all(|w| w[0].timestamp <= w[1].timestamp));
    assert!(an.summary.volumes.iter().any(|v| v.volume == "E:"));
}

#[test]
fn whole_bagmru_tree_deleted() {
    // Simulates a privacy cleaner deleting BagMRU entirely: the tree only
    // survives in unallocated cells under the live ...\Shell key.
    let t = 133_500_000_000_000_000u64;
    let mut b = HiveBuilder::new("ROOT", t);
    let mut k = HiveBuilder::ROOT;
    for name in [
        "Local Settings",
        "Software",
        "Microsoft",
        "Windows",
        "Shell",
    ] {
        k = b.add_key(k, name, t);
    }
    let bagmru = b.add_key(k, "BagMRU", t + 1);
    let mut v = build::my_computer();
    v.extend_from_slice(&[0, 0]);
    b.add_binary(bagmru, "0", &v);
    b.add_binary(bagmru, "MRUListEx", &build::mru_list_ex(&[0]));
    let mc = b.add_key(bagmru, "0", t + 2);
    let mut d = build::volume("F:\\");
    d.extend_from_slice(&[0, 0]);
    b.add_binary(mc, "0", &d);
    b.delete_key(bagmru);
    let hive = Hive::from_bytes(b.build()).unwrap();
    assert!(hive
        .open_key("Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU")
        .unwrap()
        .is_none());
    let (_, entries) = scan_hive(&hive, "x", &ScanOptions::default(), 0);
    let paths: Vec<&str> = entries.iter().map(|e| e.absolute_path.as_str()).collect();
    assert!(paths.contains(&"My Computer"), "{paths:?}");
    assert!(paths.contains(&"My Computer\\F:"), "{paths:?}");
    assert!(entries.iter().all(|e| e.status == EntryStatus::Recovered));
    assert!(entries[0].location.ends_with("(deleted)"));
}

#[test]
fn directory_discovery_and_dedupe() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir
        .path()
        .join("Users/jdoe/AppData/Local/Microsoft/Windows");
    std::fs::create_dir_all(&a).unwrap();
    std::fs::write(a.join("UsrClass.dat"), greybags::demo::demo_usrclass()).unwrap();
    // Same hive from a "shadow copy", plus a decoy log file and a non-hive.
    let vsc = dir
        .path()
        .join("vss1/Users/jdoe/AppData/Local/Microsoft/Windows");
    std::fs::create_dir_all(&vsc).unwrap();
    std::fs::write(vsc.join("UsrClass.dat"), greybags::demo::demo_usrclass()).unwrap();
    std::fs::write(vsc.join("UsrClass.dat.LOG1"), b"not a hive").unwrap();
    std::fs::write(dir.path().join("ntuser.txt"), b"hello").unwrap();

    let r = scan_inputs(&[dir.path().to_path_buf()], &ScanOptions::default());
    assert_eq!(r.hives.len(), 2, "{:?}", r.errors);
    let n = r.entries.len();
    let rd = scan_inputs(
        &[dir.path().to_path_buf()],
        &ScanOptions {
            dedupe: true,
            ..Default::default()
        },
    );
    assert_eq!(rd.entries.len(), n / 2);
    assert!(r.entries.iter().all(|e| e.user.as_deref() == Some("jdoe")));
    // Ids are unique across hives.
    let mut ids: Vec<usize> = r.entries.iter().map(|e| e.id).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), n);
}

#[test]
fn dirty_hive_with_and_without_logs() {
    // A dirty primary (sequence mismatch) with no logs is still parsed, but warns.
    let mut b = HiveBuilder::new("ROOT", 133_000_000_000_000_000).sequence(5, 4);
    b.add_key(HiveBuilder::ROOT, "Software", 133_000_000_000_000_000);
    let hive = Hive::from_bytes_with_logs(b.build(), vec![], true).unwrap();
    assert!(hive.was_dirty);
    assert!(hive
        .warnings
        .iter()
        .any(|w| w.contains("no transaction logs")));
    assert!(hive.open_key("Software").unwrap().is_some());
}
