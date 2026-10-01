//! Shell item dissector tests.
//!
//! The `real_*` fixtures are verbatim BagMRU values from the public plaso /
//! dfwinreg test hives (Windows XP and Windows 7 NTUSER.DAT, Windows 8.1
//! UsrClass.dat). The `built_*` tests round-trip items produced by
//! `shellitem::build` for types absent from those hives.

use greybags::shellitem::{build, parse_item, parse_list, Category, ParseOptions};
use greybags::util::bytes::from_hex;

fn opts() -> ParseOptions {
    ParseOptions {
        dissect: true,
        ..Default::default()
    }
}

fn one(hex: &str) -> greybags::shellitem::ShellItem {
    let raw = from_hex(hex).unwrap();
    let list = parse_list(&raw, &opts());
    assert_eq!(list.len(), 1, "expected exactly one item");
    list.into_iter().next().unwrap()
}

#[test]
fn real_my_computer_root() {
    let it = one("14001f50e04fd020ea3a6910a2d808002b30309d0000");
    assert_eq!(it.category, Category::RootFolder);
    assert_eq!(it.name, "My Computer");
    assert_eq!(
        it.guid.unwrap().to_string(),
        "20d04fe0-3aea-1069-a2d8-08002b30309d"
    );
}

#[test]
fn real_xp_volume() {
    let it = one("19002f433a5c0000000000000000000000000000000000000000000000");
    assert_eq!(it.category, Category::Volume);
    assert_eq!(it.name, "C:\\");
    assert_eq!(it.drive_letter(), Some('C'));
    assert_eq!(it.segment(), "C:");
}

#[test]
fn real_xp_file_entry_with_user_name_block() {
    let it = one("6e00310000000000ff3af3a211004d59444f43557e310000300003000400efbe4b371266043b4f79140000004d007900200044006f00630075006d0065006e007400730000001800260005000600efbe410064006d0069006e006900730074007200610074006f007200000018000000");
    assert_eq!(it.category, Category::Directory);
    assert_eq!(it.short_name.as_deref(), Some("MYDOCU~1"));
    assert_eq!(it.long_name.as_deref(), Some("My Documents"));
    assert_eq!(it.name, "My Documents");
    assert_eq!(it.ext_version, Some(3));
    assert_eq!(it.modified.unwrap().to_iso(), "2009-07-31T20:23:38Z");
    assert_eq!(it.created.unwrap().to_iso(), "2007-10-11T12:48:36Z");
    assert_eq!(it.accessed.unwrap().to_iso(), "2009-08-04T15:10:30Z");
    assert_eq!(it.detail("ext_user_name"), Some("Administrator"));
    assert_eq!(it.extension_blocks.len(), 2);
    // Every byte of the 0x6e-byte item is covered by a dissected field.
    let covered: usize = it
        .fields
        .iter()
        .filter(|f| f.size > 0)
        .map(|f| f.size)
        .sum();
    assert!(covered >= 0x6e - 2, "covered {covered}");
}

#[test]
fn real_win8_property_view_wallpaper() {
    let it = one("03010000fd0000eeebbeef000400010000004900000031535053537def0c64fad111a2030000f81fedee2d00000005000000001f0000000e0000007000610067006500570061006c006c0070006100700065007200000000000000550000003153505330f125b7ef471a10a5f102608c9eebac390000000a000000001f000000130000004400650073006b0074006f00700020004200610063006b00670072006f0075006e00640000000000000000004d000000315350538727bf5ccf480842b90eee5e5d4202943100000019000000001f000000100000007400680065006d006500630070006c002e0064006c006c002c002d0031000000000000000000000000000000");
    assert_eq!(it.category, Category::UsersPropertyView);
    assert_eq!(it.name, "Desktop Background");
    assert_eq!(it.properties.len(), 3);
}

#[test]
fn real_win7_property_view_and_webdav_share() {
    let it = one("b7000000b100bbaf933ba300040000000000450000003153505330f125b7ef471a10a5f102608c9eebac290000000a000000001f0000000b00000063006f006e00740072006f006c006c006500720000000000000000002d000000315350533aa4bddeb337834391e74498da2995ab1100000003000000001300000000000000000000002d000000315350537343e50abe43ad4f85e469dc8633986e110000000b000000000b000000ffff0000000000000000000000000000");
    assert_eq!(it.name, "controller");
    let share = one("3300c301c15c5c636f6e74726f6c6c65725c5765624461765368617265004d6963726f736f6674204e6574776f726b000002000000");
    assert_eq!(share.category, Category::NetworkLocation);
    assert_eq!(share.type_name, "Network share");
    assert_eq!(share.name, "\\\\controller\\WebDavShare");
    assert_eq!(share.detail("description"), Some("Microsoft Network"));
}

#[test]
fn real_win8_volume_guid_and_control_panel() {
    let it = one("14002e805316dd3a32ebb04cbbd7dfa0abb5acca0000");
    assert_eq!(it.category, Category::Volume);
    assert_eq!(it.name, "Pictures");
    let cat = one("0c0001008421de39010000000000");
    assert_eq!(cat.category, Category::ControlPanelCategory);
    assert_eq!(cat.name, "Appearance and Personalization");
    let cpi = one("1e00718000000000000000000000d64e83ed5a4bfe4b8f11a626dcb6a9210000");
    assert_eq!(cpi.category, Category::ControlPanelItem);
    assert_eq!(cpi.name, "Personalization");
}

#[test]
fn built_win10_directory_with_mft_reference() {
    let raw = build::file_entry(&build::FileEntry {
        long_name: "Quarterly Reports 2024",
        short_name: "QUARTE~1",
        is_dir: true,
        file_size: 0,
        modified: build::fat(2024, 3, 1, 10, 0, 0),
        created: build::fat(2024, 2, 28, 9, 30, 10),
        accessed: build::fat(2024, 3, 1, 10, 0, 0),
        mft_entry: 123_456,
        mft_seq: 7,
        attributes: 0x10,
    });
    let it = parse_item(&raw, &opts(), None);
    assert_eq!(it.name, "Quarterly Reports 2024");
    assert_eq!(it.short_name.as_deref(), Some("QUARTE~1"));
    assert_eq!((it.mft_entry, it.mft_sequence), (Some(123_456), Some(7)));
    assert_eq!(it.ext_version, Some(9));
    assert_eq!(it.created.unwrap().to_iso(), "2024-02-28T09:30:10Z");
}

#[test]
fn built_zip_contents_needs_archive_parent() {
    let list = build::list(&[
        build::dir(
            "evidence.zip",
            build::fat(2024, 1, 1, 0, 0, 0),
            build::fat(2024, 1, 1, 0, 0, 0),
            5,
            1,
        ),
        build::zip_item("payload", "06/15/2021  18:24:28"),
    ]);
    let items = parse_list(&list, &opts());
    assert_eq!(items.len(), 2);
    assert_eq!(items[1].category, Category::CompressedFolder);
    assert_eq!(items[1].name, "payload");
    assert_eq!(
        items[1].detail("zip_modified"),
        Some("06/15/2021  18:24:28")
    );
}

#[test]
fn built_uri_and_network_server() {
    let it = parse_item(&build::uri("ftp://files.example.org/pub"), &opts(), None);
    assert_eq!(it.category, Category::Uri);
    assert_eq!(it.name, "ftp://files.example.org/pub");
    let srv = parse_item(&build::network(0x42, "\\\\FILESRV01", None), &opts(), None);
    assert_eq!(srv.type_name, "Network server");
    assert_eq!(srv.name, "\\\\FILESRV01");
}

#[test]
fn built_mtp_volume() {
    let it = parse_item(
        &build::mtp_volume(
            "Internal storage",
            "\\\\?\\usb#vid_04e8&pid_6860#R58M12ABCDE#{6ac27878-a6fa-4155-ba85-f98f491d4f33}",
            "FAT32",
        ),
        &opts(),
        None,
    );
    assert_eq!(it.category, Category::MtpDevice);
    assert_eq!(it.name, "Internal storage");
    assert_eq!(it.detail("device_serial"), Some("R58M12ABCDE"));
    assert_eq!(it.detail("file_system"), Some("FAT32"));
}

#[test]
fn built_users_files_delegate() {
    let it = parse_item(
        &build::users_files_delegate("Projects", build::fat(2023, 5, 6, 7, 8, 10), 4242, 3),
        &opts(),
        None,
    );
    assert_eq!(it.category, Category::Directory);
    assert_eq!(it.name, "Projects");
    assert!(it.type_name.contains("Users Files"), "{}", it.type_name);
    assert_eq!(it.mft_entry, Some(4242));
}

#[test]
fn garbage_never_panics() {
    // Deterministic pseudo-random fuzzing of the dispatcher.
    let mut seed: u32 = 0x1234_5678;
    for len in 0..300usize {
        let mut v = Vec::with_capacity(len);
        for _ in 0..len {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            v.push(seed as u8);
        }
        if len >= 2 {
            v[0] = len as u8;
            v[1] = (len >> 8) as u8;
        }
        for class in [0x00u8, 0x1f, 0x2f, 0x31, 0x42, 0x52, 0x61, 0x71, 0x74] {
            if len > 2 {
                v[2] = class;
            }
            let _ = parse_list(&v, &opts());
        }
    }
}
