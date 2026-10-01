//! Lookup tables for GUIDs and identifiers that appear in shell items.
//!
//! Sources: libfwsi/libfwps documentation, Microsoft KNOWNFOLDERID and shell
//! namespace documentation. Unknown identifiers are rendered verbatim, so a
//! missing entry never hides data — it only means the analyst sees the GUID.

use super::guid::Guid;

/// Delegate item class identifier (`CLSID_DelegateItem`).
pub const DELEGATE_ITEM_CLSID: &str = "5e591a74-df96-48d3-8d67-1733bcee28ba";
/// CUri class used by extension block 0xbeef0014.
pub const CURI_CLSID: &str = "df2fce13-25ec-45bb-9d4c-cecd47c2430c";

/// Shell folder / namespace CLSIDs as used by root folder (0x1f), volume
/// (0x2e) and delegate shell items.
pub fn shell_folder(g: &Guid) -> Option<&'static str> {
    let s = g.to_string();
    Some(match s.as_str() {
        "20d04fe0-3aea-1069-a2d8-08002b30309d" => "My Computer",
        "450d8fba-ad25-11d0-98a8-0800361b1103" => "My Documents",
        "208d2c60-3aea-1069-a2d7-08002b30309d" => "My Network Places",
        "f02c1a0d-be21-4350-88b0-7367fc96ef3c" => "Network",
        "645ff040-5081-101b-9f08-00aa002f954e" => "Recycle Bin",
        "21ec2020-3aea-1069-a2dd-08002b30309d" => "Control Panel",
        "26ee0668-a00a-44d7-9371-beb064c98683" => "Control Panel (category view)",
        "5399e694-6ce5-4d6c-8fce-1d8870fdcba0" => "Control Panel command object",
        "2227a280-3aea-1069-a2de-08002b30309d" => "Printers",
        "871c5380-42a0-1069-a2ea-08002b30309d" => "Internet Explorer",
        "59031a47-3f72-44a7-89c5-5595fe6b30ee" => "Users Files",
        "031e4825-7b94-4dc3-b131-e946b44c8dd5" => "Libraries",
        "1cf1260c-4dd0-4ebb-811f-33c572699fde" => "Music",
        "3add1653-eb32-4cb0-bbd7-dfa0abb5acca" => "Pictures",
        "a0953c92-50dc-43bf-be83-3742fed03c9c" => "Videos",
        "a8cdff1c-4878-43be-b5fd-f8091c1c60d0" => "Documents",
        "374de290-123f-4565-9164-39c4925e467b" => "Downloads",
        "b4bfcc3a-db2c-424c-b029-7fe99a87c641" => "Desktop",
        "0db7e03f-fc29-4dc6-9020-ff41b59e513a" => "3D Objects",
        "d3162b92-9365-467a-956b-92703aca08af" => "Documents",
        "088e3905-0323-4b02-9826-5d99428e115f" => "Downloads",
        "24ad3ad4-a569-4530-98e1-ab02f9417aa8" => "Pictures",
        "3dfdf296-dbec-4fb4-81d1-6a3438bcf4de" => "Music",
        "f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a" => "Videos",
        "679f85cb-0220-4080-b29b-5540cc05aab6" => "Quick access",
        "f874310e-b6b7-47dc-bc84-b9e6b38f5903" => "Home",
        "018d5c66-4533-4307-9b53-224de2ed1fe6" => "OneDrive",
        "e31ea727-12ed-4702-820c-4b6445f92e1d" => "Dropbox",
        "9e3995ab-1f9c-4f13-b827-48b24b6c7174" => "User Pinned",
        "4234d49b-0245-4df3-b780-3893943456e1" => "Applications",
        "5e6c858f-0e22-4760-9afe-ea3317b67173" => "User profile",
        "22877a6d-37a1-461a-91b0-dbda5aaebc99" => "Recent Places",
        "323ca680-c24d-4099-b94d-446dd2d7249e" => "Favorites",
        "4336a54d-038b-4685-ab02-99bb52d3fb8b" => "Public",
        "9343812e-1c37-4a49-a12e-4b2d810d956b" => "Search Home",
        "04731b67-d933-450a-90e6-4acd2e9408fe" => "Search Folder",
        "2965e715-eb66-4719-b53f-1672673bbefa" => "Search Results",
        "e17d4fc0-5564-11d1-83f2-00a0c90dc849" => "Search Results",
        "1f4de370-d627-11d1-ba4f-00a0c91eedba" => "Search Results - Computers",
        "d20ea4e1-3957-11d2-a40b-0c5020524153" => "Administrative Tools",
        "d20ea4e1-3957-11d2-a40b-0c5020524152" => "Fonts",
        "7007acc7-3202-11d1-aad2-00805fc1270e" => "Network Connections",
        "992cffa0-f557-101a-88ec-00dd010ccc48" => "Network Connections",
        "4026492f-2f69-46b8-b9bf-5654fc07e423" => "Windows Firewall",
        "78f3955e-3b90-4184-bd14-5397c15f1efc" => "Performance Information and Tools",
        "bb06c0e4-d293-4f75-8a90-cb05b6477eee" => "System",
        "a8a91a66-3a7d-4424-8d24-04e180695c7a" => "Devices and Printers",
        "36eef7db-88ad-4e81-ad49-0e313f0c35f8" => "Windows Update",
        "60632754-c523-4b62-b45c-4172da012619" => "User Accounts",
        "9c60de1e-e5fc-40f4-a487-460851a8d915" => "AutoPlay",
        "7b81be6a-ce2b-4676-a29e-eb907a5126c5" => "Programs and Features",
        "d555645e-d4f8-4c29-a827-d93c859c4f2a" => "Ease of Access Center",
        "8e908fc9-becc-40f6-915b-f4ca0e70d03d" => "Network and Sharing Center",
        "c58c4893-3be0-4b45-abb5-a63e4b8c8651" => "Troubleshooting",
        "025a5937-a6be-4686-a844-36fe4bec8b6d" => "Power Options",
        "e2e7934b-dce5-43c4-9576-7fe4f75e7480" => "Date and Time",
        "bb64f8a7-bee7-4e1a-ab8d-7d8273f7fdb6" => "Security and Maintenance",
        "17cd9488-1228-4b2f-88ce-4298e93e0966" => "Default Programs",
        "15eae92e-f17a-4431-9f28-805e482dafd4" => "Get Programs",
        "5ea4f148-308c-46d7-98a9-49041b1dd468" => "Windows Mobility Center",
        "b98a2bea-7d42-4558-8bd1-832f41bac6fd" => "Backup and Restore",
        "9c73f5e5-7ae7-4e32-a8e8-8d23b85255bf" => "Sync Center",
        "289af617-1cc3-42a6-926c-e6a863f0e3ba" => "DLNA Media Servers",
        "35786d3c-b075-49b9-88dd-029876e11c01" => "Portable Devices",
        "640167b4-59b0-47a6-b335-a6b3c0695aea" => "Portable Media Devices",
        "b155bdf8-02f0-451e-9a26-ae317cfd7779" => "Nethood",
        "dffacdc5-679f-4156-8947-c5c76bc0b67f" => "Users Files (delegate)",
        "f5fb2c77-0e2f-4a16-a381-3e560c68bc83" => "Removable Drives",
        "896664f7-12e1-490f-8782-c0835afd98fc" => "Libraries (delegate)",
        "9113a02d-00a3-46b9-bc5f-9c04daddd5d7" => "Enhanced Storage Data Source",
        "9db7a13c-f208-4981-8353-73cc61ae2783" => "Previous Versions",
        "3134ef9c-6b18-4996-ad04-ed5912e00eb5" => "Recent Files",
        "3936e9e4-d92c-4eee-a85a-bc16d5ea0819" => "Frequent Places",
        "d34a6ca6-62c2-4c34-8a7c-14709c1ad938" => "Common Places",
        "ed50fc29-b964-48a9-afb3-15ebb9b97f36" => "Printhood",
        "c2b136e2-d50e-405c-8784-363c582bf43e" => "Wireless Devices",
        "ed228fdf-9ea8-4870-83b1-96b02cfe0d52" => "My Games",
        "b28aa736-876b-46da-b3a8-84c5e30ba492" => "Web Sites",
        "bdeadf00-c265-11d0-bced-00a0c90ab50f" => "Web Folders",
        "f3364ba0-65b9-11ce-a9ba-00aa004ae837" => "Shell File System Folder",
        "0afaced1-e828-11d1-9187-b532f1e9575d" => "Folder Shortcut",
        "85bbd920-42a0-1069-a2e4-08002b30309d" => "Briefcase",
        "e211b736-43fd-11d1-9efb-0000f8757fcd" => "Scanners and Cameras",
        "6dfd7c5c-2451-11d3-a299-00c04f8ef6af" => "Folder Options",
        "0df44eaa-ff21-4412-828e-260a8728e7f1" => "Taskbar and Start Menu",
        "78cb147a-98ea-4aa6-b0df-c8681f69341c" => "Windows CardSpace",
        "d6277990-4c6a-11cf-8d87-00aa0060f5bf" => "Scheduled Tasks",
        "5e591a74-df96-48d3-8d67-1733bcee28ba" => "Delegate folder item",
        "0bd8e793-d371-11d1-b0b5-0060972919d7" => "SolidWorks Enterprise PDM",
        // Known folder identifiers also appear as namespace roots on Win10+.
        "0ac0837c-bbf8-452a-850d-79d08e667ca7" => "Computer",
        "d20beec4-5ca8-4905-ae3b-bf251ea09b53" => "Network",
        "82a74aeb-aeb4-465c-a014-d097ee346d63" => "Control Panel",
        "1e87508d-89c2-42f0-8a7e-645a0f50ca58" => "Applications",
        "a52bba46-e9e1-435f-b3d9-28daa648c0f6" => "OneDrive",
        _ => return known_folder(g),
    })
}

/// KNOWNFOLDERID values (used by users property view items, signature
/// 0x23febbee, and by some namespace roots).
pub fn known_folder(g: &Guid) -> Option<&'static str> {
    let s = g.to_string();
    Some(match s.as_str() {
        "b4bfcc3a-db2c-424c-b029-7fe99a87c641" => "Desktop",
        "fdd39ad0-238f-46af-adb4-6c85480369c7" => "Documents",
        "374de290-123f-4565-9164-39c4925e467b" => "Downloads",
        "4bd8d571-6d19-48d3-be97-422220080e43" => "Music",
        "33e28130-4e1e-4676-835a-98395c3bc3bb" => "Pictures",
        "18989b1d-99b5-455b-841c-ab7c74e4ddfc" => "Videos",
        "5e6c858f-0e22-4760-9afe-ea3317b67173" => "User profile",
        "dfdf76a2-c82a-4d63-906a-5644ac457385" => "Public",
        "a52bba46-e9e1-435f-b3d9-28daa648c0f6" => "OneDrive",
        "4c5c32ff-bb9d-43b0-b5b4-2d72e54eaaa4" => "Saved Games",
        "bfb9d5e0-c6a9-404c-b2b2-ae6db6af4968" => "Links",
        "1777f761-68ad-4d8a-87bd-30b759fa33dd" => "Favorites",
        "56784854-c6cb-462b-8169-88e350acb882" => "Contacts",
        "7d1d3a04-debb-4115-95cf-2f29da2920da" => "Searches",
        "b7534046-3ecb-4c18-be4e-64cd4cb7d6ac" => "Recycle Bin",
        "0ac0837c-bbf8-452a-850d-79d08e667ca7" => "Computer",
        "d20beec4-5ca8-4905-ae3b-bf251ea09b53" => "Network",
        "82a74aeb-aeb4-465c-a014-d097ee346d63" => "Control Panel",
        "0762d272-c50a-4bb0-a382-697dcd729b80" => "Users",
        "f38bf404-1d43-42f2-9305-67de0b28fc23" => "Windows",
        "1ac14e77-02e7-4e5d-b744-2eb1ae5198b7" => "System32",
        "905e63b6-c1bf-494e-b29c-65b732d3d21a" => "Program Files",
        "62ab5d82-fdc1-4dc3-a9dd-070d1d495d97" => "ProgramData",
        "f1b32785-6fba-4fcf-9d55-7b8e7f157091" => "AppData\\Local",
        "3eb685db-65f9-4cf6-a03a-e3ef65729f3d" => "AppData\\Roaming",
        "a520a1a4-1780-4ff6-bd18-167343c5af16" => "AppData\\LocalLow",
        "ae50c081-ebd2-438a-8655-8a092e34987a" => "Recent Items",
        "625b53c3-ab48-4ec1-ba1f-a1ef4146fc19" => "Start Menu",
        "b97d20bb-f46a-4c97-ba10-5e3608430854" => "Startup",
        "a63293e8-664e-48db-a079-df759e0509f7" => "Templates",
        "ab5fb87b-7ce2-4f83-915d-550846c9537b" => "Camera Roll",
        "b7bede81-df94-4682-a7d8-57a52620b86f" => "Screenshots",
        "1b3ea5dc-b587-4786-b4ef-bd1dc332aeae" => "Libraries",
        "f3ce0f7c-4901-4acc-8648-d5d44b04ef8f" => "Users Files",
        "52528a6b-b9e3-4add-b60d-588c2dba842d" => "HomeGroup",
        "1e87508d-89c2-42f0-8a7e-645a0f50ca58" => "Applications",
        "ed4824af-dce4-45a8-81e2-fc7965083634" => "Public Documents",
        "3d644c9b-1fb8-4f30-9b45-f670235f79c0" => "Public Downloads",
        "31c0dd25-9439-4f12-bf41-7ff4eda38722" => "3D Objects",
        "7b0db17d-9cd2-4a93-9733-46cc89022e7c" => "Documents Library",
        "2112ab0a-c86a-4ffe-a368-0de96e47012e" => "Music Library",
        "a990ae9f-a03b-4e80-94bc-9912d7504104" => "Pictures Library",
        "491e922f-5643-4af4-a7eb-4e7a138d8174" => "Videos Library",
        _ => return None,
    })
}

/// Folder type identifiers (Bags\<n>\Shell\{GUID}, extension block 0xbeef0019).
pub fn folder_type(g: &Guid) -> Option<&'static str> {
    let s = g.to_string();
    Some(match s.as_str() {
        "5c4f28b5-f869-4e84-8e60-f11db97c5cc7" => "Generic",
        "7d49d726-3c21-4f05-99aa-fdc2c9474656" => "Documents",
        "b3690e58-e961-423b-b687-386ebfd83239" => "Pictures",
        "94d6ddcc-4a68-4175-a374-bd584a510b78" => "Music",
        "5fa96407-7e77-483c-ac93-691d05850de8" => "Videos",
        "885a186e-a440-4ada-812b-db871b942259" => "Downloads",
        "de2b70ec-9bf7-4a93-bd3d-243f7881d492" => "Contacts",
        "fbb3477e-c9e4-4b3b-a2ba-d3f5d3cd46f9" => "Documents Library",
        "0b2baaeb-0042-4dca-aa4d-3ee8648d03e5" => "Pictures Library",
        "3f2a72a7-99fa-4ddb-a5a8-c604edf61d6b" => "Music Library",
        "631958a6-ad0f-4035-a745-28ac066dc6ed" => "Videos Library",
        "7fde1a1e-8b31-49a5-93b8-6be14cfa4943" => "Search Results",
        _ => return None,
    })
}

/// Control panel category identifiers (0x01 shell item, signature 0x39de2184).
pub fn control_panel_category(id: u32) -> Option<&'static str> {
    Some(match id {
        0 => "All Control Panel Items",
        1 => "Appearance and Personalization",
        2 => "Hardware and Sound",
        3 => "Network and Internet",
        4 => "Sounds, Speech, and Audio Devices",
        5 => "System and Security",
        6 => "Clock, Language, and Region",
        7 => "Ease of Access",
        8 => "Programs",
        9 => "User Accounts",
        10 => "Security Center",
        11 => "Mobile PC",
        _ => return None,
    })
}

/// Root folder sort index meanings (libfwsi).
pub fn sort_index(v: u8) -> Option<&'static str> {
    Some(match v {
        0x00 => "Internet Explorer",
        0x42 => "Libraries",
        0x44 => "Users",
        0x48 => "My Documents",
        0x50 => "My Computer",
        0x58 => "My Network Places/Network",
        0x60 => "Recycle Bin",
        0x68 => "Internet Explorer",
        0x70 => "Unknown (0x70)",
        0x80 => "My Games",
        _ => return None,
    })
}

/// Canonical names for serialized property store keys (FMTID, PID).
pub fn property_name(fmtid: &Guid, pid: u32) -> Option<&'static str> {
    let s = fmtid.to_string();
    Some(match (s.as_str(), pid) {
        ("b725f130-47ef-101a-a5f1-02608c9eebac", 2) => "System.ItemFolderNameDisplay",
        ("b725f130-47ef-101a-a5f1-02608c9eebac", 4) => "System.ItemTypeText",
        ("b725f130-47ef-101a-a5f1-02608c9eebac", 10) => "System.ItemNameDisplay",
        ("b725f130-47ef-101a-a5f1-02608c9eebac", 12) => "System.Size",
        ("b725f130-47ef-101a-a5f1-02608c9eebac", 13) => "System.FileAttributes",
        ("b725f130-47ef-101a-a5f1-02608c9eebac", 14) => "System.DateModified",
        ("b725f130-47ef-101a-a5f1-02608c9eebac", 15) => "System.DateCreated",
        ("b725f130-47ef-101a-a5f1-02608c9eebac", 16) => "System.DateAccessed",
        ("28636aa6-953d-11d2-b5d6-00c04fd918d0", 2) => "System.DescriptionID",
        ("28636aa6-953d-11d2-b5d6-00c04fd918d0", 5) => "System.ComputerName",
        ("28636aa6-953d-11d2-b5d6-00c04fd918d0", 11) => "System.ItemType",
        ("28636aa6-953d-11d2-b5d6-00c04fd918d0", 24) => "System.ParsingName",
        ("28636aa6-953d-11d2-b5d6-00c04fd918d0", 25) => "System.SFGAOFlags",
        ("28636aa6-953d-11d2-b5d6-00c04fd918d0", 30) => "System.ParsingPath",
        ("e3e0584c-b788-4a5a-bb20-7f5a44c9acdd", 6) => "System.ItemFolderPathDisplay",
        ("e3e0584c-b788-4a5a-bb20-7f5a44c9acdd", 7) => "System.ItemPathDisplay",
        ("446d16b1-8dad-4870-a748-402ea43d788c", 104) => "System.VolumeId",
        ("9f4c2855-9f79-4b39-a8d0-e1d42de1d5f3", 5) => "System.AppUserModel.ID",
        ("f29f85e0-4ff9-1068-ab91-08002b27b3d9", 2) => "System.Title",
        ("f29f85e0-4ff9-1068-ab91-08002b27b3d9", 3) => "System.Subject",
        ("f29f85e0-4ff9-1068-ab91-08002b27b3d9", 4) => "System.Author",
        ("f29f85e0-4ff9-1068-ab91-08002b27b3d9", 5) => "System.Keywords",
        ("f29f85e0-4ff9-1068-ab91-08002b27b3d9", 6) => "System.Comment",
        ("ef6b490d-5cd8-437a-affc-da8b60ee4a3c", 2) => "WPD_OBJECT_ID",
        ("ef6b490d-5cd8-437a-affc-da8b60ee4a3c", 3) => "WPD_OBJECT_PARENT_ID",
        ("ef6b490d-5cd8-437a-affc-da8b60ee4a3c", 4) => "WPD_OBJECT_NAME",
        ("ef6b490d-5cd8-437a-affc-da8b60ee4a3c", 5) => "WPD_OBJECT_PERSISTENT_UNIQUE_ID",
        ("ef6b490d-5cd8-437a-affc-da8b60ee4a3c", 6) => "WPD_OBJECT_FORMAT",
        ("ef6b490d-5cd8-437a-affc-da8b60ee4a3c", 7) => "WPD_OBJECT_CONTENT_TYPE",
        ("ef6b490d-5cd8-437a-affc-da8b60ee4a3c", 12) => "WPD_OBJECT_ORIGINAL_FILE_NAME",
        ("ef6b490d-5cd8-437a-affc-da8b60ee4a3c", 18) => "WPD_OBJECT_DATE_CREATED",
        ("ef6b490d-5cd8-437a-affc-da8b60ee4a3c", 19) => "WPD_OBJECT_DATE_MODIFIED",
        ("01a3057a-74d6-4e80-bea7-dc4c212ce50a", 2) => "WPD_STORAGE_TYPE",
        ("01a3057a-74d6-4e80-bea7-dc4c212ce50a", 3) => "WPD_STORAGE_FILE_SYSTEM_TYPE",
        ("01a3057a-74d6-4e80-bea7-dc4c212ce50a", 4) => "WPD_STORAGE_CAPACITY",
        ("01a3057a-74d6-4e80-bea7-dc4c212ce50a", 5) => "WPD_STORAGE_FREE_SPACE_IN_BYTES",
        ("01a3057a-74d6-4e80-bea7-dc4c212ce50a", 7) => "WPD_STORAGE_DESCRIPTION",
        ("01a3057a-74d6-4e80-bea7-dc4c212ce50a", 8) => "WPD_STORAGE_SERIAL_NUMBER",
        _ => return None,
    })
}

/// Logical view mode stored in Bags\<n>\Shell\{GUID}\LogicalViewMode.
pub fn logical_view_mode(v: u32) -> Option<&'static str> {
    Some(match v {
        1 => "Details",
        2 => "Tiles",
        3 => "Icons",
        4 => "List",
        5 => "Content",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookups() {
        let g = Guid::parse("20d04fe0-3aea-1069-a2d8-08002b30309d").unwrap();
        assert_eq!(shell_folder(&g), Some("My Computer"));
        // falls through to known folders
        let g = Guid::parse("fdd39ad0-238f-46af-adb4-6c85480369c7").unwrap();
        assert_eq!(shell_folder(&g), Some("Documents"));
        assert_eq!(control_panel_category(5), Some("System and Security"));
    }
}
