# ShellBags: analyst reference

This document explains what greybags parses and how to interpret it. It is
written for analysts in training as well as experienced examiners; every
claim about Windows behaviour below is the commonly documented behaviour —
always validate against your own test data for the Windows build in question.

## What ShellBags are

Windows Explorer remembers how each folder was displayed (icon size, sort
order, window position). To key those view settings it stores the folder's
**shell item ID list** (PIDL) in the registry. Because an entry is created
when a folder is opened in Explorer (or in a common Open/Save dialog), the
stored PIDLs are a durable record of folder access, including:

* folders on removable media, network shares and mapped drives;
* folders inside ZIP archives;
* portable devices (phones/cameras over MTP), control panel applets, FTP sites;
* folders that **no longer exist** — ShellBags are not cleaned up when the
  folder is deleted.

ShellBags record *folders*, not files. Opening a file does not create one
for the file itself (see LNK files and JumpLists for that).

## Where they live

| Windows | Hive | Key (relative to hive root) |
|---|---|---|
| XP / 2003 | NTUSER.DAT | `Software\Microsoft\Windows\ShellNoRoam\BagMRU` and `...\Bags` |
| XP / 2003 | NTUSER.DAT | `Software\Microsoft\Windows\Shell\BagMRU` (network/remote folders) |
| Vista+ | UsrClass.dat | `Local Settings\Software\Microsoft\Windows\Shell\BagMRU` and `...\Bags` |
| Vista+ | UsrClass.dat | `Wow6432Node\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` |
| Vista+ | NTUSER.DAT | `Software\Microsoft\Windows\Shell\BagMRU` (mostly network/remote, desktop) |

On disk: `C:\Users\<user>\NTUSER.DAT` and
`C:\Users\<user>\AppData\Local\Microsoft\Windows\UsrClass.dat`, each with
`.LOG1`/`.LOG2` transaction logs next to it. **Always collect the logs** —
since Windows 8.1 recent changes may sit only in the logs for up to an hour.
greybags replays them in memory automatically.

## BagMRU structure

```
BagMRU                      (NodeSlot = Desktop bag, MRUListEx = order of 0,1,2...)
├── value "0"  = shell item for "My Computer"
├── value "1"  = shell item for "Network"
├── MRUListEx  = 01 00 00 00 00 00 00 00 FF FF FF FF   (1 most recent, then 0)
├── 0\                      (subkey for value "0")
│   ├── value "0" = shell item "C:\"
│   ├── NodeSlot  = 7       -> Bags\7 holds the view settings for "My Computer"
│   └── 0\                  -> children of C:\ ...
└── 1\ ...
```

* Each numbered **value** holds one shell item (one path segment).
* The **subkey with the same number** holds that item's children, so the full
  path is built by walking down the tree and joining segments.
* **MRUListEx** lists the child value numbers, most recently used first,
  terminated by `0xFFFFFFFF`.
* **NodeSlot** points to `Bags\<n>`, which holds view settings; its subkeys
  (`Shell\{GUID}`) also reveal the *folder type* Explorer chose
  (Documents, Pictures, Downloads, Generic ...).

## Timestamps — what each one means

A registry key has a single LastWrite time, updated when *any* value in it
changes. greybags derives activity times from that rule:

| Field | Source | Meaning | Confidence |
|---|---|---|---|
| `last_interacted` | parent key LastWrite, only when the item is MRU position 0 | the last time this folder was opened/selected | high |
| `first_interacted` | the item's own key LastWrite, when the item has no children | ~ first time the folder was opened (key created, never updated) | medium |
| `last_explored` | the item's own key LastWrite, when it has children | the last time a sub-folder was registered while browsing it | medium |
| `key_last_written` | the item's own key | raw value for your own reasoning | — |
| `created` / `modified` / `accessed` | inside the shell item (FAT, 2 s precision) | **the folder's own MAC times at the moment it was registered** — not user activity | describes the target |
| `ext_*` | extension block 0xbeef0026 (FILETIME) | as above, for some virtual/root items | describes the target |
| `bag_updated` | `Bags\<n>` LastWrite | view settings last saved | low |

Pitfalls:

* Only the MRU-0 child of each key gets a precise "last interacted" time; the
  others only tell you "some time before".
* Shell item MAC times are a **snapshot**: if the folder was later modified,
  the shell item keeps the old values until the bag is rewritten. This makes
  them useful for spotting timestomping (a snapshot "created" time later than
  the registry key that recorded it is impossible — greybags flags this as
  `time.target_after_key`).
* LastWrite times are UTC. FAT times in shell items are documented as UTC
  but may be local time on some systems; greybags tolerates a 24 h skew
  (`--skew-hours`) in its consistency checks.

## Shell item types greybags understands

| Class / signature | Type | Notable data |
|---|---|---|
| 0x1F | Root folder | shell folder GUID (My Computer, Network, Control Panel, OneDrive, ...), 0xbeef0026 times |
| 0x20–0x2F | Volume | drive letter, or GUID for virtual volumes |
| 0x30–0x3F | File entry (directory/file) | short name, FAT MAC times, attributes; 0xbeef0004: long name, MFT entry + sequence |
| 0x40–0x4F | Network location | domain, server, share UNC, description |
| 0x52 / ancestor | ZIP contents | name, modification date string, sizes, CRC |
| 0x61 | URI | URL, FTP host/user, connection FILETIME |
| 0x71 / 0x01 | Control panel item / category | applet GUID, category name |
| 0x74 + CFSF | Users files delegate | embedded file entry |
| delegate GUID trailer | Delegate item | Removable Drives, Portable Devices, Users Files, ... |
| 0x10312005 / 0x07192006 | MTP device / folder | device name, WPD id (USB serial), FILETIMEs |
| users property view sigs | Property views | serialized property store: ItemNameDisplay, ParsingPath, ... |
| GFSI, AugM, cabinet, CPL, APPS, Acronis | misc. signature items | names, paths |
| anything else | Unknown | heuristic strings and property stores — never dropped |

Use `greybags item <hex>` (or `greybags hive cat ...`) to see every field of
any item with its offset and size.

## Deleted ShellBags

When BagMRU keys or values are deleted (Windows' own pruning when the bag
limit is reached, privacy cleaners, manual deletion) the registry cells are
marked free but usually not wiped. greybags scans every free cell for remnant
key (`nk`) and value (`vk`) records and re-attaches them:

* a deleted key whose parent is a live BagMRU key is placed under that
  parent's path;
* a wholesale-deleted `BagMRU` tree is re-attached under the live `...\Shell`
  key and reported with location `... (deleted)`;
* if exactly one unlinked value record carries the deleted key's slot number,
  its shell item is used to name the key (marked "inferred" in the notes);
* remnant copies identical to live entries are dropped unless
  `--include-duplicates` is set.

Recovered entries have `status = recovered`. Treat them as leads: free cells
can be partially overwritten.

## Suggested workflow (Debian/Ubuntu workstation)

```sh
# 1. Acquire: extract hives + logs from the image (read-only, hashed manifest)
scripts/collect-hives.sh -i /evidence/disk.E01 -d case42/hives

# 2. Triage report
greybags analyze -f markdown -o case42/shellbags-report.md case42/hives

# 3. Full data for review in a spreadsheet / Timeline Explorer
greybags parse -f csv -o case42/shellbags.csv case42/hives

# 4. Super-timeline integration
greybags timeline -f bodyfile case42/hives > case42/shellbags.body
mactime -b case42/shellbags.body -z UTC -d > case42/shellbags-timeline.csv

# 5. Drill into a suspicious item
greybags hive cat case42/hives/p2048/Users/bob/AppData/Local/Microsoft/Windows/UsrClass.dat \
    'Local Settings\Software\Microsoft\Windows\Shell\BagMRU\1\0' 3

# 6. Cross-validate with a second, independent parser
scripts/install-sbecmd.sh
greybags sbecmd run case42/hives
```

Correlate ShellBags with: `USBSTOR`/`MountedDevices`/`setupapi.dev.log`
(devices), LNK files and JumpLists (files opened), `RecentDocs` and
`OpenSavePidlMRU` (dialogs), Security/RDP event logs (remote access), and the
MFT (the MFT entry/sequence recorded in 0xbeef0004 blocks tells you whether a
folder record was later reused).

## References

* Joachim Metz, *Windows Shell Item format* (libfwsi) and *Windows Property
  Store format* (libfwps).
* Maxim Suhanov, *Windows registry file format specification*.
* Eric Zimmerman, ShellBags Explorer / SBECmd.
* Vincent Lo, *Windows ShellBag Forensics in Depth* (SANS) — ShellBag
  timestamp semantics.
