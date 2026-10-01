# greybags

ShellBag dissector and analysis toolkit for Debian and Ubuntu forensic
workstations, written in Rust.

greybags reads Windows **ShellBags** (`BagMRU`/`Bags`) straight from offline
`NTUSER.DAT` and `UsrClass.dat` hives. It needs no Windows, Wine or .NET
runtime for its own work. It can optionally run Eric Zimmerman's SBECmd under
`dotnet` to cross-check its results.

* **Self-contained registry parser** (`regf`). Reads base blocks, hive bins,
  `nk`/`vk`/`lf`/`lh`/`li`/`ri`/`db` records, and corrupt or truncated hives.
* **Transaction log replay** of `.LOG`/`.LOG1`/`.LOG2`, both the Windows 8.1+
  `HvLE` format (Marvin32-verified) and the legacy `DIRT` format. Replay
  happens in memory and evidence is never written.
* **Deleted ShellBag recovery**. Carves `nk`/`vk` records out of unallocated
  cells and re-attaches them to the live tree, including a BagMRU tree
  deleted in full.
* **Field-level shell item dissector**. Labels every byte with offset, size,
  name and decoded value, like a packet dissector. Covers root folders,
  volumes, file entries (`0xbeef0004`: long name, MFT reference), network
  locations, URIs/FTP, ZIP contents, control panel items, delegate items,
  MTP devices (with USB serial), users property views with serialized
  property stores, and 20+ extension block types. Unknown items are never
  dropped.
* **Analysis module**:
  * timeline with explicit timestamp semantics;
  * triage findings: non-system volumes, MTP devices, admin shares,
    `\\tsclient`, WebDAV, FTP, archives, sensitive locations, a tool
    watchlist, deleted/orphaned bags, timestamp inconsistencies and MFT
    record reuse;
  * a summary of users, volumes, activity window and most recent folders.
* **Outputs**: table, tree, CSV, SBECmd-style CSV, JSON, JSON Lines,
  Sleuth Kit bodyfile (`mactime`), and text, Markdown or JSON reports.
* **Debian/Ubuntu integration**: `.deb` packaging with man page and shell
  completions, `collect-hives.sh` (extracts hives and logs from E01/raw
  images with The Sleuth Kit), and `install-sbecmd.sh` (installs the .NET
  runtime and SBECmd).

## Install

```sh
git clone https://github.com/greysneakthief/greybags && cd greybags
scripts/install-deps.sh            # build-essential + Rust (rustup); add --forensics for sleuthkit/ewf-tools
cargo build --release --locked
sudo install -m755 target/release/greybags /usr/local/bin/
```

To build a Debian package instead (it includes the man page and
bash/zsh/fish completions):

```sh
scripts/build-deb.sh
sudo apt install ./target/debian/greybags_*.deb
```

The minimum Rust version is **1.80**. On Ubuntu 24.04 you can use the distro
toolchain: `apt install rustc-1.80 cargo-1.80`, then
`cargo-1.80 build --release --locked`. Debian 13 ships Rust 1.85. Older
releases need rustup.

## Quick start

```sh
# Practice on a synthetic hive (fictional user, planted artifacts)
greybags demo-hive ./lab
greybags analyze ./lab

# Real evidence: point at hive files or whole directories (searched recursively)
greybags parse  /cases/42/hives                         # table
greybags parse  -f tree /cases/42/hives                 # hierarchy, like ShellBags Explorer
greybags parse  -f csv -o shellbags.csv /cases/42/hives
greybags analyze -f markdown -o report.md /cases/42/hives
greybags timeline -f bodyfile /cases/42/hives | mactime -b - -z UTC -d > timeline.csv
```

Getting hives out of a disk image:

```sh
scripts/collect-hives.sh -i disk.E01 -d /cases/42/hives   # needs: apt install sleuthkit
```

### Commands

| Command | Purpose |
|---|---|
| `parse` | Extract entries: `-f table\|tree\|csv\|csv-sbe\|json\|jsonl`, `--raw`, `--fields` |
| `analyze` | Triage report: `-f text\|markdown\|json`, `--watchlist FILE`, `--system-drive`, `--skew-hours` |
| `timeline` | Events: `-f csv\|jsonl\|bodyfile`, `--activity-only` |
| `item` | Dissect raw bytes: `greybags item 14001f50e04fd0...` or `--file blob.bin --offset N` |
| `hive info\|ls\|cat\|deleted` | Inspect hives: dirty state and log replay, keys, values, carved records |
| `sbecmd run\|compare` | Run SBECmd via `dotnet` and diff, or diff an existing SBECmd CSV |
| `demo-hive` | Write the synthetic training hive |
| `completions <shell>` | Shell completion script |

Options shared by `parse`, `analyze` and `timeline`:

| Option | Effect |
|---|---|
| `--no-logs` | Do not replay transaction logs |
| `--no-recover` | Do not carve deleted keys |
| `--orphan-values` | Include carved values with no recoverable parent |
| `--include-duplicates` | Keep carved copies of live entries |
| `--dedupe` | Merge identical entries across sources, such as shadow copies |
| `--scan-all` | Signature-check every file, not only `*ntuser*` and `*usrclass*` |
| `--codepage` | ANSI code page for non-Unicode names (default `windows-1252`) |
| `--filter` | Only paths containing this text |
| `--user` | Only this user's entries |
| `--since`, `--until` | Only activity inside this time window |

## Reading the output

Each entry carries:

* **`absolute_path`**: the Explorer namespace path, e.g.
  `My Computer\C:\Users\bob\Downloads`.
* **`fs_path`**: a file-system path, when the chain starts at a drive
  (`C:\...`), a UNC share (`\\srv\share\...`) or a user folder
  (`%USERPROFILE%\Downloads\...`).
* **`last_interacted`**: when the folder was last opened. This is only set
  for the MRU-0 child of each key.
* **`first_interacted`** and **`last_explored`**: derived from the folder's
  own BagMRU key LastWrite time.
* **`created`**, **`modified`** and **`accessed`**: the folder's own MAC
  times, captured when the bag was written. They describe the folder, not
  the user.
* **`status`**: `active`, `orphaned` (subkey without a value) or `recovered`
  (carved from free space).
* **`bag`**: the `Bags\<NodeSlot>` correlation, with folder type and view
  mode.

See [docs/SHELLBAGS.md](docs/SHELLBAGS.md) for the full timestamp semantics,
registry locations, item types, recovery details and a suggested casework
workflow.

## Cross-validation with Zimmerman's tools

```sh
scripts/install-sbecmd.sh                         # .NET runtime (~/.dotnet) + SBECmd (~/.local/share/greybags/eztools)
greybags sbecmd run /cases/42/hives               # runs SBECmd -d <dir> --csv sbecmd_out, then compares
greybags sbecmd compare --csv sbecmd_out/*.csv /cases/42/hives
```

The comparison normalises paths (case, separators, `This PC`/`My Computer`)
and reports entries found by only one tool and MFT reference mismatches. Two
independent parsers that agree raise confidence. Where they disagree, look
at those items by hand with `greybags item`.

## Validation

The test suite (`cargo test`) covers the following:

* Exact BagMRU values from the public plaso/dfwinreg test hives (Windows XP
  and 7 NTUSER.DAT, Windows 8.1 UsrClass.dat).
* Builder round-trips for item types those hives lack.
* Deterministic fuzzing of the item dispatcher.
* Recovery scenarios: a deleted subtree, and a BagMRU deleted in full.
* CLI smoke tests for every command and format.

During development the parser was also checked against these external
references:

* Transaction log replay output matched Windows' own recovered hives for the
  yarp `NewDirtyHive` (new format) and `OldDirtyHive` (legacy format) samples,
  compared key by key and value by value.
* Key and value counts matched `regipy` on the plaso NTUSER and UsrClass
  hives.
* BagMRU LastWrite times and entries matched plaso's published test
  expectations.

`examples/dumptree.rs` dumps a hive's full tree for comparisons of this kind:

```sh
cargo run --example dumptree -- hive.dat --logs > ours.txt
```

## Library use

```rust
use greybags::shellbags::{scan_inputs, ScanOptions};
let result = scan_inputs(&["/cases/42/hives".into()], &ScanOptions::default());
for e in &result.entries {
    println!("{} {:?}", e.absolute_path, e.last_interacted);
}
```

Modules: `regf` (hives), `shellitem` (dissector), `shellbags` (walker and
recovery), `analysis` (timeline, findings, reports), `output`, `ezt` (SBECmd).
