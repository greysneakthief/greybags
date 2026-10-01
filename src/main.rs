//! greybags command-line interface.

use anyhow::{bail, Context, Result};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use greybags::analysis::{
    self, findings::FindingOptions, report, timeline, watchlist, AnalysisOptions,
};
use greybags::output::{self, EntryOutputOptions};
use greybags::regf::{self, data_type_name, Hive, Key, OpenOptions};
use greybags::shellbags::{self, ScanOptions, ScanResult};
use greybags::shellitem::{self, ParseOptions};
use greybags::util::bytes::{from_hex, hexdump, to_hex};
use greybags::util::Timestamp;
use greybags::{demo, ezt};
use std::fs::File;
use std::io::{self, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "greybags",
    version,
    about = "Windows ShellBags dissector and analysis toolkit",
    long_about = "greybags parses ShellBags (BagMRU/Bags) from offline NTUSER.DAT and UsrClass.dat hives, \
replays registry transaction logs in memory, recovers deleted BagMRU keys from unallocated hive cells, \
dissects shell items down to individual fields and produces timelines and triage findings.\n\n\
Evidence files are only ever opened read-only.",
    after_help = "Examples:\n  \
greybags parse /mnt/evidence/Users/alice/AppData/Local/Microsoft/Windows/UsrClass.dat\n  \
greybags parse -f csv -o shellbags.csv /cases/hives/\n  \
greybags analyze -f markdown -o report.md /cases/hives/\n  \
greybags timeline -f bodyfile /cases/hives/ | mactime -b - -z UTC\n  \
greybags item 14001f50e04fd020ea3a6910a2d808002b30309d0000\n  \
greybags sbecmd compare --csv sbecmd_out.csv /cases/hives/"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Extract ShellBag entries from hives or directories of hives
    Parse(ParseArgs),
    /// Triage report: summary, findings and most recent activity
    Analyze(AnalyzeArgs),
    /// Chronological timeline of ShellBag activity
    Timeline(TimelineArgs),
    /// Dissect raw shell item / ITEMIDLIST bytes field by field
    Item(ItemArgs),
    /// Inspect registry hives (metadata, keys, values)
    #[command(subcommand)]
    Hive(HiveCmd),
    /// Cross-validate with Eric Zimmerman's SBECmd
    #[command(subcommand)]
    Sbecmd(SbeCmd),
    /// Write a synthetic training UsrClass.dat (fictional user "jdoe")
    DemoHive {
        /// Output directory (Users/jdoe/AppData/Local/Microsoft/Windows/UsrClass.dat is created inside)
        out_dir: PathBuf,
    },
    /// Print shell completion script
    Completions { shell: clap_complete::Shell },
    /// Print the roff man page
    #[command(hide = true)]
    Man,
}

#[derive(Args, Clone)]
struct ScanArgs {
    /// Hive files and/or directories to search for NTUSER.DAT / UsrClass.dat
    #[arg(required = true)]
    inputs: Vec<PathBuf>,
    /// Do not replay .LOG/.LOG1/.LOG2 transaction logs for dirty hives
    #[arg(long)]
    no_logs: bool,
    /// Do not carve deleted BagMRU keys/values from unallocated cells
    #[arg(long)]
    no_recover: bool,
    /// Also report carved value records that cannot be tied to a key
    #[arg(long)]
    orphan_values: bool,
    /// Keep recovered records identical to live entries
    #[arg(long)]
    include_duplicates: bool,
    /// Drop entries duplicated across sources (e.g. shadow copies)
    #[arg(long)]
    dedupe: bool,
    /// In directories, check every file's signature (not just *ntuser*/*usrclass*)
    #[arg(long)]
    scan_all: bool,
    /// ANSI code page for non-Unicode names (WHATWG label, e.g. windows-1251, shift_jis)
    #[arg(long, default_value = "windows-1252")]
    codepage: String,
    /// Only entries whose path contains this text (case-insensitive)
    #[arg(long)]
    filter: Option<String>,
    /// Only entries for this user
    #[arg(long)]
    user: Option<String>,
    /// Only entries with activity at/after this time (UTC, YYYY-MM-DD[THH:MM:SS])
    #[arg(long, value_parser = parse_ts)]
    since: Option<Timestamp>,
    /// Only entries with activity at/before this time (UTC)
    #[arg(long, value_parser = parse_ts)]
    until: Option<Timestamp>,
}

fn parse_ts(s: &str) -> std::result::Result<Timestamp, String> {
    Timestamp::parse(s)
        .ok_or_else(|| format!("invalid timestamp '{s}' (use YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS)"))
}

#[derive(Copy, Clone, ValueEnum)]
enum EntryFormat {
    Table,
    Csv,
    /// CSV with SBECmd-style column names
    CsvSbe,
    Json,
    Jsonl,
    Tree,
}

#[derive(Args)]
struct ParseArgs {
    #[command(flatten)]
    scan: ScanArgs,
    #[arg(short, long, value_enum, default_value = "table")]
    format: EntryFormat,
    /// Write to file instead of stdout
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Include raw shell item bytes (hex) in CSV/JSON
    #[arg(long)]
    raw: bool,
    /// Include field-level dissection in JSON
    #[arg(long)]
    fields: bool,
}

#[derive(Copy, Clone, ValueEnum)]
enum ReportFormat {
    Text,
    Markdown,
    Json,
}

#[derive(Args)]
struct AnalyzeArgs {
    #[command(flatten)]
    scan: ScanArgs,
    #[arg(short, long, value_enum, default_value = "text")]
    format: ReportFormat,
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Additional watchlist file(s) ([severity:]pattern [| label], `re:` for regex)
    #[arg(long)]
    watchlist: Vec<PathBuf>,
    /// Disable the built-in watchlist
    #[arg(long)]
    no_builtin_watchlist: bool,
    /// Drive letter of the system volume
    #[arg(long, default_value = "C")]
    system_drive: char,
    /// Tolerance (hours) for timestamp-consistency checks
    #[arg(long, default_value_t = 24)]
    skew_hours: i64,
    /// Embed the full timeline in JSON output
    #[arg(long)]
    timeline: bool,
}

#[derive(Copy, Clone, ValueEnum)]
enum TimelineFormat {
    Csv,
    Jsonl,
    /// Sleuth Kit bodyfile for mactime
    Bodyfile,
}

#[derive(Args)]
struct TimelineArgs {
    #[command(flatten)]
    scan: ScanArgs,
    #[arg(short, long, value_enum, default_value = "csv")]
    format: TimelineFormat,
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Only user-activity events (omit the target folder's own MAC times)
    #[arg(long)]
    activity_only: bool,
}

#[derive(Args)]
struct ItemArgs {
    /// Hex bytes of a shell item or ITEMIDLIST (spaces, commas, 0x allowed); "-" reads hex from stdin
    hex: Vec<String>,
    /// Read raw bytes from a file instead
    #[arg(long, conflicts_with = "hex")]
    file: Option<PathBuf>,
    /// Byte offset into --file
    #[arg(long, default_value_t = 0)]
    offset: usize,
    /// Number of bytes to read from --file (default: to end)
    #[arg(long)]
    length: Option<usize>,
    /// Output JSON instead of the annotated text view
    #[arg(long)]
    json: bool,
    /// Omit the hex dump
    #[arg(long)]
    no_hexdump: bool,
    #[arg(long, default_value = "windows-1252")]
    codepage: String,
}

#[derive(Subcommand)]
enum HiveCmd {
    /// Base block, dirty state, transaction log replay and ShellBag locations
    Info {
        hive: PathBuf,
        #[arg(long)]
        no_logs: bool,
    },
    /// List subkeys and values of a key
    Ls {
        hive: PathBuf,
        /// Key path relative to the root (default: root)
        #[arg(default_value = "")]
        key: String,
        #[arg(short, long)]
        recursive: bool,
        #[arg(long)]
        no_logs: bool,
    },
    /// Show a value (hex dump, decoded, and dissected if it is a shell item)
    Cat {
        hive: PathBuf,
        key: String,
        value: String,
        #[arg(long)]
        no_logs: bool,
    },
    /// List key/value records carved from unallocated cells
    Deleted {
        hive: PathBuf,
        #[arg(long)]
        no_logs: bool,
    },
}

#[derive(Subcommand)]
enum SbeCmd {
    /// Run SBECmd on a directory of hives (via dotnet) and compare with greybags
    Run {
        /// Directory containing the hives
        input_dir: PathBuf,
        /// Path to SBECmd.dll / SBECmd (default: $GREYBAGS_SBECMD, PATH, install-sbecmd.sh location)
        #[arg(long)]
        sbecmd: Option<PathBuf>,
        /// dotnet executable to use
        #[arg(long)]
        dotnet: Option<PathBuf>,
        /// Directory for SBECmd CSV output
        #[arg(short, long, default_value = "sbecmd_out")]
        out_dir: PathBuf,
        /// Skip the comparison step
        #[arg(long)]
        no_compare: bool,
        /// Extra arguments passed to SBECmd verbatim (after --)
        #[arg(last = true)]
        extra: Vec<String>,
    },
    /// Compare an existing SBECmd CSV with greybags results
    Compare {
        /// SBECmd CSV file(s)
        #[arg(long, required = true)]
        csv: Vec<PathBuf>,
        #[command(flatten)]
        scan: ScanArgs,
        #[arg(long)]
        json: bool,
        /// Include recovered/orphaned entries in the comparison
        #[arg(long)]
        include_recovered: bool,
    },
}

fn writer(path: &Option<PathBuf>) -> Result<Box<dyn Write>> {
    Ok(match path {
        Some(p) => Box::new(BufWriter::new(
            File::create(p).with_context(|| format!("creating {}", p.display()))?,
        )),
        None => Box::new(BufWriter::new(io::stdout().lock())),
    })
}

fn encoding(label: &str) -> Result<&'static encoding_rs::Encoding> {
    encoding_rs::Encoding::for_label(label.as_bytes())
        .with_context(|| format!("unknown code page '{label}'"))
}

fn scan(args: &ScanArgs, dissect: bool) -> Result<ScanResult> {
    let opts = ScanOptions {
        apply_logs: !args.no_logs,
        recover_deleted: !args.no_recover,
        include_duplicates: args.include_duplicates,
        include_orphan_values: args.orphan_values,
        parse: ParseOptions {
            codepage: encoding(&args.codepage)?,
            dissect,
        },
        dedupe: args.dedupe,
        scan_all_files: args.scan_all,
    };
    let mut r = shellbags::scan_inputs(&args.inputs, &opts);
    for e in &r.errors {
        eprintln!("greybags: {e}");
    }
    for h in &r.hives {
        for w in &h.warnings {
            eprintln!("greybags: {}: {w}", h.path);
        }
    }
    if r.hives.is_empty() {
        bail!("no registry hives found in the given inputs");
    }
    filter(&mut r, args);
    Ok(r)
}

fn filter(r: &mut ScanResult, a: &ScanArgs) {
    let needle = a.filter.as_ref().map(|s| s.to_lowercase());
    r.entries.retain(|e| {
        if let Some(n) = &needle {
            let hay = format!(
                "{}\n{}",
                e.absolute_path,
                e.fs_path.as_deref().unwrap_or("")
            )
            .to_lowercase();
            if !hay.contains(n) {
                return false;
            }
        }
        if let Some(u) = &a.user {
            if !e.user.as_deref().is_some_and(|x| x.eq_ignore_ascii_case(u)) {
                return false;
            }
        }
        if a.since.is_some() || a.until.is_some() {
            let Some(t) = e.activity_time() else {
                return false;
            };
            if a.since.is_some_and(|s| t < s) || a.until.is_some_and(|u| t > u) {
                return false;
            }
        }
        true
    });
}

fn main() {
    let cli = Cli::parse();
    let res = match cli.cmd {
        Cmd::Parse(a) => cmd_parse(a),
        Cmd::Analyze(a) => cmd_analyze(a),
        Cmd::Timeline(a) => cmd_timeline(a),
        Cmd::Item(a) => cmd_item(a),
        Cmd::Hive(h) => cmd_hive(h),
        Cmd::Sbecmd(s) => cmd_sbecmd(s),
        Cmd::DemoHive { out_dir } => cmd_demo(&out_dir),
        Cmd::Completions { shell } => {
            clap_complete::generate(shell, &mut Cli::command(), "greybags", &mut io::stdout());
            Ok(())
        }
        Cmd::Man => clap_mangen::Man::new(Cli::command())
            .render(&mut io::stdout())
            .map_err(Into::into),
    };
    if let Err(e) = res {
        // A closed pipe (e.g. `| head`) is not an error worth reporting.
        let broken_pipe = e.chain().any(|c| {
            c.downcast_ref::<io::Error>()
                .is_some_and(|io| io.kind() == io::ErrorKind::BrokenPipe)
                || c.to_string().contains("Broken pipe")
        });
        if broken_pipe {
            std::process::exit(0);
        }
        eprintln!("greybags: error: {e:#}");
        std::process::exit(1);
    }
}

fn cmd_parse(a: ParseArgs) -> Result<()> {
    let r = scan(&a.scan, a.fields)?;
    let mut w = writer(&a.output)?;
    let o = EntryOutputOptions {
        raw: a.raw,
        fields: a.fields,
    };
    match a.format {
        EntryFormat::Table => output::write_table(&mut w, &r.entries)?,
        EntryFormat::Csv => output::write_csv(&mut w, &r.entries, o)?,
        EntryFormat::CsvSbe => output::write_csv_sbe(&mut w, &r.entries)?,
        EntryFormat::Json => output::write_json(&mut w, &r, o)?,
        EntryFormat::Jsonl => output::write_jsonl(&mut w, &r.entries, o)?,
        EntryFormat::Tree => output::write_tree(&mut w, &r)?,
    }
    w.flush()?;
    if a.output.is_some() {
        eprintln!(
            "greybags: wrote {} entries from {} hive(s)",
            r.entries.len(),
            r.hives.len()
        );
    }
    Ok(())
}

fn cmd_analyze(a: AnalyzeArgs) -> Result<()> {
    let r = scan(&a.scan, false)?;
    let mut rules = if a.no_builtin_watchlist {
        Vec::new()
    } else {
        watchlist::builtin()
    };
    for p in &a.watchlist {
        let text =
            std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?;
        let (more, errs) = watchlist::parse(&text);
        for e in errs {
            eprintln!("greybags: {}: {e}", p.display());
        }
        rules.extend(more);
    }
    let opts = AnalysisOptions {
        findings: FindingOptions {
            watchlist: rules,
            system_drive: a.system_drive,
            skew_secs: a.skew_hours * 3600,
        },
        timeline: timeline::TimelineOptions {
            include_target_times: true,
            since: a.scan.since,
            until: a.scan.until,
        },
        include_timeline: a.timeline,
        recent_count: 15,
    };
    let an = analysis::analyze(&r, &opts);
    let mut w = writer(&a.output)?;
    match a.format {
        ReportFormat::Text => w.write_all(report::text(&an, &r).as_bytes())?,
        ReportFormat::Markdown => w.write_all(report::markdown(&an, &r).as_bytes())?,
        ReportFormat::Json => {
            let doc = serde_json::json!({ "hives": r.hives, "errors": r.errors, "analysis": an });
            serde_json::to_writer_pretty(&mut w, &doc)?;
            writeln!(w)?;
        }
    }
    w.flush()?;
    Ok(())
}

fn cmd_timeline(a: TimelineArgs) -> Result<()> {
    let r = scan(&a.scan, false)?;
    let events = timeline::build(
        &r.entries,
        &timeline::TimelineOptions {
            include_target_times: !a.activity_only,
            since: a.scan.since,
            until: a.scan.until,
        },
    );
    let mut w = writer(&a.output)?;
    match a.format {
        TimelineFormat::Csv => output::write_timeline_csv(&mut w, &events)?,
        TimelineFormat::Jsonl => output::write_timeline_jsonl(&mut w, &events)?,
        TimelineFormat::Bodyfile => output::write_bodyfile(&mut w, &events)?,
    }
    w.flush()?;
    Ok(())
}

fn cmd_item(a: ItemArgs) -> Result<()> {
    let bytes = if let Some(f) = &a.file {
        let data = std::fs::read(f).with_context(|| format!("reading {}", f.display()))?;
        let end = a
            .length
            .map(|l| a.offset + l)
            .unwrap_or(data.len())
            .min(data.len());
        if a.offset >= end {
            bail!("offset beyond end of file");
        }
        data[a.offset..end].to_vec()
    } else {
        let text = if a.hex.len() == 1 && a.hex[0] == "-" || a.hex.is_empty() {
            let mut s = String::new();
            io::stdin().read_to_string(&mut s)?;
            s
        } else {
            a.hex.join(" ")
        };
        from_hex(&text).context("could not parse hex input")?
    };
    let opts = ParseOptions {
        codepage: encoding(&a.codepage)?,
        dissect: true,
    };
    let items = shellitem::parse_list(&bytes, &opts);
    let stdout = io::stdout();
    let mut w = BufWriter::new(stdout.lock());
    if a.json {
        serde_json::to_writer_pretty(&mut w, &items)?;
        writeln!(w)?;
        return Ok(w.flush()?);
    }
    if items.is_empty() {
        writeln!(
            w,
            "No shell items found (first two bytes must be the item size)."
        )?;
    }
    let mut path = Vec::new();
    for (i, it) in items.iter().enumerate() {
        path.push(it.segment());
        writeln!(
            w,
            "Item #{i} at offset {} (0x{:x}), size {} bytes, class 0x{:02x}",
            it.offset, it.offset, it.size, it.class_type
        )?;
        writeln!(w, "  Type : {}", it.type_name)?;
        writeln!(w, "  Name : {}", it.name)?;
        for (k, v) in &it.details {
            writeln!(w, "  {k:<12}: {v}")?;
        }
        for (label, v) in [
            ("Created", it.created),
            ("Modified", it.modified),
            ("Accessed", it.accessed),
            ("ExtCreated", it.ext_created),
            ("ExtModified", it.ext_modified),
            ("ExtAccessed", it.ext_accessed),
        ] {
            if let Some(t) = v {
                writeln!(w, "  {label:<12}: {t}")?;
            }
        }
        if let (Some(e), Some(s)) = (it.mft_entry, it.mft_sequence) {
            writeln!(w, "  MFT ref     : entry {e}, sequence {s}")?;
        }
        for p in &it.properties {
            writeln!(w, "  Property    : {} = {}", p.label(), p.value)?;
        }
        for b in &it.extension_blocks {
            writeln!(
                w,
                "  Ext block   : 0x{:08x} v{} @{} ({} bytes) {}",
                b.signature, b.version, b.offset, b.size, b.name
            )?;
        }
        for warn in &it.warnings {
            writeln!(w, "  WARNING     : {warn}")?;
        }
        writeln!(
            w,
            "\n  {:>6}  {:>4}  {:<38} VALUE",
            "OFFSET", "SIZE", "FIELD"
        )?;
        for f in &it.fields {
            let abs = it.offset + f.offset;
            writeln!(
                w,
                "  0x{abs:04x}  {:>4}  {:<38} {}",
                f.size, f.name, f.value
            )?;
        }
        if !a.no_hexdump {
            writeln!(w)?;
            for line in hexdump(&it.raw, it.offset).lines() {
                writeln!(w, "  {line}")?;
            }
        }
        writeln!(w)?;
    }
    if items.len() > 1 {
        writeln!(w, "Path: {}", path.join("\\"))?;
    }
    Ok(w.flush()?)
}

fn open_hive(p: &Path, no_logs: bool) -> Result<Hive> {
    let opts = if no_logs {
        OpenOptions::default()
    } else {
        OpenOptions::with_logs()
    };
    Hive::open(p, &opts).with_context(|| format!("opening {}", p.display()))
}

fn cmd_hive(h: HiveCmd) -> Result<()> {
    let stdout = io::stdout();
    let mut w = BufWriter::new(stdout.lock());
    match h {
        HiveCmd::Info { hive, no_logs } => {
            let hv = open_hive(&hive, no_logs)?;
            let b = &hv.base;
            writeln!(w, "File              : {}", hive.display())?;
            writeln!(w, "Embedded name     : {}", b.file_name)?;
            writeln!(
                w,
                "Format version    : {}.{}",
                b.major_version, b.minor_version
            )?;
            writeln!(
                w,
                "Sequence numbers  : {} / {}",
                b.primary_seq, b.secondary_seq
            )?;
            writeln!(
                w,
                "Last written      : {}",
                b.last_written
                    .map(|t| t.to_iso())
                    .unwrap_or_else(|| "-".into())
            )?;
            writeln!(
                w,
                "Hive bins size    : {} bytes in {} bin(s)",
                hv.data.len(),
                hv.bins.len()
            )?;
            writeln!(
                w,
                "Root key          : {}",
                hv.root().map(|k| k.name().to_string()).unwrap_or_default()
            )?;
            writeln!(w, "Dirty when opened : {}", hv.was_dirty)?;
            if let Some(r) = &hv.recovery {
                writeln!(w, "Logs examined     : {}", r.logs_examined.join(", "))?;
                writeln!(w, "Logs applied      : {}", r.logs_applied.join(", "))?;
                writeln!(
                    w,
                    "Replay            : {} entr(y/ies), {} page(s), sequence {:?}..{:?}",
                    r.entries_applied, r.pages_applied, r.first_sequence, r.last_sequence
                )?;
            }
            let kind = shellbags::hive_kind(&hv, Some(&hive));
            writeln!(w, "Hive type         : {}", kind.label())?;
            writeln!(
                w,
                "Probable user     : {}",
                greybags::regf::hive::user_from_path(&hive.display().to_string())
                    .or_else(|| hv.embedded_user())
                    .unwrap_or_else(|| "?".into())
            )?;
            writeln!(w, "ShellBag locations:")?;
            let mut any = false;
            for loc in shellbags::walker::LOCATIONS {
                if let Ok(Some(k)) = hv.open_key(loc) {
                    any = true;
                    writeln!(
                        w,
                        "  {loc}  (last written {})",
                        k.last_written().map(|t| t.to_iso()).unwrap_or_default()
                    )?;
                }
            }
            if !any {
                writeln!(w, "  (none)")?;
            }
            for warn in &hv.warnings {
                writeln!(w, "WARNING: {warn}")?;
            }
        }
        HiveCmd::Ls {
            hive,
            key,
            recursive,
            no_logs,
        } => {
            let hv = open_hive(&hive, no_logs)?;
            let k = hv
                .open_key(&key)?
                .with_context(|| format!("key '{key}' not found"))?;
            list_key(&mut w, &k, recursive, 0)?;
        }
        HiveCmd::Cat {
            hive,
            key,
            value,
            no_logs,
        } => {
            let hv = open_hive(&hive, no_logs)?;
            let k = hv
                .open_key(&key)?
                .with_context(|| format!("key '{key}' not found"))?;
            let v = k
                .value(&value)?
                .with_context(|| format!("value '{value}' not found"))?;
            let data = v.data()?;
            writeln!(
                w,
                "{}\\{} ({}, {} bytes)",
                k.path(),
                v.node.display_name(),
                data_type_name(v.data_type()),
                data.len()
            )?;
            if let Some(s) = v.as_string() {
                writeln!(w, "Decoded: {s}")?;
            }
            if v.data_type() == 3 && v.name().eq_ignore_ascii_case("MRUListEx") {
                writeln!(
                    w,
                    "MRU order: {:?}",
                    shellbags::walker::parse_mru_list_ex(&data)
                )?;
            }
            write!(w, "{}", hexdump(&data, 0))?;
            if v.data_type() == 3 && v.name().parse::<u32>().is_ok() {
                writeln!(w, "\nDissect with: greybags item {}", to_hex(&data))?;
                let items = shellitem::parse_list(&data, &ParseOptions::default());
                for it in items {
                    writeln!(
                        w,
                        "Shell item: [{}] {} {}",
                        it.type_name,
                        it.name,
                        it.summary()
                    )?;
                }
            }
        }
        HiveCmd::Deleted { hive, no_logs } => {
            let hv = open_hive(&hive, no_logs)?;
            let c = regf::carve::carve(&hv);
            writeln!(w, "Recovered key records: {}", c.keys.len())?;
            for k in &c.keys {
                let parent = hv
                    .key_at(k.node.parent)
                    .map(|p| p.path())
                    .unwrap_or_else(|_| format!("<0x{:x}>", k.node.parent));
                writeln!(
                    w,
                    "  0x{:08x}  {}  {}\\{}  ({} value(s))",
                    k.node.offset,
                    k.node
                        .last_written()
                        .map(|t| t.to_short())
                        .unwrap_or_else(|| "-".into()),
                    parent,
                    k.node.name,
                    k.values.len()
                )?;
                for v in &k.values {
                    writeln!(
                        w,
                        "      {} {} {} bytes",
                        v.node.display_name(),
                        data_type_name(v.node.data_type),
                        v.node.data_size()
                    )?;
                }
            }
            writeln!(w, "Unlinked value records: {}", c.orphan_values.len())?;
            for v in &c.orphan_values {
                writeln!(
                    w,
                    "  0x{:08x}  {} {} {} bytes",
                    v.node.offset,
                    v.node.display_name(),
                    data_type_name(v.node.data_type),
                    v.node.data_size()
                )?;
            }
        }
    }
    Ok(w.flush()?)
}

fn list_key<W: Write>(w: &mut W, k: &Key, recursive: bool, depth: usize) -> Result<()> {
    let indent = "  ".repeat(depth);
    writeln!(
        w,
        "{indent}[{}]  {}",
        if k.path().is_empty() {
            k.name().to_string()
        } else {
            k.path()
        },
        k.last_written().map(|t| t.to_iso()).unwrap_or_default()
    )?;
    for v in k.values_lossy().0 {
        let d = v.data().unwrap_or_default();
        let shown = v.as_string().unwrap_or_else(|| {
            let h = to_hex(&d[..d.len().min(24)]);
            if d.len() > 24 {
                format!("{h}…")
            } else {
                h
            }
        });
        writeln!(
            w,
            "{indent}  {:<20} {:<14} {shown}",
            v.node.display_name(),
            data_type_name(v.data_type())
        )?;
    }
    let (subs, errs) = k.subkeys_lossy();
    for e in errs {
        writeln!(w, "{indent}  ! {e}")?;
    }
    for s in subs {
        if recursive {
            list_key(w, &s, true, depth + 1)?;
        } else {
            writeln!(
                w,
                "{indent}  {}\\  {}",
                s.name(),
                s.last_written().map(|t| t.to_iso()).unwrap_or_default()
            )?;
        }
    }
    Ok(())
}

fn cmd_sbecmd(s: SbeCmd) -> Result<()> {
    match s {
        SbeCmd::Run {
            input_dir,
            sbecmd,
            dotnet,
            out_dir,
            no_compare,
            extra,
        } => {
            let exe = ezt::locate(sbecmd.as_deref()).context(
                "SBECmd not found. Install it with scripts/install-sbecmd.sh, set GREYBAGS_SBECMD, or pass --sbecmd",
            )?;
            eprintln!(
                "greybags: running {} on {}",
                exe.display(),
                input_dir.display()
            );
            let csvs = ezt::run(&exe, dotnet.as_deref(), &input_dir, &out_dir, &extra)
                .map_err(anyhow::Error::msg)?;
            for c in &csvs {
                eprintln!("greybags: SBECmd wrote {}", c.display());
            }
            if no_compare {
                return Ok(());
            }
            let args = ScanArgs {
                inputs: vec![input_dir],
                no_logs: false,
                no_recover: true,
                orphan_values: false,
                include_duplicates: false,
                dedupe: false,
                scan_all: false,
                codepage: "windows-1252".into(),
                filter: None,
                user: None,
                since: None,
                until: None,
            };
            compare_and_print(&csvs, &args, false, false)
        }
        SbeCmd::Compare {
            csv,
            scan,
            json,
            include_recovered,
        } => compare_and_print(&csv, &scan, json, include_recovered),
    }
}

fn compare_and_print(
    csvs: &[PathBuf],
    args: &ScanArgs,
    json: bool,
    include_recovered: bool,
) -> Result<()> {
    let mut rows = Vec::new();
    for c in csvs {
        rows.extend(ezt::read_csv(c).map_err(anyhow::Error::msg)?);
    }
    let r = scan(args, false)?;
    let cmp = ezt::compare(&r.entries, &rows, include_recovered);
    let stdout = io::stdout();
    let mut w = BufWriter::new(stdout.lock());
    if json {
        serde_json::to_writer_pretty(&mut w, &cmp)?;
        writeln!(w)?;
        return Ok(w.flush()?);
    }
    writeln!(w, "greybags entries : {}", cmp.greybags_entries)?;
    writeln!(w, "SBECmd entries   : {}", cmp.sbecmd_entries)?;
    writeln!(
        w,
        "Matched paths    : {} ({:.1}% agreement)",
        cmp.matched,
        cmp.agreement() * 100.0
    )?;
    writeln!(w, "\nOnly in greybags ({}):", cmp.only_in_greybags.len())?;
    for p in &cmp.only_in_greybags {
        writeln!(w, "  {p}")?;
    }
    writeln!(w, "\nOnly in SBECmd ({}):", cmp.only_in_sbecmd.len())?;
    for p in &cmp.only_in_sbecmd {
        writeln!(w, "  {p}")?;
    }
    if !cmp.mft_mismatches.is_empty() {
        writeln!(
            w,
            "\nMFT reference mismatches ({}):",
            cmp.mft_mismatches.len()
        )?;
        for (p, a, b) in &cmp.mft_mismatches {
            writeln!(w, "  {p}: greybags {a} vs SBECmd {b}")?;
        }
    }
    writeln!(
        w,
        "\nPaths are compared after normalisation (case, separators, This PC/My Computer). \
         Differences in display names for virtual folders are expected; review each one."
    )?;
    Ok(w.flush()?)
}

fn cmd_demo(out_dir: &Path) -> Result<()> {
    let dir = out_dir.join("Users/jdoe/AppData/Local/Microsoft/Windows");
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let path = dir.join("UsrClass.dat");
    if path.exists() {
        bail!("{} already exists; refusing to overwrite", path.display());
    }
    std::fs::write(&path, demo::demo_usrclass())?;
    println!("Wrote synthetic training hive: {}", path.display());
    println!(
        "Try:\n  greybags parse -f tree {}\n  greybags analyze {}",
        out_dir.display(),
        out_dir.display()
    );
    Ok(())
}
