//! Developer aid: dumps every key and value of a hive in a stable text form
//! so two hives (e.g. our log replay vs. Windows' own recovery) can be diffed.
use greybags::regf::{Hive, Key, OpenOptions};
use std::path::Path;

fn walk(k: &Key, depth: usize, out: &mut String, errs: &mut usize) {
    out.push_str(&format!(
        "K {} | {}\n",
        k.path(),
        k.last_written().map(|t| t.to_iso()).unwrap_or_default()
    ));
    let (vals, e) = k.values_lossy();
    *errs += e.len();
    let mut vals: Vec<_> = vals.into_iter().collect();
    vals.sort_by(|a, b| a.name().cmp(b.name()));
    for v in vals {
        let d = v
            .data()
            .map(|d| {
                greybags::util::bytes::to_hex(&d[..d.len().min(64)]) + &format!(" len={}", d.len())
            })
            .unwrap_or_else(|e| format!("ERR {e}"));
        out.push_str(&format!("  V {} t={} {}\n", v.name(), v.data_type(), d));
    }
    let (subs, e) = k.subkeys_lossy();
    *errs += e.len();
    let mut subs = subs;
    subs.sort_by_key(|a| a.name().to_lowercase());
    if depth < 512 {
        for s in subs {
            walk(&s, depth + 1, out, errs);
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let logs = args.iter().any(|a| a == "--logs");
    let path = &args[1];
    let opts = if logs {
        OpenOptions::with_logs()
    } else {
        OpenOptions::default()
    };
    let hive = Hive::open(Path::new(path), &opts).expect("open");
    eprintln!(
        "dirty={} warnings={:?} recovery={:?}",
        hive.was_dirty, hive.warnings, hive.recovery
    );
    let mut out = String::new();
    let mut errs = 0;
    walk(&hive.root().unwrap(), 0, &mut out, &mut errs);
    print!("{out}");
    eprintln!("errors={errs} lines={}", out.lines().count());
}
