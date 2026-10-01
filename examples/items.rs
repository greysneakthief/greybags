//! Developer aid: parse every BagMRU value in a hive and print the result.
use greybags::regf::{Hive, Key, OpenOptions};
use greybags::shellitem::{parse_list, ParseOptions};

fn walk(k: &Key, opts: &ParseOptions) {
    for v in k.values_lossy().0 {
        if v.name().chars().all(|c| c.is_ascii_digit()) && v.data_type() == 3 {
            let d = v.data().unwrap();
            for it in parse_list(&d, opts) {
                println!(
                    "{}\\{} => [{}] {} | {} | {}",
                    k.path(),
                    v.name(),
                    it.type_name,
                    it.name,
                    it.summary(),
                    it.warnings.join(",")
                );
                if std::env::var("FIELDS").is_ok() {
                    for f in &it.fields {
                        println!("    {:4} {:3} {:40} {}", f.offset, f.size, f.name, f.value);
                    }
                }
                for p in &it.properties {
                    println!("    prop {} = {}", p.label(), p.value);
                }
            }
        }
    }
    for s in k.subkeys_lossy().0 {
        walk(&s, opts);
    }
}
fn main() {
    let path = std::env::args().nth(1).unwrap();
    let hive = Hive::open(std::path::Path::new(&path), &OpenOptions::with_logs()).unwrap();
    let opts = ParseOptions {
        dissect: std::env::var("FIELDS").is_ok(),
        ..Default::default()
    };
    for loc in [
        "Software\\Microsoft\\Windows\\Shell\\BagMRU",
        "Software\\Microsoft\\Windows\\ShellNoRoam\\BagMRU",
        "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
    ] {
        if let Ok(Some(k)) = hive.open_key(loc) {
            walk(&k, &opts);
        }
    }
}
