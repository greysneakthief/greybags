use greybags::shellbags::{scan_inputs, ScanOptions};
fn main() {
    let inputs: Vec<std::path::PathBuf> = std::env::args().skip(1).map(Into::into).collect();
    let r = scan_inputs(&inputs, &ScanOptions::default());
    for h in &r.hives {
        eprintln!(
            "HIVE {} kind={:?} user={:?} entries={} recovered={} warnings={:?}",
            h.path.rsplit('/').next().unwrap(),
            h.kind,
            h.user,
            h.entries,
            h.recovered,
            h.warnings
        );
    }
    for e in &r.entries {
        println!(
            "{:3} {:9} mru={:?} slot={:?} {:40} | fs={:?} | LI={:?} FI={:?} LE={:?} bag={:?}",
            e.id,
            e.status.label(),
            e.mru_position,
            e.node_slot,
            e.absolute_path,
            e.fs_path,
            e.last_interacted.map(|t| t.to_short()),
            e.first_interacted.map(|t| t.to_short()),
            e.last_explored.map(|t| t.to_short()),
            e.bag
                .as_ref()
                .map(|b| (b.folder_types.clone(), b.view_mode.clone()))
        );
    }
    eprintln!("errors={:?}", r.errors);
}
