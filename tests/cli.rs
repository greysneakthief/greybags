//! Command-line smoke tests against the synthetic training hive.

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_greybags"))
}

fn run(args: &[&str]) -> (bool, String, String) {
    let out = Command::new(bin())
        .args(args)
        .output()
        .expect("run greybags");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn demo(dir: &Path) -> String {
    let (ok, _, err) = run(&["demo-hive", dir.to_str().unwrap()]);
    assert!(ok, "{err}");
    dir.to_str().unwrap().to_string()
}

#[test]
fn parse_formats() {
    let tmp = tempfile::tempdir().unwrap();
    let d = demo(tmp.path());
    for f in ["table", "csv", "csv-sbe", "json", "jsonl", "tree"] {
        let (ok, out, err) = run(&["parse", "-f", f, &d]);
        assert!(ok, "format {f}: {err}");
        assert!(
            out.contains("mimikatz_trunk"),
            "format {f} lacks expected path"
        );
    }
    let (ok, out, _) = run(&["parse", "-f", "json", "--raw", "--fields", &d]);
    assert!(ok);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let entries = v["entries"].as_array().unwrap();
    assert!(entries.len() >= 30);
    assert!(entries[0]["item"]["fields"]
        .as_array()
        .is_some_and(|f| !f.is_empty()));
    assert!(entries[0]["item"]["raw"]
        .as_str()
        .is_some_and(|r| !r.is_empty()));
}

#[test]
fn filters() {
    let tmp = tempfile::tempdir().unwrap();
    let d = demo(tmp.path());
    let (ok, out, _) = run(&["parse", "-f", "jsonl", "--filter", "tsclient", &d]);
    assert!(ok);
    assert_eq!(out.lines().count(), 2);
    let (ok, out, _) = run(&[
        "parse",
        "-f",
        "jsonl",
        "--since",
        "2024-03-19",
        "--until",
        "2024-03-19T09:30:00",
        &d,
    ]);
    assert!(ok);
    assert!(out.lines().all(|l| l.contains("2024-03-19")));
    assert!(out.lines().count() >= 3);
}

#[test]
fn analyze_and_timeline() {
    let tmp = tempfile::tempdir().unwrap();
    let d = demo(tmp.path());
    let (ok, out, err) = run(&["analyze", "-f", "markdown", &d]);
    assert!(ok, "{err}");
    assert!(out.contains("# ShellBags analysis report"));
    assert!(out.contains("Administrative share browsed"));
    let wl = tmp.path().join("wl.txt");
    std::fs::write(&wl, "high: secretproject | Codename from the case brief\n").unwrap();
    let (ok, out, _) = run(&[
        "analyze",
        "-f",
        "json",
        "--watchlist",
        wl.to_str().unwrap(),
        &d,
    ]);
    assert!(ok);
    assert!(out.contains("Codename from the case brief"));
    let (ok, out, _) = run(&["timeline", "-f", "bodyfile", "--activity-only", &d]);
    assert!(ok);
    for line in out.lines() {
        assert_eq!(line.split('|').count(), 11, "bad bodyfile line {line}");
    }
    let (ok, out, _) = run(&["timeline", "-f", "csv", &d]);
    assert!(ok);
    assert!(out.starts_with("Timestamp,Event,"));
}

#[test]
fn item_and_hive_commands() {
    let (ok, out, _) = run(&["item", "14001f50e04fd020ea3a6910a2d808002b30309d0000"]);
    assert!(ok);
    assert!(out.contains("My Computer"));
    assert!(out.contains("Shell folder identifier"));
    let tmp = tempfile::tempdir().unwrap();
    let d = demo(tmp.path());
    let hive = format!("{d}/Users/jdoe/AppData/Local/Microsoft/Windows/UsrClass.dat");
    let (ok, out, _) = run(&["hive", "info", &hive]);
    assert!(ok);
    assert!(out.contains("UsrClass.dat"));
    assert!(out.contains("Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU"));
    let (ok, out, _) = run(&[
        "hive",
        "cat",
        &hive,
        "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
        "0",
    ]);
    assert!(ok);
    assert!(out.contains("Root folder: My Computer"));
    let (ok, out, _) = run(&["hive", "deleted", &hive]);
    assert!(ok);
    assert!(out.contains("Recovered key records: 1"));
}

#[test]
fn refuses_overwrite_and_reports_missing_inputs() {
    let tmp = tempfile::tempdir().unwrap();
    demo(tmp.path());
    let (ok, _, err) = run(&["demo-hive", tmp.path().to_str().unwrap()]);
    assert!(!ok);
    assert!(err.contains("refusing to overwrite"));
    let (ok, _, err) = run(&["parse", "/nonexistent/path"]);
    assert!(!ok);
    assert!(err.contains("no registry hives"));
}

#[test]
fn sbecmd_compare_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let d = demo(tmp.path());
    let csv = tmp.path().join("sbe.csv");
    let (ok, _, _) = run(&[
        "parse",
        "-f",
        "csv-sbe",
        "--no-recover",
        "-o",
        csv.to_str().unwrap(),
        &d,
    ]);
    assert!(ok);
    let (ok, out, err) = run(&[
        "sbecmd",
        "compare",
        "--csv",
        csv.to_str().unwrap(),
        "--json",
        &d,
    ]);
    assert!(ok, "{err}");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    // The orphaned bag is "active" in neither tool's live tree; everything else matches.
    assert_eq!(v["only_in_greybags"].as_array().unwrap().len(), 0, "{out}");
}

#[test]
fn completions_and_man() {
    let (ok, out, _) = run(&["completions", "bash"]);
    assert!(ok && out.contains("greybags"));
    let (ok, out, _) = run(&["man"]);
    assert!(ok && out.contains(".TH"));
}
