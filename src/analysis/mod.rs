//! Analysis: timeline, triage findings and summary statistics.

pub mod findings;
pub mod report;
pub mod timeline;
pub mod watchlist;

use crate::shellbags::{EntryStatus, ScanResult, ShellBagEntry};
use crate::shellitem::Category;
use crate::util::Timestamp;
use findings::{Finding, FindingOptions};
use serde::Serialize;
use std::collections::BTreeMap;
use timeline::{TimelineEvent, TimelineOptions};

#[derive(Debug, Clone, Serialize)]
pub struct VolumeSummary {
    pub volume: String,
    pub entries: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_activity: Option<Timestamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_activity: Option<Timestamp>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecentItem {
    pub timestamp: Timestamp,
    pub path: String,
    pub user: Option<String>,
    pub entry_id: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    pub hives: usize,
    pub users: Vec<String>,
    pub entries: usize,
    pub active: usize,
    pub orphaned: usize,
    pub recovered: usize,
    pub by_type: Vec<(String, usize)>,
    pub volumes: Vec<VolumeSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub earliest_activity: Option<Timestamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_activity: Option<Timestamp>,
    pub most_recent: Vec<RecentItem>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Analysis {
    pub generated_by: String,
    pub summary: Summary,
    pub findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub timeline: Vec<TimelineEvent>,
}

#[derive(Debug, Clone, Default)]
pub struct AnalysisOptions {
    pub findings: FindingOptions,
    pub timeline: TimelineOptions,
    /// Embed the full timeline in the analysis output.
    pub include_timeline: bool,
    /// Number of most-recent activity items in the summary.
    pub recent_count: usize,
}

pub fn analyze(result: &ScanResult, opts: &AnalysisOptions) -> Analysis {
    let summary = summarize(
        result,
        if opts.recent_count == 0 {
            15
        } else {
            opts.recent_count
        },
    );
    let findings = findings::evaluate(&result.entries, &result.hives, &opts.findings);
    let timeline = if opts.include_timeline {
        timeline::build(&result.entries, &opts.timeline)
    } else {
        Vec::new()
    };
    Analysis {
        generated_by: format!("greybags {}", env!("CARGO_PKG_VERSION")),
        summary,
        findings,
        timeline,
    }
}

fn volume_key(e: &ShellBagEntry) -> Option<String> {
    if let Some(fs) = &e.fs_path {
        if let Some(rest) = fs.strip_prefix("\\\\") {
            let mut parts = rest.split('\\');
            let server = parts.next().unwrap_or("");
            return Some(match parts.next() {
                Some(share) => format!("\\\\{server}\\{share}"),
                None => format!("\\\\{server}"),
            });
        }
        return fs.split('\\').next().map(|s| s.to_string());
    }
    match e.item.category {
        Category::MtpDevice | Category::MtpFolder => Some("[portable devices]".into()),
        Category::Uri => Some("[remote URIs]".into()),
        _ => None,
    }
}

pub fn summarize(result: &ScanResult, recent: usize) -> Summary {
    let entries = &result.entries;
    let mut users: Vec<String> = entries.iter().filter_map(|e| e.user.clone()).collect();
    users.sort();
    users.dedup();
    let mut types: BTreeMap<String, usize> = BTreeMap::new();
    let mut vols: BTreeMap<String, (usize, Option<Timestamp>, Option<Timestamp>)> = BTreeMap::new();
    for e in entries {
        *types
            .entry(e.item.category.label().to_string())
            .or_default() += 1;
        if let Some(v) = volume_key(e) {
            let slot = vols.entry(v).or_insert((0, None, None));
            slot.0 += 1;
            if let Some(t) = e.activity_time() {
                slot.1 = Some(slot.1.map_or(t, |x| x.min(t)));
                slot.2 = Some(slot.2.map_or(t, |x| x.max(t)));
            }
        }
    }
    let mut by_type: Vec<(String, usize)> = types.into_iter().collect();
    by_type.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let times: Vec<Timestamp> = entries.iter().filter_map(|e| e.activity_time()).collect();
    let mut recent_items: Vec<RecentItem> = entries
        .iter()
        .filter_map(|e| {
            let t = e
                .last_interacted
                .or(e.last_explored)
                .or(e.first_interacted)?;
            Some(RecentItem {
                timestamp: t,
                path: e.fs_path.clone().unwrap_or_else(|| e.absolute_path.clone()),
                user: e.user.clone(),
                entry_id: e.id,
            })
        })
        .collect();
    recent_items.sort_by(|a, b| b.timestamp.cmp_instant(&a.timestamp));
    recent_items.truncate(recent);
    Summary {
        hives: result.hives.len(),
        users,
        entries: entries.len(),
        active: entries
            .iter()
            .filter(|e| e.status == EntryStatus::Active)
            .count(),
        orphaned: entries
            .iter()
            .filter(|e| e.status == EntryStatus::Orphaned)
            .count(),
        recovered: entries
            .iter()
            .filter(|e| e.status == EntryStatus::Recovered)
            .count(),
        by_type,
        volumes: vols
            .into_iter()
            .map(|(volume, (n, f, l))| VolumeSummary {
                volume,
                entries: n,
                first_activity: f,
                last_activity: l,
            })
            .collect(),
        earliest_activity: times.iter().min().copied(),
        latest_activity: times.iter().max().copied(),
        most_recent: recent_items,
    }
}
