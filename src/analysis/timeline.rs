//! Timeline construction from ShellBag entries.

use crate::shellbags::{EntryStatus, ShellBagEntry};
use crate::util::Timestamp;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    LastInteracted,
    LastExplored,
    FirstInteracted,
    BagUpdated,
    TargetCreated,
    TargetModified,
    TargetAccessed,
    ExtCreated,
    ExtModified,
    ExtAccessed,
    UriConnected,
}

impl EventKind {
    pub fn describe(&self) -> &'static str {
        match self {
            EventKind::LastInteracted => "Folder last opened/selected (parent MRU position 0)",
            EventKind::LastExplored => "Folder browsed (a child folder was last registered)",
            EventKind::FirstInteracted => {
                "Folder first opened (BagMRU key created, no children since)"
            }
            EventKind::BagUpdated => "Folder view settings (Bags) last written",
            EventKind::TargetCreated => "Target creation time recorded in shell item",
            EventKind::TargetModified => "Target modification time recorded in shell item",
            EventKind::TargetAccessed => "Target last access time recorded in shell item",
            EventKind::ExtCreated => "Creation FILETIME (extension block 0xbeef0026)",
            EventKind::ExtModified => "Modification FILETIME (extension block 0xbeef0026)",
            EventKind::ExtAccessed => "Access FILETIME (extension block 0xbeef0026)",
            EventKind::UriConnected => "Remote URI first connected",
        }
    }

    /// Is this event direct evidence of user activity (vs. target metadata)?
    pub fn is_activity(&self) -> bool {
        matches!(
            self,
            EventKind::LastInteracted
                | EventKind::LastExplored
                | EventKind::FirstInteracted
                | EventKind::BagUpdated
                | EventKind::UriConnected
        )
    }

    pub fn code(&self) -> &'static str {
        match self {
            EventKind::LastInteracted => "last_interacted",
            EventKind::LastExplored => "last_explored",
            EventKind::FirstInteracted => "first_interacted",
            EventKind::BagUpdated => "bag_updated",
            EventKind::TargetCreated => "target_created",
            EventKind::TargetModified => "target_modified",
            EventKind::TargetAccessed => "target_accessed",
            EventKind::ExtCreated => "ext_created",
            EventKind::ExtModified => "ext_modified",
            EventKind::ExtAccessed => "ext_accessed",
            EventKind::UriConnected => "uri_connected",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TimelineEvent {
    pub timestamp: Timestamp,
    pub event: EventKind,
    pub description: &'static str,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fs_path: Option<String>,
    pub shell_type: String,
    pub entry_id: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    pub source: String,
    pub bag_path: String,
    pub status: EntryStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mft_reference: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct TimelineOptions {
    /// Include timestamps of the target folder itself (creation etc.).
    pub include_target_times: bool,
    pub since: Option<Timestamp>,
    pub until: Option<Timestamp>,
}

impl Default for TimelineOptions {
    fn default() -> Self {
        TimelineOptions {
            include_target_times: true,
            since: None,
            until: None,
        }
    }
}

pub fn build(entries: &[ShellBagEntry], opts: &TimelineOptions) -> Vec<TimelineEvent> {
    let mut out = Vec::new();
    for e in entries {
        let mut push = |ts: Option<Timestamp>, kind: EventKind| {
            let Some(ts) = ts else { return };
            if opts.since.is_some_and(|s| ts < s) || opts.until.is_some_and(|u| ts > u) {
                return;
            }
            out.push(TimelineEvent {
                timestamp: ts,
                event: kind,
                description: kind.describe(),
                path: e.absolute_path.clone(),
                fs_path: e.fs_path.clone(),
                shell_type: e.item.type_name.clone(),
                entry_id: e.id,
                user: e.user.clone(),
                source: e.source.clone(),
                bag_path: e.bag_path.clone(),
                status: e.status,
                mft_reference: match (e.item.mft_entry, e.item.mft_sequence) {
                    (Some(a), Some(b)) => Some(format!("{a}-{b}")),
                    _ => None,
                },
            });
        };
        push(e.last_interacted, EventKind::LastInteracted);
        push(e.last_explored, EventKind::LastExplored);
        push(e.first_interacted, EventKind::FirstInteracted);
        if let Some(b) = &e.bag {
            push(
                b.view_last_written.or(b.last_written),
                EventKind::BagUpdated,
            );
        }
        if let Some(c) = e.item.detail("connected").and_then(Timestamp::parse) {
            push(Some(c), EventKind::UriConnected);
        }
        if opts.include_target_times {
            push(e.item.created, EventKind::TargetCreated);
            push(e.item.modified, EventKind::TargetModified);
            push(e.item.accessed, EventKind::TargetAccessed);
            push(e.item.ext_created, EventKind::ExtCreated);
            push(e.item.ext_modified, EventKind::ExtModified);
            push(e.item.ext_accessed, EventKind::ExtAccessed);
        }
    }
    out.sort_by(|a, b| {
        a.timestamp
            .cmp_instant(&b.timestamp)
            .then(a.event.cmp(&b.event))
            .then(a.entry_id.cmp(&b.entry_id))
    });
    out
}
