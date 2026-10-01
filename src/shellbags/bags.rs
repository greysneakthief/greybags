//! `Bags\<NodeSlot>` view-setting correlation.

use super::model::BagInfo;
use crate::regf::Key;
use crate::util::{known, Guid};

pub fn read_bag(bags: &Key, slot: u32) -> Option<BagInfo> {
    let k = bags.subkey(&slot.to_string()).ok()??;
    let mut info = BagInfo {
        slot,
        key_path: k.path(),
        last_written: k.last_written(),
        ..Default::default()
    };
    for view in k.subkeys_lossy().0 {
        info.views.push(view.name().to_string());
        info.view_last_written = info.view_last_written.max(view.last_written());
        // Windows XP stores settings directly under Shell.
        absorb_values(&view, &mut info);
        for sub in view.subkeys_lossy().0 {
            info.view_last_written = info.view_last_written.max(sub.last_written());
            if let Some(g) = Guid::parse(sub.name()) {
                let label = match known::folder_type(&g) {
                    Some(n) => format!("{g} ({n})"),
                    None => g.to_string(),
                };
                if !info.folder_types.contains(&label) {
                    info.folder_types.push(label);
                }
            }
            absorb_values(&sub, &mut info);
        }
    }
    Some(info)
}

fn absorb_values(k: &Key, info: &mut BagInfo) {
    for v in k.values_lossy().0 {
        match v.name().to_ascii_lowercase().as_str() {
            "foldertype" => {
                if let Some(s) = v.as_string().filter(|s| !s.is_empty()) {
                    if !info.folder_types.contains(&s) {
                        info.folder_types.push(s);
                    }
                }
            }
            "logicalviewmode" => {
                if let Some(m) = v.as_u32() {
                    info.view_mode = Some(
                        known::logical_view_mode(m)
                            .map(str::to_string)
                            .unwrap_or_else(|| m.to_string()),
                    );
                }
            }
            "iconsize" => info.icon_size = v.as_u32(),
            _ => {}
        }
    }
}
