//! Offline Windows registry (REGF) hive parser.
//!
//! Self-contained, read-only and defensive: every offset is bounds-checked,
//! list recursion is capped, and corrupt structures produce warnings rather
//! than panics. Dirty hives can be reconciled in memory with their
//! transaction logs, and unallocated cells can be carved for deleted keys.

pub mod base;
pub mod carve;
pub mod error;
pub mod hive;
pub mod log;
pub mod marvin;
pub mod records;
pub mod writer;

pub use base::BaseBlock;
pub use error::{RegfError, Result};
pub use hive::{Hive, Key, OpenOptions, Value};
pub use records::{data_type_name, KeyNode, ValueNode};

/// Returns true if `path` starts with the `regf` signature and is a primary
/// hive (not a transaction log).
pub fn is_primary_hive(path: &std::path::Path) -> bool {
    use std::io::Read;
    let mut buf = [0u8; 32];
    match std::fs::File::open(path).and_then(|mut f| f.read_exact(&mut buf)) {
        Ok(()) => {
            &buf[0..4] == b"regf" && u32::from_le_bytes([buf[28], buf[29], buf[30], buf[31]]) == 0
        }
        Err(_) => false,
    }
}
