use thiserror::Error;

#[derive(Debug, Error)]
pub enum RegfError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("not a registry hive (missing 'regf' signature)")]
    BadSignature,
    #[error("file too small to be a registry hive ({0} bytes)")]
    TooSmall(usize),
    #[error("cell offset 0x{0:x} is outside hive bins data")]
    OffsetOutOfRange(u32),
    #[error("invalid cell at offset 0x{offset:x}: {reason}")]
    BadCell { offset: u32, reason: String },
    #[error("expected '{expected}' record at offset 0x{offset:x}, found {found:?}")]
    BadRecord {
        offset: u32,
        expected: &'static str,
        found: [u8; 2],
    },
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, RegfError>;
