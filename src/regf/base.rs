//! Registry base block (file header).

use super::error::{RegfError, Result};
use crate::util::bytes::{u32_at, u64_at, utf16le_lossy};
use crate::util::Timestamp;
use serde::Serialize;

pub const BASE_BLOCK_SIZE: usize = 4096;

#[derive(Debug, Clone, Serialize)]
pub struct BaseBlock {
    pub primary_seq: u32,
    pub secondary_seq: u32,
    #[serde(skip)]
    pub last_written_raw: u64,
    pub last_written: Option<Timestamp>,
    pub major_version: u32,
    pub minor_version: u32,
    /// 0 = primary, 1/2 = old-format log, 6 = new-format log.
    pub file_type: u32,
    pub file_format: u32,
    pub root_cell_offset: u32,
    pub hive_bins_data_size: u32,
    pub clustering_factor: u32,
    /// Partial path of the hive as recorded by the writer (debug aid; often
    /// contains `\??\C:\Users\<name>\ntuser.dat`).
    pub file_name: String,
    pub flags: u32,
    pub stored_checksum: u32,
    pub computed_checksum: u32,
    #[serde(skip)]
    pub raw: Vec<u8>,
}

impl BaseBlock {
    /// Parses a base block. `buf` may be shorter than 4096 bytes (log files
    /// only carry the first sector) but must hold at least 512 bytes.
    pub fn parse(buf: &[u8]) -> Result<BaseBlock> {
        if buf.len() < 512 {
            return Err(RegfError::TooSmall(buf.len()));
        }
        if &buf[0..4] != b"regf" {
            return Err(RegfError::BadSignature);
        }
        let r = |o| u32_at(buf, o).unwrap_or(0);
        let last_written_raw = u64_at(buf, 12).unwrap_or(0);
        let name_end = buf[48..112]
            .chunks_exact(2)
            .position(|c| c == [0, 0])
            .map(|p| 48 + p * 2)
            .unwrap_or(112);
        let mut raw = buf[..buf.len().min(BASE_BLOCK_SIZE)].to_vec();
        raw.resize(BASE_BLOCK_SIZE, 0);
        Ok(BaseBlock {
            primary_seq: r(4),
            secondary_seq: r(8),
            last_written_raw,
            last_written: Timestamp::from_filetime(last_written_raw),
            major_version: r(20),
            minor_version: r(24),
            file_type: r(28),
            file_format: r(32),
            root_cell_offset: r(36),
            hive_bins_data_size: r(40),
            clustering_factor: r(44),
            file_name: utf16le_lossy(&buf[48..name_end]),
            flags: r(144),
            stored_checksum: r(508),
            computed_checksum: checksum(&buf[..508]),
            raw,
        })
    }

    pub fn checksum_valid(&self) -> bool {
        self.stored_checksum == self.computed_checksum
    }

    /// A hive needs recovery when its checksum is wrong or the sequence
    /// numbers disagree (a write was interrupted or not yet reconciled).
    pub fn is_dirty(&self) -> bool {
        !self.checksum_valid() || self.primary_seq != self.secondary_seq
    }

    pub fn is_log(&self) -> bool {
        matches!(self.file_type, 1 | 2 | 6)
    }

    /// Writes updated sequence numbers / size back into the raw copy and
    /// recomputes the checksum (used after log replay).
    pub fn set_recovered(&mut self, seq: u32, hive_bins_data_size: u32) {
        self.primary_seq = seq;
        self.secondary_seq = seq;
        self.hive_bins_data_size = hive_bins_data_size;
        self.file_type = 0;
        self.raw[4..8].copy_from_slice(&seq.to_le_bytes());
        self.raw[8..12].copy_from_slice(&seq.to_le_bytes());
        self.raw[28..32].copy_from_slice(&0u32.to_le_bytes());
        self.raw[40..44].copy_from_slice(&hive_bins_data_size.to_le_bytes());
        let c = checksum(&self.raw[..508]);
        self.raw[508..512].copy_from_slice(&c.to_le_bytes());
        self.stored_checksum = c;
        self.computed_checksum = c;
    }
}

/// XOR-32 checksum over the first 508 bytes of the base block.
pub fn checksum(b: &[u8]) -> u32 {
    let mut c = 0u32;
    for chunk in b[..508.min(b.len())].chunks_exact(4) {
        c ^= u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    match c {
        0xFFFF_FFFF => 0xFFFF_FFFE,
        0 => 1,
        v => v,
    }
}
