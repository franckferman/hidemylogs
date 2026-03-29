/// utmp/wtmp/btmp binary record handling.
///
/// struct utmp on Linux x86_64:
///   type:    i16     (2 bytes)
///   pad:     [u8; 2] (2 bytes)
///   pid:     i32     (4 bytes)
///   line:    [u8; 32]
///   id:      [u8; 4]
///   user:    [u8; 32]
///   host:    [u8; 256]
///   exit:    [i16; 2] (4 bytes)  -- exit_status struct
///   session: i32     (4 bytes)
///   tv_sec:  i32     (4 bytes)
///   tv_usec: i32     (4 bytes)
///   addr_v6: [i32; 4] (16 bytes)
///   unused:  [u8; 20]
///   Total: 384 bytes

use std::fs;
use std::io::{self, Write};

pub const UTMP_RECORD_SIZE: usize = 384;
pub const UT_USER_PROCESS: i16 = 7;
pub const UT_DEAD_PROCESS: i16 = 8;

#[derive(Debug, Clone)]
pub struct UtmpRecord {
    pub raw: [u8; UTMP_RECORD_SIZE],
}

impl UtmpRecord {
    pub fn ut_type(&self) -> i16 {
        i16::from_le_bytes([self.raw[0], self.raw[1]])
    }

    pub fn pid(&self) -> i32 {
        i32::from_le_bytes([self.raw[4], self.raw[5], self.raw[6], self.raw[7]])
    }

    pub fn line(&self) -> String {
        extract_string(&self.raw[8..40])
    }

    pub fn user(&self) -> String {
        extract_string(&self.raw[44..76])
    }

    pub fn host(&self) -> String {
        extract_string(&self.raw[76..332])
    }

    pub fn tv_sec(&self) -> i32 {
        i32::from_le_bytes([self.raw[340], self.raw[341], self.raw[342], self.raw[343]])
    }

    pub fn timestamp(&self) -> String {
        let ts = self.tv_sec() as i64;
        if ts == 0 {
            return "never".to_string();
        }
        chrono::DateTime::from_timestamp(ts, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_else(|| format!("{}", ts))
    }

    pub fn type_str(&self) -> &str {
        match self.ut_type() {
            UT_USER_PROCESS => "LOGIN",
            UT_DEAD_PROCESS => "LOGOUT",
            1 => "RUN_LVL",
            2 => "BOOT_TIME",
            _ => "OTHER",
        }
    }

    pub fn matches_user(&self, username: &str) -> bool {
        self.user() == username
    }

    pub fn matches_host(&self, host: &str) -> bool {
        self.host() == host
    }

    pub fn is_login(&self) -> bool {
        self.ut_type() == UT_USER_PROCESS || self.ut_type() == UT_DEAD_PROCESS
    }

}

fn extract_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

/// Read all utmp records from a file.
pub fn read_records(path: &str) -> io::Result<Vec<UtmpRecord>> {
    let data = fs::read(path)?;
    let mut records = Vec::new();

    for chunk in data.chunks_exact(UTMP_RECORD_SIZE) {
        let mut raw = [0u8; UTMP_RECORD_SIZE];
        raw.copy_from_slice(chunk);
        records.push(UtmpRecord { raw });
    }

    Ok(records)
}

/// Write records back to file, preserving original file metadata.
pub fn write_records(path: &str, records: &[UtmpRecord]) -> io::Result<()> {
    let meta = fs::metadata(path)?;
    let mut file = fs::OpenOptions::new().write(true).truncate(true).open(path)?;

    for rec in records {
        file.write_all(&rec.raw)?;
    }

    // Restore original file size if we removed records
    let new_len = (records.len() * UTMP_RECORD_SIZE) as u64;
    if new_len < meta.len() {
        file.set_len(new_len)?;
    }

    Ok(())
}
