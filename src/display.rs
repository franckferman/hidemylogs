/// Display and formatting utilities.

use colored::Colorize;
use crate::utmp::UtmpRecord;
use crate::lastlog::LastlogRecord;

pub fn print_banner() {
    let banner = r#"
 _     _     _                       _
| |__ (_) __| | ___ _ __ ___  _   _| | ___   __ _ ___
| '_ \| |/ _` |/ _ \ '_ ` _ \| | | | |/ _ \ / _` / __|
| | | | | (_| |  __/ | | | | | |_| | | (_) | (_| \__ \
|_| |_|_|\__,_|\___|_| |_| |_|\__, |_|\___/ \__, |___/
                               |___/         |___/
"#;
    println!("{}", banner.red());
}

pub fn print_utmp_records(records: &[UtmpRecord]) {
    println!(
        "{:<16} {:<14} {:<24} {:<22} {:<8} {}",
        "Username".bold(),
        "Terminal".bold(),
        "From".bold(),
        "Timestamp".bold(),
        "Type".bold(),
        "PID".bold()
    );
    println!("{}", "-".repeat(96));

    for rec in records {
        if !rec.is_login() {
            continue;
        }

        let type_colored = match rec.ut_type() {
            super::utmp::UT_USER_PROCESS => rec.type_str().green(),
            super::utmp::UT_DEAD_PROCESS => rec.type_str().dimmed(),
            _ => rec.type_str().normal(),
        };

        println!(
            "{:<16} {:<14} {:<24} {:<22} {:<8} {}",
            rec.user(),
            rec.line(),
            rec.host(),
            rec.timestamp(),
            type_colored,
            rec.pid()
        );
    }
}

pub fn print_lastlog_records(records: &[LastlogRecord]) {
    println!(
        "{:<8} {:<14} {:<24} {}",
        "UID".bold(),
        "Terminal".bold(),
        "From".bold(),
        "Last Login".bold()
    );
    println!("{}", "-".repeat(70));

    for rec in records {
        if rec.is_empty() {
            continue;
        }
        println!(
            "{:<8} {:<14} {:<24} {}",
            rec.uid,
            rec.line(),
            rec.host(),
            rec.timestamp_str()
        );
    }
}

pub fn print_wipe_result(count: usize, source: &str) {
    if count > 0 {
        println!("{} {} record(s) wiped from {}", "[+]".green(), count, source);
    } else {
        println!("{} No matching records found in {}", "[*]".yellow(), source);
    }
}
