<div align="center">

# hidemylogs

**Surgical \*nix log cleaner** - selectively erase access records from lastlog, wtmp, btmp, and utmp while preserving file metadata.

[![Stars](https://img.shields.io/github/stars/franckferman/hidemylogs?style=flat-square&color=c0392b)](https://github.com/franckferman/hidemylogs/stargazers)
![](https://img.shields.io/badge/Rust-CE422B?style=flat-square&logo=rust&logoColor=white)
![](https://img.shields.io/badge/License-AGPL--3.0-blue?style=flat-square)

</div>

---

## Overview

hidemylogs is a modern Rust rewrite of [hidemyass](https://github.com/evilpan/hidemyass) (2016). It removes individual log records from Linux authentication databases without deleting the entire file, preserving file permissions, ownership, and timestamps.

Three subcommands:
- **`print`** - Read and display records from utmp, wtmp, btmp, and lastlog
- **`wipe`** - Remove records matching a username, IP, or time range filter
- **`forge`** - Overwrite a lastlog record with a fake timestamp, terminal, and host

All operations support `--dry-run` to preview changes without modifying files.

---

## How It Works

### What gets modified

Linux tracks authentication events across four binary databases:

| File | Format | Content | Read by |
|---|---|---|---|
| `/var/run/utmp` | struct utmp (384 B) | Currently logged-in users | `who`, `w`, `finger` |
| `/var/log/wtmp` | struct utmp (384 B) | Full login/logout history | `last` |
| `/var/log/btmp` | struct utmp (384 B) | Failed login attempts | `lastb` |
| `/var/log/lastlog` | struct lastlog (292 B) | Last login per UID | `lastlog` |

hidemylogs operates directly on these binary files using `struct` layouts, reading and rewriting individual records without shell commands or external tools.

**`wipe`** removes matching records from utmp/wtmp/btmp by reconstructing the file without them. For lastlog, it zeroes the record at the target UID offset.

**`forge`** overwrites a specific lastlog record at `offset = UID * 292` with attacker-supplied timestamp, terminal, and hostname.

### File metadata preservation

After writing, hidemylogs restores the original `atime` and `mtime` using `utimensat`. This prevents file integrity monitors from flagging the modification based on timestamp change alone. The file size changes only if records are removed from utmp/wtmp/btmp (inevitable when deleting records from a sequential file).

### Why Rust, not a shell script

This is a deliberate OPSEC choice:

| Aspect | Shell script / Python | Compiled binary |
|---|---|---|
| **Command history** | Every `sed`, `dd`, `truncate` logged in `.bash_history` | Single `execve` in history |
| **auditd trace** | Multiple syscalls per operation, each logged separately | One process, direct `read`/`write`/`lseek` syscalls |
| **Process visibility** | `ps` shows `python3 cleaner.py --ip 1.2.3.4` in cleartext | `ps` shows `hidemylogs` only (args visible but no interpreter) |
| **Disk artifacts** | Script file persists on disk (`.py`, `.sh`) | Binary can run from `/dev/shm` (tmpfs) and be deleted |
| **Dependencies** | Requires Python/Bash interpreter on target | musl build: zero runtime deps, drop and run |

A compiled binary reduces the forensic footprint to a single `execve` syscall. No interpreter spawning, no child processes, no shell built-in logging. The musl-linked static binary can be deployed to `/dev/shm`, executed, and removed - leaving no file on persistent storage.

### MITRE ATT&CK

| Technique | ID | Relevance |
|---|---|---|
| Indicator Removal: Clear Linux or Mac System Logs | T1070.002 | Direct purpose of the tool |
| Indicator Removal: Timestomp | T1070.006 | `forge` modifies lastlog timestamps |
| Indicator Removal: Clear Command History | T1070.003 | Binary execution avoids shell history artifacts |

---

## Build

```bash
git clone https://github.com/franckferman/hidemylogs.git
cd hidemylogs
cargo build --release
```

Binary: `target/release/hidemylogs` (~600 KB, optimized + stripped).

Pre-built binaries for x86_64 (glibc), x86_64 (musl/static), and aarch64 are available in [Releases](https://github.com/franckferman/hidemylogs/releases). The musl build has zero runtime dependencies - drop and run on any Linux.

---

## Test Samples

Sample log files are included for safe testing without touching system logs:

```bash
# Generate samples (or use the pre-built ones in samples/)
python3 scripts/generate_samples.py

# Print all sources from the compromised scenario
./hidemylogs print \
  -u samples/compromised.utmp \
  -w samples/compromised.wtmp \
  -b samples/compromised.btmp \
  -l samples/compromised.lastlog

# Dry-run wipe of attacker IP
./hidemylogs wipe \
  -w samples/compromised.wtmp \
  -b samples/compromised.btmp \
  -a 185.220.101.34 \
  -s wb --dry-run
```

The scenario simulates: brute force from Tor exit node, root compromise, backdoor account, lateral movement.

---

## Usage

### `print` - Display log records

```
hidemylogs print [OPTIONS]

Options:
  -u, --utmp <PATH>        utmp file     [default: /var/run/utmp]
  -w, --wtmp <PATH>        wtmp file     [default: /var/log/wtmp]
  -b, --btmp <PATH>        btmp file     [default: /var/log/btmp]
  -l, --lastlog <PATH>     lastlog file  [default: /var/log/lastlog]
  -s, --sources <SOURCES>  Sources to display: u/w/b/l or any combination [default: uwbl]
```

```bash
# All sources
sudo ./hidemylogs print

# Only wtmp and lastlog
sudo ./hidemylogs print -s wl

# Only btmp (failed logins)
sudo ./hidemylogs print -s b

# Custom paths
./hidemylogs print -w /path/to/wtmp -l /path/to/lastlog -s wl
```

### `wipe` - Remove matching records

```
hidemylogs wipe [OPTIONS]

Options:
  -u, --utmp <PATH>        utmp file     [default: /var/run/utmp]
  -w, --wtmp <PATH>        wtmp file     [default: /var/log/wtmp]
  -b, --btmp <PATH>        btmp file     [default: /var/log/btmp]
  -l, --lastlog <PATH>     lastlog file  [default: /var/log/lastlog]
  -s, --sources <SOURCES>  Sources to wipe [default: uwbl]
  -n, --name <USER>        Filter by username
  -a, --address <IP>       Filter by IP/hostname
  -t, --time <RANGE>       Filter by time range (HH:MM-HH:MM)
      --and                All filters must match (default: any matches)
      --dry-run            Preview without modifying files
```

```bash
# Always dry-run first
sudo ./hidemylogs wipe -a 185.220.101.34 --dry-run

# Wipe all records from an IP
sudo ./hidemylogs wipe -a 185.220.101.34

# Wipe by username
sudo ./hidemylogs wipe -n root

# Wipe only from wtmp and btmp
sudo ./hidemylogs wipe -a 185.220.101.34 -s wb

# Wipe by time range (all records between 03:00 and 04:00)
sudo ./hidemylogs wipe -t 03:00-04:00

# AND filter: IP + time range must both match
sudo ./hidemylogs wipe -a 185.220.101.34 -t 03:00-04:00 --and

# OR filter (default): matches name OR address
sudo ./hidemylogs wipe -n root -a 185.220.101.34

# AND filter: must be root AND from that IP
sudo ./hidemylogs wipe -n root -a 185.220.101.34 --and
```

After wiping, file atime and mtime are restored to their original values.

### `forge` - Fake a lastlog entry

```
hidemylogs forge [OPTIONS] --uid <UID> --time <TIME>

Options:
  -l, --lastlog <PATH>     lastlog file  [default: /var/log/lastlog]
      --uid <UID>          Target UID
  -t, --time <TIME>        Fake timestamp (YYYY-MM-DD HH:MM:SS)
      --line <TTY>         Fake terminal  [default: pts/0]
      --host <HOST>        Fake hostname/IP [default: ""]
      --dry-run            Preview without modifying
```

```bash
# Fake root's last login to look like a normal admin session
sudo ./hidemylogs forge --uid 0 -t "2026-03-15 09:30:00" --line pts/0 --host 10.0.1.50

# Preview
sudo ./hidemylogs forge --uid 0 -t "2026-03-15 09:30:00" --dry-run
```

### Global flags

```bash
# Suppress banner (scripting/pipelines)
sudo ./hidemylogs -q wipe -a 185.220.101.34

# Version
./hidemylogs --version
```

---

## Why hidemylogs

Modern rewrite of [hidemyass](https://github.com/evilpan/hidemyass) (2016, unmaintained).

|  | hidemyass | hidemylogs |
|---|---|---|
| **Language** | C (manual memory) | Rust (memory safe) |
| **Last update** | 2017 | Active |
| **CLI** | Flags only (`-uwbl -p -c`) | Subcommands (`print`, `wipe`, `forge`) |
| **Preview before action** | No | `--dry-run` on everything |
| **Filter by time** | No | `-t 03:00-04:00` |
| **Filter logic** | OR only | `--and` / OR |
| **Lastlog forge** | Timestamp only | Timestamp + terminal + host |
| **File timestamps** | atime/ctime preserved | atime + mtime preserved |
| **Scripting** | No | `-q` suppresses banner |
| **Test samples** | No | Included scenario with all log types |
| **Cross-compile** | Manual | CI builds x86_64, aarch64, musl |

---

## Defensive context

This tool exists to demonstrate what attackers can do post-exploitation. For defenders:

- **Remote log forwarding** (rsyslog, syslog-ng) is the only reliable defense
- **File integrity monitoring** (AIDE, Tripwire) detects modifications to log files
- **Cross-source correlation** reveals discrepancies when one source is tampered but not others
- **[LastLog-Audit](https://github.com/franckferman/LastLog-Audit)** is the detection counterpart to this tool - it parses lastlog, wtmp, and auth.log, cross-references all three sources, and includes a [forensic training lab](https://franckferman.github.io/LastLog-Audit/learn.html) with 9 attack scenarios

---

## Legal Disclaimer

This tool is provided for **authorized security assessments, red team engagements, and educational purposes only**. Unauthorized modification of system logs is illegal. You are solely responsible for your use of this tool.

---

## License

AGPL-3.0. See [LICENSE](LICENSE).
