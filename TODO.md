# TODO

## Text log cleaners
- [ ] `auth.log` / `secure` - regex-based line removal with timestamp preservation
- [ ] `kern.log`, `syslog`, `dmesg`, `messages` - generic syslog text cleaner
- [ ] `faillog` - binary cleaner (struct faillog)
- [ ] `maillog` - mail authentication traces

## System support
- [ ] systemd journal (`journalctl`) - binary log wipe
- [ ] ctime preservation via `utimensat`
- [ ] FreeBSD / OpenBSD utmpx compatibility

## Features
- [ ] `--backup` flag - save original file before modification
- [ ] `--regex` filter for text log cleaners
- [ ] JSON output mode for scripting integration
