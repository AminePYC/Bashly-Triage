# Bashly Triage

A single-file bash tool for **live-response / DFIR triage** on Linux hosts. Point it at a box during an incident, and it collects volatile and non-volatile forensic artifacts, hashes everything for chain of custody, and runs a lightweight anomaly-flagging pass — no dependencies beyond standard coreutils and common Linux admin tools.

Built as a portfolio project for SOC Analyst / Threat Intelligence work.

## Why this exists

Most "IR triage script" repos on GitHub are either a wall of unstructured `cat` commands, or a heavyweight Python tool with a dependency list. Bashly Triage aims for the middle ground a junior analyst is actually likely to need at 2am on someone else's server: one script, no install step, structured output, and an auto-generated findings list so you know where to start looking before you've opened a single file.

## What it collects

| Category | Artifacts |
|---|---|
| System | hostname, `uname -a`, uptime, OS release, timezone |
| Users & sessions | passwd/group/shadow, sudoers, `last`/`lastb`/`lastlog`, current sessions, bash/zsh history for every user |
| Processes | full `ps` snapshot, process tree, open files (`lsof`), processes running from a deleted binary or from `/tmp`, `/dev/shm`, `/var/tmp` |
| Network | listening sockets, established connections, ARP cache, routes, `/etc/hosts`, `/etc/resolv.conf`, firewall rules |
| Persistence | all crontabs, systemd services, `rc.local`, profile scripts, SSH `authorized_keys` (flagged if modified in the last 30 days), `LD_PRELOAD` |
| Logs | `auth.log`/`secure`, `syslog`/`messages`, last 5000 journalctl entries |
| Filesystem | SUID/SGID binaries, files modified in the last 2 days, world-writable directories, contents of temp dirs |
| Packages | installed package list (`dpkg`/`rpm`), apt history |
| Kernel | loaded modules, `sysctl -a` |

## Automated findings

While collecting, it flags things worth checking first:
- Processes executing from a deleted/unlinked binary, or from a world-writable temp path
- Cron entries matching a pipe-to-shell or `base64 -d` pattern
- `LD_PRELOAD` set (common rootkit persistence technique)
- SSH `authorized_keys` files modified in the last 30 days
- Shell history containing reverse-shell, `/dev/tcp`, or base64-decode-and-execute patterns

Findings land in `analysis/findings.txt` and at the top of the generated `CASE_REPORT.md` — they're a starting point for manual review, not a verdict.

## Usage

```bash
sudo ./triage.sh -c CASE-2026-014 -e "Alan"
```

```
Options:
  -c, --case <id>       Case identifier (recommended, shows up in the report)
  -e, --examiner <name> Examiner name (default: current user)
  -o, --output <dir>    Output base directory (default: ./triage_output_<host>_<ts>)
  -q, --quick           Quick mode: skip the slow full-filesystem sweep
      --no-archive      Do not tar/gzip the output directory
      --no-hash         Skip SHA256 manifest generation
  -h, --help             Show help
```

Run as root for full artifact access (the shadow file, some `/proc` entries, and complete log access all need it). It will still run as a normal user and warn you about what it couldn't reach.

## Output

```
triage_output_<host>_<timestamp>/
├── system/  users/  processes/  network/  persistence/  logs/  filesystem/  packages/  kernel/
├── analysis/findings.txt
├── collection.log
├── manifest.sha256          # SHA256 of every collected file — chain of custody
└── CASE_REPORT.md           # case metadata, findings, per-category file counts
```

The whole directory is also tarred and SHA256-hashed (`<output>.tar.gz` + `.sha256`) unless `--no-archive` is passed.

## Design notes / limitations

- **Read-only by design.** It never kills a process, deletes a file, or modifies configuration — it only collects and reports. Safe to run on a system you still need to keep operational while you investigate.
- **Linux only.** It relies on `/proc`, `/etc/shadow`, `systemctl`, etc. — no macOS/Windows support.
- **Not a memory dump.** It captures process/network state from `/proc` and standard tools, not a full RAM image. Pair it with something like LiME if you need one.
- **Live system caveat.** Like any live-response tool, running it changes some timestamps and process state on the host (it *is* a process itself). For disk-image-only forensics you'd use a different workflow entirely — this is for "I need to know what's happening on this box right now."

## Roadmap ideas

- YARA integration: scan flagged binaries/temp files if `yara` is present
- JSON output mode for ingestion into a SIEM or case-management tool
- Optional `debsums`/`rpm -V` integrity check against package manager checksums
- A companion Python script to turn `CASE_REPORT.md` findings into a MITRE ATT&CK-tagged summary

## Legal

Only run this against systems you own or are explicitly authorized to investigate. Unauthorized access to computer systems is illegal in most jurisdictions.

## License

MIT — see `LICENSE`.
