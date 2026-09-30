#!/usr/bin/env bash
#
# Bashly Triage - Linux Live-Response / DFIR Triage Collector
# Author: Amine "Alan" Ben Amara
# License: MIT
#
# Collects volatile and non-volatile forensic artifacts from a live Linux
# host for incident-response triage, hashes everything for chain of custody,
# and runs a lightweight anomaly-flagging pass over what it finds.
#
# LEGAL: Only run this against systems you own or are explicitly authorized
# to investigate. Unauthorized access to computer systems is illegal in most
# jurisdictions. This tool performs read-only collection; it does not
# remediate, kill processes, or modify the target system.

set -uo pipefail
umask 077

CASE_ID="UNSET"
EXAMINER="$(whoami)"
OUTDIR=""
QUICK=0
NO_ARCHIVE=0
NO_HASH=0
SCRIPT_VERSION="1.0.0"
START_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
HOSTNAME_SAFE="$(hostname 2>/dev/null | tr -cd '[:alnum:]._-')"
[ -z "$HOSTNAME_SAFE" ] && HOSTNAME_SAFE="unknown-host"
TIMESTAMP="$(date -u +%Y%m%d_%H%M%SZ)"

usage() {
  cat <<EOF
Bashly Triage v${SCRIPT_VERSION} — Linux DFIR triage collector

Usage: sudo ./triage.sh [options]

Options:
  -c, --case <id>       Case identifier (recommended, shows up in the report)
  -e, --examiner <name> Examiner name (default: current user)
  -o, --output <dir>    Output base directory (default: ./triage_output_<host>_<ts>)
  -q, --quick           Quick mode: skip the slow full-filesystem sweep
      --no-archive      Do not tar/gzip the output directory
      --no-hash         Skip SHA256 manifest generation
  -h, --help            Show this help

EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    -c|--case) CASE_ID="${2:-UNSET}"; shift 2;;
    -e|--examiner) EXAMINER="${2:-$EXAMINER}"; shift 2;;
    -o|--output) OUTDIR="${2:-}"; shift 2;;
    -q|--quick) QUICK=1; shift;;
    --no-archive) NO_ARCHIVE=1; shift;;
    --no-hash) NO_HASH=1; shift;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown option: $1" >&2; usage; exit 1;;
  esac
done

[ -z "$OUTDIR" ] && OUTDIR="./triage_output_${HOSTNAME_SAFE}_${TIMESTAMP}"
mkdir -p "$OUTDIR"/{system,users,processes,network,persistence,logs,filesystem,packages,kernel,analysis}

LOGFILE="$OUTDIR/collection.log"
FINDINGS="$OUTDIR/analysis/findings.txt"
touch "$LOGFILE" "$FINDINGS"

LOG_FROZEN=0
log() {
  local line="[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"
  echo "$line"
  [ "$LOG_FROZEN" -eq 0 ] && echo "$line" >> "$LOGFILE"
  return 0
}
flag() {
  echo "[FINDING] $*"
  echo "[FINDING] $*" >> "$FINDINGS"
  [ "$LOG_FROZEN" -eq 0 ] && echo "[FINDING] $*" >> "$LOGFILE"
  return 0
}

need_root_warning() {
  if [ "$(id -u)" -ne 0 ]; then
    log "WARNING: not running as root — shadow file, some /proc entries and full log access will be incomplete."
  fi
}

have() { command -v "$1" >/dev/null 2>&1; }


collect_system_info() {
  log "Collecting system information..."
  {
    echo "== hostname =="; hostname 2>/dev/null
    echo "== uname -a =="; uname -a 2>/dev/null
    echo "== uptime =="; uptime 2>/dev/null
    echo "== date =="; date 2>/dev/null; date -u 2>/dev/null
    echo "== /etc/os-release =="; cat /etc/os-release 2>/dev/null
    echo "== timezone =="; cat /etc/timezone 2>/dev/null; readlink -f /etc/localtime 2>/dev/null
  } > "$OUTDIR/system/system_info.txt" 2>>"$LOGFILE"
}

collect_users_sessions() {
  log "Collecting user and session data..."
  cp -p /etc/passwd "$OUTDIR/users/passwd" 2>/dev/null
  cp -p /etc/group "$OUTDIR/users/group" 2>/dev/null
  if [ "$(id -u)" -eq 0 ]; then
    cp -p /etc/shadow "$OUTDIR/users/shadow" 2>/dev/null
    cp -p /etc/sudoers "$OUTDIR/users/sudoers" 2>/dev/null
    cp -pr /etc/sudoers.d "$OUTDIR/users/sudoers.d" 2>/dev/null
  fi
  { who -a 2>/dev/null; echo "---"; w 2>/dev/null; } > "$OUTDIR/users/current_sessions.txt"
  last -Faixw 2>/dev/null > "$OUTDIR/users/last_logins.txt"
  lastlog 2>/dev/null > "$OUTDIR/users/lastlog.txt"
  lastb 2>/dev/null > "$OUTDIR/users/failed_logins.txt"

  : > "$OUTDIR/users/bash_histories.txt"
  while IFS=: read -r uname _ _ _ _ home _; do
    for hfile in "$home/.bash_history" "$home/.zsh_history"; do
      if [ -r "$hfile" ]; then
        { echo "=== $uname : $hfile ==="; cat "$hfile"; echo; } >> "$OUTDIR/users/bash_histories.txt"
      fi
    done
  done < /etc/passwd
}

collect_processes() {
  log "Collecting process information..."
  ps auxww > "$OUTDIR/processes/ps_snapshot.txt" 2>/dev/null || ps -ef > "$OUTDIR/processes/ps_snapshot.txt" 2>/dev/null
  have pstree && pstree -ap > "$OUTDIR/processes/pstree.txt" 2>/dev/null
  have lsof && lsof -n -P > "$OUTDIR/processes/lsof.txt" 2>/dev/null

  : > "$OUTDIR/processes/deleted_exe_procs.txt"
  for pid_dir in /proc/[0-9]*; do
    [ -d "$pid_dir" ] || continue
    pid="${pid_dir#/proc/}"
    exe_link="$(readlink "$pid_dir/exe" 2>/dev/null)"
    [ -z "$exe_link" ] && continue
    case "$exe_link" in
      *"(deleted)"*)
        echo "PID $pid -> $exe_link" >> "$OUTDIR/processes/deleted_exe_procs.txt"
        flag "Process $pid running from a deleted/unlinked binary: $exe_link"
        ;;
    esac
    case "$exe_link" in
      /tmp/*|/dev/shm/*|/var/tmp/*)
        flag "Process $pid executing from a world-writable temp path: $exe_link"
        ;;
    esac
  done
}

collect_network() {
  log "Collecting network state..."
  if have ss; then
    ss -tulnp > "$OUTDIR/network/listening_sockets.txt" 2>/dev/null
    ss -antp  > "$OUTDIR/network/all_tcp_conns.txt" 2>/dev/null
  elif have netstat; then
    netstat -tulnp > "$OUTDIR/network/listening_sockets.txt" 2>/dev/null
    netstat -antp  > "$OUTDIR/network/all_tcp_conns.txt" 2>/dev/null
  fi
  have arp && arp -a > "$OUTDIR/network/arp_cache.txt" 2>/dev/null
  ip addr show > "$OUTDIR/network/ip_addr.txt" 2>/dev/null
  ip route show > "$OUTDIR/network/ip_route.txt" 2>/dev/null
  cp -p /etc/hosts "$OUTDIR/network/hosts" 2>/dev/null
  cp -p /etc/resolv.conf "$OUTDIR/network/resolv.conf" 2>/dev/null
  have iptables && iptables -L -n -v > "$OUTDIR/network/iptables.txt" 2>/dev/null
  have nft && nft list ruleset > "$OUTDIR/network/nftables.txt" 2>/dev/null
}

collect_persistence() {
  log "Collecting persistence mechanisms..."
  : > "$OUTDIR/persistence/crontabs.txt"
  for udir in /var/spool/cron/crontabs /var/spool/cron; do
    if [ -d "$udir" ]; then
      for f in "$udir"/*; do
        [ -f "$f" ] && { echo "=== $f ==="; cat "$f"; } >> "$OUTDIR/persistence/crontabs.txt" 2>/dev/null
      done
    fi
  done
  for f in /etc/crontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/*; do
    [ -f "$f" ] && { echo "=== $f ==="; cat "$f"; echo; } >> "$OUTDIR/persistence/crontabs.txt" 2>/dev/null
  done
  grep -Ei '(curl|wget).*\|\s*(bash|sh)|base64 -d' "$OUTDIR/persistence/crontabs.txt" 2>/dev/null |
    while IFS= read -r line; do flag "Suspicious cron entry (pipe-to-shell/base64 pattern): $line"; done

  if have systemctl; then
    systemctl list-unit-files --type=service > "$OUTDIR/persistence/systemd_services.txt" 2>/dev/null
    systemctl list-units --type=service --state=running >> "$OUTDIR/persistence/systemd_services.txt" 2>/dev/null
  fi

  for f in /etc/rc.local /etc/profile /etc/bash.bashrc; do
    [ -f "$f" ] && cp -p "$f" "$OUTDIR/persistence/$(basename "$f")" 2>/dev/null
  done

  : > "$OUTDIR/persistence/ssh_authorized_keys.txt"
  while IFS=: read -r uname _ _ _ _ home _; do
    akfile="$home/.ssh/authorized_keys"
    if [ -r "$akfile" ]; then
      echo "=== $uname : $akfile ===" >> "$OUTDIR/persistence/ssh_authorized_keys.txt"
      cat "$akfile" >> "$OUTDIR/persistence/ssh_authorized_keys.txt"
      if find "$akfile" -mtime -30 2>/dev/null | grep -q .; then
        flag "SSH authorized_keys for $uname modified within the last 30 days: $akfile"
      fi
    fi
  done < /etc/passwd

  { env | grep -i LD_PRELOAD; cat /etc/ld.so.preload 2>/dev/null; } > "$OUTDIR/persistence/ld_preload.txt" 2>/dev/null
  [ -s "$OUTDIR/persistence/ld_preload.txt" ] && flag "LD_PRELOAD configured — common rootkit persistence technique, review ld_preload.txt"
}

collect_logs() {
  log "Collecting logs..."
  for f in /var/log/auth.log /var/log/secure /var/log/syslog /var/log/messages; do
    [ -f "$f" ] && cp -p "$f" "$OUTDIR/logs/$(basename "$f")" 2>/dev/null
  done
  have journalctl && journalctl -n 5000 --no-pager > "$OUTDIR/logs/journalctl_last5000.txt" 2>/dev/null
}

collect_filesystem_artifacts() {
  log "Collecting filesystem artifacts..."
  find / -xdev -type f -perm -4000 2>/dev/null > "$OUTDIR/filesystem/suid_files.txt"
  find / -xdev -type f -perm -2000 2>/dev/null > "$OUTDIR/filesystem/sgid_files.txt"

  if [ "$QUICK" -eq 0 ]; then
    find / -xdev -type f -mtime -2 2>/dev/null > "$OUTDIR/filesystem/modified_last_2_days.txt"
    find /tmp /var/tmp /dev/shm -xdev -type f 2>/dev/null > "$OUTDIR/filesystem/temp_dir_files.txt"
    find / -xdev -writable -type d 2>/dev/null > "$OUTDIR/filesystem/world_writable_dirs.txt"
  else
    log "Quick mode: skipping full filesystem sweep."
  fi
}

collect_packages() {
  log "Collecting installed package list..."
  have dpkg && dpkg -l > "$OUTDIR/packages/dpkg_list.txt" 2>/dev/null
  have rpm && rpm -qa > "$OUTDIR/packages/rpm_list.txt" 2>/dev/null
  [ -f /var/log/apt/history.log ] && cp -p /var/log/apt/history.log "$OUTDIR/packages/apt_history.log" 2>/dev/null
}

collect_kernel() {
  log "Collecting kernel/module info..."
  lsmod > "$OUTDIR/kernel/lsmod.txt" 2>/dev/null
  cat /proc/modules > "$OUTDIR/kernel/proc_modules.txt" 2>/dev/null
  have sysctl && sysctl -a > "$OUTDIR/kernel/sysctl.txt" 2>/dev/null
}

analyze_bash_history() {
  log "Scanning shell history for suspicious command patterns..."
  local hf="$OUTDIR/users/bash_histories.txt"
  [ -f "$hf" ] || return
  grep -Ein '(nc .*-e|/dev/tcp/|base64 -d|curl .*\| *(bash|sh)|wget .*\| *(bash|sh)|chmod \+x .*(tmp|shm)|python.* -c .*socket)' "$hf" |
    while IFS= read -r line; do flag "Suspicious shell history entry: $line"; done
}

generate_manifest() {
  if [ "$NO_HASH" -eq 1 ]; then log "Skipping hash manifest (--no-hash)."; return; fi
  if ! have sha256sum; then log "sha256sum not found, skipping manifest."; return; fi
  log "Generating SHA256 manifest for chain of custody..."
  ( cd "$OUTDIR" && find . -type f ! -name "manifest.sha256" -exec sha256sum {} \; ) > "$OUTDIR/manifest.sha256" 2>/dev/null
}

generate_case_report() {
  local report="$OUTDIR/CASE_REPORT.md"
  {
    echo "# Bashly Triage Case Report"
    echo
    echo "- **Case ID:** $CASE_ID"
    echo "- **Examiner:** $EXAMINER"
    echo "- **Host:** $(hostname 2>/dev/null)"
    echo "- **Collection start (UTC):** $START_TIME"
    echo "- **Collection end (UTC):** $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "- **Tool version:** Bashly Triage v${SCRIPT_VERSION}"
    echo "- **Run as root:** $( [ "$(id -u)" -eq 0 ] && echo yes || echo no )"
    echo
    echo "## Automated Findings"
    echo
    if [ -s "$FINDINGS" ]; then
      sed 's/^/- /' "$FINDINGS"
    else
      echo "No automated findings flagged. Manual review of raw artifacts is still recommended."
    fi
    echo
    echo "## Collected Artifact Categories"
    echo
    for d in "$OUTDIR"/*/; do
      cat_name="$(basename "$d")"
      [ "$cat_name" = "analysis" ] && continue
      count="$(find "$d" -type f | wc -l)"
      echo "- **$cat_name**: $count file(s)"
    done
    echo
    echo "## Chain of Custody"
    echo
    echo "SHA256 manifest: \`manifest.sha256\` (present unless --no-hash was used)."
    echo "Archive hash (if created): see \`<archive>.sha256\` alongside the tarball."
  } > "$report"
  log "Case report written to $report"
}

archive_output() {
  if [ "$NO_ARCHIVE" -eq 1 ]; then log "Skipping archive step (--no-archive)."; return; fi
  local archive_name
  archive_name="${OUTDIR%/}.tar.gz"
  log "Archiving output to $archive_name..."
  tar -czf "$archive_name" -C "$(dirname "$OUTDIR")" "$(basename "$OUTDIR")" 2>>"$LOGFILE"
  have sha256sum && sha256sum "$archive_name" > "${archive_name}.sha256"
  log "Archive complete: $archive_name"
}

main() {
  log "Bashly Triage v${SCRIPT_VERSION} starting. Case: $CASE_ID | Examiner: $EXAMINER"
  need_root_warning
  collect_system_info
  collect_users_sessions
  collect_processes
  collect_network
  collect_persistence
  collect_logs
  collect_filesystem_artifacts
  collect_packages
  collect_kernel
  analyze_bash_history
  generate_case_report
  LOG_FROZEN=1
  generate_manifest
  archive_output
  log "Collection complete. Output directory: $OUTDIR"
}

main
