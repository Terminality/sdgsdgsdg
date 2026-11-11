#!/bin/sh
# =============================================================================
# ID:       LX-31
# NAME:     Backup
# ROLE:     Linux  (wave 1, first 15 minutes)
# KIND:     readonly - writes only into the output folder, changes nothing
# VERSION:  1.0.0
#
# PURPOSE
#   Run FIRST, before any script that changes the box.  It gives you:
#     1. a restore point: one archive of the files that decide how the box
#        behaves (/etc, crontabs, web roots, account dotfiles and SSH keys),
#        so a fix that breaks a scored service can be put back in seconds
#     2. a hash list of every file in the archive, plus (unless --fast) of the
#        system programs and service units, so later you can prove which files
#        the red team changed (the change watch, LX-40, compares against it)
#     3. a snapshot of state that is not in files: firewall rules, running
#        services, listening ports, packages, routes, kernel settings
#   It can copy the archive off the box (--copy-to), which matters: a red
#   team that gets root can delete a backup kept on the same host.
#
# USAGE
#   sudo sh LX-31-backup.sh [--out DIR] [options]
#   Run as root.  As a normal user it still runs but cannot read /etc/shadow,
#   other users' files or root-only configs; the summary says how many paths
#   were unreadable.
#
# OPTIONS
#   --add PATH         also back up PATH (file or folder; repeat for more)
#   --webroot DIR      back up DIR as a web root (repeat; the usual web roots
#                      are included automatically)
#   --no-webroots      leave web roots out (use when they are huge; SV-14
#                      backs up databases separately)
#   --no-homes         leave out home-folder dotfiles and SSH keys
#   --fast             skip hashing system programs (saves 10-60 seconds)
#   --max-mb N         refuse to start if the backup would be larger than N MB
#                      (default 2048) - protects a small disk from filling up
#   --copy-to DEST     after the backup, copy it with scp to DEST, for example
#                      admin@10.0.0.5:/srv/backups/   (asks for a password if
#                      no key is set up)
#   --help             this text plus the common options
#
# OUTPUTS  (under --out, in LX-31_<host>_<UTC time>/)
#   backup.tar.gz      the archive; paths inside are relative to / (etc/passwd)
#   backup.tar.gz.sha256  hash of the archive, to check a copy is intact
#   files.sha256       sha256 of every file in the archive ("hash  /path")
#   system.sha256      sha256 of system programs and service units (not archived)
#   contents.txt       the archive's file list
#   included.csv       path,kind,size_kb,status  (what was asked for and what happened)
#   raw/               state snapshots: firewall rules, services, ports,
#                      packages, routes, addresses, kernel settings, mounts
#   summary.txt        what was saved, sizes, and how to restore a file
#   RESTORE.txt        restore commands for this backup
#
# WHAT IT CHANGES
#   Nothing on the host.  It reads files and runs read-only commands, and
#   writes only into the output folder (created with mode 700).
#
#   SECURITY NOTE: the archive contains /etc/shadow, SSH host keys and any
#   passwords in config files.  That is the point of a restore point, but it
#   means the output folder and any copy must stay private.
#
# DEPENDS ON
#   tar, find, awk; gzip (falls back to an uncompressed .tar); sha256sum,
#   shasum, sha256 or openssl for hashes; scp only for --copy-to.
#
# TESTED ON
#   Ubuntu 24.04 under dash, bash, busybox sh, ksh93, mksh and yash, as root
#   and as a normal user.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - Databases are NOT safely backed up by copying their files while they run.
#     Use SV-14 for MySQL/MariaDB and PostgreSQL.
#   - Files that change while the archive is written (logs, sockets) can make
#     tar warn; the archive is still checked by listing it afterwards.
#   - Home folders are not copied whole: only top-level dotfiles and .ssh,
#     which is where shells, startup files and keys live.  Add a folder with
#     --add if its contents are scored.
#
# DEBUGGING
#   --debug shows every path, size estimate and tool choice.
#   tar's own messages are in the log file.
# =============================================================================

# >>> CCDC-LIB
# Development copy: find lib/lib.sh by walking up from this file.  The build
# step (tools/build.sh, LB-03) replaces this whole block with the library
# itself, so the built script is a single standalone file.
_cc_d=$(cd "$(dirname "$0")" && pwd)
while [ "$_cc_d" != "/" ] && [ ! -f "$_cc_d/lib/lib.sh" ]; do _cc_d=$(dirname "$_cc_d"); done
[ -f "$_cc_d/lib/lib.sh" ] || { echo "cannot find lib/lib.sh above $0" >&2; exit 3; }
. "$_cc_d/lib/lib.sh"
# <<< CCDC-LIB

usage() {
    cat <<'USAGE'
LX-31 Backup - archive the files that matter, hash them, snapshot the state
  sudo sh LX-31-backup.sh [options]

  --add PATH         also back up PATH (repeatable)
  --webroot DIR      back up DIR as a web root (repeatable)
  --no-webroots      leave web roots out
  --no-homes         leave out home-folder dotfiles and SSH keys
  --fast             skip hashing system programs
  --max-mb N         refuse if the backup would be larger than N MB (default 2048)
  --copy-to DEST     copy the result off the box with scp (user@host:/path/)
  --help             show this text

USAGE
    cc_usage_common
}

NL='
'
ADD=""; WEBROOTS=""; NO_WEB=0; NO_HOMES=0; FAST=0; MAXMB=2048; COPYTO=""
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --add)         [ $# -ge 2 ] || cc_die 2 "--add needs a path"
                       [ -e "$2" ] || cc_die 2 "--add: no such file or folder: $2"
                       ADD="$ADD$2$NL"; shift 2 ;;
        --webroot)     [ $# -ge 2 ] || cc_die 2 "--webroot needs a folder"
                       [ -d "$2" ] || cc_die 2 "--webroot: not a folder: $2"
                       WEBROOTS="$WEBROOTS$2$NL"; shift 2 ;;
        --no-webroots) NO_WEB=1; shift ;;
        --no-homes)    NO_HOMES=1; shift ;;
        --fast)        FAST=1; shift ;;
        --max-mb)      [ $# -ge 2 ] || cc_die 2 "--max-mb needs a number"; MAXMB=$2; shift 2 ;;
        --copy-to)     [ $# -ge 2 ] || cc_die 2 "--copy-to needs a destination like user@host:/path/"; COPYTO=$2; shift 2 ;;
        --help|-h)     usage; exit 0 ;;
        *)             cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
case "$MAXMB" in ''|*[!0-9]*) cc_die 2 "--max-mb needs a whole number" ;; esac

cc_init "LX-31" "Backup" readonly
cc_need tar
cc_need find
cc_use_run_dir
cc_detect_os
W="$CC_RUN_DIR/.work"
mkdir -p "$W" || cc_die 3 "cannot create $W"
IS_ROOT=0
cc_is_root && IS_ROOT=1
[ "$IS_ROOT" = 1 ] || cc_warn "not running as root: /etc/shadow, root's files and other users' keys will be missing from the backup"
INC=$(cc_csv_new included "path,kind,size_kb,status")

# ---- 1. Decide what goes in ---------------------------------------------------
# $W/want holds "kind|absolute path" lines.  Missing paths are recorded as
# "absent" in included.csv and skipped, so the same command works on any distro.
: >"$W/want"
want() { printf '%s|%s\n' "$1" "$2" >>"$W/want"; }

# Configuration and scheduled jobs.  /etc holds nearly all of it on Linux;
# /usr/local/etc is where BSD and hand-built software keep theirs.
for _p in /etc /usr/local/etc /var/spool/cron /var/spool/anacron /var/spool/at /var/spool/incron \
          /var/named /var/lib/bind /root/.ssh; do
    want config "$_p"
done
# root's own dotfiles (shell startup files are a classic place to hide a
# command) - files only, not folders, so a big /root does not swell the backup.
if [ -d /root ]; then
    find /root -xdev -maxdepth 1 -type f -name '.*' 2>/dev/null >"$W/rootdots"
    while IFS= read -r _f; do want home "$_f"; done <"$W/rootdots"
fi
# Every account's top-level dotfiles and .ssh folder.
if [ "$NO_HOMES" = 0 ]; then
    awk -F: '$6 != "" && $6 != "/" && $6 != "/root" { print $6 }' /etc/passwd 2>/dev/null | sort -u >"$W/homes"
    while IFS= read -r _h; do
        [ -d "$_h" ] || continue
        find "$_h" -xdev -maxdepth 1 -type f -name '.*' 2>/dev/null >"$W/dots"
        while IFS= read -r _f; do want home "$_f"; done <"$W/dots"
        [ -d "$_h/.ssh" ] && want home "$_h/.ssh"
    done <"$W/homes"
fi
# Web roots: the usual places plus any given.  Folders inside one already
# listed are dropped so nothing is stored twice.
if [ "$NO_WEB" = 0 ]; then
    {
        for _d in /var/www /srv/www /srv/http /usr/share/nginx/html /usr/local/www /opt/lampp/htdocs; do printf '%s\n' "$_d"; done
        # Web roots named in the Apache and nginx configs (DocumentRoot, root,
        # alias).  A rough read: anything it gets wrong is just a path that
        # does not exist and is skipped.
        for _c in /etc/apache2 /etc/httpd /usr/local/etc/apache24 /etc/nginx /usr/local/etc/nginx; do
            [ -d "$_c" ] || continue
            grep -rhiE '^[[:space:]]*(DocumentRoot|root|alias)[[:space:]]' "$_c" 2>/dev/null |
                awk '{ v = $NF; if ($1 ~ /^[Aa]lias$/ && NF >= 3) v = $3; gsub(/[";]/, "", v); if (v ~ /^\//) print v }'
        done
        printf '%s' "$WEBROOTS"
    } | sed 's|/*$||' | grep . | sort -u |
        awk '{ for (k in keep) if (index($0, k "/") == 1) next; keep[$0] = 1; print }' >"$W/webroots"
    while IFS= read -r _d; do want webroot "$_d"; done <"$W/webroots"
fi
# Extra paths from --add.
printf '%s' "$ADD" | grep . >"$W/add" 2>/dev/null
while IFS= read -r _p; do want added "$(cc_abspath "$_p")"; done <"$W/add"

# ---- 2. Check each path and estimate the size ---------------------------------
# du -sk is in every Unix.  Unreadable parts make du complain; that is
# counted, not fatal.
: >"$W/paths"
_total_kb=0; _n_absent=0; _n_partial=0
sort -t'|' -k2,2 -u "$W/want" >"$W/want.sorted"
while IFS='|' read -r _k _p; do
    if [ ! -e "$_p" ]; then
        _n_absent=$((_n_absent + 1))
        cc_debug "absent: $_p"
        continue
    fi
    if [ ! -r "$_p" ]; then
        cc_csv_row "$INC" "$_p" "$_k" "" "unreadable"
        _n_partial=$((_n_partial + 1))
        continue
    fi
    _kb=$(du -sk "$_p" 2>"$W/du.err" | awk '{ print $1 }')
    _st=ok
    [ -s "$W/du.err" ] && { _st="partial (some files unreadable)"; _n_partial=$((_n_partial + 1)); }
    _total_kb=$((_total_kb + ${_kb:-0}))
    printf '%s\n' "$_p" >>"$W/paths"
    cc_csv_row "$INC" "$_p" "$_k" "${_kb:-0}" "$_st"
done <"$W/want.sorted"
[ -s "$W/paths" ] || cc_die 3 "nothing to back up (no readable paths found)"
_total_mb=$((_total_kb / 1024))
cc_info "about $_total_mb MB in $(grep -c . "$W/paths") paths"
if [ "$_total_mb" -gt "$MAXMB" ]; then
    cc_die 3 "the backup would be about $_total_mb MB, more than --max-mb $MAXMB. See included.csv for the big paths; use --no-webroots or a larger --max-mb"
fi
# Room on the disk that holds the output folder (df -P: POSIX columns).
_free_kb=$(df -Pk "$CC_RUN_DIR" 2>/dev/null | awk 'NR == 2 { print $4 }')
if [ -n "$_free_kb" ] && [ "$_free_kb" -lt "$_total_kb" ]; then
    cc_die 3 "not enough free space in $CC_OUT: need about $_total_mb MB, have $((_free_kb / 1024)) MB. Use --out on another disk, or --no-webroots"
fi

# ---- 3. Write the archive ------------------------------------------------------
# Paths are stored relative to / (tar -C / etc/passwd), so a restore can go
# back to / or to a scratch folder for comparing.  The path list becomes the
# argument list; a few hundred paths is far below any system's limit.
set --
while IFS= read -r _p; do set -- "$@" "${_p#/}"; done <"$W/paths"
ARCH="$CC_RUN_DIR/backup.tar.gz"
_z=gzip
if ! cc_have gzip; then ARCH="$CC_RUN_DIR/backup.tar"; _z=""; cc_warn "gzip not found: writing an uncompressed .tar"; fi
cc_info "writing $(basename "$ARCH")"
if [ -n "$_z" ]; then
    # The pipe hides tar's exit code, so tar's own status goes to a file.
    { tar -cf - -C / "$@" 2>>"$CC_LOG"; echo $? >"$W/tar.rc"; } | gzip -c >"$ARCH"
else
    tar -cf "$ARCH" -C / "$@" 2>>"$CC_LOG"; echo $? >"$W/tar.rc"
fi
chmod 600 "$ARCH" 2>/dev/null
_tar_rc=$(cat "$W/tar.rc" 2>/dev/null)
# GNU tar exits 1 when a file changed while being read; the archive is still
# fine.  Whatever the code, the real test is whether the archive can be read.
if [ -n "$_z" ]; then
    gzip -dc "$ARCH" 2>/dev/null | tar -tf - >"$CC_RUN_DIR/contents.txt" 2>/dev/null
else
    tar -tf "$ARCH" >"$CC_RUN_DIR/contents.txt" 2>/dev/null
fi
_n_in=$(grep -c . "$CC_RUN_DIR/contents.txt")
if [ "$_n_in" -eq 0 ]; then
    CC_N_FAIL=$((CC_N_FAIL + 1))
    cc_err "the archive could not be read back (tar exit ${_tar_rc:-?}) - see $CC_LOG"
else
    [ "${_tar_rc:-0}" = 0 ] || cc_warn "tar exited ${_tar_rc} (usually a file changed or was unreadable while archiving); the archive reads back fine with $_n_in entries"
fi
_arch_hash=$(cc_sha256 "$ARCH")
[ -n "$_arch_hash" ] && printf '%s  %s\n' "$_arch_hash" "$(basename "$ARCH")" >"$ARCH.sha256"

# ---- 4. Hash lists -------------------------------------------------------------
# hashes FILE PATH... -> "sha256  /path" lines for every regular file under the
# paths, appended to FILE.  Uses one batch tool where possible (fast); falls
# back to one call per file.
hashes() {
    _hf=$1; shift
    if cc_have sha256sum; then
        find "$@" -xdev -type f -exec sha256sum {} + 2>/dev/null >>"$_hf"
    elif cc_have shasum; then
        find "$@" -xdev -type f -exec shasum -a 256 {} + 2>/dev/null >>"$_hf"
    else
        find "$@" -xdev -type f 2>/dev/null >"$W/hashlist"
        while IFS= read -r _f; do
            _h=$(cc_sha256 "$_f") && printf '%s  %s\n' "$_h" "$_f" >>"$_hf"
        done <"$W/hashlist"
    fi
}
cc_info "hashing the backed-up files"
: >"$CC_RUN_DIR/files.sha256"
set --
while IFS= read -r _p; do set -- "$@" "$_p"; done <"$W/paths"
hashes "$CC_RUN_DIR/files.sha256" "$@"
_n_hash=$(grep -c . "$CC_RUN_DIR/files.sha256")
_n_sys=0
if [ "$FAST" = 0 ]; then
    cc_info "hashing system programs and service units"
    : >"$CC_RUN_DIR/system.sha256"
    set --
    for _d in /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /lib/systemd/system \
              /usr/lib/systemd/system /etc/systemd/system /usr/libexec; do
        # /bin is often a link to /usr/bin; skip links so nothing is hashed twice.
        [ -d "$_d" ] && [ ! -h "$_d" ] && set -- "$@" "$_d"
    done
    [ $# -gt 0 ] && hashes "$CC_RUN_DIR/system.sha256" "$@"
    _n_sys=$(grep -c . "$CC_RUN_DIR/system.sha256")
fi

# ---- 5. State that is not in files ---------------------------------------------
# Each command's output goes to raw/<name>.txt.  Missing tools are skipped.
cc_info "saving firewall rules, services, ports and other state"
snap() { _sn=$1; shift; cc_have "$1" && cc_save "$_sn" "$@"; }
snap firewall_iptables iptables-save
snap firewall_ip6tables ip6tables-save
snap firewall_nft nft list ruleset
snap firewall_ufw ufw status verbose
snap firewall_firewalld firewall-cmd --list-all-zones
snap firewall_pf pfctl -sr
if [ "$CC_INIT" = systemd ]; then
    snap services systemctl list-unit-files --no-pager
    snap services_running systemctl list-units --type=service --no-pager
    snap timers systemctl list-timers --all --no-pager
elif cc_have rc-status; then snap services rc-status -a
elif cc_have service; then snap services service --status-all
fi
if cc_have ss; then snap ports ss -tulpn; else snap ports netstat -an; fi
if cc_have ip; then
    snap addresses ip addr
    snap routes ip route
else
    snap addresses ifconfig -a
    snap routes netstat -rn
fi
case "$CC_PKG" in
    apt)    snap packages dpkg -l ;;
    dnf|yum|zypper) snap packages rpm -qa ;;
    apk)    snap packages apk info -v ;;
    pacman) snap packages pacman -Q ;;
    pkg)    snap packages pkg info ;;
esac
snap kernel_settings sysctl -a
snap mounts mount
snap users getent passwd
snap groups getent group
snap crontab_root crontab -l

# ---- 6. Copy off the box -----------------------------------------------------
_copied=""
if [ -n "$COPYTO" ]; then
    cc_need scp
    cc_info "copying to $COPYTO (scp may ask for a password)"
    if scp -q -o ConnectTimeout=15 "$ARCH" "$ARCH.sha256" "$CC_RUN_DIR/files.sha256" "$COPYTO" 2>>"$CC_LOG"; then
        _copied=yes
        cc_info "copied to $COPYTO"
    else
        _copied=no
        CC_N_FAIL=$((CC_N_FAIL + 1))
        cc_err "copy to $COPYTO FAILED - the backup is only on this box (see $CC_LOG)"
    fi
fi

# ---- 7. Restore notes and summary ------------------------------------------------
_an=$(basename "$ARCH")
if [ -n "$_z" ]; then _x="tar -xzf"; _t="tar -tzf"; else _x="tar -xf"; _t="tar -tf"; fi
cat >"$CC_RUN_DIR/RESTORE.txt" <<EOF
Restoring from $ARCH
Made on $CC_HOST at $CC_TS by LX-31.  Paths inside are relative to / (etc/passwd).

Check the archive first (the hash must match):
  cd $CC_RUN_DIR && sha256sum -c $_an.sha256

Find a file:
  $_t $_an | grep sshd_config

Put back ONE file (example: the SSH server config):
  cp -p /etc/ssh/sshd_config /etc/ssh/sshd_config.before-restore
  $_x $_an -C / etc/ssh/sshd_config

Compare without touching the system (unpack into a scratch folder):
  mkdir /tmp/restore && $_x $_an -C /tmp/restore etc/ssh
  diff -r /tmp/restore/etc/ssh /etc/ssh

Which files changed since this backup (prints only the ones that differ;
this form works with GNU, busybox and BSD-style sha256sum):
  sha256sum -c $CC_RUN_DIR/files.sha256 2>/dev/null | grep -v ': OK\$'
  sha256sum -c $CC_RUN_DIR/system.sha256 2>/dev/null | grep -v ': OK\$'

Firewall rules as they were (if iptables was in use):
  iptables-restore < $CC_RUN_DIR/raw/firewall_iptables.txt
  (nftables: nft -f $CC_RUN_DIR/raw/firewall_nft.txt after 'nft flush ruleset')

Do NOT restore all of /etc at once on a running box: it also rolls back the
password changes and fixes made since.  Put back only what broke.
EOF

{
    printf 'LX-31 Backup | host %s | %s | root: %s\n\n' "$CC_HOST" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$([ "$IS_ROOT" = 1 ] && echo yes || echo NO - partial)"
    printf 'Archive:   %s (%s, %d entries)\n' "$ARCH" "$(du -h "$ARCH" 2>/dev/null | awk '{ print $1 }')" "$_n_in"
    printf 'SHA-256:   %s\n' "${_arch_hash:-not computed (no hash tool)}"
    printf 'Hashed:    %d backed-up files (files.sha256)' "$_n_hash"
    if [ "$FAST" = 0 ]; then printf ', %d system programs and units (system.sha256)\n' "$_n_sys"; else printf ', system programs skipped (--fast)\n'; fi
    printf 'State:     %d snapshots in raw/ (firewall, services, ports, packages, routes, kernel settings)\n' "$(find "$CC_RUN_DIR/raw" -type f 2>/dev/null | wc -l | tr -d ' ')"
    printf '\nIncluded (see included.csv):\n'
    awk -F'","' 'NR > 1 { k = $2; s = $4; gsub(/"/, "", s); n[k]++; if (s != "ok") bad[k]++; kb[k] += $3 }
        END { for (k in n) printf "  %-9s %4d paths, %7.1f MB%s\n", k, n[k], kb[k] / 1024, (bad[k] ? "  (" bad[k] " partial or unreadable)" : "") }' "$INC" | sort
    [ "$_n_absent" -gt 0 ] && printf '  (%d usual paths do not exist on this system and were skipped)\n' "$_n_absent"
    printf '\n'
    case "$_copied" in
        yes) printf 'Copied off the box to %s\n' "$COPYTO" ;;
        no)  printf 'COPY FAILED to %s - the backup is only on this box\n' "$COPYTO" ;;
        *)   printf 'Not copied off the box.  From the admin workstation:\n  scp root@%s:%s .\n' "$CC_HOST" "$ARCH" ;;
    esac
    printf '\nRestore one file:   %s %s -C / etc/ssh/sshd_config\n' "$_x" "$ARCH"
    printf '%s\n' "What changed since: sha256sum -c $CC_RUN_DIR/files.sha256 2>/dev/null | grep -v ': OK\$'"
    printf 'More in RESTORE.txt.  The archive holds /etc/shadow and keys: keep it private.\n'
    printf '\nAll results: %s\n' "$CC_RUN_DIR"
} >"$CC_RUN_DIR/summary.txt"
cat "$CC_RUN_DIR/summary.txt"
rm -rf "$W"
cc_finish
