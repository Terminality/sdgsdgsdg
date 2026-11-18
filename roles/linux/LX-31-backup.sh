#!/bin/sh
# =============================================================================
# ID:       LX-31
# NAME:     Backup
# ROLE:     Linux  (wave 1, first 15 minutes)
# KIND:     readonly - writes only into the output folder, changes nothing
# VERSION:  2.0.0
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
# HOW A RUN GOES  (asks questions like sqlmap; Enter takes the default)
#   1. Questions: which box (splunk / webmail / ecomm / other: it offers that
#      box's important folders), web roots (listed with sizes), home-folder
#      dotfiles and SSH keys, hashing system programs, and three answers you
#      type: extra paths to back up, paths to leave out, and where to copy
#      the backup (user@host:/path/).  Flags answer them in advance; --batch
#      takes every default.
#   2. What will be backed up, each path with its size, then the archive,
#      the hash lists, the system state and the copy, each as a section.
#   No revert timer: the backup changes nothing on the host.
#
# USAGE
#   sudo sh LX-31-backup.sh                 asks, then backs up
#   sudo sh LX-31-backup.sh --batch         no questions, the defaults
#   sudo sh LX-31-backup.sh --box splunk --copy-to admin@10.0.0.5:/srv/backups/
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
#   --skip PATH        leave PATH out (file or folder; repeatable)
#   --box NAME         splunk | webmail | ecomm | other (answers that question)
#   --no-color         no colours
#   --batch            never ask: take every default (common option)
#   --help             this text plus the common options
#
# OUTPUTS  (under --out, one numbered folder per run: backup-1, backup-2, ...)
#   output.txt         everything shown on screen, without colours
#   included.txt       what was asked for and what happened, as a table
#   csv/included.csv   the same as CSV
#   backup.tar.gz      the archive; paths inside are relative to / (etc/passwd)
#   backup.tar.gz.sha256  hash of the archive, to check a copy is intact
#   files.sha256       sha256 of every file in the archive ("hash  /path")
#   system.sha256      sha256 of system programs and service units (not archived)
#   contents.txt       the archive's file list
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
  sudo sh LX-31-backup.sh [options]          (asks questions; --batch for none)

  --add PATH         also back up PATH (repeatable)
  --skip PATH        leave PATH out (repeatable)
  --webroot DIR      back up DIR as a web root (repeatable)
  --no-webroots      leave web roots out
  --no-homes         leave out home-folder dotfiles and SSH keys
  --fast             skip hashing system programs
  --max-mb N         ask before a backup larger than N MB (default 2048)
  --copy-to DEST     copy the result off the box with scp (user@host:/path/)
  --box NAME         splunk | webmail | ecomm | other
  --no-color         no colours
  --help             show this text

USAGE
    cc_usage_common
}

NL='
'
ADD=""; SKIPP=""; WEBROOTS=""; NO_WEB=0; NO_HOMES=0; FAST=0; MAXMB=2048; COPYTO=""; BOX=""
# Which questions the flags already answered.
F_WEB=0; F_HOMES=0; F_FAST=0; F_COPY=0; F_ADD=0; F_SKIP=0
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --add)         [ $# -ge 2 ] || cc_die 2 "--add needs a path"
                       [ -e "$2" ] || cc_die 2 "--add: no such file or folder: $2"
                       ADD="$ADD$2$NL"; F_ADD=1; shift 2 ;;
        --skip)        [ $# -ge 2 ] || cc_die 2 "--skip needs a path"
                       SKIPP="$SKIPP$2$NL"; F_SKIP=1; shift 2 ;;
        --webroot)     [ $# -ge 2 ] || cc_die 2 "--webroot needs a folder"
                       [ -d "$2" ] || cc_die 2 "--webroot: not a folder: $2"
                       WEBROOTS="$WEBROOTS$2$NL"; F_WEB=1; shift 2 ;;
        --no-webroots) NO_WEB=1; F_WEB=1; shift ;;
        --no-homes)    NO_HOMES=1; F_HOMES=1; shift ;;
        --fast)        FAST=1; F_FAST=1; shift ;;
        --max-mb)      [ $# -ge 2 ] || cc_die 2 "--max-mb needs a number"; MAXMB=$2; shift 2 ;;
        --copy-to)     [ $# -ge 2 ] || cc_die 2 "--copy-to needs a destination like user@host:/path/"; COPYTO=$2; F_COPY=1; shift 2 ;;
        --box)         [ $# -ge 2 ] || cc_die 2 "--box needs splunk, webmail, ecomm or other"; BOX=$2; shift 2 ;;
        --no-color|--no-colour)
                       # shellcheck disable=SC2034  # read by cc_color_init in the library
                       CC_NOCOLOR=1; shift ;;
        --help|-h)     usage; exit 0 ;;
        *)             cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
case "$MAXMB" in ''|*[!0-9]*) cc_die 2 "--max-mb needs a whole number" ;; esac
case "$BOX" in ''|splunk|webmail|ecomm|other) ;; *) cc_die 2 "--box must be splunk, webmail, ecomm or other" ;; esac

cc_color_init
cc_init "LX-31" "Backup" readonly
cc_need tar
cc_need find
cc_use_numbered_dir backup
CC_CSV_DIR="$CC_RUN_DIR/csv"
mkdir -p "$CC_CSV_DIR" || cc_die 3 "cannot create $CC_CSV_DIR"
cc_detect_os
W="$CC_RUN_DIR/.work"
mkdir -p "$W" || cc_die 3 "cannot create $W"
# Everything on screen also goes to output.txt (start line from the log).
OUTF="$CC_RUN_DIR/output.txt"
grep -v '\[NOTE\]\|\[DEBUG\]' "$CC_LOG" >"$OUTF" 2>/dev/null || : >"$OUTF"
# shellcheck disable=SC2034  # read by cc_show and cc_log in the library
CC_TEE=$OUTF
IS_ROOT=0
cc_is_root && IS_ROOT=1
[ "$IS_ROOT" = 1 ] || cc_warn "not running as root: /etc/shadow, root's files and other users' keys will be missing from the backup"
INC=$(cc_csv_new included "path,kind,size_kb,status")

cc_show "$C_CYN" "LX-31 Backup | host $CC_HOST | results in $CC_RUN_DIR"
cc_show "" "Legend: ${C_GRN}[+] saved / ok${C_OFF}  ${C_YEL}[*] partly saved, check${C_OFF}  ${C_RED}[x] failed${C_OFF}  ${C_GRY}[-] skipped${C_OFF}"
# header TEXT -> a section header, linpeas style.
header() { cc_show "" ""; cc_show "$C_CYN" "==========[ $1 ]=========="; }
# size_of PATH -> "12.3 MB" (du -sk works everywhere).
size_of() { du -sk "$1" 2>/dev/null | awk '{ kb = $1; if (kb >= 1024) printf "%.1f MB", kb / 1024; else printf "%d KB", kb }'; }
# list_add VAR TEXT -> append comma- or newline-separated items in TEXT to the
#   newline list in variable VAR.
list_add() {
    _la=$(printf '%s' "$2" | tr ',' '\n' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | grep .)
    [ -n "$_la" ] && eval "$1=\"\${$1}\$_la\$NL\""
    return 0
}

# ---- 0. Questions ---------------------------------------------------------------
# Web roots: the usual places, the Apache and nginx configs (DocumentRoot,
# root, alias), and any given.  Folders inside one already listed are dropped
# so nothing is stored twice.  A rough read: a wrong guess is just a path that
# does not exist and is skipped.
find_webroots() {
    {
        for _d in /var/www /srv/www /srv/http /usr/share/nginx/html /usr/local/www /opt/lampp/htdocs; do printf '%s\n' "$_d"; done
        for _c in /etc/apache2 /etc/httpd /usr/local/etc/apache24 /etc/nginx /usr/local/etc/nginx; do
            [ -d "$_c" ] || continue
            grep -rhiE '^[[:space:]]*(DocumentRoot|root|alias)[[:space:]]' "$_c" 2>/dev/null |
                awk '{ v = $NF; if ($1 ~ /^[Aa]lias$/ && NF >= 3) v = $3; gsub(/[";]/, "", v); if (v ~ /^\//) print v }'
        done
        printf '%s' "$WEBROOTS"
    } | sed 's|/*$||' | grep . | sort -u |
        awk '{ for (k in keep) if (index($0, k "/") == 1) next; keep[$0] = 1; print }' |
        while IFS= read -r _d; do [ -d "$_d" ] && printf '%s\n' "$_d"; done
}

header "QUESTIONS (Enter = the default)"
if [ -z "$BOX" ]; then
    cc_choose "Which box is this?" o "s=splunk" "w=webmail" "e=ecomm" "o=other"
    case "$CC_CHOICE" in s) BOX=splunk ;; w) BOX=webmail ;; e) BOX=ecomm ;; *) BOX=other ;; esac
fi
# Folders that matter for each scored box, beyond /etc and the web roots.
_boxp=""
case "$BOX" in
    splunk)  _boxp="/opt/splunk/etc /opt/splunkforwarder/etc /etc/chrony /etc/chrony.conf" ;;
    webmail) _boxp="/var/mail /var/vmail /var/spool/mail /var/lib/roundcube /usr/share/roundcube/config /var/lib/dovecot" ;;
    ecomm)   cc_show "$C_GRY" "    ecomm: the store's database is not in the file backup - run SV-14 (database backup) as well." ;;
esac
_boxf=""
for _p in $_boxp; do [ -e "$_p" ] && _boxf="$_boxf $_p"; done
if [ -n "$_boxf" ]; then
    for _p in $_boxf; do cc_show "$C_YEL" "    $BOX: $_p ($(size_of "$_p"))"; done
    cc_ask "Back up these $BOX folders too?" Y "yes, back them up" "no, skip them" && list_add ADD "$(printf '%s' "$_boxf" | tr ' ' ',')"
fi

if [ "$F_WEB" = 0 ]; then
    find_webroots >"$W/webfound"
    if [ -s "$W/webfound" ]; then
        while IFS= read -r _d; do cc_show "$C_YEL" "    web root: $_d ($(size_of "$_d"))"; done <"$W/webfound"
        cc_ask "Back up these web roots? (SV-14 backs up databases)" Y "yes, back them up" "no, leave them out (if they are big)" || NO_WEB=1
    else
        cc_show "$C_GRY" "    No web roots found."
    fi
fi
[ "$F_HOMES" = 1 ] || cc_ask "Back up every account's dotfiles and .ssh keys?" Y "yes, back them up" "no, skip them" || NO_HOMES=1
[ "$F_FAST" = 1 ] || cc_ask "Hash system programs and service units too? (shows later which programs were replaced)" Y "yes, hash them (10-60 s)" "no, skip it" || FAST=1
if [ "$F_ADD" = 0 ]; then
    cc_ask_text "Other files or folders to back up?" "" "paths separated by commas, like /opt/app,/srv/data"
    list_add ADD "$CC_ANSWER"
fi
if [ "$F_SKIP" = 0 ]; then
    cc_ask_text "Anything to leave out?" "" "paths separated by commas, like /var/www/big-videos"
    list_add SKIPP "$CC_ANSWER"
fi
if [ "$F_COPY" = 0 ]; then
    cc_ask_text "Copy the backup off the box?" "" "an scp destination like admin@10.0.0.5:/backups/, or Enter for no copy"
    COPYTO=$CC_ANSWER
fi

# ---- 1. Decide what goes in ---------------------------------------------------
# $W/want holds "kind|absolute path" lines.  Missing paths are counted as
# absent and skipped, so the same command works on any distro.
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
if [ "$NO_WEB" = 0 ]; then
    find_webroots >"$W/webroots"
    while IFS= read -r _d; do want webroot "$_d"; done <"$W/webroots"
fi
# Extra paths (--add, the box folders, the typed answer).
printf '%s' "$ADD" | grep . >"$W/add" 2>/dev/null
while IFS= read -r _p; do
    if [ -e "$_p" ]; then want added "$(cc_abspath "$_p")"
    else cc_show "$C_YEL" "    [*] not found, skipped: $_p"; fi
done <"$W/add"
# Paths to leave out, absolute, without a trailing slash.
printf '%s' "$SKIPP" | grep . | while IFS= read -r _p; do
    case "$_p" in /*) ;; *) _p="$(pwd)/$_p" ;; esac
    printf '%s\n' "$_p" | sed 's|/*$||'
done >"$W/skip"

# is_skipped PATH -> true if PATH is a left-out path or inside one.
is_skipped() {
    while IFS= read -r _s; do
        [ -n "$_s" ] || continue
        case "$1" in "$_s"|"$_s"/*) return 0 ;; esac
    done <"$W/skip"
    return 1
}

# ---- 2. Check each path and estimate the size ---------------------------------
header "1/5  what will be backed up"
: >"$W/paths"
_total_kb=0; _n_absent=0; _n_partial=0
sort -t'|' -k2,2 -u "$W/want" >"$W/want.sorted"
while IFS='|' read -r _k _p; do
    if [ ! -e "$_p" ]; then
        _n_absent=$((_n_absent + 1))
        cc_debug "absent: $_p"
        continue
    fi
    if is_skipped "$_p"; then
        cc_csv_row "$INC" "$_p" "$_k" "" "left out (you asked)"
        cc_show "$C_GRY" "  [-] left out: $_p"
        continue
    fi
    if [ ! -r "$_p" ]; then
        cc_csv_row "$INC" "$_p" "$_k" "" "unreadable"
        cc_show "$C_RED" "  [x] cannot read: $_p"
        _n_partial=$((_n_partial + 1))
        continue
    fi
    _kb=$(du -sk "$_p" 2>"$W/du.err" | awk '{ print $1 }')
    _st=ok
    [ -s "$W/du.err" ] && { _st="partial (some files unreadable)"; _n_partial=$((_n_partial + 1)); }
    _total_kb=$((_total_kb + ${_kb:-0}))
    printf '%s\n' "$_p" >>"$W/paths"
    cc_csv_row "$INC" "$_p" "$_k" "${_kb:-0}" "$_st"
    # Home dotfiles are many small files: counted, not listed one by one.
    if [ "$_k" = home ] && [ ! -d "$_p" ]; then _n_dot=$((${_n_dot:-0} + 1)); continue; fi
    if [ "$_st" = ok ]; then cc_show "$C_GRN" "  [+] $_p  ($_k, $(size_of "$_p"))"
    else cc_show "$C_YEL" "  [*] $_p  ($_k, $(size_of "$_p"), some files unreadable)"; fi
done <"$W/want.sorted"
[ "${_n_dot:-0}" -gt 0 ] && cc_show "$C_GRN" "  [+] ${_n_dot} home-folder dotfiles"
[ "$_n_absent" -gt 0 ] && cc_show "$C_GRY" "  [-] $_n_absent usual paths do not exist on this system"
[ -s "$W/paths" ] || cc_die 3 "nothing to back up (no readable paths found)"
_total_mb=$((_total_kb / 1024))
cc_show "" "  About $_total_mb MB in $(grep -c . "$W/paths") paths."
if [ "$_total_mb" -gt "$MAXMB" ]; then
    cc_show "$C_YEL" "  [*] That is more than the $MAXMB MB limit (--max-mb). The big paths are listed above."
    cc_ask "Back up $_total_mb MB anyway?" N "yes, back it all up" "no, stop" || cc_die 3 "the backup would be about $_total_mb MB, more than --max-mb $MAXMB. Leave big paths out (the leave-out question or --skip, --no-webroots) or raise --max-mb"
fi
# Room on the disk that holds the output folder (df -P: POSIX columns).
_free_kb=$(df -Pk "$CC_RUN_DIR" 2>/dev/null | awk 'NR == 2 { print $4 }')
if [ -n "$_free_kb" ] && [ "$_free_kb" -lt "$_total_kb" ]; then
    cc_die 3 "not enough free space in $CC_OUT: need about $_total_mb MB, have $((_free_kb / 1024)) MB. Use --out on another disk, or leave big paths out"
fi

# A folder with a left-out path inside is split into its parts, without the
# left-out ones, level by level.  Works with every tar: busybox tar (Alpine
# and other small systems) has no exclude option.
if [ -s "$W/skip" ]; then
    cp "$W/paths" "$W/queue"; : >"$W/paths"
    while [ -s "$W/queue" ]; do
        : >"$W/queue2"
        while IFS= read -r _p; do
            is_skipped "$_p" && continue
            _inside=0
            while IFS= read -r _s; do case "$_s" in "$_p"/*) _inside=1 ;; esac; done <"$W/skip"
            if [ "$_inside" = 1 ] && [ -d "$_p" ] && [ ! -h "$_p" ]; then
                find "$_p" -mindepth 1 -maxdepth 1 2>/dev/null >>"$W/queue2"
            else
                printf '%s\n' "$_p" >>"$W/paths"
            fi
        done <"$W/queue"
        mv "$W/queue2" "$W/queue"
    done
fi

# ---- 3. Write the archive ------------------------------------------------------
# Paths are stored relative to / (tar -C / etc/passwd), so a restore can go
# back to / or to a scratch folder for comparing.
header "2/5  archive"
set --
while IFS= read -r _p; do set -- "$@" "${_p#/}"; done <"$W/paths"
ARCH="$CC_RUN_DIR/backup.tar.gz"
_z=gzip
if ! cc_have gzip; then ARCH="$CC_RUN_DIR/backup.tar"; _z=""; cc_warn "gzip not found: writing an uncompressed .tar"; fi
cc_show "$C_GRY" "  writing $(basename "$ARCH") ..."
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
    cc_show "$C_RED" "  [x] the archive could not be read back (tar exit ${_tar_rc:-?}) - see $CC_LOG"
else
    cc_show "$C_GRN" "  [+] $(basename "$ARCH"): $(size_of "$ARCH"), $_n_in entries, reads back fine"
    [ "${_tar_rc:-0}" = 0 ] || cc_show "$C_YEL" "  [*] tar exited ${_tar_rc} (usually a file changed or was unreadable while archiving); the archive itself is fine"
fi
_arch_hash=$(cc_sha256 "$ARCH")
[ -n "$_arch_hash" ] && printf '%s  %s\n' "$_arch_hash" "$(basename "$ARCH")" >"$ARCH.sha256"

# ---- 4. Hash lists -------------------------------------------------------------
# hashes FILE PATH... -> "sha256  /path" lines for every regular file under the
# paths, appended to FILE.  Uses one batch tool where possible (fast); falls
# back to one call per file.  Left-out paths are removed afterwards.
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
    if [ -s "$W/skip" ]; then
        awk 'NR == FNR { if ($0 != "") s[$0] = 1; next }
             { p = substr($0, index($0, "  ") + 2); drop = 0
               for (k in s) if (p == k || index(p, k "/") == 1) drop = 1
               if (!drop) print }' "$W/skip" "$_hf" >"$_hf.t" && mv "$_hf.t" "$_hf"
    fi
}
header "3/5  hash lists (to prove later which files changed)"
: >"$CC_RUN_DIR/files.sha256"
set --
while IFS= read -r _p; do set -- "$@" "$_p"; done <"$W/paths"
hashes "$CC_RUN_DIR/files.sha256" "$@"
_n_hash=$(grep -c . "$CC_RUN_DIR/files.sha256")
cc_show "$C_GRN" "  [+] files.sha256: $_n_hash backed-up files"
_n_sys=0
if [ "$FAST" = 0 ]; then
    : >"$CC_RUN_DIR/system.sha256"
    set --
    for _d in /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /lib/systemd/system \
              /usr/lib/systemd/system /etc/systemd/system /usr/libexec; do
        # /bin is often a link to /usr/bin; skip links so nothing is hashed twice.
        [ -d "$_d" ] && [ ! -h "$_d" ] && set -- "$@" "$_d"
    done
    [ $# -gt 0 ] && hashes "$CC_RUN_DIR/system.sha256" "$@"
    _n_sys=$(grep -c . "$CC_RUN_DIR/system.sha256")
    cc_show "$C_GRN" "  [+] system.sha256: $_n_sys system programs and service units"
else
    cc_show "$C_GRY" "  [-] system programs not hashed (skipped)"
fi

# ---- 5. State that is not in files ---------------------------------------------
# Each command's output goes to raw/<name>.txt.  Missing tools are skipped.
header "4/5  system state (firewall, services, ports ...)"
snap() {
    _sn=$1; shift
    if cc_have "$1"; then
        if cc_save "$_sn" "$@"; then cc_show "$C_GRN" "  [+] $_sn  ($*)"
        else cc_show "$C_YEL" "  [*] $_sn  ($* failed; output kept in raw/$_sn.txt)"; fi
    fi
    return 0
}
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
header "5/5  copy off the box"
_copied=""
if [ -n "$COPYTO" ]; then
    cc_need scp
    cc_show "$C_GRY" "  copying to $COPYTO (scp may ask for a password) ..."
    if scp -q -o ConnectTimeout=15 "$ARCH" "$ARCH.sha256" "$CC_RUN_DIR/files.sha256" "$COPYTO" 2>>"$CC_LOG"; then
        _copied=yes
        cc_show "$C_GRN" "  [+] copied to $COPYTO"
    else
        _copied=no
        CC_N_FAIL=$((CC_N_FAIL + 1))
        cc_show "$C_RED" "  [x] copy to $COPYTO FAILED - the backup is only on this box (see $CC_LOG)"
    fi
else
    cc_show "$C_YEL" "  [*] Not copied. A red team with root can delete a backup kept on the box. From the admin machine:"
    cc_show "$C_YEL" "      scp root@$CC_HOST:$ARCH ."
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
    printf '\nIncluded (see included.txt):\n'
    awk -F'","' 'NR > 1 { k = $2; s = $4; gsub(/"/, "", s); n[k]++; if (s != "ok" && s !~ /^left out/) bad[k]++; kb[k] += $3 }
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
cc_csv_pretty "$INC" "$CC_RUN_DIR/included.txt" 80
header "SUMMARY"
# Coloured on screen: red for a failed copy or archive, yellow for partial or
# not copied, green for what was saved.  summary.txt and output.txt stay plain.
awk -v R="$C_RED" -v Y="$C_YEL" -v G="$C_GRN" -v C="$C_CYN" -v D="$C_GRY" -v O="$C_OFF" '
    NR == 1                          { print C $0 O; next }
    /^COPY FAILED/                   { print R $0 O; next }
    /^Not copied/ || /partial or unreadable/ || /^  scp / { print Y $0 O; next }
    /^(Archive|SHA-256|Hashed|State|Copied):?/ || /^  [a-z]+ +[0-9]+ paths/ { print G $0 O; next }
    /^$/                             { print; next }
                                     { print D $0 O }
' "$CC_RUN_DIR/summary.txt"
cat "$CC_RUN_DIR/summary.txt" >>"$OUTF"
rm -rf "$W"
cc_finish
