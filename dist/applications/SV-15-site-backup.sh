#!/bin/sh
# =============================================================================
# ID:       SV-15
# NAME:     Site backup and restore
# ROLE:     Applications  (wave 1: back up first; restore whenever needed)
# KIND:     changes - backup and check only read; restore is a dry run unless --apply
# VERSION:  1.0.0
#
# PURPOSE
#   Keeps each web site restorable after the red team defaces it, drops a web
#   shell in it, or wipes its database.  Three modes:
#
#     backup   every site the web servers serve (Apache, nginx) plus the
#              folders in /var/www: the files (one archive per site, with a
#              hash of every file), the site's database (read from the app's
#              own config: WordPress, Joomla, Drupal, PrestaShop, OpenCart,
#              Magento, Roundcube, .env), and the web server and PHP configs.
#     check    compares each site with the last backup and lists what
#              changed: CHANGED files (defaced pages, edited code), DELETED
#              files and NEW files (web shells).  Changes nothing.
#     restore  the same comparison, then asks per site what to put back:
#              changed and deleted files from the backup, new files to
#              quarantine, and (if you say so) the database.  Only what
#              changed is touched, so your own fixes elsewhere stay.  The
#              current files and database are saved first, a revert timer
#              runs, and every step has an undo line.
#
#   SV-14 still dumps every database on the box; SV-15 is about the sites.
#
#   QUESTIONS (Enter takes the default in capitals; a flag answers each):
#     what to do: [b]ack up, [c]heck, [r]estore      --backup / --check / --restore
#     backup:  which sites (all or names)             --site NAME
#              the sites' databases too               --db / --no-db
#              copy the backup off the box            --copy-to DEST
#     restore: per site: [a]ll back to the backup, [f]iles only,
#              [q]uarantine new files only, [n]othing --what all|files|new|none
#              put the database back too              --restore-db / --no-restore-db
#
# USAGE
#   sudo sh SV-15-site-backup.sh                              asks
#   sudo sh SV-15-site-backup.sh --backup --batch             back up every site
#   sudo sh SV-15-site-backup.sh --check --batch              what changed?
#   sudo sh SV-15-site-backup.sh --restore --protected p.csv --apply
#
# OPTIONS
#   --backup | --check | --restore   the mode (asked if not given)
#   --site NAME        only this site (repeat); names as shown in sites.txt
#   --webroot DIR      also treat DIR as a site (repeat)
#   --from DIR         the backup to compare with (default: the newest
#                      site-backup-N in --out)
#   --db / --no-db     back up the sites' databases (default yes)
#   --mysql-cnf FILE   MySQL client file ([client] user/password) when root
#                      cannot log in through the socket
#   --exclude PATTERN  leave matching paths out of backups and checks (repeat;
#                      shell pattern on the full path, e.g. '*/cache/*')
#   --max-mb N         refuse a backup bigger than N MB (default 4096)
#   --keep N           keep only the newest N backups (default: all)
#   --copy-to DEST     copy the backup off the box with scp
#   --what all|files|new|none   restore answer for every site
#   --restore-db / --no-restore-db  put the database back on restore (default no)
#   --timer SECONDS    revert countdown on restore (default 120); --no-timer
#   --no-color         no colours
#   --help             this text plus the common options
#
# OUTPUTS  (under --out)
#   site-backup-N/     one backup (mode 700: it holds the database dumps)
#     sites.txt        each site: folder, files, size, database
#     <site>/files.tar.gz   the site's files (paths relative to /)
#     <site>/files.sha256   a hash of every file (what check compares)
#     <site>/db.sql.gz | db.dump   the site's database (MySQL / PostgreSQL)
#     config.tar.gz, config.sha256   /etc/apache2|httpd|nginx|php
#     RESTORE.txt      how to put things back by hand
#   site-check-N/      changes.txt: site, change, file, why
#   site-restore-N/    plan.txt, changes.txt, before/ (what was replaced),
#                      revert.sh
#   Each folder: output.txt (the screen, no colour), summary.txt, run.txt.
#
# WHAT IT CHANGES
#   backup, check: nothing on the host.  restore with --apply: the files it
#   lists (put back from the archive, owners and modes kept), new files moved
#   to quarantine, and the database if you said so.  Everything is undone if
#   the revert timer runs out or revert.sh is run.
#
# DEPENDS ON
#   tar, gzip, find, sha256sum (or shasum / sha256 / openssl); mysqldump or
#   mariadb-dump and the client; pg_dump/pg_restore; scp for --copy-to.
#
# TESTED ON
#   Ubuntu 24.04 under dash, bash, busybox sh, ksh93, mksh and yash with
#   gawk, mawk and busybox awk: a site defaced, a file deleted and a web
#   shell planted were found by check and put right by restore; the revert
#   brought the defaced state back.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - Back up AFTER cleaning: a web shell already there is in the backup and
#     looks normal to check.  Run SV-01 first.
#   - Files are compared by content (hash), not permission or owner.
#   - Web server config changes are reported, not restored (a restart could
#     break scoring): RESTORE.txt says how.
#   - A database on another host is not dumped: back it up there.
#   - Uploads made by real users after the backup show as NEW: check before
#     quarantining (they are moved, not deleted).
#
# DEBUGGING
#   --debug shows each site found, the database logins and every command.
# =============================================================================

# >>> BT-LIB  (lib/lib.sh 0.6.0 pasted in by tools/build.sh - edit lib/lib.sh, not this copy)
# =============================================================================
# ID:       LB-01
# NAME:     Shell library (lib.sh)
# ROLE:     Automation  (wave 0, foundation)
# VERSION:  0.6.0
#
# PURPOSE
#   The jobs every Unix script in this kit repeats, written once:
#     1. common command-line flags          cc_common_flag
#     2. dry-run by default / apply mode    cc_run, cc_run_quiet
#     3. log naming and log lines           cc_init, cc_log, cc_info, ...
#     4. backup + one undo log per host     cc_backup_file, cc_undo_add
#     5. the protected-list refusal         cc_is_protected, cc_guard
#     6. meaningful exit codes              cc_die, cc_finish
#   plus small helpers the rules call for: tool detection, OS detection,
#   password generation, quarantine, SHA-256, CSV output, findings files,
#   and for inventory scripts: flags (cc_flag), a per-run folder
#   (cc_use_run_dir) and raw command capture (cc_save).
#
# HOW A SCRIPT USES IT
#   Start every new script from templates/script-template.sh.  During
#   development a script sources this file through the marker block below.  tools/build.sh replaces that block with the contents of this file
#   so every built script in dist/ is one standalone file.
#
#       # >>> BT-LIB
#       ...the loader lines from templates/script-template.sh...
#       # <<< BT-LIB
#
#       while [ $# -gt 0 ]; do
#           if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
#           case "$1" in
#               --my-option) MY_OPT=$2; shift 2 ;;
#               *) cc_die 2 "unknown option: $1" ;;
#           esac
#       done
#       cc_init "LX-99" "Example script" changes     # or: readonly
#       cc_run "stop telnet" service telnet stop
#       cc_finish
#
# LANGUAGE RULES (why this file looks old-fashioned)
#   Plain POSIX sh only, so it runs on dash, busybox ash, ksh, bash, and the
#   /bin/sh of FreeBSD and Solaris.  That means:
#     - no 'local'  -> every function uses its own _cc_<function>_ prefix for
#                      temporary variables so nested calls can't collide
#     - no arrays, no [[ ]], no 'function' keyword, no 'echo -n' (use printf)
#     - no 'set -e' -> a hardening script must keep going after one failed
#                      step and report it; errors are counted, not fatal
#   tests/lint-posix.sh checks these rules mechanically.
#
# DEBUGGING
#   --debug or CC_DEBUG=1   print DEBUG lines (tool choices, paths, decisions)
#   sh -x script.sh ...     trace every command the shell runs
#   Every run writes  <out>/<ID>_<host>_<UTC time>.log  with everything that
#   was printed plus the full output of every command run through cc_run.
#
# EXIT CODES (the same for every script in the kit)
#   0  finished; nothing failed
#   1  unexpected error
#   2  usage error (bad flag, missing argument)
#   3  missing requirement (not root, tool not found, no protected list)
#   4  refused: the only thing asked for is on the protected list
#   5  finished, but at least one change failed (see the log)
#   130 interrupted (Ctrl-C)
#
# KNOWN LIMITS
#   - cc_genpass needs /dev/urandom and a 'tr' that understands ranges such as
#     A-Z without brackets (true of GNU, busybox and BSD tr; on Solaris put
#     /usr/xpg4/bin first in PATH).
#   - cc_verify_self can only check a script that was started from a file; a
#     script piped into sh has no file to hash, so the check is skipped.
# =============================================================================

# The variables below are read by the scripts that source this file.  The
# linter cannot see that, so its 'unused variable' warning is turned off.
# shellcheck disable=SC2034
CC_LIB_VERSION="0.6.0"

# State.  ':=' keeps a value the caller already exported (for example CC_DEBUG=1
# in the environment) and only fills in a default when the variable is empty.
: "${CC_APPLY:=0}"          # 0 = dry run (default), 1 = make changes
: "${CC_DEBUG:=0}"          # 1 = print DEBUG lines
: "${CC_QUIET:=0}"          # 1 = print only WARN and ERROR on screen
: "${CC_FORCE_SCORED:=0}"   # 1 = allowed to touch a protected *account*
: "${CC_NO_PROTECTED:=0}"   # 1 = operator accepted running with no list
: "${CC_OUT:=${BT_OUT:-}}"              # output folder (operator-chosen)
: "${CC_PROTECTED:=${BT_PROTECTED:-}}"  # protected-list CSV
CC_ID="${CC_ID:-CC-00}"
CC_LOG=""                   # set by cc_init; empty means "log file not open"
CC_N_DONE=0                 # changes made
CC_N_WOULD=0                # changes a dry run would make
CC_N_FAIL=0                 # changes that failed
CC_N_REFUSED=0              # changes refused by the protected list
CC_N_FIND=0                 # findings written by cc_finding
CC_N_FLAG=0                 # flags written by cc_flag (this shell only; the
                            # report counts from the file, see cc_flag_report)
CC_CSV_DIR=""               # when set, CSV files go here instead of CC_OUT
CC_RUN_DIR=""               # per-run folder, set by cc_use_run_dir
CC_FLAGS=""                 # path of this run's flags.csv, once one is written
: "${CC_TABLES:=0}"         # 1 = flags (and the script's own tables) as .txt
                            # tables, no CSV: see cc_table_new
CC_TEE=""                   # copy of screen lines, when a script sets it
: "${CC_BATCH:=0}"          # 1 = never ask: take every default (--batch)
CC_RUN_UNDO=""              # this run's undo lines, for the revert timer
CC_TIMER_DIR=""             # folder holding revert.sh, KEEP, REVERTED
CC_TIMER_DEADLINE=0         # epoch second when the revert timer fires
CC_SHIFT=1                  # how many arguments cc_common_flag consumed

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------

# cc_log LEVEL MESSAGE...
#   One line to the screen (stderr) and to the log file.  Log lines go to
#   stderr so a script's real output (tables, CSV on stdout) stays clean when
#   piped.  Before cc_init has opened the log file, lines go to the screen only.
#   NEVER pass a password to this function: the log file is shared.
cc_log() {
    _cc_log_level=$1
    shift
    _cc_log_line="$(date -u +%H:%M:%SZ) [$_cc_log_level] $CC_ID: $*"
    _cc_log_show=0
    case "$_cc_log_level" in
        DEBUG) [ "$CC_DEBUG" = 1 ] && _cc_log_show=1 ;;
        WARN|ERROR|REFUSED) _cc_log_show=1 ;;
        NOTE) ;;            # log file only: detail that would flood the screen
        *) [ "$CC_QUIET" = 1 ] || _cc_log_show=1 ;;
    esac
    if [ "$_cc_log_show" = 1 ]; then
        printf '%s\n' "$_cc_log_line" >&2
        # CC_TEE: a file that keeps a copy of everything shown on screen
        # (SH-05 sets it to its output.txt).
        [ -n "$CC_TEE" ] && printf '%s\n' "$_cc_log_line" >>"$CC_TEE" 2>/dev/null
    fi
    if [ -n "$CC_LOG" ]; then
        printf '%s\n' "$_cc_log_line" >>"$CC_LOG" 2>/dev/null
    fi
    return 0
}
cc_info()  { cc_log INFO "$@"; }
cc_note()  { cc_log NOTE "$@"; }
cc_warn()  { cc_log WARN "$@"; }
cc_err()   { cc_log ERROR "$@"; }
cc_debug() { cc_log DEBUG "$@"; }

# cc_die CODE MESSAGE...
#   Log an error and stop the script with CODE (see EXIT CODES above).
cc_die() {
    _cc_die_code=$1
    shift
    cc_log ERROR "$*"
    exit "$_cc_die_code"
}

# -----------------------------------------------------------------------------
# Small helpers
# -----------------------------------------------------------------------------

# cc_have TOOL        -> returns 0 if TOOL is on PATH.
cc_have() { command -v "$1" >/dev/null 2>&1; }

# cc_need TOOL...     -> stop with exit 3 if any TOOL is missing.
cc_need() {
    for _cc_need_t in "$@"; do
        cc_have "$_cc_need_t" || cc_die 3 "required tool not found: $_cc_need_t"
    done
}

# cc_first TOOL...    -> print the first TOOL that exists; return 1 if none do.
#   Example: LISTEN=$(cc_first ss netstat lsof) || cc_die 3 "no port tool"
cc_first() {
    for _cc_first_t in "$@"; do
        if cc_have "$_cc_first_t"; then
            printf '%s\n' "$_cc_first_t"
            return 0
        fi
    done
    return 1
}

# cc_which NAME -> print the full path of the program NAME, or return 1.
#   Searches PATH and then the sbin folders (often missing from a normal
#   account's PATH).  Use it when a script must run the REAL program: busybox
#   sh runs its own built-in version of tools such as sysctl, chpasswd or find
#   when called by bare name, but always runs a file given by full path.
cc_which() {
    _cc_wh_ifs=$IFS; IFS=:
    for _cc_wh_d in $PATH /usr/local/sbin /usr/sbin /sbin /usr/local/bin /usr/bin /bin; do
        IFS=$_cc_wh_ifs
        [ -n "$_cc_wh_d" ] || continue
        if [ -f "$_cc_wh_d/$1" ] && [ -x "$_cc_wh_d/$1" ]; then printf '%s\n' "$_cc_wh_d/$1"; return 0; fi
    done
    IFS=$_cc_wh_ifs
    return 1
}

# cc_shquote STRING   -> print STRING wrapped in single quotes, safe to paste
#   into a shell.  Used to build the undo commands.
cc_shquote() {
    printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

# cc_abspath PATH     -> print the absolute form of PATH (file or folder).
#   The parent folder must exist.  No 'realpath' dependency.
cc_abspath() {
    case "$1" in
        /*) _cc_abs_p=$1 ;;
        *)  _cc_abs_p="$(pwd)/$1" ;;
    esac
    if [ -d "$_cc_abs_p" ]; then
        (cd "$_cc_abs_p" 2>/dev/null && pwd -P) || printf '%s\n' "$_cc_abs_p"
    else
        _cc_abs_d=$(dirname "$_cc_abs_p")
        _cc_abs_b=$(basename "$_cc_abs_p")
        _cc_abs_d=$( (cd "$_cc_abs_d" 2>/dev/null && pwd -P) || printf '%s' "$_cc_abs_d")
        printf '%s/%s\n' "${_cc_abs_d%/}" "$_cc_abs_b"
    fi
}

# cc_is_root          -> returns 0 when running as root.
#   'id -u' is missing from the default id on old Solaris, so fall back to
#   parsing plain 'id'.
cc_is_root() {
    _cc_root_uid=$(id -u 2>/dev/null) || _cc_root_uid=$(id | sed 's/^uid=\([0-9]*\).*/\1/')
    [ "$_cc_root_uid" = 0 ]
}

# cc_require_root     -> stop with exit 3 unless running as root.
cc_require_root() {
    cc_is_root || cc_die 3 "this script must be run as root (try: sudo sh $0 ...)"
}

# cc_confirm QUESTION -> ask the operator; returns 0 for yes.
#   Reads from the terminal, not stdin, so it still works when the script was
#   piped in.  BT_ASSUME_YES=1 answers yes without asking (for fan-out).
cc_confirm() {
    [ "${BT_ASSUME_YES:-0}" = 1 ] && return 0
    if [ ! -r /dev/tty ]; then
        cc_warn "no terminal to ask '$1' - treating as NO (set BT_ASSUME_YES=1 to skip questions)"
        return 1
    fi
    printf '%s [y/N] ' "$1" >/dev/tty
    read -r _cc_confirm_a </dev/tty || return 1
    case "$_cc_confirm_a" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

# -----------------------------------------------------------------------------
# Common flags
# -----------------------------------------------------------------------------

# cc_usage_common     -> print the flags every script accepts.
cc_usage_common() {
    cat <<'EOF'
Common options (every script in the kit):
  --apply            make changes (default is a dry run that changes nothing)
  --dry-run          show what would change (the default)
  --out DIR          folder for logs, CSV files, backups and the undo log
                     (default: $BT_OUT, else ~/bt-out)
  --protected FILE   protected-list CSV (default: $BT_PROTECTED, else
                     DIR/protected.csv)
  --no-protected     allow --apply without a protected list (dangerous)
  --force-scored     allow changes to accounts on the protected list
  --batch            never ask questions: take every default (like sqlmap)
  --quiet            only print warnings and errors
  --debug            print debugging detail
  --version          print the library version and exit
EOF
}

# cc_common_flag "$@"
#   Handles ONE common flag at the front of the argument list.
#   Returns 0 if it consumed something and sets CC_SHIFT to how many arguments
#   to shift (1 or 2).  Returns 1 if "$1" is not a common flag, so the calling
#   script can handle its own options.  See the usage example in the header.
cc_common_flag() {
    CC_SHIFT=1
    case "${1:-}" in
        --apply)        CC_APPLY=1 ;;
        --dry-run)      CC_APPLY=0 ;;
        --out)          [ $# -ge 2 ] || cc_die 2 "--out needs a folder"
                        CC_OUT=$2; CC_SHIFT=2 ;;
        --out=*)        CC_OUT=${1#--out=} ;;
        --protected)    [ $# -ge 2 ] || cc_die 2 "--protected needs a file"
                        CC_PROTECTED=$2; CC_SHIFT=2 ;;
        --protected=*)  CC_PROTECTED=${1#--protected=} ;;
        --no-protected) CC_NO_PROTECTED=1 ;;
        --force-scored) CC_FORCE_SCORED=1 ;;
        --batch)        CC_BATCH=1 ;;
        --quiet)        CC_QUIET=1 ;;
        --debug)        CC_DEBUG=1 ;;
        --version)      printf 'kit library %s\n' "$CC_LIB_VERSION"; exit 0 ;;
        *)              return 1 ;;
    esac
    return 0
}

# -----------------------------------------------------------------------------
# Start-up
# -----------------------------------------------------------------------------

# cc_init ID NAME KIND
#   Call once, after the flags are parsed.
#     ID    the script's ID from docs/catalog.csv, e.g. LX-20
#     NAME  short name for the log banner
#     KIND  'readonly' for inventory/detection scripts, 'changes' for scripts
#           that can modify the system.  A 'changes' script refuses to run
#           with --apply when there is no protected list (rule 4), unless the
#           operator passed --no-protected.
#   Sets: CC_HOST CC_TS CC_OUT CC_LOG CC_UNDO CC_BACKUP_DIR CC_QUAR_DIR
#         CC_KIT CC_PROTECTED
cc_init() {
    CC_ID=${1:-CC-00}
    CC_NAME=${2:-unnamed}
    CC_KIND=${3:-readonly}

    # Host name without the domain part, safe for use in a file name.
    CC_HOST=$(uname -n 2>/dev/null | sed 's/\..*//; s/[^A-Za-z0-9_-]/_/g')
    [ -n "$CC_HOST" ] || CC_HOST=unknownhost
    CC_TS=$(date -u +%Y%m%dT%H%M%SZ)

    # Where the running script lives (the "kit").  When the script was piped
    # into sh, $0 is just "sh" and there is no kit folder.
    CC_KIT=""
    if [ -f "$0" ]; then
        CC_KIT=$(cc_abspath "$(dirname "$0")")
    fi

    # Output folder: operator-chosen, never inside the kit (rule 11: the kit
    # may be on read-only media and must stay unchanged so its hash matches).
    [ -n "$CC_OUT" ] || CC_OUT="${HOME:-/root}/bt-out"
    (umask 077; mkdir -p "$CC_OUT") 2>/dev/null \
        || cc_die 3 "cannot create output folder: $CC_OUT (pass --out DIR)"
    CC_OUT=$(cc_abspath "$CC_OUT")
    if [ -n "$CC_KIT" ]; then
        case "$CC_OUT/" in
            "$CC_KIT"/*) cc_die 2 "output folder $CC_OUT is inside the kit folder $CC_KIT; choose another with --out" ;;
        esac
    fi
    [ -w "$CC_OUT" ] || cc_die 3 "output folder is not writable: $CC_OUT"

    CC_LOG="$CC_OUT/${CC_ID}_${CC_HOST}_${CC_TS}.log"
    CC_UNDO="$CC_OUT/undo-${CC_HOST}.log"
    CC_BACKUP_DIR="$CC_OUT/backup/${CC_HOST}/${CC_TS}_${CC_ID}"
    CC_QUAR_DIR="$CC_OUT/quarantine/${CC_HOST}/${CC_TS}_${CC_ID}"
    CC_FINDINGS=""
    # Create the log with private permissions without changing the umask for
    # the rest of the script (a hardening script creates system files too).
    (umask 077; : >>"$CC_LOG") 2>/dev/null || cc_die 3 "cannot write log file: $CC_LOG"

    # Protected list.
    [ -n "$CC_PROTECTED" ] || CC_PROTECTED="$CC_OUT/protected.csv"
    if [ ! -r "$CC_PROTECTED" ]; then
        if [ "$CC_KIND" = changes ] && [ "$CC_APPLY" = 1 ] && [ "$CC_NO_PROTECTED" != 1 ]; then
            cc_die 3 "no protected list at $CC_PROTECTED - refusing to change anything. Build one (SH-09), pass --protected FILE, or pass --no-protected to accept the risk"
        fi
        cc_debug "no protected list at $CC_PROTECTED (nothing will be refused)"
        CC_PROTECTED=""
    fi

    trap 'cc_log ERROR "interrupted"; exit 130' INT TERM

    if [ "$CC_KIND" = readonly ]; then _cc_init_mode="READ-ONLY (changes nothing on this host)"
    elif [ "$CC_APPLY" = 1 ]; then _cc_init_mode="APPLY (changes will be made)"
    else _cc_init_mode="DRY RUN (nothing will change)"; fi
    cc_info "start: $CC_NAME | lib $CC_LIB_VERSION | host $CC_HOST | $_cc_init_mode"
    cc_debug "out=$CC_OUT log=$CC_LOG protected=${CC_PROTECTED:-none} kit=${CC_KIT:-none} kind=$CC_KIND"
    cc_verify_self
    return 0
}

# -----------------------------------------------------------------------------
# Making changes
# -----------------------------------------------------------------------------

# cc_run DESCRIPTION COMMAND [ARG...]
#   The only way a script should change the system.
#     dry run: logs "WOULD: description [command]" and returns 0
#     apply:   logs "DO: ...", runs the command with its output appended to
#              the log file, counts success or failure, returns its exit code
#   The command line is written to the log.  If any argument is a secret, use
#   cc_run_quiet instead.
cc_run() {
    _cc_run_desc=$1
    shift
    if [ "$CC_APPLY" != 1 ]; then
        cc_log WOULD "$_cc_run_desc  [$*]"
        CC_N_WOULD=$((CC_N_WOULD + 1))
        return 0
    fi
    cc_timer_fired && { cc_log REFUSED "$_cc_run_desc: the revert timer already ran out, so nothing more is changed"; CC_N_REFUSED=$((CC_N_REFUSED + 1)); return 4; }
    cc_log DO "$_cc_run_desc  [$*]"
    "$@" >>"$CC_LOG" 2>&1
    _cc_run_rc=$?
    if [ "$_cc_run_rc" -eq 0 ]; then
        CC_N_DONE=$((CC_N_DONE + 1))
    else
        CC_N_FAIL=$((CC_N_FAIL + 1))
        cc_log ERROR "FAILED (exit $_cc_run_rc): $_cc_run_desc - command output is in $CC_LOG"
    fi
    return "$_cc_run_rc"
}

# cc_run_quiet DESCRIPTION COMMAND [ARG...]
#   Same as cc_run, but only the description is logged - never the command
#   line or its output.  Use this when an argument or the output is a secret.
cc_run_quiet() {
    _cc_runq_desc=$1
    shift
    if [ "$CC_APPLY" != 1 ]; then
        cc_log WOULD "$_cc_runq_desc"
        CC_N_WOULD=$((CC_N_WOULD + 1))
        return 0
    fi
    cc_timer_fired && { cc_log REFUSED "$_cc_runq_desc: the revert timer already ran out, so nothing more is changed"; CC_N_REFUSED=$((CC_N_REFUSED + 1)); return 4; }
    cc_log DO "$_cc_runq_desc"
    "$@" >/dev/null 2>&1
    _cc_runq_rc=$?
    if [ "$_cc_runq_rc" -eq 0 ]; then
        CC_N_DONE=$((CC_N_DONE + 1))
    else
        CC_N_FAIL=$((CC_N_FAIL + 1))
        cc_log ERROR "FAILED (exit $_cc_runq_rc): $_cc_runq_desc (output hidden because it may hold a secret)"
    fi
    return "$_cc_runq_rc"
}

# cc_undo_add DESCRIPTION COMMAND
#   Append one line to this host's undo log.  Fields are tab-separated:
#       UTC time <TAB> script ID <TAB> description <TAB> command to undo
#   Newest entries are at the bottom; to roll back, run the commands from the
#   bottom up (SH-12, the undo walker, automates that).  Does nothing in a dry
#   run, because nothing was changed.
cc_undo_add() {
    [ "$CC_APPLY" = 1 ] || return 0
    [ -f "$CC_UNDO" ] || (umask 077; : >>"$CC_UNDO")
    printf '%s\t%s\t%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$CC_ID" "$1" "$2" >>"$CC_UNDO"
    # This run's own copy, which the revert timer replays.
    [ -n "$CC_RUN_UNDO" ] && printf '%s\t%s\t%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$CC_ID" "$1" "$2" >>"$CC_RUN_UNDO"
    return 0
}

# cc_backup_file PATH
#   Copy PATH (file or folder) into this run's backup folder, keeping its full
#   path underneath, and record the restore command in the undo log.
#   Call it BEFORE changing the file.  Sets CC_LAST_BACKUP to the copy.
#   Returns 0 if backed up (or nothing to back up, or dry run), 1 on failure -
#   on failure the caller must NOT go on to change the file.
cc_backup_file() {
    CC_LAST_BACKUP=""
    if [ ! -e "$1" ]; then
        cc_debug "backup: $1 does not exist, nothing to save"
        return 0
    fi
    _cc_bk_src=$(cc_abspath "$1")
    _cc_bk_dst="$CC_BACKUP_DIR$_cc_bk_src"
    if [ "$CC_APPLY" != 1 ]; then
        cc_log WOULD "back up $_cc_bk_src"
        return 0
    fi
    (umask 077; mkdir -p "$(dirname "$_cc_bk_dst")") || { cc_err "backup: cannot create $(dirname "$_cc_bk_dst")"; return 1; }
    if cp -pR "$_cc_bk_src" "$_cc_bk_dst" 2>>"$CC_LOG"; then
        CC_LAST_BACKUP=$_cc_bk_dst
        cc_undo_add "restore $_cc_bk_src" "cp -pR $(cc_shquote "$_cc_bk_dst") $(cc_shquote "$_cc_bk_src")$(cc_relabel_cmd "$_cc_bk_src")"
        cc_debug "backup: $_cc_bk_src -> $_cc_bk_dst"
        return 0
    fi
    cc_err "backup FAILED for $_cc_bk_src - do not change this file"
    return 1
}

# -----------------------------------------------------------------------------
# Screen colours, questions and the revert timer
# -----------------------------------------------------------------------------
# Scripts that talk to the operator (sqlmap style) use these:
#   cc_color_init            set C_RED C_YEL C_GRN C_CYN C_GRY C_OFF
#   cc_show COLOUR TEXT      one line on screen, plain copy in CC_TEE
#   cc_ask QUESTION Y|N      yes/no question; Enter takes the default
#   cc_ask_text QUESTION DEF free-text question; answer in CC_ANSWER
#   cc_timer_start SECONDS   arm a revert that runs even if the session dies
#   cc_timer_finish          "keep these changes?" - keep, or revert
# --batch (CC_BATCH=1) or no terminal: every question takes its default.

# cc_now -> seconds since 1970.  'date +%s' is not POSIX; awk's srand() is.
cc_now() {
    _cc_now=$(date +%s 2>/dev/null)
    case "$_cc_now" in ''|*[!0-9]*) awk 'BEGIN { srand(); print srand() }' ;; *) printf '%s\n' "$_cc_now" ;; esac
}

# cc_color_init -> colours on when stdout is a terminal, NO_COLOR is unset
#   and the script did not set CC_NOCOLOR=1.
cc_color_init() {
    if [ "${CC_NOCOLOR:-0}" != 1 ] && [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
        C_RED=$(printf '\033[1;31m'); C_YEL=$(printf '\033[1;33m'); C_GRN=$(printf '\033[1;32m')
        C_CYN=$(printf '\033[1;36m'); C_GRY=$(printf '\033[0;90m'); C_OFF=$(printf '\033[0m')
    else
        C_RED=""; C_YEL=""; C_GRN=""; C_CYN=""; C_GRY=""; C_OFF=""
    fi
}

# cc_show COLOUR TEXT -> TEXT on screen in COLOUR; a plain copy in CC_TEE.
cc_show() {
    printf '%s%s%s\n' "$1" "$2" "${C_OFF:-}"
    [ -n "$CC_TEE" ] && printf '%s\n' "$2" >>"$CC_TEE" 2>/dev/null
    return 0
}

# cc_timer_left -> seconds until the revert timer fires (0 when it has, or
#   when no timer is running).
cc_timer_left() {
    [ "$CC_TIMER_DEADLINE" -gt 0 ] || { echo 0; return 0; }
    _cc_tl=$((CC_TIMER_DEADLINE - $(cc_now)))
    [ "$_cc_tl" -lt 0 ] && _cc_tl=0
    echo "$_cc_tl"
}
# cc_timer_fired -> true once the revert has run (or is running).
cc_timer_fired() { [ -n "$CC_TIMER_DIR" ] && { [ -f "$CC_TIMER_DIR/REVERTED" ] || [ -d "$CC_TIMER_DIR/.revert.lock" ]; }; }

# _cc_read VAR -> read one line from the terminal into VAR.  Stops at the
#   revert deadline when the shell's read has -t (bash, ksh, mksh, busybox);
#   dash's read has no -t and waits.  Returns 1 if no line was read.
_cc_read() {
    _cc_rd_left=$(cc_timer_left)
    if [ "$_cc_rd_left" -gt 0 ] && [ "${_CC_READ_T:-}" = "" ]; then
        # A shell without -t fails with status 2 ("illegal option"); one with
        # it just hits the end of /dev/null (status 1).
        # shellcheck disable=SC3045
        if ( read -r -t 1 _x </dev/null ) 2>/dev/null; [ $? -eq 1 ]; then _CC_READ_T=1; else _CC_READ_T=0; fi  # posix-ok
    fi
    if [ "$_cc_rd_left" -gt 0 ] && [ "$_CC_READ_T" = 1 ]; then
        # shellcheck disable=SC3045
        read -r -t "$_cc_rd_left" "$1" </dev/tty 2>/dev/null  # posix-ok: -t only where the shell has it
    else
        read -r "$1" </dev/tty 2>/dev/null
    fi
}

# _cc_left_txt -> " (1:42 left)" while the revert timer runs, else nothing.
_cc_left_txt() {
    _cc_lt=$(cc_timer_left)
    [ "$_cc_lt" -gt 0 ] && printf ' (%d:%02d left)' $((_cc_lt / 60)) $((_cc_lt % 60))
    return 0
}

# cc_choose QUESTION DEFAULT "l=meaning" "m=meaning" ... -> CC_CHOICE
#   Every answer is spelled out, in the password-rotation style:
#     [?] Allow root to log in over SSH? (now: key-only)
#         [y] yes, with a password or a key
#         [n] no, never
#         [k] key-only, root needs an SSH key
#         [l] leave it as it is
#         Answer [y/n/K/l]:
#   Enter takes DEFAULT (a letter, shown in capitals).  The first word of a
#   meaning works too ("yes", "no", "key-only").  Anything else is refused
#   and asked again.  With --batch or no terminal the default is taken and
#   shown with its meaning.
cc_choose() {
    _cc_ch_q=$1; _cc_ch_d=$(printf '%s' "$2" | tr 'A-Z' 'a-z'); shift 2
    _cc_ch_hint=""; _cc_ch_m=""
    for _cc_ch_o in "$@"; do
        _cc_ch_l=${_cc_ch_o%%=*}
        if [ "$_cc_ch_l" = "$_cc_ch_d" ]; then _cc_ch_m=${_cc_ch_o#*=}; _cc_ch_l=$(printf '%s' "$_cc_ch_l" | tr 'a-z' 'A-Z'); fi
        _cc_ch_hint="$_cc_ch_hint/$_cc_ch_l"
    done
    _cc_ch_hint=${_cc_ch_hint#/}
    if ! _cc_can_ask; then
        cc_show "${C_CYN:-}" "[?] $_cc_ch_q [$_cc_ch_hint] $_cc_ch_d (default): $_cc_ch_m"
        CC_CHOICE=$_cc_ch_d
        return 0
    fi
    # The question, then each answer on its own line.
    printf '%s[?]%s %s\n' "${C_CYN:-}" "${C_OFF:-}" "$_cc_ch_q" >/dev/tty
    for _cc_ch_o in "$@"; do printf '      [%s] %s\n' "${_cc_ch_o%%=*}" "${_cc_ch_o#*=}" >/dev/tty; done
    _cc_ch_prompt="      Answer [$_cc_ch_hint]:"
    while :; do
        printf '%s%s ' "$_cc_ch_prompt" "$(_cc_left_txt)" >/dev/tty
        if ! _cc_read _cc_ch_a; then
            printf '\n' >/dev/tty
            [ "$CC_TIMER_DEADLINE" -gt 0 ] && [ "$(cc_timer_left)" -eq 0 ] && cc_die 3 "the revert timer ran out while waiting for an answer. Nothing was changed. Run again (--batch or flags skip the questions; --timer SECONDS gives more time)"
            _cc_ch_a=""
        fi
        _cc_ch_t=$(printf '%s' "$_cc_ch_a" | tr 'A-Z' 'a-z' | sed 's/^ *//; s/ *$//')
        [ -z "$_cc_ch_t" ] && _cc_ch_t=$_cc_ch_d
        # The letter, or the first word of its meaning ("yes", "key-only").
        _cc_ch_a=""
        for _cc_ch_o in "$@"; do
            _cc_ch_w=$(printf '%s' "${_cc_ch_o#*=}" | awk '{ w = tolower($1); sub(/[,.:;]$/, "", w); print w }')
            if [ "$_cc_ch_t" = "${_cc_ch_o%%=*}" ] || [ "$_cc_ch_t" = "$_cc_ch_w" ]; then _cc_ch_a=${_cc_ch_o%%=*}; fi
        done
        [ -n "$_cc_ch_a" ] && break
        printf '      "%s" is not an answer here: type one of [%s] (Enter = %s).\n' "$_cc_ch_t" "$_cc_ch_hint" "$_cc_ch_d" >/dev/tty
    done
    CC_CHOICE=$_cc_ch_a
    for _cc_ch_o in "$@"; do [ "${_cc_ch_o%%=*}" = "$CC_CHOICE" ] && _cc_ch_m=${_cc_ch_o#*=}; done
    [ -n "$CC_TEE" ] && printf '[?] %s [%s] %s: %s\n' "$_cc_ch_q" "$_cc_ch_hint" "$CC_CHOICE" "$_cc_ch_m" >>"$CC_TEE"
    cc_note "asked: $_cc_ch_q -> $CC_CHOICE: $_cc_ch_m"
    return 0
}

# _cc_can_ask -> true when there is someone to ask.
#   BT_NO_TTY=1 says there is nobody (the test suite sets it, so tests
#   never wait for an answer when run from a terminal).
_cc_can_ask() { [ "$CC_BATCH" != 1 ] && [ "${BT_NO_TTY:-0}" != 1 ] && [ -r /dev/tty ] && [ -w /dev/tty ] && ( : </dev/tty ) 2>/dev/null; }

# cc_ask QUESTION DEFAULT [YES-MEANS] [NO-MEANS] -> 0 for yes, 1 for no.
#   DEFAULT is Y or N.  Shown like cc_choose, with what each answer does:
#     [?] Back up the web roots?
#         [y] yes, back them up
#         [n] no, skip them
#         Answer [Y/n]:
#   Without meanings the answers are plain "yes" and "no".  Enter takes the
#   default.  With --batch or no terminal the default is taken and shown.
#   If the revert timer runs out while waiting, the script stops (nothing
#   has been changed while questions are still being asked).
cc_ask() {
    case "${2:-N}" in Y|y) _cc_ak_d=y ;; *) _cc_ak_d=n ;; esac
    cc_choose "$1" "$_cc_ak_d" "y=${3:-yes}" "n=${4:-no}"
    [ "$CC_CHOICE" = y ]
}

# cc_ask_text QUESTION DEFAULT [WHAT-TO-TYPE] -> the answer in CC_ANSWER
#   (DEFAULT on Enter, with --batch, or with no terminal).  WHAT-TO-TYPE is
#   shown under the question, e.g. "addresses or networks separated by
#   spaces, like 10.0.0.5 10.0.0.0/24":
#     [?] Your team's addresses (never blocked)?
#         type: addresses or networks separated by spaces, like 10.0.0.5 10.0.0.0/24
#         [Enter = none]:
cc_ask_text() {
    CC_ANSWER=$2
    if ! _cc_can_ask; then
        cc_show "${C_CYN:-}" "[?] $1 ${2:-(none)} (default)"
        return 0
    fi
    if [ -n "${3:-}" ]; then
        printf '%s[?]%s %s\n' "${C_CYN:-}" "${C_OFF:-}" "$1" >/dev/tty
        printf '      type: %s\n' "$3" >/dev/tty
        printf '      [Enter = %s]:%s ' "${2:-none}" "$(_cc_left_txt)" >/dev/tty
    else
        printf '%s[?]%s %s  [Enter = %s]:%s ' "${C_CYN:-}" "${C_OFF:-}" "$1" "${2:-none}" "$(_cc_left_txt)" >/dev/tty
    fi
    if ! _cc_read _cc_at_a; then
        printf '\n' >/dev/tty
        [ "$CC_TIMER_DEADLINE" -gt 0 ] && [ "$(cc_timer_left)" -eq 0 ] && cc_die 3 "the revert timer ran out while waiting for an answer. Nothing was changed. Run again (--batch or flags skip the questions; --timer SECONDS gives more time)"
        _cc_at_a=""
    fi
    [ -n "$_cc_at_a" ] && CC_ANSWER=$_cc_at_a
    [ -n "$CC_TEE" ] && printf '[?] %s %s\n' "$1" "${CC_ANSWER:-(none)}" >>"$CC_TEE"
    cc_note "asked: $1 -> $CC_ANSWER"
    return 0
}

# cc_timer_start SECONDS
#   Arm the revert timer: after SECONDS, every change this run recorded with
#   cc_undo_add is undone (newest first) unless cc_timer_finish was answered
#   "keep".  The revert runs outside this shell (a systemd timer, else a
#   detached background job) so it still happens if the SSH or console
#   session is killed - which is the point.  Needs CC_RUN_DIR.
#   Files in the run folder:
#     undo.txt     this run's undo lines        revert.sh   runs them
#     KEEP         made by "keep" (or by hand, from another session)
#     REVERTED     made when the revert has run  revert.log  what it did
cc_timer_start() {
    _cc_ts_s=$1
    [ -n "$CC_RUN_DIR" ] || cc_die 1 "cc_timer_start needs a run folder (cc_use_run_dir first)"
    CC_TIMER_DIR=$CC_RUN_DIR
    CC_RUN_UNDO="$CC_TIMER_DIR/undo.txt"
    (umask 077; : >"$CC_RUN_UNDO")
    _cc_ts_r="$CC_TIMER_DIR/revert.sh"
    # The revert script stands alone (no library): it may run after this
    # script and the kit are gone.  It can also be run by hand at any time.
    {
        printf '#!/bin/sh\n'
        printf '# Undo everything run %s changed, newest first.  Written by %s.\n' "$(basename "$CC_TIMER_DIR")" "$CC_ID"
        printf '# Run it by hand to revert now:  sh %s\n' "$_cc_ts_r"
        printf 'D=%s\n' "$(cc_shquote "$CC_TIMER_DIR")"
        cat <<'REVERT'
[ -f "$D/KEEP" ] && [ "${1:-}" != --force ] && exit 0
mkdir "$D/.revert.lock" 2>/dev/null || exit 0
{
    echo "revert started $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    awk '{ a[NR] = $0 } END { for (i = NR; i > 0; i--) print a[i] }' "$D/undo.txt" >"$D/.undo.rev"
    T=$(printf '	')
    while IFS="$T" read -r _t _id _desc _cmd; do
        [ -n "$_cmd" ] || continue
        if sh -c "$_cmd"; then echo "undone: $_desc"; else echo "FAILED to undo: $_desc  [$_cmd]"; fi
    done <"$D/.undo.rev"
    rm -f "$D/.undo.rev"
    echo "revert finished $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} >>"$D/revert.log" 2>&1
: >"$D/REVERTED"
REVERT
    } >"$_cc_ts_r"
    chmod 700 "$_cc_ts_r"
    CC_TIMER_DEADLINE=$(( $(cc_now) + _cc_ts_s ))
    CC_TIMER_HOW=""
    # 1. A systemd transient timer: survives logout and a killed session.
    if [ "${BT_TIMER_METHOD:-}" != background ] && cc_is_root && [ -d /run/systemd/system ] && cc_have systemd-run; then
        CC_TIMER_ID="bt-revert-$$-$(cc_now)"
        if systemd-run --quiet --unit "$CC_TIMER_ID" --on-active="${_cc_ts_s}s" --timer-property=AccuracySec=1s /bin/sh "$_cc_ts_r" >>"$CC_LOG" 2>&1; then
            CC_TIMER_HOW=systemd
        fi
    fi
    # 2. A detached background job: nohup ignores the hang-up a dropped SSH
    #    session sends; setsid (where present) leaves the session entirely.
    if [ -z "$CC_TIMER_HOW" ]; then
        _cc_ts_set=""; cc_have setsid && _cc_ts_set=setsid
        # The redirections are on the wrapping ( ), not on nohup: yash keeps
        # a saved copy of the old stdout in the process that waits for a
        # redirected background job, so whatever read this script's output
        # ($( ), a pipe) would hang until the timer fired.
        # shellcheck disable=SC2086
        ( nohup $_cc_ts_set sh -c 'sleep "$1"; sh "$2"' sh "$_cc_ts_s" "$_cc_ts_r" & echo $! >"$CC_TIMER_DIR/timer.pid" ) >/dev/null 2>&1 </dev/null
        CC_TIMER_ID=$(cat "$CC_TIMER_DIR/timer.pid" 2>/dev/null)
        CC_TIMER_HOW=background
    fi
    printf 'how=%s\nid=%s\ndeadline=%s\n' "$CC_TIMER_HOW" "$CC_TIMER_ID" "$CC_TIMER_DEADLINE" >"$CC_TIMER_DIR/timer.txt"
    cc_note "revert timer armed: ${_cc_ts_s}s ($CC_TIMER_HOW $CC_TIMER_ID)"
    return 0
}

# cc_timer_cancel -> stop the pending revert (KEEP is what makes it safe;
#   stopping the job just tidies up).
cc_timer_cancel() {
    [ -n "$CC_TIMER_DIR" ] || return 0
    case "$CC_TIMER_HOW" in
        systemd)    systemctl stop "$CC_TIMER_ID.timer" "$CC_TIMER_ID.service" >/dev/null 2>&1 ;;
        background) kill "$CC_TIMER_ID" 2>/dev/null ;;
    esac
    CC_TIMER_DEADLINE=0
    return 0
}

# cc_timer_finish
#   Ask "keep these changes?".  y: keep (KEEP file, timer stopped).  n, or no
#   answer before the timer: revert now.  With --batch: keep.  With no
#   terminal and no --batch: leave the timer running and say how to keep the
#   changes from another session.  Returns 0 if the changes were kept.
cc_timer_finish() {
    [ -n "$CC_TIMER_DIR" ] || return 0
    if [ ! -s "$CC_RUN_UNDO" ]; then
        cc_timer_cancel; : >"$CC_TIMER_DIR/KEEP"
        return 0
    fi
    if cc_timer_fired; then
        cc_show "${C_RED:-}" "[!] The revert timer already ran out: the changes were undone (see $CC_TIMER_DIR/revert.log)"
        return 1
    fi
    if [ "$CC_BATCH" = 1 ]; then
        : >"$CC_TIMER_DIR/KEEP"; cc_timer_cancel
        cc_show "${C_GRN:-}" "[+] Changes kept (--batch). Revert later with: sh $CC_TIMER_DIR/revert.sh --force"
        return 0
    fi
    if ! _cc_can_ask; then
        cc_show "${C_YEL:-}" "[*] No terminal to ask. The changes are undone in $(cc_timer_left)s unless you run, from any session:"
        cc_show "${C_YEL:-}" "      touch $CC_TIMER_DIR/KEEP"
        return 0
    fi
    cc_show "${C_YEL:-}" "[*] Check you can still get in: open a NEW SSH or console session and log in now."
    if cc_ask_keep; then
        if cc_timer_fired; then
            cc_show "${C_RED:-}" "[!] Too late: the timer ran out and the changes were undone (see $CC_TIMER_DIR/revert.log)"
            return 1
        fi
        : >"$CC_TIMER_DIR/KEEP"; cc_timer_cancel
        cc_show "${C_GRN:-}" "[+] Changes kept. Revert later with: sh $CC_TIMER_DIR/revert.sh --force"
        return 0
    fi
    cc_timer_cancel
    sh "$CC_TIMER_DIR/revert.sh" --force
    cc_show "${C_RED:-}" "[!] Changes undone. What was done: $CC_TIMER_DIR/revert.log"
    return 1
}

# cc_ask_keep -> the keep question.  No answer by the deadline counts as no.
cc_ask_keep() {
    printf '%s[?]%s Keep these changes? [y/N]%s ' "${C_CYN:-}" "${C_OFF:-}" "$(_cc_left_txt)" >/dev/tty
    if ! _cc_read _cc_kp_a; then printf '\n' >/dev/tty; _cc_kp_a=""; fi
    [ -n "$CC_TEE" ] && printf '[?] Keep these changes? [y/N] %s\n' "${_cc_kp_a:-N}" >>"$CC_TEE"
    case "$_cc_kp_a" in y|Y|yes|YES|Yes) return 0 ;; *) return 1 ;; esac
}

# -----------------------------------------------------------------------------
# Protected list
# -----------------------------------------------------------------------------
# File format (CSV with a header line; see config/protected.example.csv):
#     type,value,note
#     port,80/tcp,scored web site
#     service,apache2,scored web site
#     account,svc-web,used by the scoring engine
#     path,/var/www/html,scored content
#   type   one of: port service account path host process
#   value  compared without regard to upper/lower case.  A port may be written
#          '80' (both protocols) or '80/tcp'.  Asking about plain '80' matches
#          '80/tcp' too: when unsure, the answer is "protected".
#   Lines starting with # and blank lines are ignored.  Windows line endings
#   and quotes around fields are tolerated because the file is often edited in
#   a spreadsheet.

# cc_is_protected TYPE VALUE   -> returns 0 if the pair is on the list.
cc_is_protected() {
    [ -n "$CC_PROTECTED" ] && [ -r "$CC_PROTECTED" ] || return 1
    awk -F',' -v want_type="$1" -v want_val="$2" '
        function clean(s) {    # this is awk, not shell: posix-ok
            gsub(/\r/, "", s); gsub(/^[ \t"]+|[ \t"]+$/, "", s)
            return tolower(s)
        }
        BEGIN { want_type = clean(want_type); want_val = clean(want_val); hit = 1 }
        /^[ \t]*#/ || /^[ \t\r]*$/ { next }
        {
            t = clean($1); v = clean($2)
            if (t == "type" || t != want_type) next
            if (v == want_val) { hit = 0; exit }
            if (t == "port") {
                # "80" on either side matches "80/tcp" and "80/udp".
                a = v; b = want_val
                sub(/\/.*/, "", a); sub(/\/.*/, "", b)
                if (a == b && (v !~ /\// || want_val !~ /\//)) { hit = 0; exit }
            }
        }
        END { exit hit }
    ' "$CC_PROTECTED"
}

# cc_guard TYPE VALUE   -> returns 0 if it is OK to change this item.
#   Returns 1 (and logs REFUSED) when the item is protected.  Typical use:
#       cc_guard port "$p" || continue
#   Accounts are the one type with an override: --force-scored lets a script
#   touch a protected account, with a warning in the log (rule 5).
cc_guard() {
    if cc_is_protected "$1" "$2"; then
        if [ "$1" = account ] && [ "$CC_FORCE_SCORED" = 1 ]; then
            cc_warn "protected account '$2' will be changed because --force-scored was given"
            return 0
        fi
        CC_N_REFUSED=$((CC_N_REFUSED + 1))
        cc_log REFUSED "$1 '$2' is on the protected list ($CC_PROTECTED) - skipped"
        return 1
    fi
    return 0
}

# -----------------------------------------------------------------------------
# Operating system detection
# -----------------------------------------------------------------------------

# cc_detect_os
#   Sets:
#     CC_OS_KERNEL   linux | freebsd | openbsd | netbsd | sunos | darwin | ...
#     CC_OS_FAMILY   debian | rhel | suse | alpine | arch | bsd | solaris | unknown
#     CC_OS_NAME     e.g. "Debian GNU/Linux 12 (bookworm)"
#     CC_OS_VERSION  e.g. "12"
#     CC_INIT        systemd | openrc | sysv | rc | smf | unknown
#     CC_PKG         apt | dnf | yum | zypper | apk | pacman | pkg | none
#   /etc/os-release is read as text, never sourced: sourcing would run
#   whatever a red team wrote into it.
cc_detect_os() {
    CC_OS_KERNEL=$(uname -s 2>/dev/null | tr 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' 'abcdefghijklmnopqrstuvwxyz')
    CC_OS_FAMILY=unknown; CC_OS_NAME=$(uname -sr 2>/dev/null); CC_OS_VERSION=""
    _cc_os_id=""; _cc_os_like=""
    if [ -r /etc/os-release ]; then
        _cc_os_id=$(sed -n 's/^ID=//p' /etc/os-release | tr -d '"' | head -n 1)
        _cc_os_like=$(sed -n 's/^ID_LIKE=//p' /etc/os-release | tr -d '"' | head -n 1)
        _cc_os_pretty=$(sed -n 's/^PRETTY_NAME=//p' /etc/os-release | tr -d '"' | head -n 1)
        CC_OS_VERSION=$(sed -n 's/^VERSION_ID=//p' /etc/os-release | tr -d '"' | head -n 1)
        [ -n "$_cc_os_pretty" ] && CC_OS_NAME=$_cc_os_pretty
    elif [ -r /etc/redhat-release ]; then
        _cc_os_id=rhel; CC_OS_NAME=$(head -n 1 /etc/redhat-release)
    elif [ -r /etc/debian_version ]; then
        _cc_os_id=debian; CC_OS_VERSION=$(head -n 1 /etc/debian_version)
    fi
    case " $_cc_os_id $_cc_os_like " in
        *" debian "*|*" ubuntu "*)                       CC_OS_FAMILY=debian ;;
        *" rhel "*|*" fedora "*|*" centos "*|*" rocky "*|*" almalinux "*|*" ol "*) CC_OS_FAMILY=rhel ;;
        *" suse "*|*" sles "*|*" opensuse"*)              CC_OS_FAMILY=suse ;;
        *" alpine "*)                                    CC_OS_FAMILY=alpine ;;
        *" arch "*)                                      CC_OS_FAMILY=arch ;;
    esac
    case "$CC_OS_KERNEL" in
        freebsd|openbsd|netbsd|dragonfly) CC_OS_FAMILY=bsd ;;
        sunos)                            CC_OS_FAMILY=solaris ;;
    esac

    if [ -d /run/systemd/system ]; then CC_INIT=systemd
    elif cc_have rc-service;         then CC_INIT=openrc
    elif cc_have svcadm;             then CC_INIT=smf
    elif [ -d /etc/rc.d ] && [ "$CC_OS_FAMILY" = bsd ]; then CC_INIT=rc
    elif [ -d /etc/init.d ];         then CC_INIT=sysv
    else CC_INIT=unknown
    fi

    CC_PKG=$(cc_first apt-get dnf yum zypper apk pacman pkg) || CC_PKG=none
    [ "$CC_PKG" = apt-get ] && CC_PKG=apt
    cc_debug "os: kernel=$CC_OS_KERNEL family=$CC_OS_FAMILY name='$CC_OS_NAME' version=$CC_OS_VERSION init=$CC_INIT pkg=$CC_PKG"
    return 0
}

# -----------------------------------------------------------------------------
# Services and SELinux (systemd, OpenRC or SysV init)
# -----------------------------------------------------------------------------

# cc_svc ACTION NAME -> run ACTION on service NAME with this box's init system.
#   ACTION: start stop restart reload enable disable is-active is-enabled exists
#   systemd: systemctl; OpenRC (Alpine): rc-service / rc-update; SysV: service
#   and update-rc.d or chkconfig.  Returns the tool's exit code.  BT_SVC_INIT
#   overrides the detected init (the tests use it).
cc_svc() {
    _cc_sv_i=${BT_SVC_INIT:-${CC_INIT:-}}
    [ -n "$_cc_sv_i" ] || { cc_detect_os; _cc_sv_i=$CC_INIT; }
    case "$_cc_sv_i:$1" in
        systemd:exists)      systemctl list-unit-files "$2.service" "$2" 2>/dev/null | grep -q "^$2[.@ ]" ;;
        systemd:*)           systemctl "$1" "$2" ;;
        openrc:exists)       [ -x "/etc/init.d/$2" ] ;;
        openrc:is-active)    rc-service "$2" status >/dev/null 2>&1 ;;
        openrc:is-enabled)   rc-update show -v 2>/dev/null | awk -v s="$2" '$1 == s && $3 != "" { f = 1 } END { exit !f }' ;;
        openrc:enable)       rc-update add "$2" default ;;
        openrc:disable)      rc-update -a del "$2" ;;
        openrc:*)            rc-service "$2" "$1" ;;
        *:exists)            [ -x "/etc/init.d/$2" ] ;;
        *:is-active)         service "$2" status >/dev/null 2>&1 ;;
        *:is-enabled)        ls /etc/rc[2345].d/S*"$2" >/dev/null 2>&1 ;;
        *:enable)            if cc_have update-rc.d; then update-rc.d "$2" enable; else chkconfig "$2" on; fi ;;
        *:disable)           if cc_have update-rc.d; then update-rc.d "$2" disable; else chkconfig "$2" off; fi ;;
        *)                   service "$2" "$1" ;;
    esac
}
# cc_svc_cmd ACTION NAME -> the same as a command line (for undo lines)
cc_svc_cmd() {
    _cc_sc_i=${BT_SVC_INIT:-${CC_INIT:-}}
    case "$_cc_sc_i:$1" in
        systemd:*)         printf 'systemctl %s %s' "$1" "$(cc_shquote "$2")" ;;
        openrc:enable)     printf 'rc-update add %s default' "$(cc_shquote "$2")" ;;
        openrc:disable)    printf 'rc-update -a del %s' "$(cc_shquote "$2")" ;;
        openrc:*)          printf 'rc-service %s %s' "$(cc_shquote "$2")" "$1" ;;
        *:enable)          printf '{ update-rc.d %s enable || chkconfig %s on; }' "$(cc_shquote "$2")" "$(cc_shquote "$2")" ;;
        *:disable)         printf '{ update-rc.d %s disable || chkconfig %s off; }' "$(cc_shquote "$2")" "$(cc_shquote "$2")" ;;
        *)                 printf 'service %s %s' "$(cc_shquote "$2")" "$1" ;;
    esac
}
# cc_selinux_on -> true when SELinux is enforcing or permissive on this box
cc_selinux_on() {
    [ -n "${BT_SELINUX:-}" ] && { [ "$BT_SELINUX" = 1 ]; return; }
    cc_have selinuxenabled && selinuxenabled 2>/dev/null
}
# cc_relabel_cmd PATH -> "; restorecon ..." to add to an undo line on an
#   SELinux box (a file put back by cp or mv may carry the wrong label, and a
#   service then cannot read it); nothing elsewhere.
cc_relabel_cmd() { cc_selinux_on && cc_have restorecon && printf '; restorecon -R %s 2>/dev/null' "$(cc_shquote "$1")"; return 0; }
# cc_relabel PATH... -> restore the SELinux label of new or replaced files (no-op elsewhere)
cc_relabel() { cc_selinux_on && cc_have restorecon || return 0; restorecon -R "$@" 2>/dev/null; return 0; }

# -----------------------------------------------------------------------------
# Hashing, passwords, quarantine
# -----------------------------------------------------------------------------

# cc_sha256 FILE   -> print the SHA-256 of FILE in lower-case hex.
#   Tries every tool a Unix system might have.  Returns 1 if none exists.
cc_sha256() {
    if   cc_have sha256sum; then sha256sum "$1" 2>/dev/null | awk '{print $1}'
    elif cc_have shasum;    then shasum -a 256 "$1" 2>/dev/null | awk '{print $1}'
    elif cc_have sha256;    then sha256 -q "$1" 2>/dev/null
    elif cc_have digest;    then digest -a sha256 "$1" 2>/dev/null
    elif cc_have openssl;   then openssl dgst -sha256 "$1" 2>/dev/null | awk '{print $NF}'
    else return 1
    fi
}

# cc_genpass [LENGTH]   -> print one random password (default 16 characters).
#   Characters: letters and digits without the look-alikes 0 O 1 l I, plus
#   '_' and '-'.  Those are accepted by every service we expect to be scored
#   and survive being typed into a shell, a SQL statement or a URL.  The
#   result always has an upper-case letter, a lower-case letter and a digit,
#   and never starts with '-' (which a command could read as an option).
#   The password is PRINTED ONLY - this function never logs it.  The caller
#   must send it to the operator's credential file, not to cc_log or cc_run.
cc_genpass() {
    _cc_gp_len=${1:-16}
    [ -r /dev/urandom ] || { cc_err "cc_genpass: /dev/urandom is not readable"; return 3; }
    _cc_gp_try=0
    while [ "$_cc_gp_try" -lt 50 ]; do
        _cc_gp_try=$((_cc_gp_try + 1))
        _cc_gp=$(LC_ALL=C tr -dc 'A-HJ-NP-Za-km-z2-9_-' </dev/urandom 2>/dev/null | dd bs=1 count="$_cc_gp_len" 2>/dev/null)
        [ "${#_cc_gp}" -eq "$_cc_gp_len" ] || continue
        case "$_cc_gp" in -*|_*) continue ;; esac
        case "$_cc_gp" in *[A-Z]*) ;; *) continue ;; esac
        case "$_cc_gp" in *[a-z]*) ;; *) continue ;; esac
        case "$_cc_gp" in *[0-9]*) ;; *) continue ;; esac
        printf '%s\n' "$_cc_gp"
        return 0
    done
    cc_err "cc_genpass: could not generate a password (is 'tr' the GNU/BSD/busybox kind?)"
    return 1
}

# cc_quarantine PATH
#   Move a suspicious file or folder out of the way without destroying it:
#   it goes to <out>/quarantine/<host>/<run>/<original full path>, its SHA-256
#   is logged, and the undo log gets the command that puts it back.
#   Refuses paths on the protected list.  Returns 0 on success or dry run.
cc_quarantine() {
    if [ ! -e "$1" ] && [ ! -h "$1" ]; then
        cc_debug "quarantine: $1 does not exist"
        return 0
    fi
    _cc_q_src=$(cc_abspath "$1")
    cc_guard path "$_cc_q_src" || return 4
    _cc_q_dst="$CC_QUAR_DIR$_cc_q_src"
    _cc_q_hash=""
    [ -f "$_cc_q_src" ] && _cc_q_hash=$(cc_sha256 "$_cc_q_src")
    if [ "$CC_APPLY" != 1 ]; then
        cc_log WOULD "quarantine $_cc_q_src (sha256 ${_cc_q_hash:-n/a})"
        CC_N_WOULD=$((CC_N_WOULD + 1))
        return 0
    fi
    (umask 077; mkdir -p "$(dirname "$_cc_q_dst")") || { cc_err "quarantine: cannot create $(dirname "$_cc_q_dst")"; CC_N_FAIL=$((CC_N_FAIL + 1)); return 1; }
    if mv "$_cc_q_src" "$_cc_q_dst" 2>>"$CC_LOG"; then
        CC_N_DONE=$((CC_N_DONE + 1))
        cc_log DO "quarantined $_cc_q_src -> $_cc_q_dst (sha256 ${_cc_q_hash:-n/a})"
        cc_undo_add "un-quarantine $_cc_q_src" "mv $(cc_shquote "$_cc_q_dst") $(cc_shquote "$_cc_q_src")$(cc_relabel_cmd "$_cc_q_src")"
        return 0
    fi
    CC_N_FAIL=$((CC_N_FAIL + 1))
    cc_err "quarantine FAILED for $_cc_q_src (immutable flag? try: lsattr / chattr -i)"
    return 1
}

# -----------------------------------------------------------------------------
# Output files
# -----------------------------------------------------------------------------

# cc_csv_new NAME HEADER   -> create a CSV with the given header line and
#   print its path.  Normally <out>/<ID>_<host>_<time>_<NAME>.csv; after
#   cc_use_run_dir it is <run folder>/<NAME>.csv.
#       f=$(cc_csv_new ports "proto,port,process,user")
#   NOTE: this prints the path, so it is called inside $( ).  Anything it sets
#   is lost in that subshell, which is why it sets nothing.
cc_csv_new() {
    if [ -n "$CC_CSV_DIR" ]; then
        _cc_csv_f="$CC_CSV_DIR/$1.csv"
    else
        _cc_csv_f="$CC_OUT/${CC_ID}_${CC_HOST}_${CC_TS}_$1.csv"
    fi
    (umask 077; printf '%s\n' "$2" >"$_cc_csv_f") || { cc_err "cannot write $_cc_csv_f"; return 1; }
    printf '%s\n' "$_cc_csv_f"
}

# cc_csv_row FILE FIELD...   -> append one row.  Every field is quoted, quotes
#   inside a field are doubled and line breaks become spaces, so the file
#   opens cleanly in a spreadsheet whatever the data contains.
cc_csv_row() {
    _cc_row_f=$1
    shift
    _cc_row_line=""
    _cc_row_first=1
    for _cc_row_v in "$@"; do
        case "$_cc_row_v" in
            *'"'*|*'
'*) _cc_row_v=$(printf '%s' "$_cc_row_v" | tr '\n\r' '  ' | sed 's/"/""/g') ;;
        esac
        if [ "$_cc_row_first" = 1 ]; then
            _cc_row_line="\"$_cc_row_v\""; _cc_row_first=0
        else
            _cc_row_line="$_cc_row_line,\"$_cc_row_v\""
        fi
    done
    printf '%s\n' "$_cc_row_line" >>"$_cc_row_f"
}

# cc_finding WEAKNESS FIX_ID CLASS DETAIL [PROTECTED_DEPENDENCY]
#   Detection scripts never fix anything; they write findings (the "detect,
#   then fix" rule).  A fix script later reads this file and acts by class:
#     safe       cannot break a scored service; applied in apply mode
#     service    might affect a service; skipped unless named explicitly
#     protected  would touch a protected item; always refused
#   File: <out>/<ID>_<host>_<time>_findings.csv with columns
#     host,script,weakness,fix_id,class,protected_dep,detail,time
cc_finding() {
    case "$3" in safe|service|protected) ;; *) cc_die 1 "cc_finding: class must be safe, service or protected (got '$3')" ;; esac
    # Created on first use.  The path is also derivable from the run, so a
    # finding written inside a subshell still lands in the same file.
    if [ -z "$CC_FINDINGS" ]; then
        if [ -n "$CC_CSV_DIR" ]; then _cc_fd_f="$CC_CSV_DIR/findings.csv"; else _cc_fd_f="$CC_OUT/${CC_ID}_${CC_HOST}_${CC_TS}_findings.csv"; fi
        if [ -f "$_cc_fd_f" ]; then CC_FINDINGS=$_cc_fd_f
        else CC_FINDINGS=$(cc_csv_new findings "host,script,weakness,fix_id,class,protected_dep,detail,time") || return 1
        fi
    fi
    cc_csv_row "$CC_FINDINGS" "$CC_HOST" "$CC_ID" "$1" "$2" "$3" "${5:-}" "$4" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    CC_N_FIND=$((CC_N_FIND + 1))
    cc_log FINDING "[$3] $1 ($2): $4"
}

# -----------------------------------------------------------------------------
# Inventory helpers: run folder, raw capture, flags
# -----------------------------------------------------------------------------
# Inventory scripts write many files.  They call cc_use_run_dir once after
# cc_init so everything for one run sits in one folder:
#     <out>/<ID>_<host>_<UTC time>/
#         <section>.csv        one per section       (cc_csv_new)
#         flags.csv            unusual items         (cc_flag)
#         raw/<name>.txt       untouched tool output (cc_save)
# The log file and the undo log stay in <out> itself, beside every other
# script's, so all logs for a host are in one place.

# cc_use_run_dir   -> create the run folder and send CSV files there.
#   Sets CC_RUN_DIR and CC_CSV_DIR.
cc_use_run_dir() {
    # Two runs in the same second would share one folder and mix their CSVs,
    # so claim the folder with a plain mkdir (it fails if the folder exists)
    # and add -2, -3, ... until one is free.  The suffix still sorts after
    # the plain time, so "newest last" ordering keeps working.
    CC_RUN_DIR="$CC_OUT/${CC_ID}_${CC_HOST}_${CC_TS}"
    _cc_rd_n=1
    while ! (umask 077; mkdir "$CC_RUN_DIR" 2>/dev/null); do
        [ -d "$CC_RUN_DIR" ] || cc_die 3 "cannot create run folder $CC_RUN_DIR (check that $CC_OUT is writable)"
        _cc_rd_n=$((_cc_rd_n + 1))
        [ "$_cc_rd_n" -le 99 ] || cc_die 3 "too many run folders named ${CC_ID}_${CC_HOST}_${CC_TS}-N in $CC_OUT"
        CC_RUN_DIR="$CC_OUT/${CC_ID}_${CC_HOST}_${CC_TS}-$_cc_rd_n"
    done
    (umask 077; mkdir -p "$CC_RUN_DIR/raw") || cc_die 3 "cannot create run folder $CC_RUN_DIR"
    CC_CSV_DIR=$CC_RUN_DIR
    cc_debug "run folder: $CC_RUN_DIR"
}

# cc_use_numbered_dir NAME  -> <out>/NAME-1, NAME-2, ... (next free number)
#   Same as cc_use_run_dir, but the folder is named by a plain counter so it
#   is easy to see which run came first.  The ID, host and start time go in
#   <folder>/run.txt (id=, host=, time=), which SH-04 reads to match runs.
cc_use_numbered_dir() {
    _cc_nd_max=0
    for _cc_nd_d in "$CC_OUT/$1"-*; do
        [ -d "$_cc_nd_d" ] || continue
        _cc_nd_x=${_cc_nd_d##*-}
        case "$_cc_nd_x" in ''|*[!0-9]*) continue ;; esac
        [ "$_cc_nd_x" -gt "$_cc_nd_max" ] && _cc_nd_max=$_cc_nd_x
    done
    # mkdir fails if the folder exists, so two runs started together still
    # get different numbers.
    _cc_nd_n=$((_cc_nd_max + 1))
    while ! (umask 077; mkdir "$CC_OUT/$1-$_cc_nd_n" 2>/dev/null); do
        [ -d "$CC_OUT/$1-$_cc_nd_n" ] || cc_die 3 "cannot create run folder $CC_OUT/$1-$_cc_nd_n (check that $CC_OUT is writable)"
        _cc_nd_n=$((_cc_nd_n + 1))
        [ "$_cc_nd_n" -le $((_cc_nd_max + 99)) ] || cc_die 3 "cannot find a free number for $CC_OUT/$1-N"
    done
    CC_RUN_DIR="$CC_OUT/$1-$_cc_nd_n"
    (umask 077; mkdir -p "$CC_RUN_DIR/raw") || cc_die 3 "cannot create run folder $CC_RUN_DIR"
    printf 'id=%s\nhost=%s\ntime=%s\n' "$CC_ID" "$CC_HOST" "$CC_TS" >"$CC_RUN_DIR/run.txt"
    CC_CSV_DIR=$CC_RUN_DIR
    cc_debug "run folder: $CC_RUN_DIR"
}

# cc_csv_pretty CSV TXT [WIDTH]
#   Write CSV as an aligned table people can read in a terminal (cat, less -S):
#   header in capitals, a dashed line, then one row per line.  Columns wider
#   than WIDTH (default 60) are cut with "...".  The CSV is not changed.
cc_csv_pretty() {
    [ -f "$1" ] || return 0
    awk -v maxw="${3:-60}" "$CC_AWK_CSV"'
        function cut(s) { if (length(s) > maxw) s = substr(s, 1, maxw - 3) "..."; return s }  # awk, not shell: posix-ok
        NR == FNR {
            n = csvsplit($0, f); if (n > nc) nc = n
            for (i = 1; i <= n; i++) { v = cut(f[i]); if (length(v) > w[i]) w[i] = length(v) }
            next
        }
        {
            n = csvsplit($0, f); line = ""
            for (i = 1; i <= nc; i++) {
                v = (i <= n) ? cut(f[i]) : ""
                if (FNR == 1) v = toupper(v)
                line = line sprintf("%-" w[i] "s", v) (i < nc ? "  " : "")
            }
            sub(/ +$/, "", line); print line
            if (FNR == 1) {
                line = ""
                for (i = 1; i <= nc; i++) { d = sprintf("%" w[i] "s", ""); gsub(/ /, "-", d); line = line d (i < nc ? "  " : "") }
                print line
            }
        }
        END { if (FNR <= 1) print "(nothing found)" }' "$1" "$1" >"$2"
}

# cc_save NAME COMMAND [ARG...]
#   Run a READ-ONLY command and keep its untouched output in
#   <run folder>/raw/NAME.txt (or <out>/<ID>_<host>_<time>_NAME.txt without a
#   run folder).  The first line records the command.  Use it for output that
#   is worth keeping but too varied to turn into CSV (iptables-save, sshd -T).
#   This does NOT honour dry-run: never pass it a command that changes things.
#   Returns the command's exit code; sets CC_LAST_SAVE to the file.
cc_save() {
    _cc_sv_name=$1
    shift
    if [ -n "$CC_RUN_DIR" ]; then CC_LAST_SAVE="$CC_RUN_DIR/raw/$_cc_sv_name.txt"
    else CC_LAST_SAVE="$CC_OUT/${CC_ID}_${CC_HOST}_${CC_TS}_$_cc_sv_name.txt"
    fi
    printf '# command: %s\n# time: %s\n' "$*" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$CC_LAST_SAVE"
    "$@" >>"$CC_LAST_SAVE" 2>&1
    _cc_sv_rc=$?
    cc_debug "saved '$*' to $CC_LAST_SAVE (exit $_cc_sv_rc)"
    return "$_cc_sv_rc"
}

# cc_flag SEVERITY SECTION ITEM DETAIL
#   Record something unusual that an operator should look at.  Inventory
#   scripts never act on what they see; a flag only says "look here".
#     SEVERITY  HIGH  likely red team activity or an open door - look now
#               MED   risky or unusual - look soon
#               LOW   worth knowing - kept in the file, not shown on screen
#     SECTION   which part of the script found it (users, ports, ...)
#     ITEM      the thing itself, short (an account, a port, a path)
#     DETAIL    one sentence: what is wrong and why it matters
#   Written to flags.csv (columns: severity,section,item,detail,time) and to
#   the log file.  Not printed while the script runs; cc_flag_report prints
#   the HIGH and MED ones at the end, worst first (rule 17).
#   Safe to call from a subshell: the file is the record, not a variable.
#   Never put a password or other secret in ITEM or DETAIL.
cc_flag() {
    case "$1" in HIGH|MED|LOW) ;; *) cc_die 1 "cc_flag: severity must be HIGH, MED or LOW (got '$1')" ;; esac
    # CC_TABLES=1: flags.txt, a text table (the same columns), no CSV.
    if [ "$CC_TABLES" = 1 ]; then
        if [ -z "$CC_FLAGS" ]; then
            if [ -n "$CC_RUN_DIR" ]; then CC_FLAGS="$CC_RUN_DIR/flags.txt"; else CC_FLAGS="$CC_OUT/${CC_ID}_${CC_HOST}_${CC_TS}_flags.txt"; fi
            [ -f "$CC_FLAGS" ] || (umask 077; printf 'severity | section | item | detail | time\n' >"$CC_FLAGS")
        fi
        cc_table_row "$CC_FLAGS" "$1" "$2" "$3" "$4" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        CC_N_FLAG=$((CC_N_FLAG + 1))
        cc_note "FLAG $1 [$2] $3: $4"
        return 0
    fi
    if [ -z "$CC_FLAGS" ]; then
        if [ -n "$CC_CSV_DIR" ]; then CC_FLAGS="$CC_CSV_DIR/flags.csv"; else CC_FLAGS="$CC_OUT/${CC_ID}_${CC_HOST}_${CC_TS}_flags.csv"; fi
        [ -f "$CC_FLAGS" ] || (umask 077; printf 'severity,section,item,detail,time\n' >"$CC_FLAGS")
    fi
    cc_csv_row "$CC_FLAGS" "$1" "$2" "$3" "$4" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    CC_N_FLAG=$((CC_N_FLAG + 1))
    cc_note "FLAG $1 [$2] $3: $4"
}

# CC_AWK_CSV: an awk function that splits one CSV line correctly (quoted
# fields, doubled quotes, commas inside quotes).  Paste it in front of an awk
# program that reads files this kit wrote:
#     awk "$CC_AWK_CSV"'{ n = csvsplit($0, f); print f[1] }' file.csv
CC_AWK_CSV='
function csvsplit(s, a,   n, i, c, f, q, len) {    # awk, not shell: posix-ok
    n = 0; f = ""; q = 0; len = length(s)
    for (i = 1; i <= len; i++) {
        c = substr(s, i, 1)
        if (q) {
            if (c == "\"") {
                if (substr(s, i + 1, 1) == "\"") { f = f "\""; i++ } else q = 0
            } else f = f c
        } else if (c == "\"") q = 1
        else if (c == ",") { a[++n] = f; f = "" }
        else if (c != "\r") f = f c
    }
    a[++n] = f
    return n
}'

# cc_flag_report [MAX]
#   Print the HIGH flags, then the MED flags, at most MAX lines in total
#   (default 30), then how many LOW flags and how many were cut, with the path
#   of flags.csv.  Each screen line is cut at 200 characters; the file keeps
#   the full text.  Reads the file, so it counts flags written from subshells.
#   Prints "no flags" when there are none.
cc_flag_report() {
    _cc_fr_max=${1:-30}
    # If every flag was written from a subshell, this shell never learned the
    # file name; it is always <run folder>/flags.csv in that case.
    if [ -z "$CC_FLAGS" ] && [ -n "$CC_CSV_DIR" ] && [ -f "$CC_CSV_DIR/flags.csv" ]; then
        CC_FLAGS="$CC_CSV_DIR/flags.csv"
    fi
    if [ -z "$CC_FLAGS" ] && [ "$CC_TABLES" = 1 ] && [ -n "$CC_RUN_DIR" ] && [ -f "$CC_RUN_DIR/flags.txt" ]; then
        CC_FLAGS="$CC_RUN_DIR/flags.txt"
    fi
    if [ -z "$CC_FLAGS" ] || [ ! -f "$CC_FLAGS" ]; then
        printf 'Flags: none\n'
        return 0
    fi
    # CC_FLAGS_SHOW: the path to name on screen, when a script writes a
    # readable copy of flags.csv (SH-05 writes flags.txt).
    _cc_fr_t=0; case "$CC_FLAGS" in *.txt) _cc_fr_t=1 ;; esac
    awk -v max="$_cc_fr_max" -v file="${CC_FLAGS_SHOW:-$CC_FLAGS}" -v t="$_cc_fr_t" "$CC_AWK_CSV$CC_AWK_TABLE"'
        NR == 1 { next }
        {
            if (t) tsplit($0, f); else csvsplit($0, f)
            sev = f[1]; cnt[sev]++
            line = "  [" f[2] "] " f[3] ": " f[4]
            # Screen lines are cut at 200 characters; flags.csv keeps the full text.
            if (length(line) > 200) line = substr(line, 1, 197) "..."
            if (sev == "HIGH") hi[++nh] = line
            else if (sev == "MED") me[++nm] = line
        }
        END {
            shown = 0
            printf "Flags: %d high, %d medium, %d low\n", cnt["HIGH"], cnt["MED"], cnt["LOW"]
            if (nh) { print "HIGH - look now"; for (i = 1; i <= nh && shown < max; i++) { print hi[i]; shown++ } }
            if (nm && shown < max) { print "MED - look soon"; for (i = 1; i <= nm && shown < max; i++) { print me[i]; shown++ } }
            cut = nh + nm - shown
            if (cut > 0) printf "  ... %d more high/medium not shown\n", cut
            if (cnt["LOW"] + cut > 0) printf "All flags, including low: %s\n", file
        }' "$CC_FLAGS"
}

# -----------------------------------------------------------------------------
# Text tables (instead of CSV)
# -----------------------------------------------------------------------------
# A table is a .txt file people read and scripts parse: the first line names
# the columns, then one row per line, columns separated by " | ":
#     ip         | proto | port | service
#     10.0.0.5   | tcp   | 80   | http
# A "|" inside a value becomes "/", a line break a space, so every line splits
# the same way.  cc_table_align lines the columns up once a table is done;
# the result still splits the same way.
#   f=$(cc_table_new ports ip proto port service)
#   cc_table_row "$f" 10.0.0.5 tcp 80 http
#   cc_table_align "$f"
#   awk "$CC_AWK_TABLE"'NR > 1 { tsplit($0, a); print a[3] }' "$f"

# cc_table_new NAME COLUMN... -> create <run folder>/NAME.txt (else
#   <out>/<ID>_<host>_<time>_NAME.txt) with its header line; print the path.
cc_table_new() {
    _cc_tn=$1; shift
    if [ -n "$CC_RUN_DIR" ]; then _cc_tf="$CC_RUN_DIR/$_cc_tn.txt"; else _cc_tf="$CC_OUT/${CC_ID}_${CC_HOST}_${CC_TS}_$_cc_tn.txt"; fi
    (umask 077; cc_table_line "$@" >"$_cc_tf") || { cc_err "cannot write $_cc_tf"; return 1; }
    printf '%s\n' "$_cc_tf"
}
# cc_table_line VALUE... -> one table line on stdout
cc_table_line() {
    _cc_tl=""; _cc_t1=1
    for _cc_tv in "$@"; do
        case "$_cc_tv" in *'|'*|*'
'*) _cc_tv=$(printf '%s' "$_cc_tv" | tr '|\n\r' '/  ') ;; esac
        if [ "$_cc_t1" = 1 ]; then _cc_tl=$_cc_tv; _cc_t1=0; else _cc_tl="$_cc_tl | $_cc_tv"; fi
    done
    printf '%s\n' "$_cc_tl"
}
# cc_table_row FILE VALUE... -> append one row
cc_table_row() { _cc_trf=$1; shift; cc_table_line "$@" >>"$_cc_trf"; }
# cc_table_align FILE -> pad every column to its widest value (in place)
cc_table_align() {
    [ -f "$1" ] || return 0
    awk "$CC_AWK_TABLE"'
        NR == FNR { n = tsplit($0, f); if (n > nc) nc = n; for (i = 1; i <= n; i++) if (length(f[i]) > w[i]) w[i] = length(f[i]); next }
        { n = tsplit($0, f); l = ""
          for (i = 1; i <= nc; i++) l = l (i > 1 ? " | " : "") sprintf("%-" w[i] "s", (i <= n ? f[i] : ""))
          sub(/ +$/, "", l); print l }' "$1" "$1" >"$1.al" && cat "$1.al" >"$1"
    rm -f "$1.al"
}
# cc_table_sort_flags FILE -> flags.txt with HIGH first, then MED, LOW (aligned)
cc_table_sort_flags() {
    [ -f "$1" ] || return 0
    awk "$CC_AWK_TABLE"'NR == 1 { print; next } { tsplit($0, f); r[f[1]] = r[f[1]] $0 "\n" }
        END { printf "%s%s%s", r["HIGH"], r["MED"], r["LOW"] }' "$1" >"$1.s" && cat "$1.s" >"$1"
    rm -f "$1.s"
    cc_table_align "$1"
}
# CC_AWK_TABLE: tsplit(line, a) -> the fields of one table line, trimmed.
CC_AWK_TABLE='
function tsplit(s, a,   n, i) {    # awk, not shell: posix-ok
    n = split(s, a, "|")
    for (i = 1; i <= n; i++) { sub(/^[ \t]+/, "", a[i]); sub(/[ \t\r]+$/, "", a[i]) }
    return n
}'

# -----------------------------------------------------------------------------
# Host list
# -----------------------------------------------------------------------------
# config/hosts.txt (see config/hosts.example.txt): one machine per line,
# columns separated by spaces, "-" for an empty one, the notes are the rest
# of the line; lines starting with # are comments:
#     # name   ip         os       role    connect  port  user   scored_services   notes
#     web01    10.0.0.20  linux    web     ssh      22    root   http:80;https:443 Ubuntu web box
#     fw1      10.0.0.1   network  edge    ssh      22    admin  -                 Palo Alto PA-220
# An older host list in CSV (host,ip,os,... with a header line) is still read.
# cc_hosts_rows FILE -> one line per machine:
#     name|ip|os|role|connect|port|user|scored_services|notes|vendor
#   (vendor: only from an older CSV list's "vendor" column; "|" in a value
#   becomes "/").
cc_hosts_rows() {
    _cc_hf=$1
    [ -r "$_cc_hf" ] || { cc_err "cannot read the host list $_cc_hf"; return 1; }
    _cc_hc=$(tr -d '\r' <"$_cc_hf" | awk '/^[ \t]*(#|$)/ { next } { print; exit }')
    case "$_cc_hc" in
        host,*|*,ip,*|name,*)
            tr -d '\r' <"$_cc_hf" | awk -F',' "$CC_AWK_CSV"'
                function g(k,   v) { v = (k in c) ? f[c[k]] : ""; gsub(/\|/, "/", v); return v }    # awk, not shell: posix-ok
                /^[ \t]*#/ || NF < 2 { next }
                !hdr { n = csvsplit($0, h); for (i = 1; i <= n; i++) c[tolower(h[i])] = i; if (!("host" in c) && ("name" in c)) c["host"] = c["name"]; hdr = 1; next }
                { csvsplit($0, f); print g("host") "|" g("ip") "|" g("os") "|" g("role") "|" g("connect") "|" g("port") "|" g("user") "|" g("scored_services") "|" g("notes") "|" g("vendor") }' ;;
        *)
            tr -d '\r' <"$_cc_hf" | awk '
                /^[ \t]*(#|$)/ { next }
                NF < 2 { next }
                tolower($1) ~ /^(name|host)$/ && tolower($2) == "ip" { next }
                { gsub(/\|/, "/")
                  for (i = 1; i <= 8; i++) v[i] = (i <= NF && $i != "-") ? $i : ""
                  nt = ""; for (i = 9; i <= NF; i++) nt = nt (nt == "" ? "" : " ") $i; if (nt == "-") nt = ""
                  print v[1] "|" v[2] "|" v[3] "|" v[4] "|" v[5] "|" v[6] "|" v[7] "|" v[8] "|" nt "|" }' ;;
    esac
}

# -----------------------------------------------------------------------------
# Network devices: the questions every NW script asks when no flag names them
# -----------------------------------------------------------------------------
# cc_net_hostfile -> the first host list lying around (config/hosts.txt,
#   hosts.txt in the current folder), or nothing.
cc_net_hostfile() {
    for _cc_nh in config/hosts.txt hosts.txt; do [ -r "$_cc_nh" ] && { printf '%s' "$_cc_nh"; return 0; }; done
    return 1
}
# cc_net_ask_devices DEFAULT-USER USER-GIVEN(0|1)
#   Asks which devices to work on, in the password-rotation style:
#     the host list, when one is found:   "Use the host list config/hosts.txt?"
#     else device by device:              address, what it is ([o] OpenWRT
#                                         first), a short name, the login
#                                         (root for OpenWRT, pfSense, OPNsense
#                                         unless --user was given)
#   Sets CC_NET_HOSTS (the list chosen) or appends "NAME,ADDRESS,VENDOR,USER"
#   lines to CC_NET_DEVICES.  Returns 1 when nothing was chosen.  With nobody
#   to ask, only a host list found lying around is taken.
cc_net_ask_devices() {
    CC_NET_HOSTS=""; CC_NET_DEVICES=""
    if _cc_nf=$(cc_net_hostfile); then
        if cc_ask "Use the host list $_cc_nf (the network devices in it)?" Y "yes, use every network device in it" "no, I will type the devices"; then
            CC_NET_HOSTS=$_cc_nf; return 0
        fi
    fi
    _cc_can_ask || return 1
    while :; do
        cc_ask_text "Device address (IP or name)? Enter when done" "" "like 192.168.220.2"
        _cc_na=$CC_ANSWER; [ -n "$_cc_na" ] || break
        case "$_cc_na" in *[!A-Za-z0-9._:-]*) cc_show "${C_YEL:-}" "  [*] '$_cc_na' is not an address: skipped"; continue ;; esac
        cc_choose "What is $_cc_na?" o "o=OpenWRT router" "l=Linux router" "m=MikroTik" "p=pfSense" "n=OPNsense" \
            "c=Cisco router or switch (IOS)" "a=Cisco ASA" "x=Palo Alto" "f=FortiGate" "v=VyOS"
        case "$CC_CHOICE" in o) _cc_nv=openwrt ;; l) _cc_nv=linux ;; m) _cc_nv=mikrotik ;; p) _cc_nv=pfsense ;; n) _cc_nv=opnsense ;;
            c) _cc_nv=cisco-ios ;; a) _cc_nv=cisco-asa ;; x) _cc_nv=paloalto ;; f) _cc_nv=fortigate ;; *) _cc_nv=vyos ;; esac
        # OpenWRT, pfSense and OPNsense: root runs the commands.
        _cc_nu=$1; [ "${2:-0}" = 0 ] && case "$_cc_nv" in openwrt|pfsense|opnsense) _cc_nu=root ;; esac
        _cc_nd=router; case "$_cc_nv" in cisco-asa|paloalto|fortigate|pfsense|opnsense) _cc_nd=firewall ;; esac
        cc_ask_text "A short name for it (letters, digits, - and _)?" "$_cc_nd"; _cc_nn=$CC_ANSWER
        case "$_cc_nn" in ''|*[!A-Za-z0-9_.-]*) _cc_nn=$_cc_nd ;; esac
        cc_ask_text "Log in to $_cc_nn as?" "$_cc_nu"; _cc_nu=${CC_ANSWER:-$_cc_nu}
        CC_NET_DEVICES="$CC_NET_DEVICES$_cc_nn,$_cc_na,$_cc_nv,$_cc_nu
"
        cc_ask "Another device?" N "yes, add one more" "no, that is all" || break
    done
    [ -n "$CC_NET_DEVICES" ]
}
# cc_net_ask_password [LABEL] -> BT_NET_PASS: used as it is when already set (setting
#   it is the answer), else typed now, hidden, never logged.  Returns 1 when
#   there is no password and nobody to ask.
cc_net_ask_password() {
    [ -n "${BT_NET_PASS:-}" ] && return 0
    _cc_can_ask || return 1
    printf '%s[?]%s %s (hidden, never saved): ' "${C_CYN:-}" "${C_OFF:-}" "${1:-Device password}" >/dev/tty
    stty -echo </dev/tty 2>/dev/null; read -r BT_NET_PASS </dev/tty; stty echo </dev/tty 2>/dev/null; printf '\n' >/dev/tty
    [ -n "$BT_NET_PASS" ]
}

# -----------------------------------------------------------------------------
# Kit integrity and finish
# -----------------------------------------------------------------------------

# cc_verify_self
#   Rule 15: the kit's hash is checked before each run.  tools/build.sh
#   writes SCRIPT.sha256 next to each script; when it is there (or
#   BT_MANIFEST names a hash list), the running script's hash must match it.
#   An older kit's MANIFEST.sha256 in the script's folder or one of the two
#   folders above is still read.  A mismatch stops the script: the file on
#   this host is not the one you built, and a red team may have edited it.
#   BT_SKIP_VERIFY=1 turns the check off (for development).
cc_verify_self() {
    [ "${BT_SKIP_VERIFY:-0}" = 1 ] && { cc_debug "verify: skipped (BT_SKIP_VERIFY=1)"; return 0; }
    [ -f "$0" ] || { cc_debug "verify: script was not started from a file, nothing to hash"; return 0; }
    _cc_vs_man=${BT_MANIFEST:-}
    [ -z "$_cc_vs_man" ] && [ -r "$0.sha256" ] && _cc_vs_man="$0.sha256"
    if [ -z "$_cc_vs_man" ]; then
        for _cc_vs_d in "$CC_KIT" "$CC_KIT/.." "$CC_KIT/../.."; do
            if [ -r "$_cc_vs_d/MANIFEST.sha256" ]; then _cc_vs_man="$_cc_vs_d/MANIFEST.sha256"; break; fi
        done
    fi
    [ -n "$_cc_vs_man" ] && [ -r "$_cc_vs_man" ] || { cc_debug "verify: no $(basename "$0").sha256 or MANIFEST.sha256 found (unbuilt copy), not checked"; return 0; }
    _cc_vs_name=$(basename "$0")
    _cc_vs_want=$(awk -v n="$_cc_vs_name" '{ f=$2; sub(/.*\//, "", f); if (f == n) { print $1; exit } }' "$_cc_vs_man")
    [ -n "$_cc_vs_want" ] || { cc_warn "verify: $_cc_vs_name is not listed in $_cc_vs_man"; return 0; }
    _cc_vs_got=$(cc_sha256 "$0") || { cc_warn "verify: no SHA-256 tool on this host, cannot check the kit"; return 0; }
    if [ "$_cc_vs_got" != "$_cc_vs_want" ]; then
        cc_die 3 "KIT CHECK FAILED: $0 does not match $_cc_vs_man. This copy was changed after it was built - do not run it. Re-copy the kit from the admin workstation"
    fi
    cc_debug "verify: $_cc_vs_name matches the manifest"
    return 0
}

# cc_finish [EXIT_CODE]
#   Print the one-line summary and exit.  With no argument the exit code is
#   5 when any change failed, otherwise 0.  Refusals are counted and shown but
#   are not a failure: a refusal is the protected list doing its job.
cc_finish() {
    _cc_fin_rc=${1:-}
    if [ -z "$_cc_fin_rc" ]; then
        if [ "$CC_N_FAIL" -gt 0 ]; then _cc_fin_rc=5; else _cc_fin_rc=0; fi
    fi
    cc_info "done: changed=$CC_N_DONE would-change=$CC_N_WOULD failed=$CC_N_FAIL refused=$CC_N_REFUSED findings=$CC_N_FIND exit=$_cc_fin_rc"
    [ -n "$CC_RUN_DIR" ] && cc_info "results: $CC_RUN_DIR"
    [ "$CC_N_WOULD" -gt 0 ] && cc_info "this was a dry run - re-run with --apply to make the $CC_N_WOULD change(s)"
    [ "$CC_N_DONE" -gt 0 ] && cc_info "undo commands for this host are in $CC_UNDO"
    [ -n "$CC_LOG" ] && cc_info "log: $CC_LOG"
    exit "$_cc_fin_rc"
}
# <<< BT-LIB

usage() {
    cat <<'USAGE'
SV-15 Site backup and restore - back up each web site, see what changed, put it back
  sudo sh SV-15-site-backup.sh                  asks
  sudo sh SV-15-site-backup.sh --backup --batch
  sudo sh SV-15-site-backup.sh --check --batch
  sudo sh SV-15-site-backup.sh --restore --protected p.csv --apply

  --backup | --check | --restore   the mode (asked if not given)
  --site NAME        only this site (repeatable)
  --webroot DIR      also treat DIR as a site (repeatable)
  --from DIR         the backup to compare with (default: the newest)
  --db / --no-db     back up the sites' databases (default yes)
  --mysql-cnf FILE   MySQL client file with a user and password
  --exclude PATTERN  leave matching paths out (repeatable, e.g. '*/cache/*')
  --max-mb N         refuse a backup bigger than N MB (default 4096)
  --keep N           keep only the newest N backups
  --copy-to DEST     copy the backup off the box (scp)
  --what all|files|new|none   restore answer for every site
  --restore-db / --no-restore-db   put the database back too (default no)
  --timer SECONDS    revert countdown on restore (default 120); --no-timer
  --no-color         no colours
  --help             show this text

USAGE
    cc_usage_common
}

NL='
'
MODE=""; SITES=""; WEBROOTS=""; FROM=""; DB=""; MYCNF=""; EXCL=""; MAXMB=4096; KEEP=0; COPYTO=""; COPYSET=0
WHAT=""; RDB=""; TIMER=120; NOTIMER=0; COLOR=1
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --backup)     MODE=backup; shift ;;
        --check)      MODE=check; shift ;;
        --restore)    MODE=restore; shift ;;
        --site)       [ $# -ge 2 ] || cc_die 2 "--site needs a name"; SITES="$SITES $2"; shift 2 ;;
        --webroot)    [ $# -ge 2 ] || cc_die 2 "--webroot needs a folder"; [ -d "$2" ] || cc_die 2 "--webroot: not a folder: $2"
                      WEBROOTS="$WEBROOTS$(cc_abspath "$2")$NL"; shift 2 ;;
        --from)       [ $# -ge 2 ] || cc_die 2 "--from needs a folder"; [ -f "$2/.sites" ] || cc_die 2 "--from: not an SV-15 backup: $2"
                      FROM=$(cc_abspath "$2"); shift 2 ;;
        --db)         DB=1; shift ;;
        --no-db)      DB=0; shift ;;
        --mysql-cnf)  [ $# -ge 2 ] || cc_die 2 "--mysql-cnf needs a file"; [ -r "$2" ] || cc_die 2 "--mysql-cnf: cannot read $2"; MYCNF=$(cc_abspath "$2"); shift 2 ;;
        --exclude)    [ $# -ge 2 ] || cc_die 2 "--exclude needs a pattern"; EXCL="$EXCL$2$NL"; shift 2 ;;
        --max-mb)     [ $# -ge 2 ] || cc_die 2 "--max-mb needs a number"; MAXMB=$2; shift 2 ;;
        --keep)       [ $# -ge 2 ] || cc_die 2 "--keep needs a number"; KEEP=$2; shift 2 ;;
        --copy-to)    [ $# -ge 2 ] || cc_die 2 "--copy-to needs a destination"; COPYTO=$2; COPYSET=1; shift 2 ;;
        --what)       [ $# -ge 2 ] || cc_die 2 "--what needs all, files, new or none"; WHAT=$2; shift 2 ;;
        --restore-db) RDB=1; shift ;;
        --no-restore-db) RDB=0; shift ;;
        --timer)      [ $# -ge 2 ] || cc_die 2 "--timer needs seconds"; TIMER=$2; shift 2 ;;
        --no-timer)   NOTIMER=1; shift ;;
        --no-color|--no-colour) COLOR=0; shift ;;
        --help|-h)    usage; exit 0 ;;
        *)            cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
for _n in "$MAXMB" "$KEEP" "$TIMER"; do case "$_n" in ''|*[!0-9]*) cc_die 2 "--max-mb, --keep and --timer need whole numbers" ;; esac; done
case "$WHAT" in ''|all|files|new|none) ;; *) cc_die 2 "--what must be all, files, new or none" ;; esac

cc_init "SV-15" "Site backup and restore" changes
cc_detect_os
# shellcheck disable=SC2034  # read by cc_color_init
[ "$COLOR" = 1 ] || CC_NOCOLOR=1
cc_color_init
IS_ROOT=0; cc_is_root && IS_ROOT=1
header() { cc_show "" ""; cc_show "$C_CYN" "==========[ $1 ]=========="; }

# newest_backup -> the newest site-backup-N folder in --out with a sites list.
newest_backup() {
    for _d in "$CC_OUT"/site-backup-*; do
        [ -f "$_d/.sites" ] || continue
        printf '%s %s\n' "${_d##*-}" "$_d"
    done | sort -n | tail -n 1 | cut -d' ' -f2-
}
[ -n "$FROM" ] || FROM=$(newest_backup)

# ---- What to do ---------------------------------------------------------------
if [ -z "$MODE" ]; then
    _dm=b; [ -n "$FROM" ] && _dm=c
    cc_choose "What do you want to do?$([ -n "$FROM" ] && echo " (last backup: $(basename "$FROM"))")" "$_dm" \
        "b=back up the sites now (do this first, after cleaning them)" \
        "c=check the sites against the last backup (changes nothing)" \
        "r=restore what changed since the last backup"
    case "$CC_CHOICE" in b) MODE=backup ;; c) MODE=check ;; *) MODE=restore ;; esac
fi
if [ "$MODE" != backup ] && [ -z "$FROM" ]; then
    cc_die 3 "no site backup found in $CC_OUT: run with --backup first (or give --from DIR)"
fi
[ "$MODE" = restore ] && [ "$CC_APPLY" = 1 ] && cc_require_root

cc_use_numbered_dir "site-$MODE"
chmod 700 "$CC_RUN_DIR" 2>/dev/null
rmdir "$CC_RUN_DIR/raw" 2>/dev/null
OUTF="$CC_RUN_DIR/output.txt"
grep -v '\[NOTE\]\|\[DEBUG\]' "$CC_LOG" >"$OUTF" 2>/dev/null || : >"$OUTF"
# shellcheck disable=SC2034  # CC_TEE is read by the library's log functions
CC_TEE=$OUTF
W="$CC_RUN_DIR/.work"; mkdir -p "$W"
# Tables are kept as .txt only; their CSV source is scratch data in .work.
CC_CSV_DIR="$W/csv"; mkdir -p "$CC_CSV_DIR"

cc_show "$C_CYN" "SV-15 Site backup and restore | host $CC_HOST | mode $MODE | results in $CC_RUN_DIR"
[ "$MODE" != backup ] && cc_show "$C_CYN" "Comparing with $FROM ($(cat "$FROM/.taken" 2>/dev/null))"
cc_show "" "Legend: ${C_RED}[!] HIGH${C_OFF} new program file (web shell?)   ${C_YEL}[*] MED${C_OFF} changed or deleted   ${C_GRY}[-] LOW${C_OFF} new other file   ${C_GRN}[ok]${C_OFF} same as the backup"
[ "$IS_ROOT" = 1 ] || cc_show "$C_YEL" "[!] Not root: some files and the databases cannot be read. Run with sudo."

# ---- Helpers --------------------------------------------------------------------
safe() { printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '_'; }
# excluded PATH -> true when an --exclude pattern matches PATH.
excluded() {
    [ -n "$EXCL" ] || return 1
    printf '%s\n' "$EXCL" | while IFS= read -r _p; do
        [ -n "$_p" ] || continue
        # shellcheck disable=SC2254  # the pattern is meant to match
        case "$1" in $_p) echo y; break ;; esac
    done | grep -q y
}
# manifest DIR -> "sha256  path" for every regular file under DIR, sorted
#   by path.  Symlinks are listed with a fixed hash "link:TARGET".
manifest() {
    {
        if cc_have sha256sum; then
            find "$1" -xdev -type f -exec sha256sum {} + 2>/dev/null
        else
            find "$1" -xdev -type f 2>/dev/null | while IFS= read -r _f; do printf '%s  %s\n' "$(cc_sha256 "$_f")" "$_f"; done
        fi
        find "$1" -xdev -type l 2>/dev/null | while IFS= read -r _l; do printf 'link:%s  %s\n' "$(readlink "$_l" | tr ' ' '_')" "$_l"; done
    } | if [ -n "$EXCL" ]; then
        while IFS= read -r _m; do excluded "${_m#*  }" || printf '%s\n' "$_m"; done
    else cat; fi | sort -k2
}

# ---- Find the sites ---------------------------------------------------------------
# $W/sites: "name|web root|config file", one per web root.
find_sites() {
    : >"$W/sites.raw"
    for _f in /etc/apache2/sites-enabled/* /etc/apache2/apache2.conf /etc/httpd/conf/httpd.conf /etc/httpd/conf.d/*.conf; do
        [ -f "$_f" ] || continue
        awk -v f="$_f" 'BEGIN { IGNORECASE = 0 }
            { l = $0; sub(/^[ \t]+/, "", l); d = tolower(l); split(l, w, /[ \t]+/) }
            d ~ /^<virtualhost/ { inv = 1; n = ""; r = "" }
            d ~ /^servername[ \t]/ && inv { n = w[2] }
            d ~ /^documentroot[ \t]/ { v = w[2]; gsub(/"/, "", v); if (inv) r = v; else mr = v }
            d ~ /^<\/virtualhost>/ { if (r != "") print (n != "" ? n : "default") "|" r "|" f; inv = 0 }
            END { if (mr != "") print "main|" mr "|" f }' "$_f" >>"$W/sites.raw"
    done
    for _f in /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf /etc/nginx/nginx.conf; do
        [ -f "$_f" ] || continue
        awk -v f="$_f" '
            { l = $0; sub(/#.*/, "", l); t = l; gsub(/^[ \t]+|[ \t;]+$/, "", t); split(t, w, /[ \t]+/) }
            !ins && t ~ /^server[ \t]*\{/ { ins = 1; sd = dep; n = ""; r = "" }
            ins && w[1] == "server_name" && n == "" { n = w[2] }
            ins && w[1] == "root" && dep == sd + 1 { r = w[2] }
            { dep += gsub(/\{/, "{", l); dep -= gsub(/\}/, "}", l) }
            ins && dep <= sd { if (r != "") print ((n != "" && n != "_") ? n : "default") "|" r "|" f; ins = 0 }' "$_f" >>"$W/sites.raw"
    done
    # Folders in /var/www that no config names (apps behind a proxy, or
    # turned off), and the ones given with --webroot.
    for _d in /var/www/* /srv/www/* /usr/share/nginx/html; do
        [ -d "$_d" ] && printf '%s|%s|-\n' "$(basename "$_d")" "$_d" >>"$W/sites.raw"
    done
    printf '%s' "$WEBROOTS" | while IFS= read -r _d; do [ -n "$_d" ] && printf '%s|%s|--webroot\n' "$(basename "$_d")" "$_d"; done >>"$W/sites.raw"
    # One entry per folder (the first name wins); nothing that is not a
    # folder, is /, or sits inside another site.
    awk -F'|' '{ sub(/\/+$/, "", $2) } $2 != "" && !seen[$2]++ { print }' OFS='|' "$W/sites.raw" >"$W/sites.u"
    : >"$W/sites.ok"
    while IFS='|' read -r _n _r _c; do
        [ -d "$_r" ] && [ "$_r" != / ] && printf '%s|%s|%s\n' "$_n" "$_r" "$_c" >>"$W/sites.ok"
    done <"$W/sites.u"
    sort -t'|' -k2,2 "$W/sites.ok" | awk -F'|' '{ for (k in keep) if (index($2, k "/") == 1) next; keep[$2] = 1; print }' >"$W/sites.n"
    # Unique, file-safe names.
    awk -F'|' -v OFS='|' '{ n = $1; gsub(/[^A-Za-z0-9._-]/, "_", n); if (used[n]++) n = n "-" used[n]; $1 = n; print }' "$W/sites.n" >"$W/sites"
    if [ -n "$SITES" ]; then
        awk -F'|' -v want=" $SITES " 'index(want, " " $1 " ")' "$W/sites" >"$W/sites.f"; mv "$W/sites.f" "$W/sites"
    fi
}

# ---- Each site's database, from its app config ------------------------------------
# app_db ROOT -> "app|engine|database|host" (empty when no database found).
app_db() {
    _r=$1; _app=""; _eng=mysql; _dbn=""; _dbh=localhost
    # sq: a single-quote character for the sed patterns.
    _q="['\"]"
    if [ -f "$_r/wp-config.php" ]; then
        _app=WordPress
        _dbn=$(sed -n "s/.*define( *${_q}DB_NAME${_q} *, *${_q}\([^'\"]*\)${_q}.*/\1/p" "$_r/wp-config.php" | head -n 1)
        _dbh=$(sed -n "s/.*define( *${_q}DB_HOST${_q} *, *${_q}\([^'\"]*\)${_q}.*/\1/p" "$_r/wp-config.php" | head -n 1)
    elif [ -f "$_r/configuration.php" ] && grep -q 'JConfig' "$_r/configuration.php" 2>/dev/null; then
        _app=Joomla
        _dbn=$(sed -n "s/.*public \$db *= *${_q}\([^'\"]*\)${_q}.*/\1/p" "$_r/configuration.php" | head -n 1)
        _dbh=$(sed -n "s/.*public \$host *= *${_q}\([^'\"]*\)${_q}.*/\1/p" "$_r/configuration.php" | head -n 1)
        grep -q "dbtype *= *${_q}p\?g\?sql" "$_r/configuration.php" && grep -qi "pgsql" "$_r/configuration.php" && _eng=postgres
    elif [ -f "$_r/sites/default/settings.php" ]; then
        _app=Drupal
        _dbn=$(sed -n "s/.*${_q}database${_q} *=> *${_q}\([^'\"]*\)${_q}.*/\1/p" "$_r/sites/default/settings.php" | head -n 1)
        _dbh=$(sed -n "s/.*${_q}host${_q} *=> *${_q}\([^'\"]*\)${_q}.*/\1/p" "$_r/sites/default/settings.php" | head -n 1)
        grep -q "${_q}driver${_q} *=> *${_q}pgsql" "$_r/sites/default/settings.php" && _eng=postgres
    elif [ -f "$_r/app/config/parameters.php" ]; then
        _app=PrestaShop
        _dbn=$(sed -n "s/.*${_q}database_name${_q} *=> *${_q}\([^'\"]*\)${_q}.*/\1/p" "$_r/app/config/parameters.php" | head -n 1)
        _dbh=$(sed -n "s/.*${_q}database_host${_q} *=> *${_q}\([^'\"]*\)${_q}.*/\1/p" "$_r/app/config/parameters.php" | head -n 1)
    elif [ -f "$_r/config/settings.inc.php" ]; then
        _app=PrestaShop
        _dbn=$(sed -n "s/.*define( *${_q}_DB_NAME_${_q} *, *${_q}\([^'\"]*\)${_q}.*/\1/p" "$_r/config/settings.inc.php" | head -n 1)
        _dbh=$(sed -n "s/.*define( *${_q}_DB_SERVER_${_q} *, *${_q}\([^'\"]*\)${_q}.*/\1/p" "$_r/config/settings.inc.php" | head -n 1)
    elif [ -f "$_r/config.php" ] && grep -q 'DB_DATABASE' "$_r/config.php" 2>/dev/null; then
        _app=OpenCart
        _dbn=$(sed -n "s/.*define( *${_q}DB_DATABASE${_q} *, *${_q}\([^'\"]*\)${_q}.*/\1/p" "$_r/config.php" | head -n 1)
        _dbh=$(sed -n "s/.*define( *${_q}DB_HOSTNAME${_q} *, *${_q}\([^'\"]*\)${_q}.*/\1/p" "$_r/config.php" | head -n 1)
    elif [ -f "$_r/app/etc/env.php" ]; then
        _app=Magento
        _dbn=$(sed -n "s/.*${_q}dbname${_q} *=> *${_q}\([^'\"]*\)${_q}.*/\1/p" "$_r/app/etc/env.php" | head -n 1)
        _dbh=$(sed -n "s/.*${_q}host${_q} *=> *${_q}\([^'\"]*\)${_q}.*/\1/p" "$_r/app/etc/env.php" | head -n 1)
    elif [ -f "$_r/program/include/iniset.php" ]; then
        _app=Roundcube
        for _c in "$_r/config/config.inc.php" /etc/roundcube/config.inc.php; do
            [ -f "$_c" ] || continue
            _dsn=$(sed -n "s/.*db_dsnw.\] *= *${_q}\([^'\"]*\)${_q}.*/\1/p" "$_c" | head -n 1)
            [ -n "$_dsn" ] && break
        done
        if [ -f /etc/roundcube/debian-db.php ] && { [ -z "$_dsn" ] || printf '%s' "$_dsn" | grep -q '\$'; }; then
            _dbn=$(sed -n "s/^\$dbname *= *${_q}\([^'\"]*\)${_q}.*/\1/p" /etc/roundcube/debian-db.php)
            _dbh=$(sed -n "s/^\$dbserver *= *${_q}\([^'\"]*\)${_q}.*/\1/p" /etc/roundcube/debian-db.php)
            grep -q "dbtype *= *${_q}pgsql" /etc/roundcube/debian-db.php && _eng=postgres
            grep -q "dbtype *= *${_q}sqlite" /etc/roundcube/debian-db.php && _eng=sqlite
        elif [ -n "$_dsn" ]; then
            case "$_dsn" in pgsql:*) _eng=postgres ;; sqlite:*) _eng=sqlite ;; esac
            _dbn=${_dsn##*/}; _dbn=${_dbn%%\?*}
            _dbh=$(printf '%s' "$_dsn" | sed -n 's|.*@\([^/:]*\).*|\1|p')
        fi
    elif [ -f "$_r/.env" ] && grep -q '^DB_DATABASE=' "$_r/.env" 2>/dev/null; then
        _app="app (.env)"
        _dbn=$(sed -n 's/^DB_DATABASE=["]*\([^"]*\)["]*.*/\1/p' "$_r/.env" | head -n 1)
        _dbh=$(sed -n 's/^DB_HOST=["]*\([^"]*\)["]*.*/\1/p' "$_r/.env" | head -n 1)
        grep -q '^DB_CONNECTION=pgsql' "$_r/.env" && _eng=postgres
    fi
    [ -n "$_app" ] || return 0
    _dbh=${_dbh%%:*}; [ -n "$_dbh" ] || _dbh=localhost
    printf '%s|%s|%s|%s\n' "$_app" "$_eng" "$_dbn" "$_dbh"
}
local_host() { case "$1" in localhost|127.*|::1|"$CC_HOST"|'') return 0 ;; esac; return 1; }

# ---- Database login (same order as SV-14) ----------------------------------------
MYOPT=""; MYC=$(cc_first mariadb mysql); MYD=$(cc_first mariadb-dump mysqldump)
mysql_login() {
    [ -n "$MYOPT" ] && return 0
    [ -n "$MYC" ] && [ -n "$MYD" ] || return 1
    for _try in "${MYCNF:+--defaults-extra-file=$MYCNF}" --user=root \
                "$( [ -r /etc/mysql/debian.cnf ] && echo --defaults-file=/etc/mysql/debian.cnf )"; do
        [ -n "$_try" ] || continue
        "$MYC" "$_try" --connect-timeout=5 -N -B -e 'SELECT 1' >/dev/null 2>&1 && { MYOPT=$_try; cc_debug "mysql login: $_try"; return 0; }
    done
    return 1
}
pgrun() {
    if cc_have runuser; then runuser -u postgres -- sh -c "cd / && $*"
    else su postgres -s /bin/sh -c "cd / && $*"; fi
}
# dump_db ENGINE DB FILE -> 0 when a complete dump was written.
dump_db() {
    case "$1" in
        mysql)
            mysql_login || return 2
            { "$MYD" "$MYOPT" --single-transaction --routines --triggers --events --hex-blob --databases "$2" 2>>"$CC_LOG"; echo $? >"$W/rc"; } | gzip -c >"$3"
            [ "$(cat "$W/rc")" = 0 ] && gzip -dc "$3" | tail -n 1 | grep -q 'Dump completed' ;;
        postgres)
            [ "$IS_ROOT" = 1 ] && cc_have pg_dump || return 2
            case "$2" in *[!A-Za-z0-9_-]*) return 2 ;; esac
            pgrun "pg_dump -Fc -d '$2'" >"$3" 2>>"$CC_LOG" && pg_restore -l "$3" >/dev/null 2>&1 ;;
        *) return 2 ;;
    esac
}
# load_db ENGINE DB FILE -> put a dump back (replaces the database's tables).
load_db() {
    case "$1" in
        mysql) gzip -dc "$3" | "$MYC" "$MYOPT" ;;
        postgres) pgrun "pg_restore --clean --if-exists -d '$2'" <"$3" ;;
    esac
}

# ---- Show the sites ----------------------------------------------------------------
header "1/3  sites"
find_sites
if [ "$MODE" != backup ]; then
    # Compare the sites that are in the backup (they may since have vanished).
    cp "$FROM/.sites" "$W/sites"
    if [ -n "$SITES" ]; then awk -F'|' -v want=" $SITES " 'index(want, " " $1 " ")' "$W/sites" >"$W/sites.f"; mv "$W/sites.f" "$W/sites"; fi
fi
if [ ! -s "$W/sites" ]; then
    cc_show "$C_YEL" "  [!] no web sites found$([ -n "$SITES" ] && echo " named:$SITES"). Give the folder with --webroot DIR."
    cc_finish; exit 0
fi
: >"$W/sitedb"
while IFS='|' read -r _n _r _c; do
    _db=$(app_db "$_r")
    printf '%s|%s\n' "$_n" "$_db" >>"$W/sitedb"
    cc_show "" "  $(printf '%-22s %-34s' "$_n" "$_r") ${_db:+$(printf '%s' "$_db" | awk -F'|' '{ printf "%s, %s database %s%s", $1, $2, ($3 == "" ? "?" : $3), ($4 ~ /^(localhost|127\.)/ ? "" : " on " $4) }')}"
done <"$W/sites"

# =============================================================================
# BACKUP
# =============================================================================
if [ "$MODE" = backup ]; then
    header "2/3  questions"
    if [ -z "$SITES" ] && [ "$(grep -c . "$W/sites")" -gt 1 ]; then
        cc_ask_text "Which sites?" all "site names separated by spaces (as listed above), or all"
        if [ "$CC_ANSWER" != all ]; then
            awk -F'|' -v want=" $CC_ANSWER " 'index(want, " " $1 " ")' "$W/sites" >"$W/sites.f"; mv "$W/sites.f" "$W/sites"
            [ -s "$W/sites" ] || cc_die 2 "none of those names is a site: $CC_ANSWER"
        fi
    fi
    if [ -z "$DB" ]; then
        if grep -q '|.*|.*|' "$W/sitedb"; then
            if cc_ask "Back up each site's database too?" Y "yes, dump it (read-only)" "no, files only"; then DB=1; else DB=0; fi
        else DB=0; fi
    fi
    if [ "$COPYSET" = 0 ]; then
        cc_ask_text "Copy the backup off the box?" "" "an scp destination like admin@10.0.0.5:/backups/, or Enter for no copy"
        COPYTO=$CC_ANSWER
    fi

    header "3/3  backing up"
    _need=0
    while IFS='|' read -r _n _r _c; do _need=$((_need + $(du -sk "$_r" 2>/dev/null | awk '{ print $1 }'))); done <"$W/sites"
    _need=$((_need / 1024))
    [ "$_need" -le "$MAXMB" ] || cc_die 3 "the sites add up to about $_need MB, more than --max-mb $MAXMB (use --exclude for caches and media, or raise --max-mb)"
    _free=$(df -Pk "$CC_RUN_DIR" 2>/dev/null | awk 'NR == 2 { print int($4 / 1024) }')
    [ -z "$_free" ] || [ "$_free" -gt "$_need" ] || cc_die 3 "not enough free space in $CC_OUT: need about $_need MB, have $_free MB"
    SCSV=$(cc_csv_new sites "site,web_root,config,files,size_kb,app,database,db_status")
    _nok=0; _nbad=0
    while IFS='|' read -r _n _r _c; do
        _sd="$CC_RUN_DIR/$_n"; mkdir -p "$_sd"
        manifest "$_r" >"$_sd/files.sha256"
        _nf=$(grep -c . "$_sd/files.sha256")
        # tar wants paths relative to /, one per line.
        sed 's/^[^ ]*  \///' "$_sd/files.sha256" >"$W/list"
        if (cd / && tar -czf "$_sd/files.tar.gz" -T "$W/list") 2>>"$CC_LOG" && gzip -t "$_sd/files.tar.gz" 2>/dev/null; then _fst=ok
        else _fst=FAILED; _nbad=$((_nbad + 1)); fi
        _kb=$(du -k "$_sd/files.tar.gz" 2>/dev/null | awk '{ print $1 }')
        _line=$(awk -F'|' -v n="$_n" '$1 == n { print $2 "|" $3 "|" $4 "|" $5; exit }' "$W/sitedb")
        _app=$(printf '%s' "$_line" | cut -d'|' -f1); _eng=$(printf '%s' "$_line" | cut -d'|' -f2)
        _dbn=$(printf '%s' "$_line" | cut -d'|' -f3); _dbh=$(printf '%s' "$_line" | cut -d'|' -f4)
        _dst="-"
        if [ "$DB" = 1 ] && [ -n "$_dbn" ]; then
            if ! local_host "$_dbh"; then _dst="on another host ($_dbh): back it up there"
            elif [ "$_eng" = sqlite ]; then _dst="sqlite: in the file archive"
            else
                _df="$_sd/db.sql.gz"; [ "$_eng" = postgres ] && _df="$_sd/db.dump"
                if dump_db "$_eng" "$_dbn" "$_df"; then _dst=ok; chmod 600 "$_df"
                else _rc=$?; rm -f "$_df"; _dst=$([ "$_rc" = 2 ] && echo "could not log in (give --mysql-cnf, run as root)" || echo FAILED); _nbad=$((_nbad + 1)); fi
            fi
        fi
        printf '%s|%s|%s|%s|%s\n' "$_n" "$_r" "$_app" "$_eng" "$_dbn" >"$_sd/info"
        cc_csv_row "$SCSV" "$_n" "$_r" "$_c" "$_nf" "$_kb" "${_app:--}" "${_dbn:--}" "$_dst"
        if [ "$_fst" = ok ]; then
            cc_show "$C_GRN" "  [+] $(printf '%-22s' "$_n") $_nf files ($((_kb / 1024)) MB)$([ "$_dst" = ok ] && echo ", database $_dbn")"
            _nok=$((_nok + 1))
        else cc_show "$C_RED" "  [x] $_n: the file archive failed (see $CC_LOG)"; fi
        case "$_dst" in ok|-|sqlite*) ;; *) cc_show "$C_YEL" "      database $_dbn: $_dst" ;; esac
    done <"$W/sites"
    # Web server and PHP configs, once for the box.
    : >"$W/clist"
    for _d in /etc/apache2 /etc/httpd /etc/nginx /etc/php /etc/php.ini /etc/php.d /etc/php-fpm.d; do [ -e "$_d" ] && printf '%s\n' "$_d" >>"$W/clist"; done
    if [ -s "$W/clist" ]; then
        while IFS= read -r _d; do manifest "$_d"; done <"$W/clist" >"$CC_RUN_DIR/config.sha256"
        sed 's/^[^ ]*  \///' "$CC_RUN_DIR/config.sha256" >"$W/list"
        (cd / && tar -czf "$CC_RUN_DIR/config.tar.gz" -T "$W/list") 2>>"$CC_LOG" &&
            cc_show "$C_GRN" "  [+] web server and PHP configs ($(grep -c . "$CC_RUN_DIR/config.sha256") files)"
    fi
    date -u +%Y-%m-%dT%H:%M:%SZ >"$CC_RUN_DIR/.taken"
    # The site list check and restore read back (name|folder|config).
    cp "$W/sites" "$CC_RUN_DIR/.sites"
    cat >"$CC_RUN_DIR/RESTORE.txt" <<EOF
Restoring from $CC_RUN_DIR (made on $CC_HOST at $(cat "$CC_RUN_DIR/.taken") by SV-15)

The easy way:  sh SV-15-site-backup.sh --check      what changed
               sh SV-15-site-backup.sh --restore --protected p.csv --apply

By hand (paths in the archives are relative to /):
  One file:        tar -xzpf SITE/files.tar.gz -C / var/www/html/index.php
  Look first:      mkdir /tmp/r && tar -xzpf SITE/files.tar.gz -C /tmp/r && diff -r /tmp/r/var/www/html /var/www/html
  What changed:    (cd / && sed 's|  /|  |' $CC_RUN_DIR/SITE/files.sha256 | sha256sum -c 2>/dev/null | grep -v ': OK\$')
  MySQL database:  gzip -dc SITE/db.sql.gz | mysql          (REPLACES its tables)
  PostgreSQL:      sudo -u postgres pg_restore --clean --if-exists -d DB < SITE/db.dump
  A web server config file:  tar -xzpf config.tar.gz -C / etc/apache2/sites-enabled/000-default.conf
                   then test (apache2ctl -t / nginx -t) BEFORE restarting it.
The archives hold the sites' database dumps and config passwords: keep this folder private.
EOF
    _copied=""
    if [ -n "$COPYTO" ] && [ "$_nok" -gt 0 ]; then
        if cc_have scp && scp -q -r -o ConnectTimeout=15 "$CC_RUN_DIR" "$COPYTO" 2>>"$CC_LOG"; then _copied=yes
        else _copied=no; cc_show "$C_RED" "  [x] copy to $COPYTO FAILED: the backup is only on this box"; fi
    fi
    if [ "$KEEP" -gt 0 ]; then
        for _d in "$CC_OUT"/site-backup-*; do [ -d "$_d" ] && printf '%s %s\n' "${_d##*-}" "$_d"; done | sort -n |
            awk -v k="$KEEP" '{ a[NR] = $2 } END { for (i = 1; i <= NR - k; i++) print a[i] }' >"$W/old"
        while IFS= read -r _d; do [ "$_d" != "$CC_RUN_DIR" ] && rm -rf "$_d" && cc_show "$C_GRY" "  [-] removed old backup $(basename "$_d") (--keep $KEEP)"; done <"$W/old"
    fi
    cc_csv_pretty "$SCSV" "$CC_RUN_DIR/sites.txt" 100
    {
        printf '==========[ summary ]==========\n'
        printf 'Backed up %s site(s) on %s at %s%s\n' "$_nok" "$CC_HOST" "$(cat "$CC_RUN_DIR/.taken")" "$([ "$_nbad" -gt 0 ] && echo "; $_nbad problem(s): see sites.txt")"
        case "$_copied" in yes) printf 'Copied off the box to %s\n' "$COPYTO" ;; no) printf 'COPY FAILED to %s\n' "$COPYTO" ;;
            *) printf 'Not copied off the box. From your workstation: scp -r root@%s:%s .\n' "$CC_HOST" "$CC_RUN_DIR" ;; esac
        printf '\nNext:  --check any time to see what changed;  --restore to put it back.\n'
        printf 'The backup holds database dumps and config passwords: keep %s private.\n' "$CC_RUN_DIR"
    } >"$CC_RUN_DIR/summary.txt"
    cc_show "" ""
    while IFS= read -r _l; do case "$_l" in ==*) cc_show "$C_CYN" "$_l" ;; Backed*) cc_show "$C_GRN" "$_l" ;; COPY*) cc_show "$C_RED" "$_l" ;; *) cc_show "" "$_l" ;; esac; done <"$CC_RUN_DIR/summary.txt"
    rm -rf "$W"
    cc_finish
    exit 0
fi

# =============================================================================
# CHECK and RESTORE: compare each site with the backup
# =============================================================================
# compare SITE ROOT -> $W/diff.SITE: "change|path" for changed, deleted and
#   new files; prints the three counts.
CODE_RE='\.(php[0-9]?|phtml|phar|inc|jsp|jspx|asp|aspx|ashx|cgi|pl|py|sh|so)$'
compare() {
    manifest "$2" >"$W/now.$1"
    awk 'FILENAME == ARGV[1] { h = substr($0, 1, index($0, "  ") - 1); p = substr($0, index($0, "  ") + 2); old[p] = h; next }
         { h = substr($0, 1, index($0, "  ") - 1); p = substr($0, index($0, "  ") + 2); seen[p] = 1
           if (!(p in old)) print "new|" p; else if (old[p] != h) print "changed|" p }
         END { for (p in old) if (!(p in seen)) print "deleted|" p }' "$FROM/$1/files.sha256" "$W/now.$1" | sort -t'|' -k2 >"$W/diff.$1"
    printf '%s %s %s\n' "$(grep -c '^changed|' "$W/diff.$1")" "$(grep -c '^deleted|' "$W/diff.$1")" "$(grep -c '^new|' "$W/diff.$1")"
}
# why CHANGE PATH -> severity and a few words on what the change may mean.
why() {
    case "$1" in
        new) if printf '%s' "$2" | grep -Eqi "$CODE_RE"; then echo "HIGH|new program file: a web shell or planted code?"
             else echo "LOW|new file (an upload, or planted content)"; fi ;;
        changed) case "$2" in
                     */index.*|*.html|*.htm) echo "MED|page changed: defaced?" ;;
                     *.php|*.js|*.jsp|*.asp*|*.py|*.inc) echo "MED|code changed: a backdoor added to it?" ;;
                     *.htaccess) echo "HIGH|.htaccess changed: can make any file run as PHP or redirect visitors" ;;
                     *config*|*.env|*settings*) echo "MED|config changed: database login or settings?" ;;
                     *) echo "MED|changed" ;;
                 esac ;;
        deleted) echo "MED|deleted (vandalism, or removed by the team)" ;;
    esac
}

header "2/3  what changed since $(cat "$FROM/.taken" 2>/dev/null || basename "$FROM")"
CCSV=$(cc_csv_new changes "site,change,file,severity,why")
: >"$W/plan"
NSITES_CH=0
while IFS='|' read -r _n _r _c; do
    if [ ! -f "$FROM/$_n/files.sha256" ]; then cc_show "$C_YEL" "  [!] $_n: not in that backup"; continue; fi
    if [ ! -d "$_r" ]; then
        cc_show "$C_RED" "  [!] $_n: the whole folder $_r is GONE (a restore puts it back)"
    fi
    # shellcheck disable=SC2046  # three numbers, split on purpose
    set -- $(compare "$_n" "$_r")
    _ch=$1; _de=$2; _nw=$3
    if [ $((_ch + _de + _nw)) -eq 0 ]; then
        cc_show "$C_GRN" "  [ok] $(printf '%-22s' "$_n") files same as the backup"
        # The database can still have been changed: offered on restore.
        { [ -f "$FROM/$_n/db.sql.gz" ] || [ -f "$FROM/$_n/db.dump" ]; } && printf '%s|%s|0|0|0\n' "$_n" "$_r" >>"$W/plan"
        continue
    fi
    NSITES_CH=$((NSITES_CH + 1))
    _hc=$C_YEL; awk -F'|' '$1 == "new"' "$W/diff.$_n" | cut -d'|' -f2- | grep -Eqi "$CODE_RE" && _hc=$C_RED
    cc_show "$_hc" "  [!] $(printf '%-22s' "$_n") $_ch changed, $_de deleted, $_nw new"
    _i=0
    while IFS='|' read -r _k _p; do
        _w=$(why "$_k" "$_p"); _sev=${_w%%"|"*}; _txt=${_w#*"|"}
        cc_csv_row "$CCSV" "$_n" "$_k" "$_p" "$_sev" "$_txt"
        _i=$((_i + 1))
        if [ "$_i" -le 25 ]; then
            case "$_sev" in HIGH) _cc=$C_RED; _m='[!]' ;; MED) _cc=$C_YEL; _m='[*]' ;; *) _cc=$C_GRY; _m='[-]' ;; esac
            cc_show "$_cc" "      $_m $(printf '%-8s' "$_k") $_p  - $_txt"
        fi
    done <"$W/diff.$_n"
    [ "$_i" -gt 25 ] && cc_show "$C_GRY" "      ... $((_i - 25)) more in changes.txt"
    printf '%s|%s|%s|%s|%s\n' "$_n" "$_r" "$_ch" "$_de" "$_nw" >>"$W/plan"
done <"$W/sites"
# Web server and PHP config files.
if [ -f "$FROM/config.sha256" ]; then
    : >"$W/cnow"
    awk '{ p = substr($0, index($0, "  ") + 2); print p }' "$FROM/config.sha256" | awk -F/ '{ print "/" $2 "/" $3 }' | sort -u | while IFS= read -r _d; do [ -e "$_d" ] && manifest "$_d"; done >"$W/cnow"
    awk 'FILENAME == ARGV[1] { h = substr($0, 1, index($0, "  ") - 1); p = substr($0, index($0, "  ") + 2); old[p] = h; next }
         { h = substr($0, 1, index($0, "  ") - 1); p = substr($0, index($0, "  ") + 2); seen[p] = 1; if (!(p in old)) print "new|" p; else if (old[p] != h) print "changed|" p }
         END { for (p in old) if (!(p in seen)) print "deleted|" p }' "$FROM/config.sha256" "$W/cnow" | sort -t'|' -k2 >"$W/cdiff"
    if [ -s "$W/cdiff" ]; then
        cc_show "$C_YEL" "  [*] web server / PHP config: $(grep -c . "$W/cdiff") file(s) differ (put back by hand: see RESTORE.txt in the backup)"
        while IFS='|' read -r _k _p; do
            cc_show "$C_YEL" "      [*] $(printf '%-8s' "$_k") $_p"
            cc_csv_row "$CCSV" "(config)" "$_k" "$_p" MED "web server or PHP config: compare, then restore by hand and test before restarting"
        done <"$W/cdiff"
    else
        cc_show "$C_GRN" "  [ok] web server and PHP configs same as the backup"
    fi
fi
cc_csv_pretty "$CCSV" "$CC_RUN_DIR/changes.txt" 120

if [ "$MODE" = check ]; then
    {
        printf '==========[ summary ]==========\n'
        if [ "$NSITES_CH" = 0 ]; then printf 'Every site matches the backup from %s.\n' "$(cat "$FROM/.taken" 2>/dev/null)"
        else
            printf '%s site(s) changed since the backup from %s:\n' "$NSITES_CH" "$(cat "$FROM/.taken" 2>/dev/null)"
            awk -F'|' '$3 + $4 + $5 > 0 { printf "  %-22s %s changed, %s deleted, %s new\n", $1, $3, $4, $5 }' "$W/plan"
            printf '\nEvery file: %s/changes.txt\n' "$CC_RUN_DIR"
            printf 'Put it back:  --restore (asks per site; dry run unless --apply)\n'
        fi
    } >"$CC_RUN_DIR/summary.txt"
    cc_show "" ""
    while IFS= read -r _l; do case "$_l" in ==*) cc_show "$C_CYN" "$_l" ;; Every\ site*) cc_show "$C_GRN" "$_l" ;; *changed\ since*) cc_show "$C_YEL" "$_l" ;; *) cc_show "" "$_l" ;; esac; done <"$CC_RUN_DIR/summary.txt"
    rm -rf "$W"
    cc_finish
    exit 0
fi

# =============================================================================
# RESTORE
# =============================================================================
header "3/3  restore"
if [ ! -s "$W/plan" ]; then
    cc_show "$C_GRN" "  [ok] Nothing to put back: every site matches the backup."
    rm -rf "$W"; cc_finish; exit 0
fi
# Questions, per site.
: >"$W/do"
while IFS='|' read -r _n _r _ch _de _nw; do
    _a=$WHAT
    if [ $((_ch + _de + _nw)) -eq 0 ]; then _a=dbonly
    elif [ -z "$_a" ]; then
        _d=a
        cc_choose "$_n: $_ch changed, $_de deleted, $_nw new. What should I do?" "$_d" \
            "a=all back to the backup: restore changed and deleted files, new files to quarantine" \
            "f=files only: restore changed and deleted files, leave new files" \
            "q=quarantine the new files only" \
            "n=nothing for this site"
        case "$CC_CHOICE" in a) _a=all ;; f) _a=files ;; q) _a=new ;; *) _a=none ;; esac
    fi
    _rdb=0
    _eng=$(cut -d'|' -f4 "$FROM/$_n/info" 2>/dev/null); _dbn=$(cut -d'|' -f5 "$FROM/$_n/info" 2>/dev/null)
    _dbf=""; [ -f "$FROM/$_n/db.sql.gz" ] && _dbf="$FROM/$_n/db.sql.gz"; [ -f "$FROM/$_n/db.dump" ] && _dbf="$FROM/$_n/db.dump"
    if [ -n "$_dbf" ] && [ "$_a" != none ]; then
        if [ -n "$RDB" ]; then _rdb=$RDB
        elif cc_ask "$_n: $([ "$_a" = dbonly ] && echo "files unchanged. Put" || echo "also put") the database $_dbn back as it was at the backup?" N "yes, replace it (the current one is saved first; changes since the backup are lost)" "no, leave the database"; then _rdb=1; fi
    fi
    printf '%s|%s|%s|%s|%s|%s\n' "$_n" "$_r" "$_a" "$_rdb" "$_eng|$_dbn" "$_dbf" >>"$W/do"
done <"$W/plan"

# The plan.
PCSV=$(cc_csv_new plan "site,action,file")
NCH=0
while IFS='|' read -r _n _r _a _rdb _eng _dbn _dbf; do
    : >"$W/rest.$_n"; : >"$W/quar.$_n"
    case "$_a" in all|files) awk -F'|' '$1 == "changed" || $1 == "deleted" { print $2 }' "$W/diff.$_n" >"$W/rest.$_n" ;; esac
    case "$_a" in all|new) awk -F'|' '$1 == "new" { print $2 }' "$W/diff.$_n" >"$W/quar.$_n" ;; esac
    _nr=$(grep -c . "$W/rest.$_n"); _nq=$(grep -c . "$W/quar.$_n")
    NCH=$((NCH + _nr + _nq + _rdb))
    while IFS= read -r _p; do cc_csv_row "$PCSV" "$_n" "put back from the backup" "$_p"; done <"$W/rest.$_n"
    while IFS= read -r _p; do cc_csv_row "$PCSV" "$_n" "move to quarantine" "$_p"; done <"$W/quar.$_n"
    [ "$_rdb" = 1 ] && cc_csv_row "$PCSV" "$_n" "put the database back" "$_dbn ($_eng)"
    if [ "$_a" = dbonly ]; then [ "$_rdb" = 1 ] && cc_show "$C_YEL" "  [~] $(printf '%-22s' "$_n") put the database $_dbn back"
    elif [ "$_a" != none ]; then cc_show "$C_YEL" "  [~] $(printf '%-22s' "$_n") put back $_nr file(s), quarantine $_nq new file(s)$([ "$_rdb" = 1 ] && echo ", put the database $_dbn back")"; fi
done <"$W/do"
cc_csv_pretty "$PCSV" "$CC_RUN_DIR/plan.txt" 120
APPLIED=0; TIMER_ON=0
if [ "$NCH" -eq 0 ]; then
    cc_show "$C_GRN" "  [ok] Nothing chosen."
elif [ "$CC_APPLY" != 1 ]; then
    cc_show "$C_GRY" "  Dry run: nothing was changed. The plan is in $CC_RUN_DIR/plan.txt. Run again with --apply to do it."
elif ! cc_ask "Do these $NCH change(s) now?" Y "yes, put them back (a revert timer undoes it unless you confirm from a NEW session)" "no, change nothing"; then
    cc_show "$C_GRY" "  Not done. The plan is in $CC_RUN_DIR/plan.txt"
else
    APPLIED=1
    if [ "$NOTIMER" != 1 ]; then
        cc_timer_start "$TIMER"; TIMER_ON=1
        cc_show "$C_YEL" "  [*] Revert timer started: everything is undone in $((TIMER / 60)):$(printf '%02d' $((TIMER % 60))) unless you keep it at the end."
    fi
    RCSV=$(cc_csv_new changes "site,action,file,result")
    mkdir -p "$CC_RUN_DIR/before"
    _q=$CC_QUIET; CC_QUIET=1
    while IFS='|' read -r _n _r _a _rdb _eng _dbn _dbf; do
        [ "$_a" = none ] && continue
        [ "$_a" = dbonly ] && [ "$_rdb" != 1 ] && continue
        _ok=0; _bad=0
        # Files: save the current version, then extract the backup's copies.
        if [ -s "$W/rest.$_n" ]; then
            while IFS= read -r _p; do
                if [ -e "$_p" ]; then cc_backup_file "$_p" >/dev/null || true
                else cc_undo_add "remove $_p (put back by SV-15; it was deleted before)" "rm -f $(cc_shquote "$_p")"; fi
            done <"$W/rest.$_n"
            sed 's|^/||' "$W/rest.$_n" >"$W/rel.$_n"
            if cc_run "put back $(grep -c . "$W/rel.$_n") file(s) of $_n" sh -c 'cd / && tar -xzpf "$1" -T "$2"' sh "$FROM/$_n/files.tar.gz" "$W/rel.$_n"; then
                _ok=$((_ok + $(grep -c . "$W/rel.$_n")))
                while IFS= read -r _p; do cc_csv_row "$RCSV" "$_n" "put back" "$_p" ok; done <"$W/rest.$_n"
            else
                _bad=$((_bad + 1)); cc_show "$C_RED" "  [x] $_n: extracting from the backup failed (see $CC_LOG)"
            fi
        fi
        # New files: to quarantine (they can be moved back).
        while IFS= read -r _p; do
            if cc_quarantine "$_p"; then _ok=$((_ok + 1)); cc_csv_row "$RCSV" "$_n" "quarantined" "$_p" ok
            else _bad=$((_bad + 1)); cc_csv_row "$RCSV" "$_n" "quarantined" "$_p" "refused or failed"; fi
        done <"$W/quar.$_n"
        # Database: save the current one, then load the backup.
        if [ "$_rdb" = 1 ]; then
            _pre="$CC_RUN_DIR/before/$_n.db"
            if [ "$_eng" = mysql ] && mysql_login; then
                if dump_db mysql "$_dbn" "$_pre.sql.gz"; then
                    cc_undo_add "put database $_dbn back as it was before the restore" "gzip -dc $(cc_shquote "$_pre.sql.gz") | $MYC $(cc_shquote "$MYOPT")"
                    if load_db mysql "$_dbn" "$_dbf" 2>>"$CC_LOG"; then _ok=$((_ok + 1)); cc_csv_row "$RCSV" "$_n" "database put back" "$_dbn" ok
                    else _bad=$((_bad + 1)); cc_show "$C_RED" "  [x] $_n: loading the database failed (see $CC_LOG)"; fi
                else _bad=$((_bad + 1)); cc_show "$C_RED" "  [x] $_n: could not save the current database first, so it was NOT replaced"; fi
            elif [ "$_eng" = postgres ]; then
                if dump_db postgres "$_dbn" "$_pre.dump"; then
                    cc_undo_add "put database $_dbn back as it was before the restore" "runuser -u postgres -- pg_restore --clean --if-exists -d $(cc_shquote "$_dbn") < $(cc_shquote "$_pre.dump")"
                    if load_db postgres "$_dbn" "$_dbf" 2>>"$CC_LOG"; then _ok=$((_ok + 1)); cc_csv_row "$RCSV" "$_n" "database put back" "$_dbn" ok
                    else _bad=$((_bad + 1)); cc_show "$C_RED" "  [x] $_n: loading the database failed (see $CC_LOG)"; fi
                else _bad=$((_bad + 1)); cc_show "$C_RED" "  [x] $_n: could not save the current database first, so it was NOT replaced"; fi
            else _bad=$((_bad + 1)); cc_show "$C_RED" "  [x] $_n: cannot log in to the database (give --mysql-cnf)"; fi
        fi
        # Check: the site should now match the backup for what was chosen.
        # shellcheck disable=SC2046  # three numbers, split on purpose
        set -- $(compare "$_n" "$_r")
        _left=""
        case "$_a" in all) _left=$(($1 + $2 + $3)) ;; files) _left=$(($1 + $2)) ;; new) _left=$3 ;; *) _left=0 ;; esac
        if [ "$_left" = 0 ] && [ "$_bad" = 0 ]; then cc_show "$C_GRN" "  [+] $(printf '%-22s' "$_n") $_ok change(s) done; matches the backup now"
        else cc_show "$C_YEL" "  [*] $(printf '%-22s' "$_n") $_ok done, $_bad failed; still different: $1 changed, $2 deleted, $3 new"; fi
    done <"$W/do"
    CC_QUIET=$_q
    cc_csv_pretty "$RCSV" "$CC_RUN_DIR/changes-made.txt" 120
fi
if [ "$TIMER_ON" = 1 ]; then header "KEEP OR REVERT"; cc_timer_finish || true; fi
{
    printf '==========[ summary ]==========\n'
    printf '%s | compared with the backup from %s\n' "$([ "$APPLIED" = 1 ] && echo RESTORED || echo 'DRY RUN - nothing changed')" "$(cat "$FROM/.taken" 2>/dev/null)"
    awk -F'|' '{ printf "  %-22s %s\n", $1, ($3 == "all" ? "everything back to the backup" : $3 == "files" ? "changed and deleted files back" : $3 == "new" ? "new files to quarantine" : $3 == "dbonly" ? "files unchanged" : "left as it is") ($4 == 1 ? ", database back" : "") }' "$W/do"
    printf '\nPlan: %s/plan.txt\n' "$CC_RUN_DIR"
    [ "$APPLIED" = 1 ] && [ "$TIMER_ON" = 1 ] && printf 'Undo it all: sh %s/revert.sh --force\n' "$CC_RUN_DIR"
    printf 'Quarantined files can be moved back from %s\n' "$CC_QUAR_DIR"
} >"$CC_RUN_DIR/summary.txt"
cc_show "" ""
while IFS= read -r _l; do case "$_l" in ==*) cc_show "$C_CYN" "$_l" ;; RESTORED*) cc_show "$C_GRN" "$_l" ;; DRY*) cc_show "$C_YEL" "$_l" ;; *) cc_show "" "$_l" ;; esac; done <"$CC_RUN_DIR/summary.txt"
rm -rf "$W"
cc_finish
