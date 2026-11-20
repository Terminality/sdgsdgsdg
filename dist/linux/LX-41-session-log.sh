#!/bin/sh
# =============================================================================
# ID:       LX-41
# NAME:     Linux session & command logging
# ROLE:     Linux  (wave 2 - start it once the box is hardened, beside LX-40)
# KIND:     readonly - reads logs, changes nothing (unless --setup-auditd)
# VERSION:  1.2.0
#
# PURPOSE
#   Watches who logs in and what they run, saves it to log files, and prints
#   an alert to the console for anything that looks like the red team.  Pairs
#   with LX-40 (which watches config and persistence changes); this one
#   watches events: logins and commands.
#
#   It reads logs the box already keeps, so it changes nothing:
#     logins     ssh and console logins, the source address, failed logins,
#                brute force (fast or slow), a login that succeeds after many
#                failures, sessions and logouts               (the auth log)
#     priv       sudo and su use, the command each sudo ran, denied and
#                failed attempts, new accounts, group and password changes
#     commands   every command run, with user, tty and folder   (auditd)
#     web        a command by the web-server user (a web shell running), a
#                process running from /tmp or a web root, and the web access
#                log: requests to a dropped shell or with injection markers
#
#   Privileged commands (sudo/su) are always logged from the auth log.  To log
#   EVERY command, auditd must be recording execve; the script says whether it
#   is and prints the one rule to add, or adds it with --setup-auditd.
#
#   YOUR OWN COMMANDS DO NOT FLOOD THE ALERTS.  Admin accounts (your team) are
#   logged but stay quiet on the console unless the command itself is
#   dangerous (reverse shell, curl|sh, base64 -d|sh, nc -e, wiping history,
#   adding a user...).  A non-admin or unknown user alerts right away.
#
# USAGE
#   sudo sh LX-41-session-log.sh                       watch once, from now
#   sudo sh LX-41-session-log.sh --loop 30             keep watching (Ctrl-C stops)
#   sudo sh LX-41-session-log.sh --admin "alice bob"   name your admin accounts
#   nohup sudo sh LX-41-session-log.sh --loop 30 --alert-cmd "ssh log@10.0.0.5 'cat >>/srv/alerts/web01.log'" &
#   sudo sh LX-41-session-log.sh --setup-auditd        turn on full command logging (a change)
#
# OPTIONS
#   --loop N           re-check every N seconds until stopped (min 5)
#   --count N          with --loop: stop after N checks
#   --admin "U1 U2"    accounts whose normal activity should stay quiet
#                      (added to the auto-detected sudo/wheel members and you)
#   --admin-file FILE  one admin account per line (# comments allowed)
#   --web-user NAME    treat NAME as a web-server account: a command it runs is
#                      almost certainly a web shell, so it is always HIGH
#   --webroot DIR      a web root (repeat); flags a process running from it and
#                      maps a requested URL to a file to see if it is newly dropped
#   --access-log FILE  a web access log (repeat); apache/nginx logs are auto-found
#   --alert-own        also alert on admins' normal commands (noisy)
#   --all-commands     alert on EVERY command, not only the suspicious ones
#   --low              also print LOW alerts to the console (kept in the file either way)
#   --repeat-after N   show the same alert again only after N seconds (default
#                      600; 0 shows every repeat).  Events are always logged
#   --no-color         no colours
#   --from-start       process the existing log history on the first pass too
#                      (default: start from now, so old lines are not re-alerted)
#   --alert-cmd CMD    run CMD (sh -c) after each pass that raised alerts; the
#                      new alert lines arrive on its stdin (send them off-box)
#   --setup-auditd     add the auditd execve rule so every command is logged
#                      (the ONE change this script can make; reversible)
#   --auth-log FILE    the auth log to read (default: auto - auth.log/secure)
#   --audit-log FILE   the auditd log (default: /var/log/audit/audit.log)
#   --max-mb N         roll a log file over at N megabytes (default 50)
#   --state DIR        where logs and the read-position live
#                      (default <out>/sesslog-<host>)
#   --root DIR         treat DIR as / (for tests)
#   --help             this text plus the common options
#
# OUTPUTS  (in the state folder, <out>/sesslog-<host>/ by default)
#   alerts.log     every alert, newest at the bottom: time SEV section item - detail
#   logins.log     every login, logout and failed attempt
#   priv.log       every sudo/su, and the command sudo ran
#   commands.log   every command (with auditd): time user tty cwd command
#   web.log        every web request seen in the access log
#
# WHAT IT CHANGES
#   Nothing, unless you pass --setup-auditd, which adds one auditd rule
#   (-a always,exit -F arch=... -S execve -k bt_cmd) so execve is logged,
#   and, if you say yes, the same line in /etc/audit/rules.d/bt.rules so it
#   survives a reboot.  Both have undo lines.  No revert timer: a logging rule
#   cannot lock anyone out.
#
# DEPENDS ON
#   awk, grep, tail, wc.  For full command logging: auditd (auditctl).  The
#   auth log must be readable (root).  journalctl is used if there is no auth
#   file but journald has the data.
#
# TESTED ON
#   Ubuntu 24.04 under dash, bash, busybox sh, ksh93, mksh and yash, on fixture
#   logs via --root/--state, and live with a planted ssh brute force, a sudo
#   shadow read and a reverse-shell command.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - Without auditd only sudo/su commands are captured (still the ones that
#     matter most).  --setup-auditd turns on the rest.
#   - A command is matched against known-bad patterns, not run through a
#     sandbox: a clean-looking command by an admin is not alerted.  Read
#     commands.log for the full picture.
#   - The red team can stop auditd or delete logs.  LX-40 alerts if the audit
#     service disappears; keep the off-box copy (--alert-cmd) as the record.
#   - Log files grow; they roll over at --max-mb to one .old file.
#   - The same alert is shown once and then held back for --repeat-after
#     seconds, so a scoring engine logging in every minute does not fill the
#     screen.  The pass line says how many repeats were held back.
#   - Who ran a command is the LOGIN account (auditd's auid): "bob as root"
#     is bob after sudo/su.  Root commands from a non-admin's session alert.
#   - The script runs from its state folder and skips audit events with that
#     working folder: those are its own helpers.
#
# DEBUGGING
#   --debug          show the files being read and the read positions
#   tail -f <state>/commands.log      watch commands live
# =============================================================================

# >>> BT-LIB  (lib/lib.sh 0.5.0 pasted in by tools/build.sh - edit lib/lib.sh, not this copy)
# =============================================================================
# ID:       LB-01
# NAME:     Shell library (lib.sh)
# ROLE:     Automation  (wave 0, foundation)
# VERSION:  0.5.0
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
CC_LIB_VERSION="0.5.0"

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
# cc_net_ask_password -> BT_NET_PASS: used as it is when already set (setting
#   it is the answer), else typed now, hidden, never logged.  Returns 1 when
#   there is no password and nobody to ask.
cc_net_ask_password() {
    [ -n "${BT_NET_PASS:-}" ] && return 0
    _cc_can_ask || return 1
    printf '%s[?]%s Device password (hidden, never saved): ' "${C_CYN:-}" "${C_OFF:-}" >/dev/tty
    stty -echo </dev/tty 2>/dev/null; read -r BT_NET_PASS </dev/tty; stty echo </dev/tty 2>/dev/null; printf '\n' >/dev/tty
    [ -n "$BT_NET_PASS" ]
}

# -----------------------------------------------------------------------------
# Kit integrity and finish
# -----------------------------------------------------------------------------

# cc_verify_self
#   Rule 15: the kit's hash is checked before each run.  If a MANIFEST.sha256
#   (written by tools/build.sh) sits in the script's folder or one of the two
#   folders above it, or BT_MANIFEST points to one, the running script's
#   hash must match its line there.  A mismatch stops the script: the file on
#   this host is not the one you built, and a red team may have edited it.
#   BT_SKIP_VERIFY=1 turns the check off (for development).
cc_verify_self() {
    [ "${BT_SKIP_VERIFY:-0}" = 1 ] && { cc_debug "verify: skipped (BT_SKIP_VERIFY=1)"; return 0; }
    [ -f "$0" ] || { cc_debug "verify: script was not started from a file, nothing to hash"; return 0; }
    _cc_vs_man=${BT_MANIFEST:-}
    if [ -z "$_cc_vs_man" ]; then
        for _cc_vs_d in "$CC_KIT" "$CC_KIT/.." "$CC_KIT/../.."; do
            if [ -r "$_cc_vs_d/MANIFEST.sha256" ]; then _cc_vs_man="$_cc_vs_d/MANIFEST.sha256"; break; fi
        done
    fi
    [ -n "$_cc_vs_man" ] && [ -r "$_cc_vs_man" ] || { cc_debug "verify: no MANIFEST.sha256 found (unbuilt copy), not checked"; return 0; }
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
LX-41 Linux session & command logging - who logs in, what they run, with alerts
  sudo sh LX-41-session-log.sh                   watch once, from now
  sudo sh LX-41-session-log.sh --loop 30         keep watching

  --loop N           re-check every N seconds (min 5)
  --count N          with --loop: stop after N checks
  --admin "U1 U2"    accounts whose normal activity stays quiet
  --admin-file FILE  one admin account per line
  --web-user NAME    treat NAME as a web-server account (web shell if it runs a command)
  --webroot DIR      a web root to watch processes and requests against (repeat)
  --access-log FILE  a web access log to read (repeat; apache/nginx are auto-found)
  --alert-own        also alert on admins' normal commands
  --all-commands     alert on every command, not only suspicious ones
  --low              also show LOW alerts on the console
  --repeat-after N   repeat the same alert only after N seconds (default 600)
  --no-color         no colours
  --from-start       process existing history on the first pass
  --alert-cmd CMD    run CMD with new alert lines on its stdin
  --setup-auditd     add the auditd execve rule (the one change; reversible)
  --auth-log FILE    auth log to read (default: auto)
  --audit-log FILE   auditd log (default: /var/log/audit/audit.log)
  --max-mb N         roll a log over at N MB (default 50)
  --state DIR        where logs and read-positions live
  --root DIR         treat DIR as / (tests)
  --help             this text

USAGE
    cc_usage_common
}

# ---- Options ----------------------------------------------------------------
LOOP=0; COUNT=0; ADMIN_IN=""; ADMIN_FILE=""; ALERT_OWN=0; ALLCMD=0; SHOWLOW=0
FROMSTART=0; ALERTCMD=""; SETUP_AUDITD=0; AUTHLOG=""; AUDITLOG=""; MAXMB=50; STATE=""; R=""; COLOR=1
WEBUSERS_IN=""; WEBROOTS_IN=""; ACCESSLOGS_IN=""; REPEAT=600
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --loop)        [ $# -ge 2 ] || cc_die 2 "--loop needs seconds"; LOOP=$2; shift 2 ;;
        --count)       [ $# -ge 2 ] || cc_die 2 "--count needs a number"; COUNT=$2; shift 2 ;;
        --admin)       [ $# -ge 2 ] || cc_die 2 "--admin needs one or more names"; ADMIN_IN="$ADMIN_IN $2"; shift 2 ;;
        --admin-file)  [ $# -ge 2 ] || cc_die 2 "--admin-file needs a file"; [ -r "$2" ] || cc_die 2 "cannot read $2"; ADMIN_FILE=$2; shift 2 ;;
        --web-user)    [ $# -ge 2 ] || cc_die 2 "--web-user needs a name"; WEBUSERS_IN="$WEBUSERS_IN $2"; shift 2 ;;
        --webroot)     [ $# -ge 2 ] || cc_die 2 "--webroot needs a folder"; WEBROOTS_IN="$WEBROOTS_IN $2"; shift 2 ;;
        --access-log)  [ $# -ge 2 ] || cc_die 2 "--access-log needs a file"; ACCESSLOGS_IN="$ACCESSLOGS_IN $2"; shift 2 ;;
        --alert-own)   ALERT_OWN=1; shift ;;
        --all-commands) ALLCMD=1; shift ;;
        --low)         SHOWLOW=1; shift ;;
        --repeat-after) [ $# -ge 2 ] || cc_die 2 "--repeat-after needs seconds"; REPEAT=$2; shift 2 ;;
        --no-color|--no-colour) COLOR=0; shift ;;
        --from-start)  FROMSTART=1; shift ;;
        --alert-cmd)   [ $# -ge 2 ] || cc_die 2 "--alert-cmd needs a command"; ALERTCMD=$2; shift 2 ;;
        --setup-auditd) SETUP_AUDITD=1; shift ;;
        --auth-log)    [ $# -ge 2 ] || cc_die 2 "--auth-log needs a file"; AUTHLOG=$2; shift 2 ;;
        --audit-log)   [ $# -ge 2 ] || cc_die 2 "--audit-log needs a file"; AUDITLOG=$2; shift 2 ;;
        --max-mb)      [ $# -ge 2 ] || cc_die 2 "--max-mb needs a number"; MAXMB=$2; shift 2 ;;
        --state)       [ $# -ge 2 ] || cc_die 2 "--state needs a folder"; STATE=$2; shift 2 ;;
        --root)        [ $# -ge 2 ] || cc_die 2 "--root needs a folder"; [ -d "$2" ] || cc_die 2 "--root: not a folder: $2"
                       R=$(cd "$2" && pwd); [ "$R" = / ] && R=""; shift 2 ;;
        --help|-h)     usage; exit 0 ;;
        *)             cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
case "$LOOP" in ''|*[!0-9]*) cc_die 2 "--loop needs a whole number of seconds" ;; esac
case "$COUNT" in ''|*[!0-9]*) cc_die 2 "--count needs a whole number" ;; esac
case "$REPEAT" in ''|*[!0-9]*) cc_die 2 "--repeat-after needs a whole number of seconds (0 shows every repeat)" ;; esac
case "$MAXMB" in ''|*[!0-9]*|0) cc_die 2 "--max-mb needs a whole number, 1 or more" ;; esac
[ "$LOOP" -gt 0 ] && [ "$LOOP" -lt 5 ] && cc_die 2 "--loop must be at least 5 seconds"

cc_init "LX-41" "Linux session & command logging" readonly
cc_detect_os
IS_ROOT=0
cc_is_root && IS_ROOT=1
[ "$IS_ROOT" = 1 ] || [ -n "$R" ] || cc_warn "not running as root: the auth log and audit log are usually unreadable, so logins and commands will be missed"
[ -n "$STATE" ] || STATE="$CC_OUT/sesslog-$CC_HOST"
(umask 077; mkdir -p "$STATE/.cur") || cc_die 3 "cannot create $STATE"
STATE=$(cc_abspath "$STATE")
# Run from the state folder: auditd records every helper this script starts
# (awk, date, ...) with that working folder, which is how they are told apart
# from everyone else's commands.  So file arguments are made absolute first.
[ -n "$AUTHLOG" ] && [ -e "$AUTHLOG" ] && AUTHLOG=$(cc_abspath "$AUTHLOG")
[ -n "$AUDITLOG" ] && [ -e "$AUDITLOG" ] && AUDITLOG=$(cc_abspath "$AUDITLOG")
[ -n "$ADMIN_FILE" ] && ADMIN_FILE=$(cc_abspath "$ADMIN_FILE")
_al=""; for _f in $ACCESSLOGS_IN; do [ -e "$_f" ] && _f=$(cc_abspath "$_f"); _al="$_al $_f"; done; ACCESSLOGS_IN=$_al
_wr=""; for _f in $WEBROOTS_IN; do [ -d "$_f" ] && [ -z "$R" ] && _f=$(cc_abspath "$_f"); _wr="$_wr $_f"; done; WEBROOTS_IN=$_wr
cd "$STATE" || cc_die 3 "cannot enter $STATE"
MAXBYTES=$((MAXMB * 1024 * 1024))
ALERTS="$STATE/alerts.log"
PASSWD="$R/etc/passwd"
GROUP="$R/etc/group"

cc_color_init
[ "$COLOR" = 1 ] || { C_RED=""; C_YEL=""; C_GRN=""; C_CYN=""; C_GRY=""; C_OFF=""; }

# ---- Find the auth log ------------------------------------------------------
if [ -z "$AUTHLOG" ]; then
    # (Alpine: busybox syslogd writes everything, logins too, to /var/log/messages)
    for _f in "$R/var/log/auth.log" "$R/var/log/secure" "$R/var/log/messages"; do
        [ -f "$_f" ] && { AUTHLOG=$_f; break; }
    done
fi
AUTH_JOURNAL=0
if [ -z "$AUTHLOG" ] && [ -z "$R" ] && cc_have journalctl; then
    AUTH_JOURNAL=1
    cc_info "no auth log file: reading logins and sudo from journalctl"
elif [ -n "$AUTHLOG" ]; then
    [ -r "$AUTHLOG" ] || cc_warn "cannot read $AUTHLOG (need root): logins and sudo will be missed"
    cc_info "auth log: $AUTHLOG"
else
    cc_warn "no auth log found (looked for auth.log, secure and messages): logins and sudo cannot be watched"
fi

# ---- Find the audit log -----------------------------------------------------
[ -n "$AUDITLOG" ] || AUDITLOG="$R/var/log/audit/audit.log"
AUDIT_ON=0
if [ -r "$AUDITLOG" ] && [ -s "$AUDITLOG" ]; then AUDIT_ON=1; fi
# Is the execve rule actually loaded?  (Only meaningful on a live box.)
AUDIT_RULE=0
if [ -z "$R" ] && cc_have auditctl; then
    auditctl -l 2>/dev/null | grep -q 'syscall=.*execve\|-S execve' && AUDIT_RULE=1
fi

# ---- Optional: set up the auditd execve rule (the one change) ---------------
if [ "$SETUP_AUDITD" = 1 ]; then
    [ "$IS_ROOT" = 1 ] || cc_die 2 "--setup-auditd needs root"
    [ -z "$R" ] || cc_die 2 "--setup-auditd cannot be used with --root"
    cc_have auditctl || cc_die 3 "auditd is not installed (no auditctl). Install the 'auditd' package, then re-run with --setup-auditd"
    if [ "$AUDIT_RULE" = 1 ]; then
        cc_info "the auditd execve rule is already loaded: every command is being logged"
    else
        _arch=b64; case "$(uname -m 2>/dev/null)" in i?86|armv*) _arch=b32 ;; esac
        cc_show "$C_YEL" "Adding the auditd rule so every command is logged:"
        cc_show "" "  auditctl -a always,exit -F arch=$_arch -S execve -k bt_cmd"
        if cc_confirm "Add it now?"; then
            if auditctl -a always,exit -F arch="$_arch" -S execve -k bt_cmd 2>>"$CC_LOG"; then
                [ "$_arch" = b64 ] && auditctl -a always,exit -F arch=b32 -S execve -k bt_cmd 2>>"$CC_LOG"
                CC_APPLY=1      # so the undo lines are recorded
                cc_undo_add "remove the auditd execve rule" "auditctl -d always,exit -F arch=$_arch -S execve -k bt_cmd 2>/dev/null; auditctl -d always,exit -F arch=b32 -S execve -k bt_cmd 2>/dev/null; true"
                cc_show "$C_GRN" "[ok] every command is now logged to $AUDITLOG"
                # Loaded rules are lost at reboot unless they are in rules.d.
                if [ -d /etc/audit/rules.d ] && [ ! -f /etc/audit/rules.d/bt.rules ] && cc_ask "Keep the rule after a reboot too?" Y "yes, write /etc/audit/rules.d/bt.rules" "no, only until the next reboot"; then
                    { printf -- '-a always,exit -F arch=%s -S execve -k bt_cmd\n' "$_arch"
                      [ "$_arch" = b64 ] && printf -- '-a always,exit -F arch=b32 -S execve -k bt_cmd\n'; } >/etc/audit/rules.d/bt.rules \
                        && cc_undo_add "remove /etc/audit/rules.d/bt.rules" "rm -f /etc/audit/rules.d/bt.rules" \
                        && cc_show "$C_GRN" "[ok] wrote /etc/audit/rules.d/bt.rules"
                fi
                # shellcheck disable=SC2034  # read by the library
                CC_APPLY=0
                cc_info "undo: the lines are in $CC_UNDO (auditctl -d ... removes the rule)"
                AUDIT_RULE=1; AUDIT_ON=1
            else
                cc_err "could not add the rule (see the log)"
            fi
        fi
    fi
fi

# ---- Admin allowlist (whose normal activity stays quiet) --------------------
# Auto: root, members of the admin groups, and whoever launched this.
_admins=" root "
if [ -f "$GROUP" ]; then
    for _m in $(awk -F: '$1 ~ /^(sudo|wheel|admin|adm)$/ { gsub(/,/, " ", $4); print $4 }' "$GROUP" 2>/dev/null); do
        _admins="$_admins$_m "
    done
fi
for _u in "${SUDO_USER:-}" "${LOGNAME:-}" "$(id -un 2>/dev/null)"; do
    [ -n "$_u" ] && _admins="$_admins$_u "
done
[ -n "$ADMIN_FILE" ] && for _u in $(sed 's/#.*//' "$ADMIN_FILE"); do _admins="$_admins$_u "; done
for _u in $ADMIN_IN; do _admins="$_admins$_u "; done
# Normalise to a single-spaced " a b c " with no repeats.
ADMINS=" $(printf '%s' "$_admins" | tr ' ' '\n' | grep . | sort -u | tr '\n' ' ')"
is_admin() { case "$ADMINS" in *" $1 "*) return 0 ;; esac; return 1; }
known_user() { [ -f "$PASSWD" ] || return 0; cut -d: -f1 "$PASSWD" | grep -qx "$1"; }
cc_info "admin accounts (kept quiet): $(printf '%s' "$ADMINS" | sed 's/^ //;s/ $//')"

# Web service accounts.  A command run by one of these is almost always a web
# shell, so it is always HIGH.
_webu=" www-data apache apache2 nginx httpd http daemon php php-fpm www tomcat tomcat8 tomcat9 jetty lighttpd "
for _u in $WEBUSERS_IN; do _webu="$_webu$_u "; done
WEBUSERS=" $(printf '%s' "$_webu" | tr ' ' '\n' | grep . | sort -u | tr '\n' ' ')"
is_webuser() { case "$WEBUSERS" in *" $1 "*) return 0 ;; esac; return 1; }

# Web roots: used to spot a process running from one, and to map a requested
# URL to a file on disk (to see if that file is newly dropped).
WEBROOTS=""
for _d in /var/www /var/www/html /srv/www /srv/http /usr/share/nginx/html /usr/local/www /opt/lampp/htdocs $WEBROOTS_IN; do
    case "$_d" in /*) _d="$R$_d" ;; esac
    [ -d "$_d" ] && WEBROOTS="$WEBROOTS $_d"
done

# Access logs: given ones, plus the usual apache/nginx locations.
ACCESSLOGS=""
for _g in $ACCESSLOGS_IN "$R"/var/log/apache2/*access*.log "$R"/var/log/httpd/*access_log "$R"/var/log/nginx/*access*.log "$R"/var/log/lighttpd/*access*.log; do
    [ -f "$_g" ] && [ -r "$_g" ] && ACCESSLOGS="$ACCESSLOGS $_g"
done
[ -n "$ACCESSLOGS" ] && cc_info "web access logs:$ACCESSLOGS"

# Known web-shell filenames, and markers of a command-injection / shell
# request (matched after the URL is decoded).  awk regexes: [ \t], not
# [[:space:]], so old mawk works too.
LX_SHELLNAMES='^(c99|r57|wso|b374k|alfa|cmd|shell|backdoor|webshell|p0wny|weevely|phpspy|minishell|0day|antichat|sh|x)\.(php|phtml|php[0-9]|asp|aspx|jsp|cgi)$'
LX_INJECT='(cmd=|exec=|shell_exec|passthru|system\(|popen\(|proc_open|base64_decode|eval\(|assert\(|/bin/(ba|da|z)?sh|;[ +]*id|\|[ +]*id|`|\$\(|whoami|wget[ +]|curl[ +]|/dev/tcp/|php://input|allow_url|\.\./\.\./|/etc/passwd|/etc/shadow)'

# A marker file whose mtime is "when watching began": a web-root script newer
# than this was dropped after we started looking.
[ -f "$STATE/.started" ] || : >"$STATE/.started"

# Patterns that are almost never a real admin command (reverse shells,
# download-and-run, encoded commands, log/history wiping).
LX_STRONG='(/dev/tcp/|/dev/udp/|bash -i|sh -i| -e /bin/|nc .*-e|ncat .*-e|socat .*exec|mkfifo .*\|.*sh|(curl|wget)[^|;]*\|[ \t]*(ba|da|z)?sh|base64[ \t]+(-d|--decode)|python[0-9.]*[ \t]+-c|perl[ \t]+-e|php[ \t]+-r|openssl[ \t]+s_client|chattr[ \t]+[+]i|history[ \t]+-c|unset[ \t]+HISTFILE|>[ \t]*/var/log/|truncate[^;]*/var/log/|auditctl[ \t]+-[eDd]|(systemctl|service)[ \t]+(stop|disable|mask)?[ \t]*auditd|setenforce[ \t]+0)'
LX_WEAK='(useradd|userdel|usermod|adduser|passwd([ \t]|$)|chpasswd|groupadd|gpasswd|visudo|/etc/sudoers|/etc/shadow|/etc/passwd|authorized_keys|iptables[ \t]+-F|nft[ \t]+flush|ufw[ \t]+disable|systemctl[ \t]+(stop|disable|mask)|crontab|chmod[ \t]+[^ ]*(777|[+]s|[0-7]*[4567][0-7][0-7][0-7])|chown[ \t]+root|wget[ \t]|curl[ \t]|/tmp/|/dev/shm/)'

# ---- Console + files --------------------------------------------------------
show() { printf '%s%s%s\n' "$1" "$2" "${C_OFF:-}"; }
# rollover FILE -> move it aside if it passed --max-mb.
rollover() {
    [ -f "$1" ] || return 0
    _sz=$(wc -c 2>/dev/null <"$1"); case "$_sz" in ''|*[!0-9]*) return 0 ;; esac
    [ "$_sz" -ge "$MAXBYTES" ] && mv "$1" "$1.old"
    return 0
}

# ---- Incremental read -------------------------------------------------------
# new_lines KEY FILE -> print only the lines added since last pass; on the
#   first pass (no cursor) print nothing but remember the end, unless
#   --from-start.  Handles rotation (file shorter than remembered -> restart).
new_lines() {
    _nl_k="$STATE/.cur/$1"; _nl_f="$2"
    [ -r "$_nl_f" ] || return 0
    _nl_tot=$(wc -l 2>/dev/null <"$_nl_f"); case "$_nl_tot" in ''|*[!0-9]*) _nl_tot=0 ;; esac
    if [ -f "$_nl_k" ]; then
        _nl_seen=$(cat "$_nl_k" 2>/dev/null); case "$_nl_seen" in ''|*[!0-9]*) _nl_seen=0 ;; esac
    else
        # First time we have seen this file.
        if [ "$FROMSTART" = 1 ]; then _nl_seen=0; else _nl_seen=$_nl_tot; fi
    fi
    [ "$_nl_tot" -lt "$_nl_seen" ] && _nl_seen=0            # rotated
    # Exactly the lines counted above, even if more arrive while reading.
    [ "$_nl_tot" -gt "$_nl_seen" ] && tail -n +"$((_nl_seen + 1))" "$_nl_f" | head -n "$((_nl_tot - _nl_seen))"
    printf '%s\n' "$_nl_tot" >"$_nl_k"
}

# ---- The parsers ------------------------------------------------------------
# Each pass is a fixed handful of awk runs, however many log lines arrived:
# a brute force or a scanner writes thousands of lines a minute, and a shell
# loop over them would fall behind.  Every parser appends events to the
# per-category log itself and writes candidate alerts, one per line, to
# $STATE/.raw as:  time <TAB> SEV <TAB> section <TAB> item <TAB> detail
# Settings reach awk through the environment (no backslash surprises).
export LX_STRONG LX_WEAK LX_SHELLNAMES LX_INJECT
LX_ADM=$ADMINS; LX_WEBU=$WEBUSERS; LX_OWN=$ALERT_OWN; LX_ALL=$ALLCMD; LX_PASSWD=$PASSWD
LX_RAW="$STATE/.raw"; LX_STATE=$STATE; LX_WEBROOTS=$WEBROOTS; LX_R=$R
export LX_ADM LX_WEBU LX_OWN LX_ALL LX_PASSWD LX_RAW LX_STATE LX_WEBROOTS LX_R

# Shared awk: the account lists, and the rules for one command.
AWK_CLS='
function isin(set, name) { return index(set, " " name " ") > 0 }    # awk: posix-ok
function emit(t, sev, sec, item, detail) { gsub(/\t/, " ", detail); print t "\t" sev "\t" sec "\t" item "\t" detail >> RAW }    # awk: posix-ok
function loadusers(   l, p, n) {    # awk: posix-ok
    ADM = ENVIRON["LX_ADM"]; WEBU = ENVIRON["LX_WEBU"]; OWN = ENVIRON["LX_OWN"] + 0; ALL = ENVIRON["LX_ALL"] + 0
    STRONG = ENVIRON["LX_STRONG"]; WEAK = ENVIRON["LX_WEAK"]; RAW = ENVIRON["LX_RAW"]
    while ((getline l < ENVIRON["LX_PASSWD"]) > 0) { n = split(l, p, ":"); if (n >= 3) { uname[p[3]] = p[1]; uidof[p[1]] = p[3] + 0; nusers++ } }
}
function known(u) { return nusers == 0 || (u in uidof) }    # awk: posix-ok
# classify: WHO did it (the login account), RUNAS is the account it ran as.
function classify(t, sec, who, runas, cmd, tty,   label, adm) {    # awk: posix-ok
    label = (runas != "" && runas != who) ? who " as " runas : who
    if (isin(WEBU, who) || isin(WEBU, runas)) { emit(t, "HIGH", sec, label, "web server account ran a command (web shell?): " cmd); return }
    if (cmd ~ STRONG) { emit(t, "HIGH", sec, label, "dangerous command: " cmd); return }
    if (!known(who)) { emit(t, "HIGH", sec, label, "command by an account not in /etc/passwd: " cmd); return }
    adm = isin(ADM, who)
    if (cmd ~ WEAK) { emit(t, (adm && !OWN) ? "LOW" : "MED", sec, label, "sensitive command: " cmd); return }
    if (adm) { if (ALL || OWN) emit(t, "LOW", sec, label, "command: " cmd); return }
    # A service account with no terminal is a daemon doing its job.
    if (!ALL && (who in uidof) && uidof[who] > 0 && uidof[who] < 1000 && (tty == "" || tty == "?" || tty == "(none)")) return
    emit(t, "MED", sec, label, "command by a non-admin account: " cmd)
}'

# ---- Section: logins and priv (from the auth log) ---------------------------
read_auth() {
    : >"$STATE/.auth"
    if [ "$AUTH_JOURNAL" = 1 ]; then
        # journald: one call returns the new entries and the cursor to
        # continue from, so nothing can fall between two calls.
        _jc="$STATE/.cur/journal"
        if [ -s "$_jc" ]; then
            journalctl --after-cursor="$(cat "$_jc")" --show-cursor -o short-iso --no-pager _COMM=sshd _COMM=sudo _COMM=su _COMM=useradd _COMM=usermod _COMM=userdel _COMM=groupadd _COMM=passwd 2>/dev/null >"$STATE/.jr" || :
        elif [ "$FROMSTART" = 1 ]; then
            journalctl --show-cursor -o short-iso --no-pager _COMM=sshd _COMM=sudo _COMM=su _COMM=useradd _COMM=usermod _COMM=userdel _COMM=groupadd _COMM=passwd 2>/dev/null >"$STATE/.jr" || :
        else
            journalctl -n 0 --show-cursor --no-pager 2>/dev/null >"$STATE/.jr" || :
        fi
        _jn=$(sed -n 's/^-- cursor: //p' "$STATE/.jr" | tail -n 1)
        [ -n "$_jn" ] && printf '%s\n' "$_jn" >"$_jc"
        grep -v '^-- ' "$STATE/.jr" >"$STATE/.auth" 2>/dev/null || :
        rm -f "$STATE/.jr"
    elif [ -n "$AUTHLOG" ] && [ -r "$AUTHLOG" ]; then
        new_lines auth "$AUTHLOG" >"$STATE/.auth"
    fi
    [ -s "$STATE/.auth" ] || return 0
    [ -f "$STATE/.failtotals" ] || : >"$STATE/.failtotals"
    awk "$AWK_CLS"'
        function ts() { return ($1 ~ /^[0-9][0-9][0-9][0-9]-/) ? $1 : $1 " " $2 " " $3 }    # awk: posix-ok
        function after(s, key,   i) { i = index(s, key); return i ? substr(s, i + length(key)) : "" }    # awk: posix-ok
        function word(s) { sub(/^[ \047"]+/, "", s); sub(/[ ;,(\047"].*/, "", s); return s }    # awk: posix-ok
        BEGIN {
            loadusers(); S = ENVIRON["LX_STATE"]
            LOGINS = S "/logins.log"; PRIV = S "/priv.log"; TOT = S "/.failtotals"
            while ((getline l < TOT) > 0) { split(l, a, "\t"); tot[a[1]] = a[2] + 0 }
        }
        / Accepted [a-z-]+ for / {
            s = after($0, " Accepted "); how = word(s); u = word(after(s, " for ")); ip = word(after(s, " from ")); if (ip == "") ip = "?"
            nlog++; print ts() " LOGIN " u " from " ip " (" how ")" >> LOGINS
            prior = tot[ip] + pf[ip]
            if (prior >= 6) emit(ts(), "HIGH", "logins", u "@" ip, "login SUCCEEDED after " prior " failed logins from this address (password guessed?)")
            else if (!known(u)) emit(ts(), "HIGH", "logins", u "@" ip, "login by an account not in /etc/passwd (" how ")")
            else if (u == "root" && how == "password") emit(ts(), "HIGH", "logins", "root@" ip, "root logged in over the network with a PASSWORD")
            else if (isin(ADM, u)) emit(ts(), "LOW", "logins", u "@" ip, "admin login (" how ")")
            else emit(ts(), "MED", "logins", u "@" ip, "login by a non-admin account (" how ")")
            next
        }
        / Failed (password|publickey|keyboard-interactive[^ ]*) for / {
            s = after($0, " for "); if (s ~ /^invalid user /) s = substr(s, 14)
            u = word(s); ip = word(after(s, " from ")); if (ip == "") ip = "?"
            nlog++; print ts() " FAIL " u " from " ip >> LOGINS
            if (ip != "?") pf[ip]++
            next
        }
        / session (opened|closed) for user / {
            if ($0 ~ /cron:session|systemd-user/) next
            print ts() " SESSION-" (($0 ~ / session opened /) ? "OPEN " : "CLOSE ") word(after($0, " for user ")) >> LOGINS
            if ($0 !~ /su(\[[0-9]+\])?:|su:session|su-l:session/) next
        }
        / sudo(\[[0-9]+\])?: / {
            s = after($0, " sudo"); sub(/^(\[[0-9]+\])?: */, "", s); u = word(s)
            if (s ~ /COMMAND=/) {
                cmd = after(s, "COMMAND="); runas = word(after(s, "USER=")); tty = word(after(s, "TTY="))
                if (s ~ /NOT in sudoers|not allowed|command not allowed/) {
                    print ts() " SUDO-DENIED " u ": " cmd >> PRIV
                    emit(ts(), isin(ADM, u) ? "MED" : "HIGH", "priv", u, "tried sudo but is not allowed: " cmd)
                } else if (s ~ /incorrect password attempt/) {
                    print ts() " SUDO-FAIL " u ": " cmd >> PRIV
                    emit(ts(), "MED", "priv", u, "sudo password failures, then tried: " cmd)
                } else {
                    print ts() " SUDO " u (runas != "" && runas != "root" ? " as " runas : "") ": " cmd >> PRIV
                    classify(ts(), "priv", u, runas, cmd, tty)
                }
            } else if (s ~ /authentication failure/) {
                u = word(after(s, " user=")); if (u == "") u = word(after(s, "logname="))
                print ts() " SUDO-FAIL " u >> PRIV
                emit(ts(), "MED", "priv", u, "sudo authentication failure")
            }
            next
        }
        # doas (Alpine): "doas: alice ran command ls as root from /home/alice"
        / doas(\[[0-9]+\])?: / {
            s = after($0, " doas"); sub(/^(\[[0-9]+\])?: */, "", s)
            if (s ~ / ran command /) {
                u = word(s); cmd = after(s, " ran command "); runas = ""
                if (match(cmd, / as [^ ]+ from /)) { runas = word(substr(cmd, RSTART + 4)); cmd = substr(cmd, 1, RSTART - 1) }
                print ts() " DOAS " u (runas != "" && runas != "root" ? " as " runas : "") ": " cmd >> PRIV
                classify(ts(), "priv", u, runas, cmd, "")
            } else if (s ~ /failed auth for |command not permitted for /) {
                u = (s ~ /failed auth for /) ? word(after(s, "failed auth for ")) : word(after(s, "not permitted for "))
                sub(/:$/, "", u)
                print ts() " DOAS-FAIL " u ": " s >> PRIV
                emit(ts(), isin(ADM, u) ? "MED" : "HIGH", "priv", u, "doas refused: " s)
            }
            next
        }
        / su(\[[0-9]+\])?: / {
            s = after($0, " su"); sub(/^(\[[0-9]+\])?: */, "", s)
            if (s ~ /^FAILED|FAILED su|authentication failure/) {
                u = word(after(s, " by ")); if (u == "") u = word(after(s, "ruser=")); if (u == "") u = "?"
                print ts() " SU-FAIL " u ": " s >> PRIV
                emit(ts(), "MED", "priv", u, "a su attempt failed")
            } else if (s ~ /^\(to /) {
                to = word(after(s, "(to ")); sub(/\)$/, "", to); u = word(after(s, ") "))
                print ts() " SU " u " -> " to >> PRIV
                if (!isin(ADM, u)) emit(ts(), (to == "root") ? "HIGH" : "MED", "priv", u, "su to " to " by a non-admin account")
            } else if (s ~ /session opened for user /) {
                to = word(after(s, " for user ")); u = word(after(s, " by ")); if (u == "") u = "?"
                print ts() " SU " u " -> " to >> PRIV
                if (u != "?" && !isin(ADM, u)) emit(ts(), (to == "root") ? "HIGH" : "MED", "priv", u, "su to " to " by a non-admin account")
            }
            next
        }
        # Account changes show up in the auth log too.
        / useradd(\[[0-9]+\])?: new user: / { u = word(after($0, "name=")); print ts() " ACCOUNT new user " u >> PRIV; emit(ts(), "HIGH", "accounts", u, "new account created" (($0 ~ /UID=0,/) ? " with UID 0" : "")); next }
        / (usermod|gpasswd)(\[[0-9]+\])?: .*(add|added) .* to group / {
            g = word(after($0, " to group ")); u = ($0 ~ /: user /) ? word(after($0, ": user ")) : word(after($0, " add "))
            print ts() " ACCOUNT " u " added to group " g >> PRIV
            emit(ts(), (g ~ /^(sudo|wheel|admin|root|adm|docker|lxd)$/) ? "HIGH" : "MED", "accounts", u, "added to group " g)
            next
        }
        / passwd(\[[0-9]+\])?: .*password changed for / { u = word(after($0, "password changed for ")); print ts() " ACCOUNT password changed for " u >> PRIV; emit(ts(), "MED", "accounts", u, "password changed"); next }
        / userdel(\[[0-9]+\])?: delete user / { u = word(after($0, "delete user ")); print ts() " ACCOUNT deleted user " u >> PRIV; emit(ts(), "MED", "accounts", u, "account deleted"); next }
        END {
            # Brute force: a burst in this pass, or a slow one adding up.
            for (ip in pf) {
                was = tot[ip]; tot[ip] += pf[ip]
                if (pf[ip] > 5) emit("", "HIGH", "logins", ip, pf[ip] " failed logins from this address (brute force)")
                else if (was < 20 && tot[ip] >= 20) emit("", "HIGH", "logins", ip, tot[ip] " failed logins so far from this address (slow brute force)")
            }
            for (ip in tot) print ip "\t" tot[ip] > (TOT ".new")
            print nlog + 0
        }' "$STATE/.auth" >"$STATE/.n"
    [ -f "$STATE/.failtotals.new" ] && mv "$STATE/.failtotals.new" "$STATE/.failtotals"
    N_LOGIN=$(cat "$STATE/.n" 2>/dev/null); case "$N_LOGIN" in ''|*[!0-9]*) N_LOGIN=0 ;; esac
}

# ---- Section: commands (from auditd execve) ---------------------------------
read_audit() {
    [ -r "$AUDITLOG" ] || return 0
    new_lines audit "$AUDITLOG" >"$STATE/.audit"
    [ -s "$STATE/.audit" ] || return 0
    # One command per audit event id, from the SYSCALL/EXECVE/CWD records that
    # share msg=audit(TIME:ID).  Hex-encoded arguments are decoded.  Events
    # whose working folder is our state folder are this script's own helpers
    # (it runs from there for exactly this reason) and are left out.
    awk "$AWK_CLS"'
        function hexval(c) { return index("0123456789abcdef", tolower(c)) - 1 }    # awk: posix-ok
        function unhex(s,   i, r) { r = ""; for (i = 1; i + 1 <= length(s); i += 2) r = r sprintf("%c", hexval(substr(s, i, 1)) * 16 + hexval(substr(s, i + 1, 1))); return r }    # awk: posix-ok
        function evid(line) { if (match(line, /audit\([0-9.]+:[0-9]+\)/)) return substr(line, RSTART + 6, RLENGTH - 7); return "" }    # awk: posix-ok
        # field: the value of " name=" (the space keeps uid from matching auid).
        function field(line, name,   s, v) {    # awk: posix-ok
            if (!match(line, " " name "=")) return ""
            s = substr(line, RSTART + length(name) + 2)
            if (substr(s, 1, 1) == "\"") { v = substr(s, 2); sub(/".*/, "", v); return v }
            v = s; sub(/[ \t].*/, "", v); return v
        }
        # iso: seconds since 1970 -> 2026-11-15T00:10:01Z (no strftime in POSIX awk).
        function iso(t,   d, r, z, era, doe, yoe, y, doy, mp, m, dd) {    # awk: posix-ok
            t = int(t); d = int(t / 86400); r = t - d * 86400
            z = d + 719468; era = int(z / 146097); doe = z - era * 146097
            yoe = int((doe - int(doe / 1460) + int(doe / 36524) - int(doe / 146096)) / 365)
            y = yoe + era * 400; doy = doe - (365 * yoe + int(yoe / 4) - int(yoe / 100))
            mp = int((5 * doy + 2) / 153); dd = doy - int((153 * mp + 2) / 5) + 1
            m = (mp < 10) ? mp + 3 : mp - 9; if (m <= 2) y++
            return sprintf("%04d-%02d-%02dT%02d:%02d:%02dZ", y, m, dd, int(r / 3600), int((r % 3600) / 60), r % 60)
        }
        function name(u) { return (u in uname) ? uname[u] : ("uid" u) }    # awk: posix-ok
        BEGIN { loadusers(); S = ENVIRON["LX_STATE"]; R = ENVIRON["LX_R"]; CMDS = S "/commands.log"; nw = split(ENVIRON["LX_WEBROOTS"], wr, " ") }
        /type=SYSCALL/ { id = evid($0); if (id == "") next; uid[id] = field($0, "uid"); auid[id] = field($0, "auid"); tty[id] = field($0, "tty"); succ[id] = field($0, "success"); exe[id] = field($0, "exe") }
        /type=CWD/     { id = evid($0); if (id != "") cwd[id] = field($0, "cwd") }
        /type=EXECVE/  {
            id = evid($0); if (id == "") next
            cmd = ""; s = $0
            while (match(s, / a[0-9]+=("[^"]*"|[^ \t]+)/)) {
                tok = substr(s, RSTART + 1, RLENGTH - 1); s = substr(s, RSTART + RLENGTH)
                sub(/^a[0-9]+=/, "", tok)
                if (substr(tok, 1, 1) == "\"") val = substr(tok, 2, length(tok) - 2)
                else if (tok ~ /^[0-9A-Fa-f]+$/ && length(tok) % 2 == 0) val = unhex(tok)
                else val = tok
                gsub(/[\t\n\r]/, " ", val)
                cmd = cmd (cmd == "" ? "" : " ") val
            }
            # A long command line is split over several EXECVE records.
            if (cmd == "") next
            if (id in argv) argv[id] = argv[id] " " cmd
            else { order[++seen] = id; argv[id] = cmd }
        }
        END {
            for (i = 1; i <= seen; i++) {
                id = order[i]
                if (succ[id] == "no") continue
                if (cwd[id] == S) continue                      # this script
                t = id; sub(/:.*/, "", t); t = iso(t)
                runas = name(uid[id])
                who = (auid[id] == "" || auid[id] == "4294967295" || auid[id] == "-1" || auid[id] == "unset") ? runas : name(auid[id])
                ty = (tty[id] == "") ? "?" : tty[id]; cw = (cwd[id] == "") ? "?" : cwd[id]; ex = exe[id]
                n++
                print t " " who (who != runas ? "(as " runas ")" : "") " " ty " " cw "  " argv[id] >> CMDS
                classify(t, "commands", who, runas, argv[id], ty)
                # Where it runs FROM (a web-user command is already HIGH).
                if (isin(WEBU, who) || isin(WEBU, runas)) continue
                org = ""
                if (cw ~ /^(\/tmp|\/var\/tmp|\/dev\/shm|\/run\/shm)(\/|$)/) org = "folder " cw
                if (ex ~ /\(deleted\)$/) org = "a deleted program (" ex ")"
                else if (ex ~ /^(\/tmp|\/var\/tmp|\/dev\/shm|\/run\/shm)\//) org = "program " ex
                for (k = 1; k <= nw; k++) {
                    w = wr[k]; if (R != "" && index(w, R) == 1) w = substr(w, length(R) + 1)
                    if (index(ex, w "/") == 1) org = "program under a web root (" ex ")"
                    else if (org == "" && (cw == w || index(cw, w "/") == 1)) org = "a web root (" cw ")"
                }
                if (org != "") emit(t, "HIGH", "commands", (who != runas ? who " as " runas : who), "process running from " org ": " argv[id])
            }
            print n + 0
        }' "$STATE/.audit" >"$STATE/.n"
    N_CMD=$(cat "$STATE/.n" 2>/dev/null); case "$N_CMD" in ''|*[!0-9]*) N_CMD=0 ;; esac
}

# ---- Section: web access log (what a web shell is being told to do) ---------
read_web() {
    [ -n "$ACCESSLOGS" ] || return 0
    : >"$STATE/.webchk"; N_WEB=0
    for _wl in $ACCESSLOGS; do
        [ -r "$_wl" ] || continue
        _wk=web_$(printf '%s' "$_wl" | tr -c 'A-Za-z0-9' '_')
        new_lines "$_wk" "$_wl" >"$STATE/.web1"
        [ -s "$STATE/.web1" ] || continue
        # Common/combined format: IP - - [TIME] "METHOD PATH PROTO" STATUS ... "UA"
        # A request that got an answer (2xx/3xx) is alerted on its own; ones
        # that failed (a scanner guessing) are counted per address.
        awk "$AWK_CLS"'
            function hexval(c) { return index("0123456789abcdef", tolower(c)) - 1 }    # awk: posix-ok
            function urldec(s,   o, i, c) {    # awk: posix-ok
                if (index(s, "%") == 0) return s
                o = ""
                for (i = 1; i <= length(s); i++) {
                    c = substr(s, i, 1)
                    if (c == "%" && substr(s, i + 1, 2) ~ /^[0-9A-Fa-f][0-9A-Fa-f]$/) { c = sprintf("%c", hexval(substr(s, i + 1, 1)) * 16 + hexval(substr(s, i + 2, 1))); i += 2; if (c ~ /[\t\n\r]/) c = " " }
                    o = o c
                }
                return o
            }
            BEGIN { loadusers(); S = ENVIRON["LX_STATE"]; WEB = S "/web.log"; CHK = S "/.webchk"; NAMES = ENVIRON["LX_SHELLNAMES"]; INJ = ENVIRON["LX_INJECT"] }
            {
                ip = $1; req = ""; rest = ""
                if (match($0, /"[^"]*"/)) { req = substr($0, RSTART + 1, RLENGTH - 2); rest = substr($0, RSTART + RLENGTH) }
                nn = split(req, rq, " "); if (nn < 2) next
                m = rq[1]; p = rq[2]
                st = ""; if (match(rest, /^ [0-9][0-9][0-9]/)) st = substr(rest, 2, 3)
                t = ""; if (match($0, /\[[^]]*\]/)) t = substr($0, RSTART + 1, RLENGTH - 2)
                ua = ""; s = rest; while (match(s, /"[^"]*"/)) { ua = substr(s, RSTART + 1, RLENGTH - 2); s = substr(s, RSTART + RLENGTH) }
                n++
                print t " " ip " \"" m " " p "\" " (st == "" ? "?" : st) " \"" ua "\"" >> WEB
                pp = p; sub(/\?.*/, "", pp); base = pp; sub(/.*\//, "", base)
                dp = urldec(p); lb = tolower(base)
                bad = ""
                if (lb ~ NAMES) bad = "request to a known web-shell filename (" base ")"
                else if (tolower(dp) ~ INJ) bad = "command-injection / web-shell request: " m " " substr(dp, 1, 200)
                answered = (st == "" || st ~ /^[23]/)
                if (bad != "") {
                    if (!answered) { probes[ip]++; if (!(ip in pex)) pex[ip] = pp; next }
                    if (++shown[ip] <= 10) emit(t, "HIGH", "web", ip " " m " " pp, bad)
                    else more[ip]++
                    next
                }
                # A script that answered: the shell checks if it is newly dropped.
                if (answered && lb ~ /\.(php|phtml|php[0-9]|asp|aspx|jsp|jspx|cgi|pl|py|sh)$/ && !((ip, pp) in asked) && nask < 300) {
                    asked[ip, pp] = 1; nask++
                    print t "\t" ip "\t" m "\t" pp >> CHK
                }
            }
            END {
                for (ip in more) emit("", "HIGH", "web", ip, more[ip] " more web-shell / injection requests from this address (see web.log)")
                for (ip in probes) emit("", (probes[ip] >= 20) ? "HIGH" : "MED", "web", ip, probes[ip] " request(s) probing for web shells or injection, all refused (e.g. " pex[ip] ")")
                print n + 0
            }' "$STATE/.web1" >"$STATE/.n"
        _n=$(cat "$STATE/.n" 2>/dev/null); case "$_n" in ''|*[!0-9]*) _n=0 ;; esac
        N_WEB=$((N_WEB + _n))
    done
    # Requests to scripts that answered: is the file newer than our start?
    [ -s "$STATE/.webchk" ] || return 0
    while IFS="$(printf '\t')" read -r _t _ip _m _pp; do
        _rel=${_pp#/}
        case "$_rel" in *..*) continue ;; esac
        for _wr in $WEBROOTS; do
            _f="$_wr/$_rel"
            if [ -f "$_f" ] && [ -n "$(find "$_f" -newer "$STATE/.started" 2>/dev/null)" ]; then
                printf '%s\tHIGH\tweb\t%s\t%s\n' "$_t" "$_ip $_m $_pp" "request to a script added/changed since watching began (dropped web shell?): $_rel" >>"$STATE/.raw"
                break
            fi
        done
    done <"$STATE/.webchk"
}

# ---- Alerts: drop repeats, show the rest ------------------------------------
# The same alert (same severity, section, item and text) is shown once, then
# kept quiet for --repeat-after seconds: a scoring engine logging in every
# minute, or a mail server calling sendmail, should not fill the console.
# Every event is still in its own log file.
AL_H=0; AL_M=0; AL_L=0; AL_R=0
show_alerts() {
    [ -s "$STATE/.raw" ] || return 0
    [ -f "$STATE/.seen" ] || : >"$STATE/.seen"
    _now=$(cc_now); _nowt=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    awk -F'\t' -v now="$_now" -v nowt="$_nowt" -v rep="$REPEAT" -v seenf="$STATE/.seen" '
        BEGIN { while ((getline l < seenf) > 0) { n = split(l, a, "\t"); if (n >= 2 && now - a[1] < 86400) last[a[2]] = a[1] } }
        {
            # Per-address totals ("37 failed logins from ...") repeat with a
            # new number every pass: compare them without the numbers.
            d = $5; if ($4 ~ /^[0-9a-fA-F:.]+$/) gsub(/[0-9]+/, "#", d)
            key = $2 "|" $3 "|" $4 "|" d
            if (rep > 0 && (key in last) && now - last[key] < rep) { quiet++; next }
            if (key in done) { quiet++; next }
            done[key] = 1; last[key] = now
            printf "%s\t%s %-4s %-8s %-22s - %s\n", $2, ($1 == "" ? nowt : $1), $2, $3, $4, $5
        }
        END {
            for (k in last) print last[k] "\t" k > (seenf ".new")
            print "QUIET\t" quiet + 0
        }' "$STATE/.raw" >"$STATE/.show"
    [ -f "$STATE/.seen.new" ] && mv "$STATE/.seen.new" "$STATE/.seen"
    rollover "$ALERTS"
    while IFS="$(printf '\t')" read -r _sev _line; do
        case "$_sev" in
            QUIET) AL_R=$_line; continue ;;
            HIGH)  AL_H=$((AL_H + 1)); show "${C_RED:-}" "  $_line" ;;
            MED)   AL_M=$((AL_M + 1)); show "${C_YEL:-}" "  $_line" ;;
            LOW)   AL_L=$((AL_L + 1)); [ "$SHOWLOW" = 1 ] && show "${C_GRY:-}" "  $_line" ;;
            *)     continue ;;
        esac
        printf '%s\n' "$_line" >>"$ALERTS"
        printf '%s\n' "$_line" >>"$STATE/.newalerts"
    done <"$STATE/.show"
}

# ---- One pass ---------------------------------------------------------------
N_LOGIN=0; N_CMD=0; N_WEB=0
one_pass() {
    N_LOGIN=0; N_CMD=0; N_WEB=0; AL_H=0; AL_M=0; AL_L=0; AL_R=0
    : >"$STATE/.newalerts"; : >"$STATE/.raw"
    for _lf in logins.log priv.log commands.log web.log; do rollover "$STATE/$_lf"; done
    read_auth
    read_audit
    read_web
    show_alerts
    _t=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    _rp=""; [ "$AL_R" -gt 0 ] && _rp=" ($AL_R repeat(s) not shown)"
    if [ "$AL_H" -gt 0 ] || [ "$AL_M" -gt 0 ] || [ "$AL_L" -gt 0 ]; then
        printf '%s  %d login event(s), %d command(s), %d web request(s); alerts: %d HIGH, %d MED, %d LOW%s\n' "$_t" "$N_LOGIN" "$N_CMD" "$N_WEB" "$AL_H" "$AL_M" "$AL_L" "$_rp"
    else
        printf '%s  %d login event(s), %d command(s), %d web request(s); nothing to flag%s\n' "$_t" "$N_LOGIN" "$N_CMD" "$N_WEB" "$_rp"
    fi
    if [ -s "$STATE/.newalerts" ] && [ -n "$ALERTCMD" ]; then
        sh -c "$ALERTCMD" <"$STATE/.newalerts" >>"$CC_LOG" 2>&1 || cc_warn "--alert-cmd failed (exit $?): alerts are still in $ALERTS"
    fi
    # Tamper check: the logs we read should not shrink or vanish.
    for _tf in "$AUTHLOG" "$AUDITLOG"; do
        [ -n "$_tf" ] || continue
        _tk="$STATE/.cur/had_$(printf '%s' "$_tf" | tr -c 'A-Za-z0-9' '_')"
        if [ -s "$_tf" ]; then : >"$_tk"
        elif [ -f "$_tk" ]; then
            rm -f "$_tk"
            show "${C_RED:-}" "  $_t HIGH tamper   $_tf - the log is gone or empty (wiped, or rotated just now)"
            printf '%s HIGH tamper   %s - the log is gone or empty (wiped, or rotated just now)\n' "$_t" "$_tf" >>"$ALERTS"
        fi
    done
}

# ---- Run --------------------------------------------------------------------
show "${C_CYN:-}" "LX-41 session & command logging | host $CC_HOST | state $STATE"
if [ "$AUDIT_ON" != 1 ]; then
    if [ "$AUDIT_RULE" = 1 ]; then
        cc_info "auditd rule is loaded but $AUDITLOG is empty so far"
    else
        _arch=b64; case "$(uname -m 2>/dev/null)" in i?86|armv*) _arch=b32 ;; esac
        show "${C_YEL:-}" "[!] auditd is not logging commands: only sudo/su commands are captured."
        show "${C_YEL:-}" "    Turn on full command logging with:  sudo sh $0 --setup-auditd"
        show "${C_YEL:-}" "    (or by hand: auditctl -a always,exit -F arch=$_arch -S execve -k bt_cmd)"
    fi
else
    show "${C_GRN:-}" "[ok] auditd is logging commands ($AUDITLOG)"
fi
[ "$FROMSTART" = 1 ] || cc_info "watching from now (use --from-start to include existing history)"
if [ -n "$ACCESSLOGS" ]; then show "${C_GRN:-}" "[ok] watching web access log(s) for web-shell activity"; else cc_info "no web access log found; a command run by a web-server account is still caught as a web shell"; fi

_checks=0
while :; do
    _checks=$((_checks + 1))
    one_pass
    [ "$LOOP" -gt 0 ] || break
    [ "$COUNT" -gt 0 ] && [ "$_checks" -ge "$COUNT" ] && break
    sleep "$LOOP"
done
cc_info "logs: $STATE (logins.log, priv.log, commands.log, alerts.log)"
cc_finish
