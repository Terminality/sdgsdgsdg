#!/bin/sh
# =============================================================================
# ID:       LX-40
# NAME:     Linux change watch
# ROLE:     Linux  (wave 2, first 15 minutes - start it once the box is hardened)
# KIND:     readonly - changes nothing on the host
# VERSION:  2.1.0
#
# PURPOSE
#   Takes a baseline of the places red teams use to get back in, then checks
#   again - once, or every N seconds - and raises one alert per change, in
#   plain words, worst first:
#     users        accounts added, deleted, given UID 0 or a login shell
#     passwords    a password changed, removed (empty) or an account unlocked
#                  (only a short fingerprint is kept, never the hash)
#     groups       who was added to sudo, wheel, docker ... (admin groups HIGH)
#     files        sudoers, PAM, ld.so.preload, login scripts, hosts, DNS,
#                  sshd_config, sysctl
#     cron         crontabs, cron folders, at/anacron spools, systemd timers
#     units        systemd unit files, init.d scripts, rc.local
#     running      running services: a scored one stopping, or auditd /
#                  rsyslog / splunk being stopped to hide something
#     keys         every account's authorized_keys files
#     ports        new listening ports, with the program, its user and
#                  command line (a shell or nc listening is HIGH)
#     connections  NEW: new outgoing connections (reverse shells, beacons)
#                  and new addresses connected to SSH/RDP/database ports
#     suid         new SUID/SGID programs
#     web          files added, removed or changed in the web roots
#     modules      kernel modules loaded
#   Each change is reported once.  changes-since-baseline.txt in the state
#   folder always holds the full list of what differs from the baseline.
#
#   QUESTIONS (Enter takes the [default]; a flag answers each one ahead):
#     use the existing baseline, or take a new one     --baseline / --use-baseline
#     seconds between checks (0 = once)                --loop N / --once
#     watch connections too                            --conns / --no-conns
#     your team's addresses (never alerted)            --team "ADDR NET ..."
#     extra web folders                                --webroot DIR
#     scan the disk for new SUID programs              --suid / --no-suid
#   --batch, or no terminal: defaults, and ONE check (no loop unless --loop).
#
# USAGE
#   sudo sh LX-40-change-watch.sh                        asks, then watches
#   sudo sh LX-40-change-watch.sh --batch                one check, defaults
#   sudo sh LX-40-change-watch.sh --loop 60 --team 10.0.0.0/24
#   nohup sudo sh LX-40-change-watch.sh --batch --loop 60 --alert-cmd "ssh admin@10.0.0.5 'cat >>/srv/alerts/web01.log'" &
#   sudo sh LX-40-change-watch.sh --accept               your own changes become the baseline
#
# OPTIONS
#   --baseline         take a new baseline (replaces the old one)
#   --accept           same as --baseline: use after reviewing your own changes
#   --use-baseline     keep the existing baseline (no question)
#   --loop N           check every N seconds (10 or more) until Ctrl-C
#   --once             check once and stop
#   --count N          with --loop: stop after N checks
#   --conns / --no-conns   watch connections (default yes)
#   --team "A B"       team addresses or IPv4 networks (10.0.0.5 10.0.0.0/24);
#                      connections to or from them are never alerted (repeat)
#   --webroot DIR      also watch DIR (repeat); the usual web roots always are
#   --suid / --no-suid scan the whole disk for SUID/SGID programs (default yes)
#   --suid-every N     with --loop: that scan only on every Nth check (default 10)
#   --alert-cmd CMD    run CMD (sh -c) after each check that found changes;
#                      the new alert lines arrive on its stdin
#   --state DIR        where the baseline lives (default <out>/watch-<host>)
#   --root DIR         treat DIR as / for the file sections (tests)
#   --no-color         no colours
#   --help             this text plus the common options
#
# OUTPUTS
#   <out>/changewatch-N/   this run:
#     output.txt                everything shown on screen, no colour
#     alerts.txt                this run's alerts as a table (csv/alerts.csv)
#     connections.txt           new connections seen (csv/connections.csv)
#     summary.txt               counts by severity and section
#     run.txt                   id, host, start time
#   <out>/watch-<host>/    the state, kept between runs:
#     baseline/, last/          the snapshots (plain text, no secrets)
#     alerts.log                every alert ever, one line each:
#                               time SEVERITY section change item - detail
#     changes-since-baseline.txt  what differs from the baseline right now
#     conns-seen                connections already reported
#     settings                  your answers, used as the next run's defaults
#
# WHAT IT CHANGES
#   Nothing on the host.  It reads files and runs read-only commands.
#
# DEPENDS ON
#   awk, find, ls, cksum; sha256sum (or shasum / sha256 / openssl); ss or
#   netstat; systemctl for timers and running services (optional).
#   Stand-ins for tests: BT_SS (ss), BT_SYSTEMCTL, BT_PROC (/proc).
#
# TESTED ON
#   Ubuntu 24.04 under dash, bash, busybox sh, ksh93, mksh and yash, with
#   gawk, mawk and busybox awk, on a fake root with stand-in ss/systemctl/proc;
#   live: a planted account, cron job, SSH key, listener, web shell and a
#   reverse shell to an outside address were each reported once.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - It sees changes, not intent: your own hardening shows up too.  After
#     changing things on purpose, run --accept (or answer No to "use the
#     baseline").
#   - Connections are sampled at each check: one that opens and closes
#     between two checks is not seen.  A reverse shell stays open, so it is.
#   - Web files are compared by size and time, not content (to stay fast).
#   - Without root, other accounts' passwords, keys and the program behind
#     a connection cannot be read.
#   - A red team with root can stop or fool this script.  Send alerts off
#     the box with --alert-cmd.  It does not hide itself.
#
# DEBUGGING
#   --debug shows how many items each section found.  The snapshots in
#   baseline/ and last/ are plain text: diff them by hand.
# =============================================================================

# >>> BT-LIB  (lib/lib.sh 0.4.0 pasted in by tools/build.sh - edit lib/lib.sh, not this copy)
# =============================================================================
# ID:       LB-01
# NAME:     Shell library (lib.sh)
# ROLE:     Automation  (wave 0, foundation)
# VERSION:  0.4.0
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
CC_LIB_VERSION="0.4.0"

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
LX-40 Linux change watch - alert on new accounts, keys, cron jobs, ports, connections, files
  sudo sh LX-40-change-watch.sh               asks, then watches
  sudo sh LX-40-change-watch.sh --batch       one check with the defaults

  --baseline / --accept   take a new baseline (after your own changes)
  --use-baseline     keep the existing baseline
  --loop N           check every N seconds until Ctrl-C (10 or more)
  --once             check once and stop
  --count N          with --loop: stop after N checks
  --conns / --no-conns   watch new connections (default yes)
  --team "A B"       team addresses / IPv4 networks, never alerted (repeatable)
  --webroot DIR      also watch DIR (repeatable)
  --suid / --no-suid scan the disk for new SUID/SGID programs (default yes)
  --suid-every N     with --loop: that scan on every Nth check only (default 10)
  --alert-cmd CMD    run CMD with new alerts on stdin (send them off the box)
  --state DIR        baseline folder (default <out>/watch-<host>)
  --root DIR         treat DIR as / (tests)
  --no-color         no colours
  --help             show this text

USAGE
    cc_usage_common
}

NL='
'
BASEMODE=""; LOOP=""; COUNT=0; WEBARGS=""; WEBSET=0; SUIDOPT=""; SUIDEVERY=10; ALERTCMD=""; STATE=""; R=""
CONNS=""; TEAM=""; TEAMSET=0; COLOR=1
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --baseline|--accept) BASEMODE=new; shift ;;
        --use-baseline) BASEMODE=keep; shift ;;
        --loop)      [ $# -ge 2 ] || cc_die 2 "--loop needs seconds"; LOOP=$2; shift 2 ;;
        --once)      LOOP=0; shift ;;
        --count)     [ $# -ge 2 ] || cc_die 2 "--count needs a number"; COUNT=$2; shift 2 ;;
        --conns)     CONNS=1; shift ;;
        --no-conns)  CONNS=0; shift ;;
        --team)      [ $# -ge 2 ] || cc_die 2 "--team needs addresses"; TEAM="$TEAM $(printf '%s' "$2" | tr ',' ' ')"; TEAMSET=1; shift 2 ;;
        --webroot)   [ $# -ge 2 ] || cc_die 2 "--webroot needs a folder"; [ -d "$2" ] || cc_die 2 "--webroot: not a folder: $2"
                     WEBARGS="$WEBARGS$(cc_abspath "$2")$NL"; WEBSET=1; shift 2 ;;
        --suid)      SUIDOPT=1; shift ;;
        --no-suid)   SUIDOPT=0; shift ;;
        --suid-every) [ $# -ge 2 ] || cc_die 2 "--suid-every needs a number"; SUIDEVERY=$2; shift 2 ;;
        --alert-cmd) [ $# -ge 2 ] || cc_die 2 "--alert-cmd needs a command"; ALERTCMD=$2; shift 2 ;;
        --state)     [ $# -ge 2 ] || cc_die 2 "--state needs a folder"; STATE=$2; shift 2 ;;
        --root)      [ $# -ge 2 ] || cc_die 2 "--root needs a folder"; [ -d "$2" ] || cc_die 2 "--root: not a folder: $2"
                     R=$(cd "$2" && pwd); [ "$R" = / ] && R=""; shift 2 ;;
        --no-color|--no-colour) COLOR=0; shift ;;
        --help|-h)   usage; exit 0 ;;
        *)           cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
# ok_loop VALUE -> exits 2 unless VALUE is 0 or a whole number of 10 or more.
ok_loop() {
    case "$1" in ''|*[!0-9]*) cc_die 2 "--loop needs a whole number of seconds" ;; esac
    [ "$1" -gt 0 ] && [ "$1" -lt 10 ] && cc_die 2 "--loop must be at least 10 seconds (or 0 for one check)"
    return 0
}
[ -n "$LOOP" ] && ok_loop "$LOOP"
case "$COUNT" in ''|*[!0-9]*) cc_die 2 "--count needs a whole number" ;; esac
case "$SUIDEVERY" in ''|*[!0-9]*|0) cc_die 2 "--suid-every needs a whole number, 1 or more" ;; esac
# valid_net ADDR -> an IPv4 address or network, or an IPv6 address/prefix.
valid_net() {
    printf '%s' "$1" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]|[12][0-9]|3[0-2]))?$|^[0-9a-fA-F:]+:[0-9a-fA-F:]*(/[0-9]{1,3})?$'
}
for _a in $TEAM; do valid_net "$_a" || cc_die 2 "--team: not an address or network: $_a"; done

cc_init "LX-40" "Linux change watch" readonly
cc_detect_os
# shellcheck disable=SC2034  # read by cc_color_init
[ "$COLOR" = 1 ] || CC_NOCOLOR=1
cc_color_init
cc_use_numbered_dir changewatch
CC_CSV_DIR="$CC_RUN_DIR/csv"
mkdir -p "$CC_CSV_DIR" || cc_die 3 "cannot create $CC_CSV_DIR"
rmdir "$CC_RUN_DIR/raw" 2>/dev/null
OUTF="$CC_RUN_DIR/output.txt"; : >"$OUTF"
# shellcheck disable=SC2034  # CC_TEE is read by the library's log functions
CC_TEE=$OUTF
IS_ROOT=0; cc_is_root && IS_ROOT=1
[ -n "$STATE" ] || STATE="$CC_OUT/watch-$CC_HOST"
(umask 077; mkdir -p "$STATE") || cc_die 3 "cannot create $STATE"
STATE=$(cc_abspath "$STATE")
SS=${BT_SS:-$(cc_which ss)} || SS=""
SYSCTL=${BT_SYSTEMCTL:-}
[ -z "$SYSCTL" ] && [ -z "$R" ] && [ "$CC_INIT" = systemd ] && SYSCTL=$(cc_which systemctl)
PROCROOT=${BT_PROC:-}
[ -z "$PROCROOT" ] && [ -z "$R" ] && PROCROOT=/proc
ALERTS="$STATE/alerts.log"
W="$CC_RUN_DIR/.work"; mkdir -p "$W"

header() { cc_show "" ""; cc_show "$C_CYN" "==========[ $1 ]=========="; }
# setting KEY -> the value saved by the last run (empty if none).
setting() { [ -f "$STATE/settings" ] && sed -n "s/^$1=//p" "$STATE/settings" | tail -n 1; }

cc_show "$C_CYN" "LX-40 Change watch | host $CC_HOST | results in $CC_RUN_DIR"
cc_show "$C_CYN" "Baseline and history in $STATE"
cc_show "" "Legend: ${C_RED}[!] HIGH${C_OFF} almost certainly the red team   ${C_YEL}[*] MED${C_OFF} check it   ${C_GRY}[-] LOW${C_OFF} worth knowing   ${C_GRN}[ok]${C_OFF} no changes"
[ -n "$R" ] && cc_show "$C_GRY" "Looking at $R as if it were / (tests)"
[ "$IS_ROOT" = 1 ] || [ -n "$R" ] || cc_show "$C_YEL" "[!] Not root: passwords, other accounts' keys and the programs behind connections cannot be seen. Run with sudo."

# ---- Questions (sqlmap style) ---------------------------------------------------
header "1/3  setup: what to watch"
HAVEBASE=0; [ -f "$STATE/baseline/users" ] && HAVEBASE=1
BASETIME=$(cat "$STATE/baseline/.taken" 2>/dev/null)
if [ "$HAVEBASE" = 0 ]; then
    [ "$BASEMODE" = keep ] && cc_show "$C_YEL" "[!] --use-baseline: there is no baseline yet in $STATE"
    BASEMODE=new
    cc_show "" "  No baseline yet: one is taken now, so the first check compares against this moment."
elif [ -z "$BASEMODE" ]; then
    if cc_ask "Use the baseline from ${BASETIME:-earlier}?" Y "yes, compare against it" "no, take a new one now (after your own hardening)"; then BASEMODE=keep; else BASEMODE=new; fi
fi
if [ -z "$LOOP" ]; then
    if _cc_can_ask; then
        cc_ask_text "How often should it check?" 60 "seconds between checks, like 60; 0 = check once and stop"
        LOOP=$CC_ANSWER; ok_loop "$LOOP"
    else
        LOOP=0
    fi
fi
_d=$(setting conns)
if [ -z "$CONNS" ]; then
    if cc_ask "Watch connections too?" "$([ "$_d" = 0 ] && echo N || echo Y)" "yes, watch them (catches reverse shells and who logs in)" "no, skip connections"; then CONNS=1; else CONNS=0; fi
fi
if [ "$CONNS" = 1 ] && [ "$TEAMSET" = 0 ]; then
    cc_ask_text "Your team's addresses (their connections are never alerted)?" "$(setting team)" "addresses or networks separated by spaces, like 10.0.0.5 10.0.0.0/24"
    TEAM=$(printf '%s' "$CC_ANSWER" | tr ',' ' ')
    for _a in $TEAM; do valid_net "$_a" || cc_die 2 "not an address or network: $_a"; done
fi
TEAM=$(printf '%s' "$TEAM" | sed 's/^ *//; s/ *$//')
# Web roots: the usual ones, the ones the baseline was taken with, and
# anything new.  All without the --root prefix.
_saved_web=""; [ "$BASEMODE" = keep ] && _saved_web=$(cat "$STATE/baseline/.webroots" 2>/dev/null)
if [ "$WEBSET" = 0 ]; then
    cc_ask_text "Other web folders to watch, besides /var/www /srv/www /usr/share/nginx/html ...?" "" "folders separated by spaces, like /opt/app/public"
    for _w in $(printf '%s' "$CC_ANSWER" | tr ',' ' '); do
        [ -d "$R$_w" ] || [ -d "$_w" ] || { cc_show "$C_YEL" "  [!] not a folder, skipped: $_w"; continue; }
        if [ -d "$_w" ]; then WEBARGS="$WEBARGS$(cc_abspath "$_w")$NL"; else WEBARGS="$WEBARGS$R$_w$NL"; fi
    done
fi
{
    for _d in /var/www /srv/www /srv/http /usr/share/nginx/html /usr/local/www /opt/lampp/htdocs; do printf '%s\n' "$_d"; done
    printf '%s\n' "$_saved_web"
    printf '%s' "$WEBARGS" | while IFS= read -r _w; do
        [ -n "$_w" ] || continue
        if [ -n "$R" ]; then case "$_w" in "$R"/*) _w=${_w#"$R"} ;; esac; fi
        printf '%s\n' "$_w"
    done
} | sed 's|/*$||' | grep . | sort -u | awk '{ for (k in keep) if (index($0, k "/") == 1) next; keep[$0] = 1; print }' >"$W/webroots"
_d=$(setting suid)
if [ -z "$SUIDOPT" ]; then
    if cc_ask "Look for new SUID programs on the whole disk?" "$([ "$_d" = 0 ] && echo N || echo Y)" "yes, scan for them (slower; in a loop every ${SUIDEVERY}th check)" "no, skip it"; then SUIDOPT=1; else SUIDOPT=0; fi
fi
NOSUID=$((1 - SUIDOPT))
printf 'conns=%s\nteam=%s\nsuid=%s\n' "$CONNS" "$TEAM" "$SUIDOPT" >"$STATE/settings"

cc_show "" ""
cc_show "" "  Baseline:     $([ "$BASEMODE" = new ] && echo 'take a new one now' || echo "keep the one from ${BASETIME:-earlier}")"
cc_show "" "  Checks:       $([ "$LOOP" -gt 0 ] && echo "every $LOOP seconds$([ "$COUNT" -gt 0 ] && echo ", $COUNT times") (Ctrl-C stops and prints the summary)" || echo 'once')"
cc_show "" "  Connections:  $([ "$CONNS" = 1 ] && echo "watched$([ -n "$TEAM" ] && echo "; team, never alerted: $TEAM")" || echo 'not watched')"
cc_show "" "  Web folders:  $(tr '\n' ' ' <"$W/webroots")"
cc_show "" "  SUID scan:    $([ "$SUIDOPT" = 1 ] && echo yes || echo no)"
[ -n "$ALERTCMD" ] && cc_show "" "  Off the box:  each check's alerts are sent to: $ALERTCMD"

# ---- Process details ----------------------------------------------------------------
# proc_info PID -> PR_USER, PR_CMD (command line), PR_EXE, from /proc.
proc_info() {
    PR_USER=""; PR_CMD=""; PR_EXE=""
    [ -n "$PROCROOT" ] && [ -n "$1" ] && [ -d "$PROCROOT/$1" ] || return 0
    # shellcheck disable=SC2012  # ls: the owner of /proc/PID is the account
    PR_USER=$(ls -ld "$PROCROOT/$1" 2>/dev/null | awk '{ print $3 }')
    PR_CMD=$(tr '\000' ' ' 2>/dev/null <"$PROCROOT/$1/cmdline" | tr '|\n\r\t' '/   ' | sed 's/ *$//' | cut -c1-160)
    PR_EXE=$(readlink "$PROCROOT/$1/exe" 2>/dev/null) || PR_EXE=""
}
# shellish NAME -> true for a shell, interpreter or network tool: almost never
#   the program that should be listening or calling out on a server.
shellish() {
    case "$1" in
        sh|bash|dash|zsh|ksh|ksh93|mksh|ash|csh|tcsh|busybox|nc|ncat|netcat|nc.*|socat|telnet|python|python[0-9]*|perl|perl5*|php|php[0-9]*|php-cgi*|ruby|ruby[0-9]*|lua|lua[0-9]*|awk|gawk|mawk|openssl|sshpass) return 0 ;;
    esac
    return 1
}
# badexe PATH -> true for a program in a temp folder or one deleted while running.
badexe() { case "$1" in /tmp/*|/var/tmp/*|/dev/shm/*|/run/shm/*|*" (deleted)"|*/.*/*) return 0 ;; esac; return 1; }
webuser() { case "$1" in www-data|apache|apache2|nginx|httpd|lighttpd|nobody|tomcat*|wwwrun|http) return 0 ;; esac; return 1; }
BACKDOOR_PORTS="1337 4444 4445 5555 6666 6667 9001 12345 31337 54321 2375"
backdoor_port() { case " $BACKDOOR_PORTS " in *" $1 "*) return 0 ;; esac; return 1; }

# ---- Snapshot -------------------------------------------------------------------
# hashlist PATH... -> "path|first 16 hex of sha256" for every regular file
#   under the paths.  Paths are written without the --root prefix.
hashlist() {
    _hl_n=0
    for _p in "$@"; do [ -e "$_p" ] && _hl_n=1; done
    [ "$_hl_n" = 1 ] || return 0
    if cc_have sha256sum; then
        find "$@" -xdev -type f -exec sha256sum {} + 2>/dev/null | awk -v r="$R" '{ h = $1; $1 = ""; sub(/^ +/, ""); p = $0; if (r != "" && index(p, r) == 1) p = substr(p, length(r) + 1); print p "|" substr(h, 1, 16) }'
    else
        find "$@" -xdev -type f 2>/dev/null | while IFS= read -r _f; do
            _h=$(cc_sha256 "$_f"); printf '%s|%s\n' "${_f#"$R"}" "$(printf '%s' "$_h" | cut -c1-16)"
        done
    fi
}

# snap DIR -> one sorted "key|value" file per section in DIR.
snap() {
    _sd=$1; rm -rf "$_sd"; mkdir -p "$_sd"
    # users: name -> uid:gid:home:shell
    awk -F: '{ print $1 "|" $3 ":" $4 ":" $6 ":" $7 }' "$R/etc/passwd" 2>/dev/null | sort >"$_sd/users"
    # passwords: EMPTY, LOCKED, or a 12-digit fingerprint of the shadow field
    # (a checksum of the hash), so a change is visible but nothing usable is kept.
    if [ -r "$R/etc/shadow" ]; then
        awk -F: '{ print $1 "\t" $2 }' "$R/etc/shadow" | while IFS="$(printf '\t')" read -r _u _f; do
            case "$_f" in
                '') printf '%s|EMPTY\n' "$_u" ;;
                '!'*|'*'*) printf '%s|LOCKED\n' "$_u" ;;
                *) printf '%s|%s\n' "$_u" "$(printf '%s' "$_f" | cksum | awk '{ printf "%012d", $1 % 1000000000000 }')" ;;
            esac
        done | sort >"$_sd/passwords"
    fi
    # groups: name -> gid:members
    awk -F: '{ print $1 "|" $3 ":" $4 }' "$R/etc/group" 2>/dev/null | sort >"$_sd/groups"
    # files: configuration that changes how logins and programs behave
    hashlist "$R/etc/sudoers" "$R/etc/sudoers.d" "$R/etc/pam.d" "$R/etc/security" "$R/etc/ld.so.preload" \
             "$R/etc/ld.so.conf" "$R/etc/ld.so.conf.d" "$R/etc/profile" "$R/etc/profile.d" "$R/etc/bash.bashrc" \
             "$R/etc/bashrc" "$R/etc/environment" "$R/etc/hosts" "$R/etc/resolv.conf" "$R/etc/nsswitch.conf" \
             "$R/etc/ssh/sshd_config" "$R/etc/ssh/sshd_config.d" "$R/etc/sysctl.conf" "$R/etc/sysctl.d" \
             "$R/root/.bashrc" "$R/root/.profile" "$R/root/.bash_profile" \
             "$R/etc/doas.conf" "$R/etc/doas.d" "$R/root/.ashrc" "$R/etc/apk/repositories" "$R/etc/apk/keys" | sort >"$_sd/files"
    # cron: every cron and at file, plus systemd timers by name
    { hashlist "$R/etc/crontab" "$R/etc/cron.d" "$R/etc/cron.hourly" "$R/etc/cron.daily" "$R/etc/cron.weekly" \
               "$R/etc/cron.monthly" "$R/var/spool/cron" "$R/var/spool/at" "$R/var/spool/anacron" "$R/etc/anacrontab" \
               "$R/etc/crontabs" "$R/etc/periodic"
      if [ -n "$SYSCTL" ]; then
          "$SYSCTL" list-timers --all --no-legend --no-pager 2>/dev/null | awk '{ for (i = 1; i <= NF; i++) if ($i ~ /\.timer$/) print "timer " $i "|" }'
      fi; } | sort -u >"$_sd/cron"
    # units: services that start at boot
    hashlist "$R/etc/systemd/system" "$R/lib/systemd/system" "$R/usr/lib/systemd/system" "$R/etc/init.d" \
             "$R/etc/rc.local" "$R/etc/rc.d" "$R/etc/local.d" "$R/etc/conf.d" | sort >"$_sd/units"
    # OpenRC (Alpine): which services start in which runlevel (the links in /etc/runlevels)
    for _rl in "$R"/etc/runlevels/*/; do
        [ -d "$_rl" ] || continue
        for _l in "$_rl"*; do [ -e "$_l" ] || [ -L "$_l" ] || continue; printf '%s|runlevel %s\n' "${_l#"$R"}" "$(basename "$_rl")"; done
    done | sort >>"$_sd/units"
    sort -o "$_sd/units" "$_sd/units"
    # running: services running now (systemd, or OpenRC's rc-status)
    if [ -z "$SYSCTL" ] && [ -z "$R" ] && [ "$CC_INIT" = openrc ] && cc_have rc-status; then
        rc-status -s 2>/dev/null | awk '/\[ *started/ { print $1 "|" }' | sort -u >"$_sd/running"
    fi
    if [ -n "$SYSCTL" ]; then
        "$SYSCTL" list-units --type=service --state=running --no-legend --no-pager 2>/dev/null |
            awk '{ for (i = 1; i <= NF; i++) if ($i ~ /\.service$/) { print $i "|"; break } }' | sort -u >"$_sd/running"
    fi
    # keys: every authorized_keys file of every account
    awk -F: '$6 != "" { print $6 }' "$R/etc/passwd" 2>/dev/null | sort -u | while IFS= read -r _h; do
        for _k in "$R$_h/.ssh/authorized_keys" "$R$_h/.ssh/authorized_keys2"; do [ -f "$_k" ] && printf '%s\n' "$_k"; done
    done >"$W/keyfiles"
    : >"$_sd/keys"
    while IFS= read -r _k; do
        _n=$(grep -c '^[^#]' "$_k" 2>/dev/null)
        printf '%s|%s %s keys\n' "${_k#"$R"}" "$(hashlist "$_k" | cut -d'|' -f2)" "$_n" >>"$_sd/keys"
    done <"$W/keyfiles"
    sort -o "$_sd/keys" "$_sd/keys"
    # ports: "proto address port" -> program;  ports.pid: the same key -> pid
    : >"$_sd/ports"; : >"$_sd/ports.pid"
    if [ -n "$SS" ]; then
        "$SS" -ltnup 2>/dev/null | awk -v pf="$_sd/ports.pid" 'NR > 1 && ($1 == "tcp" || $1 == "udp") {
            a = $5; p = a; sub(/.*:/, "", p); sub(/:[^:]*$/, "", a); gsub(/[][]/, "", a); sub(/%.*/, "", a)
            pr = ""; if (match($0, /\(\("[^"]*"/)) pr = substr($0, RSTART + 3, RLENGTH - 4)
            pid = ""; if (match($0, /pid=[0-9]+/)) pid = substr($0, RSTART + 4, RLENGTH - 4)
            k = $1 " " a " " p; print k "|" pr; print k "|" pid >pf }' | sort -u >"$_sd/ports"
    elif cc_have netstat; then
        netstat -ltnup 2>/dev/null | awk -v pf="$_sd/ports.pid" '$1 ~ /^(tcp|udp)/ {
            a = $4; p = a; sub(/.*:/, "", p); sub(/:[^:]*$/, "", a)
            pr = ""; pid = ""; if ($NF ~ /^[0-9]+\//) { pid = $NF; sub(/\/.*/, "", pid); pr = $NF; sub(/^[0-9]+\//, "", pr) }
            k = substr($1, 1, 3) " " a " " p; print k "|" pr; print k "|" pid >pf }' | sort -u >"$_sd/ports"
    fi
    [ "$CONNS" = 1 ] && snap_conns "$_sd"
    # suid: SUID/SGID programs on the root file system.  The scan walks the
    # whole disk, so in a loop most checks reuse the last result (DOSUID=0).
    if [ "$NOSUID" = 0 ]; then
        if [ "$DOSUID" = 0 ] && [ -f "$STATE/last/suid" ]; then
            cp "$STATE/last/suid" "$_sd/suid"
        else
            find "$R/" -xdev -type f \( -perm -4000 -o -perm -2000 \) -exec ls -ln {} + 2>/dev/null |
                awk -v r="$R" '{ p = $NF; if (r != "" && index(p, r) == 1) p = substr(p, length(r) + 1); print p "|" $1 " " $3 }' | sort >"$_sd/suid"
        fi
    fi
    # web: every file in the web roots by size and modification time
    : >"$_sd/web"
    while IFS= read -r _w; do
        [ -d "$R$_w" ] || continue
        find "$R$_w" -xdev -type f -exec ls -ln {} + 2>/dev/null |
            awk -v r="$R" '{ p = $9; for (i = 10; i <= NF; i++) p = p " " $i; if (r != "" && index(p, r) == 1) p = substr(p, length(r) + 1); print p "|" $5 " " $6 " " $7 " " $8 }' >>"$_sd/web"
    done <"$W/webroots"
    sort -o "$_sd/web" "$_sd/web"
    cp "$W/webroots" "$_sd/.webroots"
    # modules: loaded kernel modules
    if [ -r "$R/proc/modules" ]; then awk '{ print $1 "|" }' "$R/proc/modules" | sort >"$_sd/modules"; else : >"$_sd/modules"; fi
    for _s in $SECTIONS conns; do
        [ -f "$_sd/$_s" ] && cc_debug "snapshot $_s: $(grep -c . "$_sd/$_s") items"
    done
    return 0
}

# Ports where a new connecting address is worth an alert: remote logins,
# databases and file shares.
ADMIN_PORTS="21 22 23 139 445 1433 2049 3306 3389 5432 5900 5901 5985 5986 6379 27017"
# snap_conns DIR -> DIR/conns: one line per established connection worth
#   watching, as  key|direction|address|port|local port|program|pid
#   out: this box called out (the local port is not a listening one)
#   in:  someone connected to an admin port, or to a shell-like program
snap_conns() {
    : >"$1/conns"
    _lp=$(awk -F'|' '{ split($1, k, " "); if (k[1] == "tcp") printf "%s ", k[3] }' "$1/ports")
    if [ -n "$SS" ]; then
        "$SS" -tanp 2>/dev/null | awk '
            NR == 1 && ($1 == "State" || $1 == "Netid") { next }
            {   o = ($1 == "tcp" || $1 == "udp") ? 1 : 0
                st = $(1 + o); if (st != "ESTAB" && st != "SYN-SENT") next
                pr = ""; if (match($0, /\(\("[^"]*"/)) pr = substr($0, RSTART + 3, RLENGTH - 4)
                pid = ""; if (match($0, /pid=[0-9]+/)) pid = substr($0, RSTART + 4, RLENGTH - 4)
                print $(4 + o), $(5 + o), (pr == "" ? "-" : pr), (pid == "" ? "-" : pid) }'
    elif cc_have netstat; then
        netstat -tanp 2>/dev/null | awk '$1 ~ /^tcp/ && ($6 == "ESTABLISHED" || $6 == "SYN_SENT") {
            pr = "-"; pid = "-"; if ($7 ~ /^[0-9]+\//) { pid = $7; sub(/\/.*/, "", pid); pr = $7; sub(/^[0-9]+\//, "", pr) }
            print $4, $5, pr, pid }'
    fi | awk -v lp=" $_lp " -v adm=" $ADMIN_PORTS " -v team="$TEAM" '
        function ip4(s,   a, n) { n = split(s, a, "."); if (n != 4) return -1; return ((a[1] * 256 + a[2]) * 256 + a[3]) * 256 + a[4] }  # awk: posix-ok
        function hp(s,   h, p) { p = s; sub(/.*:/, "", p); h = s; sub(/:[^:]*$/, "", h); gsub(/[][]/, "", h); sub(/%.*/, "", h); sub(/^::[fF][fF][fF][fF]:/, "", h); H = h; P = p }  # awk: posix-ok
        function inteam(ip,   i, j, t, net, bits, d, v, nv, x) {  # awk: posix-ok (no "^": busybox awk may lack math)
            for (i = 1; i <= nt; i++) {
                t = tm[i]; net = t; bits = -1
                x = index(t, "/"); if (x) { net = substr(t, 1, x - 1); bits = substr(t, x + 1) + 0 }
                if (net == ip) return 1
                v = ip4(ip); nv = ip4(net)
                if (v >= 0 && nv >= 0 && bits >= 0) { d = 1; for (j = bits; j < 32; j++) d = d * 2; if (int(v / d) == int(nv / d)) return 1 }
                else if (v < 0 && bits >= 0) { sub(/:+$/, "", net); if (net != "" && index(tolower(ip), tolower(net) ":") == 1) return 1 }
            }
            return 0
        }
        function shellish(p) { return p ~ /^(sh|bash|dash|zsh|ksh|ksh93|mksh|ash|csh|tcsh|busybox|nc|ncat|netcat|nc\..*|socat|telnet|python[0-9.]*|perl[0-9.]*|php[0-9.]*|php-cgi.*|ruby[0-9.]*|lua[0-9.]*|awk|gawk|mawk|openssl|sshpass)$/ }  # awk: posix-ok
        BEGIN { nt = split(team, tm, " ") }
        {   hp($1); la = H; lport = P; hp($2); pa = H; pport = P; pr = $3; pid = $4
            if (pa ~ /^127\./ || pa == "::1" || pa == "0.0.0.0" || pa == "*" || pa == la) next
            if (nt > 0 && inteam(pa)) next
            if (index(lp, " " lport " ")) {
                if (index(adm, " " lport " ") || shellish(pr)) print "in " pa " -> " lport "|in|" pa "|" pport "|" lport "|" pr "|" pid
            } else print "out " pa ":" pport " " pr "|out|" pa "|" pport "|" lport "|" pr "|" pid
        }' | sort -t'|' -k1,1 -u >"$1/conns"
}

# ---- Compare ----------------------------------------------------------------------
SECTIONS="users passwords groups files cron units running keys ports suid web modules"
# compare OLD NEW -> "SEVERITY|section|change|item|detail" lines for every
#   difference, with a plain-words explanation and the severity rules.
compare() {
    for _s in $SECTIONS; do
        [ -f "$1/$_s" ] && [ -f "$2/$_s" ] || continue
        # FILENAME, not NR == FNR: with an empty OLD file, NR == FNR would
        # also be true for every line of the NEW file.
        awk -F'|' -v sec="$_s" -v oldf="$1/$_s" '
            FILENAME == oldf { old[$1] = $2; next }
            { new[$1] = $2; if (!($1 in old)) out("added", $1, "", $2); else if (old[$1] != $2) out("changed", $1, old[$1], $2) }
            END { for (k in old) if (!(k in new)) out("removed", k, old[k], "") }
            function nologin(s) { return s == "" || s ~ /(nologin|false|sync|shutdown|halt)$/ }  # awk: posix-ok
            function listdiff(x, y,   a, b, n, m, i, r) {  # names in x but not in y; awk: posix-ok
                n = split(x, a, ","); m = split(y, b, ","); r = ""
                for (i = 1; i <= m; i++) seen[b[i]] = 1
                for (i = 1; i <= n; i++) if (a[i] != "" && !(a[i] in seen)) r = r (r == "" ? "" : ", ") a[i]
                for (i = 1; i <= m; i++) delete seen[b[i]]
                return r
            }
            function out(c, k, o, n,   sev, d, a, b, adm, plus, minus, why, code, pp) {  # awk, not shell: posix-ok
                sev = "MED"; d = ""
                if (sec == "users") {
                    split(n, a, ":"); split(o, b, ":")
                    if (c == "added") { sev = "HIGH"; d = "new account: uid " a[1] ", home " a[3] ", shell " a[4] (a[1] == "0" ? " - UID 0 means it IS root" : "") }
                    else if (c == "removed") d = "account deleted (was uid " b[1] ")"
                    else if (a[1] == "0" && b[1] != "0") { sev = "HIGH"; d = "now has UID 0 - a second root account (was uid " b[1] ")" }
                    else if (nologin(b[4]) && !nologin(a[4])) { sev = "HIGH"; d = "can now log in: shell " (b[4] == "" ? "(none)" : b[4]) " -> " a[4] }
                    else d = "account details changed (uid:gid:home:shell " o " -> " n ")"
                } else if (sec == "passwords") {
                    if (c != "changed") return
                    if (n == "EMPTY") { sev = "HIGH"; d = "password REMOVED - anyone can log in as this account with no password" }
                    else if (n == "LOCKED") { sev = "LOW"; d = "account locked" }
                    else if (o == "LOCKED" || o == "EMPTY") { d = "account unlocked and given a password - fine if your team did it" }
                    else d = "password changed - fine if your team did it; if not, someone has a way in"
                } else if (sec == "groups") {
                    split(n, a, ":"); split(o, b, ":")
                    adm = (k ~ /^(sudo|wheel|admin|root|adm|docker|lxd|disk|shadow|sudoers)$/)
                    if (c == "added") { sev = adm ? "HIGH" : "LOW"; d = "new group (gid " a[1] (a[2] != "" ? ", members " a[2] : "") ")" }
                    else if (c == "removed") { sev = "LOW"; d = "group deleted" }
                    else {
                        plus = listdiff(a[2], b[2]); minus = listdiff(b[2], a[2])
                        d = (plus != "" ? "added: " plus : "") (minus != "" ? (plus != "" ? "; " : "") "removed: " minus : "")
                        if (d == "") d = "gid " b[1] " -> " a[1]
                        if (adm) { sev = (plus != "") ? "HIGH" : "MED"; d = d " - members of this group are admins" } else sev = "LOW"
                    }
                } else if (sec == "files") {
                    why = "config file"
                    if (k ~ /sudoers/) why = "sudo rules (who can become root)"
                    else if (k ~ /doas/) why = "doas rules (who can become root)"
                    else if (k ~ /apk\/(repositories|keys)/) why = "where packages come from (apk)"
                    else if (k ~ /pam\.d|security\//) why = "login checks (PAM)"
                    else if (k ~ /ld\.so\.preload/) why = "code loaded into EVERY program"
                    else if (k ~ /ld\.so\.conf/) why = "where programs load libraries from"
                    else if (k ~ /(profile|bashrc|bash_profile|ashrc|environment)/) why = "runs at every login"
                    else if (k ~ /hosts$/) why = "name lookups (/etc/hosts)"
                    else if (k ~ /(resolv\.conf|nsswitch)/) why = "DNS / name lookup settings"
                    else if (k ~ /sshd_config/) why = "SSH server settings"
                    else if (k ~ /sysctl/) why = "kernel settings"
                    sev = (k ~ /(sudoers|doas|pam\.d|ld\.so\.preload|security\/|apk\/keys)/ || c == "added") ? "HIGH" : "MED"
                    d = why ": file " c
                } else if (sec == "cron") {
                    sev = (c == "removed") ? "LOW" : "HIGH"
                    d = (k ~ /^timer /) ? "systemd timer " c : "scheduled job file " c
                    if (c != "removed" && k !~ /^timer /) d = d " - look at what it runs"
                } else if (sec == "units") {
                    sev = (c == "added") ? "HIGH" : (c == "removed" ? "LOW" : "MED")
                    if (k ~ /^\/etc\/runlevels\//) d = "starts at boot (OpenRC runlevel): " c (c == "added" ? " - is this service yours?" : "")
                    else if (k ~ /^\/etc\/local\.d\//) d = "runs at boot (OpenRC local.d) " c (c == "removed" ? "" : " - look at what it runs")
                    else d = "boot service file " c (c == "removed" ? "" : (k ~ /init\.d|conf\.d/ ? " - check what it starts" : " - check its ExecStart line"))
                } else if (sec == "running") {
                    if (c == "added") { sev = "LOW"; d = "service started" }
                    else if (k ~ /^(auditd|rsyslog|syslog|syslog-ng|systemd-journald|splunk.*|SplunkForwarder|wazuh.*|ossec.*|osqueryd|falco.*|fail2ban|sysmon.*|auditbeat|filebeat|crowdsec)(\.service)?$/) { sev = "HIGH"; d = "logging or security service STOPPED - the red team may be hiding something" }
                    else d = "service stopped running - if it is scored, it is down"
                } else if (sec == "keys") {
                    sev = (c == "removed") ? "MED" : "HIGH"
                    if (c == "added") d = "new SSH key file (" n ") - lets someone log in with a key, no password"
                    else if (c == "changed") d = "SSH keys changed (" o " -> " n ")"
                    else d = "SSH key file removed"
                } else if (sec == "ports") {
                    split(k, pp, " ")
                    if (c == "added") { sev = (pp[3] ~ /^(1337|4444|4445|5555|6666|6667|9001|12345|31337|54321|2375)$/) ? "HIGH" : "MED"; d = "new program listening: " (n == "" ? "(program unknown)" : n) }
                    else if (c == "removed") d = "stopped listening (" (o == "" ? "?" : o) ") - if it is scored, it is down"
                    else { sev = (o != "") ? "HIGH" : "MED"; d = "a different program now listens here: " n " (was " o ")" }
                } else if (sec == "suid") {
                    sev = (c == "added") ? "HIGH" : (c == "removed" ? "LOW" : "MED")
                    d = (c == "added") ? "new SUID/SGID program - runs with its owner rights for anyone; a common way back to root" : "SUID/SGID program " c
                } else if (sec == "web") {
                    code = (k ~ /\.(php[0-9]?|phtml|phar|jsp|jspx|asp|aspx|cgi|pl|py|sh)$/)
                    if (c == "added") { sev = code ? "HIGH" : "MED"; d = code ? "new program file in a web root (web shell?)" : "new file in a web root" }
                    else if (c == "removed") d = "file removed from a web root (defaced or deleted?)"
                    else { sev = code ? "MED" : "LOW"; d = "file changed (size/time " o " -> " n ")" }
                } else if (sec == "modules") {
                    sev = (c == "added") ? "HIGH" : "LOW"
                    d = (c == "added") ? "kernel module loaded - rootkits load as modules (check: modinfo " k ")" : "kernel module unloaded"
                }
                print sev "|" sec "|" c "|" k "|" d
            }' "$1/$_s" "$2/$_s"
    done
}

# enrich_ports NEWDIR <alerts >alerts: a new listener gets its pid, user and
#   command line; a shell-like program or one in /tmp makes it HIGH.
enrich_ports() {
    while IFS='|' read -r _sev _sec _chg _item _det; do
        if [ "$_sec" = ports ] && [ "$_chg" != removed ]; then
            _pid=$(awk -F'|' -v k="$_item" '$1 == k { print $2; exit }' "$1/ports.pid")
            _prog=$(awk -F'|' -v k="$_item" '$1 == k { print $2; exit }' "$1/ports")
            proc_info "$_pid"
            [ -n "$_pid" ] && _det="$_det; pid $_pid${PR_USER:+, user $PR_USER}${PR_CMD:+, runs: $PR_CMD}"
            if shellish "$_prog" || badexe "$PR_EXE" || badexe "$PR_CMD"; then
                _sev=HIGH; _det="$_det - a shell, script interpreter or temp-folder program listening: a backdoor"
            fi
        fi
        printf '%s|%s|%s|%s|%s\n' "$_sev" "$_sec" "$_chg" "$_item" "$_det"
    done
}

# new_conns NEWDIR -> alert lines for connections not reported before; each
#   one is added to conns-seen and to connections.csv.
new_conns() {
    [ -f "$1/conns" ] || return 0
    awk -F'|' -v seenf="$STATE/conns-seen" 'FILENAME == seenf { s[$0] = 1; next } !($1 in s)' "$STATE/conns-seen" "$1/conns" >"$W/conns.new"
    while IFS='|' read -r _key _dir _addr _port _lport _prog _pid; do
        printf '%s\n' "$_key" >>"$STATE/conns-seen"
        [ "$_prog" = - ] && _prog=""; [ "$_pid" = - ] && _pid=""
        proc_info "$_pid"
        _who="${_prog:-unknown program}${_pid:+ (pid $_pid${PR_USER:+, user $PR_USER})}${PR_CMD:+ runs: $PR_CMD}"
        if [ "$_dir" = out ]; then
            _sev=MED; _det="new outgoing connection from $_who"
            case "$_prog" in
                apt|apt-get|http|https|dnf|yum|packagekitd|snapd|unattended-upgr*|systemd-resolve*|systemd-timesyn*|chronyd|ntpd|splunkd|fwupd*|dhclient|NetworkManager|sssd*|freshclam)
                    _sev=LOW; _det="$_det (updates/agent - usually fine)" ;;
            esac
            if shellish "$_prog" || badexe "$PR_EXE" || badexe "$PR_CMD"; then
                _sev=HIGH; _det="$_det - a shell, script interpreter or temp-folder program calling out: REVERSE SHELL?"
            elif backdoor_port "$_port"; then
                _sev=HIGH; _det="$_det - port $_port is a classic attacker port"
            elif webuser "$PR_USER"; then
                case "$_prog" in apache2|httpd|nginx|lighttpd|php-fpm*) _sev=MED; _det="$_det - the web server calling out: check it is a known backend" ;;
                    *) _sev=HIGH; _det="$_det - the web server account calling out: a web shell?" ;;
                esac
            fi
            _item="$_addr:$_port"
        else
            _det="new address connected to port $_lport (${_prog:-program unknown})"
            _sev=MED
            if shellish "$_prog" || badexe "$PR_EXE"; then _sev=HIGH; _det="$_det - someone is connected to a shell-like program: a bind shell in use?"; fi
            _item="$_addr -> port $_lport"
        fi
        printf '%s|connections|%s|%s|%s\n' "$_sev" "$_dir" "$_item" "$_det"
        cc_csv_row "$CONNCSV" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$_dir" "$_addr" "$_port" "$_lport" "$_prog" "$_pid" "$PR_USER" "$PR_CMD" "$_sev"
    done <"$W/conns.new"
}

# adopt NEWDIR -> sections the baseline does not have yet (a scan turned on
#   later, an older baseline, a new web root) become part of the baseline,
#   so they are not reported as one big "added".
adopt() {
    for _s in $SECTIONS; do
        if [ -f "$1/$_s" ] && [ ! -f "$STATE/baseline/$_s" ]; then
            cp "$1/$_s" "$STATE/baseline/$_s"; cp "$1/$_s" "$STATE/last/$_s"
            cc_show "$C_GRY" "  ($_s: added to the baseline as it is now)"
        fi
    done
    [ -f "$STATE/baseline/.webroots" ] || cp "$W/webroots" "$STATE/baseline/.webroots"
    if :; then
        awk 'FILENAME == ARGV[1] { o[$0] = 1; next } !($0 in o)' "$STATE/baseline/.webroots" "$W/webroots" >"$W/webnew"
        if [ -s "$W/webnew" ]; then
            for _b in "$STATE/baseline" "$STATE/last"; do
                awk -F'|' 'FILENAME == ARGV[1] { r[$0] = 1; next } { for (x in r) if (index($1, x "/") == 1) { print; next } }' "$W/webnew" "$1/web" >>"$_b/web"
                sort -u -o "$_b/web" "$_b/web"; cp "$W/webroots" "$_b/.webroots"
            done
            cc_show "$C_GRY" "  (new web folder(s) added to the baseline: $(tr '\n' ' ' <"$W/webnew"))"
        fi
    fi
    if [ "$CONNS" = 1 ] && [ ! -f "$STATE/conns-seen" ]; then
        cut -d'|' -f1 "$1/conns" >"$STATE/conns-seen"
        cc_show "$C_GRY" "  (connections: $(grep -c . "$STATE/conns-seen") open now are taken as normal; new ones from here on are reported)"
    fi
}

ALCSV=$(cc_csv_new alerts "time,severity,section,change,item,detail")
CONNCSV=$(cc_csv_new connections "time,direction,address,port,local_port,program,pid,user,command,severity")
N_H=0; N_M=0; N_L=0; NCHECK=0; STOP=0

# ---- Baseline ------------------------------------------------------------------------
DOSUID=1    # 1 = this snapshot scans for SUID/SGID files
header "2/3  baseline"
if [ "$BASEMODE" = new ]; then
    cc_show "" "  Taking a baseline of how the box looks now ..."
    snap "$STATE/baseline"
    date -u +%Y-%m-%dT%H:%M:%SZ >"$STATE/baseline/.taken"
    rm -rf "$STATE/last"; cp -R "$STATE/baseline" "$STATE/last"
    : >"$STATE/changes-since-baseline.txt"
    rm -f "$STATE/conns-seen"
    [ "$CONNS" = 1 ] && cut -d'|' -f1 "$STATE/baseline/conns" >"$STATE/conns-seen"
    printf '%s BASELINE taken (%s)\n' "$(cat "$STATE/baseline/.taken")" "$(for _s in $SECTIONS; do [ -f "$STATE/baseline/$_s" ] && printf '%s %s, ' "$_s" "$(grep -c . "$STATE/baseline/$_s")"; done | sed 's/, $//')" >>"$ALERTS"
    BASETIME=$(cat "$STATE/baseline/.taken")
    cc_show "$C_GRN" "  [ok] baseline taken at $BASETIME"
else
    [ -d "$STATE/last" ] || cp -R "$STATE/baseline" "$STATE/last"
    cc_show "$C_GRN" "  [ok] using the baseline from ${BASETIME:-earlier}"
fi
_bl=""
for _s in $SECTIONS conns; do
    _f="$STATE/baseline/$_s"; [ "$_s" = conns ] && _f="$STATE/conns-seen"
    [ "$_s" = conns ] && [ "$CONNS" != 1 ] && continue
    [ -f "$_f" ] && _bl="$_bl$_s $(grep -c . "$_f"), "
done
cc_show "" "  What it holds: $(printf '%s' "$_bl" | sed 's/, $//')"

# ---- Checks --------------------------------------------------------------------------
header "3/3  checks$([ "$LOOP" -gt 0 ] && echo " every $LOOP seconds - Ctrl-C stops")"
# show_alert SEV SECTION CHANGE ITEM DETAIL -> two lines on screen, coloured.
show_alert() {
    case "$1" in
        HIGH) _c=$C_RED; _m='[!]' ;;
        MED)  _c=$C_YEL; _m='[*]' ;;
        *)    _c=$C_GRY; _m='[-]' ;;
    esac
    cc_show "$_c" "  $_m $(printf '%-4s %-11s %-7s' "$1" "$2" "$3") $4"
    cc_show "$_c" "        $5"
}
trap 'STOP=1' INT TERM
: >"$W/all"
if [ "$BASEMODE" = new ] && [ "$LOOP" = 0 ]; then
    cc_show "" "  Baseline only (nothing can have changed yet). Run again to check, or use --loop 60."
    STOP=1
fi
while [ "$STOP" = 0 ]; do
    NCHECK=$((NCHECK + 1))
    DOSUID=1
    [ "$LOOP" -gt 0 ] && [ $(((NCHECK - 1) % SUIDEVERY)) -ne 0 ] && DOSUID=0
    snap "$STATE/now"
    if [ "$STOP" = 1 ]; then rm -rf "$STATE/now"; NCHECK=$((NCHECK - 1)); break; fi
    adopt "$STATE/now"
    { compare "$STATE/last" "$STATE/now" | enrich_ports "$STATE/now"
      [ "$CONNS" = 1 ] && new_conns "$STATE/now"; } >"$W/new"
    _t=$(date -u +%Y-%m-%dT%H:%M:%SZ); _tl=$(date +%H:%M:%S)
    # HIGH first, then MED, then LOW.
    awk -F'|' '{ r = ($1 == "HIGH") ? 1 : ($1 == "MED" ? 2 : 3); print r "|" $0 }' "$W/new" | sort -t'|' -k1,1n -k3,3 | cut -d'|' -f2- >"$W/new.sorted"
    cat "$W/new.sorted" >>"$W/all"
    _n=$(grep -c . "$W/new.sorted"); _h=$(grep -c '^HIGH' "$W/new.sorted"); _m=$(grep -c '^MED' "$W/new.sorted"); _l=$((_n - _h - _m))
    N_H=$((N_H + _h)); N_M=$((N_M + _m)); N_L=$((N_L + _l))
    if [ "$_n" -gt 0 ]; then
        _hc=$C_YEL; [ "$_h" -gt 0 ] && _hc=$C_RED; [ "$_h" = 0 ] && [ "$_m" = 0 ] && _hc=$C_GRY
        cc_show "$_hc" "$_tl  check $NCHECK: $_n change(s) - $_h HIGH, $_m MED, $_l LOW"
        awk -F'|' -v t="$_t" '{ d = $5; for (i = 6; i <= NF; i++) d = d "|" $i; printf "%s %-4s %-11s %-7s %s - %s\n", t, $1, $2, $3, $4, d }' "$W/new.sorted" >"$W/lines"
        cat "$W/lines" >>"$ALERTS"
        _i=0
        while IFS='|' read -r _sev _sec _chg _item _det; do
            cc_csv_row "$ALCSV" "$_t" "$_sev" "$_sec" "$_chg" "$_item" "$_det"
            _i=$((_i + 1))
            [ "$_i" -le 40 ] && show_alert "$_sev" "$_sec" "$_chg" "$_item" "$_det"
        done <"$W/new.sorted"
        [ "$_n" -gt 40 ] && cc_show "$C_GRY" "  ... $((_n - 40)) more in $CC_RUN_DIR/alerts.txt"
        if [ -n "$ALERTCMD" ]; then
            sh -c "$ALERTCMD" <"$W/lines" >>"$CC_LOG" 2>&1 || cc_show "$C_YEL" "  [!] --alert-cmd failed (exit $?): the alerts are still in $ALERTS"
        fi
    else
        cc_show "$C_GRN" "$_tl  check $NCHECK: [ok] no changes"
    fi
    compare "$STATE/baseline" "$STATE/now" | sort |
        awk -F'|' '{ d = $5; for (i = 6; i <= NF; i++) d = d "|" $i; printf "%-4s %-11s %-7s %s - %s\n", $1, $2, $3, $4, d }' >"$STATE/changes-since-baseline.txt"
    rm -rf "$STATE/last"; mv "$STATE/now" "$STATE/last"
    [ "$STOP" = 1 ] && break
    [ "$LOOP" -gt 0 ] || break
    [ "$COUNT" -gt 0 ] && [ "$NCHECK" -ge "$COUNT" ] && break
    sleep "$LOOP"
    [ "$STOP" = 1 ] && break
done
trap 'cc_log ERROR "interrupted"; exit 130' INT TERM

# ---- Summary -----------------------------------------------------------------------
cc_csv_pretty "$ALCSV" "$CC_RUN_DIR/alerts.txt" 110
cc_csv_pretty "$CONNCSV" "$CC_RUN_DIR/connections.txt" 80
NDIFF=$(grep -c . "$STATE/changes-since-baseline.txt" 2>/dev/null)
{
    printf '==========[ Summary ]==========\n'
    printf 'Host %s | %s check(s) | baseline from %s\n' "$CC_HOST" "$NCHECK" "${BASETIME:-?}"
    printf 'This run: %s HIGH, %s MED, %s LOW alert(s)\n' "$N_H" "$N_M" "$N_L"
    if [ $((N_H + N_M + N_L)) -gt 0 ]; then
        printf '\nAlerts this run by section:\n'
        cut -d'|' -f1,2 "$W/all" | sort | uniq -c | sort -k1,1nr |
            awk '{ split($2, a, "|"); printf "  %-4s %-11s %s\n", a[1], a[2], $1 }'
    fi
    printf '\nDifferent from the baseline right now: %s item(s)%s\n' "$NDIFF" "$([ "$NDIFF" -gt 0 ] && echo " - see $STATE/changes-since-baseline.txt")"
    if [ "$NDIFF" -gt 0 ]; then
        grep -E '^(HIGH|MED)' "$STATE/changes-since-baseline.txt" | head -n 15 | sed 's/^/  /'
        [ "$(grep -cE '^(HIGH|MED)' "$STATE/changes-since-baseline.txt")" -gt 15 ] && printf '  ...\n'
    fi
    printf '\nFiles:\n'
    printf '  %s/alerts.txt        this run'"'"'s alerts (csv/alerts.csv)\n' "$CC_RUN_DIR"
    [ "$CONNS" = 1 ] && printf '  %s/connections.txt   new connections seen (csv/connections.csv)\n' "$CC_RUN_DIR"
    printf '  %s   every alert ever\n' "$ALERTS"
    printf '\nNext: if the changes are your own, run with --accept so they stop showing.\n'
} >"$CC_RUN_DIR/summary.txt"
cc_show "" ""
while IFS= read -r _line; do
    case "$_line" in
        ==*) cc_show "$C_CYN" "$_line" ;;
        'This run:'*) if [ "$N_H" -gt 0 ]; then cc_show "$C_RED" "$_line"; elif [ "$N_M" -gt 0 ]; then cc_show "$C_YEL" "$_line"; else cc_show "$C_GRN" "$_line"; fi ;;
        '  HIGH'*) cc_show "$C_RED" "$_line" ;;
        '  MED'*) cc_show "$C_YEL" "$_line" ;;
        *) cc_show "" "$_line" ;;
    esac
done <"$CC_RUN_DIR/summary.txt"
rm -rf "$W"
cc_finish
