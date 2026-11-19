#!/bin/sh
# =============================================================================
# ID:       NW-30
# NAME:     Device change watch
# ROLE:     Network  (wave 2, after NW-01; leave it running)
# KIND:     readonly - only "show" commands are sent; nothing on a device changes
# VERSION:  1.0.0
#
# PURPOSE
#   Reads every firewall, router and switch every few minutes and compares
#   it with a BASELINE (the config you trust).  Every line that was added,
#   removed or moved since is shown once, with:
#     how bad it is      HIGH (accounts, passwords, SNMP, NAT, firewall
#                        rules, management access, routes, logging, AAA,
#                        VPN, scheduled scripts) or MED (anything else)
#     what it may mean   e.g. "a new account: a back door?"
#     where it is        the section it is in (interface, policy, chain ...)
#     how to undo it     a suggested command - NEVER sent; you check and type it
#   Then you are asked: was this ours?
#     [n] not ours (default): it stays on the "open" list; when it goes away
#         (someone put it back) that is shown too
#     [o] ours: these lines become part of the baseline and are not shown again
#     [e] each one: asked line by line
#   Lines with NW-20/NW-21's own names (bt-, BT-IN, BT-MGMT ...) are marked
#   "probably ours (NW-20/NW-21)".  Nothing is ever accepted without a person:
#   with --batch every change stays open.
#
#   Brands: cisco-ios, cisco-asa, paloalto, fortigate, vyos, mikrotik,
#   pfsense / opnsense (log in as root), linux (a Linux router) - the same
#   reads as NW-01.
#
#   QUESTIONS (Enter takes the default in capitals; a flag answers each):
#     watch these devices?                       Y
#     each device: which baseline?               [k]eep the earlier one /
#                                                [n]W-01's copy / [f]resh now
#                                                (--baseline keep|nw01|fresh)
#     how often?                                 every 2 minutes (--every)
#     for how long?                              until Ctrl-C   (--for, --once)
#     new changes on DEVICE: ours?               [N]ot ours / [o]urs / [e]ach
#
# USAGE
#   BT_NET_PASS='pw' sh NW-30-device-watch.sh --hosts config/hosts.csv
#   BT_NET_PASS='pw' sh NW-30-device-watch.sh --device fw1,10.0.0.1,paloalto --every 60
#   BT_NET_PASS='pw' sh NW-30-device-watch.sh --hosts config/hosts.csv --once --batch   (from cron)
#
# OPTIONS
#   --device NAME,ADDRESS,VENDOR[,USER[,PORT]]   a device (repeat)
#   --hosts FILE       or the devices from the host list
#   --baseline WHICH   keep (the earlier NW-30 baseline), nw01 (NW-01's
#                      newest copy), fresh (read it now); default: asked,
#                      else keep, else nw01, else fresh
#   --every N          seconds between rounds (default 120, at least 10)
#   --for N            minutes to watch (0 = until Ctrl-C)
#   --once             one round, then stop (the same as --rounds 1)
#   --rounds N         this many rounds, then stop
#   --quiet            no bell on a HIGH change
#   --user NAME / --ask-password / --enable-env / --legacy-ssh   as NW-21
#   --no-color         no colours
#   --help             this text plus the common options
#
# OUTPUTS  (under --out, in device-watch-N/)
#   output.txt     everything shown on screen, without colour
#   changes.txt    every change seen: time, device, HIGH/MED, added/removed/
#                  moved, the line (secrets masked), where, what it may mean
#   undo-hints.txt a suggested undo per change (never sent)
#   rounds.txt     each round: each device read or not, changes
#   summary.txt    the open (not ours) changes at the end
#   net-watch/DEVICE/ in --out (mode 700, kept between runs):
#     base.norm  the baseline   ok  the lines you said were ours
#     open       the not-ours changes still there   copies/  each changed read
#
# WHAT IT CHANGES
#   Nothing on any device: the same show / export commands as NW-01.  Saved
#   reads hold password hashes and keys: mode 600, and secrets are masked in
#   everything shown or written to the run folder.
#
# DEPENDS ON
#   ssh, sshpass, diff, awk.
#
# TESTED ON
#   A stand-in device for every brand (its config changed between rounds)
#   under dash, bash, busybox sh, ksh93, mksh and yash with gawk, mawk and
#   busybox awk.  NOT yet on real devices: run --once first and check that
#   a quiet device shows no changes (a line that changes by itself on every
#   read is noise - tell us the brand and the line).
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - FortiGate shows encrypted secrets (ENC ...) differently on each read:
#     they are hidden before comparing, so a changed secret is not seen
#     (a new admin or key entry still is).
#   - MikroTik exports without secrets unless the login may see them.
#   - A changed SSH host key stops the watch of that device (HIGH): find out
#     why before trusting it.
# =============================================================================

# >>> BT-LIB  (lib/lib.sh 0.2.1 pasted in by tools/build.sh - edit lib/lib.sh, not this copy)
# =============================================================================
# ID:       LB-01
# NAME:     Shell library (lib.sh)
# ROLE:     Automation  (wave 0, foundation)
# VERSION:  0.2.1
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
CC_LIB_VERSION="0.2.1"

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
        cc_undo_add "restore $_cc_bk_src" "cp -pR $(cc_shquote "$_cc_bk_dst") $(cc_shquote "$_cc_bk_src")"
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
        cc_undo_add "un-quarantine $_cc_q_src" "mv $(cc_shquote "$_cc_q_dst") $(cc_shquote "$_cc_q_src")"
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
    if [ -z "$CC_FLAGS" ] || [ ! -f "$CC_FLAGS" ]; then
        printf 'Flags: none\n'
        return 0
    fi
    # CC_FLAGS_SHOW: the path to name on screen, when a script writes a
    # readable copy of flags.csv (SH-05 writes flags.txt).
    awk -v max="$_cc_fr_max" -v file="${CC_FLAGS_SHOW:-$CC_FLAGS}" "$CC_AWK_CSV"'
        NR == 1 { next }
        {
            csvsplit($0, f)
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

VENDORS="cisco-ios cisco-asa paloalto fortigate vyos mikrotik linux pfsense opnsense"

usage() {
    cat <<'USAGE'
NW-30 Device change watch - every change on the network devices, shown once; read-only
  BT_NET_PASS=pw sh NW-30-device-watch.sh --hosts FILE | --device NAME,ADDRESS,VENDOR [options]

  --device NAME,ADDRESS,VENDOR[,USER[,PORT]]   a device (repeat), or --hosts FILE
  --baseline keep|nw01|fresh   which config is trusted (else asked)
  --every N          seconds between rounds (default 120)
  --for N            minutes (0 = until Ctrl-C)   --once / --rounds N
  --quiet            no bell on a HIGH change
  --user NAME / --ask-password / --enable-env / --legacy-ssh
  --no-color         no colours
  --help             show this text
USAGE
    cc_usage_common
}

NL='
'
HOSTS=""; DEVICES=""; DEFUSER="admin"; ASK=0; ENABLE=0; LEGACY=0; COLOR=1
BASE=""; EVERY=""; FOR=""; ROUNDS=""; QUIET=0
num() { case "$2" in ''|*[!0-9]*) cc_die 2 "$1 needs a whole number" ;; esac; }
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --hosts)        [ $# -ge 2 ] || cc_die 2 "--hosts needs a file"; [ -r "$2" ] || cc_die 2 "--hosts: cannot read $2"; HOSTS=$2; shift 2 ;;
        --device)       [ $# -ge 2 ] || cc_die 2 "--device needs NAME,ADDRESS,VENDOR"; DEVICES="$DEVICES$2$NL"; shift 2 ;;
        --user)         [ $# -ge 2 ] || cc_die 2 "--user needs a name"; DEFUSER=$2; shift 2 ;;
        --ask-password) ASK=1; shift ;;
        --enable-env)   ENABLE=1; shift ;;
        --legacy-ssh)   LEGACY=1; shift ;;
        --baseline)     [ $# -ge 2 ] || cc_die 2 "--baseline needs keep, nw01 or fresh"
                        case "$2" in keep|nw01|fresh) BASE=$2 ;; *) cc_die 2 "--baseline: keep, nw01 or fresh" ;; esac; shift 2 ;;
        --every)        num "$1" "${2:-}"; EVERY=$2; shift 2 ;;
        --for)          num "$1" "${2:-}"; FOR=$2; shift 2 ;;
        --once)         ROUNDS=1; shift ;;
        --rounds)       num "$1" "${2:-}"; ROUNDS=$2; shift 2 ;;
        --quiet)        QUIET=1; shift ;;
        --no-color|--no-colour) COLOR=0; shift ;;
        --help|-h)      usage; exit 0 ;;
        *)              cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
[ -n "$HOSTS$DEVICES" ] || cc_die 2 "give the devices: --hosts FILE or --device NAME,ADDRESS,VENDOR (try --help)"
[ -z "$EVERY" ] || [ "$EVERY" -ge 10 ] || [ -n "${BT_TEST_FAST:-}" ] || cc_die 2 "--every: at least 10 seconds"
[ "$ROUNDS" = 0 ] && cc_die 2 "--rounds: at least 1"

cc_init "NW-30" "Device change watch" readonly
# shellcheck disable=SC2034  # read by cc_color_init
[ "$COLOR" = 1 ] || CC_NOCOLOR=1
cc_color_init
cc_use_numbered_dir device-watch
rmdir "$CC_RUN_DIR/raw" 2>/dev/null
OUTF="$CC_RUN_DIR/output.txt"
grep -v '\[NOTE\]\|\[DEBUG\]' "$CC_LOG" >"$OUTF" 2>/dev/null || : >"$OUTF"
# shellcheck disable=SC2034  # CC_TEE is read by the library's log functions
CC_TEE=$OUTF
W="$CC_RUN_DIR/.work"; (umask 077; mkdir -p "$W")
US=$(printf '\037')
header() { cc_show "" ""; cc_show "$C_CYN" "==========[ $1 ]=========="; }
CONFIGS="$CC_OUT/net-configs"; (umask 077; mkdir -p "$CONFIGS") 2>/dev/null
STATE="$CC_OUT/net-watch"; (umask 077; mkdir -p "$STATE") || cc_die 3 "cannot create $STATE"
SSH=${BT_SSH:-$(cc_which ssh)} || cc_die 3 "ssh not found"
SSHPASS_BIN=${BT_SSHPASS:-$(cc_which sshpass)} || cc_die 3 "sshpass not found (apt install sshpass)"
cc_have diff || cc_die 3 "diff not found"
if [ "$ASK" = 1 ]; then
    [ -r /dev/tty ] || cc_die 3 "--ask-password needs a terminal; set BT_NET_PASS"
    printf 'Device password: ' >/dev/tty; stty -echo </dev/tty 2>/dev/null
    read -r BT_NET_PASS </dev/tty; stty echo </dev/tty 2>/dev/null; printf '\n' >/dev/tty
fi
[ -n "${BT_NET_PASS:-}" ] || cc_die 3 "the device password is needed: set BT_NET_PASS or use --ask-password"
[ "$ENABLE" = 1 ] && [ -z "${BT_NET_ENABLE:-}" ] && cc_die 3 "--enable-env: set BT_NET_ENABLE"

cc_show "$C_CYN" "NW-30 Device change watch | from $CC_HOST | results in $CC_RUN_DIR"
cc_show "" "Legend: ${C_RED}[!] HIGH${C_OFF} change   ${C_YEL}[*] MED${C_OFF} change   ${C_GRN}[ok]${C_OFF} no change / back as before   ${C_GRY}[-]${C_OFF} information"

# ---- Devices ------------------------------------------------------------------------------
vendor_of() {
    printf '%s' "$1" | tr 'A-Z' 'a-z' | awk '
        /cisco-ios|ios-xe|catalyst|cisco ios|cisco router|cisco switch/ { print "cisco-ios"; exit }
        /cisco-asa|asa|firepower|ftd/ { print "cisco-asa"; exit }
        /paloalto|palo alto|pan-os|panos/ { print "paloalto"; exit }
        /fortigate|fortinet|fortios/ { print "fortigate"; exit }
        /vyos|vyatta/ { print "vyos"; exit }
        /opnsense/ { print "opnsense"; exit }
        /pfsense/ { print "pfsense"; exit }
        /mikrotik|routeros/ { print "mikrotik"; exit }
        /cisco/ { print "cisco-ios"; exit }'
}
: >"$W/devices"
if [ -n "$HOSTS" ]; then
    awk -F',' "$CC_AWK_CSV"'
        /^[ \t]*#/ || NF < 2 { next }
        !hdr { n = csvsplit($0, h); for (i = 1; i <= n; i++) c[tolower(h[i])] = i; hdr = 1; next }
        { csvsplit($0, f); print f[c["host"]] "|" f[c["ip"]] "|" tolower(f[c["os"]]) "|" (("vendor" in c) ? f[c["vendor"]] : "") "|" f[c["notes"]] "|" (("user" in c) ? f[c["user"]] : "") "|" (("port" in c) ? f[c["port"]] : "") }' "$HOSTS" >"$W/rows"
    while IFS='|' read -r _n _a _os _v _notes _u _p; do
        _vend=""; [ -n "$_v" ] && _vend=$(vendor_of "$_v")
        [ -z "$_vend" ] && [ "$_os" != linux ] && case " $VENDORS " in *" $_os "*) _vend=$_os ;; esac
        [ -z "$_vend" ] && [ "$_os" = network ] && _vend=$(vendor_of "$_notes")
        [ -n "$_vend" ] || continue
        printf '%s|%s|%s|%s|%s\n' "$_n" "$_a" "$_vend" "${_u:-$DEFUSER}" "${_p:-22}" >>"$W/devices"
    done <"$W/rows"
fi
printf '%s' "$DEVICES" | grep . | while IFS=',' read -r _n _a _v _u _p; do
    case " $VENDORS " in *" $_v "*) ;; *) echo "BADV|$_v"; continue ;; esac
    [ -n "$_n" ] && [ -n "$_a" ] || { echo "BAD|$_n"; continue; }
    printf '%s|%s|%s|%s|%s\n' "$_n" "$_a" "$_v" "${_u:-$DEFUSER}" "${_p:-22}"
done >>"$W/devices"
grep -q '^BAD' "$W/devices" && cc_die 2 "--device needs NAME,ADDRESS,VENDOR with a known vendor ($VENDORS)"
[ -s "$W/devices" ] || cc_die 3 "no network devices found (os must be network or a vendor name)"
for _n in $(cut -d'|' -f1 "$W/devices"); do case "$_n" in *[!A-Za-z0-9_.-]*) cc_die 2 "device name '$_n' may only use letters, digits, '.', '_' and '-'" ;; esac; done
_bp=$(awk -F'|' '$5 !~ /^[0-9]+$/ || $5 < 1 || $5 > 65535 { print $1; exit }' "$W/devices"); [ -z "$_bp" ] || cc_die 2 "device $_bp: the SSH port must be a number from 1 to 65535"

# ---- Reading a device (the same reads as NW-01) ---------------------------------------------
sshopts() {
    set -- -T -o ConnectTimeout=10 -o "UserKnownHostsFile=$CONFIGS/known_hosts" -o StrictHostKeyChecking=accept-new \
        -o LogLevel=ERROR -o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive -o NumberOfPasswordPrompts=1
    [ "$LEGACY" = 1 ] && set -- "$@" -o KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group1-sha1 -o HostKeyAlgorithms=+ssh-rsa -o Ciphers=+aes128-cbc,aes256-cbc,3des-cbc
    printf '%s\n' "$@"
}
read_mode() { case "$1" in cisco-ios|cisco-asa|paloalto|fortigate) echo stdin ;; *) echo exec ;; esac; }
read_cmds() {
    case "$1" in cisco-*) [ "$ENABLE" = 1 ] && printf 'enable\n%s\n' "$BT_NET_ENABLE" ;; esac
    case "$1" in
        cisco-ios) printf 'terminal length 0\nshow running-config\nexit\n' ;;
        cisco-asa) printf 'terminal pager 0\nshow running-config\nexit\n' ;;
        paloalto)  printf 'set cli pager off\nshow config running\nexit\n' ;;
        fortigate) printf 'show\nexit\n' ;;
        vyos)      printf '/opt/vyatta/bin/vyatta-op-cmd-wrapper show configuration commands' ;;
        pfsense|opnsense) printf 'cat /conf/config.xml' ;;
        mikrotik)  printf '/export' ;;
        linux)     printf 'S=; [ "$(id -u)" = 0 ] || S="sudo -n"; $S iptables-save 2>/dev/null; $S nft list ruleset 2>/dev/null; ip -o addr 2>/dev/null; ip route 2>/dev/null' ;;
    esac
}
# readdev VENDOR USER ADDRESS PORT OUT -> the device's config in OUT; errors in $W/err
readdev() {
    read_cmds "$1" >"$W/rin"; _rv=$1; _ru=$2; _ra=$3; _rp=$4; _ro=$5
    sshopts >"$W/opts"; set --; while IFS= read -r _o; do set -- "$@" "$_o"; done <"$W/opts"
    if [ "$(read_mode "$_rv")" = exec ]; then
        SSHPASS=$BT_NET_PASS "$SSHPASS_BIN" -e "$SSH" "$@" -p "$_rp" "$_ru@$_ra" "$(cat "$W/rin")" </dev/null >"$_ro" 2>"$W/err"
    else
        SSHPASS=$BT_NET_PASS "$SSHPASS_BIN" -e "$SSH" "$@" -p "$_rp" "$_ru@$_ra" <"$W/rin" >"$_ro" 2>"$W/err"
    fi
}
# NORMALIZE: drop what changes by itself (time stamps, counters, prompts and
# echoed commands) so only real configuration changes are compared.
NORMALIZE='
{ sub(/\r$/, ""); sub(/[ \t]+$/, "") }
/^[^ ]*[>#] *(terminal (length|pager)|show |set cli pager|exit|enable)/ { next }
/^[A-Za-z0-9_.@()-]+[>#] *$/ { next }
v == "cisco-ios" && (/^! Last configuration change/ || /^! NVRAM config last updated/ || /^ntp clock-period/ || /^Current configuration :/ || /^Building configuration/) { next }
v == "cisco-asa" && (/^: Written by/ || /^Cryptochecksum:/ || /^: Serial Number/ || /^: Hardware:/ || /^: Saved/) { next }
v == "fortigate" && (/^#conf_file_ver=/ || /^#config-version=/ || /^#buildno=/ || /^#global_vdom=/) { next }
v == "fortigate" { gsub(/ ENC [^ ]+/, " ENC (hidden)") }
v == "mikrotik" && (/^# [a-z]{3}\/[0-9]+\/[0-9]+ [0-9:]+ by RouterOS/ || /^# [0-9-]+ [0-9:]+ by RouterOS/) { next }
v == "mikrotik" && /\\$/ { sub(/\\$/, ""); held = held $0; next }
v == "mikrotik" && held != "" { sub(/^[ \t]+/, ""); $0 = held $0; held = "" }
v == "linux" && (/^# Generated by iptables-save/ || /^# Completed on/) { next }
v == "linux" && /^:[A-Z-]+ [A-Z-]+ \[[0-9]+:[0-9]+\]/ { sub(/ \[[0-9]+:[0-9]+\]$/, "") }
v == "linux" { gsub(/counter packets [0-9]+ bytes [0-9]+ /, "") }
v == "pfsense" || v == "opnsense" { if ($0 ~ /<(time|revision|lastchange)>/) next }
{ print }'
# MASK: secrets hidden in everything shown or written to the run folder.
MASK='
function mask(s,   n, w, i, out, lw, m) {  # awk, not shell: posix-ok
    if (match(s, /<(password|community|rocommunity|rwcommunity|pre-shared-key|secret|psk|key|phash|bcrypt-hash|sha512-hash|authorizedkeys)>[^<]*</)) {
        m = substr(s, RSTART, RLENGTH); sub(/>[^<]*</, ">****<", m)
        s = substr(s, 1, RSTART - 1) m substr(s, RSTART + RLENGTH)
    }
    n = split(s, w, " "); out = ""
    for (i = 1; i <= n; i++) {
        lw = tolower(w[i]); gsub(/[^a-z-]/, "", lw)
        if (lw ~ /^(password|secret|community|key|key-string|psk|psksecret|pre-shared-key|passphrase|passwd|authentication-key|plaintext-password|encrypted-password|enc|phash)$/ && i < n) {
            out = out (out ? " " : "") w[i]
            if (w[i + 1] ~ /^[0-9]$/ && i + 2 <= n) { i++; out = out " " w[i] }
            i++; out = out " ****"; continue
        }
        if (lw ~ /^(password|secret|community)=/) { sub(/=.*/, "=****", w[i]) }
        out = out (out ? " " : "") w[i]
    }
    return out
}'

# ---- Where a line is, what it may mean, how it could be undone ---------------------------------
# where VENDOR FILE -> "line US section" for each line (the section it sits in)
where() {
    awk -v v="$1" -v US="$US" '
        { l = $0 }
        v == "cisco-ios" || v == "cisco-asa" { if (l !~ /^[ \t]/) { p = l; print l US ""; next } print l US p; next }
        v == "fortigate" {
            t = l; sub(/^[ \t]+/, "", t)
            if (t ~ /^config /) { s[++n] = t; print l US path(); next }
            if (t ~ /^edit /) { s[++n] = t; print l US path(); next }
            if (t == "next" || t == "end") { if (n > 0) n--; print l US path(); next }
            print l US path(); next }
        v == "paloalto" || v == "linux" {
            t = l; sub(/^[ \t]+/, "", t)
            if (v == "linux" && t ~ /^\*/) { tb = t; n = 0 }
            if (t ~ /\{$/) { print l US path(); x = t; sub(/[ \t]*\{$/, "", x); s[++n] = x; next }
            if (t ~ /^\}/) { if (n > 0) n--; print l US path(); next }
            print l US (v == "linux" && tb != "" && n == 0 ? tb : path()); next }
        v == "mikrotik" { if (l ~ /^\//) { p = l; print l US ""; next } print l US p; next }
        { print l US "" }
        function path(   i, o) {  # awk, not shell: posix-ok
            o = ""; for (i = 1; i <= n; i++) o = o (o == "" ? "" : " > ") s[i]; return o }' "$2"
}
# judge -> reads "sign US line US section"; the line decides, else its section
# (a MikroTik "add name=x" under "/user" is an account)
judge() {
    awk -F"$US" -v OFS="$US" '
    function cls(l) {  # awk, not shell: posix-ok
        c = ""; m = ""
        if (l ~ /(username|local-user|system login user|config system admin|\/user add|user add|^\/user|<user>|create user| admin )/) { c = "account"; m = "an account added or changed: a back door?" }
        else if (l ~ /(password|secret|passwd|key-string|phash|psksecret|authorized-?keys|ssh-rsa|ssh-ed25519)/) { c = "password/key"; m = "a password or key changed: a known password or a planted key?" }
        else if (l ~ /(snmp|community)/) { c = "SNMP"; m = "a community the red team knows?" }
        else if (l ~ /(kron|event manager|scheduler|\/system script|cron|<cron>|crontab)/) { c = "scheduled job"; m = "a scheduled job or script: something that comes back by itself?" }
        else if (l ~ /(aaa|tacacs|radius|ldap)/) { c = "AAA"; m = "who may log in, or how, changed" }
        else if (l ~ /(crypto|tunnel|ipsec|vpn|wireguard|pre-shared|gre |l2tp|pptp)/) { c = "VPN/tunnel"; m = "a tunnel: a way in or a way out for data?" }
        else if (l ~ /((^|[^a-z])nat([^a-z]|$)|static \(|port-forward|dst-nat|dstnat|vip|destination-translation|masquerade|<rdr>)/) { c = "NAT"; m = "a port forwarded in to a box?" }
        else if (l ~ /(telnet|http server|ip http|allowaccess|line vty|transport input|management|service www|winbox|service (ssh|api|ftp)|set ssh|ssh version|webgui|<webgui>|permitted-ip|trusthost|ssh [0-9])/) { c = "management access"; m = "who may manage the device, or over what, changed" }
        else if (l ~ /(access-list|access-group|permit|deny|allow|accept|drop|reject|rulebase|firewall policy|firewall filter|^-a |^-i |^-d |chain|rule|<filter>|security-policy)/) { c = "firewall rule"; m = "something let in, or something blocked (a scored service?)" }
        else if (l ~ /(logging|syslog|log-|log |<syslog>)/) { c = "logging"; m = "logging changed: someone hiding what they do?" }
        else if (l ~ /(route|gateway|ospf|bgp|(^|[^a-z])rip([^a-z]|$)|eigrp)/) { c = "routing"; m = "traffic sent somewhere else?" }
        else if (l ~ /(shutdown|disable|disabled)/) { c = "turned off"; m = "a service or a port taken down?" }
        else if (l ~ /(dns|name-server|nameserver|ntp)/) { c = "DNS/time"; m = "where the device asks for names or time changed" }
    }
    { cls(tolower($2)); if (c == "" && $3 != "") cls(tolower($3))
      sev = (c == "" || c == "DNS/time") ? "MED" : "HIGH"
      if (c == "") { c = "other"; m = "a change" }
      print sev, c, m, $1, $2 }'
}
# hint VENDOR SIGN LINE SECTION -> a suggested undo (shown only; never sent)
hint() {
    _hv=$1; _hs=$2; _hl=$3; _hp=$4
    _ht=$(printf '%s' "$_hl" | sed 's/^[ \t]*//')
    case "$_hv" in
        cisco-ios|cisco-asa)
            _hw=""; [ -n "$_hp" ] && _hw="$_hp / "
            case "$_hs" in
                +) case "$_ht" in "no "*) printf 'configure terminal / %s%s' "$_hw" "${_ht#no }" ;; *) printf 'configure terminal / %sno %s' "$_hw" "$_ht" ;; esac ;;
                -) printf 'configure terminal / %s%s' "$_hw" "$_ht" ;;
                *) printf 'the order changed (a rule above or below another now): put it back in its old place, see the saved copy' ;;
            esac ;;
        vyos)
            case "$_hs" in
                +) case "$_ht" in "set "*) printf 'configure / delete %s / commit / save' "${_ht#set }" ;; *) printf 'configure, then undo: %s' "$_ht" ;; esac ;;
                -) printf 'configure / %s / commit / save' "$_ht" ;;
                *) printf 'the order changed: compare with the saved copy' ;;
            esac ;;
        linux)
            case "$_hs$_ht" in
                +-A\ *) printf 'iptables -t %s -D %s' "$(printf '%s' "${_hp:-*filter}" | tr -d '*')" "${_ht#-A }" ;;
                --A\ *) printf 'iptables -t %s -A %s   (put it back where it was)' "$(printf '%s' "${_hp:-*filter}" | tr -d '*')" "${_ht#-A }" ;;
                +table\ *) printf 'nft delete table %s' "$(printf '%s' "${_ht#table }" | sed 's/ *{$//')" ;;
                +chain\ *) printf 'nft delete chain %s %s' "$(printf '%s' "${_hp#table }" | sed 's/ > .*//')" "$(printf '%s' "${_ht#chain }" | sed 's/ *{$//')" ;;
                +*) printf 'nft -a list ruleset, find it under "%s", then nft delete rule ... handle N' "$_hp" ;;
                *) printf 'put it back under "%s" (see the saved copy)' "$_hp" ;;
            esac ;;
        fortigate)
            case "$_hs$_ht" in
                +set\ *) printf '%s / unset %s / end' "$_hp" "$(printf '%s' "${_ht#set }" | awk '{ print $1 }')" ;;
                +edit\ *) printf '%s / delete %s / end' "$(printf '%s' "$_hp" | sed 's/ > edit .*//')" "${_ht#edit }" ;;
                -set\ *) printf '%s / %s / end' "$_hp" "$_ht" ;;
                *) printf 'under "%s": compare with the saved copy' "$_hp" ;;
            esac ;;
        paloalto) printf 'configure mode or web GUI, under "%s": %s it, then commit' "$_hp" "$([ "$_hs" = + ] && echo 'delete' || echo 'put back')" ;;
        mikrotik)
            case "$_hs" in
                +) printf '%s print, find the new entry (%s), %s remove NUMBER' "${_hp:-the section}" "$(printf '%s' "$_ht" | cut -c1-50)" "${_hp:-}" ;;
                -) printf '%s %s' "$_hp" "$_ht" ;;
                *) printf 'the order changed under %s: compare with the saved copy' "$_hp" ;;
            esac ;;
        pfsense|opnsense) printf 'web GUI: Diagnostics > Backup & Restore > Config History can show and roll back this change' ;;
    esac
}
ours_like() { case "$1" in *bt-*|*BT-IN*|*BT-OUT*|*BT-MGMT*|*bt_fw*) return 0 ;; esac; return 1; }

# ---- 1. The devices and their baselines -----------------------------------------------------
header "1/3  devices and baselines"
while IFS='|' read -r _n _a _v _u _p; do cc_show "" "  $_n  $_a  $_v  (login $_u, port $_p)"; done <"$W/devices"
if ! cc_ask "Watch these $(grep -c . "$W/devices") device(s)? (read-only: only show commands are sent)" Y "yes" "no, stop"; then
    cc_show "$C_GRY" "  Stopped."; rm -rf "$W"; cc_finish; exit 0
fi
# fetch DEVICE VENDOR USER ADDRESS PORT -> $W/cur.DEVICE (normalized); 0 read, 1 failed, 2 host key changed
fetch() {
    readdev "$2" "$3" "$4" "$5" "$W/raw.$1"; _frc=$?
    if grep -q 'REMOTE HOST IDENTIFICATION HAS CHANGED\|Host key verification failed' "$W/err"; then return 2; fi
    awk -v v="$2" "$NORMALIZE" "$W/raw.$1" >"$W/cur.$1"
    [ "$_frc" = 0 ] && [ "$(grep -c . "$W/cur.$1")" -ge 3 ] && return 0
    _why=$(grep -v '^$' "$W/err" | tail -n 1 | cut -c1-80); [ -n "$_why" ] || _why="empty answer (no rights to show the config?)"
    return 1
}
: >"$W/watch"
while IFS='|' read -r _n _a _v _u _p; do
    _d="$STATE/$_n"; (umask 077; mkdir -p "$_d/copies")
    _nw="$CONFIGS/$_n/$(cat "$CONFIGS/$_n/latest" 2>/dev/null).cfg"
    _have=""; [ -s "$_d/base.norm" ] && [ "$(cat "$_d/vendor" 2>/dev/null)" = "$_v" ] && _have=keep
    _nwok=""; [ -s "$_nw" ] && _nwok=1
    _b=$BASE
    if [ -z "$_b" ]; then
        set -- "f=fresh: read it now and trust what is there now"
        _def=f
        [ -n "$_nwok" ] && { set -- "n=NW-01's copy from $(cat "$CONFIGS/$_n/latest") (catches changes made since then)" "$@"; _def=n; }
        [ -n "$_have" ] && { set -- "k=keep the baseline from the earlier watch ($(cat "$_d/base.when" 2>/dev/null)), with the changes you said were ours" "$@"; _def=k; }
        cc_choose "$_n: which config is the trusted one (the baseline)?" "$_def" "$@"
        case "$CC_CHOICE" in k) _b=keep ;; n) _b=nw01 ;; *) _b=fresh ;; esac
    fi
    if [ "$_b" = keep ] && [ -z "$_have" ]; then cc_show "$C_YEL" "  [*] $_n: no earlier baseline to keep$([ -n "$_nwok" ] && echo ': using NW-01'"'"'s copy' || echo ': reading a fresh one')"; _b=nw01; fi
    if [ "$_b" = nw01 ] && [ -z "$_nwok" ]; then cc_show "$C_YEL" "  [*] $_n: no NW-01 copy: reading a fresh one"; _b=fresh; fi
    case "$_b" in
        keep) cc_show "$C_GRN" "  [ok] $_n: the baseline from $(cat "$_d/base.when" 2>/dev/null)" ;;
        nw01)
            (umask 077; awk -v v="$_v" "$NORMALIZE" "$_nw" >"$_d/base.norm"; : >"$_d/ok"; : >"$_d/open"
             printf '%s\n' "NW-01 copy $(cat "$CONFIGS/$_n/latest")" >"$_d/base.when"; printf '%s\n' "$_v" >"$_d/vendor")
            cc_show "$C_GRN" "  [ok] $_n: the baseline is NW-01's copy from $(cat "$CONFIGS/$_n/latest")" ;;
        fresh)
            fetch "$_n" "$_v" "$_u" "$_a" "$_p"; _fr=$?
            if [ "$_fr" = 2 ]; then cc_show "$C_RED" "  [!] HIGH $_n: its SSH host key CHANGED (device replaced, reinstalled, or someone in the middle): not watched. Check, then remove its line from $CONFIGS/known_hosts"; CC_N_FAIL=$((CC_N_FAIL + 1)); continue; fi
            if [ "$_fr" != 0 ]; then cc_show "$C_RED" "  [x] $_n: could not read it ($_why): not watched"; CC_N_FAIL=$((CC_N_FAIL + 1)); continue; fi
            (umask 077; cp "$W/cur.$_n" "$_d/base.norm"; : >"$_d/ok"; : >"$_d/open"; date -u +%Y-%m-%dT%H:%M:%SZ >"$_d/base.when"; printf '%s\n' "$_v" >"$_d/vendor"
             cp "$W/raw.$_n" "$_d/copies/$(date -u +%Y%m%dT%H%M%SZ)-base.cfg")
            cc_show "$C_GRN" "  [ok] $_n: baseline read now ($(grep -c . "$_d/base.norm") lines)" ;;
    esac
    [ -f "$_d/ok" ] || : >"$_d/ok"; [ -f "$_d/open" ] || : >"$_d/open"
    printf '%s|%s|%s|%s|%s\n' "$_n" "$_a" "$_v" "$_u" "$_p" >>"$W/watch"
done <"$W/devices"
[ -s "$W/watch" ] || { cc_show "$C_RED" "  Nothing to watch."; rm -rf "$W"; cc_finish; exit; }

# ---- 2. How often, how long -------------------------------------------------------------------
header "2/3  how often, how long"
if [ -z "$EVERY" ]; then
    cc_choose "How often should each device be read?" 2 "1=every minute" "2=every 2 minutes" "5=every 5 minutes" "10=every 10 minutes"
    EVERY=$((CC_CHOICE * 60))
fi
if [ -z "$ROUNDS" ] && [ -z "$FOR" ]; then
    if _cc_can_ask; then
        cc_choose "For how long?" u "u=until I press Ctrl-C" "o=once, then stop" "h=an hour" "4=four hours"
        case "$CC_CHOICE" in o) ROUNDS=1 ;; h) FOR=60 ;; 4) FOR=240 ;; *) FOR=0 ;; esac
    else
        ROUNDS=1; cc_show "$C_GRY" "  [-] nobody to ask: one round (use --for or --rounds to watch longer)"
    fi
fi
if [ -z "$ROUNDS" ]; then
    if [ "$FOR" = 0 ]; then ROUNDS=0; else ROUNDS=$(( (FOR * 60 + EVERY - 1) / EVERY )); [ "$ROUNDS" -ge 1 ] || ROUNDS=1; fi
fi
if [ "$ROUNDS" = 0 ]; then cc_show "" "  Every $EVERY seconds until Ctrl-C. Ctrl-C stops it cleanly (the summary is still written)."
else cc_show "" "  $ROUNDS round(s), every $EVERY seconds."; fi

# ---- 3. Watch -----------------------------------------------------------------------------------
header "3/3  watching"
CH="$CC_RUN_DIR/changes.txt"; HI="$CC_RUN_DIR/undo-hints.txt"; RD="$CC_RUN_DIR/rounds.txt"
printf '%-20s %-14s %-5s %-8s %-18s %s\n' time device level change kind line >"$CH"
printf 'Suggested undo for each change. NW-30 never sends these: check each one, then type it yourself.\n\n' >"$HI"
: >"$RD"
NEWALL=0; HIGHALL=0
nap() { sleep "$1" & _nap=$!; wait "$_nap"; }
# setdiff A B -> lines of A that are not in B
# (by file name, not NR == FNR: B may be empty)
setdiff() { awk -v f="$2" 'FILENAME == f { b[$0] = 1; next } !($0 in b)' "$2" "$1"; }

# one_device NAME ADDRESS VENDOR USER PORT -> read, compare, report, ask
one_device() {
    _n=$1; _a=$2; _v=$3; _u=$4; _p=$5; _d="$STATE/$_n"; _t=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    fetch "$_n" "$_v" "$_u" "$_a" "$_p"; _fr=$?
    if [ "$_fr" = 2 ]; then
        cc_show "$C_RED" "  [!] HIGH $_n: its SSH host key CHANGED - device replaced or someone in the middle. No longer read. Check, then remove its line from $CONFIGS/known_hosts"
        printf '%s %s host key CHANGED\n' "$_t" "$_n" >>"$RD"; printf '%-20s %-14s %-5s %-8s %-18s %s\n' "$_t" "$_n" HIGH alert "host key" "the device's SSH host key changed" >>"$CH"
        echo "$_n" >>"$W/drop"; NEWALL=$((NEWALL + 1)); HIGHALL=$((HIGHALL + 1)); return
    fi
    if [ "$_fr" != 0 ]; then
        if [ ! -f "$W/down.$_n" ]; then cc_show "$C_YEL" "  [*] $_n: cannot read it ($_why) - tried again next round"; : >"$W/down.$_n"; fi
        printf '%s %s not read (%s)\n' "$_t" "$_n" "$_why" >>"$RD"; return
    fi
    [ -f "$W/down.$_n" ] && { cc_show "$C_GRN" "  [ok] $_n: can be read again"; rm -f "$W/down.$_n"; }
    # Each line is compared WITH the section it is in (" shutdown" under one
    # interface is not the same as under another).  A change is
    # "+line US section" added, "-..." removed, "~..." moved (in both).
    where "$_v" "$_d/base.norm" >"$W/bctx"; where "$_v" "$W/cur.$_n" >"$W/cctx"
    diff -u "$W/bctx" "$W/cctx" >"$W/diff" 2>/dev/null
    awk 'NR > 2 && /^[-+]/' "$W/diff" | awk -F"$US" '{ t = substr($0, 2); x = $1; sub(/^./, "", x); gsub(/[ \t]/, "", x)
            if (x == "" || x ~ /^(!|exit|next|end|\}|quit|#|\{)$/) next
            s[t] = s[t] substr($0, 1, 1); if (!(t in o)) { o[t] = 1; l[++n] = t } }
         END { for (i = 1; i <= n; i++) { t = l[i]; g = s[t]; print ((g ~ /\+/ && g ~ /-/) ? "~" : substr(g, 1, 1)) t } }' >"$W/now.$_n"
    setdiff "$W/now.$_n" "$_d/ok" >"$W/cur2.$_n"
    # A change you said was ours that is no longer there was UNDONE (by someone):
    # shown once, and taken off the "ours" list.
    setdiff "$_d/ok" "$W/now.$_n" >"$W/undone.$_n"
    if [ -s "$W/undone.$_n" ]; then
        while IFS= read -r _l; do
            _gl=$(printf '%s' "${_l#?}" | cut -d"$US" -f1 | sed 's/^[ \t]*//' | awk "$MASK"'{ print mask($0) }')
            cc_show "$C_RED" "  [!] HIGH $_n: a change you said was OURS was undone: $(printf '%s' "$_gl" | cut -c1-100)"
            printf '%-20s %-14s %-5s %-8s %-18s %s\n' "$_t" "$_n" HIGH undone "ours, undone" "$_gl" >>"$CH"
            NEWALL=$((NEWALL + 1)); HIGHALL=$((HIGHALL + 1))
        done <"$W/undone.$_n"
        setdiff "$_d/ok" "$W/undone.$_n" >"$W/ok.n"; cat "$W/ok.n" >"$_d/ok"
    fi
    setdiff "$W/cur2.$_n" "$_d/open" >"$W/new.$_n"
    setdiff "$_d/open" "$W/cur2.$_n" >"$W/gone.$_n"
    _nn=$(grep -c . "$W/new.$_n"); _ng=$(grep -c . "$W/gone.$_n")
    printf '%s %s read: %s new, %s gone, %s open\n' "$_t" "$_n" "$_nn" "$_ng" "$(grep -c . "$W/cur2.$_n")" >>"$RD"
    while IFS= read -r _l; do
        _gl=$(printf '%s' "${_l#?}" | cut -d"$US" -f1 | sed 's/^[ \t]*//' | awk "$MASK"'{ print mask($0) }')
        cc_show "$C_GRN" "  [ok] $_n: back as in the baseline: $(printf '%s' "$_gl" | cut -c1-110)"
        printf '%-20s %-14s %-5s %-8s %-18s %s\n' "$_t" "$_n" "-" "gone" "back as before" "$_gl" >>"$CH"
    done <"$W/gone.$_n"
    cp "$W/cur2.$_n" "$_d/open"
    [ "$_nn" -gt 0 ] || { [ "$_ng" -gt 0 ] || [ -s "$W/undone.$_n" ] || cc_show "$C_GRY" "  [-] $_t $_n: no new change"; return; }
    (umask 077; cp "$W/raw.$_n" "$_d/copies/$(date -u +%Y%m%dT%H%M%SZ).cfg")
    # sign US line US section
    awk -F"$US" -v OFS="$US" '{ print substr($1, 1, 1), substr($1, 2), $2 }' "$W/new.$_n" >"$W/nw"
    judge <"$W/nw" >"$W/jd"
    paste -d"$US" "$W/jd" "$W/nw" >"$W/full"
    _nh=$(grep -c "^HIGH$US" "$W/full")
    NEWALL=$((NEWALL + _nn)); HIGHALL=$((HIGHALL + _nh))
    cc_show "" ""
    cc_show "$([ "$_nh" -gt 0 ] && echo "$C_RED" || echo "$C_YEL")" "  ===== $_t $_n ($_v): $_nn new change(s), $_nh HIGH ====="
    [ "$_nh" -gt 0 ] && [ "$QUIET" != 1 ] && [ -t 1 ] && printf '\007'
    : >"$W/ours_like"
    _anysec=0
    while IFS="$US" read -r _sev _cat _mean _sg _ln _x _y _where; do
        _ml=$(printf '%s' "$_ln" | awk "$MASK"'{ print mask($0) }')
        case "$_ml" in *'****'*) _anysec=1 ;; esac
        case "$_sg" in +) _what=added ;; -) _what=removed ;; *) _what=moved ;; esac
        _col=$C_YEL; _mk="[*] MED "; [ "$_sev" = HIGH ] && { _col=$C_RED; _mk="[!] HIGH"; }
        _tag=""; ours_like "$_ln" && { _tag=" (probably ours: NW-20/NW-21)"; echo 1 >>"$W/ours_like"; }
        cc_show "$_col" "  $_mk $_what: $(printf '%s' "$_ml" | sed 's/^[ \t]*//' | cut -c1-120)$_tag"
        cc_show "$C_GRY" "        $_cat: $_mean$([ -n "$_where" ] && echo " | in: $(printf '%s' "$_where" | awk "$MASK"'{ print mask($0) }' | cut -c1-80)")"
        _h=$(hint "$_v" "$_sg" "$_ml" "$(printf '%s' "$_where" | awk "$MASK"'{ print mask($0) }')")
        [ -n "$_h" ] && cc_show "$C_GRY" "        undo (not sent): $_h"
        printf '%-20s %-14s %-5s %-8s %-18s %s%s\n' "$_t" "$_n" "$_sev" "$_what" "$_cat" "$(printf '%s' "$_ml" | sed 's/^[ \t]*//')" "$([ -n "$_where" ] && echo "   [in: $(printf '%s' "$_where" | awk "$MASK"'{ print mask($0) }')]")" >>"$CH"
        printf '%s %s %s: %s\n    %s\n\n' "$_t" "$_n" "$_what" "$(printf '%s' "$_ml" | sed 's/^[ \t]*//')" "${_h:-compare with the saved copy}" >>"$HI"
    done <"$W/full"
    [ "$_anysec" = 1 ] && cc_show "$C_GRY" "        (secrets are shown as ****; the full read is in $_d/copies, mode 600)"
    # Ours?  Only a person can say so.
    if _cc_can_ask; then
        _def=n; [ "$(grep -c . "$W/ours_like")" = "$_nn" ] && _def=o
        cc_choose "$_n: were these $_nn change(s) made by your team?" "$_def" \
            "n=not ours (or not sure): keep them on the open list; shown again only if they go away" \
            "o=ours: they become part of the baseline and are not shown again" \
            "e=each one: ask line by line"
        case "$CC_CHOICE" in
            o) cat "$W/new.$_n" >>"$_d/ok"; setdiff "$_d/open" "$W/new.$_n" >"$W/o.n"; cat "$W/o.n" >"$_d/open"
               cc_show "$C_GRN" "  [ok] $_n: $_nn change(s) taken into the baseline" ;;
            e) : >"$W/acc"
               while IFS="$US" read -r _sev _cat _mean _sg _ln _x _y _where; do
                   _ml=$(printf '%s' "$_ln" | awk "$MASK"'{ print mask($0) }' | sed 's/^[ \t]*//' | cut -c1-100)
                   _d1=n; ours_like "$_ln" && _d1=o
                   cc_choose "$_n $_sev: $_sg $_ml" "$_d1" "n=not ours / not sure" "o=ours"
                   [ "$CC_CHOICE" = o ] && printf '%s%s%s%s\n' "$_sg" "$_ln" "$US" "$_where" >>"$W/acc"
               done <"$W/full"
               cat "$W/acc" >>"$_d/ok"; setdiff "$_d/open" "$W/acc" >"$W/o.n"; cat "$W/o.n" >"$_d/open"
               cc_show "$C_GRN" "  [ok] $_n: $(grep -c . "$W/acc") taken into the baseline, $(( _nn - $(grep -c . "$W/acc") )) left open" ;;
            *) cc_show "$C_YEL" "  [*] $_n: $_nn change(s) left open (not ours). Undo hints: undo-hints.txt" ;;
        esac
    else
        cc_show "$C_YEL" "  [*] $_n: left open (nobody to ask; only a person can say a change was ours)"
    fi
}

STOP=0
trap 'STOP=1' INT TERM HUP
_r=0
while :; do
    _r=$((_r + 1))
    cc_show "$C_GRY" "  -- round $_r, $(date -u +%H:%M:%SZ)"
    while IFS='|' read -r _n _a _v _u _p; do
        [ "$STOP" = 1 ] && break
        one_device "$_n" "$_a" "$_v" "$_u" "$_p" </dev/null
    done <"$W/watch"
    if [ -s "$W/drop" ]; then awk -F'|' -v f="$W/drop" 'FILENAME == f { d[$0] = 1; next } !($1 in d)' "$W/drop" "$W/watch" >"$W/w.n"; cat "$W/w.n" >"$W/watch"; : >"$W/drop"; fi
    [ "$STOP" = 1 ] && break
    [ "$ROUNDS" != 0 ] && [ "$_r" -ge "$ROUNDS" ] && break
    [ -s "$W/watch" ] || { cc_show "$C_RED" "  No device left to watch."; break; }
    nap "$EVERY"
    [ "$STOP" = 1 ] && break
done
trap - INT TERM HUP
[ "$STOP" = 1 ] && cc_show "" "" && cc_show "$C_GRY" "  Stopped (Ctrl-C) after $_r round(s)."

# ---- Summary ----------------------------------------------------------------------------
{
    printf '==========[ summary ]==========\n'
    printf 'NW-30 Device change watch | %s round(s), every %s seconds | read-only\n' "$_r" "$EVERY"
    printf 'New changes this run: %d (%d HIGH)\n\n' "$NEWALL" "$HIGHALL"
    printf 'Still open (not ours), per device:\n'
    while IFS='|' read -r _n _a _v _u _p; do
        _o="$STATE/$_n/open"; _c=$(grep -c . "$_o" 2>/dev/null); [ -n "$_c" ] || _c=0
        printf '  %-16s %s open\n' "$_n" "$_c"
        [ "$_c" -gt 0 ] && awk -F"$US" "$MASK"'{ s = substr($1, 1, 1); t = substr($1, 2); sub(/^[ \t]+/, "", t); printf "      %s %s%s\n", (s == "+" ? "added  " : (s == "-" ? "removed" : "moved  ")), substr(mask(t), 1, 100), ($2 != "" ? "   [in: " substr(mask($2), 1, 50) "]" : "") }' "$_o" | head -n 20
    done <"$W/devices"
    printf '\nEvery change: changes.txt   suggested undo: undo-hints.txt   each round: rounds.txt\n'
    printf 'Baselines and saved reads: %s/DEVICE/ (mode 700)\n' "$STATE"
    printf 'Next: undo what is not yours (undo-hints.txt), then NW-01 to save the clean config.\n'
} >"$CC_RUN_DIR/summary.txt"
while IFS= read -r _l; do case "$_l" in ==*|NW-30*) cc_show "$C_CYN" "$_l" ;; *) cc_show "" "$_l" ;; esac; done <"$CC_RUN_DIR/summary.txt"
# shellcheck disable=SC2034  # read by cc_finish
CC_N_FIND=$NEWALL
rm -rf "$W"
cc_finish
