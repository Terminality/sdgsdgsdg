#!/bin/sh
# =============================================================================
# ID:       LX-42
# NAME:     Linux persistence sweep
# ROLE:     Linux  (wave 2 - after the enum and the safe fixes; run it again
#           whenever the red team has been on the box)
# KIND:     changes - looks only, unless --apply (then it asks before each removal)
# VERSION:  1.0.0
#
# PURPOSE
#   Finds the ways an attacker makes sure they get back in or their code
#   keeps running: everything that starts by itself, logs someone in, or
#   sits in the path of a normal command.  Then, with --apply, asks finding
#   by finding whether to remove it (like sqlmap: Enter takes the default,
#   which is always "no").
#
#   Areas it searches (pick some, or do the full scan):
#     cron      crontabs, cron.d, the cron.* folders, at jobs
#     systemd   services, timers, drop-in overrides, user units, generators
#     boot      rc.local, init.d, login/network/sleep hook folders, udev
#               rules, apt hooks, logrotate scripts, inetd/xinetd, autostart
#     ssh       every authorized_keys file, forced commands, sshd settings
#               that add keys or commands, ssh rc files
#     shell     /etc/profile, profile.d, bashrc/zshrc/profile of every user:
#               reverse shells, aliases that replace sudo/ssh, LD_PRELOAD,
#               PATH tricks, history hiding
#     preload   /etc/ld.so.preload, linker config, LD_PRELOAD in service
#               environments and in running processes
#     accounts  extra UID 0, service accounts that can log in, sudoers
#               (NOPASSWD, extra files), root-equivalent groups
#     pam       pam_exec, pam_permit shortcuts, PAM modules that are not
#               from a package, nsswitch
#     kernel    modules loaded at boot or loaded now with no file on disk,
#               modprobe install tricks, core_pattern and modprobe hooks
#     files     programs in /tmp and /dev/shm, hidden and oddly named
#               folders, files in /dev, commands shadowed in /usr/local,
#               system programs that are not from a package or do not match
#               it, SUID/SGID and capabilities, immutable files, Python
#               startup hooks
#     procs     running programs that were deleted, run from /tmp, pretend
#               to be kernel threads, or are shells holding a connection
#     web       web shells and recently changed scripts in the web roots,
#               .htaccess and php.ini tricks
#     misc      mail aliases and .forward files that run programs, polkit
#               rules that allow everything
#
#   Severity: HIGH = almost certainly planted or dangerous; MED = unusual,
#   look at it; LOW = context (written to the files, shown with --low).
#   "From a package" means the distribution's package database knows the
#   file; a file nobody packaged, in a place only packages write to, is the
#   clearest sign.
#
# USAGE
#   sudo sh LX-42-persistence-sweep.sh                 asks what to scan, then looks
#   sudo sh LX-42-persistence-sweep.sh --batch         full scan, no questions
#   sudo sh LX-42-persistence-sweep.sh --areas cron,ssh,systemd
#   sudo sh LX-42-persistence-sweep.sh --apply --protected prot.csv   look, then ask what to remove
#
# OPTIONS  (each answers a question in advance)
#   --full             scan every area
#   --areas a,b        only these areas (names above)
#   --scan-dir DIR     also search DIR for planted programs and web shells
#                      (repeat).  /opt and /srv are good candidates
#   --since DAYS       "recently changed" means within DAYS days (default 7)
#   --pkg-check / --no-pkg-check
#                      compare key system programs (ssh, sudo, login, PAM,
#                      coreutils ...) with their packages (default yes; a minute)
#   --ignore-user U    leave this account's keys, crontab and startup files
#                      out (repeat or comma-separate)
#   --ignore-path P    leave anything under P out (repeat)
#   --apply            after the scan, ask about removing each HIGH and MED
#                      finding that can be removed.  Needs root and a
#                      protected list (or --no-protected)
#   --yes-high         with --apply: default "yes" for HIGH findings
#   --timer SECONDS    revert countdown when removing (default 120)
#   --no-timer         remove with no revert timer
#   --low              show LOW findings on screen too
#   --max N            findings shown per area on screen (default 40)
#   --root DIR         treat DIR as / (for tests); live checks are skipped
#   --no-color         no colours
#   --batch            no questions: full scan with the defaults, no removal
#   --help             this text plus the common options
#
# OUTPUTS  (under --out, in persistence-N/)
#   output.txt      everything shown on screen, without colour
#   summary.txt     counts per area and the HIGH and MED findings
#   findings.txt    every finding, HIGH first, with its number
#   csv/findings.csv, csv/flags.csv   the same as CSV
#   quarantine/     removed files, at their full path (with --apply)
#   revert.sh       puts back everything this run removed (with --apply)
#
# WHAT IT CHANGES  (only with --apply, and only what you say yes to)
#   A removed file is MOVED to quarantine/, never deleted.  A removed line
#   (a cron entry, a key, a line in a startup file) is taken out after the
#   file is backed up.  A removed systemd unit is stopped and disabled first.
#   SUID is taken off with chmod.  All of that is undone by revert.sh and by
#   the revert timer.  Killing a process cannot be undone and is asked
#   separately.
#
# DEPENDS ON
#   find, grep, awk, sed.  dpkg or rpm for "from a package".  Optional and
#   used when present: systemctl, lsmod/modinfo, getcap, lsattr, ss.
#   BT_PROC and BT_SS may name stand-ins (the tests use them).
#
# TESTED ON
#   Ubuntu 24.04 under dash, bash, busybox sh, ksh93, mksh and yash, against
#   a fake root (--root) with one planted example of each kind and clean
#   look-alikes next to them, and live on a clean container (no HIGH).
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - It finds what is on disk and what is running.  A kernel rootkit that
#     hides files from find can hide from this too: the kernel area and the
#     package check are the tell-tales there.
#   - "Not from a package" is normal for software your team or the
#     organisers installed by hand (/opt, /usr/local).  Those show as MED or
#     LOW, not HIGH, unless something else is wrong with them.
#   - Removing the persistence does not remove the attacker: change the
#     passwords (LX-20) and check the logs (LX-41) for how they got in.
#   - Without root, other accounts' files and processes cannot be read.
#
# DEBUGGING
#   --debug          shows each area's file list and timing
#   findings.txt     the numbered list; csv/findings.csv has the fix column
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

ALL_AREAS="cron systemd boot ssh shell preload accounts pam kernel files procs web misc"

usage() {
    cat <<'USAGE'
LX-42 Linux persistence sweep - find what lets an attacker back in, then remove it
  sudo sh LX-42-persistence-sweep.sh              asks what to scan, then looks
  sudo sh LX-42-persistence-sweep.sh --batch      full scan, no questions
  sudo sh LX-42-persistence-sweep.sh --apply      look, then ask what to remove

  --full               scan every area
  --areas a,b          only: cron systemd boot ssh shell preload accounts pam
                       kernel files procs web misc
  --scan-dir DIR       also search DIR for planted programs and web shells (repeat)
  --since DAYS         "recently changed" = within DAYS days (default 7)
  --pkg-check / --no-pkg-check   compare key system programs with their packages
  --ignore-user U      leave this account out (repeat)
  --ignore-path P      leave anything under P out (repeat)
  --apply              ask about removing each finding (root + protected list)
  --yes-high           with --apply: default "yes" for HIGH findings
  --timer SECONDS      revert countdown when removing (default 120)
  --no-timer           no revert timer
  --low                show LOW findings too
  --max N              findings shown per area (default 40)
  --root DIR           treat DIR as / (tests)
  --no-color           no colours
  --help               show this text

USAGE
    cc_usage_common
}

# ---- Options ----------------------------------------------------------------
AREAS=""; FULL=0; SCANDIRS=""; SCANSET=0; SINCE=""; PKGCHECK=""; IGUSERS=""; IGPATHS=""; IGSET=0
YESHIGH=0; TIMER=120; NOTIMER=0; SHOWLOW=0; MAXSHOW=40; R=""; COLOR=1
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --apply)        CC_APPLY=1; shift ;;
        --full)         FULL=1; shift ;;
        --areas)        [ $# -ge 2 ] || cc_die 2 "--areas needs a list"; AREAS="$AREAS $(printf '%s' "$2" | tr ',' ' ')"; shift 2 ;;
        --scan-dir)     [ $# -ge 2 ] || cc_die 2 "--scan-dir needs a folder"; SCANDIRS="$SCANDIRS $2"; SCANSET=1; shift 2 ;;
        --since)        [ $# -ge 2 ] || cc_die 2 "--since needs a number of days"; SINCE=$2; shift 2 ;;
        --pkg-check)    PKGCHECK=1; shift ;;
        --no-pkg-check) PKGCHECK=0; shift ;;
        --ignore-user)  [ $# -ge 2 ] || cc_die 2 "--ignore-user needs a name"; IGUSERS="$IGUSERS $(printf '%s' "$2" | tr ',' ' ')"; IGSET=1; shift 2 ;;
        --ignore-path)  [ $# -ge 2 ] || cc_die 2 "--ignore-path needs a path"; IGPATHS="$IGPATHS $2"; IGSET=1; shift 2 ;;
        --yes-high)     YESHIGH=1; shift ;;
        --timer)        [ $# -ge 2 ] || cc_die 2 "--timer needs seconds"; TIMER=$2; shift 2 ;;
        --no-timer)     NOTIMER=1; shift ;;
        --low)          SHOWLOW=1; shift ;;
        --max)          [ $# -ge 2 ] || cc_die 2 "--max needs a number"; MAXSHOW=$2; shift 2 ;;
        --root)         [ $# -ge 2 ] || cc_die 2 "--root needs a folder"; [ -d "$2" ] || cc_die 2 "--root: not a folder: $2"
                        R=$(cd "$2" && pwd); [ "$R" = / ] && R=""; shift 2 ;;
        --no-color|--no-colour) COLOR=0; shift ;;
        --help|-h)      usage; exit 0 ;;
        *)              cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
ok_areas() { for _a in $1; do case " $ALL_AREAS " in *" $_a "*) ;; *) BADAREA=$_a; return 1 ;; esac; done; return 0; }
ok_areas "$AREAS" || cc_die 2 "unknown area '$BADAREA' (areas: $ALL_AREAS)"
case "$SINCE" in ''|*[!0-9]*) [ -z "$SINCE" ] || cc_die 2 "--since needs a whole number of days" ;; esac
for _n in "$TIMER" "$MAXSHOW"; do case "$_n" in ''|*[!0-9]*) cc_die 2 "--timer and --max need whole numbers" ;; esac; done

# ---- Questions (sqlmap style) -----------------------------------------------
cc_color_init
[ "$COLOR" = 1 ] || { C_RED=""; C_YEL=""; C_GRN=""; C_CYN=""; C_GRY=""; C_OFF=""; }
if [ "$FULL" = 1 ]; then AREAS=$ALL_AREAS
elif [ -z "$AREAS" ]; then
    if cc_ask "Do a full scan (cron, services, ssh keys, startup files, accounts, files, processes, web ...)?" Y "yes, scan every area" "no, let me pick the areas"; then
        AREAS=$ALL_AREAS
    else
        cc_ask_text "Which areas?" "cron systemd ssh shell accounts" "area names separated by spaces, from: $ALL_AREAS"
        AREAS=$(printf '%s' "$CC_ANSWER" | tr ',' ' ')
        ok_areas "$AREAS" || cc_die 2 "unknown area '$BADAREA' (areas: $ALL_AREAS)"
    fi
fi
want() { case " $AREAS " in *" $1 "*) return 0 ;; esac; return 1; }
if [ "$SCANSET" = 0 ] && { want files || want web; }; then
    cc_ask_text "Other folders to search for planted programs and web shells, besides the standard ones?" "" "folders separated by spaces, like /opt /srv"
    SCANDIRS=$(printf '%s' "$CC_ANSWER" | tr ',' ' ')
fi
if [ -z "$SINCE" ]; then
    cc_ask_text "How many days back counts as 'recently changed'?" 7 "a number of days, like 7 (since the competition image was built)"
    SINCE=$CC_ANSWER
    case "$SINCE" in ''|*[!0-9]*) cc_die 2 "not a number of days: '$SINCE'" ;; esac
fi
[ "$SINCE" -ge 1 ] || SINCE=1
if [ -z "$PKGCHECK" ]; then
    PKGCHECK=0
    if want files || want pam; then
        cc_ask "Compare key system programs (ssh, sudo, login, PAM ...) with their packages?" Y "yes, compare them (finds replaced programs; takes a minute)" "no, skip it" && PKGCHECK=1
    fi
fi
if [ "$IGSET" = 0 ]; then
    cc_ask_text "Accounts to leave out (their keys, crontabs and startup files are not reported)?" "" "account names separated by spaces, or Enter for none"
    IGUSERS=$(printf '%s' "$CC_ANSWER" | tr ',' ' ')
fi

cc_init "LX-42" "Linux persistence sweep" changes
cc_detect_os
cc_use_numbered_dir persistence
CC_CSV_DIR="$CC_RUN_DIR/csv"
mkdir -p "$CC_CSV_DIR" || cc_die 3 "cannot create $CC_CSV_DIR"
W="$CC_RUN_DIR/.work"; mkdir -p "$W" || cc_die 3 "cannot create $W"
OUTF="$CC_RUN_DIR/output.txt"
grep -v '\[NOTE\]\|\[DEBUG\]' "$CC_LOG" >"$OUTF" 2>/dev/null || : >"$OUTF"
# shellcheck disable=SC2034  # CC_TEE is read by the library's log functions
CC_TEE=$OUTF
IS_ROOT=0; cc_is_root && IS_ROOT=1
LIVE=0; [ -z "$R" ] && LIVE=1
PROCROOT=${BT_PROC:-}
[ -n "$PROCROOT" ] || { [ "$LIVE" = 1 ] && PROCROOT=/proc; }

# ---- Helpers ----------------------------------------------------------------
# P PATH -> PATH under --root.     L PATH -> the path without the --root prefix.
P() { printf '%s%s' "$R" "$1"; }
L() { if [ -n "$R" ]; then printf '%s' "${1#"$R"}"; else printf '%s' "$1"; fi; }
header() { cc_show "" ""; cc_show "$C_CYN" "==========[ $1 ]=========="; }

# Commands that are almost never in a legitimate startup entry.
SUSP='(/dev/tcp/|/dev/udp/|(^|[^A-Za-z0-9_.-])(ba|da|z|k)?sh[[:space:]]+-i([[:space:]]|$)|[[:space:]]-e[[:space:]]+/bin/|(^|[^A-Za-z0-9_.-])(nc|ncat|netcat)[[:space:]]([^|;&]*[[:space:]])?(-[a-zA-Z]*[ec][[:space:]]|--exec|--sh-exec)|socat[[:space:]].*(exec|EXEC|system|SYSTEM)|mkfifo[[:space:]].*\|.*sh|(curl|wget|fetch)[^|;]*\|[[:space:]]*(sudo[[:space:]]+)?(ba|da|z)?sh|base64[[:space:]]+(-d|--decode)|python[0-9.]*[[:space:]]+-c[[:space:]].*(socket|pty|subprocess|os\.system)|perl[[:space:]]+-e[[:space:]].*(socket|Socket|exec)|php[[:space:]]+-r|ruby[[:space:]]+-rsocket|openssl[[:space:]]+s_client|msfvenom|meterpreter|\$\(echo[[:space:]].*\|[[:space:]]*base64|eval[[:space:]]+"?\$\((curl|wget|echo))'
# A path in a world-writable or hidden place.
BADPATH='(^|[[:space:]="'"'"':|(;&])(/tmp/|/var/tmp/|/dev/shm/|/run/shm/|/dev/mqueue/)|/\.[A-Za-z0-9_.-]+/[^[:space:]]*'
susp() { printf '%s' "$1" | grep -Eq "$SUSP"; }
badpath() { printf '%s' "$1" | grep -Eq "$BADPATH"; }

# recent FILE -> true if FILE changed within --since days.
recent() { [ -n "$(find "$1" -prune -mtime "-$SINCE" 2>/dev/null)" ]; }
# loose FILE -> true if someone other than root can change FILE.
loose() { [ -n "$(find "$1" -prune \( ! -user root -o -perm -0002 -o \( -perm -0020 ! -group root \) \) 2>/dev/null)" ]; }

# owned LOGICAL-PATH -> 0 from a package, 1 not, 2 cannot tell.
#   Built once from the package database (dpkg: the .list files; rpm: -qal).
#   Under --root a fixture file <root>/.owned lists owned paths.
OWNEDF="$W/owned"; OWNED_OK=0
if [ -n "$R" ]; then
    [ -f "$R/.owned" ] && { sort -u "$R/.owned" >"$OWNEDF"; OWNED_OK=1; }
elif [ -d /var/lib/dpkg/info ]; then
    cat /var/lib/dpkg/info/*.list 2>/dev/null | sort -u >"$OWNEDF"; [ -s "$OWNEDF" ] && OWNED_OK=1
elif cc_have rpm; then
    rpm -qal 2>/dev/null | sort -u >"$OWNEDF"; [ -s "$OWNEDF" ] && OWNED_OK=1
fi
owned() {
    [ "$OWNED_OK" = 1 ] || return 2
    grep -qxF "$1" "$OWNEDF" && return 0
    # Merged /usr: /bin/ls is packaged as /usr/bin/ls on some systems and the
    # other way round on others.
    case "$1" in
        /usr/bin/*|/usr/sbin/*|/usr/lib/*|/usr/lib64/*) grep -qxF "${1#/usr}" "$OWNEDF" && return 0 ;;
        /bin/*|/sbin/*|/lib/*|/lib64/*) grep -qxF "/usr$1" "$OWNEDF" && return 0 ;;
    esac
    return 1
}
unowned() { owned "$1"; [ $? -eq 1 ]; }

# Accounts: name|uid|gid|home|shell, minus the ones to leave out.
: >"$W/users"
[ -r "$(P /etc/passwd)" ] && awk -F: -v ig=" $IGUSERS " 'NF >= 7 && index(ig, " " $1 " ") == 0 { print $1 "|" $3 "|" $4 "|" $6 "|" $7 }' "$(P /etc/passwd)" >"$W/users"
nologin() { case "$1" in */nologin|*/false|*/sync|*/shutdown|*/halt|'') return 0 ;; esac; return 1; }
ignored() {  # LOGICAL-PATH -> true if under an --ignore-path
    for _ip in $IGPATHS; do case "$1" in "$_ip"|"$_ip"/*) return 0 ;; esac; done
    return 1
}

# ---- Findings ---------------------------------------------------------------
# f SEV AREA ITEM DETAIL [FIXKIND FIXARG]
#   FIXKIND: none | file (quarantine ITEM) | unit (stop+disable, quarantine)
#            | line (remove the line FIXARG from ITEM) | suid | pid
#   Written to $W/findings as  N|SEV|AREA|ITEM|DETAIL|FIXKIND|FIXARG
NFOUND=0; AREA_SHOWN=0; AREA_HID=0; N_H=0; N_M=0; N_L=0
: >"$W/findings"
f() {
    ignored "$3" && return 0
    # The detail keeps its "|" on screen and in the CSV; in the internal
    # "|"-separated list it is stored as \001 and turned back when read.
    _fs=$(printf '%s' "$4" | tr '\n\r\t' '   ' | cut -c1-400)
    _fd=$(printf '%s' "$_fs" | tr '|' '\001')
    _fa=$(printf '%s' "${6:-}" | tr '\n\r' '  ')
    NFOUND=$((NFOUND + 1))
    printf '%s|%s|%s|%s|%s|%s|%s\n' "$NFOUND" "$1" "$2" "$3" "$_fd" "${5:-none}" "$_fa" >>"$W/findings"
    cc_flag "$1" "$2" "$3" "$_fs"
    case "$1" in HIGH) N_H=$((N_H + 1)) ;; MED) N_M=$((N_M + 1)) ;; *) N_L=$((N_L + 1)) ;; esac
    [ "$1" = LOW ] && [ "$SHOWLOW" != 1 ] && return 0
    if [ "$AREA_SHOWN" -ge "$MAXSHOW" ]; then AREA_HID=$((AREA_HID + 1)); return 0; fi
    AREA_SHOWN=$((AREA_SHOWN + 1))
    case "$1" in
        HIGH) cc_show "$C_RED" "  [!] #$NFOUND $3" ; cc_show "$C_RED" "        $_fs" ;;
        MED)  cc_show "$C_YEL" "  [*] #$NFOUND $3" ; cc_show "$C_YEL" "        $_fs" ;;
        *)    cc_show "$C_GRY" "  [-] #$NFOUND $3: $_fs" ;;
    esac
    return 0
}
# area_start NAME TITLE / area_end -> heading, and "[ok]" when nothing showed.
AREA_I=0; AREA_N=$(printf '%s\n' $AREAS | grep -c .)
area_start() {
    AREA_I=$((AREA_I + 1)); AREA_SHOWN=0; AREA_HID=0; _as_h=$N_H; _as_m=$N_M; _as_l=$N_L; AREA_NAME=$1
    header "$AREA_I/$AREA_N  $1: $2"
}
area_end() {
    _h=$((N_H - _as_h)); _m=$((N_M - _as_m)); _l=$((N_L - _as_l))
    [ "$AREA_HID" -gt 0 ] && cc_show "$C_GRY" "  ... $AREA_HID more in findings.txt (--max shows more)"
    if [ "$_h" -eq 0 ] && [ "$_m" -eq 0 ]; then cc_show "$C_GRN" "  [ok] nothing unusual$([ "$_l" -gt 0 ] && echo " ($_l low-priority note(s) in findings.txt)")"; fi
    printf '%s|%s|%s|%s\n' "$AREA_NAME" "$_h" "$_m" "$_l" >>"$W/areas"
}
: >"$W/areas"; : >"$W/once"

cc_show "$C_CYN" "LX-42 Persistence sweep | host $CC_HOST | results in $CC_RUN_DIR"
cc_show "$C_CYN" "Areas:$( [ "$AREAS" = "$ALL_AREAS" ] && echo ' all (full scan)' || echo " $AREAS") | recent = last $SINCE day(s) | package check: $([ "$PKGCHECK" = 1 ] && echo yes || echo no)"
cc_show "" "Legend: ${C_RED}[!] HIGH${C_OFF} almost certainly planted or dangerous   ${C_YEL}[*] MED${C_OFF} unusual, look at it   ${C_GRN}[ok]${C_OFF} nothing unusual"
[ -n "$R" ] && cc_show "$C_GRY" "Looking at $R as if it were / (live checks: processes, loaded modules, packages are skipped)"
[ "$IS_ROOT" = 1 ] || [ -n "$R" ] || cc_show "$C_YEL" "[!] Not root: other accounts' files and processes cannot be read. Run with sudo for the real picture."
[ "$OWNED_OK" = 1 ] || cc_show "$C_YEL" "[!] No package database found: 'not from a package' checks are skipped."

# lines FILE -> the lines that do something (no comments, no blanks).
lines() { grep -Ev '^[[:space:]]*(#|$)' "$1" 2>/dev/null; }
# first_path TEXT -> the first absolute path in TEXT (the program it runs).
first_path() { printf '%s' "$1" | tr ' \t;|&"()<>=' '\n\n\n\n\n\n\n\n\n\n' | tr -d "'" | grep -m 1 '^/[A-Za-z0-9_.+/-]*$'; }
# check_script LOGICAL AREA WHAT [FIX] -> the usual checks for a file that
#   runs by itself: suspicious content, loose permissions, not from a package.
#   WHAT says when it runs, e.g. "runs as root every hour".
check_script() {
    _cs=$(P "$1"); [ -f "$_cs" ] || return 0
    _fix=${4:-file}
    _hit=$(grep -En -m 1 "$SUSP" "$_cs" 2>/dev/null | cut -c1-200)
    if [ -n "$_hit" ]; then f HIGH "$2" "$1" "$3, and contains: $_hit" "$_fix"; return 0; fi
    if loose "$_cs"; then f HIGH "$2" "$1" "$3, and someone other than root can change it ($(ls -ld "$_cs" 2>/dev/null | awk '{ print $1, $3, $4 }'))" none; return 0; fi
    if unowned "$1"; then
        if recent "$_cs"; then f HIGH "$2" "$1" "$3; it is not from a package and was changed in the last $SINCE day(s)" "$_fix"
        else f MED "$2" "$1" "$3; it is not from a package (added by hand?)" "$_fix"; fi
    fi
    return 0
}

# ---- cron ---------------------------------------------------------------------
# cron_file LOGICAL KIND WHO -> every entry in one crontab.
#   KIND system (has a user column) or user (WHO is the owner).
cron_file() {
    _cf=$(P "$1"); [ -f "$_cf" ] || return 0
    _own=1; unowned "$1" && _own=0
    _rec=0; recent "$_cf" && _rec=1
    lines "$_cf" | grep -Ev '^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=' >"$W/cl"
    while IFS= read -r _l; do
        _who=$3; [ "$2" = system ] && _who=$(printf '%s' "$_l" | awk '{ print ($1 ~ /^@/) ? $2 : $6 }')
        _pth=$(first_path "$_l")
        if susp "$_l"; then f HIGH cron "$1" "runs as ${_who:-?}: $_l" line "$_l"
        elif badpath "$_l"; then f HIGH cron "$1" "runs something from a world-writable or hidden folder as ${_who:-?}: $_l" line "$_l"
        elif [ -n "$_pth" ] && [ -f "$(P "$_pth")" ] && loose "$(P "$_pth")" && { [ "$2" = system ] || [ "$3" = root ]; }; then
            f HIGH cron "$1" "runs $_pth as ${_who:-?}, and someone other than root can change that file: $_l" line "$_l"
        elif [ "$2" = user ]; then
            _uid=$(awk -F'|' -v u="$3" '$1 == u { print $2 }' "$W/users")
            if [ -n "$_uid" ] && [ "$_uid" -gt 0 ] && [ "$_uid" -lt 1000 ]; then f HIGH cron "$1" "a service account ($3) has its own crontab entry: $_l" line "$_l"
            else f MED cron "$1" "crontab entry of $3: $_l" line "$_l"; fi
        elif [ "$_own" = 0 ] && [ "$_rec" = 1 ]; then f MED cron "$1" "entry in a cron file that is not from a package and changed in the last $SINCE day(s): $_l" line "$_l"
        elif [ "$_own" = 0 ]; then f LOW cron "$1" "entry in a cron file that is not from a package: $_l" line "$_l"
        elif [ "$1" = /etc/crontab ] && ! printf '%s' "$_l" | grep -Eq 'run-parts|anacron'; then f MED cron "$1" "extra entry in the system crontab: $_l" line "$_l"
        fi
    done <"$W/cl"
    loose "$_cf" && f HIGH cron "$1" "someone other than root can write this crontab" none
    return 0
}
a_cron() {
    cron_file /etc/crontab system ""
    cron_file /etc/anacrontab system ""
    for _c in "$(P /etc/cron.d)"/*; do [ -f "$_c" ] && cron_file "$(L "$_c")" system ""; done
    for _d in /var/spool/cron/crontabs /var/spool/cron /var/cron/tabs; do
        for _c in "$(P "$_d")"/*; do
            [ -f "$_c" ] || continue
            _u=$(basename "$_c"); case " $IGUSERS " in *" $_u "*) continue ;; esac
            cron_file "$(L "$_c")" user "$_u"
        done
    done
    for _d in hourly daily weekly monthly; do
        for _c in "$(P "/etc/cron.$_d")"/*; do
            [ -f "$_c" ] || continue
            case "$_c" in */.placeholder) continue ;; esac
            check_script "$(L "$_c")" cron "runs as root every ${_d%ly}"
        done
    done
    for _d in /var/spool/cron/atjobs /var/spool/at /var/spool/atjobs; do
        for _c in "$(P "$_d")"/*; do
            [ -f "$_c" ] || continue
            case "$(basename "$_c")" in .SEQ|spool) continue ;; esac
            if grep -Eq "$SUSP" "$_c" 2>/dev/null; then f HIGH cron "$(L "$_c")" "a waiting 'at' job contains: $(grep -E -m 1 "$SUSP" "$_c" | cut -c1-160)" file
            else f MED cron "$(L "$_c")" "a waiting 'at' job (runs once, later): $(tail -n 2 "$_c" 2>/dev/null | tr '\n' ' ' | cut -c1-160)" file; fi
        done
    done
}

# ---- systemd ------------------------------------------------------------------
# unit_file LOGICAL SCOPE -> one unit or drop-in.  SCOPE: system | user:NAME
unit_file() {
    _uf=$(P "$1"); [ -f "$_uf" ] && [ ! -L "$_uf" ] || return 0
    _ub=$(basename "$1"); _fix=unit
    case "$1" in *.d/*.conf) _fix="file" ;; esac
    _how="systemd unit"; case "$2" in user:*) _how="user unit of ${2#user:}" ;; esac
    grep -E '^[[:space:]]*(Exec[A-Za-z]*|Environment|EnvironmentFile)[[:space:]]*=' "$_uf" 2>/dev/null >"$W/ul"
    _flagged=0
    while IFS= read -r _l; do
        _v=${_l#*=}; _p=$(first_path "$_v")
        if susp "$_v"; then f HIGH systemd "$1" "$_how runs: $_l" "$_fix"; _flagged=1
        elif printf '%s' "$_l" | grep -Eq 'LD_PRELOAD|LD_AUDIT|LD_LIBRARY_PATH=[^ ]*(/tmp|/dev/shm|/var/tmp)'; then f HIGH systemd "$1" "$_how loads an extra library into its program: $_l" "$_fix"; _flagged=1
        elif badpath "$_v"; then f HIGH systemd "$1" "$_how runs something from a world-writable or hidden folder: $_l" "$_fix"; _flagged=1
        elif [ -n "$_p" ] && [ -f "$(P "$_p")" ] && loose "$(P "$_p")" && [ "$2" = system ]; then f HIGH systemd "$1" "$_how runs $_p, which someone other than root can change" none; _flagged=1
        fi
        [ "$_flagged" = 1 ] && break
    done <"$W/ul"
    [ "$_flagged" = 1 ] && return 0
    if loose "$_uf" && [ "$2" = system ]; then f HIGH systemd "$1" "someone other than root can change this unit file" none; return 0; fi
    _ex=$(grep -E -m 1 '^[[:space:]]*Exec(Start|StartPre|StartPost)[[:space:]]*=' "$_uf" 2>/dev/null | cut -c1-200)
    case "$1" in
        *.d/*.conf)
            # A drop-in that adds a command to someone else's service.
            [ -n "$_ex" ] && unowned "$1" && f MED systemd "$1" "override that adds a command to ${1%/*}: $_ex" file ;;
        *)
            if unowned "$1"; then
                if recent "$_uf"; then f MED systemd "$1" "$_how not from a package, changed in the last $SINCE day(s): ${_ex:-(no ExecStart)}" "$_fix"
                else f LOW systemd "$1" "$_how not from a package: ${_ex:-(no ExecStart)}" "$_fix"; fi
            fi ;;
    esac
    return 0
}
a_systemd() {
    for _d in /etc/systemd/system /usr/local/lib/systemd/system /etc/systemd/user /run/systemd/transient; do
        [ -d "$(P "$_d")" ] || continue
        find "$(P "$_d")" -maxdepth 2 -type f \( -name '*.service' -o -name '*.timer' -o -name '*.socket' -o -name '*.path' -o -name '*.conf' \) 2>/dev/null | sort >"$W/units"
        while IFS= read -r _u; do unit_file "$(L "$_u")" system; done <"$W/units"
    done
    # Package folders: only files nobody packaged, or changed recently.
    for _d in /lib/systemd/system /usr/lib/systemd/system; do
        [ -d "$(P "$_d")" ] && [ ! -L "$(P "$_d")" ] || continue
        find "$(P "$_d")" -maxdepth 1 -type f \( -name '*.service' -o -name '*.timer' \) 2>/dev/null | sort >"$W/units"
        while IFS= read -r _u; do
            _lu=$(L "$_u")
            if unowned "$_lu"; then unit_file "$_lu" system
            elif grep -Eq "$SUSP" "$_u" 2>/dev/null; then f HIGH systemd "$_lu" "packaged unit now contains: $(grep -E -m 1 "$SUSP" "$_u" | cut -c1-160)" none; fi
        done <"$W/units"
    done
    # Per-user units.
    while IFS='|' read -r _n _uid _gid _home _sh; do
        [ -d "$(P "$_home/.config/systemd/user")" ] || continue
        find "$(P "$_home/.config/systemd/user")" -maxdepth 2 -type f \( -name '*.service' -o -name '*.timer' \) 2>/dev/null >"$W/units"
        while IFS= read -r _u; do
            _lu=$(L "$_u")
            unit_file "$_lu" "user:$_n"
            grep -q "|$_lu|" "$W/findings" || f MED systemd "$_lu" "user unit of $_n (starts when $_n logs in, or at boot with lingering): $(grep -E -m 1 '^[[:space:]]*ExecStart' "$_u" | cut -c1-160)" file
        done <"$W/units"
    done <"$W/users"
    # Generators run as root very early at every boot; almost nothing ships one here.
    for _d in /etc/systemd/system-generators /usr/local/lib/systemd/system-generators /etc/systemd/user-generators; do
        for _g in "$(P "$_d")"/*; do [ -f "$_g" ] && f HIGH systemd "$(L "$_g")" "systemd generator: runs as root at every boot before anything else" file; done
    done
}

# ---- boot and hook folders ----------------------------------------------------------
a_boot() {
    for _rc in /etc/rc.local /etc/rc.d/rc.local; do
        [ -f "$(P "$_rc")" ] || continue
        lines "$(P "$_rc")" | grep -Ev '^[[:space:]]*(exit[[:space:]]+0|touch[[:space:]]+/var/lock/subsys/local)[[:space:]]*$' >"$W/cl"
        while IFS= read -r _l; do
            if susp "$_l" || badpath "$_l"; then f HIGH boot "$_rc" "runs as root at every boot: $_l" line "$_l"
            else f MED boot "$_rc" "runs as root at every boot: $_l" line "$_l"; fi
        done <"$W/cl"
    done
    for _i in "$(P /etc/init.d)"/*; do
        [ -f "$_i" ] || continue
        case "$(basename "$_i")" in README|skeleton|functions) continue ;; esac
        check_script "$(L "$_i")" boot "init script: runs as root at boot"
    done
    # Folders whose scripts run by themselves, and when.
    for _hd in "/etc/update-motd.d|runs as root every time anyone logs in" "/etc/NetworkManager/dispatcher.d|runs as root when the network changes" \
        "/etc/network/if-up.d|runs as root when a network interface comes up" "/etc/network/if-pre-up.d|runs as root before an interface comes up" \
        "/etc/network/if-down.d|runs as root when an interface goes down" "/etc/network/if-post-down.d|runs as root after an interface goes down" \
        "/etc/dhcp/dhclient-exit-hooks.d|runs as root at every DHCP renewal" "/etc/dhcp/dhclient-enter-hooks.d|runs as root at every DHCP renewal" \
        "/etc/ppp/ip-up.d|runs as root when a ppp link comes up" "/etc/X11/Xsession.d|runs at every graphical login" \
        "/etc/pm/sleep.d|runs as root at suspend and resume" "/usr/lib/systemd/system-sleep|runs as root at suspend and resume" \
        "/etc/kernel/postinst.d|runs as root when a kernel is installed"; do
        _dir=${_hd%%"|"*}; _when=${_hd#*"|"}
        for _s in "$(P "$_dir")"/*; do [ -f "$_s" ] && check_script "$(L "$_s")" boot "$_when"; done
    done
    # udev rules that run a program when a device appears.
    for _u in "$(P /etc/udev/rules.d)"/*.rules; do
        [ -f "$_u" ] || continue
        _l=$(grep -E -m 1 '(RUN|PROGRAM|IMPORT\{program\})[+]?=' "$_u" 2>/dev/null | cut -c1-200); [ -n "$_l" ] || continue
        _lu=$(L "$_u")
        if susp "$_l" || badpath "$_l"; then f HIGH boot "$_lu" "udev rule runs a program when a device appears: $_l" file
        elif unowned "$_lu"; then f MED boot "$_lu" "udev rule (not from a package) runs a program when a device appears: $_l" file; fi
    done
    # apt hooks run as root on every apt command.
    for _a in "$(P /etc/apt/apt.conf.d)"/* "$(P /etc/apt/apt.conf)"; do
        [ -f "$_a" ] || continue
        _l=$(grep -E -m 1 '(Pre-Invoke|Post-Invoke|Pre-Install-Pkgs|Update::Pre|Update::Post)' "$_a" 2>/dev/null | cut -c1-200); [ -n "$_l" ] || continue
        _la=$(L "$_a")
        if susp "$_l" || badpath "$_l"; then f HIGH boot "$_la" "apt hook runs as root on every apt command: $_l" file
        elif unowned "$_la"; then f MED boot "$_la" "apt hook (file not from a package) runs as root on every apt command: $_l" file; fi
    done
    for _lr in "$(P /etc/logrotate.d)"/*; do
        [ -f "$_lr" ] || continue
        _l=$(grep -E -m 1 "$SUSP" "$_lr" 2>/dev/null | cut -c1-200)
        if [ -n "$_l" ]; then f HIGH boot "$(L "$_lr")" "logrotate script (runs as root daily) contains: $_l" file
        elif unowned "$(L "$_lr")" && recent "$_lr" && grep -Eq 'postrotate|prerotate|firstaction|lastaction' "$_lr"; then f MED boot "$(L "$_lr")" "logrotate file with a script, not from a package, changed in the last $SINCE day(s)" file; fi
    done
    # inetd / xinetd handing a connection straight to a shell.
    if [ -f "$(P /etc/inetd.conf)" ]; then
        lines "$(P /etc/inetd.conf)" | grep -E '(/|[[:space:]])(ba|da|z|k)?sh([[:space:]]|$)|nc(at)?[[:space:]]|/tmp/|/dev/shm/' >"$W/cl"
        while IFS= read -r _l; do f HIGH boot /etc/inetd.conf "inetd gives whoever connects a shell or runs from /tmp: $_l" line "$_l"; done <"$W/cl"
    fi
    for _x in "$(P /etc/xinetd.d)"/*; do
        [ -f "$_x" ] || continue
        grep -Eq '^[[:space:]]*disable[[:space:]]*=[[:space:]]*yes' "$_x" && continue
        _l=$(grep -E -m 1 '^[[:space:]]*server[[:space:]]*=[[:space:]]*(.*/)?((ba|da|z|k)?sh|nc|ncat|netcat|socat|python[0-9.]*|perl)[[:space:]]*$|^[[:space:]]*server[[:space:]]*=[[:space:]]*(/tmp|/dev/shm|/var/tmp)/' "$_x" 2>/dev/null)
        [ -n "$_l" ] && f HIGH boot "$(L "$_x")" "xinetd service gives whoever connects a shell or runs from /tmp: $_l" file
    done
    # Desktop autostart (only matters on boxes with a desktop).
    while IFS='|' read -r _n _uid _gid _home _sh; do
        for _d in "$(P "$_home/.config/autostart")"/*.desktop; do
            [ -f "$_d" ] || continue
            _l=$(grep -E -m 1 '^Exec=' "$_d" | cut -c1-200)
            if susp "$_l" || badpath "$_l"; then f HIGH boot "$(L "$_d")" "starts when $_n logs in to the desktop: $_l" file
            else f LOW boot "$(L "$_d")" "starts when $_n logs in to the desktop: $_l" file; fi
        done
    done <"$W/users"
    for _d in "$(P /etc/xdg/autostart)"/*.desktop; do
        [ -f "$_d" ] || continue
        _l=$(grep -E -m 1 '^Exec=' "$_d" | cut -c1-200)
        if susp "$_l" || badpath "$_l"; then f HIGH boot "$(L "$_d")" "starts at every desktop login: $_l" file
        elif unowned "$(L "$_d")"; then f MED boot "$(L "$_d")" "desktop autostart entry not from a package: $_l" file; fi
    done
}

# ---- ssh ----------------------------------------------------------------------
# keys_file LOGICAL USER UID SHELL -> every key in one authorized_keys file.
# once KEY -> true the first time KEY is seen (two accounts can share a home).
once() { grep -qxF "$1" "$W/once" 2>/dev/null && return 1; printf '%s\n' "$1" >>"$W/once"; return 0; }
keys_file() {
    _kf=$(P "$1"); [ -f "$_kf" ] || return 0
    once "keys:$1" || return 0
    _krec=0; recent "$_kf" && _krec=1
    lines "$_kf" >"$W/kl"
    while IFS= read -r _l; do
        # Show the key type, the end of the key and its comment: enough to
        # recognise it, without filling the screen.
        _show=$(printf '%s' "$_l" | awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^(ssh-|ecdsa-|sk-)/) { k = $(i + 1); c = ""; for (j = i + 2; j <= NF; j++) c = c " " $j; printf "%s ...%s%s", $i, substr(k, length(k) - 11), c; exit } }')
        [ -n "$_show" ] || _show=$(printf '%s' "$_l" | cut -c1-60)
        if printf '%s' "$_l" | grep -Eq '(^|,)[[:space:]]*(command|environment)='; then
            f HIGH ssh "$1" "key for $2 with a forced command or environment: $(printf '%s' "$_l" | cut -c1-160)" line "$_l"
        elif [ "$3" -gt 0 ] && [ "$3" -lt 1000 ]; then f HIGH ssh "$1" "a service account ($2) has an SSH key: $_show" line "$_l"
        elif nologin "$4"; then f HIGH ssh "$1" "$2 cannot log in with a password (no shell) but has an SSH key: $_show" line "$_l"
        elif [ "$3" = 0 ]; then f MED ssh "$1" "key that logs in as root: $_show - is it yours?" line "$_l"
        elif [ "$_krec" = 1 ]; then f MED ssh "$1" "key for $2, file changed in the last $SINCE day(s): $_show" line "$_l"
        else f LOW ssh "$1" "key for $2: $_show" line "$_l"; fi
    done <"$W/kl"
    loose "$_kf" && [ "$3" = 0 ] && f HIGH ssh "$1" "someone other than root can add keys to root's authorized_keys" none
    if [ "$LIVE" = 1 ] && cc_have lsattr && lsattr -d "$_kf" 2>/dev/null | awk '{ print $1 }' | grep -q i; then
        f MED ssh "$1" "the file is immutable (chattr +i): someone does not want these keys removed" none
    fi
    return 0
}
a_ssh() {
    # sshd settings that add ways in.
    for _c in "$(P /etc/ssh/sshd_config)" "$(P /etc/ssh/sshd_config.d)"/*.conf; do
        [ -f "$_c" ] || continue
        _lc=$(L "$_c")
        lines "$_c" >"$W/cl"
        while IFS= read -r _l; do
            _k=$(printf '%s' "$_l" | awk '{ print tolower($1) }'); _v=$(printf '%s' "$_l" | sed 's/^[[:space:]]*[^[:space:]]*[[:space:]]*//')
            case "$_k" in
                authorizedkeyscommand) [ "$_v" = none ] || f HIGH ssh "$_lc" "sshd asks a program for extra keys at every login: $_l" line "$_l" ;;
                authorizedkeysfile)
                    for _p in $_v; do
                        case "$_p" in .ssh/authorized_keys|.ssh/authorized_keys2|%h/.ssh/authorized_keys|%h/.ssh/authorized_keys2|none) ;;
                            *) f HIGH ssh "$_lc" "sshd also accepts keys from $_p (not the usual place): $_l" none
                               # The key files kept in that other place.
                               case "$_p" in
                                   /*%u*) _kd=${_p%/*}
                                          for _k2 in "$(P "$_kd")"/*; do
                                              [ -f "$_k2" ] && f HIGH ssh "$(L "$_k2")" "$(lines "$_k2" | grep -c .) SSH key(s) for '$(basename "$_k2")' kept outside the home folder, where nobody looks" file
                                          done ;;
                                   /*)    [ -f "$(P "$_p")" ] && f HIGH ssh "$_p" "$(lines "$(P "$_p")" | grep -c .) SSH key(s) that work for EVERY account" file ;;
                               esac ;;
                        esac
                    done ;;
                permituserenvironment) [ "$_v" = yes ] && f MED ssh "$_lc" "PermitUserEnvironment yes: a user's ~/.ssh/environment can set LD_PRELOAD for their logins" none ;;
                permitemptypasswords)  [ "$_v" = yes ] && f HIGH ssh "$_lc" "PermitEmptyPasswords yes: accounts with no password can log in" none ;;
                acceptenv) printf '%s' "$_v" | grep -q 'LD_' && f HIGH ssh "$_lc" "sshd accepts LD_* variables from the client: $_l" line "$_l" ;;
                forcecommand) f MED ssh "$_lc" "ForceCommand runs at every login: $_l" none ;;
                subsystem) case "$_v" in sftp*sftp-server*|sftp*internal-sftp*) ;; sftp*) f HIGH ssh "$_lc" "the sftp subsystem was replaced: $_l" none ;; esac ;;
            esac
        done <"$W/cl"
    done
    [ -f "$(P /etc/ssh/sshrc)" ] && f HIGH ssh /etc/ssh/sshrc "runs for every SSH login on the box: $(lines "$(P /etc/ssh/sshrc)" | head -n 1 | cut -c1-160)" file
    while IFS='|' read -r _n _uid _gid _home _sh; do
        [ -n "$_home" ] && [ -d "$(P "$_home/.ssh")" ] || continue
        once "sshhome:$_home" || continue
        keys_file "$_home/.ssh/authorized_keys" "$_n" "$_uid" "$_sh"
        if [ -f "$(P "$_home/.ssh/authorized_keys2")" ]; then
            f MED ssh "$_home/.ssh/authorized_keys2" "second key file for $_n (old name, still honoured by some setups; easy to overlook)" none
            keys_file "$_home/.ssh/authorized_keys2" "$_n" "$_uid" "$_sh"
        fi
        [ -f "$(P "$_home/.ssh/rc")" ] && f HIGH ssh "$_home/.ssh/rc" "runs every time $_n logs in over SSH: $(lines "$(P "$_home/.ssh/rc")" | head -n 1 | cut -c1-160)" file
        [ -f "$(P "$_home/.ssh/environment")" ] && f MED ssh "$_home/.ssh/environment" "sets variables for $_n's SSH logins: $(lines "$(P "$_home/.ssh/environment")" | head -n 1 | cut -c1-120)" file
        if [ -f "$(P "$_home/.ssh/config")" ]; then
            _l=$(grep -Ei -m 1 '^[[:space:]]*(ProxyCommand|LocalCommand|PermitLocalCommand[[:space:]]+yes)' "$(P "$_home/.ssh/config")" | cut -c1-160)
            [ -n "$_l" ] && { if susp "$_l" || badpath "$_l"; then f HIGH ssh "$_home/.ssh/config" "$_n's ssh client runs a command when it connects: $_l" none; else f LOW ssh "$_home/.ssh/config" "$_n's ssh client runs a command when it connects: $_l" none; fi; }
        fi
    done <"$W/users"
}

# ---- shell startup files -------------------------------------------------------
# rc_file LOGICAL WHO -> line-by-line check of one startup file.
rc_file() {
    _rf=$(P "$1"); [ -f "$_rf" ] || return 0
    once "rc:$1" || return 0
    lines "$_rf" | awk -v who="$2" '
        function out(sev, why) { print sev "\t" why "\t" $0; done = 1 }    # awk: posix-ok
        {
            done = 0; l = $0
            if (l ~ /(^|[ \t;])(export[ \t]+)?LD_(PRELOAD|AUDIT)=/) out("HIGH", "loads an extra library into every program " who " starts")
            if (!done && l ~ /(^|[ \t;])(export[ \t]+)?PATH=["\047]?(\.|\/tmp|\/dev\/shm|\/var\/tmp)(:|\/)/) out("HIGH", "PATH starts with a world-writable folder: commands can be replaced")
            if (!done && match(l, /(^|[ \t;])alias[ \t]+[A-Za-z0-9_.-]+=/)) {
                a = substr(l, RSTART, RLENGTH); sub(/^[ \t;]*alias[ \t]+/, "", a); sub(/=$/, "", a)
                v = substr(l, RSTART + RLENGTH); gsub(/^["\047]/, "", v); full = v; sub(/[ \t"\047;].*/, "", full); first = full; sub(/.*\//, "", first)
                # "alias sudo=/tmp/x/sudo" keeps the name but not the program.
                if (first == a && full != a && full !~ /^\/(usr\/)?s?bin\//) first = full
                if (a ~ /^(sudo|su|ssh|scp|sftp|passwd|sshd|login|doas)$/ && first != a) out("HIGH", "replaces the " a " command (can steal passwords)")
                else if (a ~ /^(ls|ps|cat|netstat|ss|who|w|last|id|find|lsof|top|crontab|systemctl|history|iptables|nft)$/ && first != a && first != "command") out("MED", "replaces the " a " command (can hide things)")
            }
            if (!done && l ~ /^[ \t]*(function[ \t]+)?(sudo|su|ssh|passwd|doas)[ \t]*\(\)/) out("HIGH", "defines a function that replaces a login command (can steal passwords)")
            if (!done && l ~ /PROMPT_COMMAND=.*(curl|wget|nc[ \t]|\/tmp\/|\/dev\/|base64)/) out("HIGH", "runs a command before every prompt")
            if (!done && l ~ /(^|[ \t;])trap[ \t].*[ \t]DEBUG([ \t;]|$)/) out("MED", "runs a command before every command (trap DEBUG)")
            if (!done && l ~ /(unset[ \t]+HISTFILE|HISTFILE=\/dev\/null|HISTSIZE=0|HISTFILESIZE=0|set[ \t]+\+o[ \t]+history)/) out("MED", "turns command history off (hides what was typed)")
            if (!done && l ~ /(^|[ \t;(])(nohup|setsid)[ \t].*&[ \t]*$/) out("MED", "starts a background program at every login")
        }' >"$W/rl"
    while IFS="$(printf '\t')" read -r _sev _why _l; do f "$_sev" shell "$1" "$_why: $(printf '%s' "$_l" | cut -c1-200)" line "$_l"; done <"$W/rl"
    lines "$_rf" | grep -E "$SUSP" >"$W/cl"
    while IFS= read -r _l; do
        grep -qF "$(printf '%s' "$_l" | cut -c1-200)" "$W/rl" 2>/dev/null && continue
        f HIGH shell "$1" "runs at every login of $2: $(printf '%s' "$_l" | cut -c1-200)" line "$_l"
    done <"$W/cl"
    return 0
}
a_shell() {
    for _g in /etc/profile /etc/bash.bashrc /etc/bashrc /etc/zsh/zshrc /etc/zsh/zshenv /etc/zsh/zprofile /etc/zshrc /etc/csh.cshrc /etc/csh.login /etc/environment /etc/bash.bash_logout; do
        rc_file "$_g" everyone
    done
    for _g in "$(P /etc/profile.d)"/*; do
        [ -f "$_g" ] || continue
        _lg=$(L "$_g"); _before=$NFOUND
        rc_file "$_lg" everyone
        [ "$NFOUND" = "$_before" ] && unowned "$_lg" && { if recent "$_g"; then f MED shell "$_lg" "runs at every login of everyone; not from a package, changed in the last $SINCE day(s)" file; else f LOW shell "$_lg" "runs at every login of everyone; not from a package" file; fi; }
    done
    for _g in .bashrc .profile .bash_profile .bash_login .bash_logout .zshrc; do rc_file "/etc/skel/$_g" "every new account"; done
    while IFS='|' read -r _n _uid _gid _home _sh; do
        [ -n "$_home" ] && [ -d "$(P "$_home")" ] || continue
        case "$_home" in /|/bin|/sbin|/usr/sbin|/dev|/proc|/nonexistent) continue ;; esac
        for _g in .bashrc .bash_profile .bash_login .profile .bash_logout .bash_aliases .zshrc .zshenv .zprofile .zlogin .kshrc .cshrc .tcshrc .login .config/fish/config.fish; do
            rc_file "$_home/$_g" "$_n"
        done
    done <"$W/users"
}

# ---- preload and linker -----------------------------------------------------------
a_preload() {
    if [ -s "$(P /etc/ld.so.preload)" ]; then
        lines "$(P /etc/ld.so.preload)" >"$W/cl"
        while IFS= read -r _l; do
            _note="not from a package"; owned "$_l" && _note="the library itself is from a package, but check why it is here"
            f HIGH preload /etc/ld.so.preload "EVERY program on the box loads this library first: $_l ($_note). This is how userland rootkits hide files and processes" file
        done <"$W/cl"
    fi
    for _c in "$(P /etc/ld.so.conf)" "$(P /etc/ld.so.conf.d)"/*.conf; do
        [ -f "$_c" ] || continue
        lines "$_c" | grep -v '^include' >"$W/cl"
        while IFS= read -r _l; do
            if badpath "$_l" || printf '%s' "$_l" | grep -Eq '^(/home/|/root/|/var/www)'; then f HIGH preload "$(L "$_c")" "the linker also searches $_l for libraries (a place attackers can write)" line "$_l"; fi
        done <"$W/cl"
        unowned "$(L "$_c")" && recent "$_c" && f MED preload "$(L "$_c")" "linker config not from a package, changed in the last $SINCE day(s): $(lines "$_c" | head -n 1)" file
    done
    for _d in /etc/default /etc/sysconfig /etc/environment.d; do
        [ -d "$(P "$_d")" ] || continue
        grep -El 'LD_(PRELOAD|AUDIT)[[:space:]]*=' "$(P "$_d")"/* 2>/dev/null >"$W/cl"
        while IFS= read -r _c; do f HIGH preload "$(L "$_c")" "sets LD_PRELOAD for a service: $(grep -E -m 1 'LD_(PRELOAD|AUDIT)' "$_c" | cut -c1-160)" none; done <"$W/cl"
    done
    # Running programs that were started with LD_PRELOAD.
    if [ -n "$PROCROOT" ]; then
        for _e in "$PROCROOT"/[0-9]*/environ; do
            [ -r "$_e" ] || continue
            _v=$(tr '\000' '\n' 2>/dev/null <"$_e" | grep -E -m 1 '^LD_(PRELOAD|AUDIT)=') || continue
            _pid=${_e%/environ}; _pid=${_pid##*/}
            f HIGH preload "pid $_pid ($(cat "$PROCROOT/$_pid/comm" 2>/dev/null))" "running with $_v" none
        done
    fi
}

# ---- accounts and sudo -----------------------------------------------------------
a_accounts() {
    _pw=$(P /etc/passwd); _sd=$(P /etc/shadow)
    [ -r "$_pw" ] || { cc_show "$C_YEL" "  cannot read /etc/passwd"; return 0; }
    awk -F: '$3 == 0 && $1 != "root" { print $1 }' "$_pw" >"$W/cl"
    while IFS= read -r _u; do f HIGH accounts "$_u" "has UID 0: it IS root under another name (lock it with LX-39)" none; done <"$W/cl"
    awk -F: 'NF >= 7 && $2 != "x" && $2 != "*" && $2 != "!" && $2 != "" { print $1 }' "$_pw" >"$W/cl"
    while IFS= read -r _u; do f HIGH accounts "$_u" "has its password hash in /etc/passwd itself, where everyone can read it (and it overrides /etc/shadow)" none; done <"$W/cl"
    awk -F: 'NF >= 7 && $2 == "" { print $1 }' "$_pw" >"$W/cl"
    while IFS= read -r _u; do f HIGH accounts "$_u" "has an EMPTY password field in /etc/passwd: no password needed" none; done <"$W/cl"
    awk -F: '{ c[$3]++; n[$3] = n[$3] " " $1 } END { for (u in c) if (c[u] > 1 && u != 0) print u ":" n[u] }' "$_pw" >"$W/cl"
    while IFS= read -r _l; do f MED accounts "uid ${_l%%:*}" "more than one account shares this UID:${_l#*:}" none; done <"$W/cl"
    if [ -r "$_sd" ]; then
        # Never print a hash: only whether one is set.
        awk -F: 'NR == FNR { st[$1] = ($2 == "") ? "empty" : (($2 ~ /^[!*]/) ? "locked" : "set"); next }
                 NF >= 7 { print $1 "|" $3 "|" $7 "|" st[$1] }' "$_sd" "$_pw" >"$W/cl"
        while IFS='|' read -r _u _uid _sh _st; do
            case " $IGUSERS " in *" $_u "*) continue ;; esac
            if [ "$_st" = empty ] && ! nologin "$_sh"; then f HIGH accounts "$_u" "has NO password and a login shell: anyone can log in as it" none
            elif [ "$_st" = set ] && [ "$_uid" -gt 0 ] && [ "$_uid" -lt 1000 ] && ! nologin "$_sh"; then f HIGH accounts "$_u" "a service account (UID $_uid) with a password AND a login shell ($_sh): service accounts should have neither" none
            elif [ "$_st" = set ] && [ "$_uid" -gt 0 ] && [ "$_uid" -lt 1000 ]; then f MED accounts "$_u" "a service account (UID $_uid) has a password set (its shell is $_sh, so it cannot log in, but why a password?)" none
            fi
        done <"$W/cl"
    fi
    awk -F: 'NF >= 7 && $6 ~ /^(\/tmp|\/dev\/shm|\/var\/tmp)/ { print $1 "|" $6 }' "$_pw" >"$W/cl"
    while IFS='|' read -r _u _h; do f HIGH accounts "$_u" "its home folder is $_h, a world-writable place" none; done <"$W/cl"
    # Groups that amount to root.
    if [ -r "$(P /etc/group)" ]; then
        awk -F: '$1 ~ /^(docker|lxd|disk|shadow|root)$/ && $4 != "" { print $1 "|" $4 }' "$(P /etc/group)" >"$W/cl"
        while IFS='|' read -r _g _m; do f MED accounts "group $_g" "members can become root or read every password hash: $_m" none; done <"$W/cl"
        awk -F: '$1 ~ /^(sudo|wheel|admin)$/ && $4 != "" { print $1 "|" $4 }' "$(P /etc/group)" >"$W/cl"
        while IFS='|' read -r _g _m; do
            for _u in $(printf '%s' "$_m" | tr ',' ' '); do
                _uid=$(awk -F'|' -v u="$_u" '$1 == u { print $2 }' "$W/users")
                if [ -n "$_uid" ] && [ "$_uid" -gt 0 ] && [ "$_uid" -lt 1000 ]; then f HIGH accounts "$_u" "a service account is in the $_g group: it can become root" none
                else f LOW accounts "$_u" "is in the $_g group (can become root) - expected?" none; fi
            done
        done <"$W/cl"
    fi
    # sudoers.
    for _s in "$(P /etc/sudoers)" "$(P /etc/sudoers.d)"/*; do
        [ -f "$_s" ] || continue
        _ls=$(L "$_s"); case "$_ls" in */README) continue ;; esac
        _fix=none; case "$_ls" in /etc/sudoers.d/*) _fix="file" ;; esac
        lines "$_s" >"$W/cl"
        while IFS= read -r _l; do
            _who=$(printf '%s' "$_l" | awk '{ print $1 }')
            if printf '%s' "$_l" | grep -Eq '!authenticate|env_keep.*LD_|!env_reset|setenv'; then f HIGH accounts "$_ls" "sudo rule that skips the password or keeps LD_ variables: $_l" "$_fix"
            elif printf '%s' "$_l" | grep -Eq 'NOPASSWD:[[:space:]]*ALL'; then f HIGH accounts "$_ls" "$_who can run ANYTHING as root with no password: $_l" "$_fix"
            elif printf '%s' "$_l" | grep -q 'NOPASSWD'; then f MED accounts "$_ls" "$_who runs this as root with no password: $_l" "$_fix"
            elif printf '%s' "$_l" | grep -Eq '=[[:space:]]*\(?[A-Za-z: ]*\)?[[:space:]]*ALL[[:space:]]*$' && ! printf '%s' "$_who" | grep -Eq '^(root|%sudo|%wheel|%admin|Defaults.*)$'; then
                f MED accounts "$_ls" "$_who can run anything as root: $_l" "$_fix"
            fi
        done <"$W/cl"
        loose "$_s" && f HIGH accounts "$_ls" "someone other than root can change this sudoers file" none
        case "$_ls" in /etc/sudoers.d/*) unowned "$_ls" && recent "$_s" && ! grep -q "|$_ls|" "$W/findings" && f MED accounts "$_ls" "sudoers file not from a package, changed in the last $SINCE day(s): $(lines "$_s" | head -n 1)" file ;; esac
    done
}

# ---- PAM ---------------------------------------------------------------------------
a_pam() {
    for _p in "$(P /etc/pam.d)"/*; do
        [ -f "$_p" ] || continue
        _lp=$(L "$_p")
        lines "$_p" >"$W/cl"
        while IFS= read -r _l; do
            if printf '%s' "$_l" | grep -q 'pam_exec\.so'; then
                if susp "$_l" || badpath "$_l" || unowned "$_lp" || printf '%s' "$_l" | grep -Eq 'expose_authtok'; then f HIGH pam "$_lp" "runs a program at every login through this service (pam_exec; can capture passwords): $_l" line "$_l"
                else f MED pam "$_lp" "runs a program at every login through this service (pam_exec): $_l" line "$_l"; fi
            elif printf '%s' "$_l" | grep -Eq '^[[:space:]]*-?auth[[:space:]]+(sufficient|\[[^]]*success=(done|ok|[0-9])[^]]*\])[[:space:]]+pam_permit\.so'; then
                f HIGH pam "$_lp" "lets everyone in without checking a password (pam_permit as sufficient auth): $_l" line "$_l"
            elif printf '%s' "$_l" | grep -Eq '^[[:space:]]*-?auth[[:space:]]+sufficient[[:space:]]+pam_succeed_if\.so.*user'; then
                f HIGH pam "$_lp" "lets a named account in without a password: $_l" line "$_l"
            elif printf '%s' "$_l" | grep -Eq '[[:space:]]/(tmp|dev/shm|var/tmp|home|root|usr/local)/[^[:space:]]*\.so'; then
                f HIGH pam "$_lp" "loads a PAM module from an unusual place: $_l" line "$_l"
            elif printf '%s' "$_l" | grep -Eq 'pam_(python|script)\.so'; then f MED pam "$_lp" "runs a script at login: $_l" line "$_l"
            fi
        done <"$W/cl"
    done
    # PAM modules nobody packaged (a replaced pam_unix.so is caught by the package check).
    for _d in /lib/security /lib64/security /usr/lib/security /usr/lib64/security /lib/x86_64-linux-gnu/security /usr/lib/x86_64-linux-gnu/security /lib/aarch64-linux-gnu/security /usr/lib/aarch64-linux-gnu/security; do
        [ -d "$(P "$_d")" ] && [ ! -L "$(P "$_d")" ] || continue
        for _m in "$(P "$_d")"/*.so; do
            [ -f "$_m" ] || continue
            unowned "$(L "$_m")" && f HIGH pam "$(L "$_m")" "PAM module that is not from any package (a login backdoor lives here)" file
        done
    done
    if [ -f "$(P /etc/nsswitch.conf)" ]; then
        _l=$(grep -E '^[[:space:]]*(passwd|shadow|group):' "$(P /etc/nsswitch.conf)" | grep -Ev ':[[:space:]]*((files|compat|systemd|sss|ldap|nis|winbind|db|mymachines|myhostname|extrausers|cache|altfiles|\[[^]]*\])[[:space:]]*)+$' | head -n 1)
        [ -n "$_l" ] && f MED pam /etc/nsswitch.conf "accounts are also looked up through an unusual source: $_l" none
    fi
}

# ---- kernel ------------------------------------------------------------------------
a_kernel() {
    for _c in "$(P /etc/modules)" "$(P /etc/modules-load.d)"/*.conf; do
        [ -f "$_c" ] || continue
        _lc=$(L "$_c")
        lines "$_c" >"$W/cl"
        while IFS= read -r _m; do
            _m=$(printf '%s' "$_m" | awk '{ print $1 }')
            if [ "$LIVE" = 1 ] && cc_have modinfo && ! modinfo "$_m" >/dev/null 2>&1; then f HIGH kernel "$_lc" "loads module '$_m' at boot, but no such module ships with this kernel" line "$_m"
            elif unowned "$_lc"; then f LOW kernel "$_lc" "loads module '$_m' at boot (file not from a package)" none; fi
        done <"$W/cl"
    done
    for _c in "$(P /etc/modprobe.d)"/*; do
        [ -f "$_c" ] || continue
        lines "$_c" | grep -E '^[[:space:]]*(install|remove)[[:space:]]' | grep -Ev '[[:space:]](/usr)?/bin/(true|false)[[:space:]]*$' >"$W/cl"
        while IFS= read -r _l; do
            if susp "$_l" || badpath "$_l" || printf '%s' "$_l" | grep -Eq '(ba|da)?sh[[:space:]]+-c|curl|wget|nc[[:space:]]'; then f HIGH kernel "$(L "$_c")" "runs a command whenever this module is loaded: $_l" line "$_l"
            elif unowned "$(L "$_c")"; then f MED kernel "$(L "$_c")" "runs a command whenever this module is loaded (file not from a package): $_l" line "$_l"; fi
        done <"$W/cl"
    done
    # What the kernel runs for a crash, and to load a module.
    _cp=""; [ -r "$(P /proc/sys/kernel/core_pattern)" ] && _cp=$(cat "$(P /proc/sys/kernel/core_pattern)" 2>/dev/null)
    case "$_cp" in "|"*) printf '%s' "$_cp" | grep -Eq 'apport|systemd-coredump|abrt-hook|/usr/(lib|libexec|share)/' || f HIGH kernel /proc/sys/kernel/core_pattern "the kernel runs this as root whenever a program crashes: $_cp" none
                         badpath "$_cp" && f HIGH kernel /proc/sys/kernel/core_pattern "the crash handler is in a world-writable or hidden folder: $_cp" none ;; esac
    _mp=""; [ -r "$(P /proc/sys/kernel/modprobe)" ] && _mp=$(cat "$(P /proc/sys/kernel/modprobe)" 2>/dev/null)
    case "$_mp" in ''|/sbin/modprobe|/usr/sbin/modprobe|/bin/kmod|/usr/bin/kmod|/usr/bin/modprobe) ;; *) f HIGH kernel /proc/sys/kernel/modprobe "the kernel's module loader was changed to: $_mp (runs as root)" none ;; esac
    grep -Els 'core_pattern[[:space:]]*=[[:space:]]*\|' "$(P /etc/sysctl.conf)" "$(P /etc/sysctl.d)"/* 2>/dev/null >"$W/cl"
    while IFS= read -r _c; do
        _l=$(grep -E -m 1 'core_pattern' "$_c"); printf '%s' "$_l" | grep -Eq 'apport|systemd-coredump|abrt' || f HIGH kernel "$(L "$_c")" "sets a crash handler at every boot: $_l" line "$_l"
    done <"$W/cl"
    [ "$LIVE" = 1 ] || return 0
    # Loaded modules with no file on disk, and out-of-tree / unsigned ones.
    if cc_have lsmod && cc_have modinfo; then
        lsmod 2>/dev/null | awk 'NR > 1 { print $1 }' >"$W/cl"
        while IFS= read -r _m; do
            _fn=$(modinfo -n "$_m" 2>/dev/null)
            if [ -z "$_fn" ]; then f HIGH kernel "module $_m" "loaded in the kernel but there is no module file for it on disk (rootkits load like this)" none
            else case "$_fn" in /lib/modules/*|/usr/lib/modules/*|"(builtin)") ;; *) f HIGH kernel "module $_m" "loaded from an unusual place: $_fn" none ;; esac; fi
        done <"$W/cl"
    fi
    for _t in /sys/module/*/taint; do
        [ -r "$_t" ] || continue
        _tv=$(cat "$_t" 2>/dev/null); case "$_tv" in *O*|*E*) _m=${_t%/taint}; f MED kernel "module ${_m##*/}" "is out-of-tree or unsigned (taint $_tv): not part of the distribution's kernel" none ;; esac
    done
}

# ---- files -------------------------------------------------------------------------
a_files() {
    # Programs and scripts where anyone can write.
    for _d in /tmp /var/tmp /dev/shm /run/shm $SCANDIRS; do
        [ -d "$(P "$_d")" ] || continue
        _lim=60
        case "$_d" in /tmp|/var/tmp|/dev/shm|/run/shm)
            find "$(P "$_d")" -xdev -type f \( -perm -0100 -o -name '*.sh' -o -name '*.py' -o -name '*.pl' -o -name '*.php' -o -name '*.elf' -o -name '*.so' \) ! -path '*/systemd-private-*' 2>/dev/null | head -n "$_lim" >"$W/cl"
            while IFS= read -r _x; do f HIGH files "$(L "$_x")" "a program or script in a world-writable folder ($(ls -ld "$_x" 2>/dev/null | awk '{ print $1, $3 }'))" file; done <"$W/cl"
            find "$(P "$_d")" -xdev -mindepth 1 -maxdepth 2 -name '.*' ! -name '.X11-unix' ! -name '.ICE-unix' ! -name '.font-unix' ! -name '.XIM-unix' ! -name '.Test-unix' ! -name '.lock' 2>/dev/null | head -n 30 >"$W/cl"
            while IFS= read -r _x; do grep -qF "|$(L "$_x")|" "$W/findings" || f MED files "$(L "$_x")" "hidden $([ -d "$_x" ] && echo folder || echo file) in a world-writable folder" file; done <"$W/cl" ;;
        *)  # an extra folder you named: recently changed programs and scripts
            find "$(P "$_d")" -xdev -type f -mtime "-$SINCE" \( -perm -0100 -o -name '*.sh' -o -name '*.py' -o -name '*.pl' -o -name '*.so' \) 2>/dev/null | head -n "$_lim" >"$W/cl"
            while IFS= read -r _x; do
                if grep -Eq "$SUSP" "$_x" 2>/dev/null; then f HIGH files "$(L "$_x")" "contains: $(grep -E -m 1 "$SUSP" "$_x" | cut -c1-160)" file
                else f MED files "$(L "$_x")" "program or script changed in the last $SINCE day(s)" file; fi
            done <"$W/cl" ;;
        esac
    done
    # Folders named to be overlooked: "...", ".. ", " ".
    for _d in / /etc /usr /usr/bin /usr/sbin /usr/lib /usr/local /usr/share /var /var/lib /var/www /home /root /dev /opt /srv /boot /lib; do
        [ -d "$(P "$_d")" ] && [ ! -L "$(P "$_d")" ] || continue
        find "$(P "$_d")" -xdev -maxdepth 2 \( -name '...' -o -name '.. ' -o -name '. ' -o -name ' ' -o -name '..?*' \) 2>/dev/null | head -n 20 >"$W/cl"
        while IFS= read -r _x; do grep -qF "|$(L "$_x")|" "$W/findings" || f HIGH files "$(L "$_x")" "a name chosen to be overlooked in a listing" file; done <"$W/cl"
    done
    # Ordinary files in /dev (only device nodes belong there).
    if [ -d "$(P /dev)" ]; then
        find "$(P /dev)" -xdev -type f ! -path '*/shm/*' ! -path '*/mqueue/*' ! -path '*/.udev/*' ! -name '.udev*' ! -path '*/hugepages/*' 2>/dev/null | head -n 20 >"$W/cl"
        while IFS= read -r _x; do f HIGH files "$(L "$_x")" "an ordinary file in /dev, where only devices belong (a classic hiding place)" file; done <"$W/cl"
    fi
    # Commands shadowed by a copy that comes earlier in PATH.
    for _d in /usr/local/sbin /usr/local/bin; do
        for _x in "$(P "$_d")"/*; do
            [ -f "$_x" ] || continue
            _b=$(basename "$_x")
            for _sd in /usr/bin /bin /usr/sbin /sbin; do
                if [ -e "$(P "$_sd/$_b")" ]; then
                    _sev=LOW; case "$_b" in sudo|su|ssh|sshd|scp|passwd|login|ls|ps|netstat|ss|top|find|who|w|last|id|cat|crontab|systemctl|iptables|nft|lsmod|bash|sh) _sev=HIGH ;; esac
                    f "$_sev" files "$(L "$_x")" "comes before the real $_sd/$_b in PATH: typing '$_b' runs this instead" file; break
                fi
            done
        done
    done
    # System program folders: files nobody packaged.
    if [ "$OWNED_OK" = 1 ]; then
        for _d in /bin /sbin /usr/bin /usr/sbin; do
            [ -d "$(P "$_d")" ] && [ ! -L "$(P "$_d")" ] || continue
            # One pass against the package list (thousands of files here).
            find "$(P "$_d")" -maxdepth 1 -type f 2>/dev/null | sort | awk -v r="$R" -v of="$OWNEDF" '
                BEGIN { while ((getline l < of) > 0) o[l] = 1 }
                { p = $0; if (r != "" && index(p, r) == 1) p = substr(p, length(r) + 1)
                  alt = (p ~ /^\/usr\//) ? substr(p, 5) : "/usr" p
                  if (!(p in o) && !(alt in o)) print $0 }' >"$W/cl"
            _n=0
            while IFS= read -r _x; do
                _lx=$(L "$_x")
                _n=$((_n + 1)); [ "$_n" -gt 40 ] && break
                if recent "$_x"; then f HIGH files "$_lx" "a program in a system folder that is not from any package, changed in the last $SINCE day(s)" file
                else f MED files "$_lx" "a program in a system folder that is not from any package" file; fi
            done <"$W/cl"
        done
        for _d in /usr/local/lib /lib /usr/lib /lib64 /usr/lib64 /lib/x86_64-linux-gnu /usr/lib/x86_64-linux-gnu; do
            [ -d "$(P "$_d")" ] && [ ! -L "$(P "$_d")" ] || continue
            find "$(P "$_d")" -maxdepth 1 -type f -name '*.so*' -mtime "-$SINCE" 2>/dev/null | head -n 40 >"$W/cl"
            while IFS= read -r _x; do unowned "$(L "$_x")" && f MED files "$(L "$_x")" "a library not from any package, changed in the last $SINCE day(s) (preload rootkits are libraries)" file; done <"$W/cl"
        done
    fi
    # SUID / SGID.
    _roots="/"; [ -n "$R" ] && _roots="$R"
    find "$_roots" -xdev -type f \( -perm -4000 -o -perm -2000 \) ! -path "$CC_OUT/*" 2>/dev/null | head -n 400 >"$W/cl"
    while IFS= read -r _x; do
        _lx=$(L "$_x"); _b=$(basename "$_x")
        _what=SUID; [ -n "$(find "$_x" -prune -perm -4000 2>/dev/null)" ] || _what=SGID
        case "$_b" in
            bash|sh|dash|zsh|ksh|csh|tcsh|fish|find|vi|vim|vim.*|nano|ed|less|more|man|awk|gawk|mawk|sed|python*|perl*|ruby*|lua*|php*|node|nmap|cp|mv|dd|tar|zip|unzip|env|xargs|tee|cat|head|tail|nc|ncat|socat|gdb|strace|docker|tclsh|expect|busybox|rsync|curl|wget|make|git|openssl|base64|chmod|chown)
                f HIGH files "$_lx" "$_what on $_b: anyone who runs it gets root (see GTFOBins)" suid; continue ;;
        esac
        case "$_lx" in /tmp/*|/var/tmp/*|/dev/shm/*|/home/*|/root/*|/var/www/*|/opt/*|/srv/*) f HIGH files "$_lx" "$_what program in a place packages do not install to" suid; continue ;; esac
        if unowned "$_lx"; then f HIGH files "$_lx" "$_what program that is not from any package" suid; fi
    done <"$W/cl"
    # Python runs these at every start of the interpreter.
    for _d in /usr/lib /usr/local/lib /usr/lib64; do
        for _pd in "$(P "$_d")"/python3*; do
            [ -d "$_pd" ] || continue
            find "$_pd" -maxdepth 3 \( -name 'sitecustomize.py' -o -name 'usercustomize.py' -o -name '*.pth' \) -type f 2>/dev/null >"$W/cl"
            while IFS= read -r _x; do
                _lx=$(L "$_x"); unowned "$_lx" || continue
                case "$_x" in *.pth) grep -Eq '^import[[:space:]]|exec\(|os\.system|subprocess' "$_x" 2>/dev/null || continue ;; esac
                if grep -Eq "$SUSP|socket|subprocess|os\.system|exec\(" "$_x" 2>/dev/null; then f HIGH files "$_lx" "runs every time Python starts, not from a package: $(grep -E -m 1 'socket|subprocess|os\.system|exec\(|import' "$_x" | cut -c1-140)" file
                else f MED files "$_lx" "runs every time Python starts, not from a package" file; fi
            done <"$W/cl"
        done
    done
    [ "$LIVE" = 1 ] || return 0
    # Capabilities that amount to root.
    if cc_have getcap; then
        getcap -r / 2>/dev/null | grep -E 'cap_(setuid|setgid|sys_admin|dac_override|dac_read_search|sys_ptrace|sys_module|chown|fowner)' >"$W/cl"
        while IFS= read -r _l; do
            _x=$(printf '%s' "$_l" | awk '{ print $1 }')
            if unowned "$_x" || printf '%s' "$_x" | grep -Eq '/(python|perl|ruby|php|node|bash|sh|vim?|find|tar|gdb)[0-9.]*$'; then f HIGH files "$_x" "has a capability that amounts to root: $_l" none
            else f LOW files "$_x" "has a powerful capability: $_l" none; fi
        done <"$W/cl"
    fi
    # Immutable files: someone does not want them changed back.
    if cc_have lsattr; then
        for _x in /etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/crontab /etc/ld.so.preload /etc/rc.local /etc/hosts /etc/resolv.conf /etc/ssh/sshd_config /root/.ssh/authorized_keys /root/.bashrc; do
            [ -e "$_x" ] || continue
            lsattr -d "$_x" 2>/dev/null | awk '{ print $1 }' | grep -q i && f MED files "$_x" "is immutable (chattr +i): even root cannot change it until 'chattr -i' - who set that?" none
        done
    fi
    # Key system programs against their packages.
    if [ "$PKGCHECK" = 1 ]; then
        cc_show "$C_GRY" "  comparing key system programs with their packages ..."
        if cc_have dpkg && dpkg -V dpkg >/dev/null 2>&1; then
            for _pk in openssh-server openssh-client sudo login passwd coreutils bash dash util-linux procps net-tools iproute2 cron systemd libpam-modules libpam-runtime libpam0g libc6 findutils grep sed mawk gawk psmisc lsof iptables nftables curl wget tar gzip; do
                # "??5??????   /usr/bin/x": 5 = the contents differ.  Config files
                # (marked c) and missing docs are not what we are after.
                dpkg -V "$_pk" 2>/dev/null | awk '$1 ~ /5/ && $2 != "c" && $NF ~ /\/(bin|sbin|lib|lib64|libexec)\// { print $NF }'
            done | sort -u >"$W/cl"
        elif cc_have rpm; then
            rpm -V openssh-server openssh-clients sudo shadow-utils util-linux coreutils bash procps-ng net-tools iproute cronie systemd pam glibc findutils grep sed gawk psmisc lsof iptables nftables curl wget tar gzip 2>/dev/null | awk '$1 ~ /5/ && $2 != "c" && $NF ~ /\/(bin|sbin|lib|lib64|libexec)\// { print $NF }' | sort -u >"$W/cl"
        else : >"$W/cl"; fi
        while IFS= read -r _x; do
            [ -n "$_x" ] || continue
            f HIGH files "$_x" "does NOT match the file its package installed: it was replaced or modified (reinstall the package)" none
        done <"$W/cl"
    fi
}

# ---- running processes -------------------------------------------------------------
a_procs() {
    [ -n "$PROCROOT" ] || { cc_show "$C_GRY" "  (skipped under --root: no running system)"; return 0; }
    _self=$$
    for _pd in "$PROCROOT"/[0-9]*; do
        [ -d "$_pd" ] || continue
        _pid=${_pd##*/}; [ "$_pid" = "$_self" ] && continue
        _exe=$(readlink "$_pd/exe" 2>/dev/null) || _exe=""
        _comm=$(cat "$_pd/comm" 2>/dev/null) || _comm=""
        _cmd=$(tr '\000' ' ' 2>/dev/null <"$_pd/cmdline" | tr '|\n\r\t' '/   ' | cut -c1-200)
        [ -n "$_exe$_cmd" ] || continue
        # shellcheck disable=SC2012  # ls: the owner of /proc/PID is the account
        _usr=$(ls -ld "$_pd" 2>/dev/null | awk '{ print $3 }')
        _it="pid $_pid ($_comm, runs as $_usr)"
        case "$_exe" in
            *"(deleted)")
                case "$_exe" in /tmp/*|/var/tmp/*|/dev/shm/*|/run/shm/*|/home/*|/root/*|/memfd:*|"/ (deleted)") f HIGH procs "$_it" "its program file was deleted after it started (hiding): $_exe | $_cmd" pid "$_pid" ;;
                    *) f MED procs "$_it" "its program file was deleted or replaced since it started (also normal after a package update): $_exe" pid "$_pid" ;; esac
                continue ;;
            /tmp/*|/var/tmp/*|/dev/shm/*|/run/shm/*) f HIGH procs "$_it" "runs from a world-writable folder: $_exe | $_cmd" pid "$_pid"; continue ;;
            /memfd:*) f HIGH procs "$_it" "runs from memory only, with no file on disk: $_cmd" pid "$_pid"; continue ;;
        esac
        if printf '%s' "$_exe" | grep -Eq '/\.[^/]+/'; then f HIGH procs "$_it" "runs from a hidden folder: $_exe | $_cmd" pid "$_pid"; continue; fi
        case "$_cmd" in "["*"]"*) [ -n "$_exe" ] && { f HIGH procs "$_it" "is named like a kernel thread ($_cmd) but is a real program: $_exe" pid "$_pid"; continue; } ;; esac
        if susp "$_cmd"; then f HIGH procs "$_it" "is running: $_cmd" pid "$_pid"; continue; fi
        case "$_comm" in nc|ncat|netcat|nc.openbsd|nc.traditional|socat) f MED procs "$_it" "a netcat/socat is running: $_cmd" pid "$_pid" ;; esac
    done
    # Shells holding a network connection.
    _ss=${BT_SS:-$(cc_which ss)} || _ss=""
    if [ -n "$_ss" ]; then
        "$_ss" -tnpH state established 2>/dev/null | grep -E 'users:\(\("(ba|da|z|k)?sh"' >"$W/cl"
        while IFS= read -r _l; do
            _pid=$(printf '%s' "$_l" | sed -n 's/.*pid=\([0-9]*\).*/\1/p')
            f HIGH procs "pid $_pid (shell)" "a shell is holding a network connection (reverse shell?): $(printf '%s' "$_l" | awk '{ print $3, "<->", $4 }')" pid "$_pid"
        done <"$W/cl"
    fi
}

# ---- web ---------------------------------------------------------------------------
WEBSIG='eval[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|gzuncompress|str_rot13|stripslashes[[:space:]]*\([[:space:]]*\$_|\$_(POST|GET|REQUEST|COOKIE))|(system|passthru|shell_exec|exec|popen|proc_open|assert|create_function)[[:space:]]*\([^)]*\$_(POST|GET|REQUEST|COOKIE|SERVER)|\$_(POST|GET|REQUEST|COOKIE)\[[^]]*\][[:space:]]*\(|preg_replace[[:space:]]*\([[:space:]]*["'"'"']/[^/]*/[a-z]*e|FilesMan|c99shell|r57shell|WSOsetcookie|b374k|weevely|p0wny|Runtime\.getRuntime\(\)\.exec\([[:space:]]*request\.getParameter|ProcessBuilder\([[:space:]]*request\.getParameter|base64_decode[[:space:]]*\([[:space:]]*["'"'"'][A-Za-z0-9+/=]{300}|`[[:space:]]*\$_(POST|GET|REQUEST)'
a_web() {
    _wr=""
    for _d in /var/www /srv/www /srv/http /usr/share/nginx/html /usr/local/www /opt/lampp/htdocs /var/lib/tomcat*/webapps $SCANDIRS; do
        for _dd in $(P "$_d"); do [ -d "$_dd" ] && _wr="$_wr $_dd"; done
    done
    [ -n "$_wr" ] || { cc_show "$C_GRY" "  no web root found"; return 0; }
    # shellcheck disable=SC2086
    find $_wr -xdev -type f -size -2048k \( -name '*.php' -o -name '*.phtml' -o -name '*.php[0-9]' -o -name '*.phar' -o -name '*.inc' -o -name '*.jsp' -o -name '*.jspx' -o -name '*.asp' -o -name '*.aspx' -o -name '*.cgi' -o -name '*.pl' -o -name '*.py' -o -name '*.sh' \) 2>/dev/null | sort -u >"$W/web"
    cc_debug "web: $(grep -c . "$W/web") script(s) under$_wr"
    # Signatures first (xargs keeps the command line short).
    : >"$W/webhit"
    [ -s "$W/web" ] && tr '\n' '\000' <"$W/web" | xargs -0 grep -ElI "$WEBSIG" 2>/dev/null >"$W/webhit"
    while IFS= read -r _x; do
        f HIGH web "$(L "$_x")" "web shell code: $(grep -E -o -m 1 ".{0,30}($WEBSIG)" "$_x" 2>/dev/null | head -n 1 | cut -c1-150)" file
    done <"$W/webhit"
    _n=0
    while IFS= read -r _x; do
        grep -qxF "$_x" "$W/webhit" && continue
        _lx=$(L "$_x"); _b=$(basename "$_x")
        case "$_b" in .*) f HIGH web "$_lx" "a hidden script in a web folder" file; continue ;; esac
        if printf '%s' "$_lx" | grep -Eqi '/(uploads?|files|images?|img|media|tmp|cache|avatars?|attachments?)/'; then
            case "$_b" in *.php|*.phtml|*.php[0-9]|*.phar|*.jsp|*.jspx|*.asp|*.aspx|*.cgi) f HIGH web "$_lx" "a script inside an upload/media folder, where only data belongs" file; continue ;; esac
        fi
        if recent "$_x"; then
            _n=$((_n + 1)); [ "$_n" -le 40 ] && f MED web "$_lx" "web script changed in the last $SINCE day(s) - yours?" file
        fi
    done <"$W/web"
    [ "$_n" -gt 40 ] && cc_show "$C_YEL" "  ... $((_n - 40)) more recently changed web scripts not listed (a deploy? raise --since awareness or check with find -mtime)"
    # Settings that make the web server run code from somewhere else.
    # shellcheck disable=SC2086
    find $_wr -xdev -type f \( -name '.htaccess' -o -name '.user.ini' \) 2>/dev/null >"$W/cl"
    for _i in "$(P /etc/php)"/*/*/php.ini "$(P /etc/php.ini)" "$(P /etc/php)"/*/*/conf.d/*.ini; do [ -f "$_i" ] && printf '%s\n' "$_i" >>"$W/cl"; done
    while IFS= read -r _x; do
        _l=$(grep -Ei -m 1 '^[[:space:]]*(php_value[[:space:]]+)?auto_(prepend|append)_file[[:space:]]*=?[[:space:]]*[^[:space:];]' "$_x" 2>/dev/null | grep -Eiv '=[[:space:]]*(none|"")?[[:space:]]*$' | cut -c1-160)
        [ -n "$_l" ] && f HIGH web "$(L "$_x")" "every PHP page first runs another file: $_l" none
        case "$_x" in */.htaccess)
            _l=$(grep -Ei -m 1 '^[[:space:]]*(AddHandler|AddType|SetHandler)[[:space:]].*(php|cgi-script)' "$_x" 2>/dev/null | grep -Eiv '\.php[0-9]?([[:space:]]|$)' | cut -c1-160)
            [ -n "$_l" ] && f HIGH web "$(L "$_x")" "makes the server run other file types as code (an image upload becomes a shell): $_l" file ;;
        esac
    done <"$W/cl"
}

# ---- misc --------------------------------------------------------------------------
a_misc() {
    if [ -f "$(P /etc/aliases)" ]; then
        lines "$(P /etc/aliases)" | grep -E ':[[:space:]]*"?\|' >"$W/cl"
        while IFS= read -r _l; do
            if susp "$_l" || badpath "$_l"; then f HIGH misc /etc/aliases "mail to this address runs a program: $_l" line "$_l"
            else f MED misc /etc/aliases "mail to this address runs a program: $_l" line "$_l"; fi
        done <"$W/cl"
    fi
    while IFS='|' read -r _n _uid _gid _home _sh; do
        [ -n "$_home" ] || continue
        once "mailhome:$_home" || continue
        if [ -f "$(P "$_home/.forward")" ] && grep -q '|' "$(P "$_home/.forward")" 2>/dev/null; then
            f HIGH misc "$_home/.forward" "mail to $_n runs a program: $(grep -m 1 '|' "$(P "$_home/.forward")" | cut -c1-160)" file
        fi
        [ -f "$(P "$_home/.procmailrc")" ] && grep -Eq '^[[:space:]]*\|' "$(P "$_home/.procmailrc")" 2>/dev/null && f MED misc "$_home/.procmailrc" "mail to $_n is piped to a program" file
    done <"$W/users"
    for _p in "$(P /etc/polkit-1/rules.d)"/*.rules "$(P /usr/share/polkit-1/rules.d)"/*.rules; do
        [ -f "$_p" ] || continue
        unowned "$(L "$_p")" && grep -q 'polkit\.Result\.YES' "$_p" 2>/dev/null && f MED misc "$(L "$_p")" "polkit rule (not from a package) that answers YES: grants admin actions without a password" file
    done
    if [ "$LIVE" = 1 ] && [ -S /var/run/docker.sock ] && [ -n "$(find /var/run/docker.sock -prune -perm -0002 2>/dev/null)" ]; then
        f HIGH misc /var/run/docker.sock "the Docker socket is writable by everyone: anyone on the box is root" none
    fi
}

# ---- Run the areas -----------------------------------------------------------------
for _area in $ALL_AREAS; do
    want "$_area" || continue
    case "$_area" in
        cron)     area_start cron "scheduled jobs" ;;
        systemd)  area_start systemd "services, timers and overrides" ;;
        boot)     area_start boot "boot scripts and hook folders" ;;
        ssh)      area_start ssh "SSH keys and sshd settings" ;;
        shell)    area_start shell "shell startup files" ;;
        preload)  area_start preload "libraries forced into programs" ;;
        accounts) area_start accounts "accounts, groups and sudo" ;;
        pam)      area_start pam "login modules (PAM)" ;;
        kernel)   area_start kernel "kernel modules and kernel hooks" ;;
        files)    area_start files "planted programs, hidden files, SUID" ;;
        procs)    area_start procs "what is running right now" ;;
        web)      area_start web "web shells" ;;
        misc)     area_start misc "mail hooks and other corners" ;;
    esac
    "a_$_area"
    area_end
done

# ---- Results on disk ---------------------------------------------------------------
FCSV=$(cc_csv_new findings "number,severity,area,item,detail,can_remove")
for _sv in HIGH MED LOW; do
    awk -F'|' -v s="$_sv" '$2 == s' "$W/findings" >"$W/fs"
    while IFS='|' read -r _n _s _a _it _d _fk _fa; do cc_csv_row "$FCSV" "$_n" "$_s" "$_a" "$_it" "$(printf '%s' "$_d" | tr '\001' '|')" "$([ "$_fk" = none ] && echo no || echo "yes ($_fk)")"; done <"$W/fs"
done
cc_csv_pretty "$FCSV" "$CC_RUN_DIR/findings.txt" 110
# shellcheck disable=SC2034  # read by cc_flag_report
CC_FLAGS_SHOW="$CC_RUN_DIR/findings.txt"

# ---- Removal (only with --apply) ---------------------------------------------------
NFIX=$(awk -F'|' '($2 == "HIGH" || $2 == "MED") && $6 != "none"' "$W/findings" | grep -c .)
NDONE=0; NFAILED=0; APPLIED=0; TIMER_ON=0
_rmline() { grep -vxF -- "$2" "$1" >"$1.ccnew"; cat "$1.ccnew" >"$1"; _rs=$?; rm -f "$1.ccnew"; return "$_rs"; }
_quar() { mkdir -p "$(dirname "$2")" && mv "$1" "$2"; }
_kill() { kill "$1" 2>/dev/null; sleep 1; kill -0 "$1" 2>/dev/null && kill -9 "$1" 2>/dev/null; ! kill -0 "$1" 2>/dev/null; }
_nosuid() { chmod u-s,g-s "$1"; }
header "REMOVAL"
if [ "$NFIX" -eq 0 ]; then
    cc_show "$C_GRN" "  Nothing removable was found."
elif [ "$CC_APPLY" != 1 ]; then
    cc_show "$C_GRY" "  $NFIX finding(s) can be removed. Nothing was changed: run again with --apply to be asked about each one."
elif [ "$IS_ROOT" != 1 ] && [ -z "$R" ]; then
    cc_show "$C_YEL" "  Not root: cannot remove anything. Run with sudo."
else
    if [ -z "$R" ] && [ "$NOTIMER" != 1 ]; then
        cc_timer_start "$TIMER"; TIMER_ON=1
        cc_show "$C_YEL" "  [*] Revert timer started: everything removed in this run is put back in $((TIMER / 60)):$(printf '%02d' $((TIMER % 60))) unless you keep it at the end."
    fi
    cc_show "" "  $NFIX finding(s) can be removed. Removed files go to $CC_RUN_DIR/quarantine/ (nothing is deleted)."
    awk -F'|' '($2 == "HIGH" || $2 == "MED") && $6 != "none"' "$W/findings" | sort -t'|' -k2,2 -k1,1n >"$W/fixlist"
    while IFS='|' read -r _n _s _a _it _d _fk _fa; do
        _d=$(printf '%s' "$_d" | tr '\001' '|')
        _def=N; [ "$_s" = HIGH ] && [ "$YESHIGH" = 1 ] && _def=Y
        [ "$_fk" = pid ] && _def=N
        case "$_fk" in
            file) _q="Move it to quarantine?" ;;
            unit) _q="Stop and disable it, and move the unit file to quarantine?" ;;
            line) _q="Remove that line?" ;;
            suid) _q="Take the SUID/SGID bit off?" ;;
            pid)  _q="Kill that process? (this cannot be undone)" ;;
        esac
        cc_show "$([ "$_s" = HIGH ] && printf '%s' "$C_RED" || printf '%s' "$C_YEL")" "  #$_n [$_s] $_it"
        cc_show "" "        $_d"
        case "$_fk" in
            file) _yes="yes, move it to quarantine (it can be put back)" ;;
            unit) _yes="yes, stop and disable it, unit file to quarantine" ;;
            line) _yes="yes, remove that line (backup kept)" ;;
            suid) _yes="yes, take the SUID/SGID bit off" ;;
            pid)  _yes="yes, kill it" ;;
            *)    _yes="yes, do it" ;;
        esac
        cc_ask "$_q" "$_def" "$_yes" "no, leave it" || continue
        _src=$(P "$_it"); _rc=1
        case "$_fk" in
            file|unit)
                # A key or a unit that belongs to something on the protected list stays.
                if [ "$_fk" = unit ] && ! cc_guard service "$(basename "$_it" | sed 's/\.[a-z]*$//')"; then cc_show "$C_YEL" "        refused: on the protected list"; continue; fi
                if [ "$_fk" = unit ] && [ -z "$R" ] && cc_have systemctl; then
                    _ub=$(basename "$_it"); _was=""
                    systemctl is-enabled --quiet "$_ub" 2>/dev/null && _was=enable
                    systemctl is-active --quiet "$_ub" 2>/dev/null && _was="$_was start"
                    cc_run_quiet "stop and disable $_ub" systemctl disable --now "$_ub"
                    _undo_extra="systemctl daemon-reload"
                    for _w in $_was; do _undo_extra="$_undo_extra; systemctl $_w $(cc_shquote "$_ub")"; done
                    cc_undo_add "reload systemd and restore $_ub" "$_undo_extra"
                fi
                _dst="$CC_RUN_DIR/quarantine$_it"
                cc_run_quiet "quarantine $_it" _quar "$_src" "$_dst"; _rc=$?
                [ "$_rc" -eq 0 ] && cc_undo_add "put $_it back" "mv $(cc_shquote "$_dst") $(cc_shquote "$_src")"
                [ "$_fk" = unit ] && [ -z "$R" ] && cc_have systemctl && systemctl daemon-reload 2>/dev/null ;;
            line)
                cc_backup_file "$_src" && { cc_run_quiet "remove a line from $_it" _rmline "$_src" "$_fa"; _rc=$?; } ;;
            suid)
                _m=$(stat -c '%a' "$_src" 2>/dev/null)
                cc_run_quiet "remove SUID/SGID from $_it" _nosuid "$_src"; _rc=$?
                [ "$_rc" -eq 0 ] && [ -n "$_m" ] && cc_undo_add "restore the mode of $_it" "chmod $_m $(cc_shquote "$_src")" ;;
            pid)
                cc_run_quiet "kill pid $_fa" _kill "$_fa"; _rc=$? ;;
        esac
        if [ "$_rc" -eq 0 ]; then NDONE=$((NDONE + 1)); APPLIED=1; cc_show "$C_GRN" "        [+] done"
        else NFAILED=$((NFAILED + 1)); cc_show "$C_RED" "        [x] FAILED (see the log)"; fi
    done <"$W/fixlist"
    if [ "$APPLIED" = 1 ] && [ "$TIMER_ON" = 1 ]; then
        header "KEEP OR REVERT"
        cc_timer_finish || true
    elif [ "$TIMER_ON" = 1 ]; then
        cc_timer_cancel 2>/dev/null || true
    fi
fi

# ---- Summary -----------------------------------------------------------------------
{
    printf 'LX-42 Persistence sweep | host %s | %s\n' "$CC_HOST" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'Areas:%s | recent = last %s day(s)\n\n' "$( [ "$AREAS" = "$ALL_AREAS" ] && echo ' all' || echo " $AREAS")" "$SINCE"
    printf 'Found: %s HIGH, %s MED, %s LOW\n' "$N_H" "$N_M" "$N_L"
    printf 'By area (HIGH/MED/LOW):'
    awk -F'|' '{ printf "  %s %s/%s/%s", $1, $2, $3, $4 }' "$W/areas"; printf '\n\n'
    cc_flag_report 40
    printf '\n'
    if [ "$APPLIED" = 1 ]; then
        printf 'Removed: %s (failed: %s). Quarantine: %s/quarantine\n' "$NDONE" "$NFAILED" "$CC_RUN_DIR"
        if [ "$TIMER_ON" = 1 ]; then printf 'Put everything back at any time: sh %s/revert.sh --force\n' "$CC_RUN_DIR"; else printf 'Undo lines are in %s (newest at the bottom)\n' "$CC_UNDO"; fi
    elif [ "$NFIX" -gt 0 ]; then
        printf '%s finding(s) can be removed: run again with --apply to be asked about each one.\n' "$NFIX"
    fi
    printf 'Removing persistence does not remove the attacker: change passwords (LX-20) and check how they got in (LX-41).\n'
    printf 'Every finding, numbered: %s/findings.txt\nAll results: %s\n' "$CC_RUN_DIR" "$CC_RUN_DIR"
} >"$CC_RUN_DIR/summary.txt"
header "SUMMARY"
awk -v R="$C_RED" -v Y="$C_YEL" -v G="$C_GRN" -v C="$C_CYN" -v D="$C_GRY" -v O="$C_OFF" '
    NR <= 2                     { print C $0 O; next }
    /^Found: 0 HIGH, 0 MED/     { print G $0 O; next }
    /^Found: 0 HIGH/            { print Y $0 O; next }
    /^Found:/                   { print R $0 O; next }
    /^HIGH - /                  { m = "H"; print R $0 O; next }
    /^MED - /                   { m = "M"; print Y $0 O; next }
    /^  \[/ && m == "H"         { print R "  [!]" substr($0, 3) O; next }
    /^  \[/ && m == "M"         { print Y "  [*]" substr($0, 3) O; next }
    /^Removed:/                 { print G $0 O; next }
    /^(All |Every |By area|Flags:)/ { print D $0 O; next }
                                { print }
' "$CC_RUN_DIR/summary.txt"
cat "$CC_RUN_DIR/summary.txt" >>"$OUTF"
rm -rf "$W"
cc_finish
