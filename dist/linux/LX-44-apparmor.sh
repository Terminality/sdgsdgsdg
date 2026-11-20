#!/bin/sh
# =============================================================================
# ID:       LX-44
# NAME:     AppArmor confinement for the services
# ROLE:     Linux  (wave 2, after the services are hardened and backed up)
# KIND:     changes - dry run unless --apply
# VERSION:  1.1.0
#
# PURPOSE
#   AppArmor gives a program a list of what it may touch, and the kernel
#   holds it to that list even when the program is hacked.  With Apache
#   confined, a web shell inside it cannot run bash, read /root or write
#   outside the upload folders.  This puts the web server, PHP-FPM and the
#   database under AppArmor in three safe steps:
#
#     1 complain  the profile is loaded, NOTHING is blocked: AppArmor only
#                 logs what it would have blocked.  Use the site normally.
#     2 learn     the script reads those log lines and sorts them:
#                   normal       reads, libraries, network, capabilities -
#                                offered to add to the profile
#                   web code     writes into the site's own files - asked
#                                on their own (an upload or a web shell?)
#                   programs     programs it ran - NEVER added by the
#                                script (a web shell runs sh, curl, nc ...):
#                                listed for you
#                   secrets      /etc/shadow, keys, /root, writes into /etc
#                                or /usr, sys_module ... - NEVER added: [!]
#     3 enforce   when the log is clean: everything not in the profile is
#                 blocked.  The service is checked right after; if it
#                 stopped answering it goes back to complain on its own.
#
#   Profiles: the kit's own for apache2, nginx, php-fpm and mariadb/mysql
#   (written to /etc/apparmor.d/bt-*), or the one a package already ships
#   (php-fpm, mysqld) - then only its mode is changed.  Mail (Postfix,
#   Dovecot) runs many helper programs: not covered here.
#   On Rocky / Fedora / Red Hat (SELinux, not AppArmor) it says so and shows
#   SELinux now and after a reboot (/etc/selinux/config), with how to turn
#   it on; nothing is changed.  On Alpine (AppArmor off unless booted with
#   it) it says so and stops.
#
#   QUESTIONS (Enter takes the default in capitals; a flag answers each):
#     each service, by its state:
#       unconfined   [c]omplain (default) / [e]nforce now / [k]eep
#       complain     [l]earn / [e]nforce / [c] stay in complain
#       enforced     [k]eep (default) / [c] back to complain
#     loaded but the service runs outside it   [r]estart it / [k]eep
#     add the normal log lines? / the writes into web code?   (yes / no)
#     restart the service so it runs under its profile?        (yes / no)
#     apply?                                                   --apply
#
# USAGE
#   sudo sh LX-44-apparmor.sh                                  status + dry run
#   sudo sh LX-44-apparmor.sh --protected p.csv --apply        step by step
#   sudo sh LX-44-apparmor.sh --protected p.csv --apply --batch   (complain everything; learn and enforce never happen in --batch)
#
# OPTIONS
#   --apply            make the changes (without it, dry run only)
#   --services a,b     only these: apache2 nginx php-fpm mysql
#   --writable DIR     a folder the web server may write (repeatable;
#                      upload / cache folders of the apps are found anyway)
#   --url URL          the page checked after enforcing (default http://127.0.0.1/)
#   --timer SECONDS    revert countdown for enforce (default 120); --no-timer
#   --root DIR         treat DIR as / (tests): nothing loaded or restarted
#   --no-color         no colours
#   --help             this text plus the common options
#
# OUTPUTS  (under --out, in apparmor-N/)
#   output.txt, status.txt, plan.txt, summary.txt, run.txt, revert.sh
#   learned-NAME.txt   the log lines sorted for each profile
#
# DEPENDS ON
#   apparmor_parser (the apparmor package: installed by default on Ubuntu
#   and Debian).  apparmor-utils is NOT needed.  BT_AA_PARSER may name a
#   stand-in (tests).
#
# TESTED ON
#   Profiles checked with AppArmor 4.0's own parser; the questions, the
#   learning and the undo on a fake root, under dash, bash, busybox sh,
#   ksh93, mksh and yash with gawk, mawk and busybox awk.  The SELinux and
#   Alpine messages on a fake root (os-release, /sys/fs/selinux/enforce,
#   /etc/selinux/config).  NOT yet run on a
#   kernel with AppArmor switched on (the test box is a container): try the
#   whole complain - learn - enforce cycle on a practice VM first.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - Leave a service in complain while you use the site (log in, buy,
#     upload) - every page that is never visited is a rule never learned.
#   - Enforcing too early breaks features quietly: the home page loads but
#     image upload fails.  The check catches the home page only.
#   - A restart is needed for a running service to pick up a new profile.
# =============================================================================

# >>> BT-LIB  (lib/lib.sh 0.7.0 pasted in by tools/build.sh - edit lib/lib.sh, not this copy)
# =============================================================================
# ID:       LB-01
# NAME:     Shell library (lib.sh)
# ROLE:     Automation  (wave 0, foundation)
# VERSION:  0.7.0
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
CC_LIB_VERSION="0.7.0"

# State.  ':=' keeps a value the caller already exported (for example CC_DEBUG=1
# in the environment) and only fills in a default when the variable is empty.
: "${CC_APPLY:=0}"          # 0 = dry run (default), 1 = make changes
: "${CC_DEBUG:=0}"          # 1 = print DEBUG lines
: "${CC_QUIET:=0}"          # 1 = print only WARN and ERROR on screen
: "${CC_FORCE_SCORED:=0}"   # 1 = allowed to touch a protected *account*
: "${CC_NO_PROTECTED:=0}"   # 1 = operator accepted running with no list
: "${CC_OUT:=${BT_OUT:-}}"              # output folder (operator-chosen)
: "${CC_PROTECTED:=${BT_PROTECTED:-}}"  # protected-list file (protected.txt)
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
    _cc_csv_cleanup 2>/dev/null
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
  --protected FILE   the protected list (default: $BT_PROTECTED, else
                     DIR/protected.txt)
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
    # protected.txt; an old kit's protected.csv is still found.
    if [ -z "$CC_PROTECTED" ]; then
        CC_PROTECTED="$CC_OUT/protected.txt"
        [ ! -r "$CC_PROTECTED" ] && [ -r "$CC_OUT/protected.csv" ] && CC_PROTECTED="$CC_OUT/protected.csv"
    fi
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
# File format (protected.txt; see config/protected.example.txt), one entry a
# line, the parts split by spaces:
#     port     80/tcp          scored web site
#     service  apache2         scored web site
#     account  svc-web         used by the scoring engine
#     path     /var/www/html   scored content
#   An older comma-separated line (port,80/tcp,note) still works: a line whose
#   first word is followed by a comma is split on commas.
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
    awk -v want_type="$1" -v want_val="$2" '
        function clean(s) {    # this is awk, not shell: posix-ok
            gsub(/\r/, "", s); gsub(/^[ \t"]+|[ \t"]+$/, "", s)
            return tolower(s)
        }
        BEGIN { want_type = clean(want_type); want_val = clean(want_val); hit = 1 }
        /^[ \t]*#/ || /^[ \t\r]*$/ { next }
        {
            if ($0 ~ /^[ \t"]*[^ \t,]+[ \t"]*,/) split($0, f, ","); else split($0, f)
            t = clean(f[1]); v = clean(f[2])
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

# cc_csv_table CSV TXT
#   Write CSV as a " | " table (the look SH-03 uses): the header as it is, every
#   value whole, columns padded.  SH-04 compares two runs from these tables.
#   A "|" inside a value becomes "/".
cc_csv_table() {
    [ -f "$1" ] || return 0
    awk "$CC_AWK_CSV"'{ n = csvsplit($0, f); l = ""
        for (i = 1; i <= n; i++) { v = f[i]; gsub(/\|/, "/", v); gsub(/[\r\n]/, " ", v); l = l (i > 1 ? " | " : "") v }
        print l }' "$1" >"$2" && cc_table_align "$2"
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
# ---- Which box is this -------------------------------------------------------
# One list of box kinds for every script (--box NAME and the question).
CC_BOXES="splunk webmail ecomm fileshare gitea web other"
# cc_box_valid NAME -> 0 if NAME is empty or a known box kind.
cc_box_valid() { case "$1" in ''|splunk|webmail|ecomm|fileshare|gitea|web|other) return 0 ;; esac; return 1; }
# cc_box_detect [ROOT] -> CC_BOX_GUESS (a box kind or "") and CC_BOX_WHY (the
#   file that shows it).  Only looks at files; changes nothing.
cc_box_detect() {
    _cc_bd_r=${1:-}; CC_BOX_GUESS=""; CC_BOX_WHY=""
    _cc_bd() { for _cc_bd_f in "$@"; do [ -e "$_cc_bd_r$_cc_bd_f" ] && { CC_BOX_WHY=$_cc_bd_f; return 0; }; done; return 1; }
    if _cc_bd /opt/splunk/bin/splunk /opt/splunk/etc; then CC_BOX_GUESS=splunk
    elif _cc_bd /etc/roundcube /var/lib/roundcube /usr/share/roundcube /usr/share/webapps/roundcube /var/www/roundcube /var/www/html/roundcube /usr/share/roundcubemail; then CC_BOX_GUESS=webmail
    elif [ -e "$_cc_bd_r/etc/postfix/main.cf" ] && [ -e "$_cc_bd_r/etc/dovecot/dovecot.conf" ]; then CC_BOX_GUESS=webmail; CC_BOX_WHY="postfix and dovecot"
    elif _cc_bd /etc/gitea/app.ini /var/lib/gitea/custom/conf/app.ini /usr/local/bin/gitea /usr/bin/gitea /opt/gitea; then CC_BOX_GUESS=gitea
    elif [ -r "$_cc_bd_r/etc/samba/smb.conf" ] && grep -Eiv '^[[:space:]]*\[(global|homes|printers|print\$)\]' "$_cc_bd_r/etc/samba/smb.conf" 2>/dev/null | grep -Eq '^[[:space:]]*\['; then CC_BOX_GUESS=fileshare; CC_BOX_WHY="shares in /etc/samba/smb.conf"
    elif [ -r "$_cc_bd_r/etc/exports" ] && grep -Eq '^[[:space:]]*/' "$_cc_bd_r/etc/exports" 2>/dev/null; then CC_BOX_GUESS=fileshare; CC_BOX_WHY="exports in /etc/exports"
    elif _cc_bd /etc/nginx/nginx.conf /etc/apache2/apache2.conf /etc/apache2/httpd.conf /etc/httpd/conf/httpd.conf /etc/lighttpd/lighttpd.conf /etc/caddy/Caddyfile; then CC_BOX_GUESS=web
    fi
}
# cc_box_ask DEFAULT [ROOT] [QUESTION]
#   Sets BOX (a box kind) when it is empty: the same question in every script,
#   with the guess from cc_box_detect as the answer for Enter.  DEFAULT is the
#   script's own default letter (s w e f g b o); a guess only replaces it when
#   it is sure (splunk, webmail, gitea, fileshare), or the default is "other".
cc_box_ask() {
    [ -n "${BOX:-}" ] && return 0
    _cc_ba_d=$1; cc_box_detect "${2:-}"
    case "$CC_BOX_GUESS" in
        splunk)    _cc_ba_g=s ;; webmail) _cc_ba_g=w ;; gitea) _cc_ba_g=g ;; fileshare) _cc_ba_g=f ;;
        web)       _cc_ba_g=b; [ "$_cc_ba_d" = o ] || _cc_ba_g="" ;;
        *)         _cc_ba_g="" ;;
    esac
    [ -n "$CC_BOX_GUESS" ] && cc_show "${C_GRY:-}" "  This box looks like: $CC_BOX_GUESS ($CC_BOX_WHY)"
    [ -n "$_cc_ba_g" ] && _cc_ba_d=$_cc_ba_g
    cc_choose "${3:-Which box is this?}" "$_cc_ba_d" "s=splunk" "w=webmail" "e=ecomm" "f=fileshare: Samba or NFS" "g=gitea" "b=web: a ticket, help-desk or shop site" "o=other"
    case "$CC_CHOICE" in s) BOX=splunk ;; w) BOX=webmail ;; e) BOX=ecomm ;; f) BOX=fileshare ;; g) BOX=gitea ;; b) BOX=web ;; *) BOX=other ;; esac
}

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
    _cc_csv_cleanup
    exit "$_cc_fin_rc"
}

# _cc_csv_cleanup -> no CSV files are left in the results.  The CSV files a
#   script builds while it runs (cc_csv_new, cc_flag, cc_finding) are working
#   files: at the end each becomes a .txt table, unless the script already
#   wrote one with that name, and is deleted, with the csv/ folder.
_cc_csv_cleanup() {
    [ "${BT_TEST_KEEP_CSV:-0}" = 1 ] && return 0   # tests only: read the rows as written
    if [ -n "${CC_RUN_DIR:-}" ] && [ -d "$CC_RUN_DIR" ]; then
        for _cc_cu_f in "$CC_RUN_DIR"/*.csv "$CC_RUN_DIR"/csv/*.csv; do
            [ -f "$_cc_cu_f" ] || continue
            _cc_cu_t="$CC_RUN_DIR/$(basename "$_cc_cu_f" .csv).txt"
            [ -f "$_cc_cu_t" ] || cc_csv_pretty "$_cc_cu_f" "$_cc_cu_t" 200
            rm -f "$_cc_cu_f"
        done
        rmdir "$CC_RUN_DIR/csv" 2>/dev/null
    fi
    # Without a run folder they sit in the out folder as <ID>_<host>_<time>_NAME.csv.
    if [ -n "${CC_OUT:-}" ] && [ -n "${CC_ID:-}" ] && [ -n "${CC_TS:-}" ]; then
        for _cc_cu_f in "$CC_OUT/${CC_ID}_${CC_HOST}_${CC_TS}_"*.csv; do
            [ -f "$_cc_cu_f" ] || continue
            [ -f "${_cc_cu_f%.csv}.txt" ] || cc_csv_pretty "$_cc_cu_f" "${_cc_cu_f%.csv}.txt" 200
            rm -f "$_cc_cu_f"
        done
    fi
    return 0
}
# <<< BT-LIB

usage() {
    cat <<'USAGE'
LX-44 AppArmor confinement - web server, PHP and database: complain, learn, enforce
  sudo sh LX-44-apparmor.sh                             status + dry run
  sudo sh LX-44-apparmor.sh --protected p.csv --apply   step by step

  --apply            make the changes (without it, dry run only)
  --services a,b     only these: apache2 nginx php-fpm mysql
  --writable DIR     a folder the web server may write (repeatable)
  --url URL          page checked after enforcing (default http://127.0.0.1/)
  --timer SECONDS    revert countdown for enforce (default 120); --no-timer
  --root DIR         treat DIR as / (tests)
  --no-color         no colours
  --help             show this text
USAGE
    cc_usage_common
}

NL='
'
ONLY=""; WRITABLE=""; URL="http://127.0.0.1/"; TIMER=120; NOTIMER=0; R=""; COLOR=1
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --apply)    CC_APPLY=1; shift ;;
        --services) [ $# -ge 2 ] || cc_die 2 "--services needs a list"; ONLY="$ONLY,$2"; shift 2 ;;
        --writable) [ $# -ge 2 ] || cc_die 2 "--writable needs a folder"; WRITABLE="$WRITABLE$2$NL"; shift 2 ;;
        --url)      [ $# -ge 2 ] || cc_die 2 "--url needs an address"; URL=$2; shift 2 ;;
        --timer)    [ $# -ge 2 ] || cc_die 2 "--timer needs seconds"; TIMER=$2; shift 2 ;;
        --no-timer) NOTIMER=1; shift ;;
        --root)     [ $# -ge 2 ] || cc_die 2 "--root needs a folder"; [ -d "$2" ] || cc_die 2 "--root: not a folder: $2"; R=$(cd "$2" && pwd); [ "$R" = / ] && R=""; shift 2 ;;
        --no-color|--no-colour) COLOR=0; shift ;;
        --help|-h)  usage; exit 0 ;;
        *)          cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
case "$TIMER" in ''|*[!0-9]*) cc_die 2 "--timer needs a whole number" ;; esac
for _s in $(printf '%s' "$ONLY" | tr ',' ' '); do case "$_s" in apache2|nginx|php-fpm|mysql) ;; *) cc_die 2 "--services: apache2, nginx, php-fpm or mysql" ;; esac; done
printf '%s' "$WRITABLE" | grep -q '[^A-Za-z0-9/._@*{},-]' && cc_die 2 "--writable: a plain folder path"

cc_init "LX-44" "AppArmor confinement" changes
cc_detect_os
# shellcheck disable=SC2034  # read by cc_color_init
[ "$COLOR" = 1 ] || CC_NOCOLOR=1
cc_color_init
cc_use_numbered_dir apparmor
rmdir "$CC_RUN_DIR/raw" 2>/dev/null
OUTF="$CC_RUN_DIR/output.txt"
grep -v '\[NOTE\]\|\[DEBUG\]' "$CC_LOG" >"$OUTF" 2>/dev/null || : >"$OUTF"
# shellcheck disable=SC2034  # CC_TEE is read by the library's log functions
CC_TEE=$OUTF
W="$CC_RUN_DIR/.work"; mkdir -p "$W"
header() { cc_show "" ""; cc_show "$C_CYN" "==========[ $1 ]=========="; }
P() { printf '%s%s' "$R" "$1"; }
AAD=$(P /etc/apparmor.d); STATE=$(P /var/lib/bt/apparmor)
# A full path: the revert timer may run the undo lines with a short PATH.
PARSER=${BT_AA_PARSER:-$(cc_which apparmor_parser 2>/dev/null || echo apparmor_parser)}

cc_show "$C_CYN" "LX-44 AppArmor confinement | host $CC_HOST | results in $CC_RUN_DIR"
cc_show "" "Legend: ${C_RED}[!]${C_OFF} fix now   ${C_YEL}[*]${C_OFF} look at it   ${C_GRN}[ok]${C_OFF} fine   ${C_YEL}[~] would change${C_OFF}   ${C_GRN}[+] changed${C_OFF}   ${C_RED}[x] failed${C_OFF}"
[ -n "$R" ] && cc_show "$C_GRY" "Acting on $R as if it were / (nothing loaded or restarted)"

# ---- Is AppArmor there? ---------------------------------------------------------------------
header "1/5  AppArmor on this box"
AAON=n; [ "$(cat "$(P /sys/module/apparmor/parameters/enabled)" 2>/dev/null)" = Y ] && AAON=y
if [ "$AAON" != y ]; then
    # Which kind of box: from --root's os-release in tests, else this one's.
    _fam=$CC_OS_FAMILY
    if [ -n "$R" ] && [ -r "$R/etc/os-release" ]; then
        case " $(sed -n 's/^ID=//p; s/^ID_LIKE=//p' "$R/etc/os-release" | tr -d '"' | tr '\n' ' ') " in
            *" alpine "*) _fam=alpine ;; *" rhel "*|*" fedora "*|*" rocky "*|*" centos "*) _fam=rhel ;; *) _fam=other ;;
        esac
    fi
    if cc_selinux_on || [ -f "$(P /etc/selinux/config)" ] || [ "$_fam" = rhel ]; then
        # Rocky, Fedora: SELinux does this job.  Its state now, and after a reboot.
        if [ -z "$R" ] && cc_have getenforce; then _se=$(getenforce 2>/dev/null)
        else case "$(cat "$(P /sys/fs/selinux/enforce)" 2>/dev/null)" in 1) _se=Enforcing ;; 0) _se=Permissive ;; *) _se=Disabled ;; esac; fi
        _sc=$(sed -n 's/^[[:space:]]*SELINUX[[:space:]]*=[[:space:]]*//p' "$(P /etc/selinux/config)" 2>/dev/null | tr -d '"' | tail -n 1)
        cc_show "" "  This box uses SELinux, not AppArmor: LX-44 has nothing to do here."
        cc_show "$([ "$_se" = Enforcing ] && printf '%s' "$C_GRN" || printf '%s' "$C_RED")" "  $([ "$_se" = Enforcing ] && echo '[ok]' || echo '[!]') SELinux now: $_se   (after a reboot: ${_sc:-not set in /etc/selinux/config})"
        case "$_se" in
            Permissive) cc_show "" "  Turn it on: setenforce 1 (now) and SELINUX=enforcing in /etc/selinux/config. Test the scored services right after; a denial is in /var/log/audit/audit.log (ausearch -m avc -ts recent)." ;;
            Disabled)   cc_show "" "  It is off in the kernel: turning it on needs SELINUX=permissive in /etc/selinux/config, touch /.autorelabel and a reboot (the relabel can take minutes). Plan it; do not do it mid-round." ;;
        esac
        [ "$_se" = Enforcing ] && [ -n "$_sc" ] && [ "$_sc" != enforcing ] && cc_show "$C_YEL" "  [*] /etc/selinux/config says $_sc: a reboot turns enforcing off. Set SELINUX=enforcing there."
    elif [ "$_fam" = alpine ]; then
        # Alpine's kernel can run AppArmor, but only when booted with it.
        cc_show "$C_YEL" "  [*] Alpine: AppArmor is off unless the box is booted with it (apk add apparmor; apparmor=1 security=apparmor on the kernel line; reboot). A reboot mid-round is not worth it: nothing to do here."
    else
        cc_show "$C_YEL" "  [*] AppArmor is not switched on in this kernel (a container, or apparmor=0 at boot). Nothing to do here."
    fi
    rm -rf "$W"; cc_finish; exit 0
fi
cc_have "$PARSER" || [ -x "$PARSER" ] || { cc_show "$C_RED" "  [x] apparmor_parser is missing: $([ "$CC_PKG" = apk ] && echo apk add apparmor || echo apt-get install apparmor)"; rm -rf "$W"; cc_finish; exit 3; }
_np=$(grep -c . "$(P /sys/kernel/security/apparmor/profiles)" 2>/dev/null)
cc_show "$C_GRN" "  [ok] AppArmor is on ($_np profiles loaded)"

# ---- The services ---------------------------------------------------------------------------
# kind|binaries (first found)|our profile name|service names|check
cat >"$W/svcs" <<'EOF'
apache2|/usr/sbin/apache2|bt-apache2|apache2|http
nginx|/usr/sbin/nginx|bt-nginx|nginx|http
php-fpm|/usr/sbin/php-fpm8.4 /usr/sbin/php-fpm8.3 /usr/sbin/php-fpm8.2 /usr/sbin/php-fpm8.1 /usr/sbin/php-fpm8.0 /usr/sbin/php-fpm7.4 /usr/sbin/php-fpm|bt-php-fpm|php8.4-fpm php8.3-fpm php8.2-fpm php8.1-fpm php8.0-fpm php7.4-fpm php-fpm|http
mysql|/usr/sbin/mariadbd /usr/sbin/mysqld|bt-mysqld|mariadb mysql|mysql
EOF
# The writable folders for the web: upload, cache and session folders of the apps.
{
    printf '%s' "$WRITABLE"
    for _d in /var/www /srv/www /srv/http; do
        [ -d "$(P "$_d")" ] || continue
        find "$(P "$_d")" -maxdepth 5 -type d \( -path '*/wp-content/uploads' -o -path '*/wp-content/cache' -o -path '*/wp-content/upgrade' \
            -o -path '*/img' -o -path '*/upload' -o -path '*/uploads' -o -path '*/cache' -o -path '*/var/cache' -o -path '*/var/logs' -o -path '*/tmp' \
            -o -path '*/system/storage' -o -path '*/image/cache' -o -path '*/sites/default/files' -o -path '*/pub/media' \) 2>/dev/null | sed "s|^$R||"
    done
} | grep . | sort -u >"$W/writable"
# kernel_mode PROFILE -> enforce | complain | (nothing: not loaded)
kernel_mode() { awk -v p="$1" '{ n = $0; sub(/ \(.*$/, "", n) } n == p { m = $NF; gsub(/[()]/, "", m); print m; exit }' "$(P /sys/kernel/security/apparmor/profiles)" 2>/dev/null; }
# proc_label KIND -> the AppArmor label of the running service ("unconfined", "bt-apache2 (complain)")
proc_label() {
    if [ -n "$R" ]; then cat "$R/run/bt-test/$1.label" 2>/dev/null; return; fi
    _pid=$(pgrep -o -x "$(basename "$2")" 2>/dev/null)
    [ -n "$_pid" ] || return 0
    cat "/proc/$_pid/attr/apparmor/current" 2>/dev/null || cat "/proc/$_pid/attr/current" 2>/dev/null
}
# packaged BIN -> "FILE|NAME" of a profile a package ships for BIN (not ours):
# "profile NAME /path {" or "/path {", the path may end in * (php-fpm*).
packaged() {
    for _pf in "$AAD"/*; do
        [ -f "$_pf" ] || continue
        case "$_pf" in */bt-*|*.dpkg-*|*~) continue ;; esac
        awk -v b="$1" -v f="$_pf" '
            { sub(/^[ \t]+/, "") }
            /^profile[ \t]/ { n = $2; a = $3 } /^\// { n = $1; a = $1 }
            n != "" && a ~ /^\// {
                if (a == b || (a ~ /\*$/ && index(b, substr(a, 1, length(a) - 1)) == 1)) { print f "|" n; exit }
                n = ""
            }' "$_pf"
    done | head -n 1
}

# ---- The profiles -----------------------------------------------------------------------------
# write_profile KIND BIN NAME MODE -> the profile text on stdout
write_profile() {
    _flags=""; [ "$4" = complain ] && _flags=" flags=(complain)"  # posix-ok: AppArmor text, not an array
    printf '# Written by LX-44 (%s).  Learned rules go in local/%s.\n# Delete this file and run "apparmor_parser -R" on it to remove.\nabi <abi/3.0>,\ninclude <tunables/global>\n\nprofile %s %s%s {\n' "$1" "$3" "$3" "$2" "$_flags"
    printf '  include <abstractions/base>\n  include <abstractions/nameservice>\n  include <abstractions/openssl>\n  include <abstractions/ssl_certs>\n'
    case "$1" in
        apache2|nginx|php-fpm)
            printf '  include <abstractions/ssl_keys>\n'
            [ "$1" = apache2 ] && printf '  include <abstractions/apache2-common>\n  include <abstractions/php>\n'
            [ "$1" = php-fpm ] && printf '  include <abstractions/php>\n'
            printf '  capability dac_override,\n  capability dac_read_search,\n  capability net_bind_service,\n  capability setgid,\n  capability setuid,\n  capability chown,\n  capability fowner,\n  capability kill,\n  capability sys_resource,\n'
            printf '  network inet stream,\n  network inet6 stream,\n  network inet dgram,\n  network inet6 dgram,\n  network unix stream,\n  network unix dgram,\n  network netlink raw,\n'
            printf '  signal (send, receive) peer=%s,\n\n' "$3"
            printf '  %s mrix,\n' "$2"
            case "$1" in
                apache2) printf '  /usr/lib/apache2/** mr,\n  /etc/apache2/** r,\n  /var/log/apache2/** rw,\n  /{,var/}run/apache2/** rwk,\n  /var/lib/apache2/** rwk,\n  /var/cache/apache2/** rwk,\n' ;;
                nginx) printf '  /usr/lib/nginx/** mr,\n  /usr/share/nginx/** r,\n  /etc/nginx/** r,\n  /var/log/nginx/** rw,\n  /var/lib/nginx/** rwk,\n  /{,var/}run/nginx.pid rw,\n  /{,var/}run/php/*.sock rw,\n' ;;
                php-fpm) printf '  /{,var/}run/php/** rwk,\n  /var/log/php*-fpm.log rw,\n' ;;
            esac
            printf '  /usr/lib/php/** mr,\n  /etc/php/** r,\n  /etc/mime.types r,\n  /usr/share/** r,\n  /var/lib/php/** rwk,\n  /tmp/** rwk,\n  /var/tmp/** rwk,\n'
            printf '  @{PROC}/@{pid}/** r,\n  @{PROC}/sys/kernel/random/* r,\n  /sys/devices/system/cpu/** r,\n\n'
            printf '  # The sites: read only.\n  /var/www/ r,\n  /var/www/** r,\n  /srv/** r,\n  /usr/share/roundcube/** r,\n  /etc/roundcube/** r,\n'
            printf '  /var/lib/roundcube/** rwk,\n  /var/log/roundcube/** rw,\n'
            printf '  # PHP mail() through Postfix.\n  /usr/sbin/sendmail ix,\n  /usr/sbin/postdrop ix,\n  /etc/postfix/** r,\n  /var/spool/postfix/maildrop/** rw,\n  /var/spool/postfix/public/pickup w,\n'
            printf '  # Folders the site may write (uploads, caches).\n'
            if [ -s "$W/writable" ]; then while IFS= read -r _wd; do printf '  %s/ rw,\n  %s/** rwk,\n' "$_wd" "$_wd"; done <"$W/writable"; else printf '  # (none found)\n'; fi
            printf '\n  # Not allowed, on purpose: running a shell or a download tool.\n  # That is what a web shell does; the learning step never adds it.\n' ;;
        mysql)
            printf '  capability dac_override,\n  capability setgid,\n  capability setuid,\n  capability sys_resource,\n  capability sys_nice,\n  capability ipc_lock,\n  capability chown,\n'
            printf '  network inet stream,\n  network inet6 stream,\n  network unix stream,\n  network unix dgram,\n  network netlink raw,\n\n'
            printf '  %s mr,\n  /etc/mysql/** r,\n  /usr/share/mysql/** r,\n  /usr/share/mariadb/** r,\n  /usr/lib/mysql/plugin/* mr,\n' "$2"
            printf '  /var/lib/mysql/ r,\n  /var/lib/mysql/** rwk,\n  /var/log/mysql/** rw,\n  /{,var/}run/mysqld/** rwk,\n  /tmp/** rwk,\n'
            printf '  @{PROC}/@{pid}/** r,\n  @{PROC}/sys/kernel/random/* r,\n  /sys/devices/system/cpu/** r,\n  /sys/devices/system/node/** r,\n  /sys/fs/cgroup/** r,\n  @{PROC}/sys/fs/** r,\n' ;;
    esac
    printf '\n  include if exists <local/%s>\n}\n' "$3"
}

# ---- Log lines for a profile ----------------------------------------------------------------
# events PROFILE SINCE-EPOCH -> "KIND|op|name|mask|extra" lines (KIND: ALLOWED/DENIED)
events() {
    for _l in "$(P /var/log/audit/audit.log)" "$(P /var/log/kern.log)" "$(P /var/log/syslog)"; do [ -r "$_l" ] && cat "$_l"; done 2>/dev/null >"$W/logs"
    grep -q 'apparmor=' "$W/logs" 2>/dev/null || { [ -z "$R" ] && cc_have journalctl && journalctl -k --no-pager -o cat 2>/dev/null >>"$W/logs"; }
    awk -v p="$1" -v since="${2:-0}" '
        /apparmor="(ALLOWED|DENIED)"/ && index($0, "profile=\"" p "\"") {
            t = 0; if (match($0, /audit\([0-9]+/)) t = substr($0, RSTART + 6, RLENGTH - 6) + 0
            if (t && t < since) next
            k = ($0 ~ /apparmor="ALLOWED"/) ? "ALLOWED" : "DENIED"
            op = v("operation"); nm = v("name"); mk = v("requested_mask"); x = ""
            if (op == "capable") x = v("capname")
            else if (op ~ /^(create|connect|bind|listen|sendmsg|recvmsg)$/) x = v("family") " " v("sock_type")
            print k "|" op "|" nm "|" mk "|" x
        }
        function v(key,   r) { if (match($0, key "=\"[^\"]*\"")) { r = substr($0, RSTART + length(key) + 2, RLENGTH - length(key) - 3); return r }  # awk, not shell: posix-ok
            if (match($0, key "=[^ ]*")) return substr($0, RSTART + length(key) + 1, RLENGTH - length(key) - 1); return "" }' "$W/logs" | sort -u
}
# sort_events FILE -> $W/normal (rules), $W/webw (writes into the sites),
# $W/progs (programs run), $W/bad (secrets and system files: never added)
sort_events() {
    : >"$W/normal"; : >"$W/webw"; : >"$W/progs"; : >"$W/bad"
    while IFS='|' read -r _k _op _nm _mk _x; do
        case "$_op" in
            exec) printf '%s\n' "$_nm" >>"$W/progs" ;;
            capable) case "$_x" in sys_admin|sys_module|sys_rawio|sys_boot|mac_admin|mac_override|bpf|perfmon) printf 'capability %s\n' "$_x" >>"$W/bad" ;; ?*) printf 'capability %s,\n' "$_x" >>"$W/normal" ;; esac ;;
            create|connect|bind|listen|sendmsg|recvmsg) case "$_x" in *raw*|*packet*) printf 'network %s\n' "$_x" >>"$W/bad" ;; ?*) printf 'network %s,\n' "$_x" >>"$W/normal" ;; esac ;;
            *)  [ -n "$_nm" ] || continue
                _m=$(printf '%s' "$_mk" | tr -d 'xcd' ); printf '%s' "$_mk" | grep -q '[cd]' && _m="${_m}w"
                _m=$(printf '%s' "$_m" | fold -w1 | sort -u | tr -d '\n'); [ -n "$_m" ] || _m=r
                case "$_m" in *w*) _m=$(printf '%s' "$_m" | tr -d a) ;; esac  # w and a cannot be in one rule
                # AppArmor reads * ? [ ] { } in a path as patterns: escape them.
                _rule=$(printf '"%s" %s,' "$(printf '%s' "$_nm" | sed 's/[][*?{}]/\\&/g')" "$_m")
                case "$_nm:$_m" in
                    /var/www/*:*w*|/srv/*:*w*|/usr/share/roundcube/*:*w*) printf '%s\n' "$_rule" >>"$W/webw" ;;
                    # Secrets and system files: what an attacker in the web server goes for.
                    /etc/shadow*|/etc/gshadow*|/etc/sudoers*|/etc/ssh/*key*|/root/*|/home/*/.ssh/*|/proc/*/mem:*|/dev/mem:*|/dev/kmem:*|\
                    /etc/*:*w*|/usr/*:*w*|/bin/*:*w*|/sbin/*:*w*|/lib/*:*w*|/var/spool/cron/*:*w*|/boot/*:*w*) printf '%s %s\n' "$_nm" "$_m" >>"$W/bad" ;;
                    *) printf '%s\n' "$_rule" >>"$W/normal" ;;
                esac ;;
        esac
    done <"$1"
    for _f in normal webw progs bad; do sort -u "$W/$_f" -o "$W/$_f"; done
}
SUSPECT='/(sh|bash|dash|zsh|ksh|mksh|ash|busybox|nc|ncat|netcat|socat|curl|wget|python[0-9.]*|perl|ruby|php[0-9.]*|telnet|ssh|scp|base64|chmod|crontab|at)$'

# ---- Status and questions ---------------------------------------------------------------------
header "2/5  services"
NOW=$(date +%s)
mkdir -p "$W/plans"
: >"$W/plan"; printf '%-9s %-11s %-8s %s\n' service mode profile name >"$W/status"
_seen=0
while IFS='|' read -r _kind _bins _name _units _chk; do
    [ -n "$ONLY" ] && ! printf ',%s,' "$ONLY" | grep -q ",$_kind," && continue
    _bin=""; for _b in $_bins; do [ -x "$(P "$_b")" ] && { _bin=$_b; break; }; done
    [ -n "$_bin" ] || continue
    _seen=1
    _pk=$(packaged "$_bin"); _pname=$_name; _src=bt
    [ -n "$_pk" ] && { _src=package; _pname=${_pk#*"|"}; }
    _km=$(kernel_mode "$_pname"); _lab=$(proc_label "$_kind" "$_bin")
    _state=unconfined
    case "$_km" in complain) _state=complain ;; enforce) _state=enforce ;; esac
    _since=$(cat "$STATE/$_pname.$_state" 2>/dev/null)
    printf '%-9s %-11s %-8s %s\n' "$_kind" "$_state" "$_src" "$_pname" >>"$W/status"
    cc_show "" ""
    cc_show "$C_CYN" "  $_kind ($_bin): $_state$([ "$_src" = package ] && echo ", the package's profile $_pname" || echo ", kit profile $_name")$([ -n "$_lab" ] && echo "; the running service: $_lab")"
    _ans=""
    # Loaded, but the running service started before it: AppArmor neither logs
    # nor blocks anything for it until it is restarted.
    _stale=n; _rs=n
    if [ "$_state" != unconfined ] && [ "$_lab" = unconfined ]; then
        _stale=y
        cc_show "$C_RED" "  [!] the running $_kind started before its profile was loaded: nothing is logged or blocked until it restarts"
        cc_choose "$_kind runs outside its profile: what now?" r "r=restart it now so it runs under the profile" "k=leave it (restart it later yourself)"
        [ "$CC_CHOICE" = r ] && _rs=y
        printf '%-9s %-11s %-8s %s\n' "" "(running outside it)" "" "" >>"$W/status"
    fi
    case "$_state" in
        unconfined)
            cc_show "$C_YEL" "  [*] nothing stops a hacked $_kind from touching the rest of the box"
            cc_choose "$_kind is not confined: what now?" c \
                "c=complain: load the profile in learning mode - nothing is blocked, AppArmor only logs" \
                "e=enforce now: block everything not in the profile (do the learning first)" \
                "k=keep it as it is"
            _ans=$CC_CHOICE ;;
        complain)
            events "$_pname" "${_since:-0}" >"$W/ev.$_kind"
            sort_events "$W/ev.$_kind"
            _nn=$(grep -c . "$W/normal"); _nw=$(grep -c . "$W/webw"); _np=$(grep -c . "$W/progs")
            _bad=$(grep -E "$SUSPECT" "$W/progs" | tr '\n' ' ')
            _age=""; [ -n "$_since" ] && _age=" for $(( (NOW - _since) / 60 )) min"
            { printf '%s (%s) - sorted log lines\n\nnormal (offered):\n' "$_kind" "$_pname"; sed 's/^/  /' "$W/normal"; printf '\nwrites into the sites (asked on their own):\n'; sed 's/^/  /' "$W/webw"; printf '\nprograms it ran (never added by the script):\n'; sed 's/^/  /' "$W/progs"
              printf '\nsecrets and system files, dangerous capabilities (never added):\n'; sed 's/^/  /' "$W/bad"; } >"$CC_RUN_DIR/learned-$_kind.txt"
            _nb=$(grep -c . "$W/bad")
            cc_show "" "  in complain$_age; AppArmor logged $((_nn + _nw + _np)) thing(s) it would block: $_nn normal, $_nw write(s) into the site code, $_np program(s) it ran"
            head -n 6 "$W/normal" | while IFS= read -r _l; do cc_show "$C_GRY" "      $_l"; done
            [ "$_nn" -gt 6 ] && cc_show "$C_GRY" "      ... ($CC_RUN_DIR/learned-$_kind.txt)"
            while IFS= read -r _l; do cc_show "$C_YEL" "    [*] wrote into the site code: $_l"; done <"$W/webw"
            [ -n "$_bad" ] && cc_show "$C_RED" "    [!] it ran $_bad- that is what a web shell does: look at the site with SV-16 before you enforce"
            while IFS= read -r _l; do cc_show "$C_RED" "    [!] it touched $_l - a web or database server has no reason to: never added (a break-in? look with SV-16 / LX-42)"; done <"$W/bad"
            grep -vE "$SUSPECT" "$W/progs" | while IFS= read -r _l; do cc_show "$C_YEL" "    [*] it ran $_l (add \"$_l ix,\" to $AAD/local/$_pname yourself if it is normal)"; done
            # Enforce is only the default after 10 quiet minutes of real logging.
            _d=c; if [ $((_nn + _nw)) -gt 0 ]; then _d=l; elif [ $((_np + _nb)) -gt 0 ] || [ "$_stale" = y ]; then _d=c; elif [ -n "$_since" ] && [ $((NOW - _since)) -ge 600 ]; then _d=e; fi
            [ "$_src" = package ] && [ "$_d" = l ] && _d=c
            set -- "c=stay in complain (keep using the site, look again later)" "e=enforce: block everything not in the profile$([ $((_nn + _nw + _np)) -gt 0 ] && echo ' (it would block the logged things)')"
            [ "$_src" = bt ] && [ $((_nn + _nw)) -gt 0 ] && set -- "l=learn: add the normal ones to its profile, then look again later" "$@"
            cc_choose "$_kind is in complain mode: what now?" "$_d" "$@"
            _ans=$CC_CHOICE
            if [ "$_ans" = l ]; then
                cp "$W/normal" "$W/plans/$_kind.add"
                [ "$_nn" -gt 0 ] && ! cc_ask "  Add the $_nn normal rule(s) (in $CC_RUN_DIR/learned-$_kind.txt)?" Y "yes, add them" "no" && : >"$W/plans/$_kind.add"
                [ "$_nw" -gt 0 ] && cc_ask "  Also let it write the $_nw file(s) in the site code listed above (a real upload or cache? a web shell?)" N "yes, it is the site" "no, keep them out" && cat "$W/webw" >>"$W/plans/$_kind.add"
                [ -s "$W/plans/$_kind.add" ] || _ans=c
            fi ;;
        enforce)
            events "$_pname" "${_since:-0}" | grep '^DENIED' >"$W/ev.$_kind"
            _nd=$(grep -c . "$W/ev.$_kind")
            cc_show "$([ "$_nd" -gt 0 ] && printf '%s' "$C_YEL" || printf '%s' "$C_GRN")" "  [$([ "$_nd" -gt 0 ] && echo '*' || echo ok)] enforced; AppArmor blocked $_nd thing(s) since then"
            cut -d'|' -f2-4 "$W/ev.$_kind" | head -n 6 | while IFS= read -r _l; do cc_show "$C_GRY" "      $_l"; done
            cc_choose "$_kind is enforced: what now?" k "k=keep it enforced" "c=back to complain (if it broke something)"
            _ans=$CC_CHOICE ;;
    esac
    case "$_state:$_ans" in
        unconfined:c|unconfined:e|complain:e|complain:l|enforce:c) printf '%s|%s|%s|%s|%s|%s|%s\n' "$_kind" "$_bin" "$_pname" "$_src" "$_state" "$_ans" "$_units" >>"$W/plan" ;;
    esac
    # the restart (if asked above) comes after the mode change
    [ "$_rs" = y ] && printf '%s|%s|%s|%s|%s|%s|%s\n' "$_kind" "$_bin" "$_pname" "$_src" "$_state" r "$_units" >>"$W/plan"
done <"$W/svcs"
[ "$_seen" = 1 ] || cc_show "$C_GRY" "  None of apache2, nginx, php-fpm, mariadb/mysql is installed here."

# ---- Plan -----------------------------------------------------------------------------------
header "3/5  plan"
act_word() { case "$1:$2" in *:r) echo "restart it so it runs under its profile" ;; unconfined:c) echo "load the profile in complain mode (nothing blocked)" ;; unconfined:e|complain:e) echo "ENFORCE the profile" ;; complain:l) echo "add the learned rules, stay in complain" ;; enforce:c) echo "back to complain" ;; esac; }
NCH=0; : >"$CC_RUN_DIR/plan.txt"
while IFS='|' read -r _kind _bin _pname _src _state _ans _units; do
    NCH=$((NCH + 1)); printf '%s: %s\n' "$_kind" "$(act_word "$_state" "$_ans")" >>"$CC_RUN_DIR/plan.txt"
    cc_show "$C_YEL" "  [~] $_kind: $(act_word "$_state" "$_ans")"
done <"$W/plan"
[ "$NCH" -eq 0 ] && cc_show "$C_GRN" "  [ok] Nothing to change."

# ---- Apply ----------------------------------------------------------------------------------
header "4/5  apply"
load() { if [ -n "$R" ] && [ -z "${BT_AA_PARSER:-}" ]; then return 0; fi; "$PARSER" "$@"; }
svc_restart() {
    [ -z "$R" ] || return 0
    for _u in $1; do
        if [ "$CC_INIT" = systemd ]; then systemctl is-active -q "$_u" 2>/dev/null || continue; systemctl restart "$_u" </dev/null
        else [ -x "/etc/init.d/$_u" ] || continue; service "$_u" restart </dev/null; fi
        return
    done
}
check() {   # check KIND -> 0 still answers
    [ -z "$R" ] || return 0
    [ "$1" = mysql ] || cc_have curl || return 0
    case "$1" in
        mysql) _c=$(cc_first mariadb-admin mysqladmin) || return 0; "$_c" --connect-timeout=5 ping >/dev/null 2>&1 || "$_c" ping 2>&1 | grep -qi 'access denied' ;;
        *) _s=$(curl -k -s -m 10 -o /dev/null -w '%{http_code}' "$URL" 2>/dev/null); case "$_s" in [23]??|401|403|404) return 0 ;; *) return 1 ;; esac ;;
    esac
}
# set_mode FILE NAME bt|package complain|enforce -> switch and reload
set_mode() {
    if [ "$3" = bt ]; then
        if [ "$4" = complain ]; then sed "s|^\(profile $2 [^ {]*\) {|\1 flags=(complain) {|" "$1" >"$1.n"  # posix-ok: AppArmor text
        else sed 's/ flags=(complain)//' "$1" >"$1.n"; fi  # posix-ok: AppArmor text
        cat "$1.n" >"$1"; rm -f "$1.n"
        load -r -K "$1" >>"$CC_LOG" 2>&1 </dev/null
    elif [ "$4" = complain ]; then ln -sf "$1" "$AAD/force-complain/$(basename "$1")"; load -r -C "$1" >>"$CC_LOG" 2>&1 </dev/null
    else rm -f "$AAD/force-complain/$(basename "$1")"; load -r "$1" >>"$CC_LOG" 2>&1 </dev/null; fi
}
# back_off -> after enforcing: 0 if the service still answers, else put it
# back in complain and return 1
back_off() {
    sleep 2
    # Only blame the profile if the service answered before.
    [ "$_before" = y ] || { cc_show "$C_YEL" "    [*] $_kind did not answer before the change either: not checked"; return 0; }
    check "$_kind" && return 0
    cc_show "$C_RED" "    [x] $_kind stopped answering under enforce: put back in complain"
    set_mode "$_pf" "$_pname" "$_src" complain; date +%s >"$STATE/$_pname.complain"
    _ok=0; return 1
}
# svc_restart_cmd UNITS -> a shell line that restarts the running one (for the undo)
svc_restart_cmd() {
    [ -z "$R" ] || { printf ':'; return; }
    printf 'for u in %s; do if [ -d /run/systemd/system ]; then systemctl try-restart "$u" 2>/dev/null; elif [ -x "/etc/init.d/$u" ]; then service "$u" restart; fi; done' "$1"
}
NOK=0; NBAD=0; APPLIED=0; TIMER_ON=0
if [ "$NCH" -eq 0 ]; then :
elif [ "$CC_APPLY" != 1 ] || { [ -z "$R" ] && ! cc_is_root; }; then
    [ -z "$R" ] && ! cc_is_root && cc_show "$C_YEL" "  [!] not root: showing the plan only"
    cc_show "$C_GRY" "  Dry run: nothing was changed. Run again with --apply."
    # shellcheck disable=SC2034  # read by cc_finish
    CC_N_WOULD=$NCH
elif cc_ask "Apply these $NCH change(s)?" Y "yes, apply them$(grep -q '|e|' "$W/plan" && echo ' (a revert timer undoes this run unless you confirm from a NEW session)')" "no, change nothing"; then
    APPLIED=1; mkdir -p "$STATE" "$AAD/local" "$AAD/force-complain"
    if grep -q '|e|' "$W/plan" && [ "$NOTIMER" != 1 ] && [ -z "$R" ]; then cc_timer_start "$TIMER"; TIMER_ON=1; fi
    while IFS='|' read -r _kind _bin _pname _src _state _ans _units; do
        _before=n; { [ "$_ans" = e ] || [ "$_ans" = r ]; } && check "$_kind" && _before=y
        _ok=1; _pf="$AAD/$_pname"; [ "$_src" = package ] && { _pk=$(packaged "$_bin"); _pf=${_pk%%"|"*}; }
        _fc="$AAD/force-complain/$(basename "$_pf")"; _qp=$(cc_shquote "$PARSER"); _qf=$(cc_shquote "$_pf")
        case "$_state:$_ans" in
            *:r)
                if [ -z "$R" ]; then svc_restart "$_units" >>"$CC_LOG" 2>&1; sleep 2; [ "$(proc_label "$_kind" "$_bin")" = unconfined ] && { _ok=0; cc_show "$C_RED" "    [x] still unconfined after the restart (another program name? see $CC_LOG)"; }; fi ;;
            unconfined:c|unconfined:e)
                _mode=complain; [ "$_ans" = e ] && _mode=enforce
                if [ "$_src" = bt ]; then
                    if [ -f "$_pf" ]; then
                        # a file from an earlier run, not loaded now: put it back as it was
                        cc_undo_add "unload $_pname" "$_qp -R $_qf 2>/dev/null; $(svc_restart_cmd "$_units")"
                        cc_backup_file "$_pf" >/dev/null
                    else cc_undo_add "remove the kit profile $_pname" "$_qp -R $_qf 2>/dev/null; rm -f $_qf; $(svc_restart_cmd "$_units")"; fi
                    write_profile "$_kind" "$_bin" "$_pname" "$_mode" >"$_pf"
                    [ -f "$AAD/local/$_pname" ] || : >"$AAD/local/$_pname"
                    load -r -K "$_pf" >>"$CC_LOG" 2>&1 </dev/null || { _ok=0; rm -f "$_pf"; cc_show "$C_RED" "    [x] apparmor_parser refused the profile: $CC_LOG"; }
                else
                    cc_undo_add "unload $_pname" "rm -f $(cc_shquote "$_fc"); $_qp -R $_qf 2>/dev/null; $(svc_restart_cmd "$_units")"
                    [ -e "$AAD/disable/$(basename "$_pf")" ] && { rm -f "$AAD/disable/$(basename "$_pf")"; cc_undo_add "$_pname disabled again" "ln -sf $_qf $(cc_shquote "$AAD/disable/$(basename "$_pf")")"; }
                    set_mode "$_pf" "$_pname" package "$_mode" || _ok=0
                fi
                [ "$_ok" = 1 ] && date +%s >"$STATE/$_pname.$_mode"
                if [ "$_ok" = 1 ] && [ -z "$R" ] && cc_ask "  Restart $_kind now so the running service is under its profile?" Y "yes, restart it" "no, at its next restart"; then
                    svc_restart "$_units" >>"$CC_LOG" 2>&1; sleep 2
                fi
                [ "$_ok" = 1 ] && [ "$_mode" = enforce ] && ! back_off ;;
            complain:l)
                _lf="$AAD/local/$_pname"
                cc_undo_add "reload $_pname" "$_qp -r -K $_qf"
                if [ -f "$_lf" ]; then cc_backup_file "$_lf" >/dev/null; else : >"$_lf"; cc_undo_add "empty the learned rules for $_pname" ": > $(cc_shquote "$_lf")"; fi
                { printf '# learned by LX-44 %s\n' "$(date '+%F %T')"; sed 's/^/  /' "$W/plans/$_kind.add"; } >>"$_lf"
                load -r -K "$_pf" >>"$CC_LOG" 2>&1 </dev/null || { _ok=0; cc_show "$C_RED" "    [x] apparmor_parser refused the learned rules: they are in $_lf"; }
                [ "$_ok" = 1 ] && date +%s >"$STATE/$_pname.complain" ;;
            complain:e|enforce:c)
                _to=enforce; [ "$_ans" = c ] && _to=complain
                if [ "$_src" = bt ]; then
                    cc_undo_add "reload $_pname" "$_qp -r -K $_qf"
                    cc_backup_file "$_pf" >/dev/null
                else
                    if [ "$_to" = enforce ]; then cc_undo_add "$_pname back to complain" "ln -sf $_qf $(cc_shquote "$_fc"); $_qp -r -C $_qf"
                    else cc_undo_add "$_pname back to enforce" "rm -f $(cc_shquote "$_fc"); $_qp -r $_qf"; fi
                fi
                set_mode "$_pf" "$_pname" "$_src" "$_to" || _ok=0
                [ "$_ok" = 1 ] && date +%s >"$STATE/$_pname.$_to"
                [ "$_ok" = 1 ] && [ "$_to" = enforce ] && ! back_off ;;
        esac
        if [ "$_ok" = 1 ]; then NOK=$((NOK + 1)); cc_show "$C_GRN" "  [+] $_kind: $(act_word "$_state" "$_ans")"; else NBAD=$((NBAD + 1)); cc_show "$C_RED" "  [x] $_kind: $(act_word "$_state" "$_ans") FAILED"; fi
    done <"$W/plan"
else cc_show "$C_GRY" "  Not applied."; fi
# shellcheck disable=SC2034  # read by cc_finish
CC_N_DONE=$NOK
# shellcheck disable=SC2034  # read by cc_finish
CC_N_FAIL=$NBAD

# ---- Summary ---------------------------------------------------------------------------------
header "5/5  summary"
{
    printf '==========[ summary ]==========\n'
    printf 'LX-44 AppArmor confinement | host %s | %s\n' "$CC_HOST" "$([ "$APPLIED" = 1 ] && echo APPLIED || echo 'DRY RUN - nothing changed')"
    [ -s "$CC_RUN_DIR/plan.txt" ] && { printf 'Changes%s:\n' "$([ "$APPLIED" = 1 ] || echo ' planned')"; sed 's/^/  /' "$CC_RUN_DIR/plan.txt"; }
    [ "$APPLIED" = 1 ] && printf 'Done: %d   Failed: %d\n' "$NOK" "$NBAD"
    printf '\nThe steps: complain -> use the site normally for a while (log in, buy, upload) -> run this again: learn -> again: enforce.\n'
    printf 'Learned rules live in %s/local/bt-*; the profiles in %s/bt-*.\n' "${AAD#"$R"}" "${AAD#"$R"}"
    [ "$APPLIED" = 1 ] && [ -f "$CC_RUN_DIR/revert.sh" ] && printf 'Undo this run: sh %s/revert.sh --force\n' "$CC_RUN_DIR"
    [ "$APPLIED" = 1 ] && [ ! -f "$CC_RUN_DIR/revert.sh" ] && printf 'Undo: the lines in %s/undo-%s.log\n' "$CC_OUT" "$CC_HOST"
} >"$CC_RUN_DIR/summary.txt"
{ printf 'AppArmor mode of each service when the run started\n\n'; cat "$W/status"; printf '\nunconfined = nothing stops it; complain = logs only; enforce = blocks\n'; } >"$CC_RUN_DIR/status.txt"
while IFS= read -r _l; do case "$_l" in ==*|LX-44*) cc_show "$C_CYN" "$_l" ;; *FAILED*|*'Failed: '[1-9]*) cc_show "$C_RED" "$_l" ;; *) cc_show "" "$_l" ;; esac; done <"$CC_RUN_DIR/summary.txt"
rm -rf "$W"
if [ "$TIMER_ON" = 1 ]; then header "KEEP OR REVERT"; cc_show "$C_YEL" "[*] Before you answer: click through the store (log in, add to cart, upload) and the webmail."; cc_timer_finish || true; fi
cc_finish
