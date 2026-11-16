#!/bin/sh
# =============================================================================
# ID:       SV-30
# NAME:     Service hardening (FTP and other cleartext/legacy services)
# ROLE:     Applications
# KIND:     changes - dry run unless --apply
# VERSION:  1.0.0
#
# PURPOSE
#   Hardens the insecure services that show up on CCDC Linux boxes - FTP
#   first, then telnet, rsh/rlogin/rexec, TFTP, SNMP and the old inetd
#   services.  Every action is graded by how risky it is, and the script
#   only goes as far as the level you pick:
#
#     safe     (default)  no user-visible change; cannot break a service or
#                         lock anyone out (e.g. turn off anonymous FTP)
#     service             might change how a scored service behaves, so it
#                         applies the change, checks the service still
#                         answers, and undoes just that change if it broke
#     access              might remove a service entirely (disable the
#                         daemon); covered by the revert timer and skipped
#                         for a service the host list marks as scored
#
#   It shows what it would change first (dry run), asks about each action
#   (like sqlmap: Enter takes the default), then with --apply makes the
#   changes with a revert timer running, and at the end keeps them only if
#   you confirm from a new session.  Same look and undo as LX-39.
#
# USAGE
#   sh SV-30-service-hardening.sh                     dry run, safe level, asks
#   sudo sh SV-30-service-hardening.sh --apply         apply the safe fixes
#   sudo sh SV-30-service-hardening.sh --apply --level service
#   sudo sh SV-30-service-hardening.sh --apply --level access --only ftp-disable
#   sudo sh SV-30-service-hardening.sh --apply --batch --level safe   no questions
#
# OPTIONS
#   --apply            make the changes (without it, dry run only)
#   --level L          how far to go: safe (default), service, or access.
#                      Each level includes the ones before it
#   --only a,b         only these actions (see the list below)
#   --skip a,b         leave these actions out
#   --exclude a,b      services to leave alone (names like vsftpd, snmpd):
#                      no action will touch them.  Answers the leave-alone
#                      questions in advance
#   --force-scored     allow disabling a service the host list marks scored
#                      (off by default; disabling a scored service loses points)
#   --timer SECONDS    revert countdown when applying (default 120)
#   --no-timer         apply with no revert timer (not advised for --level access)
#   --root DIR         treat DIR as / (for tests); service actions are only
#                      reported, since there is no running system under DIR
#   --no-color         no colours
#   --batch            no questions: take every default for the chosen level
#   --help             this text plus the common options
#
# ACTIONS  (risk in brackets)
#   ftp-anon        [safe]     turn off anonymous FTP login
#   ftp-accounts    [safe]     deny root and system accounts FTP (/etc/ftpusers)
#   ftp-perms       [safe]     lock down the FTP config file (chmod 600)
#   ftp-chroot      [service]  jail FTP users to their home folder
#   ftp-tls         [service]  (reports the lines to require FTPS/TLS)
#   ftp-disable     [access]   stop and disable the FTP service
#   telnet-disable  [access]   stop and disable telnet (cleartext)
#   rsh-disable     [access]   disable rsh/rlogin/rexec (cleartext)
#   tftp-disable    [access]   stop and disable TFTP
#   snmp-default    [safe]     (reports) default SNMP community strings
#   snmp-disable    [access]   stop and disable SNMP
#   legacy-disable  [access]   disable finger/echo/chargen/daytime/discard
#
# OUTPUTS  (under --out, in service-hardening-N/)
#   output.txt     everything shown on screen, without colour
#   plan.txt       what it would change (dry-run pass)
#   changes.txt    what it changed (with --apply)
#   summary.txt    the summary page
#   csv/           plan.csv and changes.csv
#   revert.sh      undo this run at any time (written when --apply changed something)
#   run.txt        id, host, time
#
# WHAT IT CHANGES  (only with --apply)
#   FTP config files (vsftpd.conf), /etc/ftpusers, config file permissions,
#   and - at --level access - whether a service is enabled and running.  Every
#   change has an undo line and is covered by the revert timer.  Open FTP
#   sessions are not killed by the config changes; disabling a service stops it.
#
# DEPENDS ON
#   awk, grep, sed.  systemctl / rc-service / service to stop or disable a
#   daemon.  ss or netstat to check a service still listens.
#
# TESTED ON
#   Ubuntu 24.04 under dash, bash, busybox sh, ksh93, mksh and yash, against a
#   fake root (--root) with vsftpd/proftpd config files.  Service enable and
#   disable is reported under --root and exercised live by hand.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - FTP config editing is full for vsftpd; for proftpd and pure-ftpd the
#     daemon is detected and the change to make is reported, not written.
#   - "scored" comes from the host list (ENVIRONMENT / --hosts in other
#     scripts); here, pass services to leave alone with --exclude, and keep
#     --force-scored off so a scored FTP/SNMP is never disabled by accident.
#   - ftp-tls and snmp-default are reported, not applied: TLS needs a cert and
#     a new SNMP community must be coordinated, so they are yours to set.
#   - A service-level change is checked by whether the service still runs and
#     listens; a service that was already stopped cannot be checked that way.
#
# DEBUGGING
#   --debug          show each command
#   output.txt       the full screen log
# =============================================================================

# >>> CCDC-LIB  (lib/lib.sh 0.2.1 pasted in by tools/build.sh - edit lib/lib.sh, not this copy)
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
#       # >>> CCDC-LIB
#       ...the loader lines from templates/script-template.sh...
#       # <<< CCDC-LIB
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
: "${CC_OUT:=${CCDC_OUT:-}}"              # output folder (operator-chosen)
: "${CC_PROTECTED:=${CCDC_PROTECTED:-}}"  # protected-list CSV
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
#   piped in.  CCDC_ASSUME_YES=1 answers yes without asking (for fan-out).
cc_confirm() {
    [ "${CCDC_ASSUME_YES:-0}" = 1 ] && return 0
    if [ ! -r /dev/tty ]; then
        cc_warn "no terminal to ask '$1' - treating as NO (set CCDC_ASSUME_YES=1 to skip questions)"
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
                     (default: $CCDC_OUT, else ~/ccdc-out)
  --protected FILE   protected-list CSV (default: $CCDC_PROTECTED, else
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
        --version)      printf 'ccdc kit library %s\n' "$CC_LIB_VERSION"; exit 0 ;;
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
    [ -n "$CC_OUT" ] || CC_OUT="${HOME:-/root}/ccdc-out"
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

# _cc_can_ask -> true when there is someone to ask.
#   CCDC_NO_TTY=1 says there is nobody (the test suite sets it, so tests
#   never wait for an answer when run from a terminal).
_cc_can_ask() { [ "$CC_BATCH" != 1 ] && [ "${CCDC_NO_TTY:-0}" != 1 ] && [ -r /dev/tty ] && [ -w /dev/tty ] && ( : </dev/tty ) 2>/dev/null; }

# cc_ask QUESTION DEFAULT -> 0 for yes, 1 for no.  DEFAULT is Y or N.
#   Enter takes the default.  With --batch or no terminal the default is
#   taken and shown.  If the revert timer runs out while waiting, the script
#   stops (nothing has been changed while questions are still being asked).
cc_ask() {
    _cc_ak_q=$1; _cc_ak_d=${2:-N}
    case "$_cc_ak_d" in Y|y) _cc_ak_h="Y/n"; _cc_ak_d=Y ;; *) _cc_ak_h="y/N"; _cc_ak_d=N ;; esac
    if ! _cc_can_ask; then
        cc_show "${C_CYN:-}" "[?] $_cc_ak_q [$_cc_ak_h] $_cc_ak_d (default)"
    else
        while :; do
            printf '%s[?]%s %s [%s]%s ' "${C_CYN:-}" "${C_OFF:-}" "$_cc_ak_q" "$_cc_ak_h" "$(_cc_left_txt)" >/dev/tty
            if ! _cc_read _cc_ak_a; then
                printf '\n' >/dev/tty
                [ "$CC_TIMER_DEADLINE" -gt 0 ] && [ "$(cc_timer_left)" -eq 0 ] && cc_die 3 "the revert timer ran out while waiting for an answer. Nothing was changed. Run again (--batch or flags skip the questions; --timer SECONDS gives more time)"
                _cc_ak_a=""
            fi
            case "$_cc_ak_a" in
                '') _cc_ak_a=$_cc_ak_d; break ;;
                y|Y|yes|YES|Yes) _cc_ak_a=Y; break ;;
                n|N|no|NO|No) _cc_ak_a=N; break ;;
                *) printf '    please answer y or n\n' >/dev/tty ;;
            esac
        done
        [ -n "$CC_TEE" ] && printf '[?] %s [%s] %s\n' "$_cc_ak_q" "$_cc_ak_h" "$_cc_ak_a" >>"$CC_TEE"
        cc_note "asked: $_cc_ak_q -> $_cc_ak_a"
        _cc_ak_d=$_cc_ak_a
    fi
    [ "$_cc_ak_d" = Y ]
}

# cc_ask_text QUESTION DEFAULT -> the answer in CC_ANSWER (DEFAULT on Enter,
#   with --batch, or with no terminal).
cc_ask_text() {
    CC_ANSWER=$2
    if ! _cc_can_ask; then
        cc_show "${C_CYN:-}" "[?] $1 ${2:-(none)} (default)"
        return 0
    fi
    printf '%s[?]%s %s [%s]%s ' "${C_CYN:-}" "${C_OFF:-}" "$1" "${2:-Enter for none}" "$(_cc_left_txt)" >/dev/tty
    if ! _cc_read _cc_at_a; then
        printf '\n' >/dev/tty
        [ "$CC_TIMER_DEADLINE" -gt 0 ] && [ "$(cc_timer_left)" -eq 0 ] && cc_die 3 "the revert timer ran out while waiting for an answer. Nothing was changed. Run again (--batch or flags skip the questions; --timer SECONDS gives more time)"
        _cc_at_a=""
    fi
    [ -n "$_cc_at_a" ] && CC_ANSWER=$_cc_at_a
    [ -n "$CC_TEE" ] && printf '[?] %s %s\n' "$1" "$CC_ANSWER" >>"$CC_TEE"
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
    if [ "${CCDC_TIMER_METHOD:-}" != background ] && cc_is_root && [ -d /run/systemd/system ] && cc_have systemd-run; then
        CC_TIMER_ID="ccdc-revert-$$-$(cc_now)"
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
#   folders above it, or CCDC_MANIFEST points to one, the running script's
#   hash must match its line there.  A mismatch stops the script: the file on
#   this host is not the one you built, and a red team may have edited it.
#   CCDC_SKIP_VERIFY=1 turns the check off (for development).
cc_verify_self() {
    [ "${CCDC_SKIP_VERIFY:-0}" = 1 ] && { cc_debug "verify: skipped (CCDC_SKIP_VERIFY=1)"; return 0; }
    [ -f "$0" ] || { cc_debug "verify: script was not started from a file, nothing to hash"; return 0; }
    _cc_vs_man=${CCDC_MANIFEST:-}
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
# <<< CCDC-LIB

ALL_ACTIONS="ftp-anon ftp-accounts ftp-perms ftp-chroot ftp-tls ftp-disable telnet-disable rsh-disable tftp-disable snmp-default snmp-disable legacy-disable"

usage() {
    cat <<'USAGE'
SV-30 Service hardening - FTP and other cleartext/legacy services
  sh SV-30-service-hardening.sh                    dry run, safe level, asks
  sudo sh SV-30-service-hardening.sh --apply        apply the safe fixes
  sudo sh SV-30-service-hardening.sh --apply --level service

  --apply            make the changes (without it, dry run only)
  --level L          safe (default) | service | access  (each includes the earlier ones)
  --only a,b         only these actions
  --skip a,b         leave these actions out
  --exclude a,b      services to leave alone (vsftpd, snmpd, ...)
  --force-scored     allow disabling a service the host list marks scored
  --timer SECONDS    revert countdown when applying (default 120)
  --no-timer         apply with no revert timer
  --root DIR         treat DIR as / (tests)
  --no-color         no colours
  --batch            no questions: defaults for the chosen level
  --help             this text

Actions (risk): ftp-anon[safe] ftp-accounts[safe] ftp-perms[safe]
  ftp-chroot[service] ftp-tls[service] ftp-disable[access] telnet-disable[access]
  rsh-disable[access] tftp-disable[access] snmp-default[safe] snmp-disable[access]
  legacy-disable[access]
USAGE
    cc_usage_common
}

# ---- Options ----------------------------------------------------------------
LEVEL=safe; ONLY=""; SKIP=""; EXCL=""; FORCE_SCORED=0; TIMER=120; NOTIMER=0; R=""; COLOR=1
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --apply)         CC_APPLY=1; shift ;;
        --level)         [ $# -ge 2 ] || cc_die 2 "--level needs safe, service or access"; LEVEL=$2; shift 2 ;;
        --only)          [ $# -ge 2 ] || cc_die 2 "--only needs a list"; ONLY="$ONLY,$2"; shift 2 ;;
        --skip)          [ $# -ge 2 ] || cc_die 2 "--skip needs a list"; SKIP="$SKIP,$2"; shift 2 ;;
        --exclude)       [ $# -ge 2 ] || cc_die 2 "--exclude needs a list of service names"; EXCL="$EXCL,$2"; shift 2 ;;
        --force-scored)  FORCE_SCORED=1; shift ;;
        --timer)         [ $# -ge 2 ] || cc_die 2 "--timer needs seconds"; TIMER=$2; shift 2 ;;
        --no-timer)      NOTIMER=1; shift ;;
        --root)          [ $# -ge 2 ] || cc_die 2 "--root needs a folder"; [ -d "$2" ] || cc_die 2 "--root: not a folder: $2"
                         R=$(cd "$2" && pwd); [ "$R" = / ] && R=""; shift 2 ;;
        --no-color|--no-colour) COLOR=0; shift ;;
        --help|-h)       usage; exit 0 ;;
        *)               cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
case "$LEVEL" in safe|service|access) ;; *) cc_die 2 "--level must be safe, service or access" ;; esac
case "$TIMER" in ''|*[!0-9]*) cc_die 2 "--timer needs a whole number of seconds" ;; esac
# Validate --only/--skip names.
for _a in $(printf '%s' "$ONLY,$SKIP" | tr ',' ' '); do
    [ -z "$_a" ] && continue
    case " $ALL_ACTIONS " in *" $_a "*) ;; *) cc_die 2 "unknown action '$_a' (see --help for the list)" ;; esac
done
# shellcheck disable=SC2034  # CC_FORCE_SCORED is read by cc_guard in the library
[ "$FORCE_SCORED" = 1 ] && CC_FORCE_SCORED=1

cc_init "SV-30" "Service hardening" changes
cc_detect_os
cc_use_numbered_dir service-hardening
cc_color_init
[ "$COLOR" = 1 ] || { C_RED=""; C_YEL=""; C_GRN=""; C_CYN=""; C_GRY=""; C_OFF=""; }
W="$CC_RUN_DIR/.work"; mkdir -p "$W" || cc_die 3 "cannot create $W"
CSV=""

OUTF="$CC_RUN_DIR/output.txt"
grep -v '\[NOTE\]\|\[DEBUG\]' "$CC_LOG" >"$OUTF" 2>/dev/null || : >"$OUTF"
# shellcheck disable=SC2034  # CC_TEE is read by the library's log functions
CC_TEE=$OUTF

# P PATH -> PATH under --root (or PATH itself).
P() { printf '%s%s' "$R" "$1"; }

# level_rank LEVEL -> 1/2/3 so levels can be compared.
level_rank() { case "$1" in safe) echo 1 ;; service) echo 2 ;; access) echo 3 ;; esac; }
WANT_RANK=$(level_rank "$LEVEL")

# ---- Per-action metadata ----------------------------------------------------
act_risk() {
    case "$1" in
        ftp-anon|ftp-accounts|ftp-perms|snmp-default) echo safe ;;
        ftp-chroot|ftp-tls)                           echo service ;;
        *)                                            echo access ;;
    esac
}
act_desc() {
    case "$1" in
        ftp-anon)       echo "turn off anonymous FTP login" ;;
        ftp-accounts)   echo "deny root and system accounts FTP" ;;
        ftp-perms)      echo "lock down the FTP config file (chmod 600)" ;;
        ftp-chroot)     echo "jail FTP users to their home folder" ;;
        ftp-tls)        echo "require FTPS/TLS (reported, not applied)" ;;
        ftp-disable)    echo "stop and disable the FTP service" ;;
        telnet-disable) echo "stop and disable telnet" ;;
        rsh-disable)    echo "disable rsh/rlogin/rexec" ;;
        tftp-disable)   echo "stop and disable TFTP" ;;
        snmp-default)   echo "flag default SNMP community strings (reported)" ;;
        snmp-disable)   echo "stop and disable SNMP" ;;
        legacy-disable) echo "disable finger/echo/chargen/daytime/discard" ;;
    esac
}

# ---- Service detection ------------------------------------------------------
# svc_state NAME -> running | stopped | missing  (live only).
svc_state() {
    [ -z "$R" ] || { echo missing; return; }
    case "$CC_INIT" in
        systemd) systemctl cat "$1.service" >/dev/null 2>&1 || { echo missing; return; }
                 systemctl is-active --quiet "$1" 2>/dev/null && echo running || echo stopped ;;
        openrc)  [ -e "/etc/init.d/$1" ] || { echo missing; return; }
                 rc-service "$1" status >/dev/null 2>&1 && echo running || echo stopped ;;
        *)       [ -e "/etc/init.d/$1" ] || { echo missing; return; }
                 service "$1" status >/dev/null 2>&1 && echo running || echo stopped ;;
    esac
}

# svc_present NAME -> true if the service exists (used in detection below).
svc_present() { [ "$(svc_state "$1")" != missing ]; }

# FTP daemon + its config file.
FTP_DAEMON=""; FTP_CONF=""
for _c in /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf; do
    [ -f "$(P "$_c")" ] && { FTP_DAEMON=vsftpd; FTP_CONF=$_c; break; }
done
if [ -z "$FTP_DAEMON" ] && [ -f "$(P /etc/proftpd/proftpd.conf)" ]; then FTP_DAEMON=proftpd; FTP_CONF=/etc/proftpd/proftpd.conf; fi
if [ -z "$FTP_DAEMON" ] && { [ -d "$(P /etc/pure-ftpd)" ] || svc_present pure-ftpd 2>/dev/null; }; then FTP_DAEMON=pure-ftpd; fi
if [ -z "$FTP_DAEMON" ] && [ -z "$R" ]; then
    for _d in vsftpd proftpd pure-ftpd; do [ "$(svc_state "$_d")" != missing ] && { FTP_DAEMON=$_d; break; }; done
fi
FTP_SVC=$FTP_DAEMON

# act_applies NAME -> 0 if the service the action targets is present.
act_applies() {
    case "$1" in
        ftp-*)          [ -n "$FTP_DAEMON" ] ;;
        telnet-disable) [ -n "$R" ] && return 1; _present telnet telnetd inetutils-telnetd ;;
        rsh-disable)    [ -n "$R" ] && return 1; _present rsh.socket rlogin.socket rexec.socket rsh rlogin ;;
        tftp-disable)   [ -n "$R" ] && return 1; _present tftpd-hpa tftp tftpd ;;
        snmp-default)   [ -f "$(P /etc/snmp/snmpd.conf)" ] ;;
        snmp-disable)   [ -f "$(P /etc/snmp/snmpd.conf)" ] || { [ -z "$R" ] && [ "$(svc_state snmpd)" != missing ]; } ;;
        legacy-disable) [ -n "$R" ] && return 1; _present inetd xinetd ;;
    esac
}
# _present NAME... -> 0 if any is an installed service or a command on PATH.
_present() {
    for _p in "$@"; do
        [ "$(svc_state "$_p")" != missing ] && return 0
        command -v "$_p" >/dev/null 2>&1 && return 0
    done
    return 1
}
# is_excluded SERVICE -> true if the service was named in --exclude / a question.
is_excluded() { case ",$EXCL," in *",$1,"*) return 0 ;; esac; return 1; }

# ---- Build the list of actions to consider ----------------------------------
# An action is in play when: it applies, its risk is within --level, it is not
# --skip'd, and (if --only was given) it is in --only.
CONSIDER=""
for _a in $ALL_ACTIONS; do
    act_applies "$_a" || continue
    [ "$(level_rank "$(act_risk "$_a")")" -le "$WANT_RANK" ] || continue
    case ",$SKIP," in *",$_a,"*) continue ;; esac
    if [ -n "$ONLY" ]; then case ",$ONLY," in *",$_a,"*) ;; *) continue ;; esac; fi
    CONSIDER="$CONSIDER $_a"
done

cc_show "$C_CYN" "SV-30 Service hardening | host $CC_HOST | level $LEVEL | results in $CC_RUN_DIR"
cc_show "" "Legend: ${C_GRN}[+] changed${C_OFF}  ${C_YEL}[~] would change  [*] check by hand${C_OFF}  ${C_RED}[x] failed${C_OFF}  ${C_GRN}[ok] already right${C_OFF}"
[ -n "$R" ] && cc_show "$C_GRY" "Acting on $R as if it were / (service enable/disable is only reported)"
if [ -n "$FTP_DAEMON" ]; then cc_show "$C_GRY" "FTP: $FTP_DAEMON${FTP_CONF:+ ($FTP_CONF)}"; else cc_show "$C_GRY" "FTP: none detected"; fi
if [ -z "$CONSIDER" ]; then
    cc_show "$C_GRN" "[ok] nothing to harden at level '$LEVEL' (none of those services are here, or all are excluded)."
    [ "$LEVEL" != access ] && cc_show "$C_GRY" "Legacy services (telnet, rsh, tftp, ...) are disabled only at --level access."
    cc_finish
    exit 0
fi

# ---- Questions (sqlmap style) -----------------------------------------------
# One per action in play.  safe/service default yes, access defaults no.
CHOSEN=""
for _a in $CONSIDER; do
    _risk=$(act_risk "$_a")
    # The service each action targets (ftp-* -> the detected FTP daemon).
    _svc=$FTP_DAEMON; case "$_a" in telnet-*) _svc=telnet ;; rsh-*) _svc=rsh ;; tftp-*) _svc=tftp ;; snmp-*) _svc=snmpd ;; legacy-*) _svc=inetd ;; esac
    is_excluded "$_svc" && continue
    # access defaults to no, unless the action was named explicitly in --only.
    _def=Y; [ "$_risk" = access ] && _def=N
    case ",$ONLY," in *",$_a,"*) _def=Y ;; esac
    if cc_ask "[$_risk] $(act_desc "$_a")?" "$_def"; then CHOSEN="$CHOSEN $_a"; fi
done
if [ -z "$CHOSEN" ]; then
    cc_show "$C_GRY" "Nothing chosen. Nothing to do."
    cc_finish; exit 0
fi

# ---- Apply gating + revert timer --------------------------------------------
CANAPPLY=0
if [ "$CC_APPLY" = 1 ] && { [ -n "$R" ] || cc_is_root; }; then CANAPPLY=1; fi
if [ "$CC_APPLY" = 1 ] && [ "$CANAPPLY" = 0 ]; then
    cc_warn "not root: cannot apply. Showing the plan only (run with sudo to apply)."
    CC_APPLY=0
fi
TIMER_ON=0
if [ "$CANAPPLY" = 1 ] && [ -z "$R" ]; then
    if [ "$NOTIMER" = 1 ]; then
        cc_show "$C_YEL" "[*] No revert timer (--no-timer): if a change locks you out, nothing puts it back."
    else
        cc_timer_start "$TIMER"; TIMER_ON=1
        cc_show "$C_YEL" "[*] Revert timer started: everything this run changes is undone in $((TIMER / 60)):$(printf '%02d' $((TIMER % 60))) unless you keep it at the end."
    fi
fi

# ---- Reporting helpers (like LX-39) -----------------------------------------
OKN=0
row() {
    cc_csv_row "$CSV" "$1" "$2" "$3" "$4" "$5"
    _rw="$3"; [ -n "$4" ] && _rw="$3: $4"
    case "$5" in
        "would change")  cc_show "$C_YEL" "  [~] $2  $_rw" ;;
        changed)         cc_show "$C_GRN" "  [+] $2  $_rw" ;;
        failed)          cc_show "$C_RED" "  [x] FAILED $2  $_rw" ;;
        refused)         cc_show "$C_YEL" "  [-] refused (scored/excluded): $2  $_rw" ;;
        "check by hand") cc_show "$C_YEL" "  [*] check: $2  $_rw" ;;
        "already ok")    OKN=$((OKN + 1)) ;;
        skipped*)        cc_show "$C_GRY" "  [-] $2: $5" ;;
        *)               cc_show "$C_YEL" "  [*] $2: $5" ;;
    esac
    return 0
}
ok_line() { [ "$OKN" -gt 0 ] && cc_show "$C_GRN" "  [ok] $OKN already right"; OKN=0; return 0; }
header() { cc_show "" ""; cc_show "$C_CYN" "==========[ $1 ]=========="; }
result() { if [ "$CC_APPLY" != 1 ]; then echo "would change"; elif [ "$1" -eq 0 ]; then echo changed; else echo failed; fi; }

# ensure_backup FILE -> back up FILE once per run (records the restore undo).
ensure_backup() {
    case " $(cat "$W/backed" 2>/dev/null) " in *" $1 "*) return 0 ;; esac
    cc_backup_file "$(P "$1")" || return 1
    printf '%s\n' "$1" >>"$W/backed"
    return 0
}

# ---- Apply primitives (run via cc_run, so only on --apply) ------------------
# _kv_set CONF KEY VAL -> rewrite "KEY=VAL" in a vsftpd-style config.
_kv_set() {
    awk -v k="$2" -v v="$3" '
        $0 ~ "^[ \t]*#?[ \t]*" k "=" { if (!done) { print k "=" v; done = 1 }; next }
        { print }
        END { if (!done) print k "=" v }' "$1" >"$1.ccnew" && mv "$1.ccnew" "$1"
}
_ftpusers_add() {
    # $1 = ftpusers path, rest = names to ensure present
    _f=$1; shift
    [ -f "$_f" ] || : >"$_f"
    for _n in "$@"; do grep -qx "$_n" "$_f" 2>/dev/null || printf '%s\n' "$_n" >>"$_f"; done
}
_chmod() { chmod "$1" "$2"; }
_svc_off() {
    # stop and disable $1 across init systems
    case "$CC_INIT" in
        systemd) systemctl disable --now "$1" 2>>"$CC_LOG" ;;
        openrc)  rc-service "$1" stop 2>>"$CC_LOG"; rc-update del "$1" 2>>"$CC_LOG" ;;
        *)       service "$1" stop 2>>"$CC_LOG"; command -v update-rc.d >/dev/null 2>&1 && update-rc.d "$1" disable 2>>"$CC_LOG" ;;
    esac
}

# cur_kv KEY CONF -> the current value of KEY (last one wins), or empty.
cur_kv() { grep -Ei "^[[:space:]]*$1=" "$2" 2>/dev/null | tail -n 1 | sed 's/^[^=]*=//' | tr -d ' \r'; }

# ---- The actions ------------------------------------------------------------
# Each reads FILE under P(); edits only when CC_APPLY=1 (via cc_run).
do_ftp_kv() {   # ACTION KEY WANT  (one vsftpd key)
    _conf=$(P "$FTP_CONF")
    if [ "$FTP_DAEMON" != vsftpd ]; then
        row "$1" "$FTP_DAEMON" "set $2=$3 by hand" "$FTP_DAEMON config" "check by hand"; return 0
    fi
    _cur=$(cur_kv "$2" "$_conf")
    if [ "$(printf '%s' "$_cur" | tr 'A-Z' 'a-z')" = "$(printf '%s' "$3" | tr 'A-Z' 'a-z')" ]; then
        row "$1" vsftpd "$2" "already $3" "already ok"; return 0
    fi
    ensure_backup "$FTP_CONF" || { row "$1" vsftpd "$2" "backup failed" failed; return 0; }
    cc_run "ftp: set $2=$3" _kv_set "$_conf" "$2" "$3"
    row "$1" vsftpd "$2" "${_cur:-unset} -> $3" "$(result $?)"
}

do_action() {
    case "$1" in
        ftp-anon)   do_ftp_kv ftp-anon anonymous_enable NO ;;
        ftp-chroot)
            do_ftp_kv ftp-chroot chroot_local_user YES
            do_ftp_kv ftp-chroot allow_writeable_chroot YES
            # Live: make sure FTP still answers; undo both keys if it broke.
            if [ -z "$R" ] && [ "$CC_APPLY" = 1 ] && [ "$FTP_DAEMON" = vsftpd ]; then svc_recheck "$FTP_SVC" ftp-chroot; fi ;;
        ftp-accounts)
            _fu=$(P /etc/ftpusers)
            _fu_existed=0; [ -f "$_fu" ] && _fu_existed=1
            _need=""
            for _n in root daemon bin sys sync games man lp mail news uucp proxy www-data backup list irc gnats nobody; do
                cut -d: -f1 "$(P /etc/passwd)" 2>/dev/null | grep -qx "$_n" || [ "$_n" = root ] || continue
                grep -qx "$_n" "$_fu" 2>/dev/null || _need="$_need $_n"
            done
            if [ -z "$_need" ]; then row ftp-accounts ftpusers /etc/ftpusers "root and system accounts already denied" "already ok"
            else
                ensure_backup /etc/ftpusers || { row ftp-accounts ftpusers /etc/ftpusers "backup failed" failed; return 0; }
                # shellcheck disable=SC2086
                cc_run "ftp: deny accounts in /etc/ftpusers" _ftpusers_add "$_fu" $_need
                # If the file did not exist, back it out by removing it (a
                # backup only exists when the file was already there).
                [ "$CC_APPLY" = 1 ] && [ "$_fu_existed" = 0 ] && cc_undo_add "remove /etc/ftpusers (created by SV-30)" "rm -f $(cc_shquote "$_fu")"
                row ftp-accounts ftpusers /etc/ftpusers "deny:$_need" "$(result $?)"
            fi ;;
        ftp-perms)
            _conf=$(P "$FTP_CONF"); [ -f "$_conf" ] || { row ftp-perms "$FTP_CONF" "" "no config file" "already ok"; return 0; }
            _m=$(mode_of "$_conf")
            if [ "$_m" = 0600 ] || [ "$_m" = 0640 ]; then row ftp-perms "$FTP_CONF" mode "$_m" "already ok"
            else
                cc_run "ftp: chmod 600 $FTP_CONF" _chmod 600 "$_conf"
                [ "$CC_APPLY" = 1 ] && cc_undo_add "restore mode of $FTP_CONF" "chmod $_m $(cc_shquote "$_conf")"
                row ftp-perms "$FTP_CONF" mode "$_m -> 0600" "$(result $?)"
            fi ;;
        ftp-tls)
            row ftp-tls "$FTP_DAEMON" "require FTPS/TLS" "add ssl_enable=YES + force_local_*_ssl=YES and a cert" "check by hand" ;;
        snmp-default)
            _sc=$(P /etc/snmp/snmpd.conf)
            if grep -Eiq '^[[:space:]]*(com2sec|rocommunity6?|rwcommunity6?)[[:space:]].*(public|private)' "$_sc" 2>/dev/null || grep -Eiq 'community[[:space:]]+(public|private)' "$_sc" 2>/dev/null; then
                row snmp-default snmpd "default community string" "public/private in snmpd.conf - change it, coordinate with monitoring" "check by hand"
            else
                row snmp-default snmpd snmpd.conf "no default community string found" "already ok"
            fi ;;
        ftp-disable)    svc_disable "$FTP_SVC" ftp-disable ;;
        telnet-disable) svc_disable "$(first_present telnet.socket telnet inetutils-telnetd telnetd)" telnet-disable ;;
        tftp-disable)   svc_disable "$(first_present tftpd-hpa tftp tftpd)" tftp-disable ;;
        snmp-disable)   svc_disable snmpd snmp-disable ;;
        rsh-disable)
            _any=0
            for _s in rsh.socket rlogin.socket rexec.socket; do [ "$(svc_state "$_s")" != missing ] && { svc_disable "$_s" rsh-disable; _any=1; }; done
            [ "$_any" = 0 ] && row rsh-disable rsh "rsh/rlogin/rexec" "present but not a service: remove the inetd lines by hand" "check by hand" ;;
        legacy-disable)
            row legacy-disable inetd "echo/chargen/daytime/discard/finger" "disable in $( [ "$(svc_state xinetd)" != missing ] && echo xinetd || echo inetd ) and reload it" "check by hand" ;;
    esac
}

# first_present NAME... -> the first that exists as a service, else the first arg.
first_present() {
    for _p in "$@"; do [ "$(svc_state "$_p")" != missing ] && { echo "$_p"; return; }; done
    echo "$1"
}

# svc_disable NAME ACTION -> stop+disable a service, with undo (access level).
svc_disable() {
    _sd=$1; _act=$2
    if [ -n "$R" ]; then row "$_act" "$_sd" "service" "only reported under --root" "skipped (--root)"; return 0; fi
    if ! cc_guard service "$_sd"; then row "$_act" "$_sd" "service" "scored/excluded" refused; return 0; fi
    _st=$(svc_state "$_sd")
    if [ "$_st" = missing ]; then row "$_act" "$_sd" service "not installed" "already ok"; return 0; fi
    if [ "$_st" = stopped ] && ! _svc_enabled "$_sd"; then row "$_act" "$_sd" service "already stopped and disabled" "already ok"; return 0; fi
    if [ "$CC_APPLY" = 1 ]; then
        _en=disabled; _svc_enabled "$_sd" && _en=enabled
        cc_undo_add "re-enable and start $_sd" "$(_svc_on_cmd "$_sd" "$_st" "$_en")"
    fi
    cc_run "disable and stop $_sd" _svc_off "$_sd"
    row "$_act" "$_sd" service "$_st -> stopped/disabled" "$(result $?)"
}
_svc_enabled() {
    case "$CC_INIT" in
        systemd) systemctl is-enabled --quiet "$1" 2>/dev/null ;;
        *)       return 0 ;;   # best effort elsewhere
    esac
}
_svc_on_cmd() {
    case "$CC_INIT" in
        systemd) printf 'systemctl %s %s' "$([ "$2" = running ] && echo 'enable --now' || echo enable)" "$1" ;;
        openrc)  printf 'rc-update add %s; rc-service %s start' "$1" "$1" ;;
        *)       printf 'service %s start' "$1" ;;
    esac
}

# svc_recheck NAME ACTION -> after a service-level change, confirm the service
#   still runs/listens; if not, restore the config backup and report failed.
svc_recheck() {
    [ "$CC_APPLY" = 1 ] || return 0
    _rn=$1; _ra=$2
    [ "$(svc_state "$_rn")" = running ] || { row "$_ra" "$_rn" "recheck" "service was not running; not restarted" "check by hand"; return 0; }
    cc_run_quiet "reload $_rn after $_ra" _svc_reload "$_rn"; sleep 1
    if [ "$(svc_state "$_rn")" = running ]; then
        row "$_ra" "$_rn" "recheck" "service still running after the change" "already ok"
    else
        cc_err "$_rn stopped after $_ra - putting the config back"
        # Restore the FTP config from its own backup (CC_LAST_BACKUP may point
        # at a different file backed up later in this run).
        _rb="$CC_BACKUP_DIR$(cc_abspath "$(P "$FTP_CONF")")"
        [ -f "$_rb" ] && cp "$_rb" "$(P "$FTP_CONF")" 2>>"$CC_LOG"
        _svc_reload "$_rn" >>"$CC_LOG" 2>&1
        row "$_ra" "$_rn" "recheck" "service broke; the change was undone" failed
    fi
}
_svc_reload() {
    case "$CC_INIT" in
        systemd) systemctl restart "$1" ;;
        openrc)  rc-service "$1" restart ;;
        *)       service "$1" restart ;;
    esac
}

# mode_of PATH -> four-digit octal, from ls -l (portable).
mode_of() {
    _ls=$(ls -ld "$1" 2>/dev/null) || { echo ""; return; }
    _s=$(printf '%s' "$_ls" | cut -c1-10)
    awk -v s="$_s" 'BEGIN{
        p=substr(s,2); v=0
        r=substr(p,1,1)=="r"?4:0; w=substr(p,2,1)=="w"?2:0; x = (substr(p,3,1)=="x"||substr(p,3,1)=="s")?1:0; u=r+w+x
        r=substr(p,4,1)=="r"?4:0; w=substr(p,5,1)=="w"?2:0; x = (substr(p,6,1)=="x"||substr(p,6,1)=="s")?1:0; g=r+w+x
        r=substr(p,7,1)=="r"?4:0; w=substr(p,8,1)=="w"?2:0; x = (substr(p,9,1)=="x"||substr(p,9,1)=="t")?1:0; o=r+w+x
        sp=0; if(substr(p,3,1)=="s"||substr(p,3,1)=="S")sp+=4; if(substr(p,6,1)=="s"||substr(p,6,1)=="S")sp+=2; if(substr(p,9,1)=="t"||substr(p,9,1)=="T")sp+=1
        printf "%d%d%d%d", sp,u,g,o }'
}

# ---- Plan, then apply -------------------------------------------------------
run_all() {
    _ra_q=$CC_QUIET; CC_QUIET=1        # the coloured row lines replace WOULD/DO lines
    _ra_i=0; _ra_n=$(printf '%s\n' $CHOSEN | grep -c .)
    for _a in $CHOSEN; do
        _ra_i=$((_ra_i + 1))
        header "$_ra_i/$_ra_n  $_a  [$(act_risk "$_a")]"
        do_action "$_a"
        ok_line
    done
    CC_QUIET=$_ra_q
}

CSV=$(cc_csv_new plan "action,service,item,detail,status")
: >"$W/backed"
_real=$CC_APPLY; CC_APPLY=0
header "PLAN (dry run: nothing is changed yet)"
run_all
CC_APPLY=$_real
NCH=$(awk "$CC_AWK_CSV"'NR>1 { csvsplit($0,f); if (f[5]=="would change") n++ } END { print n+0 }' "$CSV")
cc_csv_pretty "$CSV" "$CC_RUN_DIR/plan.txt" 90

APPLIED=0
header "DECISION"
if [ "$NCH" -eq 0 ]; then
    cc_show "$C_GRN" "[ok] Nothing to change: everything chosen is already in place (or is check-by-hand)."
elif [ "$CANAPPLY" = 0 ]; then
    cc_show "$C_GRY" "$NCH change(s) planned. Dry run only (use --apply as root), so nothing was changed."
else
    _ad=Y
    if cc_ask "Apply these $NCH change(s)?" "$_ad"; then
        if [ "$TIMER_ON" = 1 ] && { cc_timer_fired || [ "$(cc_timer_left)" -lt 3 ]; }; then
            cc_die 3 "the revert timer ran out before anything was changed. Nothing was changed. Run again with a bigger --timer or --batch"
        fi
        CC_APPLY=1; APPLIED=1
        : >"$W/backed"
        CSV=$(cc_csv_new changes "action,service,item,detail,status")
        header "APPLYING"
        run_all
        cc_csv_pretty "$CSV" "$CC_RUN_DIR/changes.txt" 90
    else
        cc_show "$C_GRY" "Not applied. The plan is in $CC_RUN_DIR/plan.txt"
    fi
fi

# ---- Keep or revert ---------------------------------------------------------
if [ "$APPLIED" = 1 ] && [ "$TIMER_ON" = 1 ]; then
    header "KEEP OR REVERT"
    cc_timer_finish || true
fi

# ---- Summary ----------------------------------------------------------------
{
    printf 'SV-30 Service hardening | host %s | %s | level %s | %s\n\n' "$CC_HOST" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$LEVEL" "$([ "$APPLIED" = 1 ] && echo APPLIED || echo 'DRY RUN - nothing changed')"
    [ -n "$FTP_DAEMON" ] && printf 'FTP daemon: %s%s\n' "$FTP_DAEMON" "${FTP_CONF:+ ($FTP_CONF)}"
    printf 'Actions chosen:%s\n\n' "$CHOSEN"
    awk "$CC_AWK_CSV"'NR>1 { csvsplit($0,f);
        if (f[5]=="changed"||f[5]=="would change"||f[5]=="failed"||f[5]=="refused"||f[5]=="check by hand")
            printf "  %-14s %-9s %-10s %s\n", toupper(f[5]), f[1], f[2], (f[4]!=""?f[3]": "f[4]:f[3]) }' "$CSV" | head -n 80
    printf '\n'
    if [ "$APPLIED" = 1 ]; then
        if [ "$TIMER_ON" = 1 ]; then printf 'Undo this run at any time: sh %s/revert.sh --force\n' "$CC_RUN_DIR"
        else printf 'Undo lines are in %s (newest at the bottom)\n' "$CC_UNDO"; fi
    else
        printf 'Nothing was changed.%s\n' "$([ "$CANAPPLY" = 0 ] && echo ' Run as root with --apply to change.' || echo '')"
    fi
    printf 'All results: %s\n' "$CC_RUN_DIR"
} >"$CC_RUN_DIR/summary.txt"

header "SUMMARY"
awk -v R="$C_RED" -v Y="$C_YEL" -v G="$C_GRN" -v C="$C_CYN" -v O="$C_OFF" '
    /^  (CHANGED|WOULD CHANGE) / { print G $0 O; next }
    /^  FAILED /                 { print R $0 O; next }
    /^  (REFUSED|CHECK BY HAND) /{ print Y $0 O; next }
    /^(SV-30|FTP daemon|Actions)/{ print C $0 O; next }
    { print }
' "$CC_RUN_DIR/summary.txt"
cat "$CC_RUN_DIR/summary.txt" >>"$OUTF"
rm -rf "$W"
cc_finish
