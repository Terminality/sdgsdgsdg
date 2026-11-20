#!/bin/sh
# =============================================================================
# ID:       LX-39
# NAME:     Linux safe fixes
# ROLE:     Linux  (wave 2, first 15 minutes)
# KIND:     changes - dry run unless --apply
# VERSION:  2.0.0
#
# PURPOSE
#   The Linux twin of WN-43: only fixes that cannot break a scored service,
#   so they can run on every Linux box in the first minutes without study.
#     sysctl      kernel network and memory settings: SYN cookies, full ASLR,
#                 no source routing or ICMP redirects, martian logging,
#                 symlink and hardlink protection, hidden kernel pointers
#     ipv6        IPv6 off with the kernel setting (disable_ipv6) on every
#                 interface except loopback.  NOT the ipv6.disable boot
#                 option: that one stops any service configured to listen on
#                 [::] (nginx's default config does) from starting at all
#     coredumps   no core dumps from setuid programs (they can hold password
#                 hashes), and a hard core-size limit of 0
#     perms       owner-only or root-only modes on the password, group,
#                 sudo, SSH host key, cron, PAM, shell startup and systemd
#                 files, and no world-writable files in /etc or program folders.
#                 Only bits are REMOVED; owners and groups are never changed
#     tmp         the sticky bit on /tmp, /var/tmp and /dev/shm
#     logging     rsyslog / syslog-ng / auditd started (and enabled) if they
#                 are installed but stopped
#     preload     /etc/ld.so.preload entries not owned by any package (the
#                 classic rootkit hook) -> the file is quarantined; LD_PRELOAD
#                 lines in /etc/environment are commented out
#     trust       .rhosts, .shosts, hosts.equiv, shosts.equiv quarantined
#     uid0        accounts other than root with UID 0 (root-equivalent
#                 backdoors) locked and expired, so neither a password nor
#                 an SSH key logs in.  Undo puts the password and date back
#     emptypw     accounts with an EMPTY password locked (anyone could log
#                 in as them without one)
#     suid        the SUID bit removed from programs that should never have
#                 it (copies of bash, find, vim, python ... from GTFOBins)
#                 and from anything SUID in /tmp, /var/tmp, /dev/shm, /home
#   Every fix that acts on items (files, accounts, settings, services) asks
#   which ones to leave alone, or takes --exclude a,b,c.
#     forwarding  IP forwarding off - ONLY with --no-forwarding, because
#                 routers, firewalls and Docker hosts need it
#   Also REPORTED (never changed): extra /etc/hosts entries, IP forwarding
#   left on, services bound to a specific IPv6 address.
#
# HOW A RUN GOES  (sqlmap style: it asks, Enter takes the default)
#   1. A 2-minute revert timer starts (root only).  If the changes are not
#      kept before it runs out - for example because you got kicked off the
#      box - everything this run changed is put back.  It runs outside the
#      script (systemd timer, else a detached job), so a dead session does
#      not stop it.
#   2. Questions: which box this is, then one per fix.  Flags answer them in
#      advance; --batch takes every default without asking.
#   3. The plan: every change it would make, then "Apply these N changes?"
#   4. The changes, shown as they are made.
#   5. "Keep these changes?" - log in from a NEW session first.  y keeps
#      them; n or no answer before the timer undoes them.
#
# USAGE
#   sudo sh LX-39-safe-fixes.sh                    ask everything, then apply if you say so
#   sudo sh LX-39-safe-fixes.sh --apply --batch    no questions: defaults, apply, keep
#   sudo sh LX-39-safe-fixes.sh --batch            no questions, dry run only
#   sudo sh LX-39-safe-fixes.sh --apply --skip ipv6
#
# OPTIONS
#   --only a,b       run only these fixes (names from --list)
#   --skip a,b       leave these fixes out
#   --keep-ipv6      same as --skip ipv6
#   --exclude a,b    items no fix may touch: paths (/etc/crontab), account
#                    names (bob), kernel settings (net.ipv4.tcp_syncookies),
#                    services (auditd).  Answers the "leave alone" questions
#   --no-forwarding  also turn IP forwarding off (not on routers/firewalls/Docker)
#   --root DIR       treat DIR as / for every FILE fix (perms, tmp, preload,
#                    trust, the sysctl and limits files).  For fixing a
#                    mounted disk image, and for the tests.  Kernel settings
#                    and services still act on the running system
#   --box NAME       splunk | webmail | ecomm | other (skips that question)
#   --timer SECONDS  revert timer length (default 120)
#   --no-timer       no revert timer (you accept the risk)
#   --no-color       no colours
#   --batch          never ask: take every default (from the common options)
#   --list           list the fixes and exit
#   --help           this text plus the common options
#
# OUTPUTS  (under --out, one numbered folder per run: safe-fixes-1, -2, ...)
#   output.txt    everything shown on screen, without colours
#   summary.txt   counts per fix, every change, and the items to check by hand
#   plan.txt      what it would change (the dry-run pass)
#   fixes.txt     what it did: fix, item, before, after, status
#                 (status: changed | would change | already ok | failed |
#                  refused | skipped | check by hand)
#   csv/          plan.csv and fixes.csv
#   revert.sh     undoes this run (sh revert.sh --force); undo.txt, revert.log,
#                 KEEP and REVERTED belong to the revert timer
#   The undo log (<out>/undo-<host>.log) gets one line per change; run its
#   commands from the bottom up to roll back.  Files are backed up first
#   under <out>/backup/<host>/.
#
# WHAT IT CHANGES  (only with --apply)
#   /etc/sysctl.d/99-zz-bt-safe.conf (new) and the running kernel settings,
#   /etc/security/limits.d/99-bt-safe.conf (new), file modes listed above,
#   /etc/environment (LD_PRELOAD lines commented out), the logging services.
#   Moves /etc/ld.so.preload and rhosts-style files to the quarantine folder.
#   Never deletes anything.  A path on the protected list is skipped.
#
# DEPENDS ON
#   ls, chmod, find, awk, sysctl (Linux); systemctl, rc-service or service
#   for the logging fix; dpkg or rpm to check who owns a preload library.
#
# TESTED ON
#   Ubuntu 24.04 under dash, bash, busybox sh, ksh93, mksh and yash, against a
#   test root and stand-in sysctl/systemctl programs, plus a dry run on the
#   live system.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - Kernel settings are made permanent in a file named 99-zz-... so it is
#     read last at boot, after /etc/sysctl.conf; a file named later still
#     (for example 99-zzz.conf) would win - the change watch shows new files.
#   - The ipv6 fix has only run against a stand-in sysctl: the test machine's
#     kernel has no IPv6.  After the first real --apply check "ip -6 addr
#     show lo" still lists ::1.
#   - Inside a container some kernel settings are read-only; those show as
#     failed in fixes.txt and the rest still apply.
#   - The preload fix trusts the package database.  On a box where the red
#     team replaced packages, check the quarantined file by hand.
#
# DEBUGGING
#   --debug shows every mode calculation and tool choice.  Every command run
#   with --apply is in the log with its output.
# =============================================================================

# >>> BT-LIB  (lib/lib.sh 0.3.0 pasted in by tools/build.sh - edit lib/lib.sh, not this copy)
# =============================================================================
# ID:       LB-01
# NAME:     Shell library (lib.sh)
# ROLE:     Automation  (wave 0, foundation)
# VERSION:  0.3.0
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
CC_LIB_VERSION="0.3.0"

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

ALL_FIXES="sysctl ipv6 forwarding coredumps perms tmp logging preload trust uid0 emptypw suid hosts"
# Fixes that act on named items, so they can ask which ones to leave alone.
EXCL_FIXES="sysctl perms logging preload trust uid0 emptypw suid"

usage() {
    cat <<'USAGE'
LX-39 Linux safe fixes - hardening that cannot break a scored service
  sudo sh LX-39-safe-fixes.sh [--apply] [options]

  --only a,b       run only these fixes
  --skip a,b       leave these fixes out
  --keep-ipv6      leave IPv6 on (same as --skip ipv6)
  --exclude a,b    items to leave alone: paths, account names, kernel settings, services
  --no-forwarding  also turn IP forwarding off (NOT on routers, firewalls or Docker hosts)
  --root DIR       treat DIR as / for the file fixes (disk images, tests)
  --box NAME       splunk | webmail | ecomm | other (skips that question)
  --timer SECONDS  revert timer length (default 120)
  --no-timer       no revert timer (you accept the risk)
  --no-color       no colours
  --batch          never ask: take every default
  --list           list the fixes and exit
  --help           show this text

USAGE
    cc_usage_common
}

list_fixes() {
    cat <<'LIST'
sysctl      SYN cookies, ASLR, no source-routed packets or redirects, link protection
ipv6        IPv6 off with disable_ipv6 (loopback kept), never the boot option
forwarding  IP forwarding off (asks first if the box routes or runs Docker; with no one to ask, only with --no-forwarding)
coredumps   no setuid core dumps, core size limit 0
perms       remove group/other write (and read on secrets) from key files
tmp         sticky bit on /tmp, /var/tmp, /dev/shm
logging     start rsyslog / syslog-ng / auditd if installed and stopped
preload     quarantine /etc/ld.so.preload with unowned libraries; LD_PRELOAD lines
trust       quarantine .rhosts, .shosts, hosts.equiv, shosts.equiv
uid0        lock and expire accounts other than root with UID 0
emptypw     lock accounts that have an empty password
suid        remove SUID from programs that should never have it (GTFOBins copies, /tmp)
hosts       report extra /etc/hosts entries (report only)
LIST
}

ONLY=""; SKIP=""; NOFWD=0; R=""; BOX=""; TIMER=120; NOTIMER=0; FWDFLAG=0; EXCL=""; EXCLFLAG=0
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --only)          [ $# -ge 2 ] || cc_die 2 "--only needs a list of fixes"; ONLY=$2; shift 2 ;;
        --skip)          [ $# -ge 2 ] || cc_die 2 "--skip needs a list of fixes"; SKIP="$SKIP,$2"; shift 2 ;;
        --keep-ipv6)     SKIP="$SKIP,ipv6"; shift ;;
        --exclude)       [ $# -ge 2 ] || cc_die 2 "--exclude needs a list (paths, account names, settings, services)"
                         EXCL="$EXCL,$2"; EXCLFLAG=1; shift 2 ;;
        --no-forwarding) NOFWD=1; FWDFLAG=1; shift ;;
        --box)           [ $# -ge 2 ] || cc_die 2 "--box needs splunk, webmail, ecomm or other"; BOX=$2; shift 2 ;;
        --timer)         [ $# -ge 2 ] || cc_die 2 "--timer needs a number of seconds"; TIMER=$2; shift 2 ;;
        --no-timer)      NOTIMER=1; shift ;;
        --no-color|--no-colour) CC_NOCOLOR=1; shift ;;
        --root)          [ $# -ge 2 ] || cc_die 2 "--root needs a folder"
                         [ -d "$2" ] || cc_die 2 "--root: not a folder: $2"
                         R=$(cd "$2" && pwd); [ "$R" = / ] && R=""; shift 2 ;;
        --list)          list_fixes; exit 0 ;;
        --help|-h)       usage; exit 0 ;;
        *)               cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
case "$TIMER" in ''|*[!0-9]*) cc_die 2 "--timer needs a whole number of seconds" ;; esac
[ "$TIMER" -ge 2 ] || cc_die 2 "--timer must be at least 2 seconds"
case "$BOX" in ''|splunk|webmail|ecomm|other) ;; *) cc_die 2 "--box must be splunk, webmail, ecomm or other" ;; esac
for _n in $(printf '%s,%s' "$ONLY" "$SKIP" | tr ',' ' '); do
    case " $ALL_FIXES " in *" $_n "*) ;; *) cc_die 2 "unknown fix '$_n' (see --list)" ;; esac
done
FIXES=$ALL_FIXES
[ -n "$ONLY" ] && FIXES=$(printf '%s' "$ONLY" | tr ',' ' ')
# Naming forwarding in --only is asking for it, like --no-forwarding.
case ",$ONLY," in *,forwarding,*) NOFWD=1; FWDFLAG=1 ;; esac
_keep=""
for _f in $FIXES; do
    case ",$SKIP," in *",$_f,"*) continue ;; esac
    _keep="$_keep $_f"
done
FIXES=$_keep
# SETTLED: true when a flag already decided the fixes, so no per-fix questions.
SETTLED=0; [ -n "$ONLY$SKIP" ] && SETTLED=1

# The sysctl program.  BT_SYSCTL lets the tests use a stand-in by full
# path: busybox sh runs its own built-in sysctl in preference to PATH.
SYSCTL=${BT_SYSCTL:-sysctl}

cc_color_init

# protected_check -> with no protected list, ask before changing anything.
#   Sets CC_NO_PROTECTED=1 on yes; returns 1 on no.
protected_check() {
    [ "$CC_NO_PROTECTED" = 1 ] && return 0
    _pc=${CC_PROTECTED:-${CC_OUT:-${BT_OUT:-${HOME:-/root}/bt-out}}/protected.csv}
    [ -r "$_pc" ] && return 0
    cc_show "$C_YEL" "[*] No protected list at $_pc (the list of scored ports, services and accounts no script may touch)."
    if cc_ask "Continue without a protected list? (LX-39 does not touch ports or services anyway)" N "yes, continue" "no, stop"; then CC_NO_PROTECTED=1; return 0; fi
    return 1
}
if [ "$CC_APPLY" = 1 ] && ! protected_check; then
    cc_show "$C_YEL" "[*] Staying in dry run: nothing will be changed."
    CC_APPLY=0
fi
APPLY_FLAG=$CC_APPLY

cc_init "LX-39" "Linux safe fixes" changes
cc_detect_os
if [ "$CC_APPLY" = 1 ] && [ -z "$R" ]; then cc_require_root; fi
cc_use_numbered_dir safe-fixes
CC_CSV_DIR="$CC_RUN_DIR/csv"
mkdir -p "$CC_CSV_DIR" || cc_die 3 "cannot create $CC_CSV_DIR"
W="$CC_RUN_DIR/.work"
mkdir -p "$W" || cc_die 3 "cannot create $W"
# Everything shown on screen also goes to output.txt (start line from the log).
OUTF="$CC_RUN_DIR/output.txt"
grep -v '\[NOTE\]\|\[DEBUG\]' "$CC_LOG" >"$OUTF" 2>/dev/null || : >"$OUTF"
CC_TEE=$OUTF
cc_show "$C_CYN" "LX-39 Linux safe fixes | host $CC_HOST | results in $CC_RUN_DIR"
cc_show "" "Legend: ${C_GRN}[+] changed${C_OFF}  ${C_YEL}[~] would change  [*] check by hand${C_OFF}  ${C_RED}[x] failed${C_OFF}  ${C_GRN}[ok] already right${C_OFF}"
[ -n "$R" ] && cc_show "$C_GRY" "File fixes act on $R (as if it were /)"

# Can this run change anything?  Root (or --root) and either --apply or
# someone at the keyboard to say yes.
CANAPPLY=0
if [ "$CC_APPLY" = 1 ] || _cc_can_ask; then
    if [ -n "$R" ] || cc_is_root; then CANAPPLY=1; fi
fi
if [ "$CANAPPLY" = 0 ]; then
    if cc_is_root || [ -n "$R" ]; then cc_show "$C_GRY" "Dry run only (--batch without --apply): nothing will be changed."
    else cc_show "$C_GRY" "Dry run only (not root): nothing will be changed. Run with sudo to make changes."; fi
elif [ "$NOTIMER" = 1 ]; then
    cc_show "$C_YEL" "[*] No revert timer (--no-timer): if a change locks you out, nothing puts it back."
else
    cc_timer_start "$TIMER"
    cc_show "$C_YEL" "[*] Revert timer started: everything this run changes is undone in $((TIMER / 60)):$(printf '%02d' $((TIMER % 60))) unless you keep it at the end."
fi

# ---- Helpers ----------------------------------------------------------------
# row ITEM BEFORE AFTER STATUS -> one line in the CSV for the current fix,
#   and one coloured line on screen ("already ok" lines are only counted).
OKN=0
row() {
    cc_csv_row "$CSV" "$FIX" "$1" "$2" "$3" "$4"
    _rw_ch=""; [ -n "$2$3" ] && _rw_ch="  ${2:-(none)} -> ${3:-(none)}"
    case "$4" in
        "would change")  cc_show "$C_YEL" "  [~] $1$_rw_ch" ;;
        changed)         cc_show "$C_GRN" "  [+] $1$_rw_ch" ;;
        failed)          cc_show "$C_RED" "  [x] FAILED $1$_rw_ch" ;;
        refused)         cc_show "$C_YEL" "  [-] refused (protected list): $1" ;;
        "check by hand") cc_show "$C_YEL" "  [*] check: $1 - $3" ;;
        "already ok"*|skipped*) OKN=$((OKN + 1)) ;;
        excluded*)       cc_show "$C_GRY" "  [-] left alone (you excluded it): $1" ;;
        *)               cc_show "$C_YEL" "  [*] $1: $4" ;;
    esac
    return 0
}
# is_excluded ITEM -> true if ITEM is on the leave-alone list (--exclude or
#   an answer to a "leave alone" question).
is_excluded() {
    case ",$EXCL," in *",$1,"*) return 0 ;; esac
    return 1
}
# ok_line -> "[ok] N already right" for the block just shown.
ok_line() { [ "$OKN" -gt 0 ] && cc_show "$C_GRN" "  [ok] $OKN already right"; OKN=0; return 0; }
# header TEXT -> a section header, linpeas style.
header() { cc_show "" ""; cc_show "$C_CYN" "==========[ $1 ]=========="; }
# result RC -> the status word for a change that was just attempted.
result() { if [ "$CC_APPLY" != 1 ]; then echo "would change"; elif [ "$1" -eq 0 ]; then echo changed; else echo failed; fi; }
# P PATH -> PATH under the --root folder (or PATH itself).
P() { printf '%s%s' "$R" "$1"; }

# mode_of PATH -> four-digit octal mode, read from ls -ld so it works with
#   every ls (GNU stat -c and BSD stat -f differ).  s/S/t/T set the special
#   digit; lower-case means the execute bit is also on.
mode_of() {
    ls -ld "$1" 2>/dev/null | awk '{
        p = $1; s = 0; u = 0; g = 0; o = 0
        c = substr(p, 2, 1); if (c == "r") u += 4
        c = substr(p, 3, 1); if (c == "w") u += 2
        c = substr(p, 4, 1); if (c == "x" || c == "s") u += 1; if (c == "s" || c == "S") s += 4
        c = substr(p, 5, 1); if (c == "r") g += 4
        c = substr(p, 6, 1); if (c == "w") g += 2
        c = substr(p, 7, 1); if (c == "x" || c == "s") g += 1; if (c == "s" || c == "S") s += 2
        c = substr(p, 8, 1); if (c == "r") o += 4
        c = substr(p, 9, 1); if (c == "w") o += 2
        c = substr(p, 10, 1); if (c == "x" || c == "t") o += 1; if (c == "t" || c == "T") s += 1
        printf "%d%d%d%d\n", s, u, g, o }'
}
# mode_calc OLD CLEAR SET -> OLD with the CLEAR bits removed and the SET bits
#   added, all four-digit octal.  Done digit by digit in awk because POSIX awk
#   has no bit operators and mksh reads 0-prefixed numbers as decimal.
mode_calc() {
    awk -v o="$1" -v c="$2" -v s="$3" 'BEGIN {
        while (length(o) < 4) o = "0" o; while (length(c) < 4) c = "0" c; while (length(s) < 4) s = "0" s
        out = ""
        for (i = 1; i <= 4; i++) {
            od = substr(o, i, 1) + 0; cd = substr(c, i, 1) + 0; sd = substr(s, i, 1) + 0; n = 0
            for (b = 4; b >= 1; b = b / 2) {
                on = (int(od / b) % 2 == 1 && int(cd / b) % 2 == 0) || int(sd / b) % 2 == 1
                if (on) n += b
            }
            out = out n
        }
        print out }'
}

# set_mode PATH CLEAR SET WHY [quiet]
#   Change PATH's mode if CLEAR bits are present or SET bits are missing.
#   Symbolic links are skipped (chmod would follow them).  With "quiet", an
#   already-correct path writes no row (used for long lists of files).
set_mode() {
    _sm_p=$1; _sm_c=$2; _sm_s=$3; _sm_why=$4; _sm_q=${5:-}
    [ -e "$_sm_p" ] || return 0
    [ -h "$_sm_p" ] && return 0
    _sm_old=$(mode_of "$_sm_p")
    [ -n "$_sm_old" ] || return 0
    _sm_new=$(mode_calc "$_sm_old" "$_sm_c" "$_sm_s")
    _sm_item=${_sm_p#"$R"}
    # Each path once per pass: the world-writable sweep would otherwise list
    # a file the named rules above already handled.
    grep -qxF "$_sm_p" "$W/handled" 2>/dev/null && return 0
    printf '%s\n' "$_sm_p" >>"$W/handled"
    if is_excluded "$_sm_item"; then row "$_sm_item" "$_sm_old" "" "excluded"; return 0; fi
    if [ "$_sm_new" = "$_sm_old" ]; then
        [ -n "$_sm_q" ] || row "$_sm_item" "$_sm_old" "$_sm_old" "already ok"
        return 0
    fi
    if ! cc_guard path "$_sm_item"; then row "$_sm_item" "$_sm_old" "$_sm_new" refused; return 0; fi
    cc_run "mode of $_sm_item $_sm_old -> $_sm_new ($_sm_why)" chmod "$_sm_new" "$_sm_p"
    _sm_rc=$?
    [ "$_sm_rc" -eq 0 ] && cc_undo_add "restore mode of $_sm_item" "chmod $_sm_old $(cc_shquote "$_sm_p")"
    row "$_sm_item" "$_sm_old" "$_sm_new" "$(result "$_sm_rc")"
}

# want_sysctl KEY VALUE -> queue one kernel setting for the sysctl step.
#   Keys this kernel does not have are recorded as skipped.
want_sysctl() {
    if is_excluded "$1"; then row "$1" "" "" "excluded"; return 0; fi
    if ! _ws_cur=$("$SYSCTL" -n "$1" 2>/dev/null); then
        row "$1" "" "$2" "skipped (not on this kernel)"
        return 0
    fi
    printf '%s|%s|%s|%s\n' "$FIX" "$1" "$2" "$_ws_cur" >>"$W/sysctl_want"
}

# ---- Fixes --------------------------------------------------------------------
: >"$W/sysctl_want"; : >"$W/report"
# report ITEM TEXT -> something to check by hand (summary and the CSV).
report() { printf '%s|%s|%s\n' "$FIX" "$1" "$2" >>"$W/report"; row "$1" "" "$2" "check by hand"; }

KEEPLO=0    # 1 = the ipv6 fix ran: keep IPv6 on the loopback interface
fix_sysctl() {
    [ "$CC_OS_KERNEL" = linux ] || { row "(all)" "" "" "skipped (not Linux)"; return 0; }
    want_sysctl net.ipv4.tcp_syncookies 1
    want_sysctl kernel.randomize_va_space 2
    want_sysctl net.ipv4.conf.all.accept_source_route 0
    want_sysctl net.ipv4.conf.default.accept_source_route 0
    want_sysctl net.ipv4.conf.all.accept_redirects 0
    want_sysctl net.ipv4.conf.default.accept_redirects 0
    want_sysctl net.ipv4.conf.all.secure_redirects 0
    want_sysctl net.ipv4.conf.default.secure_redirects 0
    want_sysctl net.ipv4.conf.all.send_redirects 0
    want_sysctl net.ipv4.conf.default.send_redirects 0
    want_sysctl net.ipv4.conf.all.log_martians 1
    want_sysctl net.ipv4.icmp_echo_ignore_broadcasts 1
    want_sysctl net.ipv4.icmp_ignore_bogus_error_responses 1
    want_sysctl fs.protected_symlinks 1
    want_sysctl fs.protected_hardlinks 1
    want_sysctl kernel.kptr_restrict 1
    want_sysctl kernel.dmesg_restrict 1
    want_sysctl kernel.unprivileged_bpf_disabled 1
    want_sysctl net.ipv4.tcp_rfc1337 1
    want_sysctl fs.protected_fifos 1
    want_sysctl fs.protected_regular 1
    # Not here on purpose: rp_filter (strict mode breaks multi-homed routers),
    # ip_forward (routers and Docker need it), ptrace_scope (debuggers).
}

fix_ipv6() {
    [ "$CC_OS_KERNEL" = linux ] || { row "(all)" "" "" "skipped (not Linux)"; return 0; }
    if ! "$SYSCTL" -n net.ipv6.conf.all.disable_ipv6 >/dev/null 2>&1; then
        row "(all)" "" "" "already ok (this kernel has no IPv6)"
        return 0
    fi
    # Loopback keeps IPv6: services bound only to ::1 keep working.  Services
    # on [::] (all addresses) keep working for IPv4.  Only a service bound to
    # one specific IPv6 address would stop answering - list those first.
    if cc_have ss; then
        ss -ltnH 2>/dev/null | awk '{ a = $4; sub(/:[^:]*$/, "", a); gsub(/[][]/, "", a)
            if (a ~ /:/ && a != "::" && a != "::1" && a !~ /^::ffff:/ && a !~ /^\*/) print $4 }' >"$W/v6"
        while IFS= read -r _l; do report "$_l" "listens on a specific IPv6 address; it stops answering once IPv6 is off"; done <"$W/v6"
    fi
    want_sysctl net.ipv6.conf.all.disable_ipv6 1
    want_sysctl net.ipv6.conf.default.disable_ipv6 1
    # "all" also switches IPv6 off on loopback and removes ::1.  It is
    # switched back on there AFTER the two settings above (see the kernel
    # settings step), so services bound to ::1 keep starting.
    "$SYSCTL" -n net.ipv6.conf.lo.disable_ipv6 >/dev/null 2>&1 && KEEPLO=1
}

fix_forwarding() {
    [ "$CC_OS_KERNEL" = linux ] || { row "(all)" "" "" "skipped (not Linux)"; return 0; }
    want_sysctl net.ipv4.ip_forward 0
    "$SYSCTL" -n net.ipv6.conf.all.forwarding >/dev/null 2>&1 && want_sysctl net.ipv6.conf.all.forwarding 0
}

fix_coredumps() {
    [ "$CC_OS_KERNEL" = linux ] && want_sysctl fs.suid_dumpable 0
    _lim=$(P /etc/security/limits.d)
    if [ -d "$_lim" ]; then
        _f="$_lim/99-bt-safe.conf"
        if [ -f "$_f" ] && grep -q '^\* *hard *core *0' "$_f"; then row "/etc/security/limits.d/99-bt-safe.conf" "" "* hard core 0" "already ok"; return 0; fi
        if ! cc_guard path "/etc/security/limits.d/99-bt-safe.conf"; then row "/etc/security/limits.d/99-bt-safe.conf" "" "" refused; return 0; fi
        printf '# Written by LX-39 (the kit): no core dumps for any account.\n* hard core 0\n' >"$W/limits.conf"
        cc_backup_file "$_f" || return 0
        cc_run "core size limit 0 in /etc/security/limits.d/99-bt-safe.conf" cp "$W/limits.conf" "$_f"
        _rc=$?
        [ "$_rc" -eq 0 ] && [ -z "$CC_LAST_BACKUP" ] && cc_undo_add "remove core limit file" "rm -f $(cc_shquote "$_f")"
        row "/etc/security/limits.d/99-bt-safe.conf" "" "* hard core 0" "$(result "$_rc")"
    else
        row "/etc/security/limits.d" "" "" "skipped (no limits.d folder)"
    fi
}

fix_perms() {
    # CLEAR masks: 0022 = group/other write; 0027 = group write + all other
    # access; 0077 = all group and other access.  Only bits are removed.
    for _f in /etc/passwd /etc/group; do set_mode "$(P "$_f")" 0022 0000 "only root may change it"; done
    for _f in /etc/shadow /etc/gshadow /etc/shadow- /etc/gshadow- /etc/security/opasswd; do
        set_mode "$(P "$_f")" 0027 0000 "password hashes: no access for other accounts"
    done
    set_mode "$(P /etc/sudoers)" 0027 0000 "sudo rules"
    for _f in "$(P /etc/sudoers.d)"/*; do set_mode "$_f" 0027 0000 "sudo rules"; done
    for _f in "$(P /etc/ssh)"/ssh_host_*_key; do set_mode "$_f" 0027 0000 "SSH host private key"; done
    set_mode "$(P /etc/ssh/sshd_config)" 0022 0000 "SSH server config"
    set_mode "$(P /root)" 0077 0000 "root's home"
    set_mode "$(P /etc/crontab)" 0022 0000 "system crontab"
    for _d in cron.d cron.hourly cron.daily cron.weekly cron.monthly; do
        set_mode "$(P /etc/$_d)" 0022 0000 "cron folder"
        for _f in "$(P /etc/$_d)"/*; do set_mode "$_f" 0022 0000 "cron job" quiet; done
    done
    # Files everyone's login runs or every program loads: writable by root only.
    for _f in /etc/profile /etc/bash.bashrc /etc/bashrc /etc/environment /etc/ld.so.conf /etc/ld.so.preload; do
        set_mode "$(P "$_f")" 0022 0000 "read at every login or program start"
    done
    for _d in /etc/profile.d /etc/ld.so.conf.d /etc/pam.d /etc/systemd/system; do
        [ -d "$(P "$_d")" ] || continue
        set_mode "$(P "$_d")" 0022 0000 "only root may add files here" quiet
        find "$(P "$_d")" -xdev -maxdepth 2 ! -type l \( -perm -0020 -o -perm -0002 \) 2>/dev/null >"$W/ww"
        while IFS= read -r _f; do set_mode "$_f" 0022 0000 "only root may change it"; done <"$W/ww"
    done
    # Anything world-writable in /etc, and in the folders on root's PATH.
    find "$(P /etc)" -xdev ! -type l -perm -0002 2>/dev/null >"$W/ww"
    for _d in /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin; do
        [ -d "$(P "$_d")" ] && [ ! -h "$(P "$_d")" ] && find "$(P "$_d")" -xdev -maxdepth 1 ! -type l -perm -0002 2>/dev/null >>"$W/ww"
    done
    # Home folders that anyone can write into (someone else could plant .bashrc).
    awk -F: '$6 ~ /^\/(home|root)/ { print $6 }' "$(P /etc/passwd)" 2>/dev/null | sort -u >"$W/homes"
    while IFS= read -r _h; do
        [ -d "$(P "$_h")" ] && find "$(P "$_h")" -maxdepth 0 -perm -0002 2>/dev/null >>"$W/ww"
    done <"$W/homes"
    sort -u "$W/ww" >"$W/ww.u"
    while IFS= read -r _f; do set_mode "$_f" 0002 0000 "world-writable"; done <"$W/ww.u"
}

fix_tmp() {
    for _d in /tmp /var/tmp /dev/shm; do
        [ -d "$(P "$_d")" ] || continue
        # Only world-writable shared folders need the sticky bit (users may
        # then delete only their own files there).
        if find "$(P "$_d")" -maxdepth 0 -perm -0002 2>/dev/null | grep -q .; then
            set_mode "$(P "$_d")" 0000 1000 "sticky bit: users cannot delete each other's files"
        else
            row "$_d" "$(mode_of "$(P "$_d")")" "" "already ok"
        fi
    done
}

# svc_state NAME -> "missing", "running" or "stopped"
svc_state() {
    case "$CC_INIT" in
        systemd)
            systemctl cat "$1.service" >/dev/null 2>&1 || { echo missing; return; }
            if systemctl is-active --quiet "$1" 2>/dev/null; then echo running; else echo stopped; fi ;;
        openrc)
            [ -e "/etc/init.d/$1" ] || { echo missing; return; }
            if rc-service "$1" status >/dev/null 2>&1; then echo running; else echo stopped; fi ;;
        *)
            [ -e "/etc/init.d/$1" ] || { echo missing; return; }
            if service "$1" status >/dev/null 2>&1; then echo running; else echo stopped; fi ;;
    esac
}
fix_logging() {
    [ -n "$R" ] && { row "(all)" "" "" "skipped (--root: services belong to the running system)"; return 0; }
    for _s in rsyslog syslog-ng auditd; do
        if is_excluded "$_s"; then row "$_s" "" "" "excluded"; continue; fi
        _st=$(svc_state "$_s")
        case "$_st" in
            missing) cc_debug "logging: $_s not installed" ;;
            running) row "$_s" running running "already ok" ;;
            stopped)
                if ! cc_guard service "$_s"; then row "$_s" stopped "" refused; continue; fi
                case "$CC_INIT" in
                    systemd) cc_run "start and enable $_s (logging)" systemctl enable --now "$_s"; _rc=$?
                             [ "$_rc" -eq 0 ] && cc_undo_add "stop $_s again" "systemctl disable --now $_s" ;;
                    openrc)  cc_run "start $_s (logging)" rc-service "$_s" start; _rc=$?
                             [ "$_rc" -eq 0 ] && cc_run "enable $_s at boot" rc-update add "$_s" default
                             [ "$_rc" -eq 0 ] && cc_undo_add "stop $_s again" "rc-service $_s stop; rc-update del $_s default" ;;
                    *)       cc_run "start $_s (logging)" service "$_s" start; _rc=$?
                             [ "$_rc" -eq 0 ] && cc_undo_add "stop $_s again" "service $_s stop" ;;
                esac
                row "$_s" stopped running "$(result "$_rc")" ;;
        esac
    done
}

# pkg_owner FILE -> the package that installed FILE, or nothing.
pkg_owner() {
    if cc_have dpkg; then dpkg -S "$1" 2>/dev/null | head -n 1 | cut -d: -f1
    elif cc_have rpm; then rpm -qf "$1" 2>/dev/null | grep -v 'not owned' | head -n 1
    fi
}
fix_preload() {
    _pl=$(P /etc/ld.so.preload)
    if is_excluded /etc/ld.so.preload; then row /etc/ld.so.preload "" "" "excluded"; _pl=/nonexistent/ld.so.preload; fi
    if [ -s "$_pl" ]; then
        # Every library named in it: owned by a package, or a red flag.
        _bad=""
        tr ' :' '\n\n' <"$_pl" | grep -v '^#' | grep . >"$W/preload"
        while IFS= read -r _lib; do
            _own=$(pkg_owner "$_lib")
            if [ -z "$_own" ]; then _bad="$_bad $_lib"; row "/etc/ld.so.preload: $_lib" "loaded into every program" "" "not owned by any package"
            else row "/etc/ld.so.preload: $_lib" "loaded into every program" "" "owned by package $_own"; fi
        done <"$W/preload"
        if [ -n "$_bad" ]; then
            cc_warn "/etc/ld.so.preload loads a library no package owns:$_bad - the classic user-mode rootkit hook"
            cc_quarantine "$_pl"
            _rc=$?
            if [ "$_rc" -eq 4 ]; then row "/etc/ld.so.preload" present present refused; else row "/etc/ld.so.preload" present "quarantined" "$(result "$_rc")"; fi
        fi
    else
        row "/etc/ld.so.preload" "absent or empty" "" "already ok"
    fi
    # LD_PRELOAD / LD_LIBRARY_PATH in /etc/environment apply to every login.
    _env=$(P /etc/environment)
    if [ -f "$_env" ] && grep -qE '^[[:space:]]*(export[[:space:]]+)?LD_(PRELOAD|LIBRARY_PATH)=' "$_env"; then
        if ! cc_guard path /etc/environment; then row /etc/environment "LD_PRELOAD set" "" refused; return 0; fi
        awk '/^[ \t]*(export[ \t]+)?LD_(PRELOAD|LIBRARY_PATH)=/ { print "# disabled by LX-39: " $0; next } { print }' "$_env" >"$W/environment"
        cc_backup_file "$_env" || return 0
        # cp onto the existing file keeps its owner and mode.
        cc_run "comment out LD_PRELOAD/LD_LIBRARY_PATH in /etc/environment" cp "$W/environment" "$_env"
        row /etc/environment "LD_PRELOAD or LD_LIBRARY_PATH set" "commented out" "$(result $?)"
    fi
}

fix_trust() {
    {
        printf '%s\n' /etc/hosts.equiv /etc/shosts.equiv /root/.rhosts /root/.shosts
        awk -F: '$6 != "" && $6 != "/" { print $6 "/.rhosts"; print $6 "/.shosts" }' "$(P /etc/passwd)" 2>/dev/null
    } | sort -u >"$W/trust"
    _n=0
    while IFS= read -r _f; do
        [ -e "$(P "$_f")" ] || continue
        if is_excluded "$_f"; then row "$_f" "" "" "excluded"; continue; fi
        _n=$((_n + 1))
        cc_quarantine "$(P "$_f")"
        _rc=$?
        if [ "$_rc" -eq 4 ]; then row "$_f" present present refused; else row "$_f" "lets other hosts log in without a password" quarantined "$(result "$_rc")"; fi
    done <"$W/trust"
    [ "$_n" -eq 0 ] && row "(rhosts-style files)" none "" "already ok"
}

# ---- Accounts -------------------------------------------------------------------
# The shadow file is edited with awk into a copy, then written back with
# cat (keeps its owner and mode).  The password field is never logged or
# stored: a lock only adds "!" in front, and the undo only removes it.

# uid0_list -> accounts other than root with UID 0.
uid0_list() { awk -F: '$3 == "0" && $1 != "root" { print $1 }' "$(P /etc/passwd)" 2>/dev/null; }
# emptypw_list -> accounts whose password field in shadow is empty.
emptypw_list() { awk -F: 'NF > 1 && $2 == "" { print $1 }' "$(P /etc/shadow)" 2>/dev/null; }

# lock_account USER EXPIRE WHY
#   Put "!" in front of USER's password (no password login) and, with
#   EXPIRE=1, set the account's expiry to day 1 (no login at all, SSH keys
#   included).  The undo removes the "!" and puts the old expiry back.
lock_account() {
    _la_u=$1; _la_e=$2; _la_why=$3
    _la_sf=$(P /etc/shadow)
    [ -r "$_la_sf" ] || { row "$_la_u" "" "" "skipped (cannot read /etc/shadow)"; return 0; }
    if is_excluded "$_la_u"; then row "$_la_u" "" "" "excluded"; return 0; fi
    # State without the secret: L = locked already, and the expiry field.
    _la_st=$(awk -F: -v u="$_la_u" '$1 == u { print (($2 ~ /^[!*]/) ? "L" : "U") "|" $8; exit }' "$_la_sf")
    [ -n "$_la_st" ] || { row "$_la_u" "" "" "skipped (not in /etc/shadow)"; return 0; }
    _la_lk=${_la_st%%"|"*}; _la_old8=${_la_st#*"|"}
    _la_bang=0; [ "$_la_lk" = U ] && _la_bang=1
    _la_exp=0; [ "$_la_e" = 1 ] && [ "$_la_old8" != 1 ] && _la_exp=1
    _la_before="unlocked"; [ "$_la_lk" = L ] && _la_before="locked"
    [ "$_la_e" = 1 ] && _la_before="$_la_before, expires ${_la_old8:-never}"
    _la_after="locked"; [ "$_la_e" = 1 ] && _la_after="locked, expired"
    if [ "$_la_bang" = 0 ] && [ "$_la_exp" = 0 ]; then row "$_la_u" "$_la_before" "$_la_after" "already ok"; return 0; fi
    if ! cc_guard account "$_la_u"; then row "$_la_u" "$_la_before" "$_la_after" refused; return 0; fi
    awk -F: -v OFS=: -v u="$_la_u" -v b="$_la_bang" -v e="$_la_exp" '
        $1 == u { if (b == 1) $2 = "!" $2; if (e == 1) $8 = 1 } { print }' "$_la_sf" >"$W/shadow.new"
    cc_run "lock account $_la_u ($_la_why)" sh -c 'cat "$1" >"$2"' sh "$W/shadow.new" "$_la_sf"
    _la_rc=$?
    rm -f "$W/shadow.new"
    if [ "$_la_rc" -eq 0 ]; then
        _la_q=$(cc_shquote "$_la_sf"); _la_t=$(cc_shquote "$_la_sf.bt-tmp")
        cc_undo_add "unlock account $_la_u" "awk -F: -v OFS=: -v u=$(cc_shquote "$_la_u") -v b=$_la_bang -v e=$_la_exp -v o=$(cc_shquote "$_la_old8") '\$1 == u { if (b == 1) sub(/^!/, \"\", \$2); if (e == 1) \$8 = o } { print }' $_la_q >$_la_t && cat $_la_t >$_la_q && rm -f $_la_t"
    fi
    row "$_la_u" "$_la_before" "$_la_after" "$(result "$_la_rc")"
}

fix_uid0() {
    uid0_list >"$W/uid0"
    [ -s "$W/uid0" ] || { row "(accounts with UID 0)" "only root" "" "already ok"; return 0; }
    while IFS= read -r _u; do lock_account "$_u" 1 "UID 0 = root-equivalent; a classic backdoor account"; done <"$W/uid0"
}

fix_emptypw() {
    [ -r "$(P /etc/shadow)" ] || { row /etc/shadow "" "" "skipped (cannot read it)"; return 0; }
    emptypw_list >"$W/emptypw"
    [ -s "$W/emptypw" ] || { row "(accounts with an empty password)" none "" "already ok"; return 0; }
    while IFS= read -r _u; do lock_account "$_u" 0 "empty password: anyone could log in as it"; done <"$W/emptypw"
}

# ---- SUID programs ------------------------------------------------------------------
# Programs that give a root shell when SUID (GTFOBins), but are never SUID on
# a normal system.  The usual SUID programs (passwd, sudo, su, mount, ping,
# pkexec, chsh ...) are not on this list and are never touched.
GTFO=" ash awk base64 bash busybox cat chmod chown cp csh curl cut dash date dd diff ed emacs env expect find flock gdb grep head hexdump ionice ip jq ksh less lua make more mv nano nawk gawk mawk nc ncat nice nmap node nohup od openssl perl php pico python python2 python3 rlwrap rsync run-parts rvim sed setarch socat sort sqlite3 strace systemctl tac tail tar taskset tclsh tee time timeout unshare vi view vim watch wget xargs xxd zip zsh "

# suid_list -> SUID files that should not be SUID, one path per line.
suid_list() {
    for _d in /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /opt /tmp /var/tmp /dev/shm /home /root; do
        [ -d "$(P "$_d")" ] && [ ! -h "$(P "$_d")" ] && find "$(P "$_d")" -xdev -type f -perm -4000 2>/dev/null
    done | sort -u | while IFS= read -r _p; do
        _i=${_p#"$R"}
        case "$_i" in /tmp/*|/var/tmp/*|/dev/shm/*|/home/*|/root/*) printf '%s\n' "$_i"; continue ;; esac
        _b=$(basename "$_i" | sed 's/[0-9.]*$//')
        case "$GTFO" in *" $_b "*) printf '%s\n' "$_i" ;; esac
    done
}

fix_suid() {
    suid_list >"$W/suid"
    [ -s "$W/suid" ] || { row "(SUID programs)" "only the usual ones" "" "already ok"; return 0; }
    while IFS= read -r _i; do set_mode "$(P "$_i")" 4000 0000 "SUID on a program that gives a root shell"; done <"$W/suid"
}

fix_hosts() {
    # Report only: scoring can depend on /etc/hosts, so nothing is changed.
    _h=$(P /etc/hosts)
    [ -r "$_h" ] || return 0
    _me=$(uname -n 2>/dev/null)
    awk -v me="$_me" -v short="${_me%%.*}" '
        /^[ \t]*#/ || NF < 2 { next }
        { keep = 0
          for (i = 2; i <= NF; i++) { n = $i; if (n ~ /^#/) break
              if (n ~ /^(localhost|ip6-|localhost\.|ip6-localhost)/ || n == me || n == short) keep = 1 }
          if (!keep && $1 !~ /^(127\.|::1$|ff0|fe00)/) print $0 }' "$_h" >"$W/hosts_extra"
    while IFS= read -r _l; do report "/etc/hosts: $_l" "name pinned to an address; check it is the team's (a red team uses this to redirect updates or logins)"; done <"$W/hosts_extra"
    [ -s "$W/hosts_extra" ] || row "/etc/hosts" "only local names" "" "already ok"
}

# ---- Questions ------------------------------------------------------------------
# fix_desc NAME -> the one-line description from --list.
fix_desc() { list_fixes | awk -v f="$1" '$1 == f { $1 = ""; sub(/^ +/, ""); print }'; }

header "QUESTIONS (Enter = the default in capitals)"
if [ -z "$BOX" ]; then
    cc_choose "Which box is this?" o "s=splunk" "w=webmail" "e=ecomm" "o=other"
    case "$CC_CHOICE" in s) BOX=splunk ;; w) BOX=webmail ;; e) BOX=ecomm ;; *) BOX=other ;; esac
fi
case "$BOX" in
    splunk)  cc_show "$C_GRY" "    Scored here: chrony (123/udp), Splunk management (8089), search, SSH, ping. LX-39 touches none of them." ;;
    webmail) cc_show "$C_GRY" "    Scored here: IMAP, SMTP, webmail login, SSH, ping. LX-39 touches none of them." ;;
    ecomm)   cc_show "$C_GRY" "    Scored here: HTTP, ping. If the store runs in Docker, IP forwarding must stay on." ;;
esac
if [ "$SETTLED" = 1 ]; then
    # --only / --skip decided the list.  forwarding still needs --no-forwarding
    # (or naming it in --only), because routers and Docker hosts need it.
    _keep=""
    for _f in $FIXES; do [ "$_f" = forwarding ] && [ "$NOFWD" = 0 ] && continue; _keep="$_keep $_f"; done
    FIXES=$_keep
    cc_show "$C_GRY" "    Fixes chosen by --only/--skip:$FIXES"
else
    _keep=""
    for _f in $FIXES; do
        case "$_f" in
            forwarding)
                if [ "$FWDFLAG" = 1 ]; then _keep="$_keep $_f"; continue; fi
                # Nobody to ask (--batch, no terminal): forwarding stays on
                # unless --no-forwarding said otherwise.
                if ! _cc_can_ask; then cc_show "$C_GRY" "    IP forwarding: left on (turn it off with --no-forwarding)"; continue; fi
                _d=N; [ "$BOX" = ecomm ] && _d=Y
                if cc_ask "Does this box route traffic or run Docker/containers? (they need IP forwarding)" "$_d" "yes, it does (forwarding stays on)" "no, it does not"; then
                    cc_show "$C_GRY" "    IP forwarding stays on."
                elif cc_ask "Turn IP forwarding off? (forwarding)" Y "yes, turn it off" "no, leave it on"; then
                    _keep="$_keep $_f"; NOFWD=1
                fi ;;
            ipv6)  cc_ask "Turn IPv6 off? Check no scored service uses IPv6 first (ipv6)" Y "yes, turn IPv6 off" "no, leave it on" && _keep="$_keep $_f" ;;
            hosts) cc_ask "Check /etc/hosts for odd entries? (hosts)" Y "yes, check it (report only, changes nothing)" "no, skip it" && _keep="$_keep $_f" ;;
            uid0|emptypw|suid)
                # Show what it found first, so you know what you are answering.
                case "$_f" in uid0) uid0_list >"$W/found" ;; emptypw) emptypw_list >"$W/found" ;; suid) suid_list >"$W/found" ;; esac
                if [ ! -s "$W/found" ]; then cc_show "$C_GRY" "    $_f: nothing found ($(fix_desc "$_f"))"; continue; fi
                _nf=$(grep -c . "$W/found")
                cc_show "$C_YEL" "    $_f found: $(head -n 6 "$W/found" | tr '\n' ' ')$([ "$_nf" -gt 6 ] && echo "+$((_nf - 6)) more (all in the plan below)")"
                cc_ask "$(fix_desc "$_f")? ($_f)" Y "yes, fix it" "no, skip it" && _keep="$_keep $_f" ;;
            *)     cc_ask "$(fix_desc "$_f")? ($_f)" Y "yes, fix it" "no, skip it" && _keep="$_keep $_f" ;;
        esac
        # A fix that acts on named items: ask what to leave alone (unless
        # --exclude already said).
        case " $_keep " in *" $_f "*) ;; *) continue ;; esac
        case " $EXCL_FIXES " in *" $_f "*) ;; *) continue ;; esac
        [ "$EXCLFLAG" = 1 ] && continue
        case "$_f" in
            uid0|emptypw) _what="account names" ;;
            suid|perms|trust|preload) _what="paths" ;;
            sysctl) _what="settings, e.g. net.ipv4.tcp_syncookies" ;;
            logging) _what="services: rsyslog, syslog-ng, auditd" ;;
        esac
        cc_ask_text "  Leave any alone for $_f?" "" "$_what separated by commas, or Enter to fix them all"
        [ -n "$CC_ANSWER" ] && EXCL="$EXCL,$CC_ANSWER"
    done
    FIXES=$_keep
fi
EXCL=$(printf '%s' "$EXCL" | tr -d ' ')
[ -n "$(printf '%s' "$EXCL" | tr -d ',')" ] && cc_show "$C_GRY" "    Left alone:$(printf '%s' "$EXCL" | tr ',' ' ')"
case " $FIXES " in *" forwarding "*) NOFWD=1 ;; esac

# ---- The fixes, as one pass ---------------------------------------------------
# run_all runs every chosen fix and the kernel settings step.  It runs twice:
# first as a dry run to show the plan, then (if you say yes) for real.
run_all() {
: >"$W/sysctl_want"; : >"$W/report"; : >"$W/handled"; KEEPLO=0
_ra_q=$CC_QUIET; CC_QUIET=1        # the coloured lines replace WOULD/DO lines
_ra_i=0; _ra_n=$(printf '%s\n' $FIXES | grep -c .)
for FIX in $FIXES; do
    _ra_i=$((_ra_i + 1))
    header "$_ra_i/$_ra_n  $FIX"
    "fix_$FIX"
    ok_line
done

# IP forwarding left on is worth a look even when it is not being changed.
if [ "$NOFWD" = 0 ] && [ "$CC_OS_KERNEL" = linux ] && [ "$("$SYSCTL" -n net.ipv4.ip_forward 2>/dev/null)" = 1 ]; then
    FIX=forwarding
    report net.ipv4.ip_forward "IP forwarding is on: right for a router, firewall or Docker host; otherwise run again with --no-forwarding"
fi

# ---- Kernel settings: one file for boot, then the running values -------------
if [ -s "$W/sysctl_want" ]; then
    header "kernel settings (sysctl, ipv6, forwarding, coredumps)"
    _sd=$(P /etc/sysctl.d)
    if [ -d "$_sd" ]; then _sf="$_sd/99-zz-bt-safe.conf"; _sfi=/etc/sysctl.d/99-zz-bt-safe.conf
    else _sf=$(P /etc/sysctl.conf); _sfi=/etc/sysctl.conf; fi
    # The boot file holds every wanted key (also those already right), so the
    # values survive a reboot even if another file sets them differently.
    {
        printf '# Written by LX-39 (the kit). Read last at boot (99-zz). Undo log has the old values.\n'
        awk -F'|' '{ print $2 " = " $3 }' "$W/sysctl_want"
        # Must come after "all": the last value written to an interface wins.
        [ "$KEEPLO" = 1 ] && printf '# loopback keeps IPv6 (::1) so services bound to it still start\nnet.ipv6.conf.lo.disable_ipv6 = 0\n'
    } >"$W/sysctl.conf"
    FIX=sysctl
    if ! cc_guard path "$_sfi"; then
        row "$_sfi" "" "" refused
    elif [ "$_sfi" = /etc/sysctl.conf ]; then
        cc_backup_file "$_sf" && cc_run "append kernel settings to /etc/sysctl.conf" sh -c 'cat "$1" >>"$2"' sh "$W/sysctl.conf" "$_sf"
        row "$_sfi" "" "$(grep -c . "$W/sysctl_want") settings" "$(result $?)"
    elif [ -f "$_sf" ] && cmp -s "$W/sysctl.conf" "$_sf" 2>/dev/null; then
        row "$_sfi" "" "" "already ok"
    else
        cc_backup_file "$_sf" && {
            cc_run "write kernel settings for boot to $_sfi" cp "$W/sysctl.conf" "$_sf"
            _rc=$?
            [ "$_rc" -eq 0 ] && [ -z "$CC_LAST_BACKUP" ] && cc_undo_add "remove $_sfi" "rm -f $(cc_shquote "$_sf")"
            row "$_sfi" "" "$(grep -c . "$W/sysctl_want") settings" "$(result "$_rc")"
        }
    fi
    # Running values: change only what differs; undo restores the old value.
    _v6set=0
    while IFS='|' read -r FIX _k _v _cur; do
        if [ "$_cur" = "$_v" ]; then row "$_k" "$_cur" "$_v" "already ok"; continue; fi
        [ "$_k" = net.ipv6.conf.all.disable_ipv6 ] && _v6set=1
        cc_run "kernel setting $_k $_cur -> $_v" "$SYSCTL" -w "$_k=$_v"
        _rc=$?
        [ "$_rc" -eq 0 ] && cc_undo_add "restore $_k" "$SYSCTL -w $_k=$_cur"
        row "$_k" "$_cur" "$_v" "$(result "$_rc")"
    done <"$W/sysctl_want"
    # Loopback: switched back on after "all" switched everything off.  Needed
    # when "all" was just changed (that also changed loopback) or when
    # loopback is off from an earlier change.
    if [ "$KEEPLO" = 1 ]; then
        FIX=ipv6; _k=net.ipv6.conf.lo.disable_ipv6
        _cur=$("$SYSCTL" -n "$_k" 2>/dev/null)
        if [ "$_v6set" = 1 ] || [ "$_cur" != 0 ]; then
            cc_run "keep IPv6 on loopback (::1 stays)" "$SYSCTL" -w "$_k=0"
            row "$_k" "$_cur" 0 "$(result $?)"
        else
            row "$_k" "$_cur" 0 "already ok"
        fi
    fi
    ok_line
fi
CC_QUIET=$_ra_q
}

# ---- Plan, then apply -----------------------------------------------------------
CSV=$(cc_csv_new plan "fix,item,before,after,status")
_real_apply=$CC_APPLY; CC_APPLY=0
header "PLAN (dry run: nothing is changed yet)"
run_all
CC_APPLY=$_real_apply
NCH=$(awk "$CC_AWK_CSV"'NR > 1 { csvsplit($0, f); if (f[5] == "would change") n++ } END { print n + 0 }' "$CSV")
cc_csv_pretty "$CSV" "$CC_RUN_DIR/plan.txt" 80
APPLIED=0
header "DECISION"
if [ "$NCH" -eq 0 ]; then
    cc_show "$C_GRN" "[ok] Nothing to change: every chosen fix is already in place."
elif [ "$CANAPPLY" = 0 ]; then
    cc_show "$C_GRY" "$NCH change(s) planned. Dry run only, so nothing was changed."
else
    _ad=N; [ "$APPLY_FLAG" = 1 ] && _ad=Y
    if cc_ask "Apply these $NCH change(s)?" "$_ad" "yes, apply them now" "no, change nothing"; then
        if [ "$APPLY_FLAG" = 0 ] && ! protected_check; then
            cc_show "$C_YEL" "[*] Not applied: no protected list."
        elif cc_timer_fired || { [ "$CC_TIMER_DEADLINE" -gt 0 ] && [ "$(cc_timer_left)" -lt 3 ]; }; then
            cc_die 3 "the revert timer ran out before anything was changed. Nothing was changed. Run again (--batch or flags skip the questions; --timer SECONDS gives more time)"
        else
            CC_APPLY=1; APPLIED=1; CC_N_WOULD=0    # the plan pass counted these
            CSV=$(cc_csv_new fixes "fix,item,before,after,status")
            header "APPLYING"
            run_all
            cc_csv_pretty "$CSV" "$CC_RUN_DIR/fixes.txt" 80
        fi
    else
        cc_show "$C_GRY" "Not applied. The plan is in $CC_RUN_DIR/plan.txt"
    fi
fi

# ---- Summary ------------------------------------------------------------------
{
    printf 'LX-39 Linux safe fixes | host %s | %s | %s\n' "$CC_HOST" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$([ "$CC_APPLY" = 1 ] && echo APPLIED || echo 'DRY RUN - nothing changed')"
    [ -n "$R" ] && printf 'File fixes acted on %s\n' "$R"
    printf '\n'
    awk -v fixes="$FIXES" "$CC_AWK_CSV"'
        NR > 1 { csvsplit($0, f); st = f[5]; k = f[1]
                 if (st == "changed" || st == "would change") ch[k]++
                 else if (st ~ /^already ok/) ok[k]++
                 else if (st == "failed") fl[k]++
                 else if (st == "refused") rf[k]++
                 else if (st == "check by hand") hb[k]++
                 else other[k]++ }
        END {
            printf "%-11s %8s %6s %6s %7s %6s\n", "fix", "changes", "ok", "failed", "refused", "check"
            n = split(fixes, fx, " ")
            for (i = 1; i <= n; i++) { k = fx[i]; printf "%-11s %8d %6d %6d %7d %6d\n", k, ch[k], ok[k], fl[k], rf[k], hb[k] }
            if (hb["forwarding"] && fixes !~ /forwarding/) printf "%-11s %8d %6d %6d %7d %6d\n", "forwarding", 0, 0, 0, 0, hb["forwarding"]
        }' "$CSV"
    printf '\n'
    awk "$CC_AWK_CSV"'NR > 1 { csvsplit($0, f); if (f[5] == "changed" || f[5] == "would change" || f[5] == "failed")
        printf "  %-13s %-10s %s%s\n", toupper(f[5]), f[1], f[2], (f[3] != "" || f[4] != "" ? "  [" f[3] " -> " f[4] "]" : "") }' "$CSV" | head -n 60
    _nch=$(awk "$CC_AWK_CSV"'NR > 1 { csvsplit($0, f); if (f[5] == "changed" || f[5] == "would change" || f[5] == "failed") n++ } END { print n + 0 }' "$CSV")
    [ "$_nch" -gt 60 ] && printf '  ... %d more in fixes.txt\n' "$((_nch - 60))"
    [ "$_nch" -eq 0 ] && printf '  Nothing to change: every fix was already in place.\n'
    if [ -s "$W/report" ]; then
        printf '\nCheck by hand (not changed):\n'
        awk -F'|' '{ l = "  " $2 ": " $3; if (length(l) > 200) l = substr(l, 1, 197) "..."; print l }' "$W/report"
    fi
    printf '\n'
    if [ "$APPLIED" = 1 ]; then
        printf 'Undo this run at any time: sh %s/revert.sh --force\n' "$CC_RUN_DIR"
        printf '(every host change is also in %s)\n' "$CC_UNDO"
    else
        printf 'Nothing was changed.\n'
    fi
    printf 'All results: %s\n' "$CC_RUN_DIR"
} >"$CC_RUN_DIR/summary.txt"
# Without a timer, revert.sh still needs writing for "undo at any time".
if [ "$APPLIED" = 1 ] && [ -z "$CC_TIMER_DIR" ]; then
    cc_show "$C_GRY" "Undo commands: $CC_UNDO (newest at the bottom)"
fi
header "SUMMARY"
# Coloured on screen: red failed, green changed, yellow would-change and
# check-by-hand, cyan headings.  summary.txt and output.txt stay plain.
awk -v R="$C_RED" -v Y="$C_YEL" -v G="$C_GRN" -v C="$C_CYN" -v D="$C_GRY" -v O="$C_OFF" '
    NR == 1 || /^fix +changes/ { intable = /^fix/; print C $0 O; next }
    intable && /^$/            { intable = 0; print; next }
    intable                    { if ($4 + 0 > 0) print R $0 O; else if ($2 + 0 > 0) print Y $0 O; else print G $0 O; next }
    /^  CHANGED/               { print G $0 O; next }
    /^  FAILED/                { print R $0 O; next }
    /^  WOULD CHANGE/          { print Y $0 O; next }
    /^Check by hand/           { hand = 1; print Y $0 O; next }
    hand && /^  /              { print Y $0 O; next }
    /^Nothing to change/ || /^  Nothing to change/ { print G $0 O; next }
                               { hand = 0; print D $0 O }
' "$CC_RUN_DIR/summary.txt"
cat "$CC_RUN_DIR/summary.txt" >>"$OUTF"
rm -rf "$W"
if [ "$APPLIED" = 1 ]; then
    header "KEEP OR REVERT"
    cc_timer_finish
elif [ -n "$CC_TIMER_DIR" ]; then
    cc_timer_cancel; : >"$CC_TIMER_DIR/KEEP"
fi
cc_finish
