#!/bin/sh
# =============================================================================
# ID:       SH-05
# NAME:     Linux enum
# ROLE:     Linux  (wave 1)
# KIND:     readonly - changes nothing on the host
# VERSION:  1.1.0
#
# PURPOSE
#   One run shows what a Unix host is and what is on it: who can log in, what
#   is listening, what starts on boot or on a schedule, who can become root,
#   what is running, and the places a red team usually hides.  It is the
#   first thing to run on every Linux/Unix box, and most later scripts and
#   inventory injects reuse its CSV files.
#
#   Output is layered so it is thorough without being overwhelming (rule 17):
#     screen (live)          like linpeas: a header per section as it runs,
#                            then what it found.  Red [!] FIX = HIGH, fix now;
#                            yellow [*] LOOK = MED, look soon; grey = info.
#                            Everything on screen (including warnings) is
#                            saved without colour in output.txt
#     summary.txt            one page at the end: key facts, a count per
#                            section, and the HIGH and MED flags, worst first
#     <section>.txt          everything collected, one readable table per section
#     flags.txt              every flag including LOW, with the reason
#     csv/                   the same data as CSV, for SH-04 and other tools
#     raw/*.txt              untouched tool output (iptables-save, sshd -T ...)
#
# USAGE
#   sh SH-05-linux-enum.sh [options]
#   Run as root.  It works as a normal user, but several sections are then
#   incomplete (shadow file, sudoers, other users' processes); the summary
#   says which.
#
# OPTIONS
#   --profile NAME   card | full | triage   (default: full)
#                      card    quick look, under a minute: system, users,
#                              ports, services, autostart, ssh, sudo, privesc
#                      full    card plus processes, connections, sessions,
#                              packages, files, firewall, pam, mac, trust,
#                              creds, containers, modules
#                      triage  full plus a copy of the logs (incident start)
#   --only a,b,c     run only these sections (names from --list)
#   --skip a,b,c     run the profile without these sections
#   --fast           skip the slow whole-disk searches (files, creds)
#   --max-flags N    how many HIGH/MED flags to print in the end summary (default 30)
#   --low            also show LOW flags live (they are always in flags.txt)
#   --no-color       no colours (also off when the output is not a terminal,
#                    or when NO_COLOR is set)
#   --list           list the sections and exit
#   --help           this text plus the common options
#   Common options (--out, --debug, --quiet ...) come from the library.
#
# OUTPUTS  (under the --out folder; never next to this script)
#   One numbered folder per run: linux-enum-1, linux-enum-2, ... (the higher
#   the number, the newer the run)
#   SH-05_<host>_<UTC time>.log      log of the run (in the --out folder)
#   linux-enum-N/output.txt          everything shown live, without colour
#   linux-enum-N/summary.txt         the one-page summary
#   linux-enum-N/flags.txt           every flag, as a readable table
#   linux-enum-N/<section>.txt       each section as a readable table
#   linux-enum-N/csv/*.csv           the same as CSV (used by SH-04)
#   linux-enum-N/raw/*.txt           raw tool output
#   linux-enum-N/logs/               copied logs (triage only)
#   linux-enum-N/run.txt             id, host and start time (read by SH-04)
#
# WHAT IT CHANGES
#   Nothing.  It only reads.  It never prints or stores a password value:
#   the creds section records the FILE and the SETTING NAME, not the value.
#
# DEPENDS ON  (every one has a fallback; a missing tool only thins a section)
#   ports        ss -> netstat -> sockstat (BSD) -> /proc/net (no tools)
#   processes    ps (procps / BSD / busybox / -ef forms)
#   services     systemctl -> service -> rc-status -> BSD service -> svcs
#   packages     dpkg-query, rpm, apk, pacman, pkg, pkginfo
#   firewall     iptables-save, ip6tables-save, nft, ufw, firewall-cmd, pfctl
#   files        find, lsattr (immutable flags), getcap (capabilities)
#   everything   awk, sed, grep, ls - present on every Unix
#
# TESTED ON
#   Debian-based Linux container, as root and as an unprivileged user, under
#   dash, bash, busybox sh, ksh93, mksh and yash.  NOT yet tested on RHEL,
#   SUSE, Alpine, FreeBSD or Solaris; the BSD and Solaris paths are written
#   but unproven.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - Flags are pointers, not verdicts.  Some will be legitimate on your box
#     (a service account that really needs a shell).  Look, then decide.
#   - It sees what the operating system reports.  A kernel rootkit can hide
#     processes, files and ports from every tool this script uses.
#   - Accounts come from /etc/passwd only; LDAP or NIS users are not listed.
#   - The files and creds sections walk the disk and can take minutes on a
#     large server.  Use --fast or --profile card when time matters.
#   - Port-to-process mapping needs root; as a normal user the pid/process
#     columns are blank for other users' sockets.
#
# DEBUGGING
#   --debug            prints each tool choice and each section's timing
#   sh -x SH-05-...    traces every command
#   raw/*.txt          shows exactly what each tool printed, so a parsing
#                      mistake can be told apart from missing data
#   Each section is independent: if one misbehaves, rerun with --only NAME.
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

ALL_SECTIONS="system users ports services autostart ssh sudo privesc processes connections sessions packages files firewall pam mac trust creds containers modules logs"
PROFILE_CARD="system users ports services autostart ssh sudo privesc"
PROFILE_FULL="$PROFILE_CARD processes connections sessions packages files firewall pam mac trust creds containers modules"
PROFILE_TRIAGE="$PROFILE_FULL logs"

usage() {
    cat <<'USAGE'
SH-05 Linux enum - read-only look at a Unix host
  sh SH-05-linux-enum.sh [options]

  --profile card|full|triage   how much to collect (default full)
  --only a,b,c                 run only these sections
  --skip a,b,c                 leave these sections out
  --fast                       skip the slow disk searches (files, creds)
  --max-flags N                HIGH/MED flags in the end summary (default 30)
  --low                        also show LOW flags live
  --no-color                   no colours
  --list                       list the sections and exit
  --help                       show this text

USAGE
    cc_usage_common
}

list_sections() {
    cat <<'LIST'
system       host facts, addresses, routes, DNS, hosts file, ld.so.preload
users        accounts, password state, admin and root-equivalent groups
ports        listening ports with the process and program behind each
services     services, enabled/running state, suspicious unit files
autostart    cron, at, timers, rc.local, shell startup files, motd, udev
ssh          effective sshd settings and every authorized_keys entry
sudo         sudoers, doas and polkit rules
privesc      ways to become root: root-run files others can change, risky sudo
             rules, writable key files, PATH, known root bugs (sudo, pkexec, kernel)
processes    every process with its program file
connections  live network connections with the process behind each
sessions     who is logged in now, recent logins
packages     installed packages and versions
files        SUID/SGID, capabilities, world-writable, immutable files   (slow)
firewall     host firewall rules for IPv4 and IPv6
pam          login (PAM) configuration and module integrity
mac          SELinux / AppArmor state
trust        .rhosts, hosts.equiv, NFS exports, mounts, TCP wrappers
creds        files holding passwords (names only), keys, shell history (slow)
containers   docker / podman / lxc / kubernetes
modules      kernel modules and module load hooks
logs         copy of the system and service logs   (triage profile only)
LIST
}

# ---- Options ----------------------------------------------------------------
PROFILE=full
ONLY=""
SKIP=""
FAST=0
MAXFLAGS=30
SHOWLOW=0
COLOR=1
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --profile)   [ $# -ge 2 ] || cc_die 2 "--profile needs card, full or triage"; PROFILE=$2; shift 2 ;;
        --only)      [ $# -ge 2 ] || cc_die 2 "--only needs a list of sections"; ONLY=$2; shift 2 ;;
        --skip)      [ $# -ge 2 ] || cc_die 2 "--skip needs a list of sections"; SKIP=$2; shift 2 ;;
        --fast)      FAST=1; shift ;;
        --max-flags) [ $# -ge 2 ] || cc_die 2 "--max-flags needs a number"; MAXFLAGS=$2; shift 2 ;;
        --low)       SHOWLOW=1; shift ;;
        --no-color|--no-colour) COLOR=0; shift ;;
        --list)      list_sections; exit 0 ;;
        --help|-h)   usage; exit 0 ;;
        *)           cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done

case "$PROFILE" in
    card)   SECTIONS=$PROFILE_CARD ;;
    full)   SECTIONS=$PROFILE_FULL ;;
    triage) SECTIONS=$PROFILE_TRIAGE ;;
    *)      cc_die 2 "unknown profile '$PROFILE' (use card, full or triage)" ;;
esac
case "$MAXFLAGS" in ''|*[!0-9]*) cc_die 2 "--max-flags needs a whole number" ;; esac

# check_names LIST -> stop with exit 2 if any name is not a section.
check_names() {
    for _cn in $(printf '%s' "$1" | tr ',' ' '); do
        case " $ALL_SECTIONS " in *" $_cn "*) ;; *) cc_die 2 "unknown section '$_cn' (see --list)" ;; esac
    done
}
if [ -n "$ONLY" ]; then
    check_names "$ONLY"
    SECTIONS=$(printf '%s' "$ONLY" | tr ',' ' ')
fi
if [ -n "$SKIP" ]; then
    check_names "$SKIP"
    _keep=""
    for _s in $SECTIONS; do
        case ",$SKIP," in *",$_s,"*) ;; *) _keep="$_keep $_s" ;; esac
    done
    SECTIONS=$_keep
fi
if [ "$FAST" = 1 ]; then
    _keep=""
    for _s in $SECTIONS; do
        case "$_s" in files|creds) ;; *) _keep="$_keep $_s" ;; esac
    done
    SECTIONS=$_keep
fi

# ---- Start ------------------------------------------------------------------
cc_init "SH-05" "Linux enum" readonly
cc_use_numbered_dir linux-enum
# CSV files (for SH-04 and other tools) go in csv/; the run folder itself
# gets a readable .txt table per file at the end.
CC_CSV_DIR="$CC_RUN_DIR/csv"
mkdir -p "$CC_CSV_DIR" || cc_die 3 "cannot create $CC_CSV_DIR"
cc_detect_os
W="$CC_RUN_DIR/.work"          # scratch files; removed at the end
mkdir -p "$W" || cc_die 3 "cannot create $W"

# ---- Live output (linpeas style) ---------------------------------------------
# Printed to file descriptor 3, a copy of the real stdout taken here, so a
# flag raised inside $( ... ) still reaches the screen instead of ending up
# in the captured text.  output.txt gets the same lines without colour.
exec 3>&1
OUTF="$CC_RUN_DIR/output.txt"
# Start with the lines already shown before the run folder existed (the
# start line, any early warnings), taken from the log.
grep -v '\[NOTE\]\|\[DEBUG\]' "$CC_LOG" >"$OUTF" 2>/dev/null || : >"$OUTF"
CC_TEE=$OUTF                   # info and warning lines go in output.txt too
if [ "$COLOR" = 1 ] && [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_RED=$(printf '\033[1;31m'); C_YEL=$(printf '\033[1;33m'); C_GRN=$(printf '\033[1;32m')
    C_CYN=$(printf '\033[1;36m'); C_GRY=$(printf '\033[0;90m'); C_OFF=$(printf '\033[0m')
else
    C_RED=""; C_YEL=""; C_GRN=""; C_CYN=""; C_GRY=""; C_OFF=""
fi
# show COLOUR TEXT -> one line on screen in COLOUR, and plain in output.txt.
show() {
    printf '%s%s%s\n' "$1" "$2" "$C_OFF" >&3
    printf '%s\n' "$2" >>"$OUTF"
}
show "$C_CYN" "SH-05 Linux enum | host $CC_HOST | profile $PROFILE | results in $CC_RUN_DIR"
show "" "Legend: ${C_RED}[!] FIX${C_OFF} fix now (HIGH)   ${C_YEL}[*] LOOK${C_OFF} look soon (MED)   ${C_GRY}grey${C_OFF} info"
IS_ROOT=0
cc_is_root && IS_ROOT=1
[ "$IS_ROOT" = 1 ] || cc_warn "not running as root: users, sudo, ports, processes and files will be incomplete"

# Lowest UID for real people; system accounts sit below it.
UID_MIN=$(awk '$1 == "UID_MIN" { print $2; exit }' /etc/login.defs 2>/dev/null)
case "$UID_MIN" in ''|*[!0-9]*) UID_MIN=1000 ;; esac

# Patterns used by several sections.  ERE, for grep -E.
#   SUSP_STRONG  almost never legitimate in a cron line, unit file or profile:
#                reverse shells, download-and-run, encoded commands.
#   SUSP_WEAK    sometimes legitimate, worth a look: temp folders, downloads,
#                account and firewall changes.
SUSP_STRONG='(/dev/tcp/|/dev/udp/|bash -i|sh -i|nc .*-e |ncat .*-e|socat .*exec|mkfifo|(curl|wget)[^|;]*\|[[:space:]]*(ba|da|z)?sh|base64 +(-d|--decode)|python[0-9.]* +-c|perl +-e|php +-r|ruby +-e|xxd +-r|openssl +s_client)'
SUSP_WEAK='(/tmp/|/var/tmp/|/dev/shm/|curl |wget |chattr |useradd |usermod |iptables +-F|nft +flush)'

# Programs that give a root shell when they carry the SUID bit (from the
# GTFOBins project).  Compared against the program name with any trailing
# version number removed, so python3.11 counts as python.
GTFO=" aria2c ash awk base64 bash busybox cat chmod chown cp csh curl cut dash date dd diff docker ed emacs env expect find flock gdb grep head hexdump ionice ip jq ksh less lua make more mv nano nawk gawk mawk nc ncat nice nmap node nohup od openssl perl php pico python python2 python3 rlwrap rsync run-parts rvim sed setarch socat sort sqlite3 strace systemctl tac tail tar taskset tclsh tee time timeout unshare vi view vim watch wget xargs xxd zip zsh "

# Names that mean "this is a shell or a netcat-like tool".
SHELLS_RE='^(sh|bash|dash|zsh|ksh|ksh93|mksh|csh|tcsh|ash|busybox)$'
NETCAT_RE='^(nc|ncat|netcat|nc\.traditional|nc\.openbsd|socat|cryptcat|pwncat|gs-netcat)$'
TMP_RE='^(/tmp|/var/tmp|/dev/shm|/run/shm)(/|$)'

# ---- Section helpers --------------------------------------------------------
# All loops read from files, never from a pipe.  In dash and bash the right
# side of a pipe runs in a subshell, so counters and variables set inside
# 'cmd | while read' are lost when the loop ends.

# sec_csv NAME HEADER  -> create <run>/NAME.csv; its path is left in SEC_CSV.
#   (A variable, not printed output, so the caller does not need $( ), which
#   would lose the SEC_FILES bookkeeping.)
sec_csv() {
    SEC_CSV=$(cc_csv_new "$1" "$2") || SEC_CSV=/dev/null
    SEC_FILES="$SEC_FILES $SEC_CSV"
}

# flag SEVERITY ITEM DETAIL  -> cc_flag with the current section filled in.
#   Also shows it live: HIGH red, MED yellow, LOW grey (only with --low).
flag() {
    cc_flag "$1" "$SEC" "$2" "$3"
    case "$1" in
        HIGH) show "$C_RED" "  [!] FIX   $2: $3" ;;
        MED)  show "$C_YEL" "  [*] LOOK  $2: $3" ;;
        LOW)  [ "$SHOWLOW" = 1 ] && show "$C_GRY" "  [-] info  $2: $3" ;;
    esac
    return 0
}

# emit_flags FILE  -> turn lines "SEVERITY|ITEM|DETAIL" (written by an awk
#   program) into flags.  Lets awk do the checking without a loop per line.
emit_flags() {
    [ -s "$1" ] || return 0
    while IFS='|' read -r _ef_sev _ef_item _ef_detail; do
        case "$_ef_sev" in HIGH|MED|LOW) flag "$_ef_sev" "$_ef_item" "$_ef_detail" ;; esac
    done <"$1"
}

# say TEXT  -> add a line to the summary's key-facts block.
say() { printf '%s\n' "$*" >>"$W/summary_lines"; show "$C_GRN" "  $*"; }

# note TEXT -> attach a short note to this section's row in the summary table
#   (for example "partial: not root").
note() { if [ -z "$SEC_NOTE" ]; then SEC_NOTE=$*; else SEC_NOTE="$SEC_NOTE; $*"; fi; }

# owner_of PATH -> print the owning user name.
owner_of() { ls -ld "$1" 2>/dev/null | awk '{ print $3 }'; }

# mode_of PATH  -> print the permission string, e.g. -rwsr-xr-x.
mode_of() { ls -ld "$1" 2>/dev/null | awk '{ print $1 }'; }

# home_dirs -> write "user|uid|home" for every account in /etc/passwd to $W/homes.
home_dirs() {
    awk -F: '{ print $1 "|" $3 "|" $6 }' /etc/passwd >"$W/homes" 2>/dev/null
}

# awk helper: q() quotes one CSV field.  Pasted in front of awk programs that
# write CSV rows directly (faster than one cc_csv_row call per line).
AWK_Q='function q(s) { gsub(/"/, "\"\"", s); gsub(/\r|\n/, " ", s); return "\"" s "\"" }'

# =============================================================================
# Sections.  Each one: create its CSV file(s), collect, flag, add summary
# lines.  A missing tool is noted, never fatal.
# =============================================================================

s_system() {
    sec_csv facts "key,value"
    F=$SEC_CSV
    _fqdn=$(hostname -f 2>/dev/null || uname -n)
    _boot=$(who -b 2>/dev/null | awk '{ $1 = ""; $2 = ""; sub(/^ +/, ""); print }')
    _up=$(uptime 2>/dev/null | sed 's/^ *//')
    _ip6=no
    if [ -r /proc/net/if_inet6 ] && awk '$6 != "lo" { found = 1 } END { exit !found }' /proc/net/if_inet6; then _ip6=yes; fi
    _container=no
    if [ -f /.dockerenv ] || grep -qE '(docker|kubepods|containerd|lxc)' /proc/1/cgroup 2>/dev/null; then _container=yes; fi
    for _kv in "hostname|$CC_HOST" "fqdn|$_fqdn" "os|$CC_OS_NAME" "os_family|$CC_OS_FAMILY" \
               "os_version|$CC_OS_VERSION" "kernel|$(uname -r 2>/dev/null)" "arch|$(uname -m 2>/dev/null)" \
               "init|$CC_INIT" "package_manager|$CC_PKG" "boot_time|$_boot" "uptime|$_up" \
               "time_utc|$(date -u +%Y-%m-%dT%H:%M:%SZ)" "time_local|$(date)" "ipv6_enabled|$_ip6" \
               "inside_container|$_container" "collector_run_as_root|$IS_ROOT"; do
        cc_csv_row "$F" "${_kv%%"|"*}" "${_kv#*"|"}"
    done

    # Addresses.  'ip -o' gives one line per address; ifconfig is the fallback
    # (BSD, Solaris, old Linux) and is parsed loosely.
    sec_csv addresses "interface,family,address"
    A=$SEC_CSV
    if cc_have ip; then
        cc_save ip_addr ip addr
        ip -o addr show 2>/dev/null | awk "$AWK_Q"'{ print q($2) "," q($3) "," q($4) }' >>"$A"
        cc_save ip_route ip route
        ip -6 route >>"$CC_LAST_SAVE" 2>&1
    elif cc_have ifconfig; then
        cc_save ifconfig ifconfig -a
        awk "$AWK_Q"'
            /^[A-Za-z0-9]/ { iface = $1; sub(/:$/, "", iface) }
            $1 == "inet" || $1 == "inet6" {
                addr = $2; sub(/^addr:/, "", addr)
                print q(iface) "," q($1) "," q(addr)
            }' "$CC_LAST_SAVE" >>"$A"
        cc_save routes netstat -rn
    elif [ -r /proc/net/fib_trie ]; then
        # No ip or ifconfig (minimal container): the kernel's routing table
        # lists every local IPv4 address as a "host LOCAL" entry.
        cc_save fib_trie cat /proc/net/fib_trie
        awk "$AWK_Q"'/\|--/ { ip = $2 } /host LOCAL/ { print q("?") ",\"inet\"," q(ip) }' /proc/net/fib_trie | sort -u >>"$A"
        note "no ip or ifconfig: addresses read from /proc, interface names unknown"
    else
        note "no ip or ifconfig"
    fi
    _addrs=$(awk -F'","' 'NR > 1 && $2 ~ /^inet$/ && $3 !~ /^127\./ { printf "%s%s %s", sep, $1, $3; sep = "; " }' "$A" | tr -d '"')
    say "Addresses: ${_addrs:-none found}"

    # DNS servers and the hosts file.  A red team edits /etc/hosts to send a
    # name (an update server, the scoring engine's target) somewhere else.
    _dns=$(awk '$1 == "nameserver" { printf "%s%s", sep, $2; sep = ", " }' /etc/resolv.conf 2>/dev/null)
    cc_csv_row "$F" "dns_servers" "$_dns"
    say "DNS servers: ${_dns:-none}"
    if [ -r /etc/hosts ]; then
        awk -v me="$CC_HOST" '
            /^[ \t]*(#|$)/ { next }
            $1 ~ /^(127\.|::1$|fe00::|ff0[0-9]::)/ { next }
            {
                own = 0
                for (i = 2; i <= NF; i++) { n = $i; sub(/\..*/, "", n); if (n == me) own = 1 }
                if (!own) print "LOW|" $0 "|hosts file maps a name to an address; check it is meant to be there"
            }' /etc/hosts >"$W/f_hosts"
        emit_flags "$W/f_hosts"
        cc_save hosts cat /etc/hosts
    fi

    # /etc/ld.so.preload makes every program load a library first.  It is
    # empty or absent on a normal system and is a classic rootkit hook.
    if [ -s /etc/ld.so.preload ] && grep -qv '^[[:space:]]*\(#\|$\)' /etc/ld.so.preload; then
        flag HIGH /etc/ld.so.preload "every program loads: $(grep -v '^[[:space:]]*#' /etc/ld.so.preload | tr '\n' ' ')- a common rootkit hook"
        cc_save ld_so_preload cat /etc/ld.so.preload
    fi
    if [ -r /proc/sys/net/ipv4/ip_forward ] && [ "$(cat /proc/sys/net/ipv4/ip_forward)" = 1 ]; then
        flag LOW ip_forward "IP forwarding is on; expected only on routers and container hosts"
    fi
    cc_save disk df -P
    cc_have free && cc_save memory free -m
}

s_users() {
    sec_csv users "user,uid,gid,home,shell,can_login,password,groups"
    F=$SEC_CSV
    if [ -r /etc/shadow ]; then
        awk -F: '{ print $1 "|" $2 }' /etc/shadow >"$W/shadow"
    else
        : >"$W/shadow"
        note "partial: /etc/shadow not readable"
    fi
    # One awk pass joins passwd, shadow and group, writes the CSV, prints flag
    # lines and two summary lines.  The password HASH is never written: only
    # its state (set, EMPTY, locked).
    awk -F: -v uidmin="$UID_MIN" -v shf="$W/shadow" -v csv="$F" -v sumf="$W/summary_lines" "$AWK_Q"'
        BEGIN {
            while ((getline l < shf) > 0) { i = index(l, "|"); sh[substr(l, 1, i - 1)] = substr(l, i + 1); hassh = 1 }
            while ((getline l < "/etc/group") > 0) {
                split(l, g, ":"); gid2name[g[3]] = g[1]
                m = split(g[4], mem, ",")
                for (j = 1; j <= m; j++) if (mem[j] != "") ug[mem[j]] = ug[mem[j]] (ug[mem[j]] == "" ? "" : " ") g[1]
            }
        }
        /^[ \t]*(#|$)/ { next }
        {
            user = $1; uid = $3; gid = $4; home = $6; shell = $7
            groups = ug[user]; pg = gid2name[gid]
            if (pg != "" && index(" " groups " ", " " pg " ") == 0) groups = pg (groups == "" ? "" : " " groups)
            login = (shell == "" || shell ~ /(nologin|false|sync|shutdown|halt)$/) ? "no" : "yes"
            pw = "unknown"
            if (hassh) {
                if (!(user in sh)) pw = "not in shadow"
                else if (sh[user] == "") pw = "EMPTY"
                else if (sh[user] ~ /^[!*]/) pw = "locked"
                else pw = "set"
            }
            if ($2 == "") pw = "EMPTY"
            else if ($2 != "x" && $2 != "*" && $2 !~ /^!/) pw = "hash in passwd"
            print q(user) "," q(uid) "," q(gid) "," q(home) "," q(shell) "," q(login) "," q(pw) "," q(groups) >> csv

            if (uid == 0 && user != "root") print "HIGH|" user "|account has UID 0, so it is a second root account"
            if (pw == "EMPTY" && login == "yes") print "HIGH|" user "|login account with an EMPTY password: anyone can log in as it"
            else if (pw == "EMPTY") print "MED|" user "|account has an empty password field"
            if (pw == "hash in passwd") print "HIGH|" user "|password hash is stored in /etc/passwd instead of /etc/shadow"
            if (++seen[uid] == 2) print "MED|UID " uid "|more than one account shares this UID"
            if (login == "yes" && uid > 0 && uid < uidmin) {
                if (user ~ /^(www-data|apache|nginx|http|httpd|nobody|daemon|bin|sys|mail|ftp|games|man|lp|news|uucp|proxy|backup|list|irc|gnats|sshd|tomcat[0-9]*|mysql|postfix|bind|named|_.*)$/)
                    print "MED|" user "|service account has a login shell (" shell "); it normally has none"
                else print "LOW|" user "|system account (UID " uid ") has a login shell (" shell ")"
            }
            if (uid != 0 && groups ~ /(^| )(docker|lxd|lxc|disk)( |$)/)
                print "MED|" user "|member of a group that is as good as root (" groups ")"
            if (login == "yes") logins = logins (logins == "" ? "" : ", ") user
            if (uid == 0 || groups ~ /(^| )(sudo|wheel|admin)( |$)/) admins = admins (admins == "" ? "" : ", ") user
        }
        END {
            print "Accounts that can log in: " (logins == "" ? "none" : logins) >> sumf
            print "Admins (UID 0 or sudo/wheel/admin group): " (admins == "" ? "none" : admins) >> sumf
        }' /etc/passwd >"$W/f_users"
    # The awk above wrote its two summary lines straight to the file; show them.
    tail -n 2 "$W/summary_lines" >"$W/users_said"
    while IFS= read -r _l; do show "$C_GRN" "  $_l"; done <"$W/users_said"
    emit_flags "$W/f_users"
}

# ---- ports ------------------------------------------------------------------
# get_listeners -> write "proto|address|port|pid|name" lines to $W/listen.
#   Tries, in order: ss, netstat, sockstat (BSD), then reads /proc/net
#   directly, which needs no tools at all.  Sets PORT_TOOL.
get_listeners() {
    : >"$W/listen"
    if cc_have ss && ss -tuln >/dev/null 2>&1; then
        PORT_TOOL=ss
        cc_save ss_listen ss -tulpn
        # Columns: Netid State Recv-Q Send-Q Local:Port Peer:Port Process
        # Process looks like users:(("sshd",pid=812,fd=3)) or, on old ss,
        # users:(("sshd",812,3)).  Only the first process is kept.
        awk '
            $1 != "tcp" && $1 != "udp" { next }
            {
                loc = $5; procs = ""
                for (i = 7; i <= NF; i++) procs = procs " " $i
                port = loc; sub(/.*:/, "", port)
                addr = loc; sub(/:[^:]*$/, "", addr); gsub(/\[|\]/, "", addr); sub(/%.*/, "", addr)
                name = ""; pid = ""
                if (match(procs, /\("[^"]*"/)) name = substr(procs, RSTART + 2, RLENGTH - 3)
                if (match(procs, /pid=[0-9]+/)) pid = substr(procs, RSTART + 4, RLENGTH - 4)
                else if (match(procs, /",[0-9]+,/)) pid = substr(procs, RSTART + 2, RLENGTH - 3)
                print $1 "|" addr "|" port "|" pid "|" name
            }' "$CC_LAST_SAVE" >"$W/listen"
    elif cc_have netstat && netstat -tuln >/dev/null 2>&1; then
        PORT_TOOL=netstat
        cc_save netstat_listen netstat -tulpn
        # Columns: Proto Recv-Q Send-Q Local Foreign [State] PID/Program
        # UDP lines have no State, so the PID/Program is taken from the last
        # field, which is "1234/sshd" or "-".
        awk '
            $1 ~ /^(tcp|udp)6?$/ {
                proto = $1; sub(/6$/, "", proto)
                loc = $4; port = loc; sub(/.*:/, "", port); addr = loc; sub(/:[^:]*$/, "", addr)
                pp = $NF; pid = ""; name = ""
                if (pp ~ /^[0-9]+\//) { pid = pp; sub(/\/.*/, "", pid); name = pp; sub(/^[0-9]+\//, "", name) }
                print proto "|" addr "|" port "|" pid "|" name
            }' "$CC_LAST_SAVE" >"$W/listen"
    elif cc_have sockstat; then
        PORT_TOOL=sockstat
        cc_save sockstat_listen sockstat -46l
        # BSD: USER COMMAND PID FD PROTO LOCAL FOREIGN
        awk '
            NR > 1 && $5 ~ /^(tcp|udp)/ {
                proto = $5; sub(/[46]+$/, "", proto)
                loc = $6; port = loc; sub(/.*:/, "", port); addr = loc; sub(/:[^:]*$/, "", addr)
                print proto "|" addr "|" port "|" $3 "|" $2
            }' "$CC_LAST_SAVE" >"$W/listen"
    elif [ -r /proc/net/tcp ]; then
        PORT_TOOL=/proc
        # No tools at all (minimal container or a box where they were
        # removed).  Map socket inodes to pids from /proc/<pid>/fd, then
        # decode /proc/net/{tcp,udp}{,6}.  State 0A = TCP LISTEN, 07 = UDP.
        ls -l /proc/[0-9]*/fd/ 2>/dev/null | awk '
            /^\/proc\/[0-9]+\/fd:$/ { pid = $0; sub(/^\/proc\//, "", pid); sub(/\/fd:$/, "", pid); next }
            /socket:\[/ { ino = $NF; gsub(/[^0-9]/, "", ino); print ino, pid }' >"$W/inodes"
        _pf=""
        for _f in /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6; do [ -r "$_f" ] && _pf="$_pf $_f"; done
        # shellcheck disable=SC2086
        awk -v inof="$W/inodes" '
            # awk, not shell (posix-ok): hex text to a number
            function hex(h,   i, n) { n = 0; h = toupper(h); for (i = 1; i <= length(h); i++) n = n * 16 + index("0123456789ABCDEF", substr(h, i, 1)) - 1; return n }   # posix-ok
            BEGIN { while ((getline l < inof) > 0) { split(l, p, " "); if (!(p[1] in own)) own[p[1]] = p[2] } }
            FNR == 1 { proto = FILENAME; sub(/.*\//, "", proto); sub(/6$/, "", proto); next }
            {
                if (proto == "tcp" && $4 != "0A") next
                if (proto == "udp" && $4 != "07") next
                split($2, la, ":"); port = hex(la[2]); a = la[1]
                if (length(a) == 8) addr = hex(substr(a, 7, 2)) "." hex(substr(a, 5, 2)) "." hex(substr(a, 3, 2)) "." hex(substr(a, 1, 2))
                else if (a ~ /^0+$/) addr = "::"
                else if (a == "00000000000000000000000001000000") addr = "::1"
                else addr = "ipv6:" a
                print proto "|" addr "|" port "|" own[$10] "|"
            }' $_pf >"$W/listen"
    else
        PORT_TOOL=none
        cc_have netstat && cc_save netstat_an netstat -an
    fi
    sort -u "$W/listen" -o "$W/listen" 2>/dev/null
    cc_debug "ports: tool=$PORT_TOOL, $(wc -l <"$W/listen" | tr -d ' ') listeners"
}

s_ports() {
    sec_csv ports "proto,address,port,exposure,pid,process,user,program"
    F=$SEC_CSV
    get_listeners
    [ "$PORT_TOOL" = none ] && { note "no ss, netstat, sockstat or /proc/net: see raw/"; say "Listening ports: could not be read on this OS (see raw/netstat_an.txt)"; return 0; }
    [ "$IS_ROOT" = 1 ] || note "partial: process shown only for your own sockets"
    if [ "$PORT_TOOL" = /proc ] && [ ! -s "$W/inodes" ]; then note "process unknown: /proc/<pid>/fd is not readable here"; fi
    : >"$W/any"; : >"$W/loc"
    while IFS='|' read -r proto addr port pid name; do
        [ -n "$port" ] || continue
        exe=""; user=""
        if [ -n "$pid" ] && [ -d "/proc/$pid" ]; then
            exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
            [ -n "$name" ] || name=$(cat "/proc/$pid/comm" 2>/dev/null)
            user=$(owner_of "/proc/$pid")
        fi
        case "$addr" in
            127.*|::1|localhost|::ffff:127.*) exposure=local; printf '%s/%s %s\n' "$proto" "$port" "$name" >>"$W/loc" ;;
            *) exposure=any; printf '%s/%s %s\n' "$proto" "$port" "$name" >>"$W/any" ;;
        esac
        cc_csv_row "$F" "$proto" "$addr" "$port" "$exposure" "$pid" "$name" "$user" "$exe"

        _it="$proto/$port"
        case "$exe" in *" (deleted)") flag HIGH "$_it" "listener's program file was deleted after it started ($exe, pid $pid): typical of malware" ;; esac
        if printf '%s' "$exe" | grep -Eq "$TMP_RE"; then flag HIGH "$_it" "listener runs from a temp folder ($exe, pid $pid)"; fi
        if printf '%s' "$name" | grep -Eq "$SHELLS_RE"; then flag HIGH "$_it" "a shell ($name, pid $pid) is listening on the network: bind shell"; fi
        if printf '%s' "$name" | grep -Eq "$NETCAT_RE"; then flag HIGH "$_it" "$name is listening (pid $pid): netcat-style backdoor"; fi
        case "$name" in python*|perl|php*|ruby*) flag MED "$_it" "an interpreter ($name, pid $pid) is listening; confirm it is a real service" ;; esac
        case "$port" in
            2375) flag HIGH "$_it" "Docker API without TLS: anyone who can reach it is root on this host" ;;
            23) [ "$proto" = tcp ] && flag MED "$_it" "Telnet-style cleartext login service ($name)" ;;
            512|513|514) [ "$proto" = tcp ] && flag MED "$_it" "rsh/rlogin/rexec-style cleartext service ($name)" ;;
            69) [ "$proto" = udp ] && flag MED "$_it" "TFTP: no authentication, files can be read by guessing names" ;;
            1337|4444|4445|5555|6666|6667|12345|31337|54321) flag MED "$_it" "port commonly used by backdoors and reverse shells ($name)" ;;
            590[0-9]) [ "$proto" = tcp ] && flag MED "$_it" "VNC remote desktop ($name); check it requires a password" ;;
        esac
    done <"$W/listen"
    _any=$(sort -u "$W/any" | awk '{ printf "%s%s", sep, $0; sep = ", " }')
    _loc=$(sort -u "$W/loc" | awk '{ printf "%s%s", sep, $0; sep = ", " }')
    say "Listening on the network: ${_any:-none}"
    say "Listening on this host only: ${_loc:-none}"
}

s_services() {
    sec_csv services "name,enabled,active,state,description,manager"
    F=$SEC_CSV
    case "$CC_INIT" in
        systemd)
            systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null | awk '{ print $1 "|" $2 }' >"$W/unitfiles"
            systemctl list-units --type=service --all --no-legend --no-pager 2>/dev/null >"$W/units"
            cc_save systemd_units cat "$W/units"
            # Old systemd prefixes failed units with a bullet character and
            # has no --plain option, so anything before the unit name is cut.
            awk -v uf="$W/unitfiles" "$AWK_Q"'
                BEGIN { while ((getline l < uf) > 0) { i = index(l, "|"); en[substr(l, 1, i - 1)] = substr(l, i + 1) } }
                {
                    sub(/^[^A-Za-z0-9@_.:-]+/, "")
                    desc = ""; for (i = 5; i <= NF; i++) desc = desc (i > 5 ? " " : "") $i
                    print q($1) "," q(en[$1]) "," q($3) "," q($4) "," q(desc) ",\"systemd\""
                }' "$W/units" >>"$F"
            # Unit files that run something suspicious.  ExecStart, ExecStartPre,
            # ExecStop ... in every unit folder, including drop-in overrides.
            : >"$W/execs"
            for _d in /etc/systemd/system /run/systemd/system /usr/local/lib/systemd/system /usr/lib/systemd/system /lib/systemd/system; do
                [ -d "$_d" ] && grep -rEn '^[[:space:]]*Exec[A-Za-z]*=' "$_d" 2>/dev/null >>"$W/execs"
            done
            grep -E "$SUSP_STRONG" "$W/execs" >"$W/execs_hi"
            while IFS= read -r _l; do flag HIGH "${_l%%:*}" "unit runs a suspicious command: ${_l#*=}"; done <"$W/execs_hi"
            grep -E '=[-@+!:]*(/tmp/|/var/tmp/|/dev/shm/)' "$W/execs" | grep -vE "$SUSP_STRONG" >"$W/execs_med"
            while IFS= read -r _l; do flag MED "${_l%%:*}" "unit runs a program from a temp folder: ${_l#*=}"; done <"$W/execs_med"
            # Service files written directly into /etc/systemd/system (not a
            # symlink to a packaged unit) are local additions: legitimate ones
            # exist, but this is also where a red team drops a new service.
            for _u in /etc/systemd/system/*.service /etc/systemd/system/*/*.service; do
                [ -f "$_u" ] && [ ! -h "$_u" ] && flag LOW "$_u" "service unit created locally (not from a package)"
            done
            ;;
        openrc)
            cc_save rc_status rc-status --all
            awk "$AWK_Q"'$2 == "[" { print q($1) ",\"\"," q($3) ",\"\",\"\",\"openrc\"" }' "$CC_LAST_SAVE" >>"$F"
            ;;
        rc)
            cc_save service_enabled service -e
            awk "$AWK_Q"'/^\// { n = $0; sub(/.*\//, "", n); print q(n) ",\"enabled\",\"\",\"\",\"\",\"rc\"" }' "$CC_LAST_SAVE" >>"$F"
            ;;
        smf)
            cc_save svcs svcs -a
            awk "$AWK_Q"'NR > 1 { print q($3) ",\"\"," q($1) ",\"\",\"\",\"smf\"" }' "$CC_LAST_SAVE" >>"$F"
            ;;
        *)
            if cc_have service; then
                cc_save service_status service --status-all
                # Lines look like " [ + ]  ssh" (running) or " [ - ]  cups".
                awk "$AWK_Q"'$1 == "[" { st = ($2 == "+") ? "active" : ($2 == "-" ? "inactive" : "unknown"); print q($4) ",\"\"," q(st) ",\"\",\"\",\"sysv\"" }' "$CC_LAST_SAVE" >>"$F"
            else
                for _s in /etc/init.d/*; do [ -f "$_s" ] && cc_csv_row "$F" "$(basename "$_s")" "" "" "" "" "init.d"; done
                note "no service manager found; listed /etc/init.d only"
            fi
            ;;
    esac
    _run=$(awk -F'","' 'NR > 1 && $3 == "active" { n++ } END { print n + 0 }' "$F")
    _all=$(($(wc -l <"$F") - 1))
    say "Services: $_all listed, $_run running"
}

s_autostart() {
    sec_csv autostart "source,user,entry"
    F=$SEC_CSV
    : >"$W/auto"     # lines: source|user|entry
    # 1. System crontabs: the 6th field is the user (or the 2nd after @reboot).
    for _f in /etc/crontab /etc/cron.d/*; do
        [ -f "$_f" ] || continue
        awk -v src="$_f" '
            /^[ \t]*(#|$)/ { next }
            /^[ \t]*[A-Za-z_][A-Za-z0-9_]*[ \t]*=/ { next }
            {
                if ($1 ~ /^@/) { user = $2; s = 3; sched = $1 } else { user = $6; s = 7; sched = $1 " " $2 " " $3 " " $4 " " $5 }
                cmd = ""; for (i = s; i <= NF; i++) cmd = cmd (i > s ? " " : "") $i
                print src "|" user "|" sched " " cmd
            }' "$_f" >>"$W/auto"
    done
    # 2. Per-user crontabs (Debian, Red Hat, BSD locations).  The file name is
    #    the user.
    for _d in /var/spool/cron/crontabs /var/spool/cron /var/cron/tabs; do
        [ -d "$_d" ] || continue
        for _f in "$_d"/*; do
            [ -f "$_f" ] || continue
            awk -v src="$_f" -v u="$(basename "$_f")" '
                /^[ \t]*(#|$)/ { next }
                /^[ \t]*[A-Za-z_][A-Za-z0-9_]*[ \t]*=/ { next }
                { print src "|" u "|" $0 }' "$_f" >>"$W/auto"
        done
    done
    [ "$IS_ROOT" = 1 ] || note "partial: user crontabs need root"
    # 3. run-parts folders: list each script, and check what is inside it.
    for _d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/periodic/daily /etc/periodic/hourly; do
        [ -d "$_d" ] || continue
        for _f in "$_d"/*; do
            [ -f "$_f" ] || continue
            printf '%s|root|script %s\n' "$_d" "$_f" >>"$W/auto"
            grep -En "$SUSP_STRONG" "$_f" 2>/dev/null >"$W/cronscript" && flag HIGH "$_f" "cron script contains: $(head -n 1 "$W/cronscript")"
        done
    done
    # 4. anacron, at, systemd timers.
    [ -f /etc/anacrontab ] && awk '/^[ \t]*(#|$)/ { next } /=/ { next } { print "/etc/anacrontab|root|" $0 }' /etc/anacrontab >>"$W/auto"
    if cc_have atq; then
        atq 2>/dev/null | awk '{ print "at|" $NF "|job " $0 }' >>"$W/auto"
    fi
    for _d in /var/spool/cron/atjobs /var/spool/at /var/at/jobs; do
        [ -d "$_d" ] || continue
        for _f in "$_d"/*; do
            [ -f "$_f" ] || continue
            grep -En "$SUSP_STRONG" "$_f" >/dev/null 2>&1 && flag HIGH "$_f" "queued 'at' job contains a suspicious command"
        done
    done
    if [ "$CC_INIT" = systemd ]; then
        systemctl list-timers --all --no-legend --no-pager 2>/dev/null | awk '{ print "systemd timer|root|" $0 }' >>"$W/auto"
    fi
    # 5. rc.local runs as root at boot and is unused on most modern systems,
    #    so every command in it is flagged for a look.
    for _f in /etc/rc.local /etc/rc.d/rc.local; do
        [ -f "$_f" ] || continue
        awk -v src="$_f" '/^[ \t]*(#|$)/ { next } /^[ \t]*exit[ \t]+0[ \t]*$/ { next } { print src "|root|" $0 }' "$_f" >"$W/rclocal"
        cat "$W/rclocal" >>"$W/auto"
        while IFS='|' read -r _s _u _e; do flag MED "$_s" "runs at boot as root: $_e"; done <"$W/rclocal"
    done
    # 6. Shell startup files, motd scripts and udev rules: only lines that
    #    look like a backdoor are recorded, because these files are long.
    : >"$W/startup"
    for _f in /etc/profile /etc/profile.d/*.sh /etc/bash.bashrc /etc/bashrc /etc/environment /etc/zsh/zshrc \
              /root/.bashrc /root/.profile /root/.bash_profile /home/*/.bashrc /home/*/.profile /home/*/.bash_profile \
              /etc/update-motd.d/* /etc/udev/rules.d/*.rules; do
        [ -f "$_f" ] || continue
        grep -En "$SUSP_STRONG" "$_f" 2>/dev/null | awk -v src="$_f" '{ print src "|-|" $0 }' >>"$W/startup"
    done
    cat "$W/startup" >>"$W/auto"
    while IFS='|' read -r _s _u _e; do flag HIGH "$_s" "startup file runs a suspicious command (line $_e)"; done <"$W/startup"

    # Write everything, then flag the cron/at/timer entries by pattern.
    while IFS='|' read -r _s _u _e; do cc_csv_row "$F" "$_s" "$_u" "$_e"; done <"$W/auto"
    grep -E "$SUSP_STRONG" "$W/auto" | grep -v '^/etc/rc' | grep -vF -f "$W/startup" >"$W/auto_hi" 2>/dev/null
    while IFS='|' read -r _s _u _e; do flag HIGH "$_s" "scheduled job for $_u runs a suspicious command: $_e"; done <"$W/auto_hi"
    grep -E "$SUSP_WEAK" "$W/auto" | grep -vE "$SUSP_STRONG" | grep -v '^/etc/rc' >"$W/auto_med" 2>/dev/null
    while IFS='|' read -r _s _u _e; do flag MED "$_s" "scheduled job for $_u is worth a look: $_e"; done <"$W/auto_med"
    _n=$(grep -cv '^systemd timer|' "$W/auto")
    say "Scheduled and startup entries: $_n (cron, at, rc.local, startup files), plus systemd timers"
}

s_ssh() {
    sec_csv ssh_config "setting,value,source"
    F=$SEC_CSV
    : >"$W/sshd"
    # 'sshd -T' prints the settings sshd really uses after every Include and
    # default, but needs root.  Otherwise read the files ourselves: for most
    # settings OpenSSH keeps the FIRST value it sees, and Match blocks apply
    # only to some connections, so reading stops at the first Match.
    if [ "$IS_ROOT" = 1 ] && cc_have sshd && sshd -T >"$W/sshd" 2>/dev/null; then
        _src="sshd -T (effective)"
        cc_save sshd_T cat "$W/sshd"
    elif [ -r /etc/ssh/sshd_config ]; then
        _src="/etc/ssh/sshd_config (read from file)"
        : >"$W/sshd_raw"
        while IFS= read -r _line; do
            case "$_line" in
                [Ii]nclude*)
                    for _g in $(printf '%s\n' "$_line" | awk '{ for (i = 2; i <= NF; i++) print $i }'); do
                        case "$_g" in /*) ;; *) _g="/etc/ssh/$_g" ;; esac
                        for _inc in $_g; do [ -f "$_inc" ] && cat "$_inc" >>"$W/sshd_raw"; done
                    done ;;
                *) printf '%s\n' "$_line" >>"$W/sshd_raw" ;;
            esac
        done </etc/ssh/sshd_config
        awk '/^[ \t]*#/ || NF == 0 { next } tolower($1) == "match" { exit }
             { k = tolower($1); if (!(k in seen)) { seen[k] = 1; v = $2; for (i = 3; i <= NF; i++) v = v " " $i; print k " " v } }' "$W/sshd_raw" >"$W/sshd"
        cc_save sshd_config cat "$W/sshd_raw"
    else
        note "no sshd configuration found"
        _src=""
    fi
    if [ -s "$W/sshd" ]; then
        awk -v src="$_src" "$AWK_Q"'
            $1 ~ /^(port|listenaddress|permitrootlogin|passwordauthentication|permitemptypasswords|pubkeyauthentication|authorizedkeysfile|authorizedkeyscommand|authorizedprincipalsfile|usepam|allowusers|allowgroups|denyusers|denygroups|x11forwarding|gatewayports|permittunnel|kbdinteractiveauthentication|challengeresponseauthentication|maxauthtries|permituserenvironment)$/ {
                v = $2; for (i = 3; i <= NF; i++) v = v " " $i
                print q($1) "," q(v) "," q(src)
            }' "$W/sshd" >>"$F"
        _get() { awk -v k="$1" '$1 == k { $1 = ""; sub(/^ /, ""); print; exit }' "$W/sshd"; }
        [ "$(_get permitemptypasswords)" = yes ] && flag HIGH PermitEmptyPasswords "sshd lets accounts with an empty password log in"
        [ "$(_get permitrootlogin)" = yes ] && flag MED PermitRootLogin "root can log in over SSH with a password"
        [ "$(_get permituserenvironment)" = yes ] && flag MED PermitUserEnvironment "users can set environment variables at login (LD_PRELOAD tricks)"
        _akc=$(_get authorizedkeyscommand)
        [ -n "$_akc" ] && [ "$_akc" != none ] && flag MED AuthorizedKeysCommand "sshd asks a program for allowed keys: $_akc"
        AKF=$(_get authorizedkeysfile)
        for _t in $AKF; do
            case "$_t" in
                .ssh/authorized_keys|.ssh/authorized_keys2|%h/.ssh/authorized_keys|%h/.ssh/authorized_keys2) ;;
                *) flag HIGH AuthorizedKeysFile "sshd also reads keys from '$_t'; a moved key file is a common way to hide a backdoor key" ;;
            esac
        done
        _rl=$(_get permitrootlogin)
        case "$_rl" in prohibit-password|without-password) _rl="key-only ($_rl)" ;; forced-commands-only) _rl="key-only, forced commands" ;; esac
        say "SSH: root login '$_rl', password login '$(_get passwordauthentication)', port(s) $(awk '$1 == "port" { printf "%s ", $2 }' "$W/sshd")"
    fi

    # Every authorized_keys file for every account, including system
    # accounts: a key on www-data or nobody is a favourite red team backdoor.
    sec_csv ssh_keys "user,uid,file,line,type,fingerprint,comment,options,file_owner,file_mode"
    K=$SEC_CSV
    home_dirs
    : >"$W/keyfiles"
    while IFS='|' read -r _user _uid _home; do
        for _kf in "$_home/.ssh/authorized_keys" "$_home/.ssh/authorized_keys2"; do
            [ -f "$_kf" ] && printf '%s|%s|%s\n' "$_user" "$_uid" "$_kf" >>"$W/keyfiles"
        done
        for _t in $AKF; do
            case "$_t" in /*)
                _kf=$(printf '%s' "$_t" | sed "s|%u|$_user|g; s|%h|$_home|g; s|%%|%|g")
                [ -f "$_kf" ] && printf '%s|%s|%s\n' "$_user" "$_uid" "$_kf" >>"$W/keyfiles" ;;
            esac
        done
    done <"$W/homes"
    sort -u "$W/keyfiles" -o "$W/keyfiles"
    _nkeys=0
    while IFS='|' read -r _user _uid _kf; do
        _ow=$(owner_of "$_kf"); _md=$(mode_of "$_kf")
        case "$_md" in ????????w*|?????w????*) flag HIGH "$_kf" "key file can be changed by other users ($_md); anyone could add a key" ;; esac
        [ "$_ow" != "$_user" ] && [ "$_ow" != root ] && flag HIGH "$_kf" "key file is owned by $_ow, not $_user"
        # Each key line: [options] type base64 [comment].  The type is found
        # by its name, because options may come first.
        awk '
            /^[ \t]*(#|$)/ { next }
            {
                t = 0
                for (i = 1; i <= NF; i++) if ($i ~ /^(ssh-|ecdsa-|sk-)/) { t = i; break }
                if (!t) next
                opts = ""; for (i = 1; i < t; i++) opts = opts (i > 1 ? " " : "") $i
                cm = ""; for (i = t + 2; i <= NF; i++) cm = cm (i > t + 2 ? " " : "") $i
                print NR "|" $t "|" $(t + 1) "|" cm "|" opts
            }' "$_kf" >"$W/keys1"
        while IFS='|' read -r _ln _type _key _cm _opts; do
            _nkeys=$((_nkeys + 1))
            _fp=""
            if cc_have ssh-keygen; then
                printf '%s %s\n' "$_type" "$_key" >"$W/onekey"
                _fp=$(ssh-keygen -lf "$W/onekey" 2>/dev/null | awk '{ print $2 }')
            fi
            cc_csv_row "$K" "$_user" "$_uid" "$_kf" "$_ln" "$_type" "$_fp" "$_cm" "$_opts" "$_ow" "$_md"
            case "$_opts" in *command=*) flag LOW "$_user" "key in $_kf line $_ln runs a forced command: $_opts" ;; esac
        done <"$W/keys1"
        _cnt=$(wc -l <"$W/keys1" | tr -d ' ')
        [ "$_cnt" -gt 0 ] || continue
        if [ "$_uid" = 0 ]; then
            flag MED "$_user" "root accepts $_cnt SSH key(s) from $_kf; confirm every one is yours"
        elif [ "$_uid" -lt "$UID_MIN" ]; then
            flag HIGH "$_user" "service account has $_cnt SSH key(s) in $_kf; service accounts should have none"
        fi
    done <"$W/keyfiles"
    say "SSH keys: $_nkeys key(s) in $(wc -l <"$W/keyfiles" | tr -d ' ') authorized_keys file(s)"
}

s_sudo() {
    sec_csv sudo "file,line,entry"
    F=$SEC_CSV
    if [ ! -r /etc/sudoers ] && [ -e /etc/sudoers ]; then
        note "partial: sudoers needs root"
    fi
    : >"$W/sudo"
    _files=""
    [ -f /etc/sudoers ] && _files="/etc/sudoers"
    # Files pulled in with #includedir / @includedir (the '#' is NOT a
    # comment there - a classic place to hide an extra rule).
    for _d in /etc/sudoers.d $(awk '$1 ~ /^[#@]includedir$/ { print $2 }' /etc/sudoers 2>/dev/null); do
        [ -d "$_d" ] && for _f in "$_d"/*; do [ -f "$_f" ] && _files="$_files $_f"; done
    done
    for _f in $(awk '$1 ~ /^[#@]include$/ { print $2 }' /etc/sudoers 2>/dev/null); do [ -f "$_f" ] && _files="$_files $_f"; done
    for _f in $_files; do
        _md=$(mode_of "$_f"); _ow=$(owner_of "$_f")
        case "$_md" in ?????w????*|????????w*) flag HIGH "$_f" "sudoers file can be changed by non-root users ($_md)" ;; esac
        [ "$_ow" != root ] && flag HIGH "$_f" "sudoers file is owned by $_ow, not root"
        awk -v src="$_f" '
            /^[ \t]*$/ { next }
            /^[ \t]*[#@]include/ { print src "|" NR "|" $0; next }
            /^[ \t]*#/ { next }
            { print src "|" NR "|" $0 }' "$_f" 2>/dev/null >>"$W/sudo"
    done
    while IFS='|' read -r _s _n _e; do cc_csv_row "$F" "$_s" "$_n" "$_e"; done <"$W/sudo"
    awk -F'|' '
        $3 ~ /NOPASSWD/ && $3 !~ /^[ \t]*Defaults/ { print "MED|" $1 ":" $2 "|passwordless sudo: " $3 }
        $3 ~ /!authenticate/ { print "HIGH|" $1 ":" $2 "|authentication is switched off for sudo: " $3 }
        $3 ~ /env_keep/ && $3 ~ /LD_PRELOAD|LD_LIBRARY_PATH/ { print "HIGH|" $1 ":" $2 "|sudo keeps LD_PRELOAD/LD_LIBRARY_PATH, which lets a user run code as root: " $3 }
        $3 ~ /^[ \t]*%/ && $3 ~ /ALL[ \t]*$/ && $3 !~ /^[ \t]*%(sudo|wheel|admin|root)[ \t]/ { print "MED|" $1 ":" $2 "|a group gets full sudo: " $3 }
        $3 ~ /^[ \t]*[A-Za-z0-9_.-]+[ \t]+[^=]*=/ && $3 !~ /NOPASSWD/ && $3 !~ /^[ \t]*(root|Defaults|Cmnd_Alias|User_Alias|Host_Alias|Runas_Alias)[ \t]/ { print "LOW|" $1 ":" $2 "|sudo rule for a single user: " $3 }
    ' "$W/sudo" >"$W/f_sudo"
    emit_flags "$W/f_sudo"
    for _f in /etc/doas.conf /usr/local/etc/doas.conf; do
        [ -f "$_f" ] || continue
        awk -v src="$_f" '/^[ \t]*(#|$)/ { next } { print src "|" NR "|" $0 }' "$_f" >"$W/doas"
        while IFS='|' read -r _s _n _e; do
            cc_csv_row "$F" "$_s" "$_n" "$_e"
            case "$_e" in *nopass*) flag MED "$_s:$_n" "passwordless doas: $_e" ;; esac
        done <"$W/doas"
    done
    for _f in /etc/polkit-1/rules.d/*.rules /etc/polkit-1/localauthority/*/*.pkla; do
        [ -f "$_f" ] || continue
        cc_csv_row "$F" "$_f" "" "polkit rule file"
        if grep -q 'Result.YES' "$_f" 2>/dev/null; then flag MED "$_f" "polkit rule grants actions without a password"
        else flag LOW "$_f" "local polkit rule; check what it allows"; fi
    done
    _ver=$(sudo -V 2>/dev/null | head -n 1)
    [ -n "$_ver" ] && cc_csv_row "$F" "sudo -V" "" "$_ver"
    say "sudo: $(grep -c . "$W/sudo") rule line(s); ${_ver:-sudo not installed}"
}

# ---- privesc ----------------------------------------------------------------
# Ways a normal user (or a red team that lost root) can become root again,
# like linpeas checks.  The folders, groups, capabilities and passwordless
# sudo that other sections already flag are not repeated here.

# who_can_write PATH -> prints why a non-root user can change PATH, or
#   nothing.  Follows symlinks (/bin -> usr/bin).  World-writable alone is
#   left to the files section; this adds owner and group write.
who_can_write() {
    ls -ldL "$1" 2>/dev/null | awk '
        { m = $1; o = $3; g = $4
          if (o != "root" && o != "0") { print "owned by " o; exit }
          if (substr(m, 6, 1) == "w" && g != "root" && g != "0") { print "group " g " can write it"; exit }
          if (substr(m, 9, 1) == "w" && substr(m, 10, 1) != "t") { print "anyone can write it"; exit } }'
}

# pe_check KIND PATH WHAT -> flag PATH (and its folder) if a non-root user can
#   change it.  WHAT says who runs it, e.g. "root cron job".
pe_check() {
    [ -e "$2" ] || return 0
    # Each file once, even when several units or cron lines run it.
    grep -qxF "$2" "$W/pe_seen" 2>/dev/null && return 0
    printf '%s\n' "$2" >>"$W/pe_seen"
    _pw=$(who_can_write "$2")
    if [ -n "$_pw" ]; then
        cc_csv_row "$SEC_CSV" "$1" "$2" "$_pw"
        flag HIGH "$2" "$3 runs this file, and $_pw: whoever changes it gets root"
        return 0
    fi
    _pd=$(dirname "$2")
    _pw=$(who_can_write "$_pd")
    if [ -n "$_pw" ] && [ "$_pd" != /tmp ] && [ "$_pd" != /var/tmp ]; then
        cc_csv_row "$SEC_CSV" "$1" "$2" "folder $_pd: $_pw"
        flag HIGH "$2" "$3 runs this file, and its folder $_pd: $_pw, so the file can be replaced"
    fi
    return 0
}

# paths_in FILE -> every absolute path to an existing file mentioned in FILE
#   (one per line, de-duplicated).  Used on root cron lines and unit commands.
paths_in() {
    tr ' \t;|&()<>"=' '\n\n\n\n\n\n\n\n\n\n' <"$1" | sed "s/^'//; s/'\$//" | grep '^/' | sort -u >"$W/pe_paths"
    while IFS= read -r _pp; do [ -f "$_pp" ] && printf '%s\n' "$_pp"; done <"$W/pe_paths"
}

# ver_lt A B -> true if version A is lower than B.  Compares number by number,
#   so 1.8.31 < 1.9.5 and 1.9.5.1 < 1.9.5.2.
ver_lt() {
    awk -v a="$1" -v b="$2" 'BEGIN {
        na = split(a, x, /[^0-9]+/); nb = split(b, y, /[^0-9]+/)
        n = (na > nb) ? na : nb
        for (i = 1; i <= n; i++) { if (x[i] + 0 < y[i] + 0) exit 0; if (x[i] + 0 > y[i] + 0) exit 1 }
        exit 1 }'
}

# patched PACKAGE CVE -> true if the package's changelog mentions the CVE,
#   which is how Debian, Ubuntu and RHEL record a backported fix.
patched() {
    for _cl in /usr/share/doc/"$1"/changelog.Debian.gz /usr/share/doc/"$1"/changelog.gz; do
        [ -f "$_cl" ] && gzip -dc "$_cl" 2>/dev/null | grep -q "$2" && return 0
    done
    cc_have rpm && rpm -q --changelog "$1" 2>/dev/null | grep -q "$2" && return 0
    return 1
}

# built_before YYYYMM -> true if the running kernel was built before that
#   month (from 'uname -v'), so a fix from that month cannot be in it.
built_before() {
    uname -v 2>/dev/null | awk -v lim="$1" '{
        y = 0; m = 0
        for (i = 1; i <= NF; i++) {
            if ($i ~ /^(19|20)[0-9][0-9]$/) y = $i
            k = index("JanFebMarAprMayJunJulAugSepOctNovDec", $i); if (length($i) == 3 && k) m = (k + 2) / 3
        }
        if (y == 0) exit 1
        exit !((y * 100 + m) < lim + 0) }'
}

s_privesc() {
    # PR: a fake system root for the tests (BT_TEST_ROOT); empty for real runs.
    PR=${BT_TEST_ROOT:-}
    sec_csv privesc "check,path,detail"
    : >"$W/pe_seen"

    # 1. Files root runs on a schedule or at boot that others can change.
    #    Root's cron lines: /etc/crontab and /etc/cron.d (user field = root),
    #    root's own crontab, and the run-parts folders.
    : >"$W/pe_cron"
    for _f in "$PR"/etc/crontab "$PR"/etc/cron.d/*; do
        [ -f "$_f" ] && awk '!/^[ \t]*#/ && NF >= 7 && $6 == "root" { for (i = 7; i <= NF; i++) printf "%s ", $i; print "" }' "$_f" >>"$W/pe_cron" 2>/dev/null
    done
    for _f in "$PR"/var/spool/cron/crontabs/root "$PR"/var/spool/cron/root; do
        [ -f "$_f" ] && awk '!/^[ \t]*#/ && NF >= 6 && $1 !~ /=/ { for (i = 6; i <= NF; i++) printf "%s ", $i; print "" }' "$_f" >>"$W/pe_cron" 2>/dev/null
    done
    paths_in "$W/pe_cron" >"$W/pe_list"
    while IFS= read -r _p; do pe_check cron "$_p" "a root cron job"; done <"$W/pe_list"
    for _f in "$PR"/etc/cron.hourly/* "$PR"/etc/cron.daily/* "$PR"/etc/cron.weekly/* "$PR"/etc/cron.monthly/* "$PR"/etc/rc.local "$PR"/etc/init.d/*; do
        [ -f "$_f" ] && pe_check boot "$_f" "root (cron run-parts or start-up)"
    done
    for _d in "$PR"/etc/cron.d "$PR"/etc/cron.hourly "$PR"/etc/cron.daily "$PR"/etc/systemd/system "$PR"/etc/init.d; do
        [ -d "$_d" ] || continue
        _pw=$(who_can_write "$_d")
        [ -n "$_pw" ] && { cc_csv_row "$SEC_CSV" folder "$_d" "$_pw"; flag HIGH "$_d" "root runs what is in this folder, and $_pw: a new file there runs as root"; }
    done

    # 2. systemd services that run as root: the unit file and the programs
    #    in its Exec lines.
    for _ud in "$PR"/etc/systemd/system "$PR"/run/systemd/system "$PR"/lib/systemd/system "$PR"/usr/lib/systemd/system; do
        [ -d "$_ud" ] || continue
        for _u in "$_ud"/*.service "$_ud"/*.timer; do
            [ -f "$_u" ] || continue
            # Skip services that run as another user (User=redis ...).
            _uu=$(sed -n 's/^[[:space:]]*User=[[:space:]]*//p' "$_u" 2>/dev/null | tail -n 1 | tr -d '[:space:]')
            case "$_uu" in ''|root|0) ;; *) continue ;; esac
            _pw=$(who_can_write "$_u")
            [ -n "$_pw" ] && { cc_csv_row "$SEC_CSV" unit "$_u" "$_pw"; flag HIGH "$_u" "systemd unit run as root, and $_pw: whoever changes it gets root"; }
            grep -E '^[[:space:]]*Exec[A-Za-z]*=' "$_u" 2>/dev/null | sed 's/^[^=]*=[-@:+!]*//' >"$W/pe_exec"
            paths_in "$W/pe_exec" >"$W/pe_list"
            # Programs and scripts only: a config file named on the command
            # line is the service's business, not a way to run code.
            while IFS= read -r _p; do
                case "$_p" in *.sh|*.py|*.pl|*.rb|*.php|*.bash) ;; *) [ -x "$_p" ] || continue ;; esac
                pe_check service "$_p" "the root service $(basename "$_u")"
            done <"$W/pe_list"
        done
    done

    # 3. Key files a normal user must never be able to change (or read, for
    #    shadow).  World-writable ones are also in the files section.
    for _f in "$PR"/etc/passwd "$PR"/etc/group "$PR"/etc/shadow "$PR"/etc/gshadow "$PR"/etc/sudoers "$PR"/etc/sudoers.d "$PR"/etc/sudoers.d/* "$PR"/etc/ld.so.preload "$PR"/etc/ld.so.conf "$PR"/etc/ld.so.conf.d "$PR"/etc/profile "$PR"/etc/environment "$PR"/etc/pam.d "$PR"/root "$PR"/root/.bashrc "$PR"/root/.profile "$PR"/root/.ssh "$PR"/root/.ssh/authorized_keys; do
        [ -e "$_f" ] || continue
        _pw=$(who_can_write "$_f")
        [ -n "$_pw" ] && { cc_csv_row "$SEC_CSV" keyfile "$_f" "$_pw"; flag HIGH "$_f" "$_pw: a normal user can use this to become root"; }
    done
    for _f in "$PR"/etc/shadow "$PR"/etc/gshadow; do
        [ -e "$_f" ] || continue
        case "$(ls -ld "$_f" 2>/dev/null | awk '{ print $1 }')" in
            ???????r*) cc_csv_row "$SEC_CSV" keyfile "$_f" "anyone can read it"; flag HIGH "$_f" "anyone can read the password hashes" ;;
        esac
    done

    # 4. Folders on root's PATH owned or writable by a non-root group, and
    #    '.' or an empty entry (both mean "the current folder").
    case ":$PATH:" in *::*|*:.:*) cc_csv_row "$SEC_CSV" path "$PATH" "current folder is on the PATH"; flag HIGH PATH "the PATH includes the current folder: a program planted in any folder root works in runs as root" ;; esac
    for _d in $(printf '%s' "$PATH" | tr ':' ' '); do
        [ -d "$_d" ] || continue
        _pw=$(who_can_write "$_d")
        case "$_pw" in ''|'anyone can write it') ;; *) cc_csv_row "$SEC_CSV" path "$_d" "$_pw"; flag HIGH "$_d" "folder on root's PATH, and $_pw: a planted program there runs as root" ;; esac
    done

    # 5. sudo rules that let a normal user run a program with a shell escape
    #    (GTFOBins: vim, less, find, python ...) or keep LD_PRELOAD.
    : >"$W/pe_sudo"
    for _f in "$PR"/etc/sudoers "$PR"/etc/sudoers.d/*; do
        [ -f "$_f" ] && [ -r "$_f" ] && grep -v '^[[:space:]]*#' "$_f" >>"$W/pe_sudo" 2>/dev/null
    done
    if grep -Eq 'env_keep.*LD_(PRELOAD|LIBRARY_PATH)' "$W/pe_sudo"; then
        cc_csv_row "$SEC_CSV" sudo "$PR"/etc/sudoers "env_keep LD_PRELOAD"
        flag HIGH "$PR"/etc/sudoers "sudo keeps LD_PRELOAD/LD_LIBRARY_PATH: any sudo rule can be turned into a root shell"
    fi
    awk -v gtfo="$GTFO" '
        /^[ \t]*(Defaults|Cmnd_Alias|User_Alias|Host_Alias|Runas_Alias|root[ \t])/ { next }
        /=/ {
            who = $1; cmds = $0; sub(/^[^=]*=[ \t]*(\([^)]*\))?[ \t]*/, "", cmds)
            gsub(/(NOPASSWD|PASSWD|SETENV|NOEXEC|EXEC):[ \t]*/, "", cmds)
            n = split(cmds, c, /,[ \t]*/)
            for (i = 1; i <= n; i++) {
                split(c[i], w, /[ \t]+/); p = w[1]; b = p; sub(/.*\//, "", b); sub(/[0-9.]+$/, "", b)
                if (b != "" && index(gtfo, " " b " ")) print who "|" p
            }
        }' "$W/pe_sudo" | sort -u >"$W/pe_gtfo"
    while IFS='|' read -r _who _prog; do
        cc_csv_row "$SEC_CSV" sudo "$_prog" "$_who may run it as root"
        flag HIGH "$_who" "may run $_prog with sudo, which has a shell escape (GTFOBins): that is a root shell"
    done <"$W/pe_gtfo"

    # 6. Known local root bugs, checked by version, then by the package
    #    changelog (distros backport fixes without changing the version).
    if cc_have sudo; then
        _sv=$(sudo -V 2>/dev/null | awk 'NR == 1 { print $NF }')
        if [ -n "$_sv" ] && ver_lt "$(printf '%s' "$_sv" | tr 'p' '.')" 1.9.5.2 && ! patched sudo CVE-2021-3156; then
            cc_csv_row "$SEC_CSV" cve "sudo $_sv" "CVE-2021-3156 Baron Samedit"
            flag HIGH "sudo $_sv" "older than 1.9.5p2 and no fix for CVE-2021-3156 (Baron Samedit) in its changelog: any user can get root. Update sudo"
        fi
    fi
    for _pk in /usr/bin/pkexec /bin/pkexec; do
        [ -u "$_pk" ] || continue
        _pv=""
        for _pkg in policykit-1 polkitd polkit; do
            _pv=$( (dpkg-query -W -f '${Version}' "$_pkg" || rpm -q --qf '%{VERSION}' "$_pkg") 2>/dev/null | grep -v 'not installed' | head -n 1)
            [ -n "$_pv" ] && break
        done
        if [ -n "$_pv" ] && ver_lt "$_pv" 0.120 && ! patched "$_pkg" CVE-2021-4034; then
            cc_csv_row "$SEC_CSV" cve "$_pk" "CVE-2021-4034 PwnKit (polkit $_pv)"
            flag HIGH "$_pk" "SUID pkexec with polkit $_pv and no fix for CVE-2021-4034 (PwnKit) in its changelog: any user can get root. Update polkit or remove the SUID bit"
        fi
        break
    done
    _kv=$(uname -r 2>/dev/null | sed 's/[^0-9.].*//')
    if [ -n "$_kv" ]; then
        if ver_lt "$_kv" 4.8.3 && built_before 201611; then
            cc_csv_row "$SEC_CSV" cve "kernel $(uname -r)" "CVE-2016-5195 Dirty COW"
            flag HIGH "kernel $(uname -r)" "kernel from before the Dirty COW fix (CVE-2016-5195): any user can get root"
        elif ! ver_lt "$_kv" 5.8 && ver_lt "$_kv" 5.16.11 && built_before 202203; then
            cc_csv_row "$SEC_CSV" cve "kernel $(uname -r)" "CVE-2022-0847 Dirty Pipe"
            flag HIGH "kernel $(uname -r)" "kernel 5.8 to 5.16 built before the Dirty Pipe fix (CVE-2022-0847): any user can get root"
        fi
    fi

    _n=$(($(wc -l <"$SEC_CSV") - 1))
    say "Privilege escalation paths: $_n found (root-run files others can change, risky sudo rules, known root bugs)"
}

s_processes() {
    sec_csv processes "pid,ppid,user,elapsed,program,command"
    F=$SEC_CSV
    # Normalise every ps flavour to "pid|ppid|user|elapsed|command".
    : >"$W/ps"
    if [ "$CC_OS_FAMILY" = bsd ] && ps -axo pid=,ppid=,user=,etime=,args= >"$W/ps0" 2>/dev/null; then :
    elif ps -eo pid=,ppid=,user=,etime=,args= >"$W/ps0" 2>/dev/null && [ -s "$W/ps0" ]; then :
    elif ps -o pid,ppid,user,args >"$W/ps1" 2>/dev/null && [ -s "$W/ps1" ]; then
        awk 'NR > 1 { a = ""; for (i = 4; i <= NF; i++) a = a (i > 4 ? " " : "") $i; print $1, $2, $3, "-", a }' "$W/ps1" >"$W/ps0"
    else
        ps -ef 2>/dev/null | awk 'NR > 1 { a = ""; for (i = 8; i <= NF; i++) a = a (i > 8 ? " " : "") $i; print $2, $3, $1, "-", a }' >"$W/ps0"
    fi
    awk '$1 ~ /^[0-9]+$/ { a = ""; for (i = 5; i <= NF; i++) a = a (i > 5 ? " " : "") $i; print $1 "|" $2 "|" $3 "|" $4 "|" a }' "$W/ps0" >"$W/ps"
    # Program file of every process, in one 'ls' instead of one readlink per
    # process.  Lines look like ".../proc/123/exe -> /usr/bin/foo".
    : >"$W/exe"
    if [ -d /proc/1 ]; then
        ls -l /proc/[0-9]*/exe 2>/dev/null | awk '
            { i = index($0, " -> "); if (!i) next
              p = substr($0, 1, i - 1); sub(/.* \/proc\//, "", p); sub(/\/exe$/, "", p)
              print p "|" substr($0, i + 4) }' >"$W/exe"
    fi
    [ "$IS_ROOT" = 1 ] || note "partial: program files of other users' processes are hidden"
    awk -F'|' -v exef="$W/exe" -v csv="$F" "$AWK_Q"'
        BEGIN { while ((getline l < exef) > 0) { i = index(l, "|"); exe[substr(l, 1, i - 1)] = substr(l, i + 1) } }
        {
            pid = $1; user = $3; cmd = $5; for (i = 6; i <= NF; i++) cmd = cmd "|" $i
            e = exe[pid]
            print q(pid) "," q($2) "," q(user) "," q($4) "," q(e) "," q(cmd) >> csv
            split(cmd, w, " "); base = w[1]; sub(/.*\//, "", base); sub(/:$/, "", base)
            it = "pid " pid " (" base ")"
            if (e ~ / \(deleted\)$/) print "HIGH|" it "|running from a program file that has been deleted (" e "); typical of malware"
            if (e ~ /^(\/tmp|\/var\/tmp|\/dev\/shm|\/run\/shm)\// || w[1] ~ /^(\/tmp|\/var\/tmp|\/dev\/shm)\//) print "HIGH|" it "|running from a temp folder: " (e != "" ? e : w[1])
            if (cmd ~ /^\[.*\]$/ && e != "") print "HIGH|" it "|named like a kernel thread " cmd " but has a program file (" e "): a disguised process"
            if (cmd ~ /(\/dev\/tcp\/|\/dev\/udp\/|bash -i|sh -i|nc .*-e |ncat .*-e|socat .*exec|mkfifo|base64 -d|base64 --decode|python[0-9.]* -c|perl -e|php -r|ruby -e)/) print "HIGH|" it "|command line looks like a reverse shell or encoded payload: " cmd
            if (base ~ /^(nc|ncat|netcat|nc\.traditional|nc\.openbsd|socat|cryptcat|pwncat|gs-netcat)$/) print "MED|" it "|netcat-style tool running: " cmd
            if (base ~ /^(chisel|ligolo|ligolo-ng|frpc|frps|gost|rsocx|pspy|pspy64|linpeas\.sh|reptile)$/) print "HIGH|" it "|known attack tool running: " cmd
            if (user ~ /^(www-data|apache|nginx|http|httpd|nobody|tomcat[0-9]*)$/ && base ~ /^(sh|bash|dash|zsh|ksh|python[0-9.]*|perl|nc|ncat|socat)$/) print "HIGH|" it "|a shell or interpreter is running as the web/service user " user ": possible webshell"
            n++; if (user == "root") nr++
        }
        END { print "SUMMARY|" n "|" nr }' "$W/ps" >"$W/f_proc"
    _sum=$(grep '^SUMMARY|' "$W/f_proc")
    grep -v '^SUMMARY|' "$W/f_proc" >"$W/f_proc2"
    emit_flags "$W/f_proc2"
    _n=$(printf '%s' "$_sum" | cut -d'|' -f2); _r=$(printf '%s' "$_sum" | cut -d'|' -f3)
    say "Processes: ${_n:-0} running, ${_r:-0} as root"
}

s_connections() {
    sec_csv connections "proto,state,local,remote,pid,process"
    F=$SEC_CSV
    : >"$W/conn"
    if cc_have ss && ss -tun >/dev/null 2>&1; then
        cc_save ss_conn ss -tunp
        awk '
            $1 != "tcp" && $1 != "udp" { next }
            $2 == "LISTEN" || $2 == "UNCONN" { next }
            {
                procs = ""; for (i = 7; i <= NF; i++) procs = procs " " $i
                name = ""; pid = ""
                if (match(procs, /\("[^"]*"/)) name = substr(procs, RSTART + 2, RLENGTH - 3)
                if (match(procs, /pid=[0-9]+/)) pid = substr(procs, RSTART + 4, RLENGTH - 4)
                print $1 "|" $2 "|" $5 "|" $6 "|" pid "|" name
            }' "$CC_LAST_SAVE" >"$W/conn"
    elif cc_have netstat; then
        cc_save netstat_conn netstat -tunp
        awk '
            $1 ~ /^(tcp|udp)6?$/ && $6 != "LISTEN" {
                proto = $1; sub(/6$/, "", proto)
                st = ($1 ~ /^udp/) ? "-" : $6
                pp = $NF; pid = ""; name = ""
                if (pp ~ /^[0-9]+\//) { pid = pp; sub(/\/.*/, "", pid); name = pp; sub(/^[0-9]+\//, "", name) }
                print proto "|" st "|" $4 "|" $5 "|" pid "|" name
            }' "$CC_LAST_SAVE" >"$W/conn"
    elif cc_have sockstat; then
        cc_save sockstat_conn sockstat -46c
        awk 'NR > 1 && $5 ~ /^(tcp|udp)/ { p = $5; sub(/[46]+$/, "", p); print p "|-|" $6 "|" $7 "|" $3 "|" $2 }' "$CC_LAST_SAVE" >"$W/conn"
    else
        note "no ss, netstat or sockstat"
        cat /proc/net/tcp /proc/net/tcp6 >"$W/proc_net" 2>/dev/null && cc_save proc_net_tcp cat "$W/proc_net"
    fi
    while IFS='|' read -r _p _s _l _r _pid _name; do
        cc_csv_row "$F" "$_p" "$_s" "$_l" "$_r" "$_pid" "$_name"
        _rp=${_r##*:}
        if printf '%s' "$_name" | grep -Eq "$SHELLS_RE|$NETCAT_RE"; then
            flag HIGH "$_name pid $_pid" "a shell or netcat has a live connection to $_r: reverse shell?"
        fi
        case "$_rp" in 1337|4444|4445|5555|6666|6667|12345|31337|54321) flag MED "$_r" "connection to a port commonly used by reverse shells ($_name pid $_pid)" ;; esac
    done <"$W/conn"
    _est=$(grep -c '|ESTAB' "$W/conn")
    _peers=$(awk -F'|' '$2 ~ /^ESTAB/ { r = $4; sub(/:[^:]*$/, "", r); gsub(/\[|\]/, "", r); if (r !~ /^(127\.|::1$)/) c[r]++ }
        END { for (k in c) print c[k], k }' "$W/conn" | sort -rn | head -n 5 | awk '{ printf "%s%s (%s)", sep, $2, $1; sep = ", " }')
    say "Connections: $_est established; busiest remote addresses: ${_peers:-none}"
}

s_sessions() {
    sec_csv sessions "user,terminal,from,since"
    F=$SEC_CSV
    if cc_have who; then
        who >"$W/who" 2>/dev/null
        awk "$AWK_Q"'{
            from = ""; if (match($0, /\(.*\)/)) from = substr($0, RSTART + 1, RLENGTH - 2)
            print q($1) "," q($2) "," q(from) "," q($3 " " $4)
        }' "$W/who" >>"$F"
        _now=$(awk '{ from = ""; if (match($0, /\(.*\)/)) from = " from " substr($0, RSTART + 1, RLENGTH - 2); printf "%s%s%s", sep, $1, from; sep = ", " }' "$W/who")
        say "Logged in now: ${_now:-nobody}"
    fi
    cc_have w && cc_save w w
    cc_have last && cc_save last last -n 50
    [ "$IS_ROOT" = 1 ] && cc_have lastb && cc_save lastb_failed lastb -n 50
}

s_packages() {
    sec_csv packages "name,version,manager"
    F=$SEC_CSV
    if cc_have dpkg-query; then
        dpkg-query -W -f='${Package}|${Version}|${Status}\n' 2>/dev/null | awk -F'|' "$AWK_Q"'$3 ~ /installed$/ { print q($1) "," q($2) ",\"dpkg\"" }' >>"$F"
    elif cc_have rpm; then
        rpm -qa --qf '%{NAME}|%{VERSION}-%{RELEASE}\n' 2>/dev/null | awk -F'|' "$AWK_Q"'{ print q($1) "," q($2) ",\"rpm\"" }' >>"$F"
    elif cc_have apk; then
        apk info -v 2>/dev/null | awk "$AWK_Q"'{ n = $0; v = $0; sub(/-[0-9].*/, "", n); sub(/^.*-([0-9])/, "\\1", v); print q(n) "," q(substr($0, length(n) + 2)) ",\"apk\"" }' >>"$F"
    elif cc_have pacman; then
        pacman -Q 2>/dev/null | awk "$AWK_Q"'{ print q($1) "," q($2) ",\"pacman\"" }' >>"$F"
    elif cc_have pkg && [ "$CC_OS_FAMILY" = bsd ]; then
        pkg query '%n|%v' 2>/dev/null | awk -F'|' "$AWK_Q"'{ print q($1) "," q($2) ",\"pkg\"" }' >>"$F"
    elif cc_have pkginfo; then
        cc_save pkginfo pkginfo
        note "Solaris: package names only (see raw/pkginfo.txt)"
    else
        note "no package manager found"
    fi
    say "Packages installed: $(($(wc -l <"$F") - 1))"
}

s_files() {
    # Searches start at each of these and stay on that filesystem (-xdev),
    # so network mounts and /proc are never walked.  Separate partitions such
    # as /home are listed explicitly so they are still covered.
    _roots=""
    for _r in / /usr /var /home /opt /srv /tmp /root /boot; do [ -d "$_r" ] && _roots="$_roots $_r"; done
    [ "$IS_ROOT" = 1 ] || note "partial: unreadable folders skipped"

    sec_csv suid "path,mode,owner,group,kind,risky_program"
    F=$SEC_CSV
    # shellcheck disable=SC2086
    for _r in $_roots; do find "$_r" -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null; done | sort -u >"$W/suid"
    while IFS= read -r _p; do
        _ls=$(ls -ld "$_p" 2>/dev/null) || continue
        _md=$(printf '%s' "$_ls" | awk '{ print $1 }'); _ow=$(printf '%s' "$_ls" | awk '{ print $3 }'); _gr=$(printf '%s' "$_ls" | awk '{ print $4 }')
        _kind=""
        case "$_md" in ???[sS]*) _kind=suid ;; esac
        case "$_md" in ??????[sS]*) _kind="${_kind:+$_kind+}sgid" ;; esac
        _base=$(basename "$_p" | sed 's/[0-9.]*$//')
        _gtfo=no
        case "$GTFO" in *" $_base "*) _gtfo=yes ;; esac
        cc_csv_row "$F" "$_p" "$_md" "$_ow" "$_gr" "$_kind" "$_gtfo"
        if printf '%s' "$_p" | grep -Eq '^(/tmp|/var/tmp|/dev/shm|/home|/root|/var/www|/srv|/opt)/'; then
            flag HIGH "$_p" "SUID/SGID program in a place where none belong ($_md)"
        elif [ "$_gtfo" = yes ]; then
            case "$_kind" in *suid*) flag HIGH "$_p" "SUID is set on $_base, which can be used to get a root shell" ;; esac
        fi
        case "$_kind" in *suid*) [ "$_ow" != root ] && flag MED "$_p" "SUID program owned by $_ow" ;; esac
    done <"$W/suid"
    say "SUID/SGID programs: $(wc -l <"$W/suid" | tr -d ' ')"

    # File capabilities: cap_setuid on an interpreter is as good as SUID root.
    if cc_have getcap; then
        sec_csv capabilities "path,capabilities"
        C=$SEC_CSV
        : >"$W/caps"
        for _r in /usr /bin /sbin /lib /lib64 /opt /home /tmp /var /srv /root; do
            [ -d "$_r" ] && getcap -r "$_r" 2>/dev/null >>"$W/caps"
        done
        sort -u "$W/caps" -o "$W/caps"
        # Old libcap prints "path = caps", new prints "path caps".
        while IFS= read -r _l; do
            _p=${_l%% *}; _c=${_l#* }; _c=${_c#= }
            cc_csv_row "$C" "$_p" "$_c"
            case "$_c" in *cap_setuid*|*cap_setgid*|*cap_sys_admin*|*cap_dac_override*|*cap_dac_read_search*|*cap_sys_ptrace*|*cap_sys_module*|*cap_chown*|*cap_fowner*)
                flag HIGH "$_p" "has the capability '$_c', which can be used to become root" ;;
            esac
        done <"$W/caps"
    else
        note "getcap not installed: capabilities not checked"
    fi

    # World-writable files in system folders: anyone can change what root runs.
    sec_csv world_writable "path,type,mode"
    WW=$SEC_CSV
    # /root and home folders are left out: they are normally closed to other
    # users, so a writable file inside cannot be reached anyway.
    for _r in /etc /usr /bin /sbin /lib /lib64 /opt /boot /var/www /srv; do
        [ -d "$_r" ] && find "$_r" -xdev \( -type f -o -type d \) -perm -0002 ! -perm -1000 ! -path '*/.cache/*' 2>/dev/null
    done | head -n 500 >"$W/ww"
    while IFS= read -r _p; do
        _md=$(mode_of "$_p")
        if [ -d "$_p" ]; then _t="dir"; else _t="file"; fi
        cc_csv_row "$WW" "$_p" "$_t" "$_md"
        case "$_p" in
            /var/www/*|/srv/*) flag MED "$_p" "world-writable $_t in the web content ($_md)" ;;
            /opt/*|/usr/local/*) flag MED "$_p" "world-writable $_t under $(printf '%s' "$_p" | cut -d/ -f2) ($_md): any user can change it" ;;
            *) flag HIGH "$_p" "world-writable $_t in a system folder ($_md): any user can change it" ;;
        esac
    done <"$W/ww"
    [ "$(wc -l <"$W/ww")" -ge 500 ] && note "world-writable list cut at 500"

    # Folders on root's PATH that others can write: a planted 'ls' runs as root.
    for _d in $(printf '%s' "$PATH" | tr ':' ' '); do
        [ -d "$_d" ] || continue
        # -L follows a symlink (/bin -> usr/bin on modern systems); a link
        # itself always shows as lrwxrwxrwx, which would be a false alarm.
        case "$(ls -ldL "$_d" 2>/dev/null | awk '{ print $1 }')" in ????????w*) flag HIGH "$_d" "folder on the PATH is world-writable; a planted program there runs as whoever uses that PATH" ;; esac
    done

    # Immutable (i) and append-only (a) flags.  A red team sets them so the
    # file cannot be fixed or deleted, even by root; 'rm' just fails.
    if cc_have lsattr; then
        sec_csv immutable "path,attributes"
        I=$SEC_CSV
        {
            lsattr -R /etc /root /var/www /var/spool/cron 2>/dev/null
            for _d in /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin; do [ -d "$_d" ] && lsattr "$_d" 2>/dev/null; done
            for _d in /home/*/.ssh /root/.ssh; do [ -d "$_d" ] && lsattr "$_d" 2>/dev/null; done
        } | awk 'NF >= 2 && $1 ~ /^[-A-Za-z]+$/ && $1 ~ /[ia]/ { a = $1; $1 = ""; sub(/^ /, ""); print a "|" $0 }' | sort -u >"$W/immut"
        while IFS='|' read -r _a _p; do
            cc_csv_row "$I" "$_p" "$_a"
            if printf '%s' "$_p" | grep -Eq '(/etc/(passwd|shadow|group|gshadow|sudoers|crontab|ld\.so\.preload|hosts|resolv\.conf|ssh/)|/\.ssh/|/etc/cron|/etc/pam\.d/|/etc/systemd/)'; then
                flag HIGH "$_p" "file is locked with chattr ($_a); changes to it will fail until 'chattr -i' is run"
            else
                flag MED "$_p" "file is locked with chattr ($_a)"
            fi
        done <"$W/immut"
    else
        note "lsattr not installed: immutable files not checked"
    fi

    # Files owned by a user or group that no longer exists (left behind by a
    # deleted account, or unpacked from an attacker's archive).
    for _r in /etc /usr /var /home /tmp /opt; do
        [ -d "$_r" ] && find "$_r" -xdev \( -nouser -o -nogroup \) 2>/dev/null
    done | head -n 100 >"$W/nouser"
    while IFS= read -r _p; do flag LOW "$_p" "owned by a user or group that does not exist"; done <"$W/nouser"
}

s_firewall() {
    sec_csv firewall "tool,status,detail"
    F=$SEC_CSV
    FW4=0; FW6=0
    if cc_have iptables-save; then
        if cc_save iptables iptables-save && [ -s "$CC_LAST_SAVE" ]; then
            _pol=$(sed -n 's/^:INPUT \([A-Z]*\).*/\1/p' "$CC_LAST_SAVE" | head -n 1)
            _n=$(grep -c '^-A INPUT' "$CC_LAST_SAVE")
            cc_csv_row "$F" iptables "INPUT policy ${_pol:-none}" "$_n INPUT rule(s); full rules in raw/iptables.txt"
            { [ "$_pol" = DROP ] || [ "$_pol" = REJECT ] || [ "$_n" -gt 0 ]; } && FW4=1
        fi
    fi
    if cc_have ip6tables-save; then
        if cc_save ip6tables ip6tables-save && [ -s "$CC_LAST_SAVE" ]; then
            _pol=$(sed -n 's/^:INPUT \([A-Z]*\).*/\1/p' "$CC_LAST_SAVE" | head -n 1)
            _n=$(grep -c '^-A INPUT' "$CC_LAST_SAVE")
            cc_csv_row "$F" ip6tables "INPUT policy ${_pol:-none}" "$_n INPUT rule(s)"
            { [ "$_pol" = DROP ] || [ "$_pol" = REJECT ] || [ "$_n" -gt 0 ]; } && FW6=1
        fi
    fi
    if cc_have nft && cc_save nftables nft list ruleset && grep -q 'hook input' "$CC_LAST_SAVE"; then
        cc_csv_row "$F" nftables "input hook present" "see raw/nftables.txt"
        grep -Eq '^table (ip|inet) ' "$CC_LAST_SAVE" && FW4=1
        grep -Eq '^table (ip6|inet) ' "$CC_LAST_SAVE" && FW6=1
    fi
    if cc_have ufw && cc_save ufw ufw status verbose; then
        _st=$(awk '/^Status:/ { print $2; exit }' "$CC_LAST_SAVE")
        cc_csv_row "$F" ufw "${_st:-unknown}" "see raw/ufw.txt"
        [ "$_st" = active ] && { FW4=1; FW6=1; }
    fi
    if cc_have firewall-cmd; then
        _st=$(firewall-cmd --state 2>/dev/null)
        cc_csv_row "$F" firewalld "${_st:-not running}" "see raw/firewalld.txt"
        if [ "$_st" = running ]; then FW4=1; FW6=1; cc_save firewalld firewall-cmd --list-all-zones; fi
    fi
    if cc_have pfctl; then
        cc_save pf_rules pfctl -sr
        _st=$(pfctl -s info 2>/dev/null | awk '/^Status:/ { print $2; exit }')
        cc_csv_row "$F" pf "${_st:-unknown}" "see raw/pf_rules.txt"
        [ "$_st" = Enabled ] && { FW4=1; FW6=1; }
    fi
    if cc_have ipfw && cc_save ipfw ipfw list; then
        _n=$(grep -cv '^65535' "$CC_LAST_SAVE")
        cc_csv_row "$F" ipfw "$_n rule(s)" "see raw/ipfw.txt"
        [ "$_n" -gt 1 ] && { FW4=1; FW6=1; }
    fi
    [ "$IS_ROOT" = 1 ] || note "partial: firewall rules need root"
    if [ "$FW4" = 0 ]; then
        flag MED "host firewall" "nothing filters incoming IPv4 traffic on this host"
    fi
    _v6=no
    if [ -r /proc/net/if_inet6 ] && awk '$6 != "lo" { f = 1 } END { exit !f }' /proc/net/if_inet6; then _v6=yes; fi
    if [ "$_v6" = yes ] && [ "$FW6" = 0 ]; then
        flag MED IPv6 "IPv6 is enabled but nothing filters it; the plan is to block IPv6 unless a scored service needs it"
    fi
    say "Host firewall: IPv4 $( [ "$FW4" = 1 ] && echo filtered || echo NOT-filtered ), IPv6 $( [ "$_v6" = yes ] && { [ "$FW6" = 1 ] && echo filtered || echo NOT-filtered; } || echo off )"
}

s_pam() {
    sec_csv pam "file,line,entry"
    F=$SEC_CSV
    : >"$W/pam"
    for _f in /etc/pam.d/* /etc/pam.conf; do
        [ -f "$_f" ] || continue
        awk -v src="$_f" '/^[ \t]*(#|$)/ { next } { print src "|" NR "|" $0 }' "$_f" >>"$W/pam"
    done
    while IFS='|' read -r _s _n _e; do cc_csv_row "$F" "$_s" "$_n" "$_e"; done <"$W/pam"
    awk -F'|' '
        {
            e = $3; it = $1 ":" $2
            if (e ~ /pam_exec\.so/) print "HIGH|" it "|pam_exec runs a program during login: " e
            split(e, w, " ")
            if (w[1] ~ /^-?auth$/ && w[2] == "sufficient" && e ~ /pam_permit\.so/) print "HIGH|" it "|pam_permit is sufficient for login: any password works. " e
            for (i = 1; i <= length(w); i++) if (w[i] ~ /^\/.*\.so$/ && w[i] !~ /^\/(usr\/)?lib(64)?\/([a-z0-9_]+-linux-gnu\/)?security\//) print "HIGH|" it "|PAM module loaded from an unusual path: " w[i]
            if (e ~ /nullok/) print "LOW|" it "|nullok lets an account with an empty password log in (default on some distributions)"
        }' "$W/pam" >"$W/f_pam"
    emit_flags "$W/f_pam"
    # Compare the PAM libraries with the package database.  A changed
    # pam_unix.so is the classic "master password" backdoor.  In the output,
    # the third character '5' means the file's checksum no longer matches.
    if cc_have dpkg; then
        dpkg -V libpam-modules libpam-modules-bin libpam-runtime 2>/dev/null >"$W/pamv"
    elif cc_have rpm; then
        rpm -V pam 2>/dev/null >"$W/pamv"
    else
        : >"$W/pamv"; note "no package database to verify PAM modules"
    fi
    if [ -s "$W/pamv" ]; then
        cc_save pam_verify cat "$W/pamv"
        awk 'substr($1, 3, 1) == "5" && $NF ~ /\.so$/ { print "HIGH|" $NF "|PAM module differs from the installed package (checksum changed): likely a backdoored login" }
             substr($1, 3, 1) == "5" && $NF !~ /\.so$/ { print "LOW|" $NF "|PAM file changed since install" }' "$W/pamv" >"$W/f_pamv"
        emit_flags "$W/f_pamv"
    fi
    say "PAM: $(wc -l <"$W/pam" | tr -d ' ') rule line(s)"
}

s_mac() {
    sec_csv mac "system,current,configured"
    F=$SEC_CSV
    _found=0
    if cc_have getenforce || [ -f /etc/selinux/config ]; then
        _found=1
        _cur=$(getenforce 2>/dev/null || echo unknown)
        _cfg=$(sed -n 's/^SELINUX=//p' /etc/selinux/config 2>/dev/null | tr -d '"' | head -n 1)
        cc_csv_row "$F" SELinux "$_cur" "${_cfg:-}"
        cc_have sestatus && cc_save sestatus sestatus
        if [ "$_cfg" = enforcing ] && [ "$_cur" != Enforcing ]; then
            flag HIGH SELinux "configured as enforcing but currently $_cur: someone switched it off"
        fi
    fi
    if [ -r /sys/module/apparmor/parameters/enabled ]; then
        _found=1
        _en=$(cat /sys/module/apparmor/parameters/enabled)
        _prof=""
        cc_have aa-status && aa-status >"$W/aa" 2>/dev/null && { cc_save aa_status cat "$W/aa"; _prof=$(awk '/profiles are in enforce mode/ { print $1 " enforced" } /profiles are in complain mode/ { print $1 " complain" }' "$W/aa" | tr '\n' ' '); }
        cc_csv_row "$F" AppArmor "$( [ "$_en" = Y ] && echo enabled || echo disabled )" "$_prof"
    fi
    [ "$_found" = 1 ] || cc_csv_row "$F" none "" ""
}

s_trust() {
    sec_csv trust "file,entry"
    F=$SEC_CSV
    home_dirs
    for _f in /etc/hosts.equiv /etc/shosts.equiv; do
        [ -s "$_f" ] || continue
        cc_csv_row "$F" "$_f" "$(tr '\n' ' ' <"$_f")"
        flag HIGH "$_f" "host-based trust file is in use: listed hosts log in without a password"
    done
    while IFS='|' read -r _u _uid _h; do
        for _f in "$_h/.rhosts" "$_h/.shosts" "$_h/.netrc"; do
            [ -f "$_f" ] || continue
            case "$_f" in
                *.netrc) cc_csv_row "$F" "$_f" "(contents not recorded: may hold passwords)"; flag MED "$_f" ".netrc stores login details for $_u" ;;
                *) cc_csv_row "$F" "$_f" "$(tr '\n' ' ' 2>/dev/null <"$_f")"; flag HIGH "$_f" "$_u trusts other hosts to log in without a password" ;;
            esac
        done
    done <"$W/homes"
    if [ -f /etc/exports ]; then
        awk '/^[ \t]*(#|$)/ { next } { print }' /etc/exports >"$W/exports"
        while IFS= read -r _e; do
            cc_csv_row "$F" /etc/exports "$_e"
            case "$_e" in *no_root_squash*) flag HIGH "/etc/exports" "NFS export lets remote root act as root: $_e" ;; esac
            case "$_e" in *'*('*|*' *'*|*insecure*) flag MED "/etc/exports" "NFS export is open to any host or allows insecure ports: $_e" ;; esac
        done <"$W/exports"
    fi
    cc_have exportfs && cc_save exportfs exportfs -v
    cc_save mounts mount
    [ -r /etc/fstab ] && cc_save fstab cat /etc/fstab
    for _f in /etc/hosts.allow /etc/hosts.deny; do
        [ -f "$_f" ] || continue
        awk '/^[ \t]*(#|$)/ { next } { print }' "$_f" >"$W/tcpw"
        while IFS= read -r _e; do
            cc_csv_row "$F" "$_f" "$_e"
            case "$_e" in *spawn*|*twist*) flag HIGH "$_f" "TCP wrappers rule runs a command on connection: $_e" ;; esac
        done <"$W/tcpw"
    done
}

s_creds() {
    # Files that hold a password-like SETTING.  Only the file, line number
    # and setting name are recorded - never the value.
    sec_csv creds "file,line,setting,owner,mode,readable_by_all"
    F=$SEC_CSV
    _roots=""
    for _r in /etc /var/www /srv /opt /home /root /usr/local/etc /var/lib/tomcat* /usr/share/nginx; do [ -d "$_r" ] && _roots="$_roots $_r"; done
    # A setting NAME, then = : or =>, then a real value (not empty and not a
    # $variable).  Requiring a value keeps lines such as nsswitch's
    # "passwd: files" or "password required pam_unix.so" out.
    _pat='(password|passphrase|db_?pass(wd)?|[a-z]_pass|secret|api[_-]?key|access[_-]?key|private[_-]?key|auth[_-]?token|token|connection[_-]?string)["'"'"']?[[:space:]]*(=|:|=>)[[:space:]]*["'"'"']?[^[:space:]"'"'"'$]'
    # Library code, caches and documentation mention these words without
    # holding real secrets.
    _skip='/(node_modules|site-packages|dist-packages|vendor|\.cache|\.npm|\.git|man|doc|locale|test|tests)/|^/opt/.*/(lib|share|platform|versions|gems)/'
    : >"$W/credfiles"
    # shellcheck disable=SC2086
    for _r in $_roots; do
        find "$_r" -xdev -type f -size -512k \( -name '*.conf' -o -name '*.cnf' -o -name '*.ini' -o -name '*.php' -o -name '*.env' -o -name '.env' \
            -o -name '*.yml' -o -name '*.yaml' -o -name '*.xml' -o -name '*.properties' -o -name '*.config' -o -name '*.cfg' \
            -o -name '.my.cnf' -o -name '.pgpass' -o -name 'wp-config.php' -o -name 'settings.py' -o -name 'config.py' \) \
            -exec grep -l -i -E "$_pat" {} + 2>/dev/null >>"$W/credfiles"
    done
    grep -vE "$_skip" "$W/credfiles" | sort -u >"$W/credfiles2"
    mv "$W/credfiles2" "$W/credfiles"
    while IFS= read -r _f; do
        _md=$(mode_of "$_f"); _ow=$(owner_of "$_f")
        _all=no; case "$_md" in ???????r*) _all=yes ;; esac
        # line number and the setting NAME only
        grep -n -i -E "$_pat" "$_f" 2>/dev/null | head -n 20 | awk -F: '{
            l = tolower($0); sub(/^[0-9]+:/, "", l)
            if (match(l, /(password|passphrase|db_?pass(wd)?|[a-z]_pass|secret|api[_-]?key|access[_-]?key|private[_-]?key|auth[_-]?token|token|connection[_-]?string)/)) print $1 "|" substr(l, RSTART, RLENGTH)
        }' >"$W/credlines"
        while IFS='|' read -r _ln _key; do cc_csv_row "$F" "$_f" "$_ln" "$_key" "$_ow" "$_md" "$_all"; done <"$W/credlines"
        # Most files in /etc are readable by everyone on purpose, so only
        # application and web files are flagged.  The /etc ones stay in the CSV.
        if [ "$_all" = yes ]; then
            case "$_f" in
                /var/www/*|/srv/*|/opt/*|/home/*|/usr/share/nginx/*|/var/lib/tomcat*) flag MED "$_f" "every user can read this file and it holds a password-like setting" ;;
                */.my.cnf|*/.pgpass|*/debian.cnf|*/wp-config.php|*/.env) flag MED "$_f" "every user can read this credentials file" ;;
            esac
        fi
    done <"$W/credfiles"
    say "Files holding password-like settings: $(wc -l <"$W/credfiles" | tr -d ' ') (names only, values never recorded)"

    # Backups and repositories inside web content can usually be downloaded.
    for _r in /var/www /srv /usr/share/nginx /var/lib/tomcat*; do
        [ -d "$_r" ] || continue
        find "$_r" -xdev \( -name '*.bak' -o -name '*.old' -o -name '*.orig' -o -name '*.sql' -o -name '*.swp' -o -name '*~' \
            -o -name '*.zip' -o -name '*.tar' -o -name '*.tar.gz' -o -name '*.tgz' -o -name '*.7z' -o -name '.git' -o -name '.env' \) 2>/dev/null
    done | head -n 100 >"$W/webbak"
    while IFS= read -r _p; do flag HIGH "$_p" "backup, archive or repository inside web content: it may be downloadable"; done <"$W/webbak"

    # Private keys outside the SSH host keys.
    sec_csv private_keys "file,owner,mode,readable_by_all"
    PK=$SEC_CSV
    # A real key file STARTS with its header line.  Matching only the first
    # line keeps out source code and documentation that mention keys.
    for _r in /home /root /etc /var/www /srv /opt; do
        [ -d "$_r" ] && find "$_r" -xdev -type f -size -16k ! -name 'ssh_host_*' -exec grep -l '^-----BEGIN .*PRIVATE KEY-----' {} + 2>/dev/null
    done | grep -vE '/(node_modules|site-packages|dist-packages|\.cache|test|tests)/|^/opt/.*/(lib|share|platform|versions|gems)/' | head -n 200 >"$W/pkeys.all"
    : >"$W/pkeys"
    while IFS= read -r _f; do
        head -n 1 "$_f" 2>/dev/null | grep -q '^-----BEGIN .*PRIVATE KEY-----' && printf '%s\n' "$_f" >>"$W/pkeys"
    done <"$W/pkeys.all"
    while IFS= read -r _f; do
        _md=$(mode_of "$_f"); _all=no; case "$_md" in ???????r*) _all=yes ;; esac
        cc_csv_row "$PK" "$_f" "$(owner_of "$_f")" "$_md" "$_all"
        [ "$_all" = yes ] && flag HIGH "$_f" "private key readable by every user"
        case "$_f" in /var/www/*|/srv/*) flag HIGH "$_f" "private key inside web content" ;; esac
    done <"$W/pkeys"

    # Shell and client history: disabled history hides what someone did;
    # typed passwords are counted, never copied.
    sec_csv history "file,lines,possible_passwords,note"
    H=$SEC_CSV
    home_dirs
    while IFS='|' read -r _u _uid _h; do
        for _n in .bash_history .zsh_history .sh_history .ash_history .mysql_history .psql_history .python_history; do
            _f="$_h/$_n"
            if [ -h "$_f" ]; then
                _t=$(readlink "$_f")
                cc_csv_row "$H" "$_f" "" "" "link to $_t"
                [ "$_t" = /dev/null ] && flag MED "$_f" "$_u's history is linked to /dev/null: commands are being hidden"
            elif [ -f "$_f" ]; then
                _lines=$(wc -l <"$_f" | tr -d ' ')
                _pw=$(grep -cE '(mysql .*-p[^ ]|sshpass|PASSWORD=|--password|passwd |chpasswd|smbpasswd|net user .* /add)' "$_f" 2>/dev/null)
                cc_csv_row "$H" "$_f" "$_lines" "$_pw" ""
                [ "${_pw:-0}" -gt 0 ] && flag MED "$_f" "$_pw history line(s) may contain typed passwords"
            fi
        done
    done <"$W/homes"
}

s_containers() {
    sec_csv containers "engine,id,image,name,status,privileged,mounts"
    F=$SEC_CSV
    _any=0
    if cc_have docker; then
        _any=1
        if docker ps -a --format '{{.ID}}|{{.Image}}|{{.Names}}|{{.Status}}' >"$W/dps" 2>/dev/null; then
            cc_save docker_ps docker ps -a
            while IFS='|' read -r _id _img _name _st; do
                _priv=$(docker inspect --format '{{.HostConfig.Privileged}}' "$_id" 2>/dev/null)
                _mnt=$(docker inspect --format '{{range .Mounts}}{{.Source}}:{{.Destination}} {{end}}' "$_id" 2>/dev/null)
                cc_csv_row "$F" docker "$_id" "$_img" "$_name" "$_st" "$_priv" "$_mnt"
                [ "$_priv" = true ] && flag HIGH "container $_name" "runs privileged: a root shell in it is root on this host"
                case " $_mnt" in *" /:"*|*docker.sock*|*" /etc:"*|*" /root:"*) flag HIGH "container $_name" "mounts a sensitive host path: $_mnt" ;; esac
            done <"$W/dps"
        else
            note "docker is installed but 'docker ps' failed (daemon down or no permission)"
        fi
    fi
    if [ -S /var/run/docker.sock ]; then
        _md=$(mode_of /var/run/docker.sock)
        case "$_md" in ????????w*) flag HIGH /var/run/docker.sock "Docker socket is world-writable: every user is effectively root" ;; esac
    fi
    cc_have podman && { _any=1; cc_save podman_ps podman ps -a; }
    cc_have lxc && { _any=1; cc_save lxc_list lxc list; }
    cc_have lxc-ls && { _any=1; cc_save lxc_ls lxc-ls -f; }
    cc_have crictl && { _any=1; cc_save crictl_ps crictl ps -a; }
    cc_have kubectl && { _any=1; cc_save kubectl_pods kubectl get pods -A -o wide; }
    [ "$_any" = 1 ] || cc_csv_row "$F" none "" "" "" "" "" ""
    say "Containers: $(($(wc -l <"$F") - 1)) listed"
}

s_modules() {
    sec_csv modules "name,size,used_by"
    F=$SEC_CSV
    if [ -r /proc/modules ]; then
        awk "$AWK_Q"'{ print q($1) "," q($2) "," q($4) }' /proc/modules >>"$F"
        _t=$(cat /proc/sys/kernel/tainted 2>/dev/null)
        [ -n "$_t" ] && [ "$_t" != 0 ] && flag LOW kernel "kernel is tainted ($_t): an unsigned or out-of-tree module was loaded"
    elif cc_have kldstat; then
        cc_save kldstat kldstat
    elif cc_have modinfo && [ "$CC_OS_FAMILY" = solaris ]; then
        cc_save modinfo modinfo
    fi
    # modprobe 'install' lines run a command whenever a module loads: a
    # persistence trick.  'install X /bin/false' (used to block a module) is
    # normal.
    for _f in /etc/modprobe.d/*.conf /etc/modprobe.conf; do
        [ -f "$_f" ] || continue
        awk -v src="$_f" '$1 == "install" && $3 !~ /^\/(usr\/)?bin\/(false|true)$/ && $0 !~ /\/sbin\/modprobe/ { print "MED|" src "|module load runs a command: " $0 }' "$_f" >"$W/f_mod"
        emit_flags "$W/f_mod"
    done
    for _f in /etc/modules /etc/modules-load.d/*.conf; do
        [ -f "$_f" ] && cc_save "modules_load_$(basename "$_f")" cat "$_f"
    done
}

s_logs() {
    # Copy logs now, before a red team clears them.  Large text logs are cut
    # to their last 200000 lines; binary login records are copied whole.
    _ld="$CC_RUN_DIR/logs"
    mkdir -p "$_ld" || { note "cannot create $_ld"; return 0; }
    sec_csv logs "file,copied_as,bytes,sha256"
    F=$SEC_CSV
    for _f in /var/log/auth.log /var/log/auth.log.1 /var/log/secure /var/log/messages /var/log/syslog /var/log/kern.log \
              /var/log/cron /var/log/audit/audit.log /var/log/mail.log /var/log/maillog \
              /var/log/apache2/access.log /var/log/apache2/error.log /var/log/httpd/access_log /var/log/httpd/error_log \
              /var/log/nginx/access.log /var/log/nginx/error.log /var/log/wtmp /var/log/btmp /var/log/lastlog; do
        [ -f "$_f" ] || continue
        _dst="$_ld/$(printf '%s' "$_f" | sed 's|^/||; s|/|_|g')"
        case "$_f" in
            */wtmp|*/btmp) cp -p "$_f" "$_dst" 2>/dev/null ;;
            */lastlog) continue ;;     # sparse file that can appear huge; 'last' output is saved instead
            *) tail -n 200000 "$_f" >"$_dst" 2>/dev/null ;;
        esac
        [ -f "$_dst" ] || continue
        cc_csv_row "$F" "$_f" "$_dst" "$(wc -c <"$_dst" | tr -d ' ')" "$(cc_sha256 "$_dst")"
    done
    if [ "$CC_INIT" = systemd ] && cc_have journalctl; then
        journalctl --since "48 hours ago" --no-pager -o short-iso >"$_ld/journal_48h.txt" 2>/dev/null
        cc_csv_row "$F" "journalctl (48 hours)" "$_ld/journal_48h.txt" "$(wc -c <"$_ld/journal_48h.txt" | tr -d ' ')" "$(cc_sha256 "$_ld/journal_48h.txt")"
    fi
    dmesg >"$_ld/dmesg.txt" 2>/dev/null
    _n=$(($(wc -l <"$F") - 1))
    say "Logs: $_n file(s) copied to $_ld - copy them off this host"
    [ "$IS_ROOT" = 1 ] || note "partial: most logs need root"
}

# =============================================================================
# Run the sections and write the summary
# =============================================================================

# nflags SEVERITY -> how many flags of that severity flags.csv holds so far.
nflags() {
    if [ -f "$CC_CSV_DIR/flags.csv" ]; then grep -c "^\"$1\"" "$CC_CSV_DIR/flags.csv"; else echo 0; fi
    return 0
}

run_section() {
    SEC=$1; SEC_FILES=""; SEC_NOTE=""
    _rs_n=$((_rs_n + 1))
    cc_note "[$_rs_n/$_rs_total] $SEC"
    show "" ""
    show "$C_CYN" "==========[ $_rs_n/$_rs_total  $SEC ]=========="
    _rs_hi0=$(nflags HIGH); _rs_me0=$(nflags MED)
    _rs_t0=$(date +%s 2>/dev/null)
    "s_$SEC"
    _rs_t1=$(date +%s 2>/dev/null)
    _rows=0
    for _f in $SEC_FILES; do
        [ -f "$_f" ] && _rows=$((_rows + $(wc -l <"$_f") - 1))
    done
    cc_debug "section $SEC: $_rows rows in $((${_rs_t1:-0} - ${_rs_t0:-0}))s"
    _rs_hi=$(( $(nflags HIGH) - _rs_hi0 ))
    _rs_me=$(( $(nflags MED) - _rs_me0 ))
    [ "$_rs_hi" -eq 0 ] && [ "$_rs_me" -eq 0 ] && show "$C_GRN" "  [ok] nothing to fix here"
    _rs_files=""
    for _f in $SEC_FILES; do [ -f "$_f" ] && _rs_files="$_rs_files $(basename "$_f")"; done
    show "$C_GRY" "  ($_rows rows${_rs_files:+ ->$(printf '%s' "$_rs_files" | sed 's/\.csv/.txt/g')}${SEC_NOTE:+; $SEC_NOTE})"
    printf '%s|%s|%s\n' "$SEC" "$_rows" "$SEC_NOTE" >>"$W/sections"
}

: >"$W/summary_lines"; : >"$W/sections"
_rs_total=$(printf '%s\n' $SECTIONS | grep -c .)
_rs_n=0
for _s in $SECTIONS; do run_section "$_s"; done

# Section table: rows collected plus flags per severity, read from flags.csv.
_flagsf="$CC_CSV_DIR/flags.csv"
[ -f "$_flagsf" ] || printf 'severity,section,item,detail,time\n' >"$_flagsf"
# Read by cc_flag_report in the library.
# shellcheck disable=SC2034
CC_FLAGS=$_flagsf
# shellcheck disable=SC2034
CC_FLAGS_SHOW="$CC_RUN_DIR/flags.txt"
# A readable table for every CSV file: <run>/users.txt, ports.txt, ...
# flags.txt lists HIGH first, then MED, then LOW, with the detail kept whole.
for _c in "$CC_CSV_DIR"/*.csv; do
    [ -f "$_c" ] || continue
    _b=$(basename "$_c" .csv)
    if [ "$_b" = flags ]; then
        { head -n 1 "$_c"; for _sv in HIGH MED LOW; do grep "^\"$_sv\"" "$_c"; done; } >"$W/flags_sorted.csv"
        cc_csv_pretty "$W/flags_sorted.csv" "$CC_RUN_DIR/flags.txt" 200
    else
        cc_csv_pretty "$_c" "$CC_RUN_DIR/$_b.txt"
    fi
done
{
    printf 'SH-05 Linux enum | host %s | %s | profile %s | root: %s\n' "$CC_HOST" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$PROFILE" "$([ "$IS_ROOT" = 1 ] && echo yes || echo NO - partial)"
    printf 'OS: %s | kernel %s | init %s\n\n' "$CC_OS_NAME" "$(uname -r 2>/dev/null)" "$CC_INIT"
    cat "$W/summary_lines"
    printf '\n'
    awk -v sf="$W/sections" "$CC_AWK_CSV"'
        BEGIN { FS = "\n" }
        NR > 1 { csvsplit($0, f); c[f[2] "|" f[1]]++ }
        END {
            printf "%-12s %6s %5s %5s %5s  %s\n", "section", "rows", "high", "med", "low", "note"
            while ((getline l < sf) > 0) {
                split(l, s, "|")
                printf "%-12s %6d %5d %5d %5d  %s\n", s[1], s[2], c[s[1] "|HIGH"], c[s[1] "|MED"], c[s[1] "|LOW"], s[3]
            }
        }' "$_flagsf"
    printf '\n'
    cc_flag_report "$MAXFLAGS"
    printf '\nAll results: %s\n' "$CC_RUN_DIR"
} >"$CC_RUN_DIR/summary.txt"
show "" ""
show "$C_CYN" "==========[ SUMMARY ]=========="
# The summary on screen is colour-coded; summary.txt and output.txt stay plain.
#   red     HIGH flags, and sections that have any
#   yellow  MED flags, and sections with MED but no HIGH
#   green   key facts, and sections with nothing to fix
#   cyan    headings
awk -v R="$C_RED" -v Y="$C_YEL" -v G="$C_GRN" -v C="$C_CYN" -v D="$C_GRY" -v O="$C_OFF" '
    /^section +rows +high/  { intable = 1; seen_table = 1; print C $0 O; next }
    intable && /^$/         { intable = 0; print; next }
    intable {
        if ($3 + 0 > 0) print R $0 O
        else if ($4 + 0 > 0) print Y $0 O
        else print G $0 O
        next
    }
    /^Flags:/               { print C $0 O; next }
    /^HIGH - /              { mode = "H"; print R $0 O; next }
    /^MED - /               { mode = "M"; print Y $0 O; next }
    /^  \[/ && mode == "H"  { print R "  [!] FIX " substr($0, 3) O; next }
    /^  \[/ && mode == "M"  { print Y "  [*] LOOK" substr($0, 2) O; next }
    /^All (flags|results)/  { print D $0 O; next }
    NR <= 2                 { print C $0 O; next }
    /^$/                    { print; next }
    !seen_table             { print G $0 O; next }
                            { print }
' "$CC_RUN_DIR/summary.txt" >&3
cat "$CC_RUN_DIR/summary.txt" >>"$OUTF"
rm -rf "$W"
cc_finish
