#!/bin/sh
# =============================================================================
# ID:       SH-03
# NAME:     Network scan
# ROLE:     Network  (wave 1)
# KIND:     readonly - sends probes, changes nothing on any host
# VERSION:  1.0.0
#
# PURPOSE
#   Finds every live host and open port on the team's networks, with the
#   service and version behind each port.  The host collectors only see the
#   boxes you already know about; this finds the ones you do not, and the
#   ports that should not be open.
#
#   Given the host list (--hosts), it also answers the two questions that
#   matter most in the first minutes:
#     - Is every scored service reachable?   (HIGH flag if one is not)
#     - Is anything up that is not on the list?
#
#   Output is layered like every inventory script:
#     screen / summary.txt   hosts up, one line per host with its open ports,
#                            and only the HIGH and MEDIUM flags
#     hosts.csv, ports.csv   everything found
#     flags.csv              every flag, including LOW
#     raw/                   nmap's own output (.nmap, .gnmap, .xml)
#
# USAGE
#   sh SH-03-network-scan.sh --target 10.0.2.0/24 [options]
#   Run it from the admin workstation.  Root is not required, but nmap is
#   faster and can guess operating systems when run as root.
#
# OPTIONS
#   --target SPEC      what to scan; repeatable.  An address (10.0.2.5), a
#                      network (10.0.2.0/24), a last-octet range
#                      (10.0.2.1-50) or a host name
#   --targets-file F   one target per line (# comments allowed)
#   --hosts FILE       host list CSV (config/hosts.example.csv format).
#                      Turns on the host-list and scored-service checks
#   --profile NAME     fast | full | udp | outside   (default: fast)
#                        fast     top 1000 TCP ports with service versions
#                        full     all 65535 TCP ports (+ OS guess as root).
#                                 Slow: minutes per host
#                        udp      top 25 UDP ports (needs root)
#                        outside  like fast, but does not trust ping (-Pn);
#                                 run it from OUTSIDE the firewall to see
#                                 what the red team sees
#   --ports LIST       scan these ports instead (e.g. 22,80,443 or 1-1024)
#   --engine NAME      nmap | python | bash | nc   (default: first available,
#                      in that order).  Without nmap there is no version
#                      detection, only a banner, and only TCP
#   --no-dns           do not look up host names (faster when DNS is slow)
#   --pn               treat every target as up (for hosts that drop ping)
#   --max-hosts N      refuse to scan more than N addresses without nmap
#                      (default 1024); nmap has no limit
#   --max-flags N      HIGH/MED flags shown on screen (default 30)
#   --help             this text plus the common options
#
# OUTPUTS  (under --out, in SH-03_<host>_<UTC time>/)
#   summary.txt     the page printed on screen
#   hosts.csv       ip,hostname,status,open_tcp,open_udp,os_guess,in_host_list,host_list_name
#   ports.csv       ip,hostname,proto,port,state,service,version
#   flags.csv       severity,section,item,detail,time
#   scored.csv      host,ip,service,port,reachable      (only with --hosts)
#   raw/            nmap output in all three formats, or the fallback's results
#
# WHAT IT CHANGES
#   Nothing on any host.  It connects to ports and reads what they say.
#   Version detection sends ordinary protocol requests; it does not exploit
#   anything.  Scans are visible in logs, which is expected and fine on your
#   own network.
#
# DEPENDS ON
#   nmap (best).  Without it: python3, else bash with 'timeout', else nc -z.
#   awk, sort, getent or host for names.
#
# TESTED ON
#   Ubuntu 24.04 with nmap 7.94 and with the python, bash and nc fallbacks,
#   scanning listeners on 127.0.0.1, under dash, bash, busybox sh, ksh93,
#   mksh and yash.  Not yet tested against a real competition network.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - A closed port can mean "not listening" or "a firewall dropped it".  A
#     scored service that shows as not reachable may be fine from the scoring
#     engine's side; check it from there or with the service checker (SH-08).
#   - From inside, you see more than the red team does.  Use --profile
#     outside from outside the firewall for their view.
#   - Hosts that drop ping and have no common port open are missed unless
#     you use --pn (slower, because every address is scanned in full).
#   - The fallback engines only check a fixed list of common TCP ports.
#
# DEBUGGING
#   --debug          shows the exact nmap command and each parsing step
#   raw/*.nmap       nmap's own human-readable report: compare it with
#                    ports.csv if something looks missing
#   --engine python  forces the fallback, to compare with nmap's results
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

# Ports the fallback engines check (TCP only).  Chosen for CCDC networks:
# the usual scored services, Windows/AD, databases, remote admin, and ports
# red teams like.
FALLBACK_PORTS="21,22,23,25,53,80,88,110,111,135,139,143,389,443,445,464,465,514,587,593,636,993,995,1080,1433,1521,2049,2375,3000,3268,3306,3389,4444,5000,5432,5601,5900,5985,5986,6379,6667,8000,8080,8081,8443,8888,9000,9090,9200,10000,11211,27017,31337"

usage() {
    cat <<'USAGE'
SH-03 Network scan - live hosts, open ports, services
  sh SH-03-network-scan.sh --target 10.0.2.0/24 [options]

  --target SPEC        address, network/NN, a.b.c.N-M or name (repeatable)
  --targets-file FILE  one target per line
  --hosts FILE         host list CSV: check scored services and unknown hosts
  --profile NAME       fast | full | udp | outside   (default fast)
  --ports LIST         ports to scan instead of the profile's
  --engine NAME        nmap | python | bash | nc     (default: best available)
  --no-dns             skip host name lookups
  --pn                 treat every target as up
  --max-hosts N        address limit for the fallback engines (default 1024)
  --max-flags N        HIGH/MED flags shown on screen (default 30)
  --help               show this text

USAGE
    cc_usage_common
}

# ---- Options ----------------------------------------------------------------
TARGETS=""
HOSTLIST=""
PROFILE=fast
PORTS=""
ENGINE=""
NODNS=0
PN=0
MAXHOSTS=1024
MAXFLAGS=30

# add_target SPEC -> append to TARGETS after checking it looks like an
#   address, network, range or host name.  Targets are handed to nmap as
#   separate arguments, never through a shell, but rejecting junk early
#   gives a clearer error than nmap's.
add_target() {
    case "$1" in
        ''|-*|*[!A-Za-z0-9./:_-]*) cc_die 2 "not a valid target: '$1' (use 10.0.2.5, 10.0.2.0/24, 10.0.2.1-50 or a name)" ;;
    esac
    TARGETS="$TARGETS $1"
}

while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --target)       [ $# -ge 2 ] || cc_die 2 "--target needs a value"; add_target "$2"; shift 2 ;;
        --targets-file) [ $# -ge 2 ] || cc_die 2 "--targets-file needs a file"
                        [ -r "$2" ] || cc_die 2 "cannot read targets file: $2"
                        for _t in $(sed 's/#.*//' "$2"); do add_target "$_t"; done
                        shift 2 ;;
        --hosts)        [ $# -ge 2 ] || cc_die 2 "--hosts needs a file"; HOSTLIST=$2; shift 2 ;;
        --profile)      [ $# -ge 2 ] || cc_die 2 "--profile needs a name"; PROFILE=$2; shift 2 ;;
        --ports)        [ $# -ge 2 ] || cc_die 2 "--ports needs a list"; PORTS=$2; shift 2 ;;
        --engine)       [ $# -ge 2 ] || cc_die 2 "--engine needs a name"; ENGINE=$2; shift 2 ;;
        --no-dns)       NODNS=1; shift ;;
        --pn)           PN=1; shift ;;
        --max-hosts)    [ $# -ge 2 ] || cc_die 2 "--max-hosts needs a number"; MAXHOSTS=$2; shift 2 ;;
        --max-flags)    [ $# -ge 2 ] || cc_die 2 "--max-flags needs a number"; MAXFLAGS=$2; shift 2 ;;
        --help|-h)      usage; exit 0 ;;
        *)              cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done

[ -n "$TARGETS" ] || cc_die 2 "nothing to scan: give --target or --targets-file (try --help)"
case "$PROFILE" in fast|full|udp|outside) ;; *) cc_die 2 "unknown profile '$PROFILE' (fast, full, udp or outside)" ;; esac
case "$MAXHOSTS" in ''|*[!0-9]*) cc_die 2 "--max-hosts needs a whole number" ;; esac
case "$MAXFLAGS" in ''|*[!0-9]*) cc_die 2 "--max-flags needs a whole number" ;; esac
case "$PORTS" in *[!0-9,-]*) cc_die 2 "--ports takes numbers, commas and ranges only (e.g. 22,80,8000-8100)" ;; esac
[ -z "$HOSTLIST" ] || [ -r "$HOSTLIST" ] || cc_die 2 "cannot read host list: $HOSTLIST"
[ "$PROFILE" = outside ] && PN=1

# Pick the engine: the requested one, or the best available.
if [ -z "$ENGINE" ]; then
    if cc_have nmap; then ENGINE=nmap
    elif cc_have python3; then ENGINE=python
    elif cc_have bash && cc_have timeout; then ENGINE=bash
    elif cc_have nc; then ENGINE=nc
    else cc_die 3 "no scanner available: install nmap (best), or make python3, bash with timeout, or nc available"
    fi
fi
case "$ENGINE" in
    nmap)   cc_need nmap ;;
    python) cc_need python3 ;;
    bash)   cc_need bash timeout ;;
    nc)     cc_need nc ;;
    *)      cc_die 2 "unknown engine '$ENGINE' (nmap, python, bash or nc)" ;;
esac
if [ "$PROFILE" = udp ] && [ "$ENGINE" != nmap ]; then cc_die 3 "the udp profile needs nmap"; fi

# ---- Start ------------------------------------------------------------------
cc_init "SH-03" "Network scan" readonly
cc_use_run_dir
W="$CC_RUN_DIR/.work"
mkdir -p "$W" || cc_die 3 "cannot create $W"
RAW="$CC_RUN_DIR/raw"
IS_ROOT=0
cc_is_root && IS_ROOT=1
if [ "$PROFILE" = udp ] && [ "$IS_ROOT" != 1 ]; then cc_die 3 "UDP scanning needs root (sudo)"; fi
cc_info "targets:$TARGETS | profile $PROFILE | engine $ENGINE"

# Shared awk helpers:
#   ip2n("10.0.2.5")      -> 167772677
#   n2ip(167772677)       -> "10.0.2.5"
#   intarget(ip, specs)   -> 1 if ip falls inside any of the space-separated
#                            target specs (address, CIDR, a.b.c.N-M); host
#                            names never match by address
AWK_IP='
function ip2n(ip,   p) { if (split(ip, p, ".") != 4) return -1; return ((p[1] * 256 + p[2]) * 256 + p[3]) * 256 + p[4] }    # awk: posix-ok
function n2ip(n,   a, b, c) { a = int(n / 16777216); n -= a * 16777216; b = int(n / 65536); n -= b * 65536; c = int(n / 256); return a "." b "." c "." (n - c * 256) }    # awk: posix-ok
function pow2(k,   r) { r = 1; while (k-- > 0) r *= 2; return r }    # awk: posix-ok
function intarget(ip, specs,   n, i, s, t, base, bits, size, lo, hi, m, x) {    # awk: posix-ok
    x = ip2n(ip); if (x < 0) return 0
    n = split(specs, s, " ")
    for (i = 1; i <= n; i++) {
        t = s[i]
        if (t == ip) return 1
        if (index(t, "/")) {
            split(t, m, "/"); bits = m[2] + 0; base = ip2n(m[1]); if (base < 0) continue
            size = pow2(32 - bits); lo = base - base % size
            if (x >= lo && x < lo + size) return 1
        } else if (t ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+-[0-9]+$/) {
            split(t, m, "-"); lo = ip2n(m[1]); hi = lo - lo % 256 + m[2]
            if (x >= lo && x <= hi) return 1
        }
    }
    return 0
}'

# Well-known names for ports, used by the fallback engines (nmap names its
# own) and in flags.
port_name() {
    case "$1" in
        21) echo ftp ;; 22) echo ssh ;; 23) echo telnet ;; 25) echo smtp ;; 53) echo domain ;; 69) echo tftp ;;
        80) echo http ;; 88) echo kerberos ;; 110) echo pop3 ;; 111) echo rpcbind ;; 135) echo msrpc ;;
        139) echo netbios-ssn ;; 143) echo imap ;; 161) echo snmp ;; 389) echo ldap ;; 443) echo https ;;
        445) echo microsoft-ds ;; 464) echo kpasswd ;; 465) echo smtps ;; 514) echo shell ;; 587) echo submission ;;
        593) echo http-rpc-epmap ;; 636) echo ldaps ;; 993) echo imaps ;; 995) echo pop3s ;; 1080) echo socks ;;
        1433) echo ms-sql-s ;; 1521) echo oracle ;; 2049) echo nfs ;; 2375) echo docker ;; 3268) echo globalcatLDAP ;;
        3306) echo mysql ;; 3389) echo ms-wbt-server ;; 5432) echo postgresql ;; 5601) echo kibana ;;
        5900) echo vnc ;; 5985) echo wsman ;; 5986) echo wsmans ;; 6379) echo redis ;; 6667) echo irc ;;
        8080|8000|8081|8888|9000|9090|3000|5000) echo http-alt ;; 8443) echo https-alt ;; 9200) echo elasticsearch ;;
        10000) echo webmin ;; 11211) echo memcache ;; 27017) echo mongodb ;; *) echo "" ;;
    esac
}

# ---- Expand targets (fallback engines only) --------------------------------
# nmap understands every target form itself.  The fallback engines need a
# plain list of addresses, built here and capped by --max-hosts.
expand_targets() {
    : >"$W/ips"
    for _t in $TARGETS; do
        case "$_t" in
            *[!0-9./-]*)  # a host name: resolve it
                _a=$(getent hosts "$_t" 2>/dev/null | awk '{ print $1; exit }')
                [ -n "$_a" ] && printf '%s\n' "$_a" >>"$W/ips" || cc_warn "cannot resolve $_t, skipped" ;;
            *)
                awk -v t="$_t" -v max="$MAXHOSTS" "$AWK_IP"'
                    BEGIN {
                        if (index(t, "/")) {
                            split(t, m, "/"); bits = m[2] + 0; base = ip2n(m[1])
                            if (base < 0 || bits < 8 || bits > 32) { print "BAD"; exit }
                            size = pow2(32 - bits); lo = base - base % size; hi = lo + size - 1
                            if (bits <= 30) { lo++; hi-- }          # skip network and broadcast
                        } else if (index(t, "-")) {
                            split(t, m, "-"); lo = ip2n(m[1]); hi = lo - lo % 256 + m[2]
                            if (lo < 0 || hi < lo) { print "BAD"; exit }
                        } else { lo = ip2n(t); hi = lo; if (lo < 0) { print "BAD"; exit } }
                        if (hi - lo + 1 > max) { print "TOOBIG " (hi - lo + 1); exit }
                        for (x = lo; x <= hi; x++) print n2ip(x)
                    }' >"$W/one"
                case "$(head -n 1 "$W/one")" in
                    BAD) cc_die 2 "cannot understand target '$_t'" ;;
                    TOOBIG*) cc_die 2 "target '$_t' has $(cut -d' ' -f2 "$W/one") addresses; the $ENGINE engine is limited to $MAXHOSTS (install nmap, scan a smaller range, or raise --max-hosts)" ;;
                esac
                cat "$W/one" >>"$W/ips" ;;
        esac
    done
    sort -u "$W/ips" -o "$W/ips"
    _n=$(wc -l <"$W/ips" | tr -d ' ')
    [ "$_n" -le "$MAXHOSTS" ] || cc_die 2 "$_n addresses in total; the $ENGINE engine is limited to $MAXHOSTS"
    cc_info "$_n address(es) to probe"
}

# ---- Engines ----------------------------------------------------------------
# Every engine ends by writing two normalised files that the rest of the
# script reads, so the reporting below does not care which engine ran:
#   $W/up     ip|hostname|os_guess          one line per live host
#   $W/open   ip|proto|port|service|version one line per open port

run_nmap() {
    _base="$RAW/nmap_$PROFILE"
    # Timing T4 is nmap's "aggressive but reliable on a LAN" setting.
    set -- -T4 --open -oA "$_base" --stats-every 60s
    [ "$NODNS" = 1 ] && set -- "$@" -n
    [ "$PN" = 1 ] && set -- "$@" -Pn
    case "$PROFILE" in
        fast|outside) set -- "$@" -sV --version-light ;;
        full)         set -- "$@" -sV; [ "$IS_ROOT" = 1 ] && set -- "$@" -O --osscan-limit ;;
        udp)          set -- "$@" -sU -sV --version-light ;;
    esac
    if [ -n "$PORTS" ]; then set -- "$@" -p "$PORTS"
    else
        case "$PROFILE" in
            fast|outside) set -- "$@" --top-ports 1000 ;;
            full)         set -- "$@" -p- ;;
            udp)          set -- "$@" --top-ports 25 ;;
        esac
    fi
    # shellcheck disable=SC2086
    set -- "$@" $TARGETS
    cc_info "running: nmap $*"
    [ "$PROFILE" = full ] && cc_info "full scans take minutes per host; progress is printed every 60 seconds"
    # nmap's own screen output goes to a file; only its progress lines are
    # shown, so the screen stays readable.
    nmap "$@" 2>&1 | tee "$RAW/nmap_screen.txt" | awk '/^Stats:|Timing:|^NSE: Script/ { print "   nmap: " $0; fflush() }' >&2
    [ -s "$_base.gnmap" ] || cc_die 1 "nmap produced no results (see $RAW/nmap_screen.txt); common causes: bad target, no permission for this scan type"
    nmap --version 2>/dev/null | head -n 1 >"$W/engine_version"

    # Grepable format, one host per line, tab-separated fields:
    #   Host: 10.0.2.5 (web01)<TAB>Ports: 22/open/tcp//ssh//OpenSSH 8.9p1/, 80/open/...<TAB>OS: Linux
    # Each port entry is exactly seven '/'-separated fields.  Versions can
    # contain commas, so entries are cut by matching that shape, not by
    # splitting on ", ".
    awk -F'\t' -v upf="$W/up" -v openf="$W/open" '
        /^Host: / {
            split($1, h, " "); ip = h[2]; name = $1; sub(/^Host: [^ ]* \(/, "", name); sub(/\)$/, "", name)
            os = ""
            for (i = 2; i <= NF; i++) if ($i ~ /^OS: /) { os = $i; sub(/^OS: /, "", os) }
            if (!(ip in seen) || os != "") { seen[ip] = 1; info[ip] = name "|" os }
            for (i = 2; i <= NF; i++) {
                if ($i !~ /^Ports: /) continue
                s = $i; sub(/^Ports: /, "", s)
                while (match(s, /^[0-9]+\/[^\/]*\/[^\/]*\/[^\/]*\/[^\/]*\/[^\/]*\/[^\/]*\//)) {
                    e = substr(s, 1, RLENGTH); s = substr(s, RLENGTH + 1); sub(/^, /, "", s)
                    split(e, f, "/")
                    if (f[2] ~ /^open/) { v = f[7]; gsub(/\|/, "/", v); print ip "|" f[3] "|" f[1] "|" f[5] "|" v > openf }
                }
            }
        }
        END { for (ip in info) print ip "|" info[ip] > upf }' "$_base.gnmap"
    touch "$W/up" "$W/open"
}

run_python() {
    expand_targets
    # One small Python program does a threaded TCP connect scan and reads a
    # short banner from each open port (HTTP ports get a HEAD request).
    cat >"$W/scan.py" <<'PY'
import socket, sys, threading
try:
    import queue
except ImportError:
    import Queue as queue
ips = [l.strip() for l in open(sys.argv[1]) if l.strip()]
ports = [int(p) for p in sys.argv[2].split(",") if p]
tmo = float(sys.argv[3])
out = open(sys.argv[4], "w")
HTTP = set([80, 3000, 5000, 8000, 8008, 8080, 8081, 8888, 9000, 9090])
lock = threading.Lock()
def probe(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(tmo)
    try:
        s.connect((ip, port))
    except Exception:
        s.close()
        return
    banner = ""
    try:
        if port in HTTP:
            s.sendall(("HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n" % ip).encode())
        s.settimeout(1.5)
        lines = s.recv(512).decode("latin-1", "replace").splitlines()
        if port in HTTP:
            srv = [l for l in lines if l.lower().startswith("server:")]
            banner = (lines[0] if lines else "") + (" " + srv[0] if srv else "")
        elif lines:
            banner = lines[0]
    except Exception:
        pass
    finally:
        s.close()
    banner = "".join(c if 32 <= ord(c) < 127 else " " for c in banner)[:150].replace("|", "/")
    with lock:
        out.write("%s|%d|%s\n" % (ip, port, banner))
        out.flush()
q = queue.Queue()
for i in ips:
    for p in ports:
        q.put((i, p))
def worker():
    while True:
        try:
            i, p = q.get_nowait()
        except queue.Empty:
            return
        probe(i, p)
ts = [threading.Thread(target=worker) for _ in range(min(128, max(1, q.qsize())))]
for t in ts:
    t.start()
for t in ts:
    t.join()
PY
    cc_info "probing $(printf '%s' "${PORTS:-$FALLBACK_PORTS}" | tr ',' '\n' | grep -c .) TCP port(s) per address with python"
    python3 "$W/scan.py" "$W/ips" "$(expand_ports)" 1.0 "$W/hits" 2>>"$CC_LOG" || cc_warn "python scan reported an error (see the log)"
    printf 'python %s\n' "$(python3 -V 2>&1)" >"$W/engine_version"
    finish_fallback
}

run_shell_engine() {
    expand_targets
    _plist=$(expand_ports | tr ',' ' ')
    : >"$W/hits"
    # One background job per address, at most 16 at a time.  Each job
    # writes its own file, so jobs never write to the same file at once.
    _n=0
    while IFS= read -r _ip; do
        (
            for _p in $_plist; do
                if [ "$ENGINE" = bash ]; then
                    timeout 1 bash -c "exec 3<>/dev/tcp/$_ip/$_p" 2>/dev/null && printf '%s|%s|\n' "$_ip" "$_p"
                else
                    nc -z -w 1 "$_ip" "$_p" >/dev/null 2>&1 && printf '%s|%s|\n' "$_ip" "$_p"
                fi
            done >"$W/hit.$_ip"
        ) &
        _n=$((_n + 1))
        [ $((_n % 16)) -eq 0 ] && wait
    done <"$W/ips"
    wait
    cat "$W"/hit.* >"$W/hits" 2>/dev/null
    rm -f "$W"/hit.*
    printf '%s\n' "$ENGINE connect scan" >"$W/engine_version"
    finish_fallback
}

# expand_ports -> print the port list with ranges (8000-8010) written out,
#   because the fallback engines take single ports.
expand_ports() {
    printf '%s' "${PORTS:-$FALLBACK_PORTS}" | tr ',' '\n' | awk -F- '
        NF == 2 { for (p = $1; p <= $2 && p <= 65535; p++) printf "%s%d", (n++ ? "," : ""), p; next }
        NF == 1 && $1 != "" { printf "%s%d", (n++ ? "," : ""), $1 }
        END { print "" }'
}

# finish_fallback -> turn $W/hits (ip|port|banner) into $W/up and $W/open.
#   A host counts as up when any port answered; there is no ping, because
#   ping is often missing or blocked.
finish_fallback() {
    : >"$W/open"
    while IFS='|' read -r _ip _p _ban; do
        printf '%s|tcp|%s|%s|%s\n' "$_ip" "$_p" "$(port_name "$_p")" "$_ban" >>"$W/open"
    done <"$W/hits"
    : >"$W/up"
    for _ip in $(cut -d'|' -f1 "$W/hits" | sort -u); do
        _name=""
        [ "$NODNS" = 1 ] || _name=$(getent hosts "$_ip" 2>/dev/null | awk '{ print $2; exit }')
        printf '%s|%s|\n' "$_ip" "$_name" >>"$W/up"
    done
}

case "$ENGINE" in
    nmap)    run_nmap ;;
    python)  run_python ;;
    bash|nc) run_shell_engine ;;
esac
sort -t'|' -k1,1 -u "$W/up" -o "$W/up"
sort -t'|' -k1,1 -k2,2 -k3,3n "$W/open" -o "$W/open"

# ---- Host list --------------------------------------------------------------
# Read config/hosts.csv into $W/hl as "ip|name|scored_services".  Lines that
# start with # are comments.  scored_services looks like http:80;dns:53.
: >"$W/hl"
if [ -n "$HOSTLIST" ]; then
    awk "$CC_AWK_CSV"'
        NR == 1 || /^[ \t]*#/ || NF == 0 { next }
        { csvsplit($0, f); if (f[2] != "") print f[2] "|" f[1] "|" f[8] }' "$HOSTLIST" >"$W/hl"
    cc_info "host list: $(wc -l <"$W/hl" | tr -d ' ') host(s) from $HOSTLIST"
fi

# ---- Write CSV files --------------------------------------------------------
HC=$(cc_csv_new hosts "ip,hostname,status,open_tcp,open_udp,os_guess,in_host_list,host_list_name")
PC=$(cc_csv_new ports "ip,hostname,proto,port,state,service,version")
awk -F'|' -v upf="$W/up" -v hlf="$W/hl" -v hc="$HC" -v pc="$PC" -v hashl="$( [ -s "$W/hl" ] && echo 1 || echo 0 )" '
    function q(s) { gsub(/"/, "\"\"", s); return "\"" s "\"" }    # awk: posix-ok
    BEGIN {
        while ((getline l < upf) > 0) { split(l, u, "|"); name[u[1]] = u[2]; os[u[1]] = u[3]; order[++n] = u[1] }
        while ((getline l < hlf) > 0) { split(l, h, "|"); hl[h[1]] = h[2] }
    }
    { if ($2 == "tcp") t[$1] = t[$1] (t[$1] == "" ? "" : " ") $3; else ud[$1] = ud[$1] (ud[$1] == "" ? "" : " ") $3
      print q($1) "," q(name[$1]) "," q($2) "," q($3) ",\"open\"," q($4) "," q($5) >> pc }
    END {
        for (i = 1; i <= n; i++) {
            ip = order[i]
            inl = hashl ? ((ip in hl) ? "yes" : "no") : ""
            print q(ip) "," q(name[ip]) ",\"up\"," q(t[ip]) "," q(ud[ip]) "," q(os[ip]) "," q(inl) "," q(hl[ip]) >> hc
        }
    }' "$W/open"

# ---- Flags ------------------------------------------------------------------
# Checks by port and by version banner.  Flags are pointers: a database port
# open on the database server may be exactly what the scoring engine needs.
while IFS='|' read -r _ip _pr _p _svc _ver; do
    _it="$_ip $_pr/$_p"
    [ -n "$_svc" ] || _svc="unknown service"
    case "$_pr/$_p" in
        tcp/2375) cc_flag HIGH ports "$_it" "Docker API without TLS: anyone who reaches it is root on that host" ;;
        tcp/23) cc_flag MED ports "$_it" "Telnet: cleartext logins" ;;
        tcp/512|tcp/513|tcp/514) cc_flag MED ports "$_it" "rsh/rlogin/rexec-style cleartext service" ;;
        udp/69) cc_flag MED ports "$_it" "TFTP: no authentication; files can be read by guessing names" ;;
        udp/161) cc_flag MED ports "$_it" "SNMP: check the community strings are not public/private" ;;
        tcp/590[0-9]) cc_flag MED ports "$_it" "VNC remote desktop; check it requires a password" ;;
        tcp/6379) cc_flag MED ports "$_it" "Redis: often has no password" ;;
        tcp/27017) cc_flag MED ports "$_it" "MongoDB: often has no password" ;;
        tcp/9200) cc_flag MED ports "$_it" "Elasticsearch: often has no authentication" ;;
        tcp/11211) cc_flag MED ports "$_it" "memcached: no authentication" ;;
        tcp/1337|tcp/4444|tcp/4445|tcp/5555|tcp/6666|tcp/12345|tcp/31337|tcp/54321) cc_flag MED ports "$_it" "port commonly used by backdoors and reverse shells ($_svc)" ;;
        tcp/3306|tcp/1433|tcp/5432|tcp/1521) cc_flag LOW ports "$_it" "database reachable over the network ($_svc); fine if the scoring engine or a web server needs it" ;;
        tcp/21) cc_flag LOW ports "$_it" "FTP: cleartext logins" ;;
    esac
    # Versions with known backdoors or trivial remote root, common in CCDC
    # images.  The weakness checker (SH-14) will cover many more.
    case "$_ver" in
        *"vsftpd 2.3.4"*) cc_flag HIGH ports "$_it" "vsftpd 2.3.4 has a built-in backdoor (smiley-face login)" ;;
        *"ProFTPD 1.3.3c"*) cc_flag HIGH ports "$_it" "ProFTPD 1.3.3c release was backdoored" ;;
        *"ProFTPD 1.3.5"*) cc_flag HIGH ports "$_it" "ProFTPD 1.3.5 mod_copy lets anyone copy files" ;;
        *UnrealIRCd*) cc_flag HIGH ports "$_it" "UnrealIRCd: the 3.2.8.1 release was backdoored" ;;
        *"Samba smbd 3.0.2"*) cc_flag HIGH ports "$_it" "Samba 3.0.20-3.0.25 allows remote root (usermap_script)" ;;
        *distccd*) cc_flag HIGH ports "$_it" "distccd runs commands for anyone who connects" ;;
        *"Microsoft Windows XP"*|*"Windows Server 2003"*) cc_flag HIGH ports "$_it" "end-of-life Windows ($_ver)" ;;
    esac
    if [ "$PROFILE" = outside ]; then
        case "$_pr/$_p" in tcp/445|tcp/139|tcp/3389|tcp/5985|tcp/5986|tcp/135) cc_flag MED ports "$_it" "Windows admin service ($_svc) is reachable from outside the firewall" ;; esac
    fi
done <"$W/open"

# Host list checks: unknown hosts, missing hosts, scored services.
if [ -s "$W/hl" ]; then
    SC=$(cc_csv_new scored "host,ip,service,port,reachable")
    while IFS='|' read -r _ip _name _os; do
        grep -q "^$_ip|" "$W/hl" || cc_flag MED hosts "$_ip ${_name:-}" "host is up but not on the host list: find out what it is"
    done <"$W/up"
    while IFS='|' read -r _ip _name _scored; do
        _inscope=$(awk -v ip="$_ip" -v specs="$TARGETS" "$AWK_IP"'BEGIN { print intarget(ip, specs) }')
        [ "$_inscope" = 1 ] || continue
        _isup=no; grep -q "^$_ip|" "$W/up" && _isup=yes
        [ "$_isup" = yes ] || cc_flag MED hosts "$_ip $_name" "on the host list but did not answer the scan"
        for _s in $(printf '%s' "$_scored" | tr ';' ' '); do
            _svc=${_s%%:*}; _p=${_s##*:}
            case "$_p" in ''|*[!0-9]*) continue ;; esac
            if grep -q "^$_ip|tcp|$_p|" "$W/open" || grep -q "^$_ip|udp|$_p|" "$W/open"; then
                cc_csv_row "$SC" "$_name" "$_ip" "$_svc" "$_p" yes
            else
                cc_csv_row "$SC" "$_name" "$_ip" "$_svc" "$_p" no
                cc_flag HIGH scored "$_name $_ip $_svc:$_p" "scored service is not reachable from here; check it now (it may only be blocked from this machine)"
            fi
        done
    done <"$W/hl"
    if [ "$PROFILE" = outside ]; then
        # From outside, an open port that is not a scored service on that host
        # is attack surface the red team can see.
        while IFS='|' read -r _ip _pr _p _svc _ver; do
            _sc=$(awk -F'|' -v ip="$_ip" '$1 == ip { print $3 }' "$W/hl")
            case ";$_sc;" in *":$_p;"*) ;; *) cc_flag MED outside "$_ip $_pr/$_p" "reachable from outside but not a scored service on this host ($_svc)" ;; esac
        done <"$W/open"
    fi
fi

# ---- Summary ----------------------------------------------------------------
_nup=$(wc -l <"$W/up" | tr -d ' ')
_nopen=$(wc -l <"$W/open" | tr -d ' ')
_unknown=""
[ -s "$W/hl" ] && _unknown=" ($(awk -F'|' -v hlf="$W/hl" 'BEGIN { while ((getline l < hlf) > 0) { split(l, h, "|"); k[h[1]] = 1 } } !($1 in k) { n++ } END { print n + 0 }' "$W/up") not on the host list)"
{
    printf 'SH-03 Network scan | from %s | %s | profile %s | engine %s\n' "$CC_HOST" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$PROFILE" "$(cat "$W/engine_version" 2>/dev/null)"
    printf 'Targets:%s\n\n' "$TARGETS"
    printf 'Hosts up: %s%s\nOpen ports: %s\n\n' "$_nup" "$_unknown" "$_nopen"
    # One line per host: address, name, open ports with service names.
    awk -F'|' -v upf="$W/up" '
        BEGIN { while ((getline l < upf) > 0) { split(l, u, "|"); name[u[1]] = u[2]; order[++n] = u[1] } }
        { p[$1] = p[$1] (p[$1] == "" ? "" : ", ") $3 ($2 == "udp" ? "/udp" : "") ($4 == "" ? "" : " " $4) }
        END {
            for (i = 1; i <= n && i <= 40; i++) { ip = order[i]; printf "  %-15s %-20s %s\n", ip, substr(name[ip], 1, 20), (p[ip] == "" ? "(no open ports in range)" : p[ip]) }
            if (n > 40) printf "  ... %d more hosts in hosts.csv\n", n - 40
        }' "$W/open"
    if [ -n "$HOSTLIST" ] && [ -n "${SC:-}" ]; then
        _sok=$(grep -c '"yes"$' "$SC"); _sno=$(grep -c '"no"$' "$SC")
        printf '\nScored services: %s reachable, %s NOT reachable\n' "$_sok" "$_sno"
    fi
    printf '\n'
    cc_flag_report "$MAXFLAGS"
    printf '\nAll results: %s\n' "$CC_RUN_DIR"
} >"$CC_RUN_DIR/summary.txt"
cat "$CC_RUN_DIR/summary.txt"
rm -rf "$W"
cc_finish
