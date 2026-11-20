#!/bin/sh
# =============================================================================
# ID:       SH-03
# NAME:     Network scan
# ROLE:     Network  (wave 1)
# KIND:     readonly - sends probes, changes nothing on any host
# VERSION:  2.3.0
#
# PURPOSE
#   Finds every live host and open port on the team's networks.  Asks what
#   to scan and which extras to run (like sqlmap: Enter takes the default),
#   then runs nmap in stages and shows nmap's own output as it goes:
#     1. quick scan    the top N TCP ports (asks how many) plus any extra
#                      ports you name, on every target
#     2. full scan     all 65535 TCP ports on the hosts that are up, or
#                      the ones you pick
#     3. details       on the open ports only: service versions, OS guess,
#                      nmap's default scripts, vuln scripts (safe ones)
#     4. UDP           top 25 UDP ports (root)
#   At the end it flags anything bad (backdoor ports, VULNERABLE script
#   results, known-bad versions, risky services) and prints a summary of
#   hosts, ports and vulns, colour-coded like the Linux enum (SH-05).
#
#   Given the host list (--hosts), it also checks:
#     - Is every scored service reachable?   (HIGH flag if one is not)
#     - Is anything up that is not on the list?
#
# USAGE
#   sh SH-03-network-scan.sh                     asks everything
#   sh SH-03-network-scan.sh --target 10.0.2.0/24 --batch     all defaults
#   Run it from the admin workstation.  Root is not required, but nmap is
#   faster as root, and OS detection and UDP need it.
#
# OPTIONS
#   --target SPEC      what to scan; repeatable.  An address (10.0.2.5), a
#                      network (10.0.2.0/24), a last-octet range
#                      (10.0.2.1-50) or a host name.  Asked if not given
#   --targets-file F   one target per line (# comments allowed)
#   --hosts FILE       host list (config/hosts.example.txt format).
#                      Turns on the host-list and scored-service checks
#   Answers in advance (each skips its question):
#   --quick / --no-quick        top 1000 ports first          (default yes)
#   --full / --no-full          all 65535 ports               (default yes)
#   --services / --no-services  service and version detection (default yes)
#   --scripts / --no-scripts    nmap default scripts (-sC)    (default yes)
#   --vuln / --no-vuln          nmap vuln scripts, safe ones  (default no)
#   --vuln-all                  every vuln script (some can crash a service)
#   --speed N                   1-5: nmap timing -T1..-T5     (default 4)
#   --top-ports N               ports in the quick scan       (default 1000)
#   --extra-ports LIST          also scan these ports on every target
#                               (--no-extra-ports: none, no question)
#   --full-hosts LIST           full scan only these hosts    (default all up)
#   --os / --no-os              OS guess, root only           (default yes)
#   --udp / --no-udp            top 25 UDP ports, root only   (default no)
#   --team-number N    also scan the outside range 10.100.N.0/24 (the team
#                      packet's numbering; asked when not given, Enter skips)
#   --profile NAME     preset answers, no questions:
#                        fast     quick scan + services
#                        full     quick + full + services (+ OS as root)
#                        udp      UDP only
#                        outside  like fast, but does not trust ping (-Pn);
#                                 run it from OUTSIDE the firewall to see
#                                 what the red team sees
#   --ports LIST       scan only these ports (e.g. 22,80,443 or 1-1024)
#                      instead of the quick and full scans
#   --engine NAME      nmap | python | bash | nc   (default: first available,
#                      in that order).  Without nmap there is no version
#                      detection, no scripts, only a banner, and only TCP
#   --no-dns           do not look up host names (faster when DNS is slow)
#   --pn               treat every target as up (for hosts that drop ping)
#   --max-hosts N      refuse to scan more than N addresses without nmap
#                      (default 1024); nmap has no limit
#   --max-flags N      HIGH/MED flags shown in the summary (default 30)
#   --no-color         no colours
#   --batch            no questions: take every default
#   --help             this text plus the common options
#
# OUTPUTS  (under --out, in netscan-N/)
#   output.txt      everything shown on screen, without colour
#   summary.txt     the summary page
#   hosts.txt       ip, name, status, open ports, OS guess
#   roles.txt       what each box looks like: ip, guess (router, Gitea, file
#                   share, domain controller, Windows, RabbitMQ, Home
#                   Assistant, web app), os, why
#   suggested-hosts.txt   host-list rows for config/hosts.txt (copy the right
#                   ones, give them real names)
#   ports.txt       one line per open port with service and version
#   vulns.txt       what the vuln and default scripts found
#   flags.txt       every flag, HIGH first
#   scored.txt      scored services reachable or not   (only with --hosts)
#                   (tables: columns separated by " | "; SH-04 and NW-20
#                   read them.  No CSV.)
#   raw/            nmap's own output for each stage (.nmap, .gnmap, .xml)
#   run.txt         ID, host and time
#
# WHAT IT CHANGES
#   Nothing on any host.  It connects to ports and reads what they say.
#   By default only vuln scripts in nmap's "safe" category are run, so
#   nothing meant to crash or change a service (--vuln-all runs them all).  Scans are visible in logs, which is
#   expected and fine on your own network.
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
#     engine's side; check it from there.
#   - From inside, you see more than the red team does.  Use --profile
#     outside from outside the firewall for their view.
#   - Hosts that drop ping and have no top-1000 port open are missed unless
#     you use --pn (slower, because every address is scanned in full).
#   - The full scan takes minutes per host.  nmap prints progress every
#     minute.  Ctrl-C stops it; nothing is changed either way.
#   - A vuln script that says nothing does not mean "safe".  The vuln list
#     is a pointer, not a verdict.
#   - The fallback engines only check a fixed list of common TCP ports.
#
# DEBUGGING
#   --debug          shows the exact nmap commands
#   raw/*.nmap       nmap's own report for each stage
#   --engine python  forces the fallback, to compare with nmap's results
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

# Ports the fallback engines check (TCP only).  Chosen for competition networks:
# the usual scored services, Windows/AD, databases, remote admin, and ports
# red teams like.
FALLBACK_PORTS="21,22,23,25,53,80,88,110,111,135,139,143,389,443,445,464,465,514,587,593,636,993,995,1080,1433,1521,2049,2222,2375,3000,3268,3306,3389,4444,5000,5432,5601,5672,5900,5985,5986,6379,6667,8000,8080,8081,8123,8443,8888,9000,9090,9200,10000,11211,15672,27017,31337"

usage() {
    cat <<'USAGE'
SH-03 Network scan - live hosts, open ports, services, vulns
  sh SH-03-network-scan.sh                          asks what to scan
  sh SH-03-network-scan.sh --target 10.0.2.0/24 --batch

  --target SPEC        address, network/NN, a.b.c.N-M or name (repeatable)
  --targets-file FILE  one target per line
  --hosts FILE         host list: check scored services and unknown hosts
  --quick / --no-quick        top 1000 ports first          (default yes)
  --full / --no-full          all 65535 ports               (default yes)
  --services / --no-services  service and version detection (default yes)
  --scripts / --no-scripts    nmap default scripts          (default yes)
  --vuln / --no-vuln          nmap vuln scripts (safe ones) (default no)
  --vuln-all                  every vuln script (some can crash a service)
  --speed N                   1 slow/quiet .. 5 fastest     (default 4)
  --top-ports N               ports in the quick scan       (default 1000)
  --extra-ports LIST          also scan these ports         (default none)
  --full-hosts LIST           full scan only these hosts    (default all up)
  --os / --no-os              OS guess, needs root          (default yes)
  --udp / --no-udp            top 25 UDP ports, needs root  (default no)
  --team-number N      also scan the outside range 10.100.N.0/24 (asked; Enter skips)
  --profile NAME       fast | full | udp | outside  (preset answers, no questions)
  --ports LIST         scan only these ports instead of the quick and full scans
  --engine NAME        nmap | python | bash | nc     (default: best available)
  --no-dns             skip host name lookups
  --pn                 treat every target as up
  --max-hosts N        address limit for the fallback engines (default 1024)
  --max-flags N        HIGH/MED flags shown in the summary (default 30)
  --no-color           no colours
  --help               show this text

USAGE
    cc_usage_common
}

# ---- Options ----------------------------------------------------------------
TARGETS=""
TEAMNUM=""
HOSTLIST=""
PROFILE=""
PORTS=""
ENGINE=""
NODNS=0
PN=0
MAXHOSTS=1024
MAXFLAGS=30
COLOR=1
# Answers: Y, N, or empty (ask).
A_QUICK=""; A_FULL=""; A_SVC=""; A_SCRIPTS=""; A_VULN=""; A_OS=""; A_UDP=""; A_VSAFE=""
SPEED=""          # nmap timing 1-5 (-T)
TOP=""            # how many top ports in the quick scan
EXTRA=""; EXTRA_SET=0   # extra ports to always scan
FULLHOSTS=""      # which hosts get the full scan: "all" or addresses

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
        --team-number)  [ $# -ge 2 ] || cc_die 2 "--team-number needs a number"; TEAMNUM=$2; shift 2 ;;
        --profile)      [ $# -ge 2 ] || cc_die 2 "--profile needs a name"; PROFILE=$2; shift 2 ;;
        --ports)        [ $# -ge 2 ] || cc_die 2 "--ports needs a list"; PORTS=$2; shift 2 ;;
        --engine)       [ $# -ge 2 ] || cc_die 2 "--engine needs a name"; ENGINE=$2; shift 2 ;;
        --quick)        A_QUICK=Y; shift ;;     --no-quick)    A_QUICK=N; shift ;;
        --full)         A_FULL=Y; shift ;;      --no-full)     A_FULL=N; shift ;;
        --services)     A_SVC=Y; shift ;;       --no-services) A_SVC=N; shift ;;
        --scripts)      A_SCRIPTS=Y; shift ;;   --no-scripts)  A_SCRIPTS=N; shift ;;
        --vuln)         A_VULN=Y; shift ;;      --no-vuln)     A_VULN=N; shift ;;
        --os)           A_OS=Y; shift ;;        --no-os)       A_OS=N; shift ;;
        --udp)          A_UDP=Y; shift ;;       --no-udp)      A_UDP=N; shift ;;
        --speed)        [ $# -ge 2 ] || cc_die 2 "--speed needs 1-5"; SPEED=$2; shift 2 ;;
        --top-ports)    [ $# -ge 2 ] || cc_die 2 "--top-ports needs a number"; TOP=$2; shift 2 ;;
        --extra-ports)  [ $# -ge 2 ] || cc_die 2 "--extra-ports needs a list"; EXTRA=$2; EXTRA_SET=1; shift 2 ;;
        --no-extra-ports) EXTRA=""; EXTRA_SET=1; shift ;;
        --full-hosts)   [ $# -ge 2 ] || cc_die 2 "--full-hosts needs addresses or all"; FULLHOSTS=$2; shift 2 ;;
        --vuln-all)     A_VULN=Y; A_VSAFE=N; shift ;;
        --no-dns)       NODNS=1; shift ;;
        --pn)           PN=1; shift ;;
        --max-hosts)    [ $# -ge 2 ] || cc_die 2 "--max-hosts needs a number"; MAXHOSTS=$2; shift 2 ;;
        --max-flags)    [ $# -ge 2 ] || cc_die 2 "--max-flags needs a number"; MAXFLAGS=$2; shift 2 ;;
        --no-color|--no-colour) COLOR=0; shift ;;
        --help|-h)      usage; exit 0 ;;
        *)              cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done

case "$PROFILE" in ''|fast|full|udp|outside) ;; *) cc_die 2 "unknown profile '$PROFILE' (fast, full, udp or outside)" ;; esac
case "$MAXHOSTS" in ''|*[!0-9]*) cc_die 2 "--max-hosts needs a whole number" ;; esac
case "$MAXFLAGS" in ''|*[!0-9]*) cc_die 2 "--max-flags needs a whole number" ;; esac
case "$PORTS" in *[!0-9,-]*) cc_die 2 "--ports takes numbers, commas and ranges only (e.g. 22,80,8000-8100)" ;; esac
[ -z "$HOSTLIST" ] || [ -r "$HOSTLIST" ] || cc_die 2 "cannot read host list: $HOSTLIST"
# ok_speed / ok_top / ok_ports VALUE -> true when VALUE is usable.
ok_speed() { case "$1" in [1-5]) return 0 ;; esac; return 1; }
ok_top() { case "$1" in ''|*[!0-9]*) return 1 ;; esac; [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }
ok_ports() { case "$1" in *[!0-9,-]*) return 1 ;; esac; return 0; }
[ -z "$SPEED" ] || ok_speed "$SPEED" || cc_die 2 "--speed takes 1 (slow, quiet) to 5 (fastest)"
[ -z "$TOP" ] || ok_top "$TOP" || cc_die 2 "--top-ports takes a number from 1 to 65535"
ok_ports "$EXTRA" || cc_die 2 "--extra-ports takes numbers, commas and ranges only (e.g. 8080,9000-9100)"
case "$FULLHOSTS" in *[!A-Za-z0-9./:_,\ -]*) cc_die 2 "--full-hosts takes addresses or all" ;; esac
[ "$PROFILE" = outside ] && PN=1

# A profile is a set of answers.  Flags given on top still win.
preset() { eval "[ -n \"\$$1\" ] || $1=$2"; }
case "$PROFILE" in
    fast|outside) preset A_QUICK Y; preset A_FULL N; preset A_SVC Y ;;
    full)         preset A_QUICK Y; preset A_FULL Y; preset A_SVC Y; preset A_OS Y ;;
    udp)          preset A_QUICK N; preset A_FULL N; preset A_UDP Y ;;
esac
if [ -n "$PROFILE" ]; then
    for _v in A_QUICK A_FULL A_SVC A_SCRIPTS A_VULN A_OS A_UDP; do preset "$_v" N; done
    preset SPEED 4; preset TOP 1000; preset A_VSAFE Y; preset FULLHOSTS all; EXTRA_SET=1
fi
# --ports replaces the quick and full scans.
[ -n "$PORTS" ] && { A_QUICK=N; A_FULL=N; }

# install_hint -> the command that installs nmap on this box.
install_hint() {
    if cc_have apt-get; then echo "sudo apt install nmap"
    elif cc_have dnf; then echo "sudo dnf install nmap"
    elif cc_have yum; then echo "sudo yum install nmap"
    elif cc_have zypper; then echo "sudo zypper install nmap"
    elif cc_have apk; then echo "sudo apk add nmap"
    elif cc_have pacman; then echo "sudo pacman -S nmap"
    else echo "install the nmap package (https://nmap.org/download)"
    fi
}

# Pick the engine: the requested one, or the best available.
NMAP_MISSING=0
cc_have nmap || NMAP_MISSING=1
[ "$ENGINE" = nmap ] && [ "$NMAP_MISSING" = 1 ] && cc_die 3 "nmap is not installed on this box. Install it: $(install_hint)"
if [ -z "$ENGINE" ]; then
    if cc_have nmap; then ENGINE=nmap
    elif cc_have python3; then ENGINE=python
    elif cc_have bash && cc_have timeout; then ENGINE=bash
    elif cc_have nc; then ENGINE=nc
    else cc_die 3 "no scanner available. Install nmap: $(install_hint)"
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
IS_ROOT=0
cc_is_root && IS_ROOT=1
if [ "$PROFILE" = udp ] && [ "$IS_ROOT" != 1 ]; then cc_die 3 "UDP scanning needs root (sudo)"; fi

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

# guess_target -> this machine's own network, e.g. 10.0.2.0/24, as the
#   default answer.  Networks bigger than a /22 are cut to the /24 around
#   this machine, so Enter never starts a scan of a /8.
guess_target() {
    _gt=$( (ip -o -4 addr show scope global 2>/dev/null || ip -o -4 addr show 2>/dev/null) | awk '$4 !~ /^127\./ { print $4; exit }')
    [ -n "$_gt" ] || return 0
    awk -v t="$_gt" "$AWK_IP"'BEGIN {
        split(t, m, "/"); bits = m[2] + 0; x = ip2n(m[1]); if (x < 0) exit
        if (bits < 22) bits = 24
        size = pow2(32 - bits); print n2ip(x - x % size) "/" bits }'
}

# ---- Questions (sqlmap style) -------------------------------------------------
# Before the run folder exists, so a question answered wrong costs nothing.
cc_color_init
[ "$COLOR" = 1 ] || { C_RED=""; C_YEL=""; C_GRN=""; C_CYN=""; C_GRY=""; C_OFF=""; }
# Quick check: is nmap here?  Without it the scan is much weaker, and the
# scan questions (speed, ports, versions, scripts, vulns, UDP) are skipped.
if [ "$NMAP_MISSING" = 1 ]; then
    cc_show "$C_YEL" "[!] nmap is not installed on this box, so the scan questions are skipped."
    cc_show "$C_YEL" "    Without it: $(printf '%s' "$FALLBACK_PORTS" | tr ',' '\n' | grep -c .) common TCP ports only, a banner instead of a version, no scripts, no vulns, no UDP."
    cc_show "$C_YEL" "    Install it: $(install_hint)"
    cc_ask "Keep going with the $ENGINE scan anyway?" Y "yes, scan with $ENGINE" "no, stop (install nmap first)" || { cc_show "" "Install nmap and run again: $(install_hint)"; exit 3; }
elif [ "$ENGINE" = nmap ]; then
    cc_show "$C_GRN" "[ok] nmap found: $(nmap --version 2>/dev/null | head -n 1)"
fi
case "$TEAMNUM" in ''|none) ;; *[!0-9]*) cc_die 2 "--team-number: a number from 1 to 254" ;; *) [ "$TEAMNUM" -ge 1 ] && [ "$TEAMNUM" -le 254 ] || cc_die 2 "--team-number: a number from 1 to 254" ;; esac
if [ -z "$TARGETS" ]; then
    _can=0; _cc_can_ask && _can=1
    if [ "$_can" = 0 ] && { [ -z "$TEAMNUM" ] || [ "$TEAMNUM" = none ]; }; then cc_die 2 "nothing to scan: give --target, --targets-file or --team-number (try --help)"; fi
    if [ "$_can" = 1 ]; then
        cc_ask_text "What should I scan? (the inside network this box is on is the default)" "$(guess_target)" "one host 10.0.2.5, a range 10.0.2.1-50 or a subnet 10.0.2.0/24; several separated by spaces"
        for _t in $(printf '%s' "$CC_ANSWER" | tr ',' ' '); do add_target "$_t"; done
    fi
fi
# The outside range is 10.100.TEAM.0/24 (the team packet's numbering):
# asked, so nobody needs to know it before the day.
if [ -z "$TEAMNUM" ] && _cc_can_ask; then
    cc_ask_text "Your team number? It adds the outside range 10.100.N.0/24 to the scan" "" "a number from 1 to 254 (Enter = skip the outside range)"
    case "$CC_ANSWER" in ''|*[!0-9]*) [ -n "$CC_ANSWER" ] && cc_show "$C_YEL" "[*] '$CC_ANSWER' is not a team number: the outside range is skipped" ;;
        *) [ "$CC_ANSWER" -ge 1 ] && [ "$CC_ANSWER" -le 254 ] && TEAMNUM=$CC_ANSWER ;; esac
fi
case "$TEAMNUM" in ''|none) ;; *) case " $TARGETS " in *" 10.100.$TEAMNUM.0/24 "*) ;; *) add_target "10.100.$TEAMNUM.0/24"; cc_show "$C_GRN" "[ok] team $TEAMNUM: the outside range 10.100.$TEAMNUM.0/24 is scanned too" ;; esac ;; esac
[ -n "$TARGETS" ] || cc_die 2 "nothing to scan"

# ask VAR QUESTION DEFAULT [YES-MEANS] [NO-MEANS] -> fill VAR with Y or N
#   unless a flag already did.
ask() {
    eval "_ak=\$$1"
    [ -n "$_ak" ] && return 0
    if cc_ask "$2" "$3" "${4:-yes}" "${5:-no}"; then eval "$1=Y"; else eval "$1=N"; fi
}
# ask_val VAR CHECK QUESTION DEFAULT -> fill VAR with a typed answer that
#   passes CHECK (ok_speed, ok_top, ok_ports), unless a flag already did.
#   Asks again on a bad answer, at most three times.
ask_val() {
    eval "_av=\$$1"
    [ -n "$_av" ] && return 0
    _av_n=0
    while :; do
        cc_ask_text "$3" "$4" "${5:-}"
        if "$2" "$CC_ANSWER"; then eval "$1=\$CC_ANSWER"; return 0; fi
        _av_n=$((_av_n + 1))
        [ "$_av_n" -lt 3 ] && _cc_can_ask || cc_die 2 "not a usable answer: '$CC_ANSWER'"
        printf '    not a usable answer, try again\n' >/dev/tty
    done
}
if [ "$ENGINE" = nmap ]; then
    ask_val SPEED ok_speed "How aggressive?" 4 "1-2 slow and quiet, 3 normal, 4 fast (good on a LAN), 5 fastest (can miss ports)"
    ask A_QUICK   "Quick scan of the top ports first?" Y "yes, quick scan first" "no, skip it"
    [ "$A_QUICK" = Y ] && ask_val TOP ok_top "How many top ports in the quick scan?" 1000 "a number: 100 is very fast, 1000 is nmap's normal"
    if [ "$EXTRA_SET" = 0 ] && [ -z "$PORTS" ]; then
        cc_ask_text "Any other ports to always scan?" "" "ports and ranges separated by commas, like 8080,9000-9100"
        ok_ports "$CC_ANSWER" || cc_die 2 "not a port list: '$CC_ANSWER' (use numbers, commas and ranges)"
        EXTRA=$CC_ANSWER
    fi
    ask A_FULL    "Full scan of all 65535 ports on the hosts that are up?" Y "yes, full scan (slow: minutes per host)" "no, quick scan only"
    ask A_SVC     "Find the service and version behind each open port?" Y "yes, find them" "no, ports only"
    ask A_SCRIPTS "Run nmap's default scripts on the open ports (anonymous FTP, SMB signing, ...)?" Y "yes, run them" "no, skip them"
    ask A_VULN    "Run nmap's vuln scripts on the open ports?" N "yes, run them (adds a few minutes)" "no, skip them"
    [ "$A_VULN" = Y ] && ask A_VSAFE "Only the safe vuln scripts?" Y "yes, safe ones only" "no, every vuln script (some can crash a service)"
    if [ "$IS_ROOT" = 1 ]; then
        ask A_OS  "Guess each host's operating system?" Y "yes, guess it" "no, skip it"
        ask A_UDP "Scan the top 25 UDP ports too? (DNS, SNMP, TFTP, ...)" N "yes, scan UDP too" "no, TCP only"
    else
        [ "$A_OS" = Y ] && cc_warn "OS detection needs root: skipped"
        [ "$A_UDP" = Y ] && cc_warn "UDP scanning needs root: skipped"
        A_OS=N; A_UDP=N
    fi
    [ "$A_QUICK" = N ] && [ "$A_FULL" = N ] && [ "$A_UDP" = N ] && [ -z "$PORTS" ] && { cc_warn "no port scan picked: doing the quick scan"; A_QUICK=Y; }
else
    case "$A_SVC$A_SCRIPTS$A_VULN$A_OS$A_UDP" in *Y*) cc_warn "the $ENGINE engine has no services, scripts, vuln, OS or UDP scans (they need nmap): skipped" ;; esac
    A_SVC=N; A_SCRIPTS=N; A_VULN=N; A_OS=N; A_UDP=N
fi

[ -n "$SPEED" ] || SPEED=4
[ -n "$TOP" ] || TOP=1000
[ -n "$A_VSAFE" ] || A_VSAFE=Y
# Extra ports join --ports, or the fallback engines' list.
if [ -n "$EXTRA" ] && { [ -n "$PORTS" ] || [ "$ENGINE" != nmap ]; }; then
    PORTS="${PORTS:-$FALLBACK_PORTS},$EXTRA"; EXTRA=""
fi

# ---- Start ------------------------------------------------------------------
# shellcheck disable=SC2034  # read by the library: tables as .txt, no CSV
CC_TABLES=1
cc_init "SH-03" "Network scan" readonly
cc_use_numbered_dir netscan
W="$CC_RUN_DIR/.work"
mkdir -p "$W" || cc_die 3 "cannot create $W"
RAW="$CC_RUN_DIR/raw"

# Live output goes to fd 3 (a copy of stdout taken here); output.txt gets
# the same lines without colour.
exec 3>&1
OUTF="$CC_RUN_DIR/output.txt"
grep -v '\[NOTE\]\|\[DEBUG\]' "$CC_LOG" >"$OUTF" 2>/dev/null || : >"$OUTF"
# Read by the library's log functions.
# shellcheck disable=SC2034
CC_TEE=$OUTF
show() {
    printf '%s%s%s\n' "$1" "$2" "$C_OFF" >&3
    printf '%s\n' "$2" >>"$OUTF"
}
yn() { [ "$1" = Y ] && echo yes || echo no; }
SCANS="speed $SPEED"
[ "$A_QUICK" = Y ] && SCANS="$SCANS, quick (top $TOP)"
[ -n "$EXTRA" ] && SCANS="$SCANS, extra ports $EXTRA"
[ "$A_FULL" = Y ] && SCANS="$SCANS, full (all 65535)"
[ -n "$PORTS" ] && SCANS="$SCANS, ports $PORTS"
[ "$A_SVC" = Y ] && SCANS="$SCANS, services"
[ "$A_SCRIPTS" = Y ] && SCANS="$SCANS, scripts"
[ "$A_VULN" = Y ] && { [ "$A_VSAFE" = Y ] && SCANS="$SCANS, vuln (safe)" || SCANS="$SCANS, vuln (all)"; }
[ "$A_OS" = Y ] && SCANS="$SCANS, OS"
[ "$A_UDP" = Y ] && SCANS="$SCANS, UDP"
[ "$ENGINE" = nmap ] || SCANS=", $ENGINE connect scan of ${PORTS:-common ports}"
SCANS=${SCANS#, }
show "$C_CYN" "SH-03 Network scan | from $CC_HOST | engine $ENGINE | results in $CC_RUN_DIR"
show "$C_CYN" "Targets:$TARGETS"
show "$C_CYN" "Scans: $SCANS"
show "" "Legend: ${C_RED}[!] FIX${C_OFF} look now (HIGH)   ${C_YEL}[*] LOOK${C_OFF} look soon (MED)   ${C_GRN}green${C_OFF} open port"
cc_note "targets:$TARGETS | engine $ENGINE | scans: $SCANS"

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
        2222) echo ssh-alt ;; 5672) echo amqp ;; 15672) echo rabbitmq-mgmt ;; 8123) echo home-assistant ;;
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

STAGE_N=0
STAGE_TOTAL=0
# stage TITLE -> print a linpeas-style heading for the next scan stage.
stage() {
    STAGE_N=$((STAGE_N + 1))
    show "" ""
    show "$C_CYN" "==========[ $STAGE_N/$STAGE_TOTAL  $1 ]=========="
}

# nmap_run NAME ARG... -> run nmap with its normal output shown live (open
#   ports green, VULNERABLE red, host headers cyan) and saved in output.txt;
#   all three nmap formats go to raw/NAME.*.
nmap_run() {
    _nr=$1; shift
    set -- "-T$SPEED" --open -oA "$RAW/$_nr" "$@"
    [ "$NODNS" = 1 ] && set -- -n "$@"
    cc_debug "running: nmap $*"
    show "$C_GRY" "\$ nmap $*"
    # Service fingerprints (SF: lines) are long hex dumps; they stay in
    # raw/NAME.nmap but are cut from the screen and output.txt.
    nmap "$@" 2>&1 | awk '
        /^SF[-:]|^=+NEXT SERVICE FINGERPRINT|^[0-9]+ services? unrecognized|^If you know the service/ { if (!cut++) print "(service fingerprints cut here; they are in the raw/*.nmap files)"; fflush(); next }
        { print; fflush() }' | tee -a "$OUTF" | awk -v R="$C_RED" -v G="$C_GRN" -v C="$C_CYN" -v D="$C_GRY" -v O="$C_OFF" '
        /NOT VULNERABLE/                { print; fflush(); next }
        /VULNERABLE/                    { print R $0 O; fflush(); next }
        /^[0-9]+\/(tcp|udp) +open/      { print G $0 O; fflush(); next }
        /^Nmap scan report for/         { print C $0 O; fflush(); next }
        /^Stats:|Timing:|^Nmap done/    { print D $0 O; fflush(); next }
                                        { print; fflush() }' >&3
    [ -s "$RAW/$_nr.gnmap" ] || cc_die 1 "nmap produced no results (see $OUTF); common causes: bad target, no permission for this scan type"
}

# up_hosts GNMAP -> addresses nmap saw as up, one per line.
up_hosts() { awk '/^Host: .*Status: Up/ { print $2 }' "$@" | sort -u; }
# open_list GNMAP PROTO -> host addresses with an open PROTO port, and the
#   port list "22,80,443" across them (written to $W/hosts_open, $W/ports_open).
open_list() {
    awk -F'\t' -v pr="$2" -v hf="$W/hosts_open" -v pf="$W/ports_open" '
        /^Host: / {
            split($1, h, " ")
            for (i = 2; i <= NF; i++) {
                if ($i !~ /^Ports: /) continue
                s = $i; sub(/^Ports: /, "", s)
                while (match(s, /^[0-9]+\/[^\/]*\/[^\/]*\/[^\/]*\/[^\/]*\/[^\/]*\/[^\/]*\//)) {
                    e = substr(s, 1, RLENGTH); s = substr(s, RLENGTH + 1); sub(/^, /, "", s)
                    split(e, f, "/")
                    if (f[2] == "open" && f[3] == pr) { hs[h[2]] = 1; ps[f[1] + 0] = 1 }
                }
            }
        }
        END {
            for (x in hs) print x > hf
            # in number order ("for in" order differs between awks)
            n = 0; for (p in ps) { v = p + 0; for (j = n; j > 0 && o[j] > v; j--) o[j + 1] = o[j]; o[j + 1] = v; n++ }
            s = ""; for (j = 1; j <= n; j++) s = s (s == "" ? "" : ",") o[j]
            print s > pf
        }' "$1"
    touch "$W/hosts_open"
}

run_nmap() {
    _det=0
    { [ "$A_SVC" = Y ] || [ "$A_SCRIPTS" = Y ] || [ "$A_VULN" = Y ] || [ "$A_OS" = Y ]; } && _det=1
    STAGE_TOTAL=0
    [ "$A_QUICK" = Y ] && STAGE_TOTAL=$((STAGE_TOTAL + 1))
    [ "$A_FULL" = Y ] && STAGE_TOTAL=$((STAGE_TOTAL + 1))
    [ -n "$PORTS" ] && STAGE_TOTAL=$((STAGE_TOTAL + 1))
    [ -n "$EXTRA" ] && STAGE_TOTAL=$((STAGE_TOTAL + 1))
    [ "$_det" = 1 ] && STAGE_TOTAL=$((STAGE_TOTAL + 1))
    [ "$A_UDP" = Y ] && STAGE_TOTAL=$((STAGE_TOTAL + 1))
    _pn=""; [ "$PN" = 1 ] && _pn=-Pn
    # TARGETS is split into separate arguments on purpose.
    # shellcheck disable=SC2086
    set -- $TARGETS
    : >"$W/up_targets"
    _have_up=0
    if [ "$A_QUICK" = Y ]; then
        stage "quick scan: top $TOP TCP ports"
        nmap_run 1-quick $_pn --top-ports "$TOP" "$@"
        up_hosts "$RAW/1-quick.gnmap" >"$W/up_targets"; _have_up=1
        show "$C_GRN" "  $(grep -c . "$W/up_targets") host(s) up"
    fi
    if [ -n "$PORTS" ]; then
        stage "port scan: $PORTS"
        nmap_run 1-ports $_pn -p "$PORTS" "$@"
        up_hosts "$RAW/1-ports.gnmap" >"$W/up_targets"; _have_up=1
    fi
    if [ -n "$EXTRA" ]; then
        stage "extra ports: $EXTRA"
        nmap_run 1-extra $_pn -p "$EXTRA" "$@"
        { cat "$W/up_targets"; up_hosts "$RAW/1-extra.gnmap"; } | sort -u >"$W/up2"; mv "$W/up2" "$W/up_targets"; _have_up=1
    fi
    if [ "$A_FULL" = Y ]; then
        stage "full scan: all 65535 TCP ports"
        if [ "$_have_up" = 1 ]; then
            # Which hosts: all that answered, or the ones named.
            if [ -z "$FULLHOSTS" ] && [ "$(grep -c . "$W/up_targets")" -gt 1 ]; then
                show "$C_GRY" "  up: $(tr '\n' ' ' <"$W/up_targets")"
                cc_ask_text "Full scan which hosts?" all "all, or addresses separated by spaces"
                FULLHOSTS=$CC_ANSWER
            fi
            case "$FULLHOSTS" in
                ''|all|ALL|All) ;;
                *) : >"$W/up_targets"
                   for _h in $(printf '%s' "$FULLHOSTS" | tr ',' ' '); do
                       case "$_h" in -*|*[!A-Za-z0-9./:_-]*) cc_warn "not an address, skipped: $_h"; continue ;; esac
                       printf '%s\n' "$_h" >>"$W/up_targets"
                   done ;;
            esac
            if [ -s "$W/up_targets" ]; then
                show "$C_GRY" "  on $(grep -c . "$W/up_targets") host(s); takes minutes per host, progress every minute"
                # shellcheck disable=SC2046
                nmap_run 2-full -Pn -p- --stats-every 60s $(cat "$W/up_targets")
            else
                show "$C_YEL" "  no hosts up: skipped (try --pn if the hosts drop ping)"
            fi
        else
            show "$C_GRY" "  takes minutes per host, progress every minute"
            nmap_run 2-full $_pn -p- --stats-every 60s "$@"
            up_hosts "$RAW/2-full.gnmap" >"$W/up_targets"; _have_up=1
        fi
    fi
    # Details only on the open ports found so far: much faster than -sV -p-.
    if [ "$_det" = 1 ]; then
        stage "details on the open ports: $(echo "$SCANS" | tr ',' '\n' | grep -E 'services|scripts|vuln|OS' | tr -d ' ' | tr '\n' ' ')"
        cat "$RAW"/1-*.gnmap "$RAW"/2-*.gnmap 2>/dev/null >"$W/all.gnmap"
        open_list "$W/all.gnmap" tcp
        _pl=$(cat "$W/ports_open")
        if [ -s "$W/hosts_open" ] && [ -n "$_pl" ]; then
            set -- -Pn -p "$_pl"
            [ "$A_SVC" = Y ] && set -- "$@" -sV
            [ "$A_OS" = Y ] && set -- "$@" -O --osscan-limit
            # By default only vuln scripts nmap also marks "safe": nothing
            # meant to crash or change a service.  --vuln-all (or "no" to the
            # question) runs every vuln script.
            _vs="vuln and safe"; [ "$A_VSAFE" = N ] && _vs=vuln
            if [ "$A_SCRIPTS" = Y ] && [ "$A_VULN" = Y ]; then set -- "$@" --script "default or ($_vs)"
            elif [ "$A_SCRIPTS" = Y ]; then set -- "$@" -sC
            elif [ "$A_VULN" = Y ]; then set -- "$@" --script "$_vs"
            fi
            [ "$A_VULN" = Y ] && show "$C_GRY" "  vuln scripts can take a few minutes per host"
            # shellcheck disable=SC2046
            nmap_run 3-details "$@" $(sort "$W/hosts_open")
        else
            show "$C_YEL" "  no open TCP ports found: skipped"
        fi
    fi
    # shellcheck disable=SC2086
    set -- $TARGETS
    if [ "$A_UDP" = Y ]; then
        stage "UDP scan: top 25 ports"
        if [ "$_have_up" = 1 ]; then
            # shellcheck disable=SC2046
            [ -s "$W/up_targets" ] && nmap_run 4-udp -Pn -sU -sV --version-light --top-ports 25 $(cat "$W/up_targets")
            [ -s "$W/up_targets" ] || show "$C_YEL" "  no hosts up: skipped"
        else
            nmap_run 4-udp $_pn -sU -sV --version-light --top-ports 25 "$@"
        fi
    fi
    nmap --version 2>/dev/null | head -n 1 >"$W/engine_version"

    # Merge every stage.  Grepable format, one host per line, tab-separated:
    #   Host: 10.0.2.5 (web01)<TAB>Ports: 22/open/tcp//ssh//OpenSSH 8.9p1/, ...<TAB>OS: Linux
    # Each port entry is exactly seven '/'-separated fields.  Versions can
    # contain commas, so entries are cut by matching that shape.  Later
    # stages (details) replace the service name and version of earlier ones.
    awk -F'\t' -v upf="$W/up" -v openf="$W/open" '
        /^Host: / {
            split($1, h, " "); ip = h[2]; name = $1; sub(/^Host: [^ ]* \(/, "", name); sub(/\)$/, "", name)
            if (!(ip in nm) || name != "") nm[ip] = name
            for (i = 2; i <= NF; i++) if ($i ~ /^OS: /) { o = $i; sub(/^OS: /, "", o); os[ip] = o }
            if (!(ip in seen)) { seen[ip] = 1; order[++n] = ip }
            for (i = 2; i <= NF; i++) {
                if ($i !~ /^Ports: /) continue
                s = $i; sub(/^Ports: /, "", s)
                while (match(s, /^[0-9]+\/[^\/]*\/[^\/]*\/[^\/]*\/[^\/]*\/[^\/]*\/[^\/]*\//)) {
                    e = substr(s, 1, RLENGTH); s = substr(s, RLENGTH + 1); sub(/^, /, "", s)
                    split(e, f, "/")
                    # "open|filtered" (UDP that did not answer) is not open.
                    if (f[2] != "open") continue
                    k = ip "|" f[3] "|" f[1]
                    if (!(k in svc)) { korder[++m] = k; svc[k] = ""; ver[k] = "" }
                    if (f[5] != "") svc[k] = f[5]
                    v = f[7]; gsub(/\|/, "/", v); if (v != "") ver[k] = v
                }
            }
        }
        END {
            for (i = 1; i <= n; i++) print order[i] "|" nm[order[i]] "|" os[order[i]] > upf
            for (i = 1; i <= m; i++) print korder[i] "|" svc[korder[i]] "|" ver[korder[i]] > openf
        }' "$RAW"/*.gnmap
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

# finish_fallback -> turn $W/hits (ip|port|banner) into $W/up and $W/open,
#   and show the open ports the way nmap would.  A host counts as up when
#   any port answered; there is no ping, because ping is often missing or
#   blocked.
finish_fallback() {
    : >"$W/open"
    sort -t'|' -k1,1 -k2,2n "$W/hits" -o "$W/hits"
    while IFS='|' read -r _ip _p _ban; do
        printf '%s|tcp|%s|%s|%s\n' "$_ip" "$_p" "$(port_name "$_p")" "$_ban" >>"$W/open"
    done <"$W/hits"
    : >"$W/up"
    for _ip in $(cut -d'|' -f1 "$W/hits" | sort -u); do
        _name=""
        [ "$NODNS" = 1 ] || _name=$(getent hosts "$_ip" 2>/dev/null | awk '{ print $2; exit }')
        printf '%s|%s|\n' "$_ip" "$_name" >>"$W/up"
        show "$C_CYN" "Scan report for $_ip${_name:+ ($_name)}"
        while IFS='|' read -r _i _pr _p _svc _ver; do
            [ "$_i" = "$_ip" ] && show "$C_GRN" "$(printf '%-10s open  %-14s %s' "$_p/$_pr" "$_svc" "$_ver")"
        done <"$W/open"
    done
    cp "$W/hits" "$RAW/$ENGINE-hits.txt"
}

case "$ENGINE" in
    nmap)    run_nmap ;;
    python)  STAGE_TOTAL=1; stage "connect scan ($ENGINE)"; run_python ;;
    bash|nc) STAGE_TOTAL=1; stage "connect scan ($ENGINE)"; run_shell_engine ;;
esac
sort -t'|' -k1,1 -u "$W/up" -o "$W/up"
sort -t'|' -k1,1 -k2,2 -k3,3n "$W/open" -o "$W/open"

# ---- Script results (vulns and other findings) -----------------------------
# Read from nmap's XML, where each script's output is one attribute on one
# line.  Writes $W/vulns as ip|proto|port|script|state|title|ids:
#   - any script that reports "State: VULNERABLE" or "LIKELY VULNERABLE"
#   - vulners: the known CVEs for the detected version, with the worst score
#   - a few default-script results that matter for defence (anonymous FTP,
#     empty database passwords, SMB signing off)
: >"$W/vulns"
for _x in "$RAW"/3-details.xml "$RAW"/4-udp.xml; do
    [ -f "$_x" ] || continue
    awk -v outf="$W/vulns" '
        function dec(s) { gsub(/&#xa;/, "\n", s); gsub(/&#x9;/, " ", s); gsub(/&quot;/, "\"", s); gsub(/&apos;/, "\047", s); gsub(/&lt;/, "<", s); gsub(/&gt;/, ">", s); gsub(/&amp;/, "\\&", s); return s }    # awk: posix-ok
        function attr(tag, name) { if (match(tag, " " name "=\"[^\"]*\"")) return substr(tag, RSTART + length(name) + 3, RLENGTH - length(name) - 4); return "" }    # awk: posix-ok
        function clean(s) { gsub(/[|\r]/, "/", s); gsub(/\n/, " ", s); gsub(/  +/, " ", s); sub(/^ /, "", s); sub(/ $/, "", s); return s }    # awk: posix-ok
        function rec(st, title, ids) { print ip "|" (port == "" ? "host" : proto) "|" (port == "" ? "-" : port) "|" id "|" st "|" clean(title) "|" ids > outf }    # awk: posix-ok
        # One tag at a time: nmap puts several tags on one line.  Attribute
        # values never hold a raw ">" (nmap writes &gt;).
        {
            s = $0
            while (match(s, /<[^>]*>/)) {
                tag = substr(s, RSTART, RLENGTH); s = substr(s, RSTART + RLENGTH)
                if (tag ~ /^<host[ >]/)          { ip = ""; port = ""; proto = "" }
                else if (tag ~ /^<address /)     { if (tag ~ /addrtype="ipv4"/ || (ip == "" && tag ~ /addrtype="ipv6"/)) ip = attr(tag, "addr") }
                else if (tag ~ /^<port /)        { proto = attr(tag, "protocol"); port = attr(tag, "portid") }
                else if (tag ~ /^<\/port>/)      { port = "" }
                else if (tag ~ /^<hostscript>/)  { port = "" }
                else if (tag ~ /^<script /)      script(attr(tag, "id"), dec(attr(tag, "output")))
            }
        }
        function script(sid, out,   ids, s2, c, tmp, n, L, i, w, worst, cnt, st, title) {    # awk: posix-ok
            id = sid; ids = ""; s2 = out
            while (match(s2, /CVE-[0-9]+-[0-9]+/)) { c = substr(s2, RSTART, RLENGTH); if (index(" " ids " ", " " c " ") == 0 && split(ids, tmp, " ") < 5) ids = ids (ids == "" ? "" : " ") c; s2 = substr(s2, RSTART + RLENGTH) }
            if (id == "vulners") {
                n = split(out, L, "\n"); worst = 0; cnt = 0
                for (i = 1; i <= n; i++) if (split(L[i], w, " ") >= 2 && w[2] ~ /^[0-9]+(\.[0-9]+)?$/) { cnt++; if (w[2] + 0 > worst) worst = w[2] + 0 }
                if (cnt > 0) rec("known CVEs", cnt " known vulnerabilities for this version, worst score " worst, ids)
                return
            }
            if (out ~ /State: (LIKELY )?VULNERABLE/) {
                st = (out ~ /State: LIKELY VULNERABLE/) ? "LIKELY VULNERABLE" : "VULNERABLE"
                n = split(out, L, "\n"); title = id
                for (i = 1; i < n; i++) if (L[i] ~ /VULNERABLE:[ ]*$/) { title = L[i + 1]; break }
                rec(st, title, ids); return
            }
            if (id == "ftp-anon" && out ~ /Anonymous FTP login allowed/) rec("finding", "anonymous FTP login allowed", "")
            else if (id ~ /empty-password/ && out ~ /[Ee]mpty password|has empty password/) rec("finding", "account with an empty password: " out, "")
            else if (id == "smb2-security-mode" && out ~ /not required/) rec("finding", "SMB signing not required", "")
            else if (id == "smb-security-mode" && out ~ /message_signing: disabled/) rec("finding", "SMB signing disabled", "")
            else if (id == "http-methods" && out ~ /[Rr]isky methods:.*(PUT|DELETE)/) rec("finding", "web server allows PUT or DELETE", "")
        }' "$_x"
done

# ---- Host list --------------------------------------------------------------
# Read the host list into $W/hl as "ip|name|scored_services" (scored
# services look like http:80;dns:53).
: >"$W/hl"
if [ -n "$HOSTLIST" ]; then
    cc_hosts_rows "$HOSTLIST" | awk -F'|' '$2 != "" { print $2 "|" $1 "|" $8 }' >"$W/hl"
    cc_info "host list: $(wc -l <"$W/hl" | tr -d ' ') host(s) from $HOSTLIST"
fi

# ---- Tables ---------------------------------------------------------------------
HC=$(cc_table_new hosts ip hostname status open_tcp open_udp os_guess in_host_list host_list_name)
PC=$(cc_table_new ports ip hostname proto port state service version)
VC=$(cc_table_new vulns ip hostname proto port script state title ids)
awk -F'|' -v upf="$W/up" -v hlf="$W/hl" -v hc="$HC" -v pc="$PC" -v hashl="$( [ -s "$W/hl" ] && echo 1 || echo 0 )" '
    BEGIN {
        while ((getline l < upf) > 0) { split(l, u, "|"); name[u[1]] = u[2]; os[u[1]] = u[3]; order[++n] = u[1] }
        while ((getline l < hlf) > 0) { split(l, h, "|"); hl[h[1]] = h[2] }
    }
    { if ($2 == "tcp") t[$1] = t[$1] (t[$1] == "" ? "" : " ") $3; else ud[$1] = ud[$1] (ud[$1] == "" ? "" : " ") $3
      print $1 " | " name[$1] " | " $2 " | " $3 " | open | " $4 " | " $5 >> pc }
    END {
        for (i = 1; i <= n; i++) {
            ip = order[i]
            inl = hashl ? ((ip in hl) ? "yes" : "no") : ""
            print ip " | " name[ip] " | up | " t[ip] " | " ud[ip] " | " os[ip] " | " inl " | " hl[ip] >> hc
        }
    }' "$W/open"
awk -F'|' -v upf="$W/up" -v vc="$VC" '
    BEGIN { while ((getline l < upf) > 0) { split(l, u, "|"); name[u[1]] = u[2] } }
    { print $1 " | " name[$1] " | " $2 " | " $3 " | " $4 " | " $5 " | " $6 " | " $7 >> vc }' "$W/vulns"

# ---- Flags ------------------------------------------------------------------
show "" ""
show "$C_CYN" "==========[ checks: what looks bad ]=========="
# flag SEVERITY SECTION ITEM DETAIL -> cc_flag, and shown live.
flag() {
    cc_flag "$1" "$2" "$3" "$4"
    case "$1" in
        HIGH) show "$C_RED" "  [!] FIX   $3: $4" ;;
        MED)  show "$C_YEL" "  [*] LOOK  $3: $4" ;;
    esac
    return 0
}
# Checks by port and by version banner.  Flags are pointers: a database port
# open on the database server may be exactly what the scoring engine needs.
while IFS='|' read -r _ip _pr _p _svc _ver; do
    _it="$_ip $_pr/$_p"
    [ -n "$_svc" ] || _svc="unknown service"
    case "$_pr/$_p" in
        tcp/2375) flag HIGH ports "$_it" "Docker API without TLS: anyone who reaches it is root on that host" ;;
        tcp/23) flag MED ports "$_it" "Telnet: cleartext logins" ;;
        tcp/512|tcp/513|tcp/514) flag MED ports "$_it" "rsh/rlogin/rexec-style cleartext service" ;;
        udp/69) flag MED ports "$_it" "TFTP: no authentication; files can be read by guessing names" ;;
        udp/161) flag MED ports "$_it" "SNMP: check the community strings are not public/private" ;;
        tcp/590[0-9]) flag MED ports "$_it" "VNC remote desktop; check it requires a password" ;;
        tcp/6379) flag MED ports "$_it" "Redis: often has no password" ;;
        tcp/27017) flag MED ports "$_it" "MongoDB: often has no password" ;;
        tcp/9200) flag MED ports "$_it" "Elasticsearch: often has no authentication" ;;
        tcp/11211) flag MED ports "$_it" "memcached: no authentication" ;;
        tcp/1337|tcp/4444|tcp/4445|tcp/5555|tcp/6666|tcp/12345|tcp/31337|tcp/54321) flag MED ports "$_it" "port commonly used by backdoors and reverse shells ($_svc)" ;;
        tcp/3306|tcp/1433|tcp/5432|tcp/1521) flag LOW ports "$_it" "database reachable over the network ($_svc); fine if the scoring engine or a web server needs it" ;;
        tcp/21) flag LOW ports "$_it" "FTP: cleartext logins" ;;
    esac
    # Versions with known backdoors or trivial remote root, common in competitions
    # images.
    case "$_ver" in
        *"vsftpd 2.3.4"*) flag HIGH ports "$_it" "vsftpd 2.3.4 has a known backdoor: replace it" ;;
        *"ProFTPD 1.3.3c"*) flag HIGH ports "$_it" "ProFTPD 1.3.3c release was backdoored" ;;
        *"ProFTPD 1.3.5"*) flag HIGH ports "$_it" "ProFTPD 1.3.5 mod_copy lets anyone copy files" ;;
        *UnrealIRCd*) flag HIGH ports "$_it" "UnrealIRCd: the 3.2.8.1 release was backdoored" ;;
        *"Samba smbd 3.0.2"*) flag HIGH ports "$_it" "Samba 3.0.20-3.0.25 allows remote root" ;;
        *distccd*) flag HIGH ports "$_it" "distccd runs commands for anyone who connects" ;;
        *"Microsoft Windows XP"*|*"Windows Server 2003"*) flag HIGH ports "$_it" "end-of-life Windows ($_ver)" ;;
    esac
    # A shell prompt or a shell's error text where a service should be.
    case "$_ver" in
        *"sh-"[0-9]*"$"*|*"bash: "*|*"/bin/sh: "*|*"command not found"*) flag HIGH ports "$_it" "answers like a shell, not a service: likely a bind shell" ;;
    esac
    if [ "$PROFILE" = outside ]; then
        case "$_pr/$_p" in tcp/445|tcp/139|tcp/3389|tcp/5985|tcp/5986|tcp/135) flag MED ports "$_it" "Windows admin service ($_svc) is reachable from outside the firewall" ;; esac
    fi
done <"$W/open"

# Script results.
while IFS='|' read -r _ip _pr _p _id _st _title _ids; do
    _it="$_ip $_pr/$_p"; [ "$_pr" = host ] && _it=$_ip
    case "$_st" in
        VULNERABLE)          flag HIGH vulns "$_it" "$_id says VULNERABLE: $_title${_ids:+ ($_ids)}" ;;
        "LIKELY VULNERABLE") flag MED vulns "$_it" "$_id says LIKELY VULNERABLE: $_title${_ids:+ ($_ids)}" ;;
        "known CVEs")
            _w=$(printf '%s' "$_title" | sed 's/.*worst score //')
            _wi=${_w%%.*}; case "$_wi" in ''|*[!0-9]*) _wi=0 ;; esac
            if [ "$_wi" -ge 9 ]; then flag HIGH vulns "$_it" "$_title: patch or update it${_ids:+ ($_ids)}"
            elif [ "$_wi" -ge 7 ]; then flag MED vulns "$_it" "$_title${_ids:+ ($_ids)}"
            else flag LOW vulns "$_it" "$_title"
            fi ;;
        finding)
            case "$_title" in
                *"empty password"*|"anonymous FTP"*) flag HIGH vulns "$_it" "$_title ($_id)" ;;
                *"PUT or DELETE"*) flag MED vulns "$_it" "$_title ($_id)" ;;
                *) flag LOW vulns "$_it" "$_title ($_id)" ;;
            esac ;;
    esac
done <"$W/vulns"

# Host list checks: unknown hosts, missing hosts, scored services.
if [ -s "$W/hl" ]; then
    SC=$(cc_table_new scored host ip service port reachable)
    while IFS='|' read -r _ip _name _os; do
        grep -q "^$_ip|" "$W/hl" || flag MED hosts "$_ip ${_name:-}" "host is up but not on the host list: find out what it is"
    done <"$W/up"
    while IFS='|' read -r _ip _name _scored; do
        _inscope=$(awk -v ip="$_ip" -v specs="$TARGETS" "$AWK_IP"'BEGIN { print intarget(ip, specs) }')
        [ "$_inscope" = 1 ] || continue
        _isup=no; grep -q "^$_ip|" "$W/up" && _isup=yes
        [ "$_isup" = yes ] || flag MED hosts "$_ip $_name" "on the host list but did not answer the scan"
        for _s in $(printf '%s' "$_scored" | tr ';' ' '); do
            _svc=${_s%%:*}; _p=${_s##*:}
            case "$_p" in ''|*[!0-9]*) continue ;; esac
            if grep -q "^$_ip|tcp|$_p|" "$W/open" || grep -q "^$_ip|udp|$_p|" "$W/open"; then
                cc_table_row "$SC" "$_name" "$_ip" "$_svc" "$_p" yes
            else
                cc_table_row "$SC" "$_name" "$_ip" "$_svc" "$_p" no
                flag HIGH scored "$_name $_ip $_svc:$_p" "scored service is not reachable from here; check it now (it may only be blocked from this machine)"
            fi
        done
    done <"$W/hl"
    if [ "$PROFILE" = outside ]; then
        # From outside, an open port that is not a scored service on that host
        # is attack surface the red team can see.
        while IFS='|' read -r _ip _pr _p _svc _ver; do
            _sc=$(awk -F'|' -v ip="$_ip" '$1 == ip { print $3 }' "$W/hl")
            case ";$_sc;" in *":$_p;"*) ;; *) flag MED outside "$_ip $_pr/$_p" "reachable from outside but not a scored service on this host ($_svc)" ;; esac
        done <"$W/open"
    fi
fi
_fl="$CC_RUN_DIR/flags.txt"
[ -f "$_fl" ] || cc_table_line severity section item detail time >"$_fl"
if ! awk -F'|' 'NR > 1 { gsub(/ /, "", $1); if ($1 == "HIGH" || $1 == "MED") f = 1 } END { exit !f }' "$_fl"; then show "$C_GRN" "  [ok] nothing high or medium"; fi

# ---- What each box looks like ------------------------------------------------------
# A guess per address from its open ports and the versions it shows, so the
# boxes on the team's diagram can be matched to their addresses.  Also
# written as host-list rows (suggested-hosts.txt) for config/hosts.txt.
show "" ""
show "$C_CYN" "==========[ what each box looks like ]=========="
RC=$(cc_table_new roles ip guess os why)
awk -F'|' -v upf="$W/up" -v rc="$RC" -v sug="$CC_RUN_DIR/suggested-hosts.txt" '
    BEGIN { while ((getline l < upf) > 0) { split(l, u, "|"); order[++n] = u[1]; os[u[1]] = tolower(u[3]) } }
    { k = $2 "/" $3; P[$1, k] = 1; v = tolower($5 " " $4); V[$1] = V[$1] " " v }
    function has(ip, k) { return ((ip, k) in P) }  # awk, not shell: posix-ok
    END {
        print "# name     ip               os       role         connect  port  user    scored_services  notes" > sug
        for (i = 1; i <= n; i++) {
            ip = order[i]; g = ""; why = ""; o = "linux"; r = "server"; c = "ssh"; cp = 22; us = "root"; sc = ""
            vv = V[ip]
            if (vv ~ /dropbear|openwrt|luci|uhttpd/) { g = "router (OpenWRT)"; why = "dropbear / LuCI / uhttpd"; o = "openwrt"; r = "router"; sc = "ssh:22" }
            else if (has(ip, "tcp/88") && has(ip, "tcp/389")) { g = "Windows domain controller (AD)"; why = "Kerberos 88 + LDAP 389"; o = "windows"; r = "domain-ctrl"; c = "winrm"; cp = 5985; us = "-"; sc = "dns:53;ldap:389" }
            else if (vv ~ /gitea|forgejo|gogs/ || (has(ip, "tcp/3000") && !has(ip, "tcp/445"))) { g = "Gitea (git server)"; why = (vv ~ /gitea/ ? "says Gitea" : "web on 3000"); r = "gitea"; sc = "http:3000" }
            else if (has(ip, "tcp/445") || has(ip, "tcp/2049")) {
                if (has(ip, "tcp/3389") || has(ip, "tcp/5985") || os[ip] ~ /windows/) { g = "Windows server"; why = "SMB + RDP/WinRM"; o = "windows"; r = "windows"; c = "winrm"; cp = 5985; us = "-" }
                else { g = "file share (" (has(ip, "tcp/445") ? "Samba" : "") (has(ip, "tcp/445") && has(ip, "tcp/2049") ? " + " : "") (has(ip, "tcp/2049") ? "NFS" : "") ")"; why = "SMB 445 / NFS 2049"; r = "fileshare"; sc = (has(ip, "tcp/445") ? "smb:445" : "nfs:2049") } }
            else if (has(ip, "tcp/3389") || has(ip, "tcp/5985") || os[ip] ~ /windows/) { g = "Windows box"; why = "RDP / WinRM"; o = "windows"; r = "windows"; c = "winrm"; cp = 5985; us = "-" }
            else if (has(ip, "tcp/5672") || has(ip, "tcp/15672") || vv ~ /rabbitmq/) { g = "RabbitMQ (message queue)"; why = "AMQP 5672 / management 15672"; r = "rabbitmq"; sc = "amqp:5672" }
            else if (has(ip, "tcp/8123") || vv ~ /home assistant/) { g = "Home Assistant"; why = "8123"; r = "homeassist"; sc = "http:8123" }
            else if (has(ip, "tcp/80") || has(ip, "tcp/443")) { g = "web app"; why = "HTTP" (has(ip, "tcp/443") ? "S" : ""); r = "web"; sc = (has(ip, "tcp/443") ? "https:443" : "http:80") }
            else if (has(ip, "tcp/22")) { g = "Linux box (SSH only)"; why = "SSH" }
            else { g = "unknown"; why = "no port this script knows"; c = "none"; cp = "-"; us = "-" }
            if (os[ip] ~ /alpine/) o = "linux"
            print ip " | " g " | " os[ip] " | " why >> rc
            print g "	" ip "	" why
            nm = ip; sub(/.*\./, "box", nm)
            printf "%-10s %-16s %-8s %-12s %-8s %-5s %-7s %-16s %s\n", nm, ip, o, r, c, cp, us, (sc == "" ? "-" : sc), "from SH-03: " g >> sug
        }
    }' "$W/open" >"$W/roles"
# Hosts with no open port at all are in $W/up but not in $W/open: still listed.
while IFS="$(printf '\t')" read -r _g _ip _why; do
    case "$_g" in unknown) _c=$C_GRY ;; "router (OpenWRT)"|"Windows domain controller (AD)") _c=$C_CYN ;; *) _c=$C_GRN ;; esac
    show "$_c" "  $(printf '%-16s %-32s (%s)' "$_ip" "$_g" "$_why")"
done <"$W/roles"
[ -s "$W/roles" ] || show "$C_GRY" "  (no open ports to go by)"
show "$C_GRY" "  Host-list rows for these: $CC_RUN_DIR/suggested-hosts.txt (copy the right ones to config/hosts.txt and give them real names)"

# ---- Tables lined up ---------------------------------------------------------------
# shellcheck disable=SC2034  # read by cc_flag_report in the library
CC_FLAGS=$_fl
cc_table_sort_flags "$_fl"
for _t in "$HC" "$PC" "$VC" "${SC:-}" "$RC"; do [ -n "$_t" ] && cc_table_align "$_t"; done

# ---- Summary ----------------------------------------------------------------
_nup=$(grep -c . "$W/up")
_nopen=$(grep -c . "$W/open")
_nvuln=$(awk -F'|' '$5 ~ /VULNERABLE/ { n++ } END { print n + 0 }' "$W/vulns")
_unknown=""
[ -s "$W/hl" ] && _unknown=" ($(awk -F'|' -v hlf="$W/hl" 'BEGIN { while ((getline l < hlf) > 0) { split(l, h, "|"); k[h[1]] = 1 } } !($1 in k) { n++ } END { print n + 0 }' "$W/up") not on the host list)"
{
    printf 'SH-03 Network scan | from %s | %s | engine %s\n' "$CC_HOST" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(cat "$W/engine_version" 2>/dev/null)"
    printf 'Targets:%s | scans: %s\n\n' "$TARGETS" "$SCANS"
    printf 'Hosts up: %s%s | open ports: %s | vulnerable: %s\n\n' "$_nup" "$_unknown" "$_nopen" "$_nvuln"
    # One block per host: address, name, OS, then one line per open port.
    printf 'Open ports\n'
    awk -F'|' -v upf="$W/up" '
        BEGIN { while ((getline l < upf) > 0) { split(l, u, "|"); name[u[1]] = u[2]; os[u[1]] = u[3]; order[++n] = u[1] } }
        { k = $1; c[k]++; p[k, c[k]] = sprintf("    %-10s %-16s %s", $3 "/" $2, substr($4, 1, 16), substr($5, 1, 70)) }
        END {
            for (i = 1; i <= n && i <= 60; i++) {
                ip = order[i]
                printf "  %s%s%s  (%d open)\n", ip, (name[ip] == "" ? "" : " " name[ip]), (os[ip] == "" ? "" : " | " substr(os[ip], 1, 40)), c[ip]
                for (j = 1; j <= c[ip]; j++) print p[ip, j]
            }
            if (n == 0) print "  (no hosts up)"
            if (n > 60) printf "  ... %d more hosts in hosts.txt\n", n - 60
        }' "$W/open"
    printf '\n'
    if [ "$A_VULN" != Y ] && [ "$A_SCRIPTS" != Y ]; then
        printf 'Vulns: not checked (run with --vuln or --scripts)\n'
    elif [ ! -s "$W/vulns" ]; then
        printf 'Vulns: none found by the scripts\n'
    else
        printf 'Vulns and script findings\n'
        awk -F'|' '{ printf "  %-22s %-30s %-17s %s%s\n", $1 " " ($2 == "host" ? "" : $2 "/" $3), substr($4, 1, 30), $5, substr($6, 1, 80), ($7 == "" ? "" : " (" $7 ")") }' "$W/vulns"
    fi
    if [ -n "$HOSTLIST" ] && [ -n "${SC:-}" ]; then
        _sok=$(awk -F'|' 'NR > 1 { gsub(/ /, "", $5); if ($5 == "yes") n++ } END { print n + 0 }' "$SC"); _sno=$(awk -F'|' 'NR > 1 { gsub(/ /, "", $5); if ($5 == "no") n++ } END { print n + 0 }' "$SC")
        printf '\nScored services: %s reachable, %s NOT reachable\n' "$_sok" "$_sno"
    fi
    printf '\n'
    cc_flag_report "$MAXFLAGS"
    printf '\nAll results: %s\n' "$CC_RUN_DIR"
} >"$CC_RUN_DIR/summary.txt"
show "" ""
show "$C_CYN" "==========[ SUMMARY ]=========="
# On screen the summary is colour-coded; summary.txt and output.txt stay plain.
awk -v R="$C_RED" -v Y="$C_YEL" -v G="$C_GRN" -v C="$C_CYN" -v D="$C_GRY" -v O="$C_OFF" '
    NR <= 2                          { print C $0 O; next }
    /^Hosts up:/                     { print (($0 ~ /vulnerable: [1-9]/) ? R : G) $0 O; next }
    /^Open ports$|^Vulns and/        { mode = substr($0, 1, 1); print C $0 O; next }
    /^Vulns: /                       { print D $0 O; next }
    /^$/                             { mode = ""; print; next }
    mode == "O" && /^  [^ ]/         { print C $0 O; next }
    mode == "O"                      { print G $0 O; next }
    mode == "V" && /VULNERABLE/      { print R $0 O; next }
    mode == "V"                      { print Y $0 O; next }
    /^Scored services:/              { print (($0 ~ / [1-9][0-9]* NOT/) ? R : G) $0 O; next }
    /^Flags:/                        { print C $0 O; next }
    /^HIGH - /                       { fm = "H"; print R $0 O; next }
    /^MED - /                        { fm = "M"; print Y $0 O; next }
    /^  \[/ && fm == "H"             { print R "  [!] FIX " substr($0, 3) O; next }
    /^  \[/ && fm == "M"             { print Y "  [*] LOOK" substr($0, 2) O; next }
    /^All (flags|results)/           { print D $0 O; next }
                                     { print }
' "$CC_RUN_DIR/summary.txt" >&3
cat "$CC_RUN_DIR/summary.txt" >>"$OUTF"
rm -rf "$W"
cc_finish
