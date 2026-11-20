#!/bin/sh
# =============================================================================
# ID:       NW-20
# NAME:     Firewall ruleset
# ROLE:     Network  (wave 2, after NW-01 backup; one device at a time)
# KIND:     changes - dry run unless --apply
# VERSION:  1.0.0
#
# PURPOSE
#   Puts a short, readable set of rules at the TOP of the network firewall
#   so that only the scored services can be reached from outside:
#     ON by default (asked):
#       allow   your team's addresses, everything
#       allow   any address -> each scored box, its scored ports only
#               (any address, so the scoring engine always gets through)
#       allow   ping in to the scored boxes (every box has a ping check)
#       block   everything else coming in from outside, logged
#     OFF by default (asked separately, default no):
#       outgoing limits: the servers may only start connections to DNS,
#       NTP and what you list (stops web-shell callbacks and exfil);
#       everything else they start is blocked and logged
#       threat prevention (Palo Alto, FortiGate) on the scored rules
#   Every rule is named bt-... so it is easy to see, and the old rules are
#   left where they were (below ours).  Nothing is deleted.
#
#   Brands: paloalto, cisco-asa, fortigate, mikrotik, linux (a Linux router:
#   its own nftables table).  pfSense / OPNsense: the same plan as web GUI
#   steps.  Cisco IOS, VyOS: the plan is shown, not applied.
#
#   HOW IT KEEPS THE SCORED SERVICES UP
#     - before: every scored box:port (and ping) is tried from this box
#     - the rules go in through one open session to the firewall
#     - the undo is written before anything is sent
#     - after: the same tries; one that answered before and no longer does,
#       a command the firewall refused, a Palo Alto commit that did not
#       work, or a new login that fails -> everything is put back at once
#     - Ctrl-C (or a kill) while a firewall is being changed -> put back
#     - then you are asked to check the scoreboard / your services within
#       --timer seconds (default 120); no answer or "n" -> put back
#     - REVERT LATER: sh <run>/undo/DEVICE.sh, or this script with --remove
#       (removes every bt- rule it added, the device's old setup back)
#
#   QUESTIONS (Enter takes the default in capitals; a flag answers each):
#     the scored boxes and their ports      --allow, --file, or typed in
#       (offered from the newest SH-03 scan when there is one)
#     is this list right?                   Y
#     your team's addresses                 --team
#     which side is outside / servers       --outside, --inside
#     each rule                             [k]eep (default) / [s]kip
#     block everything else coming in?      Y
#     limit what the servers send out?      N   (--restrict-out)
#       DNS servers, NTP, extra destinations
#     threat prevention on scored rules?    N   (--threat)
#     apply this plan to DEVICE?            Y   (--apply)
#     keep it (checked the scoreboard)?     Y within --timer, else put back
#
# USAGE
#   BT_NET_PASS='pw' sh NW-20-firewall-ruleset.sh --device fw1,10.0.0.1,paloalto
#   BT_NET_PASS='pw' sh NW-20-firewall-ruleset.sh --device fw1,10.0.0.1,paloalto \
#       --allow 10.0.0.5:80,443 --allow 10.0.0.9:25,143,993,53/udp --team 10.0.0.0/24 --apply
#   BT_NET_PASS='pw' sh NW-20-firewall-ruleset.sh --device fw1,10.0.0.1,paloalto --remove --apply
#
# OPTIONS
#   --device NAME,ADDRESS,VENDOR[,USER[,PORT]]   the firewall (repeat)
#   --hosts FILE       or the devices from the host list
#   --allow ADDR:PORTS a scored box and its ports: 80,443,53/udp,8000-8100
#                      (repeat; no ports = ping only)
#   --file FILE        the scored boxes, one per line:  ADDR  PORTS...  # note
#   --scan DIR         an SH-03 run folder to offer ports from (default: the
#                      newest netscan-N under --out)
#   --team CIDR,...    your team's addresses (allowed everything)
#   --outside NAME     the outside zone / interface (else asked)
#   --inside NAME      the zone / interface the servers are on (else asked;
#                      "all" = every zone but outside: Palo Alto, FortiGate)
#   --restrict-out     also limit what the servers start (asked otherwise, default no)
#   --dns IP,...       DNS servers the servers may use (with --restrict-out)
#   --ntp IP           time server the servers may use
#   --out-allow ADDR:PORTS   another destination the servers may reach (repeat)
#   --threat           threat prevention on the scored rules (asked otherwise)
#   --remove           take out every bt- rule this script put on the device(s)
#   --user NAME / --ask-password / --enable-env / --legacy-ssh   as NW-21
#   --wait N           seconds before the checks (default 5)
#   --commit-wait N    Palo Alto: at most this many seconds for the commit
#                      to say it worked (default 120), else put back
#   --timer N          seconds to confirm (default 120)
#   --no-color         no colours
#   --help             this text plus the common options
#
# OUTPUTS  (under --out, in firewall-ruleset-N/)
#   output.txt, scored.txt, plan.txt (every rule in plain words, per device),
#   commands-DEVICE.txt (exactly what is sent), checks.txt, summary.txt
#   undo/DEVICE.sh     takes the rules out again (needs BT_NET_PASS)
#   nw20-DEVICE.undo   in --out: what --remove sends (kept between runs)
#
# DEPENDS ON
#   ssh, sshpass, mkfifo; nc (or bash) for the service checks; ping.
#
# TESTED ON
#   A stand-in device for every brand (commands written from each brand's
#   documentation) under dash, bash, busybox sh, ksh93, mksh and yash with
#   gawk, mawk and busybox awk; the Linux router brand's ruleset checked by
#   the real nft.  NOT yet on a real Palo Alto, ASA, FortiGate or MikroTik:
#   run it without --apply, read plan.txt and commands-DEVICE.txt, then
#   --apply on ONE device.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - Scored boxes are given by their INSIDE address (the one in the host
#     list).  Palo Alto and FortiGate match the OUTSIDE (NAT) address, so
#     their NAT rules / virtual IPs that lead to a scored box are read and
#     those names are added to its rules (shown, and listed in plan.txt).
#     ASA, MikroTik and Linux match the inside address after NAT.
#   - The checks run from this box: if this box is inside, they may not
#     pass through the firewall.  Watch the scoreboard during the countdown.
#   - The confirm countdown only expires by itself in shells with "read -t"
#     (bash, ksh, mksh, yash, busybox); dash waits for the answer.
#   - Cisco ASA: one access list per interface, so BT-IN replaces the one
#     bound to the outside interface (its old one is put back on undo).
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
NW-20 Firewall ruleset - only the scored services in, everything else blocked; checked, easy to revert
  BT_NET_PASS=pw sh NW-20-firewall-ruleset.sh --device NAME,ADDRESS,VENDOR [--allow ADDR:PORTS] [--apply]

  --device NAME,ADDRESS,VENDOR[,USER[,PORT]]   the firewall (repeat), or --hosts FILE
  --allow ADDR:PORTS   a scored box: 80,443,53/udp,8000-8100 (repeat)
  --file FILE          scored boxes, one per line: ADDR PORTS... # note
  --scan DIR           an SH-03 run folder to offer ports from
  --team CIDR,...      your team's addresses
  --outside NAME / --inside NAME   zones or interfaces (else asked)
  --restrict-out       also limit what the servers start (default: asked, no)
  --dns IP,... / --ntp IP / --out-allow ADDR:PORTS   what they may still reach
  --threat             threat prevention on the scored rules
  --remove             take out every bt- rule this script added
  --user NAME / --ask-password / --enable-env / --legacy-ssh
  --wait N / --commit-wait N / --timer N
  --no-color           no colours
  --help               show this text
USAGE
    cc_usage_common
}

NL='
'
HOSTS=""; DEVICES=""; DEFUSER="admin"; ASK=0; ENABLE=0; LEGACY=0; COLOR=1
ALLOWS=""; SFILE=""; SCAN=""; TEAM=""; OUTSIDE=""; INSIDE=""; RESTRICT=""; DNS=""; NTP=""; OUTALLOW=""; THREAT=""; REMOVE=0
WAIT=5; CWAIT=120; TIMER=120
num() { case "$2" in ''|*[!0-9]*) cc_die 2 "$1 needs a whole number" ;; esac; }
okname() { case "$2" in ''|*[!A-Za-z0-9_./:-]*) cc_die 2 "$1: letters, digits and . _ / : - only" ;; esac; }
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --apply)        CC_APPLY=1; shift ;;
        --hosts)        [ $# -ge 2 ] || cc_die 2 "--hosts needs a file"; [ -r "$2" ] || cc_die 2 "--hosts: cannot read $2"; HOSTS=$2; shift 2 ;;
        --device)       [ $# -ge 2 ] || cc_die 2 "--device needs NAME,ADDRESS,VENDOR"; DEVICES="$DEVICES$2$NL"; shift 2 ;;
        --user)         [ $# -ge 2 ] || cc_die 2 "--user needs a name"; DEFUSER=$2; shift 2 ;;
        --ask-password) ASK=1; shift ;;
        --enable-env)   ENABLE=1; shift ;;
        --legacy-ssh)   LEGACY=1; shift ;;
        --allow)        [ $# -ge 2 ] || cc_die 2 "--allow needs ADDR:PORTS"; ALLOWS="$ALLOWS$2$NL"; shift 2 ;;
        --file)         [ $# -ge 2 ] || cc_die 2 "--file needs a file"; [ -r "$2" ] || cc_die 2 "--file: cannot read $2"; SFILE=$2; shift 2 ;;
        --scan)         [ $# -ge 2 ] || cc_die 2 "--scan needs a folder"; [ -d "$2" ] || cc_die 2 "--scan: not a folder: $2"; SCAN=$2; shift 2 ;;
        --team)         [ $# -ge 2 ] || cc_die 2 "--team needs addresses"; TEAM="$TEAM,$2"; shift 2 ;;
        --outside)      [ $# -ge 2 ] || cc_die 2 "--outside needs a name"; okname "$1" "$2"; OUTSIDE=$2; shift 2 ;;
        --inside)       [ $# -ge 2 ] || cc_die 2 "--inside needs a name"; okname "$1" "$2"; INSIDE=$2; shift 2 ;;
        --restrict-out) RESTRICT=y; shift ;;
        --dns)          [ $# -ge 2 ] || cc_die 2 "--dns needs addresses"; DNS="$DNS,$2"; shift 2 ;;
        --ntp)          [ $# -ge 2 ] || cc_die 2 "--ntp needs an address"; NTP=$2; shift 2 ;;
        --out-allow)    [ $# -ge 2 ] || cc_die 2 "--out-allow needs ADDR:PORTS"; OUTALLOW="$OUTALLOW$2$NL"; shift 2 ;;
        --threat)       THREAT=y; shift ;;
        --remove)       REMOVE=1; shift ;;
        --wait)         num "$1" "${2:-}"; WAIT=$2; shift 2 ;;
        --commit-wait)  num "$1" "${2:-}"; CWAIT=$2; shift 2 ;;
        --timer)        num "$1" "${2:-}"; TIMER=$2; shift 2 ;;
        --no-color|--no-colour) COLOR=0; shift ;;
        --help|-h)      usage; exit 0 ;;
        *)              cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
[ -n "$HOSTS$DEVICES" ] || cc_die 2 "give the firewall: --device NAME,ADDRESS,VENDOR (try --help)"
IPRE='[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}'
isip()   { printf '%s' "$1" | grep -q "^$IPRE\$"; }
iscidr() { printf '%s' "$1" | grep -q "^$IPRE\\(/[0-9]\\{1,2\\}\\)\\{0,1\\}\$"; }
TEAM=${TEAM#,}; DNS=${DNS#,}
for _t in $(printf '%s' "$TEAM" | tr ',' ' '); do iscidr "$_t" || cc_die 2 "--team: IPv4 addresses or CIDRs (10.0.0.0/24)"; done
for _t in $(printf '%s' "$DNS" | tr ',' ' '); do isip "$_t" || cc_die 2 "--dns: IPv4 addresses"; done
[ -z "$NTP" ] || isip "$NTP" || cc_die 2 "--ntp: an IPv4 address"

cc_init "NW-20" "Firewall ruleset" changes
# shellcheck disable=SC2034  # read by cc_color_init
[ "$COLOR" = 1 ] || CC_NOCOLOR=1
cc_color_init
cc_use_numbered_dir firewall-ruleset
rmdir "$CC_RUN_DIR/raw" 2>/dev/null
OUTF="$CC_RUN_DIR/output.txt"
grep -v '\[NOTE\]\|\[DEBUG\]' "$CC_LOG" >"$OUTF" 2>/dev/null || : >"$OUTF"
# shellcheck disable=SC2034  # CC_TEE is read by the library's log functions
CC_TEE=$OUTF
W="$CC_RUN_DIR/.work"; (umask 077; mkdir -p "$W")
US=$(printf '\037')
trap 'rm -rf "$W"; exit 130' INT TERM HUP
header() { cc_show "" ""; cc_show "$C_CYN" "==========[ $1 ]=========="; }
j() { _j=$1; shift; for _jx in "$@"; do _j="$_j$US$_jx"; done; printf '%s\n' "$_j"; }
CONFIGS="$CC_OUT/net-configs"; mkdir -p "$CONFIGS" 2>/dev/null
SSH=${BT_SSH:-$(cc_which ssh)} || cc_die 3 "ssh not found"
SSHPASS_BIN=${BT_SSHPASS:-$(cc_which sshpass)} || cc_die 3 "sshpass not found (apt install sshpass)"
cc_have mkfifo || cc_die 3 "mkfifo not found"
if [ "$ASK" = 1 ]; then
    [ -r /dev/tty ] || cc_die 3 "--ask-password needs a terminal; set BT_NET_PASS"
    printf 'Device password: ' >/dev/tty; stty -echo </dev/tty 2>/dev/null
    read -r BT_NET_PASS </dev/tty; stty echo </dev/tty 2>/dev/null; printf '\n' >/dev/tty
fi
[ -n "${BT_NET_PASS:-}" ] || cc_die 3 "the device password is needed: set BT_NET_PASS or use --ask-password"
[ "$ENABLE" = 1 ] && [ -z "${BT_NET_ENABLE:-}" ] && cc_die 3 "--enable-env: set BT_NET_ENABLE"

cc_show "$C_CYN" "NW-20 Firewall ruleset | from $CC_HOST | results in $CC_RUN_DIR"
cc_show "" "Legend: ${C_RED}[!]${C_OFF} fix now   ${C_YEL}[*]${C_OFF} look at it   ${C_GRN}[ok]${C_OFF} fine   ${C_YEL}[~] would change${C_OFF}   ${C_GRN}[+] changed${C_OFF}   ${C_RED}[x] failed${C_OFF}"

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
    cc_hosts_rows "$HOSTS" | awk -F'|' '{ print $1 "|" $2 "|" tolower($3) "|" $10 "|" $9 "|" $7 "|" $6 }' >"$W/rows"
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
[ -s "$W/devices" ] || cc_die 3 "no firewall given"
for _n in $(cut -d'|' -f1 "$W/devices"); do case "$_n" in *[!A-Za-z0-9_.-]*) cc_die 2 "device name '$_n' may only use letters, digits, '.', '_' and '-'" ;; esac; done
_bp=$(awk -F'|' '$5 !~ /^[0-9]+$/ || $5 < 1 || $5 > 65535 { print $1; exit }' "$W/devices"); [ -z "$_bp" ] || cc_die 2 "device $_bp: the SSH port must be a number from 1 to 65535"

# ---- Talking to a device ---------------------------------------------------------------
sshopts() {
    set -- -T -o ConnectTimeout=10 -o "UserKnownHostsFile=$CONFIGS/known_hosts" -o StrictHostKeyChecking=accept-new \
        -o LogLevel=ERROR -o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive -o NumberOfPasswordPrompts=1
    [ "$LEGACY" = 1 ] && set -- "$@" -o KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group1-sha1 -o HostKeyAlgorithms=+ssh-rsa -o Ciphers=+aes128-cbc,aes256-cbc,3des-cbc
    printf '%s\n' "$@"
}
read_mode() { case "$1" in mikrotik|linux) echo exec ;; *) echo stdin ;; esac; }
en() { case "$1" in cisco-*) [ "$ENABLE" = 1 ] && printf 'enable\n%s\n' "$BT_NET_ENABLE" ;; esac; return 0; }
read_cmds() {
    case "$1" in
        cisco-asa) en "$1"; printf 'terminal pager 0\nshow running-config interface\nshow running-config access-group\nshow running-config access-list\nexit\n' ;;
        paloalto)  printf 'set cli pager off\nset cli config-output-format set\nconfigure\nshow zone\nshow address\nshow rulebase nat\nshow rulebase security\nexit\nexit\n' ;;
        fortigate) printf 'show system interface\nshow firewall vip\nshow firewall policy\nexit\n' ;;
        mikrotik)  printf ':put "===if"; /interface print terse without-paging; :put "===filter"; /ip firewall filter print terse without-paging' ;;
        linux)     printf 'echo ===if; ip -o link show; echo ===nft; if [ "$(id -u)" = 0 ]; then nft list ruleset; else sudo -n nft list ruleset; fi' ;;
    esac
}
readdev() {
    read_cmds "$1" >"$W/rin"; _rv=$1; _ru=$2; _ra=$3; _rp=$4; _ro=$5
    sshopts >"$W/opts"; set --; while IFS= read -r _o; do set -- "$@" "$_o"; done <"$W/opts"
    if [ "$(read_mode "$_rv")" = exec ]; then
        SSHPASS=$BT_NET_PASS "$SSHPASS_BIN" -e "$SSH" "$@" -p "$_rp" "$_ru@$_ra" "$(cat "$W/rin")" </dev/null >"$_ro" 2>"$W/err"
    else
        SSHPASS=$BT_NET_PASS "$SSHPASS_BIN" -e "$SSH" "$@" -p "$_rp" "$_ru@$_ra" <"$W/rin" >"$_ro" 2>"$W/err"
    fi
}
# send VENDOR USER ADDRESS PORT FILE -> one session that gets FILE (for undo and --remove)
send() {
    _sv=$1; _su=$2; _sa=$3; _sp=$4; _sf=$5
    case "$_sv" in cisco-*) { en "$_sv"; cat "$5"; printf 'exit\n'; } >"$W/send.in"; _sf="$W/send.in" ;; esac
    sshopts >"$W/opts"; set --; while IFS= read -r _o; do set -- "$@" "$_o"; done <"$W/opts"
    if [ "$(read_mode "$_sv")" = exec ]; then
        SSHPASS=$BT_NET_PASS "$SSHPASS_BIN" -e "$SSH" "$@" -p "$_sp" "$_su@$_sa" "$(oneline "$_sv" "$_sf")" </dev/null >>"$CC_LOG" 2>&1
    else
        SSHPASS=$BT_NET_PASS "$SSHPASS_BIN" -e "$SSH" "$@" -p "$_sp" "$_su@$_sa" <"$_sf" >>"$CC_LOG" 2>&1
    fi
}
# oneline VENDOR FILE -> the command line for an exec session (RouterOS: joined by ";")
oneline() { if [ "$1" = mikrotik ]; then tr '\n' ';' <"$2" | sed 's/;$//'; else cat "$2"; fi; }
nap() { sleep "$1" & _nap=$!; wait "$_nap"; }

# ---- --remove: put the saved undo back ----------------------------------------------------
if [ "$REMOVE" = 1 ]; then
    header "remove the bt- rules"
    NOK=0; NBAD=0
    while IFS='|' read -r _n _a _v _u _p; do
        _st="$CC_OUT/nw20-$_n.undo"
        if [ ! -s "$_st" ]; then cc_show "$C_GRY" "  $_n: no rules from NW-20 recorded for it ($_st)"; continue; fi
        cc_show "$C_CYN" "  $_n ($_v): what will be sent:"; sed 's/^/      /' "$_st" | while IFS= read -r _l; do cc_show "$C_GRY" "$_l"; done
        if [ "$CC_APPLY" != 1 ]; then cc_show "$C_GRY" "  Dry run: run again with --apply to take them out."; continue; fi
        if cc_ask "Take NW-20's rules off $_n now?" Y "yes, take them out" "no, leave them"; then
            if send "$_v" "$_u" "$_a" "$_p" "$_st"; then NOK=$((NOK + 1)); mv "$_st" "$_st.done"; cc_show "$C_GRN" "  [+] $_n: rules taken out"
            else NBAD=$((NBAD + 1)); cc_show "$C_RED" "  [x] $_n: could not log in to take them out (see $CC_LOG)"; fi
        fi
    done <"$W/devices"
    # shellcheck disable=SC2034  # read by cc_finish
    CC_N_DONE=$NOK
    # shellcheck disable=SC2034  # read by cc_finish
    CC_N_FAIL=$NBAD
    rm -rf "$W"; cc_finish; exit
fi

# ---- 1. The scored services ---------------------------------------------------------------
header "1/6  the scored services"
# $W/scored: ADDR US tcp-ports US udp-ports US note    (ports: "80,443,8000-8100")
: >"$W/scored"
# add_scored ADDR "PORT PORT/udp ..." NOTE -> one line in $W/scored (merged per address)
add_scored() {
    isip "$1" || { cc_show "$C_RED" "  [x] not an IPv4 address, skipped: $1"; return 1; }
    _tp=""; _upp=""
    for _x in $(printf '%s' "$2" | tr ',' ' '); do
        _pr=tcp; case "$_x" in */udp) _pr=udp; _x=${_x%/udp} ;; */tcp) _x=${_x%/tcp} ;; esac
        case "$_x" in ''|*[!0-9-]*|-*|*-|*-*-*) cc_show "$C_RED" "  [x] $1: not a port, skipped: $_x"; continue ;; esac
        if [ "${_x%-*}" -lt 1 ] || [ "${_x%-*}" -gt 65535 ] || [ "${_x#*-}" -lt 1 ] || [ "${_x#*-}" -gt 65535 ] || [ "${_x%-*}" -gt "${_x#*-}" ]; then
            cc_show "$C_RED" "  [x] $1: not a port (1-65535), skipped: $_x"; continue; fi
        if [ "$_pr" = udp ]; then case "$_upp," in *",$_x,"*) ;; *) _upp="$_upp,$_x" ;; esac
        else case "$_tp," in *",$_x,"*) ;; *) _tp="$_tp,$_x" ;; esac; fi
    done
    if grep -q "^$1$US" "$W/scored"; then
        awk -F"$US" -v OFS="$US" -v a="$1" -v t="${_tp#,}" -v u="${_upp#,}" '
            function merge(old, add,   n, x, i, seen, out) {  # awk, not shell: posix-ok
                n = split(old "," add, x, ","); out = ""
                for (i = 1; i <= n; i++) if (x[i] != "" && !(x[i] in seen)) { seen[x[i]] = 1; out = out (out == "" ? "" : ",") x[i] }
                return out }
            $1 == a { $2 = merge($2, t); $3 = merge($3, u) } { print }' "$W/scored" >"$W/s.n" && cat "$W/s.n" >"$W/scored"
    else j "$1" "${_tp#,}" "${_upp#,}" "$3" >>"$W/scored"; fi
}
printf '%s' "$ALLOWS" | grep . | while IFS= read -r _l; do printf '%s %s\n' "${_l%%:*}" "$(printf '%s' "$_l" | sed -n 's/^[^:]*://p')"; done >"$W/given"
[ -n "$SFILE" ] && sed 's/#.*//' "$SFILE" | awk 'NF { a = $1; $1 = ""; sub(/^ /, ""); print a " " $0 }' >>"$W/given"
if [ -n "$SFILE" ]; then awk 'index($0, "#") { n = substr($0, index($0, "#") + 1); sub(/^[ \t]+/, "", n); split($0, a, " "); if (a[1] !~ /^#/) print a[1] " " n }' "$SFILE" >"$W/notes"; else : >"$W/notes"; fi
while IFS=' ' read -r _a _ports; do add_scored "$_a" "$_ports" "$(awk -v a="$_a" '$1 == a { $1 = ""; sub(/^ /, ""); print; exit }' "$W/notes")"; done <"$W/given"
# The newest SH-03 scan offers its open ports.
# (the newest by its number: netscan-10 is newer than netscan-9)
[ -n "$SCAN" ] || SCAN=$(for _sd in "$CC_OUT"/netscan-*; do [ -d "$_sd" ] && printf '%s %s\n' "${_sd##*-}" "$_sd"; done | sort -n | tail -n 1 | cut -d' ' -f2-)
: >"$W/scanports"
# ports.txt: a " | " table (ip hostname proto port state service version);
# an older scan has csv/ports.csv
if [ -n "$SCAN" ] && [ -f "$SCAN/ports.txt" ] && head -n 1 "$SCAN/ports.txt" | grep -q ' | '; then
    awk "$CC_AWK_TABLE"'NR > 1 { tsplit($0, f); if (f[5] == "open") print f[1] " " f[4] (f[3] == "udp" ? "/udp" : "") " " f[6] }' "$SCAN/ports.txt" >"$W/scanports"
elif [ -n "$SCAN" ] && [ -f "$SCAN/csv/ports.csv" ]; then
    awk -F',' "$CC_AWK_CSV"'NR > 1 { csvsplit($0, f); if (f[5] == "open") print f[1] " " f[4] (f[3] == "udp" ? "/udp" : "") " " f[6] }' "$SCAN/csv/ports.csv" >"$W/scanports"
fi
if [ ! -s "$W/scored" ]; then
    if [ -s "$W/scanports" ] && _cc_can_ask && [ "$CC_BATCH" != 1 ]; then
        cc_show "" "  From the scan in $SCAN - each open port, asked one by one:"
        awk '{ print $1 }' "$W/scanports" | awk '!s[$0]++' >"$W/scanhosts"
        while IFS= read -r _h; do
            _keep=""
            awk -v h="$_h" '$1 == h { print $2 " " $3 }' "$W/scanports" >"$W/hp"
            while IFS=' ' read -r _pt _svc; do
                # scored-looking ports default to keep
                case "${_pt%/udp}" in 21|22|25|53|80|88|110|123|135|139|143|389|443|445|464|587|636|993|995|1433|3268|3306|3389|5432|5985|5986|8000|8080|8089|8443|9997) _d=k ;; *) _d=b ;; esac
                cc_choose "$_h port $_pt (${_svc:-unknown}): reachable from outside?" "$_d" "k=keep it open (a scored or needed service)" "b=block it from outside"
                [ "$CC_CHOICE" = k ] && _keep="$_keep $_pt"
            done <"$W/hp"
            [ -n "$_keep" ] && add_scored "$_h" "$_keep" "from the scan"
        done <"$W/scanhosts"
    elif _cc_can_ask && [ "$CC_BATCH" != 1 ]; then
        cc_show "" "  No --allow / --file given: type each scored box (its INSIDE address), Enter on an empty line when done."
        while :; do
            cc_ask_text "Scored box address (empty = done)" "" "address"; _h=$CC_ANSWER
            [ -n "$_h" ] || break
            cc_ask_text "Its scored ports, e.g. 80 443 53/udp (empty = ping only)" "" "ports"; _ps=$CC_ANSWER
            cc_ask_text "A note (what it is)" "" "note"
            add_scored "$_h" "$_ps" "$CC_ANSWER"
        done
    fi
fi
[ -s "$W/scored" ] || { rm -rf "$W"; cc_die 2 "No scored boxes: give --allow ADDR:PORTS, --file FILE, or answer the questions. Nothing was changed."; }
{ printf '%-16s %-30s %-20s %s\n' box tcp udp note; awk -F"$US" '{ printf "%-16s %-30s %-20s %s\n", $1, ($2 == "" ? "-" : $2), ($3 == "" ? "-" : $3), $4 }' "$W/scored"; } >"$CC_RUN_DIR/scored.txt"
while IFS= read -r _l; do cc_show "" "  $_l"; done <"$CC_RUN_DIR/scored.txt"
cc_show "" "  Every box also gets ping in. These are reachable from ANY address (so the scoring engine always gets through)."
if ! cc_ask "Is this list of scored boxes and ports right?" Y "yes, build the rules from it" "no, stop (fix --allow / --file and run again)"; then
    cc_show "$C_GRY" "  Stopped: nothing was changed."; rm -rf "$W"; cc_finish; exit 0
fi
SERVERS=$(cut -d"$US" -f1 "$W/scored" | tr '\n' ',' | sed 's/,$//')

# ---- 2. Team, outgoing limits, threat prevention ---------------------------------------------
header "2/6  your team, outgoing limits, threat prevention"
if [ -z "$TEAM" ] && _cc_can_ask && [ "$CC_BATCH" != 1 ]; then
    cc_ask_text "Your team's addresses (CIDR, comma separated; empty = none)" "" "addresses"
    for _t in $(printf '%s' "$CC_ANSWER" | tr ',' ' '); do iscidr "$_t" && TEAM="$TEAM,$_t" || cc_show "$C_RED" "  [x] not an address or CIDR, left out: $_t"; done
    TEAM=${TEAM#,}
fi
[ -n "$TEAM" ] && cc_show "$C_GRN" "  [ok] your team ($TEAM): allowed everything" || cc_show "$C_YEL" "  [*] no team addresses: if you manage boxes from OUTSIDE the firewall, give --team or you are blocked too"
if [ -z "$RESTRICT" ]; then
    cc_show "" "  Outgoing limits stop a hacked server from calling out (web-shell callbacks, downloads, data sent out, ping and DNS tunnels)."
    cc_show "" "  They can break a service that must start connections out (webmail to IMAP, a store to its database, forwarders to Splunk) - you list those next."
    cc_choose "Limit what the scored servers can START out through the firewall?" n "y=yes, only DNS, NTP and what I list" "n=no, leave outgoing traffic alone (replies to the scorer always work)"
    RESTRICT=$CC_CHOICE
fi
if [ "$RESTRICT" = y ]; then
    if [ -z "$DNS" ] && _cc_can_ask && [ "$CC_BATCH" != 1 ]; then cc_ask_text "DNS servers the servers may use (comma separated)" "" "addresses"; DNS=$CC_ANSWER; fi
    if [ -z "$NTP" ] && _cc_can_ask && [ "$CC_BATCH" != 1 ]; then cc_ask_text "Time server they may use (Splunk; empty = none)" "" "address"; NTP=$CC_ANSWER; fi
    if [ -z "$OUTALLOW" ] && _cc_can_ask && [ "$CC_BATCH" != 1 ]; then
        cc_show "" "  Anything else a server must reach out through the firewall, as ADDR:PORTS (e.g. 10.0.1.9:1433 for a database, 10.0.0.20:9997 for Splunk). Empty = done."
        while :; do cc_ask_text "Also allow out to (ADDR:PORTS; empty = done)" "" "destination"; [ -n "$CC_ANSWER" ] || break; OUTALLOW="$OUTALLOW$CC_ANSWER$NL"; done
    fi
    : >"$W/outallow"
    for _d in $(printf '%s' "$DNS" | tr ',' ' '); do isip "$_d" && j "$_d" "53" "53" "DNS" >>"$W/outallow"; done
    [ -n "$NTP" ] && isip "$NTP" && j "$NTP" "" "123" "NTP" >>"$W/outallow"
    printf '%s' "$OUTALLOW" | grep . | while IFS= read -r _l; do
        _d=${_l%%:*}; _ps=$(printf '%s' "$_l" | sed -n 's/^[^:]*://p'); _tp=""; _upp=""
        isip "$_d" || { echo "BAD $_l"; continue; }
        for _x in $(printf '%s' "$_ps" | tr ',' ' '); do case "$_x" in */udp) _upp="$_upp,${_x%/udp}" ;; *) _tp="$_tp,${_x%/tcp}" ;; esac; done
        [ -n "$_tp$_upp" ] || { echo "BAD $_l (no ports)"; continue; }
        j "$_d" "${_tp#,}" "${_upp#,}" "you listed it"
    done >>"$W/outallow"
    grep '^BAD ' "$W/outallow" | while IFS= read -r _l; do cc_show "$C_RED" "  [x] not ADDR:PORTS, left out: ${_l#BAD }"; done
    # one line per destination (DNS and NTP on the same box become one rule)
    grep -v '^BAD ' "$W/outallow" | awk -F"$US" -v OFS="$US" '
        function merge(old, add,   n, x, i, seen, out) {  # awk, not shell: posix-ok
                n = split(old "," add, x, ","); out = ""
            for (i = 1; i <= n; i++) if (x[i] != "" && !(x[i] in seen)) { seen[x[i]] = 1; out = out (out == "" ? "" : ",") x[i] }
            return out }
        { if (!($1 in t)) o[++n] = $1; t[$1] = merge(t[$1], $2); u[$1] = merge(u[$1], $3); w[$1] = (w[$1] == "" ? "" : w[$1] ", ") $4 }
        END { for (i = 1; i <= n; i++) print o[i], t[o[i]], u[o[i]], w[o[i]] }' >"$W/o.n"; cat "$W/o.n" >"$W/outallow"
    [ -s "$W/outallow" ] || cc_show "$C_YEL" "  [*] no DNS, NTP or other destination listed: the servers will reach NOTHING outside the firewall"
fi
if [ -z "$THREAT" ]; then
    cc_choose "Turn on the firewall's threat prevention (IPS, antivirus, spyware) on the scored rules? (Palo Alto, FortiGate)" n "y=yes, use the firewall's default profiles" "n=no"
    THREAT=$CC_CHOICE
fi

# ---- 3. The rules (in plain words) ------------------------------------------------------------
header "3/6  the rules, one by one"
# $W/rules: kind US name US src US dst US tcp US udp US what     (kind: team scored ping indeny outallow outdeny)
: >"$W/rules"
ask_rule() {   # ask_rule KIND NAME SRC DST TCP UDP WHAT DEFAULT
    cc_choose "$7" "$8" "k=keep this rule" "s=skip it"
    [ "$CC_CHOICE" = k ] && j "$1" "$2" "$3" "$4" "$5" "$6" "$7" >>"$W/rules"
}
[ -n "$TEAM" ] && ask_rule team bt-team "$TEAM" any "" "" "ALLOW your team ($TEAM) -> anywhere, everything" k
while IFS="$US" read -r _a _t _u _note; do
    _w="ALLOW any -> $_a"; [ -n "$_t" ] && _w="$_w tcp $_t"; [ -n "$_u" ] && _w="$_w udp $_u"; [ -z "$_t$_u" ] && _w="$_w (no ports: ping only)"
    [ -n "$_note" ] && _w="$_w ($_note)"
    [ -n "$_t$_u" ] && ask_rule scored "bt-in-$_a" any "$_a" "$_t" "$_u" "$_w" k
done <"$W/scored"
ask_rule ping bt-ping any "$SERVERS" "" "" "ALLOW ping in -> the scored boxes (every box has a ping check)" k
if [ "$RESTRICT" = y ]; then
    while IFS="$US" read -r _d _t _u _note; do
        _w="ALLOW the scored servers -> $_d"; [ -n "$_t" ] && _w="$_w tcp $_t"; [ -n "$_u" ] && _w="$_w udp $_u"; _w="$_w ($_note)"
        ask_rule outallow "bt-out-$_d" "$SERVERS" "$_d" "$_t" "$_u" "$_w" k
    done <"$W/outallow"
    ask_rule outdeny bt-out-block "$SERVERS" any "" "" "BLOCK + LOG anything else the scored servers START out (callbacks, downloads, ping and DNS tunnels)" k
fi
cc_show "" "  Last: the rule that actually closes everything else. Without it the rules above change nothing."
ask_rule indeny bt-in-block any any "" "" "BLOCK + LOG every other connection coming IN from outside (replies to your own traffic still work)" k
NRULES=$(grep -c . "$W/rules")
[ "$NRULES" -gt 0 ] || { cc_show "$C_GRY" "  Every rule skipped: nothing to do."; rm -rf "$W"; cc_finish; exit 0; }
grep -q "^indeny$US" "$W/rules" || cc_show "$C_YEL" "  [*] without the BLOCK rule the firewall still lets in whatever its old rules allow"

# ---- 4. Each firewall: read, choose sides, build ------------------------------------------------
header "4/6  each firewall"
# pick LIST-FILE QUESTION DEFAULT-REGEX GIVEN -> CC_PICK (a name from the list)
# With a 5th argument "all", "a" picks every name in the list (CC_PICK=all).
# Without a terminal it never guesses: no name like the default -> refused.
pick() {
    CC_PICK=""
    if [ -n "$4" ]; then
        [ "$4" = all ] && [ "${5:-}" = all ] && [ -s "$1" ] && { CC_PICK=all; return 0; }
        grep -qxF "$4" "$1" && { CC_PICK=$4; return 0; }; cc_show "$C_RED" "  [x] '$4' is not on this device (it has: $(tr '\n' ' ' <"$1"))"; return 1; fi
    _pn=$(grep -c . "$1"); [ "$_pn" -gt 0 ] || return 1
    _pd=$(grep -inE "$3" "$1" | head -n 1 | cut -d: -f1)
    if [ -z "$_pd" ] && ! _cc_can_ask; then
        cc_show "$C_RED" "  [x] $2 - no name looks right ($(tr '\n' ' ' <"$1")) and nobody to ask: name it with --outside / --inside"; return 1; fi
    [ -n "$_pd" ] && [ "$_pd" -le 9 ] || _pd=1
    [ "$_pn" -gt 9 ] && cc_show "$C_YEL" "  [*] only the first 9 are offered: name it with --outside / --inside"
    _pf=$1; _pq=$2; _pa=${5:-}; _pi=0; set --
    while IFS= read -r _x; do _pi=$((_pi + 1)); [ "$_pi" -le 9 ] && set -- "$@" "$_pi=$_x"; done <"$_pf"
    [ "$_pa" = all ] && [ "$_pn" -gt 1 ] && set -- "$@" "a=all of them (scored servers in more than one)"
    cc_choose "$_pq" "$_pd" "$@"
    if [ "$CC_CHOICE" = a ]; then CC_PICK=all; else CC_PICK=$(sed -n "${CC_CHOICE}p" "$_pf"); fi
}
# mask PREFIX -> dotted mask (no "^": busybox awk may lack math)
mask() { awk -v p="$1" 'BEGIN { for (k = 1; k <= 4; k++) { b = p - 8 * (k - 1); if (b > 8) b = 8; if (b < 0) b = 0; v = 256; r = 1; for (i = 0; i < 8 - b; i++) r *= 2; v = (b == 0) ? 0 : 256 - r; printf "%s%s", (k > 1 ? "." : ""), v } }'; }
addr() { case "$1" in */*) printf '%s %s' "${1%/*}" "$(mask "${1#*/}")" ;; *) printf '%s 255.255.255.255' "$1" ;; esac; }
cidr() { case "$1" in */*) printf '%s' "$1" ;; *) printf '%s/32' "$1" ;; esac; }
# cidrs "a,b" -> "a/32 b/24 " (Palo Alto lists)
cidrs() { for _cx in $(printf '%s' "$1" | tr ',' ' '); do printf '%s ' "$(cidr "$_cx")"; done; }
# natx LIST -> the outside (NAT) names of the boxes in LIST, from $W/nat ("INSIDE-IP NAME" lines)
natx() { for _cx in $(printf '%s' "$1" | tr ',' ' '); do awk -v i="$_cx" '$1 == i { printf "%s ", $2 }' "$W/nat"; done; }
# shownat DEVICE -> say which NAT names were found, or warn that none were
shownat() {
    if grep -q ' SKIP$' "$W/nat"; then
        grep ' SKIP$' "$W/nat" | while read -r _ni _nn; do cc_show "$C_RED" "  [!] NAT to $_ni uses a name with spaces: not added. Rename it, or add its outside address with --allow, or the scorer may be blocked"; done
        grep -v ' SKIP$' "$W/nat" >"$W/nat.n"; cat "$W/nat.n" >"$W/nat"
    fi
    if [ -s "$W/nat" ]; then
        while read -r _ni _nn; do cc_show "$C_CYN" "  [-] NAT: outside name $_nn leads to $_ni: it is added to the rules for $_ni (the firewall matches the outside name)"; done <"$W/nat"
        { printf '%s: NAT found, these outside names are added to the scored and ping rules:\n' "$1"; sed 's/^\([^ ]*\) \(.*\)/  \2 -> \1/' "$W/nat"; printf '\n'; } >>"$CC_RUN_DIR/plan.txt"
    else
        cc_show "$C_GRY" "  [-] no NAT to the scored boxes found: the rules use their inside addresses"
    fi
}
# build VENDOR DEVICE -> $W/fix.DEV (the rules) and $W/undo.DEV (take them out again)
: >"$W/ready"
while IFS='|' read -r _n _a _v _u _p; do
    cc_show "" ""; cc_show "$C_CYN" "  $_n ($_a, $_v)"
    case "$_v" in
        pfsense|opnsense)
            cc_show "$C_YEL" "  [*] no safe command line: do it in the web GUI (Firewall > Rules > WAN), top to bottom, the rules in plan.txt; block rule last with logging on"
            { printf '%s (%s): web GUI, Firewall > Rules > WAN, top to bottom:\n' "$_n" "$_v"; awk -F"$US" '{ print "  " $7 }' "$W/rules"; printf '\n'; } >>"$CC_RUN_DIR/plan.txt"; continue ;;
        cisco-ios|vyos)
            cc_show "$C_YEL" "  [*] $_v is not built in NW-20 yet: the plan is in plan.txt to enter by hand"
            { printf '%s (%s): enter by hand, in this order:\n' "$_n" "$_v"; awk -F"$US" '{ print "  " $7 }' "$W/rules"; printf '\n'; } >>"$CC_RUN_DIR/plan.txt"; continue ;;
    esac
    if ! cc_guard host "$_a" || ! cc_guard host "$_n"; then cc_show "$C_GRY" "  protected device, skipped"; continue; fi
    if ! readdev "$_v" "$_u" "$_a" "$_p" "$W/raw.$_n"; then cc_show "$C_RED" "  [x] could not log in as $_u ($(grep -v '^$' "$W/err" | tail -n 1 | cut -c1-70))"; continue; fi
    _raw="$W/raw.$_n"; tr -d '\r' <"$_raw" | sed 's/^[A-Za-z0-9_.@()-]*[>#] *//' >"$_raw.c"
    : >"$W/fix.$_n"; : >"$W/undo.$_n"; _ok=1
    case "$_v" in
    paloalto)
        sed -n 's/^set zone \([^ ]*\) .*/\1/p' "$_raw.c" | awk '!s[$0]++' >"$W/zones"
        pick "$W/zones" "$_n: which zone is OUTSIDE (where red team and the scorer come from)?" 'untrust|outside|wan|internet|external' "$OUTSIDE" || { _ok=0; cc_show "$C_RED" "  [x] no zones read"; }
        _out=$CC_PICK
        grep -vxF "$_out" "$W/zones" >"$W/zin"
        pick "$W/zin" "$_n: which zone are the scored servers in?" 'trust|inside|lan|dmz|server' "$INSIDE" all || _ok=0
        _in=$CC_PICK; [ "$_in" = all ] && _in="[ $(tr '\n' ' ' <"$W/zin")]"
        # an earlier run's bt- rules out first ("set" on a rule that is there adds to its lists)
        awk '$1 == "set" && $2 == "rulebase" && $3 == "security" && $4 == "rules" && $5 ~ /^bt-/ && !s[$5]++ { print "delete rulebase security rules " $5 }' "$_raw.c" >"$W/oldbt"
        if [ -s "$W/oldbt" ]; then cc_show "$C_YEL" "  [*] bt- rules from an earlier run are there: they are replaced"; cat "$W/oldbt" >>"$W/fix.$_n"; fi
        awk '/^set rulebase security rules / { r = $5; if (!(r in s)) { s[r] = 1; o[++n] = r } a[r] = a[r] " " $0 }
             END { for (i = 1; i <= n; i++) { t = a[o[i]]; if (o[i] !~ /^bt-/ && t ~ / source any/ && t ~ / destination any/ && t ~ / application any/ && t ~ / service any/ && t ~ / action allow/) print o[i] } }' "$_raw.c" >"$W/anyany"
        while IFS= read -r _r; do cc_show "$C_YEL" "  [*] existing rule \"$_r\" allows anything to anything: it ends up BELOW the bt- rules, so it no longer lets the rest in"; done <"$W/anyany"
        # Palo Alto matches the destination address from BEFORE NAT: find the
        # outside address of each scored box (destination NAT, or a static
        # bi-directional source NAT) so the rule still matches the scorer.
        # (a quoted name with spaces is kept as one word; such a name is not used, only reported)
        awk 'index($0, "\"") { o = ""; q = 0; for (i = 1; i <= length($0); i++) { c = substr($0, i, 1); if (c == "\"") q = !q; o = o ((q && c == " ") ? "\001" : c) } $0 = o }
             $1 == "set" && $2 == "address" && $4 == "ip-netmask" { a = $5; sub(/\/32$/, "", a); ip[$3] = a }
             $1 == "set" && $2 == "rulebase" && $3 == "nat" && $4 == "rules" {
                 r = $5; k = $6; v = ""; for (i = 7; i <= NF; i++) if ($i != "[" && $i != "]") v = v " " $i
                 if (k == "destination") d[r] = d[r] v
                 else if (k == "source") s[r] = s[r] v
                 else if (k == "destination-translation" && $7 == "translated-address") dt[r] = $8
                 else if (k == "source-translation" && $7 == "static-ip" && $8 == "translated-address") st[r] = $9
                 else if (k == "source-translation" && $7 == "static-ip" && $8 == "bi-directional" && $9 == "yes") bi[r] = 1
                 rs[r] = 1 }
             END { for (r in rs) {
                 if (r in dt) { t = (dt[r] in ip) ? ip[dt[r]] : dt[r]; sub(/\/32$/, "", t); n = split(d[r], x, " "); for (i = 1; i <= n; i++) if (x[i] != "any") print t, (x[i] ~ /\001/ ? "SKIP" : x[i]) }
                 if ((r in st) && (r in bi)) { n = split(s[r], x, " "); for (i = 1; i <= n; i++) { t = (x[i] in ip) ? ip[x[i]] : x[i]; sub(/\/32$/, "", t); print t, (st[r] ~ /\001/ ? "SKIP" : st[r]) } } } }' "$_raw.c" | awk '!s[$0]++' | sort >"$W/nat"
        shownat "$_n"
        # services, then rules, then move each to the top (last first)
        _th=""; [ "$THREAT" = y ] && _th=" profile-setting profiles virus default spyware default vulnerability default"
        while IFS="$US" read -r _k _nm _s _d _t _ud _w; do
            _svc=""
            [ -n "$_t" ] && { printf 'set service %s-t protocol tcp port %s\n' "$_nm" "$_t" >>"$W/fix.$_n"; _svc="$_svc $_nm-t"; printf 'delete service %s-t\n' "$_nm" >>"$W/undo.$_n"; }
            [ -n "$_ud" ] && { printf 'set service %s-u protocol udp port %s\n' "$_nm" "$_ud" >>"$W/fix.$_n"; _svc="$_svc $_nm-u"; printf 'delete service %s-u\n' "$_nm" >>"$W/undo.$_n"; }
            _src=any; [ "$_s" != any ] && _src="[ $(cidrs "$_s")]"
            _dst=any; [ "$_d" != any ] && _dst="[ $(cidrs "$_d")]"
            case "$_k" in scored|ping) [ "$_d" != any ] && _dst="[ $(cidrs "$_d")$(natx "$_d")]" ;; esac
            case "$_k" in
                team)     _r="from any to any source $_src destination any application any service any action allow" ;;  # posix-ok: Palo Alto words, not the shell
                scored)   _r="from $_out to $_in source any destination $_dst application any service [$_svc ] action allow log-end yes$_th" ;;
                ping)     _r="from $_out to $_in source any destination $_dst application ping service application-default action allow" ;;
                outallow) _r="from $_in to $_out source $_src destination $_dst application any service [$_svc ] action allow" ;;  # posix-ok: Palo Alto words, not the shell
                outdeny)  _r="from $_in to $_out source $_src destination any application any service any action deny log-end yes" ;;  # posix-ok: Palo Alto words, not the shell
                indeny)   _r="from $_out to $_in source any destination any application any service any action deny log-end yes" ;;
            esac
            printf 'set rulebase security rules %s %s\n' "$_nm" "$_r" >>"$W/fix.$_n"
        done <"$W/rules"
        awk -F"$US" '{ l[NR] = $2 } END { for (i = NR; i > 0; i--) print "move rulebase security rules " l[i] " top" }' "$W/rules" >>"$W/fix.$_n"
        awk -F"$US" '{ print "delete rulebase security rules " $2 }' "$W/rules" >"$W/u1"; cat "$W/u1" "$W/undo.$_n" >"$W/u2"; cat "$W/u2" >"$W/undo.$_n"
        ;;
    cisco-asa)
        awk '/^interface / { i = $2 } $1 == "nameif" { print $2 }' "$_raw.c" >"$W/zones"
        pick "$W/zones" "$_n: which interface (nameif) is OUTSIDE?" 'outside|wan|internet|untrust' "$OUTSIDE" || { _ok=0; cc_show "$C_RED" "  [x] no interfaces read"; }
        _out=$CC_PICK
        grep -vxF "$_out" "$W/zones" >"$W/zin"
        pick "$W/zin" "$_n: which interface are the scored servers behind? (used for the outgoing limits)" 'inside|lan|dmz|server' "$([ "$INSIDE" = all ] || echo "$INSIDE")" || _ok=0
        _in=$CC_PICK
        _oldin=$(awk -v i="$_out" '$1 == "access-group" && $3 == "in" && $5 == i { print $2; exit }' "$_raw.c")
        _oldout=$(awk -v i="$_in" '$1 == "access-group" && $3 == "in" && $5 == i { print $2; exit }' "$_raw.c")
        # A second run finds our own lists bound: the ORIGINAL ones are in the first run's record.
        if [ -f "$CC_OUT/nw20-$_n.undo" ]; then
            [ "$_oldin" = BT-IN ] && _oldin=$(awk -v i="$_out" '$1 == "access-group" && $2 != "BT-IN" && $5 == i { print $2; exit }' "$CC_OUT/nw20-$_n.undo")
            [ "$_oldout" = BT-OUT ] && _oldout=$(awk -v i="$_in" '$1 == "access-group" && $2 != "BT-OUT" && $5 == i { print $2; exit }' "$CC_OUT/nw20-$_n.undo")
        fi
        [ "$_oldin" = BT-IN ] && _oldin=""; [ "$_oldout" = BT-OUT ] && _oldout=""
        [ -n "$_oldin" ] && [ "$_oldin" != BT-IN ] && cc_show "$C_YEL" "  [*] the outside interface uses access list $_oldin now: BT-IN takes its place (it is put back on undo)"
        grep -E '^access-list [^ ]+ (extended )?permit ip any4? any4?' "$_raw.c" | while IFS= read -r _l; do cc_show "$C_YEL" "  [*] existing: $_l (any to any)"; done
        printf 'configure terminal\nclear configure access-list BT-IN\n' >>"$W/fix.$_n"
        while IFS="$US" read -r _k _nm _s _d _t _ud _w; do
            case "$_k" in
                team) for _x in $(printf '%s' "$_s" | tr ',' ' '); do printf 'access-list BT-IN extended permit ip %s any\n' "$(addr "$_x")"; done ;;
                scored) for _pp in $(printf '%s' "$_t" | tr ',' ' '); do case "$_pp" in *-*) _q="range ${_pp%-*} ${_pp#*-}" ;; *) _q="eq $_pp" ;; esac; printf 'access-list BT-IN extended permit tcp any host %s %s\n' "$_d" "$_q"; done
                        for _pp in $(printf '%s' "$_ud" | tr ',' ' '); do case "$_pp" in *-*) _q="range ${_pp%-*} ${_pp#*-}" ;; *) _q="eq $_pp" ;; esac; printf 'access-list BT-IN extended permit udp any host %s %s\n' "$_d" "$_q"; done ;;
                ping) for _x in $(printf '%s' "$_d" | tr ',' ' '); do printf 'access-list BT-IN extended permit icmp any host %s echo\n' "$_x"; done
                      printf 'access-list BT-IN extended permit icmp any any echo-reply\naccess-list BT-IN extended permit icmp any any unreachable\naccess-list BT-IN extended permit icmp any any time-exceeded\n' ;;
                indeny) printf 'access-list BT-IN extended deny ip any any log\n' ;;
            esac
        done <"$W/rules" >>"$W/fix.$_n"
        grep -q "^indeny$US" "$W/rules" || printf 'access-list BT-IN extended permit ip any any\n' >>"$W/fix.$_n"
        printf 'access-group BT-IN in interface %s\n' "$_out" >>"$W/fix.$_n"
        if [ "$RESTRICT" = y ]; then
            printf 'clear configure access-list BT-OUT\n' >>"$W/fix.$_n"
            while IFS="$US" read -r _k _nm _s _d _t _ud _w; do
                case "$_k" in
                    team) for _x in $(printf '%s' "$_s" | tr ',' ' '); do printf 'access-list BT-OUT extended permit ip %s any\n' "$(addr "$_x")"; done ;;
                    outallow) for _x in $(printf '%s' "$_s" | tr ',' ' '); do
                                  for _pp in $(printf '%s' "$_t" | tr ',' ' '); do case "$_pp" in *-*) _q="range ${_pp%-*} ${_pp#*-}" ;; *) _q="eq $_pp" ;; esac; printf 'access-list BT-OUT extended permit tcp host %s host %s %s\n' "$_x" "$_d" "$_q"; done
                                  for _pp in $(printf '%s' "$_ud" | tr ',' ' '); do case "$_pp" in *-*) _q="range ${_pp%-*} ${_pp#*-}" ;; *) _q="eq $_pp" ;; esac; printf 'access-list BT-OUT extended permit udp host %s host %s %s\n' "$_x" "$_d" "$_q"; done; done ;;
                    outdeny) for _x in $(printf '%s' "$_s" | tr ',' ' '); do
                                 # this list is on the servers' interface: it sees traffic to the team too, so that stays open
                                 for _tm in $(printf '%s' "$TEAM" | tr ',' ' '); do printf 'access-list BT-OUT extended permit ip host %s %s\n' "$_x" "$(addr "$_tm")"; done
                                 printf 'access-list BT-OUT extended permit icmp host %s any echo-reply\naccess-list BT-OUT extended deny ip host %s any log\n' "$_x" "$_x"; done ;;
                esac
            done <"$W/rules" >>"$W/fix.$_n"
            [ -n "$_oldout" ] && cc_show "$C_YEL" "  [*] the servers' interface uses access list $_oldout now: BT-OUT takes its place and ends with 'permit ip any any' for everything that is not a scored server"
            cc_show "$C_YEL" "  [*] ASA: the outgoing block also stops the servers reaching OTHER inside networks (not the team): list those with --out-allow"
            printf 'access-list BT-OUT extended permit ip any any\naccess-group BT-OUT in interface %s\n' "$_in" >>"$W/fix.$_n"
        fi
        printf 'end\n' >>"$W/fix.$_n"
        {
            printf 'configure terminal\n'
            if [ -n "$_oldin" ] && [ "$_oldin" != BT-IN ]; then printf 'access-group %s in interface %s\n' "$_oldin" "$_out"; else printf 'no access-group BT-IN in interface %s\n' "$_out"; fi
            printf 'clear configure access-list BT-IN\n'
            if [ "$RESTRICT" = y ]; then
                if [ -n "$_oldout" ] && [ "$_oldout" != BT-OUT ]; then printf 'access-group %s in interface %s\n' "$_oldout" "$_in"; else printf 'no access-group BT-OUT in interface %s\n' "$_in"; fi
                printf 'clear configure access-list BT-OUT\n'
            fi
            printf 'end\nwrite memory\n'
        } >"$W/undo.$_n"
        ;;
    fortigate)
        awk '/^config system interface/ { s = 1 } s && $1 == "edit" { n = $2; gsub(/"/, "", n); print n } /^end/ { s = 0 }' "$_raw.c" >"$W/zones"
        pick "$W/zones" "$_n: which interface is OUTSIDE?" 'wan|outside|internet|port1' "$OUTSIDE" || { _ok=0; cc_show "$C_RED" "  [x] no interfaces read"; }
        _out=$CC_PICK
        grep -vxF "$_out" "$W/zones" >"$W/zin"
        pick "$W/zin" "$_n: which interface are the scored servers behind?" 'internal|lan|inside|dmz|port2' "$INSIDE" all || _ok=0
        _in=$CC_PICK; _inq="\"$_in\""; [ "$_in" = all ] && _inq=$(awk '{ printf "%s\"%s\"", (NR > 1 ? " " : ""), $0 }' "$W/zin")
        # A box reached through a virtual IP (VIP) only matches a policy that
        # names the VIP: find the VIPs that lead to each scored box.
        awk '/^config firewall vip/ { s = 1; next } s && /^end/ { s = 0 }
             s && $1 == "edit" { n = $0; sub(/^[ \t]*edit[ \t]+/, "", n); gsub(/"/, "", n); if (n ~ / /) n = "SKIP" }
             s && $1 == "set" && $2 == "mappedip" { m = $3; gsub(/"/, "", m); sub(/-.*/, "", m); print m, n }' "$_raw.c" | awk '!s[$0]++' | sort >"$W/nat"
        shownat "$_n"
        # the first policy that is not ours (ours are 9101-9199, from this or an earlier run)
        _first=$(awk '/^config firewall policy/ { s = 1; next } s && $1 == "edit" && ($2 < 9101 || $2 > 9199) { print $2; exit }' "$_raw.c")
        awk '/^config firewall policy/ { s = 1 } s && $1 == "edit" { id = $2; a = 0 } s && /set srcaddr "all"/ { a++ } s && /set dstaddr "all"/ { a++ } s && /set service "ALL"/ { a++ } s && /set action accept/ { a++ } s && $1 == "next" && a == 4 { print id }' "$_raw.c" >"$W/anyany"
        while IFS= read -r _r; do cc_show "$C_YEL" "  [*] existing policy $_r allows all to all: it ends up BELOW the bt- policies"; done <"$W/anyany"
        _id=9100; : >"$W/ids"; : >"$W/uaddr"; : >"$W/usvc"
        # an earlier run's policies (9101-9199) out first, so none is left over or half changed
        awk '/^config firewall policy/ { s = 1; next } s && /^end/ { s = 0 } s && $1 == "edit" && $2 >= 9101 && $2 <= 9199 { print $2 }' "$_raw.c" >"$W/oldids"
        if [ -s "$W/oldids" ]; then
            cc_show "$C_YEL" "  [*] bt- policies from an earlier run are there: they are replaced"
            { printf 'config firewall policy\n'; sed 's/^/delete /' "$W/oldids"; printf 'end\n'; } >>"$W/fix.$_n"
        fi
        while IFS="$US" read -r _k _nm _s _d _t _ud _w; do
            _id=$((_id + 1)); echo "$_id" >>"$W/ids"
            _sa='"all"'; _da='"all"'; _sv='"ALL"'
            if [ "$_s" != any ]; then _sa=""; for _x in $(printf '%s' "$_s" | tr ',' ' '); do printf 'config firewall address\nedit "bt-a-%s"\nset subnet %s\nnext\nend\n' "$_x" "$(addr "$_x")" >>"$W/fix.$_n"; echo "bt-a-$_x" >>"$W/uaddr"; _sa="$_sa \"bt-a-$_x\""; done; _sa=${_sa# }; fi
            if [ "$_d" != any ]; then _da=""; for _x in $(printf '%s' "$_d" | tr ',' ' '); do printf 'config firewall address\nedit "bt-a-%s"\nset subnet %s\nnext\nend\n' "$_x" "$(addr "$_x")" >>"$W/fix.$_n"; echo "bt-a-$_x" >>"$W/uaddr"; _da="$_da \"bt-a-$_x\""; done
                case "$_k" in scored|ping) for _x in $(natx "$_d"); do _da="$_da \"$_x\""; done ;; esac; _da=${_da# }; fi
            if [ -n "$_t$_ud" ]; then
                { printf 'config firewall service custom\nedit "%s"\n' "$_nm"
                  [ -n "$_t" ] && printf 'set tcp-portrange %s\n' "$(printf '%s' "$_t" | tr ',' ' ')"
                  [ -n "$_ud" ] && printf 'set udp-portrange %s\n' "$(printf '%s' "$_ud" | tr ',' ' ')"
                  printf 'next\nend\n'; } >>"$W/fix.$_n"
                echo "$_nm" >>"$W/usvc"; _sv="\"$_nm\""; fi
            case "$_k" in
                team|scored|ping|indeny) _si="\"$_out\""; _di=$_inq ;;
                outallow|outdeny)        _si=$_inq; _di="\"$_out\"" ;;
            esac
            [ "$_k" = ping ] && _sv='"PING"'
            _act=accept; case "$_k" in indeny|outdeny) _act=deny ;; esac
            {
                printf 'config firewall policy\nedit %s\nset name "%s"\nset srcintf %s\nset dstintf %s\nset srcaddr %s\nset dstaddr %s\nset service %s\nset schedule "always"\nset action %s\nset logtraffic all\n' "$_id" "$_nm" "$_si" "$_di" "$_sa" "$_da" "$_sv" "$_act"
                [ "$_k" = outallow ] && printf 'set nat enable\n'
                [ "$_k" = scored ] && [ "$THREAT" = y ] && printf 'set utm-status enable\nset ips-sensor "default"\nset av-profile "default"\n'
                printf 'next\nend\n'
            } >>"$W/fix.$_n"
        done <"$W/rules"
        if [ -n "$_first" ]; then
            { printf 'config firewall policy\n'; while IFS= read -r _x; do printf 'move %s before %s\n' "$_x" "$_first"; done <"$W/ids"; printf 'end\n'; } >>"$W/fix.$_n"
        fi
        # policies first (they use the objects), then the objects
        { printf 'config firewall policy\n'; while IFS= read -r _x; do printf 'delete %s\n' "$_x"; done <"$W/ids"; printf 'end\n'
          [ -s "$W/usvc" ] && { printf 'config firewall service custom\n'; awk '!s[$0]++ { printf "delete \"%s\"\n", $0 }' "$W/usvc"; printf 'end\n'; }
          [ -s "$W/uaddr" ] && { printf 'config firewall address\n'; awk '!s[$0]++ { printf "delete \"%s\"\n", $0 }' "$W/uaddr"; printf 'end\n'; }; } >"$W/undo.$_n"
        # the same address object may be made twice: keep the first
        awk '/^config firewall address$/ { buf = $0; getline; key = $0; buf = buf "\n" key; while ((getline l) > 0) { buf = buf "\n" l; if (l == "end") break } if (!(key in seen)) { seen[key] = 1; print buf } next } { print }' "$W/fix.$_n" >"$W/f.n" && cat "$W/f.n" >"$W/fix.$_n"
        ;;
    mikrotik)
        sed -n '/^===if/,/^===/p' "$_raw.c" | sed -n 's/.* name=\([^ ]*\).*/\1/p' | tr -d '"' >"$W/zones"
        pick "$W/zones" "$_n: which interface is OUTSIDE (WAN)?" 'wan|ether1|outside|internet' "$OUTSIDE" || { _ok=0; cc_show "$C_RED" "  [x] no interfaces read"; }
        _out=$CC_PICK
        _nf=$(sed -n '/^===filter/,$p' "$_raw.c" | grep ' chain=' | grep -vc 'comment="\{0,1\}bt-')
        _pb=""; [ "$_nf" -gt 0 ] && _pb=" place-before=0"
        grep -q 'comment=bt-\|comment="bt-' "$_raw.c" && cc_show "$C_YEL" "  [*] bt- rules from an earlier run are there: they are replaced"
        : >"$W/mt"
        printf '/ip firewall filter add chain=forward connection-state=established,related action=accept comment=bt-established\n' >>"$W/mt"
        while IFS="$US" read -r _k _nm _s _d _t _ud _w; do
            case "$_k" in
                team) for _x in $(printf '%s' "$_s" | tr ',' ' '); do printf '/ip firewall filter add chain=forward src-address=%s action=accept comment=%s\n' "$_x" "$_nm"; done ;;
                scored) [ -n "$_t" ] && printf '/ip firewall filter add chain=forward in-interface=%s dst-address=%s protocol=tcp dst-port=%s action=accept comment=%s\n' "$_out" "$_d" "$_t" "$_nm"
                        [ -n "$_ud" ] && printf '/ip firewall filter add chain=forward in-interface=%s dst-address=%s protocol=udp dst-port=%s action=accept comment=%s\n' "$_out" "$_d" "$_ud" "$_nm" ;;
                ping) for _x in $(printf '%s' "$_d" | tr ',' ' '); do printf '/ip firewall filter add chain=forward in-interface=%s dst-address=%s protocol=icmp icmp-options=8:0 action=accept comment=%s\n' "$_out" "$_x" "$_nm"; done ;;
                outallow) for _x in $(printf '%s' "$_s" | tr ',' ' '); do
                              [ -n "$_t" ] && printf '/ip firewall filter add chain=forward out-interface=%s src-address=%s dst-address=%s protocol=tcp dst-port=%s action=accept comment=%s\n' "$_out" "$_x" "$_d" "$_t" "$_nm"
                              [ -n "$_ud" ] && printf '/ip firewall filter add chain=forward out-interface=%s src-address=%s dst-address=%s protocol=udp dst-port=%s action=accept comment=%s\n' "$_out" "$_x" "$_d" "$_ud" "$_nm"; done ;;
                outdeny) for _x in $(printf '%s' "$_s" | tr ',' ' '); do printf '/ip firewall filter add chain=forward out-interface=%s src-address=%s action=drop log=yes log-prefix=bt-out comment=%s\n' "$_out" "$_x" "$_nm"; done ;;
                indeny) printf '/ip firewall filter add chain=forward in-interface=%s connection-state=new action=drop log=yes log-prefix=bt-in comment=%s\n' "$_out" "$_nm" ;;
            esac
        done <"$W/rules" >>"$W/mt"
        # remove an earlier run's bt- rules first; then add (on top: last first, each place-before=0)
        printf '/ip firewall filter remove [find comment~"^bt-"]\n' >"$W/fix.$_n"
        if [ -n "$_pb" ]; then awk -v pb="$_pb" '{ l[NR] = $0 pb } END { for (i = NR; i > 0; i--) print l[i] }' "$W/mt" >>"$W/fix.$_n"; else cat "$W/mt" >>"$W/fix.$_n"; fi
        printf '/ip firewall filter remove [find comment~"^bt-"]\n' >"$W/undo.$_n"
        ;;
    linux)
        sed -n '/^===if/,/^===/p' "$_raw.c" | awk -F': ' 'NF >= 2 && $1 ~ /^[0-9]+$/ { n = $2; sub(/@.*/, "", n); if (n != "lo") print n }' >"$W/zones"
        pick "$W/zones" "$_n: which interface is OUTSIDE?" 'wan|outside|eth0|ens3|ens18|enp' "$OUTSIDE" || { _ok=0; cc_show "$C_RED" "  [x] no interfaces read"; }
        _out=$CC_PICK
        grep -q 'table inet bt_fw' "$_raw.c" && cc_show "$C_YEL" "  [*] the bt_fw table from an earlier run is there: it is replaced"
        {
            printf 'table inet bt_fw\ndelete table inet bt_fw\ntable inet bt_fw {\n    chain forward {\n        type filter hook forward priority -10; policy accept;\n'
            printf '        ct state established,related accept comment "bt-established"\n'
            while IFS="$US" read -r _k _nm _s _d _t _ud _w; do
                case "$_k" in
                    team) printf '        ip saddr { %s } accept comment "%s"\n' "$(printf '%s' "$_s" | sed 's/,/, /g')" "$_nm" ;;
                    scored) [ -n "$_t" ] && printf '        iifname "%s" ip daddr %s tcp dport { %s } accept comment "%s"\n' "$_out" "$_d" "$(printf '%s' "$_t" | sed 's/,/, /g')" "$_nm"
                            [ -n "$_ud" ] && printf '        iifname "%s" ip daddr %s udp dport { %s } accept comment "%s"\n' "$_out" "$_d" "$(printf '%s' "$_ud" | sed 's/,/, /g')" "$_nm" ;;
                    ping) printf '        iifname "%s" ip daddr { %s } icmp type echo-request accept comment "%s"\n' "$_out" "$(printf '%s' "$_d" | sed 's/,/, /g')" "$_nm" ;;
                    outallow) [ -n "$_t" ] && printf '        oifname "%s" ip saddr { %s } ip daddr %s tcp dport { %s } accept comment "%s"\n' "$_out" "$(printf '%s' "$_s" | sed 's/,/, /g')" "$_d" "$(printf '%s' "$_t" | sed 's/,/, /g')" "$_nm"
                              [ -n "$_ud" ] && printf '        oifname "%s" ip saddr { %s } ip daddr %s udp dport { %s } accept comment "%s"\n' "$_out" "$(printf '%s' "$_s" | sed 's/,/, /g')" "$_d" "$(printf '%s' "$_ud" | sed 's/,/, /g')" "$_nm" ;;
                    outdeny) printf '        oifname "%s" ip saddr { %s } limit rate 10/minute log prefix "bt-fw-out " counter drop comment "%s"\n        oifname "%s" ip saddr { %s } drop\n' "$_out" "$(printf '%s' "$_s" | sed 's/,/, /g')" "$_nm" "$_out" "$(printf '%s' "$_s" | sed 's/,/, /g')" ;;
                    indeny) printf '        iifname "%s" limit rate 10/minute log prefix "bt-fw-in " counter drop comment "%s"\n        iifname "%s" drop\n' "$_out" "$_nm" "$_out" ;;
                esac
            done <"$W/rules"
            printf '    }\n}\n'
        } >"$W/nft.$_n"
        if cc_have nft && ! nft -c -f "$W/nft.$_n" >"$W/nftchk" 2>&1; then
            # A box where nft cannot run (no rights, a container) cannot check it: only a syntax error stops here.
            cat "$W/nftchk" >>"$CC_LOG"
            grep -qi 'syntax error\|unexpected' "$W/nftchk" && { _ok=0; cc_show "$C_RED" "  [x] nft refuses the ruleset: $(head -n 1 "$W/nftchk")"; }
        fi
        { printf "cat > /tmp/bt_fw.nft <<'BTNFT'\n"; cat "$W/nft.$_n"; printf "BTNFT\n"; printf "if [ \"\$(id -u)\" = 0 ]; then nft -f /tmp/bt_fw.nft; else sudo -n nft -f /tmp/bt_fw.nft; fi; _r=\$?; rm -f /tmp/bt_fw.nft; exit \$_r\n"; } >"$W/fix.$_n"
        printf 'if [ "$(id -u)" = 0 ]; then nft delete table inet bt_fw; else sudo -n nft delete table inet bt_fw; fi\n' >"$W/undo.$_n"
        ;;
    esac
    [ "$_ok" = 1 ] || { cc_show "$C_RED" "  [x] $_n: not built (see above)"; continue; }
    cp "$W/fix.$_n" "$CC_RUN_DIR/commands-$_n.txt"
    { printf '%s (%s): outside = %s%s\n' "$_n" "$_v" "$_out" "$([ -n "${_in:-}" ] && [ "$_v" != mikrotik ] && [ "$_v" != linux ] && echo ", servers = $_in")"
      printf '  top of the rule list, in this order:\n'; awk -F"$US" '{ printf "  %2d. %s\n", NR, $7 }' "$W/rules"
      printf '  everything below stays as it was\n  commands: commands-%s.txt\n\n' "$_n"; } >>"$CC_RUN_DIR/plan.txt"
    cc_show "$C_GRN" "  [ok] built: $NRULES rule(s) on top, outside = $_out; exact commands in commands-$_n.txt"
    printf '%s|%s|%s|%s|%s\n' "$_n" "$_a" "$_v" "$_u" "$_p" >>"$W/ready"
    _in=""
done <"$W/devices"

# ---- 5. Apply, check, confirm ------------------------------------------------------------
header "5/6  apply"
# probe ADDR PORT -> 0 if a TCP connection opens (nc, else bash /dev/tcp)
# (an nc without -z would say "down" for everything, so it is only used when it has -z)
NCZ=0; cc_have nc && nc -h 2>&1 | grep -qE -- '-z|\[-[A-Za-z0-9]*z' && NCZ=1
probe() {
    if [ "$NCZ" = 1 ]; then nc -z -w 3 "$1" "$2" >/dev/null 2>&1; return; fi
    if cc_have bash && cc_have timeout; then timeout 4 bash -c 'exec 3<>"/dev/tcp/$1/$2"' _ "$1" "$2" >/dev/null 2>&1; return; fi
    return 2
}
pinged() { ping -c 1 -W 2 "$1" >/dev/null 2>&1; }
# checks FILE -> one line per scored box:port and ping: "ADDR PORT up|down"
checks() {
    # own names: the apply loop uses _a and _u for the device
    while IFS="$US" read -r _ca _ct _cu _cn; do
        if pinged "$_ca"; then echo "$_ca ping up"; else echo "$_ca ping down"; fi
        for _cx in $(printf '%s' "$_ct" | tr ',' ' '); do
            _cp=${_cx%%-*}
            probe "$_ca" "$_cp"; _cr=$?
            case "$_cr" in 0) echo "$_ca $_cp up" ;; 2) echo "$_ca $_cp unknown" ;; *) echo "$_ca $_cp down" ;; esac
        done
    done <"$W/scored" >"$1"
}
# refused VENDOR FILE -> the first line where the device refused a command (empty: none)
refused() {
    case "$1" in
        paloalto)  _re='Invalid syntax|Unknown command|Server error|Commit failed|Validation Error|is not a valid reference|is invalid' ;;
        cisco-*)   _re='^ERROR:|% Invalid|% Incomplete|% Ambiguous|% Unknown' ;;
        fortigate) _re='Command fail|command parse error|entry not found|node_check_object fail|value parse error|Unknown action' ;;
        mikrotik)  _re='failure:|syntax error|bad command name|expected end of command|no such item|input does not match' ;;
        *)         _re='Error:|sudo: |command not found|Permission denied|Operation not permitted' ;;
    esac
    tr -d '\r' <"$2" | grep -iE "$_re" | head -n 1 | cut -c1-100
}
broke() { awk 'NR == FNR { b[$1 " " $2] = $3; next } b[$1 " " $2] == "up" && $3 == "down" { printf "%s:%s ", $1, $2 }' "$1" "$2"; }
pre()  { case "$1" in cisco-*) en "$1" ;; paloalto) printf 'set cli pager off\nconfigure\n' ;; esac; }
post() { case "$1" in paloalto) printf 'commit\n' ;; esac; }
save() { case "$1" in cisco-asa) printf 'write memory\n' ;; paloalto) printf 'exit\n' ;; esac; }
quit() { case "$1" in mikrotik) printf '/quit\n' ;; *) printf 'exit\n' ;; esac; }
verify_cmds() {
    case "$1" in
        cisco-*|paloalto) printf 'show clock\nexit\n' ;;
        fortigate) printf 'get system status\nexit\n' ;;
        mikrotik) printf '/system identity print\n/quit\n' ;;
        *) printf 'id\nexit\n' ;;
    esac
}
try_login() {
    verify_cmds "$1" >"$W/vin"; _tu=$2; _ta=$3; _tp=$4
    sshopts >"$W/opts"; set --; while IFS= read -r _o; do set -- "$@" "$_o"; done <"$W/opts"
    SSHPASS=$BT_NET_PASS "$SSHPASS_BIN" -e "$SSH" "$@" -p "$_tp" "$_tu@$_ta" <"$W/vin" >/dev/null 2>"$W/verr"
}
# undo_lines VENDOR DEVICE -> what takes the rules out (with config mode)
undo_lines() {
    case "$1" in
        paloalto) printf 'configure\n'; cat "$W/undo.$2"; printf 'commit\nexit\n' ;;
        mikrotik|linux) cat "$W/undo.$2" ;;
        *) cat "$W/undo.$2" ;;
    esac
}
write_undo() {   # write_undo VENDOR DEVICE ADDRESS USER PORT -> undo/DEVICE.sh and --out/nw20-DEVICE.undo
    mkdir -p "$CC_RUN_DIR/undo"; _uf="$CC_RUN_DIR/undo/$2.sh"
    undo_lines "$1" "$2" >"$CC_OUT/nw20-$2.undo"
    {
        printf '#!/bin/sh\n# Takes NW-20'"'"'s rules off %s.  Needs the device password in BT_NET_PASS.\n' "$2"
        printf '[ -n "$BT_NET_PASS" ] || { echo "set BT_NET_PASS to the device password first" >&2; exit 1; }\nSSHPASS=$BT_NET_PASS; export SSHPASS\n'
        if [ "$(read_mode "$1")" = exec ]; then
            printf "CMDS=\$(cat <<'CMDS'\n"; cat "$CC_OUT/nw20-$2.undo"; printf 'CMDS\n)\n'
            [ "$1" = mikrotik ] && printf 'CMDS=$(printf "%%s" "$CMDS" | tr "\\n" ";")\n'
            printf '%s -e %s %s-p %s %s "$CMDS" </dev/null\n' "$(cc_shquote "$SSHPASS_BIN")" "$(cc_shquote "$SSH")" "$(sshopts | while IFS= read -r _o; do printf '%s ' "$(cc_shquote "$_o")"; done)" "$5" "$(cc_shquote "$4@$3")"
        else
            printf '{\n'; case "$1" in cisco-*) [ "$ENABLE" = 1 ] && printf '    printf "enable\\n%%s\\n" "$BT_NET_ENABLE"\n' ;; esac
            printf "    cat <<'CMDS'\n"; cat "$CC_OUT/nw20-$2.undo"; printf 'exit\nCMDS\n'
            printf '} | %s -e %s %s-p %s %s\n' "$(cc_shquote "$SSHPASS_BIN")" "$(cc_shquote "$SSH")" "$(sshopts | while IFS= read -r _o; do printf '%s ' "$(cc_shquote "$_o")"; done)" "$5" "$(cc_shquote "$4@$3")"
        fi
        printf 'rm -f %s\n' "$(cc_shquote "$CC_OUT/nw20-$2.undo")"
    } >"$_uf"
    chmod 700 "$_uf"; printf '%s' "$_uf"
}
# putback -> take the rules off the device being changed ($_n ...): through the
# open session when it is still there, else a new one
putback() {
    if [ -n "$_spid" ] && kill -0 "$_spid" 2>/dev/null; then
        # Palo Alto: the open session is still in config mode
        { [ "$_v" = paloalto ] && printf 'exit\n'; undo_lines "$_v" "$_n"; quit "$_v"; } >&3 2>/dev/null; exec 3>&-; wait "$_spid" 2>/dev/null
    else
        [ -n "$_spid" ] && { exec 3>&- 2>/dev/null; wait "$_spid" 2>/dev/null; }
        undo_lines "$_v" "$_n" >"$W/un"; send "$_v" "$_u" "$_a" "$_p" "$W/un"
    fi
    rm -f "$CC_OUT/nw20-$_n.undo"
}
# Ctrl-C (or a kill) while a firewall is being changed: put it back first
CUR=""
onstop() {
    trap '' INT TERM HUP
    if [ -n "$CUR" ]; then
        printf '\n' >&2; cc_show "$C_RED" "  [x] stopped while $CUR was being changed - putting it back"
        putback; cc_show "$C_YEL" "  [*] $CUR: put back. Check it: the undo is $_uf"
    fi
    rm -rf "$W"; exit 130
}
trap onstop INT TERM HUP
NOK=0; NBAD=0; APPLIED=0; : >"$CC_RUN_DIR/checks.txt"
trap '' PIPE
if [ ! -s "$W/ready" ]; then cc_show "$C_GRY" "  No firewall to change."
elif [ "$CC_APPLY" != 1 ]; then
    cc_show "$C_GRY" "  Dry run: nothing was changed. Read plan.txt and commands-DEVICE.txt, then run again with --apply (ONE device first)."
    # shellcheck disable=SC2034  # read by cc_finish
    CC_N_WOULD=$(grep -c . "$W/ready")
else
    cc_show "" "  Checking every scored box:port and ping from this box first (the same checks run after the change)..."
    checks "$W/before"
    while IFS= read -r _l; do cc_show "" "    before: $_l"; done <"$W/before"
    grep -q ' unknown$' "$W/before" && cc_show "$C_YEL" "  [*] no nc (with -z) or bash + timeout here: ports cannot be checked, only ping"
    if grep -q ' ping up$' "$W/before" && ! grep -v ' ping ' "$W/before" | grep -q ' up$' && grep -v ' ping ' "$W/before" | grep -q .; then
        cc_show "$C_YEL" "  [*] no scored PORT answered from here, only ping: the automatic check only sees ping. Watch the scoreboard."
    fi
    if ! grep -q ' up$' "$W/before"; then
        cc_show "$C_RED" "  [!] NOTHING answered from this box before the change: the automatic check cannot protect the scored services."
        cc_ask "Go on anyway (you watch the scoreboard yourself)?" N "yes, go on" "no, stop - run it from a box that reaches the scored services" || { cc_show "$C_GRY" "  Stopped: nothing was changed."; : >"$W/ready"; }
    fi
    while IFS='|' read -r _n _a _v _u _p; do
        cc_show "" ""; cc_show "$C_CYN" "  -- $_n ($_v)"
        while IFS= read -r _l; do cc_show "" "    $_l"; done <<EOF
$(sed -n "/^$_n (/,/^\$/p" "$CC_RUN_DIR/plan.txt")
EOF
        cc_ask "Put these rules on $_n now?" Y "yes (checked right after; put back at once if a scored service stops answering)" "no, skip this firewall" || { cc_show "$C_GRY" "  skipped $_n"; continue; }
        APPLIED=1
        # the undo is written BEFORE anything is sent, so --remove works even if this run is killed
        _uf=$(write_undo "$_v" "$_n" "$_a" "$_u" "$_p")
        rm -f "$W/fifo"; mkfifo "$W/fifo"; _sess="$W/sess.$_n"; : >"$_sess"
        sshopts >"$W/opts"; set --; while IFS= read -r _o; do set -- "$@" "$_o"; done <"$W/opts"
        CUR=$_n; _spid=""
        if [ "$(read_mode "$_v")" = exec ]; then
            # MikroTik and Linux: the commands as one exec; the undo goes in a second session if needed
            SSHPASS=$BT_NET_PASS "$SSHPASS_BIN" -e "$SSH" "$@" -p "$_p" "$_u@$_a" "$(oneline "$_v" "$W/fix.$_n")" </dev/null >"$_sess" 2>&1; _sent=$?
        else
            SSHPASS=$BT_NET_PASS "$SSHPASS_BIN" -e "$SSH" "$@" -p "$_p" "$_u@$_a" <"$W/fifo" >"$_sess" 2>&1 &
            _spid=$!
            exec 3>"$W/fifo"
            { pre "$_v"; cat "$W/fix.$_n"; post "$_v"; } >&3 2>/dev/null
            _sent=0
        fi
        _w=$WAIT
        if [ "$_v" = paloalto ]; then
            # wait for the commit to finish (or fail), at most --commit-wait seconds, then --wait more
            _cw=0; _w=0
            while [ "$_cw" -lt "$CWAIT" ] && ! grep -qiE 'committed successfully|Commit failed|commit.*fail' "$_sess"; do nap 1; _cw=$((_cw + 1)); done
            grep -qi 'committed successfully' "$_sess" && _w=$WAIT
        fi
        nap "$_w"
        _keep=1; _why=""
        [ "$_sent" = 0 ] || { _keep=0; _why="the commands did not go through"; }
        _rf=$(refused "$_v" "$_sess")
        [ "$_keep" = 1 ] && [ -n "$_rf" ] && { _keep=0; _why="the firewall refused a command: $_rf"; }
        [ "$_keep" = 1 ] && [ "$_v" = paloalto ] && ! grep -qi 'committed successfully' "$_sess" && { _keep=0; _why="Palo Alto did not say the commit worked within $CWAIT seconds (--commit-wait)"; }
        [ "$_keep" = 1 ] && [ -n "$_spid" ] && ! kill -0 "$_spid" 2>/dev/null && { _keep=0; _why="the device closed the session"; }
        if [ "$_keep" = 1 ]; then
            checks "$W/after"
            _b=$(broke "$W/before" "$W/after")
            if [ -n "$_b" ]; then _keep=0; _why="these stopped answering: $_b"; fi
        fi
        if [ "$_keep" = 1 ] && ! try_login "$_v" "$_u" "$_a" "$_p"; then _keep=0; _why="a new login to the firewall fails"; fi
        if [ "$_keep" = 1 ] && [ "$CC_BATCH" != 1 ] && _cc_can_ask; then
            cc_show "$C_YEL" "  [*] Every scored service that answered before still answers from here. Now look at the SCOREBOARD (and a service from outside if you can)."
            CC_TIMER_DEADLINE=$(( $(cc_now) + TIMER ))
            cc_ask_keep || { _keep=0; _why="not confirmed"; }
            # shellcheck disable=SC2034  # read by the library's question timer
            CC_TIMER_DEADLINE=0
        fi
        if [ "$_keep" = 1 ]; then
            [ -n "$_spid" ] && { { save "$_v"; quit "$_v"; } >&3 2>/dev/null; exec 3>&-; wait "$_spid" 2>/dev/null; }
            CUR=""; cat "$_sess" >>"$CC_LOG"
            cc_undo_add "take NW-20's rules off $_n" "sh $(cc_shquote "$_uf")"
            NOK=$((NOK + 1)); cc_show "$C_GRN" "  [+] $_n: rules on, scored services still answer. Undo: sh $_uf  (or this script with --remove --apply)"
            { printf '%s: kept\n' "$_n"; sed 's/^/  after: /' "$W/after" 2>/dev/null; } >>"$CC_RUN_DIR/checks.txt"
        else
            cc_show "$C_RED" "  [x] $_n: $_why - putting it back"
            putback; CUR=""; cat "$_sess" >>"$CC_LOG"
            nap "$_w"
            checks "$W/after2"
            _b=$(broke "$W/before" "$W/after2")
            if [ -z "$_b" ]; then cc_show "$C_GRN" "  [+] $_n: put back; the scored services answer as before"
            else cc_show "$C_RED" "  [x] $_n: put back, but still not answering: $_b - run the undo by hand: sh $_uf"; fi
            NBAD=$((NBAD + 1))
            { printf '%s: put back (%s)\n' "$_n" "$_why"; sed 's/^/  after: /' "$W/after" 2>/dev/null; } >>"$CC_RUN_DIR/checks.txt"
        fi
    done <"$W/ready"
    sed 's/^/before: /' "$W/before" >>"$CC_RUN_DIR/checks.txt"
fi
# shellcheck disable=SC2034  # read by cc_finish
CC_N_DONE=$NOK
# shellcheck disable=SC2034  # read by cc_finish
CC_N_FAIL=$NBAD

# ---- 6. Summary ---------------------------------------------------------------------------
header "6/6  summary"
{
    printf '==========[ summary ]==========\n'
    printf 'NW-20 Firewall ruleset | %s\n' "$([ "$APPLIED" = 1 ] && echo APPLIED || echo 'DRY RUN - nothing changed')"
    printf 'Scored boxes: %d   Rules: %d   Outgoing limits: %s   Threat prevention: %s\n' "$(grep -c . "$W/scored")" "$NRULES" "$([ "$RESTRICT" = y ] && echo yes || echo no)" "$([ "$THREAT" = y ] && echo yes || echo no)"
    [ "$APPLIED" = 1 ] && printf 'Kept: %d   Put back: %d\n' "$NOK" "$NBAD"
    printf 'The plan in words: plan.txt   exact commands: commands-DEVICE.txt   checks: checks.txt\n'
    printf 'Take the rules out again: sh %s/undo/DEVICE.sh  or  NW-20 --device ... --remove --apply\n' "$CC_RUN_DIR"
    printf '\nNext: NW-01 again (the rules become the saved copy); watch the scoreboard; drops are logged with bt- in the firewall log.\n'
} >"$CC_RUN_DIR/summary.txt"
while IFS= read -r _l; do case "$_l" in ==*|NW-20*) cc_show "$C_CYN" "$_l" ;; *'Put back: '[1-9]*) cc_show "$C_RED" "$_l" ;; *) cc_show "" "$_l" ;; esac; done <"$CC_RUN_DIR/summary.txt"
rm -rf "$W"
cc_finish
