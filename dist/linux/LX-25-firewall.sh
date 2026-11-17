#!/bin/sh
# =============================================================================
# ID:       LX-25
# NAME:     Linux firewall builder
# ROLE:     Linux  (wave 2, first 15 minutes - run it LAST of the hardening)
# KIND:     changes - dry run unless --apply
# VERSION:  2.0.0
#
# PURPOSE
#   Shows every open port on the box, says in plain words what each one is
#   and which program (or script) is behind it, asks port by port whether to
#   keep it open or drop it (like sqlmap: Enter takes the default), then
#   builds a firewall that drops every incoming connection except what you
#   kept.
#
#   For each listening port it shows:
#     - the port, and whether it listens on every address or only on this
#       box itself (loopback - nobody outside can reach those anyway)
#     - the program, its pid, the account it runs as, and its full command
#       line (so "python3 /opt/app/server.py" shows the script)
#     - what that port normally is (SSH, web, mail, a database ...), and
#       whether it was a scored service in past competitions
#       (docs/ENVIRONMENT.md) or is on your protected list
#     - a recommendation: KEEP, DROP, or "find out what this is"
#
#   Always allowed: loopback, replies to connections the box made, ping
#   (every box has a ping check), DHCP replies, the scored ports on the
#   protected list, SSH, and everything from your team's addresses (--admin)
#   and the scoring hosts on the protected list.
#   IPv6 is dropped unless you keep it.  Outgoing traffic is left alone
#   unless you ask to limit it.
#
#   SAFETY
#     - It adds its OWN rules (nftables table "inet ccdc", or iptables chains
#       CCDC-IN/CCDC-OUT) and never flushes anyone else's: Docker, fail2ban,
#       firewalld and ufw keep their rules.
#     - The ruleset is checked by nft (-c) before it goes live.
#     - ROLLBACK TIMER: after --apply the rules are removed again after
#       --confirm-timeout seconds (default 120) unless someone confirms -
#       from a NEW ssh session, which proves new connections still get in:
#           sudo sh <run folder>/keep-firewall.sh
#       At a terminal it also asks; answering "y" removes the rules at once.
#     - The rules are NOT saved for reboot until you run --save, so a
#       reboot is a last-resort undo.
#
# USAGE
#   sudo sh LX-25-firewall.sh                          look and plan: asks, changes nothing
#   sudo sh LX-25-firewall.sh --apply                  ask, then load the rules
#   sudo sh LX-25-firewall.sh --apply --batch --admin 10.0.0.5     no questions
#   sudo sh LX-25-firewall.sh --save --apply           after confirming: keep across reboot
#   sudo sh LX-25-firewall.sh --remove --apply         take the rules out again
#
# OPTIONS  (each answers a question in advance)
#   --admin CIDR        your team's address or network: always allowed in,
#                       for everything (repeat)
#   --keep SPEC         keep these listening ports open: 80, 80/tcp, 53/udp
#                       (repeat or comma-separate)
#   --drop SPEC         drop these listening ports, same form
#   --allow SPEC        also open ports that are NOT listening now (a scored
#                       service that is down): PORT, PORT/tcp, FIRST-LAST/tcp
#   --ssh-from CIDR     allow SSH only from these sources (repeat).  Leave it
#                       out if the scoring engine checks SSH
#   --strict            default every port to DROP except scored ports,
#                       --keep/--allow, SSH and DHCP
#   --restrict-out      also limit OUTGOING traffic to DNS, NTP, HTTP(S),
#                       replies and the admin addresses (stops reverse shells;
#                       can break software that calls out)
#   --no-restrict-out   leave outgoing traffic alone (no question)
#   --keep-ipv6         do not drop IPv6
#   --drop-ipv6         drop IPv6 (no question)
#   --backend NAME      nft or iptables (default: nft when it works)
#   --confirm-timeout N seconds before the automatic rollback (default 120;
#                       0 = no timer, keep at once - only at the console)
#   --save              save the CURRENT ccdc rules for reboot and exit
#   --remove            remove the ccdc rules and exit
#                       (both are dry runs without --apply, like every change)
#   --no-color          no colours
#   --batch             no questions: take every default
#   --help              this text plus the common options
#
# OUTPUTS  (under --out, in firewall-N/)
#   output.txt          everything shown on screen, without colour
#   summary.txt         what stays open and why, what is dropped, timer status
#   ports.txt           every listening port: program, account, command, what
#                       it is, and what was decided
#   csv/ports.csv       the same as CSV
#   ruleset.nft / ruleset.iptables.sh   the exact rules
#   rollback.sh         removes the rules (also in the undo log)
#   keep-firewall.sh    run from a NEW session to cancel the rollback timer
#
# WHAT IT CHANGES  (only with --apply / --save / --remove)
#   The live firewall (own table/chains only).  --save also writes
#   /etc/ccdc-firewall.nft plus an include line in /etc/nftables.conf, or
#   saves iptables rules with the distribution's tool.
#
# DEPENDS ON
#   nft or iptables (+ ip6tables); ss or netstat for listening ports; /proc
#   for the program behind each port; sshd -T for the SSH port.  CCDC_NFT,
#   CCDC_IPTABLES, CCDC_IP6TABLES, CCDC_SS and CCDC_PROC may name stand-ins
#   (the tests use them).
#
# TESTED ON
#   Ubuntu 24.04 (nftables 1.0.9, iptables 1.8.10) under dash, bash, busybox
#   sh, ksh93, mksh and yash with stand-ins, and live: traffic from a separate
#   network namespace reaches allowed ports and is dropped on others; the
#   rollback timer removes the rules when nobody confirms.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - Run it LAST, after the other fixes, and keep a second session open.
#   - A scored service that is down while this runs is not listening, so it
#     is not in the list: open its port with --allow (or the question), or
#     put it on the protected list.
#   - "Scored in past competitions" comes from docs/ENVIRONMENT.md and is a
#     hint, not a fact: check the team packet.
#   - Without root the program behind another account's port cannot be read.
#   - Other firewalls still apply on top: a port this allows can still be
#     blocked by ufw or firewalld rules (the first section says if they run).
#   - FORWARD (routing) is never touched: routers and Docker keep working.
#
# DEBUGGING
#   --debug shows how every listening port was classified.  The rules are in
#   ruleset.nft / ruleset.iptables.sh; "nft list table inet ccdc" or
#   "iptables -S CCDC-IN" shows what is live.  Dropped packets are logged
#   with the prefix "CCDC-DROP" (journalctl -k | grep CCDC-DROP).
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

usage() {
    cat <<'USAGE'
LX-25 Linux firewall builder - see every open port, keep or drop each one
  sudo sh LX-25-firewall.sh             look and plan (asks; changes nothing)
  sudo sh LX-25-firewall.sh --apply     ask, then load the rules

  --admin CIDR         your team's address: always allowed in (repeatable)
  --keep SPEC          keep these listening ports open: 80, 80/tcp, 53/udp
  --drop SPEC          drop these listening ports
  --allow SPEC         also open ports not listening now: PORT[/tcp|/udp], FIRST-LAST/tcp
  --ssh-from CIDR      allow SSH only from these sources (repeatable)
  --strict             default to DROP for everything but scored ports, SSH, DHCP
  --restrict-out / --no-restrict-out   limit outgoing traffic, or leave it alone
  --keep-ipv6 / --drop-ipv6            allow or drop IPv6
  --backend nft|iptables
  --confirm-timeout N  seconds before automatic rollback (default 120, 0 = none)
  --save               save the current ccdc rules for reboot, then exit (with --apply)
  --remove             remove the ccdc rules, then exit (with --apply)
  --no-color           no colours
  --help               show this text

USAGE
    cc_usage_common
}

NL='
'
ALLOW=""; ADMIN=""; SSHFROM=""; STRICT=0; RESTOUT=""; KEEP6=""; BACKEND=""; TIMEOUT=120; MODE=build
KEEPS=""; DROPS=""; COLOR=1
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --allow)           [ $# -ge 2 ] || cc_die 2 "--allow needs a port"; ALLOW="$ALLOW,$2"; shift 2 ;;
        --keep)            [ $# -ge 2 ] || cc_die 2 "--keep needs a port"; KEEPS="$KEEPS,$2"; shift 2 ;;
        --drop)            [ $# -ge 2 ] || cc_die 2 "--drop needs a port"; DROPS="$DROPS,$2"; shift 2 ;;
        --admin)           [ $# -ge 2 ] || cc_die 2 "--admin needs an address"; ADMIN="$ADMIN$2$NL"; shift 2 ;;
        --ssh-from)        [ $# -ge 2 ] || cc_die 2 "--ssh-from needs an address"; SSHFROM="$SSHFROM$2$NL"; shift 2 ;;
        --strict)          STRICT=1; shift ;;
        --restrict-out)    RESTOUT=1; shift ;;
        --no-restrict-out) RESTOUT=0; shift ;;
        --keep-ipv6)       KEEP6=1; shift ;;
        --drop-ipv6)       KEEP6=0; shift ;;
        --backend)         [ $# -ge 2 ] || cc_die 2 "--backend needs nft or iptables"; BACKEND=$2; shift 2 ;;
        --confirm-timeout) [ $# -ge 2 ] || cc_die 2 "--confirm-timeout needs seconds"; TIMEOUT=$2; shift 2 ;;
        --save)            MODE=save; shift ;;
        --remove)          MODE=remove; shift ;;
        --no-color|--no-colour) COLOR=0; shift ;;
        --help|-h)         usage; exit 0 ;;
        *)                 cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
case "$TIMEOUT" in ''|*[!0-9]*) cc_die 2 "--confirm-timeout needs a whole number of seconds" ;; esac
case "$BACKEND" in ''|nft|iptables) ;; *) cc_die 2 "--backend must be nft or iptables" ;; esac
# valid_cidr ADDR -> IPv4 address or network (a.b.c.d or a.b.c.d/n), or IPv6.
valid_cidr() {
    printf '%s' "$1" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]|[12][0-9]|3[0-2]))?$|^[0-9a-fA-F:]+:[0-9a-fA-F:]*(/[0-9]{1,3})?$'
}
for _a in $ADMIN $SSHFROM; do valid_cidr "$_a" || cc_die 2 "not an address or network: $_a"; done
# parse_specs LIST -> "proto|first|last" lines on stdout for "80, 80/tcp,
#   53/udp, 9000-9010/tcp".  Returns 1 (and names the bad one in BADSPEC) on
#   anything that is not a port.
parse_specs() {
    BADSPEC=""
    for _s in $(printf '%s' "$1" | tr ',' ' '); do
        case "$_s" in
            */tcp|*/udp) _p=${_s%/*}; _pr=${_s#*/} ;;
            *) _p=$_s; _pr=both ;;
        esac
        case "$_p" in
            *-*) _f=${_p%-*}; _l=${_p#*-} ;;
            *) _f=$_p; _l=$_p ;;
        esac
        case "$_f$_l" in ''|*[!0-9]*) BADSPEC=$_s; return 1 ;; esac
        { [ "$_f" -ge 1 ] && [ "$_l" -le 65535 ] && [ "$_f" -le "$_l" ]; } || { BADSPEC=$_s; return 1; }
        if [ "$_pr" = both ]; then printf 'tcp|%s|%s\nudp|%s|%s\n' "$_f" "$_l" "$_f" "$_l"; else printf '%s|%s|%s\n' "$_pr" "$_f" "$_l"; fi
    done
    return 0
}
# The $( ) runs parse_specs in a subshell, so BADSPEC is found by running it
# again without one when it fails.
SPECS=$(parse_specs "$ALLOW") || { parse_specs "$ALLOW" >/dev/null; cc_die 2 "--allow: not a port or range (1-65535): $BADSPEC"; }
KEEPSPEC=$(parse_specs "$KEEPS") || { parse_specs "$KEEPS" >/dev/null; cc_die 2 "--keep: not a port or range (1-65535): $BADSPEC"; }
DROPSPEC=$(parse_specs "$DROPS") || { parse_specs "$DROPS" >/dev/null; cc_die 2 "--drop: not a port or range (1-65535): $BADSPEC"; }
# in_spec SPECLINES PROTO PORT -> true when the port is covered.
in_spec() { printf '%s\n' "$1" | awk -F'|' -v pr="$2" -v p="$3" '$1 == pr && p + 0 >= $2 + 0 && p + 0 <= $3 + 0 { f = 1 } END { exit !f }'; }

cc_init "LX-25" "Linux firewall builder" changes
cc_detect_os
[ "$CC_OS_KERNEL" = linux ] || cc_die 3 "this script is for Linux (nftables/iptables); use the BSD or Windows firewall scripts elsewhere"
{ [ "$CC_APPLY" = 1 ] || [ "$MODE" != build ]; } && cc_require_root
cc_use_numbered_dir firewall
# CSV goes in csv/; the run folder gets a readable ports.txt.
CC_CSV_DIR="$CC_RUN_DIR/csv"
mkdir -p "$CC_CSV_DIR" || cc_die 3 "cannot create $CC_CSV_DIR"
W="$CC_RUN_DIR/.work"
mkdir -p "$W" || cc_die 3 "cannot create $W"
cc_color_init
[ "$COLOR" = 1 ] || { C_RED=""; C_YEL=""; C_GRN=""; C_CYN=""; C_GRY=""; C_OFF=""; }
OUTF="$CC_RUN_DIR/output.txt"
grep -v '\[NOTE\]\|\[DEBUG\]' "$CC_LOG" >"$OUTF" 2>/dev/null || : >"$OUTF"
# shellcheck disable=SC2034  # CC_TEE is read by the library's log functions
CC_TEE=$OUTF
header() { cc_show "" ""; cc_show "$C_CYN" "==========[ $1 ]=========="; }

# ---- Tools ---------------------------------------------------------------------
NFT=${CCDC_NFT:-$(cc_which nft)} || NFT=""
IPT=${CCDC_IPTABLES:-$(cc_which iptables)} || IPT=""
IP6T=${CCDC_IP6TABLES:-$(cc_which ip6tables)} || IP6T=""
SS=${CCDC_SS:-$(cc_which ss)} || SS=""
if [ -z "$BACKEND" ]; then
    if [ -n "$NFT" ] && "$NFT" list tables >/dev/null 2>&1; then BACKEND=nft
    elif [ -n "$IPT" ]; then BACKEND=iptables
    else cc_die 3 "neither nft nor iptables works here"; fi
fi
[ "$BACKEND" = nft ] && [ -z "$NFT" ] && cc_die 3 "nft not found"
[ "$BACKEND" = iptables ] && [ -z "$IPT" ] && cc_die 3 "iptables not found"
cc_debug "backend: $BACKEND nft=$NFT iptables=$IPT ss=$SS"

# The commands that remove our rules; used by --remove, the undo log and the timer.
ROLLBACK="$CC_RUN_DIR/rollback.sh"
{
    printf '#!/bin/sh\n# Removes the CCDC firewall rules made by LX-25. Other rules are not touched.\n'
    if [ "$BACKEND" = nft ]; then
        printf '%s list table inet ccdc >/dev/null 2>&1 && %s delete table inet ccdc\n' "$NFT" "$NFT"
    else
        for _t in "$IPT" "$IP6T"; do
            [ -n "$_t" ] || continue
            printf 'while %s -D INPUT -j CCDC-IN 2>/dev/null; do :; done\n' "$_t"
            printf 'while %s -D OUTPUT -j CCDC-OUT 2>/dev/null; do :; done\n' "$_t"
            printf '%s -F CCDC-IN 2>/dev/null; %s -X CCDC-IN 2>/dev/null\n' "$_t" "$_t"
            printf '%s -F CCDC-OUT 2>/dev/null; %s -X CCDC-OUT 2>/dev/null\n' "$_t" "$_t"
        done
    fi
    printf 'echo "CCDC firewall rules removed"\n'
} >"$ROLLBACK"
chmod 700 "$ROLLBACK"

# ---- --remove and --save ----------------------------------------------------------
if [ "$MODE" = remove ]; then
    cc_run "remove the CCDC firewall rules" sh "$ROLLBACK"
    cc_finish
fi
if [ "$MODE" = save ]; then
    if [ "$BACKEND" = nft ]; then
        "$NFT" list table inet ccdc >"$W/live.nft" 2>/dev/null || cc_die 3 "no ccdc table is live: nothing to save (apply and confirm first)"
        { printf 'table inet ccdc\ndelete table inet ccdc\n'; cat "$W/live.nft"; } >"$W/save.nft"
        cc_backup_file /etc/ccdc-firewall.nft || cc_die 5 "backup failed"
        cc_run "save the rules to /etc/ccdc-firewall.nft" cp "$W/save.nft" /etc/ccdc-firewall.nft
        if [ -f /etc/nftables.conf ]; then
            if ! grep -q 'include "/etc/ccdc-firewall.nft"' /etc/nftables.conf; then
                cc_backup_file /etc/nftables.conf || cc_die 5 "backup failed"
                cc_run "load them at boot (include line in /etc/nftables.conf)" sh -c 'printf "\ninclude \"/etc/ccdc-firewall.nft\"\n" >>/etc/nftables.conf'
            fi
            [ "$CC_INIT" = systemd ] && cc_run "enable the nftables service at boot" systemctl enable nftables
        else
            cc_warn "no /etc/nftables.conf: load /etc/ccdc-firewall.nft at boot yourself (nft -f /etc/ccdc-firewall.nft)"
        fi
    else
        if cc_have netfilter-persistent; then cc_run "save iptables rules (netfilter-persistent)" netfilter-persistent save
        elif [ -d /etc/sysconfig ]; then
            cc_backup_file /etc/sysconfig/iptables
            cc_run "save iptables rules to /etc/sysconfig/iptables" sh -c 'iptables-save >/etc/sysconfig/iptables'
        else cc_warn "no iptables save tool found (install iptables-persistent, or add iptables-restore to boot)"; fi
    fi
    cc_finish
fi

cc_show "$C_CYN" "LX-25 Linux firewall | host $CC_HOST | $([ "$CC_APPLY" = 1 ] && echo 'APPLY: rules are loaded after the questions' || echo 'DRY RUN: nothing is changed') | results in $CC_RUN_DIR"
cc_show "" "Legend: ${C_GRN}KEEP${C_OFF} stays open   ${C_RED}DROP${C_OFF} blocked from outside   ${C_YEL}CHECK${C_OFF} find out what it is   ${C_GRY}local${C_OFF} only this box can reach it"

# ---- 1/5  The firewall on this box right now ----------------------------------------
header "1/5  the firewall on this box right now"
cc_show "" "  This script uses: $BACKEND (its own $([ "$BACKEND" = nft ] && echo 'table "inet ccdc"' || echo 'chains CCDC-IN / CCDC-OUT'); other rules are never flushed)"
if [ "$BACKEND" = nft ] && "$NFT" list table inet ccdc >/dev/null 2>&1; then
    cc_show "$C_YEL" "  CCDC rules from an earlier run are LIVE now. Applying replaces them."
elif [ "$BACKEND" = iptables ] && "$IPT" -S CCDC-IN >/dev/null 2>&1 && [ -z "${CCDC_IPTABLES:-}" ]; then
    cc_show "$C_YEL" "  CCDC rules from an earlier run are LIVE now. Applying replaces them."
else
    cc_show "$C_GRY" "  No CCDC rules are loaded yet."
fi
# Other firewalls still apply on top of ours.  (Skipped with stand-in tools.)
if [ -z "${CCDC_SS:-}" ]; then
    if cc_have ufw && ufw status 2>/dev/null | grep -qi '^Status: active'; then cc_show "$C_YEL" "  ufw is ACTIVE: a port kept open here can still be blocked by ufw (ufw status)."; fi
    if cc_have firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then cc_show "$C_YEL" "  firewalld is RUNNING: a port kept open here can still be blocked by it (firewall-cmd --list-all)."; fi
    if [ -n "$IPT" ]; then
        _pol=$("$IPT" -S INPUT 2>/dev/null | sed -n 's/^-P INPUT //p'); _nr=$("$IPT" -S INPUT 2>/dev/null | grep -c '^-A')
        [ -n "$_pol" ] && cc_show "$C_GRY" "  iptables INPUT: policy $_pol, $_nr rule(s) already there (left alone)."
    fi
fi

# ---- 2/5  What is listening ----------------------------------------------------------
# $W/listen: "proto|address|port|process|pid"
: >"$W/listen"
if [ -n "$SS" ]; then
    "$SS" -ltnup 2>/dev/null | awk 'NR > 1 && ($1 == "tcp" || $1 == "udp") {
        a = $5; p = a; sub(/.*:/, "", p); sub(/:[^:]*$/, "", a); gsub(/[][]/, "", a); sub(/%.*/, "", a)
        pr = ""; if (match($0, /\(\("[^"]*"/)) pr = substr($0, RSTART + 3, RLENGTH - 4)
        pid = ""; if (match($0, /pid=[0-9]+/)) pid = substr($0, RSTART + 4, RLENGTH - 4)
        print $1 "|" a "|" p "|" pr "|" pid }' >"$W/listen"
elif cc_have netstat; then
    netstat -ltnup 2>/dev/null | awk '$1 ~ /^(tcp|udp)/ {
        pr0 = ($1 ~ /^tcp/) ? "tcp" : "udp"; a = $4; p = a; sub(/.*:/, "", p); sub(/:[^:]*$/, "", a)
        pp = ($1 ~ /^tcp/) ? $7 : $6; pid = pp; sub(/\/.*/, "", pid); sub(/^[0-9]+\//, "", pp); if (pid !~ /^[0-9]+$/) pid = ""
        print pr0 "|" a "|" p "|" pp "|" pid }' >"$W/listen"
else
    cc_warn "no ss or netstat: listening ports unknown, only scored ports and --allow are opened"
fi
# One line per proto/port: where it is bound (all addresses, this box only,
# or named addresses), the program and its pid.
awk -F'|' '
    { k = $1 "|" $3; if (!(k in seen)) { seen[k] = 1; order[++n] = k }
      if ($2 ~ /^127\.|^::1$|^::ffff:127\./) lo[k]++; else { pub[k]++; if ($2 ~ /^(0\.0\.0\.0|\*|::|)$/) all[k] = 1; else addrs[k] = addrs[k] (addrs[k] == "" ? "" : " ") $2 }
      if (proc[k] == "" && $4 != "") proc[k] = $4
      if (pid[k] == "" && $5 != "") pid[k] = $5 }
    END { for (i = 1; i <= n; i++) { k = order[i]; b = (!pub[k]) ? "local" : (all[k] ? "all" : addrs[k]); print k "|" b "|" proc[k] "|" pid[k] } }' "$W/listen" |
    sort -t'|' -k1,1 -k2,2n >"$W/ports0"

# SSH port: what sshd really uses (sshd -T), else what sshd listens on, else 22.
SSHPORTS=""
if _sshd=$(cc_which sshd) && [ -z "${CCDC_SS:-}" ]; then SSHPORTS=$("$_sshd" -T 2>/dev/null | awk '$1 == "port" { print $2 }' | sort -u | tr '\n' ' ' | sed 's/ *$//'); fi
[ -n "$SSHPORTS" ] || SSHPORTS=$(awk -F'|' '$1 == "tcp" && $4 ~ /^sshd/ { print $3 }' "$W/listen" | sort -u | tr '\n' ' ' | sed 's/ *$//')
[ -n "$SSHPORTS" ] || SSHPORTS=22

# Scored ports from the protected list: "80", "80/tcp", "53/udp".
PROTSPEC=""
if [ -n "$CC_PROTECTED" ]; then
    _pl=$(awk -F',' '{ gsub(/[ "\r]/, "") } tolower($1) == "port" { print $2 }' "$CC_PROTECTED" | tr '\n' ',')
    PROTSPEC=$(parse_specs "$_pl" 2>/dev/null) || PROTSPEC=""
fi

# port_info PROTO PORT -> what the port normally is.  Sets:
#   PI_NAME   short name                PI_DESC  one plain sentence
#   PI_CLASS  scoredhint | service | data | cleartext | unneeded | backdoor | unknown
# "scoredhint" = a scored service in past competitions (docs/ENVIRONMENT.md).
port_info() {
    PI_CLASS=service
    case "$1/$2" in
        tcp/20|tcp/21) PI_NAME=FTP; PI_DESC="FTP file transfer. Logins and files cross the network in clear text."; PI_CLASS=cleartext ;;
        tcp/22)   PI_NAME=SSH; PI_DESC="SSH: remote login to this box. Scored on the Linux boxes in past competitions."; PI_CLASS=scoredhint ;;
        tcp/23)   PI_NAME=Telnet; PI_DESC="Telnet: remote login in clear text. Almost never needed; SSH replaces it."; PI_CLASS=unneeded ;;
        tcp/25)   PI_NAME=SMTP; PI_DESC="SMTP: receives mail from other servers. Scored on the mail box in past competitions."; PI_CLASS=scoredhint ;;
        tcp/53|udp/53) PI_NAME=DNS; PI_DESC="DNS: answers name lookups. Scored in past competitions; other checks may depend on it."; PI_CLASS=scoredhint ;;
        udp/67)   PI_NAME="DHCP server"; PI_DESC="DHCP server: hands out addresses to other machines. Only needed if this box is the DHCP server." ;;
        udp/68)   PI_NAME="DHCP client"; PI_DESC="DHCP client: how this box gets its own address. Always allowed." ;;
        udp/69)   PI_NAME=TFTP; PI_DESC="TFTP: file transfer with no login at all. Rarely needed."; PI_CLASS=unneeded ;;
        tcp/80)   PI_NAME=HTTP; PI_DESC="HTTP: the web server. Scored (web store, webmail) in past competitions."; PI_CLASS=scoredhint ;;
        tcp/110)  PI_NAME=POP3; PI_DESC="POP3: mail clients fetch mail. Part of the mail service." ;;
        tcp/111|udp/111) PI_NAME=rpcbind; PI_DESC="rpcbind: helper for NFS file sharing. Not needed unless this box shares or mounts NFS."; PI_CLASS=unneeded ;;
        udp/123)  PI_NAME=NTP; PI_DESC="NTP: time server (chrony/ntpd). Scored on the Splunk box in past competitions."; PI_CLASS=scoredhint ;;
        tcp/135)  PI_NAME=RPC; PI_DESC="Windows-style RPC endpoint mapper (Samba). Needed only for Windows file/AD services." ;;
        udp/137|udp/138|tcp/139) PI_NAME=NetBIOS; PI_DESC="NetBIOS: old Windows file-sharing name service (Samba). Needed only if this box shares files with Windows." ;;
        tcp/143)  PI_NAME=IMAP; PI_DESC="IMAP: mail clients read mail. Scored on the mail box in past competitions."; PI_CLASS=scoredhint ;;
        udp/161)  PI_NAME=SNMP; PI_DESC="SNMP: monitoring. Often left with the default password 'public'. Rarely scored."; PI_CLASS=unneeded ;;
        tcp/389|tcp/636) PI_NAME=LDAP; PI_DESC="LDAP: directory / login service. Other boxes may log in through it." ;;
        tcp/443)  PI_NAME=HTTPS; PI_DESC="HTTPS: the web server over TLS. Scored (web store, webmail) in past competitions."; PI_CLASS=scoredhint ;;
        tcp/445)  PI_NAME=SMB; PI_DESC="SMB: Windows file sharing (Samba). Needed only if this box shares files." ;;
        tcp/465|tcp/587) PI_NAME="mail submission"; PI_DESC="Mail submission: mail clients send mail through it. Part of the mail service." ;;
        tcp/512|tcp/513|tcp/514) PI_NAME="rsh/rlogin"; PI_DESC="rexec/rlogin/rsh: remote commands in clear text with weak or no passwords. Not needed."; PI_CLASS=unneeded ;;
        udp/514)  PI_NAME=syslog; PI_DESC="syslog: receives logs from other machines. Needed only if this box is the log server." ;;
        tcp/631|udp/631) PI_NAME=CUPS; PI_DESC="CUPS: printing. Not needed on a server."; PI_CLASS=unneeded ;;
        tcp/993)  PI_NAME=IMAPS; PI_DESC="IMAP over TLS: mail clients read mail. Scored on the mail box in past competitions."; PI_CLASS=scoredhint ;;
        tcp/995)  PI_NAME=POP3S; PI_DESC="POP3 over TLS: mail clients fetch mail. Part of the mail service." ;;
        tcp/1433) PI_NAME="SQL Server"; PI_DESC="Microsoft SQL Server database. Scored on the database box in past competitions."; PI_CLASS=scoredhint ;;
        udp/1900) PI_NAME=UPnP; PI_DESC="UPnP/SSDP device discovery. Not needed on a server."; PI_CLASS=unneeded ;;
        tcp/2049|udp/2049) PI_NAME=NFS; PI_DESC="NFS file sharing. Needed only if other boxes mount folders from this one." ;;
        tcp/2375) PI_NAME="Docker API"; PI_DESC="Docker control port with NO login: anyone who reaches it is root on this box."; PI_CLASS=backdoor ;;
        tcp/3306) PI_NAME=MySQL; PI_DESC="MySQL/MariaDB database. Usually only the web app needs it; if that app is on THIS box, outsiders do not."; PI_CLASS=data ;;
        tcp/3389) PI_NAME=RDP; PI_DESC="Remote desktop (xrdp). Scored on Windows boxes in past competitions; on Linux only if you use it." ;;
        udp/5353) PI_NAME=mDNS; PI_DESC="mDNS (avahi): finds printers and devices on the local network. Not needed on a server."; PI_CLASS=unneeded ;;
        udp/5355|tcp/5355) PI_NAME=LLMNR; PI_DESC="LLMNR local name lookups (systemd-resolved). Not needed on a server."; PI_CLASS=unneeded ;;
        tcp/5432) PI_NAME=PostgreSQL; PI_DESC="PostgreSQL database. Usually only the web app needs it; if that app is on THIS box, outsiders do not."; PI_CLASS=data ;;
        tcp/5900|tcp/5901|tcp/5902) PI_NAME=VNC; PI_DESC="VNC remote desktop, often with a weak password. Rarely needed."; PI_CLASS=unneeded ;;
        tcp/5985|tcp/5986) PI_NAME=WinRM; PI_DESC="WinRM remote management. Scored on the Windows AD box in past competitions." ;;
        tcp/6379) PI_NAME=Redis; PI_DESC="Redis data store, often with no password. Usually only apps on this box need it."; PI_CLASS=data ;;
        tcp/8000) PI_NAME="web / Splunk"; PI_DESC="Web port 8000: the Splunk web page (scored in past competitions) or a development web server."; PI_CLASS=scoredhint ;;
        tcp/8080|tcp/8081|tcp/8443|tcp/8888) PI_NAME="web (alt)"; PI_DESC="An extra web port: an app server, admin panel or proxy. Find out which app before deciding." ;;
        tcp/8089) PI_NAME="Splunk mgmt"; PI_DESC="Splunk management port. Scored on the Splunk box in past competitions."; PI_CLASS=scoredhint ;;
        tcp/9200|tcp/9300) PI_NAME=Elasticsearch; PI_DESC="Elasticsearch, usually with no login. Usually only apps on this box need it."; PI_CLASS=data ;;
        tcp/9997) PI_NAME="Splunk data"; PI_DESC="Splunk receives logs from the forwarders here. The Splunk query check needs that data."; PI_CLASS=scoredhint ;;
        tcp/10000) PI_NAME=Webmin; PI_DESC="Webmin: web admin panel for the whole box. A favourite red-team target."; PI_CLASS=unneeded ;;
        tcp/11211|udp/11211) PI_NAME=memcached; PI_DESC="memcached cache with no login. Usually only apps on this box need it."; PI_CLASS=data ;;
        tcp/27017) PI_NAME=MongoDB; PI_DESC="MongoDB database, often with no login. Usually only apps on this box need it."; PI_CLASS=data ;;
        tcp/1337|tcp/4444|tcp/4445|tcp/5555|tcp/6666|tcp/6667|tcp/12345|tcp/31337|tcp/54321)
                  PI_NAME="backdoor-style"; PI_DESC="Not a normal service port: this number is a favourite for backdoors and reverse-shell listeners."; PI_CLASS=backdoor ;;
        *)        PI_NAME=unknown; PI_DESC="Not a well-known port. Look at the program and command shown with it to see what it is."; PI_CLASS=unknown ;;
    esac
}

# proc_info PID -> PR_USER, PR_CMD (full command line), PR_EXE, from /proc.
PROCROOT=${CCDC_PROC:-/proc}
proc_info() {
    PR_USER=""; PR_CMD=""; PR_EXE=""
    [ -n "$1" ] && [ -d "$PROCROOT/$1" ] || return 0
    # shellcheck disable=SC2012  # ls: the owner of /proc/PID is the account
    PR_USER=$(ls -ld "$PROCROOT/$1" 2>/dev/null | awk '{ print $3 }')
    PR_CMD=$(tr '\000' ' ' <"$PROCROOT/$1/cmdline" 2>/dev/null | tr '|\n\r\t' '/   ' | sed 's/ *$//' | cut -c1-160)
    PR_EXE=$(readlink "$PROCROOT/$1/exe" 2>/dev/null) || PR_EXE=""
}

header "2/5  open ports: what is listening, and what is behind each one"
# $W/ports: proto|port|bind|proc|pid|user|name|class|default|why|cmd   (default: keep, drop, auto-keep, auto-drop, local)
: >"$W/ports"
_shown=0
while IFS='|' read -r _pr _p _bind _proc _pid; do
    [ -n "$_p" ] || continue
    _shown=$((_shown + 1))
    port_info "$_pr" "$_p"; proc_info "$_pid"
    # Things about the program itself that outweigh the port number.
    _sus=""
    case "$PR_EXE" in *"(deleted)") _sus="its program file was deleted after it started" ;; /tmp/*|/var/tmp/*|/dev/shm/*|/run/shm/*) _sus="it runs from $PR_EXE, a world-writable folder" ;; esac
    case "$_proc" in nc|ncat|netcat|nc.openbsd|nc.traditional|socat) [ -n "$_sus" ] || _sus="a bare $_proc listener is a classic backdoor" ;; esac
    _is_ssh=0; [ "$_pr" = tcp ] && case " $SSHPORTS " in *" $_p "*) _is_ssh=1 ;; esac
    if [ "$_bind" = local ]; then _def=local; _why="only this box can reach it (loopback), so the firewall leaves it alone"
    elif [ "$_pr/$_p" = udp/68 ]; then _def=auto-keep; _why="DHCP replies keep this box's address"
    elif in_spec "$PROTSPEC" "$_pr" "$_p"; then _def=auto-keep; _why="scored: it is on your protected list"
    elif [ "$_is_ssh" = 1 ] && [ -n "$SSHFROM" ]; then _def=auto-keep; _why="SSH, but only from the --ssh-from addresses"
    elif [ "$_is_ssh" = 1 ]; then _def=auto-keep; _why="SSH: how you (and the SSH scoring check) get in"; PI_NAME=SSH; [ "$_p" = 22 ] || PI_DESC="SSH on a non-standard port (from sshd's own config): remote login to this box."
    elif in_spec "$KEEPSPEC" "$_pr" "$_p"; then _def=auto-keep; _why="you said keep (--keep)"
    elif in_spec "$DROPSPEC" "$_pr" "$_p"; then _def=auto-drop; _why="you said drop (--drop)"
    elif in_spec "$SPECS" "$_pr" "$_p"; then _def=auto-keep; _why="you said open it (--allow)"
    elif [ -n "$_sus" ]; then _def=drop; _why="suspicious: $_sus"
    elif [ "$STRICT" = 1 ]; then _def=drop; _why="--strict: not on the protected list"
    else
        case "$PI_CLASS" in
            scoredhint) _def=keep; _why="a scored service in past competitions" ;;
            service)    _def=keep; _why="a normal service; drop it if nothing outside this box uses it" ;;
            data)       _def=keep; _why="kept in case another box's app uses it; DROP it if only this box does" ;;
            cleartext)  _def=keep; _why="clear text, but someone may rely on it; drop it if nobody does" ;;
            unneeded)   _def=drop; _why="rarely needed on a server and often abused" ;;
            backdoor)   _def=drop; _why="investigate the program behind it" ;;
            *)          _def=keep; _why="unknown: kept so nothing scored breaks, but find out what it is" ;;
        esac
    fi
    printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' "$_pr" "$_p" "$_bind" "${_proc:-?}" "$_pid" "$PR_USER" "$PI_NAME" "$PI_CLASS" "$_def" "$_why" "$PR_CMD" >>"$W/ports"
    # The block for this port.
    case "$_bind" in all) _bt="all addresses" ;; local) _bt="this box only" ;; *) _bt="on $_bind" ;; esac
    case "$_def" in
        local)           _c=$C_GRY; _tag="local" ;;
        keep|auto-keep)  _c=$C_GRN; _tag="KEEP "; [ "$PI_CLASS" = unknown ] && [ "$_def" = keep ] && { _c=$C_YEL; _tag="CHECK"; } ;;
        *)               _c=$C_RED; _tag="DROP " ;;
    esac
    cc_show "$_c" "$(printf '  %-5s %-3s %-6s %-15s %-14s %s' "$_tag" "$_pr" "$_p" "$PI_NAME" "$_bt" "${_proc:-?}${_pid:+ (pid $_pid${PR_USER:+, runs as $PR_USER})}")"
    [ -n "$PR_CMD" ] && cc_show "$C_GRY" "        command: $PR_CMD"
    [ -n "$PR_EXE" ] && [ "${PR_CMD%% *}" != "$PR_EXE" ] && cc_show "$C_GRY" "        program: $PR_EXE"
    cc_show "" "        what:    $PI_DESC"
    cc_show "$_c" "        advice:  $_why"
    cc_debug "port $_pr/$_p bind=$_bind class=$PI_CLASS default=$_def"
done <"$W/ports0"
if [ "$_shown" = 0 ]; then cc_show "$C_YEL" "  Nothing is listening (or ss/netstat could not say). Only SSH, scored ports and --allow will be open."; fi
if ! cc_is_root && [ -z "${CCDC_SS:-}" ]; then cc_show "$C_YEL" "  Not root: programs owned by other accounts show as '?'. Run with sudo to see them."; fi

# ---- 3/5  Questions -------------------------------------------------------------------
header "3/5  questions (Enter takes the answer in capitals)"
# Your team's addresses.
if [ -z "$ADMIN" ] && _cc_can_ask; then
    cc_ask_text "Your team's addresses that must always get in, for everything (e.g. 10.0.0.5 10.0.0.0/24; Enter for none)" ""
    for _a in $(printf '%s' "$CC_ANSWER" | tr ',' ' '); do
        valid_cidr "$_a" || cc_die 2 "not an address or network: $_a"
        ADMIN="$ADMIN$_a$NL"
    done
fi
# Keep or drop, port by port.
: >"$W/decided"
while IFS='|' read -r _pr _p _bind _proc _pid _user _name _class _def _why _cmd; do
    case "$_def" in
        local) _dec=local ;;
        auto-keep) _dec=keep ;;
        auto-drop) _dec=drop ;;
        *)
            _d=Y; [ "$_def" = drop ] && _d=N
            # (cc_ask reads the terminal, not this loop's file.)
            if cc_ask "Keep $_pr/$_p open? ($_name, program $_proc${_user:+ as $_user}: $_why)" "$_d"; then _dec=keep; else _dec=drop; fi ;;
    esac
    printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' "$_pr" "$_p" "$_bind" "$_proc" "$_pid" "$_user" "$_name" "$_class" "$_dec" "$_why" "$_cmd" >>"$W/decided"
done <"$W/ports"
# Ports that are not listening now.
if [ -z "$ALLOW" ] && _cc_can_ask; then
    cc_ask_text "Other ports to open that are NOT listening now, e.g. a scored service that is down (8089/tcp 123/udp; Enter for none)" ""
    SPECS=$(parse_specs "$CC_ANSWER") || { parse_specs "$CC_ANSWER" >/dev/null; cc_die 2 "not a port or range (1-65535): $BADSPEC"; }
fi
# SSH from the team only: only offered when there are team addresses.
if [ -z "$SSHFROM" ] && [ -n "$ADMIN" ] && _cc_can_ask; then
    if cc_ask "Allow SSH ONLY from your team's addresses? (say no if the scoring engine checks SSH)" N; then SSHFROM=$ADMIN; fi
fi
if [ -z "$RESTOUT" ]; then
    RESTOUT=0
    cc_ask "Also limit OUTGOING traffic to DNS, NTP, web and your team? (stops reverse shells; can break apps that call out)" N && RESTOUT=1
fi
if [ -z "$KEEP6" ]; then
    KEEP6=1
    cc_ask "Block IPv6? (yes unless this box is scored or managed over IPv6)" Y && KEEP6=0
fi

# ---- Decide every port ---------------------------------------------------------------
# $W/allow: "proto|first|last|reason"
: >"$W/allow"; : >"$W/notes"
PCSV=$(cc_csv_new ports "proto,port,bound_to,program,pid,runs_as,what,decision,why,command")
add() { printf '%s|%s|%s|%s\n' "$1" "$2" "$3" "$4" >>"$W/allow"; }
add udp 68 68 "DHCP replies (keeps the address)"
[ "$KEEP6" = 1 ] && add udp 546 546 "DHCPv6 replies"
if [ -z "$SSHFROM" ]; then for _p in $SSHPORTS; do add tcp "$_p" "$_p" "SSH"; done; fi
printf '%s\n' "$PROTSPEC" | while IFS='|' read -r _pr _f _l; do [ -n "$_pr" ] && add "$_pr" "$_f" "$_l" "scored (protected list)"; done
printf '%s\n' "$SPECS" | while IFS='|' read -r _pr _f _l; do [ -n "$_pr" ] && add "$_pr" "$_f" "$_l" "opened by you (not listening now)"; done
NKEEP=0; NDROP=0; NLOCAL=0
while IFS='|' read -r _pr _p _bind _proc _pid _user _name _class _dec _why _cmd; do
    _is_ssh=0; [ "$_pr" = tcp ] && case " $SSHPORTS " in *" $_p "*) _is_ssh=1 ;; esac
    case "$_dec" in
        local) NLOCAL=$((NLOCAL + 1)); _dt="local only" ;;
        keep)
            NKEEP=$((NKEEP + 1)); _dt=KEEP
            if [ "$_is_ssh" = 1 ] && [ -n "$SSHFROM" ]; then _dt="team only"
            elif ! awk -F'|' -v pr="$_pr" -v p="$_p" '$1 == pr && p >= $2 && p <= $3 { f = 1 } END { exit !f }' "$W/allow"; then add "$_pr" "$_p" "$_p" "$_name ($_proc)"; fi ;;
        *)
            NDROP=$((NDROP + 1)); _dt=DROP
            printf '%s/%s  %s, program %s%s: %s\n' "$_pr" "$_p" "$_name" "$_proc" "${_user:+ as $_user}" "$_why" >>"$W/notes" ;;
    esac
    cc_csv_row "$PCSV" "$_pr" "$_p" "$_bind" "$_proc" "$_pid" "$_user" "$_name" "$_dt" "$_why" "$_cmd"
done <"$W/decided"
sort -t'|' -k1,1 -k2,2n -u "$W/allow" | awk -F'|' '!s[$1 "|" $2 "|" $3]++' >"$W/allow.u"
# Opened ports that are not in the listening list get a row too.
while IFS='|' read -r _pr _f _l _why; do
    [ "$_f" = "$_l" ] && grep -q "^$_pr|$_f|" "$W/decided" && continue
    cc_csv_row "$PCSV" "$_pr" "$([ "$_f" = "$_l" ] && echo "$_f" || echo "$_f-$_l")" "" "" "" "" "" KEEP "$_why (nothing is listening on it now)" ""
done <"$W/allow.u"
cc_csv_pretty "$PCSV" "$CC_RUN_DIR/ports.txt" 60
# FTP: the control port alone is not enough.  Passive-mode data connections
# come in on other ports that are not listening yet, so they would be dropped.
FTPNOTE=""
if awk -F'|' '$1 == "tcp" && $2 <= 21 && $3 >= 21 { f = 1 } END { exit !f }' "$W/allow.u" &&
   ! awk -F'|' '$1 == "tcp" && $2 >= 1024 && $3 > $2 { f = 1 } END { exit !f }' "$W/allow.u"; then
    FTPNOTE="FTP (21/tcp) is kept open, but passive-mode data ports are not: file listings and transfers may hang. Set a passive port range in the FTP server and open it, e.g. --allow 40000-40100/tcp"
fi
# Sources allowed for everything: --admin and protected hosts (scoring engine).
SOURCES=$(printf '%s' "$ADMIN" | grep .)
if [ -n "$CC_PROTECTED" ]; then
    _ph=$(awk -F',' '{ gsub(/[ "\r]/, "") } tolower($1) == "host" { print $2 }' "$CC_PROTECTED")
    for _h in $_ph; do valid_cidr "$_h" && SOURCES="$SOURCES$NL$_h"; done
fi
SOURCES=$(printf '%s\n' "$SOURCES" | grep . | sort -u)
SSHFROM=$(printf '%s' "$SSHFROM" | grep . | sort -u)
# grep . drops the empty line printf makes from an empty list, so an empty
# list stays empty (an empty "{ }" set is a syntax error in nft).
SRC4=$(printf '%s\n' "$SOURCES" | grep . | grep -v ':' | tr '\n' ' ' | sed 's/ *$//')
SRC6=$(printf '%s\n' "$SOURCES" | grep ':' | tr '\n' ' ' | sed 's/ *$//')
SSH4=$(printf '%s\n' "$SSHFROM" | grep . | grep -v ':' | tr '\n' ' ' | sed 's/ *$//')

# portset PROTO -> "a, b, c-d" for nft, from the allowed list.
portset() { awk -F'|' -v pr="$1" '$1 == pr { s = s (s ? ", " : "") ($2 == $3 ? $2 : $2 "-" $3) } END { print s }' "$W/allow.u"; }
# commaset "a b c" -> "a, b, c"
commaset() { printf '%s' "$1" | awk '{ for (i = 1; i <= NF; i++) s = s (i > 1 ? ", " : "") $i } END { print s }'; }
TCPSET=$(portset tcp); UDPSET=$(portset udp)

# ---- 3. The rules ---------------------------------------------------------------------
if [ "$BACKEND" = nft ]; then
    RULES="$CC_RUN_DIR/ruleset.nft"
    {
        printf '# CCDC firewall (LX-25) %s - its own table; other tables are untouched.\n' "$CC_HOST"
        printf 'table inet ccdc\ndelete table inet ccdc\n'
        printf 'table inet ccdc {\n'
        printf '    chain input {\n        type filter hook input priority 0; policy accept;\n'
        printf '        iif "lo" accept\n'
        printf '        ct state established,related accept\n'
        printf '        ct state invalid drop\n'
        if [ "$KEEP6" = 1 ]; then printf '        meta l4proto ipv6-icmp accept\n'
        else printf '        meta nfproto ipv6 drop comment "IPv6 blocked"\n'; fi
        printf '        meta l4proto icmp accept comment "ping and ICMP errors"\n'
        [ -n "$SRC4" ] && printf '        ip saddr { %s } accept comment "admin and scoring hosts"\n' "$(commaset "$SRC4")"
        [ -n "$SRC6" ] && [ "$KEEP6" = 1 ] && printf '        ip6 saddr { %s } accept comment "admin and scoring hosts"\n' "$(commaset "$SRC6")"
        if [ -n "$SSHFROM" ]; then
            for _p in $SSHPORTS; do printf '        ip saddr { %s } tcp dport %s accept comment "SSH from the team only"\n' "$(commaset "$SSH4")" "$_p"; done
        fi
        [ -n "$TCPSET" ] && printf '        tcp dport { %s } accept\n' "$TCPSET"
        [ -n "$UDPSET" ] && printf '        udp dport { %s } accept\n' "$UDPSET"
        printf '        limit rate 10/minute log prefix "CCDC-DROP " level info\n'
        printf '        drop\n    }\n'
        if [ "$RESTOUT" = 1 ]; then
            printf '    chain output {\n        type filter hook output priority 0; policy accept;\n'
            printf '        oif "lo" accept\n        ct state established,related accept\n'
            printf '        meta l4proto { icmp, ipv6-icmp } accept\n'
            printf '        udp dport { 53, 67, 123 } accept\n        tcp dport { 53, 80, 443 } accept\n'
            [ -n "$SRC4" ] && printf '        ip daddr { %s } accept\n' "$(commaset "$SRC4")"
            printf '        limit rate 10/minute log prefix "CCDC-OUT-DROP " level info\n        drop\n    }\n'
        fi
        printf '}\n'
    } >"$RULES"
else
    RULES="$CC_RUN_DIR/ruleset.iptables.sh"
    {
        printf '#!/bin/sh\n# CCDC firewall (LX-25) %s - its own chains; other chains are untouched.\n' "$CC_HOST"
        printf 'set -e\nT=%s\n' "$IPT"
        printf '$T -N CCDC-IN 2>/dev/null || $T -F CCDC-IN\n'
        printf '$T -A CCDC-IN -i lo -j ACCEPT\n'
        printf '$T -A CCDC-IN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n'
        printf '$T -A CCDC-IN -m conntrack --ctstate INVALID -j DROP\n'
        printf '$T -A CCDC-IN -p icmp -j ACCEPT\n'
        for _s in $SRC4; do printf '$T -A CCDC-IN -s %s -j ACCEPT\n' "$_s"; done
        if [ -n "$SSHFROM" ]; then for _p in $SSHPORTS; do for _s in $SSH4; do printf '$T -A CCDC-IN -s %s -p tcp --dport %s -j ACCEPT\n' "$_s" "$_p"; done; done; fi
        awk -F'|' '{ printf "$T -A CCDC-IN -p %s --dport %s -j ACCEPT\n", $1, ($2 == $3 ? $2 : $2 ":" $3) }' "$W/allow.u"
        printf '$T -A CCDC-IN -m limit --limit 10/min -j LOG --log-prefix "CCDC-DROP "\n'
        printf '$T -A CCDC-IN -j DROP\n'
        printf '$T -C INPUT -j CCDC-IN 2>/dev/null || $T -I INPUT 1 -j CCDC-IN\n'
        if [ "$RESTOUT" = 1 ]; then
            printf '$T -N CCDC-OUT 2>/dev/null || $T -F CCDC-OUT\n'
            printf '$T -A CCDC-OUT -o lo -j ACCEPT\n$T -A CCDC-OUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n$T -A CCDC-OUT -p icmp -j ACCEPT\n'
            printf '$T -A CCDC-OUT -p udp -m multiport --dports 53,67,123 -j ACCEPT\n$T -A CCDC-OUT -p tcp -m multiport --dports 53,80,443 -j ACCEPT\n'
            for _s in $SRC4; do printf '$T -A CCDC-OUT -d %s -j ACCEPT\n' "$_s"; done
            printf '$T -A CCDC-OUT -m limit --limit 10/min -j LOG --log-prefix "CCDC-OUT-DROP "\n$T -A CCDC-OUT -j DROP\n'
            printf '$T -C OUTPUT -j CCDC-OUT 2>/dev/null || $T -I OUTPUT 1 -j CCDC-OUT\n'
        fi
        if [ -n "$IP6T" ]; then
            printf 'T6=%s\n$T6 -N CCDC-IN 2>/dev/null || $T6 -F CCDC-IN\n' "$IP6T"
            printf '$T6 -A CCDC-IN -i lo -j ACCEPT\n$T6 -A CCDC-IN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n'
            if [ "$KEEP6" = 1 ]; then
                printf '$T6 -A CCDC-IN -p ipv6-icmp -j ACCEPT\n'
                for _s in $SRC6; do printf '$T6 -A CCDC-IN -s %s -j ACCEPT\n' "$_s"; done
                awk -F'|' '{ printf "$T6 -A CCDC-IN -p %s --dport %s -j ACCEPT\n", $1, ($2 == $3 ? $2 : $2 ":" $3) }' "$W/allow.u"
            fi
            printf '$T6 -A CCDC-IN -j DROP\n$T6 -C INPUT -j CCDC-IN 2>/dev/null || $T6 -I INPUT 1 -j CCDC-IN\n'
        fi
    } >"$RULES"
    chmod 700 "$RULES"
fi


# ---- 4/5  The plan ---------------------------------------------------------------------
header "4/5  the plan"
cc_show "$C_GRN" "  Stays open to everyone:"
awk -F'|' '{ printf "    %-4s %-12s %s\n", $1, ($2 == $3 ? $2 : $2 "-" $3), $4 }' "$W/allow.u" >"$W/open.txt"
while IFS= read -r _l; do cc_show "$C_GRN" "$_l"; done <"$W/open.txt"
cc_show "$C_GRN" "    ping (ICMP)       every box has a ping check"
if [ -s "$W/notes" ]; then
    cc_show "$C_RED" "  Dropped from outside (the program keeps running; nothing outside can reach it):"
    while IFS= read -r _l; do cc_show "$C_RED" "    $(printf '%s' "$_l" | cut -c1-200)"; done <"$W/notes"
fi
[ -n "$SOURCES" ] && cc_show "$C_CYN" "  Always allowed in, for everything: $(printf '%s' "$SOURCES" | tr '\n' ' ')"
[ -n "$SOURCES" ] || cc_show "$C_YEL" "  No team addresses given: you get in through SSH like everyone else."
[ -n "$SSHFROM" ] && cc_show "$C_YEL" "  SSH ($SSHPORTS) only from: $(printf '%s' "$SSHFROM" | tr '\n' ' ') - the scoring engine cannot check SSH unless it is one of them"
cc_show "" "  IPv6: $([ "$KEEP6" = 1 ] && echo 'allowed like IPv4' || echo 'dropped')   Outgoing: $([ "$RESTOUT" = 1 ] && echo 'limited to DNS, DHCP, NTP, web, replies and your team' || echo 'not limited')"
[ -n "$FTPNOTE" ] && cc_show "$C_YEL" "  [*] $FTPNOTE"
cc_show "$C_GRY" "  The exact rules: $RULES"

# ---- 5/5  Check, apply, start the rollback timer -----------------------------------
header "5/5  apply"
KEEPF="$CC_RUN_DIR/.keep"
# Names the run whose rules are live.  A rollback timer only acts while it
# still names its own run: without this, the timer of an earlier, unconfirmed
# run would later remove the rules of a newer run that WAS confirmed.
CURRENT="$CC_OUT/lx25-live-$CC_HOST"
KEEPSH="$CC_RUN_DIR/keep-firewall.sh"
_state="dry run - nothing changed"
if [ "$BACKEND" = nft ] && ! "$NFT" -c -f "$RULES" >"$W/check" 2>&1; then
    cat "$W/check" >>"$CC_LOG"
    cc_err "nft rejected the ruleset (nothing applied): $(head -n 1 "$W/check")"
    CC_N_FAIL=$((CC_N_FAIL + 1))
    _state="FAILED: nft -c rejected the ruleset (see the log)"
elif [ "$CC_APPLY" = 1 ] && ! cc_ask "Load these rules now? (they are removed again in ${TIMEOUT}s unless you confirm from a NEW session)" Y; then
    CC_APPLY=0
    _state="not loaded: you said no at the last question"
    cc_show "$C_GRY" "  Not loaded. The plan and rules are in $CC_RUN_DIR"
elif [ "$CC_APPLY" = 1 ]; then
    if [ "$BACKEND" = nft ]; then cc_run "load the firewall rules (nft -f)" "$NFT" -f "$RULES"
    else cc_run "load the firewall rules (iptables)" sh "$RULES"; fi
    _rc=$?
    if [ "$_rc" -ne 0 ]; then
        cc_err "loading the rules failed - removing whatever was loaded"
        sh "$ROLLBACK" >>"$CC_LOG" 2>&1
        _state="FAILED to load; rules removed again"
    else
        cc_undo_add "remove the CCDC firewall rules" "sh $(cc_shquote "$ROLLBACK")"
        printf '%s\n' "$CC_RUN_DIR" >"$CURRENT"
        if [ "$TIMEOUT" -eq 0 ]; then
            _state="LIVE (no rollback timer: --confirm-timeout 0)"
        else
            # The timer runs detached, so it still fires if this session dies.
            cat >"$CC_RUN_DIR/rollback-timer.sh" <<EOF
#!/bin/sh
sleep $TIMEOUT
# Only if nobody confirmed AND no newer run has replaced these rules.
if [ ! -f $(cc_shquote "$KEEPF") ] && [ "\$(cat $(cc_shquote "$CURRENT") 2>/dev/null)" = $(cc_shquote "$CC_RUN_DIR") ]; then
    sh $(cc_shquote "$ROLLBACK") >/dev/null 2>&1
    date -u +%Y-%m-%dT%H:%M:%SZ >$(cc_shquote "$CC_RUN_DIR/ROLLED_BACK")
fi
EOF
            cat >"$KEEPSH" <<EOF
#!/bin/sh
# Run from a NEW session: proves new connections still get in, then keeps the rules.
if [ -f $(cc_shquote "$CC_RUN_DIR/ROLLED_BACK") ]; then echo "too late: the rules were already rolled back at \$(cat $(cc_shquote "$CC_RUN_DIR/ROLLED_BACK"))"; exit 1; fi
: >$(cc_shquote "$KEEPF")
kill \$(cat $(cc_shquote "$CC_RUN_DIR/.timer.pid") 2>/dev/null) 2>/dev/null
echo "kept: the CCDC firewall rules stay. To keep them across a reboot run LX-25 with --save."
EOF
            chmod 700 "$CC_RUN_DIR/rollback-timer.sh" "$KEEPSH"
            nohup sh "$CC_RUN_DIR/rollback-timer.sh" >/dev/null 2>&1 &
            echo $! >"$CC_RUN_DIR/.timer.pid"
            _state="LIVE - rollback in ${TIMEOUT}s unless confirmed"
            cc_show "$C_GRN" "  [+] The firewall is LIVE."
            cc_show "$C_YEL" "  [!] It removes itself in ${TIMEOUT}s unless you confirm. Open a NEW ssh session (do not close this one) and run:"
            cc_show "$C_YEL" "          sudo sh $KEEPSH"
            cc_show "$C_YEL" "      If the new session cannot connect, do nothing: the rules go away on their own."
            if _cc_can_ask && [ "${CCDC_ASSUME_YES:-0}" != 1 ]; then
                # The question cannot prove new connections work, so it only
                # offers the quick way out ("n" = remove now).
                printf 'Check scoring and open a NEW ssh session now. Remove the rules immediately? [y/N] ' >/dev/tty
                if read -r _ans </dev/tty; then
                    case "$_ans" in y|Y|yes) sh "$ROLLBACK" >>"$CC_LOG" 2>&1; : >"$KEEPF"; kill "$(cat "$CC_RUN_DIR/.timer.pid")" 2>/dev/null
                        _state="removed at your request" ;;
                    esac
                fi
            fi
        fi
    fi
fi
[ "$CC_APPLY" = 1 ] || case "$_state" in "dry run"*) cc_show "$C_GRY" "  Dry run: nothing loaded. Run again with --apply to load these rules." ;; esac

# ---- Summary ------------------------------------------------------------------------
{
    printf 'LX-25 Linux firewall | host %s | %s | %s\n\n' "$CC_HOST" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$([ "$CC_APPLY" = 1 ] && echo APPLIED || echo 'DRY RUN - nothing changed')"
    printf 'State:    %s\n' "$_state"
    printf 'Ports:    %s kept open, %s dropped, %s local only (loopback)\n' "$NKEEP" "$NDROP" "$NLOCAL"
    printf 'Backend:  %s (own %s; nothing else is flushed)\n' "$BACKEND" "$([ "$BACKEND" = nft ] && echo 'table inet ccdc' || echo 'chains CCDC-IN/CCDC-OUT')"
    printf 'IPv6:     %s\n' "$([ "$KEEP6" = 1 ] && echo 'allowed like IPv4' || echo 'dropped (except loopback)')"
    printf 'Outgoing: %s\n' "$([ "$RESTOUT" = 1 ] && echo 'limited to DNS, DHCP, NTP, HTTP(S), replies and admin hosts' || echo 'not limited')"
    printf '\nOpen to everyone:\n'
    cat "$W/open.txt"
    printf '    ping (ICMP)\n'
    [ -n "$SOURCES" ] && printf 'Allowed for everything from: %s\n' "$(printf '%s' "$SOURCES" | tr '\n' ' ')"
    [ -n "$SSHFROM" ] && printf 'SSH (%s) only from: %s\n' "$SSHPORTS" "$(printf '%s' "$SSHFROM" | tr '\n' ' ')"
    if [ -s "$W/notes" ]; then printf '\nDropped from outside:\n'; sed 's/^/    /' "$W/notes" | cut -c1-240; fi
    [ -n "$FTPNOTE" ] && printf '\nNote: %s\n' "$FTPNOTE"
    printf '\nEvery port with its program and command: %s/ports.txt\nRules: %s\n' "$CC_RUN_DIR" "$RULES"
    case "$_state" in
        LIVE*rollback*) printf '\nCONFIRM from a NEW ssh session within %ss, or the rules are removed:\n  sudo sh %s\n' "$TIMEOUT" "$KEEPSH" ;;
    esac
    [ "$CC_APPLY" = 1 ] && printf 'Remove at any time: sudo sh %s\nKeep across reboot (after confirming): run LX-25 again with --save --apply\n' "$ROLLBACK"
    [ "$CC_APPLY" = 1 ] || printf 'Nothing was changed.  Happy with the plan?  Run again with --apply.\n'
    printf 'All results: %s\n' "$CC_RUN_DIR"
} >"$CC_RUN_DIR/summary.txt"
header "SUMMARY"
# On screen the summary is colour-coded; summary.txt and output.txt stay plain.
awk -v R="$C_RED" -v Y="$C_YEL" -v G="$C_GRN" -v C="$C_CYN" -v D="$C_GRY" -v O="$C_OFF" '
    NR == 1                         { print C $0 O; next }
    /^State: +(LIVE|kept)/          { print G $0 O; next }
    /^State: +(FAILED|removed)/     { print R $0 O; next }
    /^State:/                       { print Y $0 O; next }
    /^Open to everyone:/            { m = "o"; print C $0 O; next }
    /^Dropped from outside:/        { m = "d"; print C $0 O; next }
    /^$/                            { m = ""; print; next }
    m == "o"                        { print G $0 O; next }
    m == "d"                        { print R $0 O; next }
    /^CONFIRM|^  sudo sh|^Note:/    { print Y $0 O; next }
    /^(All results|Rules|Every port)/ { print D $0 O; next }
                                    { print }
' "$CC_RUN_DIR/summary.txt"
cat "$CC_RUN_DIR/summary.txt" >>"$OUTF"
rm -rf "$W"
cc_finish
