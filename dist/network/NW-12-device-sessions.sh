#!/bin/sh
# =============================================================================
# ID:       NW-12
# NAME:     Device accounts and sessions
# ROLE:     Network  (wave 1, first 15 minutes, again every time red team is busy)
# KIND:     changes - dry run unless --apply
# VERSION:  1.2.0
#
# PURPOSE
#   A red team's first move on a firewall or router is to log in with an
#   extra admin account (or a default one) and stay logged in.  For each
#   device this shows, in one place:
#     accounts   every local admin account, its rights, and whether it is
#                new since the first run (a baseline is kept)
#     sessions   who is logged in right now, from where, how (SSH, web, API)
#   and asks, one at a time:
#     a session from outside your team     [k]ick it / [l]eave it
#     an account new since the first run   [d]isable it / [k]eep it
#   Kicking ends the session; they can log back in until the password is
#   changed - run NW-10 right after.  "Disable" is the brand's most
#   reversible way:
#     MikroTik, Linux       disabled / locked (the undo turns it back on)
#     OpenWRT               password locked (! in /etc/shadow) and the shell
#                           set to /bin/false; the undo puts both back
#     Cisco IOS/ASA, VyOS,  removed; the undo puts back the account's own
#     FortiGate             line(s) from NW-01's saved config (run NW-01 first:
#                           without that copy there is no undo, and you are told)
#     Palo Alto             removed and committed; no automatic undo
#   This script's own login (your login account from your address) is never
#   kicked, and the login account is never disabled.
#
#   Brands: cisco-ios, cisco-asa, paloalto, fortigate, vyos, mikrotik, linux,
#   openwrt (log in as root: accounts from /etc/passwd and /etc/shadow, SSH
#   sessions from dropbear's connections, web (LuCI) sessions from ubus).
#   pfSense / OPNsense: listed, check in the web GUI (System > User Manager,
#   Status > ... ).  FortiGate sessions are shown with the command to end one
#   (its session numbers change as people log in and out).
#
#   QUESTIONS (Enter takes the default in capitals; a flag answers each):
#     which devices (the host list, or typed)   --hosts FILE / --device SPEC
#     the device password                       $BT_NET_PASS / --ask-password
#     your team's addresses                     --team CIDR,...
#     each session not yours    [k]ick / [l]eave (the default: it may be a
#                               teammate) / [a]ll the rest default
#     each account to look at   [d]isable / [k]eep (the default: a teammate
#                               may have made it) / [a]ll the rest default
#   Never kicks the team off a device: nothing is kicked or disabled unless
#   you answer k or d for it; --batch kicks and disables nothing (unless
#   --kick-outside / --disable-new make those the default answers).
#     apply?                    --apply
#
# USAGE
#   BT_NET_PASS='pw' sh NW-12-device-sessions.sh --hosts hosts.txt --team 10.0.0.0/24
#   BT_NET_PASS='pw' sh NW-12-device-sessions.sh --hosts hosts.txt --team 10.0.0.0/24 --apply
#   sh NW-12-device-sessions.sh --device fw1,10.0.0.1,paloalto,admin --ask-password
#
# OPTIONS
#   --hosts FILE / --device NAME,ADDRESS,VENDOR[,USER[,PORT]]   as for NW-01
#   --user NAME        default login account (admin)
#   --ask-password     ask for the password (else $BT_NET_PASS)
#   --enable-env       Cisco: enable with $BT_NET_ENABLE
#   --team CIDR,...    your team's addresses: their sessions default to leave
#   --known NAME,...   accounts that are yours: never asked about
#   --kick-outside     kick is the default for sessions from outside --team
#                      (default: leave - a teammate may be logged in from
#                      somewhere else)
#   --disable-new      disable is the default for accounts new since the
#                      first run (default: keep)
#   --me ADDRESS       this box's address as the devices see it (default:
#                      found with "ip route get")
#   --configs DIR      NW-01's saved configs (default <out>/net-configs)
#   --legacy-ssh       allow old SSH algorithms
#   --no-color         no colours
#   --help             this text plus the common options
#
# OUTPUTS  (under --out, in device-sessions-N/)
#   output.txt, accounts.txt, sessions.txt, plan.txt, summary.txt
#   undo/              the scripts that put a removed account back
#   net-accounts-baseline.txt (in --out): device and account names, nothing else
#
# DEPENDS ON
#   ssh, sshpass (password logins).  BT_SSH / BT_SSHPASS may name stand-ins.
#
# TESTED ON
#   A stand-in device for every brand (its answers written from each brand's
#   documented output) under dash, bash, busybox sh, ksh93, mksh and yash
#   with gawk, mawk and busybox awk; the Linux brand live against OpenSSH.
#   NOT yet on real Cisco, Palo Alto, FortiGate, VyOS or MikroTik devices:
#   run it without --apply first and check that it lists what the web GUI
#   shows.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - Only local accounts.  TACACS/RADIUS logins live on that server.
#   - Kicking does not keep them out: change the passwords (NW-10) next.
#   - A teammate logged in from an address outside --team looks like red
#     team.  Give --team, and read each question.
#   - Palo Alto "kick" ends every session of that account.  Sessions on
#     your own login account are never kicked: change its password instead.
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

VENDORS="cisco-ios cisco-asa paloalto fortigate vyos mikrotik linux pfsense opnsense openwrt"

usage() {
    cat <<'USAGE'
NW-12 Device accounts and sessions - who has an account, who is logged in; kick and disable
  BT_NET_PASS=pw sh NW-12-device-sessions.sh --hosts FILE | --device SPEC [--team CIDR] [--apply]
  sh NW-12-device-sessions.sh              asks which devices, the password and your team

  --hosts FILE / --device NAME,ADDRESS,VENDOR[,USER[,PORT]]
  --user NAME        default login account (admin)
  --ask-password     ask for the password (else $BT_NET_PASS)
  --enable-env       Cisco: enable with $BT_NET_ENABLE
  --team CIDR,...    your team's addresses (their sessions default to leave)
  --known NAME,...   accounts that are yours (never asked about)
  --kick-outside     default kick for sessions from outside --team (default leave)
  --disable-new      default disable for accounts new since the first run (default keep)
  --me ADDRESS       this box's address as the devices see it
  --configs DIR      NW-01's saved configs (for the undo of a removed account)
  --legacy-ssh       allow old SSH algorithms
  --no-color         no colours
  --help             show this text
USAGE
    cc_usage_common
}

NL='
'
HOSTS=""; DEVICES=""; DEFUSER="admin"; USERSET=0; ASK=0; KICKOUT=0; DISNEW=0; ENABLE=0; TEAM=""; KNOWN=""; ME=""; CONFIGS=""; LEGACY=0; COLOR=1
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --apply)        CC_APPLY=1; shift ;;
        --hosts)        [ $# -ge 2 ] || cc_die 2 "--hosts needs a file"; [ -r "$2" ] || cc_die 2 "--hosts: cannot read $2"; HOSTS=$2; shift 2 ;;
        --device)       [ $# -ge 2 ] || cc_die 2 "--device needs NAME,ADDRESS,VENDOR"; DEVICES="$DEVICES$2$NL"; shift 2 ;;
        --user)         [ $# -ge 2 ] || cc_die 2 "--user needs a name"; DEFUSER=$2; USERSET=1; shift 2 ;;
        --ask-password) ASK=1; shift ;;
        --kick-outside) KICKOUT=1; shift ;;
        --disable-new)  DISNEW=1; shift ;;
        --enable-env)   ENABLE=1; shift ;;
        --team)         [ $# -ge 2 ] || cc_die 2 "--team needs addresses"; TEAM="$TEAM,$2"; shift 2 ;;
        --known)        [ $# -ge 2 ] || cc_die 2 "--known needs names"; KNOWN="$KNOWN,$2"; shift 2 ;;
        --me)           [ $# -ge 2 ] || cc_die 2 "--me needs an address"; ME=$2; shift 2 ;;
        --configs)      [ $# -ge 2 ] || cc_die 2 "--configs needs a folder"; CONFIGS=$2; shift 2 ;;
        --legacy-ssh)   LEGACY=1; shift ;;
        --no-color|--no-colour) COLOR=0; shift ;;
        --help|-h)      usage; exit 0 ;;
        *)              cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
for _t in $(printf '%s' "$TEAM" | tr ',' ' '); do
    printf '%s' "$_t" | grep -q '^[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\(/[0-9]\{1,2\}\)\{0,1\}$' || cc_die 2 "--team: IPv4 addresses or CIDRs (10.0.0.0/24)"
done
printf '%s' "$KNOWN" | grep -q '[^A-Za-z0-9_.@,-]' && cc_die 2 "--known: account names separated by commas"

cc_init "NW-12" "Device accounts and sessions" changes
# shellcheck disable=SC2034  # read by cc_color_init
[ "$COLOR" = 1 ] || CC_NOCOLOR=1
cc_color_init
# No device named, no host list and nobody to ask: stop before a run folder.
if [ -z "$HOSTS$DEVICES" ] && ! _cc_can_ask && ! cc_net_hostfile >/dev/null; then
    cc_die 2 "give --hosts FILE or --device NAME,ADDRESS,VENDOR (try --help)"
fi
cc_use_numbered_dir device-sessions
rmdir "$CC_RUN_DIR/raw" 2>/dev/null
OUTF="$CC_RUN_DIR/output.txt"
grep -v '\[NOTE\]\|\[DEBUG\]' "$CC_LOG" >"$OUTF" 2>/dev/null || : >"$OUTF"
# shellcheck disable=SC2034  # CC_TEE is read by the library's log functions
CC_TEE=$OUTF
W="$CC_RUN_DIR/.work"; (umask 077; mkdir -p "$W")
US=$(printf '\037')
header() { cc_show "" ""; cc_show "$C_CYN" "==========[ $1 ]=========="; }
# j FIELD... -> one line, fields split by \037 (values may hold spaces; empty ones stay)
j() { _j=$1; shift; for _jx in "$@"; do _j="$_j$US$_jx"; done; printf '%s\n' "$_j"; }
# safe TEXT -> 0 if TEXT can go into a device command as it is.  Names come
# from the device, so red team chose them: a quote or ; in one must never
# reach a command line.
safe() { case "$1" in ''|*[!A-Za-z0-9_.@/:#\ -]*) return 1 ;; esac; return 0; }
trap 'rm -rf "$W"; exit 130' INT TERM HUP
[ -n "$CONFIGS" ] || CONFIGS="$CC_OUT/net-configs"
mkdir -p "$CONFIGS" 2>/dev/null
SSH=${BT_SSH:-$(cc_which ssh)} || cc_die 3 "ssh not found"
SSHPASS_BIN=${BT_SSHPASS:-$(cc_which sshpass)} || cc_die 3 "sshpass not found (apt install sshpass): device logins use the password"
cc_show "$C_CYN" "NW-12 Device accounts and sessions | from $CC_HOST | results in $CC_RUN_DIR"
cc_show "" "Legend: ${C_RED}[!]${C_OFF} fix now   ${C_YEL}[*]${C_OFF} look at it   ${C_GRN}[ok]${C_OFF} fine   ${C_YEL}[~] would change${C_OFF}   ${C_GRN}[+] changed${C_OFF}   ${C_RED}[x] failed${C_OFF}"
header "1/5  devices"
# The questions a flag did not answer: devices, password, team.
if [ -z "$HOSTS$DEVICES" ]; then
    cc_net_ask_devices "$DEFUSER" "$USERSET" || cc_die 2 "no devices given (or use --hosts FILE / --device NAME,ADDRESS,VENDOR)"
    HOSTS=$CC_NET_HOSTS; DEVICES=$CC_NET_DEVICES
fi
if [ "$ASK" = 1 ]; then
    [ -r /dev/tty ] || cc_die 3 "--ask-password needs a terminal; set BT_NET_PASS"
    printf 'Device password: ' >/dev/tty; stty -echo </dev/tty 2>/dev/null
    read -r BT_NET_PASS </dev/tty; stty echo </dev/tty 2>/dev/null; printf '\n' >/dev/tty
else
    cc_net_ask_password
fi
[ -n "${BT_NET_PASS:-}" ] || cc_die 3 "the device password is needed: set BT_NET_PASS or use --ask-password"
[ "$ENABLE" = 1 ] && [ -z "${BT_NET_ENABLE:-}" ] && cc_die 3 "--enable-env: set BT_NET_ENABLE"
if [ -z "$TEAM" ] && _cc_can_ask; then
    cc_ask_text "Your team's addresses? (their sessions are left alone; others are offered to kick)" "" "addresses or networks separated by commas, like 192.168.220.30,192.168.220.0/24 (Enter = none: every session is asked about)"
    TEAM=$CC_ANSWER
    for _t in $(printf '%s' "$TEAM" | tr ',' ' '); do
        printf '%s' "$_t" | grep -q '^[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\(/[0-9]\{1,2\}\)\{0,1\}$' || cc_die 2 "team: IPv4 addresses or CIDRs (10.0.0.0/24)"
    done
fi

# ---- Devices (same rules as NW-01) ---------------------------------------------------
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
        /openwrt|lede|luci/ { print "openwrt"; exit }
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
[ -s "$W/devices" ] || cc_die 3 "no network devices found (os must be network or a vendor name)"
for _n in $(cut -d'|' -f1 "$W/devices"); do case "$_n" in *[!A-Za-z0-9_.-]*) cc_die 2 "device name '$_n' may only use letters, digits, '.', '_' and '-'" ;; esac; done
_bp=$(awk -F'|' '$5 !~ /^[0-9]+$/ || $5 < 1 || $5 > 65535 { print $1; exit }' "$W/devices"); [ -z "$_bp" ] || cc_die 2 "device $_bp: the SSH port must be a number from 1 to 65535"

# ---- Talking to a device ---------------------------------------------------------------
sshopts() {
    set -- -T -o ConnectTimeout=10 -o "UserKnownHostsFile=$CONFIGS/known_hosts" -o StrictHostKeyChecking=accept-new \
        -o LogLevel=ERROR -o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive -o NumberOfPasswordPrompts=1
    [ "$LEGACY" = 1 ] && set -- "$@" -o KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group1-sha1 -o HostKeyAlgorithms=+ssh-rsa -o Ciphers=+aes128-cbc,aes256-cbc,3des-cbc
    printf '%s\n' "$@"
}
# mode VENDOR -> stdin (commands typed into the CLI) | exec (one command line)
mode() { case "$1" in vyos|mikrotik|linux|openwrt) echo exec ;; *) echo stdin ;; esac; }
# session VENDOR USER ADDRESS PORT INFILE OUTFILE -> 0 when it logged in
session() {
    _sv=$1; _su=$2; _sa=$3; _sp=$4; _si=$5; _so=$6
    sshopts >"$W/opts"; set --; while IFS= read -r _o; do set -- "$@" "$_o"; done <"$W/opts"
    if [ "$(mode "$_sv")" = exec ]; then
        SSHPASS=$BT_NET_PASS "$SSHPASS_BIN" -e "$SSH" "$@" -p "$_sp" "$_su@$_sa" "$(cat "$_si")" </dev/null >"$_so" 2>"$W/err"
    else
        SSHPASS=$BT_NET_PASS "$SSHPASS_BIN" -e "$SSH" "$@" -p "$_sp" "$_su@$_sa" <"$_si" >"$_so" 2>"$W/err"
    fi
}
en() { case "$1" in cisco-*) [ "$ENABLE" = 1 ] && printf 'enable\n%s\n' "$BT_NET_ENABLE" ;; esac; return 0; }
# read_cmds VENDOR -> what to send to list the accounts and the sessions
read_cmds() {
    case "$1" in
        cisco-ios) en "$1"; printf 'terminal length 0\nshow running-config | include ^username\nshow users\nexit\n' ;;
        cisco-asa) en "$1"; printf 'terminal pager 0\nshow running-config username\nshow ssh sessions\nexit\n' ;;
        paloalto)  printf 'set cli pager off\nshow admins\nset cli config-output-format set\nconfigure\nshow mgt-config users\nexit\nexit\n' ;;
        fortigate) printf 'show system admin\nget system admin list\nexit\n' ;;
        vyos)      printf '/opt/vyatta/bin/vyatta-op-cmd-wrapper show configuration commands; who' ;;
        mikrotik)  printf '/user print terse without-paging; /user active print terse without-paging' ;;
        # passwd -S: L = locked (needs root or sudo; without it the state stays unknown)
        # OpenWRT: accounts and their lock state; each SSH session is a dropbear
        # process with a peer (busybox netstat -p) and an owner (/proc); the
        # web (LuCI) sessions are in ubus.
        openwrt)   cat <<'OWRT'
cat /etc/passwd
echo ===shadow
awk -F: '{ s = "P"; if ($2 ~ /^[!*]/) s = "L"; if ($2 == "") s = "NP"; print $1, s }' /etc/shadow
echo ===ssh
netstat -tnp 2>/dev/null | awk '$6 == "ESTABLISHED" && $4 ~ /:22$/ && $7 ~ /dropbear/ { split($7, a, "/"); p = $5; sub(/:[0-9]+$/, "", p); sub(/^::ffff:/, "", p); u = "?"; f = "/proc/" a[1] "/status"; while ((getline l < f) > 0) if (l ~ /^Uid:/) { split(l, q, /[ \t]+/); u = q[2] } close(f); print a[1], p, u }'
echo ===web
ubus call session list 2>/dev/null | awk -F'"' '/"ubus_rpc_session"/ { s = $4 } /"username"/ && s != "" { print s, $4; s = "" }'
OWRT
                   ;;
        linux)     printf 'getent passwd; echo ===groups; getent group sudo wheel admin; echo ===who; who; echo ===status; for u in $(getent passwd | awk -F: '"'"'$3 == 0 || $3 >= 1000 { print $1 }'"'"'); do passwd -S "$u" 2>/dev/null || sudo -n passwd -S "$u" 2>/dev/null; done' ;;
    esac
}
# parse VENDOR RAW -> $W/acc ("name US rights US state") and $W/ses ("id US user US from US via")
parse() {
    tr -d '\r' <"$2" | awk -v v="$1" -v US="$US" -v ao="$W/acc" -v so="$W/ses" '
        function acc(n, r, s) { gsub(/"/, "", n); if (n != "" && !(n in seen)) { seen[n] = 1; print n US r US s > ao } }  # awk, not shell: posix-ok
        function ses(i, u, f, w) { print i US u US f US w > so }  # awk, not shell: posix-ok
        { sub(/^[^ ]*[>#] */, "", $0) }
        v == "cisco-ios" && $1 == "username" { r = "privilege 1"; for (i = 3; i < NF; i++) if ($i == "privilege") r = "privilege " $(i + 1); acc($2, r, "active") }
        v == "cisco-ios" && /^[* ]*[0-9]+ +(vty|tty|con|aux) +[0-9]+ / {
            me = ($0 ~ /^ *\*/); l = $0; sub(/^[* ]+/, "", l); n = split(l, f, /[ \t]+/)
            from = f[n]; if (from ~ /^[0-9][0-9]:[0-9][0-9]:[0-9][0-9]$/ || from == "idle") from = "-"
            u = f[4]; if (u == "idle" || u ~ /^[0-9:]+$/) u = "-"
            ses((me ? "*" : "") f[2] " " f[3], u, from, f[2]) }
        v == "cisco-asa" && $1 == "username" && $2 != "" && $3 != "attributes" { r = "privilege 2"; for (i = 3; i < NF; i++) if ($i == "privilege") r = "privilege " $(i + 1); acc($2, r, "active") }
        v == "cisco-asa" && $1 ~ /^[0-9]+$/ && $2 ~ /^[0-9a-fA-F.:]+$/ && $4 == "IN" { ses($1, $NF, $2, "ssh") }
        v == "paloalto" && $1 == "set" && $2 == "mgt-config" && $3 == "users" { n = $4; if (!(n in role)) role[n] = "role-based"; if ($0 ~ /superuser yes/) role[n] = "superuser"; if ($0 ~ /superreader yes/ && role[n] != "superuser") role[n] = "superreader"; if (!(n in seen2)) { seen2[n] = 1; order[++no] = n } }
        v == "paloalto" && $2 ~ /^[0-9a-fA-F.:]+$/ && $3 ~ /^(CLI|Web|API|XML)/ && $1 !~ /^-+$/ { ses($1, $1, $2, $3) }
        v == "fortigate" && /^config system admin/ { inadm = 1 }
        v == "fortigate" && inadm && $1 == "edit" { cur = $2; gsub(/"/, "", cur); prof[cur] = "accprofile ?"; order[++no] = cur }
        v == "fortigate" && inadm && $1 == "set" && $2 == "accprofile" { p = $3; gsub(/"/, "", p); prof[cur] = "accprofile " p }
        v == "fortigate" && inadm && /^end/ { inadm = 0 }
        v == "fortigate" && $1 == "username" && $0 ~ /remote/ { inlist = 1; k = 0; next }
        v == "fortigate" && inlist && NF >= 4 && $4 ~ /:[0-9]+$/ { fr = $4; sub(/:[0-9]+$/, "", fr); ses("#" k, $1, fr, $2); k++ }
        v == "vyos" && $1 == "set" && $2 == "system" && $3 == "login" && $4 == "user" { n = $5; gsub(/\047/, "", n); acc(n, "admin", "active") }
        v ~ /^(vyos|linux)$/ && $2 ~ /^pts\// { fr = $NF; if (fr !~ /^\(/) fr = "-"; gsub(/[()]/, "", fr); ses($2, $1, fr, "ssh") }
        v == "mikrotik" && / name=/ {
            n = ""; g = ""; a = ""; w = ""; st = "active"
            if ($2 == "X" || $2 ~ /^X/) st = "disabled"
            for (i = 1; i <= NF; i++) { if ($i ~ /^name=/) { n = substr($i, 6) } else if ($i ~ /^group=/) { g = substr($i, 7) } else if ($i ~ /^address=/) { a = substr($i, 9) } else if ($i ~ /^via=/) { w = substr($i, 5) } }
            gsub(/"/, "", n)
            if ($0 ~ / via=/) ses(n "@" a, n, a, w); else acc(n, "group " g, st) }
        v == "openwrt" && /^===/ { op = substr($0, 4); next }
        v == "openwrt" && op == "" && split($0, pw, ":") >= 7 && pw[3] ~ /^[0-9]+$/ {
            # Two UID 0 accounts share one uid: a session of uid 0 is shown as
            # the first one (root), which is how the device itself sees it.
            if (!(pw[3] in uname)) uname[pw[3]] = pw[1]
            if (pw[3] == 0) owr[pw[1]] = "uid 0 (root)"
            else if (pw[7] !~ /(nologin|false)$/) owr[pw[1]] = "can log in (" pw[7] ")"
            if (pw[1] in owr) oo[++no2] = pw[1] }
        v == "openwrt" && op == "shadow" { if ($2 == "L") lk[$1] = 1; if ($2 == "NP") np[$1] = 1 }
        v == "openwrt" && op == "ssh" && NF >= 3 { u = ($3 in uname) ? uname[$3] : "uid " $3; ses($1, u, $2, "ssh") }
        v == "openwrt" && op == "web" && NF >= 2 { ses($1, $2, "?", "web (LuCI)") }
        v == "linux" && /^===groups/ { ing = 1; next }
        v == "linux" && /^===who/ { ing = 0; next }
        v == "linux" && /^===status/ { inst = 1; next }
        v == "linux" && inst { if ($2 == "L" || $2 == "LK") lk[$1] = 1; next }
        v == "linux" && ing { split($0, gg, ":"); m = gg[4]; k = split(m, mm, ","); for (i = 1; i <= k; i++) adm[mm[i]] = gg[1] }
        v == "linux" && !ing && split($0, pw, ":") >= 7 && pw[3] ~ /^[0-9]+$/ {
            if (pw[3] == 0) lin[pw[1]] = "uid 0 (root)"
            else if (pw[3] >= 1000 && pw[7] !~ /(nologin|false)$/) lin[pw[1]] = "user"
            if (pw[1] in lin) lo[++nl] = pw[1] }
        END {
            for (i = 1; i <= no; i++) { n = order[i]; acc(n, (v == "paloalto") ? role[n] : prof[n], "active") }
            for (i = 1; i <= nl; i++) { n = lo[i]; acc(n, (n in adm) ? "admin (" adm[n] ")" : lin[n], (n in lk) ? "disabled" : "active") }
            for (i = 1; i <= no2; i++) { n = oo[i]; acc(n, owr[n] ((n in np) ? ", NO PASSWORD" : ""), (n in lk) ? "disabled" : "active") }
        }'
}
# in_team ADDRESS -> 0 if it is in one of the --team ranges
in_team() {
    [ -n "$TEAM" ] || return 1
    printf '%s\n' "$TEAM" | tr ',' '\n' | grep . | awk -v ip="$1" '
        function n(a,   p) { split(a, p, "."); return ((p[1] * 256 + p[2]) * 256 + p[3]) * 256 + p[4] }  # awk, not shell: posix-ok
        ip !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ { exit 1 }
        { b = $0; m = 32; if (index(b, "/")) { m = substr(b, index(b, "/") + 1) + 0; b = substr(b, 1, index(b, "/") - 1) }
          s = 1; for (i = m; i < 32; i++) s *= 2  # no ^: busybox awk may lack math
          if (int(n(ip) / s) == int(n(b) / s)) { hit = 1; exit } }
        END { exit hit ? 0 : 1 }'
}
known() { case ",$KNOWN," in *",$1,"*) return 0 ;; esac; return 1; }
# my_addr ADDRESS -> this box's source address towards ADDRESS
my_addr() { [ -n "$ME" ] && { printf '%s' "$ME"; return; }; ip route get "$1" 2>/dev/null | sed -n 's/.* src \([^ ]*\).*/\1/p' | head -n 1; }
# latest_cfg DEVICE -> NW-01's newest copy of the device's config
latest_cfg() { _l=$(cat "$CONFIGS/$1/latest" 2>/dev/null) && [ -f "$CONFIGS/$1/$_l.cfg" ] && printf '%s' "$CONFIGS/$1/$_l.cfg"; }
# saved_lines VENDOR CFG NAME -> the account's own lines in NW-01's copy
# (read only when the undo runs: the lines hold a password hash and are never copied)
SAVED_AWK='
    { sub(/\r$/, "") }
    v ~ /^cisco/ && $1 == "username" && $2 == n { print; next }
    v == "vyos" && $1 == "set" && $2 == "system" && $3 == "login" && $4 == "user" { u = $5; gsub(/\047/, "", u); if (u == n) print; next }
    v == "fortigate" && /^config system admin/ { a = 1; next }
    v == "fortigate" && a && /^end/ { a = 0 }
    v == "fortigate" && a && $1 == "edit" { e = $2; gsub(/"/, "", e); p = (e == n) }
    v == "fortigate" && a && p { print; if ($1 == "next") p = 0 }'
has_saved() { _cf=$(latest_cfg "$2") || return 1; awk -v v="$1" -v n="$3" "$SAVED_AWK" "$_cf" | grep -q .; }

# ---- 1. Read every device --------------------------------------------------------------
: >"$W/allacc"; : >"$W/allses"; NDEV=0; NFAIL=0
printf '%-14s %-10s %-20s %-24s %s\n' device brand account rights state >"$CC_RUN_DIR/accounts.txt"
printf '%-14s %-10s %-12s %-16s %-18s %s\n' device brand session user from verdict >"$CC_RUN_DIR/sessions.txt"
while IFS='|' read -r _n _a _v _u _p; do
    case "$_v" in pfsense|opnsense)
        cc_show "$C_YEL" "  [*] $_n ($_v): no safe command line for this - check System > User Manager and the logged-in users in the web GUI"; continue ;;
    esac
    if ! cc_guard host "$_a" || ! cc_guard host "$_n"; then cc_show "$C_GRY" "  $_n: protected device, skipped"; continue; fi
    read_cmds "$_v" >"$W/in"
    if ! session "$_v" "$_u" "$_a" "$_p" "$W/in" "$W/raw.$_n"; then
        NFAIL=$((NFAIL + 1)); cc_show "$C_RED" "  [x] $_n ($_a, $_v): could not log in as $_u ($(grep -v '^$' "$W/err" | tail -n 1 | cut -c1-70))"; continue
    fi
    : >"$W/acc"; : >"$W/ses"; parse "$_v" "$W/raw.$_n"
    NDEV=$((NDEV + 1))
    _me=$(my_addr "$_a")
    [ -n "$_me" ] || cc_show "$C_YEL" "  [*] $_n: cannot tell this box's address towards it (no ip route?): pass --me ADDRESS so this script's own login is recognised"
    cc_show "$C_GRN" "  [ok] $_n ($_a, $_v): $(grep -c . "$W/acc") account(s), $(grep -c . "$W/ses") session(s)$([ -n "$_me" ] && echo "; this box is $_me")"
    while IFS="$US" read -r _an _ar _as; do j "$_n" "$_a" "$_v" "$_u" "$_p" "$_an" "$_ar" "$_as" >>"$W/allacc"; done <"$W/acc"
    while IFS="$US" read -r _si _su _sf _sw; do j "$_n" "$_a" "$_v" "$_u" "$_p" "$_si" "$_su" "$_sf" "$_sw" "$_me" >>"$W/allses"; done <"$W/ses"
done <"$W/devices"
[ "$NDEV" -eq 0 ] && cc_show "$C_RED" "  [x] no device answered"

# ---- 2. Accounts ---------------------------------------------------------------------------
header "2/5  accounts"
BASE="$CC_OUT/net-accounts-baseline.txt"
FIRST=0; [ -f "$BASE" ] || FIRST=1
: >"$W/ask"   # kind US default US device ... US target US text
while IFS="$US" read -r _n _a _v _u _p _an _ar _as; do
    _new=n; [ "$FIRST" = 0 ] && ! grep -qxF "$_n $_an" "$BASE" && _new=y
    _verd=""
    if [ "$_an" = "$_u" ]; then _verd="your login"; cc_show "$C_GRN" "  [ok] $_n: $_an ($_ar) - the account this script logs in with"
    elif known "$_an"; then _verd="known"; cc_show "$C_GRN" "  [ok] $_n: $_an ($_ar) - yours (--known)"
    elif [ "$_as" = disabled ]; then _verd="disabled"; cc_show "$C_GRY" "  $_n: $_an ($_ar) - disabled"
    elif ! safe "$_an"; then _verd="odd name"; cc_show "$C_RED" "  [!] $_n: an account with an odd name ($(printf '%s' "$_an" | tr -cd 'A-Za-z0-9_.@ -')...): check it in the device's own interface - it is not put into a command"
    elif ! cc_is_protected account "$_an" && [ "$_new" = y ]; then
        _verd="NEW"; cc_show "$C_RED" "  [!] $_n: $_an ($_ar) - NEW since the first run: who made it?"
        # Never the default (unless --disable-new): a teammate may have made it.
        j acc "$([ "$DISNEW" = 1 ] && echo d || echo k)" "$_n" "$_a" "$_v" "$_u" "$_p" "$_an" "$_ar" "NEW since the first run" >>"$W/ask"
    elif cc_is_protected account "$_an"; then _verd="protected"; cc_show "$C_GRN" "  [ok] $_n: $_an ($_ar) - on the protected list"
    else
        _verd="look at it"; cc_show "$C_YEL" "  [*] $_n: $_an ($_ar) - $([ "$FIRST" = 1 ] && echo 'first run: is it yours? (--known NAME stops this question)' || echo 'there at the first run')"
        j acc k "$_n" "$_a" "$_v" "$_u" "$_p" "$_an" "$_ar" "$([ "$FIRST" = 1 ] && echo 'first run' || echo 'there at the first run')" >>"$W/ask"
    fi
    printf '%-14s %-10s %-20s %-24s %s\n' "$_n" "$_v" "$_an" "$_ar" "$_as, $_verd" >>"$CC_RUN_DIR/accounts.txt"
done <"$W/allacc"
[ -s "$W/allacc" ] || cc_show "$C_GRY" "  No accounts read."
if [ "$FIRST" = 1 ] && [ -s "$W/allacc" ]; then
    awk -F"$US" '{ print $1 " " $6 }' "$W/allacc" | sort -u >"$BASE"
    cc_show "$C_GRN" "  [ok] first run: these accounts are the baseline ($BASE); an account added later is flagged [!]"
fi

# ---- 3. Sessions ---------------------------------------------------------------------------
header "3/5  who is logged in"
while IFS="$US" read -r _n _a _v _u _p _si _su _sf _sw _me; do
    _id=${_si#\*}; _verd=""
    if [ "$_si" != "$_id" ] || { [ "$_su" = "$_u" ] && [ -n "$_me" ] && [ "$_sf" = "$_me" ]; }; then
        _verd="this script"; cc_show "$C_GRN" "  [ok] $_n: $_su from $_sf ($_sw) - this script's own login"
    elif [ "$_sf" = "-" ]; then
        _verd="console"; cc_show "$C_YEL" "  [*] $_n: $_su on the console ($_id) - someone at the device itself"
    elif [ "$_sf" = "?" ]; then
        # OpenWRT web (LuCI) sessions do not say where they come from.
        _verd="web"; cc_show "$C_YEL" "  [*] $_n: $_su logged in to the web page ($_sw) - from where is not known: yours?"
        safe "$_id" && j ses l "$_n" "$_a" "$_v" "$_u" "$_p" "$_id" "$_su" "$_sf" "$_sw" >>"$W/ask"
    elif in_team "$_sf"; then
        _verd="team"; cc_show "$C_GRN" "  [ok] $_n: $_su from $_sf ($_sw) - your team (--team)"
    elif ! safe "$_id" || ! safe "$_su" || ! safe "$_sf"; then
        _verd="odd"; cc_show "$C_RED" "  [!] $_n: a session with odd characters in its name or address: end it in the device's own interface"
    else
        _verd="NOT your team"
        if [ -n "$TEAM" ]; then cc_show "$C_RED" "  [!] $_n: $_su from $_sf ($_sw) - not from your team"
        else cc_show "$C_YEL" "  [*] $_n: $_su from $_sf ($_sw) - yours? (--team CIDR tells your addresses apart)"; _verd="unknown"; fi
        # Never the default (unless --kick-outside with --team): a teammate
        # logged in from somewhere else would be kicked.
        j ses "$([ "$KICKOUT" = 1 ] && [ -n "$TEAM" ] && echo k || echo l)" "$_n" "$_a" "$_v" "$_u" "$_p" "$_id" "$_su" "$_sf" "$_sw" >>"$W/ask"
    fi
    printf '%-14s %-10s %-12s %-16s %-18s %s\n' "$_n" "$_v" "$_id" "$_su" "$_sf" "$_verd" >>"$CC_RUN_DIR/sessions.txt"
done <"$W/allses"
[ -s "$W/allses" ] || cc_show "$C_GRY" "  No sessions read."

# ---- 4. Questions ---------------------------------------------------------------------------
header "4/5  what to do (Enter = the default in capitals)"
how_off() {   # how_off VENDOR DEVICE NAME -> how the account is turned off, for the answer text
    case "$1" in
        mikrotik|linux) echo "disabled; the undo turns it back on" ;;
        openwrt) echo "password locked and shell set to /bin/false; the undo puts both back" ;;
        paloalto) echo "removed and committed; NO automatic undo" ;;
        *) if has_saved "$1" "$2" "$3"; then echo "removed; the undo puts back its lines from NW-01's copy"; else echo "removed; NO undo - NW-01 has no copy of it (run NW-01 first)"; fi ;;
    esac
}
: >"$W/plan"; _all=0
while IFS="$US" read -r _k _d _n _a _v _u _p _x1 _x2 _x3 _x4; do
    if [ "$_k" = acc ]; then
        _what="$_n: account $_x1 ($_x2) - $_x3"
        if [ "$_all" = 0 ]; then
            cc_choose "$_what: what now?" "$_d" "d=disable it - only if you are SURE no teammate uses it ($(how_off "$_v" "$_n" "$_x1"))" "k=keep it" "a=all the rest: take their defaults"
            case "$CC_CHOICE" in a) _all=1 ;; *) _d=$CC_CHOICE ;; esac
        fi
        [ "$_d" = d ] && j off "$_n" "$_a" "$_v" "$_u" "$_p" "$_x1" >>"$W/plan"
    else
        _what="$_n: $_x2 logged in from $_x3 ($_x4, $_x1)"
        if [ "$_v" = fortigate ]; then
            cc_show "$C_YEL" "  [*] $_what: to end it, log in and run: get system admin list, then execute disconnect-admin-session <its number>"; continue
        fi
        if [ "$_x2" = "$_u" ] && [ "$_v" = paloalto ]; then
            cc_show "$C_YEL" "  [*] $_what: same account as this script (Palo Alto ends every session of an account): change its password with NW-10 instead"; continue
        fi
        if [ "$_all" = 0 ]; then
            cc_choose "$_what: what now?" "$_d" "k=kick it (ends the session - only if you are SURE it is not a teammate; change the passwords with NW-10 next)" "l=leave it" "a=all the rest: take their defaults"
            case "$CC_CHOICE" in a) _all=1 ;; *) _d=$CC_CHOICE ;; esac
        fi
        [ "$_d" = k ] && j kick "$_n" "$_a" "$_v" "$_u" "$_p" "$_x1" "$_x2" "$_x3" >>"$W/plan"
    fi
done <"$W/ask"
NCH=$(grep -c . "$W/plan")
: >"$CC_RUN_DIR/plan.txt"
while IFS="$US" read -r _k _n _a _v _u _p _t _x _f; do
    if [ "$_k" = off ]; then _l="$_n: disable account $_t"; else _l="$_n: kick $_x from $_f ($_t)"; fi
    printf '%s\n' "$_l" >>"$CC_RUN_DIR/plan.txt"; cc_show "$C_YEL" "  [~] $_l"
done <"$W/plan"
[ "$NCH" -eq 0 ] && cc_show "$C_GRN" "  [ok] Nothing to kick or disable."

# ---- 5. Apply ---------------------------------------------------------------------------
header "5/5  apply"
# off_cmds VENDOR NAME -> lines that turn the account off (and save)
off_cmds() {
    case "$1" in
        cisco-ios|cisco-asa) printf 'configure terminal\nno username %s\nend\nwrite memory\n' "$2" ;;
        paloalto)  printf 'configure\ndelete mgt-config users %s\ncommit\nexit\n' "$2" ;;
        fortigate) printf 'config system admin\ndelete %s\nend\n' "$2" ;;
        vyos)      printf "source /opt/vyatta/etc/functions/script-template; configure; delete system login user '%s'; commit; save; exit" "$2" ;;
        mikrotik)  printf '/user disable [find name="%s"]' "$2" ;;
        linux)     printf "if [ \"\$(id -u)\" = 0 ]; then S=''; else S='sudo -n'; fi; \$S usermod -L -e 1 '%s'" "$2" ;;
        # OpenWRT has no usermod: ! before the hash, and no shell.
        openwrt)   _on=$2; printf '%s' "sed -i -e 's/^$_on:\\([^!]\\)/$_on:!\\1/' -e 's/^$_on::/$_on:!:/' /etc/shadow && sed -i 's#^\\($_on:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:\\).*\$#\\1/bin/false#' /etc/passwd" ;;  # posix-ok: sent to the OpenWRT router, whose busybox sed has -i
    esac
}
# kick_cmds VENDOR ID USER FROM -> lines that end the session (kicks come last)
kick_cmds() {
    case "$1" in
        cisco-ios) printf 'clear line %s\n\n' "$2" ;;
        cisco-asa) printf 'ssh disconnect %s\n' "$2" ;;
        paloalto)  printf 'delete admin-sessions username %s\n' "$3" ;;
        vyos)      printf "; sudo pkill -KILL -t '%s'" "$2" ;;
        mikrotik)  printf '; /user active request-logout [find name="%s" address="%s"]' "$3" "$4" ;;
        linux)     printf "; if [ \"\$(id -u)\" = 0 ]; then S=''; else S='sudo -n'; fi; \$S pkill -KILL -t '%s'" "$2" ;;
        # OpenWRT: an SSH session is a dropbear process; a web one a ubus session.
        openwrt)   case "$2" in *[!0-9]*) printf "; ubus call session destroy '{\"ubus_rpc_session\":\"%s\"}'" "$2" ;; *) printf '; kill %s' "$2" ;; esac ;;
    esac
}
# write_undo VENDOR DEVICE ADDRESS USER PORT NAME -> an undo script; prints its path
write_undo() {
    mkdir -p "$CC_RUN_DIR/undo"; _uf="$CC_RUN_DIR/undo/$2-$6.sh"
    {
        printf '#!/bin/sh\n# Puts back the account %s on %s (NW-12).  Needs the device password in BT_NET_PASS.\n' "$6" "$2"
        printf '[ -n "$BT_NET_PASS" ] || { echo "set BT_NET_PASS to the device password first" >&2; exit 1; }\n'
        printf 'SSHPASS=$BT_NET_PASS; export SSHPASS\n'
        case "$1" in
            mikrotik) printf '%s -e %s %s -p %s %s %s\n' "$(cc_shquote "$SSHPASS_BIN")" "$(cc_shquote "$SSH")" "$(sshopts | while IFS= read -r _o; do printf '%s ' "$(cc_shquote "$_o")"; done)" "$5" "$(cc_shquote "$4@$3")" "$(cc_shquote "/user enable [find name=\"$6\"]")" ;;
            linux) printf '%s -e %s %s -p %s %s %s\n' "$(cc_shquote "$SSHPASS_BIN")" "$(cc_shquote "$SSH")" "$(sshopts | while IFS= read -r _o; do printf '%s ' "$(cc_shquote "$_o")"; done)" "$5" "$(cc_shquote "$4@$3")" "$(cc_shquote "if [ \"\$(id -u)\" = 0 ]; then S=''; else S='sudo -n'; fi; \$S usermod -U -e '' '$6'")" ;;
            # OpenWRT: the ! comes off the hash and the old shell goes back.
            openwrt) _osh=$(awk -F: -v n="$6" '$1 == n { print $7; exit }' "$W/raw.$2" 2>/dev/null); case "$_osh" in ''|*[!A-Za-z0-9/_.-]*) _osh=/bin/ash ;; esac
                printf '%s -e %s %s -p %s %s %s\n' "$(cc_shquote "$SSHPASS_BIN")" "$(cc_shquote "$SSH")" "$(sshopts | while IFS= read -r _o; do printf '%s ' "$(cc_shquote "$_o")"; done)" "$5" "$(cc_shquote "$4@$3")" "$(cc_shquote "sed -i 's/^$6:!/$6:/' /etc/shadow && sed -i 's#^\($6:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:\)/bin/false\$#\1$_osh#' /etc/passwd")" ;;  # posix-ok: runs on the router
            *)
                # The account's lines are read from NW-01's copy now, not copied here (they hold a hash).
                printf 'CFG=%s\n' "$(cc_shquote "$(latest_cfg "$2")")"
                printf 'LINES=$(awk -v v=%s -v n=%s %s "$CFG")\n' "$(cc_shquote "$1")" "$(cc_shquote "$6")" "$(cc_shquote "$SAVED_AWK")"
                printf '[ -n "$LINES" ] || { echo "the account is no longer in $CFG" >&2; exit 1; }\n'
                case "$1" in
                    cisco-*)   printf 'CMDS=$(printf "%%sconfigure terminal\\n%%s\\nend\\nwrite memory\\nexit\\n" "$(%s)" "$LINES")\n' "$([ "$ENABLE" = 1 ] && printf '[ -n "$BT_NET_ENABLE" ] \&\& printf "enable\\\\n%%s\\\\n" "$BT_NET_ENABLE"' || printf ':')" ;;
                    fortigate) printf 'CMDS=$(printf "config system admin\\n%%s\\nend\\nexit\\n" "$LINES")\n' ;;
                    vyos)      printf 'CMDS=$(printf "source /opt/vyatta/etc/functions/script-template; configure; %%s; commit; save; exit" "$(printf "%%s" "$LINES" | tr "\\n" ";")")\n' ;;
                esac
                if [ "$(mode "$1")" = exec ]; then
                    printf '%s -e %s %s -p %s %s "$CMDS"\n' "$(cc_shquote "$SSHPASS_BIN")" "$(cc_shquote "$SSH")" "$(sshopts | while IFS= read -r _o; do printf '%s ' "$(cc_shquote "$_o")"; done)" "$5" "$(cc_shquote "$4@$3")"
                else
                    printf 'printf "%%s\\n" "$CMDS" | %s -e %s %s -p %s %s\n' "$(cc_shquote "$SSHPASS_BIN")" "$(cc_shquote "$SSH")" "$(sshopts | while IFS= read -r _o; do printf '%s ' "$(cc_shquote "$_o")"; done)" "$5" "$(cc_shquote "$4@$3")"
                fi ;;
        esac
    } >"$_uf"
    chmod 700 "$_uf"; printf '%s' "$_uf"
}
NOK=0; NBAD=0; APPLIED=0
if [ "$NCH" -eq 0 ]; then :
elif [ "$CC_APPLY" != 1 ]; then
    cc_show "$C_GRY" "  Dry run: nothing was changed. Run again with --apply."
    # shellcheck disable=SC2034  # read by cc_finish
    CC_N_WOULD=$NCH
elif cc_ask "Do these $NCH change(s) now?" Y "yes, kick and disable them" "no, change nothing"; then
    APPLIED=1
    # One session per device: accounts first, kicks last (a kick can end our own line).
    cut -d"$US" -f2 "$W/plan" | awk '!s[$0]++' >"$W/plandevs"
    while IFS= read -r _dev; do
        awk -F"$US" -v d="$_dev" '$2 == d' "$W/plan" >"$W/pd"
        IFS="$US" read -r _k _n _a _v _u _p _rest <"$W/pd"
        : >"$W/in"; [ "$(mode "$_v")" = stdin ] && en "$_v" >>"$W/in"
        # disables
        while IFS="$US" read -r _k _n2 _a2 _v2 _u2 _p2 _t _x _f; do
            [ "$_k" = off ] || continue
            if ! cc_guard account "$_t"; then cc_show "$C_YEL" "  [-] $_n: $_t is protected: left"; continue; fi
            case "$_v" in
                mikrotik|linux|openwrt) [ -s "$W/in" ] && printf '; ' >>"$W/in"; off_cmds "$_v" "$_t" >>"$W/in"; _uf=$(write_undo "$_v" "$_n" "$_a" "$_u" "$_p" "$_t"); cc_undo_add "turn the account $_t on $_n back on" "sh $(cc_shquote "$_uf")" ;;
                paloalto) off_cmds "$_v" "$_t" >>"$W/in" ;;
                vyos) [ -s "$W/in" ] && printf '; ' >>"$W/in"; off_cmds "$_v" "$_t" >>"$W/in"
                      has_saved "$_v" "$_n" "$_t" && { _uf=$(write_undo "$_v" "$_n" "$_a" "$_u" "$_p" "$_t"); cc_undo_add "put the account $_t back on $_n" "sh $(cc_shquote "$_uf")"; } ;;
                *) off_cmds "$_v" "$_t" >>"$W/in"
                   has_saved "$_v" "$_n" "$_t" && { _uf=$(write_undo "$_v" "$_n" "$_a" "$_u" "$_p" "$_t"); cc_undo_add "put the account $_t back on $_n" "sh $(cc_shquote "$_uf")"; } ;;
            esac
            j off "$_t" >>"$W/done.$_n"
        done <"$W/pd"
        # kicks
        while IFS="$US" read -r _k _n2 _a2 _v2 _u2 _p2 _t _x _f; do
            [ "$_k" = kick ] || continue
            case "$(mode "$_v")" in
                exec) [ -s "$W/in" ] || printf ':' >>"$W/in"; kick_cmds "$_v" "$_t" "$_x" "$_f" >>"$W/in" ;;
                *) kick_cmds "$_v" "$_t" "$_x" "$_f" >>"$W/in" ;;
            esac
            j kick "$_t" "$_x" "$_f" >>"$W/done.$_n"
        done <"$W/pd"
        [ "$(mode "$_v")" = stdin ] && printf 'exit\n' >>"$W/in"
        [ -s "$W/done.$_n" ] || continue
        if session "$_v" "$_u" "$_a" "$_p" "$W/in" "$W/apply.$_n"; then _ok=1; else _ok=0; fi
        # A kick may close our own session on some brands: judge by reading again.
        read_cmds "$_v" >"$W/in2"
        if session "$_v" "$_u" "$_a" "$_p" "$W/in2" "$W/after.$_n"; then
            : >"$W/acc"; : >"$W/ses"; parse "$_v" "$W/after.$_n"
            while IFS="$US" read -r _w _t _x _f; do
                if [ "$_w" = off ]; then
                    if awk -F"$US" -v n="$_t" '$1 == n && $3 != "disabled" { f = 1 } END { exit !f }' "$W/acc"; then NBAD=$((NBAD + 1)); cc_show "$C_RED" "  [x] $_n: account $_t is still there"
                    else NOK=$((NOK + 1)); cc_show "$C_GRN" "  [+] $_n: account $_t disabled"; fi
                else
                    if awk -F"$US" -v i="$_t" -v u="$_x" -v f="$_f" '($1 == i || $1 == "*" i) && $2 == u && $3 == f { g = 1 } END { exit !g }' "$W/ses"; then NBAD=$((NBAD + 1)); cc_show "$C_RED" "  [x] $_n: $_x from $_f is still logged in"
                    else NOK=$((NOK + 1)); cc_show "$C_GRN" "  [+] $_n: kicked $_x from $_f"; fi
                fi
            done <"$W/done.$_n"
        else
            _c=$(grep -c . "$W/done.$_n"); NBAD=$((NBAD + _c)); cc_show "$C_RED" "  [x] $_n: could not log in again to check $([ "$_ok" = 1 ] && echo '(the changes were sent)' || echo '(the change session failed too)'): look by hand"
        fi
    done <"$W/plandevs"
else cc_show "$C_GRY" "  Nothing done."; fi
# Accounts kept on purpose (with --apply) join the baseline; disabled ones stay out.
if [ "$CC_APPLY" = 1 ] && [ "$FIRST" = 0 ] && { [ "$APPLIED" = 1 ] || [ "$NCH" -eq 0 ]; }; then
    awk -F"$US" '{ print $1 " " $6 }' "$W/allacc" >"$W/now"
    while IFS= read -r _l; do
        grep -qxF "$_l" "$BASE" && continue
        awk -F"$US" -v l="$_l" '$1 == "off" && ($2 " " $7) == l { f = 1 } END { exit !f }' "$W/plan" || printf '%s\n' "$_l" >>"$BASE"
    done <"$W/now"
fi
# shellcheck disable=SC2034  # read by cc_finish
CC_N_DONE=$NOK
# shellcheck disable=SC2034  # read by cc_finish
CC_N_FAIL=$((NBAD + NFAIL))

{
    printf '==========[ summary ]==========\n'
    printf 'NW-12 Device accounts and sessions | %s\n' "$([ "$APPLIED" = 1 ] && echo APPLIED || echo 'DRY RUN - nothing changed')"
    printf 'Devices read: %d   could not log in: %d\n' "$NDEV" "$NFAIL"
    printf 'Accounts: %d (%d new since the first run)   Sessions: %d\n' "$(grep -c . "$W/allacc")" "$(grep -c 'NEW since' "$W/ask")" "$(grep -c . "$W/allses")"
    [ -s "$CC_RUN_DIR/plan.txt" ] && { printf 'Changes%s:\n' "$([ "$APPLIED" = 1 ] || echo ' planned')"; sed 's/^/  /' "$CC_RUN_DIR/plan.txt"; }
    [ "$APPLIED" = 1 ] && printf 'Done: %d   Failed: %d\n' "$NOK" "$NBAD"
    printf '\nNext: change the device passwords (NW-10) - a kicked session can log in again until then.\n'
    printf 'Tables: accounts.txt, sessions.txt\n'
    [ -d "$CC_RUN_DIR/undo" ] && printf 'Undo a disabled account: BT_NET_PASS=... sh %s/undo/DEVICE-ACCOUNT.sh\n' "$CC_RUN_DIR"
} >"$CC_RUN_DIR/summary.txt"
cc_show "" ""
while IFS= read -r _l; do case "$_l" in ==*|NW-12*) cc_show "$C_CYN" "$_l" ;; *'Failed: '[1-9]*|*'log in: '[1-9]*) cc_show "$C_RED" "$_l" ;; *) cc_show "" "$_l" ;; esac; done <"$CC_RUN_DIR/summary.txt"
rm -rf "$W"
cc_finish
