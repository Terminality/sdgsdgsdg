#!/bin/sh
# =============================================================================
# ID:       SV-26
# NAME:     Brute-force and spam banning
# ROLE:     Linux  (wave 2)
# KIND:     changes - dry run unless --apply
# VERSION:  2.0.0
#
# PURPOSE
#   Reads the login logs, counts failed logins per source address, and bans
#   an address that passes the limit with a firewall entry that REMOVES
#   ITSELF after the ban time - so a mistake fixes itself.
#     ssh        "Failed password", invalid-user scans, too many auth tries
#     ftp        vsftpd, proftpd, pure-ftpd login failures
#     mail       postfix SASL failures and relay attempts, dovecot (IMAP/POP)
#     web        POSTs to login pages (wp-login.php, xmlrpc.php, Joomla,
#                Drupal, phpMyAdmin, Roundcube, /login) and HTTP 401s, with
#                their own, higher limit
#     pam        any other "authentication failure ... rhost=" line
#   Spam is REPORTED, not banned: a sender mailing more than --mail-max
#   recipients in the window (a compromised mailbox).
#
#   NEVER BANNED: your team and the scoring engine (the question, --ignore,
#   protected hosts), this box's own addresses, loopback, and the default
#   gateway - with NAT every outside client looks like the gateway, and
#   banning it would cut off scoring.  Those are reported instead.
#
#   QUESTIONS (Enter takes the [default]; a flag answers each one ahead):
#     failed logins before a ban            --max-fails N   (10)
#     web login attempts before a ban       --web-max N     (30)
#     ban length in minutes                 --ban-time MIN  (30)
#     services to watch                     --services "ssh mail" (all)
#     addresses never to ban                --ignore / --team ADDR
#     seconds between checks (0 = once)     --loop N / --once   (60)
#   --batch, or no terminal: the defaults, and ONE check.  Answers are saved
#   as the next run's defaults.
#
#   How it counts without parsing log dates: each check reads only the lines
#   added since the last one and stores the counts with the check's time;
#   the window is the sum of the checks in the last --window minutes.  The
#   first check reads the last --history lines.
#
# USAGE
#   sudo sh SV-26-banning.sh                                   asks; dry run
#   sudo sh SV-26-banning.sh --protected p.csv --apply         asks, then bans
#   sudo sh SV-26-banning.sh --protected p.csv --apply --batch --loop 60 --team 10.0.0.0/24
#   sudo sh SV-26-banning.sh --list                            current bans
#   sudo sh SV-26-banning.sh --apply --unban 10.6.6.6
#   sudo sh SV-26-banning.sh --apply --unban-all               lift every ban now
#
# OPTIONS
#   --max-fails N    failures in the window that earn a ban (default 10)
#   --web-max N      web login attempts that earn a ban (default 30)
#   --window MIN     counting window in minutes (default 10)
#   --ban-time MIN   ban length in minutes (default 30)
#   --services LIST  only these: ssh ftp mail web pam (default all)
#   --mail-max N     recipients per sender in the window before a spam
#                    warning (default 200)
#   --ignore ADDR    never ban this address or network (repeat; --team too)
#   --log FILE       read this log (repeat).  When given, ONLY these logs are
#                    read, not the usual ones or the journal
#   --history N      lines read from each log on the first check (default 2000)
#   --loop N         check every N seconds (at least 10) until Ctrl-C
#   --once           check once
#   --count N        with --loop: stop after N checks
#   --backend NAME   nft, ipset or iptables (default: nft, else ipset, else
#                    iptables)
#   --list           show the current bans and exit
#   --unban IP       remove one ban and exit (with --apply)
#   --unban-all      remove every ban and the ban table (with --apply)
#   --state DIR      where offsets, counts and the ban history live
#                    (default <out>/ban-<host>)
#   --no-color       no colours
#   --help           this text plus the common options
#
# OUTPUTS
#   <out>/banning-N/       this run:
#     output.txt         everything shown on screen, no colour
#     bans.txt           bans made (or that would be made) this run
#     offenders.txt      every address with failures, per check, and why it
#                        was or was not banned (csv/ has both as CSV)
#     summary.txt, run.txt
#   <out>/ban-<host>/      kept between runs:
#     bans.csv           every ban ever: time,address,services,failures,
#                        accounts_tried,until,action
#     events.log         one line per check
#     hits, offsets      counts for the window, how far each log was read
#     settings           your answers, used as the next defaults
#
# WHAT IT CHANGES  (only with --apply)
#   nftables: table "inet ccdc_ban" (two address sets with timeouts and one
#   drop rule).  ipset: set "ccdc_ban" plus one iptables rule.  iptables
#   alone: one DROP rule per banned address, removed by a later check when
#   the ban ends.  --unban-all (or the undo log) removes it all.  No other
#   rule is touched.  There is no revert timer: every ban already ends by
#   itself, and the never-ban list keeps your team and scoring safe.
#
# DEPENDS ON
#   awk, tail, wc; nft or ipset+iptables or iptables; journalctl when the
#   SSH log is only in the journal.  CCDC_NFT, CCDC_IPSET and CCDC_IPTABLES
#   may name stand-ins (the tests use them).
#
# TESTED ON
#   Ubuntu 24.04 under dash, bash, busybox sh, ksh93, mksh and yash with
#   gawk, mawk and busybox awk, sample logs and stand-in firewalls; live:
#   real failed SSH logins from a separate network namespace got that
#   address banned in nftables, and the ban expired by itself.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - A red team with many addresses is slowed, not stopped.
#   - The scoring engine fails logins too (after a password change): give
#     its address to the never-ban question or the protected list.
#   - Log formats differ between versions; a service whose failures are not
#     counted shows nothing, not an error.  Check with --log and --debug.
#
# DEBUGGING
#   --debug shows each log read and the counts per address.  events.log has
#   one line per check.  "nft list table inet ccdc_ban" shows the bans.
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
#   CCDC_NO_TTY=1 says there is nobody (the test suite sets it, so tests
#   never wait for an answer when run from a terminal).
_cc_can_ask() { [ "$CC_BATCH" != 1 ] && [ "${CCDC_NO_TTY:-0}" != 1 ] && [ -r /dev/tty ] && [ -w /dev/tty ] && ( : </dev/tty ) 2>/dev/null; }

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
SV-26 Brute-force and spam banning - timed bans for addresses that keep failing logins
  sudo sh SV-26-banning.sh                       asks; dry run
  sudo sh SV-26-banning.sh --protected p.csv --apply    asks, then bans

  --max-fails N    failures that earn a ban (default 10)
  --web-max N      web login attempts that earn a ban (default 30)
  --ban-time MIN   ban length (default 30)
  --window MIN     counting window (default 10)
  --services LIST  only these: ssh ftp mail web pam (default all)
  --ignore ADDR    never ban this address/network (repeatable; --team too)
  --mail-max N     recipients per sender before a spam warning (default 200)
  --log FILE       read only these logs (repeatable)
  --history N      lines read per log on the first check (default 2000)
  --loop N         check every N seconds; --once; --count N stops after N
  --backend nft|ipset|iptables
  --list           show current bans
  --unban IP       remove a ban (with --apply)
  --unban-all      remove every ban (with --apply)
  --state DIR      state folder
  --no-color       no colours
  --help           show this text

USAGE
    cc_usage_common
}

NL='
'
MAXF=""; WEBMAX=""; WINDOW=10; BANTIME=""; MAILMAX=200; IGNORE=""; IGNSET=0; LOGS=""; HIST=2000
LOOP=""; COUNT=0; BACKEND=""; MODE=run; UNBAN=""; STATE=""; SERVICES=""; COLOR=1
num() { case "$2" in ''|*[!0-9]*) cc_die 2 "$1 needs a whole number" ;; esac; }
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --max-fails) num "$1" "${2:-}"; MAXF=$2; shift 2 ;;
        --web-max)   num "$1" "${2:-}"; WEBMAX=$2; shift 2 ;;
        --window)    num "$1" "${2:-}"; WINDOW=$2; shift 2 ;;
        --ban-time)  num "$1" "${2:-}"; BANTIME=$2; shift 2 ;;
        --mail-max)  num "$1" "${2:-}"; MAILMAX=$2; shift 2 ;;
        --history)   num "$1" "${2:-}"; HIST=$2; shift 2 ;;
        --loop)      num "$1" "${2:-}"; LOOP=$2; shift 2 ;;
        --once)      LOOP=0; shift ;;
        --count)     num "$1" "${2:-}"; COUNT=$2; shift 2 ;;
        --services)  [ $# -ge 2 ] || cc_die 2 "--services needs a list"; SERVICES=$2; shift 2 ;;
        --ignore|--team) [ $# -ge 2 ] || cc_die 2 "$1 needs an address"
                     IGNORE="$IGNORE$(printf '%s' "$2" | tr ', ' '\n\n')$NL"; IGNSET=1; shift 2 ;;
        --log)       [ $# -ge 2 ] || cc_die 2 "--log needs a file"; [ -r "$2" ] || cc_die 2 "--log: cannot read $2"; LOGS="$LOGS$(cc_abspath "$2")$NL"; shift 2 ;;
        --backend)   [ $# -ge 2 ] || cc_die 2 "--backend needs a name"; BACKEND=$2; shift 2 ;;
        --list)      MODE=list; shift ;;
        --unban)     [ $# -ge 2 ] || cc_die 2 "--unban needs an address"; MODE=unban; UNBAN=$2; shift 2 ;;
        --unban-all) MODE=unbanall; shift ;;
        --state)     [ $# -ge 2 ] || cc_die 2 "--state needs a folder"; STATE=$2; shift 2 ;;
        --no-color|--no-colour) COLOR=0; shift ;;
        --help|-h)   usage; exit 0 ;;
        *)           cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
case "$BACKEND" in ''|nft|ipset|iptables) ;; *) cc_die 2 "--backend must be nft, ipset or iptables" ;; esac
# ok_loop N -> exits 2 unless N is 0 or 10 or more.
ok_loop() { num "--loop" "$1"; [ "$1" -gt 0 ] && [ "$1" -lt 10 ] && cc_die 2 "--loop must be at least 10 seconds (or 0 for one check)"; return 0; }
[ -n "$LOOP" ] && ok_loop "$LOOP"
# ok_limits -> every limit is a whole number of at least 1.
ok_limits() {
    for _v in "$MAXF" "$WEBMAX" "$WINDOW" "$BANTIME"; do
        [ -z "$_v" ] && continue
        num "a limit" "$_v"; [ "$_v" -ge 1 ] || cc_die 2 "limits, window and ban time must be at least 1"
    done
}
ok_limits
# ok_services LIST -> exits 2 on an unknown service name.
ok_services() {
    for _s in $(printf '%s' "$1" | tr ',' ' '); do
        case "$_s" in ssh|ftp|mail|web|pam|all) ;; *) cc_die 2 "unknown service: $_s (use ssh ftp mail web pam or all)" ;; esac
    done
}
[ -n "$SERVICES" ] && ok_services "$SERVICES"
# valid_addr A -> IPv4 address or network with every part 0-255 and a
# prefix 0-32, or an IPv6 address.
valid_addr() {
    printf '%s\n' "$1" | awk '/^[0-9a-fA-F]*:[0-9a-fA-F:]*$/ { exit 0 }
        { n = split($0, x, "/"); if (n > 2 || (n == 2 && (x[2] !~ /^[0-9]+$/ || x[2] > 32))) exit 1
          if (split(x[1], o, ".") != 4) exit 1
          for (i = 1; i <= 4; i++) if (o[i] !~ /^[0-9]+$/ || o[i] > 255) exit 1 }'
}
for _a in $IGNORE; do valid_addr "$_a" || cc_die 2 "--ignore: not an address or network: $_a"; done

cc_init "SV-26" "Brute-force and spam banning" changes
cc_detect_os
# shellcheck disable=SC2034  # read by cc_color_init
[ "$COLOR" = 1 ] || CC_NOCOLOR=1
cc_color_init
[ "$CC_APPLY" = 1 ] && cc_require_root
[ -n "$STATE" ] || STATE="$CC_OUT/ban-$CC_HOST"
(umask 077; mkdir -p "$STATE") || cc_die 3 "cannot create $STATE"
STATE=$(cc_abspath "$STATE")
BANS="$STATE/bans.csv"
[ -f "$BANS" ] || printf 'time,address,services,failures,accounts_tried,until,action\n' >"$BANS"
header() { cc_show "" ""; cc_show "$C_CYN" "==========[ $1 ]=========="; }
setting() { [ -f "$STATE/settings" ] && sed -n "s/^$1=//p" "$STATE/settings" | tail -n 1; }

# now -> seconds since 1970 (date +%s where it works, else awk's srand trick).
now() { _t=$(date +%s 2>/dev/null); case "$_t" in ''|*[!0-9]*) awk 'BEGIN { srand(); print srand() }' ;; *) printf '%s\n' "$_t" ;; esac; }

# ---- Firewall backend --------------------------------------------------------
NFT=${CCDC_NFT:-$(cc_which nft)} || NFT=""
IPSET=${CCDC_IPSET:-$(cc_which ipset)} || IPSET=""
IPT=${CCDC_IPTABLES:-$(cc_which iptables)} || IPT=""
if [ -z "$BACKEND" ]; then
    if [ -n "$NFT" ] && "$NFT" list tables >/dev/null 2>&1; then BACKEND=nft
    elif [ -n "$IPSET" ] && [ -n "$IPT" ]; then BACKEND=ipset
    elif [ -n "$IPT" ]; then BACKEND=iptables
    else cc_die 3 "no firewall tool found (nft, ipset or iptables)"; fi
fi
cc_debug "backend: $BACKEND"

# fw_setup -> create the ban table/set once (keeps bans across runs).
_fw_ready=0
fw_setup() {
    [ "$_fw_ready" = 1 ] && return 0
    case "$BACKEND" in
        nft)
            if ! "$NFT" list table inet ccdc_ban >/dev/null 2>&1; then
                cat >"$W/ban.nft" <<'EOF'
table inet ccdc_ban {
    set ban4 { type ipv4_addr; flags timeout; }
    set ban6 { type ipv6_addr; flags timeout; }
    chain input {
        type filter hook input priority -5; policy accept;
        ip saddr @ban4 drop
        ip6 saddr @ban6 drop
    }
}
EOF
                cc_run "create the ban table (nft table inet ccdc_ban)" "$NFT" -f "$W/ban.nft" || return 1
                cc_undo_add "remove all SV-26 bans" "$NFT delete table inet ccdc_ban"
            fi ;;
        ipset)
            if ! "$IPSET" list ccdc_ban >/dev/null 2>&1; then
                cc_run "create the ban set (ipset ccdc_ban)" "$IPSET" create ccdc_ban hash:ip timeout 0 -exist || return 1
                cc_undo_add "remove all SV-26 bans" "$IPT -D INPUT -m set --match-set ccdc_ban src -j DROP; $IPSET destroy ccdc_ban"
            fi
            "$IPT" -C INPUT -m set --match-set ccdc_ban src -j DROP 2>/dev/null ||
                cc_run "drop traffic from banned addresses" "$IPT" -I INPUT 1 -m set --match-set ccdc_ban src -j DROP || return 1 ;;
        iptables) : ;;
    esac
    _fw_ready=1
}
# fw_ban IP SECONDS
fw_ban() {
    case "$BACKEND" in
        nft) case "$1" in *:*) _set=ban6 ;; *) _set=ban4 ;; esac
             cc_run "ban $1 for $(($2 / 60)) min" "$NFT" add element inet ccdc_ban "$_set" "{ $1 timeout ${2}s }" ;;
        ipset) cc_run "ban $1 for $(($2 / 60)) min" "$IPSET" add ccdc_ban "$1" timeout "$2" -exist ;;
        iptables) cc_run "ban $1 for $(($2 / 60)) min" "$IPT" -I INPUT 1 -s "$1" -j DROP -m comment --comment ccdc_ban
                  _rc=$?; [ "$_rc" -eq 0 ] && cc_undo_add "unban $1" "$IPT -D INPUT -s $1 -j DROP -m comment --comment ccdc_ban"; return "$_rc" ;;
    esac
}
fw_unban() {
    case "$BACKEND" in
        nft) case "$1" in *:*) _set=ban6 ;; *) _set=ban4 ;; esac
             cc_run "unban $1" "$NFT" delete element inet ccdc_ban "$_set" "{ $1 }" ;;
        ipset) cc_run "unban $1" "$IPSET" del ccdc_ban "$1" ;;
        iptables) cc_run "unban $1" "$IPT" -D INPUT -s "$1" -j DROP -m comment --comment ccdc_ban ;;
    esac
}
# fw_list -> currently banned addresses, one per line.
fw_list() {
    case "$BACKEND" in
        nft) "$NFT" list table inet ccdc_ban 2>/dev/null | awk '/elements = \{/ { s = 1 } s { gsub(/elements = \{|[{},]/, " "); for (i = 1; i <= NF; i++) if ($i ~ /^[0-9a-fA-F.:]+$/ && $i ~ /[.:]/ && $(i - 1) != "timeout" && $(i - 1) != "expires") print $i } /\}/ { s = 0 }' ;;
        ipset) "$IPSET" list ccdc_ban 2>/dev/null | awk '/^Members:/ { s = 1; next } s && NF { print $1 }' ;;
        iptables) "$IPT" -S INPUT 2>/dev/null | awk '/ccdc_ban/ && /-s / { for (i = 1; i <= NF; i++) if ($i == "-s") { a = $(i + 1); sub(/\/32$/, "", a); print a } }' ;;
    esac
}

# ---- --list, --unban, --unban-all -------------------------------------------------
if [ "$MODE" != run ]; then
    W="$STATE/.work"; mkdir -p "$W"
    case "$MODE" in
        list)
            cc_show "$C_CYN" "Banned now ($BACKEND):"
            fw_list >"$W/now"
            if [ -s "$W/now" ]; then
                while IFS= read -r _a; do
                    _why=$(awk -F, -v a="$_a" '$2 == a && $7 == "banned" { w = $3 ", " $4 " failures at " $1 } END { print w }' "$BANS")
                    cc_show "$C_RED" "  [!] $(printf '%-39s' "$_a") ${_why:-}"
                done <"$W/now"
            else
                cc_show "$C_GRN" "  [ok] nobody"
            fi
            cc_show "" "History: $BANS" ;;
        unban)
            valid_addr "$UNBAN" || cc_die 2 "--unban: not an address: $UNBAN"
            fw_unban "$UNBAN"
            [ "$CC_APPLY" = 1 ] && printf '%s,%s,,,,,unbanned by hand\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$UNBAN" >>"$BANS" ;;
        unbanall)
            fw_list >"$W/now"
            cc_show "" "Lifting $(grep -c . "$W/now") ban(s):"
            case "$BACKEND" in
                nft) "$NFT" list table inet ccdc_ban >/dev/null 2>&1 && cc_run "remove the ban table (nft table inet ccdc_ban)" "$NFT" delete table inet ccdc_ban ;;
                ipset) "$IPT" -C INPUT -m set --match-set ccdc_ban src -j DROP 2>/dev/null &&
                           cc_run "remove the ban rule" "$IPT" -D INPUT -m set --match-set ccdc_ban src -j DROP
                       "$IPSET" list ccdc_ban >/dev/null 2>&1 && cc_run "remove the ban set" "$IPSET" destroy ccdc_ban ;;
                iptables) while IFS= read -r _a; do fw_unban "$_a"; done <"$W/now"
                          [ "$CC_APPLY" = 1 ] && rm -f "$STATE/iptables-expiry" ;;
            esac
            [ "$CC_APPLY" = 1 ] && printf '%s,ALL,,,,,unbanned by hand (--unban-all)\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$BANS" ;;
    esac
    [ "$CC_APPLY" = 1 ] || [ "$MODE" = list ] || cc_show "$C_YEL" "Dry run: nothing changed. Add --apply."
    rm -rf "$W"
    cc_finish
fi

cc_use_numbered_dir banning
CC_CSV_DIR="$CC_RUN_DIR/csv"
mkdir -p "$CC_CSV_DIR" || cc_die 3 "cannot create $CC_CSV_DIR"
rmdir "$CC_RUN_DIR/raw" 2>/dev/null
OUTF="$CC_RUN_DIR/output.txt"; : >"$OUTF"
# shellcheck disable=SC2034  # CC_TEE is read by the library's log functions
CC_TEE=$OUTF
W="$CC_RUN_DIR/.work"; mkdir -p "$W"

cc_show "$C_CYN" "SV-26 Banning | host $CC_HOST | results in $CC_RUN_DIR"
cc_show "$C_CYN" "Ban history and counts in $STATE"
if [ "$CC_APPLY" = 1 ]; then
    cc_show "$C_RED" "Mode: BANNING - addresses over the limit are blocked in the firewall (each ban ends by itself)"
else
    cc_show "$C_YEL" "Mode: DRY RUN - shows who WOULD be banned, blocks nothing. Add --apply to ban."
fi
cc_show "" "Legend: ${C_RED}[!]${C_OFF} banned   ${C_YEL}[*]${C_OFF} would ban / check this   ${C_GRY}[-]${C_OFF} watching   ${C_GRN}[ok]${C_OFF} quiet"

# ---- 1/4 Questions -------------------------------------------------------------------
header "1/4  setup: limits and who never to ban"
if [ -z "$MAXF" ]; then
    cc_ask_text "How many failed logins (SSH, FTP, mail) in $WINDOW minutes before a ban?" "$(setting maxfails | grep . || echo 10)" "a number, like 10"; MAXF=$CC_ANSWER
fi
if [ -z "$WEBMAX" ]; then
    cc_ask_text "How many web login attempts in $WINDOW minutes before a ban? (real users log in once)" "$(setting webmax | grep . || echo 30)" "a number, like 30"; WEBMAX=$CC_ANSWER
fi
if [ -z "$BANTIME" ]; then
    cc_ask_text "How long is a ban? (it ends by itself)" "$(setting bantime | grep . || echo 30)" "minutes, like 30"; BANTIME=$CC_ANSWER
fi
ok_limits
if [ -z "$SERVICES" ]; then
    cc_ask_text "Which services to watch?" "$(setting services | grep . || echo all)" "names separated by spaces from: ssh ftp mail web pam - or all"
    SERVICES=$CC_ANSWER; ok_services "$SERVICES"
fi
SERVICES=$(printf '%s' "$SERVICES" | tr ',' ' ' | sed 's/^ *//; s/ *$//'); [ -n "$SERVICES" ] || SERVICES=all
case " $SERVICES " in *" all "*) SERVICES=all ;; esac
if [ "$IGNSET" = 0 ]; then
    cc_ask_text "Addresses never to ban: your team and the scoring engine?" "$(setting never)" "addresses or networks separated by spaces, like 10.0.0.5 10.0.0.0/24"
    IGNORE=$(printf '%s' "$CC_ANSWER" | tr ', ' '\n\n')
    for _a in $IGNORE; do valid_addr "$_a" || cc_die 2 "not an address or network: $_a"; done
fi
if [ -z "$LOOP" ]; then
    if _cc_can_ask; then cc_ask_text "How often should it check?" 60 "seconds between checks, like 60; 0 = check once and stop"; LOOP=$CC_ANSWER; ok_loop "$LOOP"
    else LOOP=0; fi
fi
printf 'maxfails=%s\nwebmax=%s\nbantime=%s\nservices=%s\nnever=%s\n' "$MAXF" "$WEBMAX" "$BANTIME" "$SERVICES" "$(printf '%s' "$IGNORE" | grep . | tr '\n' ' ' | sed 's/ $//')" >"$STATE/settings"
cc_show "" ""
cc_show "" "  Ban after:    $MAXF failed logins, or $WEBMAX web login attempts, in $WINDOW minutes"
cc_show "" "  Ban length:   $BANTIME minutes"
cc_show "" "  Services:     $SERVICES"
cc_show "" "  Checks:       $([ "$LOOP" -gt 0 ] && echo "every $LOOP seconds$([ "$COUNT" -gt 0 ] && echo ", $COUNT times") (Ctrl-C stops and prints the summary)" || echo once)"

# ---- 2/4 What it reads -------------------------------------------------------------
header "2/4  logs, firewall and the never-ban list"
# Never banned: team/--ignore, loopback, protected hosts, own addresses, gateways.
{
    printf '%s\n' "$IGNORE" | grep . | sed 's/$/ team/'
    printf '127.0.0.0/8 loopback\n::1 loopback\n'
    if [ -n "$CC_PROTECTED" ]; then awk -F',' '{ gsub(/[ "\r]/, "") } tolower($1) == "host" { print $2 " protected" }' "$CC_PROTECTED"; fi
    if cc_have ip; then
        ip -o addr 2>/dev/null | awk '{ a = $4; sub(/\/.*/, "", a); print a " own" }'
        ip route 2>/dev/null | awk '$1 == "default" { for (i = 1; i <= NF; i++) if ($i == "via") print $(i + 1) " gateway" }'
    fi
} | grep . | awk '!seen[$1]++' >"$W/never"
cc_debug "never banned: $(tr '\n' ' ' <"$W/never")"
# AWK_NEVER: never(ip) is 1 when ip matches a line of the never-ban file
# (exact, or inside an IPv4 network).  NV is the entry that matched, why[NV]
# the reason (team, loopback, protected, own, gateway).
AWK_NEVER='
function ip2n(a,   p) { if (split(a, p, ".") != 4) return -1; return ((p[1] * 256 + p[2]) * 256 + p[3]) * 256 + p[4] }  # awk, not shell: posix-ok
function loadnever(f,   l, n, x) { while ((getline l < f) > 0) { split(l, x, " "); nv[++nn] = x[1]; why[x[1]] = x[2] } }  # awk, not shell: posix-ok
function never(ip,   i, j, net, bits, base, size) {  # awk, not shell: posix-ok
    for (i = 1; i <= nn; i++) {
        if (nv[i] == ip) { NV = nv[i]; return 1 }
        if (index(nv[i], "/") && ip !~ /:/) {
            # 2 to the power (32 - bits) by multiplying: some busybox awks
            # are built without math support, so "^" is not available.
            split(nv[i], net, "/"); bits = net[2] + 0; base = ip2n(net[1]); size = 1
            for (j = bits; j < 32; j++) size = size * 2
            if (base >= 0 && ip2n(ip) >= int(base / size) * size && ip2n(ip) < int(base / size) * size + size) { NV = nv[i]; return 1 }
        }
    }
    return 0
}'

if [ -n "$LOGS" ]; then
    printf '%s' "$LOGS" | grep . >"$W/logs"
    USEJOURNAL=0
else
    : >"$W/logs"
    for _f in /var/log/auth.log /var/log/secure /var/log/vsftpd.log /var/log/proftpd/proftpd.log /var/log/pure-ftpd/pure-ftpd.log \
              /var/log/mail.log /var/log/maillog /var/log/apache2/access.log /var/log/apache2/other_vhosts_access.log \
              /var/log/httpd/access_log /var/log/httpd/ssl_access_log /var/log/nginx/access.log; do
        [ -f "$_f" ] && [ -r "$_f" ] && printf '%s\n' "$_f" >>"$W/logs"
    done
    for _f in /var/log/apache2/*access*.log /var/log/nginx/*access*.log; do
        [ -f "$_f" ] && ! grep -qxF "$_f" "$W/logs" && printf '%s\n' "$_f" >>"$W/logs"
    done
    # The journal holds SSH and mail logs when there is no syslog file.
    USEJOURNAL=0
    if cc_have journalctl && [ ! -s /var/log/auth.log ] && [ ! -s /var/log/secure ]; then USEJOURNAL=1; fi
fi
# what_log FILE -> what that log tells us, in words.
what_log() {
    case "$1" in
        *auth.log|*secure) echo "SSH, PAM logins" ;;
        *vsftpd*|*proftpd*|*pure-ftpd*) echo "FTP logins" ;;
        *mail.log|*maillog) echo "SMTP and IMAP/POP logins, mail volume" ;;
        *access*) echo "web login pages" ;;
        *) echo "read for every kind of failure" ;;
    esac
}
cc_show "" "  Logs read:"
while IFS= read -r _f; do cc_show "" "    $_f  ($(what_log "$_f"))"; done <"$W/logs"
[ "$USEJOURNAL" = 1 ] && cc_show "" "    the systemd journal  (SSH, FTP and mail: no auth.log on this box)"
[ -s "$W/logs" ] || [ "$USEJOURNAL" = 1 ] || cc_show "$C_YEL" "    [!] no login logs found - nothing can be counted (use --log FILE)"
cc_show "" "  Firewall:     $BACKEND$([ "$BACKEND" = nft ] && echo ' (table inet ccdc_ban, entries time out by themselves)')"
cc_show "" "  Never banned:"
while read -r _a _why; do
    case "$_why" in
        team) _w="your team / scoring (your answer)" ;; protected) _w="protected list" ;; own) _w="this box" ;;
        gateway) _w="default gateway - with NAT every outside client looks like it" ;; *) _w=$_why ;;
    esac
    cc_show "" "    $(printf '%-24s' "$_a") $_w"
done <"$W/never"
grep -q ' team$\| protected$' "$W/never" || cc_show "$C_YEL" "    [!] no team or scoring address given: the scoring engine can be banned after a password change"

# ---- Reading new log lines ----------------------------------------------------------
# Dry runs keep their counts in the run folder, so a dry loop reads each
# line once but the real state is never touched.
if [ "$CC_APPLY" = 1 ]; then DS=$STATE; else DS="$W/dry"; mkdir -p "$DS"; cp "$STATE/offsets" "$STATE/hits" "$DS/" 2>/dev/null; fi
[ -f "$DS/offsets" ] || : >"$DS/offsets"
: >"$W/wouldban"
# read_new -> every line added since the last run, from every log, on stdout.
#   Offsets are only saved when changes are applied, so dry runs can repeat.
read_new() {
    : >"$W/offsets.new"
    while IFS= read -r _f; do
        _size=$(wc -c 2>/dev/null <"$_f" | tr -d ' ')
        _off=$(awk -F'\t' -v f="$_f" '$1 == f { print $2 }' "$DS/offsets")
        if [ -z "$_off" ]; then
            tail -n "$HIST" "$_f" 2>/dev/null
        elif [ "$_size" -lt "$_off" ]; then
            cat "$_f"           # rotated or truncated: start again
        elif [ "$_size" -gt "$_off" ]; then
            tail -c +"$((_off + 1))" "$_f" 2>/dev/null
        fi
        printf '%s\t%s\n' "$_f" "$_size" >>"$W/offsets.new"
    done <"$W/logs"
    if [ "$USEJOURNAL" = 1 ]; then
        _since=$(awk -F'\t' '$1 == "journal" { print $2 }' "$DS/offsets")
        if [ -n "$_since" ]; then
            journalctl -q --no-pager -o short --since "$_since" -t sshd -t sshd-session -t postfix/smtpd -t postfix/qmgr -t dovecot -t vsftpd -t proftpd -t pure-ftpd 2>/dev/null
        else
            journalctl -q --no-pager -o short -n "$HIST" -t sshd -t sshd-session -t postfix/smtpd -t postfix/qmgr -t dovecot -t vsftpd -t proftpd -t pure-ftpd 2>/dev/null
        fi
        printf 'journal\t%s\n' "$(date '+%Y-%m-%d %H:%M:%S')" >>"$W/offsets.new"
    fi
}

# PARSE: log lines -> "service|address|account" for each failure, and
#   "mailout|sender|recipients" for each queued message.
PARSE='
function clean(a) { gsub(/[][()"]/, "", a); sub(/^::ffff:/, "", a); sub(/%.*/, "", a); return a }  # awk, not shell: posix-ok
function after(s, word,   i) { i = index(s, word); return i ? substr(s, i + length(word)) : "" }  # awk, not shell: posix-ok
function first(s,   f) { split(s, f, /[ \t,;>]/); return f[1] }  # awk, not shell: posix-ok
# isip(a): one plain IPv4 or IPv6 address - no network ("/"), no name.  Every
# address is checked before it is counted: a ban of "0.0.0.0/0" or of a host
# name the attacker chose must never reach the firewall.
function isip(a,   o, i) {  # awk, not shell: posix-ok
    if (a ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) { split(a, o, "."); for (i = 1; i <= 4; i++) if (o[i] + 0 > 255) return 0; return 1 }
    return (a ~ /^[0-9a-fA-F:]+$/ && a ~ /:.*:/)
}
# emit(service, address, account): print one failure, if the address is real.
function emit(s, a, u) { a = clean(a); if (isip(a)) print s "|" a "|" u }  # awk, not shell: posix-ok
# sshfrom(line): the address sshd itself wrote - the LAST "ADDRESS port N" on
# the line.  The account name comes before it and is chosen by the attacker:
# logging in as "x from 10.0.0.5 port 1" must not get 10.0.0.5 banned.
function sshfrom(s,   a) {  # awk, not shell: posix-ok
    a = ""
    while (match(s, / [^ ]+ port [0-9]+/)) { a = substr(s, RSTART + 1, RLENGTH - 1); sub(/ port [0-9]+$/, "", a); s = substr(s, RSTART + RLENGTH) }
    return a
}
{
    l = $0
    if (l ~ /sshd(-session)?\[[0-9]+\]:/) {
        if (l ~ /Failed password for/) {
            u = after(l, "Failed password for "); sub(/^invalid user /, "", u); u = first(u)
            emit("ssh", sshfrom(l), u); next
        }
        if (l ~ /(Connection closed by|Disconnected from) invalid user/) {
            u = after(l, "invalid user "); split(u, f, " "); emit("ssh", sshfrom(l), f[1]); next
        }
        if (l ~ /maximum authentication attempts exceeded/) { emit("ssh", sshfrom(l), ""); next }
        next
    }
    if (l ~ /FAIL LOGIN: Client "/) { a = after(l, "Client \""); sub(/".*/, "", a); u = ""; if (match(l, /\[[^]]+\] FAIL/)) u = substr(l, RSTART + 1, RLENGTH - 7); emit("ftp", a, u); next }
    if (l ~ /proftpd/ && l ~ /Login failed|no such user/) { if (match(l, /\[[0-9a-fA-F.:]+\]/)) emit("ftp", substr(l, RSTART, RLENGTH), ""); next }
    if (l ~ /pure-ftpd/ && l ~ /Authentication failed for user/) { if (match(l, /\?@[0-9a-fA-F.:]+/)) emit("ftp", substr(l, RSTART + 2, RLENGTH - 2), first(after(l, "user ["))); next }
    if (l ~ /SASL [A-Z0-9-]+ authentication failed/) { if (match(l, /\[[0-9a-fA-F.:]+\]: SASL/)) { a = substr(l, RSTART, RLENGTH - 6); emit("smtp", a, "") } ; next }
    if (l ~ /Relay access denied/) { if (match(l, /from [^[]*\[[0-9a-fA-F.:]+\]/)) { a = substr(l, RSTART, RLENGTH); sub(/.*\[/, "", a); emit("smtp-relay", a, "") } ; next }
    if (l ~ /dovecot/ && (l ~ /auth failed/ || l ~ /authentication failure/) && l ~ /rip=/) {
        a = first(after(l, "rip=")); u = first(after(l, "user=<")); emit("imap-pop", a, u); next }
    if (l ~ /qmgr\[[0-9]+\]: [0-9A-Za-z]+: from=</ && l ~ /nrcpt=/) {
        s = first(after(l, "from=<")); n = first(after(l, "nrcpt=")) + 0; if (s != "") print "mailout|" s "|" n; next }
    if (l ~ /authentication failure;/ && l ~ /rhost=[0-9a-fA-F.:]+/) { a = first(after(l, "rhost=")); u = first(after(l, " user=")); emit("pam", a, u); next }
    # Web access logs: address first, then the request in quotes.
    if (l ~ /^[0-9a-fA-F.:]+ [^ ]+ [^ ]+ \[[^]]+\] "[A-Z]+ /) {
        split(l, q, "\""); split(q[2], rq, " "); split(q[3], st, " ")
        p = tolower(rq[2])
        # Login pages only.  Not "/admin" in general: a signed-in admin posts
        # there all day (WordPress admin-ajax.php every few seconds).
        sub(/[?#].*/, "", p)
        if ((rq[1] == "POST" && (p ~ /(wp-login\.php|xmlrpc\.php|\/administrator\/(index\.php)?$|\/user\/login$|phpmyadmin\/index\.php$|\/(login|signin|sign-in)(\.[a-z]+)?\/?$)/ || tolower(rq[2]) ~ /_task=login/)) || st[1] == "401")
            emit("web", $1, "")
    }
}'

# Service names in the log -> the family asked about.
FAMILY='{ f = $1; if (f == "smtp" || f == "smtp-relay" || f == "imap-pop" || f == "mailout") f = "mail"; if (want == "all" || index(" " want " ", " " f " ")) print }'

OFFCSV=$(cc_csv_new offenders "time,address,verdict,services,failures,web_attempts,accounts_tried")
BANCSV=$(cc_csv_new bans "time,address,services,failures,accounts_tried,until,action")
T_BAN=0; T_NOT=0; T_SPAM=0; T_LINES=0; NCHECK=0; STOP=0

# ---- One check --------------------------------------------------------------------------
one_run() {
    _now=$(now)
    read_new | awk "$PARSE" | awk -F'|' -v want="$SERVICES" "$FAMILY" >"$W/events"
    # Failures and mail volume go into the window file with this check's time.
    awk -F'|' -v t="$_now" '$1 != "mailout" { print t "|" $1 "|" $2 "|1|" $3 } $1 == "mailout" { print t "|mailout|" $2 "|" $3 "|" }' "$W/events" >"$W/hits.run"
    _cut=$((_now - WINDOW * 60))
    { [ -f "$DS/hits" ] && awk -F'|' -v c="$_cut" '$1 >= c' "$DS/hits"; cat "$W/hits.run"; } >"$W/hits.all"
    # Totals per address in the window: failures (non-web), web attempts,
    # services and accounts tried; the verdict; why it is never banned.
    # -v, not trailing name=value operands: those are set only after BEGIN runs.
    awk -F'|' -v nf="$W/never" -v maxf="$MAXF" -v webmax="$WEBMAX" -v mailmax="$MAILMAX" "$AWK_NEVER"'
        BEGIN { loadnever(nf) }
        $2 == "mailout" { mo[$3] += $4; next }
        { a = $3; if (a == "") next
          if ($2 == "web") web[a] += $4; else fail[a] += $4
          if (!((a, $2) in sv)) { sv[a, $2] = 1; svc[a] = svc[a] (svc[a] ? "+" : "") $2 }
          if ($5 != "" && !((a, $5) in ac)) { ac[a, $5] = 1; nac[a]++; if (nac[a] <= 5) acc[a] = acc[a] (acc[a] ? " " : "") $5 } }
        END {
            for (a in svc) {
                f = fail[a] + 0; w = web[a] + 0
                over = (f >= maxf || w >= webmax)
                tag = never(a) ? why[NV] : (over ? "ban" : "watch")
                print tag "|" a "|" svc[a] "|" f "|" w "|" acc[a] (nac[a] > 5 ? " +" (nac[a] - 5) " more" : "")
            }
            for (s in mo) if (mo[s] >= mailmax) print "spam|" s "|mail|" mo[s] "|0|"
        }' "$W/hits.all" | sort -t'|' -k4,4nr -k5,5nr >"$W/totals"
    # Already banned now (no double bans); in a dry run, already "would ban".
    fw_list >"$W/banned" 2>/dev/null
    cat "$W/wouldban" >>"$W/banned"
    _nb=0; _ts=$(date -u +%Y-%m-%dT%H:%M:%SZ); _tl=$(date +%H:%M:%S)
    : >"$W/shown"
    while IFS='|' read -r _tag _a _svc _f _w _acc; do
        cc_csv_row "$OFFCSV" "$_ts" "$_a" "$_tag" "$_svc" "$_f" "$_w" "$_acc"
        [ "$_tag" = ban ] || continue
        if grep -qxF "$_a" "$W/banned"; then printf 'had|%s|%s|%s|%s|%s\n' "$_a" "$_svc" "$_f" "$_w" "$_acc" >>"$W/shown"; continue; fi
        fw_setup || { cc_err "could not set up the ban table"; break; }
        cc_csv_row "$BANCSV" "$_ts" "$_a" "$_svc" "$((_f + _w))" "$_acc" "+${BANTIME}min" "$([ "$CC_APPLY" = 1 ] && echo banned || echo 'would ban')"
        if fw_ban "$_a" "$((BANTIME * 60))"; then
            _nb=$((_nb + 1))
            printf 'new|%s|%s|%s|%s|%s\n' "$_a" "$_svc" "$_f" "$_w" "$_acc" >>"$W/shown"
            if [ "$CC_APPLY" = 1 ]; then
                printf '%s,%s,%s,%s,"%s",+%smin,banned\n' "$_ts" "$_a" "$_svc" "$((_f + _w))" "$_acc" "$BANTIME" >>"$BANS"
                [ "$BACKEND" = iptables ] && printf '%s|%s\n' "$((_now + BANTIME * 60))" "$_a" >>"$STATE/iptables-expiry"
            else
                printf '%s\n' "$_a" >>"$W/wouldban"
            fi
        else
            cc_show "$C_RED" "  [!] the firewall refused to ban $_a - see $CC_LOG"
        fi
    done <"$W/totals"
    # Plain iptables bans do not expire by themselves: remove the due ones.
    if [ "$BACKEND" = iptables ] && [ -f "$STATE/iptables-expiry" ] && [ "$CC_APPLY" = 1 ]; then
        awk -F'|' -v n="$_now" '$1 <= n { print $2 }' "$STATE/iptables-expiry" >"$W/due"
        while IFS= read -r _a; do fw_unban "$_a" && cc_show "$C_GRY" "  [-] ban ended: $_a"; done <"$W/due"
        awk -F'|' -v n="$_now" '$1 > n' "$STATE/iptables-expiry" >"$W/exp" && mv "$W/exp" "$STATE/iptables-expiry"
    fi
    # Report: one heading line, then the addresses, worst first.
    _ne=$(grep -c . "$W/events")
    _nn=$(awk -F'|' -v mx="$MAXF" -v wm="$WEBMAX" '$1 != "ban" && $1 != "watch" && $1 != "spam" && ($4 >= mx || $5 >= wm)' "$W/totals" | grep -c .)
    _ns=$(grep -c '^spam|' "$W/totals"); _nw=$(grep -c '^watch|' "$W/totals")
    T_BAN=$((T_BAN + _nb)); T_NOT=$((T_NOT + _nn)); T_SPAM=$((T_SPAM + _ns)); T_LINES=$((T_LINES + _ne))
    _verb=$([ "$CC_APPLY" = 1 ] && echo banned || echo "would ban")
    _line="$_ts  check $NCHECK: $_ne failed login(s) read; $_verb $_nb; not banned (protected) $_nn; spam warnings $_ns"
    printf '%s\n' "$_line" >>"$STATE/events.log"
    if [ "$_nb" -gt 0 ]; then _hc=$C_RED; elif [ $((_nn + _ns)) -gt 0 ]; then _hc=$C_YEL; elif [ "$_ne" -gt 0 ]; then _hc=$C_GRY; else _hc=$C_GRN; fi
    if [ "$_ne" = 0 ] && [ ! -s "$W/totals" ]; then
        cc_show "$_hc" "$_tl  check $NCHECK: [ok] no new failed logins"
    else
        cc_show "$_hc" "$_tl  check $NCHECK: $_ne new failed login(s) - $_verb $_nb, $_nw under watch"
    fi
    # row LABEL ADDR SERVICES FAILS WEB -> one aligned line (no colour)
    row() { printf '%-13s %-17s %-18s %4d fails %4d web' "$1" "$2" "$3" "$4" "$5"; }
    while IFS='|' read -r _k _a _svc _f _w _acc; do
        if [ "$_k" = new ]; then
            if [ "$CC_APPLY" = 1 ]; then cc_show "$C_RED" "  [!] $(row BANNED "$_a" "$_svc" "$_f" "$_w")  for $BANTIME min"
            else cc_show "$C_YEL" "  [*] $(row 'WOULD BAN' "$_a" "$_svc" "$_f" "$_w")"; fi
            [ -n "$_acc" ] && cc_show "$C_GRY" "                    accounts tried: $_acc"
        else
            cc_show "$C_GRY" "  [-] $(row "$([ "$CC_APPLY" = 1 ] && echo 'still banned' || echo 'would ban')" "$_a" "$_svc" "$_f" "$_w")  (shown before)"
        fi
    done <"$W/shown"
    awk -F'|' -v mx="$MAXF" -v wm="$WEBMAX" '$1 != "ban" && $1 != "watch" && $1 != "spam" && ($4 >= mx || $5 >= wm)' "$W/totals" |
    while IFS='|' read -r _tag _a _svc _f _w _acc; do
        case "$_tag" in
            gateway) _why="the default gateway - with NAT, every outside client looks like it. Ban by hand only if sure" ;;
            team) _why="on your never-ban list - if this is not the scoring engine or your team, look at it" ;;
            protected) _why="a protected host - probably the scoring engine failing after a password change" ;;
            own) _why="this box's own address" ;;
            *) _why="never banned ($_tag)" ;;
        esac
        cc_show "$C_YEL" "  [*] $(row 'NOT BANNED' "$_a" "$_svc" "$_f" "$_w")"
        cc_show "$C_YEL" "                    $_why"
    done
    awk -F'|' '$1 == "spam"' "$W/totals" | while IFS='|' read -r _tag _a _svc _f _w _acc; do
        cc_show "$C_YEL" "  [*] SPAM?         $_a sent to $_f recipients in $WINDOW min - a compromised mailbox? (not banned; change its password)"
    done
    awk -F'|' '$1 == "watch"' "$W/totals" | head -n 5 | while IFS='|' read -r _tag _a _svc _f _w _acc; do
        cc_show "$C_GRY" "  [-] $(row watching "$_a" "$_svc" "$_f" "$_w")  (ban at $MAXF / $WEBMAX web)"
    done
    _more=$(($(grep -c '^watch|' "$W/totals") - 5)); [ "$_more" -gt 0 ] && cc_show "$C_GRY" "      ... and $_more more under watch (offenders.txt)"
    # Save the window and how far each log was read.
    mv "$W/hits.all" "$DS/hits"
    awk -F'\t' -v nf="$W/offsets.new" 'FILENAME == nf { n[$1] = $2; next } !($1 in n) { print } END { for (k in n) print k "\t" n[k] }' "$W/offsets.new" "$DS/offsets" >"$W/off" 2>/dev/null
    [ -s "$W/offsets.new" ] && mv "$W/off" "$DS/offsets"
    return 0
}

# ---- 3/4 Checks ---------------------------------------------------------------------
header "3/4  checks$([ "$LOOP" -gt 0 ] && echo " every $LOOP seconds - Ctrl-C stops")"
trap 'STOP=1' INT TERM
# shellcheck disable=SC2034  # read by cc_run: no WOULD/DO lines, the report says it
_q=$CC_QUIET; CC_QUIET=1
while [ "$STOP" = 0 ]; do
    NCHECK=$((NCHECK + 1))
    one_run
    [ "$STOP" = 1 ] && break
    [ "$LOOP" -gt 0 ] || break
    [ "$COUNT" -gt 0 ] && [ "$NCHECK" -ge "$COUNT" ] && break
    sleep "$LOOP"
done
trap 'cc_log ERROR "interrupted"; exit 130' INT TERM
CC_QUIET=$_q

# ---- 4/4 Summary ---------------------------------------------------------------------
cc_csv_pretty "$BANCSV" "$CC_RUN_DIR/bans.txt" 110
cc_csv_pretty "$OFFCSV" "$CC_RUN_DIR/offenders.txt" 110
fw_list >"$W/active" 2>/dev/null
{
    printf '==========[ 4/4  summary ]==========\n'
    printf 'Host %s | %s check(s) | %s new failed login line(s) read\n' "$CC_HOST" "$NCHECK" "$T_LINES"
    if [ "$CC_APPLY" = 1 ]; then printf 'Banned this run: %s\n' "$T_BAN"; else printf 'Would ban: %s (dry run - nothing was blocked)\n' "$T_BAN"; fi
    [ "$T_NOT" -gt 0 ] && printf 'Over the limit but never banned (team/protected/gateway): %s - look at them\n' "$T_NOT"
    [ "$T_SPAM" -gt 0 ] && printf 'Spam warnings: %s\n' "$T_SPAM"
    printf 'Banned right now: %s\n' "$(grep -c . "$W/active")"
    if [ "$T_BAN" -gt 0 ]; then
        printf '\n'
        awk 'NR > 1' "$BANCSV" | tr -d '"' | cut -d, -f2,3,4 | awk -F, '{ printf "  %-17s %-18s %s failures\n", $1, $2, $3 }'
    fi
    printf '\nFiles:\n'
    printf '  %s/bans.txt        bans this run (csv/bans.csv)\n' "$CC_RUN_DIR"
    printf '  %s/offenders.txt   every address with failures, per check\n' "$CC_RUN_DIR"
    printf '  %s   every ban ever\n' "$BANS"
    printf '\n'
    if [ "$CC_APPLY" = 1 ]; then
        printf 'Lift a ban: --apply --unban ADDR   Lift all: --apply --unban-all   List: --list\n'
    else
        printf 'Next: run with --protected FILE --apply (and --loop 60 to keep watching) to ban for real.\n'
    fi
} >"$CC_RUN_DIR/summary.txt"
cc_show "" ""
while IFS= read -r _line; do
    case "$_line" in
        ==*) cc_show "$C_CYN" "$_line" ;;
        'Banned this run: 0'|'Would ban: 0'*) cc_show "$C_GRN" "$_line" ;;
        'Banned this run:'*) cc_show "$C_RED" "$_line" ;;
        'Would ban:'*|'Over the limit'*|'Spam'*) cc_show "$C_YEL" "$_line" ;;
        *) cc_show "" "$_line" ;;
    esac
done <"$CC_RUN_DIR/summary.txt"
rm -rf "$W"
cc_finish
