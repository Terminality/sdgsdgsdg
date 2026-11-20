#!/bin/sh
# =============================================================================
# ID:       LX-20
# NAME:     Linux password rotation
# ROLE:     Linux  (wave 2, first 15 minutes)
# KIND:     changes - dry run unless --apply
# VERSION:  2.0.0
#
# PURPOSE
#   Default and leaked passwords are the red team's first way in.  This:
#     1. gives every account that has a usable password a new random one
#        (root included), skipping accounts on the protected list - the ones
#        the scoring engine logs in with
#     2. with --keep FILE, locks every human account (UID >= UID_MIN, and any
#        extra UID 0 account) that is NOT on the team's list: password locked
#        AND account expired, which also stops SSH key logins
#     3. fixes password hashes hidden in /etc/passwd (where they bypass
#        /etc/shadow) by moving them into /etc/shadow with pwconv
#     4. writes the new passwords to ONE file, mode 600, for the captain -
#        never to the screen (unless --print) or the log
#
# HOW A RUN GOES  (asks like sqlmap; Enter takes the default)
#   1. A revert timer starts (5 minutes, --timer): unless you keep the
#      changes at the end, /etc/shadow and /etc/passwd go back to how they
#      were - old passwords, nothing locked - even if your session died.
#   2. Every account in a table: UID, shell, password state, admin or not,
#      last login, and what it will do by default.  Hidden accounts are
#      flagged: a second UID 0, an empty password, a hash in /etc/passwd, a
#      system account that can log in, an account in only one of passwd and
#      shadow, domain/LDAP accounts.
#   3. "Go through each account?"  Then, per account:
#        [r] random password   [s] set one (typed twice, not shown)
#        [d] disable (locked AND expired: stops SSH keys too)
#        [k] keep              [a] the default for all the rest
#      Protected (scoring) accounts and the account you are logged in as
#      need an extra yes.
#   4. End the sessions of the accounts you disable?  The plan, "Apply?",
#      the changes, then "Keep these changes?" - log in from a NEW session
#      with the new password first.
#   Flags answer the questions in advance; --batch takes every default.
#
# USAGE
#   sudo sh LX-20-password-rotation.sh                         asks, then applies if you say so
#   sudo sh LX-20-password-rotation.sh --apply --batch         defaults, no questions
#   sudo sh LX-20-password-rotation.sh --apply --keep team.txt lock accounts not on the list
#
# OPTIONS
#   --keep FILE        the team's account list, one name per line (# comments).
#                      Human accounts not on it are locked and expired
#   --users a,b        rotate only these accounts (repeatable)
#   --exclude a,b      never touch these accounts (repeatable).  A name in
#                      --users or --exclude that is not an account on this
#                      box STOPS the script before anything changes: a typo
#                      there would rotate the account you meant to keep
#   --ignore-missing   only warn about such names (for one list used on
#                      many boxes)
#   --passwords FILE   use these passwords instead of random ones: CSV lines
#                      "user,password" (for a password sheet made in advance).
#                      Spaces around the name and the password are dropped.
#                      Names not on this box are listed in the summary; an
#                      account that is locked or has no password is NOT
#                      given one (that would unlock it) and is listed too
#   --length N         length of random passwords (default 16)
#   --no-root          do not rotate root's password
#   --include-me       also rotate the account that ran sudo (skipped by
#                      default so you can still use sudo with your password)
#   --kick             also end every running process of a locked account
#   --print            show the new passwords on screen at the end
#   --timer SECONDS    revert timer length (default 300)
#   --no-timer         no revert timer (you accept the risk)
#   --no-color         no colours
#   --batch            never ask: take every default (common option)
#   --root DIR         treat DIR as / when reading passwd, shadow and
#                      login.defs (for the tests; changes still go through
#                      the tools, see BT_CHPASSWD below)
#   --help             this text plus the common options
#
# OUTPUTS  (under --out, one numbered folder per run: passwords-1, -2, ...)
#   output.txt      everything shown on screen (never a password)
#   summary.txt     what was rotated, locked and skipped (no passwords)
#   accounts.txt    every account: uid, shell, password state, what was done
#   csv/accounts.csv  the same as CSV
#   revert.sh       undoes this run (sh revert.sh --force)
#   passwords.csv   host,user,password,time - ONLY with --apply, mode 600.
#                   Give it to the captain, then delete it from this box
#
# WHAT IT CHANGES  (only with --apply)
#   Passwords (chpasswd, or pw on FreeBSD), account lock and expiry (usermod,
#   or pw lock), /etc/passwd and /etc/shadow through pwconv.  /etc/shadow and
#   /etc/passwd are backed up first; the undo log restores them (which also
#   restores the OLD passwords - the backup is how undo works without ever
#   writing a hash into a log).
#
# DEPENDS ON
#   chpasswd and usermod (shadow-utils or busybox) on Linux - without
#   usermod (Alpine) accounts are locked with "passwd -l" only; pw on FreeBSD
#   (reads /etc/master.passwd; NOT yet tried on a real FreeBSD box);
#   pwconv for the hidden-hash fix; /dev/urandom for passwords.
#   BT_CHPASSWD, BT_USERMOD and BT_PWCONV may name stand-in programs
#   (the tests use them so they never touch real accounts).
#
# TESTED ON
#   Ubuntu 24.04 under dash, bash, busybox sh, ksh93, mksh and yash, with
#   stand-in tools on a fake root, plus a live run on throwaway accounts.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - Accounts the scoring engine uses MUST be on the protected list
#     (type account), or scoring breaks.  If a scored password must change,
#     change it through the competition's password-change process.
#   - Samba keeps its own passwords; they are not changed here.  The summary
#     lists Samba accounts when pdbedit is installed.
#   - LDAP / Active Directory / NIS accounts are not in /etc/shadow and are
#     not touched.
#   - Locking does not end sessions already open; use --kick for that.
#
# DEBUGGING
#   --debug shows how each account was classified and why.
#   Passwords are never in the log, even with --debug.
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

usage() {
    cat <<'USAGE'
LX-20 Linux password rotation - list every account, then rotate, set or disable
  sudo sh LX-20-password-rotation.sh [--apply] [options]     (asks; --batch for none)

  --keep FILE        team account list; human accounts not on it are disabled
  --users a,b        act only on these accounts (repeatable)
  --exclude a,b      never touch these accounts (repeatable)
  --ignore-missing   warn, do not stop, when a name in --users/--exclude is not an account here
  --passwords FILE   "user,password" lines to set instead of random passwords
  --length N         random password length (default 16)
  --no-root          leave root's password alone
  --include-me       also rotate the account that ran sudo
  --kick             end running processes of disabled accounts
  --print            show the new passwords on screen at the end
  --timer SECONDS    revert timer length (default 300)
  --no-timer         no revert timer
  --no-color         no colours
  --root DIR         read passwd/shadow under DIR (tests)
  --help             show this text

USAGE
    cc_usage_common
}

KEEP=""; USERS=""; EXCLUDE=""; IGNMISS=0; PWFILE=""; LEN=16; NOROOT=0; INCME=0; KICK=0; PRINT=0; R=""
TIMER=300; NOTIMER=0; F_KICK=0
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --keep)       [ $# -ge 2 ] || cc_die 2 "--keep needs a file"; [ -r "$2" ] || cc_die 2 "--keep: cannot read $2"; KEEP=$2; shift 2 ;;
        --users)      [ $# -ge 2 ] || cc_die 2 "--users needs a list"; USERS="${USERS:+$USERS,}$2"; shift 2 ;;
        --exclude)    [ $# -ge 2 ] || cc_die 2 "--exclude needs a list"; EXCLUDE="${EXCLUDE:+$EXCLUDE,}$2"; shift 2 ;;
        --ignore-missing) IGNMISS=1; shift ;;
        --passwords)  [ $# -ge 2 ] || cc_die 2 "--passwords needs a file"; [ -r "$2" ] || cc_die 2 "--passwords: cannot read $2"; PWFILE=$2; shift 2 ;;
        --length)     [ $# -ge 2 ] || cc_die 2 "--length needs a number"; LEN=$2; shift 2 ;;
        --no-root)    NOROOT=1; shift ;;
        --include-me) INCME=1; shift ;;
        --kick)       KICK=1; F_KICK=1; shift ;;
        --print)      PRINT=1; shift ;;
        --timer)      [ $# -ge 2 ] || cc_die 2 "--timer needs a number of seconds"; TIMER=$2; shift 2 ;;
        --no-timer)   NOTIMER=1; shift ;;
        --no-color|--no-colour)
                      # shellcheck disable=SC2034  # read by cc_color_init in the library
                      CC_NOCOLOR=1; shift ;;
        --root)       [ $# -ge 2 ] || cc_die 2 "--root needs a folder"; [ -d "$2" ] || cc_die 2 "--root: not a folder: $2"
                      R=$(cd "$2" && pwd); [ "$R" = / ] && R=""; shift 2 ;;
        --help|-h)    usage; exit 0 ;;
        *)            cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
case "$LEN" in ''|*[!0-9]*) cc_die 2 "--length needs a whole number" ;; esac
[ "$LEN" -ge 12 ] || cc_die 2 "--length must be at least 12"
case "$TIMER" in ''|*[!0-9]*) cc_die 2 "--timer needs a whole number of seconds" ;; esac
[ "$TIMER" -ge 2 ] || cc_die 2 "--timer must be at least 2 seconds"

cc_color_init
APPLY_FLAG=$CC_APPLY
cc_init "LX-20" "Linux password rotation" changes
cc_detect_os
[ -z "$R" ] && cc_require_root
cc_use_numbered_dir passwords
CC_CSV_DIR="$CC_RUN_DIR/csv"
(umask 077; mkdir -p "$CC_CSV_DIR") || cc_die 3 "cannot create $CC_CSV_DIR"
W="$CC_RUN_DIR/.work"
(umask 077; mkdir -p "$W") || cc_die 3 "cannot create $W"
OUTF="$CC_RUN_DIR/output.txt"
grep -v '\[NOTE\]\|\[DEBUG\]' "$CC_LOG" >"$OUTF" 2>/dev/null || : >"$OUTF"
# shellcheck disable=SC2034  # read by cc_show and cc_log in the library
CC_TEE=$OUTF
CSV=$(cc_csv_new accounts "user,uid,shell,password_state,action,note")
PASSWD="$R/etc/passwd"; SHADOW="$R/etc/shadow"
# FreeBSD keeps the hashes in /etc/master.passwd (same place in the line:
# name:hash:...), and pw rebuilds the password database itself.
[ "$CC_OS_KERNEL" = freebsd ] && [ ! -e "$SHADOW" ] && SHADOW="$R/etc/master.passwd"
[ -r "$PASSWD" ] || cc_die 3 "cannot read $PASSWD"
[ -r "$SHADOW" ] || cc_die 3 "cannot read $SHADOW (run as root)"

cc_show "$C_CYN" "LX-20 Linux password rotation | host $CC_HOST | results in $CC_RUN_DIR"
cc_show "" "Legend: ${C_RED}red = hidden or dangerous account${C_OFF}  ${C_GRN}[+] done${C_OFF}  ${C_YEL}[~] will do${C_OFF}  ${C_GRY}[-] kept${C_OFF}"
header() { cc_show "" ""; cc_show "$C_CYN" "==========[ $1 ]=========="; }

# Can this run change anything?  --apply, or someone at the keyboard to say yes.
CANAPPLY=0
if [ "$CC_APPLY" = 1 ] || _cc_can_ask; then CANAPPLY=1; fi
if [ "$CANAPPLY" = 0 ]; then
    cc_show "$C_GRY" "Dry run only (--batch or no terminal, without --apply): nothing will be changed."
elif [ "$NOTIMER" = 1 ]; then
    cc_show "$C_YEL" "[*] No revert timer (--no-timer): if a new password locks you out, nothing puts it back."
else
    cc_timer_start "$TIMER"
    cc_show "$C_YEL" "[*] Revert timer started: unless you keep the changes at the end, every password and lock goes back in $((TIMER / 60)):$(printf '%02d' $((TIMER % 60)))."
fi

# ---- Tools ----------------------------------------------------------------------
# Full paths (cc_which), so busybox sh cannot swap in its built-in versions.
if [ "$CC_OS_KERNEL" = freebsd ] && [ -z "${BT_CHPASSWD:-}" ]; then
    PW=$(cc_which pw) || cc_die 3 "pw not found"
    TOOLS=pw
else
    CHPASSWD=${BT_CHPASSWD:-$(cc_which chpasswd)} || CHPASSWD=""
    USERMOD=${BT_USERMOD:-$(cc_which usermod)} || USERMOD=""
    PWCONV=${BT_PWCONV:-$(cc_which pwconv)} || PWCONV=""
    PASSWD_BIN=$(cc_which passwd) || PASSWD_BIN=""
    [ -n "$CHPASSWD" ] || cc_die 3 "chpasswd not found (install the shadow or passwd package)"
    TOOLS=shadow
fi
cc_debug "tools: $TOOLS chpasswd=${CHPASSWD:-} usermod=${USERMOD:-} pwconv=${PWCONV:-}"

# set_password USER PASSWORD - the password travels on stdin only, never on a
# command line (visible in ps) or in the log.  Called through cc_run_quiet.
set_password() {
    if [ "$TOOLS" = pw ]; then printf '%s\n' "$2" | "$PW" usermod "$1" -h 0
    else printf '%s:%s\n' "$1" "$2" | "$CHPASSWD"; fi
}
# lock_account USER - password locked and account expired (expiry also stops
# SSH key logins, which a locked password alone does not).
lock_account() {
    if [ "$TOOLS" = pw ]; then "$PW" lock "$1"
    elif [ -n "$USERMOD" ]; then "$USERMOD" -L -e 1 "$1"
    # No usermod (Alpine without the shadow package): lock the password only.
    elif [ -n "$PASSWD_BIN" ]; then "$PASSWD_BIN" -l "$1"
    else return 127; fi
}
unlock_cmd() {
    if [ "$TOOLS" = pw ]; then printf '%s unlock %s' "$PW" "$1"
    elif [ -n "$USERMOD" ]; then printf "%s -U %s; %s -e '' %s" "$USERMOD" "$1" "$USERMOD" "$1"
    else printf '%s -u %s' "$PASSWD_BIN" "$1"; fi
}

# ---- Lists ----------------------------------------------------------------------
# inlist NAME "a,b,c" -> true when NAME is in the comma list.
inlist() { case ",$2," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }
: >"$W/keep"
if [ -n "$KEEP" ]; then
    sed 's/#.*//; s/[[:space:]]//g' "$KEEP" | grep . >"$W/keep"
    [ -s "$W/keep" ] || cc_die 2 "--keep file has no names: $KEEP"
fi
onkeep() { grep -qx "$1" "$W/keep"; }
# Passwords given in advance: "user,password" lines.  Checked for characters
# that would break chpasswd's "user:password" input.
: >"$W/given"
if [ -n "$PWFILE" ]; then
    awk -F',' '/^[ \t]*#/ || NF < 2 { next } { u = $1; p = substr($0, length($1) + 2); gsub(/\r/, "", p); gsub(/^[ \t]+|[ \t]+$/, "", u); gsub(/^[ \t]+|[ \t]+$/, "", p); print u "\t" p }' "$PWFILE" >"$W/given"
    if awk -F'\t' '$2 ~ /:/ || length($2) < 8 { bad = 1 } END { exit !bad }' "$W/given"; then
        cc_die 2 "--passwords: every password must be 8+ characters and contain no ':'"
    fi
fi
given_pw() { awk -F'\t' -v u="$1" '$1 == u { print $2; exit }' "$W/given"; }

UID_MIN=$(awk '$1 == "UID_MIN" { print $2 }' "$R/etc/login.defs" 2>/dev/null)
case "$UID_MIN" in ''|*[!0-9]*) UID_MIN=1000 ;; esac
ME=${SUDO_USER:-}
[ "$ME" = root ] && ME=""

# ---- Classify every account -------------------------------------------------------
# One line per account: user|uid|shell|state|passwd_field
#   state: set (usable hash) | empty (no password at all) | locked | none
# A hash in /etc/passwd itself (field 2 not x) is used INSTEAD of shadow by
# most systems - a known backdoor trick - so that counts too.
awk -F: -v shf="$SHADOW" 'FILENAME == shf { sh[$1] = $2; next }
    { u = $1; pf = $2; s = (u in sh) ? sh[u] : "(missing)"
      if (pf != "x" && pf != "*" && pf !~ /^!/) st = (pf == "" ? "empty" : "set")
      else if (s == "") st = "empty"
      else if (s ~ /^[!*]/ || s == "(missing)") st = (s ~ /^!/ ? "locked" : "none")
      else st = "set"
      print u "|" $3 "|" $7 "|" st "|" pf }' "$SHADOW" "$PASSWD" >"$W/accounts"

# ---- Names given by hand must exist ------------------------------------------
# A misspelled --exclude name would otherwise be ignored without a word and
# the account it was meant to protect would get a new password.
: >"$W/notes"
_missing=""
for _nm in $(printf '%s,%s' "$USERS" "$EXCLUDE" | tr ',' ' '); do
    awk -F'|' -v u="$_nm" '$1 == u { f = 1 } END { exit !f }' "$W/accounts" || _missing="$_missing $_nm"
done
if [ -n "$_missing" ]; then
    if [ "$IGNMISS" = 1 ]; then
        cc_warn "not accounts on this box (ignored because of --ignore-missing):$_missing"
        printf 'NOTE|named in --users/--exclude but not an account here:%s\n' "$_missing" >>"$W/notes"
    else
        rm -rf "$W"
        cc_timer_cancel
        cc_die 2 "no such account on this box:$_missing (named in --users or --exclude). Nothing was changed. Fix the spelling, or add --ignore-missing"
    fi
fi
# The same check for the password sheet, as notes: one sheet often covers
# many boxes, so a name missing here is normal - but worth seeing.
awk -F'\t' -v af="$W/accounts" 'BEGIN { while ((getline l < af) > 0) { split(l, a, "|"); st[a[1]] = a[4] } }
    !($1 in st) { print "NOTE|" $1 " is in --passwords but is not an account here"; next }
    st[$1] != "set" && st[$1] != "empty" { print "NOTE|" $1 " is in --passwords but has no usable password (" st[$1] "): NOT set, which would unlock it. Unlock it first if you want it" }' "$W/given" >>"$W/notes"

# login_shell SHELL -> true if SHELL lets someone log in.
login_shell() {
    case "$(basename "${1:-/bin/sh}")" in
        nologin|false|sync|shutdown|halt|git-shell) return 1 ;;
        *) return 0 ;;
    esac
}

# ---- Defaults: what happens to each account unless you say otherwise ----------
# Action letters: r random, s set (from the sheet or typed), d disable, k keep.
# One line per account in $W/plan: user|uid|shell|state|action|why|flags
#   flags: words for the table - uid0 empty inpasswd syslogin noshadow admin
_admins=$(awk -F: '$1 ~ /^(sudo|wheel|admin|root)$/ { print $4 }' "$R/etc/group" 2>/dev/null | tr ',' ' ')
: >"$W/plan"
while IFS='|' read -r _u _uid _sh _st _pf; do
    [ -n "$_u" ] || continue
    _human=0
    { [ "$_uid" -ge "$UID_MIN" ] 2>/dev/null && [ "$_uid" -lt 60000 ]; } && _human=1
    [ "$_uid" = 0 ] && [ "$_u" != root ] && _human=1
    _fl=""
    [ "$_uid" = 0 ] && [ "$_u" != root ] && _fl="$_fl uid0"
    [ "$_st" = empty ] && _fl="$_fl empty"
    case "$_pf" in x|'*'|!*) ;; *) _fl="$_fl inpasswd" ;; esac
    [ "$_human" = 0 ] && [ "$_u" != root ] && [ "$_st" = set ] && login_shell "$_sh" && _fl="$_fl syslogin"
    grep -q "^$_u:" "$SHADOW" 2>/dev/null || _fl="$_fl noshadow"
    { [ "$_uid" = 0 ] || case " $_admins " in *" $_u "*) true ;; *) false ;; esac; } && _fl="$_fl admin"
    [ "$_st" = empty ] && printf 'HIGH|%s has NO password: anyone can log in as it\n' "$_u" >>"$W/notes"
    [ "$_uid" = 0 ] && [ "$_u" != root ] && printf 'HIGH|%s has UID 0: it IS root under another name\n' "$_u" >>"$W/notes"

    _a=k; _why=""
    if inlist "$_u" "$EXCLUDE"; then _why="--exclude"
    elif [ -n "$USERS" ] && ! inlist "$_u" "$USERS"; then _why="not in --users"
    elif [ "$_uid" = 0 ] && [ "$_u" != root ]; then _a=d; _why="extra UID 0 account (root under another name)"
    elif [ -n "$KEEP" ] && [ "$_human" = 1 ] && [ "$_u" != root ] && ! onkeep "$_u"; then _a=d; _why="not on the team list"
    elif [ "$_st" != set ] && [ "$_st" != empty ]; then _why="no usable password ($_st)"
    elif [ "$_u" = root ] && [ "$NOROOT" = 1 ]; then _why="--no-root"
    elif [ -n "$ME" ] && [ "$_u" = "$ME" ] && [ "$INCME" = 0 ]; then _why="you are logged in as it (--include-me)"
    elif [ -n "$(given_pw "$_u")" ]; then _a=s; _why="from --passwords"
    else _a=r; _why="random"
    fi
    if { [ "$_a" = r ] || [ "$_a" = s ]; } && ! login_shell "$_sh"; then
        _why="$_why; service account (no login shell) - check no service logs in with the old password"
    fi
    printf '%s|%s|%s|%s|%s|%s|%s\n' "$_u" "$_uid" "$_sh" "$_st" "$_a" "$_why" "$_fl" >>"$W/plan"
done <"$W/accounts"
# Domain / LDAP / NIS accounts the system knows but /etc/passwd does not.
if [ -z "$R" ] && cc_have getent; then
    getent passwd 2>/dev/null | cut -d: -f1 | while IFS= read -r _g; do
        grep -q "^$_g:" "$PASSWD" || printf '%s\n' "$_g"
    done >"$W/remote"
    [ -s "$W/remote" ] && printf 'NOTE|accounts from LDAP, the domain or NIS (not changed here; change them where they live): %s\n' "$(tr '\n' ' ' <"$W/remote")" >>"$W/notes"
fi
# Accounts in shadow but not passwd: a leftover or a planted entry.
awk -F: 'NR == FNR { p[$1] = 1; next } !($1 in p) { print $1 }' "$PASSWD" "$SHADOW" >"$W/onlyshadow"
[ -s "$W/onlyshadow" ] && printf 'HIGH|in /etc/shadow but not /etc/passwd: %s\n' "$(tr '\n' ' ' <"$W/onlyshadow")" >>"$W/notes"

# lastlog_of USER -> last login, short ("never" or a date), when lastlog works.
lastlog_of() {
    [ -z "$R" ] && cc_have lastlog || return 0
    lastlog -u "$1" 2>/dev/null | awk 'NR == 2 { if ($0 ~ /Never logged in/) print "never"; else print $(NF-5) " " $(NF-4) " " $(NF-3) }'
}
act_word() { case "$1" in r) echo random ;; s) echo set ;; d) echo disable ;; *) echo keep ;; esac; }

# show_table -> the account table with the current plan.
show_table() {
    cc_show "$C_CYN" "$(printf '  %-16s %6s  %-18s %-7s %-12s %-8s %s' USER UID SHELL PASSWORD "LAST LOGIN" ACTION "NOTES")"
    while IFS='|' read -r _u _uid _sh _st _a _why _fl; do
        _col=""; _note=$_why
        case "$_fl" in *uid0*|*empty*|*inpasswd*|*noshadow*|*syslogin*) _col=$C_RED ;; esac
        case "$_fl" in *uid0*) _note="UID 0 = ROOT; $_note" ;; esac
        case "$_fl" in *inpasswd*) _note="hash in /etc/passwd; $_note" ;; esac
        case "$_fl" in *syslogin*) _note="system account that can log in; $_note" ;; esac
        case "$_fl" in *noshadow*) _note="not in /etc/shadow; $_note" ;; esac
        case "$_fl" in *admin*) _note="admin; $_note" ;; esac
        if [ -z "$_col" ]; then case "$_a" in k) _col=$C_GRY ;; *) _col="" ;; esac; fi
        cc_show "$_col" "$(printf '  %-16s %6s  %-18s %-7s %-12s %-8s %s' "$_u" "$_uid" "$(basename "$_sh")" "$_st" "$(lastlog_of "$_u")" "$(act_word "$_a")" "$_note")"
    done <"$W/plan"
}

header "ACCOUNTS (every account in /etc/passwd)"
# Quiet ones in one line: no password and no login shell, nothing will change.
awk -F'|' '$5 == "k" && $4 != "set" && $4 != "empty" && $7 == "" { print }' "$W/plan" >"$W/quiet"
awk -F'|' '!($5 == "k" && $4 != "set" && $4 != "empty" && $7 == "") { print }' "$W/plan" >"$W/loud"
cp "$W/plan" "$W/plan.all"; cp "$W/loud" "$W/plan"
show_table
cp "$W/plan.all" "$W/plan"
_nq=$(grep -c . "$W/quiet")
[ -s "$W/quiet" ] && cc_show "$C_GRY" "  [-] $_nq system accounts with no password are kept: $(cut -d'|' -f1 "$W/quiet" | head -n 15 | tr '\n' ' ')$([ "$_nq" -gt 15 ] && echo "+$((_nq - 15)) more")"
if [ -s "$W/notes" ]; then
    while IFS='|' read -r _lv _tx; do
        case "$_lv" in HIGH) cc_show "$C_RED" "  [!] $_tx" ;; *) cc_show "$C_YEL" "  [*] $_tx" ;; esac
    done <"$W/notes"
fi

# ---- Questions ---------------------------------------------------------------------
# read_secret VAR PROMPT -> read a password from the terminal without echo.
#   Never logged, never in output.txt.
read_secret() {
    printf '%s' "$2" >/dev/tty
    stty -echo </dev/tty 2>/dev/null
    _cc_read "$1"; _rs_rc=$?
    stty echo </dev/tty 2>/dev/null
    printf '\n' >/dev/tty
    return "$_rs_rc"
}
# ask_password USER -> a typed password, entered twice, in TYPED (or empty).
ask_password() {
    TYPED=""
    while :; do
        read_secret _p1 "    New password for $1 (not shown): " || return 1
        read_secret _p2 "    Same password again: " || return 1
        if [ "$_p1" != "$_p2" ]; then printf '    They do not match. Again.\n' >/dev/tty; continue; fi
        case "$_p1" in *:*) printf '    No ":" please (it breaks chpasswd). Again.\n' >/dev/tty; continue ;; esac
        if [ "${#_p1}" -lt 8 ]; then printf '    At least 8 characters. Again.\n' >/dev/tty; continue; fi
        TYPED=$_p1; _p1=""; _p2=""
        return 0
    done
}
# set_plan USER ACTION WHY -> change one account's line in the plan.
set_plan() {
    awk -F'|' -v OFS='|' -v u="$1" -v a="$2" -v w="$3" '$1 == u { $5 = a; $6 = w } { print }' "$W/plan" >"$W/plan.t" && mv "$W/plan.t" "$W/plan"
}
# Typed passwords live only in this run's private work folder (mode 700),
# which is deleted at the end.
: >"$W/typed"; chmod 600 "$W/typed"

FORCED=""
header "QUESTIONS (Enter = the default in capitals)"
if [ "$CANAPPLY" = 1 ] && _cc_can_ask && cc_ask "Go through each account one by one?" Y "yes, ask me about each account" "no, use the actions in the table"; then
    _all=0
    cp "$W/loud" "$W/ask"
    while IFS='|' read -r _u _uid _sh _st _a0 _why0 _fl; do
        _a=$(awk -F'|' -v u="$_u" '$1 == u { print $5 }' "$W/plan")
        [ "$_all" = 1 ] && continue
        case "$_a" in r) _h="R/s/d/k/a" ;; s) _h="r/S/d/k/a" ;; d) _h="r/s/D/k/a" ;; *) _h="r/s/d/K/a" ;; esac
        while :; do
            printf '%s[?]%s %s (uid %s, %s, %s): [r]andom [s]et [d]isable [k]eep [a]ll the rest default  [%s]%s ' \
                "$C_CYN" "$C_OFF" "$_u" "$_uid" "$(basename "$_sh")" "$_st" "$_h" "$(_cc_left_txt)" >/dev/tty
            _cc_read _ans || { printf '\n' >/dev/tty; [ "$CC_TIMER_DEADLINE" -gt 0 ] && [ "$(cc_timer_left)" -eq 0 ] && cc_die 3 "the revert timer ran out while waiting for an answer. Nothing was changed. Run again (--timer gives more time)"; _ans=""; }
            case "$_ans" in ''|r|R|s|S|d|D|k|K|a|A) break ;; *) printf '    answer r, s, d, k or a\n' >/dev/tty ;; esac
        done
        _ans=$(printf '%s' "${_ans:-$_a}" | tr 'RSDKA' 'rsdka')
        [ -n "$CC_TEE" ] && printf '[?] %s: %s\n' "$_u" "$(act_word "$_ans")" >>"$CC_TEE"
        if [ "$_ans" = a ]; then _all=1; continue; fi
        # Extra yes for the account in use and for protected accounts.  A yes
        # for a protected account counts for that account only (FORCED).
        if [ "$_ans" != k ]; then
            if [ -n "$ME" ] && [ "$_u" = "$ME" ]; then
                cc_ask "  $_u is the account you are logged in as. Change it anyway?" N "yes, change it" "no, keep it" || { set_plan "$_u" k "you said keep"; continue; }
            fi
            if cc_is_protected account "$_u"; then
                if cc_ask "  $_u is on the protected list (scoring may log in as it). Change it anyway?" N "yes, change it (report the new password to scoring)" "no, keep it"; then
                    FORCED="$FORCED,$_u"
                else set_plan "$_u" k "protected"; continue; fi
            fi
        fi
        case "$_ans" in
            r) set_plan "$_u" r "random (you chose)" ;;
            d) set_plan "$_u" d "disable (you chose)" ;;
            k) set_plan "$_u" k "you said keep" ;;
            s) if [ -n "$(given_pw "$_u")" ] && cc_ask "  Use the password from --passwords for $_u?" Y "yes, use it" "no, I will type one"; then
                   set_plan "$_u" s "from --passwords"
               elif ask_password "$_u"; then
                   printf '%s\t%s\n' "$_u" "$TYPED" >>"$W/typed"; TYPED=""
                   set_plan "$_u" s "typed"
               else set_plan "$_u" k "no password typed"; fi ;;
        esac
    done <"$W/ask"
fi
# End the sessions of disabled accounts?  A lock does not end a login in progress.
if awk -F'|' '$5 == "d" { f = 1 } END { exit !f }' "$W/plan" && [ "$F_KICK" = 0 ] && cc_have pkill; then
    cc_ask "End the running sessions and processes of the accounts you disable?" Y "yes, log them out and stop their processes" "no, leave them running" && KICK=1
fi

# ---- Plan, then apply ------------------------------------------------------------
header "PLAN"
NCH=0
while IFS='|' read -r _u _uid _sh _st _a _why _fl; do
    case "$_a" in
        r|s|d) NCH=$((NCH + 1)); cc_show "$C_YEL" "  [~] $(act_word "$_a") $_u  ($_why)" ;;
    esac
done <"$W/plan"
[ "$NCH" -eq 0 ] && cc_show "$C_GRN" "  [ok] Nothing to change."

# Back up shadow and passwd ONCE, before the first change: the backup is the
# undo log's way back (and the revert timer's).  A second backup in the same
# run would overwrite the first copy with an already-changed file.
_backed=0
backup_once() {
    [ "$_backed" = 1 ] && return 0
    # FreeBSD: after the undo log copies master.passwd back, the password
    # database must be rebuilt.  Added first, so it runs last (bottom-up).
    case "$SHADOW" in */master.passwd) cc_undo_add "rebuild the password database" "pwd_mkdb -p $(cc_shquote "$SHADOW")" ;; esac
    cc_backup_file "$SHADOW" || return 1
    cc_backup_file "$PASSWD" || return 1
    _backed=1
}
row() { cc_csv_row "$CSV" "$1" "$2" "$3" "$4" "$5" "$6"; }
PWOUT="$CC_RUN_DIR/passwords.csv"
N_ROT=0; N_LOCK=0; N_SKIP=0; N_FAIL=0
: >"$W/show"
APPLIED=0
if [ "$NCH" -gt 0 ] && [ "$CANAPPLY" = 1 ]; then
    _ad=N; [ "$APPLY_FLAG" = 1 ] && _ad=Y
    if cc_ask "Apply these $NCH change(s)?" "$_ad" "yes, apply them now" "no, change nothing"; then
        if [ "$APPLY_FLAG" = 0 ] && [ -z "$CC_PROTECTED" ] && [ "$CC_NO_PROTECTED" != 1 ]; then
            cc_show "$C_YEL" "[*] No protected list (the accounts scoring logs in with)."
            if cc_ask "Change passwords without one?" N "yes, go on without a protected list" "no, stop"; then CC_NO_PROTECTED=1; CC_APPLY=1
            else cc_show "$C_YEL" "[*] Not applied."; fi
        else CC_APPLY=1; fi
        if [ "$CC_APPLY" = 1 ] && { cc_timer_fired || { [ "$CC_TIMER_DEADLINE" -gt 0 ] && [ "$(cc_timer_left)" -lt 3 ]; }; }; then
            cc_die 3 "the revert timer ran out before anything was changed. Nothing was changed. Run again (--timer gives more time)"
        fi
    fi
elif [ "$NCH" -gt 0 ]; then
    cc_show "$C_GRY" "$NCH change(s) planned. Dry run only, so nothing was changed."
fi
[ "$CC_APPLY" = 1 ] && { APPLIED=1; header "APPLYING"; }

# ---- Hashes hidden in /etc/passwd ------------------------------------------------
if [ "$CC_APPLY" = 1 ] && awk -F'|' '$5 != "x" && $5 != "*" && $5 !~ /^!/ { f = 1 } END { exit !f }' "$W/accounts"; then
    if [ -z "$PWCONV" ]; then
        cc_show "$C_RED" "  [x] pwconv not found: fix /etc/passwd by hand (set field 2 to x)"
    elif cc_guard path /etc/passwd; then
        backup_once && cc_run "move password hashes from /etc/passwd into /etc/shadow (pwconv)" "$PWCONV" \
            && cc_show "$C_GRN" "  [+] password hashes moved from /etc/passwd into /etc/shadow"
    fi
fi

_q=$CC_QUIET; CC_QUIET=1
while IFS='|' read -r _u _uid _sh _st _a _why _fl; do
    [ -n "$_u" ] || continue
    case "$_a" in
        k)  case "$_why" in "no usable password"*) ;; *) row "$_u" "$_uid" "$_sh" "$_st" kept "$_why" ;; esac
            continue ;;
        d)  if ! inlist "$_u" "$FORCED" && ! cc_guard account "$_u"; then row "$_u" "$_uid" "$_sh" "$_st" "skipped (protected)" "$_why"; N_SKIP=$((N_SKIP + 1)); continue; fi
            if [ "$CC_APPLY" = 1 ]; then
                backup_once || { row "$_u" "$_uid" "$_sh" "$_st" failed "backup failed"; continue; }
                cc_run "lock and expire account $_u ($_why)" lock_account "$_u"
                if [ $? -eq 0 ]; then
                    cc_undo_add "unlock $_u" "$(unlock_cmd "$_u")"
                    N_LOCK=$((N_LOCK + 1)); row "$_u" "$_uid" "$_sh" "$_st" locked "$_why"
                    cc_show "$C_GRN" "  [+] disabled $_u (locked and expired)"
                    if [ "$KICK" = 1 ] && cc_have pkill && [ -z "$R" ]; then
                        cc_run "end running processes of $_u" pkill -KILL -u "$_u" && cc_show "$C_GRN" "  [+] ended the sessions of $_u"
                    fi
                else N_FAIL=$((N_FAIL + 1)); row "$_u" "$_uid" "$_sh" "$_st" failed "$_why"; cc_show "$C_RED" "  [x] FAILED to disable $_u"; fi
            else
                N_LOCK=$((N_LOCK + 1)); row "$_u" "$_uid" "$_sh" "$_st" "would lock" "$_why"
            fi
            continue ;;
    esac
    # r or s: a new password.
    if ! inlist "$_u" "$FORCED" && ! cc_guard account "$_u"; then
        row "$_u" "$_uid" "$_sh" "$_st" "skipped (protected)" "on the protected list"
        N_SKIP=$((N_SKIP + 1)); continue
    fi
    _pw=""
    if [ "$_a" = s ]; then
        _pw=$(awk -F'\t' -v u="$_u" '$1 == u { p = $2 } END { print p }' "$W/typed")
        [ -n "$_pw" ] || _pw=$(given_pw "$_u")
    fi
    [ -n "$_pw" ] || _pw=$(cc_genpass "$LEN") || { row "$_u" "$_uid" "$_sh" "$_st" failed "no random password"; continue; }
    if [ "$CC_APPLY" != 1 ]; then
        row "$_u" "$_uid" "$_sh" "$_st" "would rotate" "$_why"; N_ROT=$((N_ROT + 1)); _pw=""; continue
    fi
    backup_once || { row "$_u" "$_uid" "$_sh" "$_st" failed "backup failed"; continue; }
    cc_run_quiet "new password for $_u" set_password "$_u" "$_pw"
    if [ $? -ne 0 ]; then
        row "$_u" "$_uid" "$_sh" "$_st" failed "$_why"; N_FAIL=$((N_FAIL + 1)); cc_show "$C_RED" "  [x] FAILED to change the password of $_u"
    else
        if [ ! -f "$PWOUT" ]; then
            (umask 077; printf 'host,user,password,time\n' >"$PWOUT")
            # If the run is undone, the passwords in this file are no longer
            # the real ones: the undo renames it so nobody hands it out.
            cc_undo_add "mark the passwords file as no longer valid" "mv $(cc_shquote "$PWOUT") $(cc_shquote "$CC_RUN_DIR/passwords-UNDONE-not-valid.csv")"
        fi
        # A given password may hold a comma or a quote: quote it the CSV way.
        _pwq=$_pw
        case "$_pw" in *,*|*'"'*) _pwq="\"$(printf '%s' "$_pw" | sed 's/"/""/g')\"" ;; esac
        printf '%s,%s,%s,%s\n' "$CC_HOST" "$_u" "$_pwq" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$PWOUT"; _pwq=""
        [ "$PRINT" = 1 ] && printf '%s:%s\n' "$_u" "$_pw" >>"$W/show"
        row "$_u" "$_uid" "$_sh" "$_st" rotated "$_why"; N_ROT=$((N_ROT + 1))
        cc_show "$C_GRN" "  [+] new password for $_u ($_why)"
    fi
    _pw=""
done <"$W/plan"
CC_QUIET=$_q
: >"$W/typed"

# Samba keeps separate passwords; list its accounts so nobody assumes they changed.
if [ -z "$R" ] && cc_have pdbedit; then
    pdbedit -L 2>/dev/null | cut -d: -f1 | grep . >"$W/samba"
    [ -s "$W/samba" ] && printf 'NOTE|Samba accounts with their own (unchanged) passwords: %s - use smbpasswd if they must change\n' "$(tr '\n' ' ' <"$W/samba")" >>"$W/notes"
fi
if [ "$N_LOCK" -gt 0 ] && [ "$TOOLS" = shadow ] && [ -z "$USERMOD" ]; then
    printf 'NOTE|usermod not found: accounts were locked with "passwd -l" only, which does NOT stop SSH key logins - remove their keys (LX-22)\n' >>"$W/notes"
fi
if [ -z "$KEEP" ]; then
    # Only accounts someone can log in to: a usable (or empty) password.
    # Locked build accounts (nixbld1..32 and the like) are not worth a note.
    awk -F'|' -v m="$UID_MIN" '($2 >= m && $2 < 60000) && ($4 == "set" || $4 == "empty") && $5 != "d" { print $1 }' "$W/plan" >"$W/humans"
    [ -s "$W/humans" ] && printf 'NOTE|human accounts not disabled: %s (check each one is the team'"'"'s)\n' "$(tr '\n' ' ' <"$W/humans")" >>"$W/notes"
fi

# ---- Summary ------------------------------------------------------------------------
{
    printf 'LX-20 Linux password rotation | host %s | %s | %s\n\n' "$CC_HOST" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$([ "$CC_APPLY" = 1 ] && echo APPLIED || echo 'DRY RUN - nothing changed')"
    if [ "$CC_APPLY" = 1 ]; then
        printf 'Rotated: %d   Locked: %d   Skipped (protected): %d   Failed: %d\n\n' "$N_ROT" "$N_LOCK" "$N_SKIP" "$N_FAIL"
    else
        printf 'Would rotate: %d   Would lock: %d   Skipped (protected): %d\n\n' "$N_ROT" "$N_LOCK" "$N_SKIP"
    fi
    awk "$CC_AWK_CSV"'NR > 1 { csvsplit($0, f); printf "  %-16s %-6s %-20s %-8s %s\n", f[1], f[2], f[5], f[4], f[6] }' "$CSV"
    if [ -s "$W/notes" ]; then
        printf '\n'
        awk -F'|' '{ printf "  %-5s %s\n", $1, $2 }' "$W/notes"
    fi
    printf '\n'
    if [ -f "$PWOUT" ]; then
        printf 'New passwords: %s (mode 600)\n' "$PWOUT"
        printf '  Give them to the captain (and the scoring portal if a scored account changed),\n'
        printf '  then remove the file from this box:  rm %s\n' "$PWOUT"
    elif [ "$CC_APPLY" != 1 ]; then
        printf 'Nothing was changed.\n'
    fi
    [ "$CC_APPLY" = 1 ] && [ "$CC_N_DONE" -gt 0 ] && printf 'Undo: sh %s/revert.sh --force (old passwords back), or %s\n' "$CC_RUN_DIR" "$CC_UNDO"
    printf 'All results: %s\n' "$CC_RUN_DIR"
} >"$CC_RUN_DIR/summary.txt"
cc_csv_pretty "$CSV" "$CC_RUN_DIR/accounts.txt" 80
header "SUMMARY"
awk -v R="$C_RED" -v Y="$C_YEL" -v G="$C_GRN" -v C="$C_CYN" -v D="$C_GRY" -v O="$C_OFF" '
    NR == 1                        { print C $0 O; next }
    /^  HIGH/ || / failed / || /Failed: [1-9]/ { print R $0 O; next }
    / rotated / || / locked /      { print G $0 O; next }
    /^  NOTE/ || /would/ || /^New passwords/ || /^  Give/ || /^  then remove/ { print Y $0 O; next }
    /^$/                           { print; next }
                                   { print D $0 O }
' "$CC_RUN_DIR/summary.txt"
cat "$CC_RUN_DIR/summary.txt" >>"$OUTF"
if [ "$PRINT" = 1 ] && [ -s "$W/show" ]; then
    # On screen only: never in output.txt or the log.
    printf '\nNew passwords (also in %s):\n' "$PWOUT"
    sed 's/^/  /' "$W/show"
fi
rm -rf "$W"
if [ "$APPLIED" = 1 ]; then
    header "KEEP OR REVERT"
    cc_show "$C_YEL" "[*] Before you answer: open a NEW SSH or console session and log in with the new password."
    cc_timer_finish
elif [ -n "$CC_TIMER_DIR" ]; then
    cc_timer_cancel; : >"$CC_TIMER_DIR/KEEP"
fi
cc_finish
