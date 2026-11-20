#!/bin/sh
# =============================================================================
# ID:       SV-42
# NAME:     Database password rotation
# ROLE:     Applications  (wave 2, first 15 minutes)
# KIND:     changes - dry run unless --apply
# VERSION:  1.0.0
#
# PURPOSE
#   Default and leaked database passwords are how red team reads the store's
#   customers and plants admins.  This gives every MySQL / MariaDB and
#   PostgreSQL account that logs in with a password a new random one:
#     - an account an app uses (WordPress, Joomla, PrestaShop, OpenCart,
#       Roundcube, Laravel .env, a [client] file such as /root/.my.cnf) gets
#       the new password in the database AND in the app's config, in one step
#     - every new password is tested by logging in with it; if that fails,
#       the old one is put back on the spot
#     - after the changes the site must still load (--url), or everything
#       this run changed is put back
#     - accounts that log in by OS account only (unix_socket, peer), locked
#       accounts and roles that cannot log in are listed and left alone
#     - a superuser or a password-less account that no app uses is flagged:
#       you can lock it
#   New passwords go to ONE file, passwords.txt (mode 600), never to the
#   screen or the logs.
#
#   QUESTIONS (Enter takes the default in capitals; a flag answers each):
#     which box                                  --box NAME
#     go through each account?                   --batch = no, defaults
#     each account: [r]andom [s]et [l]ock [k]eep [a]ll the rest default
#                                                --users / --exclude / --passwords
#     apply?                                     --apply
#
# USAGE
#   sudo sh SV-42-db-passwords.sh                                  dry run, asks
#   sudo sh SV-42-db-passwords.sh --protected p.csv --apply        asks about each account
#   sudo sh SV-42-db-passwords.sh --protected p.csv --apply --batch --url http://127.0.0.1/shop/
#
# OPTIONS
#   --apply            make the changes (without it, dry run only)
#   --box NAME         splunk | webmail | ecomm | other (asked)
#   --users a,b        only these accounts (database user names, repeatable)
#   --exclude a,b      never these accounts (repeatable)
#   --passwords FILE   use these passwords instead of random ones: lines
#                      "user password" or "user,password"
#   --length N         length of random passwords (default 20)
#   --url URL          a page to check after the changes (repeat; default
#                      http://127.0.0.1/ and each app's folder under it)
#   --webroot DIR      also look for app configs here (repeat)
#   --mysql-cnf FILE   MySQL client file to log in with
#   --no-mysql / --no-postgres   leave that database alone
#   --timer SECONDS    revert countdown (default 120); --no-timer
#   --no-color         no colours
#   --help             this text plus the common options
#
# OUTPUTS  (under --out, in db-passwords-N/, mode 700)
#   output.txt     everything shown on screen (never a password)
#   accounts.txt   each account: how it logs in, who uses it, what was done
#   plan.txt, summary.txt, run.txt, revert.sh
#   passwords.txt  the new passwords (mode 600) - hand them to the captain,
#                  then delete the file
#   before/        each account as it was (password hashes: root only)
#
# WHAT IT CHANGES  (only with --apply)
#   Database account passwords (MySQL: SET PASSWORD / ALTER USER, keeping a
#   unix_socket login; PostgreSQL: ALTER ROLE ... PASSWORD), locks the
#   accounts you choose to lock, and the password line in each app config
#   that uses a changed account.  Every change has an undo line.
#
# DEPENDS ON
#   mariadb/mysql client; psql and runuser/su for PostgreSQL; curl or wget
#   for the site check.
#
# TESTED ON
#   Ubuntu 24.04 with MariaDB 10.11 and PostgreSQL 16, under dash, bash,
#   busybox sh, ksh93, mksh and yash with gawk, mawk and busybox awk: app
#   accounts rotated with the config updated and the site still up, a socket
#   login kept, a typed password, a lock, a failed login test put back, and
#   the undo put every old password back.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - The scoring engine may log in to the database directly: put that
#     account on the protected list (it then needs an extra yes).
#   - An app whose config is not recognised keeps working only if you keep
#     its account: the table shows "used by: -" for it.  Look first (SV-01).
#   - An account allowed only from another host (user@10.0.0.5) cannot be
#     tested from here: it is changed, and marked "not tested".
#   - PostgreSQL apps: only Laravel-style .env configs are updated.
#   - "trust" lines in pg_hba.conf let anyone in without a password: SV-20
#     reports them; fix those first or the new password does not matter.
#
# DEBUGGING
#   --debug shows each command (never the passwords: they go on stdin).
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
    exit "$_cc_fin_rc"
}
# <<< BT-LIB

usage() {
    cat <<'USAGE'
SV-42 Database password rotation - new passwords for MySQL/MariaDB and PostgreSQL accounts, apps updated
  sudo sh SV-42-db-passwords.sh                          dry run, asks
  sudo sh SV-42-db-passwords.sh --protected p.csv --apply

  --apply            make the changes (without it, dry run only)
  --box NAME         splunk | webmail | ecomm | other
  --users a,b        only these accounts      --exclude a,b   never these
  --passwords FILE   "user password" lines instead of random passwords
  --length N         random password length (default 20)
  --url URL          page to check after the changes (repeatable)
  --webroot DIR      also look for app configs here (repeatable)
  --mysql-cnf FILE   MySQL client file to log in with
  --no-mysql / --no-postgres   leave that database alone
  --timer SECONDS    revert countdown (default 120); --no-timer
  --no-color         no colours
  --help             show this text
USAGE
    cc_usage_common
}

NL='
'
BOX=""; USERS=""; EXCLUDE=""; GIVEN=""; LEN=20; URLS=""; EXTRA=""; MYCNF=""; NOMY=0; NOPG=0; TIMER=120; NOTIMER=0; COLOR=1
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --apply)       CC_APPLY=1; shift ;;
        --box)         [ $# -ge 2 ] || cc_die 2 "--box needs a name"; BOX=$2; shift 2 ;;
        --users)       [ $# -ge 2 ] || cc_die 2 "--users needs a list"; USERS="$USERS,$2"; shift 2 ;;
        --exclude)     [ $# -ge 2 ] || cc_die 2 "--exclude needs a list"; EXCLUDE="$EXCLUDE,$2"; shift 2 ;;
        --passwords)   [ $# -ge 2 ] || cc_die 2 "--passwords needs a file"; [ -r "$2" ] || cc_die 2 "--passwords: cannot read $2"; GIVEN=$(cc_abspath "$2"); shift 2 ;;
        --length)      [ $# -ge 2 ] || cc_die 2 "--length needs a number"; LEN=$2; shift 2 ;;
        --url)         [ $# -ge 2 ] || cc_die 2 "--url needs an address"; URLS="$URLS $2"; shift 2 ;;
        --webroot)     [ $# -ge 2 ] || cc_die 2 "--webroot needs a folder"; [ -d "$2" ] || cc_die 2 "--webroot: not a folder: $2"; EXTRA="$EXTRA$(cc_abspath "$2")$NL"; shift 2 ;;
        --mysql-cnf)   [ $# -ge 2 ] || cc_die 2 "--mysql-cnf needs a file"; [ -r "$2" ] || cc_die 2 "--mysql-cnf: cannot read $2"; MYCNF=$(cc_abspath "$2"); shift 2 ;;
        --no-mysql)    NOMY=1; shift ;;
        --no-postgres) NOPG=1; shift ;;
        --timer)       [ $# -ge 2 ] || cc_die 2 "--timer needs seconds"; TIMER=$2; shift 2 ;;
        --no-timer)    NOTIMER=1; shift ;;
        --no-color|--no-colour) COLOR=0; shift ;;
        --help|-h)     usage; exit 0 ;;
        *)             cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
cc_box_valid "$BOX" || cc_die 2 "--box must be one of: $CC_BOXES"
for _n in "$LEN" "$TIMER"; do case "$_n" in ''|*[!0-9]*) cc_die 2 "--length and --timer need whole numbers" ;; esac; done
[ "$LEN" -ge 12 ] || cc_die 2 "--length must be at least 12"

cc_init "SV-42" "Database password rotation" changes
cc_detect_os
# shellcheck disable=SC2034  # read by cc_color_init
[ "$COLOR" = 1 ] || CC_NOCOLOR=1
cc_color_init
cc_use_numbered_dir db-passwords
rmdir "$CC_RUN_DIR/raw" 2>/dev/null
chmod 700 "$CC_RUN_DIR"
OUTF="$CC_RUN_DIR/output.txt"
grep -v '\[NOTE\]\|\[DEBUG\]' "$CC_LOG" >"$OUTF" 2>/dev/null || : >"$OUTF"
# shellcheck disable=SC2034  # CC_TEE is read by the library's log functions
CC_TEE=$OUTF
W="$CC_RUN_DIR/.work"; mkdir -p "$W"; chmod 700 "$W"
mkdir -p "$CC_RUN_DIR/before"; chmod 700 "$CC_RUN_DIR/before"
# Tables are kept as .txt only; their CSV source is scratch data in .work.
CC_CSV_DIR="$W/csv"; mkdir -p "$CC_CSV_DIR"
TAB=$(printf '\t')
header() { cc_show "" ""; cc_show "$C_CYN" "==========[ $1 ]=========="; }
inlist() { case ",$2," in *",$1,"*) return 0 ;; esac; return 1; }
# ok_pw PASSWORD -> true if it is safe inside SQL quotes, sed and config files.
ok_pw() { case "$1" in ''|*[!A-Za-z0-9_@%+=.,!?^*~-]*) return 1 ;; esac; [ "${#1}" -ge 8 ]; }

cc_show "$C_CYN" "SV-42 Database password rotation | host $CC_HOST | results in $CC_RUN_DIR"
cc_show "" "Legend: ${C_RED}[!]${C_OFF} fix now   ${C_YEL}[*]${C_OFF} look at it   ${C_YEL}[~] would change${C_OFF}   ${C_GRN}[+] changed${C_OFF}   ${C_GRY}[-] left alone${C_OFF}   ${C_RED}[x] failed${C_OFF}"

# Given passwords: "user<TAB>password".
: >"$W/given"; chmod 600 "$W/given"
if [ -n "$GIVEN" ]; then
    tr ',' ' ' <"$GIVEN" | awk '/^[ \t]*#/ || NF < 2 { next } { print $1 "\t" $2 }' >"$W/given"
    while IFS="$TAB" read -r _u _p; do ok_pw "$_p" || cc_die 2 "--passwords: the password for $_u has a character I cannot put safely in a config (use letters, digits and _@%+=.,!?^*~-, at least 8)"; done <"$W/given"
fi
given_pw() { awk -F'\t' -v u="$1" '$1 == u { print $2; exit }' "$W/given"; }

# ---- Log in -------------------------------------------------------------------------
MYC=""; MYOPT=""; MYSOCK=""; MYME=""; MYKIND=""
if [ "$NOMY" = 0 ] && MYC=$(cc_first mariadb mysql); then
    for _try in "${MYCNF:+--defaults-extra-file=$MYCNF}" --user=root \
                "$( [ -r /etc/mysql/debian.cnf ] && echo --defaults-file=/etc/mysql/debian.cnf )"; do
        [ -n "$_try" ] || continue
        "$MYC" "$_try" --connect-timeout=5 -N -B -e 'SELECT 1' >/dev/null 2>&1 && { MYOPT=$_try; break; }
    done
    if [ -z "$MYOPT" ]; then
        if pgrep -x mysqld >/dev/null 2>&1 || pgrep -x mariadbd >/dev/null 2>&1; then
            cc_show "$C_RED" "  [x] MySQL/MariaDB is running but I could not log in: run as root, or give --mysql-cnf FILE"
        fi
        MYC=""
    fi
fi
myq() { "$MYC" "$MYOPT" --connect-timeout=5 -N -B -e "$1" 2>>"$CC_LOG"; }
if [ -n "$MYC" ]; then
    MYSOCK=$(myq 'SELECT @@socket'); MYME=$(myq 'SELECT CURRENT_USER()')
    case "$(myq 'SELECT VERSION()')" in *MariaDB*) MYKIND=mariadb ;; *) MYKIND=mysql ;; esac
    # MySQL 8 hashes hold binary bytes: shown as hex, they survive the undo file.
    MYHEX=""; [ "$MYKIND" = mysql ] && myq 'SET SESSION print_identified_with_as_hex = ON' >/dev/null 2>&1 && MYHEX="SET SESSION print_identified_with_as_hex = ON;"
    cc_show "$C_GRY" "MySQL/MariaDB: $(myq 'SELECT VERSION()') (logged in as $MYME)"
fi
PGRUN=""
if [ "$NOPG" = 0 ] && cc_have psql && grep -q '^postgres:' /etc/passwd 2>/dev/null; then
    # pgdo CMD... -> run as the postgres account (runuser, or su without it).
    if cc_have runuser; then PGRUN="runuser -u postgres --"; else PGRUN="su"; fi
    pgdo() {
        if [ "$PGRUN" != su ]; then (cd / && runuser -u postgres -- "$@"); return; fi
        _pc=""; for _x in "$@"; do _pc="$_pc $(cc_shquote "$_x")"; done
        (cd / && su postgres -s /bin/sh -c "$_pc")
    }
    pgq() { pgdo psql -X -At -F "$TAB" -c "$1" 2>>"$CC_LOG"; }
    pgin() { pgdo psql -X -q -v ON_ERROR_STOP=1; }
    if [ "$(pgq 'SELECT 1')" = 1 ]; then
        PGPORT_=$(pgq 'SHOW port')
        cc_show "$C_GRY" "PostgreSQL: $(pgq 'SHOW server_version') on port $PGPORT_"
    else PGRUN=""; fi
fi
if [ -z "$MYC" ] && [ -z "$PGRUN" ]; then
    cc_show "$C_GRY" "No MySQL/MariaDB or PostgreSQL I can log in to on this box: nothing to rotate."
    rm -rf "$W"; cc_finish; exit 0
fi

if [ -z "$BOX" ]; then
    cc_box_ask e "${R:-}"
fi
case "$BOX" in
    ecomm)   cc_show "$C_GRY" "  ecomm: the store is scored (ecomm-http). Its database account is changed together with its config, and the store is checked after." ;;
    webmail) cc_show "$C_GRY" "  webmail: Roundcube's database account is changed together with its config, and the login page is checked after." ;;
esac

# ---- Apps and the database accounts they use ----------------------------------------
# $W/apps: "engine|app|config file|user"
q="['\"]"
{
    for _d in /var/www /srv/www /srv/http /usr/share/nginx/html /opt; do [ -d "$_d" ] && printf '%s\n' "$_d"; done
    printf '%s' "$EXTRA"
} | grep . | sort -u >"$W/roots"
while IFS= read -r _d; do
    find "$_d" -maxdepth 5 \( -name node_modules -o -name vendor -o -name .git -o -name cache \) -prune -o \
        -type f \( -name wp-config.php -o -name configuration.php -o -name parameters.php -o -name settings.inc.php -o -name config.php -o -name .env \) -print 2>/dev/null
done <"$W/roots" | sort -u >"$W/cfgs"
for _c in /etc/roundcube/debian-db.php /etc/roundcube/config.inc.php /root/.my.cnf /etc/mysql/debian.cnf; do [ -f "$_c" ] && printf '%s\n' "$_c" >>"$W/cfgs"; done
: >"$W/apps"
while IFS= read -r _c; do
    _app=""; _u=""; _e=mysql
    case "$_c" in
        */wp-config.php) _app=WordPress; _u=$(sed -n "s/.*define( *${q}DB_USER${q} *, *${q}\([^'\"]*\)${q}.*/\1/p" "$_c" | head -n 1) ;;
        */configuration.php) grep -q JConfig "$_c" 2>/dev/null || continue; _app=Joomla; _u=$(sed -n "s/.*public \$user *= *${q}\([^'\"]*\)${q}.*/\1/p" "$_c" | head -n 1) ;;
        */app/config/parameters.php) _app=PrestaShop; _u=$(sed -n "s/.*${q}database_user${q} *=> *${q}\([^'\"]*\)${q}.*/\1/p" "$_c" | head -n 1) ;;
        */config/settings.inc.php) _app=PrestaShop; _u=$(sed -n "s/.*define( *${q}_DB_USER_${q} *, *${q}\([^'\"]*\)${q}.*/\1/p" "$_c" | head -n 1) ;;
        */admin/config.php) continue ;;
        */config.php) grep -q "DB_USERNAME" "$_c" 2>/dev/null || continue; _app=OpenCart; _u=$(sed -n "s/.*define( *${q}DB_USERNAME${q} *, *${q}\([^'\"]*\)${q}.*/\1/p" "$_c" | head -n 1) ;;
        */.env) grep -q '^DB_USERNAME=' "$_c" 2>/dev/null || continue; _app="app (.env)"; grep -q '^DB_CONNECTION=pgsql' "$_c" && _e=postgres
            _u=$(sed -n 's/^DB_USERNAME=["]*\([^"]*\)["]*.*/\1/p' "$_c" | head -n 1) ;;
        */debian-db.php) grep -q "dbtype *= *${q}mysql" "$_c" 2>/dev/null || continue; _app=Roundcube; _u=$(sed -n "s/^\$dbuser *= *${q}\([^'\"]*\)${q}.*/\1/p" "$_c") ;;
        */config.inc.php) _dsn=$(sed -n "s/.*db_dsnw.\] *= *${q}\([a-z]*\):\/\/\([^'\"]*\)${q}.*/\1 \2/p" "$_c" | head -n 1)
            [ -n "$_dsn" ] || continue; case "$_dsn" in *'$'*) continue ;; esac; _app=Roundcube
            case "$_dsn" in pgsql*) _e=postgres ;; mysql*) ;; *) continue ;; esac
            _dsn=${_dsn#* }; _u=${_dsn%%:*} ;;
        */.my.cnf|*/debian.cnf) _app="client file"
            _u=$(awk -F= '/^[ \t]*user[ \t]*=/ { v = $2; gsub(/[ \t"]/, "", v); print v }' "$_c" | sort -u)
            # Only a file for one user, with a password in it.
            [ "$(printf '%s\n' "$_u" | grep -c .)" = 1 ] && grep -q '^[ \t]*password[ \t]*=' "$_c" || continue ;;
        *) continue ;;
    esac
    [ -n "$_u" ] && printf '%s|%s|%s|%s\n' "$_e" "$_app" "$_c" "$_u" >>"$W/apps"
    [ "$_app" = OpenCart ] && [ -f "$(dirname "$_c")/admin/config.php" ] && printf '%s|%s|%s|%s\n' "$_e" "$_app" "$(dirname "$_c")/admin/config.php" "$_u" >>"$W/apps"
done <"$W/cfgs"
apps_of() { awk -F'|' -v e="$1" -v u="$2" '$1 == e && $4 == u { print $2 }' "$W/apps" | sort -u | tr '\n' ',' | sed 's/,$//; s/,/, /g'; }

# ---- Accounts -----------------------------------------------------------------------
# $W/acc: "engine|user|hosts (space separated)|login|used by|flags|action|why"
#   login: password | empty | socket | locked | nologin | password+socket
#   action: r random, s set, l lock, k keep, - nothing to do
: >"$W/acc"; : >"$W/notes"
if [ -n "$MYC" ]; then
    myq "SELECT user, host FROM mysql.user ORDER BY user, host" >"$W/myusers"
    while IFS="$TAB" read -r _u _h; do
        _cr=$(myq "$MYHEX SHOW CREATE USER '$(printf '%s' "$_u" | sed "s/'/''/g")'@'$(printf '%s' "$_h" | sed "s/'/''/g")'")
        _l=password
        case "$_cr" in
            *"ACCOUNT LOCK"*) _l=locked ;;
            *"USING 'invalid' OR unix_socket"*|*"VIA unix_socket"|*"WITH 'auth_socket'"*|*"WITH auth_socket"*|*"USING 'invalid'"*) _l=socket ;;
            *" OR unix_socket"*) _l=password+socket ;;
            *IDENTIFIED*) ;;
            *) _l=empty ;;
        esac
        case "$_cr" in *"IDENTIFIED BY PASSWORD ''"*|*"AS ''"*) _l=empty ;; esac
        printf '%s\t%s\t%s\n' "$_u" "$_h" "$_l" >>"$W/myl"
    done <"$W/myusers"
    # One line per user: the hosts, and the weakest login among them.
    _su=$(myq "SELECT CONCAT(user, '\t', IF(Super_priv = 'Y' OR Grant_priv = 'Y', 'admin', '')) FROM mysql.user" | sort -u)
    awk -F'\t' '{ h[$1] = h[$1] (h[$1] ? " " : "") $2; l = $3
          if (!($1 in k) || l == "empty" || (l ~ /^password/ && k[$1] !~ /^(empty|password)/)) k[$1] = l }
        END { for (u in h) print u "\t" h[u] "\t" k[u] }' "$W/myl" | sort >"$W/myu"
    while IFS="$TAB" read -r _u _hs _l; do
        _by=$(apps_of mysql "$_u"); _fl=""
        printf '%s\n' "$_su" | grep -q "^$_u${TAB}admin" && _fl="admin"
        printf '%s|%s|%s|%s|%s|%s\n' mysql "$_u" "$_hs" "$_l" "${_by:--}" "$_fl" >>"$W/acc"
    done <"$W/myu"
fi
if [ -n "$PGRUN" ]; then
    pgq "SELECT rolname, CASE WHEN NOT rolcanlogin THEN 'nologin' WHEN rolpassword IS NULL THEN 'empty' ELSE 'password' END, CASE WHEN rolsuper THEN 'admin' ELSE '' END FROM pg_authid WHERE rolname !~ '^pg_' ORDER BY 1" |
    while IFS="$TAB" read -r _u _l _fl; do
        # A role with no password logs in by peer/ident (OS account) - or by "trust".
        [ "$_l" = empty ] && _l=socket
        _by=$(apps_of postgres "$_u")
        printf '%s|%s|%s|%s|%s|%s\n' postgres "$_u" - "$_l" "${_by:--}" "$_fl" >>"$W/acc"
    done
fi
# Names in --users / --exclude that are no account here stop the run: a typo
# there would change the account you meant to keep.
_miss=""
for _n in $(printf '%s,%s' "$USERS" "$EXCLUDE" | tr ',' ' '); do
    awk -F'|' -v u="$_n" '$2 == u { f = 1 } END { exit !f }' "$W/acc" || _miss="$_miss $_n"
done
[ -z "$_miss" ] || { rm -rf "$W"; cc_die 2 "no such database account:$_miss (in --users or --exclude). Nothing was changed."; }

# Defaults.
: >"$W/plan"
while IFS='|' read -r _e _u _hs _l _by _fl; do
    _a=r; _why="random"
    case "$_l" in
        socket|locked|nologin) _a=-; _why=$(case "$_l" in socket) echo "logs in by OS account only (no password to change)" ;; locked) echo "locked" ;; *) echo "cannot log in" ;; esac) ;;
    esac
    # A PostgreSQL superuser with no password (peer or trust login) that is
    # not the built-in one: kept by default, but asked about (lock it?).
    [ "$_e" = postgres ] && [ "$_l" = socket ] && [ "$_fl" = admin ] && [ "$_u" != postgres ] && { _a=k; _why="superuser, no password: lock it if it is not yours"; }
    if [ "$_a" = r ]; then
        if inlist "$_u" "$EXCLUDE"; then _a=k; _why="--exclude"
        elif [ -n "$USERS" ] && ! inlist "$_u" "$USERS"; then _a=k; _why="not in --users"
        elif [ -n "$(given_pw "$_u")" ]; then _a=s; _why="from --passwords"
        fi
        [ "$_by" != - ] && _why="$_why; config updated: $_by"
        [ "$_e" = mysql ] && [ "${MYME%@*}" = "$_u" ] && _why="$_why; I am logged in with it (changed last)"
    fi
    [ "$_l" = empty ] && printf 'HIGH|%s (%s) has NO password: anyone can log in as it\n' "$_u" "$_e" >>"$W/notes"
    [ "$_e" = postgres ] && [ "$_fl" = admin ] && [ "$_u" != postgres ] && [ "$_l" != nologin ] && \
        printf 'HIGH|%s is a PostgreSQL superuser that can log in, and is not the built-in postgres: planted? answer [l] to lock it\n' "$_u" >>"$W/notes"
    [ "$_e" = mysql ] && [ "$_fl" = admin ] && [ "$_u" != root ] && [ "$_by" = - ] && case "$_l" in password*|empty) true ;; *) false ;; esac && \
        printf 'NOTE|%s has SUPER or GRANT and no app uses it: one of yours? if not, answer [l] to lock it\n' "$_u" >>"$W/notes"
    printf '%s|%s|%s|%s|%s|%s|%s|%s\n' "$_e" "$_u" "$_hs" "$_l" "$_by" "$_fl" "$_a" "$_why" >>"$W/plan"
done <"$W/acc"
if [ -n "$PGRUN" ]; then
    _hba=$(pgq 'SHOW hba_file')
    [ -n "$_hba" ] && grep -Eq '^[^#]*[[:space:]]trust([[:space:]]|$)' "$_hba" 2>/dev/null && \
        printf 'HIGH|%s has "trust" lines: anyone gets in WITHOUT a password, new or old (SV-20 lists them; change trust to scram-sha-256)\n' "$_hba" >>"$W/notes"
fi

act_word() { case "$1" in r) echo random ;; s) echo set ;; l) echo lock ;; k) echo keep ;; *) echo "-" ;; esac; }
show_table() {
    cc_show "$C_CYN" "$(printf '  %-8s %-18s %-22s %-16s %-7s %s' DB ACCOUNT "FROM HOSTS" "LOGS IN WITH" ACTION "USED BY / NOTES")"
    while IFS='|' read -r _e _u _hs _l _by _fl _a _why; do
        [ "$_a" = - ] && continue
        _col=""; [ "$_l" = empty ] && _col=$C_RED; [ "$_a" = k ] && _col=$C_GRY
        cc_show "$_col" "$(printf '  %-8s %-18s %-22s %-16s %-7s %s' "$_e" "$_u" "$(printf '%s' "$_hs" | cut -c1-22)" "$_l" "$(act_word "$_a")" "$_by${_fl:+ [admin]}  ($_why)")"
    done <"$W/plan"
    _q=$(awk -F'|' '$7 == "-" { printf "%s(%s) ", $2, $4 }' "$W/plan")
    [ -n "$_q" ] && cc_show "$C_GRY" "  [-] left alone (no password to change): $_q"
    return 0
}
header "1/4  database accounts"
show_table
while IFS='|' read -r _lv _tx; do
    case "$_lv" in HIGH) cc_show "$C_RED" "  [!] $_tx" ;; *) cc_show "$C_YEL" "  [*] $_tx" ;; esac
done <"$W/notes"
[ -s "$W/apps" ] || cc_show "$C_YEL" "  [*] no app config found (looked in /var/www /srv /opt; add --webroot DIR): an app's account would get a new password its config does not know"
awk -F'|' '$7 != "-" && $7 != "k" && $5 == "-" { f = 1 } END { exit !f }' "$W/plan" && \
    cc_show "$C_YEL" "  [*] accounts with \"used by: -\": no app config names them. If an app or the scoring engine uses one, keep it (or put it on the protected list)."

# ---- Questions ---------------------------------------------------------------------
read_secret() {
    printf '%s' "$2" >/dev/tty
    stty -echo </dev/tty 2>/dev/null
    _cc_read "$1"; _rs_rc=$?
    stty echo </dev/tty 2>/dev/null
    printf '\n' >/dev/tty
    return "$_rs_rc"
}
ask_password() {
    TYPED=""
    while :; do
        read_secret _p1 "    New password for $1 (not shown): " || return 1
        read_secret _p2 "    Same password again: " || return 1
        if [ "$_p1" != "$_p2" ]; then printf '    They do not match. Again.\n' >/dev/tty; continue; fi
        if ! ok_pw "$_p1"; then printf '    At least 8 characters: letters, digits and _@%%+=.,!?^*~- only. Again.\n' >/dev/tty; continue; fi
        TYPED=$_p1; _p1=""; _p2=""; return 0
    done
}
set_plan() { awk -F'|' -v OFS='|' -v e="$1" -v u="$2" -v a="$3" -v w="$4" '$1 == e && $2 == u { $7 = a; $8 = w } { print }' "$W/plan" >"$W/plan.t" && mv "$W/plan.t" "$W/plan"; }
: >"$W/typed"; chmod 600 "$W/typed"
FORCED=""
CANAPPLY=0; cc_is_root && CANAPPLY=1
header "2/4  questions (Enter = the default in capitals)"
if [ "$CANAPPLY" = 1 ] && _cc_can_ask && awk -F'|' '$7 != "-" { f = 1 } END { exit !f }' "$W/plan" && \
   cc_ask "Go through each account one by one?" Y "yes, ask me about each account" "no, use the actions in the table"; then
    # Accounts left out by --users or --exclude are not asked about.
    awk -F'|' '$7 != "-" && $8 !~ /^(--exclude|not in --users)/' "$W/plan" >"$W/ask"
    _all=0
    while IFS='|' read -r _e _u _hs _l _by _fl _a _why; do
        [ "$_all" = 1 ] && break
        _cfgw="the app configs that use it are updated too"; [ "$_by" = - ] && _cfgw="no app uses it"
        cc_choose "$_e account $_u ($_l, used by: $_by)?" "$_a" \
            "r=random new password ($_cfgw)" "s=set one: you type it twice, it is not shown" \
            "l=lock it: nobody can log in as it (apps using it stop working)" "k=keep it as it is" "a=all the rest: take their defaults"
        _ans=$CC_CHOICE
        [ "$_ans" = a ] && { _all=1; continue; }
        if [ "$_ans" != k ] && cc_is_protected account "$_u"; then
            if cc_ask "  $_u is on the protected list (scoring may log in as it). Change it anyway?" N "yes, change it (report the new password to scoring)" "no, keep it"; then
                FORCED="$FORCED,$_u"
            else set_plan "$_e" "$_u" k "protected"; continue; fi
        fi
        case "$_ans" in
            r) set_plan "$_e" "$_u" r "random (you chose)" ;;
            l) set_plan "$_e" "$_u" l "lock (you chose)" ;;
            k) set_plan "$_e" "$_u" k "you said keep" ;;
            s) if [ -n "$(given_pw "$_u")" ] && cc_ask "  Use the password from --passwords for $_u?" Y "yes, use it" "no, I will type one"; then
                   set_plan "$_e" "$_u" s "from --passwords"
               elif ask_password "$_u"; then
                   printf '%s\t%s\t%s\n' "$_e" "$_u" "$TYPED" >>"$W/typed"; TYPED=""
                   set_plan "$_e" "$_u" s "typed"
               else set_plan "$_e" "$_u" k "no password typed"; fi ;;
        esac
    done <"$W/ask"
fi

# ---- Plan --------------------------------------------------------------------------
header "3/4  plan"
CSV=$(cc_csv_new accounts "db,account,logs_in_with,used_by,action,result")
# The account I am logged in with goes last: changing it first would lock
# me out of the rest.
awk -F'|' -v me="${MYME%@*}" '!($1 == "mysql" && $2 == me)' "$W/plan" >"$W/order"
awk -F'|' -v me="${MYME%@*}" '$1 == "mysql" && $2 == me' "$W/plan" >>"$W/order"
NCH=0
while IFS='|' read -r _e _u _hs _l _by _fl _a _why; do
    case "$_a" in
        r|s|l) NCH=$((NCH + 1)); cc_show "$C_YEL" "  [~] $(act_word "$_a") $_e $_u  ($_why)" ;;
        k) cc_show "$C_GRY" "  [-] keep $_e $_u  ($_why)" ;;
    esac
done <"$W/order"
[ "$NCH" -eq 0 ] && cc_show "$C_GRN" "  [ok] Nothing to change."
{ printf 'SV-42 plan | host %s\n\n' "$CC_HOST"; awk -F'|' '$7 != "-" { printf "  %-8s %-6s %-18s %-16s %s\n", $1, $7, $2, $4, $8 }' "$W/order"; } >"$CC_RUN_DIR/plan.txt"

# ---- Helpers for the changes ------------------------------------------------------------
qq() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/''/g")"; }
acct() { printf '%s@%s' "$(qq "$1")" "$(qq "$2")"; }
PWOUT="$CC_RUN_DIR/passwords.txt"
# set_cfg_pw FILE APP PASSWORD -> the new password into one app config.
set_cfg_pw() {
    _f=$1; _p=$3
    case "$2" in
        WordPress|OpenCart) _sed="s/\\(define( *['\"]DB_PASSWORD['\"] *, *['\"]\\)[^'\"]*\\(['\"]\\)/\\1$_p\\2/" ;;
        Joomla) _sed="s/\\(public \$password *= *['\"]\\)[^'\"]*\\(['\"]\\)/\\1$_p\\2/" ;;
        PrestaShop) _sed="s/\\(['\"]database_password['\"] *=> *['\"]\\)[^'\"]*\\(['\"]\\)/\\1$_p\\2/; s/\\(define( *['\"]_DB_PASSWD_['\"] *, *['\"]\\)[^'\"]*\\(['\"]\\)/\\1$_p\\2/" ;;
        "app (.env)") _sed="s/^DB_PASSWORD=.*/DB_PASSWORD=$_p/" ;;
        "client file") _sed="s/^\\([ \t]*password[ \t]*=\\).*/\\1 $_p/" ;;
        Roundcube) case "$_f" in
                       */debian-db.php) _sed="s/^\\(\$dbpass *= *['\"]\\)[^'\"]*\\(['\"]\\)/\\1$_p\\2/" ;;
                       *) _sed="s|\\(db_dsnw.\\] *= *['\"][a-z]*://[^:]*:\\)[^@]*@|\\1$_p@|" ;;
                   esac ;;
        *) return 1 ;;
    esac
    sed "$_sed" "$_f" >"$_f.ccnew" && cat "$_f.ccnew" >"$_f"; _sr=$?; rm -f "$_f.ccnew"
    touch "$_f"; return "$_sr"
}
# my_set USER HOST PASSWORD -> new password, keeping a unix_socket login.
my_set() {
    if [ "$MYKIND" = mariadb ]; then printf "SET PASSWORD FOR %s = PASSWORD('%s');\n" "$(acct "$1" "$2")" "$3"
    else printf "ALTER USER %s IDENTIFIED BY '%s';\n" "$(acct "$1" "$2")" "$3"; fi | "$MYC" "$MYOPT" -N -B 2>>"$CC_LOG"
}
# my_test USER HOST PASSWORD -> 0 works, 1 fails, 2 cannot be tested from here.
my_test() {
    _tf="$W/t.cnf"; : >"$_tf"; chmod 600 "$_tf"
    case "$2" in
        localhost) printf '[client]\nuser=%s\npassword=%s\nsocket=%s\n' "$1" "$3" "$MYSOCK" >"$_tf" ;;
        %|127.0.0.1|::1|"$CC_HOST") printf '[client]\nuser=%s\npassword=%s\nhost=127.0.0.1\nprotocol=tcp\n' "$1" "$3" >"$_tf" ;;
        *) rm -f "$_tf"; return 2 ;;
    esac
    "$MYC" --defaults-file="$_tf" --connect-timeout=5 -N -B -e 'SELECT 1' >/dev/null 2>>"$CC_LOG"; _tr=$?
    rm -f "$_tf"; [ "$_tr" -eq 0 ] && return 0; return 1
}
pg_test() {
    _tf="$W/t.pgpass"; printf '127.0.0.1:%s:*:%s:%s\n' "${PGPORT_:-5432}" "$1" "$2" >"$_tf"; chmod 600 "$_tf"
    PGPASSFILE=$_tf psql -X -w -h 127.0.0.1 -p "${PGPORT_:-5432}" -U "$1" -d postgres -At -c 'SELECT 1' >/dev/null 2>>"$CC_LOG"; _tr=$?
    rm -f "$_tf"; return "$_tr"
}
# Site check (as SV-21): status and PHP/database errors, before and after.
page() {
    _s=""
    if cc_have curl; then _s=$(curl -s -m 10 -o "$W/page" -w '%{http_code}' "$1" 2>/dev/null)
    elif cc_have wget; then _s=$(wget -q -S -O "$W/page" -T 10 "$1" 2>&1 | awk '/HTTP\// { c = $2 } END { print c }'); fi
    _pe=0; grep -qiE 'error establishing a database connection|database connection error|could not connect to (the )?database|SQLSTATE\[|access denied for user|DB Error|Fatal error' "$W/page" 2>/dev/null && _pe=1
    printf '%s %s' "${_s:-000}" "$_pe"
}
if [ -z "$URLS" ]; then
    URLS="http://127.0.0.1/"
    awk -F'|' '$2 != "client file" { print $3 }' "$W/apps" | while IFS= read -r _c; do
        case "$_c" in /var/www/html/*) _d=$(dirname "$_c"); _d=${_d%/admin}; printf 'http://127.0.0.1/%s/\n' "${_d#/var/www/html/}" ;; esac
    done | sort -u >"$W/urls"
    URLS="$URLS $(tr '\n' ' ' <"$W/urls")"
fi
site_worse() {
    _t=0
    while :; do
        sleep 2; : >"$W/worse"
        while read -r _uu _s0 _e0; do
            _pg=$(page "$_uu"); _s1=${_pg% *}; _e1=${_pg#* }
            _w0=0; case "$_s0" in [23]??) _w0=1 ;; esac; _w1=0; case "$_s1" in [23]??) _w1=1 ;; esac
            { [ "$_w0" = 1 ] && [ "$_w1" = 0 ]; } || { [ "$_e1" = 1 ] && [ "$_e0" = 0 ]; } && printf '%s %s -> %s%s\n' "$_uu" "$_s0" "$_s1" "$([ "$_e1" = 1 ] && echo ' (database error on the page)')" >>"$W/worse"
        done <"$W/site0"
        _t=$((_t + 1)); [ ! -s "$W/worse" ] || [ "$_t" -ge 5 ] && break
    done
    [ -s "$W/worse" ]
}
pw_line() {
    [ -f "$PWOUT" ] || { (umask 077; printf 'New database passwords on %s - give them to the captain, then delete this file\n\n' "$CC_HOST" >"$PWOUT")
        cc_undo_add "mark the passwords file as no longer valid" "mv $(cc_shquote "$PWOUT") $(cc_shquote "$CC_RUN_DIR/passwords-UNDONE-not-valid.txt")"; }
    printf '%-9s %-20s %-24s %s%s\n' "$1" "$2" "$3" "$(date -u +%H:%M:%SZ)" "${4:+   config: $4}" >>"$PWOUT"
}

# change ENGINE USER HOSTS ACTION LOGIN-KIND -> one account, tested; put back
#   on the spot if the new password does not work.  Sets RES.
change() {
    _e=$1; _u=$2; _hs=$3; _a=$4; RES=""; _lc=""
    _cfgs=$(awk -F'|' -v e="$_e" -v u="$_u" '$1 == e && $4 == u { print $2 "|" $3 }' "$W/apps")
    _pw=""
    if [ "$_a" = s ]; then
        _pw=$(awk -F'\t' -v e="$_e" -v u="$_u" '$1 == e && $2 == u { p = $3 } END { print p }' "$W/typed")
        [ -n "$_pw" ] || _pw=$(given_pw "$_u")
    fi
    [ "$_a" = l ] || [ -n "$_pw" ] || _pw=$(cc_genpass "$LEN") || { RES="failed: no random password"; return 1; }
    _sf="$CC_RUN_DIR/before/$(printf '%s-%s' "$_e" "$_u" | tr -c 'A-Za-z0-9._-' '_').sql"
    # Save the account first: the undo puts these statements back.
    if [ "$_e" = mysql ]; then
        : >"$_sf"; chmod 600 "$_sf"
        # An account with no password shows no IDENTIFIED part: the undo
        # must say so, or it would keep the new password.
        for _h in $_hs; do myq "$MYHEX SHOW CREATE USER $(acct "$_u" "$_h")" | sed 's/^CREATE USER/ALTER USER/; /IDENTIFIED/!s/^\(ALTER USER [^ ]*\)/\1 IDENTIFIED BY '"''"'/; s/$/;/' >>"$_sf"; done
        # A lock is undone by an unlock (only then: old servers have no ACCOUNT UNLOCK).
        [ "$_a" = l ] && { sed '/ACCOUNT LOCK/!s/;$/ ACCOUNT UNLOCK;/' "$_sf" >"$_sf.t" && cat "$_sf.t" >"$_sf"; rm -f "$_sf.t"; }
        _undo="$MYC $MYOPT < $(cc_shquote "$_sf")"
        # The account I log in with: after its change only the new password
        # works, so its undo logs in with the new one.
        if [ "${MYME%@*}" = "$_u" ] && [ "$_a" != l ] && case "$MYOPT" in --user=root) [ -f /root/.my.cnf ] ;; *) true ;; esac; then
            _lc="$CC_RUN_DIR/before/login-new.cnf"; (umask 077; printf '[client]\nuser=%s\npassword=%s\nsocket=%s\n' "$_u" "$_pw" "$MYSOCK" >"$_lc")
            _undo="$MYC --defaults-file=$(cc_shquote "$_lc") < $(cc_shquote "$_sf")"
        fi
    else
        _old=$(pgq "SELECT COALESCE(rolpassword, '') FROM pg_authid WHERE rolname = $(qq "$_u")")
        (umask 077; if [ -n "$_old" ]; then printf 'ALTER ROLE "%s" PASSWORD %s;\n' "$_u" "$(qq "$_old")"; else printf 'ALTER ROLE "%s" PASSWORD NULL;\n' "$_u"; fi >"$_sf")
        [ "$_a" = l ] && printf 'ALTER ROLE "%s" LOGIN;\n' "$_u" >>"$_sf"
        if [ "$PGRUN" = su ]; then _undo="cd / && su postgres -s /bin/sh -c 'psql -X -q' < $(cc_shquote "$_sf")"
        else _undo="cd / && runuser -u postgres -- psql -X -q < $(cc_shquote "$_sf")"; fi
        _old=""
    fi
    [ -s "$_sf" ] || { RES="failed: could not save the account first, not changed"; return 1; }
    cc_undo_add "old password back for $_e $_u" "$_undo"

    if [ "$_a" = l ]; then
        if [ "$_e" = mysql ]; then
            for _h in $_hs; do printf 'ALTER USER %s ACCOUNT LOCK;\n' "$(acct "$_u" "$_h")"; done | "$MYC" "$MYOPT" -N -B 2>>"$CC_LOG"
        else printf 'ALTER ROLE "%s" NOLOGIN;\n' "$_u" | pgin 2>>"$CC_LOG"; fi
        [ $? -eq 0 ] && { RES=locked; return 0; }
        RES="failed: could not lock"; return 1
    fi
    # Configs: backed up (and touched after a restore, for PHP's cache).
    printf '%s\n' "$_cfgs" | grep . | while IFS='|' read -r _app _f; do
        cc_undo_add "make PHP reread $_f" "touch $(cc_shquote "$_f")"
        cc_backup_file "$_f" >/dev/null
    done
    _ok=1
    if [ "$_e" = mysql ]; then for _h in $_hs; do my_set "$_u" "$_h" "$_pw" || _ok=0; done
    else printf 'ALTER ROLE "%s" PASSWORD %s;\n' "$_u" "$(qq "$_pw")" | pgin 2>>"$CC_LOG" || _ok=0; fi
    if [ "$_ok" = 1 ]; then
        printf '%s\n' "$_cfgs" | grep . | while IFS='|' read -r _app _f; do set_cfg_pw "$_f" "$_app" "$_pw" || echo bad; done | grep -q bad && _ok=0
    fi
    # Log in with the new password.
    _nt=""
    if [ "$_ok" = 1 ]; then
        if [ "$_e" = mysql ]; then
            for _h in $_hs; do my_test "$_u" "$_h" "$_pw"; case $? in 1) _ok=0 ;; 2) _nt="$_nt $_h" ;; esac; done
        else pg_test "$_u" "$_pw" || _ok=0; fi
    fi
    if [ "$_ok" = 1 ]; then
        pw_line "$_e" "$_u" "$_pw" "$(printf '%s\n' "$_cfgs" | grep . | cut -d'|' -f2 | tr '\n' ' ' | sed 's/ $//')"
        [ "$_e" = mysql ] && [ "${MYME%@*}" = "$_u" ] && [ -n "$_lc" ] && MYOPT="--defaults-file=$_lc"
        RES="changed, login tested"; [ -n "$_nt" ] && RES="changed (not tested from here: only allowed from$_nt)"
        [ -n "$_cfgs" ] && RES="$RES; config updated"
        _pw=""; return 0
    fi
    # Put this account back now.
    printf '%s\n' "$_cfgs" | grep . | while IFS='|' read -r _app _f; do _rb="$CC_BACKUP_DIR$(cc_abspath "$_f")"; [ -f "$_rb" ] && cat "$_rb" >"$_f" && touch "$_f"; done
    sh -c "$_undo" >>"$CC_LOG" 2>&1
    _pw=""; RES="failed: the new password did not work, old one put back"; return 1
}

# ---- Apply --------------------------------------------------------------------------
header "4/4  apply"
APPLIED=0; TIMER_ON=0; SITEFAIL=0; N_OK=0; N_FAIL=0; N_LOCK=0; GO=0
if [ "$NCH" -eq 0 ]; then :
elif [ "$CC_APPLY" != 1 ] || [ "$CANAPPLY" = 0 ]; then
    [ "$CANAPPLY" = 0 ] && cc_show "$C_YEL" "  [!] not root: showing the plan only"
    cc_show "$C_GRY" "  $NCH change(s) planned. Dry run: nothing was changed. Run again with --apply."
    # shellcheck disable=SC2034  # read by cc_finish
    CC_N_WOULD=$NCH
    while IFS='|' read -r _e _u _hs _l _by _fl _a _why; do
        case "$_a" in r|s|l) cc_csv_row "$CSV" "$_e" "$_u" "$_l" "$_by" "$(act_word "$_a")" "would change" ;; k) cc_csv_row "$CSV" "$_e" "$_u" "$_l" "$_by" keep "$_why" ;; esac
    done <"$W/order"
elif ! cc_ask "Apply these $NCH change(s)?" Y "yes, apply them (a revert timer undoes them unless you confirm from a NEW session)" "no, change nothing"; then
    cc_show "$C_GRY" "  Not applied. The plan is in $CC_RUN_DIR/plan.txt"
else
    GO=1
    if [ -z "$CC_PROTECTED" ] && [ "$CC_NO_PROTECTED" != 1 ]; then
        cc_show "$C_YEL" "  [*] No protected list: the scoring engine's database account (if any) is not known."
        cc_ask "Change passwords without one?" N "yes, go on without a protected list" "no, stop" || { cc_show "$C_YEL" "  [*] Not applied."; GO=0; }
    fi
fi
if [ "$GO" = 1 ]; then
    APPLIED=1
    : >"$W/site0"; for _uu in $URLS; do printf '%s %s\n' "$_uu" "$(page "$_uu")" >>"$W/site0"; done
    U0=$(grep -c . "$CC_UNDO" 2>/dev/null)
    if [ "$NOTIMER" != 1 ]; then
        cc_timer_start "$TIMER"; TIMER_ON=1
        cc_show "$C_YEL" "  [*] Revert timer started: every old password comes back in $((TIMER / 60)):$(printf '%02d' $((TIMER % 60))) unless you keep it at the end."
    fi
    _q=$CC_QUIET; CC_QUIET=1
    while IFS='|' read -r _e _u _hs _l _by _fl _a _why; do
        case "$_a" in
            r|s|l) ;;
            k) cc_csv_row "$CSV" "$_e" "$_u" "$_l" "$_by" keep "$_why"; continue ;;
            *) continue ;;
        esac
        if ! inlist "$_u" "$FORCED" && ! cc_guard account "$_u"; then
            cc_csv_row "$CSV" "$_e" "$_u" "$_l" "$_by" "$(act_word "$_a")" "skipped (protected)"; cc_show "$C_YEL" "  [-] $_e $_u: on the protected list, kept"; continue
        fi
        if change "$_e" "$_u" "$_hs" "$_a" </dev/null; then
            [ "$_a" = l ] && N_LOCK=$((N_LOCK + 1)) || N_OK=$((N_OK + 1))
            cc_show "$C_GRN" "  [+] $_e $_u: $RES"
        else
            N_FAIL=$((N_FAIL + 1)); cc_show "$C_RED" "  [x] $_e $_u: $RES"
        fi
        cc_csv_row "$CSV" "$_e" "$_u" "$_l" "$_by" "$(act_word "$_a")" "$RES"
    done <"$W/order"
    CC_QUIET=$_q
    : >"$W/typed"
    if site_worse; then
        SITEFAIL=1
        while IFS= read -r _l; do cc_show "$C_RED" "  [x] worse now: $_l"; done <"$W/worse"
        cc_show "$C_RED" "  Putting every old password back now ..."
        awk -F'\t' -v n="${U0:-0}" 'NR > n { l[NR] = $4 } END { for (i = NR; i > n; i--) print l[i] }' "$CC_UNDO" >"$W/undo-now"
        while IFS= read -r _cmd; do sh -c "$_cmd" >>"$CC_LOG" 2>&1 || cc_show "$C_RED" "  [x] could not undo: $_cmd"; done <"$W/undo-now"
        [ "$TIMER_ON" = 1 ] && cc_timer_cancel 2>/dev/null; TIMER_ON=0
        sleep 2; while read -r _uu _s0 _e0; do cc_show "" "  after the revert $_uu answers $(page "$_uu" | cut -d' ' -f1)"; done <"$W/site0"
    else
        while read -r _uu _s0 _e0; do cc_show "$C_GRN" "  [+] $_uu still answers ($(page "$_uu" | cut -d' ' -f1))"; done <"$W/site0"
    fi
fi

# ---- Summary ----------------------------------------------------------------------------
cc_csv_pretty "$CSV" "$CC_RUN_DIR/accounts.txt" 110
{
    printf '==========[ summary ]==========\n'
    # shellcheck disable=SC2034  # read by cc_finish
    CC_N_DONE=$((N_OK + N_LOCK))
    # shellcheck disable=SC2034  # read by cc_finish
    CC_N_FAIL=$N_FAIL
    printf 'SV-42 Database password rotation | host %s | %s\n' "$CC_HOST" "$([ "$APPLIED" = 1 ] && { [ "$SITEFAIL" = 1 ] && echo 'APPLIED, then PUT BACK (the site broke)' || echo APPLIED; } || echo 'DRY RUN - nothing changed')"
    [ "$APPLIED" = 1 ] && printf 'Changed: %d   Locked: %d   Failed (put back): %d\n' "$N_OK" "$N_LOCK" "$N_FAIL"
    awk "$CC_AWK_CSV"'NR > 1 { csvsplit($0, f); printf "  %-8s %-18s %-7s %s\n", f[1], f[2], f[5], f[6] }' "$CSV"
    [ -s "$W/notes" ] && printf '\nFound before the changes:\n'
    awk -F'|' '{ printf "  %-5s %s\n", $1, $2 }' "$W/notes"
    if [ -f "$PWOUT" ] && [ "$SITEFAIL" = 0 ]; then
        printf '\nNew passwords: %s (mode 600)\n  Give them to the captain (and the scoring portal if a scored account changed), then: rm %s\n' "$PWOUT" "$PWOUT"
    fi
    [ "$APPLIED" = 1 ] && [ -f "$CC_RUN_DIR/revert.sh" ] && printf 'Undo this run: sh %s/revert.sh --force\n' "$CC_RUN_DIR"
    printf 'Accounts: %s/accounts.txt\n' "$CC_RUN_DIR"
} >"$CC_RUN_DIR/summary.txt"
cc_show "" ""
while IFS= read -r _l; do
    case "$_l" in ==*|SV-42*) cc_show "$C_CYN" "$_l" ;; *'Failed (put back): '[1-9]*|*'PUT BACK'*|*HIGH*) cc_show "$C_RED" "$_l" ;; *NOTE*|*'New passwords'*|*'Give them'*) cc_show "$C_YEL" "$_l" ;; *) cc_show "" "$_l" ;; esac
done <"$CC_RUN_DIR/summary.txt"
rm -rf "$W"
if [ "$TIMER_ON" = 1 ]; then
    header "KEEP OR REVERT"
    cc_show "$C_YEL" "[*] Before you answer: load the store and the webmail login in a browser."
    cc_timer_finish || true
fi
cc_finish
