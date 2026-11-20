#!/bin/sh
# =============================================================================
# ID:       SV-20
# NAME:     Database hardening (MySQL / MariaDB)
# ROLE:     Applications  (wave 2, after SV-15 / SV-14 backups)
# KIND:     changes - dry run unless --apply
# VERSION:  1.0.0
#
# PURPOSE
#   Locks down the MySQL / MariaDB server behind the web apps without
#   breaking them.  It first lists every database account and which app
#   uses it (read from the apps' own configs), then offers each fix, graded
#   by how risky it is - the same levels as SV-30:
#
#     safe     cannot break an app
#       db-anon        drop the anonymous accounts (''@host: anyone gets in)
#       db-testdb      drop the empty "test" database
#       db-infile      local_infile OFF (LOAD DATA LOCAL reads client files)
#     service  checked against the web site, undone if it breaks
#       db-remoteroot  drop root accounts that may log in from other hosts
#       db-emptypw     lock accounts with NO password that no app uses
#       db-file        take the FILE privilege (read/write any file the
#                      server can: a web shell into the web root) from
#                      accounts other than root
#       db-apppw       new random password for each app's database account,
#                      written into the app's config in the same step
#     access   can stop something from reaching the database
#       db-bind        listen on 127.0.0.1 only (when every app is local)
#       db-udf         drop user-defined functions (lib_mysqludf_sys and
#                      other backdoors that run commands as the database)
#
#   Reported, never changed: accounts with ALL / SUPER / GRANT, triggers and
#   scheduled events (red team persistence), secure_file_priv, where the
#   server listens, and PostgreSQL "trust" logins.
#
#   After applying, the web site must answer as it did before (same HTTP
#   status, no "database connection" error); if not, everything this run
#   changed is put back.  A revert timer runs, as in the other change scripts.
#
#   QUESTIONS (Enter takes the default in capitals; a flag answers each):
#     which box                                       --box NAME
#     how far: [s]afe [v] service [a]ccess            --level L
#     each fix (yes / no)                             --only / --skip
#     new password for each app's database account    --apppw / --no-apppw
#
# USAGE
#   sudo sh SV-20-db-hardening.sh                           dry run, asks
#   sudo sh SV-20-db-hardening.sh --protected p.csv --apply --level service
#   sudo sh SV-20-db-hardening.sh --protected p.csv --apply --batch --level safe
#
# OPTIONS
#   --apply            make the changes (without it, dry run only)
#   --level L          safe | service | access (asked; Enter = safe)
#   --box NAME         splunk | webmail | ecomm | other (asked)
#   --only a,b / --skip a,b    choose fixes by name
#   --apppw / --no-apppw       change the apps' database passwords (service level)
#   --mysql-cnf FILE   MySQL client file ([client] user/password) when root
#                      cannot log in through the socket
#   --url URL          the page to check after changes (default http://127.0.0.1/)
#   --webroot DIR      also look for app configs here (repeat)
#   --timer SECONDS    revert countdown (default 120); --no-timer
#   --no-color         no colours
#   --help             this text plus the common options
#
# OUTPUTS  (under --out, in db-hardening-N/, mode 700)
#   output.txt      everything shown on screen, no colour
#   accounts.txt    every account: host, how it logs in, rights, used by
#   plan.txt, changes.txt, summary.txt, run.txt
#   passwords.txt   new app database passwords (mode 600; only with db-apppw)
#   before/         each account and setting as it was (for the undo)
#   revert.sh       undo this run
#
# WHAT IT CHANGES  (only with --apply)
#   Database accounts and privileges, the test database, local_infile, the
#   app config files that hold the database password, and a drop-in config
#   file (99-bt-hardening.cnf) for local_infile and bind-address.
#   db-bind restarts the database.  Every change has an undo line.
#
# DEPENDS ON
#   the mysql / mariadb client, curl or
#   wget for the site check (without one the check is skipped and said so).
#
# TESTED ON
#   Ubuntu 24.04 with MariaDB 10.11 and a WordPress-style config, under
#   dash, bash, busybox sh, ksh93, mksh and yash with gawk, mawk and busybox
#   awk: each fix applied, the site still answered, revert put it all back.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - Back up first (SV-15 or SV-14).
#   - An app whose config is not recognised keeps its password: db-apppw
#     only changes accounts it can also write into the app's config.
#   - A scoring check that logs in to the database directly is not known to
#     this script: put that account on the protected list.
#   - PostgreSQL is only reported.
#
# DEBUGGING
#   --debug shows each SQL statement (passwords are never shown).
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
# cc_net_ask_password -> BT_NET_PASS: used as it is when already set (setting
#   it is the answer), else typed now, hidden, never logged.  Returns 1 when
#   there is no password and nobody to ask.
cc_net_ask_password() {
    [ -n "${BT_NET_PASS:-}" ] && return 0
    _cc_can_ask || return 1
    printf '%s[?]%s Device password (hidden, never saved): ' "${C_CYN:-}" "${C_OFF:-}" >/dev/tty
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

ALL_ACTIONS="db-anon db-testdb db-infile db-remoteroot db-emptypw db-file db-apppw db-bind db-udf"

usage() {
    cat <<'USAGE'
SV-20 Database hardening - lock down MySQL / MariaDB without breaking the apps
  sudo sh SV-20-db-hardening.sh                    dry run, asks
  sudo sh SV-20-db-hardening.sh --protected p.csv --apply --level service

  --apply            make the changes (without it, dry run only)
  --level L          safe | service | access (Enter = safe)
  --box NAME         splunk | webmail | ecomm | other
  --only a,b / --skip a,b   fixes by name (see below)
  --apppw / --no-apppw      new passwords for the apps' database accounts
  --mysql-cnf FILE   MySQL client file with a user and password
  --url URL          page to check after the changes (default http://127.0.0.1/)
  --webroot DIR      also look for app configs here (repeatable)
  --timer SECONDS    revert countdown (default 120); --no-timer
  --no-color         no colours
  --help             show this text

Fixes (risk): db-anon[safe] db-testdb[safe] db-infile[safe] db-remoteroot[service]
  db-emptypw[service] db-file[service] db-apppw[service] db-bind[access] db-udf[access]
USAGE
    cc_usage_common
}

NL='
'
LEVEL=""; BOX=""; ONLY=""; SKIP=""; APPPW=""; MYCNF=""; URL=http://127.0.0.1/; EXTRA=""; TIMER=120; NOTIMER=0; COLOR=1
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --apply)      CC_APPLY=1; shift ;;
        --level)      [ $# -ge 2 ] || cc_die 2 "--level needs safe, service or access"; LEVEL=$2; shift 2 ;;
        --box)        [ $# -ge 2 ] || cc_die 2 "--box needs a name"; BOX=$2; shift 2 ;;
        --only)       [ $# -ge 2 ] || cc_die 2 "--only needs a list"; ONLY="$ONLY,$2"; shift 2 ;;
        --skip)       [ $# -ge 2 ] || cc_die 2 "--skip needs a list"; SKIP="$SKIP,$2"; shift 2 ;;
        --apppw)      APPPW=1; shift ;;
        --no-apppw)   APPPW=0; shift ;;
        --mysql-cnf)  [ $# -ge 2 ] || cc_die 2 "--mysql-cnf needs a file"; [ -r "$2" ] || cc_die 2 "--mysql-cnf: cannot read $2"; MYCNF=$(cc_abspath "$2"); shift 2 ;;
        --url)        [ $# -ge 2 ] || cc_die 2 "--url needs an address"; URL=$2; shift 2 ;;
        --webroot)    [ $# -ge 2 ] || cc_die 2 "--webroot needs a folder"; [ -d "$2" ] || cc_die 2 "--webroot: not a folder: $2"; EXTRA="$EXTRA$(cc_abspath "$2")$NL"; shift 2 ;;
        --timer)      [ $# -ge 2 ] || cc_die 2 "--timer needs seconds"; TIMER=$2; shift 2 ;;
        --no-timer)   NOTIMER=1; shift ;;
        --no-color|--no-colour) COLOR=0; shift ;;
        --help|-h)    usage; exit 0 ;;
        *)            cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
case "$LEVEL" in ''|safe|service|access) ;; *) cc_die 2 "--level must be safe, service or access" ;; esac
case "$BOX" in ''|splunk|webmail|ecomm|other) ;; *) cc_die 2 "--box must be splunk, webmail, ecomm or other" ;; esac
case "$TIMER" in ''|*[!0-9]*) cc_die 2 "--timer needs a whole number of seconds" ;; esac
for _a in $(printf '%s' "$ONLY,$SKIP" | tr ',' ' '); do
    case " $ALL_ACTIONS " in *" $_a "*) ;; *) cc_die 2 "unknown fix '$_a' (see --help)" ;; esac
done

cc_init "SV-20" "Database hardening" changes
cc_detect_os
# shellcheck disable=SC2034  # read by cc_color_init
[ "$COLOR" = 1 ] || CC_NOCOLOR=1
cc_color_init
cc_use_numbered_dir db-hardening
chmod 700 "$CC_RUN_DIR" 2>/dev/null
mkdir -p "$CC_RUN_DIR/before" || cc_die 3 "cannot create $CC_RUN_DIR/before"
rmdir "$CC_RUN_DIR/raw" 2>/dev/null
OUTF="$CC_RUN_DIR/output.txt"
grep -v '\[NOTE\]\|\[DEBUG\]' "$CC_LOG" >"$OUTF" 2>/dev/null || : >"$OUTF"
# shellcheck disable=SC2034  # CC_TEE is read by the library's log functions
CC_TEE=$OUTF
W="$CC_RUN_DIR/.work"; mkdir -p "$W"
# Tables are kept as .txt only; their CSV source is scratch data in .work.
CC_CSV_DIR="$W/csv"; mkdir -p "$CC_CSV_DIR"
TAB=$(printf '\t')
header() { cc_show "" ""; cc_show "$C_CYN" "==========[ $1 ]=========="; }
inlist() { case ",$2," in *",$1,"*) return 0 ;; esac; return 1; }

cc_show "$C_CYN" "SV-20 Database hardening | host $CC_HOST | results in $CC_RUN_DIR"
cc_show "" "Legend: ${C_RED}[!]${C_OFF} fix now   ${C_YEL}[*]${C_OFF} look at it   ${C_YEL}[~] would change${C_OFF}   ${C_GRN}[+] changed   [ok] already right${C_OFF}   ${C_RED}[x] failed${C_OFF}"

# ---- Log in -------------------------------------------------------------------------
MYC=$(cc_first mariadb mysql)
[ -n "$MYC" ] || { cc_show "$C_GRY" "No MySQL / MariaDB client on this box: nothing to harden here."; rm -rf "$W"; cc_finish; exit 0; }
MYOPT=""
for _try in "${MYCNF:+--defaults-extra-file=$MYCNF}" --user=root \
            "$( [ -r /etc/mysql/debian.cnf ] && echo --defaults-file=/etc/mysql/debian.cnf )"; do
    [ -n "$_try" ] || continue
    "$MYC" "$_try" --connect-timeout=5 -N -B -e 'SELECT 1' >/dev/null 2>&1 && { MYOPT=$_try; break; }
done
if [ -z "$MYOPT" ]; then
    if pgrep -x mysqld >/dev/null 2>&1 || pgrep -x mariadbd >/dev/null 2>&1; then
        cc_die 3 "MySQL/MariaDB is running but I could not log in: run as root, or give --mysql-cnf FILE"
    fi
    cc_show "$C_GRY" "MySQL / MariaDB is not running here: nothing to harden."; rm -rf "$W"; cc_finish; exit 0
fi
cc_debug "mysql login: $MYOPT"
# myq SQL -> tab-separated rows (nothing when the query fails).
myq() { "$MYC" "$MYOPT" --connect-timeout=5 -N -B -e "$1" 2>>"$CC_LOG"; }
# myx SQL -> run a statement (for cc_run).
myx() { cc_debug "sql: $1"; "$MYC" "$MYOPT" --connect-timeout=5 -N -B -e "$1"; }
MYCMD="$MYC $MYOPT"
VER=$(myq 'SELECT VERSION()')
cc_show "$C_GRY" "Server: $VER (logged in with $MYOPT)"

# ---- Box and level --------------------------------------------------------------------
if [ -z "$BOX" ]; then
    cc_choose "Which box is this?" e "s=splunk" "w=webmail" "e=ecomm" "o=other"
    case "$CC_CHOICE" in s) BOX=splunk ;; w) BOX=webmail ;; e) BOX=ecomm ;; *) BOX=other ;; esac
fi
case "$BOX" in
    ecomm)   cc_show "$C_GRY" "  ecomm: the store is scored (ecomm-http). It must still load after every change: that is checked." ;;
    webmail) cc_show "$C_GRY" "  webmail: the webmail login is scored. Roundcube's database account is found and kept working." ;;
esac
if [ -z "$LEVEL" ]; then
    cc_choose "How far should I go?" s \
        "s=safe: fixes that cannot break an app (anonymous accounts, test database, local_infile)" \
        "v=service: also remote root, accounts with no password, FILE rights, new app passwords - each checked against the site" \
        "a=access: also bind to 127.0.0.1 and drop user-defined functions (restarts the database)"
    case "$CC_CHOICE" in v) LEVEL=service ;; a) LEVEL=access ;; *) LEVEL=safe ;; esac
fi
level_rank() { case "$1" in safe) echo 1 ;; service) echo 2 ;; access) echo 3 ;; esac; }
act_risk() { case "$1" in db-anon|db-testdb|db-infile) echo safe ;; db-bind|db-udf) echo access ;; *) echo service ;; esac; }

# ---- Apps and the database accounts they use ----------------------------------------
# $W/apps: "app|config file|user|host|database"
find_apps() {
    : >"$W/apps"
    {
        for _d in /var/www /srv/www /srv/http /usr/share/nginx/html /opt; do [ -d "$_d" ] && printf '%s\n' "$_d"; done
        printf '%s' "$EXTRA"
    } | grep . | sort -u >"$W/roots"
    q="['\"]"
    while IFS= read -r _d; do
        find "$_d" -maxdepth 5 \( -name node_modules -o -name vendor -o -name .git -o -name cache \) -prune -o \
            -type f \( -name wp-config.php -o -name configuration.php -o -name parameters.php -o -name settings.inc.php -o -name config.php -o -name .env \) -print 2>/dev/null
    done <"$W/roots" | sort -u >"$W/cfgs"
    for _c in /etc/roundcube/debian-db.php /etc/roundcube/config.inc.php; do [ -f "$_c" ] && printf '%s\n' "$_c" >>"$W/cfgs"; done
    while IFS= read -r _c; do
        _app=""; _u=""; _h=""; _db=""
        case "$_c" in
            */wp-config.php) _app=WordPress
                _u=$(sed -n "s/.*define( *${q}DB_USER${q} *, *${q}\([^'\"]*\)${q}.*/\1/p" "$_c" | head -n 1)
                _h=$(sed -n "s/.*define( *${q}DB_HOST${q} *, *${q}\([^'\"]*\)${q}.*/\1/p" "$_c" | head -n 1)
                _db=$(sed -n "s/.*define( *${q}DB_NAME${q} *, *${q}\([^'\"]*\)${q}.*/\1/p" "$_c" | head -n 1) ;;
            */configuration.php) grep -q JConfig "$_c" 2>/dev/null || continue; _app=Joomla
                _u=$(sed -n "s/.*public \$user *= *${q}\([^'\"]*\)${q}.*/\1/p" "$_c" | head -n 1)
                _h=$(sed -n "s/.*public \$host *= *${q}\([^'\"]*\)${q}.*/\1/p" "$_c" | head -n 1)
                _db=$(sed -n "s/.*public \$db *= *${q}\([^'\"]*\)${q}.*/\1/p" "$_c" | head -n 1) ;;
            */app/config/parameters.php) _app=PrestaShop
                _u=$(sed -n "s/.*${q}database_user${q} *=> *${q}\([^'\"]*\)${q}.*/\1/p" "$_c" | head -n 1)
                _h=$(sed -n "s/.*${q}database_host${q} *=> *${q}\([^'\"]*\)${q}.*/\1/p" "$_c" | head -n 1)
                _db=$(sed -n "s/.*${q}database_name${q} *=> *${q}\([^'\"]*\)${q}.*/\1/p" "$_c" | head -n 1) ;;
            */config/settings.inc.php) _app=PrestaShop
                _u=$(sed -n "s/.*define( *${q}_DB_USER_${q} *, *${q}\([^'\"]*\)${q}.*/\1/p" "$_c" | head -n 1)
                _h=$(sed -n "s/.*define( *${q}_DB_SERVER_${q} *, *${q}\([^'\"]*\)${q}.*/\1/p" "$_c" | head -n 1)
                _db=$(sed -n "s/.*define( *${q}_DB_NAME_${q} *, *${q}\([^'\"]*\)${q}.*/\1/p" "$_c" | head -n 1) ;;
            */config.php) grep -q "DB_USERNAME" "$_c" 2>/dev/null || continue; _app=OpenCart
                _u=$(sed -n "s/.*define( *${q}DB_USERNAME${q} *, *${q}\([^'\"]*\)${q}.*/\1/p" "$_c" | head -n 1)
                _h=$(sed -n "s/.*define( *${q}DB_HOSTNAME${q} *, *${q}\([^'\"]*\)${q}.*/\1/p" "$_c" | head -n 1)
                _db=$(sed -n "s/.*define( *${q}DB_DATABASE${q} *, *${q}\([^'\"]*\)${q}.*/\1/p" "$_c" | head -n 1) ;;
            */.env) grep -q '^DB_USERNAME=' "$_c" 2>/dev/null || continue; grep -q '^DB_CONNECTION=pgsql' "$_c" && continue; _app="app (.env)"
                _u=$(sed -n 's/^DB_USERNAME=["]*\([^"]*\)["]*.*/\1/p' "$_c" | head -n 1)
                _h=$(sed -n 's/^DB_HOST=["]*\([^"]*\)["]*.*/\1/p' "$_c" | head -n 1)
                _db=$(sed -n 's/^DB_DATABASE=["]*\([^"]*\)["]*.*/\1/p' "$_c" | head -n 1) ;;
            */debian-db.php) grep -q "dbtype *= *${q}mysql" "$_c" 2>/dev/null || continue; _app=Roundcube
                _u=$(sed -n "s/^\$dbuser *= *${q}\([^'\"]*\)${q}.*/\1/p" "$_c")
                _h=$(sed -n "s/^\$dbserver *= *${q}\([^'\"]*\)${q}.*/\1/p" "$_c")
                _db=$(sed -n "s/^\$dbname *= *${q}\([^'\"]*\)${q}.*/\1/p" "$_c") ;;
            */config.inc.php) _dsn=$(sed -n "s/.*db_dsnw.\] *= *${q}mysqli*:\/\/\([^'\"]*\)${q}.*/\1/p" "$_c" | head -n 1)
                [ -n "$_dsn" ] || continue; case "$_dsn" in *'$'*) continue ;; esac; _app=Roundcube
                _u=${_dsn%%:*}; _h=$(printf '%s' "$_dsn" | sed -n 's|.*@\([^/:]*\).*|\1|p'); _db=${_dsn##*/} ;;
            *) continue ;;
        esac
        [ -n "$_u" ] || continue
        _h=${_h%%:*}; [ -n "$_h" ] || _h=localhost
        printf '%s|%s|%s|%s|%s\n' "$_app" "$_c" "$_u" "$_h" "$_db" >>"$W/apps"
    done <"$W/cfgs"
}
local_host() { case "$1" in localhost|127.*|::1|"$CC_HOST"|'') return 0 ;; esac; return 1; }

header "1/4  accounts and the apps that use them"
find_apps
# Accounts, three table layouts (as in SV-01): user host plugin empty super
# file grant all locked no-password-login.
_cols="u.user, u.host, u.plugin, IF(u.authentication_string = '' OR u.authentication_string IS NULL, 'yes', 'no'), u.Super_priv, u.File_priv, u.Grant_priv, IF(u.Select_priv='Y' AND u.Insert_priv='Y' AND u.Update_priv='Y' AND u.Delete_priv='Y' AND u.Create_priv='Y' AND u.Drop_priv='Y', 'yes', 'no')"
myq "SELECT $_cols, u.account_locked, IF(u.authentication_string = 'invalid', 'yes', 'no') FROM mysql.user u" >"$W/users" 2>/dev/null
[ -s "$W/users" ] || myq "SELECT $_cols, IF(JSON_VALUE(p.priv, '"'$.account_locked'"') IN ('1', 'true'), 'Y', 'N'), IF(u.authentication_string = 'invalid', 'yes', 'no') FROM mysql.user u LEFT JOIN mysql.global_priv p ON p.user = u.user AND p.host = u.host" >"$W/users"
[ -s "$W/users" ] || myq "SELECT u.user, u.host, '', IF(u.password = '', 'yes', 'no'), u.Super_priv, u.File_priv, u.Grant_priv, 'no', 'N', 'no' FROM mysql.user u" >"$W/users"
[ -s "$W/users" ] || cc_die 3 "could not read the account list (mysql.user): is this account an administrator?"
# Accounts: "user|host|auth|empty|super|file|grant|all|locked|used-by"
ACSV=$(cc_csv_new accounts "user,host,logs_in_with,no_password,super,file,grant,all_privileges,locked,used_by")
awk -F"$TAB" -v apps="$W/apps" -v me="$CC_HOST" '
    BEGIN { while ((getline l < apps) > 0) { split(l, a, "|"); used[a[3]] = used[a[3]] (used[a[3]] ? ", " : "") a[1] } }
    { pl = $3; sock = (pl ~ /socket|gssapi|pam/ || $10 == "yes"); locked = ($9 == "Y")
      empty = ($4 == "yes" && !sock && !locked) ? "yes" : "no"
      auth = locked ? "locked" : ($10 == "yes" ? "OS account only" : (sock ? "OS account (" pl ")" : (pl != "" ? "password (" pl ")" : "password")))
      print $1 "|" $2 "|" auth "|" empty "|" ($5 == "Y" ? "yes" : "no") "|" ($6 == "Y" ? "yes" : "no") "|" ($7 == "Y" ? "yes" : "no") "|" $8 "|" (locked ? "yes" : "no") "|" (used[$1] ? used[$1] : "-") }' "$W/users" | sort >"$W/acc"
while IFS='|' read -r _u _h _au _em _su _fi _gr _al _lo _ub; do
    cc_csv_row "$ACSV" "$_u" "$_h" "$_au" "$_em" "$_su" "$_fi" "$_gr" "$_al" "$_lo" "$_ub"
    _c=""; _m='   '; _why=""
    if [ -z "$_u" ]; then _c=$C_RED; _m='[!]'; _why="anonymous: anyone can log in"
    elif [ "$_em" = yes ]; then _c=$C_RED; _m='[!]'; _why="NO password"
    elif [ "$_u" = root ] && ! local_host "$_h"; then _c=$C_RED; _m='[!]'; _why="root from other hosts"
    elif [ "$_u" != root ] && { [ "$_fi" = yes ] || [ "$_su" = yes ] || [ "$_gr" = yes ]; } && [ "$_lo" = no ]; then
        _c=$C_YEL; _m='[*]'; _why="admin rights ($(printf '%s' "$( [ "$_su" = yes ] && printf 'SUPER ')$( [ "$_fi" = yes ] && printf 'FILE ')$( [ "$_gr" = yes ] && printf 'GRANT')" | sed 's/ $//'))"
        case "$_au" in "OS account"*) _c=""; _m='   '; _why="the server's own admin (OS login only)" ;; esac
        if [ "$_ub" = "-" ] && ! local_host "$_h" && [ -n "$_c" ]; then _c=$C_RED; _m='[!]'; _why="$_why from any host, and no app uses it: planted? drop it by hand (DROP USER) if it is not yours"; fi
    fi
    cc_show "$_c" "  $_m $(printf '%-28s %-34s' "${_u:-(anonymous)}@$_h" "$_au") used by: $_ub${_why:+  <- $_why}"
done <"$W/acc"
[ -s "$W/apps" ] || cc_show "$C_YEL" "  [*] no app config found (looked in /var/www /srv /opt; add --webroot DIR): app accounts cannot be told apart"
# Other things worth a look, never changed here.
_trg=$(myq "SELECT COUNT(*) FROM information_schema.triggers WHERE trigger_schema NOT IN ('mysql','sys')")
_evt=$(myq "SELECT COUNT(*) FROM information_schema.events")
_udf=$(myq "SELECT COUNT(*) FROM mysql.func" 2>/dev/null); _udf=${_udf:-0}
_sfp=$(myq "SELECT @@secure_file_priv"); _bind=$(myq "SELECT @@bind_address"); _inf=$(myq "SELECT @@local_infile")
[ "${_trg:-0}" -gt 0 ] && cc_show "$C_YEL" "  [*] $_trg trigger(s): rare in competition apps; one the app did not create is red team persistence (SV-01 lists them)"
[ "${_evt:-0}" -gt 0 ] && cc_show "$C_YEL" "  [*] $_evt scheduled event(s): code the database runs by itself - check each one"
[ "$_udf" -gt 0 ] && cc_show "$C_RED" "  [!] $_udf user-defined function(s): $(myq 'SELECT CONCAT(name, " (", dl, ")") FROM mysql.func' | tr '\n' ' ')- the classic way to run commands through the database"
[ -z "$_sfp" ] || [ "$_sfp" = NULL ] && cc_show "$C_YEL" "  [*] secure_file_priv is empty: SELECT ... INTO OUTFILE can write files anywhere (needs a restart to change: set secure_file_priv in the config)"
cc_show "$C_GRY" "  listens on: ${_bind:-?}   local_infile: $_inf"
if cc_have psql && [ -d /etc/postgresql ] && grep -Eq '^[^#]*[[:space:]]trust([[:space:]]|$)' /etc/postgresql/*/main/pg_hba.conf 2>/dev/null; then
    cc_show "$C_RED" "  [!] PostgreSQL: pg_hba.conf has 'trust' lines (log in with no password) - not changed here: edit pg_hba.conf"
fi

# ---- Which fixes are in play ------------------------------------------------------------
CONSIDER=""
for _a in $ALL_ACTIONS; do
    [ "$(level_rank "$(act_risk "$_a")")" -le "$(level_rank "$LEVEL")" ] || continue
    inlist "$_a" "$SKIP" && continue
    [ -n "$ONLY" ] && ! inlist "$_a" "$ONLY" && continue
    CONSIDER="$CONSIDER $_a"
done
# Accounts each fix would touch (computed once, used by plan and apply).
awk -F'|' '$1 == ""' "$W/acc" >"$W/t.anon"
awk -F'|' -v me="$CC_HOST" '$1 == "root" && $2 != "localhost" && $2 != "127.0.0.1" && $2 != "::1" && $2 != me' "$W/acc" >"$W/t.remoteroot"
awk -F'|' '$4 == "yes" && $1 != "" && $10 == "-" && $9 == "no"' "$W/acc" >"$W/t.emptypw"
# Accounts that log in only as the matching OS account (mysql@localhost on
# MariaDB) are the server's own admins: left alone.
awk -F'|' '$1 != "root" && $1 != "" && $6 == "yes" && $3 !~ /^OS account/ && $1 !~ /^(mariadb\.sys|mysql\.sys|mysql\.session|debian-sys-maint)$/' "$W/acc" >"$W/t.file"
# Apps whose account exists here, is local, and is not protected.
: >"$W/t.apppw"
while IFS='|' read -r _app _c _u _h _db; do
    local_host "$_h" || continue
    awk -F'|' -v u="$_u" '$1 == u' "$W/acc" | grep -q . || continue
    grep -q "^$_u|" "$W/t.apppw" 2>/dev/null && continue
    printf '%s|%s|%s|%s|%s\n' "$_u" "$_app" "$_c" "$_h" "$_db" >>"$W/t.apppw"
done <"$W/apps"
_testdb=$(myq "SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name = 'test'")
_testtables=$(myq "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'test'")
ALLAPPSLOCAL=1; while IFS='|' read -r _app _c _u _h _db; do local_host "$_h" || ALLAPPSLOCAL=0; done <"$W/apps"

act_desc() {
    case "$1" in
        db-anon) echo "drop the anonymous accounts ($(grep -c . "$W/t.anon"))" ;;
        db-testdb) echo "drop the empty 'test' database" ;;
        db-infile) echo "turn local_infile OFF (now $_inf)" ;;
        db-remoteroot) echo "drop root accounts allowed from other hosts ($(cut -d'|' -f2 "$W/t.remoteroot" | tr '\n' ' '))" ;;
        db-emptypw) echo "lock accounts with no password that no app uses ($(awk -F'|' '{ printf "%s@%s ", $1, $2 }' "$W/t.emptypw"))" ;;
        db-file) echo "take the FILE right from $(awk -F'|' '{ printf "%s@%s ", $1, $2 }' "$W/t.file")" ;;
        db-apppw) echo "new random password for each app's database account, written into its config ($(awk -F'|' '{ printf "%s (%s) ", $1, $2 }' "$W/t.apppw"))" ;;
        db-bind) echo "listen on 127.0.0.1 only (now $_bind; restarts the database)" ;;
        db-udf) echo "drop the user-defined functions ($_udf)" ;;
    esac
}
# applies FIX -> true when there is something for it to do.
applies() {
    case "$1" in
        db-anon) [ -s "$W/t.anon" ] ;;
        db-testdb) [ "${_testdb:-0}" -gt 0 ] ;;
        db-infile) [ "$_inf" = 1 ] || [ "$_inf" = ON ] ;;
        db-remoteroot) [ -s "$W/t.remoteroot" ] ;;
        db-emptypw) [ -s "$W/t.emptypw" ] ;;
        db-file) [ -s "$W/t.file" ] ;;
        db-apppw) [ -s "$W/t.apppw" ] ;;
        db-bind) case "$_bind" in 127.0.0.1|localhost|::1) return 1 ;; esac; [ "$ALLAPPSLOCAL" = 1 ] ;;
        db-udf) [ "$_udf" -gt 0 ] ;;
    esac
}

# ---- Questions --------------------------------------------------------------------------
header "2/4  questions (level $LEVEL)"
CHOSEN=""
for _a in $CONSIDER; do
    if ! applies "$_a"; then
        case "$_a" in db-bind) [ "$ALLAPPSLOCAL" = 0 ] && cc_show "$C_YEL" "  [-] db-bind: an app connects from another host, so the database must keep listening on the network" ;; esac
        continue
    fi
    if [ "$_a" = db-testdb ] && [ "${_testtables:-0}" -gt 0 ]; then
        cc_show "$C_YEL" "  [-] db-testdb: the test database has $_testtables table(s) - something may use it, so it stays"; continue
    fi
    _def=Y; [ "$(act_risk "$_a")" = access ] && _def=N
    inlist "$_a" "$ONLY" && _def=Y
    if [ "$_a" = db-apppw ] && [ -n "$APPPW" ]; then [ "$APPPW" = 1 ] && CHOSEN="$CHOSEN $_a"; continue; fi
    if cc_ask "[$(act_risk "$_a")] $(act_desc "$_a")?" "$_def" "yes, do it" "no, skip it"; then CHOSEN="$CHOSEN $_a"; fi
done
if [ -z "$CHOSEN" ]; then
    cc_show "$C_GRN" "  [ok] Nothing to change at level $LEVEL."
    { printf 'SV-20 Database hardening | host %s | level %s | nothing to change\n' "$CC_HOST" "$LEVEL"; } >"$CC_RUN_DIR/summary.txt"
    cc_csv_pretty "$ACSV" "$CC_RUN_DIR/accounts.txt" 120
    rm -rf "$W"; cc_finish; exit 0
fi

# ---- Undo helpers -----------------------------------------------------------------------
# save_user USER HOST [alter] -> before/<user>@<host>.sql, for the undo:
#   CREATE USER + GRANTs (to bring back a dropped account), or with "alter"
#   the same statement as ALTER USER (to put an old password back on an
#   account that still exists).  Root-only folder: it holds the password hash.
qq() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/''/g")"; }
acct() { printf '%s@%s' "$(qq "$1")" "$(qq "$2")"; }
save_user() {
    _sf="$CC_RUN_DIR/before/$(printf '%s@%s' "${1:-anonymous}" "$2" | tr -c 'A-Za-z0-9@._-' '_')${3:+-password}.sql"
    if [ "${3:-}" = alter ]; then
        myq "SHOW CREATE USER $(acct "$1" "$2")" | sed 's/^CREATE USER/ALTER USER/; s/$/;/' >"$_sf" 2>/dev/null
    else
        { myq "SHOW CREATE USER $(acct "$1" "$2")" | sed 's/$/;/'; myq "SHOW GRANTS FOR $(acct "$1" "$2")" | sed 's/$/;/'; } >"$_sf" 2>/dev/null
    fi
    chmod 600 "$_sf"
    [ -s "$_sf" ] || return 1
    SAVED=$_sf
}
# Site check: same HTTP status as before, and no database error on the page.
site_status() {
    if cc_have curl; then curl -s -m 10 -o "$W/page" -w '%{http_code}' "$URL" 2>/dev/null
    elif cc_have wget; then wget -q -S -O "$W/page" -T 10 "$URL" 2>&1 | awk '/HTTP\// { c = $2 } END { print c }'
    fi
}
db_error_page() { grep -qiE 'error establishing a database connection|database connection error|could not connect to (the )?database|SQLSTATE\[|access denied for user' "$W/page" 2>/dev/null; }

# ---- The fixes ------------------------------------------------------------------------
OKN=0
row() {
    cc_csv_row "$CSV" "$1" "$2" "$3" "$4"
    case "$4" in
        "would change") cc_show "$C_YEL" "  [~] $2: $3" ;;
        changed)        cc_show "$C_GRN" "  [+] $2: $3" ;;
        failed)         cc_show "$C_RED" "  [x] FAILED $2: $3" ;;
        refused)        cc_show "$C_YEL" "  [-] $2: $3 (protected)" ;;
        "already ok")   OKN=$((OKN + 1)) ;;
        *)              cc_show "$C_YEL" "  [*] $2: $3" ;;
    esac
    return 0
}
result() { if [ "$CC_APPLY" != 1 ]; then echo "would change"; elif [ "$1" -eq 0 ]; then echo changed; else echo failed; fi; }
DROPIN=""
for _d in /etc/mysql/mariadb.conf.d /etc/mysql/mysql.conf.d /etc/mysql/conf.d /etc/my.cnf.d; do [ -d "$_d" ] && { DROPIN="$_d/99-bt-hardening.cnf"; break; }; done
# db_service -> _svc (the database service on this box) and _rcmd (restart it).
db_service() {
    _svc=""; _rcmd=""
    for _s in mariadb mysql mysqld; do
        if [ "$CC_INIT" = systemd ]; then systemctl cat "$_s" >/dev/null 2>&1 && { _svc=$_s; break; }
        elif [ -e "/etc/init.d/$_s" ]; then _svc=$_s; break; fi
    done
    [ -n "$_svc" ] || return 0
    if [ "$CC_INIT" = systemd ]; then _rcmd="systemctl restart $_svc"; else _rcmd="service $_svc restart"; fi
}
# dropin KEY VALUE -> set KEY under [mysqld] in our drop-in file.
dropin() {
    [ -n "$DROPIN" ] || return 1
    if [ ! -f "$DROPIN" ]; then
        printf '# Added by SV-20 (database hardening). Delete this file to undo.\n[mysqld]\n' >"$DROPIN" || return 1
        cc_undo_add "remove $DROPIN (made by SV-20)" "rm -f $(cc_shquote "$DROPIN")"
    fi
    grep -v "^$1[ =]" "$DROPIN" >"$DROPIN.ccnew" && printf '%s = %s\n' "$1" "$2" >>"$DROPIN.ccnew" && cat "$DROPIN.ccnew" >"$DROPIN"; _dr=$?
    rm -f "$DROPIN.ccnew"; return "$_dr"
}
# drop_users FIX FILE -> drop each account listed, saved first.
drop_users() {
    while IFS='|' read -r _u _h _rest; do
        if [ -n "$_u" ] && ! cc_guard account "$_u"; then row "$1" "${_u}@$_h" "kept" refused; continue; fi
        if [ "$CC_APPLY" = 1 ]; then
            save_user "$_u" "$_h" || { row "$1" "${_u:-(anonymous)}@$_h" "could not save it first, so it was not dropped" failed; continue; }
            cc_undo_add "put back account ${_u:-(anonymous)}@$_h" "$MYCMD < $(cc_shquote "$SAVED")"
        fi
        cc_run "drop account ${_u:-(anonymous)}@$_h" myx "DROP USER $(acct "$_u" "$_h")"
        row "$1" "${_u:-(anonymous)}@$_h" "dropped" "$(result $?)"
    done <"$2"
}
do_fix() {
    case "$1" in
        db-anon) drop_users db-anon "$W/t.anon" ;;
        db-remoteroot) drop_users db-remoteroot "$W/t.remoteroot" ;;
        db-testdb)
            [ "$CC_APPLY" = 1 ] && cc_undo_add "create the test database again" "$MYCMD -e 'CREATE DATABASE IF NOT EXISTS test'"
            cc_run "drop database test" myx "DROP DATABASE test"
            row db-testdb test "empty test database dropped" "$(result $?)" ;;
        db-infile)
            [ "$CC_APPLY" = 1 ] && cc_undo_add "local_infile back to $_inf" "$MYCMD -e 'SET GLOBAL local_infile = 1'"
            cc_run "local_infile OFF now" myx "SET GLOBAL local_infile = 0"; _r=$?
            row db-infile local_infile "OFF now" "$(result $_r)"
            if [ -n "$DROPIN" ]; then cc_run "local_infile = 0 in $DROPIN (after restarts)" dropin local_infile 0; row db-infile "$DROPIN" "local_infile = 0 (stays after a restart)" "$(result $?)"
            else row db-infile config "no config drop-in folder: add local_infile = 0 under [mysqld] by hand" "check by hand"; fi ;;
        db-emptypw)
            while IFS='|' read -r _u _h _rest; do
                cc_guard account "$_u" || { row db-emptypw "$_u@$_h" "kept" refused; continue; }
                [ "$CC_APPLY" = 1 ] && cc_undo_add "unlock $_u@$_h" "$MYCMD -e $(cc_shquote "ALTER USER $(acct "$_u" "$_h") ACCOUNT UNLOCK")"
                cc_run "lock $_u@$_h" myx "ALTER USER $(acct "$_u" "$_h") ACCOUNT LOCK"
                row db-emptypw "$_u@$_h" "locked (it had no password and no app uses it)" "$(result $?)"
            done <"$W/t.emptypw" ;;
        db-file)
            while IFS='|' read -r _u _h _rest; do
                cc_guard account "$_u" || { row db-file "$_u@$_h" "kept" refused; continue; }
                [ "$CC_APPLY" = 1 ] && cc_undo_add "give FILE back to $_u@$_h" "$MYCMD -e $(cc_shquote "GRANT FILE ON *.* TO $(acct "$_u" "$_h")")"
                cc_run "revoke FILE from $_u@$_h" myx "REVOKE FILE ON *.* FROM $(acct "$_u" "$_h")"
                row db-file "$_u@$_h" "FILE right taken away" "$(result $?)"
            done <"$W/t.file" ;;
        db-apppw) app_passwords ;;
        db-bind)
            # The restart undo is recorded first, so a revert removes the
            # config line and THEN restarts (undo lines run newest first).
            if [ "$CC_APPLY" = 1 ]; then db_service; [ -n "$_rcmd" ] && cc_undo_add "restart the database after the config is put back" "$_rcmd"; fi
            if [ -z "$DROPIN" ]; then row db-bind config "no config drop-in folder: set bind-address = 127.0.0.1 by hand" "check by hand"; return 0; fi
            cc_run "bind-address = 127.0.0.1 in $DROPIN" dropin bind-address 127.0.0.1; _r=$?
            [ "$_r" -eq 0 ] && [ "$CC_APPLY" = 1 ] && NEEDRESTART=1
            row db-bind bind-address "127.0.0.1 (applies when the database restarts: done after the other fixes)" "$(result $_r)" ;;
        db-udf)
            myq "SELECT name, ret, type, dl FROM mysql.func" >"$W/udfs"
            while IFS="$TAB" read -r _n _ret _ty _dl; do
                _rt=STRING; case "$_ret" in 1) _rt=REAL ;; 2) _rt=INTEGER ;; 4) _rt=DECIMAL ;; esac
                _ag=""; [ "$_ty" = aggregate ] && _ag="AGGREGATE "
                [ "$CC_APPLY" = 1 ] && cc_undo_add "put back function $_n" "$MYCMD -e $(cc_shquote "CREATE ${_ag}FUNCTION $_n RETURNS $_rt SONAME '$_dl'")"
                cc_run "drop function $_n ($_dl)" myx "DROP FUNCTION $_n"
                row db-udf "$_n" "user-defined function from $_dl dropped (the .so file stays: delete it from the plugin folder)" "$(result $?)"
            done <"$W/udfs" ;;
    esac
}

# app_passwords -> for each app account: new password in the database AND
#   in the app's config, saved first.  Passwords go only to passwords.txt.
PWOUT="$CC_RUN_DIR/passwords.txt"
# set_cfg_pw FILE APP PASSWORD -> write the new password into the app config.
set_cfg_pw() {
    _f=$1; _p=$3
    case "$2" in
        WordPress) _sed="s/\\(define( *['\"]DB_PASSWORD['\"] *, *['\"]\\)[^'\"]*\\(['\"]\\)/\\1$_p\\2/" ;;
        Joomla) _sed="s/\\(public \$password *= *['\"]\\)[^'\"]*\\(['\"]\\)/\\1$_p\\2/" ;;
        PrestaShop) _sed="s/\\(['\"]database_password['\"] *=> *['\"]\\)[^'\"]*\\(['\"]\\)/\\1$_p\\2/; s/\\(define( *['\"]_DB_PASSWD_['\"] *, *['\"]\\)[^'\"]*\\(['\"]\\)/\\1$_p\\2/" ;;
        OpenCart) _sed="s/\\(define( *['\"]DB_PASSWORD['\"] *, *['\"]\\)[^'\"]*\\(['\"]\\)/\\1$_p\\2/" ;;
        "app (.env)") _sed="s/^DB_PASSWORD=.*/DB_PASSWORD=$_p/" ;;
        Roundcube) case "$_f" in
                       */debian-db.php) _sed="s/^\\(\$dbpass *= *['\"]\\)[^'\"]*\\(['\"]\\)/\\1$_p\\2/" ;;
                       *) _sed="s|\\(db_dsnw.\\] *= *['\"]mysqli*://[^:]*:\\)[^@]*@|\\1$_p@|" ;;
                   esac ;;
        *) return 1 ;;
    esac
    sed "$_sed" "$_f" >"$_f.ccnew" && cat "$_f.ccnew" >"$_f"; _sr=$?; rm -f "$_f.ccnew"
    touch "$_f"; return "$_sr"
}
app_passwords() {
    while IFS='|' read -r _u _app _c _h _db; do
        if ! cc_guard account "$_u"; then row db-apppw "$_u ($_app)" "kept" refused; continue; fi
        # OpenCart keeps the same password in admin/config.php too.
        _cfgs=$_c; [ "$_app" = OpenCart ] && [ -f "$(dirname "$_c")/admin/config.php" ] && _cfgs="$_c$NL$(dirname "$_c")/admin/config.php"
        if [ "$CC_APPLY" != 1 ]; then row db-apppw "$_u ($_app)" "new password, written into $(printf '%s' "$_cfgs" | tr '\n' ' ')" "would change"; continue; fi
        _pw=$(cc_genpass 20) || { row db-apppw "$_u" "no random password" failed; continue; }
        # Every host entry of this account gets the new password.
        awk -F'|' -v u="$_u" '$1 == u { print $2 }' "$W/acc" >"$W/hosts"
        _bad=0
        while IFS= read -r _hh; do
            save_user "$_u" "$_hh" alter || { _bad=1; break; }
            cc_undo_add "old password back for $_u@$_hh" "$MYCMD < $(cc_shquote "$SAVED")"
        done <"$W/hosts"
        [ "$_bad" = 0 ] || { row db-apppw "$_u" "could not save the account first: not changed" failed; _pw=""; continue; }
        # PHP caches compiled files (opcache) by their time stamp: a restored
        # file keeps its old time and can be ignored, so the undo touches it
        # after putting it back (this line is recorded first, so it runs last).
        printf '%s\n' "$_cfgs" | while IFS= read -r _f; do
            cc_undo_add "make PHP reread $_f" "touch $(cc_shquote "$_f")"
            cc_backup_file "$_f" >/dev/null
        done
        _ok=1
        printf '%s\n' "$_cfgs" | while IFS= read -r _f; do set_cfg_pw "$_f" "$_app" "$_pw" || echo bad; done | grep -q bad && _ok=0
        if [ "$_ok" = 1 ]; then
            while IFS= read -r _hh; do
                # On stdin, not the command line: no password in the process list.
                printf "ALTER USER %s IDENTIFIED BY '%s';\n" "$(acct "$_u" "$_hh")" "$_pw" | "$MYC" "$MYOPT" -N -B 2>>"$CC_LOG" || _ok=0
            done <"$W/hosts"
        fi
        if [ "$_ok" = 1 ]; then
            [ -f "$PWOUT" ] || { (umask 077; printf 'New database passwords on %s (already written into the apps'"'"' configs)\n\n' "$CC_HOST" >"$PWOUT")
                cc_undo_add "mark the passwords file as no longer valid" "mv $(cc_shquote "$PWOUT") $(cc_shquote "$CC_RUN_DIR/passwords-UNDONE-not-valid.txt")"; }
            printf '%-18s %-12s %-22s %s\n    config: %s\n' "$_u" "$_app" "$_pw" "$(date -u +%H:%M:%SZ)" "$_c" >>"$PWOUT"
            row db-apppw "$_u ($_app)" "new password in the database and in $(printf '%s' "$_cfgs" | tr '\n' ' ')(saved in passwords.txt)" changed
        else
            row db-apppw "$_u ($_app)" "the config or the database did not take the new password: putting both back" failed
            printf '%s\n' "$_cfgs" | while IFS= read -r _f; do _rb="$CC_BACKUP_DIR$(cc_abspath "$_f")"; [ -f "$_rb" ] && cat "$_rb" >"$_f"; done
            while IFS= read -r _hh; do _sf="$CC_RUN_DIR/before/$(printf '%s@%s' "$_u" "$_hh" | tr -c 'A-Za-z0-9@._-' '_')-password.sql"; "$MYC" "$MYOPT" <"$_sf" 2>>"$CC_LOG"; done <"$W/hosts"
        fi
        _pw=""
    done <"$W/t.apppw"
}

run_all() {
    _q=$CC_QUIET; CC_QUIET=1
    for _a in $CHOSEN; do
        cc_show "$C_CYN" "  -- $_a [$(act_risk "$_a")]"
        do_fix "$_a"
        [ "$OKN" -gt 0 ] && cc_show "$C_GRN" "  [ok] $OKN already right"; OKN=0
    done
    CC_QUIET=$_q
}

# ---- Plan -------------------------------------------------------------------------------
header "3/4  plan (dry run: nothing is changed yet)"
CSV=$(cc_csv_new plan "fix,item,detail,status")
_real=$CC_APPLY; CC_APPLY=0; NEEDRESTART=0
run_all
CC_APPLY=$_real
NCH=$(awk "$CC_AWK_CSV"'NR > 1 { csvsplit($0, f); if (f[4] == "would change") n++ } END { print n + 0 }' "$CSV")
cc_csv_pretty "$CSV" "$CC_RUN_DIR/plan.txt" 110

# ---- Apply ------------------------------------------------------------------------------
header "4/4  apply"
APPLIED=0; TIMER_ON=0
CANAPPLY=0; [ "$CC_APPLY" = 1 ] && cc_is_root && CANAPPLY=1
[ "$CC_APPLY" = 1 ] && [ "$CANAPPLY" = 0 ] && cc_show "$C_YEL" "  [!] not root: showing the plan only"
if [ "$NCH" -eq 0 ]; then
    cc_show "$C_GRN" "  [ok] Nothing to change."
elif [ "$CANAPPLY" = 0 ]; then
    cc_show "$C_GRY" "  $NCH change(s) planned. Dry run: nothing was changed. Back up first (SV-15), then run again with --apply."
elif ! cc_ask "Apply these $NCH change(s)?" Y "yes, apply them (a revert timer undoes them unless you confirm from a NEW session)" "no, change nothing"; then
    cc_show "$C_GRY" "  Not applied. The plan is in $CC_RUN_DIR/plan.txt"
else
    HTTP0=$(site_status); DBERR0=0; db_error_page && DBERR0=1
    U0=$(grep -c . "$CC_UNDO" 2>/dev/null)
    [ -n "$HTTP0" ] || cc_show "$C_YEL" "  [*] cannot check the site ($URL: no curl/wget, or no answer): the changes are not tested against it"
    if [ "$NOTIMER" != 1 ]; then
        cc_timer_start "$TIMER"; TIMER_ON=1
        cc_show "$C_YEL" "  [*] Revert timer started: everything is undone in $((TIMER / 60)):$(printf '%02d' $((TIMER % 60))) unless you keep it at the end."
    fi
    APPLIED=1
    CSV=$(cc_csv_new changes "fix,item,detail,status")
    run_all
    if [ "$NEEDRESTART" = 1 ]; then
        db_service
        if [ -z "$_svc" ]; then
            cc_show "$C_YEL" "  [*] could not tell how the database service is called: restart it by hand for bind-address"
        else
            cc_show "" "  restarting $_svc for bind-address ..."
            if sh -c "$_rcmd" >>"$CC_LOG" 2>&1 && sleep 2 && myq 'SELECT 1' >/dev/null; then
                _nb=$(myq 'SELECT @@bind_address')
                case "$_nb" in
                    127.0.0.1|localhost|::1) cc_show "$C_GRN" "  [+] $_svc restarted, now listening on $_nb only" ;;
                    *) cc_show "$C_YEL" "  [*] $_svc restarted but still listens on $_nb: another config file sets bind-address after ours (grep -r bind-address /etc/mysql)" ;;
                esac
            else
                cc_show "$C_RED" "  [x] $_svc did not come back after the restart"; SITEFAIL=1
            fi
        fi
    fi
    # The site must answer as before.
    SITEFAIL=${SITEFAIL:-0}
    if [ -n "$HTTP0" ]; then
        # Worse = it worked before and not now, or a new database error.
        # A site that was broken and now works is fine.  PHP rereads
        # changed files only every few seconds (opcache), so a worse answer
        # is tried again for up to 10 seconds before it counts.
        _w0=0; case "$HTTP0" in [23]??) _w0=1 ;; esac
        _try=0
        while :; do
            sleep 2; HTTP1=$(site_status); DBERR1=0; db_error_page && DBERR1=1
            _w1=0; case "$HTTP1" in [23]??) _w1=1 ;; esac
            _worse=0; { [ "$_w0" = 1 ] && [ "$_w1" = 0 ]; } || { [ "$DBERR1" = 1 ] && [ "$DBERR0" = 0 ]; } && _worse=1
            _try=$((_try + 1)); [ "$_worse" = 0 ] || [ "$_try" -ge 5 ] && break
        done
        if [ "$_worse" = 1 ]; then
            SITEFAIL=1
            cc_show "$C_RED" "  [x] the site answers differently now ($URL: $HTTP0 -> $HTTP1$([ "$DBERR1" = 1 ] && echo ', database error on the page'))"
        else
            if [ "$_w0" = 0 ] && [ "$_w1" = 1 ]; then cc_show "$C_GRN" "  [+] the site works now ($URL: $HTTP0 -> $HTTP1)"
            elif [ "$_w1" = 0 ]; then cc_show "$C_YEL" "  [*] the site was not working before either ($URL: $HTTP1): not made worse"
            else cc_show "$C_GRN" "  [+] the site still answers ($URL: $HTTP1)"; fi
        fi
    fi
    if [ "$SITEFAIL" = 1 ]; then
        cc_show "$C_RED" "  Putting everything back now ..."
        # This run's undo lines, newest first (the same as revert.sh does).
        awk -F'\t' -v n="${U0:-0}" 'NR > n { l[NR] = $4 } END { for (i = NR; i > n; i--) print l[i] }' "$CC_UNDO" >"$W/undo-now"
        while IFS= read -r _cmd; do sh -c "$_cmd" >>"$CC_LOG" 2>&1 || cc_show "$C_RED" "  [x] could not undo: $_cmd"; done <"$W/undo-now"
        [ "$TIMER_ON" = 1 ] && cc_timer_cancel 2>/dev/null
        sleep 1; cc_show "" "  after the revert the site answers: $(site_status)"
        TIMER_ON=0
    fi
    cc_csv_pretty "$CSV" "$CC_RUN_DIR/changes.txt" 110
fi
if [ "$TIMER_ON" = 1 ]; then header "KEEP OR REVERT"; cc_timer_finish || true; fi

# ---- Summary ----------------------------------------------------------------------------
cc_csv_pretty "$ACSV" "$CC_RUN_DIR/accounts.txt" 120
{
    printf '==========[ summary ]==========\n'
    printf 'SV-20 Database hardening | host %s | %s | level %s | %s\n' "$CC_HOST" "$VER" "$LEVEL" "$([ "$APPLIED" = 1 ] && { [ "${SITEFAIL:-0}" = 1 ] && echo 'APPLIED, then PUT BACK (the site broke)' || echo APPLIED; } || echo 'DRY RUN - nothing changed')"
    printf 'Fixes chosen:%s\n' "$CHOSEN"
    awk "$CC_AWK_CSV"'NR > 1 { csvsplit($0, f); if (f[4] != "already ok") printf "  %-13s %-12s %-28s %s\n", toupper(f[4]), f[1], f[2], f[3] }' "$CSV" | head -n 60
    [ -f "$PWOUT" ] && printf '\nNew database passwords: %s (root only). They are already in the apps'"'"' configs.\n' "$PWOUT"
    printf '\nAccounts: %s/accounts.txt\n' "$CC_RUN_DIR"
    [ "$APPLIED" = 1 ] && [ -f "$CC_RUN_DIR/revert.sh" ] && printf 'Undo this run: sh %s/revert.sh --force\n' "$CC_RUN_DIR"
} >"$CC_RUN_DIR/summary.txt"
cc_show "" ""
while IFS= read -r _l; do
    case "$_l" in ==*|SV-20*) cc_show "$C_CYN" "$_l" ;; *CHANGED*) cc_show "$C_GRN" "$_l" ;; *FAILED*|*'PUT BACK'*) cc_show "$C_RED" "$_l" ;; *'WOULD CHANGE'*|*REFUSED*) cc_show "$C_YEL" "$_l" ;; *) cc_show "" "$_l" ;; esac
done <"$CC_RUN_DIR/summary.txt"
rm -rf "$W"
cc_finish
