#!/bin/sh
# =============================================================================
# ID:       SV-32
# NAME:     TLS certificate check
# ROLE:     Applications  (wave 1 look, wave 2 fixes)
# KIND:     changes - dry run unless --apply
# VERSION:  1.0.0
#
# PURPOSE
#   HTTPS, IMAPS, POP3S and SMTP with STARTTLS all hang on a certificate and
#   its private key.  Red team swaps the certificate, steals a key anyone
#   can read, or turns on old TLS so traffic can be broken.  This looks at:
#     files    every certificate and key named in the Apache, nginx,
#              Dovecot, Postfix, vsftpd and MariaDB/MySQL configs:
#              expired or about to, not matching its key, self-signed,
#              weak key (< 2048 bits), SHA-1 / MD5 signature, a key file
#              others can read
#     served   each TLS port on this box (443, 8443, 993, 995, 465, and
#              STARTTLS on 25, 587, 143, 110, 21, 3306): the certificate it
#              really serves, whether it still takes TLS 1.0 / 1.1 or weak
#              ciphers (RC4, 3DES, NULL, anonymous)
#     changes  a fingerprint baseline: a certificate that changed since the
#              first run is flagged (a swap)
#
#   QUESTIONS (Enter takes the default in capitals; a flag answers each):
#     a key others can read        [f]ix it (chmod 600) / [l]eave      f
#     a broken or expired cert     [n]ew self-signed one / [l]eave
#                                  (default n only when it was self-signed:
#                                   nothing a CA signed is replaced on its own)
#     old TLS / weak ciphers       [f]ix the config (TLS 1.2+, strong
#                                  ciphers; tested, reloaded, checked) / [l]   f
#     changed since the baseline   [k]eep flagging it / [u]se it as the
#                                  new baseline                         k
#     apply?                       --apply
#
# USAGE
#   sudo sh SV-32-tls-check.sh                                  look + dry run
#   sudo sh SV-32-tls-check.sh --protected p.csv --apply        asks each fix
#   sudo sh SV-32-tls-check.sh --protected p.csv --apply --batch
#
# OPTIONS
#   --apply            make the changes (without it, dry run only)
#   --port P[:PROTO[:SERVICE]]  also probe this port (repeatable); PROTO is
#                      a STARTTLS kind (smtp imap pop3 ftp mysql) or tls;
#                      SERVICE (apache2 nginx dovecot postfix) whose config
#                      to fix when the program is not seen
#   --host NAME        address to probe (default 127.0.0.1)
#   --days N           warn when a certificate ends within N days (default 14)
#   --no-probe         do not connect to the ports, files only
#   --root DIR         treat DIR as / for the files (tests): nothing reloaded
#   --no-color         no colours
#   --help             this text plus the common options
#
# OUTPUTS  (under --out, in tls-N/)
#   output.txt, certs.txt, served.txt, findings.txt, summary.txt
#   tls-baseline-HOST.txt (in --out): fingerprints only, never a key
#
# DEPENDS ON
#   openssl (the command), ss; timeout when there (a probe never hangs).
#
# TESTED ON
#   OpenSSL 3.0 on Ubuntu 24.04: certificates and configs in a fake root
#   (expired, weak, mismatched, readable key) and openssl s_server
#   stand-ins on high ports, under dash, bash, busybox sh, ksh93, mksh and
#   yash with gawk, mawk and busybox awk.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - A new self-signed certificate makes browsers and a scoring check that
#     verifies certificates complain.  That is why a CA-signed one is never
#     replaced by default.
#   - Old TLS off can lock out a very old client.  The fix is checked with a
#     TLS 1.2 connection and put back if the port stops answering.
# =============================================================================

# >>> BT-LIB  (lib/lib.sh 0.3.0 pasted in by tools/build.sh - edit lib/lib.sh, not this copy)
# =============================================================================
# ID:       LB-01
# NAME:     Shell library (lib.sh)
# ROLE:     Automation  (wave 0, foundation)
# VERSION:  0.3.0
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
CC_LIB_VERSION="0.3.0"

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

usage() {
    cat <<'USAGE'
SV-32 TLS certificate check - certificates, keys, what each port serves, old TLS
  sudo sh SV-32-tls-check.sh                             look + dry run
  sudo sh SV-32-tls-check.sh --protected p.csv --apply   asks each fix

  --apply            make the changes (without it, dry run only)
  --port P[:PROTO[:SERVICE]]  also probe this port; PROTO: tls smtp imap pop3 ftp mysql
                     SERVICE: apache2 nginx dovecot postfix (whose config to fix)
  --host NAME        address to probe (default 127.0.0.1)
  --days N           warn when a certificate ends within N days (default 14)
  --no-probe         files only, no connections
  --root DIR         treat DIR as / for the files (tests)
  --no-color         no colours
  --help             show this text
USAGE
    cc_usage_common
}

NL='
'
EXTRA=""; PHOST=127.0.0.1; DAYS=14; PROBE=1; R=""; COLOR=1
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --apply)    CC_APPLY=1; shift ;;
        --port)     [ $# -ge 2 ] || cc_die 2 "--port needs a port"; EXTRA="$EXTRA$2$NL"; shift 2 ;;
        --host)     [ $# -ge 2 ] || cc_die 2 "--host needs a name"; PHOST=$2; shift 2 ;;
        --days)     [ $# -ge 2 ] || cc_die 2 "--days needs a number"; DAYS=$2; shift 2 ;;
        --no-probe) PROBE=0; shift ;;
        --root)     [ $# -ge 2 ] || cc_die 2 "--root needs a folder"; [ -d "$2" ] || cc_die 2 "--root: not a folder: $2"; R=$(cd "$2" && pwd); [ "$R" = / ] && R=""; shift 2 ;;
        --no-color|--no-colour) COLOR=0; shift ;;
        --help|-h)  usage; exit 0 ;;
        *)          cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
case "$DAYS" in ''|*[!0-9]*) cc_die 2 "--days needs a whole number" ;; esac
printf '%s' "$EXTRA" | grep -v '^[0-9]\{1,5\}\(:\(tls\|smtp\|imap\|pop3\|ftp\|mysql\)\(:\(apache2\|nginx\|dovecot\|postfix\)\)\{0,1\}\)\{0,1\}$' | grep -q . && cc_die 2 "--port: PORT, PORT:PROTO or PORT:PROTO:SERVICE (tls smtp imap pop3 ftp mysql; apache2 nginx dovecot postfix)"
printf '%s' "$PHOST" | grep -q '^[A-Za-z0-9.:-]*$' || cc_die 2 "--host: a name or address"

cc_init "SV-32" "TLS certificate check" changes
cc_detect_os
# shellcheck disable=SC2034  # read by cc_color_init
[ "$COLOR" = 1 ] || CC_NOCOLOR=1
cc_color_init
cc_use_numbered_dir tls
rmdir "$CC_RUN_DIR/raw" 2>/dev/null
OUTF="$CC_RUN_DIR/output.txt"
grep -v '\[NOTE\]\|\[DEBUG\]' "$CC_LOG" >"$OUTF" 2>/dev/null || : >"$OUTF"
# shellcheck disable=SC2034  # CC_TEE is read by the library's log functions
CC_TEE=$OUTF
W="$CC_RUN_DIR/.work"; mkdir -p "$W"
US=$(printf '\037')
header() { cc_show "" ""; cc_show "$C_CYN" "==========[ $1 ]=========="; }
P() { printf '%s%s' "$R" "$1"; }
# real FILE -> the file a symlink chain ends at (inside --root too).  Edits and
# backups go to the real file: a backup of the link would restore nothing.
real() {
    _rf=$1; _ri=0
    while [ -h "$_rf" ] && [ "$_ri" -lt 10 ]; do
        _rl=$(readlink "$_rf"); case "$_rl" in /*) _rf="$R$_rl" ;; *) _rf="$(dirname "$_rf")/$_rl" ;; esac; _ri=$((_ri + 1))
    done
    printf '%s' "$_rf"
}
TO=""; cc_have timeout && TO="timeout 8"
cc_have openssl || { cc_show "$C_RED" "[x] the openssl command is missing (apt-get install openssl)"; rm -rf "$W"; cc_finish; exit 3; }

cc_show "$C_CYN" "SV-32 TLS certificate check | host $CC_HOST | results in $CC_RUN_DIR"
cc_show "" "Legend: ${C_RED}[!]${C_OFF} fix now   ${C_YEL}[*]${C_OFF} look at it   ${C_GRN}[ok]${C_OFF} fine   ${C_YEL}[~] would change${C_OFF}   ${C_GRN}[+] changed${C_OFF}   ${C_RED}[x] failed${C_OFF}"
[ -n "$R" ] && cc_show "$C_GRY" "Acting on $R as if it were / (nothing reloaded)"
: >"$W/find"   # level US service US what US fix US target US default
finding() { printf '%s\037%s\037%s\037%s\037%s\037%s\n' "$1" "$2" "$3" "$4" "$5" "$6" >>"$W/find"
    case "$1" in HIGH) cc_show "$C_RED" "  [!] $2: $3" ;; MED) cc_show "$C_YEL" "  [*] $2: $3" ;; esac; }

# ---- 1. Certificate files in the configs ----------------------------------------------------------
header "1/5  certificates in the configs"
# pairs FILES... (stdin: style) -> "service|conf|cert|key" from one service's configs
# awk reads KEY VALUE lines; cert and key pair up in the order they come.
pairs() {
    _svc=$1; _ck=$2; _kk=$3; shift 3
    for _f in "$@"; do
        [ -f "$_f" ] || continue
        awk -v s="$_svc" -v ck="$_ck" -v kk="$_kk" -v f="${_f#"$R"}" '
            { l = $0; sub(/^[ \t]+/, "", l); if (l ~ /^[#;]/) next
              n = split(l, w, /[ \t=]+/); if (n < 2) next; k = tolower(w[1]); v = w[2]
              if (v == "<" || v == "") v = w[3]; sub(/^</, "", v); gsub(/[";]/, "", v)
              if (k == ck) { if (c != "") out(); c = v } else if (k == kk) k2 = v; else next
              if (c != "" && k2 != "") out() }
            function out() { print s "|" f "|" c "|" (k2 == "" ? c : k2); c = ""; k2 = "" }  # awk, not shell: posix-ok
            END { if (c != "") out() }' "$_f"
    done
}
{
    pairs apache2 sslcertificatefile sslcertificatekeyfile "$(P /etc/apache2/sites-enabled)"/* "$(P /etc/apache2/mods-enabled)"/*.conf "$(P /etc/httpd/conf.d)"/*.conf "$(P /etc/httpd/conf/httpd.conf)"
    # snippets only when an enabled site includes them (Ubuntu's snakeoil.conf)
    _sn=$(cat "$(P /etc/nginx/sites-enabled)"/* "$(P /etc/nginx/conf.d)"/*.conf 2>/dev/null | sed -n 's|^[[:space:]]*include[[:space:]]\{1,\}\(snippets/[^;[:space:]]*\);.*|\1|p' | sort -u | while IFS= read -r _x; do printf '%s ' "$(P "/etc/nginx/$_x")"; done)
    # shellcheck disable=SC2086  # a list of files
    pairs nginx ssl_certificate ssl_certificate_key "$(P /etc/nginx/nginx.conf)" "$(P /etc/nginx/sites-enabled)"/* "$(P /etc/nginx/conf.d)"/*.conf $_sn
    pairs dovecot ssl_cert ssl_key "$(P /etc/dovecot/dovecot.conf)" "$(P /etc/dovecot/conf.d)"/*.conf
    pairs dovecot ssl_server_cert_file ssl_server_key_file "$(P /etc/dovecot/dovecot.conf)" "$(P /etc/dovecot/conf.d)"/*.conf
    pairs postfix smtpd_tls_cert_file smtpd_tls_key_file "$(P /etc/postfix/main.cf)"
    pairs vsftpd rsa_cert_file rsa_private_key_file "$(P /etc/vsftpd.conf)" "$(P /etc/vsftpd/vsftpd.conf)"
    pairs mysql ssl-cert ssl-key "$(P /etc/mysql/my.cnf)" "$(P /etc/mysql/mariadb.conf.d)"/*.cnf "$(P /etc/mysql/mysql.conf.d)"/*.cnf "$(P /etc/my.cnf)" "$(P /etc/my.cnf.d)"/*.cnf
    pairs mysql ssl_cert ssl_key "$(P /etc/mysql/my.cnf)" "$(P /etc/mysql/mariadb.conf.d)"/*.cnf "$(P /etc/mysql/mysql.conf.d)"/*.cnf "$(P /etc/my.cnf)" "$(P /etc/my.cnf.d)"/*.cnf
} | grep -v '|\$' | sort -u >"$W/pairs"
# one line per cert|key with every service that uses it
awk -F'|' '{ k = $3 "|" $4; if (!(k in s)) { o[++n] = k; s[k] = $1 } else if (index("," s[k] ",", "," $1 ",") == 0) s[k] = s[k] "," $1 }
    END { for (i = 1; i <= n; i++) print s[o[i]] "|" o[i] }' "$W/pairs" >"$W/certs"
# Debian's default snakeoil pair counts too when a service uses no explicit one.
[ -s "$W/certs" ] || { [ -f "$(P /etc/ssl/certs/ssl-cert-snakeoil.pem)" ] && printf 'default|/etc/ssl/certs/ssl-cert-snakeoil.pem|/etc/ssl/private/ssl-cert-snakeoil.key\n' >"$W/certs"; }
fp() { openssl x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//'; }
printf '%-16s %-44s %-22s %-26s %-6s %-10s %s\n' service certificate "name (CN)" "ends" bits signature notes >"$CC_RUN_DIR/certs.txt"
NCERT=0
while IFS='|' read -r _svc _c _k; do
    NCERT=$((NCERT + 1)); _rc=$(P "$_c"); _rk=$(P "$_k")
    cc_show "" ""
    cc_show "$C_CYN" "  $_c  (used by $_svc)"
    if [ ! -r "$_rc" ]; then finding HIGH "$_svc" "the certificate file is missing: $_c - the service will not start" new "$_c|$_k|$_svc" n; printf '%-16s %-44s missing\n' "$_svc" "$_c" >>"$CC_RUN_DIR/certs.txt"; continue; fi
    _txt=$(openssl x509 -in "$_rc" -noout -text 2>/dev/null)
    [ -n "$_txt" ] || { finding HIGH "$_svc" "not a certificate openssl can read: $_c" new "$_c|$_k|$_svc" l; continue; }
    _cn=$(openssl x509 -in "$_rc" -noout -subject 2>/dev/null | sed -n 's/.*CN *= *\([^,/]*\).*/\1/p')
    _sub=$(openssl x509 -in "$_rc" -noout -subject 2>/dev/null | sed 's/^subject= *//'); _iss=$(openssl x509 -in "$_rc" -noout -issuer 2>/dev/null | sed 's/^issuer= *//')
    _end=$(openssl x509 -in "$_rc" -noout -enddate 2>/dev/null | sed 's/^notAfter=//')
    _bits=$(printf '%s\n' "$_txt" | sed -n 's/.*Public-Key: (\([0-9]*\) bit).*/\1/p' | head -n 1)
    _alg=$(printf '%s\n' "$_txt" | sed -n 's/^ *Signature Algorithm: *//p' | head -n 1)
    _self=n; [ "$_sub" = "$_iss" ] && _self=y
    _ec=n; printf '%s' "$_txt" | grep -q 'id-ecPublicKey\|ED25519\|ED448' && _ec=y
    _notes=""; _dflt=l; [ "$_self" = y ] && { _dflt=n; _notes="self-signed "; }
    cc_show "" "    name $_cn | ends $_end | ${_bits:-?} bit | $_alg$([ "$_self" = y ] && echo ' | self-signed') | issuer $_iss"
    if ! openssl x509 -in "$_rc" -noout -checkend 0 >/dev/null 2>&1; then
        finding HIGH "$_svc" "EXPIRED on $_end: clients and scoring checks that verify it fail" new "$_c|$_k|$_svc" "$_dflt"; _notes="${_notes}EXPIRED "
    elif ! openssl x509 -in "$_rc" -noout -checkend $((DAYS * 86400)) >/dev/null 2>&1; then
        finding MED "$_svc" "ends within $DAYS days ($_end)" new "$_c|$_k|$_svc" "$_dflt"; _notes="${_notes}ends-soon "
    else cc_show "$C_GRN" "    [ok] valid until $_end"; fi
    if [ "$_ec" = n ] && [ -n "$_bits" ] && [ "$_bits" -lt 2048 ]; then finding MED "$_svc" "weak key: $_bits bit RSA (2048 or more)" new "$_c|$_k|$_svc" "$_dflt"; _notes="${_notes}weak-key "; fi
    case "$_alg" in *[Ss][Hh][Aa]1[Ww]*|*[Mm][Dd]5*|*-[Ss][Hh][Aa]1*) finding MED "$_svc" "weak signature: $_alg" new "$_c|$_k|$_svc" "$_dflt"; _notes="${_notes}weak-signature " ;; esac
    # the key
    if [ ! -e "$_rk" ]; then finding HIGH "$_svc" "the key file is missing: $_k - the service will not start" new "$_c|$_k|$_svc" "$_dflt"; _notes="${_notes}no-key "
    else
        _cpk=$(openssl x509 -in "$_rc" -noout -pubkey 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | cksum)
        _kpk=$(openssl pkey -in "$_rk" -passin pass: -pubout -outform DER 2>/dev/null | cksum)
        if [ ! -r "$_rk" ]; then finding MED "$_svc" "cannot read the key $_k (run as root to check it)" "" "" ""
        elif [ -z "$_kpk" ] || [ "$_kpk" = "$(printf '' | cksum)" ]; then finding MED "$_svc" "the key $_k cannot be read without a passphrase (or is not a key)" "" "" ""
        elif [ "$_cpk" != "$_kpk" ]; then finding HIGH "$_svc" "the certificate does NOT match its key $_k: TLS fails (a swapped certificate or key?)" new "$_c|$_k|$_svc" "$_dflt"; _notes="${_notes}KEY-MISMATCH "
        else cc_show "$C_GRN" "    [ok] matches its key $_k"; fi
        # who can read the key
        _ls=$(ls -lnL "$_rk" 2>/dev/null); _mode=$(printf '%s' "$_ls" | cut -c1-10); _ouid=$(printf '%s' "$_ls" | awk '{ print $3 }'); _ogid=$(printf '%s' "$_ls" | awk '{ print $4 }')
        _gname=$(awk -F: -v g="$_ogid" '$3 == g { print $1; exit }' "$(P /etc/group)" 2>/dev/null)
        case "$_mode" in
            ???????r??|????????w?) finding HIGH "$_svc" "the private key $_k can be read by every user ($_mode): anyone can decrypt or impersonate the site" perm "$_k" f ;;
            ????r?????) case "$_gname" in root|ssl-cert|ssl|mail|dovecot|postfix|www-data|nginx|apache|mysql|"") ;; *) finding MED "$_svc" "the private key $_k can be read by the group $_gname ($_mode)" perm "$_k" f ;; esac ;;
        esac
        _on=$(awk -F: -v u="$_ouid" '$3 == u { print $1; exit }' "$(P /etc/passwd)" 2>/dev/null)
        # MariaDB reads its key as the mysql user: that owner is right there.
        case "$_ouid:$_on:$_svc" in 0:*|:*|*:mysql:*mysql*) ;; *) finding MED "$_svc" "the private key $_k belongs to ${_on:-uid $_ouid}, not root" "" "" "" ;; esac
    fi
    printf '%-16s %-44s %-22s %-26s %-6s %-10s %s\n' "$_svc" "$_c" "${_cn:--}" "$_end" "${_bits:-?}" "$(printf '%s' "$_alg" | cut -c1-10)" "${_notes:-ok}" >>"$CC_RUN_DIR/certs.txt"
    printf '%s|%s|%s\n' "$_c" "$(fp "$_rc")" "$_svc" >>"$W/fps"
done <"$W/certs"
[ "$NCERT" -eq 0 ] && cc_show "$C_GRY" "  No certificate named in the Apache, nginx, Dovecot, Postfix, vsftpd or MariaDB configs."

# ---- 2. What the ports serve ----------------------------------------------------------------------
header "2/5  what each TLS port serves"
printf '%-6s %-6s %-16s %-10s %-9s %-8s %s\n' port kind program "TLS1.0/1.1" "weak-ciph" matches certificate >"$CC_RUN_DIR/served.txt"
: >"$W/ports"
if [ "$PROBE" = 1 ]; then
    if [ -z "$R" ]; then
        ss -ltnpH 2>/dev/null | awk '{ a = $4; sub(/.*:/, "", a); p = "-"; if (match($0, /\(\("[^"]+"/)) p = substr($0, RSTART + 3, RLENGTH - 4); print a "|" p }' | sort -t'|' -k1,1n -u | while IFS='|' read -r _p _prog; do
            case "$_p" in 443|8443|993|995|465|636|989|990|5986|8089) printf '%s|tls|%s\n' "$_p" "$_prog" ;; 25|587) printf '%s|smtp|%s\n' "$_p" "$_prog" ;; 143) printf '%s|imap|%s\n' "$_p" "$_prog" ;;
                110) printf '%s|pop3|%s\n' "$_p" "$_prog" ;; 21) printf '%s|ftp|%s\n' "$_p" "$_prog" ;; 3306) printf '%s|mysql|%s\n' "$_p" "$_prog" ;; esac
        done >>"$W/ports"
    fi
    printf '%s' "$EXTRA" | while IFS=: read -r _p _k _sv; do [ -n "$_p" ] && printf '%s|%s|%s\n' "$_p" "${_k:-tls}" "${_sv:--}"; done >>"$W/ports"
fi
# probe PORT KIND [s_client options] -> s_client output; 0 when a handshake happened
probe() {
    _pp=$1; _pk=$2; shift 2
    _st=""; [ "$_pk" = tls ] || _st="-starttls $_pk"
    # shellcheck disable=SC2086  # $TO and $_st are words on purpose
    $TO openssl s_client -connect "$PHOST:$_pp" -servername "$PHOST" $_st "$@" </dev/null >"$W/probe" 2>&1
    grep -q 'Cipher is [A-Z0-9]' "$W/probe" && ! grep -q 'Cipher is (NONE)' "$W/probe"
}
NPORT=0; : >"$W/fixtls"
while IFS='|' read -r _p _k _prog; do
    [ -n "$_p" ] || continue
    if ! probe "$_p" "$_k"; then
        case "$_k" in imap|pop3|ftp) finding MED "port $_p ($_prog)" "$_k without TLS: passwords cross the network in clear text (turn on STARTTLS)" "" "" "" ;; *) cc_show "$C_GRY" "  port $_p ($_k, $_prog): no TLS handshake" ;; esac
        printf '%-6s %-6s %-16s no TLS handshake\n' "$_p" "$_k" "$_prog" >>"$CC_RUN_DIR/served.txt"; continue; fi
    NPORT=$((NPORT + 1))
    _sfp=$(openssl x509 -in "$W/probe" -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//')
    _scn=$(openssl x509 -in "$W/probe" -noout -subject 2>/dev/null | sed -n 's/.*CN *= *\([^,/]*\).*/\1/p')
    _send=$(openssl x509 -in "$W/probe" -noout -enddate 2>/dev/null | sed 's/^notAfter=//')
    _file=$(awk -F'|' -v f="$_sfp" '$2 == f { printf "%s%s", (n++ ? ", " : ""), $1 }' "$W/fps" 2>/dev/null)
    _old=n; probe "$_p" "$_k" -tls1 -cipher 'DEFAULT@SECLEVEL=0' && _old=y
    [ "$_old" = n ] && probe "$_p" "$_k" -tls1_1 -cipher 'DEFAULT@SECLEVEL=0' && _old=y
    _weak=n; probe "$_p" "$_k" -tls1_2 -cipher 'RC4:3DES:DES:NULL:EXPORT:aNULL:eNULL:MD5@SECLEVEL=0' && _weak=y
    cc_show "$C_CYN" "  port $_p ($_k, $_prog): serves $_scn, ends $_send"
    printf '%-6s %-6s %-16s %-10s %-9s %-8s %s\n' "$_p" "$_k" "$_prog" "$_old" "$_weak" "$([ -n "$_file" ] && echo yes || echo NO)" "${_file:-$_scn}" >>"$CC_RUN_DIR/served.txt"
    _svc=$(case "$_prog" in apache2|httpd) echo apache2 ;; postfix) echo postfix ;; nginx) echo nginx ;; dovecot|imap-login|pop3-login) echo dovecot ;; master|smtpd) echo postfix ;; *) echo "" ;; esac)
    if [ -z "$_file" ] && [ -s "$W/fps" ]; then finding MED "port $_p" "serves a certificate ($_scn) that is not in any config file read above - another program or a swapped file?" "" "" ""
    elif [ -n "$_file" ]; then cc_show "$C_GRN" "    [ok] the certificate from $_file"; fi
    if [ "$_old" = y ] || [ "$_weak" = y ]; then
        _what=""; [ "$_old" = y ] && _what="TLS 1.0/1.1"; [ "$_weak" = y ] && _what="${_what:+$_what and }weak ciphers (RC4/3DES/NULL/anonymous)"
        if [ -n "$_svc" ] && ! grep -q "^$_svc|" "$W/fixtls"; then printf '%s|%s\n' "$_svc" "$_p" >>"$W/fixtls"; finding MED "port $_p ($_svc)" "still takes $_what" tls "$_svc|$_p" f
        else finding MED "port $_p ($_prog)" "still takes $_what - fix it in that program's config" "" "" ""; fi
    else cc_show "$C_GRN" "    [ok] TLS 1.2+ only, no weak ciphers"; fi
done <"$W/ports"
[ "$PROBE" = 1 ] && [ ! -s "$W/ports" ] && cc_show "$C_GRY" "  No TLS port is listening here."
[ "$PROBE" = 0 ] && cc_show "$C_GRY" "  Not probed (--no-probe)."

# ---- 3. Baseline ------------------------------------------------------------------------------------
header "3/5  changes since the baseline"
BASE="$CC_OUT/tls-baseline-$CC_HOST.txt"
if [ ! -s "$W/fps" ]; then cc_show "$C_GRY" "  No certificate to compare."
elif [ ! -f "$BASE" ]; then
    cut -d'|' -f1,2 "$W/fps" >"$BASE"; cc_show "$C_GRN" "  [ok] first run: fingerprints saved as the baseline ($BASE)"
else
    while IFS='|' read -r _c _f _svc; do
        _b=$(awk -F'|' -v c="$_c" '$1 == c { print $2; exit }' "$BASE")
        if [ -z "$_b" ]; then cc_show "$C_YEL" "  [*] new since the baseline (added to it): $_c"; printf '%s|%s\n' "$_c" "$_f" >>"$BASE"
        elif [ "$_b" != "$_f" ]; then finding HIGH "$_svc" "$_c CHANGED since the baseline (was ${_b%"${_b#???????????}"}..., now ${_f%"${_f#???????????}"}...): if your team did not change it, put back your backup copy" base "$_c|$_f" k
        else cc_show "$C_GRN" "  [ok] unchanged: $_c"; fi
    done <"$W/fps"
fi

# ---- 4. Questions and changes ---------------------------------------------------------------------
header "4/5  fixes"
: >"$W/plan"
while IFS="$US" read -r _lv _svc _what _fix _tg _d; do
    [ -n "$_fix" ] || continue
    _ak="$_fix ${_tg%%"|"*}"; grep -qxF "$_ak" "$W/asked" 2>/dev/null && continue
    printf '%s\n' "$_ak" >>"$W/asked"
    case "$_fix" in
        perm) cc_choose "$_svc: $_what. What now?" "$_d" "f=fix it: only the owner (and a service group) can read it (chmod 600 / 640)" "l=leave it" ;;
        new)  # every problem of this certificate in one question
              _what=$(awk -F"$US" -v c="${_tg%%"|"*}" '$4 == "new" && index($5, c "|") == 1 { printf "%s%s", (n++ ? "; " : ""), $3 }' "$W/find")
              cc_choose "$_svc, ${_tg%%"|"*}: $_what. What now?" "$_d" "n=new self-signed certificate and key (same name, 1 year; the old pair is backed up)" "l=leave it" ;;
        tls)  cc_choose "$_svc: $_what. What now?" "$_d" "f=fix the config: TLS 1.2 and 1.3 only, strong ciphers (tested, reloaded, put back if the port stops answering)" "l=leave it" ;;
        base) cc_choose "$_svc: $_what. What now?" "$_d" "k=keep flagging it (the baseline stays)" "u=use it as the new baseline (your team changed it)" ;;
    esac
    case "$CC_CHOICE" in f|n|u) printf '%s\037%s\037%s\n' "$_fix" "$_tg" "$_svc" >>"$W/plan" ;; esac
done <"$W/find"
plan_word() { case "$1" in perm) echo "only the owner can read $2" ;; new) echo "new self-signed certificate ${2%%"|"*}" ;; tls) echo "TLS 1.2+ and strong ciphers for ${2%%"|"*}" ;; base) echo "new baseline for ${2%%"|"*}" ;; esac; }
NCH=$(grep -c . "$W/plan")
while IFS="$US" read -r _fix _tg _svc; do cc_show "$C_YEL" "  [~] $(plan_word "$_fix" "$_tg")"; done <"$W/plan"
[ "$NCH" -eq 0 ] && cc_show "$C_GRN" "  [ok] Nothing to change."

# set_kv FILE STYLE KEY VALUE -> replace KEY's value in FILE (0: found)
# STYLE: sp "Key value" | ng "key value;" | eq "key = value"
set_kv() {
    awk -v st="$2" -v k="$3" -v v="$4" '
        { l = $0; sub(/^[ \t]+/, "", l); n = split(l, w, /[ \t=]+/) }
        n > 0 && tolower(w[1]) == tolower(k) && l !~ /^[#;]/ { i = $0; sub(/[^ \t].*$/, "", i)
            if (st == "sp") $0 = i k " " v; else if (st == "ng") $0 = i k " " v ";"; else $0 = i k " = " v; hit = 1 }
        { print } END { exit hit ? 0 : 1 }' "$1" >"$1.bt" && { cat "$1.bt" >"$1"; rm -f "$1.bt"; return 0; }
    rm -f "$1.bt"; return 1
}
# add_after FILE ANCHOR-KEY LINE -> put LINE (indented like the anchor) after each anchor line
add_after() {
    awk -v a="$2" -v t="$3" '{ print; l = $0; sub(/^[ \t]+/, "", l); n = split(l, w, /[ \t=]+/)
        if (n > 0 && tolower(w[1]) == tolower(a) && l !~ /^[#;]/) { i = $0; sub(/[^ \t].*$/, "", i); print i t } }' "$1" >"$1.bt" && cat "$1.bt" >"$1"; rm -f "$1.bt"
}
# put_kv KEY VALUE ANCHOR -> set KEY in the files of $W/tf (style $_st)
put_kv() {
    _hit=0; while IFS= read -r _f; do set_kv "$_f" "$_st" "$1" "$2" && _hit=1; done <"$W/tf"
    [ "$_hit" = 1 ] && return 0
    case "$_st" in sp) _line="$1 $2" ;; ng) _line="$1 $2;" ;; *) _line="$1 = $2" ;; esac
    while IFS= read -r _f; do add_after "$_f" "$3" "$_line"; done <"$W/tf"
}
conf_files() { awk -F'|' -v s="$1" '$1 == s { print $2 }' "$W/pairs" | sort -u; }
svc_test() {
    [ -z "$R" ] || return 0
    case "$1" in
        apache2) _x=$(cc_first apache2ctl apachectl) && "$_x" -t ;; nginx) nginx -t ;; dovecot) doveconf -n >/dev/null ;; postfix) postfix check ;;
    esac >>"$CC_LOG" 2>&1
}
svc_reload() {
    [ -z "$R" ] || return 0
    for _u in $(case "$1" in apache2) echo "apache2 httpd" ;; mysql) echo "mariadb mysql" ;; *) echo "$1" ;; esac); do
        if [ "$CC_INIT" = systemd ]; then systemctl is-active -q "$_u" 2>/dev/null || continue; systemctl reload-or-restart "$_u" </dev/null
        else [ -x "/etc/init.d/$_u" ] || continue; service "$_u" reload </dev/null || service "$_u" restart </dev/null; fi
        return
    done
}
svc_reload_cmd() { [ -z "$R" ] || { printf ':'; return; }; printf 'for u in %s; do if [ -d /run/systemd/system ]; then systemctl try-reload-or-restart "$u" 2>/dev/null; elif [ -x "/etc/init.d/$u" ]; then service "$u" reload || service "$u" restart; fi; done' "$(case "$1" in apache2) echo "apache2 httpd" ;; mysql) echo "mariadb mysql" ;; *) echo "$1" ;; esac)"; }

NOK=0; NBAD=0; APPLIED=0
if [ "$NCH" -eq 0 ]; then :
elif [ "$CC_APPLY" != 1 ] || { [ -z "$R" ] && ! cc_is_root; }; then
    [ -z "$R" ] && ! cc_is_root && cc_show "$C_YEL" "  [!] not root: showing the plan only"
    cc_show "$C_GRY" "  Dry run: nothing was changed. Run again with --apply."
    # shellcheck disable=SC2034  # read by cc_finish
    CC_N_WOULD=$NCH
elif cc_ask "Apply these $NCH change(s)?" Y "yes, apply them" "no, change nothing"; then
    APPLIED=1
    while IFS="$US" read -r _fix _tg _svc; do
        _ok=1
        case "$_fix" in
            perm)
                _rk=$(P "$_tg")
                if cc_guard path "$_tg"; then
                    _om=$(stat -c %a "$_rk" 2>/dev/null) || _om=600
                    # keep the group's read when the group is a service's (ssl-cert, mysql...)
                    _gn=$(awk -F: -v g="$(ls -lnL "$_rk" | awk '{ print $4 }')" '$3 == g { print $1; exit }' "$(P /etc/group)" 2>/dev/null)
                    _nm=600; case "$_gn" in ssl-cert|ssl|mail|dovecot|postfix|www-data|nginx|apache|mysql) _nm=640 ;; esac
                    chmod "$_nm" "$_rk" && cc_undo_add "mode $_om back on $_tg" "chmod $_om $(cc_shquote "$_rk")" || _ok=0
                else _ok=0; fi ;;
            new)
                _c=${_tg%%"|"*}; _k=${_tg#*"|"}; _k=${_k%%"|"*}; _rc=$(real "$(P "$_c")"); _rk=$(real "$(P "$_k")")
                _cn=$(openssl x509 -in "$_rc" -noout -subject 2>/dev/null | sed -n 's/.*CN *= *\([^,/]*\).*/\1/p'); [ -n "$_cn" ] || _cn=$CC_HOST
                _cn=$(printf '%s' "$_cn" | tr -cd 'A-Za-z0-9.*-')
                if cc_guard path "$_c" && cc_guard path "$_k"; then
                    for _s in $(printf '%s' "$_svc" | tr ',' ' '); do cc_undo_add "reload $_s" "$(svc_reload_cmd "$_s")"; done
                    [ -f "$_rc" ] && cc_backup_file "$_rc" >/dev/null; [ "$_rk" != "$_rc" ] && [ -f "$_rk" ] && cc_backup_file "$_rk" >/dev/null
                    [ -f "$_rc" ] || cc_undo_add "remove the new $_c" "rm -f $(cc_shquote "$_rc")"
                    [ -f "$_rk" ] || cc_undo_add "remove the new $_k" "rm -f $(cc_shquote "$_rk")"
                    mkdir -p "$(dirname "$_rc")" "$(dirname "$_rk")"
                    _san="DNS:$_cn"; [ "$_cn" != "$CC_HOST" ] && _san="$_san,DNS:$CC_HOST"
                    # -addext needs OpenSSL 1.1.1; older ones get no SAN
                    if (umask 077; openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 365 -keyout "$W/new.key" -out "$W/new.crt" -subj "/CN=$_cn" -addext "subjectAltName=$_san" >>"$CC_LOG" 2>&1 ||
                        openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 365 -keyout "$W/new.key" -out "$W/new.crt" -subj "/CN=$_cn" >>"$CC_LOG" 2>&1); then
                        if [ "$_rk" = "$_rc" ]; then cat "$W/new.crt" "$W/new.key" >"$_rc"; chmod 600 "$_rc"
                        else cat "$W/new.crt" >"$_rc"; chmod 644 "$_rc"; cat "$W/new.key" >"$_rk"; chmod 600 "$_rk"; fi
                        rm -f "$W/new.key" "$W/new.crt"
                        # our own change: the baseline follows it (no false "CHANGED" next run)
                        [ -f "$BASE" ] && { _nf=$(fp "$_rc"); awk -F'|' -v c="$_c" -v f="$_nf" 'BEGIN { OFS = "|" } $1 == c { $2 = f } { print }' "$BASE" >"$BASE.n" && cat "$BASE.n" >"$BASE"; rm -f "$BASE.n"; }
                        for _s in $(printf '%s' "$_svc" | tr ',' ' '); do svc_reload "$_s" >>"$CC_LOG" 2>&1; done
                        cc_show "$C_YEL" "    [*] a self-signed certificate: browsers warn; tell the team (and the scoring contact if they verify certificates)"
                    else _ok=0; fi
                else _ok=0; fi ;;
            tls)
                _s=${_tg%%"|"*}; _p=${_tg#*"|"}; _kind=tls
                _p2=$(awk -F'|' -v p="$_p" '$1 == p { print $2; exit }' "$W/ports"); [ -n "$_p2" ] && _kind=$_p2
                cc_undo_add "reload $_s" "$(svc_reload_cmd "$_s")"
                _files=$(conf_files "$_s"); [ "$_s" = nginx ] && _files="$_files$NL/etc/nginx/nginx.conf"
                [ -n "$_files" ] || { _ok=0; cc_show "$C_RED" "    [x] no config file of $_s known"; }
                printf '%s\n' "$_files" | sort -u | grep . | while IFS= read -r _f; do _f=$(real "$(P "$_f")"); [ -f "$_f" ] && printf '%s\n' "$_f"; done | sort -u >"$W/tf"
                while IFS= read -r _f; do cc_backup_file "$_f" >/dev/null; done <"$W/tf"
                case "$_s" in
                    apache2) _st=sp; set -- SSLProtocol "all -SSLv3 -TLSv1 -TLSv1.1" SSLCipherSuite "HIGH:!aNULL:!MD5:!3DES:!RC4" SSLCertificateFile ;;
                    nginx)   _st=ng; set -- ssl_protocols "TLSv1.2 TLSv1.3" ssl_ciphers "HIGH:!aNULL:!MD5:!3DES:!RC4" ssl_certificate ;;
                    dovecot) _st=eq; _an=ssl_cert; while IFS= read -r _f; do grep -q '^[[:space:]]*ssl_server_cert_file' "$_f" && _an=ssl_server_cert_file; done <"$W/tf"
                             set -- ssl_min_protocol "TLSv1.2" ssl_cipher_list "HIGH:!aNULL:!MD5:!3DES:!RC4" "$_an" ;;
                    postfix) _st=eq; set -- smtpd_tls_protocols "!SSLv2, !SSLv3, !TLSv1, !TLSv1.1" smtpd_tls_mandatory_protocols "!SSLv2, !SSLv3, !TLSv1, !TLSv1.1" smtpd_tls_cert_file ;;
                esac
                # Each setting: replace it where it is; nowhere -> add it after the certificate line.
                put_kv "$1" "$2" "$5"; put_kv "$3" "$4" "$5"
                if [ "$_s" = postfix ]; then
                    _mf=$(P /etc/postfix/main.cf)
                    set_kv "$_mf" eq smtpd_tls_exclude_ciphers "aNULL, MD5, 3DES, RC4" || printf 'smtpd_tls_exclude_ciphers = aNULL, MD5, 3DES, RC4\n' >>"$_mf"
                fi
                if ! svc_test "$_s"; then
                    cc_show "$C_RED" "    [x] $_s refuses the new config: put back"; _ok=0
                    while IFS= read -r _f; do _b="$CC_BACKUP_DIR$(cc_abspath "$_f")"; [ -f "$_b" ] && cat "$_b" >"$_f"; done <"$W/tf"
                else
                    svc_reload "$_s" >>"$CC_LOG" 2>&1
                    if [ -z "$R" ]; then
                        sleep 2
                        if ! probe "$_p" "$_kind" -tls1_2; then
                            cc_show "$C_RED" "    [x] port $_p stopped answering TLS 1.2: put back"; _ok=0
                            while IFS= read -r _f; do _b="$CC_BACKUP_DIR$(cc_abspath "$_f")"; [ -f "$_b" ] && cat "$_b" >"$_f"; done <"$W/tf"
                            svc_reload "$_s" >>"$CC_LOG" 2>&1
                        elif probe "$_p" "$_kind" -tls1 -cipher 'DEFAULT@SECLEVEL=0'; then cc_show "$C_YEL" "    [*] port $_p still takes TLS 1.0: a setting elsewhere wins (look for another $_s TLS line)"; fi
                    fi
                fi ;;
            base)
                _c=${_tg%%"|"*}; _f=${_tg#*"|"}
                cc_backup_file "$BASE" >/dev/null
                awk -F'|' -v c="$_c" -v f="$_f" 'BEGIN { OFS = "|" } $1 == c { $2 = f } { print }' "$BASE" >"$BASE.n" && cat "$BASE.n" >"$BASE"; rm -f "$BASE.n" ;;
        esac
        if [ "$_ok" = 1 ]; then NOK=$((NOK + 1)); cc_show "$C_GRN" "  [+] $(plan_word "$_fix" "$_tg")"; else NBAD=$((NBAD + 1)); cc_show "$C_RED" "  [x] $(plan_word "$_fix" "$_tg") FAILED"; fi
    done <"$W/plan"
else cc_show "$C_GRY" "  Not applied."; fi
# shellcheck disable=SC2034  # read by cc_finish
CC_N_DONE=$NOK
# shellcheck disable=SC2034  # read by cc_finish
CC_N_FAIL=$NBAD

# ---- 5. Summary ------------------------------------------------------------------------------------
header "5/5  summary"
awk -F"$US" '{ printf "%-4s %-22s %s\n", $1, $2, $3 }' "$W/find" >"$CC_RUN_DIR/findings.txt"
NH=$(grep -c "^HIGH$US" "$W/find"); NM=$(grep -c "^MED$US" "$W/find")
{
    printf '==========[ summary ]==========\n'
    printf 'SV-32 TLS certificate check | host %s | %s\n' "$CC_HOST" "$([ "$APPLIED" = 1 ] && echo APPLIED || echo 'DRY RUN - nothing changed')"
    printf 'Certificates: %d   TLS ports: %d   Fix now [!]: %d   Look at [*]: %d\n' "$NCERT" "$NPORT" "$NH" "$NM"
    [ -s "$W/plan" ] && { printf 'Changes%s:\n' "$([ "$APPLIED" = 1 ] || echo ' planned')"; while IFS="$US" read -r _fix _tg _svc; do printf '  %s\n' "$(plan_word "$_fix" "$_tg")"; done <"$W/plan"; }
    [ "$APPLIED" = 1 ] && printf 'Done: %d   Failed: %d\n' "$NOK" "$NBAD"
    printf 'Tables: certs.txt (each certificate), served.txt (each port), findings.txt\n'
} >"$CC_RUN_DIR/summary.txt"
while IFS= read -r _l; do case "$_l" in ==*|SV-32*) cc_show "$C_CYN" "$_l" ;; *'Failed: '[1-9]*) cc_show "$C_RED" "$_l" ;; *) cc_show "" "$_l" ;; esac; done <"$CC_RUN_DIR/summary.txt"
rm -rf "$W"
cc_finish
