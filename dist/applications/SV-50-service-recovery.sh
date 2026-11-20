#!/bin/sh
# =============================================================================
# ID:       SV-50
# NAME:     Service recovery (find out why a service is down, bring it back)
# ROLE:     Applications  (any time a scored service goes red)
# KIND:     changes - dry run unless --apply
# VERSION:  1.1.0
#
# PURPOSE
#   When a scored service goes down, restarting it often fails: red team
#   broke something under it.  This checks every service on the box the same
#   way, finds the reason, and offers the fix:
#
#     web (apache2, httpd, nginx), php-fpm, database (mariadb, mysql,
#     postgresql), mail (dovecot, postfix), splunk, ssh, time (chrony, ntp),
#     file shares (Samba, NFS), Gitea (or Forgejo; its port from app.ini)
#
#   For each one that is installed:
#     1  running?          stopped / failed / masked / disabled at boot
#     2  config loads?     apache2ctl -t, nginx -t, php-fpm -t, postfix
#                          check, doveconf, sshd -t (errors shown); a service
#                          is never restarted on a config that fails
#     3  port?             listening; or ANOTHER program holds the port
#     4  answers?          tested the way scoring does: HTTP status, IMAP /
#                          SMTP / SSH banner, database ping, chrony tracking
#     5  firewall?         iptables DROP/REJECT rules on the service's port
#                          (nftables: shown); on Rocky/Fedora a port that
#                          firewalld does not allow, on Ubuntu/Mint one ufw
#                          does not allow
#     6  tampered?         config files changed in the last 2 hours,
#                          systemd drop-ins (ExecStart=/bin/true), package
#                          files that no longer match (dpkg -V / rpm -V)
#   Services start through systemd, OpenRC (Alpine: rc-service, "starts at
#   boot" from rc-update) or SysV.
#   And once for the box: disk or inodes full, /tmp not writable, programs
#   killed for lack of memory.
#
#   Fixes offered (each asked, yes/no): unmask, enable at boot, remove a
#   firewall rule that blocks the port (or open it in firewalld / ufw), stop the program holding the port,
#   start / restart (only after the config test passes).  Each fixed service
#   is tested again.  Reported, never changed: config errors, changed files,
#   a full disk - with what to do.  Defaced or wiped site: SV-15 --restore.
#
#   --watch checks every N seconds and prints a line the moment a service
#   goes down or comes back (and why); with --auto-restart it also restarts
#   a service that went down, if its config test passes (at most 3 times in
#   10 minutes each, so a crash loop is not hidden).
#
#   No revert timer: these fixes bring services UP; undoing them would take
#   them down again.  Each change still has an undo line (revert.sh).
#
#   QUESTIONS (Enter takes the default in capitals; a flag answers each):
#     which box                       --box NAME
#     which services                  --services a,b (Enter = all found)
#     each fix (yes / no)             --fix KINDS (always yes for these kinds)
#
# USAGE
#   sudo sh SV-50-service-recovery.sh                       check all, dry run
#   sudo sh SV-50-service-recovery.sh --apply               check and fix (asks)
#   sudo sh SV-50-service-recovery.sh --apply --batch --services web,mysql
#   sudo sh SV-50-service-recovery.sh --watch 30 --auto-restart --apply
#
# OPTIONS
#   --apply            make the fixes (without it, dry run only)
#   --box NAME         splunk | webmail | ecomm | fileshare | gitea | web |
#                      other (asked)
#   --services a,b     only these: web php-fpm mysql postgres imap smtp splunk
#                      ssh ntp smb nfs gitea, or unit names (apache2, nginx ...)
#   --fix KINDS        answer yes for these fix kinds: unmask enable firewall
#                      kill start (default: each asked; --batch takes the
#                      default shown)
#   --watch SECONDS    keep checking; print changes (Ctrl-C to stop)
#   --auto-restart     with --watch and --apply: restart what goes down
#   --watch-count N    with --watch: stop after N rounds (tests)
#   --no-color         no colours
#   --help             this text plus the common options
#
# OUTPUTS  (under --out, in recovery-N/)
#   output.txt   everything shown on screen, no colour
#   status.txt   each service: running, config, port, answer, problems
#   summary.txt, run.txt, revert.sh;  watch.txt with --watch
#
# DEPENDS ON
#   ss (or netstat / busybox netstat), systemctl, OpenRC or service; curl or wget; nc or openssl (banners);
#   iptables, firewall-cmd, ufw (firewall check); testparm, smbclient,
#   showmount when there.  BT_SVC_DIRS (tests) adds folders of stand-in init
#   scripts; BT_SVC_INIT names the init system, BT_TEST_RUNLEVELS OpenRC's
#   runlevel folder.
#
# TESTED ON
#   Ubuntu 24.04 (SysV init in a container) with Apache, MariaDB,
#   PostgreSQL, Dovecot, Postfix, OpenSSH and chrony, under dash, bash,
#   busybox sh, ksh93, mksh and yash: a stopped Apache, a DROP rule on 80,
#   a program holding port 80 and a broken Apache config were each found;
#   the first three fixed, the broken config reported and Apache left alone.
#   Stand-ins (no real service touched): Gitea (python's web server under
#   that name), a stopped Samba, firewalld and ufw that block the port, and
#   OpenRC (runlevels, rc-update) - found, fixed, undo lines written.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - "Up" here means it answers on this box.  If scoring still fails, check
#     the router/firewall between (NW scripts) and the scoring IP.
#   - A defaced or wiped site answers 200: use SV-15 --check for content.
#   - nftables rules are shown, not removed.
#
# DEBUGGING
#   --debug shows each command.  status.txt holds every check's result.
# =============================================================================

# >>> BT-LIB  (lib/lib.sh 0.4.0 pasted in by tools/build.sh - edit lib/lib.sh, not this copy)
# =============================================================================
# ID:       LB-01
# NAME:     Shell library (lib.sh)
# ROLE:     Automation  (wave 0, foundation)
# VERSION:  0.4.0
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
CC_LIB_VERSION="0.4.0"

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
SV-50 Service recovery - why is a service down, and bring it back
  sudo sh SV-50-service-recovery.sh                     check all, dry run
  sudo sh SV-50-service-recovery.sh --apply             check and fix (asks)
  sudo sh SV-50-service-recovery.sh --watch 30 --auto-restart --apply

  --apply            make the fixes (without it, dry run only)
  --box NAME         splunk | webmail | ecomm | fileshare | gitea | web | other
  --services a,b     web php-fpm mysql postgres imap smtp splunk ssh ntp smb nfs gitea, or unit names
  --fix KINDS        yes for these fix kinds: unmask enable firewall kill start
  --watch SECONDS    keep checking, print changes (Ctrl-C to stop)
  --auto-restart     with --watch and --apply: restart what goes down
  --watch-count N    with --watch: stop after N rounds
  --no-color         no colours
  --help             show this text
USAGE
    cc_usage_common
}

BOX=""; ONLY=""; FIXK=""; WATCH=""; AUTOR=0; WCOUNT=0; COLOR=1
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --apply)        CC_APPLY=1; shift ;;
        --box)          [ $# -ge 2 ] || cc_die 2 "--box needs a name"; BOX=$2; shift 2 ;;
        --services)     [ $# -ge 2 ] || cc_die 2 "--services needs a list"; ONLY="$ONLY,$2"; shift 2 ;;
        --fix)          [ $# -ge 2 ] || cc_die 2 "--fix needs a list"; FIXK="$FIXK,$2"; shift 2 ;;
        --watch)        [ $# -ge 2 ] || cc_die 2 "--watch needs seconds"; WATCH=$2; shift 2 ;;
        --auto-restart) AUTOR=1; shift ;;
        --watch-count)  [ $# -ge 2 ] || cc_die 2 "--watch-count needs a number"; WCOUNT=$2; shift 2 ;;
        --no-color|--no-colour) COLOR=0; shift ;;
        --help|-h)      usage; exit 0 ;;
        *)              cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
case "$BOX" in ''|splunk|webmail|ecomm|fileshare|gitea|web|other) ;; *) cc_die 2 "--box must be splunk, webmail, ecomm, fileshare, gitea, web or other" ;; esac
for _n in "$WATCH" "$WCOUNT"; do case "$_n" in *[!0-9]*) cc_die 2 "--watch and --watch-count need whole numbers" ;; esac; done
[ -z "$WATCH" ] || [ "$WATCH" -ge 5 ] || cc_die 2 "--watch must be at least 5 seconds"
for _k in $(printf '%s' "$FIXK" | tr ',' ' '); do
    case "$_k" in unmask|enable|firewall|kill|start) ;; *) cc_die 2 "--fix: unknown kind '$_k' (unmask enable firewall kill start)" ;; esac
done
[ "$AUTOR" = 1 ] && [ -z "$WATCH" ] && cc_die 2 "--auto-restart needs --watch"

cc_init "SV-50" "Service recovery" changes
cc_detect_os
# shellcheck disable=SC2034  # read by cc_color_init
[ "$COLOR" = 1 ] || CC_NOCOLOR=1
cc_color_init
cc_use_numbered_dir recovery
rmdir "$CC_RUN_DIR/raw" 2>/dev/null
OUTF="$CC_RUN_DIR/output.txt"
grep -v '\[NOTE\]\|\[DEBUG\]' "$CC_LOG" >"$OUTF" 2>/dev/null || : >"$OUTF"
# shellcheck disable=SC2034  # CC_TEE is read by the library's log functions
CC_TEE=$OUTF
W="$CC_RUN_DIR/.work"; mkdir -p "$W"
CC_CSV_DIR="$W/csv"; mkdir -p "$CC_CSV_DIR"
header() { cc_show "" ""; cc_show "$C_CYN" "==========[ $1 ]=========="; }
inlist() { case ",$2," in *",$1,"*) return 0 ;; esac; return 1; }
now() { date +%H:%M:%S; }

cc_show "$C_CYN" "SV-50 Service recovery | host $CC_HOST | init $CC_INIT | results in $CC_RUN_DIR"
cc_show "" "Legend: ${C_RED}[!] DOWN / broken${C_OFF}   ${C_YEL}[*] look at it${C_OFF}   ${C_GRN}[ok] up${C_OFF}   ${C_YEL}[~] would fix${C_OFF}   ${C_GRN}[+] fixed${C_OFF}   ${C_RED}[x] fix failed${C_OFF}"

# ---- The services ---------------------------------------------------------------------
# kind|unit names|process names|ports (any of; uN = udp)|probe
cat >"$W/table" <<'EOF'
web|apache2 httpd|apache2 httpd|80 443|http
web|nginx|nginx|80 443|http
php-fpm|php-fpm php8.4-fpm php8.3-fpm php8.2-fpm php8.1-fpm php8.0-fpm php7.4-fpm php7.3-fpm php7.2-fpm php-fpm84 php-fpm83 php-fpm82 php-fpm81|php-fpm|-|none
mysql|mariadb mysql mysqld|mariadbd mysqld|3306|mysql
postgres|postgresql|postgres|5432|pg
imap|dovecot|dovecot|143 993|imap
smtp|postfix|master|25 587 465|smtp
smtp|exim4 exim|exim4 exim|25 587|smtp
splunk|Splunkd splunk|splunkd|8089 8000|splunk
ssh|ssh sshd|sshd|22|ssh
ntp|chrony chronyd|chronyd|u123|ntp
ntp|ntp ntpd ntpsec|ntpd|u123|ntp
smb|smbd smb samba|smbd|445 139|smb
nfs|nfs-server nfs-kernel-server nfs|nfsd|2049|nfs
gitea|gitea forgejo|gitea forgejo|GITEA_PORT|http
EOF
# Gitea's web port: HTTP_PORT in its app.ini (3000 when not set).
GITEA_PORT=""
for _f in /etc/gitea/app.ini /etc/forgejo/app.ini /var/lib/gitea/custom/conf/app.ini /home/git/gitea/custom/conf/app.ini; do
    [ -r "$_f" ] || continue
    GITEA_PORT=$(sed -n 's/^[[:space:]]*HTTP_PORT[[:space:]]*=[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$_f" | head -n 1)
    [ -n "$GITEA_PORT" ] && break
done
sed "s/GITEA_PORT/${GITEA_PORT:-3000}/" "$W/table" >"$W/table.t" && mv "$W/table.t" "$W/table"
# The init system (BT_SVC_INIT names one in tests).
INIT=${BT_SVC_INIT:-$CC_INIT}
RUNLEVELS=${BT_TEST_RUNLEVELS:-/etc/runlevels}
# unit_exists NAME -> the service is installed under this name.
unit_exists() {
    case "$1" in Splunkd|splunk) [ -x /opt/splunk/bin/splunk ] && return 0 ;; esac
    if [ "$INIT" = systemd ]; then
        systemctl list-unit-files "$1.service" 2>/dev/null | grep -q "^$1\.service" && return 0
    fi
    [ -x "/etc/init.d/$1" ] && return 0
    for _d in ${BT_SVC_DIRS:-}; do [ -x "$_d/$1" ] && return 0; done
    return 1
}
# The rows to check: kind|unit|procs|ports|probe
: >"$W/rows"
while IFS='|' read -r _k _us _ps _pt _pr; do
    for _u in $_us; do
        unit_exists "$_u" || continue
        printf '%s|%s|%s|%s|%s\n' "$_k" "$_u" "$_ps" "$_pt" "$_pr" >>"$W/rows"
        break
    done
done <"$W/table"
for _s in $(printf '%s' "$ONLY" | tr ',' ' '); do
    awk -F'|' -v s="$_s" '$1 == s || $2 == s { f = 1 } END { exit !f }' "$W/rows" || \
        cc_die 2 "--services: '$_s' is not installed here (installed: $(cut -d'|' -f2 "$W/rows" | tr '\n' ' '))"
done
[ -s "$W/rows" ] || { cc_show "$C_GRY" "None of the services this script knows is installed here."; rm -rf "$W"; cc_finish; exit 0; }

if [ -z "$BOX" ] && [ -z "$WATCH" ]; then
    cc_choose "Which box is this?" o "s=splunk" "w=webmail" "e=ecomm" "f=fileshare: Samba or NFS" "g=gitea" "b=web: a ticket, help-desk or shop site" "o=other"
    case "$CC_CHOICE" in s) BOX=splunk ;; w) BOX=webmail ;; e) BOX=ecomm ;; f) BOX=fileshare ;; g) BOX=gitea ;; b) BOX=web ;; *) BOX=other ;; esac
fi
case "$BOX" in
    splunk)    SCORED="splunk ssh ntp" ;;
    webmail)   SCORED="imap smtp web ssh php-fpm mysql postgres" ;;
    ecomm|web) SCORED="web php-fpm mysql postgres" ;;
    fileshare) SCORED="smb nfs ssh" ;;
    gitea)     SCORED="gitea web ssh mysql postgres" ;;
    *)         SCORED="" ;;
esac
if [ -z "$ONLY" ] && [ -z "$WATCH" ] && [ "$(grep -c . "$W/rows")" -gt 1 ]; then
    cc_choose "Check which services? (found: $(cut -d'|' -f2 "$W/rows" | tr '\n' ' ' | sed 's/ $//'))" a \
        "a=all of them" "s=only the scored ones for this box${SCORED:+ ($SCORED)}"
    [ "$CC_CHOICE" = s ] && [ -n "$SCORED" ] && ONLY=",$(printf '%s' "$SCORED" | tr ' ' ',')"
fi
if [ -n "$ONLY" ]; then
    awk -F'|' -v l="$ONLY," 'index(l, "," $1 ",") || index(l, "," $2 ",")' "$W/rows" >"$W/rows.t" && mv "$W/rows.t" "$W/rows"
fi

# ---- Checks --------------------------------------------------------------------------
svc_cmd() {   # svc_cmd UNIT start|stop|restart|status
    case "$1" in Splunkd|splunk) /opt/splunk/bin/splunk "$2" --accept-license --answer-yes --no-prompt; return ;; esac
    for _d in ${BT_SVC_DIRS:-}; do [ -x "$_d/$1" ] && { "$_d/$1" "$2"; return; }; done
    if [ "$INIT" = systemd ]; then systemctl "$2" "$1"
    elif [ "$INIT" = openrc ] || cc_have rc-service; then rc-service "$1" "$2"
    elif cc_have service; then service "$1" "$2"
    else "/etc/init.d/$1" "$2"; fi
}
running() {   # running UNIT PROCS
    if [ "$INIT" = systemd ] && ! printf '%s' "$1" | grep -q '^Splunkd$\|^splunk$'; then
        systemctl is-active -q "$1" 2>/dev/null && return 0
    fi
    # nfsd is kernel threads: up when the kernel serves NFS.
    case "$1" in nfs|nfs-server|nfs-kernel-server) [ -n "$(cat /proc/fs/nfsd/threads 2>/dev/null | grep -v '^0$')" ] && return 0 ;; esac
    for _p in $2; do
        case "$_p" in php-fpm) pgrep -f '^php-fpm' >/dev/null 2>&1 && return 0 ;; *) pgrep -x "$_p" >/dev/null 2>&1 && return 0 ;; esac
    done
    return 1
}
unit_state() {   # unit_state UNIT -> "masked" | "disabled" | "enabled" | "-"
    if [ "$INIT" = systemd ]; then
        case "$(systemctl is-enabled "$1" 2>/dev/null)" in
            masked*) echo masked ;; disabled) echo disabled ;; enabled*|static|alias|indirect|generated) echo enabled ;; *) echo - ;; esac
    elif [ "$INIT" = openrc ]; then
        # Alpine: started at boot when linked in a runlevel.
        _rl_on=""; for _rl in "$RUNLEVELS"/*; do { [ -h "$_rl/$1" ] || [ -e "$_rl/$1" ]; } && _rl_on=1; done
        if [ -n "$_rl_on" ]; then echo enabled; elif unit_exists "$1"; then echo disabled; else echo -; fi
    elif [ -d /etc/rc2.d ] || [ -d /etc/rc3.d ]; then
        if ls /etc/rc[2345].d/S*"$1" >/dev/null 2>&1; then echo enabled; elif [ -x "/etc/init.d/$1" ]; then echo disabled; else echo -; fi
    else echo -; fi
}
config_test() {   # config_test UNIT -> output in $W/ct, rc 0 ok / 1 broken / 2 none
    : >"$W/ct"
    case "$1" in
        apache2) _c=$(cc_first apache2ctl apachectl) || return 2; "$_c" -t >"$W/ct" 2>&1 ;;
        httpd) _c=$(cc_first httpd apachectl) || return 2; "$_c" -t >"$W/ct" 2>&1 ;;
        nginx) cc_have nginx || return 2; nginx -t >"$W/ct" 2>&1 ;;
        php*-fpm) _v=${1#php}; _v=${_v%-fpm}; _c=$(cc_first "php-fpm$_v" php-fpm) || return 2; "$_c" -t >"$W/ct" 2>&1 ;;
        # Alpine: php-fpm83 and the like.
        php-fpm[0-9]*) _c=$(cc_first "$1" php-fpm) || return 2; "$_c" -t >"$W/ct" 2>&1 ;;
        smbd|smb|samba) cc_have testparm || return 2; testparm -s >/dev/null 2>"$W/ct"; grep -qi 'error\|unknown parameter' "$W/ct" && return 1; return 0 ;;
        postfix) cc_have postfix || return 2; postfix check >"$W/ct" 2>&1 ;;
        dovecot) cc_have doveconf || return 2; doveconf -n >/dev/null 2>"$W/ct" ;;
        ssh|sshd) _c=$(cc_which sshd) || return 2; [ -d /run/sshd ] || mkdir -p /run/sshd 2>/dev/null; "$_c" -t >"$W/ct" 2>&1 ;;
        *) return 2 ;;
    esac
    [ $? -eq 0 ] && return 0; return 1
}
# Which ports answer.  tcp n, or uN for udp.
listening() {   # listening PORT -> pid/program on stdout, rc 0 if someone listens
    if ! cc_have ss; then
        # Alpine: busybox netstat, "PID/name" last; shown as ss would.
        case "$1" in u*) _lf=-lunp; _lp=${1#u} ;; *) _lf=-ltnp; _lp=$1 ;; esac
        { netstat "$_lf" 2>/dev/null || busybox netstat "$_lf" 2>/dev/null; } | awk -v p=":$_lp" '$1 ~ /^(tcp|udp)/ { n = split($4, a, ":"); if (":" a[n] == p) { split($NF, w, "/"); print "users:((\"" w[2] "\",pid=" w[1] "))"; f = 1 } } END { exit !f }'
        return
    fi
    case "$1" in
        u*) ss -lunp 2>/dev/null | awk -v p=":${1#u}" '{ n = split($4, a, ":"); if (":" a[n] == p) { print $NF; f = 1 } } END { exit !f }' ;;
        *)  ss -ltnp 2>/dev/null | awk -v p=":$1" '{ n = split($4, a, ":"); if (":" a[n] == p) { print $NF; f = 1 } } END { exit !f }' ;;
    esac
}
banner() {   # banner PORT [tls] -> first line the server sends
    if [ "${2:-}" = tls ]; then
        cc_have openssl && { sleep 2 | timeout 6 openssl s_client -connect "127.0.0.1:$1" -quiet 2>/dev/null | head -n 1; }; return
    fi
    if cc_have nc; then { sleep 2; } | timeout 6 nc -w 3 127.0.0.1 "$1" 2>/dev/null | head -n 1 | tr -d '\r'
    elif cc_have curl; then curl -s -m 3 "telnet://127.0.0.1:$1" </dev/null 2>/dev/null | head -n 1 | tr -d '\r'
    fi
}
http_code() {   # http_code URL
    if cc_have curl; then curl -sk -m 8 -o "$W/page" -w '%{http_code}' "$1" 2>/dev/null
    elif cc_have wget; then wget -q -S -O "$W/page" -T 8 --no-check-certificate "$1" 2>&1 | awk '/HTTP\// { c = $2 } END { print c }'; fi
}
# probe KIND UNIT PORTS -> "ok TEXT" or "bad TEXT" or "- TEXT"
#   ksh93 can lose what probe_raw prints when it is called in $( ) (it runs
#   curl in a nested $( )), so it writes to a file and probe prints that.
probe() { probe_raw "$@" >"$W/probe.out" 2>/dev/null; cat "$W/probe.out"; }
probe_raw() {
    _pd=""   # a port answered: the loops break (no return inside them)
    case "$1" in
        http)
            for _p in $3; do
                listening "$_p" >/dev/null || continue
                _sc=http; [ "$_p" = 443 ] && _sc=https
                _c=$(http_code "$_sc://127.0.0.1:$_p/"); _c=${_c:-000}
                case "$_c" in
                    000) echo "bad no HTTP answer on $_p" ;;
                    5??) if grep -qiE 'database|SQLSTATE|mysql' "$W/page" 2>/dev/null; then echo "bad HTTP $_c on $_p: a database error (check mysql)"; else echo "bad HTTP $_c on $_p (the app or PHP fails: error.log)"; fi ;;
                    *)   echo "ok HTTP $_c on $_p" ;;
                esac
                _pd=1; break
            done
            [ -n "$_pd" ] || echo "bad nothing answers on $3" ;;
        mysql)
            _c=$(cc_first mariadb-admin mysqladmin) || { echo "- no mysqladmin"; return; }
            if "$_c" --connect-timeout=5 ping >/dev/null 2>&1; then echo "ok answers a ping"
            elif "$_c" --connect-timeout=5 ping 2>&1 | grep -qi 'access denied'; then echo "ok answers (login refused for root: fine)"
            else echo "bad does not answer a ping"; fi ;;
        pg)
            if cc_have pg_isready; then pg_isready -q -h 127.0.0.1 2>/dev/null && echo "ok accepting connections" || echo "bad not accepting connections"
            else echo "- no pg_isready"; fi ;;
        imap)
            for _p in $3; do
                listening "$_p" >/dev/null || continue
                if [ "$_p" = 993 ]; then _b=$(banner 993 tls); else _b=$(banner "$_p"); fi
                case "$_b" in "* OK"*) echo "ok IMAP banner on $_p" ;; '') echo "bad no IMAP banner on $_p" ;; *) echo "bad odd answer on $_p: $(printf '%s' "$_b" | cut -c1-40)" ;; esac
                _pd=1; break
            done
            [ -n "$_pd" ] || echo "bad nothing answers on $3" ;;
        smtp)
            for _p in $3; do
                listening "$_p" >/dev/null || continue
                [ "$_p" = 465 ] && continue
                _b=$(banner "$_p")
                case "$_b" in 220*) echo "ok SMTP banner on $_p" ;; '') echo "bad no SMTP banner on $_p" ;; *) echo "bad odd answer on $_p: $(printf '%s' "$_b" | cut -c1-40)" ;; esac
                _pd=1; break
            done
            [ -n "$_pd" ] || echo "bad nothing answers on $3" ;;
        ssh)
            _b=$(banner 22)
            case "$_b" in SSH-*) echo "ok SSH banner" ;; '') echo "bad no SSH banner on 22" ;; *) echo "bad odd answer on 22" ;; esac ;;
        splunk)
            _c=$(http_code "https://127.0.0.1:8089/"); case "${_c:-000}" in 000) echo "bad management port 8089 does not answer" ;; *) echo "ok 8089 answers ($_c)" ;; esac ;;
        ntp)
            if cc_have chronyc && [ "$2" != ntp ] && [ "$2" != ntpd ] && [ "$2" != ntpsec ]; then
                chronyc -n tracking >/dev/null 2>&1 && echo "ok chronyc tracking answers" || echo "bad chronyc gets no answer"
            elif listening u123 >/dev/null; then echo "ok listening on 123/udp"
            else echo "bad nothing on 123/udp"; fi ;;
        smb)
            for _p in $3; do
                listening "$_p" >/dev/null || continue
                if cc_have smbclient; then
                    # A refused guest still means Samba answers.
                    _o=$(timeout 10 smbclient -N -L 127.0.0.1 -p "$_p" 2>&1)
                    case "$_o" in *Sharename*|*ACCESS_DENIED*|*LOGON_FAILURE*) echo "ok Samba answers on $_p" ;; *) echo "bad listening on $_p but no SMB answer" ;; esac
                else echo "ok listening on $_p"; fi
                _pd=1; break
            done
            [ -n "$_pd" ] || echo "bad nothing answers on $3" ;;
        nfs)
            if listening 2049 >/dev/null; then
                if cc_have showmount; then _o=$(timeout 10 showmount -e 127.0.0.1 2>&1) && echo "ok NFS answers ($(printf '%s\n' "$_o" | grep -c '^/') export(s))" || echo "bad listening on 2049 but showmount gets no answer"
                else echo "ok listening on 2049"; fi
            else echo "bad nothing on 2049"; fi ;;
        *) echo "- not tested" ;;
    esac
}
# firewalld (Rocky, Fedora) and ufw (Ubuntu, Mint) drop what they do not
# allow, whatever iptables shows.
FWD=0; UFW=0
cc_have firewall-cmd && [ "$(firewall-cmd --state 2>/dev/null)" = running ] && FWD=1
cc_have ufw && ufw status 2>/dev/null | head -n 1 | grep -q 'Status: active' && UFW=1
fwd_allows() {   # fwd_allows PORT PROTO -> firewalld lets it in
    firewall-cmd -q --query-port="$1/$2" 2>/dev/null && return 0
    for _fs in $(firewall-cmd --list-services 2>/dev/null); do
        firewall-cmd --info-service="$_fs" 2>/dev/null | awk -v p="$1/$2" '$1 == "ports:" { for (i = 2; i <= NF; i++) if ($i == p) f = 1 } END { exit !f }' && return 0
    done
    return 1
}
ufw_allows() {   # ufw_allows PORT PROTO -> ufw lets it in
    ufw status verbose 2>/dev/null | grep -q '^Default: allow (incoming)' && return 0
    ufw status 2>/dev/null | awk -v p="$1" -v pp="$1/$2" '($1 == p || $1 == pp) && $2 == "ALLOW" { f = 1 } END { exit !f }'
}
# Firewall rules that drop the port: "iptables-spec" lines.
fw_rules() {   # fw_rules PORT
    _pn=${1#u}
    cc_have iptables || return 0
    iptables -S 2>/dev/null | awk -v p="$_pn" '
        /^-A / && / -j (DROP|REJECT)/ {
            for (i = 1; i <= NF; i++) {
                if ($i == "--dport" && $(i + 1) == p) { print; next }
                if ($i == "--dports") { n = split($(i + 1), a, ","); for (j = 1; j <= n; j++) { split(a[j], r, ":"); if (a[j] == p || (r[2] != "" && p >= r[1] && p <= r[2])) { print; next } } }
            }
        }'
}
pol_drop() { cc_have iptables && iptables -S INPUT 2>/dev/null | grep -q '^-P INPUT DROP'; }

# ---- Watch mode --------------------------------------------------------------------------
if [ -n "$WATCH" ]; then
    # Only the web server in use is watched (apache2 or nginx, not both).
    _wu=""; while IFS='|' read -r _k _u _ps _pt _pr; do [ "$_k" = web ] && [ -z "$_wu" ] && running "$_u" "$_ps" && _wu=$_u; done <"$W/rows"
    [ -n "$_wu" ] || _wu=$(awk -F'|' '$1 == "web" { print $2; exit }' "$W/rows")
    awk -F'|' -v w="$_wu" '$1 != "web" || $2 == w' "$W/rows" >"$W/rows.t" && mv "$W/rows.t" "$W/rows"
    WF="$CC_RUN_DIR/watch.txt"
    cc_show "$C_CYN" "Watching $(cut -d'|' -f2 "$W/rows" | tr '\n' ' ')every $WATCH s$([ "$AUTOR" = 1 ] && [ "$CC_APPLY" = 1 ] && echo ', restarting what goes down'). Ctrl-C to stop."
    [ "$AUTOR" = 1 ] && [ "$CC_APPLY" != 1 ] && cc_show "$C_YEL" "  [*] --auto-restart without --apply: only reporting."
    : >"$W/state"; : >"$W/restarts"; _round=0
    trap 'cc_show "" "Stopped. Log: $WF"; rm -rf "$W"; cc_finish; exit 0' INT TERM
    while :; do
        _round=$((_round + 1))
        while IFS='|' read -r _k _u _ps _pt _pr; do
            if running "$_u" "$_ps"; then _r=$(probe "$_pr" "$_u" "$_pt"); else _r="bad not running"; fi
            _st=${_r%% *}; _tx=${_r#* }
            _was=$(awk -F'|' -v u="$_u" '$1 == u { print $2 }' "$W/state")
            if [ "$_st" != "${_was:-new}" ]; then
                awk -F'|' -v u="$_u" '$1 != u' "$W/state" >"$W/state.t"; printf '%s|%s\n' "$_u" "$_st" >>"$W/state.t"; mv "$W/state.t" "$W/state"
                case "$_st" in
                    ok)  [ -n "$_was" ] && cc_show "$C_GRN" "$(now) [ok] $_u is UP again: $_tx" || cc_show "$C_GRN" "$(now) [ok] $_u: $_tx" ;;
                    bad) cc_show "$C_RED" "$(now) [!] $_u is DOWN: $_tx" ;;
                    *)   cc_show "$C_GRY" "$(now) [-] $_u: $_tx" ;;
                esac
                printf '%s %s %s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$_u" "$_st" "$_tx" >>"$WF"
            fi
            if [ "$_st" = bad ] && [ "$AUTOR" = 1 ] && [ "$CC_APPLY" = 1 ]; then
                _t=$(date +%s); _n=$(awk -v t="$_t" -v u="$_u" '$1 == u && $2 > t - 600 { n++ } END { print n + 0 }' "$W/restarts")
                config_test "$_u"; _ctr=$?
                if [ "$_ctr" = 1 ]; then
                    cc_show "$C_RED" "$(now) [x] $_u: NOT restarted, its config test fails: $(head -n 2 "$W/ct" | tr '\n' ' ')"
                elif [ "$_n" -ge 3 ]; then
                    [ "$_n" = 3 ] && cc_show "$C_RED" "$(now) [x] $_u: restarted 3 times in 10 minutes and still going down - run SV-50 without --watch to see why"
                    printf '%s %s\n' "$_u" "$_t" >>"$W/restarts"
                else
                    printf '%s %s\n' "$_u" "$_t" >>"$W/restarts"
                    if svc_cmd "$_u" restart >>"$CC_LOG" 2>&1; then cc_show "$C_GRN" "$(now) [+] $_u restarted"; else cc_show "$C_RED" "$(now) [x] $_u did not restart (log: $CC_LOG)"; fi
                    printf '%s %s restarted\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$_u" >>"$WF"
                fi
            fi
        done <"$W/rows"
        [ "$WCOUNT" -gt 0 ] && [ "$_round" -ge "$WCOUNT" ] && break
        sleep "$WATCH"
    done
    trap - INT TERM
    rm -rf "$W"; cc_finish; exit 0
fi

# ---- The box -------------------------------------------------------------------------
header "1/4  the box"
BOXP=0
df -P / /var /tmp 2>/dev/null | awk 'NR > 1 { u = $5; sub(/%/, "", u); if (u + 0 >= 95) print $6 " " u "%" }' | sort -u >"$W/full"
while read -r _m _p; do cc_show "$C_RED" "  [!] $_m is $_p full: services cannot write logs, PID files or sessions. Look: du -xh $_m | sort -h | tail"; BOXP=1; done <"$W/full"
df -Pi / /var /tmp 2>/dev/null | awk 'NR > 1 { u = $5; sub(/%/, "", u); if (u + 0 >= 95) print $6 " " u "%" }' | sort -u | while read -r _m _p; do cc_show "$C_RED" "  [!] $_m has no inodes left ($_p): someone may have filled it with tiny files"; done
_tt="/tmp/.bt-sv50-$$"; if : >"$_tt" 2>/dev/null; then rm -f "$_tt"; else cc_show "$C_RED" "  [!] /tmp is not writable: PHP sessions and many services fail. Check: ls -ld /tmp (should be drwxrwxrwt)"; BOXP=1; fi
[ "$(stat -c %a /tmp 2>/dev/null)" = 1777 ] || { [ -d /tmp ] && cc_show "$C_YEL" "  [*] /tmp mode is $(stat -c %a /tmp 2>/dev/null), not 1777 (fix: chmod 1777 /tmp)"; }
_oom=$( { dmesg 2>/dev/null; journalctl -k -n 500 --no-pager 2>/dev/null; } | grep -i 'out of memory\|killed process' | tail -n 3)
[ -n "$_oom" ] && { cc_show "$C_YEL" "  [*] programs were killed for lack of memory:"; printf '%s\n' "$_oom" | while IFS= read -r _l; do cc_show "$C_GRY" "      $_l"; done; }
[ "$BOXP" = 0 ] && cc_show "$C_GRN" "  [ok] disk, inodes and /tmp"

# ---- Each service ----------------------------------------------------------------------
header "2/4  services"
# fixes: unit|kind|description|default|command|undo
: >"$W/fixes"
SCSV=$(cc_csv_new status "service,unit,running,boot,config,port,answer,problems")
# addfix UNIT KIND DESC DEFAULT CMD UNDO - once per kill/firewall command:
#   two web servers on one port share the same fix.
addfix() {
    case "$2" in kill|firewall) awk -F'|' -v k="$2" -v c="$5" '$2 == k && $5 == c { f = 1 } END { exit !f }' "$W/fixes" && return 0 ;; esac
    printf '%s|%s|%s|%s|%s|%s\n' "$@" >>"$W/fixes"
}
NDOWN=0; WEBSTART=""; WEBBROKEN=""
# Two web servers installed (apache2 and nginx): only one serves the site.
WEBUP=""
while IFS='|' read -r _k _u _ps _pt _pr; do [ "$_k" = web ] && running "$_u" "$_ps" && WEBUP="$WEBUP $_u"; done <"$W/rows"
while IFS='|' read -r _k _u _ps _pt _pr; do
    _probs=""; _st=$(unit_state "$_u"); _run=no; running "$_u" "$_ps" && _run=yes
    if [ "$_k" = web ] && [ "$_run" = no ] && [ -n "$WEBUP" ]; then
        cc_show "$C_GRY" "  [-] $(printf '%-9s %-12s' web "$_u") not in use (the web server here is${WEBUP})"
        cc_csv_row "$SCSV" "$_k" "$_u" no "$(unit_state "$_u")" - - "not in use" ""; continue
    fi
    config_test "$_u"; _ctr=$?
    _cfg=ok; [ "$_ctr" = 1 ] && _cfg=BROKEN; [ "$_ctr" = 2 ] && _cfg=-
    # Ports: who listens.
    _pinfo=""; _held=""
    for _p in $_pt; do
        [ "$_p" = - ] && continue
        if _who=$(listening "$_p"); then
            _pn=$(printf '%s' "$_who" | sed -n 's/.*"\([^"]*\)".*/\1/p' | head -n 1)
            _ok=0; for _x in $_ps; do case "$_pn" in "$_x"*|php-fpm*) _ok=1 ;; esac; done
            case "$_u" in ssh|sshd) [ "$_pn" = sshd ] && _ok=1 ;; esac
            if [ "$_ok" = 1 ] || [ -z "$_pn" ]; then _pinfo="$_pinfo ${_p#u}"
            else _pinfo="$_pinfo ${_p#u}:$_pn"; _held="$_held $_p:$_who"; fi
        fi
    done
    if [ "$_run" = yes ]; then _ans=$(probe "$_pr" "$_u" "$_pt"); else _ans="bad not running"; fi
    _ast=${_ans%% *}; _atx=${_ans#* }
    # Problems and fixes.
    [ "$_st" = masked ] && { _probs="$_probs masked;"; addfix "$_u" unmask "unmask $_u (masked: it cannot start at all)" y "unmask" "mask"; }
    if [ "$_st" = disabled ] && { [ "$_run" = no ] || [ -n "$SCORED" ]; }; then
        case " $SCORED " in *" $_k "*) _probs="$_probs disabled at boot;"; addfix "$_u" enable "enable $_u at boot (a scored service: a reboot would leave it down)" y enable disable ;;
            *) [ "$_run" = no ] && _probs="$_probs disabled at boot;" ;; esac
    fi
    [ "$_cfg" = BROKEN ] && _probs="$_probs config test FAILS;"
    for _h in $_held; do
        _hp=${_h%%:*}; _hw=${_h#*:}; _hpid=$(printf '%s' "$_hw" | sed -n 's/.*pid=\([0-9]*\).*/\1/p' | head -n 1)
        _hn=$(printf '%s' "$_hw" | sed -n 's/.*"\([^"]*\)".*/\1/p' | head -n 1)
        _hexe=$(readlink "/proc/$_hpid/exe" 2>/dev/null)
        _probs="$_probs port ${_hp#u} held by $_hn (pid $_hpid);"
        _hd=n; case "$_hexe" in /tmp/*|/var/tmp/*|/dev/shm/*|*"(deleted)"*|'') _hd=y ;; esac
        [ -n "$_hpid" ] && addfix "$_u" kill "stop $_hn (pid $_hpid, ${_hexe:-program gone from disk}) holding port ${_hp#u} - $([ "$_hd" = y ] && echo 'runs from a temp folder or a deleted file: red team' || echo 'is it yours?')" "$_hd" "kill $_hpid" "-"
    done
    for _p in $_pt; do
        [ "$_p" = - ] && continue
        fw_rules "$_p" >"$W/fw"
        while IFS= read -r _rule; do
            [ -n "$_rule" ] || continue
            _probs="$_probs firewall drops ${_p#u};"
            addfix "$_u" firewall "remove the firewall rule: $_rule" y "${_rule#-A }" "${_rule#-A }"
        done <"$W/fw"
        # nftables only when iptables shows nothing (iptables-nft shows the
        # same rule in both).
        if [ ! -s "$W/fw" ] && cc_have nft && nft list ruleset 2>/dev/null | grep -Eq "dport (\{[^}]*[ ,])?${_p#u}([ ,][^}]*\})? .*(drop|reject)"; then
            _probs="$_probs nftables drops ${_p#u} (nft list ruleset);"
        fi
    done
    for _p in $_pt; do
        [ "$_p" = - ] && continue
        _pr2=tcp; case "$_p" in u*) _pr2=udp ;; esac; _pn=${_p#u}
        if [ "$FWD" = 1 ] && ! fwd_allows "$_pn" "$_pr2"; then
            _probs="$_probs firewalld does not allow $_pn/$_pr2;"
            addfix "$_u" firewall "open $_pn/$_pr2 in firewalld (now and after a reboot)" y "firewall-cmd --add-port=$_pn/$_pr2; firewall-cmd --permanent --add-port=$_pn/$_pr2" "firewall-cmd --remove-port=$_pn/$_pr2; firewall-cmd --permanent --remove-port=$_pn/$_pr2"
        fi
        if [ "$UFW" = 1 ] && ! ufw_allows "$_pn" "$_pr2"; then
            _probs="$_probs ufw does not allow $_pn/$_pr2;"
            addfix "$_u" firewall "allow $_pn/$_pr2 in ufw" y "ufw allow $_pn/$_pr2" "ufw delete allow $_pn/$_pr2"
        fi
    done
    pol_drop && ! iptables -S INPUT 2>/dev/null | grep -q -- "--dport ${_pt%% *} .*ACCEPT\|-j ACCEPT$" && _probs="$_probs INPUT policy DROP with no ACCEPT for ${_pt%% *};"
    if [ "$_run" = no ]; then
        _probs="$_probs not running;"
        if [ "$_cfg" = BROKEN ]; then _probs="$_probs not started: fix the config first;"; [ "$_k" = web ] && WEBBROKEN=${WEBBROKEN:-$_u}
        elif [ "$_k" = web ] && [ -n "$WEBSTART" ]; then
            addfix "$_u" start "start $_u too ($WEBSTART is being started on the same ports: say yes only if both are used)" n start "-"
        elif [ "$_k" = web ] && [ -n "$WEBBROKEN" ]; then
            addfix "$_u" start "start $_u instead ($WEBBROKEN cannot start: say yes only if $_u serves this site)" n start "-"
        else addfix "$_u" start "start $_u$([ "$_cfg" = ok ] && echo ' (its config test passes)')" y start "-"; fi
        [ "$_k" = web ] && [ -z "$WEBSTART" ] && [ "$_cfg" != BROKEN ] && [ -z "$WEBBROKEN" ] && WEBSTART=$_u
    elif [ "$_ast" = bad ]; then
        if [ "$_cfg" = BROKEN ]; then _probs="$_probs running but not answering, config broken: NOT restarted;"
        else addfix "$_u" start "restart $_u (running but $_atx)" y restart "-"; fi
    fi
    [ "$_ast" = bad ] && [ "$_run" = yes ] && _probs="$_probs $_atx;"
    # Tampering: config changed lately, drop-ins, package files.
    case "$_u" in apache2) _cd=/etc/apache2 ;; httpd) _cd=/etc/httpd ;; nginx) _cd=/etc/nginx ;; php*-fpm) _cd=/etc/php ;; mariadb|mysql|mysqld) _cd=/etc/mysql ;; postgresql) _cd=/etc/postgresql ;;
        dovecot) _cd=/etc/dovecot ;; postfix) _cd=/etc/postfix ;; ssh|sshd) _cd=/etc/ssh ;; chrony|chronyd) _cd=/etc/chrony ;;
        smbd|smb|samba) _cd=/etc/samba ;; nfs*) _cd=/etc/exports ;; gitea) _cd=/etc/gitea ;; forgejo) _cd=/etc/forgejo ;; *) _cd="" ;; esac
    _recent=""; [ -n "$_cd" ] && [ -e "$_cd" ] && _recent=$(find "$_cd" -type f -mmin -120 2>/dev/null | head -n 5 | tr '\n' ' ')
    _drop=""; [ "$INIT" = systemd ] && _drop=$(ls -d "/etc/systemd/system/$_u.service.d" "/etc/systemd/system/$_u.service" 2>/dev/null | tr '\n' ' ')
    [ -n "$_drop" ] && grep -rqs 'ExecStart=.*\(/bin/true\|/bin/false\|/dev/null\|sleep\)' $_drop && _probs="$_probs systemd override replaces how it starts ($_drop);"
    printf '%s|%s\n' "$_u" "$_recent" >>"$W/recent"
    _pk=""; if cc_have dpkg; then _pk=$(dpkg -S "$(cc_which "$(printf '%s' "$_ps" | cut -d' ' -f1)" 2>/dev/null || echo /nonexistent)" 2>/dev/null | cut -d: -f1 | head -n 1); fi
    if [ -n "$_pk" ]; then
        _bad=$(dpkg -V "$_pk" 2>/dev/null | awk '$2 != "c" && $1 ~ /5/ { print $NF }' | head -n 3 | tr '\n' ' ')
        [ -n "$_bad" ] && _probs="$_probs program files changed ($_bad) - reinstall: apt-get install --reinstall $_pk;"
    elif cc_have rpm; then
        # Rocky, Fedora.
        _bin=$(cc_which "$(printf '%s' "$_ps" | cut -d' ' -f1)" 2>/dev/null)
        if [ -n "$_bin" ] && _pk=$(rpm -qf "$_bin" 2>/dev/null); then
            _bad=$(rpm -V "$_pk" 2>/dev/null | awk '$2 != "c" && $1 ~ /5/ { print $NF }' | head -n 3 | tr '\n' ' ')
            [ -n "$_bad" ] && _probs="$_probs program files changed ($_bad) - reinstall: dnf reinstall $_pk;"
        fi
    fi
    # Show it.
    _line=$(printf '%-9s %-12s run:%-3s boot:%-8s config:%-6s port:%-12s %s' "$_k" "$_u" "$_run" "$_st" "$_cfg" "${_pinfo# }" "$([ "$_run" = yes ] && printf "%s" "$_atx")")
    if [ -z "$_probs" ] && [ "$_ast" != bad ]; then cc_show "$C_GRN" "  [ok] $_line"
    else NDOWN=$((NDOWN + 1)); cc_show "$C_RED" "  [!] $_line"
        printf '%s' "$_probs" | tr ';' '\n' | sed 's/^ *//' | grep . | while IFS= read -r _pl; do cc_show "$C_YEL" "        - $_pl"; done
        [ "$_cfg" = BROKEN ] && head -n 4 "$W/ct" | while IFS= read -r _cl; do cc_show "$C_GRY" "        config: $_cl"; done
        [ -n "$_recent" ] && cc_show "$C_YEL" "        - config files changed in the last 2 hours: $_recent(compare with your backup; SV-15 --restore puts configs back)"
        if [ "$_run" = no ] || [ "$_ast" = bad ]; then
            _lg=""; case "$_u" in apache2) _lg=/var/log/apache2/error.log ;; httpd) _lg=/var/log/httpd/error_log ;; nginx) _lg=/var/log/nginx/error.log ;;
                mariadb|mysql|mysqld) _lg=$(ls /var/log/mysql/error.log /var/log/mariadb/mariadb.log 2>/dev/null | head -n 1) ;; dovecot|postfix) _lg=$(ls /var/log/mail.log /var/log/maillog 2>/dev/null | head -n 1) ;; esac
            # Alpine (OpenRC): the system log is /var/log/messages.
            [ -z "$_lg" ] && [ "$INIT" != systemd ] && _lg=/var/log/messages
            if [ "$INIT" = systemd ]; then journalctl -u "$_u" -n 3 --no-pager -o cat 2>/dev/null; elif [ -n "$_lg" ]; then tail -n 3 "$_lg" 2>/dev/null; fi | cut -c1-150 | while IFS= read -r _ll; do cc_show "$C_GRY" "        log: $_ll"; done
        fi
    fi
    cc_csv_row "$SCSV" "$_k" "$_u" "$_run" "$_st" "$_cfg" "${_pinfo# }" "$_atx" "$(printf '%s' "$_probs" | sed 's/;$//; s/^ //')"
done <"$W/rows"

# ---- Fixes ------------------------------------------------------------------------------
header "3/4  fixes"
NFIX=$(grep -c . "$W/fixes")
[ "$NFIX" -eq 0 ] && cc_show "$C_GRN" "  [ok] Nothing to fix here.$([ "$NDOWN" -gt 0 ] && echo ' (The problems above need a hand: see each one.)')"
: >"$W/chosen"
while IFS='|' read -r _u _kd _ds _df _cmd _un; do
    if inlist "$_kd" "$FIXK"; then printf '%s|%s|%s|%s|%s\n' "$_u" "$_kd" "$_ds" "$_cmd" "$_un" >>"$W/chosen"; continue; fi
    _d=Y; [ "$_df" = n ] && _d=N
    cc_ask "[$_kd] $_ds?" "$_d" "yes, do it" "no, leave it" && printf '%s|%s|%s|%s|%s\n' "$_u" "$_kd" "$_ds" "$_cmd" "$_un" >>"$W/chosen"
done <"$W/fixes"
NCH=$(grep -c . "$W/chosen")

header "4/4  apply"
NOK=0; NBAD=0
if [ "$NCH" -eq 0 ]; then
    [ "$NFIX" -gt 0 ] && cc_show "$C_GRY" "  No fix chosen."
elif [ "$CC_APPLY" != 1 ] || ! cc_is_root; then
    cc_is_root || cc_show "$C_YEL" "  [!] not root: showing the fixes only"
    while IFS='|' read -r _u _kd _ds _cmd _un; do cc_show "$C_YEL" "  [~] $_ds"; done <"$W/chosen"
    cc_show "$C_GRY" "  Dry run: nothing was changed. Run again with --apply."
    # shellcheck disable=SC2034  # read by cc_finish
    CC_N_WOULD=$NCH
else
    # Order: unmask, firewall, kill, enable, then start - each fix clears
    # the way for the next.
    for _kd in unmask firewall kill enable start; do
        awk -F'|' -v k="$_kd" '$2 == k' "$W/chosen" | while IFS='|' read -r _u _k2 _ds _cmd _un; do
            case "$_kd" in
                unmask) cc_undo_add "mask $_u again" "systemctl mask $_u"; systemctl unmask "$_u" >>"$CC_LOG" 2>&1; _r=$? ;;
                enable) if [ "$INIT" = systemd ]; then cc_undo_add "disable $_u at boot again" "systemctl disable $_u"; systemctl enable "$_u" >>"$CC_LOG" 2>&1
                        elif [ "$INIT" = openrc ]; then cc_undo_add "disable $_u at boot again" "$(cc_svc_cmd disable "$_u")"; cc_svc enable "$_u" >>"$CC_LOG" 2>&1
                        else cc_undo_add "disable $_u at boot again" "update-rc.d $_u disable"; update-rc.d "$_u" enable >>"$CC_LOG" 2>&1; fi; _r=$? ;;
                firewall) case "$_cmd" in
                            firewall-cmd*|ufw*) cc_undo_add "close the port again" "$_un"; sh -c "$_cmd" >>"$CC_LOG" 2>&1 ;;
                            *)  cc_undo_add "put the firewall rule back" "iptables -A $_un"
                                # shellcheck disable=SC2086  # the rule's words
                                iptables -D $_cmd >>"$CC_LOG" 2>&1 ;;
                        esac; _r=$? ;;
                kill)   kill ${_cmd#kill } 2>>"$CC_LOG"; sleep 1; kill -0 ${_cmd#kill } 2>/dev/null && kill -9 ${_cmd#kill } 2>>"$CC_LOG"; _r=0 ;;
                start)  svc_cmd "$_u" "$_cmd" >>"$CC_LOG" 2>&1; _r=$? ;;
            esac
            if [ "$_r" = 0 ]; then cc_show "$C_GRN" "  [+] $_ds"; echo ok >>"$W/res"; else cc_show "$C_RED" "  [x] FAILED: $_ds (log: $CC_LOG)"; echo bad >>"$W/res"; fi
        done
    done
    NOK=$(grep -c ok "$W/res" 2>/dev/null); NBAD=$(grep -c bad "$W/res" 2>/dev/null)
    # shellcheck disable=SC2034  # read by cc_finish
    CC_N_DONE=$NOK
    # shellcheck disable=SC2034  # read by cc_finish
    CC_N_FAIL=$NBAD
    # Test each fixed service again.
    cut -d'|' -f1 "$W/chosen" | sort -u | while IFS= read -r _u; do
        _row=$(awk -F'|' -v u="$_u" '$2 == u' "$W/rows")
        _ps=$(printf '%s' "$_row" | cut -d'|' -f3); _pt=$(printf '%s' "$_row" | cut -d'|' -f4); _pr=$(printf '%s' "$_row" | cut -d'|' -f5)
        _i=0; _ans="bad not running"
        while [ "$_i" -lt 5 ]; do
            sleep 2; _i=$((_i + 1))
            running "$_u" "$_ps" && _ans=$(probe "$_pr" "$_u" "$_pt") && [ "${_ans%% *}" != bad ] && break
        done
        case "$_ans" in ok*|-*) cc_show "$C_GRN" "  [ok] $_u is UP: ${_ans#* }" ;; *) cc_show "$C_RED" "  [!] $_u is still DOWN: ${_ans#* } - look at the problems above" ;; esac
        printf '%s %s\n' "$_u" "${_ans%% *}" >>"$W/after"
    done
fi

# ---- Summary ----------------------------------------------------------------------------
cc_csv_pretty "$SCSV" "$CC_RUN_DIR/status.txt" 140
{
    printf '==========[ summary ]==========\n'
    printf 'SV-50 Service recovery | host %s | %s\n' "$CC_HOST" "$([ "$CC_APPLY" = 1 ] && [ "$NCH" -gt 0 ] && echo APPLIED || echo 'CHECK / DRY RUN')"
    printf 'Services with problems: %d of %d\n' "$NDOWN" "$(grep -c . "$W/rows")"
    awk "$CC_AWK_CSV"'NR > 1 { csvsplit($0, f); if (f[8] != "") printf "  %-12s %s\n", f[2], substr(f[8], 1, 150) }' "$SCSV"
    [ -s "$W/after" ] && { printf '\nAfter the fixes:\n'; awk '{ printf "  %-12s %s\n", $1, ($2 == "bad" ? "STILL DOWN" : "up") }' "$W/after"; }
    printf '\nIf the box says up but scoring says down: check the network firewall / router (NW scripts) and that the scoring IP is not banned (SV-26 --unban-all).\n'
    printf 'Defaced or wiped site: SV-15 --check, then --restore.   Watch: sh %s --watch 30\n' "$0"
    [ -f "$CC_RUN_DIR/revert.sh" ] && printf 'Undo this run: sh %s/revert.sh --force\n' "$CC_RUN_DIR"
} >"$CC_RUN_DIR/summary.txt"
cc_show "" ""
while IFS= read -r _l; do
    case "$_l" in ==*|SV-50*) cc_show "$C_CYN" "$_l" ;; *'STILL DOWN'*) cc_show "$C_RED" "$_l" ;; '  '*) cc_show "$C_YEL" "$_l" ;; *) cc_show "" "$_l" ;; esac
done <"$CC_RUN_DIR/summary.txt"
rm -rf "$W"
cc_finish
