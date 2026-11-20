#!/bin/sh
# =============================================================================
# ID:       LX-22
# NAME:     SSH hardening and key cleanup
# ROLE:     Linux  (wave 2, first 15 minutes)
# KIND:     changes - dry run unless --apply
# VERSION:  2.1.0
#
# PURPOSE
#   A changed password does not stop a red team that planted an SSH key, and
#   a loose sshd_config lets them back in other ways.  This script:
#     1. shows how SSH is set up now: the sshd version and ports, the value
#        every important setting has right now, Match blocks that loosen
#        things, extra key sources, extra sshd processes
#     2. lists every authorized key of every account (service accounts like
#        www-data too) with its fingerprint, comment, options and when the
#        file changed, says which ones look planted, and asks key by key
#        whether to keep it
#     3. asks setting by setting whether to turn it on or off (like sqlmap:
#        Enter takes the recommended answer), with a plain explanation of
#        what each one does and what could break
#     4. writes the chosen settings as a marked block at the TOP of
#        sshd_config (sshd uses the first value it reads, so the block wins
#        over anything below it and over sshd_config.d), tests it with
#        "sshd -t" BEFORE installing, reloads sshd (open sessions stay up),
#        checks sshd still listens, and puts the old config back by itself
#        if not.  Ubuntu 24.04 and Mint 22 (ssh.socket: systemd starts an
#        sshd per login) need no reload: the next login reads the new config
#
#   Gitea (Forgejo, Gogs, GitLab) writes its users' keys into the git
#   account's authorized_keys with a forced command that only runs git.
#   Those are shown as Gitea's, kept by default (one question for all of
#   them, --gitea-keys), and the git account is added to AllowUsers.  A
#   forced command with anything more in it is still flagged as planted.
#     5. with a revert timer running: everything is undone after --timer
#        seconds unless you confirm from a NEW SSH session that you can
#        still log in
#
# USAGE
#   sudo sh LX-22-ssh-hardening.sh                     look and plan (asks; changes nothing)
#   sudo sh LX-22-ssh-hardening.sh --apply             ask, then change
#   sudo sh LX-22-ssh-hardening.sh --apply --batch     the recommended answers, no questions
#   sudo sh LX-22-ssh-hardening.sh --apply --allow-keys team.pub   keep only the team's keys
#
# OPTIONS  (each answers a question in advance)
#   --allow-keys FILE   the team's public keys (authorized_keys format) or
#                       fingerprints (SHA256:...), one per line.  Every
#                       other key is removed, without asking
#   --remove-all-keys   remove every key (no questions)
#   --keep-all-keys     keep every key (no questions)
#   --gitea-keys keep|ask  the keys Gitea (or Forgejo, Gogs, GitLab) wrote for
#                       its users (they only run git, no shell): keep them all
#                       (default) or ask about each one
#   --root-login MODE   yes | no | key-only | leave   (PermitRootLogin)
#   --no-passwords      turn password logins OFF (key only).  Off by default:
#                       scoring engines usually log in with passwords
#   --no-forwarding     turn off TCP forwarding, tunnels and gateway ports
#   --strong-crypto     only modern ciphers, key exchange and MACs
#   --allow-users LIST  only these accounts may log in by SSH (space or comma
#                       separated; protected accounts are added)
#   --banner FILE       show this file before login
#   --set KEY=yes|no    answer one setting question (repeat).  KEYs:
#                       emptypw rhosts userenv x11 agent maxauth grace alive
#                       loglevel
#   --timer SECONDS     revert countdown (default 120)
#   --no-timer          apply with no revert timer (not advised)
#   --no-reload         install the config but do not reload sshd
#   --box NAME          splunk | webmail | ecomm | fileshare | gitea | web |
#                       other.  SSH is treated as scored on splunk, webmail
#                       and gitea (git over SSH): password logins stay on
#   --root DIR          treat DIR as / (tests; sshd is not reloaded)
#   --no-color          no colours
#   --batch             no questions: recommended answers
#   --help              this text plus the common options
#
# OUTPUTS  (under --out, in ssh-hardening-N/)
#   output.txt      everything shown on screen, without colour
#   summary.txt     settings before and after, keys kept and removed, checks
#   keys.txt        every key: account, file, type, fingerprint, comment,
#                   options, verdict, action
#   settings.txt    every setting: before, after, status
#   csv/            the same as CSV
#   revert.sh       undo this run (with --apply)
#
# WHAT IT CHANGES  (only with --apply)
#   /etc/ssh/sshd_config (marked block at the top; backed up first),
#   authorized_keys files (rewritten without the removed keys; backed up;
#   removed lines kept as evidence in quarantine/), ~/.ssh/rc and
#   /etc/ssh/sshrc if you say so (moved to quarantine/), and reloads sshd.
#   Every change has an undo line and is covered by the revert timer; a
#   revert also reloads sshd.
#
# DEPENDS ON
#   sshd (to read the current settings, test and reload), ssh-keygen
#   (fingerprints), awk; ss, or netstat / busybox netstat (Alpine).
#   BT_SSHD may name a stand-in sshd, BT_SSH_SOCKET=1 says ssh.socket is on
#   (the tests).
#
# TESTED ON
#   Ubuntu 24.04 with OpenSSH 9.6 under dash, bash, busybox sh, ksh93, mksh
#   and yash (fake root and stand-in sshd), and live: after --apply the kept
#   key still logs in and the removed key is refused.  Gitea key lines,
#   ssh.socket and busybox netstat with stand-ins (fake root).
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - Keep a second root session open while applying.
#   - Settings inside Match blocks apply on top of the global ones for
#     matching logins; they are reported, not changed.
#   - Keys from an AuthorizedKeysCommand or LDAP are not in files: reported.
#   - Accounts on the protected list keep their keys.
#   - --strong-crypto can lock out old clients (and an old scoring engine).
#
# DEBUGGING
#   --debug shows each key file and fingerprint; the candidate config and the
#   sshd -t output are in the log.
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
LX-22 SSH hardening and key cleanup - see every key and setting, keep or change each
  sudo sh LX-22-ssh-hardening.sh              look and plan (asks; changes nothing)
  sudo sh LX-22-ssh-hardening.sh --apply      ask, then change

  --allow-keys FILE    team keys/fingerprints: every other key is removed
  --remove-all-keys    remove every key        --keep-all-keys   keep every key
  --gitea-keys keep|ask   Gitea's user keys (git only, no shell): keep all, or ask each
  --box NAME           splunk | webmail | ecomm | fileshare | gitea | web | other
                       (asked; SSH is treated as scored on splunk, webmail and gitea)
  --banners / --no-banners   replace the login banners that show the OS (default yes)
  --root-login MODE    yes | no | key-only | leave
  --no-passwords       password logins OFF (key only) - careful, scoring uses passwords
  --no-forwarding      TCP forwarding and tunnels off
  --strong-crypto      modern ciphers only (can lock out old clients)
  --allow-users LIST   only these accounts may log in by SSH
  --banner FILE        pre-login banner
  --set KEY=yes|no     answer a setting question: emptypw rhosts userenv x11
                       agent maxauth grace alive loglevel
  --timer SECONDS      revert countdown (default 120)   --no-timer
  --no-reload          install without reloading sshd
  --root DIR           treat DIR as / (tests)
  --no-color           no colours
  --help               show this text

USAGE
    cc_usage_common
}

# ---- Options ----------------------------------------------------------------
BOX=""; BANNERS=""; ALLOWKEYS=""; KEYMODE=""; GKEYS=""; ROOTMODE=""; NOPW=""; NOFWD=""; STRONG=""; ALLOWUSERS=""; AUSET=0; BANNER=""
SETS=""; TIMER=120; NOTIMER=0; NORELOAD=0; R=""; COLOR=1
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --allow-keys)      [ $# -ge 2 ] || cc_die 2 "--allow-keys needs a file"; [ -r "$2" ] || cc_die 2 "--allow-keys: cannot read $2"; ALLOWKEYS=$2; KEYMODE=allow; shift 2 ;;
        --remove-all-keys) [ "$KEYMODE" = allow ] && cc_die 2 "use --allow-keys or --remove-all-keys, not both"; KEYMODE=all; shift ;;
        --keep-all-keys)   KEYMODE=keep; shift ;;
        --gitea-keys)      [ $# -ge 2 ] || cc_die 2 "--gitea-keys needs keep or ask"; GKEYS=$2; shift 2 ;;
        --box)             [ $# -ge 2 ] || cc_die 2 "--box needs splunk, webmail, ecomm, fileshare, gitea, web or other"; BOX=$2; shift 2 ;;
        --banners)         BANNERS=Y; shift ;;
        --no-banners)      BANNERS=N; shift ;;
        --root-login)      [ $# -ge 2 ] || cc_die 2 "--root-login needs yes, no, key-only or leave"; ROOTMODE=$2; shift 2 ;;
        --no-root-login)   ROOTMODE=no; shift ;;
        --root-key-only)   ROOTMODE=key-only; shift ;;
        --keep-root-login) ROOTMODE=leave; shift ;;
        --no-passwords)    NOPW=Y; shift ;;
        --no-forwarding)   NOFWD=Y; shift ;;
        --strong-crypto)   STRONG=Y; shift ;;
        --allow-users)     [ $# -ge 2 ] || cc_die 2 "--allow-users needs a list"; ALLOWUSERS=$(printf '%s' "$2" | tr ',' ' '); AUSET=1; shift 2 ;;
        --banner)          [ $# -ge 2 ] || cc_die 2 "--banner needs a file"; [ -r "$2" ] || cc_die 2 "--banner: cannot read $2"; BANNER=$(cc_abspath "$2"); shift 2 ;;
        --set)             [ $# -ge 2 ] || cc_die 2 "--set needs KEY=yes|no"; SETS="$SETS $2"; shift 2 ;;
        --timer)           [ $# -ge 2 ] || cc_die 2 "--timer needs seconds"; TIMER=$2; shift 2 ;;
        --no-timer)        NOTIMER=1; shift ;;
        --no-reload)       NORELOAD=1; shift ;;
        --root)            [ $# -ge 2 ] || cc_die 2 "--root needs a folder"; [ -d "$2" ] || cc_die 2 "--root: not a folder: $2"
                           R=$(cd "$2" && pwd); [ "$R" = / ] && R=""; shift 2 ;;
        --no-color|--no-colour) COLOR=0; shift ;;
        --help|-h)         usage; exit 0 ;;
        *)                 cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
case "$BOX" in ''|splunk|webmail|ecomm|fileshare|gitea|web|other) ;; *) cc_die 2 "--box must be splunk, webmail, ecomm, fileshare, gitea, web or other" ;; esac
case "$GKEYS" in ''|keep|ask) ;; *) cc_die 2 "--gitea-keys must be keep or ask" ;; esac
case "$ROOTMODE" in y|yes) ROOTMODE=yes ;; n|no) ROOTMODE=no ;; k|key-only) ROOTMODE=key-only ;; l|leave) ROOTMODE=leave ;; '') ;; *) cc_die 2 "--root-login must be yes, no, key-only or leave" ;; esac
case "$TIMER" in ''|*[!0-9]*) cc_die 2 "--timer needs a whole number of seconds" ;; esac
for _s in $SETS; do
    case "$_s" in
        emptypw=*|rhosts=*|userenv=*|x11=*|agent=*|maxauth=*|grace=*|alive=*|loglevel=*) ;;
        *) cc_die 2 "--set: unknown setting '${_s%%=*}' (emptypw rhosts userenv x11 agent maxauth grace alive loglevel)" ;;
    esac
    case "${_s#*=}" in yes|no) ;; *) cc_die 2 "--set $_s: the answer must be yes or no" ;; esac
done

cc_init "LX-22" "SSH hardening and key cleanup" changes
cc_detect_os
[ -z "$R" ] && [ "$CC_APPLY" = 1 ] && cc_require_root
cc_use_numbered_dir ssh-hardening
CC_CSV_DIR="$CC_RUN_DIR/csv"
mkdir -p "$CC_CSV_DIR" || cc_die 3 "cannot create $CC_CSV_DIR"
W="$CC_RUN_DIR/.work"; mkdir -p "$W" || cc_die 3 "cannot create $W"
cc_color_init
[ "$COLOR" = 1 ] || { C_RED=""; C_YEL=""; C_GRN=""; C_CYN=""; C_GRY=""; C_OFF=""; }
OUTF="$CC_RUN_DIR/output.txt"
grep -v '\[NOTE\]\|\[DEBUG\]' "$CC_LOG" >"$OUTF" 2>/dev/null || : >"$OUTF"
# shellcheck disable=SC2034  # CC_TEE is read by the library's log functions
CC_TEE=$OUTF
header() { cc_show "" ""; cc_show "$C_CYN" "==========[ $1 ]=========="; }
CONF="$R/etc/ssh/sshd_config"
SSHD=${BT_SSHD:-$(cc_which sshd)} || SSHD=""
KEYGEN=$(cc_which ssh-keygen) || KEYGEN=""
: >"$W/report"
report() { printf '%s\n' "$*" >>"$W/report"; }
nologin() { case "$1" in */nologin|*/false|*/sync|*/shutdown|*/halt|'') return 0 ;; esac; return 1; }

cc_show "$C_CYN" "LX-22 SSH hardening | host $CC_HOST | $([ "$CC_APPLY" = 1 ] && echo 'APPLY: changes are made after the questions' || echo 'DRY RUN: nothing is changed') | results in $CC_RUN_DIR"
cc_show "" "Legend: ${C_GRN}[ok] already right${C_OFF}   ${C_YEL}[~] would change  [*] check by hand${C_OFF}   ${C_RED}[!] looks planted${C_OFF}"
[ -n "$R" ] && cc_show "$C_GRY" "Acting on $R as if it were / (sshd is not reloaded)"

# ---- 1/5  SSH now ---------------------------------------------------------------------
header "1/5  how SSH is set up now"
# Effective settings: sshd -T on a live box, else the config file (first
# value outside Match, which is what sshd uses), else sshd's default.
: >"$W/eff"
if [ -z "$R" ] && [ -n "$SSHD" ] && [ -z "${BT_SSHD:-}" ]; then
    "$SSHD" -T 2>/dev/null >"$W/eff"
    _ver=$("$SSHD" -V 2>&1 | head -n 1)
    [ -n "$_ver" ] && cc_show "" "  sshd:     $_ver"
fi
[ -f "$CONF" ] || cc_show "$C_YEL" "  No $CONF: the SSH server is not installed here (or configured elsewhere)."
# rootword VALUE -> the PermitRootLogin value in plain words.
rootword() {
    case "$1" in
        prohibit-password|without-password) echo "key-only ($1)" ;;
        forced-commands-only) echo "key-only, forced commands ($1)" ;;
        yes) echo "yes (password or key)" ;;
        no) echo "no (root cannot log in by SSH)" ;;
        *) echo "$1" ;;
    esac
}
cur() {  # cur KEY DEFAULT -> the value in effect now
    _k=$(printf '%s' "$1" | tr 'A-Z' 'a-z')
    _v=$(awk -v k="$_k" '$1 == k { $1 = ""; sub(/^ /, ""); print; exit }' "$W/eff")
    [ -n "$_v" ] || _v=$(awk -v k="$_k" 'tolower($1) == "match" { exit } tolower($1) == k { $1 = ""; sub(/^ /, ""); print; exit }' "$CONF" 2>/dev/null)
    printf '%s' "${_v:-$2}" | tr 'A-Z' 'a-z'
}
_ports=$(cur port 22 | tr '\n' ' ')
cc_show "" "  Port(s):  $_ports    Root login: $(rootword "$(cur permitrootlogin prohibit-password)")    Password logins: $(cur passwordauthentication yes)"
# Ubuntu 24.04 and Mint 22: systemd holds the port (ssh.socket) and starts
# an sshd for each login, so no sshd is listening.  BT_SSH_SOCKET=1 in tests.
SOCKET=0
if [ -n "${BT_SSH_SOCKET:-}" ]; then SOCKET=$BT_SSH_SOCKET
elif [ -z "$R" ] && [ "$CC_INIT" = systemd ] && systemctl is-active -q ssh.socket 2>/dev/null; then SOCKET=1; fi
# listeners PROGRAM -> "addr:port ..." that PROGRAM listens on (ss, else
# netstat, else busybox netstat on Alpine).
listeners() {
    if cc_have ss; then ss -ltnp 2>/dev/null | awk -v p="\"$1\"" 'index($0, p) { print $4 }'
    else { netstat -ltnp 2>/dev/null || busybox netstat -ltnp 2>/dev/null; } | awk -v p="/$1" '$1 ~ /^tcp/ { n = $NF; if (substr(n, length(n) - length(p) + 1) == p || index(n, p " ")) print $4 }'
    fi | tr '\n' ' '
}
if [ -z "$R" ] || [ -n "${BT_SSH_SOCKET:-}" ]; then
    if [ "$SOCKET" = 1 ]; then
        cc_show "" "  Listening: $(listeners systemd)(ssh.socket: systemd starts an sshd for each login, so a new config counts from the next login)"
    else
        _l=$(listeners sshd)
        if [ -n "$_l" ]; then cc_show "" "  Listening: $_l"; else cc_show "$C_YEL" "  sshd is not listening right now."; fi
    fi
fi
# Things only a person can judge.
if [ -f "$CONF" ]; then
    awk 'tolower($1) == "match" { m = $0; next }
         m != "" && tolower($1) ~ /^(permitrootlogin|passwordauthentication|permitemptypasswords|authorizedkeysfile|authorizedkeyscommand|forcecommand|permituserenvironment|allowtcpforwarding)$/ {
             print "a Match block [" m "] changes " $1 " for those logins: " $0 }
         m == "" && tolower($1) ~ /^(authorizedkeyscommand|authorizedprincipalscommand|trustedusercakeys)$/ && tolower($2) != "none" {
             print "sshd gets keys from outside the key files: " $0 " - check it is the team'"'"'s" }' "$CONF" >>"$W/report"
    for _d in "$R/etc/ssh/sshd_config.d"/*.conf; do
        [ -f "$_d" ] && cc_show "$C_GRY" "  also read: ${_d#"$R"} ($(grep -Ev '^[[:space:]]*(#|$)' "$_d" | tr '\n' ';' | cut -c1-100))"
    done
fi
if [ -z "$R" ]; then
    ps -eo user=,args= 2>/dev/null | awk '$2 ~ /sshd$/ && ($0 ~ / -f / || $0 ~ / -p /) { $1 = ""; print "an extra sshd is running with its own config or port:" $0 }' >>"$W/report"
fi
for _f in /etc/ssh/sshrc $(awk -F: '$6 != "" { print $6 "/.ssh/rc" }' "$R/etc/passwd" 2>/dev/null | sort -u); do
    [ -f "$R$_f" ] && printf '%s\n' "$_f" >>"$W/rcfiles"
done
if [ -s "$W/report" ]; then while IFS= read -r _l; do cc_show "$C_YEL" "  [*] $_l"; done <"$W/report"; fi

# ---- 2/5  Keys ------------------------------------------------------------------------
header "2/5  SSH keys: who can log in without a password"
AWK_KEY='
function iskeytype(t) { return t ~ /^(ssh-(rsa|dss|ed25519)|ecdsa-sha2-nistp[0-9]+|sk-[a-z0-9-]+@openssh\.com|ssh-[a-z0-9-]+-cert-v01@openssh\.com)$/ }  # awk, not shell: posix-ok
function parse(line,   rest, i, c, q, n, f) {  # awk, not shell: posix-ok
    K_opts = ""; K_type = ""; K_blob = ""; K_comment = ""
    sub(/^[ \t]+/, "", line)
    if (line == "" || line ~ /^#/) return 0
    n = split(line, f, /[ \t]+/)
    if (iskeytype(f[1])) { K_type = f[1]; K_blob = f[2]; rest = line; sub(/^[^ \t]+[ \t]+[^ \t]+[ \t]*/, "", rest); K_comment = rest; return 1 }
    q = 0
    for (i = 1; i <= length(line); i++) {
        c = substr(line, i, 1)
        if (c == "\"") q = !q
        else if ((c == " " || c == "\t") && !q) break
    }
    K_opts = substr(line, 1, i - 1); rest = substr(line, i); sub(/^[ \t]+/, "", rest)
    n = split(rest, f, /[ \t]+/)
    if (!iskeytype(f[1])) return 0
    K_type = f[1]; K_blob = f[2]; sub(/^[^ \t]+[ \t]+[^ \t]+[ \t]*/, "", rest); K_comment = rest
    return 1
}'
fingerprint() {
    [ -n "$KEYGEN" ] || return 0
    printf '%s %s\n' "$1" "$2" >"$W/fp.pub"
    "$KEYGEN" -l -f "$W/fp.pub" 2>/dev/null | awk '{ print $2 }'
}
[ -n "$KEYGEN" ] || cc_show "$C_YEL" "  ssh-keygen not found: keys are shown by their end, not their fingerprint."
: >"$W/allowed"
if [ -n "$ALLOWKEYS" ]; then
    awk "$AWK_KEY"'{ l = $0; sub(/^[ \t]+/, "", l); if (l ~ /^SHA256:/) { split(l, a, /[ \t]/); print "F " a[1]; next }
                     if (parse(l)) print "K " K_type " " K_blob }' "$ALLOWKEYS" >"$W/allow.raw"
    while read -r _k _t _b; do
        if [ "$_k" = F ]; then printf '%s\n' "$_t" >>"$W/allowed"
        else printf '%s\n' "$_b" >>"$W/allowed"; _fp=$(fingerprint "$_t" "$_b"); [ -n "$_fp" ] && printf '%s\n' "$_fp" >>"$W/allowed"; fi
    done <"$W/allow.raw"
    [ -s "$W/allowed" ] || cc_die 2 "--allow-keys: no keys or fingerprints found in $ALLOWKEYS"
fi
# Where keys live: AuthorizedKeysFile from sshd, else the config, else defaults.
AKF=$(awk '$1 == "authorizedkeysfile" { $1 = ""; sub(/^ /, ""); print }' "$W/eff")
[ -n "$AKF" ] || AKF=$(awk 'tolower($1) == "authorizedkeysfile" && !m { $1 = ""; sub(/^ /, ""); print; exit } tolower($1) == "match" { m = 1 }' "$CONF" 2>/dev/null)
[ -n "$AKF" ] || AKF=".ssh/authorized_keys .ssh/authorized_keys2"
# $W/keys: n|user|uid|file|line|type|blob|comment|opts|fp|verdict|why|default
: >"$W/keys"; : >"$W/seen"; _n=0
awk -F: '$6 != "" { print $1 ":" $3 ":" $6 ":" $7 }' "$R/etc/passwd" 2>/dev/null >"$W/users"
while IFS=: read -r _u _uid _h _sh; do
    for _pat in $AKF; do
        _f=$(printf '%s' "$_pat" | sed "s|%h|$_h|g; s|%u|$_u|g; s|%%|%|g")
        case "$_f" in /*) ;; *) _f="$_h/$_f" ;; esac
        _pf="$R$_f"
        [ -e "$_pf" ] || [ -h "$_pf" ] || continue
        grep -qxF "$_pf" "$W/seen" && continue
        printf '%s\n' "$_pf" >>"$W/seen"
        if [ -h "$_pf" ]; then report "$_f ($_u) is a link to $(ls -l "$_pf" | sed 's/.*-> //'): check it by hand"; continue; fi
        [ -r "$_pf" ] || { report "$_f ($_u) cannot be read (run as root)"; continue; }
        _age=old; [ -n "$(find "$_pf" -prune -mtime -7 2>/dev/null)" ] && _age=recent
        awk "$AWK_KEY"'{ if (parse($0)) print NR "|" K_type "|" K_blob "|" K_comment "|" K_opts }' "$_pf" >"$W/k"
        while IFS='|' read -r _ln _t _b _c _o; do
            _n=$((_n + 1)); _fp=$(fingerprint "$_t" "$_b")
            [ -n "$_fp" ] || _fp="...$(printf '%s' "$_b" | awk '{ print substr($0, length($0) - 11) }')"
            _v=ok; _why=""; _d=Y
            # Gitea / Forgejo / Gogs / GitLab write their users' keys with a
            # forced command that only runs git (no shell).  Anything more in
            # that command (; | & $ ...) is not theirs.
            case "$_o" in *command=*)
                _fc=$(printf '%s' "$_o" | sed -n 's/.*command="\([^"]*\)".*/\1/p')
                case "$_fc" in
                    *[\;\|\&\$\`\<\>]*) ;;
                    *gitea*" serv key-"[0-9]*|*forgejo*" serv key-"[0-9]*|*gogs*" serv key-"[0-9]*|*gitlab-shell*" key-"[0-9]*)
                        _v=gitea; _why="a Gitea user's key: it can only run git (push and pull), no shell. Gitea wrote it; manage it in Gitea (Site Administration, the user, SSH keys)" ;;
                esac ;;
            esac
            [ "$_v" = ok ] && case "$_o" in *command=*|*environment=*) _v=planted; _why="has a forced command or environment ($_o): runs something at every login with this key"; _d=N ;; esac
            if [ "$_v" = ok ] && [ "$_uid" -gt 0 ] && [ "$_uid" -lt 1000 ]; then _v=planted; _why="on a service account ($_u): service accounts do not log in"; _d=N; fi
            if [ "$_v" = ok ] && nologin "$_sh"; then _v=planted; _why="$_u has no login shell ($_sh) but has a key"; _d=N; fi
            if [ "$_v" = ok ] && [ "$_f" != "$_h/.ssh/authorized_keys" ] && [ "$_f" != "$_h/.ssh/authorized_keys2" ]; then _v=check; _why="kept outside the home folder ($_f)"; fi
            if [ "$_v" = ok ] && [ "$_age" = recent ]; then _v=check; _why="the key file changed in the last 7 days"; fi
            [ "$_v" = ok ] && [ "$_uid" = 0 ] && { _v=check; _why="logs in as root"; }
            _act=""
            # Gitea's keys follow --gitea-keys (asked below), not the key flags.
            [ "$_v" = gitea ] || case "$KEYMODE" in
                all)   _act=remove ;;
                keep)  _act=keep ;;
                allow) if grep -qxF "$_b" "$W/allowed" || grep -qxF "$_fp" "$W/allowed"; then _act=keep; else _act=remove; fi ;;
            esac
            if cc_is_protected account "$_u" && [ "$CC_FORCE_SCORED" != 1 ]; then _act=keep; _why="${_why:+$_why; }the account is on the protected list"; fi
            printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' "$_n" "$_u" "$_uid" "$_f" "$_ln" "$_t" "$_b" "$_c" "$_o" "$_fp" "$_v" "$_why" "$_d" "$_act" >>"$W/keys"
            case "$_v" in planted) _col=$C_RED; _tag="[!]" ;; check) _col=$C_YEL; _tag="[*]" ;; *) _col=$C_GRN; _tag="[ok]" ;; esac
            # Many Gitea keys: one line each would bury the rest.
            if [ "$_v" = gitea ]; then printf '%s\n' "$_f" >>"$W/gitea"; continue; fi
            cc_show "$_col" "  $_tag key #$_n  $_u  $_t $_fp  ${_c:-(no comment)}"
            cc_show "$C_GRY" "        file: $_f$([ "$_age" = recent ] && echo ' (changed in the last 7 days)')"
            [ -n "$_why" ] && cc_show "$_col" "        $_why"
        done <"$W/k"
    done
done <"$W/users"
[ "$_n" -eq 0 ] && cc_show "$C_GRN" "  [ok] no SSH keys on any account"
NGIT=0
if [ -s "$W/gitea" ]; then
    NGIT=$(grep -c . "$W/gitea")
    cc_show "$C_GRN" "  [ok] $NGIT Gitea user key(s) in $(sort -u "$W/gitea" | tr '\n' ' ')(git only, no shell; listed in keys.txt)"
fi

# ---- 3/5  Questions -------------------------------------------------------------------
header "3/5  questions (each one lists the answers it takes; Enter = the one in capitals)"
# yn QUESTION DEFAULT(Y|N) YES-MEANS NO-MEANS -> 0 for y, 1 for n.
yn() {
    cc_choose "$1" "$2" "y=$3" "n=$4"
    [ "$CC_CHOICE" = y ]
}
if [ -z "$BOX" ]; then
    cc_choose "Which box is this?" o "s=splunk" "w=webmail" "e=ecomm" "f=fileshare: Samba or NFS" "g=gitea (git over SSH may be scored)" "b=web: a ticket, help-desk or shop site" "o=other"
    case "$CC_CHOICE" in s) BOX=splunk ;; w) BOX=webmail ;; e) BOX=ecomm ;; f) BOX=fileshare ;; g) BOX=gitea ;; b) BOX=web ;; *) BOX=other ;; esac
fi
SCORED=0
case "$BOX" in splunk|webmail)
    SCORED=1
    cc_show "$C_YEL" "  SSH is SCORED on $BOX ($BOX-ssh): the scoring engine logs in, probably with a password. Password logins stay on and nothing here blocks it unless you say so." ;;
gitea)
    SCORED=1
    cc_show "$C_YEL" "  Git over SSH may be SCORED on gitea (a clone or push through the git account). Password logins stay on, the git account and its Gitea keys are kept, and nothing here blocks it unless you say so." ;;
esac
# Gitea's user keys: all kept, or one by one.
if [ "$NGIT" -gt 0 ]; then
    if [ -z "$GKEYS" ]; then
        cc_choose "Gitea keeps $NGIT user key(s) for git over SSH (they only run git, no shell). What to do with them?" k \
            "k=keep them all (Gitea manages them; look at them in its web admin)" "o=one by one"
        case "$CC_CHOICE" in o) GKEYS=ask ;; *) GKEYS=keep ;; esac
    fi
    if [ "$GKEYS" = keep ]; then
        awk -F'|' 'BEGIN { OFS = "|" } $11 == "gitea" && $14 == "" { $14 = "keep" } { print }' "$W/keys" >"$W/keys.g" && mv "$W/keys.g" "$W/keys"
    fi
fi
# Keys, one by one, unless a flag already decided.
: >"$W/keydec"
while IFS='|' read -r _n _u _uid _f _ln _t _b _c _o _fp _v _why _d _act; do
    if [ -z "$_act" ]; then
        if yn "Keep key #$_n ($_u, $_fp, ${_c:-no comment})?$([ -n "$_why" ] && echo " [$_why]")" "$_d" \
            "yes, keep it (this key can still log in)" "no, remove it (backup kept; that key can no longer log in)"; then _act=keep; else _act=remove; fi
    fi
    printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' "$_n" "$_u" "$_f" "$_ln" "$_t" "$_fp" "$_c" "$_o" "$_v" "$_why" "$_act" "$_uid" >>"$W/keydec"
done <"$W/keys"
_rootkeys=$(awk -F'|' '$12 == 0 && $11 == "keep"' "$W/keydec" | grep -c .)

# rc files: commands run at every SSH login.
: >"$W/rcq"
if [ -s "$W/rcfiles" ]; then
    while IFS= read -r _f; do
        cc_show "$C_RED" "  [!] $_f runs at every SSH login: $(grep -Ev '^[[:space:]]*(#|$)' "$R$_f" | head -n 1 | cut -c1-100)"
        yn "Move $_f to quarantine?" Y "yes, move it (it stops running at every login; backup kept)" "no, leave it" && printf '%s\n' "$_f" >>"$W/rcq"
    done <"$W/rcfiles"
fi

# Root login.
_rnow=$(cur permitrootlogin prohibit-password)
_rpw=$(awk -F: '$1 == "root" { print ($2 == "" || $2 ~ /^[!*]/) ? "no" : "yes" }' "$R/etc/shadow" 2>/dev/null)
if cc_is_protected account root && [ "$CC_FORCE_SCORED" != 1 ]; then
    ROOTMODE=leave; cc_show "$C_GRY" "  Root login: left as it is ($(rootword "$_rnow")): root is on the protected list."
elif [ -z "$ROOTMODE" ]; then
    # Never default to locking root out of SSH: key-only only when root keeps a key.
    if [ "$_rootkeys" -gt 0 ] || [ "$_rpw" = no ]; then _rd=key-only; else _rd=leave; fi
    [ "$_rd" = leave ] && cc_show "$C_YEL" "  root has a password and no SSH key that stays, so key-only would lock root out of SSH: the default is l (leave)."
    cc_choose "Allow root to log in over SSH? (now: $(rootword "$_rnow"))" "$(printf '%s' "$_rd" | cut -c1)" \
        "y=yes, with a password or a key (not recommended)" \
        "n=no, root cannot log in over SSH at all (log in as yourself, then sudo)" \
        "k=key-only, root needs an SSH key; passwords are refused" \
        "l=leave it as it is"
    case "$CC_CHOICE" in y) ROOTMODE=yes ;; n) ROOTMODE=no ;; k) ROOTMODE=key-only ;; *) ROOTMODE=leave ;; esac
fi

# One question per setting.  Format: key|sshd lines|question|why|default|now-key|now-default|want
# The question is skipped when the setting is already what we want.
ans() {  # ans KEY QUESTION DEFAULT YES-MEANS NO-MEANS -> 0 = yes, from --set or a question
    for _s in $SETS; do [ "${_s%%=*}" = "$1" ] && { [ "${_s#*=}" = yes ]; return; }; done
    yn "$2" "$3" "$4" "$5"
}
: >"$W/lines"
q() {  # q KEY WANT-KEY WANT-VALUE NOW-DEFAULT DEFAULT QUESTION -- why
    _qk=$1; _wk=$2; _wv=$3; _nd=$4; _qd=$5; _qq=$6; _qw=$7
    _now=$(cur "$_wk" "$_nd")
    if [ "$_now" = "$(printf '%s' "$_wv" | tr 'A-Z' 'a-z')" ]; then
        cc_show "$C_GRN" "  [ok] $_wk is already $_wv"
        printf '%s %s\n' "$_wk" "$_wv" >>"$W/lines"
        return 0
    fi
    cc_show "$C_GRY" "        $_qw"
    if ans "$_qk" "$_qq (now: $_now)" "$_qd" "yes, set $_wk $_wv" "no, leave it ($_wk $_now)"; then printf '%s %s\n' "$_wk" "$_wv" >>"$W/lines"; fi
    return 0
}
q emptypw  PermitEmptyPasswords no  no Y "Turn OFF logins with an empty password?" "Accounts with no password could log in over SSH with nothing at all."
q rhosts   HostbasedAuthentication no no Y "Turn OFF host-based logins (.rhosts/.shosts trust)?" "Old trust files let anyone on a 'trusted' machine log in with no password."
[ "$(cur ignorerhosts yes)" = yes ] || q rhosts IgnoreRhosts yes yes Y "Ignore .rhosts files?" "Same as above: .rhosts lists hosts that get in with no password."
q userenv  PermitUserEnvironment no no Y "Stop users setting environment variables at login (~/.ssh/environment)?" "A planted ~/.ssh/environment can set LD_PRELOAD and run code at every login."
q x11      X11Forwarding no no Y "Turn OFF X11 forwarding?" "Graphical forwarding: not needed on a server, and a way to attack the admin's screen."
q agent    AllowAgentForwarding no yes Y "Turn OFF agent forwarding?" "Anyone who is root here could use a forwarded agent to log in elsewhere as you."
q maxauth  MaxAuthTries 4 6 Y "Limit password/key tries per connection to 4?" "Slows down password guessing. Does not affect normal logins."
q grace    LoginGraceTime 30 120 Y "Drop connections that have not logged in after 30 seconds?" "Stops half-open connections piling up. A person typing a password has plenty of time."
q alive    ClientAliveInterval 300 0 Y "Check idle sessions every 5 minutes and drop dead ones?" "Cleans up abandoned sessions (ClientAliveInterval 300, ClientAliveCountMax 2). Open sessions you use stay up."
grep -q '^ClientAliveInterval' "$W/lines" && printf 'ClientAliveCountMax 2\n' >>"$W/lines"
q maxstart MaxStartups 10:30:60 10:30:100 Y "Drop floods of half-open logins (MaxStartups 10:30:60)?" "Logins still typing a password beyond 10 are dropped at random, all at 60. Slows brute force; normal logins are not affected."
if [ -f "$R/etc/debian_version" ]; then
    q debbanner DebianBanner no yes Y "Hide the OS version in the SSH greeting (DebianBanner no)?" "The greeting now says which Ubuntu/Debian build this is. The OpenSSH version itself stays: it cannot be hidden without rebuilding sshd."
fi
q loglevel LogLevel VERBOSE info Y "Log the fingerprint of the key used at every login (LogLevel VERBOSE)?" "Then the auth log (and LX-41) shows which key got in. Only adds log lines."
# The ones that can break something are asked with default no.
_pw=$(cur passwordauthentication yes)
if [ "$_pw" = yes ]; then
    cc_show "$C_GRY" "        Key-only logins stop password guessing completely, but scoring engines usually log in with a PASSWORD: that check would fail."
    if [ "$NOPW" = Y ] || { [ -z "$NOPW" ] && yn "Turn OFF password logins (key only)? (now: yes)" N "yes, keys only ($([ "$SCORED" = 1 ] && echo "the scored SSH check on $BOX WILL FAIL" || echo "a scoring check that logs in with a password will FAIL"))" "no, keep password logins"; }; then
        printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\n' >>"$W/lines"
        awk -F'|' '$11 == "keep" && $12 != 0' "$W/keydec" | grep -q . || cc_show "$C_RED" "  [!] No account except root keeps a key: after this, only root can log in (with a key)."
    fi
fi
if [ "$(cur allowtcpforwarding yes)" != no ]; then
    cc_show "$C_GRY" "        Port forwarding lets anyone who logs in tunnel to other machines through this box (pivoting). Some apps tunnel on purpose."
    if [ "$NOFWD" = Y ] || { [ -z "$NOFWD" ] && yn "Turn OFF TCP forwarding, tunnels and gateway ports? (now: $(cur allowtcpforwarding yes))" N "yes, turn them off" "no, leave them on"; }; then
        printf 'AllowTcpForwarding no\nPermitTunnel no\nGatewayPorts no\nAllowStreamLocalForwarding no\n' >>"$W/lines"
    fi
fi
cc_show "$C_GRY" "        Modern ciphers only: drops old algorithms, but an old client or scoring engine may no longer connect."
if [ "$STRONG" = Y ] || { [ -z "$STRONG" ] && yn "Allow only modern ciphers, key exchange and MACs?" N "yes, modern only (a very old client or scoring engine may not connect)" "no, keep the defaults"; }; then
    printf 'KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512\n' >>"$W/lines"
    printf 'Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\n' >>"$W/lines"
    printf 'MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256\n' >>"$W/lines"
fi
[ "$SCORED" = 1 ] && [ "$AUSET" = 0 ] && cc_show "$C_YEL" "        SSH is scored here: if you limit accounts, include the one the scoring engine logs in with."
if [ "$AUSET" = 0 ]; then
    cc_show "$C_GRY" "        AllowUsers: ONLY the accounts listed may log in by SSH. Strong, but easy to lock out the scoring engine or yourself."
    cc_ask_text "Only these accounts may log in by SSH? Type the names separated by spaces, or press Enter for no limit" ""
    ALLOWUSERS=$(printf '%s' "$CC_ANSWER" | tr ',' ' ')
fi
if [ -n "$ALLOWUSERS" ]; then
    _au=$ALLOWUSERS
    if [ -n "$CC_PROTECTED" ]; then
        for _p in $(awk -F',' 'tolower($1) ~ /account/ { gsub(/[ "\r]/, "", $2); print $2 }' "$CC_PROTECTED"); do
            case " $_au " in *" $_p "*) ;; *) _au="$_au $_p" ;; esac
        done
    fi
    # The account Gitea's keys are on (git): git over SSH logs in as it.
    for _p in $(awk -F'|' '$11 == "gitea" && $14 != "remove" { print $2 }' "$W/keys" | sort -u); do
        case " $_au " in *" $_p "*) ;; *) _au="$_au $_p"; cc_show "$C_GRY" "        $_p added: Gitea's git over SSH logs in as it" ;; esac
    done
    printf 'AllowUsers %s\n' "$_au" >>"$W/lines"
fi
# Login banners: /etc/issue and /etc/issue.net name the OS and version, and
# the update-motd scripts print more after login.  Replaced with a plain
# warning; the SSH pre-login banner shows the same text.
BANNER_TEXT="Authorized use only. All activity on this system is monitored and logged."
_issue_os=$(cat "$R/etc/issue" "$R/etc/issue.net" 2>/dev/null | grep -iE 'ubuntu|debian|centos|red hat|fedora|alpine|rocky|alma|suse|kernel|\\[rmsvn]' | head -n 1)
_motd_x=$(find "$R/etc/update-motd.d" -type f -perm -u+x 2>/dev/null | grep -c .)
if [ -z "$BANNERS" ]; then
    if [ -n "$_issue_os$(grep -c . "$R/etc/issue" 2>/dev/null | grep -v '^0$')" ] || [ "$_motd_x" -gt 0 ]; then
        cc_show "$C_GRY" "        The login banners tell the red team the OS and version${_issue_os:+ (now: $_issue_os)}."
        if yn "Replace the login banners with a plain warning?" Y "yes, replace /etc/issue, /etc/issue.net, show it before SSH login, and turn off the update-motd scripts" "no, leave them"; then BANNERS=Y; else BANNERS=N; fi
    else BANNERS=N; fi
fi
[ "$BANNERS" = Y ] && [ -z "$BANNER" ] && printf 'Banner /etc/issue.net\n' >>"$W/lines"
case "$ROOTMODE" in yes) printf 'PermitRootLogin yes\n' >>"$W/lines" ;; no) printf 'PermitRootLogin no\n' >>"$W/lines" ;; key-only) printf 'PermitRootLogin prohibit-password\n' >>"$W/lines" ;; esac
[ -n "$BANNER" ] && printf 'Banner %s\n' "$BANNER" >>"$W/lines"

# ---- 4/5  The plan --------------------------------------------------------------------
header "4/5  the plan"
SCSV=$(cc_csv_new settings "setting,before,after,status")
NSET=0
{ printf '# >>> BT LX-22 (sshd uses the first value it reads, so this block wins)\n'; cat "$W/lines"; printf '# <<< BT LX-22\n'; } >"$W/block"  # text, not a here-string: posix-ok
while read -r _k _v; do
    # The value in effect now: the first one sshd reads (an older LX-22 block included).
    _b=$(awk -v k="$(printf '%s' "$_k" | tr 'A-Z' 'a-z')" 'tolower($1) == "match" { exit } tolower($1) == k { $1 = ""; sub(/^ /, ""); print; exit }' "$CONF" 2>/dev/null)
    if [ "$(printf '%s' "$_b" | tr 'A-Z' 'a-z')" = "$(printf '%s' "$_v" | tr 'A-Z' 'a-z')" ]; then _st="already ok"
    else _st=$([ "$CC_APPLY" = 1 ] && echo changed || echo "would change"); NSET=$((NSET + 1)); cc_show "$C_YEL" "  [~] $_k: ${_b:-(default)} -> $_v"; fi
    cc_csv_row "$SCSV" "$_k" "${_b:-(default)}" "$_v" "$_st"
done <"$W/lines"
[ "$NSET" -eq 0 ] && cc_show "$C_GRN" "  [ok] no sshd setting to change"
NRM=$(awk -F'|' '$11 == "remove"' "$W/keydec" | grep -c .)
NKEEP=$(awk -F'|' '$11 == "keep"' "$W/keydec" | grep -c .)
[ "$NRM" -gt 0 ] && awk -F'|' '$11 == "remove" { printf "  [~] remove key #%s (%s, %s, %s) from %s\n", $1, $2, $6, ($7 == "" ? "no comment" : $7), $3 }' "$W/keydec" >"$W/rmshow" && while IFS= read -r _l; do cc_show "$C_YEL" "$_l"; done <"$W/rmshow"
[ -s "$W/rcq" ] && while IFS= read -r _f; do cc_show "$C_YEL" "  [~] move $_f to quarantine"; done <"$W/rcq"
NBAN=0
if [ "$BANNERS" = Y ]; then
    for _f in /etc/issue /etc/issue.net; do
        [ "$(cat "$R$_f" 2>/dev/null)" = "$BANNER_TEXT" ] && continue
        NBAN=$((NBAN + 1)); cc_show "$C_YEL" "  [~] $_f -> \"$BANNER_TEXT\""
    done
    if [ "$_motd_x" -gt 0 ]; then NBAN=$((NBAN + 1)); cc_show "$C_YEL" "  [~] turn off $_motd_x update-motd script(s) (chmod -x; they print the OS after login)"; fi
fi
cc_show "" "  Keys: $NKEEP kept, $NRM removed.  Password logins: $(grep -q '^PasswordAuthentication no' "$W/lines" && echo 'turned OFF' || echo 'left on')."
KCSV=$(cc_csv_new keys "number,user,file,type,fingerprint,comment,options,verdict,why,action")
while IFS='|' read -r _n _u _f _ln _t _fp _c _o _v _why _act _uid; do
    cc_csv_row "$KCSV" "$_n" "$_u" "$_f" "$_t" "$_fp" "$_c" "$_o" "$_v" "$_why" "$([ "$CC_APPLY" = 1 ] && [ "$_act" = remove ] && echo removed || echo "$_act")"
done <"$W/keydec"

# Candidate config: our block, then the file without any older block.
_cfg_status="not changed"
if [ -f "$CONF" ]; then
    awk '/^# >>> BT LX-22/ { skip = 1 } !skip { print } /^# <<< BT LX-22/ { skip = 0 }' "$CONF" >"$W/rest"  # awk regex: posix-ok
    cat "$W/block" "$W/rest" >"$W/sshd_config.new"
    if cmp -s "$W/sshd_config.new" "$CONF"; then _cfg_status="already in place"
    elif [ -z "$SSHD" ]; then _cfg_status="not changed: sshd not found, so the new config cannot be tested"
    elif ! "$SSHD" -t -f "$W/sshd_config.new" >"$W/sshd_t" 2>&1; then
        cat "$W/sshd_t" >>"$CC_LOG"; CC_N_FAIL=$((CC_N_FAIL + 1))
        _cfg_status="FAILED: sshd -t rejected the new config, so it is NOT installed: $(head -n 1 "$W/sshd_t")"
        cc_show "$C_RED" "  [x] $_cfg_status"
    else
        _cfg_status="ready (passed sshd -t)"
        cc_show "$C_GRN" "  [ok] the new config passed sshd -t"
    fi
fi

# ---- 5/5  Apply -----------------------------------------------------------------------
header "5/5  apply"
[ "$_cfg_status" = "already in place" ] && NSET=0
NRC=$(grep -c . "$W/rcq" 2>/dev/null); case "$NRC" in ''|*[!0-9]*) NRC=0 ;; esac
NCH=$((NSET + NRM + NRC + NBAN))
APPLIED=0; TIMER_ON=0; _reload="not needed"
result() { if [ "$1" -eq 0 ]; then echo changed; else echo failed; fi; }
sshd_listening() { [ -n "$(listeners sshd)" ]; }
sshd_reload_cmd() {
    if [ "$CC_INIT" = systemd ]; then echo 'systemctl reload ssh 2>/dev/null || systemctl reload sshd'
    elif cc_have rc-service; then echo 'rc-service sshd reload'
    else echo 'kill -HUP "$(cat /run/sshd.pid 2>/dev/null || cat /var/run/sshd.pid)"'; fi
}
if [ "$NCH" -eq 0 ]; then
    cc_show "$C_GRN" "  [ok] Nothing to change."
elif [ "$CC_APPLY" != 1 ]; then
    cc_show "$C_GRY" "  $NCH change(s) planned. Dry run: nothing was changed. Run again with --apply (keep a second root session open)."
elif ! yn "Apply these $NCH change(s) now?" Y "yes, apply them (a revert timer undoes them unless you confirm from a NEW session)" "no, change nothing"; then
    cc_show "$C_GRY" "  Not applied. The plan is in $CC_RUN_DIR"
else
    APPLIED=1
    if [ -z "$R" ] && [ "$NOTIMER" != 1 ]; then
        cc_timer_start "$TIMER"; TIMER_ON=1
        cc_show "$C_YEL" "  [*] Revert timer started: everything is undone in $((TIMER / 60)):$(printf '%02d' $((TIMER % 60))) unless you confirm at the end."
    fi
    _q=$CC_QUIET; CC_QUIET=1
    # Keys: rewrite each file without the removed lines (evidence kept).
    awk -F'|' '$11 == "remove" { print $3 }' "$W/keydec" | sort -u >"$W/kfiles"
    while IFS= read -r _f; do
        _pf="$R$_f"
        awk -F'|' -v f="$_f" '$3 == f && $11 == "remove" { print $4 }' "$W/keydec" >"$W/drop"
        awk 'NR == FNR { d[$1] = 1; next } !(FNR in d)' "$W/drop" "$_pf" >"$W/kept"
        awk 'NR == FNR { d[$1] = 1; next } (FNR in d)' "$W/drop" "$_pf" >"$W/removed"
        cc_guard path "$_f" || { cc_show "$C_YEL" "  [-] $_f is protected: left alone"; continue; }
        cc_backup_file "$_pf" || continue
        (umask 077; mkdir -p "$(dirname "$CC_QUAR_DIR$_f")" && cp "$W/removed" "$CC_QUAR_DIR$_f.removed")
        # cp onto the existing file keeps its owner and mode.
        if cc_run "remove $(grep -c . "$W/drop") key(s) from $_f" cp "$W/kept" "$_pf"; then cc_show "$C_GRN" "  [+] removed $(grep -c . "$W/drop") key(s) from $_f (copy in quarantine/)"
        else cc_show "$C_RED" "  [x] could not rewrite $_f (immutable? lsattr $_f; chattr -i $_f)"; fi
    done <"$W/kfiles"
    while IFS= read -r _f; do
        cc_quarantine "$R$_f"; _rc=$?
        if [ "$_rc" -eq 0 ]; then cc_show "$C_GRN" "  [+] moved $_f to quarantine"; elif [ "$_rc" -eq 4 ]; then cc_show "$C_YEL" "  [-] $_f is protected: left alone"; else cc_show "$C_RED" "  [x] could not move $_f"; fi
    done <"$W/rcq"
    if [ "$BANNERS" = Y ] && [ "$NBAN" -gt 0 ]; then
        for _f in /etc/issue /etc/issue.net; do
            [ "$(cat "$R$_f" 2>/dev/null)" = "$BANNER_TEXT" ] && continue
            if [ -f "$R$_f" ]; then cc_backup_file "$R$_f" || continue
            else cc_undo_add "remove $_f (made by LX-22)" "rm -f $(cc_shquote "$R$_f")"; fi
            if cc_run "write the plain banner to $_f" sh -c 'printf "%s\n" "$1" >"$2"' sh "$BANNER_TEXT" "$R$_f"; then cc_show "$C_GRN" "  [+] $_f: plain warning, no OS name"
            else cc_show "$C_RED" "  [x] could not write $_f"; fi
        done
        find "$R/etc/update-motd.d" -type f -perm -u+x 2>/dev/null | while IFS= read -r _m; do
            cc_undo_add "turn $_m back on" "chmod +x $(cc_shquote "$_m")"
            cc_run "turn off $_m" chmod -x "$_m" || cc_show "$C_RED" "  [x] could not change $_m"
        done
        [ "$_motd_x" -gt 0 ] && cc_show "$C_GRN" "  [+] $_motd_x update-motd script(s) turned off (chmod -x)"
    fi
    # sshd_config: installed only if it passed sshd -t.
    case "$_cfg_status" in
        "ready"*)
            if cc_guard path /etc/ssh/sshd_config; then
                # A revert puts the file back and then reloads sshd (undo lines run newest first).
                [ -z "$R" ] && [ "$NORELOAD" != 1 ] && [ "$SOCKET" != 1 ] && cc_undo_add "reload sshd after the config is put back" "$(sshd_reload_cmd)"
                if cc_backup_file "$CONF" && cc_run "install the hardened sshd_config" cp "$W/sshd_config.new" "$CONF"; then
                    _cfg_status="installed (passed sshd -t)"; cc_show "$C_GRN" "  [+] sshd_config: block of $(grep -c . "$W/lines") setting(s) installed at the top"
                else _cfg_status="FAILED to install"; cc_show "$C_RED" "  [x] could not install sshd_config"; fi
            else _cfg_status="not changed (protected)"; fi ;;
    esac
    CC_QUIET=$_q
    case "$_cfg_status" in installed*)
        if [ "$SOCKET" = 1 ]; then _reload="not needed: ssh.socket starts a new sshd for each login, so the next login uses the new config (open sessions stay up)"; cc_show "$C_GRN" "  [ok] $_reload"
        elif [ -n "$R" ] || [ "$NORELOAD" = 1 ]; then _reload="not reloaded (--no-reload or --root): run 'sshd -t' and reload sshd yourself"
        elif ! sshd_listening; then _reload="sshd is not running; the new config applies when it starts"
        else
            cc_run_quiet "reload sshd" sh -c "$(sshd_reload_cmd)"; sleep 2
            if sshd_listening; then _reload="reloaded; sshd still listening (open sessions stay up)"; cc_show "$C_GRN" "  [+] sshd reloaded and still listening"
            else
                cc_err "sshd is NOT listening after the reload - putting the old config back"
                _rb="$CC_BACKUP_DIR$(cc_abspath "$CONF")"; [ -f "$_rb" ] && cp -p "$_rb" "$CONF" 2>>"$CC_LOG"
                sh -c "$(sshd_reload_cmd)" >>"$CC_LOG" 2>&1 || "$SSHD" >>"$CC_LOG" 2>&1
                CC_N_FAIL=$((CC_N_FAIL + 1))
                _reload="FAILED: sshd stopped listening; old config restored$(sshd_listening && echo ', sshd is back' || echo ', START SSHD BY HAND')"
                cc_show "$C_RED" "  [x] $_reload"
            fi
        fi ;;
    esac
    if [ "$TIMER_ON" = 1 ]; then
        header "KEEP OR REVERT"
        cc_timer_finish || true
    fi
fi

# ---- Summary --------------------------------------------------------------------------
cc_csv_pretty "$SCSV" "$CC_RUN_DIR/settings.txt" 60
cc_csv_pretty "$KCSV" "$CC_RUN_DIR/keys.txt" 60
{
    printf 'LX-22 SSH hardening | host %s | %s | %s\n\n' "$CC_HOST" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$([ "$APPLIED" = 1 ] && echo APPLIED || echo 'DRY RUN - nothing changed')"
    printf 'sshd_config: %s\n' "$_cfg_status"
    printf 'sshd:        %s\n' "$_reload"
    printf '\nSettings:\n'
    awk "$CC_AWK_CSV"'NR > 1 { csvsplit($0, f); printf "  %-24s %-18s -> %-30s %s\n", f[1], substr(f[2], 1, 18), substr(f[3], 1, 30), f[4] }' "$SCSV"
    printf '\nKeys: %s kept, %s %s\n' "$NKEEP" "$NRM" "$([ "$APPLIED" = 1 ] && echo removed || echo 'to remove')"
    awk -F'|' '{ printf "  #%-3s %-10s %-8s %-46s %s%s\n", $1, $2, $11, $6, ($7 == "" ? "" : $7), ($9 == "ok" ? "" : "  <- " $9) }' "$W/keydec" | head -n 40
    if [ -s "$W/report" ]; then printf '\nCheck by hand:\n'; awk '{ l = "  " $0; if (length(l) > 220) l = substr(l, 1, 217) "..."; print l }' "$W/report"; fi
    printf '\n'
    [ "$APPLIED" = 1 ] || printf 'Nothing was changed.%s\n' "$([ "$CC_APPLY" = 1 ] || echo '  Run again with --apply (keep a second root session open).')"
    [ "$APPLIED" = 1 ] && [ "$TIMER_ON" = 1 ] && printf 'Undo at any time: sh %s/revert.sh --force\n' "$CC_RUN_DIR"
    printf 'All results: %s\n' "$CC_RUN_DIR"
} >"$CC_RUN_DIR/summary.txt"
header "SUMMARY"
awk -v R="$C_RED" -v Y="$C_YEL" -v G="$C_GRN" -v C="$C_CYN" -v D="$C_GRY" -v O="$C_OFF" '
    NR == 1                                  { print C $0 O; next }
    /^(sshd_config|sshd): +(FAILED|not changed: sshd)/ { print R $0 O; next }
    /^(sshd_config|sshd):/                   { print G $0 O; next }
    /^(Settings|Keys|Check by hand)/         { m = substr($0, 1, 1); print C $0 O; next }
    /^$/                                     { m = ""; print; next }
    m == "S" && / (changed|would change)$/   { print Y $0 O; next }
    m == "S"                                 { print G $0 O; next }
    m == "K" && /<- planted/                 { print R $0 O; next }
    m == "K" && /<- check/                   { print Y $0 O; next }
    m == "C"                                 { print Y $0 O; next }
    /^All results/                           { print D $0 O; next }
                                             { print }
' "$CC_RUN_DIR/summary.txt"
cat "$CC_RUN_DIR/summary.txt" >>"$OUTF"
rm -rf "$W"
cc_finish
