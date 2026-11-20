#!/bin/sh
# =============================================================================
# ID:       SV-01
# NAME:     Web and database enum
# ROLE:     Applications  (wave 1)
# KIND:     readonly - changes nothing on the host
# VERSION:  2.0.0
#
# PURPOSE
#   One run on a Linux/Unix host answers "what web sites and databases are on
#   this box, and what is wrong with them?":
#     web servers   Apache, nginx, lighttpd, Caddy, Tomcat and PHP-FPM: version,
#                   running or not, and the account they run as
#     sites         every virtual host / server block: name, port, TLS, web root
#     web roots     owner, files the web server can change, and the files that
#                   should not be there: web shells, PHP in upload folders,
#                   database dumps, .env and .git, backups, phpinfo pages
#     php           the risky php.ini settings for each PHP install
#     apps          WordPress, Joomla, Drupal, phpMyAdmin, Roundcube, MediaWiki,
#                   Moodle, Nextcloud, OpenCart, PrestaShop: version, and which
#                   database and database user they use (never the password)
#     mysql         MySQL / MariaDB: accounts with no password or remote root,
#                   databases, backdoor functions (UDFs), triggers and events
#     postgres      PostgreSQL: roles, superusers, databases, pg_hba "trust" rules
#     datastores    Redis, memcached, MongoDB, Elasticsearch, CouchDB: where they
#                   listen and whether they answer without a password
#   It replaces the separate web (SV-01) and database (SV-03) inventories in
#   the plan: one script per job keeps the kit small.
#
#   Output is layered like the Linux collector (SH-05): one page on screen,
#   everything in CSV files, every flag in flags.csv.
#
# USAGE
#   sudo sh SV-01-web-db-inventory.sh [options]
#   Run as root.  As a normal user it still works, but it cannot read most
#   configs, log in to the databases through their local socket, or see every
#   file in the web roots; the summary says which sections are partial.
#
# OPTIONS
#   --only a,b,c         run only these sections (names from --list)
#   --skip a,b,c         leave these sections out
#   --fast               skip reading file contents (web shell and phpinfo search)
#   --webroot DIR        also treat DIR as a web root (repeat for more)
#   --apache-conf FILE   read this Apache config file instead of asking Apache
#                        which files it uses (repeat for more; useful when the
#                        apachectl program is missing or broken)
#   --nginx-conf FILE    the same for nginx
#   --mysql-cnf FILE     MySQL client options file with a user and password, for
#                        when root cannot log in through the socket:
#                            [client]
#                            user=root
#                            password=...
#                        Keep it mode 600 and delete it after the run.
#   --max-flags N        HIGH/MED flags shown on screen (default 30)
#   --list               list the sections and exit
#   --help               this text plus the common options
#
# OUTPUTS  (under --out, in SV-01_<host>_<UTC time>/)
#   summary.txt        one page: what was found, counts, HIGH and MED flags
#   servers.csv        server,version,running,run_as,program,config
#   fpm_pools.csv      file,pool,user,group,listen
#   sites.csv          server,site,listen,tls,web_root,config
#   webroots.csv       path,owner,mode,files,code_files,owned_by_web_account,world_writable
#   files.csv          web_root,kind,path    (the files that should not be there)
#   php.csv            ini,sapi,setting,value
#   apps.csv           web_root,app,version,path,config,db_name,db_user,db_host
#   db_users.csv       engine,user,host,auth,empty_password,superuser,file_access,can_grant,notes
#   db_settings.csv    engine,setting,value
#   db_databases.csv   engine,database,tables,size_mb
#   db_objects.csv     engine,schema,kind,name,detail   (triggers, events, UDFs ...)
#   pg_hba.csv         line,type,database,user,address,method
#   datastores.csv     service,address,port,process,answers_without_password
#   flags.csv          severity,section,item,detail,time
#   raw/               apache -S and -M, nginx -T, server version output
#
# WHAT IT CHANGES
#   Nothing.  It reads config files and runs read-only queries (SELECT, SHOW).
#   It never records a password: app configs give only the database name, user
#   and host; database queries only ask WHETHER a password is empty.
#
# DEPENDS ON  (each has a fallback; a missing tool only thins a section)
#   apachectl/apache2ctl/httpd, nginx   to find the config files; otherwise the
#                                        usual config paths are read directly
#   mysql or mariadb client, psql        for the database sections
#   ss -> netstat                        for listening ports
#   find, grep, awk, sed, ps             present on every Unix
#   redis-cli, curl                      optional, for the no-password checks
#
# TESTED ON
#   Ubuntu 24.04 with Apache 2.4 + mod_php 8.3, nginx 1.24, MariaDB 10.11 and
#   PostgreSQL 16, as root, under dash, bash, busybox sh, ksh93, mksh and yash.
#   Not yet on RHEL (httpd), FreeBSD or with MySQL 8.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - Flags are pointers, not verdicts.  A web root owned by the web account is
#     normal for some WordPress installs; it is still how web shells get in.
#   - The web shell search looks for common patterns.  An obfuscated shell can
#     slip past it, and a security plugin's signature file can match it.
#   - Config parsing follows the usual layouts.  Unusual Include lines,
#     variables in paths or configs generated at run time can be missed: check
#     raw/apache_S.txt and raw/nginx_T.txt against sites.csv.
#   - Database accounts are only listed when the script can log in.  If it
#     cannot, the summary says so; give --mysql-cnf or run as root.
#
# DEBUGGING
#   --debug          shows each tool choice, file list and section timing
#   --only NAME      rerun one section
#   sh -x SV-01-...  traces every command
#   raw/*.txt        what the servers themselves reported
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

ALL_SECTIONS="servers sites paths runtimes webroots php apps mysql postgres datastores"

usage() {
    cat <<'USAGE'
SV-01 Web and database inventory - read-only look at web sites and databases
  sudo sh SV-01-web-db-inventory.sh [options]

  --only a,b,c         run only these sections
  --skip a,b,c         leave these sections out
  --fast               skip the web shell and phpinfo content search
  --webroot DIR        also scan DIR as a web root (repeatable)
  --apache-conf FILE   read this Apache config file directly (repeatable)
  --nginx-conf FILE    read this nginx config file directly (repeatable)
  --mysql-cnf FILE     MySQL client file with user and password ([client] section)
  --max-flags N        HIGH/MED flags shown on screen (default 30)
  --list               list the sections and exit
  --help               show this text

USAGE
    cc_usage_common
}

list_sections() {
    cat <<'LIST'
servers      web servers and PHP-FPM pools: version, running, run-as account
sites        virtual hosts and server blocks: name, port, TLS, web root, listing
paths        which URL path serves which folder or app (aliases, proxies, PHP, status pages)
runtimes     languages and app servers: PHP, Python, Node.js, Java, Ruby, .NET, dev servers
webroots     web root owners and modes, and files that should not be there
php          risky php.ini settings per PHP install
apps         WordPress, Joomla, Drupal, phpMyAdmin and others: version, database
mysql        MySQL / MariaDB accounts, settings, databases, UDFs, triggers
postgres     PostgreSQL roles, settings, databases, pg_hba rules
datastores   Redis, memcached, MongoDB, Elasticsearch, CouchDB exposure
LIST
}

# ---- Options ----------------------------------------------------------------
# Repeatable options collect newline-separated lists (paths may hold spaces).
NL='
'
ONLY=""; SKIP=""; FAST=""; MAXFLAGS=30; NODB=""; COLOR=1; ROOTSET=0
EXTRA_ROOTS=""; APACHE_FILES_GIVEN=""; NGINX_FILES_GIVEN=""; MYSQL_CNF=""
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --only)        [ $# -ge 2 ] || cc_die 2 "--only needs a list of sections"; ONLY=$2; shift 2 ;;
        --skip)        [ $# -ge 2 ] || cc_die 2 "--skip needs a list of sections"; SKIP=$2; shift 2 ;;
        --fast)        FAST=1; shift ;;
        --deep)        FAST=0; shift ;;
        --no-db)       NODB=1; shift ;;
        --db)          NODB=0; shift ;;
        --no-color|--no-colour) COLOR=0; shift ;;
        --webroot)     [ $# -ge 2 ] || cc_die 2 "--webroot needs a folder"
                       [ -d "$2" ] || cc_die 2 "--webroot: not a folder: $2"
                       EXTRA_ROOTS="$EXTRA_ROOTS$2$NL"; ROOTSET=1; shift 2 ;;
        --apache-conf) [ $# -ge 2 ] || cc_die 2 "--apache-conf needs a file"
                       [ -r "$2" ] || cc_die 2 "--apache-conf: cannot read $2"
                       APACHE_FILES_GIVEN="$APACHE_FILES_GIVEN$2$NL"; shift 2 ;;
        --nginx-conf)  [ $# -ge 2 ] || cc_die 2 "--nginx-conf needs a file"
                       [ -r "$2" ] || cc_die 2 "--nginx-conf: cannot read $2"
                       NGINX_FILES_GIVEN="$NGINX_FILES_GIVEN$2$NL"; shift 2 ;;
        --mysql-cnf)   [ $# -ge 2 ] || cc_die 2 "--mysql-cnf needs a file"
                       [ -r "$2" ] || cc_die 2 "--mysql-cnf: cannot read $2"
                       MYSQL_CNF=$2; shift 2 ;;
        --max-flags)   [ $# -ge 2 ] || cc_die 2 "--max-flags needs a number"; MAXFLAGS=$2; shift 2 ;;
        --list)        list_sections; exit 0 ;;
        --help|-h)     usage; exit 0 ;;
        *)             cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
case "$MAXFLAGS" in ''|*[!0-9]*) cc_die 2 "--max-flags needs a whole number" ;; esac

# check_names LIST -> stop with exit 2 if any name is not a section.
check_names() {
    for _cn in $(printf '%s' "$1" | tr ',' ' '); do
        case " $ALL_SECTIONS " in *" $_cn "*) ;; *) cc_die 2 "unknown section '$_cn' (see --list)" ;; esac
    done
}
# ---- Start ------------------------------------------------------------------
cc_init "SV-01" "Web and database enum" readonly
cc_use_numbered_dir web-enum
# CSV files go in csv/; the run folder gets a readable .txt table per file.
CC_CSV_DIR="$CC_RUN_DIR/csv"
mkdir -p "$CC_CSV_DIR" || cc_die 3 "cannot create $CC_CSV_DIR"
cc_detect_os
W="$CC_RUN_DIR/.work"          # scratch files; removed at the end
mkdir -p "$W" || cc_die 3 "cannot create $W"

# ---- Live output (linpeas style, like SH-05) ----------------------------------
# fd 3 is the real stdout, so a flag raised inside $( ... ) still reaches the
# screen.  output.txt gets the same lines without colour.
exec 3>&1
OUTF="$CC_RUN_DIR/output.txt"
grep -v '\[NOTE\]\|\[DEBUG\]' "$CC_LOG" >"$OUTF" 2>/dev/null || : >"$OUTF"
# shellcheck disable=SC2034  # read by the library's log functions
CC_TEE=$OUTF
if [ "$COLOR" = 1 ] && [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_RED=$(printf '\033[1;31m'); C_YEL=$(printf '\033[1;33m'); C_GRN=$(printf '\033[1;32m')
    C_CYN=$(printf '\033[1;36m'); C_GRY=$(printf '\033[0;90m'); C_OFF=$(printf '\033[0m')
else
    C_RED=""; C_YEL=""; C_GRN=""; C_CYN=""; C_GRY=""; C_OFF=""
fi
show() { printf '%s%s%s\n' "$1" "$2" "$C_OFF" >&3; printf '%s\n' "$2" >>"$OUTF"; }
show "$C_CYN" "SV-01 Web and database enum | host $CC_HOST | results in $CC_RUN_DIR"
show "" "Legend: ${C_RED}[!] FIX${C_OFF} fix now (HIGH)   ${C_YEL}[*] LOOK${C_OFF} look soon (MED)   ${C_GRN}green${C_OFF} what was found   ${C_GRY}grey${C_OFF} info"

# ---- Questions (Enter takes the answer in capitals) ---------------------------
show "" ""
show "$C_CYN" "==========[ setup ]=========="
if [ -z "$ONLY$SKIP" ]; then
    if ! cc_ask "Look at everything (web servers, URL paths, languages, web roots, PHP, apps, databases)?" Y "yes, every section" "no, let me pick"; then
        cc_ask_text "Which sections?" "servers sites paths runtimes webroots" "names separated by spaces, from: $ALL_SECTIONS"
        ONLY=$(printf '%s' "$CC_ANSWER" | tr ' ' ',')
    fi
fi
[ -n "$FAST" ] || { if cc_ask "Search file contents for web shells and phpinfo pages?" Y "yes, read the files (slower on big sites)" "no, names only (fast)"; then FAST=0; else FAST=1; fi; }
if [ "$ROOTSET" = 0 ]; then
    cc_ask_text "Other web folders to look in, besides the ones the web servers use?" "" "folders separated by spaces, like /opt/shop /srv/app"
    for _w in $CC_ANSWER; do
        if [ -d "$_w" ]; then EXTRA_ROOTS="$EXTRA_ROOTS$_w$NL"; else show "$C_YEL" "  [!] not a folder, skipped: $_w"; fi
    done
fi
[ -n "$NODB" ] || { if cc_ask "Log in to the databases (read-only) to list accounts, settings and databases?" Y "yes, read-only queries as root through the local socket" "no, config files only"; then NODB=0; else NODB=1; fi; }
SECTIONS=$ALL_SECTIONS
if [ -n "$ONLY" ]; then check_names "$ONLY"; SECTIONS=$(printf '%s' "$ONLY" | tr ',' ' '); fi
if [ -n "$SKIP" ]; then
    check_names "$SKIP"
    _keep=""
    for _s in $SECTIONS; do case ",$SKIP," in *",$_s,"*) ;; *) _keep="$_keep $_s" ;; esac; done
    SECTIONS=$_keep
fi

if [ "$NODB" = 1 ]; then
    _keep=""
    for _s in $SECTIONS; do case "$_s" in mysql|postgres) ;; *) _keep="$_keep $_s" ;; esac; done
    SECTIONS=$_keep
fi
IS_ROOT=0
cc_is_root && IS_ROOT=1
[ "$IS_ROOT" = 1 ] || cc_warn "not running as root: configs, database logins and some web root files will be missing"
TAB=$(printf '\t')
# Every external server query gets a time limit when 'timeout' exists, so a
# hung database cannot stall the run.  Used unquoted on purpose (empty = none).
TO=""
cc_have timeout && TO="timeout 20"

# Web shell patterns (ERE for grep -E): code run straight from a request,
# encoded eval, and the names of well-known shells.  Kept short on purpose:
# each line here is a known shell idiom, not a guess.
SHELL_RE='(eval|assert)[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|gzuncompress|str_rot13|\$_(GET|POST|REQUEST|COOKIE|SERVER))'
SHELL_RE="$SHELL_RE"'|(system|shell_exec|passthru|exec|popen|proc_open|pcntl_exec)[[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST|COOKIE)'
SHELL_RE="$SHELL_RE"'|create_function[[:space:]]*\(.{0,80}\$_(GET|POST|REQUEST)|`[[:space:]]*\$_(GET|POST|REQUEST)'
SHELL_RE="$SHELL_RE"'|Runtime\.getRuntime\(\)\.exec\([[:space:]]*request\.getParameter|FilesMan|c99shell|r57shell|b374k|WSO [0-9]'

# ---- Helpers (same pattern as SH-05) ----------------------------------------
# All loops read from files, never from a pipe: in dash and bash the right
# side of a pipe runs in a subshell and loses the variables it sets.

# sec_csv NAME HEADER -> create <run>/NAME.csv; its path is left in SEC_CSV.
sec_csv() {
    SEC_CSV=$(cc_csv_new "$1" "$2") || SEC_CSV=/dev/null
    SEC_FILES="$SEC_FILES $SEC_CSV"
}
# db_csv NAME HEADER -> like sec_csv, for the files MySQL and PostgreSQL share
#   (db_users.csv ...): created by whichever section runs first, then appended
#   to.  Their rows are counted per engine at the end of each section (ENGINE).
db_csv() {
    SEC_CSV="$CC_CSV_DIR/$1.csv"
    [ -f "$SEC_CSV" ] || SEC_CSV=$(cc_csv_new "$1" "$2") || SEC_CSV=/dev/null
    SEC_DBFILES="$SEC_DBFILES $SEC_CSV"
}
# flag SEVERITY ITEM DETAIL -> cc_flag with the current section filled in.
flag() {
    cc_flag "$1" "$SEC" "$2" "$3"
    case "$1" in
        HIGH) show "$C_RED" "  [!] FIX   $2: $3" ;;
        MED)  show "$C_YEL" "  [*] LOOK  $2: $3" ;;
    esac
    return 0
}
# emit_flags FILE -> turn lines "SEVERITY|ITEM|DETAIL" into flags.
emit_flags() {
    [ -s "$1" ] || return 0
    while IFS='|' read -r _ef_sev _ef_item _ef_detail; do
        case "$_ef_sev" in HIGH|MED|LOW) flag "$_ef_sev" "$_ef_item" "$_ef_detail" ;; esac
    done <"$1"
}
# say TEXT -> add a line to the summary's key-facts block.
say() { printf '%s\n' "$*" >>"$W/summary_lines"; show "$C_GRN" "  $*"; }
# note TEXT -> a short note on this section's row in the summary table.
note() { if [ -z "$SEC_NOTE" ]; then SEC_NOTE=$*; else SEC_NOTE="$SEC_NOTE; $*"; fi; }
# AWK_Q: q() quotes one CSV field, for awk programs that write CSV directly.
AWK_Q='function q(s) { gsub(/"/, "\"\"", s); gsub(/\r|\n/, " ", s); return "\"" s "\"" }'

# ps_users REGEX -> the accounts running processes whose name matches REGEX,
#   space separated, root first if present.
ps_users() { awk -v re="$1" '$2 ~ re { print $1 }' "$W/ps" | sort -u | tr '\n' ' ' | sed 's/ $//'; }

# run_as USER COMMAND-STRING -> run a shell command as another account (root
#   only).  runuser where it exists, else su in the Linux or BSD form.
run_as() {
    if cc_have runuser; then runuser -u "$1" -- sh -c "$2"
    elif [ "$(uname -s)" = Linux ]; then su "$1" -s /bin/sh -c "$2"
    else su -m "$1" -c "$2"
    fi
}

# nonlocal ADDRESS -> true when ADDRESS is reachable from other machines.
nonlocal() { case "$1" in 127.*|::1|localhost|::ffff:127.*) return 1 ;; *) return 0 ;; esac; }

# php_val FILE KEY-REGEX -> the first quoted value after KEY-REGEX in a PHP
#   config file, skipping comment lines.  Used only for database NAME, USER and
#   HOST; never call it for a password key.
php_val() {
    [ -r "$1" ] || return 0
    grep -v '^[[:space:]]*\(\*\|#\|//\|/\*\)' "$1" 2>/dev/null |
        sed -n "s/.*$2[^'\"]*['\"]\([^'\"]*\)['\"].*/\1/p" | head -n 1
}

# ---- Facts every section can use --------------------------------------------
# $W/ps      "user command" for every process
# $W/psargs  "user full-command-line"
# $W/listen  "proto|address|port|process" for every listening TCP socket
get_ps() {
    ps -eo user=,comm= >"$W/ps" 2>/dev/null || ps -axo user=,comm= >"$W/ps" 2>/dev/null ||
        ps -o user,comm 2>/dev/null | sed 1d >"$W/ps"
    ps -eo user=,args= >"$W/psargs" 2>/dev/null || ps -axo user=,args= >"$W/psargs" 2>/dev/null || : >"$W/psargs"
}
get_listen() {
    : >"$W/listen"
    if cc_have ss; then
        ss -ltnp 2>/dev/null | awk 'NR > 1 {
            a = $4; p = a; sub(/.*:/, "", p); sub(/:[^:]*$/, "", a); gsub(/[][]/, "", a); sub(/%.*/, "", a)
            pr = ""; if (match($0, /\(\("[^"]*"/)) pr = substr($0, RSTART + 3, RLENGTH - 4)
            print "tcp|" a "|" p "|" pr }' >"$W/listen"
    fi
    if [ ! -s "$W/listen" ] && cc_have netstat; then
        netstat -ltnp 2>/dev/null | awk '$1 ~ /^tcp/ && $6 == "LISTEN" {
            a = $4; p = a; sub(/.*:/, "", p); sub(/:[^:]*$/, "", a)
            pr = $7; sub(/^[0-9]+\//, "", pr); print "tcp|" a "|" p "|" pr }' >"$W/listen"
        # BSD form: "tcp4 0 0 *.22 *.* LISTEN", address and port joined by a dot.
        [ -s "$W/listen" ] || netstat -an 2>/dev/null | awk '$1 ~ /^tcp/ && $NF == "LISTEN" {
            a = $4; p = a; sub(/.*\./, "", p); sub(/\.[^.]*$/, "", a); print "tcp|" a "|" p "|" }' >"$W/listen"
    fi
    cc_debug "listening sockets: $(grep -c . "$W/listen")"
}

# ---- Web server detection (feeds servers, sites, webroots, apps) ------------
# Writes:
#   $W/servers   "server|version|running|run_as|program|config"
#   $W/webusers  accounts the web servers and PHP-FPM pools run as
#   $W/pools     "file|pool|user|group|listen"
detect_web() {
    : >"$W/servers"; : >"$W/webusers"; : >"$W/pools"
    # Apache.  apache2ctl (Debian) sets the environment the config needs, so
    # it is preferred over calling the apache2 program directly.
    APACHECTL=$(cc_first apache2ctl apachectl /usr/local/sbin/apachectl /usr/sbin/apachectl)
    [ -n "$APACHECTL" ] || APACHECTL=$(cc_first httpd apache2 /usr/sbin/httpd /usr/local/sbin/httpd)
    _au=$(ps_users '^(apache2|httpd|httpd-prefork|httpd-worker|apache)$')
    if [ -n "$APACHECTL" ] || [ -n "$_au" ]; then
        _ver=""; _root=""
        if [ -n "$APACHECTL" ]; then
            # shellcheck disable=SC2086
            _ver=$($TO "$APACHECTL" -v 2>/dev/null | sed -n 's/^Server version: *//p' | head -n 1)
            # shellcheck disable=SC2086
            cc_save apache_S $TO "$APACHECTL" -S
            _root=$(sed -n 's/^ServerRoot: *"\(.*\)"/\1/p' "$CC_LAST_SAVE" | head -n 1)
            # shellcheck disable=SC2086
            cc_save apache_M $TO "$APACHECTL" -M
        fi
        printf 'apache|%s|%s|%s|%s|%s\n' "${_ver:-unknown}" "$([ -n "$_au" ] && echo yes || echo no)" "$_au" "${APACHECTL:-not found}" "$_root" >>"$W/servers"
        printf '%s\n' $_au >>"$W/webusers"
    fi
    # nginx
    NGINX=$(cc_first nginx /usr/sbin/nginx /usr/local/sbin/nginx /usr/local/nginx/sbin/nginx)
    _nu=$(ps_users '^nginx')
    if [ -n "$NGINX" ] || [ -n "$_nu" ]; then
        _ver=""
        if [ -n "$NGINX" ]; then
            _ver=$("$NGINX" -v 2>&1 | sed -n 's/^nginx version: *//p' | head -n 1)
            # shellcheck disable=SC2086
            cc_save nginx_T $TO "$NGINX" -T
        fi
        printf 'nginx|%s|%s|%s|%s|%s\n' "${_ver:-unknown}" "$([ -n "$_nu" ] && echo yes || echo no)" "$_nu" "${NGINX:-not found}" "" >>"$W/servers"
        printf '%s\n' $_nu >>"$W/webusers"
    fi
    # lighttpd and Caddy: version and accounts only.
    _lb=$(cc_first lighttpd); _lu=$(ps_users '^lighttpd$')
    if [ -n "$_lb$_lu" ]; then
        _ver=""; [ -n "$_lb" ] && _ver=$("$_lb" -v 2>/dev/null | head -n 1)
        printf 'lighttpd|%s|%s|%s|%s|\n' "${_ver:-unknown}" "$([ -n "$_lu" ] && echo yes || echo no)" "$_lu" "${_lb:-not found}" >>"$W/servers"
        printf '%s\n' $_lu >>"$W/webusers"
    fi
    _cb=$(cc_first caddy); _cu=$(ps_users '^caddy$')
    if [ -n "$_cb$_cu" ]; then
        _ver=""; [ -n "$_cb" ] && _ver=$($TO "$_cb" version 2>/dev/null | head -n 1)
        printf 'caddy|%s|%s|%s|%s|\n' "${_ver:-unknown}" "$([ -n "$_cu" ] && echo yes || echo no)" "$_cu" "${_cb:-not found}" >>"$W/servers"
        printf '%s\n' $_cu >>"$W/webusers"
    fi
    # Tomcat runs as "java", so look for its main class in the command lines.
    _tu=$(awk '/org\.apache\.catalina/ { print $1 }' "$W/psargs" | sort -u | tr '\n' ' ' | sed 's/ $//')
    if [ -n "$_tu" ]; then
        _home=$(sed -n 's/.*-Dcatalina\.home=\([^ ]*\).*/\1/p' "$W/psargs" | head -n 1)
        _ver=""; [ -x "$_home/bin/version.sh" ] && _ver=$($TO sh "$_home/bin/version.sh" 2>/dev/null | sed -n 's/^Server version: *//p')
        printf 'tomcat|%s|yes|%s|java|%s\n' "${_ver:-unknown}" "$_tu" "$_home" >>"$W/servers"
        printf '%s\n' $_tu >>"$W/webusers"
    fi
    # PHP-FPM pools.  Unmatched globs stay literal, so each is checked with -d.
    for _d in /etc/php/*/fpm/pool.d /etc/php-fpm.d /etc/php*/php-fpm.d /usr/local/etc/php-fpm.d /etc/opt/remi/*/php-fpm.d; do
        [ -d "$_d" ] || continue
        for _f in "$_d"/*.conf; do
            [ -r "$_f" ] || continue
            awk -v f="$_f" '
                function out() { if (pool != "") print f "|" pool "|" u "|" g "|" l }  # awk, not shell: posix-ok
                /^[ \t]*[;#]/ { next }
                /^[ \t]*\[.*\][ \t]*$/ { out(); pool = $0; gsub(/[][ \t]/, "", pool); u = ""; g = ""; l = ""; next }
                { line = $0; sub(/[;#].*/, "", line); n = index(line, "="); if (!n) next
                  k = substr(line, 1, n - 1); v = substr(line, n + 1); gsub(/[ \t"]/, "", k); gsub(/^[ \t"]+|[ \t"]+$/, "", v)
                  if (k == "user") u = v; else if (k == "group") g = v; else if (k == "listen") l = v }
                END { out() }' "$_f" >>"$W/pools"
        done
    done
    awk -F'|' '$3 != "" { print $3 }' "$W/pools" >>"$W/webusers"
    _fu=$(ps_users '^php-fpm')
    if [ -s "$W/pools" ] || [ -n "$_fu" ]; then
        _fb=$(cc_first php-fpm php-fpm8.3 php-fpm8.2 php-fpm8.1 php-fpm8.0 php-fpm7.4 /usr/sbin/php-fpm)
        _ver=""; [ -n "$_fb" ] && _ver=$("$_fb" -v 2>/dev/null | head -n 1 | awk '{ print $1 " " $2 }')
        printf 'php-fpm|%s|%s|%s|%s|\n' "${_ver:-unknown}" "$([ -n "$_fu" ] && echo yes || echo no)" "$_fu" "${_fb:-not found}" >>"$W/servers"
    fi
    # The usual web accounts, when they exist, even if nothing runs as them now.
    for _u in www-data apache nginx http www lighttpd; do
        grep -q "^$_u:" /etc/passwd 2>/dev/null && printf '%s\n' "$_u" >>"$W/webusers"
    done
    grep -v '^root$' "$W/webusers" | grep . | sort -u >"$W/webusers.tmp"
    mv "$W/webusers.tmp" "$W/webusers"
    cc_debug "web servers: $(cut -d'|' -f1 "$W/servers" | tr '\n' ' ')  web accounts: $(tr '\n' ' ' <"$W/webusers")"
}

# ---- Config parsing (feeds sites and webroots) -------------------------------
# Writes:
#   $W/sites        "server|site|listen|tls|web_root|config"
#   $W/site_flags   "SEVERITY|item|detail"
#   $W/roots        "server|site|path"  every web root and alias target
parse_web_configs() {
    : >"$W/sites"; : >"$W/site_flags"; : >"$W/roots"; : >"$W/paths"
    # --- Apache: ask Apache which files it reads, else use the usual paths.
    if [ -n "$APACHE_FILES_GIVEN" ]; then
        printf '%s' "$APACHE_FILES_GIVEN" >"$W/apache_files"
    else
        : >"$W/apache_files"
        if [ -n "$APACHECTL" ]; then
            # shellcheck disable=SC2086
            $TO "$APACHECTL" -t -D DUMP_INCLUDES 2>/dev/null |
                awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^\//) print $i }' >"$W/apache_files"
        fi
        if [ ! -s "$W/apache_files" ]; then
            for _f in /etc/apache2/apache2.conf /etc/apache2/ports.conf /etc/apache2/sites-enabled/* /etc/apache2/conf-enabled/* \
                      /etc/httpd/conf/httpd.conf /etc/httpd/conf.d/*.conf /usr/local/etc/apache24/httpd.conf \
                      /usr/local/etc/apache24/Includes/*.conf /usr/local/apache2/conf/httpd.conf; do
                [ -f "$_f" ] && printf '%s\n' "$_f" >>"$W/apache_files"
            done
        fi
    fi
    set --
    while IFS= read -r _f; do [ -r "$_f" ] && set -- "$@" "$_f"; done <"$W/apache_files"
    cc_debug "apache config files: $#"
    if [ $# -gt 0 ]; then
        # sq holds a single quote: "\x27" is not understood by every awk.
        awk -v sites="$W/sites" -v ff="$W/site_flags" -v roots="$W/roots" -v paths="$W/paths" -v sq="'" '
            function unq(s) { gsub("^[\"" sq "]|[\"" sq "]$", "", s); return s }  # awk, not shell: posix-ok
            function emit(name, listen, tls, root, where) {  # awk, not shell: posix-ok
                print "apache|" name "|" listen "|" tls "|" root "|" where >> sites
                if (root != "") { print "apache|" name "|" root >> roots; print "apache|" name "|/|" root "|web root|" where >> paths }
            }
            function site() { return invh ? (vn != "" ? vn : "(default)") : "(main)" }  # awk, not shell: posix-ok
            {
                line = $0; sub(/^[ \t]+/, "", line)
                if (line == "" || line ~ /^#/) next
                n = split(line, w, /[ \t]+/); d = tolower(w[1])
                if (d == "listen") { p = w[2]; sub(/.*:/, "", p); ports = ports (ports != "" ? " " : "") p }
                else if (d ~ /^<virtualhost/) {
                    invh = 1; va = line; sub(/^<[^ \t]+[ \t]+/, "", va); sub(/>.*/, "", va)
                    vn = ""; vr = ""; vs = "no"; vw = FILENAME ":" FNR
                }
                else if (d == "</virtualhost>") { emit(vn != "" ? vn : "(default)", va, vs, vr, vw); invh = 0 }
                else if (d == "servername") { if (invh) vn = w[2]; else mn = w[2] }
                else if (d == "documentroot") {
                    v = unq(w[2])
                    if (invh) vr = v; else { mr = v; mw = FILENAME ":" FNR }
                    if (v == "/") print "HIGH|" FILENAME ":" FNR "|DocumentRoot is / : the whole disk can be read through the web site" >> ff
                }
                else if (d == "sslengine" && tolower(w[2]) == "on" && invh) vs = "yes"
                else if (d ~ /^<directory/) { dir = line; sub(/^<[^ \t]+[ \t]+/, "", dir); sub(/>.*/, "", dir); dir = unq(dir) }
                else if (d == "</directory>" || d == "</directorymatch>") dir = ""
                else if (d == "options") {
                    o = " " tolower(substr(line, length(w[1]) + 1)) " "
                    if ((o ~ /[ \t+]indexes[ \t]/ || o ~ /[ \t]all[ \t]/) && o !~ /-indexes/)
                        print "MED|" FILENAME ":" FNR "|directory listing is on (Options Indexes) for " (dir != "" ? dir : (invh ? "site " vn : "the whole server")) ": visitors can browse files" >> ff
                }
                else if (d == "servertokens") tokens = tolower(w[2])
                else if ((d == "alias" || d == "scriptalias") && n >= 3) {
                    t = unq(w[3]); if (t !~ /^\/usr\/share\/apache2\//) print "apache|alias " unq(w[2]) "|" t >> roots
                    print "apache|" site() "|" unq(w[2]) "|" t "|" (d == "scriptalias" ? "scripts (CGI)" : "alias") "|" FILENAME ":" FNR >> paths
                }
                else if (d == "proxypass" && n >= 3 && w[3] != "!") print "apache|" site() "|" w[2] "|" w[3] "|proxy to an app|" FILENAME ":" FNR >> paths
                else if (d ~ /^<location/) { loc = line; sub(/^<[^ \t]+[ \t]+/, "", loc); sub(/>.*/, "", loc); loc = unq(loc); lstat = 0; lreq = 0 }
                else if (d == "sethandler" && loc != "" && tolower(w[2]) ~ /^server-(status|info)$/) {
                    lstat = 1; print "apache|" site() "|" loc "|" tolower(w[2]) "|status page|" FILENAME ":" FNR >> paths
                    lwhere = FILENAME ":" FNR
                }
                else if (d == "require" && loc != "" && tolower(line) ~ /require[ \t]+(local|ip|host)/) lreq = 1
                else if (d == "</location>") {
                    if (lstat && !lreq) print "MED|" lwhere "|" loc " shows the server status (who is connected, what they ask for) to anyone: add Require local" >> ff
                    loc = ""
                }
            }
            END {
                if (mr != "") emit(mn != "" ? mn " (main)" : "(main)", ports, "no", mr, mw)
                if (NR > 0 && tokens != "prod" && tokens != "productonly")
                    print "LOW|apache ServerTokens|the version is shown in every response header and error page (set ServerTokens Prod)" >> ff
            }' "$@"
    fi
    # --- nginx: "nginx -T" prints every file it loads with a marker line.
    : >"$W/nginx_all"
    if [ -n "$NGINX_FILES_GIVEN" ]; then
        while IFS= read -r _f; do
            [ -r "$_f" ] && { printf '# configuration file %s:\n' "$_f"; cat "$_f"; } >>"$W/nginx_all"
        done <<EOF
$NGINX_FILES_GIVEN
EOF
    elif [ -f "$CC_RUN_DIR/raw/nginx_T.txt" ] && grep -q '^# configuration file ' "$CC_RUN_DIR/raw/nginx_T.txt"; then
        cp "$CC_RUN_DIR/raw/nginx_T.txt" "$W/nginx_all"
    else
        for _f in /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf /etc/nginx/sites-enabled/* /usr/local/etc/nginx/nginx.conf; do
            [ -f "$_f" ] && [ -r "$_f" ] && { printf '# configuration file %s:\n' "$_f"; cat "$_f"; } >>"$W/nginx_all"
        done
    fi
    if [ -s "$W/nginx_all" ]; then
        awk -v sites="$W/sites" -v ff="$W/site_flags" -v roots="$W/roots" -v users="$W/webusers" -v paths="$W/paths" '
            function sn() { return (nm != "" && nm != "_") ? nm : "(default)" }  # awk, not shell: posix-ok
            /^# configuration file .*:$/ { file = $0; sub(/^# configuration file /, "", file); sub(/:$/, "", file); ln = 0; next }
            {
                ln++; line = $0; sub(/#.*/, "", line); t = line; gsub(/^[ \t]+|[ \t]+$/, "", t)
                split(t, w, /[ \t]+/); d = w[1]; v = t; sub(/^[^ \t]+[ \t]*/, "", v); sub(/[ \t]*;$/, "", v)
                if (!insrv && t ~ /^server[ \t]*\{/) {
                    insrv = 1; sdepth = depth; li = ""; nm = ""; rt = ""; tls = "no"; where = file ":" ln
                } else if (insrv) {
                    if (t ~ /^location[ \t]/) { loc = t; sub(/^location[ \t]+/, "", loc); sub(/[ \t]*\{.*$/, "", loc); ldepth = depth }
                    if (loc != "" && (d == "proxy_pass" || d == "fastcgi_pass" || d == "uwsgi_pass" || d == "scgi_pass" || d == "grpc_pass"))
                        print "nginx|" sn() "|" loc "|" v "|" (d == "proxy_pass" ? "proxy to an app" : d == "fastcgi_pass" ? "PHP (FastCGI)" : d == "uwsgi_pass" ? "Python (uWSGI)" : d) "|" file ":" ln >> paths
                    if (loc != "" && (d == "root" || d == "alias")) print "nginx|" sn() "|" loc "|" v "|" d "|" file ":" ln >> paths
                    if (loc != "" && d == "stub_status") print "nginx|" sn() "|" loc "|stub_status|status page|" file ":" ln >> paths
                    if (d == "listen") { li = li (li != "" ? " " : "") v; if (v ~ /(^|[ \t])ssl/) tls = "yes" }
                    else if (d == "server_name") nm = v
                    else if (d == "ssl_certificate") tls = "yes"
                    else if (d == "root" || d == "alias") {
                        if (d == "root" && depth == sdepth + 1) rt = v
                        else print "nginx|" (nm != "" ? nm : "(default)") " location|" v >> roots
                    }
                    else if (d == "autoindex" && v == "on")
                        print "MED|" file ":" ln "|directory listing is on (autoindex) in server " (nm != "" ? nm : "(default)") ": visitors can browse files" >> ff
                } else {
                    if (d == "user") { u = v; sub(/[ \t].*/, "", u); print u >> users }
                    if (d == "server_tokens") tokens = v
                }
                depth += gsub(/\{/, "{", line); depth -= gsub(/\}/, "}", line)
                if (loc != "" && depth <= ldepth) loc = ""
                if (insrv && depth <= sdepth) {
                    if (rt != "") print "nginx|" sn() "|/|" rt "|web root|" where >> paths
                    if (nm == "" || nm == "_") nm = "(default)"
                    print "nginx|" nm "|" li "|" tls "|" rt "|" where >> sites
                    if (rt != "") print "nginx|" nm "|" rt >> roots
                    insrv = 0
                }
            }
            END { if (NR > 0 && tokens != "off") print "LOW|nginx server_tokens|the version is shown in every response header and error page (set server_tokens off)" >> ff }' "$W/nginx_all"
        sort -u "$W/webusers" | grep -v '^root$' >"$W/webusers.tmp"; mv "$W/webusers.tmp" "$W/webusers"
    fi
}

# build_webroots -> $W/webroots: one folder per line, existing folders only,
#   without folders that sit inside another listed folder (scanned once).
build_webroots() {
    {
        awk -F'|' '{ print $3 }' "$W/roots"
        for _d in /var/www /srv/www /srv/http /usr/share/nginx/html /usr/local/www /var/www/htdocs \
                  /opt/lampp/htdocs /usr/share/phpmyadmin /usr/share/roundcube /var/lib/roundcube; do
            printf '%s\n' "$_d"
        done
        printf '%s' "$EXTRA_ROOTS"
    } | sed 's|/*$||' | grep . >"$W/roots_all"
    : >"$W/roots_ok"
    while IFS= read -r _d; do
        [ -d "$_d" ] && [ "$_d" != "/" ] && printf '%s\n' "$_d" >>"$W/roots_ok"
    done <"$W/roots_all"
    sort -u "$W/roots_ok" | awk '{ for (k in keep) if (index($0, k "/") == 1) next; keep[$0] = 1; print }' >"$W/webroots"
    cc_debug "web roots: $(tr '\n' ' ' <"$W/webroots")"
}

# =============================================================================
# Sections
# =============================================================================

s_servers() {
    sec_csv servers "server,version,running,run_as,program,config"
    _F=$SEC_CSV
    if [ ! -s "$W/servers" ]; then note "no web server found"; return 0; fi
    while IFS='|' read -r _s _v _r _u _p _c; do
        cc_csv_row "$_F" "$_s" "$_v" "$_r" "$_u" "$_p" "$_c"
        # Workers running as root turn any web flaw into a root shell.  Apache
        # and nginx normally start as root and run workers as another account.
        if [ "$_r" = yes ] && [ "$_u" = root ]; then
            flag HIGH "$_s" "every $_s process runs as root: any flaw in a site gives a root shell"
        fi
    done <"$W/servers"
    sec_csv fpm_pools "file,pool,user,group,listen"
    _F=$SEC_CSV
    while IFS='|' read -r _f _p _u _g _l; do
        cc_csv_row "$_F" "$_f" "$_p" "$_u" "$_g" "$_l"
        [ "$_u" = root ] && flag HIGH "php-fpm pool $_p" "runs PHP as root ($_f): any PHP flaw gives a root shell"
    done <"$W/pools"
    _list=$(awk -F'|' '{ s = $1 " " $2; if ($3 == "yes") s = s " (running as " ($4 != "" ? $4 : "?") ")"; else s = s " (not running)"; printf "%s%s", (NR > 1 ? "; " : ""), s }' "$W/servers")
    say "Web servers: $_list"
    _pv=$(php -v 2>/dev/null | head -n 1 | awk '{ print $2 }')
    [ -n "$_pv" ] && say "PHP: $_pv"
}

s_sites() {
    sec_csv sites "server,site,listen,tls,web_root,config"
    _F=$SEC_CSV
    while IFS='|' read -r _s _n _l _t _r _w; do cc_csv_row "$_F" "$_s" "$_n" "$_l" "$_t" "$_r" "$_w"; done <"$W/sites"
    emit_flags "$W/site_flags"
    _n=$(grep -c . "$W/sites")
    [ "$_n" -gt 0 ] && say "Sites: $_n ($(awk -F'|' '{ printf "%s%s %s", (NR > 1 ? ", " : ""), $1, $2 }' "$W/sites" | cut -c1-160))"
    [ "$IS_ROOT" = 1 ] || note "partial: not root"
}

s_paths() {
    sec_csv paths "server,site,url_path,serves,kind,config"
    _F=$SEC_CSV
    sort -u "$W/paths" >"$W/paths.s"
    while IFS='|' read -r _sv _si _u _t _k _c; do
        cc_csv_row "$_F" "$_sv" "$_si" "$_u" "$_t" "$_k" "$_c"
    done <"$W/paths.s"
    _np=$(grep -c . "$W/paths.s"); _npx=$(grep -c '|proxy to an app|' "$W/paths.s")
    [ "$_np" -gt 0 ] && say "URL paths: $_np ($(grep -c '|web root|' "$W/paths.s") web roots, $(grep -c '|alias|' "$W/paths.s") aliases, $_npx proxied to an app, $(grep -c '|PHP (FastCGI)|' "$W/paths.s") PHP handlers)"
    # What each path leads to, worst first.
    awk -F'|' '
        $5 ~ /alias|root/ && $4 ~ /^\/(etc|root|home|boot|proc|var\/log)?\/?$/ { print "HIGH|" $2 " " $3 "|serves " $4 " to the web: system files can be downloaded" }
        $5 ~ /alias|root/ && $4 ~ /^\/(etc|root|var\/log)\// { print "HIGH|" $2 " " $3 "|serves " $4 " to the web: system files can be downloaded" }
        $5 == "proxy to an app" { a = $4; sub(/^[a-z]+:\/\//, "", a); print "LOW|" $2 " " $3 "|handed to an app at " a ": that app is part of the site (see runtimes)" }
        $5 == "scripts (CGI)" { print "LOW|" $2 " " $3 "|runs programs from " $4 ": check every file there" }' "$W/paths.s" >"$W/pf"
    emit_flags "$W/pf"
    # On screen: every path, as "site  /url  ->  what serves it".
    awk -F'|' '{ printf "    %-8s %-26s %-22s -> %s (%s)\n", $1, substr($2, 1, 26), $3, $4, $5 }' "$W/paths.s" | head -n 30 >"$W/pshow"
    while IFS= read -r _l; do show "" "$_l"; done <"$W/pshow"
    [ "$_np" -gt 30 ] && show "$C_GRY" "    ... $((_np - 30)) more in paths.txt"
    [ "$_np" = 0 ] && note "no web server config read"
    return 0
}

s_runtimes() {
    sec_csv runtimes "language,version,kind,detail,user,where"
    _F=$SEC_CSV
    : >"$W/rt"
    # Languages installed (version only).
    _pv=$(php -v 2>/dev/null | head -n 1 | awk '{ print $2 }')
    [ -n "$_pv" ] && printf 'PHP|%s|installed|php command|-|%s\n' "$_pv" "$(command -v php)" >>"$W/rt"
    for _d in /etc/php/*/; do [ -d "$_d" ] && printf 'PHP|%s|installed|configs for this version|-|%s\n' "$(basename "$_d")" "$_d" >>"$W/rt"; done
    for _l in python3:Python node:Node.js nodejs:Node.js java:Java ruby:Ruby dotnet:.NET go:Go perl:Perl; do
        _c=${_l%%:*}; _n=${_l#*:}
        cc_have "$_c" || continue
        case "$_c" in
            java) _v=$(java -version 2>&1 | sed -n 's/.*version "\([^"]*\)".*/\1/p' | head -n 1) ;;
            ruby) _v=$(ruby --version 2>/dev/null | awk '{ print $2 }') ;;
            go) _v=$(go version 2>/dev/null | awk '{ print $3 }') ;;
            dotnet) _v=$(dotnet --version 2>/dev/null) ;;
            perl) _v=$(perl -e 'print $^V' 2>/dev/null) ;;
            *) _v=$("$_c" --version 2>&1 | head -n 1 | awk '{ print $NF }') ;;
        esac
        _v=$(printf '%s' "$_v" | tr -d '|' | cut -c1-40)
        printf '%s|%s|installed|%s command|-|%s\n' "$_n" "${_v:-?}" "$_c" "$(command -v "$_c")" >>"$W/rt"
    done
    # App servers running now, from the full command lines.  Dev servers
    # (debug consoles, auto reload) let anyone who reaches them run code.
    awk -v tab="$TAB" '{
        u = $1; c = $0; sub(/^[^ \t]+[ \t]+/, "", c); l = tolower(c); k = ""; lang = ""; dev = 0
        if (l ~ /(^|\/)(gunicorn|uwsgi|uvicorn|daphne|hypercorn|waitress-serve)([ \t]|$)/) { lang = "Python"; k = "app server" }
        else if (l ~ /manage\.py[ \t]+runserver/ || l ~ /flask[ \t]+run/ || l ~ /werkzeug/) { lang = "Python"; k = "DEV server"; dev = 1 }
        else if (l ~ /(^|\/)python[0-9.]*[ \t].*\.py/ && l !~ /(unattended|networkd|apt|landscape|fail2ban|cloud-init|supervisord|bt)/) { lang = "Python"; k = "python program" }
        else if (l ~ /(^|\/)(node|nodejs)[ \t]/ || l ~ /(^|\/)pm2/) { lang = "Node.js"; k = (l ~ /--inspect/ ? "DEBUG port open" : (l ~ /(npm|yarn)[ \t]+(run[ \t]+)?(dev|start:dev)|nodemon|next[ \t]+dev/ ? "DEV server" : "app")); dev = (k != "app") }
        else if (l ~ /(npm|yarn)[ \t]+(run[ \t]+)?dev/) { lang = "Node.js"; k = "DEV server"; dev = 1 }
        else if (l ~ /(^|\/)java[ \t]/ && l !~ /catalina/) { lang = "Java"; k = (l ~ /-jar/ ? "jar app" : "java program"); if (l ~ /-agentlib:jdwp|-xdebug/) { k = "DEBUG port open"; dev = 1 } }
        else if (l ~ /catalina/) { lang = "Java"; k = "Tomcat" }
        else if (l ~ /(^|\/)(puma|unicorn|passenger|thin)([ \t:]|$)/) { lang = "Ruby"; k = "app server" }
        else if (l ~ /rails[ \t]+(s|server)([ \t]|$)/) { lang = "Ruby"; k = "DEV server"; dev = 1 }
        else if (l ~ /(^|\/)dotnet[ \t]/) { lang = ".NET"; k = "app" }
        else if (l ~ /(^|\/)php[0-9.]*[ \t]+(-[a-z]+[ \t]+)*-s[ \t]/) { lang = "PHP"; k = "DEV server (php -S)"; dev = 1 }
        if (lang != "") print lang "|-|" k "|" substr(c, 1, 150) "|" u "|running" (dev ? "|DEV" : "")
    }' "$W/psargs" >>"$W/rt"
    # App files in the usual places (not inside node_modules or vendor).
    for _d in $(cat "$W/webroots") /opt /srv /home; do
        [ -d "$_d" ] || continue
        find "$_d" -maxdepth 4 \( -name node_modules -o -name vendor -o -name .git -o -name site-packages \) -prune -o \
            -type f \( -name manage.py -o -name wsgi.py -o -name requirements.txt -o -name package.json -o -name Gemfile -o -name '*.war' -o -name pom.xml -o -name go.mod -o -name '*.csproj' -o -name composer.json \) -print 2>/dev/null
    done | sort -u | head -n 200 | while IFS= read -r _f; do
        case "$(basename "$_f")" in
            manage.py|wsgi.py|requirements.txt) _n=Python ;; package.json) _n=Node.js ;; Gemfile) _n=Ruby ;;
            *.war|pom.xml) _n=Java ;; go.mod) _n=Go ;; *.csproj) _n=.NET ;; composer.json) _n=PHP ;;
        esac
        printf '%s|-|app files|%s|%s|%s\n' "$_n" "$(basename "$_f")" "$(ls -ld "$_f" 2>/dev/null | awk '{ print $3 }')" "$(dirname "$_f")"
    done >>"$W/rt"
    # Programs on web-style ports that are not the known web servers.
    awk -F'|' '$3 ~ /^(80|443|3000|3001|4000|5000|5173|8000|8008|8080|8081|8443|8888|9000|9090)$/ && $4 !~ /^(apache2|httpd|nginx|lighttpd|caddy|php-fpm.*|haproxy|varnishd|traefik|splunkd|sshd)$/ {
        print ($4 == "" ? "unknown" : $4) "|-|listening|port " $3 " on " $2 "|-|" $2 ":" $3 "|PORT" }' "$W/listen" >>"$W/rt"
    _seen_lang=""
    while IFS='|' read -r _l _v _k _d _u _w _x; do
        cc_csv_row "$_F" "$_l" "$_v" "$_k" "$_d" "$_u" "$_w"
        case "$_x" in
            DEV)  flag HIGH "$_l $_k" "$_d (as $_u): development and debug servers let anyone who reaches them run code - stop it or keep it local" ;;
            PORT) flag MED "port ${_w##*:}" "$_l is serving web traffic on $_w: what is it? (not a known web server)" ;;
        esac
        [ "$_k" = running ] || [ "$_x" = DEV ] || case "$_k" in "app server"|app|"jar app"|Tomcat|"python program")
            [ "$_u" = root ] && flag MED "$_l $_k" "runs as root: a hole in the app gives root ($_d)" ;; esac
        case " $_seen_lang " in *" $_l "*) ;; *) _seen_lang="$_seen_lang $_l" ;; esac
    done <"$W/rt"
    # On screen: one line per language: versions, then what runs.
    awk -F'|' '{ k = $1; if ($3 == "installed") v[k] = v[k] (v[k] ? ", " : "") $2; else if ($6 ~ /^running/) r[k] = r[k] (r[k] ? "; " : "") $3 " as " $5; else if ($3 == "app files") a[k]++ }
        END { for (k in v) n[k] = 1; for (k in r) n[k] = 1; for (k in a) n[k] = 1
              for (k in n) printf "    %-9s %s%s%s\n", k, (v[k] ? "version " v[k] : "version ?"), (r[k] ? "  | running: " r[k] : ""), (a[k] ? "  | app folders: " a[k] : "") }' "$W/rt" | sort >"$W/rshow"
    while IFS= read -r _l; do show "" "$_l"; done <"$W/rshow"
    [ -n "$_seen_lang" ] && say "Languages / runtimes:$(printf '%s' "$_seen_lang" | sed 's/ \{1,\}/, /g; s/^, / /')"
    _nrun=$(grep -c '|running' "$W/rt")
    [ "$_nrun" -gt 0 ] && say "App servers running: $_nrun ($(awk -F'|' '$6 ~ /^running/ { print $1 " " $3 }' "$W/rt" | sort -u | tr '\n' ';' | sed 's/;$//; s/;/, /g'))"
    return 0
}

s_webroots() {
    sec_csv webroots "path,owner,mode,files,code_files,owned_by_web_account,world_writable"
    _FR=$SEC_CSV
    sec_csv files "web_root,kind,path"
    _FF=$SEC_CSV
    if [ ! -s "$W/webroots" ]; then note "no web root found"; return 0; fi
    : >"$W/notable"
    while IFS= read -r _r; do
        _own=$(ls -ld "$_r" 2>/dev/null | awk '{ print $3 }')
        _mode=$(ls -ld "$_r" 2>/dev/null | awk '{ print $1 }')
        _files=$(find "$_r" -xdev -type f 2>/dev/null | wc -l | tr -d ' ')
        _code=$(find "$_r" -xdev -type f \( -name '*.php' -o -name '*.php[0-9]' -o -name '*.phtml' -o -name '*.phar' \
                 -o -name '*.jsp' -o -name '*.cgi' -o -name '*.pl' -o -name '*.py' \) 2>/dev/null | wc -l | tr -d ' ')
        # Files owned by any web account: the web server can rewrite them.
        _wown=0
        while IFS= read -r _u; do
            _c=$(find "$_r" -xdev -user "$_u" 2>/dev/null | wc -l | tr -d ' ')
            _wown=$((_wown + _c))
        done <"$W/webusers"
        _ww=$(find "$_r" -xdev -perm -0002 ! -type l 2>/dev/null | wc -l | tr -d ' ')
        cc_csv_row "$_FR" "$_r" "$_own" "$_mode" "$_files" "$_code" "$_wown" "$_ww"
        [ "$_ww" -gt 0 ] && flag MED "$_r" "$_ww world-writable files or folders: any local account can change them (find $_r -xdev -perm -0002)"
        # Files that should not be in a web root.  Each find prints "kind|path".
        find "$_r" -xdev \( -name .git -o -name .svn -o -name .hg \) -prune -print 2>/dev/null | sed "s|^|vcs|" >>"$W/notable.k"
        find "$_r" -xdev -type f \( -name '.env' -o -name '.env.*' \) 2>/dev/null | sed "s|^|env|" >>"$W/notable.k"
        find "$_r" -xdev -type f \( -name '*.sql' -o -name '*.sql.gz' -o -name '*.sql.zip' -o -name '*.dump' \) 2>/dev/null | sed "s|^|dump|" >>"$W/notable.k"
        find "$_r" -xdev -type f \( -name '*.bak' -o -name '*.old' -o -name '*.orig' -o -name '*.save' -o -name '*.swp' -o -name '*~' \
             -o -name '*.zip' -o -name '*.tar' -o -name '*.tar.gz' -o -name '*.tgz' -o -name '*.7z' -o -name '*.rar' \) 2>/dev/null | sed "s|^|backup|" >>"$W/notable.k"
        find "$_r" -xdev -type f \( -path '*/upload*/*' -o -path '*/images/*' -o -path '*/img/*' -o -path '*/media/*' -o -path '*/files/*' \) \
             \( -name '*.php' -o -name '*.php[0-9]' -o -name '*.phtml' -o -name '*.phar' -o -name '*.jsp' -o -name '*.cgi' \) 2>/dev/null | sed "s|^|upload_code|" >>"$W/notable.k"
        find "$_r" -xdev -type f \( -name wp-config.php -o -name configuration.php -o -name settings.php -o -name config.php \
             -o -name config.inc.php -o -name LocalSettings.php -o -name parameters.php -o -name env.php \
             -o -name database.yml -o -name local.xml \) -perm -0004 2>/dev/null | sed "s|^|config_readable|" >>"$W/notable.k"
        if [ "$FAST" = 0 ]; then
            # Content search, limited to files under 2 MB (-size counts 512-byte blocks).
            find "$_r" -xdev -type f \( -name '*.php' -o -name '*.php[0-9]' -o -name '*.phtml' -o -name '*.phar' -o -name '*.inc' \
                 -o -name '*.jsp' -o -name '*.jspx' \) -size -4096 -exec grep -lE "$SHELL_RE" {} + 2>/dev/null | sed "s|^|webshell|" >>"$W/notable.k"
            # phpinfo pages are tiny test files; large files that mention phpinfo are code.
            find "$_r" -xdev -type f -name '*.php' -size -8 -exec grep -l 'phpinfo[[:space:]]*(' {} + 2>/dev/null | sed "s|^|phpinfo|" >>"$W/notable.k"
        fi
        # sed above wrote "kindPATH"; split the kind back off with the root attached.
        awk -v r="$_r" '{ k = $0; sub(/\/.*/, "", k); p = substr($0, length(k) + 1); print r "|" k "|" p }' "$W/notable.k" >>"$W/notable"
        rm -f "$W/notable.k"
    done <"$W/webroots"
    # Ownership: check every web root, including ones inside another (a site
    # folder under /var/www is scanned with /var/www but owned separately).
    sort -u "$W/roots_ok" >"$W/roots_own"
    while IFS= read -r _r; do
        _own=$(ls -ld "$_r" 2>/dev/null | awk '{ print $3 }')
        if grep -qx "$_own" "$W/webusers" 2>/dev/null; then
            flag MED "$_r" "owned by the web server account ($_own): an upload or code flaw lets an attacker change the site"
        fi
    done <"$W/roots_own"
    [ "$FAST" = 1 ] && note "fast: no web shell search"
    awk -F'|' -v csv="$_FF" "$AWK_Q"'{ print q($1) "," q($2) "," q($3) >> csv }' "$W/notable"
    # Flags: at most 5 per kind per web root individually, then one "and N more".
    awk -F'|' '
        BEGIN {
            sev["webshell"] = "HIGH";  txt["webshell"] = "looks like a web shell (runs commands from the request): read it, then quarantine"
            sev["upload_code"] = "HIGH"; txt["upload_code"] = "program file in an upload or media folder: the usual place for an uploaded web shell"
            sev["dump"] = "HIGH";      txt["dump"] = "database dump inside the web root: anyone may be able to download it"
            sev["env"] = "HIGH";       txt["env"] = ".env file inside the web root: usually holds passwords and keys"
            sev["vcs"] = "MED";        txt["vcs"] = "version-control folder in the web root: source code and history may be downloadable"  # awk text: posix-ok
            sev["phpinfo"] = "MED";    txt["phpinfo"] = "phpinfo page: shows paths, versions and settings to anyone"
            sev["config_readable"] = "MED"; txt["config_readable"] = "app config with the database password is readable by every local account"
            sev["backup"] = "MED";     txt["backup"] = "backup or archive file in the web root: may expose source code or data"  # awk text: posix-ok
        }
        { key = $1 "|" $2; n[key]++
          if (n[key] <= 5) print sev[$2] "|" $3 "|" txt[$2]
          else { more[key]++; ks[key] = $2; rt[key] = $1 } }
        END { for (k in more) print sev[ks[k]] "|" rt[k] "|" more[k] " more " ks[k] " files (see files.csv)" }' "$W/notable" >"$W/notable_flags"
    emit_flags "$W/notable_flags"
    say "Web roots: $(tr '\n' ' ' <"$W/webroots" | cut -c1-200)"
    [ "$IS_ROOT" = 1 ] || note "partial: not root"
}

s_php() {
    sec_csv php "ini,sapi,setting,value"
    _F=$SEC_CSV
    : >"$W/inis"
    for _d in /etc/php /etc/php5 /etc/php7 /etc/php8 /usr/local/etc /etc/opt/remi /opt/remi; do
        [ -d "$_d" ] && find "$_d" -maxdepth 5 -name php.ini 2>/dev/null >>"$W/inis"
    done
    [ -f /etc/php.ini ] && printf '%s\n' /etc/php.ini >>"$W/inis"
    sort -u "$W/inis" -o "$W/inis"
    if [ ! -s "$W/inis" ]; then note "no php.ini found"; return 0; fi
    : >"$W/php_rows"
    while IFS= read -r _ini; do
        _dir=$(dirname "$_ini")
        _sapi=$(basename "$_dir")
        case "$_sapi" in apache2|apache|fpm|cli|cgi|embed|litespeed|phpdbg) ;; *) _sapi=main ;; esac
        # conf.d next to php.ini (Debian) or /etc/php.d (Red Hat) can override it.
        _scan="$_dir/conf.d"; [ "$_ini" = /etc/php.ini ] && _scan=/etc/php.d
        set -- "$_ini"
        if [ -d "$_scan" ]; then for _x in "$_scan"/*.ini; do [ -r "$_x" ] && set -- "$@" "$_x"; done; fi
        awk -v ini="$_ini" -v sapi="$_sapi" '
            BEGIN { split("allow_url_include allow_url_fopen display_errors expose_php disable_functions open_basedir file_uploads", ks, " ")
                    for (i in ks) want[ks[i]] = 1 }
            /^[ \t]*[;#\[]/ { next }
            { n = index($0, "="); if (!n) next
              k = substr($0, 1, n - 1); v = substr($0, n + 1); gsub(/[ \t]/, "", k); sub(/[ \t]*;.*$/, "", v); gsub(/^[ \t"]+|[ \t"]+$/, "", v)
              if (k in want) val[k] = v }
            END { for (k in want) print ini "|" sapi "|" k "|" (k in val ? val[k] : "(default)") }' "$@" >>"$W/php_rows"
    done <"$W/inis"
    sort "$W/php_rows" -o "$W/php_rows"
    while IFS='|' read -r _i _s _k _v; do cc_csv_row "$_F" "$_i" "$_s" "$_k" "$_v"; done <"$W/php_rows"
    awk -F'|' '
        function on(v) { v = tolower(v); return v == "on" || v == "1" || v == "true" || v == "yes" }  # awk, not shell: posix-ok
        $3 == "allow_url_include" && on($4) { print ($2 == "cli" ? "LOW" : "HIGH") "|" $1 "|allow_url_include is On: a file-include flaw can run code from another server" }
        $2 != "cli" && $3 == "display_errors" && on($4) { print "LOW|" $1 "|display_errors is On: error pages show paths and code details" }
        $2 != "cli" && $3 == "expose_php" && on($4) { print "LOW|" $1 "|expose_php is On: the PHP version is sent in every response" }
        $2 != "cli" && $3 == "disable_functions" && ($4 == "" || $4 == "(default)") { print "LOW|" $1 "|disable_functions is empty: a web shell can call system() and exec()" }' "$W/php_rows" >"$W/php_flags"
    emit_flags "$W/php_flags"
}

s_apps() {
    sec_csv apps "web_root,app,version,path,config,db_name,db_user,db_host"
    _F=$SEC_CSV
    if [ ! -s "$W/webroots" ]; then note "no web root found"; return 0; fi
    : >"$W/markers"
    while IFS= read -r _r; do
        find "$_r" -xdev -maxdepth 7 -type f \( -path '*/wp-includes/version.php' -o -path '*/administrator/manifests/files/joomla.xml' \
             -o -path '*/core/lib/Drupal.php' -o -path '*/includes/bootstrap.inc' -o -path '*/libraries/classes/Version.php' \
             -o -path '*/libraries/Config.class.php' -o -path '*/program/include/iniset.php' -o -path '*/includes/Defines.php' \
             -o -path '*/lib/moodlelib.php' -o -path '*/lib/versioncheck.php' -o -path '*/system/startup.php' \
             -o -path '*/classes/PrestaShopAutoload.php' \) 2>/dev/null | sed "s|^|$_r\||" >>"$W/markers"
    done <"$W/webroots"
    _napps=0; _alist=""
    while IFS='|' read -r _r _m; do
        _app=""; _ver=""; _cfg=""; _dbn=""; _dbu=""; _dbh=""
        case "$_m" in
            */wp-includes/version.php)
                _app=WordPress; _dir=${_m%/wp-includes/version.php}
                _ver=$(sed -n "s/.*\$wp_version *= *'\([^']*\)'.*/\1/p" "$_m" | head -n 1)
                _cfg="$_dir/wp-config.php"; [ -f "$_cfg" ] || _cfg="$(dirname "$_dir")/wp-config.php"
                _dbn=$(php_val "$_cfg" "DB_NAME['\"]"); _dbu=$(php_val "$_cfg" "DB_USER['\"]"); _dbh=$(php_val "$_cfg" "DB_HOST['\"]") ;;
            */administrator/manifests/files/joomla.xml)
                _app=Joomla; _dir=${_m%/administrator/manifests/files/joomla.xml}
                _ver=$(sed -n 's/.*<version>\([^<]*\)<\/version>.*/\1/p' "$_m" | head -n 1)
                _cfg="$_dir/configuration.php"
                _dbn=$(php_val "$_cfg" '\$db *='); _dbu=$(php_val "$_cfg" '\$user *='); _dbh=$(php_val "$_cfg" '\$host *=') ;;
            */core/lib/Drupal.php|*/includes/bootstrap.inc)
                case "$_m" in */core/lib/Drupal.php) _dir=${_m%/core/lib/Drupal.php} ;; *) _dir=${_m%/includes/bootstrap.inc} ;; esac
                grep -q 'DRUPAL\|Drupal' "$_m" 2>/dev/null || continue
                _app=Drupal
                _ver=$(sed -n "s/.*const VERSION *= *'\([^']*\)'.*/\1/p; s/.*define('VERSION', *'\([^']*\)').*/\1/p" "$_m" | head -n 1)
                _cfg="$_dir/sites/default/settings.php"
                _dbn=$(php_val "$_cfg" "'database'[ \t]*=>"); _dbu=$(php_val "$_cfg" "'username'[ \t]*=>"); _dbh=$(php_val "$_cfg" "'host'[ \t]*=>") ;;
            */libraries/classes/Version.php|*/libraries/Config.class.php)
                grep -q 'phpMyAdmin\|PMA_VERSION' "$_m" 2>/dev/null || continue
                _app=phpMyAdmin; _dir=${_m%/libraries/*}
                _ver=$(sed -n "s/.*const VERSION *= *'\([^']*\)'.*/\1/p; s/.*'PMA_VERSION', *'\([^']*\)'.*/\1/p" "$_m" | head -n 1)
                _cfg="$_dir/config.inc.php"; [ -f "$_cfg" ] || _cfg="" ;;
            */program/include/iniset.php)
                _app=Roundcube; _dir=${_m%/program/include/iniset.php}
                _ver=$(sed -n "s/.*'RCMAIL_VERSION', *'\([^']*\)'.*/\1/p" "$_m" | head -n 1)
                _cfg="$_dir/config/config.inc.php" ;;
            */includes/Defines.php)
                grep -q 'MW_VERSION\|MediaWiki' "$_m" 2>/dev/null || continue
                _app=MediaWiki; _dir=${_m%/includes/Defines.php}
                _ver=$(sed -n "s/.*'MW_VERSION', *'\([^']*\)'.*/\1/p" "$_m" | head -n 1)
                _cfg="$_dir/LocalSettings.php"
                _dbn=$(php_val "$_cfg" '\$wgDBname *='); _dbu=$(php_val "$_cfg" '\$wgDBuser *='); _dbh=$(php_val "$_cfg" '\$wgDBserver *=') ;;
            */lib/moodlelib.php)
                _app=Moodle; _dir=${_m%/lib/moodlelib.php}
                _ver=$(sed -n "s/^\$release *= *'\([^ ']*\).*/\1/p" "$_dir/version.php" 2>/dev/null | head -n 1)
                _cfg="$_dir/config.php"
                _dbn=$(php_val "$_cfg" '->dbname *='); _dbu=$(php_val "$_cfg" '->dbuser *='); _dbh=$(php_val "$_cfg" '->dbhost *=') ;;
            */lib/versioncheck.php)
                _dir=${_m%/lib/versioncheck.php}
                [ -f "$_dir/version.php" ] || continue
                _app=Nextcloud/ownCloud
                _ver=$(sed -n "s/^\$OC_VersionString *= *'\([^']*\)'.*/\1/p" "$_dir/version.php" | head -n 1)
                _cfg="$_dir/config/config.php"
                _dbn=$(php_val "$_cfg" "'dbname'[ \t]*=>"); _dbu=$(php_val "$_cfg" "'dbuser'[ \t]*=>"); _dbh=$(php_val "$_cfg" "'dbhost'[ \t]*=>") ;;
            */system/startup.php)
                _dir=${_m%/system/startup.php}
                grep -q "define('VERSION'" "$_dir/index.php" 2>/dev/null || continue
                _app=OpenCart
                _ver=$(sed -n "s/.*define('VERSION', *'\([^']*\)').*/\1/p" "$_dir/index.php" | head -n 1)
                _cfg="$_dir/config.php"
                _dbn=$(php_val "$_cfg" "DB_DATABASE['\"]"); _dbu=$(php_val "$_cfg" "DB_USERNAME['\"]"); _dbh=$(php_val "$_cfg" "DB_HOSTNAME['\"]") ;;
            */classes/PrestaShopAutoload.php)
                _app=PrestaShop; _dir=${_m%/classes/PrestaShopAutoload.php}
                _ver=$(sed -n "s/.*const VERSION *= *'\([^']*\)'.*/\1/p" "$_dir/app/AppKernel.php" 2>/dev/null | head -n 1)
                _cfg="$_dir/app/config/parameters.php"
                _dbn=$(php_val "$_cfg" "'database_name'[ \t]*=>"); _dbu=$(php_val "$_cfg" "'database_user'[ \t]*=>"); _dbh=$(php_val "$_cfg" "'database_host'[ \t]*=>") ;;
        esac
        [ -n "$_app" ] || continue
        [ -n "$_cfg" ] && [ ! -f "$_cfg" ] && _cfg="$_cfg (missing)"
        cc_csv_row "$_F" "$_r" "$_app" "${_ver:-unknown}" "$_dir" "$_cfg" "$_dbn" "$_dbu" "$_dbh"
        _napps=$((_napps + 1)); _alist="$_alist${_alist:+, }$_app ${_ver:-?} ($_dir)"
        [ "$_dbu" = root ] && flag MED "$_app $_dir" "the app logs in to the database as root: a flaw in the app gives full control of every database"
    done <"$W/markers"
    [ "$_napps" -gt 0 ] && say "Apps: $(printf '%s' "$_alist" | cut -c1-220)"
    [ "$_napps" -gt 0 ] || note "no known app found"
}

s_mysql() {
    _bin=$(cc_first mariadbd mysqld /usr/sbin/mysqld /usr/sbin/mariadbd /usr/libexec/mysqld /usr/local/libexec/mysqld)
    _users=$(ps_users '^(mysqld|mariadbd|mysqld_safe|mariadbd-safe)$')
    MYC=$(cc_first mariadb mysql)
    if [ -z "$_bin$_users$MYC" ]; then note "not installed"; return 0; fi
    db_csv db_settings "engine,setting,value"; _FS=$SEC_CSV
    db_csv db_users "engine,user,host,auth,empty_password,superuser,file_access,can_grant,notes"; _FU=$SEC_CSV
    db_csv db_databases "engine,database,tables,size_mb"; _FD=$SEC_CSV
    db_csv db_objects "engine,schema,kind,name,detail"; _FO=$SEC_CSV
    # Where it listens, from the socket list (works even without a login).
    awk -F'|' '$4 ~ /^(mysqld|mariadbd)$/ { print $2 "|" $3 }' "$W/listen" | sort -u >"$W/my_listen"
    while IFS='|' read -r _a _p; do
        nonlocal "$_a" && flag MED "$_a:$_p" "MySQL/MariaDB listens on a network address: fine only if an app on another host needs it; otherwise bind to 127.0.0.1 or firewall it"
    done <"$W/my_listen"
    if [ -z "$MYC" ]; then note "no mysql client: accounts not listed"; say "MySQL/MariaDB: running as ${_users:-?}, no client to log in"; return 0; fi
    # Log in: the options file given, root through the socket, the Debian
    # maintenance account, then whatever ~/.my.cnf gives.  Never prompts.
    MYOPT=""; _how=""
    for _try in "${MYSQL_CNF:+--defaults-extra-file=$MYSQL_CNF}" --user=root \
                "$( [ -r /etc/mysql/debian.cnf ] && echo --defaults-file=/etc/mysql/debian.cnf )" "-"; do
        [ -n "$_try" ] || continue
        if [ "$_try" = "-" ]; then
            # shellcheck disable=SC2086
            if $TO "$MYC" --connect-timeout=5 -N -B -e 'SELECT 1' >/dev/null 2>&1; then MYOPT="-"; _how="default client settings"; break; fi
        else
            # shellcheck disable=SC2086
            if $TO "$MYC" "$_try" --connect-timeout=5 -N -B -e 'SELECT 1' >/dev/null 2>&1; then MYOPT=$_try; _how=$_try; break; fi
        fi
    done
    if [ -z "$MYOPT" ]; then
        note "could not log in: give --mysql-cnf"
        say "MySQL/MariaDB: found, but could not log in (accounts not checked; use --mysql-cnf)"
        return 0
    fi
    cc_debug "mysql login: $_how"
    # How the login worked can itself be a finding.  As root, --user=root
    # works through the socket, which is normal.  As anyone else it means root
    # has no password; and "default settings" with no ~/.my.cnf means an
    # anonymous account let us in.
    if [ "$IS_ROOT" = 0 ] && [ "$MYOPT" = --user=root ]; then
        flag HIGH "root@localhost" "a normal account logged in to MySQL as root with NO password"
    elif [ "$MYOPT" = "-" ] && [ ! -f "${HOME:-/nonexistent}/.my.cnf" ]; then
        flag HIGH "anonymous login" "logged in to MySQL with no user name and no password: any local account (and the web server) can"
    fi
    # myq SQL -> tab-separated rows, no header; NOTHING if the query fails.
    #   Some client versions echo a failed statement on standard output, so
    #   the output is kept only when the exit code says the query worked.
    #   That lets callers try a newer query and fall back when it is empty.
    myq() {
        # shellcheck disable=SC2086
        if [ "$MYOPT" = "-" ]; then $TO "$MYC" --connect-timeout=5 -N -B -e "$1" >"$W/myq.out" 2>/dev/null
        else $TO "$MYC" "$MYOPT" --connect-timeout=5 -N -B -e "$1" >"$W/myq.out" 2>/dev/null; fi
        _myq_rc=$?
        [ "$_myq_rc" -eq 0 ] && cat "$W/myq.out"
        rm -f "$W/myq.out"
        return "$_myq_rc"
    }
    _ver=$(myq 'SELECT VERSION()')
    myq "SHOW GLOBAL VARIABLES WHERE Variable_name IN ('version','bind_address','skip_networking','port','secure_file_priv','local_infile','general_log','log_error','have_ssl','plugin_dir')" >"$W/my_vars"
    awk -F"$TAB" -v csv="$_FS" "$AWK_Q"'{ print q("mysql") "," q($1) "," q($2) >> csv }' "$W/my_vars"
    awk -F"$TAB" '
        $1 == "secure_file_priv" && $2 == "" { print "MED|secure_file_priv|empty: SELECT ... INTO OUTFILE can write files anywhere the database account can, such as a web shell into the web root" }
        $1 == "local_infile" && ($2 == "ON" || $2 == "1") { print "LOW|local_infile|ON: LOAD DATA LOCAL can read files from client machines" }' "$W/my_vars" >"$W/my_flags"
    # Accounts.  Columns: user host plugin empty super file grant all locked
    # no_password_login.  Three layouts are tried in turn:
    #   MySQL 5.7+   has an account_locked column
    #   MariaDB 10.4+ keeps "locked" in mysql.global_priv (JSON)
    #   older        Password column, no lock information
    # authentication_string 'invalid' (MariaDB) means password login is
    # impossible; such accounts log in only as the matching OS account.
    _cols="u.user, u.host, u.plugin, IF(u.authentication_string = '' OR u.authentication_string IS NULL, 'yes', 'no'), u.Super_priv, u.File_priv, u.Grant_priv, IF(u.Select_priv='Y' AND u.Insert_priv='Y' AND u.Update_priv='Y' AND u.Delete_priv='Y' AND u.Create_priv='Y' AND u.Drop_priv='Y', 'yes', 'no')"
    myq "SELECT $_cols, u.account_locked, IF(u.authentication_string = 'invalid', 'yes', 'no') FROM mysql.user u" >"$W/my_users"
    if [ ! -s "$W/my_users" ]; then
        myq "SELECT $_cols, IF(JSON_VALUE(p.priv, '"'$.account_locked'"') IN ('1', 'true'), 'Y', 'N'), IF(u.authentication_string = 'invalid', 'yes', 'no') FROM mysql.user u LEFT JOIN mysql.global_priv p ON p.user = u.user AND p.host = u.host" >"$W/my_users"
    fi
    if [ ! -s "$W/my_users" ]; then
        myq "SELECT u.user, u.host, '', IF(u.password = '', 'yes', 'no'), u.Super_priv, u.File_priv, u.Grant_priv, IF(u.Select_priv='Y' AND u.Insert_priv='Y' AND u.Update_priv='Y' AND u.Delete_priv='Y' AND u.Create_priv='Y' AND u.Drop_priv='Y', 'yes', 'no'), 'N', 'no' FROM mysql.user u" >"$W/my_users"
    fi
    awk -F"$TAB" -v csv="$_FU" -v me="$CC_HOST" "$AWK_Q"'
        function local(h) { return h == "localhost" || h == "127.0.0.1" || h == "::1" || h == me }  # awk, not shell: posix-ok
        {
            u = $1; h = $2; pl = $3; auth = (pl != "" ? pl : "password")
            locked = ($9 == "Y")
            sock = (pl ~ /socket|gssapi|pam/ || $10 == "yes")
            empty = ($4 == "yes" && !sock && !locked) ? "yes" : "no"
            if (locked) auth = "locked (cannot log in)"
            else if ($10 == "yes") auth = "local OS account only (no password login)"
            else if (sock) auth = auth " (local OS account login)"
            all = ($8 == "yes") ? "all privileges" : ""
            print q("mysql") "," q(u) "," q(h) "," q(auth) "," q(empty) "," q($5 == "Y" ? "yes" : "no") "," q($6 == "Y" ? "yes" : "no") "," q($7 == "Y" ? "yes" : "no") "," q(all) >> csv
            if (locked) next
            who = (u == "" ? "(anonymous)" : u) "@" h
            if (u == "") print "MED|" who "|anonymous account: anyone can log in without a user name"
            else if (empty == "yes") print "HIGH|" who "|has NO password: anyone who can reach the database logs in"
            if (u == "root" && !local(h)) print "HIGH|" who "|root can log in from " (h == "%" ? "any address" : h)
            else if (!local(h) && ($5 == "Y" || $7 == "Y" || $8 == "yes")) print "HIGH|" who "|full or admin rights from " (h == "%" ? "any address" : h) ": check it is a known app account"
            else if (u != "" && h == "%") print "LOW|" who "|can log in from any address"
            if (u != "root" && u != "" && $6 == "Y" && !sock) print "MED|" who "|has the FILE privilege: can read server files and write new ones (web shells)"
        }' "$W/my_users" >>"$W/my_flags"
    myq "SELECT s.schema_name, COUNT(t.table_name), IFNULL(ROUND(SUM(t.data_length + t.index_length) / 1048576, 1), 0) FROM information_schema.schemata s LEFT JOIN information_schema.tables t ON t.table_schema = s.schema_name GROUP BY s.schema_name" >"$W/my_dbs"
    awk -F"$TAB" -v csv="$_FD" "$AWK_Q"'{ print q("mysql") "," q($1) "," q($2) "," q($3) >> csv }' "$W/my_dbs"
    # Objects that can run code or change data on their own.
    _sys="'mysql','sys','information_schema','performance_schema'"
    {
        myq "SELECT trigger_schema, 'trigger', trigger_name, CONCAT(action_timing, ' ', event_manipulation, ' on ', event_object_table) FROM information_schema.triggers WHERE trigger_schema NOT IN ($_sys)"
        myq "SELECT event_schema, 'event', event_name, CONCAT(status, ' ', IFNULL(CONCAT('every ', interval_value, ' ', interval_field), 'once')) FROM information_schema.events"
        myq "SELECT 'mysql', 'udf', name, dl FROM mysql.func"
        myq "SELECT routine_schema, LOWER(routine_type), routine_name, '' FROM information_schema.routines WHERE routine_schema NOT IN ($_sys)"
    } >"$W/my_objs"
    awk -F"$TAB" -v csv="$_FO" "$AWK_Q"'
        { print q("mysql") "," q($1) "," q($2) "," q($3) "," q($4) >> csv }
        $2 == "udf" { print "HIGH|udf " $3 "|user-defined function loaded from " $4 ": a classic database backdoor that runs OS commands (lib_mysqludf_sys)" }
        $2 == "trigger" { print "MED|trigger " $1 "." $3 "|" $4 ": triggers run on every change; check it belongs to the app" }
        $2 == "event" { print "MED|event " $1 "." $3 "|scheduled database job (" $4 "): check it belongs to the app" }' "$W/my_objs" >>"$W/my_flags"
    emit_flags "$W/my_flags"
    if [ -s "$W/my_users" ]; then
        say "MySQL/MariaDB: ${_ver:-?}, $(grep -c . "$W/my_users") accounts, $(grep -c . "$W/my_dbs") databases (logged in with $_how)"
    else
        note "logged in, but this login cannot read the account list"
        say "MySQL/MariaDB: ${_ver:-?}, accounts not readable with $_how (run as root or give --mysql-cnf)"
    fi
}

s_postgres() {
    _users=$(ps_users '^(postgres|postmaster)$')
    _psql=$(cc_first psql)
    if [ -z "$_users$_psql" ]; then note "not installed"; return 0; fi
    db_csv db_settings "engine,setting,value"; _FS=$SEC_CSV
    db_csv db_users "engine,user,host,auth,empty_password,superuser,file_access,can_grant,notes"; _FU=$SEC_CSV
    db_csv db_databases "engine,database,tables,size_mb"; _FD=$SEC_CSV
    sec_csv pg_hba "line,type,database,user,address,method"; _FH=$SEC_CSV
    : >"$W/pg_flags"
    awk -F'|' '$4 ~ /^(postgres|postmaster)$/ { print $2 "|" $3 }' "$W/listen" | sort -u >"$W/pg_listen"
    while IFS='|' read -r _a _p; do
        nonlocal "$_a" && flag MED "$_a:$_p" "PostgreSQL listens on a network address: fine only if an app on another host needs it; check pg_hba rules"
    done <"$W/pg_listen"
    if [ -z "$_psql" ]; then note "no psql: roles not listed"; return 0; fi
    # As root, ask as the postgres account (peer login through the socket).
    PG_AS=""
    if [ "$IS_ROOT" = 1 ] && grep -q '^postgres:' /etc/passwd 2>/dev/null; then PG_AS=postgres; fi
    # pgq SQL -> "|"-separated rows.  The query goes in on stdin so no quoting
    # has to survive the su command line.
    pgq() {
        if [ -n "$PG_AS" ]; then printf '%s\n' "$1" | run_as "$PG_AS" "cd / && $TO psql -X -A -t -q -F '|'" 2>/dev/null
        else printf '%s\n' "$1" | $TO psql -X -A -t -q -F '|' 2>/dev/null; fi
    }
    _ver=$(pgq 'SHOW server_version')
    if [ -z "$_ver" ]; then
        note "could not log in"
        say "PostgreSQL: found, but could not log in (run as root)"
        return 0
    fi
    pgq "SELECT name, setting FROM pg_settings WHERE name IN ('listen_addresses','port','hba_file','ssl','password_encryption','log_connections','data_directory')" >"$W/pg_vars"
    awk -F'|' -v csv="$_FS" "$AWK_Q"'{ print q("postgres") "," q($1) "," q($2) >> csv }' "$W/pg_vars"
    pgq "SELECT rolname, rolsuper, rolcanlogin, rolcreaterole, rolcreatedb, rolpassword IS NULL FROM pg_authid WHERE rolname !~ '^pg_'" >"$W/pg_roles"
    [ -s "$W/pg_roles" ] || pgq "SELECT rolname, rolsuper, rolcanlogin, rolcreaterole, rolcreatedb, 'unknown' FROM pg_roles WHERE rolname !~ '^pg_'" >"$W/pg_roles"
    awk -F'|' -v csv="$_FU" "$AWK_Q"'
        { notes = ($3 == "t" ? "can log in" : "cannot log in") ($5 == "t" ? ", create databases" : "")
          auth = ($6 == "t" ? "no password set" : ($6 == "f" ? "password set" : "unknown"))
          print q("postgres") "," q($1) "," q("") "," q(auth) "," q("no") "," q($2 == "t" ? "yes" : "no") "," q($2 == "t" ? "yes" : "no") "," q($4 == "t" ? "yes" : "no") "," q(notes) >> csv
          if ($2 == "t" && $1 != "postgres") print "MED|role " $1 "|extra superuser: full control of every database and can run OS commands; check it is the team'"'"'s" }' "$W/pg_roles" >>"$W/pg_flags"
    pgq "SELECT datname, (SELECT 0), round(pg_database_size(datname) / 1048576.0, 1) FROM pg_database WHERE NOT datistemplate" >"$W/pg_dbs"
    awk -F'|' -v csv="$_FD" "$AWK_Q"'{ print q("postgres") "," q($1) "," q("") "," q($3) >> csv }' "$W/pg_dbs"
    # Login rules.  "trust" means no password at all.
    _hba=$(awk -F'|' '$1 == "hba_file" { print $2 }' "$W/pg_vars")
    if [ -n "$_hba" ] && [ -r "$_hba" ]; then
        awk -v csv="$_FH" "$AWK_Q"'
            BEGIN { split("trust reject md5 password scram-sha-256 gss sspi ident peer ldap radius cert pam bsd", ms, " "); for (i in ms) meth[ms[i]] = 1 }
            { line = $0; sub(/#.*/, "", line); n = split(line, f, /[ \t]+/); if (f[1] == "") { for (i = 1; i < n; i++) f[i] = f[i + 1]; n-- }
              if (n < 3) next
              t = f[1]; db = f[2]; u = f[3]; addr = ""; m = ""
              start = (t == "local") ? 4 : 5
              if (t != "local") addr = f[4]
              for (i = start; i <= n; i++) if (f[i] in meth) { m = f[i]; break }
              if (t != "local" && addr !~ /\// && f[5] ~ /^[0-9.:a-fA-F]+$/ && !(f[5] in meth)) addr = addr "/" f[5]
              print q(FNR) "," q(t) "," q(db) "," q(u) "," q(addr) "," q(m) >> csv
              if (m == "trust" && t != "local") print "HIGH|pg_hba line " FNR "|trust from " addr ": anyone who can reach the port logs in as " u " to " db " with NO password"
              else if (m == "trust") print "MED|pg_hba line " FNR "|trust for local connections: any local account (www-data too) can log in as " u " without a password"
              else if (m == "password") print "LOW|pg_hba line " FNR "|password method sends passwords in clear text; use scram-sha-256" }' "$_hba" >>"$W/pg_flags"
    else
        note "pg_hba not readable"
    fi
    emit_flags "$W/pg_flags"
    say "PostgreSQL: $_ver, $(grep -c . "$W/pg_roles") roles, $(grep -c . "$W/pg_dbs") databases"
}

s_datastores() {
    sec_csv datastores "service,address,port,process,answers_without_password"
    _F=$SEC_CSV
    # Services usually installed without a password, matched by port or process.
    awk -F'|' '
        $3 == 6379 || $4 ~ /^redis/   { print "redis|" $2 "|" $3 "|" $4; next }
        $3 == 11211 || $4 ~ /^memcached/ { print "memcached|" $2 "|" $3 "|" $4; next }
        $3 == 27017 || $4 ~ /^mongod/ { print "mongodb|" $2 "|" $3 "|" $4; next }
        $3 == 9200                    { print "elasticsearch|" $2 "|" $3 "|" $4; next }
        $3 == 5984 || $4 ~ /^beam/    { print "couchdb|" $2 "|" $3 "|" $4; next }' "$W/listen" | sort -u >"$W/ds"
    if [ ! -s "$W/ds" ]; then note "none listening"; return 0; fi
    while IFS='|' read -r _s _a _p _pr; do
        _host=$_a; case "$_a" in 0.0.0.0|\*|::|'') _host=127.0.0.1 ;; esac
        _open="not checked"
        case "$_s" in
            redis)
                if cc_have redis-cli; then
                    # shellcheck disable=SC2086
                    case "$($TO redis-cli -h "$_host" -p "$_p" ping 2>&1)" in PONG*) _open=yes ;; *NOAUTH*|*Authentication*) _open=no ;; esac
                fi ;;
            elasticsearch|couchdb)
                if cc_have curl; then
                    case "$(curl -s -m 5 "http://$_host:$_p/" 2>/dev/null)" in *cluster_name*|*couchdb*) _open=yes ;; *) _open=no ;; esac
                fi ;;
            memcached) _open="yes (no login exists)" ;;
        esac
        cc_csv_row "$_F" "$_s" "$_a" "$_p" "$_pr" "$_open"
        if nonlocal "$_a"; then
            case "$_open" in
                yes*) flag HIGH "$_s $_a:$_p" "reachable from the network and answers without a password: bind to 127.0.0.1, set a password or firewall it" ;;
                *)    flag MED "$_s $_a:$_p" "reachable from the network; these often have no password: bind to 127.0.0.1 or firewall it" ;;
            esac
        else
            case "$_open" in yes*) flag LOW "$_s $_a:$_p" "answers local programs without a password" ;; esac
        fi
    done <"$W/ds"
    say "Data stores: $(awk -F'|' '{ printf "%s%s %s:%s", (NR > 1 ? ", " : ""), $1, $2, $3 }' "$W/ds")"
}

# =============================================================================
# Run the sections and write the summary
# =============================================================================
get_ps
get_listen
detect_web
parse_web_configs
build_webroots

# sec_title NAME -> the section's line from --list, without the name.
sec_title() { list_sections | awk -v n="$1" '$1 == n { $1 = ""; sub(/^ +/, ""); print }'; }
nflags() { [ -f "$CC_CSV_DIR/flags.csv" ] && grep -c "^\"$1\"" "$CC_CSV_DIR/flags.csv" || echo 0; }
run_section() {
    SEC=$1; SEC_FILES=""; SEC_DBFILES=""; SEC_NOTE=""
    _rs_n=$((_rs_n + 1))
    cc_note "[$_rs_n/$_rs_total] $SEC"
    show "" ""
    show "$C_CYN" "==========[ $_rs_n/$_rs_total  $SEC: $(sec_title "$SEC") ]=========="
    _rs_hi0=$(nflags HIGH); _rs_me0=$(nflags MED)
    "s_$SEC"
    _rows=0
    for _f in $SEC_FILES; do [ -f "$_f" ] && _rows=$((_rows + $(wc -l <"$_f") - 1)); done
    # Shared database files: count only this engine's rows.
    for _f in $SEC_DBFILES; do [ -f "$_f" ] && _rows=$((_rows + $(grep -c "^\"$SEC\"," "$_f"))); done
    [ "$(nflags HIGH)" = "$_rs_hi0" ] && [ "$(nflags MED)" = "$_rs_me0" ] && show "$C_GRN" "  [ok] nothing to fix here"
    _rs_files=""
    for _f in $SEC_FILES $SEC_DBFILES; do [ -f "$_f" ] && _rs_files="$_rs_files $(basename "$_f" .csv).txt"; done
    show "$C_GRY" "  ($_rows rows${_rs_files:+ ->$(printf '%s' "$_rs_files" | tr ' ' '\n' | sort -u | tr '\n' ' ' | sed 's/ $//')}${SEC_NOTE:+; $SEC_NOTE})"
    printf '%s|%s|%s\n' "$SEC" "$_rows" "$SEC_NOTE" >>"$W/sections"
}

: >"$W/summary_lines"; : >"$W/sections"
_rs_total=$(printf '%s\n' $SECTIONS | grep -c .)
_rs_n=0
for _s in $SECTIONS; do run_section "$_s"; done

_flagsf="$CC_CSV_DIR/flags.csv"
[ -f "$_flagsf" ] || printf 'severity,section,item,detail,time\n' >"$_flagsf"
# Read by cc_flag_report in the library.
# shellcheck disable=SC2034
CC_FLAGS=$_flagsf
# shellcheck disable=SC2034
CC_FLAGS_SHOW="$CC_RUN_DIR/flags.txt"
for _c in "$CC_CSV_DIR"/*.csv; do
    [ -f "$_c" ] || continue
    _b=$(basename "$_c" .csv)
    if [ "$_b" = flags ]; then
        { head -n 1 "$_c"; for _sv in HIGH MED LOW; do grep "^\"$_sv\"" "$_c"; done; } >"$W/flags_sorted.csv"
        cc_csv_pretty "$W/flags_sorted.csv" "$CC_RUN_DIR/flags.txt" 200
    else
        cc_csv_pretty "$_c" "$CC_RUN_DIR/$_b.txt"
    fi
done
{
    printf 'SV-01 Web and database enum | host %s | %s | root: %s\n\n' "$CC_HOST" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$([ "$IS_ROOT" = 1 ] && echo yes || echo NO - partial)"
    if [ -s "$W/summary_lines" ]; then cat "$W/summary_lines"; else echo "No web server, web root or database found."; fi
    [ "$NODB" = 1 ] && printf 'Databases: not logged in (you chose config files only)\n'
    printf '\n'
    awk -v sf="$W/sections" "$CC_AWK_CSV"'
        NR > 1 { csvsplit($0, f); c[f[2] "|" f[1]]++ }
        END {
            printf "%-12s %6s %5s %5s %5s  %s\n", "section", "rows", "high", "med", "low", "note"
            while ((getline l < sf) > 0) {
                split(l, s, "|")
                printf "%-12s %6d %5d %5d %5d  %s\n", s[1], s[2], c[s[1] "|HIGH"], c[s[1] "|MED"], c[s[1] "|LOW"], s[3]
            }
        }' "$_flagsf"
    printf '\n'
    cc_flag_report "$MAXFLAGS"
    printf '\nAll results: %s\n' "$CC_RUN_DIR"
} >"$CC_RUN_DIR/summary.txt"
show "" ""
show "$C_CYN" "==========[ SUMMARY ]=========="
awk -v R="$C_RED" -v Y="$C_YEL" -v G="$C_GRN" -v C="$C_CYN" -v D="$C_GRY" -v O="$C_OFF" '
    /^section +rows +high/  { intable = 1; seen_table = 1; print C $0 O; next }
    intable && /^$/         { intable = 0; print; next }
    intable { if ($3 + 0 > 0) print R $0 O; else if ($4 + 0 > 0) print Y $0 O; else print G $0 O; next }
    /^Flags:/               { print C $0 O; next }
    /^HIGH - /              { mode = "H"; print R $0 O; next }
    /^MED - /               { mode = "M"; print Y $0 O; next }
    /^  \[/ && mode == "H"  { print R "  [!] FIX " substr($0, 3) O; next }
    /^  \[/ && mode == "M"  { print Y "  [*] LOOK" substr($0, 2) O; next }
    /^All (flags|results)/  { print D $0 O; next }
    NR <= 1                 { print C $0 O; next }
    /^$/                    { print; next }
    !seen_table             { print G $0 O; next }
                            { print }
' "$CC_RUN_DIR/summary.txt" >&3
cat "$CC_RUN_DIR/summary.txt" >>"$OUTF"
rm -rf "$W"
cc_finish
