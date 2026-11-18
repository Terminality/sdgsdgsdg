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

# >>> CCDC-LIB
# Development copy: find lib/lib.sh by walking up from this file.  The build
# step (tools/build.sh, LB-03) replaces this whole block with the library
# itself, so the built script is a single standalone file.
_cc_d=$(cd "$(dirname "$0")" && pwd)
while [ "$_cc_d" != "/" ] && [ ! -f "$_cc_d/lib/lib.sh" ]; do _cc_d=$(dirname "$_cc_d"); done
[ -f "$_cc_d/lib/lib.sh" ] || { echo "cannot find lib/lib.sh above $0" >&2; exit 3; }
. "$_cc_d/lib/lib.sh"
# <<< CCDC-LIB

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
        else if (l ~ /(^|\/)python[0-9.]*[ \t].*\.py/ && l !~ /(unattended|networkd|apt|landscape|fail2ban|cloud-init|supervisord|ccdc)/) { lang = "Python"; k = "python program" }
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
