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

# >>> BT-LIB
# Development copy: find lib/lib.sh by walking up from this file.  The build
# step (tools/build.sh, LB-03) replaces this whole block with the library
# itself, so the built script is a single standalone file.
_cc_d=$(cd "$(dirname "$0")" && pwd)
while [ "$_cc_d" != "/" ] && [ ! -f "$_cc_d/lib/lib.sh" ]; do _cc_d=$(dirname "$_cc_d"); done
[ -f "$_cc_d/lib/lib.sh" ] || { echo "cannot find lib/lib.sh above $0" >&2; exit 3; }
. "$_cc_d/lib/lib.sh"
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
cc_box_valid "$BOX" || cc_die 2 "--box must be one of: $CC_BOXES"
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
    cc_box_ask e "${R:-}"
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
