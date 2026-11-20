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

# >>> BT-LIB
# Development copy: find lib/lib.sh by walking up from this file.  The build
# step (tools/build.sh, LB-03) replaces this whole block with the library
# itself, so the built script is a single standalone file.
_cc_d=$(cd "$(dirname "$0")" && pwd)
while [ "$_cc_d" != "/" ] && [ ! -f "$_cc_d/lib/lib.sh" ]; do _cc_d=$(dirname "$_cc_d"); done
[ -f "$_cc_d/lib/lib.sh" ] || { echo "cannot find lib/lib.sh above $0" >&2; exit 3; }
. "$_cc_d/lib/lib.sh"
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
        printf '\nNew passwords: %s (mode 600)\n  Give them to the captain, then: rm %s\n%s\n' "$PWOUT" "$PWOUT" '[!] SCORED ACCOUNTS: submit each new password in the scoring engine (Quotient: password change request) NOW - until then its checks use the old one and fail.'
    fi
    [ "$APPLIED" = 1 ] && [ -f "$CC_RUN_DIR/revert.sh" ] && printf 'Undo this run: sh %s/revert.sh --force\n' "$CC_RUN_DIR"
    printf 'Accounts: %s/accounts.txt\n' "$CC_RUN_DIR"
} >"$CC_RUN_DIR/summary.txt"
cc_show "" ""
while IFS= read -r _l; do
    case "$_l" in ==*|SV-42*) cc_show "$C_CYN" "$_l" ;; *'Failed (put back): '[1-9]*|*'PUT BACK'*|*HIGH*|'[!] SCORED'*) cc_show "$C_RED" "$_l" ;; *NOTE*|*'New passwords'*|*'Give them'*) cc_show "$C_YEL" "$_l" ;; *) cc_show "" "$_l" ;; esac
done <"$CC_RUN_DIR/summary.txt"
rm -rf "$W"
if [ "$TIMER_ON" = 1 ]; then
    header "KEEP OR REVERT"
    cc_show "$C_YEL" "[*] Before you answer: load the store and the webmail login in a browser."
    cc_timer_finish || true
fi
cc_finish
