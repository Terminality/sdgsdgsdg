#!/bin/sh
# =============================================================================
# ID:       SV-15
# NAME:     Site backup and restore
# ROLE:     Applications  (wave 1: back up first; restore whenever needed)
# KIND:     changes - backup and check only read; restore is a dry run unless --apply
# VERSION:  1.0.0
#
# PURPOSE
#   Keeps each web site restorable after the red team defaces it, drops a web
#   shell in it, or wipes its database.  Three modes:
#
#     backup   every site the web servers serve (Apache, nginx) plus the
#              folders in /var/www: the files (one archive per site, with a
#              hash of every file), the site's database (read from the app's
#              own config: WordPress, Joomla, Drupal, PrestaShop, OpenCart,
#              Magento, Roundcube, .env), and the web server and PHP configs.
#     check    compares each site with the last backup and lists what
#              changed: CHANGED files (defaced pages, edited code), DELETED
#              files and NEW files (web shells).  Changes nothing.
#     restore  the same comparison, then asks per site what to put back:
#              changed and deleted files from the backup, new files to
#              quarantine, and (if you say so) the database.  Only what
#              changed is touched, so your own fixes elsewhere stay.  The
#              current files and database are saved first, a revert timer
#              runs, and every step has an undo line.
#
#   SV-14 still dumps every database on the box; SV-15 is about the sites.
#
#   QUESTIONS (Enter takes the default in capitals; a flag answers each):
#     what to do: [b]ack up, [c]heck, [r]estore      --backup / --check / --restore
#     backup:  which sites (all or names)             --site NAME
#              the sites' databases too               --db / --no-db
#              copy the backup off the box            --copy-to DEST
#     restore: per site: [a]ll back to the backup, [f]iles only,
#              [q]uarantine new files only, [n]othing --what all|files|new|none
#              put the database back too              --restore-db / --no-restore-db
#
# USAGE
#   sudo sh SV-15-site-backup.sh                              asks
#   sudo sh SV-15-site-backup.sh --backup --batch             back up every site
#   sudo sh SV-15-site-backup.sh --check --batch              what changed?
#   sudo sh SV-15-site-backup.sh --restore --protected p.csv --apply
#
# OPTIONS
#   --backup | --check | --restore   the mode (asked if not given)
#   --site NAME        only this site (repeat); names as shown in sites.txt
#   --webroot DIR      also treat DIR as a site (repeat)
#   --from DIR         the backup to compare with (default: the newest
#                      site-backup-N in --out)
#   --db / --no-db     back up the sites' databases (default yes)
#   --mysql-cnf FILE   MySQL client file ([client] user/password) when root
#                      cannot log in through the socket
#   --exclude PATTERN  leave matching paths out of backups and checks (repeat;
#                      shell pattern on the full path, e.g. '*/cache/*')
#   --max-mb N         refuse a backup bigger than N MB (default 4096)
#   --keep N           keep only the newest N backups (default: all)
#   --copy-to DEST     copy the backup off the box with scp
#   --what all|files|new|none   restore answer for every site
#   --restore-db / --no-restore-db  put the database back on restore (default no)
#   --timer SECONDS    revert countdown on restore (default 120); --no-timer
#   --no-color         no colours
#   --help             this text plus the common options
#
# OUTPUTS  (under --out)
#   site-backup-N/     one backup (mode 700: it holds the database dumps)
#     sites.txt        each site: folder, files, size, database
#     <site>/files.tar.gz   the site's files (paths relative to /)
#     <site>/files.sha256   a hash of every file (what check compares)
#     <site>/db.sql.gz | db.dump   the site's database (MySQL / PostgreSQL)
#     config.tar.gz, config.sha256   /etc/apache2|httpd|nginx|php
#     RESTORE.txt      how to put things back by hand
#   site-check-N/      changes.txt: site, change, file, why
#   site-restore-N/    plan.txt, changes.txt, before/ (what was replaced),
#                      revert.sh
#   Each folder: output.txt (the screen, no colour), summary.txt, run.txt.
#
# WHAT IT CHANGES
#   backup, check: nothing on the host.  restore with --apply: the files it
#   lists (put back from the archive, owners and modes kept), new files moved
#   to quarantine, and the database if you said so.  Everything is undone if
#   the revert timer runs out or revert.sh is run.
#
# DEPENDS ON
#   tar, gzip, find, sha256sum (or shasum / sha256 / openssl); mysqldump or
#   mariadb-dump and the client; pg_dump/pg_restore; scp for --copy-to.
#
# TESTED ON
#   Ubuntu 24.04 under dash, bash, busybox sh, ksh93, mksh and yash with
#   gawk, mawk and busybox awk: a site defaced, a file deleted and a web
#   shell planted were found by check and put right by restore; the revert
#   brought the defaced state back.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - Back up AFTER cleaning: a web shell already there is in the backup and
#     looks normal to check.  Run SV-01 first.
#   - Files are compared by content (hash), not permission or owner.
#   - Web server config changes are reported, not restored (a restart could
#     break scoring): RESTORE.txt says how.
#   - A database on another host is not dumped: back it up there.
#   - Uploads made by real users after the backup show as NEW: check before
#     quarantining (they are moved, not deleted).
#
# DEBUGGING
#   --debug shows each site found, the database logins and every command.
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
SV-15 Site backup and restore - back up each web site, see what changed, put it back
  sudo sh SV-15-site-backup.sh                  asks
  sudo sh SV-15-site-backup.sh --backup --batch
  sudo sh SV-15-site-backup.sh --check --batch
  sudo sh SV-15-site-backup.sh --restore --protected p.csv --apply

  --backup | --check | --restore   the mode (asked if not given)
  --site NAME        only this site (repeatable)
  --webroot DIR      also treat DIR as a site (repeatable)
  --from DIR         the backup to compare with (default: the newest)
  --db / --no-db     back up the sites' databases (default yes)
  --mysql-cnf FILE   MySQL client file with a user and password
  --exclude PATTERN  leave matching paths out (repeatable, e.g. '*/cache/*')
  --max-mb N         refuse a backup bigger than N MB (default 4096)
  --keep N           keep only the newest N backups
  --copy-to DEST     copy the backup off the box (scp)
  --what all|files|new|none   restore answer for every site
  --restore-db / --no-restore-db   put the database back too (default no)
  --timer SECONDS    revert countdown on restore (default 120); --no-timer
  --no-color         no colours
  --help             show this text

USAGE
    cc_usage_common
}

NL='
'
MODE=""; SITES=""; WEBROOTS=""; FROM=""; DB=""; MYCNF=""; EXCL=""; MAXMB=4096; KEEP=0; COPYTO=""; COPYSET=0
WHAT=""; RDB=""; TIMER=120; NOTIMER=0; COLOR=1
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --backup)     MODE=backup; shift ;;
        --check)      MODE=check; shift ;;
        --restore)    MODE=restore; shift ;;
        --site)       [ $# -ge 2 ] || cc_die 2 "--site needs a name"; SITES="$SITES $2"; shift 2 ;;
        --webroot)    [ $# -ge 2 ] || cc_die 2 "--webroot needs a folder"; [ -d "$2" ] || cc_die 2 "--webroot: not a folder: $2"
                      WEBROOTS="$WEBROOTS$(cc_abspath "$2")$NL"; shift 2 ;;
        --from)       [ $# -ge 2 ] || cc_die 2 "--from needs a folder"; [ -f "$2/.sites" ] || cc_die 2 "--from: not an SV-15 backup: $2"
                      FROM=$(cc_abspath "$2"); shift 2 ;;
        --db)         DB=1; shift ;;
        --no-db)      DB=0; shift ;;
        --mysql-cnf)  [ $# -ge 2 ] || cc_die 2 "--mysql-cnf needs a file"; [ -r "$2" ] || cc_die 2 "--mysql-cnf: cannot read $2"; MYCNF=$(cc_abspath "$2"); shift 2 ;;
        --exclude)    [ $# -ge 2 ] || cc_die 2 "--exclude needs a pattern"; EXCL="$EXCL$2$NL"; shift 2 ;;
        --max-mb)     [ $# -ge 2 ] || cc_die 2 "--max-mb needs a number"; MAXMB=$2; shift 2 ;;
        --keep)       [ $# -ge 2 ] || cc_die 2 "--keep needs a number"; KEEP=$2; shift 2 ;;
        --copy-to)    [ $# -ge 2 ] || cc_die 2 "--copy-to needs a destination"; COPYTO=$2; COPYSET=1; shift 2 ;;
        --what)       [ $# -ge 2 ] || cc_die 2 "--what needs all, files, new or none"; WHAT=$2; shift 2 ;;
        --restore-db) RDB=1; shift ;;
        --no-restore-db) RDB=0; shift ;;
        --timer)      [ $# -ge 2 ] || cc_die 2 "--timer needs seconds"; TIMER=$2; shift 2 ;;
        --no-timer)   NOTIMER=1; shift ;;
        --no-color|--no-colour) COLOR=0; shift ;;
        --help|-h)    usage; exit 0 ;;
        *)            cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
for _n in "$MAXMB" "$KEEP" "$TIMER"; do case "$_n" in ''|*[!0-9]*) cc_die 2 "--max-mb, --keep and --timer need whole numbers" ;; esac; done
case "$WHAT" in ''|all|files|new|none) ;; *) cc_die 2 "--what must be all, files, new or none" ;; esac

cc_init "SV-15" "Site backup and restore" changes
cc_detect_os
# shellcheck disable=SC2034  # read by cc_color_init
[ "$COLOR" = 1 ] || CC_NOCOLOR=1
cc_color_init
IS_ROOT=0; cc_is_root && IS_ROOT=1
header() { cc_show "" ""; cc_show "$C_CYN" "==========[ $1 ]=========="; }

# newest_backup -> the newest site-backup-N folder in --out with a sites list.
newest_backup() {
    for _d in "$CC_OUT"/site-backup-*; do
        [ -f "$_d/.sites" ] || continue
        printf '%s %s\n' "${_d##*-}" "$_d"
    done | sort -n | tail -n 1 | cut -d' ' -f2-
}
[ -n "$FROM" ] || FROM=$(newest_backup)

# ---- What to do ---------------------------------------------------------------
if [ -z "$MODE" ]; then
    _dm=b; [ -n "$FROM" ] && _dm=c
    cc_choose "What do you want to do?$([ -n "$FROM" ] && echo " (last backup: $(basename "$FROM"))")" "$_dm" \
        "b=back up the sites now (do this first, after cleaning them)" \
        "c=check the sites against the last backup (changes nothing)" \
        "r=restore what changed since the last backup"
    case "$CC_CHOICE" in b) MODE=backup ;; c) MODE=check ;; *) MODE=restore ;; esac
fi
if [ "$MODE" != backup ] && [ -z "$FROM" ]; then
    cc_die 3 "no site backup found in $CC_OUT: run with --backup first (or give --from DIR)"
fi
[ "$MODE" = restore ] && [ "$CC_APPLY" = 1 ] && cc_require_root

cc_use_numbered_dir "site-$MODE"
chmod 700 "$CC_RUN_DIR" 2>/dev/null
rmdir "$CC_RUN_DIR/raw" 2>/dev/null
OUTF="$CC_RUN_DIR/output.txt"
grep -v '\[NOTE\]\|\[DEBUG\]' "$CC_LOG" >"$OUTF" 2>/dev/null || : >"$OUTF"
# shellcheck disable=SC2034  # CC_TEE is read by the library's log functions
CC_TEE=$OUTF
W="$CC_RUN_DIR/.work"; mkdir -p "$W"
# Tables are kept as .txt only; their CSV source is scratch data in .work.
CC_CSV_DIR="$W/csv"; mkdir -p "$CC_CSV_DIR"

cc_show "$C_CYN" "SV-15 Site backup and restore | host $CC_HOST | mode $MODE | results in $CC_RUN_DIR"
[ "$MODE" != backup ] && cc_show "$C_CYN" "Comparing with $FROM ($(cat "$FROM/.taken" 2>/dev/null))"
cc_show "" "Legend: ${C_RED}[!] HIGH${C_OFF} new program file (web shell?)   ${C_YEL}[*] MED${C_OFF} changed or deleted   ${C_GRY}[-] LOW${C_OFF} new other file   ${C_GRN}[ok]${C_OFF} same as the backup"
[ "$IS_ROOT" = 1 ] || cc_show "$C_YEL" "[!] Not root: some files and the databases cannot be read. Run with sudo."

# ---- Helpers --------------------------------------------------------------------
safe() { printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '_'; }
# excluded PATH -> true when an --exclude pattern matches PATH.
excluded() {
    [ -n "$EXCL" ] || return 1
    printf '%s\n' "$EXCL" | while IFS= read -r _p; do
        [ -n "$_p" ] || continue
        # shellcheck disable=SC2254  # the pattern is meant to match
        case "$1" in $_p) echo y; break ;; esac
    done | grep -q y
}
# manifest DIR -> "sha256  path" for every regular file under DIR, sorted
#   by path.  Symlinks are listed with a fixed hash "link:TARGET".
manifest() {
    {
        if cc_have sha256sum; then
            find "$1" -xdev -type f -exec sha256sum {} + 2>/dev/null
        else
            find "$1" -xdev -type f 2>/dev/null | while IFS= read -r _f; do printf '%s  %s\n' "$(cc_sha256 "$_f")" "$_f"; done
        fi
        find "$1" -xdev -type l 2>/dev/null | while IFS= read -r _l; do printf 'link:%s  %s\n' "$(readlink "$_l" | tr ' ' '_')" "$_l"; done
    } | if [ -n "$EXCL" ]; then
        while IFS= read -r _m; do excluded "${_m#*  }" || printf '%s\n' "$_m"; done
    else cat; fi | sort -k2
}

# ---- Find the sites ---------------------------------------------------------------
# $W/sites: "name|web root|config file", one per web root.
find_sites() {
    : >"$W/sites.raw"
    for _f in /etc/apache2/sites-enabled/* /etc/apache2/apache2.conf /etc/httpd/conf/httpd.conf /etc/httpd/conf.d/*.conf; do
        [ -f "$_f" ] || continue
        awk -v f="$_f" 'BEGIN { IGNORECASE = 0 }
            { l = $0; sub(/^[ \t]+/, "", l); d = tolower(l); split(l, w, /[ \t]+/) }
            d ~ /^<virtualhost/ { inv = 1; n = ""; r = "" }
            d ~ /^servername[ \t]/ && inv { n = w[2] }
            d ~ /^documentroot[ \t]/ { v = w[2]; gsub(/"/, "", v); if (inv) r = v; else mr = v }
            d ~ /^<\/virtualhost>/ { if (r != "") print (n != "" ? n : "default") "|" r "|" f; inv = 0 }
            END { if (mr != "") print "main|" mr "|" f }' "$_f" >>"$W/sites.raw"
    done
    for _f in /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf /etc/nginx/nginx.conf; do
        [ -f "$_f" ] || continue
        awk -v f="$_f" '
            { l = $0; sub(/#.*/, "", l); t = l; gsub(/^[ \t]+|[ \t;]+$/, "", t); split(t, w, /[ \t]+/) }
            !ins && t ~ /^server[ \t]*\{/ { ins = 1; sd = dep; n = ""; r = "" }
            ins && w[1] == "server_name" && n == "" { n = w[2] }
            ins && w[1] == "root" && dep == sd + 1 { r = w[2] }
            { dep += gsub(/\{/, "{", l); dep -= gsub(/\}/, "}", l) }
            ins && dep <= sd { if (r != "") print ((n != "" && n != "_") ? n : "default") "|" r "|" f; ins = 0 }' "$_f" >>"$W/sites.raw"
    done
    # Folders in /var/www that no config names (apps behind a proxy, or
    # turned off), and the ones given with --webroot.
    for _d in /var/www/* /srv/www/* /usr/share/nginx/html; do
        [ -d "$_d" ] && printf '%s|%s|-\n' "$(basename "$_d")" "$_d" >>"$W/sites.raw"
    done
    printf '%s' "$WEBROOTS" | while IFS= read -r _d; do [ -n "$_d" ] && printf '%s|%s|--webroot\n' "$(basename "$_d")" "$_d"; done >>"$W/sites.raw"
    # One entry per folder (the first name wins); nothing that is not a
    # folder, is /, or sits inside another site.
    awk -F'|' '{ sub(/\/+$/, "", $2) } $2 != "" && !seen[$2]++ { print }' OFS='|' "$W/sites.raw" >"$W/sites.u"
    : >"$W/sites.ok"
    while IFS='|' read -r _n _r _c; do
        [ -d "$_r" ] && [ "$_r" != / ] && printf '%s|%s|%s\n' "$_n" "$_r" "$_c" >>"$W/sites.ok"
    done <"$W/sites.u"
    sort -t'|' -k2,2 "$W/sites.ok" | awk -F'|' '{ for (k in keep) if (index($2, k "/") == 1) next; keep[$2] = 1; print }' >"$W/sites.n"
    # Unique, file-safe names.
    awk -F'|' -v OFS='|' '{ n = $1; gsub(/[^A-Za-z0-9._-]/, "_", n); if (used[n]++) n = n "-" used[n]; $1 = n; print }' "$W/sites.n" >"$W/sites"
    if [ -n "$SITES" ]; then
        awk -F'|' -v want=" $SITES " 'index(want, " " $1 " ")' "$W/sites" >"$W/sites.f"; mv "$W/sites.f" "$W/sites"
    fi
}

# ---- Each site's database, from its app config ------------------------------------
# app_db ROOT -> "app|engine|database|host" (empty when no database found).
app_db() {
    _r=$1; _app=""; _eng=mysql; _dbn=""; _dbh=localhost
    # sq: a single-quote character for the sed patterns.
    _q="['\"]"
    if [ -f "$_r/wp-config.php" ]; then
        _app=WordPress
        _dbn=$(sed -n "s/.*define( *${_q}DB_NAME${_q} *, *${_q}\([^'\"]*\)${_q}.*/\1/p" "$_r/wp-config.php" | head -n 1)
        _dbh=$(sed -n "s/.*define( *${_q}DB_HOST${_q} *, *${_q}\([^'\"]*\)${_q}.*/\1/p" "$_r/wp-config.php" | head -n 1)
    elif [ -f "$_r/configuration.php" ] && grep -q 'JConfig' "$_r/configuration.php" 2>/dev/null; then
        _app=Joomla
        _dbn=$(sed -n "s/.*public \$db *= *${_q}\([^'\"]*\)${_q}.*/\1/p" "$_r/configuration.php" | head -n 1)
        _dbh=$(sed -n "s/.*public \$host *= *${_q}\([^'\"]*\)${_q}.*/\1/p" "$_r/configuration.php" | head -n 1)
        grep -q "dbtype *= *${_q}p\?g\?sql" "$_r/configuration.php" && grep -qi "pgsql" "$_r/configuration.php" && _eng=postgres
    elif [ -f "$_r/sites/default/settings.php" ]; then
        _app=Drupal
        _dbn=$(sed -n "s/.*${_q}database${_q} *=> *${_q}\([^'\"]*\)${_q}.*/\1/p" "$_r/sites/default/settings.php" | head -n 1)
        _dbh=$(sed -n "s/.*${_q}host${_q} *=> *${_q}\([^'\"]*\)${_q}.*/\1/p" "$_r/sites/default/settings.php" | head -n 1)
        grep -q "${_q}driver${_q} *=> *${_q}pgsql" "$_r/sites/default/settings.php" && _eng=postgres
    elif [ -f "$_r/app/config/parameters.php" ]; then
        _app=PrestaShop
        _dbn=$(sed -n "s/.*${_q}database_name${_q} *=> *${_q}\([^'\"]*\)${_q}.*/\1/p" "$_r/app/config/parameters.php" | head -n 1)
        _dbh=$(sed -n "s/.*${_q}database_host${_q} *=> *${_q}\([^'\"]*\)${_q}.*/\1/p" "$_r/app/config/parameters.php" | head -n 1)
    elif [ -f "$_r/config/settings.inc.php" ]; then
        _app=PrestaShop
        _dbn=$(sed -n "s/.*define( *${_q}_DB_NAME_${_q} *, *${_q}\([^'\"]*\)${_q}.*/\1/p" "$_r/config/settings.inc.php" | head -n 1)
        _dbh=$(sed -n "s/.*define( *${_q}_DB_SERVER_${_q} *, *${_q}\([^'\"]*\)${_q}.*/\1/p" "$_r/config/settings.inc.php" | head -n 1)
    elif [ -f "$_r/config.php" ] && grep -q 'DB_DATABASE' "$_r/config.php" 2>/dev/null; then
        _app=OpenCart
        _dbn=$(sed -n "s/.*define( *${_q}DB_DATABASE${_q} *, *${_q}\([^'\"]*\)${_q}.*/\1/p" "$_r/config.php" | head -n 1)
        _dbh=$(sed -n "s/.*define( *${_q}DB_HOSTNAME${_q} *, *${_q}\([^'\"]*\)${_q}.*/\1/p" "$_r/config.php" | head -n 1)
    elif [ -f "$_r/app/etc/env.php" ]; then
        _app=Magento
        _dbn=$(sed -n "s/.*${_q}dbname${_q} *=> *${_q}\([^'\"]*\)${_q}.*/\1/p" "$_r/app/etc/env.php" | head -n 1)
        _dbh=$(sed -n "s/.*${_q}host${_q} *=> *${_q}\([^'\"]*\)${_q}.*/\1/p" "$_r/app/etc/env.php" | head -n 1)
    elif [ -f "$_r/program/include/iniset.php" ]; then
        _app=Roundcube
        for _c in "$_r/config/config.inc.php" /etc/roundcube/config.inc.php; do
            [ -f "$_c" ] || continue
            _dsn=$(sed -n "s/.*db_dsnw.\] *= *${_q}\([^'\"]*\)${_q}.*/\1/p" "$_c" | head -n 1)
            [ -n "$_dsn" ] && break
        done
        if [ -f /etc/roundcube/debian-db.php ] && { [ -z "$_dsn" ] || printf '%s' "$_dsn" | grep -q '\$'; }; then
            _dbn=$(sed -n "s/^\$dbname *= *${_q}\([^'\"]*\)${_q}.*/\1/p" /etc/roundcube/debian-db.php)
            _dbh=$(sed -n "s/^\$dbserver *= *${_q}\([^'\"]*\)${_q}.*/\1/p" /etc/roundcube/debian-db.php)
            grep -q "dbtype *= *${_q}pgsql" /etc/roundcube/debian-db.php && _eng=postgres
            grep -q "dbtype *= *${_q}sqlite" /etc/roundcube/debian-db.php && _eng=sqlite
        elif [ -n "$_dsn" ]; then
            case "$_dsn" in pgsql:*) _eng=postgres ;; sqlite:*) _eng=sqlite ;; esac
            _dbn=${_dsn##*/}; _dbn=${_dbn%%\?*}
            _dbh=$(printf '%s' "$_dsn" | sed -n 's|.*@\([^/:]*\).*|\1|p')
        fi
    elif [ -f "$_r/.env" ] && grep -q '^DB_DATABASE=' "$_r/.env" 2>/dev/null; then
        _app="app (.env)"
        _dbn=$(sed -n 's/^DB_DATABASE=["]*\([^"]*\)["]*.*/\1/p' "$_r/.env" | head -n 1)
        _dbh=$(sed -n 's/^DB_HOST=["]*\([^"]*\)["]*.*/\1/p' "$_r/.env" | head -n 1)
        grep -q '^DB_CONNECTION=pgsql' "$_r/.env" && _eng=postgres
    fi
    [ -n "$_app" ] || return 0
    _dbh=${_dbh%%:*}; [ -n "$_dbh" ] || _dbh=localhost
    printf '%s|%s|%s|%s\n' "$_app" "$_eng" "$_dbn" "$_dbh"
}
local_host() { case "$1" in localhost|127.*|::1|"$CC_HOST"|'') return 0 ;; esac; return 1; }

# ---- Database login (same order as SV-14) ----------------------------------------
MYOPT=""; MYC=$(cc_first mariadb mysql); MYD=$(cc_first mariadb-dump mysqldump)
mysql_login() {
    [ -n "$MYOPT" ] && return 0
    [ -n "$MYC" ] && [ -n "$MYD" ] || return 1
    for _try in "${MYCNF:+--defaults-extra-file=$MYCNF}" --user=root \
                "$( [ -r /etc/mysql/debian.cnf ] && echo --defaults-file=/etc/mysql/debian.cnf )"; do
        [ -n "$_try" ] || continue
        "$MYC" "$_try" --connect-timeout=5 -N -B -e 'SELECT 1' >/dev/null 2>&1 && { MYOPT=$_try; cc_debug "mysql login: $_try"; return 0; }
    done
    return 1
}
pgrun() {
    if cc_have runuser; then runuser -u postgres -- sh -c "cd / && $*"
    else su postgres -s /bin/sh -c "cd / && $*"; fi
}
# dump_db ENGINE DB FILE -> 0 when a complete dump was written.
dump_db() {
    case "$1" in
        mysql)
            mysql_login || return 2
            { "$MYD" "$MYOPT" --single-transaction --routines --triggers --events --hex-blob --databases "$2" 2>>"$CC_LOG"; echo $? >"$W/rc"; } | gzip -c >"$3"
            [ "$(cat "$W/rc")" = 0 ] && gzip -dc "$3" | tail -n 1 | grep -q 'Dump completed' ;;
        postgres)
            [ "$IS_ROOT" = 1 ] && cc_have pg_dump || return 2
            case "$2" in *[!A-Za-z0-9_-]*) return 2 ;; esac
            pgrun "pg_dump -Fc -d '$2'" >"$3" 2>>"$CC_LOG" && pg_restore -l "$3" >/dev/null 2>&1 ;;
        *) return 2 ;;
    esac
}
# load_db ENGINE DB FILE -> put a dump back (replaces the database's tables).
load_db() {
    case "$1" in
        mysql) gzip -dc "$3" | "$MYC" "$MYOPT" ;;
        postgres) pgrun "pg_restore --clean --if-exists -d '$2'" <"$3" ;;
    esac
}

# ---- Show the sites ----------------------------------------------------------------
header "1/3  sites"
find_sites
if [ "$MODE" != backup ]; then
    # Compare the sites that are in the backup (they may since have vanished).
    cp "$FROM/.sites" "$W/sites"
    if [ -n "$SITES" ]; then awk -F'|' -v want=" $SITES " 'index(want, " " $1 " ")' "$W/sites" >"$W/sites.f"; mv "$W/sites.f" "$W/sites"; fi
fi
if [ ! -s "$W/sites" ]; then
    cc_show "$C_YEL" "  [!] no web sites found$([ -n "$SITES" ] && echo " named:$SITES"). Give the folder with --webroot DIR."
    cc_finish; exit 0
fi
: >"$W/sitedb"
while IFS='|' read -r _n _r _c; do
    _db=$(app_db "$_r")
    printf '%s|%s\n' "$_n" "$_db" >>"$W/sitedb"
    cc_show "" "  $(printf '%-22s %-34s' "$_n" "$_r") ${_db:+$(printf '%s' "$_db" | awk -F'|' '{ printf "%s, %s database %s%s", $1, $2, ($3 == "" ? "?" : $3), ($4 ~ /^(localhost|127\.)/ ? "" : " on " $4) }')}"
done <"$W/sites"

# =============================================================================
# BACKUP
# =============================================================================
if [ "$MODE" = backup ]; then
    header "2/3  questions"
    if [ -z "$SITES" ] && [ "$(grep -c . "$W/sites")" -gt 1 ]; then
        cc_ask_text "Which sites?" all "site names separated by spaces (as listed above), or all"
        if [ "$CC_ANSWER" != all ]; then
            awk -F'|' -v want=" $CC_ANSWER " 'index(want, " " $1 " ")' "$W/sites" >"$W/sites.f"; mv "$W/sites.f" "$W/sites"
            [ -s "$W/sites" ] || cc_die 2 "none of those names is a site: $CC_ANSWER"
        fi
    fi
    if [ -z "$DB" ]; then
        if grep -q '|.*|.*|' "$W/sitedb"; then
            if cc_ask "Back up each site's database too?" Y "yes, dump it (read-only)" "no, files only"; then DB=1; else DB=0; fi
        else DB=0; fi
    fi
    if [ "$COPYSET" = 0 ]; then
        cc_ask_text "Copy the backup off the box?" "" "an scp destination like admin@10.0.0.5:/backups/, or Enter for no copy"
        COPYTO=$CC_ANSWER
    fi

    header "3/3  backing up"
    _need=0
    while IFS='|' read -r _n _r _c; do _need=$((_need + $(du -sk "$_r" 2>/dev/null | awk '{ print $1 }'))); done <"$W/sites"
    _need=$((_need / 1024))
    [ "$_need" -le "$MAXMB" ] || cc_die 3 "the sites add up to about $_need MB, more than --max-mb $MAXMB (use --exclude for caches and media, or raise --max-mb)"
    _free=$(df -Pk "$CC_RUN_DIR" 2>/dev/null | awk 'NR == 2 { print int($4 / 1024) }')
    [ -z "$_free" ] || [ "$_free" -gt "$_need" ] || cc_die 3 "not enough free space in $CC_OUT: need about $_need MB, have $_free MB"
    SCSV=$(cc_csv_new sites "site,web_root,config,files,size_kb,app,database,db_status")
    _nok=0; _nbad=0
    while IFS='|' read -r _n _r _c; do
        _sd="$CC_RUN_DIR/$_n"; mkdir -p "$_sd"
        manifest "$_r" >"$_sd/files.sha256"
        _nf=$(grep -c . "$_sd/files.sha256")
        # tar wants paths relative to /, one per line.
        sed 's/^[^ ]*  \///' "$_sd/files.sha256" >"$W/list"
        if (cd / && tar -czf "$_sd/files.tar.gz" -T "$W/list") 2>>"$CC_LOG" && gzip -t "$_sd/files.tar.gz" 2>/dev/null; then _fst=ok
        else _fst=FAILED; _nbad=$((_nbad + 1)); fi
        _kb=$(du -k "$_sd/files.tar.gz" 2>/dev/null | awk '{ print $1 }')
        _line=$(awk -F'|' -v n="$_n" '$1 == n { print $2 "|" $3 "|" $4 "|" $5; exit }' "$W/sitedb")
        _app=$(printf '%s' "$_line" | cut -d'|' -f1); _eng=$(printf '%s' "$_line" | cut -d'|' -f2)
        _dbn=$(printf '%s' "$_line" | cut -d'|' -f3); _dbh=$(printf '%s' "$_line" | cut -d'|' -f4)
        _dst="-"
        if [ "$DB" = 1 ] && [ -n "$_dbn" ]; then
            if ! local_host "$_dbh"; then _dst="on another host ($_dbh): back it up there"
            elif [ "$_eng" = sqlite ]; then _dst="sqlite: in the file archive"
            else
                _df="$_sd/db.sql.gz"; [ "$_eng" = postgres ] && _df="$_sd/db.dump"
                if dump_db "$_eng" "$_dbn" "$_df"; then _dst=ok; chmod 600 "$_df"
                else _rc=$?; rm -f "$_df"; _dst=$([ "$_rc" = 2 ] && echo "could not log in (give --mysql-cnf, run as root)" || echo FAILED); _nbad=$((_nbad + 1)); fi
            fi
        fi
        printf '%s|%s|%s|%s|%s\n' "$_n" "$_r" "$_app" "$_eng" "$_dbn" >"$_sd/info"
        cc_csv_row "$SCSV" "$_n" "$_r" "$_c" "$_nf" "$_kb" "${_app:--}" "${_dbn:--}" "$_dst"
        if [ "$_fst" = ok ]; then
            cc_show "$C_GRN" "  [+] $(printf '%-22s' "$_n") $_nf files ($((_kb / 1024)) MB)$([ "$_dst" = ok ] && echo ", database $_dbn")"
            _nok=$((_nok + 1))
        else cc_show "$C_RED" "  [x] $_n: the file archive failed (see $CC_LOG)"; fi
        case "$_dst" in ok|-|sqlite*) ;; *) cc_show "$C_YEL" "      database $_dbn: $_dst" ;; esac
    done <"$W/sites"
    # Web server and PHP configs, once for the box.
    : >"$W/clist"
    for _d in /etc/apache2 /etc/httpd /etc/nginx /etc/php /etc/php.ini /etc/php.d /etc/php-fpm.d; do [ -e "$_d" ] && printf '%s\n' "$_d" >>"$W/clist"; done
    if [ -s "$W/clist" ]; then
        while IFS= read -r _d; do manifest "$_d"; done <"$W/clist" >"$CC_RUN_DIR/config.sha256"
        sed 's/^[^ ]*  \///' "$CC_RUN_DIR/config.sha256" >"$W/list"
        (cd / && tar -czf "$CC_RUN_DIR/config.tar.gz" -T "$W/list") 2>>"$CC_LOG" &&
            cc_show "$C_GRN" "  [+] web server and PHP configs ($(grep -c . "$CC_RUN_DIR/config.sha256") files)"
    fi
    date -u +%Y-%m-%dT%H:%M:%SZ >"$CC_RUN_DIR/.taken"
    # The site list check and restore read back (name|folder|config).
    cp "$W/sites" "$CC_RUN_DIR/.sites"
    cat >"$CC_RUN_DIR/RESTORE.txt" <<EOF
Restoring from $CC_RUN_DIR (made on $CC_HOST at $(cat "$CC_RUN_DIR/.taken") by SV-15)

The easy way:  sh SV-15-site-backup.sh --check      what changed
               sh SV-15-site-backup.sh --restore --protected p.csv --apply

By hand (paths in the archives are relative to /):
  One file:        tar -xzpf SITE/files.tar.gz -C / var/www/html/index.php
  Look first:      mkdir /tmp/r && tar -xzpf SITE/files.tar.gz -C /tmp/r && diff -r /tmp/r/var/www/html /var/www/html
  What changed:    (cd / && sed 's|  /|  |' $CC_RUN_DIR/SITE/files.sha256 | sha256sum -c 2>/dev/null | grep -v ': OK\$')
  MySQL database:  gzip -dc SITE/db.sql.gz | mysql          (REPLACES its tables)
  PostgreSQL:      sudo -u postgres pg_restore --clean --if-exists -d DB < SITE/db.dump
  A web server config file:  tar -xzpf config.tar.gz -C / etc/apache2/sites-enabled/000-default.conf
                   then test (apache2ctl -t / nginx -t) BEFORE restarting it.
The archives hold the sites' database dumps and config passwords: keep this folder private.
EOF
    _copied=""
    if [ -n "$COPYTO" ] && [ "$_nok" -gt 0 ]; then
        if cc_have scp && scp -q -r -o ConnectTimeout=15 "$CC_RUN_DIR" "$COPYTO" 2>>"$CC_LOG"; then _copied=yes
        else _copied=no; cc_show "$C_RED" "  [x] copy to $COPYTO FAILED: the backup is only on this box"; fi
    fi
    if [ "$KEEP" -gt 0 ]; then
        for _d in "$CC_OUT"/site-backup-*; do [ -d "$_d" ] && printf '%s %s\n' "${_d##*-}" "$_d"; done | sort -n |
            awk -v k="$KEEP" '{ a[NR] = $2 } END { for (i = 1; i <= NR - k; i++) print a[i] }' >"$W/old"
        while IFS= read -r _d; do [ "$_d" != "$CC_RUN_DIR" ] && rm -rf "$_d" && cc_show "$C_GRY" "  [-] removed old backup $(basename "$_d") (--keep $KEEP)"; done <"$W/old"
    fi
    cc_csv_pretty "$SCSV" "$CC_RUN_DIR/sites.txt" 100
    {
        printf '==========[ summary ]==========\n'
        printf 'Backed up %s site(s) on %s at %s%s\n' "$_nok" "$CC_HOST" "$(cat "$CC_RUN_DIR/.taken")" "$([ "$_nbad" -gt 0 ] && echo "; $_nbad problem(s): see sites.txt")"
        case "$_copied" in yes) printf 'Copied off the box to %s\n' "$COPYTO" ;; no) printf 'COPY FAILED to %s\n' "$COPYTO" ;;
            *) printf 'Not copied off the box. From your workstation: scp -r root@%s:%s .\n' "$CC_HOST" "$CC_RUN_DIR" ;; esac
        printf '\nNext:  --check any time to see what changed;  --restore to put it back.\n'
        printf 'The backup holds database dumps and config passwords: keep %s private.\n' "$CC_RUN_DIR"
    } >"$CC_RUN_DIR/summary.txt"
    cc_show "" ""
    while IFS= read -r _l; do case "$_l" in ==*) cc_show "$C_CYN" "$_l" ;; Backed*) cc_show "$C_GRN" "$_l" ;; COPY*) cc_show "$C_RED" "$_l" ;; *) cc_show "" "$_l" ;; esac; done <"$CC_RUN_DIR/summary.txt"
    rm -rf "$W"
    cc_finish
    exit 0
fi

# =============================================================================
# CHECK and RESTORE: compare each site with the backup
# =============================================================================
# compare SITE ROOT -> $W/diff.SITE: "change|path" for changed, deleted and
#   new files; prints the three counts.
CODE_RE='\.(php[0-9]?|phtml|phar|inc|jsp|jspx|asp|aspx|ashx|cgi|pl|py|sh|so)$'
compare() {
    manifest "$2" >"$W/now.$1"
    awk 'FILENAME == ARGV[1] { h = substr($0, 1, index($0, "  ") - 1); p = substr($0, index($0, "  ") + 2); old[p] = h; next }
         { h = substr($0, 1, index($0, "  ") - 1); p = substr($0, index($0, "  ") + 2); seen[p] = 1
           if (!(p in old)) print "new|" p; else if (old[p] != h) print "changed|" p }
         END { for (p in old) if (!(p in seen)) print "deleted|" p }' "$FROM/$1/files.sha256" "$W/now.$1" | sort -t'|' -k2 >"$W/diff.$1"
    printf '%s %s %s\n' "$(grep -c '^changed|' "$W/diff.$1")" "$(grep -c '^deleted|' "$W/diff.$1")" "$(grep -c '^new|' "$W/diff.$1")"
}
# why CHANGE PATH -> severity and a few words on what the change may mean.
why() {
    case "$1" in
        new) if printf '%s' "$2" | grep -Eqi "$CODE_RE"; then echo "HIGH|new program file: a web shell or planted code?"
             else echo "LOW|new file (an upload, or planted content)"; fi ;;
        changed) case "$2" in
                     */index.*|*.html|*.htm) echo "MED|page changed: defaced?" ;;
                     *.php|*.js|*.jsp|*.asp*|*.py|*.inc) echo "MED|code changed: a backdoor added to it?" ;;
                     *.htaccess) echo "HIGH|.htaccess changed: can make any file run as PHP or redirect visitors" ;;
                     *config*|*.env|*settings*) echo "MED|config changed: database login or settings?" ;;
                     *) echo "MED|changed" ;;
                 esac ;;
        deleted) echo "MED|deleted (vandalism, or removed by the team)" ;;
    esac
}

header "2/3  what changed since $(cat "$FROM/.taken" 2>/dev/null || basename "$FROM")"
CCSV=$(cc_csv_new changes "site,change,file,severity,why")
: >"$W/plan"
NSITES_CH=0
while IFS='|' read -r _n _r _c; do
    if [ ! -f "$FROM/$_n/files.sha256" ]; then cc_show "$C_YEL" "  [!] $_n: not in that backup"; continue; fi
    if [ ! -d "$_r" ]; then
        cc_show "$C_RED" "  [!] $_n: the whole folder $_r is GONE (a restore puts it back)"
    fi
    # shellcheck disable=SC2046  # three numbers, split on purpose
    set -- $(compare "$_n" "$_r")
    _ch=$1; _de=$2; _nw=$3
    if [ $((_ch + _de + _nw)) -eq 0 ]; then
        cc_show "$C_GRN" "  [ok] $(printf '%-22s' "$_n") files same as the backup"
        # The database can still have been changed: offered on restore.
        { [ -f "$FROM/$_n/db.sql.gz" ] || [ -f "$FROM/$_n/db.dump" ]; } && printf '%s|%s|0|0|0\n' "$_n" "$_r" >>"$W/plan"
        continue
    fi
    NSITES_CH=$((NSITES_CH + 1))
    _hc=$C_YEL; awk -F'|' '$1 == "new"' "$W/diff.$_n" | cut -d'|' -f2- | grep -Eqi "$CODE_RE" && _hc=$C_RED
    cc_show "$_hc" "  [!] $(printf '%-22s' "$_n") $_ch changed, $_de deleted, $_nw new"
    _i=0
    while IFS='|' read -r _k _p; do
        _w=$(why "$_k" "$_p"); _sev=${_w%%"|"*}; _txt=${_w#*"|"}
        cc_csv_row "$CCSV" "$_n" "$_k" "$_p" "$_sev" "$_txt"
        _i=$((_i + 1))
        if [ "$_i" -le 25 ]; then
            case "$_sev" in HIGH) _cc=$C_RED; _m='[!]' ;; MED) _cc=$C_YEL; _m='[*]' ;; *) _cc=$C_GRY; _m='[-]' ;; esac
            cc_show "$_cc" "      $_m $(printf '%-8s' "$_k") $_p  - $_txt"
        fi
    done <"$W/diff.$_n"
    [ "$_i" -gt 25 ] && cc_show "$C_GRY" "      ... $((_i - 25)) more in changes.txt"
    printf '%s|%s|%s|%s|%s\n' "$_n" "$_r" "$_ch" "$_de" "$_nw" >>"$W/plan"
done <"$W/sites"
# Web server and PHP config files.
if [ -f "$FROM/config.sha256" ]; then
    : >"$W/cnow"
    awk '{ p = substr($0, index($0, "  ") + 2); print p }' "$FROM/config.sha256" | awk -F/ '{ print "/" $2 "/" $3 }' | sort -u | while IFS= read -r _d; do [ -e "$_d" ] && manifest "$_d"; done >"$W/cnow"
    awk 'FILENAME == ARGV[1] { h = substr($0, 1, index($0, "  ") - 1); p = substr($0, index($0, "  ") + 2); old[p] = h; next }
         { h = substr($0, 1, index($0, "  ") - 1); p = substr($0, index($0, "  ") + 2); seen[p] = 1; if (!(p in old)) print "new|" p; else if (old[p] != h) print "changed|" p }
         END { for (p in old) if (!(p in seen)) print "deleted|" p }' "$FROM/config.sha256" "$W/cnow" | sort -t'|' -k2 >"$W/cdiff"
    if [ -s "$W/cdiff" ]; then
        cc_show "$C_YEL" "  [*] web server / PHP config: $(grep -c . "$W/cdiff") file(s) differ (put back by hand: see RESTORE.txt in the backup)"
        while IFS='|' read -r _k _p; do
            cc_show "$C_YEL" "      [*] $(printf '%-8s' "$_k") $_p"
            cc_csv_row "$CCSV" "(config)" "$_k" "$_p" MED "web server or PHP config: compare, then restore by hand and test before restarting"
        done <"$W/cdiff"
    else
        cc_show "$C_GRN" "  [ok] web server and PHP configs same as the backup"
    fi
fi
cc_csv_pretty "$CCSV" "$CC_RUN_DIR/changes.txt" 120

if [ "$MODE" = check ]; then
    {
        printf '==========[ summary ]==========\n'
        if [ "$NSITES_CH" = 0 ]; then printf 'Every site matches the backup from %s.\n' "$(cat "$FROM/.taken" 2>/dev/null)"
        else
            printf '%s site(s) changed since the backup from %s:\n' "$NSITES_CH" "$(cat "$FROM/.taken" 2>/dev/null)"
            awk -F'|' '$3 + $4 + $5 > 0 { printf "  %-22s %s changed, %s deleted, %s new\n", $1, $3, $4, $5 }' "$W/plan"
            printf '\nEvery file: %s/changes.txt\n' "$CC_RUN_DIR"
            printf 'Put it back:  --restore (asks per site; dry run unless --apply)\n'
        fi
    } >"$CC_RUN_DIR/summary.txt"
    cc_show "" ""
    while IFS= read -r _l; do case "$_l" in ==*) cc_show "$C_CYN" "$_l" ;; Every\ site*) cc_show "$C_GRN" "$_l" ;; *changed\ since*) cc_show "$C_YEL" "$_l" ;; *) cc_show "" "$_l" ;; esac; done <"$CC_RUN_DIR/summary.txt"
    rm -rf "$W"
    cc_finish
    exit 0
fi

# =============================================================================
# RESTORE
# =============================================================================
header "3/3  restore"
if [ ! -s "$W/plan" ]; then
    cc_show "$C_GRN" "  [ok] Nothing to put back: every site matches the backup."
    rm -rf "$W"; cc_finish; exit 0
fi
# Questions, per site.
: >"$W/do"
while IFS='|' read -r _n _r _ch _de _nw; do
    _a=$WHAT
    if [ $((_ch + _de + _nw)) -eq 0 ]; then _a=dbonly
    elif [ -z "$_a" ]; then
        _d=a
        cc_choose "$_n: $_ch changed, $_de deleted, $_nw new. What should I do?" "$_d" \
            "a=all back to the backup: restore changed and deleted files, new files to quarantine" \
            "f=files only: restore changed and deleted files, leave new files" \
            "q=quarantine the new files only" \
            "n=nothing for this site"
        case "$CC_CHOICE" in a) _a=all ;; f) _a=files ;; q) _a=new ;; *) _a=none ;; esac
    fi
    _rdb=0
    _eng=$(cut -d'|' -f4 "$FROM/$_n/info" 2>/dev/null); _dbn=$(cut -d'|' -f5 "$FROM/$_n/info" 2>/dev/null)
    _dbf=""; [ -f "$FROM/$_n/db.sql.gz" ] && _dbf="$FROM/$_n/db.sql.gz"; [ -f "$FROM/$_n/db.dump" ] && _dbf="$FROM/$_n/db.dump"
    if [ -n "$_dbf" ] && [ "$_a" != none ]; then
        if [ -n "$RDB" ]; then _rdb=$RDB
        elif cc_ask "$_n: $([ "$_a" = dbonly ] && echo "files unchanged. Put" || echo "also put") the database $_dbn back as it was at the backup?" N "yes, replace it (the current one is saved first; changes since the backup are lost)" "no, leave the database"; then _rdb=1; fi
    fi
    printf '%s|%s|%s|%s|%s|%s\n' "$_n" "$_r" "$_a" "$_rdb" "$_eng|$_dbn" "$_dbf" >>"$W/do"
done <"$W/plan"

# The plan.
PCSV=$(cc_csv_new plan "site,action,file")
NCH=0
while IFS='|' read -r _n _r _a _rdb _eng _dbn _dbf; do
    : >"$W/rest.$_n"; : >"$W/quar.$_n"
    case "$_a" in all|files) awk -F'|' '$1 == "changed" || $1 == "deleted" { print $2 }' "$W/diff.$_n" >"$W/rest.$_n" ;; esac
    case "$_a" in all|new) awk -F'|' '$1 == "new" { print $2 }' "$W/diff.$_n" >"$W/quar.$_n" ;; esac
    _nr=$(grep -c . "$W/rest.$_n"); _nq=$(grep -c . "$W/quar.$_n")
    NCH=$((NCH + _nr + _nq + _rdb))
    while IFS= read -r _p; do cc_csv_row "$PCSV" "$_n" "put back from the backup" "$_p"; done <"$W/rest.$_n"
    while IFS= read -r _p; do cc_csv_row "$PCSV" "$_n" "move to quarantine" "$_p"; done <"$W/quar.$_n"
    [ "$_rdb" = 1 ] && cc_csv_row "$PCSV" "$_n" "put the database back" "$_dbn ($_eng)"
    if [ "$_a" = dbonly ]; then [ "$_rdb" = 1 ] && cc_show "$C_YEL" "  [~] $(printf '%-22s' "$_n") put the database $_dbn back"
    elif [ "$_a" != none ]; then cc_show "$C_YEL" "  [~] $(printf '%-22s' "$_n") put back $_nr file(s), quarantine $_nq new file(s)$([ "$_rdb" = 1 ] && echo ", put the database $_dbn back")"; fi
done <"$W/do"
cc_csv_pretty "$PCSV" "$CC_RUN_DIR/plan.txt" 120
APPLIED=0; TIMER_ON=0
if [ "$NCH" -eq 0 ]; then
    cc_show "$C_GRN" "  [ok] Nothing chosen."
elif [ "$CC_APPLY" != 1 ]; then
    cc_show "$C_GRY" "  Dry run: nothing was changed. The plan is in $CC_RUN_DIR/plan.txt. Run again with --apply to do it."
elif ! cc_ask "Do these $NCH change(s) now?" Y "yes, put them back (a revert timer undoes it unless you confirm from a NEW session)" "no, change nothing"; then
    cc_show "$C_GRY" "  Not done. The plan is in $CC_RUN_DIR/plan.txt"
else
    APPLIED=1
    if [ "$NOTIMER" != 1 ]; then
        cc_timer_start "$TIMER"; TIMER_ON=1
        cc_show "$C_YEL" "  [*] Revert timer started: everything is undone in $((TIMER / 60)):$(printf '%02d' $((TIMER % 60))) unless you keep it at the end."
    fi
    RCSV=$(cc_csv_new changes "site,action,file,result")
    mkdir -p "$CC_RUN_DIR/before"
    _q=$CC_QUIET; CC_QUIET=1
    while IFS='|' read -r _n _r _a _rdb _eng _dbn _dbf; do
        [ "$_a" = none ] && continue
        [ "$_a" = dbonly ] && [ "$_rdb" != 1 ] && continue
        _ok=0; _bad=0
        # Files: save the current version, then extract the backup's copies.
        if [ -s "$W/rest.$_n" ]; then
            while IFS= read -r _p; do
                if [ -e "$_p" ]; then cc_backup_file "$_p" >/dev/null || true
                else cc_undo_add "remove $_p (put back by SV-15; it was deleted before)" "rm -f $(cc_shquote "$_p")"; fi
            done <"$W/rest.$_n"
            sed 's|^/||' "$W/rest.$_n" >"$W/rel.$_n"
            if cc_run "put back $(grep -c . "$W/rel.$_n") file(s) of $_n" sh -c 'cd / && tar -xzpf "$1" -T "$2"' sh "$FROM/$_n/files.tar.gz" "$W/rel.$_n"; then
                _ok=$((_ok + $(grep -c . "$W/rel.$_n")))
                while IFS= read -r _p; do cc_csv_row "$RCSV" "$_n" "put back" "$_p" ok; done <"$W/rest.$_n"
            else
                _bad=$((_bad + 1)); cc_show "$C_RED" "  [x] $_n: extracting from the backup failed (see $CC_LOG)"
            fi
        fi
        # New files: to quarantine (they can be moved back).
        while IFS= read -r _p; do
            if cc_quarantine "$_p"; then _ok=$((_ok + 1)); cc_csv_row "$RCSV" "$_n" "quarantined" "$_p" ok
            else _bad=$((_bad + 1)); cc_csv_row "$RCSV" "$_n" "quarantined" "$_p" "refused or failed"; fi
        done <"$W/quar.$_n"
        # Database: save the current one, then load the backup.
        if [ "$_rdb" = 1 ]; then
            _pre="$CC_RUN_DIR/before/$_n.db"
            if [ "$_eng" = mysql ] && mysql_login; then
                if dump_db mysql "$_dbn" "$_pre.sql.gz"; then
                    cc_undo_add "put database $_dbn back as it was before the restore" "gzip -dc $(cc_shquote "$_pre.sql.gz") | $MYC $(cc_shquote "$MYOPT")"
                    if load_db mysql "$_dbn" "$_dbf" 2>>"$CC_LOG"; then _ok=$((_ok + 1)); cc_csv_row "$RCSV" "$_n" "database put back" "$_dbn" ok
                    else _bad=$((_bad + 1)); cc_show "$C_RED" "  [x] $_n: loading the database failed (see $CC_LOG)"; fi
                else _bad=$((_bad + 1)); cc_show "$C_RED" "  [x] $_n: could not save the current database first, so it was NOT replaced"; fi
            elif [ "$_eng" = postgres ]; then
                if dump_db postgres "$_dbn" "$_pre.dump"; then
                    cc_undo_add "put database $_dbn back as it was before the restore" "runuser -u postgres -- pg_restore --clean --if-exists -d $(cc_shquote "$_dbn") < $(cc_shquote "$_pre.dump")"
                    if load_db postgres "$_dbn" "$_dbf" 2>>"$CC_LOG"; then _ok=$((_ok + 1)); cc_csv_row "$RCSV" "$_n" "database put back" "$_dbn" ok
                    else _bad=$((_bad + 1)); cc_show "$C_RED" "  [x] $_n: loading the database failed (see $CC_LOG)"; fi
                else _bad=$((_bad + 1)); cc_show "$C_RED" "  [x] $_n: could not save the current database first, so it was NOT replaced"; fi
            else _bad=$((_bad + 1)); cc_show "$C_RED" "  [x] $_n: cannot log in to the database (give --mysql-cnf)"; fi
        fi
        # Check: the site should now match the backup for what was chosen.
        # shellcheck disable=SC2046  # three numbers, split on purpose
        set -- $(compare "$_n" "$_r")
        _left=""
        case "$_a" in all) _left=$(($1 + $2 + $3)) ;; files) _left=$(($1 + $2)) ;; new) _left=$3 ;; *) _left=0 ;; esac
        if [ "$_left" = 0 ] && [ "$_bad" = 0 ]; then cc_show "$C_GRN" "  [+] $(printf '%-22s' "$_n") $_ok change(s) done; matches the backup now"
        else cc_show "$C_YEL" "  [*] $(printf '%-22s' "$_n") $_ok done, $_bad failed; still different: $1 changed, $2 deleted, $3 new"; fi
    done <"$W/do"
    CC_QUIET=$_q
    cc_csv_pretty "$RCSV" "$CC_RUN_DIR/changes-made.txt" 120
fi
if [ "$TIMER_ON" = 1 ]; then header "KEEP OR REVERT"; cc_timer_finish || true; fi
{
    printf '==========[ summary ]==========\n'
    printf '%s | compared with the backup from %s\n' "$([ "$APPLIED" = 1 ] && echo RESTORED || echo 'DRY RUN - nothing changed')" "$(cat "$FROM/.taken" 2>/dev/null)"
    awk -F'|' '{ printf "  %-22s %s\n", $1, ($3 == "all" ? "everything back to the backup" : $3 == "files" ? "changed and deleted files back" : $3 == "new" ? "new files to quarantine" : $3 == "dbonly" ? "files unchanged" : "left as it is") ($4 == 1 ? ", database back" : "") }' "$W/do"
    printf '\nPlan: %s/plan.txt\n' "$CC_RUN_DIR"
    [ "$APPLIED" = 1 ] && [ "$TIMER_ON" = 1 ] && printf 'Undo it all: sh %s/revert.sh --force\n' "$CC_RUN_DIR"
    printf 'Quarantined files can be moved back from %s\n' "$CC_QUAR_DIR"
} >"$CC_RUN_DIR/summary.txt"
cc_show "" ""
while IFS= read -r _l; do case "$_l" in ==*) cc_show "$C_CYN" "$_l" ;; RESTORED*) cc_show "$C_GRN" "$_l" ;; DRY*) cc_show "$C_YEL" "$_l" ;; *) cc_show "" "$_l" ;; esac; done <"$CC_RUN_DIR/summary.txt"
rm -rf "$W"
cc_finish
