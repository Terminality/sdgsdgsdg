#!/bin/sh
# =============================================================================
# ID:       SV-14
# NAME:     Database backup
# ROLE:     Applications  (wave 1, first 15 minutes)
# KIND:     readonly - reads the databases, writes only into the output folder
# VERSION:  1.0.0
#
# PURPOSE
#   Copying a running database's files does not give a usable backup; a dump
#   does.  This dumps every database on a Linux/Unix host, checks each dump
#   can be read back, hashes them and can copy them off the box:
#     MySQL / MariaDB   one file per database (mysql_<db>.sql.gz), including
#                       the "mysql" system database (accounts and grants);
#                       consistent for InnoDB (--single-transaction), with
#                       routines, triggers and events
#     PostgreSQL        roles and settings (pg_globals.sql.gz) plus one
#                       custom-format dump per database (pg_<db>.dump)
#     SQLite            database files found in web roots (or given with
#                       --sqlite), copied with sqlite3 .backup when available
#   With the backup you can undo a dropped table, a defaced page stored in a
#   database, or an admin account the red team added.
#
# USAGE
#   sudo sh SV-14-db-backup.sh [--out DIR]
#   sudo sh SV-14-db-backup.sh --copy-to admin@10.0.0.5:/srv/backups/db01/
#
# OPTIONS
#   --only mysql,postgres,sqlite   which engines (default: all found)
#   --mysql-cnf FILE   MySQL client file with a user and password ([client]
#                      section) when root cannot log in through the socket
#   --sqlite FILE      also back up this SQLite file (repeat)
#   --max-mb N         refuse if the databases add up to more than N MB
#                      (default 4096)
#   --keep N           keep only the newest N SV-14 backups of this host in
#                      the output folder (default: keep all)
#   --copy-to DEST     copy the result off the box with scp
#   --help             this text plus the common options
#
# OUTPUTS  (under --out, in SV-14_<host>_<UTC time>/, mode 700)
#   mysql_<db>.sql.gz, pg_globals.sql.gz, pg_<db>.dump, sqlite_<name>.db
#   SHA256SUMS        hashes of every dump
#   dumps.txt         engine, database, file, size_kb, status
#   RESTORE.txt       restore commands for each dump
#   summary.txt       what was dumped and what failed
#
# WHAT IT CHANGES
#   Nothing in the databases or on the host.  Dumps are read-only for the
#   database (InnoDB dumps run in one transaction; MyISAM tables are read
#   without locking, so a table written during the dump can be a moment
#   inconsistent).  --keep deletes old SV-14 folders in the output folder.
#
#   SECURITY NOTE: the dumps hold every password hash and every row of data,
#   including the "mysql" database.  Keep the folder private.
#
# DEPENDS ON
#   mysqldump or mariadb-dump (and the mysql client to list databases);
#   pg_dump, pg_dumpall (and pg_restore to verify); sqlite3 optional; gzip.
#
# TESTED ON
#   Ubuntu 24.04 with MariaDB 10.11 and PostgreSQL 16 under dash, bash,
#   busybox sh, ksh93, mksh and yash: dumps restored into new databases
#   gave back the same rows.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - MongoDB, Redis and MSSQL are not covered (MSSQL is in the Windows set).
#   - A SQLite file copied without sqlite3 while the app writes to it can be
#     inconsistent; install sqlite3 or stop the app for the copy.
#   - Big databases take time and disk: --max-mb protects the disk.
#
# DEBUGGING
#   --debug shows how the script logged in and each command (without
#   passwords).  Each dump tool's own errors are in the log.
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
SV-14 Database backup - dump every MySQL/MariaDB, PostgreSQL and SQLite database
  sudo sh SV-14-db-backup.sh [options]

  --only mysql,postgres,sqlite   which engines (default: all found)
  --mysql-cnf FILE   MySQL client file with user and password
  --sqlite FILE      also back up this SQLite file (repeatable)
  --max-mb N         refuse if the databases are bigger than N MB (default 4096)
  --keep N           keep only the newest N backups of this host
  --copy-to DEST     copy the result off the box with scp
  --help             show this text

USAGE
    cc_usage_common
}

NL='
'
ONLY="mysql,postgres,sqlite"; MYCNF=""; SQLITES=""; MAXMB=4096; KEEP=0; COPYTO=""
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --only)      [ $# -ge 2 ] || cc_die 2 "--only needs a list"; ONLY=$2; shift 2 ;;
        --mysql-cnf) [ $# -ge 2 ] || cc_die 2 "--mysql-cnf needs a file"; [ -r "$2" ] || cc_die 2 "--mysql-cnf: cannot read $2"; MYCNF=$(cc_abspath "$2"); shift 2 ;;
        --sqlite)    [ $# -ge 2 ] || cc_die 2 "--sqlite needs a file"; [ -r "$2" ] || cc_die 2 "--sqlite: cannot read $2"; SQLITES="$SQLITES$(cc_abspath "$2")$NL"; shift 2 ;;
        --max-mb)    [ $# -ge 2 ] || cc_die 2 "--max-mb needs a number"; MAXMB=$2; shift 2 ;;
        --keep)      [ $# -ge 2 ] || cc_die 2 "--keep needs a number"; KEEP=$2; shift 2 ;;
        --copy-to)   [ $# -ge 2 ] || cc_die 2 "--copy-to needs a destination"; COPYTO=$2; shift 2 ;;
        --help|-h)   usage; exit 0 ;;
        *)           cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
case "$MAXMB" in ''|*[!0-9]*) cc_die 2 "--max-mb needs a whole number" ;; esac
case "$KEEP" in ''|*[!0-9]*) cc_die 2 "--keep needs a whole number" ;; esac
for _e in $(printf '%s' "$ONLY" | tr ',' ' '); do
    case "$_e" in mysql|postgres|sqlite) ;; *) cc_die 2 "--only: unknown engine '$_e' (mysql, postgres, sqlite)" ;; esac
done
want() { case ",$ONLY," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }

cc_init "SV-14" "Database backup" readonly
cc_detect_os
IS_ROOT=0
cc_is_root && IS_ROOT=1
[ "$IS_ROOT" = 1 ] || cc_warn "not running as root: PostgreSQL and the MySQL socket login need root; give --mysql-cnf for MySQL"
cc_use_run_dir
chmod 700 "$CC_RUN_DIR" 2>/dev/null
W="$CC_RUN_DIR/.work"
mkdir -p "$W" || cc_die 3 "cannot create $W"
CSV=$(cc_csv_new dumps "engine,database,file,size_kb,status")
cc_have gzip || cc_die 3 "gzip not found"
TO=""
cc_have timeout && TO="timeout 3600"
: >"$W/notes"
note() { printf '%s\n' "$*" >>"$W/notes"; }
_nok=0; _nfail=0
# done_row ENGINE DB FILE STATUS
done_row() {
    _kb=0; [ -f "$CC_RUN_DIR/$3" ] && _kb=$(du -k "$CC_RUN_DIR/$3" 2>/dev/null | awk '{ print $1 }')
    cc_csv_row "$CSV" "$1" "$2" "$3" "$_kb" "$4"
    case "$4" in ok*) _nok=$((_nok + 1)) ;; *) _nfail=$((_nfail + 1)); CC_N_FAIL=$((CC_N_FAIL + 1)) ;; esac
}
# Free space check against an estimate (MB).
_est=0
space_check() {
    _est=$((_est + $1))
    [ "$_est" -le "$MAXMB" ] || cc_die 3 "the databases add up to about $_est MB, more than --max-mb $MAXMB"
    _free=$(df -Pk "$CC_RUN_DIR" 2>/dev/null | awk 'NR == 2 { print int($4 / 1024) }')
    [ -z "$_free" ] || [ "$_free" -ge "$_est" ] || cc_die 3 "not enough free space in $CC_OUT: need about $_est MB, have $_free MB"
}

# ---- MySQL / MariaDB ---------------------------------------------------------
MYOPT=""
if want mysql; then
    MYC=$(cc_first mariadb mysql)
    MYD=$(cc_first mariadb-dump mysqldump)
    if [ -z "$MYC" ] || [ -z "$MYD" ]; then
        cc_debug "mysql: client or dump tool not installed"
    else
        # Same login order as SV-01: given file, root by socket, Debian
        # maintenance account, the client's own defaults.  Never prompts.
        for _try in "${MYCNF:+--defaults-extra-file=$MYCNF}" --user=root \
                    "$( [ -r /etc/mysql/debian.cnf ] && echo --defaults-file=/etc/mysql/debian.cnf )" "-"; do
            [ -n "$_try" ] || continue
            if [ "$_try" = "-" ]; then
                "$MYC" --connect-timeout=5 -N -B -e 'SELECT 1' >/dev/null 2>&1 && { MYOPT="-"; break; }
            else
                "$MYC" "$_try" --connect-timeout=5 -N -B -e 'SELECT 1' >/dev/null 2>&1 && { MYOPT=$_try; break; }
            fi
        done
        if [ -z "$MYOPT" ]; then
            if pgrep -x mysqld >/dev/null 2>&1 || pgrep -x mariadbd >/dev/null 2>&1; then
                note "MySQL/MariaDB is running but could not log in: give --mysql-cnf"
                _nfail=$((_nfail + 1)); CC_N_FAIL=$((CC_N_FAIL + 1))
            fi
        else
            cc_debug "mysql login: $MYOPT"
            # my CLIENT ARGS... -> run a MySQL tool with the login option first
            # (--defaults-file must be the first option).
            my() { _my_t=$1; shift; if [ "$MYOPT" = "-" ]; then "$_my_t" "$@"; else "$_my_t" "$MYOPT" "$@"; fi; }
            # mydump ARGS... -> the dump tool with the login option and, where
            # "timeout" exists, a one-hour limit (it cannot wrap a function).
            # shellcheck disable=SC2086
            mydump() { if [ "$MYOPT" = "-" ]; then $TO "$MYD" "$@"; else $TO "$MYD" "$MYOPT" "$@"; fi; }
            my "$MYC" -N -B -e "SELECT s.schema_name, IFNULL(ROUND(SUM(t.data_length + t.index_length) / 1048576), 0) FROM information_schema.schemata s LEFT JOIN information_schema.tables t ON t.table_schema = s.schema_name GROUP BY s.schema_name" 2>>"$CC_LOG" |
                awk -F'\t' '$1 != "information_schema" && $1 != "performance_schema" && $1 != "sys"' >"$W/mydbs"
            space_check "$(awk -F'\t' '{ s += $2 } END { print s + 0 }' "$W/mydbs")"
            while IFS="$(printf '\t')" read -r _db _mb; do
                _f="mysql_$(printf '%s' "$_db" | tr -c 'A-Za-z0-9_.-' '_').sql.gz"
                cc_info "mysql: dumping $_db (about ${_mb} MB)"
                # The dump tool's exit code is kept in a file: the pipe to gzip hides it.
                { mydump --single-transaction --routines --triggers --events --hex-blob --databases "$_db" 2>>"$CC_LOG"; echo $? >"$W/rc"; } | gzip -c >"$CC_RUN_DIR/$_f"
                if [ "$(cat "$W/rc")" = 0 ] && gzip -t "$CC_RUN_DIR/$_f" 2>/dev/null && gzip -dc "$CC_RUN_DIR/$_f" | tail -n 1 | grep -q 'Dump completed'; then
                    done_row mysql "$_db" "$_f" ok
                else
                    done_row mysql "$_db" "$_f" "FAILED (exit $(cat "$W/rc"); see the log)"
                fi
            done <"$W/mydbs"
        fi
    fi
fi

# ---- PostgreSQL ----------------------------------------------------------------
if want postgres && cc_have pg_dump; then
    if [ "$IS_ROOT" = 1 ] && grep -q '^postgres:' /etc/passwd; then
        # Run as the postgres account; output goes through this (root) shell.
        pgrun() {
            if cc_have runuser; then runuser -u postgres -- sh -c "cd / && $*"
            else su postgres -s /bin/sh -c "cd / && $*"; fi
        }
        if pgrun "psql -X -A -t -c 'SELECT 1'" >/dev/null 2>&1; then
            pgrun "psql -X -A -t -F '|' -c 'SELECT datname, pg_database_size(datname) / 1048576 FROM pg_database WHERE datallowconn AND NOT datistemplate'" >"$W/pgdbs" 2>>"$CC_LOG"
            space_check "$(awk -F'|' '{ s += $2 } END { print s + 0 }' "$W/pgdbs")"
            cc_info "postgres: dumping roles and settings"
            { pgrun "$TO pg_dumpall --globals-only" 2>>"$CC_LOG"; echo $? >"$W/rc"; } | gzip -c >"$CC_RUN_DIR/pg_globals.sql.gz"
            if [ "$(cat "$W/rc")" = 0 ]; then done_row postgres "(roles)" pg_globals.sql.gz ok; else done_row postgres "(roles)" pg_globals.sql.gz "FAILED (see the log)"; fi
            while IFS='|' read -r _db _mb; do
                [ -n "$_db" ] || continue
                case "$_db" in *"'"*|*'"'*|*'$'*|*'`'*) note "postgres: database name $_db has quote characters: dump it by hand"; continue ;; esac
                _f="pg_$(printf '%s' "$_db" | tr -c 'A-Za-z0-9_.-' '_').dump"
                cc_info "postgres: dumping $_db (about ${_mb} MB)"
                pgrun "$TO pg_dump -Fc -d '$_db'" >"$CC_RUN_DIR/$_f" 2>>"$CC_LOG"
                _rc=$?
                # pg_restore -l reads the dump's table of contents: a quick
                # proof the file is a complete custom-format dump.
                if [ "$_rc" -eq 0 ] && pg_restore -l "$CC_RUN_DIR/$_f" >/dev/null 2>&1; then done_row postgres "$_db" "$_f" ok
                else done_row postgres "$_db" "$_f" "FAILED (exit $_rc; see the log)"; fi
            done <"$W/pgdbs"
        else
            if pgrep -x postgres >/dev/null 2>&1; then note "PostgreSQL is running but the postgres account could not log in through the socket"; _nfail=$((_nfail + 1)); CC_N_FAIL=$((CC_N_FAIL + 1)); fi
        fi
    elif pgrep -x postgres >/dev/null 2>&1; then
        note "PostgreSQL is running: run as root to dump it"
    fi
fi

# ---- SQLite --------------------------------------------------------------------------
if want sqlite; then
    {
        printf '%s' "$SQLITES"
        # Files in web roots that start with the SQLite header.
        for _d in /var/www /srv/www /srv/http /usr/share/nginx/html /var/lib/grafana /opt; do
            [ -d "$_d" ] || continue
            find "$_d" -xdev -type f \( -name '*.sqlite' -o -name '*.sqlite3' -o -name '*.db' -o -name '*.db3' \) -size -2097152 2>/dev/null
        done
    } | grep . | sort -u >"$W/sqlite.cand"
    _i=0
    while IFS= read -r _s; do
        [ "$(dd if="$_s" bs=15 count=1 2>/dev/null)" = "SQLite format 3" ] || continue
        _i=$((_i + 1))
        _f="sqlite_${_i}_$(basename "$_s" | tr -c 'A-Za-z0-9_.-' '_')"
        if cc_have sqlite3 && sqlite3 "$_s" ".backup '$CC_RUN_DIR/$_f'" 2>>"$CC_LOG"; then
            done_row sqlite "$_s" "$_f" "ok (sqlite3 .backup)"
        elif cp -p "$_s" "$CC_RUN_DIR/$_f" 2>>"$CC_LOG"; then
            done_row sqlite "$_s" "$_f" "ok (copied; may be inconsistent if written during the copy)"
        else
            done_row sqlite "$_s" "$_f" "FAILED to copy"
        fi
    done <"$W/sqlite.cand"
fi

# ---- Hashes, restore notes, copy, rotation ------------------------------------------
chmod 600 "$CC_RUN_DIR"/mysql_* "$CC_RUN_DIR"/pg_* "$CC_RUN_DIR"/sqlite_* 2>/dev/null
(cd "$CC_RUN_DIR" && for _f in mysql_* pg_* sqlite_*; do
    [ -f "$_f" ] || continue
    _h=$(cc_sha256 "$_f") && printf '%s  %s\n' "$_h" "$_f"
done) >"$CC_RUN_DIR/SHA256SUMS"

{
    printf 'Restoring from %s (made on %s by SV-14)\n\n' "$CC_RUN_DIR" "$CC_HOST"
    printf 'Check the files first:  cd %s && sha256sum -c SHA256SUMS\n\n' "$CC_RUN_DIR"
    awk "$CC_AWK_CSV"'NR > 1 { csvsplit($0, f); if (f[5] !~ /^ok/) next
        if (f[1] == "mysql") {
            printf "MySQL %s (REPLACES the database: its file holds DROP/CREATE TABLE):\n  gzip -dc %s | mysql\n", f[2], f[3]
            printf "  to compare first, load it under another name:\n  mysql -e \"CREATE DATABASE restore_check\" && gzip -dc %s | sed \"s/^USE `%s`/USE `restore_check`/; /^CREATE DATABASE/d\" | mysql restore_check\n\n", f[3], f[2]
        } else if (f[1] == "postgres" && f[2] == "(roles)") {
            printf "PostgreSQL roles (creates missing roles; existing ones give harmless errors):\n  gzip -dc %s | sudo -u postgres psql\n\n", f[3]
        } else if (f[1] == "postgres") {
            # The file is fed on stdin: the postgres account cannot open
            # files in this private (root-only) folder itself.
            printf "PostgreSQL %s (REPLACES its objects):\n  sudo -u postgres pg_restore --clean --if-exists -d %s < %s\n", f[2], f[2], f[3]
            printf "  to compare first:  sudo -u postgres createdb restore_check && sudo -u postgres pg_restore -d restore_check < %s\n\n", f[3]
        } else if (f[1] == "sqlite") {
            printf "SQLite %s (stop the app first):\n  cp -p %s %s.before-restore && cp %s %s\n\n", f[2], f[2], f[2], f[3], f[2]
        } }' "$CSV"
    printf 'Restore ONE table from a MySQL dump: extract its part with\n  gzip -dc FILE | sed -n "/^-- Table structure for table `TABLE`/,/^-- Table structure for table/p" > table.sql\n'
} >"$CC_RUN_DIR/RESTORE.txt"

_copied=""
if [ -n "$COPYTO" ] && [ "$_nok" -gt 0 ]; then
    cc_need scp
    set --
    for _f in "$CC_RUN_DIR"/mysql_* "$CC_RUN_DIR"/pg_* "$CC_RUN_DIR"/sqlite_* "$CC_RUN_DIR/SHA256SUMS" "$CC_RUN_DIR/RESTORE.txt"; do [ -f "$_f" ] && set -- "$@" "$_f"; done
    if scp -q -o ConnectTimeout=15 "$@" "$COPYTO" 2>>"$CC_LOG"; then _copied=yes; else _copied=no; CC_N_FAIL=$((CC_N_FAIL + 1)); cc_err "copy to $COPYTO FAILED"; fi
fi
if [ "$KEEP" -gt 0 ]; then
    # Folder names end in the UTC time, so a name sort is a time sort.
    # Folders only (the .log files share the name), trailing "/" removed
    # before sorting so "...Z" sorts before its same-second twin "...Z-2".
    for _o in "$CC_OUT"/SV-14_"$CC_HOST"_*/; do [ -d "$_o" ] && printf '%s\n' "${_o%/}"; done | sort | awk -v k="$KEEP" '{ a[NR] = $0 } END { for (i = 1; i <= NR - k; i++) print a[i] }' >"$W/old"
    while IFS= read -r _o; do
        [ -d "$_o" ] && [ "$_o" != "$CC_RUN_DIR" ] && rm -rf "$_o" && cc_info "removed old backup $(basename "$_o") (--keep $KEEP)"
    done <"$W/old"
fi

{
    printf 'SV-14 Database backup | host %s | %s | root: %s\n\n' "$CC_HOST" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$([ "$IS_ROOT" = 1 ] && echo yes || echo NO)"
    if [ "$_nok" -eq 0 ] && [ "$_nfail" -eq 0 ]; then
        printf 'No databases found (MySQL/MariaDB, PostgreSQL, SQLite).\n'
    else
        awk "$CC_AWK_CSV"'NR > 1 { csvsplit($0, f); printf "  %-8s %-28s %9s KB  %s\n", f[1], f[2], f[4], f[5] }' "$CSV"
        printf '\n%d dump(s) OK, %d failed.  Hashes: SHA256SUMS.  Restore commands: RESTORE.txt\n' "$_nok" "$_nfail"
    fi
    [ -s "$W/notes" ] && { printf '\n'; sed 's/^/  NOTE: /' "$W/notes"; }
    case "$_copied" in
        yes) printf 'Copied off the box to %s\n' "$COPYTO" ;;
        no)  printf 'COPY FAILED to %s - the dumps are only on this box\n' "$COPYTO" ;;
        *)   [ "$_nok" -gt 0 ] && printf 'Not copied off the box.  From the admin workstation:  scp -r root@%s:%s .\n' "$CC_HOST" "$CC_RUN_DIR" ;;
    esac
    printf 'The dumps hold every password hash and every row: keep them private.\n'
    printf 'All results: %s\n' "$CC_RUN_DIR"
} >"$CC_RUN_DIR/summary.txt"
cat "$CC_RUN_DIR/summary.txt"
rm -rf "$W"
cc_finish
