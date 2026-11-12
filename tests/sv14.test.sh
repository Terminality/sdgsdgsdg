#!/bin/sh
# Tests for roles/applications/SV-14-db-backup.sh.
# Always: options, SQLite backup (a file with the SQLite header is backed up,
# a look-alike is not), the hash list, --keep rotation.
# Only with CCDC_TEST_DB=1 (it creates and drops a database called
# ccdc_sv14_test on the local MySQL/MariaDB and PostgreSQL): dump, drop,
# restore, and the row is back.
. "$(dirname "$0")/helper.sh"
SH=${TEST_SHELL:-sh}
C="$T_ROOT/roles/applications/SV-14-db-backup.sh"
export CCDC_SKIP_VERIFY=1
# shellcheck disable=SC2086
run() { $SH "$C" "$@"; }
O="$T_TMP/out"; mkdir -p "$O"
rundir() { printf '%s\n' "$1" | sed -n 's/^All results: //p'; }

t_start "options"
run --only oracle >/dev/null 2>&1; t_eq "$?" 2 "unknown engine exits 2"
run --keep x >/dev/null 2>&1; t_eq "$?" 2 "non-number --keep exits 2"
run --sqlite "$T_TMP/none.db" >/dev/null 2>&1; t_eq "$?" 2 "missing --sqlite file exits 2"

t_start "SQLite"
printf 'SQLite format 3\000rest-of-a-database' >"$T_TMP/app.db"
printf 'not a database' >"$T_TMP/fake.db"
out=$(run --out "$O" --only sqlite --sqlite "$T_TMP/app.db" --sqlite "$T_TMP/fake.db" 2>&1); rc=$?
t_eq "$rc" 0 "exit 0"
d=$(rundir "$out")
t_has "$(cat "$d/dumps.csv")" "\"sqlite\",\"$T_TMP/app.db\"" "SQLite file backed up"
t_hasnt "$(cat "$d/dumps.csv")" "fake.db" "file without the SQLite header skipped"
t_ok "hash list checks out" sh -c "cd '$d' && sha256sum -c SHA256SUMS >/dev/null 2>&1"
t_file "$d/RESTORE.txt" "restore notes written"

t_start "--keep"
run --out "$O" --only sqlite --sqlite "$T_TMP/app.db" >/dev/null 2>&1
run --out "$O" --only sqlite --sqlite "$T_TMP/app.db" --keep 2 >/dev/null 2>&1
n=0; for f in "$O"/SV-14_*/; do [ -d "$f" ] && n=$((n + 1)); done
t_eq "$n" 2 "only the newest 2 backups kept (folders; the .log files stay)"

if [ "${CCDC_TEST_DB:-0}" = 1 ] && [ "$(id -u)" = 0 ]; then
    t_start "MySQL/MariaDB and PostgreSQL dump and restore (CCDC_TEST_DB=1)"
    if command -v mysql >/dev/null 2>&1 && mysql -e 'SELECT 1' >/dev/null 2>&1; then
        mysql -e "DROP DATABASE IF EXISTS ccdc_sv14_test; CREATE DATABASE ccdc_sv14_test; CREATE TABLE ccdc_sv14_test.t (v VARCHAR(20)); INSERT INTO ccdc_sv14_test.t VALUES ('row-one');"
    fi
    if command -v psql >/dev/null 2>&1; then
        runuser -u postgres -- sh -c "cd / && psql -X -q -c 'DROP DATABASE IF EXISTS ccdc_sv14_test' -c 'CREATE DATABASE ccdc_sv14_test'" >/dev/null 2>&1
        runuser -u postgres -- sh -c "cd / && psql -X -q -d ccdc_sv14_test -c \"CREATE TABLE t (v text); INSERT INTO t VALUES ('row-one');\"" >/dev/null 2>&1
    fi
    out=$(run --out "$O" 2>&1); rc=$?
    t_eq "$rc" 0 "exit 0"
    d=$(rundir "$out")
    t_file "$d/mysql_ccdc_sv14_test.sql.gz" "MySQL dump written"
    t_file "$d/pg_ccdc_sv14_test.dump" "PostgreSQL dump written"
    t_file "$d/pg_globals.sql.gz" "PostgreSQL roles written"
    mysql -e "DROP TABLE ccdc_sv14_test.t"
    gzip -dc "$d/mysql_ccdc_sv14_test.sql.gz" | mysql
    t_eq "$(mysql -N -e 'SELECT v FROM ccdc_sv14_test.t')" row-one "MySQL row back after drop and restore"
    runuser -u postgres -- sh -c "cd / && psql -X -q -d ccdc_sv14_test -c 'DROP TABLE t'"
    runuser -u postgres -- pg_restore --clean --if-exists -d ccdc_sv14_test <"$d/pg_ccdc_sv14_test.dump" >/dev/null 2>&1
    t_eq "$(runuser -u postgres -- sh -c "cd / && psql -X -A -t -d ccdc_sv14_test -c 'SELECT v FROM t'")" row-one "PostgreSQL row back after drop and restore"
    mysql -e "DROP DATABASE ccdc_sv14_test"
    runuser -u postgres -- sh -c "cd / && psql -X -q -c 'DROP DATABASE ccdc_sv14_test'" >/dev/null 2>&1
fi
t_done
