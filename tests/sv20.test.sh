#!/bin/sh
# Tests for roles/applications/SV-20-db-hardening.sh.
# Always: options, and a clean exit on a box without MySQL/MariaDB.
# Only with CCDC_TEST_DB=1, as root, with a local MariaDB/MySQL (it creates
# and drops test accounts and a database called ccdc_sv20_test, and drops
# ANY anonymous account and root@'%' it finds - use a throwaway server):
# plants an anonymous account, an empty test database, root@'%', an unused
# account with no password, and an app account with the FILE right whose
# config is a WordPress-style wp-config.php; then the dry run changes
# nothing, --apply fixes each one, the app's new password is in its config
# and works, no password reaches the output, and the undo puts it all back.
. "$(dirname "$0")/helper.sh"
SH=${TEST_SHELL:-sh}
C="$T_ROOT/roles/applications/SV-20-db-hardening.sh"
export CCDC_SKIP_VERIFY=1
O="$T_TMP/out"; A="$T_TMP/app"

t_start "options"
$SH "$C" --level extreme >/dev/null 2>&1; t_eq "$?" 2 "a bad --level exits 2"
$SH "$C" --only db-everything >/dev/null 2>&1; t_eq "$?" 2 "an unknown fix exits 2"
$SH "$C" --box moon >/dev/null 2>&1; t_eq "$?" 2 "a bad --box exits 2"
out=$($SH "$C" --help 2>&1); t_has "$out" "db-apppw[service]" "--help lists the fixes with their risk"

if [ "${CCDC_TEST_DB:-0}" = 1 ] && [ "$(id -u)" = 0 ] && command -v mysql >/dev/null 2>&1 && mysql -e 'SELECT 1' >/dev/null 2>&1; then
    t_start "a real database (CCDC_TEST_DB=1)"
    my() { mysql -N -B -e "$1" 2>/dev/null; }
    my "DROP DATABASE IF EXISTS ccdc_sv20_test; CREATE DATABASE ccdc_sv20_test; CREATE TABLE ccdc_sv20_test.t (v VARCHAR(10)); INSERT INTO ccdc_sv20_test.t VALUES ('row')"
    my "DROP USER IF EXISTS 'ccdc_app'@'localhost'; CREATE USER 'ccdc_app'@'localhost' IDENTIFIED BY 'OldAppPass77'; GRANT ALL ON ccdc_sv20_test.* TO 'ccdc_app'@'localhost'; GRANT FILE ON *.* TO 'ccdc_app'@'localhost'"
    my "DROP USER IF EXISTS 'ccdc_nopw'@'localhost'; CREATE USER 'ccdc_nopw'@'localhost'"
    my "DROP USER IF EXISTS ''@'localhost'; CREATE USER ''@'localhost'"
    my "DROP USER IF EXISTS 'root'@'%'; CREATE USER 'root'@'%' IDENTIFIED BY 'RemoteRoot88'"
    my "CREATE DATABASE IF NOT EXISTS test"
    mkdir -p "$A"
    printf "<?php\ndefine( 'DB_NAME', 'ccdc_sv20_test' );\ndefine( 'DB_USER', 'ccdc_app' );\ndefine( 'DB_PASSWORD', 'OldAppPass77' );\ndefine( 'DB_HOST', 'localhost' );\n" >"$A/wp-config.php"
    run() { $SH "$C" --out "$O" --no-color --batch --box ecomm --webroot "$A" --url http://127.0.0.1:9/ "$@"; }

    out=$(run --level service 2>&1)
    t_has "$out" "ccdc_app@localhost" "the app account is listed"
    t_has "$out" "used by: WordPress" "with the app that uses it"
    t_has "$out" "(anonymous)@localhost" "the anonymous account is listed"
    t_has "$out" "anonymous: anyone can log in" "and flagged"
    t_has "$out" "root@%" "remote root is listed"
    t_has "$out" "ccdc_nopw@localhost" "the account with no password is listed"
    t_has "$out" "Dry run: nothing was changed" "dry run without --apply"
    t_eq "$(my "SELECT COUNT(*) FROM mysql.user WHERE user = ''")" 1 "a dry run changes nothing"
    d=$(ls -d "$O"/db-hardening-* | sort -t- -k3 -n | tail -n 1)
    t_file "$d/accounts.txt" "accounts.txt written"
    t_fail "no CSV files are left" sh -c "find '$O' -name '*.csv' | grep -q ."

    _u0=$(cat "$O"/undo-*.log 2>/dev/null | grep -c .)
    out=$(run --level service --no-protected --apply --no-timer 2>&1)
    t_eq "$(my "SELECT COUNT(*) FROM mysql.user WHERE user = ''")" 0 "anonymous account dropped"
    t_eq "$(my "SELECT COUNT(*) FROM mysql.user WHERE user = 'root' AND host = '%'")" 0 "remote root dropped"
    t_eq "$(my "SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name = 'test'")" 0 "test database dropped"
    t_eq "$(my 'SELECT @@local_infile')" 0 "local_infile off"
    t_hasnt "$(my "SHOW GRANTS FOR 'ccdc_app'@'localhost'")" "FILE" "FILE taken from the app account"
    t_has "$(my "SHOW CREATE USER 'ccdc_nopw'@'localhost'")" "ACCOUNT LOCK" "the unused account with no password is locked"
    t_hasnt "$(cat "$A/wp-config.php")" "OldAppPass77" "the app config has a new password"
    _np=$(sed -n "s/.*DB_PASSWORD', '\([^']*\)'.*/\1/p" "$A/wp-config.php")
    t_eq "$(mysql -N -B --user=ccdc_app --password="$_np" -e 'SELECT v FROM ccdc_sv20_test.t' 2>/dev/null)" row "and it works in the database"
    d=$(ls -d "$O"/db-hardening-* | sort -t- -k3 -n | tail -n 1)
    t_eq "$(ls -l "$d/passwords.txt" | cut -c1-10)" "-rw-------" "passwords.txt is root only"
    t_fail "the new password is not in output.txt" grep -q "$_np" "$d/output.txt"
    t_fail "nor in the log" sh -c "grep -q '$_np' '$O'/*.log"
    t_fail "nor in summary.txt" grep -q "$_np" "$d/summary.txt"

    # Undo: this run's lines, newest first.
    cat "$O"/undo-*.log | awk -F'\t' -v n="$_u0" 'NR > n { l[NR] = $4 } END { for (i = NR; i > n; i--) print l[i] }' >"$T_TMP/undo.sh"
    sh "$T_TMP/undo.sh" >/dev/null 2>&1
    t_eq "$(my "SELECT COUNT(*) FROM mysql.user WHERE user = ''")" 1 "undo: anonymous account back"
    t_eq "$(my "SELECT COUNT(*) FROM mysql.user WHERE user = 'root' AND host = '%'")" 1 "undo: remote root back"
    t_has "$(my "SHOW GRANTS FOR 'ccdc_app'@'localhost'")" "FILE" "undo: FILE back"
    t_has "$(cat "$A/wp-config.php")" "OldAppPass77" "undo: old password back in the config"
    t_eq "$(mysql -N -B --user=ccdc_app --password=OldAppPass77 -e 'SELECT v FROM ccdc_sv20_test.t' 2>/dev/null)" row "undo: old password works again"

    my "DROP USER IF EXISTS 'ccdc_app'@'localhost'; DROP USER IF EXISTS 'ccdc_nopw'@'localhost'; DROP USER IF EXISTS ''@'localhost'; DROP USER IF EXISTS 'root'@'%'; DROP DATABASE IF EXISTS ccdc_sv20_test; DROP DATABASE IF EXISTS test; SET GLOBAL local_infile = 1"
fi
t_done
