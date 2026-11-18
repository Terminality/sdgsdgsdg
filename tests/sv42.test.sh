#!/bin/sh
# Tests for roles/applications/SV-42-db-passwords.sh.
# Always: options, and a clean exit with no database to log in to.
# Only with CCDC_TEST_DB=1, as root, with a local MariaDB/MySQL (and
# PostgreSQL when psql works as postgres): makes test accounts ccdc_sv42_*
# - an app account named in a WordPress-style config, one with no password,
# one to lock, a PostgreSQL role - then: the dry run changes nothing;
# --apply gives new passwords that work, writes the app's into its config,
# keeps it out of every output, locks on a typed answer; the undo puts every
# old password (and the empty one) back.
. "$(dirname "$0")/helper.sh"
SH=${TEST_SHELL:-sh}
C="$T_ROOT/roles/applications/SV-42-db-passwords.sh"
export CCDC_SKIP_VERIFY=1
O="$T_TMP/out"; A="$T_TMP/app"

t_start "options"
$SH "$C" --box moon >/dev/null 2>&1; t_eq "$?" 2 "a bad --box exits 2"
$SH "$C" --length 5 >/dev/null 2>&1; t_eq "$?" 2 "a short --length exits 2"
printf 'bob it"s\n' >"$T_TMP/bad.txt"
$SH "$C" --passwords "$T_TMP/bad.txt" --no-mysql --no-postgres >/dev/null 2>&1; t_eq "$?" 2 "a --passwords entry with a quote exits 2"
out=$($SH "$C" --out "$O" --no-color --batch --no-mysql --no-postgres 2>&1); t_has "$out" "nothing to rotate" "no database: nothing to do"
out=$($SH "$C" --help 2>&1); t_has "$out" "--passwords FILE" "--help"

if [ "${CCDC_TEST_DB:-0}" = 1 ] && [ "$(id -u)" = 0 ] && command -v mysql >/dev/null 2>&1 && mysql -e 'SELECT 1' >/dev/null 2>&1; then
    t_start "a real database (CCDC_TEST_DB=1)"
    my() { mysql -N -B -e "$1" 2>/dev/null; }
    login() { mysql -N -B --user="$1" --password="$2" -h 127.0.0.1 --protocol=tcp -e 'SELECT 1' 2>/dev/null; }
    my "DROP USER IF EXISTS 'ccdc_sv42_app'@'%'; CREATE USER 'ccdc_sv42_app'@'%' IDENTIFIED BY 'OldApp4242x'"
    my "DROP USER IF EXISTS 'ccdc_sv42_nopw'@'%'; CREATE USER 'ccdc_sv42_nopw'@'%'"
    my "DROP USER IF EXISTS 'ccdc_sv42_lock'@'%'; CREATE USER 'ccdc_sv42_lock'@'%' IDENTIFIED BY 'OldLock4242x'"
    PG=0
    if command -v psql >/dev/null 2>&1 && (cd / && runuser -u postgres -- psql -X -At -c 'SELECT 1') >/dev/null 2>&1; then
        PG=1; pg() { (cd / && runuser -u postgres -- psql -X -At -c "$1") 2>/dev/null; }
        pg "DROP ROLE IF EXISTS ccdc_sv42_pg" >/dev/null; pg "CREATE ROLE ccdc_sv42_pg LOGIN PASSWORD 'OldPg4242x'"  >/dev/null
        pglogin() { PGPASSWORD=$2 psql -X -w -h 127.0.0.1 -U "$1" -d postgres -At -c 'SELECT 1' 2>/dev/null; }
    fi
    U="ccdc_sv42_app,ccdc_sv42_nopw,ccdc_sv42_lock,ccdc_sv42_pg"; [ "$PG" = 1 ] || U="ccdc_sv42_app,ccdc_sv42_nopw,ccdc_sv42_lock"
    mkdir -p "$A"
    printf "<?php\ndefine( 'DB_NAME', 'x' );\ndefine( 'DB_USER', 'ccdc_sv42_app' );\ndefine( 'DB_PASSWORD', 'OldApp4242x' );\ndefine( 'DB_HOST', '127.0.0.1' );\n" >"$A/wp-config.php"
    run() { $SH "$C" --out "$O" --no-color --box ecomm --webroot "$A" --users "$U" --url http://127.0.0.1:9/ "$@"; }

    out=$(run --batch 2>&1)
    t_has "$out" "ccdc_sv42_app" "the app account is listed"
    t_has "$out" "config updated: WordPress" "with the config that uses it"
    t_has "$out" "ccdc_sv42_nopw (mysql) has NO password" "the account with no password is flagged"
    t_has "$out" "Dry run: nothing was changed" "dry run without --apply"
    t_eq "$(login ccdc_sv42_app OldApp4242x)" 1 "a dry run changes nothing"
    t_fail "no CSV files are left" sh -c "find '$O' -name '*.csv' | grep -q ."

    _u0=$(cat "$O"/undo-*.log 2>/dev/null | grep -c .)
    if command -v script >/dev/null 2>&1; then
        # apply: one by one, then each account in table order (app, lock, nopw, pg): r, l, r, r; then Enter to apply
        printf 'y\nr\nl\nr\nr\n\n' >"$T_TMP/ans"
        out=$(CCDC_NO_TTY=0 script -qc "$SH '$C' --out '$O' --no-color --box ecomm --webroot '$A' --users '$U' --url http://127.0.0.1:9/ --no-protected --apply --no-timer" /dev/null <"$T_TMP/ans" 2>&1)
        t_has "$out" "[r] random new password" "each account lists its answers"
        t_has "$out" "[l] lock it" "including lock"
        t_has "$out" "mysql ccdc_sv42_lock: locked" "the typed answer l locks"
    else
        out=$(run --batch --no-protected --apply --no-timer 2>&1)
    fi
    d=$(ls -d "$O"/db-passwords-* | sort -t- -k3 -n | tail -n 1)
    t_eq "$(ls -l "$d/passwords.txt" | cut -c1-10)" "-rw-------" "passwords.txt is root only"
    _np=$(awk '$1 == "mysql" && $2 == "ccdc_sv42_app" { print $3 }' "$d/passwords.txt")
    t_ok "the app account has a new password" test -n "$_np"
    t_eq "$(login ccdc_sv42_app "$_np")" 1 "and it works"
    t_eq "$(login ccdc_sv42_app OldApp4242x)" "" "the old one does not"
    t_has "$(cat "$A/wp-config.php")" "'DB_PASSWORD', '$_np'" "the app config has the new password"
    _ne=$(awk '$2 == "ccdc_sv42_nopw" { print $3 }' "$d/passwords.txt")
    t_eq "$(login ccdc_sv42_nopw "$_ne")" 1 "the account with no password has one now"
    if [ "$PG" = 1 ]; then
        _pp=$(awk '$1 == "postgres" && $2 == "ccdc_sv42_pg" { print $3 }' "$d/passwords.txt")
        t_eq "$(pglogin ccdc_sv42_pg "$_pp")" 1 "PostgreSQL: the new password works"
        t_eq "$(pglogin ccdc_sv42_pg OldPg4242x)" "" "PostgreSQL: the old one does not"
    fi
    t_fail "no new password in output.txt" grep -q "$_np" "$d/output.txt"
    t_fail "nor in the log" sh -c "grep -q '$_np' '$O'/*.log"
    t_fail "nor in summary.txt or accounts.txt" grep -q "$_np" "$d/summary.txt" "$d/accounts.txt"

    t_start "undo"
    cat "$O"/undo-*.log | awk -F'\t' -v n="$_u0" 'NR > n { l[NR] = $4 } END { for (i = NR; i > n; i--) print l[i] }' >"$T_TMP/undo.sh"
    sh "$T_TMP/undo.sh" >/dev/null 2>&1
    t_eq "$(login ccdc_sv42_app OldApp4242x)" 1 "undo: the old app password works again"
    t_has "$(cat "$A/wp-config.php")" "OldApp4242x" "undo: the old password is back in the config"
    t_eq "$(login ccdc_sv42_nopw '')" 1 "undo: no password again (as it was)"
    if command -v script >/dev/null 2>&1; then t_eq "$(login ccdc_sv42_lock OldLock4242x)" 1 "undo: the locked account is unlocked"; fi
    [ "$PG" = 1 ] && t_eq "$(pglogin ccdc_sv42_pg OldPg4242x)" 1 "undo: PostgreSQL old password back"
    t_has "$(ls "$d")" "passwords-UNDONE-not-valid.txt" "undo: the passwords file is marked not valid"

    my "DROP USER IF EXISTS 'ccdc_sv42_app'@'%'; DROP USER IF EXISTS 'ccdc_sv42_nopw'@'%'; DROP USER IF EXISTS 'ccdc_sv42_lock'@'%'"
    [ "$PG" = 1 ] && pg "DROP ROLE IF EXISTS ccdc_sv42_pg" >/dev/null
fi
t_done
