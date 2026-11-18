#!/bin/sh
# Tests for roles/applications/SV-15-site-backup.sh.
# A test site (given with --webroot): back it up, deface a page, delete a
# file, plant a web shell; check finds each one; a dry-run restore changes
# nothing; restore --apply puts it right; replaying the undo lines brings the
# defaced state back; a .htaccess change is HIGH; app configs give the
# database name; questions on a terminal.  With CCDC_TEST_DB=1 and a local
# MariaDB/MySQL: the database is backed up, changed, restored and reverted.
. "$(dirname "$0")/helper.sh"
SH=${TEST_SHELL:-sh}
C="$T_ROOT/roles/applications/SV-15-site-backup.sh"
export CCDC_SKIP_VERIFY=1
CCDC_TIMER_METHOD=background; export CCDC_TIMER_METHOD
O="$T_TMP/out"; S="$T_TMP/shop"
# shellcheck disable=SC2086
run() { $SH "$C" --out "$O" --no-color --site shop "$@"; }
mksite() {
    rm -rf "$S"; mkdir -p "$S/wp-content/uploads" "$S/img"
    printf '<h1>Shop</h1>\n' >"$S/index.html"
    printf '<?php echo "ok";\n' >"$S/index.php"
    printf 'body{}\n' >"$S/style.css"
    printf 'RewriteEngine On\n' >"$S/.htaccess"
    printf "<?php\ndefine( 'DB_NAME', 'ccdc_sv15_test' );\ndefine( 'DB_PASSWORD', 'PlantedSecret55' );\ndefine( 'DB_HOST', 'localhost' );\n" >"$S/wp-config.php"
    chmod 640 "$S/wp-config.php"
}

t_start "options"
$SH "$C" --what maybe >/dev/null 2>&1; t_eq "$?" 2 "a bad --what exits 2"
$SH "$C" --keep x >/dev/null 2>&1; t_eq "$?" 2 "a bad --keep exits 2"
$SH "$C" --out "$T_TMP/empty" --check --batch >/dev/null 2>&1; t_eq "$?" 3 "check with no backup exits 3"

t_start "backup"
mksite
out=$(run --backup --batch --no-db --webroot "$S" 2>&1); rc=$?
t_eq "$rc" 0 "exit 0"
t_has "$out" "WordPress, mysql database ccdc_sv15_test" "the app and its database are found"
t_has "$out" "[+] shop" "the site is backed up"
B="$O/site-backup-1"
for f in output.txt summary.txt sites.txt RESTORE.txt run.txt shop/files.tar.gz shop/files.sha256; do t_file "$B/$f" "$f written"; done
t_eq "$(grep -c . "$B/shop/files.sha256")" 5 "every file hashed"
t_eq "$(ls -ld "$B" | cut -c1-10)" "drwx------" "the backup folder is private"
t_fail "no password in the output" grep -rq "PlantedSecret55" "$B/output.txt" "$B/summary.txt" "$B/sites.txt"

t_start "check"
out=$(run --check --batch 2>&1)
t_has "$out" "[ok] shop" "an untouched site matches"
printf 'HACKED\n' >"$S/index.html"; rm "$S/style.css"
printf '<?php system($_GET["c"]);\n' >"$S/wp-content/uploads/x.php"
printf 'cat.jpg\n' >"$S/img/cat.jpg"
printf 'AddType application/x-httpd-php .jpg\n' >>"$S/.htaccess"
out=$(run --check --batch 2>&1)
t_has "$out" "2 changed, 1 deleted, 2 new" "counts"
t_has "$out" "index.html  - page changed: defaced?" "defaced page"
t_has "$out" "style.css  - deleted" "deleted file"
t_has "$out" "[!] new      $S/wp-content/uploads/x.php  - new program file" "web shell is HIGH"
t_has "$out" "[-] new      $S/img/cat.jpg" "a new image is LOW"
t_has "$out" ".htaccess changed: can make any file run as PHP" ".htaccess change is HIGH"
t_ok "changes.txt lists the web shell" grep -q 'x.php' "$(ls -d "$O"/site-check-* | sort -t- -k3 -n | tail -n 1)/changes.txt"
t_fail "no CSV files are left" sh -c "find '$O' -name '*.csv' | grep -q ."
t_eq "$(cat "$S/index.html")" "HACKED" "check changes nothing"

t_start "restore"
out=$(run --restore --batch --no-protected 2>&1)
t_has "$out" "put back 3 file(s), quarantine 2 new file(s)" "the plan"
t_has "$out" "Dry run: nothing was changed" "dry run without --apply"
t_eq "$(cat "$S/index.html")" "HACKED" "a dry run changes nothing"
_u0=$(cat "$O"/undo-*.log 2>/dev/null | grep -c .)
out=$(run --restore --batch --no-protected --apply --no-timer 2>&1)
t_has "$out" "matches the backup now" "restore says the site matches"
t_eq "$(cat "$S/index.html")" "<h1>Shop</h1>" "the defaced page is back"
t_ok "the deleted file is back" test -f "$S/style.css"
t_fail "the web shell is in quarantine" test -f "$S/wp-content/uploads/x.php"
t_hasnt "$(cat "$S/.htaccess")" "AddType" ".htaccess put back"
t_eq "$(ls -l "$S/wp-config.php" | cut -c1-10)" "-rw-r-----" "unchanged files keep their mode"
out=$(run --check --batch 2>&1); t_has "$out" "[ok] shop" "a check after the restore is clean"
cat "$O"/undo-*.log | awk -F'\t' -v n="$_u0" 'NR > n { l[NR] = $4 } END { for (i = NR; i > n; i--) print l[i] }' >"$T_TMP/undo.sh"
sh "$T_TMP/undo.sh" >/dev/null 2>&1
t_eq "$(cat "$S/index.html")" "HACKED" "undo brings the replaced file back"
t_ok "undo brings the quarantined file back" test -f "$S/wp-content/uploads/x.php"
out=$(run --restore --batch --no-protected --apply --no-timer --what new 2>&1)
t_fail "--what new: only the new files go" test -f "$S/wp-content/uploads/x.php"
t_eq "$(cat "$S/index.html")" "HACKED" "--what new leaves changed files"

t_start "a site folder wiped"
rm -rf "$S"
out=$(run --check --batch 2>&1); t_has "$out" "is GONE" "a missing folder is reported"
t_fail "check does not create it" test -d "$S"
run --restore --batch --no-protected --apply --no-timer >/dev/null 2>&1
t_eq "$(cat "$S/index.html" 2>/dev/null)" "<h1>Shop</h1>" "restore rebuilds a wiped site"

t_start "questions on a terminal"
if command -v script >/dev/null 2>&1; then
    printf 'X\n' >"$S/index.html"
    # mode: r | site: f
    printf 'r\nf\n' >"$T_TMP/ans"
    tt=$(CCDC_NO_TTY=0 script -qc "$SH '$C' --out '$O' --no-color --site shop --no-protected" /dev/null <"$T_TMP/ans" 2>&1)
    t_has "$tt" "[b] back up the sites now" "the mode question lists its answers"
    t_has "$tt" "[a] all back to the backup" "the restore question lists its answers"
    t_has "$tt" "put back 1 file(s), quarantine 0 new file(s)" "the typed answer f is used"
fi

if [ "${CCDC_TEST_DB:-0}" = 1 ] && command -v mysql >/dev/null 2>&1 && mysql -e 'SELECT 1' >/dev/null 2>&1; then
    t_start "database (CCDC_TEST_DB=1)"
    mksite
    mysql -e "DROP DATABASE IF EXISTS ccdc_sv15_test; CREATE DATABASE ccdc_sv15_test; CREATE TABLE ccdc_sv15_test.p (t VARCHAR(30)); INSERT INTO ccdc_sv15_test.p VALUES ('good');"
    run --backup --batch --webroot "$S" >/dev/null 2>&1
    mysql -e "UPDATE ccdc_sv15_test.p SET t='HACKED'"
    out=$(run --restore --batch --no-protected --apply --no-timer --restore-db 2>&1)
    t_has "$out" "put the database ccdc_sv15_test back" "the database is offered even when the files are unchanged"
    t_eq "$(mysql -N -e 'SELECT t FROM ccdc_sv15_test.p')" good "the database is back"
    mysql -e "DROP DATABASE ccdc_sv15_test"
fi
t_done
