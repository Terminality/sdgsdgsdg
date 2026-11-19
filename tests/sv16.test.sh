#!/bin/sh
# Tests for roles/applications/SV-16-webshell-hunter.sh.
# A WordPress-style test site (given with --webroot) with planted shells:
# a one-liner in uploads, eval(base64_decode()), a function named in the
# request, PHP inside a .jpg, an .htaccess handler, a changed core file, an
# extra core file; plus a plugin that runs programs (MED), WordPress's
# "Silence is golden" index.php and clean files (not flagged).  Checks: each
# is found at the right level; a dry run changes nothing; --apply moves the
# HIGH files out and keeps the MED one; the undo puts them back; the
# questions on a terminal; --watch catches a new shell and
# --auto-quarantine moves it out.  Only the test folder is touched.
. "$(dirname "$0")/helper.sh"
SH=${TEST_SHELL:-sh}
C="$T_ROOT/roles/applications/SV-16-webshell-hunter.sh"
export BT_SKIP_VERIFY=1
BT_TIMER_METHOD=background; export BT_TIMER_METHOD
O="$T_TMP/out"; S="$T_TMP/site"; J="$T_TMP/wp.json"

mksite() {
    rm -rf "$S"; mkdir -p "$S/wp-admin" "$S/wp-includes" "$S/wp-content/uploads" "$S/wp-content/plugins/good" "$S/wp-content/plugins/backup" "$S/wp-content/themes/t"
    printf "<?php\n\$wp_version = '6.4.2';\n" >"$S/wp-includes/version.php"
    printf '<?php\nfunction wp_load() { return 1; }\n' >"$S/wp-includes/load.php"
    printf '<?php\necho "about";\n' >"$S/wp-admin/about.php"
    printf '<?php\nrequire "wp-includes/load.php";\necho "shop";\n' >"$S/index.php"
    # Checksums of the clean core, as wordpress.org gives them.
    { printf '{"checksums":{'; _f=1
      for _x in wp-includes/version.php wp-includes/load.php wp-admin/about.php index.php; do
          [ "$_f" = 1 ] || printf ','; _f=0; printf '"%s":"%s"' "$_x" "$(md5sum "$S/$_x" | cut -d' ' -f1)"
      done; printf '}}'; } >"$J"
    printf '<?php\n// Silence is golden.\n' >"$S/wp-content/uploads/index.php"
    printf '<?php\nfunction good_hello() { return "hello"; }\n' >"$S/wp-content/plugins/good/good.php"
    printf '<?php\n$p = proc_open("mysqldump", $d, $pipes);\n$h = popen("gzip", "w");\n' >"$S/wp-content/plugins/backup/run.php"
    # The planted ones.
    printf '<?php system($_GET["c"]); ?>\n' >"$S/wp-content/uploads/x.php"
    printf "<?php eval(base64_decode('ZWNobyAiaGkiOw==')); ?>\n" >"$S/wp-content/plugins/good/cache.php"
    printf '<?php $_GET["f"]($_GET["a"]); ?>\n' >"$S/wp-content/themes/t/footer2.php"
    printf 'GIF89a<?php system($_REQUEST["x"]); ?>\n' >"$S/wp-content/uploads/cat.jpg"
    printf 'AddType application/x-httpd-php .jpg\n' >"$S/wp-content/uploads/.htaccess"
    printf '<?php\nfunction wp_load() { return 1; }\n@include "/tmp/.x";\n' >"$S/wp-includes/load.php"
    printf '<?php echo 1;\n' >"$S/wp-includes/sys.php"
}
run() { $SH "$C" --out "$O" --no-color --webroot "$S" --wp-checksums "$J" --no-online --url http://127.0.0.1:9/ "$@"; }
snap() { (cd "$S" && find . -type f | sort; find . -type f -exec cat {} +) | cksum; }

t_start "options"
$SH "$C" --watch 2 >/dev/null 2>&1; t_eq "$?" 2 "--watch under 5 seconds exits 2"
$SH "$C" --auto-quarantine >/dev/null 2>&1; t_eq "$?" 2 "--auto-quarantine without --watch exits 2"
$SH "$C" --hours x >/dev/null 2>&1; t_eq "$?" 2 "a bad --hours exits 2"
out=$($SH "$C" --help 2>&1); t_has "$out" "--wp-checksums FILE" "--help"

t_start "find"
mksite; before=$(snap)
out=$(run --batch 2>&1)
t_has "$out" "[!] HIGH  $S/wp-content/uploads/x.php" "a one-liner in uploads is HIGH"
t_has "$out" "runs request data as code or a command (line 1): <?php system(\$_GET[\"c\"]); ?>" "with the line that matched"
t_has "$out" "[!] HIGH  $S/wp-content/plugins/good/cache.php" "eval(base64_decode()) is HIGH"
t_has "$out" "eval of hidden (encoded) code" "with the reason"
t_has "$out" "[!] HIGH  $S/wp-content/themes/t/footer2.php" "a function named in the request is HIGH"
t_has "$out" "[!] HIGH  $S/wp-content/uploads/cat.jpg" "PHP inside a .jpg is HIGH"
t_has "$out" "[!] HIGH  $S/wp-content/uploads/.htaccess" "an .htaccess handler is HIGH"
t_has "$out" "a WordPress core file that differs from wordpress.org 6.4.2" "a changed core file is HIGH"
t_has "$out" "$S/wp-includes/sys.php" "an extra file in wp-includes is found"
t_has "$out" "that WordPress 6.4.2 does not ship" "with the reason"
t_has "$out" "[*] MED  $S/wp-content/plugins/backup/run.php" "a plugin that runs programs is MED"
t_hasnt "$out" "uploads/index.php" "WordPress's Silence is golden index.php is not flagged"
t_hasnt "$out" "good/good.php" "a clean plugin file is not flagged"
t_hasnt "$out" "HIGH  $S/wp-admin/about.php" "a core file that matches is not flagged"
t_has "$out" "Dry run: nothing was changed" "dry run without --apply"
t_eq "$(snap)" "$before" "a dry run changes nothing"
d=$(ls -d "$O"/webshells-* | sort -t- -k3 -n | tail -n 1)
t_file "$d/findings.txt" "findings.txt written"
t_fail "no CSV files are left" sh -c "find '$O' -name '*.csv' | grep -q ."

t_start "quarantine"
_u0=$(cat "$O"/undo-*.log 2>/dev/null | grep -c .)
out=$(run --batch --no-protected --apply --no-timer 2>&1)
for f in wp-content/uploads/x.php wp-content/plugins/good/cache.php wp-content/themes/t/footer2.php wp-content/uploads/cat.jpg wp-content/uploads/.htaccess wp-includes/sys.php; do
    t_fail "$f is out of the site" test -f "$S/$f"
done
t_ok "the MED plugin is kept (default keep)" test -f "$S/wp-content/plugins/backup/run.php"
t_ok "the clean files stay" test -f "$S/wp-content/plugins/good/good.php"
out=$(run --batch 2>&1)
t_hasnt "$out" "uploads/x.php" "a second scan no longer finds them"
cat "$O"/undo-*.log | awk -F'\t' -v n="$_u0" 'NR > n { l[NR] = $4 } END { for (i = NR; i > n; i--) print l[i] }' >"$T_TMP/undo.sh"
sh "$T_TMP/undo.sh" >/dev/null 2>&1
t_eq "$(snap)" "$before" "undo puts every file back"

t_start "questions on a terminal"
if command -v script >/dev/null 2>&1; then
    mksite
    # first file: keep; second: quarantine; the rest: all defaults; apply: Enter
    printf 'k\nq\na\n\n' >"$T_TMP/ans"
    tt=$(BT_NO_TTY=0 script -qc "$SH '$C' --out '$O' --no-color --webroot '$S' --wp-checksums '$J' --no-online --url http://127.0.0.1:9/ --no-protected --apply --no-timer" /dev/null <"$T_TMP/ans" 2>&1)
    t_has "$tt" "[q] quarantine it" "each file lists its answers"
    t_has "$tt" "[a] all the rest" "including all the rest"
    _left=0; for f in wp-content/uploads/x.php wp-content/plugins/good/cache.php wp-content/themes/t/footer2.php wp-content/uploads/cat.jpg wp-content/uploads/.htaccess wp-includes/sys.php wp-includes/load.php; do [ -f "$S/$f" ] && _left=$((_left + 1)); done
    t_eq "$_left" 1 "the one answered k stays, the others go"
fi

t_start "watch"
mksite
rm -f "$S/wp-content/uploads/x.php" "$S/wp-content/plugins/good/cache.php" "$S/wp-content/themes/t/footer2.php" "$S/wp-content/uploads/cat.jpg" "$S/wp-content/uploads/.htaccess"
( sleep 2; printf '<?php passthru($_POST["cmd"]); ?>\n' >"$S/wp-content/uploads/new.php" ) &
out=$(run --no-protected --apply --watch 5 --watch-count 2 --auto-quarantine 2>&1)
t_has "$out" "HIGH  $S/wp-content/uploads/new.php" "--watch finds a new shell"
t_has "$out" "[+] quarantined" "--auto-quarantine moves it out"
t_fail "it is out of the site" test -f "$S/wp-content/uploads/new.php"
d=$(ls -d "$O"/webshells-* | sort -t- -k3 -n | tail -n 1)
t_ok "watch.txt records it" grep -q "quarantined $S/wp-content/uploads/new.php" "$d/watch.txt"
t_done
