#!/bin/sh
# Tests for roles/linux/LX-44-apparmor.sh.
# Everything happens in a fake root (--root): a copy of /etc/apparmor.d,
# stand-in apache2 / mariadbd / php-fpm programs, a fake kernel profile list
# and a fake kern.log with AppArmor lines.  A stand-in apparmor_parser checks
# every profile with the REAL parser (-Q: never loaded into a kernel) and
# writes the fake kernel list.  Checks: unconfined -> complain writes valid
# profiles; the learning sorts the log lines (normal / web code / programs)
# and never adds a shell; complain -> enforce; the undo; the questions on a
# terminal.  Nothing outside the test folder is touched.
. "$(dirname "$0")/helper.sh"
SH=${TEST_SHELL:-sh}
C="$T_ROOT/roles/linux/LX-44-apparmor.sh"
export CCDC_SKIP_VERIFY=1
O="$T_TMP/out"; F="$T_TMP/root"; B="$T_TMP/bin"
command -v apparmor_parser >/dev/null 2>&1 && [ -d /etc/apparmor.d/abstractions ] || { echo "apparmor_parser not installed: skipped"; t_done; exit 0; }
mkdir -p "$B"
cat >"$B/aa" <<'EOF'
#!/bin/sh
# stand-in apparmor_parser: check with the real one, keep a fake kernel list
act=r; mode=""; f=""
for a; do case "$a" in -r) act=r ;; -R) act=R ;; -C) mode=complain ;; -K|-Q) ;; *) f=$a ;; esac; done
P="$AA_ROOT/sys/kernel/security/apparmor/profiles"
name=$(awk '{ sub(/^[ \t]+/, "") } /^profile[ \t]/ { print $2; exit } /^\// { print $1; exit }' "$f")
grep -v "^$name (" "$P" >"$P.n" 2>/dev/null; cat "$P.n" >"$P"; rm -f "$P.n"
[ "$act" = R ] && exit 0
apparmor_parser -Q -K -b "$AA_ROOT/etc/apparmor.d" "$f" >/dev/null 2>"$AA_ROOT/parser.err" || { cat "$AA_ROOT/parser.err" >&2; exit 1; }
[ -n "$mode" ] || { grep -q 'flags=(complain)' "$f" && mode=complain || mode=enforce; }
echo "$name ($mode)" >>"$P"
EOF
chmod +x "$B/aa"
export CCDC_AA_PARSER="$B/aa" AA_ROOT="$F"
mkroot() {
    rm -rf "$F"; mkdir -p "$F/sys/module/apparmor/parameters" "$F/sys/kernel/security/apparmor" "$F/usr/sbin" "$F/var/log" \
        "$F/var/www/html/wp-content/uploads" "$F/var/www/html/admin"
    echo Y >"$F/sys/module/apparmor/parameters/enabled"; : >"$F/sys/kernel/security/apparmor/profiles"
    mkdir -p "$F/etc"; cp -R /etc/apparmor.d "$F/etc/apparmor.d"
    # only our own profiles in the copy: no packaged ones for these programs
    rm -f "$F/etc/apparmor.d/php-fpm" "$F/etc/apparmor.d/usr.sbin.mysqld" "$F/etc/apparmor.d/local/"ccdc-* 2>/dev/null
    for p in apache2 mariadbd; do printf '#!/bin/sh\n' >"$F/usr/sbin/$p"; chmod +x "$F/usr/sbin/$p"; done
    : >"$F/var/log/kern.log"
}
logline() {  # logline PROFILE OP NAME MASK [extra]
    printf 'Nov 19 10:00:00 web kernel: audit: type=1400 audit(%s.100:1): apparmor="ALLOWED" operation="%s" profile="%s" name="%s" pid=1 comm="apache2" requested_mask="%s" denied_mask="%s" %s\n' \
        "$(date +%s)" "$2" "$1" "$3" "$4" "$4" "${5:-}" >>"$F/var/log/kern.log"
}
run() { $SH "$C" --out "$O" --no-color --root "$F" --no-protected "$@"; }

t_start "options"
$SH "$C" --services moon >/dev/null 2>&1; t_eq "$?" 2 "a bad --services exits 2"
$SH "$C" --timer x >/dev/null 2>&1; t_eq "$?" 2 "a bad --timer exits 2"
out=$($SH "$C" --help 2>&1); t_has "$out" "--writable DIR" "--help"

t_start "no AppArmor"
mkroot; echo N >"$F/sys/module/apparmor/parameters/enabled"
out=$(run --batch 2>&1); t_has "$out" "AppArmor is not switched on" "says so and stops"

t_start "status and dry run"
mkroot
out=$(run --batch 2>&1)
t_has "$out" "apache2 (/usr/sbin/apache2): unconfined" "apache2 is unconfined"
t_has "$out" "mysql (/usr/sbin/mariadbd): unconfined" "mariadb is unconfined"
t_has "$out" "c (default): complain: load the profile in learning mode" "the default answer is shown"
t_has "$out" "[~] apache2: load the profile in complain mode" "the plan"
t_has "$out" "Dry run: nothing was changed" "dry run without --apply"
t_fail "a dry run writes no profile" test -f "$F/etc/apparmor.d/ccdc-apache2"
t_file "$(ls -d "$O"/apparmor-* | tail -n 1)/status.txt" "status.txt"
t_fail "no CSV files are left" sh -c "find '$O' -name '*.csv' | grep -q ."

t_start "complain (--batch --apply)"
out=$(run --batch --apply 2>&1)
t_has "$out" "[+] apache2: load the profile in complain mode" "apache2 into complain"
t_has "$out" "[+] mysql: load the profile in complain mode" "mariadb into complain"
t_hasnt "$out" "apparmor_parser refused" "the real parser takes both profiles"
t_ok "the profile is written" grep -q '/var/www/html/wp-content/uploads/\*\* rwk' "$F/etc/apparmor.d/ccdc-apache2"
t_ok "the kernel list has it in complain" grep -qx 'ccdc-apache2 (complain)' "$F/sys/kernel/security/apparmor/profiles"
t_hasnt "$(cat "$F/etc/apparmor.d/ccdc-apache2")" "/bin/sh" "the web profile does not let it run a shell"

t_start "nginx and php-fpm profiles"
for p in nginx php-fpm8.3; do printf '#!/bin/sh\n' >"$F/usr/sbin/$p"; chmod +x "$F/usr/sbin/$p"; done
out=$(run --batch --apply --services nginx,php-fpm 2>&1)
t_has "$out" "[+] nginx: load the profile in complain mode" "nginx into complain"
t_has "$out" "[+] php-fpm: load the profile in complain mode" "php-fpm into complain"
t_hasnt "$out" "apparmor_parser refused" "the real parser takes both"
t_hasnt "$out" "apache2 (" "--services leaves the others out"
rm -f "$F/usr/sbin/nginx" "$F/usr/sbin/php-fpm8.3"

t_start "a profile the package ships"
printf '#!/bin/sh\n' >"$F/usr/sbin/php-fpm8.3"; chmod +x "$F/usr/sbin/php-fpm8.3"
printf 'abi <abi/3.0>,\ninclude <tunables/global>\nprofile php-fpm /usr/sbin/php-fpm* {\n  include <abstractions/base>\n}\n' >"$F/etc/apparmor.d/php-fpm"
rm -f "$F/etc/apparmor.d/ccdc-php-fpm"; grep -v '^ccdc-php-fpm ' "$F/sys/kernel/security/apparmor/profiles" >"$T_TMP/p"; cat "$T_TMP/p" >"$F/sys/kernel/security/apparmor/profiles"
out=$(run --batch --apply --services php-fpm 2>&1)
t_has "$out" "the package's profile php-fpm" "the packaged profile is used"
t_ok "complain through force-complain" test -L "$F/etc/apparmor.d/force-complain/php-fpm"
t_fail "no CCDC profile next to it" test -f "$F/etc/apparmor.d/ccdc-php-fpm"
rm -f "$F/usr/sbin/php-fpm8.3"

t_start "learn"
logline ccdc-apache2 open /opt/shop/conf.ini r
logline ccdc-apache2 open /var/log/shop.log w
logline ccdc-apache2 open /var/log/shop2.log wa
logline ccdc-apache2 capable "" "" 'capname="sys_ptrace"'
logline ccdc-apache2 open /var/www/html/admin/x.php w
logline ccdc-apache2 exec /usr/bin/dash x
logline ccdc-apache2 exec /usr/bin/convert x
logline ccdc-apache2 open /etc/shadow r
logline ccdc-apache2 capable "" "" 'capname="sys_module"'
logline ccdc-apache2 open '/opt/shop/a*b.txt' r
# apache2: learn (default), add the normal ones (Y), not the web code write (N); mysql: complain (default); apply: Enter
out=$(run --batch --apply 2>&1)
_rd=$(ls -d "$O"/apparmor-* | tail -n 1)
t_has "$out" "[!] it ran /usr/bin/dash" "running a shell is HIGH"
t_has "$out" "[*] it ran /usr/bin/convert" "another program is listed"
t_has "$out" "[*] wrote into the site code: \"/var/www/html/admin/x.php\" w," "a write into the site is shown"
t_has "$out" "[+] apache2: add the learned rules" "learned"
L="$F/etc/apparmor.d/local/ccdc-apache2"
t_ok "a normal read is added" grep -q '"/opt/shop/conf.ini" r,' "$L"
t_ok "w and a are not mixed" grep -q '"/var/log/shop2.log" w,' "$L"
t_ok "a capability is added" grep -q 'capability sys_ptrace,' "$L"
t_fail "the web code write is not added (default no)" grep -q 'x.php' "$L"
t_fail "the shell is never added" grep -q 'dash' "$L"
t_fail "/etc/shadow is never added" grep -q 'shadow' "$L"
t_fail "a dangerous capability is never added" grep -q 'sys_module' "$L"
t_has "$out" "[!] it touched /etc/shadow r" "reading /etc/shadow is HIGH"
t_ok "a * in a file name is escaped" grep -q '"/opt/shop/a\\\*b.txt" r,' "$L"
t_hasnt "$out" "apparmor_parser refused" "the real parser takes the learned rules"
t_file "$_rd/learned-apache2.txt" "learned-apache2.txt"

t_start "a service running outside its profile"
mkdir -p "$F/run/ccdc-test"; echo unconfined >"$F/run/ccdc-test/apache2.label"
out=$(run --batch 2>&1)
t_has "$out" "[!] the running apache2 started before its profile was loaded" "it is seen"
t_has "$out" "[~] apache2: restart it so it runs under its profile" "a restart is planned (default)"
t_hasnt "$out" "apache2: ENFORCE" "and it is not enforced by default"
rm -f "$F/run/ccdc-test/apache2.label"

t_start "enforce, then undo"
: >"$F/var/log/kern.log"
printf 'e\nc\n\n' >"$T_TMP/ans"
if command -v script >/dev/null 2>&1; then
    # apache2: e (enforce); mysql: c (stay); apply: Enter
    tt=$(CCDC_NO_TTY=0 script -qc "$SH '$C' --out '$O' --no-color --root '$F' --no-protected --apply" /dev/null <"$T_TMP/ans" 2>&1)
    t_has "$tt" "[e] enforce: block everything" "complain lists its answers"
    t_has "$tt" "[+] apache2: ENFORCE the profile" "e: enforced"
    t_ok "the kernel list has it enforced" grep -qx 'ccdc-apache2 (enforce)' "$F/sys/kernel/security/apparmor/profiles"
    t_ok "c: mariadb stays in complain" grep -qx 'ccdc-mysqld (complain)' "$F/sys/kernel/security/apparmor/profiles"
    t_fail "the profile has no complain flag" grep -q 'flags=(complain)' "$F/etc/apparmor.d/ccdc-apache2"
    _rd=$(ls -d "$O"/apparmor-* | tail -n 1)
    _u=$(cat "$O"/undo-*.log | grep -c .)
    awk -F'\t' '{ l[NR] = $4 } END { for (i = NR; i > 0; i--) print l[i] }' "$O"/undo-*.log >"$T_TMP/undo.sh"
    sh "$T_TMP/undo.sh" >/dev/null 2>&1
    t_fail "undo of everything removes the CCDC profiles" test -f "$F/etc/apparmor.d/ccdc-apache2"
    t_fail "and unloads them" grep -q ccdc- "$F/sys/kernel/security/apparmor/profiles"
    t_ok "$_u undo lines were written" test "$_u" -gt 0
fi
t_done
