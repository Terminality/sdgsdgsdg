#!/bin/sh
# Tests for roles/applications/SV-50-service-recovery.sh.
# Always: options.  Only with BT_TEST_SVC=1, as root, with Apache
# installed (it stops and starts Apache, adds and removes an iptables rule on
# port 80, runs a stand-in program on port 80 and writes a broken Apache
# config file for a moment - use a throwaway box): a healthy Apache is OK; a
# dry run changes nothing; a DROP rule on 80, a program holding port 80 and a
# stopped Apache are each found and fixed; a broken config is reported and
# Apache is NOT started on it; --watch --auto-restart brings Apache back.
. "$(dirname "$0")/helper.sh"
SH=${TEST_SHELL:-sh}
C="$T_ROOT/roles/applications/SV-50-service-recovery.sh"
export BT_SKIP_VERIFY=1
O="$T_TMP/out"

t_start "options"
$SH "$C" --fix everything >/dev/null 2>&1; t_eq "$?" 2 "an unknown --fix kind exits 2"
$SH "$C" --auto-restart >/dev/null 2>&1; t_eq "$?" 2 "--auto-restart without --watch exits 2"
$SH "$C" --watch 2 >/dev/null 2>&1; t_eq "$?" 2 "--watch under 5 seconds exits 2"
$SH "$C" --out "$O" --batch --services no-such-thing >/dev/null 2>&1; t_eq "$?" 2 "a service that is not installed exits 2"
out=$($SH "$C" --help 2>&1); t_has "$out" "--auto-restart" "--help"

if [ "${BT_TEST_SVC:-0}" = 1 ] && [ "$(id -u)" = 0 ] && [ -x /usr/sbin/apache2 ] && command -v iptables >/dev/null 2>&1; then
    t_start "a real Apache (BT_TEST_SVC=1)"
    run() { $SH "$C" --out "$O" --no-color --batch --box ecomm --services web --no-protected "$@" 2>&1; }
    up() { pgrep -x apache2 >/dev/null; }
    stop() { service apache2 stop >/dev/null 2>&1; i=0; while up && [ "$i" -lt 10 ]; do sleep 1; i=$((i + 1)); done; }
    up || service apache2 start >/dev/null 2>&1
    out=$(run)
    t_has "$out" "[ok] web       apache2" "a healthy Apache is OK"
    t_hasnt "$out" "[!] web       apache2" "and not flagged"

    stop
    out=$(run)
    t_has "$out" "not running" "a stopped Apache is found"
    t_has "$out" "Dry run: nothing was changed" "dry run without --apply"
    t_fail "a dry run does not start it" up
    out=$(run --apply)
    t_has "$out" "[+] start apache2" "--apply starts it"
    t_has "$out" "[ok] apache2 is UP: HTTP" "and tests it over HTTP"

    iptables -A INPUT -p tcp --dport 80 -j DROP
    out=$(run --apply)
    t_has "$out" "firewall drops 80" "a DROP rule on 80 is found"
    t_eq "$(iptables -S INPUT | grep -c -- '--dport 80 .*DROP')" 0 "and removed"
    t_has "$out" "[ok] apache2 is UP" "Apache answers again"

    stop
    cp "$(command -v nc)" "$T_TMP/evilnc" 2>/dev/null
    if [ -x "$T_TMP/evilnc" ]; then
        "$T_TMP/evilnc" -lk -p 80 >/dev/null 2>&1 &
        sleep 1
        out=$(run --apply)
        t_has "$out" "port 80 held by evilnc" "a program holding port 80 is found"
        t_has "$out" "[+] stop evilnc" "it is stopped (runs from a temp folder: default yes)"
        t_fail "it is gone" pgrep -f "$T_TMP/evilnc"
        t_ok "Apache is started after it" up
        rm -f "$T_TMP/evilnc"
    fi

    stop
    echo 'BrokenDirective on' >/etc/apache2/conf-enabled/zz-bt-sv50-test.conf
    out=$(run --apply)
    t_has "$out" "config:BROKEN" "a broken config is found"
    t_has "$out" "Invalid command 'BrokenDirective'" "with the error line"
    t_has "$out" "zz-bt-sv50-test.conf" "and the file changed in the last 2 hours"
    t_fail "Apache is NOT started on a broken config" up
    rm -f /etc/apache2/conf-enabled/zz-bt-sv50-test.conf

    out=$($SH "$C" --out "$O" --no-color --services web --no-protected --watch 5 --watch-count 2 --auto-restart --apply 2>&1)
    t_has "$out" "apache2 is DOWN" "--watch reports it down"
    t_has "$out" "apache2 restarted" "--auto-restart restarts it"
    t_has "$out" "apache2 is UP again" "and reports it up again"
    t_hasnt "$out" "nginx" "only the web server in use is watched"
    d=$(ls -d "$O"/recovery-* | sort -t- -k3 -n | tail -n 1)
    t_file "$d/watch.txt" "watch.txt written"
    t_fail "no CSV files are left" sh -c "find '$O' -name '*.csv' | grep -q ."
    up || service apache2 start >/dev/null 2>&1
fi
t_done
