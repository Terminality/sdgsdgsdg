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
t_start "stand-ins: Gitea, Samba, firewalld, ufw, OpenRC"
# Nothing real is touched: init scripts in a test folder (BT_SVC_DIRS),
# python's web server named gitea on a free port, and firewall-cmd, ufw and
# rc-update stand-ins that only log their calls.
PY=$(command -v python3 2>/dev/null)
if [ -n "$PY" ] && command -v ss >/dev/null 2>&1; then
    S="$T_TMP/svc"; B="$T_TMP/sbin"; L="$T_TMP/calls"; mkdir -p "$S" "$B" "$T_TMP/www"; : >"$L"
    GP=""; for _p in 3000 13000 23000 33000; do ss -ltn | grep -q ":$_p " || { GP=$_p; break; }; done
    for _u in gitea smbd; do printf '#!/bin/sh\necho "init %s $1" >>"%s"\n' "$_u" "$L" >"$S/$_u"; chmod +x "$S/$_u"; done
    ln -s "$PY" "$B/gitea"
    (cd "$T_TMP/www" && exec "$B/gitea" -m http.server "$GP" --bind 127.0.0.1 >/dev/null 2>&1) & GPID=$!
    _i=0; while ! ss -ltn | grep -q ":$GP " && [ "$_i" -lt 20 ]; do sleep 1; _i=$((_i + 1)); done
    # firewalld that allows only ssh; ufw that allows only 22.
    printf '#!/bin/sh\necho "firewall-cmd $*" >>"%s"\ncase "$1" in --state) echo running ;; --list-services) echo ssh ;; --info-service=ssh) echo "  ports: 22/tcp" ;; -q) exit 1 ;; esac\nexit 0\n' "$L" >"$B/firewall-cmd"
    printf '#!/bin/sh\necho "ufw $*" >>"%s"\ncase "$*" in "status") printf "Status: active\\n\\nTo Action From\\n22/tcp ALLOW Anywhere\\n" ;; "status verbose") echo "Default: deny (incoming)" ;; esac\nexit 0\n' "$L" >"$B/ufw"
    printf '#!/bin/sh\necho "rc-update $*" >>"%s"\n' "$L" >"$B/rc-update"; printf '#!/bin/sh\necho "rc-service $*" >>"%s"\n' "$L" >"$B/rc-service"
    chmod +x "$B/firewall-cmd" "$B/ufw" "$B/rc-update" "$B/rc-service"
    mkdir -p "$T_TMP/runlevels/default"
    # app.ini says which port Gitea serves.
    srun() { (export BT_SVC_DIRS="$S" BT_SVC_INIT=openrc BT_TEST_RUNLEVELS="$T_TMP/runlevels" PATH="$B:$PATH"; $SH "$C" --out "$O" --no-color --batch --no-protected "$@" 2>&1); }
    if [ "$GP" != 3000 ]; then t_ok "skip: port 3000 is taken here (the app.ini port is read from a real /etc/gitea only)" true; fi
    if [ "$GP" = 3000 ]; then
        out=$(srun --box gitea --services gitea,smbd)
        t_has "$out" "[!] gitea     gitea" "Gitea is checked"
        t_has "$out" "HTTP 200 on 3000" "over HTTP on its port"
        t_has "$out" "firewalld does not allow 3000/tcp" "a port firewalld blocks is found"
        t_has "$out" "ufw does not allow 3000/tcp" "and one ufw blocks"
        t_has "$out" "disabled at boot" "OpenRC: not in a runlevel = disabled at boot"
        t_has "$out" "smb       smbd" "Samba is checked"
        t_has "$out" "not running" "a stopped Samba is found"
        t_has "$out" "[~] open 3000/tcp in firewalld (now and after a reboot)" "the firewalld fix is offered"
        t_has "$out" "[~] allow 3000/tcp in ufw" "the ufw fix is offered"
        t_has "$out" "Dry run: nothing was changed" "dry run"
        t_hasnt "$(cat "$L")" "add-port" "a dry run opens nothing"
        out=$(srun --box gitea --services gitea,smbd --apply)
        c=$(cat "$L")
        t_has "$c" "firewall-cmd --add-port=3000/tcp" "--apply opens it in firewalld"
        t_has "$c" "firewall-cmd --permanent --add-port=3000/tcp" "also after a reboot"
        t_has "$c" "ufw allow 3000/tcp" "and in ufw"
        t_has "$c" "rc-update add gitea default" "enabled at boot through OpenRC"
        t_has "$c" "init smbd start" "Samba started"
        u=$(cat "$O"/undo-*.log)
        t_has "$u" "firewall-cmd --remove-port=3000/tcp" "undo closes the port again"
        t_has "$u" "ufw delete allow 3000/tcp" "in ufw too"
        t_has "$u" "rc-update -a del" "and takes it out of the runlevel"
        ln -s /etc/init.d/gitea "$T_TMP/runlevels/default/gitea"
        out=$(srun --box gitea --services gitea)
        t_hasnt "$out" "disabled at boot" "in a runlevel: enabled"
    fi
    out=$(srun --batch --services gitea 2>&1)
    t_has "$out" "Which box is this? [s/w/e/f/g/b/O] o (default): other" "the box question offers the new boxes"
    for _b in fileshare gitea web; do srun --box "$_b" --services gitea >/dev/null; t_eq "$?" 0 "--box $_b is accepted"; done
    # SELinux enforcing and a denial for gitea (stand-ins for getenforce and ausearch).
    printf '#!/bin/sh\necho Enforcing\n' >"$B/getenforce"
    printf '#!/bin/sh\necho "type=AVC msg=audit(1700000000.1:5): avc:  denied  { read } for  pid=12 comm=\\"gitea\\" name=\\"app.ini\\" dev=\\"sda1\\" ino=5 scontext=system_u:system_r:gitea_t:s0 tcontext=unconfined_u:object_r:user_home_t:s0 tclass=file permissive=0"\n' >"$B/ausearch"
    chmod +x "$B/getenforce" "$B/ausearch"
    out=$(srun --services gitea)
    t_has "$out" "SELinux blocks it: read on app.ini (labelled user_home_t) - put the right label back: restorecon -Rv" "an SELinux denial is named, with the fix"
    printf '#!/bin/sh\necho Permissive\n' >"$B/getenforce"
    out=$(srun --services gitea)
    t_hasnt "$out" "SELinux blocks it" "not when SELinux is not enforcing"
    rm -f "$B/getenforce" "$B/ausearch"
    kill "$GPID" 2>/dev/null; pkill -f "$B/gitea" 2>/dev/null
    # Wait until the port is free again (the next shell's run uses it).
    _i=0; while ss -ltn | grep -q ":$GP " && [ "$_i" -lt 20 ]; do sleep 1; _i=$((_i + 1)); done
fi
t_done
