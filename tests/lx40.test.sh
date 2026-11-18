#!/bin/sh
# Tests for roles/linux/LX-40-change-watch.sh.
# A fake root (--root), a stand-in ss (listeners and connections switched by
# files), a stand-in systemctl and a stand-in /proc.  Takes a baseline,
# plants one change per section, and checks each is reported once with the
# right severity and words; connections: a reverse shell, a normal outgoing
# connection, the team's address, an admin-port login, loopback; then a quiet
# second check, --alert-cmd, --accept, settings kept, the run folder files,
# the questions on a terminal, and that no password hash is ever stored.
. "$(dirname "$0")/helper.sh"
SH=${TEST_SHELL:-sh}
C="$T_ROOT/roles/linux/LX-40-change-watch.sh"
export CCDC_SKIP_VERIFY=1
O="$T_TMP/out"; R="$T_TMP/root"; B="$T_TMP/bin"; ST="$T_TMP/state"; P="$T_TMP/proc"
mkdir -p "$O" "$B" "$P"
# shellcheck disable=SC2086
run() { $SH "$C" --out "$O" --state "$ST" --root "$R" --no-color "$@"; }
SS_LISTEN="$T_TMP/ss.listen"; SS_CONN="$T_TMP/ss.conn"; RUNNING="$T_TMP/running"
export SS_LISTEN SS_CONN RUNNING
cat >"$B/ss" <<'STUB'
#!/bin/sh
case "$1" in
    -ltnup) echo 'Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process'
            echo 'tcp   LISTEN 0      128    0.0.0.0:22         0.0.0.0:*         users:(("sshd",pid=1,fd=3))'
            echo 'tcp   LISTEN 0      128    0.0.0.0:80         0.0.0.0:*         users:(("apache2",pid=2,fd=3))'
            cat "$SS_LISTEN" ;;
    -tanp)  echo 'State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process'
            echo 'ESTAB  0      0      10.0.0.2:22        10.0.0.50:51000   users:(("sshd",pid=1,fd=4))'
            echo 'ESTAB  0      0      10.0.0.2:80        198.51.100.7:40000 users:(("apache2",pid=2,fd=5))'
            echo 'ESTAB  0      0      127.0.0.1:5000     127.0.0.1:3306    users:(("app",pid=3,fd=6))'
            cat "$SS_CONN" ;;
esac
STUB
cat >"$B/systemctl" <<'STUB'
#!/bin/sh
case "$1" in list-units) cat "$RUNNING" ;; esac
STUB
chmod +x "$B/ss" "$B/systemctl"
CCDC_SS="$B/ss"; CCDC_SYSTEMCTL="$B/systemctl"; CCDC_PROC="$P"; export CCDC_SS CCDC_SYSTEMCTL CCDC_PROC
: >"$SS_LISTEN"; : >"$SS_CONN"
printf '  ssh.service loaded active running OpenSSH\n  auditd.service loaded active running Audit\n  apache2.service loaded active running Apache\n' >"$RUNNING"
# proc PID USER CMD EXE -> a stand-in /proc/PID (owner shown by ls is the test user)
proc() { mkdir -p "$P/$1"; printf '%s\n' $3 | tr '\n' '\000' >"$P/$1/cmdline"; ln -sf "$4" "$P/$1/exe"; }

mkdir -p "$R/etc/cron.d" "$R/etc/sudoers.d" "$R/etc/pam.d" "$R/etc/systemd/system" "$R/home/alice/.ssh" "$R/var/www/html" "$R/usr/bin" "$R/root" "$R/opt/app/public"
printf 'root:x:0:0::/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\nsvc:x:998:998::/var/svc:/usr/sbin/nologin\nbob:x:1002:1002::/home/bob:/bin/bash\n' >"$R/etc/passwd"
printf 'root:$6$planted$SECRETHASHVALUE:19000::::::\nalice:$6$a$alicehash:19000::::::\nsvc:!:19000::::::\nbob:$6$b$bobhash:19000::::::\n' >"$R/etc/shadow"
printf 'root:x:0:\nsudo:x:27:alice\nalice:x:1000:\nusers:x:100:\n' >"$R/etc/group"
printf 'root ALL=(ALL) ALL\n' >"$R/etc/sudoers"  # posix-ok
printf 'auth required pam_unix.so\n' >"$R/etc/pam.d/common-auth"
printf '<h1>ok</h1>\n' >"$R/var/www/html/index.html"
printf 'x\n' >"$R/usr/bin/tool"

t_start "baseline and questions answered by flags"
out=$(run --batch --team 10.0.0.50 --baseline 2>&1); rc=$?
t_eq "$rc" 0 "exit 0"
t_has "$out" "baseline taken at" "baseline taken"
t_has "$out" "Baseline only" "a baseline-only run says how to check"
t_ok "first run folder" test -f "$O/changewatch-1/run.txt"
t_ok "output.txt written" test -s "$O/changewatch-1/output.txt"
t_hasnt "$(cat "$O/changewatch-1/output.txt")" "$(printf '\033')" "output.txt has no colour codes"
t_has "$(cat "$ST/settings")" "team=10.0.0.50" "answers saved for next time"
out=$(run --batch 2>&1)
t_has "$out" "using the baseline from" "existing baseline kept by default"
t_has "$out" "check 1: [ok] no changes" "nothing changed yet"
t_has "$out" "team, never alerted: 10.0.0.50" "team address remembered from the last run"
t_has "$out" "Different from the baseline right now: 0" "summary: nothing different"

t_start "one change per section"
printf 'mallory:x:1001:1001::/home/mallory:/bin/bash\n' >>"$R/etc/passwd"
sed -e 's/^alice:x:1000:/alice:x:0:/' -e 's|^svc:x:998:998::/var/svc:/usr/sbin/nologin|svc:x:998:998::/var/svc:/bin/bash|' "$R/etc/passwd" >"$R/etc/passwd.t" && mv "$R/etc/passwd.t" "$R/etc/passwd"
sed -e 's/alicehash/newalicehash/' -e 's/^bob:[^:]*:/bob::/' "$R/etc/shadow" >"$R/etc/shadow.t" && mv "$R/etc/shadow.t" "$R/etc/shadow"
sed -e 's/^sudo:x:27:alice$/sudo:x:27:alice,mallory/' -e 's/^users:x:100:$/users:x:100:bob/' "$R/etc/group" >"$R/etc/group.t" && mv "$R/etc/group.t" "$R/etc/group"
printf 'mallory ALL=(ALL) NOPASSWD:ALL\n' >"$R/etc/sudoers.d/90-x"  # posix-ok
printf '* * * * * root /tmp/.x\n' >"$R/etc/cron.d/update"
printf '[Service]\nExecStart=/tmp/.x\n' >"$R/etc/systemd/system/sys-update.service"
printf 'ssh-ed25519 AAAAPLANTED red\n' >"$R/home/alice/.ssh/authorized_keys"
printf '<?php system($_GET[1]);\n' >"$R/var/www/html/c.php"
cp "$R/usr/bin/tool" "$R/usr/bin/tool2"; chmod 4755 "$R/usr/bin/tool2"
grep -v auditd "$RUNNING" | grep -v apache2 >"$RUNNING.t"; mv "$RUNNING.t" "$RUNNING"
proc 9 root "nc -lvp 4444 -e /bin/sh" /usr/bin/nc
proc 21 root "/tmp/.k/agent" "/tmp/.k/agent"
echo 'tcp   LISTEN 0      5      0.0.0.0:4444       0.0.0.0:*         users:(("nc",pid=9,fd=3))' >"$SS_LISTEN"
echo 'tcp   LISTEN 0      5      0.0.0.0:8081       0.0.0.0:*         users:(("agent",pid=21,fd=3))' >>"$SS_LISTEN"
proc 33 www-data "bash -i" /usr/bin/bash
proc 34 root "/usr/bin/curl https://example.org" /usr/bin/curl
proc 35 root "/usr/lib/apt/methods/http" /usr/lib/apt/methods/http
cat >"$SS_CONN" <<'EOF'
ESTAB  0      0      10.0.0.2:43210     203.0.113.9:4444  users:(("bash",pid=33,fd=0))
ESTAB  0      0      10.0.0.2:43211     203.0.113.10:443  users:(("curl",pid=34,fd=3))
ESTAB  0      0      10.0.0.2:43212     91.189.91.81:80   users:(("http",pid=35,fd=3))
ESTAB  0      0      10.0.0.2:43213     10.0.0.50:9997    users:(("splunkd",pid=36,fd=3))
ESTAB  0      0      10.0.0.2:22        203.0.113.66:5123 users:(("sshd",pid=1,fd=7))
ESTAB  0      0      10.0.0.2:80        198.51.100.8:40001 users:(("apache2",pid=2,fd=8))
ESTAB  0      0      [::ffff:10.0.0.2]:43214 [::ffff:203.0.113.11]:8080 users:(("python3",pid=37,fd=3))
EOF
out=$(run --batch --team 10.0.0.48/29 --alert-cmd "cat >'$T_TMP/sent.txt'" 2>&1)
t_has "$out" "[!] HIGH users       added   mallory" "new account HIGH"
t_has "$out" "new account: uid 1001, home /home/mallory, shell /bin/bash" "new account explained"
t_has "$out" "now has UID 0 - a second root account (was uid 1000)" "account made UID 0"
t_has "$out" "[!] HIGH users       changed svc" "service account given a shell HIGH"
t_has "$out" "can now log in: shell /usr/sbin/nologin -> /bin/bash" "login shell change explained"
t_has "$out" "[*] MED  passwords   changed alice" "password change MED"
t_has "$out" "[!] HIGH passwords   changed bob" "password removed HIGH"
t_has "$out" "password REMOVED" "empty password explained"
t_has "$out" "[!] HIGH groups      changed sudo" "sudo group change HIGH"
t_has "$out" "added: mallory - members of this group are admins" "names who was added to sudo"
t_has "$out" "[-] LOW  groups      changed users" "ordinary group change LOW"
t_has "$out" "[!] HIGH files       added   /etc/sudoers.d/90-x" "new sudoers file HIGH"
t_has "$out" "sudo rules (who can become root): file added" "sudoers file explained"
t_has "$out" "[!] HIGH cron        added   /etc/cron.d/update" "new cron job HIGH"
t_has "$out" "[!] HIGH units       added   /etc/systemd/system/sys-update.service" "new service file HIGH"
t_has "$out" "[!] HIGH running     removed auditd.service" "auditd stopped HIGH"
t_has "$out" "[*] MED  running     removed apache2.service" "a service stopping MED"
t_has "$out" "if it is scored, it is down" "stopped service explained"
t_has "$out" "[!] HIGH keys        added   /home/alice/.ssh/authorized_keys" "new SSH key HIGH"
t_has "$out" "[!] HIGH web         added   /var/www/html/c.php" "web shell HIGH"
t_has "$out" "[!] HIGH suid        added   /usr/bin/tool2" "new SUID program HIGH"
t_has "$out" "[!] HIGH ports       added   tcp 0.0.0.0 4444" "backdoor port HIGH"
t_has "$out" "pid 9, user" "listener shows its pid and user"
t_has "$out" "runs: nc -lvp 4444 -e /bin/sh" "listener shows its command line"
t_has "$out" "[!] HIGH ports       added   tcp 0.0.0.0 8081" "listener from /tmp HIGH"
t_has "$(cat "$T_TMP/sent.txt")" "mallory" "--alert-cmd received the alerts"

t_start "connections"
t_has "$out" "[!] HIGH connections out     203.0.113.9:4444" "reverse shell HIGH"
t_has "$out" "REVERSE SHELL?" "reverse shell explained"
t_has "$out" "runs: bash -i" "reverse shell shows its command"
t_has "$out" "[*] MED  connections out     203.0.113.10:443" "unknown outgoing connection MED"
t_has "$out" "[-] LOW  connections out     91.189.91.81:80" "package updates LOW"
t_has "$out" "[!] HIGH connections out     203.0.113.11:8080" "python calling out HIGH (IPv4-mapped address)"
t_hasnt "$out" "10.0.0.50:9997" "team address never alerted"
t_has "$out" "[*] MED  connections in      203.0.113.66 -> port 22" "new address on SSH MED"
t_hasnt "$out" "198.51.100.8" "web visitors are not alerted"
t_hasnt "$out" "127.0.0.1" "loopback not alerted"
t_hasnt "$out" "198.51.100.7" "connections open at the baseline are not alerted"
t_ok "connections.csv written" grep -q '203.0.113.9' "$O/changewatch-3/csv/connections.csv"
t_ok "alerts.txt table" grep -q 'SEVERITY' "$O/changewatch-3/alerts.txt"
t_ok "summary.txt" grep -q 'This run: ' "$O/changewatch-3/summary.txt"
t_has "$(cat "$O/changewatch-3/summary.txt")" "connections" "summary counts by section"

t_start "reported once; accept"
out=$(run --batch 2>&1)
t_has "$out" "check 1: [ok] no changes" "second check is quiet (connections too)"
t_ok "changes since baseline still listed" grep -q 'mallory' "$ST/changes-since-baseline.txt"
t_has "$out" "Different from the baseline right now:" "summary lists the differences"
run --batch --accept >/dev/null 2>&1
out=$(run --batch 2>&1)
t_has "$out" "Different from the baseline right now: 0" "--accept clears the differences"
t_fail "no password hash stored" grep -rq "SECRETHASHVALUE\|alicehash" "$ST" "$O"
rm "$R/var/www/html/index.html"
out=$(run --batch --loop 10 --count 1 2>&1)
t_has "$out" "[*] MED  web         removed /var/www/html/index.html" "--loop runs a check; removed web file MED"
$SH "$C" --loop 5 >/dev/null 2>&1; t_eq "$?" 2 "--loop under 10 seconds exits 2"
$SH "$C" --team 10.0.0.999/40 >/dev/null 2>&1; t_eq "$?" 2 "a bad team address exits 2"

t_start "new web folder joins the baseline quietly"
printf 'x\n' >"$R/opt/app/public/index.php"
out=$(run --batch --webroot "$R/opt/app/public" 2>&1)
t_has "$out" "new web folder(s) added to the baseline: /opt/app/public" "said so"
t_hasnt "$out" "added   /opt/app/public/index.php" "its files were not alerted"
printf 'y\n' >"$R/opt/app/public/shell.php"
out=$(run --batch 2>&1)
t_has "$out" "[!] HIGH web         added   /opt/app/public/shell.php" "the folder is watched from then on"

t_start "in a loop the SUID scan runs on every Nth check only"
run --batch --accept >/dev/null 2>&1
cp "$R/usr/bin/tool2" "$R/usr/bin/tool3"; chmod 4755 "$R/usr/bin/tool3"
out=$(run --batch --loop 10 --count 2 --suid-every 2 2>&1)
t_eq "$(printf '%s\n' "$out" | grep -c '\[!\] HIGH suid        added   /usr/bin/tool3')" 1 "the new SUID file is reported once, by the check that scans"
$SH "$C" --suid-every 0 >/dev/null 2>&1; t_eq "$?" 2 "--suid-every 0 exits 2"
out=$(run --batch --no-conns --no-suid 2>&1)
t_has "$out" "Connections:  not watched" "--no-conns"
t_has "$(cat "$ST/settings")" "conns=0" "--no-conns saved as the next default"

t_start "questions on a terminal"
if command -v script >/dev/null 2>&1; then
    # baseline? (Enter = keep) | seconds: 0 | conns? y | team: 10.0.0.9 | web: Enter | suid? n
    printf '\n0\ny\n10.0.0.9\n\nn\n' >"$T_TMP/answers"
    out=$(CCDC_NO_TTY=0 script -qc "$SH '$C' --out '$O' --state '$ST' --root '$R' --no-color" /dev/null <"$T_TMP/answers" 2>&1)
    t_has "$out" "Use the baseline from" "asks about the baseline"
    t_has "$out" "Seconds between checks" "asks how often"
    t_has "$out" "Watch connections too?" "asks about connections"
    t_has "$out" "Your team's addresses" "asks for team addresses"
    t_has "$out" "new SUID programs" "asks about the SUID scan"
    t_has "$(cat "$ST/settings")" "team=10.0.0.9" "typed answer used"
    t_has "$(cat "$ST/settings")" "suid=0" "no to SUID used"
else
    t_ok "script(1) not installed - skipped" true
fi
t_done
