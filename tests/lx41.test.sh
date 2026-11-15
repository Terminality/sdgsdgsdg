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
export CCDC_SKIP_VERIFY=1
# shellcheck disable=SC2086
run() { $SH "$C" "$@"; }
O="$T_TMP/out"; R="$T_TMP/root"; ST="$T_TMP/state"
mkdir -p "$O" "$R/var/log/audit" "$R/etc"
AUTH="$R/var/log/auth.log"; AUDIT="$R/var/log/audit/audit.log"

printf 'root:x:0:0::/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\nbob:x:1001:1001::/home/bob:/bin/bash\n' >"$R/etc/passwd"
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
type=SYSCALL msg=audit(1731631000.100:200): arch=c000003e syscall=59 success=yes uid=1000 tty=pts0 comm="ls" exe="/bin/ls" key="ccdc_cmd"
type=EXECVE msg=audit(1731631000.100:200): argc=2 a0="ls" a1="-la"
type=CWD msg=audit(1731631000.100:200): cwd="/home/alice"
type=SYSCALL msg=audit(1731631000.200:201): arch=c000003e syscall=59 success=yes uid=1001 tty=pts1 comm="bash" exe="/bin/bash" key="ccdc_cmd"
type=EXECVE msg=audit(1731631000.200:201): argc=2 a0="bash" a1="-i"
type=CWD msg=audit(1731631000.200:201): cwd="/tmp"
type=SYSCALL msg=audit(1731631000.300:202): arch=c000003e syscall=59 success=yes uid=0 tty=pts0 comm="nc" exe="/bin/nc" key="ccdc_cmd"
type=EXECVE msg=audit(1731631000.300:202): argc=3 a0="nc" a1="-e" a2=2F62696E2F7368
type=CWD msg=audit(1731631000.300:202): cwd="/root"
type=SYSCALL msg=audit(1731631000.400:203): arch=c000003e syscall=59 success=no uid=1001 tty=pts1 comm="id" exe="/usr/bin/id" key="ccdc_cmd"
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
printf 'type=SYSCALL msg=audit(1731631009.0:209): arch=c000003e syscall=59 success=yes uid=1001 tty=pts1 comm="wget" exe="/usr/bin/wget" key="ccdc_cmd"\ntype=EXECVE msg=audit(1731631009.0:209): argc=2 a0="wget" a1="http://10.9.9.9/x"\n' >>"$AUDIT"
r=$(run --out "$O" --state "$ST4" --root "$R" --no-color 2>&1)
t_has "$r" "1 command(s)" "a newly appended command is picked up"
t_ok "non-admin wget is flagged" grep -q 'commands bob .* wget' "$ST4/alerts.log"

# ---- no auditd --------------------------------------------------------------
t_start "no auditd: still logs sudo, points at --setup-auditd"
rm -f "$AUDIT"
r=$(run --out "$O" --state "$T_TMP/state5" --root "$R" --from-start --no-color 2>&1)
t_has "$r" "auditd is not logging commands" "says auditd is off"
t_has "$r" "--setup-auditd" "and how to turn it on"
t_done
