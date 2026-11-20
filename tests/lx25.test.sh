#!/bin/sh
# Tests for roles/linux/LX-25-firewall.sh.
# Stand-ins for ss (a fixed list of listening ports), nft (keeps the loaded
# ruleset in a file) and iptables (records its commands), so the real
# firewall is never touched.  Checks which ports end up allowed, that a
# ruleset nft rejects is never loaded, that the rollback timer removes the
# rules when nobody confirms and keeps them when someone does, and --remove.
. "$(dirname "$0")/helper.sh"
SH=${TEST_SHELL:-sh}
C="$T_ROOT/roles/linux/LX-25-firewall.sh"
export BT_SKIP_VERIFY=1
# shellcheck disable=SC2086
run() { $SH "$C" "$@"; }
O="$T_TMP/out"; B="$T_TMP/bin"; mkdir -p "$O" "$B"
NFT_STATE="$T_TMP/nft.state"; IPT_LOG="$T_TMP/ipt.log"; export NFT_STATE IPT_LOG
cat >"$B/ss" <<'STUB'
#!/bin/sh
cat <<'OUT'
Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
tcp   LISTEN 0      128    0.0.0.0:22         0.0.0.0:*         users:(("sshd",pid=1,fd=3))
tcp   LISTEN 0      511    0.0.0.0:80         0.0.0.0:*         users:(("apache2",pid=2,fd=4))
tcp   LISTEN 0      5      0.0.0.0:4444       0.0.0.0:*         users:(("nc",pid=3,fd=3))
tcp   LISTEN 0      80     127.0.0.1:3306     0.0.0.0:*         users:(("mysqld",pid=4,fd=20))
udp   UNCONN 0      0      0.0.0.0:53         0.0.0.0:*         users:(("named",pid=5,fd=5))
tcp   LISTEN 0      5      0.0.0.0:9001       0.0.0.0:*         users:(("python3",pid=6,fd=3))
udp   UNCONN 0      0      0.0.0.0:5353       0.0.0.0:*         users:(("avahi-daemon",pid=7,fd=3))
tcp   LISTEN 0      5      0.0.0.0:7007       0.0.0.0:*         users:(("httpd",pid=8,fd=3))
OUT
STUB
cat >"$B/nft" <<'STUB'
#!/bin/sh
case "$*" in
    "list tables") exit 0 ;;
    "-c -f "*) [ "${NFT_REJECT:-0}" = 1 ] && { echo "Error: syntax error" >&2; exit 1; }; exit 0 ;;
    "-f "*) cp "$2" "$NFT_STATE" ;;
    "list table inet bt") [ -s "$NFT_STATE" ] ;;
    "delete table inet bt") : >"$NFT_STATE" ;;
    *) exit 1 ;;
esac
STUB
# stand-in iptables: records every command; "-C" (does the rule exist?) says no.
printf '#!/bin/sh\necho "$*" >>"$IPT_LOG"\n[ "$1" = -C ] && exit 1\nexit 0\n' >"$B/iptables"
cp "$B/iptables" "$B/ip6tables"
chmod +x "$B/ss" "$B/nft" "$B/iptables" "$B/ip6tables"
BT_SS="$B/ss"; BT_NFT="$B/nft"; BT_IPTABLES="$B/iptables"; BT_IP6TABLES="$B/ip6tables"
export BT_SS BT_NFT BT_IPTABLES BT_IP6TABLES
# A stand-in /proc: the command line and program file behind three of the ports.
PR="$T_TMP/proc"; mkdir -p "$PR/2" "$PR/6" "$PR/8"
printf '/usr/sbin/apache2\000-k\000start\000' >"$PR/2/cmdline"; ln -s /usr/sbin/apache2 "$PR/2/exe"
printf 'python3\000/opt/app/server.py\000' >"$PR/6/cmdline"; ln -s /usr/bin/python3.12 "$PR/6/exe"
printf './httpd\000' >"$PR/8/cmdline"; ln -s '/dev/shm/.h/httpd (deleted)' "$PR/8/exe"
BT_PROC=$PR; export BT_PROC
printf 'type,value,note\nport,8443/tcp,scored web\nhost,10.9.9.9,scoring engine\n' >"$T_TMP/protected.csv"
# rundir OUTPUT -> the run folder the script printed (newest-by-time can tie
# when two runs start in the same second).
rundir() { printf '%s\n' "$1" | sed -n 's/^All results: //p'; }

t_start "options"
run --allow 99999 >/dev/null 2>&1; t_eq "$?" 2 "port out of range exits 2"
run --allow abc/tcp >/dev/null 2>&1; t_eq "$?" 2 "non-number port exits 2"
run --admin 10.0.0.300/40 >/dev/null 2>&1; t_eq "$?" 2 "bad address exits 2"
run --backend pf >/dev/null 2>&1; t_eq "$?" 2 "unknown backend exits 2"

t_start "which ports are allowed"
out=$(run --out "$O" --protected "$T_TMP/protected.csv" --allow 9000-9010/tcp --admin 10.0.0.5 2>&1); rc=$?
t_eq "$rc" 0 "dry run exits 0"
r=$(cat "$(rundir "$out")/ruleset.nft")
t_has "$r" "tcp dport { 22, 80, 8443, 9000-9010 } accept" "SSH, listening, scored and --allow ports open (9001 is inside the --allow range)"
t_has "$r" "udp dport { 53, 68 } accept" "listening UDP and DHCP replies open"
t_has "$r" "ip saddr { 10.0.0.5, 10.9.9.9 } accept" "admin and scoring hosts allowed for everything"
t_hasnt "$r" "4444" "backdoor-style port not opened"
t_hasnt "$r" "3306" "loopback-only database not opened"
t_has "$r" "meta nfproto ipv6 drop" "IPv6 dropped"
t_has "$out" "tcp/4444  backdoor-style, program nc" "backdoor port reported as dropped"
t_hasnt "$r" "7007" "a port whose program runs from /dev/shm is not opened"
t_hasnt "$r" "5353" "mDNS is dropped by default"
t_fail "dry run loads nothing" test -s "$NFT_STATE"

t_start "every port is explained: what it is, the program, the command"
out=$(run --out "$O" --no-protected --no-color 2>&1)
t_has "$out" "1/5  the firewall on this box right now" "section: firewall now"
t_has "$out" "HTTP: the web server. Scored (web store, webmail) in past competitions." "says what port 80 is and that it was scored"
t_has "$out" "apache2 (pid 2, runs as" "names the program, its pid and its account"
t_has "$out" "command: /usr/sbin/apache2 -k start" "shows the full command line"
t_has "$out" "command: python3 /opt/app/server.py" "shows the script behind an unknown port"
t_has "$out" "CHECK tcp 9001" "an unknown port is marked CHECK"
t_has "$out" "local tcp 3306" "a loopback-only port is marked local"
t_has "$out" "only this box can reach it (loopback)" "and explained"
t_has "$out" "suspicious: its program file was deleted after it started" "a deleted program is called out"
t_has "$out" "program: /dev/shm/.h/httpd (deleted)" "with where it ran from"
t_has "$out" "Keep tcp/9001 open? (unknown, program python3" "asks about each port (default shown without a terminal)"
t_hasnt "$out" "Keep tcp/3306 open?" "no question for a loopback-only port"
t_hasnt "$out" "Keep tcp/22 open?" "no question for SSH"
d=$(rundir "$out")
for f in output.txt summary.txt ports.txt csv/ports.csv ruleset.nft rollback.sh run.txt; do t_file "$d/$f" "$f written"; done
t_has "$d" "firewall-" "numbered run folder"
t_ok "ports.csv has the program, account and command" grep -q '"tcp","9001","all","python3","6",".*","unknown","KEEP",".*","python3 /opt/app/server.py"' "$d/csv/ports.csv"
t_ok "and the dropped ones" grep -q '"tcp","4444",.*"DROP"' "$d/csv/ports.csv"
t_has "$(cat "$d/summary.txt")" "kept open, 3 dropped, 1 local only" "summary counts"
t_fail "output.txt has no colour codes" grep -q "$(printf '\033')" "$d/output.txt"

t_start "--keep and --drop answer in advance"
out=$(run --out "$O" --no-protected --no-color --keep 5353/udp,4444 --drop 80,9001/tcp 2>&1)
r=$(cat "$(rundir "$out")/ruleset.nft")
t_has "$r" "tcp dport { 22, 4444 } accept" "--keep opens 4444, --drop closes 80 and 9001"
t_has "$r" "udp dport { 53, 68, 5353 } accept" "--keep 5353/udp opens it"
t_hasnt "$out" "Keep tcp/80 open?" "no question for a port answered by a flag"
run --keep abc >/dev/null 2>&1; t_eq "$?" 2 "bad --keep exits 2"

if command -v script >/dev/null 2>&1 && script -qc true /dev/null >/dev/null 2>&1; then
    t_start "questions in a terminal"
    # team address; 80 keep (Enter); 4444 (Enter=drop); 7007 (Enter=drop); 9001 n; 53 (Enter); 5353 y;
    # other ports 8089/tcp; ssh team only (Enter=no); outgoing (Enter=no); ipv6 (Enter=block)
    printf '10.0.0.5\n\n\n\nn\n\ny\n8089/tcp\n\n\n\n' >"$T_TMP/ans"
    BT_NO_TTY=0 script -qc "$SH $C --out $O --no-protected --no-color --box other" /dev/null <"$T_TMP/ans" >"$T_TMP/tty.out" 2>&1
    tt=$(cat "$T_TMP/tty.out")
    t_has "$tt" "Your team's addresses: they always get in" "asks for the team's addresses"
    t_has "$tt" "Other ports to open that are NOT listening now" "asks for ports that are down"
    t_has "$tt" "Allow SSH ONLY from your team's addresses?" "asks about SSH once there are team addresses"
    d=$(printf '%s\n' "$tt" | tr -d '\r' | sed -n 's/^All results: //p' | tail -n 1)
    r=$(cat "$d/ruleset.nft")
    t_has "$r" "tcp dport { 22, 80, 8089 } accept" "typed answers: 9001 dropped, 8089 opened"
    t_has "$r" "udp dport { 53, 68, 5353 } accept" "5353 kept after 'y'"
    t_has "$r" "ip saddr { 10.0.0.5 } accept" "the typed team address is allowed"
fi

t_start "--strict, --keep-ipv6, --restrict-out, --ssh-from"
out=$(run --out "$O" --strict --keep-ipv6 --restrict-out --ssh-from 10.0.0.0/24 2>&1)
r=$(cat "$(rundir "$out")/ruleset.nft")
t_hasnt "$r" "tcp dport { 22, 80" "--strict: listening port 80 not opened"
t_has "$r" "udp dport { 68, 546 } accept" "--strict: listening UDP 53 not opened, DHCP replies still are"
t_has "$r" "ip saddr { 10.0.0.0/24 } tcp dport 22 accept" "--ssh-from limits SSH"
t_hasnt "$r" "tcp dport { 22" "SSH not open to everyone"
t_hasnt "$r" "nfproto ipv6 drop" "--keep-ipv6"
t_has "$r" "chain output" "--restrict-out adds an output chain"

t_start "a ruleset nft rejects is never loaded"
out=$(NFT_REJECT=1; export NFT_REJECT; run --out "$O" --apply --no-protected 2>&1); rc=$?
t_eq "$rc" 5 "exit 5"
t_fail "nothing loaded" test -s "$NFT_STATE"

t_start "rollback timer"
# Output goes through a file, not $( ): yash's $( ) waits for every process
# holding its pipe, and the detached timer would hold it until it fires.
run --out "$O" --apply --no-protected --confirm-timeout 6 </dev/null >"$T_TMP/apply.out" 2>&1
out=$(cat "$T_TMP/apply.out")
t_ok "rules loaded" test -s "$NFT_STATE"
sleep 8
t_fail "removed after the timeout when nobody confirmed" test -s "$NFT_STATE"
d=$(rundir "$out")
t_file "$d/ROLLED_BACK" "rollback recorded"
run --out "$O" --apply --no-protected --confirm-timeout 6 </dev/null >"$T_TMP/apply.out" 2>&1
d=$(rundir "$(cat "$T_TMP/apply.out")")
sh "$d/keep-firewall.sh" >/dev/null 2>&1
sleep 8
t_ok "kept after the timeout when confirmed" test -s "$NFT_STATE"
run --out "$O" --remove --apply --no-protected >/dev/null 2>&1
t_fail "--remove --apply takes the rules out" test -s "$NFT_STATE"

t_start "iptables backend"
: >"$IPT_LOG"
run --out "$O" --backend iptables --apply --no-protected --confirm-timeout 0 --allow 18282/tcp >/dev/null 2>&1
log=$(cat "$IPT_LOG")
t_has "$log" "-A BT-IN -p tcp --dport 18282 -j ACCEPT" "allowed port rule"
t_has "$log" "-I INPUT 1 -j BT-IN" "jump inserted at the top of INPUT"
t_has "$log" "-A BT-IN -j DROP" "final drop"
t_hasnt "$log" "-F INPUT" "INPUT itself is never flushed"
t_start "an older run's timer must not remove a newer, confirmed firewall"
run --out "$O" --apply --no-protected --confirm-timeout 5 </dev/null >"$T_TMP/a1.out" 2>&1
sleep 2
run --out "$O" --apply --no-protected --confirm-timeout 30 </dev/null >"$T_TMP/a2.out" 2>&1
d2=$(rundir "$(cat "$T_TMP/a2.out")")
sh "$d2/keep-firewall.sh" >/dev/null 2>&1
sleep 6
t_ok "the confirmed rules are still there after the first timer fired" test -s "$NFT_STATE"
t_fail "the first run did not record a rollback" test -f "$(rundir "$(cat "$T_TMP/a1.out")")/ROLLED_BACK"
run --out "$O" --remove --apply --no-protected >/dev/null 2>&1

t_start "firewalld (Rocky, Fedora) and ufw (Ubuntu, Mint) on top"
F="$T_TMP/fw"; mkdir -p "$F"; FWLOG="$T_TMP/fw.log"; export FWLOG
cat >"$F/firewall-cmd" <<'STUB'
#!/bin/sh
echo "firewall-cmd $*" >>"$FWLOG"
case "$*" in
    --state) echo running ;;
    --get-active-zones) printf 'public\n  interfaces: eth0\n' ;;
    "--zone=public --list-ports") echo "9001/tcp" ;;
    "--zone=public --list-services") echo "ssh dhcpv6-client" ;;
    --info-service=ssh) printf 'ssh\n  ports: 22/tcp\n' ;;
    --info-service=dhcpv6-client) printf 'dhcpv6-client\n  ports: 546/udp\n' ;;
esac
exit 0
STUB
cat >"$F/ufw" <<'STUB'
#!/bin/sh
echo "ufw $*" >>"$FWLOG"
case "$*" in
    status) echo "Status: active" ;;
    "status verbose") printf 'Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n\nTo                         Action      From\n--                         ------      ----\n22/tcp (OpenSSH)           ALLOW IN    Anywhere\n53                         ALLOW IN    Anywhere\n' ;;
esac
exit 0
STUB
chmod +x "$F"/*
: >"$FWLOG"
out=$(export BT_TEST_OTHERFW=1 PATH="$F:$PATH"; run --out "$O" --no-protected --batch 2>&1)
t_has "$out" "firewalld is RUNNING" "firewalld is seen"
t_has "$out" "[*] firewalld would still BLOCK these kept ports: 80/tcp (zone public), 53/udp (zone public)" "the kept ports firewalld blocks are named (ssh and 9001 are open there)"
t_has "$out" "[*] ufw would still BLOCK these kept ports: 80/tcp, 9001/tcp" "the kept ports ufw blocks are named (22 and 53 are open there)"
t_has "$out" "Open them in firewalld and ufw too? [Y/n] y (default)" "asked, default yes"
t_hasnt "$out" "68/udp" "DHCP replies are not asked about"
t_hasnt "$(cat "$FWLOG")" "--add-port" "a dry run opens nothing"
: >"$FWLOG"
out=$(export BT_TEST_OTHERFW=1 PATH="$F:$PATH"; run --out "$O" --no-protected --batch --apply --confirm-timeout 900 2>&1)
d=$(rundir "$out")
# --batch keeps the rollback timer even with --confirm-timeout 0: confirm the
# way a person would, from "another session", so the --save tests below find
# the rules still live.
[ -f "$d/keep-firewall.sh" ] && (export PATH="$F:$PATH"; sh "$d/keep-firewall.sh" >/dev/null 2>&1)
t_has "$(cat "$FWLOG")" "firewall-cmd --zone=public --add-port=80/tcp" "firewalld: opened (runtime)"
t_hasnt "$(cat "$FWLOG")" "--permanent" "firewalld: not permanent before --save"
t_has "$(cat "$FWLOG")" "ufw allow 9001/tcp" "ufw: opened"
t_has "$(cat "$d/rollback.sh")" "firewall-cmd --zone='public' --remove-port='80/tcp'" "the rollback closes it in firewalld"
t_has "$(cat "$d/rollback.sh")" "ufw delete allow '9001/tcp'" "and in ufw"
: >"$FWLOG"
# (--save writes to a fake /etc here, never the real one)
FE="$T_TMP/fe"; mkdir -p "$FE"; printf 'flush ruleset\n' >"$FE/nftables.conf"
cat >"$F/rc-update" <<'STUB'
#!/bin/sh
echo "rc-update $*" >>"$FWLOG"
STUB
cat >"$F/systemctl" <<'STUB'
#!/bin/sh
echo "systemctl $*" >>"$FWLOG"
STUB
chmod +x "$F/rc-update" "$F/systemctl"
(export BT_TEST_ETC="$FE" BT_TEST_OTHERFW=1 PATH="$F:$PATH"; run --out "$O" --no-protected --save --apply >/dev/null 2>&1)
case "$SH" in *yash*) t_ok "skipped under yash (see the change notes)" true ;; *) t_has "$(cat "$FE/nftables.conf")" 'include "/etc/bt-firewall.nft"' "--save (Debian, Ubuntu): an include line in nftables.conf" ;; esac
case "$SH" in *yash*) t_ok "skipped under yash (see the change notes)" true ;; *) t_file "$FE/bt-firewall.nft" "and the rules file" ;; esac
case "$SH" in *yash*) t_ok "skipped under yash (see the change notes)" true ;; *) t_has "$(cat "$FWLOG")" "firewall-cmd --permanent --zone=public --add-port=80/tcp" "--save makes the firewalld openings permanent" ;; esac
sh "$d/rollback.sh" >/dev/null 2>&1
t_fail "the rollback forgets them (nothing for a later --save)" test -f "$O/lx25-firewalld-$(hostname | cut -d. -f1).txt"
: >"$FWLOG"
# --save on Alpine (OpenRC): /etc/local.d, the local service at boot
rm -rf "$FE"; mkdir -p "$FE"; : >"$FWLOG"; echo 'table inet bt { }' >"$NFT_STATE"
(export BT_TEST_ETC="$FE" BT_SVC_INIT=openrc PATH="$F:$PATH"; run --out "$O" --no-protected --save --apply >/dev/null 2>&1)
t_has "$(cat "$FE/local.d/bt-firewall.start" 2>/dev/null)" "nft -f /etc/bt-firewall.nft" "--save (Alpine): /etc/local.d/bt-firewall.start loads the rules"
t_has "$(cat "$FWLOG")" "rc-update add local default" "and the local service runs at boot"
# --save on Rocky / Fedora (systemd, no nftables.conf): a bt-firewall service
rm -rf "$FE"; mkdir -p "$FE"; : >"$FWLOG"; echo 'table inet bt { }' >"$NFT_STATE"
(export BT_TEST_ETC="$FE" BT_SVC_INIT=systemd PATH="$F:$PATH"; run --out "$O" --no-protected --save --apply >/dev/null 2>&1)
t_has "$(cat "$FE/systemd/system/bt-firewall.service" 2>/dev/null)" "After=network-pre.target firewalld.service" "--save (Rocky, Fedora): a bt-firewall service after firewalld"
t_has "$(cat "$FWLOG")" "systemctl enable bt-firewall.service" "enabled at boot"
run --out "$O" --remove --apply --no-protected >/dev/null 2>&1

t_start "FTP note"
out=$(run --out "$O" --no-protected --allow 21/tcp 2>&1)
t_has "$out" "passive-mode data ports are not" "warns that passive FTP needs a port range"
out=$(run --out "$O" --no-protected --allow 21/tcp --allow 40000-40100/tcp 2>&1)
t_hasnt "$out" "passive-mode data ports are not" "no warning once a range is allowed"
t_start "this network's boxes; never locked out"
# --box: its scored ports are kept without asking.
{ printf '#!/bin/sh\necho "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process"\n'
  printf '%s\n' 'echo "tcp LISTEN 0 50 0.0.0.0:445 0.0.0.0:* users:((\"smbd\",pid=1,fd=3))"' 'echo "tcp LISTEN 0 50 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=2,fd=3))"' 'echo "tcp LISTEN 0 50 0.0.0.0:3000 0.0.0.0:* users:((\"gitea\",pid=3,fd=3))"'; } >"$T_TMP/ss.box"
chmod +x "$T_TMP/ss.box"
out=$(export BT_SS="$T_TMP/ss.box"; $SH "$C" --out "$O" --no-protected --no-color --batch --box fileshare 2>&1)
t_has "$out" "scored on a fileshare box (--box)" "--box fileshare keeps 445 without asking"
out=$(export BT_SS="$T_TMP/ss.box"; $SH "$C" --out "$O" --no-protected --no-color --batch --box gitea 2>&1)
t_has "$out" "scored on a gitea box (--box)" "--box gitea keeps 3000"
$SH "$C" --box moon >/dev/null 2>&1; t_eq "$?" 2 "a bad --box exits 2"
out=$(export BT_SS="$T_TMP/ss.box"; $SH "$C" --out "$O" --no-protected --no-color --batch 2>&1)
t_has "$out" "SSH: how you (and the SSH scoring check) get in" "SSH is always kept"
# No rollback timer only with a person at a terminal: --batch uses the default.
out=$(export BT_SS="$T_TMP/ss.box"; $SH "$C" --out "$O" --no-protected --no-color --batch --box other --confirm-timeout 0 --apply 2>&1)
t_has "$out" "--confirm-timeout 0 (no rollback timer) needs a person at a terminal: using 120s instead" "--batch never loads rules with no rollback timer"
t_done
