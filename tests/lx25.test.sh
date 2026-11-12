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
export CCDC_SKIP_VERIFY=1
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
OUT
STUB
cat >"$B/nft" <<'STUB'
#!/bin/sh
case "$*" in
    "list tables") exit 0 ;;
    "-c -f "*) [ "${NFT_REJECT:-0}" = 1 ] && { echo "Error: syntax error" >&2; exit 1; }; exit 0 ;;
    "-f "*) cp "$2" "$NFT_STATE" ;;
    "list table inet ccdc") [ -s "$NFT_STATE" ] ;;
    "delete table inet ccdc") : >"$NFT_STATE" ;;
    *) exit 1 ;;
esac
STUB
# stand-in iptables: records every command; "-C" (does the rule exist?) says no.
printf '#!/bin/sh\necho "$*" >>"$IPT_LOG"\n[ "$1" = -C ] && exit 1\nexit 0\n' >"$B/iptables"
cp "$B/iptables" "$B/ip6tables"
chmod +x "$B/ss" "$B/nft" "$B/iptables" "$B/ip6tables"
CCDC_SS="$B/ss"; CCDC_NFT="$B/nft"; CCDC_IPTABLES="$B/iptables"; CCDC_IP6TABLES="$B/ip6tables"
export CCDC_SS CCDC_NFT CCDC_IPTABLES CCDC_IP6TABLES
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
t_has "$r" "tcp dport { 22, 80, 8443, 9000-9010 } accept" "SSH, listening, scored and --allow ports open"
t_has "$r" "udp dport { 53, 68 } accept" "listening UDP and DHCP replies open"
t_has "$r" "ip saddr { 10.0.0.5, 10.9.9.9 } accept" "admin and scoring hosts allowed for everything"
t_hasnt "$r" "4444" "backdoor-style port not opened"
t_hasnt "$r" "3306" "loopback-only database not opened"
t_has "$r" "meta nfproto ipv6 drop" "IPv6 dropped"
t_has "$out" "4444/tcp (nc) - backdoor-style port, NOT allowed" "backdoor port reported"
t_fail "dry run loads nothing" test -s "$NFT_STATE"

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
t_has "$log" "-A CCDC-IN -p tcp --dport 18282 -j ACCEPT" "allowed port rule"
t_has "$log" "-I INPUT 1 -j CCDC-IN" "jump inserted at the top of INPUT"
t_has "$log" "-A CCDC-IN -j DROP" "final drop"
t_hasnt "$log" "-F INPUT" "INPUT itself is never flushed"
t_done
