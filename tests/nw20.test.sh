#!/bin/sh
# Tests for roles/network/NW-20-firewall-ruleset.sh.
# Stand-in firewalls for every brand (the stand-in ssh logs each command and
# prints that brand's documented answer), and stand-in nc and ping that read
# which scored box:port "answers" from a file.  In "break" mode a firewall
# that gets the block rule makes a scored port stop answering, and the undo
# brings it back - so the automatic put-back is tested.  Checks: the
# questions and defaults, plan.txt and the exact commands per brand, the
# real nft accepts the Linux ruleset, a dry run sends no change, --apply,
# the put-back, the undo script, --remove.
. "$(dirname "$0")/helper.sh"
SH=${TEST_SHELL:-sh}
C="$T_ROOT/roles/network/NW-20-firewall-ruleset.sh"
export BT_SKIP_VERIFY=1
O="$T_TMP/out"; B="$T_TMP/bin"; D="$T_TMP/dev"; mkdir -p "$O" "$B" "$D"
STUB_DIR=$D; export STUB_DIR
cat >"$B/ssh" <<'STUB'
#!/bin/sh
host=""; cmd=""; seen=0
for a in "$@"; do
    if [ "$seen" = 1 ]; then cmd=$a; continue; fi
    case "$a" in *@*) host=${a#*@}; seen=1 ;; esac
done
pwf="$STUB_DIR/$host.pw"; [ -f "$pwf" ] || { echo "ssh: connect to host $host: Connection timed out" >&2; exit 255; }
[ "$SSHPASS" = "$(cat "$pwf")" ] || { echo "Permission denied" >&2; exit 255; }
if [ -n "$cmd" ]; then printf '%s\n' "$cmd" | tr ';' '\n'; else cat; fi | while IFS= read -r l; do
    printf '%s\n' "$l" >>"$STUB_DIR/$host.log"
    [ "$l" = commit ] && echo "Configuration committed successfully"
    [ -f "$STUB_DIR/$host.refuse" ] && case "$l" in *bt-in-block*) echo "$(cat "$STUB_DIR/$host.refuse")" ;; esac
    if [ -f "$STUB_DIR/$host.break" ]; then
        case "$l" in
            *bt-in-block*|*"access-group BT-IN in"*|*"bt-fw-in"*) grep -v '^10.0.0.5 80$' "$STUB_DIR/up" >"$STUB_DIR/up.n"; cat "$STUB_DIR/up.n" >"$STUB_DIR/up" ;;
        esac
        case "$l" in
            "delete rulebase security rules bt-in-block"|*'remove [find comment~"^bt-"]'*|*"delete table inet bt_fw"*|"no access-group BT-IN"*|"access-group OUTSIDE_IN in"*) cp "$STUB_DIR/up.orig" "$STUB_DIR/up" ;;
        esac
    fi
done
cat "$STUB_DIR/$host.out"
exit 0
STUB
cat >"$B/nc" <<'STUB'
#!/bin/sh
# nc -z -w 3 ADDR PORT
[ "$1" = -h ] && { echo "usage: nc [-46z] ..."; exit 0; }
eval "a=\${$(($# - 1))}"; eval "p=\${$#}"
grep -qx "$a $p" "$STUB_DIR/up"
STUB
cat >"$B/ping" <<'STUB'
#!/bin/sh
eval "a=\${$#}"
grep -qx "$a ping" "$STUB_DIR/up"
STUB
printf '#!/bin/sh\n[ "$1" = -e ] || exit 9\nshift\nexec "$@"\n' >"$B/sshpass"
chmod +x "$B"/*
BT_SSH="$B/ssh"; BT_SSHPASS="$B/sshpass"; BT_NET_PASS='Dev-Pass-1'; export BT_SSH BT_SSHPASS BT_NET_PASS
PATH="$B:$PATH"; export PATH

devices() {
    rm -f "$D"/*.log "$D"/*.break "$D"/*.refuse
    for h in pan asa fg mt lnx; do printf '%s\n' "$BT_NET_PASS" >"$D/$h.pw"; done
    printf '10.0.0.5 ping\n10.0.0.5 80\n10.0.0.5 443\n10.0.0.9 ping\n10.0.0.9 25\n' >"$D/up"; cp "$D/up" "$D/up.orig"
    cat >"$D/pan.out" <<'EOF'
admin@PA# show zone
set zone untrust network layer3 ethernet1/1
set zone trust network layer3 ethernet1/2
admin@PA# show rulebase security
set rulebase security rules allow-all from any
set rulebase security rules allow-all to any
set rulebase security rules allow-all source any
set rulebase security rules allow-all destination any
set rulebase security rules allow-all application any
set rulebase security rules allow-all service any
set rulebase security rules allow-all action allow
EOF
    cat >"$D/asa.out" <<'EOF'
interface GigabitEthernet0/0
 nameif outside
 security-level 0
interface GigabitEthernet0/1
 nameif inside
 security-level 100
access-group OUTSIDE_IN in interface outside
access-list OUTSIDE_IN extended permit ip any any
EOF
    cat >"$D/fg.out" <<'EOF'
config system interface
    edit "wan1"
        set ip 203.0.113.2 255.255.255.0
    next
    edit "internal"
        set ip 10.0.0.1 255.255.255.0
    next
end
config firewall policy
    edit 1
        set srcintf "internal"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "ALL"
    next
end
EOF
    cat >"$D/mt.out" <<'EOF'
===if
 0  R name=ether1 type=ether mtu=1500
 1  R name=ether2 type=ether mtu=1500
===filter
 0    chain=input action=accept connection-state=established,related
 1    chain=forward action=accept
EOF
    cat >"$D/lnx.out" <<'EOF'
===if
1: lo: <LOOPBACK,UP> mtu 65536 qdisc noqueue state UNKNOWN
2: eth0: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc fq_codel state UP
3: eth1: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc fq_codel state UP
===nft
EOF
}
DEVS="--device p1,pan,paloalto --device a1,asa,cisco-asa --device f1,fg,fortigate --device m1,mt,mikrotik --device l1,lnx,linux --device pf1,pfx,pfsense --device v1,vy,vyos"
ALLOW="--allow 10.0.0.5:80,443 --allow 10.0.0.9:25,53/udp --team 10.0.0.0/24 --wait 1 --commit-wait 1"
# shellcheck disable=SC2086
run() { $SH "$C" --out "$O" --no-color $ALLOW "$@"; }
# newest -> the newest run folder (by its number: ls puts -10 before -9)
newest() { for _f in "$O"/firewall-ruleset-*; do printf '%s %s\n' "${_f##*-}" "$_f"; done | sort -n | tail -n 1 | cut -d' ' -f2-; }

t_start "options"
$SH "$C" --device p1,pan,paloalto --team moon >/dev/null 2>&1; t_eq "$?" 2 "a bad --team exits 2"
$SH "$C" >/dev/null 2>&1; t_eq "$?" 2 "no firewall exits 2"
$SH "$C" --device p1,pan,paloalto,admin,22x >/dev/null 2>&1; t_eq "$?" 2 "a port that is not a number exits 2"
out=$($SH "$C" --out "$O" --device p1,pan,paloalto --batch 2>&1); t_eq "$?" 2 "no scored boxes exits 2"
t_has "$out" "No scored boxes" "and says why"
out=$($SH "$C" --help 2>&1); t_has "$out" "--remove" "--help"

t_start "plan (dry run, defaults)"
devices
# shellcheck disable=SC2086
out=$(run $DEVS --batch 2>&1)
_rd=$(newest)
t_has "$out" "Is this list of scored boxes and ports right?" "the list is shown and asked about"
t_has "$out" "Limit what the scored servers can START out through the firewall? [y/N] n (default)" "outgoing limits: default no"
t_has "$out" "threat prevention" "threat prevention asked"
t_has "$out" "ALLOW any -> 10.0.0.5 tcp 80,443" "a rule per scored box"
t_has "$out" "BLOCK + LOG every other connection coming IN" "the block rule"
t_has "$out" "[K/s] k (default)" "each rule: default keep"
t_has "$out" "which zone is OUTSIDE" "Palo Alto: the zone is asked"
t_has "$out" "existing rule \"allow-all\" allows anything to anything" "Palo Alto: any-any rule seen"
t_has "$out" "access list OUTSIDE_IN now: BT-IN takes its place" "ASA: the old access list is named"
t_has "$out" "existing policy 1 allows all to all" "FortiGate: any-any policy seen"
t_has "$out" "pf1 (pfx, pfsense)" "pfSense listed"
t_has "$out" "vyos is not built in NW-20 yet" "VyOS: plan only"
t_has "$out" "Dry run: nothing was changed" "dry run"
t_fail "a dry run sends no change" sh -c "grep -q 'rulebase security rules bt-' '$D/pan.log'"
t_file "$_rd/plan.txt" "plan.txt"; t_file "$_rd/scored.txt" "scored.txt"
t_fail "no CSV files are left in the run" sh -c "find '$_rd' -name '*.csv' | grep -q ."
P="$_rd/commands-p1.txt"; A="$_rd/commands-a1.txt"; F="$_rd/commands-f1.txt"; M="$_rd/commands-m1.txt"; L="$_rd/commands-l1.txt"
t_ok "PAN: service object" grep -qx 'set service bt-in-10.0.0.5-t protocol tcp port 80,443' "$P"
t_ok "PAN: scored rule" grep -q '^set rulebase security rules bt-in-10.0.0.5 from untrust to trust source any destination \[ 10.0.0.5/32 \] application any service \[ bt-in-10.0.0.5-t \] action allow' "$P"
t_ok "PAN: block rule" grep -qx 'set rulebase security rules bt-in-block from untrust to trust source any destination any application any service any action deny log-end yes' "$P"
t_ok "PAN: moved to the top" grep -qx 'move rulebase security rules bt-team top' "$P"
t_eq "$(grep 'top$' "$P" | tail -n 1)" "move rulebase security rules bt-team top" "PAN: bt-team ends up first"
t_ok "ASA: team" grep -qx 'access-list BT-IN extended permit ip 10.0.0.0 255.255.255.0 any' "$A"
t_ok "ASA: scored ports" grep -qx 'access-list BT-IN extended permit tcp any host 10.0.0.5 eq 443' "$A"
t_ok "ASA: udp" grep -qx 'access-list BT-IN extended permit udp any host 10.0.0.9 eq 53' "$A"
t_ok "ASA: ping" grep -qx 'access-list BT-IN extended permit icmp any host 10.0.0.5 echo' "$A"
t_ok "ASA: block last" sh -c "grep '^access-list BT-IN' '$A' | tail -n 1 | grep -qx 'access-list BT-IN extended deny ip any any log'"
t_ok "ASA: bound to outside" grep -qx 'access-group BT-IN in interface outside' "$A"
t_ok "FortiGate: address object" grep -qx 'edit "bt-a-10.0.0.5"' "$F"
t_ok "FortiGate: service" grep -qx 'set tcp-portrange 80 443' "$F"
t_ok "FortiGate: deny policy" grep -qx 'set action deny' "$F"
t_ok "FortiGate: moved before policy 1" grep -qx 'move 9101 before 1' "$F"
t_eq "$(grep -c '^edit "bt-a-10.0.0.5"$' "$F")" 1 "FortiGate: an address object made once"
t_ok "MikroTik: an earlier run's rules out first" sh -c "head -n 1 '$M' | grep -qF '/ip firewall filter remove [find comment~\"^bt-\"]'"
t_ok "MikroTik: scored" grep -q 'in-interface=ether1 dst-address=10.0.0.5 protocol=tcp dst-port=80,443 action=accept comment=bt-in-10.0.0.5 place-before=0' "$M"
t_ok "MikroTik: on top, established first" sh -c "tail -n 1 '$M' | grep -q 'comment=bt-established'"
t_ok "Linux: its own table" grep -q 'table inet bt_fw {' "$L"
t_ok "Linux: scored" grep -q 'iifname "eth0" ip daddr 10.0.0.5 tcp dport { 80, 443 } accept' "$L"
if command -v nft >/dev/null 2>&1 && nft list ruleset >/dev/null 2>&1; then
    sed -n "/^table inet bt_fw\$/,/^BTNFT\$/p" "$L" | sed '$d' >"$T_TMP/r.nft"
    t_ok "Linux: the real nft accepts the ruleset" nft -c -f "$T_TMP/r.nft"
fi
t_ok "pfSense: GUI steps in plan.txt" grep -q 'pf1 (pfsense): web GUI' "$_rd/plan.txt"

t_start "--apply --batch"
devices
# shellcheck disable=SC2086
out=$(run $DEVS --batch --no-protected --apply 2>&1)
t_has "$out" "before: 10.0.0.5 80 up" "checked before"
for d in p1 a1 f1 m1 l1; do t_has "$out" "[+] $d: rules on, scored services still answer" "$d: kept"; done
t_ok "PAN: committed" grep -qx 'commit' "$D/pan.log"
t_ok "ASA: saved" grep -qx 'write memory' "$D/asa.log"
t_ok "MikroTik: one line, joined" grep -q '^/ip firewall filter add chain=forward' "$D/mt.log"
t_ok "Linux: nft run" grep -q 'nft -f /tmp/bt_fw.nft' "$D/lnx.log"
t_file "$O/nw20-p1.undo" "the --remove record is kept in --out"
_rd=$(newest)
t_file "$_rd/checks.txt" "checks.txt"

t_start "a scored service stops answering: put back at once"
devices; : >"$D/pan.break"
out=$(run --device p1,pan,paloalto --batch --no-protected --apply 2>&1)
t_has "$out" "[x] p1: these stopped answering: 10.0.0.5:80" "the broken service is seen"
t_has "$out" "[+] p1: put back; the scored services answer as before" "put back and checked again"
t_ok "the bt- rules were deleted" grep -qx 'delete rulebase security rules bt-in-block' "$D/pan.log"
t_fail "nothing to --remove for it" test -f "$O/nw20-p1.undo"

t_start "undo script and --remove"
devices
out=$(run --device l1,lnx,linux --device m1,mt,mikrotik --batch --no-protected --apply 2>&1)
_rd=$(newest)
sh "$_rd/undo/l1.sh" >/dev/null 2>&1
t_ok "the undo script takes the Linux table out" grep -q 'nft delete table inet bt_fw' "$D/lnx.log"
t_fail "and clears its --remove record" test -f "$O/nw20-l1.undo"
out=$($SH "$C" --out "$O" --no-color --device m1,mt,mikrotik --remove 2>&1)
t_has "$out" "Dry run: run again with --apply" "--remove is a dry run first"
out=$($SH "$C" --out "$O" --no-color --device m1,mt,mikrotik --remove --batch --no-protected --apply 2>&1)
t_has "$out" "[+] m1: rules taken out" "--remove --apply"
t_eq "$(grep -c 'remove \[find comment~"^bt-"\]' "$D/mt.log")" 2 "MikroTik: the remove was sent (after the one at apply)"

t_start "outgoing limits and threat prevention"
devices
printf '# scored boxes\n10.0.0.5  80 443   # webmail\n10.0.0.9  25 53/udp\n' >"$T_TMP/scored.txt"
out=$($SH "$C" --out "$O" --no-color --file "$T_TMP/scored.txt" --team 10.0.0.0/24 --restrict-out --dns 10.0.0.53 --ntp 10.0.0.20 --out-allow 10.0.1.9:1433 --threat \
      --device p1,pan,paloalto --device a1,asa,cisco-asa --device m1,mt,mikrotik --device l1,lnx,linux --device f1,fg,fortigate --batch 2>&1)
_rd=$(newest)
t_has "$out" "ALLOW any -> 10.0.0.5 tcp 80,443 (webmail)" "--file: ports and the note"
t_has "$out" "ALLOW the scored servers -> 10.0.0.53 tcp 53 udp 53 (DNS)" "DNS out"
t_has "$out" "ALLOW the scored servers -> 10.0.1.9 tcp 1433 (you listed it)" "a listed destination out"
t_has "$out" "BLOCK + LOG anything else the scored servers START out" "the outgoing block"
t_ok "PAN: threat profiles on the scored rules" grep -q 'bt-in-10.0.0.5 .*profile-setting profiles virus default spyware default vulnerability default' "$_rd/commands-p1.txt"
t_ok "PAN: outgoing block" grep -q '^set rulebase security rules bt-out-block from trust to untrust source \[ 10.0.0.5/32 10.0.0.9/32 \] destination any application any service any action deny' "$_rd/commands-p1.txt"
t_ok "ASA: BT-OUT on the inside interface" grep -qx 'access-group BT-OUT in interface inside' "$_rd/commands-a1.txt"
t_ok "ASA: servers may answer pings" grep -qx 'access-list BT-OUT extended permit icmp host 10.0.0.5 any echo-reply' "$_rd/commands-a1.txt"
t_ok "ASA: everyone else still goes out" sh -c "grep '^access-list BT-OUT' '$_rd/commands-a1.txt' | tail -n 1 | grep -qx 'access-list BT-OUT extended permit ip any any'"
t_ok "MikroTik: outgoing block" grep -q 'out-interface=ether1 src-address=10.0.0.5 action=drop log=yes' "$_rd/commands-m1.txt"
t_ok "FortiGate: IPS on the scored rules" grep -qx 'set ips-sensor "default"' "$_rd/commands-f1.txt"
t_ok "FortiGate: NAT on what goes out" grep -qx 'set nat enable' "$_rd/commands-f1.txt"
t_ok "Linux: outgoing block" grep -q 'oifname "eth0" ip saddr { 10.0.0.5, 10.0.0.9 } limit rate 10/minute log prefix "bt-fw-out "' "$_rd/commands-l1.txt"
if command -v nft >/dev/null 2>&1 && nft list ruleset >/dev/null 2>&1; then
    sed -n "/^table inet bt_fw\$/,/^BTNFT\$/p" "$_rd/commands-l1.txt" | sed '$d' >"$T_TMP/r2.nft"
    t_ok "Linux: the real nft accepts the ruleset with outgoing limits" nft -c -f "$T_TMP/r2.nft"
fi

t_start "NAT: Palo Alto and FortiGate match the outside address"
devices
cat >>"$D/pan.out" <<'EOF'
admin@PA# show address
set address web-pub ip-netmask 172.25.20.5
set address web-in ip-netmask 10.0.0.5/32
admin@PA# show rulebase nat
set rulebase nat rules web-in to untrust
set rulebase nat rules web-in destination [ web-pub 172.25.20.55 ]
set rulebase nat rules web-in destination-translation translated-address web-in
set rulebase nat rules mail source 10.0.0.9
set rulebase nat rules mail source-translation static-ip translated-address 172.25.20.9
set rulebase nat rules mail source-translation static-ip bi-directional yes
set rulebase nat rules outbound source any
set rulebase nat rules "dns in" destination "dns pub"
set rulebase nat rules "dns in" destination-translation translated-address 10.0.0.9
set rulebase nat rules outbound source-translation dynamic-ip-and-port interface-address interface ethernet1/1
EOF
sed '/^config firewall policy$/,$d' "$D/fg.out" >"$D/fg.n"
cat >>"$D/fg.n" <<'EOF'
config firewall vip
    edit "web-vip"
        set extip 203.0.113.5
        set extintf "wan1"
        set mappedip "10.0.0.5-10.0.0.5"
    next
end
EOF
sed -n '/^config firewall policy$/,$p' "$D/fg.out" >>"$D/fg.n"; cat "$D/fg.n" >"$D/fg.out"
out=$(run --device p1,pan,paloalto --device f1,fg,fortigate --batch 2>&1)
_rd=$(newest)
t_has "$out" "NAT: outside name web-pub leads to 10.0.0.5" "PAN: destination NAT found (by object name)"
t_has "$out" "NAT: outside name 172.25.20.9 leads to 10.0.0.9" "PAN: bi-directional static NAT found"
t_has "$out" "NAT to 10.0.0.9 uses a name with spaces: not added" "PAN: a name with spaces is reported, not used"
t_ok "PAN: scored rule has the outside names" grep -q '^set rulebase security rules bt-in-10.0.0.5 .*destination \[ 10.0.0.5/32 172.25.20.55 web-pub \]' "$_rd/commands-p1.txt"
t_ok "PAN: ping rule has them too" grep -q '^set rulebase security rules bt-ping .*destination \[ 10.0.0.5/32 10.0.0.9/32 172.25.20.55 web-pub 172.25.20.9 \]' "$_rd/commands-p1.txt"
t_fail "PAN: the block rule stays any" grep -q 'bt-in-block .*web-pub' "$_rd/commands-p1.txt"
t_has "$out" "NAT: outside name web-vip leads to 10.0.0.5" "FortiGate: VIP found"
t_ok "FortiGate: the scored policy names the VIP" grep -qx 'set dstaddr "bt-a-10.0.0.5" "web-vip"' "$_rd/commands-f1.txt"
t_ok "plan.txt lists the NAT names" grep -q 'web-vip -> 10.0.0.5' "$_rd/plan.txt"
out=$(run --device a1,asa,cisco-asa --batch 2>&1)
t_hasnt "$out" "NAT:" "ASA: inside addresses, no NAT names"
t_ok "FortiGate: one space between names" grep -qx 'set srcaddr "bt-a-10.0.0.0/24"' "$_rd/commands-f1.txt"

t_start "a second run"
devices
rm -f "$O"/nw20-*.undo
out=$(run --device a1,asa,cisco-asa --batch --no-protected --apply 2>&1)
# the ASA now has BT-IN bound; a second run must still put OUTSIDE_IN back on undo
sed 's/^access-group OUTSIDE_IN in interface outside$/access-group BT-IN in interface outside/' "$D/asa.out" >"$D/asa.n"; cat "$D/asa.n" >"$D/asa.out"
out=$(run --device a1,asa,cisco-asa --batch --no-protected --apply 2>&1)
t_ok "ASA: the undo of a second run puts the ORIGINAL list back" grep -qx 'access-group OUTSIDE_IN in interface outside' "$O/nw20-a1.undo"
# FortiGate with our policies already on top: new ones still go before the first one that is not ours
sed '/^config firewall policy$/,$d' "$D/fg.out" >"$D/fg.n"
cat >>"$D/fg.n" <<'EOF'
config firewall policy
    edit 9101
        set name "bt-team"
    next
    edit 1
        set action accept
    next
end
EOF
cat "$D/fg.n" >"$D/fg.out"
out=$(run --device f1,fg,fortigate --batch 2>&1)
_rd=$(newest)
t_ok "FortiGate: moved before the first policy that is not ours" grep -qx 'move 9101 before 1' "$_rd/commands-f1.txt"

t_ok "FortiGate: the earlier run's policies are deleted first" grep -qx 'delete 9101' "$_rd/commands-f1.txt"
t_ok "FortiGate: team policy only from outside (no outgoing policy without NAT)" sh -c "sed -n '/set name \"bt-team\"/,/^next/p' '$_rd/commands-f1.txt' | grep -qx 'set srcintf \"wan1\"'"
# Palo Alto with bt- rules from an earlier run: deleted first ("set" would add to them)
devices
printf 'set rulebase security rules bt-out-block from trust\nset rulebase security rules bt-out-block action deny\n' >>"$D/pan.out"
out=$(run --device p1,pan,paloalto --batch 2>&1)
_rd=$(newest)
t_eq "$(grep -c '^delete rulebase security rules bt-out-block$' "$_rd/commands-p1.txt")" 1 "PAN: an earlier run's rule is deleted once, before the new ones"
t_eq "$(head -n 1 "$_rd/commands-p1.txt")" "delete rulebase security rules bt-out-block" "PAN: and first"

t_start "the firewall refuses a command: put back"
devices; echo "Invalid syntax." >"$D/pan.refuse"
out=$(run --device p1,pan,paloalto --batch --no-protected --apply 2>&1)
t_has "$out" "[x] p1: the firewall refused a command: Invalid syntax." "the refusal is seen"
t_has "$out" "[+] p1: put back" "and put back"
t_fail "no --remove record left" test -f "$O/nw20-p1.undo"
devices
printf '===if\n2: eth0: <UP>\n3: eth1: <UP>\n===nft\n' >"$D/lnx.out"
cp "$B/ssh" "$B/ssh.bak"; sed 's|^cat "\$STUB_DIR/\$host.out"$|cat "$STUB_DIR/$host.out"; [ -f "$STUB_DIR/$host.fail" ] \&\& case "$cmd" in *bt_fw.nft*) echo "Error: syntax error"; exit 1 ;; esac|' "$B/ssh.bak" >"$B/ssh"
: >"$D/lnx.fail"
out=$(run --device l1,lnx,linux --batch --no-protected --apply 2>&1)
t_has "$out" "[x] l1: the commands did not go through" "Linux: nft failing is seen (its exit status is kept)"
rm -f "$D/lnx.fail"; mv "$B/ssh.bak" "$B/ssh"
t_ok "Linux: the remote command keeps nft's exit status" grep -q '_r=$?; rm -f /tmp/bt_fw.nft; exit $_r' "$(newest)/commands-l1.txt"

t_start "stopped while a firewall is being changed: put back"
devices
$SH "$C" --out "$O" --no-color $ALLOW --wait 20 --device l1,lnx,linux --batch --no-protected --apply >"$T_TMP/stop.out" 2>&1 &
_bg=$!
_i=0; while [ "$_i" -lt 50 ] && ! grep -q 'bt_fw.nft' "$D/lnx.log" 2>/dev/null; do sleep 0.2; _i=$((_i + 1)); done
sleep 1; kill -TERM "$_bg" 2>/dev/null; wait "$_bg" 2>/dev/null
t_has "$(cat "$T_TMP/stop.out")" "stopped while l1 was being changed - putting it back" "the stop is seen"
t_ok "the rules were taken out" grep -q 'nft delete table inet bt_fw' "$D/lnx.log"
t_fail "no --remove record left" test -f "$O/nw20-l1.undo"

t_start "lists are checked and merged"
devices
out=$(run --allow 10.0.0.5:70000,80,80,9-3 --device l1,lnx,linux --restrict-out --dns 10.0.0.20 --ntp 10.0.0.20 --out-allow 10.0.1.9:8000-8100 --batch 2>&1)
_rd=$(newest)
t_has "$out" "not a port (1-65535), skipped: 70000" "a port over 65535 is refused"
t_has "$out" "not a port (1-65535), skipped: 9-3" "a backwards range is refused"
t_has "$out" "ALLOW any -> 10.0.0.5 tcp 80,443" "ports given twice appear once"
t_has "$out" "ALLOW the scored servers -> 10.0.0.20 tcp 53 udp 53,123 (DNS, NTP)" "DNS and NTP on one box: one rule"
t_eq "$(grep -c 'comment "bt-out-10.0.0.20"' "$_rd/commands-l1.txt")" 2 "Linux: one tcp and one udp line for it"
out=$(run --device a1,asa,cisco-asa --restrict-out --dns 10.0.0.20 --out-allow 10.0.1.9:8000-8100 --batch 2>&1)
_rd=$(newest)
t_ok "ASA: a range going out" grep -qx 'access-list BT-OUT extended permit tcp host 10.0.0.5 host 10.0.1.9 range 8000 8100' "$_rd/commands-a1.txt"
t_ok "ASA: the servers still reach the team" grep -qx 'access-list BT-OUT extended permit ip host 10.0.0.5 10.0.0.0 255.255.255.0' "$_rd/commands-a1.txt"
printf 'set zone zone-a network layer3 ethernet1/1\nset zone zone-b network layer3 ethernet1/2\n' >"$D/pan.out"
out=$(run --device p1,pan,paloalto --batch 2>&1)
t_has "$out" "no name looks right" "no terminal and no name that looks right: not guessed"
t_has "$out" "p1: not built" "and the firewall is skipped"
out=$(run --device p1,pan,paloalto --outside zone-a --inside all --batch 2>&1)
t_ok "PAN: --inside all" grep -q '^set rulebase security rules bt-in-block from zone-a to \[ zone-b \] ' "$(newest)/commands-p1.txt"

t_start "nothing answers from here: stop"
devices; : >"$D/up"
out=$(run --device l1,lnx,linux --batch --no-protected --apply 2>&1)
t_has "$out" "NOTHING answered from this box before the change" "warned"
t_has "$out" "Stopped: nothing was changed" "--batch stops (default no)"
t_fail "nothing was sent" grep -q 'bt_fw.nft' "$D/lnx.log"

t_start "the ports offered from an SH-03 scan"
if command -v script >/dev/null 2>&1; then
    devices
    mkdir -p "$O/netscan-1/csv"
    printf 'ip,hostname,proto,port,state,service,version\n"10.0.0.5","web","tcp","80","open","http",""\n"10.0.0.5","web","tcp","6667","open","irc",""\n' >"$O/netscan-1/csv/ports.csv"
    # 80: Enter (keep), 6667: Enter (block); then: list right, outgoing, threat, rules..., outside: Enters; put on: n
    printf '\n\n\n\n\n\n\n\n\n\nn\n' >"$T_TMP/ans"
    tt=$(BT_NO_TTY=0 script -qc "$SH '$C' --out '$O' --no-color --device l1,lnx,linux --team 10.0.0.0/24 --wait 1 --no-protected --apply" /dev/null <"$T_TMP/ans" 2>&1)
    t_has "$tt" "10.0.0.5 port 80 (http): reachable from outside?" "each scanned port is asked"
    t_has "$tt" "Answer [K/b]" "a scored-looking port defaults to keep"
    t_has "$tt" "Answer [k/B]" "an odd port defaults to block"
    t_has "$tt" "ALLOW any -> 10.0.0.5 tcp 80 (from the scan)" "only the kept port becomes a rule"
    t_hasnt "$tt" "6667 (from" "the blocked one is not allowed"
    rm -rf "$O/netscan-1"
fi

t_start "questions on a terminal"
if command -v script >/dev/null 2>&1; then
    devices
    # list right, outgoing (no), threat (no), team, scored, ping, block rules (keep), outside, put on, keep? n
    printf '\n\n\n\n\n\n\n\n\nn\n' >"$T_TMP/ans"
    tt=$(BT_NO_TTY=0 script -qc "$SH '$C' --out '$O' --no-color --device l1,lnx,linux --allow 10.0.0.5:80 --team 10.0.0.0/24 --wait 1 --no-protected --apply --timer 30" /dev/null <"$T_TMP/ans" 2>&1)
    t_has "$tt" "[k] keep this rule" "each rule lists its answers"
    t_has "$tt" "[1] eth0" "the interfaces are listed"
    t_has "$tt" "Now look at the SCOREBOARD" "asks to check the scoreboard"
    t_has "$tt" "[x] l1: not confirmed - putting it back" "n: put back"
    t_ok "n: the table was taken out" grep -q 'nft delete table inet bt_fw' "$D/lnx.log"
fi
t_done
