#!/bin/sh
# Tests for roles/network/NW-01-config-backup.sh.
# A stand-in ssh plays the devices: it answers with sample output in each
# vendor's style (prompts, echoed commands, timestamp lines), records the
# commands it was sent, and can act "down", "host key changed" or "old
# algorithms only".  Checks per-vendor commands and clean-up, that time-only
# changes are not reported, that a planted admin account is HIGH with its
# password masked, the failure cases, and that a password never reaches the
# log or a command line.
. "$(dirname "$0")/helper.sh"
SH=${TEST_SHELL:-sh}
C="$T_ROOT/roles/network/NW-01-config-backup.sh"
export BT_SKIP_VERIFY=1
# shellcheck disable=SC2086
run() { $SH "$C" "$@"; }
O="$T_TMP/out"; B="$T_TMP/bin"; D="$T_TMP/dev"; mkdir -p "$O" "$B" "$D"
STUB_DIR=$D; export STUB_DIR
cat >"$B/ssh" <<'STUB'
#!/bin/sh
# stand-in ssh: the device is the host part of the user@host argument
all="$*"; host=""; cmd=""; seen=0
for a in "$@"; do
    if [ "$seen" = 1 ]; then cmd=$a; fi
    case "$a" in *@*) host=${a#*@}; seen=1 ;; esac
done
echo "ARGS $all" >>"$STUB_DIR/$host.args"
case "$host" in
    down) echo "ssh: connect to host down port 22: Connection timed out" >&2; exit 255 ;;
    keychg) echo "@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@" >&2; echo "Host key verification failed." >&2; exit 255 ;;
    oldbox) case "$all" in *KexAlgorithms=+*) ;; *) echo "Unable to negotiate with oldbox port 22: no matching key exchange method found." >&2; exit 255 ;; esac ;;
esac
if [ -n "$cmd" ]; then echo "$cmd" >"$STUB_DIR/$host.cmds"; else cat >"$STUB_DIR/$host.cmds"; fi
cat "$STUB_DIR/$host.out"
STUB
printf '#!/bin/sh\n[ "$1" = -e ] || exit 9\nshift\necho "SSHPASS_SET=${SSHPASS:+yes}" >>"$STUB_DIR/sshpass.log"\nexec "$@"\n' >"$B/sshpass"
chmod +x "$B/ssh" "$B/sshpass"
BT_SSH="$B/ssh"; export BT_SSH
PATH="$B:$PATH"; export PATH

# cisco_cfg STAMP EXTRA -> a Cisco IOS session (prompts, echoed commands, timestamps)
cisco_cfg() { cat <<CFG
r1#terminal length 0
r1#show running-config
Building configuration...

Current configuration : 1$1 bytes
!
! Last configuration change at 10:0$1:00 UTC Wed Nov 11 2026 by admin
!
version 15.2
hostname r1
enable secret 9 \$9\$abcdef
username admin privilege 15 secret 9 \$9\$xyz
$2
snmp-server community s3cr3tRO RO
line vty 0 4
 transport input ssh
end
r1#exit
CFG
}
cisco_cfg 1 "" >"$D/10.0.0.1.out"
cat >"$D/10.0.0.2.out" <<'CFG'
admin@fw1> set cli pager off
admin@fw1> show config running
config {
  mgt-config {
    users {
      admin {
        phash $1$panhash;
      }
    }
  }
}
admin@fw1> exit
CFG
cat >"$D/10.0.0.3.out" <<'CFG'
asa1# terminal pager 0
asa1# show running-config
: Saved
: Serial Number: JAD123
: Hardware:   ASA5506
ASA Version 9.8(4)
hostname asa1
telnet 0.0.0.0 0.0.0.0 inside
Cryptochecksum:0a1b2c
: end
asa1# exit
CFG
printf '#config-version=FGT60F-7.2.5\n#conf_file_ver=111\nconfig system global\n    set hostname "fg1"\nend\nconfig system admin\n    edit "admin"\n        set password ENC SH2aaaa\n    next\nend\n' >"$D/10.0.0.4.out"
printf "set system host-name 'vyos1'\nset service ssh port '22'\nset system login user vyos authentication encrypted-password 'x'\n" >"$D/10.0.0.5.out"
printf '<?xml version="1.0"?>\n<pfsense>\n<system><hostname>pf1</hostname>\n<user><name>admin</name><bcrypt-hash>$2y$abc</bcrypt-hash></user>\n</system>\n<snmpd><rocommunity>public</rocommunity></snmpd>\n</pfsense>\n' >"$D/10.0.0.6.out"
printf 'hostname old\nline1\nline2\nline3\n' >"$D/oldbox.out"
cat >"$T_TMP/hosts.txt" <<'H'
# name   ip          os         role       connect port user  scored  notes
r1       10.0.0.1    network    core       ssh     22   admin  -       Cisco IOS router
fw1      10.0.0.2    network    perimeter  ssh     22   admin  -       Palo Alto PA-220
asa1     10.0.0.3    cisco-asa  firewall   ssh     22   admin  -       -
fg1      10.0.0.4    network    branch     ssh     22   admin  -       FortiGate 60F
vyos1    10.0.0.5    network    edge       ssh     22   vyos   -       VyOS
pf1      10.0.0.6    network    lab        ssh     22   root   -       pfSense CE
mystery  10.0.0.9    network    ???        ssh     22   admin  -       unknown box
web01    10.0.0.20   linux      web        ssh     22   root   http:80 -
H
# the same list in the older CSV form
cat >"$T_TMP/hosts.csv" <<'H'
host,ip,os,role,connect,port,user,scored_services,notes
r1,10.0.0.1,network,core router,ssh,22,admin,,Cisco IOS router
fw1,10.0.0.2,network,perimeter,ssh,22,admin,,Palo Alto PA-220
asa1,10.0.0.3,cisco-asa,firewall,ssh,22,admin,,
fg1,10.0.0.4,network,branch,ssh,22,admin,,FortiGate 60F
vyos1,10.0.0.5,network,edge,ssh,22,vyos,,VyOS
pf1,10.0.0.6,network,lab,ssh,22,root,,pfSense CE
mystery,10.0.0.9,network,???,ssh,22,admin,,unknown box
web01,10.0.0.20,linux,web,ssh,22,root,http:80,
H

t_start "options"
run >/dev/null 2>&1; t_eq "$?" 2 "no devices given exits 2"
run --device x,1.2.3.4,junos >/dev/null 2>&1; t_eq "$?" 2 "unknown vendor exits 2"
run --device 'bad/name,1.2.3.4,vyos' >/dev/null 2>&1; t_eq "$?" 2 "unsafe device name exits 2"
run --device 'r9,1.2.3.4,vyos,admin,22x' >/dev/null 2>&1; t_eq "$?" 2 "a port that is not a number exits 2"

t_start "first backup of six vendors"
out=$(run --out "$O" --hosts "$T_TMP/hosts.txt" 2>&1); rc=$?
t_eq "$rc" 0 "exit 0"
for d in r1 fw1 asa1 fg1 vyos1 pf1; do t_has "$out" "$d" "$d in the summary"; done
t_has "$out" "mystery: os is network but the vendor is unknown" "device with an unknown vendor skipped with a warning"
t_hasnt "$out" "web01" "non-network host ignored"
t_has "$(cat "$D/10.0.0.1.cmds")" "terminal length 0" "Cisco IOS got terminal length 0"
t_has "$(cat "$D/10.0.0.2.cmds")" "set cli pager off" "Palo Alto got set cli pager off"
t_has "$(cat "$D/10.0.0.3.cmds")" "terminal pager 0" "ASA got terminal pager 0"
t_has "$(cat "$D/10.0.0.5.cmds")" "show configuration commands" "VyOS got show configuration commands"
t_has "$(cat "$D/10.0.0.6.cmds")" "cat /conf/config.xml" "pfSense got cat /conf/config.xml"
n=$(cat "$O/net-configs/r1/$(cat "$O/net-configs/r1/latest").norm")
t_hasnt "$n" "Last configuration change" "Cisco timestamp line removed"
t_hasnt "$n" "r1#" "prompt lines removed"
t_has "$n" "hostname r1" "config kept"
t_eq "$(ls -l "$O/net-configs/r1/$(cat "$O/net-configs/r1/latest").cfg" | cut -c1-10)" "-rw-------" "saved config is mode 600"
t_hasnt "$(cat "$O/net-configs/asa1/$(cat "$O/net-configs/asa1/latest").norm")" "Cryptochecksum" "ASA checksum line removed"

t_start "time-only changes are not reported"
cisco_cfg 2 "" >"$D/10.0.0.1.out"
# FortiGate shows its encrypted secrets differently on every read
sed 's/conf_file_ver=111/conf_file_ver=222/; s/ENC SH2aaaa/ENC SH2bbbb/' "$D/10.0.0.4.out" >"$D/fg.t" && mv "$D/fg.t" "$D/10.0.0.4.out"
out=$(run --out "$O" --hosts "$T_TMP/hosts.txt" 2>&1)
d=$(printf '%s\n' "$out" | sed -n 's/^All results: //p')
t_hasnt "$(cat "$d/devices.txt")" '| changed' "no device reported as changed"
t_has "$(cat "$d/devices.txt")" '| no change' "devices compared"
t_fail "no CSV files in the run" sh -c "ls '$d' | grep -q csv"

t_start "a planted admin account"
cisco_cfg 3 "username backdoor privilege 15 password 0 Hunter2Pass" >"$D/10.0.0.1.out"
out=$(run --out "$O" --hosts "$T_TMP/hosts.txt" 2>&1)
d=$(printf '%s\n' "$out" | sed -n 's/^All results: //p')
t_has "$out" "[r1] config line: added: username backdoor privilege 15 password 0 ****" "HIGH flag with the password masked"
t_hasnt "$out" "Hunter2Pass" "password not on screen"
t_file "$d/flags.txt" "flags.txt written"
t_has "$(cat "$d/flags.txt")" "HIGH" "the flag is in flags.txt"
t_hasnt "$(cat "$d/flags.txt")" "Hunter2Pass" "password not in flags.txt"
out=$(run --out "$O" --hosts "$T_TMP/hosts.csv" 2>&1)
t_has "$out" "pf1" "an older CSV host list is still read"
t_file "$d/r1.diff" "diff saved"

t_start "failures"
out=$(run --out "$O" --device dead,down,linux --device moved,keychg,linux 2>&1); rc=$?
t_eq "$rc" 5 "exit 5 when a device fails"
t_has "$out" "backup FAILED: ssh: connect to host down port 22: Connection timed out" "unreachable device reported"
t_has "$out" "SSH host key CHANGED" "changed host key is HIGH"
out=$(run --out "$O" --device old,oldbox,linux 2>&1); rc=$?
t_eq "$rc" 0 "old-algorithm device works on the retry"
t_has "$out" "old SSH algorithms" "summary says old algorithms were used"

t_start "password logins"
BT_NET_PASS='TopSecret-99'; export BT_NET_PASS
out=$(run --out "$O" --device vyos1,10.0.0.5,vyos --password-env 2>&1); rc=$?
t_eq "$rc" 0 "exit 0"
t_has "$(cat "$D/sshpass.log")" "SSHPASS_SET=yes" "password handed over in the environment"
t_hasnt "$(cat "$D/10.0.0.5.args")" "TopSecret-99" "password never on a command line"
t_fail "password never in a log" grep -rq "TopSecret-99" "$O"
t_done
