#!/bin/sh
# Tests for roles/network/NW-10-device-passwords.sh.
# A stand-in device: the stand-in ssh checks the password (from sshpass's
# SSHPASS) against a state file, then reads the session's commands line by
# line and applies each vendor's password command to that state.  A device
# in "ignore" mode accepts the commands but changes nothing, so the new
# password fails and the script must put the old one back.
. "$(dirname "$0")/helper.sh"
SH=${TEST_SHELL:-sh}
C="$T_ROOT/roles/network/NW-10-device-passwords.sh"
export BT_SKIP_VERIFY=1
# shellcheck disable=SC2086
run() { $SH "$C" "$@"; }
O="$T_TMP/out"; B="$T_TMP/bin"; D="$T_TMP/dev"; mkdir -p "$O" "$B" "$D"
STUB_DIR=$D; export STUB_DIR
cat >"$B/ssh" <<'STUB'
#!/bin/sh
host=""; cmd=""; seen=0; cfg=""; nextf=0
for a in "$@"; do
    if [ "$nextf" = 1 ]; then cfg=$a; nextf=0; continue; fi
    [ "$a" = -F ] && { nextf=1; continue; }
    if [ "$seen" = 1 ]; then cmd=$a; continue; fi; case "$a" in *@*) host=${a#*@}; seen=1 ;; esac
done
echo "ARGS $*" >>"$STUB_DIR/args.log"
# a command given in an ssh config file (RemoteCommand, %% for %)
[ -n "$cfg" ] && cmd=$(sed -n 's/^ *RemoteCommand //p' "$cfg" | sed 's/%%/%/g')
pwf="$STUB_DIR/$host.pw"; [ -f "$pwf" ] || { echo "ssh: connect to host $host: Connection timed out" >&2; exit 255; }
# a RouterOS job scheduled to put the old password back runs when it is due
sch="$STUB_DIR/$host.sched"
if [ -f "$sch" ] && [ "$(date +%s)" -ge "$(cut -d' ' -f2 "$sch")" ]; then cut -d' ' -f1 "$sch" >"$pwf"; rm -f "$sch"; fi
cur=$(cat "$pwf")
case "$cur" in
    phash:*) h=${cur#phash:}; salt=$(echo "$h" | cut -d'$' -f3); [ "$(openssl passwd -5 -salt "$salt" "$SSHPASS")" = "$h" ] || { echo "Permission denied" >&2; exit 255; } ;;
    *) [ "$SSHPASS" = "$cur" ] || { echo "Permission denied, please try again." >&2; exit 255; } ;;
esac
mode=$(cat "$STUB_DIR/$host.mode" 2>/dev/null)
# A command on the ssh line (RouterOS): no commands are read from stdin.
if [ -n "$cmd" ]; then
    printf '%s\n' "$cmd" >>"$STUB_DIR/$host.log"
    case "$cmd" in
        *'scheduler add name="bt-nw10-revert"'*)
            old=$(printf '%s' "$cmd" | sed 's/.*on-event="\/user set \[find name=\\"[^\\]*\\"\] password=\\"\([^\\]*\)\\".*/\1/')
            iv=$(printf '%s' "$cmd" | sed 's/.*interval=\([0-9]*\)s.*/\1/')
            echo "$old $(( $(date +%s) + iv ))" >"$sch"
            new=$(printf '%s' "$cmd" | sed 's/.*; \/user set \[find name="[^"]*"\] password="\([^"]*\)"$/\1/')
            case "$mode" in ignore) ;; garble) echo "garbled-$new" >"$pwf" ;; *) printf '%s\n' "$new" >"$pwf" ;; esac ;;
        *':put [:len'*) if [ -f "$sch" ]; then echo 1; else echo 0; fi ;;
        *'scheduler remove'*) [ "$mode" = keepjob ] || rm -f "$sch" ;;
        "/system identity print") echo "  name: $host" ;;
    esac
    exit 0
fi
prev=""
while IFS= read -r l; do
    echo "$l" >>"$STUB_DIR/$host.log"
    [ "$mode" = ignore ] && continue
    new=""
    case "$l" in
        "username "*" secret "*) new=${l##* secret }; p=$(echo "$l" | awk '{ print $4 }'); echo "$p" >"$STUB_DIR/$host.priv" ;;
        "username "*" password "*) new=$(echo "$l" | awk '{ print $4 }') ;;
        "set mgt-config users "*" phash "*) new="phash:${l##* phash }" ;;
        "set password "*) set -- $l; [ "$4" = "$(cat "$pwf")" ] && new=$3 ;;
        *plaintext-password*) new=$(echo "$l" | sed "s/.*plaintext-password '\(.*\)'/\1/") ;;
        "/user set "*) new=$(echo "$l" | sed 's/.*password="\(.*\)"/\1/') ;;
        *chpasswd*) new=$(printf '%s\n' "$l" | awk -F"'" '{ print $6 }') ;;
        *"| passwd "*) new=$(printf '%s\n' "$l" | awk -F"'" '{ print $4 }') ;;
        "enable secret "*) echo "${l#enable secret }" >"$STUB_DIR/$host.en" ;;
        "show privilege") [ "$prev" = en_ok ] && echo "Current privilege level is 15" || echo "Current privilege level is 1" ;;
    esac
    [ "$prev" = enable ] && { [ "$l" = "$(cat "$STUB_DIR/$host.en" 2>/dev/null)" ] && prev=en_ok || prev=en_bad; continue; }
    [ "$l" = enable ] && prev=enable
    [ -n "$new" ] && printf '%s\n' "$new" >"$pwf"
done
exit 0
STUB
printf '#!/bin/sh\n[ "$1" = -e ] || exit 9\nshift\nexec "$@"\n' >"$B/sshpass"
chmod +x "$B/ssh" "$B/sshpass"
BT_SSH="$B/ssh"; BT_SSHPASS="$B/sshpass"; export BT_SSH BT_SSHPASS
OLD='Old-Device-Pass1'
devices() {
    for h in ios asa pan fg vyos mt lnx bad; do printf '%s\n' "$OLD" >"$D/$h.pw"; rm -f "$D/$h.mode" "$D/$h.log" "$D/$h.priv" "$D/$h.en" "$D/$h.sched"; done
    echo ignore >"$D/bad.mode"
    # NW-01's store: the Cisco account's privilege level comes from here.
    mkdir -p "$O/net-configs/r1" "$O/net-configs/a1" "$O/net-configs/bad"
    printf 'username admin privilege 15 secret 9 $9$x\n' >"$O/net-configs/r1/T1.cfg"; echo T1 >"$O/net-configs/r1/latest"
    printf 'username admin password x encrypted privilege 15\n' >"$O/net-configs/a1/T1.cfg"; echo T1 >"$O/net-configs/a1/latest"
    printf 'username admin privilege 15 secret 9 $9$x\n' >"$O/net-configs/bad/T1.cfg"; echo T1 >"$O/net-configs/bad/latest"
}
DEVS="--device r1,ios,cisco-ios --device a1,asa,cisco-asa --device p1,pan,paloalto --device f1,fg,fortigate --device v1,vyos,vyos,vyos --device m1,mt,mikrotik --device l1,lnx,linux,ops --device pf1,pfx,pfsense"
BT_NET_PASS=$OLD; export BT_NET_PASS
# pw_of FILE DEVICE -> the password a passwords.txt table gives the device
pw_of() { awk -F'|' -v d="$2" '{ x = $1; gsub(/ /, "", x) } x == d { p = $4; gsub(/ /, "", p); print p }' "$1"; }

t_start "options"
(unset BT_NET_PASS; run --device r1,ios,cisco-ios >/dev/null 2>&1); t_eq "$?" 3 "no current password exits 3"
(BT_NET_NEWPASS='has space and ?'; export BT_NET_NEWPASS; run --device r1,ios,cisco-ios --new-password-env >/dev/null 2>&1); t_eq "$?" 2 "unsafe new password exits 2"
run --device r1,ios,junos >/dev/null 2>&1; t_eq "$?" 2 "unknown vendor exits 2"
run --device '../x,ios,cisco-ios' >/dev/null 2>&1; t_eq "$?" 2 "an unsafe device name exits 2"
run --device 'r1,ios,cisco-ios,admin,22x' >/dev/null 2>&1; t_eq "$?" 2 "a port that is not a number exits 2"

t_start "dry run"
devices
# shellcheck disable=SC2086
out=$(run --out "$O" $DEVS 2>&1); rc=$?
t_eq "$rc" 0 "exit 0"
t_has "$out" "r1             cisco-ios  admin      would change" "would change"
t_eq "$(cat "$D/ios.pw")" "$OLD" "nothing changed"

t_start "--apply on seven vendors"
devices
# shellcheck disable=SC2086
out=$(run --out "$O" $DEVS --apply --no-protected --wait 1 --commit-wait 1 2>&1); rc=$?
t_eq "$rc" 0 "exit 0"
P=$(printf '%s\n' "$out" | sed -n 's/^All results: //p')/passwords.txt
t_eq "$(ls -l "$P" | cut -c1-10)" "-rw-------" "passwords file is mode 600"
for pair in r1:ios a1:asa f1:fg v1:vyos m1:mt l1:lnx; do
    d=${pair%:*}; h=${pair#*:}
    t_eq "$(cat "$D/$h.pw")" "$(pw_of "$P" "$d")" "$d: device has the password from the file"
done
case "$(cat "$D/pan.pw")" in 'phash:$5$'*|'phash:$1$'*) t_ok "Palo Alto got a password hash, not the password" true ;; *) t_ok "Palo Alto got a password hash, not the password" false ;; esac
t_has "$out" "p1             paloalto   admin      changed (new login tested)" "Palo Alto new login tested"
t_eq "$(cat "$D/ios.priv")" 15 "Cisco privilege level 15 kept"
t_has "$(cat "$D/ios.log")" "write memory" "Cisco config saved after the test"
t_has "$out" "pf1            pfsense    admin      skipped: change it in the web GUI" "pfSense pointed to the GUI"
leak=0
for p in $(awk -F'|' 'NR > 1 { gsub(/ /, "", $4); print $4 }' "$P"); do grep -rqF -- "$p" "$O"/*.log "$(dirname "$P")/summary.txt" "$(dirname "$P")/devices.txt" && leak=1; done
t_eq "$leak" 0 "no new password in the log, summary or devices.txt"
t_fail "no CSV files in the run" sh -c "ls '$(dirname "$P")' | grep -q csv"
t_has "$(cat "$D/mt.log")" 'scheduler add name="bt-nw10-revert"' "MikroTik: a put-back is scheduled on the device first"
t_fail "MikroTik: and removed once the new password works" test -f "$D/mt.sched"
t_fail "no password on any ssh command line (MikroTik's goes in a config file)" sh -c "grep -F -e '$OLD' -e \"\$(cat '$D/mt.pw')\" '$D/args.log'"

t_start "safety"
devices
out=$(run --out "$O" --device bad,bad,cisco-ios --apply --no-protected --wait 1 2>&1); rc=$?
t_eq "$rc" 5 "exit 5 when the new password does not work"
t_has "$out" "failed: new password did not work; old password restored and tested" "old password put back"
t_eq "$(cat "$D/bad.pw")" "$OLD" "device still has the old password"
devices
out=$(BT_NET_PASS=wrong-password-1; export BT_NET_PASS; run --out "$O" --device r1,ios,cisco-ios --apply --no-protected --wait 1 2>&1)
t_has "$out" "failed: could not log in with the current password" "wrong current password: nothing changed"
t_eq "$(cat "$D/ios.pw")" "$OLD" "device unchanged"
rm -rf "$O/net-configs/r1"
out=$(run --out "$O" --device r1,ios,cisco-ios --apply --no-protected --wait 1 2>&1)
t_has "$out" "skipped: account not found in NW-01's saved config" "Cisco without a saved config is skipped"
printf 'type,value,note\nhost,fg,scored\n' >"$T_TMP/prot.csv"
out=$(run --out "$O" --device f1,fg,fortigate --apply --protected "$T_TMP/prot.csv" --wait 1 2>&1)
t_has "$out" "skipped (protected device)" "protected device skipped"

t_start "Cisco enable secret"
devices
out=$(run --out "$O" --device r1,ios,cisco-ios --enable-too --apply --no-protected --wait 1 2>&1)
P=$(printf '%s\n' "$out" | sed -n 's/^All results: //p')/passwords.txt
t_has "$out" "changed (new login tested, enable secret too)" "enable secret changed and tested at level 15"
t_eq "$(cat "$D/ios.en")" "$(awk -F'|' '$3 ~ /enable secret/ { gsub(/ /, "", $4); print $4 }' "$P")" "device has the enable secret from the file"
t_start "chosen passwords per device (--passwords)"
devices
printf '# device  password\nf1   Chosen-For-Forti-1 \n10.99.99.99 Not-A-Device-Here1\n' >"$T_TMP/devpw.txt"
out=$(run --out "$O" --device f1,fg,fortigate --device m1,mt,mikrotik --passwords "$T_TMP/devpw.txt" --apply --no-protected --wait 1 2>&1)
P=$(printf '%s\n' "$out" | sed -n 's/^All results: //p')/passwords.txt
t_eq "$(cat "$D/fg.pw")" "Chosen-For-Forti-1" "the device named in the file got the chosen password"
t_eq "$(cat "$D/mt.pw")" "$(pw_of "$P" m1)" "the other device got a random one"
t_has "$out" "not a device in this run: 10.99.99.99" "a name that is no device is reported"
t_hasnt "$(cat "$O"/NW-10_*.log)" "Chosen-For-Forti-1" "the chosen password is not in the log"
printf 'f1 bad pass?\n' >"$T_TMP/devbad.txt"
run --out "$O" --device f1,fg,fortigate --passwords "$T_TMP/devbad.txt" >/dev/null 2>&1; t_eq "$?" 2 "an unsafe chosen password exits 2"
t_fail "no pending file left after a normal run" sh -c "ls '$O'/NW-10_*/pending-password.txt >/dev/null 2>&1"
devices
printf 'f1,Older-Comma-Form-1\n' >"$T_TMP/devold.txt"
run --out "$O" --device f1,fg,fortigate --passwords "$T_TMP/devold.txt" --apply --no-protected --wait 1 >/dev/null 2>&1
t_eq "$(cat "$D/fg.pw")" "Older-Comma-Form-1" "an older device,password file is still read"

t_start "MikroTik: the device puts the old password back by itself"
# "garble": the device takes a password nobody knows; only its own job saves it
devices; echo garble >"$D/mt.mode"
out=$(run --out "$O" --device m1,mt,mikrotik --apply --no-protected --wait 1 --revert-after 5 2>&1); rc=$?
t_eq "$rc" 5 "exit 5"
t_has "$out" "puts the old one back by itself within 5s" "it says it waits for the device"
t_has "$out" "failed: new password did not work; the device put the old password back; tested" "old password back and tested"
t_eq "$(cat "$D/mt.pw")" "$OLD" "the device has the old password"
devices; echo keepjob >"$D/mt.mode"
out=$(run --out "$O" --device m1,mt,mikrotik --apply --no-protected --wait 1 --revert-after 5 2>&1)
t_has "$out" "REMOVE /system scheduler bt-nw10-revert now" "a put-back that cannot be removed is shouted about"
devices
out=$(BT_NET_PASS='Has$Dollar-Sign1'; export BT_NET_PASS; run --out "$O" --device m1,mt,mikrotik --apply --no-protected --wait 1 2>&1)
t_has "$out" "characters RouterOS would read as code" "a current password RouterOS would misread: skipped"

t_start "stopped in the middle: the new password is not lost"
devices
# The start-and-stop runs in a small script of its own under the system sh:
# the signal must reach the script itself (a function in the background is a
# subshell), and a yash parent ends its background children without letting
# their traps run.
cat >"$T_TMP/stop.sh" <<'STOP'
out=$1; shift
"$@" >"$out" 2>&1 &
pid=$!
sleep 4
kill -TERM "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
STOP
# shellcheck disable=SC2086
sh "$T_TMP/stop.sh" "$T_TMP/stop.out" $SH "$C" --out "$O" --device p1,pan,paloalto --apply --no-protected --commit-wait 20
pend=$(ls "$O"/NW-10_*/pending-password.txt 2>/dev/null | tail -n 1)
t_file "${pend:-$O/none}" "pending-password.txt is left behind"
t_eq "$(ls -l "$pend" | cut -c1-10)" "-rw-------" "and is mode 600"
t_has "$(cat "$T_TMP/stop.out")" "EITHER its old password OR the new one" "the message says what to do"
t_start "OpenWRT"
printf 'Old-Pass-1\n' >"$D/owrt.pw"; rm -f "$D/owrt.log" "$D/owrt.mode"
out=$(BT_NET_PASS='Old-Pass-1' run --out "$O" --no-color --device router,owrt,openwrt,root --batch 2>&1)
t_has "$out" "[~] router (openwrt, owrt): root - would change" "dry run: one line per device"
t_eq "$(cat "$D/owrt.pw")" "Old-Pass-1" "a dry run changes nothing"
out=$(BT_NET_PASS='Old-Pass-1' run --out "$O" --no-color --device router,owrt,openwrt,root --batch --apply --no-protected 2>&1)
t_has "$(cat "$D/owrt.log")" "| passwd 'root'" "busybox passwd, the new password on its input"
t_has "$out" "[+] router (openwrt, owrt): root - changed (new login tested)" "changed and tested"
_np=$(cat "$D/owrt.pw")
t_hasnt "$_np" "Old-Pass-1" "the password really changed"
t_hasnt "$out" "$_np" "the new password is never on screen"
t_has "$(cat "$(ls -d "$O"/NW-10_*/ | tail -n 1)passwords.txt" 2>/dev/null)$(cat "$O"/NW-10_*/passwords.txt 2>/dev/null)" "$_np" "it is in passwords.txt"
printf 'Old-Pass-1\n' >"$D/owrt.pw"; echo ignore >"$D/owrt.mode"
out=$(BT_NET_PASS='Old-Pass-1' run --out "$O" --no-color --device router,owrt,openwrt,root --batch --apply --no-protected 2>&1)
t_has "$out" "[x] router (openwrt, owrt): root - failed: new password did not work; old password restored and tested" "a change that does not take: the old one is kept"
rm -f "$D/owrt.mode"

t_start "questions: devices, current password, new password"
if command -v script >/dev/null 2>&1; then
    printf 'Old-Pass-1\n' >"$D/owrt.pw"; rm -f "$D/owrt.mode"
    # address, type (Enter = OpenWRT), name, user, another (Enter = no),
    # current password, new passwords: t, typed twice, then: change now? Enter
    printf 'owrt\n\n\n\n\nOld-Pass-1\n\nTyped-Pass-12\nTyped-Pass-12\n\n' >"$T_TMP/ans"
    mkdir -p "$T_TMP/empty"
    tt=$(cd "$T_TMP/empty" && unset BT_NET_PASS && BT_NO_TTY=0 script -qc "$SH '$C' --out '$O' --no-color --apply --no-protected" /dev/null <"$T_TMP/ans" 2>&1)
    t_has "$tt" "What is owrt?" "the device is asked for"
    t_has "$tt" "The CURRENT device password (hidden, never saved)" "the current password is asked"
    t_has "$tt" "New passwords?" "how to make the new ones is asked"
    t_has "$tt" "[t] type one for every device" "with every answer spelled out"
    t_has "$tt" "Change the password on 1 device(s) now?" "one yes before anything is sent"
    t_has "$tt" "Answer [T/r]" "typing one shared password is the default"
    t_has "$tt" "EVERYONE who logs in to these devices with the current password" "it says who needs the new password"
    t_eq "$(cat "$D/owrt.pw")" "Typed-Pass-12" "the typed password is set"
fi
t_done
