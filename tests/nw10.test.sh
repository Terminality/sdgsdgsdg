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
export CCDC_SKIP_VERIFY=1
# shellcheck disable=SC2086
run() { $SH "$C" "$@"; }
O="$T_TMP/out"; B="$T_TMP/bin"; D="$T_TMP/dev"; mkdir -p "$O" "$B" "$D"
STUB_DIR=$D; export STUB_DIR
cat >"$B/ssh" <<'STUB'
#!/bin/sh
host=""; for a in "$@"; do case "$a" in *@*) host=${a#*@} ;; esac; done
pwf="$STUB_DIR/$host.pw"; [ -f "$pwf" ] || { echo "ssh: connect to host $host: Connection timed out" >&2; exit 255; }
cur=$(cat "$pwf")
case "$cur" in
    phash:*) h=${cur#phash:}; salt=$(echo "$h" | cut -d'$' -f3); [ "$(openssl passwd -5 -salt "$salt" "$SSHPASS")" = "$h" ] || { echo "Permission denied" >&2; exit 255; } ;;
    *) [ "$SSHPASS" = "$cur" ] || { echo "Permission denied, please try again." >&2; exit 255; } ;;
esac
mode=$(cat "$STUB_DIR/$host.mode" 2>/dev/null)
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
CCDC_SSH="$B/ssh"; CCDC_SSHPASS="$B/sshpass"; export CCDC_SSH CCDC_SSHPASS
OLD='Old-Device-Pass1'
devices() {
    for h in ios asa pan fg vyos mt lnx bad; do printf '%s\n' "$OLD" >"$D/$h.pw"; rm -f "$D/$h.mode" "$D/$h.log" "$D/$h.priv" "$D/$h.en"; done
    echo ignore >"$D/bad.mode"
    # NW-01's store: the Cisco account's privilege level comes from here.
    mkdir -p "$O/net-configs/r1" "$O/net-configs/a1" "$O/net-configs/bad"
    printf 'username admin privilege 15 secret 9 $9$x\n' >"$O/net-configs/r1/T1.cfg"; echo T1 >"$O/net-configs/r1/latest"
    printf 'username admin password x encrypted privilege 15\n' >"$O/net-configs/a1/T1.cfg"; echo T1 >"$O/net-configs/a1/latest"
    printf 'username admin privilege 15 secret 9 $9$x\n' >"$O/net-configs/bad/T1.cfg"; echo T1 >"$O/net-configs/bad/latest"
}
DEVS="--device r1,ios,cisco-ios --device a1,asa,cisco-asa --device p1,pan,paloalto --device f1,fg,fortigate --device v1,vyos,vyos,vyos --device m1,mt,mikrotik --device l1,lnx,linux,ops --device pf1,pfx,pfsense"
CCDC_NET_PASS=$OLD; export CCDC_NET_PASS

t_start "options"
(unset CCDC_NET_PASS; run --device r1,ios,cisco-ios >/dev/null 2>&1); t_eq "$?" 3 "no current password exits 3"
(CCDC_NET_NEWPASS='has space and ?'; export CCDC_NET_NEWPASS; run --device r1,ios,cisco-ios --new-password-env >/dev/null 2>&1); t_eq "$?" 2 "unsafe new password exits 2"
run --device r1,ios,junos >/dev/null 2>&1; t_eq "$?" 2 "unknown vendor exits 2"

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
P=$(printf '%s\n' "$out" | sed -n 's/^All results: //p')/passwords.csv
t_eq "$(ls -l "$P" | cut -c1-10)" "-rw-------" "passwords file is mode 600"
for pair in r1:ios a1:asa f1:fg v1:vyos m1:mt l1:lnx; do
    d=${pair%:*}; h=${pair#*:}
    t_eq "$(cat "$D/$h.pw")" "$(awk -F, -v d="$d" '$1 == d { print $4 }' "$P")" "$d: device has the password from the file"
done
case "$(cat "$D/pan.pw")" in 'phash:$5$'*|'phash:$1$'*) t_ok "Palo Alto got a password hash, not the password" true ;; *) t_ok "Palo Alto got a password hash, not the password" false ;; esac
t_has "$out" "p1             paloalto   admin      changed (new login tested)" "Palo Alto new login tested"
t_eq "$(cat "$D/ios.priv")" 15 "Cisco privilege level 15 kept"
t_has "$(cat "$D/ios.log")" "write memory" "Cisco config saved after the test"
t_has "$out" "pf1            pfsense    admin      skipped: change it in the web GUI" "pfSense pointed to the GUI"
leak=0
for p in $(awk -F, 'NR > 1 { print $4 }' "$P"); do grep -rqF -- "$p" "$O"/*.log "$(dirname "$P")/summary.txt" "$(dirname "$P")/devices.csv" && leak=1; done
t_eq "$leak" 0 "no new password in the log, summary or devices.csv"

t_start "safety"
devices
out=$(run --out "$O" --device bad,bad,cisco-ios --apply --no-protected --wait 1 2>&1); rc=$?
t_eq "$rc" 5 "exit 5 when the new password does not work"
t_has "$out" "failed: new password did not work; old password restored and tested" "old password put back"
t_eq "$(cat "$D/bad.pw")" "$OLD" "device still has the old password"
devices
out=$(CCDC_NET_PASS=wrong-password-1; export CCDC_NET_PASS; run --out "$O" --device r1,ios,cisco-ios --apply --no-protected --wait 1 2>&1)
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
P=$(printf '%s\n' "$out" | sed -n 's/^All results: //p')/passwords.csv
t_has "$out" "changed (new login tested, enable secret too)" "enable secret changed and tested at level 15"
t_eq "$(cat "$D/ios.en")" "$(awk -F, '$3 == "(enable secret)" { print $4 }' "$P")" "device has the enable secret from the file"
t_start "chosen passwords per device (--passwords)"
devices
printf '# device,password\nf1, Chosen-For-Forti-1 \n10.99.99.99,Not-A-Device-Here1\n' >"$T_TMP/devpw.csv"
out=$(run --out "$O" --device f1,fg,fortigate --device m1,mt,mikrotik --passwords "$T_TMP/devpw.csv" --apply --no-protected --wait 1 2>&1)
P=$(printf '%s\n' "$out" | sed -n 's/^All results: //p')/passwords.csv
t_eq "$(cat "$D/fg.pw")" "Chosen-For-Forti-1" "the device named in the file got the chosen password"
t_eq "$(cat "$D/mt.pw")" "$(awk -F, '$1 == "m1" { print $4 }' "$P")" "the other device got a random one"
t_has "$out" "not a device in this run: 10.99.99.99" "a name that is no device is reported"
t_hasnt "$(cat "$O"/NW-10_*.log)" "Chosen-For-Forti-1" "the chosen password is not in the log"
printf 'f1,bad pass?\n' >"$T_TMP/devbad.csv"
run --out "$O" --device f1,fg,fortigate --passwords "$T_TMP/devbad.csv" >/dev/null 2>&1; t_eq "$?" 2 "an unsafe chosen password exits 2"
t_fail "no pending file left after a normal run" sh -c "ls '$O'/NW-10_*/pending-password.csv >/dev/null 2>&1"

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
pend=$(ls "$O"/NW-10_*/pending-password.csv 2>/dev/null | tail -n 1)
t_file "${pend:-$O/none}" "pending-password.csv is left behind"
t_eq "$(ls -l "$pend" | cut -c1-10)" "-rw-------" "and is mode 600"
t_has "$(cat "$T_TMP/stop.out")" "EITHER its old password OR the new one" "the message says what to do"
t_done
