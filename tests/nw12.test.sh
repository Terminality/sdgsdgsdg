#!/bin/sh
# Tests for roles/network/NW-12-device-sessions.sh.
# A stand-in device for every brand: the stand-in ssh checks the password,
# prints that brand's documented answer (accounts and sessions, kept in a
# file per device) and applies the commands it is sent to that file - a
# removed account or an ended session disappears, a disabled one is marked.
# Checks: what is found and how it is judged (own login, team, console, red
# team), the baseline, the questions, a dry run sends nothing, --apply sends
# the right command per brand and checks the result, the undo puts an account
# back from NW-01's copy, odd names never reach a command, no password hash
# is copied into the results.
. "$(dirname "$0")/helper.sh"
SH=${TEST_SHELL:-sh}
C="$T_ROOT/roles/network/NW-12-device-sessions.sh"
export BT_SKIP_VERIFY=1
O="$T_TMP/out"; B="$T_TMP/bin"; D="$T_TMP/dev"; mkdir -p "$O" "$B" "$D"
STUB_DIR=$D; export STUB_DIR
cat >"$B/ssh" <<'STUB'
#!/bin/sh
# stand-in ssh: ssh [opts] -p PORT user@host [command]
host=""; cmd=""; seen=0
for a in "$@"; do
    if [ "$seen" = 1 ]; then cmd=$a; continue; fi
    case "$a" in *@*) host=${a#*@}; seen=1 ;; esac
done
pwf="$STUB_DIR/$host.pw"; [ -f "$pwf" ] || { echo "ssh: connect to host $host: Connection timed out" >&2; exit 255; }
[ "$SSHPASS" = "$(cat "$pwf")" ] || { echo "Permission denied, please try again." >&2; exit 255; }
out="$STUB_DIR/$host.out"; tmp="$out.n"
cp "$out" "$STUB_DIR/$host.reply"
# The commands: exec mode is one line split on ";", stdin mode one per line.
if [ -n "$cmd" ]; then printf '%s\n' "$cmd" | tr ';' '\n'; else cat; fi >"$STUB_DIR/$host.cmds"
while IFS= read -r l; do
    l=$(printf '%s' "$l" | sed 's/^ *//')
    [ -n "$l" ] || continue
    echo "$l" >>"$STUB_DIR/$host.log"
    case "$l" in
        "no username "*) n=${l#no username }; grep -v "^username $n " "$out" >"$tmp"; cat "$tmp" >"$out" ;;
        "username "*) echo "$l" >>"$out" ;;
        "clear line "*) id=${l#clear line }; grep -v " $id " "$out" >"$tmp"; cat "$tmp" >"$out" ;;
        "ssh disconnect "*) id=${l#ssh disconnect }; awk -v i="$id" '$1 == i { skip = 1; next } skip && $1 == "OUT" { next } { skip = 0; print }' "$out" >"$tmp"; cat "$tmp" >"$out" ;;
        "delete mgt-config users "*) n=${l#delete mgt-config users }; grep -v "^set mgt-config users $n " "$out" >"$tmp"; cat "$tmp" >"$out" ;;
        "delete admin-sessions username "*) n=${l#delete admin-sessions username }; awk -v n="$n" '!($1 == n && $3 ~ /^(CLI|Web)/)' "$out" >"$tmp"; cat "$tmp" >"$out" ;;
        "delete system login user "*) n=$(printf '%s' "${l#delete system login user }" | tr -d "'"); grep -v "^set system login user $n " "$out" >"$tmp"; cat "$tmp" >"$out" ;;
        "set system login user "*) echo "$l" >>"$out" ;;
        *"pkill -KILL -t "*) t=$(printf '%s' "${l##*-t }" | tr -d "'"); grep -v " $t " "$out" >"$tmp"; cat "$tmp" >"$out" ;;
        "/user disable "*) n=$(printf '%s' "$l" | sed 's/.*name="\([^"]*\)".*/\1/'); sed "s/^\( *[0-9][0-9]*\)  *name=$n /\1 X name=$n /" "$out" >"$tmp"; cat "$tmp" >"$out" ;;
        "/user enable "*) n=$(printf '%s' "$l" | sed 's/.*name="\([^"]*\)".*/\1/'); sed "s/^\( *[0-9][0-9]*\) X name=$n /\1 name=$n /" "$out" >"$tmp"; cat "$tmp" >"$out" ;;
        "/user active request-logout "*) n=$(printf '%s' "$l" | sed 's/.*name="\([^"]*\)".*/\1/'); grep -v "name=$n .*via=" "$out" >"$tmp"; cat "$tmp" >"$out" ;;
        *"usermod -L -e 1 "*) n=$(printf '%s' "${l##* }" | tr -d "'"); sed "s/^$n P /$n L /" "$out" >"$tmp"; cat "$tmp" >"$out" ;;
        *"usermod -U -e '' "*) n=$(printf '%s' "${l##* }" | tr -d "'"); sed "s/^$n L /$n P /" "$out" >"$tmp"; cat "$tmp" >"$out" ;;
        "delete "*) n=${l#delete }; awk -v n="$n" '$1 == "edit" { e = $2; gsub(/"/, "", e); if (e == n) { skip = 1; next } } skip { if ($1 == "next") skip = 0; next } { print }' "$out" >"$tmp"; cat "$tmp" >"$out" ;;
        "edit "*) awk -v l="$l" '{ print } /^config system admin/ { print "    " l; print "    next" }' "$out" >"$tmp"; cat "$tmp" >"$out" ;;
    esac
done <"$STUB_DIR/$host.cmds"
cat "$STUB_DIR/$host.reply"
exit 0
STUB
printf '#!/bin/sh\n[ "$1" = -e ] || exit 9\nshift\nexec "$@"\n' >"$B/sshpass"
chmod +x "$B/ssh" "$B/sshpass"
BT_SSH="$B/ssh"; BT_SSHPASS="$B/sshpass"; BT_NET_PASS='Dev-Pass-1'; export BT_SSH BT_SSHPASS BT_NET_PASS
ME=10.9.9.9; RED=172.16.5.5

devices() {
    for h in ios asa pan fg vyos mt lnx; do printf '%s\n' "$BT_NET_PASS" >"$D/$h.pw"; rm -f "$D/$h.log"; done
    cat >"$D/ios.out" <<EOF
r1#show running-config | include ^username
username admin privilege 15 secret 9 \$9\$abc
username backdoor privilege 15 secret 9 \$9\$def
username ops privilege 1 secret 9 \$9\$ghi
r1#show users
    Line       User       Host(s)              Idle       Location
*  2 vty 0     admin      idle                 00:00:00 $ME
   3 vty 1     backdoor   idle                 00:01:10 $RED
   4 vty 2     ops        idle                 00:00:30 10.0.0.7
   0 con 0                idle                 00:05:00
EOF
    cat >"$D/asa.out" <<EOF
a1# show running-config username
username admin password xx pbkdf2 privilege 15
username eve password yy pbkdf2 privilege 15
a1# show ssh sessions
SID Client IP       Version Mode Encryption Hmac          State           Username
0   $ME        2.0     IN   aes128-ctr hmac-sha1     SessionStarted  admin
                            OUT  aes128-ctr hmac-sha1     SessionStarted  admin
1   $RED      2.0     IN   aes128-ctr hmac-sha1     SessionStarted  eve
                            OUT  aes128-ctr hmac-sha1     SessionStarted  eve
EOF
    cat >"$D/pan.out" <<EOF
admin@PA> show admins
Admin          From            Client Session-start     Idle-for
--------------------------------------------------------------------------
admin          $ME        CLI    11/19 10:00:00   00:00:00s
mallory        $RED      Web    11/19 09:58:00   00:00:10s
admin@PA# show mgt-config users
set mgt-config users admin phash *
set mgt-config users admin permissions role-based superuser yes
set mgt-config users mallory phash *
set mgt-config users mallory permissions role-based superuser yes
EOF
    cat >"$D/fg.out" <<EOF
FG # show system admin
config system admin
    edit "admin"
        set accprofile "super_admin"
        set password ENC SH2xxx
    next
    edit "rogue"
        set accprofile "super_admin"
        set password ENC SH2yyy
    next
end
FG # get system admin list
username      local        device              remote               started
admin         ssh          port1:10.0.0.1:22   $ME:51234       2026-11-19 10:00:00
rogue         https        port1:10.0.0.1:443  $RED:40000     2026-11-19 09:00:00
EOF
    cat >"$D/vyos.out" <<EOF
set system login user vyos authentication encrypted-password '\$6\$x'
set system login user hax authentication encrypted-password '\$6\$y'
vyos     pts/0        2026-11-19 10:00 ($ME)
hax      pts/1        2026-11-19 10:01 ($RED)
EOF
    cat >"$D/mt.out" <<EOF
 0   name=admin group=full address="" last-logged-in=2026-11-19 10:00:00
 1   name=svc group=full address=""
 0   when=2026-11-19 10:00:00 name=admin address=$ME via=ssh group=full
 1   when=2026-11-19 09:00:00 name=svc address=$RED via=winbox group=full
EOF
    cat >"$D/lnx.out" <<EOF
root:x:0:0:root:/root:/bin/bash
ops:x:1000:1000::/home/ops:/bin/bash
evil:x:1001:1001::/home/evil:/bin/sh
x';reboot;':x:1002:1002::/home/x:/bin/sh
www-data:x:33:33::/var/www:/usr/sbin/nologin
===groups
sudo:x:27:ops,evil
===who
ops      pts/0        2026-11-19 10:00 ($ME)
evil     pts/1        2026-11-19 10:01 ($RED)
===status
root P 11/19/2026 0 99999 7 -1
ops P 11/19/2026 0 99999 7 -1
evil P 11/19/2026 0 99999 7 -1
EOF
    # NW-01's saved configs: the undo reads the account's lines from here.
    mkdir -p "$O/net-configs/r1" "$O/net-configs/v1" "$O/net-configs/f1"
    grep '^username' "$D/ios.out" >"$O/net-configs/r1/T1.cfg"; echo T1 >"$O/net-configs/r1/latest"
    grep '^set system' "$D/vyos.out" >"$O/net-configs/v1/T1.cfg"; echo T1 >"$O/net-configs/v1/latest"
    sed -n '/^config system admin/,/^end/p' "$D/fg.out" >"$O/net-configs/f1/T1.cfg"; echo T1 >"$O/net-configs/f1/latest"
}
DEVS="--device r1,ios,cisco-ios --device a1,asa,cisco-asa --device p1,pan,paloalto --device f1,fg,fortigate --device v1,vyos,vyos,vyos --device m1,mt,mikrotik --device l1,lnx,linux,ops --device pf1,pfx,pfsense"
# shellcheck disable=SC2086
run() { $SH "$C" --out "$O" --no-color --me "$ME" $DEVS "$@"; }

t_start "options"
$SH "$C" --device r1,ios,junos >/dev/null 2>&1; t_eq "$?" 2 "an unknown vendor exits 2"
$SH "$C" --device r1,ios,cisco-ios,admin,22x >/dev/null 2>&1; t_eq "$?" 2 "a port that is not a number exits 2"
$SH "$C" --device r1,ios,cisco-ios --team moon >/dev/null 2>&1; t_eq "$?" 2 "a bad --team exits 2"
(unset BT_NET_PASS; $SH "$C" --out "$O" --device r1,ios,cisco-ios >/dev/null 2>&1); t_eq "$?" 3 "no password exits 3"
out=$($SH "$C" --help 2>&1); t_has "$out" "--known NAME" "--help"

t_start "first run: look, baseline, dry run"
devices; rm -f "$O/net-accounts-baseline.txt"
out=$(run --batch --team 10.0.0.0/24 2>&1)
t_has "$out" "[ok] r1 (ios, cisco-ios): 3 account(s), 4 session(s)" "Cisco IOS read"
t_has "$out" "[ok] r1: admin from $ME (vty) - this script's own login" "own login recognised"
t_has "$out" "[!] r1: backdoor from $RED (vty) - not from your team" "a session from outside the team is HIGH"
t_has "$out" "[ok] r1: ops from 10.0.0.7 (vty) - your team" "a team session is fine"
t_has "$out" "on the console" "the console is shown"
t_has "$out" "[!] a1: eve from $RED (ssh)" "ASA session"
t_has "$out" "[!] p1: mallory from $RED (Web)" "Palo Alto session"
t_has "$out" "p1: mallory (superuser)" "Palo Alto rights"
t_has "$out" "f1: rogue (accprofile super_admin)" "FortiGate account"
t_has "$out" "[!] v1: hax from $RED (ssh)" "VyOS session"
t_has "$out" "[!] m1: svc from $RED (winbox)" "MikroTik session"
t_has "$out" "l1: evil (admin (sudo))" "Linux sudo member"
t_has "$out" "an account with an odd name" "an odd account name is flagged"
t_hasnt "$out" "';reboot;'" "and never printed whole or asked about"
t_has "$out" "pf1 (pfsense): no safe command line" "pfSense is pointed at the web GUI"
t_has "$out" "first run: these accounts are the baseline" "baseline saved"
t_has "$out" "kick it (ends the session" "kick question"
t_has "$out" "[K/l/a] k (default)" "outside the team: default kick"
t_has "$out" "first run: is it yours?" "first run accounts are looked at"
t_has "$out" "Dry run: nothing was changed" "dry run"
t_fail "a dry run sends nothing but the reads" grep -q 'no username\|clear line' "$D/ios.log"
_rd=$(ls -d "$O"/device-sessions-* | tail -n 1)
t_file "$_rd/accounts.txt" "accounts.txt"; t_file "$_rd/sessions.txt" "sessions.txt"
t_fail "no CSV files are left" sh -c "find '$O' -name '*.csv' | grep -q ."
t_fail "no password hash in the results" sh -c "grep -rqF -e '\$9\$abc' -e '\$9\$def' -e 'SH2' '$_rd' '$O/net-accounts-baseline.txt'"
t_fail "the device password is not written anywhere" sh -c "grep -rq 'Dev-Pass-1' '$O'"

t_start "accounts new since the first run, --apply --batch"
devices
grep -v ' backdoor$\| eve$\| mallory$\| rogue$\| hax$\| svc$\| evil$' "$O/net-accounts-baseline.txt" >"$T_TMP/b"; cat "$T_TMP/b" >"$O/net-accounts-baseline.txt"
out=$(run --batch --team 10.0.0.0/24 --no-protected --apply 2>&1)
t_has "$out" "[!] r1: backdoor (privilege 15) - NEW since the first run" "a new account is HIGH"
t_ok "IOS: no username backdoor" grep -qx 'no username backdoor' "$D/ios.log"
t_ok "IOS: clear line vty 1" grep -qx 'clear line vty 1' "$D/ios.log"
t_ok "IOS: saved" grep -qx 'write memory' "$D/ios.log"
t_fail "IOS: the team session is left" grep -q 'clear line vty 2' "$D/ios.log"
t_fail "IOS: our own login account is never removed" grep -q 'no username admin' "$D/ios.log"
t_has "$out" "[+] r1: account backdoor disabled" "checked after: gone"
t_has "$out" "[+] r1: kicked backdoor from $RED" "checked after: kicked"
t_ok "ASA: no username eve, ssh disconnect 1" sh -c "grep -qx 'no username eve' '$D/asa.log' && grep -qx 'ssh disconnect 1' '$D/asa.log'"
t_ok "Palo Alto: delete and commit" sh -c "grep -qx 'delete mgt-config users mallory' '$D/pan.log' && grep -qx 'commit' '$D/pan.log'"
t_ok "Palo Alto: delete admin-sessions" grep -qx 'delete admin-sessions username mallory' "$D/pan.log"
t_ok "FortiGate: delete rogue" grep -qx 'delete rogue' "$D/fg.log"
t_has "$out" "execute disconnect-admin-session" "FortiGate session: the command is shown"
t_ok "VyOS: delete, commit, save" sh -c "grep -qx \"delete system login user 'hax'\" '$D/vyos.log' && grep -qx 'save' '$D/vyos.log'"
t_ok "VyOS: pkill pts/1" grep -q "pkill -KILL -t 'pts/1'" "$D/vyos.log"
t_ok "MikroTik: disable svc" grep -qx '/user disable \[find name="svc"\]' "$D/mt.log"
t_ok "MikroTik: logout svc" grep -q 'request-logout \[find name="svc" address="'"$RED"'"\]' "$D/mt.log"
t_has "$out" "[+] m1: account svc disabled" "MikroTik: checked after"
t_ok "Linux: usermod -L evil" grep -q "usermod -L -e 1 'evil'" "$D/lnx.log"
t_has "$out" "[+] l1: account evil disabled" "Linux: locked, checked after"
t_fail "the odd name never reaches a command" grep -q 'reboot' "$D/lnx.log"
_rd=$(ls -d "$O"/device-sessions-* | tail -n 1)
t_fail "no hash copied into the undo scripts" sh -c "grep -rqF -e '\$9\$def' -e 'SH2yyy' '$_rd/undo'"
t_ok "the disabled ones stay out of the baseline" sh -c "! grep -q 'r1 backdoor' '$O/net-accounts-baseline.txt'"

t_start "the undo"
awk -F'\t' '{ l[NR] = $4 } END { for (i = NR; i > 0; i--) print l[i] }' "$O"/undo-*.log >"$T_TMP/undo.sh"
sh "$T_TMP/undo.sh" >"$T_TMP/undo.out" 2>&1
t_ok "IOS: the account's own line is put back from NW-01's copy" grep -qx 'username backdoor privilege 15 secret 9 $9$def' "$D/ios.log"
t_ok "VyOS: put back" grep -q "set system login user hax authentication encrypted-password" "$D/vyos.log"
t_ok "FortiGate: put back" grep -qx 'edit "rogue"' "$D/fg.log"
t_ok "MikroTik: enabled again" grep -qx '/user enable \[find name="svc"\]' "$D/mt.log"
t_ok "Linux: unlocked" grep -q "usermod -U -e '' 'evil'" "$D/lnx.log"
(unset BT_NET_PASS; sh "$_rd/undo/r1-backdoor.sh" >/dev/null 2>&1); t_eq "$?" 1 "an undo without BT_NET_PASS stops"

t_start "questions on a terminal"
if command -v script >/dev/null 2>&1; then
    devices; rm -f "$O/net-accounts-baseline.txt"
    run --batch >/dev/null 2>&1      # baseline
    grep -v ' backdoor$' "$O/net-accounts-baseline.txt" >"$T_TMP/b"; cat "$T_TMP/b" >"$O/net-accounts-baseline.txt"
    # only r1: backdoor (new) k; ops (first-run, not new) Enter; session backdoor l; apply Enter
    printf 'k\n\nl\n\n' >"$T_TMP/ans"
    tt=$(BT_NO_TTY=0 script -qc "$SH '$C' --out '$O' --no-color --me $ME --device r1,ios,cisco-ios --team 10.0.0.0/24 --no-protected --apply" /dev/null <"$T_TMP/ans" 2>&1)
    t_has "$tt" "[d] disable it (removed; the undo puts back its lines from NW-01's copy)" "an account lists its answers"
    t_has "$tt" "[k] kick it" "a session lists its answers"
    t_fail "k: the account is kept" grep -q 'no username backdoor' "$D/ios.log"
    t_fail "l: the session is left" grep -q 'clear line' "$D/ios.log"
    t_ok "a kept account joins the baseline" grep -qx 'r1 backdoor' "$O/net-accounts-baseline.txt"
fi
t_done
