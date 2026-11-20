#!/bin/sh
# Tests for roles/network/NW-21-device-hardening.sh.
# A stand-in device for every brand.  The stand-in ssh checks the password,
# logs every command line it gets and prints the device's config (written
# from each brand's documented output).  The Cisco IOS stand-in also APPLIES
# the commands to its config (line vty blocks, "no ...", new lines), so the
# after-check and the undo are real; in "lockout" mode it refuses new logins
# once an access-class is set, so the put-back through the open session is
# tested.  Checks: the findings per brand, a secret SNMP community is never
# shown, a dry run sends no change, --apply sends each brand's commands, a
# failed new login puts the device back, the confirm question, the undo.
. "$(dirname "$0")/helper.sh"
SH=${TEST_SHELL:-sh}
C="$T_ROOT/roles/network/NW-21-device-hardening.sh"
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
[ -f "$STUB_DIR/$host.locked" ] && { echo "Connection closed by remote host" >&2; exit 255; }
cfg="$STUB_DIR/$host.cfg"
# Cisco IOS model: apply one config line to the config file.
ios() {
    awk -v l="$1" -v ctx="$(cat "$STUB_DIR/$host.ctx" 2>/dev/null)" '
        function key(s,   w) { split(s, w, " "); return w[1] }  # awk, not shell: posix-ok
        { a[++n] = $0 }
        END {
            if (l ~ /^ /) {
                s = substr(l, 2); neg = 0
                if (s ~ /^no /) { s = substr(s, 4); neg = 1 } else if (s ~ /^default /) { s = substr(s, 9); neg = 1 }
                k = key(s); out = 0
                for (i = 1; i <= n; i++) {
                    if (a[i] == ctx) { inb = 1; print a[i]; if (!neg) print l; continue }
                    if (inb && a[i] !~ /^ /) inb = 0
                    if (inb && key(substr(a[i], 2)) == k) continue
                    print a[i]
                }
            } else if (l ~ /^no /) { s = substr(l, 4); for (i = 1; i <= n; i++) if (index(a[i], s) != 1) print a[i] }
            else { f = 0; for (i = 1; i <= n; i++) { print a[i]; if (a[i] == l) f = 1 } if (!f) print l }
        }' "$cfg" >"$cfg.n" && cat "$cfg.n" >"$cfg"
}
# OpenWRT model: uci set / delete / add_list / del_list and the telnet init
# script, applied to the "uci show" lines in the config file.
owrt() {
    printf '%s\n' "$1" | sed 's/ && /\n/g; s/; /\n/g' | while IFS= read -r c; do
        set -- $c
        case "$1 $2" in
            "uci set"|"uci add_list"|"uci del_list"|"uci delete")
                awk -v op="$2" -v a="$3" '
                    BEGIN { q = sprintf("%c", 39); k = a; v = ""; if (index(a, "=")) { k = substr(a, 1, index(a, "=") - 1); v = substr(a, index(a, "=") + 1) } }
                    /^===/ { if (insec && !done) emit(); insec = ($0 == "===uci") }
                    insec && index($0, k "=") == 1 { done = 1; cur = substr($0, length(k) + 2)
                        if (op == "set") print k "=" q v q
                        else if (op == "add_list") print k "=" cur " " q v q
                        else if (op == "del_list") { gsub(" ?" q v q, "", cur); print k "=" cur }
                        next }
                    { print }
                    END { if (insec && !done) emit() }
                    function emit() { done = 1; if (op == "set" || op == "add_list") print k "=" q v q }' "$cfg" >"$cfg.n" && cat "$cfg.n" >"$cfg" ;;  # awk function, not shell: posix-ok
            "/etc/init.d/telnet disable") grep -v 'telnet' "$cfg" >"$cfg.n"; cat "$cfg.n" >"$cfg" ;;
            "/etc/init.d/telnet enable") awk '{ print } $0 == "===rc" { print "S50telnet" }' "$cfg" >"$cfg.n"; cat "$cfg.n" >"$cfg" ;;
        esac
    done
}
if [ -n "$cmd" ]; then printf '%s\n' "$cmd" | tr ';' '\n'; else cat; fi | while IFS= read -r l; do
    printf '%s\n' "$l" >>"$STUB_DIR/$host.log"
    [ "$(cat "$STUB_DIR/$host.kind" 2>/dev/null)" = owrt ] && case "$l" in *"uci "*|"/etc/init.d/"*) owrt "$l" ;; esac
    case "$(cat "$STUB_DIR/$host.kind" 2>/dev/null)" in ios)
        case "$l" in
            "configure terminal"|"terminal length 0"|"write memory"|exit|"show running-config") ;;
            end) rm -f "$STUB_DIR/$host.ctx" ;;
            "line vty "*) printf '%s\n' "$l" >"$STUB_DIR/$host.ctx" ;;
            "ip access-list standard "*) rm -f "$STUB_DIR/$host.ctx"; ios "$l" ;;
            " permit "*) ;;
            " "*) ios "$l"
                  [ -f "$STUB_DIR/$host.lockout" ] && case "$l" in " access-class BT-MGMT in") : >"$STUB_DIR/$host.locked" ;; " no access-class BT-MGMT in") rm -f "$STUB_DIR/$host.locked" ;; esac ;;
            *) rm -f "$STUB_DIR/$host.ctx"; ios "$l" ;;
        esac ;;
    esac
done
cat "$cfg"
exit 0
STUB
printf '#!/bin/sh\n[ "$1" = -e ] || exit 9\nshift\nexec "$@"\n' >"$B/sshpass"
chmod +x "$B/ssh" "$B/sshpass"
BT_SSH="$B/ssh"; BT_SSHPASS="$B/sshpass"; BT_NET_PASS='Dev-Pass-1'; export BT_SSH BT_SSHPASS BT_NET_PASS
ME=10.9.9.9

IOS_CFG='hostname r1
ip http server
snmp-server community public RO
snmp-server community S3cretComm RW
line vty 0 4
 transport input telnet ssh
 login local
line vty 5 15
 login local'
devices() {
    rm -f "$D"/*
    for h in ios bad asa pan fg vyos mt; do printf '%s\n' "$BT_NET_PASS" >"$D/$h.pw"; done
    printf '%s\n' "$IOS_CFG" >"$D/ios.cfg"; echo ios >"$D/ios.kind"
    printf '%s\n' "$IOS_CFG" >"$D/bad.cfg"; echo ios >"$D/bad.kind"; : >"$D/bad.lockout"
    cat >"$D/asa.cfg" <<'EOF'
hostname a1
telnet 0.0.0.0 0.0.0.0 inside
ssh 0.0.0.0 0.0.0.0 outside
ssh timeout 30
http server enable
http 0.0.0.0 0.0.0.0 inside
snmp-server community public
EOF
    cat >"$D/pan.cfg" <<'EOF'
set deviceconfig system hostname PA
set deviceconfig system service disable-telnet no
set deviceconfig system service disable-http no
set deviceconfig system snmp-setting access-setting version v2c snmp-community-string public
EOF
    cat >"$D/fg.cfg" <<'EOF'
config system interface
    edit "port1"
        set ip 10.0.0.1 255.255.255.0
        set allowaccess ping https ssh http telnet
    next
end
config system admin
    edit "admin"
        set accprofile "super_admin"
        set password ENC SH2xxx
    next
end
config system global
    set admintimeout 480
    set hostname "FG"
end
config log syslogd setting
    set status disable
end
config system ntp
    set type fortiguard
end
EOF
    cat >"$D/vyos.cfg" <<'EOF'
set service telnet port '23'
set service ssh port '22'
set service snmp community public authorization 'ro'
set service ntp server time1.vyos.net
EOF
    cat >"$D/mt.cfg" <<'EOF'
===svc
 0   name=telnet port=23 address="" vrf=main max-sessions=20
 1 X name=ftp port=21 address=""
 2   name=www port=80 address=""
 3   name=ssh port=22 address=""
 4   name=winbox port=8291 address=""
===snmp
                 enabled: no
 0   name=public addresses=::/0 security=none read-access=yes
===log
 0   name=memory target=memory
===ntp
          enabled: no
          servers:
===mac
  allowed-interface-list: all
===macwb
  allowed-interface-list: all
===note
     show-at-login: no
EOF
}
DEVS="--device r1,ios,cisco-ios --device a1,asa,cisco-asa --device p1,pan,paloalto --device f1,fg,fortigate --device v1,vyos,vyos,vyos --device m1,mt,mikrotik --device pf1,pfx,pfsense --device l1,lnx,linux"
OPTS="--team 10.0.0.0/24 --me $ME --log-host 10.0.0.20 --ntp 10.0.0.20 --wait 1 --commit-wait 1"
# shellcheck disable=SC2086
run() { $SH "$C" --out "$O" --no-color $OPTS "$@"; }

t_start "options"
$SH "$C" --device r1,ios,cisco-ios --banner 'a;b' >/dev/null 2>&1; t_eq "$?" 2 "a banner with odd characters exits 2"
$SH "$C" --device r1,ios,cisco-ios --timeout 0 >/dev/null 2>&1; t_eq "$?" 2 "--timeout 0 exits 2"
$SH "$C" --device r1,ios,cisco-ios,admin,22x >/dev/null 2>&1; t_eq "$?" 2 "a port that is not a number exits 2"
$SH "$C" --device r1,ios,cisco-ios --log-host moon >/dev/null 2>&1; t_eq "$?" 2 "a bad --log-host exits 2"
out=$($SH "$C" --help 2>&1); t_has "$out" "--log-host IP" "--help"

t_start "find (dry run)"
devices
# shellcheck disable=SC2086
out=$(run $DEVS --batch 2>&1)
t_has "$out" "[!] telnet allowed on the vty lines" "IOS: telnet"
t_has "$out" "[!] SSH to the device is open to any address (no access-class" "IOS: management open"
t_has "$out" "[!] plain HTTP management is on (ip http server)" "IOS: http"
t_has "$out" "[*] default SNMP community \"public\"" "IOS: default community"
t_has "$out" "an SNMP community is set with WRITE access (value not shown)" "IOS: other community reported"
t_hasnt "$out" "S3cretComm" "the secret community is never shown"
t_has "$out" "[*] SSH version 1 is still allowed" "IOS: ssh v1"
t_has "$out" "[*] logs are not sent to 10.0.0.20" "log server"
t_has "$out" "[!] telnet management is allowed (1 line(s))" "ASA: telnet"
t_has "$out" "[!] SSH/ASDM management is open to any address" "ASA: management open"
t_has "$out" "[*] SSH idle timeout is 30 minutes" "ASA: timeout"
t_has "$out" "[!] the management interface is open to any address (no permitted-ip)" "Palo Alto: permitted-ip"
t_has "$out" "add a syslog server profile" "Palo Alto: syslog pointed at the GUI"
t_has "$out" "[!] telnet or plain HTTP management on: 1 interface(s)" "FortiGate: allowaccess"
t_has "$out" "[!] 1 admin account(s) can log in from any address" "FortiGate: trusted hosts"
t_has "$out" "[*] admin idle timeout is 480 minutes" "FortiGate: timeout"
t_has "$out" "[!] the telnet service is on" "VyOS: telnet"
t_has "$out" "limit it with firewall rules (NW-20)" "VyOS: SSH limit pointed at NW-20"
t_has "$out" "[!] insecure services on: telnet www" "MikroTik: telnet and www (ftp is off)"
t_has "$out" "[!] management open to any address: ssh winbox" "MikroTik: ssh and winbox open"
t_has "$out" "[!] MAC telnet / MAC WinBox answer on all interfaces" "MikroTik: MAC server"
t_has "$out" "use LX-22 (SSH hardening) and LX-25" "Linux pointed at LX-22 / LX-25"
t_has "$out" "System > Advanced > Admin Access" "pfSense pointed at the web GUI"
t_has "$out" "[F/l/a] f (default)" "fixes default to fix"
t_has "$out" "Dry run: nothing was changed" "dry run"
t_fail "a dry run sends no change" grep -q 'transport input ssh' "$D/ios.log"
_rd=$(ls -d "$O"/device-hardening-* | tail -n 1)
t_file "$_rd/findings.txt" "findings.txt"
t_fail "no CSV files are left" sh -c "find '$O' -name '*.csv' | grep -q ."
t_fail "the secret community is not in the results" grep -rq S3cretComm "$_rd"
t_fail "the device password is not written anywhere" grep -rq 'Dev-Pass-1' "$O"

t_start "--apply --batch"
devices
# shellcheck disable=SC2086
out=$(run $DEVS --batch --no-protected --apply 2>&1)
for l in ' transport input ssh' 'ip access-list standard BT-MGMT' ' permit 10.0.0.0 0.0.0.255' " permit host $ME" ' access-class BT-MGMT in' ' exec-timeout 10 0' \
         'ip ssh version 2' 'no ip http server' 'no snmp-server community public' 'logging host 10.0.0.20' 'ntp server 10.0.0.20' \
         'banner login #Authorized access only. Activity is monitored.#' 'service password-encryption' 'write memory'; do
    t_ok "IOS sent:$l" grep -qxF "$l" "$D/ios.log"
done
t_fail "IOS: the secret community is not removed" grep -q 'S3cretComm' "$D/ios.log"
t_has "$out" "[+] r1: fixed: telnet allowed on the vty lines" "IOS: checked after, telnet gone"
t_has "$out" "[+] r1: fixed: SSH to the device is open to any address" "IOS: checked after, management limited"
t_has "$out" "[+] r1: fixed: plain HTTP management is on" "IOS: checked after, http off"
t_ok "IOS: the config now has the limit" grep -qxF ' access-class BT-MGMT in' "$D/ios.cfg"
for l in 'no telnet 0.0.0.0 0.0.0.0 inside' 'ssh 10.0.0.0 255.255.255.0 outside' "ssh $ME 255.255.255.255 outside" 'no ssh 0.0.0.0 0.0.0.0 outside' \
         'http 10.0.0.0 255.255.255.0 inside' 'ssh timeout 10' 'logging host outside 10.0.0.20' 'no snmp-server community public'; do
    t_ok "ASA sent: $l" grep -qxF "$l" "$D/asa.log"
done
for l in 'set deviceconfig system permitted-ip 10.0.0.0/24' "set deviceconfig system permitted-ip $ME/32" 'set deviceconfig system service disable-telnet yes' \
         'set deviceconfig system service disable-http yes' 'set deviceconfig setting management idle-timeout 10' 'commit'; do
    t_ok "Palo Alto sent: $l" grep -qxF "$l" "$D/pan.log"
done
for l in 'set allowaccess ping https ssh' 'set trusthost1 10.0.0.0 255.255.255.0' "set trusthost2 $ME 255.255.255.255" 'set admintimeout 10' 'set server "10.0.0.20"' 'set pre-login-banner enable'; do
    t_ok "FortiGate sent: $l" grep -qxF "$l" "$D/fg.log"
done
for l in 'delete service telnet' 'delete service snmp community public' 'set service ntp server 10.0.0.20' 'set system syslog remote 10.0.0.20 facility all level info' 'commit' 'save'; do
    t_ok "VyOS sent: $l" grep -qxF "$l" "$D/vyos.log"
done
for l in '/ip service disable telnet' '/ip service disable www' "/ip service set ssh address=10.0.0.0/24,$ME/32" '/tool mac-server set allowed-interface-list=none' \
         '/tool mac-server mac-winbox set allowed-interface-list=none' '/system ntp client set enabled=yes servers=10.0.0.20'; do
    t_ok "MikroTik sent: $l" grep -qxF "$l" "$D/mt.log"
done
t_fail "MikroTik: ftp (already off) is left alone" grep -q 'disable ftp' "$D/mt.log"
t_fail "the secret community is not in the results" grep -rq S3cretComm "$O"

t_start "the undo"
awk -F'\t' '{ l[NR] = $4 } END { for (i = NR; i > 0; i--) print l[i] }' "$O"/undo-*.log >"$T_TMP/undo.sh"
sh "$T_TMP/undo.sh" >"$T_TMP/undo.out" 2>&1
t_ok "IOS: telnet back as it was" grep -qxF ' transport input telnet ssh' "$D/ios.cfg"
t_ok "IOS: plain HTTP back" grep -qxF 'ip http server' "$D/ios.cfg"
t_fail "IOS: the limit is gone" grep -q 'BT-MGMT' "$D/ios.cfg"
t_ok "IOS: the default community back" grep -qxF 'snmp-server community public RO' "$D/ios.cfg"
t_ok "ASA: the open line back" grep -qxF 'ssh 0.0.0.0 0.0.0.0 outside' "$D/asa.log"
t_ok "FortiGate: the old allowaccess back" grep -qxF 'set allowaccess ping https ssh http telnet' "$D/fg.log"
t_ok "VyOS: telnet back" grep -qxF "set service telnet port '23'" "$D/vyos.log"
t_ok "MikroTik: telnet back" grep -qxF '/ip service enable telnet' "$D/mt.log"
(unset BT_NET_PASS; sh "$(ls -d "$O"/device-hardening-* | tail -n 1)/undo/r1.sh" >/dev/null 2>&1); t_eq "$?" 1 "an undo without BT_NET_PASS stops"

t_start "a new login fails: put back through the open session"
devices
out=$(run --device b1,bad,cisco-ios --batch --no-protected --apply 2>&1)
t_has "$out" "[x] b1: a new login FAILED after the change" "the failed login is seen"
t_has "$out" "[+] b1: put back, and a new login works again" "put back and checked"
t_ok "the access-class was taken off" grep -qxF ' no access-class BT-MGMT in' "$D/bad.log"
t_fail "the device is not locked" test -f "$D/bad.locked"
t_ok "its config is as before" grep -qxF ' transport input telnet ssh' "$D/bad.cfg"

t_start "questions on a terminal"
if command -v script >/dev/null 2>&1; then
    devices
    # all the defaults (a), apply (Enter), then "keep?" from another machine: n
    printf 'a\n\nn\n' >"$T_TMP/ans"
    tt=$(BT_NO_TTY=0 script -qc "$SH '$C' --out '$O' --no-color $OPTS --device r1,ios,cisco-ios --no-protected --apply --timer 30" /dev/null <"$T_TMP/ans" 2>&1)
    t_has "$tt" "[f] fix it (turn it off; SSH (and HTTPS) stay)" "a finding lists its answers"
    t_has "$tt" "log in to r1 from ANOTHER team machine" "asks for a login from another machine"
    t_has "$tt" "Not confirmed: putting r1 back" "n: put back"
    t_ok "n: the config is as before" grep -qxF ' transport input telnet ssh' "$D/ios.cfg"
    t_fail "n: the limit is gone" grep -q 'BT-MGMT' "$D/ios.cfg"
fi
t_start "OpenWRT"
printf '%s\n' "$BT_NET_PASS" >"$D/ow.pw"; echo owrt >"$D/ow.kind"; rm -f "$D/ow.log"
cat >"$D/ow.cfg" <<'EOF'
===uci
dropbear.@dropbear[0]=dropbear
dropbear.@dropbear[0].PasswordAuth='on'
dropbear.@dropbear[0].Port='22'
uhttpd.main=uhttpd
uhttpd.main.listen_http='0.0.0.0:80' '[::]:80'
uhttpd.main.listen_https='0.0.0.0:443' '[::]:443'
uhttpd.main.redirect_https='0'
system.@system[0]=system
system.@system[0].hostname='router'
system.ntp=timeserver
system.ntp.enabled='1'
system.ntp.server='0.openwrt.pool.ntp.org'
upnpd.config=upnpd
upnpd.config.enabled='1'
snmpd.public=community
snmpd.public.community='public'
===lan
192.168.220.2/24
===rc
S10boot
S50dropbear
S50telnet
EOF
cp "$D/ow.cfg" "$T_TMP/ow.orig"
OW="--device router,ow,openwrt,root"
out=$(run $OW --batch 2>&1)
for x in "[!] web admin (LuCI) over plain HTTP" "[!] telnet starts at boot (/etc/rc.d/S50telnet)" "[!] SSH and the web admin answer on every interface" \
         "[!] UPnP is on" "[*] SNMP has a default community name" "[*] SSH logins never time out" "[*] logs are not sent to 10.0.0.20" \
         "[*] time is not taken from 10.0.0.20" "[-] no login banner"; do t_has "$out" "$x" "OpenWRT: $x"; done
t_has "$out" "Dry run: nothing was changed" "dry run"
t_fail "a dry run sends no uci change" grep -q '^uci set' "$D/ow.log"
_u0=$(cat "$O"/undo-*.log 2>/dev/null | grep -c .)
out=$(run $OW --batch --apply --no-protected 2>&1)
c=$(cat "$D/ow.cfg")
t_has "$c" "uhttpd.main.redirect_https='1'" "HTTPS only"
t_has "$c" "dropbear.@dropbear[0].Interface='lan'" "SSH on lan only"
t_has "$c" "uhttpd.main.listen_https='192.168.220.2:443'" "the web admin on the lan address"
t_hasnt "$c" "0.0.0.0" "nothing on every address"
t_has "$c" "upnpd.config.enabled='0'" "UPnP off"
t_hasnt "$c" "S50telnet" "telnet disabled"
t_has "$c" "dropbear.@dropbear[0].IdleTimeout='600'" "idle timeout 10 minutes"
t_has "$c" "system.@system[0].log_ip='10.0.0.20'" "logs to the log server"
t_has "$c" "system.ntp.server='0.openwrt.pool.ntp.org' '10.0.0.20'" "time server added"
t_has "$c" "dropbear.@dropbear[0].BannerFile='/etc/bt-banner'" "banner"
t_has "$(cat "$D/ow.log")" "uci commit uhttpd" "each package committed"
t_has "$out" "[+] router: fixed: web admin (LuCI) over plain HTTP" "checked after: fixed"
t_hasnt "$out" "still there" "every fix checked as gone"
cat "$O"/undo-*.log | awk -F'\t' -v n="$_u0" 'NR > n { l[NR] = $4 } END { for (i = NR; i > n; i--) print l[i] }' >"$T_TMP/undo.sh"
sh "$T_TMP/undo.sh" >/dev/null 2>&1
c=$(cat "$D/ow.cfg")
t_has "$c" "uhttpd.main.redirect_https='0'" "undo: HTTP again"
t_has "$c" "S50telnet" "undo: telnet back"
t_has "$c" "upnpd.config.enabled='1'" "undo: UPnP back"
t_hasnt "$c" "Interface='lan'" "undo: SSH on every interface again"
t_has "$c" "uhttpd.main.listen_http='0.0.0.0:80' '[::]:80'" "undo: the old web addresses back"

t_start "questions: devices, password, team, log and time servers"
if command -v script >/dev/null 2>&1; then
    cp "$T_TMP/ow.orig" "$D/ow.cfg"
    # address, type, name, user, another, password, team, log server, time server, then Enter for the rest
    printf 'ow\n\n\n\n\n%s\n10.0.0.0/24\n10.0.0.20\n\n\n\n\n\n\n\n\n\n\n\n\n' "$BT_NET_PASS" >"$T_TMP/ans"
    mkdir -p "$T_TMP/empty"
    tt=$(cd "$T_TMP/empty" && unset BT_NET_PASS && BT_NO_TTY=0 script -qc "$SH '$C' --out '$O' --no-color --me $ME --wait 1" /dev/null <"$T_TMP/ans" 2>&1)
    t_has "$tt" "What is ow?" "the device is asked for"
    t_has "$tt" "Device password (hidden, never saved)" "the password"
    t_has "$tt" "Your team's addresses?" "the team"
    t_has "$tt" "Send the devices' logs to a log server?" "the log server"
    t_has "$tt" "Take the time from a time server?" "the time server"
    t_has "$tt" "logs are not sent to 10.0.0.20" "the answer is used"
    t_hasnt "$tt" "time is not taken from" "no time server: not checked"
fi
t_done
