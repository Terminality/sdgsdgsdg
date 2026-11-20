#!/bin/sh
# =============================================================================
# ID:       NW-21
# NAME:     Network device hardening
# ROLE:     Network  (wave 2, after NW-01 backup and NW-10 passwords)
# KIND:     changes - dry run unless --apply
# VERSION:  1.0.0
#
# PURPOSE
#   Locks down how the firewalls, routers and switches themselves are
#   managed.  For each device it reads the config and checks:
#     telnet / plain HTTP management on      -> turned off (SSH and HTTPS stay)
#     management open to any address         -> limited to --team and this box
#     SSH version 1 allowed (Cisco IOS)      -> version 2 only
#     no idle timeout on management logins   -> --timeout minutes (default 10)
#     default SNMP communities (public ...)  -> removed (other ones: reported,
#                                               the value is never shown)
#     MikroTik MAC telnet / MAC WinBox       -> off
#     no log server (with --log-host)        -> logs go to it (Splunk)
#     no time server (with --ntp)            -> time from it
#     no login banner                        -> --banner text
#     Cisco passwords stored readable        -> service password-encryption
#   Each one is asked about.  Then, per device, ONE session stays open:
#     1. the chosen changes are sent through it
#     2. a NEW login from this box is tried
#     3. it works -> (for a management limit or telnet change) you are asked
#        to check a login from another team machine within --timer seconds
#        (default 60); yes -> saved; no / no answer -> put back
#        it fails -> everything is put back through the open session
#   Every change has an undo script (needs BT_NET_PASS when run).
#
#   Brands: cisco-ios, cisco-asa, paloalto, fortigate, vyos, mikrotik.
#   Linux devices: use LX-22 (SSH) and LX-25 (firewall).  pfSense /
#   OPNsense: listed with where to do it in the web GUI.
#
#   QUESTIONS (Enter takes the default in capitals; a flag answers each):
#     each finding               [f]ix (default) / [l]eave / [a]ll the rest default
#     do these?                  --apply
#     keep the changes? (after a management change, from another machine)
#                                Y within --timer seconds, else put back; --batch keeps
#
# USAGE
#   BT_NET_PASS='pw' sh NW-21-device-hardening.sh --hosts hosts.txt --team 10.0.0.0/24
#   BT_NET_PASS='pw' sh NW-21-device-hardening.sh --hosts hosts.txt --team 10.0.0.0/24 \
#       --log-host 10.0.0.20 --ntp 10.0.0.20 --protected p.csv --apply
#
# OPTIONS
#   --hosts FILE / --device NAME,ADDRESS,VENDOR[,USER[,PORT]]   as for NW-01
#   --user NAME        default login account (admin)
#   --ask-password     ask for the password (else $BT_NET_PASS)
#   --enable-env       Cisco: enable with $BT_NET_ENABLE
#   --team CIDR,...    your team's addresses: management is limited to these
#                      and this box (without it, that change is not offered)
#   --me ADDRESS       this box's address as the devices see it (default:
#                      "ip route get"); always kept in the management limit
#   --log-host IP      send device logs here (Splunk)
#   --ntp IP           take time from here
#   --banner TEXT      login banner (default "Authorized access only.
#                      Activity is monitored.")
#   --timeout MIN      idle timeout for management logins (default 10)
#   --wait N           seconds before the new-login test (default 5)
#   --commit-wait N    Palo Alto: seconds for a commit (default 120)
#   --timer N          seconds to confirm from another machine (default 60)
#   --configs DIR      where NW-01 keeps known_hosts (default <out>/net-configs)
#   --legacy-ssh       allow old SSH algorithms
#   --no-color         no colours
#   --help             this text plus the common options
#
# OUTPUTS  (under --out, in device-hardening-N/)
#   output.txt, findings.txt, plan.txt, summary.txt
#   undo/DEVICE.sh     puts the device back (needs BT_NET_PASS)
#
# DEPENDS ON
#   ssh, sshpass, mkfifo.  BT_SSH / BT_SSHPASS may name stand-ins (tests).
#
# TESTED ON
#   A stand-in device for every brand (answers written from each brand's
#   documented config output; the Cisco IOS stand-in applies the commands,
#   so the after-check and the put-back on a failed login are tested) under
#   dash, bash, busybox sh, ksh93, mksh and yash with gawk, mawk and busybox
#   awk.  NOT yet on real Cisco, Palo Alto, FortiGate, VyOS or MikroTik
#   devices: run it without --apply first, then --apply on ONE device.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - The management limit keeps --team and this box.  A teammate (or the
#     scoring engine!) managing a device from elsewhere is locked out: put
#     such an address in --team, or the device on the protected list.
#   - The confirm countdown only expires by itself in shells with "read -t"
#     (bash, ksh, mksh, yash, busybox); in dash it waits for an answer.
#   - If this script is killed during the countdown, the open session dies
#     with it: the changes stay (Cisco/VyOS: not saved, a reload undoes them).
#   - VyOS SSH source limits need firewall rules (NW-20): reported only.
#   - Palo Alto syslog and SNMP need profiles in the web GUI: reported only.
# =============================================================================

# >>> BT-LIB
# Development copy: find lib/lib.sh by walking up from this file.  The build
# step (tools/build.sh, LB-03) replaces this whole block with the library
# itself, so the built script is a single standalone file.
_cc_d=$(cd "$(dirname "$0")" && pwd)
while [ "$_cc_d" != "/" ] && [ ! -f "$_cc_d/lib/lib.sh" ]; do _cc_d=$(dirname "$_cc_d"); done
[ -f "$_cc_d/lib/lib.sh" ] || { echo "cannot find lib/lib.sh above $0" >&2; exit 3; }
. "$_cc_d/lib/lib.sh"
# <<< BT-LIB

VENDORS="cisco-ios cisco-asa paloalto fortigate vyos mikrotik linux pfsense opnsense"

usage() {
    cat <<'USAGE'
NW-21 Network device hardening - management access, telnet/HTTP, SNMP, logs, time, banner
  BT_NET_PASS=pw sh NW-21-device-hardening.sh --hosts FILE | --device SPEC [--team CIDR] [--apply]

  --hosts FILE / --device NAME,ADDRESS,VENDOR[,USER[,PORT]]
  --user NAME        default login account (admin)
  --ask-password     ask for the password (else $BT_NET_PASS)
  --enable-env       Cisco: enable with $BT_NET_ENABLE
  --team CIDR,...    your team's addresses (management is limited to these and this box)
  --me ADDRESS       this box's address as the devices see it
  --log-host IP      send device logs here (Splunk)
  --ntp IP           take time from here
  --banner TEXT      login banner text
  --timeout MIN      idle timeout for management logins (default 10)
  --wait N           seconds before the new-login test (default 5)
  --commit-wait N    Palo Alto commit time (default 120)
  --timer N          seconds to confirm from another machine (default 60)
  --configs DIR      NW-01's folder (known_hosts)
  --legacy-ssh       allow old SSH algorithms
  --no-color         no colours
  --help             show this text
USAGE
    cc_usage_common
}

NL='
'
HOSTS=""; DEVICES=""; DEFUSER="admin"; ASK=0; ENABLE=0; TEAM=""; ME=""; LOGHOST=""; NTP=""
BANNER="Authorized access only. Activity is monitored."; TO=10; WAIT=5; CWAIT=120; TIMER=60; CONFIGS=""; LEGACY=0; COLOR=1
num() { case "$2" in ''|*[!0-9]*) cc_die 2 "$1 needs a whole number" ;; esac; }
ipv4() { printf '%s' "$2" | grep -q '^[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}$' || cc_die 2 "$1 needs an IPv4 address"; }
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --apply)        CC_APPLY=1; shift ;;
        --hosts)        [ $# -ge 2 ] || cc_die 2 "--hosts needs a file"; [ -r "$2" ] || cc_die 2 "--hosts: cannot read $2"; HOSTS=$2; shift 2 ;;
        --device)       [ $# -ge 2 ] || cc_die 2 "--device needs NAME,ADDRESS,VENDOR"; DEVICES="$DEVICES$2$NL"; shift 2 ;;
        --user)         [ $# -ge 2 ] || cc_die 2 "--user needs a name"; DEFUSER=$2; shift 2 ;;
        --ask-password) ASK=1; shift ;;
        --enable-env)   ENABLE=1; shift ;;
        --team)         [ $# -ge 2 ] || cc_die 2 "--team needs addresses"; TEAM="$TEAM,$2"; shift 2 ;;
        --me)           [ $# -ge 2 ] || cc_die 2 "--me needs an address"; ipv4 "$1" "$2"; ME=$2; shift 2 ;;
        --log-host)     [ $# -ge 2 ] || cc_die 2 "--log-host needs an address"; ipv4 "$1" "$2"; LOGHOST=$2; shift 2 ;;
        --ntp)          [ $# -ge 2 ] || cc_die 2 "--ntp needs an address"; ipv4 "$1" "$2"; NTP=$2; shift 2 ;;
        --banner)       [ $# -ge 2 ] || cc_die 2 "--banner needs text"; BANNER=$2; shift 2 ;;
        --timeout)      num "$1" "${2:-}"; TO=$2; shift 2 ;;
        --wait)         num "$1" "${2:-}"; WAIT=$2; shift 2 ;;
        --commit-wait)  num "$1" "${2:-}"; CWAIT=$2; shift 2 ;;
        --timer)        num "$1" "${2:-}"; TIMER=$2; shift 2 ;;
        --configs)      [ $# -ge 2 ] || cc_die 2 "--configs needs a folder"; CONFIGS=$2; shift 2 ;;
        --legacy-ssh)   LEGACY=1; shift ;;
        --no-color|--no-colour) COLOR=0; shift ;;
        --help|-h)      usage; exit 0 ;;
        *)              cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
[ -n "$HOSTS$DEVICES" ] || cc_die 2 "give --hosts FILE or --device NAME,ADDRESS,VENDOR (try --help)"
TEAM=${TEAM#,}
for _t in $(printf '%s' "$TEAM" | tr ',' ' '); do
    printf '%s' "$_t" | grep -q '^[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\(/[0-9]\{1,2\}\)\{0,1\}$' || cc_die 2 "--team: IPv4 addresses or CIDRs (10.0.0.0/24)"
done
# The banner goes into device commands: letters, digits, spaces and . , - ! only.
case "$BANNER" in ''|*[!A-Za-z0-9\ .,!-]*) cc_die 2 "--banner: letters, digits, spaces and . , - ! only" ;; esac
[ "$TO" -ge 1 ] && [ "$TO" -le 60 ] || cc_die 2 "--timeout: 1 to 60 minutes"

cc_init "NW-21" "Network device hardening" changes
# shellcheck disable=SC2034  # read by cc_color_init
[ "$COLOR" = 1 ] || CC_NOCOLOR=1
cc_color_init
cc_use_numbered_dir device-hardening
rmdir "$CC_RUN_DIR/raw" 2>/dev/null
OUTF="$CC_RUN_DIR/output.txt"
grep -v '\[NOTE\]\|\[DEBUG\]' "$CC_LOG" >"$OUTF" 2>/dev/null || : >"$OUTF"
# shellcheck disable=SC2034  # CC_TEE is read by the library's log functions
CC_TEE=$OUTF
W="$CC_RUN_DIR/.work"; (umask 077; mkdir -p "$W")
US=$(printf '\037')
header() { cc_show "" ""; cc_show "$C_CYN" "==========[ $1 ]=========="; }
# j FIELD... -> one line, fields split by \037
j() { _j=$1; shift; for _jx in "$@"; do _j="$_j$US$_jx"; done; printf '%s\n' "$_j"; }
trap 'rm -rf "$W"; exit 130' INT TERM HUP
[ -n "$CONFIGS" ] || CONFIGS="$CC_OUT/net-configs"
mkdir -p "$CONFIGS" 2>/dev/null
SSH=${BT_SSH:-$(cc_which ssh)} || cc_die 3 "ssh not found"
SSHPASS_BIN=${BT_SSHPASS:-$(cc_which sshpass)} || cc_die 3 "sshpass not found (apt install sshpass): device logins use the password"
cc_have mkfifo || cc_die 3 "mkfifo not found"
if [ "$ASK" = 1 ]; then
    [ -r /dev/tty ] || cc_die 3 "--ask-password needs a terminal; set BT_NET_PASS"
    printf 'Device password: ' >/dev/tty; stty -echo </dev/tty 2>/dev/null
    read -r BT_NET_PASS </dev/tty; stty echo </dev/tty 2>/dev/null; printf '\n' >/dev/tty
fi
[ -n "${BT_NET_PASS:-}" ] || cc_die 3 "the device password is needed: set BT_NET_PASS or use --ask-password"
[ "$ENABLE" = 1 ] && [ -z "${BT_NET_ENABLE:-}" ] && cc_die 3 "--enable-env: set BT_NET_ENABLE"

cc_show "$C_CYN" "NW-21 Network device hardening | from $CC_HOST | results in $CC_RUN_DIR"
cc_show "" "Legend: ${C_RED}[!]${C_OFF} fix now   ${C_YEL}[*]${C_OFF} look at it   ${C_GRN}[ok]${C_OFF} fine   ${C_YEL}[~] would change${C_OFF}   ${C_GRN}[+] changed${C_OFF}   ${C_RED}[x] failed${C_OFF}"

# ---- Devices (same rules as NW-01) ---------------------------------------------------
vendor_of() {
    printf '%s' "$1" | tr 'A-Z' 'a-z' | awk '
        /cisco-ios|ios-xe|catalyst|cisco ios|cisco router|cisco switch/ { print "cisco-ios"; exit }
        /cisco-asa|asa|firepower|ftd/ { print "cisco-asa"; exit }
        /paloalto|palo alto|pan-os|panos/ { print "paloalto"; exit }
        /fortigate|fortinet|fortios/ { print "fortigate"; exit }
        /vyos|vyatta/ { print "vyos"; exit }
        /opnsense/ { print "opnsense"; exit }
        /pfsense/ { print "pfsense"; exit }
        /mikrotik|routeros/ { print "mikrotik"; exit }
        /cisco/ { print "cisco-ios"; exit }'
}
: >"$W/devices"
if [ -n "$HOSTS" ]; then
    cc_hosts_rows "$HOSTS" | awk -F'|' '{ print $1 "|" $2 "|" tolower($3) "|" $10 "|" $9 "|" $7 "|" $6 }' >"$W/rows"
    while IFS='|' read -r _n _a _os _v _notes _u _p; do
        _vend=""; [ -n "$_v" ] && _vend=$(vendor_of "$_v")
        [ -z "$_vend" ] && [ "$_os" != linux ] && case " $VENDORS " in *" $_os "*) _vend=$_os ;; esac
        [ -z "$_vend" ] && [ "$_os" = network ] && _vend=$(vendor_of "$_notes")
        [ -n "$_vend" ] || continue
        printf '%s|%s|%s|%s|%s\n' "$_n" "$_a" "$_vend" "${_u:-$DEFUSER}" "${_p:-22}" >>"$W/devices"
    done <"$W/rows"
fi
printf '%s' "$DEVICES" | grep . | while IFS=',' read -r _n _a _v _u _p; do
    case " $VENDORS " in *" $_v "*) ;; *) echo "BADV|$_v"; continue ;; esac
    [ -n "$_n" ] && [ -n "$_a" ] || { echo "BAD|$_n"; continue; }
    printf '%s|%s|%s|%s|%s\n' "$_n" "$_a" "$_v" "${_u:-$DEFUSER}" "${_p:-22}"
done >>"$W/devices"
grep -q '^BAD' "$W/devices" && cc_die 2 "--device needs NAME,ADDRESS,VENDOR with a known vendor ($VENDORS)"
[ -s "$W/devices" ] || cc_die 3 "no network devices found (os must be network or a vendor name)"
for _n in $(cut -d'|' -f1 "$W/devices"); do case "$_n" in *[!A-Za-z0-9_.-]*) cc_die 2 "device name '$_n' may only use letters, digits, '.', '_' and '-'" ;; esac; done
_bp=$(awk -F'|' '$5 !~ /^[0-9]+$/ || $5 < 1 || $5 > 65535 { print $1; exit }' "$W/devices"); [ -z "$_bp" ] || cc_die 2 "device $_bp: the SSH port must be a number from 1 to 65535"

# ---- Talking to a device ---------------------------------------------------------------
sshopts() {
    set -- -T -o ConnectTimeout=10 -o "UserKnownHostsFile=$CONFIGS/known_hosts" -o StrictHostKeyChecking=accept-new \
        -o LogLevel=ERROR -o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive -o NumberOfPasswordPrompts=1
    [ "$LEGACY" = 1 ] && set -- "$@" -o KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group1-sha1 -o HostKeyAlgorithms=+ssh-rsa -o Ciphers=+aes128-cbc,aes256-cbc,3des-cbc
    printf '%s\n' "$@"
}
# read_cmds VENDOR -> what to send to read the settings; mode: exec (one line) or stdin
read_mode() { case "$1" in vyos|mikrotik) echo exec ;; *) echo stdin ;; esac; }
en() { case "$1" in cisco-*) [ "$ENABLE" = 1 ] && printf 'enable\n%s\n' "$BT_NET_ENABLE" ;; esac; return 0; }
read_cmds() {
    case "$1" in
        cisco-ios) en "$1"; printf 'terminal length 0\nshow running-config\nexit\n' ;;
        cisco-asa) en "$1"; printf 'terminal pager 0\nshow running-config\nexit\n' ;;
        paloalto)  printf 'set cli pager off\nset cli config-output-format set\nconfigure\nshow deviceconfig\nexit\nexit\n' ;;
        fortigate) printf 'show system interface\nshow system admin\nshow system global\nshow log syslogd setting\nshow system ntp\nshow system snmp community\nexit\n' ;;
        vyos)      printf '/opt/vyatta/bin/vyatta-op-cmd-wrapper show configuration commands' ;;
        mikrotik)  printf ':put "===svc"; /ip service print terse without-paging; :put "===snmp"; /snmp print; /snmp community print terse without-paging; :put "===log"; /system logging action print terse without-paging; :put "===ntp"; /system ntp client print; :put "===mac"; /tool mac-server print; :put "===macwb"; /tool mac-server mac-winbox print; :put "===note"; /system note print' ;;
    esac
}
# readdev VENDOR USER ADDRESS PORT OUT -> 0 when it logged in
readdev() {
    read_cmds "$1" >"$W/rin"
    sshopts >"$W/opts"; set -- "$1" "$2" "$3" "$4" "$5"; _rv=$1; _ru=$2; _ra=$3; _rp=$4; _ro=$5
    set --; while IFS= read -r _o; do set -- "$@" "$_o"; done <"$W/opts"
    if [ "$(read_mode "$_rv")" = exec ]; then
        SSHPASS=$BT_NET_PASS "$SSHPASS_BIN" -e "$SSH" "$@" -p "$_rp" "$_ru@$_ra" "$(cat "$W/rin")" </dev/null >"$_ro" 2>"$W/err"
    else
        SSHPASS=$BT_NET_PASS "$SSHPASS_BIN" -e "$SSH" "$@" -p "$_rp" "$_ru@$_ra" <"$W/rin" >"$_ro" 2>"$W/err"
    fi
}
my_addr() { [ -n "$ME" ] && { printf '%s' "$ME"; return; }; ip route get "$1" 2>/dev/null | sed -n 's/.* src \([^ ]*\).*/\1/p' | head -n 1; }

# ---- The checks ----------------------------------------------------------------------------
# check VENDOR CONFIG ALLOWED -> lines, split by \037:
#   O text                            fine
#   F id level text default           a finding (default "-" = report only)
#   X id command                      a line of its fix
#   U id command                      a line of its undo
# ALLOWED: the --team ranges plus this box, "net/prefix" comma separated.
CHECK_AWK='
function mask(p,   o, k, b, v) { o = ""; for (k = 1; k <= 4; k++) { b = p - 8 * (k - 1); if (b > 8) b = 8; if (b < 0) b = 0; v = (b == 0) ? 0 : 256 - pw2(8 - b); o = o (k > 1 ? "." : "") v } return o }  # awk, not shell: posix-ok
function wild(p,   m, q, o, k) { m = mask(p); split(m, q, "."); o = ""; for (k = 1; k <= 4; k++) o = o (k > 1 ? "." : "") (255 - q[k]); return o }  # awk, not shell: posix-ok
function pw2(n,   r) { r = 1; while (n-- > 0) r *= 2; return r }  # awk, not shell: posix-ok
function F(id, lv, t, d) { print "F" US id US lv US t US d }  # awk, not shell: posix-ok
function X(id, c) { print "X" US id US c }  # awk, not shell: posix-ok
function U(id, c) { print "U" US id US c }  # awk, not shell: posix-ok
function O(t) { print "O" US t }  # awk, not shell: posix-ok
function dflt(n) { return (n ~ /^(public|private|cisco|community|admin|default|secret|password|snmp|manager|monitor|read|write|test|snmpd|all private)$/) }  # awk, not shell: posix-ok
BEGIN { na = split(allowed, A, ","); for (i = 1; i <= na; i++) { p = 32; n = A[i]; if (index(n, "/")) { p = substr(n, index(n, "/") + 1) + 0; n = substr(n, 1, index(n, "/") - 1) } AN[i] = n; AP[i] = p } }
{ sub(/\r$/, "") }
'
# Cisco IOS
IOS_AWK='
/^line vty / { nb++; B[nb] = $0; tr[nb] = "-"; ac[nb] = ""; et[nb] = ""; inb = 1; next }
/^[^ ]/ { inb = 0 }
inb && $1 == "transport" && $2 == "input" { tr[nb] = $0; sub(/^ *transport input */, "", tr[nb]) }
inb && $1 == "access-class" && $3 == "in" { ac[nb] = $2 }
inb && $1 == "exec-timeout" { et[nb] = $2 " " $3 }
/^ip ssh version 2/ { v2 = 1 }
/^ip http server/ { http = 1 }
/^snmp-server community / { nc++; SC[nc] = $0; SN[nc] = $3; SW[nc] = ($4 == "RW" || $4 == "rw") }
/^logging (host )?[0-9]/ { if ($NF == lh || $2 == lh || $3 == lh) haslog = 1 }
/^ntp server / { if ($3 == ntp) hasntp = 1 }
/^banner (login|motd) / { banner = 1 }
/^service password-encryption/ { pwenc = 1 }
END {
    tel = 0; for (b = 1; b <= nb; b++) if (tr[b] == "-" || tr[b] ~ /telnet|all/) tel = 1
    if (nb && tel) { F("telnet", "HIGH", "telnet allowed on the vty lines: passwords cross the network in clear text", "f")
        for (b = 1; b <= nb; b++) if (tr[b] == "-" || tr[b] ~ /telnet|all/) { X("telnet", B[b]); X("telnet", " transport input ssh"); U("telnet", B[b]); U("telnet", (tr[b] == "-") ? " default transport input" : " transport input " tr[b]) } }
    else if (nb) O("vty lines: SSH only")
    acl = 0; for (b = 1; b <= nb; b++) if (ac[b] != "") acl = ac[b]
    if (nb && !acl && na) { F("mgmt", "HIGH", "SSH to the device is open to any address (no access-class on the vty lines)", "f")
        X("mgmt", "ip access-list standard BT-MGMT"); for (i = 1; i <= na; i++) X("mgmt", (AP[i] == 32) ? " permit host " AN[i] : " permit " AN[i] " " wild(AP[i]))
        for (b = 1; b <= nb; b++) { X("mgmt", B[b]); X("mgmt", " access-class BT-MGMT in"); U("mgmt", B[b]); U("mgmt", " no access-class BT-MGMT in") }
        U("mgmt", "no ip access-list standard BT-MGMT") }
    else if (nb && !acl) F("mgmt", "HIGH", "SSH to the device is open to any address: pass --team to limit it", "-")
    else if (nb) O("vty lines limited by access-class " acl)
    slow = 0; for (b = 1; b <= nb; b++) { split(et[b], e, " "); if (et[b] == "" || (e[1] + 0 == 0 && e[2] + 0 == 0) || e[1] + 0 > to) slow = 1 }
    if (nb && slow) { F("timeout", "MED", "management logins have no or a long idle timeout", "f")
        for (b = 1; b <= nb; b++) { X("timeout", B[b]); X("timeout", " exec-timeout " to " 0"); U("timeout", B[b]); U("timeout", (et[b] == "") ? " no exec-timeout" : " exec-timeout " et[b]) } }
    if (!v2) { F("sshv2", "MED", "SSH version 1 is still allowed", "f"); X("sshv2", "ip ssh version 2"); U("sshv2", "no ip ssh version 2") } else O("SSH version 2 only")
    if (http) { F("http", "HIGH", "plain HTTP management is on (ip http server)", "f"); X("http", "no ip http server"); U("http", "ip http server") } else O("no plain HTTP management")
    snmp(); logntpban()
    if (!pwenc) { F("pwenc", "MED", "passwords in the config are stored readable (no service password-encryption)", "f"); X("pwenc", "service password-encryption"); U("pwenc", "no service password-encryption") }
}
function snmp(   i, k) { for (i = 1; i <= nc; i++) { if (dflt(SN[i])) { k = "snmp" i; F(k, SW[i] ? "HIGH" : "MED", "default SNMP community \"" SN[i] "\"" (SW[i] ? " with WRITE access" : ""), "f"); X(k, "no snmp-server community " SN[i]); U(k, SC[i]) } else F("snmpo" i, SW[i] ? "HIGH" : "LOW", "an SNMP community is set" (SW[i] ? " with WRITE access" : "") " (value not shown): make sure it is not guessable", "-") } }  # awk, not shell: posix-ok
function logntpban() {  # awk, not shell: posix-ok
    if (lh != "" && !haslog) { F("log", "MED", "logs are not sent to " lh, "f"); X("log", "logging host " lh); X("log", "logging trap informational"); U("log", "no logging host " lh) }
    if (ntp != "" && !hasntp) { F("ntp", "MED", "time is not taken from " ntp, "f"); X("ntp", "ntp server " ntp); U("ntp", "no ntp server " ntp) }
    if (!banner) { F("banner", "LOW", "no login banner", "f"); X("banner", "banner login #" bn "#"); U("banner", "no banner login") } }
'
# Cisco ASA
ASA_AWK='
/^telnet [0-9]/ { nt++; T[nt] = $0 }
/^ssh [0-9]/ && NF >= 4 { if ($2 == "0.0.0.0" && $3 == "0.0.0.0") { na2++; SA[na2] = $4 } if (sif == "") sif = $4 }
/^http [0-9]/ && NF >= 4 { if ($2 == "0.0.0.0" && $3 == "0.0.0.0") { nh++; HA[nh] = $4 } if (sif == "") sif = $4 }
/^ssh timeout / { sto = $3 }
/^snmp-server community / { nc++; SC[nc] = $0; SN[nc] = $3; SW[nc] = 0 }
/^logging host / { if ($4 == lh || $3 == lh) haslog = 1 }
/^ntp server / { if ($3 == ntp) hasntp = 1 }
/^banner (login|motd) / { banner = 1 }
END {
    if (nt) { F("telnet", "HIGH", "telnet management is allowed (" nt " line(s))", "f"); for (i = 1; i <= nt; i++) { X("telnet", "no " T[i]); U("telnet", T[i]) } } else O("no telnet management")
    if ((na2 || nh) && na) { F("mgmt", "HIGH", "SSH" (nh ? "/ASDM" : "") " management is open to any address", "f")
        for (i = 1; i <= na2; i++) { for (k = 1; k <= na; k++) X("mgmt", "ssh " AN[k] " " mask(AP[k]) " " SA[i]); X("mgmt", "no ssh 0.0.0.0 0.0.0.0 " SA[i]); U("mgmt", "ssh 0.0.0.0 0.0.0.0 " SA[i]); for (k = 1; k <= na; k++) U("mgmt", "no ssh " AN[k] " " mask(AP[k]) " " SA[i]) }
        for (i = 1; i <= nh; i++) { for (k = 1; k <= na; k++) X("mgmt", "http " AN[k] " " mask(AP[k]) " " HA[i]); X("mgmt", "no http 0.0.0.0 0.0.0.0 " HA[i]); U("mgmt", "http 0.0.0.0 0.0.0.0 " HA[i]); for (k = 1; k <= na; k++) U("mgmt", "no http " AN[k] " " mask(AP[k]) " " HA[i]) } }
    else if (na2 || nh) F("mgmt", "HIGH", "management is open to any address: pass --team to limit it", "-")
    else O("management limited to listed addresses")
    if (sto != "" && sto + 0 > to) { F("timeout", "MED", "SSH idle timeout is " sto " minutes", "f"); X("timeout", "ssh timeout " to); U("timeout", "ssh timeout " sto) }
    for (i = 1; i <= nc; i++) { if (dflt(SN[i])) { k = "snmp" i; F(k, "MED", "default SNMP community \"" SN[i] "\"", "f"); X(k, "no snmp-server community " SN[i]); U(k, SC[i]) } else F("snmpo" i, "LOW", "an SNMP community is set (value not shown): make sure it is not guessable", "-") }
    li = (sif == "") ? "inside" : sif
    if (lh != "" && !haslog) { F("log", "MED", "logs are not sent to " lh, "f"); X("log", "logging enable"); X("log", "logging trap informational"); X("log", "logging host " li " " lh); U("log", "no logging host " li " " lh) }
    if (ntp != "" && !hasntp) { F("ntp", "MED", "time is not taken from " ntp, "f"); X("ntp", "ntp server " ntp); U("ntp", "no ntp server " ntp) }
    if (!banner) { F("banner", "LOW", "no login banner", "f"); X("banner", "banner login " bn); U("banner", "no banner login") }
}
'
# Palo Alto (set format)
PAN_AWK='
/^set deviceconfig system permitted-ip / { pip = 1 }
/^set deviceconfig system service disable-telnet no/ { tel = 1 }
/^set deviceconfig system service disable-http no/ { http = 1 }
/snmp-community-string / { snmpc = 1 }
/^set deviceconfig system ntp-servers primary-ntp-server ntp-server-address / { if ($NF == ntp) hasntp = 1 }
/^set deviceconfig system login-banner / { banner = 1 }
/^set deviceconfig setting management idle-timeout / { ito = $NF }
END {
    if (!pip && na) { F("mgmt", "HIGH", "the management interface is open to any address (no permitted-ip)", "f"); for (i = 1; i <= na; i++) X("mgmt", "set deviceconfig system permitted-ip " AN[i] "/" AP[i]); U("mgmt", "delete deviceconfig system permitted-ip") }
    else if (!pip) F("mgmt", "HIGH", "the management interface is open to any address: pass --team to limit it", "-")
    else O("management limited by permitted-ip")
    if (tel) { F("telnet", "HIGH", "telnet management is on", "f"); X("telnet", "set deviceconfig system service disable-telnet yes"); U("telnet", "set deviceconfig system service disable-telnet no") } else O("telnet management off")
    if (http) { F("http", "HIGH", "plain HTTP management is on", "f"); X("http", "set deviceconfig system service disable-http yes"); U("http", "set deviceconfig system service disable-http no") } else O("plain HTTP management off")
    if (ito == "" || ito + 0 == 0 || ito + 0 > to) { F("timeout", "MED", "management idle timeout is " (ito == "" ? "the default (60 minutes)" : ito " minutes"), "f"); X("timeout", "set deviceconfig setting management idle-timeout " to); U("timeout", (ito == "") ? "delete deviceconfig setting management idle-timeout" : "set deviceconfig setting management idle-timeout " ito) }
    if (snmpc) F("snmp", "LOW", "an SNMP v2c community is set (value not shown): make sure it is not guessable (Device > Setup > Operations > SNMP)", "-")
    if (lh != "") F("log", "MED", "logs to " lh ": add a syslog server profile and log forwarding in the web GUI (Device > Server Profiles > Syslog)", "-")
    if (ntp != "" && !hasntp) { F("ntp", "MED", "time is not taken from " ntp, "f"); X("ntp", "set deviceconfig system ntp-servers primary-ntp-server ntp-server-address " ntp); U("ntp", "delete deviceconfig system ntp-servers primary-ntp-server") }
    if (!banner) { F("banner", "LOW", "no login banner", "f"); X("banner", "set deviceconfig system login-banner \"" bn "\""); U("banner", "delete deviceconfig system login-banner") }
}
'
# FortiGate
FG_AWK='
/^config / { sec = $0; next }
/^end/ { sec = ""; next }
$1 == "edit" { cur = $2; gsub(/"/, "", cur) }
sec == "config system interface" && $1 == "set" && $2 == "allowaccess" { ni++; IF[ni] = cur; old = ""; new = ""; for (k = 3; k <= NF; k++) { old = old (old == "" ? "" : " ") $k; if ($k != "telnet" && $k != "http") new = new (new == "" ? "" : " ") $k } if (old != new) { nb++; BI[nb] = cur; BO[nb] = old; BN[nb] = new } }
sec == "config system admin" && $1 == "edit" { nad++; AD[nad] = cur; TH[cur] = 0 }
sec == "config system admin" && $1 == "set" && $2 ~ /^trusthost[0-9]+$/ && !($3 == "0.0.0.0" && $4 == "0.0.0.0") { TH[cur] = 1 }
sec == "config system global" && $2 == "admintimeout" { ato = $3 }
sec == "config system global" && $2 == "pre-login-banner" && $3 == "enable" { banner = 1 }
sec == "config log syslogd setting" && $2 == "status" { lst = $3 }
sec == "config log syslogd setting" && $2 == "server" { lsv = $3; gsub(/"/, "", lsv) }
sec == "config system ntp" && $2 == "type" { nty = $3 }
sec == "config system ntp" && $2 == "server" { s = $3; gsub(/"/, "", s); if (s == ntp) hasntp = 1 }
sec == "config system snmp community" && $2 == "name" { s = $3; gsub(/"/, "", s); if (dflt(s)) snmpd = 1; else snmpo = 1 }
END {
    if (nb) { F("plain", "HIGH", "telnet or plain HTTP management on: " nb " interface(s)", "f"); X("plain", "config system interface"); U("plain", "config system interface")
        for (i = 1; i <= nb; i++) { X("plain", "edit \"" BI[i] "\""); X("plain", (BN[i] == "") ? "unset allowaccess" : "set allowaccess " BN[i]); X("plain", "next"); U("plain", "edit \"" BI[i] "\""); U("plain", "set allowaccess " BO[i]); U("plain", "next") }
        X("plain", "end"); U("plain", "end") } else O("no telnet or plain HTTP management")
    open = 0; for (i = 1; i <= nad; i++) if (!TH[AD[i]]) open++
    if (open && na && na <= 10) { F("mgmt", "HIGH", open " admin account(s) can log in from any address (no trusted hosts)", "f"); X("mgmt", "config system admin"); U("mgmt", "config system admin")
        for (i = 1; i <= nad; i++) if (!TH[AD[i]]) { X("mgmt", "edit \"" AD[i] "\""); U("mgmt", "edit \"" AD[i] "\""); for (k = 1; k <= na; k++) { X("mgmt", "set trusthost" k " " AN[k] " " mask(AP[k])); U("mgmt", "unset trusthost" k) } X("mgmt", "next"); U("mgmt", "next") }
        X("mgmt", "end"); U("mgmt", "end") }
    else if (open) F("mgmt", "HIGH", open " admin account(s) can log in from any address: pass --team (10 ranges at most) to limit them", "-")
    else O("every admin account has trusted hosts")
    if (ato != "" && ato + 0 > to) { F("timeout", "MED", "admin idle timeout is " ato " minutes", "f"); X("timeout", "config system global"); X("timeout", "set admintimeout " to); X("timeout", "end"); U("timeout", "config system global"); U("timeout", "set admintimeout " ato); U("timeout", "end") }
    if (snmpd) F("snmp", "MED", "a default SNMP community name is set: change it (System > SNMP)", "-")
    else if (snmpo) F("snmp", "LOW", "an SNMP community is set (value not shown): make sure it is not guessable", "-")
    if (lh != "" && !(lst == "enable" && lsv == lh)) { F("log", "MED", "logs are not sent to " lh, "f"); X("log", "config log syslogd setting"); X("log", "set status enable"); X("log", "set server \"" lh "\""); X("log", "end")
        U("log", "config log syslogd setting"); U("log", "set status " (lst == "" ? "disable" : lst)); U("log", (lsv == "") ? "unset server" : "set server \"" lsv "\""); U("log", "end") }
    if (ntp != "" && !hasntp) { F("ntp", "MED", "time is not taken from " ntp, "f"); X("ntp", "config system ntp"); X("ntp", "set ntpsync enable"); X("ntp", "set type custom"); X("ntp", "config ntpserver"); X("ntp", "edit 1"); X("ntp", "set server \"" ntp "\""); X("ntp", "next"); X("ntp", "end"); X("ntp", "end")
        U("ntp", "config system ntp"); U("ntp", "set type " (nty == "" ? "fortiguard" : nty)); U("ntp", "end") }
    if (!banner) { F("banner", "LOW", "no pre-login banner", "f"); X("banner", "config system global"); X("banner", "set pre-login-banner enable"); X("banner", "end"); U("banner", "config system global"); U("banner", "set pre-login-banner disable"); U("banner", "end") }
}
'
# VyOS (set format)
VY_AWK='
/^set service telnet/ { nt++; T[nt] = $0 }
/^set service snmp community / { n = $5; gsub(/\047/, "", n); if (dflt(n)) { if (!(n in sc)) { ns++; SN[ns] = n } sc[n] = sc[n] "\n" $0 } else snmpo = 1 }
/^set service ntp / { v14 = 1 }
/^set system ntp / { v13 = 1 }
/^set system syslog (remote|host) / { s = $5; gsub(/\047/, "", s); if (s == lh) haslog = 1 }
/^set (service|system) ntp server / { s = $5; gsub(/\047/, "", s); if (s == ntp) hasntp = 1 }
/^set system login banner pre-login / { banner = 1 }
/^set service ssh/ { ssh = 1 }
END {
    new = (v14 || !v13)
    if (nt) { F("telnet", "HIGH", "the telnet service is on", "f"); X("telnet", "delete service telnet"); for (i = 1; i <= nt; i++) U("telnet", T[i]) } else O("no telnet service")
    if (ssh) F("mgmt", "MED", "SSH has no source-address limit on the device: limit it with firewall rules (NW-20)", "-")
    for (i = 1; i <= ns; i++) { k = "snmp" i; F(k, "MED", "default SNMP community \"" SN[i] "\"", "f"); X(k, "delete service snmp community " SN[i]); m = split(sc[SN[i]], L, "\n"); for (q = 2; q <= m; q++) U(k, L[q]) }
    if (snmpo) F("snmpo", "LOW", "an SNMP community is set (value not shown): make sure it is not guessable", "-")
    if (lh != "" && !haslog) { F("log", "MED", "logs are not sent to " lh, "f"); X("log", "set system syslog " (new ? "remote" : "host") " " lh " facility all level info"); U("log", "delete system syslog " (new ? "remote" : "host") " " lh) }
    if (ntp != "" && !hasntp) { F("ntp", "MED", "time is not taken from " ntp, "f"); X("ntp", "set " (new ? "service" : "system") " ntp server " ntp); U("ntp", "delete " (new ? "service" : "system") " ntp server " ntp) }
    if (!banner) { F("banner", "LOW", "no login banner", "f"); X("banner", "set system login banner pre-login \047" bn "\047"); U("banner", "delete system login banner pre-login") }
}
'
# MikroTik (several prints, split by ===markers)
MT_AWK='
/^===/ { sec = substr($0, 4); next }
sec == "svc" && / name=/ { n = ""; a = ""; dis = ($2 == "X" || $2 ~ /^X/); for (i = 1; i <= NF; i++) { if ($i ~ /^name=/) n = substr($i, 6); else if ($i ~ /^address=/) a = substr($i, 9) } gsub(/"/, "", n); gsub(/"/, "", a)
    if (dis) next
    if (n ~ /^(telnet|ftp|www|api)$/) { np++; PL[np] = n } else if (n ~ /^(ssh|winbox|www-ssl|api-ssl)$/ && a == "") { no++; OP[no] = n } }
sec == "snmp" && /enabled: *yes/ { snmpon = 1 }
sec == "snmp" && / name=/ { for (i = 1; i <= NF; i++) if ($i ~ /^name=/) { n = substr($i, 6); gsub(/"/, "", n); if (dflt(n)) snmpd = 1 } }
sec == "log" && / target=remote/ && index($0, "remote=" lh) { haslog = 1 }
sec == "ntp" && /enabled: *yes/ { ntpon = 1 }
sec == "ntp" && /servers:/ { v7 = 1 }
sec == "ntp" && index($0, ntp) && ntp != "" { hasntp = 1 }
sec == "mac" && /allowed-interface-list:/ { mac = $NF }
sec == "macwb" && /allowed-interface-list:/ { macwb = $NF }
sec == "note" && /show-at-login: *yes/ { banner = 1 }
END {
    if (np) { F("plain", "HIGH", "insecure services on:" svcs(PL, np) " (clear text)", "f"); for (i = 1; i <= np; i++) { X("plain", "/ip service disable " PL[i]); U("plain", "/ip service enable " PL[i]) } } else O("telnet, ftp, www and api are off")
    if (no && na) { F("mgmt", "HIGH", "management open to any address:" svcs(OP, no), "f"); l = ""; for (k = 1; k <= na; k++) l = l (k > 1 ? "," : "") AN[k] "/" AP[k]
        for (i = 1; i <= no; i++) { X("mgmt", "/ip service set " OP[i] " address=" l); U("mgmt", "/ip service set " OP[i] " address=\"\"") } }
    else if (no) F("mgmt", "HIGH", "management open to any address:" svcs(OP, no) ": pass --team to limit it", "-")
    else O("ssh and winbox limited to listed addresses (or off)")
    if ((mac != "" && mac != "none") || (macwb != "" && macwb != "none")) { F("mac", "HIGH", "MAC telnet / MAC WinBox answer on " (mac != "none" ? mac : macwb) " interfaces (no IP needed to reach the router)", "f")
        X("mac", "/tool mac-server set allowed-interface-list=none"); X("mac", "/tool mac-server mac-winbox set allowed-interface-list=none")
        U("mac", "/tool mac-server set allowed-interface-list=" (mac == "" ? "all" : mac)); U("mac", "/tool mac-server mac-winbox set allowed-interface-list=" (macwb == "" ? "all" : macwb)) }
    if (snmpon && snmpd) F("snmp", "MED", "SNMP is on with a default community name: change it (IP > SNMP)", "-")
    if (lh != "" && !haslog) { F("log", "MED", "logs are not sent to " lh, "f"); X("log", "/system logging action add name=btremote target=remote remote=" lh); X("log", "/system logging add topics=info action=btremote")
        U("log", "/system logging remove [find action=btremote]"); U("log", "/system logging action remove [find name=btremote]") }
    if (ntp != "" && !(ntpon && hasntp)) { F("ntp", "MED", "time is not taken from " ntp, "f"); X("ntp", "/system ntp client set enabled=yes " (v7 ? "servers=" : "primary-ntp=") ntp); U("ntp", "/system ntp client set enabled=" (ntpon ? "yes" : "no")) }
    if (!banner) { F("banner", "LOW", "no login banner", "f"); X("banner", "/system note set show-at-login=yes note=\"" bn "\""); U("banner", "/system note set show-at-login=no") }
}
function svcs(a, n,   s, i) { s = ""; for (i = 1; i <= n; i++) s = s " " a[i]; return s }  # awk, not shell: posix-ok
'
# check VENDOR RAWFILE ALLOWED -> the lines (see above)
check() {
    case "$1" in cisco-ios) _ck=$IOS_AWK ;; cisco-asa) _ck=$ASA_AWK ;; paloalto) _ck=$PAN_AWK ;; fortigate) _ck=$FG_AWK ;; vyos) _ck=$VY_AWK ;; mikrotik) _ck=$MT_AWK ;; esac
    # prompts and echoed commands off the front of each line
    sed 's/^[A-Za-z0-9_.@()-]*[>#] *//' "$2" | awk -v US="$US" -v allowed="$3" -v lh="$LOGHOST" -v ntp="$NTP" -v bn="$BANNER" -v to="$TO" "$CHECK_AWK$_ck"
}
# allowed DEVICE-ADDRESS -> --team plus this box
allowed() { _al=$TEAM; [ -n "$TEAM" ] && [ -n "$1" ] && _al="$_al,$1/32"; printf '%s' "$_al"; }

# ---- 1. Read and check every device -------------------------------------------------------
header "1/4  devices"
: >"$W/find"; : >"$W/ok"; NDEV=0; NFAIL=0
while IFS='|' read -r _n _a _v _u _p; do
    case "$_v" in
        pfsense|opnsense) cc_show "$C_YEL" "  [*] $_n ($_v): do it in the web GUI - System > Advanced > Admin Access (HTTPS only, anti-lockout, SSH), Status > System Logs > Settings (remote log server), System > General Setup (time server)"; continue ;;
        linux) cc_show "$C_YEL" "  [*] $_n (linux): use LX-22 (SSH hardening) and LX-25 (firewall) on it"; continue ;;
    esac
    if ! cc_guard host "$_a" || ! cc_guard host "$_n"; then cc_show "$C_GRY" "  $_n: protected device, skipped"; continue; fi
    if ! readdev "$_v" "$_u" "$_a" "$_p" "$W/raw.$_n"; then
        NFAIL=$((NFAIL + 1)); cc_show "$C_RED" "  [x] $_n ($_a, $_v): could not log in as $_u ($(grep -v '^$' "$W/err" | tail -n 1 | cut -c1-70))"; continue
    fi
    _me=$(my_addr "$_a")
    [ -z "$_me" ] && [ -n "$TEAM" ] && cc_show "$C_YEL" "  [*] $_n: cannot tell this box's address towards it: pass --me ADDRESS, or the management limit may leave this box out"
    check "$_v" "$W/raw.$_n" "$(allowed "$_me")" >"$W/chk.$_n"
    NDEV=$((NDEV + 1)); printf '%s|%s|%s|%s|%s|%s\n' "$_n" "$_a" "$_v" "$_u" "$_p" "$_me" >>"$W/read"
    cc_show "" ""
    cc_show "$C_CYN" "  $_n ($_a, $_v)"
    while IFS="$US" read -r _k _i _l _t _d; do
        case "$_k" in
            O) cc_show "$C_GRN" "    [ok] $_i" ;;
            F) case "$_l" in HIGH) cc_show "$C_RED" "    [!] $_t" ;; MED) cc_show "$C_YEL" "    [*] $_t" ;; *) cc_show "$C_GRY" "    [-] $_t" ;; esac
               j "$_n" "$_i" "$_l" "$_t" "$_d" >>"$W/find" ;;
        esac
    done <"$W/chk.$_n"
done <"$W/devices"
[ "$NDEV" -eq 0 ] && cc_show "$C_RED" "  [x] no device answered"
awk -F"$US" '{ printf "%-14s %-4s %s\n", $1, $3, $4 }' "$W/find" >"$CC_RUN_DIR/findings.txt"

# ---- 2. Questions ---------------------------------------------------------------------------
header "2/4  what to fix (Enter = the default in capitals)"
: >"$W/plan"; _all=0
while IFS="$US" read -r _n _i _l _t _d; do
    [ "$_d" = "-" ] && continue
    if [ "$_all" = 0 ]; then
        case "$_i" in
            mgmt) _how="limit it to $TEAM and this box; a new login is tested, then you confirm from another machine" ;;
            telnet|plain) _how="turn it off; SSH (and HTTPS) stay" ;;
            *) _how="change it; the undo puts it back" ;;
        esac
        cc_choose "$_n: $_t. What now?" "$_d" "f=fix it ($_how)" "l=leave it" "a=all the rest: take their defaults"
        case "$CC_CHOICE" in a) _all=1 ;; *) _d=$CC_CHOICE ;; esac
    fi
    [ "$_d" = f ] && j "$_n" "$_i" "$_t" >>"$W/plan"
done <"$W/find"
NCH=$(grep -c . "$W/plan")
awk -F"$US" '{ print $1 ": " $3 }' "$W/plan" >"$CC_RUN_DIR/plan.txt"
while IFS= read -r _l; do cc_show "$C_YEL" "  [~] fix $_l"; done <"$CC_RUN_DIR/plan.txt"
[ "$NCH" -eq 0 ] && cc_show "$C_GRN" "  [ok] Nothing to change."

# ---- 3. Apply ---------------------------------------------------------------------------
header "3/4  apply"
# wrap VENDOR -> config mode in / out, and save (one line each, "-" = none)
pre()  { case "$1" in cisco-*) printf 'configure terminal\n' ;; paloalto) printf 'configure\n' ;; vyos) printf 'source /opt/vyatta/etc/functions/script-template\nconfigure\n' ;; esac; }
post() { case "$1" in cisco-*) printf 'end\n' ;; paloalto|vyos) printf 'commit\n' ;; esac; }
save() { case "$1" in cisco-*) printf 'write memory\n' ;; paloalto) printf 'exit\n' ;; vyos) printf 'save\nexit\n' ;; esac; }
quit() { case "$1" in mikrotik) printf '/quit\n' ;; *) printf 'exit\n' ;; esac; }
preamble() { case "$1" in cisco-ios) en "$1"; printf 'terminal length 0\n' ;; cisco-asa) en "$1"; printf 'terminal pager 0\n' ;; paloalto) printf 'set cli pager off\n' ;; esac; }
verify_cmds() {
    case "$1" in
        cisco-*|paloalto) printf 'show clock\nexit\n' ;;
        fortigate) printf 'get system status\nexit\n' ;;
        mikrotik) printf '/system identity print\n/quit\n' ;;
        *) printf 'id\nexit\n' ;;
    esac
}
# try_login VENDOR USER ADDRESS PORT -> 0 if a NEW session logs in
try_login() {
    verify_cmds "$1" >"$W/vin"; _tu=$2; _ta=$3; _tp=$4
    sshopts >"$W/opts"; set --; while IFS= read -r _o; do set -- "$@" "$_o"; done <"$W/opts"
    SSHPASS=$BT_NET_PASS "$SSHPASS_BIN" -e "$SSH" "$@" -p "$_tp" "$_tu@$_ta" <"$W/vin" >"$W/vout" 2>"$W/verr"
}
nap() { sleep "$1" & _nap=$!; wait "$_nap"; }
# lines DEVICE X|U IDS-FILE -> the fix (X, in plan order) or undo (U, in reverse) lines
lines() {
    if [ "$2" = X ]; then _ids=$(cat "$3"); else _ids=$(awk '{ l[NR] = $0 } END { for (i = NR; i > 0; i--) print l[i] }' "$3"); fi
    for _id in $_ids; do awk -F"$US" -v k="$2" -v id="$_id" '$1 == k && $2 == id { print $3 }' "$W/chk.$1"; done
}
# write_undo VENDOR DEVICE ADDRESS USER PORT -> undo/DEVICE.sh (the undo lines; no password in it)
write_undo() {
    mkdir -p "$CC_RUN_DIR/undo"; _uf="$CC_RUN_DIR/undo/$2.sh"
    {
        printf '#!/bin/sh\n# Puts back what NW-21 changed on %s.  Needs the device password in BT_NET_PASS' "$2"
        case "$1" in cisco-*) [ "$ENABLE" = 1 ] && printf ' (and BT_NET_ENABLE)' ;; esac
        printf '.\n[ -n "$BT_NET_PASS" ] || { echo "set BT_NET_PASS to the device password first" >&2; exit 1; }\n'
        printf 'SSHPASS=$BT_NET_PASS; export SSHPASS\n{\n'
        # The enable password is never written here: it is read when the undo runs.
        case "$1" in cisco-*) [ "$ENABLE" = 1 ] && printf '    printf "enable\\n%%s\\n" "$BT_NET_ENABLE"\n' ;; esac
        printf "    cat <<'CMDS'\n"
        cat "$W/undo.$2"
        printf 'CMDS\n} | %s -e %s %s-p %s %s\n' "$(cc_shquote "$SSHPASS_BIN")" "$(cc_shquote "$SSH")" "$(sshopts | while IFS= read -r _o; do printf '%s ' "$(cc_shquote "$_o")"; done)" "$5" "$(cc_shquote "$4@$3")"
    } >"$_uf"
    chmod 700 "$_uf"; printf '%s' "$_uf"
}
NOK=0; NBAD=0; APPLIED=0
trap '' PIPE
if [ "$NCH" -eq 0 ]; then :
elif [ "$CC_APPLY" != 1 ]; then
    cc_show "$C_GRY" "  Dry run: nothing was changed. Run again with --apply (try ONE device first: --device)."
    # shellcheck disable=SC2034  # read by cc_finish
    CC_N_WOULD=$NCH
elif cc_ask "Do these $NCH change(s) now, one device at a time?" Y "yes (each device: new login tested, put back if it fails)" "no, change nothing"; then
    APPLIED=1
    while IFS='|' read -r _n _a _v _u _p _me; do
        awk -F"$US" -v d="$_n" '$1 == d { print $2 }' "$W/plan" >"$W/ids.$_n"
        [ -s "$W/ids.$_n" ] || continue
        cc_show "" ""; cc_show "$C_CYN" "  -- $_n ($_v): $(tr '\n' ' ' <"$W/ids.$_n")"
        { pre "$_v"; lines "$_n" X "$W/ids.$_n"; post "$_v"; } >"$W/fix.$_n"
        { pre "$_v"; lines "$_n" U "$W/ids.$_n"; post "$_v"; save "$_v"; } >"$W/undo.$_n"
        _risky=0; grep -qxE 'mgmt|telnet|plain' "$W/ids.$_n" && _risky=1
        # 1. One session stays open: the changes go in through a FIFO.
        rm -f "$W/fifo"; mkfifo "$W/fifo"
        sshopts >"$W/opts"; set --; while IFS= read -r _o; do set -- "$@" "$_o"; done <"$W/opts"
        SSHPASS=$BT_NET_PASS "$SSHPASS_BIN" -e "$SSH" "$@" -p "$_p" "$_u@$_a" <"$W/fifo" >"$W/sess.$_n" 2>"$W/sess.err" &
        _spid=$!
        exec 3>"$W/fifo"
        { preamble "$_v"; cat "$W/fix.$_n"; } >&3 2>/dev/null
        _w=$WAIT; [ "$_v" = paloalto ] && _w=$CWAIT
        nap "$_w"
        if ! kill -0 "$_spid" 2>/dev/null; then
            exec 3>&-; wait "$_spid" 2>/dev/null
            if try_login "$_v" "$_u" "$_a" "$_p"; then
                cc_show "$C_YEL" "  [*] $_n: the device closed the change session early; a new login still works - check the changes by hand"
            else
                cc_show "$C_RED" "  [x] $_n: the change session closed and a new login FAILS: check this device from its console NOW (undo/$_n.sh holds the put-back commands)"
            fi
            write_undo "$_v" "$_n" "$_a" "$_u" "$_p" >/dev/null
            NBAD=$((NBAD + $(grep -c . "$W/ids.$_n"))); continue
        fi
        # 2. A NEW login from this box.
        _keep=0
        if try_login "$_v" "$_u" "$_a" "$_p"; then
            _keep=1
            # 3. Management changes: confirm from another machine before saving.
            if [ "$_risky" = 1 ] && [ "$CC_BATCH" != 1 ] && _cc_can_ask; then
                cc_show "$C_YEL" "  [*] A new login from this box works. Now log in to $_n from ANOTHER team machine (or its web page)."
                CC_TIMER_DEADLINE=$(( $(cc_now) + TIMER ))
                cc_ask_keep || _keep=0
                # shellcheck disable=SC2034  # read by the library's question timer
                CC_TIMER_DEADLINE=0
                [ "$_keep" = 0 ] && cc_show "$C_YEL" "  [*] Not confirmed: putting $_n back"
            fi
        else
            cc_show "$C_RED" "  [x] $_n: a new login FAILED after the change: putting it back through the open session"
        fi
        if [ "$_keep" = 1 ]; then
            { save "$_v"; quit "$_v"; } >&3 2>/dev/null
            exec 3>&-; wait "$_spid" 2>/dev/null
            _uf=$(write_undo "$_v" "$_n" "$_a" "$_u" "$_p")
            cc_undo_add "put $_n back as it was before NW-21" "sh $(cc_shquote "$_uf")"
        else
            { cat "$W/undo.$_n"; quit "$_v"; } >&3 2>/dev/null
            exec 3>&-; wait "$_spid" 2>/dev/null
            nap "$_w"
            if try_login "$_v" "$_u" "$_a" "$_p"; then cc_show "$C_GRN" "  [+] $_n: put back, and a new login works again"
            else cc_show "$C_RED" "  [x] $_n: put back, but a new login STILL fails: check it from the console NOW"; fi
            NBAD=$((NBAD + $(grep -c . "$W/ids.$_n"))); continue
        fi
        # 4. Read again: is each finding gone?
        if readdev "$_v" "$_u" "$_a" "$_p" "$W/after.$_n"; then
            check "$_v" "$W/after.$_n" "$(allowed "$_me")" >"$W/chk2.$_n"
            while IFS= read -r _id; do
                _t=$(awk -F"$US" -v id="$_id" '$1 == "F" && $2 == id { print $4; exit }' "$W/chk.$_n")
                if awk -F"$US" -v id="$_id" '$1 == "F" && $2 == id { f = 1 } END { exit !f }' "$W/chk2.$_n"; then NBAD=$((NBAD + 1)); cc_show "$C_RED" "  [x] $_n: still there: $_t"
                else NOK=$((NOK + 1)); cc_show "$C_GRN" "  [+] $_n: fixed: $_t"; fi
            done <"$W/ids.$_n"
        else
            cc_show "$C_YEL" "  [*] $_n: changes sent and a new login worked, but reading it again failed: check by hand"
            NOK=$((NOK + $(grep -c . "$W/ids.$_n")))
        fi
    done <"$W/read"
else cc_show "$C_GRY" "  Nothing done."; fi
# shellcheck disable=SC2034  # read by cc_finish
CC_N_DONE=$NOK
# shellcheck disable=SC2034  # read by cc_finish
CC_N_FAIL=$((NBAD + NFAIL))

# ---- 4. Summary ---------------------------------------------------------------------------
header "4/4  summary"
{
    printf '==========[ summary ]==========\n'
    printf 'NW-21 Network device hardening | %s\n' "$([ "$APPLIED" = 1 ] && echo APPLIED || echo 'DRY RUN - nothing changed')"
    printf 'Devices read: %d   could not log in: %d\n' "$NDEV" "$NFAIL"
    printf 'Found: %d HIGH, %d MED, %d LOW\n' "$(grep -c "${US}HIGH$US" "$W/find")" "$(grep -c "${US}MED$US" "$W/find")" "$(grep -c "${US}LOW$US" "$W/find")"
    [ -s "$CC_RUN_DIR/plan.txt" ] && { printf 'Changes%s:\n' "$([ "$APPLIED" = 1 ] || echo ' planned')"; sed 's/^/  /' "$CC_RUN_DIR/plan.txt"; }
    [ "$APPLIED" = 1 ] && printf 'Done: %d   Failed or put back: %d\n' "$NOK" "$NBAD"
    [ -d "$CC_RUN_DIR/undo" ] && printf 'Undo a device: BT_NET_PASS=... sh %s/undo/DEVICE.sh\n' "$CC_RUN_DIR"
    printf '\nNext: NW-01 again (the changes become the saved copy), then SH-03 --hosts to check every scored service still answers.\n'
} >"$CC_RUN_DIR/summary.txt"
while IFS= read -r _l; do case "$_l" in ==*|NW-21*) cc_show "$C_CYN" "$_l" ;; *'put back: '[1-9]*|*'log in: '[1-9]*) cc_show "$C_RED" "$_l" ;; *) cc_show "" "$_l" ;; esac; done <"$CC_RUN_DIR/summary.txt"
rm -rf "$W"
cc_finish
