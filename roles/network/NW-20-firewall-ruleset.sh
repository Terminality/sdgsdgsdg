#!/bin/sh
# =============================================================================
# ID:       NW-20
# NAME:     Firewall ruleset
# ROLE:     Network  (wave 2, after NW-01 backup; one device at a time)
# KIND:     changes - dry run unless --apply
# VERSION:  1.2.0
#
# PURPOSE
#   Puts a short, readable set of rules at the TOP of the network firewall
#   so that only the scored services can be reached from outside:
#     ON by default (asked):
#       allow   your team's addresses, everything
#       allow   any address -> each scored box, its scored ports only
#               (any address, so the scoring engine always gets through)
#       allow   ping in to the scored boxes (every box has a ping check)
#       block   everything else coming in from outside, logged
#     OFF by default (asked separately, default no):
#       outgoing limits: the servers may only start connections to DNS,
#       NTP and what you list (stops web-shell callbacks and exfil);
#       everything else they start is blocked and logged
#       threat prevention (Palo Alto, FortiGate) on the scored rules
#   Every rule is named bt-... so it is easy to see, and the old rules are
#   left where they were (below ours).  Nothing is deleted.
#
#   Brands: paloalto, cisco-asa, fortigate, mikrotik, openwrt (its own
#   nftables table bt_fw, loaded again by fw4 at every reload and boot through
#   a uci include; the router's port forwards are kept open, asked), linux (a Linux router:
#   its own nftables table).  pfSense / OPNsense: the same plan as web GUI
#   steps.  Cisco IOS, VyOS: the plan is shown, not applied.
#
#   HOW IT KEEPS THE SCORED SERVICES UP
#     - before: every scored box:port (and ping) is tried from this box
#     - the rules go in through one open session to the firewall
#     - the undo is written before anything is sent
#     - after: the same tries; one that answered before and no longer does,
#       a command the firewall refused, a Palo Alto commit that did not
#       work, or a new login that fails -> everything is put back at once
#     - Ctrl-C (or a kill) while a firewall is being changed -> put back
#     - then you are asked to check the scoreboard / your services within
#       --timer seconds (default 120); no answer or "n" -> put back
#     - REVERT LATER: sh <run>/undo/DEVICE.sh, or this script with --remove
#       (removes every bt- rule it added, the device's old setup back)
#
#   QUESTIONS (Enter takes the default in capitals; a flag answers each):
#     the scored boxes and their ports      --allow, --file, or typed in
#       (offered from the newest SH-03 scan when there is one)
#     is this list right?                   Y
#     your team's addresses                 --team
#     addresses you log in from outside     --remote
#     ports you log in on (kept open)       --login-ports   (22,3389)
#     which side is outside / servers       --outside, --inside
#     each rule                             [k]eep (default) / [s]kip
#     block everything else coming in?      Y
#     limit what the servers send out?      N   (--restrict-out)
#       DNS servers, NTP, extra destinations
#     threat prevention on scored rules?    N   (--threat)
#     apply this plan to DEVICE?            Y   (--apply)
#     keep it (checked the scoreboard)?     Y within --timer, else put back
#
# USAGE
#   BT_NET_PASS='pw' sh NW-20-firewall-ruleset.sh --device fw1,10.0.0.1,paloalto
#   BT_NET_PASS='pw' sh NW-20-firewall-ruleset.sh --device fw1,10.0.0.1,paloalto \
#       --allow 10.0.0.5:80,443 --allow 10.0.0.9:25,143,993,53/udp --team 10.0.0.0/24 --apply
#   BT_NET_PASS='pw' sh NW-20-firewall-ruleset.sh --device fw1,10.0.0.1,paloalto --remove --apply
#
# OPTIONS
#   --device NAME,ADDRESS,VENDOR[,USER[,PORT]]   the firewall (repeat)
#   --hosts FILE       or the devices from the host list
#   --allow ADDR:PORTS a scored box and its ports: 80,443,53/udp,8000-8100
#                      (repeat; no ports = ping only)
#   --file FILE        the scored boxes, one per line:  ADDR  PORTS...  # note
#   --scan DIR         an SH-03 run folder to offer ports from (default: the
#                      newest netscan-N under --out)
#   --team CIDR,...    your team's addresses (allowed everything)
#   --remote CIDR,...  addresses you log in from OUTSIDE (remote teammates,
#                      VPN): allowed everything, like the team (asked)
#   --login-ports P,.. ports you log in to the boxes on (default 22,3389):
#                      kept open to every scored box from any address, so
#                      the team is never blocked; "none" closes them (asked)
#   --outside NAME     the outside zone / interface (else asked)
#   --inside NAME      the zone / interface the servers are on (else asked;
#                      "all" = every zone but outside: Palo Alto, FortiGate)
#   --restrict-out     also limit what the servers start (asked otherwise, default no)
#   --dns IP,...       DNS servers the servers may use (with --restrict-out)
#   --ntp IP           time server the servers may use
#   --out-allow ADDR:PORTS   another destination the servers may reach (repeat)
#   --threat           threat prevention on the scored rules (asked otherwise)
#   --remove           take out every bt- rule this script put on the device(s)
#   --no-forwards      OpenWRT: do not keep the router's port forwards open
#                      (asked otherwise, default keep)
#   --user NAME / --ask-password / --enable-env / --legacy-ssh   as NW-21
#   --wait N           seconds before the checks (default 5)
#   --commit-wait N    Palo Alto: at most this many seconds for the commit
#                      to say it worked (default 120), else put back
#   --timer N          seconds to confirm (default 120)
#   --no-color         no colours
#   --help             this text plus the common options
#
# OUTPUTS  (under --out, in firewall-ruleset-N/)
#   output.txt, scored.txt, plan.txt (every rule in plain words, per device),
#   commands-DEVICE.txt (exactly what is sent), checks.txt, summary.txt
#   undo/DEVICE.sh     takes the rules out again (needs BT_NET_PASS)
#   nw20-DEVICE.undo   in --out: what --remove sends (kept between runs)
#
# DEPENDS ON
#   ssh, sshpass, mkfifo; nc (or bash) for the service checks; ping.
#
# TESTED ON
#   A stand-in device for every brand (commands written from each brand's
#   documentation) under dash, bash, busybox sh, ksh93, mksh and yash with
#   gawk, mawk and busybox awk; the Linux router brand's ruleset checked by
#   the real nft.  NOT yet on a real Palo Alto, ASA, FortiGate or MikroTik:
#   run it without --apply, read plan.txt and commands-DEVICE.txt, then
#   --apply on ONE device.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - Scored boxes are given by their INSIDE address (the one in the host
#     list).  Palo Alto and FortiGate match the OUTSIDE (NAT) address, so
#     their NAT rules / virtual IPs that lead to a scored box are read and
#     those names are added to its rules (shown, and listed in plan.txt).
#     ASA, MikroTik and Linux match the inside address after NAT.
#   - The checks run from this box: if this box is inside, they may not
#     pass through the firewall.  Watch the scoreboard during the countdown.
#   - The confirm countdown only expires by itself in shells with "read -t"
#     (bash, ksh, mksh, yash, busybox); dash waits for the answer.
#   - Cisco ASA: one access list per interface, so BT-IN replaces the one
#     bound to the outside interface (its old one is put back on undo).
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

VENDORS="cisco-ios cisco-asa paloalto fortigate vyos mikrotik linux pfsense opnsense openwrt"

usage() {
    cat <<'USAGE'
NW-20 Firewall ruleset - only the scored services in, everything else blocked; checked, easy to revert
  BT_NET_PASS=pw sh NW-20-firewall-ruleset.sh --device NAME,ADDRESS,VENDOR [--allow ADDR:PORTS] [--apply]

  --device NAME,ADDRESS,VENDOR[,USER[,PORT]]   the firewall (repeat), or --hosts FILE
  --allow ADDR:PORTS   a scored box: 80,443,53/udp,8000-8100 (repeat)
  --file FILE          scored boxes, one per line: ADDR PORTS... # note
  --scan DIR           an SH-03 run folder to offer ports from
  --team CIDR,...      your team's addresses
  --remote CIDR,...    addresses you log in from outside (allowed everything)
  --login-ports P,...  ports you log in on, kept open to every box (default 22,3389; none)
  --outside NAME / --inside NAME   zones or interfaces (else asked)
  --restrict-out       also limit what the servers start (default: asked, no)
  --dns IP,... / --ntp IP / --out-allow ADDR:PORTS   what they may still reach
  --threat             threat prevention on the scored rules
  --remove             take out every bt- rule this script added
  --no-forwards         OpenWRT: do not keep the router's port forwards open (asked)
  --user NAME / --ask-password / --enable-env / --legacy-ssh
  --wait N / --commit-wait N / --timer N
  --no-color           no colours
  --help               show this text
USAGE
    cc_usage_common
}

NL='
'
HOSTS=""; DEVICES=""; DEFUSER="admin"; ASK=0; ENABLE=0; LEGACY=0; COLOR=1
KEEPFWD=""; DEFUSER_SET=0; ALLOWS=""; SFILE=""; SCAN=""; TEAM=""; REMOTE=""; LOGINP=""; OUTSIDE=""; INSIDE=""; RESTRICT=""; DNS=""; NTP=""; OUTALLOW=""; THREAT=""; REMOVE=0
WAIT=5; CWAIT=120; TIMER=120
num() { case "$2" in ''|*[!0-9]*) cc_die 2 "$1 needs a whole number" ;; esac; }
okname() { case "$2" in ''|*[!A-Za-z0-9_./:-]*) cc_die 2 "$1: letters, digits and . _ / : - only" ;; esac; }
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --apply)        CC_APPLY=1; shift ;;
        --hosts)        [ $# -ge 2 ] || cc_die 2 "--hosts needs a file"; [ -r "$2" ] || cc_die 2 "--hosts: cannot read $2"; HOSTS=$2; shift 2 ;;
        --device)       [ $# -ge 2 ] || cc_die 2 "--device needs NAME,ADDRESS,VENDOR"; DEVICES="$DEVICES$2$NL"; shift 2 ;;
        --user)         [ $# -ge 2 ] || cc_die 2 "--user needs a name"; DEFUSER=$2; DEFUSER_SET=1; shift 2 ;;
        --ask-password) ASK=1; shift ;;
        --enable-env)   ENABLE=1; shift ;;
        --legacy-ssh)   LEGACY=1; shift ;;
        --allow)        [ $# -ge 2 ] || cc_die 2 "--allow needs ADDR:PORTS"; ALLOWS="$ALLOWS$2$NL"; shift 2 ;;
        --file)         [ $# -ge 2 ] || cc_die 2 "--file needs a file"; [ -r "$2" ] || cc_die 2 "--file: cannot read $2"; SFILE=$2; shift 2 ;;
        --scan)         [ $# -ge 2 ] || cc_die 2 "--scan needs a folder"; [ -d "$2" ] || cc_die 2 "--scan: not a folder: $2"; SCAN=$2; shift 2 ;;
        --team)         [ $# -ge 2 ] || cc_die 2 "--team needs addresses"; TEAM="$TEAM,$2"; shift 2 ;;
        --remote)       [ $# -ge 2 ] || cc_die 2 "--remote needs addresses"; REMOTE="$REMOTE,$2"; shift 2 ;;
        --login-ports)  [ $# -ge 2 ] || cc_die 2 "--login-ports needs ports or none"; LOGINP=$2; shift 2 ;;
        --outside)      [ $# -ge 2 ] || cc_die 2 "--outside needs a name"; okname "$1" "$2"; OUTSIDE=$2; shift 2 ;;
        --inside)       [ $# -ge 2 ] || cc_die 2 "--inside needs a name"; okname "$1" "$2"; INSIDE=$2; shift 2 ;;
        --restrict-out) RESTRICT=y; shift ;;
        --dns)          [ $# -ge 2 ] || cc_die 2 "--dns needs addresses"; DNS="$DNS,$2"; shift 2 ;;
        --ntp)          [ $# -ge 2 ] || cc_die 2 "--ntp needs an address"; NTP=$2; shift 2 ;;
        --out-allow)    [ $# -ge 2 ] || cc_die 2 "--out-allow needs ADDR:PORTS"; OUTALLOW="$OUTALLOW$2$NL"; shift 2 ;;
        --threat)       THREAT=y; shift ;;
        --remove)       REMOVE=1; shift ;;
        --no-forwards)  KEEPFWD=n; shift ;;
        --wait)         num "$1" "${2:-}"; WAIT=$2; shift 2 ;;
        --commit-wait)  num "$1" "${2:-}"; CWAIT=$2; shift 2 ;;
        --timer)        num "$1" "${2:-}"; TIMER=$2; shift 2 ;;
        --no-color|--no-colour) COLOR=0; shift ;;
        --help|-h)      usage; exit 0 ;;
        *)              cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
IPRE='[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}'
isip()   { printf '%s' "$1" | grep -q "^$IPRE\$"; }
iscidr() { printf '%s' "$1" | grep -q "^$IPRE\\(/[0-9]\\{1,2\\}\\)\\{0,1\\}\$"; }
TEAM=${TEAM#,}; DNS=${DNS#,}
for _t in $(printf '%s' "$TEAM" | tr ',' ' '); do iscidr "$_t" || cc_die 2 "--team: IPv4 addresses or CIDRs (10.0.0.0/24)"; done
REMOTE=${REMOTE#,}
for _t in $(printf '%s' "$REMOTE" | tr ',' ' '); do iscidr "$_t" || cc_die 2 "--remote: IPv4 addresses or CIDRs"; done
case "$LOGINP" in ''|none) ;; *[!0-9,]*|,*|*,) cc_die 2 "--login-ports: port numbers separated by commas (22,3389), or none" ;; esac
for _t in $(printf '%s' "$DNS" | tr ',' ' '); do isip "$_t" || cc_die 2 "--dns: IPv4 addresses"; done
[ -z "$NTP" ] || isip "$NTP" || cc_die 2 "--ntp: an IPv4 address"

cc_init "NW-20" "Firewall ruleset" changes
# No firewall named, no host list and nobody to ask: stop before a run folder.
if [ -z "$HOSTS$DEVICES" ] && ! _cc_can_ask && ! cc_net_hostfile >/dev/null; then
    cc_die 2 "give the firewall: --device NAME,ADDRESS,VENDOR (try --help)"
fi
# shellcheck disable=SC2034  # read by cc_color_init
[ "$COLOR" = 1 ] || CC_NOCOLOR=1
cc_color_init
cc_use_numbered_dir firewall-ruleset
rmdir "$CC_RUN_DIR/raw" 2>/dev/null
OUTF="$CC_RUN_DIR/output.txt"
grep -v '\[NOTE\]\|\[DEBUG\]' "$CC_LOG" >"$OUTF" 2>/dev/null || : >"$OUTF"
# shellcheck disable=SC2034  # CC_TEE is read by the library's log functions
CC_TEE=$OUTF
W="$CC_RUN_DIR/.work"; (umask 077; mkdir -p "$W")
US=$(printf '\037')
trap 'rm -rf "$W"; exit 130' INT TERM HUP
header() { cc_show "" ""; cc_show "$C_CYN" "==========[ $1 ]=========="; }
j() { _j=$1; shift; for _jx in "$@"; do _j="$_j$US$_jx"; done; printf '%s\n' "$_j"; }
CONFIGS="$CC_OUT/net-configs"; mkdir -p "$CONFIGS" 2>/dev/null
SSH=${BT_SSH:-$(cc_which ssh)} || cc_die 3 "ssh not found"
SSHPASS_BIN=${BT_SSHPASS:-$(cc_which sshpass)} || cc_die 3 "sshpass not found (apt install sshpass)"
cc_have mkfifo || cc_die 3 "mkfifo not found"
cc_show "$C_CYN" "NW-20 Firewall ruleset | from $CC_HOST | results in $CC_RUN_DIR"
cc_show "" "Legend: ${C_RED}[!]${C_OFF} fix now   ${C_YEL}[*]${C_OFF} look at it   ${C_GRN}[ok]${C_OFF} fine   ${C_YEL}[~] would change${C_OFF}   ${C_GRN}[+] changed${C_OFF}   ${C_RED}[x] failed${C_OFF}"
# Which firewall, and its password, when no flag said.
if [ -z "$HOSTS$DEVICES" ]; then
    cc_net_ask_devices "$DEFUSER" "$DEFUSER_SET" || cc_die 2 "no firewall given (or use --device NAME,ADDRESS,VENDOR)"
    HOSTS=$CC_NET_HOSTS; DEVICES=$CC_NET_DEVICES
fi
if [ "$ASK" = 1 ]; then
    [ -r /dev/tty ] || cc_die 3 "--ask-password needs a terminal; set BT_NET_PASS"
    printf 'Device password: ' >/dev/tty; stty -echo </dev/tty 2>/dev/null
    read -r BT_NET_PASS </dev/tty; stty echo </dev/tty 2>/dev/null; printf '\n' >/dev/tty
else
    cc_net_ask_password
fi
[ -n "${BT_NET_PASS:-}" ] || cc_die 3 "the device password is needed: set BT_NET_PASS or use --ask-password"
[ "$ENABLE" = 1 ] && [ -z "${BT_NET_ENABLE:-}" ] && cc_die 3 "--enable-env: set BT_NET_ENABLE"

# ---- Devices ------------------------------------------------------------------------------
vendor_of() {
    printf '%s' "$1" | tr 'A-Z' 'a-z' | awk '
        /cisco-ios|ios-xe|catalyst|cisco ios|cisco router|cisco switch/ { print "cisco-ios"; exit }
        /cisco-asa|asa|firepower|ftd/ { print "cisco-asa"; exit }
        /paloalto|palo alto|pan-os|panos/ { print "paloalto"; exit }
        /fortigate|fortinet|fortios/ { print "fortigate"; exit }
        /vyos|vyatta/ { print "vyos"; exit }
        /openwrt|lede|luci/ { print "openwrt"; exit }
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
[ -s "$W/devices" ] || cc_die 3 "no firewall given"
for _n in $(cut -d'|' -f1 "$W/devices"); do case "$_n" in *[!A-Za-z0-9_.-]*) cc_die 2 "device name '$_n' may only use letters, digits, '.', '_' and '-'" ;; esac; done
_bp=$(awk -F'|' '$5 !~ /^[0-9]+$/ || $5 < 1 || $5 > 65535 { print $1; exit }' "$W/devices"); [ -z "$_bp" ] || cc_die 2 "device $_bp: the SSH port must be a number from 1 to 65535"

# ---- Talking to a device ---------------------------------------------------------------
sshopts() {
    set -- -T -o ConnectTimeout=10 -o "UserKnownHostsFile=$CONFIGS/known_hosts" -o StrictHostKeyChecking=accept-new \
        -o LogLevel=ERROR -o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive -o NumberOfPasswordPrompts=1
    [ "$LEGACY" = 1 ] && set -- "$@" -o KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group1-sha1 -o HostKeyAlgorithms=+ssh-rsa -o Ciphers=+aes128-cbc,aes256-cbc,3des-cbc
    printf '%s\n' "$@"
}
read_mode() { case "$1" in mikrotik|linux|openwrt) echo exec ;; *) echo stdin ;; esac; }
en() { case "$1" in cisco-*) [ "$ENABLE" = 1 ] && printf 'enable\n%s\n' "$BT_NET_ENABLE" ;; esac; return 0; }
read_cmds() {
    case "$1" in
        cisco-asa) en "$1"; printf 'terminal pager 0\nshow running-config interface\nshow running-config access-group\nshow running-config access-list\nexit\n' ;;
        paloalto)  printf 'set cli pager off\nset cli config-output-format set\nconfigure\nshow zone\nshow address\nshow rulebase nat\nshow rulebase security\nexit\nexit\n' ;;
        fortigate) printf 'show system interface\nshow firewall vip\nshow firewall policy\nexit\n' ;;
        mikrotik)  printf ':put "===if"; /interface print terse without-paging; :put "===filter"; /ip firewall filter print terse without-paging' ;;
        linux)     printf 'echo ===if; ip -o link show; echo ===nft; if [ "$(id -u)" = 0 ]; then nft list ruleset; else sudo -n nft list ruleset; fi' ;;
        # OpenWRT: the interfaces, which one is wan, the port forwards (uci) and nft.
        openwrt)   printf 'echo ===if; ip -o link show; echo ===wan; uci -q get network.wan.device || uci -q get network.wan.ifname; echo ===fwd; uci -q show firewall | grep "^firewall\\.@redirect\\["; echo ===nft; nft list ruleset' ;;
    esac
}
readdev() {
    read_cmds "$1" >"$W/rin"; _rv=$1; _ru=$2; _ra=$3; _rp=$4; _ro=$5
    sshopts >"$W/opts"; set --; while IFS= read -r _o; do set -- "$@" "$_o"; done <"$W/opts"
    if [ "$(read_mode "$_rv")" = exec ]; then
        SSHPASS=$BT_NET_PASS "$SSHPASS_BIN" -e "$SSH" "$@" -p "$_rp" "$_ru@$_ra" "$(cat "$W/rin")" </dev/null >"$_ro" 2>"$W/err"
    else
        SSHPASS=$BT_NET_PASS "$SSHPASS_BIN" -e "$SSH" "$@" -p "$_rp" "$_ru@$_ra" <"$W/rin" >"$_ro" 2>"$W/err"
    fi
}
# send VENDOR USER ADDRESS PORT FILE -> one session that gets FILE (for undo and --remove)
send() {
    _sv=$1; _su=$2; _sa=$3; _sp=$4; _sf=$5
    case "$_sv" in cisco-*) { en "$_sv"; cat "$5"; printf 'exit\n'; } >"$W/send.in"; _sf="$W/send.in" ;; esac
    sshopts >"$W/opts"; set --; while IFS= read -r _o; do set -- "$@" "$_o"; done <"$W/opts"
    if [ "$(read_mode "$_sv")" = exec ]; then
        SSHPASS=$BT_NET_PASS "$SSHPASS_BIN" -e "$SSH" "$@" -p "$_sp" "$_su@$_sa" "$(oneline "$_sv" "$_sf")" </dev/null >>"$CC_LOG" 2>&1
    else
        SSHPASS=$BT_NET_PASS "$SSHPASS_BIN" -e "$SSH" "$@" -p "$_sp" "$_su@$_sa" <"$_sf" >>"$CC_LOG" 2>&1
    fi
}
# oneline VENDOR FILE -> the command line for an exec session (RouterOS: joined by ";")
oneline() { if [ "$1" = mikrotik ]; then tr '\n' ';' <"$2" | sed 's/;$//'; else cat "$2"; fi; }
nap() { sleep "$1" & _nap=$!; wait "$_nap"; }

# ---- --remove: put the saved undo back ----------------------------------------------------
if [ "$REMOVE" = 1 ]; then
    header "remove the bt- rules"
    NOK=0; NBAD=0
    while IFS='|' read -r _n _a _v _u _p; do
        _st="$CC_OUT/nw20-$_n.undo"
        if [ ! -s "$_st" ]; then cc_show "$C_GRY" "  $_n: no rules from NW-20 recorded for it ($_st)"; continue; fi
        cc_show "$C_CYN" "  $_n ($_v): what will be sent:"; sed 's/^/      /' "$_st" | while IFS= read -r _l; do cc_show "$C_GRY" "$_l"; done
        if [ "$CC_APPLY" != 1 ]; then cc_show "$C_GRY" "  Dry run: run again with --apply to take them out."; continue; fi
        if cc_ask "Take NW-20's rules off $_n now?" Y "yes, take them out" "no, leave them"; then
            if send "$_v" "$_u" "$_a" "$_p" "$_st"; then NOK=$((NOK + 1)); mv "$_st" "$_st.done"; cc_show "$C_GRN" "  [+] $_n: rules taken out"
            else NBAD=$((NBAD + 1)); cc_show "$C_RED" "  [x] $_n: could not log in to take them out (see $CC_LOG)"; fi
        fi
    done <"$W/devices"
    # shellcheck disable=SC2034  # read by cc_finish
    CC_N_DONE=$NOK
    # shellcheck disable=SC2034  # read by cc_finish
    CC_N_FAIL=$NBAD
    rm -rf "$W"; cc_finish; exit
fi

# ---- 1. The scored services ---------------------------------------------------------------
header "1/6  the scored services"
# $W/scored: ADDR US tcp-ports US udp-ports US note    (ports: "80,443,8000-8100")
: >"$W/scored"
# add_scored ADDR "PORT PORT/udp ..." NOTE -> one line in $W/scored (merged per address)
add_scored() {
    isip "$1" || { cc_show "$C_RED" "  [x] not an IPv4 address, skipped: $1"; return 1; }
    _tp=""; _upp=""
    for _x in $(printf '%s' "$2" | tr ',' ' '); do
        _pr=tcp; case "$_x" in */udp) _pr=udp; _x=${_x%/udp} ;; */tcp) _x=${_x%/tcp} ;; esac
        case "$_x" in ''|*[!0-9-]*|-*|*-|*-*-*) cc_show "$C_RED" "  [x] $1: not a port, skipped: $_x"; continue ;; esac
        if [ "${_x%-*}" -lt 1 ] || [ "${_x%-*}" -gt 65535 ] || [ "${_x#*-}" -lt 1 ] || [ "${_x#*-}" -gt 65535 ] || [ "${_x%-*}" -gt "${_x#*-}" ]; then
            cc_show "$C_RED" "  [x] $1: not a port (1-65535), skipped: $_x"; continue; fi
        if [ "$_pr" = udp ]; then case "$_upp," in *",$_x,"*) ;; *) _upp="$_upp,$_x" ;; esac
        else case "$_tp," in *",$_x,"*) ;; *) _tp="$_tp,$_x" ;; esac; fi
    done
    if grep -q "^$1$US" "$W/scored"; then
        awk -F"$US" -v OFS="$US" -v a="$1" -v t="${_tp#,}" -v u="${_upp#,}" '
            function merge(old, add,   n, x, i, seen, out) {  # awk, not shell: posix-ok
                n = split(old "," add, x, ","); out = ""
                for (i = 1; i <= n; i++) if (x[i] != "" && !(x[i] in seen)) { seen[x[i]] = 1; out = out (out == "" ? "" : ",") x[i] }
                return out }
            $1 == a { $2 = merge($2, t); $3 = merge($3, u) } { print }' "$W/scored" >"$W/s.n" && cat "$W/s.n" >"$W/scored"
    else j "$1" "${_tp#,}" "${_upp#,}" "$3" >>"$W/scored"; fi
}
printf '%s' "$ALLOWS" | grep . | while IFS= read -r _l; do printf '%s %s\n' "${_l%%:*}" "$(printf '%s' "$_l" | sed -n 's/^[^:]*://p')"; done >"$W/given"
[ -n "$SFILE" ] && sed 's/#.*//' "$SFILE" | awk 'NF { a = $1; $1 = ""; sub(/^ /, ""); print a " " $0 }' >>"$W/given"
if [ -n "$SFILE" ]; then awk 'index($0, "#") { n = substr($0, index($0, "#") + 1); sub(/^[ \t]+/, "", n); split($0, a, " "); if (a[1] !~ /^#/) print a[1] " " n }' "$SFILE" >"$W/notes"; else : >"$W/notes"; fi
while IFS=' ' read -r _a _ports; do add_scored "$_a" "$_ports" "$(awk -v a="$_a" '$1 == a { $1 = ""; sub(/^ /, ""); print; exit }' "$W/notes")"; done <"$W/given"
# The newest SH-03 scan offers its open ports.
# (the newest by its number: netscan-10 is newer than netscan-9)
[ -n "$SCAN" ] || SCAN=$(for _sd in "$CC_OUT"/netscan-*; do [ -d "$_sd" ] && printf '%s %s\n' "${_sd##*-}" "$_sd"; done | sort -n | tail -n 1 | cut -d' ' -f2-)
: >"$W/scanports"
# ports.txt: a " | " table (ip hostname proto port state service version);
# an older scan has csv/ports.csv
if [ -n "$SCAN" ] && [ -f "$SCAN/ports.txt" ] && head -n 1 "$SCAN/ports.txt" | grep -q ' | '; then
    awk "$CC_AWK_TABLE"'NR > 1 { tsplit($0, f); if (f[5] == "open") print f[1] " " f[4] (f[3] == "udp" ? "/udp" : "") " " f[6] }' "$SCAN/ports.txt" >"$W/scanports"
elif [ -n "$SCAN" ] && [ -f "$SCAN/csv/ports.csv" ]; then
    awk -F',' "$CC_AWK_CSV"'NR > 1 { csvsplit($0, f); if (f[5] == "open") print f[1] " " f[4] (f[3] == "udp" ? "/udp" : "") " " f[6] }' "$SCAN/csv/ports.csv" >"$W/scanports"
fi
if [ ! -s "$W/scored" ]; then
    if [ -s "$W/scanports" ] && _cc_can_ask && [ "$CC_BATCH" != 1 ]; then
        cc_show "" "  From the scan in $SCAN - each open port, asked one by one:"
        awk '{ print $1 }' "$W/scanports" | awk '!s[$0]++' >"$W/scanhosts"
        while IFS= read -r _h; do
            _keep=""
            awk -v h="$_h" '$1 == h { print $2 " " $3 }' "$W/scanports" >"$W/hp"
            while IFS=' ' read -r _pt _svc; do
                # scored-looking ports default to keep
                case "${_pt%/udp}" in 21|22|25|53|80|88|110|123|135|139|143|389|443|445|464|587|636|993|995|1433|3268|3306|3389|5432|5985|5986|8000|8080|8089|8443|9997) _d=k ;; *) _d=b ;; esac
                cc_choose "$_h port $_pt (${_svc:-unknown}): reachable from outside?" "$_d" "k=keep it open (a scored or needed service)" "b=block it from outside"
                [ "$CC_CHOICE" = k ] && _keep="$_keep $_pt"
            done <"$W/hp"
            [ -n "$_keep" ] && add_scored "$_h" "$_keep" "from the scan"
        done <"$W/scanhosts"
    elif _cc_can_ask && [ "$CC_BATCH" != 1 ]; then
        cc_show "" "  No --allow / --file given: type each scored box (its INSIDE address), Enter on an empty line when done."
        while :; do
            cc_ask_text "Scored box address (empty = done)" "" "address"; _h=$CC_ANSWER
            [ -n "$_h" ] || break
            cc_ask_text "Its scored ports, e.g. 80 443 53/udp (empty = ping only)" "" "ports"; _ps=$CC_ANSWER
            cc_ask_text "A note (what it is)" "" "note"
            add_scored "$_h" "$_ps" "$CC_ANSWER"
        done
    fi
fi
[ -s "$W/scored" ] || { rm -rf "$W"; cc_die 2 "No scored boxes: give --allow ADDR:PORTS, --file FILE, or answer the questions. Nothing was changed."; }
{ printf '%-16s %-30s %-20s %s\n' box tcp udp note; awk -F"$US" '{ printf "%-16s %-30s %-20s %s\n", $1, ($2 == "" ? "-" : $2), ($3 == "" ? "-" : $3), $4 }' "$W/scored"; } >"$CC_RUN_DIR/scored.txt"
while IFS= read -r _l; do cc_show "" "  $_l"; done <"$CC_RUN_DIR/scored.txt"
cc_show "" "  Every box also gets ping in. These are reachable from ANY address (so the scoring engine always gets through)."
if ! cc_ask "Is this list of scored boxes and ports right?" Y "yes, build the rules from it" "no, stop (fix --allow / --file and run again)"; then
    cc_show "$C_GRY" "  Stopped: nothing was changed."; rm -rf "$W"; cc_finish; exit 0
fi
SERVERS=$(cut -d"$US" -f1 "$W/scored" | tr '\n' ',' | sed 's/,$//')

# ---- 2. Team, outgoing limits, threat prevention ---------------------------------------------
header "2/6  your team, outgoing limits, threat prevention"
if [ -z "$TEAM" ] && _cc_can_ask && [ "$CC_BATCH" != 1 ]; then
    cc_ask_text "Your team's addresses (CIDR, comma separated; empty = none)" "" "addresses"
    for _t in $(printf '%s' "$CC_ANSWER" | tr ',' ' '); do iscidr "$_t" && TEAM="$TEAM,$_t" || cc_show "$C_RED" "  [x] not an address or CIDR, left out: $_t"; done
    TEAM=${TEAM#,}
fi
# Never block the team: where you log in from outside, and the ports you
# log in on, stay open.
if [ -z "$REMOTE" ] && _cc_can_ask && [ "$CC_BATCH" != 1 ]; then
    cc_ask_text "Addresses you log in to the boxes from OUTSIDE the firewall (remote teammates, VPN)? Allowed everything, like the team" "" "addresses or networks separated by commas (Enter = none, or from anywhere)"
    for _t in $(printf '%s' "$CC_ANSWER" | tr ',' ' '); do iscidr "$_t" && REMOTE="$REMOTE,$_t" || cc_show "$C_RED" "  [x] not an address or CIDR, left out: $_t"; done
    REMOTE=${REMOTE#,}
fi
# (each address once: one given as both --team and --remote counts once)
[ -n "$REMOTE" ] && TEAM=$(printf '%s,%s' "$TEAM" "$REMOTE" | tr ',' '\n' | awk 'NF && !s[$0]++' | tr '\n' ',' | sed 's/,$//')
if [ -z "$LOGINP" ]; then
    LOGINP=22,3389
    if _cc_can_ask && [ "$CC_BATCH" != 1 ]; then
        cc_ask_text "Ports you log in to the boxes on from outside? They stay open to every box from ANY address, so the team is never blocked" "$LOGINP" "port numbers separated by commas (22 SSH, 3389 RDP, 5985 WinRM), or none"
        LOGINP=$CC_ANSWER
        case "$LOGINP" in ''|none) LOGINP=none ;; *[!0-9,]*|,*|*,) cc_show "$C_RED" "  [x] not a port list: kept 22,3389"; LOGINP=22,3389 ;; esac
    fi
fi
[ -n "$TEAM" ] && cc_show "$C_GRN" "  [ok] your team ($TEAM): allowed everything" || cc_show "$C_YEL" "  [*] no team addresses: if you manage boxes from OUTSIDE the firewall, give --team or --remote, or keep their login ports open"
if [ "$LOGINP" != none ]; then
    # The login ports join every scored box's TCP ports (each port once).
    awk -F"$US" -v OFS="$US" -v lp="$LOGINP" '{ n = split($2 "," lp, p, ","); o = ""; split("", s); for (i = 1; i <= n; i++) if (p[i] != "" && !(p[i] in s)) { s[p[i]] = 1; o = o (o == "" ? "" : ",") p[i] } $2 = o; if ($4 !~ /login/) $4 = $4 ($4 == "" ? "" : ", ") "+ login " lp; print }' "$W/scored" >"$W/scored.n" && cat "$W/scored.n" >"$W/scored"
    cc_show "$C_GRN" "  [ok] login ports $LOGINP stay open to every scored box from any address (--login-ports none to close them)"
else
    cc_show "$C_YEL" "  [*] no login ports kept open: from outside, only --team / --remote addresses can log in to the boxes"
fi
if [ -z "$RESTRICT" ]; then
    cc_show "" "  Outgoing limits stop a hacked server from calling out (web-shell callbacks, downloads, data sent out, ping and DNS tunnels)."
    cc_show "" "  They can break a service that must start connections out (webmail to IMAP, a store to its database, forwarders to Splunk) - you list those next."
    cc_choose "Limit what the scored servers can START out through the firewall?" n "y=yes, only DNS, NTP and what I list" "n=no, leave outgoing traffic alone (replies to the scorer always work)"
    RESTRICT=$CC_CHOICE
fi
if [ "$RESTRICT" = y ]; then
    if [ -z "$DNS" ] && _cc_can_ask && [ "$CC_BATCH" != 1 ]; then cc_ask_text "DNS servers the servers may use (comma separated)" "" "addresses"; DNS=$CC_ANSWER; fi
    if [ -z "$NTP" ] && _cc_can_ask && [ "$CC_BATCH" != 1 ]; then cc_ask_text "Time server they may use (Splunk; empty = none)" "" "address"; NTP=$CC_ANSWER; fi
    if [ -z "$OUTALLOW" ] && _cc_can_ask && [ "$CC_BATCH" != 1 ]; then
        cc_show "" "  Anything else a server must reach out through the firewall, as ADDR:PORTS (e.g. 10.0.1.9:1433 for a database, 10.0.0.20:9997 for Splunk). Empty = done."
        while :; do cc_ask_text "Also allow out to (ADDR:PORTS; empty = done)" "" "destination"; [ -n "$CC_ANSWER" ] || break; OUTALLOW="$OUTALLOW$CC_ANSWER$NL"; done
    fi
    : >"$W/outallow"
    for _d in $(printf '%s' "$DNS" | tr ',' ' '); do isip "$_d" && j "$_d" "53" "53" "DNS" >>"$W/outallow"; done
    [ -n "$NTP" ] && isip "$NTP" && j "$NTP" "" "123" "NTP" >>"$W/outallow"
    printf '%s' "$OUTALLOW" | grep . | while IFS= read -r _l; do
        _d=${_l%%:*}; _ps=$(printf '%s' "$_l" | sed -n 's/^[^:]*://p'); _tp=""; _upp=""
        isip "$_d" || { echo "BAD $_l"; continue; }
        for _x in $(printf '%s' "$_ps" | tr ',' ' '); do case "$_x" in */udp) _upp="$_upp,${_x%/udp}" ;; *) _tp="$_tp,${_x%/tcp}" ;; esac; done
        [ -n "$_tp$_upp" ] || { echo "BAD $_l (no ports)"; continue; }
        j "$_d" "${_tp#,}" "${_upp#,}" "you listed it"
    done >>"$W/outallow"
    grep '^BAD ' "$W/outallow" | while IFS= read -r _l; do cc_show "$C_RED" "  [x] not ADDR:PORTS, left out: ${_l#BAD }"; done
    # one line per destination (DNS and NTP on the same box become one rule)
    grep -v '^BAD ' "$W/outallow" | awk -F"$US" -v OFS="$US" '
        function merge(old, add,   n, x, i, seen, out) {  # awk, not shell: posix-ok
                n = split(old "," add, x, ","); out = ""
            for (i = 1; i <= n; i++) if (x[i] != "" && !(x[i] in seen)) { seen[x[i]] = 1; out = out (out == "" ? "" : ",") x[i] }
            return out }
        { if (!($1 in t)) o[++n] = $1; t[$1] = merge(t[$1], $2); u[$1] = merge(u[$1], $3); w[$1] = (w[$1] == "" ? "" : w[$1] ", ") $4 }
        END { for (i = 1; i <= n; i++) print o[i], t[o[i]], u[o[i]], w[o[i]] }' >"$W/o.n"; cat "$W/o.n" >"$W/outallow"
    [ -s "$W/outallow" ] || cc_show "$C_YEL" "  [*] no DNS, NTP or other destination listed: the servers will reach NOTHING outside the firewall"
fi
if [ -z "$THREAT" ]; then
    cc_choose "Turn on the firewall's threat prevention (IPS, antivirus, spyware) on the scored rules? (Palo Alto, FortiGate)" n "y=yes, use the firewall's default profiles" "n=no"
    THREAT=$CC_CHOICE
fi

# ---- 3. The rules (in plain words) ------------------------------------------------------------
header "3/6  the rules, one by one"
# $W/rules: kind US name US src US dst US tcp US udp US what     (kind: team scored ping indeny outallow outdeny)
: >"$W/rules"
ask_rule() {   # ask_rule KIND NAME SRC DST TCP UDP WHAT DEFAULT
    cc_choose "$7" "$8" "k=keep this rule" "s=skip it"
    [ "$CC_CHOICE" = k ] && j "$1" "$2" "$3" "$4" "$5" "$6" "$7" >>"$W/rules"
}
[ -n "$TEAM" ] && ask_rule team bt-team "$TEAM" any "" "" "ALLOW your team ($TEAM) -> anywhere, everything" k
while IFS="$US" read -r _a _t _u _note; do
    _w="ALLOW any -> $_a"; [ -n "$_t" ] && _w="$_w tcp $_t"; [ -n "$_u" ] && _w="$_w udp $_u"; [ -z "$_t$_u" ] && _w="$_w (no ports: ping only)"
    [ -n "$_note" ] && _w="$_w ($_note)"
    [ -n "$_t$_u" ] && ask_rule scored "bt-in-$_a" any "$_a" "$_t" "$_u" "$_w" k
done <"$W/scored"
ask_rule ping bt-ping any "$SERVERS" "" "" "ALLOW ping in -> the scored boxes (every box has a ping check)" k
if [ "$RESTRICT" = y ]; then
    while IFS="$US" read -r _d _t _u _note; do
        _w="ALLOW the scored servers -> $_d"; [ -n "$_t" ] && _w="$_w tcp $_t"; [ -n "$_u" ] && _w="$_w udp $_u"; _w="$_w ($_note)"
        ask_rule outallow "bt-out-$_d" "$SERVERS" "$_d" "$_t" "$_u" "$_w" k
    done <"$W/outallow"
    ask_rule outdeny bt-out-block "$SERVERS" any "" "" "BLOCK + LOG anything else the scored servers START out (callbacks, downloads, ping and DNS tunnels)" k
fi
cc_show "" "  Last: the rule that actually closes everything else. Without it the rules above change nothing."
ask_rule indeny bt-in-block any any "" "" "BLOCK + LOG every other connection coming IN from outside (replies to your own traffic still work)" k
NRULES=$(grep -c . "$W/rules")
[ "$NRULES" -gt 0 ] || { cc_show "$C_GRY" "  Every rule skipped: nothing to do."; rm -rf "$W"; cc_finish; exit 0; }
grep -q "^indeny$US" "$W/rules" || cc_show "$C_YEL" "  [*] without the BLOCK rule the firewall still lets in whatever its old rules allow"

# ---- 4. Each firewall: read, choose sides, build ------------------------------------------------
header "4/6  each firewall"
# pick LIST-FILE QUESTION DEFAULT-REGEX GIVEN -> CC_PICK (a name from the list)
# With a 5th argument "all", "a" picks every name in the list (CC_PICK=all).
# Without a terminal it never guesses: no name like the default -> refused.
pick() {
    CC_PICK=""
    if [ -n "$4" ]; then
        [ "$4" = all ] && [ "${5:-}" = all ] && [ -s "$1" ] && { CC_PICK=all; return 0; }
        grep -qxF "$4" "$1" && { CC_PICK=$4; return 0; }; cc_show "$C_RED" "  [x] '$4' is not on this device (it has: $(tr '\n' ' ' <"$1"))"; return 1; fi
    _pn=$(grep -c . "$1"); [ "$_pn" -gt 0 ] || return 1
    _pd=$(grep -inE "$3" "$1" | head -n 1 | cut -d: -f1)
    if [ -z "$_pd" ] && ! _cc_can_ask; then
        cc_show "$C_RED" "  [x] $2 - no name looks right ($(tr '\n' ' ' <"$1")) and nobody to ask: name it with --outside / --inside"; return 1; fi
    [ -n "$_pd" ] && [ "$_pd" -le 9 ] || _pd=1
    [ "$_pn" -gt 9 ] && cc_show "$C_YEL" "  [*] only the first 9 are offered: name it with --outside / --inside"
    _pf=$1; _pq=$2; _pa=${5:-}; _pi=0; set --
    while IFS= read -r _x; do _pi=$((_pi + 1)); [ "$_pi" -le 9 ] && set -- "$@" "$_pi=$_x"; done <"$_pf"
    [ "$_pa" = all ] && [ "$_pn" -gt 1 ] && set -- "$@" "a=all of them (scored servers in more than one)"
    cc_choose "$_pq" "$_pd" "$@"
    if [ "$CC_CHOICE" = a ]; then CC_PICK=all; else CC_PICK=$(sed -n "${CC_CHOICE}p" "$_pf"); fi
}
# mask PREFIX -> dotted mask (no "^": busybox awk may lack math)
mask() { awk -v p="$1" 'BEGIN { for (k = 1; k <= 4; k++) { b = p - 8 * (k - 1); if (b > 8) b = 8; if (b < 0) b = 0; v = 256; r = 1; for (i = 0; i < 8 - b; i++) r *= 2; v = (b == 0) ? 0 : 256 - r; printf "%s%s", (k > 1 ? "." : ""), v } }'; }
addr() { case "$1" in */*) printf '%s %s' "${1%/*}" "$(mask "${1#*/}")" ;; *) printf '%s 255.255.255.255' "$1" ;; esac; }
cidr() { case "$1" in */*) printf '%s' "$1" ;; *) printf '%s/32' "$1" ;; esac; }
# cidrs "a,b" -> "a/32 b/24 " (Palo Alto lists)
cidrs() { for _cx in $(printf '%s' "$1" | tr ',' ' '); do printf '%s ' "$(cidr "$_cx")"; done; }
# natx LIST -> the outside (NAT) names of the boxes in LIST, from $W/nat ("INSIDE-IP NAME" lines)
natx() { for _cx in $(printf '%s' "$1" | tr ',' ' '); do awk -v i="$_cx" '$1 == i { printf "%s ", $2 }' "$W/nat"; done; }
# shownat DEVICE -> say which NAT names were found, or warn that none were
shownat() {
    if grep -q ' SKIP$' "$W/nat"; then
        grep ' SKIP$' "$W/nat" | while read -r _ni _nn; do cc_show "$C_RED" "  [!] NAT to $_ni uses a name with spaces: not added. Rename it, or add its outside address with --allow, or the scorer may be blocked"; done
        grep -v ' SKIP$' "$W/nat" >"$W/nat.n"; cat "$W/nat.n" >"$W/nat"
    fi
    if [ -s "$W/nat" ]; then
        while read -r _ni _nn; do cc_show "$C_CYN" "  [-] NAT: outside name $_nn leads to $_ni: it is added to the rules for $_ni (the firewall matches the outside name)"; done <"$W/nat"
        { printf '%s: NAT found, these outside names are added to the scored and ping rules:\n' "$1"; sed 's/^\([^ ]*\) \(.*\)/  \2 -> \1/' "$W/nat"; printf '\n'; } >>"$CC_RUN_DIR/plan.txt"
    else
        cc_show "$C_GRY" "  [-] no NAT to the scored boxes found: the rules use their inside addresses"
    fi
}
# build VENDOR DEVICE -> $W/fix.DEV (the rules) and $W/undo.DEV (take them out again)
: >"$W/ready"
while IFS='|' read -r _n _a _v _u _p; do
    cc_show "" ""; cc_show "$C_CYN" "  $_n ($_a, $_v)"
    case "$_v" in
        pfsense|opnsense)
            cc_show "$C_YEL" "  [*] no safe command line: do it in the web GUI (Firewall > Rules > WAN), top to bottom, the rules in plan.txt; block rule last with logging on"
            { printf '%s (%s): web GUI, Firewall > Rules > WAN, top to bottom:\n' "$_n" "$_v"; awk -F"$US" '{ print "  " $7 }' "$W/rules"; printf '\n'; } >>"$CC_RUN_DIR/plan.txt"; continue ;;
        cisco-ios|vyos)
            cc_show "$C_YEL" "  [*] $_v is not built in NW-20 yet: the plan is in plan.txt to enter by hand"
            { printf '%s (%s): enter by hand, in this order:\n' "$_n" "$_v"; awk -F"$US" '{ print "  " $7 }' "$W/rules"; printf '\n'; } >>"$CC_RUN_DIR/plan.txt"; continue ;;
    esac
    if ! cc_guard host "$_a" || ! cc_guard host "$_n"; then cc_show "$C_GRY" "  protected device, skipped"; continue; fi
    if ! readdev "$_v" "$_u" "$_a" "$_p" "$W/raw.$_n"; then cc_show "$C_RED" "  [x] could not log in as $_u ($(grep -v '^$' "$W/err" | tail -n 1 | cut -c1-70))"; continue; fi
    _raw="$W/raw.$_n"; tr -d '\r' <"$_raw" | sed 's/^[A-Za-z0-9_.@()-]*[>#] *//' >"$_raw.c"
    : >"$W/fix.$_n"; : >"$W/undo.$_n"; _ok=1
    case "$_v" in
    paloalto)
        sed -n 's/^set zone \([^ ]*\) .*/\1/p' "$_raw.c" | awk '!s[$0]++' >"$W/zones"
        pick "$W/zones" "$_n: which zone is OUTSIDE (where red team and the scorer come from)?" 'untrust|outside|wan|internet|external' "$OUTSIDE" || { _ok=0; cc_show "$C_RED" "  [x] no zones read"; }
        _out=$CC_PICK
        grep -vxF "$_out" "$W/zones" >"$W/zin"
        pick "$W/zin" "$_n: which zone are the scored servers in?" 'trust|inside|lan|dmz|server' "$INSIDE" all || _ok=0
        _in=$CC_PICK; [ "$_in" = all ] && _in="[ $(tr '\n' ' ' <"$W/zin")]"
        # an earlier run's bt- rules out first ("set" on a rule that is there adds to its lists)
        awk '$1 == "set" && $2 == "rulebase" && $3 == "security" && $4 == "rules" && $5 ~ /^bt-/ && !s[$5]++ { print "delete rulebase security rules " $5 }' "$_raw.c" >"$W/oldbt"
        if [ -s "$W/oldbt" ]; then cc_show "$C_YEL" "  [*] bt- rules from an earlier run are there: they are replaced"; cat "$W/oldbt" >>"$W/fix.$_n"; fi
        awk '/^set rulebase security rules / { r = $5; if (!(r in s)) { s[r] = 1; o[++n] = r } a[r] = a[r] " " $0 }
             END { for (i = 1; i <= n; i++) { t = a[o[i]]; if (o[i] !~ /^bt-/ && t ~ / source any/ && t ~ / destination any/ && t ~ / application any/ && t ~ / service any/ && t ~ / action allow/) print o[i] } }' "$_raw.c" >"$W/anyany"
        while IFS= read -r _r; do cc_show "$C_YEL" "  [*] existing rule \"$_r\" allows anything to anything: it ends up BELOW the bt- rules, so it no longer lets the rest in"; done <"$W/anyany"
        # Palo Alto matches the destination address from BEFORE NAT: find the
        # outside address of each scored box (destination NAT, or a static
        # bi-directional source NAT) so the rule still matches the scorer.
        # (a quoted name with spaces is kept as one word; such a name is not used, only reported)
        awk 'index($0, "\"") { o = ""; q = 0; for (i = 1; i <= length($0); i++) { c = substr($0, i, 1); if (c == "\"") q = !q; o = o ((q && c == " ") ? "\001" : c) } $0 = o }
             $1 == "set" && $2 == "address" && $4 == "ip-netmask" { a = $5; sub(/\/32$/, "", a); ip[$3] = a }
             $1 == "set" && $2 == "rulebase" && $3 == "nat" && $4 == "rules" {
                 r = $5; k = $6; v = ""; for (i = 7; i <= NF; i++) if ($i != "[" && $i != "]") v = v " " $i
                 if (k == "destination") d[r] = d[r] v
                 else if (k == "source") s[r] = s[r] v
                 else if (k == "destination-translation" && $7 == "translated-address") dt[r] = $8
                 else if (k == "source-translation" && $7 == "static-ip" && $8 == "translated-address") st[r] = $9
                 else if (k == "source-translation" && $7 == "static-ip" && $8 == "bi-directional" && $9 == "yes") bi[r] = 1
                 rs[r] = 1 }
             END { for (r in rs) {
                 if (r in dt) { t = (dt[r] in ip) ? ip[dt[r]] : dt[r]; sub(/\/32$/, "", t); n = split(d[r], x, " "); for (i = 1; i <= n; i++) if (x[i] != "any") print t, (x[i] ~ /\001/ ? "SKIP" : x[i]) }
                 if ((r in st) && (r in bi)) { n = split(s[r], x, " "); for (i = 1; i <= n; i++) { t = (x[i] in ip) ? ip[x[i]] : x[i]; sub(/\/32$/, "", t); print t, (st[r] ~ /\001/ ? "SKIP" : st[r]) } } } }' "$_raw.c" | awk '!s[$0]++' | sort >"$W/nat"
        shownat "$_n"
        # services, then rules, then move each to the top (last first)
        _th=""; [ "$THREAT" = y ] && _th=" profile-setting profiles virus default spyware default vulnerability default"
        while IFS="$US" read -r _k _nm _s _d _t _ud _w; do
            _svc=""
            [ -n "$_t" ] && { printf 'set service %s-t protocol tcp port %s\n' "$_nm" "$_t" >>"$W/fix.$_n"; _svc="$_svc $_nm-t"; printf 'delete service %s-t\n' "$_nm" >>"$W/undo.$_n"; }
            [ -n "$_ud" ] && { printf 'set service %s-u protocol udp port %s\n' "$_nm" "$_ud" >>"$W/fix.$_n"; _svc="$_svc $_nm-u"; printf 'delete service %s-u\n' "$_nm" >>"$W/undo.$_n"; }
            _src=any; [ "$_s" != any ] && _src="[ $(cidrs "$_s")]"
            _dst=any; [ "$_d" != any ] && _dst="[ $(cidrs "$_d")]"
            case "$_k" in scored|ping) [ "$_d" != any ] && _dst="[ $(cidrs "$_d")$(natx "$_d")]" ;; esac
            case "$_k" in
                team)     _r="from any to any source $_src destination any application any service any action allow" ;;  # posix-ok: Palo Alto words, not the shell
                scored)   _r="from $_out to $_in source any destination $_dst application any service [$_svc ] action allow log-end yes$_th" ;;
                ping)     _r="from $_out to $_in source any destination $_dst application ping service application-default action allow" ;;
                outallow) _r="from $_in to $_out source $_src destination $_dst application any service [$_svc ] action allow" ;;  # posix-ok: Palo Alto words, not the shell
                outdeny)  _r="from $_in to $_out source $_src destination any application any service any action deny log-end yes" ;;  # posix-ok: Palo Alto words, not the shell
                indeny)   _r="from $_out to $_in source any destination any application any service any action deny log-end yes" ;;
            esac
            printf 'set rulebase security rules %s %s\n' "$_nm" "$_r" >>"$W/fix.$_n"
        done <"$W/rules"
        awk -F"$US" '{ l[NR] = $2 } END { for (i = NR; i > 0; i--) print "move rulebase security rules " l[i] " top" }' "$W/rules" >>"$W/fix.$_n"
        awk -F"$US" '{ print "delete rulebase security rules " $2 }' "$W/rules" >"$W/u1"; cat "$W/u1" "$W/undo.$_n" >"$W/u2"; cat "$W/u2" >"$W/undo.$_n"
        ;;
    cisco-asa)
        awk '/^interface / { i = $2 } $1 == "nameif" { print $2 }' "$_raw.c" >"$W/zones"
        pick "$W/zones" "$_n: which interface (nameif) is OUTSIDE?" 'outside|wan|internet|untrust' "$OUTSIDE" || { _ok=0; cc_show "$C_RED" "  [x] no interfaces read"; }
        _out=$CC_PICK
        grep -vxF "$_out" "$W/zones" >"$W/zin"
        pick "$W/zin" "$_n: which interface are the scored servers behind? (used for the outgoing limits)" 'inside|lan|dmz|server' "$([ "$INSIDE" = all ] || echo "$INSIDE")" || _ok=0
        _in=$CC_PICK
        _oldin=$(awk -v i="$_out" '$1 == "access-group" && $3 == "in" && $5 == i { print $2; exit }' "$_raw.c")
        _oldout=$(awk -v i="$_in" '$1 == "access-group" && $3 == "in" && $5 == i { print $2; exit }' "$_raw.c")
        # A second run finds our own lists bound: the ORIGINAL ones are in the first run's record.
        if [ -f "$CC_OUT/nw20-$_n.undo" ]; then
            [ "$_oldin" = BT-IN ] && _oldin=$(awk -v i="$_out" '$1 == "access-group" && $2 != "BT-IN" && $5 == i { print $2; exit }' "$CC_OUT/nw20-$_n.undo")
            [ "$_oldout" = BT-OUT ] && _oldout=$(awk -v i="$_in" '$1 == "access-group" && $2 != "BT-OUT" && $5 == i { print $2; exit }' "$CC_OUT/nw20-$_n.undo")
        fi
        [ "$_oldin" = BT-IN ] && _oldin=""; [ "$_oldout" = BT-OUT ] && _oldout=""
        [ -n "$_oldin" ] && [ "$_oldin" != BT-IN ] && cc_show "$C_YEL" "  [*] the outside interface uses access list $_oldin now: BT-IN takes its place (it is put back on undo)"
        grep -E '^access-list [^ ]+ (extended )?permit ip any4? any4?' "$_raw.c" | while IFS= read -r _l; do cc_show "$C_YEL" "  [*] existing: $_l (any to any)"; done
        printf 'configure terminal\nclear configure access-list BT-IN\n' >>"$W/fix.$_n"
        while IFS="$US" read -r _k _nm _s _d _t _ud _w; do
            case "$_k" in
                team) for _x in $(printf '%s' "$_s" | tr ',' ' '); do printf 'access-list BT-IN extended permit ip %s any\n' "$(addr "$_x")"; done ;;
                scored) for _pp in $(printf '%s' "$_t" | tr ',' ' '); do case "$_pp" in *-*) _q="range ${_pp%-*} ${_pp#*-}" ;; *) _q="eq $_pp" ;; esac; printf 'access-list BT-IN extended permit tcp any host %s %s\n' "$_d" "$_q"; done
                        for _pp in $(printf '%s' "$_ud" | tr ',' ' '); do case "$_pp" in *-*) _q="range ${_pp%-*} ${_pp#*-}" ;; *) _q="eq $_pp" ;; esac; printf 'access-list BT-IN extended permit udp any host %s %s\n' "$_d" "$_q"; done ;;
                ping) for _x in $(printf '%s' "$_d" | tr ',' ' '); do printf 'access-list BT-IN extended permit icmp any host %s echo\n' "$_x"; done
                      printf 'access-list BT-IN extended permit icmp any any echo-reply\naccess-list BT-IN extended permit icmp any any unreachable\naccess-list BT-IN extended permit icmp any any time-exceeded\n' ;;
                indeny) printf 'access-list BT-IN extended deny ip any any log\n' ;;
            esac
        done <"$W/rules" >>"$W/fix.$_n"
        grep -q "^indeny$US" "$W/rules" || printf 'access-list BT-IN extended permit ip any any\n' >>"$W/fix.$_n"
        printf 'access-group BT-IN in interface %s\n' "$_out" >>"$W/fix.$_n"
        if [ "$RESTRICT" = y ]; then
            printf 'clear configure access-list BT-OUT\n' >>"$W/fix.$_n"
            while IFS="$US" read -r _k _nm _s _d _t _ud _w; do
                case "$_k" in
                    team) for _x in $(printf '%s' "$_s" | tr ',' ' '); do printf 'access-list BT-OUT extended permit ip %s any\n' "$(addr "$_x")"; done ;;
                    outallow) for _x in $(printf '%s' "$_s" | tr ',' ' '); do
                                  for _pp in $(printf '%s' "$_t" | tr ',' ' '); do case "$_pp" in *-*) _q="range ${_pp%-*} ${_pp#*-}" ;; *) _q="eq $_pp" ;; esac; printf 'access-list BT-OUT extended permit tcp host %s host %s %s\n' "$_x" "$_d" "$_q"; done
                                  for _pp in $(printf '%s' "$_ud" | tr ',' ' '); do case "$_pp" in *-*) _q="range ${_pp%-*} ${_pp#*-}" ;; *) _q="eq $_pp" ;; esac; printf 'access-list BT-OUT extended permit udp host %s host %s %s\n' "$_x" "$_d" "$_q"; done; done ;;
                    outdeny) for _x in $(printf '%s' "$_s" | tr ',' ' '); do
                                 # this list is on the servers' interface: it sees traffic to the team too, so that stays open
                                 for _tm in $(printf '%s' "$TEAM" | tr ',' ' '); do printf 'access-list BT-OUT extended permit ip host %s %s\n' "$_x" "$(addr "$_tm")"; done
                                 printf 'access-list BT-OUT extended permit icmp host %s any echo-reply\naccess-list BT-OUT extended deny ip host %s any log\n' "$_x" "$_x"; done ;;
                esac
            done <"$W/rules" >>"$W/fix.$_n"
            [ -n "$_oldout" ] && cc_show "$C_YEL" "  [*] the servers' interface uses access list $_oldout now: BT-OUT takes its place and ends with 'permit ip any any' for everything that is not a scored server"
            cc_show "$C_YEL" "  [*] ASA: the outgoing block also stops the servers reaching OTHER inside networks (not the team): list those with --out-allow"
            printf 'access-list BT-OUT extended permit ip any any\naccess-group BT-OUT in interface %s\n' "$_in" >>"$W/fix.$_n"
        fi
        printf 'end\n' >>"$W/fix.$_n"
        {
            printf 'configure terminal\n'
            if [ -n "$_oldin" ] && [ "$_oldin" != BT-IN ]; then printf 'access-group %s in interface %s\n' "$_oldin" "$_out"; else printf 'no access-group BT-IN in interface %s\n' "$_out"; fi
            printf 'clear configure access-list BT-IN\n'
            if [ "$RESTRICT" = y ]; then
                if [ -n "$_oldout" ] && [ "$_oldout" != BT-OUT ]; then printf 'access-group %s in interface %s\n' "$_oldout" "$_in"; else printf 'no access-group BT-OUT in interface %s\n' "$_in"; fi
                printf 'clear configure access-list BT-OUT\n'
            fi
            printf 'end\nwrite memory\n'
        } >"$W/undo.$_n"
        ;;
    fortigate)
        awk '/^config system interface/ { s = 1 } s && $1 == "edit" { n = $2; gsub(/"/, "", n); print n } /^end/ { s = 0 }' "$_raw.c" >"$W/zones"
        pick "$W/zones" "$_n: which interface is OUTSIDE?" 'wan|outside|internet|port1' "$OUTSIDE" || { _ok=0; cc_show "$C_RED" "  [x] no interfaces read"; }
        _out=$CC_PICK
        grep -vxF "$_out" "$W/zones" >"$W/zin"
        pick "$W/zin" "$_n: which interface are the scored servers behind?" 'internal|lan|inside|dmz|port2' "$INSIDE" all || _ok=0
        _in=$CC_PICK; _inq="\"$_in\""; [ "$_in" = all ] && _inq=$(awk '{ printf "%s\"%s\"", (NR > 1 ? " " : ""), $0 }' "$W/zin")
        # A box reached through a virtual IP (VIP) only matches a policy that
        # names the VIP: find the VIPs that lead to each scored box.
        awk '/^config firewall vip/ { s = 1; next } s && /^end/ { s = 0 }
             s && $1 == "edit" { n = $0; sub(/^[ \t]*edit[ \t]+/, "", n); gsub(/"/, "", n); if (n ~ / /) n = "SKIP" }
             s && $1 == "set" && $2 == "mappedip" { m = $3; gsub(/"/, "", m); sub(/-.*/, "", m); print m, n }' "$_raw.c" | awk '!s[$0]++' | sort >"$W/nat"
        shownat "$_n"
        # the first policy that is not ours (ours are 9101-9199, from this or an earlier run)
        _first=$(awk '/^config firewall policy/ { s = 1; next } s && $1 == "edit" && ($2 < 9101 || $2 > 9199) { print $2; exit }' "$_raw.c")
        awk '/^config firewall policy/ { s = 1 } s && $1 == "edit" { id = $2; a = 0 } s && /set srcaddr "all"/ { a++ } s && /set dstaddr "all"/ { a++ } s && /set service "ALL"/ { a++ } s && /set action accept/ { a++ } s && $1 == "next" && a == 4 { print id }' "$_raw.c" >"$W/anyany"
        while IFS= read -r _r; do cc_show "$C_YEL" "  [*] existing policy $_r allows all to all: it ends up BELOW the bt- policies"; done <"$W/anyany"
        _id=9100; : >"$W/ids"; : >"$W/uaddr"; : >"$W/usvc"
        # an earlier run's policies (9101-9199) out first, so none is left over or half changed
        awk '/^config firewall policy/ { s = 1; next } s && /^end/ { s = 0 } s && $1 == "edit" && $2 >= 9101 && $2 <= 9199 { print $2 }' "$_raw.c" >"$W/oldids"
        if [ -s "$W/oldids" ]; then
            cc_show "$C_YEL" "  [*] bt- policies from an earlier run are there: they are replaced"
            { printf 'config firewall policy\n'; sed 's/^/delete /' "$W/oldids"; printf 'end\n'; } >>"$W/fix.$_n"
        fi
        while IFS="$US" read -r _k _nm _s _d _t _ud _w; do
            _id=$((_id + 1)); echo "$_id" >>"$W/ids"
            _sa='"all"'; _da='"all"'; _sv='"ALL"'
            if [ "$_s" != any ]; then _sa=""; for _x in $(printf '%s' "$_s" | tr ',' ' '); do printf 'config firewall address\nedit "bt-a-%s"\nset subnet %s\nnext\nend\n' "$_x" "$(addr "$_x")" >>"$W/fix.$_n"; echo "bt-a-$_x" >>"$W/uaddr"; _sa="$_sa \"bt-a-$_x\""; done; _sa=${_sa# }; fi
            if [ "$_d" != any ]; then _da=""; for _x in $(printf '%s' "$_d" | tr ',' ' '); do printf 'config firewall address\nedit "bt-a-%s"\nset subnet %s\nnext\nend\n' "$_x" "$(addr "$_x")" >>"$W/fix.$_n"; echo "bt-a-$_x" >>"$W/uaddr"; _da="$_da \"bt-a-$_x\""; done
                case "$_k" in scored|ping) for _x in $(natx "$_d"); do _da="$_da \"$_x\""; done ;; esac; _da=${_da# }; fi
            if [ -n "$_t$_ud" ]; then
                { printf 'config firewall service custom\nedit "%s"\n' "$_nm"
                  [ -n "$_t" ] && printf 'set tcp-portrange %s\n' "$(printf '%s' "$_t" | tr ',' ' ')"
                  [ -n "$_ud" ] && printf 'set udp-portrange %s\n' "$(printf '%s' "$_ud" | tr ',' ' ')"
                  printf 'next\nend\n'; } >>"$W/fix.$_n"
                echo "$_nm" >>"$W/usvc"; _sv="\"$_nm\""; fi
            case "$_k" in
                team|scored|ping|indeny) _si="\"$_out\""; _di=$_inq ;;
                outallow|outdeny)        _si=$_inq; _di="\"$_out\"" ;;
            esac
            [ "$_k" = ping ] && _sv='"PING"'
            _act=accept; case "$_k" in indeny|outdeny) _act=deny ;; esac
            {
                printf 'config firewall policy\nedit %s\nset name "%s"\nset srcintf %s\nset dstintf %s\nset srcaddr %s\nset dstaddr %s\nset service %s\nset schedule "always"\nset action %s\nset logtraffic all\n' "$_id" "$_nm" "$_si" "$_di" "$_sa" "$_da" "$_sv" "$_act"
                [ "$_k" = outallow ] && printf 'set nat enable\n'
                [ "$_k" = scored ] && [ "$THREAT" = y ] && printf 'set utm-status enable\nset ips-sensor "default"\nset av-profile "default"\n'
                printf 'next\nend\n'
            } >>"$W/fix.$_n"
        done <"$W/rules"
        if [ -n "$_first" ]; then
            { printf 'config firewall policy\n'; while IFS= read -r _x; do printf 'move %s before %s\n' "$_x" "$_first"; done <"$W/ids"; printf 'end\n'; } >>"$W/fix.$_n"
        fi
        # policies first (they use the objects), then the objects
        { printf 'config firewall policy\n'; while IFS= read -r _x; do printf 'delete %s\n' "$_x"; done <"$W/ids"; printf 'end\n'
          [ -s "$W/usvc" ] && { printf 'config firewall service custom\n'; awk '!s[$0]++ { printf "delete \"%s\"\n", $0 }' "$W/usvc"; printf 'end\n'; }
          [ -s "$W/uaddr" ] && { printf 'config firewall address\n'; awk '!s[$0]++ { printf "delete \"%s\"\n", $0 }' "$W/uaddr"; printf 'end\n'; }; } >"$W/undo.$_n"
        # the same address object may be made twice: keep the first
        awk '/^config firewall address$/ { buf = $0; getline; key = $0; buf = buf "\n" key; while ((getline l) > 0) { buf = buf "\n" l; if (l == "end") break } if (!(key in seen)) { seen[key] = 1; print buf } next } { print }' "$W/fix.$_n" >"$W/f.n" && cat "$W/f.n" >"$W/fix.$_n"
        ;;
    mikrotik)
        sed -n '/^===if/,/^===/p' "$_raw.c" | sed -n 's/.* name=\([^ ]*\).*/\1/p' | tr -d '"' >"$W/zones"
        pick "$W/zones" "$_n: which interface is OUTSIDE (WAN)?" 'wan|ether1|outside|internet' "$OUTSIDE" || { _ok=0; cc_show "$C_RED" "  [x] no interfaces read"; }
        _out=$CC_PICK
        _nf=$(sed -n '/^===filter/,$p' "$_raw.c" | grep ' chain=' | grep -vc 'comment="\{0,1\}bt-')
        _pb=""; [ "$_nf" -gt 0 ] && _pb=" place-before=0"
        grep -q 'comment=bt-\|comment="bt-' "$_raw.c" && cc_show "$C_YEL" "  [*] bt- rules from an earlier run are there: they are replaced"
        : >"$W/mt"
        printf '/ip firewall filter add chain=forward connection-state=established,related action=accept comment=bt-established\n' >>"$W/mt"
        while IFS="$US" read -r _k _nm _s _d _t _ud _w; do
            case "$_k" in
                team) for _x in $(printf '%s' "$_s" | tr ',' ' '); do printf '/ip firewall filter add chain=forward src-address=%s action=accept comment=%s\n' "$_x" "$_nm"; done ;;
                scored) [ -n "$_t" ] && printf '/ip firewall filter add chain=forward in-interface=%s dst-address=%s protocol=tcp dst-port=%s action=accept comment=%s\n' "$_out" "$_d" "$_t" "$_nm"
                        [ -n "$_ud" ] && printf '/ip firewall filter add chain=forward in-interface=%s dst-address=%s protocol=udp dst-port=%s action=accept comment=%s\n' "$_out" "$_d" "$_ud" "$_nm" ;;
                ping) for _x in $(printf '%s' "$_d" | tr ',' ' '); do printf '/ip firewall filter add chain=forward in-interface=%s dst-address=%s protocol=icmp icmp-options=8:0 action=accept comment=%s\n' "$_out" "$_x" "$_nm"; done ;;
                outallow) for _x in $(printf '%s' "$_s" | tr ',' ' '); do
                              [ -n "$_t" ] && printf '/ip firewall filter add chain=forward out-interface=%s src-address=%s dst-address=%s protocol=tcp dst-port=%s action=accept comment=%s\n' "$_out" "$_x" "$_d" "$_t" "$_nm"
                              [ -n "$_ud" ] && printf '/ip firewall filter add chain=forward out-interface=%s src-address=%s dst-address=%s protocol=udp dst-port=%s action=accept comment=%s\n' "$_out" "$_x" "$_d" "$_ud" "$_nm"; done ;;
                outdeny) for _x in $(printf '%s' "$_s" | tr ',' ' '); do printf '/ip firewall filter add chain=forward out-interface=%s src-address=%s action=drop log=yes log-prefix=bt-out comment=%s\n' "$_out" "$_x" "$_nm"; done ;;
                indeny) printf '/ip firewall filter add chain=forward in-interface=%s connection-state=new action=drop log=yes log-prefix=bt-in comment=%s\n' "$_out" "$_nm" ;;
            esac
        done <"$W/rules" >>"$W/mt"
        # remove an earlier run's bt- rules first; then add (on top: last first, each place-before=0)
        printf '/ip firewall filter remove [find comment~"^bt-"]\n' >"$W/fix.$_n"
        if [ -n "$_pb" ]; then awk -v pb="$_pb" '{ l[NR] = $0 pb } END { for (i = NR; i > 0; i--) print l[i] }' "$W/mt" >>"$W/fix.$_n"; else cat "$W/mt" >>"$W/fix.$_n"; fi
        printf '/ip firewall filter remove [find comment~"^bt-"]\n' >"$W/undo.$_n"
        ;;
    linux|openwrt)
        sed -n '/^===if/,/^===/p' "$_raw.c" | awk -F': ' 'NF >= 2 && $1 ~ /^[0-9]+$/ { n = $2; sub(/@.*/, "", n); if (n != "lo") print n }' >"$W/zones"
        # OpenWRT says which device is wan: offered first.
        _wre='wan|outside|eth0|ens3|ens18|enp'
        if [ "$_v" = openwrt ]; then _wd=$(sed -n '/^===wan/,/^===/p' "$_raw.c" | sed -n '2p' | tr -d "' "); [ -n "$_wd" ] && grep -qxF "$_wd" "$W/zones" && _wre="^$_wd\$"; fi
        pick "$W/zones" "$_n: which interface is OUTSIDE?" "$_wre" "$OUTSIDE" || { _ok=0; cc_show "$C_RED" "  [x] no interfaces read"; }
        _out=$CC_PICK
        grep -q 'table inet bt_fw' "$_raw.c" && cc_show "$C_YEL" "  [*] the bt_fw table from an earlier run is there: it is replaced"
        # OpenWRT port forwards (DNAT from wan): the scored paths, most likely.
        # After DNAT the forward chain sees the inside address and port.
        : >"$W/fwd"
        if [ "$_v" = openwrt ]; then
            sed -n '/^===fwd/,/^===/p' "$_raw.c" | tr -d "'" | awk -F'[].=[]' '/^firewall\.@redirect\[/ { i = $3; k = $5; v = substr($0, index($0, "=") + 1); R[i, k] = v; I[i] = 1 }
                END { for (i in I) { if (R[i, "enabled"] == "0") continue; if (R[i, "src"] != "" && R[i, "src"] != "wan") continue; if (R[i, "target"] != "" && R[i, "target"] != "DNAT") continue
                      d = R[i, "dest_ip"]; p = R[i, "dest_port"]; if (p == "") p = R[i, "src_dport"]; pr = R[i, "proto"]; if (pr == "") pr = "tcp udp"
                      if (d ~ /^[0-9.]+$/ && p ~ /^[0-9]+(-[0-9]+)?$/) print i " " d " " p " " pr " " R[i, "name"] } }' | sort -n >"$W/fwd"
            if [ -s "$W/fwd" ]; then
                while read -r _fi _fd _fp _fpr _fn; do cc_show "$C_CYN" "  [-] port forward ${_fn:-#$_fi}: outside -> $_fd:$_fp ($_fpr)"; done <"$W/fwd"
                _kf=$KEEPFWD
                [ -z "$_kf" ] && { cc_ask "$_n: keep these $(grep -c . "$W/fwd") port forward(s) open? (they are most likely the scored services; NW-07 flags ones that look planted)" Y "yes, keep them open" "no, only the scored boxes and ports above" && _kf=y || _kf=n; }
                [ "$_kf" = y ] || : >"$W/fwd"
            else cc_show "$C_GRY" "  [-] no port forwards on $_n"; fi
        fi
        {
            printf 'table inet bt_fw\ndelete table inet bt_fw\ntable inet bt_fw {\n    chain forward {\n        type filter hook forward priority -10; policy accept;\n'
            printf '        ct state established,related accept comment "bt-established"\n'
            while read -r _fi _fd _fp _fpr _fn; do
                for _x in $_fpr; do case "$_x" in tcp|udp) printf '        iifname "%s" ip daddr %s %s dport %s accept comment "bt-fwd-%s"\n' "$_out" "$_fd" "$_x" "$_fp" "$_fi" ;; esac; done
            done <"$W/fwd"

            while IFS="$US" read -r _k _nm _s _d _t _ud _w; do
                case "$_k" in
                    team) printf '        ip saddr { %s } accept comment "%s"\n' "$(printf '%s' "$_s" | sed 's/,/, /g')" "$_nm" ;;
                    scored) [ -n "$_t" ] && printf '        iifname "%s" ip daddr %s tcp dport { %s } accept comment "%s"\n' "$_out" "$_d" "$(printf '%s' "$_t" | sed 's/,/, /g')" "$_nm"
                            [ -n "$_ud" ] && printf '        iifname "%s" ip daddr %s udp dport { %s } accept comment "%s"\n' "$_out" "$_d" "$(printf '%s' "$_ud" | sed 's/,/, /g')" "$_nm" ;;
                    ping) printf '        iifname "%s" ip daddr { %s } icmp type echo-request accept comment "%s"\n' "$_out" "$(printf '%s' "$_d" | sed 's/,/, /g')" "$_nm" ;;
                    outallow) [ -n "$_t" ] && printf '        oifname "%s" ip saddr { %s } ip daddr %s tcp dport { %s } accept comment "%s"\n' "$_out" "$(printf '%s' "$_s" | sed 's/,/, /g')" "$_d" "$(printf '%s' "$_t" | sed 's/,/, /g')" "$_nm"
                              [ -n "$_ud" ] && printf '        oifname "%s" ip saddr { %s } ip daddr %s udp dport { %s } accept comment "%s"\n' "$_out" "$(printf '%s' "$_s" | sed 's/,/, /g')" "$_d" "$(printf '%s' "$_ud" | sed 's/,/, /g')" "$_nm" ;;
                    outdeny) printf '        oifname "%s" ip saddr { %s } limit rate 10/minute log prefix "bt-fw-out " counter drop comment "%s"\n        oifname "%s" ip saddr { %s } drop\n' "$_out" "$(printf '%s' "$_s" | sed 's/,/, /g')" "$_nm" "$_out" "$(printf '%s' "$_s" | sed 's/,/, /g')" ;;
                    indeny) printf '        iifname "%s" limit rate 10/minute log prefix "bt-fw-in " counter drop comment "%s"\n        iifname "%s" drop\n' "$_out" "$_nm" "$_out" ;;
                esac
            done <"$W/rules"
            printf '    }\n}\n'
        } >"$W/nft.$_n"
        if cc_have nft && ! nft -c -f "$W/nft.$_n" >"$W/nftchk" 2>&1; then
            # A box where nft cannot run (no rights, a container) cannot check it: only a syntax error stops here.
            cat "$W/nftchk" >>"$CC_LOG"
            grep -qi 'syntax error\|unexpected' "$W/nftchk" && { _ok=0; cc_show "$C_RED" "  [x] nft refuses the ruleset: $(head -n 1 "$W/nftchk")"; }
        fi
        if [ "$_v" = openwrt ]; then
            # Kept in /etc and loaded by fw4 at every reload and boot (a uci
            # include); loaded now with nft.  Root on OpenWRT: no sudo.
            { printf "cat > /etc/bt_fw.nft <<'BTNFT'\n"; cat "$W/nft.$_n"; printf "BTNFT\n"
              printf "nft -f /etc/bt_fw.nft || exit 1\nuci set firewall.bt_fw=include && uci set firewall.bt_fw.type=nftables && uci set firewall.bt_fw.path=/etc/bt_fw.nft && uci set firewall.bt_fw.position=ruleset-post && uci commit firewall\n"; } >"$W/fix.$_n"
            printf 'nft delete table inet bt_fw; uci -q delete firewall.bt_fw; uci commit firewall; rm -f /etc/bt_fw.nft\n' >"$W/undo.$_n"
        else
        { printf "cat > /tmp/bt_fw.nft <<'BTNFT'\n"; cat "$W/nft.$_n"; printf "BTNFT\n"; printf "if [ \"\$(id -u)\" = 0 ]; then nft -f /tmp/bt_fw.nft; else sudo -n nft -f /tmp/bt_fw.nft; fi; _r=\$?; rm -f /tmp/bt_fw.nft; exit \$_r\n"; } >"$W/fix.$_n"
        printf 'if [ "$(id -u)" = 0 ]; then nft delete table inet bt_fw; else sudo -n nft delete table inet bt_fw; fi\n' >"$W/undo.$_n"
        fi
        ;;
    esac
    [ "$_ok" = 1 ] || { cc_show "$C_RED" "  [x] $_n: not built (see above)"; continue; }
    cp "$W/fix.$_n" "$CC_RUN_DIR/commands-$_n.txt"
    { printf '%s (%s): outside = %s%s\n' "$_n" "$_v" "$_out" "$([ -n "${_in:-}" ] && [ "$_v" != mikrotik ] && [ "$_v" != linux ] && [ "$_v" != openwrt ] && echo ", servers = $_in")"
      printf '  top of the rule list, in this order:\n'; awk -F"$US" '{ printf "  %2d. %s\n", NR, $7 }' "$W/rules"
      printf '  everything below stays as it was\n  commands: commands-%s.txt\n\n' "$_n"; } >>"$CC_RUN_DIR/plan.txt"
    cc_show "$C_GRN" "  [ok] built: $NRULES rule(s) on top, outside = $_out; exact commands in commands-$_n.txt"
    printf '%s|%s|%s|%s|%s\n' "$_n" "$_a" "$_v" "$_u" "$_p" >>"$W/ready"
    _in=""
done <"$W/devices"

# ---- 5. Apply, check, confirm ------------------------------------------------------------
header "5/6  apply"
# probe ADDR PORT -> 0 if a TCP connection opens (nc, else bash /dev/tcp)
# (an nc without -z would say "down" for everything, so it is only used when it has -z)
NCZ=0; cc_have nc && nc -h 2>&1 | grep -qE -- '-z|\[-[A-Za-z0-9]*z' && NCZ=1
probe() {
    if [ "$NCZ" = 1 ]; then nc -z -w 3 "$1" "$2" >/dev/null 2>&1; return; fi
    if cc_have bash && cc_have timeout; then timeout 4 bash -c 'exec 3<>"/dev/tcp/$1/$2"' _ "$1" "$2" >/dev/null 2>&1; return; fi
    return 2
}
pinged() { ping -c 1 -W 2 "$1" >/dev/null 2>&1; }
# checks FILE -> one line per scored box:port and ping: "ADDR PORT up|down"
checks() {
    # own names: the apply loop uses _a and _u for the device
    while IFS="$US" read -r _ca _ct _cu _cn; do
        if pinged "$_ca"; then echo "$_ca ping up"; else echo "$_ca ping down"; fi
        for _cx in $(printf '%s' "$_ct" | tr ',' ' '); do
            _cp=${_cx%%-*}
            probe "$_ca" "$_cp"; _cr=$?
            case "$_cr" in 0) echo "$_ca $_cp up" ;; 2) echo "$_ca $_cp unknown" ;; *) echo "$_ca $_cp down" ;; esac
        done
    done <"$W/scored" >"$1"
}
# refused VENDOR FILE -> the first line where the device refused a command (empty: none)
refused() {
    case "$1" in
        paloalto)  _re='Invalid syntax|Unknown command|Server error|Commit failed|Validation Error|is not a valid reference|is invalid' ;;
        cisco-*)   _re='^ERROR:|% Invalid|% Incomplete|% Ambiguous|% Unknown' ;;
        fortigate) _re='Command fail|command parse error|entry not found|node_check_object fail|value parse error|Unknown action' ;;
        mikrotik)  _re='failure:|syntax error|bad command name|expected end of command|no such item|input does not match' ;;
        *)         _re='Error:|sudo: |command not found|Permission denied|Operation not permitted' ;;
    esac
    tr -d '\r' <"$2" | grep -iE "$_re" | head -n 1 | cut -c1-100
}
broke() { awk 'NR == FNR { b[$1 " " $2] = $3; next } b[$1 " " $2] == "up" && $3 == "down" { printf "%s:%s ", $1, $2 }' "$1" "$2"; }
pre()  { case "$1" in cisco-*) en "$1" ;; paloalto) printf 'set cli pager off\nconfigure\n' ;; esac; }
post() { case "$1" in paloalto) printf 'commit\n' ;; esac; }
save() { case "$1" in cisco-asa) printf 'write memory\n' ;; paloalto) printf 'exit\n' ;; esac; }
quit() { case "$1" in mikrotik) printf '/quit\n' ;; *) printf 'exit\n' ;; esac; }
verify_cmds() {
    case "$1" in
        cisco-*|paloalto) printf 'show clock\nexit\n' ;;
        fortigate) printf 'get system status\nexit\n' ;;
        mikrotik) printf '/system identity print\n/quit\n' ;;
        *) printf 'id\nexit\n' ;;
    esac
}
try_login() {
    verify_cmds "$1" >"$W/vin"; _tu=$2; _ta=$3; _tp=$4
    sshopts >"$W/opts"; set --; while IFS= read -r _o; do set -- "$@" "$_o"; done <"$W/opts"
    SSHPASS=$BT_NET_PASS "$SSHPASS_BIN" -e "$SSH" "$@" -p "$_tp" "$_tu@$_ta" <"$W/vin" >/dev/null 2>"$W/verr"
}
# undo_lines VENDOR DEVICE -> what takes the rules out (with config mode)
undo_lines() {
    case "$1" in
        paloalto) printf 'configure\n'; cat "$W/undo.$2"; printf 'commit\nexit\n' ;;
        mikrotik|linux|openwrt) cat "$W/undo.$2" ;;
        *) cat "$W/undo.$2" ;;
    esac
}
write_undo() {   # write_undo VENDOR DEVICE ADDRESS USER PORT -> undo/DEVICE.sh and --out/nw20-DEVICE.undo
    mkdir -p "$CC_RUN_DIR/undo"; _uf="$CC_RUN_DIR/undo/$2.sh"
    undo_lines "$1" "$2" >"$CC_OUT/nw20-$2.undo"
    {
        printf '#!/bin/sh\n# Takes NW-20'"'"'s rules off %s.  Needs the device password in BT_NET_PASS.\n' "$2"
        printf '[ -n "$BT_NET_PASS" ] || { echo "set BT_NET_PASS to the device password first" >&2; exit 1; }\nSSHPASS=$BT_NET_PASS; export SSHPASS\n'
        if [ "$(read_mode "$1")" = exec ]; then
            printf "CMDS=\$(cat <<'CMDS'\n"; cat "$CC_OUT/nw20-$2.undo"; printf 'CMDS\n)\n'
            [ "$1" = mikrotik ] && printf 'CMDS=$(printf "%%s" "$CMDS" | tr "\\n" ";")\n'
            printf '%s -e %s %s-p %s %s "$CMDS" </dev/null\n' "$(cc_shquote "$SSHPASS_BIN")" "$(cc_shquote "$SSH")" "$(sshopts | while IFS= read -r _o; do printf '%s ' "$(cc_shquote "$_o")"; done)" "$5" "$(cc_shquote "$4@$3")"
        else
            printf '{\n'; case "$1" in cisco-*) [ "$ENABLE" = 1 ] && printf '    printf "enable\\n%%s\\n" "$BT_NET_ENABLE"\n' ;; esac
            printf "    cat <<'CMDS'\n"; cat "$CC_OUT/nw20-$2.undo"; printf 'exit\nCMDS\n'
            printf '} | %s -e %s %s-p %s %s\n' "$(cc_shquote "$SSHPASS_BIN")" "$(cc_shquote "$SSH")" "$(sshopts | while IFS= read -r _o; do printf '%s ' "$(cc_shquote "$_o")"; done)" "$5" "$(cc_shquote "$4@$3")"
        fi
        printf 'rm -f %s\n' "$(cc_shquote "$CC_OUT/nw20-$2.undo")"
    } >"$_uf"
    chmod 700 "$_uf"; printf '%s' "$_uf"
}
# putback -> take the rules off the device being changed ($_n ...): through the
# open session when it is still there, else a new one
putback() {
    if [ -n "$_spid" ] && kill -0 "$_spid" 2>/dev/null; then
        # Palo Alto: the open session is still in config mode
        { [ "$_v" = paloalto ] && printf 'exit\n'; undo_lines "$_v" "$_n"; quit "$_v"; } >&3 2>/dev/null; exec 3>&-; wait "$_spid" 2>/dev/null
    else
        [ -n "$_spid" ] && { exec 3>&- 2>/dev/null; wait "$_spid" 2>/dev/null; }
        undo_lines "$_v" "$_n" >"$W/un"; send "$_v" "$_u" "$_a" "$_p" "$W/un"
    fi
    rm -f "$CC_OUT/nw20-$_n.undo"
}
# Ctrl-C (or a kill) while a firewall is being changed: put it back first
CUR=""
onstop() {
    trap '' INT TERM HUP
    if [ -n "$CUR" ]; then
        printf '\n' >&2; cc_show "$C_RED" "  [x] stopped while $CUR was being changed - putting it back"
        putback; cc_show "$C_YEL" "  [*] $CUR: put back. Check it: the undo is $_uf"
    fi
    rm -rf "$W"; exit 130
}
trap onstop INT TERM HUP
NOK=0; NBAD=0; APPLIED=0; : >"$CC_RUN_DIR/checks.txt"
trap '' PIPE
if [ ! -s "$W/ready" ]; then cc_show "$C_GRY" "  No firewall to change."
elif [ "$CC_APPLY" != 1 ]; then
    cc_show "$C_GRY" "  Dry run: nothing was changed. Read plan.txt and commands-DEVICE.txt, then run again with --apply (ONE device first)."
    # shellcheck disable=SC2034  # read by cc_finish
    CC_N_WOULD=$(grep -c . "$W/ready")
else
    cc_show "" "  Checking every scored box:port and ping from this box first (the same checks run after the change)..."
    checks "$W/before"
    while IFS= read -r _l; do cc_show "" "    before: $_l"; done <"$W/before"
    grep -q ' unknown$' "$W/before" && cc_show "$C_YEL" "  [*] no nc (with -z) or bash + timeout here: ports cannot be checked, only ping"
    if grep -q ' ping up$' "$W/before" && ! grep -v ' ping ' "$W/before" | grep -q ' up$' && grep -v ' ping ' "$W/before" | grep -q .; then
        cc_show "$C_YEL" "  [*] no scored PORT answered from here, only ping: the automatic check only sees ping. Watch the scoreboard."
    fi
    if ! grep -q ' up$' "$W/before"; then
        cc_show "$C_RED" "  [!] NOTHING answered from this box before the change: the automatic check cannot protect the scored services."
        cc_ask "Go on anyway (you watch the scoreboard yourself)?" N "yes, go on" "no, stop - run it from a box that reaches the scored services" || { cc_show "$C_GRY" "  Stopped: nothing was changed."; : >"$W/ready"; }
    fi
    while IFS='|' read -r _n _a _v _u _p; do
        cc_show "" ""; cc_show "$C_CYN" "  -- $_n ($_v)"
        while IFS= read -r _l; do cc_show "" "    $_l"; done <<EOF
$(sed -n "/^$_n (/,/^\$/p" "$CC_RUN_DIR/plan.txt")
EOF
        cc_ask "Put these rules on $_n now?" Y "yes (checked right after; put back at once if a scored service stops answering)" "no, skip this firewall" || { cc_show "$C_GRY" "  skipped $_n"; continue; }
        APPLIED=1
        # the undo is written BEFORE anything is sent, so --remove works even if this run is killed
        _uf=$(write_undo "$_v" "$_n" "$_a" "$_u" "$_p")
        rm -f "$W/fifo"; mkfifo "$W/fifo"; _sess="$W/sess.$_n"; : >"$_sess"
        sshopts >"$W/opts"; set --; while IFS= read -r _o; do set -- "$@" "$_o"; done <"$W/opts"
        CUR=$_n; _spid=""
        if [ "$(read_mode "$_v")" = exec ]; then
            # MikroTik and Linux: the commands as one exec; the undo goes in a second session if needed
            SSHPASS=$BT_NET_PASS "$SSHPASS_BIN" -e "$SSH" "$@" -p "$_p" "$_u@$_a" "$(oneline "$_v" "$W/fix.$_n")" </dev/null >"$_sess" 2>&1; _sent=$?
        else
            SSHPASS=$BT_NET_PASS "$SSHPASS_BIN" -e "$SSH" "$@" -p "$_p" "$_u@$_a" <"$W/fifo" >"$_sess" 2>&1 &
            _spid=$!
            exec 3>"$W/fifo"
            { pre "$_v"; cat "$W/fix.$_n"; post "$_v"; } >&3 2>/dev/null
            _sent=0
        fi
        _w=$WAIT
        if [ "$_v" = paloalto ]; then
            # wait for the commit to finish (or fail), at most --commit-wait seconds, then --wait more
            _cw=0; _w=0
            while [ "$_cw" -lt "$CWAIT" ] && ! grep -qiE 'committed successfully|Commit failed|commit.*fail' "$_sess"; do nap 1; _cw=$((_cw + 1)); done
            grep -qi 'committed successfully' "$_sess" && _w=$WAIT
        fi
        nap "$_w"
        _keep=1; _why=""
        [ "$_sent" = 0 ] || { _keep=0; _why="the commands did not go through"; }
        _rf=$(refused "$_v" "$_sess")
        [ "$_keep" = 1 ] && [ -n "$_rf" ] && { _keep=0; _why="the firewall refused a command: $_rf"; }
        [ "$_keep" = 1 ] && [ "$_v" = paloalto ] && ! grep -qi 'committed successfully' "$_sess" && { _keep=0; _why="Palo Alto did not say the commit worked within $CWAIT seconds (--commit-wait)"; }
        [ "$_keep" = 1 ] && [ -n "$_spid" ] && ! kill -0 "$_spid" 2>/dev/null && { _keep=0; _why="the device closed the session"; }
        if [ "$_keep" = 1 ]; then
            checks "$W/after"
            _b=$(broke "$W/before" "$W/after")
            if [ -n "$_b" ]; then _keep=0; _why="these stopped answering: $_b"; fi
        fi
        if [ "$_keep" = 1 ] && ! try_login "$_v" "$_u" "$_a" "$_p"; then _keep=0; _why="a new login to the firewall fails"; fi
        if [ "$_keep" = 1 ] && [ "$CC_BATCH" != 1 ] && _cc_can_ask; then
            cc_show "$C_YEL" "  [*] Every scored service that answered before still answers from here. Now look at the SCOREBOARD (and a service from outside if you can)."
            CC_TIMER_DEADLINE=$(( $(cc_now) + TIMER ))
            cc_ask_keep || { _keep=0; _why="not confirmed"; }
            # shellcheck disable=SC2034  # read by the library's question timer
            CC_TIMER_DEADLINE=0
        fi
        if [ "$_keep" = 1 ]; then
            [ -n "$_spid" ] && { { save "$_v"; quit "$_v"; } >&3 2>/dev/null; exec 3>&-; wait "$_spid" 2>/dev/null; }
            CUR=""; cat "$_sess" >>"$CC_LOG"
            cc_undo_add "take NW-20's rules off $_n" "sh $(cc_shquote "$_uf")"
            NOK=$((NOK + 1)); cc_show "$C_GRN" "  [+] $_n: rules on, scored services still answer. Undo: sh $_uf  (or this script with --remove --apply)"
            { printf '%s: kept\n' "$_n"; sed 's/^/  after: /' "$W/after" 2>/dev/null; } >>"$CC_RUN_DIR/checks.txt"
        else
            cc_show "$C_RED" "  [x] $_n: $_why - putting it back"
            putback; CUR=""; cat "$_sess" >>"$CC_LOG"
            nap "$_w"
            checks "$W/after2"
            _b=$(broke "$W/before" "$W/after2")
            if [ -z "$_b" ]; then cc_show "$C_GRN" "  [+] $_n: put back; the scored services answer as before"
            else cc_show "$C_RED" "  [x] $_n: put back, but still not answering: $_b - run the undo by hand: sh $_uf"; fi
            NBAD=$((NBAD + 1))
            { printf '%s: put back (%s)\n' "$_n" "$_why"; sed 's/^/  after: /' "$W/after" 2>/dev/null; } >>"$CC_RUN_DIR/checks.txt"
        fi
    done <"$W/ready"
    sed 's/^/before: /' "$W/before" >>"$CC_RUN_DIR/checks.txt"
fi
# shellcheck disable=SC2034  # read by cc_finish
CC_N_DONE=$NOK
# shellcheck disable=SC2034  # read by cc_finish
CC_N_FAIL=$NBAD

# ---- 6. Summary ---------------------------------------------------------------------------
header "6/6  summary"
{
    printf '==========[ summary ]==========\n'
    printf 'NW-20 Firewall ruleset | %s\n' "$([ "$APPLIED" = 1 ] && echo APPLIED || echo 'DRY RUN - nothing changed')"
    printf 'Scored boxes: %d   Rules: %d   Outgoing limits: %s   Threat prevention: %s\n' "$(grep -c . "$W/scored")" "$NRULES" "$([ "$RESTRICT" = y ] && echo yes || echo no)" "$([ "$THREAT" = y ] && echo yes || echo no)"
    [ "$APPLIED" = 1 ] && printf 'Kept: %d   Put back: %d\n' "$NOK" "$NBAD"
    printf 'The plan in words: plan.txt   exact commands: commands-DEVICE.txt   checks: checks.txt\n'
    printf 'Take the rules out again: sh %s/undo/DEVICE.sh  or  NW-20 --device ... --remove --apply\n' "$CC_RUN_DIR"
    printf '\nNext: NW-01 again (the rules become the saved copy); watch the scoreboard; drops are logged with bt- in the firewall log.\n'
} >"$CC_RUN_DIR/summary.txt"
while IFS= read -r _l; do case "$_l" in ==*|NW-20*) cc_show "$C_CYN" "$_l" ;; *'Put back: '[1-9]*) cc_show "$C_RED" "$_l" ;; *) cc_show "" "$_l" ;; esac; done <"$CC_RUN_DIR/summary.txt"
rm -rf "$W"
cc_finish
