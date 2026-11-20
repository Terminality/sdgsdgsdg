#!/bin/sh
# =============================================================================
# ID:       NW-30
# NAME:     Device change watch
# ROLE:     Network  (wave 2, after NW-01; leave it running)
# KIND:     readonly - only "show" commands are sent; nothing on a device changes
# VERSION:  1.1.0
#
# PURPOSE
#   Reads every firewall, router and switch every few minutes and compares
#   it with a BASELINE (the config you trust).  Every line that was added,
#   removed or moved since is shown once, with:
#     how bad it is      HIGH (accounts, passwords, SNMP, NAT, firewall
#                        rules, management access, routes, logging, AAA,
#                        VPN, scheduled scripts) or MED (anything else)
#     what it may mean   e.g. "a new account: a back door?"
#     where it is        the section it is in (interface, policy, chain ...)
#     how to undo it     a suggested command - NEVER sent; you check and type it
#   Then you are asked: was this ours?
#     [n] not ours (default): it stays on the "open" list; when it goes away
#         (someone put it back) that is shown too
#     [o] ours: these lines become part of the baseline and are not shown again
#     [e] each one: asked line by line
#   Lines with NW-20/NW-21's own names (bt-, BT-IN, BT-MGMT ...) are marked
#   "probably ours (NW-20/NW-21)".  Nothing is ever accepted without a person:
#   with --batch every change stays open.
#
#   Brands: cisco-ios, cisco-asa, paloalto, fortigate, vyos, mikrotik,
#   pfsense / opnsense (log in as root), linux (a Linux router), openwrt
#   (log in as root: every uci setting, the fw4 rules, accounts, root's SSH
#   keys, cron, boot scripts) - the same reads as NW-01.
#
#   QUESTIONS (Enter takes the default in capitals; a flag answers each):
#     watch these devices?                       Y
#     each device: which baseline?               [k]eep the earlier one /
#                                                [n]W-01's copy / [f]resh now
#                                                (--baseline keep|nw01|fresh)
#     how often?                                 every 2 minutes (--every)
#     for how long?                              until Ctrl-C   (--for, --once)
#     new changes on DEVICE: ours?               [N]ot ours / [o]urs / [e]ach
#
# USAGE
#   BT_NET_PASS='pw' sh NW-30-device-watch.sh --hosts config/hosts.txt
#   BT_NET_PASS='pw' sh NW-30-device-watch.sh --device fw1,10.0.0.1,paloalto --every 60
#   BT_NET_PASS='pw' sh NW-30-device-watch.sh --hosts config/hosts.txt --once --batch   (from cron)
#
# OPTIONS
#   --device NAME,ADDRESS,VENDOR[,USER[,PORT]]   a device (repeat)
#   --hosts FILE       or the devices from the host list
#   --baseline WHICH   keep (the earlier NW-30 baseline), nw01 (NW-01's
#                      newest copy), fresh (read it now); default: asked,
#                      else keep, else nw01, else fresh
#   --every N          seconds between rounds (default 120, at least 10)
#   --for N            minutes to watch (0 = until Ctrl-C)
#   --once             one round, then stop (the same as --rounds 1)
#   --rounds N         this many rounds, then stop
#   --quiet            no bell on a HIGH change
#   --user NAME / --ask-password / --enable-env / --legacy-ssh   as NW-21
#   --no-color         no colours
#   --help             this text plus the common options
#
# OUTPUTS  (under --out, in device-watch-N/)
#   output.txt     everything shown on screen, without colour
#   changes.txt    every change seen: time, device, HIGH/MED, added/removed/
#                  moved, the line (secrets masked), where, what it may mean
#   undo-hints.txt a suggested undo per change (never sent)
#   rounds.txt     each round: each device read or not, changes
#   summary.txt    the open (not ours) changes at the end
#   net-watch/DEVICE/ in --out (mode 700, kept between runs):
#     base.norm  the baseline   ok  the lines you said were ours
#     open       the not-ours changes still there   copies/  each changed read
#
# WHAT IT CHANGES
#   Nothing on any device: the same show / export commands as NW-01.  Saved
#   reads hold password hashes and keys: mode 600, and secrets are masked in
#   everything shown or written to the run folder.
#
# DEPENDS ON
#   ssh, sshpass, diff, awk.
#
# TESTED ON
#   A stand-in device for every brand (its config changed between rounds)
#   under dash, bash, busybox sh, ksh93, mksh and yash with gawk, mawk and
#   busybox awk.  NOT yet on real devices: run --once first and check that
#   a quiet device shows no changes (a line that changes by itself on every
#   read is noise - tell us the brand and the line).
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - FortiGate shows encrypted secrets (ENC ...) differently on each read:
#     they are hidden before comparing, so a changed secret is not seen
#     (a new admin or key entry still is).
#   - MikroTik exports without secrets unless the login may see them.
#   - A changed SSH host key stops the watch of that device (HIGH): find out
#     why before trusting it.
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
NW-30 Device change watch - every change on the network devices, shown once; read-only
  BT_NET_PASS=pw sh NW-30-device-watch.sh --hosts FILE | --device NAME,ADDRESS,VENDOR [options]

  --device NAME,ADDRESS,VENDOR[,USER[,PORT]]   a device (repeat), or --hosts FILE
  --baseline keep|nw01|fresh   which config is trusted (else asked)
  --every N          seconds between rounds (default 120)
  --for N            minutes (0 = until Ctrl-C)   --once / --rounds N
  --quiet            no bell on a HIGH change
  --user NAME / --ask-password / --enable-env / --legacy-ssh
  --no-color         no colours
  --help             show this text
USAGE
    cc_usage_common
}

NL='
'
HOSTS=""; DEVICES=""; DEFUSER="admin"; ASK=0; ENABLE=0; LEGACY=0; COLOR=1
BASE=""; EVERY=""; FOR=""; ROUNDS=""; QUIET=0
num() { case "$2" in ''|*[!0-9]*) cc_die 2 "$1 needs a whole number" ;; esac; }
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --hosts)        [ $# -ge 2 ] || cc_die 2 "--hosts needs a file"; [ -r "$2" ] || cc_die 2 "--hosts: cannot read $2"; HOSTS=$2; shift 2 ;;
        --device)       [ $# -ge 2 ] || cc_die 2 "--device needs NAME,ADDRESS,VENDOR"; DEVICES="$DEVICES$2$NL"; shift 2 ;;
        --user)         [ $# -ge 2 ] || cc_die 2 "--user needs a name"; DEFUSER=$2; shift 2 ;;
        --ask-password) ASK=1; shift ;;
        --enable-env)   ENABLE=1; shift ;;
        --legacy-ssh)   LEGACY=1; shift ;;
        --baseline)     [ $# -ge 2 ] || cc_die 2 "--baseline needs keep, nw01 or fresh"
                        case "$2" in keep|nw01|fresh) BASE=$2 ;; *) cc_die 2 "--baseline: keep, nw01 or fresh" ;; esac; shift 2 ;;
        --every)        num "$1" "${2:-}"; EVERY=$2; shift 2 ;;
        --for)          num "$1" "${2:-}"; FOR=$2; shift 2 ;;
        --once)         ROUNDS=1; shift ;;
        --rounds)       num "$1" "${2:-}"; ROUNDS=$2; shift 2 ;;
        --quiet)        QUIET=1; shift ;;
        --no-color|--no-colour) COLOR=0; shift ;;
        --help|-h)      usage; exit 0 ;;
        *)              cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
[ -n "$HOSTS$DEVICES" ] || cc_die 2 "give the devices: --hosts FILE or --device NAME,ADDRESS,VENDOR (try --help)"
[ -z "$EVERY" ] || [ "$EVERY" -ge 10 ] || [ -n "${BT_TEST_FAST:-}" ] || cc_die 2 "--every: at least 10 seconds"
[ "$ROUNDS" = 0 ] && cc_die 2 "--rounds: at least 1"

cc_init "NW-30" "Device change watch" readonly
# shellcheck disable=SC2034  # read by cc_color_init
[ "$COLOR" = 1 ] || CC_NOCOLOR=1
cc_color_init
cc_use_numbered_dir device-watch
rmdir "$CC_RUN_DIR/raw" 2>/dev/null
OUTF="$CC_RUN_DIR/output.txt"
grep -v '\[NOTE\]\|\[DEBUG\]' "$CC_LOG" >"$OUTF" 2>/dev/null || : >"$OUTF"
# shellcheck disable=SC2034  # CC_TEE is read by the library's log functions
CC_TEE=$OUTF
W="$CC_RUN_DIR/.work"; (umask 077; mkdir -p "$W")
US=$(printf '\037')
header() { cc_show "" ""; cc_show "$C_CYN" "==========[ $1 ]=========="; }
CONFIGS="$CC_OUT/net-configs"; (umask 077; mkdir -p "$CONFIGS") 2>/dev/null
STATE="$CC_OUT/net-watch"; (umask 077; mkdir -p "$STATE") || cc_die 3 "cannot create $STATE"
SSH=${BT_SSH:-$(cc_which ssh)} || cc_die 3 "ssh not found"
SSHPASS_BIN=${BT_SSHPASS:-$(cc_which sshpass)} || cc_die 3 "sshpass not found (apt install sshpass)"
cc_have diff || cc_die 3 "diff not found"
if [ "$ASK" = 1 ]; then
    [ -r /dev/tty ] || cc_die 3 "--ask-password needs a terminal; set BT_NET_PASS"
    printf 'Device password: ' >/dev/tty; stty -echo </dev/tty 2>/dev/null
    read -r BT_NET_PASS </dev/tty; stty echo </dev/tty 2>/dev/null; printf '\n' >/dev/tty
fi
[ -n "${BT_NET_PASS:-}" ] || cc_die 3 "the device password is needed: set BT_NET_PASS or use --ask-password"
[ "$ENABLE" = 1 ] && [ -z "${BT_NET_ENABLE:-}" ] && cc_die 3 "--enable-env: set BT_NET_ENABLE"

cc_show "$C_CYN" "NW-30 Device change watch | from $CC_HOST | results in $CC_RUN_DIR"
cc_show "" "Legend: ${C_RED}[!] HIGH${C_OFF} change   ${C_YEL}[*] MED${C_OFF} change   ${C_GRN}[ok]${C_OFF} no change / back as before   ${C_GRY}[-]${C_OFF} information"

# ---- Devices ------------------------------------------------------------------------------
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
        /openwrt|lede|luci/ { print "openwrt"; exit }
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

# ---- Reading a device (the same reads as NW-01) ---------------------------------------------
sshopts() {
    set -- -T -o ConnectTimeout=10 -o "UserKnownHostsFile=$CONFIGS/known_hosts" -o StrictHostKeyChecking=accept-new \
        -o LogLevel=ERROR -o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive -o NumberOfPasswordPrompts=1
    [ "$LEGACY" = 1 ] && set -- "$@" -o KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group1-sha1 -o HostKeyAlgorithms=+ssh-rsa -o Ciphers=+aes128-cbc,aes256-cbc,3des-cbc
    printf '%s\n' "$@"
}
read_mode() { case "$1" in cisco-ios|cisco-asa|paloalto|fortigate) echo stdin ;; *) echo exec ;; esac; }
read_cmds() {
    case "$1" in cisco-*) [ "$ENABLE" = 1 ] && printf 'enable\n%s\n' "$BT_NET_ENABLE" ;; esac
    case "$1" in
        cisco-ios) printf 'terminal length 0\nshow running-config\nexit\n' ;;
        cisco-asa) printf 'terminal pager 0\nshow running-config\nexit\n' ;;
        paloalto)  printf 'set cli pager off\nshow config running\nexit\n' ;;
        fortigate) printf 'show\nexit\n' ;;
        vyos)      printf '/opt/vyatta/bin/vyatta-op-cmd-wrapper show configuration commands' ;;
        pfsense|opnsense) printf 'cat /conf/config.xml' ;;
        mikrotik)  printf '/export' ;;
        linux)     printf 'S=; [ "$(id -u)" = 0 ] || S="sudo -n"; $S iptables-save 2>/dev/null; $S nft list ruleset 2>/dev/null; ip -o addr 2>/dev/null; ip route 2>/dev/null' ;;
        # OpenWRT: the same read as NW-01, so its copies are a baseline.
        openwrt)   printf 'echo "===release"; cat /etc/openwrt_release 2>/dev/null; echo "===uci"; uci export 2>/dev/null; echo "===nft"; nft list ruleset 2>/dev/null; echo "===addr"; ip -o addr 2>/dev/null; echo "===route"; ip route 2>/dev/null; echo "===passwd"; cat /etc/passwd 2>/dev/null; echo "===keys"; cat /etc/dropbear/authorized_keys /root/.ssh/authorized_keys 2>/dev/null; echo "===cron"; cat /etc/crontabs/* 2>/dev/null; echo "===startup"; ls /etc/rc.d 2>/dev/null; echo "===rc.local"; cat /etc/rc.local 2>/dev/null' ;;
    esac
}
# readdev VENDOR USER ADDRESS PORT OUT -> the device's config in OUT; errors in $W/err
readdev() {
    read_cmds "$1" >"$W/rin"; _rv=$1; _ru=$2; _ra=$3; _rp=$4; _ro=$5
    sshopts >"$W/opts"; set --; while IFS= read -r _o; do set -- "$@" "$_o"; done <"$W/opts"
    if [ "$(read_mode "$_rv")" = exec ]; then
        SSHPASS=$BT_NET_PASS "$SSHPASS_BIN" -e "$SSH" "$@" -p "$_rp" "$_ru@$_ra" "$(cat "$W/rin")" </dev/null >"$_ro" 2>"$W/err"
    else
        SSHPASS=$BT_NET_PASS "$SSHPASS_BIN" -e "$SSH" "$@" -p "$_rp" "$_ru@$_ra" <"$W/rin" >"$_ro" 2>"$W/err"
    fi
}
# NORMALIZE: drop what changes by itself (time stamps, counters, prompts and
# echoed commands) so only real configuration changes are compared.
NORMALIZE='
{ sub(/\r$/, ""); sub(/[ \t]+$/, "") }
/^[^ ]*[>#] *(terminal (length|pager)|show |set cli pager|exit|enable)/ { next }
/^[A-Za-z0-9_.@()-]+[>#] *$/ { next }
v == "cisco-ios" && (/^! Last configuration change/ || /^! NVRAM config last updated/ || /^ntp clock-period/ || /^Current configuration :/ || /^Building configuration/) { next }
v == "cisco-asa" && (/^: Written by/ || /^Cryptochecksum:/ || /^: Serial Number/ || /^: Hardware:/ || /^: Saved/) { next }
v == "fortigate" && (/^#conf_file_ver=/ || /^#config-version=/ || /^#buildno=/ || /^#global_vdom=/) { next }
v == "fortigate" { gsub(/ ENC [^ ]+/, " ENC (hidden)") }
v == "mikrotik" && (/^# [a-z]{3}\/[0-9]+\/[0-9]+ [0-9:]+ by RouterOS/ || /^# [0-9-]+ [0-9:]+ by RouterOS/) { next }
v == "mikrotik" && /\\$/ { sub(/\\$/, ""); held = held $0; next }
v == "mikrotik" && held != "" { sub(/^[ \t]+/, ""); $0 = held $0; held = "" }
v == "linux" && (/^# Generated by iptables-save/ || /^# Completed on/) { next }
v == "linux" && /^:[A-Z-]+ [A-Z-]+ \[[0-9]+:[0-9]+\]/ { sub(/ \[[0-9]+:[0-9]+\]$/, "") }
v == "linux" || v == "openwrt" { gsub(/counter packets [0-9]+ bytes [0-9]+ /, "") }
v == "openwrt" { gsub(/ valid_lft [0-9]+sec preferred_lft [0-9]+sec/, ""); gsub(/ expires [0-9]+sec/, "") }
v == "pfsense" || v == "opnsense" { if ($0 ~ /<(time|revision|lastchange)>/) next }
{ print }'
# MASK: secrets hidden in everything shown or written to the run folder.
MASK='
function mask(s,   n, w, i, out, lw, m) {  # awk, not shell: posix-ok
    if (match(s, /<(password|community|rocommunity|rwcommunity|pre-shared-key|secret|psk|key|phash|bcrypt-hash|sha512-hash|authorizedkeys)>[^<]*</)) {
        m = substr(s, RSTART, RLENGTH); sub(/>[^<]*</, ">****<", m)
        s = substr(s, 1, RSTART - 1) m substr(s, RSTART + RLENGTH)
    }
    n = split(s, w, " "); out = ""
    for (i = 1; i <= n; i++) {
        lw = tolower(w[i]); gsub(/[^a-z-]/, "", lw)
        if (lw ~ /^(password|secret|community|key|key-string|psk|psksecret|pre-shared-key|passphrase|passwd|authentication-key|plaintext-password|encrypted-password|enc|phash)$/ && i < n) {
            out = out (out ? " " : "") w[i]
            if (w[i + 1] ~ /^[0-9]$/ && i + 2 <= n) { i++; out = out " " w[i] }
            i++; out = out " ****"; continue
        }
        if (lw ~ /^(password|secret|community)=/) { sub(/=.*/, "=****", w[i]) }
        out = out (out ? " " : "") w[i]
    }
    return out
}'

# ---- Where a line is, what it may mean, how it could be undone ---------------------------------
# where VENDOR FILE -> "line US section" for each line (the section it sits in)
where() {
    awk -v v="$1" -v US="$US" '
        { l = $0 }
        v == "cisco-ios" || v == "cisco-asa" { if (l !~ /^[ \t]/) { p = l; print l US ""; next } print l US p; next }
        v == "fortigate" {
            t = l; sub(/^[ \t]+/, "", t)
            if (t ~ /^config /) { s[++n] = t; print l US path(); next }
            if (t ~ /^edit /) { s[++n] = t; print l US path(); next }
            if (t == "next" || t == "end") { if (n > 0) n--; print l US path(); next }
            print l US path(); next }
        v == "paloalto" || v == "linux" {
            t = l; sub(/^[ \t]+/, "", t)
            if (v == "linux" && t ~ /^\*/) { tb = t; n = 0 }
            if (t ~ /\{$/) { print l US path(); x = t; sub(/[ \t]*\{$/, "", x); s[++n] = x; next }
            if (t ~ /^\}/) { if (n > 0) n--; print l US path(); next }
            print l US (v == "linux" && tb != "" && n == 0 ? tb : path()); next }
        v == "mikrotik" { if (l ~ /^\//) { p = l; print l US ""; next } print l US p; next }
        # OpenWRT: "===part" headers; in the uci part "package P" and
        # "config TYPE name" give the section; the nft part nests in braces.
        v == "openwrt" && l ~ /^===/ { part = substr(l, 4); pk = ""; cf = ""; n = 0; print l US ""; next }
        v == "openwrt" && part == "uci" {
            if (l ~ /^package /) { pk = l; cf = ""; print l US ""; next }
            if (l ~ /^config /) { cf = l; print l US pk; next }
            print l US (pk (cf != "" ? " > " cf : "")); next }
        v == "openwrt" && part == "nft" {
            t = l; sub(/^[ \t]+/, "", t)
            if (t ~ /\{$/) { print l US path(); x = t; sub(/[ \t]*\{$/, "", x); s[++n] = x; next }
            if (t ~ /^\}/) { if (n > 0) n--; print l US path(); next }
            print l US path(); next }
        v == "openwrt" { print l US part; next }
        { print l US "" }
        function path(   i, o) {  # awk, not shell: posix-ok
            o = ""; for (i = 1; i <= n; i++) o = o (o == "" ? "" : " > ") s[i]; return o }' "$2"
}
# judge -> reads "sign US line US section"; the line decides, else its section
# (a MikroTik "add name=x" under "/user" is an account)
judge() {
    awk -F"$US" -v OFS="$US" '
    function cls(l) {  # awk, not shell: posix-ok
        c = ""; m = ""
        if (l ~ /(username|local-user|system login user|config system admin|\/user add|user add|^\/user|<user>|create user| admin |^passwd$|config login)/) { c = "account"; m = "an account added or changed: a back door?" }
        else if (l ~ /(password|secret|passwd|key-string|phash|psksecret|authorized-?keys|ssh-rsa|ssh-ed25519|^keys$)/) { c = "password/key"; m = "a password or key changed: a known password or a planted key?" }
        else if (l ~ /(snmp|community)/) { c = "SNMP"; m = "a community the red team knows?" }
        else if (l ~ /(kron|event manager|scheduler|\/system script|cron|<cron>|crontab|^startup$|rc\.local)/) { c = "scheduled job"; m = "a scheduled job or script: something that comes back by itself?" }
        else if (l ~ /(aaa|tacacs|radius|ldap)/) { c = "AAA"; m = "who may log in, or how, changed" }
        else if (l ~ /(crypto|tunnel|ipsec|vpn|wireguard|pre-shared|gre |l2tp|pptp)/) { c = "VPN/tunnel"; m = "a tunnel: a way in or a way out for data?" }
        else if (l ~ /((^|[^a-z])nat([^a-z]|$)|static \(|port-forward|dst-nat|dstnat|vip|destination-translation|masquerade|<rdr>|config redirect|dnat|upnpd)/) { c = "NAT"; m = "a port forwarded in to a box?" }
        else if (l ~ /(telnet|http server|ip http|allowaccess|line vty|transport input|management|service www|winbox|service (ssh|api|ftp)|set ssh|ssh version|webgui|<webgui>|permitted-ip|trusthost|ssh [0-9]|dropbear|uhttpd|rpcd)/) { c = "management access"; m = "who may manage the device, or over what, changed" }
        else if (l ~ /(access-list|access-group|permit|deny|allow|accept|drop|reject|rulebase|firewall policy|firewall filter|^-a |^-i |^-d |chain|rule|<filter>|security-policy|config (zone|forwarding|defaults))/) { c = "firewall rule"; m = "something let in, or something blocked (a scored service?)" }
        else if (l ~ /(logging|syslog|log-|log |<syslog>|log_ip|log_port)/) { c = "logging"; m = "logging changed: someone hiding what they do?" }
        else if (l ~ /(route|gateway|ospf|bgp|(^|[^a-z])rip([^a-z]|$)|eigrp)/) { c = "routing"; m = "traffic sent somewhere else?" }
        else if (l ~ /(shutdown|disable|disabled)/) { c = "turned off"; m = "a service or a port taken down?" }
        else if (l ~ /(dns|name-server|nameserver|ntp)/) { c = "DNS/time"; m = "where the device asks for names or time changed" }
    }
    { cls(tolower($2)); if (c == "" && $3 != "") cls(tolower($3))
      sev = (c == "" || c == "DNS/time") ? "MED" : "HIGH"
      if (c == "") { c = "other"; m = "a change" }
      print sev, c, m, $1, $2 }'
}
# hint VENDOR SIGN LINE SECTION -> a suggested undo (shown only; never sent)
hint() {
    _hv=$1; _hs=$2; _hl=$3; _hp=$4
    _ht=$(printf '%s' "$_hl" | sed 's/^[ \t]*//')
    case "$_hv" in
        cisco-ios|cisco-asa)
            _hw=""; [ -n "$_hp" ] && _hw="$_hp / "
            case "$_hs" in
                +) case "$_ht" in "no "*) printf 'configure terminal / %s%s' "$_hw" "${_ht#no }" ;; *) printf 'configure terminal / %sno %s' "$_hw" "$_ht" ;; esac ;;
                -) printf 'configure terminal / %s%s' "$_hw" "$_ht" ;;
                *) printf 'the order changed (a rule above or below another now): put it back in its old place, see the saved copy' ;;
            esac ;;
        vyos)
            case "$_hs" in
                +) case "$_ht" in "set "*) printf 'configure / delete %s / commit / save' "${_ht#set }" ;; *) printf 'configure, then undo: %s' "$_ht" ;; esac ;;
                -) printf 'configure / %s / commit / save' "$_ht" ;;
                *) printf 'the order changed: compare with the saved copy' ;;
            esac ;;
        linux)
            case "$_hs$_ht" in
                +-A\ *) printf 'iptables -t %s -D %s' "$(printf '%s' "${_hp:-*filter}" | tr -d '*')" "${_ht#-A }" ;;
                --A\ *) printf 'iptables -t %s -A %s   (put it back where it was)' "$(printf '%s' "${_hp:-*filter}" | tr -d '*')" "${_ht#-A }" ;;
                +table\ *) printf 'nft delete table %s' "$(printf '%s' "${_ht#table }" | sed 's/ *{$//')" ;;
                +chain\ *) printf 'nft delete chain %s %s' "$(printf '%s' "${_hp#table }" | sed 's/ > .*//')" "$(printf '%s' "${_ht#chain }" | sed 's/ *{$//')" ;;
                +*) printf 'nft -a list ruleset, find it under "%s", then nft delete rule ... handle N' "$_hp" ;;
                *) printf 'put it back under "%s" (see the saved copy)' "$_hp" ;;
            esac ;;
        fortigate)
            case "$_hs$_ht" in
                +set\ *) printf '%s / unset %s / end' "$_hp" "$(printf '%s' "${_ht#set }" | awk '{ print $1 }')" ;;
                +edit\ *) printf '%s / delete %s / end' "$(printf '%s' "$_hp" | sed 's/ > edit .*//')" "${_ht#edit }" ;;
                -set\ *) printf '%s / %s / end' "$_hp" "$_ht" ;;
                *) printf 'under "%s": compare with the saved copy' "$_hp" ;;
            esac ;;
        paloalto) printf 'configure mode or web GUI, under "%s": %s it, then commit' "$_hp" "$([ "$_hs" = + ] && echo 'delete' || echo 'put back')" ;;
        mikrotik)
            case "$_hs" in
                +) printf '%s print, find the new entry (%s), %s remove NUMBER' "${_hp:-the section}" "$(printf '%s' "$_ht" | cut -c1-50)" "${_hp:-}" ;;
                -) printf '%s %s' "$_hp" "$_ht" ;;
                *) printf 'the order changed under %s: compare with the saved copy' "$_hp" ;;
            esac ;;
        pfsense|opnsense) printf 'web GUI: Diagnostics > Backup & Restore > Config History can show and roll back this change' ;;
        openwrt)
            case "$_hp" in
                passwd) printf 'remove the account: delete its line in /etc/passwd and /etc/shadow (NW-12 can disable it)' ;;
                keys) printf 'delete that line from /etc/dropbear/authorized_keys' ;;
                cron) printf 'delete that line with crontab -e, then /etc/init.d/cron restart' ;;
                startup) printf '/etc/init.d/NAME disable; /etc/init.d/NAME stop (NAME without the S50 number)' ;;
                rc.local) printf 'delete that line from /etc/rc.local' ;;
                "package "*)
                    _hk=$(printf '%s' "$_hp" | sed 's/^package \([^ ]*\).*/\1/')
                    _hr="/etc/init.d/$_hk reload"; [ "$_hk" = firewall ] && _hr="fw4 reload"
                    if [ "$_hs" = + ]; then printf 'uci show %s, find it under "%s", uci delete (or set back) that entry; uci commit %s; %s' "$_hk" "$_hp" "$_hk" "$_hr"
                    else printf 'put it back under "%s" with uci set / uci add_list (see the saved copy); uci commit %s; %s' "$_hp" "$_hk" "$_hr"; fi ;;
                *) printf 'nft rules come from uci: undo the uci change above (fw4 reload), or nft -a list ruleset and delete by handle' ;;
            esac ;;
    esac
}
ours_like() { case "$1" in *bt-*|*BT-IN*|*BT-OUT*|*BT-MGMT*|*bt_fw*) return 0 ;; esac; return 1; }

# ---- 1. The devices and their baselines -----------------------------------------------------
header "1/3  devices and baselines"
while IFS='|' read -r _n _a _v _u _p; do cc_show "" "  $_n  $_a  $_v  (login $_u, port $_p)"; done <"$W/devices"
if ! cc_ask "Watch these $(grep -c . "$W/devices") device(s)? (read-only: only show commands are sent)" Y "yes" "no, stop"; then
    cc_show "$C_GRY" "  Stopped."; rm -rf "$W"; cc_finish; exit 0
fi
# fetch DEVICE VENDOR USER ADDRESS PORT -> $W/cur.DEVICE (normalized); 0 read, 1 failed, 2 host key changed
fetch() {
    readdev "$2" "$3" "$4" "$5" "$W/raw.$1"; _frc=$?
    if grep -q 'REMOTE HOST IDENTIFICATION HAS CHANGED\|Host key verification failed' "$W/err"; then return 2; fi
    awk -v v="$2" "$NORMALIZE" "$W/raw.$1" >"$W/cur.$1"
    [ "$_frc" = 0 ] && [ "$(grep -c . "$W/cur.$1")" -ge 3 ] && return 0
    _why=$(grep -v '^$' "$W/err" | tail -n 1 | cut -c1-80); [ -n "$_why" ] || _why="empty answer (no rights to show the config?)"
    return 1
}
: >"$W/watch"
while IFS='|' read -r _n _a _v _u _p; do
    _d="$STATE/$_n"; (umask 077; mkdir -p "$_d/copies")
    _nw="$CONFIGS/$_n/$(cat "$CONFIGS/$_n/latest" 2>/dev/null).cfg"
    _have=""; [ -s "$_d/base.norm" ] && [ "$(cat "$_d/vendor" 2>/dev/null)" = "$_v" ] && _have=keep
    _nwok=""; [ -s "$_nw" ] && _nwok=1
    _b=$BASE
    if [ -z "$_b" ]; then
        set -- "f=fresh: read it now and trust what is there now"
        _def=f
        [ -n "$_nwok" ] && { set -- "n=NW-01's copy from $(cat "$CONFIGS/$_n/latest") (catches changes made since then)" "$@"; _def=n; }
        [ -n "$_have" ] && { set -- "k=keep the baseline from the earlier watch ($(cat "$_d/base.when" 2>/dev/null)), with the changes you said were ours" "$@"; _def=k; }
        cc_choose "$_n: which config is the trusted one (the baseline)?" "$_def" "$@"
        case "$CC_CHOICE" in k) _b=keep ;; n) _b=nw01 ;; *) _b=fresh ;; esac
    fi
    if [ "$_b" = keep ] && [ -z "$_have" ]; then cc_show "$C_YEL" "  [*] $_n: no earlier baseline to keep$([ -n "$_nwok" ] && echo ': using NW-01'"'"'s copy' || echo ': reading a fresh one')"; _b=nw01; fi
    if [ "$_b" = nw01 ] && [ -z "$_nwok" ]; then cc_show "$C_YEL" "  [*] $_n: no NW-01 copy: reading a fresh one"; _b=fresh; fi
    case "$_b" in
        keep) cc_show "$C_GRN" "  [ok] $_n: the baseline from $(cat "$_d/base.when" 2>/dev/null)" ;;
        nw01)
            (umask 077; awk -v v="$_v" "$NORMALIZE" "$_nw" >"$_d/base.norm"; : >"$_d/ok"; : >"$_d/open"
             printf '%s\n' "NW-01 copy $(cat "$CONFIGS/$_n/latest")" >"$_d/base.when"; printf '%s\n' "$_v" >"$_d/vendor")
            cc_show "$C_GRN" "  [ok] $_n: the baseline is NW-01's copy from $(cat "$CONFIGS/$_n/latest")" ;;
        fresh)
            fetch "$_n" "$_v" "$_u" "$_a" "$_p"; _fr=$?
            if [ "$_fr" = 2 ]; then cc_show "$C_RED" "  [!] HIGH $_n: its SSH host key CHANGED (device replaced, reinstalled, or someone in the middle): not watched. Check, then remove its line from $CONFIGS/known_hosts"; CC_N_FAIL=$((CC_N_FAIL + 1)); continue; fi
            if [ "$_fr" != 0 ]; then cc_show "$C_RED" "  [x] $_n: could not read it ($_why): not watched"; CC_N_FAIL=$((CC_N_FAIL + 1)); continue; fi
            (umask 077; cp "$W/cur.$_n" "$_d/base.norm"; : >"$_d/ok"; : >"$_d/open"; date -u +%Y-%m-%dT%H:%M:%SZ >"$_d/base.when"; printf '%s\n' "$_v" >"$_d/vendor"
             cp "$W/raw.$_n" "$_d/copies/$(date -u +%Y%m%dT%H%M%SZ)-base.cfg")
            cc_show "$C_GRN" "  [ok] $_n: baseline read now ($(grep -c . "$_d/base.norm") lines)" ;;
    esac
    [ -f "$_d/ok" ] || : >"$_d/ok"; [ -f "$_d/open" ] || : >"$_d/open"
    printf '%s|%s|%s|%s|%s\n' "$_n" "$_a" "$_v" "$_u" "$_p" >>"$W/watch"
done <"$W/devices"
[ -s "$W/watch" ] || { cc_show "$C_RED" "  Nothing to watch."; rm -rf "$W"; cc_finish; exit; }

# ---- 2. How often, how long -------------------------------------------------------------------
header "2/3  how often, how long"
if [ -z "$EVERY" ]; then
    cc_choose "How often should each device be read?" 2 "1=every minute" "2=every 2 minutes" "5=every 5 minutes" "10=every 10 minutes"
    EVERY=$((CC_CHOICE * 60))
fi
if [ -z "$ROUNDS" ] && [ -z "$FOR" ]; then
    if _cc_can_ask; then
        cc_choose "For how long?" u "u=until I press Ctrl-C" "o=once, then stop" "h=an hour" "4=four hours"
        case "$CC_CHOICE" in o) ROUNDS=1 ;; h) FOR=60 ;; 4) FOR=240 ;; *) FOR=0 ;; esac
    else
        ROUNDS=1; cc_show "$C_GRY" "  [-] nobody to ask: one round (use --for or --rounds to watch longer)"
    fi
fi
if [ -z "$ROUNDS" ]; then
    if [ "$FOR" = 0 ]; then ROUNDS=0; else ROUNDS=$(( (FOR * 60 + EVERY - 1) / EVERY )); [ "$ROUNDS" -ge 1 ] || ROUNDS=1; fi
fi
if [ "$ROUNDS" = 0 ]; then cc_show "" "  Every $EVERY seconds until Ctrl-C. Ctrl-C stops it cleanly (the summary is still written)."
else cc_show "" "  $ROUNDS round(s), every $EVERY seconds."; fi

# ---- 3. Watch -----------------------------------------------------------------------------------
header "3/3  watching"
CH="$CC_RUN_DIR/changes.txt"; HI="$CC_RUN_DIR/undo-hints.txt"; RD="$CC_RUN_DIR/rounds.txt"
printf '%-20s %-14s %-5s %-8s %-18s %s\n' time device level change kind line >"$CH"
printf 'Suggested undo for each change. NW-30 never sends these: check each one, then type it yourself.\n\n' >"$HI"
: >"$RD"
NEWALL=0; HIGHALL=0
nap() { sleep "$1" & _nap=$!; wait "$_nap"; }
# setdiff A B -> lines of A that are not in B
# (by file name, not NR == FNR: B may be empty)
setdiff() { awk -v f="$2" 'FILENAME == f { b[$0] = 1; next } !($0 in b)' "$2" "$1"; }

# one_device NAME ADDRESS VENDOR USER PORT -> read, compare, report, ask
one_device() {
    _n=$1; _a=$2; _v=$3; _u=$4; _p=$5; _d="$STATE/$_n"; _t=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    fetch "$_n" "$_v" "$_u" "$_a" "$_p"; _fr=$?
    if [ "$_fr" = 2 ]; then
        cc_show "$C_RED" "  [!] HIGH $_n: its SSH host key CHANGED - device replaced or someone in the middle. No longer read. Check, then remove its line from $CONFIGS/known_hosts"
        printf '%s %s host key CHANGED\n' "$_t" "$_n" >>"$RD"; printf '%-20s %-14s %-5s %-8s %-18s %s\n' "$_t" "$_n" HIGH alert "host key" "the device's SSH host key changed" >>"$CH"
        echo "$_n" >>"$W/drop"; NEWALL=$((NEWALL + 1)); HIGHALL=$((HIGHALL + 1)); return
    fi
    if [ "$_fr" != 0 ]; then
        if [ ! -f "$W/down.$_n" ]; then cc_show "$C_YEL" "  [*] $_n: cannot read it ($_why) - tried again next round"; : >"$W/down.$_n"; fi
        printf '%s %s not read (%s)\n' "$_t" "$_n" "$_why" >>"$RD"; return
    fi
    [ -f "$W/down.$_n" ] && { cc_show "$C_GRN" "  [ok] $_n: can be read again"; rm -f "$W/down.$_n"; }
    # Each line is compared WITH the section it is in (" shutdown" under one
    # interface is not the same as under another).  A change is
    # "+line US section" added, "-..." removed, "~..." moved (in both).
    where "$_v" "$_d/base.norm" >"$W/bctx"; where "$_v" "$W/cur.$_n" >"$W/cctx"
    diff -u "$W/bctx" "$W/cctx" >"$W/diff" 2>/dev/null
    awk 'NR > 2 && /^[-+]/' "$W/diff" | awk -F"$US" '{ t = substr($0, 2); x = $1; sub(/^./, "", x); gsub(/[ \t]/, "", x)
            if (x == "" || x ~ /^(!|exit|next|end|\}|quit|#|\{)$/) next
            s[t] = s[t] substr($0, 1, 1); if (!(t in o)) { o[t] = 1; l[++n] = t } }
         END { for (i = 1; i <= n; i++) { t = l[i]; g = s[t]; print ((g ~ /\+/ && g ~ /-/) ? "~" : substr(g, 1, 1)) t } }' >"$W/now.$_n"
    setdiff "$W/now.$_n" "$_d/ok" >"$W/cur2.$_n"
    # A change you said was ours that is no longer there was UNDONE (by someone):
    # shown once, and taken off the "ours" list.
    setdiff "$_d/ok" "$W/now.$_n" >"$W/undone.$_n"
    if [ -s "$W/undone.$_n" ]; then
        while IFS= read -r _l; do
            _gl=$(printf '%s' "${_l#?}" | cut -d"$US" -f1 | sed 's/^[ \t]*//' | awk "$MASK"'{ print mask($0) }')
            cc_show "$C_RED" "  [!] HIGH $_n: a change you said was OURS was undone: $(printf '%s' "$_gl" | cut -c1-100)"
            printf '%-20s %-14s %-5s %-8s %-18s %s\n' "$_t" "$_n" HIGH undone "ours, undone" "$_gl" >>"$CH"
            NEWALL=$((NEWALL + 1)); HIGHALL=$((HIGHALL + 1))
        done <"$W/undone.$_n"
        setdiff "$_d/ok" "$W/undone.$_n" >"$W/ok.n"; cat "$W/ok.n" >"$_d/ok"
    fi
    setdiff "$W/cur2.$_n" "$_d/open" >"$W/new.$_n"
    setdiff "$_d/open" "$W/cur2.$_n" >"$W/gone.$_n"
    _nn=$(grep -c . "$W/new.$_n"); _ng=$(grep -c . "$W/gone.$_n")
    printf '%s %s read: %s new, %s gone, %s open\n' "$_t" "$_n" "$_nn" "$_ng" "$(grep -c . "$W/cur2.$_n")" >>"$RD"
    while IFS= read -r _l; do
        _gl=$(printf '%s' "${_l#?}" | cut -d"$US" -f1 | sed 's/^[ \t]*//' | awk "$MASK"'{ print mask($0) }')
        cc_show "$C_GRN" "  [ok] $_n: back as in the baseline: $(printf '%s' "$_gl" | cut -c1-110)"
        printf '%-20s %-14s %-5s %-8s %-18s %s\n' "$_t" "$_n" "-" "gone" "back as before" "$_gl" >>"$CH"
    done <"$W/gone.$_n"
    cp "$W/cur2.$_n" "$_d/open"
    [ "$_nn" -gt 0 ] || { [ "$_ng" -gt 0 ] || [ -s "$W/undone.$_n" ] || cc_show "$C_GRY" "  [-] $_t $_n: no new change"; return; }
    (umask 077; cp "$W/raw.$_n" "$_d/copies/$(date -u +%Y%m%dT%H%M%SZ).cfg")
    # sign US line US section
    awk -F"$US" -v OFS="$US" '{ print substr($1, 1, 1), substr($1, 2), $2 }' "$W/new.$_n" >"$W/nw"
    judge <"$W/nw" >"$W/jd"
    paste -d"$US" "$W/jd" "$W/nw" >"$W/full"
    _nh=$(grep -c "^HIGH$US" "$W/full")
    NEWALL=$((NEWALL + _nn)); HIGHALL=$((HIGHALL + _nh))
    cc_show "" ""
    cc_show "$([ "$_nh" -gt 0 ] && echo "$C_RED" || echo "$C_YEL")" "  ===== $_t $_n ($_v): $_nn new change(s), $_nh HIGH ====="
    [ "$_nh" -gt 0 ] && [ "$QUIET" != 1 ] && [ -t 1 ] && printf '\007'
    : >"$W/ours_like"
    _anysec=0
    while IFS="$US" read -r _sev _cat _mean _sg _ln _x _y _where; do
        _ml=$(printf '%s' "$_ln" | awk "$MASK"'{ print mask($0) }')
        case "$_ml" in *'****'*) _anysec=1 ;; esac
        case "$_sg" in +) _what=added ;; -) _what=removed ;; *) _what=moved ;; esac
        _col=$C_YEL; _mk="[*] MED "; [ "$_sev" = HIGH ] && { _col=$C_RED; _mk="[!] HIGH"; }
        _tag=""; ours_like "$_ln" && { _tag=" (probably ours: NW-20/NW-21)"; echo 1 >>"$W/ours_like"; }
        cc_show "$_col" "  $_mk $_what: $(printf '%s' "$_ml" | sed 's/^[ \t]*//' | cut -c1-120)$_tag"
        cc_show "$C_GRY" "        $_cat: $_mean$([ -n "$_where" ] && echo " | in: $(printf '%s' "$_where" | awk "$MASK"'{ print mask($0) }' | cut -c1-80)")"
        _h=$(hint "$_v" "$_sg" "$_ml" "$(printf '%s' "$_where" | awk "$MASK"'{ print mask($0) }')")
        [ -n "$_h" ] && cc_show "$C_GRY" "        undo (not sent): $_h"
        printf '%-20s %-14s %-5s %-8s %-18s %s%s\n' "$_t" "$_n" "$_sev" "$_what" "$_cat" "$(printf '%s' "$_ml" | sed 's/^[ \t]*//')" "$([ -n "$_where" ] && echo "   [in: $(printf '%s' "$_where" | awk "$MASK"'{ print mask($0) }')]")" >>"$CH"
        printf '%s %s %s: %s\n    %s\n\n' "$_t" "$_n" "$_what" "$(printf '%s' "$_ml" | sed 's/^[ \t]*//')" "${_h:-compare with the saved copy}" >>"$HI"
    done <"$W/full"
    [ "$_anysec" = 1 ] && cc_show "$C_GRY" "        (secrets are shown as ****; the full read is in $_d/copies, mode 600)"
    # Ours?  Only a person can say so.
    if _cc_can_ask; then
        _def=n; [ "$(grep -c . "$W/ours_like")" = "$_nn" ] && _def=o
        cc_choose "$_n: were these $_nn change(s) made by your team?" "$_def" \
            "n=not ours (or not sure): keep them on the open list; shown again only if they go away" \
            "o=ours: they become part of the baseline and are not shown again" \
            "e=each one: ask line by line"
        case "$CC_CHOICE" in
            o) cat "$W/new.$_n" >>"$_d/ok"; setdiff "$_d/open" "$W/new.$_n" >"$W/o.n"; cat "$W/o.n" >"$_d/open"
               cc_show "$C_GRN" "  [ok] $_n: $_nn change(s) taken into the baseline" ;;
            e) : >"$W/acc"
               while IFS="$US" read -r _sev _cat _mean _sg _ln _x _y _where; do
                   _ml=$(printf '%s' "$_ln" | awk "$MASK"'{ print mask($0) }' | sed 's/^[ \t]*//' | cut -c1-100)
                   _d1=n; ours_like "$_ln" && _d1=o
                   cc_choose "$_n $_sev: $_sg $_ml" "$_d1" "n=not ours / not sure" "o=ours"
                   [ "$CC_CHOICE" = o ] && printf '%s%s%s%s\n' "$_sg" "$_ln" "$US" "$_where" >>"$W/acc"
               done <"$W/full"
               cat "$W/acc" >>"$_d/ok"; setdiff "$_d/open" "$W/acc" >"$W/o.n"; cat "$W/o.n" >"$_d/open"
               cc_show "$C_GRN" "  [ok] $_n: $(grep -c . "$W/acc") taken into the baseline, $(( _nn - $(grep -c . "$W/acc") )) left open" ;;
            *) cc_show "$C_YEL" "  [*] $_n: $_nn change(s) left open (not ours). Undo hints: undo-hints.txt" ;;
        esac
    else
        cc_show "$C_YEL" "  [*] $_n: left open (nobody to ask; only a person can say a change was ours)"
    fi
}

STOP=0
trap 'STOP=1' INT TERM HUP
_r=0
while :; do
    _r=$((_r + 1))
    cc_show "$C_GRY" "  -- round $_r, $(date -u +%H:%M:%SZ)"
    while IFS='|' read -r _n _a _v _u _p; do
        [ "$STOP" = 1 ] && break
        one_device "$_n" "$_a" "$_v" "$_u" "$_p" </dev/null
    done <"$W/watch"
    if [ -s "$W/drop" ]; then awk -F'|' -v f="$W/drop" 'FILENAME == f { d[$0] = 1; next } !($1 in d)' "$W/drop" "$W/watch" >"$W/w.n"; cat "$W/w.n" >"$W/watch"; : >"$W/drop"; fi
    [ "$STOP" = 1 ] && break
    [ "$ROUNDS" != 0 ] && [ "$_r" -ge "$ROUNDS" ] && break
    [ -s "$W/watch" ] || { cc_show "$C_RED" "  No device left to watch."; break; }
    nap "$EVERY"
    [ "$STOP" = 1 ] && break
done
trap - INT TERM HUP
[ "$STOP" = 1 ] && cc_show "" "" && cc_show "$C_GRY" "  Stopped (Ctrl-C) after $_r round(s)."

# ---- Summary ----------------------------------------------------------------------------
{
    printf '==========[ summary ]==========\n'
    printf 'NW-30 Device change watch | %s round(s), every %s seconds | read-only\n' "$_r" "$EVERY"
    printf 'New changes this run: %d (%d HIGH)\n\n' "$NEWALL" "$HIGHALL"
    printf 'Still open (not ours), per device:\n'
    while IFS='|' read -r _n _a _v _u _p; do
        _o="$STATE/$_n/open"; _c=$(grep -c . "$_o" 2>/dev/null); [ -n "$_c" ] || _c=0
        printf '  %-16s %s open\n' "$_n" "$_c"
        [ "$_c" -gt 0 ] && awk -F"$US" "$MASK"'{ s = substr($1, 1, 1); t = substr($1, 2); sub(/^[ \t]+/, "", t); printf "      %s %s%s\n", (s == "+" ? "added  " : (s == "-" ? "removed" : "moved  ")), substr(mask(t), 1, 100), ($2 != "" ? "   [in: " substr(mask($2), 1, 50) "]" : "") }' "$_o" | head -n 20
    done <"$W/devices"
    printf '\nEvery change: changes.txt   suggested undo: undo-hints.txt   each round: rounds.txt\n'
    printf 'Baselines and saved reads: %s/DEVICE/ (mode 700)\n' "$STATE"
    printf 'Next: undo what is not yours (undo-hints.txt), then NW-01 to save the clean config.\n'
} >"$CC_RUN_DIR/summary.txt"
while IFS= read -r _l; do case "$_l" in ==*|NW-30*) cc_show "$C_CYN" "$_l" ;; *) cc_show "" "$_l" ;; esac; done <"$CC_RUN_DIR/summary.txt"
# shellcheck disable=SC2034  # read by cc_finish
CC_N_FIND=$NEWALL
rm -rf "$W"
cc_finish
