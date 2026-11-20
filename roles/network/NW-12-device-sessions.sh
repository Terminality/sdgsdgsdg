#!/bin/sh
# =============================================================================
# ID:       NW-12
# NAME:     Device accounts and sessions
# ROLE:     Network  (wave 1, first 15 minutes, again every time red team is busy)
# KIND:     changes - dry run unless --apply
# VERSION:  1.2.0
#
# PURPOSE
#   A red team's first move on a firewall or router is to log in with an
#   extra admin account (or a default one) and stay logged in.  For each
#   device this shows, in one place:
#     accounts   every local admin account, its rights, and whether it is
#                new since the first run (a baseline is kept)
#     sessions   who is logged in right now, from where, how (SSH, web, API)
#   and asks, one at a time:
#     a session from outside your team     [k]ick it / [l]eave it
#     an account new since the first run   [d]isable it / [k]eep it
#   Kicking ends the session; they can log back in until the password is
#   changed - run NW-10 right after.  "Disable" is the brand's most
#   reversible way:
#     MikroTik, Linux       disabled / locked (the undo turns it back on)
#     OpenWRT               password locked (! in /etc/shadow) and the shell
#                           set to /bin/false; the undo puts both back
#     Cisco IOS/ASA, VyOS,  removed; the undo puts back the account's own
#     FortiGate             line(s) from NW-01's saved config (run NW-01 first:
#                           without that copy there is no undo, and you are told)
#     Palo Alto             removed and committed; no automatic undo
#   This script's own login (your login account from your address) is never
#   kicked, and the login account is never disabled.
#
#   Brands: cisco-ios, cisco-asa, paloalto, fortigate, vyos, mikrotik, linux,
#   openwrt (log in as root: accounts from /etc/passwd and /etc/shadow, SSH
#   sessions from dropbear's connections, web (LuCI) sessions from ubus).
#   pfSense / OPNsense: listed, check in the web GUI (System > User Manager,
#   Status > ... ).  FortiGate sessions are shown with the command to end one
#   (its session numbers change as people log in and out).
#
#   QUESTIONS (Enter takes the default in capitals; a flag answers each):
#     which devices (the host list, or typed)   --hosts FILE / --device SPEC
#     the device password                       $BT_NET_PASS / --ask-password
#     your team's addresses                     --team CIDR,...
#     each session not yours    [k]ick / [l]eave (the default: it may be a
#                               teammate) / [a]ll the rest default
#     each account to look at   [d]isable / [k]eep (the default: a teammate
#                               may have made it) / [a]ll the rest default
#   Never kicks the team off a device: nothing is kicked or disabled unless
#   you answer k or d for it; --batch kicks and disables nothing (unless
#   --kick-outside / --disable-new make those the default answers).
#     apply?                    --apply
#
# USAGE
#   BT_NET_PASS='pw' sh NW-12-device-sessions.sh --hosts hosts.txt --team 10.0.0.0/24
#   BT_NET_PASS='pw' sh NW-12-device-sessions.sh --hosts hosts.txt --team 10.0.0.0/24 --apply
#   sh NW-12-device-sessions.sh --device fw1,10.0.0.1,paloalto,admin --ask-password
#
# OPTIONS
#   --hosts FILE / --device NAME,ADDRESS,VENDOR[,USER[,PORT]]   as for NW-01
#   --user NAME        default login account (admin)
#   --ask-password     ask for the password (else $BT_NET_PASS)
#   --enable-env       Cisco: enable with $BT_NET_ENABLE
#   --team CIDR,...    your team's addresses: their sessions default to leave
#   --known NAME,...   accounts that are yours: never asked about
#   --kick-outside     kick is the default for sessions from outside --team
#                      (default: leave - a teammate may be logged in from
#                      somewhere else)
#   --disable-new      disable is the default for accounts new since the
#                      first run (default: keep)
#   --me ADDRESS       this box's address as the devices see it (default:
#                      found with "ip route get")
#   --configs DIR      NW-01's saved configs (default <out>/net-configs)
#   --legacy-ssh       allow old SSH algorithms
#   --no-color         no colours
#   --help             this text plus the common options
#
# OUTPUTS  (under --out, in device-sessions-N/)
#   output.txt, accounts.txt, sessions.txt, plan.txt, summary.txt
#   undo/              the scripts that put a removed account back
#   net-accounts-baseline.txt (in --out): device and account names, nothing else
#
# DEPENDS ON
#   ssh, sshpass (password logins).  BT_SSH / BT_SSHPASS may name stand-ins.
#
# TESTED ON
#   A stand-in device for every brand (its answers written from each brand's
#   documented output) under dash, bash, busybox sh, ksh93, mksh and yash
#   with gawk, mawk and busybox awk; the Linux brand live against OpenSSH.
#   NOT yet on real Cisco, Palo Alto, FortiGate, VyOS or MikroTik devices:
#   run it without --apply first and check that it lists what the web GUI
#   shows.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - Only local accounts.  TACACS/RADIUS logins live on that server.
#   - Kicking does not keep them out: change the passwords (NW-10) next.
#   - A teammate logged in from an address outside --team looks like red
#     team.  Give --team, and read each question.
#   - Palo Alto "kick" ends every session of that account.  Sessions on
#     your own login account are never kicked: change its password instead.
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
NW-12 Device accounts and sessions - who has an account, who is logged in; kick and disable
  BT_NET_PASS=pw sh NW-12-device-sessions.sh --hosts FILE | --device SPEC [--team CIDR] [--apply]
  sh NW-12-device-sessions.sh              asks which devices, the password and your team

  --hosts FILE / --device NAME,ADDRESS,VENDOR[,USER[,PORT]]
  --user NAME        default login account (admin)
  --ask-password     ask for the password (else $BT_NET_PASS)
  --enable-env       Cisco: enable with $BT_NET_ENABLE
  --team CIDR,...    your team's addresses (their sessions default to leave)
  --known NAME,...   accounts that are yours (never asked about)
  --kick-outside     default kick for sessions from outside --team (default leave)
  --disable-new      default disable for accounts new since the first run (default keep)
  --me ADDRESS       this box's address as the devices see it
  --configs DIR      NW-01's saved configs (for the undo of a removed account)
  --legacy-ssh       allow old SSH algorithms
  --no-color         no colours
  --help             show this text
USAGE
    cc_usage_common
}

NL='
'
HOSTS=""; DEVICES=""; DEFUSER="admin"; USERSET=0; ASK=0; KICKOUT=0; DISNEW=0; ENABLE=0; TEAM=""; KNOWN=""; ME=""; CONFIGS=""; LEGACY=0; COLOR=1
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --apply)        CC_APPLY=1; shift ;;
        --hosts)        [ $# -ge 2 ] || cc_die 2 "--hosts needs a file"; [ -r "$2" ] || cc_die 2 "--hosts: cannot read $2"; HOSTS=$2; shift 2 ;;
        --device)       [ $# -ge 2 ] || cc_die 2 "--device needs NAME,ADDRESS,VENDOR"; DEVICES="$DEVICES$2$NL"; shift 2 ;;
        --user)         [ $# -ge 2 ] || cc_die 2 "--user needs a name"; DEFUSER=$2; USERSET=1; shift 2 ;;
        --ask-password) ASK=1; shift ;;
        --kick-outside) KICKOUT=1; shift ;;
        --disable-new)  DISNEW=1; shift ;;
        --enable-env)   ENABLE=1; shift ;;
        --team)         [ $# -ge 2 ] || cc_die 2 "--team needs addresses"; TEAM="$TEAM,$2"; shift 2 ;;
        --known)        [ $# -ge 2 ] || cc_die 2 "--known needs names"; KNOWN="$KNOWN,$2"; shift 2 ;;
        --me)           [ $# -ge 2 ] || cc_die 2 "--me needs an address"; ME=$2; shift 2 ;;
        --configs)      [ $# -ge 2 ] || cc_die 2 "--configs needs a folder"; CONFIGS=$2; shift 2 ;;
        --legacy-ssh)   LEGACY=1; shift ;;
        --no-color|--no-colour) COLOR=0; shift ;;
        --help|-h)      usage; exit 0 ;;
        *)              cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
for _t in $(printf '%s' "$TEAM" | tr ',' ' '); do
    printf '%s' "$_t" | grep -q '^[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\(/[0-9]\{1,2\}\)\{0,1\}$' || cc_die 2 "--team: IPv4 addresses or CIDRs (10.0.0.0/24)"
done
printf '%s' "$KNOWN" | grep -q '[^A-Za-z0-9_.@,-]' && cc_die 2 "--known: account names separated by commas"

cc_init "NW-12" "Device accounts and sessions" changes
# shellcheck disable=SC2034  # read by cc_color_init
[ "$COLOR" = 1 ] || CC_NOCOLOR=1
cc_color_init
# No device named, no host list and nobody to ask: stop before a run folder.
if [ -z "$HOSTS$DEVICES" ] && ! _cc_can_ask && ! cc_net_hostfile >/dev/null; then
    cc_die 2 "give --hosts FILE or --device NAME,ADDRESS,VENDOR (try --help)"
fi
cc_use_numbered_dir device-sessions
rmdir "$CC_RUN_DIR/raw" 2>/dev/null
OUTF="$CC_RUN_DIR/output.txt"
grep -v '\[NOTE\]\|\[DEBUG\]' "$CC_LOG" >"$OUTF" 2>/dev/null || : >"$OUTF"
# shellcheck disable=SC2034  # CC_TEE is read by the library's log functions
CC_TEE=$OUTF
W="$CC_RUN_DIR/.work"; (umask 077; mkdir -p "$W")
US=$(printf '\037')
header() { cc_show "" ""; cc_show "$C_CYN" "==========[ $1 ]=========="; }
# j FIELD... -> one line, fields split by \037 (values may hold spaces; empty ones stay)
j() { _j=$1; shift; for _jx in "$@"; do _j="$_j$US$_jx"; done; printf '%s\n' "$_j"; }
# safe TEXT -> 0 if TEXT can go into a device command as it is.  Names come
# from the device, so red team chose them: a quote or ; in one must never
# reach a command line.
safe() { case "$1" in ''|*[!A-Za-z0-9_.@/:#\ -]*) return 1 ;; esac; return 0; }
trap 'rm -rf "$W"; exit 130' INT TERM HUP
[ -n "$CONFIGS" ] || CONFIGS="$CC_OUT/net-configs"
mkdir -p "$CONFIGS" 2>/dev/null
SSH=${BT_SSH:-$(cc_which ssh)} || cc_die 3 "ssh not found"
SSHPASS_BIN=${BT_SSHPASS:-$(cc_which sshpass)} || cc_die 3 "sshpass not found (apt install sshpass): device logins use the password"
cc_show "$C_CYN" "NW-12 Device accounts and sessions | from $CC_HOST | results in $CC_RUN_DIR"
cc_show "" "Legend: ${C_RED}[!]${C_OFF} fix now   ${C_YEL}[*]${C_OFF} look at it   ${C_GRN}[ok]${C_OFF} fine   ${C_YEL}[~] would change${C_OFF}   ${C_GRN}[+] changed${C_OFF}   ${C_RED}[x] failed${C_OFF}"
header "1/5  devices"
# The questions a flag did not answer: devices, password, team.
if [ -z "$HOSTS$DEVICES" ]; then
    cc_net_ask_devices "$DEFUSER" "$USERSET" || cc_die 2 "no devices given (or use --hosts FILE / --device NAME,ADDRESS,VENDOR)"
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
if [ -z "$TEAM" ] && _cc_can_ask; then
    cc_ask_text "Your team's addresses? (their sessions are left alone; others are offered to kick)" "" "addresses or networks separated by commas, like 192.168.220.30,192.168.220.0/24 (Enter = none: every session is asked about)"
    TEAM=$CC_ANSWER
    for _t in $(printf '%s' "$TEAM" | tr ',' ' '); do
        printf '%s' "$_t" | grep -q '^[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\(/[0-9]\{1,2\}\)\{0,1\}$' || cc_die 2 "team: IPv4 addresses or CIDRs (10.0.0.0/24)"
    done
fi

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

# ---- Talking to a device ---------------------------------------------------------------
sshopts() {
    set -- -T -o ConnectTimeout=10 -o "UserKnownHostsFile=$CONFIGS/known_hosts" -o StrictHostKeyChecking=accept-new \
        -o LogLevel=ERROR -o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive -o NumberOfPasswordPrompts=1
    [ "$LEGACY" = 1 ] && set -- "$@" -o KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group1-sha1 -o HostKeyAlgorithms=+ssh-rsa -o Ciphers=+aes128-cbc,aes256-cbc,3des-cbc
    printf '%s\n' "$@"
}
# mode VENDOR -> stdin (commands typed into the CLI) | exec (one command line)
mode() { case "$1" in vyos|mikrotik|linux|openwrt) echo exec ;; *) echo stdin ;; esac; }
# session VENDOR USER ADDRESS PORT INFILE OUTFILE -> 0 when it logged in
session() {
    _sv=$1; _su=$2; _sa=$3; _sp=$4; _si=$5; _so=$6
    sshopts >"$W/opts"; set --; while IFS= read -r _o; do set -- "$@" "$_o"; done <"$W/opts"
    if [ "$(mode "$_sv")" = exec ]; then
        SSHPASS=$BT_NET_PASS "$SSHPASS_BIN" -e "$SSH" "$@" -p "$_sp" "$_su@$_sa" "$(cat "$_si")" </dev/null >"$_so" 2>"$W/err"
    else
        SSHPASS=$BT_NET_PASS "$SSHPASS_BIN" -e "$SSH" "$@" -p "$_sp" "$_su@$_sa" <"$_si" >"$_so" 2>"$W/err"
    fi
}
en() { case "$1" in cisco-*) [ "$ENABLE" = 1 ] && printf 'enable\n%s\n' "$BT_NET_ENABLE" ;; esac; return 0; }
# read_cmds VENDOR -> what to send to list the accounts and the sessions
read_cmds() {
    case "$1" in
        cisco-ios) en "$1"; printf 'terminal length 0\nshow running-config | include ^username\nshow users\nexit\n' ;;
        cisco-asa) en "$1"; printf 'terminal pager 0\nshow running-config username\nshow ssh sessions\nexit\n' ;;
        paloalto)  printf 'set cli pager off\nshow admins\nset cli config-output-format set\nconfigure\nshow mgt-config users\nexit\nexit\n' ;;
        fortigate) printf 'show system admin\nget system admin list\nexit\n' ;;
        vyos)      printf '/opt/vyatta/bin/vyatta-op-cmd-wrapper show configuration commands; who' ;;
        mikrotik)  printf '/user print terse without-paging; /user active print terse without-paging' ;;
        # passwd -S: L = locked (needs root or sudo; without it the state stays unknown)
        # OpenWRT: accounts and their lock state; each SSH session is a dropbear
        # process with a peer (busybox netstat -p) and an owner (/proc); the
        # web (LuCI) sessions are in ubus.
        openwrt)   cat <<'OWRT'
cat /etc/passwd
echo ===shadow
awk -F: '{ s = "P"; if ($2 ~ /^[!*]/) s = "L"; if ($2 == "") s = "NP"; print $1, s }' /etc/shadow
echo ===ssh
netstat -tnp 2>/dev/null | awk '$6 == "ESTABLISHED" && $4 ~ /:22$/ && $7 ~ /dropbear/ { split($7, a, "/"); p = $5; sub(/:[0-9]+$/, "", p); sub(/^::ffff:/, "", p); u = "?"; f = "/proc/" a[1] "/status"; while ((getline l < f) > 0) if (l ~ /^Uid:/) { split(l, q, /[ \t]+/); u = q[2] } close(f); print a[1], p, u }'
echo ===web
ubus call session list 2>/dev/null | awk -F'"' '/"ubus_rpc_session"/ { s = $4 } /"username"/ && s != "" { print s, $4; s = "" }'
OWRT
                   ;;
        linux)     printf 'getent passwd; echo ===groups; getent group sudo wheel admin; echo ===who; who; echo ===status; for u in $(getent passwd | awk -F: '"'"'$3 == 0 || $3 >= 1000 { print $1 }'"'"'); do passwd -S "$u" 2>/dev/null || sudo -n passwd -S "$u" 2>/dev/null; done' ;;
    esac
}
# parse VENDOR RAW -> $W/acc ("name US rights US state") and $W/ses ("id US user US from US via")
parse() {
    tr -d '\r' <"$2" | awk -v v="$1" -v US="$US" -v ao="$W/acc" -v so="$W/ses" '
        function acc(n, r, s) { gsub(/"/, "", n); if (n != "" && !(n in seen)) { seen[n] = 1; print n US r US s > ao } }  # awk, not shell: posix-ok
        function ses(i, u, f, w) { print i US u US f US w > so }  # awk, not shell: posix-ok
        { sub(/^[^ ]*[>#] */, "", $0) }
        v == "cisco-ios" && $1 == "username" { r = "privilege 1"; for (i = 3; i < NF; i++) if ($i == "privilege") r = "privilege " $(i + 1); acc($2, r, "active") }
        v == "cisco-ios" && /^[* ]*[0-9]+ +(vty|tty|con|aux) +[0-9]+ / {
            me = ($0 ~ /^ *\*/); l = $0; sub(/^[* ]+/, "", l); n = split(l, f, /[ \t]+/)
            from = f[n]; if (from ~ /^[0-9][0-9]:[0-9][0-9]:[0-9][0-9]$/ || from == "idle") from = "-"
            u = f[4]; if (u == "idle" || u ~ /^[0-9:]+$/) u = "-"
            ses((me ? "*" : "") f[2] " " f[3], u, from, f[2]) }
        v == "cisco-asa" && $1 == "username" && $2 != "" && $3 != "attributes" { r = "privilege 2"; for (i = 3; i < NF; i++) if ($i == "privilege") r = "privilege " $(i + 1); acc($2, r, "active") }
        v == "cisco-asa" && $1 ~ /^[0-9]+$/ && $2 ~ /^[0-9a-fA-F.:]+$/ && $4 == "IN" { ses($1, $NF, $2, "ssh") }
        v == "paloalto" && $1 == "set" && $2 == "mgt-config" && $3 == "users" { n = $4; if (!(n in role)) role[n] = "role-based"; if ($0 ~ /superuser yes/) role[n] = "superuser"; if ($0 ~ /superreader yes/ && role[n] != "superuser") role[n] = "superreader"; if (!(n in seen2)) { seen2[n] = 1; order[++no] = n } }
        v == "paloalto" && $2 ~ /^[0-9a-fA-F.:]+$/ && $3 ~ /^(CLI|Web|API|XML)/ && $1 !~ /^-+$/ { ses($1, $1, $2, $3) }
        v == "fortigate" && /^config system admin/ { inadm = 1 }
        v == "fortigate" && inadm && $1 == "edit" { cur = $2; gsub(/"/, "", cur); prof[cur] = "accprofile ?"; order[++no] = cur }
        v == "fortigate" && inadm && $1 == "set" && $2 == "accprofile" { p = $3; gsub(/"/, "", p); prof[cur] = "accprofile " p }
        v == "fortigate" && inadm && /^end/ { inadm = 0 }
        v == "fortigate" && $1 == "username" && $0 ~ /remote/ { inlist = 1; k = 0; next }
        v == "fortigate" && inlist && NF >= 4 && $4 ~ /:[0-9]+$/ { fr = $4; sub(/:[0-9]+$/, "", fr); ses("#" k, $1, fr, $2); k++ }
        v == "vyos" && $1 == "set" && $2 == "system" && $3 == "login" && $4 == "user" { n = $5; gsub(/\047/, "", n); acc(n, "admin", "active") }
        v ~ /^(vyos|linux)$/ && $2 ~ /^pts\// { fr = $NF; if (fr !~ /^\(/) fr = "-"; gsub(/[()]/, "", fr); ses($2, $1, fr, "ssh") }
        v == "mikrotik" && / name=/ {
            n = ""; g = ""; a = ""; w = ""; st = "active"
            if ($2 == "X" || $2 ~ /^X/) st = "disabled"
            for (i = 1; i <= NF; i++) { if ($i ~ /^name=/) { n = substr($i, 6) } else if ($i ~ /^group=/) { g = substr($i, 7) } else if ($i ~ /^address=/) { a = substr($i, 9) } else if ($i ~ /^via=/) { w = substr($i, 5) } }
            gsub(/"/, "", n)
            if ($0 ~ / via=/) ses(n "@" a, n, a, w); else acc(n, "group " g, st) }
        v == "openwrt" && /^===/ { op = substr($0, 4); next }
        v == "openwrt" && op == "" && split($0, pw, ":") >= 7 && pw[3] ~ /^[0-9]+$/ {
            # Two UID 0 accounts share one uid: a session of uid 0 is shown as
            # the first one (root), which is how the device itself sees it.
            if (!(pw[3] in uname)) uname[pw[3]] = pw[1]
            if (pw[3] == 0) owr[pw[1]] = "uid 0 (root)"
            else if (pw[7] !~ /(nologin|false)$/) owr[pw[1]] = "can log in (" pw[7] ")"
            if (pw[1] in owr) oo[++no2] = pw[1] }
        v == "openwrt" && op == "shadow" { if ($2 == "L") lk[$1] = 1; if ($2 == "NP") np[$1] = 1 }
        v == "openwrt" && op == "ssh" && NF >= 3 { u = ($3 in uname) ? uname[$3] : "uid " $3; ses($1, u, $2, "ssh") }
        v == "openwrt" && op == "web" && NF >= 2 { ses($1, $2, "?", "web (LuCI)") }
        v == "linux" && /^===groups/ { ing = 1; next }
        v == "linux" && /^===who/ { ing = 0; next }
        v == "linux" && /^===status/ { inst = 1; next }
        v == "linux" && inst { if ($2 == "L" || $2 == "LK") lk[$1] = 1; next }
        v == "linux" && ing { split($0, gg, ":"); m = gg[4]; k = split(m, mm, ","); for (i = 1; i <= k; i++) adm[mm[i]] = gg[1] }
        v == "linux" && !ing && split($0, pw, ":") >= 7 && pw[3] ~ /^[0-9]+$/ {
            if (pw[3] == 0) lin[pw[1]] = "uid 0 (root)"
            else if (pw[3] >= 1000 && pw[7] !~ /(nologin|false)$/) lin[pw[1]] = "user"
            if (pw[1] in lin) lo[++nl] = pw[1] }
        END {
            for (i = 1; i <= no; i++) { n = order[i]; acc(n, (v == "paloalto") ? role[n] : prof[n], "active") }
            for (i = 1; i <= nl; i++) { n = lo[i]; acc(n, (n in adm) ? "admin (" adm[n] ")" : lin[n], (n in lk) ? "disabled" : "active") }
            for (i = 1; i <= no2; i++) { n = oo[i]; acc(n, owr[n] ((n in np) ? ", NO PASSWORD" : ""), (n in lk) ? "disabled" : "active") }
        }'
}
# in_team ADDRESS -> 0 if it is in one of the --team ranges
in_team() {
    [ -n "$TEAM" ] || return 1
    printf '%s\n' "$TEAM" | tr ',' '\n' | grep . | awk -v ip="$1" '
        function n(a,   p) { split(a, p, "."); return ((p[1] * 256 + p[2]) * 256 + p[3]) * 256 + p[4] }  # awk, not shell: posix-ok
        ip !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ { exit 1 }
        { b = $0; m = 32; if (index(b, "/")) { m = substr(b, index(b, "/") + 1) + 0; b = substr(b, 1, index(b, "/") - 1) }
          s = 1; for (i = m; i < 32; i++) s *= 2  # no ^: busybox awk may lack math
          if (int(n(ip) / s) == int(n(b) / s)) { hit = 1; exit } }
        END { exit hit ? 0 : 1 }'
}
known() { case ",$KNOWN," in *",$1,"*) return 0 ;; esac; return 1; }
# my_addr ADDRESS -> this box's source address towards ADDRESS
my_addr() { [ -n "$ME" ] && { printf '%s' "$ME"; return; }; ip route get "$1" 2>/dev/null | sed -n 's/.* src \([^ ]*\).*/\1/p' | head -n 1; }
# latest_cfg DEVICE -> NW-01's newest copy of the device's config
latest_cfg() { _l=$(cat "$CONFIGS/$1/latest" 2>/dev/null) && [ -f "$CONFIGS/$1/$_l.cfg" ] && printf '%s' "$CONFIGS/$1/$_l.cfg"; }
# saved_lines VENDOR CFG NAME -> the account's own lines in NW-01's copy
# (read only when the undo runs: the lines hold a password hash and are never copied)
SAVED_AWK='
    { sub(/\r$/, "") }
    v ~ /^cisco/ && $1 == "username" && $2 == n { print; next }
    v == "vyos" && $1 == "set" && $2 == "system" && $3 == "login" && $4 == "user" { u = $5; gsub(/\047/, "", u); if (u == n) print; next }
    v == "fortigate" && /^config system admin/ { a = 1; next }
    v == "fortigate" && a && /^end/ { a = 0 }
    v == "fortigate" && a && $1 == "edit" { e = $2; gsub(/"/, "", e); p = (e == n) }
    v == "fortigate" && a && p { print; if ($1 == "next") p = 0 }'
has_saved() { _cf=$(latest_cfg "$2") || return 1; awk -v v="$1" -v n="$3" "$SAVED_AWK" "$_cf" | grep -q .; }

# ---- 1. Read every device --------------------------------------------------------------
: >"$W/allacc"; : >"$W/allses"; NDEV=0; NFAIL=0
printf '%-14s %-10s %-20s %-24s %s\n' device brand account rights state >"$CC_RUN_DIR/accounts.txt"
printf '%-14s %-10s %-12s %-16s %-18s %s\n' device brand session user from verdict >"$CC_RUN_DIR/sessions.txt"
while IFS='|' read -r _n _a _v _u _p; do
    case "$_v" in pfsense|opnsense)
        cc_show "$C_YEL" "  [*] $_n ($_v): no safe command line for this - check System > User Manager and the logged-in users in the web GUI"; continue ;;
    esac
    if ! cc_guard host "$_a" || ! cc_guard host "$_n"; then cc_show "$C_GRY" "  $_n: protected device, skipped"; continue; fi
    read_cmds "$_v" >"$W/in"
    if ! session "$_v" "$_u" "$_a" "$_p" "$W/in" "$W/raw.$_n"; then
        NFAIL=$((NFAIL + 1)); cc_show "$C_RED" "  [x] $_n ($_a, $_v): could not log in as $_u ($(grep -v '^$' "$W/err" | tail -n 1 | cut -c1-70))"; continue
    fi
    : >"$W/acc"; : >"$W/ses"; parse "$_v" "$W/raw.$_n"
    NDEV=$((NDEV + 1))
    _me=$(my_addr "$_a")
    [ -n "$_me" ] || cc_show "$C_YEL" "  [*] $_n: cannot tell this box's address towards it (no ip route?): pass --me ADDRESS so this script's own login is recognised"
    cc_show "$C_GRN" "  [ok] $_n ($_a, $_v): $(grep -c . "$W/acc") account(s), $(grep -c . "$W/ses") session(s)$([ -n "$_me" ] && echo "; this box is $_me")"
    while IFS="$US" read -r _an _ar _as; do j "$_n" "$_a" "$_v" "$_u" "$_p" "$_an" "$_ar" "$_as" >>"$W/allacc"; done <"$W/acc"
    while IFS="$US" read -r _si _su _sf _sw; do j "$_n" "$_a" "$_v" "$_u" "$_p" "$_si" "$_su" "$_sf" "$_sw" "$_me" >>"$W/allses"; done <"$W/ses"
done <"$W/devices"
[ "$NDEV" -eq 0 ] && cc_show "$C_RED" "  [x] no device answered"

# ---- 2. Accounts ---------------------------------------------------------------------------
header "2/5  accounts"
BASE="$CC_OUT/net-accounts-baseline.txt"
FIRST=0; [ -f "$BASE" ] || FIRST=1
: >"$W/ask"   # kind US default US device ... US target US text
while IFS="$US" read -r _n _a _v _u _p _an _ar _as; do
    _new=n; [ "$FIRST" = 0 ] && ! grep -qxF "$_n $_an" "$BASE" && _new=y
    _verd=""
    if [ "$_an" = "$_u" ]; then _verd="your login"; cc_show "$C_GRN" "  [ok] $_n: $_an ($_ar) - the account this script logs in with"
    elif known "$_an"; then _verd="known"; cc_show "$C_GRN" "  [ok] $_n: $_an ($_ar) - yours (--known)"
    elif [ "$_as" = disabled ]; then _verd="disabled"; cc_show "$C_GRY" "  $_n: $_an ($_ar) - disabled"
    elif ! safe "$_an"; then _verd="odd name"; cc_show "$C_RED" "  [!] $_n: an account with an odd name ($(printf '%s' "$_an" | tr -cd 'A-Za-z0-9_.@ -')...): check it in the device's own interface - it is not put into a command"
    elif ! cc_is_protected account "$_an" && [ "$_new" = y ]; then
        _verd="NEW"; cc_show "$C_RED" "  [!] $_n: $_an ($_ar) - NEW since the first run: who made it?"
        # Never the default (unless --disable-new): a teammate may have made it.
        j acc "$([ "$DISNEW" = 1 ] && echo d || echo k)" "$_n" "$_a" "$_v" "$_u" "$_p" "$_an" "$_ar" "NEW since the first run" >>"$W/ask"
    elif cc_is_protected account "$_an"; then _verd="protected"; cc_show "$C_GRN" "  [ok] $_n: $_an ($_ar) - on the protected list"
    else
        _verd="look at it"; cc_show "$C_YEL" "  [*] $_n: $_an ($_ar) - $([ "$FIRST" = 1 ] && echo 'first run: is it yours? (--known NAME stops this question)' || echo 'there at the first run')"
        j acc k "$_n" "$_a" "$_v" "$_u" "$_p" "$_an" "$_ar" "$([ "$FIRST" = 1 ] && echo 'first run' || echo 'there at the first run')" >>"$W/ask"
    fi
    printf '%-14s %-10s %-20s %-24s %s\n' "$_n" "$_v" "$_an" "$_ar" "$_as, $_verd" >>"$CC_RUN_DIR/accounts.txt"
done <"$W/allacc"
[ -s "$W/allacc" ] || cc_show "$C_GRY" "  No accounts read."
if [ "$FIRST" = 1 ] && [ -s "$W/allacc" ]; then
    awk -F"$US" '{ print $1 " " $6 }' "$W/allacc" | sort -u >"$BASE"
    cc_show "$C_GRN" "  [ok] first run: these accounts are the baseline ($BASE); an account added later is flagged [!]"
fi

# ---- 3. Sessions ---------------------------------------------------------------------------
header "3/5  who is logged in"
while IFS="$US" read -r _n _a _v _u _p _si _su _sf _sw _me; do
    _id=${_si#\*}; _verd=""
    if [ "$_si" != "$_id" ] || { [ "$_su" = "$_u" ] && [ -n "$_me" ] && [ "$_sf" = "$_me" ]; }; then
        _verd="this script"; cc_show "$C_GRN" "  [ok] $_n: $_su from $_sf ($_sw) - this script's own login"
    elif [ "$_sf" = "-" ]; then
        _verd="console"; cc_show "$C_YEL" "  [*] $_n: $_su on the console ($_id) - someone at the device itself"
    elif [ "$_sf" = "?" ]; then
        # OpenWRT web (LuCI) sessions do not say where they come from.
        _verd="web"; cc_show "$C_YEL" "  [*] $_n: $_su logged in to the web page ($_sw) - from where is not known: yours?"
        safe "$_id" && j ses l "$_n" "$_a" "$_v" "$_u" "$_p" "$_id" "$_su" "$_sf" "$_sw" >>"$W/ask"
    elif in_team "$_sf"; then
        _verd="team"; cc_show "$C_GRN" "  [ok] $_n: $_su from $_sf ($_sw) - your team (--team)"
    elif ! safe "$_id" || ! safe "$_su" || ! safe "$_sf"; then
        _verd="odd"; cc_show "$C_RED" "  [!] $_n: a session with odd characters in its name or address: end it in the device's own interface"
    else
        _verd="NOT your team"
        if [ -n "$TEAM" ]; then cc_show "$C_RED" "  [!] $_n: $_su from $_sf ($_sw) - not from your team"
        else cc_show "$C_YEL" "  [*] $_n: $_su from $_sf ($_sw) - yours? (--team CIDR tells your addresses apart)"; _verd="unknown"; fi
        # Never the default (unless --kick-outside with --team): a teammate
        # logged in from somewhere else would be kicked.
        j ses "$([ "$KICKOUT" = 1 ] && [ -n "$TEAM" ] && echo k || echo l)" "$_n" "$_a" "$_v" "$_u" "$_p" "$_id" "$_su" "$_sf" "$_sw" >>"$W/ask"
    fi
    printf '%-14s %-10s %-12s %-16s %-18s %s\n' "$_n" "$_v" "$_id" "$_su" "$_sf" "$_verd" >>"$CC_RUN_DIR/sessions.txt"
done <"$W/allses"
[ -s "$W/allses" ] || cc_show "$C_GRY" "  No sessions read."

# ---- 4. Questions ---------------------------------------------------------------------------
header "4/5  what to do (Enter = the default in capitals)"
how_off() {   # how_off VENDOR DEVICE NAME -> how the account is turned off, for the answer text
    case "$1" in
        mikrotik|linux) echo "disabled; the undo turns it back on" ;;
        openwrt) echo "password locked and shell set to /bin/false; the undo puts both back" ;;
        paloalto) echo "removed and committed; NO automatic undo" ;;
        *) if has_saved "$1" "$2" "$3"; then echo "removed; the undo puts back its lines from NW-01's copy"; else echo "removed; NO undo - NW-01 has no copy of it (run NW-01 first)"; fi ;;
    esac
}
: >"$W/plan"; _all=0
while IFS="$US" read -r _k _d _n _a _v _u _p _x1 _x2 _x3 _x4; do
    if [ "$_k" = acc ]; then
        _what="$_n: account $_x1 ($_x2) - $_x3"
        if [ "$_all" = 0 ]; then
            cc_choose "$_what: what now?" "$_d" "d=disable it - only if you are SURE no teammate uses it ($(how_off "$_v" "$_n" "$_x1"))" "k=keep it" "a=all the rest: take their defaults"
            case "$CC_CHOICE" in a) _all=1 ;; *) _d=$CC_CHOICE ;; esac
        fi
        [ "$_d" = d ] && j off "$_n" "$_a" "$_v" "$_u" "$_p" "$_x1" >>"$W/plan"
    else
        _what="$_n: $_x2 logged in from $_x3 ($_x4, $_x1)"
        if [ "$_v" = fortigate ]; then
            cc_show "$C_YEL" "  [*] $_what: to end it, log in and run: get system admin list, then execute disconnect-admin-session <its number>"; continue
        fi
        if [ "$_x2" = "$_u" ] && [ "$_v" = paloalto ]; then
            cc_show "$C_YEL" "  [*] $_what: same account as this script (Palo Alto ends every session of an account): change its password with NW-10 instead"; continue
        fi
        if [ "$_all" = 0 ]; then
            cc_choose "$_what: what now?" "$_d" "k=kick it (ends the session - only if you are SURE it is not a teammate; change the passwords with NW-10 next)" "l=leave it" "a=all the rest: take their defaults"
            case "$CC_CHOICE" in a) _all=1 ;; *) _d=$CC_CHOICE ;; esac
        fi
        [ "$_d" = k ] && j kick "$_n" "$_a" "$_v" "$_u" "$_p" "$_x1" "$_x2" "$_x3" >>"$W/plan"
    fi
done <"$W/ask"
NCH=$(grep -c . "$W/plan")
: >"$CC_RUN_DIR/plan.txt"
while IFS="$US" read -r _k _n _a _v _u _p _t _x _f; do
    if [ "$_k" = off ]; then _l="$_n: disable account $_t"; else _l="$_n: kick $_x from $_f ($_t)"; fi
    printf '%s\n' "$_l" >>"$CC_RUN_DIR/plan.txt"; cc_show "$C_YEL" "  [~] $_l"
done <"$W/plan"
[ "$NCH" -eq 0 ] && cc_show "$C_GRN" "  [ok] Nothing to kick or disable."

# ---- 5. Apply ---------------------------------------------------------------------------
header "5/5  apply"
# off_cmds VENDOR NAME -> lines that turn the account off (and save)
off_cmds() {
    case "$1" in
        cisco-ios|cisco-asa) printf 'configure terminal\nno username %s\nend\nwrite memory\n' "$2" ;;
        paloalto)  printf 'configure\ndelete mgt-config users %s\ncommit\nexit\n' "$2" ;;
        fortigate) printf 'config system admin\ndelete %s\nend\n' "$2" ;;
        vyos)      printf "source /opt/vyatta/etc/functions/script-template; configure; delete system login user '%s'; commit; save; exit" "$2" ;;
        mikrotik)  printf '/user disable [find name="%s"]' "$2" ;;
        linux)     printf "if [ \"\$(id -u)\" = 0 ]; then S=''; else S='sudo -n'; fi; \$S usermod -L -e 1 '%s'" "$2" ;;
        # OpenWRT has no usermod: ! before the hash, and no shell.
        openwrt)   _on=$2; printf '%s' "sed -i -e 's/^$_on:\\([^!]\\)/$_on:!\\1/' -e 's/^$_on::/$_on:!:/' /etc/shadow && sed -i 's#^\\($_on:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:\\).*\$#\\1/bin/false#' /etc/passwd" ;;  # posix-ok: sent to the OpenWRT router, whose busybox sed has -i
    esac
}
# kick_cmds VENDOR ID USER FROM -> lines that end the session (kicks come last)
kick_cmds() {
    case "$1" in
        cisco-ios) printf 'clear line %s\n\n' "$2" ;;
        cisco-asa) printf 'ssh disconnect %s\n' "$2" ;;
        paloalto)  printf 'delete admin-sessions username %s\n' "$3" ;;
        vyos)      printf "; sudo pkill -KILL -t '%s'" "$2" ;;
        mikrotik)  printf '; /user active request-logout [find name="%s" address="%s"]' "$3" "$4" ;;
        linux)     printf "; if [ \"\$(id -u)\" = 0 ]; then S=''; else S='sudo -n'; fi; \$S pkill -KILL -t '%s'" "$2" ;;
        # OpenWRT: an SSH session is a dropbear process; a web one a ubus session.
        openwrt)   case "$2" in *[!0-9]*) printf "; ubus call session destroy '{\"ubus_rpc_session\":\"%s\"}'" "$2" ;; *) printf '; kill %s' "$2" ;; esac ;;
    esac
}
# write_undo VENDOR DEVICE ADDRESS USER PORT NAME -> an undo script; prints its path
write_undo() {
    mkdir -p "$CC_RUN_DIR/undo"; _uf="$CC_RUN_DIR/undo/$2-$6.sh"
    {
        printf '#!/bin/sh\n# Puts back the account %s on %s (NW-12).  Needs the device password in BT_NET_PASS.\n' "$6" "$2"
        printf '[ -n "$BT_NET_PASS" ] || { echo "set BT_NET_PASS to the device password first" >&2; exit 1; }\n'
        printf 'SSHPASS=$BT_NET_PASS; export SSHPASS\n'
        case "$1" in
            mikrotik) printf '%s -e %s %s -p %s %s %s\n' "$(cc_shquote "$SSHPASS_BIN")" "$(cc_shquote "$SSH")" "$(sshopts | while IFS= read -r _o; do printf '%s ' "$(cc_shquote "$_o")"; done)" "$5" "$(cc_shquote "$4@$3")" "$(cc_shquote "/user enable [find name=\"$6\"]")" ;;
            linux) printf '%s -e %s %s -p %s %s %s\n' "$(cc_shquote "$SSHPASS_BIN")" "$(cc_shquote "$SSH")" "$(sshopts | while IFS= read -r _o; do printf '%s ' "$(cc_shquote "$_o")"; done)" "$5" "$(cc_shquote "$4@$3")" "$(cc_shquote "if [ \"\$(id -u)\" = 0 ]; then S=''; else S='sudo -n'; fi; \$S usermod -U -e '' '$6'")" ;;
            # OpenWRT: the ! comes off the hash and the old shell goes back.
            openwrt) _osh=$(awk -F: -v n="$6" '$1 == n { print $7; exit }' "$W/raw.$2" 2>/dev/null); case "$_osh" in ''|*[!A-Za-z0-9/_.-]*) _osh=/bin/ash ;; esac
                printf '%s -e %s %s -p %s %s %s\n' "$(cc_shquote "$SSHPASS_BIN")" "$(cc_shquote "$SSH")" "$(sshopts | while IFS= read -r _o; do printf '%s ' "$(cc_shquote "$_o")"; done)" "$5" "$(cc_shquote "$4@$3")" "$(cc_shquote "sed -i 's/^$6:!/$6:/' /etc/shadow && sed -i 's#^\($6:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:\)/bin/false\$#\1$_osh#' /etc/passwd")" ;;  # posix-ok: runs on the router
            *)
                # The account's lines are read from NW-01's copy now, not copied here (they hold a hash).
                printf 'CFG=%s\n' "$(cc_shquote "$(latest_cfg "$2")")"
                printf 'LINES=$(awk -v v=%s -v n=%s %s "$CFG")\n' "$(cc_shquote "$1")" "$(cc_shquote "$6")" "$(cc_shquote "$SAVED_AWK")"
                printf '[ -n "$LINES" ] || { echo "the account is no longer in $CFG" >&2; exit 1; }\n'
                case "$1" in
                    cisco-*)   printf 'CMDS=$(printf "%%sconfigure terminal\\n%%s\\nend\\nwrite memory\\nexit\\n" "$(%s)" "$LINES")\n' "$([ "$ENABLE" = 1 ] && printf '[ -n "$BT_NET_ENABLE" ] \&\& printf "enable\\\\n%%s\\\\n" "$BT_NET_ENABLE"' || printf ':')" ;;
                    fortigate) printf 'CMDS=$(printf "config system admin\\n%%s\\nend\\nexit\\n" "$LINES")\n' ;;
                    vyos)      printf 'CMDS=$(printf "source /opt/vyatta/etc/functions/script-template; configure; %%s; commit; save; exit" "$(printf "%%s" "$LINES" | tr "\\n" ";")")\n' ;;
                esac
                if [ "$(mode "$1")" = exec ]; then
                    printf '%s -e %s %s -p %s %s "$CMDS"\n' "$(cc_shquote "$SSHPASS_BIN")" "$(cc_shquote "$SSH")" "$(sshopts | while IFS= read -r _o; do printf '%s ' "$(cc_shquote "$_o")"; done)" "$5" "$(cc_shquote "$4@$3")"
                else
                    printf 'printf "%%s\\n" "$CMDS" | %s -e %s %s -p %s %s\n' "$(cc_shquote "$SSHPASS_BIN")" "$(cc_shquote "$SSH")" "$(sshopts | while IFS= read -r _o; do printf '%s ' "$(cc_shquote "$_o")"; done)" "$5" "$(cc_shquote "$4@$3")"
                fi ;;
        esac
    } >"$_uf"
    chmod 700 "$_uf"; printf '%s' "$_uf"
}
NOK=0; NBAD=0; APPLIED=0
if [ "$NCH" -eq 0 ]; then :
elif [ "$CC_APPLY" != 1 ]; then
    cc_show "$C_GRY" "  Dry run: nothing was changed. Run again with --apply."
    # shellcheck disable=SC2034  # read by cc_finish
    CC_N_WOULD=$NCH
elif cc_ask "Do these $NCH change(s) now?" Y "yes, kick and disable them" "no, change nothing"; then
    APPLIED=1
    # One session per device: accounts first, kicks last (a kick can end our own line).
    cut -d"$US" -f2 "$W/plan" | awk '!s[$0]++' >"$W/plandevs"
    while IFS= read -r _dev; do
        awk -F"$US" -v d="$_dev" '$2 == d' "$W/plan" >"$W/pd"
        IFS="$US" read -r _k _n _a _v _u _p _rest <"$W/pd"
        : >"$W/in"; [ "$(mode "$_v")" = stdin ] && en "$_v" >>"$W/in"
        # disables
        while IFS="$US" read -r _k _n2 _a2 _v2 _u2 _p2 _t _x _f; do
            [ "$_k" = off ] || continue
            if ! cc_guard account "$_t"; then cc_show "$C_YEL" "  [-] $_n: $_t is protected: left"; continue; fi
            case "$_v" in
                mikrotik|linux|openwrt) [ -s "$W/in" ] && printf '; ' >>"$W/in"; off_cmds "$_v" "$_t" >>"$W/in"; _uf=$(write_undo "$_v" "$_n" "$_a" "$_u" "$_p" "$_t"); cc_undo_add "turn the account $_t on $_n back on" "sh $(cc_shquote "$_uf")" ;;
                paloalto) off_cmds "$_v" "$_t" >>"$W/in" ;;
                vyos) [ -s "$W/in" ] && printf '; ' >>"$W/in"; off_cmds "$_v" "$_t" >>"$W/in"
                      has_saved "$_v" "$_n" "$_t" && { _uf=$(write_undo "$_v" "$_n" "$_a" "$_u" "$_p" "$_t"); cc_undo_add "put the account $_t back on $_n" "sh $(cc_shquote "$_uf")"; } ;;
                *) off_cmds "$_v" "$_t" >>"$W/in"
                   has_saved "$_v" "$_n" "$_t" && { _uf=$(write_undo "$_v" "$_n" "$_a" "$_u" "$_p" "$_t"); cc_undo_add "put the account $_t back on $_n" "sh $(cc_shquote "$_uf")"; } ;;
            esac
            j off "$_t" >>"$W/done.$_n"
        done <"$W/pd"
        # kicks
        while IFS="$US" read -r _k _n2 _a2 _v2 _u2 _p2 _t _x _f; do
            [ "$_k" = kick ] || continue
            case "$(mode "$_v")" in
                exec) [ -s "$W/in" ] || printf ':' >>"$W/in"; kick_cmds "$_v" "$_t" "$_x" "$_f" >>"$W/in" ;;
                *) kick_cmds "$_v" "$_t" "$_x" "$_f" >>"$W/in" ;;
            esac
            j kick "$_t" "$_x" "$_f" >>"$W/done.$_n"
        done <"$W/pd"
        [ "$(mode "$_v")" = stdin ] && printf 'exit\n' >>"$W/in"
        [ -s "$W/done.$_n" ] || continue
        if session "$_v" "$_u" "$_a" "$_p" "$W/in" "$W/apply.$_n"; then _ok=1; else _ok=0; fi
        # A kick may close our own session on some brands: judge by reading again.
        read_cmds "$_v" >"$W/in2"
        if session "$_v" "$_u" "$_a" "$_p" "$W/in2" "$W/after.$_n"; then
            : >"$W/acc"; : >"$W/ses"; parse "$_v" "$W/after.$_n"
            while IFS="$US" read -r _w _t _x _f; do
                if [ "$_w" = off ]; then
                    if awk -F"$US" -v n="$_t" '$1 == n && $3 != "disabled" { f = 1 } END { exit !f }' "$W/acc"; then NBAD=$((NBAD + 1)); cc_show "$C_RED" "  [x] $_n: account $_t is still there"
                    else NOK=$((NOK + 1)); cc_show "$C_GRN" "  [+] $_n: account $_t disabled"; fi
                else
                    if awk -F"$US" -v i="$_t" -v u="$_x" -v f="$_f" '($1 == i || $1 == "*" i) && $2 == u && $3 == f { g = 1 } END { exit !g }' "$W/ses"; then NBAD=$((NBAD + 1)); cc_show "$C_RED" "  [x] $_n: $_x from $_f is still logged in"
                    else NOK=$((NOK + 1)); cc_show "$C_GRN" "  [+] $_n: kicked $_x from $_f"; fi
                fi
            done <"$W/done.$_n"
        else
            _c=$(grep -c . "$W/done.$_n"); NBAD=$((NBAD + _c)); cc_show "$C_RED" "  [x] $_n: could not log in again to check $([ "$_ok" = 1 ] && echo '(the changes were sent)' || echo '(the change session failed too)'): look by hand"
        fi
    done <"$W/plandevs"
else cc_show "$C_GRY" "  Nothing done."; fi
# Accounts kept on purpose (with --apply) join the baseline; disabled ones stay out.
if [ "$CC_APPLY" = 1 ] && [ "$FIRST" = 0 ] && { [ "$APPLIED" = 1 ] || [ "$NCH" -eq 0 ]; }; then
    awk -F"$US" '{ print $1 " " $6 }' "$W/allacc" >"$W/now"
    while IFS= read -r _l; do
        grep -qxF "$_l" "$BASE" && continue
        awk -F"$US" -v l="$_l" '$1 == "off" && ($2 " " $7) == l { f = 1 } END { exit !f }' "$W/plan" || printf '%s\n' "$_l" >>"$BASE"
    done <"$W/now"
fi
# shellcheck disable=SC2034  # read by cc_finish
CC_N_DONE=$NOK
# shellcheck disable=SC2034  # read by cc_finish
CC_N_FAIL=$((NBAD + NFAIL))

{
    printf '==========[ summary ]==========\n'
    printf 'NW-12 Device accounts and sessions | %s\n' "$([ "$APPLIED" = 1 ] && echo APPLIED || echo 'DRY RUN - nothing changed')"
    printf 'Devices read: %d   could not log in: %d\n' "$NDEV" "$NFAIL"
    printf 'Accounts: %d (%d new since the first run)   Sessions: %d\n' "$(grep -c . "$W/allacc")" "$(grep -c 'NEW since' "$W/ask")" "$(grep -c . "$W/allses")"
    [ -s "$CC_RUN_DIR/plan.txt" ] && { printf 'Changes%s:\n' "$([ "$APPLIED" = 1 ] || echo ' planned')"; sed 's/^/  /' "$CC_RUN_DIR/plan.txt"; }
    [ "$APPLIED" = 1 ] && printf 'Done: %d   Failed: %d\n' "$NOK" "$NBAD"
    printf '\nNext: change the device passwords (NW-10) - a kicked session can log in again until then.\n'
    printf 'Tables: accounts.txt, sessions.txt\n'
    [ -d "$CC_RUN_DIR/undo" ] && printf 'Undo a disabled account: BT_NET_PASS=... sh %s/undo/DEVICE-ACCOUNT.sh\n' "$CC_RUN_DIR"
} >"$CC_RUN_DIR/summary.txt"
cc_show "" ""
while IFS= read -r _l; do case "$_l" in ==*|NW-12*) cc_show "$C_CYN" "$_l" ;; *'Failed: '[1-9]*|*'log in: '[1-9]*) cc_show "$C_RED" "$_l" ;; *) cc_show "" "$_l" ;; esac; done <"$CC_RUN_DIR/summary.txt"
rm -rf "$W"
cc_finish
