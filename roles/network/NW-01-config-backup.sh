#!/bin/sh
# =============================================================================
# ID:       NW-01
# NAME:     Network device config backup and diff
# ROLE:     Network  (wave 1, first 15 minutes)
# KIND:     readonly - only runs "show" commands on the devices
# VERSION:  1.0.0
#
# PURPOSE
#   Logs in to each firewall, router and switch over SSH, saves its running
#   configuration with a timestamp, and shows what changed since the last
#   saved copy.  Run it first (the backup you restore from) and again every
#   few minutes (the change watch for network gear: a new admin account, an
#   SNMP community, a NAT rule or an "allow any" the red team added shows up
#   as a HIGH change).
#
#   Vendors (the "vendor" of a device):
#     cisco-ios   routers and switches   terminal length 0 / show running-config
#     cisco-asa   ASA firewalls          terminal pager 0 / show running-config
#     paloalto    PAN-OS firewalls       set cli pager off / show config running
#     fortigate   FortiGate              show
#     vyos        VyOS routers           show configuration commands
#     pfsense     pfSense                cat /conf/config.xml  (log in as root)
#     opnsense    OPNsense               cat /conf/config.xml  (log in as root)
#     mikrotik    RouterOS               /export
#     linux       Linux router/firewall  iptables-save, nft list ruleset, ip addr/route
#
# USAGE
#   sh NW-01-config-backup.sh --hosts config/hosts.csv            all network devices
#   sh NW-01-config-backup.sh --device fw01,10.0.2.1,paloalto
#   BT_NET_PASS='...' sh NW-01-config-backup.sh --hosts hosts.csv --password-env
#
# OPTIONS
#   --hosts FILE       host list (config/hosts.example.csv format).  Rows with
#                      os "network" (or a vendor name as os) are devices; the
#                      vendor comes from a "vendor" column, the os column, or
#                      the notes ("Palo Alto", "Cisco ASA", "pfSense" ...)
#   --device SPEC      NAME,ADDRESS,VENDOR[,USER[,PORT]] (repeat)
#   --user NAME        login name when the list gives none (default admin)
#   --password-env     log in with the password in $BT_NET_PASS (needs
#                      sshpass); without it SSH keys are used
#   --ask-password     ask for the password once (needs sshpass)
#   --enable-env       Cisco: send "enable" with the password in
#                      $BT_NET_ENABLE (when the login is not privilege 15)
#   --legacy-ssh       allow old SSH algorithms from the start (old Cisco gear;
#                      tried automatically when a device refuses the modern ones)
#   --max-flags N      HIGH/MED flags shown on screen (default 30)
#   --help             this text plus the common options
#
# OUTPUTS
#   <out>/NW-01_<host>_<UTC time>/
#     summary.txt              each device: status, size, changes; the flags
#     devices.csv              device,address,vendor,status,lines,added,removed,sha256
#     <device>.diff            unified diff against the previous copy
#     flags.csv                HIGH/MED/LOW changes
#   <out>/net-configs/<device>/<UTC time>.cfg   every saved config (mode 600)
#   <out>/net-configs/known_hosts               the devices' SSH host keys
#
# WHAT IT CHANGES
#   Nothing on the devices: only show/cat/export commands are sent (and the
#   session-only pager settings above).  Configs hold password hashes, SNMP
#   communities and VPN keys: they are saved mode 600, and secrets are masked
#   in everything printed on screen.
#
# DEPENDS ON
#   ssh; sshpass for password logins; diff; awk.  BT_SSH may name a
#   stand-in ssh (the tests use one).
#
# TESTED ON
#   The flow end to end against a real OpenSSH server (vendor "linux"), and
#   every vendor's commands and clean-up against recorded-style sample output,
#   under dash, bash, busybox sh, ksh93, mksh and yash.  NOT yet against real
#   Cisco, Palo Alto, FortiGate, VyOS or pfSense devices - run it once on the
#   real gear and check the saved configs look complete.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - Cisco logins below privilege 15 see a partial config; use --enable-env
#     or a privilege 15 account.
#   - pfSense/OPNsense: log in as root (its shell can run commands; admin
#     lands in a menu).
#   - A changed device SSH key stops the backup for that device and is a HIGH
#     flag: find out why before you trust it (rm the line from known_hosts).
#
# DEBUGGING
#   --debug shows each ssh command (never the password) and its exit code.
#   The raw output of a failed device is in the log.
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

VENDORS="cisco-ios cisco-asa paloalto fortigate vyos pfsense opnsense mikrotik linux"

usage() {
    cat <<'USAGE'
NW-01 Network device config backup and diff
  sh NW-01-config-backup.sh --hosts FILE | --device NAME,ADDRESS,VENDOR[,USER[,PORT]] [options]

  --hosts FILE       host list; rows with os "network" or a vendor name
  --device SPEC      NAME,ADDRESS,VENDOR[,USER[,PORT]] (repeatable)
  --user NAME        default login name (admin)
  --password-env     password from $BT_NET_PASS (needs sshpass)
  --ask-password     ask for the password once (needs sshpass)
  --enable-env       Cisco enable password from $BT_NET_ENABLE
  --legacy-ssh       allow old SSH algorithms
  --max-flags N      HIGH/MED flags on screen (default 30)
  --help             show this text

Vendors: cisco-ios cisco-asa paloalto fortigate vyos pfsense opnsense mikrotik linux
USAGE
    cc_usage_common
}

NL='
'
HOSTS=""; DEVICES=""; DEFUSER="admin"; PWMODE="key"; ENABLE=0; LEGACY=0; MAXFLAGS=30
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --hosts)        [ $# -ge 2 ] || cc_die 2 "--hosts needs a file"; [ -r "$2" ] || cc_die 2 "--hosts: cannot read $2"; HOSTS=$2; shift 2 ;;
        --device)       [ $# -ge 2 ] || cc_die 2 "--device needs NAME,ADDRESS,VENDOR"; DEVICES="$DEVICES$2$NL"; shift 2 ;;
        --user)         [ $# -ge 2 ] || cc_die 2 "--user needs a name"; DEFUSER=$2; shift 2 ;;
        --password-env) PWMODE="env"; shift ;;
        --ask-password) PWMODE="ask"; shift ;;
        --enable-env)   ENABLE=1; shift ;;
        --legacy-ssh)   LEGACY=1; shift ;;
        --max-flags)    [ $# -ge 2 ] || cc_die 2 "--max-flags needs a number"; MAXFLAGS=$2; shift 2 ;;
        --help|-h)      usage; exit 0 ;;
        *)              cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
[ -n "$HOSTS$DEVICES" ] || cc_die 2 "give --hosts FILE or --device NAME,ADDRESS,VENDOR (try --help)"
case "$MAXFLAGS" in ''|*[!0-9]*) cc_die 2 "--max-flags needs a whole number" ;; esac

cc_init "NW-01" "Network config backup" readonly
cc_use_run_dir
W="$CC_RUN_DIR/.work"
mkdir -p "$W" || cc_die 3 "cannot create $W"
STORE="$CC_OUT/net-configs"
(umask 077; mkdir -p "$STORE") || cc_die 3 "cannot create $STORE"
SSH=${BT_SSH:-$(cc_which ssh)} || cc_die 3 "ssh not found"
DCSV=$(cc_csv_new devices "device,address,vendor,status,lines,added,removed,sha256")

# ---- Password (never on a command line, never in the log) --------------------
if [ "$PWMODE" != key ]; then
    SSHPASS_BIN=$(cc_which sshpass) || cc_die 3 "password logins need sshpass (apt install sshpass), or use SSH keys"
    if [ "$PWMODE" = ask ]; then
        [ -r /dev/tty ] || cc_die 3 "--ask-password needs a terminal; use --password-env"
        printf 'Device password: ' >/dev/tty; stty -echo </dev/tty 2>/dev/null
        read -r BT_NET_PASS </dev/tty; stty echo </dev/tty 2>/dev/null; printf '\n' >/dev/tty
    fi
    [ -n "${BT_NET_PASS:-}" ] || cc_die 3 "no password: set BT_NET_PASS (or use --ask-password)"
    # sshpass -e reads SSHPASS from the environment, so the password never
    # appears in a process list.
    SSHPASS=$BT_NET_PASS; export SSHPASS
fi
if [ "$ENABLE" = 1 ] && [ -z "${BT_NET_ENABLE:-}" ]; then cc_die 3 "--enable-env: set BT_NET_ENABLE"; fi

# ---- Device list ---------------------------------------------------------------
# $W/devices: name|address|vendor|user|port
# vendor_of TEXT -> a vendor name guessed from free text (os or notes).
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
        /^linux$/ { print "linux"; exit }
        /cisco/ { print "cisco-ios"; exit }'
}
: >"$W/devices"
if [ -n "$HOSTS" ]; then
    awk -F',' "$CC_AWK_CSV"'
        /^[ \t]*#/ || NF < 2 { next }
        !hdr { n = csvsplit($0, h); for (i = 1; i <= n; i++) c[tolower(h[i])] = i; hdr = 1; next }
        { csvsplit($0, f)
          os = tolower(f[c["os"]]); v = ("vendor" in c) ? f[c["vendor"]] : ""
          print f[c["host"]] "|" f[c["ip"]] "|" os "|" v "|" f[c["notes"]] "|" (("user" in c) ? f[c["user"]] : "") "|" (("port" in c) ? f[c["port"]] : "") }' "$HOSTS" >"$W/rows"
    while IFS='|' read -r _n _a _os _v _notes _u _p; do
        _vend=""
        [ -n "$_v" ] && _vend=$(vendor_of "$_v")
        # A vendor name in the os column counts - except "linux", which is
        # every Linux server: a Linux router is named with a vendor column
        # or --device.
        [ -z "$_vend" ] && [ "$_os" != linux ] && case " $VENDORS " in *" $_os "*) _vend=$_os ;; esac
        if [ -z "$_vend" ] && [ "$_os" = network ]; then
            _vend=$(vendor_of "$_notes")
            [ -n "$_vend" ] || { cc_warn "$_n: os is network but the vendor is unknown (add a vendor column or name it in notes) - skipped"; continue; }
        fi
        [ -n "$_vend" ] || continue
        printf '%s|%s|%s|%s|%s\n' "$_n" "$_a" "$_vend" "${_u:-$DEFUSER}" "${_p:-22}" >>"$W/devices"
    done <"$W/rows"
fi
printf '%s' "$DEVICES" | grep . | while IFS=',' read -r _n _a _v _u _p; do
    [ -n "$_n" ] && [ -n "$_a" ] && [ -n "$_v" ] || { echo "BAD|$_n,$_a,$_v"; continue; }
    case " $VENDORS " in *" $_v "*) ;; *) echo "BADV|$_v"; continue ;; esac
    printf '%s|%s|%s|%s|%s\n' "$_n" "$_a" "$_v" "${_u:-$DEFUSER}" "${_p:-22}"
done >>"$W/devices"
if grep -q '^BAD|' "$W/devices"; then cc_die 2 "--device needs NAME,ADDRESS,VENDOR: $(grep '^BAD|' "$W/devices" | head -n 1 | cut -d'|' -f2)"; fi
if grep -q '^BADV|' "$W/devices"; then cc_die 2 "unknown vendor '$(grep '^BADV|' "$W/devices" | head -n 1 | cut -d'|' -f2)' (one of: $VENDORS)"; fi
[ -s "$W/devices" ] || cc_die 3 "no network devices found in the host list (os must be network or a vendor name)"
for _n in $(cut -d'|' -f1 "$W/devices"); do
    case "$_n" in *[!A-Za-z0-9_.-]*) cc_die 2 "device name '$_n' may only use letters, digits, '.', '_' and '-'" ;; esac
done

# ---- Per vendor: how to fetch, and what to drop before comparing -------------
# cmd_mode VENDOR -> "stdin" (commands typed into a shell session) or "exec"
# cmd_text VENDOR -> the commands
cmd_mode() { case "$1" in cisco-ios|cisco-asa|paloalto|fortigate) echo stdin ;; *) echo exec ;; esac; }
cmd_text() {
    _en=""
    [ "$ENABLE" = 1 ] && _en="enable$NL$BT_NET_ENABLE$NL"
    case "$1" in
        cisco-ios) printf '%sterminal length 0\nshow running-config\nexit\n' "$_en" ;;
        cisco-asa) printf '%sterminal pager 0\nshow running-config\nexit\n' "$_en" ;;
        paloalto)  printf 'set cli pager off\nshow config running\nexit\n' ;;
        fortigate) printf 'show\nexit\n' ;;
        vyos)      printf '/opt/vyatta/bin/vyatta-op-cmd-wrapper show configuration commands' ;;
        pfsense|opnsense) printf 'cat /conf/config.xml' ;;
        mikrotik)  printf '/export' ;;
        linux)     printf 'iptables-save 2>/dev/null; nft list ruleset 2>/dev/null; ip -o addr 2>/dev/null; ip route 2>/dev/null' ;;
    esac
}
# NORMALIZE: drop what changes by itself (timestamps, counters, prompts and
# echoed commands) so a diff shows only real configuration changes.
NORMALIZE='
{ sub(/\r$/, ""); sub(/[ \t]+$/, "") }
/^[^ ]*[>#] *(terminal (length|pager)|show |set cli pager|exit|enable)/ { next }
/^[A-Za-z0-9_.@()-]+[>#] *$/ { next }
v == "cisco-ios" && (/^! Last configuration change/ || /^! NVRAM config last updated/ || /^ntp clock-period/ || /^Current configuration :/ || /^Building configuration/) { next }
v == "cisco-asa" && (/^: Written by/ || /^Cryptochecksum:/ || /^: Serial Number/ || /^: Hardware:/ || /^: Saved/) { next }
v == "fortigate" && (/^#conf_file_ver=/) { next }
v == "mikrotik" && (/^# [a-z]{3}\/[0-9]+\/[0-9]+ [0-9:]+ by RouterOS/ || /^# [0-9-]+ [0-9:]+ by RouterOS/) { next }
v == "linux" && (/^# Generated by iptables-save/ || /^# Completed on/) { next }
v == "linux" && /^:[A-Z-]+ [A-Z-]+ \[[0-9]+:[0-9]+\]/ { sub(/ \[[0-9]+:[0-9]+\]$/, "") }
v == "linux" { gsub(/counter packets [0-9]+ bytes [0-9]+ /, "") }
{ print }'
# MASK: hide secrets in text shown on screen (the saved files keep them).
MASK='
function mask(s,   n, w, i, out, lw, m) {  # awk, not shell: posix-ok
    if (match(s, /<(password|community|rocommunity|rwcommunity|pre-shared-key|secret|psk|key|phash)>[^<]*</)) {
        m = substr(s, RSTART, RLENGTH); sub(/>[^<]*</, ">****<", m)
        s = substr(s, 1, RSTART - 1) m substr(s, RSTART + RLENGTH)
    }
    n = split(s, w, " "); out = ""
    for (i = 1; i <= n; i++) {
        lw = tolower(w[i]); gsub(/[^a-z-]/, "", lw)
        if (lw ~ /^(password|secret|community|key|key-string|psk|pre-shared-key|passphrase|passwd|authentication-key|plaintext-password|encrypted-password|enc)$/ && i < n) {
            out = out (out ? " " : "") w[i]
            if (w[i + 1] ~ /^[0-9]$/ && i + 2 <= n) { i++; out = out " " w[i] }
            i++; out = out " ****"; continue
        }
        out = out (out ? " " : "") w[i]
    }
    return out
}'

# ---- Fetch every device ---------------------------------------------------------
# run_ssh NAME ADDRESS USER PORT VENDOR LEGACYFLAG -> config on stdout
run_ssh() {
    _kh="$STORE/known_hosts"
    set -- "$1" "$2" "$3" "$4" "$5" "$6" -o ConnectTimeout=10 -o "UserKnownHostsFile=$_kh" -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR -p "$4"
    if [ "$PWMODE" = key ]; then set -- "$@" -o BatchMode=yes; else set -- "$@" -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1; fi
    if [ "$6" = 1 ]; then
        set -- "$@" -o KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group1-sha1 -o HostKeyAlgorithms=+ssh-rsa \
            -o PubkeyAcceptedAlgorithms=+ssh-rsa -o Ciphers=+aes128-cbc,aes256-cbc,3des-cbc
    fi
    _rs_n=$1; _rs_a=$2; _rs_u=$3; _rs_v=$5
    shift 6
    if [ "$(cmd_mode "$_rs_v")" = stdin ]; then
        cmd_text "$_rs_v" >"$W/cmds"
        if [ "$PWMODE" = key ]; then "$SSH" -T "$@" "$_rs_u@$_rs_a" <"$W/cmds"
        else "$SSHPASS_BIN" -e "$SSH" -T "$@" "$_rs_u@$_rs_a" <"$W/cmds"; fi
    else
        if [ "$PWMODE" = key ]; then "$SSH" "$@" "$_rs_u@$_rs_a" "$(cmd_text "$_rs_v")" </dev/null
        else "$SSHPASS_BIN" -e "$SSH" "$@" "$_rs_u@$_rs_a" "$(cmd_text "$_rs_v")" </dev/null; fi
    fi
}

: >"$W/summary_rows"
while IFS='|' read -r _n _a _v _u _p; do
    cc_info "$_n ($_v, $_a): fetching"
    mkdir -p "$STORE/$_n"; chmod 700 "$STORE/$_n"
    _try=$LEGACY
    run_ssh "$_n" "$_a" "$_u" "$_p" "$_v" "$_try" >"$W/raw" 2>"$W/err"
    _rc=$?
    if [ "$_rc" -ne 0 ] && [ "$_try" = 0 ] && grep -qi 'no matching \(key exchange\|host key\|cipher\)' "$W/err"; then
        cc_info "$_n: refused modern SSH algorithms - retrying with the old ones"
        _try=1
        run_ssh "$_n" "$_a" "$_u" "$_p" "$_v" 1 >"$W/raw" 2>"$W/err"
        _rc=$?
    fi
    cc_debug "$_n: ssh exit $_rc, $(wc -l <"$W/raw" | tr -d ' ') lines"
    # An empty or near-empty answer is a failure even with exit 0.
    awk -v v="$_v" "$NORMALIZE" "$W/raw" >"$W/norm"
    _lines=$(grep -c . "$W/norm")
    if grep -q 'REMOTE HOST IDENTIFICATION HAS CHANGED\|Host key verification failed' "$W/err"; then
        sed 's/^/    /' "$W/err" >>"$CC_LOG"
        cc_flag HIGH "$_n" "$_a" "the device's SSH host key CHANGED since the last backup: device replaced, reinstalled, or someone in the middle. Not backed up. Check, then remove its line from $STORE/known_hosts"
        cc_csv_row "$DCSV" "$_n" "$_a" "$_v" "HOST KEY CHANGED" 0 0 0 ""
        printf '%s|%s|HOST KEY CHANGED|0|0|0\n' "$_n" "$_v" >>"$W/summary_rows"; CC_N_FAIL=$((CC_N_FAIL + 1)); continue
    fi
    if [ "$_rc" -ne 0 ] || [ "$_lines" -lt 3 ]; then
        { printf '%s: ssh exit %s\n' "$_n" "$_rc"; sed 's/^/    /' "$W/err"; head -n 20 "$W/raw" | awk "$MASK"'{ print "    " mask($0) }'; } >>"$CC_LOG"
        _why=$(grep -v '^$' "$W/err" | tail -n 1 | cut -c1-80)
        [ -n "$_why" ] || _why="empty answer (no rights to show the config?)"
        cc_flag MED "$_n" "$_a" "backup FAILED: $_why"
        cc_csv_row "$DCSV" "$_n" "$_a" "$_v" "failed: $_why" "$_lines" 0 0 ""
        printf '%s|%s|failed: %s|%s|0|0\n' "$_n" "$_v" "$_why" "$_lines" >>"$W/summary_rows"; CC_N_FAIL=$((CC_N_FAIL + 1)); continue
    fi
    # Compare with the newest earlier copy FIRST, then save this one.  Copies
    # are named after this run's folder (time plus -2, -3 for runs in the
    # same second), so two quick runs never overwrite each other.
    # "latest" names the newest copy: sorting names would put a same-second
    # "...Z-2" copy before its "...Z" twin.
    _prev=""
    [ -f "$STORE/$_n/latest" ] && _prev="$STORE/$_n/$(cat "$STORE/$_n/latest").norm"
    [ -f "$_prev" ] || _prev=""
    _stamp=${CC_RUN_DIR##*_}
    _hash=$(cc_sha256 "$W/norm")
    _add=0; _del=0
    if [ -n "$_prev" ]; then
        diff -u "$_prev" "$W/norm" >"$W/diff" 2>/dev/null
        # Skip the two header lines (---/+++) by position, not by pattern: a
        # config line can itself start with "-" (iptables "-A INPUT ...").
        awk 'NR > 2 && /^[-+]/' "$W/diff" >"$W/changed"
        _add=$(grep -c '^+' "$W/changed"); _del=$(grep -c '^-' "$W/changed")
        if [ "$_add" -gt 0 ] || [ "$_del" -gt 0 ]; then
            (umask 077; cp "$W/diff" "$CC_RUN_DIR/$_n.diff")
            # Changes to accounts, secrets, SNMP, NAT, permits, management
            # services or routing are HIGH; any other change is MED.
            awk -v d="$_n" "$MASK"'
                { sign = substr($0, 1, 1); l = substr($0, 2); low = tolower(l)
                  sev = (low ~ /(username|user |admin|password|secret|community|snmp|nat|static|permit (ip|tcp|udp) any|any any|allow|accept|telnet|http server|ip http|allowaccess|aaa|crypto|key|tunnel|route|rule|policy|ssh|login)/) ? "HIGH" : "MED"
                  print sev "|" d "|" (sign == "+" ? "added: " : "removed: ") mask(l) }' "$W/changed" >"$W/chg"
            while IFS='|' read -r _sev _d _det; do cc_flag "$_sev" "$_d" "config line" "$_det"; done <"$W/chg"
        fi
        _st=$([ "$_add" -gt 0 ] || [ "$_del" -gt 0 ] && echo changed || echo "no change")
    else
        _st="saved (first copy)"
    fi
    (umask 077; cp "$W/raw" "$STORE/$_n/$_stamp.cfg"; cp "$W/norm" "$STORE/$_n/$_stamp.norm"; printf '%s\n' "$_stamp" >"$STORE/$_n/latest"; printf '%s\n' "$_v" >"$STORE/$_n/vendor")
    [ "$_try" = 1 ] && _st="$_st, old SSH algorithms"
    cc_csv_row "$DCSV" "$_n" "$_a" "$_v" "$_st" "$_lines" "$_add" "$_del" "$_hash"
    printf '%s|%s|%s|%s|%s|%s\n' "$_n" "$_v" "$_st" "$_lines" "$_add" "$_del" >>"$W/summary_rows"
done <"$W/devices"

# ---- Summary ----------------------------------------------------------------------
{
    printf 'NW-01 Network config backup | %s\n\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '%-16s %-10s %6s %6s %6s  %s\n' device vendor lines added removed status
    awk -F'|' '{ printf "%-16s %-10s %6s %6s %6s  %s\n", $1, $2, $4, $5, $6, $3 }' "$W/summary_rows"
    printf '\n'
    cc_flag_report "$MAXFLAGS"
    printf '\nSaved configs: %s/<device>/  (mode 600: they hold password hashes and keys)\n' "$STORE"
    ls "$CC_RUN_DIR"/*.diff >/dev/null 2>&1 && printf 'Diffs: %s/<device>.diff\n' "$CC_RUN_DIR"
    printf 'All results: %s\n' "$CC_RUN_DIR"
} >"$CC_RUN_DIR/summary.txt"
cat "$CC_RUN_DIR/summary.txt"
rm -rf "$W"
cc_finish
