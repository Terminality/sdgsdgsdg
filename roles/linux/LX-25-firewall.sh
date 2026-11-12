#!/bin/sh
# =============================================================================
# ID:       LX-25
# NAME:     Linux firewall builder
# ROLE:     Linux  (wave 2, first 15 minutes - run it LAST of the hardening)
# KIND:     changes - dry run unless --apply
# VERSION:  1.1.0
#
# PURPOSE
#   Drops every incoming connection except the ones the box needs:
#     - loopback, replies to connections the box made, ping, DHCP replies
#     - the scored ports (protected list, type port) and every port that is
#       listening on a network address right now - EXCEPT backdoor-style
#       ports (4444, 31337, ...), which are listed instead
#     - SSH (the port sshd really uses), optionally only from --ssh-from
#     - everything from the admin addresses (--admin) and the protected
#       hosts (type host: the scoring engine)
#   IPv6 is dropped (except loopback) unless --keep-ipv6.  Outgoing traffic
#   is left alone unless --restrict-out.
#
#   SAFETY
#     - It adds its OWN rules (nftables table "inet ccdc", or iptables chains
#       CCDC-IN/CCDC-OUT) and never flushes anyone else's: Docker, fail2ban,
#       firewalld and ufw keep their rules.
#     - The ruleset is checked by nft (-c) before it goes live.
#     - ROLLBACK TIMER: after --apply the rules are removed again after
#       --confirm-timeout seconds (default 120) unless someone confirms -
#       from a NEW ssh session, which proves new connections still get in:
#           sudo sh <run folder>/keep-firewall.sh
#       At a terminal it also asks; answering "n" removes the rules at once.
#     - The rules are NOT saved for reboot until you run --save, so a
#       reboot is a last-resort undo.
#
# USAGE
#   sudo sh LX-25-firewall.sh                          dry run: prints the rules
#   sudo sh LX-25-firewall.sh --apply --admin 10.0.0.5
#   sudo sh LX-25-firewall.sh --save --apply           after confirming: keep across reboot
#   sudo sh LX-25-firewall.sh --remove --apply         take the rules out again
#
# OPTIONS
#   --allow SPEC        also allow PORT, PORT/tcp, PORT/udp or FIRST-LAST/tcp
#                       (repeat or comma-separate)
#   --admin CIDR        allow everything from this address or network (repeat)
#   --ssh-from CIDR     allow SSH only from these sources (repeat).  Leave it
#                       out if the scoring engine checks SSH
#   --strict            allow ONLY scored ports, --allow, SSH and DHCP - not
#                       every port that happens to be listening
#   --restrict-out      also limit OUTGOING traffic to DNS, NTP, HTTP(S),
#                       replies and the admin addresses (stops reverse shells;
#                       can break software that calls out)
#   --keep-ipv6         do not drop IPv6
#   --backend NAME      nft or iptables (default: nft when it works)
#   --confirm-timeout N seconds before the automatic rollback (default 120;
#                       0 = no timer, keep at once - only at the console)
#   --save              save the CURRENT ccdc rules for reboot and exit
#   --remove            remove the ccdc rules and exit
#                       (both are dry runs without --apply, like every change)
#   --help              this text plus the common options
#
# OUTPUTS  (under --out, in LX-25_<host>_<UTC time>/)
#   summary.txt         what is allowed and why, what is not, timer status
#   ports.csv           proto,port,allowed,reason
#   ruleset.nft / ruleset.iptables.sh   the exact rules
#   rollback.sh         removes the rules (also in the undo log)
#   keep-firewall.sh    run from a NEW session to cancel the rollback timer
#
# WHAT IT CHANGES  (only with --apply / --save / --remove)
#   The live firewall (own table/chains only).  --save also writes
#   /etc/ccdc-firewall.nft plus an include line in /etc/nftables.conf, or
#   saves iptables rules with the distribution's tool.
#
# DEPENDS ON
#   nft or iptables (+ ip6tables); ss or netstat for listening ports; sshd -T
#   for the SSH port.  CCDC_NFT, CCDC_IPTABLES, CCDC_IP6TABLES and CCDC_SS
#   may name stand-in programs (the tests use them).
#
# TESTED ON
#   Ubuntu 24.04 (nftables 1.0.9, iptables 1.8.10) under dash, bash, busybox
#   sh, ksh93, mksh and yash with stand-ins, and live: traffic from a separate
#   network namespace reaches allowed ports and is dropped on others; the
#   rollback timer removes the rules when nobody confirms.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - Run it LAST, after the other fixes, and keep a second session open.
#   - A scored service that is down while this runs is not listening, so its
#     port is only allowed if it is on the protected list or in --allow.
#   - Other firewalls still apply on top: a port this allows can still be
#     blocked by ufw or firewalld rules.
#   - FORWARD (routing) is never touched: routers and Docker keep working.
#
# DEBUGGING
#   --debug shows how every listening port was classified.  The rules are in
#   ruleset.nft / ruleset.iptables.sh; "nft list table inet ccdc" or
#   "iptables -S CCDC-IN" shows what is live.  Dropped packets are logged
#   with the prefix "CCDC-DROP" (journalctl -k | grep CCDC-DROP).
# =============================================================================

# >>> CCDC-LIB
# Development copy: find lib/lib.sh by walking up from this file.  The build
# step (tools/build.sh, LB-03) replaces this whole block with the library
# itself, so the built script is a single standalone file.
_cc_d=$(cd "$(dirname "$0")" && pwd)
while [ "$_cc_d" != "/" ] && [ ! -f "$_cc_d/lib/lib.sh" ]; do _cc_d=$(dirname "$_cc_d"); done
[ -f "$_cc_d/lib/lib.sh" ] || { echo "cannot find lib/lib.sh above $0" >&2; exit 3; }
. "$_cc_d/lib/lib.sh"
# <<< CCDC-LIB

usage() {
    cat <<'USAGE'
LX-25 Linux firewall builder - drop everything the box does not need
  sudo sh LX-25-firewall.sh [--apply] [options]

  --allow SPEC         also allow PORT[/tcp|/udp] or FIRST-LAST/tcp (repeatable)
  --admin CIDR         allow everything from this address (repeatable)
  --ssh-from CIDR      allow SSH only from these sources (repeatable)
  --strict             allow only scored ports, --allow, SSH, DHCP
  --restrict-out       also limit outgoing traffic (stops reverse shells)
  --keep-ipv6          do not drop IPv6
  --backend nft|iptables
  --confirm-timeout N  seconds before automatic rollback (default 120, 0 = none)
  --save               save the current ccdc rules for reboot, then exit (with --apply)
  --remove             remove the ccdc rules, then exit (with --apply)
  --help               show this text

USAGE
    cc_usage_common
}

NL='
'
ALLOW=""; ADMIN=""; SSHFROM=""; STRICT=0; RESTOUT=0; KEEP6=0; BACKEND=""; TIMEOUT=120; MODE=build
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --allow)           [ $# -ge 2 ] || cc_die 2 "--allow needs a port"; ALLOW="$ALLOW,$2"; shift 2 ;;
        --admin)           [ $# -ge 2 ] || cc_die 2 "--admin needs an address"; ADMIN="$ADMIN$2$NL"; shift 2 ;;
        --ssh-from)        [ $# -ge 2 ] || cc_die 2 "--ssh-from needs an address"; SSHFROM="$SSHFROM$2$NL"; shift 2 ;;
        --strict)          STRICT=1; shift ;;
        --restrict-out)    RESTOUT=1; shift ;;
        --keep-ipv6)       KEEP6=1; shift ;;
        --backend)         [ $# -ge 2 ] || cc_die 2 "--backend needs nft or iptables"; BACKEND=$2; shift 2 ;;
        --confirm-timeout) [ $# -ge 2 ] || cc_die 2 "--confirm-timeout needs seconds"; TIMEOUT=$2; shift 2 ;;
        --save)            MODE=save; shift ;;
        --remove)          MODE=remove; shift ;;
        --help|-h)         usage; exit 0 ;;
        *)                 cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
case "$TIMEOUT" in ''|*[!0-9]*) cc_die 2 "--confirm-timeout needs a whole number of seconds" ;; esac
case "$BACKEND" in ''|nft|iptables) ;; *) cc_die 2 "--backend must be nft or iptables" ;; esac
# valid_cidr ADDR -> IPv4 address or network (a.b.c.d or a.b.c.d/n), or IPv6.
valid_cidr() {
    printf '%s' "$1" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]|[12][0-9]|3[0-2]))?$|^[0-9a-fA-F:]+:[0-9a-fA-F:]*(/[0-9]{1,3})?$'
}
for _a in $ADMIN $SSHFROM; do valid_cidr "$_a" || cc_die 2 "not an address or network: $_a"; done
# Port specs -> "proto|first|last" lines.
SPECS=""
for _s in $(printf '%s' "$ALLOW" | tr ',' ' '); do
    case "$_s" in
        */tcp|*/udp) _p=${_s%/*}; _pr=${_s#*/} ;;
        *) _p=$_s; _pr=both ;;
    esac
    case "$_p" in
        *-*) _f=${_p%-*}; _l=${_p#*-} ;;
        *) _f=$_p; _l=$_p ;;
    esac
    case "$_f$_l" in ''|*[!0-9]*) cc_die 2 "--allow: not a port or range: $_s" ;; esac
    { [ "$_f" -ge 1 ] && [ "$_l" -le 65535 ] && [ "$_f" -le "$_l" ]; } || cc_die 2 "--allow: port out of range: $_s"
    if [ "$_pr" = both ]; then SPECS="${SPECS}tcp|$_f|$_l$NL""udp|$_f|$_l$NL"; else SPECS="$SPECS$_pr|$_f|$_l$NL"; fi
done

cc_init "LX-25" "Linux firewall builder" changes
cc_detect_os
[ "$CC_OS_KERNEL" = linux ] || cc_die 3 "this script is for Linux (nftables/iptables); use the BSD or Windows firewall scripts elsewhere"
{ [ "$CC_APPLY" = 1 ] || [ "$MODE" != build ]; } && cc_require_root
cc_use_run_dir
W="$CC_RUN_DIR/.work"
mkdir -p "$W" || cc_die 3 "cannot create $W"

# ---- Tools ---------------------------------------------------------------------
NFT=${CCDC_NFT:-$(cc_which nft)} || NFT=""
IPT=${CCDC_IPTABLES:-$(cc_which iptables)} || IPT=""
IP6T=${CCDC_IP6TABLES:-$(cc_which ip6tables)} || IP6T=""
SS=${CCDC_SS:-$(cc_which ss)} || SS=""
if [ -z "$BACKEND" ]; then
    if [ -n "$NFT" ] && "$NFT" list tables >/dev/null 2>&1; then BACKEND=nft
    elif [ -n "$IPT" ]; then BACKEND=iptables
    else cc_die 3 "neither nft nor iptables works here"; fi
fi
[ "$BACKEND" = nft ] && [ -z "$NFT" ] && cc_die 3 "nft not found"
[ "$BACKEND" = iptables ] && [ -z "$IPT" ] && cc_die 3 "iptables not found"
cc_debug "backend: $BACKEND nft=$NFT iptables=$IPT ss=$SS"

# The commands that remove our rules; used by --remove, the undo log and the timer.
ROLLBACK="$CC_RUN_DIR/rollback.sh"
{
    printf '#!/bin/sh\n# Removes the CCDC firewall rules made by LX-25. Other rules are not touched.\n'
    if [ "$BACKEND" = nft ]; then
        printf '%s list table inet ccdc >/dev/null 2>&1 && %s delete table inet ccdc\n' "$NFT" "$NFT"
    else
        for _t in "$IPT" "$IP6T"; do
            [ -n "$_t" ] || continue
            printf 'while %s -D INPUT -j CCDC-IN 2>/dev/null; do :; done\n' "$_t"
            printf 'while %s -D OUTPUT -j CCDC-OUT 2>/dev/null; do :; done\n' "$_t"
            printf '%s -F CCDC-IN 2>/dev/null; %s -X CCDC-IN 2>/dev/null\n' "$_t" "$_t"
            printf '%s -F CCDC-OUT 2>/dev/null; %s -X CCDC-OUT 2>/dev/null\n' "$_t" "$_t"
        done
    fi
    printf 'echo "CCDC firewall rules removed"\n'
} >"$ROLLBACK"
chmod 700 "$ROLLBACK"

# ---- --remove and --save ----------------------------------------------------------
if [ "$MODE" = remove ]; then
    cc_run "remove the CCDC firewall rules" sh "$ROLLBACK"
    cc_finish
fi
if [ "$MODE" = save ]; then
    if [ "$BACKEND" = nft ]; then
        "$NFT" list table inet ccdc >"$W/live.nft" 2>/dev/null || cc_die 3 "no ccdc table is live: nothing to save (apply and confirm first)"
        { printf 'table inet ccdc\ndelete table inet ccdc\n'; cat "$W/live.nft"; } >"$W/save.nft"
        cc_backup_file /etc/ccdc-firewall.nft || cc_die 5 "backup failed"
        cc_run "save the rules to /etc/ccdc-firewall.nft" cp "$W/save.nft" /etc/ccdc-firewall.nft
        if [ -f /etc/nftables.conf ]; then
            if ! grep -q 'include "/etc/ccdc-firewall.nft"' /etc/nftables.conf; then
                cc_backup_file /etc/nftables.conf || cc_die 5 "backup failed"
                cc_run "load them at boot (include line in /etc/nftables.conf)" sh -c 'printf "\ninclude \"/etc/ccdc-firewall.nft\"\n" >>/etc/nftables.conf'
            fi
            [ "$CC_INIT" = systemd ] && cc_run "enable the nftables service at boot" systemctl enable nftables
        else
            cc_warn "no /etc/nftables.conf: load /etc/ccdc-firewall.nft at boot yourself (nft -f /etc/ccdc-firewall.nft)"
        fi
    else
        if cc_have netfilter-persistent; then cc_run "save iptables rules (netfilter-persistent)" netfilter-persistent save
        elif [ -d /etc/sysconfig ]; then
            cc_backup_file /etc/sysconfig/iptables
            cc_run "save iptables rules to /etc/sysconfig/iptables" sh -c 'iptables-save >/etc/sysconfig/iptables'
        else cc_warn "no iptables save tool found (install iptables-persistent, or add iptables-restore to boot)"; fi
    fi
    cc_finish
fi

# ---- 1. What is listening ---------------------------------------------------------
# $W/listen: "proto|address|port|process"
: >"$W/listen"
if [ -n "$SS" ]; then
    "$SS" -ltnup 2>/dev/null | awk 'NR > 1 && ($1 == "tcp" || $1 == "udp") {
        a = $5; p = a; sub(/.*:/, "", p); sub(/:[^:]*$/, "", a); gsub(/[][]/, "", a); sub(/%.*/, "", a)
        pr = ""; if (match($0, /\(\("[^"]*"/)) pr = substr($0, RSTART + 3, RLENGTH - 4)
        print $1 "|" a "|" p "|" pr }' >"$W/listen"
elif cc_have netstat; then
    netstat -ltnup 2>/dev/null | awk '$1 ~ /^(tcp|udp)/ {
        pr0 = ($1 ~ /^tcp/) ? "tcp" : "udp"; a = $4; p = a; sub(/.*:/, "", p); sub(/:[^:]*$/, "", a)
        pp = ($1 ~ /^tcp/) ? $7 : $6; sub(/^[0-9]+\//, "", pp); print pr0 "|" a "|" p "|" pp }' >"$W/listen"
else
    cc_warn "no ss or netstat: listening ports unknown, only scored ports and --allow are opened"
fi
# SSH port: what sshd really uses (sshd -T), else what sshd listens on, else 22.
SSHPORTS=""
if _sshd=$(cc_which sshd) && [ -z "${CCDC_SS:-}" ]; then SSHPORTS=$("$_sshd" -T 2>/dev/null | awk '$1 == "port" { print $2 }' | sort -u | tr '\n' ' ' | sed 's/ *$//'); fi
[ -n "$SSHPORTS" ] || SSHPORTS=$(awk -F'|' '$1 == "tcp" && $4 ~ /^sshd/ { print $3 }' "$W/listen" | sort -u | tr '\n' ' ' | sed 's/ *$//')
[ -n "$SSHPORTS" ] || SSHPORTS=22

# ---- 2. Decide every port ------------------------------------------------------------
# $W/allow: "proto|first|last|reason"
BACKDOOR=' 1337 4444 4445 5555 6666 6667 12345 31337 54321 2375 '
: >"$W/allow"; : >"$W/notes"
PCSV=$(cc_csv_new ports "proto,port,allowed,reason")
add() { printf '%s|%s|%s|%s\n' "$1" "$2" "$3" "$4" >>"$W/allow"; }
add udp 68 68 "DHCP replies (keeps the address)"
[ "$KEEP6" = 1 ] && add udp 546 546 "DHCPv6 replies"
if [ -z "$SSHFROM" ]; then for _p in $SSHPORTS; do add tcp "$_p" "$_p" "SSH"; done; fi
# Scored ports from the protected list: "80", "80/tcp", "53/udp".
if [ -n "$CC_PROTECTED" ]; then
    awk -F',' '{ gsub(/[ "\r]/, "") } tolower($1) == "port" { print $2 }' "$CC_PROTECTED" >"$W/pports"
    while IFS= read -r _s; do
        _p=${_s%/*}; case "$_s" in */*) _pr=${_s#*/} ;; *) _pr=both ;; esac
        case "$_p" in ''|*[!0-9]*) continue ;; esac
        if [ "$_pr" = both ]; then add tcp "$_p" "$_p" "scored (protected list)"; add udp "$_p" "$_p" "scored (protected list)"
        else add "$_pr" "$_p" "$_p" "scored (protected list)"; fi
    done <"$W/pports"
fi
printf '%s' "$SPECS" | while IFS='|' read -r _pr _f _l; do [ -n "$_pr" ] && add "$_pr" "$_f" "$_l" "--allow"; done
# Listening ports: allowed unless loopback-only, backdoor-style, or --strict.
sort -t'|' -k1,1 -k3,3n -u "$W/listen" >"$W/listen.u"
while IFS='|' read -r _pr _a _p _proc; do
    case "$_a" in 127.*|::1|::ffff:127.*) cc_debug "loopback only: $_pr/$_p ($_proc)"; continue ;; esac
    if awk -F'|' -v pr="$_pr" -v p="$_p" '$1 == pr && p >= $2 && p <= $3 { f = 1 } END { exit !f }' "$W/allow"; then continue; fi
    # With --ssh-from, SSH gets its own rule limited to those sources; opening
    # it here as a listening port would let everyone in again.
    if [ -n "$SSHFROM" ] && [ "$_pr" = tcp ] && case " $SSHPORTS " in *" $_p "*) true ;; *) false ;; esac; then
        cc_csv_row "$PCSV" tcp "$_p" "only from --ssh-from" "SSH"
        continue
    fi
    case "$BACKDOOR" in
        *" $_p "*) cc_csv_row "$PCSV" "$_pr" "$_p" no "listening (${_proc:-?}) on a backdoor-style port - NOT allowed"
                   printf 'listening on %s/%s (%s) - backdoor-style port, NOT allowed; investigate it\n' "$_p" "$_pr" "${_proc:-?}" >>"$W/notes"
                   continue ;;
    esac
    if [ "$STRICT" = 1 ]; then
        cc_csv_row "$PCSV" "$_pr" "$_p" no "listening (${_proc:-?}) but --strict"
        printf 'listening on %s/%s (%s) - NOT allowed (--strict); add --allow %s/%s if it is scored\n' "$_p" "$_pr" "${_proc:-?}" "$_p" "$_pr" >>"$W/notes"
        continue
    fi
    add "$_pr" "$_p" "$_p" "listening now (${_proc:-?})"
done <"$W/listen.u"
# One row per allowed range for the CSV (duplicates merged).
sort -t'|' -k1,1 -k2,2n -u "$W/allow" | awk -F'|' '!s[$1 "|" $2 "|" $3]++' >"$W/allow.u"
while IFS='|' read -r _pr _f _l _why; do
    if [ "$_f" = "$_l" ]; then cc_csv_row "$PCSV" "$_pr" "$_f" yes "$_why"; else cc_csv_row "$PCSV" "$_pr" "$_f-$_l" yes "$_why"; fi
done <"$W/allow.u"
# FTP: the control port alone is not enough.  Passive-mode data connections
# come in on other ports that are not listening yet, so they would be dropped.
if awk -F'|' '$1 == "tcp" && $2 <= 21 && $3 >= 21 { f = 1 } END { exit !f }' "$W/allow.u" &&
   ! awk -F'|' '$1 == "tcp" && $2 >= 1024 && $3 > $2 { f = 1 } END { exit !f }' "$W/allow.u"; then
    printf 'FTP (21/tcp) is allowed, but passive-mode data ports are not: file listings and transfers may hang. Set a passive port range in the FTP server and add it, e.g. --allow 40000-40100/tcp\n' >>"$W/notes"
fi
# Sources allowed for everything: --admin and protected hosts (scoring engine).
SOURCES=$(printf '%s' "$ADMIN" | grep .)
if [ -n "$CC_PROTECTED" ]; then
    _ph=$(awk -F',' '{ gsub(/[ "\r]/, "") } tolower($1) == "host" { print $2 }' "$CC_PROTECTED")
    for _h in $_ph; do valid_cidr "$_h" && SOURCES="$SOURCES$NL$_h"; done
fi
SOURCES=$(printf '%s\n' "$SOURCES" | grep . | sort -u)
SSHFROM=$(printf '%s' "$SSHFROM" | grep . | sort -u)
# grep . drops the empty line printf makes from an empty list, so an empty
# list stays empty (an empty "{ }" set is a syntax error in nft).
SRC4=$(printf '%s\n' "$SOURCES" | grep . | grep -v ':' | tr '\n' ' ' | sed 's/ *$//')
SRC6=$(printf '%s\n' "$SOURCES" | grep ':' | tr '\n' ' ' | sed 's/ *$//')
SSH4=$(printf '%s\n' "$SSHFROM" | grep . | grep -v ':' | tr '\n' ' ' | sed 's/ *$//')

# portset PROTO -> "a, b, c-d" for nft, from the allowed list.
portset() { awk -F'|' -v pr="$1" '$1 == pr { s = s (s ? ", " : "") ($2 == $3 ? $2 : $2 "-" $3) } END { print s }' "$W/allow.u"; }
# commaset "a b c" -> "a, b, c"
commaset() { printf '%s' "$1" | awk '{ for (i = 1; i <= NF; i++) s = s (i > 1 ? ", " : "") $i } END { print s }'; }
TCPSET=$(portset tcp); UDPSET=$(portset udp)

# ---- 3. The rules ---------------------------------------------------------------------
if [ "$BACKEND" = nft ]; then
    RULES="$CC_RUN_DIR/ruleset.nft"
    {
        printf '# CCDC firewall (LX-25) %s - its own table; other tables are untouched.\n' "$CC_HOST"
        printf 'table inet ccdc\ndelete table inet ccdc\n'
        printf 'table inet ccdc {\n'
        printf '    chain input {\n        type filter hook input priority 0; policy accept;\n'
        printf '        iif "lo" accept\n'
        printf '        ct state established,related accept\n'
        printf '        ct state invalid drop\n'
        if [ "$KEEP6" = 1 ]; then printf '        meta l4proto ipv6-icmp accept\n'
        else printf '        meta nfproto ipv6 drop comment "IPv6 blocked"\n'; fi
        printf '        meta l4proto icmp accept comment "ping and ICMP errors"\n'
        [ -n "$SRC4" ] && printf '        ip saddr { %s } accept comment "admin and scoring hosts"\n' "$(commaset "$SRC4")"
        [ -n "$SRC6" ] && [ "$KEEP6" = 1 ] && printf '        ip6 saddr { %s } accept comment "admin and scoring hosts"\n' "$(commaset "$SRC6")"
        if [ -n "$SSHFROM" ]; then
            for _p in $SSHPORTS; do printf '        ip saddr { %s } tcp dport %s accept comment "SSH from the team only"\n' "$(commaset "$SSH4")" "$_p"; done
        fi
        [ -n "$TCPSET" ] && printf '        tcp dport { %s } accept\n' "$TCPSET"
        [ -n "$UDPSET" ] && printf '        udp dport { %s } accept\n' "$UDPSET"
        printf '        limit rate 10/minute log prefix "CCDC-DROP " level info\n'
        printf '        drop\n    }\n'
        if [ "$RESTOUT" = 1 ]; then
            printf '    chain output {\n        type filter hook output priority 0; policy accept;\n'
            printf '        oif "lo" accept\n        ct state established,related accept\n'
            printf '        meta l4proto { icmp, ipv6-icmp } accept\n'
            printf '        udp dport { 53, 67, 123 } accept\n        tcp dport { 53, 80, 443 } accept\n'
            [ -n "$SRC4" ] && printf '        ip daddr { %s } accept\n' "$(commaset "$SRC4")"
            printf '        limit rate 10/minute log prefix "CCDC-OUT-DROP " level info\n        drop\n    }\n'
        fi
        printf '}\n'
    } >"$RULES"
else
    RULES="$CC_RUN_DIR/ruleset.iptables.sh"
    {
        printf '#!/bin/sh\n# CCDC firewall (LX-25) %s - its own chains; other chains are untouched.\n' "$CC_HOST"
        printf 'set -e\nT=%s\n' "$IPT"
        printf '$T -N CCDC-IN 2>/dev/null || $T -F CCDC-IN\n'
        printf '$T -A CCDC-IN -i lo -j ACCEPT\n'
        printf '$T -A CCDC-IN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n'
        printf '$T -A CCDC-IN -m conntrack --ctstate INVALID -j DROP\n'
        printf '$T -A CCDC-IN -p icmp -j ACCEPT\n'
        for _s in $SRC4; do printf '$T -A CCDC-IN -s %s -j ACCEPT\n' "$_s"; done
        if [ -n "$SSHFROM" ]; then for _p in $SSHPORTS; do for _s in $SSH4; do printf '$T -A CCDC-IN -s %s -p tcp --dport %s -j ACCEPT\n' "$_s" "$_p"; done; done; fi
        awk -F'|' '{ printf "$T -A CCDC-IN -p %s --dport %s -j ACCEPT\n", $1, ($2 == $3 ? $2 : $2 ":" $3) }' "$W/allow.u"
        printf '$T -A CCDC-IN -m limit --limit 10/min -j LOG --log-prefix "CCDC-DROP "\n'
        printf '$T -A CCDC-IN -j DROP\n'
        printf '$T -C INPUT -j CCDC-IN 2>/dev/null || $T -I INPUT 1 -j CCDC-IN\n'
        if [ "$RESTOUT" = 1 ]; then
            printf '$T -N CCDC-OUT 2>/dev/null || $T -F CCDC-OUT\n'
            printf '$T -A CCDC-OUT -o lo -j ACCEPT\n$T -A CCDC-OUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n$T -A CCDC-OUT -p icmp -j ACCEPT\n'
            printf '$T -A CCDC-OUT -p udp -m multiport --dports 53,67,123 -j ACCEPT\n$T -A CCDC-OUT -p tcp -m multiport --dports 53,80,443 -j ACCEPT\n'
            for _s in $SRC4; do printf '$T -A CCDC-OUT -d %s -j ACCEPT\n' "$_s"; done
            printf '$T -A CCDC-OUT -m limit --limit 10/min -j LOG --log-prefix "CCDC-OUT-DROP "\n$T -A CCDC-OUT -j DROP\n'
            printf '$T -C OUTPUT -j CCDC-OUT 2>/dev/null || $T -I OUTPUT 1 -j CCDC-OUT\n'
        fi
        if [ -n "$IP6T" ]; then
            printf 'T6=%s\n$T6 -N CCDC-IN 2>/dev/null || $T6 -F CCDC-IN\n' "$IP6T"
            printf '$T6 -A CCDC-IN -i lo -j ACCEPT\n$T6 -A CCDC-IN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n'
            if [ "$KEEP6" = 1 ]; then
                printf '$T6 -A CCDC-IN -p ipv6-icmp -j ACCEPT\n'
                for _s in $SRC6; do printf '$T6 -A CCDC-IN -s %s -j ACCEPT\n' "$_s"; done
                awk -F'|' '{ printf "$T6 -A CCDC-IN -p %s --dport %s -j ACCEPT\n", $1, ($2 == $3 ? $2 : $2 ":" $3) }' "$W/allow.u"
            fi
            printf '$T6 -A CCDC-IN -j DROP\n$T6 -C INPUT -j CCDC-IN 2>/dev/null || $T6 -I INPUT 1 -j CCDC-IN\n'
        fi
    } >"$RULES"
    chmod 700 "$RULES"
fi

# ---- 4. Check, apply, start the rollback timer -------------------------------------
KEEPF="$CC_RUN_DIR/.keep"
# Names the run whose rules are live.  A rollback timer only acts while it
# still names its own run: without this, the timer of an earlier, unconfirmed
# run would later remove the rules of a newer run that WAS confirmed.
CURRENT="$CC_OUT/lx25-live-$CC_HOST"
KEEPSH="$CC_RUN_DIR/keep-firewall.sh"
_state="dry run - nothing changed"
if [ "$BACKEND" = nft ] && ! "$NFT" -c -f "$RULES" >"$W/check" 2>&1; then
    cat "$W/check" >>"$CC_LOG"
    cc_err "nft rejected the ruleset (nothing applied): $(head -n 1 "$W/check")"
    CC_N_FAIL=$((CC_N_FAIL + 1))
    _state="FAILED: nft -c rejected the ruleset (see the log)"
elif [ "$CC_APPLY" = 1 ]; then
    if [ "$BACKEND" = nft ]; then cc_run "load the firewall rules (nft -f)" "$NFT" -f "$RULES"
    else cc_run "load the firewall rules (iptables)" sh "$RULES"; fi
    _rc=$?
    if [ "$_rc" -ne 0 ]; then
        cc_err "loading the rules failed - removing whatever was loaded"
        sh "$ROLLBACK" >>"$CC_LOG" 2>&1
        _state="FAILED to load; rules removed again"
    else
        cc_undo_add "remove the CCDC firewall rules" "sh $(cc_shquote "$ROLLBACK")"
        printf '%s\n' "$CC_RUN_DIR" >"$CURRENT"
        if [ "$TIMEOUT" -eq 0 ]; then
            _state="LIVE (no rollback timer: --confirm-timeout 0)"
        else
            # The timer runs detached, so it still fires if this session dies.
            cat >"$CC_RUN_DIR/rollback-timer.sh" <<EOF
#!/bin/sh
sleep $TIMEOUT
# Only if nobody confirmed AND no newer run has replaced these rules.
if [ ! -f $(cc_shquote "$KEEPF") ] && [ "\$(cat $(cc_shquote "$CURRENT") 2>/dev/null)" = $(cc_shquote "$CC_RUN_DIR") ]; then
    sh $(cc_shquote "$ROLLBACK") >/dev/null 2>&1
    date -u +%Y-%m-%dT%H:%M:%SZ >$(cc_shquote "$CC_RUN_DIR/ROLLED_BACK")
fi
EOF
            cat >"$KEEPSH" <<EOF
#!/bin/sh
# Run from a NEW session: proves new connections still get in, then keeps the rules.
if [ -f $(cc_shquote "$CC_RUN_DIR/ROLLED_BACK") ]; then echo "too late: the rules were already rolled back at \$(cat $(cc_shquote "$CC_RUN_DIR/ROLLED_BACK"))"; exit 1; fi
: >$(cc_shquote "$KEEPF")
kill \$(cat $(cc_shquote "$CC_RUN_DIR/.timer.pid") 2>/dev/null) 2>/dev/null
echo "kept: the CCDC firewall rules stay. To keep them across a reboot run LX-25 with --save."
EOF
            chmod 700 "$CC_RUN_DIR/rollback-timer.sh" "$KEEPSH"
            nohup sh "$CC_RUN_DIR/rollback-timer.sh" >/dev/null 2>&1 &
            echo $! >"$CC_RUN_DIR/.timer.pid"
            _state="LIVE - rollback in ${TIMEOUT}s unless confirmed"
            cc_warn "firewall is live. Rules are removed again in ${TIMEOUT}s unless confirmed."
            cc_warn "From a NEW ssh session run:  sudo sh $KEEPSH"
            if [ -r /dev/tty ] && [ "${CCDC_ASSUME_YES:-0}" != 1 ]; then
                # The question cannot prove new connections work, so it only
                # offers the quick way out ("n" = remove now).
                printf 'Check scoring and open a NEW ssh session now. Remove the rules immediately? [y/N] ' >/dev/tty
                if read -r _ans </dev/tty; then
                    case "$_ans" in y|Y|yes) sh "$ROLLBACK" >>"$CC_LOG" 2>&1; : >"$KEEPF"; kill "$(cat "$CC_RUN_DIR/.timer.pid")" 2>/dev/null
                        _state="removed at your request" ;;
                    esac
                fi
            fi
        fi
    fi
fi

# ---- Summary ------------------------------------------------------------------------
{
    printf 'LX-25 Linux firewall builder | host %s | %s | %s\n\n' "$CC_HOST" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$([ "$CC_APPLY" = 1 ] && echo APPLIED || echo 'DRY RUN - nothing changed')"
    printf 'Backend:  %s (own %s; nothing else is flushed)\n' "$BACKEND" "$([ "$BACKEND" = nft ] && echo 'table inet ccdc' || echo 'chains CCDC-IN/CCDC-OUT')"
    printf 'State:    %s\n' "$_state"
    printf 'IPv6:     %s\n' "$([ "$KEEP6" = 1 ] && echo 'allowed like IPv4 (--keep-ipv6)' || echo 'dropped (except loopback)')"
    printf 'Outgoing: %s\n' "$([ "$RESTOUT" = 1 ] && echo 'limited to DNS, DHCP, NTP, HTTP(S), replies and admin hosts' || echo 'not limited')"
    printf 'Allowed from anywhere:\n'
    awk -F'|' '{ printf "  %-4s %-12s %s\n", $1, ($2 == $3 ? $2 : $2 "-" $3), $4 }' "$W/allow.u"
    [ -n "$SOURCES" ] && printf 'Allowed for everything from: %s\n' "$(printf '%s' "$SOURCES" | tr '\n' ' ')"
    [ -n "$SSHFROM" ] && printf 'SSH (%s) only from: %s\n' "$SSHPORTS" "$(printf '%s' "$SSHFROM" | tr '\n' ' ')"
    if [ -s "$W/notes" ]; then printf '\nNOT allowed (check):\n'; sed 's/^/  /' "$W/notes" | cut -c1-240; fi
    printf '\nRules: %s\n' "$RULES"
    case "$_state" in
        LIVE*rollback*) printf '\nCONFIRM from a NEW ssh session within %ss, or the rules are removed:\n  sudo sh %s\n' "$TIMEOUT" "$KEEPSH" ;;
    esac
    [ "$CC_APPLY" = 1 ] && printf 'Remove at any time: sudo sh %s\nKeep across reboot (after confirming): run LX-25 again with --save\n' "$ROLLBACK"
    [ "$CC_APPLY" = 1 ] || printf 'Dry run: nothing changed.  Read the rules above, then run with --apply.\n'
    printf 'All results: %s\n' "$CC_RUN_DIR"
} >"$CC_RUN_DIR/summary.txt"
cat "$CC_RUN_DIR/summary.txt"
rm -rf "$W"
cc_finish
