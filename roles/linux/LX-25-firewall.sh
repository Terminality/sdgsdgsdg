#!/bin/sh
# =============================================================================
# ID:       LX-25
# NAME:     Linux firewall builder
# ROLE:     Linux  (wave 2, first 15 minutes - run it LAST of the hardening)
# KIND:     changes - dry run unless --apply
# VERSION:  2.2.0
#
# PURPOSE
#   Shows every open port on the box, says in plain words what each one is
#   and which program (or script) is behind it, asks port by port whether to
#   keep it open or drop it (like sqlmap: Enter takes the default), then
#   builds a firewall that drops every incoming connection except what you
#   kept.
#
#   For each listening port it shows:
#     - the port, and whether it listens on every address or only on this
#       box itself (loopback - nobody outside can reach those anyway)
#     - the program, its pid, the account it runs as, and its full command
#       line (so "python3 /opt/app/server.py" shows the script)
#     - what that port normally is (SSH, web, mail, a database ...), and
#       whether it was a scored service in past competitions
#       (docs/ENVIRONMENT.md) or is on your protected list
#     - a recommendation: KEEP, DROP, or "find out what this is"
#
#   Always allowed: loopback, replies to connections the box made, ping
#   (every box has a ping check), DHCP replies, the scored ports on the
#   protected list, SSH, and everything from your team's addresses (--admin)
#   and the scoring hosts on the protected list.
#   IPv6 is dropped unless you keep it.  Outgoing traffic is left alone
#   unless you ask to limit it.
#
#   SAFETY
#     - It adds its OWN rules (nftables table "inet bt", or iptables chains
#       BT-IN/BT-OUT) and never flushes anyone else's: Docker, fail2ban,
#       firewalld and ufw keep their rules.
#     - The ruleset is checked by nft (-c) before it goes live.
#     - ROLLBACK TIMER: after --apply the rules are removed again after
#       --confirm-timeout seconds (default 120) unless someone confirms -
#       from a NEW ssh session, which proves new connections still get in:
#           sudo sh <run folder>/keep-firewall.sh
#       At a terminal it also asks; answering "y" removes the rules at once.
#     - The rules are NOT saved for reboot until you run --save, so a
#       reboot is a last-resort undo.
#
# USAGE
#   sudo sh LX-25-firewall.sh                          look and plan: asks, changes nothing
#   sudo sh LX-25-firewall.sh --apply                  ask, then load the rules
#   sudo sh LX-25-firewall.sh --apply --batch --admin 10.0.0.5     no questions
#   sudo sh LX-25-firewall.sh --save --apply           after confirming: keep across reboot
#   sudo sh LX-25-firewall.sh --remove --apply         take the rules out again
#
# OPTIONS  (each answers a question in advance)
#   --admin CIDR        your team's address or network: always allowed in,
#                       for everything (repeat)
#   --keep SPEC         keep these listening ports open: 80, 80/tcp, 53/udp
#                       (repeat or comma-separate)
#   --drop SPEC         drop these listening ports, same form
#   --allow SPEC        also open ports that are NOT listening now (a scored
#                       service that is down): PORT, PORT/tcp, FIRST-LAST/tcp
#   --ssh-from CIDR     allow SSH only from these sources (repeat).  Leave it
#                       out if the scoring engine checks SSH
#   --box NAME          splunk | webmail | ecomm | fileshare | gitea | web |
#                       other (asked): that box's scored ports stay open
#                       without asking.  fileshare: 139, 445, 137-138/udp,
#                       2049, 111; gitea: 3000, 2222, 80, 443; web: 80, 443
#   --strict            default every port to DROP except scored ports,
#                       --keep/--allow, SSH and DHCP
#   --restrict-out      also limit OUTGOING traffic to DNS, NTP, HTTP(S),
#                       replies and the admin addresses (stops reverse shells;
#                       can break software that calls out)
#   --no-restrict-out   leave outgoing traffic alone (no question)
#   --keep-ipv6         do not drop IPv6
#   --drop-ipv6         drop IPv6 (no question)
#   --backend NAME      nft or iptables (default: nft when it works)
#   --confirm-timeout N seconds before the automatic rollback (default 120;
#                       0 = no timer: only at a terminal, after an extra yes;
#                       refused with --batch, so nothing can lock you out
#                       without a way back)
#   --save              save the CURRENT bt rules for reboot and exit
#   --remove            remove the bt rules and exit
#                       (both are dry runs without --apply, like every change)
#   --no-color          no colours
#   --batch             no questions: take every default
#   --help              this text plus the common options
#
# OUTPUTS  (under --out, in firewall-N/)
#   output.txt          everything shown on screen, without colour
#   summary.txt         what stays open and why, what is dropped, timer status
#   ports.txt           every listening port: program, account, command, what
#                       it is, and what was decided
#   ruleset.nft / ruleset.iptables.sh   the exact rules
#   rollback.sh         removes the rules (also in the undo log)
#   keep-firewall.sh    run from a NEW session to cancel the rollback timer
#
# WHAT IT CHANGES  (only with --apply / --save / --remove)
#   The live firewall (own table/chains only).  --save also writes
#   /etc/bt-firewall.nft and loads it at boot: an include line in
#   /etc/nftables.conf (Debian, Ubuntu), a small bt-firewall service
#   (systemd without that file: Rocky, Fedora) or /etc/local.d/
#   bt-firewall.start (OpenRC: Alpine); or saves iptables rules with the
#   distribution's tool (rc-service iptables save on Alpine).  With firewalld,
#   --save also makes the ports opened there permanent.
#
# DEPENDS ON
#   nft or iptables (+ ip6tables); ss or netstat for listening ports; /proc
#   for the program behind each port; sshd -T for the SSH port.  BT_NFT,
#   BT_IPTABLES, BT_IP6TABLES, BT_SS and BT_PROC may name stand-ins
#   (the tests use them).
#
# TESTED ON
#   Ubuntu 24.04 (nftables 1.0.9, iptables 1.8.10) under dash, bash, busybox
#   sh, ksh93, mksh and yash with stand-ins, and live: traffic from a separate
#   network namespace reaches allowed ports and is dropped on others; the
#   rollback timer removes the rules when nobody confirms.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - Run it LAST, after the other fixes, and keep a second session open.
#   - A scored service that is down while this runs is not listening, so it
#     is not in the list: open its port with --allow (or the question), or
#     put it on the protected list.
#   - "Scored in past competitions" comes from docs/ENVIRONMENT.md and is a
#     hint, not a fact: check the team packet.
#   - Without root the program behind another account's port cannot be read.
#   - Other firewalls still apply on top: a port this allows can still be
#     blocked by ufw (Ubuntu, Mint) or firewalld (Rocky, Fedora).  When one
#     of them runs, the ports kept here that it would still block are shown
#     and you are asked to open them there too (default yes): firewalld only
#     until its next reload (--save makes it permanent), ufw at once (ufw
#     keeps its rules); both are taken out again by the rollback.
#   - FORWARD (routing) is never touched: routers and Docker keep working.
#
# DEBUGGING
#   --debug shows how every listening port was classified.  The rules are in
#   ruleset.nft / ruleset.iptables.sh; "nft list table inet bt" or
#   "iptables -S BT-IN" shows what is live.  Dropped packets are logged
#   with the prefix "BT-DROP" (journalctl -k | grep BT-DROP).
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

usage() {
    cat <<'USAGE'
LX-25 Linux firewall builder - see every open port, keep or drop each one
  sudo sh LX-25-firewall.sh             look and plan (asks; changes nothing)
  sudo sh LX-25-firewall.sh --apply     ask, then load the rules

  --admin CIDR         your team's address: always allowed in (repeatable)
  --keep SPEC          keep these listening ports open: 80, 80/tcp, 53/udp
  --drop SPEC          drop these listening ports
  --allow SPEC         also open ports not listening now: PORT[/tcp|/udp], FIRST-LAST/tcp
  --ssh-from CIDR      allow SSH only from these sources (repeatable)
  --strict             default to DROP for everything but scored ports, SSH, DHCP
  --restrict-out / --no-restrict-out   limit outgoing traffic, or leave it alone
  --keep-ipv6 / --drop-ipv6            allow or drop IPv6
  --backend nft|iptables
  --confirm-timeout N  seconds before automatic rollback (default 120; 0 = none, terminal only)
  --box NAME           splunk webmail ecomm fileshare gitea web other: its scored ports stay open
  --save               save the current bt rules for reboot, then exit (with --apply)
  --remove             remove the bt rules, then exit (with --apply)
  --no-color           no colours
  --help               show this text

USAGE
    cc_usage_common
}

NL='
'
BOX=""; ALLOW=""; ADMIN=""; SSHFROM=""; STRICT=0; RESTOUT=""; KEEP6=""; BACKEND=""; TIMEOUT=120; DEFTIMEOUT=120; MODE=build
KEEPS=""; DROPS=""; COLOR=1
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --allow)           [ $# -ge 2 ] || cc_die 2 "--allow needs a port"; ALLOW="$ALLOW,$2"; shift 2 ;;
        --keep)            [ $# -ge 2 ] || cc_die 2 "--keep needs a port"; KEEPS="$KEEPS,$2"; shift 2 ;;
        --drop)            [ $# -ge 2 ] || cc_die 2 "--drop needs a port"; DROPS="$DROPS,$2"; shift 2 ;;
        --admin)           [ $# -ge 2 ] || cc_die 2 "--admin needs an address"; ADMIN="$ADMIN$2$NL"; shift 2 ;;
        --ssh-from)        [ $# -ge 2 ] || cc_die 2 "--ssh-from needs an address"; SSHFROM="$SSHFROM$2$NL"; shift 2 ;;
        --strict)          STRICT=1; shift ;;
        --box)             [ $# -ge 2 ] || cc_die 2 "--box needs a name"; BOX=$2; shift 2 ;;
        --restrict-out)    RESTOUT=1; shift ;;
        --no-restrict-out) RESTOUT=0; shift ;;
        --keep-ipv6)       KEEP6=1; shift ;;
        --drop-ipv6)       KEEP6=0; shift ;;
        --backend)         [ $# -ge 2 ] || cc_die 2 "--backend needs nft or iptables"; BACKEND=$2; shift 2 ;;
        --confirm-timeout) [ $# -ge 2 ] || cc_die 2 "--confirm-timeout needs seconds"; TIMEOUT=$2; shift 2 ;;
        --save)            MODE=save; shift ;;
        --remove)          MODE=remove; shift ;;
        --no-color|--no-colour) COLOR=0; shift ;;
        --help|-h)         usage; exit 0 ;;
        *)                 cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
case "$TIMEOUT" in ''|*[!0-9]*) cc_die 2 "--confirm-timeout needs a whole number of seconds" ;; esac
cc_box_valid "$BOX" || cc_die 2 "--box must be one of: $CC_BOXES"
case "$BACKEND" in ''|nft|iptables) ;; *) cc_die 2 "--backend must be nft or iptables" ;; esac
# valid_cidr ADDR -> IPv4 address or network (a.b.c.d or a.b.c.d/n), or IPv6.
valid_cidr() {
    printf '%s' "$1" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]|[12][0-9]|3[0-2]))?$|^[0-9a-fA-F:]+:[0-9a-fA-F:]*(/[0-9]{1,3})?$'
}
for _a in $ADMIN $SSHFROM; do valid_cidr "$_a" || cc_die 2 "not an address or network: $_a"; done
# parse_specs LIST -> "proto|first|last" lines on stdout for "80, 80/tcp,
#   53/udp, 9000-9010/tcp".  Returns 1 (and names the bad one in BADSPEC) on
#   anything that is not a port.
parse_specs() {
    BADSPEC=""
    for _s in $(printf '%s' "$1" | tr ',' ' '); do
        case "$_s" in
            */tcp|*/udp) _p=${_s%/*}; _pr=${_s#*/} ;;
            *) _p=$_s; _pr=both ;;
        esac
        case "$_p" in
            *-*) _f=${_p%-*}; _l=${_p#*-} ;;
            *) _f=$_p; _l=$_p ;;
        esac
        case "$_f$_l" in ''|*[!0-9]*) BADSPEC=$_s; return 1 ;; esac
        { [ "$_f" -ge 1 ] && [ "$_l" -le 65535 ] && [ "$_f" -le "$_l" ]; } || { BADSPEC=$_s; return 1; }
        if [ "$_pr" = both ]; then printf 'tcp|%s|%s\nudp|%s|%s\n' "$_f" "$_l" "$_f" "$_l"; else printf '%s|%s|%s\n' "$_pr" "$_f" "$_l"; fi
    done
    return 0
}
# The $( ) runs parse_specs in a subshell, so BADSPEC is found by running it
# again without one when it fails.
SPECS=$(parse_specs "$ALLOW") || { parse_specs "$ALLOW" >/dev/null; cc_die 2 "--allow: not a port or range (1-65535): $BADSPEC"; }
KEEPSPEC=$(parse_specs "$KEEPS") || { parse_specs "$KEEPS" >/dev/null; cc_die 2 "--keep: not a port or range (1-65535): $BADSPEC"; }
DROPSPEC=$(parse_specs "$DROPS") || { parse_specs "$DROPS" >/dev/null; cc_die 2 "--drop: not a port or range (1-65535): $BADSPEC"; }
# in_spec SPECLINES PROTO PORT -> true when the port is covered.
in_spec() { printf '%s\n' "$1" | awk -F'|' -v pr="$2" -v p="$3" '$1 == pr && p + 0 >= $2 + 0 && p + 0 <= $3 + 0 { f = 1 } END { exit !f }'; }

cc_init "LX-25" "Linux firewall builder" changes
cc_detect_os
[ "$CC_OS_KERNEL" = linux ] || cc_die 3 "this script is for Linux (nftables/iptables); use the BSD or Windows firewall scripts elsewhere"
{ [ "$CC_APPLY" = 1 ] || [ "$MODE" != build ]; } && cc_require_root
cc_use_numbered_dir firewall
# CSV goes in csv/; the run folder gets a readable ports.txt.
CC_CSV_DIR="$CC_RUN_DIR/csv"
mkdir -p "$CC_CSV_DIR" || cc_die 3 "cannot create $CC_CSV_DIR"
W="$CC_RUN_DIR/.work"
mkdir -p "$W" || cc_die 3 "cannot create $W"
cc_color_init
[ "$COLOR" = 1 ] || { C_RED=""; C_YEL=""; C_GRN=""; C_CYN=""; C_GRY=""; C_OFF=""; }
OUTF="$CC_RUN_DIR/output.txt"
grep -v '\[NOTE\]\|\[DEBUG\]' "$CC_LOG" >"$OUTF" 2>/dev/null || : >"$OUTF"
# shellcheck disable=SC2034  # CC_TEE is read by the library's log functions
CC_TEE=$OUTF
header() { cc_show "" ""; cc_show "$C_CYN" "==========[ $1 ]=========="; }

# ---- Tools ---------------------------------------------------------------------
NFT=${BT_NFT:-$(cc_which nft)} || NFT=""
IPT=${BT_IPTABLES:-$(cc_which iptables)} || IPT=""
IP6T=${BT_IP6TABLES:-$(cc_which ip6tables)} || IP6T=""
SS=${BT_SS:-$(cc_which ss)} || SS=""
if [ -z "$BACKEND" ]; then
    if [ -n "$NFT" ] && "$NFT" list tables >/dev/null 2>&1; then BACKEND=nft
    elif [ -n "$IPT" ]; then BACKEND=iptables
    else cc_die 3 "neither nft nor iptables works here"; fi
fi
[ "$BACKEND" = nft ] && [ -z "$NFT" ] && cc_die 3 "nft not found"
[ "$BACKEND" = iptables ] && [ -z "$IPT" ] && cc_die 3 "iptables not found"
cc_debug "backend: $BACKEND nft=$NFT iptables=$IPT ss=$SS"

# Ports this script opened in firewalld (zone|port/proto), for --save.
FWDREC="$CC_OUT/lx25-firewalld-$CC_HOST.txt"
# The commands that remove our rules; used by --remove, the undo log and the timer.
ROLLBACK="$CC_RUN_DIR/rollback.sh"
{
    printf '#!/bin/sh\n# Removes the LX-25 firewall rules made by LX-25. Other rules are not touched.\n'
    if [ "$BACKEND" = nft ]; then
        printf '%s list table inet bt >/dev/null 2>&1 && %s delete table inet bt\n' "$NFT" "$NFT"
    else
        for _t in "$IPT" "$IP6T"; do
            [ -n "$_t" ] || continue
            printf 'while %s -D INPUT -j BT-IN 2>/dev/null; do :; done\n' "$_t"
            printf 'while %s -D OUTPUT -j BT-OUT 2>/dev/null; do :; done\n' "$_t"
            printf '%s -F BT-IN 2>/dev/null; %s -X BT-IN 2>/dev/null\n' "$_t" "$_t"
            printf '%s -F BT-OUT 2>/dev/null; %s -X BT-OUT 2>/dev/null\n' "$_t" "$_t"
        done
    fi
    printf 'echo "LX-25 firewall rules removed"\n'
} >"$ROLLBACK"
chmod 700 "$ROLLBACK"

# ---- --remove and --save ----------------------------------------------------------
if [ "$MODE" = remove ]; then
    cc_run "remove the LX-25 firewall rules" sh "$ROLLBACK"
    cc_finish
fi
if [ "$MODE" = save ]; then
    E=${BT_TEST_ETC:-/etc}   # (the tests point this at a fake /etc)
    _init=${BT_SVC_INIT:-$CC_INIT}
    if [ "$BACKEND" = nft ]; then
        "$NFT" list table inet bt >"$W/live.nft" 2>/dev/null || cc_die 3 "no bt table is live: nothing to save (apply and confirm first)"
        { printf 'table inet bt\ndelete table inet bt\n'; cat "$W/live.nft"; } >"$W/save.nft"
        cc_backup_file "$E/bt-firewall.nft" || cc_die 5 "backup failed"
        cc_run "save the rules to /etc/bt-firewall.nft" cp "$W/save.nft" "$E/bt-firewall.nft"
        if [ -f "$E/nftables.conf" ]; then
            if ! grep -q 'include "/etc/bt-firewall.nft"' "$E/nftables.conf"; then
                cc_backup_file "$E/nftables.conf" || cc_die 5 "backup failed"
                cc_run "load them at boot (include line in /etc/nftables.conf)" sh -c 'printf "\ninclude \"/etc/bt-firewall.nft\"\n" >>"$1"' _ "$E/nftables.conf"
            fi
            [ "$_init" = systemd ] && cc_run "enable the nftables service at boot" systemctl enable nftables
        elif [ "$_init" = openrc ]; then
            # Alpine: OpenRC's "local" service runs /etc/local.d/*.start at boot.
            # (Not the nftables service: its own /etc/nftables.nft would load too.)
            cc_backup_file "$E/local.d/bt-firewall.start" || cc_die 5 "backup failed"
            cc_run "load them at boot (/etc/local.d/bt-firewall.start)" sh -c 'mkdir -p "$1/local.d" && printf "#!/bin/sh\n# LX-25: the bt firewall rules\nnft -f /etc/bt-firewall.nft\n" >"$1/local.d/bt-firewall.start" && chmod 755 "$1/local.d/bt-firewall.start"' _ "$E"
            [ -e "$E/runlevels/default/local" ] || { cc_run "start the local service at boot" rc-update add local default && cc_undo_add "stop running /etc/local.d at boot" "rc-update del local default"; }
            cc_undo_add "do not load the bt rules at boot" "rm -f $(cc_shquote "$E/local.d/bt-firewall.start")"
        elif [ "$_init" = systemd ]; then
            # Rocky, Fedora: no /etc/nftables.conf, and the nftables service must
            # not run next to firewalld; a small service of our own loads the file.
            cc_run "load them at boot (bt-firewall service)" sh -c 'mkdir -p "$1/systemd/system" && printf "[Unit]\nDescription=LX-25 bt firewall rules\nAfter=network-pre.target firewalld.service\nWants=network-pre.target\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=%s -f /etc/bt-firewall.nft\n\n[Install]\nWantedBy=multi-user.target\n" "$2" >"$1/systemd/system/bt-firewall.service" && systemctl daemon-reload && systemctl enable bt-firewall.service' _ "$E" "$NFT"
            cc_undo_add "do not load the bt rules at boot" "systemctl disable bt-firewall.service; rm -f $(cc_shquote "$E/systemd/system/bt-firewall.service"); systemctl daemon-reload"
            cc_relabel "$E/systemd/system/bt-firewall.service" "$E/bt-firewall.nft"
        else
            cc_warn "no /etc/nftables.conf: load /etc/bt-firewall.nft at boot yourself (nft -f /etc/bt-firewall.nft)"
        fi
    else
        if cc_have netfilter-persistent; then cc_run "save iptables rules (netfilter-persistent)" netfilter-persistent save
        elif [ "$_init" = openrc ] && [ -x /etc/init.d/iptables ]; then
            cc_backup_file /etc/iptables/rules-save
            cc_run "save iptables rules (rc-service iptables save)" /etc/init.d/iptables save
            cc_run "restore them at boot" rc-update add iptables default
        elif [ -d /etc/sysconfig ]; then
            cc_backup_file /etc/sysconfig/iptables
            cc_run "save iptables rules to /etc/sysconfig/iptables" sh -c 'iptables-save >/etc/sysconfig/iptables'
        else cc_warn "no iptables save tool found (install iptables-persistent, or add iptables-restore to boot)"; fi
    fi
    # firewalld: the ports this script opened there (runtime only) become permanent
    if [ -s "$FWDREC" ] && cc_have firewall-cmd; then
        while IFS='|' read -r _z _pp; do
            cc_run "open $_pp in firewalld zone $_z for good" firewall-cmd --permanent "--zone=$_z" "--add-port=$_pp" &&
                cc_undo_add "close $_pp in firewalld zone $_z (permanent)" "firewall-cmd --permanent --zone=$(cc_shquote "$_z") --remove-port=$(cc_shquote "$_pp")"
        done <"$FWDREC"
    fi
    cc_finish
fi

cc_show "$C_CYN" "LX-25 Linux firewall | host $CC_HOST | $([ "$CC_APPLY" = 1 ] && echo 'APPLY: rules are loaded after the questions' || echo 'DRY RUN: nothing is changed') | results in $CC_RUN_DIR"
cc_show "" "Legend: ${C_GRN}KEEP${C_OFF} stays open   ${C_RED}DROP${C_OFF} blocked from outside   ${C_YEL}CHECK${C_OFF} find out what it is   ${C_GRY}local${C_OFF} only this box can reach it"

# ---- 1/5  The firewall on this box right now ----------------------------------------
header "1/5  the firewall on this box right now"
cc_show "" "  This script uses: $BACKEND (its own $([ "$BACKEND" = nft ] && echo 'table "inet bt"' || echo 'chains BT-IN / BT-OUT'); other rules are never flushed)"
if [ "$BACKEND" = nft ] && "$NFT" list table inet bt >/dev/null 2>&1; then
    cc_show "$C_YEL" "  LX-25 rules from an earlier run are LIVE now. Applying replaces them."
elif [ "$BACKEND" = iptables ] && "$IPT" -S BT-IN >/dev/null 2>&1 && [ -z "${BT_IPTABLES:-}" ]; then
    cc_show "$C_YEL" "  LX-25 rules from an earlier run are LIVE now. Applying replaces them."
else
    cc_show "$C_GRY" "  No LX-25 rules are loaded yet."
fi
# Other firewalls still apply on top of ours.  (Skipped with stand-in tools,
# unless the test says otherwise.)
UFW=0; FWD=0
if [ -z "${BT_SS:-}" ] || [ -n "${BT_TEST_OTHERFW:-}" ]; then
    if cc_have ufw && ufw status 2>/dev/null | grep -qi '^Status: active'; then UFW=1; cc_show "$C_YEL" "  ufw is ACTIVE: a port kept open here can still be blocked by ufw (the plan says which; you are asked)."; fi
    if cc_have firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then FWD=1; cc_show "$C_YEL" "  firewalld is RUNNING: a port kept open here can still be blocked by it (the plan says which; you are asked)."; fi
    if [ -n "$IPT" ]; then
        _pol=$("$IPT" -S INPUT 2>/dev/null | sed -n 's/^-P INPUT //p'); _nr=$("$IPT" -S INPUT 2>/dev/null | grep -c '^-A')
        [ -n "$_pol" ] && cc_show "$C_GRY" "  iptables INPUT: policy $_pol, $_nr rule(s) already there (left alone)."
    fi
fi

# ---- 2/5  What is listening ----------------------------------------------------------
# $W/listen: "proto|address|port|process|pid"
: >"$W/listen"
if [ -n "$SS" ]; then
    "$SS" -ltnup 2>/dev/null | awk 'NR > 1 && ($1 == "tcp" || $1 == "udp") {
        a = $5; p = a; sub(/.*:/, "", p); sub(/:[^:]*$/, "", a); gsub(/[][]/, "", a); sub(/%.*/, "", a)
        pr = ""; if (match($0, /\(\("[^"]*"/)) pr = substr($0, RSTART + 3, RLENGTH - 4)
        pid = ""; if (match($0, /pid=[0-9]+/)) pid = substr($0, RSTART + 4, RLENGTH - 4)
        print $1 "|" a "|" p "|" pr "|" pid }' >"$W/listen"
elif cc_have netstat; then
    netstat -ltnup 2>/dev/null | awk '$1 ~ /^(tcp|udp)/ {
        pr0 = ($1 ~ /^tcp/) ? "tcp" : "udp"; a = $4; p = a; sub(/.*:/, "", p); sub(/:[^:]*$/, "", a)
        pp = ($1 ~ /^tcp/) ? $7 : $6; pid = pp; sub(/\/.*/, "", pid); sub(/^[0-9]+\//, "", pp); if (pid !~ /^[0-9]+$/) pid = ""
        print pr0 "|" a "|" p "|" pp "|" pid }' >"$W/listen"
else
    cc_warn "no ss or netstat: listening ports unknown, only scored ports and --allow are opened"
fi
# One line per proto/port: where it is bound (all addresses, this box only,
# or named addresses), the program and its pid.
awk -F'|' '
    { k = $1 "|" $3; if (!(k in seen)) { seen[k] = 1; order[++n] = k }
      if ($2 ~ /^127\.|^::1$|^::ffff:127\./) lo[k]++; else { pub[k]++; if ($2 ~ /^(0\.0\.0\.0|\*|::|)$/) all[k] = 1; else addrs[k] = addrs[k] (addrs[k] == "" ? "" : " ") $2 }
      if (proc[k] == "" && $4 != "") proc[k] = $4
      if (pid[k] == "" && $5 != "") pid[k] = $5 }
    END { for (i = 1; i <= n; i++) { k = order[i]; b = (!pub[k]) ? "local" : (all[k] ? "all" : addrs[k]); print k "|" b "|" proc[k] "|" pid[k] } }' "$W/listen" |
    sort -t'|' -k1,1 -k2,2n >"$W/ports0"

# SSH port: what sshd really uses (sshd -T), else what sshd listens on, else 22.
SSHPORTS=""
if _sshd=$(cc_which sshd) && [ -z "${BT_SS:-}" ]; then SSHPORTS=$("$_sshd" -T 2>/dev/null | awk '$1 == "port" { print $2 }' | sort -u | tr '\n' ' ' | sed 's/ *$//'); fi
[ -n "$SSHPORTS" ] || SSHPORTS=$(awk -F'|' '$1 == "tcp" && $4 ~ /^sshd/ { print $3 }' "$W/listen" | sort -u | tr '\n' ' ' | sed 's/ *$//')
[ -n "$SSHPORTS" ] || SSHPORTS=22

# Which box: its scored ports are kept without asking (--box).
if [ -z "$BOX" ]; then
    cc_box_ask o "${R:-}" "Which box is this? (its scored ports stay open)"
fi
case "$BOX" in
    splunk)    BOXPORTS="22/tcp,8000/tcp,8089/tcp,9997/tcp,123/udp" ;;
    webmail)   BOXPORTS="22/tcp,25/tcp,80/tcp,443/tcp,143/tcp,993/tcp,587/tcp" ;;
    ecomm|web) BOXPORTS="80/tcp,443/tcp" ;;
    fileshare) BOXPORTS="139/tcp,445/tcp,137/udp,138/udp,2049,111" ;;
    gitea)     BOXPORTS="3000/tcp,2222/tcp,80/tcp,443/tcp" ;;
    *)         BOXPORTS="" ;;
esac
BOXSPEC=""; [ -n "$BOXPORTS" ] && BOXSPEC=$(parse_specs "$BOXPORTS")

# Scored ports from the protected list: "80", "80/tcp", "53/udp".
PROTSPEC=""
if [ -n "$CC_PROTECTED" ]; then
    _pl=$(awk -F',' '{ gsub(/[ "\r]/, "") } tolower($1) == "port" { print $2 }' "$CC_PROTECTED" | tr '\n' ',')
    PROTSPEC=$(parse_specs "$_pl" 2>/dev/null) || PROTSPEC=""
fi

# port_info PROTO PORT -> what the port normally is.  Sets:
#   PI_NAME   short name                PI_DESC  one plain sentence
#   PI_CLASS  scoredhint | service | data | cleartext | unneeded | backdoor | unknown
# "scoredhint" = a scored service in past competitions (docs/ENVIRONMENT.md).
port_info() {
    PI_CLASS=service
    case "$1/$2" in
        tcp/20|tcp/21) PI_NAME=FTP; PI_DESC="FTP file transfer. Logins and files cross the network in clear text."; PI_CLASS=cleartext ;;
        tcp/22)   PI_NAME=SSH; PI_DESC="SSH: remote login to this box. Scored on the Linux boxes in past competitions."; PI_CLASS=scoredhint ;;
        tcp/23)   PI_NAME=Telnet; PI_DESC="Telnet: remote login in clear text. Almost never needed; SSH replaces it."; PI_CLASS=unneeded ;;
        tcp/25)   PI_NAME=SMTP; PI_DESC="SMTP: receives mail from other servers. Scored on the mail box in past competitions."; PI_CLASS=scoredhint ;;
        tcp/53|udp/53) PI_NAME=DNS; PI_DESC="DNS: answers name lookups. Scored in past competitions; other checks may depend on it."; PI_CLASS=scoredhint ;;
        udp/67)   PI_NAME="DHCP server"; PI_DESC="DHCP server: hands out addresses to other machines. Only needed if this box is the DHCP server." ;;
        udp/68)   PI_NAME="DHCP client"; PI_DESC="DHCP client: how this box gets its own address. Always allowed." ;;
        udp/69)   PI_NAME=TFTP; PI_DESC="TFTP: file transfer with no login at all. Rarely needed."; PI_CLASS=unneeded ;;
        tcp/80)   PI_NAME=HTTP; PI_DESC="HTTP: the web server. Scored (web store, webmail) in past competitions."; PI_CLASS=scoredhint ;;
        tcp/110)  PI_NAME=POP3; PI_DESC="POP3: mail clients fetch mail. Part of the mail service." ;;
        tcp/111|udp/111) PI_NAME=rpcbind; PI_DESC="rpcbind: helper for NFS file sharing. Not needed unless this box shares or mounts NFS."; PI_CLASS=unneeded ;;
        udp/123)  PI_NAME=NTP; PI_DESC="NTP: time server (chrony/ntpd). Scored on the Splunk box in past competitions."; PI_CLASS=scoredhint ;;
        tcp/135)  PI_NAME=RPC; PI_DESC="Windows-style RPC endpoint mapper (Samba). Needed only for Windows file/AD services." ;;
        udp/137|udp/138|tcp/139) PI_NAME=NetBIOS; PI_DESC="NetBIOS: old Windows file-sharing name service (Samba). Needed only if this box shares files with Windows." ;;
        tcp/143)  PI_NAME=IMAP; PI_DESC="IMAP: mail clients read mail. Scored on the mail box in past competitions."; PI_CLASS=scoredhint ;;
        udp/161)  PI_NAME=SNMP; PI_DESC="SNMP: monitoring. Often left with the default password 'public'. Rarely scored."; PI_CLASS=unneeded ;;
        tcp/389|tcp/636) PI_NAME=LDAP; PI_DESC="LDAP: directory / login service. Other boxes may log in through it." ;;
        tcp/443)  PI_NAME=HTTPS; PI_DESC="HTTPS: the web server over TLS. Scored (web store, webmail) in past competitions."; PI_CLASS=scoredhint ;;
        tcp/445)  PI_NAME=SMB; PI_DESC="SMB: Windows file sharing (Samba). Needed only if this box shares files." ;;
        tcp/465|tcp/587) PI_NAME="mail submission"; PI_DESC="Mail submission: mail clients send mail through it. Part of the mail service." ;;
        tcp/512|tcp/513|tcp/514) PI_NAME="rsh/rlogin"; PI_DESC="rexec/rlogin/rsh: remote commands in clear text with weak or no passwords. Not needed."; PI_CLASS=unneeded ;;
        udp/514)  PI_NAME=syslog; PI_DESC="syslog: receives logs from other machines. Needed only if this box is the log server." ;;
        tcp/631|udp/631) PI_NAME=CUPS; PI_DESC="CUPS: printing. Not needed on a server."; PI_CLASS=unneeded ;;
        tcp/993)  PI_NAME=IMAPS; PI_DESC="IMAP over TLS: mail clients read mail. Scored on the mail box in past competitions."; PI_CLASS=scoredhint ;;
        tcp/995)  PI_NAME=POP3S; PI_DESC="POP3 over TLS: mail clients fetch mail. Part of the mail service." ;;
        tcp/1433) PI_NAME="SQL Server"; PI_DESC="Microsoft SQL Server database. Scored on the database box in past competitions."; PI_CLASS=scoredhint ;;
        udp/1900) PI_NAME=UPnP; PI_DESC="UPnP/SSDP device discovery. Not needed on a server."; PI_CLASS=unneeded ;;
        tcp/2049|udp/2049) PI_NAME=NFS; PI_DESC="NFS file sharing. Needed only if other boxes mount folders from this one." ;;
        tcp/2375) PI_NAME="Docker API"; PI_DESC="Docker control port with NO login: anyone who reaches it is root on this box."; PI_CLASS=backdoor ;;
        tcp/3306) PI_NAME=MySQL; PI_DESC="MySQL/MariaDB database. Usually only the web app needs it; if that app is on THIS box, outsiders do not."; PI_CLASS=data ;;
        tcp/3389) PI_NAME=RDP; PI_DESC="Remote desktop (xrdp). Scored on Windows boxes in past competitions; on Linux only if you use it." ;;
        udp/5353) PI_NAME=mDNS; PI_DESC="mDNS (avahi): finds printers and devices on the local network. Not needed on a server."; PI_CLASS=unneeded ;;
        udp/5355|tcp/5355) PI_NAME=LLMNR; PI_DESC="LLMNR local name lookups (systemd-resolved). Not needed on a server."; PI_CLASS=unneeded ;;
        tcp/5432) PI_NAME=PostgreSQL; PI_DESC="PostgreSQL database. Usually only the web app needs it; if that app is on THIS box, outsiders do not."; PI_CLASS=data ;;
        tcp/5900|tcp/5901|tcp/5902) PI_NAME=VNC; PI_DESC="VNC remote desktop, often with a weak password. Rarely needed."; PI_CLASS=unneeded ;;
        tcp/5985|tcp/5986) PI_NAME=WinRM; PI_DESC="WinRM remote management. Scored on the Windows AD box in past competitions." ;;
        tcp/6379) PI_NAME=Redis; PI_DESC="Redis data store, often with no password. Usually only apps on this box need it."; PI_CLASS=data ;;
        tcp/8000) PI_NAME="web / Splunk"; PI_DESC="Web port 8000: the Splunk web page (scored in past competitions) or a development web server."; PI_CLASS=scoredhint ;;
        tcp/8080|tcp/8081|tcp/8443|tcp/8888) PI_NAME="web (alt)"; PI_DESC="An extra web port: an app server, admin panel or proxy. Find out which app before deciding." ;;
        tcp/8089) PI_NAME="Splunk mgmt"; PI_DESC="Splunk management port. Scored on the Splunk box in past competitions."; PI_CLASS=scoredhint ;;
        tcp/9200|tcp/9300) PI_NAME=Elasticsearch; PI_DESC="Elasticsearch, usually with no login. Usually only apps on this box need it."; PI_CLASS=data ;;
        tcp/9997) PI_NAME="Splunk data"; PI_DESC="Splunk receives logs from the forwarders here. The Splunk query check needs that data."; PI_CLASS=scoredhint ;;
        tcp/10000) PI_NAME=Webmin; PI_DESC="Webmin: web admin panel for the whole box. A favourite red-team target."; PI_CLASS=unneeded ;;
        tcp/11211|udp/11211) PI_NAME=memcached; PI_DESC="memcached cache with no login. Usually only apps on this box need it."; PI_CLASS=data ;;
        tcp/27017) PI_NAME=MongoDB; PI_DESC="MongoDB database, often with no login. Usually only apps on this box need it."; PI_CLASS=data ;;
        tcp/1337|tcp/4444|tcp/4445|tcp/5555|tcp/6666|tcp/6667|tcp/12345|tcp/31337|tcp/54321)
                  PI_NAME="backdoor-style"; PI_DESC="Not a normal service port: this number is a favourite for backdoors and reverse-shell listeners."; PI_CLASS=backdoor ;;
        *)        PI_NAME=unknown; PI_DESC="Not a well-known port. Look at the program and command shown with it to see what it is."; PI_CLASS=unknown ;;
    esac
}

# proc_info PID -> PR_USER, PR_CMD (full command line), PR_EXE, from /proc.
PROCROOT=${BT_PROC:-/proc}
proc_info() {
    PR_USER=""; PR_CMD=""; PR_EXE=""
    [ -n "$1" ] && [ -d "$PROCROOT/$1" ] || return 0
    # shellcheck disable=SC2012  # ls: the owner of /proc/PID is the account
    PR_USER=$(ls -ld "$PROCROOT/$1" 2>/dev/null | awk '{ print $3 }')
    PR_CMD=$(tr '\000' ' ' 2>/dev/null <"$PROCROOT/$1/cmdline" | tr '|\n\r\t' '/   ' | sed 's/ *$//' | cut -c1-160)
    PR_EXE=$(readlink "$PROCROOT/$1/exe" 2>/dev/null) || PR_EXE=""
}

header "2/5  open ports: what is listening, and what is behind each one"
# $W/ports: proto|port|bind|proc|pid|user|name|class|default|why|cmd   (default: keep, drop, auto-keep, auto-drop, local)
: >"$W/ports"
_shown=0
while IFS='|' read -r _pr _p _bind _proc _pid; do
    [ -n "$_p" ] || continue
    _shown=$((_shown + 1))
    port_info "$_pr" "$_p"; proc_info "$_pid"
    # Things about the program itself that outweigh the port number.
    _sus=""
    case "$PR_EXE" in *"(deleted)") _sus="its program file was deleted after it started" ;; /tmp/*|/var/tmp/*|/dev/shm/*|/run/shm/*) _sus="it runs from $PR_EXE, a world-writable folder" ;; esac
    case "$_proc" in nc|ncat|netcat|nc.openbsd|nc.traditional|socat) [ -n "$_sus" ] || _sus="a bare $_proc listener is a classic backdoor" ;; esac
    _is_ssh=0; [ "$_pr" = tcp ] && case " $SSHPORTS " in *" $_p "*) _is_ssh=1 ;; esac
    if [ "$_bind" = local ]; then _def=local; _why="only this box can reach it (loopback), so the firewall leaves it alone"
    elif [ "$_pr/$_p" = udp/68 ]; then _def=auto-keep; _why="DHCP replies keep this box's address"
    elif in_spec "$PROTSPEC" "$_pr" "$_p"; then _def=auto-keep; _why="scored: it is on your protected list"
    elif in_spec "$BOXSPEC" "$_pr" "$_p"; then _def=auto-keep; _why="scored on a $BOX box (--box)"
    elif [ "$_is_ssh" = 1 ] && [ -n "$SSHFROM" ]; then _def=auto-keep; _why="SSH, but only from the --ssh-from addresses"
    elif [ "$_is_ssh" = 1 ]; then _def=auto-keep; _why="SSH: how you (and the SSH scoring check) get in"; PI_NAME=SSH; [ "$_p" = 22 ] || PI_DESC="SSH on a non-standard port (from sshd's own config): remote login to this box."
    elif in_spec "$KEEPSPEC" "$_pr" "$_p"; then _def=auto-keep; _why="you said keep (--keep)"
    elif in_spec "$DROPSPEC" "$_pr" "$_p"; then _def=auto-drop; _why="you said drop (--drop)"
    elif in_spec "$SPECS" "$_pr" "$_p"; then _def=auto-keep; _why="you said open it (--allow)"
    elif [ -n "$_sus" ]; then _def=drop; _why="suspicious: $_sus"
    elif [ "$STRICT" = 1 ]; then _def=drop; _why="--strict: not on the protected list"
    else
        case "$PI_CLASS" in
            scoredhint) _def=keep; _why="a scored service in past competitions" ;;
            service)    _def=keep; _why="a normal service; drop it if nothing outside this box uses it" ;;
            data)       _def=keep; _why="kept in case another box's app uses it; DROP it if only this box does" ;;
            cleartext)  _def=keep; _why="clear text, but someone may rely on it; drop it if nobody does" ;;
            unneeded)   _def=drop; _why="rarely needed on a server and often abused" ;;
            backdoor)   _def=drop; _why="investigate the program behind it" ;;
            *)          _def=keep; _why="unknown: kept so nothing scored breaks, but find out what it is" ;;
        esac
    fi
    printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' "$_pr" "$_p" "$_bind" "${_proc:-?}" "$_pid" "$PR_USER" "$PI_NAME" "$PI_CLASS" "$_def" "$_why" "$PR_CMD" >>"$W/ports"
    # The block for this port.
    case "$_bind" in all) _bt="all addresses" ;; local) _bt="this box only" ;; *) _bt="on $_bind" ;; esac
    case "$_def" in
        local)           _c=$C_GRY; _tag="local" ;;
        keep|auto-keep)  _c=$C_GRN; _tag="KEEP "; [ "$PI_CLASS" = unknown ] && [ "$_def" = keep ] && { _c=$C_YEL; _tag="CHECK"; } ;;
        *)               _c=$C_RED; _tag="DROP " ;;
    esac
    cc_show "$_c" "$(printf '  %-5s %-3s %-6s %-15s %-14s %s' "$_tag" "$_pr" "$_p" "$PI_NAME" "$_bt" "${_proc:-?}${_pid:+ (pid $_pid${PR_USER:+, runs as $PR_USER})}")"
    [ -n "$PR_CMD" ] && cc_show "$C_GRY" "        command: $PR_CMD"
    [ -n "$PR_EXE" ] && [ "${PR_CMD%% *}" != "$PR_EXE" ] && cc_show "$C_GRY" "        program: $PR_EXE"
    cc_show "" "        what:    $PI_DESC"
    cc_show "$_c" "        advice:  $_why"
    cc_debug "port $_pr/$_p bind=$_bind class=$PI_CLASS default=$_def"
done <"$W/ports0"
if [ "$_shown" = 0 ]; then cc_show "$C_YEL" "  Nothing is listening (or ss/netstat could not say). Only SSH, scored ports and --allow will be open."; fi
if ! cc_is_root && [ -z "${BT_SS:-}" ]; then cc_show "$C_YEL" "  Not root: programs owned by other accounts show as '?'. Run with sudo to see them."; fi

# ---- 3/5  Questions -------------------------------------------------------------------
header "3/5  questions (Enter takes the answer in capitals)"
# Your team's addresses.
if [ -z "$ADMIN" ] && _cc_can_ask; then
    cc_ask_text "Your team's addresses: they always get in, to every port?" "" "addresses or networks separated by spaces, like 10.0.0.5 10.0.0.0/24"
    for _a in $(printf '%s' "$CC_ANSWER" | tr ',' ' '); do
        valid_cidr "$_a" || cc_die 2 "not an address or network: $_a"
        ADMIN="$ADMIN$_a$NL"
    done
fi
# Keep or drop, port by port.
: >"$W/decided"
while IFS='|' read -r _pr _p _bind _proc _pid _user _name _class _def _why _cmd; do
    case "$_def" in
        local) _dec=local ;;
        auto-keep) _dec=keep ;;
        auto-drop) _dec=drop ;;
        *)
            _d=Y; [ "$_def" = drop ] && _d=N
            # (cc_ask reads the terminal, not this loop's file.)
            if cc_ask "Keep $_pr/$_p open? ($_name, program $_proc${_user:+ as $_user}: $_why)" "$_d" "yes, keep it open" "no, block it"; then _dec=keep; else _dec=drop; fi ;;
    esac
    printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' "$_pr" "$_p" "$_bind" "$_proc" "$_pid" "$_user" "$_name" "$_class" "$_dec" "$_why" "$_cmd" >>"$W/decided"
done <"$W/ports"
# Ports that are not listening now.
if [ -z "$ALLOW" ] && _cc_can_ask; then
    cc_ask_text "Other ports to open that are NOT listening now (e.g. a scored service that is down)?" "" "port/protocol separated by spaces, like 8089/tcp 123/udp"
    SPECS=$(parse_specs "$CC_ANSWER") || { parse_specs "$CC_ANSWER" >/dev/null; cc_die 2 "not a port or range (1-65535): $BADSPEC"; }
fi
# SSH from the team only: only offered when there are team addresses.
if [ -z "$SSHFROM" ] && [ -n "$ADMIN" ] && _cc_can_ask; then
    if cc_ask "Allow SSH ONLY from your team's addresses?" N "yes, ONLY these addresses can SSH in: a teammate from anywhere else is LOCKED OUT, and scoring SSH checks FAIL" "no, SSH stays open to everyone (recommended)"; then SSHFROM=$ADMIN; fi
fi
if [ -z "$RESTOUT" ]; then
    RESTOUT=0
    cc_ask "Also limit OUTGOING traffic to DNS, NTP, web and your team?" N "yes, block the rest (stops reverse shells; can break apps that call out)" "no, leave outgoing open" && RESTOUT=1
fi
if [ -z "$KEEP6" ]; then
    KEEP6=1
    cc_ask "Block IPv6?" Y "yes, block all IPv6 (fine unless something is scored over IPv6)" "no, leave IPv6 as it is" && KEEP6=0
fi

# ---- Decide every port ---------------------------------------------------------------
# $W/allow: "proto|first|last|reason"
: >"$W/allow"; : >"$W/notes"
PCSV=$(cc_csv_new ports "proto,port,bound_to,program,pid,runs_as,what,decision,why,command")
add() { printf '%s|%s|%s|%s\n' "$1" "$2" "$3" "$4" >>"$W/allow"; }
add udp 68 68 "DHCP replies (keeps the address)"
[ "$KEEP6" = 1 ] && add udp 546 546 "DHCPv6 replies"
if [ -z "$SSHFROM" ]; then for _p in $SSHPORTS; do add tcp "$_p" "$_p" "SSH"; done; fi
printf '%s\n' "$PROTSPEC" | while IFS='|' read -r _pr _f _l; do [ -n "$_pr" ] && add "$_pr" "$_f" "$_l" "scored (protected list)"; done
printf '%s\n' "$SPECS" | while IFS='|' read -r _pr _f _l; do [ -n "$_pr" ] && add "$_pr" "$_f" "$_l" "opened by you (not listening now)"; done
NKEEP=0; NDROP=0; NLOCAL=0
while IFS='|' read -r _pr _p _bind _proc _pid _user _name _class _dec _why _cmd; do
    _is_ssh=0; [ "$_pr" = tcp ] && case " $SSHPORTS " in *" $_p "*) _is_ssh=1 ;; esac
    case "$_dec" in
        local) NLOCAL=$((NLOCAL + 1)); _dt="local only" ;;
        keep)
            NKEEP=$((NKEEP + 1)); _dt=KEEP
            if [ "$_is_ssh" = 1 ] && [ -n "$SSHFROM" ]; then _dt="team only"
            elif ! awk -F'|' -v pr="$_pr" -v p="$_p" '$1 == pr && p >= $2 && p <= $3 { f = 1 } END { exit !f }' "$W/allow"; then add "$_pr" "$_p" "$_p" "$_name ($_proc)"; fi ;;
        *)
            NDROP=$((NDROP + 1)); _dt=DROP
            printf '%s/%s  %s, program %s%s: %s\n' "$_pr" "$_p" "$_name" "$_proc" "${_user:+ as $_user}" "$_why" >>"$W/notes" ;;
    esac
    cc_csv_row "$PCSV" "$_pr" "$_p" "$_bind" "$_proc" "$_pid" "$_user" "$_name" "$_dt" "$_why" "$_cmd"
done <"$W/decided"
sort -t'|' -k1,1 -k2,2n -u "$W/allow" | awk -F'|' '!s[$1 "|" $2 "|" $3]++' >"$W/allow.u"
# Opened ports that are not in the listening list get a row too.
while IFS='|' read -r _pr _f _l _why; do
    [ "$_f" = "$_l" ] && grep -q "^$_pr|$_f|" "$W/decided" && continue
    cc_csv_row "$PCSV" "$_pr" "$([ "$_f" = "$_l" ] && echo "$_f" || echo "$_f-$_l")" "" "" "" "" "" KEEP "$_why (nothing is listening on it now)" ""
done <"$W/allow.u"
cc_csv_pretty "$PCSV" "$CC_RUN_DIR/ports.txt" 60
# FTP: the control port alone is not enough.  Passive-mode data connections
# come in on other ports that are not listening yet, so they would be dropped.
FTPNOTE=""
if awk -F'|' '$1 == "tcp" && $2 <= 21 && $3 >= 21 { f = 1 } END { exit !f }' "$W/allow.u" &&
   ! awk -F'|' '$1 == "tcp" && $2 >= 1024 && $3 > $2 { f = 1 } END { exit !f }' "$W/allow.u"; then
    FTPNOTE="FTP (21/tcp) is kept open, but passive-mode data ports are not: file listings and transfers may hang. Set a passive port range in the FTP server and open it, e.g. --allow 40000-40100/tcp"
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
        printf '# Firewall (LX-25) %s - its own table; other tables are untouched.\n' "$CC_HOST"
        printf 'table inet bt\ndelete table inet bt\n'
        printf 'table inet bt {\n'
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
        printf '        limit rate 10/minute log prefix "BT-DROP " level info\n'
        printf '        drop\n    }\n'
        if [ "$RESTOUT" = 1 ]; then
            printf '    chain output {\n        type filter hook output priority 0; policy accept;\n'
            printf '        oif "lo" accept\n        ct state established,related accept\n'
            printf '        meta l4proto { icmp, ipv6-icmp } accept\n'
            printf '        udp dport { 53, 67, 123 } accept\n        tcp dport { 53, 80, 443 } accept\n'
            [ -n "$SRC4" ] && printf '        ip daddr { %s } accept\n' "$(commaset "$SRC4")"
            printf '        limit rate 10/minute log prefix "BT-OUT-DROP " level info\n        drop\n    }\n'
        fi
        printf '}\n'
    } >"$RULES"
else
    RULES="$CC_RUN_DIR/ruleset.iptables.sh"
    {
        printf '#!/bin/sh\n# Firewall (LX-25) %s - its own chains; other chains are untouched.\n' "$CC_HOST"
        printf 'set -e\nT=%s\n' "$IPT"
        printf '$T -N BT-IN 2>/dev/null || $T -F BT-IN\n'
        printf '$T -A BT-IN -i lo -j ACCEPT\n'
        printf '$T -A BT-IN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n'
        printf '$T -A BT-IN -m conntrack --ctstate INVALID -j DROP\n'
        printf '$T -A BT-IN -p icmp -j ACCEPT\n'
        for _s in $SRC4; do printf '$T -A BT-IN -s %s -j ACCEPT\n' "$_s"; done
        if [ -n "$SSHFROM" ]; then for _p in $SSHPORTS; do for _s in $SSH4; do printf '$T -A BT-IN -s %s -p tcp --dport %s -j ACCEPT\n' "$_s" "$_p"; done; done; fi
        awk -F'|' '{ printf "$T -A BT-IN -p %s --dport %s -j ACCEPT\n", $1, ($2 == $3 ? $2 : $2 ":" $3) }' "$W/allow.u"
        printf '$T -A BT-IN -m limit --limit 10/min -j LOG --log-prefix "BT-DROP "\n'
        printf '$T -A BT-IN -j DROP\n'
        printf '$T -C INPUT -j BT-IN 2>/dev/null || $T -I INPUT 1 -j BT-IN\n'
        if [ "$RESTOUT" = 1 ]; then
            printf '$T -N BT-OUT 2>/dev/null || $T -F BT-OUT\n'
            printf '$T -A BT-OUT -o lo -j ACCEPT\n$T -A BT-OUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n$T -A BT-OUT -p icmp -j ACCEPT\n'
            printf '$T -A BT-OUT -p udp -m multiport --dports 53,67,123 -j ACCEPT\n$T -A BT-OUT -p tcp -m multiport --dports 53,80,443 -j ACCEPT\n'
            for _s in $SRC4; do printf '$T -A BT-OUT -d %s -j ACCEPT\n' "$_s"; done
            printf '$T -A BT-OUT -m limit --limit 10/min -j LOG --log-prefix "BT-OUT-DROP "\n$T -A BT-OUT -j DROP\n'
            printf '$T -C OUTPUT -j BT-OUT 2>/dev/null || $T -I OUTPUT 1 -j BT-OUT\n'
        fi
        if [ -n "$IP6T" ]; then
            printf 'T6=%s\n$T6 -N BT-IN 2>/dev/null || $T6 -F BT-IN\n' "$IP6T"
            printf '$T6 -A BT-IN -i lo -j ACCEPT\n$T6 -A BT-IN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n'
            if [ "$KEEP6" = 1 ]; then
                printf '$T6 -A BT-IN -p ipv6-icmp -j ACCEPT\n'
                for _s in $SRC6; do printf '$T6 -A BT-IN -s %s -j ACCEPT\n' "$_s"; done
                awk -F'|' '{ printf "$T6 -A BT-IN -p %s --dport %s -j ACCEPT\n", $1, ($2 == $3 ? $2 : $2 ":" $3) }' "$W/allow.u"
            fi
            printf '$T6 -A BT-IN -j DROP\n$T6 -C INPUT -j BT-IN 2>/dev/null || $T6 -I INPUT 1 -j BT-IN\n'
        fi
    } >"$RULES"
    chmod 700 "$RULES"
fi


# ---- 4/5  The plan ---------------------------------------------------------------------
header "4/5  the plan"
cc_show "$C_GRN" "  Stays open to everyone:"
awk -F'|' '{ printf "    %-4s %-12s %s\n", $1, ($2 == $3 ? $2 : $2 "-" $3), $4 }' "$W/allow.u" >"$W/open.txt"
while IFS= read -r _l; do cc_show "$C_GRN" "$_l"; done <"$W/open.txt"
cc_show "$C_GRN" "    ping (ICMP)       every box has a ping check"
if [ -s "$W/notes" ]; then
    cc_show "$C_RED" "  Dropped from outside (the program keeps running; nothing outside can reach it):"
    while IFS= read -r _l; do cc_show "$C_RED" "    $(printf '%s' "$_l" | cut -c1-200)"; done <"$W/notes"
fi
[ -n "$SOURCES" ] && cc_show "$C_CYN" "  Always allowed in, for everything: $(printf '%s' "$SOURCES" | tr '\n' ' ')"
[ -n "$SOURCES" ] || cc_show "$C_YEL" "  No team addresses given: you get in through SSH like everyone else."
[ -n "$SSHFROM" ] && cc_show "$C_YEL" "  SSH ($SSHPORTS) only from: $(printf '%s' "$SSHFROM" | tr '\n' ' ') - the scoring engine cannot check SSH unless it is one of them"
cc_show "" "  IPv6: $([ "$KEEP6" = 1 ] && echo 'allowed like IPv4' || echo 'dropped')   Outgoing: $([ "$RESTOUT" = 1 ] && echo 'limited to DNS, DHCP, NTP, web, replies and your team' || echo 'not limited')"
[ -n "$FTPNOTE" ] && cc_show "$C_YEL" "  [*] $FTPNOTE"
cc_show "$C_GRY" "  The exact rules: $RULES"

# firewalld / ufw on top: which kept ports would they still block?
# keptports -> "port/proto" for each single kept port (DHCP replies need no opening: they are replies)
keptports() { awk -F'|' '$2 == $3 && !($1 == "udp" && ($2 == 68 || $2 == 546)) { print $2 "/" $1 }' "$W/allow.u"; }
# $W/other: "fwd|zone|port/proto" or "ufw||port/proto"
: >"$W/other"
if [ "$FWD" = 1 ]; then
    # every active zone (an interface's zone), else the default zone
    _zones=$(firewall-cmd --get-active-zones 2>/dev/null | awk '/^[^ \t]/ { print $1 }')
    [ -n "$_zones" ] || _zones=$(firewall-cmd --get-default-zone 2>/dev/null)
    for _z in $_zones; do
        { firewall-cmd --zone="$_z" --list-ports 2>/dev/null | tr ' ' '\n'
          for _sv in $(firewall-cmd --zone="$_z" --list-services 2>/dev/null); do
              firewall-cmd --info-service="$_sv" 2>/dev/null | sed -n 's/^ *ports: *//p' | tr ' ' '\n'
          done; } | grep . >"$W/fwdopen"
        keptports | while IFS= read -r _pp; do
            awk -v pp="$_pp" 'BEGIN { split(pp, a, "/") } { split($0, b, "/"); split(b[1], r, "-"); if (b[2] == a[2] && a[1] + 0 >= r[1] + 0 && a[1] + 0 <= (r[2] == "" ? r[1] : r[2]) + 0) f = 1 } END { exit !f }' "$W/fwdopen" ||
                printf 'fwd|%s|%s\n' "$_z" "$_pp"
        done >>"$W/other"
    done
fi
if [ "$UFW" = 1 ] && ufw status verbose 2>/dev/null | grep -qiE 'Default: *(deny|reject) \(incoming\)'; then
    # "80/tcp  ALLOW IN  Anywhere", "22 (OpenSSH) ...", "8000:8100/tcp ..."
    ufw status verbose 2>/dev/null | awk '/ALLOW( IN)? +Anywhere/ { print $1 }' >"$W/ufwopen"
    keptports | while IFS= read -r _pp; do
        awk -v pp="$_pp" 'BEGIN { split(pp, a, "/") } { split($0, b, "/"); split(b[1], r, ":"); if ((b[2] == "" || b[2] == a[2]) && a[1] + 0 >= r[1] + 0 && a[1] + 0 <= (r[2] == "" ? r[1] : r[2]) + 0) f = 1 } END { exit !f }' "$W/ufwopen" ||
            printf 'ufw||%s\n' "$_pp"
    done >>"$W/other"
fi
OTHERFW=0
if [ -s "$W/other" ]; then
    _fwdl=$(awk -F'|' '$1 == "fwd" { printf "%s%s (zone %s)", (n++ ? ", " : ""), $3, $2 }' "$W/other")
    _ufwl=$(awk -F'|' '$1 == "ufw" { printf "%s%s", (n++ ? ", " : ""), $3 }' "$W/other")
    [ -n "$_fwdl" ] && cc_show "$C_YEL" "  [*] firewalld would still BLOCK these kept ports: $_fwdl"
    [ -n "$_ufwl" ] && cc_show "$C_YEL" "  [*] ufw would still BLOCK these kept ports: $_ufwl"
    cc_ask "Open them in $([ -n "$_fwdl" ] && echo firewalld)$([ -n "$_fwdl" ] && [ -n "$_ufwl" ] && echo ' and ')$([ -n "$_ufwl" ] && echo ufw) too?" Y "yes, open them there too (taken out again by the rollback)" "no, leave that firewall as it is" && OTHERFW=1
fi

# ---- 5/5  Check, apply, start the rollback timer -----------------------------------
header "5/5  apply"
KEEPF="$CC_RUN_DIR/.keep"
# Names the run whose rules are live.  A rollback timer only acts while it
# still names its own run: without this, the timer of an earlier, unconfirmed
# run would later remove the rules of a newer run that WAS confirmed.
CURRENT="$CC_OUT/lx25-live-$CC_HOST"
KEEPSH="$CC_RUN_DIR/keep-firewall.sh"
_state="dry run - nothing changed"
# No rollback timer: only with a person at a terminal who says yes twice.
# Nothing may cut the team off without a way back.
if [ "$CC_APPLY" = 1 ] && [ "$TIMEOUT" -eq 0 ]; then
    if [ "$CC_BATCH" = 1 ] || ! _cc_can_ask; then
        cc_show "$C_YEL" "  [*] --confirm-timeout 0 (no rollback timer) needs a person at a terminal: using ${DEFTIMEOUT}s instead"
        TIMEOUT=$DEFTIMEOUT
    elif ! cc_ask "NO rollback timer: if these rules cut you off, nothing takes them out again. Load them with no timer?" N "yes, no timer (you are at the console)" "no, use a ${DEFTIMEOUT}s rollback timer"; then
        TIMEOUT=$DEFTIMEOUT
    fi
fi
if [ "$BACKEND" = nft ] && ! "$NFT" -c -f "$RULES" >"$W/check" 2>&1; then
    cat "$W/check" >>"$CC_LOG"
    cc_err "nft rejected the ruleset (nothing applied): $(head -n 1 "$W/check")"
    CC_N_FAIL=$((CC_N_FAIL + 1))
    _state="FAILED: nft -c rejected the ruleset (see the log)"
elif [ "$CC_APPLY" = 1 ] && ! cc_ask "Load these rules now?" Y "yes, load them (removed again in ${TIMEOUT}s unless you confirm from a NEW session)" "no, load nothing"; then
    CC_APPLY=0
    _state="not loaded: you said no at the last question"
    cc_show "$C_GRY" "  Not loaded. The plan and rules are in $CC_RUN_DIR"
elif [ "$CC_APPLY" = 1 ]; then
    if [ "$BACKEND" = nft ]; then cc_run "load the firewall rules (nft -f)" "$NFT" -f "$RULES"
    else cc_run "load the firewall rules (iptables)" sh "$RULES"; fi
    _rc=$?
    if [ "$_rc" -ne 0 ]; then
        cc_err "loading the rules failed - removing whatever was loaded"
        sh "$ROLLBACK" >>"$CC_LOG" 2>&1
        _state="FAILED to load; rules removed again"
    else
        cc_undo_add "remove the LX-25 firewall rules" "sh $(cc_shquote "$ROLLBACK")"
        printf '%s\n' "$CC_RUN_DIR" >"$CURRENT"
        if [ "$OTHERFW" = 1 ]; then
            while IFS='|' read -r _k _z _pp; do
                if [ "$_k" = fwd ]; then
                    cc_run "open $_pp in firewalld zone $_z (until its next reload)" firewall-cmd "--zone=$_z" "--add-port=$_pp" || continue
                    printf 'firewall-cmd --zone=%s --remove-port=%s >/dev/null 2>&1\n' "$(cc_shquote "$_z")" "$(cc_shquote "$_pp")" >>"$ROLLBACK"
                    grep -qxF "$_z|$_pp" "$FWDREC" 2>/dev/null || printf '%s|%s\n' "$_z" "$_pp" >>"$FWDREC"
                    grep -qF "$FWDREC" "$ROLLBACK" || printf 'rm -f %s\n' "$(cc_shquote "$FWDREC")" >>"$ROLLBACK"
                else
                    cc_run "open $_pp in ufw" ufw allow "$_pp" || continue
                    printf 'ufw delete allow %s >/dev/null 2>&1\n' "$(cc_shquote "$_pp")" >>"$ROLLBACK"
                fi
            done <"$W/other"
        fi
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
echo "kept: the LX-25 firewall rules stay. To keep them across a reboot run LX-25 with --save."
EOF
            chmod 700 "$CC_RUN_DIR/rollback-timer.sh" "$KEEPSH"
            nohup sh "$CC_RUN_DIR/rollback-timer.sh" >/dev/null 2>&1 &
            echo $! >"$CC_RUN_DIR/.timer.pid"
            _state="LIVE - rollback in ${TIMEOUT}s unless confirmed"
            cc_show "$C_GRN" "  [+] The firewall is LIVE."
            cc_show "$C_YEL" "  [!] It removes itself in ${TIMEOUT}s unless you confirm. Open a NEW ssh session (do not close this one) and run:"
            cc_show "$C_YEL" "          sudo sh $KEEPSH"
            cc_show "$C_YEL" "      If the new session cannot connect, do nothing: the rules go away on their own."
            if _cc_can_ask && [ "${BT_ASSUME_YES:-0}" != 1 ]; then
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
[ "$CC_APPLY" = 1 ] || case "$_state" in "dry run"*) cc_show "$C_GRY" "  Dry run: nothing loaded. Run again with --apply to load these rules." ;; esac

# ---- Summary ------------------------------------------------------------------------
{
    printf 'LX-25 Linux firewall | host %s | %s | %s\n\n' "$CC_HOST" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$([ "$CC_APPLY" = 1 ] && echo APPLIED || echo 'DRY RUN - nothing changed')"
    printf 'State:    %s\n' "$_state"
    printf 'Ports:    %s kept open, %s dropped, %s local only (loopback)\n' "$NKEEP" "$NDROP" "$NLOCAL"
    printf 'Backend:  %s (own %s; nothing else is flushed)\n' "$BACKEND" "$([ "$BACKEND" = nft ] && echo 'table inet bt' || echo 'chains BT-IN/BT-OUT')"
    printf 'IPv6:     %s\n' "$([ "$KEEP6" = 1 ] && echo 'allowed like IPv4' || echo 'dropped (except loopback)')"
    printf 'Outgoing: %s\n' "$([ "$RESTOUT" = 1 ] && echo 'limited to DNS, DHCP, NTP, HTTP(S), replies and admin hosts' || echo 'not limited')"
    printf '\nOpen to everyone:\n'
    cat "$W/open.txt"
    printf '    ping (ICMP)\n'
    [ -n "$SOURCES" ] && printf 'Allowed for everything from: %s\n' "$(printf '%s' "$SOURCES" | tr '\n' ' ')"
    [ -n "$SSHFROM" ] && printf 'SSH (%s) only from: %s\n' "$SSHPORTS" "$(printf '%s' "$SSHFROM" | tr '\n' ' ')"
    if [ -s "$W/notes" ]; then printf '\nDropped from outside:\n'; sed 's/^/    /' "$W/notes" | cut -c1-240; fi
    [ -n "$FTPNOTE" ] && printf '\nNote: %s\n' "$FTPNOTE"
    printf '\nEvery port with its program and command: %s/ports.txt\nRules: %s\n' "$CC_RUN_DIR" "$RULES"
    case "$_state" in
        LIVE*rollback*) printf '\nCONFIRM from a NEW ssh session within %ss, or the rules are removed:\n  sudo sh %s\n' "$TIMEOUT" "$KEEPSH" ;;
    esac
    [ "$CC_APPLY" = 1 ] && printf 'Remove at any time: sudo sh %s\nKeep across reboot (after confirming): run LX-25 again with --save --apply\n' "$ROLLBACK"
    [ "$CC_APPLY" = 1 ] || printf 'Nothing was changed.  Happy with the plan?  Run again with --apply.\n'
    printf 'All results: %s\n' "$CC_RUN_DIR"
} >"$CC_RUN_DIR/summary.txt"
header "SUMMARY"
# On screen the summary is colour-coded; summary.txt and output.txt stay plain.
awk -v R="$C_RED" -v Y="$C_YEL" -v G="$C_GRN" -v C="$C_CYN" -v D="$C_GRY" -v O="$C_OFF" '
    NR == 1                         { print C $0 O; next }
    /^State: +(LIVE|kept)/          { print G $0 O; next }
    /^State: +(FAILED|removed)/     { print R $0 O; next }
    /^State:/                       { print Y $0 O; next }
    /^Open to everyone:/            { m = "o"; print C $0 O; next }
    /^Dropped from outside:/        { m = "d"; print C $0 O; next }
    /^$/                            { m = ""; print; next }
    m == "o"                        { print G $0 O; next }
    m == "d"                        { print R $0 O; next }
    /^CONFIRM|^  sudo sh|^Note:/    { print Y $0 O; next }
    /^(All results|Rules|Every port)/ { print D $0 O; next }
                                    { print }
' "$CC_RUN_DIR/summary.txt"
cat "$CC_RUN_DIR/summary.txt" >>"$OUTF"
rm -rf "$W"
cc_finish
