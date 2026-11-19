#!/bin/sh
# =============================================================================
# ID:       SV-26
# NAME:     Brute-force and spam banning
# ROLE:     Linux  (wave 2)
# KIND:     changes - dry run unless --apply
# VERSION:  2.0.0
#
# PURPOSE
#   Reads the login logs, counts failed logins per source address, and bans
#   an address that passes the limit with a firewall entry that REMOVES
#   ITSELF after the ban time - so a mistake fixes itself.
#     ssh        "Failed password", invalid-user scans, too many auth tries
#     ftp        vsftpd, proftpd, pure-ftpd login failures
#     mail       postfix SASL failures and relay attempts, dovecot (IMAP/POP)
#     web        POSTs to login pages (wp-login.php, xmlrpc.php, Joomla,
#                Drupal, phpMyAdmin, Roundcube, /login) and HTTP 401s, with
#                their own, higher limit
#     pam        any other "authentication failure ... rhost=" line
#   Spam is REPORTED, not banned: a sender mailing more than --mail-max
#   recipients in the window (a compromised mailbox).
#
#   NEVER BANNED: your team and the scoring engine (the question, --ignore,
#   protected hosts), this box's own addresses, loopback, and the default
#   gateway - with NAT every outside client looks like the gateway, and
#   banning it would cut off scoring.  Those are reported instead.
#
#   QUESTIONS (Enter takes the [default]; a flag answers each one ahead):
#     failed logins before a ban            --max-fails N   (10)
#     web login attempts before a ban       --web-max N     (30)
#     ban length in minutes                 --ban-time MIN  (30)
#     services to watch                     --services "ssh mail" (all)
#     addresses never to ban                --ignore / --team ADDR
#     seconds between checks (0 = once)     --loop N / --once   (60)
#   --batch, or no terminal: the defaults, and ONE check.  Answers are saved
#   as the next run's defaults.
#
#   How it counts without parsing log dates: each check reads only the lines
#   added since the last one and stores the counts with the check's time;
#   the window is the sum of the checks in the last --window minutes.  The
#   first check reads the last --history lines.
#
# USAGE
#   sudo sh SV-26-banning.sh                                   asks; dry run
#   sudo sh SV-26-banning.sh --protected p.csv --apply         asks, then bans
#   sudo sh SV-26-banning.sh --protected p.csv --apply --batch --loop 60 --team 10.0.0.0/24
#   sudo sh SV-26-banning.sh --list                            current bans
#   sudo sh SV-26-banning.sh --apply --unban 10.6.6.6
#   sudo sh SV-26-banning.sh --apply --unban-all               lift every ban now
#
# OPTIONS
#   --max-fails N    failures in the window that earn a ban (default 10)
#   --web-max N      web login attempts that earn a ban (default 30)
#   --window MIN     counting window in minutes (default 10)
#   --ban-time MIN   ban length in minutes (default 30)
#   --services LIST  only these: ssh ftp mail web pam (default all)
#   --mail-max N     recipients per sender in the window before a spam
#                    warning (default 200)
#   --ignore ADDR    never ban this address or network (repeat; --team too)
#   --log FILE       read this log (repeat).  When given, ONLY these logs are
#                    read, not the usual ones or the journal
#   --history N      lines read from each log on the first check (default 2000)
#   --loop N         check every N seconds (at least 10) until Ctrl-C
#   --once           check once
#   --count N        with --loop: stop after N checks
#   --backend NAME   nft, ipset or iptables (default: nft, else ipset, else
#                    iptables)
#   --list           show the current bans and exit
#   --unban IP       remove one ban and exit (with --apply)
#   --unban-all      remove every ban and the ban table (with --apply)
#   --state DIR      where offsets, counts and the ban history live
#                    (default <out>/ban-<host>)
#   --no-color       no colours
#   --help           this text plus the common options
#
# OUTPUTS
#   <out>/banning-N/       this run:
#     output.txt         everything shown on screen, no colour
#     bans.txt           bans made (or that would be made) this run
#     offenders.txt      every address with failures, per check, and why it
#                        was or was not banned (csv/ has both as CSV)
#     summary.txt, run.txt
#   <out>/ban-<host>/      kept between runs:
#     bans.csv           every ban ever: time,address,services,failures,
#                        accounts_tried,until,action
#     events.log         one line per check
#     hits, offsets      counts for the window, how far each log was read
#     settings           your answers, used as the next defaults
#
# WHAT IT CHANGES  (only with --apply)
#   nftables: table "inet bt_ban" (two address sets with timeouts and one
#   drop rule).  ipset: set "bt_ban" plus one iptables rule.  iptables
#   alone: one DROP rule per banned address, removed by a later check when
#   the ban ends.  --unban-all (or the undo log) removes it all.  No other
#   rule is touched.  There is no revert timer: every ban already ends by
#   itself, and the never-ban list keeps your team and scoring safe.
#
# DEPENDS ON
#   awk, tail, wc; nft or ipset+iptables or iptables; journalctl when the
#   SSH log is only in the journal.  BT_NFT, BT_IPSET and BT_IPTABLES
#   may name stand-ins (the tests use them).
#
# TESTED ON
#   Ubuntu 24.04 under dash, bash, busybox sh, ksh93, mksh and yash with
#   gawk, mawk and busybox awk, sample logs and stand-in firewalls; live:
#   real failed SSH logins from a separate network namespace got that
#   address banned in nftables, and the ban expired by itself.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - A red team with many addresses is slowed, not stopped.
#   - The scoring engine fails logins too (after a password change): give
#     its address to the never-ban question or the protected list.
#   - Log formats differ between versions; a service whose failures are not
#     counted shows nothing, not an error.  Check with --log and --debug.
#
# DEBUGGING
#   --debug shows each log read and the counts per address.  events.log has
#   one line per check.  "nft list table inet bt_ban" shows the bans.
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
SV-26 Brute-force and spam banning - timed bans for addresses that keep failing logins
  sudo sh SV-26-banning.sh                       asks; dry run
  sudo sh SV-26-banning.sh --protected p.csv --apply    asks, then bans

  --max-fails N    failures that earn a ban (default 10)
  --web-max N      web login attempts that earn a ban (default 30)
  --ban-time MIN   ban length (default 30)
  --window MIN     counting window (default 10)
  --services LIST  only these: ssh ftp mail web pam (default all)
  --ignore ADDR    never ban this address/network (repeatable; --team too)
  --mail-max N     recipients per sender before a spam warning (default 200)
  --log FILE       read only these logs (repeatable)
  --history N      lines read per log on the first check (default 2000)
  --loop N         check every N seconds; --once; --count N stops after N
  --backend nft|ipset|iptables
  --list           show current bans
  --unban IP       remove a ban (with --apply)
  --unban-all      remove every ban (with --apply)
  --state DIR      state folder
  --no-color       no colours
  --help           show this text

USAGE
    cc_usage_common
}

NL='
'
MAXF=""; WEBMAX=""; WINDOW=10; BANTIME=""; MAILMAX=200; IGNORE=""; IGNSET=0; LOGS=""; HIST=2000
LOOP=""; COUNT=0; BACKEND=""; MODE=run; UNBAN=""; STATE=""; SERVICES=""; COLOR=1
num() { case "$2" in ''|*[!0-9]*) cc_die 2 "$1 needs a whole number" ;; esac; }
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --max-fails) num "$1" "${2:-}"; MAXF=$2; shift 2 ;;
        --web-max)   num "$1" "${2:-}"; WEBMAX=$2; shift 2 ;;
        --window)    num "$1" "${2:-}"; WINDOW=$2; shift 2 ;;
        --ban-time)  num "$1" "${2:-}"; BANTIME=$2; shift 2 ;;
        --mail-max)  num "$1" "${2:-}"; MAILMAX=$2; shift 2 ;;
        --history)   num "$1" "${2:-}"; HIST=$2; shift 2 ;;
        --loop)      num "$1" "${2:-}"; LOOP=$2; shift 2 ;;
        --once)      LOOP=0; shift ;;
        --count)     num "$1" "${2:-}"; COUNT=$2; shift 2 ;;
        --services)  [ $# -ge 2 ] || cc_die 2 "--services needs a list"; SERVICES=$2; shift 2 ;;
        --ignore|--team) [ $# -ge 2 ] || cc_die 2 "$1 needs an address"
                     IGNORE="$IGNORE$(printf '%s' "$2" | tr ', ' '\n\n')$NL"; IGNSET=1; shift 2 ;;
        --log)       [ $# -ge 2 ] || cc_die 2 "--log needs a file"; [ -r "$2" ] || cc_die 2 "--log: cannot read $2"; LOGS="$LOGS$(cc_abspath "$2")$NL"; shift 2 ;;
        --backend)   [ $# -ge 2 ] || cc_die 2 "--backend needs a name"; BACKEND=$2; shift 2 ;;
        --list)      MODE=list; shift ;;
        --unban)     [ $# -ge 2 ] || cc_die 2 "--unban needs an address"; MODE=unban; UNBAN=$2; shift 2 ;;
        --unban-all) MODE=unbanall; shift ;;
        --state)     [ $# -ge 2 ] || cc_die 2 "--state needs a folder"; STATE=$2; shift 2 ;;
        --no-color|--no-colour) COLOR=0; shift ;;
        --help|-h)   usage; exit 0 ;;
        *)           cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
case "$BACKEND" in ''|nft|ipset|iptables) ;; *) cc_die 2 "--backend must be nft, ipset or iptables" ;; esac
# ok_loop N -> exits 2 unless N is 0 or 10 or more.
ok_loop() { num "--loop" "$1"; [ "$1" -gt 0 ] && [ "$1" -lt 10 ] && cc_die 2 "--loop must be at least 10 seconds (or 0 for one check)"; return 0; }
[ -n "$LOOP" ] && ok_loop "$LOOP"
# ok_limits -> every limit is a whole number of at least 1.
ok_limits() {
    for _v in "$MAXF" "$WEBMAX" "$WINDOW" "$BANTIME"; do
        [ -z "$_v" ] && continue
        num "a limit" "$_v"; [ "$_v" -ge 1 ] || cc_die 2 "limits, window and ban time must be at least 1"
    done
}
ok_limits
# ok_services LIST -> exits 2 on an unknown service name.
ok_services() {
    for _s in $(printf '%s' "$1" | tr ',' ' '); do
        case "$_s" in ssh|ftp|mail|web|pam|all) ;; *) cc_die 2 "unknown service: $_s (use ssh ftp mail web pam or all)" ;; esac
    done
}
[ -n "$SERVICES" ] && ok_services "$SERVICES"
# valid_addr A -> IPv4 address or network with every part 0-255 and a
# prefix 0-32, or an IPv6 address.
valid_addr() {
    printf '%s\n' "$1" | awk '/^[0-9a-fA-F]*:[0-9a-fA-F:]*$/ { exit 0 }
        { n = split($0, x, "/"); if (n > 2 || (n == 2 && (x[2] !~ /^[0-9]+$/ || x[2] > 32))) exit 1
          if (split(x[1], o, ".") != 4) exit 1
          for (i = 1; i <= 4; i++) if (o[i] !~ /^[0-9]+$/ || o[i] > 255) exit 1 }'
}
for _a in $IGNORE; do valid_addr "$_a" || cc_die 2 "--ignore: not an address or network: $_a"; done

cc_init "SV-26" "Brute-force and spam banning" changes
cc_detect_os
# shellcheck disable=SC2034  # read by cc_color_init
[ "$COLOR" = 1 ] || CC_NOCOLOR=1
cc_color_init
[ "$CC_APPLY" = 1 ] && cc_require_root
[ -n "$STATE" ] || STATE="$CC_OUT/ban-$CC_HOST"
(umask 077; mkdir -p "$STATE") || cc_die 3 "cannot create $STATE"
STATE=$(cc_abspath "$STATE")
BANS="$STATE/bans.csv"
[ -f "$BANS" ] || printf 'time,address,services,failures,accounts_tried,until,action\n' >"$BANS"
header() { cc_show "" ""; cc_show "$C_CYN" "==========[ $1 ]=========="; }
setting() { [ -f "$STATE/settings" ] && sed -n "s/^$1=//p" "$STATE/settings" | tail -n 1; }

# now -> seconds since 1970 (date +%s where it works, else awk's srand trick).
now() { _t=$(date +%s 2>/dev/null); case "$_t" in ''|*[!0-9]*) awk 'BEGIN { srand(); print srand() }' ;; *) printf '%s\n' "$_t" ;; esac; }

# ---- Firewall backend --------------------------------------------------------
NFT=${BT_NFT:-$(cc_which nft)} || NFT=""
IPSET=${BT_IPSET:-$(cc_which ipset)} || IPSET=""
IPT=${BT_IPTABLES:-$(cc_which iptables)} || IPT=""
if [ -z "$BACKEND" ]; then
    if [ -n "$NFT" ] && "$NFT" list tables >/dev/null 2>&1; then BACKEND=nft
    elif [ -n "$IPSET" ] && [ -n "$IPT" ]; then BACKEND=ipset
    elif [ -n "$IPT" ]; then BACKEND=iptables
    else cc_die 3 "no firewall tool found (nft, ipset or iptables)"; fi
fi
cc_debug "backend: $BACKEND"

# fw_setup -> create the ban table/set once (keeps bans across runs).
_fw_ready=0
fw_setup() {
    [ "$_fw_ready" = 1 ] && return 0
    case "$BACKEND" in
        nft)
            if ! "$NFT" list table inet bt_ban >/dev/null 2>&1; then
                cat >"$W/ban.nft" <<'EOF'
table inet bt_ban {
    set ban4 { type ipv4_addr; flags timeout; }
    set ban6 { type ipv6_addr; flags timeout; }
    chain input {
        type filter hook input priority -5; policy accept;
        ip saddr @ban4 drop
        ip6 saddr @ban6 drop
    }
}
EOF
                cc_run "create the ban table (nft table inet bt_ban)" "$NFT" -f "$W/ban.nft" || return 1
                cc_undo_add "remove all SV-26 bans" "$NFT delete table inet bt_ban"
            fi ;;
        ipset)
            if ! "$IPSET" list bt_ban >/dev/null 2>&1; then
                cc_run "create the ban set (ipset bt_ban)" "$IPSET" create bt_ban hash:ip timeout 0 -exist || return 1
                cc_undo_add "remove all SV-26 bans" "$IPT -D INPUT -m set --match-set bt_ban src -j DROP; $IPSET destroy bt_ban"
            fi
            "$IPT" -C INPUT -m set --match-set bt_ban src -j DROP 2>/dev/null ||
                cc_run "drop traffic from banned addresses" "$IPT" -I INPUT 1 -m set --match-set bt_ban src -j DROP || return 1 ;;
        iptables) : ;;
    esac
    _fw_ready=1
}
# fw_ban IP SECONDS
fw_ban() {
    case "$BACKEND" in
        nft) case "$1" in *:*) _set=ban6 ;; *) _set=ban4 ;; esac
             cc_run "ban $1 for $(($2 / 60)) min" "$NFT" add element inet bt_ban "$_set" "{ $1 timeout ${2}s }" ;;
        ipset) cc_run "ban $1 for $(($2 / 60)) min" "$IPSET" add bt_ban "$1" timeout "$2" -exist ;;
        iptables) cc_run "ban $1 for $(($2 / 60)) min" "$IPT" -I INPUT 1 -s "$1" -j DROP -m comment --comment bt_ban
                  _rc=$?; [ "$_rc" -eq 0 ] && cc_undo_add "unban $1" "$IPT -D INPUT -s $1 -j DROP -m comment --comment bt_ban"; return "$_rc" ;;
    esac
}
fw_unban() {
    case "$BACKEND" in
        nft) case "$1" in *:*) _set=ban6 ;; *) _set=ban4 ;; esac
             cc_run "unban $1" "$NFT" delete element inet bt_ban "$_set" "{ $1 }" ;;
        ipset) cc_run "unban $1" "$IPSET" del bt_ban "$1" ;;
        iptables) cc_run "unban $1" "$IPT" -D INPUT -s "$1" -j DROP -m comment --comment bt_ban ;;
    esac
}
# fw_list -> currently banned addresses, one per line.
fw_list() {
    case "$BACKEND" in
        nft) "$NFT" list table inet bt_ban 2>/dev/null | awk '/elements = \{/ { s = 1 } s { gsub(/elements = \{|[{},]/, " "); for (i = 1; i <= NF; i++) if ($i ~ /^[0-9a-fA-F.:]+$/ && $i ~ /[.:]/ && $(i - 1) != "timeout" && $(i - 1) != "expires") print $i } /\}/ { s = 0 }' ;;
        ipset) "$IPSET" list bt_ban 2>/dev/null | awk '/^Members:/ { s = 1; next } s && NF { print $1 }' ;;
        iptables) "$IPT" -S INPUT 2>/dev/null | awk '/bt_ban/ && /-s / { for (i = 1; i <= NF; i++) if ($i == "-s") { a = $(i + 1); sub(/\/32$/, "", a); print a } }' ;;
    esac
}

# ---- --list, --unban, --unban-all -------------------------------------------------
if [ "$MODE" != run ]; then
    W="$STATE/.work"; mkdir -p "$W"
    case "$MODE" in
        list)
            cc_show "$C_CYN" "Banned now ($BACKEND):"
            fw_list >"$W/now"
            if [ -s "$W/now" ]; then
                while IFS= read -r _a; do
                    _why=$(awk -F, -v a="$_a" '$2 == a && $7 == "banned" { w = $3 ", " $4 " failures at " $1 } END { print w }' "$BANS")
                    cc_show "$C_RED" "  [!] $(printf '%-39s' "$_a") ${_why:-}"
                done <"$W/now"
            else
                cc_show "$C_GRN" "  [ok] nobody"
            fi
            cc_show "" "History: $BANS" ;;
        unban)
            valid_addr "$UNBAN" || cc_die 2 "--unban: not an address: $UNBAN"
            fw_unban "$UNBAN"
            [ "$CC_APPLY" = 1 ] && printf '%s,%s,,,,,unbanned by hand\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$UNBAN" >>"$BANS" ;;
        unbanall)
            fw_list >"$W/now"
            cc_show "" "Lifting $(grep -c . "$W/now") ban(s):"
            case "$BACKEND" in
                nft) "$NFT" list table inet bt_ban >/dev/null 2>&1 && cc_run "remove the ban table (nft table inet bt_ban)" "$NFT" delete table inet bt_ban ;;
                ipset) "$IPT" -C INPUT -m set --match-set bt_ban src -j DROP 2>/dev/null &&
                           cc_run "remove the ban rule" "$IPT" -D INPUT -m set --match-set bt_ban src -j DROP
                       "$IPSET" list bt_ban >/dev/null 2>&1 && cc_run "remove the ban set" "$IPSET" destroy bt_ban ;;
                iptables) while IFS= read -r _a; do fw_unban "$_a"; done <"$W/now"
                          [ "$CC_APPLY" = 1 ] && rm -f "$STATE/iptables-expiry" ;;
            esac
            [ "$CC_APPLY" = 1 ] && printf '%s,ALL,,,,,unbanned by hand (--unban-all)\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$BANS" ;;
    esac
    [ "$CC_APPLY" = 1 ] || [ "$MODE" = list ] || cc_show "$C_YEL" "Dry run: nothing changed. Add --apply."
    rm -rf "$W"
    cc_finish
fi

cc_use_numbered_dir banning
CC_CSV_DIR="$CC_RUN_DIR/csv"
mkdir -p "$CC_CSV_DIR" || cc_die 3 "cannot create $CC_CSV_DIR"
rmdir "$CC_RUN_DIR/raw" 2>/dev/null
OUTF="$CC_RUN_DIR/output.txt"; : >"$OUTF"
# shellcheck disable=SC2034  # CC_TEE is read by the library's log functions
CC_TEE=$OUTF
W="$CC_RUN_DIR/.work"; mkdir -p "$W"

cc_show "$C_CYN" "SV-26 Banning | host $CC_HOST | results in $CC_RUN_DIR"
cc_show "$C_CYN" "Ban history and counts in $STATE"
if [ "$CC_APPLY" = 1 ]; then
    cc_show "$C_RED" "Mode: BANNING - addresses over the limit are blocked in the firewall (each ban ends by itself)"
else
    cc_show "$C_YEL" "Mode: DRY RUN - shows who WOULD be banned, blocks nothing. Add --apply to ban."
fi
cc_show "" "Legend: ${C_RED}[!]${C_OFF} banned   ${C_YEL}[*]${C_OFF} would ban / check this   ${C_GRY}[-]${C_OFF} watching   ${C_GRN}[ok]${C_OFF} quiet"

# ---- 1/4 Questions -------------------------------------------------------------------
header "1/4  setup: limits and who never to ban"
if [ -z "$MAXF" ]; then
    cc_ask_text "How many failed logins (SSH, FTP, mail) in $WINDOW minutes before a ban?" "$(setting maxfails | grep . || echo 10)" "a number, like 10"; MAXF=$CC_ANSWER
fi
if [ -z "$WEBMAX" ]; then
    cc_ask_text "How many web login attempts in $WINDOW minutes before a ban? (real users log in once)" "$(setting webmax | grep . || echo 30)" "a number, like 30"; WEBMAX=$CC_ANSWER
fi
if [ -z "$BANTIME" ]; then
    cc_ask_text "How long is a ban? (it ends by itself)" "$(setting bantime | grep . || echo 30)" "minutes, like 30"; BANTIME=$CC_ANSWER
fi
ok_limits
if [ -z "$SERVICES" ]; then
    cc_ask_text "Which services to watch?" "$(setting services | grep . || echo all)" "names separated by spaces from: ssh ftp mail web pam - or all"
    SERVICES=$CC_ANSWER; ok_services "$SERVICES"
fi
SERVICES=$(printf '%s' "$SERVICES" | tr ',' ' ' | sed 's/^ *//; s/ *$//'); [ -n "$SERVICES" ] || SERVICES=all
case " $SERVICES " in *" all "*) SERVICES=all ;; esac
if [ "$IGNSET" = 0 ]; then
    cc_ask_text "Addresses never to ban: your team and the scoring engine?" "$(setting never)" "addresses or networks separated by spaces, like 10.0.0.5 10.0.0.0/24"
    IGNORE=$(printf '%s' "$CC_ANSWER" | tr ', ' '\n\n')
    for _a in $IGNORE; do valid_addr "$_a" || cc_die 2 "not an address or network: $_a"; done
fi
if [ -z "$LOOP" ]; then
    if _cc_can_ask; then cc_ask_text "How often should it check?" 60 "seconds between checks, like 60; 0 = check once and stop"; LOOP=$CC_ANSWER; ok_loop "$LOOP"
    else LOOP=0; fi
fi
printf 'maxfails=%s\nwebmax=%s\nbantime=%s\nservices=%s\nnever=%s\n' "$MAXF" "$WEBMAX" "$BANTIME" "$SERVICES" "$(printf '%s' "$IGNORE" | grep . | tr '\n' ' ' | sed 's/ $//')" >"$STATE/settings"
cc_show "" ""
cc_show "" "  Ban after:    $MAXF failed logins, or $WEBMAX web login attempts, in $WINDOW minutes"
cc_show "" "  Ban length:   $BANTIME minutes"
cc_show "" "  Services:     $SERVICES"
cc_show "" "  Checks:       $([ "$LOOP" -gt 0 ] && echo "every $LOOP seconds$([ "$COUNT" -gt 0 ] && echo ", $COUNT times") (Ctrl-C stops and prints the summary)" || echo once)"

# ---- 2/4 What it reads -------------------------------------------------------------
header "2/4  logs, firewall and the never-ban list"
# Never banned: team/--ignore, loopback, protected hosts, own addresses, gateways.
{
    printf '%s\n' "$IGNORE" | grep . | sed 's/$/ team/'
    printf '127.0.0.0/8 loopback\n::1 loopback\n'
    if [ -n "$CC_PROTECTED" ]; then awk -F',' '{ gsub(/[ "\r]/, "") } tolower($1) == "host" { print $2 " protected" }' "$CC_PROTECTED"; fi
    if cc_have ip; then
        ip -o addr 2>/dev/null | awk '{ a = $4; sub(/\/.*/, "", a); print a " own" }'
        ip route 2>/dev/null | awk '$1 == "default" { for (i = 1; i <= NF; i++) if ($i == "via") print $(i + 1) " gateway" }'
    fi
} | grep . | awk '!seen[$1]++' >"$W/never"
cc_debug "never banned: $(tr '\n' ' ' <"$W/never")"
# AWK_NEVER: never(ip) is 1 when ip matches a line of the never-ban file
# (exact, or inside an IPv4 network).  NV is the entry that matched, why[NV]
# the reason (team, loopback, protected, own, gateway).
AWK_NEVER='
function ip2n(a,   p) { if (split(a, p, ".") != 4) return -1; return ((p[1] * 256 + p[2]) * 256 + p[3]) * 256 + p[4] }  # awk, not shell: posix-ok
function loadnever(f,   l, n, x) { while ((getline l < f) > 0) { split(l, x, " "); nv[++nn] = x[1]; why[x[1]] = x[2] } }  # awk, not shell: posix-ok
function never(ip,   i, j, net, bits, base, size) {  # awk, not shell: posix-ok
    for (i = 1; i <= nn; i++) {
        if (nv[i] == ip) { NV = nv[i]; return 1 }
        if (index(nv[i], "/") && ip !~ /:/) {
            # 2 to the power (32 - bits) by multiplying: some busybox awks
            # are built without math support, so "^" is not available.
            split(nv[i], net, "/"); bits = net[2] + 0; base = ip2n(net[1]); size = 1
            for (j = bits; j < 32; j++) size = size * 2
            if (base >= 0 && ip2n(ip) >= int(base / size) * size && ip2n(ip) < int(base / size) * size + size) { NV = nv[i]; return 1 }
        }
    }
    return 0
}'

if [ -n "$LOGS" ]; then
    printf '%s' "$LOGS" | grep . >"$W/logs"
    USEJOURNAL=0
else
    : >"$W/logs"
    for _f in /var/log/auth.log /var/log/secure /var/log/vsftpd.log /var/log/proftpd/proftpd.log /var/log/pure-ftpd/pure-ftpd.log \
              /var/log/mail.log /var/log/maillog /var/log/apache2/access.log /var/log/apache2/other_vhosts_access.log \
              /var/log/httpd/access_log /var/log/httpd/ssl_access_log /var/log/nginx/access.log; do
        [ -f "$_f" ] && [ -r "$_f" ] && printf '%s\n' "$_f" >>"$W/logs"
    done
    for _f in /var/log/apache2/*access*.log /var/log/nginx/*access*.log; do
        [ -f "$_f" ] && ! grep -qxF "$_f" "$W/logs" && printf '%s\n' "$_f" >>"$W/logs"
    done
    # The journal holds SSH and mail logs when there is no syslog file.
    USEJOURNAL=0
    if cc_have journalctl && [ ! -s /var/log/auth.log ] && [ ! -s /var/log/secure ]; then USEJOURNAL=1; fi
fi
# what_log FILE -> what that log tells us, in words.
what_log() {
    case "$1" in
        *auth.log|*secure) echo "SSH, PAM logins" ;;
        *vsftpd*|*proftpd*|*pure-ftpd*) echo "FTP logins" ;;
        *mail.log|*maillog) echo "SMTP and IMAP/POP logins, mail volume" ;;
        *access*) echo "web login pages" ;;
        *) echo "read for every kind of failure" ;;
    esac
}
cc_show "" "  Logs read:"
while IFS= read -r _f; do cc_show "" "    $_f  ($(what_log "$_f"))"; done <"$W/logs"
[ "$USEJOURNAL" = 1 ] && cc_show "" "    the systemd journal  (SSH, FTP and mail: no auth.log on this box)"
[ -s "$W/logs" ] || [ "$USEJOURNAL" = 1 ] || cc_show "$C_YEL" "    [!] no login logs found - nothing can be counted (use --log FILE)"
cc_show "" "  Firewall:     $BACKEND$([ "$BACKEND" = nft ] && echo ' (table inet bt_ban, entries time out by themselves)')"
cc_show "" "  Never banned:"
while read -r _a _why; do
    case "$_why" in
        team) _w="your team / scoring (your answer)" ;; protected) _w="protected list" ;; own) _w="this box" ;;
        gateway) _w="default gateway - with NAT every outside client looks like it" ;; *) _w=$_why ;;
    esac
    cc_show "" "    $(printf '%-24s' "$_a") $_w"
done <"$W/never"
grep -q ' team$\| protected$' "$W/never" || cc_show "$C_YEL" "    [!] no team or scoring address given: the scoring engine can be banned after a password change"

# ---- Reading new log lines ----------------------------------------------------------
# Dry runs keep their counts in the run folder, so a dry loop reads each
# line once but the real state is never touched.
if [ "$CC_APPLY" = 1 ]; then DS=$STATE; else DS="$W/dry"; mkdir -p "$DS"; cp "$STATE/offsets" "$STATE/hits" "$DS/" 2>/dev/null; fi
[ -f "$DS/offsets" ] || : >"$DS/offsets"
: >"$W/wouldban"
# read_new -> every line added since the last run, from every log, on stdout.
#   Offsets are only saved when changes are applied, so dry runs can repeat.
read_new() {
    : >"$W/offsets.new"
    while IFS= read -r _f; do
        _size=$(wc -c 2>/dev/null <"$_f" | tr -d ' ')
        _off=$(awk -F'\t' -v f="$_f" '$1 == f { print $2 }' "$DS/offsets")
        if [ -z "$_off" ]; then
            tail -n "$HIST" "$_f" 2>/dev/null
        elif [ "$_size" -lt "$_off" ]; then
            cat "$_f"           # rotated or truncated: start again
        elif [ "$_size" -gt "$_off" ]; then
            tail -c +"$((_off + 1))" "$_f" 2>/dev/null
        fi
        printf '%s\t%s\n' "$_f" "$_size" >>"$W/offsets.new"
    done <"$W/logs"
    if [ "$USEJOURNAL" = 1 ]; then
        _since=$(awk -F'\t' '$1 == "journal" { print $2 }' "$DS/offsets")
        if [ -n "$_since" ]; then
            journalctl -q --no-pager -o short --since "$_since" -t sshd -t sshd-session -t postfix/smtpd -t postfix/qmgr -t dovecot -t vsftpd -t proftpd -t pure-ftpd 2>/dev/null
        else
            journalctl -q --no-pager -o short -n "$HIST" -t sshd -t sshd-session -t postfix/smtpd -t postfix/qmgr -t dovecot -t vsftpd -t proftpd -t pure-ftpd 2>/dev/null
        fi
        printf 'journal\t%s\n' "$(date '+%Y-%m-%d %H:%M:%S')" >>"$W/offsets.new"
    fi
}

# PARSE: log lines -> "service|address|account" for each failure, and
#   "mailout|sender|recipients" for each queued message.
PARSE='
function clean(a) { gsub(/[][()"]/, "", a); sub(/^::ffff:/, "", a); sub(/%.*/, "", a); return a }  # awk, not shell: posix-ok
function after(s, word,   i) { i = index(s, word); return i ? substr(s, i + length(word)) : "" }  # awk, not shell: posix-ok
function first(s,   f) { split(s, f, /[ \t,;>]/); return f[1] }  # awk, not shell: posix-ok
# isip(a): one plain IPv4 or IPv6 address - no network ("/"), no name.  Every
# address is checked before it is counted: a ban of "0.0.0.0/0" or of a host
# name the attacker chose must never reach the firewall.
function isip(a,   o, i) {  # awk, not shell: posix-ok
    if (a ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) { split(a, o, "."); for (i = 1; i <= 4; i++) if (o[i] + 0 > 255) return 0; return 1 }
    return (a ~ /^[0-9a-fA-F:]+$/ && a ~ /:.*:/)
}
# emit(service, address, account): print one failure, if the address is real.
function emit(s, a, u) { a = clean(a); if (isip(a)) print s "|" a "|" u }  # awk, not shell: posix-ok
# sshfrom(line): the address sshd itself wrote - the LAST "ADDRESS port N" on
# the line.  The account name comes before it and is chosen by the attacker:
# logging in as "x from 10.0.0.5 port 1" must not get 10.0.0.5 banned.
function sshfrom(s,   a) {  # awk, not shell: posix-ok
    a = ""
    while (match(s, / [^ ]+ port [0-9]+/)) { a = substr(s, RSTART + 1, RLENGTH - 1); sub(/ port [0-9]+$/, "", a); s = substr(s, RSTART + RLENGTH) }
    return a
}
{
    l = $0
    if (l ~ /sshd(-session)?\[[0-9]+\]:/) {
        if (l ~ /Failed password for/) {
            u = after(l, "Failed password for "); sub(/^invalid user /, "", u); u = first(u)
            emit("ssh", sshfrom(l), u); next
        }
        if (l ~ /(Connection closed by|Disconnected from) invalid user/) {
            u = after(l, "invalid user "); split(u, f, " "); emit("ssh", sshfrom(l), f[1]); next
        }
        if (l ~ /maximum authentication attempts exceeded/) { emit("ssh", sshfrom(l), ""); next }
        next
    }
    if (l ~ /FAIL LOGIN: Client "/) { a = after(l, "Client \""); sub(/".*/, "", a); u = ""; if (match(l, /\[[^]]+\] FAIL/)) u = substr(l, RSTART + 1, RLENGTH - 7); emit("ftp", a, u); next }
    if (l ~ /proftpd/ && l ~ /Login failed|no such user/) { if (match(l, /\[[0-9a-fA-F.:]+\]/)) emit("ftp", substr(l, RSTART, RLENGTH), ""); next }
    if (l ~ /pure-ftpd/ && l ~ /Authentication failed for user/) { if (match(l, /\?@[0-9a-fA-F.:]+/)) emit("ftp", substr(l, RSTART + 2, RLENGTH - 2), first(after(l, "user ["))); next }
    if (l ~ /SASL [A-Z0-9-]+ authentication failed/) { if (match(l, /\[[0-9a-fA-F.:]+\]: SASL/)) { a = substr(l, RSTART, RLENGTH - 6); emit("smtp", a, "") } ; next }
    if (l ~ /Relay access denied/) { if (match(l, /from [^[]*\[[0-9a-fA-F.:]+\]/)) { a = substr(l, RSTART, RLENGTH); sub(/.*\[/, "", a); emit("smtp-relay", a, "") } ; next }
    if (l ~ /dovecot/ && (l ~ /auth failed/ || l ~ /authentication failure/) && l ~ /rip=/) {
        a = first(after(l, "rip=")); u = first(after(l, "user=<")); emit("imap-pop", a, u); next }
    if (l ~ /qmgr\[[0-9]+\]: [0-9A-Za-z]+: from=</ && l ~ /nrcpt=/) {
        s = first(after(l, "from=<")); n = first(after(l, "nrcpt=")) + 0; if (s != "") print "mailout|" s "|" n; next }
    if (l ~ /authentication failure;/ && l ~ /rhost=[0-9a-fA-F.:]+/) { a = first(after(l, "rhost=")); u = first(after(l, " user=")); emit("pam", a, u); next }
    # Web access logs: address first, then the request in quotes.
    if (l ~ /^[0-9a-fA-F.:]+ [^ ]+ [^ ]+ \[[^]]+\] "[A-Z]+ /) {
        split(l, q, "\""); split(q[2], rq, " "); split(q[3], st, " ")
        p = tolower(rq[2])
        # Login pages only.  Not "/admin" in general: a signed-in admin posts
        # there all day (WordPress admin-ajax.php every few seconds).
        sub(/[?#].*/, "", p)
        if ((rq[1] == "POST" && (p ~ /(wp-login\.php|xmlrpc\.php|\/administrator\/(index\.php)?$|\/user\/login$|phpmyadmin\/index\.php$|\/(login|signin|sign-in)(\.[a-z]+)?\/?$)/ || tolower(rq[2]) ~ /_task=login/)) || st[1] == "401")
            emit("web", $1, "")
    }
}'

# Service names in the log -> the family asked about.
FAMILY='{ f = $1; if (f == "smtp" || f == "smtp-relay" || f == "imap-pop" || f == "mailout") f = "mail"; if (want == "all" || index(" " want " ", " " f " ")) print }'

OFFCSV=$(cc_csv_new offenders "time,address,verdict,services,failures,web_attempts,accounts_tried")
BANCSV=$(cc_csv_new bans "time,address,services,failures,accounts_tried,until,action")
T_BAN=0; T_NOT=0; T_SPAM=0; T_LINES=0; NCHECK=0; STOP=0

# ---- One check --------------------------------------------------------------------------
one_run() {
    _now=$(now)
    read_new | awk "$PARSE" | awk -F'|' -v want="$SERVICES" "$FAMILY" >"$W/events"
    # Failures and mail volume go into the window file with this check's time.
    awk -F'|' -v t="$_now" '$1 != "mailout" { print t "|" $1 "|" $2 "|1|" $3 } $1 == "mailout" { print t "|mailout|" $2 "|" $3 "|" }' "$W/events" >"$W/hits.run"
    _cut=$((_now - WINDOW * 60))
    { [ -f "$DS/hits" ] && awk -F'|' -v c="$_cut" '$1 >= c' "$DS/hits"; cat "$W/hits.run"; } >"$W/hits.all"
    # Totals per address in the window: failures (non-web), web attempts,
    # services and accounts tried; the verdict; why it is never banned.
    # -v, not trailing name=value operands: those are set only after BEGIN runs.
    awk -F'|' -v nf="$W/never" -v maxf="$MAXF" -v webmax="$WEBMAX" -v mailmax="$MAILMAX" "$AWK_NEVER"'
        BEGIN { loadnever(nf) }
        $2 == "mailout" { mo[$3] += $4; next }
        { a = $3; if (a == "") next
          if ($2 == "web") web[a] += $4; else fail[a] += $4
          if (!((a, $2) in sv)) { sv[a, $2] = 1; svc[a] = svc[a] (svc[a] ? "+" : "") $2 }
          if ($5 != "" && !((a, $5) in ac)) { ac[a, $5] = 1; nac[a]++; if (nac[a] <= 5) acc[a] = acc[a] (acc[a] ? " " : "") $5 } }
        END {
            for (a in svc) {
                f = fail[a] + 0; w = web[a] + 0
                over = (f >= maxf || w >= webmax)
                tag = never(a) ? why[NV] : (over ? "ban" : "watch")
                print tag "|" a "|" svc[a] "|" f "|" w "|" acc[a] (nac[a] > 5 ? " +" (nac[a] - 5) " more" : "")
            }
            for (s in mo) if (mo[s] >= mailmax) print "spam|" s "|mail|" mo[s] "|0|"
        }' "$W/hits.all" | sort -t'|' -k4,4nr -k5,5nr >"$W/totals"
    # Already banned now (no double bans); in a dry run, already "would ban".
    fw_list >"$W/banned" 2>/dev/null
    cat "$W/wouldban" >>"$W/banned"
    _nb=0; _ts=$(date -u +%Y-%m-%dT%H:%M:%SZ); _tl=$(date +%H:%M:%S)
    : >"$W/shown"
    while IFS='|' read -r _tag _a _svc _f _w _acc; do
        cc_csv_row "$OFFCSV" "$_ts" "$_a" "$_tag" "$_svc" "$_f" "$_w" "$_acc"
        [ "$_tag" = ban ] || continue
        if grep -qxF "$_a" "$W/banned"; then printf 'had|%s|%s|%s|%s|%s\n' "$_a" "$_svc" "$_f" "$_w" "$_acc" >>"$W/shown"; continue; fi
        fw_setup || { cc_err "could not set up the ban table"; break; }
        cc_csv_row "$BANCSV" "$_ts" "$_a" "$_svc" "$((_f + _w))" "$_acc" "+${BANTIME}min" "$([ "$CC_APPLY" = 1 ] && echo banned || echo 'would ban')"
        if fw_ban "$_a" "$((BANTIME * 60))"; then
            _nb=$((_nb + 1))
            printf 'new|%s|%s|%s|%s|%s\n' "$_a" "$_svc" "$_f" "$_w" "$_acc" >>"$W/shown"
            if [ "$CC_APPLY" = 1 ]; then
                printf '%s,%s,%s,%s,"%s",+%smin,banned\n' "$_ts" "$_a" "$_svc" "$((_f + _w))" "$_acc" "$BANTIME" >>"$BANS"
                [ "$BACKEND" = iptables ] && printf '%s|%s\n' "$((_now + BANTIME * 60))" "$_a" >>"$STATE/iptables-expiry"
            else
                printf '%s\n' "$_a" >>"$W/wouldban"
            fi
        else
            cc_show "$C_RED" "  [!] the firewall refused to ban $_a - see $CC_LOG"
        fi
    done <"$W/totals"
    # Plain iptables bans do not expire by themselves: remove the due ones.
    if [ "$BACKEND" = iptables ] && [ -f "$STATE/iptables-expiry" ] && [ "$CC_APPLY" = 1 ]; then
        awk -F'|' -v n="$_now" '$1 <= n { print $2 }' "$STATE/iptables-expiry" >"$W/due"
        while IFS= read -r _a; do fw_unban "$_a" && cc_show "$C_GRY" "  [-] ban ended: $_a"; done <"$W/due"
        awk -F'|' -v n="$_now" '$1 > n' "$STATE/iptables-expiry" >"$W/exp" && mv "$W/exp" "$STATE/iptables-expiry"
    fi
    # Report: one heading line, then the addresses, worst first.
    _ne=$(grep -c . "$W/events")
    _nn=$(awk -F'|' -v mx="$MAXF" -v wm="$WEBMAX" '$1 != "ban" && $1 != "watch" && $1 != "spam" && ($4 >= mx || $5 >= wm)' "$W/totals" | grep -c .)
    _ns=$(grep -c '^spam|' "$W/totals"); _nw=$(grep -c '^watch|' "$W/totals")
    T_BAN=$((T_BAN + _nb)); T_NOT=$((T_NOT + _nn)); T_SPAM=$((T_SPAM + _ns)); T_LINES=$((T_LINES + _ne))
    _verb=$([ "$CC_APPLY" = 1 ] && echo banned || echo "would ban")
    _line="$_ts  check $NCHECK: $_ne failed login(s) read; $_verb $_nb; not banned (protected) $_nn; spam warnings $_ns"
    printf '%s\n' "$_line" >>"$STATE/events.log"
    if [ "$_nb" -gt 0 ]; then _hc=$C_RED; elif [ $((_nn + _ns)) -gt 0 ]; then _hc=$C_YEL; elif [ "$_ne" -gt 0 ]; then _hc=$C_GRY; else _hc=$C_GRN; fi
    if [ "$_ne" = 0 ] && [ ! -s "$W/totals" ]; then
        cc_show "$_hc" "$_tl  check $NCHECK: [ok] no new failed logins"
    else
        cc_show "$_hc" "$_tl  check $NCHECK: $_ne new failed login(s) - $_verb $_nb, $_nw under watch"
    fi
    # row LABEL ADDR SERVICES FAILS WEB -> one aligned line (no colour)
    row() { printf '%-13s %-17s %-18s %4d fails %4d web' "$1" "$2" "$3" "$4" "$5"; }
    while IFS='|' read -r _k _a _svc _f _w _acc; do
        if [ "$_k" = new ]; then
            if [ "$CC_APPLY" = 1 ]; then cc_show "$C_RED" "  [!] $(row BANNED "$_a" "$_svc" "$_f" "$_w")  for $BANTIME min"
            else cc_show "$C_YEL" "  [*] $(row 'WOULD BAN' "$_a" "$_svc" "$_f" "$_w")"; fi
            [ -n "$_acc" ] && cc_show "$C_GRY" "                    accounts tried: $_acc"
        else
            cc_show "$C_GRY" "  [-] $(row "$([ "$CC_APPLY" = 1 ] && echo 'still banned' || echo 'would ban')" "$_a" "$_svc" "$_f" "$_w")  (shown before)"
        fi
    done <"$W/shown"
    awk -F'|' -v mx="$MAXF" -v wm="$WEBMAX" '$1 != "ban" && $1 != "watch" && $1 != "spam" && ($4 >= mx || $5 >= wm)' "$W/totals" |
    while IFS='|' read -r _tag _a _svc _f _w _acc; do
        case "$_tag" in
            gateway) _why="the default gateway - with NAT, every outside client looks like it. Ban by hand only if sure" ;;
            team) _why="on your never-ban list - if this is not the scoring engine or your team, look at it" ;;
            protected) _why="a protected host - probably the scoring engine failing after a password change" ;;
            own) _why="this box's own address" ;;
            *) _why="never banned ($_tag)" ;;
        esac
        cc_show "$C_YEL" "  [*] $(row 'NOT BANNED' "$_a" "$_svc" "$_f" "$_w")"
        cc_show "$C_YEL" "                    $_why"
    done
    awk -F'|' '$1 == "spam"' "$W/totals" | while IFS='|' read -r _tag _a _svc _f _w _acc; do
        cc_show "$C_YEL" "  [*] SPAM?         $_a sent to $_f recipients in $WINDOW min - a compromised mailbox? (not banned; change its password)"
    done
    awk -F'|' '$1 == "watch"' "$W/totals" | head -n 5 | while IFS='|' read -r _tag _a _svc _f _w _acc; do
        cc_show "$C_GRY" "  [-] $(row watching "$_a" "$_svc" "$_f" "$_w")  (ban at $MAXF / $WEBMAX web)"
    done
    _more=$(($(grep -c '^watch|' "$W/totals") - 5)); [ "$_more" -gt 0 ] && cc_show "$C_GRY" "      ... and $_more more under watch (offenders.txt)"
    # Save the window and how far each log was read.
    mv "$W/hits.all" "$DS/hits"
    awk -F'\t' -v nf="$W/offsets.new" 'FILENAME == nf { n[$1] = $2; next } !($1 in n) { print } END { for (k in n) print k "\t" n[k] }' "$W/offsets.new" "$DS/offsets" >"$W/off" 2>/dev/null
    [ -s "$W/offsets.new" ] && mv "$W/off" "$DS/offsets"
    return 0
}

# ---- 3/4 Checks ---------------------------------------------------------------------
header "3/4  checks$([ "$LOOP" -gt 0 ] && echo " every $LOOP seconds - Ctrl-C stops")"
trap 'STOP=1' INT TERM
# shellcheck disable=SC2034  # read by cc_run: no WOULD/DO lines, the report says it
_q=$CC_QUIET; CC_QUIET=1
while [ "$STOP" = 0 ]; do
    NCHECK=$((NCHECK + 1))
    one_run
    [ "$STOP" = 1 ] && break
    [ "$LOOP" -gt 0 ] || break
    [ "$COUNT" -gt 0 ] && [ "$NCHECK" -ge "$COUNT" ] && break
    sleep "$LOOP"
done
trap 'cc_log ERROR "interrupted"; exit 130' INT TERM
CC_QUIET=$_q

# ---- 4/4 Summary ---------------------------------------------------------------------
cc_csv_pretty "$BANCSV" "$CC_RUN_DIR/bans.txt" 110
cc_csv_pretty "$OFFCSV" "$CC_RUN_DIR/offenders.txt" 110
fw_list >"$W/active" 2>/dev/null
{
    printf '==========[ 4/4  summary ]==========\n'
    printf 'Host %s | %s check(s) | %s new failed login line(s) read\n' "$CC_HOST" "$NCHECK" "$T_LINES"
    if [ "$CC_APPLY" = 1 ]; then printf 'Banned this run: %s\n' "$T_BAN"; else printf 'Would ban: %s (dry run - nothing was blocked)\n' "$T_BAN"; fi
    [ "$T_NOT" -gt 0 ] && printf 'Over the limit but never banned (team/protected/gateway): %s - look at them\n' "$T_NOT"
    [ "$T_SPAM" -gt 0 ] && printf 'Spam warnings: %s\n' "$T_SPAM"
    printf 'Banned right now: %s\n' "$(grep -c . "$W/active")"
    if [ "$T_BAN" -gt 0 ]; then
        printf '\n'
        awk 'NR > 1' "$BANCSV" | tr -d '"' | cut -d, -f2,3,4 | awk -F, '{ printf "  %-17s %-18s %s failures\n", $1, $2, $3 }'
    fi
    printf '\nFiles:\n'
    printf '  %s/bans.txt        bans this run (csv/bans.csv)\n' "$CC_RUN_DIR"
    printf '  %s/offenders.txt   every address with failures, per check\n' "$CC_RUN_DIR"
    printf '  %s   every ban ever\n' "$BANS"
    printf '\n'
    if [ "$CC_APPLY" = 1 ]; then
        printf 'Lift a ban: --apply --unban ADDR   Lift all: --apply --unban-all   List: --list\n'
    else
        printf 'Next: run with --protected FILE --apply (and --loop 60 to keep watching) to ban for real.\n'
    fi
} >"$CC_RUN_DIR/summary.txt"
cc_show "" ""
while IFS= read -r _line; do
    case "$_line" in
        ==*) cc_show "$C_CYN" "$_line" ;;
        'Banned this run: 0'|'Would ban: 0'*) cc_show "$C_GRN" "$_line" ;;
        'Banned this run:'*) cc_show "$C_RED" "$_line" ;;
        'Would ban:'*|'Over the limit'*|'Spam'*) cc_show "$C_YEL" "$_line" ;;
        *) cc_show "" "$_line" ;;
    esac
done <"$CC_RUN_DIR/summary.txt"
rm -rf "$W"
cc_finish
