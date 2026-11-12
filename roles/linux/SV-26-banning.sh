#!/bin/sh
# =============================================================================
# ID:       SV-26
# NAME:     Brute-force and spam banning
# ROLE:     Linux  (wave 2)
# KIND:     changes - dry run unless --apply
# VERSION:  1.1.0
#
# PURPOSE
#   Reads the login logs, counts failures per source address, and bans an
#   address that passes the limit with a firewall entry that REMOVES ITSELF
#   after --ban-time minutes.
#     SSH        "Failed password", invalid-user scans, too many auth tries
#     FTP        vsftpd, proftpd, pure-ftpd login failures
#     mail       postfix SASL failures and relay attempts, dovecot (IMAP/POP)
#                failures
#     web        POSTs to login pages (wp-login.php, xmlrpc.php, Joomla,
#                Drupal, phpMyAdmin, Roundcube, /login, /admin) and HTTP 401s,
#                with their own, higher limit
#     PAM        any other "authentication failure ... rhost=" line
#   Spam is REPORTED, not banned: a sender or mail account sending to more
#   than --mail-max recipients in the window (a compromised mailbox).
#
#   NEVER BANNED: protected hosts (protected list, type host: the scoring
#   engine), --ignore addresses, this box's own addresses, loopback, and the
#   default gateway - when traffic is NATed every outside client looks like
#   the gateway, and banning it would cut off scoring.  Those are reported.
#
#   How it counts without parsing log dates: each run reads only the lines
#   added since the last run and stores the counts with the run's time; the
#   window is the sum of the runs in the last --window minutes.  Run it in a
#   loop (--loop 60).  The first run reads the last --history lines.
#
# USAGE
#   sudo sh SV-26-banning.sh                         dry run: who would be banned
#   sudo sh SV-26-banning.sh --apply --loop 60       ban, checking every minute
#   sudo sh SV-26-banning.sh --list                  current bans
#   sudo sh SV-26-banning.sh --apply --unban 10.6.6.6
#
# OPTIONS
#   --max-fails N    failures in the window that earn a ban (default 10)
#   --web-max N      web login attempts that earn a ban (default 30)
#   --window MIN     counting window in minutes (default 10)
#   --ban-time MIN   ban length in minutes (default 30)
#   --mail-max N     recipients per sender in the window before a spam
#                    warning (default 200)
#   --ignore CIDR    never ban this address or network (repeat)
#   --log FILE       read this log (repeat).  When given, ONLY these logs are
#                    read, not the usual ones or the journal
#   --history N      lines read from each log on the first run (default 2000)
#   --loop N         run every N seconds (at least 10) until stopped
#   --count N        with --loop: stop after N runs
#   --backend NAME   nft, ipset or iptables (default: nft, else ipset, else
#                    iptables)
#   --list           show the current bans and exit
#   --unban IP       remove a ban and exit (with --apply)
#   --state DIR      where offsets, counts and bans.csv live
#                    (default <out>/ban-<host>)
#   --help           this text plus the common options
#
# OUTPUTS  (in the state folder)
#   bans.csv        time,address,services,failures,accounts_tried,until,action
#   events.log      one line per run: failures seen, bans made, warnings
#   hits            counts per run (used for the window)
#   offsets         how far each log has been read
#
# WHAT IT CHANGES  (only with --apply)
#   nftables: table "inet ccdc_ban" (two address sets with timeouts and one
#   drop rule).  ipset: set "ccdc_ban" plus one iptables rule.  iptables
#   alone: one DROP rule per banned address, removed by a later run when the
#   ban ends.  The undo log removes it all.  No other rule is touched.
#
# DEPENDS ON
#   awk, tail, wc; nft or ipset+iptables or iptables; journalctl when the
#   SSH log is only in the journal.  CCDC_NFT, CCDC_IPSET and CCDC_IPTABLES
#   may name stand-ins (the tests use them).
#
# TESTED ON
#   Ubuntu 24.04 under dash, bash, busybox sh, ksh93, mksh and yash with
#   sample logs and stand-in firewalls, and live: real failed SSH logins from
#   a separate network namespace got that address banned in nftables, and
#   the ban expired by itself.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - A red team with many addresses is slowed, not stopped.
#   - The scoring engine fails logins too (after a password change): put it on
#     the protected list as a host.
#   - Log formats differ between versions; a service whose failures are not
#     counted shows nothing, not an error.  Check with --log and --debug.
#
# DEBUGGING
#   --debug shows each log read and the counts per address.  events.log has
#   one line per run.  "nft list table inet ccdc_ban" shows the bans.
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
SV-26 Brute-force and spam banning - timed bans for addresses that keep failing logins
  sudo sh SV-26-banning.sh [--apply] [options]

  --max-fails N    failures that earn a ban (default 10)
  --web-max N      web login attempts that earn a ban (default 30)
  --window MIN     counting window (default 10)
  --ban-time MIN   ban length (default 30)
  --mail-max N     recipients per sender before a spam warning (default 200)
  --ignore CIDR    never ban this address/network (repeatable)
  --log FILE       read only these logs (repeatable)
  --history N      lines read per log on the first run (default 2000)
  --loop N         run every N seconds; --count N stops after N runs
  --backend nft|ipset|iptables
  --list           show current bans
  --unban IP       remove a ban (with --apply)
  --state DIR      state folder
  --help           show this text

USAGE
    cc_usage_common
}

NL='
'
MAXF=10; WEBMAX=30; WINDOW=10; BANTIME=30; MAILMAX=200; IGNORE=""; LOGS=""; HIST=2000
LOOP=0; COUNT=0; BACKEND=""; MODE=run; UNBAN=""; STATE=""
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
        --count)     num "$1" "${2:-}"; COUNT=$2; shift 2 ;;
        --ignore)    [ $# -ge 2 ] || cc_die 2 "--ignore needs an address"; IGNORE="$IGNORE$2$NL"; shift 2 ;;
        --log)       [ $# -ge 2 ] || cc_die 2 "--log needs a file"; [ -r "$2" ] || cc_die 2 "--log: cannot read $2"; LOGS="$LOGS$(cc_abspath "$2")$NL"; shift 2 ;;
        --backend)   [ $# -ge 2 ] || cc_die 2 "--backend needs a name"; BACKEND=$2; shift 2 ;;
        --list)      MODE=list; shift ;;
        --unban)     [ $# -ge 2 ] || cc_die 2 "--unban needs an address"; MODE=unban; UNBAN=$2; shift 2 ;;
        --state)     [ $# -ge 2 ] || cc_die 2 "--state needs a folder"; STATE=$2; shift 2 ;;
        --help|-h)   usage; exit 0 ;;
        *)           cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
case "$BACKEND" in ''|nft|ipset|iptables) ;; *) cc_die 2 "--backend must be nft, ipset or iptables" ;; esac
[ "$LOOP" -gt 0 ] && [ "$LOOP" -lt 10 ] && cc_die 2 "--loop must be at least 10 seconds"
[ "$MAXF" -ge 1 ] && [ "$WEBMAX" -ge 1 ] && [ "$WINDOW" -ge 1 ] && [ "$BANTIME" -ge 1 ] || cc_die 2 "limits, window and ban time must be at least 1"
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
[ "$CC_APPLY" = 1 ] && cc_require_root
[ -n "$STATE" ] || STATE="$CC_OUT/ban-$CC_HOST"
(umask 077; mkdir -p "$STATE") || cc_die 3 "cannot create $STATE"
STATE=$(cc_abspath "$STATE")
W="$STATE/.work"; mkdir -p "$W"
BANS="$STATE/bans.csv"
[ -f "$BANS" ] || printf 'time,address,services,failures,accounts_tried,until,action\n' >"$BANS"

# now -> seconds since 1970 (date +%s where it works, else awk's srand trick).
now() { _t=$(date +%s 2>/dev/null); case "$_t" in ''|*[!0-9]*) awk 'BEGIN { srand(); print srand() }' ;; *) printf '%s\n' "$_t" ;; esac; }

# ---- Firewall backend --------------------------------------------------------
NFT=${CCDC_NFT:-$(cc_which nft)} || NFT=""
IPSET=${CCDC_IPSET:-$(cc_which ipset)} || IPSET=""
IPT=${CCDC_IPTABLES:-$(cc_which iptables)} || IPT=""
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
            if ! "$NFT" list table inet ccdc_ban >/dev/null 2>&1; then
                cat >"$W/ban.nft" <<'EOF'
table inet ccdc_ban {
    set ban4 { type ipv4_addr; flags timeout; }
    set ban6 { type ipv6_addr; flags timeout; }
    chain input {
        type filter hook input priority -5; policy accept;
        ip saddr @ban4 drop
        ip6 saddr @ban6 drop
    }
}
EOF
                cc_run "create the ban table (nft table inet ccdc_ban)" "$NFT" -f "$W/ban.nft" || return 1
                cc_undo_add "remove all SV-26 bans" "$NFT delete table inet ccdc_ban"
            fi ;;
        ipset)
            if ! "$IPSET" list ccdc_ban >/dev/null 2>&1; then
                cc_run "create the ban set (ipset ccdc_ban)" "$IPSET" create ccdc_ban hash:ip timeout 0 -exist || return 1
                cc_undo_add "remove all SV-26 bans" "$IPT -D INPUT -m set --match-set ccdc_ban src -j DROP; $IPSET destroy ccdc_ban"
            fi
            "$IPT" -C INPUT -m set --match-set ccdc_ban src -j DROP 2>/dev/null ||
                cc_run "drop traffic from banned addresses" "$IPT" -I INPUT 1 -m set --match-set ccdc_ban src -j DROP || return 1 ;;
        iptables) : ;;
    esac
    _fw_ready=1
}
# fw_ban IP SECONDS
fw_ban() {
    case "$BACKEND" in
        nft) case "$1" in *:*) _set=ban6 ;; *) _set=ban4 ;; esac
             cc_run "ban $1 for $(($2 / 60)) min" "$NFT" add element inet ccdc_ban "$_set" "{ $1 timeout ${2}s }" ;;
        ipset) cc_run "ban $1 for $(($2 / 60)) min" "$IPSET" add ccdc_ban "$1" timeout "$2" -exist ;;
        iptables) cc_run "ban $1 for $(($2 / 60)) min" "$IPT" -I INPUT 1 -s "$1" -j DROP -m comment --comment ccdc_ban
                  _rc=$?; [ "$_rc" -eq 0 ] && cc_undo_add "unban $1" "$IPT -D INPUT -s $1 -j DROP -m comment --comment ccdc_ban"; return "$_rc" ;;
    esac
}
fw_unban() {
    case "$BACKEND" in
        nft) case "$1" in *:*) _set=ban6 ;; *) _set=ban4 ;; esac
             cc_run "unban $1" "$NFT" delete element inet ccdc_ban "$_set" "{ $1 }" ;;
        ipset) cc_run "unban $1" "$IPSET" del ccdc_ban "$1" ;;
        iptables) cc_run "unban $1" "$IPT" -D INPUT -s "$1" -j DROP -m comment --comment ccdc_ban ;;
    esac
}
# fw_list -> currently banned addresses, one per line.
fw_list() {
    case "$BACKEND" in
        nft) "$NFT" list table inet ccdc_ban 2>/dev/null | awk '/elements = \{/ { s = 1 } s { gsub(/elements = \{|[{},]/, " "); for (i = 1; i <= NF; i++) if ($i ~ /^[0-9a-fA-F.:]+$/ && $i ~ /[.:]/ && $(i - 1) != "timeout" && $(i - 1) != "expires") print $i } /\}/ { s = 0 }' ;;
        ipset) "$IPSET" list ccdc_ban 2>/dev/null | awk '/^Members:/ { s = 1; next } s && NF { print $1 }' ;;
        iptables) "$IPT" -S INPUT 2>/dev/null | awk '/ccdc_ban/ && /-s / { for (i = 1; i <= NF; i++) if ($i == "-s") { a = $(i + 1); sub(/\/32$/, "", a); print a } }' ;;
    esac
}

if [ "$MODE" = list ]; then
    printf 'Banned now (%s):\n' "$BACKEND"
    fw_list | sed 's/^/  /'
    printf 'History: %s\n' "$BANS"
    cc_finish
fi
if [ "$MODE" = unban ]; then
    fw_unban "$UNBAN"
    printf '%s,%s,,,,,unbanned by hand\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$UNBAN" >>"$BANS"
    cc_finish
fi

# ---- Never-ban list --------------------------------------------------------------
# Protected hosts, --ignore, own addresses, loopback, default gateways.
{
    printf '%s' "$IGNORE"
    printf '127.0.0.0/8\n::1\n'
    if [ -n "$CC_PROTECTED" ]; then awk -F',' '{ gsub(/[ "\r]/, "") } tolower($1) == "host" { print $2 }' "$CC_PROTECTED"; fi
    if cc_have ip; then
        ip -o addr 2>/dev/null | awk '{ a = $4; sub(/\/.*/, "", a); print a }'
        ip route 2>/dev/null | awk '$1 == "default" { for (i = 1; i <= NF; i++) if ($i == "via") print $(i + 1) " gateway" }'
    fi
} | grep . | sort -u >"$STATE/never"
cc_debug "never banned: $(tr '\n' ' ' <"$STATE/never")"
# AWK_NEVER: never(ip) is 1 when ip matches a line of the never-ban file
# (exact, or inside an IPv4 network).  Gateways are marked so they can be
# reported separately.
AWK_NEVER='
function ip2n(a,   p) { if (split(a, p, ".") != 4) return -1; return ((p[1] * 256 + p[2]) * 256 + p[3]) * 256 + p[4] }  # awk, not shell: posix-ok
function loadnever(f,   l, n, x) { while ((getline l < f) > 0) { split(l, x, " "); nv[++nn] = x[1]; gw[x[1]] = (x[2] == "gateway") } }  # awk, not shell: posix-ok
function never(ip,   i, j, net, bits, base, size) {  # awk, not shell: posix-ok
    for (i = 1; i <= nn; i++) {
        if (nv[i] == ip) return 1
        if (index(nv[i], "/") && ip !~ /:/) {
            # 2 to the power (32 - bits) by multiplying: some busybox awks
            # are built without math support, so "^" is not available.
            split(nv[i], net, "/"); bits = net[2] + 0; base = ip2n(net[1]); size = 1
            for (j = bits; j < 32; j++) size = size * 2
            if (base >= 0 && ip2n(ip) >= int(base / size) * size && ip2n(ip) < int(base / size) * size + size) return 1
        }
    }
    return 0
}'

# ---- Reading new log lines ----------------------------------------------------------
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
[ -f "$STATE/offsets" ] || : >"$STATE/offsets"

# read_new -> every line added since the last run, from every log, on stdout.
#   Offsets are only saved when changes are applied, so dry runs can repeat.
read_new() {
    : >"$W/offsets.new"
    while IFS= read -r _f; do
        _size=$(wc -c <"$_f" 2>/dev/null | tr -d ' ')
        _off=$(awk -F'\t' -v f="$_f" '$1 == f { print $2 }' "$STATE/offsets")
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
        _since=$(awk -F'\t' '$1 == "journal" { print $2 }' "$STATE/offsets")
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

# ---- One run --------------------------------------------------------------------------
one_run() {
    _now=$(now)
    read_new | awk "$PARSE" >"$W/events"
    # Failures and mail volume go into the window file with this run's time.
    awk -F'|' -v t="$_now" '$1 != "mailout" { print t "|" $1 "|" $2 "|1|" $3 } $1 == "mailout" { print t "|mailout|" $2 "|" $3 "|" }' "$W/events" >"$W/hits.run"
    _cut=$((_now - WINDOW * 60))
    { [ -f "$STATE/hits" ] && awk -F'|' -v c="$_cut" '$1 >= c' "$STATE/hits"; cat "$W/hits.run"; } >"$W/hits.all"
    # Totals per address in the window: failures (non-web), web attempts,
    # services and accounts tried.
    # -v, not trailing name=value operands: those are set only after BEGIN runs.
    awk -F'|' -v nf="$STATE/never" -v maxf="$MAXF" -v webmax="$WEBMAX" -v mailmax="$MAILMAX" "$AWK_NEVER"'
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
                tag = never(a) ? (gw[a] ? "gateway" : "never") : (over ? "ban" : "watch")
                print tag "|" a "|" svc[a] "|" f "|" w "|" acc[a] (nac[a] > 5 ? " +" (nac[a] - 5) " more" : "")
            }
            for (s in mo) if (mo[s] >= mailmax) print "spam|" s "|mail|" mo[s] "|0|"
        }' "$W/hits.all" | sort -t'|' -k4,4nr >"$W/totals"
    # Already banned now (no double bans).
    fw_list >"$W/banned" 2>/dev/null
    _nb=0; _ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    while IFS='|' read -r _tag _a _svc _f _w _acc; do
        [ "$_tag" = ban ] || continue
        if grep -qxF "$_a" "$W/banned"; then cc_debug "$_a already banned"; continue; fi
        fw_setup || { cc_err "could not set up the ban table"; break; }
        if fw_ban "$_a" "$((BANTIME * 60))"; then
            _nb=$((_nb + 1))
            _act=$([ "$CC_APPLY" = 1 ] && echo banned || echo "would ban")
            [ "$CC_APPLY" = 1 ] && printf '%s,%s,%s,%s,"%s",+%smin,%s\n' "$_ts" "$_a" "$_svc" "$((_f + _w))" "$_acc" "$BANTIME" "$_act" >>"$BANS"
            [ "$BACKEND" = iptables ] && [ "$CC_APPLY" = 1 ] && printf '%s|%s\n' "$((_now + BANTIME * 60))" "$_a" >>"$STATE/iptables-expiry"
        fi
    done <"$W/totals"
    # Plain iptables bans do not expire by themselves: remove the due ones.
    if [ "$BACKEND" = iptables ] && [ -f "$STATE/iptables-expiry" ] && [ "$CC_APPLY" = 1 ]; then
        awk -F'|' -v n="$_now" '$1 <= n { print $2 }' "$STATE/iptables-expiry" >"$W/due"
        while IFS= read -r _a; do fw_unban "$_a"; done <"$W/due"
        awk -F'|' -v n="$_now" '$1 > n' "$STATE/iptables-expiry" >"$W/exp" && mv "$W/exp" "$STATE/iptables-expiry"
    fi
    # Report.
    _ne=$(grep -c . "$W/events")
    _line="$_ts  $_ne new failure line(s); $([ "$CC_APPLY" = 1 ] && echo banned || echo 'would ban') $_nb"
    printf '%s\n' "$_line"
    printf '%s\n' "$_line" >>"$STATE/events.log"
    awk -F'|' -v mx="$MAXF" -v wm="$WEBMAX" -v w="$WINDOW" -v bf="$W/banned" '
        BEGIN { while ((getline l < bf) > 0) was[l] = 1 }
        $1 == "ban" && ($2 in was) { printf "  banned  %-39s %4d fails %4d web  %-18s (already banned)\n", $2, $4, $5, $3; next }
        $1 == "ban"     { printf "  BAN     %-39s %4d fails %4d web  %-18s %s\n", $2, $4, $5, $3, $6 }
        $1 == "gateway" && ($4 >= mx || $5 >= wm) { printf "  NOT BANNED (default gateway; NATed traffic?) %s: %d fails - ban by hand only if sure\n", $2, $4 + $5 }
        $1 == "never"   && ($4 >= mx || $5 >= wm) { printf "  NOT BANNED (protected/ignored/own) %s: %d fails %s\n", $2, $4 + $5, $3 }
        $1 == "spam"    { printf "  SPAM?   %s sent to %d recipients in %d min - compromised mailbox? (not banned)\n", $2, $4, w }' "$W/totals" | tee -a "$STATE/events.log" | head -n 30
    awk -F'|' '$1 == "watch"' "$W/totals" | head -n 5 | awk -F'|' -v mx="$MAXF" '{ printf "  watch   %-39s %4d fails %4d web  %-18s (ban at %d)\n", $2, $4, $5, $3, mx }'
    # Keep state only when changes are applied, so a dry run can be repeated.
    if [ "$CC_APPLY" = 1 ]; then
        mv "$W/hits.all" "$STATE/hits"
        # Merge new offsets over old ones.
        awk -F'\t' -v nf="$W/offsets.new" 'FILENAME == nf { n[$1] = $2; next } !($1 in n) { print } END { for (k in n) print k "\t" n[k] }' "$W/offsets.new" "$STATE/offsets" >"$W/off" 2>/dev/null
        [ -s "$W/offsets.new" ] && mv "$W/off" "$STATE/offsets"
    fi
}

_r=0
while :; do
    _r=$((_r + 1))
    one_run
    [ "$LOOP" -gt 0 ] || break
    [ "$COUNT" -gt 0 ] && [ "$_r" -ge "$COUNT" ] && break
    sleep "$LOOP"
done
[ "$CC_APPLY" = 1 ] || printf 'Dry run: nothing banned.  Run again with --apply (and --loop 60 to keep watching).\n'
printf 'Bans: %s   Events: %s\n' "$BANS" "$STATE/events.log"
rm -rf "$W"
cc_finish
