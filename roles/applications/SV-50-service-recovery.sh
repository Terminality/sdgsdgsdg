#!/bin/sh
# =============================================================================
# ID:       SV-50
# NAME:     Service recovery (find out why a service is down, bring it back)
# ROLE:     Applications  (any time a scored service goes red)
# KIND:     changes - dry run unless --apply
# VERSION:  1.0.0
#
# PURPOSE
#   When a scored service goes down, restarting it often fails: red team
#   broke something under it.  This checks every service on the box the same
#   way, finds the reason, and offers the fix:
#
#     web (apache2, httpd, nginx), php-fpm, database (mariadb, mysql,
#     postgresql), mail (dovecot, postfix), splunk, ssh, time (chrony, ntp)
#
#   For each one that is installed:
#     1  running?          stopped / failed / masked / disabled at boot
#     2  config loads?     apache2ctl -t, nginx -t, php-fpm -t, postfix
#                          check, doveconf, sshd -t (errors shown); a service
#                          is never restarted on a config that fails
#     3  port?             listening; or ANOTHER program holds the port
#     4  answers?          tested the way scoring does: HTTP status, IMAP /
#                          SMTP / SSH banner, database ping, chrony tracking
#     5  firewall?         iptables DROP/REJECT rules on the service's port
#                          (nftables: shown)
#     6  tampered?         config files changed in the last 2 hours,
#                          systemd drop-ins (ExecStart=/bin/true), package
#                          files that no longer match (dpkg -V / rpm -V)
#   And once for the box: disk or inodes full, /tmp not writable, programs
#   killed for lack of memory.
#
#   Fixes offered (each asked, yes/no): unmask, enable at boot, remove a
#   firewall rule that blocks the port, stop the program holding the port,
#   start / restart (only after the config test passes).  Each fixed service
#   is tested again.  Reported, never changed: config errors, changed files,
#   a full disk - with what to do.  Defaced or wiped site: SV-15 --restore.
#
#   --watch checks every N seconds and prints a line the moment a service
#   goes down or comes back (and why); with --auto-restart it also restarts
#   a service that went down, if its config test passes (at most 3 times in
#   10 minutes each, so a crash loop is not hidden).
#
#   No revert timer: these fixes bring services UP; undoing them would take
#   them down again.  Each change still has an undo line (revert.sh).
#
#   QUESTIONS (Enter takes the default in capitals; a flag answers each):
#     which box                       --box NAME
#     which services                  --services a,b (Enter = all found)
#     each fix (yes / no)             --fix KINDS (always yes for these kinds)
#
# USAGE
#   sudo sh SV-50-service-recovery.sh                       check all, dry run
#   sudo sh SV-50-service-recovery.sh --apply               check and fix (asks)
#   sudo sh SV-50-service-recovery.sh --apply --batch --services web,mysql
#   sudo sh SV-50-service-recovery.sh --watch 30 --auto-restart --apply
#
# OPTIONS
#   --apply            make the fixes (without it, dry run only)
#   --box NAME         splunk | webmail | ecomm | other (asked)
#   --services a,b     only these: web php-fpm mysql postgres imap smtp splunk
#                      ssh ntp, or unit names (apache2, nginx ...)
#   --fix KINDS        answer yes for these fix kinds: unmask enable firewall
#                      kill start (default: each asked; --batch takes the
#                      default shown)
#   --watch SECONDS    keep checking; print changes (Ctrl-C to stop)
#   --auto-restart     with --watch and --apply: restart what goes down
#   --watch-count N    with --watch: stop after N rounds (tests)
#   --no-color         no colours
#   --help             this text plus the common options
#
# OUTPUTS  (under --out, in recovery-N/)
#   output.txt   everything shown on screen, no colour
#   status.txt   each service: running, config, port, answer, problems
#   summary.txt, run.txt, revert.sh;  watch.txt with --watch
#
# DEPENDS ON
#   ss, systemctl or service; curl or wget; nc or openssl (banners);
#   iptables (firewall check).  CCDC_SVC_DIRS (tests) adds folders of
#   stand-in init scripts.
#
# TESTED ON
#   Ubuntu 24.04 (SysV init in a container) with Apache, MariaDB,
#   PostgreSQL, Dovecot, Postfix, OpenSSH and chrony, under dash, bash,
#   busybox sh, ksh93, mksh and yash: a stopped Apache, a DROP rule on 80,
#   a program holding port 80 and a broken Apache config were each found;
#   the first three fixed, the broken config reported and Apache left alone.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - "Up" here means it answers on this box.  If scoring still fails, check
#     the router/firewall between (NW scripts) and the scoring IP.
#   - A defaced or wiped site answers 200: use SV-15 --check for content.
#   - nftables rules are shown, not removed.
#
# DEBUGGING
#   --debug shows each command.  status.txt holds every check's result.
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
SV-50 Service recovery - why is a service down, and bring it back
  sudo sh SV-50-service-recovery.sh                     check all, dry run
  sudo sh SV-50-service-recovery.sh --apply             check and fix (asks)
  sudo sh SV-50-service-recovery.sh --watch 30 --auto-restart --apply

  --apply            make the fixes (without it, dry run only)
  --box NAME         splunk | webmail | ecomm | other
  --services a,b     web php-fpm mysql postgres imap smtp splunk ssh ntp, or unit names
  --fix KINDS        yes for these fix kinds: unmask enable firewall kill start
  --watch SECONDS    keep checking, print changes (Ctrl-C to stop)
  --auto-restart     with --watch and --apply: restart what goes down
  --watch-count N    with --watch: stop after N rounds
  --no-color         no colours
  --help             show this text
USAGE
    cc_usage_common
}

BOX=""; ONLY=""; FIXK=""; WATCH=""; AUTOR=0; WCOUNT=0; COLOR=1
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --apply)        CC_APPLY=1; shift ;;
        --box)          [ $# -ge 2 ] || cc_die 2 "--box needs a name"; BOX=$2; shift 2 ;;
        --services)     [ $# -ge 2 ] || cc_die 2 "--services needs a list"; ONLY="$ONLY,$2"; shift 2 ;;
        --fix)          [ $# -ge 2 ] || cc_die 2 "--fix needs a list"; FIXK="$FIXK,$2"; shift 2 ;;
        --watch)        [ $# -ge 2 ] || cc_die 2 "--watch needs seconds"; WATCH=$2; shift 2 ;;
        --auto-restart) AUTOR=1; shift ;;
        --watch-count)  [ $# -ge 2 ] || cc_die 2 "--watch-count needs a number"; WCOUNT=$2; shift 2 ;;
        --no-color|--no-colour) COLOR=0; shift ;;
        --help|-h)      usage; exit 0 ;;
        *)              cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
case "$BOX" in ''|splunk|webmail|ecomm|other) ;; *) cc_die 2 "--box must be splunk, webmail, ecomm or other" ;; esac
for _n in "$WATCH" "$WCOUNT"; do case "$_n" in *[!0-9]*) cc_die 2 "--watch and --watch-count need whole numbers" ;; esac; done
[ -z "$WATCH" ] || [ "$WATCH" -ge 5 ] || cc_die 2 "--watch must be at least 5 seconds"
for _k in $(printf '%s' "$FIXK" | tr ',' ' '); do
    case "$_k" in unmask|enable|firewall|kill|start) ;; *) cc_die 2 "--fix: unknown kind '$_k' (unmask enable firewall kill start)" ;; esac
done
[ "$AUTOR" = 1 ] && [ -z "$WATCH" ] && cc_die 2 "--auto-restart needs --watch"

cc_init "SV-50" "Service recovery" changes
cc_detect_os
# shellcheck disable=SC2034  # read by cc_color_init
[ "$COLOR" = 1 ] || CC_NOCOLOR=1
cc_color_init
cc_use_numbered_dir recovery
rmdir "$CC_RUN_DIR/raw" 2>/dev/null
OUTF="$CC_RUN_DIR/output.txt"
grep -v '\[NOTE\]\|\[DEBUG\]' "$CC_LOG" >"$OUTF" 2>/dev/null || : >"$OUTF"
# shellcheck disable=SC2034  # CC_TEE is read by the library's log functions
CC_TEE=$OUTF
W="$CC_RUN_DIR/.work"; mkdir -p "$W"
CC_CSV_DIR="$W/csv"; mkdir -p "$CC_CSV_DIR"
header() { cc_show "" ""; cc_show "$C_CYN" "==========[ $1 ]=========="; }
inlist() { case ",$2," in *",$1,"*) return 0 ;; esac; return 1; }
now() { date +%H:%M:%S; }

cc_show "$C_CYN" "SV-50 Service recovery | host $CC_HOST | init $CC_INIT | results in $CC_RUN_DIR"
cc_show "" "Legend: ${C_RED}[!] DOWN / broken${C_OFF}   ${C_YEL}[*] look at it${C_OFF}   ${C_GRN}[ok] up${C_OFF}   ${C_YEL}[~] would fix${C_OFF}   ${C_GRN}[+] fixed${C_OFF}   ${C_RED}[x] fix failed${C_OFF}"

# ---- The services ---------------------------------------------------------------------
# kind|unit names|process names|ports (any of; uN = udp)|probe
cat >"$W/table" <<'EOF'
web|apache2 httpd|apache2 httpd|80 443|http
web|nginx|nginx|80 443|http
php-fpm|php-fpm php8.4-fpm php8.3-fpm php8.2-fpm php8.1-fpm php8.0-fpm php7.4-fpm php7.3-fpm php7.2-fpm|php-fpm|-|none
mysql|mariadb mysql mysqld|mariadbd mysqld|3306|mysql
postgres|postgresql|postgres|5432|pg
imap|dovecot|dovecot|143 993|imap
smtp|postfix|master|25 587 465|smtp
smtp|exim4 exim|exim4 exim|25 587|smtp
splunk|Splunkd splunk|splunkd|8089 8000|splunk
ssh|ssh sshd|sshd|22|ssh
ntp|chrony chronyd|chronyd|u123|ntp
ntp|ntp ntpd ntpsec|ntpd|u123|ntp
EOF
# unit_exists NAME -> the service is installed under this name.
unit_exists() {
    case "$1" in Splunkd|splunk) [ -x /opt/splunk/bin/splunk ] && return 0 ;; esac
    if [ "$CC_INIT" = systemd ]; then
        systemctl list-unit-files "$1.service" 2>/dev/null | grep -q "^$1\.service" && return 0
    fi
    [ -x "/etc/init.d/$1" ] && return 0
    for _d in ${CCDC_SVC_DIRS:-}; do [ -x "$_d/$1" ] && return 0; done
    return 1
}
# The rows to check: kind|unit|procs|ports|probe
: >"$W/rows"
while IFS='|' read -r _k _us _ps _pt _pr; do
    for _u in $_us; do
        unit_exists "$_u" || continue
        printf '%s|%s|%s|%s|%s\n' "$_k" "$_u" "$_ps" "$_pt" "$_pr" >>"$W/rows"
        break
    done
done <"$W/table"
for _s in $(printf '%s' "$ONLY" | tr ',' ' '); do
    awk -F'|' -v s="$_s" '$1 == s || $2 == s { f = 1 } END { exit !f }' "$W/rows" || \
        cc_die 2 "--services: '$_s' is not installed here (installed: $(cut -d'|' -f2 "$W/rows" | tr '\n' ' '))"
done
[ -s "$W/rows" ] || { cc_show "$C_GRY" "None of the services this script knows is installed here."; rm -rf "$W"; cc_finish; exit 0; }

if [ -z "$BOX" ] && [ -z "$WATCH" ]; then
    cc_choose "Which box is this?" o "s=splunk" "w=webmail" "e=ecomm" "o=other"
    case "$CC_CHOICE" in s) BOX=splunk ;; w) BOX=webmail ;; e) BOX=ecomm ;; *) BOX=other ;; esac
fi
case "$BOX" in
    splunk)  SCORED="splunk ssh ntp" ;;
    webmail) SCORED="imap smtp web ssh php-fpm mysql postgres" ;;
    ecomm)   SCORED="web php-fpm mysql postgres" ;;
    *)       SCORED="" ;;
esac
if [ -z "$ONLY" ] && [ -z "$WATCH" ] && [ "$(grep -c . "$W/rows")" -gt 1 ]; then
    cc_choose "Check which services? (found: $(cut -d'|' -f2 "$W/rows" | tr '\n' ' ' | sed 's/ $//'))" a \
        "a=all of them" "s=only the scored ones for this box${SCORED:+ ($SCORED)}"
    [ "$CC_CHOICE" = s ] && [ -n "$SCORED" ] && ONLY=",$(printf '%s' "$SCORED" | tr ' ' ',')"
fi
if [ -n "$ONLY" ]; then
    awk -F'|' -v l="$ONLY," 'index(l, "," $1 ",") || index(l, "," $2 ",")' "$W/rows" >"$W/rows.t" && mv "$W/rows.t" "$W/rows"
fi

# ---- Checks --------------------------------------------------------------------------
svc_cmd() {   # svc_cmd UNIT start|stop|restart|status
    case "$1" in Splunkd|splunk) /opt/splunk/bin/splunk "$2" --accept-license --answer-yes --no-prompt; return ;; esac
    for _d in ${CCDC_SVC_DIRS:-}; do [ -x "$_d/$1" ] && { "$_d/$1" "$2"; return; }; done
    if [ "$CC_INIT" = systemd ]; then systemctl "$2" "$1"
    elif cc_have rc-service; then rc-service "$1" "$2"
    elif cc_have service; then service "$1" "$2"
    else "/etc/init.d/$1" "$2"; fi
}
running() {   # running UNIT PROCS
    if [ "$CC_INIT" = systemd ] && ! printf '%s' "$1" | grep -q '^Splunkd$\|^splunk$'; then
        systemctl is-active -q "$1" 2>/dev/null && return 0
    fi
    for _p in $2; do
        case "$_p" in php-fpm) pgrep -f '^php-fpm' >/dev/null 2>&1 && return 0 ;; *) pgrep -x "$_p" >/dev/null 2>&1 && return 0 ;; esac
    done
    return 1
}
unit_state() {   # unit_state UNIT -> "masked" | "disabled" | "enabled" | "-"
    if [ "$CC_INIT" = systemd ]; then
        case "$(systemctl is-enabled "$1" 2>/dev/null)" in
            masked*) echo masked ;; disabled) echo disabled ;; enabled*|static|alias|indirect|generated) echo enabled ;; *) echo - ;; esac
    elif [ -d /etc/rc2.d ] || [ -d /etc/rc3.d ]; then
        if ls /etc/rc[2345].d/S*"$1" >/dev/null 2>&1; then echo enabled; elif [ -x "/etc/init.d/$1" ]; then echo disabled; else echo -; fi
    else echo -; fi
}
config_test() {   # config_test UNIT -> output in $W/ct, rc 0 ok / 1 broken / 2 none
    : >"$W/ct"
    case "$1" in
        apache2) _c=$(cc_first apache2ctl apachectl) || return 2; "$_c" -t >"$W/ct" 2>&1 ;;
        httpd) _c=$(cc_first httpd apachectl) || return 2; "$_c" -t >"$W/ct" 2>&1 ;;
        nginx) cc_have nginx || return 2; nginx -t >"$W/ct" 2>&1 ;;
        php*-fpm) _v=${1#php}; _v=${_v%-fpm}; _c=$(cc_first "php-fpm$_v" php-fpm) || return 2; "$_c" -t >"$W/ct" 2>&1 ;;
        postfix) cc_have postfix || return 2; postfix check >"$W/ct" 2>&1 ;;
        dovecot) cc_have doveconf || return 2; doveconf -n >/dev/null 2>"$W/ct" ;;
        ssh|sshd) _c=$(cc_which sshd) || return 2; [ -d /run/sshd ] || mkdir -p /run/sshd 2>/dev/null; "$_c" -t >"$W/ct" 2>&1 ;;
        *) return 2 ;;
    esac
    [ $? -eq 0 ] && return 0; return 1
}
# Which ports answer.  tcp n, or uN for udp.
listening() {   # listening PORT -> pid/program on stdout, rc 0 if someone listens
    case "$1" in
        u*) ss -lunp 2>/dev/null | awk -v p=":${1#u}" '{ n = split($4, a, ":"); if (":" a[n] == p) { print $NF; f = 1 } } END { exit !f }' ;;
        *)  ss -ltnp 2>/dev/null | awk -v p=":$1" '{ n = split($4, a, ":"); if (":" a[n] == p) { print $NF; f = 1 } } END { exit !f }' ;;
    esac
}
banner() {   # banner PORT [tls] -> first line the server sends
    if [ "${2:-}" = tls ]; then
        cc_have openssl && { sleep 2 | timeout 6 openssl s_client -connect "127.0.0.1:$1" -quiet 2>/dev/null | head -n 1; }; return
    fi
    if cc_have nc; then { sleep 2; } | timeout 6 nc -w 3 127.0.0.1 "$1" 2>/dev/null | head -n 1 | tr -d '\r'
    elif cc_have curl; then curl -s -m 3 "telnet://127.0.0.1:$1" </dev/null 2>/dev/null | head -n 1 | tr -d '\r'
    fi
}
http_code() {   # http_code URL
    if cc_have curl; then curl -sk -m 8 -o "$W/page" -w '%{http_code}' "$1" 2>/dev/null
    elif cc_have wget; then wget -q -S -O "$W/page" -T 8 --no-check-certificate "$1" 2>&1 | awk '/HTTP\// { c = $2 } END { print c }'; fi
}
probe() {   # probe KIND UNIT PORTS -> "ok TEXT" or "bad TEXT" or "- TEXT"
    case "$1" in
        http)
            for _p in $3; do
                listening "$_p" >/dev/null || continue
                _sc=http; [ "$_p" = 443 ] && _sc=https
                _c=$(http_code "$_sc://127.0.0.1:$_p/"); _c=${_c:-000}
                case "$_c" in
                    000) echo "bad no HTTP answer on $_p" ;;
                    5??) if grep -qiE 'database|SQLSTATE|mysql' "$W/page" 2>/dev/null; then echo "bad HTTP $_c on $_p: a database error (check mysql)"; else echo "bad HTTP $_c on $_p (the app or PHP fails: error.log)"; fi ;;
                    *)   echo "ok HTTP $_c on $_p" ;;
                esac
                return
            done
            echo "bad nothing answers on $3" ;;
        mysql)
            _c=$(cc_first mariadb-admin mysqladmin) || { echo "- no mysqladmin"; return; }
            if "$_c" --connect-timeout=5 ping >/dev/null 2>&1; then echo "ok answers a ping"
            elif "$_c" --connect-timeout=5 ping 2>&1 | grep -qi 'access denied'; then echo "ok answers (login refused for root: fine)"
            else echo "bad does not answer a ping"; fi ;;
        pg)
            if cc_have pg_isready; then pg_isready -q -h 127.0.0.1 2>/dev/null && echo "ok accepting connections" || echo "bad not accepting connections"
            else echo "- no pg_isready"; fi ;;
        imap)
            for _p in $3; do
                listening "$_p" >/dev/null || continue
                if [ "$_p" = 993 ]; then _b=$(banner 993 tls); else _b=$(banner "$_p"); fi
                case "$_b" in "* OK"*) echo "ok IMAP banner on $_p" ;; '') echo "bad no IMAP banner on $_p" ;; *) echo "bad odd answer on $_p: $(printf '%s' "$_b" | cut -c1-40)" ;; esac
                return
            done
            echo "bad nothing answers on $3" ;;
        smtp)
            for _p in $3; do
                listening "$_p" >/dev/null || continue
                [ "$_p" = 465 ] && continue
                _b=$(banner "$_p")
                case "$_b" in 220*) echo "ok SMTP banner on $_p" ;; '') echo "bad no SMTP banner on $_p" ;; *) echo "bad odd answer on $_p: $(printf '%s' "$_b" | cut -c1-40)" ;; esac
                return
            done
            echo "bad nothing answers on $3" ;;
        ssh)
            _b=$(banner 22)
            case "$_b" in SSH-*) echo "ok SSH banner" ;; '') echo "bad no SSH banner on 22" ;; *) echo "bad odd answer on 22" ;; esac ;;
        splunk)
            _c=$(http_code "https://127.0.0.1:8089/"); case "${_c:-000}" in 000) echo "bad management port 8089 does not answer" ;; *) echo "ok 8089 answers ($_c)" ;; esac ;;
        ntp)
            if cc_have chronyc && [ "$2" != ntp ] && [ "$2" != ntpd ] && [ "$2" != ntpsec ]; then
                chronyc -n tracking >/dev/null 2>&1 && echo "ok chronyc tracking answers" || echo "bad chronyc gets no answer"
            elif listening u123 >/dev/null; then echo "ok listening on 123/udp"
            else echo "bad nothing on 123/udp"; fi ;;
        *) echo "- not tested" ;;
    esac
}
# Firewall rules that drop the port: "iptables-spec" lines.
fw_rules() {   # fw_rules PORT
    _pn=${1#u}
    cc_have iptables || return 0
    iptables -S 2>/dev/null | awk -v p="$_pn" '
        /^-A / && / -j (DROP|REJECT)/ {
            for (i = 1; i <= NF; i++) {
                if ($i == "--dport" && $(i + 1) == p) { print; next }
                if ($i == "--dports") { n = split($(i + 1), a, ","); for (j = 1; j <= n; j++) { split(a[j], r, ":"); if (a[j] == p || (r[2] != "" && p >= r[1] && p <= r[2])) { print; next } } }
            }
        }'
}
pol_drop() { cc_have iptables && iptables -S INPUT 2>/dev/null | grep -q '^-P INPUT DROP'; }

# ---- Watch mode --------------------------------------------------------------------------
if [ -n "$WATCH" ]; then
    # Only the web server in use is watched (apache2 or nginx, not both).
    _wu=""; while IFS='|' read -r _k _u _ps _pt _pr; do [ "$_k" = web ] && [ -z "$_wu" ] && running "$_u" "$_ps" && _wu=$_u; done <"$W/rows"
    [ -n "$_wu" ] || _wu=$(awk -F'|' '$1 == "web" { print $2; exit }' "$W/rows")
    awk -F'|' -v w="$_wu" '$1 != "web" || $2 == w' "$W/rows" >"$W/rows.t" && mv "$W/rows.t" "$W/rows"
    WF="$CC_RUN_DIR/watch.txt"
    cc_show "$C_CYN" "Watching $(cut -d'|' -f2 "$W/rows" | tr '\n' ' ')every $WATCH s$([ "$AUTOR" = 1 ] && [ "$CC_APPLY" = 1 ] && echo ', restarting what goes down'). Ctrl-C to stop."
    [ "$AUTOR" = 1 ] && [ "$CC_APPLY" != 1 ] && cc_show "$C_YEL" "  [*] --auto-restart without --apply: only reporting."
    : >"$W/state"; : >"$W/restarts"; _round=0
    trap 'cc_show "" "Stopped. Log: $WF"; rm -rf "$W"; cc_finish; exit 0' INT TERM
    while :; do
        _round=$((_round + 1))
        while IFS='|' read -r _k _u _ps _pt _pr; do
            if running "$_u" "$_ps"; then _r=$(probe "$_pr" "$_u" "$_pt"); else _r="bad not running"; fi
            _st=${_r%% *}; _tx=${_r#* }
            _was=$(awk -F'|' -v u="$_u" '$1 == u { print $2 }' "$W/state")
            if [ "$_st" != "${_was:-new}" ]; then
                awk -F'|' -v u="$_u" '$1 != u' "$W/state" >"$W/state.t"; printf '%s|%s\n' "$_u" "$_st" >>"$W/state.t"; mv "$W/state.t" "$W/state"
                case "$_st" in
                    ok)  [ -n "$_was" ] && cc_show "$C_GRN" "$(now) [ok] $_u is UP again: $_tx" || cc_show "$C_GRN" "$(now) [ok] $_u: $_tx" ;;
                    bad) cc_show "$C_RED" "$(now) [!] $_u is DOWN: $_tx" ;;
                    *)   cc_show "$C_GRY" "$(now) [-] $_u: $_tx" ;;
                esac
                printf '%s %s %s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$_u" "$_st" "$_tx" >>"$WF"
            fi
            if [ "$_st" = bad ] && [ "$AUTOR" = 1 ] && [ "$CC_APPLY" = 1 ]; then
                _t=$(date +%s); _n=$(awk -v t="$_t" -v u="$_u" '$1 == u && $2 > t - 600 { n++ } END { print n + 0 }' "$W/restarts")
                config_test "$_u"; _ctr=$?
                if [ "$_ctr" = 1 ]; then
                    cc_show "$C_RED" "$(now) [x] $_u: NOT restarted, its config test fails: $(head -n 2 "$W/ct" | tr '\n' ' ')"
                elif [ "$_n" -ge 3 ]; then
                    [ "$_n" = 3 ] && cc_show "$C_RED" "$(now) [x] $_u: restarted 3 times in 10 minutes and still going down - run SV-50 without --watch to see why"
                    printf '%s %s\n' "$_u" "$_t" >>"$W/restarts"
                else
                    printf '%s %s\n' "$_u" "$_t" >>"$W/restarts"
                    if svc_cmd "$_u" restart >>"$CC_LOG" 2>&1; then cc_show "$C_GRN" "$(now) [+] $_u restarted"; else cc_show "$C_RED" "$(now) [x] $_u did not restart (log: $CC_LOG)"; fi
                    printf '%s %s restarted\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$_u" >>"$WF"
                fi
            fi
        done <"$W/rows"
        [ "$WCOUNT" -gt 0 ] && [ "$_round" -ge "$WCOUNT" ] && break
        sleep "$WATCH"
    done
    trap - INT TERM
    rm -rf "$W"; cc_finish; exit 0
fi

# ---- The box -------------------------------------------------------------------------
header "1/4  the box"
BOXP=0
df -P / /var /tmp 2>/dev/null | awk 'NR > 1 { u = $5; sub(/%/, "", u); if (u + 0 >= 95) print $6 " " u "%" }' | sort -u >"$W/full"
while read -r _m _p; do cc_show "$C_RED" "  [!] $_m is $_p full: services cannot write logs, PID files or sessions. Look: du -xh $_m | sort -h | tail"; BOXP=1; done <"$W/full"
df -Pi / /var /tmp 2>/dev/null | awk 'NR > 1 { u = $5; sub(/%/, "", u); if (u + 0 >= 95) print $6 " " u "%" }' | sort -u | while read -r _m _p; do cc_show "$C_RED" "  [!] $_m has no inodes left ($_p): someone may have filled it with tiny files"; done
_tt="/tmp/.ccdc-sv50-$$"; if : >"$_tt" 2>/dev/null; then rm -f "$_tt"; else cc_show "$C_RED" "  [!] /tmp is not writable: PHP sessions and many services fail. Check: ls -ld /tmp (should be drwxrwxrwt)"; BOXP=1; fi
[ "$(stat -c %a /tmp 2>/dev/null)" = 1777 ] || { [ -d /tmp ] && cc_show "$C_YEL" "  [*] /tmp mode is $(stat -c %a /tmp 2>/dev/null), not 1777 (fix: chmod 1777 /tmp)"; }
_oom=$( { dmesg 2>/dev/null; journalctl -k -n 500 --no-pager 2>/dev/null; } | grep -i 'out of memory\|killed process' | tail -n 3)
[ -n "$_oom" ] && { cc_show "$C_YEL" "  [*] programs were killed for lack of memory:"; printf '%s\n' "$_oom" | while IFS= read -r _l; do cc_show "$C_GRY" "      $_l"; done; }
[ "$BOXP" = 0 ] && cc_show "$C_GRN" "  [ok] disk, inodes and /tmp"

# ---- Each service ----------------------------------------------------------------------
header "2/4  services"
# fixes: unit|kind|description|default|command|undo
: >"$W/fixes"
SCSV=$(cc_csv_new status "service,unit,running,boot,config,port,answer,problems")
# addfix UNIT KIND DESC DEFAULT CMD UNDO - once per kill/firewall command:
#   two web servers on one port share the same fix.
addfix() {
    case "$2" in kill|firewall) awk -F'|' -v k="$2" -v c="$5" '$2 == k && $5 == c { f = 1 } END { exit !f }' "$W/fixes" && return 0 ;; esac
    printf '%s|%s|%s|%s|%s|%s\n' "$@" >>"$W/fixes"
}
NDOWN=0; WEBSTART=""; WEBBROKEN=""
# Two web servers installed (apache2 and nginx): only one serves the site.
WEBUP=""
while IFS='|' read -r _k _u _ps _pt _pr; do [ "$_k" = web ] && running "$_u" "$_ps" && WEBUP="$WEBUP $_u"; done <"$W/rows"
while IFS='|' read -r _k _u _ps _pt _pr; do
    _probs=""; _st=$(unit_state "$_u"); _run=no; running "$_u" "$_ps" && _run=yes
    if [ "$_k" = web ] && [ "$_run" = no ] && [ -n "$WEBUP" ]; then
        cc_show "$C_GRY" "  [-] $(printf '%-9s %-12s' web "$_u") not in use (the web server here is${WEBUP})"
        cc_csv_row "$SCSV" "$_k" "$_u" no "$(unit_state "$_u")" - - "not in use" ""; continue
    fi
    config_test "$_u"; _ctr=$?
    _cfg=ok; [ "$_ctr" = 1 ] && _cfg=BROKEN; [ "$_ctr" = 2 ] && _cfg=-
    # Ports: who listens.
    _pinfo=""; _held=""
    for _p in $_pt; do
        [ "$_p" = - ] && continue
        if _who=$(listening "$_p"); then
            _pn=$(printf '%s' "$_who" | sed -n 's/.*"\([^"]*\)".*/\1/p' | head -n 1)
            _ok=0; for _x in $_ps; do case "$_pn" in "$_x"*|php-fpm*) _ok=1 ;; esac; done
            case "$_u" in ssh|sshd) [ "$_pn" = sshd ] && _ok=1 ;; esac
            if [ "$_ok" = 1 ] || [ -z "$_pn" ]; then _pinfo="$_pinfo ${_p#u}"
            else _pinfo="$_pinfo ${_p#u}:$_pn"; _held="$_held $_p:$_who"; fi
        fi
    done
    if [ "$_run" = yes ]; then _ans=$(probe "$_pr" "$_u" "$_pt"); else _ans="bad not running"; fi
    _ast=${_ans%% *}; _atx=${_ans#* }
    # Problems and fixes.
    [ "$_st" = masked ] && { _probs="$_probs masked;"; addfix "$_u" unmask "unmask $_u (masked: it cannot start at all)" y "unmask" "mask"; }
    if [ "$_st" = disabled ] && { [ "$_run" = no ] || [ -n "$SCORED" ]; }; then
        case " $SCORED " in *" $_k "*) _probs="$_probs disabled at boot;"; addfix "$_u" enable "enable $_u at boot (a scored service: a reboot would leave it down)" y enable disable ;;
            *) [ "$_run" = no ] && _probs="$_probs disabled at boot;" ;; esac
    fi
    [ "$_cfg" = BROKEN ] && _probs="$_probs config test FAILS;"
    for _h in $_held; do
        _hp=${_h%%:*}; _hw=${_h#*:}; _hpid=$(printf '%s' "$_hw" | sed -n 's/.*pid=\([0-9]*\).*/\1/p' | head -n 1)
        _hn=$(printf '%s' "$_hw" | sed -n 's/.*"\([^"]*\)".*/\1/p' | head -n 1)
        _hexe=$(readlink "/proc/$_hpid/exe" 2>/dev/null)
        _probs="$_probs port ${_hp#u} held by $_hn (pid $_hpid);"
        _hd=n; case "$_hexe" in /tmp/*|/var/tmp/*|/dev/shm/*|*"(deleted)"*|'') _hd=y ;; esac
        [ -n "$_hpid" ] && addfix "$_u" kill "stop $_hn (pid $_hpid, ${_hexe:-program gone from disk}) holding port ${_hp#u} - $([ "$_hd" = y ] && echo 'runs from a temp folder or a deleted file: red team' || echo 'is it yours?')" "$_hd" "kill $_hpid" "-"
    done
    for _p in $_pt; do
        [ "$_p" = - ] && continue
        fw_rules "$_p" >"$W/fw"
        while IFS= read -r _rule; do
            [ -n "$_rule" ] || continue
            _probs="$_probs firewall drops ${_p#u};"
            addfix "$_u" firewall "remove the firewall rule: $_rule" y "${_rule#-A }" "${_rule#-A }"
        done <"$W/fw"
        # nftables only when iptables shows nothing (iptables-nft shows the
        # same rule in both).
        if [ ! -s "$W/fw" ] && cc_have nft && nft list ruleset 2>/dev/null | grep -Eq "dport (\{[^}]*[ ,])?${_p#u}([ ,][^}]*\})? .*(drop|reject)"; then
            _probs="$_probs nftables drops ${_p#u} (nft list ruleset);"
        fi
    done
    pol_drop && ! iptables -S INPUT 2>/dev/null | grep -q -- "--dport ${_pt%% *} .*ACCEPT\|-j ACCEPT$" && _probs="$_probs INPUT policy DROP with no ACCEPT for ${_pt%% *};"
    if [ "$_run" = no ]; then
        _probs="$_probs not running;"
        if [ "$_cfg" = BROKEN ]; then _probs="$_probs not started: fix the config first;"; [ "$_k" = web ] && WEBBROKEN=${WEBBROKEN:-$_u}
        elif [ "$_k" = web ] && [ -n "$WEBSTART" ]; then
            addfix "$_u" start "start $_u too ($WEBSTART is being started on the same ports: say yes only if both are used)" n start "-"
        elif [ "$_k" = web ] && [ -n "$WEBBROKEN" ]; then
            addfix "$_u" start "start $_u instead ($WEBBROKEN cannot start: say yes only if $_u serves this site)" n start "-"
        else addfix "$_u" start "start $_u$([ "$_cfg" = ok ] && echo ' (its config test passes)')" y start "-"; fi
        [ "$_k" = web ] && [ -z "$WEBSTART" ] && [ "$_cfg" != BROKEN ] && [ -z "$WEBBROKEN" ] && WEBSTART=$_u
    elif [ "$_ast" = bad ]; then
        if [ "$_cfg" = BROKEN ]; then _probs="$_probs running but not answering, config broken: NOT restarted;"
        else addfix "$_u" start "restart $_u (running but $_atx)" y restart "-"; fi
    fi
    [ "$_ast" = bad ] && [ "$_run" = yes ] && _probs="$_probs $_atx;"
    # Tampering: config changed lately, drop-ins, package files.
    case "$_u" in apache2) _cd=/etc/apache2 ;; httpd) _cd=/etc/httpd ;; nginx) _cd=/etc/nginx ;; php*-fpm) _cd=/etc/php ;; mariadb|mysql|mysqld) _cd=/etc/mysql ;; postgresql) _cd=/etc/postgresql ;;
        dovecot) _cd=/etc/dovecot ;; postfix) _cd=/etc/postfix ;; ssh|sshd) _cd=/etc/ssh ;; chrony|chronyd) _cd=/etc/chrony ;; *) _cd="" ;; esac
    _recent=""; [ -n "$_cd" ] && [ -d "$_cd" ] && _recent=$(find "$_cd" -type f -mmin -120 2>/dev/null | head -n 5 | tr '\n' ' ')
    _drop=""; [ "$CC_INIT" = systemd ] && _drop=$(ls -d "/etc/systemd/system/$_u.service.d" "/etc/systemd/system/$_u.service" 2>/dev/null | tr '\n' ' ')
    [ -n "$_drop" ] && grep -rqs 'ExecStart=.*\(/bin/true\|/bin/false\|/dev/null\|sleep\)' $_drop && _probs="$_probs systemd override replaces how it starts ($_drop);"
    printf '%s|%s\n' "$_u" "$_recent" >>"$W/recent"
    _pk=""; if cc_have dpkg; then _pk=$(dpkg -S "$(cc_which "$(printf '%s' "$_ps" | cut -d' ' -f1)" 2>/dev/null || echo /nonexistent)" 2>/dev/null | cut -d: -f1 | head -n 1); fi
    if [ -n "$_pk" ]; then
        _bad=$(dpkg -V "$_pk" 2>/dev/null | awk '$2 != "c" && $1 ~ /5/ { print $NF }' | head -n 3 | tr '\n' ' ')
        [ -n "$_bad" ] && _probs="$_probs program files changed ($_bad) - reinstall: apt-get install --reinstall $_pk;"
    fi
    # Show it.
    _line=$(printf '%-9s %-12s run:%-3s boot:%-8s config:%-6s port:%-12s %s' "$_k" "$_u" "$_run" "$_st" "$_cfg" "${_pinfo# }" "$([ "$_run" = yes ] && printf "%s" "$_atx")")
    if [ -z "$_probs" ] && [ "$_ast" != bad ]; then cc_show "$C_GRN" "  [ok] $_line"
    else NDOWN=$((NDOWN + 1)); cc_show "$C_RED" "  [!] $_line"
        printf '%s' "$_probs" | tr ';' '\n' | sed 's/^ *//' | grep . | while IFS= read -r _pl; do cc_show "$C_YEL" "        - $_pl"; done
        [ "$_cfg" = BROKEN ] && head -n 4 "$W/ct" | while IFS= read -r _cl; do cc_show "$C_GRY" "        config: $_cl"; done
        [ -n "$_recent" ] && cc_show "$C_YEL" "        - config files changed in the last 2 hours: $_recent(compare with your backup; SV-15 --restore puts configs back)"
        if [ "$_run" = no ] || [ "$_ast" = bad ]; then
            _lg=""; case "$_u" in apache2) _lg=/var/log/apache2/error.log ;; httpd) _lg=/var/log/httpd/error_log ;; nginx) _lg=/var/log/nginx/error.log ;;
                mariadb|mysql|mysqld) _lg=$(ls /var/log/mysql/error.log /var/log/mariadb/mariadb.log 2>/dev/null | head -n 1) ;; dovecot|postfix) _lg=$(ls /var/log/mail.log /var/log/maillog 2>/dev/null | head -n 1) ;; esac
            if [ "$CC_INIT" = systemd ]; then journalctl -u "$_u" -n 3 --no-pager -o cat 2>/dev/null; elif [ -n "$_lg" ]; then tail -n 3 "$_lg" 2>/dev/null; fi | cut -c1-150 | while IFS= read -r _ll; do cc_show "$C_GRY" "        log: $_ll"; done
        fi
    fi
    cc_csv_row "$SCSV" "$_k" "$_u" "$_run" "$_st" "$_cfg" "${_pinfo# }" "$_atx" "$(printf '%s' "$_probs" | sed 's/;$//; s/^ //')"
done <"$W/rows"

# ---- Fixes ------------------------------------------------------------------------------
header "3/4  fixes"
NFIX=$(grep -c . "$W/fixes")
[ "$NFIX" -eq 0 ] && cc_show "$C_GRN" "  [ok] Nothing to fix here.$([ "$NDOWN" -gt 0 ] && echo ' (The problems above need a hand: see each one.)')"
: >"$W/chosen"
while IFS='|' read -r _u _kd _ds _df _cmd _un; do
    if inlist "$_kd" "$FIXK"; then printf '%s|%s|%s|%s|%s\n' "$_u" "$_kd" "$_ds" "$_cmd" "$_un" >>"$W/chosen"; continue; fi
    _d=Y; [ "$_df" = n ] && _d=N
    cc_ask "[$_kd] $_ds?" "$_d" "yes, do it" "no, leave it" && printf '%s|%s|%s|%s|%s\n' "$_u" "$_kd" "$_ds" "$_cmd" "$_un" >>"$W/chosen"
done <"$W/fixes"
NCH=$(grep -c . "$W/chosen")

header "4/4  apply"
NOK=0; NBAD=0
if [ "$NCH" -eq 0 ]; then
    [ "$NFIX" -gt 0 ] && cc_show "$C_GRY" "  No fix chosen."
elif [ "$CC_APPLY" != 1 ] || ! cc_is_root; then
    cc_is_root || cc_show "$C_YEL" "  [!] not root: showing the fixes only"
    while IFS='|' read -r _u _kd _ds _cmd _un; do cc_show "$C_YEL" "  [~] $_ds"; done <"$W/chosen"
    cc_show "$C_GRY" "  Dry run: nothing was changed. Run again with --apply."
    # shellcheck disable=SC2034  # read by cc_finish
    CC_N_WOULD=$NCH
else
    # Order: unmask, firewall, kill, enable, then start - each fix clears
    # the way for the next.
    for _kd in unmask firewall kill enable start; do
        awk -F'|' -v k="$_kd" '$2 == k' "$W/chosen" | while IFS='|' read -r _u _k2 _ds _cmd _un; do
            case "$_kd" in
                unmask) cc_undo_add "mask $_u again" "systemctl mask $_u"; systemctl unmask "$_u" >>"$CC_LOG" 2>&1; _r=$? ;;
                enable) if [ "$CC_INIT" = systemd ]; then cc_undo_add "disable $_u at boot again" "systemctl disable $_u"; systemctl enable "$_u" >>"$CC_LOG" 2>&1
                        else cc_undo_add "disable $_u at boot again" "update-rc.d $_u disable"; update-rc.d "$_u" enable >>"$CC_LOG" 2>&1; fi; _r=$? ;;
                firewall) # shellcheck disable=SC2086  # the rule's words
                        { cc_undo_add "put the firewall rule back" "iptables -A $_un"; iptables -D $_cmd >>"$CC_LOG" 2>&1; }; _r=$? ;;
                kill)   kill ${_cmd#kill } 2>>"$CC_LOG"; sleep 1; kill -0 ${_cmd#kill } 2>/dev/null && kill -9 ${_cmd#kill } 2>>"$CC_LOG"; _r=0 ;;
                start)  svc_cmd "$_u" "$_cmd" >>"$CC_LOG" 2>&1; _r=$? ;;
            esac
            if [ "$_r" = 0 ]; then cc_show "$C_GRN" "  [+] $_ds"; echo ok >>"$W/res"; else cc_show "$C_RED" "  [x] FAILED: $_ds (log: $CC_LOG)"; echo bad >>"$W/res"; fi
        done
    done
    NOK=$(grep -c ok "$W/res" 2>/dev/null); NBAD=$(grep -c bad "$W/res" 2>/dev/null)
    # shellcheck disable=SC2034  # read by cc_finish
    CC_N_DONE=$NOK
    # shellcheck disable=SC2034  # read by cc_finish
    CC_N_FAIL=$NBAD
    # Test each fixed service again.
    cut -d'|' -f1 "$W/chosen" | sort -u | while IFS= read -r _u; do
        _row=$(awk -F'|' -v u="$_u" '$2 == u' "$W/rows")
        _ps=$(printf '%s' "$_row" | cut -d'|' -f3); _pt=$(printf '%s' "$_row" | cut -d'|' -f4); _pr=$(printf '%s' "$_row" | cut -d'|' -f5)
        _i=0; _ans="bad not running"
        while [ "$_i" -lt 5 ]; do
            sleep 2; _i=$((_i + 1))
            running "$_u" "$_ps" && _ans=$(probe "$_pr" "$_u" "$_pt") && [ "${_ans%% *}" != bad ] && break
        done
        case "$_ans" in ok*|-*) cc_show "$C_GRN" "  [ok] $_u is UP: ${_ans#* }" ;; *) cc_show "$C_RED" "  [!] $_u is still DOWN: ${_ans#* } - look at the problems above" ;; esac
        printf '%s %s\n' "$_u" "${_ans%% *}" >>"$W/after"
    done
fi

# ---- Summary ----------------------------------------------------------------------------
cc_csv_pretty "$SCSV" "$CC_RUN_DIR/status.txt" 140
{
    printf '==========[ summary ]==========\n'
    printf 'SV-50 Service recovery | host %s | %s\n' "$CC_HOST" "$([ "$CC_APPLY" = 1 ] && [ "$NCH" -gt 0 ] && echo APPLIED || echo 'CHECK / DRY RUN')"
    printf 'Services with problems: %d of %d\n' "$NDOWN" "$(grep -c . "$W/rows")"
    awk "$CC_AWK_CSV"'NR > 1 { csvsplit($0, f); if (f[8] != "") printf "  %-12s %s\n", f[2], substr(f[8], 1, 150) }' "$SCSV"
    [ -s "$W/after" ] && { printf '\nAfter the fixes:\n'; awk '{ printf "  %-12s %s\n", $1, ($2 == "bad" ? "STILL DOWN" : "up") }' "$W/after"; }
    printf '\nIf the box says up but scoring says down: check the network firewall / router (NW scripts) and that the scoring IP is not banned (SV-26 --unban-all).\n'
    printf 'Defaced or wiped site: SV-15 --check, then --restore.   Watch: sh %s --watch 30\n' "$0"
    [ -f "$CC_RUN_DIR/revert.sh" ] && printf 'Undo this run: sh %s/revert.sh --force\n' "$CC_RUN_DIR"
} >"$CC_RUN_DIR/summary.txt"
cc_show "" ""
while IFS= read -r _l; do
    case "$_l" in ==*|SV-50*) cc_show "$C_CYN" "$_l" ;; *'STILL DOWN'*) cc_show "$C_RED" "$_l" ;; '  '*) cc_show "$C_YEL" "$_l" ;; *) cc_show "" "$_l" ;; esac
done <"$CC_RUN_DIR/summary.txt"
rm -rf "$W"
cc_finish
