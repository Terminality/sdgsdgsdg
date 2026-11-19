#!/bin/sh
# =============================================================================
# ID:       LX-43
# NAME:     Log shipping to Splunk
# ROLE:     Linux  (wave 2: the Splunk box first, then every other box)
# KIND:     changes - dry run unless --apply
# VERSION:  1.0.0
#
# PURPOSE
#   Red team clears logs on the box they are on.  Logs that already left
#   for the Splunk box are safe, and one search there shows every box at
#   once.  Two halves, one script:
#
#     receiver (on the Splunk box)   a Splunk TCP input (default 1514) for
#       syslog, written as its own small app (etc/apps/bt_receiver), then
#       a Splunk restart (asked).  Open the port with LX-25.
#     sender (every other box)       rsyslog sends the system logs (auth,
#       syslog, kern, mail, cron) and the service log files it finds -
#       Apache / nginx access and error, mail.log, Dovecot, Roundcube,
#       MySQL/MariaDB errors, audit.log, the kit's logs - to the Splunk box.
#       Disk-buffered: if Splunk is down the logs wait and are sent later.
#       Then a test line is sent; search Splunk for it.
#
#   QUESTIONS (Enter takes the default in capitals; a flag answers each):
#     this box: [s]end its logs / [r]eceive (the Splunk box)   --send / --receive
#     the Splunk box's address                                 --to HOST
#     the port                                                 --port N
#     TCP or UDP                                               --udp
#     which logs: [a]ll found [s]ystem only [p]ick one by one   --logs all|system
#     apply?                                                   --apply
#
# USAGE
#   sudo sh LX-43-log-shipping.sh --receive --apply                (Splunk box)
#   sudo sh LX-43-log-shipping.sh --send --to 10.0.0.20 --apply    (every other box)
#   sudo sh LX-43-log-shipping.sh --send --to 10.0.0.20 --apply --batch --logs all
#
# OPTIONS
#   --apply            make the changes (without it, dry run only)
#   --send / --receive this box sends its logs / is the Splunk box
#   --to HOST          the Splunk box (sender)
#   --port N           TCP/UDP port (default 1514)
#   --udp              send over UDP (default TCP: nothing lost, buffered)
#   --logs all|system  which logs to send (asked; Enter = all)
#   --index NAME       Splunk index for the receiver (default main)
#   --splunk-home DIR  receiver: where Splunk is (default /opt/splunk)
#   --root DIR         treat DIR as / (tests): nothing restarted
#   --no-color         no colours
#   --help             this text plus the common options
#
# OUTPUTS  (under --out, in logship-N/)
#   output.txt, plan.txt, summary.txt, run.txt, revert.sh
#   the config written: /etc/rsyslog.d/90-bt-splunk.conf (sender) or
#   SPLUNK/etc/apps/bt_receiver/local/inputs.conf (receiver)
#
# DEPENDS ON
#   rsyslog with imfile (sender; installed on most Linux boxes); Splunk
#   (receiver).  logger for the test line.
#
# TESTED ON
#   Ubuntu 24.04 with rsyslog 8.2312 (live, sending to a stand-in listener)
#   and a fake root, under dash, bash, busybox sh, ksh93, mksh and yash
#   with gawk, mawk and busybox awk.  The receiver is tested against a
#   stand-in Splunk folder: NOT yet against a real Splunk.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - Open the port on the Splunk box (LX-25) and on any firewall between
#     (NW scripts) - the sender cannot tell whether it arrives.
#   - Plain syslog is not encrypted: fine inside the team network.
#   - Boxes with only journald (no rsyslog): install rsyslog first
#     (apt-get install rsyslog) or forward with systemd-journal-upload.
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
LX-43 Log shipping to Splunk - logs leave the box before red team can clear them
  sudo sh LX-43-log-shipping.sh --receive --apply                 (the Splunk box)
  sudo sh LX-43-log-shipping.sh --send --to 10.0.0.20 --apply     (every other box)

  --apply            make the changes (without it, dry run only)
  --send / --receive this box sends its logs / is the Splunk box
  --to HOST          the Splunk box (sender)
  --port N           TCP/UDP port (default 1514)
  --udp              send over UDP (default TCP)
  --logs all|system  which logs to send
  --index NAME       Splunk index for the receiver (default main)
  --splunk-home DIR  receiver: where Splunk is
  --root DIR         treat DIR as / (tests)
  --no-color         no colours
  --help             show this text
USAGE
    cc_usage_common
}

MODE=""; TO=""; PORT=""; UDP=""; LOGS=""; INDEX=main; SH_HOME=""; R=""; COLOR=1
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --apply)       CC_APPLY=1; shift ;;
        --send)        MODE=send; shift ;;
        --receive)     MODE=receive; shift ;;
        --to)          [ $# -ge 2 ] || cc_die 2 "--to needs an address"; TO=$2; shift 2 ;;
        --port)        [ $# -ge 2 ] || cc_die 2 "--port needs a number"; PORT=$2; shift 2 ;;
        --udp)         UDP=1; shift ;;
        --logs)        [ $# -ge 2 ] || cc_die 2 "--logs needs all or system"; LOGS=$2; shift 2 ;;
        --index)       [ $# -ge 2 ] || cc_die 2 "--index needs a name"; INDEX=$2; shift 2 ;;
        --splunk-home) [ $# -ge 2 ] || cc_die 2 "--splunk-home needs a folder"; SH_HOME=$2; shift 2 ;;
        --root)        [ $# -ge 2 ] || cc_die 2 "--root needs a folder"; [ -d "$2" ] || cc_die 2 "--root: not a folder: $2"; R=$(cd "$2" && pwd); [ "$R" = / ] && R=""; shift 2 ;;
        --no-color|--no-colour) COLOR=0; shift ;;
        --help|-h)     usage; exit 0 ;;
        *)             cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
case "$PORT" in ''|*[!0-9]*) [ -z "$PORT" ] || cc_die 2 "--port needs a number" ;; esac
case "$LOGS" in ''|all|system) ;; *) cc_die 2 "--logs must be all or system" ;; esac
case "$INDEX" in *[!A-Za-z0-9_-]*) cc_die 2 "--index: letters, digits, _ and - only" ;; esac
case "$TO" in *[!A-Za-z0-9.:_-]*) cc_die 2 "--to: a host name or an address" ;; esac

cc_init "LX-43" "Log shipping to Splunk" changes
cc_detect_os
# shellcheck disable=SC2034  # read by cc_color_init
[ "$COLOR" = 1 ] || CC_NOCOLOR=1
cc_color_init
cc_use_numbered_dir logship
rmdir "$CC_RUN_DIR/raw" 2>/dev/null
OUTF="$CC_RUN_DIR/output.txt"
grep -v '\[NOTE\]\|\[DEBUG\]' "$CC_LOG" >"$OUTF" 2>/dev/null || : >"$OUTF"
# shellcheck disable=SC2034  # CC_TEE is read by the library's log functions
CC_TEE=$OUTF
W="$CC_RUN_DIR/.work"; mkdir -p "$W"
header() { cc_show "" ""; cc_show "$C_CYN" "==========[ $1 ]=========="; }
P() { printf '%s%s' "$R" "$1"; }

cc_show "$C_CYN" "LX-43 Log shipping to Splunk | host $CC_HOST | results in $CC_RUN_DIR"
cc_show "" "Legend: ${C_RED}[!]${C_OFF} fix now   ${C_YEL}[*]${C_OFF} look at it   ${C_GRN}[ok]${C_OFF} fine   ${C_YEL}[~] would change${C_OFF}   ${C_GRN}[+] changed${C_OFF}   ${C_RED}[x] failed${C_OFF}"
[ -n "$R" ] && cc_show "$C_GRY" "Acting on $R as if it were / (nothing restarted)"

# ---- Which half -------------------------------------------------------------------------
if [ -z "$SH_HOME" ]; then for _d in /opt/splunk "${SPLUNK_HOME:-}"; do [ -n "$_d" ] && [ -d "$(P "$_d")/etc" ] && { SH_HOME=$_d; break; }; done; fi
if [ -z "$MODE" ]; then
    _d=s; [ -n "$SH_HOME" ] && _d=r
    cc_choose "What does this box do with logs?$([ -n "$SH_HOME" ] && echo " (Splunk is installed here: $SH_HOME)")" "$_d" \
        "s=send: this box sends its logs to the Splunk box" \
        "r=receive: this IS the Splunk box (open a port for the other boxes' logs)"
    case "$CC_CHOICE" in r) MODE=receive ;; *) MODE=send ;; esac
fi
if [ -z "$PORT" ]; then cc_ask_text "Port the logs go to" 1514 "a port number (the same on every box)"; PORT=$CC_ANSWER; fi
case "$PORT" in ''|*[!0-9]*) cc_die 2 "the port must be a number" ;; esac
if [ -z "$UDP" ]; then
    cc_choose "Send over TCP or UDP?" t "t=TCP: nothing is lost; logs wait on disk while Splunk is down" "u=UDP: simplest, but lines can be lost"
    [ "$CC_CHOICE" = u ] && UDP=1
fi
PROTO=tcp; [ "$UDP" = 1 ] && PROTO=udp
NCH=0; : >"$CC_RUN_DIR/plan.txt"
plan() { NCH=$((NCH + 1)); printf '%s\n' "$1" >>"$CC_RUN_DIR/plan.txt"; cc_show "$C_YEL" "  [~] $1"; }
APPLIED=0; NOK=0; NBAD=0
CANAPPLY=0; { [ -n "$R" ] || cc_is_root; } && CANAPPLY=1
go() {
    [ "$NCH" -gt 0 ] || { cc_show "$C_GRN" "  [ok] Nothing to change."; return 1; }
    if [ "$CC_APPLY" != 1 ] || [ "$CANAPPLY" = 0 ]; then
        [ "$CANAPPLY" = 0 ] && cc_show "$C_YEL" "  [!] not root: showing the plan only"
        cc_show "$C_GRY" "  Dry run: nothing was changed. Run again with --apply."
        # shellcheck disable=SC2034  # read by cc_finish
        CC_N_WOULD=$NCH; return 1
    fi
    cc_ask "Apply these $NCH change(s)?" Y "yes, apply them" "no, change nothing" || { cc_show "$C_GRY" "  Not applied."; return 1; }
    APPLIED=1; return 0
}

# ---- Receiver ----------------------------------------------------------------------------
if [ "$MODE" = receive ]; then
    header "1/2  the Splunk box: a port for the other boxes' logs"
    [ -n "$SH_HOME" ] || { cc_show "$C_RED" "  [x] Splunk not found (give --splunk-home DIR)"; rm -rf "$W"; cc_finish; exit 3; }
    APPD="$(P "$SH_HOME")/etc/apps/bt_receiver"; INP="$APPD/local/inputs.conf"
    _have=$(grep -rls "^\[$PROTO://\(.*:\)\?$PORT\]" "$(P "$SH_HOME")"/etc/system/local/inputs.conf "$(P "$SH_HOME")"/etc/apps/*/local/inputs.conf 2>/dev/null | head -n 1)
    if [ -n "$_have" ]; then cc_show "$C_GRN" "  [ok] Splunk already listens on $PROTO $PORT (${_have#"$R"})"
    else plan "Splunk input $PROTO://$PORT, sourcetype syslog, index $INDEX, host = the sender's address (in ${INP#"$R"})"; fi
    cc_show "$C_GRY" "  Open $PROTO $PORT on this box's firewall for the other boxes (LX-25), and on any firewall between them."
    header "2/2  apply"
    if go; then
        mkdir -p "$APPD/local" "$APPD/default"
        cc_undo_add "remove the bt_receiver Splunk app" "rm -rf $(cc_shquote "$APPD")"
        printf '[install]\nstate = enabled\n\n[ui]\nis_visible = false\nlabel = log receiver (LX-43)\n' >"$APPD/default/app.conf"
        printf '# Written by LX-43: logs from the other boxes.\n[%s://%s]\nsourcetype = syslog\nindex = %s\nconnection_host = ip\ndisabled = 0\n' "$PROTO" "$PORT" "$INDEX" >"$INP"
        _ow=$(ls -ld "$(P "$SH_HOME")" | awk '{ print $3 ":" $4 }'); chown -R "$_ow" "$APPD" 2>/dev/null
        cc_show "$C_GRN" "  [+] Splunk input $PROTO://$PORT written"; NOK=1
        if [ -z "$R" ] && cc_ask "Restart Splunk now so it listens (about a minute)?" Y "yes, restart it now" "no, I will restart it later"; then
            "$SH_HOME/bin/splunk" restart --accept-license --answer-yes --no-prompt >>"$CC_LOG" 2>&1
            sleep 2
            if ss -lntu 2>/dev/null | awk '{ print $5 }' | grep -q ":$PORT\$"; then cc_show "$C_GRN" "  [+] Splunk listens on $PORT"
            else cc_show "$C_RED" "  [x] nothing listens on $PORT yet: check $SH_HOME/var/log/splunk/splunkd.log"; NBAD=1; fi
        fi
    fi
    {
        printf '==========[ summary ]==========\n'
        printf 'LX-43 Log shipping | host %s | receiver | %s\n' "$CC_HOST" "$([ "$APPLIED" = 1 ] && echo APPLIED || echo 'DRY RUN - nothing changed')"
        printf 'Splunk input: %s %s, index %s\n' "$PROTO" "$PORT" "$INDEX"
        printf 'Next: on every other box: sudo sh LX-43-log-shipping.sh --send --to %s --port %s%s --apply\n' "$(hostname -I 2>/dev/null | awk '{ print $1 }')" "$PORT" "$([ "$UDP" = 1 ] && echo ' --udp')"
        printf 'Search in Splunk: index=%s sourcetype=syslog | stats count by host\n' "$INDEX"
        [ -f "$CC_RUN_DIR/revert.sh" ] && printf 'Undo: sh %s/revert.sh --force\n' "$CC_RUN_DIR"
    } >"$CC_RUN_DIR/summary.txt"
    cc_show "" ""; while IFS= read -r _l; do cc_show "" "$_l"; done <"$CC_RUN_DIR/summary.txt"
    # shellcheck disable=SC2034  # read by cc_finish
    CC_N_DONE=$NOK
    rm -rf "$W"; cc_finish; exit 0
fi

# ---- Sender -------------------------------------------------------------------------------
header "1/3  this box's logs"
[ -n "$R" ] || cc_have rsyslogd || { cc_show "$C_RED" "  [x] rsyslog is not installed: apt-get install rsyslog (or dnf install rsyslog), then run again"; rm -rf "$W"; cc_finish; exit 3; }
if [ -z "$TO" ]; then cc_ask_text "The Splunk box's address" "" "its IP address or name"; TO=$CC_ANSWER; fi
case "$TO" in ''|*[!A-Za-z0-9.:_-]*) cc_die 2 "the Splunk box's address is needed (--to HOST)" ;; esac
# Service log files: tag|file
: >"$W/files"
for _e in "apache-access|/var/log/apache2/access.log" "apache-error|/var/log/apache2/error.log" "httpd-access|/var/log/httpd/access_log" "httpd-error|/var/log/httpd/error_log" \
          "nginx-access|/var/log/nginx/access.log" "nginx-error|/var/log/nginx/error.log" "maillog|/var/log/mail.log" "maillog|/var/log/maillog" \
          "dovecot|/var/log/dovecot.log" "roundcube|/var/log/roundcube/errors.log" "roundcube-logins|/var/log/roundcube/userlogins.log" \
          "mysql-error|/var/log/mysql/error.log" "mariadb|/var/log/mariadb/mariadb.log" "postgresql|/var/log/postgresql/postgresql-*-main.log" \
          "audit|/var/log/audit/audit.log" "splunk|/opt/splunk/var/log/splunk/splunkd.log" "bt-session|/var/log/bt/sessions.log" "fail2ban|/var/log/fail2ban.log"; do
    _t=${_e%%"|"*}; _f=${_e#*"|"}
    for _x in $(P "$_f"); do [ -f "$_x" ] && printf '%s|%s\n' "$_t" "${_x#"$R"}" >>"$W/files"; done
done
cc_show "" "  System logs (auth, syslog, kern, mail, cron): always sent"
while IFS='|' read -r _t _f; do cc_show "" "  $(printf '%-17s' "$_t") $_f"; done <"$W/files"
[ -s "$W/files" ] || cc_show "$C_GRY" "  (no service log files found)"
if [ -z "$LOGS" ] && [ -s "$W/files" ]; then
    cc_choose "Which logs should go to Splunk?" a "a=all of the above" "s=system logs only" "p=pick the service logs one by one"
    case "$CC_CHOICE" in s) LOGS=system ;; p) LOGS=pick ;; *) LOGS=all ;; esac
fi
case "$LOGS" in
    system) : >"$W/files" ;;
    pick) : >"$W/keep"; while IFS='|' read -r _t _f; do cc_ask "Send $_f?" Y "yes, send it" "no, leave it out" && printf '%s|%s\n' "$_t" "$_f" >>"$W/keep"; done <"$W/files"; mv "$W/keep" "$W/files" ;;
esac

header "2/3  plan"
CONF=/etc/rsyslog.d/90-bt-splunk.conf
{
    printf '# Written by LX-43: send this box'"'"'s logs to Splunk (%s %s:%s).\n# Delete this file and restart rsyslog to stop.\n' "$PROTO" "$TO" "$PORT"
    printf '# Logs wait on disk while the Splunk box cannot be reached.\n'
    printf 'ruleset(name="bt_splunk") {\n    action(type="omfwd" target="%s" port="%s" protocol="%s"\n           queue.type="LinkedList" queue.filename="bt_splunk_q" queue.maxDiskSpace="200m" queue.saveOnShutdown="on"\n           action.resumeRetryCount="-1")\n}\n' "$TO" "$PORT" "$PROTO"
    if [ -s "$W/files" ]; then
        # Service log files go only to Splunk (they already have their own files here).
        printf 'module(load="imfile" PollingInterval="5")\n'
        while IFS='|' read -r _t _f; do
            printf 'input(type="imfile" File="%s" Tag="%s:" Facility="local6" Severity="info" ruleset="bt_splunk")\n' "$_f" "$_t"
        done <"$W/files"
    fi
    printf '# The system logs.\nif prifilt("auth,authpriv.*;*.info;mail.*;cron.*;kern.*") then {\n    call bt_splunk\n}\n'
} >"$W/conf"
if [ -f "$(P "$CONF")" ] && cmp -s "$W/conf" "$(P "$CONF")"; then cc_show "$C_GRN" "  [ok] $CONF is already this"
else plan "write $CONF: send $([ -s "$W/files" ] && echo "the system logs and $(grep -c . "$W/files") service log(s)" || echo 'the system logs') to $TO:$PORT over $PROTO"
    sed 's/^/      /' "$W/conf" | while IFS= read -r _l; do cc_show "$C_GRY" "$_l"; done
    [ -z "$R" ] && plan "restart rsyslog (config checked with rsyslogd -N1 first), then send a test line"
fi
_other=$(grep -lE '^[^#]*(@@?[0-9A-Za-z]|type="omfwd")' "$(P /etc/rsyslog.conf)" "$(P /etc/rsyslog.d)"/*.conf 2>/dev/null | grep -v "90-bt-splunk.conf" | sed "s|^$R||")
[ -n "$_other" ] && cc_show "$C_YEL" "  [*] logs are already sent somewhere by: $_other - one of yours? (red team can send copies of logs out too)"

header "3/3  apply"
TESTID=""
if go; then
    _cf=$(P "$CONF"); mkdir -p "$(dirname "$_cf")"
    if [ -f "$_cf" ]; then cc_backup_file "$_cf" >/dev/null; else cc_undo_add "remove $CONF" "rm -f $(cc_shquote "$_cf")"; fi
    if [ -z "$R" ]; then
        # A restart, or stop + start where the init script has no restart.
        if [ "$CC_INIT" = systemd ]; then _rs="systemctl restart rsyslog"; else _rs="service rsyslog restart || { service rsyslog stop; sleep 1; service rsyslog start; }"; fi
        cc_undo_add "restart rsyslog after its config is put back" "$_rs"
    fi
    cat "$W/conf" >"$_cf"; chmod 644 "$_cf"
    if [ -z "$R" ]; then
        if ! rsyslogd -N1 >>"$CC_LOG" 2>&1; then
            cc_show "$C_RED" "  [x] rsyslog does not accept the config (rsyslogd -N1): put back"
            awk -F'\t' '{ l[NR] = $4 } END { for (i = NR; i > 0; i--) print l[i] }' "$CC_UNDO" | tail -n 2 | while IFS= read -r _c; do sh -c "$_c" >>"$CC_LOG" 2>&1; done
            NBAD=1
        else
            cc_show "$C_GRN" "  [+] wrote $CONF"; NOK=1
            _p0=$(pgrep -x rsyslogd 2>/dev/null | head -n 1)
            sh -c "$_rs" >>"$CC_LOG" 2>&1 </dev/null
            # It must be a NEW rsyslog (the old one never read the new config).
            _i=0; while { _p1=$(pgrep -x rsyslogd 2>/dev/null | head -n 1); [ -z "$_p1" ] || [ "$_p1" = "$_p0" ]; } && [ "$_i" -lt 10 ]; do sleep 1; _i=$((_i + 1)); done
            if [ -n "$_p1" ] && [ "$_p1" = "$_p0" ]; then
                { service rsyslog stop || kill "$_p0"; sleep 1; service rsyslog start || rsyslogd; } >>"$CC_LOG" 2>&1 </dev/null; sleep 2; _p1=$(pgrep -x rsyslogd 2>/dev/null | head -n 1)
            fi
            if [ -n "$_p1" ] && [ "$_p1" != "$_p0" ]; then cc_show "$C_GRN" "  [+] rsyslog restarted (it reads the new config)"
            else cc_show "$C_RED" "  [x] rsyslog did not restart (still pid ${_p1:-none}): restart it by hand, then logger test"; NBAD=1; fi
            TESTID="BT-LX43-TEST-$CC_HOST-$(date +%s)"
            logger -p auth.info "$TESTID" 2>/dev/null && cc_show "$C_GRN" "  [+] test line sent: search Splunk for $TESTID"
        fi
    else cc_show "$C_GRN" "  [+] wrote $CONF"; NOK=1; fi
fi
# shellcheck disable=SC2034  # read by cc_finish
CC_N_DONE=$NOK
# shellcheck disable=SC2034  # read by cc_finish
CC_N_FAIL=$NBAD
{
    printf '==========[ summary ]==========\n'
    printf 'LX-43 Log shipping | host %s | sender | %s\n' "$CC_HOST" "$([ "$APPLIED" = 1 ] && echo APPLIED || echo 'DRY RUN - nothing changed')"
    printf 'To: %s:%s over %s   Service logs: %d\n' "$TO" "$PORT" "$PROTO" "$(grep -c . "$W/files")"
    sed 's/^/  /' "$W/files" | tr '|' ' '
    [ -n "$TESTID" ] && printf '\nIn Splunk, search: "%s"   (nothing? open %s %s on the Splunk box: LX-25, and run LX-43 --receive there)\n' "$TESTID" "$PROTO" "$PORT"
    [ -f "$CC_RUN_DIR/revert.sh" ] && printf 'Undo: sh %s/revert.sh --force\n' "$CC_RUN_DIR"
} >"$CC_RUN_DIR/summary.txt"
cc_show "" ""; while IFS= read -r _l; do case "$_l" in ==*|LX-43*) cc_show "$C_CYN" "$_l" ;; *) cc_show "" "$_l" ;; esac; done <"$CC_RUN_DIR/summary.txt"
rm -rf "$W"
cc_finish
