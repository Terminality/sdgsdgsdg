#!/bin/sh
# Tests for roles/linux/LX-43-log-shipping.sh.
# Sender on a fake root (--root): the service logs it finds become imfile
# inputs, the forward goes to --to:--port over TCP (or UDP), "system only"
# leaves the files out, a second run finds nothing to do, the undo removes
# the file.  Receiver on a stand-in Splunk folder: the bt_receiver app with
# a TCP input, and a second run sees it is there.  With BT_TEST_LOGS=1, as
# root, with rsyslog: the real sender sends to a local nc listener and the
# test line arrives; then it is undone.
. "$(dirname "$0")/helper.sh"
SH=${TEST_SHELL:-sh}
C="$T_ROOT/roles/linux/LX-43-log-shipping.sh"
export BT_SKIP_VERIFY=1
O="$T_TMP/out"; F="$T_TMP/root"
CF="$F/etc/rsyslog.d/90-bt-splunk.conf"

mkroot() {
    rm -rf "$F"; mkdir -p "$F/etc/rsyslog.d" "$F/var/log/apache2" "$F/var/log/roundcube" "$F/opt/splunk/etc/apps/search/local" "$F/opt/splunk/bin"
    : >"$F/etc/rsyslog.conf"; : >"$F/var/log/apache2/access.log"; : >"$F/var/log/mail.log"; : >"$F/var/log/roundcube/userlogins.log"
    printf '*.* @@203.0.113.9:514\n' >"$F/etc/rsyslog.d/40-other.conf"
}
run() { $SH "$C" --root "$F" --out "$O" --no-color "$@"; }

t_start "options"
$SH "$C" --logs some >/dev/null 2>&1; t_eq "$?" 2 "a bad --logs exits 2"
$SH "$C" --port x >/dev/null 2>&1; t_eq "$?" 2 "a bad --port exits 2"
$SH "$C" --to 'a;b' >/dev/null 2>&1; t_eq "$?" 2 "an odd --to exits 2"
out=$($SH "$C" --help 2>&1); t_has "$out" "--receive" "--help"

t_start "sender"
mkroot
out=$(run --send --to 10.0.0.20 --batch --logs all 2>&1)
t_has "$out" "apache-access     /var/log/apache2/access.log" "the Apache log is found"
t_has "$out" "roundcube-logins  /var/log/roundcube/userlogins.log" "the Roundcube login log too"
t_has "$out" "logs are already sent somewhere by: /etc/rsyslog.d/40-other.conf" "another forward is flagged"
t_has "$out" "Dry run: nothing was changed" "dry run without --apply"
t_fail "a dry run writes nothing" test -f "$CF"
out=$(run --send --to 10.0.0.20 --batch --logs all --no-protected --apply 2>&1)
t_ok "the config is written" test -f "$CF"
t_has "$(cat "$CF")" 'target="10.0.0.20" port="1514" protocol="tcp"' "to the Splunk box over TCP 1514"
t_has "$(cat "$CF")" 'queue.type="LinkedList" queue.filename="bt_splunk_q"' "disk-buffered"
t_has "$(cat "$CF")" 'File="/var/log/apache2/access.log" Tag="apache-access:"' "the Apache log is an imfile input"
t_has "$(cat "$CF")" 'File="/var/log/mail.log" Tag="maillog:"' "the mail log too"
t_has "$(cat "$CF")" 'if prifilt("auth,authpriv.*;*.info;mail.*;cron.*;kern.*")' "and the system logs"
t_eq "$(grep -n 'ruleset(name=' "$CF" | cut -d: -f1)" "$(( $(grep -n 'imfile' "$CF" | head -n 1 | cut -d: -f1) - 5 ))" "the ruleset comes before the inputs"
out=$(run --send --to 10.0.0.20 --batch --logs all 2>&1)
t_has "$out" "is already this" "a second run finds nothing to do"
_u0=0
cat "$O"/undo-*.log | awk -F'\t' -v n="$_u0" 'NR > n { l[NR] = $4 } END { for (i = NR; i > n; i--) print l[i] }' >"$T_TMP/undo.sh"
sh "$T_TMP/undo.sh" >/dev/null 2>&1
t_fail "undo removes the config" test -f "$CF"
out=$(run --send --to 10.0.0.20 --batch --logs system --udp --no-protected --apply 2>&1)
t_hasnt "$(cat "$CF")" "imfile" "system only: no service files"
t_has "$(cat "$CF")" 'protocol="udp"' "--udp"

t_start "receiver"
mkroot
out=$(run --receive --splunk-home /opt/splunk --batch --no-protected --apply 2>&1)
I="$F/opt/splunk/etc/apps/bt_receiver/local/inputs.conf"
t_ok "the receiver app is written" test -f "$I"
t_has "$(cat "$I")" "[tcp://1514]" "a TCP input on 1514"
t_has "$(cat "$I")" "sourcetype = syslog" "as syslog"
t_has "$(cat "$I")" "connection_host = ip" "with the sender's address as host"
t_has "$out" "--send --to" "the summary says what to run on the other boxes"
out=$(run --receive --splunk-home /opt/splunk --batch 2>&1)
t_has "$out" "already listens on tcp 1514" "a second run sees the input"

t_start "questions on a terminal"
if command -v script >/dev/null 2>&1; then
    mkroot; rm -f "$CF"
    # send; port Enter (1514); TCP Enter; Splunk address; logs: pick; apache y, mail y, roundcube n; apply Enter
    printf 's\n\n\n10.9.9.9\np\ny\ny\nn\n\n' >"$T_TMP/ans"
    tt=$(BT_NO_TTY=0 script -qc "$SH '$C' --root '$F' --out '$O' --no-color --no-protected --apply" /dev/null <"$T_TMP/ans" 2>&1)
    t_has "$tt" "[r] receive: this IS the Splunk box" "the first question lists its answers"
    t_has "$tt" "[p] pick the service logs one by one" "the logs question too"
    t_has "$(cat "$CF")" 'target="10.9.9.9"' "the typed address is used"
    t_hasnt "$(cat "$CF")" "userlogins" "the log answered n is left out"
    t_has "$(cat "$CF")" "access.log" "the ones answered y are in"
fi

if [ "${BT_TEST_LOGS:-0}" = 1 ] && [ "$(id -u)" = 0 ] && command -v rsyslogd >/dev/null 2>&1 && command -v nc >/dev/null 2>&1; then
    t_start "real rsyslog (BT_TEST_LOGS=1)"
    : >"$T_TMP/rx"; nc -lk 15143 >"$T_TMP/rx" 2>/dev/null & NCP=$!
    sleep 1
    _u0=$(cat "$O"/undo-*.log 2>/dev/null | grep -c .)
    out=$($SH "$C" --out "$O" --no-color --send --to 127.0.0.1 --port 15143 --batch --logs system --no-protected --apply 2>&1)
    t_has "$out" "rsyslog restarted" "rsyslog restarts with the config"
    _id=$(printf '%s\n' "$out" | sed -n 's/.*search Splunk for \(BT-LX43-TEST-[^ ]*\).*/\1/p')
    _i=0; while ! grep -q "$_id" "$T_TMP/rx" && [ "$_i" -lt 20 ]; do sleep 1; _i=$((_i + 1)); done
    t_ok "the test line arrives at the listener" grep -q "$_id" "$T_TMP/rx"
    cat "$O"/undo-*.log | awk -F'\t' -v n="$_u0" 'NR > n { l[NR] = $4 } END { for (i = NR; i > n; i--) print l[i] }' >"$T_TMP/undo2.sh"
    sh "$T_TMP/undo2.sh" >/dev/null 2>&1 </dev/null
    t_fail "undo removes the real config" test -f /etc/rsyslog.d/90-bt-splunk.conf
    kill "$NCP" 2>/dev/null
fi
t_done
