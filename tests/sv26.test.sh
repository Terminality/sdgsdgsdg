#!/bin/sh
# Tests for roles/linux/SV-26-banning.sh.
# Sample logs for every service it reads, and stand-in firewalls: the nft
# stand-in keeps banned addresses in a file; the iptables/ipset stand-ins
# record their commands.  Checks the limits, the never-ban list, the separate
# web limit, spam reports, that lines are counted once, that a rotated log is
# read again, that a dry run keeps no state, and --unban / --list.
. "$(dirname "$0")/helper.sh"
SH=${TEST_SHELL:-sh}
C="$T_ROOT/roles/linux/SV-26-banning.sh"
export CCDC_SKIP_VERIFY=1
# shellcheck disable=SC2086
run() { $SH "$C" --batch --no-color "$@"; }
# row ADDR -> the first report line about ADDR (label, services, counts).
row() { printf '%s\n' "$out" | grep '^  \[' | grep -F " $1 " | head -n 1; }
O="$T_TMP/out"; B="$T_TMP/bin"; L="$T_TMP/logs"; ST="$T_TMP/state"
mkdir -p "$O" "$B" "$L"
BANNED="$T_TMP/banned.txt"; FW_LOG="$T_TMP/fw.log"; export BANNED FW_LOG
: >"$BANNED"; : >"$FW_LOG"
cat >"$B/nft" <<'STUB'
#!/bin/sh
# stand-in nft: the table exists once created; banned addresses live in $BANNED
case "$*" in
    "list tables") exit 0 ;;
    "list table inet ccdc_ban") [ -f "$BANNED.table" ] || exit 1
        printf 'table inet ccdc_ban {\n set ban4 {\n  elements = { %s }\n }\n}\n' "$(sed 's/$/ timeout 30m expires 29m/' "$BANNED" | paste -sd, -)" ;;
    "-f "*) : >"$BANNED.table" ;;
    "add element inet ccdc_ban "*) ip=$(echo "$*" | sed 's/.*{ \([^ ]*\) .*/\1/'); echo "$ip" >>"$BANNED" ;;
    "delete element inet ccdc_ban "*) ip=$(echo "$*" | sed 's/.*{ \([^ ]*\) }.*/\1/'); grep -vx "$ip" "$BANNED" >"$BANNED.t"; mv "$BANNED.t" "$BANNED" ;;
    *) exit 1 ;;
esac
STUB
printf '#!/bin/sh\necho "iptables $*" >>"$FW_LOG"\n[ "$1" = -C ] && exit 1\n[ "$1" = -S ] && exit 0\nexit 0\n' >"$B/iptables"
printf '#!/bin/sh\necho "ipset $*" >>"$FW_LOG"\n[ "$1" = list ] && exit 1\nexit 0\n' >"$B/ipset"
chmod +x "$B/nft" "$B/iptables" "$B/ipset"
CCDC_NFT="$B/nft"; CCDC_IPTABLES="$B/iptables"; CCDC_IPSET="$B/ipset"; export CCDC_NFT CCDC_IPTABLES CCDC_IPSET

# Sample logs: 12 SSH failures from .66, 3 from .77, 12 from the protected
# scoring host .99, FTP/mail/IMAP failures from .88, 40 WordPress login POSTs
# from .55 (web limit 30), 10 from .44, and a mailbox sending to 300 people.
i=0; : >"$L/auth.log"
while [ $i -lt 12 ]; do
    echo "Nov 11 10:00:0$((i % 10)) web01 sshd[100$i]: Failed password for invalid user admin$i from 10.6.6.66 port 4$i ssh2" >>"$L/auth.log"
    echo "Nov 11 10:00:0$((i % 10)) web01 sshd[200$i]: Failed password for root from 10.9.9.99 port 5$i ssh2" >>"$L/auth.log"
    i=$((i + 1))
done
for i in 1 2 3; do echo "Nov 11 10:01:0$i web01 sshd[30$i]: Failed password for bob from 10.7.7.77 port 6$i ssh2" >>"$L/auth.log"; done
echo "Nov 11 10:02:00 web01 sshd[400]: Connection closed by invalid user oracle 10.6.6.66 port 7000 [preauth]" >>"$L/auth.log"
: >"$L/vsftpd.log"; : >"$L/mail.log"
for i in 1 2 3 4; do
    echo "Tue Nov 11 10:03:0$i 2026 [pid 9$i] [ftpuser] FAIL LOGIN: Client \"::ffff:10.8.8.88\"" >>"$L/vsftpd.log"
    echo "Nov 11 10:03:0$i mail postfix/smtpd[5$i]: warning: unknown[10.8.8.88]: SASL LOGIN authentication failed: UGFzc3dvcmQ6" >>"$L/mail.log"
    echo "Nov 11 10:03:0$i mail dovecot: imap-login: Disconnected (auth failed, 1 attempts in 2 secs): user=<alice>, method=PLAIN, rip=10.8.8.88, lip=10.0.0.5" >>"$L/mail.log"
done
echo "Nov 11 10:04:00 mail postfix/qmgr[60]: 4AB12C: from=<alice@team.local>, size=1200, nrcpt=300 (queue active)" >>"$L/mail.log"
: >"$L/access.log"
i=0; while [ $i -lt 40 ]; do echo "10.5.5.55 - - [11/Nov/2026:10:05:00 +0000] \"POST /wp-login.php HTTP/1.1\" 200 512 \"-\" \"curl\"" >>"$L/access.log"; i=$((i + 1)); done
i=0; while [ $i -lt 10 ]; do echo "10.4.4.44 - - [11/Nov/2026:10:05:00 +0000] \"POST /wp-login.php HTTP/1.1\" 200 512 \"-\" \"Mozilla\"" >>"$L/access.log"; i=$((i + 1)); done
echo "10.4.4.44 - - [11/Nov/2026:10:05:01 +0000] \"GET / HTTP/1.1\" 200 512 \"-\" \"Mozilla\"" >>"$L/access.log"
printf 'type,value,note\nhost,10.9.9.99,scoring engine\n' >"$T_TMP/protected.csv"
LOGARGS="--log $L/auth.log --log $L/vsftpd.log --log $L/mail.log --log $L/access.log"

t_start "options"
run --max-fails abc >/dev/null 2>&1; t_eq "$?" 2 "non-number limit exits 2"
run --ignore 10.0.0.999/8 >/dev/null 2>&1; t_eq "$?" 2 "bad --ignore exits 2"
run --loop 5 >/dev/null 2>&1; t_eq "$?" 2 "--loop under 10 seconds exits 2"

t_start "dry run"
# shellcheck disable=SC2086
out=$(run --out "$O" --state "$ST" --protected "$T_TMP/protected.csv" --ignore 10.7.7.0/24 $LOGARGS 2>&1); rc=$?
t_eq "$rc" 0 "exit 0"
t_has "$out" "Mode: DRY RUN" "says it is a dry run"
t_has "$(row 10.6.6.66)" "[*] WOULD BAN" "SSH brute force would be banned"
t_has "$(row 10.6.6.66)" "13 fails" "with its count"
t_has "$out" "accounts tried: admin0 admin1 admin2 admin3 admin4 +8 more" "accounts tried listed"
t_has "$(row 10.8.8.88)" "WOULD BAN" "FTP + SMTP + IMAP failures add up"
t_has "$(row 10.5.5.55)" "WOULD BAN" "web login flood over the web limit"
t_has "$(row 10.4.4.44)" "[-] watching" "10 web logins are under the web limit: watched"
t_hasnt "$out" "10.7.7.77" "an ignored network is quiet when under the limit"
t_has "$(row 10.9.9.99)" "[*] NOT BANNED" "protected scoring host never banned"
t_has "$out" "a protected host - probably the scoring engine" "and why"
t_has "$out" "SPAM?         alice@team.local sent to 300 recipients" "spam reported"
t_has "$out" "Would ban: 3 (dry run" "summary count"
t_has "$out" "/auth.log  (SSH, PAM logins)" "logs listed with what they hold"
t_has "$out" "10.7.7.0/24              your team / scoring" "never-ban list shown with reasons"
t_ok "run folder with output.txt" test -s "$O/banning-1/output.txt"
t_hasnt "$(cat "$O/banning-1/output.txt")" "$(printf '\033')" "output.txt has no colour codes"
t_ok "bans.txt table" grep -q 10.6.6.66 "$O/banning-1/bans.txt"
t_ok "offenders.csv lists the watched address too" grep -q '10.4.4.44.*watch' "$O/banning-1/csv/offenders.csv"
t_has "$(cat "$ST/settings")" "never=10.7.7.0/24" "answers saved for next time"
t_eq "$(grep -c . "$BANNED")" 0 "dry run bans nothing"
t_fail "dry run keeps no offsets" test -s "$ST/offsets"

t_start "--apply"
# shellcheck disable=SC2086
out=$(run --out "$O" --state "$ST" --protected "$T_TMP/protected.csv" --apply $LOGARGS 2>&1)
b=$(cat "$BANNED")
t_has "$b" "10.6.6.66" "SSH attacker banned"
t_has "$b" "10.8.8.88" "mail/FTP attacker banned"
t_has "$b" "10.5.5.55" "web attacker banned"
t_hasnt "$b" "10.9.9.99" "scoring host not banned"
t_has "$(cat "$ST/bans.csv")" "10.6.6.66,ssh,13,\"admin0 admin1 admin2 admin3 admin4 +8 more\",+30min,banned" "bans.csv records services, count and accounts tried"
# shellcheck disable=SC2086
out=$(run --out "$O" --state "$ST" --protected "$T_TMP/protected.csv" --apply $LOGARGS 2>&1)
t_has "$out" "Mode: BANNING" "says it is banning"
t_has "$out" "check 1: 0 new failed login(s)" "lines are counted once"
t_has "$(row 10.6.6.66)" "[-] still banned" "no double ban"
t_has "$(cat "$ST/settings")" "never=10.7.7.0/24" "never-ban answer kept from the last run"
t_eq "$(grep -c 10.6.6.66 "$BANNED")" 1 "banned once"

t_start "rotation, list, unban"
: >"$L/auth.log"
for i in 1 2 3 4 5 6 7 8 9 10 11; do echo "Nov 11 11:00:00 web01 sshd[9$i]: Failed password for root from 10.3.3.33 port 1$i ssh2" >>"$L/auth.log"; done
# shellcheck disable=SC2086
out=$(run --out "$O" --state "$ST" --protected "$T_TMP/protected.csv" --apply $LOGARGS 2>&1)
t_has "$(cat "$BANNED")" "10.3.3.33" "a rotated (shorter) log is read from the start"
out=$(run --out "$O" --state "$ST" --list 2>&1)
t_has "$out" "10.3.3.33" "--list shows bans"
run --out "$O" --state "$ST" --apply --no-protected --unban 10.3.3.33 >/dev/null 2>&1
t_hasnt "$(cat "$BANNED")" "10.3.3.33" "--unban removes the ban"

t_start "ipset and iptables backends"
: >"$FW_LOG"; rm -rf "$ST"
run --out "$O" --state "$ST" --backend ipset --apply --no-protected --log "$L/auth.log" >/dev/null 2>&1
t_has "$(cat "$FW_LOG")" "ipset add ccdc_ban 10.3.3.33 timeout 1800 -exist" "ipset ban with a timeout"
t_has "$(cat "$FW_LOG")" "iptables -I INPUT 1 -m set --match-set ccdc_ban src -j DROP" "one iptables rule for the set"
: >"$FW_LOG"; rm -rf "$ST"
run --out "$O" --state "$ST" --backend iptables --apply --no-protected --log "$L/auth.log" >/dev/null 2>&1
t_has "$(cat "$FW_LOG")" "iptables -I INPUT 1 -s 10.3.3.33 -j DROP -m comment --comment ccdc_ban" "plain iptables ban"
t_file "$ST/iptables-expiry" "expiry recorded for plain iptables"
t_start "an attacker cannot choose who gets banned (log injection)"
: >"$BANNED"; rm -f "$BANNED.table"; : >"$FW_LOG"
: >"$L/inj.log"
i=0; while [ $i -lt 12 ]; do
    # Account names that try to look like "from ADDRESS port N".
    echo "Nov 11 12:00:00 web01 sshd[5$i]: Failed password for invalid user x from 10.2.2.22 port 1 from 10.1.1.11 port 6$i ssh2" >>"$L/inj.log"
    echo "Nov 11 12:00:00 web01 sshd[6$i]: Failed password for invalid user y from 0.0.0.0/0 port 1 from 10.1.1.11 port 7$i ssh2" >>"$L/inj.log"
    echo "Nov 11 12:00:00 web01 sshd[7$i]: Connection closed by invalid user z 10.2.2.23 port 9 10.1.1.11 port 8$i [preauth]" >>"$L/inj.log"
    echo "Nov 11 12:00:00 web01 sshd[8$i]: Failed password for root from evil.example.com port 9$i ssh2" >>"$L/inj.log"
    i=$((i + 1))
done
out=$(run --out "$O" --state "$T_TMP/state-inj" --log "$L/inj.log" --backend iptables --apply --no-protected 2>&1)
t_has "$(row 10.1.1.11)" "BANNED" "the real source address is banned"
t_hasnt "$out" "10.2.2.22" "the address inside the account name is not"
t_hasnt "$out" "10.2.2.23" "nor the one in a 'Connection closed' line"
t_hasnt "$(cat "$FW_LOG")" "0.0.0.0/0" "a network never reaches the firewall"
t_hasnt "$(cat "$FW_LOG")" "evil.example.com" "nor does a host name"

t_start "web: only login pages count, not every admin request"
: >"$L/web2.log"
i=0; while [ $i -lt 40 ]; do
    echo "10.8.8.81 - - [11/Nov/2026:12:05:00 +0000] \"POST /wp-admin/admin-ajax.php HTTP/1.1\" 200 50 \"-\" \"Mozilla\"" >>"$L/web2.log"
    echo "10.8.8.82 - - [11/Nov/2026:12:05:00 +0000] \"POST /user/login?next=/ HTTP/1.1\" 200 50 \"-\" \"curl\"" >>"$L/web2.log"
    i=$((i + 1))
done
out=$(run --out "$O" --state "$T_TMP/state-web2" --log "$L/web2.log" --no-protected 2>&1)
t_hasnt "$out" "10.8.8.81" "a signed-in admin's requests are not counted"
t_has "$(row 10.8.8.82)" "WOULD BAN" "a flood on a login page still is"

t_start "services, dry loop, unban-all, questions"
out=$(run --out "$O" --state "$T_TMP/state-svc" --no-protected --services ssh $LOGARGS 2>&1)
t_has "$(row 10.3.3.33)" "WOULD BAN" "ssh still counted with --services ssh"
t_hasnt "$out" "10.8.8.88" "ftp/mail failures ignored with --services ssh"
t_hasnt "$out" "10.5.5.55" "web ignored with --services ssh"
run --services telnet >/dev/null 2>&1; t_eq "$?" 2 "an unknown service exits 2"
out=$(run --out "$O" --state "$T_TMP/state-loop" --no-protected --loop 10 --count 2 --log "$L/auth.log" 2>&1)
t_has "$out" "check 2: 0 new failed login(s)" "a dry loop reads each line once"
t_eq "$(printf '%s\n' "$out" | grep -c 'WOULD BAN')" 1 "and reports the would-ban once"
t_fail "a dry loop keeps no offsets" test -s "$T_TMP/state-loop/offsets"
: >"$BANNED"; touch "$BANNED.table"; echo 10.6.6.66 >"$BANNED"
printf '2026-11-11T10:00:00Z,10.6.6.66,ssh,13,"root",+30min,banned\n' >>"$ST/bans.csv"
out=$(run --out "$O" --state "$ST" --list 2>&1)
t_has "$out" "10.6.6.66" "--list shows the ban"
t_has "$out" "ssh" "--list says why"
cat >"$B/nft2" <<'STUB'
#!/bin/sh
echo "nft $*" >>"$FW_LOG"
case "$*" in "list tables"|"list table inet ccdc_ban") exit 0 ;; esac; exit 0
STUB
chmod +x "$B/nft2"; : >"$FW_LOG"
CCDC_NFT="$B/nft2" run --out "$O" --state "$ST" --apply --no-protected --unban-all >/dev/null 2>&1
t_has "$(cat "$FW_LOG")" "nft delete table inet ccdc_ban" "--unban-all removes the ban table"
t_has "$(cat "$ST/bans.csv")" "--unban-all" "and records it"
if command -v script >/dev/null 2>&1; then
    # fails: 5 | web: Enter | ban: 60 | services: ssh | never: 10.0.0.9 | seconds: 0
    printf '5\n\n60\nssh\n10.0.0.9\n0\n' >"$T_TMP/answers"
    out=$(CCDC_NO_TTY=0 script -qc "$SH '$C' --no-color --out '$O' --state '$T_TMP/state-q' --no-protected --log '$L/auth.log'" /dev/null <"$T_TMP/answers" 2>&1)
    t_has "$out" "How many failed logins (SSH, FTP, mail)" "asks the failure limit"
    t_has "$out" "Addresses never to ban" "asks who never to ban"
    t_has "$out" "How often should it check?" "asks how often"
    t_has "$out" "Ban after:    5 failed logins" "typed limit used"
    t_has "$out" "Ban length:   60 minutes" "typed ban length used"
    t_has "$(cat "$T_TMP/state-q/settings")" "never=10.0.0.9" "typed never-ban saved"
else
    t_ok "script(1) not installed - skipped" true
fi
t_done
