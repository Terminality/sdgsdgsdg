#!/bin/sh
# Tests for roles/applications/SV-30-service-hardening.sh.
# Uses a fake root (--root) with vsftpd/proftpd config so the file edits can
# be checked; service enable/disable is reported under --root.  --no-protected
# lets --apply run without a protected list in the tests.
. "$(dirname "$0")/helper.sh"
SH=${TEST_SHELL:-sh}
C="$T_ROOT/roles/applications/SV-30-service-hardening.sh"
export BT_SKIP_VERIFY=1
# shellcheck disable=SC2086
run() { $SH "$C" "$@"; }
R="$T_TMP/root"; O="$T_TMP/out"
mkdir -p "$R/etc" "$O"
printf 'root:x:0:0::/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\nalice:x:1000:1000::/home/alice:/bin/bash\n' >"$R/etc/passwd"
mkvsftpd() { printf 'listen=YES\nanonymous_enable=YES\nlocal_enable=YES\nwrite_enable=YES\n' >"$R/etc/vsftpd.conf"; chmod 644 "$R/etc/vsftpd.conf"; rm -f "$R/etc/ftpusers"; }

t_start "options"
run --level bogus >/dev/null 2>&1; t_eq "$?" 2 "a bad --level is refused"
run --only no-such >/dev/null 2>&1; t_eq "$?" 2 "an unknown action is refused"
run --timer x >/dev/null 2>&1; t_eq "$?" 2 "a bad --timer is refused"
t_has "$(run --help 2>&1)" "ftp-anon" "help lists the actions and their risk"

t_start "detects vsftpd and plans the safe fixes (dry run)"
mkvsftpd
r=$(run --root "$R" --out "$O" --batch --no-color 2>&1); t_eq "$?" 0 "exit 0"
t_has "$r" "FTP: vsftpd" "detects vsftpd"
t_has "$r" "anonymous_enable: YES -> NO" "plans anon off"
t_has "$r" "ftpusers" "plans the deny list"
t_has "$r" "mode: 0644 -> 0600" "plans the config perms"
t_fail "nothing was changed in a dry run" grep -qi 'anonymous_enable=NO' "$R/etc/vsftpd.conf"
t_file "$O/service-hardening-1/plan.txt" "plan.txt written"

t_start "--apply needs a protected list"
r=$(run --root "$R" --out "$O" --batch --apply --no-color 2>&1); rc=$?
t_eq "$rc" 3 "refuses to apply with no protected list"
t_has "$r" "protected list" "and says why"

t_start "safe level: apply the FTP fixes"
mkvsftpd
r=$(run --root "$R" --out "$O" --batch --apply --no-protected --no-color 2>&1); t_eq "$?" 0 "exit 0"
t_ok "anonymous login turned off" grep -qi '^anonymous_enable=NO' "$R/etc/vsftpd.conf"
t_ok "root denied FTP" grep -qx 'root' "$R/etc/ftpusers"
t_ok "system account denied FTP" grep -qx 'daemon' "$R/etc/ftpusers"
t_eq "$(stat -c '%a' "$R/etc/vsftpd.conf" 2>/dev/null)" 600 "config locked to 600"
t_has "$r" "[+]" "shows applied changes"

t_ok "transfer logging on" grep -q '^xferlog_enable=YES' "$R/etc/vsftpd.conf"
t_ok "version banner hidden" grep -q '^ftpd_banner=FTP server' "$R/etc/vsftpd.conf"
t_ok "other settings are untouched" grep -q '^local_enable=YES' "$R/etc/vsftpd.conf"
t_eq "$(grep -c . "$R/etc/vsftpd.conf")" 6 "no line lost or doubled"

t_start "an /etc/ftpusers that already exists is added to, and reported as changed"
mkvsftpd; printf 'games\n' >"$R/etc/ftpusers"
r=$(run --root "$R" --out "$O" --batch --apply --no-protected --only ftp-accounts --no-color 2>&1)
t_hasnt "$r" "FAILED" "not reported as failed"
t_ok "the old entry is kept" grep -qx games "$R/etc/ftpusers"
t_ok "root is added" grep -qx root "$R/etc/ftpusers"

t_start "two files changed in one run: each backup holds the original"
mkvsftpd; printf 'games\n' >"$R/etc/ftpusers"
run --root "$R" --out "$T_TMP/o2" --batch --apply --no-protected --level service --no-color >/dev/null 2>&1
_b=$(find "$T_TMP/o2/backup" -name vsftpd.conf | head -n 1)
t_ok "the vsftpd.conf backup is the file from before the run" grep -q '^anonymous_enable=YES' "$_b"
t_fail "and has none of this run's changes" grep -q 'chroot_local_user' "$_b"

t_start "idempotent: a second run finds nothing to change"
mkvsftpd; run --root "$R" --out "$O" --batch --apply --no-protected --no-color >/dev/null 2>&1
r=$(run --root "$R" --out "$O" --batch --apply --no-protected --no-color 2>&1)
t_has "$r" "Nothing to change" "already-hardened box is left alone"

t_start "safe level does not include the service-level chroot"
mkvsftpd
t_hasnt "$(run --root "$R" --out "$O" --batch --no-color 2>&1)" "chroot_local_user" "chroot is not offered at --level safe"
r=$(run --root "$R" --out "$O" --batch --level service --no-color 2>&1)
t_has "$r" "chroot_local_user" "chroot is offered at --level service"
run --root "$R" --out "$O" --batch --level service --apply --no-protected --no-color >/dev/null 2>&1
t_ok "chroot set" grep -qi '^chroot_local_user=YES' "$R/etc/vsftpd.conf"
t_ok "writeable chroot allowed (so it does not break)" grep -qi '^allow_writeable_chroot=YES' "$R/etc/vsftpd.conf"

t_start "--exclude leaves the service alone"
mkvsftpd
r=$(run --root "$R" --out "$O" --batch --exclude vsftpd --no-color 2>&1)
t_has "$r" "Nothing" "excluding vsftpd leaves nothing to do"
t_fail "and plans no FTP change" sh -c "printf '%s' \"$r\" | grep -q 'anonymous_enable'"

t_start "access action named with --only is chosen; reported under --root"
mkvsftpd
r=$(run --root "$R" --out "$O" --batch --level access --only ftp-disable --no-color 2>&1)
t_has "$r" "ftp-disable" "ftp-disable is chosen when named in --only"
t_has "$r" "skipped (--root)" "service disable is reported, not done, under --root"

t_start "proftpd is detected and reported, not edited"
rm -f "$R/etc/vsftpd.conf"; mkdir -p "$R/etc/proftpd"; printf 'ServerName x\n<Anonymous ~ftp>\n  User ftp\n</Anonymous>\n' >"$R/etc/proftpd/proftpd.conf"
r=$(run --root "$R" --out "$O" --batch --no-color 2>&1)
t_has "$r" "FTP: proftpd" "detects proftpd"
t_has "$r" "<Anonymous> block in /etc/proftpd/proftpd.conf" "reports the anonymous block instead of editing it"
t_ok "and leaves the file alone" grep -q '<Anonymous' "$R/etc/proftpd/proftpd.conf"
printf 'ServerName x\n' >"$R/etc/proftpd/proftpd.conf"
t_hasnt "$(run --root "$R" --out "$O" --batch --only ftp-anon --no-color 2>&1)" "check:" "no anonymous block: nothing to report"
rm -rf "$R/etc/proftpd"

t_start "pure-ftpd: anonymous off through its conf folder"
mkdir -p "$R/etc/pure-ftpd/conf"
r=$(run --root "$R" --out "$O" --batch --apply --no-protected --only ftp-anon --no-color 2>&1)
t_has "$r" "FTP: pure-ftpd" "detects pure-ftpd"
t_eq "$(cat "$R/etc/pure-ftpd/conf/NoAnonymous" 2>/dev/null)" yes "NoAnonymous set to yes"
rm -rf "$R/etc/pure-ftpd"

if command -v script >/dev/null 2>&1 && script -qc true /dev/null >/dev/null 2>&1; then
    t_start "asks how far to go when --level is not given"
    mkvsftpd
    # level (service), then Enter for each action, in a terminal.
    printf '\nservice\n\n\n\n\n\n\n\n' >"$T_TMP/ans"
    BT_NO_TTY=0 script -qc "$SH $C --root $R --out $O --no-color" /dev/null <"$T_TMP/ans" >"$T_TMP/tty.out" 2>&1
    t_has "$(cat "$T_TMP/tty.out")" "How far should I go?" "asks for the level"
    t_has "$(cat "$T_TMP/tty.out")" "chroot_local_user" "the typed level (service) is used"
    t_has "$(cat "$T_TMP/tty.out")" "[safe] turn off anonymous FTP login?" "then asks about each action with its risk"
fi

t_start "web, mail and time services (webmail box)"
rm -rf "$R"; mkdir -p "$R/etc/apache2/conf-enabled" "$R/etc/nginx/conf.d" "$R/etc/php/8.3/apache2" "$R/etc/postfix" "$R/etc/dovecot" "$R/etc/chrony" \
    "$R/var/www/html/.git" "$R/var/lib/roundcube/program/include" "$R/var/lib/roundcube/installer"
printf 'include /etc/nginx/conf.d/*.conf;\n' >"$R/etc/nginx/nginx.conf"
printf '[PHP]\nexpose_php = On\n' >"$R/etc/php/8.3/apache2/php.ini"
printf 'smtpd_banner = $myhostname ESMTP $mail_name (Ubuntu)\nsmtpd_relay_restrictions = permit_mynetworks\n    defer_unauth_destination\nmynetworks = 0.0.0.0/0\n' >"$R/etc/postfix/main.cf"
printf '#login_greeting = Dovecot ready.\n!include conf.d/*.conf\n' >"$R/etc/dovecot/dovecot.conf"
printf 'pool x iburst\ncmdallow 10.0.0.0/8\n' >"$R/etc/chrony/chrony.conf"
echo '<?php phpinfo();' >"$R/var/www/html/info.php"; echo x >"$R/var/www/html/site.sql"
echo "define('RCMAIL_VERSION', '1.5.2');" >"$R/var/lib/roundcube/program/include/iniset.php"
_u0=$(cat "$O"/undo-*.log 2>/dev/null | grep -c .)
out=$($SH "$C" --root "$R" --out "$O" --no-color --batch --apply --no-protected --level service --box webmail 2>&1)
t_has "$out" "Scored on webmail: IMAP, SMTP, webmail login" "the box says what is scored"
t_eq "$(cat "$R/etc/apache2/conf-enabled/zz-bt-hardening.conf" | grep -v '^#' | tr '\n' ' ')" "ServerTokens Prod ServerSignature Off TraceEnable Off <Directory /var/www/>     Options -Indexes </Directory> " "Apache drop-in: versions hidden, TRACE and listings off"
t_has "$(cat "$R/etc/nginx/conf.d/zz-bt-hardening.conf")" "server_tokens off;" "nginx version hidden"
t_has "$(cat "$R/etc/php/8.3/apache2/php.ini")" "expose_php = Off" "PHP X-Powered-By off"
mc=$(cat "$R/etc/postfix/main.cf")
t_has "$mc" 'smtpd_banner = $myhostname ESMTP' "Postfix greeting without the name"
t_hasnt "$mc" "(Ubuntu)" "no OS in the greeting"
t_has "$mc" "disable_vrfy_command = yes" "VRFY off"
t_has "$mc" "smtpd_helo_required = yes" "HELO required (service level)"
t_has "$mc" "    defer_unauth_destination" "continuation lines left alone"
t_has "$out" "EVERYONE may relay mail" "open relay (mynetworks 0.0.0.0/0) reported"
dc=$(cat "$R/etc/dovecot/dovecot.conf")
t_has "$dc" "login_greeting = Mail server ready." "IMAP greeting without the name"
t_has "$dc" "auth_failure_delay = 5 secs" "slower failed IMAP logins"
t_has "$(cat "$R/etc/chrony/chrony.conf")" "#bt cmdallow 10.0.0.0/8" "chrony remote control off"
t_has "$out" "no 'allow' line: chrony answers nobody" "chrony not serving time is reported"
t_has "$out" "/var/www/html/.git: can be downloaded by anyone" ".git in the web root reported"
t_has "$out" "/var/www/html/info.php" "phpinfo page reported"
t_has "$out" "Roundcube 1.5.2" "Roundcube version reported"
t_has "$out" "/var/lib/roundcube/installer" "Roundcube installer reported"
t_ok "exposed files are only reported below access level" test -f "$R/var/www/html/info.php"
out=$($SH "$C" --root "$R" --out "$O" --no-color --batch --apply --no-protected --level service --box webmail 2>&1)
t_has "$out" "Nothing to change" "a second run changes nothing"
cat "$O"/undo-*.log | awk -F'\t' -v n="$_u0" 'NR > n { l[NR] = $4 } END { for (i = NR; i > n; i--) print l[i] }' >"$T_TMP/undo30.sh"
sh "$T_TMP/undo30.sh" >/dev/null 2>&1
t_has "$(cat "$R/etc/postfix/main.cf")" '$mail_name (Ubuntu)' "undo puts the Postfix greeting back"
t_fail "undo removes the Apache drop-in" test -f "$R/etc/apache2/conf-enabled/zz-bt-hardening.conf"
t_has "$(cat "$R/etc/php/8.3/apache2/php.ini")" "expose_php = On" "undo puts php.ini back"
out=$($SH "$C" --root "$R" --out "$O" --no-color --batch --apply --no-protected --level access --only web-exposed-remove 2>&1)
t_fail "access level: info.php moved to quarantine" test -f "$R/var/www/html/info.php"
t_fail "access level: Roundcube installer moved" test -d "$R/var/lib/roundcube/installer"
$SH "$C" --box mars >/dev/null 2>&1; t_eq "$?" 2 "a bad --box exits 2"
rm -rf "$R"; mkdir -p "$R/etc"

t_start "Alpine: Apache conf.d and /etc/phpNN"
rm -rf "$R"; mkdir -p "$R/etc/apache2/conf.d" "$R/etc/php83"
printf '[PHP]\nexpose_php = On\n' >"$R/etc/php83/php.ini"
out=$($SH "$C" --root "$R" --out "$O" --no-color --batch --apply --no-protected --level service 2>&1)
t_has "$(cat "$R/etc/apache2/conf.d/zz-bt-hardening.conf" 2>/dev/null)" "ServerTokens Prod" "the Apache drop-in goes in conf.d"
t_has "$(cat "$R/etc/php83/php.ini")" "expose_php = Off" "PHP in /etc/php83 is found"

t_start "nothing to do when no service is present"
rm -rf "$R"; mkdir -p "$R/etc"
r=$(run --root "$R" --out "$O" --batch --no-color 2>&1)
t_has "$r" "nothing to harden" "says there is nothing to harden"
t_done
