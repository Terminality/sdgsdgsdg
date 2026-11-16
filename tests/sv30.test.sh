#!/bin/sh
# Tests for roles/applications/SV-30-service-hardening.sh.
# Uses a fake root (--root) with vsftpd/proftpd config so the file edits can
# be checked; service enable/disable is reported under --root.  --no-protected
# lets --apply run without a protected list in the tests.
. "$(dirname "$0")/helper.sh"
SH=${TEST_SHELL:-sh}
C="$T_ROOT/roles/applications/SV-30-service-hardening.sh"
export CCDC_SKIP_VERIFY=1
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

t_start "idempotent: a second run finds nothing to change"
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
rm -f "$R/etc/vsftpd.conf"; mkdir -p "$R/etc/proftpd"; printf 'ServerName x\n' >"$R/etc/proftpd/proftpd.conf"
r=$(run --root "$R" --out "$O" --batch --no-color 2>&1)
t_has "$r" "FTP: proftpd" "detects proftpd"
t_has "$r" "set anonymous_enable=NO by hand" "reports the proftpd change instead of writing it"
rm -rf "$R/etc/proftpd"

t_start "nothing to do when no service is present"
r=$(run --root "$R" --out "$O" --batch --no-color 2>&1)
t_has "$r" "nothing to harden" "says there is nothing to harden"
t_done
