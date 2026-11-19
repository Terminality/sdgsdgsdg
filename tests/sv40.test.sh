#!/bin/sh
# Tests for roles/applications/SV-40-mail-passwords.sh.
# A fake root (--root) with stand-in chpasswd/usermod that edit its
# /etc/shadow, and a stand-in "doveconf -n" (BT_DOVECONF) with a pam
# passdb, a passwd-file, a master passdb and a static one: users with a
# mailbox are found (others left out), master and static are flagged; the
# dry run changes nothing; --apply changes the shadow hash and the
# passwd-file line, keeps passwords out of every output; a typed answer
# locks; the undo puts every hash back.  With BT_TEST_MAIL=1, as root,
# with Dovecot answering on 993 or 143: a throwaway account btsv40 is made,
# rotated, logged in with over IMAP, put back, and removed.
. "$(dirname "$0")/helper.sh"
SH=${TEST_SHELL:-sh}
C="$T_ROOT/roles/applications/SV-40-mail-passwords.sh"
export BT_SKIP_VERIFY=1
O="$T_TMP/out"; F="$T_TMP/root"; B="$T_TMP/bin"
mkdir -p "$B"
cat >"$B/chpasswd" <<'STUB'
#!/bin/sh
# Stand-in chpasswd: edits $SV40_ROOT/etc/shadow.  -e takes the hash as is;
# otherwise a fake hash of the password (never the password itself).
e=0; [ "$1" = -e ] && e=1
while IFS=: read -r u p; do
    if [ "$e" = 1 ]; then h=$p; else h="\$6\$fake\$$(printf '%s' "$p" | cksum | cut -d' ' -f1)"; fi
    awk -F: -v OFS=: -v u="$u" -v h="$h" '$1 == u { $2 = h } { print }' "$SV40_ROOT/etc/shadow" >"$SV40_ROOT/etc/shadow.n" && mv "$SV40_ROOT/etc/shadow.n" "$SV40_ROOT/etc/shadow"
done
STUB
cat >"$B/usermod" <<'STUB'
#!/bin/sh
[ "$1" = -L ] || exit 1
awk -F: -v OFS=: -v u="$2" '$1 == u { $2 = "!" $2 } { print }' "$SV40_ROOT/etc/shadow" >"$SV40_ROOT/etc/shadow.n" && mv "$SV40_ROOT/etc/shadow.n" "$SV40_ROOT/etc/shadow"
STUB
chmod +x "$B/chpasswd" "$B/usermod"
SV40_ROOT=$F; BT_CHPASSWD="$B/chpasswd"; BT_USERMOD="$B/usermod"; BT_DOVECONF="$T_TMP/doveconf"
export SV40_ROOT BT_CHPASSWD BT_USERMOD BT_DOVECONF
unset SUDO_USER

mkroot() {
    rm -rf "$F"; mkdir -p "$F/etc/dovecot" "$F/var/mail" "$F/home/bob/Maildir"
    printf 'root:x:0:0::/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/sh\nbob:x:1001:1001::/home/bob:/bin/sh\ncarol:x:1002:1002::/home/carol:/bin/sh\nlocked:x:1003:1003::/home/locked:/bin/sh\n' >"$F/etc/passwd"
    printf 'root:$6$r$root:1::::::\nalice:$6$a$alice:1::::::\nbob:$6$b$bob:1::::::\ncarol:$6$c$carol:1::::::\nlocked:!$6$l$locked:1::::::\n' >"$F/etc/shadow"
    : >"$F/var/mail/alice"; : >"$F/var/mail/locked"
    printf 'vuser:{PLAIN}OldVirt40x::::::\nother:{SHA512-CRYPT}$6$o$other::::::\n' >"$F/etc/dovecot/users"
    printf 'boss:{PLAIN}Master40x\n' >"$F/etc/dovecot/master-users"
    cat >"$BT_DOVECONF" <<'EOF'
passdb {
  driver = pam
}
passdb {
  args = scheme=PLAIN /etc/dovecot/users
  driver = passwd-file
}
passdb {
  args = /etc/dovecot/master-users
  driver = passwd-file
  master = yes
}
passdb {
  args = password=letmein
  driver = static
}
EOF
}
run() { $SH "$C" --root "$F" --out "$O" --no-color --box webmail "$@"; }
snap() { cat "$F/etc/shadow" "$F/etc/dovecot/users" | cksum; }

t_start "options"
$SH "$C" --box moon >/dev/null 2>&1; t_eq "$?" 2 "a bad --box exits 2"
$SH "$C" --length 4 >/dev/null 2>&1; t_eq "$?" 2 "a short --length exits 2"
out=$($SH "$C" --help 2>&1); t_has "$out" "--all-accounts" "--help"

t_start "find the users"
mkroot; before=$(snap)
out=$(run --batch 2>&1)
t_has "$out" "alice" "a system account with /var/mail is a mail user"
t_has "$out" "bob" "one with ~/Maildir too"
t_hasnt "$out" "carol" "one with no mailbox is left out"
t_hasnt "$out" "root   " "root is not a mail user"
t_has "$out" "vuser" "a passwd-file user is found"
t_has "$out" "MASTER users in /etc/dovecot/master-users" "master users are flagged"
t_has "$out" "boss" "with their names"
t_has "$out" '"static" passdb' "a static passdb is flagged"
t_has "$out" "Dry run: nothing was changed" "dry run without --apply"
t_eq "$(snap)" "$before" "a dry run changes nothing"
out=$(run --batch --all-accounts 2>&1); t_has "$out" "carol" "--all-accounts takes every human account"
$SH "$C" --root "$F" --out "$O" --box webmail --batch --users nobodyhere >/dev/null 2>&1; t_eq "$?" 2 "a typo in --users stops the run"
t_fail "no CSV files are left" sh -c "find '$O' -name '*.csv' | grep -q ."

t_start "apply"
_u0=$(cat "$O"/undo-*.log 2>/dev/null | grep -c .)
if command -v script >/dev/null 2>&1; then
    # one by one: alice r, bob l, vuser r, other r; then Enter to apply
    printf 'y\nr\nl\nr\nr\n\n' >"$T_TMP/ans"
    out=$(BT_NO_TTY=0 script -qc "$SH '$C' --root '$F' --out '$O' --no-color --box webmail --no-protected --apply" /dev/null <"$T_TMP/ans" 2>&1)
    t_has "$out" "[s] set one" "each user lists its answers"
    t_has "$out" "bob (system): locked" "the typed answer l locks"
    t_eq "$(awk -F: '$1 == "bob" { print substr($2, 1, 1) }' "$F/etc/shadow")" "!" "bob is locked in shadow"
else
    out=$(run --batch --no-protected --apply 2>&1)
fi
d=$(ls -d "$O"/mail-passwords-* | sort -t- -k3 -n | tail -n 1)
t_eq "$(ls -l "$d/passwords.txt" | cut -c1-10)" "-rw-------" "passwords.txt is root only"
t_hasnt "$(awk -F: '$1 == "alice"' "$F/etc/shadow")" '$6$a$alice' "alice has a new hash"
t_has "$(awk -F: '$1 == "vuser"' "$F/etc/dovecot/users")" "{SHA512-CRYPT}\$6\$" "vuser has a SHA512-CRYPT hash"
t_hasnt "$(cat "$F/etc/dovecot/users")" "OldVirt40x" "the old plain password is gone"
t_has "$(awk -F: '$1 == "vuser"' "$F/etc/dovecot/users")" "::::::" "the rest of the line is kept"
_np=$(awk '$2 == "vuser" { print $3 }' "$d/passwords.txt")
t_ok "the new password is in passwords.txt" test -n "$_np"
t_fail "and not in output.txt" grep -q "$_np" "$d/output.txt"
t_fail "nor in the log" sh -c "grep -q '$_np' '$O'/*.log"
t_fail "nor in summary.txt or users.txt" grep -q "$_np" "$d/summary.txt" "$d/users.txt"
t_has "$(cat "$d/summary.txt")" "login not tested here" "--root: no login test"

t_start "undo"
cat "$O"/undo-*.log | awk -F'\t' -v n="$_u0" 'NR > n { l[NR] = $4 } END { for (i = NR; i > n; i--) print l[i] }' >"$T_TMP/undo.sh"
sh "$T_TMP/undo.sh" >/dev/null 2>&1
t_eq "$(snap)" "$before" "undo puts every hash and line back"
t_has "$(ls "$d")" "passwords-UNDONE-not-valid.txt" "the passwords file is marked not valid"

if [ "${BT_TEST_MAIL:-0}" = 1 ] && [ "$(id -u)" = 0 ] && command -v doveconf >/dev/null 2>&1 && command -v openssl >/dev/null 2>&1; then
    t_start "a real Dovecot (BT_TEST_MAIL=1)"
    unset BT_CHPASSWD BT_USERMOD BT_DOVECONF
    imap() { (printf 'a LOGIN "%s" "%s"\n' "$1" "$2"; sleep 4; printf 'b LOGOUT\n'; sleep 1) | timeout 15 openssl s_client -connect 127.0.0.1:993 -quiet -crlf 2>/dev/null | grep -c '^a OK'; }
    userdel -r btsv40 >/dev/null 2>&1
    useradd -m -s /bin/sh btsv40 && printf 'btsv40:Old40Mail!x\n' | chpasswd && : >/var/mail/btsv40
    t_eq "$(imap btsv40 'Old40Mail!x')" 1 "the old password logs in before"
    _u0=$(cat "$O"/undo-*.log 2>/dev/null | grep -c .)
    $SH "$C" --out "$O" --no-color --box webmail --batch --users btsv40 --no-protected --apply --no-timer >"$T_TMP/live" 2>&1
    t_has "$(cat "$T_TMP/live")" "btsv40 (system): changed, IMAP login tested" "rotated and tested over IMAP"
    d=$(ls -d "$O"/mail-passwords-* | sort -t- -k3 -n | tail -n 1)
    _np=$(awk '$2 == "btsv40" { print $3 }' "$d/passwords.txt")
    t_eq "$(imap btsv40 "$_np")" 1 "the new password logs in"
    t_eq "$(imap btsv40 'Old40Mail!x')" 0 "the old one does not"
    cat "$O"/undo-*.log | awk -F'\t' -v n="$_u0" 'NR > n { l[NR] = $4 } END { for (i = NR; i > n; i--) print l[i] }' | sh >/dev/null 2>&1
    t_eq "$(imap btsv40 'Old40Mail!x')" 1 "undo: the old password logs in again"
    userdel -r btsv40 >/dev/null 2>&1; rm -f /var/mail/btsv40
fi
t_done
