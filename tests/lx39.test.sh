#!/bin/sh
# Tests for roles/linux/LX-39-safe-fixes.sh.
# Everything happens in a fake root folder (--root) with planted problems, and
# a stand-in 'sysctl' that keeps kernel settings in a text file, so the test
# never touches the real system.  Checks: the dry run changes nothing; --apply
# fixes each planted problem; running the undo log puts everything back; a
# protected path is left alone; a second run finds nothing to do.
. "$(dirname "$0")/helper.sh"
SH=${TEST_SHELL:-sh}
C="$T_ROOT/roles/linux/LX-39-safe-fixes.sh"
export CCDC_SKIP_VERIFY=1
# shellcheck disable=SC2086
run() { $SH "$C" "$@"; }
O="$T_TMP/out"; R="$T_TMP/root"; B="$T_TMP/bin"
mkdir -p "$O" "$B"

# Stand-in sysctl: "sysctl -n key" and "sysctl -w key=value" on a state file.
cat >"$B/sysctl" <<'STUB'
#!/bin/sh
S=$SYSCTL_STATE
case "$1" in
    -n) awk -F= -v k="$2" '$1 == k { print $2; f = 1 } END { exit !f }' "$S" || exit 255 ;;
    -w) k=${2%%=*}; v=${2#*=}
        grep -q "^$k=" "$S" || exit 255
        # Like the kernel: "all.disable_ipv6" also changes every interface,
        # loopback included.
        awk -F= -v k="$k" -v v="$v" '$1 == k || (k == "net.ipv6.conf.all.disable_ipv6" && $1 == "net.ipv6.conf.lo.disable_ipv6") { $0 = $1 "=" v } { print }' "$S" >"$S.t" && mv "$S.t" "$S"
        echo "$k = $v" ;;
    *)  exit 1 ;;
esac
STUB
chmod +x "$B/sysctl"
PATH="$B:$PATH"; export PATH
SYSCTL_STATE="$T_TMP/sysctl.state"; export SYSCTL_STATE
# Full path: busybox sh would otherwise run its own built-in sysctl, which
# changes the REAL kernel.  The script and this test both use the stand-in.
CCDC_SYSCTL="$B/sysctl"; export CCDC_SYSCTL
# The revert timer as a background job, never a real systemd unit.
CCDC_TIMER_METHOD=background; export CCDC_TIMER_METHOD
sysctl() { "$B/sysctl" "$@"; }

# mode PATH -> octal mode (portable, like the script itself).
mode() { ls -ld "$1" | awk '{ p = $1; s = 0; u = 0; g = 0; o = 0
    if (substr(p,2,1) == "r") u += 4; if (substr(p,3,1) == "w") u += 2; if (substr(p,4,1) ~ /[xs]/) u += 1
    if (substr(p,5,1) == "r") g += 4; if (substr(p,6,1) == "w") g += 2; if (substr(p,7,1) ~ /[xs]/) g += 1
    if (substr(p,8,1) == "r") o += 4; if (substr(p,9,1) == "w") o += 2; if (substr(p,10,1) ~ /[xt]/) o += 1
    if (substr(p,10,1) ~ /[tT]/) s += 1; printf "%d%d%d%d\n", s, u, g, o }'; }

# plant -> (re)build the fake root with every problem the fixes look for.
plant() {
    rm -rf "$R"; mkdir -p "$R/etc/sudoers.d" "$R/etc/ssh" "$R/etc/cron.d" "$R/etc/profile.d" "$R/etc/security/limits.d" \
        "$R/etc/sysctl.d" "$R/root" "$R/tmp" "$R/home/bob" "$R/usr/bin"
    printf 'root:x:0:0:root:/root:/bin/bash\nbob:x:1000:1000::/home/bob:/bin/bash\n' >"$R/etc/passwd"; chmod 644 "$R/etc/passwd"
    printf 'root:*:1::::::\n' >"$R/etc/shadow"; chmod 644 "$R/etc/shadow"
    printf 'root ALL=(ALL) ALL\n' >"$R/etc/sudoers"; chmod 644 "$R/etc/sudoers"  # sudoers text, not an array: posix-ok
    printf 'bob ALL=(ALL) ALL\n' >"$R/etc/sudoers.d/bob"; chmod 666 "$R/etc/sudoers.d/bob"  # posix-ok
    printf 'KEY\n' >"$R/etc/ssh/ssh_host_rsa_key"; chmod 644 "$R/etc/ssh/ssh_host_rsa_key"
    printf 'PermitRootLogin no\n' >"$R/etc/ssh/sshd_config"; chmod 666 "$R/etc/ssh/sshd_config"
    chmod 755 "$R/root"
    printf '* * * * * root true\n' >"$R/etc/crontab"; chmod 666 "$R/etc/crontab"
    printf '* * * * * root true\n' >"$R/etc/cron.d/job"; chmod 666 "$R/etc/cron.d/job"
    printf 'export A=1\n' >"$R/etc/profile.d/a.sh"; chmod 666 "$R/etc/profile.d/a.sh"
    printf 'x\n' >"$R/etc/world.conf"; chmod 666 "$R/etc/world.conf"
    printf 'x\n' >"$R/usr/bin/tool"; chmod 777 "$R/usr/bin/tool"
    chmod 777 "$R/tmp"
    printf '/lib/x86_64-linux-gnu/libevil.so\n' >"$R/etc/ld.so.preload"
    printf 'PATH="/usr/bin"\nLD_PRELOAD=/lib/libevil.so\n' >"$R/etc/environment"
    printf '+ +\n' >"$R/home/bob/.rhosts"
    printf 'trusted.example\n' >"$R/etc/hosts.equiv"
    printf '127.0.0.1 localhost\n10.6.6.6 security.ubuntu.com\n' >"$R/etc/hosts"
    printf 'net.ipv4.tcp_syncookies=0\nkernel.randomize_va_space=0\nnet.ipv4.conf.all.accept_redirects=1\nnet.ipv6.conf.all.disable_ipv6=0\nnet.ipv6.conf.default.disable_ipv6=0\nnet.ipv6.conf.lo.disable_ipv6=0\nnet.ipv4.ip_forward=1\nfs.suid_dumpable=2\n' >"$SYSCTL_STATE"
}

t_start "options"
run --only nothing >/dev/null 2>&1; t_eq "$?" 2 "unknown fix exits 2"
run --root "$T_TMP/no/such" >/dev/null 2>&1; t_eq "$?" 2 "missing --root folder exits 2"
out=$(run --list); t_has "$out" "preload" "--list shows the fixes"

t_start "dry run changes nothing"
plant
out=$(run --out "$O" --root "$R" 2>&1); rc=$?
t_eq "$rc" 0 "exit 0"
t_has "$out" "DRY RUN" "says dry run"
t_eq "$(mode "$R/etc/shadow")" 0644 "shadow untouched"
t_file "$R/etc/ld.so.preload" "preload untouched"
t_eq "$(sysctl -n net.ipv4.tcp_syncookies)" 0 "kernel setting untouched"
t_has "$out" "WOULD CHANGE  perms      /etc/shadow" "lists the shadow change"
t_has "$out" "/etc/hosts: 10.6.6.6 security.ubuntu.com" "reports the pinned update host"
t_has "$out" "net.ipv4.ip_forward: IP forwarding is on" "reports forwarding without changing it"

t_start "--apply fixes every planted problem"
out=$(run --out "$O" --root "$R" --apply --batch --no-protected 2>&1); rc=$?
t_eq "$rc" 0 "exit 0"
t_eq "$(mode "$R/etc/shadow")" 0640 "shadow loses other read"
t_eq "$(mode "$R/etc/sudoers.d/bob")" 0640 "sudoers.d file loses group write and other access"
t_eq "$(mode "$R/etc/ssh/ssh_host_rsa_key")" 0640 "host key loses other read"
t_eq "$(mode "$R/etc/ssh/sshd_config")" 0644 "sshd_config loses write for others"
t_eq "$(mode "$R/root")" 0700 "/root becomes 700"
t_eq "$(mode "$R/etc/cron.d/job")" 0644 "cron job not writable by others"
t_eq "$(mode "$R/etc/profile.d/a.sh")" 0644 "profile.d script not writable by others"
t_eq "$(mode "$R/etc/world.conf")" 0664 "world-writable file in /etc fixed"
t_eq "$(mode "$R/usr/bin/tool")" 0775 "world-writable program fixed"
t_eq "$(mode "$R/tmp")" 1777 "/tmp gets the sticky bit"
t_fail "ld.so.preload quarantined" test -e "$R/etc/ld.so.preload"
t_has "$(cat "$R/etc/environment")" "# disabled by LX-39: LD_PRELOAD=" "LD_PRELOAD line commented out"
t_fail ".rhosts quarantined" test -e "$R/home/bob/.rhosts"
t_fail "hosts.equiv quarantined" test -e "$R/etc/hosts.equiv"
t_file "$R/etc/security/limits.d/99-ccdc-safe.conf" "core limit file written"
t_has "$(cat "$R/etc/sysctl.d/99-zz-ccdc-safe.conf")" "net.ipv6.conf.all.disable_ipv6 = 1" "boot file has the IPv6 setting"
t_eq "$(sysctl -n net.ipv4.tcp_syncookies)" 1 "SYN cookies on"
t_eq "$(sysctl -n kernel.randomize_va_space)" 2 "ASLR full"
t_eq "$(sysctl -n net.ipv6.conf.all.disable_ipv6)" 1 "IPv6 off"
t_eq "$(sysctl -n net.ipv6.conf.lo.disable_ipv6)" 0 "but still on for loopback (::1 stays)"
t_eq "$(tail -n 1 "$R/etc/sysctl.d/99-zz-ccdc-safe.conf")" "net.ipv6.conf.lo.disable_ipv6 = 0" "boot file switches loopback back on, after the all setting"
t_eq "$(sysctl -n fs.suid_dumpable)" 0 "setuid core dumps off"
t_eq "$(sysctl -n net.ipv4.ip_forward)" 1 "forwarding left on without --no-forwarding"
t_has "$(cat "$R/etc/hosts")" "10.6.6.6" "/etc/hosts never changed"

t_start "a second run finds nothing to do"
out=$(run --out "$O" --root "$R" --apply --batch --no-protected 2>&1)
t_has "$out" "Nothing to change" "idempotent"

t_start "the undo log puts everything back"
U=$(ls "$O"/undo-*.log)
# Run the undo commands from the bottom up (newest first).
awk -F'\t' '{ l[NR] = $4 } END { for (i = NR; i >= 1; i--) print l[i] }' "$U" >"$T_TMP/undo.sh"
sh "$T_TMP/undo.sh" >/dev/null 2>&1
t_eq "$(mode "$R/etc/shadow")" 0644 "shadow mode restored"
t_eq "$(mode "$R/tmp")" 0777 "/tmp mode restored"
t_file "$R/etc/ld.so.preload" "preload file put back"
t_file "$R/home/bob/.rhosts" ".rhosts put back"
t_hasnt "$(cat "$R/etc/environment")" "disabled by LX-39" "/etc/environment restored"
t_eq "$(sysctl -n net.ipv4.tcp_syncookies)" 0 "kernel setting restored"
t_fail "boot file removed" test -e "$R/etc/sysctl.d/99-zz-ccdc-safe.conf"
rm -f "$U"

t_start "protected list and options"
plant
printf 'type,value,note\npath,%s,scored\n' "$R/etc/shadow" >"$T_TMP/protected.csv"
printf 'path,/etc/shadow,scored\n' >>"$T_TMP/protected.csv"
out=$(run --out "$O" --root "$R" --apply --batch --protected "$T_TMP/protected.csv" --only perms 2>&1)
t_eq "$(mode "$R/etc/shadow")" 0644 "protected file left alone"
t_eq "$(mode "$R/etc/sudoers")" 0640 "other files still fixed"
run --out "$O" --root "$R" --apply --batch --no-protected --keep-ipv6 --only ipv6,sysctl >/dev/null 2>&1
t_eq "$(sysctl -n net.ipv6.conf.all.disable_ipv6)" 0 "--keep-ipv6 leaves IPv6 on"
run --out "$O" --root "$R" --apply --batch --no-protected --only sysctl >/dev/null 2>&1
t_eq "$(sysctl -n net.ipv4.ip_forward)" 1 "forwarding is opt-in"
run --out "$O" --root "$R" --apply --batch --no-protected --no-forwarding >/dev/null 2>&1
t_eq "$(sysctl -n net.ipv4.ip_forward)" 0 "--no-forwarding turns forwarding off"
t_start "output: numbered folders, readable files, colour-free when piped"
plant
out=$(run --out "$T_TMP/o2" --root "$R" 2>&1)
t_file "$T_TMP/o2/safe-fixes-1/output.txt" "first run is safe-fixes-1"
t_file "$T_TMP/o2/safe-fixes-1/plan.txt" "plan.txt written"
t_has "$out" "==========[ PLAN (dry run: nothing is changed yet) ]==========" "plan section"
t_has "$out" "[~] /etc/shadow  0644 -> 0640" "planned change shown live"
t_has "$out" "[?] Which box is this? splunk / webmail / ecomm / other other (default)" "box question takes its default with no terminal"
t_hasnt "$out" "$(printf '\033')" "no colour codes when piped"
t_has "$(cat "$T_TMP/o2/safe-fixes-1/output.txt")" "==========[ SUMMARY ]==========" "output.txt has everything"
run --out "$T_TMP/o2" --root "$R" >/dev/null 2>&1
t_file "$T_TMP/o2/safe-fixes-2/output.txt" "next run is safe-fixes-2"

t_start "revert timer: no answer -> everything put back"
plant
out=$(run --out "$T_TMP/o3" --root "$R" --apply --no-protected --timer 10 2>&1)
D="$T_TMP/o3/safe-fixes-1"
t_has "$out" "Revert timer started" "timer announced"
t_has "$out" "touch $D/KEEP" "says how to keep the changes from another session"
t_eq "$(mode "$R/etc/shadow")" 0640 "changed right after the run"
t_hasnt "$out" "this was a dry run" "the end line does not call an applied run a dry run"
sleep 12
t_file "$D/REVERTED" "the timer ran the revert"
t_eq "$(mode "$R/etc/shadow")" 0644 "shadow mode put back"
t_file "$R/etc/ld.so.preload" "quarantined file put back"
t_eq "$(sysctl -n net.ipv4.tcp_syncookies)" 0 "kernel setting put back"
t_has "$(cat "$D/revert.log")" "undone: restore mode of /etc/shadow" "revert.log lists what was undone"

t_start "revert timer: KEEP from another session stops it"
plant
out=$(run --out "$T_TMP/o4" --root "$R" --apply --no-protected --timer 10 2>&1)
D="$T_TMP/o4/safe-fixes-1"
: >"$D/KEEP"
sleep 12
t_fail "no revert after KEEP" test -e "$D/REVERTED"
t_eq "$(mode "$R/etc/shadow")" 0640 "change kept"
sh "$D/revert.sh" --force
t_eq "$(mode "$R/etc/shadow")" 0644 "revert.sh --force still undoes it later"

t_start "timer runs out before applying: nothing is changed"
plant
out=$(run --out "$T_TMP/o8" --root "$R" --apply --no-protected --timer 2 2>&1)
sleep 3
t_eq "$(mode "$R/etc/shadow")" 0644 "a change after the deadline is refused or reverted"

t_start "--batch keeps, --no-timer has no timer"
plant
out=$(run --out "$T_TMP/o5" --root "$R" --apply --batch --no-protected --timer 10 2>&1)
t_has "$out" "Changes kept (--batch)" "--batch keeps the changes"
sleep 12
t_eq "$(mode "$R/etc/shadow")" 0640 "still changed after the timer would have fired"
plant
out=$(run --out "$T_TMP/o6" --root "$R" --apply --no-protected --no-timer 2>&1)
t_has "$out" "No revert timer (--no-timer)" "--no-timer warns"
t_fail "--no-timer writes no revert.sh" test -e "$T_TMP/o6/safe-fixes-1/revert.sh"
run --timer abc >/dev/null 2>&1; t_eq "$?" 2 "bad --timer exits 2"
run --box mars >/dev/null 2>&1; t_eq "$?" 2 "bad --box exits 2"

t_start "questions answered at a terminal (needs 'script')"
if command -v script >/dev/null 2>&1 && script -qc true /dev/null >/dev/null 2>&1; then
    plant
    # Answers: box splunk; sysctl n; ipv6 n; routes? n; forwarding off? y;
    # coredumps n; perms y; tmp n; logging n; preload n; trust n; hosts n;
    # apply y; keep y.
    printf 'splunk\nn\nn\nn\ny\nn\ny\nn\nn\nn\nn\nn\ny\ny\n' >"$T_TMP/answers"
    CCDC_NO_TTY=0 script -qc "$SH $C --out $T_TMP/o7 --root $R --no-protected --no-color --timer 60" /dev/null <"$T_TMP/answers" >"$T_TMP/tty.out" 2>&1
    out=$(cat "$T_TMP/o7/safe-fixes-1/output.txt" 2>/dev/null)
    t_has "$out" "Scored here: chrony" "the box answer shows that box's scored services"
    t_eq "$(mode "$R/etc/shadow")" 0640 "perms (answered y) applied"
    t_eq "$(sysctl -n net.ipv4.tcp_syncookies)" 0 "sysctl (answered n) not applied"
    t_eq "$(sysctl -n net.ipv4.ip_forward)" 0 "forwarding (answered y) turned off"
    t_file "$R/etc/ld.so.preload" "preload (answered n) left alone"
    t_file "$T_TMP/o7/safe-fixes-1/KEEP" "keep answered y"
else
    t_start "(skipped: no 'script' command)"
fi
t_done
