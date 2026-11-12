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
out=$(run --out "$O" --root "$R" --apply --no-protected 2>&1); rc=$?
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
out=$(run --out "$O" --root "$R" --apply --no-protected 2>&1)
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
out=$(run --out "$O" --root "$R" --apply --protected "$T_TMP/protected.csv" --only perms 2>&1)
t_eq "$(mode "$R/etc/shadow")" 0644 "protected file left alone"
t_eq "$(mode "$R/etc/sudoers")" 0640 "other files still fixed"
run --out "$O" --root "$R" --apply --no-protected --keep-ipv6 --only ipv6,sysctl >/dev/null 2>&1
t_eq "$(sysctl -n net.ipv6.conf.all.disable_ipv6)" 0 "--keep-ipv6 leaves IPv6 on"
run --out "$O" --root "$R" --apply --no-protected --only sysctl >/dev/null 2>&1
t_eq "$(sysctl -n net.ipv4.ip_forward)" 1 "forwarding is opt-in"
run --out "$O" --root "$R" --apply --no-protected --no-forwarding >/dev/null 2>&1
t_eq "$(sysctl -n net.ipv4.ip_forward)" 0 "--no-forwarding turns forwarding off"
t_done
