#!/bin/sh
# Tests for roles/linux/SH-05-linux-enum.sh.
# Runs the real enum against this machine.  Checks that it works under
# every shell, produces its files, changes nothing, and - when run as root -
# flags problems planted in a private temp folder.
. "$(dirname "$0")/helper.sh"
SH=${TEST_SHELL:-sh}
C="$T_ROOT/roles/linux/SH-05-linux-enum.sh"
export BT_SKIP_VERIFY=1
# shellcheck disable=SC2086
run() { $SH "$C" "$@"; }

t_start "options"
run --nope >/dev/null 2>&1; t_eq "$?" 2 "unknown option exits 2"
run --profile huge >/dev/null 2>&1; t_eq "$?" 2 "unknown profile exits 2"
run --only system,bogus >/dev/null 2>&1; t_eq "$?" 2 "unknown section exits 2"
r=$(run --list 2>&1); t_has "$r" "autostart" "--list names the sections"
r=$(run --help 2>&1); t_has "$r" "--profile" "--help shows the options"

t_start "card profile runs and writes its files"
r=$(run --out "$T_TMP/o1" --profile card 2>"$T_TMP/err1"); t_eq "$?" 0 "exits 0"
RUN=$(ls -d "$T_TMP"/o1/linux-enum-*/ 2>/dev/null | head -n 1)
for f in summary.txt flags.txt facts.txt users.txt ports.txt services.txt autostart.txt sudo.txt; do t_file "$RUN/$f" "$f written"; done
t_fail "no CSV files are left" sh -c "find '$RUN' -name '*.csv' | grep -q ."
t_has "$(sed -n 1p "$RUN/users.txt")" "user " "users.txt is a table with a header"
t_has "$(sed -n 1p "$RUN/users.txt")" " | " "split by | (SH-04 reads it)"
t_hasnt "$(cat "$RUN/users.txt")" '","' "users.txt is not CSV"
t_has "$r" "section        rows" "summary table printed"
t_has "$r" "==========[ 1/8  system ]==========" "a header per section, printed live"
t_has "$r" "[ok] nothing to fix here" "a section with nothing to fix says so"
t_hasnt "$r" "$(printf '\033')" "no colour codes when the output is not a terminal"
t_eq "$RUN" "$T_TMP/o1/linux-enum-1/" "the first run folder is linux-enum-1"
t_file "$RUN/output.txt" "output.txt written"
t_has "$(cat "$RUN/output.txt")" "==========[ 2/8  users ]==========" "output.txt has the live output"
t_has "$(cat "$RUN/run.txt")" "id=SH-05" "run.txt records the ID"
t_has "$(cat "$RUN/output.txt")" "[INFO] SH-05: start:" "output.txt has the start line"
t_has "$(cat "$RUN/output.txt")" "[INFO] SH-05: done:" "output.txt has the info lines up to the end"
t_has "$(cat "$RUN/output.txt")" "==========[ SUMMARY ]==========" "output.txt has the summary"
run --out "$T_TMP/o1" --only system >/dev/null 2>&1
t_file "$T_TMP/o1/linux-enum-2/summary.txt" "the next run is linux-enum-2"
t_has "$r" "Accounts that can log in:" "users summary line printed"
t_fail "card does not run the slow sections" test -f "$RUN/suid.txt"
t_fail "work folder removed" test -d "$RUN/.work"
t_ok "facts.txt has the hostname key (ksh and mksh once lost every key)" grep -q '^hostname *|' "$RUN/facts.txt"
t_eq "$(head -n 1 "$RUN/users.txt" | tr -s ' ')" "user | uid | gid | home | shell | can_login | password | groups" "users.txt header"
t_ok "root is listed in users.txt" grep -q '^root *| 0 ' "$RUN/users.txt"
t_hasnt "$(cat "$RUN"/*.txt "$T_TMP"/o1/*.log)" '$6$' "no password hash anywhere in the output"

t_start "--only and --skip"
run --out "$T_TMP/o2" --only system,users >/dev/null 2>&1; t_eq "$?" 0 "--only exits 0"
R2=$(ls -d "$T_TMP"/o2/linux-enum-*/ | head -n 1)
t_file "$R2/users.txt" "--only ran users"; t_fail "--only skipped ports" test -f "$R2/ports.txt"
run --out "$T_TMP/o3" --profile card --skip ports,sudo >/dev/null 2>&1
R3=$(ls -d "$T_TMP"/o3/linux-enum-*/ | head -n 1)
t_fail "--skip left ports out" test -f "$R3/ports.txt"; t_file "$R3/users.txt" "--skip kept the rest"

t_start "planted problems are flagged (root only)"
if [ "$(id -u)" = 0 ]; then
    P="$T_TMP/plant"; mkdir -p "$P"
    # A real file path is needed: under busybox, 'command -v find' prints the
    # applet name "find", not a path.
    for _fb in /usr/bin/find /bin/find; do [ -f "$_fb" ] && break; done
    cp "$_fb" "$P/find" && chmod 4755 "$P/find"
    printf 'type,value,note\n' >"$P/dummy"
    run --out "$T_TMP/o4" --only files >/dev/null 2>&1; t_eq "$?" 0 "files section exits 0"
    R4=$(ls -d "$T_TMP"/o4/linux-enum-*/ | head -n 1)
    t_ok "planted SUID copy of find is in suid.txt" grep -q "$P/find" "$R4/suid.txt"
    t_ok "planted SUID copy of find is flagged HIGH" grep -q "^HIGH  *files  *$P/find" "$R4/flags.txt"
    rm -f "$P/find"
else
    t_start "(skipped: not root)"
fi

t_start "privesc: planted problems in a fake system folder"
F="$T_TMP/fakeroot"; B="$T_TMP/bin"
mkdir -p "$F/etc/cron.d" "$F/etc/systemd/system" "$F/etc/sudoers.d" "$B"
printf '#!/bin/sh\necho hi\n' >"$B/backup.sh"; chmod 777 "$B/backup.sh"
printf '#!/bin/sh\necho ok\n' >"$B/safe.sh"; chmod 755 "$B/safe.sh"
printf '#!/bin/sh\necho svc\n' >"$B/svc"; chmod 777 "$B/svc"
printf '#!/bin/sh\necho other\n' >"$B/other"; chmod 777 "$B/other"
printf '%s\n' "17 * * * * root $B/backup.sh >/dev/null" "18 * * * * root sh $B/safe.sh" "19 * * * * bob $B/other" >"$F/etc/crontab"
printf '[Service]\nExecStart=%s --flag\n' "$B/svc" >"$F/etc/systemd/system/bad.service"
printf '[Service]\nUser=redis\nExecStart=%s\n' "$B/other" >"$F/etc/systemd/system/redis.service"
printf '%s\n' 'Defaults env_keep += "LD_PRELOAD"' 'bob ALL=(root) NOPASSWD: /usr/bin/vim, /usr/bin/id' 'root ALL=(ALL) ALL' >"$F/etc/sudoers"  # posix-ok: sudoers text, not shell
printf 'root:x:0:\n' >"$F/etc/shadow"; chmod 644 "$F/etc/shadow"
# export inside $( ): ksh does not pass VAR=x in front of a function call on
# to the programs the function starts.
r=$(BT_TEST_ROOT="$F"; export BT_TEST_ROOT; run --out "$T_TMP/o6" --only privesc 2>&1); t_eq "$?" 0 "privesc exits 0"
R6=$(ls -d "$T_TMP"/o6/linux-enum-*/ | head -n 1)
t_has "$r" "==========[ 1/1  privesc ]==========" "privesc section runs"
t_has "$r" "[!] FIX   $B/backup.sh: a root cron job runs this file, and anyone can write it" "writable root cron script is a FIX"
t_hasnt "$r" "$B/safe.sh:" "a root cron script nobody else can write is not flagged"
t_hasnt "$r" "$B/other: a root cron" "another user's cron job is not a root job"
t_has "$r" "[!] FIX   $B/svc: the root service bad.service runs this file" "writable program of a root service is a FIX"
t_hasnt "$r" "redis.service" "a service that runs as another user is skipped"
t_has "$r" "bob: may run /usr/bin/vim with sudo" "sudo rule for a shell-escape program is a FIX"
t_hasnt "$r" "/usr/bin/id with sudo" "a harmless sudo program is not flagged"
t_has "$r" "sudo keeps LD_PRELOAD" "env_keep LD_PRELOAD is a FIX"
t_has "$r" "anyone can read the password hashes" "readable shadow file is a FIX"
t_has "$(head -n 1 "$R6/privesc.txt")" " | " "privesc.txt is a table"
r=$(PATH=".:$PATH"; export PATH; run --out "$T_TMP/o7" --only privesc 2>&1)
t_has "$r" "the PATH includes the current folder" "'.' on the PATH is a FIX"

t_start "it changes nothing"
before=$(ls -la /etc | cksum)
run --out "$T_TMP/o5" --only system,users,ssh,sudo,pam >/dev/null 2>&1
t_eq "$(ls -la /etc | cksum)" "$before" "/etc listing unchanged"

t_start "SELinux (Rocky, Fedora)"
# Stand-ins: getenforce, semanage and semodule on PATH; a fake root for the files.
SE="$T_TMP/se"; mkdir -p "$SE/bin" "$SE/root/etc/selinux" "$SE/root/proc" "$SE/root/etc/default"
printf '#!/bin/sh\necho Permissive\n' >"$SE/bin/getenforce"
cat >"$SE/bin/semanage" <<'STUB'
#!/bin/sh
case "$1 $2" in
    "permissive -l") echo "httpd_t" ;;
    "boolean -l") echo "httpd_execmem                  (on   ,  off)  Allow httpd to execmem" ;;
    "fcontext -l") echo "/tmp/x(/.*)?    all files   system_u:object_r:bin_t:s0" ;;
esac
STUB
printf '#!/bin/sh\nprintf "100 base pp\\n200 container pp\\n400 sshbackdoor pp\\n"\n' >"$SE/bin/semodule"
chmod +x "$SE/bin/"*
printf 'SELINUX=enforcing\nSELINUXTYPE=targeted\n' >"$SE/root/etc/selinux/config"
printf 'BOOT_IMAGE=/vmlinuz root=/dev/sda1 enforcing=0 quiet\n' >"$SE/root/proc/cmdline"
printf 'GRUB_CMDLINE_LINUX="rhgb quiet selinux=0"\n' >"$SE/root/etc/default/grub"
r=$(PATH="$SE/bin:$PATH" BT_TEST_ROOT="$SE/root"; export PATH BT_TEST_ROOT; run --out "$T_TMP/ose" --only mac 2>&1); t_eq "$?" 0 "mac exits 0"
RS=$(ls -d "$T_TMP"/ose/linux-enum-*/ | head -n 1); fl=$(cat "$RS/flags.txt")
t_has "$fl" "configured as enforcing but currently Permissive" "switched off since boot is HIGH"
t_has "$fl" "the kernel was started with enforcing=0" "off on the kernel command line is HIGH"
t_has "$fl" "/etc/default/grub turns SELinux off at boot (selinux=0" "off in GRUB is HIGH"
t_has "$fl" "permissive domain httpd_t" "a permissive domain is HIGH"
t_has "$fl" "boolean changed on this box: httpd_execmem = on" "a changed boolean is listed"
t_has "$fl" "policy module sshbackdoor was added on this box" "a module added by hand is listed"
t_hasnt "$fl" "policy module base" "the distribution's modules are not"
t_has "$fl" "1 file label rule(s) added" "local file labels are counted"
t_has "$(grep '^HIGH' "$RS/flags.txt")" "permissive domain" "HIGH ones first"
printf 'SELINUX=permissive\n' >"$SE/root/etc/selinux/config"; printf 'BOOT_IMAGE=/vmlinuz\n' >"$SE/root/proc/cmdline"; : >"$SE/root/etc/default/grub"
printf '#!/bin/sh\necho Enforcing\n' >"$SE/bin/getenforce"
r=$(PATH="$SE/bin:$PATH" BT_TEST_ROOT="$SE/root"; export PATH BT_TEST_ROOT; run --out "$T_TMP/ose2" --only mac 2>&1)
fl=$(cat "$(ls -d "$T_TMP"/ose2/linux-enum-*/ | head -n 1)/flags.txt")
t_has "$fl" "SELINUX=permissive: it goes off at the next boot" "on now but off at the next boot is HIGH"
t_hasnt "$fl" "kernel was started" "a clean command line is fine"

t_done
