#!/bin/sh
# Tests for roles/linux/LX-40-change-watch.sh.
# A fake root (--root) and a stand-in ss whose output a variable switches.
# Takes a baseline, plants one change per section, and checks each is
# reported once with the right severity; that a second check is quiet; that
# --alert-cmd gets the lines; that --accept clears the differences; and that
# no password hash is ever written into the state folder.
. "$(dirname "$0")/helper.sh"
SH=${TEST_SHELL:-sh}
C="$T_ROOT/roles/linux/LX-40-change-watch.sh"
export CCDC_SKIP_VERIFY=1
# shellcheck disable=SC2086
run() { $SH "$C" "$@"; }
O="$T_TMP/out"; R="$T_TMP/root"; B="$T_TMP/bin"; ST="$T_TMP/state"
mkdir -p "$O" "$B"
SS_EXTRA="$T_TMP/ss.extra"; export SS_EXTRA; : >"$SS_EXTRA"
cat >"$B/ss" <<'STUB'
#!/bin/sh
echo 'Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process'
echo 'tcp   LISTEN 0      128    0.0.0.0:22         0.0.0.0:*         users:(("sshd",pid=1,fd=3))'
cat "$SS_EXTRA"
STUB
chmod +x "$B/ss"; CCDC_SS="$B/ss"; export CCDC_SS

mkdir -p "$R/etc/cron.d" "$R/etc/sudoers.d" "$R/etc/pam.d" "$R/etc/systemd/system" "$R/home/alice/.ssh" "$R/var/www/html" "$R/usr/bin" "$R/root"
printf 'root:x:0:0::/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n' >"$R/etc/passwd"
printf 'root:$6$planted$SECRETHASHVALUE:19000::::::\nalice:$6$a$alicehash:19000::::::\n' >"$R/etc/shadow"
printf 'root:x:0:\nsudo:x:27:\nalice:x:1000:\n' >"$R/etc/group"
printf 'root ALL=(ALL) ALL\n' >"$R/etc/sudoers"  # posix-ok
printf 'auth required pam_unix.so\n' >"$R/etc/pam.d/common-auth"
printf '<h1>ok</h1>\n' >"$R/var/www/html/index.html"
printf 'x\n' >"$R/usr/bin/tool"

t_start "baseline"
out=$(run --out "$O" --state "$ST" --root "$R" --baseline 2>&1); rc=$?
t_eq "$rc" 0 "exit 0"
t_has "$out" "baseline: BASELINE taken" "baseline taken"
out=$(run --out "$O" --state "$ST" --root "$R" 2>&1)
t_has "$out" "no changes" "nothing changed yet"

t_start "one change per section"
printf 'mallory:x:1001:1001::/home/mallory:/bin/bash\n' >>"$R/etc/passwd"
sed 's/^alice:x:1000:/alice:x:0:/' "$R/etc/passwd" >"$R/etc/passwd.t" && mv "$R/etc/passwd.t" "$R/etc/passwd"
sed 's/alicehash/newalicehash/' "$R/etc/shadow" >"$R/etc/shadow.t" && mv "$R/etc/shadow.t" "$R/etc/shadow"
sed 's/^sudo:x:27:$/sudo:x:27:mallory/' "$R/etc/group" >"$R/etc/group.t" && mv "$R/etc/group.t" "$R/etc/group"
printf 'mallory ALL=(ALL) NOPASSWD:ALL\n' >"$R/etc/sudoers.d/90-x"  # posix-ok
printf '* * * * * root /tmp/.x\n' >"$R/etc/cron.d/update"
printf '[Service]\nExecStart=/tmp/.x\n' >"$R/etc/systemd/system/sys-update.service"
printf 'ssh-ed25519 AAAAPLANTED red\n' >"$R/home/alice/.ssh/authorized_keys"
printf '<?php system($_GET[1]);\n' >"$R/var/www/html/c.php"
cp "$R/usr/bin/tool" "$R/usr/bin/tool2"; chmod 4755 "$R/usr/bin/tool2"
echo 'tcp   LISTEN 0      5      0.0.0.0:4444       0.0.0.0:*         users:(("nc",pid=9,fd=3))' >"$SS_EXTRA"
out=$(run --out "$O" --state "$ST" --root "$R" --alert-cmd "cat >'$T_TMP/sent.txt'" 2>&1)
t_has "$out" "HIGH users     added   mallory" "new account HIGH"
t_has "$out" "HIGH users     changed alice - now UID 0" "account turned into UID 0 HIGH"
t_has "$out" "MED  passwords changed alice" "password change MED"
t_has "$out" "HIGH groups    changed sudo" "sudo group change HIGH"
t_has "$out" "HIGH files     added   /etc/sudoers.d/90-x" "new sudoers file HIGH"
t_has "$out" "HIGH cron      added   /etc/cron.d/update" "new cron job HIGH"
t_has "$out" "HIGH units     added   /etc/systemd/system/sys-update.service" "new service HIGH"
t_has "$out" "HIGH keys      added   /home/alice/.ssh/authorized_keys" "new SSH key HIGH"
t_has "$out" "HIGH web       added   /var/www/html/c.php" "web shell HIGH"
t_has "$out" "HIGH suid      added   /usr/bin/tool2" "new SUID program HIGH"
t_has "$out" "HIGH ports     added   tcp 0.0.0.0 4444" "backdoor port HIGH"
t_has "$(cat "$T_TMP/sent.txt")" "mallory" "--alert-cmd received the alerts"

t_start "reported once; accept"
out=$(run --out "$O" --state "$ST" --root "$R" 2>&1)
t_has "$out" "no changes" "second check is quiet"
t_ok "changes since baseline still listed" test -s "$ST/changes-since-baseline.txt"
run --out "$O" --state "$ST" --root "$R" --accept >/dev/null 2>&1
out=$(run --out "$O" --state "$ST" --root "$R" 2>&1)
t_fail "--accept clears the differences" test -s "$ST/changes-since-baseline.txt"
t_fail "no password hash stored" grep -rq "SECRETHASHVALUE" "$ST"
rm "$R/var/www/html/index.html"
out=$(run --out "$O" --state "$ST" --root "$R" --loop 10 --count 1 2>&1)
t_has "$out" "MED  web       removed /var/www/html/index.html" "--loop runs a check; removed web file MED"
run --loop 5 >/dev/null 2>&1; t_eq "$?" 2 "--loop under 10 seconds exits 2"
t_start "in a loop the SUID scan runs on every Nth check only"
run --out "$O" --state "$ST" --root "$R" --accept >/dev/null 2>&1
cp "$R/usr/bin/tool2" "$R/usr/bin/tool3"; chmod 4755 "$R/usr/bin/tool3"
out=$(run --out "$O" --state "$ST" --root "$R" --loop 10 --count 2 --suid-every 2 2>&1)
t_eq "$(printf '%s\n' "$out" | grep -c 'suid      added   /usr/bin/tool3')" 1 "the new SUID file is reported once, by the check that scans"
run --suid-every 0 >/dev/null 2>&1; t_eq "$?" 2 "--suid-every 0 exits 2"
t_done
