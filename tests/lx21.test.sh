#!/bin/sh
# Tests for roles/linux/LX-21-account-lockdown.sh.
# A fake root (--root) with planted accounts: a second UID 0, a user with
# no password, a hash in /etc/passwd, www-data with a shell and a key, an
# extra admin with NOPASSWD and a key, a sudo line for everyone and one for
# a user that does not exist; plus a protected team account and clean
# service accounts.  Checks: each is found at the right level; a dry run
# changes nothing; --batch --apply takes the defaults (lock, no-login,
# comment out); the questions on a terminal (take admin away, remove keys);
# protected and root are never locked; the undo puts every line back.
. "$(dirname "$0")/helper.sh"
SH=${TEST_SHELL:-sh}
C="$T_ROOT/roles/linux/LX-21-account-lockdown.sh"
export BT_SKIP_VERIFY=1
O="$T_TMP/out"; F="$T_TMP/root"; PR="$T_TMP/protected.csv"
printf 'kind,name,why\naccount,teamadmin,our admin\n' >"$PR"

mkroot() {
    rm -rf "$F"; mkdir -p "$F/etc/sudoers.d" "$F/home/eve/.ssh" "$F/home/teamadmin/.ssh" "$F/var/www/.ssh" "$F/usr/sbin" "$F/home/bob" "$F/home/nopw" "$F/home/toor"
    printf 'UID_MIN 1000\n' >"$F/etc/login.defs"
    cat >"$F/etc/passwd" <<'EOF'
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/bin/bash
mysql:x:110:110:MySQL:/nonexistent:/bin/false
toor:x:0:0::/home/toor:/bin/sh
teamadmin:x:1000:1000::/home/teamadmin:/bin/bash
eve:x:1001:1001::/home/eve:/bin/bash
bob:x:1002:1002::/home/bob:/bin/bash
nopw:x:1003:1003::/home/nopw:/bin/bash
inpw:$6$abc$hashinpasswd:1004:1004::/home/bob:/bin/bash
EOF
    old=$(( $(date +%s) / 86400 - 100 ))
    cat >"$F/etc/shadow" <<EOF
root:\$6\$r\$roothash:$old:0:99999:7:::
daemon:*:$old:0:99999:7:::
www-data:\$6\$w\$wwwhash:$old:0:99999:7:::
mysql:!:$old:0:99999:7:::
toor:\$6\$t\$toorhash:$old:0:99999:7:::
teamadmin:\$6\$a\$teamhash:$old:0:99999:7:::
eve:\$6\$e\$evehash:$old:0:99999:7:::
bob:\$6\$b\$bobhash:$old:0:99999:7:::
nopw::$old:0:99999:7:::
inpw:x:$old:0:99999:7:::
EOF
    cat >"$F/etc/group" <<'EOF'
root:x:0:
sudo:x:27:teamadmin,eve
docker:x:999:eve
www-data:x:33:
teamadmin:x:1000:
eve:x:1001:
bob:x:1002:
EOF
    printf 'root ALL=(ALL:ALL) ALL\n%%sudo ALL=(ALL:ALL) ALL\nALL ALL=(ALL) NOPASSWD: ALL\n' >"$F/etc/sudoers"  # sudoers text, not an array: posix-ok
    printf 'eve ALL=(ALL) NOPASSWD: ALL\nghost ALL=(ALL) ALL\n' >"$F/etc/sudoers.d/90-extra"  # sudoers text, not an array: posix-ok
    printf 'ssh-ed25519 AAAAevekey eve@evil\n' >"$F/home/eve/.ssh/authorized_keys"
    printf 'command="/bin/sh" ssh-rsa AAAAwwwkey red@team\n' >"$F/var/www/.ssh/authorized_keys"
    printf 'ssh-ed25519 AAAAteamkey team@us\n' >"$F/home/teamadmin/.ssh/authorized_keys"
    : >"$F/usr/sbin/nologin"; chmod +x "$F/usr/sbin/nologin"
}
run() { $SH "$C" --root "$F" --out "$O" --no-color --box ecomm --protected "$PR" "$@"; }
snap() { (cd "$F" && find . -type f | sort; find . -type f -exec cat {} +) | cksum; }

t_start "options"
$SH "$C" --box moon >/dev/null 2>&1; t_eq "$?" 2 "a bad --box exits 2"
$SH "$C" --days x >/dev/null 2>&1; t_eq "$?" 2 "a bad --days exits 2"
out=$($SH "$C" --help 2>&1); t_has "$out" "--all" "--help"

t_start "find"
mkroot; before=$(snap)
out=$(run --batch 2>&1)
t_has "$out" "UID 0: it IS root under another name" "a second UID 0 is HIGH"
t_has "$out" "NO password: anyone can log in" "an empty password is HIGH"
t_has "$out" "password hash in /etc/passwd" "a hash in /etc/passwd is HIGH"
t_has "$out" "service account that can log in (/bin/bash, has a password, 1 SSH key(s))" "www-data with a shell, password and key is HIGH"
t_has "$out" "admin (sudo docker) - one of yours?" "an extra admin is MED"
t_has "$out" "NOPASSWD" "with NOPASSWD"
t_hasnt "$out" "teamadmin: " "the protected admin is not asked about"
t_has "$out" "/etc/sudoers line 3: ALL ALL=(ALL) NOPASSWD: ALL  - gives EVERY user root" "a sudo line for everyone is HIGH"  # sudoers text, not an array: posix-ok
t_has "$out" "for a user that does not exist (ghost)" "a sudo line for a missing user is HIGH"
t_hasnt "$out" "mysql " "a service account with no login is not listed"
t_has "$out" "Dry run: nothing was changed" "dry run without --apply"
t_eq "$(snap)" "$before" "a dry run changes nothing"
d=$(ls -d "$O"/accounts-* | sort -t- -k3 -n | tail -n 1)
t_file "$d/accounts.txt" "accounts.txt written"
t_fail "no hash in the output" grep -rq 'hashinpasswd\|roothash\|evehash' "$d/output.txt" "$d/accounts.txt"
t_fail "no CSV files are left" sh -c "find '$O' -name '*.csv' | grep -q ."

t_start "apply the defaults (--batch)"
_u0=$(cat "$O"/undo-*.log 2>/dev/null | grep -c .)
out=$(run --batch --apply --no-timer 2>&1)
t_has "$(awk -F: '$1 == "toor" { print $2 }' "$F/etc/shadow")" "!" "the second UID 0 is locked"
t_eq "$(awk -F: '$1 == "toor" { print $8 }' "$F/etc/shadow")" 1 "and expired (keys stop too)"
t_has "$(awk -F: '$1 == "nopw" { print $2 }' "$F/etc/shadow")" "!" "the empty-password account is locked"
t_eq "$(awk -F: '$1 == "www-data" { print $7 }' "$F/etc/passwd")" /usr/sbin/nologin "www-data gets a no-login shell"
t_eq "$(awk -F: '$1 == "root" { print $2 }' "$F/etc/shadow")" '$6$r$roothash' "root is never locked"
t_eq "$(awk -F: '$1 == "teamadmin" { print $2 }' "$F/etc/shadow")" '$6$a$teamhash' "the protected account is untouched"
t_has "$(cat "$F/etc/sudoers")" "# LX-21: ALL ALL=(ALL) NOPASSWD: ALL" "the sudo line for everyone is commented out"  # sudoers text, not an array: posix-ok
t_has "$(cat "$F/etc/sudoers.d/90-extra")" "# LX-21: ghost ALL=(ALL) ALL" "the line for a missing user too"  # sudoers text, not an array: posix-ok
t_has "$(cat "$F/etc/group")" "sudo:x:27:teamadmin,eve" "eve's admin is kept by default (MED: keep)"
cat "$O"/undo-*.log | awk -F'\t' -v n="$_u0" 'NR > n { l[NR] = $4 } END { for (i = NR; i > n; i--) print l[i] }' >"$T_TMP/undo.sh"
sh "$T_TMP/undo.sh" >/dev/null 2>&1
t_eq "$(snap)" "$before" "undo puts every line back"

t_start "Alpine: doas rules"
mkroot; rm -rf "$F/etc/sudoers" "$F/etc/sudoers.d"; mkdir -p "$F/etc/doas.d"
printf 'wheel:x:10:teamadmin,eve\nops:x:20:bob\n' >>"$F/etc/group"
printf '# local rules\npermit persist :wheel\npermit nopass :users\ndeny eve as root cmd /bin/sh\npermit nopass setenv { PATH } :ops\n' >"$F/etc/doas.conf"
printf 'permit nopass keepenv eve\npermit nopass ghost as root\npermit nopass :docker cmd /usr/bin/docker\n' >"$F/etc/doas.d/90-extra.conf"
printf 'permit nopass :users\n' >"$F/etc/doas.d/README"
before=$(snap)
out=$(run --batch 2>&1)
t_has "$out" "admin (sudo docker wheel) - one of yours?" "a wheel member is an admin"
t_has "$out" "has sudo lines (/etc/doas.conf:2 /etc/doas.d/90-extra.conf:1 /etc/doas.d/90-extra.conf:3), NOPASSWD" "eve's doas lines, with nopass"
t_has "$out" "/etc/doas.conf line 3: permit nopass :users  - gives a whole group (%users) root" "nopass for a whole group is HIGH"
t_has "$out" "/etc/doas.d/90-extra.conf line 2: permit nopass ghost as root  - for a user that does not exist (ghost)" "a doas line for a missing user is HIGH"
t_has "$out" "/etc/doas.conf line 5: permit nopass setenv { PATH } :ops  - doas nopass for the whole group" "nopass for another group is HIGH (setenv skipped)"
t_hasnt "$out" "90-extra.conf line 3" "nopass for one command is not flagged"
t_hasnt "$out" "README" "only doas.d/*.conf files are read"
t_hasnt "$out" "doas.conf line 4:" "deny lines give nothing"
out=$(run --batch --apply --no-timer 2>&1)
t_has "$(cat "$F/etc/doas.conf")" "# LX-21: permit nopass :users" "--apply comments out the group line"
t_has "$(cat "$F/etc/doas.conf")" "permit persist :wheel" "the rest stays"
t_has "$(cat "$F/etc/doas.d/90-extra.conf")" "# LX-21: permit nopass ghost as root" "and the missing-user line"
t_has "$(awk -F: '$1 == "toor" { print $2 }' "$F/etc/shadow")" "!" "locking works without usermod (busybox)"

t_start "questions on a terminal"
if command -v script >/dev/null 2>&1; then
    mkroot; before=$(snap)
    # one by one: y; www-data n, toor l, eve b, nopw k, inpw k; sudo lines: y, n; apply: Enter
    out=$(run --batch 2>&1)
    order=$(printf '%s\n' "$out" | sed -n 's/^\[?\] \([a-z-]*\) (uid.*/\1/p' | tr '\n' ' ')
    t_eq "$order" "www-data toor eve nopw inpw " "the flagged accounts are asked in order"
    printf 'y\nn\nl\nb\nk\nk\ny\nn\n\n' >"$T_TMP/ans"
    tt=$(BT_NO_TTY=0 script -qc "$SH '$C' --root '$F' --out '$O' --no-color --box ecomm --protected '$PR' --apply --no-timer" /dev/null <"$T_TMP/ans" 2>&1)
    t_has "$tt" "[d] take its admin rights away (groups: sudo docker" "an admin is offered: take admin away"
    t_has "$tt" "[r] remove its SSH keys (1, moved to quarantine)" "and: remove its keys"
    t_has "$tt" "[n] no-login shell" "a service account is offered a no-login shell"
    t_has "$(cat "$F/etc/group")" "sudo:x:27:teamadmin" "b: eve is out of sudo"
    t_hasnt "$(awk -F: '$1 == "sudo" || $1 == "docker"' "$F/etc/group")" "eve" "and out of docker"
    t_has "$(cat "$F/etc/sudoers.d/90-extra")" "# LX-21: eve ALL=(ALL) NOPASSWD: ALL" "and her own sudo line is commented out"  # sudoers text, not an array: posix-ok
    t_fail "and her key is gone" test -f "$F/home/eve/.ssh/authorized_keys"
    t_ok "the team's key stays" test -f "$F/home/teamadmin/.ssh/authorized_keys"
    t_has "$(cat "$F/etc/sudoers")" "# LX-21: ALL ALL" "the first sudo line: y"
    t_hasnt "$(cat "$F/etc/sudoers.d/90-extra")" "# LX-21: ghost" "the second: n"
fi

t_done
