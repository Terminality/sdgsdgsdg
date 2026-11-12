#!/bin/sh
# Tests for roles/linux/LX-20-password-rotation.sh.
# Works on a fake root (--root) with stand-in chpasswd, usermod and pwconv
# that edit the fake files, so no real account is touched.  The stand-in
# chpasswd stores "$test$<password>" so the test can check which password
# was set.  Checks: dry run changes nothing; --apply rotates usable accounts,
# skips protected ones, locks accounts not on --keep, fixes a hash hidden in
# /etc/passwd; passwords never reach the log, summary or accounts.csv; the
# undo log restores the old shadow file.
. "$(dirname "$0")/helper.sh"
SH=${TEST_SHELL:-sh}
C="$T_ROOT/roles/linux/LX-20-password-rotation.sh"
export CCDC_SKIP_VERIFY=1
# shellcheck disable=SC2086
run() { $SH "$C" "$@"; }
O="$T_TMP/out"; R="$T_TMP/root"; B="$T_TMP/bin"
mkdir -p "$O" "$B"
STUB_ROOT=$R; export STUB_ROOT

cat >"$B/chpasswd" <<'STUB'
#!/bin/sh
# stand-in chpasswd: "user:password" lines on stdin -> field 2 of the fake shadow
while IFS= read -r l; do
    u=${l%%:*}; p=${l#*:}
    awk -F: -v OFS=: -v u="$u" -v p="\$test\$$p" '$1 == u { $2 = p; f = 1 } { print } END { exit !f }' "$STUB_ROOT/etc/shadow" >"$STUB_ROOT/etc/shadow.t" || exit 1
    mv "$STUB_ROOT/etc/shadow.t" "$STUB_ROOT/etc/shadow"
done
STUB
cat >"$B/usermod" <<'STUB'
#!/bin/sh
# stand-in usermod: -L (lock), -U (unlock), -e DAYS (expiry); user is last
L=0; U=0; E=unset
while [ $# -gt 1 ]; do case "$1" in -L) L=1 ;; -U) U=1 ;; -e) shift; E=$1 ;; esac; shift; done
awk -F: -v OFS=: -v u="$1" -v L="$L" -v U="$U" -v E="$E" '$1 == u {
    if (L == 1 && $2 !~ /^!/) $2 = "!" $2
    if (U == 1) sub(/^!/, "", $2)
    if (E != "unset") $8 = E } { print }' "$STUB_ROOT/etc/shadow" >"$STUB_ROOT/etc/shadow.t" && mv "$STUB_ROOT/etc/shadow.t" "$STUB_ROOT/etc/shadow"
STUB
cat >"$B/pwconv" <<'STUB'
#!/bin/sh
# stand-in pwconv: hash in passwd field 2 -> shadow field 2, passwd gets x
awk -F: 'NR == FNR { if ($2 != "x") h[$1] = $2; next } { print }' "$STUB_ROOT/etc/passwd" "$STUB_ROOT/etc/passwd" >/dev/null
awk -F: -v OFS=: 'NR == FNR { if ($2 != "x" && $2 != "*") h[$1] = $2; next } ($1 in h) { $2 = h[$1] } { print }' "$STUB_ROOT/etc/passwd" "$STUB_ROOT/etc/shadow" >"$STUB_ROOT/etc/shadow.t" && mv "$STUB_ROOT/etc/shadow.t" "$STUB_ROOT/etc/shadow"
awk -F: -v OFS=: '$2 != "x" && $2 != "*" { $2 = "x" } { print }' "$STUB_ROOT/etc/passwd" >"$STUB_ROOT/etc/passwd.t" && mv "$STUB_ROOT/etc/passwd.t" "$STUB_ROOT/etc/passwd"
STUB
chmod +x "$B/chpasswd" "$B/usermod" "$B/pwconv"
CCDC_CHPASSWD="$B/chpasswd"; CCDC_USERMOD="$B/usermod"; CCDC_PWCONV="$B/pwconv"
export CCDC_CHPASSWD CCDC_USERMOD CCDC_PWCONV
unset SUDO_USER

plant() {
    rm -rf "$R"; mkdir -p "$R/etc"
    cat >"$R/etc/passwd" <<'P'
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
svc:x:999:999:service:/srv:/usr/sbin/nologin
alice:x:1000:1000::/home/alice:/bin/bash
bob:x:1001:1001::/home/bob:/bin/bash
mallory:x:1002:1002::/home/mallory:/bin/bash
nopass:x:1003:1003::/home/nopass:/bin/bash
hidden:$6$planted$hashinpasswd:1004:1004::/home/hidden:/bin/bash
toor:x:0:0::/root:/bin/bash
P
    cat >"$R/etc/shadow" <<'S'
root:$6$a$root:19000:0:99999:7:::
daemon:*:19000:0:99999:7:::
svc:$6$a$svc:19000:0:99999:7:::
alice:$6$a$alice:19000:0:99999:7:::
bob:$6$a$bob:19000:0:99999:7:::
mallory:$6$a$mallory:19000:0:99999:7:::
nopass::19000:0:99999:7:::
hidden:x:19000:0:99999:7:::
toor:$6$a$toor:19000:0:99999:7:::
S
    printf 'UID_MIN 1000\n' >"$R/etc/login.defs"
    cp "$R/etc/shadow" "$T_TMP/shadow.orig"; cp "$R/etc/passwd" "$T_TMP/passwd.orig"
}
f2() { awk -F: -v u="$1" '$1 == u { print $2 }' "$R/etc/shadow"; }
f8() { awk -F: -v u="$1" '$1 == u { print $8 }' "$R/etc/shadow"; }
printf 'alice\nbob\nnopass\nhidden\n' >"$T_TMP/keep.txt"
printf 'type,value,note\naccount,bob,scoring engine logs in as bob\n' >"$T_TMP/protected.csv"

t_start "options"
run --length 8 >/dev/null 2>&1; t_eq "$?" 2 "--length below 12 exits 2"
run --keep "$T_TMP/none.txt" >/dev/null 2>&1; t_eq "$?" 2 "missing --keep file exits 2"

t_start "dry run changes nothing"
plant
out=$(run --out "$O" --root "$R" --keep "$T_TMP/keep.txt" 2>&1); rc=$?
t_eq "$rc" 0 "exit 0"
t_ok "shadow unchanged" cmp -s "$R/etc/shadow" "$T_TMP/shadow.orig"
t_has "$out" "would rotate" "lists accounts it would rotate"
t_has "$out" "would lock" "lists accounts it would lock"
t_has "$out" "nopass has NO password" "reports the empty password"
t_has "$out" "toor has UID 0" "reports the extra UID 0 account"
t_fail "no passwords file in a dry run" sh -c "ls '$O'/LX-20_*/passwords.csv >/dev/null 2>&1"

t_start "--apply with a team list and a protected account"
out=$(run --out "$O" --root "$R" --keep "$T_TMP/keep.txt" --protected "$T_TMP/protected.csv" --apply 2>&1); rc=$?
t_eq "$rc" 0 "exit 0"
d=$(printf '%s\n' "$out" | sed -n 's/^All results: //p')
P="$d/passwords.csv"
t_file "$P" "passwords file written"
t_eq "$(ls -l "$P" | cut -c1-10)" "-rw-------" "passwords file is mode 600"
pw_alice=$(awk -F, '$2 == "alice" { print $3 }' "$P")
t_eq "$(f2 alice)" "\$test\$$pw_alice" "alice has the password written in the file"
t_eq "${#pw_alice}" 16 "random password is 16 characters"
t_has "$(f2 root)" "\$test\$" "root rotated"
t_has "$(f2 svc)" "\$test\$" "service account with a password rotated"
t_has "$(f2 nopass)" "\$test\$" "empty password replaced"
t_eq "$(f2 bob)" "\$6\$a\$bob" "protected account left alone"
t_eq "$(f2 mallory)" "!\$6\$a\$mallory" "account not on the list is locked"
t_eq "$(f8 mallory)" 1 "and expired"
t_eq "$(f2 toor)" "!\$6\$a\$toor" "extra UID 0 account locked"
t_eq "$(f2 daemon)" "*" "system account without a password untouched"
t_eq "$(awk -F: '$1 == "hidden" { print $2 }' "$R/etc/passwd")" x "hash moved out of /etc/passwd"
t_has "$(f2 hidden)" "\$test\$" "and that account rotated"
# No password may appear anywhere but passwords.csv.
leak=0
for p in $(awk -F, 'NR > 1 { print $3 }' "$P"); do
    grep -rqF -- "$p" "$d/summary.txt" "$d/accounts.csv" "$O"/*.log "$O"/undo-*.log && leak=1
done
t_eq "$leak" 0 "no password in the summary, accounts.csv, log or undo log"

t_start "undo restores the old passwords"
U=$(ls "$O"/undo-*.log)
awk -F'\t' '{ l[NR] = $4 } END { for (i = NR; i >= 1; i--) print l[i] }' "$U" >"$T_TMP/undo.sh"
sh "$T_TMP/undo.sh" >/dev/null 2>&1
t_ok "shadow back to the original" cmp -s "$R/etc/shadow" "$T_TMP/shadow.orig"
t_ok "passwd back to the original" cmp -s "$R/etc/passwd" "$T_TMP/passwd.orig"
rm -f "$U"

t_start "given passwords, --users, and the sudo account"
plant
printf 'alice,Correct-Horse-42\n' >"$T_TMP/pw.csv"
run --out "$O" --root "$R" --users alice,root --passwords "$T_TMP/pw.csv" --apply --no-protected >/dev/null 2>&1
t_eq "$(f2 alice)" "\$test\$Correct-Horse-42" "--passwords used for alice"
t_eq "$(f2 svc)" "\$6\$a\$svc" "--users leaves other accounts alone"
plant
(SUDO_USER=alice; export SUDO_USER; run --out "$O" --root "$R" --users alice --apply --no-protected >/dev/null 2>&1)
t_eq "$(f2 alice)" "\$6\$a\$alice" "the account that ran sudo is skipped"
(SUDO_USER=alice; export SUDO_USER; run --out "$O" --root "$R" --users alice --include-me --apply --no-protected >/dev/null 2>&1)
t_has "$(f2 alice)" "\$test\$" "--include-me rotates it"
printf 'alice,bad:pw:here\n' >"$T_TMP/bad.csv"
run --out "$O" --root "$R" --passwords "$T_TMP/bad.csv" >/dev/null 2>&1; t_eq "$?" 2 "a password with ':' is refused"
t_done
