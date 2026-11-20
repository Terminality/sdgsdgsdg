#!/bin/sh
# Tests for roles/linux/LX-45-rootkit-scan.sh.
# Harmless stand-ins: a copy of sleep named xmrig (a miner), sleep run under
# the name [kworker/9:9] (a fake kernel thread), and rootkit paths in a fake
# root (--root: /reptile, a program in /dev/shm).  Checks: each is found;
# nothing on a clean box is flagged; a dry run changes nothing; --apply
# kills the stand-ins and quarantines the files; the undo puts the files
# back; the questions on a terminal.  With ClamAV installed: an EICAR test
# file is found.  Only the test's own processes and files are touched.
. "$(dirname "$0")/helper.sh"
SH=${TEST_SHELL:-sh}
C="$T_ROOT/roles/linux/LX-45-rootkit-scan.sh"
export BT_SKIP_VERIFY=1
O="$T_TMP/out"; F="$T_TMP/root"; B="$T_TMP/bin"
SLEEP=""; for _d in /usr/bin /bin; do [ -x "$_d/sleep" ] && { SLEEP=$_d/sleep; break; }; done
mkdir -p "$B"; cp "$SLEEP" "$B/xmrig"
mkroot() { rm -rf "$F"; mkdir -p "$F/dev/shm" "$F/tmp"; printf 'x\n' >"$F/reptile"; printf '#!/bin/sh\n' >"$F/dev/shm/.k"; chmod +x "$F/dev/shm/.k"; }
alive() { kill -0 "$1" 2>/dev/null && ! ps -o stat= -p "$1" 2>/dev/null | grep -q '^Z'; }
run() { $SH "$C" --out "$O" --no-color --no-install --no-clamav --root "$F" "$@"; }

t_start "options"
$SH "$C" --scan /nonexistent >/dev/null 2>&1; t_eq "$?" 2 "a missing --scan folder exits 2"
out=$($SH "$C" --help 2>&1); t_has "$out" "--no-clamav" "--help"

t_start "find"
mkroot
"$B/xmrig" 600 & MP=$!
KP=""; if command -v bash >/dev/null 2>&1; then bash -c "exec -a '[kworker/9:9]' $SLEEP 600" & KP=$!; fi
_i=0; while ! ps -eo comm= | grep -qx xmrig && [ "$_i" -lt 20 ]; do sleep 1; _i=$((_i + 1)); done
out=$(run --batch 2>&1)
t_has "$out" "[!] a crypto miner: pid $MP (xmrig" "a miner is HIGH"
[ -n "$KP" ] && t_has "$out" "[!] pid $KP calls itself [kworker/9:9] 600 but runs $SLEEP" "a fake kernel thread is HIGH"
t_has "$out" "[!] a path rootkits use is there: /reptile" "a rootkit path is HIGH"
t_has "$out" "[!] a program file in /dev/shm: /dev/shm/.k" "a program in /dev/shm is HIGH"
t_has "$out" "[ok] every process in /proc is shown by ps" "no false hidden processes"
t_has "$out" "[ok] every listening TCP port in /proc is shown by ss" "no false hidden ports"
t_has "$out" "Dry run: nothing was changed" "dry run without --apply"
t_ok "a dry run kills nothing" alive "$MP"
t_ok "and moves nothing" test -f "$F/reptile"
t_fail "no CSV files are left" sh -c "find '$O' -name '*.csv' | grep -q ."

if [ "$(id -u)" = 0 ]; then
    t_start "apply the defaults (--batch)"
    _u0=$(cat "$O"/undo-*.log 2>/dev/null | grep -c .)
    out=$(run --batch --no-protected --apply 2>&1)
    t_fail "the miner is killed" alive "$MP"
    [ -n "$KP" ] && t_fail "the fake kernel thread is killed" alive "$KP"
    t_fail "the rootkit path is quarantined" test -f "$F/reptile"
    t_fail "the /dev/shm program is quarantined" test -f "$F/dev/shm/.k"
    cat "$O"/undo-*.log | awk -F'\t' -v n="$_u0" 'NR > n { l[NR] = $4 } END { for (i = NR; i > n; i--) print l[i] }' >"$T_TMP/undo.sh"
    sh "$T_TMP/undo.sh" >/dev/null 2>&1
    t_ok "undo puts the files back" test -f "$F/reptile"

    t_start "the protected list"
    mkroot
    "$B/xmrig" 600 & MP=$!
    _i=0; while ! ps -eo comm= | grep -qx xmrig && [ "$_i" -lt 20 ]; do sleep 1; _i=$((_i + 1)); done
    printf 'type,value,note\nprocess,xmrig,test\npath,/reptile,test\n' >"$T_TMP/prot.csv"
    out=$(run --batch --protected "$T_TMP/prot.csv" --apply 2>&1)
    t_ok "a protected process is not killed" alive "$MP"
    t_ok "a protected path is not quarantined" test -f "$F/reptile"
    t_fail "an unprotected one still is" test -f "$F/dev/shm/.k"
    kill "$MP" 2>/dev/null

    t_start "questions on a terminal"
    if command -v script >/dev/null 2>&1; then
        mkroot
        "$B/xmrig" 600 & MP=$!
        _i=0; while ! ps -eo comm= | grep -qx xmrig && [ "$_i" -lt 20 ]; do sleep 1; _i=$((_i + 1)); done
        # in order: /reptile q, /dev/shm/.k l, the miner l; apply Enter
        printf 'q\nl\nl\n\n' >"$T_TMP/ans"
        tt=$(BT_NO_TTY=0 script -qc "$SH '$C' --out '$O' --no-color --no-install --no-clamav --root '$F' --no-protected --apply" /dev/null <"$T_TMP/ans" 2>&1)
        t_has "$tt" "[q] quarantine it" "a file lists its answers"
        t_has "$tt" "[k] kill it" "a process lists its answers"
        t_fail "q: /reptile is quarantined" test -f "$F/reptile"
        t_ok "l: /dev/shm/.k stays" test -f "$F/dev/shm/.k"
        t_ok "l: the miner keeps running" alive "$MP"
    fi
fi
kill "$MP" "$KP" 2>/dev/null

if command -v clamscan >/dev/null 2>&1 && [ -n "$(ls /var/lib/clamav/*.c?d 2>/dev/null)" ]; then
    t_start "ClamAV"
    mkdir -p "$T_TMP/scan"
    printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' >"$T_TMP/scan/eicar.txt"  # the standard test string: posix-ok
    out=$($SH "$C" --out "$O" --no-color --no-install --batch --scan "$T_TMP/scan" 2>&1)
    t_has "$out" "ClamAV: $T_TMP/scan/eicar.txt is" "ClamAV finds the EICAR test file"
fi

t_start "no ss: netstat (Alpine)"
# A PATH with every program but ss; netstat is busybox's when there is no
# other one.
NB="$T_TMP/noss"; mkdir -p "$NB"
for _d in /usr/local/bin /usr/bin /bin /usr/sbin /sbin; do
    for _x in "$_d"/*; do _n=${_x##*/}; [ "$_n" = ss ] && continue; [ -e "$NB/$_n" ] || ln -s "$_x" "$NB/$_n" 2>/dev/null; done
done
if [ ! -e "$NB/netstat" ] && command -v busybox >/dev/null 2>&1; then printf '#!/bin/sh\nexec busybox netstat "$@"\n' >"$NB/netstat"; chmod +x "$NB/netstat"; fi
if [ -e "$NB/netstat" ]; then
    mkroot
    out=$(export PATH="$NB"; run --batch 2>&1)
    t_has "$out" "[ok] every listening TCP port in /proc is shown by netstat" "netstat is the second view"
    t_hasnt "$out" "hidden-port check skipped" "the port check still runs"
fi

t_start "Alpine programs (apk)"
# A stand-in apk database: every program in /usr/bin and /usr/sbin belongs
# to package "core", except ps (placed by hand); apk audit says grep changed.
A="$T_TMP/apkb"; mkdir -p "$A"
_ps=$(command -v ps); _grep=$(command -v grep)
{ printf 'P:core\n'
  for _d in /usr/bin /usr/sbin /bin /sbin; do
      [ -h "$_d" ] && continue
      printf 'F:%s\n' "${_d#/}"
      for _x in "$_d"/*; do [ "$_x" = "$_ps" ] && continue; printf 'R:%s\n' "${_x##*/}"; done
  done; } >"$T_TMP/apkdb"
cat >"$A/apk" <<EOF
#!/bin/sh
case "\$1" in audit) echo "U ${_grep#/}"; echo "A usr/bin/something-new" ;; esac
EOF
chmod +x "$A/apk"
out=$(export BT_TEST_PM=apk BT_TEST_APKDB="$T_TMP/apkdb" PATH="$A:$PATH"; $SH "$C" --out "$O" --no-color --no-install --no-clamav --batch 2>&1)
t_has "$out" "[!] $_ps belongs to no package: placed there by hand?" "a core program no package owns is HIGH"
t_has "$out" "[!] $_grep does not match its package (replaced?): reinstall it - apk fix core" "apk audit U is HIGH, with apk fix"
t_hasnt "$out" "something-new" "an added file that is not a core program is left out"
t_has "$out" "apk add rkhunter" "the install hint is for apk"

t_start "file shares are scanned"
mkroot
mkdir -p "$F/etc/samba" "$F/srv/share" "$F/data/my files" "$F/exp"
printf '[global]\n   workgroup = X\n[share]\n   path = /srv/share\n[files]\n\tpath = /data/my files \n[homes]\n   path = /home/%%U\n' >"$F/etc/samba/smb.conf"
printf '/exp 10.0.0.0/24(rw)\n# /nope *(rw)\n' >"$F/etc/exports"
if command -v clamscan >/dev/null 2>&1; then
    out=$($SH "$C" --out "$O" --no-color --no-install --batch --root "$F" 2>&1)
    _l=$(printf '%s\n' "$out" | grep "ClamAV over:")
    t_has "$_l" "$F/srv " "a Samba share in /srv is scanned with /srv"
    t_has "$_l" "$F/data/my files" "one with a space in its name"
    t_has "$_l" "$F/exp" "an NFS export"
    t_hasnt "$_l" "%U" "per-user paths are left out"
    t_hasnt "$_l" "/nope" "a commented export is left out"
    t_has "$out" "[?] Also scan the shared folders (Samba, NFS, Gitea): /data/my files /exp? [Y/n] y (default)" "asked, default yes; /srv/share is in /srv already"
    [ -z "$(ls /var/lib/clamav/*.c?d 2>/dev/null)" ] && t_has "$out" "ClamAV has no signatures, so it scanned nothing" "no signatures: said plainly"
    out=$($SH "$C" --out "$O" --no-color --no-install --batch --root "$F" --no-shares 2>&1)
    t_hasnt "$(printf '%s\n' "$out" | grep "ClamAV over:")" "$F/exp" "--no-shares answers no"
    t_hasnt "$out" "Also scan the shared folders" "and is not asked"
fi
t_done
