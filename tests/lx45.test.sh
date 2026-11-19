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
export CCDC_SKIP_VERIFY=1
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

    t_start "questions on a terminal"
    if command -v script >/dev/null 2>&1; then
        mkroot
        "$B/xmrig" 600 & MP=$!
        _i=0; while ! ps -eo comm= | grep -qx xmrig && [ "$_i" -lt 20 ]; do sleep 1; _i=$((_i + 1)); done
        # in order: /reptile q, /dev/shm/.k l, the miner l; apply Enter
        printf 'q\nl\nl\n\n' >"$T_TMP/ans"
        tt=$(CCDC_NO_TTY=0 script -qc "$SH '$C' --out '$O' --no-color --no-install --no-clamav --root '$F' --no-protected --apply" /dev/null <"$T_TMP/ans" 2>&1)
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
t_done
