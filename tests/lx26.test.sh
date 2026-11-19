#!/bin/sh
# Tests for roles/linux/LX-26-remote-access.sh.
# Starts harmless stand-ins in the test folder - copies of sleep named ngrok
# and x11vnc, a copy of nc named ttyd listening on a high port, busybox nc
# with -e (a bind shell) - then: each is found at the right level; a dry run
# stops nothing; the questions on a terminal; --apply as root kills the
# chosen ones and quarantines their files from the temp folder; a kept one
# stays.  Only the test's own processes and files are touched.
. "$(dirname "$0")/helper.sh"
SH=${TEST_SHELL:-sh}
C="$T_ROOT/roles/linux/LX-26-remote-access.sh"
export BT_SKIP_VERIFY=1
O="$T_TMP/out"; B="$T_TMP/bin"
mkdir -p "$B"
# The sleep program itself (ksh and busybox have a built-in sleep, so
# "command -v sleep" is not a path there).
SLEEP=""; for _d in /usr/bin /bin; do [ -x "$_d/sleep" ] && { SLEEP=$_d/sleep; break; }; done
cp "$SLEEP" "$B/ngrok"; cp "$SLEEP" "$B/x11vnc"
HAVE_NC=0; command -v nc >/dev/null 2>&1 && { cp "$(command -v nc)" "$B/ttyd"; HAVE_NC=1; }
HAVE_BB=0; busybox nc 2>&1 | grep -q -- '-e PROG' && HAVE_BB=1
PIDS=""
start() {
    "$B/ngrok" 600 & PIDS="$PIDS $!"
    "$B/x11vnc" 600 & PIDS="$PIDS $!"
    [ "$HAVE_NC" = 1 ] && { "$B/ttyd" -lk 17681 >/dev/null 2>&1 & PIDS="$PIDS $!"; }
    [ "$HAVE_BB" = 1 ] && { busybox nc -ll -p 14445 -e /bin/true >/dev/null 2>&1 & PIDS="$PIDS $!"; }
    # Wait until they show up under their own names.
    _i=0; while ! ps -eo comm= | grep -qx x11vnc && [ "$_i" -lt 20 ]; do sleep 1; _i=$((_i + 1)); done
}
stop_all() { for _p in $PIDS; do kill "$_p" 2>/dev/null; done; PIDS=""; sleep 1; }
up() { kill -0 "$1" 2>/dev/null && ! ps -o stat= -p "$1" 2>/dev/null | grep -q Z; }
run() { $SH "$C" --out "$O" --no-color --box ecomm "$@"; }

t_start "options"
$SH "$C" --box moon >/dev/null 2>&1; t_eq "$?" 2 "a bad --box exits 2"
$SH "$C" --timer x >/dev/null 2>&1; t_eq "$?" 2 "a bad --timer exits 2"
out=$($SH "$C" --help 2>&1); t_has "$out" "SSH: LX-22" "--help"

t_start "find"
start
out=$(run --batch 2>&1)
t_has "$out" "[!] HIGH tunnel: a tunnel out past the firewall: ngrok" "a tunnel is HIGH"
t_has "$out" "[!] HIGH remote desktop: a remote desktop: x11vnc" "a VNC server is HIGH"
[ "$HAVE_NC" = 1 ] && t_has "$out" "web terminal: a shell in a web browser: ttyd" "a web terminal is HIGH" && t_has "$out" "port 17681" "with its port"
[ "$HAVE_BB" = 1 ] && t_has "$out" "netcat that runs a program for whoever connects" "a bind shell is HIGH"
t_hasnt "$out" "<defunct>" "zombies are left out"
t_has "$out" "Dry run: nothing was changed" "dry run without --apply"
_alive=0; for _p in $PIDS; do up "$_p" && _alive=$((_alive + 1)); done
t_eq "$_alive" "$(printf '%s' "$PIDS" | wc -w | tr -d ' ')" "a dry run stops nothing"
t_fail "no CSV files are left" sh -c "find '$O' -name '*.csv' | grep -q ."

if [ "$(id -u)" = 0 ]; then
    t_start "apply the defaults (--batch)"
    out=$(run --batch --no-protected --apply --no-timer 2>&1)
    _alive=0; for _p in $PIDS; do up "$_p" && _alive=$((_alive + 1)); done
    t_eq "$_alive" 0 "every HIGH one is stopped"
    t_fail "the tunnel's file is quarantined from the temp folder" test -f "$B/ngrok"
    t_has "$out" "[+] stopped: a tunnel out past the firewall" "it says so"
    stop_all

    t_start "questions on a terminal"
    if command -v script >/dev/null 2>&1; then
        cp "$SLEEP" "$B/ngrok"; cp "$SLEEP" "$B/x11vnc"
        "$B/ngrok" 600 & P1=$!; "$B/x11vnc" 600 & P2=$!
        _i=0; while ! ps -eo comm= | grep -qx x11vnc && [ "$_i" -lt 20 ]; do sleep 1; _i=$((_i + 1)); done
        # remote desktop (x11vnc) first: keep; tunnel (ngrok): stop; apply: Enter
        printf 'k\ns\n\n' >"$T_TMP/ans"
        tt=$(BT_NO_TTY=0 script -qc "$SH '$C' --out '$O' --no-color --box ecomm --no-protected --apply --no-timer" /dev/null <"$T_TMP/ans" 2>&1)
        t_has "$tt" "[s] stop it (kill it; quarantine" "each finding lists its answers"
        t_ok "k: x11vnc keeps running" up "$P2"
        t_fail "s: ngrok is stopped" up "$P1"
        kill "$P1" "$P2" 2>/dev/null
    fi
fi
stop_all
t_done
