#!/bin/sh
# Tests for roles/network/SH-03-network-scan.sh.
# Starts two listeners on 127.0.0.1 (a web server and a "backdoor" port),
# scans them with the python engine and, when installed, nmap, and checks
# the results and the host-list checks.  Needs python3 for the listeners.
. "$(dirname "$0")/helper.sh"
SH=${TEST_SHELL:-sh}
C="$T_ROOT/roles/network/SH-03-network-scan.sh"
export CCDC_SKIP_VERIFY=1
# shellcheck disable=SC2086
run() { $SH "$C" "$@"; }

t_start "options"
run >/dev/null 2>&1; t_eq "$?" 2 "no target exits 2"
run --target 'bad;rm' >/dev/null 2>&1; t_eq "$?" 2 "a target with shell characters is refused"
run --target 10.0.0.0/8 --engine python --out "$T_TMP/x" >/dev/null 2>&1; t_eq "$?" 2 "too many addresses for a fallback engine exits 2"
run --target 127.0.0.1 --ports '22;id' >/dev/null 2>&1; t_eq "$?" 2 "bad --ports exits 2"
run --target 127.0.0.1 --profile huge >/dev/null 2>&1; t_eq "$?" 2 "unknown profile exits 2"

if ! command -v python3 >/dev/null 2>&1; then
    t_start "(skipped: python3 is needed for the test listeners)"; t_done; exit $?
fi
# Two listeners that accept and close connections; killed at the end.
python3 -c '
import socket, threading, time, sys
def serve(port, reply):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port)); s.listen(64)
    while True:
        c, _ = s.accept()
        try: c.sendall(reply)
        except Exception: pass
        c.close()
for p, r in ((int(sys.argv[1]), b"HTTP/1.0 200 OK\r\nServer: TestServer\r\n\r\n"), (int(sys.argv[2]), b"")):
    threading.Thread(target=serve, args=(p, r), daemon=True).start()  # python, not shell: posix-ok
time.sleep(300)' 18181 31337 >/dev/null 2>&1 &
LPID=$!
sleep 1
printf 'host,ip,os,role,connect,port,user,scored_services,notes\nself,127.0.0.1,linux,test,ssh,22,u,http:18181;smtp:2526,\nghost,127.0.0.9,linux,gone,ssh,22,u,,\n' >"$T_TMP/hosts.csv"

for engine in python nmap; do
    if [ "$engine" = nmap ] && ! command -v nmap >/dev/null 2>&1; then t_start "(skipped: nmap not installed)"; continue; fi
    t_start "$engine engine"
    r=$(run --out "$T_TMP/o_$engine" --target 127.0.0.1 --target 127.0.0.9 --ports 2526,31337,18181 --hosts "$T_TMP/hosts.csv" --engine "$engine" --no-dns 2>/dev/null)
    t_eq "$?" 0 "exits 0"
    R=$(ls -d "$T_TMP/o_$engine"/SH-03_*/ | head -n 1)
    for f in summary.txt hosts.csv ports.csv flags.csv scored.csv; do t_file "$R/$f" "$f written"; done
    t_ok "port 18181 found" grep -q '"127.0.0.1","","tcp","18181"' "$R/ports.csv"
    t_ok "port 31337 found" grep -q '"127.0.0.1","","tcp","31337"' "$R/ports.csv"
    t_fail "closed port 2526 not listed" grep -q '"2526"' "$R/ports.csv"
    t_ok "31337 flagged as a backdoor-style port" grep -q '"MED","ports","127.0.0.1 tcp/31337"' "$R/flags.csv"
    t_ok "missing scored service flagged HIGH" grep -q '"HIGH","scored","self 127.0.0.1 smtp:2526"' "$R/flags.csv"
    t_ok "reachable scored service recorded" grep -q '"self","127.0.0.1","http","18181","yes"' "$R/scored.csv"
    t_ok "host on the list that did not answer is flagged" grep -q '"127.0.0.9 ghost"' "$R/flags.csv"
    t_has "$r" "Scored services: 1 reachable, 1 NOT reachable" "summary counts scored services"
done
kill "$LPID" 2>/dev/null
t_done
