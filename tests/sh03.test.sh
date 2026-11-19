#!/bin/sh
# Tests for roles/network/SH-03-network-scan.sh.
#   1. options
#   2. a fake nmap (a stub on PATH) to check the stages, the merge, the vuln
#      parsing, the flags, the questions and SH-04 reading the new folders
#   3. two listeners on 127.0.0.1 (a web server and a "backdoor" port)
#      scanned with the python engine and, when installed, real nmap
# Needs python3 for the listeners.  Nothing outside 127.0.0.1 is scanned.
. "$(dirname "$0")/helper.sh"
SH=${TEST_SHELL:-sh}
C="$T_ROOT/roles/network/SH-03-network-scan.sh"
export CCDC_SKIP_VERIFY=1
# shellcheck disable=SC2086
run() { $SH "$C" "$@"; }

t_start "options"
run >/dev/null 2>&1; t_eq "$?" 2 "no target and nobody to ask exits 2"
run --target 'bad;rm' >/dev/null 2>&1; t_eq "$?" 2 "a target with shell characters is refused"
run --target 10.0.0.0/8 --engine python --out "$T_TMP/x" >/dev/null 2>&1; t_eq "$?" 2 "too many addresses for a fallback engine exits 2"
run --target 127.0.0.1 --ports '22;id' >/dev/null 2>&1; t_eq "$?" 2 "bad --ports exits 2"
run --target 127.0.0.1 --profile huge >/dev/null 2>&1; t_eq "$?" 2 "unknown profile exits 2"
t_has "$(run --help 2>&1)" "--vuln / --no-vuln" "help lists the scan questions as flags"

t_start "nmap check"
# A PATH with every usual program except nmap.
mkdir -p "$T_TMP/nonmap"
for _f in /usr/local/bin/* /usr/bin/* /bin/*; do
    _b=$(basename "$_f"); [ -e "$T_TMP/nonmap/$_b" ] || ln -s "$_f" "$T_TMP/nonmap/$_b" 2>/dev/null
done
rm -f "$T_TMP/nonmap/nmap"
r=$(env PATH="$T_TMP/nonmap" $SH "$C" --target 127.0.0.1 --ports 1 --out "$T_TMP/nn" 2>&1); t_eq "$?" 0 "without nmap it keeps going (default yes)"
t_has "$r" "nmap is not installed on this box" "says nmap is missing"
t_has "$r" "Install it:" "and how to install it"
r=$(env PATH="$T_TMP/nonmap" $SH "$C" --target 127.0.0.1 --engine nmap --out "$T_TMP/nn" 2>&1); t_eq "$?" 3 "--engine nmap without nmap exits 3"
t_has "$r" "Install it:" "   with the install command"
if command -v nmap >/dev/null 2>&1; then
    r=$(run --target 127.0.0.1 --ports 1 --no-scripts --no-services --no-os --no-udp --out "$T_TMP/nn" 2>&1)
    t_has "$r" "[ok] nmap found" "says when nmap is found"
fi

# ---- Fake nmap ----------------------------------------------------------------
# Writes results for 10.9.9.5 by stage name (the -oA file name) and logs its
# arguments.  quick: 21, 22.  full: adds 4444.  details: versions and the
# XML with script results.
mkdir -p "$T_TMP/bin"
cat >"$T_TMP/bin/nmap" <<'STUB'
#!/bin/sh
[ "$1" = --version ] && { echo "Nmap version 9.99 (stub)"; exit 0; }
printf '%s\n' "$*" >>"$STUBLOG"
b=""; prev=""
for a in "$@"; do [ "$prev" = -oA ] && b=$a; prev=$a; done
T=$(printf '\t')
case "$(basename "$b")" in
    1-quick|1-ports) P="21/open/tcp//ftp///, 22/open/tcp//ssh///" ;;
    2-full)  P="21/open/tcp//ftp///, 22/open/tcp//ssh///, 4444/open/tcp//krb524///" ;;
    3-details) P="21/open/tcp//ftp//vsftpd 2.3.4/, 22/open/tcp//ssh//OpenSSH 8.9p1 Ubuntu (protocol 2.0)/, 4444/open/tcp//shell//sh-5.1\$ /"
        # Script results only when scripts were asked for.
        case "$*" in *--script*|*-sC*) ;; *) b=$b.noscripts ;; esac
        cat >"$b.xml" <<'XML'
<host starttime="1"><status state="up"/>
<address addr="10.9.9.5" addrtype="ipv4"/>
<hostnames><hostname name="web01"/></hostnames>
<ports>
<port protocol="tcp" portid="21"><state state="open"/><service name="ftp"/><script id="ftp-anon" output="Anonymous FTP login allowed (FTP code 230)&#xa;-rw-r--r-- 1 0 0 0 a.txt"/></port>
<port protocol="tcp" portid="22"><state state="open"/><script id="vulners" output="&#xa;  cpe:/a:openbsd:openssh:8.9p1: &#xa;    &#x9;CVE-2023-38408&#x9;9.8&#x9;https://vulners.com/cve/CVE-2023-38408&#xa;    &#x9;CVE-2023-51385&#x9;6.5&#x9;https://vulners.com/cve/CVE-2023-51385"/></port>
<port protocol="tcp" portid="4444"><state state="open"/><script id="test-vuln" output="&#xa;  VULNERABLE:&#xa;  Test remote weakness&#xa;    State: VULNERABLE&#xa;    IDs:  CVE:CVE-2099-0001&#xa;"/></port>
</ports>
<hostscript><script id="test-notvuln" output="&#xa;  NOT VULNERABLE:&#xa;  Other thing&#xa;    State: NOT VULNERABLE&#xa;"/></hostscript>
</host>
XML
        ;;
    4-udp) P="69/open|filtered/udp//tftp///, 161/open/udp//snmp//net-snmp/" ;;
esac
b=${b%.noscripts}
# The quick scan also sees 10.9.9.6 up, with no open ports.
case "$(basename "$b")" in 1-quick) printf 'Host: 10.9.9.6 ()%sStatus: Up\n' "$T" >"$b.gnmap" ;; *) : >"$b.gnmap" ;; esac
printf 'Host: 10.9.9.5 (web01)%sStatus: Up\nHost: 10.9.9.5 (web01)%sPorts: %s%sIgnored State: closed (997)\n' "$T" "$T" "$P" "$T" >>"$b.gnmap"
: >"$b.nmap"; [ -f "$b.xml" ] || : >"$b.xml"
echo "Nmap scan report for web01 (10.9.9.5)"
echo "21/tcp open  ftp"
echo "SF-Port4444-TCP:V=7.94%I=7%D=1/1%Time=0%P=x"
echo "SF:%r(NULL,0,\"\")"
echo "Nmap done: 1 IP address (1 host up)"
STUB
chmod +x "$T_TMP/bin/nmap"
export STUBLOG="$T_TMP/stub.log"
# In a subshell: ksh keeps a VAR=value set in front of a function call, which
# would leave the fake nmap on PATH for the real-nmap tests below.
srun() { ( PATH="$T_TMP/bin:$PATH"; export PATH; run "$@" ); }

t_start "stages with a fake nmap (--batch: every default)"
: >"$STUBLOG"
r=$(srun --out "$T_TMP/s" --target 10.9.9.0/24 --batch --vuln --no-os --no-color 2>&1); t_eq "$?" 0 "exits 0"
R="$T_TMP/s/netscan-1"
t_file "$R/run.txt" "numbered folder netscan-1 with run.txt"
t_eq "$(sed -n 1p "$STUBLOG" | grep -c -- '--top-ports 1000')" 1 "1: quick scan of the top 1000 ports"
t_has "$(sed -n 1p "$STUBLOG")" "10.9.9.0/24" "   on the whole target"
t_has "$(sed -n 1p "$STUBLOG")" "-T4" "   at speed 4 (default)"
t_has "$(sed -n 2p "$STUBLOG")" "-p- --stats-every 60s 10.9.9.5 10.9.9.6" "2: full scan only on the hosts that were up (all, the default)"
t_has "$(sed -n 3p "$STUBLOG")" "-p 21,22,4444" "3: details only on the open ports"
t_has "$(sed -n 3p "$STUBLOG")" "default or (vuln and safe)" "   with default scripts and safe vuln scripts"
t_eq "$(grep -c . "$STUBLOG")" 3 "no UDP scan (default no)"
t_has "$r" "==========[ 1/3  quick scan" "stage headings"
t_has "$r" "Nmap scan report for web01" "nmap's own output is shown"
t_hasnt "$r" "SF:%r" "service fingerprints are cut from the screen"
t_has "$(cat "$R/output.txt")" "Nmap scan report for web01" "and saved in output.txt"
for f in summary.txt hosts.txt ports.txt vulns.txt flags.txt csv/hosts.csv csv/ports.csv csv/vulns.csv csv/flags.csv raw/1-quick.gnmap raw/2-full.gnmap raw/3-details.xml; do t_file "$R/$f" "$f written"; done
t_ok "versions from the details stage win" grep -q '"10.9.9.5","web01","tcp","21","open","ftp","vsftpd 2.3.4"' "$R/csv/ports.csv"
t_ok "port only the full scan found is listed" grep -q '"tcp","4444"' "$R/csv/ports.csv"
t_ok "VULNERABLE script result in vulns.csv" grep -q '"test-vuln","VULNERABLE","Test remote weakness","CVE-2099-0001"' "$R/csv/vulns.csv"
t_fail "NOT VULNERABLE is not listed" grep -q 'test-notvuln' "$R/csv/vulns.csv"
t_ok "vulners: count and worst score" grep -q '"vulners","known CVEs","2 known vulnerabilities for this version, worst score 9.8"' "$R/csv/vulns.csv"
t_ok "anonymous FTP found" grep -q '"ftp-anon","finding","anonymous FTP login allowed"' "$R/csv/vulns.csv"
F="$R/csv/flags.csv"
t_ok "VULNERABLE flagged HIGH" grep -q '"HIGH","vulns","10.9.9.5 tcp/4444","test-vuln says VULNERABLE: Test remote weakness (CVE-2099-0001)"' "$F"
t_ok "CVE score 9.8 flagged HIGH" grep -q '"HIGH","vulns","10.9.9.5 tcp/22","2 known' "$F"
t_ok "anonymous FTP flagged HIGH" grep -q '"HIGH","vulns","10.9.9.5 tcp/21","anonymous FTP' "$F"
t_ok "vsftpd 2.3.4 flagged HIGH" grep -q '"HIGH","ports","10.9.9.5 tcp/21","vsftpd 2.3.4' "$F"
t_ok "shell answering on a port flagged HIGH" grep -q '"HIGH","ports","10.9.9.5 tcp/4444","answers like a shell' "$F"
t_ok "4444 flagged as a backdoor-style port" grep -q '"MED","ports","10.9.9.5 tcp/4444"' "$F"
S=$(cat "$R/summary.txt")
t_has "$S" "Hosts up: 2 | open ports: 3 | vulnerable: 1" "summary counts hosts, ports, vulns"
t_has "$S" "Vulns and script findings" "summary lists the vulns"
t_has "$S" "Open ports" "summary lists the ports per host"
t_has "$r" "[!] FIX   10.9.9.5 tcp/4444: test-vuln says VULNERABLE" "flags shown live"

t_start "fake nmap: speed, top ports, extra ports, picked hosts"
: >"$STUBLOG"
srun --out "$T_TMP/s2" --target 10.9.9.0/24 --speed 2 --top-ports 100 --extra-ports 8080,9000-9001 --full-hosts 10.9.9.6 --no-services --no-scripts --no-os --no-udp >/dev/null 2>&1
t_eq "$?" 0 "exits 0"
t_has "$(sed -n 1p "$STUBLOG")" "-T2" "--speed 2 gives -T2"
t_has "$(sed -n 1p "$STUBLOG")" "--top-ports 100" "--top-ports 100"
t_has "$(sed -n 2p "$STUBLOG")" "-p 8080,9000-9001 10.9.9.0/24" "extra ports scanned on every target"
t_has "$(sed -n 3p "$STUBLOG")" "-p- --stats-every 60s 10.9.9.6" "full scan only on the picked host"
t_hasnt "$(sed -n 3p "$STUBLOG")" "10.9.9.5" "   and not the others"
run --target 10.9.9.5 --speed 9 >/dev/null 2>&1; t_eq "$?" 2 "--speed 9 exits 2"
run --target 10.9.9.5 --top-ports 0 >/dev/null 2>&1; t_eq "$?" 2 "--top-ports 0 exits 2"
run --target 10.9.9.5 --extra-ports 'x;y' >/dev/null 2>&1; t_eq "$?" 2 "bad --extra-ports exits 2"
: >"$STUBLOG"
srun --out "$T_TMP/s2" --target 10.9.9.5 --no-quick --no-full --ports 22 --vuln-all --no-scripts --no-os --no-udp >/dev/null 2>&1
t_has "$(tail -n 1 "$STUBLOG")" "--script vuln 10.9.9.5" "--vuln-all runs every vuln script"

t_start "fake nmap: --ports, --no-full, UDP, profiles"
: >"$STUBLOG"
srun --out "$T_TMP/s" --target 10.9.9.5 --ports 21,22 --no-scripts --no-services --no-os --udp >/dev/null 2>&1
t_has "$(cat "$STUBLOG")" "-p 21,22 10.9.9.5" "--ports replaces the quick and full scans"
t_eq "$(grep -c -- '-p-' "$STUBLOG")" 0 "no full scan with --ports"
if [ "$(id -u)" = 0 ]; then
    t_has "$(tail -n 1 "$STUBLOG")" "-sU" "UDP scan as root"
    t_ok "UDP port listed" grep -q '"udp","161"' "$T_TMP/s/netscan-2/csv/ports.csv"
    t_ok "SNMP flagged" grep -q '"MED","ports","10.9.9.5 udp/161"' "$T_TMP/s/netscan-2/csv/flags.csv"
    t_fail "a UDP port that is only open|filtered is not listed as open" grep -q '"udp","69"' "$T_TMP/s/netscan-2/csv/ports.csv"
else
    t_eq "$(grep -c -- '-sU' "$STUBLOG")" 0 "no UDP scan without root"
fi
: >"$STUBLOG"
srun --out "$T_TMP/s" --target 10.9.9.5 --profile fast >/dev/null 2>&1
t_eq "$(grep -c . "$STUBLOG")" 2 "profile fast: quick scan and details"
t_has "$(tail -n 1 "$STUBLOG")" "-sV" "   with versions"
t_hasnt "$(cat "$STUBLOG")" "-sC" "   and no scripts"
t_has "$(cat "$T_TMP/s/netscan-3/summary.txt")" "Vulns: not checked" "summary says when vulns were not checked"
: >"$STUBLOG"
srun --out "$T_TMP/s" --target 10.9.9.5 --profile wrccdc >/dev/null 2>&1
t_has "$(sed -n 1p "$STUBLOG")" "-p 21,22,23,25,53,80,88" "WRCCDC profile scans the competition service set"
t_has "$(sed -n 1p "$STUBLOG")" "3389,5432,5900,5985,5986" "WRCCDC profile includes Windows and both candidate databases"
t_eq "$(grep -c -- '-p-' "$STUBLOG")" 0 "WRCCDC profile avoids a slow full scan"

t_start "SH-04 compares two netscan-N runs"
r=$($SH "$T_ROOT/roles/network/SH-04-scan-diff.sh" --runs "$T_TMP/s" --out "$T_TMP/d" 2>&1); t_eq "$?" 0 "SH-04 exits 0"
t_has "$r" "netscan-3" "picks the older run"
t_has "$r" "netscan-4" "and the newest run"
r=$($SH "$T_ROOT/roles/network/SH-04-scan-diff.sh" --old "$T_TMP/s/netscan-4" --new "$T_TMP/s/netscan-1" --out "$T_TMP/d" 2>&1)
t_eq "$?" 0 "SH-04 with --old and --new exits 0"
t_ok "new vuln between runs flagged HIGH" grep -q '"HIGH","vulns"' "$(ls -d "$T_TMP"/d/diff-*/ | tail -n 1)csv/flags.csv"

if command -v script >/dev/null 2>&1 && script -qc true /dev/null >/dev/null 2>&1; then
    t_start "questions in a terminal (fake nmap)"
    : >"$STUBLOG"
    # target, speed (5), quick (Enter), top ports (100), extra ports (8080),
    # full (n), services (Enter), scripts (n), vuln (y), safe only (n), then
    # OS (n) and UDP (Enter) when root.
    printf '10.9.9.5\n5\n\n100\n8080\nn\n\nn\ny\nn\nn\n\n' >"$T_TMP/answers"
    CCDC_NO_TTY=0 PATH="$T_TMP/bin:$PATH" script -qc "$SH $C --out $T_TMP/q --no-color --no-dns" /dev/null <"$T_TMP/answers" >"$T_TMP/tty.out" 2>&1
    t_has "$(cat "$T_TMP/tty.out")" "What should I scan?" "asks for the target"
    t_has "$(cat "$T_TMP/tty.out")" "vuln scripts" "asks about vuln scripts"
    t_has "$(sed -n 1p "$STUBLOG")" "10.9.9.5" "scans the typed target"
    t_eq "$(grep -c -- '-p-' "$STUBLOG")" 0 "no full scan after 'n'"
    t_has "$(cat "$T_TMP/tty.out")" "How aggressive?" "asks how aggressive"
    t_has "$(cat "$T_TMP/tty.out")" "How many top ports" "asks how many top ports"
    t_has "$(cat "$T_TMP/tty.out")" "other ports to always scan" "asks for extra ports"
    t_has "$(sed -n 1p "$STUBLOG")" "-T5 --open" "speed 5 after '5'"
    t_has "$(sed -n 1p "$STUBLOG")" "--top-ports 100" "top 100 after '100'"
    t_has "$(sed -n 2p "$STUBLOG")" "-p 8080" "extra port 8080 scanned"
    t_has "$(tail -n 1 "$STUBLOG")" "--script vuln 10.9.9.5" "all vuln scripts after 'n' to safe only, without default scripts"
    t_has "$(tail -n 1 "$STUBLOG")" "-sV" "versions after Enter (default yes)"
    t_start "nmap check in a terminal"
    printf 'n\n' >"$T_TMP/answers3"
    CCDC_NO_TTY=0 PATH="$T_TMP/nonmap" script -qc "$SH $C --out $T_TMP/q3 --no-color --target 127.0.0.1" /dev/null <"$T_TMP/answers3" >"$T_TMP/tty3.out" 2>&1
    t_has "$(cat "$T_TMP/tty3.out")" "Keep going with the" "asks whether to keep going without nmap"
    t_has "$(cat "$T_TMP/tty3.out")" "Install nmap and run again" "stops after 'n'"
    t_fail "and scans nothing" ls -d "$T_TMP"/q3/netscan-*/ 2>/dev/null

    t_start "picking hosts for the full scan in a terminal"
    : >"$STUBLOG"
    printf '10.9.9.6\n' >"$T_TMP/answers2"
    CCDC_NO_TTY=0 PATH="$T_TMP/bin:$PATH" script -qc "$SH $C --out $T_TMP/q --no-color --target 10.9.9.0/24 --speed 4 --quick --top-ports 10 --no-extra-ports --full --no-services --no-scripts --no-vuln --no-os --no-udp" /dev/null <"$T_TMP/answers2" >"$T_TMP/tty2.out" 2>&1
    t_has "$(cat "$T_TMP/tty2.out")" "Full scan which hosts?" "asks which hosts get the full scan"
    t_has "$(cat "$T_TMP/tty2.out")" "up: 10.9.9.5 10.9.9.6" "after showing the hosts that are up"
    t_has "$(sed -n 2p "$STUBLOG")" "-p- --stats-every 60s 10.9.9.6" "full scan only on the typed host"
    t_hasnt "$(sed -n 2p "$STUBLOG")" "10.9.9.5" "   and not the other"
else
    t_start "(skipped: no 'script' command for the terminal test)"
fi

# ---- Real listeners -----------------------------------------------------------
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
time.sleep(900)' 18181 31337 >/dev/null 2>&1 &
LPID=$!
# Wait until both listeners answer (up to 10 seconds).
_i=0
until python3 -c 'import socket,sys
for p in (18181, 31337): socket.create_connection(("127.0.0.1", p), 1).close()' 2>/dev/null || [ "$_i" -ge 20 ]; do
    sleep 0.5 2>/dev/null || sleep 1; _i=$((_i + 1))
done
printf 'host,ip,os,role,connect,port,user,scored_services,notes\nself,127.0.0.1,linux,test,ssh,22,u,http:18181;smtp:2526,\nghost,127.0.0.9,linux,gone,ssh,22,u,,\n' >"$T_TMP/hosts.csv"

for engine in python nmap; do
    if [ "$engine" = nmap ] && ! command -v nmap >/dev/null 2>&1; then t_start "(skipped: nmap not installed)"; continue; fi
    t_start "$engine engine on 127.0.0.1"
    r=$(run --out "$T_TMP/o_$engine" --target 127.0.0.1 --target 127.0.0.9 --ports 2526,31337,18181 --hosts "$T_TMP/hosts.csv" --engine "$engine" --no-dns --no-scripts --no-os 2>/dev/null)
    t_eq "$?" 0 "exits 0"
    R="$T_TMP/o_$engine/netscan-1"
    for f in summary.txt output.txt hosts.txt ports.txt flags.txt scored.txt csv/hosts.csv csv/ports.csv csv/flags.csv csv/scored.csv; do t_file "$R/$f" "$f written"; done
    t_ok "port 18181 found" grep -q '"127.0.0.1","","tcp","18181"' "$R/csv/ports.csv"
    t_ok "port 31337 found" grep -q '"127.0.0.1","","tcp","31337"' "$R/csv/ports.csv"
    t_fail "closed port 2526 not listed" grep -q '"2526"' "$R/csv/ports.csv"
    t_ok "31337 flagged as a backdoor-style port" grep -q '"MED","ports","127.0.0.1 tcp/31337"' "$R/csv/flags.csv"
    t_ok "missing scored service flagged HIGH" grep -q '"HIGH","scored","self 127.0.0.1 smtp:2526"' "$R/csv/flags.csv"
    t_ok "reachable scored service recorded" grep -q '"self","127.0.0.1","http","18181","yes"' "$R/csv/scored.csv"
    t_ok "host on the list that did not answer is flagged" grep -q '"127.0.0.9 ghost"' "$R/csv/flags.csv"
    t_has "$r" "Scored services: 1 reachable, 1 NOT reachable" "summary counts scored services"
    t_has "$r" "31337" "open ports shown"
done
kill "$LPID" 2>/dev/null
t_done
