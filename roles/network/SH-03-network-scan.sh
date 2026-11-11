#!/bin/sh
# =============================================================================
# ID:       SH-03
# NAME:     Network scan
# ROLE:     Network  (wave 1)
# KIND:     readonly - sends probes, changes nothing on any host
# VERSION:  1.0.0
#
# PURPOSE
#   Finds every live host and open port on the team's networks, with the
#   service and version behind each port.  The host collectors only see the
#   boxes you already know about; this finds the ones you do not, and the
#   ports that should not be open.
#
#   Given the host list (--hosts), it also answers the two questions that
#   matter most in the first minutes:
#     - Is every scored service reachable?   (HIGH flag if one is not)
#     - Is anything up that is not on the list?
#
#   Output is layered like every inventory script:
#     screen / summary.txt   hosts up, one line per host with its open ports,
#                            and only the HIGH and MEDIUM flags
#     hosts.csv, ports.csv   everything found
#     flags.csv              every flag, including LOW
#     raw/                   nmap's own output (.nmap, .gnmap, .xml)
#
# USAGE
#   sh SH-03-network-scan.sh --target 10.0.2.0/24 [options]
#   Run it from the admin workstation.  Root is not required, but nmap is
#   faster and can guess operating systems when run as root.
#
# OPTIONS
#   --target SPEC      what to scan; repeatable.  An address (10.0.2.5), a
#                      network (10.0.2.0/24), a last-octet range
#                      (10.0.2.1-50) or a host name
#   --targets-file F   one target per line (# comments allowed)
#   --hosts FILE       host list CSV (config/hosts.example.csv format).
#                      Turns on the host-list and scored-service checks
#   --profile NAME     fast | full | udp | outside   (default: fast)
#                        fast     top 1000 TCP ports with service versions
#                        full     all 65535 TCP ports (+ OS guess as root).
#                                 Slow: minutes per host
#                        udp      top 25 UDP ports (needs root)
#                        outside  like fast, but does not trust ping (-Pn);
#                                 run it from OUTSIDE the firewall to see
#                                 what the red team sees
#   --ports LIST       scan these ports instead (e.g. 22,80,443 or 1-1024)
#   --engine NAME      nmap | python | bash | nc   (default: first available,
#                      in that order).  Without nmap there is no version
#                      detection, only a banner, and only TCP
#   --no-dns           do not look up host names (faster when DNS is slow)
#   --pn               treat every target as up (for hosts that drop ping)
#   --max-hosts N      refuse to scan more than N addresses without nmap
#                      (default 1024); nmap has no limit
#   --max-flags N      HIGH/MED flags shown on screen (default 30)
#   --help             this text plus the common options
#
# OUTPUTS  (under --out, in SH-03_<host>_<UTC time>/)
#   summary.txt     the page printed on screen
#   hosts.csv       ip,hostname,status,open_tcp,open_udp,os_guess,in_host_list,host_list_name
#   ports.csv       ip,hostname,proto,port,state,service,version
#   flags.csv       severity,section,item,detail,time
#   scored.csv      host,ip,service,port,reachable      (only with --hosts)
#   raw/            nmap output in all three formats, or the fallback's results
#
# WHAT IT CHANGES
#   Nothing on any host.  It connects to ports and reads what they say.
#   Version detection sends ordinary protocol requests; it does not exploit
#   anything.  Scans are visible in logs, which is expected and fine on your
#   own network.
#
# DEPENDS ON
#   nmap (best).  Without it: python3, else bash with 'timeout', else nc -z.
#   awk, sort, getent or host for names.
#
# TESTED ON
#   Ubuntu 24.04 with nmap 7.94 and with the python, bash and nc fallbacks,
#   scanning listeners on 127.0.0.1, under dash, bash, busybox sh, ksh93,
#   mksh and yash.  Not yet tested against a real competition network.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - A closed port can mean "not listening" or "a firewall dropped it".  A
#     scored service that shows as not reachable may be fine from the scoring
#     engine's side; check it from there or with the service checker (SH-08).
#   - From inside, you see more than the red team does.  Use --profile
#     outside from outside the firewall for their view.
#   - Hosts that drop ping and have no common port open are missed unless
#     you use --pn (slower, because every address is scanned in full).
#   - The fallback engines only check a fixed list of common TCP ports.
#
# DEBUGGING
#   --debug          shows the exact nmap command and each parsing step
#   raw/*.nmap       nmap's own human-readable report: compare it with
#                    ports.csv if something looks missing
#   --engine python  forces the fallback, to compare with nmap's results
# =============================================================================

# >>> CCDC-LIB
# Development copy: find lib/lib.sh by walking up from this file.  The build
# step (tools/build.sh, LB-03) replaces this whole block with the library
# itself, so the built script is a single standalone file.
_cc_d=$(cd "$(dirname "$0")" && pwd)
while [ "$_cc_d" != "/" ] && [ ! -f "$_cc_d/lib/lib.sh" ]; do _cc_d=$(dirname "$_cc_d"); done
[ -f "$_cc_d/lib/lib.sh" ] || { echo "cannot find lib/lib.sh above $0" >&2; exit 3; }
. "$_cc_d/lib/lib.sh"
# <<< CCDC-LIB

# Ports the fallback engines check (TCP only).  Chosen for CCDC networks:
# the usual scored services, Windows/AD, databases, remote admin, and ports
# red teams like.
FALLBACK_PORTS="21,22,23,25,53,80,88,110,111,135,139,143,389,443,445,464,465,514,587,593,636,993,995,1080,1433,1521,2049,2375,3000,3268,3306,3389,4444,5000,5432,5601,5900,5985,5986,6379,6667,8000,8080,8081,8443,8888,9000,9090,9200,10000,11211,27017,31337"

usage() {
    cat <<'USAGE'
SH-03 Network scan - live hosts, open ports, services
  sh SH-03-network-scan.sh --target 10.0.2.0/24 [options]

  --target SPEC        address, network/NN, a.b.c.N-M or name (repeatable)
  --targets-file FILE  one target per line
  --hosts FILE         host list CSV: check scored services and unknown hosts
  --profile NAME       fast | full | udp | outside   (default fast)
  --ports LIST         ports to scan instead of the profile's
  --engine NAME        nmap | python | bash | nc     (default: best available)
  --no-dns             skip host name lookups
  --pn                 treat every target as up
  --max-hosts N        address limit for the fallback engines (default 1024)
  --max-flags N        HIGH/MED flags shown on screen (default 30)
  --help               show this text

USAGE
    cc_usage_common
}

# ---- Options ----------------------------------------------------------------
TARGETS=""
HOSTLIST=""
PROFILE=fast
PORTS=""
ENGINE=""
NODNS=0
PN=0
MAXHOSTS=1024
MAXFLAGS=30

# add_target SPEC -> append to TARGETS after checking it looks like an
#   address, network, range or host name.  Targets are handed to nmap as
#   separate arguments, never through a shell, but rejecting junk early
#   gives a clearer error than nmap's.
add_target() {
    case "$1" in
        ''|-*|*[!A-Za-z0-9./:_-]*) cc_die 2 "not a valid target: '$1' (use 10.0.2.5, 10.0.2.0/24, 10.0.2.1-50 or a name)" ;;
    esac
    TARGETS="$TARGETS $1"
}

while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --target)       [ $# -ge 2 ] || cc_die 2 "--target needs a value"; add_target "$2"; shift 2 ;;
        --targets-file) [ $# -ge 2 ] || cc_die 2 "--targets-file needs a file"
                        [ -r "$2" ] || cc_die 2 "cannot read targets file: $2"
                        for _t in $(sed 's/#.*//' "$2"); do add_target "$_t"; done
                        shift 2 ;;
        --hosts)        [ $# -ge 2 ] || cc_die 2 "--hosts needs a file"; HOSTLIST=$2; shift 2 ;;
        --profile)      [ $# -ge 2 ] || cc_die 2 "--profile needs a name"; PROFILE=$2; shift 2 ;;
        --ports)        [ $# -ge 2 ] || cc_die 2 "--ports needs a list"; PORTS=$2; shift 2 ;;
        --engine)       [ $# -ge 2 ] || cc_die 2 "--engine needs a name"; ENGINE=$2; shift 2 ;;
        --no-dns)       NODNS=1; shift ;;
        --pn)           PN=1; shift ;;
        --max-hosts)    [ $# -ge 2 ] || cc_die 2 "--max-hosts needs a number"; MAXHOSTS=$2; shift 2 ;;
        --max-flags)    [ $# -ge 2 ] || cc_die 2 "--max-flags needs a number"; MAXFLAGS=$2; shift 2 ;;
        --help|-h)      usage; exit 0 ;;
        *)              cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done

[ -n "$TARGETS" ] || cc_die 2 "nothing to scan: give --target or --targets-file (try --help)"
case "$PROFILE" in fast|full|udp|outside) ;; *) cc_die 2 "unknown profile '$PROFILE' (fast, full, udp or outside)" ;; esac
case "$MAXHOSTS" in ''|*[!0-9]*) cc_die 2 "--max-hosts needs a whole number" ;; esac
case "$MAXFLAGS" in ''|*[!0-9]*) cc_die 2 "--max-flags needs a whole number" ;; esac
case "$PORTS" in *[!0-9,-]*) cc_die 2 "--ports takes numbers, commas and ranges only (e.g. 22,80,8000-8100)" ;; esac
[ -z "$HOSTLIST" ] || [ -r "$HOSTLIST" ] || cc_die 2 "cannot read host list: $HOSTLIST"
[ "$PROFILE" = outside ] && PN=1

# Pick the engine: the requested one, or the best available.
if [ -z "$ENGINE" ]; then
    if cc_have nmap; then ENGINE=nmap
    elif cc_have python3; then ENGINE=python
    elif cc_have bash && cc_have timeout; then ENGINE=bash
    elif cc_have nc; then ENGINE=nc
    else cc_die 3 "no scanner available: install nmap (best), or make python3, bash with timeout, or nc available"
    fi
fi
case "$ENGINE" in
    nmap)   cc_need nmap ;;
    python) cc_need python3 ;;
    bash)   cc_need bash timeout ;;
    nc)     cc_need nc ;;
    *)      cc_die 2 "unknown engine '$ENGINE' (nmap, python, bash or nc)" ;;
esac
if [ "$PROFILE" = udp ] && [ "$ENGINE" != nmap ]; then cc_die 3 "the udp profile needs nmap"; fi

# ---- Start ------------------------------------------------------------------
cc_init "SH-03" "Network scan" readonly
cc_use_run_dir
W="$CC_RUN_DIR/.work"
mkdir -p "$W" || cc_die 3 "cannot create $W"
RAW="$CC_RUN_DIR/raw"
IS_ROOT=0
cc_is_root && IS_ROOT=1
if [ "$PROFILE" = udp ] && [ "$IS_ROOT" != 1 ]; then cc_die 3 "UDP scanning needs root (sudo)"; fi
cc_info "targets:$TARGETS | profile $PROFILE | engine $ENGINE"

# Shared awk helpers:
#   ip2n("10.0.2.5")      -> 167772677
#   n2ip(167772677)       -> "10.0.2.5"
#   intarget(ip, specs)   -> 1 if ip falls inside any of the space-separated
#                            target specs (address, CIDR, a.b.c.N-M); host
#                            names never match by address
AWK_IP='
function ip2n(ip,   p) { if (split(ip, p, ".") != 4) return -1; return ((p[1] * 256 + p[2]) * 256 + p[3]) * 256 + p[4] }    # awk: posix-ok
function n2ip(n,   a, b, c) { a = int(n / 16777216); n -= a * 16777216; b = int(n / 65536); n -= b * 65536; c = int(n / 256); return a "." b "." c "." (n - c * 256) }    # awk: posix-ok
function pow2(k,   r) { r = 1; while (k-- > 0) r *= 2; return r }    # awk: posix-ok
function intarget(ip, specs,   n, i, s, t, base, bits, size, lo, hi, m, x) {    # awk: posix-ok
    x = ip2n(ip); if (x < 0) return 0
    n = split(specs, s, " ")
    for (i = 1; i <= n; i++) {
        t = s[i]
        if (t == ip) return 1
        if (index(t, "/")) {
            split(t, m, "/"); bits = m[2] + 0; base = ip2n(m[1]); if (base < 0) continue
            size = pow2(32 - bits); lo = base - base % size
            if (x >= lo && x < lo + size) return 1
        } else if (t ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+-[0-9]+$/) {
            split(t, m, "-"); lo = ip2n(m[1]); hi = lo - lo % 256 + m[2]
            if (x >= lo && x <= hi) return 1
        }
    }
    return 0
}'

# Well-known names for ports, used by the fallback engines (nmap names its
# own) and in flags.
port_name() {
    case "$1" in
        21) echo ftp ;; 22) echo ssh ;; 23) echo telnet ;; 25) echo smtp ;; 53) echo domain ;; 69) echo tftp ;;
        80) echo http ;; 88) echo kerberos ;; 110) echo pop3 ;; 111) echo rpcbind ;; 135) echo msrpc ;;
        139) echo netbios-ssn ;; 143) echo imap ;; 161) echo snmp ;; 389) echo ldap ;; 443) echo https ;;
        445) echo microsoft-ds ;; 464) echo kpasswd ;; 465) echo smtps ;; 514) echo shell ;; 587) echo submission ;;
        593) echo http-rpc-epmap ;; 636) echo ldaps ;; 993) echo imaps ;; 995) echo pop3s ;; 1080) echo socks ;;
        1433) echo ms-sql-s ;; 1521) echo oracle ;; 2049) echo nfs ;; 2375) echo docker ;; 3268) echo globalcatLDAP ;;
        3306) echo mysql ;; 3389) echo ms-wbt-server ;; 5432) echo postgresql ;; 5601) echo kibana ;;
        5900) echo vnc ;; 5985) echo wsman ;; 5986) echo wsmans ;; 6379) echo redis ;; 6667) echo irc ;;
        8080|8000|8081|8888|9000|9090|3000|5000) echo http-alt ;; 8443) echo https-alt ;; 9200) echo elasticsearch ;;
        10000) echo webmin ;; 11211) echo memcache ;; 27017) echo mongodb ;; *) echo "" ;;
    esac
}

# ---- Expand targets (fallback engines only) --------------------------------
# nmap understands every target form itself.  The fallback engines need a
# plain list of addresses, built here and capped by --max-hosts.
expand_targets() {
    : >"$W/ips"
    for _t in $TARGETS; do
        case "$_t" in
            *[!0-9./-]*)  # a host name: resolve it
                _a=$(getent hosts "$_t" 2>/dev/null | awk '{ print $1; exit }')
                [ -n "$_a" ] && printf '%s\n' "$_a" >>"$W/ips" || cc_warn "cannot resolve $_t, skipped" ;;
            *)
                awk -v t="$_t" -v max="$MAXHOSTS" "$AWK_IP"'
                    BEGIN {
                        if (index(t, "/")) {
                            split(t, m, "/"); bits = m[2] + 0; base = ip2n(m[1])
                            if (base < 0 || bits < 8 || bits > 32) { print "BAD"; exit }
                            size = pow2(32 - bits); lo = base - base % size; hi = lo + size - 1
                            if (bits <= 30) { lo++; hi-- }          # skip network and broadcast
                        } else if (index(t, "-")) {
                            split(t, m, "-"); lo = ip2n(m[1]); hi = lo - lo % 256 + m[2]
                            if (lo < 0 || hi < lo) { print "BAD"; exit }
                        } else { lo = ip2n(t); hi = lo; if (lo < 0) { print "BAD"; exit } }
                        if (hi - lo + 1 > max) { print "TOOBIG " (hi - lo + 1); exit }
                        for (x = lo; x <= hi; x++) print n2ip(x)
                    }' >"$W/one"
                case "$(head -n 1 "$W/one")" in
                    BAD) cc_die 2 "cannot understand target '$_t'" ;;
                    TOOBIG*) cc_die 2 "target '$_t' has $(cut -d' ' -f2 "$W/one") addresses; the $ENGINE engine is limited to $MAXHOSTS (install nmap, scan a smaller range, or raise --max-hosts)" ;;
                esac
                cat "$W/one" >>"$W/ips" ;;
        esac
    done
    sort -u "$W/ips" -o "$W/ips"
    _n=$(wc -l <"$W/ips" | tr -d ' ')
    [ "$_n" -le "$MAXHOSTS" ] || cc_die 2 "$_n addresses in total; the $ENGINE engine is limited to $MAXHOSTS"
    cc_info "$_n address(es) to probe"
}

# ---- Engines ----------------------------------------------------------------
# Every engine ends by writing two normalised files that the rest of the
# script reads, so the reporting below does not care which engine ran:
#   $W/up     ip|hostname|os_guess          one line per live host
#   $W/open   ip|proto|port|service|version one line per open port

run_nmap() {
    _base="$RAW/nmap_$PROFILE"
    # Timing T4 is nmap's "aggressive but reliable on a LAN" setting.
    set -- -T4 --open -oA "$_base" --stats-every 60s
    [ "$NODNS" = 1 ] && set -- "$@" -n
    [ "$PN" = 1 ] && set -- "$@" -Pn
    case "$PROFILE" in
        fast|outside) set -- "$@" -sV --version-light ;;
        full)         set -- "$@" -sV; [ "$IS_ROOT" = 1 ] && set -- "$@" -O --osscan-limit ;;
        udp)          set -- "$@" -sU -sV --version-light ;;
    esac
    if [ -n "$PORTS" ]; then set -- "$@" -p "$PORTS"
    else
        case "$PROFILE" in
            fast|outside) set -- "$@" --top-ports 1000 ;;
            full)         set -- "$@" -p- ;;
            udp)          set -- "$@" --top-ports 25 ;;
        esac
    fi
    # shellcheck disable=SC2086
    set -- "$@" $TARGETS
    cc_info "running: nmap $*"
    [ "$PROFILE" = full ] && cc_info "full scans take minutes per host; progress is printed every 60 seconds"
    # nmap's own screen output goes to a file; only its progress lines are
    # shown, so the screen stays readable.
    nmap "$@" 2>&1 | tee "$RAW/nmap_screen.txt" | awk '/^Stats:|Timing:|^NSE: Script/ { print "   nmap: " $0; fflush() }' >&2
    [ -s "$_base.gnmap" ] || cc_die 1 "nmap produced no results (see $RAW/nmap_screen.txt); common causes: bad target, no permission for this scan type"
    nmap --version 2>/dev/null | head -n 1 >"$W/engine_version"

    # Grepable format, one host per line, tab-separated fields:
    #   Host: 10.0.2.5 (web01)<TAB>Ports: 22/open/tcp//ssh//OpenSSH 8.9p1/, 80/open/...<TAB>OS: Linux
    # Each port entry is exactly seven '/'-separated fields.  Versions can
    # contain commas, so entries are cut by matching that shape, not by
    # splitting on ", ".
    awk -F'\t' -v upf="$W/up" -v openf="$W/open" '
        /^Host: / {
            split($1, h, " "); ip = h[2]; name = $1; sub(/^Host: [^ ]* \(/, "", name); sub(/\)$/, "", name)
            os = ""
            for (i = 2; i <= NF; i++) if ($i ~ /^OS: /) { os = $i; sub(/^OS: /, "", os) }
            if (!(ip in seen) || os != "") { seen[ip] = 1; info[ip] = name "|" os }
            for (i = 2; i <= NF; i++) {
                if ($i !~ /^Ports: /) continue
                s = $i; sub(/^Ports: /, "", s)
                while (match(s, /^[0-9]+\/[^\/]*\/[^\/]*\/[^\/]*\/[^\/]*\/[^\/]*\/[^\/]*\//)) {
                    e = substr(s, 1, RLENGTH); s = substr(s, RLENGTH + 1); sub(/^, /, "", s)
                    split(e, f, "/")
                    if (f[2] ~ /^open/) { v = f[7]; gsub(/\|/, "/", v); print ip "|" f[3] "|" f[1] "|" f[5] "|" v > openf }
                }
            }
        }
        END { for (ip in info) print ip "|" info[ip] > upf }' "$_base.gnmap"
    touch "$W/up" "$W/open"
}

run_python() {
    expand_targets
    # One small Python program does a threaded TCP connect scan and reads a
    # short banner from each open port (HTTP ports get a HEAD request).
    cat >"$W/scan.py" <<'PY'
import socket, sys, threading
try:
    import queue
except ImportError:
    import Queue as queue
ips = [l.strip() for l in open(sys.argv[1]) if l.strip()]
ports = [int(p) for p in sys.argv[2].split(",") if p]
tmo = float(sys.argv[3])
out = open(sys.argv[4], "w")
HTTP = set([80, 3000, 5000, 8000, 8008, 8080, 8081, 8888, 9000, 9090])
lock = threading.Lock()
def probe(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(tmo)
    try:
        s.connect((ip, port))
    except Exception:
        s.close()
        return
    banner = ""
    try:
        if port in HTTP:
            s.sendall(("HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n" % ip).encode())
        s.settimeout(1.5)
        lines = s.recv(512).decode("latin-1", "replace").splitlines()
        if port in HTTP:
            srv = [l for l in lines if l.lower().startswith("server:")]
            banner = (lines[0] if lines else "") + (" " + srv[0] if srv else "")
        elif lines:
            banner = lines[0]
    except Exception:
        pass
    finally:
        s.close()
    banner = "".join(c if 32 <= ord(c) < 127 else " " for c in banner)[:150].replace("|", "/")
    with lock:
        out.write("%s|%d|%s\n" % (ip, port, banner))
        out.flush()
q = queue.Queue()
for i in ips:
    for p in ports:
        q.put((i, p))
def worker():
    while True:
        try:
            i, p = q.get_nowait()
        except queue.Empty:
            return
        probe(i, p)
ts = [threading.Thread(target=worker) for _ in range(min(128, max(1, q.qsize())))]
for t in ts:
    t.start()
for t in ts:
    t.join()
PY
    cc_info "probing $(printf '%s' "${PORTS:-$FALLBACK_PORTS}" | tr ',' '\n' | grep -c .) TCP port(s) per address with python"
    python3 "$W/scan.py" "$W/ips" "$(expand_ports)" 1.0 "$W/hits" 2>>"$CC_LOG" || cc_warn "python scan reported an error (see the log)"
    printf 'python %s\n' "$(python3 -V 2>&1)" >"$W/engine_version"
    finish_fallback
}

run_shell_engine() {
    expand_targets
    _plist=$(expand_ports | tr ',' ' ')
    : >"$W/hits"
    # One background job per address, at most 16 at a time.  Each job
    # writes its own file, so jobs never write to the same file at once.
    _n=0
    while IFS= read -r _ip; do
        (
            for _p in $_plist; do
                if [ "$ENGINE" = bash ]; then
                    timeout 1 bash -c "exec 3<>/dev/tcp/$_ip/$_p" 2>/dev/null && printf '%s|%s|\n' "$_ip" "$_p"
                else
                    nc -z -w 1 "$_ip" "$_p" >/dev/null 2>&1 && printf '%s|%s|\n' "$_ip" "$_p"
                fi
            done >"$W/hit.$_ip"
        ) &
        _n=$((_n + 1))
        [ $((_n % 16)) -eq 0 ] && wait
    done <"$W/ips"
    wait
    cat "$W"/hit.* >"$W/hits" 2>/dev/null
    rm -f "$W"/hit.*
    printf '%s\n' "$ENGINE connect scan" >"$W/engine_version"
    finish_fallback
}

# expand_ports -> print the port list with ranges (8000-8010) written out,
#   because the fallback engines take single ports.
expand_ports() {
    printf '%s' "${PORTS:-$FALLBACK_PORTS}" | tr ',' '\n' | awk -F- '
        NF == 2 { for (p = $1; p <= $2 && p <= 65535; p++) printf "%s%d", (n++ ? "," : ""), p; next }
        NF == 1 && $1 != "" { printf "%s%d", (n++ ? "," : ""), $1 }
        END { print "" }'
}

# finish_fallback -> turn $W/hits (ip|port|banner) into $W/up and $W/open.
#   A host counts as up when any port answered; there is no ping, because
#   ping is often missing or blocked.
finish_fallback() {
    : >"$W/open"
    while IFS='|' read -r _ip _p _ban; do
        printf '%s|tcp|%s|%s|%s\n' "$_ip" "$_p" "$(port_name "$_p")" "$_ban" >>"$W/open"
    done <"$W/hits"
    : >"$W/up"
    for _ip in $(cut -d'|' -f1 "$W/hits" | sort -u); do
        _name=""
        [ "$NODNS" = 1 ] || _name=$(getent hosts "$_ip" 2>/dev/null | awk '{ print $2; exit }')
        printf '%s|%s|\n' "$_ip" "$_name" >>"$W/up"
    done
}

case "$ENGINE" in
    nmap)    run_nmap ;;
    python)  run_python ;;
    bash|nc) run_shell_engine ;;
esac
sort -t'|' -k1,1 -u "$W/up" -o "$W/up"
sort -t'|' -k1,1 -k2,2 -k3,3n "$W/open" -o "$W/open"

# ---- Host list --------------------------------------------------------------
# Read config/hosts.csv into $W/hl as "ip|name|scored_services".  Lines that
# start with # are comments.  scored_services looks like http:80;dns:53.
: >"$W/hl"
if [ -n "$HOSTLIST" ]; then
    awk "$CC_AWK_CSV"'
        NR == 1 || /^[ \t]*#/ || NF == 0 { next }
        { csvsplit($0, f); if (f[2] != "") print f[2] "|" f[1] "|" f[8] }' "$HOSTLIST" >"$W/hl"
    cc_info "host list: $(wc -l <"$W/hl" | tr -d ' ') host(s) from $HOSTLIST"
fi

# ---- Write CSV files --------------------------------------------------------
HC=$(cc_csv_new hosts "ip,hostname,status,open_tcp,open_udp,os_guess,in_host_list,host_list_name")
PC=$(cc_csv_new ports "ip,hostname,proto,port,state,service,version")
awk -F'|' -v upf="$W/up" -v hlf="$W/hl" -v hc="$HC" -v pc="$PC" -v hashl="$( [ -s "$W/hl" ] && echo 1 || echo 0 )" '
    function q(s) { gsub(/"/, "\"\"", s); return "\"" s "\"" }    # awk: posix-ok
    BEGIN {
        while ((getline l < upf) > 0) { split(l, u, "|"); name[u[1]] = u[2]; os[u[1]] = u[3]; order[++n] = u[1] }
        while ((getline l < hlf) > 0) { split(l, h, "|"); hl[h[1]] = h[2] }
    }
    { if ($2 == "tcp") t[$1] = t[$1] (t[$1] == "" ? "" : " ") $3; else ud[$1] = ud[$1] (ud[$1] == "" ? "" : " ") $3
      print q($1) "," q(name[$1]) "," q($2) "," q($3) ",\"open\"," q($4) "," q($5) >> pc }
    END {
        for (i = 1; i <= n; i++) {
            ip = order[i]
            inl = hashl ? ((ip in hl) ? "yes" : "no") : ""
            print q(ip) "," q(name[ip]) ",\"up\"," q(t[ip]) "," q(ud[ip]) "," q(os[ip]) "," q(inl) "," q(hl[ip]) >> hc
        }
    }' "$W/open"

# ---- Flags ------------------------------------------------------------------
# Checks by port and by version banner.  Flags are pointers: a database port
# open on the database server may be exactly what the scoring engine needs.
while IFS='|' read -r _ip _pr _p _svc _ver; do
    _it="$_ip $_pr/$_p"
    [ -n "$_svc" ] || _svc="unknown service"
    case "$_pr/$_p" in
        tcp/2375) cc_flag HIGH ports "$_it" "Docker API without TLS: anyone who reaches it is root on that host" ;;
        tcp/23) cc_flag MED ports "$_it" "Telnet: cleartext logins" ;;
        tcp/512|tcp/513|tcp/514) cc_flag MED ports "$_it" "rsh/rlogin/rexec-style cleartext service" ;;
        udp/69) cc_flag MED ports "$_it" "TFTP: no authentication; files can be read by guessing names" ;;
        udp/161) cc_flag MED ports "$_it" "SNMP: check the community strings are not public/private" ;;
        tcp/590[0-9]) cc_flag MED ports "$_it" "VNC remote desktop; check it requires a password" ;;
        tcp/6379) cc_flag MED ports "$_it" "Redis: often has no password" ;;
        tcp/27017) cc_flag MED ports "$_it" "MongoDB: often has no password" ;;
        tcp/9200) cc_flag MED ports "$_it" "Elasticsearch: often has no authentication" ;;
        tcp/11211) cc_flag MED ports "$_it" "memcached: no authentication" ;;
        tcp/1337|tcp/4444|tcp/4445|tcp/5555|tcp/6666|tcp/12345|tcp/31337|tcp/54321) cc_flag MED ports "$_it" "port commonly used by backdoors and reverse shells ($_svc)" ;;
        tcp/3306|tcp/1433|tcp/5432|tcp/1521) cc_flag LOW ports "$_it" "database reachable over the network ($_svc); fine if the scoring engine or a web server needs it" ;;
        tcp/21) cc_flag LOW ports "$_it" "FTP: cleartext logins" ;;
    esac
    # Versions with known backdoors or trivial remote root, common in CCDC
    # images.  The weakness checker (SH-14) will cover many more.
    case "$_ver" in
        *"vsftpd 2.3.4"*) cc_flag HIGH ports "$_it" "vsftpd 2.3.4 has a built-in backdoor (smiley-face login)" ;;
        *"ProFTPD 1.3.3c"*) cc_flag HIGH ports "$_it" "ProFTPD 1.3.3c release was backdoored" ;;
        *"ProFTPD 1.3.5"*) cc_flag HIGH ports "$_it" "ProFTPD 1.3.5 mod_copy lets anyone copy files" ;;
        *UnrealIRCd*) cc_flag HIGH ports "$_it" "UnrealIRCd: the 3.2.8.1 release was backdoored" ;;
        *"Samba smbd 3.0.2"*) cc_flag HIGH ports "$_it" "Samba 3.0.20-3.0.25 allows remote root (usermap_script)" ;;
        *distccd*) cc_flag HIGH ports "$_it" "distccd runs commands for anyone who connects" ;;
        *"Microsoft Windows XP"*|*"Windows Server 2003"*) cc_flag HIGH ports "$_it" "end-of-life Windows ($_ver)" ;;
    esac
    if [ "$PROFILE" = outside ]; then
        case "$_pr/$_p" in tcp/445|tcp/139|tcp/3389|tcp/5985|tcp/5986|tcp/135) cc_flag MED ports "$_it" "Windows admin service ($_svc) is reachable from outside the firewall" ;; esac
    fi
done <"$W/open"

# Host list checks: unknown hosts, missing hosts, scored services.
if [ -s "$W/hl" ]; then
    SC=$(cc_csv_new scored "host,ip,service,port,reachable")
    while IFS='|' read -r _ip _name _os; do
        grep -q "^$_ip|" "$W/hl" || cc_flag MED hosts "$_ip ${_name:-}" "host is up but not on the host list: find out what it is"
    done <"$W/up"
    while IFS='|' read -r _ip _name _scored; do
        _inscope=$(awk -v ip="$_ip" -v specs="$TARGETS" "$AWK_IP"'BEGIN { print intarget(ip, specs) }')
        [ "$_inscope" = 1 ] || continue
        _isup=no; grep -q "^$_ip|" "$W/up" && _isup=yes
        [ "$_isup" = yes ] || cc_flag MED hosts "$_ip $_name" "on the host list but did not answer the scan"
        for _s in $(printf '%s' "$_scored" | tr ';' ' '); do
            _svc=${_s%%:*}; _p=${_s##*:}
            case "$_p" in ''|*[!0-9]*) continue ;; esac
            if grep -q "^$_ip|tcp|$_p|" "$W/open" || grep -q "^$_ip|udp|$_p|" "$W/open"; then
                cc_csv_row "$SC" "$_name" "$_ip" "$_svc" "$_p" yes
            else
                cc_csv_row "$SC" "$_name" "$_ip" "$_svc" "$_p" no
                cc_flag HIGH scored "$_name $_ip $_svc:$_p" "scored service is not reachable from here; check it now (it may only be blocked from this machine)"
            fi
        done
    done <"$W/hl"
    if [ "$PROFILE" = outside ]; then
        # From outside, an open port that is not a scored service on that host
        # is attack surface the red team can see.
        while IFS='|' read -r _ip _pr _p _svc _ver; do
            _sc=$(awk -F'|' -v ip="$_ip" '$1 == ip { print $3 }' "$W/hl")
            case ";$_sc;" in *":$_p;"*) ;; *) cc_flag MED outside "$_ip $_pr/$_p" "reachable from outside but not a scored service on this host ($_svc)" ;; esac
        done <"$W/open"
    fi
fi

# ---- Summary ----------------------------------------------------------------
_nup=$(wc -l <"$W/up" | tr -d ' ')
_nopen=$(wc -l <"$W/open" | tr -d ' ')
_unknown=""
[ -s "$W/hl" ] && _unknown=" ($(awk -F'|' -v hlf="$W/hl" 'BEGIN { while ((getline l < hlf) > 0) { split(l, h, "|"); k[h[1]] = 1 } } !($1 in k) { n++ } END { print n + 0 }' "$W/up") not on the host list)"
{
    printf 'SH-03 Network scan | from %s | %s | profile %s | engine %s\n' "$CC_HOST" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$PROFILE" "$(cat "$W/engine_version" 2>/dev/null)"
    printf 'Targets:%s\n\n' "$TARGETS"
    printf 'Hosts up: %s%s\nOpen ports: %s\n\n' "$_nup" "$_unknown" "$_nopen"
    # One line per host: address, name, open ports with service names.
    awk -F'|' -v upf="$W/up" '
        BEGIN { while ((getline l < upf) > 0) { split(l, u, "|"); name[u[1]] = u[2]; order[++n] = u[1] } }
        { p[$1] = p[$1] (p[$1] == "" ? "" : ", ") $3 ($2 == "udp" ? "/udp" : "") ($4 == "" ? "" : " " $4) }
        END {
            for (i = 1; i <= n && i <= 40; i++) { ip = order[i]; printf "  %-15s %-20s %s\n", ip, substr(name[ip], 1, 20), (p[ip] == "" ? "(no open ports in range)" : p[ip]) }
            if (n > 40) printf "  ... %d more hosts in hosts.csv\n", n - 40
        }' "$W/open"
    if [ -n "$HOSTLIST" ] && [ -n "${SC:-}" ]; then
        _sok=$(grep -c '"yes"$' "$SC"); _sno=$(grep -c '"no"$' "$SC")
        printf '\nScored services: %s reachable, %s NOT reachable\n' "$_sok" "$_sno"
    fi
    printf '\n'
    cc_flag_report "$MAXFLAGS"
    printf '\nAll results: %s\n' "$CC_RUN_DIR"
} >"$CC_RUN_DIR/summary.txt"
cat "$CC_RUN_DIR/summary.txt"
rm -rf "$W"
cc_finish
