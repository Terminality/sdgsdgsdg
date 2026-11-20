#!/bin/sh
# =============================================================================
# ID:       SH-03
# NAME:     Network scan
# ROLE:     Network  (wave 1)
# KIND:     readonly - sends probes, changes nothing on any host
# VERSION:  2.3.0
#
# PURPOSE
#   Finds every live host and open port on the team's networks.  Asks what
#   to scan and which extras to run (like sqlmap: Enter takes the default),
#   then runs nmap in stages and shows nmap's own output as it goes:
#     1. quick scan    the top N TCP ports (asks how many) plus any extra
#                      ports you name, on every target
#     2. full scan     all 65535 TCP ports on the hosts that are up, or
#                      the ones you pick
#     3. details       on the open ports only: service versions, OS guess,
#                      nmap's default scripts, vuln scripts (safe ones)
#     4. UDP           top 25 UDP ports (root)
#   At the end it flags anything bad (backdoor ports, VULNERABLE script
#   results, known-bad versions, risky services) and prints a summary of
#   hosts, ports and vulns, colour-coded like the Linux enum (SH-05).
#
#   Given the host list (--hosts), it also checks:
#     - Is every scored service reachable?   (HIGH flag if one is not)
#     - Is anything up that is not on the list?
#
# USAGE
#   sh SH-03-network-scan.sh                     asks everything
#   sh SH-03-network-scan.sh --target 10.0.2.0/24 --batch     all defaults
#   Run it from the admin workstation.  Root is not required, but nmap is
#   faster as root, and OS detection and UDP need it.
#
# OPTIONS
#   --target SPEC      what to scan; repeatable.  An address (10.0.2.5), a
#                      network (10.0.2.0/24), a last-octet range
#                      (10.0.2.1-50) or a host name.  Asked if not given
#   --targets-file F   one target per line (# comments allowed)
#   --hosts FILE       host list (config/hosts.example.txt format).
#                      Turns on the host-list and scored-service checks
#   Answers in advance (each skips its question):
#   --quick / --no-quick        top 1000 ports first          (default yes)
#   --full / --no-full          all 65535 ports               (default yes)
#   --services / --no-services  service and version detection (default yes)
#   --scripts / --no-scripts    nmap default scripts (-sC)    (default yes)
#   --vuln / --no-vuln          nmap vuln scripts, safe ones  (default no)
#   --vuln-all                  every vuln script (some can crash a service)
#   --speed N                   1-5: nmap timing -T1..-T5     (default 4)
#   --top-ports N               ports in the quick scan       (default 1000)
#   --extra-ports LIST          also scan these ports on every target
#                               (--no-extra-ports: none, no question)
#   --full-hosts LIST           full scan only these hosts    (default all up)
#   --os / --no-os              OS guess, root only           (default yes)
#   --udp / --no-udp            top 25 UDP ports, root only   (default no)
#   --team-number N    also scan the outside range 10.100.1NN.0/24: team 2 is
#                      10.100.102.0/24, team 13 is 10.100.113.0/24 (1:1 NAT,
#                      the team packet's numbering; asked, Enter skips)
#   --profile NAME     preset answers, no questions:
#                        fast     quick scan + services
#                        full     quick + full + services (+ OS as root)
#                        udp      UDP only
#                        outside  like fast, but does not trust ping (-Pn);
#                                 run it from OUTSIDE the firewall to see
#                                 what the red team sees
#   --ports LIST       scan only these ports (e.g. 22,80,443 or 1-1024)
#                      instead of the quick and full scans
#   --engine NAME      nmap | python | bash | nc   (default: first available,
#                      in that order).  Without nmap there is no version
#                      detection, no scripts, only a banner, and only TCP
#   --no-dns           do not look up host names (faster when DNS is slow)
#   --pn               treat every target as up (for hosts that drop ping)
#   --max-hosts N      refuse to scan more than N addresses without nmap
#                      (default 1024); nmap has no limit
#   --max-flags N      HIGH/MED flags shown in the summary (default 30)
#   --no-color         no colours
#   --batch            no questions: take every default
#   --help             this text plus the common options
#
# OUTPUTS  (under --out, in netscan-N/)
#   output.txt      everything shown on screen, without colour
#   summary.txt     the summary page
#   hosts.txt       ip, name, status, open ports, OS guess
#   roles.txt       what each box looks like: ip, guess (router, Gitea, file
#                   share, domain controller, Windows, RabbitMQ, Home
#                   Assistant, web app), os, why
#   suggested-hosts.txt   host-list rows for config/hosts.txt (copy the right
#                   ones, give them real names)
#   ports.txt       one line per open port with service and version
#   vulns.txt       what the vuln and default scripts found
#   flags.txt       every flag, HIGH first
#   scored.txt      scored services reachable or not   (only with --hosts)
#                   (tables: columns separated by " | "; SH-04 and NW-20
#                   read them.  No CSV.)
#   raw/            nmap's own output for each stage (.nmap, .gnmap, .xml)
#   run.txt         ID, host and time
#
# WHAT IT CHANGES
#   Nothing on any host.  It connects to ports and reads what they say.
#   By default only vuln scripts in nmap's "safe" category are run, so
#   nothing meant to crash or change a service (--vuln-all runs them all).  Scans are visible in logs, which is
#   expected and fine on your own network.
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
#     engine's side; check it from there.
#   - From inside, you see more than the red team does.  Use --profile
#     outside from outside the firewall for their view.
#   - Hosts that drop ping and have no top-1000 port open are missed unless
#     you use --pn (slower, because every address is scanned in full).
#   - The full scan takes minutes per host.  nmap prints progress every
#     minute.  Ctrl-C stops it; nothing is changed either way.
#   - A vuln script that says nothing does not mean "safe".  The vuln list
#     is a pointer, not a verdict.
#   - The fallback engines only check a fixed list of common TCP ports.
#
# DEBUGGING
#   --debug          shows the exact nmap commands
#   raw/*.nmap       nmap's own report for each stage
#   --engine python  forces the fallback, to compare with nmap's results
# =============================================================================

# >>> BT-LIB
# Development copy: find lib/lib.sh by walking up from this file.  The build
# step (tools/build.sh, LB-03) replaces this whole block with the library
# itself, so the built script is a single standalone file.
_cc_d=$(cd "$(dirname "$0")" && pwd)
while [ "$_cc_d" != "/" ] && [ ! -f "$_cc_d/lib/lib.sh" ]; do _cc_d=$(dirname "$_cc_d"); done
[ -f "$_cc_d/lib/lib.sh" ] || { echo "cannot find lib/lib.sh above $0" >&2; exit 3; }
. "$_cc_d/lib/lib.sh"
# <<< BT-LIB

# Ports the fallback engines check (TCP only).  Chosen for competition networks:
# the usual scored services, Windows/AD, databases, remote admin, and ports
# red teams like.
FALLBACK_PORTS="21,22,23,25,53,80,88,110,111,135,139,143,389,443,445,464,465,514,587,593,636,993,995,1080,1433,1521,2049,2222,2375,3000,3268,3306,3389,4444,5000,5432,5601,5672,5900,5985,5986,6379,6667,8000,8080,8081,8123,8443,8888,9000,9090,9200,10000,11211,15672,27017,31337"

usage() {
    cat <<'USAGE'
SH-03 Network scan - live hosts, open ports, services, vulns
  sh SH-03-network-scan.sh                          asks what to scan
  sh SH-03-network-scan.sh --target 10.0.2.0/24 --batch

  --target SPEC        address, network/NN, a.b.c.N-M or name (repeatable)
  --targets-file FILE  one target per line
  --hosts FILE         host list: check scored services and unknown hosts
  --quick / --no-quick        top 1000 ports first          (default yes)
  --full / --no-full          all 65535 ports               (default yes)
  --services / --no-services  service and version detection (default yes)
  --scripts / --no-scripts    nmap default scripts          (default yes)
  --vuln / --no-vuln          nmap vuln scripts (safe ones) (default no)
  --vuln-all                  every vuln script (some can crash a service)
  --speed N                   1 slow/quiet .. 5 fastest     (default 4)
  --top-ports N               ports in the quick scan       (default 1000)
  --extra-ports LIST          also scan these ports         (default none)
  --full-hosts LIST           full scan only these hosts    (default all up)
  --os / --no-os              OS guess, needs root          (default yes)
  --udp / --no-udp            top 25 UDP ports, needs root  (default no)
  --team-number N      also scan the outside range 10.100.(100+N).0/24, e.g. team 2: 10.100.102.0/24 (asked)
  --profile NAME       fast | full | udp | outside  (preset answers, no questions)
  --ports LIST         scan only these ports instead of the quick and full scans
  --engine NAME        nmap | python | bash | nc     (default: best available)
  --no-dns             skip host name lookups
  --pn                 treat every target as up
  --max-hosts N        address limit for the fallback engines (default 1024)
  --max-flags N        HIGH/MED flags shown in the summary (default 30)
  --no-color           no colours
  --help               show this text

USAGE
    cc_usage_common
}

# ---- Options ----------------------------------------------------------------
TARGETS=""
TEAMNUM=""
HOSTLIST=""
PROFILE=""
PORTS=""
ENGINE=""
NODNS=0
PN=0
MAXHOSTS=1024
MAXFLAGS=30
COLOR=1
# Answers: Y, N, or empty (ask).
A_QUICK=""; A_FULL=""; A_SVC=""; A_SCRIPTS=""; A_VULN=""; A_OS=""; A_UDP=""; A_VSAFE=""
SPEED=""          # nmap timing 1-5 (-T)
TOP=""            # how many top ports in the quick scan
EXTRA=""; EXTRA_SET=0   # extra ports to always scan
FULLHOSTS=""      # which hosts get the full scan: "all" or addresses

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
        --team-number)  [ $# -ge 2 ] || cc_die 2 "--team-number needs a number"; TEAMNUM=$2; shift 2 ;;
        --profile)      [ $# -ge 2 ] || cc_die 2 "--profile needs a name"; PROFILE=$2; shift 2 ;;
        --ports)        [ $# -ge 2 ] || cc_die 2 "--ports needs a list"; PORTS=$2; shift 2 ;;
        --engine)       [ $# -ge 2 ] || cc_die 2 "--engine needs a name"; ENGINE=$2; shift 2 ;;
        --quick)        A_QUICK=Y; shift ;;     --no-quick)    A_QUICK=N; shift ;;
        --full)         A_FULL=Y; shift ;;      --no-full)     A_FULL=N; shift ;;
        --services)     A_SVC=Y; shift ;;       --no-services) A_SVC=N; shift ;;
        --scripts)      A_SCRIPTS=Y; shift ;;   --no-scripts)  A_SCRIPTS=N; shift ;;
        --vuln)         A_VULN=Y; shift ;;      --no-vuln)     A_VULN=N; shift ;;
        --os)           A_OS=Y; shift ;;        --no-os)       A_OS=N; shift ;;
        --udp)          A_UDP=Y; shift ;;       --no-udp)      A_UDP=N; shift ;;
        --speed)        [ $# -ge 2 ] || cc_die 2 "--speed needs 1-5"; SPEED=$2; shift 2 ;;
        --top-ports)    [ $# -ge 2 ] || cc_die 2 "--top-ports needs a number"; TOP=$2; shift 2 ;;
        --extra-ports)  [ $# -ge 2 ] || cc_die 2 "--extra-ports needs a list"; EXTRA=$2; EXTRA_SET=1; shift 2 ;;
        --no-extra-ports) EXTRA=""; EXTRA_SET=1; shift ;;
        --full-hosts)   [ $# -ge 2 ] || cc_die 2 "--full-hosts needs addresses or all"; FULLHOSTS=$2; shift 2 ;;
        --vuln-all)     A_VULN=Y; A_VSAFE=N; shift ;;
        --no-dns)       NODNS=1; shift ;;
        --pn)           PN=1; shift ;;
        --max-hosts)    [ $# -ge 2 ] || cc_die 2 "--max-hosts needs a number"; MAXHOSTS=$2; shift 2 ;;
        --max-flags)    [ $# -ge 2 ] || cc_die 2 "--max-flags needs a number"; MAXFLAGS=$2; shift 2 ;;
        --no-color|--no-colour) COLOR=0; shift ;;
        --help|-h)      usage; exit 0 ;;
        *)              cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done

case "$PROFILE" in ''|fast|full|udp|outside) ;; *) cc_die 2 "unknown profile '$PROFILE' (fast, full, udp or outside)" ;; esac
case "$MAXHOSTS" in ''|*[!0-9]*) cc_die 2 "--max-hosts needs a whole number" ;; esac
case "$MAXFLAGS" in ''|*[!0-9]*) cc_die 2 "--max-flags needs a whole number" ;; esac
case "$PORTS" in *[!0-9,-]*) cc_die 2 "--ports takes numbers, commas and ranges only (e.g. 22,80,8000-8100)" ;; esac
[ -z "$HOSTLIST" ] || [ -r "$HOSTLIST" ] || cc_die 2 "cannot read host list: $HOSTLIST"
# ok_speed / ok_top / ok_ports VALUE -> true when VALUE is usable.
ok_speed() { case "$1" in [1-5]) return 0 ;; esac; return 1; }
ok_top() { case "$1" in ''|*[!0-9]*) return 1 ;; esac; [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }
ok_ports() { case "$1" in *[!0-9,-]*) return 1 ;; esac; return 0; }
[ -z "$SPEED" ] || ok_speed "$SPEED" || cc_die 2 "--speed takes 1 (slow, quiet) to 5 (fastest)"
[ -z "$TOP" ] || ok_top "$TOP" || cc_die 2 "--top-ports takes a number from 1 to 65535"
ok_ports "$EXTRA" || cc_die 2 "--extra-ports takes numbers, commas and ranges only (e.g. 8080,9000-9100)"
case "$FULLHOSTS" in *[!A-Za-z0-9./:_,\ -]*) cc_die 2 "--full-hosts takes addresses or all" ;; esac
[ "$PROFILE" = outside ] && PN=1

# A profile is a set of answers.  Flags given on top still win.
preset() { eval "[ -n \"\$$1\" ] || $1=$2"; }
case "$PROFILE" in
    fast|outside) preset A_QUICK Y; preset A_FULL N; preset A_SVC Y ;;
    full)         preset A_QUICK Y; preset A_FULL Y; preset A_SVC Y; preset A_OS Y ;;
    udp)          preset A_QUICK N; preset A_FULL N; preset A_UDP Y ;;
esac
if [ -n "$PROFILE" ]; then
    for _v in A_QUICK A_FULL A_SVC A_SCRIPTS A_VULN A_OS A_UDP; do preset "$_v" N; done
    preset SPEED 4; preset TOP 1000; preset A_VSAFE Y; preset FULLHOSTS all; EXTRA_SET=1
fi
# --ports replaces the quick and full scans.
[ -n "$PORTS" ] && { A_QUICK=N; A_FULL=N; }

# install_hint -> the command that installs nmap on this box.
install_hint() {
    if cc_have apt-get; then echo "sudo apt install nmap"
    elif cc_have dnf; then echo "sudo dnf install nmap"
    elif cc_have yum; then echo "sudo yum install nmap"
    elif cc_have zypper; then echo "sudo zypper install nmap"
    elif cc_have apk; then echo "sudo apk add nmap"
    elif cc_have pacman; then echo "sudo pacman -S nmap"
    else echo "install the nmap package (https://nmap.org/download)"
    fi
}

# Pick the engine: the requested one, or the best available.
NMAP_MISSING=0
cc_have nmap || NMAP_MISSING=1
[ "$ENGINE" = nmap ] && [ "$NMAP_MISSING" = 1 ] && cc_die 3 "nmap is not installed on this box. Install it: $(install_hint)"
if [ -z "$ENGINE" ]; then
    if cc_have nmap; then ENGINE=nmap
    elif cc_have python3; then ENGINE=python
    elif cc_have bash && cc_have timeout; then ENGINE=bash
    elif cc_have nc; then ENGINE=nc
    else cc_die 3 "no scanner available. Install nmap: $(install_hint)"
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
IS_ROOT=0
cc_is_root && IS_ROOT=1
if [ "$PROFILE" = udp ] && [ "$IS_ROOT" != 1 ]; then cc_die 3 "UDP scanning needs root (sudo)"; fi

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

# guess_target -> this machine's own network, e.g. 10.0.2.0/24, as the
#   default answer.  Networks bigger than a /22 are cut to the /24 around
#   this machine, so Enter never starts a scan of a /8.
guess_target() {
    _gt=$( (ip -o -4 addr show scope global 2>/dev/null || ip -o -4 addr show 2>/dev/null) | awk '$4 !~ /^127\./ { print $4; exit }')
    [ -n "$_gt" ] || return 0
    awk -v t="$_gt" "$AWK_IP"'BEGIN {
        split(t, m, "/"); bits = m[2] + 0; x = ip2n(m[1]); if (x < 0) exit
        if (bits < 22) bits = 24
        size = pow2(32 - bits); print n2ip(x - x % size) "/" bits }'
}

# ---- Questions (sqlmap style) -------------------------------------------------
# Before the run folder exists, so a question answered wrong costs nothing.
cc_color_init
[ "$COLOR" = 1 ] || { C_RED=""; C_YEL=""; C_GRN=""; C_CYN=""; C_GRY=""; C_OFF=""; }
# Quick check: is nmap here?  Without it the scan is much weaker, and the
# scan questions (speed, ports, versions, scripts, vulns, UDP) are skipped.
if [ "$NMAP_MISSING" = 1 ]; then
    cc_show "$C_YEL" "[!] nmap is not installed on this box, so the scan questions are skipped."
    cc_show "$C_YEL" "    Without it: $(printf '%s' "$FALLBACK_PORTS" | tr ',' '\n' | grep -c .) common TCP ports only, a banner instead of a version, no scripts, no vulns, no UDP."
    cc_show "$C_YEL" "    Install it: $(install_hint)"
    cc_ask "Keep going with the $ENGINE scan anyway?" Y "yes, scan with $ENGINE" "no, stop (install nmap first)" || { cc_show "" "Install nmap and run again: $(install_hint)"; exit 3; }
elif [ "$ENGINE" = nmap ]; then
    cc_show "$C_GRN" "[ok] nmap found: $(nmap --version 2>/dev/null | head -n 1)"
fi
case "$TEAMNUM" in ''|none) ;; *[!0-9]*) cc_die 2 "--team-number: a number from 1 to 155" ;; *) TEAMNUM=$((TEAMNUM + 0)); [ "$TEAMNUM" -ge 1 ] && [ "$TEAMNUM" -le 155 ] || cc_die 2 "--team-number: a number from 1 to 155" ;; esac
if [ -z "$TARGETS" ]; then
    _can=0; _cc_can_ask && _can=1
    if [ "$_can" = 0 ] && { [ -z "$TEAMNUM" ] || [ "$TEAMNUM" = none ]; }; then cc_die 2 "nothing to scan: give --target, --targets-file or --team-number (try --help)"; fi
    if [ "$_can" = 1 ]; then
        cc_ask_text "What should I scan? (the inside network this box is on is the default)" "$(guess_target)" "one host 10.0.2.5, a range 10.0.2.1-50 or a subnet 10.0.2.0/24; several separated by spaces"
        for _t in $(printf '%s' "$CC_ANSWER" | tr ',' ' '); do add_target "$_t"; done
    fi
fi
# The outside range (1:1 NAT, the team packet): 10.100.1XX.Y is 192.168.220.Y,
# XX the team number - team 2 is 10.100.102.0/24.  Asked, so nobody needs to
# know it before the day.
if [ -z "$TEAMNUM" ] && _cc_can_ask; then
    cc_ask_text "Your team number? It adds the outside range 10.100.1XX.0/24 (team 2 = 10.100.102.0/24) to the scan" "" "a number from 1 to 155 (Enter = skip the outside range)"
    case "$CC_ANSWER" in ''|*[!0-9]*) [ -n "$CC_ANSWER" ] && cc_show "$C_YEL" "[*] '$CC_ANSWER' is not a team number: the outside range is skipped" ;;
        *) _tn=$((CC_ANSWER + 0)); [ "$_tn" -ge 1 ] && [ "$_tn" -le 155 ] && TEAMNUM=$_tn ;; esac
fi
OUTSIDE=""
case "$TEAMNUM" in ''|none) ;; *) OUTSIDE="10.100.$((100 + TEAMNUM)).0/24"
    case " $TARGETS " in *" $OUTSIDE "*) ;; *) add_target "$OUTSIDE"; cc_show "$C_GRN" "[ok] team $TEAMNUM: the outside range $OUTSIDE is scanned too (10.100.$((100 + TEAMNUM)).Y = 192.168.220.Y)" ;; esac ;; esac
[ -n "$TARGETS" ] || cc_die 2 "nothing to scan"

# ask VAR QUESTION DEFAULT [YES-MEANS] [NO-MEANS] -> fill VAR with Y or N
#   unless a flag already did.
ask() {
    eval "_ak=\$$1"
    [ -n "$_ak" ] && return 0
    if cc_ask "$2" "$3" "${4:-yes}" "${5:-no}"; then eval "$1=Y"; else eval "$1=N"; fi
}
# ask_val VAR CHECK QUESTION DEFAULT -> fill VAR with a typed answer that
#   passes CHECK (ok_speed, ok_top, ok_ports), unless a flag already did.
#   Asks again on a bad answer, at most three times.
ask_val() {
    eval "_av=\$$1"
    [ -n "$_av" ] && return 0
    _av_n=0
    while :; do
        cc_ask_text "$3" "$4" "${5:-}"
        if "$2" "$CC_ANSWER"; then eval "$1=\$CC_ANSWER"; return 0; fi
        _av_n=$((_av_n + 1))
        [ "$_av_n" -lt 3 ] && _cc_can_ask || cc_die 2 "not a usable answer: '$CC_ANSWER'"
        printf '    not a usable answer, try again\n' >/dev/tty
    done
}
if [ "$ENGINE" = nmap ]; then
    ask_val SPEED ok_speed "How aggressive?" 4 "1-2 slow and quiet, 3 normal, 4 fast (good on a LAN), 5 fastest (can miss ports)"
    ask A_QUICK   "Quick scan of the top ports first?" Y "yes, quick scan first" "no, skip it"
    [ "$A_QUICK" = Y ] && ask_val TOP ok_top "How many top ports in the quick scan?" 1000 "a number: 100 is very fast, 1000 is nmap's normal"
    if [ "$EXTRA_SET" = 0 ] && [ -z "$PORTS" ]; then
        cc_ask_text "Any other ports to always scan?" "" "ports and ranges separated by commas, like 8080,9000-9100"
        ok_ports "$CC_ANSWER" || cc_die 2 "not a port list: '$CC_ANSWER' (use numbers, commas and ranges)"
        EXTRA=$CC_ANSWER
    fi
    ask A_FULL    "Full scan of all 65535 ports on the hosts that are up?" Y "yes, full scan (slow: minutes per host)" "no, quick scan only"
    ask A_SVC     "Find the service and version behind each open port?" Y "yes, find them" "no, ports only"
    ask A_SCRIPTS "Run nmap's default scripts on the open ports (anonymous FTP, SMB signing, ...)?" Y "yes, run them" "no, skip them"
    ask A_VULN    "Run nmap's vuln scripts on the open ports?" N "yes, run them (adds a few minutes)" "no, skip them"
    [ "$A_VULN" = Y ] && ask A_VSAFE "Only the safe vuln scripts?" Y "yes, safe ones only" "no, every vuln script (some can crash a service)"
    if [ "$IS_ROOT" = 1 ]; then
        ask A_OS  "Guess each host's operating system?" Y "yes, guess it" "no, skip it"
        ask A_UDP "Scan the top 25 UDP ports too? (DNS, SNMP, TFTP, ...)" N "yes, scan UDP too" "no, TCP only"
    else
        [ "$A_OS" = Y ] && cc_warn "OS detection needs root: skipped"
        [ "$A_UDP" = Y ] && cc_warn "UDP scanning needs root: skipped"
        A_OS=N; A_UDP=N
    fi
    [ "$A_QUICK" = N ] && [ "$A_FULL" = N ] && [ "$A_UDP" = N ] && [ -z "$PORTS" ] && { cc_warn "no port scan picked: doing the quick scan"; A_QUICK=Y; }
else
    case "$A_SVC$A_SCRIPTS$A_VULN$A_OS$A_UDP" in *Y*) cc_warn "the $ENGINE engine has no services, scripts, vuln, OS or UDP scans (they need nmap): skipped" ;; esac
    A_SVC=N; A_SCRIPTS=N; A_VULN=N; A_OS=N; A_UDP=N
fi

[ -n "$SPEED" ] || SPEED=4
[ -n "$TOP" ] || TOP=1000
[ -n "$A_VSAFE" ] || A_VSAFE=Y
# Extra ports join --ports, or the fallback engines' list.
if [ -n "$EXTRA" ] && { [ -n "$PORTS" ] || [ "$ENGINE" != nmap ]; }; then
    PORTS="${PORTS:-$FALLBACK_PORTS},$EXTRA"; EXTRA=""
fi

# ---- Start ------------------------------------------------------------------
# shellcheck disable=SC2034  # read by the library: tables as .txt, no CSV
CC_TABLES=1
cc_init "SH-03" "Network scan" readonly
cc_use_numbered_dir netscan
W="$CC_RUN_DIR/.work"
mkdir -p "$W" || cc_die 3 "cannot create $W"
RAW="$CC_RUN_DIR/raw"

# Live output goes to fd 3 (a copy of stdout taken here); output.txt gets
# the same lines without colour.
exec 3>&1
OUTF="$CC_RUN_DIR/output.txt"
grep -v '\[NOTE\]\|\[DEBUG\]' "$CC_LOG" >"$OUTF" 2>/dev/null || : >"$OUTF"
# Read by the library's log functions.
# shellcheck disable=SC2034
CC_TEE=$OUTF
show() {
    printf '%s%s%s\n' "$1" "$2" "$C_OFF" >&3
    printf '%s\n' "$2" >>"$OUTF"
}
yn() { [ "$1" = Y ] && echo yes || echo no; }
SCANS="speed $SPEED"
[ "$A_QUICK" = Y ] && SCANS="$SCANS, quick (top $TOP)"
[ -n "$EXTRA" ] && SCANS="$SCANS, extra ports $EXTRA"
[ "$A_FULL" = Y ] && SCANS="$SCANS, full (all 65535)"
[ -n "$PORTS" ] && SCANS="$SCANS, ports $PORTS"
[ "$A_SVC" = Y ] && SCANS="$SCANS, services"
[ "$A_SCRIPTS" = Y ] && SCANS="$SCANS, scripts"
[ "$A_VULN" = Y ] && { [ "$A_VSAFE" = Y ] && SCANS="$SCANS, vuln (safe)" || SCANS="$SCANS, vuln (all)"; }
[ "$A_OS" = Y ] && SCANS="$SCANS, OS"
[ "$A_UDP" = Y ] && SCANS="$SCANS, UDP"
[ "$ENGINE" = nmap ] || SCANS=", $ENGINE connect scan of ${PORTS:-common ports}"
SCANS=${SCANS#, }
show "$C_CYN" "SH-03 Network scan | from $CC_HOST | engine $ENGINE | results in $CC_RUN_DIR"
show "$C_CYN" "Targets:$TARGETS"
show "$C_CYN" "Scans: $SCANS"
show "" "Legend: ${C_RED}[!] FIX${C_OFF} look now (HIGH)   ${C_YEL}[*] LOOK${C_OFF} look soon (MED)   ${C_GRN}green${C_OFF} open port"
cc_note "targets:$TARGETS | engine $ENGINE | scans: $SCANS"

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
        2222) echo ssh-alt ;; 5672) echo amqp ;; 15672) echo rabbitmq-mgmt ;; 8123) echo home-assistant ;;
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

STAGE_N=0
STAGE_TOTAL=0
# stage TITLE -> print a linpeas-style heading for the next scan stage.
stage() {
    STAGE_N=$((STAGE_N + 1))
    show "" ""
    show "$C_CYN" "==========[ $STAGE_N/$STAGE_TOTAL  $1 ]=========="
}

# nmap_run NAME ARG... -> run nmap with its normal output shown live (open
#   ports green, VULNERABLE red, host headers cyan) and saved in output.txt;
#   all three nmap formats go to raw/NAME.*.
nmap_run() {
    _nr=$1; shift
    set -- "-T$SPEED" --open -oA "$RAW/$_nr" "$@"
    [ "$NODNS" = 1 ] && set -- -n "$@"
    cc_debug "running: nmap $*"
    show "$C_GRY" "\$ nmap $*"
    # Service fingerprints (SF: lines) are long hex dumps; they stay in
    # raw/NAME.nmap but are cut from the screen and output.txt.
    nmap "$@" 2>&1 | awk '
        /^SF[-:]|^=+NEXT SERVICE FINGERPRINT|^[0-9]+ services? unrecognized|^If you know the service/ { if (!cut++) print "(service fingerprints cut here; they are in the raw/*.nmap files)"; fflush(); next }
        { print; fflush() }' | tee -a "$OUTF" | awk -v R="$C_RED" -v G="$C_GRN" -v C="$C_CYN" -v D="$C_GRY" -v O="$C_OFF" '
        /NOT VULNERABLE/                { print; fflush(); next }
        /VULNERABLE/                    { print R $0 O; fflush(); next }
        /^[0-9]+\/(tcp|udp) +open/      { print G $0 O; fflush(); next }
        /^Nmap scan report for/         { print C $0 O; fflush(); next }
        /^Stats:|Timing:|^Nmap done/    { print D $0 O; fflush(); next }
                                        { print; fflush() }' >&3
    [ -s "$RAW/$_nr.gnmap" ] || cc_die 1 "nmap produced no results (see $OUTF); common causes: bad target, no permission for this scan type"
}

# up_hosts GNMAP -> addresses nmap saw as up, one per line.
up_hosts() { awk '/^Host: .*Status: Up/ { print $2 }' "$@" | sort -u; }
# open_list GNMAP PROTO -> host addresses with an open PROTO port, and the
#   port list "22,80,443" across them (written to $W/hosts_open, $W/ports_open).
open_list() {
    awk -F'\t' -v pr="$2" -v hf="$W/hosts_open" -v pf="$W/ports_open" '
        /^Host: / {
            split($1, h, " ")
            for (i = 2; i <= NF; i++) {
                if ($i !~ /^Ports: /) continue
                s = $i; sub(/^Ports: /, "", s)
                while (match(s, /^[0-9]+\/[^\/]*\/[^\/]*\/[^\/]*\/[^\/]*\/[^\/]*\/[^\/]*\//)) {
                    e = substr(s, 1, RLENGTH); s = substr(s, RLENGTH + 1); sub(/^, /, "", s)
                    split(e, f, "/")
                    if (f[2] == "open" && f[3] == pr) { hs[h[2]] = 1; ps[f[1] + 0] = 1 }
                }
            }
        }
        END {
            for (x in hs) print x > hf
            # in number order ("for in" order differs between awks)
            n = 0; for (p in ps) { v = p + 0; for (j = n; j > 0 && o[j] > v; j--) o[j + 1] = o[j]; o[j + 1] = v; n++ }
            s = ""; for (j = 1; j <= n; j++) s = s (s == "" ? "" : ",") o[j]
            print s > pf
        }' "$1"
    touch "$W/hosts_open"
}

run_nmap() {
    _det=0
    { [ "$A_SVC" = Y ] || [ "$A_SCRIPTS" = Y ] || [ "$A_VULN" = Y ] || [ "$A_OS" = Y ]; } && _det=1
    STAGE_TOTAL=0
    [ "$A_QUICK" = Y ] && STAGE_TOTAL=$((STAGE_TOTAL + 1))
    [ "$A_FULL" = Y ] && STAGE_TOTAL=$((STAGE_TOTAL + 1))
    [ -n "$PORTS" ] && STAGE_TOTAL=$((STAGE_TOTAL + 1))
    [ -n "$EXTRA" ] && STAGE_TOTAL=$((STAGE_TOTAL + 1))
    [ "$_det" = 1 ] && STAGE_TOTAL=$((STAGE_TOTAL + 1))
    [ "$A_UDP" = Y ] && STAGE_TOTAL=$((STAGE_TOTAL + 1))
    _pn=""; [ "$PN" = 1 ] && _pn=-Pn
    # TARGETS is split into separate arguments on purpose.
    # shellcheck disable=SC2086
    set -- $TARGETS
    : >"$W/up_targets"
    _have_up=0
    if [ "$A_QUICK" = Y ]; then
        stage "quick scan: top $TOP TCP ports"
        nmap_run 1-quick $_pn --top-ports "$TOP" "$@"
        up_hosts "$RAW/1-quick.gnmap" >"$W/up_targets"; _have_up=1
        show "$C_GRN" "  $(grep -c . "$W/up_targets") host(s) up"
    fi
    if [ -n "$PORTS" ]; then
        stage "port scan: $PORTS"
        nmap_run 1-ports $_pn -p "$PORTS" "$@"
        up_hosts "$RAW/1-ports.gnmap" >"$W/up_targets"; _have_up=1
    fi
    if [ -n "$EXTRA" ]; then
        stage "extra ports: $EXTRA"
        nmap_run 1-extra $_pn -p "$EXTRA" "$@"
        { cat "$W/up_targets"; up_hosts "$RAW/1-extra.gnmap"; } | sort -u >"$W/up2"; mv "$W/up2" "$W/up_targets"; _have_up=1
    fi
    if [ "$A_FULL" = Y ]; then
        stage "full scan: all 65535 TCP ports"
        if [ "$_have_up" = 1 ]; then
            # Which hosts: all that answered, or the ones named.
            if [ -z "$FULLHOSTS" ] && [ "$(grep -c . "$W/up_targets")" -gt 1 ]; then
                show "$C_GRY" "  up: $(tr '\n' ' ' <"$W/up_targets")"
                cc_ask_text "Full scan which hosts?" all "all, or addresses separated by spaces"
                FULLHOSTS=$CC_ANSWER
            fi
            case "$FULLHOSTS" in
                ''|all|ALL|All) ;;
                *) : >"$W/up_targets"
                   for _h in $(printf '%s' "$FULLHOSTS" | tr ',' ' '); do
                       case "$_h" in -*|*[!A-Za-z0-9./:_-]*) cc_warn "not an address, skipped: $_h"; continue ;; esac
                       printf '%s\n' "$_h" >>"$W/up_targets"
                   done ;;
            esac
            if [ -s "$W/up_targets" ]; then
                show "$C_GRY" "  on $(grep -c . "$W/up_targets") host(s); takes minutes per host, progress every minute"
                # shellcheck disable=SC2046
                nmap_run 2-full -Pn -p- --stats-every 60s $(cat "$W/up_targets")
            else
                show "$C_YEL" "  no hosts up: skipped (try --pn if the hosts drop ping)"
            fi
        else
            show "$C_GRY" "  takes minutes per host, progress every minute"
            nmap_run 2-full $_pn -p- --stats-every 60s "$@"
            up_hosts "$RAW/2-full.gnmap" >"$W/up_targets"; _have_up=1
        fi
    fi
    # Details only on the open ports found so far: much faster than -sV -p-.
    if [ "$_det" = 1 ]; then
        stage "details on the open ports: $(echo "$SCANS" | tr ',' '\n' | grep -E 'services|scripts|vuln|OS' | tr -d ' ' | tr '\n' ' ')"
        cat "$RAW"/1-*.gnmap "$RAW"/2-*.gnmap 2>/dev/null >"$W/all.gnmap"
        open_list "$W/all.gnmap" tcp
        _pl=$(cat "$W/ports_open")
        if [ -s "$W/hosts_open" ] && [ -n "$_pl" ]; then
            set -- -Pn -p "$_pl"
            [ "$A_SVC" = Y ] && set -- "$@" -sV
            [ "$A_OS" = Y ] && set -- "$@" -O --osscan-limit
            # By default only vuln scripts nmap also marks "safe": nothing
            # meant to crash or change a service.  --vuln-all (or "no" to the
            # question) runs every vuln script.
            _vs="vuln and safe"; [ "$A_VSAFE" = N ] && _vs=vuln
            if [ "$A_SCRIPTS" = Y ] && [ "$A_VULN" = Y ]; then set -- "$@" --script "default or ($_vs)"
            elif [ "$A_SCRIPTS" = Y ]; then set -- "$@" -sC
            elif [ "$A_VULN" = Y ]; then set -- "$@" --script "$_vs"
            fi
            [ "$A_VULN" = Y ] && show "$C_GRY" "  vuln scripts can take a few minutes per host"
            # shellcheck disable=SC2046
            nmap_run 3-details "$@" $(sort "$W/hosts_open")
        else
            show "$C_YEL" "  no open TCP ports found: skipped"
        fi
    fi
    # shellcheck disable=SC2086
    set -- $TARGETS
    if [ "$A_UDP" = Y ]; then
        stage "UDP scan: top 25 ports"
        if [ "$_have_up" = 1 ]; then
            # shellcheck disable=SC2046
            [ -s "$W/up_targets" ] && nmap_run 4-udp -Pn -sU -sV --version-light --top-ports 25 $(cat "$W/up_targets")
            [ -s "$W/up_targets" ] || show "$C_YEL" "  no hosts up: skipped"
        else
            nmap_run 4-udp $_pn -sU -sV --version-light --top-ports 25 "$@"
        fi
    fi
    nmap --version 2>/dev/null | head -n 1 >"$W/engine_version"

    # Merge every stage.  Grepable format, one host per line, tab-separated:
    #   Host: 10.0.2.5 (web01)<TAB>Ports: 22/open/tcp//ssh//OpenSSH 8.9p1/, ...<TAB>OS: Linux
    # Each port entry is exactly seven '/'-separated fields.  Versions can
    # contain commas, so entries are cut by matching that shape.  Later
    # stages (details) replace the service name and version of earlier ones.
    awk -F'\t' -v upf="$W/up" -v openf="$W/open" '
        /^Host: / {
            split($1, h, " "); ip = h[2]; name = $1; sub(/^Host: [^ ]* \(/, "", name); sub(/\)$/, "", name)
            if (!(ip in nm) || name != "") nm[ip] = name
            for (i = 2; i <= NF; i++) if ($i ~ /^OS: /) { o = $i; sub(/^OS: /, "", o); os[ip] = o }
            if (!(ip in seen)) { seen[ip] = 1; order[++n] = ip }
            for (i = 2; i <= NF; i++) {
                if ($i !~ /^Ports: /) continue
                s = $i; sub(/^Ports: /, "", s)
                while (match(s, /^[0-9]+\/[^\/]*\/[^\/]*\/[^\/]*\/[^\/]*\/[^\/]*\/[^\/]*\//)) {
                    e = substr(s, 1, RLENGTH); s = substr(s, RLENGTH + 1); sub(/^, /, "", s)
                    split(e, f, "/")
                    # "open|filtered" (UDP that did not answer) is not open.
                    if (f[2] != "open") continue
                    k = ip "|" f[3] "|" f[1]
                    if (!(k in svc)) { korder[++m] = k; svc[k] = ""; ver[k] = "" }
                    if (f[5] != "") svc[k] = f[5]
                    v = f[7]; gsub(/\|/, "/", v); if (v != "") ver[k] = v
                }
            }
        }
        END {
            for (i = 1; i <= n; i++) print order[i] "|" nm[order[i]] "|" os[order[i]] > upf
            for (i = 1; i <= m; i++) print korder[i] "|" svc[korder[i]] "|" ver[korder[i]] > openf
        }' "$RAW"/*.gnmap
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

# finish_fallback -> turn $W/hits (ip|port|banner) into $W/up and $W/open,
#   and show the open ports the way nmap would.  A host counts as up when
#   any port answered; there is no ping, because ping is often missing or
#   blocked.
finish_fallback() {
    : >"$W/open"
    sort -t'|' -k1,1 -k2,2n "$W/hits" -o "$W/hits"
    while IFS='|' read -r _ip _p _ban; do
        printf '%s|tcp|%s|%s|%s\n' "$_ip" "$_p" "$(port_name "$_p")" "$_ban" >>"$W/open"
    done <"$W/hits"
    : >"$W/up"
    for _ip in $(cut -d'|' -f1 "$W/hits" | sort -u); do
        _name=""
        [ "$NODNS" = 1 ] || _name=$(getent hosts "$_ip" 2>/dev/null | awk '{ print $2; exit }')
        printf '%s|%s|\n' "$_ip" "$_name" >>"$W/up"
        show "$C_CYN" "Scan report for $_ip${_name:+ ($_name)}"
        while IFS='|' read -r _i _pr _p _svc _ver; do
            [ "$_i" = "$_ip" ] && show "$C_GRN" "$(printf '%-10s open  %-14s %s' "$_p/$_pr" "$_svc" "$_ver")"
        done <"$W/open"
    done
    cp "$W/hits" "$RAW/$ENGINE-hits.txt"
}

case "$ENGINE" in
    nmap)    run_nmap ;;
    python)  STAGE_TOTAL=1; stage "connect scan ($ENGINE)"; run_python ;;
    bash|nc) STAGE_TOTAL=1; stage "connect scan ($ENGINE)"; run_shell_engine ;;
esac
sort -t'|' -k1,1 -u "$W/up" -o "$W/up"
sort -t'|' -k1,1 -k2,2 -k3,3n "$W/open" -o "$W/open"

# ---- Script results (vulns and other findings) -----------------------------
# Read from nmap's XML, where each script's output is one attribute on one
# line.  Writes $W/vulns as ip|proto|port|script|state|title|ids:
#   - any script that reports "State: VULNERABLE" or "LIKELY VULNERABLE"
#   - vulners: the known CVEs for the detected version, with the worst score
#   - a few default-script results that matter for defence (anonymous FTP,
#     empty database passwords, SMB signing off)
: >"$W/vulns"
for _x in "$RAW"/3-details.xml "$RAW"/4-udp.xml; do
    [ -f "$_x" ] || continue
    awk -v outf="$W/vulns" '
        function dec(s) { gsub(/&#xa;/, "\n", s); gsub(/&#x9;/, " ", s); gsub(/&quot;/, "\"", s); gsub(/&apos;/, "\047", s); gsub(/&lt;/, "<", s); gsub(/&gt;/, ">", s); gsub(/&amp;/, "\\&", s); return s }    # awk: posix-ok
        function attr(tag, name) { if (match(tag, " " name "=\"[^\"]*\"")) return substr(tag, RSTART + length(name) + 3, RLENGTH - length(name) - 4); return "" }    # awk: posix-ok
        function clean(s) { gsub(/[|\r]/, "/", s); gsub(/\n/, " ", s); gsub(/  +/, " ", s); sub(/^ /, "", s); sub(/ $/, "", s); return s }    # awk: posix-ok
        function rec(st, title, ids) { print ip "|" (port == "" ? "host" : proto) "|" (port == "" ? "-" : port) "|" id "|" st "|" clean(title) "|" ids > outf }    # awk: posix-ok
        # One tag at a time: nmap puts several tags on one line.  Attribute
        # values never hold a raw ">" (nmap writes &gt;).
        {
            s = $0
            while (match(s, /<[^>]*>/)) {
                tag = substr(s, RSTART, RLENGTH); s = substr(s, RSTART + RLENGTH)
                if (tag ~ /^<host[ >]/)          { ip = ""; port = ""; proto = "" }
                else if (tag ~ /^<address /)     { if (tag ~ /addrtype="ipv4"/ || (ip == "" && tag ~ /addrtype="ipv6"/)) ip = attr(tag, "addr") }
                else if (tag ~ /^<port /)        { proto = attr(tag, "protocol"); port = attr(tag, "portid") }
                else if (tag ~ /^<\/port>/)      { port = "" }
                else if (tag ~ /^<hostscript>/)  { port = "" }
                else if (tag ~ /^<script /)      script(attr(tag, "id"), dec(attr(tag, "output")))
            }
        }
        function script(sid, out,   ids, s2, c, tmp, n, L, i, w, worst, cnt, st, title) {    # awk: posix-ok
            id = sid; ids = ""; s2 = out
            while (match(s2, /CVE-[0-9]+-[0-9]+/)) { c = substr(s2, RSTART, RLENGTH); if (index(" " ids " ", " " c " ") == 0 && split(ids, tmp, " ") < 5) ids = ids (ids == "" ? "" : " ") c; s2 = substr(s2, RSTART + RLENGTH) }
            if (id == "vulners") {
                n = split(out, L, "\n"); worst = 0; cnt = 0
                for (i = 1; i <= n; i++) if (split(L[i], w, " ") >= 2 && w[2] ~ /^[0-9]+(\.[0-9]+)?$/) { cnt++; if (w[2] + 0 > worst) worst = w[2] + 0 }
                if (cnt > 0) rec("known CVEs", cnt " known vulnerabilities for this version, worst score " worst, ids)
                return
            }
            if (out ~ /State: (LIKELY )?VULNERABLE/) {
                st = (out ~ /State: LIKELY VULNERABLE/) ? "LIKELY VULNERABLE" : "VULNERABLE"
                n = split(out, L, "\n"); title = id
                for (i = 1; i < n; i++) if (L[i] ~ /VULNERABLE:[ ]*$/) { title = L[i + 1]; break }
                rec(st, title, ids); return
            }
            if (id == "ftp-anon" && out ~ /Anonymous FTP login allowed/) rec("finding", "anonymous FTP login allowed", "")
            else if (id ~ /empty-password/ && out ~ /[Ee]mpty password|has empty password/) rec("finding", "account with an empty password: " out, "")
            else if (id == "smb2-security-mode" && out ~ /not required/) rec("finding", "SMB signing not required", "")
            else if (id == "smb-security-mode" && out ~ /message_signing: disabled/) rec("finding", "SMB signing disabled", "")
            else if (id == "http-methods" && out ~ /[Rr]isky methods:.*(PUT|DELETE)/) rec("finding", "web server allows PUT or DELETE", "")
        }' "$_x"
done

# ---- Host list --------------------------------------------------------------
# Read the host list into $W/hl as "ip|name|scored_services" (scored
# services look like http:80;dns:53).
: >"$W/hl"
if [ -n "$HOSTLIST" ]; then
    cc_hosts_rows "$HOSTLIST" | awk -F'|' '$2 != "" { print $2 "|" $1 "|" $8 }' >"$W/hl"
    cc_info "host list: $(wc -l <"$W/hl" | tr -d ' ') host(s) from $HOSTLIST"
fi

# ---- Tables ---------------------------------------------------------------------
HC=$(cc_table_new hosts ip hostname status open_tcp open_udp os_guess in_host_list host_list_name)
PC=$(cc_table_new ports ip hostname proto port state service version)
VC=$(cc_table_new vulns ip hostname proto port script state title ids)
awk -F'|' -v upf="$W/up" -v hlf="$W/hl" -v hc="$HC" -v pc="$PC" -v hashl="$( [ -s "$W/hl" ] && echo 1 || echo 0 )" '
    BEGIN {
        while ((getline l < upf) > 0) { split(l, u, "|"); name[u[1]] = u[2]; os[u[1]] = u[3]; order[++n] = u[1] }
        while ((getline l < hlf) > 0) { split(l, h, "|"); hl[h[1]] = h[2] }
    }
    { if ($2 == "tcp") t[$1] = t[$1] (t[$1] == "" ? "" : " ") $3; else ud[$1] = ud[$1] (ud[$1] == "" ? "" : " ") $3
      print $1 " | " name[$1] " | " $2 " | " $3 " | open | " $4 " | " $5 >> pc }
    END {
        for (i = 1; i <= n; i++) {
            ip = order[i]
            inl = hashl ? ((ip in hl) ? "yes" : "no") : ""
            print ip " | " name[ip] " | up | " t[ip] " | " ud[ip] " | " os[ip] " | " inl " | " hl[ip] >> hc
        }
    }' "$W/open"
awk -F'|' -v upf="$W/up" -v vc="$VC" '
    BEGIN { while ((getline l < upf) > 0) { split(l, u, "|"); name[u[1]] = u[2] } }
    { print $1 " | " name[$1] " | " $2 " | " $3 " | " $4 " | " $5 " | " $6 " | " $7 >> vc }' "$W/vulns"

# ---- Flags ------------------------------------------------------------------
show "" ""
show "$C_CYN" "==========[ checks: what looks bad ]=========="
# flag SEVERITY SECTION ITEM DETAIL -> cc_flag, and shown live.
flag() {
    cc_flag "$1" "$2" "$3" "$4"
    case "$1" in
        HIGH) show "$C_RED" "  [!] FIX   $3: $4" ;;
        MED)  show "$C_YEL" "  [*] LOOK  $3: $4" ;;
    esac
    return 0
}
# Checks by port and by version banner.  Flags are pointers: a database port
# open on the database server may be exactly what the scoring engine needs.
while IFS='|' read -r _ip _pr _p _svc _ver; do
    _it="$_ip $_pr/$_p"
    [ -n "$_svc" ] || _svc="unknown service"
    case "$_pr/$_p" in
        tcp/2375) flag HIGH ports "$_it" "Docker API without TLS: anyone who reaches it is root on that host" ;;
        tcp/23) flag MED ports "$_it" "Telnet: cleartext logins" ;;
        tcp/512|tcp/513|tcp/514) flag MED ports "$_it" "rsh/rlogin/rexec-style cleartext service" ;;
        udp/69) flag MED ports "$_it" "TFTP: no authentication; files can be read by guessing names" ;;
        udp/161) flag MED ports "$_it" "SNMP: check the community strings are not public/private" ;;
        tcp/590[0-9]) flag MED ports "$_it" "VNC remote desktop; check it requires a password" ;;
        tcp/6379) flag MED ports "$_it" "Redis: often has no password" ;;
        tcp/27017) flag MED ports "$_it" "MongoDB: often has no password" ;;
        tcp/9200) flag MED ports "$_it" "Elasticsearch: often has no authentication" ;;
        tcp/11211) flag MED ports "$_it" "memcached: no authentication" ;;
        tcp/1337|tcp/4444|tcp/4445|tcp/5555|tcp/6666|tcp/12345|tcp/31337|tcp/54321) flag MED ports "$_it" "port commonly used by backdoors and reverse shells ($_svc)" ;;
        tcp/3306|tcp/1433|tcp/5432|tcp/1521) flag LOW ports "$_it" "database reachable over the network ($_svc); fine if the scoring engine or a web server needs it" ;;
        tcp/21) flag LOW ports "$_it" "FTP: cleartext logins" ;;
    esac
    # Versions with known backdoors or trivial remote root, common in competitions
    # images.
    case "$_ver" in
        *"vsftpd 2.3.4"*) flag HIGH ports "$_it" "vsftpd 2.3.4 has a known backdoor: replace it" ;;
        *"ProFTPD 1.3.3c"*) flag HIGH ports "$_it" "ProFTPD 1.3.3c release was backdoored" ;;
        *"ProFTPD 1.3.5"*) flag HIGH ports "$_it" "ProFTPD 1.3.5 mod_copy lets anyone copy files" ;;
        *UnrealIRCd*) flag HIGH ports "$_it" "UnrealIRCd: the 3.2.8.1 release was backdoored" ;;
        *"Samba smbd 3.0.2"*) flag HIGH ports "$_it" "Samba 3.0.20-3.0.25 allows remote root" ;;
        *distccd*) flag HIGH ports "$_it" "distccd runs commands for anyone who connects" ;;
        *"Microsoft Windows XP"*|*"Windows Server 2003"*) flag HIGH ports "$_it" "end-of-life Windows ($_ver)" ;;
    esac
    # A shell prompt or a shell's error text where a service should be.
    case "$_ver" in
        *"sh-"[0-9]*"$"*|*"bash: "*|*"/bin/sh: "*|*"command not found"*) flag HIGH ports "$_it" "answers like a shell, not a service: likely a bind shell" ;;
    esac
    if [ "$PROFILE" = outside ]; then
        case "$_pr/$_p" in tcp/445|tcp/139|tcp/3389|tcp/5985|tcp/5986|tcp/135) flag MED ports "$_it" "Windows admin service ($_svc) is reachable from outside the firewall" ;; esac
    fi
done <"$W/open"

# Script results.
while IFS='|' read -r _ip _pr _p _id _st _title _ids; do
    _it="$_ip $_pr/$_p"; [ "$_pr" = host ] && _it=$_ip
    case "$_st" in
        VULNERABLE)          flag HIGH vulns "$_it" "$_id says VULNERABLE: $_title${_ids:+ ($_ids)}" ;;
        "LIKELY VULNERABLE") flag MED vulns "$_it" "$_id says LIKELY VULNERABLE: $_title${_ids:+ ($_ids)}" ;;
        "known CVEs")
            _w=$(printf '%s' "$_title" | sed 's/.*worst score //')
            _wi=${_w%%.*}; case "$_wi" in ''|*[!0-9]*) _wi=0 ;; esac
            if [ "$_wi" -ge 9 ]; then flag HIGH vulns "$_it" "$_title: patch or update it${_ids:+ ($_ids)}"
            elif [ "$_wi" -ge 7 ]; then flag MED vulns "$_it" "$_title${_ids:+ ($_ids)}"
            else flag LOW vulns "$_it" "$_title"
            fi ;;
        finding)
            case "$_title" in
                *"empty password"*|"anonymous FTP"*) flag HIGH vulns "$_it" "$_title ($_id)" ;;
                *"PUT or DELETE"*) flag MED vulns "$_it" "$_title ($_id)" ;;
                *) flag LOW vulns "$_it" "$_title ($_id)" ;;
            esac ;;
    esac
done <"$W/vulns"

# Host list checks: unknown hosts, missing hosts, scored services.
if [ -s "$W/hl" ]; then
    SC=$(cc_table_new scored host ip service port reachable)
    while IFS='|' read -r _ip _name _os; do
        grep -q "^$_ip|" "$W/hl" || flag MED hosts "$_ip ${_name:-}" "host is up but not on the host list: find out what it is"
    done <"$W/up"
    while IFS='|' read -r _ip _name _scored; do
        _inscope=$(awk -v ip="$_ip" -v specs="$TARGETS" "$AWK_IP"'BEGIN { print intarget(ip, specs) }')
        [ "$_inscope" = 1 ] || continue
        _isup=no; grep -q "^$_ip|" "$W/up" && _isup=yes
        [ "$_isup" = yes ] || flag MED hosts "$_ip $_name" "on the host list but did not answer the scan"
        for _s in $(printf '%s' "$_scored" | tr ';' ' '); do
            _svc=${_s%%:*}; _p=${_s##*:}
            case "$_p" in ''|*[!0-9]*) continue ;; esac
            if grep -q "^$_ip|tcp|$_p|" "$W/open" || grep -q "^$_ip|udp|$_p|" "$W/open"; then
                cc_table_row "$SC" "$_name" "$_ip" "$_svc" "$_p" yes
            else
                cc_table_row "$SC" "$_name" "$_ip" "$_svc" "$_p" no
                flag HIGH scored "$_name $_ip $_svc:$_p" "scored service is not reachable from here; check it now (it may only be blocked from this machine)"
            fi
        done
    done <"$W/hl"
    if [ "$PROFILE" = outside ]; then
        # From outside, an open port that is not a scored service on that host
        # is attack surface the red team can see.
        while IFS='|' read -r _ip _pr _p _svc _ver; do
            _sc=$(awk -F'|' -v ip="$_ip" '$1 == ip { print $3 }' "$W/hl")
            case ";$_sc;" in *":$_p;"*) ;; *) flag MED outside "$_ip $_pr/$_p" "reachable from outside but not a scored service on this host ($_svc)" ;; esac
        done <"$W/open"
    fi
fi
_fl="$CC_RUN_DIR/flags.txt"
[ -f "$_fl" ] || cc_table_line severity section item detail time >"$_fl"
if ! awk -F'|' 'NR > 1 { gsub(/ /, "", $1); if ($1 == "HIGH" || $1 == "MED") f = 1 } END { exit !f }' "$_fl"; then show "$C_GRN" "  [ok] nothing high or medium"; fi

# ---- What each box looks like ------------------------------------------------------
# A guess per address from its open ports and the versions it shows, so the
# boxes on the team's diagram can be matched to their addresses.  Also
# written as host-list rows (suggested-hosts.txt) for config/hosts.txt.
show "" ""
show "$C_CYN" "==========[ what each box looks like ]=========="
RC=$(cc_table_new roles ip guess os why)
awk -F'|' -v upf="$W/up" -v rc="$RC" -v sug="$CC_RUN_DIR/suggested-hosts.txt" '
    BEGIN { while ((getline l < upf) > 0) { split(l, u, "|"); order[++n] = u[1]; os[u[1]] = tolower(u[3]) } }
    { k = $2 "/" $3; P[$1, k] = 1; v = tolower($5 " " $4); V[$1] = V[$1] " " v }
    function has(ip, k) { return ((ip, k) in P) }  # awk, not shell: posix-ok
    END {
        print "# name     ip               os       role         connect  port  user    scored_services  notes" > sug
        for (i = 1; i <= n; i++) {
            ip = order[i]; g = ""; why = ""; o = "linux"; r = "server"; c = "ssh"; cp = 22; us = "root"; sc = ""
            vv = V[ip]
            if (vv ~ /dropbear|openwrt|luci|uhttpd/) { g = "router (OpenWRT)"; why = "dropbear / LuCI / uhttpd"; o = "openwrt"; r = "router"; sc = "ssh:22" }
            else if (has(ip, "tcp/88") && has(ip, "tcp/389")) { g = "Windows domain controller (AD)"; why = "Kerberos 88 + LDAP 389"; o = "windows"; r = "domain-ctrl"; c = "winrm"; cp = 5985; us = "-"; sc = "dns:53;ldap:389" }
            else if (vv ~ /gitea|forgejo|gogs/ || (has(ip, "tcp/3000") && !has(ip, "tcp/445"))) { g = "Gitea (git server)"; why = (vv ~ /gitea/ ? "says Gitea" : "web on 3000"); r = "gitea"; sc = "http:3000" }
            else if (has(ip, "tcp/445") || has(ip, "tcp/2049")) {
                if (has(ip, "tcp/3389") || has(ip, "tcp/5985") || os[ip] ~ /windows/) { g = "Windows server"; why = "SMB + RDP/WinRM"; o = "windows"; r = "windows"; c = "winrm"; cp = 5985; us = "-" }
                else { g = "file share (" (has(ip, "tcp/445") ? "Samba" : "") (has(ip, "tcp/445") && has(ip, "tcp/2049") ? " + " : "") (has(ip, "tcp/2049") ? "NFS" : "") ")"; why = "SMB 445 / NFS 2049"; r = "fileshare"; sc = (has(ip, "tcp/445") ? "smb:445" : "nfs:2049") } }
            else if (has(ip, "tcp/3389") || has(ip, "tcp/5985") || os[ip] ~ /windows/) { g = "Windows box"; why = "RDP / WinRM"; o = "windows"; r = "windows"; c = "winrm"; cp = 5985; us = "-" }
            else if (has(ip, "tcp/5672") || has(ip, "tcp/15672") || vv ~ /rabbitmq/) { g = "RabbitMQ (message queue)"; why = "AMQP 5672 / management 15672"; r = "rabbitmq"; sc = "amqp:5672" }
            else if (has(ip, "tcp/8123") || vv ~ /home assistant/) { g = "Home Assistant"; why = "8123"; r = "homeassist"; sc = "http:8123" }
            else if (has(ip, "tcp/80") || has(ip, "tcp/443")) { g = "web app"; why = "HTTP" (has(ip, "tcp/443") ? "S" : ""); r = "web"; sc = (has(ip, "tcp/443") ? "https:443" : "http:80") }
            else if (has(ip, "tcp/22")) { g = "Linux box (SSH only)"; why = "SSH" }
            else { g = "unknown"; why = "no port this script knows"; c = "none"; cp = "-"; us = "-" }
            if (os[ip] ~ /alpine/) o = "linux"
            print ip " | " g " | " os[ip] " | " why >> rc
            print g "	" ip "	" why
            nm = ip; sub(/.*\./, "box", nm)
            printf "%-10s %-16s %-8s %-12s %-8s %-5s %-7s %-16s %s\n", nm, ip, o, r, c, cp, us, (sc == "" ? "-" : sc), "from SH-03: " g >> sug
        }
    }' "$W/open" >"$W/roles"
# Hosts with no open port at all are in $W/up but not in $W/open: still listed.
while IFS="$(printf '\t')" read -r _g _ip _why; do
    case "$_g" in unknown) _c=$C_GRY ;; "router (OpenWRT)"|"Windows domain controller (AD)") _c=$C_CYN ;; *) _c=$C_GRN ;; esac
    show "$_c" "  $(printf '%-16s %-32s (%s)' "$_ip" "$_g" "$_why")"
done <"$W/roles"
[ -s "$W/roles" ] || show "$C_GRY" "  (no open ports to go by)"
show "$C_GRY" "  Host-list rows for these: $CC_RUN_DIR/suggested-hosts.txt (copy the right ones to config/hosts.txt and give them real names)"

# ---- Tables lined up ---------------------------------------------------------------
# shellcheck disable=SC2034  # read by cc_flag_report in the library
CC_FLAGS=$_fl
cc_table_sort_flags "$_fl"
for _t in "$HC" "$PC" "$VC" "${SC:-}" "$RC"; do [ -n "$_t" ] && cc_table_align "$_t"; done

# ---- Summary ----------------------------------------------------------------
_nup=$(grep -c . "$W/up")
_nopen=$(grep -c . "$W/open")
_nvuln=$(awk -F'|' '$5 ~ /VULNERABLE/ { n++ } END { print n + 0 }' "$W/vulns")
_unknown=""
[ -s "$W/hl" ] && _unknown=" ($(awk -F'|' -v hlf="$W/hl" 'BEGIN { while ((getline l < hlf) > 0) { split(l, h, "|"); k[h[1]] = 1 } } !($1 in k) { n++ } END { print n + 0 }' "$W/up") not on the host list)"
{
    printf 'SH-03 Network scan | from %s | %s | engine %s\n' "$CC_HOST" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(cat "$W/engine_version" 2>/dev/null)"
    printf 'Targets:%s | scans: %s\n\n' "$TARGETS" "$SCANS"
    printf 'Hosts up: %s%s | open ports: %s | vulnerable: %s\n\n' "$_nup" "$_unknown" "$_nopen" "$_nvuln"
    # One block per host: address, name, OS, then one line per open port.
    printf 'Open ports\n'
    awk -F'|' -v upf="$W/up" '
        BEGIN { while ((getline l < upf) > 0) { split(l, u, "|"); name[u[1]] = u[2]; os[u[1]] = u[3]; order[++n] = u[1] } }
        { k = $1; c[k]++; p[k, c[k]] = sprintf("    %-10s %-16s %s", $3 "/" $2, substr($4, 1, 16), substr($5, 1, 70)) }
        END {
            for (i = 1; i <= n && i <= 60; i++) {
                ip = order[i]
                printf "  %s%s%s  (%d open)\n", ip, (name[ip] == "" ? "" : " " name[ip]), (os[ip] == "" ? "" : " | " substr(os[ip], 1, 40)), c[ip]
                for (j = 1; j <= c[ip]; j++) print p[ip, j]
            }
            if (n == 0) print "  (no hosts up)"
            if (n > 60) printf "  ... %d more hosts in hosts.txt\n", n - 60
        }' "$W/open"
    printf '\n'
    if [ "$A_VULN" != Y ] && [ "$A_SCRIPTS" != Y ]; then
        printf 'Vulns: not checked (run with --vuln or --scripts)\n'
    elif [ ! -s "$W/vulns" ]; then
        printf 'Vulns: none found by the scripts\n'
    else
        printf 'Vulns and script findings\n'
        awk -F'|' '{ printf "  %-22s %-30s %-17s %s%s\n", $1 " " ($2 == "host" ? "" : $2 "/" $3), substr($4, 1, 30), $5, substr($6, 1, 80), ($7 == "" ? "" : " (" $7 ")") }' "$W/vulns"
    fi
    if [ -n "$HOSTLIST" ] && [ -n "${SC:-}" ]; then
        _sok=$(awk -F'|' 'NR > 1 { gsub(/ /, "", $5); if ($5 == "yes") n++ } END { print n + 0 }' "$SC"); _sno=$(awk -F'|' 'NR > 1 { gsub(/ /, "", $5); if ($5 == "no") n++ } END { print n + 0 }' "$SC")
        printf '\nScored services: %s reachable, %s NOT reachable\n' "$_sok" "$_sno"
    fi
    printf '\n'
    cc_flag_report "$MAXFLAGS"
    printf '\nAll results: %s\n' "$CC_RUN_DIR"
} >"$CC_RUN_DIR/summary.txt"
show "" ""
show "$C_CYN" "==========[ SUMMARY ]=========="
# On screen the summary is colour-coded; summary.txt and output.txt stay plain.
awk -v R="$C_RED" -v Y="$C_YEL" -v G="$C_GRN" -v C="$C_CYN" -v D="$C_GRY" -v O="$C_OFF" '
    NR <= 2                          { print C $0 O; next }
    /^Hosts up:/                     { print (($0 ~ /vulnerable: [1-9]/) ? R : G) $0 O; next }
    /^Open ports$|^Vulns and/        { mode = substr($0, 1, 1); print C $0 O; next }
    /^Vulns: /                       { print D $0 O; next }
    /^$/                             { mode = ""; print; next }
    mode == "O" && /^  [^ ]/         { print C $0 O; next }
    mode == "O"                      { print G $0 O; next }
    mode == "V" && /VULNERABLE/      { print R $0 O; next }
    mode == "V"                      { print Y $0 O; next }
    /^Scored services:/              { print (($0 ~ / [1-9][0-9]* NOT/) ? R : G) $0 O; next }
    /^Flags:/                        { print C $0 O; next }
    /^HIGH - /                       { fm = "H"; print R $0 O; next }
    /^MED - /                        { fm = "M"; print Y $0 O; next }
    /^  \[/ && fm == "H"             { print R "  [!] FIX " substr($0, 3) O; next }
    /^  \[/ && fm == "M"             { print Y "  [*] LOOK" substr($0, 2) O; next }
    /^All (flags|results)/           { print D $0 O; next }
                                     { print }
' "$CC_RUN_DIR/summary.txt" >&3
cat "$CC_RUN_DIR/summary.txt" >>"$OUTF"
rm -rf "$W"
cc_finish
