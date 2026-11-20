#!/bin/sh
# =============================================================================
# ID:       NW-07
# NAME:     Network device config audit
# ROLE:     Network  (wave 1, first 15 minutes - right after NW-01)
# KIND:     readonly - reads saved config files, touches no device
# VERSION:  1.1.0
#
# PURPOSE
#   Reads the configs NW-01 saved (or config files you give it) and flags the
#   weaknesses a red team uses first on network gear:
#     - telnet or plain-HTTP management turned on
#     - SNMP with default or write-access communities
#     - passwords stored in clear text or reversible "type 7"
#     - management reachable from any address (no access-class / trusted
#       hosts / permitted IPs)
#     - "any to any, allow" firewall rules
#     - accounts: the default admin, every admin account listed
#   Vendors: cisco-ios, cisco-asa, paloalto, fortigate, vyos, pfsense,
#   opnsense, mikrotik, openwrt.  The vendor comes from NW-01's notes or is
#   recognised from the config text.
#
#   OpenWRT (what NW-01 saves: uci export, accounts, keys, cron, startup):
#   the outside (wan) zone accepting or forwarding everything, wan -> lan
#   forwarding, router management (SSH, LuCI) open from the outside, any-any
#   allow rules, management or database ports forwarded in, UPnP on, SSH
#   listening on wan, LuCI over plain HTTP, extra UID 0 accounts, root SSH
#   keys, cron jobs and rc.local commands, telnet at boot, no log server.
#   The port forwards are listed: on a NAT router those are the scored paths.
#
#   QUESTIONS (only when no flag answers them; --batch takes the defaults):
#     audit the configs NW-01 saved?       --configs DIR
#     else which file, and what device     --file F[,VENDOR]
#
# USAGE
#   sh NW-07-config-audit.sh --out ~/bt-out                 latest config of every device NW-01 saved
#   sh NW-07-config-audit.sh --file r1.cfg --file fw1.cfg     files copied by hand (vendor recognised)
#   sh NW-07-config-audit.sh --file fw1.txt,paloalto          ... or named
#
# OPTIONS
#   --configs DIR    NW-01's store (default <out>/net-configs)
#   --file F[,VENDOR]  audit this file (repeat); the vendor is recognised
#                    from the text when not given
#   --max-flags N    HIGH/MED findings shown on screen (default 40)
#   --no-color       no colours
#   --help           this text plus the common options
#
# OUTPUTS  (under --out, in NW-07_<host>_<UTC time>/)
#   summary.txt      per device: vendor and counts; then the findings, worst first
#   findings.txt     device, vendor, severity, finding, detail
#   flags.txt        the same as flags (section = device), HIGH first
#
# WHAT IT CHANGES
#   Nothing.  Secrets in config lines are masked in every output.
#
# DEPENDS ON
#   awk, sed.  The configs: run NW-01 first, or give --file.
#
# TESTED ON
#   Sample configs for every vendor (OpenWRT: a uci export as NW-01 saves
#   it), with planted problems and clean versions, under dash, bash, busybox sh, ksh93, mksh and yash.  The rules
#   follow each vendor's documented config syntax; check the first report
#   against the real devices.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - It reads what the config says, not what is running: a service turned
#     on by a default that never appears in the config is only noted where
#     the default is known to be unsafe (older Cisco IOS VTY lines, MikroTik
#     telnet).
#   - Palo Alto: the brace format of "show config running" (what NW-01
#     saves).  The "set" format is not read.
#   - A finding is a lead: an "any any allow" rule may be the scored path.
#
# DEBUGGING
#   --debug shows the vendor chosen for each file and the number of findings.
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

VENDORS="cisco-ios cisco-asa paloalto fortigate vyos pfsense opnsense mikrotik openwrt"

usage() {
    cat <<'USAGE'
NW-07 Network device config audit - telnet, SNMP, weak passwords, open management, any-any rules
  sh NW-07-config-audit.sh [--configs DIR] [--file F[,VENDOR]]... [options]

  --configs DIR      NW-01's saved configs (default <out>/net-configs)
  --file F[,VENDOR]  audit this file (repeatable)
  --max-flags N      findings shown on screen (default 40)
  --no-color         no colours
  --help             show this text

Without --file it offers the configs NW-01 saved, or asks for a file.

USAGE
    cc_usage_common
}

NL='
'
CONFIGS=""; FILES=""; MAXFLAGS=40; COLOR=1
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --configs)   [ $# -ge 2 ] || cc_die 2 "--configs needs a folder"; [ -d "$2" ] || cc_die 2 "--configs: not a folder: $2"; CONFIGS=$2; shift 2 ;;
        --file)      [ $# -ge 2 ] || cc_die 2 "--file needs a file"
                     _f=${2%%,*}; [ -r "$_f" ] || cc_die 2 "--file: cannot read $_f"
                     FILES="$FILES$2$NL"; shift 2 ;;
        --max-flags) [ $# -ge 2 ] || cc_die 2 "--max-flags needs a number"; MAXFLAGS=$2; shift 2 ;;
        --no-color|--no-colour) COLOR=0; shift ;;
        --help|-h)   usage; exit 0 ;;
        *)           cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
case "$MAXFLAGS" in ''|*[!0-9]*) cc_die 2 "--max-flags needs a whole number" ;; esac

# shellcheck disable=SC2034  # read by the library: tables as .txt, no CSV
CC_TABLES=1
cc_init "NW-07" "Network config audit" readonly
# shellcheck disable=SC2034  # read by cc_color_init
[ "$COLOR" = 1 ] || CC_NOCOLOR=1
cc_color_init
cc_use_run_dir
W="$CC_RUN_DIR/.work"
mkdir -p "$W" || cc_die 3 "cannot create $W"
header() { cc_show "" ""; cc_show "$C_CYN" "==========[ $1 ]=========="; }
cc_show "$C_CYN" "NW-07 Network config audit | from $CC_HOST | results in $CC_RUN_DIR"
cc_show "" "Legend: ${C_RED}[!] HIGH${C_OFF} fix now   ${C_YEL}[*] MED${C_OFF} look at it   ${C_GRN}[ok]${C_OFF} nothing found   (reads saved files only: touches no device)"
header "1/3  which configs"
FT=$(cc_table_new findings device vendor severity finding detail)

# detect FILE -> vendor recognised from the text (empty if unknown).
detect() {
    awk '
        /^ASA Version / { print "cisco-asa"; exit }
        /^version [0-9]+\.[0-9]+/ { print "cisco-ios"; exit }
        /^#config-version=F/ { print "fortigate"; exit }
        /^config system global/ { print "fortigate"; exit }
        /<pfsense>/ { print "pfsense"; exit }
        /<opnsense>/ { print "opnsense"; exit }
        /^set system host-name / || /^set interfaces ethernet / { print "vyos"; exit }
        /by RouterOS/ || /^\/interface / || /^\/ip service/ { print "mikrotik"; exit }
        /^ *(deviceconfig|mgt-config) \{/ { print "paloalto"; exit }
        /^DISTRIB_ID=.OpenWrt/ || /^package (firewall|dropbear|uhttpd)$/ { print "openwrt"; exit }
        END { }' "$1"
}

# ---- What to audit: "device|vendor|file" ------------------------------------------
: >"$W/todo"
if [ -n "$FILES" ]; then
    printf '%s' "$FILES" | grep . >"$W/files"
    while IFS= read -r _spec; do
        _f=${_spec%%,*}; _v=""
        case "$_spec" in *,*) _v=${_spec#*,} ;; esac
        [ -n "$_v" ] || _v=$(detect "$_f")
        if [ -z "$_v" ]; then cc_warn "$_f: vendor not recognised - give it as --file $_f,VENDOR"; continue; fi
        case " $VENDORS " in *" $_v "*) ;; *) cc_die 2 "unknown vendor '$_v' (one of: $VENDORS)" ;; esac
        printf '%s|%s|%s\n' "$(basename "$_f" | sed 's/\.[^.]*$//')" "$_v" "$_f" >>"$W/todo"
    done <"$W/files"
else
    _given=$CONFIGS
    [ -n "$CONFIGS" ] || CONFIGS="$CC_OUT/net-configs"
    _saved=""; for _d in "$CONFIGS"/*/; do [ -f "$_d/latest" ] && _saved="$_saved $(basename "$_d")"; done
    # No flag said which: offer NW-01's copies, or ask for a file.
    if [ -z "$_given" ] && _cc_can_ask; then
        _use=n
        if [ -n "$_saved" ]; then
            cc_ask "Audit the newest config NW-01 saved for:$_saved?" Y "yes, audit them" "no, I will name a file" && _use=y
        fi
        if [ "$_use" = n ]; then
            cc_ask_text "Config file to audit?" "" "a file copied off the device, like router.cfg"
            [ -r "$CC_ANSWER" ] || cc_die 2 "cannot read '$CC_ANSWER' (run NW-01 first, or give --file)"
            _af=$CC_ANSWER; _av=$(detect "$_af")
            if [ -z "$_av" ]; then
                cc_choose "What device is $(basename "$_af") from?" o "o=OpenWRT router" "m=MikroTik" "p=pfSense" "n=OPNsense" \
                    "c=Cisco router or switch (IOS)" "a=Cisco ASA" "x=Palo Alto" "f=FortiGate" "v=VyOS"
                case "$CC_CHOICE" in o) _av=openwrt ;; m) _av=mikrotik ;; p) _av=pfsense ;; n) _av=opnsense ;;
                    c) _av=cisco-ios ;; a) _av=cisco-asa ;; x) _av=paloalto ;; f) _av=fortigate ;; *) _av=vyos ;; esac
            fi
            printf '%s|%s|%s\n' "$(basename "$_af" | sed 's/\.[^.]*$//')" "$_av" "$_af" >>"$W/todo"
            CONFIGS=/nonexistent
        fi
    fi
    [ -d "$CONFIGS" ] || [ -s "$W/todo" ] || cc_die 3 "no saved configs in $CONFIGS: run NW-01 first, or give --file"
    for _d in "$CONFIGS"/*/; do
        [ -f "$_d/latest" ] || continue
        _n=$(basename "$_d"); _s=$(cat "$_d/latest")
        _f="$_d$_s.norm"; [ -f "$_f" ] || _f="$_d$_s.cfg"
        [ -f "$_f" ] || continue
        _v=$(cat "$_d/vendor" 2>/dev/null); [ -n "$_v" ] || _v=$(detect "$_f")
        case " $VENDORS " in *" $_v "*) ;; *) cc_debug "$_n: vendor '${_v:-?}' has no audit rules (linux devices are audited by the Linux scripts)"; continue ;; esac
        printf '%s|%s|%s\n' "$_n" "$_v" "$_f" >>"$W/todo"
    done
fi
[ -s "$W/todo" ] || cc_die 3 "no configs to audit"

# ---- The rules ------------------------------------------------------------------
# Every rule prints "SEVERITY|finding|detail".  "detail" is the config line
# with secrets masked, or a short explanation.
MASK='
function mask(s,   n, w, i, out, lw, m) {  # awk, not shell: posix-ok
    if (match(s, /<(password|community|rocommunity|rwcommunity|pre-shared-key|secret|psk|key|phash|bcrypt-hash)>[^<]*</)) {
        m = substr(s, RSTART, RLENGTH); sub(/>[^<]*</, ">****<", m); s = substr(s, 1, RSTART - 1) m substr(s, RSTART + RLENGTH)
    }
    n = split(s, w, " "); out = ""
    for (i = 1; i <= n; i++) {
        lw = tolower(w[i]); gsub(/[^a-z-]/, "", lw)
        if (lw ~ /^(password|secret|key|key-string|psk|pre-shared-key|passphrase|passwd|plaintext-password|encrypted-password|phash|community|community-string)$/ && i < n) {
            out = out (out ? " " : "") w[i]
            if (w[i + 1] ~ /^[0-9]$/ && i + 2 <= n) { i++; out = out " " w[i] }
            i++; out = out " ****"; continue
        }
        out = out (out ? " " : "") w[i]
    }
    return out
}
function f(sev, what, line) { print sev "|" what "|" mask(line) }  # awk, not shell: posix-ok
function trim(s) { gsub(/^[ \t]+|[ \t;]+$/, "", s); return s }'  # awk, not shell: posix-ok

# Default and guessable SNMP communities.
WEAKSNMP='^(public|private|cisco|community|admin|default|secret|password|snmp|monitor|manager|read|write|test|bt)$'

RULES_CISCO_IOS='
/^line (vty|con|aux)/ { endline(); inline = 1; lname = $0; tin = ""; acl = 0; nologin = 0; next }
inline && /^[^ ]/ { endline() }
inline && /^ transport input/ { tin = $0 }
inline && /^ access-class/ { acl = 1 }
inline && /^ no login/ { nologin = 1 }
inline && /^ password 7 / { f("MED", "reversible line password (type 7)", lname ": " $0) }
inline && /^ password [^57]/ && !/^ password 7/ { f("HIGH", "clear-text line password", lname ": " $0) }
function endline() {  # awk, not shell: posix-ok
    if (!inline) return
    if (lname ~ /vty/) {
        if (tin ~ /telnet|all/) f("HIGH", "telnet allowed on remote login lines", lname ": " trim(tin))
        else if (tin == "") f("MED", "no \"transport input\" on remote login lines (older IOS then allow telnet)", lname)
        if (!acl) f("MED", "remote login lines accept any address (no access-class)", lname)
    }
    if (nologin) f("HIGH", "login with NO password on " lname, lname ": no login")
    inline = 0
}
/^ip http server/ { f("MED", "plain HTTP management server on", $0) }
/^ip http secure-server/ { f("LOW", "HTTPS management server on (limit it with ip http access-class)", $0) }
/^snmp-server community / { c = $3; t = toupper($4)
    if (tolower(c) ~ weak) f("HIGH", "default/guessable SNMP community", $0)
    else if (t == "RW") f("HIGH", "SNMP read-WRITE community (can change the config)", $0)
    else f("LOW", "SNMPv1/v2c community (clear text on the wire)", $0) }
/^enable password / { f("HIGH", "enable password stored weakly (use enable secret)", $0) }
/^enable secret 5 / { f("LOW", "enable secret uses MD5 (type 5); prefer type 8 or 9", $0) }
/^enable secret/ { hasenable = 1 }
/^username / {
    users = users (users ? ", " : "") $2
    if ($0 ~ / password [07] / || $0 ~ / password [^0-9]/) f("HIGH", "account " $2 " has a clear-text or reversible password", $0)
    if (tolower($2) ~ /^(cisco|admin|root|test|guest|user)$/) f("MED", "default-looking account name " $2, $0)
}
/^no service password-encryption/ { f("LOW", "service password-encryption is off", $0) }
/^service password-encryption/ { pwenc = 1 }
/^ip ssh version 1/ { f("MED", "SSH version 1 allowed", $0) }
/^ip ssh version 2/ { ssh2 = 1 }
/^logging (host )?[0-9]/ { logsrv = 1 }
/^service (tcp|udp)-small-servers/ { f("MED", "small servers (echo, chargen) on", $0) }
/^ip finger|^service finger/ { f("LOW", "finger service on", $0) }
/^ip source-route/ { f("LOW", "IP source routing on", $0) }
END { endline()
    if (!hasenable) f("MED", "no enable secret set", "(none)")
    if (!pwenc) f("LOW", "service password-encryption not set", "(missing)")
    if (!ssh2) f("LOW", "SSH not limited to version 2 (ip ssh version 2)", "(missing)")
    if (!logsrv) f("LOW", "no remote logging server", "(missing)")
    if (users != "") f("INFO", "local accounts", users) }'

RULES_CISCO_ASA='
/^telnet [0-9]/ { if ($2 == "0.0.0.0" && $3 == "0.0.0.0") f("HIGH", "telnet management open to ANY address on " $4, $0); else f("HIGH", "telnet management on", $0) }
/^http [0-9]/ { if ($2 == "0.0.0.0" && $3 == "0.0.0.0") f("HIGH", "web management (ASDM) open to ANY address on " $4, $0); else f("LOW", "web management (ASDM) allowed from " $2, $0) }
/^ssh [0-9]/ && $2 == "0.0.0.0" && $3 == "0.0.0.0" { f("MED", "SSH management open to ANY address on " $4, $0) }
/^snmp-server community / { if (tolower($3) ~ weak) f("HIGH", "default/guessable SNMP community", $0); else f("LOW", "SNMPv1/v2c community", $0) }
/^snmp-server host / && / community / { split($0, a, " community "); split(a[2], b, " "); if (tolower(b[1]) ~ weak) f("HIGH", "default/guessable SNMP community", $0) }
/^enable password / && $0 !~ /(encrypted|pbkdf2)/ { f("HIGH", "enable password not hashed", $0) }
/^username / { users = users (users ? ", " : "") $2
    if ($0 ~ / password / && $0 !~ /(encrypted|pbkdf2|nt-encrypted)/) f("HIGH", "account " $2 " password not hashed", $0)
    if (tolower($2) ~ /^(cisco|admin|root|test|guest|user)$/) f("MED", "default-looking account name " $2, $0) }
/^access-list / && / permit ip any4? any4?( |$)/ { f("HIGH", "access list permits ANY to ANY", $0) }
/^access-list / && / permit (tcp|udp) any4? any4?( |$)/ { f("MED", "access list permits any TCP/UDP to anywhere", $0) }
/^logging host / { logsrv = 1 }
END { if (!logsrv) f("LOW", "no remote logging server", "(missing)")
      if (users != "") f("INFO", "local accounts", users) }'

# Palo Alto brace format.  path[] tracks the open blocks.
RULES_PALOALTO='
{ line = $0; sub(/^[ \t]+/, "", line) }
line ~ /\{ *$/ { nm = line; sub(/ *\{ *$/, "", nm); path[++d] = nm
    if (nm == "permitted-ip") permitted = 1
    if (path[d - 1] == "rules" && infw) { inrule = 1; rname = nm; gsub(/"/, "", rname); delete ra }
    if (nm == "security" && path[d - 1] == "rulebase") infw = d
    if (path[d - 1] == "users" && path[d - 2] == "mgt-config") { admins = admins (admins ? ", " : "") nm; if (nm == "admin") f("MED", "the default admin account exists: make sure its password was changed", "mgt-config users admin") }
    next }
line ~ /^\}/ { if (inrule && path[d - 1] == "rules") { checkrule(); inrule = 0 }
    if (infw == d) infw = 0
    d--; next }
inrule { k = line; sub(/ .*/, "", k); v = line; sub(/^[^ ]+ */, "", v); gsub(/[;\[\]]/, "", v); v = trim(v); ra[k] = v }
line ~ /^disable-telnet no;/ { f("HIGH", "telnet management on", line) }
line ~ /^disable-http no;/ { f("MED", "plain HTTP management on", line) }
line ~ /^telnet yes;/ && pathhas("interface-management-profile") { f("HIGH", "telnet allowed by management profile " path[d], line) }
line ~ /^http yes;/ && pathhas("interface-management-profile") { f("MED", "plain HTTP allowed by management profile " path[d], line) }
line ~ /^(community-string|community) / { c = line; sub(/^[^ ]+ /, "", c); gsub(/[";]/, "", c); if (tolower(c) ~ weak) f("HIGH", "default/guessable SNMP community", line); else f("LOW", "SNMPv2c community", line) }
line ~ /^permitted-ip / { permitted = 1 }
function pathhas(s,   i) { for (i = 1; i <= d; i++) if (path[i] == s) return 1; return 0 }  # awk, not shell: posix-ok
function checkrule() {  # awk, not shell: posix-ok
    if (ra["action"] == "allow" && ra["source"] == "any" && ra["destination"] == "any" && ra["application"] == "any" && (ra["service"] == "any" || ra["service"] == "application-default"))
        f("HIGH", "security rule " rname " allows ANY source to ANY destination for ANY application", "from " ra["from"] " to " ra["to"])
}
END { if (!permitted) f("MED", "management interface accepts any address (no permitted-ip)", "(missing)")
      if (admins != "") f("INFO", "admin accounts", admins) }'

RULES_FORTIGATE='
/^config / { sect = $0; sub(/^config /, "", sect) }
/^end/ { sect = "" }
/^ *edit / { ed = $0; sub(/^ *edit /, "", ed); gsub(/"/, "", ed); delete pa; hastrust = 0 }
/^ *next/ { if (sect == "firewall policy") checkpol(); if (sect == "system admin") { admins = admins (admins ? ", " : "") ed; if (!hastrust) f("MED", "admin " ed " can log in from any address (no trusthost)", "config system admin / edit " ed) } ed = "" }
sect == "system interface" && /set allowaccess/ {
    if ($0 ~ / telnet/) f("HIGH", "telnet management on interface " ed, $0)
    if ($0 ~ / http( |$)/) f("MED", "plain HTTP management on interface " ed, $0) }
sect == "system admin" && /set trusthost[0-9]/ { hastrust = 1 }
sect ~ /^system snmp community/ && /set name / { c = $3; gsub(/"/, "", c); if (tolower(c) ~ weak) f("HIGH", "default/guessable SNMP community", $0); else f("LOW", "SNMPv2c community", $0) }
sect == "firewall policy" && /set (srcaddr|dstaddr|service|action) / { k = $2; v = $0; sub(/^ *set [a-z]+ /, "", v); gsub(/"/, "", v); pa[k] = v }
function checkpol() {  # awk, not shell: posix-ok
    if (pa["action"] == "accept" && pa["srcaddr"] == "all" && pa["dstaddr"] == "all" && toupper(pa["service"]) == "ALL")
        f("HIGH", "firewall policy " ed " accepts ALL to ALL for ALL services", "edit " ed)
}
END { if (admins != "") f("INFO", "admin accounts", admins) }'

RULES_VYOS='
/^set service telnet/ { f("HIGH", "telnet service on", $0) }
/^set service snmp community / { c = $5; gsub(/\047/, "", c); if (tolower(c) ~ weak) f("HIGH", "default/guessable SNMP community", $0); else f("LOW", "SNMPv2c community", $0) }
/^set service snmp community .* authorization .?rw/ { f("HIGH", "SNMP read-WRITE community", $0) }
/plaintext-password/ { f("HIGH", "clear-text login password in the config", $0) }
/^set system login user / { u = $5; gsub(/\047/, "", u); if (!(u in seen)) { seen[u] = 1; users = users (users ? ", " : "") u } }
/^set service https/ { f("LOW", "HTTPS API/management on", $0) }
/^set service ssh listen-address/ { sshlim = 1 }
/^set service ssh/ { ssh = 1 }
END { if (ssh && !sshlim) f("LOW", "SSH listens on every address (no listen-address)", "(missing)")
      if (users != "") f("INFO", "login accounts", users) }'

# pfSense and OPNsense config.xml.
RULES_PFSENSE='
{ l = $0 }
l ~ /<webgui>/ { inweb = 1 } l ~ /<\/webgui>/ { inweb = 0 }
inweb && l ~ /<protocol>http<\/protocol>/ { f("MED", "web GUI over plain HTTP", trim(l)) }
l ~ /<rocommunity>|<rwcommunity>/ { c = l; sub(/.*community>/, "", c); sub(/<.*/, "", c); if (tolower(c) ~ weak) f("HIGH", "default/guessable SNMP community", trim(l)); else f("LOW", "SNMP community", trim(l)) }
l ~ /<rwcommunity>/ { f("HIGH", "SNMP read-WRITE community", trim(l)) }
l ~ /<user>/ { inuser = 1 } l ~ /<\/user>/ { inuser = 0 }
inuser && l ~ /<name>/ { u = l; sub(/.*<name>/, "", u); sub(/<.*/, "", u); users = users (users ? ", " : "") u }
l ~ /<rule>/ { inrule = 1; iface = ""; typ = "pass"; srcany = 0; dstany = 0; inside = ""; dis = 0 }
inrule && l ~ /<source>/ { inside = "src" } inrule && l ~ /<destination>/ { inside = "dst" }
inrule && l ~ /<\/source>|<\/destination>/ { inside = "" }
inrule && l ~ /<any\/>|<any><\/any>|<any>1<\/any>/ { if (inside == "src") srcany = 1; if (inside == "dst") dstany = 1 }
inrule && l ~ /<interface>/ { iface = l; sub(/.*<interface>/, "", iface); sub(/<.*/, "", iface) }
inrule && l ~ /<type>/ { typ = l; sub(/.*<type>/, "", typ); sub(/<.*/, "", typ) }
inrule && l ~ /<disabled/ { dis = 1 }
l ~ /<\/rule>/ { if (inrule && !dis && typ == "pass" && srcany && dstany && iface ~ /wan/) f("HIGH", "rule passes ANY to ANY on the WAN interface", "interface " iface); inrule = 0 }
END { if (users != "") f("INFO", "accounts", users) }'

RULES_MIKROTIK='
/^\// { insvc = 0; insnmp = 0; inuser = 0 }
/^\/ip service/ { insvc = 1; next }
insvc && /set telnet/ { tel = 1; if ($0 !~ /disabled=yes/) f("HIGH", "telnet service on", $0) }
insvc && /set www / && $0 !~ /disabled=yes/ { f("MED", "plain HTTP management (www) on", $0) }
insvc && /set (ftp|api) / && $0 !~ /disabled=yes/ { f("MED", $2 " service on", $0) }
/^\/snmp community/ { insnmp = 1; next }
insnmp && /name=/ { c = $0; sub(/.*name=/, "", c); sub(/ .*/, "", c); if (tolower(c) ~ weak) f("HIGH", "default/guessable SNMP community", $0) }
/^\/user/ { inuser = 1; next }
inuser && /add .*name=/ { u = $0; sub(/.*name=/, "", u); sub(/ .*/, "", u); users = users (users ? ", " : "") u }
END { if (!tel) f("MED", "telnet not disabled in the export (RouterOS has it on by default)", "/ip service set telnet disabled=yes is missing")
      if (users != "") f("INFO", "accounts", users) }'

RULES_OPENWRT='
# uci export: "package X", then "config TYPE [name]" sections with
# "option K V" / "list K V".  Each section is judged when it ends.  The
# "===name" parts are what NW-01 adds: accounts, keys, cron, startup.
function uq(s) { gsub(/^[ \t]+|[ \t]+$/, "", s); if (Q == "") Q = sprintf("%c", 39); gsub("^" Q "|" Q "$", "", s); return s }  # awk, not shell: posix-ok
function endsec(   k) {  # awk, not shell: posix-ok
    if (pkg == "dropbear" && ctype == "dropbear") {
        if (o["Interface"] == "" || o["Interface"] == "wan") f("MED", "SSH (dropbear) listens on every interface, the outside (wan) too", "set option Interface lan (NW-21)")
        if (o["GatewayPorts"] == "on" || o["GatewayPorts"] == "1") f("MED", "SSH lets logins open ports for others (GatewayPorts on)", "option GatewayPorts " o["GatewayPorts"])
    }
    if (pkg == "uhttpd" && ctype == "uhttpd") {
        if (http != "" && o["redirect_https"] != "1" && o["redirect_https"] != "on") f("MED", "web admin (LuCI) over plain HTTP: the root password crosses the network in the clear", "listen_http " http " (redirect_https off)")
        if (http ~ /0\.0\.0\.0|\[::\]|^[0-9]+$/ || https ~ /0\.0\.0\.0|\[::\]|^[0-9]+$/) f("LOW", "web admin (LuCI) listens on every address", "listen " http " " https)
    }
    if (pkg == "firewall" && ctype == "zone" && o["name"] == "wan") {
        if (o["input"] == "ACCEPT") f("HIGH", "the outside (wan) zone ACCEPTs everything sent to the router", "zone wan: option input ACCEPT")
        if (o["forward"] == "ACCEPT") f("HIGH", "the outside (wan) zone forwards everything to the inside", "zone wan: option forward ACCEPT")
    }
    if (pkg == "firewall" && ctype == "forwarding" && o["src"] == "wan" && o["dest"] == "lan") f("HIGH", "outside to inside forwarding: every inside box is open from the outside", "forwarding wan -> lan")
    if (pkg == "firewall" && ctype == "rule" && o["src"] == "wan" && o["target"] == "ACCEPT") {
        nm = (o["name"] != "" ? o["name"] : "(no name)")
        if (o["dest"] == "") {
            if (o["dest_port"] ~ /(^| )(22|23|80|443|8080)( |$)/) f("HIGH", "router management open from the outside (port " o["dest_port"] ")", "rule " nm)
            else if (o["dest_port"] == "" && o["proto"] != "icmp") f("HIGH", "everything to the router allowed from the outside", "rule " nm)
        } else if (o["dest_port"] == "" && o["dest_ip"] == "") f("HIGH", "any-to-any allow from the outside", "rule " nm " (src wan, dest " o["dest"] ")")
        else f("INFO", "allowed from the outside", "rule " nm ": " o["proto"] " " o["dest_ip"] ":" o["dest_port"])
    }
    if (pkg == "firewall" && ctype == "redirect" && (o["target"] == "DNAT" || o["target"] == "")) {
        fw = o["src_dport"] " -> " o["dest_ip"] ":" (o["dest_port"] != "" ? o["dest_port"] : o["src_dport"])
        if ((o["dest_port"] != "" ? o["dest_port"] : o["src_dport"]) ~ /^(22|23|3389|5985|5986|445|3306|5432)$/) f("MED", "a management or database port is forwarded from the outside (scored? else red team)", "redirect " o["name"] ": " fw)
        fwds = fwds (fwds ? ", " : "") fw
    }
    if (pkg == "upnpd" && ctype == "upnpd" && o["enabled"] == "1") f("HIGH", "UPnP is on: any program inside can open ports on the router to the outside", "upnpd enabled 1")
    if (pkg == "snmpd" && ctype == "community" && tolower(o["community"]) ~ weak) f("HIGH", "default/guessable SNMP community", "community " o["community"])
    if (pkg == "system" && ctype == "system" && o["log_ip"] == "") f("LOW", "no remote log server (logs stay on the router)", "set system log_ip (NW-21)")
    if (pkg == "system" && ctype == "timeserver" && o["enabled"] == "0") f("LOW", "the time server client is off", "timeserver enabled 0")
    if (pkg == "rpcd" && ctype == "login" && o["username"] != "root") f("MED", "an extra LuCI login", "rpcd login " o["username"])
    split("", o); http = ""; https = ""
}
/^===/ { endsec(); part = substr($0, 4); pkg = ""; ctype = ""; next }
part == "uci" && /^package / { endsec(); pkg = $2; ctype = ""; next }
part == "uci" && /^config / { endsec(); ctype = uq($2); next }
part == "uci" && /^[ \t]+option / { k = $2; v = $0; sub(/^[ \t]+option[ \t]+[^ \t]+[ \t]+/, "", v); o[k] = uq(v); next }
part == "uci" && /^[ \t]+list listen_http / { v = $0; sub(/.*listen_http[ \t]+/, "", v); http = http (http ? " " : "") uq(v); next }
part == "uci" && /^[ \t]+list listen_https / { v = $0; sub(/.*listen_https[ \t]+/, "", v); https = https (https ? " " : "") uq(v); next }
part == "passwd" && /:/ { split($0, a, ":"); if (a[3] == "0" && a[1] != "root") f("HIGH", "a second account with root rights (UID 0)", a[1]); if (a[7] !~ /(false|nologin)$/ && a[1] != "root") users = users (users ? ", " : "") a[1] }
part == "keys" && /^(ssh-|ecdsa-|sk-)/ { nk++; kc = kc (kc ? ", " : "") $NF }
part == "cron" && NF && !/^#/ { f("MED", "root cron job on the router (yours?)", $0) }
part == "startup" && /telnet/ { f("HIGH", "telnet starts at boot", "/etc/rc.d/" $0) }
part == "rc.local" && NF && !/^#/ && !/^exit 0/ { f("MED", "a command in /etc/rc.local (runs at every boot)", $0) }
END { endsec()
      if (nk) f("MED", nk " SSH key(s) can log in as root (check each is yours)", kc)
      if (fwds != "") f("INFO", "port forwards (outside -> inside: likely the scored paths)", fwds)
      if (users != "") f("INFO", "accounts that can log in", users) }'

rules_for() {
    case "$1" in
        cisco-ios) printf '%s' "$RULES_CISCO_IOS" ;;
        cisco-asa) printf '%s' "$RULES_CISCO_ASA" ;;
        paloalto)  printf '%s' "$RULES_PALOALTO" ;;
        fortigate) printf '%s' "$RULES_FORTIGATE" ;;
        vyos)      printf '%s' "$RULES_VYOS" ;;
        pfsense|opnsense) printf '%s' "$RULES_PFSENSE" ;;
        mikrotik)  printf '%s' "$RULES_MIKROTIK" ;;
        openwrt)   printf '%s' "$RULES_OPENWRT" ;;
    esac
}

# ---- Run ---------------------------------------------------------------------------
: >"$W/summary_rows"
awk -F'|' '{ printf "  %s (%s): %s\n", $1, $2, $3 }' "$W/todo" | while IFS= read -r _l; do cc_show "$C_GRY" "$_l"; done
header "2/3  each device"
while IFS='|' read -r _n _v _f; do
    # CR line ends (configs saved from Windows tools) would break the matches.
    tr -d '\r' <"$_f" >"$W/cfg"
    # XML configs: one tag per line, whatever the file's own layout, so the
    # line-based rules see every tag.
    case "$_v" in pfsense|opnsense) awk '{ gsub(/></, ">\n<"); print }' "$W/cfg" >"$W/cfg.x" && mv "$W/cfg.x" "$W/cfg" ;; esac
    # MikroTik wraps long export lines with "\": join them, or a
    # "disabled=yes" on the second half is not seen.
    case "$_v" in mikrotik) awk '/\\$/ { sub(/\\$/, ""); h = h $0; next } h != "" { sub(/^[ \t]+/, ""); $0 = h $0; h = "" } { print }' "$W/cfg" >"$W/cfg.x" && mv "$W/cfg.x" "$W/cfg" ;; esac
    awk -v weak="$WEAKSNMP" "$MASK$(rules_for "$_v")" "$W/cfg" >"$W/found"
    cc_debug "$_n ($_v): $(grep -c . "$W/found") findings from $_f"
    while IFS='|' read -r _sev _what _det; do
        cc_table_row "$FT" "$_n" "$_v" "$_sev" "$_what" "$_det"
        case "$_sev" in HIGH|MED|LOW) cc_flag "$_sev" "$_n" "$_what" "$_det" ;; esac
    done <"$W/found"
    printf '%s|%s|%s|%s|%s|%s\n' "$_n" "$_v" "$(grep -c '^HIGH' "$W/found")" "$(grep -c '^MED' "$W/found")" "$(grep -c '^LOW' "$W/found")" \
        "$(awk -F'|' '$1 == "INFO" { print $2 ": " $3 }' "$W/found" | head -n 1 | cut -c1-70)" >>"$W/summary_rows"
    _h=$(grep -c '^HIGH' "$W/found"); _m=$(grep -c '^MED' "$W/found")
    if [ "$_h" -gt 0 ]; then cc_show "$C_RED" "  [!] $_n ($_v): $_h HIGH, $_m MED - listed below, worst first"
    elif [ "$_m" -gt 0 ]; then cc_show "$C_YEL" "  [*] $_n ($_v): $_m MED - listed below"
    else cc_show "$C_GRN" "  [ok] $_n ($_v): nothing found"; fi
done <"$W/todo"

cc_table_align "$FT"
cc_table_sort_flags "$CC_RUN_DIR/flags.txt"
{
    printf 'NW-07 Network config audit | %s\n\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '%-16s %-10s %4s %4s %4s  %s\n' device vendor high med low accounts
    awk -F'|' '{ printf "%-16s %-10s %4d %4d %4d  %s\n", $1, $2, $3, $4, $5, $6 }' "$W/summary_rows"
    printf '\n'
    cc_flag_report "$MAXFLAGS"
    printf '\nEvery finding: %s/findings.txt\nAll results: %s\n' "$CC_RUN_DIR" "$CC_RUN_DIR"
} >"$CC_RUN_DIR/summary.txt"
header "3/3  summary"
cat "$CC_RUN_DIR/summary.txt"
rm -rf "$W"
cc_finish
