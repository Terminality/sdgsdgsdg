#!/bin/sh
# =============================================================================
# ID:       SH-05
# NAME:     Linux enum
# ROLE:     Linux  (wave 1)
# KIND:     readonly - changes nothing on the host
# VERSION:  1.1.0
#
# PURPOSE
#   One run shows what a Unix host is and what is on it: who can log in, what
#   is listening, what starts on boot or on a schedule, who can become root,
#   what is running, and the places a red team usually hides.  It is the
#   first thing to run on every Linux/Unix box, and most later scripts and
#   inventory injects reuse its CSV files.
#
#   Output is layered so it is thorough without being overwhelming (rule 17):
#     screen (live)          like linpeas: a header per section as it runs,
#                            then what it found.  Red [!] FIX = HIGH, fix now;
#                            yellow [*] LOOK = MED, look soon; grey = info.
#                            Same text without colour in output.txt
#     summary.txt            one page at the end: key facts, a count per
#                            section, and the HIGH and MED flags, worst first
#     <section>.txt          everything collected, one readable table per section
#     flags.txt              every flag including LOW, with the reason
#     csv/                   the same data as CSV, for SH-04 and other tools
#     raw/*.txt              untouched tool output (iptables-save, sshd -T ...)
#
# USAGE
#   sh SH-05-linux-enum.sh [options]
#   Run as root.  It works as a normal user, but several sections are then
#   incomplete (shadow file, sudoers, other users' processes); the summary
#   says which.
#
# OPTIONS
#   --profile NAME   card | full | triage   (default: full)
#                      card    quick look, under a minute: system, users,
#                              ports, services, autostart, ssh, sudo
#                      full    card plus processes, connections, sessions,
#                              packages, files, firewall, pam, mac, trust,
#                              creds, containers, modules
#                      triage  full plus a copy of the logs (incident start)
#   --only a,b,c     run only these sections (names from --list)
#   --skip a,b,c     run the profile without these sections
#   --fast           skip the slow whole-disk searches (files, creds)
#   --max-flags N    how many HIGH/MED flags to print in the end summary (default 30)
#   --low            also show LOW flags live (they are always in flags.txt)
#   --no-color       no colours (also off when the output is not a terminal,
#                    or when NO_COLOR is set)
#   --list           list the sections and exit
#   --help           this text plus the common options
#   Common options (--out, --debug, --quiet ...) come from the library.
#
# OUTPUTS  (under the --out folder; never next to this script)
#   One numbered folder per run: linux-enum-1, linux-enum-2, ... (the higher
#   the number, the newer the run)
#   SH-05_<host>_<UTC time>.log      log of the run (in the --out folder)
#   linux-enum-N/output.txt          everything shown live, without colour
#   linux-enum-N/summary.txt         the one-page summary
#   linux-enum-N/flags.txt           every flag, as a readable table
#   linux-enum-N/<section>.txt       each section as a readable table
#   linux-enum-N/csv/*.csv           the same as CSV (used by SH-04)
#   linux-enum-N/raw/*.txt           raw tool output
#   linux-enum-N/logs/               copied logs (triage only)
#   linux-enum-N/run.txt             id, host and start time (read by SH-04)
#
# WHAT IT CHANGES
#   Nothing.  It only reads.  It never prints or stores a password value:
#   the creds section records the FILE and the SETTING NAME, not the value.
#
# DEPENDS ON  (every one has a fallback; a missing tool only thins a section)
#   ports        ss -> netstat -> sockstat (BSD) -> /proc/net (no tools)
#   processes    ps (procps / BSD / busybox / -ef forms)
#   services     systemctl -> service -> rc-status -> BSD service -> svcs
#   packages     dpkg-query, rpm, apk, pacman, pkg, pkginfo
#   firewall     iptables-save, ip6tables-save, nft, ufw, firewall-cmd, pfctl
#   files        find, lsattr (immutable flags), getcap (capabilities)
#   everything   awk, sed, grep, ls - present on every Unix
#
# TESTED ON
#   Debian-based Linux container, as root and as an unprivileged user, under
#   dash, bash, busybox sh, ksh93, mksh and yash.  NOT yet tested on RHEL,
#   SUSE, Alpine, FreeBSD or Solaris; the BSD and Solaris paths are written
#   but unproven.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - Flags are pointers, not verdicts.  Some will be legitimate on your box
#     (a service account that really needs a shell).  Look, then decide.
#   - It sees what the operating system reports.  A kernel rootkit can hide
#     processes, files and ports from every tool this script uses.
#   - Accounts come from /etc/passwd only; LDAP or NIS users are not listed.
#   - The files and creds sections walk the disk and can take minutes on a
#     large server.  Use --fast or --profile card when time matters.
#   - Port-to-process mapping needs root; as a normal user the pid/process
#     columns are blank for other users' sockets.
#
# DEBUGGING
#   --debug            prints each tool choice and each section's timing
#   sh -x SH-05-...    traces every command
#   raw/*.txt          shows exactly what each tool printed, so a parsing
#                      mistake can be told apart from missing data
#   Each section is independent: if one misbehaves, rerun with --only NAME.
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

ALL_SECTIONS="system users ports services autostart ssh sudo processes connections sessions packages files firewall pam mac trust creds containers modules logs"
PROFILE_CARD="system users ports services autostart ssh sudo"
PROFILE_FULL="$PROFILE_CARD processes connections sessions packages files firewall pam mac trust creds containers modules"
PROFILE_TRIAGE="$PROFILE_FULL logs"

usage() {
    cat <<'USAGE'
SH-05 Linux enum - read-only look at a Unix host
  sh SH-05-linux-enum.sh [options]

  --profile card|full|triage   how much to collect (default full)
  --only a,b,c                 run only these sections
  --skip a,b,c                 leave these sections out
  --fast                       skip the slow disk searches (files, creds)
  --max-flags N                HIGH/MED flags in the end summary (default 30)
  --low                        also show LOW flags live
  --no-color                   no colours
  --list                       list the sections and exit
  --help                       show this text

USAGE
    cc_usage_common
}

list_sections() {
    cat <<'LIST'
system       host facts, addresses, routes, DNS, hosts file, ld.so.preload
users        accounts, password state, admin and root-equivalent groups
ports        listening ports with the process and program behind each
services     services, enabled/running state, suspicious unit files
autostart    cron, at, timers, rc.local, shell startup files, motd, udev
ssh          effective sshd settings and every authorized_keys entry
sudo         sudoers, doas and polkit rules
processes    every process with its program file
connections  live network connections with the process behind each
sessions     who is logged in now, recent logins
packages     installed packages and versions
files        SUID/SGID, capabilities, world-writable, immutable files   (slow)
firewall     host firewall rules for IPv4 and IPv6
pam          login (PAM) configuration and module integrity
mac          SELinux / AppArmor state
trust        .rhosts, hosts.equiv, NFS exports, mounts, TCP wrappers
creds        files holding passwords (names only), keys, shell history (slow)
containers   docker / podman / lxc / kubernetes
modules      kernel modules and module load hooks
logs         copy of the system and service logs   (triage profile only)
LIST
}

# ---- Options ----------------------------------------------------------------
PROFILE=full
ONLY=""
SKIP=""
FAST=0
MAXFLAGS=30
SHOWLOW=0
COLOR=1
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --profile)   [ $# -ge 2 ] || cc_die 2 "--profile needs card, full or triage"; PROFILE=$2; shift 2 ;;
        --only)      [ $# -ge 2 ] || cc_die 2 "--only needs a list of sections"; ONLY=$2; shift 2 ;;
        --skip)      [ $# -ge 2 ] || cc_die 2 "--skip needs a list of sections"; SKIP=$2; shift 2 ;;
        --fast)      FAST=1; shift ;;
        --max-flags) [ $# -ge 2 ] || cc_die 2 "--max-flags needs a number"; MAXFLAGS=$2; shift 2 ;;
        --low)       SHOWLOW=1; shift ;;
        --no-color|--no-colour) COLOR=0; shift ;;
        --list)      list_sections; exit 0 ;;
        --help|-h)   usage; exit 0 ;;
        *)           cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done

case "$PROFILE" in
    card)   SECTIONS=$PROFILE_CARD ;;
    full)   SECTIONS=$PROFILE_FULL ;;
    triage) SECTIONS=$PROFILE_TRIAGE ;;
    *)      cc_die 2 "unknown profile '$PROFILE' (use card, full or triage)" ;;
esac
case "$MAXFLAGS" in ''|*[!0-9]*) cc_die 2 "--max-flags needs a whole number" ;; esac

# check_names LIST -> stop with exit 2 if any name is not a section.
check_names() {
    for _cn in $(printf '%s' "$1" | tr ',' ' '); do
        case " $ALL_SECTIONS " in *" $_cn "*) ;; *) cc_die 2 "unknown section '$_cn' (see --list)" ;; esac
    done
}
if [ -n "$ONLY" ]; then
    check_names "$ONLY"
    SECTIONS=$(printf '%s' "$ONLY" | tr ',' ' ')
fi
if [ -n "$SKIP" ]; then
    check_names "$SKIP"
    _keep=""
    for _s in $SECTIONS; do
        case ",$SKIP," in *",$_s,"*) ;; *) _keep="$_keep $_s" ;; esac
    done
    SECTIONS=$_keep
fi
if [ "$FAST" = 1 ]; then
    _keep=""
    for _s in $SECTIONS; do
        case "$_s" in files|creds) ;; *) _keep="$_keep $_s" ;; esac
    done
    SECTIONS=$_keep
fi

# ---- Start ------------------------------------------------------------------
cc_init "SH-05" "Linux enum" readonly
cc_use_numbered_dir linux-enum
# CSV files (for SH-04 and other tools) go in csv/; the run folder itself
# gets a readable .txt table per file at the end.
CC_CSV_DIR="$CC_RUN_DIR/csv"
mkdir -p "$CC_CSV_DIR" || cc_die 3 "cannot create $CC_CSV_DIR"
cc_detect_os
W="$CC_RUN_DIR/.work"          # scratch files; removed at the end
mkdir -p "$W" || cc_die 3 "cannot create $W"

# ---- Live output (linpeas style) ---------------------------------------------
# Printed to file descriptor 3, a copy of the real stdout taken here, so a
# flag raised inside $( ... ) still reaches the screen instead of ending up
# in the captured text.  output.txt gets the same lines without colour.
exec 3>&1
OUTF="$CC_RUN_DIR/output.txt"
: >"$OUTF"
if [ "$COLOR" = 1 ] && [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_RED=$(printf '\033[1;31m'); C_YEL=$(printf '\033[1;33m'); C_GRN=$(printf '\033[1;32m')
    C_CYN=$(printf '\033[1;36m'); C_GRY=$(printf '\033[0;90m'); C_OFF=$(printf '\033[0m')
else
    C_RED=""; C_YEL=""; C_GRN=""; C_CYN=""; C_GRY=""; C_OFF=""
fi
# show COLOUR TEXT -> one line on screen in COLOUR, and plain in output.txt.
show() {
    printf '%s%s%s\n' "$1" "$2" "$C_OFF" >&3
    printf '%s\n' "$2" >>"$OUTF"
}
show "$C_CYN" "SH-05 Linux enum | host $CC_HOST | profile $PROFILE | results in $CC_RUN_DIR"
show "" "Legend: ${C_RED}[!] FIX${C_OFF} fix now (HIGH)   ${C_YEL}[*] LOOK${C_OFF} look soon (MED)   ${C_GRY}grey${C_OFF} info"
IS_ROOT=0
cc_is_root && IS_ROOT=1
[ "$IS_ROOT" = 1 ] || cc_warn "not running as root: users, sudo, ports, processes and files will be incomplete"

# Lowest UID for real people; system accounts sit below it.
UID_MIN=$(awk '$1 == "UID_MIN" { print $2; exit }' /etc/login.defs 2>/dev/null)
case "$UID_MIN" in ''|*[!0-9]*) UID_MIN=1000 ;; esac

# Patterns used by several sections.  ERE, for grep -E.
#   SUSP_STRONG  almost never legitimate in a cron line, unit file or profile:
#                reverse shells, download-and-run, encoded commands.
#   SUSP_WEAK    sometimes legitimate, worth a look: temp folders, downloads,
#                account and firewall changes.
SUSP_STRONG='(/dev/tcp/|/dev/udp/|bash -i|sh -i|nc .*-e |ncat .*-e|socat .*exec|mkfifo|(curl|wget)[^|;]*\|[[:space:]]*(ba|da|z)?sh|base64 +(-d|--decode)|python[0-9.]* +-c|perl +-e|php +-r|ruby +-e|xxd +-r|openssl +s_client)'
SUSP_WEAK='(/tmp/|/var/tmp/|/dev/shm/|curl |wget |chattr |useradd |usermod |iptables +-F|nft +flush)'

# Programs that give a root shell when they carry the SUID bit (from the
# GTFOBins project).  Compared against the program name with any trailing
# version number removed, so python3.11 counts as python.
GTFO=" aria2c ash awk base64 bash busybox cat chmod chown cp csh curl cut dash date dd diff docker ed emacs env expect find flock gdb grep head hexdump ionice ip jq ksh less lua make more mv nano nawk gawk mawk nc ncat nice nmap node nohup od openssl perl php pico python python2 python3 rlwrap rsync run-parts rvim sed setarch socat sort sqlite3 strace systemctl tac tail tar taskset tclsh tee time timeout unshare vi view vim watch wget xargs xxd zip zsh "

# Names that mean "this is a shell or a netcat-like tool".
SHELLS_RE='^(sh|bash|dash|zsh|ksh|ksh93|mksh|csh|tcsh|ash|busybox)$'
NETCAT_RE='^(nc|ncat|netcat|nc\.traditional|nc\.openbsd|socat|cryptcat|pwncat|gs-netcat)$'
TMP_RE='^(/tmp|/var/tmp|/dev/shm|/run/shm)(/|$)'

# ---- Section helpers --------------------------------------------------------
# All loops read from files, never from a pipe.  In dash and bash the right
# side of a pipe runs in a subshell, so counters and variables set inside
# 'cmd | while read' are lost when the loop ends.

# sec_csv NAME HEADER  -> create <run>/NAME.csv; its path is left in SEC_CSV.
#   (A variable, not printed output, so the caller does not need $( ), which
#   would lose the SEC_FILES bookkeeping.)
sec_csv() {
    SEC_CSV=$(cc_csv_new "$1" "$2") || SEC_CSV=/dev/null
    SEC_FILES="$SEC_FILES $SEC_CSV"
}

# flag SEVERITY ITEM DETAIL  -> cc_flag with the current section filled in.
#   Also shows it live: HIGH red, MED yellow, LOW grey (only with --low).
flag() {
    cc_flag "$1" "$SEC" "$2" "$3"
    case "$1" in
        HIGH) show "$C_RED" "  [!] FIX   $2: $3" ;;
        MED)  show "$C_YEL" "  [*] LOOK  $2: $3" ;;
        LOW)  [ "$SHOWLOW" = 1 ] && show "$C_GRY" "  [-] info  $2: $3" ;;
    esac
    return 0
}

# emit_flags FILE  -> turn lines "SEVERITY|ITEM|DETAIL" (written by an awk
#   program) into flags.  Lets awk do the checking without a loop per line.
emit_flags() {
    [ -s "$1" ] || return 0
    while IFS='|' read -r _ef_sev _ef_item _ef_detail; do
        case "$_ef_sev" in HIGH|MED|LOW) flag "$_ef_sev" "$_ef_item" "$_ef_detail" ;; esac
    done <"$1"
}

# say TEXT  -> add a line to the summary's key-facts block.
say() { printf '%s\n' "$*" >>"$W/summary_lines"; show "$C_GRN" "  $*"; }

# note TEXT -> attach a short note to this section's row in the summary table
#   (for example "partial: not root").
note() { if [ -z "$SEC_NOTE" ]; then SEC_NOTE=$*; else SEC_NOTE="$SEC_NOTE; $*"; fi; }

# owner_of PATH -> print the owning user name.
owner_of() { ls -ld "$1" 2>/dev/null | awk '{ print $3 }'; }

# mode_of PATH  -> print the permission string, e.g. -rwsr-xr-x.
mode_of() { ls -ld "$1" 2>/dev/null | awk '{ print $1 }'; }

# home_dirs -> write "user|uid|home" for every account in /etc/passwd to $W/homes.
home_dirs() {
    awk -F: '{ print $1 "|" $3 "|" $6 }' /etc/passwd >"$W/homes" 2>/dev/null
}

# awk helper: q() quotes one CSV field.  Pasted in front of awk programs that
# write CSV rows directly (faster than one cc_csv_row call per line).
AWK_Q='function q(s) { gsub(/"/, "\"\"", s); gsub(/\r|\n/, " ", s); return "\"" s "\"" }'

# =============================================================================
# Sections.  Each one: create its CSV file(s), collect, flag, add summary
# lines.  A missing tool is noted, never fatal.
# =============================================================================

s_system() {
    sec_csv facts "key,value"
    F=$SEC_CSV
    _fqdn=$(hostname -f 2>/dev/null || uname -n)
    _boot=$(who -b 2>/dev/null | awk '{ $1 = ""; $2 = ""; sub(/^ +/, ""); print }')
    _up=$(uptime 2>/dev/null | sed 's/^ *//')
    _ip6=no
    if [ -r /proc/net/if_inet6 ] && awk '$6 != "lo" { found = 1 } END { exit !found }' /proc/net/if_inet6; then _ip6=yes; fi
    _container=no
    if [ -f /.dockerenv ] || grep -qE '(docker|kubepods|containerd|lxc)' /proc/1/cgroup 2>/dev/null; then _container=yes; fi
    for _kv in "hostname|$CC_HOST" "fqdn|$_fqdn" "os|$CC_OS_NAME" "os_family|$CC_OS_FAMILY" \
               "os_version|$CC_OS_VERSION" "kernel|$(uname -r 2>/dev/null)" "arch|$(uname -m 2>/dev/null)" \
               "init|$CC_INIT" "package_manager|$CC_PKG" "boot_time|$_boot" "uptime|$_up" \
               "time_utc|$(date -u +%Y-%m-%dT%H:%M:%SZ)" "time_local|$(date)" "ipv6_enabled|$_ip6" \
               "inside_container|$_container" "collector_run_as_root|$IS_ROOT"; do
        cc_csv_row "$F" "${_kv%%|*}" "${_kv#*|}"
    done

    # Addresses.  'ip -o' gives one line per address; ifconfig is the fallback
    # (BSD, Solaris, old Linux) and is parsed loosely.
    sec_csv addresses "interface,family,address"
    A=$SEC_CSV
    if cc_have ip; then
        cc_save ip_addr ip addr
        ip -o addr show 2>/dev/null | awk "$AWK_Q"'{ print q($2) "," q($3) "," q($4) }' >>"$A"
        cc_save ip_route ip route
        ip -6 route >>"$CC_LAST_SAVE" 2>&1
    elif cc_have ifconfig; then
        cc_save ifconfig ifconfig -a
        awk "$AWK_Q"'
            /^[A-Za-z0-9]/ { iface = $1; sub(/:$/, "", iface) }
            $1 == "inet" || $1 == "inet6" {
                addr = $2; sub(/^addr:/, "", addr)
                print q(iface) "," q($1) "," q(addr)
            }' "$CC_LAST_SAVE" >>"$A"
        cc_save routes netstat -rn
    elif [ -r /proc/net/fib_trie ]; then
        # No ip or ifconfig (minimal container): the kernel's routing table
        # lists every local IPv4 address as a "host LOCAL" entry.
        cc_save fib_trie cat /proc/net/fib_trie
        awk "$AWK_Q"'/\|--/ { ip = $2 } /host LOCAL/ { print q("?") ",\"inet\"," q(ip) }' /proc/net/fib_trie | sort -u >>"$A"
        note "no ip or ifconfig: addresses read from /proc, interface names unknown"
    else
        note "no ip or ifconfig"
    fi
    _addrs=$(awk -F'","' 'NR > 1 && $2 ~ /^inet$/ && $3 !~ /^127\./ { printf "%s%s %s", sep, $1, $3; sep = "; " }' "$A" | tr -d '"')
    say "Addresses: ${_addrs:-none found}"

    # DNS servers and the hosts file.  A red team edits /etc/hosts to send a
    # name (an update server, the scoring engine's target) somewhere else.
    _dns=$(awk '$1 == "nameserver" { printf "%s%s", sep, $2; sep = ", " }' /etc/resolv.conf 2>/dev/null)
    cc_csv_row "$F" "dns_servers" "$_dns"
    say "DNS servers: ${_dns:-none}"
    if [ -r /etc/hosts ]; then
        awk -v me="$CC_HOST" '
            /^[ \t]*(#|$)/ { next }
            $1 ~ /^(127\.|::1$|fe00::|ff0[0-9]::)/ { next }
            {
                own = 0
                for (i = 2; i <= NF; i++) { n = $i; sub(/\..*/, "", n); if (n == me) own = 1 }
                if (!own) print "LOW|" $0 "|hosts file maps a name to an address; check it is meant to be there"
            }' /etc/hosts >"$W/f_hosts"
        emit_flags "$W/f_hosts"
        cc_save hosts cat /etc/hosts
    fi

    # /etc/ld.so.preload makes every program load a library first.  It is
    # empty or absent on a normal system and is a classic rootkit hook.
    if [ -s /etc/ld.so.preload ] && grep -qv '^[[:space:]]*\(#\|$\)' /etc/ld.so.preload; then
        flag HIGH /etc/ld.so.preload "every program loads: $(grep -v '^[[:space:]]*#' /etc/ld.so.preload | tr '\n' ' ')- a common rootkit hook"
        cc_save ld_so_preload cat /etc/ld.so.preload
    fi
    if [ -r /proc/sys/net/ipv4/ip_forward ] && [ "$(cat /proc/sys/net/ipv4/ip_forward)" = 1 ]; then
        flag LOW ip_forward "IP forwarding is on; expected only on routers and container hosts"
    fi
    cc_save disk df -P
    cc_have free && cc_save memory free -m
}

s_users() {
    sec_csv users "user,uid,gid,home,shell,can_login,password,groups"
    F=$SEC_CSV
    if [ -r /etc/shadow ]; then
        awk -F: '{ print $1 "|" $2 }' /etc/shadow >"$W/shadow"
    else
        : >"$W/shadow"
        note "partial: /etc/shadow not readable"
    fi
    # One awk pass joins passwd, shadow and group, writes the CSV, prints flag
    # lines and two summary lines.  The password HASH is never written: only
    # its state (set, EMPTY, locked).
    awk -F: -v uidmin="$UID_MIN" -v shf="$W/shadow" -v csv="$F" -v sumf="$W/summary_lines" "$AWK_Q"'
        BEGIN {
            while ((getline l < shf) > 0) { i = index(l, "|"); sh[substr(l, 1, i - 1)] = substr(l, i + 1); hassh = 1 }
            while ((getline l < "/etc/group") > 0) {
                split(l, g, ":"); gid2name[g[3]] = g[1]
                m = split(g[4], mem, ",")
                for (j = 1; j <= m; j++) if (mem[j] != "") ug[mem[j]] = ug[mem[j]] (ug[mem[j]] == "" ? "" : " ") g[1]
            }
        }
        /^[ \t]*(#|$)/ { next }
        {
            user = $1; uid = $3; gid = $4; home = $6; shell = $7
            groups = ug[user]; pg = gid2name[gid]
            if (pg != "" && index(" " groups " ", " " pg " ") == 0) groups = pg (groups == "" ? "" : " " groups)
            login = (shell == "" || shell ~ /(nologin|false|sync|shutdown|halt)$/) ? "no" : "yes"
            pw = "unknown"
            if (hassh) {
                if (!(user in sh)) pw = "not in shadow"
                else if (sh[user] == "") pw = "EMPTY"
                else if (sh[user] ~ /^[!*]/) pw = "locked"
                else pw = "set"
            }
            if ($2 == "") pw = "EMPTY"
            else if ($2 != "x" && $2 != "*" && $2 !~ /^!/) pw = "hash in passwd"
            print q(user) "," q(uid) "," q(gid) "," q(home) "," q(shell) "," q(login) "," q(pw) "," q(groups) >> csv

            if (uid == 0 && user != "root") print "HIGH|" user "|account has UID 0, so it is a second root account"
            if (pw == "EMPTY" && login == "yes") print "HIGH|" user "|login account with an EMPTY password: anyone can log in as it"
            else if (pw == "EMPTY") print "MED|" user "|account has an empty password field"
            if (pw == "hash in passwd") print "HIGH|" user "|password hash is stored in /etc/passwd instead of /etc/shadow"
            if (++seen[uid] == 2) print "MED|UID " uid "|more than one account shares this UID"
            if (login == "yes" && uid > 0 && uid < uidmin) {
                if (user ~ /^(www-data|apache|nginx|http|httpd|nobody|daemon|bin|sys|mail|ftp|games|man|lp|news|uucp|proxy|backup|list|irc|gnats|sshd|tomcat[0-9]*|mysql|postfix|bind|named|_.*)$/)
                    print "MED|" user "|service account has a login shell (" shell "); it normally has none"
                else print "LOW|" user "|system account (UID " uid ") has a login shell (" shell ")"
            }
            if (uid != 0 && groups ~ /(^| )(docker|lxd|lxc|disk)( |$)/)
                print "MED|" user "|member of a group that is as good as root (" groups ")"
            if (login == "yes") logins = logins (logins == "" ? "" : ", ") user
            if (uid == 0 || groups ~ /(^| )(sudo|wheel|admin)( |$)/) admins = admins (admins == "" ? "" : ", ") user
        }
        END {
            print "Accounts that can log in: " (logins == "" ? "none" : logins) >> sumf
            print "Admins (UID 0 or sudo/wheel/admin group): " (admins == "" ? "none" : admins) >> sumf
        }' /etc/passwd >"$W/f_users"
    # The awk above wrote its two summary lines straight to the file; show them.
    tail -n 2 "$W/summary_lines" >"$W/users_said"
    while IFS= read -r _l; do show "$C_GRN" "  $_l"; done <"$W/users_said"
    emit_flags "$W/f_users"
}

# ---- ports ------------------------------------------------------------------
# get_listeners -> write "proto|address|port|pid|name" lines to $W/listen.
#   Tries, in order: ss, netstat, sockstat (BSD), then reads /proc/net
#   directly, which needs no tools at all.  Sets PORT_TOOL.
get_listeners() {
    : >"$W/listen"
    if cc_have ss && ss -tuln >/dev/null 2>&1; then
        PORT_TOOL=ss
        cc_save ss_listen ss -tulpn
        # Columns: Netid State Recv-Q Send-Q Local:Port Peer:Port Process
        # Process looks like users:(("sshd",pid=812,fd=3)) or, on old ss,
        # users:(("sshd",812,3)).  Only the first process is kept.
        awk '
            $1 != "tcp" && $1 != "udp" { next }
            {
                loc = $5; procs = ""
                for (i = 7; i <= NF; i++) procs = procs " " $i
                port = loc; sub(/.*:/, "", port)
                addr = loc; sub(/:[^:]*$/, "", addr); gsub(/\[|\]/, "", addr); sub(/%.*/, "", addr)
                name = ""; pid = ""
                if (match(procs, /\("[^"]*"/)) name = substr(procs, RSTART + 2, RLENGTH - 3)
                if (match(procs, /pid=[0-9]+/)) pid = substr(procs, RSTART + 4, RLENGTH - 4)
                else if (match(procs, /",[0-9]+,/)) pid = substr(procs, RSTART + 2, RLENGTH - 3)
                print $1 "|" addr "|" port "|" pid "|" name
            }' "$CC_LAST_SAVE" >"$W/listen"
    elif cc_have netstat && netstat -tuln >/dev/null 2>&1; then
        PORT_TOOL=netstat
        cc_save netstat_listen netstat -tulpn
        # Columns: Proto Recv-Q Send-Q Local Foreign [State] PID/Program
        # UDP lines have no State, so the PID/Program is taken from the last
        # field, which is "1234/sshd" or "-".
        awk '
            $1 ~ /^(tcp|udp)6?$/ {
                proto = $1; sub(/6$/, "", proto)
                loc = $4; port = loc; sub(/.*:/, "", port); addr = loc; sub(/:[^:]*$/, "", addr)
                pp = $NF; pid = ""; name = ""
                if (pp ~ /^[0-9]+\//) { pid = pp; sub(/\/.*/, "", pid); name = pp; sub(/^[0-9]+\//, "", name) }
                print proto "|" addr "|" port "|" pid "|" name
            }' "$CC_LAST_SAVE" >"$W/listen"
    elif cc_have sockstat; then
        PORT_TOOL=sockstat
        cc_save sockstat_listen sockstat -46l
        # BSD: USER COMMAND PID FD PROTO LOCAL FOREIGN
        awk '
            NR > 1 && $5 ~ /^(tcp|udp)/ {
                proto = $5; sub(/[46]+$/, "", proto)
                loc = $6; port = loc; sub(/.*:/, "", port); addr = loc; sub(/:[^:]*$/, "", addr)
                print proto "|" addr "|" port "|" $3 "|" $2
            }' "$CC_LAST_SAVE" >"$W/listen"
    elif [ -r /proc/net/tcp ]; then
        PORT_TOOL=/proc
        # No tools at all (minimal container or a box where they were
        # removed).  Map socket inodes to pids from /proc/<pid>/fd, then
        # decode /proc/net/{tcp,udp}{,6}.  State 0A = TCP LISTEN, 07 = UDP.
        ls -l /proc/[0-9]*/fd/ 2>/dev/null | awk '
            /^\/proc\/[0-9]+\/fd:$/ { pid = $0; sub(/^\/proc\//, "", pid); sub(/\/fd:$/, "", pid); next }
            /socket:\[/ { ino = $NF; gsub(/[^0-9]/, "", ino); print ino, pid }' >"$W/inodes"
        _pf=""
        for _f in /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6; do [ -r "$_f" ] && _pf="$_pf $_f"; done
        # shellcheck disable=SC2086
        awk -v inof="$W/inodes" '
            # awk, not shell (posix-ok): hex text to a number
            function hex(h,   i, n) { n = 0; h = toupper(h); for (i = 1; i <= length(h); i++) n = n * 16 + index("0123456789ABCDEF", substr(h, i, 1)) - 1; return n }   # posix-ok
            BEGIN { while ((getline l < inof) > 0) { split(l, p, " "); if (!(p[1] in own)) own[p[1]] = p[2] } }
            FNR == 1 { proto = FILENAME; sub(/.*\//, "", proto); sub(/6$/, "", proto); next }
            {
                if (proto == "tcp" && $4 != "0A") next
                if (proto == "udp" && $4 != "07") next
                split($2, la, ":"); port = hex(la[2]); a = la[1]
                if (length(a) == 8) addr = hex(substr(a, 7, 2)) "." hex(substr(a, 5, 2)) "." hex(substr(a, 3, 2)) "." hex(substr(a, 1, 2))
                else if (a ~ /^0+$/) addr = "::"
                else if (a == "00000000000000000000000001000000") addr = "::1"
                else addr = "ipv6:" a
                print proto "|" addr "|" port "|" own[$10] "|"
            }' $_pf >"$W/listen"
    else
        PORT_TOOL=none
        cc_have netstat && cc_save netstat_an netstat -an
    fi
    sort -u "$W/listen" -o "$W/listen" 2>/dev/null
    cc_debug "ports: tool=$PORT_TOOL, $(wc -l <"$W/listen" | tr -d ' ') listeners"
}

s_ports() {
    sec_csv ports "proto,address,port,exposure,pid,process,user,program"
    F=$SEC_CSV
    get_listeners
    [ "$PORT_TOOL" = none ] && { note "no ss, netstat, sockstat or /proc/net: see raw/"; say "Listening ports: could not be read on this OS (see raw/netstat_an.txt)"; return 0; }
    [ "$IS_ROOT" = 1 ] || note "partial: process shown only for your own sockets"
    if [ "$PORT_TOOL" = /proc ] && [ ! -s "$W/inodes" ]; then note "process unknown: /proc/<pid>/fd is not readable here"; fi
    : >"$W/any"; : >"$W/loc"
    while IFS='|' read -r proto addr port pid name; do
        [ -n "$port" ] || continue
        exe=""; user=""
        if [ -n "$pid" ] && [ -d "/proc/$pid" ]; then
            exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
            [ -n "$name" ] || name=$(cat "/proc/$pid/comm" 2>/dev/null)
            user=$(owner_of "/proc/$pid")
        fi
        case "$addr" in
            127.*|::1|localhost|::ffff:127.*) exposure=local; printf '%s/%s %s\n' "$proto" "$port" "$name" >>"$W/loc" ;;
            *) exposure=any; printf '%s/%s %s\n' "$proto" "$port" "$name" >>"$W/any" ;;
        esac
        cc_csv_row "$F" "$proto" "$addr" "$port" "$exposure" "$pid" "$name" "$user" "$exe"

        _it="$proto/$port"
        case "$exe" in *" (deleted)") flag HIGH "$_it" "listener's program file was deleted after it started ($exe, pid $pid): typical of malware" ;; esac
        if printf '%s' "$exe" | grep -Eq "$TMP_RE"; then flag HIGH "$_it" "listener runs from a temp folder ($exe, pid $pid)"; fi
        if printf '%s' "$name" | grep -Eq "$SHELLS_RE"; then flag HIGH "$_it" "a shell ($name, pid $pid) is listening on the network: bind shell"; fi
        if printf '%s' "$name" | grep -Eq "$NETCAT_RE"; then flag HIGH "$_it" "$name is listening (pid $pid): netcat-style backdoor"; fi
        case "$name" in python*|perl|php*|ruby*) flag MED "$_it" "an interpreter ($name, pid $pid) is listening; confirm it is a real service" ;; esac
        case "$port" in
            2375) flag HIGH "$_it" "Docker API without TLS: anyone who can reach it is root on this host" ;;
            23) [ "$proto" = tcp ] && flag MED "$_it" "Telnet-style cleartext login service ($name)" ;;
            512|513|514) [ "$proto" = tcp ] && flag MED "$_it" "rsh/rlogin/rexec-style cleartext service ($name)" ;;
            69) [ "$proto" = udp ] && flag MED "$_it" "TFTP: no authentication, files can be read by guessing names" ;;
            1337|4444|4445|5555|6666|6667|12345|31337|54321) flag MED "$_it" "port commonly used by backdoors and reverse shells ($name)" ;;
            590[0-9]) [ "$proto" = tcp ] && flag MED "$_it" "VNC remote desktop ($name); check it requires a password" ;;
        esac
    done <"$W/listen"
    _any=$(sort -u "$W/any" | awk '{ printf "%s%s", sep, $0; sep = ", " }')
    _loc=$(sort -u "$W/loc" | awk '{ printf "%s%s", sep, $0; sep = ", " }')
    say "Listening on the network: ${_any:-none}"
    say "Listening on this host only: ${_loc:-none}"
}

s_services() {
    sec_csv services "name,enabled,active,state,description,manager"
    F=$SEC_CSV
    case "$CC_INIT" in
        systemd)
            systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null | awk '{ print $1 "|" $2 }' >"$W/unitfiles"
            systemctl list-units --type=service --all --no-legend --no-pager 2>/dev/null >"$W/units"
            cc_save systemd_units cat "$W/units"
            # Old systemd prefixes failed units with a bullet character and
            # has no --plain option, so anything before the unit name is cut.
            awk -v uf="$W/unitfiles" "$AWK_Q"'
                BEGIN { while ((getline l < uf) > 0) { i = index(l, "|"); en[substr(l, 1, i - 1)] = substr(l, i + 1) } }
                {
                    sub(/^[^A-Za-z0-9@_.:-]+/, "")
                    desc = ""; for (i = 5; i <= NF; i++) desc = desc (i > 5 ? " " : "") $i
                    print q($1) "," q(en[$1]) "," q($3) "," q($4) "," q(desc) ",\"systemd\""
                }' "$W/units" >>"$F"
            # Unit files that run something suspicious.  ExecStart, ExecStartPre,
            # ExecStop ... in every unit folder, including drop-in overrides.
            : >"$W/execs"
            for _d in /etc/systemd/system /run/systemd/system /usr/local/lib/systemd/system /usr/lib/systemd/system /lib/systemd/system; do
                [ -d "$_d" ] && grep -rEn '^[[:space:]]*Exec[A-Za-z]*=' "$_d" 2>/dev/null >>"$W/execs"
            done
            grep -E "$SUSP_STRONG" "$W/execs" >"$W/execs_hi"
            while IFS= read -r _l; do flag HIGH "${_l%%:*}" "unit runs a suspicious command: ${_l#*=}"; done <"$W/execs_hi"
            grep -E '=[-@+!:]*(/tmp/|/var/tmp/|/dev/shm/)' "$W/execs" | grep -vE "$SUSP_STRONG" >"$W/execs_med"
            while IFS= read -r _l; do flag MED "${_l%%:*}" "unit runs a program from a temp folder: ${_l#*=}"; done <"$W/execs_med"
            # Service files written directly into /etc/systemd/system (not a
            # symlink to a packaged unit) are local additions: legitimate ones
            # exist, but this is also where a red team drops a new service.
            for _u in /etc/systemd/system/*.service /etc/systemd/system/*/*.service; do
                [ -f "$_u" ] && [ ! -h "$_u" ] && flag LOW "$_u" "service unit created locally (not from a package)"
            done
            ;;
        openrc)
            cc_save rc_status rc-status --all
            awk "$AWK_Q"'$2 == "[" { print q($1) ",\"\"," q($3) ",\"\",\"\",\"openrc\"" }' "$CC_LAST_SAVE" >>"$F"
            ;;
        rc)
            cc_save service_enabled service -e
            awk "$AWK_Q"'/^\// { n = $0; sub(/.*\//, "", n); print q(n) ",\"enabled\",\"\",\"\",\"\",\"rc\"" }' "$CC_LAST_SAVE" >>"$F"
            ;;
        smf)
            cc_save svcs svcs -a
            awk "$AWK_Q"'NR > 1 { print q($3) ",\"\"," q($1) ",\"\",\"\",\"smf\"" }' "$CC_LAST_SAVE" >>"$F"
            ;;
        *)
            if cc_have service; then
                cc_save service_status service --status-all
                # Lines look like " [ + ]  ssh" (running) or " [ - ]  cups".
                awk "$AWK_Q"'$1 == "[" { st = ($2 == "+") ? "active" : ($2 == "-" ? "inactive" : "unknown"); print q($4) ",\"\"," q(st) ",\"\",\"\",\"sysv\"" }' "$CC_LAST_SAVE" >>"$F"
            else
                for _s in /etc/init.d/*; do [ -f "$_s" ] && cc_csv_row "$F" "$(basename "$_s")" "" "" "" "" "init.d"; done
                note "no service manager found; listed /etc/init.d only"
            fi
            ;;
    esac
    _run=$(awk -F'","' 'NR > 1 && $3 == "active" { n++ } END { print n + 0 }' "$F")
    _all=$(($(wc -l <"$F") - 1))
    say "Services: $_all listed, $_run running"
}

s_autostart() {
    sec_csv autostart "source,user,entry"
    F=$SEC_CSV
    : >"$W/auto"     # lines: source|user|entry
    # 1. System crontabs: the 6th field is the user (or the 2nd after @reboot).
    for _f in /etc/crontab /etc/cron.d/*; do
        [ -f "$_f" ] || continue
        awk -v src="$_f" '
            /^[ \t]*(#|$)/ { next }
            /^[ \t]*[A-Za-z_][A-Za-z0-9_]*[ \t]*=/ { next }
            {
                if ($1 ~ /^@/) { user = $2; s = 3; sched = $1 } else { user = $6; s = 7; sched = $1 " " $2 " " $3 " " $4 " " $5 }
                cmd = ""; for (i = s; i <= NF; i++) cmd = cmd (i > s ? " " : "") $i
                print src "|" user "|" sched " " cmd
            }' "$_f" >>"$W/auto"
    done
    # 2. Per-user crontabs (Debian, Red Hat, BSD locations).  The file name is
    #    the user.
    for _d in /var/spool/cron/crontabs /var/spool/cron /var/cron/tabs; do
        [ -d "$_d" ] || continue
        for _f in "$_d"/*; do
            [ -f "$_f" ] || continue
            awk -v src="$_f" -v u="$(basename "$_f")" '
                /^[ \t]*(#|$)/ { next }
                /^[ \t]*[A-Za-z_][A-Za-z0-9_]*[ \t]*=/ { next }
                { print src "|" u "|" $0 }' "$_f" >>"$W/auto"
        done
    done
    [ "$IS_ROOT" = 1 ] || note "partial: user crontabs need root"
    # 3. run-parts folders: list each script, and check what is inside it.
    for _d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/periodic/daily /etc/periodic/hourly; do
        [ -d "$_d" ] || continue
        for _f in "$_d"/*; do
            [ -f "$_f" ] || continue
            printf '%s|root|script %s\n' "$_d" "$_f" >>"$W/auto"
            grep -En "$SUSP_STRONG" "$_f" 2>/dev/null >"$W/cronscript" && flag HIGH "$_f" "cron script contains: $(head -n 1 "$W/cronscript")"
        done
    done
    # 4. anacron, at, systemd timers.
    [ -f /etc/anacrontab ] && awk '/^[ \t]*(#|$)/ { next } /=/ { next } { print "/etc/anacrontab|root|" $0 }' /etc/anacrontab >>"$W/auto"
    if cc_have atq; then
        atq 2>/dev/null | awk '{ print "at|" $NF "|job " $0 }' >>"$W/auto"
    fi
    for _d in /var/spool/cron/atjobs /var/spool/at /var/at/jobs; do
        [ -d "$_d" ] || continue
        for _f in "$_d"/*; do
            [ -f "$_f" ] || continue
            grep -En "$SUSP_STRONG" "$_f" >/dev/null 2>&1 && flag HIGH "$_f" "queued 'at' job contains a suspicious command"
        done
    done
    if [ "$CC_INIT" = systemd ]; then
        systemctl list-timers --all --no-legend --no-pager 2>/dev/null | awk '{ print "systemd timer|root|" $0 }' >>"$W/auto"
    fi
    # 5. rc.local runs as root at boot and is unused on most modern systems,
    #    so every command in it is flagged for a look.
    for _f in /etc/rc.local /etc/rc.d/rc.local; do
        [ -f "$_f" ] || continue
        awk -v src="$_f" '/^[ \t]*(#|$)/ { next } /^[ \t]*exit[ \t]+0[ \t]*$/ { next } { print src "|root|" $0 }' "$_f" >"$W/rclocal"
        cat "$W/rclocal" >>"$W/auto"
        while IFS='|' read -r _s _u _e; do flag MED "$_s" "runs at boot as root: $_e"; done <"$W/rclocal"
    done
    # 6. Shell startup files, motd scripts and udev rules: only lines that
    #    look like a backdoor are recorded, because these files are long.
    : >"$W/startup"
    for _f in /etc/profile /etc/profile.d/*.sh /etc/bash.bashrc /etc/bashrc /etc/environment /etc/zsh/zshrc \
              /root/.bashrc /root/.profile /root/.bash_profile /home/*/.bashrc /home/*/.profile /home/*/.bash_profile \
              /etc/update-motd.d/* /etc/udev/rules.d/*.rules; do
        [ -f "$_f" ] || continue
        grep -En "$SUSP_STRONG" "$_f" 2>/dev/null | awk -v src="$_f" '{ print src "|-|" $0 }' >>"$W/startup"
    done
    cat "$W/startup" >>"$W/auto"
    while IFS='|' read -r _s _u _e; do flag HIGH "$_s" "startup file runs a suspicious command (line $_e)"; done <"$W/startup"

    # Write everything, then flag the cron/at/timer entries by pattern.
    while IFS='|' read -r _s _u _e; do cc_csv_row "$F" "$_s" "$_u" "$_e"; done <"$W/auto"
    grep -E "$SUSP_STRONG" "$W/auto" | grep -v '^/etc/rc' | grep -vF -f "$W/startup" >"$W/auto_hi" 2>/dev/null
    while IFS='|' read -r _s _u _e; do flag HIGH "$_s" "scheduled job for $_u runs a suspicious command: $_e"; done <"$W/auto_hi"
    grep -E "$SUSP_WEAK" "$W/auto" | grep -vE "$SUSP_STRONG" | grep -v '^/etc/rc' >"$W/auto_med" 2>/dev/null
    while IFS='|' read -r _s _u _e; do flag MED "$_s" "scheduled job for $_u is worth a look: $_e"; done <"$W/auto_med"
    _n=$(grep -cv '^systemd timer|' "$W/auto")
    say "Scheduled and startup entries: $_n (cron, at, rc.local, startup files), plus systemd timers"
}

s_ssh() {
    sec_csv ssh_config "setting,value,source"
    F=$SEC_CSV
    : >"$W/sshd"
    # 'sshd -T' prints the settings sshd really uses after every Include and
    # default, but needs root.  Otherwise read the files ourselves: for most
    # settings OpenSSH keeps the FIRST value it sees, and Match blocks apply
    # only to some connections, so reading stops at the first Match.
    if [ "$IS_ROOT" = 1 ] && cc_have sshd && sshd -T >"$W/sshd" 2>/dev/null; then
        _src="sshd -T (effective)"
        cc_save sshd_T cat "$W/sshd"
    elif [ -r /etc/ssh/sshd_config ]; then
        _src="/etc/ssh/sshd_config (read from file)"
        : >"$W/sshd_raw"
        while IFS= read -r _line; do
            case "$_line" in
                [Ii]nclude*)
                    for _g in $(printf '%s\n' "$_line" | awk '{ for (i = 2; i <= NF; i++) print $i }'); do
                        case "$_g" in /*) ;; *) _g="/etc/ssh/$_g" ;; esac
                        for _inc in $_g; do [ -f "$_inc" ] && cat "$_inc" >>"$W/sshd_raw"; done
                    done ;;
                *) printf '%s\n' "$_line" >>"$W/sshd_raw" ;;
            esac
        done </etc/ssh/sshd_config
        awk '/^[ \t]*#/ || NF == 0 { next } tolower($1) == "match" { exit }
             { k = tolower($1); if (!(k in seen)) { seen[k] = 1; v = $2; for (i = 3; i <= NF; i++) v = v " " $i; print k " " v } }' "$W/sshd_raw" >"$W/sshd"
        cc_save sshd_config cat "$W/sshd_raw"
    else
        note "no sshd configuration found"
        _src=""
    fi
    if [ -s "$W/sshd" ]; then
        awk -v src="$_src" "$AWK_Q"'
            $1 ~ /^(port|listenaddress|permitrootlogin|passwordauthentication|permitemptypasswords|pubkeyauthentication|authorizedkeysfile|authorizedkeyscommand|authorizedprincipalsfile|usepam|allowusers|allowgroups|denyusers|denygroups|x11forwarding|gatewayports|permittunnel|kbdinteractiveauthentication|challengeresponseauthentication|maxauthtries|permituserenvironment)$/ {
                v = $2; for (i = 3; i <= NF; i++) v = v " " $i
                print q($1) "," q(v) "," q(src)
            }' "$W/sshd" >>"$F"
        _get() { awk -v k="$1" '$1 == k { $1 = ""; sub(/^ /, ""); print; exit }' "$W/sshd"; }
        [ "$(_get permitemptypasswords)" = yes ] && flag HIGH PermitEmptyPasswords "sshd lets accounts with an empty password log in"
        [ "$(_get permitrootlogin)" = yes ] && flag MED PermitRootLogin "root can log in over SSH with a password"
        [ "$(_get permituserenvironment)" = yes ] && flag MED PermitUserEnvironment "users can set environment variables at login (LD_PRELOAD tricks)"
        _akc=$(_get authorizedkeyscommand)
        [ -n "$_akc" ] && [ "$_akc" != none ] && flag MED AuthorizedKeysCommand "sshd asks a program for allowed keys: $_akc"
        AKF=$(_get authorizedkeysfile)
        for _t in $AKF; do
            case "$_t" in
                .ssh/authorized_keys|.ssh/authorized_keys2|%h/.ssh/authorized_keys|%h/.ssh/authorized_keys2) ;;
                *) flag HIGH AuthorizedKeysFile "sshd also reads keys from '$_t'; a moved key file is a common way to hide a backdoor key" ;;
            esac
        done
        say "SSH: root login '$(_get permitrootlogin)', password login '$(_get passwordauthentication)', port(s) $(awk '$1 == "port" { printf "%s ", $2 }' "$W/sshd")"
    fi

    # Every authorized_keys file for every account, including system
    # accounts: a key on www-data or nobody is a favourite red team backdoor.
    sec_csv ssh_keys "user,uid,file,line,type,fingerprint,comment,options,file_owner,file_mode"
    K=$SEC_CSV
    home_dirs
    : >"$W/keyfiles"
    while IFS='|' read -r _user _uid _home; do
        for _kf in "$_home/.ssh/authorized_keys" "$_home/.ssh/authorized_keys2"; do
            [ -f "$_kf" ] && printf '%s|%s|%s\n' "$_user" "$_uid" "$_kf" >>"$W/keyfiles"
        done
        for _t in $AKF; do
            case "$_t" in /*)
                _kf=$(printf '%s' "$_t" | sed "s|%u|$_user|g; s|%h|$_home|g; s|%%|%|g")
                [ -f "$_kf" ] && printf '%s|%s|%s\n' "$_user" "$_uid" "$_kf" >>"$W/keyfiles" ;;
            esac
        done
    done <"$W/homes"
    sort -u "$W/keyfiles" -o "$W/keyfiles"
    _nkeys=0
    while IFS='|' read -r _user _uid _kf; do
        _ow=$(owner_of "$_kf"); _md=$(mode_of "$_kf")
        case "$_md" in ????????w*|?????w????*) flag HIGH "$_kf" "key file can be changed by other users ($_md); anyone could add a key" ;; esac
        [ "$_ow" != "$_user" ] && [ "$_ow" != root ] && flag HIGH "$_kf" "key file is owned by $_ow, not $_user"
        # Each key line: [options] type base64 [comment].  The type is found
        # by its name, because options may come first.
        awk '
            /^[ \t]*(#|$)/ { next }
            {
                t = 0
                for (i = 1; i <= NF; i++) if ($i ~ /^(ssh-|ecdsa-|sk-)/) { t = i; break }
                if (!t) next
                opts = ""; for (i = 1; i < t; i++) opts = opts (i > 1 ? " " : "") $i
                cm = ""; for (i = t + 2; i <= NF; i++) cm = cm (i > t + 2 ? " " : "") $i
                print NR "|" $t "|" $(t + 1) "|" cm "|" opts
            }' "$_kf" >"$W/keys1"
        while IFS='|' read -r _ln _type _key _cm _opts; do
            _nkeys=$((_nkeys + 1))
            _fp=""
            if cc_have ssh-keygen; then
                printf '%s %s\n' "$_type" "$_key" >"$W/onekey"
                _fp=$(ssh-keygen -lf "$W/onekey" 2>/dev/null | awk '{ print $2 }')
            fi
            cc_csv_row "$K" "$_user" "$_uid" "$_kf" "$_ln" "$_type" "$_fp" "$_cm" "$_opts" "$_ow" "$_md"
            case "$_opts" in *command=*) flag LOW "$_user" "key in $_kf line $_ln runs a forced command: $_opts" ;; esac
        done <"$W/keys1"
        _cnt=$(wc -l <"$W/keys1" | tr -d ' ')
        [ "$_cnt" -gt 0 ] || continue
        if [ "$_uid" = 0 ]; then
            flag MED "$_user" "root accepts $_cnt SSH key(s) from $_kf; confirm every one is yours"
        elif [ "$_uid" -lt "$UID_MIN" ]; then
            flag HIGH "$_user" "service account has $_cnt SSH key(s) in $_kf; service accounts should have none"
        fi
    done <"$W/keyfiles"
    say "SSH keys: $_nkeys key(s) in $(wc -l <"$W/keyfiles" | tr -d ' ') authorized_keys file(s)"
}

s_sudo() {
    sec_csv sudo "file,line,entry"
    F=$SEC_CSV
    if [ ! -r /etc/sudoers ] && [ -e /etc/sudoers ]; then
        note "partial: sudoers needs root"
    fi
    : >"$W/sudo"
    _files=""
    [ -f /etc/sudoers ] && _files="/etc/sudoers"
    # Files pulled in with #includedir / @includedir (the '#' is NOT a
    # comment there - a classic place to hide an extra rule).
    for _d in /etc/sudoers.d $(awk '$1 ~ /^[#@]includedir$/ { print $2 }' /etc/sudoers 2>/dev/null); do
        [ -d "$_d" ] && for _f in "$_d"/*; do [ -f "$_f" ] && _files="$_files $_f"; done
    done
    for _f in $(awk '$1 ~ /^[#@]include$/ { print $2 }' /etc/sudoers 2>/dev/null); do [ -f "$_f" ] && _files="$_files $_f"; done
    for _f in $_files; do
        _md=$(mode_of "$_f"); _ow=$(owner_of "$_f")
        case "$_md" in ?????w????*|????????w*) flag HIGH "$_f" "sudoers file can be changed by non-root users ($_md)" ;; esac
        [ "$_ow" != root ] && flag HIGH "$_f" "sudoers file is owned by $_ow, not root"
        awk -v src="$_f" '
            /^[ \t]*$/ { next }
            /^[ \t]*[#@]include/ { print src "|" NR "|" $0; next }
            /^[ \t]*#/ { next }
            { print src "|" NR "|" $0 }' "$_f" 2>/dev/null >>"$W/sudo"
    done
    while IFS='|' read -r _s _n _e; do cc_csv_row "$F" "$_s" "$_n" "$_e"; done <"$W/sudo"
    awk -F'|' '
        $3 ~ /NOPASSWD/ && $3 !~ /^[ \t]*Defaults/ { print "MED|" $1 ":" $2 "|passwordless sudo: " $3 }
        $3 ~ /!authenticate/ { print "HIGH|" $1 ":" $2 "|authentication is switched off for sudo: " $3 }
        $3 ~ /env_keep/ && $3 ~ /LD_PRELOAD|LD_LIBRARY_PATH/ { print "HIGH|" $1 ":" $2 "|sudo keeps LD_PRELOAD/LD_LIBRARY_PATH, which lets a user run code as root: " $3 }
        $3 ~ /^[ \t]*%/ && $3 ~ /ALL[ \t]*$/ && $3 !~ /^[ \t]*%(sudo|wheel|admin|root)[ \t]/ { print "MED|" $1 ":" $2 "|a group gets full sudo: " $3 }
        $3 ~ /^[ \t]*[A-Za-z0-9_.-]+[ \t]+[^=]*=/ && $3 !~ /NOPASSWD/ && $3 !~ /^[ \t]*(root|Defaults|Cmnd_Alias|User_Alias|Host_Alias|Runas_Alias)[ \t]/ { print "LOW|" $1 ":" $2 "|sudo rule for a single user: " $3 }
    ' "$W/sudo" >"$W/f_sudo"
    emit_flags "$W/f_sudo"
    for _f in /etc/doas.conf /usr/local/etc/doas.conf; do
        [ -f "$_f" ] || continue
        awk -v src="$_f" '/^[ \t]*(#|$)/ { next } { print src "|" NR "|" $0 }' "$_f" >"$W/doas"
        while IFS='|' read -r _s _n _e; do
            cc_csv_row "$F" "$_s" "$_n" "$_e"
            case "$_e" in *nopass*) flag MED "$_s:$_n" "passwordless doas: $_e" ;; esac
        done <"$W/doas"
    done
    for _f in /etc/polkit-1/rules.d/*.rules /etc/polkit-1/localauthority/*/*.pkla; do
        [ -f "$_f" ] || continue
        cc_csv_row "$F" "$_f" "" "polkit rule file"
        if grep -q 'Result.YES' "$_f" 2>/dev/null; then flag MED "$_f" "polkit rule grants actions without a password"
        else flag LOW "$_f" "local polkit rule; check what it allows"; fi
    done
    _ver=$(sudo -V 2>/dev/null | head -n 1)
    [ -n "$_ver" ] && cc_csv_row "$F" "sudo -V" "" "$_ver"
    say "sudo: $(grep -c . "$W/sudo") rule line(s); ${_ver:-sudo not installed}"
}

s_processes() {
    sec_csv processes "pid,ppid,user,elapsed,program,command"
    F=$SEC_CSV
    # Normalise every ps flavour to "pid|ppid|user|elapsed|command".
    : >"$W/ps"
    if [ "$CC_OS_FAMILY" = bsd ] && ps -axo pid=,ppid=,user=,etime=,args= >"$W/ps0" 2>/dev/null; then :
    elif ps -eo pid=,ppid=,user=,etime=,args= >"$W/ps0" 2>/dev/null && [ -s "$W/ps0" ]; then :
    elif ps -o pid,ppid,user,args >"$W/ps1" 2>/dev/null && [ -s "$W/ps1" ]; then
        awk 'NR > 1 { a = ""; for (i = 4; i <= NF; i++) a = a (i > 4 ? " " : "") $i; print $1, $2, $3, "-", a }' "$W/ps1" >"$W/ps0"
    else
        ps -ef 2>/dev/null | awk 'NR > 1 { a = ""; for (i = 8; i <= NF; i++) a = a (i > 8 ? " " : "") $i; print $2, $3, $1, "-", a }' >"$W/ps0"
    fi
    awk '$1 ~ /^[0-9]+$/ { a = ""; for (i = 5; i <= NF; i++) a = a (i > 5 ? " " : "") $i; print $1 "|" $2 "|" $3 "|" $4 "|" a }' "$W/ps0" >"$W/ps"
    # Program file of every process, in one 'ls' instead of one readlink per
    # process.  Lines look like ".../proc/123/exe -> /usr/bin/foo".
    : >"$W/exe"
    if [ -d /proc/1 ]; then
        ls -l /proc/[0-9]*/exe 2>/dev/null | awk '
            { i = index($0, " -> "); if (!i) next
              p = substr($0, 1, i - 1); sub(/.* \/proc\//, "", p); sub(/\/exe$/, "", p)
              print p "|" substr($0, i + 4) }' >"$W/exe"
    fi
    [ "$IS_ROOT" = 1 ] || note "partial: program files of other users' processes are hidden"
    awk -F'|' -v exef="$W/exe" -v csv="$F" "$AWK_Q"'
        BEGIN { while ((getline l < exef) > 0) { i = index(l, "|"); exe[substr(l, 1, i - 1)] = substr(l, i + 1) } }
        {
            pid = $1; user = $3; cmd = $5; for (i = 6; i <= NF; i++) cmd = cmd "|" $i
            e = exe[pid]
            print q(pid) "," q($2) "," q(user) "," q($4) "," q(e) "," q(cmd) >> csv
            split(cmd, w, " "); base = w[1]; sub(/.*\//, "", base); sub(/:$/, "", base)
            it = "pid " pid " (" base ")"
            if (e ~ / \(deleted\)$/) print "HIGH|" it "|running from a program file that has been deleted (" e "); typical of malware"
            if (e ~ /^(\/tmp|\/var\/tmp|\/dev\/shm|\/run\/shm)\// || w[1] ~ /^(\/tmp|\/var\/tmp|\/dev\/shm)\//) print "HIGH|" it "|running from a temp folder: " (e != "" ? e : w[1])
            if (cmd ~ /^\[.*\]$/ && e != "") print "HIGH|" it "|named like a kernel thread " cmd " but has a program file (" e "): a disguised process"
            if (cmd ~ /(\/dev\/tcp\/|\/dev\/udp\/|bash -i|sh -i|nc .*-e |ncat .*-e|socat .*exec|mkfifo|base64 -d|base64 --decode|python[0-9.]* -c|perl -e|php -r|ruby -e)/) print "HIGH|" it "|command line looks like a reverse shell or encoded payload: " cmd
            if (base ~ /^(nc|ncat|netcat|nc\.traditional|nc\.openbsd|socat|cryptcat|pwncat|gs-netcat)$/) print "MED|" it "|netcat-style tool running: " cmd
            if (base ~ /^(chisel|ligolo|ligolo-ng|frpc|frps|gost|rsocx|pspy|pspy64|linpeas\.sh|reptile)$/) print "HIGH|" it "|known attack tool running: " cmd
            if (user ~ /^(www-data|apache|nginx|http|httpd|nobody|tomcat[0-9]*)$/ && base ~ /^(sh|bash|dash|zsh|ksh|python[0-9.]*|perl|nc|ncat|socat)$/) print "HIGH|" it "|a shell or interpreter is running as the web/service user " user ": possible webshell"
            n++; if (user == "root") nr++
        }
        END { print "SUMMARY|" n "|" nr }' "$W/ps" >"$W/f_proc"
    _sum=$(grep '^SUMMARY|' "$W/f_proc")
    grep -v '^SUMMARY|' "$W/f_proc" >"$W/f_proc2"
    emit_flags "$W/f_proc2"
    _n=$(printf '%s' "$_sum" | cut -d'|' -f2); _r=$(printf '%s' "$_sum" | cut -d'|' -f3)
    say "Processes: ${_n:-0} running, ${_r:-0} as root"
}

s_connections() {
    sec_csv connections "proto,state,local,remote,pid,process"
    F=$SEC_CSV
    : >"$W/conn"
    if cc_have ss && ss -tun >/dev/null 2>&1; then
        cc_save ss_conn ss -tunp
        awk '
            $1 != "tcp" && $1 != "udp" { next }
            $2 == "LISTEN" || $2 == "UNCONN" { next }
            {
                procs = ""; for (i = 7; i <= NF; i++) procs = procs " " $i
                name = ""; pid = ""
                if (match(procs, /\("[^"]*"/)) name = substr(procs, RSTART + 2, RLENGTH - 3)
                if (match(procs, /pid=[0-9]+/)) pid = substr(procs, RSTART + 4, RLENGTH - 4)
                print $1 "|" $2 "|" $5 "|" $6 "|" pid "|" name
            }' "$CC_LAST_SAVE" >"$W/conn"
    elif cc_have netstat; then
        cc_save netstat_conn netstat -tunp
        awk '
            $1 ~ /^(tcp|udp)6?$/ && $6 != "LISTEN" {
                proto = $1; sub(/6$/, "", proto)
                st = ($1 ~ /^udp/) ? "-" : $6
                pp = $NF; pid = ""; name = ""
                if (pp ~ /^[0-9]+\//) { pid = pp; sub(/\/.*/, "", pid); name = pp; sub(/^[0-9]+\//, "", name) }
                print proto "|" st "|" $4 "|" $5 "|" pid "|" name
            }' "$CC_LAST_SAVE" >"$W/conn"
    elif cc_have sockstat; then
        cc_save sockstat_conn sockstat -46c
        awk 'NR > 1 && $5 ~ /^(tcp|udp)/ { p = $5; sub(/[46]+$/, "", p); print p "|-|" $6 "|" $7 "|" $3 "|" $2 }' "$CC_LAST_SAVE" >"$W/conn"
    else
        note "no ss, netstat or sockstat"
        cat /proc/net/tcp /proc/net/tcp6 >"$W/proc_net" 2>/dev/null && cc_save proc_net_tcp cat "$W/proc_net"
    fi
    while IFS='|' read -r _p _s _l _r _pid _name; do
        cc_csv_row "$F" "$_p" "$_s" "$_l" "$_r" "$_pid" "$_name"
        _rp=${_r##*:}
        if printf '%s' "$_name" | grep -Eq "$SHELLS_RE|$NETCAT_RE"; then
            flag HIGH "$_name pid $_pid" "a shell or netcat has a live connection to $_r: reverse shell?"
        fi
        case "$_rp" in 1337|4444|4445|5555|6666|6667|12345|31337|54321) flag MED "$_r" "connection to a port commonly used by reverse shells ($_name pid $_pid)" ;; esac
    done <"$W/conn"
    _est=$(grep -c '|ESTAB' "$W/conn")
    _peers=$(awk -F'|' '$2 ~ /^ESTAB/ { r = $4; sub(/:[^:]*$/, "", r); gsub(/\[|\]/, "", r); if (r !~ /^(127\.|::1$)/) c[r]++ }
        END { for (k in c) print c[k], k }' "$W/conn" | sort -rn | head -n 5 | awk '{ printf "%s%s (%s)", sep, $2, $1; sep = ", " }')
    say "Connections: $_est established; busiest remote addresses: ${_peers:-none}"
}

s_sessions() {
    sec_csv sessions "user,terminal,from,since"
    F=$SEC_CSV
    if cc_have who; then
        who >"$W/who" 2>/dev/null
        awk "$AWK_Q"'{
            from = ""; if (match($0, /\(.*\)/)) from = substr($0, RSTART + 1, RLENGTH - 2)
            print q($1) "," q($2) "," q(from) "," q($3 " " $4)
        }' "$W/who" >>"$F"
        _now=$(awk '{ from = ""; if (match($0, /\(.*\)/)) from = " from " substr($0, RSTART + 1, RLENGTH - 2); printf "%s%s%s", sep, $1, from; sep = ", " }' "$W/who")
        say "Logged in now: ${_now:-nobody}"
    fi
    cc_have w && cc_save w w
    cc_have last && cc_save last last -n 50
    [ "$IS_ROOT" = 1 ] && cc_have lastb && cc_save lastb_failed lastb -n 50
}

s_packages() {
    sec_csv packages "name,version,manager"
    F=$SEC_CSV
    if cc_have dpkg-query; then
        dpkg-query -W -f='${Package}|${Version}|${Status}\n' 2>/dev/null | awk -F'|' "$AWK_Q"'$3 ~ /installed$/ { print q($1) "," q($2) ",\"dpkg\"" }' >>"$F"
    elif cc_have rpm; then
        rpm -qa --qf '%{NAME}|%{VERSION}-%{RELEASE}\n' 2>/dev/null | awk -F'|' "$AWK_Q"'{ print q($1) "," q($2) ",\"rpm\"" }' >>"$F"
    elif cc_have apk; then
        apk info -v 2>/dev/null | awk "$AWK_Q"'{ n = $0; v = $0; sub(/-[0-9].*/, "", n); sub(/^.*-([0-9])/, "\\1", v); print q(n) "," q(substr($0, length(n) + 2)) ",\"apk\"" }' >>"$F"
    elif cc_have pacman; then
        pacman -Q 2>/dev/null | awk "$AWK_Q"'{ print q($1) "," q($2) ",\"pacman\"" }' >>"$F"
    elif cc_have pkg && [ "$CC_OS_FAMILY" = bsd ]; then
        pkg query '%n|%v' 2>/dev/null | awk -F'|' "$AWK_Q"'{ print q($1) "," q($2) ",\"pkg\"" }' >>"$F"
    elif cc_have pkginfo; then
        cc_save pkginfo pkginfo
        note "Solaris: package names only (see raw/pkginfo.txt)"
    else
        note "no package manager found"
    fi
    say "Packages installed: $(($(wc -l <"$F") - 1))"
}

s_files() {
    # Searches start at each of these and stay on that filesystem (-xdev),
    # so network mounts and /proc are never walked.  Separate partitions such
    # as /home are listed explicitly so they are still covered.
    _roots=""
    for _r in / /usr /var /home /opt /srv /tmp /root /boot; do [ -d "$_r" ] && _roots="$_roots $_r"; done
    [ "$IS_ROOT" = 1 ] || note "partial: unreadable folders skipped"

    sec_csv suid "path,mode,owner,group,kind,risky_program"
    F=$SEC_CSV
    # shellcheck disable=SC2086
    for _r in $_roots; do find "$_r" -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null; done | sort -u >"$W/suid"
    while IFS= read -r _p; do
        _ls=$(ls -ld "$_p" 2>/dev/null) || continue
        _md=$(printf '%s' "$_ls" | awk '{ print $1 }'); _ow=$(printf '%s' "$_ls" | awk '{ print $3 }'); _gr=$(printf '%s' "$_ls" | awk '{ print $4 }')
        _kind=""
        case "$_md" in ???[sS]*) _kind=suid ;; esac
        case "$_md" in ??????[sS]*) _kind="${_kind:+$_kind+}sgid" ;; esac
        _base=$(basename "$_p" | sed 's/[0-9.]*$//')
        _gtfo=no
        case "$GTFO" in *" $_base "*) _gtfo=yes ;; esac
        cc_csv_row "$F" "$_p" "$_md" "$_ow" "$_gr" "$_kind" "$_gtfo"
        if printf '%s' "$_p" | grep -Eq '^(/tmp|/var/tmp|/dev/shm|/home|/root|/var/www|/srv|/opt)/'; then
            flag HIGH "$_p" "SUID/SGID program in a place where none belong ($_md)"
        elif [ "$_gtfo" = yes ]; then
            case "$_kind" in *suid*) flag HIGH "$_p" "SUID is set on $_base, which can be used to get a root shell" ;; esac
        fi
        case "$_kind" in *suid*) [ "$_ow" != root ] && flag MED "$_p" "SUID program owned by $_ow" ;; esac
    done <"$W/suid"
    say "SUID/SGID programs: $(wc -l <"$W/suid" | tr -d ' ')"

    # File capabilities: cap_setuid on an interpreter is as good as SUID root.
    if cc_have getcap; then
        sec_csv capabilities "path,capabilities"
        C=$SEC_CSV
        : >"$W/caps"
        for _r in /usr /bin /sbin /lib /lib64 /opt /home /tmp /var /srv /root; do
            [ -d "$_r" ] && getcap -r "$_r" 2>/dev/null >>"$W/caps"
        done
        sort -u "$W/caps" -o "$W/caps"
        # Old libcap prints "path = caps", new prints "path caps".
        while IFS= read -r _l; do
            _p=${_l%% *}; _c=${_l#* }; _c=${_c#= }
            cc_csv_row "$C" "$_p" "$_c"
            case "$_c" in *cap_setuid*|*cap_setgid*|*cap_sys_admin*|*cap_dac_override*|*cap_dac_read_search*|*cap_sys_ptrace*|*cap_sys_module*|*cap_chown*|*cap_fowner*)
                flag HIGH "$_p" "has the capability '$_c', which can be used to become root" ;;
            esac
        done <"$W/caps"
    else
        note "getcap not installed: capabilities not checked"
    fi

    # World-writable files in system folders: anyone can change what root runs.
    sec_csv world_writable "path,type,mode"
    WW=$SEC_CSV
    # /root and home folders are left out: they are normally closed to other
    # users, so a writable file inside cannot be reached anyway.
    for _r in /etc /usr /bin /sbin /lib /lib64 /opt /boot /var/www /srv; do
        [ -d "$_r" ] && find "$_r" -xdev \( -type f -o -type d \) -perm -0002 ! -perm -1000 ! -path '*/.cache/*' 2>/dev/null
    done | head -n 500 >"$W/ww"
    while IFS= read -r _p; do
        _md=$(mode_of "$_p")
        if [ -d "$_p" ]; then _t="dir"; else _t="file"; fi
        cc_csv_row "$WW" "$_p" "$_t" "$_md"
        case "$_p" in
            /var/www/*|/srv/*) flag MED "$_p" "world-writable $_t in the web content ($_md)" ;;
            /opt/*|/usr/local/*) flag MED "$_p" "world-writable $_t under $(printf '%s' "$_p" | cut -d/ -f2) ($_md): any user can change it" ;;
            *) flag HIGH "$_p" "world-writable $_t in a system folder ($_md): any user can change it" ;;
        esac
    done <"$W/ww"
    [ "$(wc -l <"$W/ww")" -ge 500 ] && note "world-writable list cut at 500"

    # Folders on root's PATH that others can write: a planted 'ls' runs as root.
    for _d in $(printf '%s' "$PATH" | tr ':' ' '); do
        [ -d "$_d" ] || continue
        # -L follows a symlink (/bin -> usr/bin on modern systems); a link
        # itself always shows as lrwxrwxrwx, which would be a false alarm.
        case "$(ls -ldL "$_d" 2>/dev/null | awk '{ print $1 }')" in ????????w*) flag HIGH "$_d" "folder on the PATH is world-writable; a planted program there runs as whoever uses that PATH" ;; esac
    done

    # Immutable (i) and append-only (a) flags.  A red team sets them so the
    # file cannot be fixed or deleted, even by root; 'rm' just fails.
    if cc_have lsattr; then
        sec_csv immutable "path,attributes"
        I=$SEC_CSV
        {
            lsattr -R /etc /root /var/www /var/spool/cron 2>/dev/null
            for _d in /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin; do [ -d "$_d" ] && lsattr "$_d" 2>/dev/null; done
            for _d in /home/*/.ssh /root/.ssh; do [ -d "$_d" ] && lsattr "$_d" 2>/dev/null; done
        } | awk 'NF >= 2 && $1 ~ /^[-A-Za-z]+$/ && $1 ~ /[ia]/ { a = $1; $1 = ""; sub(/^ /, ""); print a "|" $0 }' | sort -u >"$W/immut"
        while IFS='|' read -r _a _p; do
            cc_csv_row "$I" "$_p" "$_a"
            if printf '%s' "$_p" | grep -Eq '(/etc/(passwd|shadow|group|gshadow|sudoers|crontab|ld\.so\.preload|hosts|resolv\.conf|ssh/)|/\.ssh/|/etc/cron|/etc/pam\.d/|/etc/systemd/)'; then
                flag HIGH "$_p" "file is locked with chattr ($_a); changes to it will fail until 'chattr -i' is run"
            else
                flag MED "$_p" "file is locked with chattr ($_a)"
            fi
        done <"$W/immut"
    else
        note "lsattr not installed: immutable files not checked"
    fi

    # Files owned by a user or group that no longer exists (left behind by a
    # deleted account, or unpacked from an attacker's archive).
    for _r in /etc /usr /var /home /tmp /opt; do
        [ -d "$_r" ] && find "$_r" -xdev \( -nouser -o -nogroup \) 2>/dev/null
    done | head -n 100 >"$W/nouser"
    while IFS= read -r _p; do flag LOW "$_p" "owned by a user or group that does not exist"; done <"$W/nouser"
}

s_firewall() {
    sec_csv firewall "tool,status,detail"
    F=$SEC_CSV
    FW4=0; FW6=0
    if cc_have iptables-save; then
        if cc_save iptables iptables-save && [ -s "$CC_LAST_SAVE" ]; then
            _pol=$(sed -n 's/^:INPUT \([A-Z]*\).*/\1/p' "$CC_LAST_SAVE" | head -n 1)
            _n=$(grep -c '^-A INPUT' "$CC_LAST_SAVE")
            cc_csv_row "$F" iptables "INPUT policy ${_pol:-none}" "$_n INPUT rule(s); full rules in raw/iptables.txt"
            { [ "$_pol" = DROP ] || [ "$_pol" = REJECT ] || [ "$_n" -gt 0 ]; } && FW4=1
        fi
    fi
    if cc_have ip6tables-save; then
        if cc_save ip6tables ip6tables-save && [ -s "$CC_LAST_SAVE" ]; then
            _pol=$(sed -n 's/^:INPUT \([A-Z]*\).*/\1/p' "$CC_LAST_SAVE" | head -n 1)
            _n=$(grep -c '^-A INPUT' "$CC_LAST_SAVE")
            cc_csv_row "$F" ip6tables "INPUT policy ${_pol:-none}" "$_n INPUT rule(s)"
            { [ "$_pol" = DROP ] || [ "$_pol" = REJECT ] || [ "$_n" -gt 0 ]; } && FW6=1
        fi
    fi
    if cc_have nft && cc_save nftables nft list ruleset && grep -q 'hook input' "$CC_LAST_SAVE"; then
        cc_csv_row "$F" nftables "input hook present" "see raw/nftables.txt"
        grep -Eq '^table (ip|inet) ' "$CC_LAST_SAVE" && FW4=1
        grep -Eq '^table (ip6|inet) ' "$CC_LAST_SAVE" && FW6=1
    fi
    if cc_have ufw && cc_save ufw ufw status verbose; then
        _st=$(awk '/^Status:/ { print $2; exit }' "$CC_LAST_SAVE")
        cc_csv_row "$F" ufw "${_st:-unknown}" "see raw/ufw.txt"
        [ "$_st" = active ] && { FW4=1; FW6=1; }
    fi
    if cc_have firewall-cmd; then
        _st=$(firewall-cmd --state 2>/dev/null)
        cc_csv_row "$F" firewalld "${_st:-not running}" "see raw/firewalld.txt"
        if [ "$_st" = running ]; then FW4=1; FW6=1; cc_save firewalld firewall-cmd --list-all-zones; fi
    fi
    if cc_have pfctl; then
        cc_save pf_rules pfctl -sr
        _st=$(pfctl -s info 2>/dev/null | awk '/^Status:/ { print $2; exit }')
        cc_csv_row "$F" pf "${_st:-unknown}" "see raw/pf_rules.txt"
        [ "$_st" = Enabled ] && { FW4=1; FW6=1; }
    fi
    if cc_have ipfw && cc_save ipfw ipfw list; then
        _n=$(grep -cv '^65535' "$CC_LAST_SAVE")
        cc_csv_row "$F" ipfw "$_n rule(s)" "see raw/ipfw.txt"
        [ "$_n" -gt 1 ] && { FW4=1; FW6=1; }
    fi
    [ "$IS_ROOT" = 1 ] || note "partial: firewall rules need root"
    if [ "$FW4" = 0 ]; then
        flag MED "host firewall" "nothing filters incoming IPv4 traffic on this host"
    fi
    _v6=no
    if [ -r /proc/net/if_inet6 ] && awk '$6 != "lo" { f = 1 } END { exit !f }' /proc/net/if_inet6; then _v6=yes; fi
    if [ "$_v6" = yes ] && [ "$FW6" = 0 ]; then
        flag MED IPv6 "IPv6 is enabled but nothing filters it; the plan is to block IPv6 unless a scored service needs it"
    fi
    say "Host firewall: IPv4 $( [ "$FW4" = 1 ] && echo filtered || echo NOT-filtered ), IPv6 $( [ "$_v6" = yes ] && { [ "$FW6" = 1 ] && echo filtered || echo NOT-filtered; } || echo off )"
}

s_pam() {
    sec_csv pam "file,line,entry"
    F=$SEC_CSV
    : >"$W/pam"
    for _f in /etc/pam.d/* /etc/pam.conf; do
        [ -f "$_f" ] || continue
        awk -v src="$_f" '/^[ \t]*(#|$)/ { next } { print src "|" NR "|" $0 }' "$_f" >>"$W/pam"
    done
    while IFS='|' read -r _s _n _e; do cc_csv_row "$F" "$_s" "$_n" "$_e"; done <"$W/pam"
    awk -F'|' '
        {
            e = $3; it = $1 ":" $2
            if (e ~ /pam_exec\.so/) print "HIGH|" it "|pam_exec runs a program during login: " e
            split(e, w, " ")
            if (w[1] ~ /^-?auth$/ && w[2] == "sufficient" && e ~ /pam_permit\.so/) print "HIGH|" it "|pam_permit is sufficient for login: any password works. " e
            for (i = 1; i <= length(w); i++) if (w[i] ~ /^\/.*\.so$/ && w[i] !~ /^\/(usr\/)?lib(64)?\/([a-z0-9_]+-linux-gnu\/)?security\//) print "HIGH|" it "|PAM module loaded from an unusual path: " w[i]
            if (e ~ /nullok/) print "LOW|" it "|nullok lets an account with an empty password log in (default on some distributions)"
        }' "$W/pam" >"$W/f_pam"
    emit_flags "$W/f_pam"
    # Compare the PAM libraries with the package database.  A changed
    # pam_unix.so is the classic "master password" backdoor.  In the output,
    # the third character '5' means the file's checksum no longer matches.
    if cc_have dpkg; then
        dpkg -V libpam-modules libpam-modules-bin libpam-runtime 2>/dev/null >"$W/pamv"
    elif cc_have rpm; then
        rpm -V pam 2>/dev/null >"$W/pamv"
    else
        : >"$W/pamv"; note "no package database to verify PAM modules"
    fi
    if [ -s "$W/pamv" ]; then
        cc_save pam_verify cat "$W/pamv"
        awk 'substr($1, 3, 1) == "5" && $NF ~ /\.so$/ { print "HIGH|" $NF "|PAM module differs from the installed package (checksum changed): likely a backdoored login" }
             substr($1, 3, 1) == "5" && $NF !~ /\.so$/ { print "LOW|" $NF "|PAM file changed since install" }' "$W/pamv" >"$W/f_pamv"
        emit_flags "$W/f_pamv"
    fi
    say "PAM: $(wc -l <"$W/pam" | tr -d ' ') rule line(s)"
}

s_mac() {
    sec_csv mac "system,current,configured"
    F=$SEC_CSV
    _found=0
    if cc_have getenforce || [ -f /etc/selinux/config ]; then
        _found=1
        _cur=$(getenforce 2>/dev/null || echo unknown)
        _cfg=$(sed -n 's/^SELINUX=//p' /etc/selinux/config 2>/dev/null | tr -d '"' | head -n 1)
        cc_csv_row "$F" SELinux "$_cur" "${_cfg:-}"
        cc_have sestatus && cc_save sestatus sestatus
        if [ "$_cfg" = enforcing ] && [ "$_cur" != Enforcing ]; then
            flag HIGH SELinux "configured as enforcing but currently $_cur: someone switched it off"
        fi
    fi
    if [ -r /sys/module/apparmor/parameters/enabled ]; then
        _found=1
        _en=$(cat /sys/module/apparmor/parameters/enabled)
        _prof=""
        cc_have aa-status && aa-status >"$W/aa" 2>/dev/null && { cc_save aa_status cat "$W/aa"; _prof=$(awk '/profiles are in enforce mode/ { print $1 " enforced" } /profiles are in complain mode/ { print $1 " complain" }' "$W/aa" | tr '\n' ' '); }
        cc_csv_row "$F" AppArmor "$( [ "$_en" = Y ] && echo enabled || echo disabled )" "$_prof"
    fi
    [ "$_found" = 1 ] || cc_csv_row "$F" none "" ""
}

s_trust() {
    sec_csv trust "file,entry"
    F=$SEC_CSV
    home_dirs
    for _f in /etc/hosts.equiv /etc/shosts.equiv; do
        [ -s "$_f" ] || continue
        cc_csv_row "$F" "$_f" "$(tr '\n' ' ' <"$_f")"
        flag HIGH "$_f" "host-based trust file is in use: listed hosts log in without a password"
    done
    while IFS='|' read -r _u _uid _h; do
        for _f in "$_h/.rhosts" "$_h/.shosts" "$_h/.netrc"; do
            [ -f "$_f" ] || continue
            case "$_f" in
                *.netrc) cc_csv_row "$F" "$_f" "(contents not recorded: may hold passwords)"; flag MED "$_f" ".netrc stores login details for $_u" ;;
                *) cc_csv_row "$F" "$_f" "$(tr '\n' ' ' <"$_f" 2>/dev/null)"; flag HIGH "$_f" "$_u trusts other hosts to log in without a password" ;;
            esac
        done
    done <"$W/homes"
    if [ -f /etc/exports ]; then
        awk '/^[ \t]*(#|$)/ { next } { print }' /etc/exports >"$W/exports"
        while IFS= read -r _e; do
            cc_csv_row "$F" /etc/exports "$_e"
            case "$_e" in *no_root_squash*) flag HIGH "/etc/exports" "NFS export lets remote root act as root: $_e" ;; esac
            case "$_e" in *'*('*|*' *'*|*insecure*) flag MED "/etc/exports" "NFS export is open to any host or allows insecure ports: $_e" ;; esac
        done <"$W/exports"
    fi
    cc_have exportfs && cc_save exportfs exportfs -v
    cc_save mounts mount
    [ -r /etc/fstab ] && cc_save fstab cat /etc/fstab
    for _f in /etc/hosts.allow /etc/hosts.deny; do
        [ -f "$_f" ] || continue
        awk '/^[ \t]*(#|$)/ { next } { print }' "$_f" >"$W/tcpw"
        while IFS= read -r _e; do
            cc_csv_row "$F" "$_f" "$_e"
            case "$_e" in *spawn*|*twist*) flag HIGH "$_f" "TCP wrappers rule runs a command on connection: $_e" ;; esac
        done <"$W/tcpw"
    done
}

s_creds() {
    # Files that hold a password-like SETTING.  Only the file, line number
    # and setting name are recorded - never the value.
    sec_csv creds "file,line,setting,owner,mode,readable_by_all"
    F=$SEC_CSV
    _roots=""
    for _r in /etc /var/www /srv /opt /home /root /usr/local/etc /var/lib/tomcat* /usr/share/nginx; do [ -d "$_r" ] && _roots="$_roots $_r"; done
    # A setting NAME, then = : or =>, then a real value (not empty and not a
    # $variable).  Requiring a value keeps lines such as nsswitch's
    # "passwd: files" or "password required pam_unix.so" out.
    _pat='(password|passphrase|db_?pass(wd)?|[a-z]_pass|secret|api[_-]?key|access[_-]?key|private[_-]?key|auth[_-]?token|token|connection[_-]?string)["'"'"']?[[:space:]]*(=|:|=>)[[:space:]]*["'"'"']?[^[:space:]"'"'"'$]'
    # Library code, caches and documentation mention these words without
    # holding real secrets.
    _skip='/(node_modules|site-packages|dist-packages|vendor|\.cache|\.npm|\.git|man|doc|locale|test|tests)/|^/opt/.*/(lib|share|platform|versions|gems)/'
    : >"$W/credfiles"
    # shellcheck disable=SC2086
    for _r in $_roots; do
        find "$_r" -xdev -type f -size -512k \( -name '*.conf' -o -name '*.cnf' -o -name '*.ini' -o -name '*.php' -o -name '*.env' -o -name '.env' \
            -o -name '*.yml' -o -name '*.yaml' -o -name '*.xml' -o -name '*.properties' -o -name '*.config' -o -name '*.cfg' \
            -o -name '.my.cnf' -o -name '.pgpass' -o -name 'wp-config.php' -o -name 'settings.py' -o -name 'config.py' \) \
            -exec grep -l -i -E "$_pat" {} + 2>/dev/null >>"$W/credfiles"
    done
    grep -vE "$_skip" "$W/credfiles" | sort -u >"$W/credfiles2"
    mv "$W/credfiles2" "$W/credfiles"
    while IFS= read -r _f; do
        _md=$(mode_of "$_f"); _ow=$(owner_of "$_f")
        _all=no; case "$_md" in ???????r*) _all=yes ;; esac
        # line number and the setting NAME only
        grep -n -i -E "$_pat" "$_f" 2>/dev/null | head -n 20 | awk -F: '{
            l = tolower($0); sub(/^[0-9]+:/, "", l)
            if (match(l, /(password|passphrase|db_?pass(wd)?|[a-z]_pass|secret|api[_-]?key|access[_-]?key|private[_-]?key|auth[_-]?token|token|connection[_-]?string)/)) print $1 "|" substr(l, RSTART, RLENGTH)
        }' >"$W/credlines"
        while IFS='|' read -r _ln _key; do cc_csv_row "$F" "$_f" "$_ln" "$_key" "$_ow" "$_md" "$_all"; done <"$W/credlines"
        # Most files in /etc are readable by everyone on purpose, so only
        # application and web files are flagged.  The /etc ones stay in the CSV.
        if [ "$_all" = yes ]; then
            case "$_f" in
                /var/www/*|/srv/*|/opt/*|/home/*|/usr/share/nginx/*|/var/lib/tomcat*) flag MED "$_f" "every user can read this file and it holds a password-like setting" ;;
                */.my.cnf|*/.pgpass|*/debian.cnf|*/wp-config.php|*/.env) flag MED "$_f" "every user can read this credentials file" ;;
            esac
        fi
    done <"$W/credfiles"
    say "Files holding password-like settings: $(wc -l <"$W/credfiles" | tr -d ' ') (names only, values never recorded)"

    # Backups and repositories inside web content can usually be downloaded.
    for _r in /var/www /srv /usr/share/nginx /var/lib/tomcat*; do
        [ -d "$_r" ] || continue
        find "$_r" -xdev \( -name '*.bak' -o -name '*.old' -o -name '*.orig' -o -name '*.sql' -o -name '*.swp' -o -name '*~' \
            -o -name '*.zip' -o -name '*.tar' -o -name '*.tar.gz' -o -name '*.tgz' -o -name '*.7z' -o -name '.git' -o -name '.env' \) 2>/dev/null
    done | head -n 100 >"$W/webbak"
    while IFS= read -r _p; do flag HIGH "$_p" "backup, archive or repository inside web content: it may be downloadable"; done <"$W/webbak"

    # Private keys outside the SSH host keys.
    sec_csv private_keys "file,owner,mode,readable_by_all"
    PK=$SEC_CSV
    # A real key file STARTS with its header line.  Matching only the first
    # line keeps out source code and documentation that mention keys.
    for _r in /home /root /etc /var/www /srv /opt; do
        [ -d "$_r" ] && find "$_r" -xdev -type f -size -16k ! -name 'ssh_host_*' -exec grep -l '^-----BEGIN .*PRIVATE KEY-----' {} + 2>/dev/null
    done | grep -vE '/(node_modules|site-packages|dist-packages|\.cache|test|tests)/|^/opt/.*/(lib|share|platform|versions|gems)/' | head -n 200 >"$W/pkeys.all"
    : >"$W/pkeys"
    while IFS= read -r _f; do
        head -n 1 "$_f" 2>/dev/null | grep -q '^-----BEGIN .*PRIVATE KEY-----' && printf '%s\n' "$_f" >>"$W/pkeys"
    done <"$W/pkeys.all"
    while IFS= read -r _f; do
        _md=$(mode_of "$_f"); _all=no; case "$_md" in ???????r*) _all=yes ;; esac
        cc_csv_row "$PK" "$_f" "$(owner_of "$_f")" "$_md" "$_all"
        [ "$_all" = yes ] && flag HIGH "$_f" "private key readable by every user"
        case "$_f" in /var/www/*|/srv/*) flag HIGH "$_f" "private key inside web content" ;; esac
    done <"$W/pkeys"

    # Shell and client history: disabled history hides what someone did;
    # typed passwords are counted, never copied.
    sec_csv history "file,lines,possible_passwords,note"
    H=$SEC_CSV
    home_dirs
    while IFS='|' read -r _u _uid _h; do
        for _n in .bash_history .zsh_history .sh_history .ash_history .mysql_history .psql_history .python_history; do
            _f="$_h/$_n"
            if [ -h "$_f" ]; then
                _t=$(readlink "$_f")
                cc_csv_row "$H" "$_f" "" "" "link to $_t"
                [ "$_t" = /dev/null ] && flag MED "$_f" "$_u's history is linked to /dev/null: commands are being hidden"
            elif [ -f "$_f" ]; then
                _lines=$(wc -l <"$_f" | tr -d ' ')
                _pw=$(grep -cE '(mysql .*-p[^ ]|sshpass|PASSWORD=|--password|passwd |chpasswd|smbpasswd|net user .* /add)' "$_f" 2>/dev/null)
                cc_csv_row "$H" "$_f" "$_lines" "$_pw" ""
                [ "${_pw:-0}" -gt 0 ] && flag MED "$_f" "$_pw history line(s) may contain typed passwords"
            fi
        done
    done <"$W/homes"
}

s_containers() {
    sec_csv containers "engine,id,image,name,status,privileged,mounts"
    F=$SEC_CSV
    _any=0
    if cc_have docker; then
        _any=1
        if docker ps -a --format '{{.ID}}|{{.Image}}|{{.Names}}|{{.Status}}' >"$W/dps" 2>/dev/null; then
            cc_save docker_ps docker ps -a
            while IFS='|' read -r _id _img _name _st; do
                _priv=$(docker inspect --format '{{.HostConfig.Privileged}}' "$_id" 2>/dev/null)
                _mnt=$(docker inspect --format '{{range .Mounts}}{{.Source}}:{{.Destination}} {{end}}' "$_id" 2>/dev/null)
                cc_csv_row "$F" docker "$_id" "$_img" "$_name" "$_st" "$_priv" "$_mnt"
                [ "$_priv" = true ] && flag HIGH "container $_name" "runs privileged: a root shell in it is root on this host"
                case " $_mnt" in *" /:"*|*docker.sock*|*" /etc:"*|*" /root:"*) flag HIGH "container $_name" "mounts a sensitive host path: $_mnt" ;; esac
            done <"$W/dps"
        else
            note "docker is installed but 'docker ps' failed (daemon down or no permission)"
        fi
    fi
    if [ -S /var/run/docker.sock ]; then
        _md=$(mode_of /var/run/docker.sock)
        case "$_md" in ????????w*) flag HIGH /var/run/docker.sock "Docker socket is world-writable: every user is effectively root" ;; esac
    fi
    cc_have podman && { _any=1; cc_save podman_ps podman ps -a; }
    cc_have lxc && { _any=1; cc_save lxc_list lxc list; }
    cc_have lxc-ls && { _any=1; cc_save lxc_ls lxc-ls -f; }
    cc_have crictl && { _any=1; cc_save crictl_ps crictl ps -a; }
    cc_have kubectl && { _any=1; cc_save kubectl_pods kubectl get pods -A -o wide; }
    [ "$_any" = 1 ] || cc_csv_row "$F" none "" "" "" "" "" ""
    say "Containers: $(($(wc -l <"$F") - 1)) listed"
}

s_modules() {
    sec_csv modules "name,size,used_by"
    F=$SEC_CSV
    if [ -r /proc/modules ]; then
        awk "$AWK_Q"'{ print q($1) "," q($2) "," q($4) }' /proc/modules >>"$F"
        _t=$(cat /proc/sys/kernel/tainted 2>/dev/null)
        [ -n "$_t" ] && [ "$_t" != 0 ] && flag LOW kernel "kernel is tainted ($_t): an unsigned or out-of-tree module was loaded"
    elif cc_have kldstat; then
        cc_save kldstat kldstat
    elif cc_have modinfo && [ "$CC_OS_FAMILY" = solaris ]; then
        cc_save modinfo modinfo
    fi
    # modprobe 'install' lines run a command whenever a module loads: a
    # persistence trick.  'install X /bin/false' (used to block a module) is
    # normal.
    for _f in /etc/modprobe.d/*.conf /etc/modprobe.conf; do
        [ -f "$_f" ] || continue
        awk -v src="$_f" '$1 == "install" && $3 !~ /^\/(usr\/)?bin\/(false|true)$/ && $0 !~ /\/sbin\/modprobe/ { print "MED|" src "|module load runs a command: " $0 }' "$_f" >"$W/f_mod"
        emit_flags "$W/f_mod"
    done
    for _f in /etc/modules /etc/modules-load.d/*.conf; do
        [ -f "$_f" ] && cc_save "modules_load_$(basename "$_f")" cat "$_f"
    done
}

s_logs() {
    # Copy logs now, before a red team clears them.  Large text logs are cut
    # to their last 200000 lines; binary login records are copied whole.
    _ld="$CC_RUN_DIR/logs"
    mkdir -p "$_ld" || { note "cannot create $_ld"; return 0; }
    sec_csv logs "file,copied_as,bytes,sha256"
    F=$SEC_CSV
    for _f in /var/log/auth.log /var/log/auth.log.1 /var/log/secure /var/log/messages /var/log/syslog /var/log/kern.log \
              /var/log/cron /var/log/audit/audit.log /var/log/mail.log /var/log/maillog \
              /var/log/apache2/access.log /var/log/apache2/error.log /var/log/httpd/access_log /var/log/httpd/error_log \
              /var/log/nginx/access.log /var/log/nginx/error.log /var/log/wtmp /var/log/btmp /var/log/lastlog; do
        [ -f "$_f" ] || continue
        _dst="$_ld/$(printf '%s' "$_f" | sed 's|^/||; s|/|_|g')"
        case "$_f" in
            */wtmp|*/btmp) cp -p "$_f" "$_dst" 2>/dev/null ;;
            */lastlog) continue ;;     # sparse file that can appear huge; 'last' output is saved instead
            *) tail -n 200000 "$_f" >"$_dst" 2>/dev/null ;;
        esac
        [ -f "$_dst" ] || continue
        cc_csv_row "$F" "$_f" "$_dst" "$(wc -c <"$_dst" | tr -d ' ')" "$(cc_sha256 "$_dst")"
    done
    if [ "$CC_INIT" = systemd ] && cc_have journalctl; then
        journalctl --since "48 hours ago" --no-pager -o short-iso >"$_ld/journal_48h.txt" 2>/dev/null
        cc_csv_row "$F" "journalctl (48 hours)" "$_ld/journal_48h.txt" "$(wc -c <"$_ld/journal_48h.txt" | tr -d ' ')" "$(cc_sha256 "$_ld/journal_48h.txt")"
    fi
    dmesg >"$_ld/dmesg.txt" 2>/dev/null
    _n=$(($(wc -l <"$F") - 1))
    say "Logs: $_n file(s) copied to $_ld - copy them off this host"
    [ "$IS_ROOT" = 1 ] || note "partial: most logs need root"
}

# =============================================================================
# Run the sections and write the summary
# =============================================================================

# nflags SEVERITY -> how many flags of that severity flags.csv holds so far.
nflags() {
    if [ -f "$CC_CSV_DIR/flags.csv" ]; then grep -c "^\"$1\"" "$CC_CSV_DIR/flags.csv"; else echo 0; fi
    return 0
}

run_section() {
    SEC=$1; SEC_FILES=""; SEC_NOTE=""
    _rs_n=$((_rs_n + 1))
    cc_note "[$_rs_n/$_rs_total] $SEC"
    show "" ""
    show "$C_CYN" "==========[ $_rs_n/$_rs_total  $SEC ]=========="
    _rs_hi0=$(nflags HIGH); _rs_me0=$(nflags MED)
    _rs_t0=$(date +%s 2>/dev/null)
    "s_$SEC"
    _rs_t1=$(date +%s 2>/dev/null)
    _rows=0
    for _f in $SEC_FILES; do
        [ -f "$_f" ] && _rows=$((_rows + $(wc -l <"$_f") - 1))
    done
    cc_debug "section $SEC: $_rows rows in $((${_rs_t1:-0} - ${_rs_t0:-0}))s"
    _rs_hi=$(( $(nflags HIGH) - _rs_hi0 ))
    _rs_me=$(( $(nflags MED) - _rs_me0 ))
    [ "$_rs_hi" -eq 0 ] && [ "$_rs_me" -eq 0 ] && show "$C_GRN" "  [ok] nothing to fix here"
    _rs_files=""
    for _f in $SEC_FILES; do [ -f "$_f" ] && _rs_files="$_rs_files $(basename "$_f")"; done
    show "$C_GRY" "  ($_rows rows${_rs_files:+ ->$(printf '%s' "$_rs_files" | sed 's/\.csv/.txt/g')}${SEC_NOTE:+; $SEC_NOTE})"
    printf '%s|%s|%s\n' "$SEC" "$_rows" "$SEC_NOTE" >>"$W/sections"
}

: >"$W/summary_lines"; : >"$W/sections"
_rs_total=$(printf '%s\n' $SECTIONS | grep -c .)
_rs_n=0
for _s in $SECTIONS; do run_section "$_s"; done

# Section table: rows collected plus flags per severity, read from flags.csv.
_flagsf="$CC_CSV_DIR/flags.csv"
[ -f "$_flagsf" ] || printf 'severity,section,item,detail,time\n' >"$_flagsf"
# Read by cc_flag_report in the library.
# shellcheck disable=SC2034
CC_FLAGS=$_flagsf
# shellcheck disable=SC2034
CC_FLAGS_SHOW="$CC_RUN_DIR/flags.txt"
# A readable table for every CSV file: <run>/users.txt, ports.txt, ...
# flags.txt lists HIGH first, then MED, then LOW, with the detail kept whole.
for _c in "$CC_CSV_DIR"/*.csv; do
    [ -f "$_c" ] || continue
    _b=$(basename "$_c" .csv)
    if [ "$_b" = flags ]; then
        { head -n 1 "$_c"; for _sv in HIGH MED LOW; do grep "^\"$_sv\"" "$_c"; done; } >"$W/flags_sorted.csv"
        cc_csv_pretty "$W/flags_sorted.csv" "$CC_RUN_DIR/flags.txt" 200
    else
        cc_csv_pretty "$_c" "$CC_RUN_DIR/$_b.txt"
    fi
done
{
    printf 'SH-05 Linux enum | host %s | %s | profile %s | root: %s\n' "$CC_HOST" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$PROFILE" "$([ "$IS_ROOT" = 1 ] && echo yes || echo NO - partial)"
    printf 'OS: %s | kernel %s | init %s\n\n' "$CC_OS_NAME" "$(uname -r 2>/dev/null)" "$CC_INIT"
    cat "$W/summary_lines"
    printf '\n'
    awk -v sf="$W/sections" "$CC_AWK_CSV"'
        BEGIN { FS = "\n" }
        NR > 1 { csvsplit($0, f); c[f[2] "|" f[1]]++ }
        END {
            printf "%-12s %6s %5s %5s %5s  %s\n", "section", "rows", "high", "med", "low", "note"
            while ((getline l < sf) > 0) {
                split(l, s, "|")
                printf "%-12s %6d %5d %5d %5d  %s\n", s[1], s[2], c[s[1] "|HIGH"], c[s[1] "|MED"], c[s[1] "|LOW"], s[3]
            }
        }' "$_flagsf"
    printf '\n'
    cc_flag_report "$MAXFLAGS"
    printf '\nAll results: %s\n' "$CC_RUN_DIR"
} >"$CC_RUN_DIR/summary.txt"
show "" ""
show "$C_CYN" "==========[ SUMMARY ]=========="
cat "$CC_RUN_DIR/summary.txt"
cat "$CC_RUN_DIR/summary.txt" >>"$OUTF"
rm -rf "$W"
cc_finish
