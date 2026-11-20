#!/bin/sh
# =============================================================================
# ID:       LX-40
# NAME:     Linux change watch
# ROLE:     Linux  (wave 2, first 15 minutes - start it once the box is hardened)
# KIND:     readonly - changes nothing on the host
# VERSION:  2.1.0
#
# PURPOSE
#   Takes a baseline of the places red teams use to get back in, then checks
#   again - once, or every N seconds - and raises one alert per change, in
#   plain words, worst first:
#     users        accounts added, deleted, given UID 0 or a login shell
#     passwords    a password changed, removed (empty) or an account unlocked
#                  (only a short fingerprint is kept, never the hash)
#     groups       who was added to sudo, wheel, docker ... (admin groups HIGH)
#     files        sudoers, PAM, ld.so.preload, login scripts, hosts, DNS,
#                  sshd_config, sysctl
#     cron         crontabs, cron folders, at/anacron spools, systemd timers
#     units        systemd unit files, init.d scripts, rc.local
#     running      running services: a scored one stopping, or auditd /
#                  rsyslog / splunk being stopped to hide something
#     keys         every account's authorized_keys files
#     ports        new listening ports, with the program, its user and
#                  command line (a shell or nc listening is HIGH)
#     connections  NEW: new outgoing connections (reverse shells, beacons)
#                  and new addresses connected to SSH/RDP/database ports
#     suid         new SUID/SGID programs
#     web          files added, removed or changed in the web roots
#     modules      kernel modules loaded
#   Each change is reported once.  changes-since-baseline.txt in the state
#   folder always holds the full list of what differs from the baseline.
#
#   QUESTIONS (Enter takes the [default]; a flag answers each one ahead):
#     use the existing baseline, or take a new one     --baseline / --use-baseline
#     seconds between checks (0 = once)                --loop N / --once
#     watch connections too                            --conns / --no-conns
#     your team's addresses (never alerted)            --team "ADDR NET ..."
#     extra web folders                                --webroot DIR
#     scan the disk for new SUID programs              --suid / --no-suid
#   --batch, or no terminal: defaults, and ONE check (no loop unless --loop).
#
# USAGE
#   sudo sh LX-40-change-watch.sh                        asks, then watches
#   sudo sh LX-40-change-watch.sh --batch                one check, defaults
#   sudo sh LX-40-change-watch.sh --loop 60 --team 10.0.0.0/24
#   nohup sudo sh LX-40-change-watch.sh --batch --loop 60 --alert-cmd "ssh admin@10.0.0.5 'cat >>/srv/alerts/web01.log'" &
#   sudo sh LX-40-change-watch.sh --accept               your own changes become the baseline
#
# OPTIONS
#   --baseline         take a new baseline (replaces the old one)
#   --accept           same as --baseline: use after reviewing your own changes
#   --use-baseline     keep the existing baseline (no question)
#   --loop N           check every N seconds (10 or more) until Ctrl-C
#   --once             check once and stop
#   --count N          with --loop: stop after N checks
#   --conns / --no-conns   watch connections (default yes)
#   --team "A B"       team addresses or IPv4 networks (10.0.0.5 10.0.0.0/24);
#                      connections to or from them are never alerted (repeat)
#   --webroot DIR      also watch DIR (repeat); the usual web roots always are
#   --suid / --no-suid scan the whole disk for SUID/SGID programs (default yes)
#   --suid-every N     with --loop: that scan only on every Nth check (default 10)
#   --alert-cmd CMD    run CMD (sh -c) after each check that found changes;
#                      the new alert lines arrive on its stdin
#   --state DIR        where the baseline lives (default <out>/watch-<host>)
#   --root DIR         treat DIR as / for the file sections (tests)
#   --no-color         no colours
#   --help             this text plus the common options
#
# OUTPUTS
#   <out>/changewatch-N/   this run:
#     output.txt                everything shown on screen, no colour
#     alerts.txt                this run's alerts as a table
#     connections.txt           new connections seen
#     summary.txt               counts by severity and section
#     run.txt                   id, host, start time
#   <out>/watch-<host>/    the state, kept between runs:
#     baseline/, last/          the snapshots (plain text, no secrets)
#     alerts.log                every alert ever, one line each:
#                               time SEVERITY section change item - detail
#     changes-since-baseline.txt  what differs from the baseline right now
#     conns-seen                connections already reported
#     settings                  your answers, used as the next run's defaults
#
# WHAT IT CHANGES
#   Nothing on the host.  It reads files and runs read-only commands.
#
# DEPENDS ON
#   awk, find, ls, cksum; sha256sum (or shasum / sha256 / openssl); ss or
#   netstat; systemctl for timers and running services (optional).
#   Stand-ins for tests: BT_SS (ss), BT_SYSTEMCTL, BT_PROC (/proc).
#
# TESTED ON
#   Ubuntu 24.04 under dash, bash, busybox sh, ksh93, mksh and yash, with
#   gawk, mawk and busybox awk, on a fake root with stand-in ss/systemctl/proc;
#   live: a planted account, cron job, SSH key, listener, web shell and a
#   reverse shell to an outside address were each reported once.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - It sees changes, not intent: your own hardening shows up too.  After
#     changing things on purpose, run --accept (or answer No to "use the
#     baseline").
#   - Connections are sampled at each check: one that opens and closes
#     between two checks is not seen.  A reverse shell stays open, so it is.
#   - Web files are compared by size and time, not content (to stay fast).
#   - Without root, other accounts' passwords, keys and the program behind
#     a connection cannot be read.
#   - A red team with root can stop or fool this script.  Send alerts off
#     the box with --alert-cmd.  It does not hide itself.
#
# DEBUGGING
#   --debug shows how many items each section found.  The snapshots in
#   baseline/ and last/ are plain text: diff them by hand.
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

usage() {
    cat <<'USAGE'
LX-40 Linux change watch - alert on new accounts, keys, cron jobs, ports, connections, files
  sudo sh LX-40-change-watch.sh               asks, then watches
  sudo sh LX-40-change-watch.sh --batch       one check with the defaults

  --baseline / --accept   take a new baseline (after your own changes)
  --use-baseline     keep the existing baseline
  --loop N           check every N seconds until Ctrl-C (10 or more)
  --once             check once and stop
  --count N          with --loop: stop after N checks
  --conns / --no-conns   watch new connections (default yes)
  --team "A B"       team addresses / IPv4 networks, never alerted (repeatable)
  --webroot DIR      also watch DIR (repeatable)
  --suid / --no-suid scan the disk for new SUID/SGID programs (default yes)
  --suid-every N     with --loop: that scan on every Nth check only (default 10)
  --alert-cmd CMD    run CMD with new alerts on stdin (send them off the box)
  --state DIR        baseline folder (default <out>/watch-<host>)
  --root DIR         treat DIR as / (tests)
  --no-color         no colours
  --help             show this text

USAGE
    cc_usage_common
}

NL='
'
BASEMODE=""; LOOP=""; COUNT=0; WEBARGS=""; WEBSET=0; SUIDOPT=""; SUIDEVERY=10; ALERTCMD=""; STATE=""; R=""
CONNS=""; TEAM=""; TEAMSET=0; COLOR=1
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --baseline|--accept) BASEMODE=new; shift ;;
        --use-baseline) BASEMODE=keep; shift ;;
        --loop)      [ $# -ge 2 ] || cc_die 2 "--loop needs seconds"; LOOP=$2; shift 2 ;;
        --once)      LOOP=0; shift ;;
        --count)     [ $# -ge 2 ] || cc_die 2 "--count needs a number"; COUNT=$2; shift 2 ;;
        --conns)     CONNS=1; shift ;;
        --no-conns)  CONNS=0; shift ;;
        --team)      [ $# -ge 2 ] || cc_die 2 "--team needs addresses"; TEAM="$TEAM $(printf '%s' "$2" | tr ',' ' ')"; TEAMSET=1; shift 2 ;;
        --webroot)   [ $# -ge 2 ] || cc_die 2 "--webroot needs a folder"; [ -d "$2" ] || cc_die 2 "--webroot: not a folder: $2"
                     WEBARGS="$WEBARGS$(cc_abspath "$2")$NL"; WEBSET=1; shift 2 ;;
        --suid)      SUIDOPT=1; shift ;;
        --no-suid)   SUIDOPT=0; shift ;;
        --suid-every) [ $# -ge 2 ] || cc_die 2 "--suid-every needs a number"; SUIDEVERY=$2; shift 2 ;;
        --alert-cmd) [ $# -ge 2 ] || cc_die 2 "--alert-cmd needs a command"; ALERTCMD=$2; shift 2 ;;
        --state)     [ $# -ge 2 ] || cc_die 2 "--state needs a folder"; STATE=$2; shift 2 ;;
        --root)      [ $# -ge 2 ] || cc_die 2 "--root needs a folder"; [ -d "$2" ] || cc_die 2 "--root: not a folder: $2"
                     R=$(cd "$2" && pwd); [ "$R" = / ] && R=""; shift 2 ;;
        --no-color|--no-colour) COLOR=0; shift ;;
        --help|-h)   usage; exit 0 ;;
        *)           cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
# ok_loop VALUE -> exits 2 unless VALUE is 0 or a whole number of 10 or more.
ok_loop() {
    case "$1" in ''|*[!0-9]*) cc_die 2 "--loop needs a whole number of seconds" ;; esac
    [ "$1" -gt 0 ] && [ "$1" -lt 10 ] && cc_die 2 "--loop must be at least 10 seconds (or 0 for one check)"
    return 0
}
[ -n "$LOOP" ] && ok_loop "$LOOP"
case "$COUNT" in ''|*[!0-9]*) cc_die 2 "--count needs a whole number" ;; esac
case "$SUIDEVERY" in ''|*[!0-9]*|0) cc_die 2 "--suid-every needs a whole number, 1 or more" ;; esac
# valid_net ADDR -> an IPv4 address or network, or an IPv6 address/prefix.
valid_net() {
    printf '%s' "$1" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]|[12][0-9]|3[0-2]))?$|^[0-9a-fA-F:]+:[0-9a-fA-F:]*(/[0-9]{1,3})?$'
}
for _a in $TEAM; do valid_net "$_a" || cc_die 2 "--team: not an address or network: $_a"; done

cc_init "LX-40" "Linux change watch" readonly
cc_detect_os
# shellcheck disable=SC2034  # read by cc_color_init
[ "$COLOR" = 1 ] || CC_NOCOLOR=1
cc_color_init
cc_use_numbered_dir changewatch
CC_CSV_DIR="$CC_RUN_DIR/csv"
mkdir -p "$CC_CSV_DIR" || cc_die 3 "cannot create $CC_CSV_DIR"
rmdir "$CC_RUN_DIR/raw" 2>/dev/null
OUTF="$CC_RUN_DIR/output.txt"; : >"$OUTF"
# shellcheck disable=SC2034  # CC_TEE is read by the library's log functions
CC_TEE=$OUTF
IS_ROOT=0; cc_is_root && IS_ROOT=1
[ -n "$STATE" ] || STATE="$CC_OUT/watch-$CC_HOST"
(umask 077; mkdir -p "$STATE") || cc_die 3 "cannot create $STATE"
STATE=$(cc_abspath "$STATE")
SS=${BT_SS:-$(cc_which ss)} || SS=""
SYSCTL=${BT_SYSTEMCTL:-}
[ -z "$SYSCTL" ] && [ -z "$R" ] && [ "$CC_INIT" = systemd ] && SYSCTL=$(cc_which systemctl)
PROCROOT=${BT_PROC:-}
[ -z "$PROCROOT" ] && [ -z "$R" ] && PROCROOT=/proc
ALERTS="$STATE/alerts.log"
W="$CC_RUN_DIR/.work"; mkdir -p "$W"

header() { cc_show "" ""; cc_show "$C_CYN" "==========[ $1 ]=========="; }
# setting KEY -> the value saved by the last run (empty if none).
setting() { [ -f "$STATE/settings" ] && sed -n "s/^$1=//p" "$STATE/settings" | tail -n 1; }

cc_show "$C_CYN" "LX-40 Change watch | host $CC_HOST | results in $CC_RUN_DIR"
cc_show "$C_CYN" "Baseline and history in $STATE"
cc_show "" "Legend: ${C_RED}[!] HIGH${C_OFF} almost certainly the red team   ${C_YEL}[*] MED${C_OFF} check it   ${C_GRY}[-] LOW${C_OFF} worth knowing   ${C_GRN}[ok]${C_OFF} no changes"
[ -n "$R" ] && cc_show "$C_GRY" "Looking at $R as if it were / (tests)"
[ "$IS_ROOT" = 1 ] || [ -n "$R" ] || cc_show "$C_YEL" "[!] Not root: passwords, other accounts' keys and the programs behind connections cannot be seen. Run with sudo."

# ---- Questions (sqlmap style) ---------------------------------------------------
header "1/3  setup: what to watch"
HAVEBASE=0; [ -f "$STATE/baseline/users" ] && HAVEBASE=1
BASETIME=$(cat "$STATE/baseline/.taken" 2>/dev/null)
if [ "$HAVEBASE" = 0 ]; then
    [ "$BASEMODE" = keep ] && cc_show "$C_YEL" "[!] --use-baseline: there is no baseline yet in $STATE"
    BASEMODE=new
    cc_show "" "  No baseline yet: one is taken now, so the first check compares against this moment."
elif [ -z "$BASEMODE" ]; then
    if cc_ask "Use the baseline from ${BASETIME:-earlier}?" Y "yes, compare against it" "no, take a new one now (after your own hardening)"; then BASEMODE=keep; else BASEMODE=new; fi
fi
if [ -z "$LOOP" ]; then
    if _cc_can_ask; then
        cc_ask_text "How often should it check?" 60 "seconds between checks, like 60; 0 = check once and stop"
        LOOP=$CC_ANSWER; ok_loop "$LOOP"
    else
        LOOP=0
    fi
fi
_d=$(setting conns)
if [ -z "$CONNS" ]; then
    if cc_ask "Watch connections too?" "$([ "$_d" = 0 ] && echo N || echo Y)" "yes, watch them (catches reverse shells and who logs in)" "no, skip connections"; then CONNS=1; else CONNS=0; fi
fi
if [ "$CONNS" = 1 ] && [ "$TEAMSET" = 0 ]; then
    cc_ask_text "Your team's addresses (their connections are never alerted)?" "$(setting team)" "addresses or networks separated by spaces, like 10.0.0.5 10.0.0.0/24"
    TEAM=$(printf '%s' "$CC_ANSWER" | tr ',' ' ')
    for _a in $TEAM; do valid_net "$_a" || cc_die 2 "not an address or network: $_a"; done
fi
TEAM=$(printf '%s' "$TEAM" | sed 's/^ *//; s/ *$//')
# Web roots: the usual ones, the ones the baseline was taken with, and
# anything new.  All without the --root prefix.
_saved_web=""; [ "$BASEMODE" = keep ] && _saved_web=$(cat "$STATE/baseline/.webroots" 2>/dev/null)
if [ "$WEBSET" = 0 ]; then
    cc_ask_text "Other web folders to watch, besides /var/www /srv/www /usr/share/nginx/html ...?" "" "folders separated by spaces, like /opt/app/public"
    for _w in $(printf '%s' "$CC_ANSWER" | tr ',' ' '); do
        [ -d "$R$_w" ] || [ -d "$_w" ] || { cc_show "$C_YEL" "  [!] not a folder, skipped: $_w"; continue; }
        if [ -d "$_w" ]; then WEBARGS="$WEBARGS$(cc_abspath "$_w")$NL"; else WEBARGS="$WEBARGS$R$_w$NL"; fi
    done
fi
{
    for _d in /var/www /srv/www /srv/http /usr/share/nginx/html /usr/local/www /opt/lampp/htdocs; do printf '%s\n' "$_d"; done
    printf '%s\n' "$_saved_web"
    printf '%s' "$WEBARGS" | while IFS= read -r _w; do
        [ -n "$_w" ] || continue
        if [ -n "$R" ]; then case "$_w" in "$R"/*) _w=${_w#"$R"} ;; esac; fi
        printf '%s\n' "$_w"
    done
} | sed 's|/*$||' | grep . | sort -u | awk '{ for (k in keep) if (index($0, k "/") == 1) next; keep[$0] = 1; print }' >"$W/webroots"
_d=$(setting suid)
if [ -z "$SUIDOPT" ]; then
    if cc_ask "Look for new SUID programs on the whole disk?" "$([ "$_d" = 0 ] && echo N || echo Y)" "yes, scan for them (slower; in a loop every ${SUIDEVERY}th check)" "no, skip it"; then SUIDOPT=1; else SUIDOPT=0; fi
fi
NOSUID=$((1 - SUIDOPT))
printf 'conns=%s\nteam=%s\nsuid=%s\n' "$CONNS" "$TEAM" "$SUIDOPT" >"$STATE/settings"

cc_show "" ""
cc_show "" "  Baseline:     $([ "$BASEMODE" = new ] && echo 'take a new one now' || echo "keep the one from ${BASETIME:-earlier}")"
cc_show "" "  Checks:       $([ "$LOOP" -gt 0 ] && echo "every $LOOP seconds$([ "$COUNT" -gt 0 ] && echo ", $COUNT times") (Ctrl-C stops and prints the summary)" || echo 'once')"
cc_show "" "  Connections:  $([ "$CONNS" = 1 ] && echo "watched$([ -n "$TEAM" ] && echo "; team, never alerted: $TEAM")" || echo 'not watched')"
cc_show "" "  Web folders:  $(tr '\n' ' ' <"$W/webroots")"
cc_show "" "  SUID scan:    $([ "$SUIDOPT" = 1 ] && echo yes || echo no)"
[ -n "$ALERTCMD" ] && cc_show "" "  Off the box:  each check's alerts are sent to: $ALERTCMD"

# ---- Process details ----------------------------------------------------------------
# proc_info PID -> PR_USER, PR_CMD (command line), PR_EXE, from /proc.
proc_info() {
    PR_USER=""; PR_CMD=""; PR_EXE=""
    [ -n "$PROCROOT" ] && [ -n "$1" ] && [ -d "$PROCROOT/$1" ] || return 0
    # shellcheck disable=SC2012  # ls: the owner of /proc/PID is the account
    PR_USER=$(ls -ld "$PROCROOT/$1" 2>/dev/null | awk '{ print $3 }')
    PR_CMD=$(tr '\000' ' ' 2>/dev/null <"$PROCROOT/$1/cmdline" | tr '|\n\r\t' '/   ' | sed 's/ *$//' | cut -c1-160)
    PR_EXE=$(readlink "$PROCROOT/$1/exe" 2>/dev/null) || PR_EXE=""
}
# shellish NAME -> true for a shell, interpreter or network tool: almost never
#   the program that should be listening or calling out on a server.
shellish() {
    case "$1" in
        sh|bash|dash|zsh|ksh|ksh93|mksh|ash|csh|tcsh|busybox|nc|ncat|netcat|nc.*|socat|telnet|python|python[0-9]*|perl|perl5*|php|php[0-9]*|php-cgi*|ruby|ruby[0-9]*|lua|lua[0-9]*|awk|gawk|mawk|openssl|sshpass) return 0 ;;
    esac
    return 1
}
# badexe PATH -> true for a program in a temp folder or one deleted while running.
badexe() { case "$1" in /tmp/*|/var/tmp/*|/dev/shm/*|/run/shm/*|*" (deleted)"|*/.*/*) return 0 ;; esac; return 1; }
webuser() { case "$1" in www-data|apache|apache2|nginx|httpd|lighttpd|nobody|tomcat*|wwwrun|http) return 0 ;; esac; return 1; }
BACKDOOR_PORTS="1337 4444 4445 5555 6666 6667 9001 12345 31337 54321 2375"
backdoor_port() { case " $BACKDOOR_PORTS " in *" $1 "*) return 0 ;; esac; return 1; }

# ---- Snapshot -------------------------------------------------------------------
# hashlist PATH... -> "path|first 16 hex of sha256" for every regular file
#   under the paths.  Paths are written without the --root prefix.
hashlist() {
    _hl_n=0
    for _p in "$@"; do [ -e "$_p" ] && _hl_n=1; done
    [ "$_hl_n" = 1 ] || return 0
    if cc_have sha256sum; then
        find "$@" -xdev -type f -exec sha256sum {} + 2>/dev/null | awk -v r="$R" '{ h = $1; $1 = ""; sub(/^ +/, ""); p = $0; if (r != "" && index(p, r) == 1) p = substr(p, length(r) + 1); print p "|" substr(h, 1, 16) }'
    else
        find "$@" -xdev -type f 2>/dev/null | while IFS= read -r _f; do
            _h=$(cc_sha256 "$_f"); printf '%s|%s\n' "${_f#"$R"}" "$(printf '%s' "$_h" | cut -c1-16)"
        done
    fi
}

# snap DIR -> one sorted "key|value" file per section in DIR.
snap() {
    _sd=$1; rm -rf "$_sd"; mkdir -p "$_sd"
    # users: name -> uid:gid:home:shell
    awk -F: '{ print $1 "|" $3 ":" $4 ":" $6 ":" $7 }' "$R/etc/passwd" 2>/dev/null | sort >"$_sd/users"
    # passwords: EMPTY, LOCKED, or a 12-digit fingerprint of the shadow field
    # (a checksum of the hash), so a change is visible but nothing usable is kept.
    if [ -r "$R/etc/shadow" ]; then
        awk -F: '{ print $1 "\t" $2 }' "$R/etc/shadow" | while IFS="$(printf '\t')" read -r _u _f; do
            case "$_f" in
                '') printf '%s|EMPTY\n' "$_u" ;;
                '!'*|'*'*) printf '%s|LOCKED\n' "$_u" ;;
                *) printf '%s|%s\n' "$_u" "$(printf '%s' "$_f" | cksum | awk '{ printf "%012d", $1 % 1000000000000 }')" ;;
            esac
        done | sort >"$_sd/passwords"
    fi
    # groups: name -> gid:members
    awk -F: '{ print $1 "|" $3 ":" $4 }' "$R/etc/group" 2>/dev/null | sort >"$_sd/groups"
    # files: configuration that changes how logins and programs behave
    hashlist "$R/etc/sudoers" "$R/etc/sudoers.d" "$R/etc/pam.d" "$R/etc/security" "$R/etc/ld.so.preload" \
             "$R/etc/ld.so.conf" "$R/etc/ld.so.conf.d" "$R/etc/profile" "$R/etc/profile.d" "$R/etc/bash.bashrc" \
             "$R/etc/bashrc" "$R/etc/environment" "$R/etc/hosts" "$R/etc/resolv.conf" "$R/etc/nsswitch.conf" \
             "$R/etc/ssh/sshd_config" "$R/etc/ssh/sshd_config.d" "$R/etc/sysctl.conf" "$R/etc/sysctl.d" \
             "$R/root/.bashrc" "$R/root/.profile" "$R/root/.bash_profile" \
             "$R/etc/doas.conf" "$R/etc/doas.d" "$R/root/.ashrc" "$R/etc/apk/repositories" "$R/etc/apk/keys" | sort >"$_sd/files"
    # cron: every cron and at file, plus systemd timers by name
    { hashlist "$R/etc/crontab" "$R/etc/cron.d" "$R/etc/cron.hourly" "$R/etc/cron.daily" "$R/etc/cron.weekly" \
               "$R/etc/cron.monthly" "$R/var/spool/cron" "$R/var/spool/at" "$R/var/spool/anacron" "$R/etc/anacrontab" \
               "$R/etc/crontabs" "$R/etc/periodic"
      if [ -n "$SYSCTL" ]; then
          "$SYSCTL" list-timers --all --no-legend --no-pager 2>/dev/null | awk '{ for (i = 1; i <= NF; i++) if ($i ~ /\.timer$/) print "timer " $i "|" }'
      fi; } | sort -u >"$_sd/cron"
    # units: services that start at boot
    hashlist "$R/etc/systemd/system" "$R/lib/systemd/system" "$R/usr/lib/systemd/system" "$R/etc/init.d" \
             "$R/etc/rc.local" "$R/etc/rc.d" "$R/etc/local.d" "$R/etc/conf.d" | sort >"$_sd/units"
    # OpenRC (Alpine): which services start in which runlevel (the links in /etc/runlevels)
    for _rl in "$R"/etc/runlevels/*/; do
        [ -d "$_rl" ] || continue
        for _l in "$_rl"*; do [ -e "$_l" ] || [ -L "$_l" ] || continue; printf '%s|runlevel %s\n' "${_l#"$R"}" "$(basename "$_rl")"; done
    done | sort >>"$_sd/units"
    sort -o "$_sd/units" "$_sd/units"
    # running: services running now (systemd, or OpenRC's rc-status)
    if [ -z "$SYSCTL" ] && [ -z "$R" ] && [ "$CC_INIT" = openrc ] && cc_have rc-status; then
        rc-status -s 2>/dev/null | awk '/\[ *started/ { print $1 "|" }' | sort -u >"$_sd/running"
    fi
    if [ -n "$SYSCTL" ]; then
        "$SYSCTL" list-units --type=service --state=running --no-legend --no-pager 2>/dev/null |
            awk '{ for (i = 1; i <= NF; i++) if ($i ~ /\.service$/) { print $i "|"; break } }' | sort -u >"$_sd/running"
    fi
    # keys: every authorized_keys file of every account
    awk -F: '$6 != "" { print $6 }' "$R/etc/passwd" 2>/dev/null | sort -u | while IFS= read -r _h; do
        for _k in "$R$_h/.ssh/authorized_keys" "$R$_h/.ssh/authorized_keys2"; do [ -f "$_k" ] && printf '%s\n' "$_k"; done
    done >"$W/keyfiles"
    : >"$_sd/keys"
    while IFS= read -r _k; do
        _n=$(grep -c '^[^#]' "$_k" 2>/dev/null)
        printf '%s|%s %s keys\n' "${_k#"$R"}" "$(hashlist "$_k" | cut -d'|' -f2)" "$_n" >>"$_sd/keys"
    done <"$W/keyfiles"
    sort -o "$_sd/keys" "$_sd/keys"
    # ports: "proto address port" -> program;  ports.pid: the same key -> pid
    : >"$_sd/ports"; : >"$_sd/ports.pid"
    if [ -n "$SS" ]; then
        "$SS" -ltnup 2>/dev/null | awk -v pf="$_sd/ports.pid" 'NR > 1 && ($1 == "tcp" || $1 == "udp") {
            a = $5; p = a; sub(/.*:/, "", p); sub(/:[^:]*$/, "", a); gsub(/[][]/, "", a); sub(/%.*/, "", a)
            pr = ""; if (match($0, /\(\("[^"]*"/)) pr = substr($0, RSTART + 3, RLENGTH - 4)
            pid = ""; if (match($0, /pid=[0-9]+/)) pid = substr($0, RSTART + 4, RLENGTH - 4)
            k = $1 " " a " " p; print k "|" pr; print k "|" pid >pf }' | sort -u >"$_sd/ports"
    elif cc_have netstat; then
        netstat -ltnup 2>/dev/null | awk -v pf="$_sd/ports.pid" '$1 ~ /^(tcp|udp)/ {
            a = $4; p = a; sub(/.*:/, "", p); sub(/:[^:]*$/, "", a)
            pr = ""; pid = ""; if ($NF ~ /^[0-9]+\//) { pid = $NF; sub(/\/.*/, "", pid); pr = $NF; sub(/^[0-9]+\//, "", pr) }
            k = substr($1, 1, 3) " " a " " p; print k "|" pr; print k "|" pid >pf }' | sort -u >"$_sd/ports"
    fi
    [ "$CONNS" = 1 ] && snap_conns "$_sd"
    # suid: SUID/SGID programs on the root file system.  The scan walks the
    # whole disk, so in a loop most checks reuse the last result (DOSUID=0).
    if [ "$NOSUID" = 0 ]; then
        if [ "$DOSUID" = 0 ] && [ -f "$STATE/last/suid" ]; then
            cp "$STATE/last/suid" "$_sd/suid"
        else
            find "$R/" -xdev -type f \( -perm -4000 -o -perm -2000 \) -exec ls -ln {} + 2>/dev/null |
                awk -v r="$R" '{ p = $NF; if (r != "" && index(p, r) == 1) p = substr(p, length(r) + 1); print p "|" $1 " " $3 }' | sort >"$_sd/suid"
        fi
    fi
    # web: every file in the web roots by size and modification time
    : >"$_sd/web"
    while IFS= read -r _w; do
        [ -d "$R$_w" ] || continue
        find "$R$_w" -xdev -type f -exec ls -ln {} + 2>/dev/null |
            awk -v r="$R" '{ p = $9; for (i = 10; i <= NF; i++) p = p " " $i; if (r != "" && index(p, r) == 1) p = substr(p, length(r) + 1); print p "|" $5 " " $6 " " $7 " " $8 }' >>"$_sd/web"
    done <"$W/webroots"
    sort -o "$_sd/web" "$_sd/web"
    cp "$W/webroots" "$_sd/.webroots"
    # modules: loaded kernel modules
    if [ -r "$R/proc/modules" ]; then awk '{ print $1 "|" }' "$R/proc/modules" | sort >"$_sd/modules"; else : >"$_sd/modules"; fi
    for _s in $SECTIONS conns; do
        [ -f "$_sd/$_s" ] && cc_debug "snapshot $_s: $(grep -c . "$_sd/$_s") items"
    done
    return 0
}

# Ports where a new connecting address is worth an alert: remote logins,
# databases and file shares.
ADMIN_PORTS="21 22 23 139 445 1433 2049 3306 3389 5432 5900 5901 5985 5986 6379 27017"
# snap_conns DIR -> DIR/conns: one line per established connection worth
#   watching, as  key|direction|address|port|local port|program|pid
#   out: this box called out (the local port is not a listening one)
#   in:  someone connected to an admin port, or to a shell-like program
snap_conns() {
    : >"$1/conns"
    _lp=$(awk -F'|' '{ split($1, k, " "); if (k[1] == "tcp") printf "%s ", k[3] }' "$1/ports")
    if [ -n "$SS" ]; then
        "$SS" -tanp 2>/dev/null | awk '
            NR == 1 && ($1 == "State" || $1 == "Netid") { next }
            {   o = ($1 == "tcp" || $1 == "udp") ? 1 : 0
                st = $(1 + o); if (st != "ESTAB" && st != "SYN-SENT") next
                pr = ""; if (match($0, /\(\("[^"]*"/)) pr = substr($0, RSTART + 3, RLENGTH - 4)
                pid = ""; if (match($0, /pid=[0-9]+/)) pid = substr($0, RSTART + 4, RLENGTH - 4)
                print $(4 + o), $(5 + o), (pr == "" ? "-" : pr), (pid == "" ? "-" : pid) }'
    elif cc_have netstat; then
        netstat -tanp 2>/dev/null | awk '$1 ~ /^tcp/ && ($6 == "ESTABLISHED" || $6 == "SYN_SENT") {
            pr = "-"; pid = "-"; if ($7 ~ /^[0-9]+\//) { pid = $7; sub(/\/.*/, "", pid); pr = $7; sub(/^[0-9]+\//, "", pr) }
            print $4, $5, pr, pid }'
    fi | awk -v lp=" $_lp " -v adm=" $ADMIN_PORTS " -v team="$TEAM" '
        function ip4(s,   a, n) { n = split(s, a, "."); if (n != 4) return -1; return ((a[1] * 256 + a[2]) * 256 + a[3]) * 256 + a[4] }  # awk: posix-ok
        function hp(s,   h, p) { p = s; sub(/.*:/, "", p); h = s; sub(/:[^:]*$/, "", h); gsub(/[][]/, "", h); sub(/%.*/, "", h); sub(/^::[fF][fF][fF][fF]:/, "", h); H = h; P = p }  # awk: posix-ok
        function inteam(ip,   i, j, t, net, bits, d, v, nv, x) {  # awk: posix-ok (no "^": busybox awk may lack math)
            for (i = 1; i <= nt; i++) {
                t = tm[i]; net = t; bits = -1
                x = index(t, "/"); if (x) { net = substr(t, 1, x - 1); bits = substr(t, x + 1) + 0 }
                if (net == ip) return 1
                v = ip4(ip); nv = ip4(net)
                if (v >= 0 && nv >= 0 && bits >= 0) { d = 1; for (j = bits; j < 32; j++) d = d * 2; if (int(v / d) == int(nv / d)) return 1 }
                else if (v < 0 && bits >= 0) { sub(/:+$/, "", net); if (net != "" && index(tolower(ip), tolower(net) ":") == 1) return 1 }
            }
            return 0
        }
        function shellish(p) { return p ~ /^(sh|bash|dash|zsh|ksh|ksh93|mksh|ash|csh|tcsh|busybox|nc|ncat|netcat|nc\..*|socat|telnet|python[0-9.]*|perl[0-9.]*|php[0-9.]*|php-cgi.*|ruby[0-9.]*|lua[0-9.]*|awk|gawk|mawk|openssl|sshpass)$/ }  # awk: posix-ok
        BEGIN { nt = split(team, tm, " ") }
        {   hp($1); la = H; lport = P; hp($2); pa = H; pport = P; pr = $3; pid = $4
            if (pa ~ /^127\./ || pa == "::1" || pa == "0.0.0.0" || pa == "*" || pa == la) next
            if (nt > 0 && inteam(pa)) next
            if (index(lp, " " lport " ")) {
                if (index(adm, " " lport " ") || shellish(pr)) print "in " pa " -> " lport "|in|" pa "|" pport "|" lport "|" pr "|" pid
            } else print "out " pa ":" pport " " pr "|out|" pa "|" pport "|" lport "|" pr "|" pid
        }' | sort -t'|' -k1,1 -u >"$1/conns"
}

# ---- Compare ----------------------------------------------------------------------
SECTIONS="users passwords groups files cron units running keys ports suid web modules"
# compare OLD NEW -> "SEVERITY|section|change|item|detail" lines for every
#   difference, with a plain-words explanation and the severity rules.
compare() {
    for _s in $SECTIONS; do
        [ -f "$1/$_s" ] && [ -f "$2/$_s" ] || continue
        # FILENAME, not NR == FNR: with an empty OLD file, NR == FNR would
        # also be true for every line of the NEW file.
        awk -F'|' -v sec="$_s" -v oldf="$1/$_s" '
            FILENAME == oldf { old[$1] = $2; next }
            { new[$1] = $2; if (!($1 in old)) out("added", $1, "", $2); else if (old[$1] != $2) out("changed", $1, old[$1], $2) }
            END { for (k in old) if (!(k in new)) out("removed", k, old[k], "") }
            function nologin(s) { return s == "" || s ~ /(nologin|false|sync|shutdown|halt)$/ }  # awk: posix-ok
            function listdiff(x, y,   a, b, n, m, i, r) {  # names in x but not in y; awk: posix-ok
                n = split(x, a, ","); m = split(y, b, ","); r = ""
                for (i = 1; i <= m; i++) seen[b[i]] = 1
                for (i = 1; i <= n; i++) if (a[i] != "" && !(a[i] in seen)) r = r (r == "" ? "" : ", ") a[i]
                for (i = 1; i <= m; i++) delete seen[b[i]]
                return r
            }
            function out(c, k, o, n,   sev, d, a, b, adm, plus, minus, why, code, pp) {  # awk, not shell: posix-ok
                sev = "MED"; d = ""
                if (sec == "users") {
                    split(n, a, ":"); split(o, b, ":")
                    if (c == "added") { sev = "HIGH"; d = "new account: uid " a[1] ", home " a[3] ", shell " a[4] (a[1] == "0" ? " - UID 0 means it IS root" : "") }
                    else if (c == "removed") d = "account deleted (was uid " b[1] ")"
                    else if (a[1] == "0" && b[1] != "0") { sev = "HIGH"; d = "now has UID 0 - a second root account (was uid " b[1] ")" }
                    else if (nologin(b[4]) && !nologin(a[4])) { sev = "HIGH"; d = "can now log in: shell " (b[4] == "" ? "(none)" : b[4]) " -> " a[4] }
                    else d = "account details changed (uid:gid:home:shell " o " -> " n ")"
                } else if (sec == "passwords") {
                    if (c != "changed") return
                    if (n == "EMPTY") { sev = "HIGH"; d = "password REMOVED - anyone can log in as this account with no password" }
                    else if (n == "LOCKED") { sev = "LOW"; d = "account locked" }
                    else if (o == "LOCKED" || o == "EMPTY") { d = "account unlocked and given a password - fine if your team did it" }
                    else d = "password changed - fine if your team did it; if not, someone has a way in"
                } else if (sec == "groups") {
                    split(n, a, ":"); split(o, b, ":")
                    adm = (k ~ /^(sudo|wheel|admin|root|adm|docker|lxd|disk|shadow|sudoers)$/)
                    if (c == "added") { sev = adm ? "HIGH" : "LOW"; d = "new group (gid " a[1] (a[2] != "" ? ", members " a[2] : "") ")" }
                    else if (c == "removed") { sev = "LOW"; d = "group deleted" }
                    else {
                        plus = listdiff(a[2], b[2]); minus = listdiff(b[2], a[2])
                        d = (plus != "" ? "added: " plus : "") (minus != "" ? (plus != "" ? "; " : "") "removed: " minus : "")
                        if (d == "") d = "gid " b[1] " -> " a[1]
                        if (adm) { sev = (plus != "") ? "HIGH" : "MED"; d = d " - members of this group are admins" } else sev = "LOW"
                    }
                } else if (sec == "files") {
                    why = "config file"
                    if (k ~ /sudoers/) why = "sudo rules (who can become root)"
                    else if (k ~ /doas/) why = "doas rules (who can become root)"
                    else if (k ~ /apk\/(repositories|keys)/) why = "where packages come from (apk)"
                    else if (k ~ /pam\.d|security\//) why = "login checks (PAM)"
                    else if (k ~ /ld\.so\.preload/) why = "code loaded into EVERY program"
                    else if (k ~ /ld\.so\.conf/) why = "where programs load libraries from"
                    else if (k ~ /(profile|bashrc|bash_profile|ashrc|environment)/) why = "runs at every login"
                    else if (k ~ /hosts$/) why = "name lookups (/etc/hosts)"
                    else if (k ~ /(resolv\.conf|nsswitch)/) why = "DNS / name lookup settings"
                    else if (k ~ /sshd_config/) why = "SSH server settings"
                    else if (k ~ /sysctl/) why = "kernel settings"
                    sev = (k ~ /(sudoers|doas|pam\.d|ld\.so\.preload|security\/|apk\/keys)/ || c == "added") ? "HIGH" : "MED"
                    d = why ": file " c
                } else if (sec == "cron") {
                    sev = (c == "removed") ? "LOW" : "HIGH"
                    d = (k ~ /^timer /) ? "systemd timer " c : "scheduled job file " c
                    if (c != "removed" && k !~ /^timer /) d = d " - look at what it runs"
                } else if (sec == "units") {
                    sev = (c == "added") ? "HIGH" : (c == "removed" ? "LOW" : "MED")
                    if (k ~ /^\/etc\/runlevels\//) d = "starts at boot (OpenRC runlevel): " c (c == "added" ? " - is this service yours?" : "")
                    else if (k ~ /^\/etc\/local\.d\//) d = "runs at boot (OpenRC local.d) " c (c == "removed" ? "" : " - look at what it runs")
                    else d = "boot service file " c (c == "removed" ? "" : (k ~ /init\.d|conf\.d/ ? " - check what it starts" : " - check its ExecStart line"))
                } else if (sec == "running") {
                    if (c == "added") { sev = "LOW"; d = "service started" }
                    else if (k ~ /^(auditd|rsyslog|syslog|syslog-ng|systemd-journald|splunk.*|SplunkForwarder|wazuh.*|ossec.*|osqueryd|falco.*|fail2ban|sysmon.*|auditbeat|filebeat|crowdsec)(\.service)?$/) { sev = "HIGH"; d = "logging or security service STOPPED - the red team may be hiding something" }
                    else d = "service stopped running - if it is scored, it is down"
                } else if (sec == "keys") {
                    sev = (c == "removed") ? "MED" : "HIGH"
                    if (c == "added") d = "new SSH key file (" n ") - lets someone log in with a key, no password"
                    else if (c == "changed") d = "SSH keys changed (" o " -> " n ")"
                    else d = "SSH key file removed"
                } else if (sec == "ports") {
                    split(k, pp, " ")
                    if (c == "added") { sev = (pp[3] ~ /^(1337|4444|4445|5555|6666|6667|9001|12345|31337|54321|2375)$/) ? "HIGH" : "MED"; d = "new program listening: " (n == "" ? "(program unknown)" : n) }
                    else if (c == "removed") d = "stopped listening (" (o == "" ? "?" : o) ") - if it is scored, it is down"
                    else { sev = (o != "") ? "HIGH" : "MED"; d = "a different program now listens here: " n " (was " o ")" }
                } else if (sec == "suid") {
                    sev = (c == "added") ? "HIGH" : (c == "removed" ? "LOW" : "MED")
                    d = (c == "added") ? "new SUID/SGID program - runs with its owner rights for anyone; a common way back to root" : "SUID/SGID program " c
                } else if (sec == "web") {
                    code = (k ~ /\.(php[0-9]?|phtml|phar|jsp|jspx|asp|aspx|cgi|pl|py|sh)$/)
                    if (c == "added") { sev = code ? "HIGH" : "MED"; d = code ? "new program file in a web root (web shell?)" : "new file in a web root" }
                    else if (c == "removed") d = "file removed from a web root (defaced or deleted?)"
                    else { sev = code ? "MED" : "LOW"; d = "file changed (size/time " o " -> " n ")" }
                } else if (sec == "modules") {
                    sev = (c == "added") ? "HIGH" : "LOW"
                    d = (c == "added") ? "kernel module loaded - rootkits load as modules (check: modinfo " k ")" : "kernel module unloaded"
                }
                print sev "|" sec "|" c "|" k "|" d
            }' "$1/$_s" "$2/$_s"
    done
}

# enrich_ports NEWDIR <alerts >alerts: a new listener gets its pid, user and
#   command line; a shell-like program or one in /tmp makes it HIGH.
enrich_ports() {
    while IFS='|' read -r _sev _sec _chg _item _det; do
        if [ "$_sec" = ports ] && [ "$_chg" != removed ]; then
            _pid=$(awk -F'|' -v k="$_item" '$1 == k { print $2; exit }' "$1/ports.pid")
            _prog=$(awk -F'|' -v k="$_item" '$1 == k { print $2; exit }' "$1/ports")
            proc_info "$_pid"
            [ -n "$_pid" ] && _det="$_det; pid $_pid${PR_USER:+, user $PR_USER}${PR_CMD:+, runs: $PR_CMD}"
            if shellish "$_prog" || badexe "$PR_EXE" || badexe "$PR_CMD"; then
                _sev=HIGH; _det="$_det - a shell, script interpreter or temp-folder program listening: a backdoor"
            fi
        fi
        printf '%s|%s|%s|%s|%s\n' "$_sev" "$_sec" "$_chg" "$_item" "$_det"
    done
}

# new_conns NEWDIR -> alert lines for connections not reported before; each
#   one is added to conns-seen and to connections.csv.
new_conns() {
    [ -f "$1/conns" ] || return 0
    awk -F'|' -v seenf="$STATE/conns-seen" 'FILENAME == seenf { s[$0] = 1; next } !($1 in s)' "$STATE/conns-seen" "$1/conns" >"$W/conns.new"
    while IFS='|' read -r _key _dir _addr _port _lport _prog _pid; do
        printf '%s\n' "$_key" >>"$STATE/conns-seen"
        [ "$_prog" = - ] && _prog=""; [ "$_pid" = - ] && _pid=""
        proc_info "$_pid"
        _who="${_prog:-unknown program}${_pid:+ (pid $_pid${PR_USER:+, user $PR_USER})}${PR_CMD:+ runs: $PR_CMD}"
        if [ "$_dir" = out ]; then
            _sev=MED; _det="new outgoing connection from $_who"
            case "$_prog" in
                apt|apt-get|http|https|dnf|yum|packagekitd|snapd|unattended-upgr*|systemd-resolve*|systemd-timesyn*|chronyd|ntpd|splunkd|fwupd*|dhclient|NetworkManager|sssd*|freshclam)
                    _sev=LOW; _det="$_det (updates/agent - usually fine)" ;;
            esac
            if shellish "$_prog" || badexe "$PR_EXE" || badexe "$PR_CMD"; then
                _sev=HIGH; _det="$_det - a shell, script interpreter or temp-folder program calling out: REVERSE SHELL?"
            elif backdoor_port "$_port"; then
                _sev=HIGH; _det="$_det - port $_port is a classic attacker port"
            elif webuser "$PR_USER"; then
                case "$_prog" in apache2|httpd|nginx|lighttpd|php-fpm*) _sev=MED; _det="$_det - the web server calling out: check it is a known backend" ;;
                    *) _sev=HIGH; _det="$_det - the web server account calling out: a web shell?" ;;
                esac
            fi
            _item="$_addr:$_port"
        else
            _det="new address connected to port $_lport (${_prog:-program unknown})"
            _sev=MED
            if shellish "$_prog" || badexe "$PR_EXE"; then _sev=HIGH; _det="$_det - someone is connected to a shell-like program: a bind shell in use?"; fi
            _item="$_addr -> port $_lport"
        fi
        printf '%s|connections|%s|%s|%s\n' "$_sev" "$_dir" "$_item" "$_det"
        cc_csv_row "$CONNCSV" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$_dir" "$_addr" "$_port" "$_lport" "$_prog" "$_pid" "$PR_USER" "$PR_CMD" "$_sev"
    done <"$W/conns.new"
}

# adopt NEWDIR -> sections the baseline does not have yet (a scan turned on
#   later, an older baseline, a new web root) become part of the baseline,
#   so they are not reported as one big "added".
adopt() {
    for _s in $SECTIONS; do
        if [ -f "$1/$_s" ] && [ ! -f "$STATE/baseline/$_s" ]; then
            cp "$1/$_s" "$STATE/baseline/$_s"; cp "$1/$_s" "$STATE/last/$_s"
            cc_show "$C_GRY" "  ($_s: added to the baseline as it is now)"
        fi
    done
    [ -f "$STATE/baseline/.webroots" ] || cp "$W/webroots" "$STATE/baseline/.webroots"
    if :; then
        awk 'FILENAME == ARGV[1] { o[$0] = 1; next } !($0 in o)' "$STATE/baseline/.webroots" "$W/webroots" >"$W/webnew"
        if [ -s "$W/webnew" ]; then
            for _b in "$STATE/baseline" "$STATE/last"; do
                awk -F'|' 'FILENAME == ARGV[1] { r[$0] = 1; next } { for (x in r) if (index($1, x "/") == 1) { print; next } }' "$W/webnew" "$1/web" >>"$_b/web"
                sort -u -o "$_b/web" "$_b/web"; cp "$W/webroots" "$_b/.webroots"
            done
            cc_show "$C_GRY" "  (new web folder(s) added to the baseline: $(tr '\n' ' ' <"$W/webnew"))"
        fi
    fi
    if [ "$CONNS" = 1 ] && [ ! -f "$STATE/conns-seen" ]; then
        cut -d'|' -f1 "$1/conns" >"$STATE/conns-seen"
        cc_show "$C_GRY" "  (connections: $(grep -c . "$STATE/conns-seen") open now are taken as normal; new ones from here on are reported)"
    fi
}

ALCSV=$(cc_csv_new alerts "time,severity,section,change,item,detail")
CONNCSV=$(cc_csv_new connections "time,direction,address,port,local_port,program,pid,user,command,severity")
N_H=0; N_M=0; N_L=0; NCHECK=0; STOP=0

# ---- Baseline ------------------------------------------------------------------------
DOSUID=1    # 1 = this snapshot scans for SUID/SGID files
header "2/3  baseline"
if [ "$BASEMODE" = new ]; then
    cc_show "" "  Taking a baseline of how the box looks now ..."
    snap "$STATE/baseline"
    date -u +%Y-%m-%dT%H:%M:%SZ >"$STATE/baseline/.taken"
    rm -rf "$STATE/last"; cp -R "$STATE/baseline" "$STATE/last"
    : >"$STATE/changes-since-baseline.txt"
    rm -f "$STATE/conns-seen"
    [ "$CONNS" = 1 ] && cut -d'|' -f1 "$STATE/baseline/conns" >"$STATE/conns-seen"
    printf '%s BASELINE taken (%s)\n' "$(cat "$STATE/baseline/.taken")" "$(for _s in $SECTIONS; do [ -f "$STATE/baseline/$_s" ] && printf '%s %s, ' "$_s" "$(grep -c . "$STATE/baseline/$_s")"; done | sed 's/, $//')" >>"$ALERTS"
    BASETIME=$(cat "$STATE/baseline/.taken")
    cc_show "$C_GRN" "  [ok] baseline taken at $BASETIME"
else
    [ -d "$STATE/last" ] || cp -R "$STATE/baseline" "$STATE/last"
    cc_show "$C_GRN" "  [ok] using the baseline from ${BASETIME:-earlier}"
fi
_bl=""
for _s in $SECTIONS conns; do
    _f="$STATE/baseline/$_s"; [ "$_s" = conns ] && _f="$STATE/conns-seen"
    [ "$_s" = conns ] && [ "$CONNS" != 1 ] && continue
    [ -f "$_f" ] && _bl="$_bl$_s $(grep -c . "$_f"), "
done
cc_show "" "  What it holds: $(printf '%s' "$_bl" | sed 's/, $//')"

# ---- Checks --------------------------------------------------------------------------
header "3/3  checks$([ "$LOOP" -gt 0 ] && echo " every $LOOP seconds - Ctrl-C stops")"
# show_alert SEV SECTION CHANGE ITEM DETAIL -> two lines on screen, coloured.
show_alert() {
    case "$1" in
        HIGH) _c=$C_RED; _m='[!]' ;;
        MED)  _c=$C_YEL; _m='[*]' ;;
        *)    _c=$C_GRY; _m='[-]' ;;
    esac
    cc_show "$_c" "  $_m $(printf '%-4s %-11s %-7s' "$1" "$2" "$3") $4"
    cc_show "$_c" "        $5"
}
trap 'STOP=1' INT TERM
: >"$W/all"
if [ "$BASEMODE" = new ] && [ "$LOOP" = 0 ]; then
    cc_show "" "  Baseline only (nothing can have changed yet). Run again to check, or use --loop 60."
    STOP=1
fi
while [ "$STOP" = 0 ]; do
    NCHECK=$((NCHECK + 1))
    DOSUID=1
    [ "$LOOP" -gt 0 ] && [ $(((NCHECK - 1) % SUIDEVERY)) -ne 0 ] && DOSUID=0
    snap "$STATE/now"
    if [ "$STOP" = 1 ]; then rm -rf "$STATE/now"; NCHECK=$((NCHECK - 1)); break; fi
    adopt "$STATE/now"
    { compare "$STATE/last" "$STATE/now" | enrich_ports "$STATE/now"
      [ "$CONNS" = 1 ] && new_conns "$STATE/now"; } >"$W/new"
    _t=$(date -u +%Y-%m-%dT%H:%M:%SZ); _tl=$(date +%H:%M:%S)
    # HIGH first, then MED, then LOW.
    awk -F'|' '{ r = ($1 == "HIGH") ? 1 : ($1 == "MED" ? 2 : 3); print r "|" $0 }' "$W/new" | sort -t'|' -k1,1n -k3,3 | cut -d'|' -f2- >"$W/new.sorted"
    cat "$W/new.sorted" >>"$W/all"
    _n=$(grep -c . "$W/new.sorted"); _h=$(grep -c '^HIGH' "$W/new.sorted"); _m=$(grep -c '^MED' "$W/new.sorted"); _l=$((_n - _h - _m))
    N_H=$((N_H + _h)); N_M=$((N_M + _m)); N_L=$((N_L + _l))
    if [ "$_n" -gt 0 ]; then
        _hc=$C_YEL; [ "$_h" -gt 0 ] && _hc=$C_RED; [ "$_h" = 0 ] && [ "$_m" = 0 ] && _hc=$C_GRY
        cc_show "$_hc" "$_tl  check $NCHECK: $_n change(s) - $_h HIGH, $_m MED, $_l LOW"
        awk -F'|' -v t="$_t" '{ d = $5; for (i = 6; i <= NF; i++) d = d "|" $i; printf "%s %-4s %-11s %-7s %s - %s\n", t, $1, $2, $3, $4, d }' "$W/new.sorted" >"$W/lines"
        cat "$W/lines" >>"$ALERTS"
        _i=0
        while IFS='|' read -r _sev _sec _chg _item _det; do
            cc_csv_row "$ALCSV" "$_t" "$_sev" "$_sec" "$_chg" "$_item" "$_det"
            _i=$((_i + 1))
            [ "$_i" -le 40 ] && show_alert "$_sev" "$_sec" "$_chg" "$_item" "$_det"
        done <"$W/new.sorted"
        [ "$_n" -gt 40 ] && cc_show "$C_GRY" "  ... $((_n - 40)) more in $CC_RUN_DIR/alerts.txt"
        if [ -n "$ALERTCMD" ]; then
            sh -c "$ALERTCMD" <"$W/lines" >>"$CC_LOG" 2>&1 || cc_show "$C_YEL" "  [!] --alert-cmd failed (exit $?): the alerts are still in $ALERTS"
        fi
    else
        cc_show "$C_GRN" "$_tl  check $NCHECK: [ok] no changes"
    fi
    compare "$STATE/baseline" "$STATE/now" | sort |
        awk -F'|' '{ d = $5; for (i = 6; i <= NF; i++) d = d "|" $i; printf "%-4s %-11s %-7s %s - %s\n", $1, $2, $3, $4, d }' >"$STATE/changes-since-baseline.txt"
    rm -rf "$STATE/last"; mv "$STATE/now" "$STATE/last"
    [ "$STOP" = 1 ] && break
    [ "$LOOP" -gt 0 ] || break
    [ "$COUNT" -gt 0 ] && [ "$NCHECK" -ge "$COUNT" ] && break
    sleep "$LOOP"
    [ "$STOP" = 1 ] && break
done
trap 'cc_log ERROR "interrupted"; exit 130' INT TERM

# ---- Summary -----------------------------------------------------------------------
cc_csv_pretty "$ALCSV" "$CC_RUN_DIR/alerts.txt" 110
cc_csv_pretty "$CONNCSV" "$CC_RUN_DIR/connections.txt" 80
NDIFF=$(grep -c . "$STATE/changes-since-baseline.txt" 2>/dev/null)
{
    printf '==========[ Summary ]==========\n'
    printf 'Host %s | %s check(s) | baseline from %s\n' "$CC_HOST" "$NCHECK" "${BASETIME:-?}"
    printf 'This run: %s HIGH, %s MED, %s LOW alert(s)\n' "$N_H" "$N_M" "$N_L"
    if [ $((N_H + N_M + N_L)) -gt 0 ]; then
        printf '\nAlerts this run by section:\n'
        cut -d'|' -f1,2 "$W/all" | sort | uniq -c | sort -k1,1nr |
            awk '{ split($2, a, "|"); printf "  %-4s %-11s %s\n", a[1], a[2], $1 }'
    fi
    printf '\nDifferent from the baseline right now: %s item(s)%s\n' "$NDIFF" "$([ "$NDIFF" -gt 0 ] && echo " - see $STATE/changes-since-baseline.txt")"
    if [ "$NDIFF" -gt 0 ]; then
        grep -E '^(HIGH|MED)' "$STATE/changes-since-baseline.txt" | head -n 15 | sed 's/^/  /'
        [ "$(grep -cE '^(HIGH|MED)' "$STATE/changes-since-baseline.txt")" -gt 15 ] && printf '  ...\n'
    fi
    printf '\nFiles:\n'
    printf '  %s/alerts.txt        this run'"'"'s alerts\n' "$CC_RUN_DIR"
    [ "$CONNS" = 1 ] && printf '  %s/connections.txt   new connections seen\n' "$CC_RUN_DIR"
    printf '  %s   every alert ever\n' "$ALERTS"
    printf '\nNext: if the changes are your own, run with --accept so they stop showing.\n'
} >"$CC_RUN_DIR/summary.txt"
cc_show "" ""
while IFS= read -r _line; do
    case "$_line" in
        ==*) cc_show "$C_CYN" "$_line" ;;
        'This run:'*) if [ "$N_H" -gt 0 ]; then cc_show "$C_RED" "$_line"; elif [ "$N_M" -gt 0 ]; then cc_show "$C_YEL" "$_line"; else cc_show "$C_GRN" "$_line"; fi ;;
        '  HIGH'*) cc_show "$C_RED" "$_line" ;;
        '  MED'*) cc_show "$C_YEL" "$_line" ;;
        *) cc_show "" "$_line" ;;
    esac
done <"$CC_RUN_DIR/summary.txt"
rm -rf "$W"
cc_finish
