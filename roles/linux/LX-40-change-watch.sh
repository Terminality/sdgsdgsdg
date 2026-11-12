#!/bin/sh
# =============================================================================
# ID:       LX-40
# NAME:     Linux change watch
# ROLE:     Linux  (wave 2, first 15 minutes - start it once the box is hardened)
# KIND:     readonly - changes nothing on the host
# VERSION:  1.0.0
#
# PURPOSE
#   Takes a quick baseline of the places red teams use to keep access, then
#   checks again - once, or every N seconds - and raises an alert for each
#   change:
#     users      accounts added, removed, or changed (UID 0, shell, home)
#     passwords  a password changed (stored as a short fingerprint of the
#                shadow field, never the hash itself)
#     groups     members of every group (sudo, wheel, docker... are HIGH)
#     files      sudoers, PAM, ld.so.preload, profile and shell startup
#                files, hosts, resolv.conf, sshd_config, sysctl files
#     cron       crontabs and cron folders, at/anacron spools, systemd timers
#     units      systemd unit files, init.d scripts, rc.local
#     keys       every account's authorized_keys files
#     ports      listening TCP/UDP ports and their programs
#     suid       SUID/SGID programs (skip with --no-suid)
#     web        files in web roots: added, removed, changed (size or time)
#     modules    loaded kernel modules
#   Each check alerts only on what changed since the PREVIOUS check, so one
#   change is reported once; changes-since-baseline.txt keeps the full list.
#
# USAGE
#   sudo sh LX-40-change-watch.sh --baseline           take the baseline
#   sudo sh LX-40-change-watch.sh                      one check now
#   sudo sh LX-40-change-watch.sh --loop 60            check every 60 s (Ctrl-C stops)
#   nohup sudo sh LX-40-change-watch.sh --loop 60 --alert-cmd "ssh admin@10.0.0.5 'cat >>/srv/alerts/web01.log'" &
#   sudo sh LX-40-change-watch.sh --accept             your own changes become the baseline
#
# OPTIONS
#   --baseline         take a new baseline (replaces the old one)
#   --accept           same as --baseline: use after reviewing your own changes
#   --loop N           check every N seconds until stopped
#   --count N          with --loop: stop after N checks
#   --webroot DIR      also watch DIR (repeat); the usual web roots are watched
#   --no-suid          skip the SUID/SGID scan (it reads the whole disk)
#   --alert-cmd CMD    run CMD (with sh -c) after each check that found
#                      changes; the new alert lines arrive on its stdin
#   --state DIR        where the baseline lives (default <out>/watch-<host>)
#   --root DIR         treat DIR as / for the file sections (tests)
#   --help             this text plus the common options
#
# OUTPUTS  (in the state folder, <out>/watch-<host>/ by default)
#   alerts.log                 every alert, newest at the bottom:
#                              time SEVERITY section change item detail
#   changes-since-baseline.txt everything that differs from the baseline now
#   baseline/, last/           the snapshots (text files, no secrets)
#
# WHAT IT CHANGES
#   Nothing on the host.  It reads files and runs read-only commands.
#
# DEPENDS ON
#   awk, find, ls; sha256sum (or shasum / sha256 / openssl); ss or netstat;
#   systemctl for timers (optional).  CCDC_SS may name a stand-in ss.
#
# TESTED ON
#   Ubuntu 24.04 under dash, bash, busybox sh, ksh93, mksh and yash on a fake
#   root, and live: a planted account, cron job, SSH key, listener and web
#   shell were each reported once.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - It sees changes, not intent: your own hardening shows up too.  After
#     changing things on purpose, run --accept.
#   - Web files are compared by size and modification time, not content (to
#     stay fast).  A red team that keeps both the same is not seen here; the
#     backup's hash list (LX-31) catches that.
#   - A red team with root can stop or fool this script.  Send alerts off the
#     box with --alert-cmd.
#
# DEBUGGING
#   --debug shows how many items each section found.  The snapshots in
#   baseline/ and last/ are plain text: diff them by hand.
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

usage() {
    cat <<'USAGE'
LX-40 Linux change watch - alert on new accounts, keys, cron jobs, ports, files
  sudo sh LX-40-change-watch.sh [--baseline | --accept] [options]

  --baseline         take a new baseline
  --accept           make the current state the baseline (after your own changes)
  --loop N           check every N seconds until stopped
  --count N          with --loop: stop after N checks
  --webroot DIR      also watch DIR (repeatable)
  --no-suid          skip the SUID/SGID scan
  --alert-cmd CMD    run CMD with new alerts on stdin (send them off the box)
  --state DIR        baseline folder (default <out>/watch-<host>)
  --root DIR         treat DIR as / (tests)
  --help             show this text

USAGE
    cc_usage_common
}

NL='
'
DOBASE=0; LOOP=0; COUNT=0; WEBROOTS=""; NOSUID=0; ALERTCMD=""; STATE=""; R=""
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --baseline|--accept) DOBASE=1; shift ;;
        --loop)      [ $# -ge 2 ] || cc_die 2 "--loop needs seconds"; LOOP=$2; shift 2 ;;
        --count)     [ $# -ge 2 ] || cc_die 2 "--count needs a number"; COUNT=$2; shift 2 ;;
        --webroot)   [ $# -ge 2 ] || cc_die 2 "--webroot needs a folder"; [ -d "$2" ] || cc_die 2 "--webroot: not a folder: $2"
                     WEBROOTS="$WEBROOTS$(cc_abspath "$2")$NL"; shift 2 ;;
        --no-suid)   NOSUID=1; shift ;;
        --alert-cmd) [ $# -ge 2 ] || cc_die 2 "--alert-cmd needs a command"; ALERTCMD=$2; shift 2 ;;
        --state)     [ $# -ge 2 ] || cc_die 2 "--state needs a folder"; STATE=$2; shift 2 ;;
        --root)      [ $# -ge 2 ] || cc_die 2 "--root needs a folder"; [ -d "$2" ] || cc_die 2 "--root: not a folder: $2"
                     R=$(cd "$2" && pwd); [ "$R" = / ] && R=""; shift 2 ;;
        --help|-h)   usage; exit 0 ;;
        *)           cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
case "$LOOP" in ''|*[!0-9]*) cc_die 2 "--loop needs a whole number of seconds" ;; esac
case "$COUNT" in ''|*[!0-9]*) cc_die 2 "--count needs a whole number" ;; esac
[ "$LOOP" -gt 0 ] && [ "$LOOP" -lt 10 ] && cc_die 2 "--loop must be at least 10 seconds"

cc_init "LX-40" "Linux change watch" readonly
cc_detect_os
IS_ROOT=0
cc_is_root && IS_ROOT=1
[ "$IS_ROOT" = 1 ] || [ -n "$R" ] || cc_warn "not running as root: password, key and some cron changes cannot be seen"
[ -n "$STATE" ] || STATE="$CC_OUT/watch-$CC_HOST"
(umask 077; mkdir -p "$STATE") || cc_die 3 "cannot create $STATE"
STATE=$(cc_abspath "$STATE")
SS=${CCDC_SS:-$(cc_which ss)} || SS=""
ALERTS="$STATE/alerts.log"

# The usual web roots plus --webroot, nested ones dropped.
{
    for _d in /var/www /srv/www /srv/http /usr/share/nginx/html /usr/local/www /opt/lampp/htdocs; do printf '%s\n' "$R$_d"; done
    printf '%s' "$WEBROOTS"
} | sed 's|/*$||' | grep . | sort -u | awk '{ for (k in keep) if (index($0, k "/") == 1) next; keep[$0] = 1; print }' >"$STATE/.webroots"

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

# snap DIR -> write one sorted "key|value" file per section into DIR.
snap() {
    _sd=$1; rm -rf "$_sd"; mkdir -p "$_sd"
    # users: name -> uid:gid:home:shell
    awk -F: '{ print $1 "|" $3 ":" $4 ":" $6 ":" $7 }' "$R/etc/passwd" 2>/dev/null | sort >"$_sd/users"
    # passwords: a 12-character fingerprint of each shadow field (a hash of the
    # hash), so a change is visible but nothing usable is stored.
    : >"$_sd/passwords"
    if [ -r "$R/etc/shadow" ]; then
        awk -F: '{ print $1 "\t" $2 }' "$R/etc/shadow" | while IFS="$(printf '\t')" read -r _u _f; do
            printf '%s|%s\n' "$_u" "$(printf '%s' "$_f" | cksum | awk '{ printf "%012d", $1 % 1000000000000 }')"
        done | sort >"$_sd/passwords"
    fi
    # groups: name -> gid:members
    awk -F: '{ print $1 "|" $3 ":" $4 }' "$R/etc/group" 2>/dev/null | sort >"$_sd/groups"
    # files: configuration that changes how logins and programs behave
    hashlist "$R/etc/sudoers" "$R/etc/sudoers.d" "$R/etc/pam.d" "$R/etc/security" "$R/etc/ld.so.preload" \
             "$R/etc/ld.so.conf" "$R/etc/ld.so.conf.d" "$R/etc/profile" "$R/etc/profile.d" "$R/etc/bash.bashrc" \
             "$R/etc/bashrc" "$R/etc/environment" "$R/etc/hosts" "$R/etc/resolv.conf" "$R/etc/nsswitch.conf" \
             "$R/etc/ssh/sshd_config" "$R/etc/ssh/sshd_config.d" "$R/etc/sysctl.conf" "$R/etc/sysctl.d" \
             "$R/root/.bashrc" "$R/root/.profile" "$R/root/.bash_profile" | sort >"$_sd/files"
    # cron: every cron and at file, plus systemd timers by name
    { hashlist "$R/etc/crontab" "$R/etc/cron.d" "$R/etc/cron.hourly" "$R/etc/cron.daily" "$R/etc/cron.weekly" \
               "$R/etc/cron.monthly" "$R/var/spool/cron" "$R/var/spool/at" "$R/var/spool/anacron" "$R/etc/anacrontab"
      if [ -z "$R" ] && [ "$CC_INIT" = systemd ]; then
          systemctl list-timers --all --no-legend --no-pager 2>/dev/null | awk '{ for (i = 1; i <= NF; i++) if ($i ~ /\.timer$/) print "timer " $i "|" }'
      fi; } | sort -u >"$_sd/cron"
    # units: services that start at boot
    hashlist "$R/etc/systemd/system" "$R/lib/systemd/system" "$R/usr/lib/systemd/system" "$R/etc/init.d" \
             "$R/etc/rc.local" "$R/etc/rc.d" | sort >"$_sd/units"
    # keys: every authorized_keys file of every account
    awk -F: '$6 != "" { print $6 }' "$R/etc/passwd" 2>/dev/null | sort -u | while IFS= read -r _h; do
        for _k in "$R$_h/.ssh/authorized_keys" "$R$_h/.ssh/authorized_keys2"; do [ -f "$_k" ] && printf '%s\n' "$_k"; done
    done >"$STATE/.keyfiles"
    : >"$_sd/keys"
    while IFS= read -r _k; do
        _n=$(grep -c '^[^#]' "$_k" 2>/dev/null)
        printf '%s|%s %s keys\n' "${_k#"$R"}" "$(hashlist "$_k" | cut -d'|' -f2)" "$_n" >>"$_sd/keys"
    done <"$STATE/.keyfiles"
    sort -o "$_sd/keys" "$_sd/keys"
    # ports: proto address port -> program
    : >"$_sd/ports"
    if [ -n "$SS" ]; then
        "$SS" -ltnup 2>/dev/null | awk 'NR > 1 && ($1 == "tcp" || $1 == "udp") {
            a = $5; p = a; sub(/.*:/, "", p); sub(/:[^:]*$/, "", a); gsub(/[][]/, "", a)
            pr = ""; if (match($0, /\(\("[^"]*"/)) pr = substr($0, RSTART + 3, RLENGTH - 4)
            print $1 " " a " " p "|" pr }' | sort -u >"$_sd/ports"
    elif cc_have netstat; then
        netstat -ltnu 2>/dev/null | awk '$1 ~ /^(tcp|udp)/ { a = $4; p = a; sub(/.*:/, "", p); sub(/:[^:]*$/, "", a); print substr($1, 1, 3) " " a " " p "|" }' | sort -u >"$_sd/ports"
    fi
    # suid: SUID/SGID programs anywhere on the root file system
    : >"$_sd/suid"
    if [ "$NOSUID" = 0 ]; then
        find "$R/" -xdev -type f \( -perm -4000 -o -perm -2000 \) -exec ls -ln {} + 2>/dev/null |
            awk -v r="$R" '{ p = $NF; if (r != "" && index(p, r) == 1) p = substr(p, length(r) + 1); print p "|" $1 " " $3 }' | sort >"$_sd/suid"
    fi
    # web: every file in the web roots by size and modification time
    : >"$_sd/web"
    while IFS= read -r _w; do
        [ -d "$_w" ] || continue
        find "$_w" -xdev -type f -exec ls -ln {} + 2>/dev/null |
            awk -v r="$R" '{ p = $9; for (i = 10; i <= NF; i++) p = p " " $i; if (r != "" && index(p, r) == 1) p = substr(p, length(r) + 1); print p "|" $5 " " $6 " " $7 " " $8 }' >>"$_sd/web"
    done <"$STATE/.webroots"
    sort -o "$_sd/web" "$_sd/web"
    # modules: loaded kernel modules
    if [ -r "$R/proc/modules" ]; then awk '{ print $1 "|" }' "$R/proc/modules" | sort >"$_sd/modules"; else : >"$_sd/modules"; fi
    for _s in users passwords groups files cron units keys ports suid web modules; do
        cc_debug "snapshot $_s: $(grep -c . "$_sd/$_s") items"
    done
}

# ---- Compare ----------------------------------------------------------------------
SECTIONS="users passwords groups files cron units keys ports suid web modules"
# compare OLD NEW -> "SEVERITY|section|change|item|detail" lines for every
#   difference, with the severity rules for each section.
compare() {
    for _s in $SECTIONS; do
        [ -f "$1/$_s" ] && [ -f "$2/$_s" ] || continue
        # FILENAME, not NR == FNR: with an empty OLD file, NR == FNR would
        # also be true for every line of the NEW file.
        awk -F'|' -v sec="$_s" -v oldf="$1/$_s" '
            FILENAME == oldf { old[$1] = $2; next }
            { new[$1] = $2; if (!($1 in old)) out("added", $1, "", $2); else if (old[$1] != $2) out("changed", $1, old[$1], $2) }
            END { for (k in old) if (!(k in new)) out("removed", k, old[k], "") }
            function out(c, k, o, n,   sev, d) {  # awk, not shell: posix-ok
                sev = "MED"; d = ""
                if (sec == "users") {
                    if (c == "added") { sev = "HIGH"; d = "new account (uid:gid:home:shell " n ")" }
                    else if (c == "removed") d = "account removed"
                    else { d = "was " o ", now " n; if (n ~ /^0:/) { sev = "HIGH"; d = "now UID 0 (root): " d } }
                } else if (sec == "passwords") {
                    if (c != "changed") return
                    d = "password changed - if the team did not do this, someone has a way in"
                } else if (sec == "groups") {
                    split(k, g, " "); sev = (k ~ /^(sudo|wheel|admin|root|adm|docker|lxd|disk|shadow|sudoers)$/) ? "HIGH" : "LOW"
                    d = (c == "changed") ? "members/gid were " o ", now " n : c
                } else if (sec == "files") {
                    sev = (k ~ /(sudoers|pam\.d|ld\.so\.preload|security\/)/ || c == "added") ? "HIGH" : "MED"
                    d = "file " c
                } else if (sec == "cron") {
                    sev = (c == "removed") ? "LOW" : "HIGH"; d = "scheduled job " c
                } else if (sec == "units") {
                    sev = (c == "added") ? "HIGH" : (c == "removed" ? "LOW" : "MED"); d = "boot service file " c
                } else if (sec == "keys") {
                    sev = (c == "removed") ? "MED" : "HIGH"; d = "SSH keys " c (n != "" ? " (" n ")" : "")
                } else if (sec == "ports") {
                    split(k, pp, " ")
                    if (c == "added") { sev = (pp[3] ~ /^(1337|4444|4445|5555|6666|6667|12345|31337|54321|2375)$/) ? "HIGH" : "MED"; d = "new listener (" n ")" }
                    else if (c == "removed") d = "stopped listening (" o ") - if it is scored, it is down"
                    else d = "now owned by " n " (was " o ")"
                } else if (sec == "suid") {
                    sev = (c == "added") ? "HIGH" : "MED"; d = "SUID/SGID program " c
                } else if (sec == "web") {
                    code = (k ~ /\.(php[0-9]?|phtml|phar|jsp|jspx|asp|aspx|cgi|pl|py|sh)$/)
                    if (c == "added") { sev = code ? "HIGH" : "MED"; d = code ? "new program file in a web root (web shell?)" : "new file in a web root" }
                    else if (c == "removed") d = "file removed from a web root (defaced or deleted?)"
                    else { sev = code ? "MED" : "LOW"; d = "file changed (size/time " o " -> " n ")" }
                } else if (sec == "modules") {
                    sev = (c == "added") ? "HIGH" : "LOW"; d = "kernel module " c
                }
                print sev "|" sec "|" c "|" k "|" d
            }' "$1/$_s" "$2/$_s"
    done
}

# ---- Run -----------------------------------------------------------------------------
if [ "$DOBASE" = 1 ] || [ ! -d "$STATE/baseline" ]; then
    [ "$DOBASE" = 1 ] || cc_info "no baseline yet in $STATE - taking one now"
    snap "$STATE/baseline"
    rm -rf "$STATE/last"; cp -R "$STATE/baseline" "$STATE/last"
    : >"$STATE/changes-since-baseline.txt"
    printf '%s BASELINE taken (%s)\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(for _s in $SECTIONS; do printf '%s %s, ' "$_s" "$(grep -c . "$STATE/baseline/$_s")"; done | sed 's/, $//')" >>"$ALERTS"
    cc_info "baseline: $(tail -n 1 "$ALERTS" | cut -c22-)"
    cc_info "state folder: $STATE"
    [ "$LOOP" -gt 0 ] || cc_finish
fi

_n=0
while :; do
    _n=$((_n + 1))
    snap "$STATE/now"
    compare "$STATE/last" "$STATE/now" | sort -t'|' -k1,1 >"$STATE/.new"
    _t=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    if [ -s "$STATE/.new" ]; then
        # HIGH first, then MED, then LOW.
        awk -F'|' -v t="$_t" '{ r = ($1 == "HIGH") ? 1 : ($1 == "MED" ? 2 : 3); printf "%d|%s %-4s %-9s %-7s %s - %s\n", r, t, $1, $2, $3, $4, $5 }' "$STATE/.new" |
            sort -t'|' -k1,1n | cut -d'|' -f2- >"$STATE/.lines"
        cat "$STATE/.lines" >>"$ALERTS"
        _h=$(grep -c '^HIGH' "$STATE/.new"); _m=$(grep -c '^MED' "$STATE/.new")
        printf '%s  %d change(s): %d HIGH, %d MED\n' "$_t" "$(grep -c . "$STATE/.new")" "$_h" "$_m"
        awk '{ l = "  " $0; if (length(l) > 220) l = substr(l, 1, 217) "..."; print l }' "$STATE/.lines" | head -n 40
        [ "$(grep -c . "$STATE/.lines")" -gt 40 ] && printf '  ... more in %s\n' "$ALERTS"
        if [ -n "$ALERTCMD" ]; then
            sh -c "$ALERTCMD" <"$STATE/.lines" >>"$CC_LOG" 2>&1 || cc_warn "--alert-cmd failed (exit $?): alerts are still in $ALERTS"
        fi
    else
        printf '%s  no changes\n' "$_t"
    fi
    compare "$STATE/baseline" "$STATE/now" | sort >"$STATE/changes-since-baseline.txt"
    rm -rf "$STATE/last"; mv "$STATE/now" "$STATE/last"
    [ "$LOOP" -gt 0 ] || break
    [ "$COUNT" -gt 0 ] && [ "$_n" -ge "$COUNT" ] && break
    sleep "$LOOP"
done
cc_info "alerts: $ALERTS ($(grep -c . "$STATE/changes-since-baseline.txt") differences from the baseline)"
cc_finish
