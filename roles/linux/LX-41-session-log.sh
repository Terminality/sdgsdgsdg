#!/bin/sh
# =============================================================================
# ID:       LX-41
# NAME:     Linux session & command logging
# ROLE:     Linux  (wave 2 - start it once the box is hardened, beside LX-40)
# KIND:     readonly - reads logs, changes nothing (unless --setup-auditd)
# VERSION:  1.0.0
#
# PURPOSE
#   Watches who logs in and what they run, saves it to log files, and prints
#   an alert to the console for anything that looks like the red team.  Pairs
#   with LX-40 (which watches config and persistence changes); this one
#   watches events: logins and commands.
#
#   It reads logs the box already keeps, so it changes nothing:
#     logins     ssh and console logins, the source address, failed logins
#                and brute force, new sessions and logouts   (the auth log)
#     priv       sudo and su use, and the command each sudo ran, and failures
#     commands   every command run, with user, tty and folder   (auditd)
#     web        a command by the web-server user (a web shell running), a
#                process running from /tmp or a web root, and the web access
#                log: requests to a dropped shell or with injection markers
#
#   Privileged commands (sudo/su) are always logged from the auth log.  To log
#   EVERY command, auditd must be recording execve; the script says whether it
#   is and prints the one rule to add, or adds it with --setup-auditd.
#
#   YOUR OWN COMMANDS DO NOT FLOOD THE ALERTS.  Admin accounts (your team) are
#   logged but stay quiet on the console unless the command itself is
#   dangerous (reverse shell, curl|sh, base64 -d|sh, nc -e, wiping history,
#   adding a user...).  A non-admin or unknown user alerts right away.
#
# USAGE
#   sudo sh LX-41-session-log.sh                       watch once, from now
#   sudo sh LX-41-session-log.sh --loop 30             keep watching (Ctrl-C stops)
#   sudo sh LX-41-session-log.sh --admin "alice bob"   name your admin accounts
#   nohup sudo sh LX-41-session-log.sh --loop 30 --alert-cmd "ssh log@10.0.0.5 'cat >>/srv/alerts/web01.log'" &
#   sudo sh LX-41-session-log.sh --setup-auditd        turn on full command logging (a change)
#
# OPTIONS
#   --loop N           re-check every N seconds until stopped (min 5)
#   --count N          with --loop: stop after N checks
#   --admin "U1 U2"    accounts whose normal activity should stay quiet
#                      (added to the auto-detected sudo/wheel members and you)
#   --admin-file FILE  one admin account per line (# comments allowed)
#   --web-user NAME    treat NAME as a web-server account: a command it runs is
#                      almost certainly a web shell, so it is always HIGH
#   --webroot DIR      a web root (repeat); flags a process running from it and
#                      maps a requested URL to a file to see if it is newly dropped
#   --access-log FILE  a web access log (repeat); apache/nginx logs are auto-found
#   --alert-own        also alert on admins' normal commands (noisy)
#   --all-commands     alert on EVERY command, not only the suspicious ones
#   --low              also print LOW alerts to the console (kept in the file either way)
#   --no-color         no colours
#   --from-start       process the existing log history on the first pass too
#                      (default: start from now, so old lines are not re-alerted)
#   --alert-cmd CMD    run CMD (sh -c) after each pass that raised alerts; the
#                      new alert lines arrive on its stdin (send them off-box)
#   --setup-auditd     add the auditd execve rule so every command is logged
#                      (the ONE change this script can make; reversible)
#   --auth-log FILE    the auth log to read (default: auto - auth.log/secure)
#   --audit-log FILE   the auditd log (default: /var/log/audit/audit.log)
#   --max-mb N         roll a log file over at N megabytes (default 50)
#   --state DIR        where logs and the read-position live
#                      (default <out>/sesslog-<host>)
#   --root DIR         treat DIR as / (for tests)
#   --help             this text plus the common options
#
# OUTPUTS  (in the state folder, <out>/sesslog-<host>/ by default)
#   alerts.log     every alert, newest at the bottom: time SEV section item - detail
#   logins.log     every login, logout and failed attempt
#   priv.log       every sudo/su, and the command sudo ran
#   commands.log   every command (with auditd): time user tty cwd command
#   web.log        every web request seen in the access log
#
# WHAT IT CHANGES
#   Nothing, unless you pass --setup-auditd, which adds one auditd rule
#   (-a always,exit -F arch=... -S execve -k ccdc_cmd) so execve is logged.
#   That change is reversible: an undo line is written and a revert timer armed
#   like the other change scripts.
#
# DEPENDS ON
#   awk, grep, tail, wc.  For full command logging: auditd (auditctl).  The
#   auth log must be readable (root).  journalctl is used if there is no auth
#   file but journald has the data.
#
# TESTED ON
#   Ubuntu 24.04 under dash, bash, busybox sh, ksh93, mksh and yash, on fixture
#   logs via --root/--state, and live with a planted ssh brute force, a sudo
#   shadow read and a reverse-shell command.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - Without auditd only sudo/su commands are captured (still the ones that
#     matter most).  --setup-auditd turns on the rest.
#   - A command is matched against known-bad patterns, not run through a
#     sandbox: a clean-looking command by an admin is not alerted.  Read
#     commands.log for the full picture.
#   - The red team can stop auditd or delete logs.  LX-40 alerts if the audit
#     service disappears; keep the off-box copy (--alert-cmd) as the record.
#   - Log files grow; they roll over at --max-mb to one .old file.
#
# DEBUGGING
#   --debug          show the files being read and the read positions
#   tail -f <state>/commands.log      watch commands live
# =============================================================================

# >>> CCDC-LIB
_cc_d=$(cd "$(dirname "$0")" && pwd)
while [ "$_cc_d" != "/" ] && [ ! -f "$_cc_d/lib/lib.sh" ]; do _cc_d=$(dirname "$_cc_d"); done
[ -f "$_cc_d/lib/lib.sh" ] || { echo "cannot find lib/lib.sh above $0" >&2; exit 3; }
. "$_cc_d/lib/lib.sh"
# <<< CCDC-LIB

usage() {
    cat <<'USAGE'
LX-41 Linux session & command logging - who logs in, what they run, with alerts
  sudo sh LX-41-session-log.sh                   watch once, from now
  sudo sh LX-41-session-log.sh --loop 30         keep watching

  --loop N           re-check every N seconds (min 5)
  --count N          with --loop: stop after N checks
  --admin "U1 U2"    accounts whose normal activity stays quiet
  --admin-file FILE  one admin account per line
  --web-user NAME    treat NAME as a web-server account (web shell if it runs a command)
  --webroot DIR      a web root to watch processes and requests against (repeat)
  --access-log FILE  a web access log to read (repeat; apache/nginx are auto-found)
  --alert-own        also alert on admins' normal commands
  --all-commands     alert on every command, not only suspicious ones
  --low              also show LOW alerts on the console
  --no-color         no colours
  --from-start       process existing history on the first pass
  --alert-cmd CMD    run CMD with new alert lines on its stdin
  --setup-auditd     add the auditd execve rule (the one change; reversible)
  --auth-log FILE    auth log to read (default: auto)
  --audit-log FILE   auditd log (default: /var/log/audit/audit.log)
  --max-mb N         roll a log over at N MB (default 50)
  --state DIR        where logs and read-positions live
  --root DIR         treat DIR as / (tests)
  --help             this text

USAGE
    cc_usage_common
}

# ---- Options ----------------------------------------------------------------
LOOP=0; COUNT=0; ADMIN_IN=""; ADMIN_FILE=""; ALERT_OWN=0; ALLCMD=0; SHOWLOW=0
FROMSTART=0; ALERTCMD=""; SETUP_AUDITD=0; AUTHLOG=""; AUDITLOG=""; MAXMB=50; STATE=""; R=""; COLOR=1
WEBUSERS_IN=""; WEBROOTS_IN=""; ACCESSLOGS_IN=""
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --loop)        [ $# -ge 2 ] || cc_die 2 "--loop needs seconds"; LOOP=$2; shift 2 ;;
        --count)       [ $# -ge 2 ] || cc_die 2 "--count needs a number"; COUNT=$2; shift 2 ;;
        --admin)       [ $# -ge 2 ] || cc_die 2 "--admin needs one or more names"; ADMIN_IN="$ADMIN_IN $2"; shift 2 ;;
        --admin-file)  [ $# -ge 2 ] || cc_die 2 "--admin-file needs a file"; [ -r "$2" ] || cc_die 2 "cannot read $2"; ADMIN_FILE=$2; shift 2 ;;
        --web-user)    [ $# -ge 2 ] || cc_die 2 "--web-user needs a name"; WEBUSERS_IN="$WEBUSERS_IN $2"; shift 2 ;;
        --webroot)     [ $# -ge 2 ] || cc_die 2 "--webroot needs a folder"; WEBROOTS_IN="$WEBROOTS_IN $2"; shift 2 ;;
        --access-log)  [ $# -ge 2 ] || cc_die 2 "--access-log needs a file"; ACCESSLOGS_IN="$ACCESSLOGS_IN $2"; shift 2 ;;
        --alert-own)   ALERT_OWN=1; shift ;;
        --all-commands) ALLCMD=1; shift ;;
        --low)         SHOWLOW=1; shift ;;
        --no-color|--no-colour) COLOR=0; shift ;;
        --from-start)  FROMSTART=1; shift ;;
        --alert-cmd)   [ $# -ge 2 ] || cc_die 2 "--alert-cmd needs a command"; ALERTCMD=$2; shift 2 ;;
        --setup-auditd) SETUP_AUDITD=1; shift ;;
        --auth-log)    [ $# -ge 2 ] || cc_die 2 "--auth-log needs a file"; AUTHLOG=$2; shift 2 ;;
        --audit-log)   [ $# -ge 2 ] || cc_die 2 "--audit-log needs a file"; AUDITLOG=$2; shift 2 ;;
        --max-mb)      [ $# -ge 2 ] || cc_die 2 "--max-mb needs a number"; MAXMB=$2; shift 2 ;;
        --state)       [ $# -ge 2 ] || cc_die 2 "--state needs a folder"; STATE=$2; shift 2 ;;
        --root)        [ $# -ge 2 ] || cc_die 2 "--root needs a folder"; [ -d "$2" ] || cc_die 2 "--root: not a folder: $2"
                       R=$(cd "$2" && pwd); [ "$R" = / ] && R=""; shift 2 ;;
        --help|-h)     usage; exit 0 ;;
        *)             cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
case "$LOOP" in ''|*[!0-9]*) cc_die 2 "--loop needs a whole number of seconds" ;; esac
case "$COUNT" in ''|*[!0-9]*) cc_die 2 "--count needs a whole number" ;; esac
case "$MAXMB" in ''|*[!0-9]*|0) cc_die 2 "--max-mb needs a whole number, 1 or more" ;; esac
[ "$LOOP" -gt 0 ] && [ "$LOOP" -lt 5 ] && cc_die 2 "--loop must be at least 5 seconds"

cc_init "LX-41" "Linux session & command logging" readonly
cc_detect_os
IS_ROOT=0
cc_is_root && IS_ROOT=1
[ "$IS_ROOT" = 1 ] || [ -n "$R" ] || cc_warn "not running as root: the auth log and audit log are usually unreadable, so logins and commands will be missed"
[ -n "$STATE" ] || STATE="$CC_OUT/sesslog-$CC_HOST"
(umask 077; mkdir -p "$STATE/.cur") || cc_die 3 "cannot create $STATE"
STATE=$(cc_abspath "$STATE")
MAXBYTES=$((MAXMB * 1024 * 1024))
ALERTS="$STATE/alerts.log"
PASSWD="$R/etc/passwd"
GROUP="$R/etc/group"

cc_color_init
[ "$COLOR" = 1 ] || { C_RED=""; C_YEL=""; C_GRN=""; C_CYN=""; C_GRY=""; C_OFF=""; }

# ---- Find the auth log ------------------------------------------------------
if [ -z "$AUTHLOG" ]; then
    for _f in "$R/var/log/auth.log" "$R/var/log/secure"; do
        [ -f "$_f" ] && { AUTHLOG=$_f; break; }
    done
fi
AUTH_JOURNAL=0
if [ -z "$AUTHLOG" ] && [ -z "$R" ] && cc_have journalctl; then
    AUTH_JOURNAL=1
    cc_info "no auth log file: reading logins and sudo from journalctl"
elif [ -n "$AUTHLOG" ]; then
    [ -r "$AUTHLOG" ] || cc_warn "cannot read $AUTHLOG (need root): logins and sudo will be missed"
    cc_info "auth log: $AUTHLOG"
else
    cc_warn "no auth log found (looked for auth.log and secure): logins and sudo cannot be watched"
fi

# ---- Find the audit log -----------------------------------------------------
[ -n "$AUDITLOG" ] || AUDITLOG="$R/var/log/audit/audit.log"
AUDIT_ON=0
if [ -r "$AUDITLOG" ] && [ -s "$AUDITLOG" ]; then AUDIT_ON=1; fi
# Is the execve rule actually loaded?  (Only meaningful on a live box.)
AUDIT_RULE=0
if [ -z "$R" ] && cc_have auditctl; then
    auditctl -l 2>/dev/null | grep -q 'syscall=.*execve\|-S execve' && AUDIT_RULE=1
fi

# ---- Optional: set up the auditd execve rule (the one change) ---------------
if [ "$SETUP_AUDITD" = 1 ]; then
    [ "$IS_ROOT" = 1 ] || cc_die 2 "--setup-auditd needs root"
    [ -z "$R" ] || cc_die 2 "--setup-auditd cannot be used with --root"
    cc_have auditctl || cc_die 3 "auditd is not installed (no auditctl). Install the 'auditd' package, then re-run with --setup-auditd"
    if [ "$AUDIT_RULE" = 1 ]; then
        cc_info "the auditd execve rule is already loaded: every command is being logged"
    else
        _arch=b64; case "$(uname -m 2>/dev/null)" in i?86|armv*) _arch=b32 ;; esac
        cc_show "$C_YEL" "Adding the auditd rule so every command is logged:"
        cc_show "" "  auditctl -a always,exit -F arch=$_arch -S execve -k ccdc_cmd"
        if cc_confirm "Add it now?"; then
            if auditctl -a always,exit -F arch="$_arch" -S execve -k ccdc_cmd 2>>"$CC_LOG"; then
                [ "$_arch" = b64 ] && auditctl -a always,exit -F arch=b32 -S execve -k ccdc_cmd 2>>"$CC_LOG"
                cc_undo_add "auditctl -d always,exit -F arch=$_arch -S execve -k ccdc_cmd 2>/dev/null; [ '$_arch' = b64 ] && auditctl -d always,exit -F arch=b32 -S execve -k ccdc_cmd 2>/dev/null; true"
                # shellcheck disable=SC2034  # CC_RUN_DIR is read by cc_timer_start in the library
                cc_use_run_dir 2>/dev/null || CC_RUN_DIR=$STATE
                cc_timer_start 120
                cc_show "$C_GRN" "[ok] execve logging on. To make it survive a reboot, add the same line to /etc/audit/rules.d/ccdc.rules"
                cc_info "a 120s revert timer is armed; cc_timer_finish decides keep or revert"
                AUDIT_RULE=1; AUDIT_ON=1
            else
                cc_err "could not add the rule (see the log)"
            fi
        fi
    fi
fi

# ---- Admin allowlist (whose normal activity stays quiet) --------------------
# Auto: root, members of the admin groups, and whoever launched this.
_admins=" root "
if [ -f "$GROUP" ]; then
    for _m in $(awk -F: '$1 ~ /^(sudo|wheel|admin|adm)$/ { gsub(/,/, " ", $4); print $4 }' "$GROUP" 2>/dev/null); do
        _admins="$_admins$_m "
    done
fi
for _u in "${SUDO_USER:-}" "${LOGNAME:-}" "$(id -un 2>/dev/null)"; do
    [ -n "$_u" ] && _admins="$_admins$_u "
done
[ -n "$ADMIN_FILE" ] && for _u in $(sed 's/#.*//' "$ADMIN_FILE"); do _admins="$_admins$_u "; done
for _u in $ADMIN_IN; do _admins="$_admins$_u "; done
# Normalise to a single-spaced " a b c " with no repeats.
ADMINS=" $(printf '%s' "$_admins" | tr ' ' '\n' | grep . | sort -u | tr '\n' ' ')"
is_admin() { case "$ADMINS" in *" $1 "*) return 0 ;; esac; return 1; }
known_user() { [ -f "$PASSWD" ] || return 0; cut -d: -f1 "$PASSWD" | grep -qx "$1"; }
cc_info "admin accounts (kept quiet): $(printf '%s' "$ADMINS" | sed 's/^ //;s/ $//')"

# Web service accounts.  A command run by one of these is almost always a web
# shell, so it is always HIGH.
_webu=" www-data apache apache2 nginx httpd http daemon php php-fpm www tomcat tomcat8 tomcat9 jetty lighttpd "
for _u in $WEBUSERS_IN; do _webu="$_webu$_u "; done
WEBUSERS=" $(printf '%s' "$_webu" | tr ' ' '\n' | grep . | sort -u | tr '\n' ' ')"
is_webuser() { case "$WEBUSERS" in *" $1 "*) return 0 ;; esac; return 1; }

# Web roots: used to spot a process running from one, and to map a requested
# URL to a file on disk (to see if that file is newly dropped).
WEBROOTS=""
for _d in /var/www /var/www/html /srv/www /srv/http /usr/share/nginx/html /usr/local/www /opt/lampp/htdocs $WEBROOTS_IN; do
    case "$_d" in /*) _d="$R$_d" ;; esac
    [ -d "$_d" ] && WEBROOTS="$WEBROOTS $_d"
done

# Access logs: given ones, plus the usual apache/nginx locations.
ACCESSLOGS=""
for _g in $ACCESSLOGS_IN "$R"/var/log/apache2/*access*.log "$R"/var/log/httpd/*access_log "$R"/var/log/nginx/*access*.log "$R"/var/log/lighttpd/*access*.log; do
    [ -f "$_g" ] && [ -r "$_g" ] && ACCESSLOGS="$ACCESSLOGS $_g"
done
[ -n "$ACCESSLOGS" ] && cc_info "web access logs:$ACCESSLOGS"

# Known web-shell filenames, and markers of a command-injection / shell request.
WEBSHELL_NAMES='^(c99|r57|wso|b374k|alfa|cmd|shell|up|upload|backdoor|webshell|p0wny|weevely|phpspy|minishell|0day|antichat|mini|conf|sh|x)\.(php|phtml|php[0-9]|asp|aspx|jsp|cgi)$'
WEB_INJECT='(cmd=|exec=|[?&]c=|[?&]x=|shell_exec|passthru|system\(|popen|proc_open|base64_decode|eval\(|assert\(|/bin/(ba|da|z)?sh|%2[fF]bin%2[fF]|;id|%3[bB]id|\|id|whoami|wget[ +%]|curl[ +%]|/dev/tcp/|php://input|allow_url|\.\./\.\./|%00)'

# A marker file whose mtime is "when watching began": a web-root script newer
# than this was dropped after we started looking.
[ -f "$STATE/.started" ] || : >"$STATE/.started"

# Patterns that are almost never a real admin command (reverse shells,
# download-and-run, encoded commands, log/history wiping, account changes).
SUSP_STRONG='(/dev/tcp/|/dev/udp/|bash -i|sh -i| -e /bin/|nc .*-e|ncat .*-e|socat .*exec|mkfifo .*\|.*sh|(curl|wget)[^|;]*\|[[:space:]]*(ba|da|z)?sh|base64[[:space:]]+(-d|--decode)|python[0-9.]*[[:space:]]+-c|perl[[:space:]]+-e|php[[:space:]]+-r|openssl[[:space:]]+s_client|chattr[[:space:]]+[+]i|history[[:space:]]+-c|unset[[:space:]]+HISTFILE|>[[:space:]]*/var/log/|truncate[^;]*/var/log/)'
SUSP_WEAK='(useradd|userdel|usermod|passwd[[:space:]]|groupadd|visudo|/etc/sudoers|/etc/shadow|/etc/passwd|authorized_keys|iptables[[:space:]]+-F|nft[[:space:]]+flush|systemctl[[:space:]]+(stop|disable|mask)|wget[[:space:]]|curl[[:space:]]|/tmp/|/dev/shm/)'

# ---- Console + files --------------------------------------------------------
show() { printf '%s%s%s\n' "$1" "$2" "${C_OFF:-}"; }
# rollover FILE -> move it aside if it passed --max-mb.
rollover() {
    [ -f "$1" ] || return 0
    _sz=$(wc -c <"$1" 2>/dev/null); case "$_sz" in ''|*[!0-9]*) return 0 ;; esac
    [ "$_sz" -ge "$MAXBYTES" ] && mv "$1" "$1.old"
    return 0
}
# logcat BASENAME LINE -> append to one of the per-category log files.
logcat() { rollover "$STATE/$1"; printf '%s\n' "$2" >>"$STATE/$1"; }
AL_H=0; AL_M=0; AL_L=0
# alert SEV SECTION ITEM DETAIL -> record and (HIGH/MED, or LOW with --low) show.
alert() {
    _al_t=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    _al_line=$(printf '%s %-4s %-8s %-22s - %s' "$_al_t" "$1" "$2" "$3" "$4")
    rollover "$ALERTS"; printf '%s\n' "$_al_line" >>"$ALERTS"
    printf '%s\n' "$_al_line" >>"$STATE/.newalerts"
    case "$1" in
        HIGH) AL_H=$((AL_H + 1)); show "${C_RED:-}" "  $_al_line" ;;
        MED)  AL_M=$((AL_M + 1)); show "${C_YEL:-}" "  $_al_line" ;;
        LOW)  AL_L=$((AL_L + 1)); [ "$SHOWLOW" = 1 ] && show "${C_GRY:-}" "  $_al_line" ;;
    esac
    return 0
}

# ---- Incremental read -------------------------------------------------------
# new_lines KEY FILE -> print only the lines added since last pass; on the
#   first pass (no cursor) print nothing but remember the end, unless
#   --from-start.  Handles rotation (file shorter than remembered -> restart).
new_lines() {
    _nl_k="$STATE/.cur/$1"; _nl_f="$2"
    [ -r "$_nl_f" ] || return 0
    _nl_tot=$(wc -l <"$_nl_f" 2>/dev/null); case "$_nl_tot" in ''|*[!0-9]*) _nl_tot=0 ;; esac
    if [ -f "$_nl_k" ]; then
        _nl_seen=$(cat "$_nl_k" 2>/dev/null); case "$_nl_seen" in ''|*[!0-9]*) _nl_seen=0 ;; esac
    else
        # First time we have seen this file.
        if [ "$FROMSTART" = 1 ]; then _nl_seen=0; else _nl_seen=$_nl_tot; fi
    fi
    [ "$_nl_tot" -lt "$_nl_seen" ] && _nl_seen=0            # rotated
    if [ "$_nl_tot" -gt "$_nl_seen" ]; then
        tail -n +"$((_nl_seen + 1))" "$_nl_f"
        printf '%s\n' "$_nl_tot" >"$_nl_k"
    else
        printf '%s\n' "$_nl_tot" >"$_nl_k"
    fi
}

N_LOGIN=0; N_CMD=0; N_WEB=0

# ---- Section: logins and priv (from the auth log) ---------------------------
# Writes the new auth-log lines to $STATE/.auth for parsing.
read_auth() {
    : >"$STATE/.auth"
    if [ "$AUTH_JOURNAL" = 1 ]; then
        # journald: keep a cursor file so only new entries come back.
        _jc="$STATE/.cur/journal"
        if [ -f "$_jc" ] && [ -s "$_jc" ]; then
            journalctl --after-cursor="$(cat "$_jc")" -o short-iso --no-pager _COMM=sshd _COMM=sudo _COMM=su 2>/dev/null >"$STATE/.auth" || :
        elif [ "$FROMSTART" = 1 ]; then
            journalctl -o short-iso --no-pager _COMM=sshd _COMM=sudo _COMM=su 2>/dev/null >"$STATE/.auth" || :
        fi
        journalctl -o export --no-pager -n 0 --show-cursor 2>/dev/null | sed -n 's/^-- cursor: //p' >"$_jc" 2>/dev/null || :
    elif [ -n "$AUTHLOG" ] && [ -r "$AUTHLOG" ]; then
        new_lines auth "$AUTHLOG" >"$STATE/.auth"
    fi
    [ -s "$STATE/.auth" ] || return 0
    # Parse each kind of line.
    while IFS= read -r _L; do
        case "$_L" in
            *"Accepted "*" for "*" from "*)
                _u=$(printf '%s' "$_L" | sed -n 's/.*Accepted [a-z]* for \([^ ]*\) from \([0-9a-fA-F:.]*\).*/\1/p')
                _ip=$(printf '%s' "$_L" | sed -n 's/.*Accepted [a-z]* for [^ ]* from \([0-9a-fA-F:.]*\).*/\1/p')
                _how=$(printf '%s' "$_L" | sed -n 's/.*Accepted \([a-z]*\) for .*/\1/p')
                N_LOGIN=$((N_LOGIN + 1)); logcat logins.log "$(date -u +%Y-%m-%dT%H:%M:%SZ) LOGIN $_u from ${_ip:-?} ($_how)"
                if ! known_user "$_u"; then alert HIGH logins "$_u@${_ip:-?}" "login by an account not in /etc/passwd ($_how)"
                elif [ "$_u" = root ] && [ "$_how" = password ]; then alert HIGH logins "root@${_ip:-?}" "root logged in over the network with a PASSWORD"
                elif is_admin "$_u"; then alert LOW logins "$_u@${_ip:-?}" "admin login ($_how)"
                else alert MED logins "$_u@${_ip:-?}" "login by a non-admin account ($_how)"
                fi ;;
            *"Failed password for "*" from "*|*"Failed publickey for "*|*"authentication failure"*|*"Invalid user "*)
                _ip=$(printf '%s' "$_L" | sed -n 's/.* from \([0-9a-fA-F:.]*\).*/\1/p')
                _u=$(printf '%s' "$_L" | sed -n 's/.*for \(invalid user \)\{0,1\}\([^ ]*\) from .*/\2/p')
                logcat logins.log "$(date -u +%Y-%m-%dT%H:%M:%SZ) FAIL ${_u:-?} from ${_ip:-?}"
                # Count failures per IP this pass; a burst is a brute force.
                [ -n "$_ip" ] && printf '%s\n' "$_ip" >>"$STATE/.fails" ;;
            *" session opened for user "*)
                _u=$(printf '%s' "$_L" | sed -n 's/.*session opened for user \([^ (]*\).*/\1/p')
                logcat logins.log "$(date -u +%Y-%m-%dT%H:%M:%SZ) SESSION-OPEN $_u" ;;
            *" session closed for user "*)
                _u=$(printf '%s' "$_L" | sed -n 's/.*session closed for user \([^ (]*\).*/\1/p')
                logcat logins.log "$(date -u +%Y-%m-%dT%H:%M:%SZ) SESSION-CLOSE $_u" ;;
        esac
        # sudo / su.
        case "$_L" in
            *"sudo: "*" : "*"COMMAND="*)
                _u=$(printf '%s' "$_L" | sed -n 's/.*sudo: *\([^ ]*\) : .*/\1/p')
                _cmd=$(printf '%s' "$_L" | sed -n 's/.*COMMAND=//p')
                logcat priv.log "$(date -u +%Y-%m-%dT%H:%M:%SZ) SUDO $_u: $_cmd"
                classify_cmd "$_u" "sudo" "$_cmd" priv ;;
            *"sudo: "*"authentication failure"*|*"sudo: "*"incorrect password attempt"*)
                _u=$(printf '%s' "$_L" | sed -n 's/.*sudo: *\([^ ]*\) .*/\1/p')
                logcat priv.log "$(date -u +%Y-%m-%dT%H:%M:%SZ) SUDO-FAIL $_u"
                alert MED priv "$_u" "sudo authentication failure" ;;
            *"su: "*"FAILED"*|*"FAILED su "*)
                logcat priv.log "$(date -u +%Y-%m-%dT%H:%M:%SZ) SU-FAIL: $_L"
                alert MED priv su "a su attempt failed" ;;
            *" su["*"session opened"*|*"su: (to "*)
                logcat priv.log "$(date -u +%Y-%m-%dT%H:%M:%SZ) SU: $_L" ;;
        esac
    done <"$STATE/.auth"
    # Brute force: more than 5 failures from one IP in a pass.
    if [ -f "$STATE/.fails" ]; then
        sort "$STATE/.fails" | uniq -c | while read -r _n _ip; do
            [ "$_n" -gt 5 ] && alert HIGH logins "$_ip" "$_n failed logins from this address (brute force)"
        done
        rm -f "$STATE/.fails"
    fi
}

# classify_cmd USER SOURCE COMMAND SECTION -> log it, and alert per the rules.
classify_cmd() {
    _cu=$1; _csrc=$2; _cc=$3; _csec=$4
    [ "$_csec" = commands ] && N_CMD=$((N_CMD + 1))
    if is_webuser "$_cu"; then
        # A web server account almost never runs a command: this is the web
        # shell executing.  Always HIGH, whatever the command is.
        alert HIGH "$_csec" "$_cu" "web server account ran a command (web shell?): $_cc"
    elif printf '%s' "$_cc" | grep -Eq "$SUSP_STRONG"; then
        alert HIGH "$_csec" "$_cu" "dangerous command: $_cc"
    elif ! known_user "$_cu"; then
        alert HIGH "$_csec" "$_cu" "command by an account not in /etc/passwd: $_cc"
    elif printf '%s' "$_cc" | grep -Eq "$SUSP_WEAK"; then
        if is_admin "$_cu" && [ "$ALERT_OWN" = 0 ]; then alert LOW "$_csec" "$_cu" "sensitive command: $_cc"
        else alert MED "$_csec" "$_cu" "sensitive command: $_cc"; fi
    elif is_admin "$_cu"; then
        if [ "$ALLCMD" = 1 ] || [ "$ALERT_OWN" = 1 ]; then alert LOW "$_csec" "$_cu" "command: $_cc"; fi
    else
        alert MED "$_csec" "$_cu" "command by a non-admin account: $_cc"
    fi
    return 0
}

# ---- Section: commands (from auditd execve) ---------------------------------
read_audit() {
    [ "$AUDIT_ON" = 1 ] || return 0
    new_lines audit "$AUDITLOG" >"$STATE/.audit"
    [ -s "$STATE/.audit" ] || return 0
    # Reconstruct one command per audit event id from the EXECVE/SYSCALL/CWD
    # records that share msg=audit(TIME:ID).  Hex-encoded args are decoded.
    awk -v passwd="$PASSWD" '
        function hexval(c) { return index("0123456789abcdef", tolower(c)) - 1 }   # awk: posix-ok
        function unhex(s,   i, r) { r = ""; for (i = 1; i + 1 <= length(s); i += 2) r = r sprintf("%c", hexval(substr(s, i, 1)) * 16 + hexval(substr(s, i + 1, 1))); return r }   # awk: posix-ok
        function evid(line,   m) { if (match(line, /audit\([0-9.]+:[0-9]+\)/)) return substr(line, RSTART + 6, RLENGTH - 7); return "" }   # awk: posix-ok
        function field(line, name,   m, s, v) {   # awk: posix-ok
            if (!match(line, name "=")) return ""
            s = substr(line, RSTART + length(name) + 1)
            if (substr(s, 1, 1) == "\"") { v = substr(s, 2); sub(/".*/, "", v); return v }
            v = s; sub(/[ \t].*/, "", v); return v
        }
        BEGIN { while ((getline l < passwd) > 0) { n = split(l, p, ":"); if (n >= 3) uname[p[3]] = p[1] } }
        /type=SYSCALL/ { id = evid($0); if (id == "") next; uid[id] = field($0, "uid"); tty[id] = field($0, "tty"); succ[id] = field($0, "success"); exe[id] = field($0, "exe") }
        /type=CWD/     { id = evid($0); if (id != "") cwd[id] = field($0, "cwd") }
        /type=EXECVE/  {
            id = evid($0); if (id == "") next
            cmd = ""; n = 0
            s = $0
            while (match(s, /a[0-9]+=([^ \t]+|"[^"]*")/)) {
                tok = substr(s, RSTART, RLENGTH); s = substr(s, RSTART + RLENGTH)
                sub(/^a[0-9]+=/, "", tok)
                if (substr(tok, 1, 1) == "\"") { val = substr(tok, 2, length(tok) - 2) }
                else { val = unhex(tok) }
                cmd = cmd (cmd == "" ? "" : " ") val; n++
            }
            if (cmd != "") { order[++seen] = id; argv[id] = cmd }
        }
        END {
            for (i = 1; i <= seen; i++) {
                id = order[i]; u = uid[id]
                nm = (u in uname) ? uname[u] : ("uid" u)
                if (succ[id] == "no") continue
                print nm "\t" (tty[id] == "" ? "?" : tty[id]) "\t" (cwd[id] == "" ? "?" : cwd[id]) "\t" (exe[id] == "" ? "?" : exe[id]) "\t" argv[id]
            }
        }' "$STATE/.audit" >"$STATE/.cmds"
    while IFS="$(printf '\t')" read -r _u _tty _cwd _exe _cmd; do
        [ -n "$_cmd" ] || continue
        logcat commands.log "$(date -u +%Y-%m-%dT%H:%M:%SZ) $_u $_tty $_cwd  $_cmd"
        classify_cmd "$_u" audit "$_cmd" commands
        # Where it runs FROM: a process whose folder or program lives in a
        # world-writable spot or a web root, or a deleted binary, is a red
        # flag on its own.  (A web-user command is already HIGH above.)
        if ! is_webuser "$_u"; then
            _org=""
            case "$_cwd" in /tmp/*|/var/tmp/*|/dev/shm/*|/run/shm/*) _org="folder $_cwd" ;; esac
            case "$_exe" in *"(deleted)") _org="a deleted program ($_exe)" ;; /tmp/*|/var/tmp/*|/dev/shm/*|/run/shm/*) _org="program $_exe" ;; esac
            for _wr in $WEBROOTS; do
                case "$_exe" in "$_wr"/*) _org="program under a web root ($_exe)" ;; esac
                case "$_cwd" in "$_wr"/*) [ -n "$_org" ] || _org="a web root ($_cwd)" ;; esac
            done
            [ -n "$_org" ] && alert HIGH commands "$_u" "process running from $_org: $_cmd"
        fi
    done <"$STATE/.cmds"
}

# ---- Section: web access log (what a web shell is being told to do) ---------
read_web() {
    [ -n "$ACCESSLOGS" ] || return 0
    for _wl in $ACCESSLOGS; do
        [ -r "$_wl" ] || continue
        _wk=web_$(printf '%s' "$_wl" | tr -c 'A-Za-z0-9' '_')
        new_lines "$_wk" "$_wl" >"$STATE/.web1"
        [ -s "$STATE/.web1" ] || continue
        # Common/combined access-log format: IP ... "METHOD PATH PROTO" STATUS ... "UA"
        awk '{
            ip = $1
            if (match($0, /"[^"]*"/)) { req = substr($0, RSTART + 1, RLENGTH - 2); rest = substr($0, RSTART + RLENGTH) } else { req = ""; rest = "" }
            m = ""; p = ""; nn = split(req, rq, " "); if (nn >= 1) m = rq[1]; if (nn >= 2) p = rq[2]
            st = ""; if (match(rest, / [0-9][0-9][0-9] /)) st = substr(rest, RSTART + 1, 3)
            ua = ""; s = $0; while (match(s, /"[^"]*"/)) { ua = substr(s, RSTART + 1, RLENGTH - 2); s = substr(s, RSTART + RLENGTH) }
            if (p != "") print ip "\t" m "\t" p "\t" st "\t" ua
        }' "$STATE/.web1" >"$STATE/.web2"
        while IFS="$(printf '\t')" read -r _ip _m _p _st _ua; do
            N_WEB=$((N_WEB + 1))
            logcat web.log "$(date -u +%Y-%m-%dT%H:%M:%SZ) $_ip \"$_m $_p\" ${_st:-?} \"$_ua\""
            _pp=${_p%%\?*}; _base=${_pp##*/}
            _it="$_ip $_m $_pp"
            if printf '%s' "$_base" | grep -Eiq "$WEBSHELL_NAMES"; then
                alert HIGH web "$_it" "request to a known web-shell filename ($_base)"
            elif printf '%s' "$_p" | grep -Eiq "$WEB_INJECT"; then
                alert HIGH web "$_it" "command-injection / web-shell request: $_m $_pp"
            else
                case "$_base" in
                    *.php|*.phtml|*.php[0-9]|*.asp|*.aspx|*.jsp|*.jspx|*.cgi|*.pl|*.py|*.sh)
                        _rel=${_pp#/}
                        for _wr in $WEBROOTS; do
                            _f="$_wr/$_rel"
                            if [ -f "$_f" ] && [ -n "$(find "$_f" -newer "$STATE/.started" 2>/dev/null)" ]; then
                                alert HIGH web "$_it" "request to a script added/changed since watching began (dropped web shell?): $_rel"
                                break
                            fi
                        done ;;
                esac
            fi
        done <"$STATE/.web2"
    done
}

# ---- One pass ---------------------------------------------------------------
one_pass() {
    N_LOGIN=0; N_CMD=0; N_WEB=0; AL_H=0; AL_M=0; AL_L=0
    : >"$STATE/.newalerts"
    read_auth
    read_audit
    read_web
    _t=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    if [ "$AL_H" -gt 0 ] || [ "$AL_M" -gt 0 ] || [ "$AL_L" -gt 0 ]; then
        printf '%s  %d login event(s), %d command(s), %d web request(s); alerts: %d HIGH, %d MED, %d LOW\n' "$_t" "$N_LOGIN" "$N_CMD" "$N_WEB" "$AL_H" "$AL_M" "$AL_L"
    else
        printf '%s  %d login event(s), %d command(s), %d web request(s); nothing to flag\n' "$_t" "$N_LOGIN" "$N_CMD" "$N_WEB"
    fi
    if [ -s "$STATE/.newalerts" ] && [ -n "$ALERTCMD" ]; then
        sh -c "$ALERTCMD" <"$STATE/.newalerts" >>"$CC_LOG" 2>&1 || cc_warn "--alert-cmd failed (exit $?): alerts are still in $ALERTS"
    fi
}

# ---- Run --------------------------------------------------------------------
show "${C_CYN:-}" "LX-41 session & command logging | host $CC_HOST | state $STATE"
if [ "$AUDIT_ON" != 1 ]; then
    if [ "$AUDIT_RULE" = 1 ]; then
        cc_info "auditd rule is loaded but $AUDITLOG is empty so far"
    else
        _arch=b64; case "$(uname -m 2>/dev/null)" in i?86|armv*) _arch=b32 ;; esac
        show "${C_YEL:-}" "[!] auditd is not logging commands: only sudo/su commands are captured."
        show "${C_YEL:-}" "    Turn on full command logging with:  sudo sh $0 --setup-auditd"
        show "${C_YEL:-}" "    (or by hand: auditctl -a always,exit -F arch=$_arch -S execve -k ccdc_cmd)"
    fi
else
    show "${C_GRN:-}" "[ok] auditd is logging commands ($AUDITLOG)"
fi
[ "$FROMSTART" = 1 ] || cc_info "watching from now (use --from-start to include existing history)"
if [ -n "$ACCESSLOGS" ]; then show "${C_GRN:-}" "[ok] watching web access log(s) for web-shell activity"; else cc_info "no web access log found; a command run by a web-server account is still caught as a web shell"; fi

_checks=0
while :; do
    _checks=$((_checks + 1))
    one_pass
    [ "$LOOP" -gt 0 ] || break
    [ "$COUNT" -gt 0 ] && [ "$_checks" -ge "$COUNT" ] && break
    sleep "$LOOP"
done
cc_info "logs: $STATE (logins.log, priv.log, commands.log, alerts.log)"
cc_finish
