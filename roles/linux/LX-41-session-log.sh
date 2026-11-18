#!/bin/sh
# =============================================================================
# ID:       LX-41
# NAME:     Linux session & command logging
# ROLE:     Linux  (wave 2 - start it once the box is hardened, beside LX-40)
# KIND:     readonly - reads logs, changes nothing (unless --setup-auditd)
# VERSION:  1.1.0
#
# PURPOSE
#   Watches who logs in and what they run, saves it to log files, and prints
#   an alert to the console for anything that looks like the red team.  Pairs
#   with LX-40 (which watches config and persistence changes); this one
#   watches events: logins and commands.
#
#   It reads logs the box already keeps, so it changes nothing:
#     logins     ssh and console logins, the source address, failed logins,
#                brute force (fast or slow), a login that succeeds after many
#                failures, sessions and logouts               (the auth log)
#     priv       sudo and su use, the command each sudo ran, denied and
#                failed attempts, new accounts, group and password changes
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
#   --repeat-after N   show the same alert again only after N seconds (default
#                      600; 0 shows every repeat).  Events are always logged
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
#   (-a always,exit -F arch=... -S execve -k ccdc_cmd) so execve is logged,
#   and, if you say yes, the same line in /etc/audit/rules.d/ccdc.rules so it
#   survives a reboot.  Both have undo lines.  No revert timer: a logging rule
#   cannot lock anyone out.
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
#   - The same alert is shown once and then held back for --repeat-after
#     seconds, so a scoring engine logging in every minute does not fill the
#     screen.  The pass line says how many repeats were held back.
#   - Who ran a command is the LOGIN account (auditd's auid): "bob as root"
#     is bob after sudo/su.  Root commands from a non-admin's session alert.
#   - The script runs from its state folder and skips audit events with that
#     working folder: those are its own helpers.
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
  --repeat-after N   repeat the same alert only after N seconds (default 600)
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
WEBUSERS_IN=""; WEBROOTS_IN=""; ACCESSLOGS_IN=""; REPEAT=600
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
        --repeat-after) [ $# -ge 2 ] || cc_die 2 "--repeat-after needs seconds"; REPEAT=$2; shift 2 ;;
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
case "$REPEAT" in ''|*[!0-9]*) cc_die 2 "--repeat-after needs a whole number of seconds (0 shows every repeat)" ;; esac
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
# Run from the state folder: auditd records every helper this script starts
# (awk, date, ...) with that working folder, which is how they are told apart
# from everyone else's commands.  So file arguments are made absolute first.
[ -n "$AUTHLOG" ] && [ -e "$AUTHLOG" ] && AUTHLOG=$(cc_abspath "$AUTHLOG")
[ -n "$AUDITLOG" ] && [ -e "$AUDITLOG" ] && AUDITLOG=$(cc_abspath "$AUDITLOG")
[ -n "$ADMIN_FILE" ] && ADMIN_FILE=$(cc_abspath "$ADMIN_FILE")
_al=""; for _f in $ACCESSLOGS_IN; do [ -e "$_f" ] && _f=$(cc_abspath "$_f"); _al="$_al $_f"; done; ACCESSLOGS_IN=$_al
_wr=""; for _f in $WEBROOTS_IN; do [ -d "$_f" ] && [ -z "$R" ] && _f=$(cc_abspath "$_f"); _wr="$_wr $_f"; done; WEBROOTS_IN=$_wr
cd "$STATE" || cc_die 3 "cannot enter $STATE"
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
                CC_APPLY=1      # so the undo lines are recorded
                cc_undo_add "remove the auditd execve rule" "auditctl -d always,exit -F arch=$_arch -S execve -k ccdc_cmd 2>/dev/null; auditctl -d always,exit -F arch=b32 -S execve -k ccdc_cmd 2>/dev/null; true"
                cc_show "$C_GRN" "[ok] every command is now logged to $AUDITLOG"
                # Loaded rules are lost at reboot unless they are in rules.d.
                if [ -d /etc/audit/rules.d ] && [ ! -f /etc/audit/rules.d/ccdc.rules ] && cc_ask "Keep the rule after a reboot too?" Y "yes, write /etc/audit/rules.d/ccdc.rules" "no, only until the next reboot"; then
                    { printf -- '-a always,exit -F arch=%s -S execve -k ccdc_cmd\n' "$_arch"
                      [ "$_arch" = b64 ] && printf -- '-a always,exit -F arch=b32 -S execve -k ccdc_cmd\n'; } >/etc/audit/rules.d/ccdc.rules \
                        && cc_undo_add "remove /etc/audit/rules.d/ccdc.rules" "rm -f /etc/audit/rules.d/ccdc.rules" \
                        && cc_show "$C_GRN" "[ok] wrote /etc/audit/rules.d/ccdc.rules"
                fi
                # shellcheck disable=SC2034  # read by the library
                CC_APPLY=0
                cc_info "undo: the lines are in $CC_UNDO (auditctl -d ... removes the rule)"
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

# Known web-shell filenames, and markers of a command-injection / shell
# request (matched after the URL is decoded).  awk regexes: [ \t], not
# [[:space:]], so old mawk works too.
LX_SHELLNAMES='^(c99|r57|wso|b374k|alfa|cmd|shell|backdoor|webshell|p0wny|weevely|phpspy|minishell|0day|antichat|sh|x)\.(php|phtml|php[0-9]|asp|aspx|jsp|cgi)$'
LX_INJECT='(cmd=|exec=|shell_exec|passthru|system\(|popen\(|proc_open|base64_decode|eval\(|assert\(|/bin/(ba|da|z)?sh|;[ +]*id|\|[ +]*id|`|\$\(|whoami|wget[ +]|curl[ +]|/dev/tcp/|php://input|allow_url|\.\./\.\./|/etc/passwd|/etc/shadow)'

# A marker file whose mtime is "when watching began": a web-root script newer
# than this was dropped after we started looking.
[ -f "$STATE/.started" ] || : >"$STATE/.started"

# Patterns that are almost never a real admin command (reverse shells,
# download-and-run, encoded commands, log/history wiping).
LX_STRONG='(/dev/tcp/|/dev/udp/|bash -i|sh -i| -e /bin/|nc .*-e|ncat .*-e|socat .*exec|mkfifo .*\|.*sh|(curl|wget)[^|;]*\|[ \t]*(ba|da|z)?sh|base64[ \t]+(-d|--decode)|python[0-9.]*[ \t]+-c|perl[ \t]+-e|php[ \t]+-r|openssl[ \t]+s_client|chattr[ \t]+[+]i|history[ \t]+-c|unset[ \t]+HISTFILE|>[ \t]*/var/log/|truncate[^;]*/var/log/|auditctl[ \t]+-[eDd]|(systemctl|service)[ \t]+(stop|disable|mask)?[ \t]*auditd|setenforce[ \t]+0)'
LX_WEAK='(useradd|userdel|usermod|adduser|passwd([ \t]|$)|chpasswd|groupadd|gpasswd|visudo|/etc/sudoers|/etc/shadow|/etc/passwd|authorized_keys|iptables[ \t]+-F|nft[ \t]+flush|ufw[ \t]+disable|systemctl[ \t]+(stop|disable|mask)|crontab|chmod[ \t]+[^ ]*(777|[+]s|[0-7]*[4567][0-7][0-7][0-7])|chown[ \t]+root|wget[ \t]|curl[ \t]|/tmp/|/dev/shm/)'

# ---- Console + files --------------------------------------------------------
show() { printf '%s%s%s\n' "$1" "$2" "${C_OFF:-}"; }
# rollover FILE -> move it aside if it passed --max-mb.
rollover() {
    [ -f "$1" ] || return 0
    _sz=$(wc -c 2>/dev/null <"$1"); case "$_sz" in ''|*[!0-9]*) return 0 ;; esac
    [ "$_sz" -ge "$MAXBYTES" ] && mv "$1" "$1.old"
    return 0
}

# ---- Incremental read -------------------------------------------------------
# new_lines KEY FILE -> print only the lines added since last pass; on the
#   first pass (no cursor) print nothing but remember the end, unless
#   --from-start.  Handles rotation (file shorter than remembered -> restart).
new_lines() {
    _nl_k="$STATE/.cur/$1"; _nl_f="$2"
    [ -r "$_nl_f" ] || return 0
    _nl_tot=$(wc -l 2>/dev/null <"$_nl_f"); case "$_nl_tot" in ''|*[!0-9]*) _nl_tot=0 ;; esac
    if [ -f "$_nl_k" ]; then
        _nl_seen=$(cat "$_nl_k" 2>/dev/null); case "$_nl_seen" in ''|*[!0-9]*) _nl_seen=0 ;; esac
    else
        # First time we have seen this file.
        if [ "$FROMSTART" = 1 ]; then _nl_seen=0; else _nl_seen=$_nl_tot; fi
    fi
    [ "$_nl_tot" -lt "$_nl_seen" ] && _nl_seen=0            # rotated
    # Exactly the lines counted above, even if more arrive while reading.
    [ "$_nl_tot" -gt "$_nl_seen" ] && tail -n +"$((_nl_seen + 1))" "$_nl_f" | head -n "$((_nl_tot - _nl_seen))"
    printf '%s\n' "$_nl_tot" >"$_nl_k"
}

# ---- The parsers ------------------------------------------------------------
# Each pass is a fixed handful of awk runs, however many log lines arrived:
# a brute force or a scanner writes thousands of lines a minute, and a shell
# loop over them would fall behind.  Every parser appends events to the
# per-category log itself and writes candidate alerts, one per line, to
# $STATE/.raw as:  time <TAB> SEV <TAB> section <TAB> item <TAB> detail
# Settings reach awk through the environment (no backslash surprises).
export LX_STRONG LX_WEAK LX_SHELLNAMES LX_INJECT
LX_ADM=$ADMINS; LX_WEBU=$WEBUSERS; LX_OWN=$ALERT_OWN; LX_ALL=$ALLCMD; LX_PASSWD=$PASSWD
LX_RAW="$STATE/.raw"; LX_STATE=$STATE; LX_WEBROOTS=$WEBROOTS; LX_R=$R
export LX_ADM LX_WEBU LX_OWN LX_ALL LX_PASSWD LX_RAW LX_STATE LX_WEBROOTS LX_R

# Shared awk: the account lists, and the rules for one command.
AWK_CLS='
function isin(set, name) { return index(set, " " name " ") > 0 }    # awk: posix-ok
function emit(t, sev, sec, item, detail) { gsub(/\t/, " ", detail); print t "\t" sev "\t" sec "\t" item "\t" detail >> RAW }    # awk: posix-ok
function loadusers(   l, p, n) {    # awk: posix-ok
    ADM = ENVIRON["LX_ADM"]; WEBU = ENVIRON["LX_WEBU"]; OWN = ENVIRON["LX_OWN"] + 0; ALL = ENVIRON["LX_ALL"] + 0
    STRONG = ENVIRON["LX_STRONG"]; WEAK = ENVIRON["LX_WEAK"]; RAW = ENVIRON["LX_RAW"]
    while ((getline l < ENVIRON["LX_PASSWD"]) > 0) { n = split(l, p, ":"); if (n >= 3) { uname[p[3]] = p[1]; uidof[p[1]] = p[3] + 0; nusers++ } }
}
function known(u) { return nusers == 0 || (u in uidof) }    # awk: posix-ok
# classify: WHO did it (the login account), RUNAS is the account it ran as.
function classify(t, sec, who, runas, cmd, tty,   label, adm) {    # awk: posix-ok
    label = (runas != "" && runas != who) ? who " as " runas : who
    if (isin(WEBU, who) || isin(WEBU, runas)) { emit(t, "HIGH", sec, label, "web server account ran a command (web shell?): " cmd); return }
    if (cmd ~ STRONG) { emit(t, "HIGH", sec, label, "dangerous command: " cmd); return }
    if (!known(who)) { emit(t, "HIGH", sec, label, "command by an account not in /etc/passwd: " cmd); return }
    adm = isin(ADM, who)
    if (cmd ~ WEAK) { emit(t, (adm && !OWN) ? "LOW" : "MED", sec, label, "sensitive command: " cmd); return }
    if (adm) { if (ALL || OWN) emit(t, "LOW", sec, label, "command: " cmd); return }
    # A service account with no terminal is a daemon doing its job.
    if (!ALL && (who in uidof) && uidof[who] > 0 && uidof[who] < 1000 && (tty == "" || tty == "?" || tty == "(none)")) return
    emit(t, "MED", sec, label, "command by a non-admin account: " cmd)
}'

# ---- Section: logins and priv (from the auth log) ---------------------------
read_auth() {
    : >"$STATE/.auth"
    if [ "$AUTH_JOURNAL" = 1 ]; then
        # journald: one call returns the new entries and the cursor to
        # continue from, so nothing can fall between two calls.
        _jc="$STATE/.cur/journal"
        if [ -s "$_jc" ]; then
            journalctl --after-cursor="$(cat "$_jc")" --show-cursor -o short-iso --no-pager _COMM=sshd _COMM=sudo _COMM=su _COMM=useradd _COMM=usermod _COMM=userdel _COMM=groupadd _COMM=passwd 2>/dev/null >"$STATE/.jr" || :
        elif [ "$FROMSTART" = 1 ]; then
            journalctl --show-cursor -o short-iso --no-pager _COMM=sshd _COMM=sudo _COMM=su _COMM=useradd _COMM=usermod _COMM=userdel _COMM=groupadd _COMM=passwd 2>/dev/null >"$STATE/.jr" || :
        else
            journalctl -n 0 --show-cursor --no-pager 2>/dev/null >"$STATE/.jr" || :
        fi
        _jn=$(sed -n 's/^-- cursor: //p' "$STATE/.jr" | tail -n 1)
        [ -n "$_jn" ] && printf '%s\n' "$_jn" >"$_jc"
        grep -v '^-- ' "$STATE/.jr" >"$STATE/.auth" 2>/dev/null || :
        rm -f "$STATE/.jr"
    elif [ -n "$AUTHLOG" ] && [ -r "$AUTHLOG" ]; then
        new_lines auth "$AUTHLOG" >"$STATE/.auth"
    fi
    [ -s "$STATE/.auth" ] || return 0
    [ -f "$STATE/.failtotals" ] || : >"$STATE/.failtotals"
    awk "$AWK_CLS"'
        function ts() { return ($1 ~ /^[0-9][0-9][0-9][0-9]-/) ? $1 : $1 " " $2 " " $3 }    # awk: posix-ok
        function after(s, key,   i) { i = index(s, key); return i ? substr(s, i + length(key)) : "" }    # awk: posix-ok
        function word(s) { sub(/^[ \047"]+/, "", s); sub(/[ ;,(\047"].*/, "", s); return s }    # awk: posix-ok
        BEGIN {
            loadusers(); S = ENVIRON["LX_STATE"]
            LOGINS = S "/logins.log"; PRIV = S "/priv.log"; TOT = S "/.failtotals"
            while ((getline l < TOT) > 0) { split(l, a, "\t"); tot[a[1]] = a[2] + 0 }
        }
        / Accepted [a-z-]+ for / {
            s = after($0, " Accepted "); how = word(s); u = word(after(s, " for ")); ip = word(after(s, " from ")); if (ip == "") ip = "?"
            nlog++; print ts() " LOGIN " u " from " ip " (" how ")" >> LOGINS
            prior = tot[ip] + pf[ip]
            if (prior >= 6) emit(ts(), "HIGH", "logins", u "@" ip, "login SUCCEEDED after " prior " failed logins from this address (password guessed?)")
            else if (!known(u)) emit(ts(), "HIGH", "logins", u "@" ip, "login by an account not in /etc/passwd (" how ")")
            else if (u == "root" && how == "password") emit(ts(), "HIGH", "logins", "root@" ip, "root logged in over the network with a PASSWORD")
            else if (isin(ADM, u)) emit(ts(), "LOW", "logins", u "@" ip, "admin login (" how ")")
            else emit(ts(), "MED", "logins", u "@" ip, "login by a non-admin account (" how ")")
            next
        }
        / Failed (password|publickey|keyboard-interactive[^ ]*) for / {
            s = after($0, " for "); if (s ~ /^invalid user /) s = substr(s, 14)
            u = word(s); ip = word(after(s, " from ")); if (ip == "") ip = "?"
            nlog++; print ts() " FAIL " u " from " ip >> LOGINS
            if (ip != "?") pf[ip]++
            next
        }
        / session (opened|closed) for user / {
            if ($0 ~ /cron:session|systemd-user/) next
            print ts() " SESSION-" (($0 ~ / session opened /) ? "OPEN " : "CLOSE ") word(after($0, " for user ")) >> LOGINS
            if ($0 !~ /su(\[[0-9]+\])?:|su:session|su-l:session/) next
        }
        / sudo(\[[0-9]+\])?: / {
            s = after($0, " sudo"); sub(/^(\[[0-9]+\])?: */, "", s); u = word(s)
            if (s ~ /COMMAND=/) {
                cmd = after(s, "COMMAND="); runas = word(after(s, "USER=")); tty = word(after(s, "TTY="))
                if (s ~ /NOT in sudoers|not allowed|command not allowed/) {
                    print ts() " SUDO-DENIED " u ": " cmd >> PRIV
                    emit(ts(), isin(ADM, u) ? "MED" : "HIGH", "priv", u, "tried sudo but is not allowed: " cmd)
                } else if (s ~ /incorrect password attempt/) {
                    print ts() " SUDO-FAIL " u ": " cmd >> PRIV
                    emit(ts(), "MED", "priv", u, "sudo password failures, then tried: " cmd)
                } else {
                    print ts() " SUDO " u (runas != "" && runas != "root" ? " as " runas : "") ": " cmd >> PRIV
                    classify(ts(), "priv", u, runas, cmd, tty)
                }
            } else if (s ~ /authentication failure/) {
                u = word(after(s, " user=")); if (u == "") u = word(after(s, "logname="))
                print ts() " SUDO-FAIL " u >> PRIV
                emit(ts(), "MED", "priv", u, "sudo authentication failure")
            }
            next
        }
        / su(\[[0-9]+\])?: / {
            s = after($0, " su"); sub(/^(\[[0-9]+\])?: */, "", s)
            if (s ~ /^FAILED|FAILED su|authentication failure/) {
                u = word(after(s, " by ")); if (u == "") u = word(after(s, "ruser=")); if (u == "") u = "?"
                print ts() " SU-FAIL " u ": " s >> PRIV
                emit(ts(), "MED", "priv", u, "a su attempt failed")
            } else if (s ~ /^\(to /) {
                to = word(after(s, "(to ")); sub(/\)$/, "", to); u = word(after(s, ") "))
                print ts() " SU " u " -> " to >> PRIV
                if (!isin(ADM, u)) emit(ts(), (to == "root") ? "HIGH" : "MED", "priv", u, "su to " to " by a non-admin account")
            } else if (s ~ /session opened for user /) {
                to = word(after(s, " for user ")); u = word(after(s, " by ")); if (u == "") u = "?"
                print ts() " SU " u " -> " to >> PRIV
                if (u != "?" && !isin(ADM, u)) emit(ts(), (to == "root") ? "HIGH" : "MED", "priv", u, "su to " to " by a non-admin account")
            }
            next
        }
        # Account changes show up in the auth log too.
        / useradd(\[[0-9]+\])?: new user: / { u = word(after($0, "name=")); print ts() " ACCOUNT new user " u >> PRIV; emit(ts(), "HIGH", "accounts", u, "new account created" (($0 ~ /UID=0,/) ? " with UID 0" : "")); next }
        / (usermod|gpasswd)(\[[0-9]+\])?: .*(add|added) .* to group / {
            g = word(after($0, " to group ")); u = ($0 ~ /: user /) ? word(after($0, ": user ")) : word(after($0, " add "))
            print ts() " ACCOUNT " u " added to group " g >> PRIV
            emit(ts(), (g ~ /^(sudo|wheel|admin|root|adm|docker|lxd)$/) ? "HIGH" : "MED", "accounts", u, "added to group " g)
            next
        }
        / passwd(\[[0-9]+\])?: .*password changed for / { u = word(after($0, "password changed for ")); print ts() " ACCOUNT password changed for " u >> PRIV; emit(ts(), "MED", "accounts", u, "password changed"); next }
        / userdel(\[[0-9]+\])?: delete user / { u = word(after($0, "delete user ")); print ts() " ACCOUNT deleted user " u >> PRIV; emit(ts(), "MED", "accounts", u, "account deleted"); next }
        END {
            # Brute force: a burst in this pass, or a slow one adding up.
            for (ip in pf) {
                was = tot[ip]; tot[ip] += pf[ip]
                if (pf[ip] > 5) emit("", "HIGH", "logins", ip, pf[ip] " failed logins from this address (brute force)")
                else if (was < 20 && tot[ip] >= 20) emit("", "HIGH", "logins", ip, tot[ip] " failed logins so far from this address (slow brute force)")
            }
            for (ip in tot) print ip "\t" tot[ip] > (TOT ".new")
            print nlog + 0
        }' "$STATE/.auth" >"$STATE/.n"
    [ -f "$STATE/.failtotals.new" ] && mv "$STATE/.failtotals.new" "$STATE/.failtotals"
    N_LOGIN=$(cat "$STATE/.n" 2>/dev/null); case "$N_LOGIN" in ''|*[!0-9]*) N_LOGIN=0 ;; esac
}

# ---- Section: commands (from auditd execve) ---------------------------------
read_audit() {
    [ -r "$AUDITLOG" ] || return 0
    new_lines audit "$AUDITLOG" >"$STATE/.audit"
    [ -s "$STATE/.audit" ] || return 0
    # One command per audit event id, from the SYSCALL/EXECVE/CWD records that
    # share msg=audit(TIME:ID).  Hex-encoded arguments are decoded.  Events
    # whose working folder is our state folder are this script's own helpers
    # (it runs from there for exactly this reason) and are left out.
    awk "$AWK_CLS"'
        function hexval(c) { return index("0123456789abcdef", tolower(c)) - 1 }    # awk: posix-ok
        function unhex(s,   i, r) { r = ""; for (i = 1; i + 1 <= length(s); i += 2) r = r sprintf("%c", hexval(substr(s, i, 1)) * 16 + hexval(substr(s, i + 1, 1))); return r }    # awk: posix-ok
        function evid(line) { if (match(line, /audit\([0-9.]+:[0-9]+\)/)) return substr(line, RSTART + 6, RLENGTH - 7); return "" }    # awk: posix-ok
        # field: the value of " name=" (the space keeps uid from matching auid).
        function field(line, name,   s, v) {    # awk: posix-ok
            if (!match(line, " " name "=")) return ""
            s = substr(line, RSTART + length(name) + 2)
            if (substr(s, 1, 1) == "\"") { v = substr(s, 2); sub(/".*/, "", v); return v }
            v = s; sub(/[ \t].*/, "", v); return v
        }
        # iso: seconds since 1970 -> 2026-11-15T00:10:01Z (no strftime in POSIX awk).
        function iso(t,   d, r, z, era, doe, yoe, y, doy, mp, m, dd) {    # awk: posix-ok
            t = int(t); d = int(t / 86400); r = t - d * 86400
            z = d + 719468; era = int(z / 146097); doe = z - era * 146097
            yoe = int((doe - int(doe / 1460) + int(doe / 36524) - int(doe / 146096)) / 365)
            y = yoe + era * 400; doy = doe - (365 * yoe + int(yoe / 4) - int(yoe / 100))
            mp = int((5 * doy + 2) / 153); dd = doy - int((153 * mp + 2) / 5) + 1
            m = (mp < 10) ? mp + 3 : mp - 9; if (m <= 2) y++
            return sprintf("%04d-%02d-%02dT%02d:%02d:%02dZ", y, m, dd, int(r / 3600), int((r % 3600) / 60), r % 60)
        }
        function name(u) { return (u in uname) ? uname[u] : ("uid" u) }    # awk: posix-ok
        BEGIN { loadusers(); S = ENVIRON["LX_STATE"]; R = ENVIRON["LX_R"]; CMDS = S "/commands.log"; nw = split(ENVIRON["LX_WEBROOTS"], wr, " ") }
        /type=SYSCALL/ { id = evid($0); if (id == "") next; uid[id] = field($0, "uid"); auid[id] = field($0, "auid"); tty[id] = field($0, "tty"); succ[id] = field($0, "success"); exe[id] = field($0, "exe") }
        /type=CWD/     { id = evid($0); if (id != "") cwd[id] = field($0, "cwd") }
        /type=EXECVE/  {
            id = evid($0); if (id == "") next
            cmd = ""; s = $0
            while (match(s, / a[0-9]+=("[^"]*"|[^ \t]+)/)) {
                tok = substr(s, RSTART + 1, RLENGTH - 1); s = substr(s, RSTART + RLENGTH)
                sub(/^a[0-9]+=/, "", tok)
                if (substr(tok, 1, 1) == "\"") val = substr(tok, 2, length(tok) - 2)
                else if (tok ~ /^[0-9A-Fa-f]+$/ && length(tok) % 2 == 0) val = unhex(tok)
                else val = tok
                gsub(/[\t\n\r]/, " ", val)
                cmd = cmd (cmd == "" ? "" : " ") val
            }
            # A long command line is split over several EXECVE records.
            if (cmd == "") next
            if (id in argv) argv[id] = argv[id] " " cmd
            else { order[++seen] = id; argv[id] = cmd }
        }
        END {
            for (i = 1; i <= seen; i++) {
                id = order[i]
                if (succ[id] == "no") continue
                if (cwd[id] == S) continue                      # this script
                t = id; sub(/:.*/, "", t); t = iso(t)
                runas = name(uid[id])
                who = (auid[id] == "" || auid[id] == "4294967295" || auid[id] == "-1" || auid[id] == "unset") ? runas : name(auid[id])
                ty = (tty[id] == "") ? "?" : tty[id]; cw = (cwd[id] == "") ? "?" : cwd[id]; ex = exe[id]
                n++
                print t " " who (who != runas ? "(as " runas ")" : "") " " ty " " cw "  " argv[id] >> CMDS
                classify(t, "commands", who, runas, argv[id], ty)
                # Where it runs FROM (a web-user command is already HIGH).
                if (isin(WEBU, who) || isin(WEBU, runas)) continue
                org = ""
                if (cw ~ /^(\/tmp|\/var\/tmp|\/dev\/shm|\/run\/shm)(\/|$)/) org = "folder " cw
                if (ex ~ /\(deleted\)$/) org = "a deleted program (" ex ")"
                else if (ex ~ /^(\/tmp|\/var\/tmp|\/dev\/shm|\/run\/shm)\//) org = "program " ex
                for (k = 1; k <= nw; k++) {
                    w = wr[k]; if (R != "" && index(w, R) == 1) w = substr(w, length(R) + 1)
                    if (index(ex, w "/") == 1) org = "program under a web root (" ex ")"
                    else if (org == "" && (cw == w || index(cw, w "/") == 1)) org = "a web root (" cw ")"
                }
                if (org != "") emit(t, "HIGH", "commands", (who != runas ? who " as " runas : who), "process running from " org ": " argv[id])
            }
            print n + 0
        }' "$STATE/.audit" >"$STATE/.n"
    N_CMD=$(cat "$STATE/.n" 2>/dev/null); case "$N_CMD" in ''|*[!0-9]*) N_CMD=0 ;; esac
}

# ---- Section: web access log (what a web shell is being told to do) ---------
read_web() {
    [ -n "$ACCESSLOGS" ] || return 0
    : >"$STATE/.webchk"; N_WEB=0
    for _wl in $ACCESSLOGS; do
        [ -r "$_wl" ] || continue
        _wk=web_$(printf '%s' "$_wl" | tr -c 'A-Za-z0-9' '_')
        new_lines "$_wk" "$_wl" >"$STATE/.web1"
        [ -s "$STATE/.web1" ] || continue
        # Common/combined format: IP - - [TIME] "METHOD PATH PROTO" STATUS ... "UA"
        # A request that got an answer (2xx/3xx) is alerted on its own; ones
        # that failed (a scanner guessing) are counted per address.
        awk "$AWK_CLS"'
            function hexval(c) { return index("0123456789abcdef", tolower(c)) - 1 }    # awk: posix-ok
            function urldec(s,   o, i, c) {    # awk: posix-ok
                if (index(s, "%") == 0) return s
                o = ""
                for (i = 1; i <= length(s); i++) {
                    c = substr(s, i, 1)
                    if (c == "%" && substr(s, i + 1, 2) ~ /^[0-9A-Fa-f][0-9A-Fa-f]$/) { c = sprintf("%c", hexval(substr(s, i + 1, 1)) * 16 + hexval(substr(s, i + 2, 1))); i += 2; if (c ~ /[\t\n\r]/) c = " " }
                    o = o c
                }
                return o
            }
            BEGIN { loadusers(); S = ENVIRON["LX_STATE"]; WEB = S "/web.log"; CHK = S "/.webchk"; NAMES = ENVIRON["LX_SHELLNAMES"]; INJ = ENVIRON["LX_INJECT"] }
            {
                ip = $1; req = ""; rest = ""
                if (match($0, /"[^"]*"/)) { req = substr($0, RSTART + 1, RLENGTH - 2); rest = substr($0, RSTART + RLENGTH) }
                nn = split(req, rq, " "); if (nn < 2) next
                m = rq[1]; p = rq[2]
                st = ""; if (match(rest, /^ [0-9][0-9][0-9]/)) st = substr(rest, 2, 3)
                t = ""; if (match($0, /\[[^]]*\]/)) t = substr($0, RSTART + 1, RLENGTH - 2)
                ua = ""; s = rest; while (match(s, /"[^"]*"/)) { ua = substr(s, RSTART + 1, RLENGTH - 2); s = substr(s, RSTART + RLENGTH) }
                n++
                print t " " ip " \"" m " " p "\" " (st == "" ? "?" : st) " \"" ua "\"" >> WEB
                pp = p; sub(/\?.*/, "", pp); base = pp; sub(/.*\//, "", base)
                dp = urldec(p); lb = tolower(base)
                bad = ""
                if (lb ~ NAMES) bad = "request to a known web-shell filename (" base ")"
                else if (tolower(dp) ~ INJ) bad = "command-injection / web-shell request: " m " " substr(dp, 1, 200)
                answered = (st == "" || st ~ /^[23]/)
                if (bad != "") {
                    if (!answered) { probes[ip]++; if (!(ip in pex)) pex[ip] = pp; next }
                    if (++shown[ip] <= 10) emit(t, "HIGH", "web", ip " " m " " pp, bad)
                    else more[ip]++
                    next
                }
                # A script that answered: the shell checks if it is newly dropped.
                if (answered && lb ~ /\.(php|phtml|php[0-9]|asp|aspx|jsp|jspx|cgi|pl|py|sh)$/ && !((ip, pp) in asked) && nask < 300) {
                    asked[ip, pp] = 1; nask++
                    print t "\t" ip "\t" m "\t" pp >> CHK
                }
            }
            END {
                for (ip in more) emit("", "HIGH", "web", ip, more[ip] " more web-shell / injection requests from this address (see web.log)")
                for (ip in probes) emit("", (probes[ip] >= 20) ? "HIGH" : "MED", "web", ip, probes[ip] " request(s) probing for web shells or injection, all refused (e.g. " pex[ip] ")")
                print n + 0
            }' "$STATE/.web1" >"$STATE/.n"
        _n=$(cat "$STATE/.n" 2>/dev/null); case "$_n" in ''|*[!0-9]*) _n=0 ;; esac
        N_WEB=$((N_WEB + _n))
    done
    # Requests to scripts that answered: is the file newer than our start?
    [ -s "$STATE/.webchk" ] || return 0
    while IFS="$(printf '\t')" read -r _t _ip _m _pp; do
        _rel=${_pp#/}
        case "$_rel" in *..*) continue ;; esac
        for _wr in $WEBROOTS; do
            _f="$_wr/$_rel"
            if [ -f "$_f" ] && [ -n "$(find "$_f" -newer "$STATE/.started" 2>/dev/null)" ]; then
                printf '%s\tHIGH\tweb\t%s\t%s\n' "$_t" "$_ip $_m $_pp" "request to a script added/changed since watching began (dropped web shell?): $_rel" >>"$STATE/.raw"
                break
            fi
        done
    done <"$STATE/.webchk"
}

# ---- Alerts: drop repeats, show the rest ------------------------------------
# The same alert (same severity, section, item and text) is shown once, then
# kept quiet for --repeat-after seconds: a scoring engine logging in every
# minute, or a mail server calling sendmail, should not fill the console.
# Every event is still in its own log file.
AL_H=0; AL_M=0; AL_L=0; AL_R=0
show_alerts() {
    [ -s "$STATE/.raw" ] || return 0
    [ -f "$STATE/.seen" ] || : >"$STATE/.seen"
    _now=$(cc_now); _nowt=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    awk -F'\t' -v now="$_now" -v nowt="$_nowt" -v rep="$REPEAT" -v seenf="$STATE/.seen" '
        BEGIN { while ((getline l < seenf) > 0) { n = split(l, a, "\t"); if (n >= 2 && now - a[1] < 86400) last[a[2]] = a[1] } }
        {
            # Per-address totals ("37 failed logins from ...") repeat with a
            # new number every pass: compare them without the numbers.
            d = $5; if ($4 ~ /^[0-9a-fA-F:.]+$/) gsub(/[0-9]+/, "#", d)
            key = $2 "|" $3 "|" $4 "|" d
            if (rep > 0 && (key in last) && now - last[key] < rep) { quiet++; next }
            if (key in done) { quiet++; next }
            done[key] = 1; last[key] = now
            printf "%s\t%s %-4s %-8s %-22s - %s\n", $2, ($1 == "" ? nowt : $1), $2, $3, $4, $5
        }
        END {
            for (k in last) print last[k] "\t" k > (seenf ".new")
            print "QUIET\t" quiet + 0
        }' "$STATE/.raw" >"$STATE/.show"
    [ -f "$STATE/.seen.new" ] && mv "$STATE/.seen.new" "$STATE/.seen"
    rollover "$ALERTS"
    while IFS="$(printf '\t')" read -r _sev _line; do
        case "$_sev" in
            QUIET) AL_R=$_line; continue ;;
            HIGH)  AL_H=$((AL_H + 1)); show "${C_RED:-}" "  $_line" ;;
            MED)   AL_M=$((AL_M + 1)); show "${C_YEL:-}" "  $_line" ;;
            LOW)   AL_L=$((AL_L + 1)); [ "$SHOWLOW" = 1 ] && show "${C_GRY:-}" "  $_line" ;;
            *)     continue ;;
        esac
        printf '%s\n' "$_line" >>"$ALERTS"
        printf '%s\n' "$_line" >>"$STATE/.newalerts"
    done <"$STATE/.show"
}

# ---- One pass ---------------------------------------------------------------
N_LOGIN=0; N_CMD=0; N_WEB=0
one_pass() {
    N_LOGIN=0; N_CMD=0; N_WEB=0; AL_H=0; AL_M=0; AL_L=0; AL_R=0
    : >"$STATE/.newalerts"; : >"$STATE/.raw"
    for _lf in logins.log priv.log commands.log web.log; do rollover "$STATE/$_lf"; done
    read_auth
    read_audit
    read_web
    show_alerts
    _t=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    _rp=""; [ "$AL_R" -gt 0 ] && _rp=" ($AL_R repeat(s) not shown)"
    if [ "$AL_H" -gt 0 ] || [ "$AL_M" -gt 0 ] || [ "$AL_L" -gt 0 ]; then
        printf '%s  %d login event(s), %d command(s), %d web request(s); alerts: %d HIGH, %d MED, %d LOW%s\n' "$_t" "$N_LOGIN" "$N_CMD" "$N_WEB" "$AL_H" "$AL_M" "$AL_L" "$_rp"
    else
        printf '%s  %d login event(s), %d command(s), %d web request(s); nothing to flag%s\n' "$_t" "$N_LOGIN" "$N_CMD" "$N_WEB" "$_rp"
    fi
    if [ -s "$STATE/.newalerts" ] && [ -n "$ALERTCMD" ]; then
        sh -c "$ALERTCMD" <"$STATE/.newalerts" >>"$CC_LOG" 2>&1 || cc_warn "--alert-cmd failed (exit $?): alerts are still in $ALERTS"
    fi
    # Tamper check: the logs we read should not shrink or vanish.
    for _tf in "$AUTHLOG" "$AUDITLOG"; do
        [ -n "$_tf" ] || continue
        _tk="$STATE/.cur/had_$(printf '%s' "$_tf" | tr -c 'A-Za-z0-9' '_')"
        if [ -s "$_tf" ]; then : >"$_tk"
        elif [ -f "$_tk" ]; then
            rm -f "$_tk"
            show "${C_RED:-}" "  $_t HIGH tamper   $_tf - the log is gone or empty (wiped, or rotated just now)"
            printf '%s HIGH tamper   %s - the log is gone or empty (wiped, or rotated just now)\n' "$_t" "$_tf" >>"$ALERTS"
        fi
    done
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
