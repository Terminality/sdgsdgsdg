#!/bin/sh
# =============================================================================
# ID:       SV-30
# NAME:     Service hardening (FTP and other cleartext/legacy services)
# ROLE:     Applications
# KIND:     changes - dry run unless --apply
# VERSION:  1.3.0
#
# PURPOSE
#   Hardens the insecure services that show up on competition Linux boxes - FTP
#   first, then telnet, rsh/rlogin/rexec, TFTP, SNMP and the old inetd
#   services.  Every action is graded by how risky it is, and the script
#   only goes as far as the level you pick:
#
#     safe     (default)  no user-visible change; cannot break a service or
#                         lock anyone out (e.g. turn off anonymous FTP)
#     service             might change how a scored service behaves, so it
#                         applies the change, checks the service still
#                         answers, and undoes just that change if it broke
#     access              might remove a service entirely (disable the
#                         daemon); covered by the revert timer and skipped
#                         for a service the host list marks as scored
#
#   It shows what it would change first (dry run), asks about each action
#   (like sqlmap: Enter takes the default), then with --apply makes the
#   changes with a revert timer running, and at the end keeps them only if
#   you confirm from a new session.  Same look and undo as LX-39.
#
# USAGE
#   sh SV-30-service-hardening.sh                     dry run, safe level, asks
#   sudo sh SV-30-service-hardening.sh --apply         apply the safe fixes
#   sudo sh SV-30-service-hardening.sh --apply --level service
#   sudo sh SV-30-service-hardening.sh --apply --level access --only ftp-disable
#   sudo sh SV-30-service-hardening.sh --apply --batch --level safe   no questions
#
# OPTIONS
#   --apply            make the changes (without it, dry run only)
#   --level L          how far to go: safe, service, or access.  Each level
#                      includes the ones before it.  Asked if not given
#                      (Enter = safe)
#   --only a,b         only these actions (see the list below)
#   --skip a,b         leave these actions out
#   --exclude a,b      services to leave alone (names like vsftpd, snmpd):
#                      no action will touch them.  Answers the leave-alone
#                      questions in advance
#   --force-scored     allow disabling a service the host list marks scored
#                      (off by default; disabling a scored service loses points)
#   --timer SECONDS    revert countdown when applying (default 120)
#   --no-timer         apply with no revert timer (not advised for --level access)
#   --root DIR         treat DIR as / (for tests); service actions are only
#                      reported, since there is no running system under DIR
#   --no-color         no colours
#   --batch            no questions: take every default for the chosen level
#   --help             this text plus the common options
#
# ACTIONS  (risk in brackets)
#   ftp-anon        [safe]     turn off anonymous FTP login
#   ftp-accounts    [safe]     deny root and system accounts FTP (/etc/ftpusers)
#   ftp-perms       [safe]     lock down the FTP config file (chmod 600)
#   ftp-logging     [safe]     log FTP transfers; hide the version banner
#   ftp-chroot      [service]  jail FTP users to their home folder
#   ftp-tls         [service]  (reports the lines to require FTPS/TLS)
#   ftp-disable     [access]   stop and disable the FTP service
#   telnet-disable  [access]   stop and disable telnet (cleartext)
#   rsh-disable     [access]   disable rsh/rlogin/rexec (cleartext)
#   tftp-disable    [access]   stop and disable TFTP
#   snmp-default    [safe]     (reports) default SNMP community strings
#   snmp-disable    [access]   stop and disable SNMP
#   legacy-disable  [access]   disable finger/echo/chargen/daytime/discard
#
# OUTPUTS  (under --out, in service-hardening-N/)
#   output.txt     everything shown on screen, without colour
#   plan.txt       what it would change (dry-run pass)
#   changes.txt    what it changed (with --apply)
#   summary.txt    the summary page
#   revert.sh      undo this run at any time (written when --apply changed something)
#   run.txt        id, host, time
#
# WHAT IT CHANGES  (only with --apply)
#   FTP config files (vsftpd.conf), /etc/ftpusers, config file permissions,
#   and - at --level access - whether a service is enabled and running.  Every
#   change has an undo line and is covered by the revert timer.  Open FTP
#   sessions are not killed by the config changes; disabling a service stops it.
#
# DEPENDS ON
#   awk, grep, sed.  systemctl / rc-service / service to stop or disable a
#   daemon.  ss or netstat to check a service still listens.
#
# TESTED ON
#   Ubuntu 24.04 under dash, bash, busybox sh, ksh93, mksh and yash, against a
#   fake root (--root) with vsftpd/proftpd config files.  Service enable and
#   disable is reported under --root and exercised live by hand.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - FTP config editing is full for vsftpd; for proftpd and pure-ftpd the
#     daemon is detected and the change to make is reported, not written.
#   - "scored" comes from the host list (ENVIRONMENT / --hosts in other
#     scripts); here, pass services to leave alone with --exclude, and keep
#     --force-scored off so a scored FTP/SNMP is never disabled by accident.
#   - ftp-tls and snmp-default are reported, not applied: TLS needs a cert and
#     a new SNMP community must be coordinated, so they are yours to set.
#   - FTP config changes only take effect when the daemon restarts, so after
#     changing them on a live box the script restarts it (open FTP sessions
#     drop), checks it is running and listening again, and puts the config
#     back if it is not.  A daemon that was stopped is left stopped.
#
# DEBUGGING
#   --debug          show each command
#   output.txt       the full screen log
# =============================================================================

# >>> BT-LIB
_cc_d=$(cd "$(dirname "$0")" && pwd)
while [ "$_cc_d" != "/" ] && [ ! -f "$_cc_d/lib/lib.sh" ]; do _cc_d=$(dirname "$_cc_d"); done
[ -f "$_cc_d/lib/lib.sh" ] || { echo "cannot find lib/lib.sh above $0" >&2; exit 3; }
. "$_cc_d/lib/lib.sh"
# <<< BT-LIB

ALL_ACTIONS="web-version web-trace web-indexes web-exposed web-exposed-remove mail-banner mail-vrfy mail-relay mail-authdelay mail-helo mail-plaintext ntp-chrony splunk-report ftp-anon ftp-accounts ftp-perms ftp-logging ftp-chroot ftp-tls ftp-disable telnet-disable rsh-disable tftp-disable snmp-default snmp-disable legacy-disable"

usage() {
    cat <<'USAGE'
SV-30 Service hardening - FTP and other cleartext/legacy services
  sh SV-30-service-hardening.sh                    dry run, safe level, asks
  sudo sh SV-30-service-hardening.sh --apply        apply the safe fixes
  sudo sh SV-30-service-hardening.sh --apply --level service

  --apply            make the changes (without it, dry run only)
  --box NAME         splunk | webmail | ecomm | other (asked if not given)
  --level L          safe (default) | service | access  (each includes the earlier ones)
  --only a,b         only these actions
  --skip a,b         leave these actions out
  --exclude a,b      services to leave alone (vsftpd, snmpd, ...)
  --force-scored     allow disabling a service the host list marks scored
  --timer SECONDS    revert countdown when applying (default 120)
  --no-timer         apply with no revert timer
  --root DIR         treat DIR as / (tests)
  --no-color         no colours
  --batch            no questions: defaults for the chosen level
  --help             this text

Actions (risk): ftp-anon[safe] ftp-accounts[safe] ftp-perms[safe] ftp-logging[safe]
  ftp-chroot[service] ftp-tls[service] ftp-disable[access] telnet-disable[access]
  rsh-disable[access] tftp-disable[access] snmp-default[safe] snmp-disable[access]
  legacy-disable[access]
USAGE
    cc_usage_common
}

# ---- Options ----------------------------------------------------------------
BOX=""; LEVEL=""; ONLY=""; SKIP=""; EXCL=""; FORCE_SCORED=0; TIMER=120; NOTIMER=0; R=""; COLOR=1
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --apply)         CC_APPLY=1; shift ;;
        --box)           [ $# -ge 2 ] || cc_die 2 "--box needs splunk, webmail, ecomm or other"; BOX=$2; shift 2 ;;
        --level)         [ $# -ge 2 ] || cc_die 2 "--level needs safe, service or access"; LEVEL=$2; shift 2 ;;
        --only)          [ $# -ge 2 ] || cc_die 2 "--only needs a list"; ONLY="$ONLY,$2"; shift 2 ;;
        --skip)          [ $# -ge 2 ] || cc_die 2 "--skip needs a list"; SKIP="$SKIP,$2"; shift 2 ;;
        --exclude)       [ $# -ge 2 ] || cc_die 2 "--exclude needs a list of service names"; EXCL="$EXCL,$2"; shift 2 ;;
        --force-scored)  FORCE_SCORED=1; shift ;;
        --timer)         [ $# -ge 2 ] || cc_die 2 "--timer needs seconds"; TIMER=$2; shift 2 ;;
        --no-timer)      NOTIMER=1; shift ;;
        --root)          [ $# -ge 2 ] || cc_die 2 "--root needs a folder"; [ -d "$2" ] || cc_die 2 "--root: not a folder: $2"
                         R=$(cd "$2" && pwd); [ "$R" = / ] && R=""; shift 2 ;;
        --no-color|--no-colour) COLOR=0; shift ;;
        --help|-h)       usage; exit 0 ;;
        *)               cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
case "$LEVEL" in ''|safe|service|access) ;; *) cc_die 2 "--level must be safe, service or access" ;; esac
cc_box_valid "$BOX" || cc_die 2 "--box must be one of: $CC_BOXES"
case "$TIMER" in ''|*[!0-9]*) cc_die 2 "--timer needs a whole number of seconds" ;; esac
# Validate --only/--skip names.
for _a in $(printf '%s' "$ONLY,$SKIP" | tr ',' ' '); do
    [ -z "$_a" ] && continue
    case " $ALL_ACTIONS " in *" $_a "*) ;; *) cc_die 2 "unknown action '$_a' (see --help for the list)" ;; esac
done

# Which box: says what is scored here, so nothing scored is turned off.
if [ -z "$BOX" ]; then
    cc_box_ask o "${R:-}"
fi
# How far to go: asked when --level was not given (Enter = safe).
if [ -z "$LEVEL" ]; then
    LEVEL=safe
    if _cc_can_ask; then
        cc_choose "How far should I go?" s \
            "s=safe: settings that cannot break anything" \
            "v=service: also service changes; each is checked and undone if the service breaks" \
            "a=access: also turns off services that should not run (telnet, rsh, tftp ...)"
        case "$CC_CHOICE" in s) LEVEL=safe ;; v) LEVEL=service ;; a) LEVEL=access ;; esac
    fi
fi

cc_init "SV-30" "Service hardening" changes
cc_detect_os
cc_use_numbered_dir service-hardening
cc_color_init
[ "$COLOR" = 1 ] || { C_RED=""; C_YEL=""; C_GRN=""; C_CYN=""; C_GRY=""; C_OFF=""; }
W="$CC_RUN_DIR/.work"; mkdir -p "$W" || cc_die 3 "cannot create $W"
CSV=""

OUTF="$CC_RUN_DIR/output.txt"
grep -v '\[NOTE\]\|\[DEBUG\]' "$CC_LOG" >"$OUTF" 2>/dev/null || : >"$OUTF"
# shellcheck disable=SC2034  # CC_TEE is read by the library's log functions
CC_TEE=$OUTF

# P PATH -> PATH under --root (or PATH itself).
P() { printf '%s%s' "$R" "$1"; }

# level_rank LEVEL -> 1/2/3 so levels can be compared.
level_rank() { case "$1" in safe) echo 1 ;; service) echo 2 ;; access) echo 3 ;; esac; }
WANT_RANK=$(level_rank "$LEVEL")

# ---- Per-action metadata ----------------------------------------------------
act_risk() {
    case "$1" in
        ftp-anon|ftp-accounts|ftp-perms|ftp-logging|snmp-default) echo safe ;;
        web-version|web-trace|web-exposed|mail-banner|mail-vrfy|mail-relay|mail-authdelay|mail-plaintext|splunk-report) echo safe ;;
        ftp-chroot|ftp-tls|web-indexes|mail-helo|ntp-chrony) echo service ;;
        *)                                            echo access ;;
    esac
}
act_desc() {
    case "$1" in
        web-version)    echo "hide the web server and PHP version (Server and X-Powered-By headers, error pages)" ;;
        web-trace)      echo "turn off HTTP TRACE in Apache" ;;
        web-indexes)    echo "turn off folder listings in /var/www (Apache)" ;;
        web-exposed)    echo "look for .git folders, backups, dumps, phpinfo pages and the Roundcube installer in the web roots (report)" ;;
        web-exposed-remove) echo "move those exposed files to quarantine" ;;
        mail-banner)    echo "hide the mail server names in the SMTP and IMAP greetings" ;;
        mail-vrfy)      echo "turn off SMTP VRFY (stops checking which usernames exist)" ;;
        mail-relay)     echo "check Postfix is not an open relay (report)" ;;
        mail-authdelay) echo "wait 5 seconds after each failed IMAP login (slows password guessing)" ;;
        mail-helo)      echo "require HELO/EHLO before mail is accepted (drops crude bots)" ;;
        mail-plaintext) echo "show whether IMAP allows passwords without TLS (report)" ;;
        ntp-chrony)     echo "check chrony serves time and allow remote control from localhost only" ;;
        splunk-report)  echo "check the Splunk web UI and accounts (report)" ;;
        ftp-anon)       echo "turn off anonymous FTP login" ;;
        ftp-accounts)   echo "deny root and system accounts FTP" ;;
        ftp-perms)      echo "lock down the FTP config file (chmod 600)" ;;
        ftp-logging)    echo "log FTP transfers and hide the version banner" ;;
        ftp-chroot)     echo "jail FTP users to their home folder" ;;
        ftp-tls)        echo "require FTPS/TLS (reported, not applied)" ;;
        ftp-disable)    echo "stop and disable the FTP service" ;;
        telnet-disable) echo "stop and disable telnet" ;;
        rsh-disable)    echo "disable rsh/rlogin/rexec" ;;
        tftp-disable)   echo "stop and disable TFTP" ;;
        snmp-default)   echo "flag default SNMP community strings (reported)" ;;
        snmp-disable)   echo "stop and disable SNMP" ;;
        legacy-disable) echo "disable finger/echo/chargen/daytime/discard" ;;
    esac
}

# ---- Service detection ------------------------------------------------------
# svc_state NAME -> running | stopped | missing  (live only).
svc_state() {
    [ -z "$R" ] || { echo missing; return; }
    case "$CC_INIT" in
        systemd) _ss=$1; case "$_ss" in *.socket|*.service) ;; *) _ss="$1.service" ;; esac
                 systemctl cat "$_ss" >/dev/null 2>&1 || { echo missing; return; }
                 systemctl is-active --quiet "$1" 2>/dev/null && echo running || echo stopped ;;
        openrc)  [ -e "/etc/init.d/$1" ] || { echo missing; return; }
                 rc-service "$1" status >/dev/null 2>&1 && echo running || echo stopped ;;
        *)       [ -e "/etc/init.d/$1" ] || { echo missing; return; }
                 service "$1" status >/dev/null 2>&1 && echo running || echo stopped ;;
    esac
}

# svc_present NAME -> true if the service exists (used in detection below).
svc_present() { [ "$(svc_state "$1")" != missing ]; }

# FTP daemon + its config file.
FTP_DAEMON=""; FTP_CONF=""
for _c in /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf; do
    [ -f "$(P "$_c")" ] && { FTP_DAEMON=vsftpd; FTP_CONF=$_c; break; }
done
if [ -z "$FTP_DAEMON" ] && [ -f "$(P /etc/proftpd/proftpd.conf)" ]; then FTP_DAEMON=proftpd; FTP_CONF=/etc/proftpd/proftpd.conf; fi
if [ -z "$FTP_DAEMON" ] && { [ -d "$(P /etc/pure-ftpd)" ] || svc_present pure-ftpd 2>/dev/null; }; then FTP_DAEMON=pure-ftpd; fi
if [ -z "$FTP_DAEMON" ] && [ -z "$R" ]; then
    for _d in vsftpd proftpd pure-ftpd; do [ "$(svc_state "$_d")" != missing ] && { FTP_DAEMON=$_d; break; }; done
fi
FTP_SVC=$FTP_DAEMON
# What FTP looked like before we touched anything (for the restart check).
FTP_CHANGED=0; FTP_WAS=missing; FTP_LISTEN=0
if [ -n "$FTP_SVC" ] && [ -z "$R" ]; then
    FTP_WAS=$(svc_state "$FTP_SVC")
    if cc_have ss; then ss -ltn 2>/dev/null | grep -Eq '[:.]21[[:space:]]' && FTP_LISTEN=1
    elif cc_have netstat; then netstat -ltn 2>/dev/null | grep -Eq '[:.]21[[:space:]]' && FTP_LISTEN=1; fi
fi

# Where things are (all relative to /, under --root in tests).
APACHE_DIR=""; APACHE_SVC=""
if [ -d "$(P /etc/apache2)" ]; then APACHE_DIR=/etc/apache2; APACHE_SVC=apache2
elif [ -d "$(P /etc/httpd)" ]; then APACHE_DIR=/etc/httpd; APACHE_SVC=httpd; fi
# The drop-in loads last (zz-) so it wins over security.conf and friends.
APACHE_DROP=""
[ "$APACHE_DIR" = /etc/apache2 ] && [ -d "$(P /etc/apache2/conf-enabled)" ] && APACHE_DROP=/etc/apache2/conf-enabled/zz-bt-hardening.conf
[ "$APACHE_DIR" = /etc/httpd ] && [ -d "$(P /etc/httpd/conf.d)" ] && APACHE_DROP=/etc/httpd/conf.d/zz-bt-hardening.conf
# Alpine: /etc/apache2 has no conf-enabled; httpd.conf reads conf.d/*.conf.
[ "$APACHE_DIR" = /etc/apache2 ] && [ -z "$APACHE_DROP" ] && [ -d "$(P /etc/apache2/conf.d)" ] && APACHE_DROP=/etc/apache2/conf.d/zz-bt-hardening.conf
NGINX_DIR=""; [ -f "$(P /etc/nginx/nginx.conf)" ] && NGINX_DIR=/etc/nginx
# Debian/Ubuntu /etc/php/V/..., Rocky/Fedora /etc/php.ini, Alpine /etc/phpNN/php.ini
PHP_INIS=$( { ls -d "$(P /etc/php)"/*/apache2/php.ini "$(P /etc/php)"/*/fpm/php.ini "$(P /etc/php.ini)" "$(P /etc)"/php[0-9]*/php.ini 2>/dev/null; } | sed "s|^$R||")
POSTFIX_CF=""; [ -f "$(P /etc/postfix/main.cf)" ] && POSTFIX_CF=/etc/postfix/main.cf
DOVECOT_CF=""; [ -f "$(P /etc/dovecot/dovecot.conf)" ] && DOVECOT_CF=/etc/dovecot/dovecot.conf
CHRONY_CF=""; for _c in /etc/chrony/chrony.conf /etc/chrony.conf; do [ -f "$(P "$_c")" ] && { CHRONY_CF=$_c; break; }; done
CHRONY_SVC=chrony; [ -z "$R" ] && [ "$(svc_state chrony)" = missing ] && CHRONY_SVC=chronyd
SPLUNK_HOME=""; for _d in /opt/splunk /opt/splunkforwarder; do [ -d "$(P "$_d")" ] && { SPLUNK_HOME=$_d; break; }; done
WEBROOTS=""; for _d in /var/www /srv/www /srv/http /usr/share/nginx/html; do [ -d "$(P "$_d")" ] && WEBROOTS="$WEBROOTS $_d"; done
ROUNDCUBE=""; for _d in /var/lib/roundcube /usr/share/roundcube /var/www/roundcube /var/www/html/roundcube /var/www/webmail /var/www/html/webmail /srv/www/roundcube; do
    [ -f "$(P "$_d")/program/include/iniset.php" ] && ROUNDCUBE="$ROUNDCUBE $_d"
done

# act_applies NAME -> 0 if the service the action targets is present.
act_applies() {
    case "$1" in
        ftp-*)          [ -n "$FTP_DAEMON" ] ;;
        web-version)    [ -n "$APACHE_DIR$NGINX_DIR$PHP_INIS" ] ;;
        web-trace|web-indexes) [ -n "$APACHE_DROP" ] ;;
        web-exposed|web-exposed-remove) [ -n "$WEBROOTS$ROUNDCUBE" ] ;;
        mail-banner)    [ -n "$POSTFIX_CF$DOVECOT_CF" ] ;;
        mail-vrfy|mail-relay|mail-helo) [ -n "$POSTFIX_CF" ] ;;
        mail-authdelay|mail-plaintext) [ -n "$DOVECOT_CF" ] ;;
        ntp-chrony)     [ -n "$CHRONY_CF" ] ;;
        splunk-report)  [ -n "$SPLUNK_HOME" ] ;;
        telnet-disable) [ -n "$R" ] && return 1; _present telnet telnetd inetutils-telnetd ;;
        rsh-disable)    [ -n "$R" ] && return 1; _present rsh.socket rlogin.socket rexec.socket rsh rlogin ;;
        tftp-disable)   [ -n "$R" ] && return 1; _present tftpd-hpa tftp tftpd ;;
        snmp-default)   [ -f "$(P /etc/snmp/snmpd.conf)" ] ;;
        snmp-disable)   [ -f "$(P /etc/snmp/snmpd.conf)" ] || { [ -z "$R" ] && [ "$(svc_state snmpd)" != missing ]; } ;;
        legacy-disable) [ -n "$R" ] && return 1; _present inetd xinetd ;;
    esac
}
# _present NAME... -> 0 if any is an installed service or a command on PATH.
_present() {
    for _p in "$@"; do
        [ "$(svc_state "$_p")" != missing ] && return 0
        command -v "$_p" >/dev/null 2>&1 && return 0
    done
    return 1
}
# is_excluded SERVICE -> true if the service was named in --exclude / a question.
is_excluded() { case ",$EXCL," in *",$1,"*) return 0 ;; esac; return 1; }

# ---- Build the list of actions to consider ----------------------------------
# An action is in play when: it applies, its risk is within --level, it is not
# --skip'd, and (if --only was given) it is in --only.
CONSIDER=""
for _a in $ALL_ACTIONS; do
    act_applies "$_a" || continue
    [ "$(level_rank "$(act_risk "$_a")")" -le "$WANT_RANK" ] || continue
    case ",$SKIP," in *",$_a,"*) continue ;; esac
    if [ -n "$ONLY" ]; then case ",$ONLY," in *",$_a,"*) ;; *) continue ;; esac; fi
    CONSIDER="$CONSIDER $_a"
done

cc_show "$C_CYN" "SV-30 Service hardening | host $CC_HOST | level $LEVEL | results in $CC_RUN_DIR"
cc_show "" "Legend: ${C_GRN}[+] changed${C_OFF}  ${C_YEL}[~] would change  [*] check by hand${C_OFF}  ${C_RED}[x] failed${C_OFF}  ${C_GRN}[ok] already right${C_OFF}"
[ -n "$R" ] && cc_show "$C_GRY" "Acting on $R as if it were / (service enable/disable is only reported)"
case "$BOX" in
    splunk)  cc_show "$C_GRY" "Scored on splunk: chrony (123/udp), management (8089), query, SSH, ping. Only checked and reported here, never turned off." ;;
    webmail) cc_show "$C_GRY" "Scored on webmail: IMAP, SMTP, webmail login (web), SSH, ping. Each changed service is restarted and must still answer." ;;
    ecomm)   cc_show "$C_GRY" "Scored on ecomm: the web store (HTTP), ping. The web server is restarted after a change and must give the same page." ;;
esac
if [ -n "$FTP_DAEMON" ]; then cc_show "$C_GRY" "FTP: $FTP_DAEMON${FTP_CONF:+ ($FTP_CONF)}"; else cc_show "$C_GRY" "FTP: none detected"; fi
if [ -z "$CONSIDER" ]; then
    cc_show "$C_GRN" "[ok] nothing to harden at level '$LEVEL' (none of those services are here, or all are excluded)."
    [ "$LEVEL" != access ] && cc_show "$C_GRY" "Legacy services (telnet, rsh, tftp, ...) are disabled only at --level access."
    cc_finish
    exit 0
fi

# ---- Questions (sqlmap style) -----------------------------------------------
# One per action in play.  safe/service default yes, access defaults no.
CHOSEN=""
for _a in $CONSIDER; do
    _risk=$(act_risk "$_a")
    # The service each action targets (ftp-* -> the detected FTP daemon).
    _svc=$FTP_DAEMON; case "$_a" in web-*) _svc=${APACHE_SVC:-nginx} ;; mail-vrfy|mail-relay|mail-helo) _svc=postfix ;; mail-authdelay|mail-plaintext) _svc=dovecot ;; mail-*) _svc=postfix ;; ntp-*) _svc=$CHRONY_SVC ;; splunk-*) _svc=splunk ;; telnet-*) _svc=telnet ;; rsh-*) _svc=rsh ;; tftp-*) _svc=tftp ;; snmp-*) _svc=snmpd ;; legacy-*) _svc=inetd ;; esac
    is_excluded "$_svc" && continue
    # access defaults to no, unless the action was named explicitly in --only.
    _def=Y; [ "$_risk" = access ] && _def=N
    case ",$ONLY," in *",$_a,"*) _def=Y ;; esac
    if cc_ask "[$_risk] $(act_desc "$_a")?" "$_def" "yes, do it" "no, skip it"; then CHOSEN="$CHOSEN $_a"; fi
done
if [ -z "$CHOSEN" ]; then
    cc_show "$C_GRY" "Nothing chosen. Nothing to do."
    cc_finish; exit 0
fi

# ---- Apply gating + revert timer --------------------------------------------
CANAPPLY=0
if [ "$CC_APPLY" = 1 ] && { [ -n "$R" ] || cc_is_root; }; then CANAPPLY=1; fi
if [ "$CC_APPLY" = 1 ] && [ "$CANAPPLY" = 0 ]; then
    cc_warn "not root: cannot apply. Showing the plan only (run with sudo to apply)."
    CC_APPLY=0
fi
TIMER_ON=0
if [ "$CANAPPLY" = 1 ] && [ -z "$R" ]; then
    if [ "$NOTIMER" = 1 ]; then
        cc_show "$C_YEL" "[*] No revert timer (--no-timer): if a change locks you out, nothing puts it back."
    else
        cc_timer_start "$TIMER"; TIMER_ON=1
        cc_show "$C_YEL" "[*] Revert timer started: everything this run changes is undone in $((TIMER / 60)):$(printf '%02d' $((TIMER % 60))) unless you keep it at the end."
    fi
fi

# ---- Reporting helpers (like LX-39) -----------------------------------------
OKN=0
row() {
    cc_csv_row "$CSV" "$1" "$2" "$3" "$4" "$5"
    _rw="$3"; [ -n "$4" ] && _rw="$3: $4"
    case "$5" in
        "would change")  cc_show "$C_YEL" "  [~] $2  $_rw" ;;
        changed)         cc_show "$C_GRN" "  [+] $2  $_rw" ;;
        failed)          cc_show "$C_RED" "  [x] FAILED $2  $_rw" ;;
        refused)         cc_show "$C_YEL" "  [-] refused (scored/excluded): $2  $_rw" ;;
        "check by hand") cc_show "$C_YEL" "  [*] check: $2  $_rw" ;;
        "already ok")    OKN=$((OKN + 1)) ;;
        skipped*)        cc_show "$C_GRY" "  [-] $2: $5" ;;
        *)               cc_show "$C_YEL" "  [*] $2: $5" ;;
    esac
    return 0
}
ok_line() { [ "$OKN" -gt 0 ] && cc_show "$C_GRN" "  [ok] $OKN already right"; OKN=0; return 0; }
header() { cc_show "" ""; cc_show "$C_CYN" "==========[ $1 ]=========="; }
result() { if [ "$CC_APPLY" != 1 ]; then echo "would change"; elif [ "$1" -eq 0 ]; then echo changed; else echo failed; fi; }

# ensure_backup FILE -> back up FILE once per run (records the restore undo).
ensure_backup() {
    grep -qxF "$1" "$W/backed" 2>/dev/null && return 0
    # Undo lines are replayed newest first, so this restart is recorded before
    # the file restore and runs after it: a revert also restarts the daemon.
    if [ "$1" = "$FTP_CONF" ] && [ -z "$R" ] && [ "$CC_APPLY" = 1 ] && [ "$(svc_state "$FTP_SVC")" = running ]; then
        cc_undo_add "restart $FTP_SVC after the config is put back" "$(_svc_reload_cmd "$FTP_SVC")"
    fi
    cc_backup_file "$(P "$1")" || return 1
    printf '%s\n' "$1" >>"$W/backed"
    return 0
}

# ---- Apply primitives (run via cc_run, so only on --apply) ------------------
# _kv_set CONF KEY VAL -> rewrite "KEY=VAL" in a vsftpd-style config.
_kv_set() {
    awk -v k="$2" -v v="$3" '
        $0 ~ "^[ \t]*#?[ \t]*" k "=" { if (!done) { print k "=" v; done = 1 }; next }
        { print }
        END { if (!done) print k "=" v }' "$1" >"$1.ccnew" || { rm -f "$1.ccnew"; return 1; }
    # Write back into the same file so its owner and mode stay as they were.
    cat "$1.ccnew" >"$1"; _ks=$?; rm -f "$1.ccnew"; return "$_ks"
}
_ftpusers_add() {
    # $1 = ftpusers path, rest = names to ensure present
    _f=$1; shift
    [ -f "$_f" ] || : >"$_f"
    for _n in "$@"; do grep -qx "$_n" "$_f" 2>/dev/null || printf '%s\n' "$_n" >>"$_f"; done
}
_chmod() { chmod "$1" "$2"; }
_svc_off() {
    # stop and disable $1 across init systems
    case "$CC_INIT" in
        systemd) systemctl disable --now "$1" 2>>"$CC_LOG" ;;
        openrc)  rc-service "$1" stop 2>>"$CC_LOG"; rc-update del "$1" 2>>"$CC_LOG" ;;
        *)       service "$1" stop 2>>"$CC_LOG"; command -v update-rc.d >/dev/null 2>&1 && update-rc.d "$1" disable 2>>"$CC_LOG" ;;
    esac
}

# cur_kv KEY CONF -> the current value of KEY (last one wins), or empty.
cur_kv() { grep -Ei "^[[:space:]]*$1=" "$2" 2>/dev/null | tail -n 1 | sed 's/^[^=]*=//' | tr -d ' \r'; }

# ---- The actions ------------------------------------------------------------
# Each reads FILE under P(); edits only when CC_APPLY=1 (via cc_run).
do_ftp_kv() {   # ACTION KEY WANT  (one vsftpd key)
    _conf=$(P "$FTP_CONF")
    if [ "$FTP_DAEMON" != vsftpd ]; then
        row "$1" "$FTP_DAEMON" "set $2=$3 by hand" "$FTP_DAEMON config" "check by hand"; return 0
    fi
    _cur=$(cur_kv "$2" "$_conf")
    if [ "$(printf '%s' "$_cur" | tr 'A-Z' 'a-z')" = "$(printf '%s' "$3" | tr -d ' ' | tr 'A-Z' 'a-z')" ]; then
        row "$1" vsftpd "$2" "already $3" "already ok"; return 0
    fi
    ensure_backup "$FTP_CONF" || { row "$1" vsftpd "$2" "backup failed" failed; return 0; }
    cc_run "ftp: set $2=$3" _kv_set "$_conf" "$2" "$3"; _kr=$?
    [ "$CC_APPLY" = 1 ] && [ "$_kr" -eq 0 ] && FTP_CHANGED=1
    row "$1" vsftpd "$2" "${_cur:-unset} -> $3" "$(result "$_kr")"
}

# ftp_anon -> anonymous login off, the way each daemon wants it.
ftp_anon() {
    case "$FTP_DAEMON" in
        vsftpd) do_ftp_kv ftp-anon anonymous_enable NO ;;
        proftpd)
            if grep -Eiq '^[[:space:]]*<Anonymous' "$(P "$FTP_CONF")" 2>/dev/null; then
                row ftp-anon proftpd "<Anonymous> block in $FTP_CONF" "remove or comment out the whole block, then restart proftpd" "check by hand"
            else row ftp-anon proftpd "$FTP_CONF" "no <Anonymous> block" "already ok"; fi ;;
        pure-ftpd)
            # Debian layout: one file per setting.
            _pd=$(P /etc/pure-ftpd/conf)
            if [ ! -d "$_pd" ]; then row ftp-anon pure-ftpd "anonymous login" "set NoAnonymous yes in the pure-ftpd config" "check by hand"
            elif [ "$(tr -d ' \r\n' 2>/dev/null <"$_pd/NoAnonymous" | tr 'A-Z' 'a-z')" = yes ]; then row ftp-anon pure-ftpd NoAnonymous "already yes" "already ok"
            else
                _pe=0; [ -f "$_pd/NoAnonymous" ] && _pe=1
                ensure_backup /etc/pure-ftpd/conf/NoAnonymous || { row ftp-anon pure-ftpd NoAnonymous "backup failed" failed; return 0; }
                cc_run "ftp: NoAnonymous yes" _write_line "$_pd/NoAnonymous" yes; _kr=$?
                [ "$CC_APPLY" = 1 ] && [ "$_pe" = 0 ] && cc_undo_add "remove NoAnonymous (created by SV-30)" "rm -f $(cc_shquote "$_pd/NoAnonymous")"
                [ "$CC_APPLY" = 1 ] && [ "$_kr" -eq 0 ] && FTP_CHANGED=1
                row ftp-anon pure-ftpd NoAnonymous "-> yes" "$(result "$_kr")"
            fi ;;
    esac
}
_write_line() { printf '%s\n' "$2" >"$1"; }

do_action() {
    case "$1" in
        web-version)    web_version ;;
        web-trace)      drop_line web-trace "$APACHE_SVC" "$APACHE_DROP" "TraceEnable Off" "HTTP TRACE off" ;;
        web-indexes)    drop_line web-indexes "$APACHE_SVC" "$APACHE_DROP" "<Directory /var/www/>
    Options -Indexes
</Directory>" "no folder listings under /var/www" ;;
        web-exposed)    web_exposed 0 ;;
        web-exposed-remove) web_exposed 1 ;;
        mail-banner)
            [ -n "$POSTFIX_CF" ] && ini_kv mail-banner postfix "$POSTFIX_CF" smtpd_banner '$myhostname ESMTP'
            [ -n "$DOVECOT_CF" ] && ini_kv mail-banner dovecot "$DOVECOT_CF" login_greeting "Mail server ready."
            return 0 ;;
        mail-vrfy)      ini_kv mail-vrfy postfix "$POSTFIX_CF" disable_vrfy_command yes ;;
        mail-helo)      ini_kv mail-helo postfix "$POSTFIX_CF" smtpd_helo_required yes ;;
        mail-relay)     mail_relay ;;
        mail-authdelay) ini_kv mail-authdelay dovecot "$DOVECOT_CF" auth_failure_delay "5 secs" ;;
        mail-plaintext)
            _pt=$(_ini_get "$(P "$DOVECOT_CF")" disable_plaintext_auth)$(_ini_get "$(P "$DOVECOT_CF")" auth_allow_cleartext)
            row mail-plaintext dovecot "passwords without TLS" "setting: ${_pt:-default (refused on 143 without STARTTLS, except from localhost)}. Leave as it is if scoring logs in over plain IMAP" "check by hand" ;;
        ntp-chrony)     chrony_check ;;
        splunk-report)  splunk_report ;;
        ftp-anon)   ftp_anon ;;
        ftp-logging)
            do_ftp_kv ftp-logging xferlog_enable YES
            do_ftp_kv ftp-logging ftpd_banner "FTP server" ;;
        ftp-chroot)
            do_ftp_kv ftp-chroot chroot_local_user YES
            do_ftp_kv ftp-chroot allow_writeable_chroot YES ;;
        ftp-accounts)
            # RHEL-family vsftpd reads /etc/vsftpd/ftpusers; everything else /etc/ftpusers.
            _fun=/etc/ftpusers; [ -f "$(P /etc/vsftpd/ftpusers)" ] && _fun=/etc/vsftpd/ftpusers
            _fu=$(P "$_fun")
            _fu_existed=0; [ -f "$_fu" ] && _fu_existed=1
            _need=""
            for _n in root daemon bin sys sync games man lp mail news uucp proxy www-data backup list irc gnats nobody; do
                cut -d: -f1 "$(P /etc/passwd)" 2>/dev/null | grep -qx "$_n" || [ "$_n" = root ] || continue
                grep -qx "$_n" "$_fu" 2>/dev/null || _need="$_need $_n"
            done
            if [ -z "$_need" ]; then row ftp-accounts ftpusers "$_fun" "root and system accounts already denied" "already ok"
            else
                ensure_backup "$_fun" || { row ftp-accounts ftpusers "$_fun" "backup failed" failed; return 0; }
                # shellcheck disable=SC2086
                cc_run "ftp: deny accounts in $_fun" _ftpusers_add "$_fu" $_need; _kr=$?
                # If the file did not exist, back it out by removing it (a
                # backup only exists when the file was already there).
                [ "$CC_APPLY" = 1 ] && [ "$_fu_existed" = 0 ] && cc_undo_add "remove $_fun (created by SV-30)" "rm -f $(cc_shquote "$_fu")"
                row ftp-accounts ftpusers "$_fun" "deny:$_need" "$(result "$_kr")"
            fi ;;
        ftp-perms)
            _conf=$(P "$FTP_CONF"); [ -f "$_conf" ] || { row ftp-perms "$FTP_CONF" "" "no config file" "already ok"; return 0; }
            _m=$(mode_of "$_conf")
            if [ "$_m" = 0600 ] || [ "$_m" = 0640 ]; then row ftp-perms "$FTP_CONF" mode "$_m" "already ok"
            else
                cc_run "ftp: chmod 600 $FTP_CONF" _chmod 600 "$_conf"; _kr=$?
                [ "$CC_APPLY" = 1 ] && cc_undo_add "restore mode of $FTP_CONF" "chmod $_m $(cc_shquote "$_conf")"
                row ftp-perms "$FTP_CONF" mode "$_m -> 0600" "$(result "$_kr")"
            fi ;;
        ftp-tls)
            row ftp-tls "$FTP_DAEMON" "require FTPS/TLS" "add ssl_enable=YES + force_local_*_ssl=YES and a cert" "check by hand" ;;
        snmp-default)
            _sc=$(P /etc/snmp/snmpd.conf)
            if grep -Eiq '^[[:space:]]*(com2sec|rocommunity6?|rwcommunity6?)[[:space:]].*(public|private)' "$_sc" 2>/dev/null || grep -Eiq 'community[[:space:]]+(public|private)' "$_sc" 2>/dev/null; then
                row snmp-default snmpd "default community string" "public/private in snmpd.conf - change it, coordinate with monitoring" "check by hand"
            else
                row snmp-default snmpd snmpd.conf "no default community string found" "already ok"
            fi ;;
        ftp-disable)    svc_disable "$FTP_SVC" ftp-disable ;;
        telnet-disable) svc_disable "$(first_present telnet.socket telnet inetutils-telnetd telnetd)" telnet-disable ;;
        tftp-disable)   svc_disable "$(first_present tftpd-hpa tftp tftpd)" tftp-disable ;;
        snmp-disable)   svc_disable snmpd snmp-disable ;;
        rsh-disable)
            _any=0
            for _s in rsh.socket rlogin.socket rexec.socket; do [ "$(svc_state "$_s")" != missing ] && { svc_disable "$_s" rsh-disable; _any=1; }; done
            [ "$_any" = 0 ] && row rsh-disable rsh "rsh/rlogin/rexec" "present but not a service: remove the inetd lines by hand" "check by hand" ;;
        legacy-disable)
            row legacy-disable inetd "echo/chargen/daytime/discard/finger" "disable in $( [ "$(svc_state xinetd)" != missing ] && echo xinetd || echo inetd ) and reload it" "check by hand" ;;
    esac
}

# first_present NAME... -> the first that exists as a service, else the first arg.
first_present() {
    for _p in "$@"; do [ "$(svc_state "$_p")" != missing ] && { echo "$_p"; return; }; done
    echo "$1"
}

# svc_disable NAME ACTION -> stop+disable a service, with undo (access level).
svc_disable() {
    _sd=$1; _act=$2
    if [ -n "$R" ]; then row "$_act" "$_sd" "service" "only reported under --root" "skipped (--root)"; return 0; fi
    if [ "$FORCE_SCORED" = 1 ]; then
        cc_is_protected service "$_sd" && cc_warn "$_sd is on the protected list; disabling it anyway (--force-scored)"
    elif ! cc_guard service "$_sd"; then row "$_act" "$_sd" "service" "on the protected list (scored)" refused; return 0; fi
    _st=$(svc_state "$_sd")
    if [ "$_st" = missing ]; then row "$_act" "$_sd" service "not installed" "already ok"; return 0; fi
    if [ "$_st" = stopped ] && ! _svc_enabled "$_sd"; then row "$_act" "$_sd" service "already stopped and disabled" "already ok"; return 0; fi
    if [ "$CC_APPLY" = 1 ]; then
        _en=disabled; _svc_enabled "$_sd" && _en=enabled
        cc_undo_add "re-enable and start $_sd" "$(_svc_on_cmd "$_sd" "$_st" "$_en")"
    fi
    cc_run "disable and stop $_sd" _svc_off "$_sd"
    row "$_act" "$_sd" service "$_st -> stopped/disabled" "$(result $?)"
}
_svc_enabled() {
    case "$CC_INIT" in
        systemd) systemctl is-enabled --quiet "$1" 2>/dev/null ;;
        openrc)  rc-update show 2>/dev/null | awk -v s="$1" '$1 == s { f = 1 } END { exit !f }' ;;
        *)       return 0 ;;   # best effort elsewhere
    esac
}
_svc_on_cmd() {
    case "$CC_INIT" in
        systemd) printf 'systemctl %s %s' "$([ "$2" = running ] && echo 'enable --now' || echo enable)" "$1" ;;
        openrc)  printf 'rc-update add %s; rc-service %s start' "$1" "$1" ;;
        *)       printf 'service %s start' "$1" ;;
    esac
}

# ftp_restart_check -> the FTP daemon only reads its config when it starts.
#   After config changes on a live box: restart it, make sure it is running
#   (and listening again, if it was), and if not put the config back and
#   restart once more.  Called once, after all FTP actions.
ftp_restart_check() {
    [ "$CC_APPLY" = 1 ] && [ -z "$R" ] && [ "$FTP_CHANGED" = 1 ] || return 0
    header "FTP restart check"
    if [ "$FTP_WAS" != running ]; then
        row ftp-restart "$FTP_SVC" "restart" "$FTP_SVC was not running, so it was not started; the new config applies when it starts" "check by hand"; return 0
    fi
    cc_run_quiet "restart $FTP_SVC" _svc_reload "$FTP_SVC"; sleep 1
    _ok=1
    [ "$(svc_state "$FTP_SVC")" = running ] || _ok=0
    [ "$_ok" = 1 ] && [ "$FTP_LISTEN" = 1 ] && ! ftp_listening && { sleep 2; ftp_listening || _ok=0; }
    if [ "$_ok" = 1 ]; then
        cc_show "$C_GRN" "  [+] $FTP_SVC restarted and running: the changes are live"
        cc_csv_row "$CSV" ftp-restart "$FTP_SVC" restart "running after the change" changed
        return 0
    fi
    cc_err "$FTP_SVC did not come back after the change - putting the config back"
    _rb="$CC_BACKUP_DIR$(cc_abspath "$(P "$FTP_CONF")")"
    [ -f "$_rb" ] && cp -p "$_rb" "$(P "$FTP_CONF")" 2>>"$CC_LOG"
    _svc_reload "$FTP_SVC" >>"$CC_LOG" 2>&1; sleep 1
    row ftp-restart "$FTP_SVC" "restart" "service broke with the new config; the config was put back and it is $(svc_state "$FTP_SVC") again" failed
}
ftp_listening() {
    if cc_have ss; then ss -ltn 2>/dev/null | grep -Eq '[:.]21[[:space:]]'
    elif cc_have netstat; then netstat -ltn 2>/dev/null | grep -Eq '[:.]21[[:space:]]'
    else return 0; fi
}
_svc_reload_cmd() {
    case "$CC_INIT" in
        systemd) printf 'systemctl restart %s' "$1" ;;
        openrc)  printf 'rc-service %s restart' "$1" ;;
        *)       printf 'service %s restart' "$1" ;;
    esac
}
_svc_reload() {
    case "$CC_INIT" in
        systemd) systemctl restart "$1" ;;
        openrc)  rc-service "$1" restart ;;
        *)       service "$1" restart ;;
    esac
}

# mode_of PATH -> four-digit octal, from ls -l (portable).
mode_of() {
    _ls=$(ls -ld "$1" 2>/dev/null) || { echo ""; return; }
    _s=$(printf '%s' "$_ls" | cut -c1-10)
    awk -v s="$_s" 'BEGIN{
        p=substr(s,2); v=0
        r=substr(p,1,1)=="r"?4:0; w=substr(p,2,1)=="w"?2:0; x = (substr(p,3,1)=="x"||substr(p,3,1)=="s")?1:0; u=r+w+x
        r=substr(p,4,1)=="r"?4:0; w=substr(p,5,1)=="w"?2:0; x = (substr(p,6,1)=="x"||substr(p,6,1)=="s")?1:0; g=r+w+x
        r=substr(p,7,1)=="r"?4:0; w=substr(p,8,1)=="w"?2:0; x = (substr(p,9,1)=="x"||substr(p,9,1)=="t")?1:0; o=r+w+x
        sp=0; if(substr(p,3,1)=="s"||substr(p,3,1)=="S")sp+=4; if(substr(p,6,1)=="s"||substr(p,6,1)=="S")sp+=2; if(substr(p,9,1)=="t"||substr(p,9,1)=="T")sp+=1
        printf "%d%d%d%d", sp,u,g,o }'
}

# ---- Scored services: web, mail, time, Splunk ------------------------------------
# Each config change is recorded with the service that reads it
# ("SERVICE|FILE|created" in $W/touched).  After applying, every touched
# service that was running is checked (config test), restarted, and must
# answer on the same ports as before (and the web server must give the same
# HTTP status for /).  If not, that service's files are put back and it is
# restarted again - the same idea as the FTP restart check.

# undo_restart SERVICE -> once per service, before its first file is backed
#   up: undo lines run newest first, so on a revert this restart runs AFTER
#   the files are put back, and the service picks up its old config.
undo_restart() {
    [ "$CC_APPLY" = 1 ] && [ -z "$R" ] || return 0
    grep -qxF "$1" "$W/undo-restart" 2>/dev/null && return 0
    printf '%s\n' "$1" >>"$W/undo-restart"
    [ "$(awk -v s="$1" '$1 == s { print $2 }' "$W/before" 2>/dev/null)" = running ] || return 0  # awk ==: posix-ok
    cc_undo_add "restart $1 after its config is put back" "$(_svc_reload_cmd "$1")"
}
# touch_svc SERVICE FILE [created] -> remember which service reads FILE.
touch_svc() { [ "$CC_APPLY" = 1 ] && printf '%s|%s|%s\n' "$1" "$2" "${3:-}" >>"$W/touched"; return 0; }

# _ini_get FILE KEY -> the value of the last uncommented "KEY = value" line
#   at the start of a line, with indented continuation lines (main.cf).
_ini_get() {
    awk -v k="$2" '
        /^[ \t]+[^ \t]/ { if (on) { t = $0; sub(/^[ \t]+/, "", t); sub(/[ \t\r]+$/, "", t); v = v " " t }; next }
        { on = 0 }
        /^[#;]/ { next }
        { split($0, a, "="); kk = a[1]; gsub(/[ \t]/, "", kk) }
        index($0, "=") && kk == k { v = substr($0, index($0, "=") + 1); sub(/^[ \t]+/, "", v); sub(/[ \t\r]+$/, "", v); on = 1 }
        END { print v }' "$1" 2>/dev/null
}
# _ini_set FILE KEY VALUE -> "KEY = VALUE": the first uncommented line for
#   KEY is replaced (with its indented continuation lines, as in main.cf),
#   other uncommented ones are dropped; appended when there is none.
_ini_set() {
    awk -v k="$2" -v v="$3" '
        function key(s,   a) { sub(/^[ \t]+/, "", s); if (s ~ /^[#;]/) return ""; split(s, a, "="); gsub(/[ \t]/, "", a[1]); return (index(s, "=") ? a[1] : "") }  # awk, not shell: posix-ok
        skip && /^[ \t]+[^ \t]/ { next }
        { skip = 0 }
        key($0) == k && $0 !~ /^[ \t]/ { if (!done) { print k " = " v; done = 1 }; skip = 1; next }
        { print }
        END { if (!done) print k " = " v }' "$1" >"$1.ccnew" || { rm -f "$1.ccnew"; return 1; }
    cat "$1.ccnew" >"$1"; _is=$?; rm -f "$1.ccnew"; return "$_is"
}
# ini_kv ACTION SERVICE FILE KEY VALUE [CHECK-VALUE] -> set one setting with backup and undo.
ini_kv() {
    _f=$(P "$3"); _want=${6:-$5}
    _cur=$(_ini_get "$_f" "$4")
    if [ "$(printf '%s' "$_cur" | tr 'A-Z' 'a-z')" = "$(printf '%s' "$_want" | tr 'A-Z' 'a-z')" ]; then
        row "$1" "$2" "$4" "already $_cur" "already ok"; return 0
    fi
    undo_restart "$2"
    ensure_backup "$3" || { row "$1" "$2" "$4" "backup failed" failed; return 0; }
    cc_run "$2: set $4 = $5 in $3" _ini_set "$_f" "$4" "$5"; _kr=$?
    [ "$_kr" -eq 0 ] && touch_svc "$2" "$3"
    row "$1" "$2" "$4" "${_cur:-unset} -> $5" "$(result "$_kr")"
}
# _drop_add FILE LINE -> add LINE to a drop-in file we own (made if missing).
_drop_add() {
    [ -f "$1" ] || printf '# Added by SV-30 (service hardening). Delete this file to undo.\n' >"$1" || return 1
    printf '%s\n' "$2" >>"$1"
}
# drop_line ACTION SERVICE DROPIN LINE DESC -> one line in our drop-in file.
drop_line() {
    _f=$(P "$3")
    if grep -qxF "$4" "$_f" 2>/dev/null; then row "$1" "$2" "$5" "already set" "already ok"; return 0; fi
    _new=""; [ -f "$_f" ] || _new=created
    undo_restart "$2"
    if [ "$CC_APPLY" = 1 ] && [ "$_new" = created ] && ! grep -qxF "$3" "$W/created" 2>/dev/null; then
        cc_undo_add "remove $3 (made by SV-30)" "rm -f $(cc_shquote "$_f")"
        printf '%s\n' "$3" >>"$W/created"
    fi
    cc_run "$2: add '$4' to $3" _drop_add "$_f" "$4"; _kr=$?
    [ "$_kr" -eq 0 ] && touch_svc "$2" "$3" "$_new"
    row "$1" "$2" "$5" "$(printf '%s' "$4" | tr '\n' ' ')" "$(result "$_kr")"
}

# web_version -> no version numbers in headers and error pages.
web_version() {
    if [ -n "$APACHE_DIR" ]; then
        if [ -n "$APACHE_DROP" ]; then
            drop_line web-version "$APACHE_SVC" "$APACHE_DROP" "ServerTokens Prod" "Server header: 'Apache' only, no version or OS"
            drop_line web-version "$APACHE_SVC" "$APACHE_DROP" "ServerSignature Off" "no version line on error pages"
        else
            row web-version "$APACHE_SVC" "ServerTokens Prod, ServerSignature Off" "no conf-enabled or conf.d folder: add them to the main config by hand" "check by hand"
        fi
    fi
    if [ -n "$NGINX_DIR" ]; then
        _nf=$(grep -rlE '^[[:space:]]*server_tokens[[:space:]]' "$(P "$NGINX_DIR")" 2>/dev/null | head -n 1)
        if [ -n "$_nf" ]; then
            _nfr=${_nf#"$R"}
            if grep -Eq '^[[:space:]]*server_tokens[[:space:]]+off' "$_nf"; then row web-version nginx server_tokens "already off" "already ok"
            else
                undo_restart nginx
                ensure_backup "$_nfr" || { row web-version nginx server_tokens "backup failed" failed; return 0; }
                cc_run "nginx: server_tokens off in $_nfr" _sed_inplace "$_nf" 's/^\([[:space:]]*server_tokens[[:space:]]\{1,\}\)[^;]*;/\1off;/'; _kr=$?
                [ "$_kr" -eq 0 ] && touch_svc nginx "$_nfr"
                row web-version nginx server_tokens "-> off ($_nfr)" "$(result "$_kr")"
            fi
        elif grep -Eq 'include[[:space:]]+[^;]*conf\.d/\*\.conf' "$(P "$NGINX_DIR/nginx.conf")" 2>/dev/null; then
            drop_line web-version nginx "$NGINX_DIR/conf.d/zz-bt-hardening.conf" "server_tokens off;" "Server header: 'nginx' only, no version"
        else
            row web-version nginx server_tokens "add 'server_tokens off;' inside the http { } block" "check by hand"
        fi
    fi
    for _pi in $PHP_INIS; do
        _psvc=$APACHE_SVC
        case "$_pi" in
            */fpm/*) _psvc=$(printf '%s' "$_pi" | sed -n 's|^/etc/php/\([^/]*\)/fpm/.*|php\1-fpm|p') ;;
            /etc/php[0-9]*/php.ini) [ -n "$_psvc" ] || _psvc=$(printf '%s' "$_pi" | sed -n 's|^/etc/php\([0-9]*\)/.*|php-fpm\1|p') ;;   # Alpine
        esac
        [ -n "$_psvc" ] || _psvc=php-fpm
        ini_kv web-version "$_psvc" "$_pi" expose_php Off
    done
    [ -z "$APACHE_DIR$NGINX_DIR$PHP_INIS" ] && row web-version web "Apache, nginx, PHP" "none found" "already ok"
    return 0
}
_sed_inplace() { sed "$2" "$1" >"$1.ccnew" && cat "$1.ccnew" >"$1"; _si=$?; rm -f "$1.ccnew"; return "$_si"; }

# web_exposed REMOVE -> files the red team looks for first: .git folders,
#   backups and dumps, phpinfo pages, Roundcube's installer.  0 = report,
#   1 = move them to quarantine (access level).
web_exposed() {
    _act=web-exposed; [ "$1" = 1 ] && _act=web-exposed-remove
    : >"$W/exposed"
    for _wr in $WEBROOTS; do
        find "$(P "$_wr")" -xdev \( -type d -name .git -prune -print \) -o \( -type f \( -name '*.bak' -o -name '*.old' -o -name '*.orig' -o -name '*.save' -o -name '*~' \
            -o -name '*.sql' -o -name '*.sql.gz' -o -name '*.tar' -o -name '*.tar.gz' -o -name '*.tgz' -o -name '*.zip' -o -name '.env' \
            -o -name 'phpinfo.php' -o -name 'info.php' \) -print \) 2>/dev/null | sed "s|^$R||" >>"$W/exposed"
    done
    for _rc in $ROUNDCUBE; do
        [ -d "$(P "$_rc")/installer" ] && printf '%s/installer\n' "$_rc" >>"$W/exposed"
        _rv=$(sed -n "s/.*RCMAIL_VERSION'*[ ,]*'\([0-9][0-9.]*\)'.*/\1/p" "$(P "$_rc")/program/include/iniset.php" 2>/dev/null | head -n 1)
        [ "$1" = 0 ] && row web-exposed roundcube "$_rc" "Roundcube ${_rv:-version unknown}: check it is the newest 1.6.x (older ones have known holes)" "check by hand"
    done
    if [ ! -s "$W/exposed" ]; then row "$_act" web "web roots" "no .git, backups, dumps, phpinfo or installer found" "already ok"; return 0; fi
    sort -u "$W/exposed" | while IFS= read -r _x; do
        if [ "$1" = 0 ]; then
            row web-exposed web "$_x" "can be downloaded by anyone: move it out of the web root" "check by hand"
        else
            cc_run "move $_x to quarantine" cc_quarantine "$(P "$_x")"; _kr=$?
            row web-exposed-remove web "$_x" "moved to quarantine" "$(result "$_kr")"
        fi
    done
}

# mail_relay -> report settings that make Postfix an open relay.
mail_relay() {
    _mf=$(P "$POSTFIX_CF")
    _rr=$(_ini_get "$_mf" smtpd_relay_restrictions); _rc=$(_ini_get "$_mf" smtpd_recipient_restrictions); _mn=$(_ini_get "$_mf" mynetworks)
    case " $_mn " in *0.0.0.0/0*|*::/0*) row mail-relay postfix mynetworks "$_mn: EVERYONE may relay mail through this box" "check by hand" ;; esac
    if [ -n "$_rr$_rc" ] && ! printf "%s %s" "$_rr" "$_rc" | grep -Eq "(reject|defer)_unauth_destination"; then
        row mail-relay postfix "relay restrictions" "no reject_unauth_destination: may be an open relay" "check by hand"
    else
        row mail-relay postfix "relay restrictions" "reject_unauth_destination in place (or the safe default)" "already ok"
    fi
}

# chrony_check -> serves time to the scoring engine, remote control off.
chrony_check() {
    _cf=$(P "$CHRONY_CF")
    _al=$(grep -E '^[[:space:]]*allow([[:space:]]|$)' "$_cf" 2>/dev/null | tr '\n' ';')
    if [ -z "$_al" ]; then
        row ntp-chrony chrony allow "no 'allow' line: chrony answers nobody. If time is scored here, add 'allow <scoring network>' (e.g. allow 10.0.0.0/8)" "check by hand"
    else
        row ntp-chrony chrony allow "serves time to: $_al" "already ok"
    fi
    if grep -Eq '^[[:space:]]*cmdallow' "$_cf" 2>/dev/null; then
        undo_restart "$CHRONY_SVC"
        ensure_backup "$CHRONY_CF" || { row ntp-chrony chrony cmdallow "backup failed" failed; return 0; }
        cc_run "chrony: comment out cmdallow (remote control)" _sed_inplace "$_cf" 's/^\([[:space:]]*cmdallow\)/#bt \1/'; _kr=$?
        [ "$_kr" -eq 0 ] && touch_svc "$CHRONY_SVC" "$CHRONY_CF"
        row ntp-chrony chrony cmdallow "remote control of chrony -> off (localhost only)" "$(result "$_kr")"
    else
        row ntp-chrony chrony cmdallow "remote control already local only" "already ok"
    fi
}

# splunk_report -> things to check on the Splunk box (nothing is changed:
#   the scoring query logs in with Splunk's own accounts).
splunk_report() {
    _sh=$(P "$SPLUNK_HOME")
    _ssl=$(awk -F= 'tolower($1) ~ /enablesplunkwebssl/ { gsub(/[ \r]/, "", $2); v = $2 } END { print v }' "$_sh/etc/system/local/web.conf" 2>/dev/null)
    case "$_ssl" in true|1|True) row splunk-report splunk "web UI" "HTTPS" "already ok" ;;
        *) row splunk-report splunk "web UI (8000)" "plain HTTP: logins can be sniffed. Turn on HTTPS only if the scoring query still works" "check by hand" ;; esac
    row splunk-report splunk admin "change the admin password only together with whoever runs the scoring query (splunk-query logs in)" "check by hand"
    [ -f "$_sh/etc/passwd" ] && row splunk-report splunk "local accounts" "$(cut -d: -f2 "$_sh/etc/passwd" 2>/dev/null | grep . | tr '\n' ' ')- remove any you did not make" "check by hand"
    return 0
}

# ---- Restart and verify each touched service ------------------------------------
# svc_ports SERVICE -> the ports it should answer on (checked only if they
#   were listening before).
svc_ports() {
    case "$1" in
        apache2|httpd|nginx|php*) echo "tcp/80 tcp/443" ;;
        postfix) echo "tcp/25 tcp/465 tcp/587" ;;
        dovecot) echo "tcp/143 tcp/993 tcp/110 tcp/995" ;;
        chrony|chronyd) echo "udp/123" ;;
        vsftpd|proftpd|pure-ftpd) echo "tcp/21" ;;
    esac
}
# listening PROTO PORT -> true if something listens there now.
listening() {
    if cc_have ss; then ss -ln"$(printf '%s' "$1" | cut -c1)" 2>/dev/null | awk -v p="$2" '{ n = $4; sub(/.*:/, "", n); if (n == p) f = 1 } END { exit !f }'
    elif cc_have netstat; then netstat -ln"$(printf '%s' "$1" | cut -c1)" 2>/dev/null | awk -v p="$2" '{ n = $4; sub(/.*:/, "", n); if (n == p) f = 1 } END { exit !f }'
    else return 0; fi
}
http_status() {
    if cc_have curl; then curl -s -o /dev/null -m 5 -w '%{http_code}' http://127.0.0.1/ 2>/dev/null
    elif cc_have wget; then wget -q -S -O /dev/null -T 5 http://127.0.0.1/ 2>&1 | awk '/HTTP\// { c = $2 } END { print c }'
    fi
}
# config_test SERVICE -> the service's own syntax check, where it has one.
config_test() {
    case "$1" in
        apache2) cc_have apache2ctl && apache2ctl -t ;;
        httpd)   cc_have httpd && httpd -t ;;
        nginx)   cc_have nginx && nginx -t ;;
        postfix) cc_have postfix && postfix check ;;
        dovecot) cc_have doveconf && doveconf -n >/dev/null ;;
        *) return 0 ;;
    esac
}
# Before anything changes: what is running and listening, and the web status.
: >"$W/before"
if [ -z "$R" ]; then
    for _s in $APACHE_SVC nginx postfix dovecot $CHRONY_SVC $(for _pi in $PHP_INIS; do case "$_pi" in */fpm/*) printf '%s\n' "$_pi" | sed -n 's|^/etc/php/\([^/]*\)/fpm/.*|php\1-fpm|p' ;; /etc/php[0-9]*/php.ini) printf '%s\n' "$_pi" | sed -n 's|^/etc/php\([0-9]*\)/.*|php-fpm\1|p' ;; esac; done); do
        printf '%s %s %s\n' "$_s" "$(svc_state "$_s")" "$(for _p in $(svc_ports "$_s"); do listening "${_p%/*}" "${_p#*/}" && printf '%s ' "$_p"; done)" >>"$W/before"
    done
    HTTP_BEFORE=$(http_status)
fi
# restart_checks -> after applying: test, restart, verify; put back on failure.
restart_checks() {
    [ "$CC_APPLY" = 1 ] && [ -z "$R" ] && [ -s "$W/touched" ] || return 0
    header "RESTART CHECK (each changed service must still answer)"
    for _s in $(cut -d'|' -f1 "$W/touched" | sort -u); do
        _was=$(awk -v s="$_s" '$1 == s { print $2 }' "$W/before")
        _ports=$(awk -v s="$_s" '$1 == s { $1 = ""; $2 = ""; sub(/^ +/, ""); sub(/ +$/, ""); print }' "$W/before")
        if [ "$_was" != running ]; then
            row restart "$_s" restart "was not running, so it was not started; the change applies when it starts" "check by hand"; continue
        fi
        _ok=1; _why=""
        config_test "$_s" >>"$CC_LOG" 2>&1 || { _ok=0; _why="its config test failed"; }
        if [ "$_ok" = 1 ]; then
            _svc_reload "$_s" >>"$CC_LOG" 2>&1; sleep 2
            [ "$(svc_state "$_s")" = running ] || { _ok=0; _why="it did not start"; }
        fi
        if [ "$_ok" = 1 ]; then
            for _p in $_ports; do listening "${_p%/*}" "${_p#*/}" || { sleep 2; listening "${_p%/*}" "${_p#*/}" || { _ok=0; _why="nothing answers on $_p any more"; }; }; done
        fi
        case "$_s" in apache2|httpd|nginx|php*)
            if [ "$_ok" = 1 ] && [ -n "$HTTP_BEFORE" ]; then
                _hn=$(http_status); [ "$_hn" = "$HTTP_BEFORE" ] || { _ok=0; _why="the web page answers $_hn now, was $HTTP_BEFORE"; }
            fi ;;
        esac
        if [ "$_ok" = 1 ]; then
            cc_show "$C_GRN" "  [+] $_s restarted and answering$([ -n "$_ports" ] && echo " on $_ports"): the changes are live"
            cc_csv_row "$CSV" restart "$_s" restart "answering after the change" changed
            continue
        fi
        cc_err "$_s: $_why - putting its config back"
        awk -F'|' -v s="$_s" '$1 == s { print $2 "|" $3 }' "$W/touched" | sort -u | while IFS='|' read -r _f _c; do
            if [ "$_c" = created ]; then rm -f "$(P "$_f")"
            else _rb="$CC_BACKUP_DIR$(cc_abspath "$(P "$_f")")"; [ -f "$_rb" ] && cat "$_rb" >"$(P "$_f")"; fi
        done
        _svc_reload "$_s" >>"$CC_LOG" 2>&1; sleep 1
        row restart "$_s" restart "$_why; its config was put back and it is $(svc_state "$_s") again" failed
    done
}

# ---- Plan, then apply -------------------------------------------------------
run_all() {
    _ra_q=$CC_QUIET; CC_QUIET=1        # the coloured row lines replace WOULD/DO lines
    _ra_i=0; _ra_n=$(printf '%s\n' $CHOSEN | grep -c .)
    for _a in $CHOSEN; do
        _ra_i=$((_ra_i + 1))
        header "$_ra_i/$_ra_n  $_a  [$(act_risk "$_a")]"
        do_action "$_a"
        ok_line
    done
    CC_QUIET=$_ra_q
}

CSV=$(cc_csv_new plan "action,service,item,detail,status")
: >"$W/backed"
_real=$CC_APPLY; CC_APPLY=0
header "PLAN (dry run: nothing is changed yet)"
run_all
CC_APPLY=$_real
NCH=$(awk "$CC_AWK_CSV"'NR>1 { csvsplit($0,f); if (f[5]=="would change") n++ } END { print n+0 }' "$CSV")
cc_csv_pretty "$CSV" "$CC_RUN_DIR/plan.txt" 90

APPLIED=0
header "DECISION"
if [ "$NCH" -eq 0 ]; then
    cc_show "$C_GRN" "[ok] Nothing to change: everything chosen is already in place (or is check-by-hand)."
elif [ "$CANAPPLY" = 0 ]; then
    cc_show "$C_GRY" "$NCH change(s) planned. Dry run only (use --apply as root), so nothing was changed."
else
    _ad=Y
    if cc_ask "Apply these $NCH change(s)?" "$_ad" "yes, apply them now" "no, change nothing"; then
        if [ "$TIMER_ON" = 1 ] && { cc_timer_fired || [ "$(cc_timer_left)" -lt 3 ]; }; then
            cc_die 3 "the revert timer ran out before anything was changed. Nothing was changed. Run again with a bigger --timer or --batch"
        fi
        CC_APPLY=1; APPLIED=1
        : >"$W/backed"
        CSV=$(cc_csv_new changes "action,service,item,detail,status")
        header "APPLYING"
        run_all
        ftp_restart_check
        restart_checks
        cc_csv_pretty "$CSV" "$CC_RUN_DIR/changes.txt" 90
    else
        cc_show "$C_GRY" "Not applied. The plan is in $CC_RUN_DIR/plan.txt"
    fi
fi

# ---- Keep or revert ---------------------------------------------------------
if [ "$APPLIED" = 1 ] && [ "$TIMER_ON" = 1 ]; then
    header "KEEP OR REVERT"
    cc_timer_finish || true
fi

# ---- Summary ----------------------------------------------------------------
{
    printf 'SV-30 Service hardening | host %s | %s | level %s | %s\n\n' "$CC_HOST" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$LEVEL" "$([ "$APPLIED" = 1 ] && echo APPLIED || echo 'DRY RUN - nothing changed')"
    [ -n "$FTP_DAEMON" ] && printf 'FTP daemon: %s%s\n' "$FTP_DAEMON" "${FTP_CONF:+ ($FTP_CONF)}"
    printf 'Actions chosen:%s\n\n' "$CHOSEN"
    awk "$CC_AWK_CSV"'NR>1 { csvsplit($0,f);
        if (f[5]=="changed"||f[5]=="would change"||f[5]=="failed"||f[5]=="refused"||f[5]=="check by hand")
            printf "  %-14s %-9s %-10s %s\n", toupper(f[5]), f[1], f[2], (f[4]!=""?f[3]": "f[4]:f[3]) }' "$CSV" | head -n 80
    printf '\n'
    if [ "$APPLIED" = 1 ]; then
        if [ "$TIMER_ON" = 1 ]; then printf 'Undo this run at any time: sh %s/revert.sh --force\n' "$CC_RUN_DIR"
        else printf 'Undo lines are in %s (newest at the bottom)\n' "$CC_UNDO"; fi
    else
        printf 'Nothing was changed.%s\n' "$([ "$CANAPPLY" = 0 ] && echo ' Run as root with --apply to change.' || echo '')"
    fi
    printf 'All results: %s\n' "$CC_RUN_DIR"
} >"$CC_RUN_DIR/summary.txt"

header "SUMMARY"
awk -v R="$C_RED" -v Y="$C_YEL" -v G="$C_GRN" -v C="$C_CYN" -v O="$C_OFF" '
    /^  (CHANGED|WOULD CHANGE) / { print G $0 O; next }
    /^  FAILED /                 { print R $0 O; next }
    /^  (REFUSED|CHECK BY HAND) /{ print Y $0 O; next }
    /^(SV-30|FTP daemon|Actions)/{ print C $0 O; next }
    { print }
' "$CC_RUN_DIR/summary.txt"
cat "$CC_RUN_DIR/summary.txt" >>"$OUTF"
rm -rf "$W"
cc_finish
