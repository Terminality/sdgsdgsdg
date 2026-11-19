#!/bin/sh
# =============================================================================
# ID:       SV-44
# NAME:     Splunk hardening and passwords
# ROLE:     Applications  (wave 2, the Splunk box)
# KIND:     changes - dry run unless --apply
# VERSION:  1.0.0
#
# PURPOSE
#   Splunk is three of the scored checks (splunk-mgmt 8089, splunk-query and
#   the box itself) and a favourite red team backdoor: a scripted input or an
#   alert script runs any command as the Splunk user, every few seconds.
#   This finds Splunk, then:
#
#     looks at (never changed): version, who it runs as, the ports, every
#       Splunk user and role, apps that did not come with Splunk (and when
#       they changed), scripted inputs and alert scripts, scripted / LDAP /
#       SAML login, a deployment server or forwarding target that is not
#       yours, HTTP Event Collector tokens, the old default password
#       (admin / changeme), file permissions on the secrets
#     offers (each asked):
#       passwords      a new password for each Splunk user ([r]andom [s]et
#                      [k]eep [a]ll the rest), through Splunk's REST API on
#                      8089, each tested by logging in with it
#       scripts-off    disable scripted inputs in apps that did not come
#                      with Splunk (disabled = 1 in that app's local/inputs.conf)
#       app-quarantine move a suspicious app out of etc/apps (asked per app)
#       deploy-off     remove deploymentclient.conf (a deployment server can
#                      push any app - and any command - to this Splunk)
#       secrets-perms  etc/passwd and etc/auth/splunk.secret readable by the
#                      Splunk owner only; delete etc/system/local/user-seed.conf
#   After file changes Splunk is restarted (asked), then 8089 must answer and
#   a test search must run (that is what splunk-query scores).  If not,
#   everything this run changed is put back and Splunk restarted again.
#   New passwords go to ONE file, passwords.txt (mode 600).
#
#   QUESTIONS (Enter takes the default in capitals; a flag answers each):
#     the Splunk admin user and its CURRENT password     --auth-file FILE
#     each fix (yes / no)                                --only / --skip
#     each Splunk user: [r]andom [s]et [k]eep [a]ll       --users / --exclude
#     each suspicious app: [q]uarantine [k]eep            --quarantine NAMES
#     restart Splunk now?                                 --batch = yes
#
# USAGE
#   sudo sh SV-44-splunk-hardening.sh                              look + dry run
#   sudo sh SV-44-splunk-hardening.sh --protected p.csv --apply
#   sudo sh SV-44-splunk-hardening.sh --protected p.csv --apply --batch --auth-file admin.txt
#
# OPTIONS
#   --apply              make the changes (without it, dry run only)
#   --splunk-home DIR    where Splunk is (default: /opt/splunk, then
#                        /opt/splunkforwarder, then $SPLUNK_HOME)
#   --auth-file FILE     one line: "user password" (the CURRENT admin login;
#                        delete the file after)
#   --only a,b / --skip a,b   fixes by name (passwords scripts-off
#                        app-quarantine deploy-off secrets-perms)
#   --users a,b / --exclude a,b   Splunk users to change / never change
#   --quarantine a,b     apps to quarantine without asking
#   --length N           random password length (default 20)
#   --timer SECONDS      revert countdown (default 120); --no-timer
#   --no-color           no colours
#   --help               this text plus the common options
#
# OUTPUTS  (under --out, in splunk-N/, mode 700)
#   output.txt, findings.txt, plan.txt, summary.txt, run.txt, revert.sh
#   passwords.txt  the new Splunk passwords (mode 600)
#
# DEPENDS ON
#   curl (REST on 8089); Splunk's own bin/splunk to restart.
#   BT_SPLUNK_CURL may name a stand-in curl: the tests use one.
#
# TESTED ON
#   A stand-in Splunk (the real file layout - etc/passwd, etc/apps,
#   inputs.conf, deploymentclient.conf - and a stand-in for the REST API),
#   under dash, bash, busybox sh, ksh93, mksh and yash with gawk, mawk and
#   busybox awk.  NOT yet run against a real Splunk: try it on a test box
#   first, and read the dry run before --apply.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - splunk-query logs in as a Splunk user: put that user on the protected
#     list, or report its new password in the scoring portal.
#   - Changing the admin password needs the current one (Splunk asks for it).
#   - An app you quarantine may be one the scoring search needs: the test
#     search after the restart catches that and puts it back.
#   - LDAP / SAML users are listed only.
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

ALL_FIX="passwords scripts-off app-quarantine deploy-off secrets-perms"
usage() {
    cat <<'USAGE'
SV-44 Splunk hardening and passwords - backdoors out, new passwords, splunk-query still works
  sudo sh SV-44-splunk-hardening.sh                        look + dry run
  sudo sh SV-44-splunk-hardening.sh --protected p.csv --apply

  --apply              make the changes (without it, dry run only)
  --splunk-home DIR    where Splunk is (default /opt/splunk)
  --auth-file FILE     "user password": the CURRENT admin login
  --only a,b / --skip a,b   passwords scripts-off app-quarantine deploy-off secrets-perms
  --users a,b / --exclude a,b   Splunk users to change / never change
  --quarantine a,b     apps to quarantine without asking
  --length N           random password length (default 20)
  --timer SECONDS      revert countdown (default 120); --no-timer
  --no-color           no colours
  --help               show this text
USAGE
    cc_usage_common
}

SH_HOME=""; AUTHF=""; ONLY=""; SKIP=""; USERS=""; EXCLUDE=""; QUAR=""; LEN=20; TIMER=120; NOTIMER=0; COLOR=1
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --apply)        CC_APPLY=1; shift ;;
        --splunk-home)  [ $# -ge 2 ] || cc_die 2 "--splunk-home needs a folder"; [ -d "$2" ] || cc_die 2 "--splunk-home: not a folder: $2"; SH_HOME=$(cd "$2" && pwd); shift 2 ;;
        --auth-file)    [ $# -ge 2 ] || cc_die 2 "--auth-file needs a file"; [ -r "$2" ] || cc_die 2 "--auth-file: cannot read $2"; AUTHF=$(cc_abspath "$2"); shift 2 ;;
        --only)         [ $# -ge 2 ] || cc_die 2 "--only needs a list"; ONLY="$ONLY,$2"; shift 2 ;;
        --skip)         [ $# -ge 2 ] || cc_die 2 "--skip needs a list"; SKIP="$SKIP,$2"; shift 2 ;;
        --users)        [ $# -ge 2 ] || cc_die 2 "--users needs a list"; USERS="$USERS,$2"; shift 2 ;;
        --exclude)      [ $# -ge 2 ] || cc_die 2 "--exclude needs a list"; EXCLUDE="$EXCLUDE,$2"; shift 2 ;;
        --quarantine)   [ $# -ge 2 ] || cc_die 2 "--quarantine needs a list"; QUAR="$QUAR,$2"; shift 2 ;;
        --length)       [ $# -ge 2 ] || cc_die 2 "--length needs a number"; LEN=$2; shift 2 ;;
        --timer)        [ $# -ge 2 ] || cc_die 2 "--timer needs seconds"; TIMER=$2; shift 2 ;;
        --no-timer)     NOTIMER=1; shift ;;
        --no-color|--no-colour) COLOR=0; shift ;;
        --help|-h)      usage; exit 0 ;;
        *)              cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
for _n in "$LEN" "$TIMER"; do case "$_n" in ''|*[!0-9]*) cc_die 2 "--length and --timer need whole numbers" ;; esac; done
[ "$LEN" -ge 12 ] || cc_die 2 "--length must be at least 12"
for _a in $(printf '%s' "$ONLY,$SKIP" | tr ',' ' '); do
    case " $ALL_FIX " in *" $_a "*) ;; *) cc_die 2 "unknown fix '$_a' (passwords scripts-off app-quarantine deploy-off secrets-perms)" ;; esac
done

cc_init "SV-44" "Splunk hardening and passwords" changes
cc_detect_os
# shellcheck disable=SC2034  # read by cc_color_init
[ "$COLOR" = 1 ] || CC_NOCOLOR=1
cc_color_init
cc_use_numbered_dir splunk
rmdir "$CC_RUN_DIR/raw" 2>/dev/null
chmod 700 "$CC_RUN_DIR"
OUTF="$CC_RUN_DIR/output.txt"
grep -v '\[NOTE\]\|\[DEBUG\]' "$CC_LOG" >"$OUTF" 2>/dev/null || : >"$OUTF"
# shellcheck disable=SC2034  # CC_TEE is read by the library's log functions
CC_TEE=$OUTF
W="$CC_RUN_DIR/.work"; mkdir -p "$W"; chmod 700 "$W"
mkdir -p "$CC_RUN_DIR/before"; chmod 700 "$CC_RUN_DIR/before"
CC_CSV_DIR="$W/csv"; mkdir -p "$CC_CSV_DIR"
header() { cc_show "" ""; cc_show "$C_CYN" "==========[ $1 ]=========="; }
inlist() { case ",$2," in *",$1,"*) return 0 ;; esac; return 1; }
ok_pw() { case "$1" in ''|*[!A-Za-z0-9_@%+=.,!?^*~-]*) return 1 ;; esac; [ "${#1}" -ge 8 ]; }
want() { inlist "$1" "$SKIP" && return 1; [ -z "$ONLY" ] || inlist "$1" "$ONLY"; }
CURL=${BT_SPLUNK_CURL:-curl}

cc_show "$C_CYN" "SV-44 Splunk hardening and passwords | host $CC_HOST | results in $CC_RUN_DIR"
cc_show "" "Legend: ${C_RED}[!]${C_OFF} fix now   ${C_YEL}[*]${C_OFF} look at it   ${C_GRN}[ok]${C_OFF} fine   ${C_YEL}[~] would change${C_OFF}   ${C_GRN}[+] changed${C_OFF}   ${C_RED}[x] failed${C_OFF}"

# ---- Find Splunk ------------------------------------------------------------------------
if [ -z "$SH_HOME" ]; then
    for _d in /opt/splunk /opt/splunkforwarder "${SPLUNK_HOME:-}"; do [ -n "$_d" ] && [ -d "$_d/etc" ] && { SH_HOME=$_d; break; }; done
fi
if [ -z "$SH_HOME" ]; then
    cc_show "$C_GRY" "No Splunk here (looked in /opt/splunk, /opt/splunkforwarder, \$SPLUNK_HOME; give --splunk-home DIR)."
    rm -rf "$W"; cc_finish; exit 0
fi
E="$SH_HOME/etc"
FWD=0; [ -f "$E/apps/SplunkUniversalForwarder/default/app.conf" ] || case "$SH_HOME" in *forwarder*) FWD=1 ;; esac
[ -f "$E/apps/SplunkUniversalForwarder/default/app.conf" ] && FWD=1
VER=$(sed -n 's/^VERSION=//p' "$E/splunk.version" 2>/dev/null)
OWNER=$(ls -ld "$SH_HOME" 2>/dev/null | awk '{ print $3 }')
RUNAS=$(ps -eo user=,comm= 2>/dev/null | awk '$2 == "splunkd" { print $1; exit }')
# conf_get FILE STANZA KEY -> the value (last wins).
conf_get() { awk -v s="[$2]" -v k="$3" '/^[ \t]*\[/ { t = $0; gsub(/^[ \t]+|[ \t\r]+$/, "", t); on = (t == s); next }
    on && /=/ { kk = $0; sub(/[ \t]*=.*/, "", kk); gsub(/^[ \t]+/, "", kk); if (kk == k) { v = $0; sub(/^[^=]*=[ \t]*/, "", v); sub(/[ \t\r]+$/, "", v) } }
    END { print v }' "$1" 2>/dev/null; }
MGMT=$(conf_get "$E/system/local/web.conf" settings mgmtHostPort); MGMT=${MGMT##*:}; MGMT=${MGMT:-8089}
WEBP=$(conf_get "$E/system/local/web.conf" settings httpport); WEBP=${WEBP:-8000}
header "1/5  Splunk"
cc_show "" "  $([ "$FWD" = 1 ] && echo 'Universal Forwarder' || echo 'Splunk Enterprise') ${VER:-?} in $SH_HOME   files owned by: ${OWNER:-?}   splunkd runs as: ${RUNAS:-not running}   management port: $MGMT$([ "$FWD" = 0 ] && echo "   web: $WEBP")"
[ -z "$RUNAS" ] && cc_show "$C_RED" "  [!] splunkd is not running: SV-50 --services splunk (or $SH_HOME/bin/splunk start)"
[ "$RUNAS" = root ] && cc_show "$C_YEL" "  [*] splunkd runs as root: a scripted input or alert script red team adds runs as root too"

# ---- Admin login ---------------------------------------------------------------------
read_secret() {
    printf '%s' "$2" >/dev/tty
    stty -echo </dev/tty 2>/dev/null
    _cc_read "$1"; _rs_rc=$?
    stty echo </dev/tty 2>/dev/null
    printf '\n' >/dev/tty
    return "$_rs_rc"
}
# A curl config file per login keeps passwords off the command line.
# curlcfg FILE USER PASSWORD
curlcfg() { (umask 077; printf 'user = "%s:%s"\n' "$2" "$(printf '%s' "$3" | sed 's/\\/\\\\/g; s/"/\\"/g')" >"$1"); }
# rest CFG METHOD PATH [name@file ...] -> HTTP code; body in $W/r
rest() {
    _cf=$1; _m=$2; _p=$3; shift 3
    _da=""; for _x in "$@"; do _da="$_da --data-urlencode $_x"; done
    # shellcheck disable=SC2086  # _da is a list of --data-urlencode words
    "$CURL" -sk -m 20 -K "$_cf" -X "$_m" -o "$W/r" -w '%{http_code}' $_da "https://127.0.0.1:$MGMT$_p" 2>>"$CC_LOG"
}
ADMIN=""; AUTHOK=0; ACF="$W/admin.cfg"
if [ -n "$AUTHF" ]; then
    read -r ADMIN _apw <"$AUTHF"
elif [ -n "$RUNAS" ] && _cc_can_ask; then
    cc_ask_text "Splunk admin user (to change passwords and read users through 8089)" admin "a Splunk user with the admin role"
    ADMIN=$CC_ANSWER
    read_secret _apw "  Its CURRENT password (not shown; Enter = skip the login): " || _apw=""
fi
if [ -n "$ADMIN" ] && [ -n "${_apw:-}" ] && [ -n "$RUNAS" ]; then
    curlcfg "$ACF" "$ADMIN" "$_apw"
    (umask 077; printf '%s' "$_apw" >"$W/admin.old")
    _c=$(rest "$ACF" GET /services/authentication/current-context)
    if [ "$_c" = 200 ]; then AUTHOK=1; cc_show "$C_GRN" "  [ok] logged in to 8089 as $ADMIN"
    else cc_show "$C_RED" "  [x] could not log in to 8089 as $ADMIN (HTTP ${_c:-none}): passwords are listed but not changed"; fi
fi
_apw=""
# The old default password.
DEFPW=0
if [ -n "$RUNAS" ]; then
    curlcfg "$W/def.cfg" admin changeme
    [ "$(rest "$W/def.cfg" GET /services/authentication/current-context)" = 200 ] && DEFPW=1
    rm -f "$W/def.cfg"
fi

# ---- Findings --------------------------------------------------------------------------
header "2/5  users, apps, inputs, logins"
: >"$W/find"
find_add() { printf '%s|%s|%s\n' "$1" "$2" "$3" >>"$W/find"; case "$1" in HIGH) cc_show "$C_RED" "  [!] $2: $3" ;; MED) cc_show "$C_YEL" "  [*] $2: $3" ;; *) cc_show "$C_GRN" "  [ok] $2: $3" ;; esac; }
[ "$DEFPW" = 1 ] && find_add HIGH "admin" "the old default password 'changeme' WORKS - change it now"
# Users: etc/passwd is ":user:hash:?:Full name:roles:email:..."
: >"$W/users"
if [ -f "$E/passwd" ]; then
    awk -F: 'NF > 2 && $2 != "" { print $2 "|" $6 }' "$E/passwd" >"$W/users"
    while IFS='|' read -r _u _r; do
        case ";$_r;" in *";admin;"*|*";sc_admin;"*) find_add MED "user $_u" "roles: $_r (an admin: one of yours?)" ;; *) cc_show "" "  user $_u: roles: ${_r:-?}" ;; esac
    done <"$W/users"
fi
# Roles that hand out admin powers.
for _f in "$E"/system/local/authorize.conf "$E"/apps/*/local/authorize.conf; do
    [ -f "$_f" ] || continue
    awk '/^\[role_/ { r = $0; gsub(/[][]/, "", r); sub(/^role_/, "", r); next }
         /^[ \t]*(admin_all_objects|edit_user|change_authentication|edit_roles|edit_scripted|rest_apps_management)[ \t]*=[ \t]*enabled/ { k = $0; sub(/[ \t]*=.*/, "", k); gsub(/^[ \t]+/, "", k); if (r != "admin" && r != "sc_admin") print r " has " k }' "$_f" |
        while IFS= read -r _l; do find_add HIGH "role" "$_l (in ${_f#"$SH_HOME"/}) - a role that can make admins"; done
done
# Scripted / LDAP / SAML login.
_at=$(conf_get "$E/system/local/authentication.conf" authentication authType)
case "$_at" in Scripted) find_add HIGH "login" "authType = Scripted: a script decides who logs in ($E/system/local/authentication.conf)" ;;
    LDAP|SAML) find_add MED "login" "authType = $_at: those users are not changed here" ;; esac
# Deployment server and forwarding.
for _f in "$E"/system/local/deploymentclient.conf "$E"/apps/*/local/deploymentclient.conf "$E"/apps/*/default/deploymentclient.conf; do
    [ -f "$_f" ] || continue
    _tu=$(conf_get "$_f" target-broker:deploymentServer targetUri)
    [ -n "$_tu" ] && find_add HIGH "deployment" "this Splunk takes apps from $_tu (${_f#"$SH_HOME"/}): a deployment server can push any command here"
    printf '%s\n' "$_f" >>"$W/deploy"
done
for _f in "$E"/system/local/outputs.conf "$E"/apps/*/local/outputs.conf; do
    [ -f "$_f" ] || continue
    _sv=$(grep -h '^[ \t]*server[ \t]*=' "$_f" | sed 's/^[^=]*=[ \t]*//' | tr '\n' ' ')
    [ -n "$_sv" ] && find_add MED "forwarding" "logs are sent to $_sv(${_f#"$SH_HOME"/}) - is that your Splunk?"
done
# HEC tokens.
for _f in "$E"/system/local/inputs.conf "$E"/apps/*/local/inputs.conf; do
    [ -f "$_f" ] || continue
    grep -o '^\[http://[^]]*\]' "$_f" 2>/dev/null | while IFS= read -r _t; do find_add MED "HEC" "token $_t in ${_f#"$SH_HOME"/} (anyone with it can send fake logs)"; done
done
# Apps that did not come with Splunk.
KNOWN=" alert_logevent alert_webhook appsbrowser framework gettingstarted introspection_generator_addon journald_input launcher learned legacy python_upgrade_readiness_app sample_app search splunk_archiver splunk_assist splunk_essentials_8_2 splunk_essentials_9_0 splunk_gdi splunk_httpinput splunk_instrumentation splunk_internal_metrics splunk_metrics_workspace splunk_monitoring_console splunk_rapid_diag splunk_secure_gateway splunk-dashboard-studio splunk_ingest_actions splunk-visual-exporter SplunkForwarder SplunkLightForwarder SplunkUniversalForwarder SplunkDeploymentServerConfig user-prefs dmc search_artifacts "
: >"$W/apps"
for _a in "$E"/apps/*/; do
    [ -d "$_a" ] || continue
    _n=$(basename "$_a")
    case "$KNOWN" in *" $_n "*) continue ;; esac
    _new=""; [ -n "$(find "$_a" -newer "$E/splunk.version" -type f 2>/dev/null | head -n 1)" ] && _new="files newer than the Splunk install"
    _recent=""; [ -n "$(find "$_a" -mmin -240 -type f 2>/dev/null | head -n 1)" ] && _recent="changed in the last 4 hours"
    _bin=""; [ -n "$(find "$_a/bin" -type f 2>/dev/null | head -n 1)" ] && _bin="has programs in bin/: $(ls "$_a/bin" 2>/dev/null | head -n 4 | tr '\n' ' ')"
    _lvl=MED; [ -n "$_bin" ] && [ -n "$_recent" ] && _lvl=HIGH
    printf '%s|%s\n' "$_n" "$_lvl" >>"$W/apps"
    find_add "$_lvl" "app $_n" "did not come with Splunk${_recent:+; $_recent}${_bin:+; $_bin}${_new:+; $_new}"
done
# Scripted inputs, alert scripts, custom commands (they run programs).
: >"$W/scripts"
for _f in "$E"/apps/*/default/inputs.conf "$E"/apps/*/local/inputs.conf "$E"/system/local/inputs.conf; do
    [ -f "$_f" ] || continue
    _app=$(printf '%s' "$_f" | sed -n 's|.*/apps/\([^/]*\)/.*|\1|p'); _app=${_app:-system}
    awk '/^[ \t]*\[/ { if (s != "") print s "|" d; s = ""; d = "no" } /^[ \t]*\[script:\/\// { s = $0; gsub(/^[ \t]*\[|\][ \t\r]*$/, "", s) }
         s != "" && /^[ \t]*disabled[ \t]*=/ { v = $0; sub(/^[^=]*=[ \t]*/, "", v); d = (v ~ /^(1|true|t)/) ? "yes" : "no" }
         END { if (s != "") print s "|" d }' "$_f" | while IFS='|' read -r _s _d; do
        _local="$E/apps/$_app/local/inputs.conf"; [ "$_app" = system ] && _local="$E/system/local/inputs.conf"
        _dl=$(conf_get "$_local" "$_s" disabled); case "$_dl" in 1|true|t|True) _d=yes ;; 0|false|f|False) _d=no ;; esac
        [ "$_d" = yes ] && continue
        case "$KNOWN" in *" $_app "*) _lv=MED ;; *) _lv=HIGH ;; esac
        printf '%s|%s|%s\n' "$_app" "$_s" "$_lv" >>"$W/scripts"
        find_add "$_lv" "scripted input" "$_s in app $_app runs a program on a timer$([ "$_lv" = HIGH ] && echo ' - an app that did not come with Splunk')"
    done
done
for _f in "$E"/apps/*/local/savedsearches.conf "$E"/system/local/savedsearches.conf; do
    [ -f "$_f" ] || continue
    awk '/^[ \t]*\[/ { s = $0 } /^[ \t]*action\.script[ \t]*=[ \t]*(1|true)/ || /^[ \t]*action\.script\.filename[ \t]*=/ { print s }' "$_f" | sort -u |
        while IFS= read -r _s; do find_add HIGH "alert script" "$_s in ${_f#"$SH_HOME"/} runs a script when it fires"; done
done
# Secrets on disk.
for _f in "$E/passwd" "$E/auth/splunk.secret"; do
    [ -f "$_f" ] || continue
    _m=$(ls -l "$_f" | cut -c1-10)
    case "$_m" in -rw-------|-r--------) ;; *) find_add MED "file" "${_f#"$SH_HOME"/} is $_m (others can read it)"; printf '%s\n' "$_f" >>"$W/perms" ;; esac
done
[ -f "$E/system/local/user-seed.conf" ] && { find_add MED "file" "etc/system/local/user-seed.conf is still there (it holds the first admin password hash)"; printf '%s\n' "$E/system/local/user-seed.conf" >>"$W/perms"; }
[ -s "$W/find" ] || cc_show "$C_GRN" "  [ok] nothing odd found"

# ---- Questions ----------------------------------------------------------------------
header "3/5  questions"
CHOSEN=""
_q() {   # _q FIX DEFAULT QUESTION
    want "$1" || return 0
    if inlist "$1" "$ONLY" || cc_ask "$3" "$2" "yes, do it" "no, skip it"; then CHOSEN="$CHOSEN $1"; fi
}
[ "$AUTHOK" = 1 ] && [ -s "$W/users" ] && _q passwords Y "[passwords] new passwords for the Splunk users (asked one by one)?"
[ -s "$W/scripts" ] && grep -q '|HIGH$' "$W/scripts" && _q scripts-off Y "[scripts-off] disable the $(grep -c '|HIGH$' "$W/scripts") scripted input(s) in apps that did not come with Splunk?"
[ -s "$W/apps" ] && _q app-quarantine N "[app-quarantine] look at each app that did not come with Splunk and quarantine the bad ones?"
[ -s "$W/deploy" ] && _q deploy-off N "[deploy-off] remove deploymentclient.conf (stop taking apps from a deployment server)?"
[ -s "$W/perms" ] && _q secrets-perms Y "[secrets-perms] secrets readable by the Splunk owner only, user-seed.conf removed?"
[ "$AUTHOK" = 1 ] || { want passwords && [ -n "$RUNAS" ] && cc_show "$C_GRY" "  (passwords: not offered - no admin login to 8089)"; }

# Per user and per app.
: >"$W/uplan"; : >"$W/typed"; chmod 600 "$W/typed"
case " $CHOSEN " in *" passwords "*)
    while IFS='|' read -r _u _r; do
        _a=r; _why=random
        if inlist "$_u" "$EXCLUDE"; then _a=k; _why="--exclude"
        elif [ -n "$USERS" ] && ! inlist "$_u" "$USERS"; then _a=k; _why="not in --users"; fi
        printf '%s|%s|%s\n' "$_u" "$_a" "$_why" >>"$W/uplan"
    done <"$W/users"
    if _cc_can_ask && cc_ask "Go through each Splunk user one by one?" Y "yes, ask me about each user" "no, a random password for each"; then
        _all=0; : >"$W/uplan.n"
        while IFS='|' read -r _u _a _why; do
            if [ "$_all" = 1 ] || [ "$_a" = k ]; then printf '%s|%s|%s\n' "$_u" "$_a" "$_why" >>"$W/uplan.n"; continue; fi
            cc_choose "Splunk user $_u?" r "r=random new password" "s=set one: you type it twice, it is not shown" "k=keep it as it is" "a=all the rest: random"
            case "$CC_CHOICE" in
                a) _all=1; printf '%s|r|random\n' "$_u" >>"$W/uplan.n" ;;
                k) printf '%s|k|you said keep\n' "$_u" >>"$W/uplan.n" ;;
                s) _tp=""; while :; do
                       read_secret _p1 "    New password for $_u (not shown): " || break
                       read_secret _p2 "    Same password again: " || break
                       [ "$_p1" = "$_p2" ] && ok_pw "$_p1" && { _tp=$_p1; break; }
                       printf '    Different, or not 8+ characters of letters, digits and _@%%+=.,!?^*~-. Again.\n' >/dev/tty
                   done; _p1=""; _p2=""
                   if [ -n "$_tp" ]; then printf '%s\t%s\n' "$_u" "$_tp" >>"$W/typed"; printf '%s|s|typed\n' "$_u" >>"$W/uplan.n"; else printf '%s|k|no password typed\n' "$_u" >>"$W/uplan.n"; fi; _tp="" ;;
                *) printf '%s|r|random (you chose)\n' "$_u" >>"$W/uplan.n" ;;
            esac
        done <"$W/uplan"
        mv "$W/uplan.n" "$W/uplan"
    fi ;;
esac
: >"$W/qapps"
case " $CHOSEN " in *" app-quarantine "*)
    while IFS='|' read -r _n _lv; do
        if inlist "$_n" "$QUAR"; then printf '%s\n' "$_n" >>"$W/qapps"; continue; fi
        cc_show "$C_GRY" "    $_n: $(find "$E/apps/$_n" -type f 2>/dev/null | sed "s|$E/apps/$_n/||" | head -n 8 | tr '\n' ' ')"
        cc_choose "App $_n ($([ "$_lv" = HIGH ] && echo 'programs, changed lately' || echo 'did not come with Splunk'))?" "$([ "$_lv" = HIGH ] && echo q || echo k)" \
            "q=quarantine it (moved out of etc/apps; Splunk restarts without it)" "k=keep it"
        [ "$CC_CHOICE" = q ] && printf '%s\n' "$_n" >>"$W/qapps"
    done <"$W/apps" ;;
esac

# ---- Plan ---------------------------------------------------------------------------------
header "4/5  plan"
NCH=0; RESTART=0
plan() { NCH=$((NCH + 1)); cc_show "$C_YEL" "  [~] $1"; printf '%s\n' "$1" >>"$CC_RUN_DIR/plan.txt"; }
: >"$CC_RUN_DIR/plan.txt"
for _x in $CHOSEN; do
    case "$_x" in
        passwords) while IFS='|' read -r _u _a _why; do [ "$_a" != k ] && plan "new password for Splunk user $_u ($_why)"; done <"$W/uplan" ;;
        scripts-off) while IFS='|' read -r _ap _s _lv; do [ "$_lv" = HIGH ] && { plan "disable $_s (app $_ap)"; RESTART=1; }; done <"$W/scripts" ;;
        app-quarantine) while IFS= read -r _n; do plan "quarantine app $_n"; RESTART=1; done <"$W/qapps" ;;
        deploy-off) while IFS= read -r _f; do plan "remove ${_f#"$SH_HOME"/}"; RESTART=1; done <"$W/deploy" ;;
        secrets-perms) while IFS= read -r _f; do case "$_f" in *user-seed.conf) plan "remove ${_f#"$SH_HOME"/}" ;; *) plan "chmod 600 ${_f#"$SH_HOME"/}" ;; esac; done <"$W/perms" ;;
    esac
done
[ "$NCH" -eq 0 ] && cc_show "$C_GRN" "  [ok] Nothing to change."
[ "$RESTART" = 1 ] && cc_show "$C_GRY" "  (these need a Splunk restart: asked before it happens)"

# ---- Apply ----------------------------------------------------------------------------------
header "5/5  apply"
PWOUT="$CC_RUN_DIR/passwords.txt"; NOK=0; NBAD=0; APPLIED=0; TIMER_ON=0; BROKE=0
GO=0
if [ "$NCH" -eq 0 ]; then :
elif [ "$CC_APPLY" != 1 ] || ! cc_is_root; then
    cc_is_root || cc_show "$C_YEL" "  [!] not root: showing the plan only"
    cc_show "$C_GRY" "  $NCH change(s) planned. Dry run: nothing was changed. Run again with --apply."
    # shellcheck disable=SC2034  # read by cc_finish
    CC_N_WOULD=$NCH
elif cc_ask "Apply these $NCH change(s)?" Y "yes, apply them (a revert timer undoes them unless you confirm from a NEW session)" "no, change nothing"; then GO=1
else cc_show "$C_GRY" "  Not applied. The plan is in $CC_RUN_DIR/plan.txt"; fi

search_ok() {   # a test search, the way splunk-query scores
    [ "$FWD" = 1 ] && return 0
    printf '%s' 'search index=_internal earliest=-15m | head 1' >"$W/q"; printf '%s' json >"$W/of"
    [ "$(rest "$1" POST /services/search/jobs/export "search@$W/q" "output_mode@$W/of")" = 200 ]
}
splunk_restart() { "$SH_HOME/bin/splunk" restart --accept-license --answer-yes --no-prompt >>"$CC_LOG" 2>&1; }
mgmt_up() { _i=0; while [ "$_i" -lt 30 ]; do [ "$(rest "$1" GET /services/server/info)" = 200 ] && return 0; sleep 3; _i=$((_i + 1)); done; return 1; }

if [ "$GO" = 1 ]; then
    APPLIED=1
    U0=$(grep -c . "$CC_UNDO" 2>/dev/null)
    if [ "$NOTIMER" != 1 ]; then cc_timer_start "$TIMER"; TIMER_ON=1
        cc_show "$C_YEL" "  [*] Revert timer started: everything is undone in $((TIMER / 60)):$(printf '%02d' $((TIMER % 60))) unless you keep it at the end."; fi
    LOGIN=$ACF
    # Files first, then the restart, then the passwords (a restart does not need them).
    case " $CHOSEN " in *" scripts-off "*)
        while IFS='|' read -r _ap _s _lv; do
            [ "$_lv" = HIGH ] || continue
            _lf="$E/apps/$_ap/local/inputs.conf"; [ "$_ap" = system ] && _lf="$E/system/local/inputs.conf"
            mkdir -p "$(dirname "$_lf")"
            if [ -f "$_lf" ]; then cc_backup_file "$_lf" >/dev/null; else cc_undo_add "remove $_lf (made by SV-44)" "rm -f $(cc_shquote "$_lf")"; fi
            if grep -qF "[$_s]" "$_lf" 2>/dev/null; then
                awk -v s="[$_s]" '{ print } $0 == s { print "disabled = 1" }' "$_lf" >"$_lf.n" && cat "$_lf.n" >"$_lf"; rm -f "$_lf.n"
            else printf '\n[%s]\ndisabled = 1\n' "$_s" >>"$_lf"; fi
            chown "$OWNER" "$_lf" 2>/dev/null
            cc_show "$C_GRN" "  [+] disabled $_s (app $_ap)"; NOK=$((NOK + 1))
        done <"$W/scripts" ;;
    esac
    case " $CHOSEN " in *" app-quarantine "*)
        while IFS= read -r _n; do
            if cc_quarantine "$E/apps/$_n" >>"$CC_LOG" 2>&1; then cc_show "$C_GRN" "  [+] quarantined app $_n"; NOK=$((NOK + 1)); else cc_show "$C_RED" "  [x] could not quarantine $_n"; NBAD=$((NBAD + 1)); fi
        done <"$W/qapps" ;;
    esac
    case " $CHOSEN " in *" deploy-off "*)
        while IFS= read -r _f; do cc_backup_file "$_f" >/dev/null && rm -f "$_f" && { cc_show "$C_GRN" "  [+] removed ${_f#"$SH_HOME"/}"; NOK=$((NOK + 1)); }; done <"$W/deploy" ;;
    esac
    case " $CHOSEN " in *" secrets-perms "*)
        while IFS= read -r _f; do
            case "$_f" in
                *user-seed.conf) cc_backup_file "$_f" >/dev/null && rm -f "$_f" && cc_show "$C_GRN" "  [+] removed user-seed.conf" ;;
                *) _om=$(stat -c %a "$_f" 2>/dev/null); cc_undo_add "mode of $_f back" "chmod $_om $(cc_shquote "$_f")"; chmod 600 "$_f" && cc_show "$C_GRN" "  [+] chmod 600 ${_f#"$SH_HOME"/}" ;;
            esac; NOK=$((NOK + 1))
        done <"$W/perms" ;;
    esac
    if [ "$RESTART" = 1 ] && [ -n "$RUNAS" ]; then
        if cc_ask "Restart Splunk now (the changes above take effect on restart; takes about a minute)?" Y "yes, restart it now" "no, I will restart it later"; then
            cc_undo_add "restart Splunk after its files are put back" "$(cc_shquote "$SH_HOME/bin/splunk") restart --accept-license --answer-yes --no-prompt"
            cc_show "" "  restarting Splunk ..."
            splunk_restart
            if [ "$AUTHOK" = 1 ]; then
                if mgmt_up "$LOGIN" && search_ok "$LOGIN"; then cc_show "$C_GRN" "  [+] Splunk is back: 8089 answers and a test search runs"
                else BROKE=1; cc_show "$C_RED" "  [x] after the restart 8089 or the test search FAILS"; fi
            fi
        fi
    fi
    # Passwords.
    if [ "$BROKE" = 0 ] && case " $CHOSEN " in *" passwords "*) true ;; *) false ;; esac; then
        cc_backup_file "$E/passwd" >/dev/null
        # Undo: etc/passwd back, then a restart rereads it (no password is
        # kept on disk for the undo).
        cc_undo_add "restart Splunk so it rereads its users" "$(cc_shquote "$SH_HOME/bin/splunk") restart --accept-license --answer-yes --no-prompt"
        # The admin I log in with is changed last.
        { awk -F'|' -v a="$ADMIN" '$1 != a' "$W/uplan"; awk -F'|' -v a="$ADMIN" '$1 == a' "$W/uplan"; } >"$W/uorder"
        while IFS='|' read -r _u _a _why; do
            [ "$_a" = k ] && continue
            if ! cc_guard account "$_u"; then cc_show "$C_YEL" "  [-] $_u: on the protected list, kept"; continue; fi
            _pw=""; [ "$_a" = s ] && _pw=$(awk -F'\t' -v u="$_u" '$1 == u { print $2 }' "$W/typed")
            [ -n "$_pw" ] || _pw=$(cc_genpass "$LEN")
            (umask 077; printf '%s' "$_pw" >"$W/np")
            if [ "$_u" = "$ADMIN" ]; then _c=$(rest "$LOGIN" POST "/services/authentication/users/$_u" "password@$W/np" "oldpassword@$W/admin.old")
            else _c=$(rest "$LOGIN" POST "/services/authentication/users/$_u" "password@$W/np"); fi
            curlcfg "$W/test.cfg" "$_u" "$_pw"
            if [ "$_c" = 200 ] && [ "$(rest "$W/test.cfg" GET /services/authentication/current-context)" = 200 ]; then
                [ -f "$PWOUT" ] || { (umask 077; printf 'New Splunk passwords on %s - give them to the captain, then delete this file\n\n' "$CC_HOST" >"$PWOUT")
                    cc_undo_add "mark the passwords file as no longer valid" "mv $(cc_shquote "$PWOUT") $(cc_shquote "$CC_RUN_DIR/passwords-UNDONE-not-valid.txt")"; }
                printf '%-20s %-24s %s\n' "$_u" "$_pw" "$(date -u +%H:%M:%SZ)" >>"$PWOUT"
                cc_show "$C_GRN" "  [+] $_u: new password, login tested"; NOK=$((NOK + 1))
                [ "$_u" = "$ADMIN" ] && { cp "$W/test.cfg" "$W/admin.new"; LOGIN="$W/admin.new"; }
            else
                cc_show "$C_RED" "  [x] $_u: Splunk refused the change (HTTP ${_c:-none})$([ "$_c" = 200 ] && echo ', or the new password did not log in')"; NBAD=$((NBAD + 1))
            fi
            _pw=""; rm -f "$W/np" "$W/test.cfg"
        done <"$W/uorder"
        : >"$W/typed"
        search_ok "$LOGIN" || { BROKE=1; cc_show "$C_RED" "  [x] the test search fails after the password changes"; }
    fi
    if [ "$BROKE" = 1 ]; then
        cc_show "$C_RED" "  Putting everything back now (and restarting Splunk) ..."
        awk -F'\t' -v n="${U0:-0}" 'NR > n { l[NR] = $4 } END { for (i = NR; i > n; i--) print l[i] }' "$CC_UNDO" >"$W/undo-now"
        while IFS= read -r _cmd; do sh -c "$_cmd" >>"$CC_LOG" 2>&1 || cc_show "$C_RED" "  [x] could not undo: $_cmd"; done <"$W/undo-now"
        [ "$TIMER_ON" = 1 ] && cc_timer_cancel 2>/dev/null; TIMER_ON=0
    fi
fi
# shellcheck disable=SC2034  # read by cc_finish
CC_N_DONE=$NOK
# shellcheck disable=SC2034  # read by cc_finish
CC_N_FAIL=$NBAD

# ---- Summary ----------------------------------------------------------------------------
{
    printf '==========[ summary ]==========\n'
    printf 'SV-44 Splunk hardening | host %s | %s\n' "$CC_HOST" "$([ "$APPLIED" = 1 ] && { [ "$BROKE" = 1 ] && echo 'APPLIED, then PUT BACK (splunk-query broke)' || echo APPLIED; } || echo 'DRY RUN - nothing changed')"
    [ "$APPLIED" = 1 ] && printf 'Changed: %d   Failed: %d\n' "$NOK" "$NBAD"
    printf 'Found: %d high, %d to look at\n' "$(grep -c '^HIGH' "$W/find")" "$(grep -c '^MED' "$W/find")"
    awk -F'|' '$1 != "OK" { printf "  %-5s %-16s %s\n", $1, $2, $3 }' "$W/find"
    [ -f "$PWOUT" ] && [ "$BROKE" = 0 ] && printf '\nNew passwords: %s (mode 600)\n  Give them to the captain (and the scoring portal for the splunk-query user), then: rm %s\n' "$PWOUT" "$PWOUT"
    [ "$APPLIED" = 1 ] && [ -f "$CC_RUN_DIR/revert.sh" ] && printf 'Undo this run: sh %s/revert.sh --force\n' "$CC_RUN_DIR"
    printf 'Splunk down? sh SV-50-service-recovery.sh --services splunk\n'
} >"$CC_RUN_DIR/summary.txt"
awk -F'|' '{ printf "%-5s %-16s %s\n", $1, $2, $3 }' "$W/find" >"$CC_RUN_DIR/findings.txt"
cc_show "" ""
while IFS= read -r _l; do
    case "$_l" in ==*|SV-44*) cc_show "$C_CYN" "$_l" ;; *HIGH*|*'PUT BACK'*|*'Failed: '[1-9]*) cc_show "$C_RED" "$_l" ;; *MED*|*'New passwords'*|*'Give them'*) cc_show "$C_YEL" "$_l" ;; *) cc_show "" "$_l" ;; esac
done <"$CC_RUN_DIR/summary.txt"
rm -rf "$W"
if [ "$TIMER_ON" = 1 ]; then
    header "KEEP OR REVERT"
    cc_show "$C_YEL" "[*] Before you answer: log in to Splunk Web with the new admin password and run a search."
    cc_timer_finish || true
fi
cc_finish
