#!/bin/sh
# =============================================================================
# ID:       SV-45
# NAME:     Gitea hardening
# ROLE:     Applications
# KIND:     changes - dry run unless --apply
# VERSION:  1.0.0
#
# PURPOSE
#   Gitea (or Forgejo) is a scored service: people log in, browse and clone.
#   It is also an easy way in: an install page left open rewrites the whole
#   server, git hooks run any command on the box, migrations read files from
#   the box, webhooks reach inside the network.  This reads app.ini and the
#   repositories, then:
#
#     looks at (never changed)
#       version, web port, SSH, who can see repositories without logging in,
#       admin accounts (sqlite), Actions (runners run code)
#     offers (each asked, yes/no; Enter = yes)
#       install-lock    INSTALL_LOCK = true: the install page cannot be used
#                       to take the server over
#       no-register     DISABLE_REGISTRATION = true: no new accounts from the
#                       web (say no if the scoring engine signs up users)
#       git-hooks       DISABLE_GIT_HOOKS = true: users cannot add server-side
#                       hooks (they run as the gitea user)
#       local-migrate   [migrations] ALLOW_LOCALNETWORKS = false: a migration
#                       cannot read this box or the inside network
#       webhook-local   [webhook] ALLOWED_HOST_LIST = external: webhooks cannot
#                       reach this box or the inside network
#       repo-hooks      quarantine hooks inside repositories that Gitea did not
#                       put there (they run on every push)
#       config-perms    app.ini readable by its owner and the gitea group only
#                       (it holds the secret key and the database password)
#   After: restart Gitea, then the login page must load, or everything is
#   put back.
#
#   QUESTIONS (Enter takes the default in capitals; a flag answers each):
#     each fix (yes / no)             --only / --skip
#     apply?                          --apply
#
# USAGE
#   sudo sh SV-45-gitea-hardening.sh                             look + dry run
#   sudo sh SV-45-gitea-hardening.sh --protected p.csv --apply
#   sudo sh SV-45-gitea-hardening.sh --protected p.csv --apply --batch --skip no-register
#
# OPTIONS
#   --apply            make the changes (without it, dry run only)
#   --only a,b / --skip a,b   install-lock no-register git-hooks local-migrate
#                      webhook-local repo-hooks config-perms
#   --config FILE      app.ini (default: found in /etc/gitea, /etc/forgejo,
#                      /var/lib/gitea/custom/conf, /home/git/gitea/custom/conf ...)
#   --url URL          the login page (default http://127.0.0.1:HTTP_PORT/user/login)
#   --timer SECONDS    revert countdown (default 120); --no-timer
#   --root DIR         treat DIR as / (tests): files only
#   --no-color         no colours
#   --help             this text plus the common options
#
# OUTPUTS  (under --out, in gitea-N/)
#   output.txt, findings.txt, plan.txt, summary.txt, run.txt, revert.sh
#
# DEPENDS ON
#   awk, sed, find; curl or wget for the login page; sqlite3 for the admin
#   list (optional).
#
# TESTED ON
#   A fake root (app.ini, repositories with hooks, sqlite database) under
#   dash, bash, busybox sh, ksh93, mksh and yash with gawk, mawk and busybox
#   awk.  Not yet run against a live Gitea.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - Settings given as GITEA__section__KEY environment variables (Docker)
#     win over app.ini: they are not read.
#   - Gitea is not updated here.  Admin accounts in MySQL/PostgreSQL: listed
#     with "gitea admin user list --admin" (shown).
#   - SSH keys: LX-22 keeps Gitea's keys.  Ports: LX-25 --box gitea.  Keep it
#     up: SV-50 --box gitea.  Web shells: SV-16.
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

ALL_FIX="install-lock no-register git-hooks local-migrate webhook-local repo-hooks config-perms"
usage() {
    cat <<'USAGE'
SV-45 Gitea hardening - install page, sign-ups, git hooks, migrations, webhooks, planted hooks
  sudo sh SV-45-gitea-hardening.sh                        look + dry run
  sudo sh SV-45-gitea-hardening.sh --protected p.csv --apply

  --apply            make the changes (without it, dry run only)
  --only a,b / --skip a,b   install-lock no-register git-hooks local-migrate
                     webhook-local repo-hooks config-perms
  --config FILE      app.ini (default: found)
  --url URL          the login page (default http://127.0.0.1:HTTP_PORT/user/login)
  --timer SECONDS    revert countdown (default 120); --no-timer
  --root DIR         treat DIR as / (tests)
  --no-color         no colours
  --help             show this text
USAGE
    cc_usage_common
}

ONLY=""; SKIP=""; CONF=""; URL=""; TIMER=120; NOTIMER=0; R=""; COLOR=1
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --apply)    CC_APPLY=1; shift ;;
        --only)     [ $# -ge 2 ] || cc_die 2 "--only needs a list"; ONLY="$ONLY,$2"; shift 2 ;;
        --skip)     [ $# -ge 2 ] || cc_die 2 "--skip needs a list"; SKIP="$SKIP,$2"; shift 2 ;;
        --config)   [ $# -ge 2 ] || cc_die 2 "--config needs a file"; CONF=$2; shift 2 ;;
        --url)      [ $# -ge 2 ] || cc_die 2 "--url needs an address"; URL=$2; shift 2 ;;
        --timer)    [ $# -ge 2 ] || cc_die 2 "--timer needs seconds"; TIMER=$2; shift 2 ;;
        --no-timer) NOTIMER=1; shift ;;
        --root)     [ $# -ge 2 ] || cc_die 2 "--root needs a folder"; [ -d "$2" ] || cc_die 2 "--root: not a folder: $2"; R=$(cd "$2" && pwd); [ "$R" = / ] && R=""; shift 2 ;;
        --no-color|--no-colour) COLOR=0; shift ;;
        --help|-h)  usage; exit 0 ;;
        *)          cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
case "$TIMER" in ''|*[!0-9]*) cc_die 2 "--timer needs a whole number" ;; esac
for _a in $(printf '%s' "$ONLY,$SKIP" | tr ',' ' '); do
    case " $ALL_FIX " in *" $_a "*) ;; *) cc_die 2 "unknown fix '$_a' ($ALL_FIX)" ;; esac
done

cc_init "SV-45" "Gitea hardening" changes
cc_detect_os
# shellcheck disable=SC2034  # read by cc_color_init
[ "$COLOR" = 1 ] || CC_NOCOLOR=1
cc_color_init
cc_use_numbered_dir gitea
rmdir "$CC_RUN_DIR/raw" 2>/dev/null
OUTF="$CC_RUN_DIR/output.txt"
grep -v '\[NOTE\]\|\[DEBUG\]' "$CC_LOG" >"$OUTF" 2>/dev/null || : >"$OUTF"
# shellcheck disable=SC2034  # CC_TEE is read by the library's log functions
CC_TEE=$OUTF
W="$CC_RUN_DIR/.work"; mkdir -p "$W"
TAB=$(printf '\t')
header() { cc_show "" ""; cc_show "$C_CYN" "==========[ $1 ]=========="; }
inlist() { case ",$2," in *",$1,"*) return 0 ;; esac; return 1; }
want() { inlist "$1" "$SKIP" && return 1; [ -z "$ONLY" ] || inlist "$1" "$ONLY"; }
P() { printf '%s%s' "$R" "$1"; }

cc_show "$C_CYN" "SV-45 Gitea hardening | host $CC_HOST | results in $CC_RUN_DIR"
cc_show "" "Legend: ${C_RED}[!] HIGH${C_OFF}   ${C_YEL}[*] MED${C_OFF}   ${C_GRN}[ok]${C_OFF} fine   ${C_YEL}[~] would change${C_OFF}   ${C_GRN}[+] changed${C_OFF}   ${C_RED}[x] failed${C_OFF}"
[ -n "$R" ] && cc_show "$C_GRY" "Acting on $R as if it were / (files only)"

# ---- Find app.ini ----------------------------------------------------------------------
if [ -n "$CONF" ]; then
    [ -f "$(P "$CONF")" ] || cc_die 2 "--config: no such file: $CONF"
else
    for _c in /etc/gitea/app.ini /etc/forgejo/app.ini /var/lib/gitea/custom/conf/app.ini /var/lib/forgejo/custom/conf/app.ini \
              /home/git/gitea/custom/conf/app.ini /home/git/custom/conf/app.ini /opt/gitea/custom/conf/app.ini /usr/local/etc/gitea/conf/app.ini; do
        [ -f "$(P "$_c")" ] && { CONF=$_c; break; }
    done
fi
if [ -z "$CONF" ]; then
    cc_show "$C_GRY" "No Gitea here (no app.ini in /etc/gitea, /etc/forgejo, /var/lib/gitea/custom/conf, /home/git ...; give it with --config FILE)."
    rm -rf "$W"; cc_finish; exit 0
fi
CF=$(P "$CONF")
SVC=gitea; case "$CONF" in *forgejo*) SVC=forgejo ;; esac

# ini_get SECTION KEY -> the value in app.ini ("" when not set); last one wins.
#   Keys are matched without regard to case.  SECTION "" is the top.
ini_get() {
    awk -v s="$1" -v k="$2" '
        /^[ \t]*[;#]/ { next }
        /^[ \t]*\[/ { l = $0; gsub(/[ \t\r]|\[|\]/, "", l); cur = l; next }
        cur == s { i = index($0, "="); if (!i) next
            kk = substr($0, 1, i - 1); gsub(/[ \t]/, "", kk)
            if (toupper(kk) == toupper(k)) { v = substr($0, i + 1); sub(/^[ \t]+/, "", v); sub(/[ \t\r]+$/, "", v); gsub(/^["`]|["`]$/, "", v); last = v } }
        END { print last }' "$CF" 2>/dev/null
}
lc() { printf '%s' "$1" | tr 'A-Z' 'a-z'; }
istrue() { case "$(lc "$1")" in true|1|yes|on) return 0 ;; esac; return 1; }

# ---- Look -------------------------------------------------------------------------------
: >"$W/find"; : >"$W/fixes"
fnd() { printf '%s\t%s\n' "$1" "$2" >>"$W/find"; case "$1" in HIGH) cc_show "$C_RED" "  [!] $2" ;; MED) cc_show "$C_YEL" "  [*] $2" ;; INFO) cc_show "" "  $2" ;; *) cc_show "$C_GRN" "  [ok] $2" ;; esac; }
fix() { want "$1" && printf '%s\t%s\t%s\n' "$1" "$2" "$3" >>"$W/fixes"; return 0; }

header "1/4  what this Gitea is"
HTTP_PORT=$(ini_get server HTTP_PORT); HTTP_PORT=${HTTP_PORT:-3000}
PROTO=$(lc "$(ini_get server PROTOCOL)"); PROTO=${PROTO:-http}
RUNU=$(ini_get "" RUN_USER); RUNU=${RUNU:-git}
DATA=$(ini_get server APP_DATA_PATH)
fnd INFO "config:     $CONF"
_ver=""
if [ -z "$R" ]; then
    _b=$(cc_first gitea forgejo); [ -z "$_b" ] && for _x in /usr/local/bin/gitea /usr/bin/gitea /opt/gitea/gitea /home/git/gitea/gitea; do [ -x "$_x" ] && { _b=$_x; break; }; done
    [ -n "$_b" ] && _ver=$("$_b" --version 2>/dev/null | sed -n 's/.*version \([0-9][0-9.]*\).*/\1/p' | head -n 1)
fi
fnd INFO "version:    ${_ver:-unknown (gitea --version)}"
fnd INFO "web:        $PROTO on port $HTTP_PORT (root URL $(ini_get server ROOT_URL))"
if istrue "$(ini_get server DISABLE_SSH)"; then fnd INFO "git over SSH: off"
elif istrue "$(ini_get server START_SSH_SERVER)"; then fnd INFO "git over SSH: Gitea's own SSH server on port $(ini_get server SSH_LISTEN_PORT)$(ini_get server SSH_PORT)"
else fnd INFO "git over SSH: through the system sshd as user $RUNU (LX-22 keeps its keys)"; fi
fnd INFO "runs as:    $RUNU"
istrue "$(ini_get service REQUIRE_SIGNIN_VIEW)" && fnd INFO "repositories: only seen after logging in" || fnd INFO "repositories: public ones can be seen without logging in (may be scored: left as is)"
[ "$PROTO" = http ] && fnd MED "the web runs plain HTTP: passwords cross the network in clear (left as is: the scoring engine may use http)"
istrue "$(ini_get actions ENABLED)" && fnd MED "Actions are on: a runner runs code from any repository that has a workflow - check which runners are registered (Site Administration > Runners)"

header "2/4  settings"
if istrue "$(ini_get security INSTALL_LOCK)"; then fnd OK "INSTALL_LOCK = true: the install page is closed"
else fnd HIGH "INSTALL_LOCK is not true: anyone can open the install page and take the server over"; fix install-lock "security INSTALL_LOCK true" "INSTALL_LOCK = true (closes the install page)"; fi
if istrue "$(ini_get service DISABLE_REGISTRATION)"; then fnd OK "sign-ups are off"
else fnd MED "anyone can sign up for an account from the web page"; fix no-register "service DISABLE_REGISTRATION true" "DISABLE_REGISTRATION = true (no new accounts from the web; say no if the scoring engine signs up users)"; fi
_gh=$(ini_get security DISABLE_GIT_HOOKS)
if [ -z "$_gh" ] || istrue "$_gh"; then fnd OK "git hooks cannot be added by users"
else fnd HIGH "DISABLE_GIT_HOOKS = false: users allowed to edit hooks run any command on this box"; fix git-hooks "security DISABLE_GIT_HOOKS true" "DISABLE_GIT_HOOKS = true (users cannot add server-side hooks)"; fi
if istrue "$(ini_get migrations ALLOW_LOCALNETWORKS)"; then fnd HIGH "migrations may read this box and the inside network (ALLOW_LOCALNETWORKS = true)"; fix local-migrate "migrations ALLOW_LOCALNETWORKS false" "[migrations] ALLOW_LOCALNETWORKS = false"
else fnd OK "migrations cannot reach the inside network"; fi
_wh=$(lc "$(ini_get webhook ALLOWED_HOST_LIST)")
case ",$(printf '%s' "$_wh" | tr -d ' ')," in
    *,\*,*|*,all,*|*,loopback,*|*,private,*|*,127.*|*,192.168.*|*,10.*|*,172.*)
        fnd MED "webhooks may call this box or the inside network (ALLOWED_HOST_LIST = $_wh)"; fix webhook-local "webhook ALLOWED_HOST_LIST external" "[webhook] ALLOWED_HOST_LIST = external" ;;
    *) fnd OK "webhooks only reach outside addresses (${_wh:-external, the default})" ;;
esac
_m=$(ls -ln "$CF" | awk '{ print $1 }')
case "$_m" in
    ???????---*) fnd OK "$CONF: other users cannot read it" ;;
    *) fnd MED "$CONF can be read by every user (secret key, database password)"; fix config-perms "-" "$CONF: owner and the $RUNU group only (mode 640)" ;;
esac

header "3/4  hooks in repositories and admin accounts"
REPOS=$(ini_get repository ROOT)
_cands="$REPOS"
[ -n "$DATA" ] && _cands="$_cands $DATA/gitea-repositories"
_cands="$_cands /var/lib/gitea/data/gitea-repositories /var/lib/gitea/repositories /var/lib/gitea/git/repositories /home/git/gitea-repositories /home/git/gitea/data/gitea-repositories /var/lib/forgejo/data/forgejo-repositories"
REPOS=""; for _d in $_cands; do [ -d "$(P "$_d")" ] && { REPOS=$_d; break; }; done
: >"$W/hooks"
if [ -z "$REPOS" ]; then fnd MED "repository folder not found (set [repository] ROOT): hooks not checked"
else
    _nr=$(find "$(P "$REPOS")" -mindepth 2 -maxdepth 2 -type d -name '*.git' 2>/dev/null | grep -c .)
    fnd INFO "repositories: $_nr in $REPOS"
    # Gitea's own: hooks/{pre-receive,update,post-receive,proc-receive} that run
    # the files in the matching .d folder, and hooks/*.d/gitea.  *.sample are git's.
    find "$(P "$REPOS")" -mindepth 4 -maxdepth 5 -path '*/hooks/*' -type f 2>/dev/null | while IFS= read -r _h; do
        _n=${_h##*/}; _pd=${_h%/*}; _pd=${_pd##*/}
        case "$_n" in *.sample) continue ;; esac
        case "$_pd" in
            hooks) case "$_n" in pre-receive|update|post-receive|proc-receive) grep -q "$_n\.d" "$_h" 2>/dev/null && continue ;; esac ;;
            *.d)   [ "$_n" = gitea ] && grep -qi 'gitea\|forgejo' "$_h" 2>/dev/null && continue ;;
        esac
        printf '%s\n' "$_h" >>"$W/hooks"
    done
    if [ -s "$W/hooks" ]; then
        while IFS= read -r _h; do
            fnd HIGH "a hook Gitea did not put there (runs on every push): ${_h#"$R"}"
            fix repo-hooks "$_h" "quarantine ${_h#"$R"}"
        done <"$W/hooks"
    else fnd OK "no hooks in the repositories except Gitea's own"; fi
fi
DBT=$(lc "$(ini_get database DB_TYPE)")
case "$DBT" in
    sqlite3|sqlite|'')
        _db=$(ini_get database PATH); [ -z "$_db" ] && [ -n "$DATA" ] && _db="$DATA/gitea.db"
        [ -n "$_db" ] && [ ! -f "$(P "$_db")" ] && _db=""
        [ -z "$_db" ] && for _x in /var/lib/gitea/data/gitea.db /home/git/gitea/data/gitea.db /var/lib/gitea/gitea.db; do [ -f "$(P "$_x")" ] && { _db=$_x; break; }; done
        if [ -n "$_db" ] && cc_have sqlite3; then
            _ad=$(sqlite3 "$(P "$_db")" "select name from user where is_admin = 1 and type = 0;" 2>/dev/null | tr '\n' ' ' | sed 's/ *$//')
            if [ -n "$_ad" ]; then fnd MED "admin accounts: $_ad - any you do not know is red team (Site Administration > User Accounts)"
            else fnd MED "could not read the admin accounts from $_db"; fi
        else fnd MED "admin accounts not read (no sqlite3 or no database): run  su $RUNU -s /bin/sh -c 'gitea -c $CONF admin user list --admin'"; fi ;;
    *) fnd MED "admin accounts are in $DBT: run  su $RUNU -s /bin/sh -c 'gitea -c $CONF admin user list --admin'" ;;
esac

# ---- Questions ---------------------------------------------------------------------------
header "4/4  questions and changes (Enter = the default in capitals)"
: >"$W/chosen"
while IFS="$TAB" read -r _fx _arg _ds; do
    cc_ask "[$_fx] $_ds?" Y "yes, do it" "no, skip it" && printf '%s\t%s\t%s\n' "$_fx" "$_arg" "$_ds" >>"$W/chosen"
done <"$W/fixes"
NCH=$(grep -c . "$W/chosen")
cut -f3 "$W/chosen" >"$CC_RUN_DIR/plan.txt"

# ---- Helpers for the changes ----------------------------------------------------------
backed() { grep -qxF "$1" "$W/backed" 2>/dev/null && return 0; cc_backup_file "$1" >/dev/null || return 1; printf '%s\n' "$1" >>"$W/backed"; }
# ini_set SECTION KEY VALUE -> replace the key in its section, or add it (and
#   the section).  Gitea ignores inline comments, so the mark goes on the line before.
ini_set() {
    backed "$CF" || return 1
    awk -v s="$1" -v k="$2" -v v="$3" '
        BEGIN { m = "; BT SV-45\n" k " = " v }
        /^[ \t]*\[/ { if (cur == s && !done) { print m; done = 1 } l = $0; gsub(/[ \t\r]|\[|\]/, "", l); cur = l; print; next }
        cur == s && !/^[ \t]*[;#]/ { i = index($0, "="); if (i) { kk = substr($0, 1, i - 1); gsub(/[ \t]/, "", kk)
            if (toupper(kk) == toupper(k)) { if (!done) { print m; done = 1 } next } } }
        { print }
        END { if (!done) { if (cur != s) { print ""; print "[" s "]" } print m } }' "$CF" >"$CF.ccnew" && cat "$CF.ccnew" >"$CF"
    _r=$?; rm -f "$CF.ccnew"; return "$_r"
}
do_fix() {   # do_fix FIX ARG
    case "$1" in
        repo-hooks) cc_quarantine "$2" >>"$CC_LOG" 2>&1 ;;
        config-perms)
            _om=$(ls -ln "$CF" | awk '{ print $3 ":" $4 }'); _mm=$(ls -l "$CF" | awk '{ m = $1; u = substr(m, 2, 3); g = substr(m, 5, 3); o = substr(m, 8, 3); gsub(/-/, "", u); gsub(/-/, "", g); gsub(/-/, "", o); print "u=" u ",g=" g ",o=" o }')
            cc_undo_add "owner and mode of $CONF back" "chown $_om $(cc_shquote "$CF"); chmod $_mm $(cc_shquote "$CF")"
            # Gitea reads it as RUN_USER: give the file to that group before closing it to others.
            grep -q "^$RUNU:" "$(P /etc/group)" 2>/dev/null && chgrp "$RUNU" "$CF" 2>/dev/null
            chmod 640 "$CF" ;;
        # shellcheck disable=SC2086  # ARG is "SECTION KEY VALUE"
        *) set -- $2; ini_set "$1" "$2" "$3" ;;
    esac
}
login_url() { [ -n "$URL" ] && { printf '%s' "$URL"; return; }; printf '%s://127.0.0.1:%s/user/login' "$PROTO" "$HTTP_PORT"; }
login_ok() {
    if cc_have curl; then _c=$(curl -sk -m 8 -o "$W/page" -w '%{http_code}' "$(login_url)" 2>/dev/null)
    else _c=$(wget -q -S --no-check-certificate -O "$W/page" -T 8 "$(login_url)" 2>&1 | awk '/HTTP\// { c = $2 } END { print c }'); fi
    [ "$_c" = 200 ] && grep -qi 'gitea\|forgejo\|user_name' "$W/page"
}
svc_restart() {
    case "$CC_INIT" in
        systemd) systemctl restart "$SVC" ;;
        openrc)  rc-service "$SVC" restart ;;
        *)       service "$SVC" restart ;;
    esac
}
restart_cmd() { case "$CC_INIT" in systemd) printf 'systemctl restart %s' "$SVC" ;; openrc) printf 'rc-service %s restart' "$SVC" ;; *) printf 'service %s restart' "$SVC" ;; esac; }

# ---- Apply ------------------------------------------------------------------------------
NOK=0; NBAD=0; APPLIED=0; TIMER_ON=0; BROKE=0
if [ "$NCH" -eq 0 ]; then cc_show "$C_GRN" "  [ok] Nothing to change."
elif [ "$CC_APPLY" != 1 ] || { [ -z "$R" ] && ! cc_is_root; }; then
    [ -z "$R" ] && ! cc_is_root && cc_show "$C_YEL" "  [!] not root: showing the plan only"
    while IFS= read -r _l; do cc_show "$C_YEL" "  [~] $_l"; done <"$CC_RUN_DIR/plan.txt"
    cc_show "$C_GRY" "  Dry run: nothing was changed. Run again with --apply."
    # shellcheck disable=SC2034  # read by cc_finish
    CC_N_WOULD=$NCH
elif cc_ask "Apply these $NCH change(s)?" Y "yes, apply them (a revert timer undoes them unless you confirm from a NEW session)" "no, change nothing"; then
    APPLIED=1; : >"$W/backed"
    U0=$(grep -c . "$CC_UNDO" 2>/dev/null)
    PAGE0=0; [ -z "$R" ] && login_ok && PAGE0=1
    if [ "$NOTIMER" != 1 ] && [ -z "$R" ]; then cc_timer_start "$TIMER"; TIMER_ON=1
        cc_show "$C_YEL" "  [*] Revert timer started: everything is undone in $((TIMER / 60)):$(printf '%02d' $((TIMER % 60))) unless you keep it at the end."; fi
    _cfg=0; cut -f1 "$W/chosen" | grep -qv repo-hooks && _cfg=1
    [ -z "$R" ] && [ "$_cfg" = 1 ] && cc_undo_add "restart $SVC after its config is put back" "$(restart_cmd)"
    while IFS="$TAB" read -r _fx _arg _ds; do
        if do_fix "$_fx" "$_arg"; then NOK=$((NOK + 1)); cc_show "$C_GRN" "  [+] $_ds"; else NBAD=$((NBAD + 1)); cc_show "$C_RED" "  [x] FAILED: $_ds"; fi
    done <"$W/chosen"
    if [ -z "$R" ] && [ "$_cfg" = 1 ]; then
        if svc_restart >>"$CC_LOG" 2>&1; then cc_show "$C_GRN" "  [+] $SVC restarted"; else cc_show "$C_RED" "  [x] $SVC did not restart"; BROKE=1; fi
        if [ "$PAGE0" = 1 ]; then
            _i=0; until login_ok || [ "$_i" -ge 20 ]; do sleep 2; _i=$((_i + 2)); done
            if login_ok; then cc_show "$C_GRN" "  [+] $(login_url) still shows the login page"
            else BROKE=1; cc_show "$C_RED" "  [x] $(login_url) no longer shows the login page"; fi
        else cc_show "$C_YEL" "  [*] the login page did not load before the change either ($(login_url)): check it by hand"; fi
        if [ "$BROKE" = 1 ]; then
            cc_show "$C_RED" "  Putting everything back now ..."
            awk -F'\t' -v n="${U0:-0}" 'NR > n { l[NR] = $4 } END { for (i = NR; i > n; i--) print l[i] }' "$CC_UNDO" >"$W/undo-now"
            while IFS= read -r _cmd; do sh -c "$_cmd" >>"$CC_LOG" 2>&1; done <"$W/undo-now"
            [ "$TIMER_ON" = 1 ] && cc_timer_cancel 2>/dev/null; TIMER_ON=0
        fi
    fi
else cc_show "$C_GRY" "  Not applied. The plan is in $CC_RUN_DIR/plan.txt"; fi
# shellcheck disable=SC2034  # read by cc_finish
CC_N_DONE=$NOK
# shellcheck disable=SC2034  # read by cc_finish
CC_N_FAIL=$NBAD

# ---- Summary ----------------------------------------------------------------------------
awk -F'\t' '$1 != "INFO" { printf "%-4s %s\n", $1, $2 }' "$W/find" >"$CC_RUN_DIR/findings.txt"
{
    printf '==========[ summary ]==========\n'
    printf 'SV-45 Gitea hardening | host %s | %s\n' "$CC_HOST" "$([ "$APPLIED" = 1 ] && { [ "$BROKE" = 1 ] && echo 'APPLIED, then PUT BACK (Gitea broke)' || echo APPLIED; } || echo 'DRY RUN - nothing changed')"
    printf 'Found: %d HIGH, %d MED\n' "$(grep -c "^HIGH$TAB" "$W/find")" "$(grep -c "^MED$TAB" "$W/find")"
    awk -F'\t' '$1 == "HIGH" || $1 == "MED" { printf "  %-4s %s\n", $1, substr($2, 1, 150) }' "$W/find"
    [ -s "$CC_RUN_DIR/plan.txt" ] && { printf '\nChanges%s:\n' "$([ "$APPLIED" = 1 ] || echo ' planned')"; sed 's/^/  /' "$CC_RUN_DIR/plan.txt"; }
    [ "$APPLIED" = 1 ] && printf 'Done: %d   Failed: %d\n' "$NOK" "$NBAD"
    [ "$APPLIED" = 1 ] && [ -f "$CC_RUN_DIR/revert.sh" ] && printf 'Undo this run: sh %s/revert.sh --force\n' "$CC_RUN_DIR"
    printf '\nAlso: SSH keys LX-22 (keeps Gitea'"'"'s keys); ports LX-25 --box gitea; keep it up SV-50 --box gitea; web shells SV-16.\n'
} >"$CC_RUN_DIR/summary.txt"
cc_show "" ""
while IFS= read -r _l; do
    case "$_l" in ==*|SV-45*) cc_show "$C_CYN" "$_l" ;; '  HIGH'*|*'PUT BACK'*) cc_show "$C_RED" "$_l" ;; '  MED'*) cc_show "$C_YEL" "$_l" ;; *) cc_show "" "$_l" ;; esac
done <"$CC_RUN_DIR/summary.txt"
rm -rf "$W"
if [ "$TIMER_ON" = 1 ]; then header "KEEP OR REVERT"; cc_show "$C_YEL" "[*] Before you answer: log in to Gitea from a browser and open a repository."; cc_timer_finish || true; fi
cc_finish
