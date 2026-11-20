#!/bin/sh
# =============================================================================
# ID:       SV-41
# NAME:     Webmail (Roundcube) hardening
# ROLE:     Applications  (wave 2, the webmail box)
# KIND:     changes - dry run unless --apply
# VERSION:  1.0.0
#
# PURPOSE
#   webmail-interactive is scored: someone logs in to Roundcube and reads
#   mail.  Roundcube is also an easy way in: an installer left reachable,
#   known holes in old versions, logs that hold passwords, a config that
#   sends every login to red team's server.  This finds each Roundcube,
#   then:
#
#     looks at (never changed)
#       version     against known holes: CVE-2025-49113 (any logged-in user
#                   runs code; fixed 1.6.11 / 1.5.10), CVE-2024-42009 (XSS
#                   steals mail; 1.6.8 / 1.5.8), 1.4 and older (no fixes
#                   at all).  A distribution package may carry the fix: its
#                   changelog is read when it is there.
#       where logins go   imap_host / default_host / smtp_host that are not
#                   this box: every password typed into the webmail goes there
#       plugins     every plugin enabled, and plugin folders changed lately
#     offers (each asked, yes/no)
#       installer       quarantine the installer/ folder; enable_installer off
#       debug-off       sql/imap/smtp debug off (they write passwords to the
#                       logs), debug_level 1 (no errors shown to users)
#       des-key         a new des_key when it is the published default or
#                       too short (everyone logs in again)
#       log-logins      log_logins on (who logged in, from where: for you)
#       config-perms    config files readable by root and the web server only
#       block-dirs      Apache: logs, temp, config, SQL, bin, installer
#                       cannot be downloaded (one drop-in file)
#   After: config test, Apache reload, then the login page must still load
#   (and the IMAP check still answer), or everything is put back.
#
#   QUESTIONS (Enter takes the default in capitals; a flag answers each):
#     which box                       --box NAME
#     each fix (yes / no)             --only / --skip
#     apply?                          --apply
#
# USAGE
#   sudo sh SV-41-roundcube-hardening.sh                             look + dry run
#   sudo sh SV-41-roundcube-hardening.sh --protected p.csv --apply
#   sudo sh SV-41-roundcube-hardening.sh --protected p.csv --apply --batch --url http://127.0.0.1/roundcube/
#
# OPTIONS
#   --apply            make the changes (without it, dry run only)
#   --box NAME         splunk | webmail | ecomm | other (asked)
#   --only a,b / --skip a,b   installer debug-off des-key log-logins
#                      config-perms block-dirs
#   --url URL          the webmail login page (default: found from Apache,
#                      else http://127.0.0.1/roundcube/)
#   --webroot DIR      look for Roundcube here too (repeatable)
#   --timer SECONDS    revert countdown (default 120); --no-timer
#   --root DIR         treat DIR as / (tests): files only
#   --no-color         no colours
#   --help             this text plus the common options
#
# OUTPUTS  (under --out, in roundcube-N/)
#   output.txt, findings.txt, plan.txt, summary.txt, run.txt, revert.sh
#
# DEPENDS ON
#   awk, sed, curl or wget; apache2ctl to test and reload.
#
# TESTED ON
#   Ubuntu 24.04 with the roundcube-core 1.6.6 package behind Apache (live),
#   and a fake root, under dash, bash, busybox sh, ksh93, mksh and yash with
#   gawk, mawk and busybox awk.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - Updating Roundcube is not done here (apt-get install --only-upgrade
#     roundcube-core, or a new tarball): the dry run says when it is needed.
#   - nginx is not edited: the lines are written to nginx-bt.conf.
#   - Web shells inside Roundcube: SV-16 --webroot /usr/share/roundcube.
#   - Mail passwords: SV-40.  Roundcube's database password: SV-42.
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

ALL_FIX="installer debug-off des-key log-logins config-perms block-dirs"
usage() {
    cat <<'USAGE'
SV-41 Webmail (Roundcube) hardening - installer, old versions, password leaks, logins sent elsewhere
  sudo sh SV-41-roundcube-hardening.sh                        look + dry run
  sudo sh SV-41-roundcube-hardening.sh --protected p.csv --apply

  --apply            make the changes (without it, dry run only)
  --box NAME         splunk | webmail | ecomm | other
  --only a,b / --skip a,b   installer debug-off des-key log-logins config-perms block-dirs
  --url URL          the webmail login page
  --webroot DIR      look for Roundcube here too (repeatable)
  --timer SECONDS    revert countdown (default 120); --no-timer
  --root DIR         treat DIR as / (tests)
  --no-color         no colours
  --help             show this text
USAGE
    cc_usage_common
}

NL='
'
BOX=""; ONLY=""; SKIP=""; URL=""; EXTRA=""; TIMER=120; NOTIMER=0; R=""; COLOR=1
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --apply)    CC_APPLY=1; shift ;;
        --box)      [ $# -ge 2 ] || cc_die 2 "--box needs a name"; BOX=$2; shift 2 ;;
        --only)     [ $# -ge 2 ] || cc_die 2 "--only needs a list"; ONLY="$ONLY,$2"; shift 2 ;;
        --skip)     [ $# -ge 2 ] || cc_die 2 "--skip needs a list"; SKIP="$SKIP,$2"; shift 2 ;;
        --url)      [ $# -ge 2 ] || cc_die 2 "--url needs an address"; URL=$2; shift 2 ;;
        --webroot)  [ $# -ge 2 ] || cc_die 2 "--webroot needs a folder"; [ -d "$2" ] || cc_die 2 "--webroot: not a folder: $2"; EXTRA="$EXTRA$(cc_abspath "$2")$NL"; shift 2 ;;
        --timer)    [ $# -ge 2 ] || cc_die 2 "--timer needs seconds"; TIMER=$2; shift 2 ;;
        --no-timer) NOTIMER=1; shift ;;
        --root)     [ $# -ge 2 ] || cc_die 2 "--root needs a folder"; [ -d "$2" ] || cc_die 2 "--root: not a folder: $2"; R=$(cd "$2" && pwd); [ "$R" = / ] && R=""; shift 2 ;;
        --no-color|--no-colour) COLOR=0; shift ;;
        --help|-h)  usage; exit 0 ;;
        *)          cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
cc_box_valid "$BOX" || cc_die 2 "--box must be one of: $CC_BOXES"
case "$TIMER" in ''|*[!0-9]*) cc_die 2 "--timer needs a whole number" ;; esac
for _a in $(printf '%s' "$ONLY,$SKIP" | tr ',' ' '); do
    case " $ALL_FIX " in *" $_a "*) ;; *) cc_die 2 "unknown fix '$_a' ($ALL_FIX)" ;; esac
done

cc_init "SV-41" "Webmail (Roundcube) hardening" changes
cc_detect_os
# shellcheck disable=SC2034  # read by cc_color_init
[ "$COLOR" = 1 ] || CC_NOCOLOR=1
cc_color_init
cc_use_numbered_dir roundcube
rmdir "$CC_RUN_DIR/raw" 2>/dev/null
OUTF="$CC_RUN_DIR/output.txt"
grep -v '\[NOTE\]\|\[DEBUG\]' "$CC_LOG" >"$OUTF" 2>/dev/null || : >"$OUTF"
# shellcheck disable=SC2034  # CC_TEE is read by the library's log functions
CC_TEE=$OUTF
W="$CC_RUN_DIR/.work"; mkdir -p "$W"
CC_CSV_DIR="$W/csv"; mkdir -p "$CC_CSV_DIR"
TAB=$(printf '\t')
header() { cc_show "" ""; cc_show "$C_CYN" "==========[ $1 ]=========="; }
inlist() { case ",$2," in *",$1,"*) return 0 ;; esac; return 1; }
want() { inlist "$1" "$SKIP" && return 1; [ -z "$ONLY" ] || inlist "$1" "$ONLY"; }
P() { printf '%s%s' "$R" "$1"; }

cc_show "$C_CYN" "SV-41 Webmail (Roundcube) hardening | host $CC_HOST | results in $CC_RUN_DIR"
cc_show "" "Legend: ${C_RED}[!] HIGH${C_OFF}   ${C_YEL}[*] MED${C_OFF}   ${C_GRN}[ok]${C_OFF} fine   ${C_YEL}[~] would change${C_OFF}   ${C_GRN}[+] changed${C_OFF}   ${C_RED}[x] failed${C_OFF}"
[ -n "$R" ] && cc_show "$C_GRY" "Acting on $R as if it were / (files only)"

# ---- Find Roundcube --------------------------------------------------------------------
{
    for _d in /usr/share/roundcube /var/lib/roundcube /usr/share/webapps/roundcube /var/www /srv/www /srv/http /opt; do [ -d "$(P "$_d")" ] && printf '%s\n' "$(P "$_d")"; done
    printf '%s' "$EXTRA"
} | grep . | sort -u | while IFS= read -r _d; do
    find "$_d" -maxdepth 5 -path '*/program/include/iniset.php' -type f 2>/dev/null
done | sed 's|/program/include/iniset.php$||' | sort -u >"$W/roots"
if [ ! -s "$W/roots" ]; then
    cc_show "$C_GRY" "No Roundcube here (looked in /usr/share/roundcube, /var/lib/roundcube, /var/www, /srv, /opt; add --webroot DIR)."
    rm -rf "$W"; cc_finish; exit 0
fi
if [ -z "$BOX" ]; then
    cc_box_ask w "${R:-}"
fi
[ "$BOX" = webmail ] && cc_show "$C_GRY" "  webmail: webmail-interactive is scored - the login page is checked after any change."

# conf_files ROOT -> the config files Roundcube reads (Debian keeps them in /etc/roundcube).
#   Its own config/ first; /etc/roundcube only for a packaged install.
conf_files() {
    if [ -f "$1/config/config.inc.php" ]; then printf '%s\n' "$1/config/config.inc.php"
    elif [ -f "$(P /etc/roundcube/config.inc.php)" ]; then printf '%s\n' "$(P /etc/roundcube/config.inc.php)"; fi
}
# rc_get FILE KEY -> the value as written ($config['KEY'] = VALUE;), last one wins
rc_get() {
    awk -v k="$2" -v q="'" '
        { l = $0; sub(/^[ \t]+/, "", l) }
        l ~ /^(\/\/|#)/ { next }
        index(l, "$config[" q k q "]") == 1 || index(l, "$config[\"" k "\"]") == 1 || index(l, "$rcmail_config[" q k q "]") == 1 {
            v = l; sub(/^[^=]*=[ \t]*/, "", v); sub(/;[ \t]*(\/\/.*)?$/, "", v); last = v }
        END { print last }' "$1" 2>/dev/null
}
# The value Roundcube uses: the config file, then its defaults.
rc_val() {   # rc_val ROOT KEY
    _v=$(rc_get "$(conf_files "$1")" "$2")
    [ -n "$_v" ] && { printf '%s' "$_v"; return; }
    for _d in "$(dirname "$(conf_files "$1")")/defaults.inc.php" "$1/config/defaults.inc.php" "$(P /etc/roundcube/defaults.inc.php)"; do [ -f "$_d" ] && { rc_get "$_d" "$2"; return; }; done
}
unq() { printf '%s' "$1" | sed "s/^[\"']//; s/[\"']$//"; }
# The URL of the login page: --url, an Apache Alias to the root, else /roundcube/.
url_for() {
    [ -n "$URL" ] && { printf '%s' "$URL"; return; }
    _al=$(grep -rhs "^[[:space:]]*Alias[[:space:]]" "$(P /etc/apache2)" "$(P /etc/httpd)" 2>/dev/null | awk -v r="${1#"$R"}" '$3 == r || $3 == r "/" { print $2; exit }')
    case "${1#"$R"}" in /var/www/html/*) _al="/${1#"$R"/var/www/html/}" ;; esac
    printf 'http://127.0.0.1%s/' "$(printf '%s' "${_al:-/roundcube}" | sed 's|/$||')"
}
http_code() { if cc_have curl; then curl -s -m 8 -o "$W/page" -w '%{http_code}' "$1" 2>/dev/null; else wget -q -S -O "$W/page" -T 8 "$1" 2>&1 | awk '/HTTP\// { c = $2 } END { print c }'; fi; }

# ---- Look -------------------------------------------------------------------------------
# findings: level<TAB>root<TAB>what   fixes offered: fix<TAB>root<TAB>arg<TAB>description
: >"$W/find"; : >"$W/fixes"
fnd() { printf '%s\t%s\t%s\n' "$1" "$2" "$3" >>"$W/find"; case "$1" in HIGH) cc_show "$C_RED" "  [!] $3" ;; MED) cc_show "$C_YEL" "  [*] $3" ;; *) cc_show "$C_GRN" "  [ok] $3" ;; esac; }
fix() { want "$1" && printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >>"$W/fixes"; return 0; }
# vlt A B -> true if version A < B
vlt() { [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -t. -k1,1n -k2,2n -k3,3n | head -n 1)" = "$1" ]; }
N=0
# fd 3: nothing inside the loop can read the list by accident.
while IFS= read -r _rt <&3; do
    N=$((N + 1)); _cf=$(conf_files "$_rt"); _u=$(url_for "$_rt")
    _ver=$(sed -n "s/.*RCMAIL_VERSION'*[ ,]*'\([0-9][0-9.]*\)'.*/\1/p" "$_rt/program/include/iniset.php" | head -n 1)
    header "$N  Roundcube ${_ver:-?} in ${_rt#"$R"}  ($_u)"
    [ -n "$_cf" ] || { fnd MED "$_rt" "no config.inc.php found for it: is it set up?"; continue; }
    cc_show "$C_GRY" "  config: ${_cf#"$R"}"
    # The version.
    _pkg=0; _cl=""
    case "${_rt#"$R"}" in /usr/share/roundcube|/var/lib/roundcube|/usr/share/webapps/roundcube) _pkg=1 ;; esac
    for _c in "$(P /usr/share/doc/roundcube-core/changelog.Debian.gz)" "$(P /usr/share/doc/roundcube/changelog.Debian.gz)"; do [ -r "$_c" ] && { _cl=$_c; break; }; done
    vchk() {   # vchk CVE FIXED-1.6 FIXED-1.5 WHAT
        _bad=0
        case "$_ver" in 1.6.*) vlt "$_ver" "$2" && _bad=1 ;; 1.5.*) vlt "$_ver" "$3" && _bad=1 ;; 1.[0-4].*|0.*) _bad=1 ;; esac
        [ "$_bad" = 1 ] || return 0
        if [ "$_pkg" = 1 ] && [ -n "$_cl" ] && gzip -dc "$_cl" 2>/dev/null | grep -q "$1"; then fnd OK "$_rt" "$1 ($4): fixed by the distribution package (in its changelog)"
        elif [ "$_pkg" = 1 ]; then fnd HIGH "$_rt" "$1: $4 - $_ver is older than $2; a distribution package may have the fix: check 'apt changelog roundcube-core | grep $1', else upgrade it"
        else fnd HIGH "$_rt" "$1: $4 - $_ver is older than $2 (or $3 for 1.5): upgrade Roundcube"; fi
    }
    case "$_ver" in 1.[0-4].*|0.*) fnd HIGH "$_rt" "Roundcube $_ver gets no security fixes any more: upgrade it" ;; esac
    vchk CVE-2025-49113 1.6.11 1.5.10 "any logged-in user can run commands on the server"
    vchk CVE-2024-42009 1.6.8 1.5.8 "an email that steals the reader's mail (XSS)"
    # Where logins go.
    for _k in imap_host default_host smtp_host smtp_server; do
        _v=$(unq "$(rc_val "$_rt" "$_k")"); [ -n "$_v" ] || continue
        _hosts=$(printf '%s' "$_v" | tr -d '[]"'"'" | tr ',' '\n' | sed 's|^[a-z]*://||; s|:[0-9]*$||; s/^ *//; s/ *$//' | grep . | sort -u)
        for _h in $_hosts; do
            case "$_h" in localhost|127.0.0.1|::1|"$CC_HOST"|%h|%n|%d|%s|%t|%z) continue ;; esac
            fnd HIGH "$_rt" "$_k = $_v: logins are sent to $_h, not this box - every webmail password goes there (is that your mail server?)"
        done
    done
    # The installer.
    _ie=$(unq "$(rc_val "$_rt" enable_installer)")
    if [ -d "$_rt/installer" ]; then
        _ic=-; [ -z "$R" ] && _ic=$(http_code "${_u}installer/")
        case "$_ie" in true|1|TRUE) fnd HIGH "$_rt" "the installer is ON (enable_installer = true): anyone can rewrite the config" ;; esac
        case "$_ic" in 200) fnd HIGH "$_rt" "installer/ answers 200 at ${_u}installer/" ;; -) fnd MED "$_rt" "installer/ folder is there (not needed after setup)" ;; *) fnd MED "$_rt" "installer/ folder is there (answers $_ic; not needed after setup)" ;; esac
        fix installer "$_rt" "-" "quarantine ${_rt#"$R"}/installer and set enable_installer = false"
    else fnd OK "$_rt" "no installer/ folder"; fi
    # Debug that writes passwords to the logs.
    _dbg=""
    for _k in sql_debug imap_debug smtp_debug ldap_debug memcache_debug; do
        case "$(unq "$(rc_val "$_rt" "$_k")")" in true|1|TRUE) _dbg="$_dbg $_k" ;; esac
    done
    _dl=$(unq "$(rc_val "$_rt" debug_level)"); case "$_dl" in ''|*[!0-9]*) _dl=1 ;; esac
    if [ -n "$_dbg" ]; then fnd HIGH "$_rt" "debug on:$_dbg - these write mail and passwords to the log files"; fix debug-off "$_rt" "$_dbg" "turn off:$_dbg; debug_level = 1"
    elif [ $((_dl & 4)) -ne 0 ]; then fnd MED "$_rt" "debug_level = $_dl shows errors (paths, SQL) to users"; fix debug-off "$_rt" "" "debug_level = 1"
    else fnd OK "$_rt" "no debug logging"; fi
    # des_key.
    _dk=$(unq "$(rc_val "$_rt" des_key)")
    if [ "$_dk" = 'rcmail-!24ByteDESkey*Str' ] || [ "${#_dk}" -lt 24 ]; then
        fnd HIGH "$_rt" "des_key is $([ "${#_dk}" -lt 24 ] && echo "only ${#_dk} characters" || echo 'the published default'): stored passwords and sessions can be decrypted"
        fix des-key "$_rt" "-" "a new random des_key (everyone logs in again)"
    else fnd OK "$_rt" "des_key is set (${#_dk} characters)"; fi
    # log_logins.
    case "$(unq "$(rc_val "$_rt" log_logins)")" in true|1|TRUE) fnd OK "$_rt" "log_logins is on" ;;
        *) fnd MED "$_rt" "log_logins is off: you cannot see who logged in to the webmail"; fix log-logins "$_rt" "-" "log_logins = true (logins go to Roundcube's userlogins log)" ;; esac
    # Plugins.
    # The plugins list can span lines: $config['plugins'] = [ 'a', 'b' ];
    _pl=$(awk '/\$config\[.plugins.\]/ { on = 1 } on { l = $0; sub(/\/\/.*/, "", l); sub(/#.*/, "", l); e = (index(l, ";") > 0); gsub(/\$config\[.plugins.\]|array|[][()",;=]/, " ", l); gsub(/[\047]/, " ", l); s = s " " l; if (e) on = 0 } END { print s }' "$_cf" 2>/dev/null | tr -s ' ')
    [ -n "$(printf '%s' "$_pl" | tr -d ' ')" ] && cc_show "" "  plugins enabled:$_pl"
    # Files keep the package's dates; a plugin file newer than Roundcube's
    # own code was added or changed later.
    for _p in "$_rt"/plugins/*/; do
        [ -d "$_p" ] || continue
        _nf=$(find "$_p" -type f -newer "$_rt/program/include/iniset.php" 2>/dev/null | head -n 3 | sed "s|^$_p||" | tr '\n' ' ')
        [ -n "$_nf" ] && fnd MED "$_rt" "plugin $(basename "$_p") has files newer than Roundcube itself ($_nf): added later? (SV-16 --webroot ${_p%/})"
    done
    # Config file permissions.
    for _c in "$_cf" "$(dirname "$_cf")/debian-db.php"; do
        [ -f "$_c" ] || continue
        case "$(ls -l "$_c" | cut -c8-10)" in ---) ;; *) fnd MED "$_rt" "${_c#"$R"} can be read by every user (des_key, database password)"; fix config-perms "$_rt" "$_c" "${_c#"$R"}: root, web server group, mode 640" ;; esac
    done
    # What the web can download.
    if [ -z "$R" ]; then
        _open=""; _info=""
        for _x in logs/errors.log logs/userlogins.log logs/ temp/ config/config.inc.php; do
            _c=$(http_code "$_u$_x"); case "$_c" in 200) _open="$_open $_x" ;; esac
        done
        for _x in SQL/mysql.initial.sql bin/update.sh composer.json; do
            _c=$(http_code "$_u$_x"); case "$_c" in 200) _info="$_info $_x" ;; esac
        done
        [ -n "$_open" ] && fnd HIGH "$_rt" "these can be downloaded from the web:$_open (logs hold logins, config holds secrets)"
        [ -n "$_info" ] && fnd MED "$_rt" "these can be downloaded from the web:$_info (they show the version and the database layout)"
        if [ -n "$_open$_info" ]; then fix block-dirs "$_rt" "$_u" "Apache: deny installer, logs, temp, config, SQL, bin under ${_rt#"$R"}"
        else fnd OK "$_rt" "logs, temp, config, SQL, bin: not downloadable"; fi
    else fix block-dirs "$_rt" "-" "Apache: deny installer, logs, temp, config, SQL, bin under ${_rt#"$R"}"; fi
done 3<"$W/roots"

# ---- Questions ---------------------------------------------------------------------------
header "questions (Enter = the default in capitals)"
: >"$W/chosen"
while IFS="$TAB" read -r _fx _rt _arg _ds; do
    _d=Y; [ "$_fx" = block-dirs ] && [ "$_arg" = - ] && _d=N
    cc_ask "[$_fx] ${_rt#"$R"}: $_ds?" "$_d" "yes, do it" "no, skip it" && printf '%s\t%s\t%s\t%s\n' "$_fx" "$_rt" "$_arg" "$_ds" >>"$W/chosen"
done <"$W/fixes"
NCH=$(grep -c . "$W/chosen")
cut -f4 "$W/chosen" >"$CC_RUN_DIR/plan.txt"

# ---- Helpers for the changes ----------------------------------------------------------
backed() { grep -qxF "$1" "$W/backed" 2>/dev/null && return 0; cc_backup_file "$1" >/dev/null || return 1; printf '%s\n' "$1" >>"$W/backed"; }
# rc_set FILE KEY PHP-VALUE -> replace the line, or add it at the end.
rc_set() {
    backed "$1" || return 1
    awk -v k="$2" -v v="$3" -v q="'" '
        { l = $0; sub(/^[ \t]+/, "", l) }
        (index(l, "$config[" q k q "]") == 1 || index(l, "$config[\"" k "\"]") == 1) && l !~ /^(\/\/|#)/ { if (!done) { print "$config[" q k q "] = " v "; // BT SV-41"; done = 1 }; next }
        { print }
        END { if (!done) print "$config[" q k q "] = " v "; // BT SV-41" }' "$1" >"$1.n" && cat "$1.n" >"$1"; _r=$?; rm -f "$1.n"; touch "$1"; return "$_r"
}
WEBG=""; for _g in www-data apache nginx http; do grep -q "^$_g:" "$(P /etc/group)" 2>/dev/null && { WEBG=$_g; break; }; done
DROP=""; [ -d "$(P /etc/apache2/conf-enabled)" ] && DROP=/etc/apache2/conf-enabled/zz-bt-roundcube.conf
[ -z "$DROP" ] && [ -d "$(P /etc/httpd/conf.d)" ] && DROP=/etc/httpd/conf.d/zz-bt-roundcube.conf
APSVC=apache2; [ -d "$(P /etc/httpd)" ] && [ ! -d "$(P /etc/apache2)" ] && APSVC=httpd
do_fix() {   # do_fix FIX ROOT ARG
    _cf=$(conf_files "$2")
    case "$1" in
        installer) cc_quarantine "$2/installer" >>"$CC_LOG" 2>&1 && rc_set "$_cf" enable_installer false ;;
        debug-off) for _k in $3; do rc_set "$_cf" "$_k" false || return 1; done; rc_set "$_cf" debug_level 1 ;;
        des-key) _nk=$(cc_genpass 24) && [ "${#_nk}" -ge 24 ] && rc_set "$_cf" des_key "'$(printf '%s' "$_nk" | cut -c1-24)'"; _nk="" ;;
        log-logins) rc_set "$_cf" log_logins true ;;
        config-perms)
            _om=$(ls -ln "$3" | awk '{ print $3 ":" $4 }'); _mm=$(ls -l "$3" | awk '{ m = $1; u = substr(m, 2, 3); g = substr(m, 5, 3); o = substr(m, 8, 3); gsub(/-/, "", u); gsub(/-/, "", g); gsub(/-/, "", o); print "u=" u ",g=" g ",o=" o }')
            cc_undo_add "owner and mode of $3 back" "chown $_om $(cc_shquote "$3"); chmod $_mm $(cc_shquote "$3")"
            chown "0:${WEBG:-0}" "$3" 2>/dev/null; chmod 640 "$3" ;;
        block-dirs)
            [ -n "$DROP" ] || { printf '%s\n' "location ~ ^${3#http*://*/}(installer|logs|temp|config|SQL|bin)/ { deny all; }" >>"$CC_RUN_DIR/nginx-bt.conf"; return 0; }
            _df=$(P "$DROP"); [ -f "$_df" ] || { cc_undo_add "remove $DROP (made by SV-41)" "rm -f $(cc_shquote "$_df")"; printf '# Added by SV-41 (Roundcube). Delete this file to undo.\n' >"$_df"; }
            _rr=${2#"$R"}
            for _p in "$_rr" "$(cd "$2" 2>/dev/null && pwd -P | sed "s|^$R||")"; do
                [ -n "$_p" ] || continue
                grep -qF "<DirectoryMatch \"^$_p/(installer|logs|temp|config|SQL|bin)" "$_df" && continue
                printf '<DirectoryMatch "^%s/(installer|logs|temp|config|SQL|bin)(/|$)">\n    Require all denied\n</DirectoryMatch>\n' "$_p" >>"$_df"
            done
            # Debian's logs and temp are links to /var/log/roundcube and /var/lib/roundcube/temp.
            for _l in logs temp config; do
                _t=$(cd "$2/$_l" 2>/dev/null && pwd -P | sed "s|^$R||")
                [ -n "$_t" ] && [ "$_t" != "$_rr/$_l" ] && ! grep -qF "<Directory \"$_t\">" "$_df" && printf '<Directory "%s">\n    Require all denied\n</Directory>\n' "$_t" >>"$_df"
            done
            return 0 ;;
    esac
}
login_ok() { _c=$(http_code "$1"); case "$_c" in 200) grep -qi 'roundcube\|rcmloginuser\|_user' "$W/page" ;; *) return 1 ;; esac; }

# ---- Apply ------------------------------------------------------------------------------
header "apply"
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
    # The login pages that work now must work after.
    : >"$W/pages0"; [ -z "$R" ] && while IFS= read -r _rt; do _u=$(url_for "$_rt"); login_ok "$_u" && printf '%s\n' "$_u" >>"$W/pages0"; done <"$W/roots"
    if [ "$NOTIMER" != 1 ] && [ -z "$R" ]; then cc_timer_start "$TIMER"; TIMER_ON=1
        cc_show "$C_YEL" "  [*] Revert timer started: everything is undone in $((TIMER / 60)):$(printf '%02d' $((TIMER % 60))) unless you keep it at the end."; fi
    if [ -z "$R" ] && cut -f1 "$W/chosen" | grep -q block-dirs; then
        if [ "$CC_INIT" = systemd ]; then _rl="systemctl reload $APSVC"; else _rl="service $APSVC reload"; fi
        cc_undo_add "reload $APSVC after its config is put back" "$_rl"
    fi
    while IFS="$TAB" read -r _fx _rt _arg _ds; do
        if do_fix "$_fx" "$_rt" "$_arg"; then NOK=$((NOK + 1)); cc_show "$C_GRN" "  [+] $_ds"; else NBAD=$((NBAD + 1)); cc_show "$C_RED" "  [x] FAILED: $_ds"; fi
    done <"$W/chosen"
    if [ -z "$R" ]; then
        if cut -f1 "$W/chosen" | grep -q block-dirs && [ -n "$DROP" ]; then
            _ct=$(cc_first apache2ctl apachectl httpd)
            if [ -n "$_ct" ] && ! "$_ct" -t >>"$CC_LOG" 2>&1; then BROKE=1; cc_show "$C_RED" "  [x] the Apache config test FAILS"
            elif { if [ "$CC_INIT" = systemd ]; then systemctl reload "$APSVC"; else service "$APSVC" reload; fi; } >>"$CC_LOG" 2>&1; then cc_show "$C_GRN" "  [+] $APSVC reloaded"
            fi
        fi
        sleep 3
        while IFS= read -r _u; do
            if login_ok "$_u"; then cc_show "$C_GRN" "  [+] $_u still shows the login page"
            else BROKE=1; cc_show "$C_RED" "  [x] $_u no longer shows the login page"; fi
        done <"$W/pages0"
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
awk -F'\t' -v r="$R" '{ t = $2; if (r != "" && index(t, r) == 1) t = substr(t, length(r) + 1); printf "%-4s %s  %s\n", $1, t, $3 }' "$W/find" >"$CC_RUN_DIR/findings.txt"
[ -s "$CC_RUN_DIR/nginx-bt.conf" ] || rm -f "$CC_RUN_DIR/nginx-bt.conf"
{
    printf '==========[ summary ]==========\n'
    printf 'SV-41 Roundcube hardening | host %s | %s\n' "$CC_HOST" "$([ "$APPLIED" = 1 ] && { [ "$BROKE" = 1 ] && echo 'APPLIED, then PUT BACK (the login page broke)' || echo APPLIED; } || echo 'DRY RUN - nothing changed')"
    printf 'Found: %d HIGH, %d MED\n' "$(grep -c "^HIGH$TAB" "$W/find")" "$(grep -c "^MED$TAB" "$W/find")"
    awk -F'\t' '$1 != "OK" { printf "  %-4s %s\n", $1, substr($3, 1, 150) }' "$W/find"
    [ -s "$CC_RUN_DIR/plan.txt" ] && { printf '\nChanges%s:\n' "$([ "$APPLIED" = 1 ] || echo ' planned')"; sed 's/^/  /' "$CC_RUN_DIR/plan.txt"; }
    [ "$APPLIED" = 1 ] && printf 'Done: %d   Failed: %d\n' "$NOK" "$NBAD"
    [ -f "$CC_RUN_DIR/nginx-bt.conf" ] && printf 'nginx: include %s/nginx-bt.conf in the server block, then nginx -t and reload.\n' "$CC_RUN_DIR"
    [ "$APPLIED" = 1 ] && [ -f "$CC_RUN_DIR/revert.sh" ] && printf 'Undo this run: sh %s/revert.sh --force\n' "$CC_RUN_DIR"
    printf '\nAlso: web shells SV-16 --webroot <roundcube>; mail passwords SV-40; its database password SV-42; mail backdoors SV-31.\n'
} >"$CC_RUN_DIR/summary.txt"
cc_show "" ""
while IFS= read -r _l; do
    case "$_l" in ==*|SV-41*) cc_show "$C_CYN" "$_l" ;; '  HIGH'*|*'PUT BACK'*) cc_show "$C_RED" "$_l" ;; '  MED'*) cc_show "$C_YEL" "$_l" ;; *) cc_show "" "$_l" ;; esac
done <"$CC_RUN_DIR/summary.txt"
rm -rf "$W"
if [ "$TIMER_ON" = 1 ]; then header "KEEP OR REVERT"; cc_show "$C_YEL" "[*] Before you answer: log in to the webmail from a browser and open a mail."; cc_timer_finish || true; fi
cc_finish
