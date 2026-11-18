#!/bin/sh
# =============================================================================
# ID:       SV-21
# NAME:     PHP and web app hardening
# ROLE:     Applications  (wave 2, after SV-15 backups)
# KIND:     changes - dry run unless --apply
# VERSION:  1.0.0
#
# PURPOSE
#   Makes the web apps (WordPress, Joomla, Drupal, PrestaShop, OpenCart,
#   Magento, Roundcube, any PHP site) much harder to take over, and makes an
#   uploaded web shell useless - without taking the site down.  It finds the
#   sites and apps first, then offers each fix, graded like SV-20 and SV-30:
#
#     safe
#       php-urlinclude  allow_url_include Off (stops including code from
#                       another server)
#       php-errors      display_errors Off, log_errors On (error pages show
#                       paths and SQL)
#       php-expose      expose_php Off (no PHP version in the headers)
#       app-config      app config files (database password) readable by the
#                       web server only: owner root, group of the web server,
#                       mode 640
#       wp-fileedit     WordPress: no editing of theme/plugin code from the
#                       admin panel (DISALLOW_FILE_EDIT)
#     service  (Apache: one drop-in file, zz-ccdc-web.conf)
#       upload-nophp    PHP cannot run in upload folders (wp-content/uploads,
#                       images, sites/default/files ...): an uploaded web
#                       shell is just text
#       block-files     .git, .env, backups and dumps cannot be downloaded
#       wp-xmlrpc       WordPress xmlrpc.php blocked (password guessing many
#                       at a time)
#       wp-admins       WordPress admins created in the last --days days:
#                       asked one by one, [k]eep or [d]emote to subscriber
#     access
#       php-functions   disable_functions: system, exec, shell_exec,
#                       passthru, proc_open, popen, pcntl_exec - most web
#                       shells stop working (some apps need one of them)
#       code-readonly   the web server account can no longer change the
#                       site's code; upload and cache folders stay writable
#
#   Reported, never changed: phpinfo pages, old app versions, nginx (the
#   lines to add are written to a file to include by hand).
#
#   After applying: the web server's config test, a reload of the web server
#   and PHP-FPM, then each --url must answer as before (same or better, no
#   PHP or database error page).  If not, everything this run changed is put
#   back on the spot.  A revert timer runs, as in the other change scripts.
#
#   QUESTIONS (Enter takes the default in capitals; a flag answers each):
#     which box                         --box NAME
#     how far: [s]afe [v] service [a]ccess    --level L
#     each fix (yes / no)               --only / --skip
#     each new WordPress admin: [k]eep [d]emote    --admins keep|demote
#
# USAGE
#   sudo sh SV-21-web-hardening.sh                             dry run, asks
#   sudo sh SV-21-web-hardening.sh --protected p.csv --apply --level service
#   sudo sh SV-21-web-hardening.sh --protected p.csv --apply --batch --level safe --url http://127.0.0.1/shop/
#
# OPTIONS
#   --apply            make the changes (without it, dry run only)
#   --level L          safe | service | access (asked; Enter = safe)
#   --box NAME         splunk | webmail | ecomm | other (asked)
#   --only a,b / --skip a,b   fixes by name
#   --url URL          a page to check after the changes (repeat; default
#                      http://127.0.0.1/ and each app's folder under it)
#   --webroot DIR      also look for apps here (repeat)
#   --days N           an admin made in the last N days is "new" (default 7)
#   --admins keep|demote   answer for every new WordPress admin
#   --mysql-cnf FILE   MySQL client file (for the WordPress admin list)
#   --timer SECONDS    revert countdown (default 120); --no-timer
#   --root DIR         treat DIR as / (tests): files only, nothing restarted
#   --no-color         no colours
#   --help             this text plus the common options
#
# OUTPUTS  (under --out, in web-hardening-N/)
#   output.txt   everything shown on screen, no colour
#   apps.txt     each app: folder, version, config, upload folders
#   plan.txt, changes.txt, summary.txt, run.txt, revert.sh
#   nginx-ccdc.conf   the nginx lines to include by hand (when nginx serves)
#
# WHAT IT CHANGES  (only with --apply)
#   php.ini files (apache2, fpm, cgi - not the command line one), one Apache
#   drop-in file, the app config files' owner and mode, wp-config.php
#   (DISALLOW_FILE_EDIT), WordPress admin roles, and with code-readonly the
#   owner of the site's files.  Every change has an undo line.
#
# DEPENDS ON
#   awk, sed, find; apache2ctl/apachectl or httpd for the config test;
#   curl or wget for the site check; the mysql client for wp-admins.
#
# TESTED ON
#   Ubuntu 24.04 with Apache 2.4 + PHP 8.3 and a WordPress-style site, under
#   dash, bash, busybox sh, ksh93, mksh and yash with gawk, mawk and busybox
#   awk: each fix applied, a planted web shell in uploads stopped running,
#   the site still answered, and revert put everything back.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - Back up first (SV-15).
#   - php-functions can break an app that runs programs (image tools, mail
#     through sendmail with popen, backup plugins).  The site check catches
#     the home page only: click through the store after it.
#   - code-readonly stops app updates and plugin installs from the admin
#     panel.  That is the point during the competition.
#   - nginx is not edited: include nginx-ccdc.conf in each server { } by hand.
#
# DEBUGGING
#   --debug shows each command.  The Apache drop-in is plain text:
#   /etc/apache2/conf-enabled/zz-ccdc-web.conf (or /etc/httpd/conf.d/).
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

ALL_ACTIONS="php-urlinclude php-errors php-expose app-config wp-fileedit upload-nophp block-files wp-xmlrpc wp-admins php-functions code-readonly"

usage() {
    cat <<'USAGE'
SV-21 PHP and web app hardening - make the apps hard to take over, web shells useless
  sudo sh SV-21-web-hardening.sh                    dry run, asks
  sudo sh SV-21-web-hardening.sh --protected p.csv --apply --level service

  --apply            make the changes (without it, dry run only)
  --level L          safe | service | access (Enter = safe)
  --box NAME         splunk | webmail | ecomm | other
  --only a,b / --skip a,b   fixes by name (see below)
  --url URL          page to check after the changes (repeatable)
  --webroot DIR      also look for apps here (repeatable)
  --days N           admins made in the last N days are "new" (default 7)
  --admins keep|demote   answer for every new WordPress admin
  --mysql-cnf FILE   MySQL client file (WordPress admin list)
  --timer SECONDS    revert countdown (default 120); --no-timer
  --root DIR         treat DIR as / (tests)
  --no-color         no colours
  --help             show this text

Fixes (risk): php-urlinclude[safe] php-errors[safe] php-expose[safe] app-config[safe]
  wp-fileedit[safe] upload-nophp[service] block-files[service] wp-xmlrpc[service]
  wp-admins[service] php-functions[access] code-readonly[access]
USAGE
    cc_usage_common
}

NL='
'
LEVEL=""; BOX=""; ONLY=""; SKIP=""; URLS=""; EXTRA=""; DAYS=7; ADMINS=""; MYCNF=""; TIMER=120; NOTIMER=0; R=""; COLOR=1
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --apply)      CC_APPLY=1; shift ;;
        --level)      [ $# -ge 2 ] || cc_die 2 "--level needs safe, service or access"; LEVEL=$2; shift 2 ;;
        --box)        [ $# -ge 2 ] || cc_die 2 "--box needs a name"; BOX=$2; shift 2 ;;
        --only)       [ $# -ge 2 ] || cc_die 2 "--only needs a list"; ONLY="$ONLY,$2"; shift 2 ;;
        --skip)       [ $# -ge 2 ] || cc_die 2 "--skip needs a list"; SKIP="$SKIP,$2"; shift 2 ;;
        --url)        [ $# -ge 2 ] || cc_die 2 "--url needs an address"; URLS="$URLS $2"; shift 2 ;;
        --webroot)    [ $# -ge 2 ] || cc_die 2 "--webroot needs a folder"; [ -d "$2" ] || cc_die 2 "--webroot: not a folder: $2"; EXTRA="$EXTRA$(cc_abspath "$2")$NL"; shift 2 ;;
        --days)       [ $# -ge 2 ] || cc_die 2 "--days needs a number"; DAYS=$2; shift 2 ;;
        --admins)     [ $# -ge 2 ] || cc_die 2 "--admins needs keep or demote"; ADMINS=$2; shift 2 ;;
        --mysql-cnf)  [ $# -ge 2 ] || cc_die 2 "--mysql-cnf needs a file"; [ -r "$2" ] || cc_die 2 "--mysql-cnf: cannot read $2"; MYCNF=$(cc_abspath "$2"); shift 2 ;;
        --timer)      [ $# -ge 2 ] || cc_die 2 "--timer needs seconds"; TIMER=$2; shift 2 ;;
        --no-timer)   NOTIMER=1; shift ;;
        --root)       [ $# -ge 2 ] || cc_die 2 "--root needs a folder"; [ -d "$2" ] || cc_die 2 "--root: not a folder: $2"; R=$(cd "$2" && pwd); [ "$R" = / ] && R=""; shift 2 ;;
        --no-color|--no-colour) COLOR=0; shift ;;
        --help|-h)    usage; exit 0 ;;
        *)            cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
case "$LEVEL" in ''|safe|service|access) ;; *) cc_die 2 "--level must be safe, service or access" ;; esac
case "$BOX" in ''|splunk|webmail|ecomm|other) ;; *) cc_die 2 "--box must be splunk, webmail, ecomm or other" ;; esac
case "$ADMINS" in ''|keep|demote) ;; *) cc_die 2 "--admins must be keep or demote" ;; esac
for _n in "$DAYS" "$TIMER"; do case "$_n" in ''|*[!0-9]*) cc_die 2 "--days and --timer need whole numbers" ;; esac; done
for _a in $(printf '%s' "$ONLY,$SKIP" | tr ',' ' '); do
    case " $ALL_ACTIONS " in *" $_a "*) ;; *) cc_die 2 "unknown fix '$_a' (see --help)" ;; esac
done

cc_init "SV-21" "PHP and web app hardening" changes
cc_detect_os
# shellcheck disable=SC2034  # read by cc_color_init
[ "$COLOR" = 1 ] || CC_NOCOLOR=1
cc_color_init
cc_use_numbered_dir web-hardening
rmdir "$CC_RUN_DIR/raw" 2>/dev/null
OUTF="$CC_RUN_DIR/output.txt"
grep -v '\[NOTE\]\|\[DEBUG\]' "$CC_LOG" >"$OUTF" 2>/dev/null || : >"$OUTF"
# shellcheck disable=SC2034  # CC_TEE is read by the library's log functions
CC_TEE=$OUTF
W="$CC_RUN_DIR/.work"; mkdir -p "$W"
# Tables are kept as .txt only; their CSV source is scratch data in .work.
CC_CSV_DIR="$W/csv"; mkdir -p "$CC_CSV_DIR"
header() { cc_show "" ""; cc_show "$C_CYN" "==========[ $1 ]=========="; }
inlist() { case ",$2," in *",$1,"*) return 0 ;; esac; return 1; }
P() { printf '%s%s' "$R" "$1"; }

cc_show "$C_CYN" "SV-21 PHP and web app hardening | host $CC_HOST | results in $CC_RUN_DIR"
cc_show "" "Legend: ${C_RED}[!]${C_OFF} fix now   ${C_YEL}[*]${C_OFF} look at it   ${C_YEL}[~] would change${C_OFF}   ${C_GRN}[+] changed   [ok] already right${C_OFF}   ${C_RED}[x] failed${C_OFF}"
[ -n "$R" ] && cc_show "$C_GRY" "Acting on $R as if it were / (nothing is restarted)"

# ---- Box and level ----------------------------------------------------------------------
if [ -z "$BOX" ]; then
    cc_choose "Which box is this?" e "s=splunk" "w=webmail" "e=ecomm" "o=other"
    case "$CC_CHOICE" in s) BOX=splunk ;; w) BOX=webmail ;; e) BOX=ecomm ;; *) BOX=other ;; esac
fi
case "$BOX" in
    ecomm)   cc_show "$C_GRY" "  ecomm: the store is scored (ecomm-http). It must still load after the changes: that is checked." ;;
    webmail) cc_show "$C_GRY" "  webmail: the webmail login is scored. Roundcube must still load after the changes: that is checked." ;;
esac
if [ -z "$LEVEL" ]; then
    cc_choose "How far should I go?" s \
        "s=safe: PHP settings, config file permissions, no code editing in the WordPress admin" \
        "v=service: also no PHP in upload folders, block .git/.env/backups and xmlrpc, check new WordPress admins" \
        "a=access: also disable the functions web shells use, and make the site's code read-only for the web server"
    case "$CC_CHOICE" in v) LEVEL=service ;; a) LEVEL=access ;; *) LEVEL=safe ;; esac
fi
level_rank() { case "$1" in safe) echo 1 ;; service) echo 2 ;; access) echo 3 ;; esac; }
act_risk() {
    case "$1" in
        php-urlinclude|php-errors|php-expose|app-config|wp-fileedit) echo safe ;;
        php-functions|code-readonly) echo access ;;
        *) echo service ;;
    esac
}

# ---- What is here ---------------------------------------------------------------------------
header "1/4  web server, PHP and apps"
APACHE_SVC=""; DROP=""
if [ -d "$(P /etc/apache2)" ]; then APACHE_SVC=apache2; [ -d "$(P /etc/apache2/conf-enabled)" ] && DROP=/etc/apache2/conf-enabled/zz-ccdc-web.conf
elif [ -d "$(P /etc/httpd)" ]; then APACHE_SVC=httpd; [ -d "$(P /etc/httpd/conf.d)" ] && DROP=/etc/httpd/conf.d/zz-ccdc-web.conf; fi
NGINX=""; [ -f "$(P /etc/nginx/nginx.conf)" ] && NGINX=/etc/nginx
# php.ini files the web uses (not the command line one).
PHP_INIS=$( { ls -d "$(P /etc/php)"/*/apache2/php.ini "$(P /etc/php)"/*/fpm/php.ini "$(P /etc/php)"/*/cgi/php.ini "$(P /etc/php.ini)" 2>/dev/null; } | sed "s|^$R||")
FPM_SVCS=$(printf '%s\n' $PHP_INIS | sed -n 's|^/etc/php/\([^/]*\)/fpm/.*|php\1-fpm|p' | tr '\n' ' ')
[ -f "$(P /etc/php.ini)" ] && [ -d "$(P /etc/php-fpm.d)" ] && FPM_SVCS="$FPM_SVCS php-fpm"
# The account the web server runs as, and its group.
WEBUSER=""
for _u in www-data apache nginx http wwwrun; do grep -q "^$_u:" "$(P /etc/passwd)" 2>/dev/null && { WEBUSER=$_u; break; }; done
WEBGROUP=$(awk -F: -v u="$WEBUSER" '$1 == u { print $4 }' "$(P /etc/passwd)" 2>/dev/null)
WEBGROUP=$(awk -F: -v g="$WEBGROUP" '$3 == g { print $1 }' "$(P /etc/group)" 2>/dev/null)
[ -n "$WEBGROUP" ] || WEBGROUP=$WEBUSER
cc_show "" "  Web server: ${APACHE_SVC:-none}$([ -n "$NGINX" ] && echo ' + nginx')   runs as: ${WEBUSER:-?}   PHP configs: $(printf '%s ' $PHP_INIS)"

# Apps: "app|root|config|version|upload folders (space separated)"
: >"$W/apps"
{
    for _d in /var/www /srv/www /srv/http /usr/share/nginx/html /opt /usr/share/roundcube /var/lib/roundcube; do [ -d "$(P "$_d")" ] && printf '%s\n' "$(P "$_d")"; done
    printf '%s' "$EXTRA"
} | grep . | sort -u >"$W/roots"
while IFS= read -r _d; do
    find "$_d" -maxdepth 5 \( -name node_modules -o -name vendor -o -name .git -o -name cache \) -prune -o -type f \
        \( -name wp-config.php -o -name configuration.php -o -name parameters.php -o -name settings.inc.php -o -name config.php -o -name env.php -o -name iniset.php -o -name settings.php \) -print 2>/dev/null
done <"$W/roots" | sort -u >"$W/cfgs"
while IFS= read -r _c; do
    _app=""; _root=""; _ver=""; _ups=""
    case "$_c" in
        */wp-config.php) _app=WordPress; _root=$(dirname "$_c"); _ups="wp-content/uploads"
            _ver=$(sed -n "s/^\$wp_version *= *'\([^']*\)'.*/\1/p" "$_root/wp-includes/version.php" 2>/dev/null) ;;
        */configuration.php) grep -q JConfig "$_c" 2>/dev/null || continue; _app=Joomla; _root=$(dirname "$_c"); _ups="images media tmp" ;;
        */sites/default/settings.php) _app=Drupal; _root=${_c%/sites/default/settings.php}; _ups="sites/default/files" ;;
        */app/config/parameters.php) _app=PrestaShop; _root=${_c%/app/config/parameters.php}; _ups="img upload download" ;;
        */config/settings.inc.php) _app=PrestaShop; _root=${_c%/config/settings.inc.php}; _ups="img upload download" ;;
        */admin/config.php) continue ;;
        */config.php) grep -q "DB_DATABASE" "$_c" 2>/dev/null || continue; _app=OpenCart; _root=$(dirname "$_c"); _ups="image system/storage/upload" ;;
        */app/etc/env.php) _app=Magento; _root=${_c%/app/etc/env.php}; _ups="pub/media" ;;
        */program/include/iniset.php) _app=Roundcube; _root=${_c%/program/include/iniset.php}; _ups="temp logs"; _c="$_root/config/config.inc.php"
            _ver=$(sed -n "s/.*RCMAIL_VERSION'*[ ,]*'\([0-9][0-9.]*\)'.*/\1/p" "$_root/program/include/iniset.php" | head -n 1) ;;
        *) continue ;;
    esac
    grep -q "|$_root|" "$W/apps" && continue
    # Only upload folders that exist.
    _ex=""; for _u in $_ups; do [ -d "$_root/$_u" ] && _ex="$_ex $_u"; done
    printf '%s|%s|%s|%s|%s\n' "$_app" "$_root" "$_c" "${_ver:-?}" "${_ex# }" >>"$W/apps"
done <"$W/cfgs"
# Folders named like upload folders in the web roots, for sites with no app.
while IFS= read -r _d; do
    find "$_d" -maxdepth 4 -type d \( -name uploads -o -name upload -o -name files -o -name images \) 2>/dev/null
done <"$W/roots" | sort -u >"$W/genup"
ACSV=$(cc_csv_new apps "app,folder,version,config,upload_folders")
if [ -s "$W/apps" ]; then
    while IFS='|' read -r _app _root _c _ver _ups; do
        cc_csv_row "$ACSV" "$_app" "${_root#"$R"}" "$_ver" "${_c#"$R"}" "${_ups:--}"
        cc_show "$C_GRN" "  $(printf '%-11s %-8s %-34s' "$_app" "$_ver" "${_root#"$R"}") uploads: ${_ups:-none found}"
    done <"$W/apps"
else
    cc_show "$C_YEL" "  [*] no known app found (looked in /var/www, /srv, /opt; add --webroot DIR)"
fi
# phpinfo pages: report only.
while IFS= read -r _d; do
    find "$_d" -maxdepth 5 -type f -name '*.php' -size -2k 2>/dev/null | while IFS= read -r _f; do
        grep -q 'phpinfo *(' "$_f" 2>/dev/null && cc_show "$C_YEL" "  [*] phpinfo page: ${_f#"$R"} - shows paths, versions and settings to anyone: move it out (SV-15 quarantines it on restore)"
    done
done <"$W/roots"
HAS_WP=0; grep -q '^WordPress|' "$W/apps" && HAS_WP=1

# ---- Which fixes, and what each would touch -----------------------------------------------
_ini_get() {
    awk -v k="$2" '/^[#;]/ { next } { split($0, a, "="); kk = a[1]; gsub(/[ \t]/, "", kk) }
        index($0, "=") && kk == k { v = substr($0, index($0, "=") + 1); sub(/^[ \t]+/, "", v); sub(/[ \t\r]+$/, "", v) }
        END { print v }' "$1" 2>/dev/null
}
_ini_set() {
    awk -v k="$2" -v v="$3" '
        function key(s,   a) { sub(/^[ \t]+/, "", s); if (s ~ /^[#;]/) return ""; split(s, a, "="); gsub(/[ \t]/, "", a[1]); return (index(s, "=") ? a[1] : "") }  # awk, not shell: posix-ok
        key($0) == k { if (!done) { print k " = " v; done = 1 }; next }
        { print }
        END { if (!done) print k " = " v }' "$1" >"$1.ccnew" || { rm -f "$1.ccnew"; return 1; }
    cat "$1.ccnew" >"$1"; _is=$?; rm -f "$1.ccnew"; return "$_is"
}
CONSIDER=""
for _a in $ALL_ACTIONS; do
    [ "$(level_rank "$(act_risk "$_a")")" -le "$(level_rank "$LEVEL")" ] || continue
    inlist "$_a" "$SKIP" && continue
    [ -n "$ONLY" ] && ! inlist "$_a" "$ONLY" && continue
    case "$_a" in
        php-*) [ -n "$PHP_INIS" ] || continue ;;
        app-config|code-readonly) [ -s "$W/apps" ] || continue ;;
        wp-*) [ "$HAS_WP" = 1 ] || continue ;;
        upload-nophp|block-files) [ -n "$DROP$NGINX" ] || continue ;;
    esac
    CONSIDER="$CONSIDER $_a"
done
act_desc() {
    case "$1" in
        php-urlinclude) echo "allow_url_include Off in $(printf '%s ' $PHP_INIS | sed 's/ $//')" ;;
        php-errors) echo "display_errors Off, log_errors On (error pages show paths and SQL)" ;;
        php-expose) echo "expose_php Off (no PHP version in the headers)" ;;
        app-config) echo "app config files readable by the web server only (root:$WEBGROUP 640)" ;;
        wp-fileedit) echo "WordPress: no code editing from the admin panel (DISALLOW_FILE_EDIT)" ;;
        upload-nophp) echo "PHP cannot run in the upload folders (an uploaded web shell becomes plain text)" ;;
        block-files) echo "block downloading .git, .env, backups and dumps" ;;
        wp-xmlrpc) echo "block WordPress xmlrpc.php (password guessing, many tries per request)" ;;
        wp-admins) echo "check WordPress admins made in the last $DAYS days, one by one" ;;
        php-functions) echo "disable system, exec, shell_exec, passthru, proc_open, popen, pcntl_exec (stops most web shells; some apps need one)" ;;
        code-readonly) echo "the web server can no longer change the site's code (uploads and caches stay writable)" ;;
    esac
}

# ---- Questions ----------------------------------------------------------------------------
header "2/4  questions (level $LEVEL)"
CHOSEN=""
for _a in $CONSIDER; do
    _def=Y; [ "$(act_risk "$_a")" = access ] && _def=N
    inlist "$_a" "$ONLY" && _def=Y
    if cc_ask "[$(act_risk "$_a")] $(act_desc "$_a")?" "$_def" "yes, do it" "no, skip it"; then CHOSEN="$CHOSEN $_a"; fi
done
[ -n "$CHOSEN" ] || { cc_show "$C_GRN" "  [ok] Nothing chosen."; cc_csv_pretty "$ACSV" "$CC_RUN_DIR/apps.txt" 120; rm -rf "$W"; cc_finish; exit 0; }

# ---- Helpers for the fixes --------------------------------------------------------------
OKN=0
row() {
    cc_csv_row "$CSV" "$1" "$2" "$3" "$4"
    case "$4" in
        "would change") cc_show "$C_YEL" "  [~] $2: $3" ;;
        changed)        cc_show "$C_GRN" "  [+] $2: $3" ;;
        failed)         cc_show "$C_RED" "  [x] FAILED $2: $3" ;;
        refused)        cc_show "$C_YEL" "  [-] $2: $3 (protected)" ;;
        "already ok")   OKN=$((OKN + 1)) ;;
        *)              cc_show "$C_YEL" "  [*] $2: $3" ;;
    esac
    return 0
}
result() { if [ "$CC_APPLY" != 1 ]; then echo "would change"; elif [ "$1" -eq 0 ]; then echo changed; else echo failed; fi; }
reload_cmd() { if [ "$CC_INIT" = systemd ]; then printf 'systemctl reload %s 2>/dev/null || systemctl restart %s' "$1" "$1"; else printf 'service %s reload 2>/dev/null || service %s restart' "$1" "$1"; fi; }
# needs_reload SERVICE -> remembered, reloaded once after all fixes; the undo
#   line is recorded before the files change, so a revert reloads after
#   putting them back (undo lines run newest first).
needs_reload() {
    [ -n "$1" ] && [ "$CC_APPLY" = 1 ] && [ -z "$R" ] || return 0
    grep -qxF "$1" "$W/reload" 2>/dev/null && return 0
    printf '%s\n' "$1" >>"$W/reload"
    cc_undo_add "reload $1 after its config is put back" "$(reload_cmd "$1")"
}
# backed FILE -> back the file up once per run.
backed() {
    grep -qxF "$1" "$W/backed" 2>/dev/null && return 0
    cc_backup_file "$1" >/dev/null || return 1
    printf '%s\n' "$1" >>"$W/backed"
}
# svc_of_ini FILE -> the service that reads this php.ini.
svc_of_ini() { case "$1" in */fpm/*) printf '%s' "$1" | sed -n 's|^/etc/php/\([^/]*\)/fpm/.*|php\1-fpm|p' ;; *) printf '%s' "$APACHE_SVC" ;; esac; }
# php_set FIX KEY VALUE -> in every web php.ini.
php_set() {
    for _i in $PHP_INIS; do
        _f=$(P "$_i"); _cur=$(_ini_get "$_f" "$2")
        if [ "$(printf '%s' "$_cur" | tr 'A-Z' 'a-z')" = "$(printf '%s' "$3" | tr 'A-Z' 'a-z')" ]; then row "$1" "$_i" "$2 already $_cur" "already ok"; continue; fi
        needs_reload "$(svc_of_ini "$_i")"
        [ "$CC_APPLY" = 1 ] && { backed "$_f" || { row "$1" "$_i" "backup failed" failed; continue; }; }
        cc_run "$2 = $3 in $_i" _ini_set "$_f" "$2" "$3"
        row "$1" "$_i" "$2: ${_cur:-unset} -> $3" "$(result $?)"
    done
}
# drop_add FIX LINES DESC -> add a block to the Apache drop-in (made if missing).
drop_add() {
    [ -n "$DROP" ] || { row "$1" apache "no Apache drop-in folder: see nginx-ccdc.conf / add by hand" "check by hand"; return 0; }
    _df=$(P "$DROP")
    if grep -qF "# ccdc: $1" "$_df" 2>/dev/null; then row "$1" "$DROP" "already there" "already ok"; return 0; fi
    needs_reload "$APACHE_SVC"
    if [ "$CC_APPLY" = 1 ] && [ ! -f "$_df" ]; then cc_undo_add "remove $DROP (made by SV-21)" "rm -f $(cc_shquote "$_df")"; fi
    cc_run "add $1 to $DROP" sh -c '[ -f "$1" ] || printf "# Added by CCDC SV-21 (web hardening). Delete this file to undo.\n" >"$1"; printf "# ccdc: %s\n%s\n" "$2" "$3" >>"$1"' sh "$_df" "$1" "$2"
    row "$1" "$DROP" "$3" "$(result $?)"
}
# nginx_add LINES -> the nginx lines go to a file to include by hand.
nginx_add() { [ -n "$NGINX" ] && printf '%s\n' "$1" >>"$CC_RUN_DIR/nginx-ccdc.conf"; return 0; }
# PHP file name patterns that run as code.
PHPEXT='\.(php[0-9]?|phtml|phar|pht|phps)$'

do_fix() {
    case "$1" in
        php-urlinclude) php_set php-urlinclude allow_url_include Off ;;
        php-errors) php_set php-errors display_errors Off; php_set php-errors log_errors On ;;
        php-expose) php_set php-expose expose_php Off ;;
        app-config)
            while IFS='|' read -r _app _root _c _ver _ups; do
                for _f in "$_c" $( [ "$_app" = OpenCart ] && echo "$_root/admin/config.php" ) $( [ -f "$_root/.env" ] && echo "$_root/.env" ); do
                    [ -f "$_f" ] || continue
                    _ls=$(ls -ln "$_f" | awk '{ print $1 " " $3 ":" $4 }'); _m=${_ls%% *}; _og=${_ls#* }
                    _gid=$(awk -F: -v g="$WEBGROUP" '$1 == g { print $3 }' "$(P /etc/group)" 2>/dev/null)
                    case "$_m" in -rw-r-----) [ "$_og" = "0:$_gid" ] && { row app-config "${_f#"$R"}" "already root:$WEBGROUP 640" "already ok"; continue; } ;; esac
                    if [ "$CC_APPLY" = 1 ]; then
                        _om=$(ls -l "$_f" | awk '{ m = $1; u = substr(m, 2, 3); g = substr(m, 5, 3); o = substr(m, 8, 3); gsub(/-/, "", u); gsub(/-/, "", g); gsub(/-/, "", o); print "u=" u ",g=" g ",o=" o }')
                        cc_undo_add "owner and mode of ${_f#"$R"} back" "chown $_og $(cc_shquote "$_f"); chmod $_om $(cc_shquote "$_f")"
                    fi
                    cc_run "root:$WEBGROUP 640 on ${_f#"$R"}" sh -c 'chown "0:$2" "$1" && chmod 640 "$1"' sh "$_f" "${_gid:-0}"
                    row app-config "${_f#"$R"}" "$_m $_og -> -rw-r----- root:$WEBGROUP ($_app)" "$(result $?)"
                done
            done <"$W/apps" ;;
        wp-fileedit)
            awk -F'|' '$1 == "WordPress" { print $3 }' "$W/apps" >"$W/wpc"
            while IFS= read -r _c; do
                if grep -q "DISALLOW_FILE_EDIT" "$_c"; then row wp-fileedit "${_c#"$R"}" "DISALLOW_FILE_EDIT already set" "already ok"; continue; fi
                if [ "$CC_APPLY" = 1 ]; then
                    cc_undo_add "make PHP reread ${_c#"$R"}" "touch $(cc_shquote "$_c")"
                    backed "$_c" || { row wp-fileedit "${_c#"$R"}" "backup failed" failed; continue; }
                fi
                # Right after the opening <?php line.
                cc_run "DISALLOW_FILE_EDIT in ${_c#"$R"}" sh -c 'awk "NR == 1 && /<\\?php/ { print; print \"define( '"'"'DISALLOW_FILE_EDIT'"'"', true ); // CCDC SV-21\"; next } { print }" "$1" >"$1.ccnew" && cat "$1.ccnew" >"$1" && rm -f "$1.ccnew" && touch "$1"' sh "$_c"
                row wp-fileedit "${_c#"$R"}" "no theme/plugin code editing from the admin panel" "$(result $?)"
            done <"$W/wpc" ;;
        upload-nophp)
            : >"$W/updirs"
            while IFS='|' read -r _app _root _c _ver _ups; do for _u in $_ups; do printf '%s/%s\n' "${_root#"$R"}" "$_u" >>"$W/updirs"; done; done <"$W/apps"
            sed "s|^$R||" "$W/genup" >>"$W/updirs"
            sort -u "$W/updirs" -o "$W/updirs"
            [ -s "$W/updirs" ] || { row upload-nophp uploads "no upload folders found" "already ok"; return 0; }
            _blk=""
            while IFS= read -r _u; do
                _blk="$_blk<Directory \"$_u\">
    <FilesMatch \"$PHPEXT\">
        Require all denied
    </FilesMatch>
    php_admin_flag engine off
</Directory>
"
                nginx_add "location ^~ ${_u#/var/www/html} { location ~* $PHPEXT { deny all; } }"
            done <"$W/updirs"
            # php_admin_flag only exists with mod_php: wrapped so the config
            # still loads without it.
            _blk=$(printf '%s' "$_blk" | awk '/php_admin_flag/ { print "    <IfModule mod_php.c>"; print "    " $0; print "    </IfModule>"; print "    <IfModule mod_php7.c>"; print "    " $0; print "    </IfModule>"; next } { print }')
            drop_add upload-nophp "$_blk" "no PHP in: $(tr '\n' ' ' <"$W/updirs" | sed 's/ $//')" ;;
        block-files)
            drop_add block-files '<DirectoryMatch "/\.(git|svn|hg)(/|$)">
    Require all denied
</DirectoryMatch>
<FilesMatch "(^\.env|\.(bak|old|orig|save|swp|sql|sql\.gz|tar|tgz|tar\.gz|zip|7z|rar|log)|~)$">
    Require all denied
</FilesMatch>' ".git/.svn folders, .env, backups, dumps and archives cannot be downloaded"
            nginx_add 'location ~ /\.(git|svn|hg|env) { deny all; }
location ~* \.(bak|old|orig|save|swp|sql|tar|tgz|zip|7z|rar|log)$ { deny all; }' ;;
        wp-xmlrpc)
            drop_add wp-xmlrpc '<Files "xmlrpc.php">
    Require all denied
</Files>' "xmlrpc.php blocked for every WordPress site"
            nginx_add 'location = /xmlrpc.php { deny all; }' ;;
        wp-admins) wp_admins ;;
        php-functions)
            _want="system,exec,shell_exec,passthru,proc_open,popen,pcntl_exec"
            for _i in $PHP_INIS; do
                _f=$(P "$_i"); _cur=$(_ini_get "$_f" disable_functions)
                _new=$(printf '%s,%s' "$_cur" "$_want" | tr ',' '\n' | sed 's/^ *//; s/ *$//' | grep . | awk '!s[$0]++' | tr '\n' ',' | sed 's/,$//')
                if [ "$_new" = "$(printf '%s' "$_cur" | tr -d ' ')" ]; then row php-functions "$_i" "already disabled" "already ok"; continue; fi
                needs_reload "$(svc_of_ini "$_i")"
                [ "$CC_APPLY" = 1 ] && { backed "$_f" || { row php-functions "$_i" "backup failed" failed; continue; }; }
                cc_run "disable_functions in $_i" _ini_set "$_f" disable_functions "$_new"
                row php-functions "$_i" "disable_functions = $_new" "$(result $?)"
            done ;;
        code-readonly) code_readonly ;;
    esac
}

# wp_admins -> WordPress administrators made in the last DAYS days.
MYC=$(cc_first mariadb mysql); MYOPT=""
wp_admins() {
    [ -z "$R" ] || { row wp-admins wordpress "not checked under --root" "check by hand"; return 0; }
    [ -n "$MYC" ] || { row wp-admins wordpress "no mysql client" "check by hand"; return 0; }
    if [ -z "$MYOPT" ]; then
        for _try in "${MYCNF:+--defaults-extra-file=$MYCNF}" --user=root "$( [ -r /etc/mysql/debian.cnf ] && echo --defaults-file=/etc/mysql/debian.cnf )"; do
            [ -n "$_try" ] && "$MYC" "$_try" -N -B -e 'SELECT 1' >/dev/null 2>&1 && { MYOPT=$_try; break; }
        done
    fi
    [ -n "$MYOPT" ] || { row wp-admins wordpress "could not log in to the database (give --mysql-cnf)" "check by hand"; return 0; }
    awk -F'|' '$1 == "WordPress" { print $3 }' "$W/apps" >"$W/wpc"
    while IFS= read -r _c; do
        _db=$(sed -n "s/.*define( *['\"]DB_NAME['\"] *, *['\"]\([^'\"]*\)['\"].*/\1/p" "$_c" | head -n 1)
        _px=$(sed -n "s/^\$table_prefix *= *['\"]\([^'\"]*\)['\"].*/\1/p" "$_c" | head -n 1); _px=${_px:-wp_}
        case "$_db$_px" in *[!A-Za-z0-9_]*|'') row wp-admins "${_c#"$R"}" "odd database or table name: check by hand" "check by hand"; continue ;; esac
        "$MYC" "$MYOPT" -N -B -e "SELECT u.ID, u.user_login, u.user_email, u.user_registered, IF(u.user_registered > NOW() - INTERVAL $DAYS DAY, 'new', 'old') FROM \`$_db\`.\`${_px}users\` u JOIN \`$_db\`.\`${_px}usermeta\` m ON m.user_id = u.ID AND m.meta_key = '${_px}capabilities' WHERE m.meta_value LIKE '%administrator%' ORDER BY u.user_registered" 2>>"$CC_LOG" >"$W/admins" || { row wp-admins "$_db" "could not read ${_px}users (WordPress not set up yet, or no access)" "check by hand"; continue; }
        cc_show "" "    WordPress admins in $_db: $(awk -F'\t' '{ printf "%s (%s%s)  ", $2, substr($4, 1, 10), ($5 == "new" ? ", NEW" : "") }' "$W/admins")"
        awk -F'\t' '$5 == "new"' "$W/admins" >"$W/newadm"
        [ -s "$W/newadm" ] || { row wp-admins "$_db" "no admin made in the last $DAYS days" "already ok"; continue; }
        while IFS="$(printf '\t')" read -r _id _login _mail _reg _n; do
            _do=$ADMINS
            if [ -z "$_do" ]; then
                if [ "$CC_APPLY" = 1 ]; then
                    cc_choose "New WordPress admin '$_login' ($_mail, made $_reg) in $_db: keep it?" k \
                        "k=keep it (it is one of ours)" "d=demote it to subscriber (it can no longer change the site)"
                    case "$CC_CHOICE" in d) _do=demote ;; *) _do=keep ;; esac
                else _do=keep; fi
            fi
            if [ "$_do" = keep ]; then
                row wp-admins "$_login" "new admin (made $_reg, $_mail): $([ "$CC_APPLY" = 1 ] && echo kept || echo 'asked about on --apply')" "check by hand"; continue
            fi
            if ! cc_guard account "$_login"; then row wp-admins "$_login" "kept" refused; continue; fi
            _old=$("$MYC" "$MYOPT" -N -B -e "SELECT meta_value FROM \`$_db\`.\`${_px}usermeta\` WHERE user_id = $_id AND meta_key = '${_px}capabilities'" 2>/dev/null)
            _oldq=$(printf '%s' "$_old" | sed "s/'/''/g")
            _lvl=$("$MYC" "$MYOPT" -N -B -e "SELECT meta_value FROM \`$_db\`.\`${_px}usermeta\` WHERE user_id = $_id AND meta_key = '${_px}user_level'" 2>/dev/null)
            case "$_lvl" in ''|*[!0-9]*) _lvl=10 ;; esac
            cc_undo_add "make $_login an admin again" "$MYC $MYOPT -e $(cc_shquote "UPDATE \`$_db\`.\`${_px}usermeta\` SET meta_value = '$_oldq' WHERE user_id = $_id AND meta_key = '${_px}capabilities'; UPDATE \`$_db\`.\`${_px}usermeta\` SET meta_value = '$_lvl' WHERE user_id = $_id AND meta_key = '${_px}user_level'")"
            cc_run "demote $_login to subscriber" "$MYC" "$MYOPT" -e "UPDATE \`$_db\`.\`${_px}usermeta\` SET meta_value = 'a:1:{s:10:\"subscriber\";b:1;}' WHERE user_id = $_id AND meta_key = '${_px}capabilities'; UPDATE \`$_db\`.\`${_px}usermeta\` SET meta_value = '0' WHERE user_id = $_id AND meta_key = '${_px}user_level'"
            row wp-admins "$_login" "demoted to subscriber (made $_reg, $_mail)" "$(result $?)"
        done <"$W/newadm"
    done <"$W/wpc"
}

# code_readonly -> the site's files owned by root (group: the web server's
#   group, readable); upload, cache and session folders stay owned by the web
#   server.  The owner of every file is saved first for the undo.
code_readonly() {
    [ -n "$WEBUSER" ] || { row code-readonly web "no web server account found" "check by hand"; return 0; }
    _wuid=$(awk -F: -v u="$WEBUSER" '$1 == u { print $3 }' "$(P /etc/passwd)")
    while IFS='|' read -r _app _root _c _ver _ups; do
        # Upload, cache and temp folders are left exactly as they are.
        _keep=""; for _u in $_ups wp-content/cache wp-content/upgrade var cache tmp storage system/storage; do [ -d "$_root/$_u" ] && _keep="$_keep $_u"; done
        find "$_root" -xdev -user "$_wuid" -print 2>/dev/null | awk -v r="$_root" -v k="$_keep" '
            BEGIN { n = split(k, ks, " ") }
            { for (i = 1; i <= n; i++) { d = r "/" ks[i]; if ($0 == d || index($0, d "/") == 1) next }; print }' >"$W/own"
        _n=$(grep -c . "$W/own")
        [ "$_n" -gt 0 ] || { row code-readonly "${_root#"$R"}" "the web server owns no code here" "already ok"; continue; }
        if [ "$CC_APPLY" = 1 ]; then
            _own="$CC_RUN_DIR/owners-$(printf '%s' "${_root#"$R"}" | tr '/' '_').txt"
            while IFS= read -r _p; do printf '%s\t%s\n' "$(ls -lnd "$_p" | awk '{ print $3 ":" $4 }')" "$_p"; done <"$W/own" >"$_own"
            cc_undo_add "owners under ${_root#"$R"} back ($_n files)" "while IFS=\$(printf '\\t') read -r o p; do chown -h \"\$o\" \"\$p\"; done < $(cc_shquote "$_own")"
        fi
        cc_run "root owns the code in ${_root#"$R"}" sh -c 'while IFS= read -r p; do chown -h 0 "$p"; done <"$1"' sh "$W/own"
        row code-readonly "${_root#"$R"}" "$_n file(s) no longer owned by $WEBUSER; left writable: ${_keep# }" "$(result $?)"
    done <"$W/apps"
}

run_all() {
    _q=$CC_QUIET; CC_QUIET=1
    for _a in $CHOSEN; do
        cc_show "$C_CYN" "  -- $_a [$(act_risk "$_a")]"
        do_fix "$_a"
        [ "$OKN" -gt 0 ] && cc_show "$C_GRN" "  [ok] $OKN already right"; OKN=0
    done
    CC_QUIET=$_q
}

# ---- Plan -------------------------------------------------------------------------------
header "3/4  plan (dry run: nothing is changed yet)"
CSV=$(cc_csv_new plan "fix,item,detail,status")
_real=$CC_APPLY; CC_APPLY=0
: >"$W/reload"; : >"$W/backed"; : >"$CC_RUN_DIR/nginx-ccdc.conf"
run_all
CC_APPLY=$_real
NCH=$(awk "$CC_AWK_CSV"'NR > 1 { csvsplit($0, f); if (f[4] == "would change") n++ } END { print n + 0 }' "$CSV")
cc_csv_pretty "$CSV" "$CC_RUN_DIR/plan.txt" 110

# ---- Site check ---------------------------------------------------------------------------
# The pages to check: --url, else the home page and each app's folder under it.
if [ -z "$URLS" ]; then
    URLS="http://127.0.0.1/"
    while IFS='|' read -r _app _root _c _ver _ups; do
        case "${_root#"$R"}" in /var/www/html/*) URLS="$URLS http://127.0.0.1/${_root#"$R"/var/www/html/}/" ;; esac
    done <"$W/apps"
fi
# page URL -> "STATUS ERRFLAG" (ERRFLAG 1 when the page shows a PHP or database error).
page() {
    _s=""
    if cc_have curl; then _s=$(curl -s -m 10 -o "$W/page" -w '%{http_code}' "$1" 2>/dev/null)
    elif cc_have wget; then _s=$(wget -q -S -O "$W/page" -T 10 "$1" 2>&1 | awk '/HTTP\// { c = $2 } END { print c }'); fi
    _e=0; grep -qiE 'Fatal error|Parse error|Warning:.*on line|error establishing a database connection|SQLSTATE\[|has been disabled for security reasons' "$W/page" 2>/dev/null && _e=1
    printf '%s %s' "${_s:-000}" "$_e"
}
site_before() { : >"$W/site0"; for _u in $URLS; do printf '%s %s\n' "$_u" "$(page "$_u")" >>"$W/site0"; done; }
# site_worse -> lists pages that worked before and not now (tries for 10 s).
site_worse() {
    _t=0
    while :; do
        sleep 2; : >"$W/worse"
        while read -r _u _s0 _e0; do
            _pg=$(page "$_u"); _s1=${_pg% *}; _e1=${_pg#* }
            _w0=0; case "$_s0" in [23]??) _w0=1 ;; esac; _w1=0; case "$_s1" in [23]??) _w1=1 ;; esac
            { [ "$_w0" = 1 ] && [ "$_w1" = 0 ]; } || { [ "$_e1" = 1 ] && [ "$_e0" = 0 ]; } && printf '%s %s -> %s%s\n' "$_u" "$_s0" "$_s1" "$([ "$_e1" = 1 ] && echo ' (error on the page)')" >>"$W/worse"
        done <"$W/site0"
        _t=$((_t + 1)); [ ! -s "$W/worse" ] || [ "$_t" -ge 5 ] && break
    done
    [ -s "$W/worse" ]
}
config_test() {
    case "$1" in
        apache2) cc_have apache2ctl && apache2ctl -t ;;
        httpd) cc_have httpd && httpd -t ;;
        php*-fpm) _v=${1#php}; _v=${_v%-fpm}; _b=$(cc_first "php-fpm$_v" php-fpm); [ -z "$_b" ] || "$_b" -t ;;
        *) return 0 ;;
    esac
}

# ---- Apply --------------------------------------------------------------------------------
header "4/4  apply"
APPLIED=0; TIMER_ON=0; SITEFAIL=0
CANAPPLY=0; [ "$CC_APPLY" = 1 ] && { [ -n "$R" ] || cc_is_root; } && CANAPPLY=1
[ "$CC_APPLY" = 1 ] && [ "$CANAPPLY" = 0 ] && cc_show "$C_YEL" "  [!] not root: showing the plan only"
if [ "$NCH" -eq 0 ]; then
    cc_show "$C_GRN" "  [ok] Nothing to change."
elif [ "$CANAPPLY" = 0 ]; then
    cc_show "$C_GRY" "  $NCH change(s) planned. Dry run: nothing was changed. Back up first (SV-15), then run again with --apply."
elif ! cc_ask "Apply these $NCH change(s)?" Y "yes, apply them (a revert timer undoes them unless you confirm from a NEW session)" "no, change nothing"; then
    cc_show "$C_GRY" "  Not applied. The plan is in $CC_RUN_DIR/plan.txt"
else
    [ -z "$R" ] && site_before
    U0=$(grep -c . "$CC_UNDO" 2>/dev/null)
    if [ "$NOTIMER" != 1 ] && [ -z "$R" ]; then
        cc_timer_start "$TIMER"; TIMER_ON=1
        cc_show "$C_YEL" "  [*] Revert timer started: everything is undone in $((TIMER / 60)):$(printf '%02d' $((TIMER % 60))) unless you keep it at the end."
    fi
    APPLIED=1
    : >"$W/reload"; : >"$W/backed"; : >"$CC_RUN_DIR/nginx-ccdc.conf"
    CSV=$(cc_csv_new changes "fix,item,detail,status")
    # shellcheck disable=SC2034  # read by cc_finish
    CC_N_WOULD=0
    run_all
    if [ -z "$R" ] && [ -s "$W/reload" ]; then
        while IFS= read -r _s; do
            [ -n "$_s" ] || continue
            if ! config_test "$_s" >>"$CC_LOG" 2>&1; then cc_show "$C_RED" "  [x] $_s: its config test FAILED"; SITEFAIL=1; continue; fi
            sh -c "$(reload_cmd "$_s")" >>"$CC_LOG" 2>&1 && cc_show "$C_GRN" "  [+] $_s reloaded" || { cc_show "$C_RED" "  [x] $_s did not reload"; SITEFAIL=1; }
        done <"$W/reload"
    fi
    if [ -z "$R" ] && [ "$SITEFAIL" = 0 ]; then
        if site_worse; then
            SITEFAIL=1
            while IFS= read -r _l; do cc_show "$C_RED" "  [x] worse now: $_l"; done <"$W/worse"
        else
            while read -r _u _s0 _e0; do cc_show "$C_GRN" "  [+] $_u still answers ($(page "$_u" | cut -d' ' -f1))"; done <"$W/site0"
        fi
    fi
    if [ "$SITEFAIL" = 1 ]; then
        cc_show "$C_RED" "  Putting everything back now ..."
        awk -F'\t' -v n="${U0:-0}" 'NR > n { l[NR] = $4 } END { for (i = NR; i > n; i--) print l[i] }' "$CC_UNDO" >"$W/undo-now"
        while IFS= read -r _cmd; do sh -c "$_cmd" >>"$CC_LOG" 2>&1 || cc_show "$C_RED" "  [x] could not undo: $_cmd"; done <"$W/undo-now"
        [ "$TIMER_ON" = 1 ] && cc_timer_cancel 2>/dev/null; TIMER_ON=0
        sleep 2; while read -r _u _s0 _e0; do cc_show "" "  after the revert $_u answers $(page "$_u" | cut -d' ' -f1)"; done <"$W/site0"
    fi
    cc_csv_pretty "$CSV" "$CC_RUN_DIR/changes.txt" 110
fi
[ -s "$CC_RUN_DIR/nginx-ccdc.conf" ] || rm -f "$CC_RUN_DIR/nginx-ccdc.conf"
if [ "$TIMER_ON" = 1 ]; then header "KEEP OR REVERT"; cc_timer_finish || true; fi

# ---- Summary ----------------------------------------------------------------------------
cc_csv_pretty "$ACSV" "$CC_RUN_DIR/apps.txt" 120
{
    printf '==========[ summary ]==========\n'
    printf 'SV-21 PHP and web app hardening | host %s | level %s | %s\n' "$CC_HOST" "$LEVEL" "$([ "$APPLIED" = 1 ] && { [ "$SITEFAIL" = 1 ] && echo 'APPLIED, then PUT BACK (the site broke)' || echo APPLIED; } || echo 'DRY RUN - nothing changed')"
    printf 'Fixes chosen:%s\n' "$CHOSEN"
    awk "$CC_AWK_CSV"'NR > 1 { csvsplit($0, f); if (f[4] != "already ok") printf "  %-13s %-14s %-40s %s\n", toupper(f[4]), f[1], substr(f[2], 1, 40), f[3] }' "$CSV" | head -n 60
    [ -f "$CC_RUN_DIR/nginx-ccdc.conf" ] && printf '\nnginx: include %s inside each server { } block, then nginx -t and reload.\n' "$CC_RUN_DIR/nginx-ccdc.conf"
    printf '\nApps: %s/apps.txt\n' "$CC_RUN_DIR"
    [ "$APPLIED" = 1 ] && [ -f "$CC_RUN_DIR/revert.sh" ] && printf 'Undo this run: sh %s/revert.sh --force\n' "$CC_RUN_DIR"
    case " $CHOSEN " in *" php-functions "*) printf 'php-functions: click through the store (checkout, image upload, mail): a broken feature shows "has been disabled for security reasons".\n' ;; esac
} >"$CC_RUN_DIR/summary.txt"
cc_show "" ""
while IFS= read -r _l; do
    case "$_l" in ==*|SV-21*) cc_show "$C_CYN" "$_l" ;; *CHANGED*) cc_show "$C_GRN" "$_l" ;; *FAILED*|*'PUT BACK'*) cc_show "$C_RED" "$_l" ;; *'WOULD CHANGE'*|*REFUSED*|*'CHECK BY HAND'*) cc_show "$C_YEL" "$_l" ;; *) cc_show "" "$_l" ;; esac
done <"$CC_RUN_DIR/summary.txt"
rm -rf "$W"
cc_finish
