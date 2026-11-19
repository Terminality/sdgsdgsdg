#!/bin/sh
# =============================================================================
# ID:       LX-44
# NAME:     AppArmor confinement for the services
# ROLE:     Linux  (wave 2, after the services are hardened and backed up)
# KIND:     changes - dry run unless --apply
# VERSION:  1.0.0
#
# PURPOSE
#   AppArmor gives a program a list of what it may touch, and the kernel
#   holds it to that list even when the program is hacked.  With Apache
#   confined, a web shell inside it cannot run bash, read /root or write
#   outside the upload folders.  This puts the web server, PHP-FPM and the
#   database under AppArmor in three safe steps:
#
#     1 complain  the profile is loaded, NOTHING is blocked: AppArmor only
#                 logs what it would have blocked.  Use the site normally.
#     2 learn     the script reads those log lines and sorts them:
#                   normal       reads, libraries, network, capabilities -
#                                offered to add to the profile
#                   web code     writes into the site's own files - asked
#                                on their own (an upload or a web shell?)
#                   programs     programs it ran - NEVER added by the
#                                script (a web shell runs sh, curl, nc ...):
#                                listed for you
#                   secrets      /etc/shadow, keys, /root, writes into /etc
#                                or /usr, sys_module ... - NEVER added: [!]
#     3 enforce   when the log is clean: everything not in the profile is
#                 blocked.  The service is checked right after; if it
#                 stopped answering it goes back to complain on its own.
#
#   Profiles: CCDC's own for apache2, nginx, php-fpm and mariadb/mysql
#   (written to /etc/apparmor.d/ccdc-*), or the one a package already ships
#   (php-fpm, mysqld) - then only its mode is changed.  Mail (Postfix,
#   Dovecot) runs many helper programs: not covered here.
#   On Red Hat / Rocky / CentOS (SELinux, not AppArmor) the SELinux mode is
#   shown instead.
#
#   QUESTIONS (Enter takes the default in capitals; a flag answers each):
#     each service, by its state:
#       unconfined   [c]omplain (default) / [e]nforce now / [k]eep
#       complain     [l]earn / [e]nforce / [c] stay in complain
#       enforced     [k]eep (default) / [c] back to complain
#     loaded but the service runs outside it   [r]estart it / [k]eep
#     add the normal log lines? / the writes into web code?   (yes / no)
#     restart the service so it runs under its profile?        (yes / no)
#     apply?                                                   --apply
#
# USAGE
#   sudo sh LX-44-apparmor.sh                                  status + dry run
#   sudo sh LX-44-apparmor.sh --protected p.csv --apply        step by step
#   sudo sh LX-44-apparmor.sh --protected p.csv --apply --batch   (complain everything; learn and enforce never happen in --batch)
#
# OPTIONS
#   --apply            make the changes (without it, dry run only)
#   --services a,b     only these: apache2 nginx php-fpm mysql
#   --writable DIR     a folder the web server may write (repeatable;
#                      upload / cache folders of the apps are found anyway)
#   --url URL          the page checked after enforcing (default http://127.0.0.1/)
#   --timer SECONDS    revert countdown for enforce (default 120); --no-timer
#   --root DIR         treat DIR as / (tests): nothing loaded or restarted
#   --no-color         no colours
#   --help             this text plus the common options
#
# OUTPUTS  (under --out, in apparmor-N/)
#   output.txt, status.txt, plan.txt, summary.txt, run.txt, revert.sh
#   learned-NAME.txt   the log lines sorted for each profile
#
# DEPENDS ON
#   apparmor_parser (the apparmor package: installed by default on Ubuntu
#   and Debian).  apparmor-utils is NOT needed.  CCDC_AA_PARSER may name a
#   stand-in (tests).
#
# TESTED ON
#   Profiles checked with AppArmor 4.0's own parser; the questions, the
#   learning and the undo on a fake root, under dash, bash, busybox sh,
#   ksh93, mksh and yash with gawk, mawk and busybox awk.  NOT yet run on a
#   kernel with AppArmor switched on (the test box is a container): try the
#   whole complain - learn - enforce cycle on a practice VM first.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - Leave a service in complain while you use the site (log in, buy,
#     upload) - every page that is never visited is a rule never learned.
#   - Enforcing too early breaks features quietly: the home page loads but
#     image upload fails.  The check catches the home page only.
#   - A restart is needed for a running service to pick up a new profile.
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
LX-44 AppArmor confinement - web server, PHP and database: complain, learn, enforce
  sudo sh LX-44-apparmor.sh                             status + dry run
  sudo sh LX-44-apparmor.sh --protected p.csv --apply   step by step

  --apply            make the changes (without it, dry run only)
  --services a,b     only these: apache2 nginx php-fpm mysql
  --writable DIR     a folder the web server may write (repeatable)
  --url URL          page checked after enforcing (default http://127.0.0.1/)
  --timer SECONDS    revert countdown for enforce (default 120); --no-timer
  --root DIR         treat DIR as / (tests)
  --no-color         no colours
  --help             show this text
USAGE
    cc_usage_common
}

NL='
'
ONLY=""; WRITABLE=""; URL="http://127.0.0.1/"; TIMER=120; NOTIMER=0; R=""; COLOR=1
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --apply)    CC_APPLY=1; shift ;;
        --services) [ $# -ge 2 ] || cc_die 2 "--services needs a list"; ONLY="$ONLY,$2"; shift 2 ;;
        --writable) [ $# -ge 2 ] || cc_die 2 "--writable needs a folder"; WRITABLE="$WRITABLE$2$NL"; shift 2 ;;
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
for _s in $(printf '%s' "$ONLY" | tr ',' ' '); do case "$_s" in apache2|nginx|php-fpm|mysql) ;; *) cc_die 2 "--services: apache2, nginx, php-fpm or mysql" ;; esac; done
printf '%s' "$WRITABLE" | grep -q '[^A-Za-z0-9/._@*{},-]' && cc_die 2 "--writable: a plain folder path"

cc_init "LX-44" "AppArmor confinement" changes
cc_detect_os
# shellcheck disable=SC2034  # read by cc_color_init
[ "$COLOR" = 1 ] || CC_NOCOLOR=1
cc_color_init
cc_use_numbered_dir apparmor
rmdir "$CC_RUN_DIR/raw" 2>/dev/null
OUTF="$CC_RUN_DIR/output.txt"
grep -v '\[NOTE\]\|\[DEBUG\]' "$CC_LOG" >"$OUTF" 2>/dev/null || : >"$OUTF"
# shellcheck disable=SC2034  # CC_TEE is read by the library's log functions
CC_TEE=$OUTF
W="$CC_RUN_DIR/.work"; mkdir -p "$W"
header() { cc_show "" ""; cc_show "$C_CYN" "==========[ $1 ]=========="; }
P() { printf '%s%s' "$R" "$1"; }
AAD=$(P /etc/apparmor.d); STATE=$(P /var/lib/ccdc/apparmor)
# A full path: the revert timer may run the undo lines with a short PATH.
PARSER=${CCDC_AA_PARSER:-$(cc_which apparmor_parser 2>/dev/null || echo apparmor_parser)}

cc_show "$C_CYN" "LX-44 AppArmor confinement | host $CC_HOST | results in $CC_RUN_DIR"
cc_show "" "Legend: ${C_RED}[!]${C_OFF} fix now   ${C_YEL}[*]${C_OFF} look at it   ${C_GRN}[ok]${C_OFF} fine   ${C_YEL}[~] would change${C_OFF}   ${C_GRN}[+] changed${C_OFF}   ${C_RED}[x] failed${C_OFF}"
[ -n "$R" ] && cc_show "$C_GRY" "Acting on $R as if it were / (nothing loaded or restarted)"

# ---- Is AppArmor there? ---------------------------------------------------------------------
header "1/5  AppArmor on this box"
AAON=n; [ "$(cat "$(P /sys/module/apparmor/parameters/enabled)" 2>/dev/null)" = Y ] && AAON=y
if [ "$AAON" != y ]; then
    if [ -z "$R" ] && cc_have getenforce; then
        _se=$(getenforce 2>/dev/null)
        cc_show "$([ "$_se" = Enforcing ] && printf '%s' "$C_GRN" || printf '%s' "$C_RED")" "  This box uses SELinux, not AppArmor: SELinux is $_se."
        [ "$_se" = Enforcing ] || cc_show "" "  Turn it on: setenforce 1 (now) and SELINUX=enforcing in /etc/selinux/config (after a reboot). Test the services after."
    else
        cc_show "$C_YEL" "  [*] AppArmor is not switched on in this kernel (a container, or apparmor=0 at boot). Nothing to do here."
    fi
    rm -rf "$W"; cc_finish; exit 0
fi
cc_have "$PARSER" || [ -x "$PARSER" ] || { cc_show "$C_RED" "  [x] apparmor_parser is missing: apt-get install apparmor"; rm -rf "$W"; cc_finish; exit 3; }
_np=$(grep -c . "$(P /sys/kernel/security/apparmor/profiles)" 2>/dev/null)
cc_show "$C_GRN" "  [ok] AppArmor is on ($_np profiles loaded)"

# ---- The services ---------------------------------------------------------------------------
# kind|binaries (first found)|our profile name|service names|check
cat >"$W/svcs" <<'EOF'
apache2|/usr/sbin/apache2|ccdc-apache2|apache2|http
nginx|/usr/sbin/nginx|ccdc-nginx|nginx|http
php-fpm|/usr/sbin/php-fpm8.4 /usr/sbin/php-fpm8.3 /usr/sbin/php-fpm8.2 /usr/sbin/php-fpm8.1 /usr/sbin/php-fpm8.0 /usr/sbin/php-fpm7.4 /usr/sbin/php-fpm|ccdc-php-fpm|php8.4-fpm php8.3-fpm php8.2-fpm php8.1-fpm php8.0-fpm php7.4-fpm php-fpm|http
mysql|/usr/sbin/mariadbd /usr/sbin/mysqld|ccdc-mysqld|mariadb mysql|mysql
EOF
# The writable folders for the web: upload, cache and session folders of the apps.
{
    printf '%s' "$WRITABLE"
    for _d in /var/www /srv/www /srv/http; do
        [ -d "$(P "$_d")" ] || continue
        find "$(P "$_d")" -maxdepth 5 -type d \( -path '*/wp-content/uploads' -o -path '*/wp-content/cache' -o -path '*/wp-content/upgrade' \
            -o -path '*/img' -o -path '*/upload' -o -path '*/uploads' -o -path '*/cache' -o -path '*/var/cache' -o -path '*/var/logs' -o -path '*/tmp' \
            -o -path '*/system/storage' -o -path '*/image/cache' -o -path '*/sites/default/files' -o -path '*/pub/media' \) 2>/dev/null | sed "s|^$R||"
    done
} | grep . | sort -u >"$W/writable"
# kernel_mode PROFILE -> enforce | complain | (nothing: not loaded)
kernel_mode() { awk -v p="$1" '{ n = $0; sub(/ \(.*$/, "", n) } n == p { m = $NF; gsub(/[()]/, "", m); print m; exit }' "$(P /sys/kernel/security/apparmor/profiles)" 2>/dev/null; }
# proc_label KIND -> the AppArmor label of the running service ("unconfined", "ccdc-apache2 (complain)")
proc_label() {
    if [ -n "$R" ]; then cat "$R/run/ccdc-test/$1.label" 2>/dev/null; return; fi
    _pid=$(pgrep -o -x "$(basename "$2")" 2>/dev/null)
    [ -n "$_pid" ] || return 0
    cat "/proc/$_pid/attr/apparmor/current" 2>/dev/null || cat "/proc/$_pid/attr/current" 2>/dev/null
}
# packaged BIN -> "FILE|NAME" of a profile a package ships for BIN (not ours):
# "profile NAME /path {" or "/path {", the path may end in * (php-fpm*).
packaged() {
    for _pf in "$AAD"/*; do
        [ -f "$_pf" ] || continue
        case "$_pf" in */ccdc-*|*.dpkg-*|*~) continue ;; esac
        awk -v b="$1" -v f="$_pf" '
            { sub(/^[ \t]+/, "") }
            /^profile[ \t]/ { n = $2; a = $3 } /^\// { n = $1; a = $1 }
            n != "" && a ~ /^\// {
                if (a == b || (a ~ /\*$/ && index(b, substr(a, 1, length(a) - 1)) == 1)) { print f "|" n; exit }
                n = ""
            }' "$_pf"
    done | head -n 1
}

# ---- The profiles -----------------------------------------------------------------------------
# write_profile KIND BIN NAME MODE -> the profile text on stdout
write_profile() {
    _flags=""; [ "$4" = complain ] && _flags=" flags=(complain)"  # posix-ok: AppArmor text, not an array
    printf '# Written by CCDC LX-44 (%s).  Learned rules go in local/%s.\n# Delete this file and run "apparmor_parser -R" on it to remove.\nabi <abi/3.0>,\ninclude <tunables/global>\n\nprofile %s %s%s {\n' "$1" "$3" "$3" "$2" "$_flags"
    printf '  include <abstractions/base>\n  include <abstractions/nameservice>\n  include <abstractions/openssl>\n  include <abstractions/ssl_certs>\n'
    case "$1" in
        apache2|nginx|php-fpm)
            printf '  include <abstractions/ssl_keys>\n'
            [ "$1" = apache2 ] && printf '  include <abstractions/apache2-common>\n  include <abstractions/php>\n'
            [ "$1" = php-fpm ] && printf '  include <abstractions/php>\n'
            printf '  capability dac_override,\n  capability dac_read_search,\n  capability net_bind_service,\n  capability setgid,\n  capability setuid,\n  capability chown,\n  capability fowner,\n  capability kill,\n  capability sys_resource,\n'
            printf '  network inet stream,\n  network inet6 stream,\n  network inet dgram,\n  network inet6 dgram,\n  network unix stream,\n  network unix dgram,\n  network netlink raw,\n'
            printf '  signal (send, receive) peer=%s,\n\n' "$3"
            printf '  %s mrix,\n' "$2"
            case "$1" in
                apache2) printf '  /usr/lib/apache2/** mr,\n  /etc/apache2/** r,\n  /var/log/apache2/** rw,\n  /{,var/}run/apache2/** rwk,\n  /var/lib/apache2/** rwk,\n  /var/cache/apache2/** rwk,\n' ;;
                nginx) printf '  /usr/lib/nginx/** mr,\n  /usr/share/nginx/** r,\n  /etc/nginx/** r,\n  /var/log/nginx/** rw,\n  /var/lib/nginx/** rwk,\n  /{,var/}run/nginx.pid rw,\n  /{,var/}run/php/*.sock rw,\n' ;;
                php-fpm) printf '  /{,var/}run/php/** rwk,\n  /var/log/php*-fpm.log rw,\n' ;;
            esac
            printf '  /usr/lib/php/** mr,\n  /etc/php/** r,\n  /etc/mime.types r,\n  /usr/share/** r,\n  /var/lib/php/** rwk,\n  /tmp/** rwk,\n  /var/tmp/** rwk,\n'
            printf '  @{PROC}/@{pid}/** r,\n  @{PROC}/sys/kernel/random/* r,\n  /sys/devices/system/cpu/** r,\n\n'
            printf '  # The sites: read only.\n  /var/www/ r,\n  /var/www/** r,\n  /srv/** r,\n  /usr/share/roundcube/** r,\n  /etc/roundcube/** r,\n'
            printf '  /var/lib/roundcube/** rwk,\n  /var/log/roundcube/** rw,\n'
            printf '  # PHP mail() through Postfix.\n  /usr/sbin/sendmail ix,\n  /usr/sbin/postdrop ix,\n  /etc/postfix/** r,\n  /var/spool/postfix/maildrop/** rw,\n  /var/spool/postfix/public/pickup w,\n'
            printf '  # Folders the site may write (uploads, caches).\n'
            if [ -s "$W/writable" ]; then while IFS= read -r _wd; do printf '  %s/ rw,\n  %s/** rwk,\n' "$_wd" "$_wd"; done <"$W/writable"; else printf '  # (none found)\n'; fi
            printf '\n  # Not allowed, on purpose: running a shell or a download tool.\n  # That is what a web shell does; the learning step never adds it.\n' ;;
        mysql)
            printf '  capability dac_override,\n  capability setgid,\n  capability setuid,\n  capability sys_resource,\n  capability sys_nice,\n  capability ipc_lock,\n  capability chown,\n'
            printf '  network inet stream,\n  network inet6 stream,\n  network unix stream,\n  network unix dgram,\n  network netlink raw,\n\n'
            printf '  %s mr,\n  /etc/mysql/** r,\n  /usr/share/mysql/** r,\n  /usr/share/mariadb/** r,\n  /usr/lib/mysql/plugin/* mr,\n' "$2"
            printf '  /var/lib/mysql/ r,\n  /var/lib/mysql/** rwk,\n  /var/log/mysql/** rw,\n  /{,var/}run/mysqld/** rwk,\n  /tmp/** rwk,\n'
            printf '  @{PROC}/@{pid}/** r,\n  @{PROC}/sys/kernel/random/* r,\n  /sys/devices/system/cpu/** r,\n  /sys/devices/system/node/** r,\n  /sys/fs/cgroup/** r,\n  @{PROC}/sys/fs/** r,\n' ;;
    esac
    printf '\n  include if exists <local/%s>\n}\n' "$3"
}

# ---- Log lines for a profile ----------------------------------------------------------------
# events PROFILE SINCE-EPOCH -> "KIND|op|name|mask|extra" lines (KIND: ALLOWED/DENIED)
events() {
    for _l in "$(P /var/log/audit/audit.log)" "$(P /var/log/kern.log)" "$(P /var/log/syslog)"; do [ -r "$_l" ] && cat "$_l"; done 2>/dev/null >"$W/logs"
    grep -q 'apparmor=' "$W/logs" 2>/dev/null || { [ -z "$R" ] && cc_have journalctl && journalctl -k --no-pager -o cat 2>/dev/null >>"$W/logs"; }
    awk -v p="$1" -v since="${2:-0}" '
        /apparmor="(ALLOWED|DENIED)"/ && index($0, "profile=\"" p "\"") {
            t = 0; if (match($0, /audit\([0-9]+/)) t = substr($0, RSTART + 6, RLENGTH - 6) + 0
            if (t && t < since) next
            k = ($0 ~ /apparmor="ALLOWED"/) ? "ALLOWED" : "DENIED"
            op = v("operation"); nm = v("name"); mk = v("requested_mask"); x = ""
            if (op == "capable") x = v("capname")
            else if (op ~ /^(create|connect|bind|listen|sendmsg|recvmsg)$/) x = v("family") " " v("sock_type")
            print k "|" op "|" nm "|" mk "|" x
        }
        function v(key,   r) { if (match($0, key "=\"[^\"]*\"")) { r = substr($0, RSTART + length(key) + 2, RLENGTH - length(key) - 3); return r }  # awk, not shell: posix-ok
            if (match($0, key "=[^ ]*")) return substr($0, RSTART + length(key) + 1, RLENGTH - length(key) - 1); return "" }' "$W/logs" | sort -u
}
# sort_events FILE -> $W/normal (rules), $W/webw (writes into the sites),
# $W/progs (programs run), $W/bad (secrets and system files: never added)
sort_events() {
    : >"$W/normal"; : >"$W/webw"; : >"$W/progs"; : >"$W/bad"
    while IFS='|' read -r _k _op _nm _mk _x; do
        case "$_op" in
            exec) printf '%s\n' "$_nm" >>"$W/progs" ;;
            capable) case "$_x" in sys_admin|sys_module|sys_rawio|sys_boot|mac_admin|mac_override|bpf|perfmon) printf 'capability %s\n' "$_x" >>"$W/bad" ;; ?*) printf 'capability %s,\n' "$_x" >>"$W/normal" ;; esac ;;
            create|connect|bind|listen|sendmsg|recvmsg) case "$_x" in *raw*|*packet*) printf 'network %s\n' "$_x" >>"$W/bad" ;; ?*) printf 'network %s,\n' "$_x" >>"$W/normal" ;; esac ;;
            *)  [ -n "$_nm" ] || continue
                _m=$(printf '%s' "$_mk" | tr -d 'xcd' ); printf '%s' "$_mk" | grep -q '[cd]' && _m="${_m}w"
                _m=$(printf '%s' "$_m" | fold -w1 | sort -u | tr -d '\n'); [ -n "$_m" ] || _m=r
                case "$_m" in *w*) _m=$(printf '%s' "$_m" | tr -d a) ;; esac  # w and a cannot be in one rule
                # AppArmor reads * ? [ ] { } in a path as patterns: escape them.
                _rule=$(printf '"%s" %s,' "$(printf '%s' "$_nm" | sed 's/[][*?{}]/\\&/g')" "$_m")
                case "$_nm:$_m" in
                    /var/www/*:*w*|/srv/*:*w*|/usr/share/roundcube/*:*w*) printf '%s\n' "$_rule" >>"$W/webw" ;;
                    # Secrets and system files: what an attacker in the web server goes for.
                    /etc/shadow*|/etc/gshadow*|/etc/sudoers*|/etc/ssh/*key*|/root/*|/home/*/.ssh/*|/proc/*/mem:*|/dev/mem:*|/dev/kmem:*|\
                    /etc/*:*w*|/usr/*:*w*|/bin/*:*w*|/sbin/*:*w*|/lib/*:*w*|/var/spool/cron/*:*w*|/boot/*:*w*) printf '%s %s\n' "$_nm" "$_m" >>"$W/bad" ;;
                    *) printf '%s\n' "$_rule" >>"$W/normal" ;;
                esac ;;
        esac
    done <"$1"
    for _f in normal webw progs bad; do sort -u "$W/$_f" -o "$W/$_f"; done
}
SUSPECT='/(sh|bash|dash|zsh|ksh|mksh|ash|busybox|nc|ncat|netcat|socat|curl|wget|python[0-9.]*|perl|ruby|php[0-9.]*|telnet|ssh|scp|base64|chmod|crontab|at)$'

# ---- Status and questions ---------------------------------------------------------------------
header "2/5  services"
NOW=$(date +%s)
mkdir -p "$W/plans"
: >"$W/plan"; printf '%-9s %-11s %-8s %s\n' service mode profile name >"$W/status"
_seen=0
while IFS='|' read -r _kind _bins _name _units _chk; do
    [ -n "$ONLY" ] && ! printf ',%s,' "$ONLY" | grep -q ",$_kind," && continue
    _bin=""; for _b in $_bins; do [ -x "$(P "$_b")" ] && { _bin=$_b; break; }; done
    [ -n "$_bin" ] || continue
    _seen=1
    _pk=$(packaged "$_bin"); _pname=$_name; _src=ccdc
    [ -n "$_pk" ] && { _src=package; _pname=${_pk#*"|"}; }
    _km=$(kernel_mode "$_pname"); _lab=$(proc_label "$_kind" "$_bin")
    _state=unconfined
    case "$_km" in complain) _state=complain ;; enforce) _state=enforce ;; esac
    _since=$(cat "$STATE/$_pname.$_state" 2>/dev/null)
    printf '%-9s %-11s %-8s %s\n' "$_kind" "$_state" "$_src" "$_pname" >>"$W/status"
    cc_show "" ""
    cc_show "$C_CYN" "  $_kind ($_bin): $_state$([ "$_src" = package ] && echo ", the package's profile $_pname" || echo ", CCDC profile $_name")$([ -n "$_lab" ] && echo "; the running service: $_lab")"
    _ans=""
    # Loaded, but the running service started before it: AppArmor neither logs
    # nor blocks anything for it until it is restarted.
    _stale=n; _rs=n
    if [ "$_state" != unconfined ] && [ "$_lab" = unconfined ]; then
        _stale=y
        cc_show "$C_RED" "  [!] the running $_kind started before its profile was loaded: nothing is logged or blocked until it restarts"
        cc_choose "$_kind runs outside its profile: what now?" r "r=restart it now so it runs under the profile" "k=leave it (restart it later yourself)"
        [ "$CC_CHOICE" = r ] && _rs=y
        printf '%-9s %-11s %-8s %s\n' "" "(running outside it)" "" "" >>"$W/status"
    fi
    case "$_state" in
        unconfined)
            cc_show "$C_YEL" "  [*] nothing stops a hacked $_kind from touching the rest of the box"
            cc_choose "$_kind is not confined: what now?" c \
                "c=complain: load the profile in learning mode - nothing is blocked, AppArmor only logs" \
                "e=enforce now: block everything not in the profile (do the learning first)" \
                "k=keep it as it is"
            _ans=$CC_CHOICE ;;
        complain)
            events "$_pname" "${_since:-0}" >"$W/ev.$_kind"
            sort_events "$W/ev.$_kind"
            _nn=$(grep -c . "$W/normal"); _nw=$(grep -c . "$W/webw"); _np=$(grep -c . "$W/progs")
            _bad=$(grep -E "$SUSPECT" "$W/progs" | tr '\n' ' ')
            _age=""; [ -n "$_since" ] && _age=" for $(( (NOW - _since) / 60 )) min"
            { printf '%s (%s) - sorted log lines\n\nnormal (offered):\n' "$_kind" "$_pname"; sed 's/^/  /' "$W/normal"; printf '\nwrites into the sites (asked on their own):\n'; sed 's/^/  /' "$W/webw"; printf '\nprograms it ran (never added by the script):\n'; sed 's/^/  /' "$W/progs"
              printf '\nsecrets and system files, dangerous capabilities (never added):\n'; sed 's/^/  /' "$W/bad"; } >"$CC_RUN_DIR/learned-$_kind.txt"
            _nb=$(grep -c . "$W/bad")
            cc_show "" "  in complain$_age; AppArmor logged $((_nn + _nw + _np)) thing(s) it would block: $_nn normal, $_nw write(s) into the site code, $_np program(s) it ran"
            head -n 6 "$W/normal" | while IFS= read -r _l; do cc_show "$C_GRY" "      $_l"; done
            [ "$_nn" -gt 6 ] && cc_show "$C_GRY" "      ... ($CC_RUN_DIR/learned-$_kind.txt)"
            while IFS= read -r _l; do cc_show "$C_YEL" "    [*] wrote into the site code: $_l"; done <"$W/webw"
            [ -n "$_bad" ] && cc_show "$C_RED" "    [!] it ran $_bad- that is what a web shell does: look at the site with SV-16 before you enforce"
            while IFS= read -r _l; do cc_show "$C_RED" "    [!] it touched $_l - a web or database server has no reason to: never added (a break-in? look with SV-16 / LX-42)"; done <"$W/bad"
            grep -vE "$SUSPECT" "$W/progs" | while IFS= read -r _l; do cc_show "$C_YEL" "    [*] it ran $_l (add \"$_l ix,\" to $AAD/local/$_pname yourself if it is normal)"; done
            # Enforce is only the default after 10 quiet minutes of real logging.
            _d=c; if [ $((_nn + _nw)) -gt 0 ]; then _d=l; elif [ $((_np + _nb)) -gt 0 ] || [ "$_stale" = y ]; then _d=c; elif [ -n "$_since" ] && [ $((NOW - _since)) -ge 600 ]; then _d=e; fi
            [ "$_src" = package ] && [ "$_d" = l ] && _d=c
            set -- "c=stay in complain (keep using the site, look again later)" "e=enforce: block everything not in the profile$([ $((_nn + _nw + _np)) -gt 0 ] && echo ' (it would block the logged things)')"
            [ "$_src" = ccdc ] && [ $((_nn + _nw)) -gt 0 ] && set -- "l=learn: add the normal ones to its profile, then look again later" "$@"
            cc_choose "$_kind is in complain mode: what now?" "$_d" "$@"
            _ans=$CC_CHOICE
            if [ "$_ans" = l ]; then
                cp "$W/normal" "$W/plans/$_kind.add"
                [ "$_nn" -gt 0 ] && ! cc_ask "  Add the $_nn normal rule(s) (in $CC_RUN_DIR/learned-$_kind.txt)?" Y "yes, add them" "no" && : >"$W/plans/$_kind.add"
                [ "$_nw" -gt 0 ] && cc_ask "  Also let it write the $_nw file(s) in the site code listed above (a real upload or cache? a web shell?)" N "yes, it is the site" "no, keep them out" && cat "$W/webw" >>"$W/plans/$_kind.add"
                [ -s "$W/plans/$_kind.add" ] || _ans=c
            fi ;;
        enforce)
            events "$_pname" "${_since:-0}" | grep '^DENIED' >"$W/ev.$_kind"
            _nd=$(grep -c . "$W/ev.$_kind")
            cc_show "$([ "$_nd" -gt 0 ] && printf '%s' "$C_YEL" || printf '%s' "$C_GRN")" "  [$([ "$_nd" -gt 0 ] && echo '*' || echo ok)] enforced; AppArmor blocked $_nd thing(s) since then"
            cut -d'|' -f2-4 "$W/ev.$_kind" | head -n 6 | while IFS= read -r _l; do cc_show "$C_GRY" "      $_l"; done
            cc_choose "$_kind is enforced: what now?" k "k=keep it enforced" "c=back to complain (if it broke something)"
            _ans=$CC_CHOICE ;;
    esac
    case "$_state:$_ans" in
        unconfined:c|unconfined:e|complain:e|complain:l|enforce:c) printf '%s|%s|%s|%s|%s|%s|%s\n' "$_kind" "$_bin" "$_pname" "$_src" "$_state" "$_ans" "$_units" >>"$W/plan" ;;
    esac
    # the restart (if asked above) comes after the mode change
    [ "$_rs" = y ] && printf '%s|%s|%s|%s|%s|%s|%s\n' "$_kind" "$_bin" "$_pname" "$_src" "$_state" r "$_units" >>"$W/plan"
done <"$W/svcs"
[ "$_seen" = 1 ] || cc_show "$C_GRY" "  None of apache2, nginx, php-fpm, mariadb/mysql is installed here."

# ---- Plan -----------------------------------------------------------------------------------
header "3/5  plan"
act_word() { case "$1:$2" in *:r) echo "restart it so it runs under its profile" ;; unconfined:c) echo "load the profile in complain mode (nothing blocked)" ;; unconfined:e|complain:e) echo "ENFORCE the profile" ;; complain:l) echo "add the learned rules, stay in complain" ;; enforce:c) echo "back to complain" ;; esac; }
NCH=0; : >"$CC_RUN_DIR/plan.txt"
while IFS='|' read -r _kind _bin _pname _src _state _ans _units; do
    NCH=$((NCH + 1)); printf '%s: %s\n' "$_kind" "$(act_word "$_state" "$_ans")" >>"$CC_RUN_DIR/plan.txt"
    cc_show "$C_YEL" "  [~] $_kind: $(act_word "$_state" "$_ans")"
done <"$W/plan"
[ "$NCH" -eq 0 ] && cc_show "$C_GRN" "  [ok] Nothing to change."

# ---- Apply ----------------------------------------------------------------------------------
header "4/5  apply"
load() { if [ -n "$R" ] && [ -z "${CCDC_AA_PARSER:-}" ]; then return 0; fi; "$PARSER" "$@"; }
svc_restart() {
    [ -z "$R" ] || return 0
    for _u in $1; do
        if [ "$CC_INIT" = systemd ]; then systemctl is-active -q "$_u" 2>/dev/null || continue; systemctl restart "$_u" </dev/null
        else [ -x "/etc/init.d/$_u" ] || continue; service "$_u" restart </dev/null; fi
        return
    done
}
check() {   # check KIND -> 0 still answers
    [ -z "$R" ] || return 0
    [ "$1" = mysql ] || cc_have curl || return 0
    case "$1" in
        mysql) _c=$(cc_first mariadb-admin mysqladmin) || return 0; "$_c" --connect-timeout=5 ping >/dev/null 2>&1 || "$_c" ping 2>&1 | grep -qi 'access denied' ;;
        *) _s=$(curl -k -s -m 10 -o /dev/null -w '%{http_code}' "$URL" 2>/dev/null); case "$_s" in [23]??|401|403|404) return 0 ;; *) return 1 ;; esac ;;
    esac
}
# set_mode FILE NAME ccdc|package complain|enforce -> switch and reload
set_mode() {
    if [ "$3" = ccdc ]; then
        if [ "$4" = complain ]; then sed "s|^\(profile $2 [^ {]*\) {|\1 flags=(complain) {|" "$1" >"$1.n"  # posix-ok: AppArmor text
        else sed 's/ flags=(complain)//' "$1" >"$1.n"; fi  # posix-ok: AppArmor text
        cat "$1.n" >"$1"; rm -f "$1.n"
        load -r -K "$1" >>"$CC_LOG" 2>&1 </dev/null
    elif [ "$4" = complain ]; then ln -sf "$1" "$AAD/force-complain/$(basename "$1")"; load -r -C "$1" >>"$CC_LOG" 2>&1 </dev/null
    else rm -f "$AAD/force-complain/$(basename "$1")"; load -r "$1" >>"$CC_LOG" 2>&1 </dev/null; fi
}
# back_off -> after enforcing: 0 if the service still answers, else put it
# back in complain and return 1
back_off() {
    sleep 2
    # Only blame the profile if the service answered before.
    [ "$_before" = y ] || { cc_show "$C_YEL" "    [*] $_kind did not answer before the change either: not checked"; return 0; }
    check "$_kind" && return 0
    cc_show "$C_RED" "    [x] $_kind stopped answering under enforce: put back in complain"
    set_mode "$_pf" "$_pname" "$_src" complain; date +%s >"$STATE/$_pname.complain"
    _ok=0; return 1
}
# svc_restart_cmd UNITS -> a shell line that restarts the running one (for the undo)
svc_restart_cmd() {
    [ -z "$R" ] || { printf ':'; return; }
    printf 'for u in %s; do if [ -d /run/systemd/system ]; then systemctl try-restart "$u" 2>/dev/null; elif [ -x "/etc/init.d/$u" ]; then service "$u" restart; fi; done' "$1"
}
NOK=0; NBAD=0; APPLIED=0; TIMER_ON=0
if [ "$NCH" -eq 0 ]; then :
elif [ "$CC_APPLY" != 1 ] || { [ -z "$R" ] && ! cc_is_root; }; then
    [ -z "$R" ] && ! cc_is_root && cc_show "$C_YEL" "  [!] not root: showing the plan only"
    cc_show "$C_GRY" "  Dry run: nothing was changed. Run again with --apply."
    # shellcheck disable=SC2034  # read by cc_finish
    CC_N_WOULD=$NCH
elif cc_ask "Apply these $NCH change(s)?" Y "yes, apply them$(grep -q '|e|' "$W/plan" && echo ' (a revert timer undoes this run unless you confirm from a NEW session)')" "no, change nothing"; then
    APPLIED=1; mkdir -p "$STATE" "$AAD/local" "$AAD/force-complain"
    if grep -q '|e|' "$W/plan" && [ "$NOTIMER" != 1 ] && [ -z "$R" ]; then cc_timer_start "$TIMER"; TIMER_ON=1; fi
    while IFS='|' read -r _kind _bin _pname _src _state _ans _units; do
        _before=n; { [ "$_ans" = e ] || [ "$_ans" = r ]; } && check "$_kind" && _before=y
        _ok=1; _pf="$AAD/$_pname"; [ "$_src" = package ] && { _pk=$(packaged "$_bin"); _pf=${_pk%%"|"*}; }
        _fc="$AAD/force-complain/$(basename "$_pf")"; _qp=$(cc_shquote "$PARSER"); _qf=$(cc_shquote "$_pf")
        case "$_state:$_ans" in
            *:r)
                if [ -z "$R" ]; then svc_restart "$_units" >>"$CC_LOG" 2>&1; sleep 2; [ "$(proc_label "$_kind" "$_bin")" = unconfined ] && { _ok=0; cc_show "$C_RED" "    [x] still unconfined after the restart (another program name? see $CC_LOG)"; }; fi ;;
            unconfined:c|unconfined:e)
                _mode=complain; [ "$_ans" = e ] && _mode=enforce
                if [ "$_src" = ccdc ]; then
                    if [ -f "$_pf" ]; then
                        # a file from an earlier run, not loaded now: put it back as it was
                        cc_undo_add "unload $_pname" "$_qp -R $_qf 2>/dev/null; $(svc_restart_cmd "$_units")"
                        cc_backup_file "$_pf" >/dev/null
                    else cc_undo_add "remove the CCDC profile $_pname" "$_qp -R $_qf 2>/dev/null; rm -f $_qf; $(svc_restart_cmd "$_units")"; fi
                    write_profile "$_kind" "$_bin" "$_pname" "$_mode" >"$_pf"
                    [ -f "$AAD/local/$_pname" ] || : >"$AAD/local/$_pname"
                    load -r -K "$_pf" >>"$CC_LOG" 2>&1 </dev/null || { _ok=0; rm -f "$_pf"; cc_show "$C_RED" "    [x] apparmor_parser refused the profile: $CC_LOG"; }
                else
                    cc_undo_add "unload $_pname" "rm -f $(cc_shquote "$_fc"); $_qp -R $_qf 2>/dev/null; $(svc_restart_cmd "$_units")"
                    [ -e "$AAD/disable/$(basename "$_pf")" ] && { rm -f "$AAD/disable/$(basename "$_pf")"; cc_undo_add "$_pname disabled again" "ln -sf $_qf $(cc_shquote "$AAD/disable/$(basename "$_pf")")"; }
                    set_mode "$_pf" "$_pname" package "$_mode" || _ok=0
                fi
                [ "$_ok" = 1 ] && date +%s >"$STATE/$_pname.$_mode"
                if [ "$_ok" = 1 ] && [ -z "$R" ] && cc_ask "  Restart $_kind now so the running service is under its profile?" Y "yes, restart it" "no, at its next restart"; then
                    svc_restart "$_units" >>"$CC_LOG" 2>&1; sleep 2
                fi
                [ "$_ok" = 1 ] && [ "$_mode" = enforce ] && ! back_off ;;
            complain:l)
                _lf="$AAD/local/$_pname"
                cc_undo_add "reload $_pname" "$_qp -r -K $_qf"
                if [ -f "$_lf" ]; then cc_backup_file "$_lf" >/dev/null; else : >"$_lf"; cc_undo_add "empty the learned rules for $_pname" ": > $(cc_shquote "$_lf")"; fi
                { printf '# learned by CCDC LX-44 %s\n' "$(date '+%F %T')"; sed 's/^/  /' "$W/plans/$_kind.add"; } >>"$_lf"
                load -r -K "$_pf" >>"$CC_LOG" 2>&1 </dev/null || { _ok=0; cc_show "$C_RED" "    [x] apparmor_parser refused the learned rules: they are in $_lf"; }
                [ "$_ok" = 1 ] && date +%s >"$STATE/$_pname.complain" ;;
            complain:e|enforce:c)
                _to=enforce; [ "$_ans" = c ] && _to=complain
                if [ "$_src" = ccdc ]; then
                    cc_undo_add "reload $_pname" "$_qp -r -K $_qf"
                    cc_backup_file "$_pf" >/dev/null
                else
                    if [ "$_to" = enforce ]; then cc_undo_add "$_pname back to complain" "ln -sf $_qf $(cc_shquote "$_fc"); $_qp -r -C $_qf"
                    else cc_undo_add "$_pname back to enforce" "rm -f $(cc_shquote "$_fc"); $_qp -r $_qf"; fi
                fi
                set_mode "$_pf" "$_pname" "$_src" "$_to" || _ok=0
                [ "$_ok" = 1 ] && date +%s >"$STATE/$_pname.$_to"
                [ "$_ok" = 1 ] && [ "$_to" = enforce ] && ! back_off ;;
        esac
        if [ "$_ok" = 1 ]; then NOK=$((NOK + 1)); cc_show "$C_GRN" "  [+] $_kind: $(act_word "$_state" "$_ans")"; else NBAD=$((NBAD + 1)); cc_show "$C_RED" "  [x] $_kind: $(act_word "$_state" "$_ans") FAILED"; fi
    done <"$W/plan"
else cc_show "$C_GRY" "  Not applied."; fi
# shellcheck disable=SC2034  # read by cc_finish
CC_N_DONE=$NOK
# shellcheck disable=SC2034  # read by cc_finish
CC_N_FAIL=$NBAD

# ---- Summary ---------------------------------------------------------------------------------
header "5/5  summary"
{
    printf '==========[ summary ]==========\n'
    printf 'LX-44 AppArmor confinement | host %s | %s\n' "$CC_HOST" "$([ "$APPLIED" = 1 ] && echo APPLIED || echo 'DRY RUN - nothing changed')"
    [ -s "$CC_RUN_DIR/plan.txt" ] && { printf 'Changes%s:\n' "$([ "$APPLIED" = 1 ] || echo ' planned')"; sed 's/^/  /' "$CC_RUN_DIR/plan.txt"; }
    [ "$APPLIED" = 1 ] && printf 'Done: %d   Failed: %d\n' "$NOK" "$NBAD"
    printf '\nThe steps: complain -> use the site normally for a while (log in, buy, upload) -> run this again: learn -> again: enforce.\n'
    printf 'Learned rules live in %s/local/ccdc-*; the profiles in %s/ccdc-*.\n' "${AAD#"$R"}" "${AAD#"$R"}"
    [ "$APPLIED" = 1 ] && [ -f "$CC_RUN_DIR/revert.sh" ] && printf 'Undo this run: sh %s/revert.sh --force\n' "$CC_RUN_DIR"
    [ "$APPLIED" = 1 ] && [ ! -f "$CC_RUN_DIR/revert.sh" ] && printf 'Undo: the lines in %s/undo-%s.log\n' "$CC_OUT" "$CC_HOST"
} >"$CC_RUN_DIR/summary.txt"
{ printf 'AppArmor mode of each service when the run started\n\n'; cat "$W/status"; printf '\nunconfined = nothing stops it; complain = logs only; enforce = blocks\n'; } >"$CC_RUN_DIR/status.txt"
while IFS= read -r _l; do case "$_l" in ==*|LX-44*) cc_show "$C_CYN" "$_l" ;; *FAILED*|*'Failed: '[1-9]*) cc_show "$C_RED" "$_l" ;; *) cc_show "" "$_l" ;; esac; done <"$CC_RUN_DIR/summary.txt"
rm -rf "$W"
if [ "$TIMER_ON" = 1 ]; then header "KEEP OR REVERT"; cc_show "$C_YEL" "[*] Before you answer: click through the store (log in, add to cart, upload) and the webmail."; cc_timer_finish || true; fi
cc_finish
