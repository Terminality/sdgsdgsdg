#!/bin/sh
# =============================================================================
# ID:       LX-46
# NAME:     Safe security updates
# ROLE:     Linux  (wave 2, once the services are backed up)
# KIND:     changes - dry run unless --apply
# VERSION:  1.0.0
#
# PURPOSE
#   Patches the holes red team will use (OpenSSH, OpenSSL, sudo, Apache,
#   PHP, the database, mail) without breaking a scored service:
#     - looks first at WHERE updates come from: package sources that are not
#       the distribution's, sources with no signature check, and packages
#       put on hold (red team holds openssh so it never gets patched)
#     - lists the pending updates, security ones apart, grouped by the
#       service they belong to
#     - asks about each group; non-security updates and the kernel (it
#       needs a reboot) default to skip
#     - before each group: saves the old packages (for the rollback) and
#       which ports were listening; your config files are always kept
#     - after each group: checks every port that listened before still
#       listens (and the web page and database still answer); if one does
#       not, offers to roll that group back right away
#     - services still running the old (deleted) library code are offered
#       a restart
#
#   QUESTIONS (Enter takes the default in capitals; a flag answers each):
#     refresh the package lists first?                 Y   --no-refresh
#     each held package          [k]eep held / [r]elease it
#     each group of security updates   [u]pdate / [s]kip      default u
#     the kernel                       [u]pdate / [s]kip      default s
#     the non-security updates         [u]pdate / [s]kip      default s
#     a service broke after a group    [r]oll back / [l]eave  default r
#     restart services on old library code?            Y
#     apply?                                           --apply
#
# USAGE
#   sudo sh LX-46-safe-updates.sh                                 list + dry run
#   sudo sh LX-46-safe-updates.sh --protected p.csv --apply       step by step
#   sudo sh LX-46-safe-updates.sh --protected p.csv --apply --batch
#
# OPTIONS
#   --apply           install (without it, dry run only)
#   --no-refresh      do not run apt-get update / dnf makecache first
#   --no-restart      never offer to restart services still on old code
#   --all             default to [u] for the non-security updates too
#   --kernel          default to [u] for the kernel too
#   --url URL         page checked before and after (default http://127.0.0.1/)
#   --no-color        no colours
#   --help            this text plus the common options
#
# OUTPUTS  (under --out, in updates-N/)
#   output.txt, sources.txt, updates.txt, versions-before.txt,
#   versions-after.txt, summary.txt, old-packages/ (the saved .deb files);
#   the rollback lines go in the undo log
#
# DEPENDS ON
#   apt-get + dpkg (Debian, Ubuntu) or dnf / yum (Red Hat family); ss.
#
# TESTED ON
#   Stand-in apt-get, dpkg-query, apt-mark and ss (no real package is
#   installed by the tests) under dash, bash, busybox sh, ksh93, mksh and
#   yash with gawk, mawk and busybox awk; the parsing of apt-get -s on
#   Ubuntu 24.04.  The dnf path is NOT yet tested on a real Red Hat box.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - The rollback needs the old package: saved with "apt-get download"
#     before the update.  If the mirror no longer has it, you are told
#     before you choose.
#   - The check sees ports, the web page and the database; not every
#     feature.  Click through the site after a web or PHP group.
#   - Updates restart services: a scoring check that lands in those
#     seconds fails.  Do it early, one group at a time.
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
LX-46 Safe security updates - by service, checked after, rolled back if a service broke
  sudo sh LX-46-safe-updates.sh                             list + dry run
  sudo sh LX-46-safe-updates.sh --protected p.csv --apply   step by step

  --apply           install (without it, dry run only)
  --no-refresh      do not refresh the package lists first
  --no-restart      never offer to restart services after
  --all             default to update the non-security updates too
  --kernel          default to update the kernel too
  --url URL         page checked before and after (default http://127.0.0.1/)
  --no-color        no colours
  --help            show this text
USAGE
    cc_usage_common
}

RESTART=1; REFRESH=1; ALL=s; KERN=s; URL="http://127.0.0.1/"; COLOR=1
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --apply)      CC_APPLY=1; shift ;;
        --no-refresh) REFRESH=0; shift ;;
        --no-restart) RESTART=0; shift ;;
        --all)        ALL=u; shift ;;
        --kernel)     KERN=u; shift ;;
        --url)        [ $# -ge 2 ] || cc_die 2 "--url needs an address"; URL=$2; shift 2 ;;
        --no-color|--no-colour) COLOR=0; shift ;;
        --help|-h)    usage; exit 0 ;;
        *)            cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done

cc_init "LX-46" "Safe security updates" changes
cc_detect_os
# shellcheck disable=SC2034  # read by cc_color_init
[ "$COLOR" = 1 ] || CC_NOCOLOR=1
cc_color_init
cc_use_numbered_dir updates
rmdir "$CC_RUN_DIR/raw" 2>/dev/null
OUTF="$CC_RUN_DIR/output.txt"
grep -v '\[NOTE\]\|\[DEBUG\]' "$CC_LOG" >"$OUTF" 2>/dev/null || : >"$OUTF"
# shellcheck disable=SC2034  # CC_TEE is read by the library's log functions
CC_TEE=$OUTF
W="$CC_RUN_DIR/.work"; mkdir -p "$W"
AETC=${BT_TEST_ETC:-/etc}   # tests point this at a fake /etc
ACACHE=${BT_TEST_APTCACHE:-/var/cache/apt/archives}
header() { cc_show "" ""; cc_show "$C_CYN" "==========[ $1 ]=========="; }
export DEBIAN_FRONTEND=noninteractive
APTO="-o Dpkg::Options::=--force-confold -o Dpkg::Options::=--force-confdef"

cc_show "$C_CYN" "LX-46 Safe security updates | host $CC_HOST | results in $CC_RUN_DIR"
cc_show "" "Legend: ${C_RED}[!]${C_OFF} fix now   ${C_YEL}[*]${C_OFF} look at it   ${C_GRN}[ok]${C_OFF} fine   ${C_YEL}[~] would change${C_OFF}   ${C_GRN}[+] changed${C_OFF}   ${C_RED}[x] failed${C_OFF}"
CAN=0; [ "$CC_APPLY" = 1 ] && cc_is_root && CAN=1
[ "$CC_APPLY" = 1 ] && [ "$CAN" = 0 ] && cc_show "$C_YEL" "  [!] not root: showing the plan only"

# ---- 1. Sources and holds ---------------------------------------------------------------------
header "1/6  where updates come from"
PM=""; if cc_have apt-get && cc_have dpkg-query; then PM=apt; elif cc_have dnf; then PM=dnf; elif cc_have yum; then PM=yum; fi
[ -n "$PM" ] || { cc_show "$C_RED" "  [x] no apt-get, dnf or yum here"; rm -rf "$W"; cc_finish; exit 3; }
cc_show "" "  package manager: $PM"
if [ "$PM" = apt ] && _busy=$(ps -eo comm= 2>/dev/null | grep -xE 'apt|apt-get|dpkg|unattended-upgr|aptitude' | sort -u | tr '\n' ' ') && [ -n "$_busy" ]; then
    cc_show "$C_YEL" "  [*] another package job is running ($_busy): wait for it, or this run cannot install"
fi
: >"$CC_RUN_DIR/sources.txt"
NSRC=0
src_line() {  # src_line LEVEL TEXT
    printf '%s %s\n' "$1" "$2" >>"$CC_RUN_DIR/sources.txt"
    case "$1" in '[!]') cc_show "$C_RED" "  $1 $2" ;; '[*]') cc_show "$C_YEL" "  $1 $2" ;; *) cc_show "$C_GRN" "  $1 $2" ;; esac
    NSRC=$((NSRC + 1))
}
OFFICIAL='(^|\.)(ubuntu\.com|debian\.org|launchpadcontent\.net|launchpad\.net|canonical\.com|rockylinux\.org|almalinux\.org|centos\.org|fedoraproject\.org|redhat\.com|oracle\.com)$'
if [ "$PM" = apt ]; then
    {
        cat "$AETC"/apt/sources.list "$AETC"/apt/sources.list.d/*.list 2>/dev/null | sed 's/#.*//' | awk '$1 == "deb" { o = ""; u = ""; for (i = 2; i <= NF; i++) { if ($i ~ /^\[/) { while (i <= NF && $i !~ /\]$/) { o = o " " $i; i++ } o = o " " $i; continue } u = $i; break } print u "|" o }'
        cat "$AETC"/apt/sources.list.d/*.sources 2>/dev/null | awk 'BEGIN { RS = "" } /(^|\n)Types:.*deb/ { u = ""; o = ""; n = split($0, l, "\n"); for (i = 1; i <= n; i++) { if (l[i] ~ /^URIs:/) { sub(/^URIs:[ \t]*/, "", l[i]); u = l[i] } if (l[i] ~ /^(Trusted|Allow-Insecure|Allow-Weak):[ \t]*yes/) o = o " trusted=yes" } split(u, us, " "); for (j in us) print us[j] "|" o }'
    } | sort -u >"$W/src"
    while IFS='|' read -r _u _o; do
        [ -n "$_u" ] || continue
        _h=$(printf '%s' "$_u" | sed 's|^[a-z+]*://||; s|[/:].*||')
        case "$_o" in *trusted=yes*|*allow-insecure=yes*) src_line '[!]' "no signature check: $_u ($_o): anything served there gets installed" ;; esac
        if printf '%s' "$_h" | grep -qE "$OFFICIAL"; then src_line '[ok]' "$_u"
        else src_line '[*]' "not the distribution's: $_u (added by your team? if not, delete it from /etc/apt/sources.list.d)"; fi
    done <"$W/src"
    grep -rhsiE 'AllowUnauthenticated[[:space:]]+"?(true|1)|AllowInsecureRepositories[[:space:]]+"?(true|1)' "$AETC"/apt/apt.conf "$AETC"/apt/apt.conf.d 2>/dev/null | while IFS= read -r _l; do src_line '[!]' "apt takes unsigned packages: $_l (in /etc/apt/apt.conf.d)"; done
    # Pins can block updates as well as a hold: Pin-Priority below 0 never installs.
    for _pf in "$AETC"/apt/preferences "$AETC"/apt/preferences.d/*; do
        [ -f "$_pf" ] || continue
        awk -v f="${_pf#"$AETC"}" 'BEGIN { RS = "" } /Pin-Priority:[ \t]*-/ { p = ""; if (match($0, /Package:[^\n]*/)) p = substr($0, RSTART + 8, RLENGTH - 8); print "/etc" f "|" p }' "$_pf"
    done | while IFS='|' read -r _f _p; do src_line '[*]' "a pin that blocks updates (Pin-Priority below 0) for$_p in $_f: red team uses this like a hold"; done
    grep -rhsiE '^[^#]*Acquire::(http|https|ftp)::Proxy' "$AETC"/apt/apt.conf "$AETC"/apt/apt.conf.d 2>/dev/null | while IFS= read -r _l; do src_line '[*]' "apt goes through a proxy: $_l (yours? a proxy can hand out old packages)"; done
    apt-mark showhold 2>/dev/null | grep . >"$W/held"
else
    for _f in "$AETC"/yum.repos.d/*.repo; do
        [ -f "$_f" ] || continue
        awk -v f="$_f" -F= '/^\[/ { s = $0 } $1 ~ /^(baseurl|mirrorlist|metalink)$/ { print f "|" s "|" $2 } $1 == "gpgcheck" && $2 + 0 == 0 { print f "|" s "|GPGOFF" } $1 == "enabled" && $2 + 0 == 0 { print f "|" s "|DISABLED" }' "$_f"
    done | sort -u >"$W/src"
    grep '|DISABLED$' "$W/src" | cut -d'|' -f1,2 >"$W/srcoff"
    while IFS='|' read -r _f _s _u; do
        grep -qxF "$_f|$_s" "$W/srcoff" && continue
        case "$_u" in DISABLED) continue ;; GPGOFF) src_line '[!]' "no signature check: $_s in $_f (gpgcheck=0)"; continue ;; esac
        _h=$(printf '%s' "$_u" | sed 's|^[a-z+]*://||; s|[/:?].*||')
        if printf '%s' "$_h" | grep -qE "$OFFICIAL"; then src_line '[ok]' "$_s $_u"; else src_line '[*]' "not the distribution's: $_s $_u ($_f)"; fi
    done <"$W/src"
    { dnf versionlock list 2>/dev/null || yum versionlock list 2>/dev/null; } | grep -v '^Last metadata\|^Loaded plugins' | sed 's/-[0-9]:.*//; s/-[0-9][^-]*-[^-]*$//' | grep . >"$W/held"
fi
[ "$NSRC" -gt 0 ] || src_line '[*]' "no package sources found"
: >"$W/release"
if [ -s "$W/held" ]; then
    while IFS= read -r _p; do
        cc_show "$C_YEL" "  [*] held (never updated): $_p - red team holds packages so a hole stays open"
        cc_choose "$_p is held: what now?" k "k=keep it held (your team held it on purpose)" "r=release it so it can be updated"
        [ "$CC_CHOICE" = r ] && printf '%s\n' "$_p" >>"$W/release"
    done <"$W/held"
else cc_show "$C_GRN" "  [ok] no packages held"; fi

# ---- 2. Before ------------------------------------------------------------------------------
header "2/6  services before"
# Ports below 32768 only: higher ones are usually short-lived (they come and
# go on their own and would look like a broken service).
ports() { ss -ltnH 2>/dev/null | awk '{ a = $4; sub(/.*:/, "", a); if (a + 0 < 32768) print a }' | sort -un; }
web() { cc_have curl || return 0; curl -s -m 8 -o /dev/null -w '%{http_code}' "$URL" 2>/dev/null; }
dbok() { _c=$(cc_first mariadb-admin mysqladmin) || return 0; "$_c" --connect-timeout=5 ping >/dev/null 2>&1 && echo up && return; "$_c" ping 2>&1 | grep -qi 'access denied' && echo up; }
ports >"$W/ports0"; WEB0=$(web); DB0=$(dbok)
cc_show "" "  listening TCP ports: $(tr '\n' ' ' <"$W/ports0")"
[ -n "$WEB0" ] && [ "$WEB0" != 000 ] && cc_show "" "  web page $URL answers $WEB0"
[ "$DB0" = up ] && cc_show "" "  the database answers"

# ---- 3. Pending updates -----------------------------------------------------------------------
header "3/6  pending updates"
if [ "$REFRESH" = 1 ]; then
    if [ "$CAN" = 1 ] || { [ "$CC_APPLY" != 1 ] && cc_is_root; }; then
        cc_ask "Refresh the package lists first (apt-get update / dnf makecache)?" Y "yes, so the newest fixes show" "no, use the lists from the last refresh" && {
            if [ "$PM" = apt ]; then apt-get update -q </dev/null >>"$CC_LOG" 2>&1; else $PM -q makecache </dev/null >>"$CC_LOG" 2>&1; fi || cc_show "$C_YEL" "  [*] the refresh failed (no internet?): using the old lists"
        }
    fi
fi
# grp NAME -> the group a package belongs to
grp() {
    case "$1" in
        linux-image*|linux-headers*|linux-modules*|linux-generic*|linux-virtual*|linux-aws*|linux-azure*|linux-gcp*|kernel|kernel-core|kernel-modules*|kernel-headers) echo kernel ;;
        openssh*) echo ssh ;;
        openssl*|libssl*) echo openssl ;;
        sudo|sudo-*) echo sudo ;;
        apache2*|libapache2*|httpd*|mod_*|nginx*|libnginx*) echo web ;;
        php*|libphp*) echo php ;;
        mariadb*|mysql*|libmariadb*|libmysql*|galera*) echo database ;;
        postfix*|dovecot*|roundcube*) echo mail ;;
        bind9*|bind|named*) echo dns ;;
        vsftpd*|proftpd*|pure-ftpd*) echo ftp ;;
        *) echo system ;;
    esac
}
# grp_units GROUP -> service names a group belongs to (for the protected list)
grp_units() {
    case "$1" in
        ssh) echo "ssh sshd" ;; web) echo "apache2 httpd nginx" ;; php) echo "php-fpm php8.3-fpm php8.2-fpm php8.1-fpm php7.4-fpm" ;;
        database) echo "mariadb mysql mysqld" ;; mail) echo "postfix dovecot" ;; dns) echo "bind9 named" ;; ftp) echo "vsftpd proftpd" ;;
    esac
}
: >"$W/upd"
if [ "$PM" = apt ]; then
    # Inst NAME [OLD] (NEW SOURCE [ARCH])
    apt-get -s -o Debug::NoLocking=1 dist-upgrade </dev/null 2>>"$CC_LOG" | awk '
        /^Inst / { n = $2; o = ""; if ($3 ~ /^\[/) { o = $3; gsub(/[][]/, "", o) }
                   if (!match($0, /\([^)]*\)/)) next; p = substr($0, RSTART + 1, RLENGTH - 2); split(p, a, " ")
                   s = (p ~ /-security|Debian-Security|security\./) ? "security" : "other"
                   print n "|" o "|" a[1] "|" s }' >"$W/upd0"
else
    $PM -q check-update --security </dev/null 2>/dev/null | awk 'NF == 3 && $2 ~ /[0-9]/ { n = $1; sub(/\.[^.]*$/, "", n); print n }' | sort -u >"$W/sec"
    $PM -q check-update </dev/null 2>/dev/null | awk 'NF == 3 && $2 ~ /[0-9]/ { n = $1; sub(/\.[^.]*$/, "", n); print n "|" $2 }' | sort -u | while IFS='|' read -r _n _v; do
        _o=$(rpm -q --qf '%{VERSION}-%{RELEASE}' "$_n" 2>/dev/null | head -n 1)
        _s=other; grep -qxF "$_n" "$W/sec" && _s=security
        printf '%s|%s|%s|%s\n' "$_n" "$_o" "$_v" "$_s"
    done >"$W/upd0"
fi
while IFS='|' read -r _n _o _v _s; do
    _g=$(grp "$_n"); [ "$_g" = kernel ] && _s=kernel
    printf '%s|%s|%s|%s|%s\n' "$_g" "$_s" "$_n" "$_o" "$_v"
done <"$W/upd0" | sort >"$W/upd"
NUPD=$(grep -c . "$W/upd"); NSEC=$(grep -c '|security|' "$W/upd")
{
    printf '%-10s %-9s %-34s %-28s %s\n' group kind package installed new
    awk -F'|' '{ printf "%-10s %-9s %-34s %-28s %s\n", $1, $2, $3, $4, $5 }' "$W/upd"
} >"$CC_RUN_DIR/updates.txt"
if [ "$NUPD" -eq 0 ]; then cc_show "$C_GRN" "  [ok] nothing to update"
else
    cc_show "$([ "$NSEC" -gt 0 ] && printf '%s' "$C_RED" || printf '%s' "$C_YEL")" "  $NUPD update(s), $NSEC of them security (full list: $CC_RUN_DIR/updates.txt)"
    for _g in ssh openssl sudo web php database mail dns ftp system kernel; do
        _l=$(awk -F'|' -v g="$_g" '$1 == g { printf "%s%s", (n++ ? ", " : ""), $3 }' "$W/upd")
        [ -n "$_l" ] || continue
        _ns=$(grep -c "^$_g|security|" "$W/upd")
        cc_show "$([ "$_ns" -gt 0 ] && printf '%s' "$C_RED" || printf '%s' "$C_GRY")" "  $([ "$_ns" -gt 0 ] && printf '[!]' || printf '   ') $_g: $_l"
    done
fi

# ---- 4. Questions ---------------------------------------------------------------------------
header "4/6  what to update"
: >"$W/plan"   # GROUP|KIND|packages
ask_group() {  # ask_group GROUP KIND DEFAULT TEXT
    _pk=$(awk -F'|' -v g="$1" -v k="$2" '$1 == g && $2 == k { printf "%s ", $3 }' "$W/upd"); _pk=${_pk% }
    [ -n "$_pk" ] || return 0
    for _u in $(grp_units "$1"); do
        if cc_is_protected service "$_u"; then cc_show "$C_YEL" "  [*] $1: the service $_u is on the protected list - its updates are skipped (update it by hand when it is safe)"; return 0; fi
    done
    _n=$(printf '%s' "$_pk" | wc -w | tr -d ' ')
    cc_choose "$4 ($_n: $_pk): what now?" "$3" "u=update them (checked after; rolled back if a service broke)" "s=skip them"
    [ "$CC_CHOICE" = u ] && printf '%s|%s|%s\n' "$1" "$2" "$_pk" >>"$W/plan"
}
for _g in ssh openssl sudo web php database mail dns ftp system; do ask_group "$_g" security u "Security updates for $_g"; done
ask_group kernel kernel "$KERN" "Kernel updates (only take effect after a REBOOT; a reboot mid-game drops every service for minutes)"
for _g in ssh openssl sudo web php database mail dns ftp system; do ask_group "$_g" other "$ALL" "Non-security updates for $_g"; done
NPLAN=$(grep -c . "$W/plan"); NREL=$(grep -c . "$W/release")
[ "$NPLAN" -eq 0 ] && [ "$NREL" -eq 0 ] && cc_show "$C_GRN" "  [ok] nothing chosen"

# ---- 5. Apply -------------------------------------------------------------------------------
header "5/6  apply"
NOK=0; NBAD=0; NROLL=0; APPLIED=0
ver_list() { if [ "$PM" = apt ]; then dpkg-query -W -f '${Package} ${Version}\n' 2>/dev/null; else rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\n' 2>/dev/null; fi | sort; }
# broke -> the checks that passed before and fail now (empty: all fine); waits up to 15 s
broke() {
    _t=0
    while :; do
        ports >"$W/ports1"; _b=$(comm -23 "$W/ports0" "$W/ports1" | tr '\n' ' '); _b=${_b% }
        _r=""; [ -n "$_b" ] && _r="port(s) $_b no longer listening; "
        if [ -n "$WEB0" ] && [ "$WEB0" != 000 ]; then _w=$(web); [ "$_w" = "$WEB0" ] || _r="${_r}the web page answers ${_w:-nothing} (was $WEB0); "; fi
        [ "$DB0" = up ] && [ "$(dbok)" != up ] && _r="${_r}the database does not answer; "
        [ -z "$_r" ] || [ "$_t" -ge 15 ] && break
        sleep 3; _t=$((_t + 3))
    done
    printf '%s' "${_r%; }"
}
if [ "$NPLAN" -eq 0 ] && [ "$NREL" -eq 0 ]; then :
elif [ "$CAN" != 1 ]; then
    while IFS='|' read -r _g _k _pk; do cc_show "$C_YEL" "  [~] would update $_g ($_k): $_pk"; done <"$W/plan"
    while IFS= read -r _p; do cc_show "$C_YEL" "  [~] would release the hold on $_p"; done <"$W/release"
    cc_show "$C_GRY" "  Dry run: nothing was changed. Run again with --apply."
    # shellcheck disable=SC2034  # read by cc_finish
    CC_N_WOULD=$((NPLAN + NREL))
elif cc_ask "Apply: $NPLAN group(s) of updates$([ "$NREL" -gt 0 ] && echo ", $NREL hold(s) released")?" Y "yes, one group at a time, checked after each" "no, change nothing"; then
    APPLIED=1
    ver_list >"$CC_RUN_DIR/versions-before.txt"
    while IFS= read -r _p; do
        if [ "$PM" = apt ]; then apt-mark unhold "$_p" >>"$CC_LOG" 2>&1 </dev/null; _rc=$?; cc_undo_add "hold $_p again" "apt-mark hold $(cc_shquote "$_p")"
        else $PM versionlock delete "$_p" >>"$CC_LOG" 2>&1 </dev/null; _rc=$?; cc_undo_add "lock $_p again" "$PM versionlock add $(cc_shquote "$_p")"; fi
        if [ "$_rc" = 0 ]; then NOK=$((NOK + 1)); cc_show "$C_GRN" "  [+] released the hold on $_p"; else NBAD=$((NBAD + 1)); cc_show "$C_RED" "  [x] could not release $_p"; fi
    done <"$W/release"
    OLD="$CC_RUN_DIR/old-packages"; mkdir -p "$OLD"
    while IFS='|' read -r _g _k _pk; do
        cc_show "" ""
        cc_show "$C_CYN" "  -- $_g ($_k): $_pk"
        # Save the old packages and write the rollback.
        _back=""; _miss=""
        if [ "$PM" = apt ]; then
            for _p in $_pk; do
                _o=$(awk -F'|' -v p="$_p" '$3 == p { print $4; exit }' "$W/upd")
                [ -n "$_o" ] || continue   # a new package: nothing to go back to
                # apt's own cache first (often still there), then the mirror
                _cf=$(ls "$ACACHE/${_p}_$(printf '%s' "$_o" | sed 's/:/%3a/')_"*.deb 2>/dev/null | head -n 1)
                if [ -n "$_cf" ] && cp "$_cf" "$OLD/" 2>>"$CC_LOG"; then _back="$_back $_p=$_o"
                elif (cd "$OLD" && apt-get download "$_p=$_o" </dev/null >>"$CC_LOG" 2>&1); then _back="$_back $_p=$_o"; else _miss="$_miss $_p"; fi
            done
            _undo=""; [ -n "$_back" ] && _undo="cd $(cc_shquote "$OLD") && DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades $APTO$(for _x in $_back; do printf ' ./%s_%s_*.deb' "${_x%%=*}" "$(printf '%s' "${_x#*=}" | sed 's/:/%3a/')"; done)"
        else
            _undo=""   # set after the update: the number of its dnf transaction
        fi
        if [ -n "$_miss" ]; then
            cc_show "$C_YEL" "  [*] the old version of$_miss is no longer on the mirror: no rollback for it"
            cc_ask "  Update $_g anyway?" N "yes, update without a full rollback" "no, skip $_g" || { cc_show "$C_GRY" "  skipped $_g"; continue; }
        fi
        if [ "$PM" = apt ]; then
            # shellcheck disable=SC2086  # word splitting wanted: options and packages
            apt-get install -y --only-upgrade $APTO $_pk </dev/null >>"$CC_LOG" 2>&1
        else
            # shellcheck disable=SC2086
            $PM -y upgrade $_pk </dev/null >>"$CC_LOG" 2>&1
        fi
        _rc=$?
        if [ "$PM" != apt ] && [ "$_rc" = 0 ]; then
            # Undo this transaction by its number, not "last" (a later one would be undone instead).
            _tid=$($PM -q history list 2>/dev/null | awk '$1 ~ /^[0-9]+$/ { print $1; exit }')
            [ -n "$_tid" ] && _undo="$PM -y history undo $_tid"
        fi
        [ -n "$_undo" ] && { [ -n "$_back" ] || [ "$PM" != apt ]; } && cc_undo_add "roll back $_g updates" "$_undo"
        _why=$(broke)
        if [ "$_rc" != 0 ]; then
            NBAD=$((NBAD + 1)); cc_show "$C_RED" "  [x] $_g: the package manager failed (see $CC_LOG)"
        elif [ -z "$_why" ]; then
            NOK=$((NOK + 1)); cc_show "$C_GRN" "  [+] $_g updated; ports, web page and database still answer"
        else
            cc_show "$C_RED" "  [!] after the $_g ($_k) update: $_why"
            cc_choose "A service broke after the $_g update: what now?" r "r=roll back the $_g update now" "l=leave it (fix it by hand; the rollback line is in the undo log)"
            if [ "$CC_CHOICE" = r ] && [ -z "$_undo" ]; then NBAD=$((NBAD + 1)); cc_show "$C_RED" "  [x] no rollback for this group (the old packages could not be saved)"
            elif [ "$CC_CHOICE" = r ]; then
                if sh -c "$_undo" </dev/null >>"$CC_LOG" 2>&1; then
                    NROLL=$((NROLL + 1)); _why2=$(broke)
                    if [ -z "$_why2" ]; then cc_show "$C_GRN" "  [+] rolled back; everything answers again"
                    else cc_show "$C_RED" "  [x] rolled back, but still: $_why2 - restart it by hand or run SV-50"; fi
                else NBAD=$((NBAD + 1)); cc_show "$C_RED" "  [x] the rollback failed (see $CC_LOG)"; fi
            else NBAD=$((NBAD + 1)); fi
            # The next groups are checked against how things are now, so the
            # same broken service is not blamed on them too.
            ports >"$W/ports0"; WEB0=$(web); DB0=$(dbok)
        fi
    done <"$W/plan"
    ver_list >"$CC_RUN_DIR/versions-after.txt"
    # Config files the package wanted to replace: yours were kept.
    find "$AETC" -newer "$CC_RUN_DIR/versions-before.txt" \( -name '*.dpkg-dist' -o -name '*.dpkg-new' -o -name '*.rpmnew' \) 2>/dev/null | while IFS= read -r _f; do
        cc_show "$C_YEL" "  [*] new default config from the package, yours kept: $_f (compare later, do not just copy it over)"
    done
    # Services still running the old library code.
    for _pd in /proc/[0-9]*; do
        _pid=${_pd#/proc/}
        grep -qE '\.so[.0-9]* \(deleted\)$|/(usr/)?s?bin/[^ ]+ \(deleted\)$' "/proc/$_pid/maps" 2>/dev/null || continue
        cat "/proc/$_pid/comm" 2>/dev/null
    done | sort -u >"$W/stale"
    _rs=""
    [ "$RESTART" = 1 ] || : >"$W/stale"
    for _u in ssh sshd apache2 httpd nginx php8.3-fpm php8.2-fpm php8.1-fpm php7.4-fpm php-fpm mariadb mysql postfix dovecot named bind9 vsftpd cron rsyslog; do
        case "$_u" in ssh|sshd) _c=sshd ;; mariadb) _c=mariadbd ;; mysql) _c=mysqld ;; postfix) _c=master ;; php*) _c=php-fpm ;; *) _c=$_u ;; esac
        grep -q "^$_c" "$W/stale" || continue
        if [ "$CC_INIT" = systemd ]; then systemctl is-active -q "$_u" 2>/dev/null || continue; else [ -x "/etc/init.d/$_u" ] || continue; fi
        cc_is_protected service "$_u" && continue
        case " $_rs " in *" $_c "*) continue ;; esac
        _rs="$_rs $_u"
    done
    if [ -n "$_rs" ] && cc_ask "  Still running the old (unpatched) code:$_rs. Restart them now?" Y "yes, restart them (a few seconds each)" "no, they stay on the old code until restarted"; then
        for _u in $_rs; do
            if [ "$CC_INIT" = systemd ]; then systemctl restart "$_u" </dev/null >>"$CC_LOG" 2>&1; else service "$_u" restart </dev/null >>"$CC_LOG" 2>&1; fi && cc_show "$C_GRN" "  [+] restarted $_u" || cc_show "$C_RED" "  [x] $_u did not restart: SV-50 can bring it back"
        done
        _why=$(broke); [ -n "$_why" ] && cc_show "$C_RED" "  [!] after the restarts: $_why"
    fi
    { [ -f /var/run/reboot-required ] || [ -f /run/reboot-required ]; } && cc_show "$C_YEL" "  [*] a reboot is needed for the kernel or libc update (plan it between scoring checks)"
else cc_show "$C_GRY" "  Not applied."; fi
# shellcheck disable=SC2034  # read by cc_finish
CC_N_DONE=$NOK
# shellcheck disable=SC2034  # read by cc_finish
CC_N_FAIL=$NBAD

# ---- 6. Summary ------------------------------------------------------------------------------
header "6/6  summary"
{
    printf '==========[ summary ]==========\n'
    printf 'LX-46 Safe security updates | host %s | %s\n' "$CC_HOST" "$([ "$APPLIED" = 1 ] && echo APPLIED || echo 'DRY RUN - nothing changed')"
    printf 'Pending: %s update(s), %s security\n' "$NUPD" "$NSEC"
    printf 'Sources: %s ([!] %s, [*] %s)\n' "$NSRC" "$(grep -c '^\[!\]' "$CC_RUN_DIR/sources.txt")" "$(grep -c '^\[\*\]' "$CC_RUN_DIR/sources.txt")"
    [ -s "$W/plan" ] && { printf 'Chosen:\n'; awk -F'|' '{ printf "  %s (%s): %s\n", $1, $2, $3 }' "$W/plan"; }
    [ "$APPLIED" = 1 ] && printf 'Done: %d   Failed: %d   Rolled back: %d\n' "$NOK" "$NBAD" "$NROLL"
    [ "$APPLIED" = 1 ] && printf 'Undo: the rollback lines are in %s/undo-%s.log (newest last; old packages in %s/old-packages)\n' "$CC_OUT" "$CC_HOST" "$CC_RUN_DIR"
} >"$CC_RUN_DIR/summary.txt"
while IFS= read -r _l; do case "$_l" in ==*|LX-46*) cc_show "$C_CYN" "$_l" ;; *'Failed: '[1-9]*) cc_show "$C_RED" "$_l" ;; *) cc_show "" "$_l" ;; esac; done <"$CC_RUN_DIR/summary.txt"
rm -rf "$W"
cc_finish
