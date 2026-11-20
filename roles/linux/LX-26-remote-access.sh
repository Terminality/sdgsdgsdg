#!/bin/sh
# =============================================================================
# ID:       LX-26
# NAME:     Remote access lockdown (everything but SSH)
# ROLE:     Linux  (wave 1, after SSH hardening; again after red team)
# KIND:     changes - dry run unless --apply
# VERSION:  1.2.0
#
# PURPOSE
#   SSH is handled by LX-22.  Red team also gets in through everything
#   else that gives a remote screen, a shell in a browser, or a tunnel out
#   past the firewall.  This finds them - as running programs, as listening
#   ports and as installed services - and offers to stop each one:
#
#     HIGH  tunnels out (ngrok, chisel, frpc/frps, cloudflared, bore, gost,
#           ligolo, rathole, inlets, pinggy/localtunnel ssh -R, wstunnel,
#           sshx), mesh VPNs (Tailscale, ZeroTier), DNS and ICMP tunnels
#           (iodine, dnscat2, ptunnel), web terminals (ttyd, gotty,
#           shellinabox, wetty, tmate, code-server, Jupyter), bind / reverse
#           shells (nc -e, ncat -e/--exec, socat ... exec:, a shell holding a
#           network connection), remote desktops (x11vnc, Xvnc, vncserver,
#           xrdp, NoMachine, TeamViewer, AnyDesk, RustDesk, Vino, KRfb,
#           GNOME Remote Desktop, MeshCentral agent, Guacamole, DWService,
#           Chrome Remote Desktop, xpra)
#     MED   admin panels (Webmin 10000, Cockpit 9090, Usermin, ISPConfig,
#           Virtualmin), file-sharing listeners (python -m http.server,
#           php -S, busybox httpd), desktop control (KDE Connect, Barrier,
#           Synergy, Input Leap: keyboard and mouse from another machine)
#     LOW   database panels on the web (phpMyAdmin, Adminer): listed
#
#   For each one (Enter = the default in capitals):
#     [s] stop it and keep it from starting again (service disabled, or the
#         program killed; its file quarantined if it lives in /tmp, /dev/shm,
#         a home folder or /var/tmp)
#     [k] keep it
#     [a] all the rest: take their defaults
#   A tool someone is connected through right now from another machine (the
#   boxes may be reached over VNC or telnet - maybe it is you) is marked IN USE
#   NOW and kept by default.
#   Defaults: stop for HIGH, keep for MED.  Scored services and anything on
#   the protected list are never offered.
#
#   QUESTIONS (a flag answers each):
#     which box (its scored ports are kept)    --box NAME
#     each finding: [s]top [k]eep [a]ll        --batch takes the defaults
#     apply?                                   --apply
#
# USAGE
#   sudo sh LX-26-remote-access.sh                                look + dry run
#   sudo sh LX-26-remote-access.sh --protected p.csv --apply      asks about each
#   sudo sh LX-26-remote-access.sh --protected p.csv --apply --batch
#
# OPTIONS
#   --apply            make the changes (without it, dry run only)
#   --box NAME         splunk | webmail | ecomm | fileshare | gitea | web |
#                      other (asked).  fileshare keeps 139, 445, 2049, 111;
#                      gitea keeps 3000 and 2222 (its SSH), 80, 443; web
#                      (a ticket, help-desk or shop site) keeps 80, 443
#   --timer SECONDS    revert countdown (default 120); --no-timer
#   --no-color         no colours
#   --help             this text plus the common options
#
# OUTPUTS  (under --out, in remote-access-N/)
#   output.txt, findings.txt, plan.txt, summary.txt, run.txt, revert.sh
#
# DEPENDS ON
#   ps, ss (or netstat, or busybox netstat); systemctl, OpenRC or service; BT_SERVICE may name a stand-in for
#   "service" (tests).
#
# TESTED ON
#   Ubuntu 24.04 with planted programs (a tunnel, a web terminal, a VNC
#   server and a bind shell, as renamed copies of harmless programs), under
#   dash, bash, busybox sh, ksh93, mksh and yash with gawk, mawk and busybox
#   awk.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - A killed program can be started again by red team's cron job or
#     service: LX-42 finds those.  Run LX-26 --batch again later.
#   - telnet, rsh, FTP, SNMP and the other old services: SV-30.
#   - A remote desktop your team uses: put its port on the protected list.
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
LX-26 Remote access lockdown - tunnels, web terminals, remote desktops, admin panels (SSH: LX-22)
  sudo sh LX-26-remote-access.sh                          look + dry run
  sudo sh LX-26-remote-access.sh --protected p.csv --apply

  --apply            make the changes (without it, dry run only)
  --box NAME         splunk | webmail | ecomm | fileshare | gitea | web | other
  --timer SECONDS    revert countdown (default 120); --no-timer
  --no-color         no colours
  --help             show this text
USAGE
    cc_usage_common
}

BOX=""; TIMER=120; NOTIMER=0; COLOR=1
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --apply)    CC_APPLY=1; shift ;;
        --box)      [ $# -ge 2 ] || cc_die 2 "--box needs a name"; BOX=$2; shift 2 ;;
        --timer)    [ $# -ge 2 ] || cc_die 2 "--timer needs seconds"; TIMER=$2; shift 2 ;;
        --no-timer) NOTIMER=1; shift ;;
        --no-color|--no-colour) COLOR=0; shift ;;
        --help|-h)  usage; exit 0 ;;
        *)          cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
cc_box_valid "$BOX" || cc_die 2 "--box must be one of: $CC_BOXES"
case "$TIMER" in ''|*[!0-9]*) cc_die 2 "--timer needs a whole number" ;; esac

cc_init "LX-26" "Remote access lockdown" changes
cc_detect_os
# shellcheck disable=SC2034  # read by cc_color_init
[ "$COLOR" = 1 ] || CC_NOCOLOR=1
cc_color_init
cc_use_numbered_dir remote-access
rmdir "$CC_RUN_DIR/raw" 2>/dev/null
OUTF="$CC_RUN_DIR/output.txt"
grep -v '\[NOTE\]\|\[DEBUG\]' "$CC_LOG" >"$OUTF" 2>/dev/null || : >"$OUTF"
# shellcheck disable=SC2034  # CC_TEE is read by the library's log functions
CC_TEE=$OUTF
W="$CC_RUN_DIR/.work"; mkdir -p "$W"
# Fields are split on the unit separator (\037): unlike a tab it is not
# whitespace, so empty fields stay in place.
TAB=$(printf '\037')
header() { cc_show "" ""; cc_show "$C_CYN" "==========[ $1 ]=========="; }

cc_show "$C_CYN" "LX-26 Remote access lockdown | host $CC_HOST | results in $CC_RUN_DIR"
cc_show "" "Legend: ${C_RED}[!] HIGH${C_OFF}   ${C_YEL}[*] MED${C_OFF}   ${C_GRY}[-] LOW${C_OFF}   ${C_GRN}[ok]${C_OFF} fine   ${C_YEL}[~] would stop${C_OFF}   ${C_GRN}[+] stopped${C_OFF}   ${C_RED}[x] failed${C_OFF}"

if [ -z "$BOX" ]; then
    cc_box_ask o "${R:-}" "Which box is this? (its scored ports are never offered)"
fi
# Ports that are scored on this box: never offered.
case "$BOX" in
    splunk)    SCORED_PORTS="22 8000 8089 123" ;;
    webmail)   SCORED_PORTS="22 25 80 443 143 993 587" ;;
    ecomm|web) SCORED_PORTS="80 443" ;;
    fileshare) SCORED_PORTS="139 445 2049 111" ;;
    gitea)     SCORED_PORTS="3000 2222 80 443" ;;
    *)         SCORED_PORTS="" ;;
esac

# ---- What to look for --------------------------------------------------------------------
# level|kind|program names (ps comm, space separated)|service names|what it is
cat >"$W/table" <<'EOF'
HIGH|tunnel|ngrok chisel frpc frps cloudflared bore gost ligolo ligolo-ng ligolo-agent rathole inlets pgrok zrok sshuttle wstunnel sshx|ngrok cloudflared frpc frps chisel|a tunnel out past the firewall
HIGH|tunnel|tailscaled tailscale zerotier-one|tailscaled zerotier-one|a mesh VPN (a way in that skips the firewall)
HIGH|tunnel|iodine iodined dnscat dnscat2 dnscat2-server ptunnel ptunnel-ng icmptunnel|iodined|a DNS or ICMP tunnel (data hidden in lookups or pings)
HIGH|web terminal|ttyd gotty shellinaboxd shellinabox wetty tmate butterfly code-server jupyter jupyter-lab jupyter-noteboo jupyter-notebook|ttyd shellinabox wetty code-server|a shell in a web browser
HIGH|remote desktop|x11vnc Xvnc Xtightvnc Xtigervnc x0vncserver vncserver vnc4server xrdp xrdp-sesman nxserver nxd nxnode teamviewerd TeamViewer anydesk rustdesk hbbs hbbr vino-server krfb gnome-remote-de grd-daemon meshagent guacd dwagent chrome-remote-d chrome-remote-desktop xpra|xrdp xrdp-sesman x11vnc vncserver nxserver teamviewerd anydesk rustdesk gnome-remote-desktop meshagent guacd dwagent chrome-remote-desktop xpra|a remote desktop
MED|admin panel|miniserv.pl cockpit-ws cockpit-tls usermin ispconfig virtualmin|webmin cockpit cockpit.socket usermin|a web admin panel (root on the box from a browser)
MED|desktop control|kdeconnectd barriers barrierc synergys synergyc input-leaps input-leapc|barrier synergy|keyboard and mouse from another machine
EOF
# ps: pid|comm|args
# (zombies - already dead, waiting for their parent - are left out)
ps -eo pid=,stat=,comm=,args= 2>/dev/null | awk '$2 !~ /^Z/ { p = $1; c = $3; $1 = ""; $2 = ""; $3 = ""; sub(/^   /, ""); print p "|" c "|" $0 }' >"$W/ps"
# listening: port|pid|comm  (tcp and udp)
if cc_have ss; then
    ss -lntup 2>/dev/null | awk 'NR > 1 { n = split($5, a, ":"); port = a[n]; pid = ""; c = ""; if (match($0, /pid=[0-9]+/)) pid = substr($0, RSTART + 4, RLENGTH - 4); if (match($0, /\(\("[^"]+"/)) c = substr($0, RSTART + 3, RLENGTH - 4); print port "|" pid "|" c }' | sort -u >"$W/listen"
else
    # Alpine: no ss, busybox netstat ("PID/name" in the last column).  A
    # box with neither: busybox's own.
    NETSTAT=netstat; cc_have netstat || { cc_have busybox && NETSTAT="busybox netstat"; }
    $NETSTAT -lntup 2>/dev/null | awk '$1 ~ /^(tcp|udp)/ { n = split($4, a, ":"); pid = ""; c = ""; if (match($NF, /^[0-9]+\//)) { pid = substr($NF, 1, RLENGTH - 1); c = substr($NF, RLENGTH + 1) } print a[n] "|" pid "|" c }' | sort -u >"$W/listen"
fi
# Live connections from another machine: localport|remote address, from
#   ss (or netstat).  A tool someone is logged in through right now - maybe
#   you, over VNC or telnet - is kept by default.  BT_TEST_ESTAB names a
#   stand-in file of "port|address" lines for the tests.
if [ -n "${BT_TEST_ESTAB:-}" ]; then cat "$BT_TEST_ESTAB" >"$W/estab" 2>/dev/null || : >"$W/estab"
elif cc_have ss; then
    ss -tn state established 2>/dev/null | awk '$1 ~ /^[0-9]+$/ { n = split($3, a, ":"); r = $4; sub(/:[0-9]+$/, "", r); gsub(/^\[|\]$/, "", r); print a[n] "|" r }' >"$W/estab"
else
    ${NETSTAT:-netstat} -tn 2>/dev/null | awk '$6 == "ESTABLISHED" { n = split($4, a, ":"); r = $5; sub(/:[0-9]+$/, "", r); print a[n] "|" r }' >"$W/estab"
fi
awk -F'|' '$2 !~ /^(127\.|::1$|::ffff:127\.)/' "$W/estab" >"$W/estab.t" && mv "$W/estab.t" "$W/estab"
# in_use PID -> "N connection(s) from A B" when a port of PID has a live
#   connection from another machine; nothing otherwise.
in_use() {
    [ -n "$1" ] || return 0
    for _iu in $(port_of "$1"); do awk -F'|' -v p="$_iu" '$1 == p { print $2 }' "$W/estab"; done | sort -u >"$W/iu"
    [ -s "$W/iu" ] && printf '%s connection(s) from %s' "$(grep -c . "$W/iu")" "$(head -n 3 "$W/iu" | tr '\n' ' ' | sed 's/ $//')"
    return 0
}
# exe PID -> the program file (or "(deleted)")
exe() { ls -l "/proc/$1/exe" 2>/dev/null | sed 's/.* -> //'; }
port_of() { awk -F'|' -v p="$1" '$2 == p { printf "%s ", $1 }' "$W/listen" | sed 's/ $//'; }
svc_exists() { cc_svc exists "$1"; }

# Findings: level<TAB>kind<TAB>name<TAB>pid<TAB>service<TAB>file<TAB>what
: >"$W/find"
add() { printf '%s\037%s\037%s\037%s\037%s\037%s\037%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" >>"$W/find"; }
header "1/4  looking"
while IFS='|' read -r _lv _kind _progs _svcs _what; do
    for _p in $_progs; do
        awk -F'|' -v c="$_p" '$2 == c || ($2 ~ /^(perl|python|python3|node)$/ && $3 ~ ("(^|[ /])" c "( |$)"))' "$W/ps" | while IFS='|' read -r _pid _c _args; do
            _x=$(exe "$_pid"); _po=$(port_of "$_pid")
            add "$_lv" "$_kind" "$_p" "$_pid" "" "$_x" "$_what: $_c (pid $_pid${_po:+, port $_po}) $(printf '%s' "$_args" | cut -c1-90)"
        done
    done
    for _s in $_svcs; do
        svc_exists "$_s" || continue
        awk -F'\037' -v s="$_s" '$5 == s { f = 1 } END { exit !f }' "$W/find" && continue
        _on=no
        cc_svc is-enabled "$_s" >/dev/null 2>&1 && _on=yes
        [ "$_on" = yes ] && add "$_lv" "$_kind" "$_s" "" "$_s" "" "$_what: the $_s service starts at boot"
    done
done <"$W/table"
# Shells and netcat holding the network: bind / reverse shells.
while IFS='|' read -r _pid _c _args; do
    case "$_c|$_args" in
        nc\|*" -e "*|nc\|*" -c "*|ncat\|*" -e "*|ncat\|*--exec*|ncat\|*--sh-exec*|netcat\|*" -e "*|nc.traditional\|*" -e "*|nc.openbsd\|*" -e "*|busybox\|*"nc "*" -e "*)
            add HIGH shell "$_c" "$_pid" "" "$(exe "$_pid")" "netcat that runs a program for whoever connects (pid $_pid): $(printf '%s' "$_args" | cut -c1-80)" ;;
        socat\|*exec:*|socat\|*EXEC:*|socat\|*system:*|socat\|*SYSTEM:*)
            add HIGH shell "$_c" "$_pid" "" "$(exe "$_pid")" "socat that runs a program (pid $_pid): $(printf '%s' "$_args" | cut -c1-90)" ;;
        ssh\|*" -R "*|ssh\|*" -R"[0-9]*|ssh\|*"-fNR"*|ssh\|*"-NR"*)
            add HIGH tunnel ssh "$_pid" "" "$(exe "$_pid")" "an SSH reverse tunnel (opens a way back in from outside): $(printf '%s' "$_args" | cut -c1-90)" ;;
        python*\|*http.server*|python*\|*SimpleHTTPServer*|php\|*" -S "*|busybox\|*httpd*|ruby\|*httpd*|ruby\|*un.rb*)
            add MED "file share" "$_c" "$_pid" "" "$(exe "$_pid")" "a quick web server (anyone can download files): $(printf '%s' "$_args" | cut -c1-80)" ;;
    esac
done <"$W/ps"
# A shell (sh, bash, ...) whose own input is a network socket.
for _s in $(awk -F'|' '$2 ~ /^(sh|bash|dash|zsh|ksh|mksh|ash)$/ { print $1 }' "$W/ps"); do
    _l0=$(readlink "/proc/$_s/fd/0" 2>/dev/null); case "$_l0" in socket:*) ;; *) continue ;; esac
    _sp=$(printf '%s' "$_l0" | sed 's/socket:\[\([0-9]*\)\]/\1/')
    grep -q " $_sp " /proc/net/tcp /proc/net/tcp6 2>/dev/null || continue
    add HIGH shell "$(awk -F'|' -v p="$_s" '$1 == p { print $2 }' "$W/ps")" "$_s" "" "$(exe "$_s")" "a shell whose keyboard is a network connection (reverse or bind shell): pid $_s"
done
# Database panels: listed only.
for _d in /usr/share/phpmyadmin /var/www/html/phpmyadmin /var/www/phpmyadmin /usr/share/adminer; do [ -d "$_d" ] && add LOW "db panel" "$(basename "$_d")" "" "" "$_d" "a database panel on the web ($_d): keep it only if you use it, and behind a password"; done
find /var/www /srv -maxdepth 4 -name 'adminer*.php' 2>/dev/null | while IFS= read -r _f; do add LOW "db panel" adminer "" "" "$_f" "Adminer ($_f): a one-file database panel"; done

# Drop what is scored or protected.
: >"$W/keep"
while IFS="$TAB" read -r _lv _kind _n _pid _svc _f _what; do
    _po=""; [ -n "$_pid" ] && _po=$(port_of "$_pid")
    _skip=""
    for _p in $_po; do case " $SCORED_PORTS " in *" $_p "*) _skip="scored port $_p" ;; esac; cc_is_protected port "$_p" && _skip="protected port $_p"; done
    cc_is_protected service "${_svc:-$_n}" && _skip="protected"
    printf '%s\037%s\037%s\037%s\037%s\037%s\037%s\037%s\n' "$_lv" "$_kind" "$_n" "$_pid" "$_svc" "$_f" "$_what" "$_skip" >>"$W/keep"
done <"$W/find"
# HIGH first, then MED, then LOW.
sort -u "$W/keep" | awk -F'\037' '{ print ($1 == "HIGH" ? 1 : ($1 == "MED" ? 2 : 3)) "\037" $0 }' | sort -t"$TAB" -k1,1n | cut -d"$TAB" -f2- >"$W/find"
while IFS="$TAB" read -r _lv _kind _n _pid _svc _f _what _skip; do
    case "$_lv" in HIGH) _c=$C_RED; _m='[!]' ;; MED) _c=$C_YEL; _m='[*]' ;; *) _c=$C_GRY; _m='[-]' ;; esac
    cc_show "$_c" "  $_m $_lv $_kind: $_what${_skip:+   (kept: $_skip)}"
    _iu=$(in_use "$_pid"); [ -n "$_iu" ] && cc_show "$C_RED" "      IN USE NOW: $_iu - if that is you or your team, keep it (stopping it cuts the session)"
done <"$W/find"
[ -s "$W/find" ] || cc_show "$C_GRN" "  [ok] no tunnel, web terminal, remote desktop, admin panel or network shell found"

# ---- Questions ------------------------------------------------------------------------------
header "2/4  questions (Enter = the default in capitals)"
: >"$W/chosen"
awk -F'\037' '$1 != "LOW" && $8 == ""' "$W/find" >"$W/ask"
_all=0
while IFS="$TAB" read -r _lv _kind _n _pid _svc _f _what _skip; do
    _d=k; [ "$_lv" = HIGH ] && _d=s
    # Someone is connected through it now (maybe you, over VNC or telnet): keep by default.
    _iu=$(in_use "$_pid"); [ -n "$_iu" ] && _d=k
    if [ "$_all" = 0 ]; then
        [ -n "$_iu" ] && cc_show "$C_RED" "  [!] IN USE NOW ($_iu): stopping it cuts that session - keep it if it is you"
        _how="kill it"; [ -n "$_svc" ] && _how="stop the $_svc service and disable it at boot"
        case "$_f" in /tmp/*|/var/tmp/*|/dev/shm/*|/home/*|/root/*|*"(deleted)"*) _how="$_how; quarantine $_f" ;; esac
        cc_choose "$_lv $_kind: $_what?" "$_d" "s=stop it ($_how)" "k=keep it" "a=all the rest: take their defaults (HIGH stopped, MED and in-use kept)"
        case "$CC_CHOICE" in a) _all=1 ;; s) printf '%s\n' "$_lv$TAB$_kind$TAB$_n$TAB$_pid$TAB$_svc$TAB$_f$TAB$_what" >>"$W/chosen"; continue ;; k) continue ;; esac
    fi
    [ "$_d" = s ] && printf '%s\n' "$_lv$TAB$_kind$TAB$_n$TAB$_pid$TAB$_svc$TAB$_f$TAB$_what" >>"$W/chosen"
done <"$W/ask"
NCH=$(grep -c . "$W/chosen")
cut -d"$TAB" -f7 "$W/chosen" | sed 's/^/stop: /' >"$CC_RUN_DIR/plan.txt"

# ---- Apply ----------------------------------------------------------------------------------
header "3/4  plan"
while IFS= read -r _l; do cc_show "$C_YEL" "  [~] $_l"; done <"$CC_RUN_DIR/plan.txt"
[ "$NCH" -eq 0 ] && cc_show "$C_GRN" "  [ok] Nothing to stop."
header "4/4  apply"
SERVICE=${BT_SERVICE:-service}
# alive PID -> running (a zombie is dead, only waiting for its parent)
alive() { kill -0 "$1" 2>/dev/null && ! ps -o stat= -p "$1" 2>/dev/null | grep -q '^Z'; }
svc_off() {   # svc_off NAME -> stop and disable; undo enables and starts
    if [ "$CC_INIT" = systemd ] && [ -z "${BT_SERVICE:-}" ]; then
        cc_undo_add "enable and start $1 again" "systemctl enable $1; systemctl start $1"
        systemctl stop "$1" && systemctl disable "$1"
    elif [ "${BT_SVC_INIT:-$CC_INIT}" = openrc ] && [ -z "${BT_SERVICE:-}" ]; then
        cc_undo_add "enable and start $1 again" "$(cc_svc_cmd enable "$1"); $(cc_svc_cmd start "$1")"
        cc_svc stop "$1"; cc_svc disable "$1"
    else
        cc_undo_add "enable and start $1 again" "update-rc.d $1 enable 2>/dev/null; $SERVICE $1 start"
        "$SERVICE" "$1" stop; update-rc.d "$1" disable 2>/dev/null; return 0
    fi
}
NOK=0; NBAD=0; APPLIED=0; TIMER_ON=0
if [ "$NCH" -eq 0 ]; then :
elif [ "$CC_APPLY" != 1 ] || ! cc_is_root; then
    cc_is_root || cc_show "$C_YEL" "  [!] not root: showing the plan only"
    cc_show "$C_GRY" "  Dry run: nothing was changed. Run again with --apply."
    # shellcheck disable=SC2034  # read by cc_finish
    CC_N_WOULD=$NCH
elif cc_ask "Stop these $NCH?" Y "yes, stop them (services come back on the undo; killed programs do not)" "no, leave them"; then
    APPLIED=1
    if [ "$NOTIMER" != 1 ]; then cc_timer_start "$TIMER"; TIMER_ON=1
        cc_show "$C_YEL" "  [*] Revert timer started: disabled services come back in $((TIMER / 60)):$(printf '%02d' $((TIMER % 60))) unless you keep it at the end."; fi
    while IFS="$TAB" read -r _lv _kind _n _pid _svc _f _what; do
        _ok=1
        if [ -n "$_svc" ]; then svc_off "$_svc" >>"$CC_LOG" 2>&1 || _ok=0; fi
        if [ -n "$_pid" ] && alive "$_pid"; then
            kill "$_pid" 2>>"$CC_LOG"; sleep 1; alive "$_pid" && kill -9 "$_pid" 2>>"$CC_LOG"
            sleep 1; alive "$_pid" && _ok=0
        fi
        case "$_f" in /tmp/*|/var/tmp/*|/dev/shm/*|/home/*|/root/*) [ -f "$_f" ] && { cc_quarantine "$_f" >>"$CC_LOG" 2>&1 || _ok=0; } ;; esac
        if [ "$_ok" = 1 ]; then NOK=$((NOK + 1)); cc_show "$C_GRN" "  [+] stopped: $_what"; else NBAD=$((NBAD + 1)); cc_show "$C_RED" "  [x] could not stop: $_what"; fi
    done <"$W/chosen"
else cc_show "$C_GRY" "  Not stopped."; fi
# shellcheck disable=SC2034  # read by cc_finish
CC_N_DONE=$NOK
# shellcheck disable=SC2034  # read by cc_finish
CC_N_FAIL=$NBAD

awk -F'\037' '{ printf "%-4s %-15s %s%s\n", $1, $2, $7, ($8 != "" ? "   (kept: " $8 ")" : "") }' "$W/find" >"$CC_RUN_DIR/findings.txt"
{
    printf '==========[ summary ]==========\n'
    printf 'LX-26 Remote access lockdown | host %s | %s\n' "$CC_HOST" "$([ "$APPLIED" = 1 ] && echo APPLIED || echo 'DRY RUN - nothing changed')"
    printf 'Found: %d HIGH, %d MED, %d LOW\n' "$(grep -c "^HIGH$TAB" "$W/find")" "$(grep -c "^MED$TAB" "$W/find")" "$(grep -c "^LOW$TAB" "$W/find")"
    awk -F'\037' '{ printf "  %-4s %s\n", $1, substr($7, 1, 140) }' "$W/find"
    [ "$APPLIED" = 1 ] && printf 'Stopped: %d   Failed: %d\n' "$NOK" "$NBAD"
    [ "$APPLIED" = 1 ] && [ -f "$CC_RUN_DIR/revert.sh" ] && printf 'Undo (services only): sh %s/revert.sh --force\n' "$CC_RUN_DIR"
    printf '\nWhat starts them again (cron, services, .bashrc): LX-42.  SSH: LX-22.  telnet/rsh/FTP/SNMP: SV-30.\n'
} >"$CC_RUN_DIR/summary.txt"
cc_show "" ""
while IFS= read -r _l; do
    case "$_l" in ==*|LX-26*) cc_show "$C_CYN" "$_l" ;; '  HIGH'*) cc_show "$C_RED" "$_l" ;; '  MED'*) cc_show "$C_YEL" "$_l" ;; *) cc_show "" "$_l" ;; esac
done <"$CC_RUN_DIR/summary.txt"
rm -rf "$W"
if [ "$TIMER_ON" = 1 ]; then header "KEEP OR REVERT"; cc_timer_finish || true; fi
cc_finish
