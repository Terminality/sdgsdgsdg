#!/bin/sh
# =============================================================================
# ID:       LX-45
# NAME:     Rootkit and malware scan
# ROLE:     Linux  (wave 2, then whenever something feels off)
# KIND:     changes - dry run unless --apply (it only kills and quarantines)
# VERSION:  1.0.0
#
# PURPOSE
#   LX-42 finds what red team leaves to come back (cron, services, keys).
#   This looks for what hides: a rootkit that lies to ps, ss and ls, a
#   kernel module that is not listed, a replaced ps or ssh, a miner using
#   the CPU, malware in the temp and web folders.
#
#     hidden processes   a process in /proc that ps does not show
#     hidden ports       a port listening in /proc/net that ss does not show
#     hidden modules     a kernel module in /sys/module that /proc/modules
#                        (lsmod) does not list; out-of-tree or unsigned
#                        modules (the kernel's taint flags); known rootkit
#                        module names (diamorphine, reptile, suterusu ...)
#     replaced programs  ps, ss, netstat, ls, find, top, lsof, ssh, sshd,
#                        sudo, login, passwd ... that do not match their
#                        package (dpkg -V / rpm -V)
#     rootkit files      paths known rootkits leave (/etc/ld.so.preload is
#                        LX-42's; here: reptile, azazel, jynx, bdvl, beurk,
#                        diamorphine leftovers and the like)
#     fake kernel threads  a program named like [kworker/0:1] that has a
#                        program file (real kernel threads have none)
#     miners             known miner names, and connections to mining ports
#     sniffers           network cards in promiscuous mode
#     malware            ClamAV, rkhunter and chkrootkit when installed
#                        (ClamAV over /tmp, /var/tmp, /dev/shm, the web
#                        folders and the homes); offered to install when the
#                        box can reach a package mirror
#
#   Then asked, one by one: kill a hidden / fake / miner process, quarantine
#   a malware or rootkit file.  Kernel modules are reported, not unloaded
#   (unloading a rootkit module often crashes the box): the fix is to
#   remove what loads it (LX-42) and reboot.
#
#   QUESTIONS (Enter takes the default in capitals; a flag answers each):
#     install ClamAV / rkhunter now?      --install / --no-install
#     each finding: [k]ill / [q]uarantine / [l]eave / [a]ll the rest default
#     apply?                              --apply
#
# USAGE
#   sudo sh LX-45-rootkit-scan.sh                             scan, dry run
#   sudo sh LX-45-rootkit-scan.sh --protected p.csv --apply   asks about each
#   sudo sh LX-45-rootkit-scan.sh --protected p.csv --apply --batch --no-install
#
# OPTIONS
#   --apply            kill / quarantine (without it, dry run only)
#   --install          install clamav and rkhunter if missing (needs a mirror)
#   --no-install       never offer it
#   --no-clamav        skip the ClamAV scan (it can take minutes)
#   --scan DIR         also scan this folder with ClamAV (repeatable)
#   --root DIR         treat DIR as / for the file checks (tests)
#   --no-color         no colours
#   --help             this text plus the common options
#
# OUTPUTS  (under --out, in rootkit-N/)
#   output.txt, findings.txt, summary.txt, clamav.txt / rkhunter.txt /
#   chkrootkit.txt when they ran; quarantined files and their undo lines
#
# DEPENDS ON
#   ps, ss, awk, /proc and /sys; dpkg or rpm for the program check;
#   clamscan, rkhunter, chkrootkit when present.
#
# TESTED ON
#   Ubuntu 24.04 with stand-ins (a miner, a fake kernel thread, a replaced
#   program, rootkit file paths in a fake root, an EICAR test file for
#   ClamAV), under dash, bash, busybox sh, ksh93, mksh and yash with gawk,
#   mawk and busybox awk.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - A kernel rootkit can hide from /proc too.  If this finds nothing but
#     the box still feels wrong, check from outside (SH-03 scan of the box:
#     a port open there but not in ss is hidden).
#   - The "hidden" checks compare two views a split second apart: a process
#     that just ended can show once.  Run it twice before acting.
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
LX-45 Rootkit and malware scan - hidden processes, ports and modules, replaced programs, miners, malware
  sudo sh LX-45-rootkit-scan.sh                          scan, dry run
  sudo sh LX-45-rootkit-scan.sh --protected p.csv --apply

  --apply            kill / quarantine (without it, dry run only)
  --install          install clamav and rkhunter if missing
  --no-install       never offer it
  --no-clamav        skip the ClamAV scan
  --scan DIR         also scan this folder with ClamAV (repeatable)
  --root DIR         treat DIR as / for the file checks (tests)
  --no-color         no colours
  --help             show this text
USAGE
    cc_usage_common
}

NL='
'
INSTALL=""; CLAM=1; EXTRA=""; R=""; COLOR=1
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --apply)      CC_APPLY=1; shift ;;
        --install)    INSTALL=y; shift ;;
        --no-install) INSTALL=n; shift ;;
        --no-clamav)  CLAM=0; shift ;;
        --scan)       [ $# -ge 2 ] || cc_die 2 "--scan needs a folder"; [ -d "$2" ] || cc_die 2 "--scan: not a folder: $2"; EXTRA="$EXTRA$(cc_abspath "$2")$NL"; shift 2 ;;
        --root)       [ $# -ge 2 ] || cc_die 2 "--root needs a folder"; [ -d "$2" ] || cc_die 2 "--root: not a folder: $2"; R=$(cd "$2" && pwd); [ "$R" = / ] && R=""; shift 2 ;;
        --no-color|--no-colour) COLOR=0; shift ;;
        --help|-h)    usage; exit 0 ;;
        *)            cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done

cc_init "LX-45" "Rootkit and malware scan" changes
cc_detect_os
# shellcheck disable=SC2034  # read by cc_color_init
[ "$COLOR" = 1 ] || CC_NOCOLOR=1
cc_color_init
cc_use_numbered_dir rootkit
rmdir "$CC_RUN_DIR/raw" 2>/dev/null
OUTF="$CC_RUN_DIR/output.txt"
grep -v '\[NOTE\]\|\[DEBUG\]' "$CC_LOG" >"$OUTF" 2>/dev/null || : >"$OUTF"
# shellcheck disable=SC2034  # CC_TEE is read by the library's log functions
CC_TEE=$OUTF
W="$CC_RUN_DIR/.work"; mkdir -p "$W"
# Findings: level, area, what, fix (kill|quarantine|none), target - split on \037
US=$(printf '\037')
header() { cc_show "" ""; cc_show "$C_CYN" "==========[ $1 ]=========="; }
P() { printf '%s%s' "$R" "$1"; }
: >"$W/find"
f() {
    printf '%s\037%s\037%s\037%s\037%s\n' "$1" "$2" "$3" "$4" "$5" >>"$W/find"
    case "$1" in HIGH) cc_show "$C_RED" "  [!] $3" ;; MED) cc_show "$C_YEL" "  [*] $3" ;; esac
}
ok() { cc_show "$C_GRN" "  [ok] $1"; }

cc_show "$C_CYN" "LX-45 Rootkit and malware scan | host $CC_HOST | results in $CC_RUN_DIR"
cc_show "" "Legend: ${C_RED}[!] HIGH${C_OFF}   ${C_YEL}[*] MED${C_OFF}   ${C_GRN}[ok]${C_OFF} clean   ${C_YEL}[~] would change${C_OFF}   ${C_GRN}[+] done${C_OFF}   ${C_RED}[x] failed${C_OFF}"
[ -n "$R" ] && cc_show "$C_GRY" "File checks on $R as if it were / (the process, port and module checks look at this box)"

# ---- 1. Hidden processes and ports -----------------------------------------------------
header "1/6  hidden processes and ports"
# What ps shows, and what /proc has - twice, to drop processes that ended
# in between.
hidden_procs() {
    ps -e -o pid= 2>/dev/null | tr -d ' ' | sort -n >"$W/ps.$1"
    for _d in /proc/[0-9]*; do printf '%s\n' "${_d#/proc/}"; done | sort -n >"$W/proc.$1"
    comm -13 "$W/ps.$1" "$W/proc.$1"
}
hidden_procs a >"$W/hid.a"; sleep 1; hidden_procs b >"$W/hid.b"
# A ps that cannot list everything (a cut-down busybox, a container without
# the rights) would make every process look hidden - and the default answer
# is "kill".  Only compare when ps sees most of /proc.
_nps=$(grep -c . "$W/ps.b"); _npr=$(grep -c . "$W/proc.b")
if [ "$_nps" -lt $((_npr / 2)) ]; then
    cc_show "$C_YEL" "  [*] ps lists $_nps processes but /proc has $_npr: this ps cannot be trusted for the hidden-process check (skipped)"
    : >"$W/hid.a"
fi
# Threads (/proc/PID/task) are not separate processes: only real ones count.
comm -12 "$W/hid.a" "$W/hid.b" | while IFS= read -r _p; do
    [ -r "/proc/$_p/status" ] || continue
    _tg=$(awk '$1 == "Tgid:" { print $2 }' "/proc/$_p/status" 2>/dev/null)
    [ "$_tg" = "$_p" ] || continue
    _c=$(cat "/proc/$_p/comm" 2>/dev/null); _x=$(readlink "/proc/$_p/exe" 2>/dev/null)
    f HIGH process "a process ps does NOT show: pid $_p ($_c, $_x) - something is hiding it" kill "$_p $_c"
done
[ "$_nps" -lt $((_npr / 2)) ] || grep -q "${US}process${US}" "$W/find" || ok "every process in /proc is shown by ps"
# Ports: /proc/net/tcp state 0A = LISTEN; ports in hex.
awk 'FNR > 1 && $4 == "0A" { split($2, a, ":"); print a[2] }' /proc/net/tcp /proc/net/tcp6 2>/dev/null | sort -u | while IFS= read -r _h; do
    printf '%d\n' "0x$_h"; done | sort -un >"$W/pp"
ss -lnt 2>/dev/null | awk 'NR > 1 { n = split($4, a, ":"); print a[n] }' | sort -un >"$W/sp"
_hp=$(comm -23 "$W/pp" "$W/sp" | tr '\n' ' ')
if ! cc_have ss || { [ -s "$W/pp" ] && [ ! -s "$W/sp" ]; }; then cc_show "$C_YEL" "  [*] ss is missing or lists nothing: hidden-port check skipped"
elif [ -n "$_hp" ]; then f HIGH port "listening in /proc/net/tcp but NOT shown by ss: $_hp- something is hiding it (check with SH-03 from another box)" none ""
else ok "every listening TCP port in /proc is shown by ss"; fi

# ---- 2. Kernel modules ----------------------------------------------------------------------
header "2/6  kernel modules"
awk '{ print $1 }' /proc/modules 2>/dev/null | sort >"$W/mods"
# A loaded module has /sys/module/NAME/initstate; built-in ones do not.
for _m in /sys/module/*/initstate; do [ -f "$_m" ] || continue; _n=${_m%/initstate}; basename "$_n"; done | sort >"$W/sysmods"
_hm=$(comm -13 "$W/mods" "$W/sysmods" | tr '\n' ' ')
[ -n "$_hm" ] && f HIGH module "loaded but hidden from lsmod: $_hm- a kernel rootkit" none ""
_bad=$(grep -Eiw 'diamorphine|reptile|reptile_module|suterusu|kovid|nuk3gh0st|rootfoo|adore|knark|enyelkm|wnps|sutekh|kbeast|vlany|bdvl|puszek|khook|singularity|lkm_rootkit' "$W/mods" | tr '\n' ' ')
[ -n "$_bad" ] && f HIGH module "a module with a known rootkit name is loaded: $_bad" none ""
_t=$(cat /proc/sys/kernel/tainted 2>/dev/null); _t=${_t:-0}
if [ "$_t" -ne 0 ]; then
    _why=""; [ $((_t & 4096)) -ne 0 ] && _why="$_why out-of-tree module;"; [ $((_t & 8192)) -ne 0 ] && _why="$_why unsigned module;"; [ $((_t & 1)) -ne 0 ] && _why="$_why proprietary module;"; [ $((_t & 2)) -ne 0 ] && _why="$_why forced load;"
    if [ -n "$_why" ]; then
        _oot=""; while IFS= read -r _m; do [ -r "/sys/module/$_m/taint" ] && case "$(cat "/sys/module/$_m/taint")" in *O*|*E*|*P*|*F*) _oot="$_oot $_m($(cat "/sys/module/$_m/taint"))" ;; esac; done <"$W/mods"
        f MED module "the kernel is tainted ($_t):$_why modules:${_oot:- none listed} - fine for VirtualBox/VMware/NVIDIA drivers, not otherwise" none ""
    fi
fi
grep -q "${US}module${US}" "$W/find" || ok "$(grep -c . "$W/mods") modules, none hidden, none with a rootkit name, kernel not tainted by one"

# ---- 3. Replaced programs --------------------------------------------------------------------
header "3/6  replaced programs"
CORE="ps ss netstat ls find top lsof ssh sshd sudo su login passwd w who last lastlog grep cat crontab systemctl ip ifconfig kill pgrep pkill du df stat md5sum sha256sum"
: >"$W/replaced"
if [ -z "$R" ] && cc_have dpkg; then
    for _b in $CORE; do _p=$(cc_which "$_b") || continue; printf '%s\n' "$_p"; done | sort -u >"$W/bins"
    while IFS= read -r _p; do
        # With the merged /usr, dpkg may list /usr/bin/ss as /bin/ss.
        _pk=""; _tgt=$_p; _i=0
        # alternatives: /usr/bin/x -> /etc/alternatives/x -> /usr/bin/x.real
        while [ -h "$_tgt" ] && [ "$_i" -lt 5 ]; do _l=$(readlink "$_tgt"); case "$_l" in /*) _tgt=$_l ;; *) _tgt="$(dirname "$_tgt")/$_l" ;; esac; _i=$((_i + 1)); done
        for _q in "$_p" "$_tgt" "$(printf '%s' "$_p" | sed 's|^/usr/bin/|/bin/|; s|^/usr/sbin/|/sbin/|')" "$(printf '%s' "$_p" | sed 's|^/bin/|/usr/bin/|; s|^/sbin/|/usr/sbin/|')"; do
            _pk=$(dpkg -S "$_q" 2>/dev/null | head -n 1 | cut -d: -f1); [ -n "$_pk" ] && break
        done
        if [ -z "$_pk" ]; then f HIGH program "$_p belongs to no package: placed there by hand?" quarantine "$_p"; continue; fi
        printf '%s\n' "$_pk" >>"$W/pkgs"
    done <"$W/bins"
    sort -u "$W/pkgs" 2>/dev/null | while IFS= read -r _pk; do
        dpkg -V "$_pk" 2>/dev/null | awk '$1 ~ /5/ && $2 != "c" { print $NF }'
    done >"$W/changed"
    while IFS= read -r _c; do
        # Only the core programs (dpkg names them by its own path).
        grep -q "/${_c##*/}\$" "$W/bins" || continue
        f HIGH program "$_c does not match its package (replaced?): reinstall it - apt-get install --reinstall $(dpkg -S "$_c" 2>/dev/null | cut -d: -f1 | head -n 1)" none ""
    done <"$W/changed"
elif [ -z "$R" ] && cc_have rpm; then
    for _b in $CORE; do _p=$(cc_which "$_b") || continue; rpm -Vf "$_p" 2>/dev/null | awk -v p="$_p" '$1 ~ /5/ && $NF == p { print p }'; done | sort -u | while IFS= read -r _c; do
        f HIGH program "$_c does not match its package (replaced?): dnf reinstall $(rpm -qf "$_c")" none ""
    done
fi
grep -q "${US}program${US}" "$W/find" || ok "ps, ss, ls, ssh, sudo and the other core programs match their packages"

# ---- 4. Rootkit files, fake kernel threads, miners, sniffers ---------------------------------
header "4/6  rootkit files, fake kernel threads, miners, sniffers"
for _x in /reptile /lib/udev/reptile /etc/reptile /usr/lib/libselinux.so.4 /lib/libsplit.so /usr/local/lib/libpcap.so.0.8 \
          /etc/ld.so.preload.d /lib/libsh /usr/lib/libsh /dev/.hdlc /dev/.mdmon /dev/.lib /dev/.udev/rules.d/.x /usr/bin/.sshd /usr/sbin/.sshd \
          /lib/libext-2.so.7 /etc/xinetd.d/.x /usr/share/.ssh /var/tmp/.ICE-unix /dev/shm/.x /tmp/.X11-unix/.x /usr/lib/x86_64-linux-gnu/libprocesshider.so \
          /usr/local/lib/libprocesshider.so /lib/libprocesshider.so /usr/lib/libjynx.so /lib/libjynx2.so /usr/lib/libazazel.so /lib/libazazel.so \
          /lib/x86_64-linux-gnu/libbdvl.so /usr/lib/libbeurk.so /lib/security/pam_unix2.so /etc/rc.d/init.d/diamorphine; do
    [ -e "$(P "$_x")" ] && f HIGH file "a path rootkits use is there: $_x" quarantine "$(P "$_x")"
done
for _d in /dev /dev/shm; do
    # /dev without /dev/shm (that one has its own pass)
    find "$(P "$_d")" -maxdepth 2 \( -path "$(P /dev/shm)" -a ! -path "$(P "$_d")" \) -prune -o -type f -perm -u+x -print 2>/dev/null | head -n 20 | while IFS= read -r _x; do
        f HIGH file "a program file in ${_d}: ${_x#"$R"} (nothing belongs there)" quarantine "$_x"
    done
done
grep -q "${US}file${US}" "$W/find" || ok "no known rootkit files, no programs in /dev or /dev/shm"
# Fake kernel threads: [name] in ps, but with a program file.
ps -eo pid=,stat=,args= 2>/dev/null | awk '$2 !~ /^Z/ { p = $1; $1 = ""; $2 = ""; sub(/^  /, ""); if ($0 ~ /^\[.*\]/) print p "\t" $0 }' | while IFS="$(printf '\t')" read -r _p _a; do
    _x=$(readlink "/proc/$_p/exe" 2>/dev/null)
    [ -n "$_x" ] && f HIGH process "pid $_p calls itself $_a but runs $_x - real kernel threads have no program" kill "$_p $(cat "/proc/$_p/comm" 2>/dev/null)"
done
# Miners: names and pool ports.
# One snapshot first, then search it (so the search is not in its own list).
# (zombies - already dead, waiting for their parent - are left out)
ps -eo pid=,stat=,comm=,args= 2>/dev/null | awk '$2 !~ /^Z/ { $2 = ""; print }' >"$W/psall"
awk '{ c = tolower($2); a = tolower($0) }
     c ~ /^(xmrig|xmr-stak|xmr-stak-cpu|minerd|cpuminer|cpuminer-multi|kdevtmpfsi|kinsing|ethminer|nbminer|t-rex|phoenixminer|lolminer|srbminer|teamredminer)$/ || a ~ /stratum\+(tcp|ssl):\/\/|--donate-level|--algo[= ]+(rx|cn|randomx|cryptonight)/ { print $1 "\t" $2 }' "$W/psall" | while IFS="$(printf '\t')" read -r _p _c; do
    [ "$_p" = "$$" ] && continue
    f HIGH miner "a crypto miner: pid $_p ($_c, $(readlink "/proc/$_p/exe" 2>/dev/null))" kill "$_p $(cat "/proc/$_p/comm" 2>/dev/null)"
done
ss -tnp 2>/dev/null | awk 'NR > 1 { n = split($5, a, ":"); if (a[n] ~ /^(3333|4444|5555|7777|14433|14444|45700|45560|20580|9999)$/) print $5 " " $NF }' | while IFS= read -r _l; do
    f MED miner "a connection to a usual mining-pool port: $_l" none ""
done
for _i in /sys/class/net/*/flags; do
    [ -r "$_i" ] || continue; _fl=$(cat "$_i")
    [ $(( _fl & 0x100 )) -ne 0 ] && f MED sniffer "$(basename "$(dirname "$_i")") is in promiscuous mode: something is capturing all traffic (tcpdump? fine if it is yours)" none ""
done
grep -Eq "${US}(miner|sniffer)${US}|calls itself" "$W/find" || ok "no fake kernel threads, miners or sniffers"

# ---- 5. Malware scanners ---------------------------------------------------------------------
header "5/6  ClamAV, rkhunter, chkrootkit"
_miss=""; cc_have clamscan || _miss="$_miss clamav"; cc_have rkhunter || _miss="$_miss rkhunter"
if [ -n "$_miss" ] && [ -z "$R" ] && [ "$INSTALL" != n ] && cc_have apt-get; then
    if [ "$INSTALL" = y ] || cc_ask "Install$_miss now (needs a package mirror; about 300 MB for ClamAV)?" N "yes, install them" "no, scan without them"; then
        if [ "$CC_APPLY" = 1 ] && cc_is_root; then
            cc_show "" "  installing$_miss ..."
            # shellcheck disable=SC2086  # a list of package names
            DEBIAN_FRONTEND=noninteractive $(cc_have timeout && echo timeout 600) apt-get install -y -q $_miss >>"$CC_LOG" 2>&1 && cc_show "$C_GRN" "  [+] installed$_miss" || cc_show "$C_RED" "  [x] could not install$_miss (no mirror?)"
        else cc_show "$C_GRY" "  (installing needs --apply and root)"; fi
    fi
fi
SCAN=""
for _d in /tmp /var/tmp /dev/shm /var/www /srv /home /root /usr/share/roundcube; do [ -d "$(P "$_d")" ] && SCAN="$SCAN$(P "$_d")$NL"; done
SCAN="$SCAN$EXTRA"
if [ "$CLAM" = 1 ] && cc_have clamscan; then
    cc_show "" "  ClamAV over: $(printf '%s' "$SCAN" | tr '\n' ' ')(can take a few minutes)"
    # shellcheck disable=SC2046  # the folder list
    clamscan -r -i --no-summary --max-filesize=20M $(printf '%s' "$SCAN" | tr '\n' ' ') >"$CC_RUN_DIR/clamav.txt" 2>>"$CC_LOG"
    sed -n 's/^\(.*\): \(.*\) FOUND$/\1\037\2/p' "$CC_RUN_DIR/clamav.txt" | while IFS="$US" read -r _x _sig; do
        f HIGH malware "ClamAV: ${_x#"$R"} is $_sig" quarantine "$_x"
    done
    grep -q "${US}malware${US}" "$W/find" || ok "ClamAV found nothing (signatures from $(sigtool --info /var/lib/clamav/daily.c?d 2>/dev/null | sed -n 's/^Build time: //p' | head -n 1))"
else cc_show "$C_GRY" "  ClamAV: not installed (or --no-clamav)"; fi
if [ -z "$R" ] && cc_have rkhunter; then
    rkhunter --check --sk --nocolors --rwo >"$CC_RUN_DIR/rkhunter.txt" 2>>"$CC_LOG"
    grep -i 'warning' "$CC_RUN_DIR/rkhunter.txt" | head -n 15 | while IFS= read -r _l; do f MED rkhunter "rkhunter: $_l" none ""; done
    grep -qi warning "$CC_RUN_DIR/rkhunter.txt" || ok "rkhunter: no warnings"
fi
if [ -z "$R" ] && cc_have chkrootkit; then
    chkrootkit -q >"$CC_RUN_DIR/chkrootkit.txt" 2>>"$CC_LOG"
    grep -iE 'INFECTED|Vulnerable|suspicious|Possible' "$CC_RUN_DIR/chkrootkit.txt" | head -n 15 | while IFS= read -r _l; do f MED chkrootkit "chkrootkit: $_l" none ""; done
fi

# ---- 6. Questions and apply ---------------------------------------------------------------
header "6/6  what to do (Enter = the default in capitals)"
: >"$W/chosen"
awk -F"$US" '$4 != "none"' "$W/find" >"$W/ask"
_all=0
while IFS="$US" read -r _lv _ar _wh _fx _tg; do
    if [ "$_all" = 0 ]; then
        if [ "$_fx" = kill ]; then cc_choose "$_wh?" k "k=kill it" "l=leave it running" "a=all the rest: take their defaults (kill / quarantine)"
        else cc_choose "$_wh?" q "q=quarantine it (moved out; the undo puts it back)" "l=leave it" "a=all the rest: take their defaults (kill / quarantine)"; fi
        case "$CC_CHOICE" in l) continue ;; a) _all=1 ;; esac
    fi
    printf '%s\037%s\037%s\n' "$_fx" "$_tg" "$_wh" >>"$W/chosen"
done <"$W/ask"
NCH=$(grep -c . "$W/chosen")
NOK=0; NBAD=0; APPLIED=0
alive() { kill -0 "$1" 2>/dev/null && ! ps -o stat= -p "$1" 2>/dev/null | grep -q '^Z'; }
if [ "$NCH" -eq 0 ]; then cc_show "$C_GRN" "  [ok] Nothing to kill or quarantine."
elif [ "$CC_APPLY" != 1 ] || { [ -z "$R" ] && ! cc_is_root; }; then
    while IFS="$US" read -r _fx _tg _wh; do cc_show "$C_YEL" "  [~] $_fx: $_wh"; done <"$W/chosen"
    cc_show "$C_GRY" "  Dry run: nothing was changed. Run again with --apply."
    # shellcheck disable=SC2034  # read by cc_finish
    CC_N_WOULD=$NCH
elif cc_ask "Do these $NCH?" Y "yes, kill and quarantine them" "no, leave everything"; then
    APPLIED=1
    while IFS="$US" read -r _fx _tg _wh; do
        _ok=0
        case "$_fx" in
            kill)
                _pid=${_tg%% *}; _pn=${_tg#* }
                if ! alive "$_pid"; then _ok=1
                elif [ "$(cat "/proc/$_pid/comm" 2>/dev/null)" != "$_pn" ]; then
                    # The pid now belongs to another program (it ended and the number was reused).
                    cc_show "$C_YEL" "  [-] pid $_pid is now $(cat "/proc/$_pid/comm" 2>/dev/null), not $_pn: left alone"; continue
                elif ! cc_guard process "$_pn"; then cc_show "$C_YEL" "  [-] protected, left: $_wh"; continue
                else kill "$_pid" 2>>"$CC_LOG"; sleep 1; alive "$_pid" && kill -9 "$_pid" 2>>"$CC_LOG"; sleep 1; alive "$_pid" || _ok=1; fi ;;
            quarantine)
                if ! cc_guard path "${_tg#"$R"}"; then cc_show "$C_YEL" "  [-] protected, left: $_wh"; continue; fi
                cc_quarantine "$_tg" >>"$CC_LOG" 2>&1 && _ok=1
                # Rootkits often set the immutable flag so the file cannot be moved.
                if [ "$_ok" = 0 ] && cc_have lsattr && lsattr -d "$_tg" 2>/dev/null | cut -d' ' -f1 | grep -q i; then
                    chattr -i "$_tg" 2>>"$CC_LOG" && cc_quarantine "$_tg" >>"$CC_LOG" 2>&1 && _ok=1 && cc_show "$C_YEL" "  [*] it had the immutable flag (chattr +i): removed it to move it"
                fi ;;
        esac
        if [ "$_ok" = 1 ]; then NOK=$((NOK + 1)); cc_show "$C_GRN" "  [+] $_fx: $_wh"; else NBAD=$((NBAD + 1)); cc_show "$C_RED" "  [x] could not $_fx: $_wh"; fi
    done <"$W/chosen"
else cc_show "$C_GRY" "  Nothing done."; fi
# shellcheck disable=SC2034  # read by cc_finish
CC_N_DONE=$NOK
# shellcheck disable=SC2034  # read by cc_finish
CC_N_FAIL=$NBAD

awk -F"$US" '{ printf "%-4s %-10s %s\n", $1, $2, $3 }' "$W/find" >"$CC_RUN_DIR/findings.txt"
{
    printf '==========[ summary ]==========\n'
    printf 'LX-45 Rootkit and malware scan | host %s | %s\n' "$CC_HOST" "$([ "$APPLIED" = 1 ] && echo APPLIED || echo 'DRY RUN - nothing changed')"
    printf 'Found: %d HIGH, %d MED\n' "$(grep -c "^HIGH$US" "$W/find")" "$(grep -c "^MED$US" "$W/find")"
    awk -F"$US" '{ printf "  %-4s %s\n", $1, substr($3, 1, 150) }' "$W/find"
    [ "$APPLIED" = 1 ] && printf 'Done: %d   Failed: %d\n' "$NOK" "$NBAD"
    [ "$APPLIED" = 1 ] && [ "$NOK" -gt 0 ] && printf 'Quarantined files are in %s; the undo lines (put them back) in %s/undo-%s.log\n' "$CC_QUAR_DIR" "$CC_OUT" "$CC_HOST"
    grep -q "${US}module${US}" "$W/find" && printf '\nA rootkit module is not unloaded here (that can crash the box): find what loads it (LX-42 kernel), remove that, reboot.\n'
    printf '\nWhat starts these again (cron, services, preload): LX-42.\n'
} >"$CC_RUN_DIR/summary.txt"
cc_show "" ""
while IFS= read -r _l; do
    case "$_l" in ==*|LX-45*) cc_show "$C_CYN" "$_l" ;; '  HIGH'*) cc_show "$C_RED" "$_l" ;; '  MED'*) cc_show "$C_YEL" "$_l" ;; *) cc_show "" "$_l" ;; esac
done <"$CC_RUN_DIR/summary.txt"
rm -rf "$W"
cc_finish
