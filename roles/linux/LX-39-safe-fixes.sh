#!/bin/sh
# =============================================================================
# ID:       LX-39
# NAME:     Linux safe fixes
# ROLE:     Linux  (wave 2, first 15 minutes)
# KIND:     changes - dry run unless --apply
# VERSION:  1.0.0
#
# PURPOSE
#   The Linux twin of WN-43: only fixes that cannot break a scored service,
#   so they can run on every Linux box in the first minutes without study.
#     sysctl      kernel network and memory settings: SYN cookies, full ASLR,
#                 no source routing or ICMP redirects, martian logging,
#                 symlink and hardlink protection, hidden kernel pointers
#     ipv6        IPv6 off with the kernel setting (disable_ipv6) on every
#                 interface except loopback.  NOT the ipv6.disable boot
#                 option: that one stops any service configured to listen on
#                 [::] (nginx's default config does) from starting at all
#     coredumps   no core dumps from setuid programs (they can hold password
#                 hashes), and a hard core-size limit of 0
#     perms       owner-only or root-only modes on the password, group,
#                 sudo, SSH host key, cron, PAM, shell startup and systemd
#                 files, and no world-writable files in /etc or program folders.
#                 Only bits are REMOVED; owners and groups are never changed
#     tmp         the sticky bit on /tmp, /var/tmp and /dev/shm
#     logging     rsyslog / syslog-ng / auditd started (and enabled) if they
#                 are installed but stopped
#     preload     /etc/ld.so.preload entries not owned by any package (the
#                 classic rootkit hook) -> the file is quarantined; LD_PRELOAD
#                 lines in /etc/environment are commented out
#     trust       .rhosts, .shosts, hosts.equiv, shosts.equiv quarantined
#     forwarding  IP forwarding off - ONLY with --no-forwarding, because
#                 routers, firewalls and Docker hosts need it
#   Also REPORTED (never changed): extra /etc/hosts entries, IP forwarding
#   left on, services bound to a specific IPv6 address.
#
# USAGE
#   sudo sh LX-39-safe-fixes.sh                    dry run: shows what it would do
#   sudo sh LX-39-safe-fixes.sh --apply            make the changes
#   sudo sh LX-39-safe-fixes.sh --apply --skip ipv6
#
# OPTIONS
#   --only a,b       run only these fixes (names from --list)
#   --skip a,b       leave these fixes out
#   --keep-ipv6      same as --skip ipv6
#   --no-forwarding  also turn IP forwarding off (not on routers/firewalls/Docker)
#   --root DIR       treat DIR as / for every FILE fix (perms, tmp, preload,
#                    trust, the sysctl and limits files).  For fixing a
#                    mounted disk image, and for the tests.  Kernel settings
#                    and services still act on the running system
#   --list           list the fixes and exit
#   --help           this text plus the common options
#
# OUTPUTS  (under --out, in LX-39_<host>_<UTC time>/)
#   summary.txt   counts per fix, every change, and the items to check by hand
#   fixes.csv     fix,item,before,after,status
#                 (status: changed | would change | already ok | failed |
#                  refused | skipped | check by hand)
#   The undo log (<out>/undo-<host>.log) gets one line per change; run its
#   commands from the bottom up to roll back.  Files are backed up first
#   under <out>/backup/<host>/.
#
# WHAT IT CHANGES  (only with --apply)
#   /etc/sysctl.d/99-zz-ccdc-safe.conf (new) and the running kernel settings,
#   /etc/security/limits.d/99-ccdc-safe.conf (new), file modes listed above,
#   /etc/environment (LD_PRELOAD lines commented out), the logging services.
#   Moves /etc/ld.so.preload and rhosts-style files to the quarantine folder.
#   Never deletes anything.  A path on the protected list is skipped.
#
# DEPENDS ON
#   ls, chmod, find, awk, sysctl (Linux); systemctl, rc-service or service
#   for the logging fix; dpkg or rpm to check who owns a preload library.
#
# TESTED ON
#   Ubuntu 24.04 under dash, bash, busybox sh, ksh93, mksh and yash, against a
#   test root and stand-in sysctl/systemctl programs, plus a dry run on the
#   live system.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - Kernel settings are made permanent in a file named 99-zz-... so it is
#     read last at boot, after /etc/sysctl.conf; a file named later still
#     (for example 99-zzz.conf) would win - the change watch shows new files.
#   - Inside a container some kernel settings are read-only; those show as
#     failed in fixes.csv and the rest still apply.
#   - The preload fix trusts the package database.  On a box where the red
#     team replaced packages, check the quarantined file by hand.
#
# DEBUGGING
#   --debug shows every mode calculation and tool choice.  Every command run
#   with --apply is in the log with its output.
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

ALL_FIXES="sysctl ipv6 forwarding coredumps perms tmp logging preload trust hosts"

usage() {
    cat <<'USAGE'
LX-39 Linux safe fixes - hardening that cannot break a scored service
  sudo sh LX-39-safe-fixes.sh [--apply] [options]

  --only a,b       run only these fixes
  --skip a,b       leave these fixes out
  --keep-ipv6      leave IPv6 on (same as --skip ipv6)
  --no-forwarding  also turn IP forwarding off (NOT on routers, firewalls or Docker hosts)
  --root DIR       treat DIR as / for the file fixes (disk images, tests)
  --list           list the fixes and exit
  --help           show this text

USAGE
    cc_usage_common
}

list_fixes() {
    cat <<'LIST'
sysctl      SYN cookies, ASLR, no source-routed packets or redirects, link protection
ipv6        IPv6 off with disable_ipv6 (loopback kept), never the boot option
forwarding  IP forwarding off - only with --no-forwarding
coredumps   no setuid core dumps, core size limit 0
perms       remove group/other write (and read on secrets) from key files
tmp         sticky bit on /tmp, /var/tmp, /dev/shm
logging     start rsyslog / syslog-ng / auditd if installed and stopped
preload     quarantine /etc/ld.so.preload with unowned libraries; LD_PRELOAD lines
trust       quarantine .rhosts, .shosts, hosts.equiv, shosts.equiv
hosts       report extra /etc/hosts entries (report only)
LIST
}

ONLY=""; SKIP=""; NOFWD=0; R=""
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --only)          [ $# -ge 2 ] || cc_die 2 "--only needs a list of fixes"; ONLY=$2; shift 2 ;;
        --skip)          [ $# -ge 2 ] || cc_die 2 "--skip needs a list of fixes"; SKIP="$SKIP,$2"; shift 2 ;;
        --keep-ipv6)     SKIP="$SKIP,ipv6"; shift ;;
        --no-forwarding) NOFWD=1; shift ;;
        --root)          [ $# -ge 2 ] || cc_die 2 "--root needs a folder"
                         [ -d "$2" ] || cc_die 2 "--root: not a folder: $2"
                         R=$(cd "$2" && pwd); [ "$R" = / ] && R=""; shift 2 ;;
        --list)          list_fixes; exit 0 ;;
        --help|-h)       usage; exit 0 ;;
        *)               cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
for _n in $(printf '%s,%s' "$ONLY" "$SKIP" | tr ',' ' '); do
    case " $ALL_FIXES " in *" $_n "*) ;; *) cc_die 2 "unknown fix '$_n' (see --list)" ;; esac
done
FIXES=$ALL_FIXES
[ -n "$ONLY" ] && FIXES=$(printf '%s' "$ONLY" | tr ',' ' ')
# Naming forwarding in --only is asking for it, like --no-forwarding.
case ",$ONLY," in *,forwarding,*) NOFWD=1 ;; esac
_keep=""
for _f in $FIXES; do
    case ",$SKIP," in *",$_f,"*) continue ;; esac
    # forwarding is opt-in: it runs only when --no-forwarding was given.
    [ "$_f" = forwarding ] && [ "$NOFWD" = 0 ] && continue
    _keep="$_keep $_f"
done
FIXES=$_keep

# The sysctl program.  CCDC_SYSCTL lets the tests use a stand-in by full
# path: busybox sh runs its own built-in sysctl in preference to PATH.
SYSCTL=${CCDC_SYSCTL:-sysctl}

cc_init "LX-39" "Linux safe fixes" changes
cc_detect_os
if [ "$CC_APPLY" = 1 ] && [ -z "$R" ]; then cc_require_root; fi
cc_use_run_dir
W="$CC_RUN_DIR/.work"
mkdir -p "$W" || cc_die 3 "cannot create $W"
CSV=$(cc_csv_new fixes "fix,item,before,after,status")
[ -n "$R" ] && cc_info "file fixes act on $R (as if it were /)"

# ---- Helpers ----------------------------------------------------------------
# row ITEM BEFORE AFTER STATUS -> one line in fixes.csv for the current fix.
row() { cc_csv_row "$CSV" "$FIX" "$1" "$2" "$3" "$4"; }
# result RC -> the status word for a change that was just attempted.
result() { if [ "$CC_APPLY" != 1 ]; then echo "would change"; elif [ "$1" -eq 0 ]; then echo changed; else echo failed; fi; }
# P PATH -> PATH under the --root folder (or PATH itself).
P() { printf '%s%s' "$R" "$1"; }

# mode_of PATH -> four-digit octal mode, read from ls -ld so it works with
#   every ls (GNU stat -c and BSD stat -f differ).  s/S/t/T set the special
#   digit; lower-case means the execute bit is also on.
mode_of() {
    ls -ld "$1" 2>/dev/null | awk '{
        p = $1; s = 0; u = 0; g = 0; o = 0
        c = substr(p, 2, 1); if (c == "r") u += 4
        c = substr(p, 3, 1); if (c == "w") u += 2
        c = substr(p, 4, 1); if (c == "x" || c == "s") u += 1; if (c == "s" || c == "S") s += 4
        c = substr(p, 5, 1); if (c == "r") g += 4
        c = substr(p, 6, 1); if (c == "w") g += 2
        c = substr(p, 7, 1); if (c == "x" || c == "s") g += 1; if (c == "s" || c == "S") s += 2
        c = substr(p, 8, 1); if (c == "r") o += 4
        c = substr(p, 9, 1); if (c == "w") o += 2
        c = substr(p, 10, 1); if (c == "x" || c == "t") o += 1; if (c == "t" || c == "T") s += 1
        printf "%d%d%d%d\n", s, u, g, o }'
}
# mode_calc OLD CLEAR SET -> OLD with the CLEAR bits removed and the SET bits
#   added, all four-digit octal.  Done digit by digit in awk because POSIX awk
#   has no bit operators and mksh reads 0-prefixed numbers as decimal.
mode_calc() {
    awk -v o="$1" -v c="$2" -v s="$3" 'BEGIN {
        while (length(o) < 4) o = "0" o; while (length(c) < 4) c = "0" c; while (length(s) < 4) s = "0" s
        out = ""
        for (i = 1; i <= 4; i++) {
            od = substr(o, i, 1) + 0; cd = substr(c, i, 1) + 0; sd = substr(s, i, 1) + 0; n = 0
            for (b = 4; b >= 1; b = b / 2) {
                on = (int(od / b) % 2 == 1 && int(cd / b) % 2 == 0) || int(sd / b) % 2 == 1
                if (on) n += b
            }
            out = out n
        }
        print out }'
}

# set_mode PATH CLEAR SET WHY [quiet]
#   Change PATH's mode if CLEAR bits are present or SET bits are missing.
#   Symbolic links are skipped (chmod would follow them).  With "quiet", an
#   already-correct path writes no row (used for long lists of files).
set_mode() {
    _sm_p=$1; _sm_c=$2; _sm_s=$3; _sm_why=$4; _sm_q=${5:-}
    [ -e "$_sm_p" ] || return 0
    [ -h "$_sm_p" ] && return 0
    _sm_old=$(mode_of "$_sm_p")
    [ -n "$_sm_old" ] || return 0
    _sm_new=$(mode_calc "$_sm_old" "$_sm_c" "$_sm_s")
    _sm_item=${_sm_p#"$R"}
    if [ "$_sm_new" = "$_sm_old" ]; then
        [ -n "$_sm_q" ] || row "$_sm_item" "$_sm_old" "$_sm_old" "already ok"
        return 0
    fi
    if ! cc_guard path "$_sm_item"; then row "$_sm_item" "$_sm_old" "$_sm_new" refused; return 0; fi
    cc_run "mode of $_sm_item $_sm_old -> $_sm_new ($_sm_why)" chmod "$_sm_new" "$_sm_p"
    _sm_rc=$?
    [ "$_sm_rc" -eq 0 ] && cc_undo_add "restore mode of $_sm_item" "chmod $_sm_old $(cc_shquote "$_sm_p")"
    row "$_sm_item" "$_sm_old" "$_sm_new" "$(result "$_sm_rc")"
}

# want_sysctl KEY VALUE -> queue one kernel setting for the sysctl step.
#   Keys this kernel does not have are recorded as skipped.
want_sysctl() {
    if ! _ws_cur=$("$SYSCTL" -n "$1" 2>/dev/null); then
        row "$1" "" "$2" "skipped (not on this kernel)"
        return 0
    fi
    printf '%s|%s|%s|%s\n' "$FIX" "$1" "$2" "$_ws_cur" >>"$W/sysctl_want"
}

# ---- Fixes --------------------------------------------------------------------
: >"$W/sysctl_want"; : >"$W/report"
# report ITEM TEXT -> something to check by hand (summary and fixes.csv).
report() { printf '%s|%s|%s\n' "$FIX" "$1" "$2" >>"$W/report"; row "$1" "" "$2" "check by hand"; }

fix_sysctl() {
    [ "$CC_OS_KERNEL" = linux ] || { row "(all)" "" "" "skipped (not Linux)"; return 0; }
    want_sysctl net.ipv4.tcp_syncookies 1
    want_sysctl kernel.randomize_va_space 2
    want_sysctl net.ipv4.conf.all.accept_source_route 0
    want_sysctl net.ipv4.conf.default.accept_source_route 0
    want_sysctl net.ipv4.conf.all.accept_redirects 0
    want_sysctl net.ipv4.conf.default.accept_redirects 0
    want_sysctl net.ipv4.conf.all.secure_redirects 0
    want_sysctl net.ipv4.conf.default.secure_redirects 0
    want_sysctl net.ipv4.conf.all.send_redirects 0
    want_sysctl net.ipv4.conf.default.send_redirects 0
    want_sysctl net.ipv4.conf.all.log_martians 1
    want_sysctl net.ipv4.icmp_echo_ignore_broadcasts 1
    want_sysctl net.ipv4.icmp_ignore_bogus_error_responses 1
    want_sysctl fs.protected_symlinks 1
    want_sysctl fs.protected_hardlinks 1
    want_sysctl kernel.kptr_restrict 1
    want_sysctl kernel.dmesg_restrict 1
    # Not here on purpose: rp_filter (strict mode breaks multi-homed routers),
    # ip_forward (routers and Docker need it), ptrace_scope (debuggers).
}

fix_ipv6() {
    [ "$CC_OS_KERNEL" = linux ] || { row "(all)" "" "" "skipped (not Linux)"; return 0; }
    if ! "$SYSCTL" -n net.ipv6.conf.all.disable_ipv6 >/dev/null 2>&1; then
        row "(all)" "" "" "already ok (this kernel has no IPv6)"
        return 0
    fi
    # Loopback keeps IPv6: services bound only to ::1 keep working.  Services
    # on [::] (all addresses) keep working for IPv4.  Only a service bound to
    # one specific IPv6 address would stop answering - list those first.
    if cc_have ss; then
        ss -ltnH 2>/dev/null | awk '{ a = $4; sub(/:[^:]*$/, "", a); gsub(/[][]/, "", a)
            if (a ~ /:/ && a != "::" && a != "::1" && a !~ /^::ffff:/ && a !~ /^\*/) print $4 }' >"$W/v6"
        while IFS= read -r _l; do report "$_l" "listens on a specific IPv6 address; it stops answering once IPv6 is off"; done <"$W/v6"
    fi
    want_sysctl net.ipv6.conf.all.disable_ipv6 1
    want_sysctl net.ipv6.conf.default.disable_ipv6 1
}

fix_forwarding() {
    [ "$CC_OS_KERNEL" = linux ] || { row "(all)" "" "" "skipped (not Linux)"; return 0; }
    want_sysctl net.ipv4.ip_forward 0
    "$SYSCTL" -n net.ipv6.conf.all.forwarding >/dev/null 2>&1 && want_sysctl net.ipv6.conf.all.forwarding 0
}

fix_coredumps() {
    [ "$CC_OS_KERNEL" = linux ] && want_sysctl fs.suid_dumpable 0
    _lim=$(P /etc/security/limits.d)
    if [ -d "$_lim" ]; then
        _f="$_lim/99-ccdc-safe.conf"
        if [ -f "$_f" ] && grep -q '^\* *hard *core *0' "$_f"; then row "/etc/security/limits.d/99-ccdc-safe.conf" "" "* hard core 0" "already ok"; return 0; fi
        if ! cc_guard path "/etc/security/limits.d/99-ccdc-safe.conf"; then row "/etc/security/limits.d/99-ccdc-safe.conf" "" "" refused; return 0; fi
        printf '# Written by LX-39 (CCDC kit): no core dumps for any account.\n* hard core 0\n' >"$W/limits.conf"
        cc_backup_file "$_f" || return 0
        cc_run "core size limit 0 in /etc/security/limits.d/99-ccdc-safe.conf" cp "$W/limits.conf" "$_f"
        _rc=$?
        [ "$_rc" -eq 0 ] && [ -z "$CC_LAST_BACKUP" ] && cc_undo_add "remove core limit file" "rm -f $(cc_shquote "$_f")"
        row "/etc/security/limits.d/99-ccdc-safe.conf" "" "* hard core 0" "$(result "$_rc")"
    else
        row "/etc/security/limits.d" "" "" "skipped (no limits.d folder)"
    fi
}

fix_perms() {
    # CLEAR masks: 0022 = group/other write; 0027 = group write + all other
    # access; 0077 = all group and other access.  Only bits are removed.
    for _f in /etc/passwd /etc/group; do set_mode "$(P "$_f")" 0022 0000 "only root may change it"; done
    for _f in /etc/shadow /etc/gshadow /etc/shadow- /etc/gshadow- /etc/security/opasswd; do
        set_mode "$(P "$_f")" 0027 0000 "password hashes: no access for other accounts"
    done
    set_mode "$(P /etc/sudoers)" 0027 0000 "sudo rules"
    for _f in "$(P /etc/sudoers.d)"/*; do set_mode "$_f" 0027 0000 "sudo rules"; done
    for _f in "$(P /etc/ssh)"/ssh_host_*_key; do set_mode "$_f" 0027 0000 "SSH host private key"; done
    set_mode "$(P /etc/ssh/sshd_config)" 0022 0000 "SSH server config"
    set_mode "$(P /root)" 0077 0000 "root's home"
    set_mode "$(P /etc/crontab)" 0022 0000 "system crontab"
    for _d in cron.d cron.hourly cron.daily cron.weekly cron.monthly; do
        set_mode "$(P /etc/$_d)" 0022 0000 "cron folder"
        for _f in "$(P /etc/$_d)"/*; do set_mode "$_f" 0022 0000 "cron job" quiet; done
    done
    # Files everyone's login runs or every program loads: writable by root only.
    for _f in /etc/profile /etc/bash.bashrc /etc/bashrc /etc/environment /etc/ld.so.conf /etc/ld.so.preload; do
        set_mode "$(P "$_f")" 0022 0000 "read at every login or program start"
    done
    for _d in /etc/profile.d /etc/ld.so.conf.d /etc/pam.d /etc/systemd/system; do
        [ -d "$(P "$_d")" ] || continue
        set_mode "$(P "$_d")" 0022 0000 "only root may add files here" quiet
        find "$(P "$_d")" -xdev -maxdepth 2 ! -type l \( -perm -0020 -o -perm -0002 \) 2>/dev/null >"$W/ww"
        while IFS= read -r _f; do set_mode "$_f" 0022 0000 "only root may change it"; done <"$W/ww"
    done
    # Anything world-writable in /etc, and in the folders on root's PATH.
    find "$(P /etc)" -xdev ! -type l -perm -0002 2>/dev/null >"$W/ww"
    for _d in /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin; do
        [ -d "$(P "$_d")" ] && [ ! -h "$(P "$_d")" ] && find "$(P "$_d")" -xdev -maxdepth 1 ! -type l -perm -0002 2>/dev/null >>"$W/ww"
    done
    # Home folders that anyone can write into (someone else could plant .bashrc).
    awk -F: '$6 ~ /^\/(home|root)/ { print $6 }' "$(P /etc/passwd)" 2>/dev/null | sort -u >"$W/homes"
    while IFS= read -r _h; do
        [ -d "$(P "$_h")" ] && find "$(P "$_h")" -maxdepth 0 -perm -0002 2>/dev/null >>"$W/ww"
    done <"$W/homes"
    sort -u "$W/ww" >"$W/ww.u"
    while IFS= read -r _f; do set_mode "$_f" 0002 0000 "world-writable"; done <"$W/ww.u"
}

fix_tmp() {
    for _d in /tmp /var/tmp /dev/shm; do
        [ -d "$(P "$_d")" ] || continue
        # Only world-writable shared folders need the sticky bit (users may
        # then delete only their own files there).
        if find "$(P "$_d")" -maxdepth 0 -perm -0002 2>/dev/null | grep -q .; then
            set_mode "$(P "$_d")" 0000 1000 "sticky bit: users cannot delete each other's files"
        else
            row "$_d" "$(mode_of "$(P "$_d")")" "" "already ok"
        fi
    done
}

# svc_state NAME -> "missing", "running" or "stopped"
svc_state() {
    case "$CC_INIT" in
        systemd)
            systemctl cat "$1.service" >/dev/null 2>&1 || { echo missing; return; }
            if systemctl is-active --quiet "$1" 2>/dev/null; then echo running; else echo stopped; fi ;;
        openrc)
            [ -e "/etc/init.d/$1" ] || { echo missing; return; }
            if rc-service "$1" status >/dev/null 2>&1; then echo running; else echo stopped; fi ;;
        *)
            [ -e "/etc/init.d/$1" ] || { echo missing; return; }
            if service "$1" status >/dev/null 2>&1; then echo running; else echo stopped; fi ;;
    esac
}
fix_logging() {
    [ -n "$R" ] && { row "(all)" "" "" "skipped (--root: services belong to the running system)"; return 0; }
    for _s in rsyslog syslog-ng auditd; do
        _st=$(svc_state "$_s")
        case "$_st" in
            missing) cc_debug "logging: $_s not installed" ;;
            running) row "$_s" running running "already ok" ;;
            stopped)
                if ! cc_guard service "$_s"; then row "$_s" stopped "" refused; continue; fi
                case "$CC_INIT" in
                    systemd) cc_run "start and enable $_s (logging)" systemctl enable --now "$_s"; _rc=$?
                             [ "$_rc" -eq 0 ] && cc_undo_add "stop $_s again" "systemctl disable --now $_s" ;;
                    openrc)  cc_run "start $_s (logging)" rc-service "$_s" start; _rc=$?
                             [ "$_rc" -eq 0 ] && cc_run "enable $_s at boot" rc-update add "$_s" default
                             [ "$_rc" -eq 0 ] && cc_undo_add "stop $_s again" "rc-service $_s stop; rc-update del $_s default" ;;
                    *)       cc_run "start $_s (logging)" service "$_s" start; _rc=$?
                             [ "$_rc" -eq 0 ] && cc_undo_add "stop $_s again" "service $_s stop" ;;
                esac
                row "$_s" stopped running "$(result "$_rc")" ;;
        esac
    done
}

# pkg_owner FILE -> the package that installed FILE, or nothing.
pkg_owner() {
    if cc_have dpkg; then dpkg -S "$1" 2>/dev/null | head -n 1 | cut -d: -f1
    elif cc_have rpm; then rpm -qf "$1" 2>/dev/null | grep -v 'not owned' | head -n 1
    fi
}
fix_preload() {
    _pl=$(P /etc/ld.so.preload)
    if [ -s "$_pl" ]; then
        # Every library named in it: owned by a package, or a red flag.
        _bad=""
        tr ' :' '\n\n' <"$_pl" | grep -v '^#' | grep . >"$W/preload"
        while IFS= read -r _lib; do
            _own=$(pkg_owner "$_lib")
            if [ -z "$_own" ]; then _bad="$_bad $_lib"; row "/etc/ld.so.preload: $_lib" "loaded into every program" "" "not owned by any package"
            else row "/etc/ld.so.preload: $_lib" "loaded into every program" "" "owned by package $_own"; fi
        done <"$W/preload"
        if [ -n "$_bad" ]; then
            cc_warn "/etc/ld.so.preload loads a library no package owns:$_bad - the classic user-mode rootkit hook"
            cc_quarantine "$_pl"
            _rc=$?
            if [ "$_rc" -eq 4 ]; then row "/etc/ld.so.preload" present present refused; else row "/etc/ld.so.preload" present "quarantined" "$(result "$_rc")"; fi
        fi
    else
        row "/etc/ld.so.preload" "absent or empty" "" "already ok"
    fi
    # LD_PRELOAD / LD_LIBRARY_PATH in /etc/environment apply to every login.
    _env=$(P /etc/environment)
    if [ -f "$_env" ] && grep -qE '^[[:space:]]*(export[[:space:]]+)?LD_(PRELOAD|LIBRARY_PATH)=' "$_env"; then
        if ! cc_guard path /etc/environment; then row /etc/environment "LD_PRELOAD set" "" refused; return 0; fi
        awk '/^[ \t]*(export[ \t]+)?LD_(PRELOAD|LIBRARY_PATH)=/ { print "# disabled by LX-39: " $0; next } { print }' "$_env" >"$W/environment"
        cc_backup_file "$_env" || return 0
        # cp onto the existing file keeps its owner and mode.
        cc_run "comment out LD_PRELOAD/LD_LIBRARY_PATH in /etc/environment" cp "$W/environment" "$_env"
        row /etc/environment "LD_PRELOAD or LD_LIBRARY_PATH set" "commented out" "$(result $?)"
    fi
}

fix_trust() {
    {
        printf '%s\n' /etc/hosts.equiv /etc/shosts.equiv /root/.rhosts /root/.shosts
        awk -F: '$6 != "" && $6 != "/" { print $6 "/.rhosts"; print $6 "/.shosts" }' "$(P /etc/passwd)" 2>/dev/null
    } | sort -u >"$W/trust"
    _n=0
    while IFS= read -r _f; do
        [ -e "$(P "$_f")" ] || continue
        _n=$((_n + 1))
        cc_quarantine "$(P "$_f")"
        _rc=$?
        if [ "$_rc" -eq 4 ]; then row "$_f" present present refused; else row "$_f" "lets other hosts log in without a password" quarantined "$(result "$_rc")"; fi
    done <"$W/trust"
    [ "$_n" -eq 0 ] && row "(rhosts-style files)" none "" "already ok"
}

fix_hosts() {
    # Report only: scoring can depend on /etc/hosts, so nothing is changed.
    _h=$(P /etc/hosts)
    [ -r "$_h" ] || return 0
    _me=$(uname -n 2>/dev/null)
    awk -v me="$_me" -v short="${_me%%.*}" '
        /^[ \t]*#/ || NF < 2 { next }
        { keep = 0
          for (i = 2; i <= NF; i++) { n = $i; if (n ~ /^#/) break
              if (n ~ /^(localhost|ip6-|localhost\.|ip6-localhost)/ || n == me || n == short) keep = 1 }
          if (!keep && $1 !~ /^(127\.|::1$|ff0|fe00)/) print $0 }' "$_h" >"$W/hosts_extra"
    while IFS= read -r _l; do report "/etc/hosts: $_l" "name pinned to an address; check it is the team's (a red team uses this to redirect updates or logins)"; done <"$W/hosts_extra"
    [ -s "$W/hosts_extra" ] || row "/etc/hosts" "only local names" "" "already ok"
}

# ---- Run the fixes ------------------------------------------------------------
for FIX in $FIXES; do
    cc_info "fix: $FIX"
    "fix_$FIX"
done

# IP forwarding left on is worth a look even when it is not being changed.
if [ "$NOFWD" = 0 ] && [ "$CC_OS_KERNEL" = linux ] && [ "$("$SYSCTL" -n net.ipv4.ip_forward 2>/dev/null)" = 1 ]; then
    FIX=forwarding
    report net.ipv4.ip_forward "IP forwarding is on: right for a router, firewall or Docker host; otherwise run again with --no-forwarding"
fi

# ---- Kernel settings: one file for boot, then the running values -------------
if [ -s "$W/sysctl_want" ]; then
    _sd=$(P /etc/sysctl.d)
    if [ -d "$_sd" ]; then _sf="$_sd/99-zz-ccdc-safe.conf"; _sfi=/etc/sysctl.d/99-zz-ccdc-safe.conf
    else _sf=$(P /etc/sysctl.conf); _sfi=/etc/sysctl.conf; fi
    # The boot file holds every wanted key (also those already right), so the
    # values survive a reboot even if another file sets them differently.
    {
        printf '# Written by LX-39 (CCDC kit). Read last at boot (99-zz). Undo log has the old values.\n'
        awk -F'|' '{ print $2 " = " $3 }' "$W/sysctl_want"
    } >"$W/sysctl.conf"
    FIX=sysctl
    if ! cc_guard path "$_sfi"; then
        row "$_sfi" "" "" refused
    elif [ "$_sfi" = /etc/sysctl.conf ]; then
        cc_backup_file "$_sf" && cc_run "append kernel settings to /etc/sysctl.conf" sh -c 'cat "$1" >>"$2"' sh "$W/sysctl.conf" "$_sf"
        row "$_sfi" "" "$(grep -c . "$W/sysctl_want") settings" "$(result $?)"
    elif [ -f "$_sf" ] && cmp -s "$W/sysctl.conf" "$_sf" 2>/dev/null; then
        row "$_sfi" "" "" "already ok"
    else
        cc_backup_file "$_sf" && {
            cc_run "write kernel settings for boot to $_sfi" cp "$W/sysctl.conf" "$_sf"
            _rc=$?
            [ "$_rc" -eq 0 ] && [ -z "$CC_LAST_BACKUP" ] && cc_undo_add "remove $_sfi" "rm -f $(cc_shquote "$_sf")"
            row "$_sfi" "" "$(grep -c . "$W/sysctl_want") settings" "$(result "$_rc")"
        }
    fi
    # Running values: change only what differs; undo restores the old value.
    while IFS='|' read -r FIX _k _v _cur; do
        if [ "$_cur" = "$_v" ]; then row "$_k" "$_cur" "$_v" "already ok"; continue; fi
        cc_run "kernel setting $_k $_cur -> $_v" "$SYSCTL" -w "$_k=$_v"
        _rc=$?
        [ "$_rc" -eq 0 ] && cc_undo_add "restore $_k" "$SYSCTL -w $_k=$_cur"
        row "$_k" "$_cur" "$_v" "$(result "$_rc")"
    done <"$W/sysctl_want"
fi

# ---- Summary ------------------------------------------------------------------
{
    printf 'LX-39 Linux safe fixes | host %s | %s | %s\n' "$CC_HOST" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$([ "$CC_APPLY" = 1 ] && echo APPLIED || echo 'DRY RUN - nothing changed')"
    [ -n "$R" ] && printf 'File fixes acted on %s\n' "$R"
    printf '\n'
    awk -v fixes="$FIXES" "$CC_AWK_CSV"'
        NR > 1 { csvsplit($0, f); st = f[5]; k = f[1]
                 if (st == "changed" || st == "would change") ch[k]++
                 else if (st ~ /^already ok/) ok[k]++
                 else if (st == "failed") fl[k]++
                 else if (st == "refused") rf[k]++
                 else if (st == "check by hand") hb[k]++
                 else other[k]++ }
        END {
            printf "%-11s %8s %6s %6s %7s %6s\n", "fix", "changes", "ok", "failed", "refused", "check"
            n = split(fixes, fx, " ")
            for (i = 1; i <= n; i++) { k = fx[i]; printf "%-11s %8d %6d %6d %7d %6d\n", k, ch[k], ok[k], fl[k], rf[k], hb[k] }
            if (hb["forwarding"] && fixes !~ /forwarding/) printf "%-11s %8d %6d %6d %7d %6d\n", "forwarding", 0, 0, 0, 0, hb["forwarding"]
        }' "$CSV"
    printf '\n'
    awk "$CC_AWK_CSV"'NR > 1 { csvsplit($0, f); if (f[5] == "changed" || f[5] == "would change" || f[5] == "failed")
        printf "  %-13s %-10s %s%s\n", toupper(f[5]), f[1], f[2], (f[3] != "" || f[4] != "" ? "  [" f[3] " -> " f[4] "]" : "") }' "$CSV" | head -n 60
    _nch=$(awk "$CC_AWK_CSV"'NR > 1 { csvsplit($0, f); if (f[5] == "changed" || f[5] == "would change" || f[5] == "failed") n++ } END { print n + 0 }' "$CSV")
    [ "$_nch" -gt 60 ] && printf '  ... %d more in fixes.csv\n' "$((_nch - 60))"
    [ "$_nch" -eq 0 ] && printf '  Nothing to change: every fix was already in place.\n'
    if [ -s "$W/report" ]; then
        printf '\nCheck by hand (not changed):\n'
        awk -F'|' '{ l = "  " $2 ": " $3; if (length(l) > 200) l = substr(l, 1, 197) "..."; print l }' "$W/report"
    fi
    printf '\n'
    if [ "$CC_APPLY" = 1 ]; then
        printf 'Undo: the commands are in %s (run them from the bottom up).\n' "$CC_UNDO"
    else
        printf 'Dry run: nothing changed.  Run again with --apply to make these changes.\n'
    fi
    printf 'All results: %s\n' "$CC_RUN_DIR"
} >"$CC_RUN_DIR/summary.txt"
cat "$CC_RUN_DIR/summary.txt"
rm -rf "$W"
cc_finish
