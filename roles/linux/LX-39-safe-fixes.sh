#!/bin/sh
# =============================================================================
# ID:       LX-39
# NAME:     Linux safe fixes
# ROLE:     Linux  (wave 2, first 15 minutes)
# KIND:     changes - dry run unless --apply
# VERSION:  2.0.0
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
#     uid0        accounts other than root with UID 0 (root-equivalent
#                 backdoors) locked and expired, so neither a password nor
#                 an SSH key logs in.  Undo puts the password and date back
#     emptypw     accounts with an EMPTY password locked (anyone could log
#                 in as them without one)
#     suid        the SUID bit removed from programs that should never have
#                 it (copies of bash, find, vim, python ... from GTFOBins)
#                 and from anything SUID in /tmp, /var/tmp, /dev/shm, /home
#   Every fix that acts on items (files, accounts, settings, services) asks
#   which ones to leave alone, or takes --exclude a,b,c.
#     forwarding  IP forwarding off - ONLY with --no-forwarding, because
#                 routers, firewalls and Docker hosts need it
#   Also REPORTED (never changed): extra /etc/hosts entries, IP forwarding
#   left on, services bound to a specific IPv6 address.
#
# HOW A RUN GOES  (sqlmap style: it asks, Enter takes the default)
#   1. A 2-minute revert timer starts (root only).  If the changes are not
#      kept before it runs out - for example because you got kicked off the
#      box - everything this run changed is put back.  It runs outside the
#      script (systemd timer, else a detached job), so a dead session does
#      not stop it.
#   2. Questions: which box this is, then one per fix.  Flags answer them in
#      advance; --batch takes every default without asking.
#   3. The plan: every change it would make, then "Apply these N changes?"
#   4. The changes, shown as they are made.
#   5. "Keep these changes?" - log in from a NEW session first.  y keeps
#      them; n or no answer before the timer undoes them.
#
# USAGE
#   sudo sh LX-39-safe-fixes.sh                    ask everything, then apply if you say so
#   sudo sh LX-39-safe-fixes.sh --apply --batch    no questions: defaults, apply, keep
#   sudo sh LX-39-safe-fixes.sh --batch            no questions, dry run only
#   sudo sh LX-39-safe-fixes.sh --apply --skip ipv6
#
# OPTIONS
#   --only a,b       run only these fixes (names from --list)
#   --skip a,b       leave these fixes out
#   --keep-ipv6      same as --skip ipv6
#   --exclude a,b    items no fix may touch: paths (/etc/crontab), account
#                    names (bob), kernel settings (net.ipv4.tcp_syncookies),
#                    services (auditd).  Answers the "leave alone" questions
#   --no-forwarding  also turn IP forwarding off (not on routers/firewalls/Docker)
#   --root DIR       treat DIR as / for every FILE fix (perms, tmp, preload,
#                    trust, the sysctl and limits files).  For fixing a
#                    mounted disk image, and for the tests.  Kernel settings
#                    and services still act on the running system
#   --box NAME       splunk | webmail | ecomm | other (skips that question)
#   --timer SECONDS  revert timer length (default 120)
#   --no-timer       no revert timer (you accept the risk)
#   --no-color       no colours
#   --batch          never ask: take every default (from the common options)
#   --list           list the fixes and exit
#   --help           this text plus the common options
#
# OUTPUTS  (under --out, one numbered folder per run: safe-fixes-1, -2, ...)
#   output.txt    everything shown on screen, without colours
#   summary.txt   counts per fix, every change, and the items to check by hand
#   plan.txt      what it would change (the dry-run pass)
#   fixes.txt     what it did: fix, item, before, after, status
#                 (status: changed | would change | already ok | failed |
#                  refused | skipped | check by hand)
#   csv/          plan.csv and fixes.csv
#   revert.sh     undoes this run (sh revert.sh --force); undo.txt, revert.log,
#                 KEEP and REVERTED belong to the revert timer
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
#   - The ipv6 fix has only run against a stand-in sysctl: the test machine's
#     kernel has no IPv6.  After the first real --apply check "ip -6 addr
#     show lo" still lists ::1.
#   - Inside a container some kernel settings are read-only; those show as
#     failed in fixes.txt and the rest still apply.
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

ALL_FIXES="sysctl ipv6 forwarding coredumps perms tmp logging preload trust uid0 emptypw suid hosts"
# Fixes that act on named items, so they can ask which ones to leave alone.
EXCL_FIXES="sysctl perms logging preload trust uid0 emptypw suid"

usage() {
    cat <<'USAGE'
LX-39 Linux safe fixes - hardening that cannot break a scored service
  sudo sh LX-39-safe-fixes.sh [--apply] [options]

  --only a,b       run only these fixes
  --skip a,b       leave these fixes out
  --keep-ipv6      leave IPv6 on (same as --skip ipv6)
  --exclude a,b    items to leave alone: paths, account names, kernel settings, services
  --no-forwarding  also turn IP forwarding off (NOT on routers, firewalls or Docker hosts)
  --root DIR       treat DIR as / for the file fixes (disk images, tests)
  --box NAME       splunk | webmail | ecomm | other (skips that question)
  --timer SECONDS  revert timer length (default 120)
  --no-timer       no revert timer (you accept the risk)
  --no-color       no colours
  --batch          never ask: take every default
  --list           list the fixes and exit
  --help           show this text

USAGE
    cc_usage_common
}

list_fixes() {
    cat <<'LIST'
sysctl      SYN cookies, ASLR, no source-routed packets or redirects, link protection
ipv6        IPv6 off with disable_ipv6 (loopback kept), never the boot option
forwarding  IP forwarding off (asks first if the box routes or runs Docker; with no one to ask, only with --no-forwarding)
coredumps   no setuid core dumps, core size limit 0
perms       remove group/other write (and read on secrets) from key files
tmp         sticky bit on /tmp, /var/tmp, /dev/shm
logging     start rsyslog / syslog-ng / auditd if installed and stopped
preload     quarantine /etc/ld.so.preload with unowned libraries; LD_PRELOAD lines
trust       quarantine .rhosts, .shosts, hosts.equiv, shosts.equiv
uid0        lock and expire accounts other than root with UID 0
emptypw     lock accounts that have an empty password
suid        remove SUID from programs that should never have it (GTFOBins copies, /tmp)
hosts       report extra /etc/hosts entries (report only)
LIST
}

ONLY=""; SKIP=""; NOFWD=0; R=""; BOX=""; TIMER=120; NOTIMER=0; FWDFLAG=0; EXCL=""; EXCLFLAG=0
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --only)          [ $# -ge 2 ] || cc_die 2 "--only needs a list of fixes"; ONLY=$2; shift 2 ;;
        --skip)          [ $# -ge 2 ] || cc_die 2 "--skip needs a list of fixes"; SKIP="$SKIP,$2"; shift 2 ;;
        --keep-ipv6)     SKIP="$SKIP,ipv6"; shift ;;
        --exclude)       [ $# -ge 2 ] || cc_die 2 "--exclude needs a list (paths, account names, settings, services)"
                         EXCL="$EXCL,$2"; EXCLFLAG=1; shift 2 ;;
        --no-forwarding) NOFWD=1; FWDFLAG=1; shift ;;
        --box)           [ $# -ge 2 ] || cc_die 2 "--box needs splunk, webmail, ecomm or other"; BOX=$2; shift 2 ;;
        --timer)         [ $# -ge 2 ] || cc_die 2 "--timer needs a number of seconds"; TIMER=$2; shift 2 ;;
        --no-timer)      NOTIMER=1; shift ;;
        --no-color|--no-colour) CC_NOCOLOR=1; shift ;;
        --root)          [ $# -ge 2 ] || cc_die 2 "--root needs a folder"
                         [ -d "$2" ] || cc_die 2 "--root: not a folder: $2"
                         R=$(cd "$2" && pwd); [ "$R" = / ] && R=""; shift 2 ;;
        --list)          list_fixes; exit 0 ;;
        --help|-h)       usage; exit 0 ;;
        *)               cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
case "$TIMER" in ''|*[!0-9]*) cc_die 2 "--timer needs a whole number of seconds" ;; esac
[ "$TIMER" -ge 2 ] || cc_die 2 "--timer must be at least 2 seconds"
case "$BOX" in ''|splunk|webmail|ecomm|other) ;; *) cc_die 2 "--box must be splunk, webmail, ecomm or other" ;; esac
for _n in $(printf '%s,%s' "$ONLY" "$SKIP" | tr ',' ' '); do
    case " $ALL_FIXES " in *" $_n "*) ;; *) cc_die 2 "unknown fix '$_n' (see --list)" ;; esac
done
FIXES=$ALL_FIXES
[ -n "$ONLY" ] && FIXES=$(printf '%s' "$ONLY" | tr ',' ' ')
# Naming forwarding in --only is asking for it, like --no-forwarding.
case ",$ONLY," in *,forwarding,*) NOFWD=1; FWDFLAG=1 ;; esac
_keep=""
for _f in $FIXES; do
    case ",$SKIP," in *",$_f,"*) continue ;; esac
    _keep="$_keep $_f"
done
FIXES=$_keep
# SETTLED: true when a flag already decided the fixes, so no per-fix questions.
SETTLED=0; [ -n "$ONLY$SKIP" ] && SETTLED=1

# The sysctl program.  CCDC_SYSCTL lets the tests use a stand-in by full
# path: busybox sh runs its own built-in sysctl in preference to PATH.
SYSCTL=${CCDC_SYSCTL:-sysctl}

cc_color_init

# protected_check -> with no protected list, ask before changing anything.
#   Sets CC_NO_PROTECTED=1 on yes; returns 1 on no.
protected_check() {
    [ "$CC_NO_PROTECTED" = 1 ] && return 0
    _pc=${CC_PROTECTED:-${CC_OUT:-${CCDC_OUT:-${HOME:-/root}/ccdc-out}}/protected.csv}
    [ -r "$_pc" ] && return 0
    cc_show "$C_YEL" "[*] No protected list at $_pc (the list of scored ports, services and accounts no script may touch)."
    if cc_ask "Continue without a protected list? LX-39 does not touch ports or services anyway" N; then CC_NO_PROTECTED=1; return 0; fi
    return 1
}
if [ "$CC_APPLY" = 1 ] && ! protected_check; then
    cc_show "$C_YEL" "[*] Staying in dry run: nothing will be changed."
    CC_APPLY=0
fi
APPLY_FLAG=$CC_APPLY

cc_init "LX-39" "Linux safe fixes" changes
cc_detect_os
if [ "$CC_APPLY" = 1 ] && [ -z "$R" ]; then cc_require_root; fi
cc_use_numbered_dir safe-fixes
CC_CSV_DIR="$CC_RUN_DIR/csv"
mkdir -p "$CC_CSV_DIR" || cc_die 3 "cannot create $CC_CSV_DIR"
W="$CC_RUN_DIR/.work"
mkdir -p "$W" || cc_die 3 "cannot create $W"
# Everything shown on screen also goes to output.txt (start line from the log).
OUTF="$CC_RUN_DIR/output.txt"
grep -v '\[NOTE\]\|\[DEBUG\]' "$CC_LOG" >"$OUTF" 2>/dev/null || : >"$OUTF"
CC_TEE=$OUTF
cc_show "$C_CYN" "LX-39 Linux safe fixes | host $CC_HOST | results in $CC_RUN_DIR"
cc_show "" "Legend: ${C_GRN}[+] changed${C_OFF}  ${C_YEL}[~] would change  [*] check by hand${C_OFF}  ${C_RED}[x] failed${C_OFF}  ${C_GRN}[ok] already right${C_OFF}"
[ -n "$R" ] && cc_show "$C_GRY" "File fixes act on $R (as if it were /)"

# Can this run change anything?  Root (or --root) and either --apply or
# someone at the keyboard to say yes.
CANAPPLY=0
if [ "$CC_APPLY" = 1 ] || _cc_can_ask; then
    if [ -n "$R" ] || cc_is_root; then CANAPPLY=1; fi
fi
if [ "$CANAPPLY" = 0 ]; then
    if cc_is_root || [ -n "$R" ]; then cc_show "$C_GRY" "Dry run only (--batch without --apply): nothing will be changed."
    else cc_show "$C_GRY" "Dry run only (not root): nothing will be changed. Run with sudo to make changes."; fi
elif [ "$NOTIMER" = 1 ]; then
    cc_show "$C_YEL" "[*] No revert timer (--no-timer): if a change locks you out, nothing puts it back."
else
    cc_timer_start "$TIMER"
    cc_show "$C_YEL" "[*] Revert timer started: everything this run changes is undone in $((TIMER / 60)):$(printf '%02d' $((TIMER % 60))) unless you keep it at the end."
fi

# ---- Helpers ----------------------------------------------------------------
# row ITEM BEFORE AFTER STATUS -> one line in the CSV for the current fix,
#   and one coloured line on screen ("already ok" lines are only counted).
OKN=0
row() {
    cc_csv_row "$CSV" "$FIX" "$1" "$2" "$3" "$4"
    _rw_ch=""; [ -n "$2$3" ] && _rw_ch="  ${2:-(none)} -> ${3:-(none)}"
    case "$4" in
        "would change")  cc_show "$C_YEL" "  [~] $1$_rw_ch" ;;
        changed)         cc_show "$C_GRN" "  [+] $1$_rw_ch" ;;
        failed)          cc_show "$C_RED" "  [x] FAILED $1$_rw_ch" ;;
        refused)         cc_show "$C_YEL" "  [-] refused (protected list): $1" ;;
        "check by hand") cc_show "$C_YEL" "  [*] check: $1 - $3" ;;
        "already ok"*|skipped*) OKN=$((OKN + 1)) ;;
        excluded*)       cc_show "$C_GRY" "  [-] left alone (you excluded it): $1" ;;
        *)               cc_show "$C_YEL" "  [*] $1: $4" ;;
    esac
    return 0
}
# is_excluded ITEM -> true if ITEM is on the leave-alone list (--exclude or
#   an answer to a "leave alone" question).
is_excluded() {
    case ",$EXCL," in *",$1,"*) return 0 ;; esac
    return 1
}
# ok_line -> "[ok] N already right" for the block just shown.
ok_line() { [ "$OKN" -gt 0 ] && cc_show "$C_GRN" "  [ok] $OKN already right"; OKN=0; return 0; }
# header TEXT -> a section header, linpeas style.
header() { cc_show "" ""; cc_show "$C_CYN" "==========[ $1 ]=========="; }
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
    # Each path once per pass: the world-writable sweep would otherwise list
    # a file the named rules above already handled.
    grep -qxF "$_sm_p" "$W/handled" 2>/dev/null && return 0
    printf '%s\n' "$_sm_p" >>"$W/handled"
    if is_excluded "$_sm_item"; then row "$_sm_item" "$_sm_old" "" "excluded"; return 0; fi
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
    if is_excluded "$1"; then row "$1" "" "" "excluded"; return 0; fi
    if ! _ws_cur=$("$SYSCTL" -n "$1" 2>/dev/null); then
        row "$1" "" "$2" "skipped (not on this kernel)"
        return 0
    fi
    printf '%s|%s|%s|%s\n' "$FIX" "$1" "$2" "$_ws_cur" >>"$W/sysctl_want"
}

# ---- Fixes --------------------------------------------------------------------
: >"$W/sysctl_want"; : >"$W/report"
# report ITEM TEXT -> something to check by hand (summary and the CSV).
report() { printf '%s|%s|%s\n' "$FIX" "$1" "$2" >>"$W/report"; row "$1" "" "$2" "check by hand"; }

KEEPLO=0    # 1 = the ipv6 fix ran: keep IPv6 on the loopback interface
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
    want_sysctl kernel.unprivileged_bpf_disabled 1
    want_sysctl net.ipv4.tcp_rfc1337 1
    want_sysctl fs.protected_fifos 1
    want_sysctl fs.protected_regular 1
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
    # "all" also switches IPv6 off on loopback and removes ::1.  It is
    # switched back on there AFTER the two settings above (see the kernel
    # settings step), so services bound to ::1 keep starting.
    "$SYSCTL" -n net.ipv6.conf.lo.disable_ipv6 >/dev/null 2>&1 && KEEPLO=1
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
        if is_excluded "$_s"; then row "$_s" "" "" "excluded"; continue; fi
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
    if is_excluded /etc/ld.so.preload; then row /etc/ld.so.preload "" "" "excluded"; _pl=/nonexistent/ld.so.preload; fi
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
        if is_excluded "$_f"; then row "$_f" "" "" "excluded"; continue; fi
        _n=$((_n + 1))
        cc_quarantine "$(P "$_f")"
        _rc=$?
        if [ "$_rc" -eq 4 ]; then row "$_f" present present refused; else row "$_f" "lets other hosts log in without a password" quarantined "$(result "$_rc")"; fi
    done <"$W/trust"
    [ "$_n" -eq 0 ] && row "(rhosts-style files)" none "" "already ok"
}

# ---- Accounts -------------------------------------------------------------------
# The shadow file is edited with awk into a copy, then written back with
# cat (keeps its owner and mode).  The password field is never logged or
# stored: a lock only adds "!" in front, and the undo only removes it.

# uid0_list -> accounts other than root with UID 0.
uid0_list() { awk -F: '$3 == "0" && $1 != "root" { print $1 }' "$(P /etc/passwd)" 2>/dev/null; }
# emptypw_list -> accounts whose password field in shadow is empty.
emptypw_list() { awk -F: 'NF > 1 && $2 == "" { print $1 }' "$(P /etc/shadow)" 2>/dev/null; }

# lock_account USER EXPIRE WHY
#   Put "!" in front of USER's password (no password login) and, with
#   EXPIRE=1, set the account's expiry to day 1 (no login at all, SSH keys
#   included).  The undo removes the "!" and puts the old expiry back.
lock_account() {
    _la_u=$1; _la_e=$2; _la_why=$3
    _la_sf=$(P /etc/shadow)
    [ -r "$_la_sf" ] || { row "$_la_u" "" "" "skipped (cannot read /etc/shadow)"; return 0; }
    if is_excluded "$_la_u"; then row "$_la_u" "" "" "excluded"; return 0; fi
    # State without the secret: L = locked already, and the expiry field.
    _la_st=$(awk -F: -v u="$_la_u" '$1 == u { print (($2 ~ /^[!*]/) ? "L" : "U") "|" $8; exit }' "$_la_sf")
    [ -n "$_la_st" ] || { row "$_la_u" "" "" "skipped (not in /etc/shadow)"; return 0; }
    _la_lk=${_la_st%%"|"*}; _la_old8=${_la_st#*"|"}
    _la_bang=0; [ "$_la_lk" = U ] && _la_bang=1
    _la_exp=0; [ "$_la_e" = 1 ] && [ "$_la_old8" != 1 ] && _la_exp=1
    _la_before="unlocked"; [ "$_la_lk" = L ] && _la_before="locked"
    [ "$_la_e" = 1 ] && _la_before="$_la_before, expires ${_la_old8:-never}"
    _la_after="locked"; [ "$_la_e" = 1 ] && _la_after="locked, expired"
    if [ "$_la_bang" = 0 ] && [ "$_la_exp" = 0 ]; then row "$_la_u" "$_la_before" "$_la_after" "already ok"; return 0; fi
    if ! cc_guard account "$_la_u"; then row "$_la_u" "$_la_before" "$_la_after" refused; return 0; fi
    awk -F: -v OFS=: -v u="$_la_u" -v b="$_la_bang" -v e="$_la_exp" '
        $1 == u { if (b == 1) $2 = "!" $2; if (e == 1) $8 = 1 } { print }' "$_la_sf" >"$W/shadow.new"
    cc_run "lock account $_la_u ($_la_why)" sh -c 'cat "$1" >"$2"' sh "$W/shadow.new" "$_la_sf"
    _la_rc=$?
    rm -f "$W/shadow.new"
    if [ "$_la_rc" -eq 0 ]; then
        _la_q=$(cc_shquote "$_la_sf"); _la_t=$(cc_shquote "$_la_sf.ccdc-tmp")
        cc_undo_add "unlock account $_la_u" "awk -F: -v OFS=: -v u=$(cc_shquote "$_la_u") -v b=$_la_bang -v e=$_la_exp -v o=$(cc_shquote "$_la_old8") '\$1 == u { if (b == 1) sub(/^!/, \"\", \$2); if (e == 1) \$8 = o } { print }' $_la_q >$_la_t && cat $_la_t >$_la_q && rm -f $_la_t"
    fi
    row "$_la_u" "$_la_before" "$_la_after" "$(result "$_la_rc")"
}

fix_uid0() {
    uid0_list >"$W/uid0"
    [ -s "$W/uid0" ] || { row "(accounts with UID 0)" "only root" "" "already ok"; return 0; }
    while IFS= read -r _u; do lock_account "$_u" 1 "UID 0 = root-equivalent; a classic backdoor account"; done <"$W/uid0"
}

fix_emptypw() {
    [ -r "$(P /etc/shadow)" ] || { row /etc/shadow "" "" "skipped (cannot read it)"; return 0; }
    emptypw_list >"$W/emptypw"
    [ -s "$W/emptypw" ] || { row "(accounts with an empty password)" none "" "already ok"; return 0; }
    while IFS= read -r _u; do lock_account "$_u" 0 "empty password: anyone could log in as it"; done <"$W/emptypw"
}

# ---- SUID programs ------------------------------------------------------------------
# Programs that give a root shell when SUID (GTFOBins), but are never SUID on
# a normal system.  The usual SUID programs (passwd, sudo, su, mount, ping,
# pkexec, chsh ...) are not on this list and are never touched.
GTFO=" ash awk base64 bash busybox cat chmod chown cp csh curl cut dash date dd diff ed emacs env expect find flock gdb grep head hexdump ionice ip jq ksh less lua make more mv nano nawk gawk mawk nc ncat nice nmap node nohup od openssl perl php pico python python2 python3 rlwrap rsync run-parts rvim sed setarch socat sort sqlite3 strace systemctl tac tail tar taskset tclsh tee time timeout unshare vi view vim watch wget xargs xxd zip zsh "

# suid_list -> SUID files that should not be SUID, one path per line.
suid_list() {
    for _d in /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /opt /tmp /var/tmp /dev/shm /home /root; do
        [ -d "$(P "$_d")" ] && [ ! -h "$(P "$_d")" ] && find "$(P "$_d")" -xdev -type f -perm -4000 2>/dev/null
    done | sort -u | while IFS= read -r _p; do
        _i=${_p#"$R"}
        case "$_i" in /tmp/*|/var/tmp/*|/dev/shm/*|/home/*|/root/*) printf '%s\n' "$_i"; continue ;; esac
        _b=$(basename "$_i" | sed 's/[0-9.]*$//')
        case "$GTFO" in *" $_b "*) printf '%s\n' "$_i" ;; esac
    done
}

fix_suid() {
    suid_list >"$W/suid"
    [ -s "$W/suid" ] || { row "(SUID programs)" "only the usual ones" "" "already ok"; return 0; }
    while IFS= read -r _i; do set_mode "$(P "$_i")" 4000 0000 "SUID on a program that gives a root shell"; done <"$W/suid"
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

# ---- Questions ------------------------------------------------------------------
# fix_desc NAME -> the one-line description from --list.
fix_desc() { list_fixes | awk -v f="$1" '$1 == f { $1 = ""; sub(/^ +/, ""); print }'; }

header "QUESTIONS (Enter = the default in capitals)"
if [ -z "$BOX" ]; then
    cc_ask_text "Which box is this? splunk / webmail / ecomm / other" other
    BOX=$CC_ANSWER
    case "$BOX" in splunk|webmail|ecomm|other) ;; *) cc_show "$C_GRY" "    '$BOX' is not one of the four: using other"; BOX=other ;; esac
fi
case "$BOX" in
    splunk)  cc_show "$C_GRY" "    Scored here: chrony (123/udp), Splunk management (8089), search, SSH, ping. LX-39 touches none of them." ;;
    webmail) cc_show "$C_GRY" "    Scored here: IMAP, SMTP, webmail login, SSH, ping. LX-39 touches none of them." ;;
    ecomm)   cc_show "$C_GRY" "    Scored here: HTTP, ping. If the store runs in Docker, IP forwarding must stay on." ;;
esac
if [ "$SETTLED" = 1 ]; then
    # --only / --skip decided the list.  forwarding still needs --no-forwarding
    # (or naming it in --only), because routers and Docker hosts need it.
    _keep=""
    for _f in $FIXES; do [ "$_f" = forwarding ] && [ "$NOFWD" = 0 ] && continue; _keep="$_keep $_f"; done
    FIXES=$_keep
    cc_show "$C_GRY" "    Fixes chosen by --only/--skip:$FIXES"
else
    _keep=""
    for _f in $FIXES; do
        case "$_f" in
            forwarding)
                if [ "$FWDFLAG" = 1 ]; then _keep="$_keep $_f"; continue; fi
                # Nobody to ask (--batch, no terminal): forwarding stays on
                # unless --no-forwarding said otherwise.
                if ! _cc_can_ask; then cc_show "$C_GRY" "    IP forwarding: left on (turn it off with --no-forwarding)"; continue; fi
                _d=N; [ "$BOX" = ecomm ] && _d=Y
                if cc_ask "Does this box route traffic or run Docker/containers? (they need IP forwarding)" "$_d"; then
                    cc_show "$C_GRY" "    IP forwarding stays on."
                elif cc_ask "Turn IP forwarding off? (forwarding)" Y; then
                    _keep="$_keep $_f"; NOFWD=1
                fi ;;
            ipv6)  cc_ask "Turn IPv6 off? Check no scored service uses IPv6 first (ipv6)" Y && _keep="$_keep $_f" ;;
            hosts) cc_ask "Check /etc/hosts for odd entries? Report only (hosts)" Y && _keep="$_keep $_f" ;;
            uid0|emptypw|suid)
                # Show what it found first, so you know what you are answering.
                case "$_f" in uid0) uid0_list >"$W/found" ;; emptypw) emptypw_list >"$W/found" ;; suid) suid_list >"$W/found" ;; esac
                if [ ! -s "$W/found" ]; then cc_show "$C_GRY" "    $_f: nothing found ($(fix_desc "$_f"))"; continue; fi
                cc_show "$C_YEL" "    $_f found: $(tr '\n' ' ' <"$W/found")"
                cc_ask "$(fix_desc "$_f")? ($_f)" Y && _keep="$_keep $_f" ;;
            *)     cc_ask "$(fix_desc "$_f")? ($_f)" Y && _keep="$_keep $_f" ;;
        esac
        # A fix that acts on named items: ask what to leave alone (unless
        # --exclude already said).
        case " $_keep " in *" $_f "*) ;; *) continue ;; esac
        case " $EXCL_FIXES " in *" $_f "*) ;; *) continue ;; esac
        [ "$EXCLFLAG" = 1 ] && continue
        case "$_f" in
            uid0|emptypw) _what="account names" ;;
            suid|perms|trust|preload) _what="paths" ;;
            sysctl) _what="settings, e.g. net.ipv4.tcp_syncookies" ;;
            logging) _what="services: rsyslog, syslog-ng, auditd" ;;
        esac
        cc_ask_text "  Leave any alone for $_f? ($_what, comma list)" ""
        [ -n "$CC_ANSWER" ] && EXCL="$EXCL,$CC_ANSWER"
    done
    FIXES=$_keep
fi
EXCL=$(printf '%s' "$EXCL" | tr -d ' ')
[ -n "$(printf '%s' "$EXCL" | tr -d ',')" ] && cc_show "$C_GRY" "    Left alone:$(printf '%s' "$EXCL" | tr ',' ' ')"
case " $FIXES " in *" forwarding "*) NOFWD=1 ;; esac

# ---- The fixes, as one pass ---------------------------------------------------
# run_all runs every chosen fix and the kernel settings step.  It runs twice:
# first as a dry run to show the plan, then (if you say yes) for real.
run_all() {
: >"$W/sysctl_want"; : >"$W/report"; : >"$W/handled"; KEEPLO=0
_ra_q=$CC_QUIET; CC_QUIET=1        # the coloured lines replace WOULD/DO lines
_ra_i=0; _ra_n=$(printf '%s\n' $FIXES | grep -c .)
for FIX in $FIXES; do
    _ra_i=$((_ra_i + 1))
    header "$_ra_i/$_ra_n  $FIX"
    "fix_$FIX"
    ok_line
done

# IP forwarding left on is worth a look even when it is not being changed.
if [ "$NOFWD" = 0 ] && [ "$CC_OS_KERNEL" = linux ] && [ "$("$SYSCTL" -n net.ipv4.ip_forward 2>/dev/null)" = 1 ]; then
    FIX=forwarding
    report net.ipv4.ip_forward "IP forwarding is on: right for a router, firewall or Docker host; otherwise run again with --no-forwarding"
fi

# ---- Kernel settings: one file for boot, then the running values -------------
if [ -s "$W/sysctl_want" ]; then
    header "kernel settings (sysctl, ipv6, forwarding, coredumps)"
    _sd=$(P /etc/sysctl.d)
    if [ -d "$_sd" ]; then _sf="$_sd/99-zz-ccdc-safe.conf"; _sfi=/etc/sysctl.d/99-zz-ccdc-safe.conf
    else _sf=$(P /etc/sysctl.conf); _sfi=/etc/sysctl.conf; fi
    # The boot file holds every wanted key (also those already right), so the
    # values survive a reboot even if another file sets them differently.
    {
        printf '# Written by LX-39 (CCDC kit). Read last at boot (99-zz). Undo log has the old values.\n'
        awk -F'|' '{ print $2 " = " $3 }' "$W/sysctl_want"
        # Must come after "all": the last value written to an interface wins.
        [ "$KEEPLO" = 1 ] && printf '# loopback keeps IPv6 (::1) so services bound to it still start\nnet.ipv6.conf.lo.disable_ipv6 = 0\n'
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
    _v6set=0
    while IFS='|' read -r FIX _k _v _cur; do
        if [ "$_cur" = "$_v" ]; then row "$_k" "$_cur" "$_v" "already ok"; continue; fi
        [ "$_k" = net.ipv6.conf.all.disable_ipv6 ] && _v6set=1
        cc_run "kernel setting $_k $_cur -> $_v" "$SYSCTL" -w "$_k=$_v"
        _rc=$?
        [ "$_rc" -eq 0 ] && cc_undo_add "restore $_k" "$SYSCTL -w $_k=$_cur"
        row "$_k" "$_cur" "$_v" "$(result "$_rc")"
    done <"$W/sysctl_want"
    # Loopback: switched back on after "all" switched everything off.  Needed
    # when "all" was just changed (that also changed loopback) or when
    # loopback is off from an earlier change.
    if [ "$KEEPLO" = 1 ]; then
        FIX=ipv6; _k=net.ipv6.conf.lo.disable_ipv6
        _cur=$("$SYSCTL" -n "$_k" 2>/dev/null)
        if [ "$_v6set" = 1 ] || [ "$_cur" != 0 ]; then
            cc_run "keep IPv6 on loopback (::1 stays)" "$SYSCTL" -w "$_k=0"
            row "$_k" "$_cur" 0 "$(result $?)"
        else
            row "$_k" "$_cur" 0 "already ok"
        fi
    fi
    ok_line
fi
CC_QUIET=$_ra_q
}

# ---- Plan, then apply -----------------------------------------------------------
CSV=$(cc_csv_new plan "fix,item,before,after,status")
_real_apply=$CC_APPLY; CC_APPLY=0
header "PLAN (dry run: nothing is changed yet)"
run_all
CC_APPLY=$_real_apply
NCH=$(awk "$CC_AWK_CSV"'NR > 1 { csvsplit($0, f); if (f[5] == "would change") n++ } END { print n + 0 }' "$CSV")
cc_csv_pretty "$CSV" "$CC_RUN_DIR/plan.txt" 80
APPLIED=0
header "DECISION"
if [ "$NCH" -eq 0 ]; then
    cc_show "$C_GRN" "[ok] Nothing to change: every chosen fix is already in place."
elif [ "$CANAPPLY" = 0 ]; then
    cc_show "$C_GRY" "$NCH change(s) planned. Dry run only, so nothing was changed."
else
    _ad=N; [ "$APPLY_FLAG" = 1 ] && _ad=Y
    if cc_ask "Apply these $NCH change(s)?" "$_ad"; then
        if [ "$APPLY_FLAG" = 0 ] && ! protected_check; then
            cc_show "$C_YEL" "[*] Not applied: no protected list."
        elif cc_timer_fired || { [ "$CC_TIMER_DEADLINE" -gt 0 ] && [ "$(cc_timer_left)" -lt 3 ]; }; then
            cc_die 3 "the revert timer ran out before anything was changed. Nothing was changed. Run again (--batch or flags skip the questions; --timer SECONDS gives more time)"
        else
            CC_APPLY=1; APPLIED=1; CC_N_WOULD=0    # the plan pass counted these
            CSV=$(cc_csv_new fixes "fix,item,before,after,status")
            header "APPLYING"
            run_all
            cc_csv_pretty "$CSV" "$CC_RUN_DIR/fixes.txt" 80
        fi
    else
        cc_show "$C_GRY" "Not applied. The plan is in $CC_RUN_DIR/plan.txt"
    fi
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
    [ "$_nch" -gt 60 ] && printf '  ... %d more in fixes.txt\n' "$((_nch - 60))"
    [ "$_nch" -eq 0 ] && printf '  Nothing to change: every fix was already in place.\n'
    if [ -s "$W/report" ]; then
        printf '\nCheck by hand (not changed):\n'
        awk -F'|' '{ l = "  " $2 ": " $3; if (length(l) > 200) l = substr(l, 1, 197) "..."; print l }' "$W/report"
    fi
    printf '\n'
    if [ "$APPLIED" = 1 ]; then
        printf 'Undo this run at any time: sh %s/revert.sh --force\n' "$CC_RUN_DIR"
        printf '(every host change is also in %s)\n' "$CC_UNDO"
    else
        printf 'Nothing was changed.\n'
    fi
    printf 'All results: %s\n' "$CC_RUN_DIR"
} >"$CC_RUN_DIR/summary.txt"
# Without a timer, revert.sh still needs writing for "undo at any time".
if [ "$APPLIED" = 1 ] && [ -z "$CC_TIMER_DIR" ]; then
    cc_show "$C_GRY" "Undo commands: $CC_UNDO (newest at the bottom)"
fi
header "SUMMARY"
# Coloured on screen: red failed, green changed, yellow would-change and
# check-by-hand, cyan headings.  summary.txt and output.txt stay plain.
awk -v R="$C_RED" -v Y="$C_YEL" -v G="$C_GRN" -v C="$C_CYN" -v D="$C_GRY" -v O="$C_OFF" '
    NR == 1 || /^fix +changes/ { intable = /^fix/; print C $0 O; next }
    intable && /^$/            { intable = 0; print; next }
    intable                    { if ($4 + 0 > 0) print R $0 O; else if ($2 + 0 > 0) print Y $0 O; else print G $0 O; next }
    /^  CHANGED/               { print G $0 O; next }
    /^  FAILED/                { print R $0 O; next }
    /^  WOULD CHANGE/          { print Y $0 O; next }
    /^Check by hand/           { hand = 1; print Y $0 O; next }
    hand && /^  /              { print Y $0 O; next }
    /^Nothing to change/ || /^  Nothing to change/ { print G $0 O; next }
                               { hand = 0; print D $0 O }
' "$CC_RUN_DIR/summary.txt"
cat "$CC_RUN_DIR/summary.txt" >>"$OUTF"
rm -rf "$W"
if [ "$APPLIED" = 1 ]; then
    header "KEEP OR REVERT"
    cc_timer_finish
elif [ -n "$CC_TIMER_DIR" ]; then
    cc_timer_cancel; : >"$CC_TIMER_DIR/KEEP"
fi
cc_finish
