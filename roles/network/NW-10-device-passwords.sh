#!/bin/sh
# =============================================================================
# ID:       NW-10
# NAME:     Network device password rotation
# ROLE:     Network  (wave 2, first 15 minutes)
# KIND:     changes - dry run unless --apply
# VERSION:  1.0.0
#
# PURPOSE
#   Default and leaked passwords on firewalls and switches are a red team's
#   fastest way in.  For each device this changes the password of the account
#   used to log in (and, for Cisco, optionally the enable secret) WITHOUT
#   risking a lock-out:
#     1. log in with the current password and send the change, keeping that
#        session OPEN
#     2. open a SECOND, new session with the new password
#     3. it works  -> save the config through the first session, close it
#        it fails  -> set the OLD password back through the first session,
#                     close it, and report the device as failed
#   New passwords go to one file (mode 600) for the captain, never the
#   screen or the log.
#
#   Vendors: cisco-ios, cisco-asa, paloalto (commit), fortigate, vyos
#   (commit, save), mikrotik, linux.  pfsense/opnsense: not supported (no
#   safe CLI for it) - change those in the web GUI; they are listed.
#
# USAGE
#   CCDC_NET_PASS='current' sh NW-10-device-passwords.sh --hosts hosts.csv          dry run
#   CCDC_NET_PASS='current' sh NW-10-device-passwords.sh --hosts hosts.csv --apply
#   sh NW-10-device-passwords.sh --device r1,10.0.0.1,cisco-ios,admin --ask-password --apply
#
# OPTIONS
#   --hosts FILE / --device SPEC   the devices, as for NW-01
#   --user NAME          default login account (admin)
#   --ask-password       ask for the CURRENT password (else $CCDC_NET_PASS)
#   --new-password-env   use $CCDC_NET_NEWPASS as the new password for every
#                        device (default: a new random one per device)
#   --enable-env         Cisco: log in through enable with $CCDC_NET_ENABLE
#   --enable-too         Cisco: also set a new enable secret (verified too)
#   --length N           random password length (default 16, minimum 12)
#   --wait N             seconds to let a change apply before testing it
#                        (default 5; Palo Alto commits use --commit-wait)
#   --commit-wait N      Palo Alto: seconds for the commit (default 120)
#   --configs DIR        NW-01's saved configs (default <out>/net-configs);
#                        Cisco privilege levels are read from there
#   --legacy-ssh         allow old SSH algorithms
#   --help               this text plus the common options
#
# OUTPUTS  (under --out, in NW-10_<host>_<UTC time>/)
#   summary.txt     each device: changed / would change / failed (reverted) / skipped
#   devices.csv     device,address,vendor,account,status
#   passwords.csv   device,address,account,password,time  (mode 600, --apply only)
#
# WHAT IT CHANGES  (only with --apply)
#   The login account's password on each device (and the Cisco enable secret
#   with --enable-too), saved to the startup config / committed.  A device or
#   account on the protected list is skipped (protected host = the device's
#   address; protected account = the login account, unless --force-scored).
#
# DEPENDS ON
#   ssh, sshpass, mkfifo; openssl for Palo Alto (password hash).  CCDC_SSH and
#   CCDC_SSHPASS may name stand-ins (the tests use them).
#
# TESTED ON
#   Live against a real OpenSSH server (vendor linux): the password changed,
#   the new one logged in, the old one did not.  Every vendor's command
#   sequence, the verify step and the automatic revert against a stand-in
#   device under dash, bash, busybox sh, ksh93, mksh and yash.  NOT yet on
#   real Cisco, Palo Alto, FortiGate, VyOS or MikroTik devices: try it on ONE
#   device first.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - Only local accounts.  TACACS/RADIUS/LDAP logins are changed on that server.
#   - Cisco: the account must be in the saved config (run NW-01 first) so its
#     privilege level is kept; re-entering "username" without it drops it to 1.
#   - Palo Alto commits take a minute or more; the first session waits.
#   - If the scoring engine logs in to a device, put that account (or the
#     device) on the protected list, or report the new password as required.
#
# DEBUGGING
#   --debug shows each step per device (never a password).  Device output is
#   NOT logged: it can echo the new password.
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

VENDORS="cisco-ios cisco-asa paloalto fortigate vyos mikrotik linux pfsense opnsense"

usage() {
    cat <<'USAGE'
NW-10 Network device password rotation - change, prove the new login, then save (or revert)
  CCDC_NET_PASS=current sh NW-10-device-passwords.sh --hosts FILE | --device SPEC [--apply] [options]

  --hosts FILE / --device NAME,ADDRESS,VENDOR[,USER[,PORT]]
  --user NAME          default login account (admin)
  --ask-password       ask for the current password
  --new-password-env   new password from $CCDC_NET_NEWPASS (default: random per device)
  --enable-env         Cisco: enable password from $CCDC_NET_ENABLE
  --enable-too         Cisco: also set a new enable secret
  --length N           random password length (default 16)
  --wait N             seconds before testing a change (default 5)
  --commit-wait N      Palo Alto commit time (default 120)
  --configs DIR        NW-01's saved configs (Cisco privilege levels)
  --legacy-ssh         allow old SSH algorithms
  --help               show this text

USAGE
    cc_usage_common
}

NL='
'
HOSTS=""; DEVICES=""; DEFUSER="admin"; ASK=0; NEWENV=0; ENABLE=0; ENTOO=0; LEN=16; WAIT=5; CWAIT=120; CONFIGS=""; LEGACY=0
num() { case "$2" in ''|*[!0-9]*) cc_die 2 "$1 needs a whole number" ;; esac; }
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --hosts)            [ $# -ge 2 ] || cc_die 2 "--hosts needs a file"; [ -r "$2" ] || cc_die 2 "--hosts: cannot read $2"; HOSTS=$2; shift 2 ;;
        --device)           [ $# -ge 2 ] || cc_die 2 "--device needs NAME,ADDRESS,VENDOR"; DEVICES="$DEVICES$2$NL"; shift 2 ;;
        --user)             [ $# -ge 2 ] || cc_die 2 "--user needs a name"; DEFUSER=$2; shift 2 ;;
        --ask-password)     ASK=1; shift ;;
        --new-password-env) NEWENV=1; shift ;;
        --enable-env)       ENABLE=1; shift ;;
        --enable-too)       ENTOO=1; shift ;;
        --length)           num "$1" "${2:-}"; LEN=$2; shift 2 ;;
        --wait)             num "$1" "${2:-}"; WAIT=$2; shift 2 ;;
        --commit-wait)      num "$1" "${2:-}"; CWAIT=$2; shift 2 ;;
        --configs)          [ $# -ge 2 ] || cc_die 2 "--configs needs a folder"; CONFIGS=$2; shift 2 ;;
        --legacy-ssh)       LEGACY=1; shift ;;
        --help|-h)          usage; exit 0 ;;
        *)                  cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
[ -n "$HOSTS$DEVICES" ] || cc_die 2 "give --hosts FILE or --device NAME,ADDRESS,VENDOR (try --help)"
[ "$LEN" -ge 12 ] || cc_die 2 "--length must be at least 12"

cc_init "NW-10" "Device password rotation" changes
cc_use_run_dir
W="$CC_RUN_DIR/.work"
(umask 077; mkdir -p "$W") || cc_die 3 "cannot create $W"
[ -n "$CONFIGS" ] || CONFIGS="$CC_OUT/net-configs"
(umask 077; mkdir -p "$CONFIGS") || cc_die 3 "cannot create $CONFIGS"
ENTEST=""
DCSV=$(cc_csv_new devices "device,address,vendor,account,status")
SSH=${CCDC_SSH:-$(cc_which ssh)} || cc_die 3 "ssh not found"
SSHPASS_BIN=${CCDC_SSHPASS:-$(cc_which sshpass)} || cc_die 3 "sshpass not found (apt install sshpass): password changes need password logins"
cc_have mkfifo || cc_die 3 "mkfifo not found"

# ---- Passwords --------------------------------------------------------------
if [ "$ASK" = 1 ]; then
    [ -r /dev/tty ] || cc_die 3 "--ask-password needs a terminal; set CCDC_NET_PASS"
    printf 'CURRENT device password: ' >/dev/tty; stty -echo </dev/tty 2>/dev/null
    read -r CCDC_NET_PASS </dev/tty; stty echo </dev/tty 2>/dev/null; printf '\n' >/dev/tty
fi
OLDPW=${CCDC_NET_PASS:-}
[ -n "$OLDPW" ] || cc_die 3 "the current password is needed: set CCDC_NET_PASS or use --ask-password"
if [ "$NEWENV" = 1 ]; then
    [ -n "${CCDC_NET_NEWPASS:-}" ] || cc_die 3 "--new-password-env: set CCDC_NET_NEWPASS"
    # Only characters every device CLI takes literally ("?" is Cisco help,
    # quotes and spaces end a word, "#" and "!" start comments).
    case "$CCDC_NET_NEWPASS" in *[!A-Za-z0-9_.,@%+=-]*) cc_die 2 "CCDC_NET_NEWPASS may only use letters, digits and _ . , @ % + = -" ;; esac
    [ "${#CCDC_NET_NEWPASS}" -ge 12 ] || cc_die 2 "CCDC_NET_NEWPASS must be at least 12 characters"
fi
case "$OLDPW" in *[\ \"\'?#]*) cc_warn "the current password has a space, quote, ? or #: an automatic revert may not be able to type it" ;; esac
[ "$ENABLE" = 1 ] && [ -z "${CCDC_NET_ENABLE:-}" ] && cc_die 3 "--enable-env: set CCDC_NET_ENABLE"

# ---- Devices (same rules as NW-01) ---------------------------------------------
vendor_of() {
    printf '%s' "$1" | tr 'A-Z' 'a-z' | awk '
        /cisco-ios|ios-xe|catalyst|cisco ios|cisco router|cisco switch/ { print "cisco-ios"; exit }
        /cisco-asa|asa|firepower|ftd/ { print "cisco-asa"; exit }
        /paloalto|palo alto|pan-os|panos/ { print "paloalto"; exit }
        /fortigate|fortinet|fortios/ { print "fortigate"; exit }
        /vyos|vyatta/ { print "vyos"; exit }
        /opnsense/ { print "opnsense"; exit }
        /pfsense/ { print "pfsense"; exit }
        /mikrotik|routeros/ { print "mikrotik"; exit }
        /cisco/ { print "cisco-ios"; exit }'
}
: >"$W/devices"
if [ -n "$HOSTS" ]; then
    awk -F',' "$CC_AWK_CSV"'
        /^[ \t]*#/ || NF < 2 { next }
        !hdr { n = csvsplit($0, h); for (i = 1; i <= n; i++) c[tolower(h[i])] = i; hdr = 1; next }
        { csvsplit($0, f); print f[c["host"]] "|" f[c["ip"]] "|" tolower(f[c["os"]]) "|" (("vendor" in c) ? f[c["vendor"]] : "") "|" f[c["notes"]] "|" (("user" in c) ? f[c["user"]] : "") "|" (("port" in c) ? f[c["port"]] : "") }' "$HOSTS" >"$W/rows"
    while IFS='|' read -r _n _a _os _v _notes _u _p; do
        _vend=""; [ -n "$_v" ] && _vend=$(vendor_of "$_v")
        [ -z "$_vend" ] && [ "$_os" != linux ] && case " $VENDORS " in *" $_os "*) _vend=$_os ;; esac
        [ -z "$_vend" ] && [ "$_os" = network ] && _vend=$(vendor_of "$_notes")
        [ -n "$_vend" ] || continue
        printf '%s|%s|%s|%s|%s\n' "$_n" "$_a" "$_vend" "${_u:-$DEFUSER}" "${_p:-22}" >>"$W/devices"
    done <"$W/rows"
fi
printf '%s' "$DEVICES" | grep . | while IFS=',' read -r _n _a _v _u _p; do
    case " $VENDORS " in *" $_v "*) ;; *) echo "BADV|$_v"; continue ;; esac
    [ -n "$_n" ] && [ -n "$_a" ] || { echo "BAD|$_n"; continue; }
    printf '%s|%s|%s|%s|%s\n' "$_n" "$_a" "$_v" "${_u:-$DEFUSER}" "${_p:-22}"
done >>"$W/devices"
grep -q '^BAD' "$W/devices" && cc_die 2 "--device needs NAME,ADDRESS,VENDOR with a known vendor ($VENDORS)"
[ -s "$W/devices" ] || cc_die 3 "no network devices found"

# ---- Per-vendor command sequences ----------------------------------------------
# priv DEVICE USER -> the account's privilege level in NW-01's newest copy.
priv() {
    _pf="$CONFIGS/$1/$(cat "$CONFIGS/$1/latest" 2>/dev/null).cfg"
    [ -f "$_pf" ] || return 1
    tr -d '\r' <"$_pf" | awk -v u="$2" '$1 == "username" && $2 == u { for (i = 3; i <= NF; i++) if ($i == "privilege") { print $(i + 1); exit } print "1"; exit }'
}
# preamble VENDOR -> lines that start a session (enable for Cisco)
preamble() {
    case "$1" in
        cisco-ios|cisco-asa) [ "$ENABLE" = 1 ] && printf 'enable\n%s\n' "$CCDC_NET_ENABLE"
                             [ "$1" = cisco-ios ] && printf 'terminal length 0\n' || printf 'terminal pager 0\n' ;;
        paloalto) printf 'set cli pager off\n' ;;
    esac
}
# setpw VENDOR USER PASSWORD PRIV CURRENT -> lines that set USER's password
setpw() {
    case "$1" in
        cisco-ios) printf 'configure terminal\nusername %s privilege %s secret %s\nend\n' "$2" "$4" "$3" ;;
        cisco-asa) printf 'configure terminal\nusername %s password %s privilege %s\nend\n' "$2" "$3" "$4" ;;
        paloalto)  _ph=$(openssl passwd -5 "$3" 2>/dev/null || openssl passwd -1 "$3")
                   printf 'configure\nset mgt-config users %s phash %s\ncommit\nexit\n' "$2" "$_ph" ;;
        fortigate) printf 'config system admin\nedit %s\nset password %s %s\nnext\nend\n' "$2" "$3" "$5" ;;
        vyos)      printf "source /opt/vyatta/etc/functions/script-template\nconfigure\nset system login user %s authentication plaintext-password '%s'\ncommit\nsave\nexit\n" "$2" "$3" ;;
        mikrotik)  printf '/user set [find name="%s"] password="%s"\n' "$2" "$3" ;;
        linux)     printf "if [ \"\$(id -u)\" = 0 ]; then printf '%%s:%%s\\\\n' '%s' '%s' | chpasswd; else printf '%%s:%%s\\\\n' '%s' '%s' | sudo -n chpasswd; fi\n" "$2" "$3" "$2" "$3" ;;
    esac
}
setenable() { printf 'configure terminal\nenable secret %s\nend\n' "$2"; }
# save VENDOR -> lines that make the change survive a reboot
save() { case "$1" in cisco-ios|cisco-asa) printf 'write memory\n' ;; esac; }
# endsession VENDOR -> lines that close the session cleanly
endsession() { case "$1" in mikrotik) printf '/quit\n' ;; *) printf 'exit\n' ;; esac; }
# verify VENDOR -> a harmless command for the test login
verify_cmds() {
    case "$1" in
        cisco-ios) printf 'show privilege\nexit\n' ;;
        cisco-asa) printf 'show curpriv\nexit\n' ;;
        paloalto)  printf 'show clock\nexit\n' ;;
        fortigate) printf 'get system status\nexit\n' ;;
        mikrotik)  printf '/system identity print\n/quit\n' ;;
        *)         printf 'id\nexit\n' ;;
    esac
}
sshopts() {
    set -- -T -o ConnectTimeout=10 -o "UserKnownHostsFile=$CONFIGS/known_hosts" -o StrictHostKeyChecking=accept-new \
        -o LogLevel=ERROR -o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive -o NumberOfPasswordPrompts=1
    [ "$LEGACY" = 1 ] && set -- "$@" -o KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group1-sha1 -o HostKeyAlgorithms=+ssh-rsa -o Ciphers=+aes128-cbc,aes256-cbc,3des-cbc
    printf '%s\n' "$@"
}
# try_login VENDOR USER ADDRESS PORT PASSWORD [EXTRA-LINES] -> 0 if a new
#   session logs in with PASSWORD (and, for an enable test, reaches level 15).
try_login() {
    # printf adds the newline that $( ) stripped from the extra lines.
    { [ -n "${6:-}" ] && printf '%s\n' "$6"; verify_cmds "$1"; } >"$W/verify.in"
    # Keep the arguments before "set --" reuses the list for the ssh options.
    _tl_u=$2; _tl_a=$3; _tl_p=$4; _tl_pw=$5
    sshopts >"$W/opts"
    set --; while IFS= read -r _o; do set -- "$@" "$_o"; done <"$W/opts"
    SSHPASS=$_tl_pw "$SSHPASS_BIN" -e "$SSH" "$@" -p "$_tl_p" "$_tl_u@$_tl_a" <"$W/verify.in" >"$W/verify.out" 2>"$W/verify.err"
    _tl_rc=$?
    [ "$_tl_rc" -eq 0 ] || return 1
    # A level-15 check only when the enable secret was changed.
    if [ -n "$ENTEST" ] && ! grep -q 'level is 15\|Privilege Level 15\|privilege level is 15' "$W/verify.out"; then return 1; fi
    return 0
}

# ---- Each device ------------------------------------------------------------------
PWOUT="$CC_RUN_DIR/passwords.csv"
trap '' PIPE    # a session that dies must not kill this script mid-write
: >"$W/rows_out"
row() { cc_csv_row "$DCSV" "$1" "$2" "$3" "$4" "$5"; printf '%s|%s|%s|%s\n' "$1" "$3" "$4" "$5" >>"$W/rows_out"; }
while IFS='|' read -r _n _a _v _u _p; do
    case "$_v" in pfsense|opnsense)
        row "$_n" "$_a" "$_v" "$_u" "skipped: change it in the web GUI (System > User Manager)"; continue ;;
    esac
    if ! cc_guard host "$_a"; then row "$_n" "$_a" "$_v" "$_u" "skipped (protected device)"; continue; fi
    if ! cc_guard account "$_u"; then row "$_n" "$_a" "$_v" "$_u" "skipped (protected account)"; continue; fi
    _pr=15
    case "$_v" in cisco-ios|cisco-asa)
        if ! _pr=$(priv "$_n" "$_u") || [ -z "$_pr" ]; then
            row "$_n" "$_a" "$_v" "$_u" "skipped: account not found in NW-01's saved config (run NW-01; AAA logins are changed on the AAA server)"; continue
        fi ;;
    esac
    if [ "$NEWENV" = 1 ]; then _new=$CCDC_NET_NEWPASS; else _new=$(cc_genpass "$LEN") || { row "$_n" "$_a" "$_v" "$_u" "failed: no random password"; continue; }; fi
    _newen=""
    [ "$ENTOO" = 1 ] && case "$_v" in cisco-*) _newen=$(cc_genpass "$LEN") ;; esac
    if [ "$CC_APPLY" != 1 ]; then
        cc_log WOULD "$_n ($_v): change the password of $_u$([ -n "$_newen" ] && echo ' and the enable secret'), test a new login, then save (or revert)"
        CC_N_WOULD=$((CC_N_WOULD + 1))
        row "$_n" "$_a" "$_v" "$_u" "would change"; continue
    fi
    cc_info "$_n ($_v): changing the password of $_u"
    # 1. The first session: commands go in through a FIFO so it stays open
    #    while the new password is tested from a second session.
    rm -f "$W/fifo"; mkfifo "$W/fifo"
    sshopts >"$W/opts"
    set --; while IFS= read -r _o; do set -- "$@" "$_o"; done <"$W/opts"
    SSHPASS=$OLDPW "$SSHPASS_BIN" -e "$SSH" "$@" -p "$_p" "$_u@$_a" <"$W/fifo" >/dev/null 2>"$W/sess.err" &
    _spid=$!
    exec 3>"$W/fifo"
    { preamble "$_v"; setpw "$_v" "$_u" "$_new" "$_pr" "$OLDPW"; [ -n "$_newen" ] && setenable "$_v" "$_newen"; } >&3 2>/dev/null
    _w=$WAIT; [ "$_v" = paloalto ] && _w=$CWAIT
    sleep "$_w"
    if ! kill -0 "$_spid" 2>/dev/null; then
        # The first session is gone: the login failed (wrong current
        # password, unreachable) or the device closed it.
        exec 3>&-; wait "$_spid" 2>/dev/null
        _why=$(grep -v '^$' "$W/sess.err" | tail -n 1 | cut -c1-80)
        # It may still have applied the change before closing: check.
        if try_login "$_v" "$_u" "$_a" "$_p" "$_new"; then
            (umask 077; [ -f "$PWOUT" ] || printf 'device,address,account,password,time\n' >"$PWOUT"; printf '%s,%s,%s,%s,%s\n' "$_n" "$_a" "$_u" "$_new" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$PWOUT")
            CC_N_DONE=$((CC_N_DONE + 1))
            row "$_n" "$_a" "$_v" "$_u" "changed (session closed early; new password works; config may not be SAVED - save it by hand)"
        else
            CC_N_FAIL=$((CC_N_FAIL + 1))
            row "$_n" "$_a" "$_v" "$_u" "failed: could not log in with the current password (${_why:-no answer}); nothing changed"
        fi
        continue
    fi
    # 2. A second, new session with the new password.
    ENTEST=""
    if try_login "$_v" "$_u" "$_a" "$_p" "$_new"; then
        _ok=1
        if [ -n "$_newen" ]; then ENTEST=1; try_login "$_v" "$_u" "$_a" "$_p" "$_new" "$(printf 'enable\n%s\n' "$_newen")" || _ok=2; ENTEST=""; fi
    else
        _ok=0
    fi
    # 3. Save, or put the old password back, through the first session.
    if [ "$_ok" = 1 ]; then
        { save "$_v"; endsession "$_v"; } >&3 2>/dev/null
        exec 3>&-; wait "$_spid" 2>/dev/null
        (umask 077; [ -f "$PWOUT" ] || printf 'device,address,account,password,time\n' >"$PWOUT"
         printf '%s,%s,%s,%s,%s\n' "$_n" "$_a" "$_u" "$_new" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$PWOUT"
         [ -n "$_newen" ] && printf '%s,%s,(enable secret),%s,%s\n' "$_n" "$_a" "$_newen" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$PWOUT")
        cc_log DO "$_n: password of $_u changed, new login tested, config saved"
        CC_N_DONE=$((CC_N_DONE + 1))
        row "$_n" "$_a" "$_v" "$_u" "changed (new login tested$([ -n "$_newen" ] && echo ', enable secret too'))"
    else
        cc_err "$_n: the new password did NOT work - putting the old one back through the open session"
        { setpw "$_v" "$_u" "$OLDPW" "$_pr" "$_new"; endsession "$_v"; } >&3 2>/dev/null
        exec 3>&-; wait "$_spid" 2>/dev/null
        sleep "$_w"
        if try_login "$_v" "$_u" "$_a" "$_p" "$OLDPW"; then _rv="old password restored and tested"; else _rv="REVERT NOT CONFIRMED - check this device NOW from the console"; fi
        CC_N_FAIL=$((CC_N_FAIL + 1))
        _what="new password did not work"; [ "$_ok" = 2 ] && _what="new enable secret did not reach level 15"
        row "$_n" "$_a" "$_v" "$_u" "failed: $_what; $_rv"
    fi
    _new=""; _newen=""
done <"$W/devices"

{
    printf 'NW-10 Device password rotation | %s | %s\n\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$([ "$CC_APPLY" = 1 ] && echo APPLIED || echo 'DRY RUN - nothing changed')"
    awk -F'|' '{ printf "  %-14s %-10s %-10s %s\n", $1, $2, $3, $4 }' "$W/rows_out"
    printf '\n'
    if [ -f "$PWOUT" ]; then
        printf 'New passwords: %s (mode 600)\n  Give them to the captain, then remove the file: rm %s\n' "$PWOUT" "$PWOUT"
        printf '  Then run NW-01 again: the changed account lines are expected changes.\n'
    fi
    [ "$CC_APPLY" = 1 ] || printf 'Dry run: nothing changed.  Try --apply on ONE device first (--device), then the rest.\n'
    printf 'All results: %s\n' "$CC_RUN_DIR"
} >"$CC_RUN_DIR/summary.txt"
cat "$CC_RUN_DIR/summary.txt"
rm -rf "$W"
cc_finish
