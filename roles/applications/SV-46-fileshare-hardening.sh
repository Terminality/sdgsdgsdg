#!/bin/sh
# =============================================================================
# ID:       SV-46
# NAME:     File share hardening (Samba and NFS)
# ROLE:     Applications
# KIND:     changes - dry run unless --apply
# VERSION:  1.0.0
#
# PURPOSE
#   A file share is a scored service: someone connects and reads or writes a
#   file.  It is also an easy way in: SMB1, shares anyone can write to,
#   smb.conf lines that run a program as root on every connect, NFS exports
#   that give root on the client root on the share.  This reads smb.conf and
#   /etc/exports, then:
#
#     looks at (never changed)
#       every share and export, who can reach it, guest shares that can only
#       be read, force user = root, admin users, Samba users, share folders
#       anyone can write to
#     offers (each asked; Enter takes the default in capitals)
#       smb1-off      [Y] server min protocol = SMB2_02 (no SMB1)
#       ntlmv1-off    [Y] ntlm auth = ntlmv2-only, lanman auth = no
#       exec-lines    [Y] turn off lines that run programs (root preexec,
#                         postexec, magic script, add user script ...)
#       wide-links    [Y] wide links = no (links out of the share)
#       guest-write   [n] guest ok = no on a share anyone can write to (say
#                         yes only if the scoring engine logs in with a user)
#       conf-perms    [Y] smb.conf not writable by other users
#       root-squash   [Y] NFS: no_root_squash -> root_squash
#       nfs-insecure  [Y] NFS: drop "insecure" (clients must use ports < 1024)
#   After: testparm, then Samba reloads its config (smbcontrol, else a
#   restart) and must still listen; exportfs -ra must work.  If not,
#   everything is put back.
#
#   QUESTIONS (Enter takes the default in capitals; a flag answers each):
#     each fix (yes / no)             --only / --skip
#     apply?                          --apply
#
# USAGE
#   sudo sh SV-46-fileshare-hardening.sh                         look + dry run
#   sudo sh SV-46-fileshare-hardening.sh --protected p.csv --apply
#   sudo sh SV-46-fileshare-hardening.sh --protected p.csv --apply --batch --skip root-squash
#
# OPTIONS
#   --apply            make the changes (without it, dry run only)
#   --only a,b / --skip a,b   smb1-off ntlmv1-off exec-lines wide-links
#                      guest-write conf-perms root-squash nfs-insecure
#                      (a fix named with --only is chosen, even guest-write)
#   --timer SECONDS    revert countdown (default 120); --no-timer
#   --root DIR         treat DIR as / (tests): files only
#   --no-color         no colours
#   --help             this text plus the common options
#
# OUTPUTS  (under --out, in fileshare-N/)
#   output.txt, findings.txt, plan.txt, summary.txt, run.txt, revert.sh
#
# DEPENDS ON
#   awk, sed; testparm and smbcontrol (Samba), exportfs (NFS), pdbedit for the
#   user list (optional).
#
# TESTED ON
#   A fake root (smb.conf, /etc/exports, /etc/exports.d) under dash, bash,
#   busybox sh, ksh93, mksh and yash with gawk, mawk and busybox awk.  Not yet
#   run against a live Samba or NFS server.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - Files pulled in with "include =" are named, not read.
#   - Who may connect (hosts allow, the NFS client list) is reported, never
#     changed: only you know the team's addresses.  The firewall: LX-25
#     --box fileshare.  Keep it up: SV-50 --box fileshare.  Malware in the
#     shares: LX-45 (scans them).
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

ALL_FIX="smb1-off ntlmv1-off exec-lines wide-links guest-write conf-perms root-squash nfs-insecure"
usage() {
    cat <<'USAGE'
SV-46 File share hardening - Samba (SMB1, NTLMv1, guest write, lines that run programs) and NFS (no_root_squash, insecure)
  sudo sh SV-46-fileshare-hardening.sh                        look + dry run
  sudo sh SV-46-fileshare-hardening.sh --protected p.csv --apply

  --apply            make the changes (without it, dry run only)
  --only a,b / --skip a,b   smb1-off ntlmv1-off exec-lines wide-links
                     guest-write conf-perms root-squash nfs-insecure
  --timer SECONDS    revert countdown (default 120); --no-timer
  --root DIR         treat DIR as / (tests)
  --no-color         no colours
  --help             show this text
USAGE
    cc_usage_common
}

ONLY=""; SKIP=""; TIMER=120; NOTIMER=0; R=""; COLOR=1
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --apply)    CC_APPLY=1; shift ;;
        --only)     [ $# -ge 2 ] || cc_die 2 "--only needs a list"; ONLY="$ONLY,$2"; shift 2 ;;
        --skip)     [ $# -ge 2 ] || cc_die 2 "--skip needs a list"; SKIP="$SKIP,$2"; shift 2 ;;
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

cc_init "SV-46" "File share hardening" changes
cc_detect_os
# shellcheck disable=SC2034  # read by cc_color_init
[ "$COLOR" = 1 ] || CC_NOCOLOR=1
cc_color_init
cc_use_numbered_dir fileshare
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
lc() { printf '%s' "$1" | tr 'A-Z' 'a-z'; }
yes_() { case "$(lc "$1")" in yes|true|1|on) return 0 ;; esac; return 1; }

cc_show "$C_CYN" "SV-46 File share hardening | host $CC_HOST | results in $CC_RUN_DIR"
cc_show "" "Legend: ${C_RED}[!] HIGH${C_OFF}   ${C_YEL}[*] MED${C_OFF}   ${C_GRN}[ok]${C_OFF} fine   ${C_YEL}[~] would change${C_OFF}   ${C_GRN}[+] changed${C_OFF}   ${C_RED}[x] failed${C_OFF}"
[ -n "$R" ] && cc_show "$C_GRY" "Acting on $R as if it were / (files only)"

SMB=""; for _c in /etc/samba/smb.conf /usr/local/etc/smb4.conf /usr/local/samba/etc/smb.conf; do [ -f "$(P "$_c")" ] && { SMB=$_c; break; }; done
EXPORTS=""
[ -f "$(P /etc/exports)" ] && EXPORTS=/etc/exports
for _e in "$(P /etc/exports.d)"/*.exports; do [ -f "$_e" ] && EXPORTS="$EXPORTS ${_e#"$R"}"; done
if [ -z "$SMB$EXPORTS" ]; then
    cc_show "$C_GRY" "No file share here (no smb.conf, no /etc/exports)."
    rm -rf "$W"; cc_finish; exit 0
fi

: >"$W/find"; : >"$W/fixes"
fnd() { printf '%s\t%s\n' "$1" "$2" >>"$W/find"; case "$1" in HIGH) cc_show "$C_RED" "  [!] $2" ;; MED) cc_show "$C_YEL" "  [*] $2" ;; INFO) cc_show "" "  $2" ;; *) cc_show "$C_GRN" "  [ok] $2" ;; esac; }
# fix NAME DEFAULT ARG DESCRIPTION
fix() { want "$1" && printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >>"$W/fixes"; return 0; }
mode_other() { ls -ld "$1" 2>/dev/null | cut -c8-10; }

# ---- Samba ------------------------------------------------------------------------------
# $W/smb: section<TAB>key<TAB>value<TAB>line  (sections and keys lower case,
#   key spaces squeezed; comments and blank lines left out)
if [ -n "$SMB" ]; then
    header "1/3  Samba ($SMB)"
    awk '/^[ \t]*[#;]/ || /^[ \t]*$/ { next }
        /^[ \t]*\[/ { s = $0; sub(/^[ \t]*\[/, "", s); sub(/\].*/, "", s); sec = tolower(s); next }
        { i = index($0, "="); if (!i) next
          k = tolower(substr($0, 1, i - 1)); gsub(/^[ \t]+|[ \t]+$/, "", k); gsub(/[ \t]+/, " ", k)
          v = substr($0, i + 1); gsub(/^[ \t]+|[ \t\r]+$/, "", v)
          print sec "\t" k "\t" v "\t" NR }' "$(P "$SMB")" >"$W/smb"
    sget() { awk -F'\t' -v s="$1" -v k="$2" '$1 == s && $2 == k { v = $3 } END { print v }' "$W/smb"; }
    # Global settings.
    _mp=$(sget global "server min protocol"); [ -z "$_mp" ] && _mp=$(sget global "min protocol")
    case "$(lc "$_mp")" in
        nt1|lanman1|lanman2|core|coreplus) fnd HIGH "SMB1 is allowed (server min protocol = $_mp): old, and how EternalBlue-style attacks get in"
            fix smb1-off Y "-" "server min protocol = SMB2_02 (no SMB1; Windows XP-era clients stop working)" ;;
        *) fnd OK "SMB1 is off (server min protocol = ${_mp:-SMB2_02, the default})" ;;
    esac
    _na=$(lc "$(sget global "ntlm auth")"); _la=$(lc "$(sget global "lanman auth")")
    if yes_ "$_la"; then fnd HIGH "lanman auth = yes: passwords can be cracked from the network in minutes"; fix ntlmv1-off Y "-" "ntlm auth = ntlmv2-only, lanman auth = no"
    elif yes_ "$_na" || [ "$_na" = ntlmv1-permitted ]; then fnd MED "NTLMv1 logins are allowed (ntlm auth = $_na): easy to crack from the network"; fix ntlmv1-off Y "-" "ntlm auth = ntlmv2-only, lanman auth = no"
    else fnd OK "only NTLMv2 or Kerberos logins"; fi
    _ha=$(sget global "hosts allow")
    [ -n "$_ha" ] && fnd INFO "only these may connect: $_ha" || fnd INFO "any address may connect (hosts allow is not set; the firewall: LX-25 --box fileshare)"
    _inc=$(awk -F'\t' '$2 == "include" { printf "%s ", $3 }' "$W/smb"); [ -n "$_inc" ] && fnd MED "also reads: $_inc(not checked here)"
    # Lines that run programs, anywhere in the file.
    EXECKEYS="root preexec|root postexec|preexec|postexec|exec|magic script|magic output|add user script|delete user script|add group script|add machine script|add user to group script|username map script|check password script|print command|lpq command|lprm command"
    awk -F'\t' -v ks="|$EXECKEYS|" 'index(ks, "|" $2 "|") { print }' "$W/smb" >"$W/exec"
    if [ -s "$W/exec" ]; then
        while IFS="$TAB" read -r _s _k _v _n; do fnd HIGH "[$_s] $_k = $_v (line $_n): runs a program$(case "$_k" in root*|*script) echo ' as root' ;; esac) - is it yours?"; done <"$W/exec"
        fix exec-lines Y "-" "turn off the $(grep -c . "$W/exec") line(s) that run programs (commented out with # BT SV-46 off:)"
    else fnd OK "no lines that run programs (preexec, postexec, magic script, ... script)"; fi
    _wl=$(awk -F'\t' '($2 == "wide links" || $2 == "allow insecure wide links") && tolower($3) ~ /^(yes|true|1)$/ { print $1 ": " $2 }' "$W/smb" | tr '\n' ' ')
    if [ -n "$_wl" ]; then fnd MED "symbolic links may point out of the share: $_wl"; fix wide-links Y "-" "wide links = no, allow insecure wide links = no"
    else fnd OK "links cannot point out of a share"; fi
    _au=$(sget global "admin users"); [ -n "$_au" ] && fnd MED "[global] admin users = $_au: they are root on every share"
    # Each share.
    cut -f1 "$W/smb" | awk '!s[$0]++' | grep -v '^global$' >"$W/shares"
    : >"$W/gw"
    while IFS= read -r _s; do
        _p=$(sget "$_s" path); _g=$(sget "$_s" "guest ok"); [ -z "$_g" ] && _g=$(sget "$_s" public)
        _ro=$(sget "$_s" "read only"); _wr=$(sget "$_s" writable); [ -z "$_wr" ] && _wr=$(sget "$_s" writeable); [ -z "$_wr" ] && _wr=$(sget "$_s" "write ok")
        _w=0; { [ -n "$_ro" ] && ! yes_ "$_ro"; } && _w=1; yes_ "$_wr" && _w=1
        _vu=$(sget "$_s" "valid users"); _fu=$(sget "$_s" "force user")
        _line="[$_s] ${_p:-no path}: $([ "$_w" = 1 ] && echo read-write || echo read-only), $(yes_ "$_g" && echo 'guests allowed' || echo "users: ${_vu:-any Samba user}")"
        if yes_ "$_g" && [ "$_w" = 1 ]; then fnd HIGH "$_line - ANYONE can write here, no password"; printf '%s\n' "$_s" >>"$W/gw"
        elif yes_ "$_g"; then fnd MED "$_line - anyone can read it, no password"
        else fnd INFO "$_line"; fi
        [ "$(lc "$_fu")" = root ] && fnd MED "[$_s] force user = root: every file is written as root"
        case "$_s" in homes|printers|print\$) ;; *)
            [ -n "$_p" ] && [ -d "$(P "$_p")" ] && case "$(mode_other "$(P "$_p")")" in ?w?) fnd MED "[$_s] the folder $_p can be written by every user on this box (chmod o-w; o+t at least)" ;; esac ;;
        esac
    done <"$W/shares"
    if [ -s "$W/gw" ]; then fix guest-write N "-" "guest ok = no on $(tr '\n' ' ' <"$W/gw")(guests can no longer connect: say yes only if the scoring engine logs in with a user)"; fi
    case "$(mode_other "$(P "$SMB")")" in ?w?) fnd HIGH "$SMB can be changed by every user on this box"; fix conf-perms Y "-" "$SMB: not writable by other users (chmod o-w)" ;; esac
    if [ -z "$R" ] && cc_have pdbedit; then
        _us=$(pdbedit -L 2>/dev/null | cut -d: -f1 | tr '\n' ' ')
        fnd MED "Samba users: ${_us:-none} - any you do not know is red team (pdbedit -x NAME; passwords: smbpasswd NAME)"
    fi
fi

# ---- NFS --------------------------------------------------------------------------------
# $W/nfs: file<TAB>line<TAB>folder<TAB>client<TAB>options
if [ -n "$EXPORTS" ]; then
    header "2/3  NFS ($EXPORTS)"
    : >"$W/nfs"
    for _e in $EXPORTS; do
        awk -v f="$_e" '/^[ \t]*#/ || /^[ \t]*$/ { next }
            { d = $1; if (NF == 1) print f "\t" NR "\t" d "\t*\t"
              for (i = 2; i <= NF; i++) { c = $i; o = ""; p = index(c, "(")
                  if (p) { o = substr(c, p + 1); sub(/\).*/, "", o); c = substr(c, 1, p - 1) }
                  if (c == "") c = "*"   # no client: everyone (an empty field would vanish in read)
                  print f "\t" NR "\t" d "\t" c "\t" o } }' "$(P "$_e")" >>"$W/nfs"
    done
    _nrs=0; _nin=0
    while IFS="$TAB" read -r _f _n _d _cl _op; do
        _who=${_cl:-everyone}; [ "$_who" = '*' ] && _who=everyone
        _rw=read-only; case ",$_op," in *,rw,*) _rw=read-write ;; esac
        fnd INFO "$_d -> $_who: $_rw ($_op)"
        case ",$_op," in *,no_root_squash,*) fnd HIGH "$_d -> $_who: no_root_squash - root on the client is root on the share (plants setuid files)"; _nrs=1 ;; esac
        case ",$_op," in *,insecure,*) fnd MED "$_d -> $_who: insecure - any user on a client can connect"; _nin=1 ;; esac
        [ "$_who" = everyone ] && [ "$_rw" = read-write ] && fnd MED "$_d: every address may write to it (only you know the team's addresses: set the client list by hand)"
    done <"$W/nfs"
    [ "$_nrs" = 1 ] && fix root-squash Y "-" "NFS: no_root_squash -> root_squash (root on a client is nobody on the share)"
    [ "$_nin" = 1 ] && fix nfs-insecure Y "-" "NFS: drop 'insecure' (clients must connect from ports below 1024)"
    [ "$_nrs$_nin" = 00 ] && fnd OK "no no_root_squash or insecure exports"
fi

# ---- Questions ---------------------------------------------------------------------------
header "3/3  questions and changes (Enter = the default in capitals)"
: >"$W/chosen"
while IFS="$TAB" read -r _fx _d _arg _ds; do
    inlist "$_fx" "$ONLY" && _d=Y   # naming a fix with --only chooses it
    cc_ask "[$_fx] $_ds?" "$_d" "yes, do it" "no, skip it" && printf '%s\t%s\t%s\n' "$_fx" "$_arg" "$_ds" >>"$W/chosen"
done <"$W/fixes"
NCH=$(grep -c . "$W/chosen")
cut -f3 "$W/chosen" >"$CC_RUN_DIR/plan.txt"

# ---- Helpers for the changes ----------------------------------------------------------
backed() { grep -qxF "$1" "$W/backed" 2>/dev/null && return 0; cc_backup_file "$1" >/dev/null || return 1; printf '%s\n' "$1" >>"$W/backed"; }
# smb_set SECTION KEY VALUE [ALIAS...] -> the key (and its aliases) replaced in
#   that section, or added at its end; the section is added when missing.
#   Samba has no comments at the end of a line: the mark goes on the line before.
smb_set() {
    _sf=$(P "$SMB"); backed "$_sf" || return 1
    _ss=$1; _sk=$2; _sv=$3; shift 3
    awk -v s="$_ss" -v k="$_sk" -v v="$_sv" -v al="$_sk|$(printf '%s|' "$@")" '
        BEGIN { m = "   # BT SV-46\n   " k " = " v; n = split(al, a, "|"); for (i = 1; i <= n; i++) if (a[i] != "") ks[a[i]] = 1 }
        /^[ \t]*\[/ { if (cur == s && !done) { print m; done = 1 } l = $0; sub(/^[ \t]*\[/, "", l); sub(/\].*/, "", l); cur = tolower(l); print; next }
        cur == s && !/^[ \t]*[#;]/ { i = index($0, "="); if (i) { kk = tolower(substr($0, 1, i - 1)); gsub(/^[ \t]+|[ \t]+$/, "", kk); gsub(/[ \t]+/, " ", kk)
            if (kk in ks) { if (!done) { print m; done = 1 } next } } }
        { print }
        END { if (!done) { if (cur != s) { print ""; print "[" s "]" } print m } }' "$_sf" >"$_sf.ccnew" && cat "$_sf.ccnew" >"$_sf"
    _r=$?; rm -f "$_sf.ccnew"; return "$_r"
}
do_fix() {   # do_fix FIX
    case "$1" in
        smb1-off)   smb_set global "server min protocol" SMB2_02 "min protocol" ;;
        ntlmv1-off) smb_set global "ntlm auth" ntlmv2-only && smb_set global "lanman auth" no ;;
        wide-links) for _s in $(awk -F'\t' '$2 == "wide links" || $2 == "allow insecure wide links" { print $1 }' "$W/smb" | sort -u); do
                        smb_set "$_s" "wide links" no && smb_set "$_s" "allow insecure wide links" no || return 1; done ;;
        guest-write) while IFS= read -r _s; do smb_set "$_s" "guest ok" no public || return 1; done <"$W/gw" ;;
        exec-lines)
            _sf=$(P "$SMB"); backed "$_sf" || return 1
            # By name, not line number: the other fixes may have added lines above.
            awk -v ks="|$EXECKEYS|" '!/^[ \t]*[#;]/ { i = index($0, "="); if (i) { k = tolower(substr($0, 1, i - 1)); gsub(/^[ \t]+|[ \t]+$/, "", k); gsub(/[ \t]+/, " ", k)
                    if (index(ks, "|" k "|")) { print "# BT SV-46 off: " $0; next } } } { print }' "$_sf" >"$_sf.ccnew" && cat "$_sf.ccnew" >"$_sf"
            _r=$?; rm -f "$_sf.ccnew"; return "$_r" ;;
        conf-perms)
            _sf=$(P "$SMB"); _mm=$(ls -l "$_sf" | awk '{ m = $1; u = substr(m, 2, 3); g = substr(m, 5, 3); o = substr(m, 8, 3); gsub(/-/, "", u); gsub(/-/, "", g); gsub(/-/, "", o); print "u=" u ",g=" g ",o=" o }')
            cc_undo_add "mode of $SMB back" "chmod $_mm $(cc_shquote "$_sf")"
            chmod o-w "$_sf" ;;
        root-squash|nfs-insecure)
            for _e in $EXPORTS; do
                _ef=$(P "$_e"); backed "$_ef" || return 1
                if [ "$1" = root-squash ]; then _ex='s/no_root_squash/root_squash/g'; else _ex='s/,insecure\([,)]\)/\1/g; s/(insecure,/(/g; s/(insecure)/(ro)/g'; fi
                sed "/^[[:space:]]*#/!{$_ex;}" "$_ef" >"$_ef.ccnew" && cat "$_ef.ccnew" >"$_ef"
                _r=$?; rm -f "$_ef.ccnew"; [ "$_r" = 0 ] || return 1
            done ;;
    esac
}
# Samba's service: smbd (Debian, Ubuntu), smb (Rocky, Fedora), samba (Alpine).
SMBSVC=""
if [ -z "$R" ]; then for _n in smbd smb samba; do
    case "$CC_INIT" in systemd) systemctl cat "$_n.service" >/dev/null 2>&1 && { SMBSVC=$_n; break; } ;; *) [ -e "/etc/init.d/$_n" ] && { SMBSVC=$_n; break; } ;; esac
done; fi
smb_reload() {
    if cc_have smbcontrol && smbcontrol smbd reload-config >>"$CC_LOG" 2>&1; then return 0; fi
    [ -n "$SMBSVC" ] || return 1
    case "$CC_INIT" in systemd) systemctl restart "$SMBSVC" ;; openrc) rc-service "$SMBSVC" restart ;; *) service "$SMBSVC" restart ;; esac
}
listening445() {
    if cc_have ss; then ss -ltn 2>/dev/null | grep -Eq '[:.]445[[:space:]]'
    elif cc_have netstat; then netstat -ltn 2>/dev/null | grep -Eq '[:.]445[[:space:]]'
    else return 0; fi
}

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
    L445=0; [ -z "$R" ] && listening445 && L445=1
    _smbch=0; cut -f1 "$W/chosen" | grep -Eqv '^(root-squash|nfs-insecure)$' && _smbch=1
    _nfsch=0; cut -f1 "$W/chosen" | grep -Eq '^(root-squash|nfs-insecure)$' && _nfsch=1
    if [ "$NOTIMER" != 1 ] && [ -z "$R" ]; then cc_timer_start "$TIMER"; TIMER_ON=1
        cc_show "$C_YEL" "  [*] Revert timer started: everything is undone in $((TIMER / 60)):$(printf '%02d' $((TIMER % 60))) unless you keep it at the end."; fi
    if [ -z "$R" ]; then
        [ "$_smbch" = 1 ] && cc_undo_add "Samba reads its config again" "smbcontrol smbd reload-config 2>/dev/null || true"
        [ "$_nfsch" = 1 ] && cc_undo_add "NFS reads /etc/exports again" "exportfs -ra 2>/dev/null || true"
    fi
    while IFS="$TAB" read -r _fx _arg _ds; do
        if do_fix "$_fx"; then NOK=$((NOK + 1)); cc_show "$C_GRN" "  [+] $_ds"; else NBAD=$((NBAD + 1)); cc_show "$C_RED" "  [x] FAILED: $_ds"; fi
    done <"$W/chosen"
    if [ -z "$R" ]; then
        if [ "$_smbch" = 1 ]; then
            if cc_have testparm && ! testparm -s "$SMB" >/dev/null 2>>"$CC_LOG"; then BROKE=1; cc_show "$C_RED" "  [x] testparm says $SMB is broken"
            elif smb_reload >>"$CC_LOG" 2>&1; then cc_show "$C_GRN" "  [+] Samba read the new config"
            else cc_show "$C_YEL" "  [*] Samba could not be told to read the new config (it applies at its next start)"; fi
            if [ "$BROKE" = 0 ] && [ "$L445" = 1 ]; then
                sleep 2; if listening445; then cc_show "$C_GRN" "  [+] Samba still listens on 445"; else BROKE=1; cc_show "$C_RED" "  [x] Samba no longer listens on 445"; fi
            fi
        fi
        if [ "$_nfsch" = 1 ] && [ "$BROKE" = 0 ] && cc_have exportfs; then
            if exportfs -ra >>"$CC_LOG" 2>&1; then cc_show "$C_GRN" "  [+] exportfs -ra: the exports are live"; else BROKE=1; cc_show "$C_RED" "  [x] exportfs -ra failed"; fi
        fi
        if [ "$BROKE" = 1 ]; then
            cc_show "$C_RED" "  Putting everything back now ..."
            awk -F'\t' -v n="${U0:-0}" 'NR > n { l[NR] = $4 } END { for (i = NR; i > n; i--) print l[i] }' "$CC_UNDO" >"$W/undo-now"
            while IFS= read -r _cmd; do sh -c "$_cmd" >>"$CC_LOG" 2>&1; done <"$W/undo-now"
            [ "$_smbch" = 1 ] && smb_reload >>"$CC_LOG" 2>&1
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
    printf 'SV-46 File share hardening | host %s | %s\n' "$CC_HOST" "$([ "$APPLIED" = 1 ] && { [ "$BROKE" = 1 ] && echo 'APPLIED, then PUT BACK (the share broke)' || echo APPLIED; } || echo 'DRY RUN - nothing changed')"
    printf 'Found: %d HIGH, %d MED\n' "$(grep -c "^HIGH$TAB" "$W/find")" "$(grep -c "^MED$TAB" "$W/find")"
    awk -F'\t' '$1 == "HIGH" || $1 == "MED" { printf "  %-4s %s\n", $1, substr($2, 1, 150) }' "$W/find"
    [ -s "$CC_RUN_DIR/plan.txt" ] && { printf '\nChanges%s:\n' "$([ "$APPLIED" = 1 ] || echo ' planned')"; sed 's/^/  /' "$CC_RUN_DIR/plan.txt"; }
    [ "$APPLIED" = 1 ] && printf 'Done: %d   Failed: %d\n' "$NOK" "$NBAD"
    [ "$APPLIED" = 1 ] && [ -f "$CC_RUN_DIR/revert.sh" ] && printf 'Undo this run: sh %s/revert.sh --force\n' "$CC_RUN_DIR"
    printf '\nAlso: ports LX-25 --box fileshare; keep it up SV-50 --box fileshare; malware in the shares LX-45; who changed what LX-40.\n'
} >"$CC_RUN_DIR/summary.txt"
cc_show "" ""
while IFS= read -r _l; do
    case "$_l" in ==*|SV-46*) cc_show "$C_CYN" "$_l" ;; '  HIGH'*|*'PUT BACK'*) cc_show "$C_RED" "$_l" ;; '  MED'*) cc_show "$C_YEL" "$_l" ;; *) cc_show "" "$_l" ;; esac
done <"$CC_RUN_DIR/summary.txt"
rm -rf "$W"
if [ "$TIMER_ON" = 1 ]; then header "KEEP OR REVERT"; cc_show "$C_YEL" "[*] Before you answer: connect to the share from another box and open a file."; cc_timer_finish || true; fi
cc_finish
