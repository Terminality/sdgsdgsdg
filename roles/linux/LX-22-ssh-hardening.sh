#!/bin/sh
# =============================================================================
# ID:       LX-22
# NAME:     SSH hardening and key cleanup
# ROLE:     Linux  (wave 2, first 15 minutes)
# KIND:     changes - dry run unless --apply
# VERSION:  2.0.0
#
# PURPOSE
#   A changed password does not stop a red team that planted an SSH key, and
#   a loose sshd_config lets them back in other ways.  This script:
#     1. shows how SSH is set up now: the sshd version and ports, the value
#        every important setting has right now, Match blocks that loosen
#        things, extra key sources, extra sshd processes
#     2. lists every authorized key of every account (service accounts like
#        www-data too) with its fingerprint, comment, options and when the
#        file changed, says which ones look planted, and asks key by key
#        whether to keep it
#     3. asks setting by setting whether to turn it on or off (like sqlmap:
#        Enter takes the recommended answer), with a plain explanation of
#        what each one does and what could break
#     4. writes the chosen settings as a marked block at the TOP of
#        sshd_config (sshd uses the first value it reads, so the block wins
#        over anything below it and over sshd_config.d), tests it with
#        "sshd -t" BEFORE installing, reloads sshd (open sessions stay up),
#        checks sshd still listens, and puts the old config back by itself
#        if not
#     5. with a revert timer running: everything is undone after --timer
#        seconds unless you confirm from a NEW SSH session that you can
#        still log in
#
# USAGE
#   sudo sh LX-22-ssh-hardening.sh                     look and plan (asks; changes nothing)
#   sudo sh LX-22-ssh-hardening.sh --apply             ask, then change
#   sudo sh LX-22-ssh-hardening.sh --apply --batch     the recommended answers, no questions
#   sudo sh LX-22-ssh-hardening.sh --apply --allow-keys team.pub   keep only the team's keys
#
# OPTIONS  (each answers a question in advance)
#   --allow-keys FILE   the team's public keys (authorized_keys format) or
#                       fingerprints (SHA256:...), one per line.  Every
#                       other key is removed, without asking
#   --remove-all-keys   remove every key (no questions)
#   --keep-all-keys     keep every key (no questions)
#   --root-login MODE   no | key-only | leave   (PermitRootLogin)
#   --no-passwords      turn password logins OFF (key only).  Off by default:
#                       scoring engines usually log in with passwords
#   --no-forwarding     turn off TCP forwarding, tunnels and gateway ports
#   --strong-crypto     only modern ciphers, key exchange and MACs
#   --allow-users LIST  only these accounts may log in by SSH (space or comma
#                       separated; protected accounts are added)
#   --banner FILE       show this file before login
#   --set KEY=yes|no    answer one setting question (repeat).  KEYs:
#                       emptypw rhosts userenv x11 agent maxauth grace alive
#                       loglevel
#   --timer SECONDS     revert countdown (default 120)
#   --no-timer          apply with no revert timer (not advised)
#   --no-reload         install the config but do not reload sshd
#   --root DIR          treat DIR as / (tests; sshd is not reloaded)
#   --no-color          no colours
#   --batch             no questions: recommended answers
#   --help              this text plus the common options
#
# OUTPUTS  (under --out, in ssh-hardening-N/)
#   output.txt      everything shown on screen, without colour
#   summary.txt     settings before and after, keys kept and removed, checks
#   keys.txt        every key: account, file, type, fingerprint, comment,
#                   options, verdict, action
#   settings.txt    every setting: before, after, status
#   csv/            the same as CSV
#   revert.sh       undo this run (with --apply)
#
# WHAT IT CHANGES  (only with --apply)
#   /etc/ssh/sshd_config (marked block at the top; backed up first),
#   authorized_keys files (rewritten without the removed keys; backed up;
#   removed lines kept as evidence in quarantine/), ~/.ssh/rc and
#   /etc/ssh/sshrc if you say so (moved to quarantine/), and reloads sshd.
#   Every change has an undo line and is covered by the revert timer; a
#   revert also reloads sshd.
#
# DEPENDS ON
#   sshd (to read the current settings, test and reload), ssh-keygen
#   (fingerprints), awk.  CCDC_SSHD may name a stand-in sshd (the tests).
#
# TESTED ON
#   Ubuntu 24.04 with OpenSSH 9.6 under dash, bash, busybox sh, ksh93, mksh
#   and yash (fake root and stand-in sshd), and live: after --apply the kept
#   key still logs in and the removed key is refused.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - Keep a second root session open while applying.
#   - Settings inside Match blocks apply on top of the global ones for
#     matching logins; they are reported, not changed.
#   - Keys from an AuthorizedKeysCommand or LDAP are not in files: reported.
#   - Accounts on the protected list keep their keys.
#   - --strong-crypto can lock out old clients (and an old scoring engine).
#
# DEBUGGING
#   --debug shows each key file and fingerprint; the candidate config and the
#   sshd -t output are in the log.
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
LX-22 SSH hardening and key cleanup - see every key and setting, keep or change each
  sudo sh LX-22-ssh-hardening.sh              look and plan (asks; changes nothing)
  sudo sh LX-22-ssh-hardening.sh --apply      ask, then change

  --allow-keys FILE    team keys/fingerprints: every other key is removed
  --remove-all-keys    remove every key        --keep-all-keys   keep every key
  --root-login MODE    no | key-only | leave
  --no-passwords       password logins OFF (key only) - careful, scoring uses passwords
  --no-forwarding      TCP forwarding and tunnels off
  --strong-crypto      modern ciphers only (can lock out old clients)
  --allow-users LIST   only these accounts may log in by SSH
  --banner FILE        pre-login banner
  --set KEY=yes|no     answer a setting question: emptypw rhosts userenv x11
                       agent maxauth grace alive loglevel
  --timer SECONDS      revert countdown (default 120)   --no-timer
  --no-reload          install without reloading sshd
  --root DIR           treat DIR as / (tests)
  --no-color           no colours
  --help               show this text

USAGE
    cc_usage_common
}

# ---- Options ----------------------------------------------------------------
ALLOWKEYS=""; KEYMODE=""; ROOTMODE=""; NOPW=""; NOFWD=""; STRONG=""; ALLOWUSERS=""; AUSET=0; BANNER=""
SETS=""; TIMER=120; NOTIMER=0; NORELOAD=0; R=""; COLOR=1
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --allow-keys)      [ $# -ge 2 ] || cc_die 2 "--allow-keys needs a file"; [ -r "$2" ] || cc_die 2 "--allow-keys: cannot read $2"; ALLOWKEYS=$2; KEYMODE=allow; shift 2 ;;
        --remove-all-keys) [ "$KEYMODE" = allow ] && cc_die 2 "use --allow-keys or --remove-all-keys, not both"; KEYMODE=all; shift ;;
        --keep-all-keys)   KEYMODE=keep; shift ;;
        --root-login)      [ $# -ge 2 ] || cc_die 2 "--root-login needs no, key-only or leave"; ROOTMODE=$2; shift 2 ;;
        --no-root-login)   ROOTMODE=no; shift ;;
        --root-key-only)   ROOTMODE=key-only; shift ;;
        --keep-root-login) ROOTMODE=leave; shift ;;
        --no-passwords)    NOPW=Y; shift ;;
        --no-forwarding)   NOFWD=Y; shift ;;
        --strong-crypto)   STRONG=Y; shift ;;
        --allow-users)     [ $# -ge 2 ] || cc_die 2 "--allow-users needs a list"; ALLOWUSERS=$(printf '%s' "$2" | tr ',' ' '); AUSET=1; shift 2 ;;
        --banner)          [ $# -ge 2 ] || cc_die 2 "--banner needs a file"; [ -r "$2" ] || cc_die 2 "--banner: cannot read $2"; BANNER=$(cc_abspath "$2"); shift 2 ;;
        --set)             [ $# -ge 2 ] || cc_die 2 "--set needs KEY=yes|no"; SETS="$SETS $2"; shift 2 ;;
        --timer)           [ $# -ge 2 ] || cc_die 2 "--timer needs seconds"; TIMER=$2; shift 2 ;;
        --no-timer)        NOTIMER=1; shift ;;
        --no-reload)       NORELOAD=1; shift ;;
        --root)            [ $# -ge 2 ] || cc_die 2 "--root needs a folder"; [ -d "$2" ] || cc_die 2 "--root: not a folder: $2"
                           R=$(cd "$2" && pwd); [ "$R" = / ] && R=""; shift 2 ;;
        --no-color|--no-colour) COLOR=0; shift ;;
        --help|-h)         usage; exit 0 ;;
        *)                 cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
case "$ROOTMODE" in ''|no|key-only|leave) ;; *) cc_die 2 "--root-login must be no, key-only or leave" ;; esac
case "$TIMER" in ''|*[!0-9]*) cc_die 2 "--timer needs a whole number of seconds" ;; esac
for _s in $SETS; do
    case "$_s" in
        emptypw=*|rhosts=*|userenv=*|x11=*|agent=*|maxauth=*|grace=*|alive=*|loglevel=*) ;;
        *) cc_die 2 "--set: unknown setting '${_s%%=*}' (emptypw rhosts userenv x11 agent maxauth grace alive loglevel)" ;;
    esac
    case "${_s#*=}" in yes|no) ;; *) cc_die 2 "--set $_s: the answer must be yes or no" ;; esac
done

cc_init "LX-22" "SSH hardening and key cleanup" changes
cc_detect_os
[ -z "$R" ] && [ "$CC_APPLY" = 1 ] && cc_require_root
cc_use_numbered_dir ssh-hardening
CC_CSV_DIR="$CC_RUN_DIR/csv"
mkdir -p "$CC_CSV_DIR" || cc_die 3 "cannot create $CC_CSV_DIR"
W="$CC_RUN_DIR/.work"; mkdir -p "$W" || cc_die 3 "cannot create $W"
cc_color_init
[ "$COLOR" = 1 ] || { C_RED=""; C_YEL=""; C_GRN=""; C_CYN=""; C_GRY=""; C_OFF=""; }
OUTF="$CC_RUN_DIR/output.txt"
grep -v '\[NOTE\]\|\[DEBUG\]' "$CC_LOG" >"$OUTF" 2>/dev/null || : >"$OUTF"
# shellcheck disable=SC2034  # CC_TEE is read by the library's log functions
CC_TEE=$OUTF
header() { cc_show "" ""; cc_show "$C_CYN" "==========[ $1 ]=========="; }
CONF="$R/etc/ssh/sshd_config"
SSHD=${CCDC_SSHD:-$(cc_which sshd)} || SSHD=""
KEYGEN=$(cc_which ssh-keygen) || KEYGEN=""
: >"$W/report"
report() { printf '%s\n' "$*" >>"$W/report"; }
nologin() { case "$1" in */nologin|*/false|*/sync|*/shutdown|*/halt|'') return 0 ;; esac; return 1; }

cc_show "$C_CYN" "LX-22 SSH hardening | host $CC_HOST | $([ "$CC_APPLY" = 1 ] && echo 'APPLY: changes are made after the questions' || echo 'DRY RUN: nothing is changed') | results in $CC_RUN_DIR"
cc_show "" "Legend: ${C_GRN}[ok] already right${C_OFF}   ${C_YEL}[~] would change  [*] check by hand${C_OFF}   ${C_RED}[!] looks planted${C_OFF}"
[ -n "$R" ] && cc_show "$C_GRY" "Acting on $R as if it were / (sshd is not reloaded)"

# ---- 1/5  SSH now ---------------------------------------------------------------------
header "1/5  how SSH is set up now"
# Effective settings: sshd -T on a live box, else the config file (first
# value outside Match, which is what sshd uses), else sshd's default.
: >"$W/eff"
if [ -z "$R" ] && [ -n "$SSHD" ] && [ -z "${CCDC_SSHD:-}" ]; then
    "$SSHD" -T 2>/dev/null >"$W/eff"
    _ver=$("$SSHD" -V 2>&1 | head -n 1)
    [ -n "$_ver" ] && cc_show "" "  sshd:     $_ver"
fi
[ -f "$CONF" ] || cc_show "$C_YEL" "  No $CONF: the SSH server is not installed here (or configured elsewhere)."
# rootword VALUE -> the PermitRootLogin value in plain words.
rootword() {
    case "$1" in
        prohibit-password|without-password) echo "key-only ($1)" ;;
        forced-commands-only) echo "key-only, forced commands ($1)" ;;
        yes) echo "yes (password or key)" ;;
        no) echo "no (root cannot log in by SSH)" ;;
        *) echo "$1" ;;
    esac
}
cur() {  # cur KEY DEFAULT -> the value in effect now
    _k=$(printf '%s' "$1" | tr 'A-Z' 'a-z')
    _v=$(awk -v k="$_k" '$1 == k { $1 = ""; sub(/^ /, ""); print; exit }' "$W/eff")
    [ -n "$_v" ] || _v=$(awk -v k="$_k" 'tolower($1) == "match" { exit } tolower($1) == k { $1 = ""; sub(/^ /, ""); print; exit }' "$CONF" 2>/dev/null)
    printf '%s' "${_v:-$2}" | tr 'A-Z' 'a-z'
}
_ports=$(cur port 22 | tr '\n' ' ')
cc_show "" "  Port(s):  $_ports    Root login: $(rootword "$(cur permitrootlogin prohibit-password)")    Password logins: $(cur passwordauthentication yes)"
if [ -z "$R" ] && cc_have ss; then
    _l=$(ss -ltnp 2>/dev/null | awk '/"sshd"/ { print $4 }' | tr '\n' ' ')
    if [ -n "$_l" ]; then cc_show "" "  Listening: $_l"; else cc_show "$C_YEL" "  sshd is not listening right now."; fi
fi
# Things only a person can judge.
if [ -f "$CONF" ]; then
    awk 'tolower($1) == "match" { m = $0; next }
         m != "" && tolower($1) ~ /^(permitrootlogin|passwordauthentication|permitemptypasswords|authorizedkeysfile|authorizedkeyscommand|forcecommand|permituserenvironment|allowtcpforwarding)$/ {
             print "a Match block [" m "] changes " $1 " for those logins: " $0 }
         m == "" && tolower($1) ~ /^(authorizedkeyscommand|authorizedprincipalscommand|trustedusercakeys)$/ && tolower($2) != "none" {
             print "sshd gets keys from outside the key files: " $0 " - check it is the team'"'"'s" }' "$CONF" >>"$W/report"
    for _d in "$R/etc/ssh/sshd_config.d"/*.conf; do
        [ -f "$_d" ] && cc_show "$C_GRY" "  also read: ${_d#"$R"} ($(grep -Ev '^[[:space:]]*(#|$)' "$_d" | tr '\n' ';' | cut -c1-100))"
    done
fi
if [ -z "$R" ]; then
    ps -eo user=,args= 2>/dev/null | awk '$2 ~ /sshd$/ && ($0 ~ / -f / || $0 ~ / -p /) { $1 = ""; print "an extra sshd is running with its own config or port:" $0 }' >>"$W/report"
fi
for _f in /etc/ssh/sshrc $(awk -F: '$6 != "" { print $6 "/.ssh/rc" }' "$R/etc/passwd" 2>/dev/null | sort -u); do
    [ -f "$R$_f" ] && printf '%s\n' "$_f" >>"$W/rcfiles"
done
if [ -s "$W/report" ]; then while IFS= read -r _l; do cc_show "$C_YEL" "  [*] $_l"; done <"$W/report"; fi

# ---- 2/5  Keys ------------------------------------------------------------------------
header "2/5  SSH keys: who can log in without a password"
AWK_KEY='
function iskeytype(t) { return t ~ /^(ssh-(rsa|dss|ed25519)|ecdsa-sha2-nistp[0-9]+|sk-[a-z0-9-]+@openssh\.com|ssh-[a-z0-9-]+-cert-v01@openssh\.com)$/ }  # awk, not shell: posix-ok
function parse(line,   rest, i, c, q, n, f) {  # awk, not shell: posix-ok
    K_opts = ""; K_type = ""; K_blob = ""; K_comment = ""
    sub(/^[ \t]+/, "", line)
    if (line == "" || line ~ /^#/) return 0
    n = split(line, f, /[ \t]+/)
    if (iskeytype(f[1])) { K_type = f[1]; K_blob = f[2]; rest = line; sub(/^[^ \t]+[ \t]+[^ \t]+[ \t]*/, "", rest); K_comment = rest; return 1 }
    q = 0
    for (i = 1; i <= length(line); i++) {
        c = substr(line, i, 1)
        if (c == "\"") q = !q
        else if ((c == " " || c == "\t") && !q) break
    }
    K_opts = substr(line, 1, i - 1); rest = substr(line, i); sub(/^[ \t]+/, "", rest)
    n = split(rest, f, /[ \t]+/)
    if (!iskeytype(f[1])) return 0
    K_type = f[1]; K_blob = f[2]; sub(/^[^ \t]+[ \t]+[^ \t]+[ \t]*/, "", rest); K_comment = rest
    return 1
}'
fingerprint() {
    [ -n "$KEYGEN" ] || return 0
    printf '%s %s\n' "$1" "$2" >"$W/fp.pub"
    "$KEYGEN" -l -f "$W/fp.pub" 2>/dev/null | awk '{ print $2 }'
}
[ -n "$KEYGEN" ] || cc_show "$C_YEL" "  ssh-keygen not found: keys are shown by their end, not their fingerprint."
: >"$W/allowed"
if [ -n "$ALLOWKEYS" ]; then
    awk "$AWK_KEY"'{ l = $0; sub(/^[ \t]+/, "", l); if (l ~ /^SHA256:/) { split(l, a, /[ \t]/); print "F " a[1]; next }
                     if (parse(l)) print "K " K_type " " K_blob }' "$ALLOWKEYS" >"$W/allow.raw"
    while read -r _k _t _b; do
        if [ "$_k" = F ]; then printf '%s\n' "$_t" >>"$W/allowed"
        else printf '%s\n' "$_b" >>"$W/allowed"; _fp=$(fingerprint "$_t" "$_b"); [ -n "$_fp" ] && printf '%s\n' "$_fp" >>"$W/allowed"; fi
    done <"$W/allow.raw"
    [ -s "$W/allowed" ] || cc_die 2 "--allow-keys: no keys or fingerprints found in $ALLOWKEYS"
fi
# Where keys live: AuthorizedKeysFile from sshd, else the config, else defaults.
AKF=$(awk '$1 == "authorizedkeysfile" { $1 = ""; sub(/^ /, ""); print }' "$W/eff")
[ -n "$AKF" ] || AKF=$(awk 'tolower($1) == "authorizedkeysfile" && !m { $1 = ""; sub(/^ /, ""); print; exit } tolower($1) == "match" { m = 1 }' "$CONF" 2>/dev/null)
[ -n "$AKF" ] || AKF=".ssh/authorized_keys .ssh/authorized_keys2"
# $W/keys: n|user|uid|file|line|type|blob|comment|opts|fp|verdict|why|default
: >"$W/keys"; : >"$W/seen"; _n=0
awk -F: '$6 != "" { print $1 ":" $3 ":" $6 ":" $7 }' "$R/etc/passwd" 2>/dev/null >"$W/users"
while IFS=: read -r _u _uid _h _sh; do
    for _pat in $AKF; do
        _f=$(printf '%s' "$_pat" | sed "s|%h|$_h|g; s|%u|$_u|g; s|%%|%|g")
        case "$_f" in /*) ;; *) _f="$_h/$_f" ;; esac
        _pf="$R$_f"
        [ -e "$_pf" ] || [ -h "$_pf" ] || continue
        grep -qxF "$_pf" "$W/seen" && continue
        printf '%s\n' "$_pf" >>"$W/seen"
        if [ -h "$_pf" ]; then report "$_f ($_u) is a link to $(ls -l "$_pf" | sed 's/.*-> //'): check it by hand"; continue; fi
        [ -r "$_pf" ] || { report "$_f ($_u) cannot be read (run as root)"; continue; }
        _age=old; [ -n "$(find "$_pf" -prune -mtime -7 2>/dev/null)" ] && _age=recent
        awk "$AWK_KEY"'{ if (parse($0)) print NR "|" K_type "|" K_blob "|" K_comment "|" K_opts }' "$_pf" >"$W/k"
        while IFS='|' read -r _ln _t _b _c _o; do
            _n=$((_n + 1)); _fp=$(fingerprint "$_t" "$_b")
            [ -n "$_fp" ] || _fp="...$(printf '%s' "$_b" | awk '{ print substr($0, length($0) - 11) }')"
            _v=ok; _why=""; _d=Y
            case "$_o" in *command=*|*environment=*) _v=planted; _why="has a forced command or environment ($_o): runs something at every login with this key"; _d=N ;; esac
            if [ "$_v" = ok ] && [ "$_uid" -gt 0 ] && [ "$_uid" -lt 1000 ]; then _v=planted; _why="on a service account ($_u): service accounts do not log in"; _d=N; fi
            if [ "$_v" = ok ] && nologin "$_sh"; then _v=planted; _why="$_u has no login shell ($_sh) but has a key"; _d=N; fi
            if [ "$_v" = ok ] && [ "$_f" != "$_h/.ssh/authorized_keys" ] && [ "$_f" != "$_h/.ssh/authorized_keys2" ]; then _v=check; _why="kept outside the home folder ($_f)"; fi
            if [ "$_v" = ok ] && [ "$_age" = recent ]; then _v=check; _why="the key file changed in the last 7 days"; fi
            [ "$_v" = ok ] && [ "$_uid" = 0 ] && { _v=check; _why="logs in as root"; }
            _act=""
            case "$KEYMODE" in
                all)   _act=remove ;;
                keep)  _act=keep ;;
                allow) if grep -qxF "$_b" "$W/allowed" || grep -qxF "$_fp" "$W/allowed"; then _act=keep; else _act=remove; fi ;;
            esac
            if cc_is_protected account "$_u" && [ "$CC_FORCE_SCORED" != 1 ]; then _act=keep; _why="${_why:+$_why; }the account is on the protected list"; fi
            printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' "$_n" "$_u" "$_uid" "$_f" "$_ln" "$_t" "$_b" "$_c" "$_o" "$_fp" "$_v" "$_why" "$_d" "$_act" >>"$W/keys"
            case "$_v" in planted) _col=$C_RED; _tag="[!]" ;; check) _col=$C_YEL; _tag="[*]" ;; *) _col=$C_GRN; _tag="[ok]" ;; esac
            cc_show "$_col" "  $_tag key #$_n  $_u  $_t $_fp  ${_c:-(no comment)}"
            cc_show "$C_GRY" "        file: $_f$([ "$_age" = recent ] && echo ' (changed in the last 7 days)')"
            [ -n "$_why" ] && cc_show "$_col" "        $_why"
        done <"$W/k"
    done
done <"$W/users"
[ "$_n" -eq 0 ] && cc_show "$C_GRN" "  [ok] no SSH keys on any account"

# ---- 3/5  Questions -------------------------------------------------------------------
header "3/5  questions (Enter takes the answer in capitals)"
# Keys, one by one, unless a flag already decided.
: >"$W/keydec"
while IFS='|' read -r _n _u _uid _f _ln _t _b _c _o _fp _v _why _d _act; do
    if [ -z "$_act" ]; then
        if cc_ask "Keep key #$_n ($_u, $_fp, ${_c:-no comment})?$([ -n "$_why" ] && echo " [$_why]")" "$_d"; then _act=keep; else _act=remove; fi
    fi
    printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' "$_n" "$_u" "$_f" "$_ln" "$_t" "$_fp" "$_c" "$_o" "$_v" "$_why" "$_act" "$_uid" >>"$W/keydec"
done <"$W/keys"
_rootkeys=$(awk -F'|' '$12 == 0 && $11 == "keep"' "$W/keydec" | grep -c .)

# rc files: commands run at every SSH login.
: >"$W/rcq"
if [ -s "$W/rcfiles" ]; then
    while IFS= read -r _f; do
        cc_show "$C_RED" "  [!] $_f runs at every SSH login: $(grep -Ev '^[[:space:]]*(#|$)' "$R$_f" | head -n 1 | cut -c1-100)"
        cc_ask "Move $_f to quarantine?" Y && printf '%s\n' "$_f" >>"$W/rcq"
    done <"$W/rcfiles"
fi

# Root login.
_rnow=$(cur permitrootlogin prohibit-password)
_rpw=$(awk -F: '$1 == "root" { print ($2 == "" || $2 ~ /^[!*]/) ? "no" : "yes" }' "$R/etc/shadow" 2>/dev/null)
if cc_is_protected account root && [ "$CC_FORCE_SCORED" != 1 ]; then
    ROOTMODE=leave; cc_show "$C_GRY" "  Root login: left as it is ($(rootword "$_rnow")): root is on the protected list."
elif [ -z "$ROOTMODE" ]; then
    # Never default to locking root out of SSH: key-only only when root keeps a key.
    if [ "$_rootkeys" -gt 0 ] || [ "$_rpw" = no ]; then _rd=key-only; else _rd=leave; fi
    cc_show "" "  Root login is now: $(rootword "$_rnow"). no = root cannot log in over SSH at all; key-only = only with a key; leave = no change."
    [ "$_rd" = leave ] && cc_show "$C_YEL" "  root has a password and no SSH key that stays, so key-only would lock root out of SSH: the default is leave."
    cc_ask_text "Root login over SSH: no, key-only or leave?" "$_rd"
    case "$CC_ANSWER" in no|key-only|leave) ROOTMODE=$CC_ANSWER ;; *) cc_die 2 "not an answer: '$CC_ANSWER' (no, key-only or leave)" ;; esac
fi

# One question per setting.  Format: key|sshd lines|question|why|default|now-key|now-default|want
# The question is skipped when the setting is already what we want.
ans() {  # ans KEY QUESTION DEFAULT -> 0 = yes, from --set or a question
    for _s in $SETS; do [ "${_s%%=*}" = "$1" ] && { [ "${_s#*=}" = yes ]; return; }; done
    cc_ask "$2" "$3"
}
: >"$W/lines"
q() {  # q KEY WANT-KEY WANT-VALUE NOW-DEFAULT DEFAULT QUESTION -- why
    _qk=$1; _wk=$2; _wv=$3; _nd=$4; _qd=$5; _qq=$6; _qw=$7
    _now=$(cur "$_wk" "$_nd")
    if [ "$_now" = "$(printf '%s' "$_wv" | tr 'A-Z' 'a-z')" ]; then
        cc_show "$C_GRN" "  [ok] $_wk is already $_wv"
        printf '%s %s\n' "$_wk" "$_wv" >>"$W/lines"
        return 0
    fi
    cc_show "$C_GRY" "        $_qw"
    if ans "$_qk" "$_qq (now: $_now)" "$_qd"; then printf '%s %s\n' "$_wk" "$_wv" >>"$W/lines"; fi
    return 0
}
q emptypw  PermitEmptyPasswords no  no Y "Turn OFF logins with an empty password?" "Accounts with no password could log in over SSH with nothing at all."
q rhosts   HostbasedAuthentication no no Y "Turn OFF host-based logins (.rhosts/.shosts trust)?" "Old trust files let anyone on a 'trusted' machine log in with no password."
[ "$(cur ignorerhosts yes)" = yes ] || q rhosts IgnoreRhosts yes yes Y "Ignore .rhosts files?" "Same as above: .rhosts lists hosts that get in with no password."
q userenv  PermitUserEnvironment no no Y "Stop users setting environment variables at login (~/.ssh/environment)?" "A planted ~/.ssh/environment can set LD_PRELOAD and run code at every login."
q x11      X11Forwarding no no Y "Turn OFF X11 forwarding?" "Graphical forwarding: not needed on a server, and a way to attack the admin's screen."
q agent    AllowAgentForwarding no yes Y "Turn OFF agent forwarding?" "Anyone who is root here could use a forwarded agent to log in elsewhere as you."
q maxauth  MaxAuthTries 4 6 Y "Limit password/key tries per connection to 4?" "Slows down password guessing. Does not affect normal logins."
q grace    LoginGraceTime 30 120 Y "Drop connections that have not logged in after 30 seconds?" "Stops half-open connections piling up. A person typing a password has plenty of time."
q alive    ClientAliveInterval 300 0 Y "Check idle sessions every 5 minutes and drop dead ones?" "Cleans up abandoned sessions (ClientAliveInterval 300, ClientAliveCountMax 2). Open sessions you use stay up."
grep -q '^ClientAliveInterval' "$W/lines" && printf 'ClientAliveCountMax 2\n' >>"$W/lines"
q loglevel LogLevel VERBOSE info Y "Log the fingerprint of the key used at every login (LogLevel VERBOSE)?" "Then the auth log (and LX-41) shows which key got in. Only adds log lines."
# The ones that can break something are asked with default no.
_pw=$(cur passwordauthentication yes)
if [ "$_pw" = yes ]; then
    cc_show "$C_GRY" "        Key-only logins stop password guessing completely, but scoring engines usually log in with a PASSWORD: that check would fail."
    if [ "$NOPW" = Y ] || { [ -z "$NOPW" ] && cc_ask "Turn OFF password logins (key only)? (now: yes)" N; }; then
        printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\n' >>"$W/lines"
        awk -F'|' '$11 == "keep" && $12 != 0' "$W/keydec" | grep -q . || cc_show "$C_RED" "  [!] No account except root keeps a key: after this, only root can log in (with a key)."
    fi
fi
if [ "$(cur allowtcpforwarding yes)" != no ]; then
    cc_show "$C_GRY" "        Port forwarding lets anyone who logs in tunnel to other machines through this box (pivoting). Some apps tunnel on purpose."
    if [ "$NOFWD" = Y ] || { [ -z "$NOFWD" ] && cc_ask "Turn OFF TCP forwarding, tunnels and gateway ports? (now: $(cur allowtcpforwarding yes))" N; }; then
        printf 'AllowTcpForwarding no\nPermitTunnel no\nGatewayPorts no\nAllowStreamLocalForwarding no\n' >>"$W/lines"
    fi
fi
cc_show "$C_GRY" "        Modern ciphers only: drops old algorithms, but an old client or scoring engine may no longer connect."
if [ "$STRONG" = Y ] || { [ -z "$STRONG" ] && cc_ask "Allow only modern ciphers, key exchange and MACs?" N; }; then
    printf 'KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512\n' >>"$W/lines"
    printf 'Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\n' >>"$W/lines"
    printf 'MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256\n' >>"$W/lines"
fi
if [ "$AUSET" = 0 ]; then
    cc_show "$C_GRY" "        AllowUsers: ONLY the accounts listed may log in by SSH. Strong, but easy to lock out the scoring engine or yourself."
    cc_ask_text "Only these accounts may log in by SSH (space separated; Enter = no limit)" ""
    ALLOWUSERS=$(printf '%s' "$CC_ANSWER" | tr ',' ' ')
fi
if [ -n "$ALLOWUSERS" ]; then
    _au=$ALLOWUSERS
    if [ -n "$CC_PROTECTED" ]; then
        for _p in $(awk -F',' 'tolower($1) ~ /account/ { gsub(/[ "\r]/, "", $2); print $2 }' "$CC_PROTECTED"); do
            case " $_au " in *" $_p "*) ;; *) _au="$_au $_p" ;; esac
        done
    fi
    printf 'AllowUsers %s\n' "$_au" >>"$W/lines"
fi
case "$ROOTMODE" in no) printf 'PermitRootLogin no\n' >>"$W/lines" ;; key-only) printf 'PermitRootLogin prohibit-password\n' >>"$W/lines" ;; esac
[ -n "$BANNER" ] && printf 'Banner %s\n' "$BANNER" >>"$W/lines"

# ---- 4/5  The plan --------------------------------------------------------------------
header "4/5  the plan"
SCSV=$(cc_csv_new settings "setting,before,after,status")
NSET=0
{ printf '# >>> CCDC LX-22 (sshd uses the first value it reads, so this block wins)\n'; cat "$W/lines"; printf '# <<< CCDC LX-22\n'; } >"$W/block"  # text, not a here-string: posix-ok
while read -r _k _v; do
    # The value in effect now: the first one sshd reads (an older CCDC block included).
    _b=$(awk -v k="$(printf '%s' "$_k" | tr 'A-Z' 'a-z')" 'tolower($1) == "match" { exit } tolower($1) == k { $1 = ""; sub(/^ /, ""); print; exit }' "$CONF" 2>/dev/null)
    if [ "$(printf '%s' "$_b" | tr 'A-Z' 'a-z')" = "$(printf '%s' "$_v" | tr 'A-Z' 'a-z')" ]; then _st="already ok"
    else _st=$([ "$CC_APPLY" = 1 ] && echo changed || echo "would change"); NSET=$((NSET + 1)); cc_show "$C_YEL" "  [~] $_k: ${_b:-(default)} -> $_v"; fi
    cc_csv_row "$SCSV" "$_k" "${_b:-(default)}" "$_v" "$_st"
done <"$W/lines"
[ "$NSET" -eq 0 ] && cc_show "$C_GRN" "  [ok] no sshd setting to change"
NRM=$(awk -F'|' '$11 == "remove"' "$W/keydec" | grep -c .)
NKEEP=$(awk -F'|' '$11 == "keep"' "$W/keydec" | grep -c .)
[ "$NRM" -gt 0 ] && awk -F'|' '$11 == "remove" { printf "  [~] remove key #%s (%s, %s, %s) from %s\n", $1, $2, $6, ($7 == "" ? "no comment" : $7), $3 }' "$W/keydec" >"$W/rmshow" && while IFS= read -r _l; do cc_show "$C_YEL" "$_l"; done <"$W/rmshow"
[ -s "$W/rcq" ] && while IFS= read -r _f; do cc_show "$C_YEL" "  [~] move $_f to quarantine"; done <"$W/rcq"
cc_show "" "  Keys: $NKEEP kept, $NRM removed.  Password logins: $(grep -q '^PasswordAuthentication no' "$W/lines" && echo 'turned OFF' || echo 'left on')."
KCSV=$(cc_csv_new keys "number,user,file,type,fingerprint,comment,options,verdict,why,action")
while IFS='|' read -r _n _u _f _ln _t _fp _c _o _v _why _act _uid; do
    cc_csv_row "$KCSV" "$_n" "$_u" "$_f" "$_t" "$_fp" "$_c" "$_o" "$_v" "$_why" "$([ "$CC_APPLY" = 1 ] && [ "$_act" = remove ] && echo removed || echo "$_act")"
done <"$W/keydec"

# Candidate config: our block, then the file without any older block.
_cfg_status="not changed"
if [ -f "$CONF" ]; then
    awk '/^# >>> CCDC LX-22/ { skip = 1 } !skip { print } /^# <<< CCDC LX-22/ { skip = 0 }' "$CONF" >"$W/rest"  # awk regex: posix-ok
    cat "$W/block" "$W/rest" >"$W/sshd_config.new"
    if cmp -s "$W/sshd_config.new" "$CONF"; then _cfg_status="already in place"
    elif [ -z "$SSHD" ]; then _cfg_status="not changed: sshd not found, so the new config cannot be tested"
    elif ! "$SSHD" -t -f "$W/sshd_config.new" >"$W/sshd_t" 2>&1; then
        cat "$W/sshd_t" >>"$CC_LOG"; CC_N_FAIL=$((CC_N_FAIL + 1))
        _cfg_status="FAILED: sshd -t rejected the new config, so it is NOT installed: $(head -n 1 "$W/sshd_t")"
        cc_show "$C_RED" "  [x] $_cfg_status"
    else
        _cfg_status="ready (passed sshd -t)"
        cc_show "$C_GRN" "  [ok] the new config passed sshd -t"
    fi
fi

# ---- 5/5  Apply -----------------------------------------------------------------------
header "5/5  apply"
[ "$_cfg_status" = "already in place" ] && NSET=0
NRC=$(grep -c . "$W/rcq" 2>/dev/null); case "$NRC" in ''|*[!0-9]*) NRC=0 ;; esac
NCH=$((NSET + NRM + NRC))
APPLIED=0; TIMER_ON=0; _reload="not needed"
result() { if [ "$1" -eq 0 ]; then echo changed; else echo failed; fi; }
sshd_listening() {
    if cc_have ss; then ss -ltnp 2>/dev/null | grep -q '"sshd"'
    else netstat -ltnp 2>/dev/null | grep -q '/sshd'; fi
}
sshd_reload_cmd() {
    if [ "$CC_INIT" = systemd ]; then echo 'systemctl reload ssh 2>/dev/null || systemctl reload sshd'
    elif cc_have rc-service; then echo 'rc-service sshd reload'
    else echo 'kill -HUP "$(cat /run/sshd.pid 2>/dev/null || cat /var/run/sshd.pid)"'; fi
}
if [ "$NCH" -eq 0 ]; then
    cc_show "$C_GRN" "  [ok] Nothing to change."
elif [ "$CC_APPLY" != 1 ]; then
    cc_show "$C_GRY" "  $NCH change(s) planned. Dry run: nothing was changed. Run again with --apply (keep a second root session open)."
elif ! cc_ask "Apply these $NCH change(s) now? (a revert timer undoes them unless you confirm from a NEW session)" Y; then
    cc_show "$C_GRY" "  Not applied. The plan is in $CC_RUN_DIR"
else
    APPLIED=1
    if [ -z "$R" ] && [ "$NOTIMER" != 1 ]; then
        cc_timer_start "$TIMER"; TIMER_ON=1
        cc_show "$C_YEL" "  [*] Revert timer started: everything is undone in $((TIMER / 60)):$(printf '%02d' $((TIMER % 60))) unless you confirm at the end."
    fi
    _q=$CC_QUIET; CC_QUIET=1
    # Keys: rewrite each file without the removed lines (evidence kept).
    awk -F'|' '$11 == "remove" { print $3 }' "$W/keydec" | sort -u >"$W/kfiles"
    while IFS= read -r _f; do
        _pf="$R$_f"
        awk -F'|' -v f="$_f" '$3 == f && $11 == "remove" { print $4 }' "$W/keydec" >"$W/drop"
        awk 'NR == FNR { d[$1] = 1; next } !(FNR in d)' "$W/drop" "$_pf" >"$W/kept"
        awk 'NR == FNR { d[$1] = 1; next } (FNR in d)' "$W/drop" "$_pf" >"$W/removed"
        cc_guard path "$_f" || { cc_show "$C_YEL" "  [-] $_f is protected: left alone"; continue; }
        cc_backup_file "$_pf" || continue
        (umask 077; mkdir -p "$(dirname "$CC_QUAR_DIR$_f")" && cp "$W/removed" "$CC_QUAR_DIR$_f.removed")
        # cp onto the existing file keeps its owner and mode.
        if cc_run "remove $(grep -c . "$W/drop") key(s) from $_f" cp "$W/kept" "$_pf"; then cc_show "$C_GRN" "  [+] removed $(grep -c . "$W/drop") key(s) from $_f (copy in quarantine/)"
        else cc_show "$C_RED" "  [x] could not rewrite $_f (immutable? lsattr $_f; chattr -i $_f)"; fi
    done <"$W/kfiles"
    while IFS= read -r _f; do
        cc_quarantine "$R$_f"; _rc=$?
        if [ "$_rc" -eq 0 ]; then cc_show "$C_GRN" "  [+] moved $_f to quarantine"; elif [ "$_rc" -eq 4 ]; then cc_show "$C_YEL" "  [-] $_f is protected: left alone"; else cc_show "$C_RED" "  [x] could not move $_f"; fi
    done <"$W/rcq"
    # sshd_config: installed only if it passed sshd -t.
    case "$_cfg_status" in
        "ready"*)
            if cc_guard path /etc/ssh/sshd_config; then
                # A revert puts the file back and then reloads sshd (undo lines run newest first).
                [ -z "$R" ] && [ "$NORELOAD" != 1 ] && cc_undo_add "reload sshd after the config is put back" "$(sshd_reload_cmd)"
                if cc_backup_file "$CONF" && cc_run "install the hardened sshd_config" cp "$W/sshd_config.new" "$CONF"; then
                    _cfg_status="installed (passed sshd -t)"; cc_show "$C_GRN" "  [+] sshd_config: block of $(grep -c . "$W/lines") setting(s) installed at the top"
                else _cfg_status="FAILED to install"; cc_show "$C_RED" "  [x] could not install sshd_config"; fi
            else _cfg_status="not changed (protected)"; fi ;;
    esac
    CC_QUIET=$_q
    case "$_cfg_status" in installed*)
        if [ -n "$R" ] || [ "$NORELOAD" = 1 ]; then _reload="not reloaded (--no-reload or --root): run 'sshd -t' and reload sshd yourself"
        elif ! sshd_listening; then _reload="sshd is not running; the new config applies when it starts"
        else
            cc_run_quiet "reload sshd" sh -c "$(sshd_reload_cmd)"; sleep 2
            if sshd_listening; then _reload="reloaded; sshd still listening (open sessions stay up)"; cc_show "$C_GRN" "  [+] sshd reloaded and still listening"
            else
                cc_err "sshd is NOT listening after the reload - putting the old config back"
                _rb="$CC_BACKUP_DIR$(cc_abspath "$CONF")"; [ -f "$_rb" ] && cp -p "$_rb" "$CONF" 2>>"$CC_LOG"
                sh -c "$(sshd_reload_cmd)" >>"$CC_LOG" 2>&1 || "$SSHD" >>"$CC_LOG" 2>&1
                CC_N_FAIL=$((CC_N_FAIL + 1))
                _reload="FAILED: sshd stopped listening; old config restored$(sshd_listening && echo ', sshd is back' || echo ', START SSHD BY HAND')"
                cc_show "$C_RED" "  [x] $_reload"
            fi
        fi ;;
    esac
    if [ "$TIMER_ON" = 1 ]; then
        header "KEEP OR REVERT"
        cc_timer_finish || true
    fi
fi

# ---- Summary --------------------------------------------------------------------------
cc_csv_pretty "$SCSV" "$CC_RUN_DIR/settings.txt" 60
cc_csv_pretty "$KCSV" "$CC_RUN_DIR/keys.txt" 60
{
    printf 'LX-22 SSH hardening | host %s | %s | %s\n\n' "$CC_HOST" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$([ "$APPLIED" = 1 ] && echo APPLIED || echo 'DRY RUN - nothing changed')"
    printf 'sshd_config: %s\n' "$_cfg_status"
    printf 'sshd:        %s\n' "$_reload"
    printf '\nSettings:\n'
    awk "$CC_AWK_CSV"'NR > 1 { csvsplit($0, f); printf "  %-24s %-18s -> %-30s %s\n", f[1], substr(f[2], 1, 18), substr(f[3], 1, 30), f[4] }' "$SCSV"
    printf '\nKeys: %s kept, %s %s\n' "$NKEEP" "$NRM" "$([ "$APPLIED" = 1 ] && echo removed || echo 'to remove')"
    awk -F'|' '{ printf "  #%-3s %-10s %-8s %-46s %s%s\n", $1, $2, $11, $6, ($7 == "" ? "" : $7), ($9 == "ok" ? "" : "  <- " $9) }' "$W/keydec" | head -n 40
    if [ -s "$W/report" ]; then printf '\nCheck by hand:\n'; awk '{ l = "  " $0; if (length(l) > 220) l = substr(l, 1, 217) "..."; print l }' "$W/report"; fi
    printf '\n'
    [ "$APPLIED" = 1 ] || printf 'Nothing was changed.%s\n' "$([ "$CC_APPLY" = 1 ] || echo '  Run again with --apply (keep a second root session open).')"
    [ "$APPLIED" = 1 ] && [ "$TIMER_ON" = 1 ] && printf 'Undo at any time: sh %s/revert.sh --force\n' "$CC_RUN_DIR"
    printf 'All results: %s\n' "$CC_RUN_DIR"
} >"$CC_RUN_DIR/summary.txt"
header "SUMMARY"
awk -v R="$C_RED" -v Y="$C_YEL" -v G="$C_GRN" -v C="$C_CYN" -v D="$C_GRY" -v O="$C_OFF" '
    NR == 1                                  { print C $0 O; next }
    /^(sshd_config|sshd): +(FAILED|not changed: sshd)/ { print R $0 O; next }
    /^(sshd_config|sshd):/                   { print G $0 O; next }
    /^(Settings|Keys|Check by hand)/         { m = substr($0, 1, 1); print C $0 O; next }
    /^$/                                     { m = ""; print; next }
    m == "S" && / (changed|would change)$/   { print Y $0 O; next }
    m == "S"                                 { print G $0 O; next }
    m == "K" && /<- planted/                 { print R $0 O; next }
    m == "K" && /<- check/                   { print Y $0 O; next }
    m == "C"                                 { print Y $0 O; next }
    /^All results/                           { print D $0 O; next }
                                             { print }
' "$CC_RUN_DIR/summary.txt"
cat "$CC_RUN_DIR/summary.txt" >>"$OUTF"
rm -rf "$W"
cc_finish
