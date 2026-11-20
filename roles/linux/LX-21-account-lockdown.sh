#!/bin/sh
# =============================================================================
# ID:       LX-21
# NAME:     Account lockdown (Linux)
# ROLE:     Linux  (wave 1, right after the passwords; again after red team)
# KIND:     changes - dry run unless --apply
# VERSION:  1.1.0
#
# PURPOSE
#   After the web shells, red team's way back in is an account: one they
#   made, a second root, a key in someone's authorized_keys, a sudo rule, a
#   service account with a shell.  This goes through every account, one by
#   one, shows what it can do, and asks what to do with it:
#
#     every account     UID, shell, password (set / empty / locked / in
#                       /etc/passwd), admin groups (sudo wheel admin docker
#                       lxd disk shadow ...), its sudo lines (NOPASSWD), SSH
#                       keys (and key options), when its password last changed
#     HIGH              a second UID 0; an empty password; a hash in
#                       /etc/passwd; a service account (www-data, mysql ...)
#                       that can log in with a password or a key
#     MED               an admin that is not on the protected list; NOPASSWD;
#                       a password changed in the last 2 days; a service
#                       account with a login shell
#     sudo rules        lines that give everyone root (ALL ALL, %users ...),
#                       NOPASSWD: ALL, rules for users that do not exist;
#                       doas rules (Alpine) the same way (nopass = NOPASSWD)
#
#   For each account worth a decision (Enter = the default in capitals):
#     [k] keep   [l] lock (no password or key logins; files stay)
#     [d] take admin away (admin groups and its sudo lines)
#     [r] remove its SSH keys (to quarantine)   [b] both d and r
#     [n] no-login shell (service accounts)     [a] all the rest default
#   Accounts on the protected list, root and the account you are using are
#   never locked; the protected ones need an extra yes for anything.
#   For each dangerous sudo line: comment it out, yes or no.
#   Every sudoers change is checked with visudo -c first (doas: doas -C).
#
#   QUESTIONS (a flag answers each):
#     which box                                --box NAME
#     go through each account?                 --batch = no, defaults
#     each account / each sudo line            --batch takes the defaults
#     apply?                                   --apply
#
# USAGE
#   sudo sh LX-21-account-lockdown.sh                             look + dry run
#   sudo sh LX-21-account-lockdown.sh --protected p.csv --apply   asks about each
#   sudo sh LX-21-account-lockdown.sh --protected p.csv --apply --batch
#
# OPTIONS
#   --apply            make the changes (without it, dry run only)
#   --box NAME         splunk | webmail | ecomm | other (asked)
#   --all              ask about every account, not only those flagged
#   --days N           "changed lately" = the last N days (default 2)
#   --timer SECONDS    revert countdown (default 120); --no-timer
#   --root DIR         treat DIR as / (tests): files edited directly
#   --no-color         no colours
#   --help             this text plus the common options
#
# OUTPUTS  (under --out, in accounts-N/)
#   output.txt   everything shown on screen, no colour
#   accounts.txt every account and what it can do
#   plan.txt, changes.txt, summary.txt, run.txt, revert.sh
#   before/      each account's lines as they were (root only)
#
# WHAT IT CHANGES  (only with --apply)
#   /etc/shadow (lock + expire), /etc/passwd (login shell), /etc/group and
#   /etc/gshadow (admin group membership), sudoers lines (commented out with
#   "# LX-21: "), authorized_keys files (moved to quarantine).  The undo puts
#   each account's saved lines back.  Passwords: LX-20.  Finding planted
#   cron jobs, PAM and the rest: LX-42.
#
# DEPENDS ON
#   usermod, gpasswd, visudo when present (with --root: plain file edits).
#
# TESTED ON
#   Ubuntu 24.04 (fake root, and a live throwaway account), under dash,
#   bash, busybox sh, ksh93, mksh and yash with gawk, mawk and busybox awk.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - Lock = usermod -L and an expired account, so SSH keys stop too.  An
#     already logged-in session stays: LX-40 shows it, kill it by hand.
#   - LDAP / AD accounts (sssd, winbind) are not in /etc/passwd: not seen.
#   - The scoring engine logs in to SSH as some account: protected list.
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
LX-21 Account lockdown - every account, one by one: keep, lock, take admin away, remove keys
  sudo sh LX-21-account-lockdown.sh                          look + dry run
  sudo sh LX-21-account-lockdown.sh --protected p.csv --apply

  --apply            make the changes (without it, dry run only)
  --box NAME         splunk | webmail | ecomm | other
  --all              ask about every account, not only those flagged
  --days N           "changed lately" = the last N days (default 2)
  --timer SECONDS    revert countdown (default 120); --no-timer
  --root DIR         treat DIR as / (tests)
  --no-color         no colours
  --help             show this text
USAGE
    cc_usage_common
}

BOX=""; ALL=0; DAYS=2; TIMER=120; NOTIMER=0; R=""; COLOR=1
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --apply)    CC_APPLY=1; shift ;;
        --box)      [ $# -ge 2 ] || cc_die 2 "--box needs a name"; BOX=$2; shift 2 ;;
        --all)      ALL=1; shift ;;
        --days)     [ $# -ge 2 ] || cc_die 2 "--days needs a number"; DAYS=$2; shift 2 ;;
        --timer)    [ $# -ge 2 ] || cc_die 2 "--timer needs seconds"; TIMER=$2; shift 2 ;;
        --no-timer) NOTIMER=1; shift ;;
        --root)     [ $# -ge 2 ] || cc_die 2 "--root needs a folder"; [ -d "$2" ] || cc_die 2 "--root: not a folder: $2"; R=$(cd "$2" && pwd); [ "$R" = / ] && R=""; shift 2 ;;
        --no-color|--no-colour) COLOR=0; shift ;;
        --help|-h)  usage; exit 0 ;;
        *)          cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
case "$BOX" in ''|splunk|webmail|ecomm|other) ;; *) cc_die 2 "--box must be splunk, webmail, ecomm or other" ;; esac
for _n in "$DAYS" "$TIMER"; do case "$_n" in ''|*[!0-9]*) cc_die 2 "--days and --timer need whole numbers" ;; esac; done

cc_init "LX-21" "Account lockdown" changes
cc_detect_os
# shellcheck disable=SC2034  # read by cc_color_init
[ "$COLOR" = 1 ] || CC_NOCOLOR=1
cc_color_init
cc_use_numbered_dir accounts
rmdir "$CC_RUN_DIR/raw" 2>/dev/null
OUTF="$CC_RUN_DIR/output.txt"
grep -v '\[NOTE\]\|\[DEBUG\]' "$CC_LOG" >"$OUTF" 2>/dev/null || : >"$OUTF"
# shellcheck disable=SC2034  # CC_TEE is read by the library's log functions
CC_TEE=$OUTF
W="$CC_RUN_DIR/.work"; mkdir -p "$W"; chmod 700 "$W"
mkdir -p "$CC_RUN_DIR/before"; chmod 700 "$CC_RUN_DIR/before"
CC_CSV_DIR="$W/csv"; mkdir -p "$CC_CSV_DIR"
header() { cc_show "" ""; cc_show "$C_CYN" "==========[ $1 ]=========="; }
P() { printf '%s%s' "$R" "$1"; }

cc_show "$C_CYN" "LX-21 Account lockdown | host $CC_HOST | results in $CC_RUN_DIR"
cc_show "" "Legend: ${C_RED}[!]${C_OFF} fix now   ${C_YEL}[*]${C_OFF} look at it   ${C_GRN}[ok]${C_OFF} fine   ${C_YEL}[~] would change${C_OFF}   ${C_GRN}[+] changed${C_OFF}   ${C_RED}[x] failed${C_OFF}"
[ -n "$R" ] && cc_show "$C_GRY" "Acting on $R as if it were / (files edited directly)"

if [ -z "$BOX" ]; then
    cc_choose "Which box is this?" o "s=splunk" "w=webmail" "e=ecomm" "o=other"
    case "$CC_CHOICE" in s) BOX=splunk ;; w) BOX=webmail ;; e) BOX=ecomm ;; *) BOX=other ;; esac
fi
case "$BOX" in splunk|webmail)
    cc_show "$C_YEL" "  SSH is SCORED on $BOX ($BOX-ssh): the scoring engine logs in as some account. Keep that one (put it on the protected list)." ;;
esac

# ---- Accounts --------------------------------------------------------------------------
UID_MIN=$(awk '$1 == "UID_MIN" { print $2 }' "$(P /etc/login.defs)" 2>/dev/null); case "$UID_MIN" in ''|*[!0-9]*) UID_MIN=1000 ;; esac
ADMIN_GROUPS="root sudo wheel admin docker lxd lxc libvirt disk shadow"
ME=${SUDO_USER:-$(id -un 2>/dev/null)}
TODAY=$(( $(date +%s) / 86400 ))
# Every sudoers and doas line in use: "file|line number|who|NOPASSWD y/n|text"
#   who: a user name, or %group.
: >"$W/sudo"
for _s in "$(P /etc/sudoers)" "$(P /etc/sudoers.d)"/*; do
    [ -f "$_s" ] || continue
    # sudo skips sudoers.d files whose name has a dot or ends in ~: so do we.
    case "${_s##*/}" in *~|*.*) [ "$(dirname "$_s")" = "$(P /etc/sudoers.d)" ] && continue ;; esac
    awk -v f="${_s#"$R"}" '{ t = $0; sub(/^[ \t]+/, "", t) } t == "" || t ~ /^#/ || t ~ /^(Defaults|Cmnd_Alias|Host_Alias|Runas_Alias|User_Alias)/ { next }
        { split(t, w, /[ \t]+/); printf "%s|%d|%s|%s|%s\n", f, NR, w[1], (t ~ /NOPASSWD/) ? "y" : "n", t }' "$_s" >>"$W/sudo"
done
# doas (Alpine): "permit [nopass persist ...] user|:group [as target] [cmd ...]".
# Only permit lines give rights; :group is written %group like sudo.
for _s in "$(P /etc/doas.conf)" "$(P /etc/doas.d)"/*.conf; do
    [ -f "$_s" ] || continue
    awk -v f="${_s#"$R"}" '{ t = $0; sub(/^[ \t]+/, "", t) } t !~ /^permit[ \t]/ { next }
        { n = split(t, w, /[ \t]+/); np = "n"; who = ""; i = 2
          # options, and a setenv { ... } block
          while (i <= n) { if (w[i] == "nopass") np = "y"
              if (w[i] ~ /^setenv/) { while (i <= n && w[i] !~ /}$/) i++; i++; continue }
              if (w[i] ~ /^(nopass|nolog|persist|keepenv)$/) { i++; continue }
              break }
          who = w[i]; if (substr(who, 1, 1) == ":") who = "%" substr(who, 2)
          printf "%s|%d|%s|%s|%s\n", f, NR, who, np, t }' "$_s" >>"$W/sudo"
done
# groups_of USER GID -> space separated group names
groups_of() { awk -F: -v u="$1" -v g="$2" '$3 == g { print $1; next } { n = split($4, m, ","); for (i = 1; i <= n; i++) if (m[i] == u) { print $1; break } }' "$(P /etc/group)" | tr '\n' ' ' | sed 's/ $//'; }
# keys_of HOME -> "COUNT|OPTIONS" (options: command=, from= ...)
keys_of() {
    _kn=0; _ko=""
    for _k in "$1/.ssh/authorized_keys" "$1/.ssh/authorized_keys2"; do
        [ -f "$(P "$_k")" ] || continue
        _kn=$((_kn + $(grep -c '^[^#]*\(ssh-\|ecdsa-\|sk-\)' "$(P "$_k")")))
        grep -q '^[a-z-]*=\|^[^#]*command=' "$(P "$_k")" && _ko="with options (command=/from=)"
    done
    printf '%s|%s' "$_kn" "$_ko"
}
# $W/acc: user|uid|kind|shell|login|pw|groups|admin|sudo|nopw|keys|keyopt|days|home|flags|level|default
: >"$W/acc"
awk -F: '{ print $1 "|" $3 "|" $4 "|" $6 "|" $7 "|" $2 }' "$(P /etc/passwd)" >"$W/pw"
while IFS='|' read -r _u _uid _gid _home _sh _pf; do
    _kind=service; [ "$_uid" = 0 ] && _kind=root
    [ "$_uid" -ge "$UID_MIN" ] && [ "$_uid" -lt 60000 ] && _kind=human
    [ "$_uid" = 0 ] && [ "$_u" != root ] && _kind=uid0
    _login=no; case "${_sh##*/}" in nologin|false|sync|shutdown|halt|'') ;; *) _login=yes ;; esac
    _sl=$(awk -F: -v u="$_u" '$1 == u { print $2 "|" $3 }' "$(P /etc/shadow)" 2>/dev/null)
    _hash=${_sl%%"|"*}; _lc=${_sl#*"|"}
    case "$_pf" in x|'*'|'!'|'!!') case "$_hash" in '') _pw=empty ;; '!'*|'*'*) _pw=locked ;; *) _pw="set" ;; esac ;;
        '') _pw=empty ;; *) _pw=in-passwd ;; esac
    [ -z "$_sl" ] && [ "$_pf" = x ] && _pw=locked
    _grs=$(groups_of "$_u" "$_gid"); _adm=""
    for _g in $_grs; do case " $ADMIN_GROUPS " in *" $_g "*) _adm="$_adm $_g" ;; esac; done; _adm=${_adm# }
    # Sudo lines for this user (by name, or by one of its groups).
    _sud=$(awk -F'|' -v u="$_u" -v g=" $_grs " '{ n = $3; if (n == u || (substr(n, 1, 1) == "%" && index(g, " " substr(n, 2) " "))) print $1 ":" $2 }' "$W/sudo" | tr '\n' ' ' | sed 's/ $//')
    _nop=no; [ -n "$_sud" ] && awk -F'|' -v u="$_u" -v g=" $_grs " '{ n = $3; if ((n == u || (substr(n, 1, 1) == "%" && index(g, " " substr(n, 2) " "))) && $4 == "y") f = 1 } END { exit !f }' "$W/sudo" && _nop=yes
    _ki=$(keys_of "$_home"); _keys=${_ki%%"|"*}; _kopt=${_ki#*"|"}
    _days=-; case "$_lc" in ''|*[!0-9]*) ;; *) _days=$((TODAY - _lc)) ;; esac
    # Findings and the default answer.
    _fl=""; _lv=ok; _def=k
    hi() { _fl="$_fl $1;"; _lv=HIGH; }
    me() { _fl="$_fl $1;"; [ "$_lv" = HIGH ] || _lv=MED; }
    [ "$_kind" = uid0 ] && { hi "UID 0: it IS root under another name"; _def=l; }
    [ "$_pw" = empty ] && [ "$_login" = yes ] && { hi "NO password: anyone can log in"; _def=l; }
    [ "$_pw" = in-passwd ] && { hi "password hash in /etc/passwd (readable by everyone)"; _def=l; }
    if [ "$_kind" = service ] && [ "$_login" = yes ]; then
        if [ "$_pw" = set ] || [ "$_keys" -gt 0 ]; then hi "service account that can log in ($_sh$([ "$_pw" = set ] && echo ', has a password')$([ "$_keys" -gt 0 ] && echo ", $_keys SSH key(s)"))"; else me "service account with a login shell ($_sh)"; fi
        _def=n
    fi
    # sync, halt, shutdown (Alpine: group root) cannot log in at all: no use as an admin.
    _dead=0; [ "$_login" = no ] && [ "$_pw" != set ] && [ "$_keys" = 0 ] && [ -z "$_sud" ] && _dead=1
    [ -n "$_adm" ] && [ "$_kind" != root ] && [ "$_dead" = 0 ] && ! cc_is_protected account "$_u" && me "admin ($_adm) - one of yours?"
    [ -n "$_sud" ] && [ "$_kind" != root ] && ! cc_is_protected account "$_u" && me "has sudo lines ($_sud)$([ "$_nop" = yes ] && echo ', NOPASSWD')"
    [ "$_keys" -gt 0 ] && [ -n "$_kopt" ] && me "SSH keys $_kopt"
    [ "$_days" != - ] && [ "$_days" -le "$DAYS" ] && [ "$_pw" = set ] && [ "$_kind" != service ] && me "password changed $_days day(s) ago"
    printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' "$_u" "$_uid" "$_kind" "$_sh" "$_login" "$_pw" "$_grs" "$_adm" "$_sud" "$_nop" "$_keys" "$_kopt" "$_days" "$_home" "${_fl# }" "$_lv" "$_def" >>"$W/acc"
done <"$W/pw"

header "1/5  accounts"
cc_show "$C_CYN" "$(printf '  %-14s %-6s %-8s %-6s %-9s %-16s %-5s %-4s %s' USER UID KIND LOGIN PASSWORD "ADMIN GROUPS" SUDO KEYS NOTES)"
ACSV=$(cc_csv_new accounts "user,uid,kind,shell,password,groups,admin_groups,sudo_lines,nopasswd,ssh_keys,password_changed_days_ago,notes,decision")
while IFS='|' read -r _u _uid _kind _sh _login _pw _grs _adm _sud _nop _keys _kopt _days _home _fl _lv _def; do
    # Clean accounts that cannot log in (service, build users) stay out of the table.
    _show=1; [ "$_lv" = ok ] && [ "$_login" = no ] && _show=0; [ "$_kind" = service ] && [ "$_lv" = ok ] && _show=0
    if [ "$_show" = 1 ]; then
        _c=""; [ "$_lv" = HIGH ] && _c=$C_RED; [ "$_lv" = MED ] && _c=$C_YEL
        cc_show "$_c" "$(printf '  %-14s %-6s %-8s %-6s %-9s %-16s %-5s %-4s %s' "$_u" "$_uid" "$_kind" "$_login" "$_pw" "${_adm:--}" "$([ -n "$_sud" ] && { [ "$_nop" = yes ] && echo NOPW || echo yes; } || echo -)" "$_keys" "$(printf '%s' "$_fl" | sed 's/;$//')")"
    fi
done <"$W/acc"
cc_show "$C_GRY" "  ($(awk -F'|' '$16 == "ok" && ($5 == "no" || $3 == "service")' "$W/acc" | grep -c .) clean accounts that cannot log in are not shown: they are in accounts.txt)"

# ---- Sudo rules on their own -------------------------------------------------------------
header "2/5  sudo rules"
: >"$W/sbad"
while IFS='|' read -r _f _n _w _np _t; do
    _why=""
    case "$_w" in ALL) _why="gives EVERY user root" ;; %users|%everyone|%staff) _why="gives a whole group ($_w) root" ;; esac
    if [ -z "$_why" ] && [ "${_w#%}" = "$_w" ] && [ "$_w" != root ] && ! awk -F'|' -v u="$_w" '$1 == u { f = 1 } END { exit !f }' "$W/pw"; then
        awk -F= -v u="$_w" '/^User_Alias/ { split($1, a, /[ \t]+/); if (a[2] == u) f = 1 } END { exit !f }' "$(P /etc/sudoers)" 2>/dev/null || _why="for a user that does not exist ($_w)"
    fi
    # A line for one existing user is asked about with that account; here
    # only group-wide NOPASSWD.
    case "$_w$_t" in %*NOPASSWD*ALL*) [ -z "$_why" ] && ! cc_is_protected account "$_w" && _why="NOPASSWD: ALL for the whole group (root with no password)" ;; esac
    # doas: nopass for a whole group, any command.
    case "$_w|$_np|$_t" in %*"|y|permit"*) case "$_t" in *[[:space:]]cmd[[:space:]]*) ;; *) [ -z "$_why" ] && ! cc_is_protected account "$_w" && _why="doas nopass for the whole group (root with no password)" ;; esac ;; esac
    if [ -n "$_why" ]; then printf '%s|%s|%s|%s\n' "$_f" "$_n" "$_t" "$_why" >>"$W/sbad"; cc_show "$C_RED" "  [!] $_f line $_n: $_t  - $_why"; fi
done <"$W/sudo"
[ -s "$W/sbad" ] || cc_show "$C_GRN" "  [ok] no sudo line gives everyone root (per-account lines are with each account)"

# ---- Questions ------------------------------------------------------------------------
header "3/5  questions (Enter = the default in capitals)"
# $W/plan: user|action|why    action: k l d r b n
: >"$W/plan"
if [ "$ALL" = 1 ]; then awk -F'|' '$3 != "service" || $16 != "ok"' "$W/acc" >"$W/ask"
else awk -F'|' '$16 != "ok"' "$W/acc" >"$W/ask"; fi
CANAPPLY=0; { [ -n "$R" ] || cc_is_root; } && CANAPPLY=1
ONEBYONE=0
if [ -s "$W/ask" ]; then
    if cc_ask "Go through the $(grep -c . "$W/ask") flagged account(s) one by one?" Y "yes, ask me about each account" "no, take the default for each (shown in the table)"; then ONEBYONE=1; fi
fi
_all=0
while IFS='|' read -r _u _uid _kind _sh _login _pw _grs _adm _sud _nop _keys _kopt _days _home _fl _lv _def; do
    # Never offered: locking root or yourself.
    _self=0; { [ "$_u" = root ] || [ "$_u" = "$ME" ]; } && _self=1
    _prot=0; cc_is_protected account "$_u" && _prot=1
    [ "$_prot" = 1 ] && _def=k
    [ "$_self" = 1 ] && [ "$_def" = l ] && _def=k
    if [ "$ONEBYONE" = 0 ] || [ "$_all" = 1 ]; then printf '%s|%s|%s\n' "$_u" "$_def" "default" >>"$W/plan"; continue; fi
    cc_show "" ""
    cc_show "$([ "$_lv" = HIGH ] && printf '%s' "$C_RED" || printf '%s' "$C_YEL")" "  $_u: $(printf '%s' "$_fl" | sed 's/;$//')"
    [ "$_prot" = 1 ] && cc_show "$C_GRY" "  (on the protected list)"
    [ "$_self" = 1 ] && cc_show "$C_GRY" "  ($([ "$_u" = root ] && echo 'root' || echo 'the account you are using'): it cannot be locked here)"
    set -- "k=keep it as it is"
    [ "$_self" = 0 ] && set -- "$@" "l=lock it: no password or SSH-key logins (its files stay)"
    [ -n "$_adm$_sud" ] && set -- "$@" "d=take its admin rights away (groups: ${_adm:-none}; sudo lines: ${_sud:-none})"
    [ "$_keys" -gt 0 ] && set -- "$@" "r=remove its SSH keys ($_keys, moved to quarantine)"
    [ -n "$_adm$_sud" ] && [ "$_keys" -gt 0 ] && set -- "$@" "b=both: take admin away and remove its keys"
    [ "$_login" = yes ] && [ "$_kind" = service ] && set -- "$@" "n=no-login shell (the service keeps running; nobody logs in as it)"
    set -- "$@" "a=all the rest: take their defaults"
    cc_choose "$_u (uid $_uid, $([ "$_login" = yes ] && echo 'can log in' || echo 'no login shell'), password $_pw$([ -n "$_grs" ] && echo ", groups: $_grs")$([ "$_keys" -gt 0 ] && echo ", $_keys SSH key(s)")$([ -n "$_sud" ] && echo ", sudo$([ "$_nop" = yes ] && echo ' NOPASSWD')"))?" "$_def" "$@"
    _ans=$CC_CHOICE
    [ "$_ans" = a ] && { _all=1; printf '%s|%s|%s\n' "$_u" "$_def" "default" >>"$W/plan"; continue; }
    if [ "$_ans" != k ] && [ "$_prot" = 1 ]; then
        cc_ask "  $_u is on the protected list. Change it anyway?" N "yes, change it" "no, keep it" || _ans=k
    fi
    printf '%s|%s|%s\n' "$_u" "$_ans" "you chose" >>"$W/plan"
done <"$W/ask"
: >"$W/splan"
while IFS='|' read -r _f _n _t _why; do
    _chk=visudo; case "$_f" in /etc/doas*) _chk="doas -C" ;; esac
    cc_ask "Comment out $_f line $_n ($_t) - $_why?" Y "yes, comment it out (checked with $_chk first)" "no, leave it" && printf '%s|%s|%s\n' "$_f" "$_n" "$_t" >>"$W/splan"
done <"$W/sbad"

# ---- Plan ---------------------------------------------------------------------------------
header "4/5  plan"
act_word() { case "$1" in l) echo "lock" ;; d) echo "take admin away" ;; r) echo "remove SSH keys" ;; b) echo "take admin away + remove SSH keys" ;; n) echo "no-login shell" ;; *) echo keep ;; esac; }
NCH=0; : >"$CC_RUN_DIR/plan.txt"
while IFS='|' read -r _u _a _why; do
    [ "$_a" = k ] && continue
    NCH=$((NCH + 1)); cc_show "$C_YEL" "  [~] $_u: $(act_word "$_a")"; printf '%s: %s (%s)\n' "$_u" "$(act_word "$_a")" "$_why" >>"$CC_RUN_DIR/plan.txt"
done <"$W/plan"
while IFS='|' read -r _f _n _t; do NCH=$((NCH + 1)); cc_show "$C_YEL" "  [~] comment out $_f line $_n: $_t"; printf 'comment out %s line %s: %s\n' "$_f" "$_n" "$_t" >>"$CC_RUN_DIR/plan.txt"; done <"$W/splan"
[ "$NCH" -eq 0 ] && cc_show "$C_GRN" "  [ok] Nothing to change."

# ---- Helpers for the changes ------------------------------------------------------------
# save_line FILE USER -> the user's line kept in before/, undo puts it back.
save_line() {
    _sf="$CC_RUN_DIR/before/$(basename "$1")-$2"
    [ -f "$_sf" ] && return 0
    _real=$(P "$1")
    if [ "$(basename "$1")" = group ] || [ "$(basename "$1")" = gshadow ]; then
        # Group files: every line the user is in.
        (umask 077; awk -F: -v u="$2" '{ n = split($4, m, ","); for (i = 1; i <= n; i++) if (m[i] == u) { print; break } }' "$_real" >"$_sf")
    else (umask 077; awk -F: -v u="$2" '$1 == u' "$_real" >"$_sf"); fi
    [ -s "$_sf" ] || { rm -f "$_sf"; return 0; }
    cc_undo_add "put back $2's lines in $1" "awk -F: 'NR == FNR { l[\$1] = \$0; next } (\$1 in l) { print l[\$1]; next } { print }' $(cc_shquote "$_sf") $(cc_shquote "$_real") > $(cc_shquote "$_real.lx21") && cat $(cc_shquote "$_real.lx21") > $(cc_shquote "$_real") && rm -f $(cc_shquote "$_real.lx21")"
}
# edit FILE AWK-PROGRAM USER -> rewrite a file in place (keeps owner and mode).
edit() { awk -F: -v OFS=: -v u="$3" "$2" "$(P "$1")" >"$(P "$1").lx21" && cat "$(P "$1").lx21" >"$(P "$1")"; _er=$?; rm -f "$(P "$1").lx21"; return "$_er"; }
do_lock() {
    save_line /etc/shadow "$1"
    if [ -z "$R" ] && cc_have usermod; then usermod -L "$1" && usermod -e 1 "$1"
    else edit /etc/shadow '$1 == u { if ($2 !~ /^!/) $2 = "!" $2; $8 = 1 } { print }' "$1"; fi
}
do_nologin() {
    save_line /etc/passwd "$1"
    _nl=/usr/sbin/nologin; [ -x "$(P /usr/sbin/nologin)" ] || { [ -x "$(P /sbin/nologin)" ] && _nl=/sbin/nologin; } || _nl=/bin/false
    [ -x "$(P "$_nl")" ] || _nl=/usr/sbin/nologin
    if [ -z "$R" ] && cc_have usermod; then usermod -s "$_nl" "$1"
    else edit /etc/passwd "\$1 == u { \$7 = \"$_nl\" } { print }" "$1"; fi
}
do_unadmin() {   # do_unadmin USER ADMIN-GROUPS SUDO-LINES
    save_line /etc/group "$1"; [ -f "$(P /etc/gshadow)" ] && save_line /etc/gshadow "$1"
    for _g in $2; do
        # The primary group cannot be taken away: say so.
        _pg=$(awk -F: -v u="$1" '$1 == u { print $4 }' "$(P /etc/passwd)"); _gg=$(awk -F: -v g="$_g" '$1 == g { print $3 }' "$(P /etc/group)")
        [ "$_pg" = "$_gg" ] && { cc_show "$C_YEL" "    [*] $_g is $1's primary group: not changed (lock the account instead)"; continue; }
        if [ -z "$R" ] && cc_have gpasswd; then gpasswd -d "$1" "$_g" >>"$CC_LOG" 2>&1
        else
            for _gf in /etc/group /etc/gshadow; do [ -f "$(P "$_gf")" ] || continue
                edit "$_gf" "\$1 == \"$_g\" { n = split(\$4, m, \",\"); s = \"\"; for (i = 1; i <= n; i++) if (m[i] != u) s = s (s == \"\" ? \"\" : \",\") m[i]; \$4 = s } { print }" "$1"; done
        fi
    done
    # Its own sudo lines (by name): commented out.
    for _sl in $3; do
        _f=${_sl%:*}; _n=${_sl##*:}
        awk -F'|' -v f="$_f" -v n="$_n" -v u="$1" '$1 == f && $2 == n && $3 == u { x = 1 } END { exit !x }' "$W/sudo" && sudo_comment "$_f" "$_n"
    done
    return 0
}
sudo_comment() {   # sudo_comment FILE LINE -> "# LX-21: " in front, checked by visudo (doas -C for doas)
    _rf=$(P "$1")
    grep -qxF "$_rf" "$W/sbacked" 2>/dev/null || { cc_backup_file "$_rf" >/dev/null || return 1; printf '%s\n' "$_rf" >>"$W/sbacked"; }
    awk -v n="$2" 'NR == n && !/^# LX-21: / { print "# LX-21: " $0; next } { print }' "$_rf" >"$W/sudo.new" || return 1
    case "$1" in /etc/doas*)
        if [ -z "$R" ] && cc_have doas; then
            doas -C "$W/sudo.new" >>"$CC_LOG" 2>&1 || { cc_show "$C_RED" "    [x] doas -C does not accept the change to $1: left as it is"; return 1; }
        fi
        cat "$W/sudo.new" >"$_rf"; return ;;
    esac
    if [ -z "$R" ] && cc_have visudo; then
        _chk=$W/sudo.new; [ "$1" = /etc/sudoers ] || { cp "$(P /etc/sudoers)" "$W/sudo.main"; _chk=$W/sudo.new; }
        visudo -c -f "$_chk" >>"$CC_LOG" 2>&1 || { cc_show "$C_RED" "    [x] visudo does not accept the change to $1: left as it is"; return 1; }
    fi
    cat "$W/sudo.new" >"$_rf"
}
do_keys() {   # do_keys HOME
    for _k in "$1/.ssh/authorized_keys" "$1/.ssh/authorized_keys2"; do
        [ -f "$(P "$_k")" ] && { cc_quarantine "$(P "$_k")" >>"$CC_LOG" 2>&1 || return 1; }
    done
    return 0
}

# ---- Apply --------------------------------------------------------------------------------
header "5/5  apply"
CSV=$(cc_csv_new changes "account,change,result")
NOK=0; NBAD=0; APPLIED=0; TIMER_ON=0
if [ "$NCH" -eq 0 ]; then :
elif [ "$CC_APPLY" != 1 ] || [ "$CANAPPLY" = 0 ]; then
    [ "$CANAPPLY" = 0 ] && cc_show "$C_YEL" "  [!] not root: showing the plan only"
    cc_show "$C_GRY" "  $NCH change(s) planned. Dry run: nothing was changed. Run again with --apply."
    # shellcheck disable=SC2034  # read by cc_finish
    CC_N_WOULD=$NCH
elif cc_ask "Apply these $NCH change(s)?" Y "yes, apply them (a revert timer undoes them unless you confirm from a NEW session)" "no, change nothing"; then
    APPLIED=1
    if [ "$NOTIMER" != 1 ] && [ -z "$R" ]; then cc_timer_start "$TIMER"; TIMER_ON=1
        cc_show "$C_YEL" "  [*] Revert timer started: everything is undone in $((TIMER / 60)):$(printf '%02d' $((TIMER % 60))) unless you keep it from a NEW login."; fi
    : >"$W/sbacked"
    while IFS='|' read -r _u _a _why; do
        [ "$_a" = k ] && continue
        _row=$(awk -F'|' -v u="$_u" '$1 == u' "$W/acc")
        _adm=$(printf '%s' "$_row" | cut -d'|' -f8); _sud=$(printf '%s' "$_row" | cut -d'|' -f9); _home=$(printf '%s' "$_row" | cut -d'|' -f14)
        _ok=0
        case "$_a" in
            l) do_lock "$_u" >>"$CC_LOG" 2>&1 && _ok=1 ;;
            n) do_nologin "$_u" >>"$CC_LOG" 2>&1 && _ok=1 ;;
            d) do_unadmin "$_u" "$_adm" "$_sud" && _ok=1 ;;
            r) do_keys "$_home" && _ok=1 ;;
            b) do_unadmin "$_u" "$_adm" "$_sud" && do_keys "$_home" && _ok=1 ;;
        esac
        if [ "$_ok" = 1 ]; then cc_show "$C_GRN" "  [+] $_u: $(act_word "$_a")"; NOK=$((NOK + 1)); cc_csv_row "$CSV" "$_u" "$(act_word "$_a")" "done"
        else cc_show "$C_RED" "  [x] $_u: $(act_word "$_a") FAILED (log: $CC_LOG)"; NBAD=$((NBAD + 1)); cc_csv_row "$CSV" "$_u" "$(act_word "$_a")" failed; fi
    done <"$W/plan"
    # Lines asked about on their own; line numbers do not move (we only add "# LX-21: ").
    while IFS='|' read -r _f _n _t; do
        if sudo_comment "$_f" "$_n"; then cc_show "$C_GRN" "  [+] commented out $_f line $_n"; NOK=$((NOK + 1)); cc_csv_row "$CSV" "$_f:$_n" "sudo line commented out" "done"
        else NBAD=$((NBAD + 1)); cc_csv_row "$CSV" "$_f:$_n" "sudo line commented out" failed; fi
    done <"$W/splan"
    cc_csv_pretty "$CSV" "$CC_RUN_DIR/changes.txt" 100
else cc_show "$C_GRY" "  Not applied. The plan is in $CC_RUN_DIR/plan.txt"; fi
# shellcheck disable=SC2034  # read by cc_finish
CC_N_DONE=$NOK
# shellcheck disable=SC2034  # read by cc_finish
CC_N_FAIL=$NBAD

# ---- Summary ----------------------------------------------------------------------------
while IFS='|' read -r _u _uid _kind _sh _login _pw _grs _adm _sud _nop _keys _kopt _days _home _fl _lv _def; do
    _dc=$(awk -F'|' -v u="$_u" '$1 == u { print $2 }' "$W/plan"); _dc=$(act_word "${_dc:-k}")
    cc_csv_row "$ACSV" "$_u" "$_uid" "$_kind" "$_sh" "$_pw" "$_grs" "${_adm:--}" "${_sud:--}" "$_nop" "$_keys" "$_days" "$(printf '%s' "$_fl" | sed 's/;$//')" "$_dc"
done <"$W/acc"
cc_csv_pretty "$ACSV" "$CC_RUN_DIR/accounts.txt" 160
{
    printf '==========[ summary ]==========\n'
    printf 'LX-21 Account lockdown | host %s | %s\n' "$CC_HOST" "$([ "$APPLIED" = 1 ] && echo APPLIED || echo 'DRY RUN - nothing changed')"
    printf 'Accounts: %d (%d HIGH, %d MED)   Sudo lines that give root widely: %d\n' "$(grep -c . "$W/acc")" "$(awk -F'|' '$16 == "HIGH"' "$W/acc" | grep -c .)" "$(awk -F'|' '$16 == "MED"' "$W/acc" | grep -c .)" "$(grep -c . "$W/sbad")"
    awk -F'|' '$16 != "ok" { printf "  %-4s %-14s %s\n", $16, $1, $15 }' "$W/acc"
    [ -s "$CC_RUN_DIR/plan.txt" ] && { printf '\nChanges%s:\n' "$([ "$APPLIED" = 1 ] || echo ' planned')"; sed 's/^/  /' "$CC_RUN_DIR/plan.txt"; }
    [ "$APPLIED" = 1 ] && printf 'Done: %d   Failed: %d\n' "$NOK" "$NBAD"
    [ "$APPLIED" = 1 ] && [ -f "$CC_RUN_DIR/revert.sh" ] && printf 'Undo this run: sh %s/revert.sh --force\n' "$CC_RUN_DIR"
    printf '\nAlso: new passwords LX-20; cron, PAM, services and the rest red team plants LX-42; who is logged in now LX-40.\n'
} >"$CC_RUN_DIR/summary.txt"
cc_show "" ""
while IFS= read -r _l; do
    case "$_l" in ==*|LX-21*) cc_show "$C_CYN" "$_l" ;; '  HIGH'*|*'Failed: '[1-9]*) cc_show "$C_RED" "$_l" ;; '  MED'*) cc_show "$C_YEL" "$_l" ;; *) cc_show "" "$_l" ;; esac
done <"$CC_RUN_DIR/summary.txt"
rm -rf "$W"
if [ "$TIMER_ON" = 1 ]; then header "KEEP OR REVERT"; cc_show "$C_YEL" "[*] Before you answer: log in again from a NEW terminal (SSH) and check sudo works."; cc_timer_finish || true; fi
cc_finish
