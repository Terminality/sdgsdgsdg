#!/bin/sh
# =============================================================================
# ID:       LX-20
# NAME:     Linux password rotation
# ROLE:     Linux  (wave 2, first 15 minutes)
# KIND:     changes - dry run unless --apply
# VERSION:  2.0.0
#
# PURPOSE
#   Default and leaked passwords are the red team's first way in.  This:
#     1. gives every account that has a usable password a new random one
#        (root included), skipping accounts on the protected list - the ones
#        the scoring engine logs in with
#     2. with --keep FILE, locks every human account (UID >= UID_MIN, and any
#        extra UID 0 account) that is NOT on the team's list: password locked
#        AND account expired, which also stops SSH key logins
#     3. fixes password hashes hidden in /etc/passwd (where they bypass
#        /etc/shadow) by moving them into /etc/shadow with pwconv
#     4. writes the new passwords to ONE file, mode 600, for the captain -
#        never to the screen (unless --print) or the log
#
# HOW A RUN GOES  (asks like sqlmap; Enter takes the default)
#   1. A revert timer starts (5 minutes, --timer): unless you keep the
#      changes at the end, /etc/shadow and /etc/passwd go back to how they
#      were - old passwords, nothing locked - even if your session died.
#   2. Every account in a table: UID, shell, password state, admin or not,
#      last login, and what it will do by default.  Hidden accounts are
#      flagged: a second UID 0, an empty password, a hash in /etc/passwd, a
#      system account that can log in, an account in only one of passwd and
#      shadow, domain/LDAP accounts.
#   3. "Go through each account?"  Then, per account:
#        [r] random password   [s] set one (typed twice, not shown)
#        [d] disable (locked AND expired: stops SSH keys too)
#        [k] keep              [a] the default for all the rest
#      Protected (scoring) accounts and the account you are logged in as
#      need an extra yes.
#   4. End the sessions of the accounts you disable?  The plan, "Apply?",
#      the changes, then "Keep these changes?" - log in from a NEW session
#      with the new password first.
#   Flags answer the questions in advance; --batch takes every default.
#
# USAGE
#   sudo sh LX-20-password-rotation.sh                         asks, then applies if you say so
#   sudo sh LX-20-password-rotation.sh --apply --batch         defaults, no questions
#   sudo sh LX-20-password-rotation.sh --apply --keep team.txt lock accounts not on the list
#
# OPTIONS
#   --keep FILE        the team's account list, one name per line (# comments).
#                      Human accounts not on it are locked and expired
#   --users a,b        rotate only these accounts (repeatable)
#   --exclude a,b      never touch these accounts (repeatable).  A name in
#                      --users or --exclude that is not an account on this
#                      box STOPS the script before anything changes: a typo
#                      there would rotate the account you meant to keep
#   --ignore-missing   only warn about such names (for one list used on
#                      many boxes)
#   --passwords FILE   use these passwords instead of random ones: lines
#                      "user password" (for a password sheet made in advance;
#                      the old "user,password" lines still work).
#                      Spaces around the name and the password are dropped.
#                      Names not on this box are listed in the summary; an
#                      account that is locked or has no password is NOT
#                      given one (that would unlock it) and is listed too
#   --length N         length of random passwords (default 16)
#   --no-root          do not rotate root's password
#   --include-me       also rotate the account that ran sudo (skipped by
#                      default so you can still use sudo with your password)
#   --kick             also end every running process of a locked account
#   --print            show the new passwords on screen at the end
#   --timer SECONDS    revert timer length (default 300)
#   --no-timer         no revert timer (you accept the risk)
#   --no-color         no colours
#   --batch            never ask: take every default (common option)
#   --root DIR         treat DIR as / when reading passwd, shadow and
#                      login.defs (for the tests; changes still go through
#                      the tools, see BT_CHPASSWD below)
#   --help             this text plus the common options
#
# OUTPUTS  (under --out, one numbered folder per run: passwords-1, -2, ...)
#   output.txt      everything shown on screen (never a password)
#   summary.txt     what was rotated, locked and skipped (no passwords)
#   accounts.txt    every account: uid, shell, password state, what was done
#   revert.sh       undoes this run (sh revert.sh --force)
#   passwords.txt   HOST USER PASSWORD TIME - ONLY with --apply, mode 600.
#                   Give it to the captain, then delete it from this box
#
# WHAT IT CHANGES  (only with --apply)
#   Passwords (chpasswd, or pw on FreeBSD), account lock and expiry (usermod,
#   or pw lock), /etc/passwd and /etc/shadow through pwconv.  /etc/shadow and
#   /etc/passwd are backed up first; the undo log restores them (which also
#   restores the OLD passwords - the backup is how undo works without ever
#   writing a hash into a log).
#
# DEPENDS ON
#   chpasswd and usermod (shadow-utils or busybox) on Linux - without
#   usermod (Alpine) accounts are locked with "passwd -l" only; pw on FreeBSD
#   (reads /etc/master.passwd; NOT yet tried on a real FreeBSD box);
#   pwconv for the hidden-hash fix; /dev/urandom for passwords.
#   BT_CHPASSWD, BT_USERMOD and BT_PWCONV may name stand-in programs
#   (the tests use them so they never touch real accounts).
#
# TESTED ON
#   Ubuntu 24.04 under dash, bash, busybox sh, ksh93, mksh and yash, with
#   stand-in tools on a fake root, plus a live run on throwaway accounts.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - Accounts the scoring engine uses MUST be on the protected list
#     (type account), or scoring breaks.  If a scored password must change,
#     change it through the competition's password-change process.
#   - Samba keeps its own passwords; they are not changed here.  The summary
#     lists Samba accounts when pdbedit is installed.
#   - LDAP / Active Directory / NIS accounts are not in /etc/shadow and are
#     not touched.
#   - Locking does not end sessions already open; use --kick for that.
#
# DEBUGGING
#   --debug shows how each account was classified and why.
#   Passwords are never in the log, even with --debug.
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
LX-20 Linux password rotation - list every account, then rotate, set or disable
  sudo sh LX-20-password-rotation.sh [--apply] [options]     (asks; --batch for none)

  --keep FILE        team account list; human accounts not on it are disabled
  --users a,b        act only on these accounts (repeatable)
  --exclude a,b      never touch these accounts (repeatable)
  --ignore-missing   warn, do not stop, when a name in --users/--exclude is not an account here
  --passwords FILE   "user password" lines to set instead of random passwords
  --length N         random password length (default 16)
  --no-root          leave root's password alone
  --include-me       also rotate the account that ran sudo
  --kick             end running processes of disabled accounts
  --print            show the new passwords on screen at the end
  --timer SECONDS    revert timer length (default 300)
  --no-timer         no revert timer
  --no-color         no colours
  --root DIR         read passwd/shadow under DIR (tests)
  --help             show this text

USAGE
    cc_usage_common
}

KEEP=""; USERS=""; EXCLUDE=""; IGNMISS=0; PWFILE=""; LEN=16; NOROOT=0; INCME=0; KICK=0; PRINT=0; R=""
TIMER=300; NOTIMER=0; F_KICK=0
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --keep)       [ $# -ge 2 ] || cc_die 2 "--keep needs a file"; [ -r "$2" ] || cc_die 2 "--keep: cannot read $2"; KEEP=$2; shift 2 ;;
        --users)      [ $# -ge 2 ] || cc_die 2 "--users needs a list"; USERS="${USERS:+$USERS,}$2"; shift 2 ;;
        --exclude)    [ $# -ge 2 ] || cc_die 2 "--exclude needs a list"; EXCLUDE="${EXCLUDE:+$EXCLUDE,}$2"; shift 2 ;;
        --ignore-missing) IGNMISS=1; shift ;;
        --passwords)  [ $# -ge 2 ] || cc_die 2 "--passwords needs a file"; [ -r "$2" ] || cc_die 2 "--passwords: cannot read $2"; PWFILE=$2; shift 2 ;;
        --length)     [ $# -ge 2 ] || cc_die 2 "--length needs a number"; LEN=$2; shift 2 ;;
        --no-root)    NOROOT=1; shift ;;
        --include-me) INCME=1; shift ;;
        --kick)       KICK=1; F_KICK=1; shift ;;
        --print)      PRINT=1; shift ;;
        --timer)      [ $# -ge 2 ] || cc_die 2 "--timer needs a number of seconds"; TIMER=$2; shift 2 ;;
        --no-timer)   NOTIMER=1; shift ;;
        --no-color|--no-colour)
                      # shellcheck disable=SC2034  # read by cc_color_init in the library
                      CC_NOCOLOR=1; shift ;;
        --root)       [ $# -ge 2 ] || cc_die 2 "--root needs a folder"; [ -d "$2" ] || cc_die 2 "--root: not a folder: $2"
                      R=$(cd "$2" && pwd); [ "$R" = / ] && R=""; shift 2 ;;
        --help|-h)    usage; exit 0 ;;
        *)            cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
case "$LEN" in ''|*[!0-9]*) cc_die 2 "--length needs a whole number" ;; esac
[ "$LEN" -ge 12 ] || cc_die 2 "--length must be at least 12"
case "$TIMER" in ''|*[!0-9]*) cc_die 2 "--timer needs a whole number of seconds" ;; esac
[ "$TIMER" -ge 2 ] || cc_die 2 "--timer must be at least 2 seconds"

cc_color_init
APPLY_FLAG=$CC_APPLY
cc_init "LX-20" "Linux password rotation" changes
cc_detect_os
[ -z "$R" ] && cc_require_root
cc_use_numbered_dir passwords
W="$CC_RUN_DIR/.work"
(umask 077; mkdir -p "$W") || cc_die 3 "cannot create $W"
# The table is built in the work folder and kept only as accounts.txt.
CC_CSV_DIR="$W"
OUTF="$CC_RUN_DIR/output.txt"
grep -v '\[NOTE\]\|\[DEBUG\]' "$CC_LOG" >"$OUTF" 2>/dev/null || : >"$OUTF"
# shellcheck disable=SC2034  # read by cc_show and cc_log in the library
CC_TEE=$OUTF
CSV=$(cc_csv_new accounts "user,uid,shell,password_state,action,note")
PASSWD="$R/etc/passwd"; SHADOW="$R/etc/shadow"
# FreeBSD keeps the hashes in /etc/master.passwd (same place in the line:
# name:hash:...), and pw rebuilds the password database itself.
[ "$CC_OS_KERNEL" = freebsd ] && [ ! -e "$SHADOW" ] && SHADOW="$R/etc/master.passwd"
[ -r "$PASSWD" ] || cc_die 3 "cannot read $PASSWD"
[ -r "$SHADOW" ] || cc_die 3 "cannot read $SHADOW (run as root)"

cc_show "$C_CYN" "LX-20 Linux password rotation | host $CC_HOST | results in $CC_RUN_DIR"
cc_show "" "Legend: ${C_RED}red = hidden or dangerous account${C_OFF}  ${C_GRN}[+] done${C_OFF}  ${C_YEL}[~] will do${C_OFF}  ${C_GRY}[-] kept${C_OFF}"
header() { cc_show "" ""; cc_show "$C_CYN" "==========[ $1 ]=========="; }

# Can this run change anything?  --apply, or someone at the keyboard to say yes.
CANAPPLY=0
if [ "$CC_APPLY" = 1 ] || _cc_can_ask; then CANAPPLY=1; fi
if [ "$CANAPPLY" = 0 ]; then
    cc_show "$C_GRY" "Dry run only (--batch or no terminal, without --apply): nothing will be changed."
elif [ "$NOTIMER" = 1 ]; then
    cc_show "$C_YEL" "[*] No revert timer (--no-timer): if a new password locks you out, nothing puts it back."
else
    cc_timer_start "$TIMER"
    cc_show "$C_YEL" "[*] Revert timer started: unless you keep the changes at the end, every password and lock goes back in $((TIMER / 60)):$(printf '%02d' $((TIMER % 60)))."
fi

# ---- Tools ----------------------------------------------------------------------
# Full paths (cc_which), so busybox sh cannot swap in its built-in versions.
if [ "$CC_OS_KERNEL" = freebsd ] && [ -z "${BT_CHPASSWD:-}" ]; then
    PW=$(cc_which pw) || cc_die 3 "pw not found"
    TOOLS=pw
else
    CHPASSWD=${BT_CHPASSWD:-$(cc_which chpasswd)} || CHPASSWD=""
    USERMOD=${BT_USERMOD:-$(cc_which usermod)} || USERMOD=""
    PWCONV=${BT_PWCONV:-$(cc_which pwconv)} || PWCONV=""
    PASSWD_BIN=$(cc_which passwd) || PASSWD_BIN=""
    [ -n "$CHPASSWD" ] || cc_die 3 "chpasswd not found (install the shadow or passwd package)"
    TOOLS=shadow
fi
cc_debug "tools: $TOOLS chpasswd=${CHPASSWD:-} usermod=${USERMOD:-} pwconv=${PWCONV:-}"

# set_password USER PASSWORD - the password travels on stdin only, never on a
# command line (visible in ps) or in the log.  Called through cc_run_quiet.
set_password() {
    if [ "$TOOLS" = pw ]; then printf '%s\n' "$2" | "$PW" usermod "$1" -h 0
    else printf '%s:%s\n' "$1" "$2" | "$CHPASSWD"; fi
}
# lock_account USER - password locked and account expired (expiry also stops
# SSH key logins, which a locked password alone does not).
lock_account() {
    if [ "$TOOLS" = pw ]; then "$PW" lock "$1"
    elif [ -n "$USERMOD" ]; then "$USERMOD" -L -e 1 "$1"
    # No usermod (Alpine without the shadow package): lock the password only.
    elif [ -n "$PASSWD_BIN" ]; then "$PASSWD_BIN" -l "$1"
    else return 127; fi
}
unlock_cmd() {
    if [ "$TOOLS" = pw ]; then printf '%s unlock %s' "$PW" "$1"
    elif [ -n "$USERMOD" ]; then printf "%s -U %s; %s -e '' %s" "$USERMOD" "$1" "$USERMOD" "$1"
    else printf '%s -u %s' "$PASSWD_BIN" "$1"; fi
}

# ---- Lists ----------------------------------------------------------------------
# inlist NAME "a,b,c" -> true when NAME is in the comma list.
inlist() { case ",$2," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }
: >"$W/keep"
if [ -n "$KEEP" ]; then
    sed 's/#.*//; s/[[:space:]]//g' "$KEEP" | grep . >"$W/keep"
    [ -s "$W/keep" ] || cc_die 2 "--keep file has no names: $KEEP"
fi
onkeep() { grep -qx "$1" "$W/keep"; }
# Passwords given in advance: "user,password" lines.  Checked for characters
# that would break chpasswd's "user:password" input.
: >"$W/given"
if [ -n "$PWFILE" ]; then
    # "user password", or the old "user,password" (name, then a comma).
    awk '/^[ \t]*#/ { next } { l = $0; gsub(/\r/, "", l); sub(/^[ \t]+/, "", l); if (l == "") next
        w = l; sub(/[ \t].*/, "", w)
        if (l ~ /^[^ \t,]+[ \t]*,/) { u = substr(l, 1, index(l, ",") - 1); p = substr(l, index(l, ",") + 1) }
        else { u = w; p = substr(l, length(w) + 1) }
        gsub(/^[ \t]+|[ \t]+$/, "", u); gsub(/^[ \t]+|[ \t]+$/, "", p); if (u == "" || p == "") next
        print u "\t" p }' "$PWFILE" >"$W/given"
    if awk -F'\t' '$2 ~ /:/ || length($2) < 8 { bad = 1 } END { exit !bad }' "$W/given"; then
        cc_die 2 "--passwords: every password must be 8+ characters and contain no ':'"
    fi
fi
given_pw() { awk -F'\t' -v u="$1" '$1 == u { print $2; exit }' "$W/given"; }

UID_MIN=$(awk '$1 == "UID_MIN" { print $2 }' "$R/etc/login.defs" 2>/dev/null)
case "$UID_MIN" in ''|*[!0-9]*) UID_MIN=1000 ;; esac
ME=${SUDO_USER:-}
[ "$ME" = root ] && ME=""

# ---- Classify every account -------------------------------------------------------
# One line per account: user|uid|shell|state|passwd_field
#   state: set (usable hash) | empty (no password at all) | locked | none
# A hash in /etc/passwd itself (field 2 not x) is used INSTEAD of shadow by
# most systems - a known backdoor trick - so that counts too.
awk -F: -v shf="$SHADOW" 'FILENAME == shf { sh[$1] = $2; next }
    { u = $1; pf = $2; s = (u in sh) ? sh[u] : "(missing)"
      if (pf != "x" && pf != "*" && pf !~ /^!/) st = (pf == "" ? "empty" : "set")
      else if (s == "") st = "empty"
      else if (s ~ /^[!*]/ || s == "(missing)") st = (s ~ /^!/ ? "locked" : "none")
      else st = "set"
      print u "|" $3 "|" $7 "|" st "|" pf }' "$SHADOW" "$PASSWD" >"$W/accounts"

# ---- Names given by hand must exist ------------------------------------------
# A misspelled --exclude name would otherwise be ignored without a word and
# the account it was meant to protect would get a new password.
: >"$W/notes"
_missing=""
for _nm in $(printf '%s,%s' "$USERS" "$EXCLUDE" | tr ',' ' '); do
    awk -F'|' -v u="$_nm" '$1 == u { f = 1 } END { exit !f }' "$W/accounts" || _missing="$_missing $_nm"
done
if [ -n "$_missing" ]; then
    if [ "$IGNMISS" = 1 ]; then
        cc_warn "not accounts on this box (ignored because of --ignore-missing):$_missing"
        printf 'NOTE|named in --users/--exclude but not an account here:%s\n' "$_missing" >>"$W/notes"
    else
        rm -rf "$W"
        cc_timer_cancel
        cc_die 2 "no such account on this box:$_missing (named in --users or --exclude). Nothing was changed. Fix the spelling, or add --ignore-missing"
    fi
fi
# The same check for the password sheet, as notes: one sheet often covers
# many boxes, so a name missing here is normal - but worth seeing.
awk -F'\t' -v af="$W/accounts" 'BEGIN { while ((getline l < af) > 0) { split(l, a, "|"); st[a[1]] = a[4] } }
    !($1 in st) { print "NOTE|" $1 " is in --passwords but is not an account here"; next }
    st[$1] != "set" && st[$1] != "empty" { print "NOTE|" $1 " is in --passwords but has no usable password (" st[$1] "): NOT set, which would unlock it. Unlock it first if you want it" }' "$W/given" >>"$W/notes"

# login_shell SHELL -> true if SHELL lets someone log in.
login_shell() {
    case "$(basename "${1:-/bin/sh}")" in
        nologin|false|sync|shutdown|halt|git-shell) return 1 ;;
        *) return 0 ;;
    esac
}

# ---- Defaults: what happens to each account unless you say otherwise ----------
# Action letters: r random, s set (from the sheet or typed), d disable, k keep.
# One line per account in $W/plan: user|uid|shell|state|action|why|flags
#   flags: words for the table - uid0 empty inpasswd syslogin noshadow admin
_admins=$(awk -F: '$1 ~ /^(sudo|wheel|admin|root)$/ { print $4 }' "$R/etc/group" 2>/dev/null | tr ',' ' ')
: >"$W/plan"
while IFS='|' read -r _u _uid _sh _st _pf; do
    [ -n "$_u" ] || continue
    _human=0
    { [ "$_uid" -ge "$UID_MIN" ] 2>/dev/null && [ "$_uid" -lt 60000 ]; } && _human=1
    [ "$_uid" = 0 ] && [ "$_u" != root ] && _human=1
    _fl=""
    [ "$_uid" = 0 ] && [ "$_u" != root ] && _fl="$_fl uid0"
    [ "$_st" = empty ] && _fl="$_fl empty"
    case "$_pf" in x|'*'|!*) ;; *) _fl="$_fl inpasswd" ;; esac
    [ "$_human" = 0 ] && [ "$_u" != root ] && [ "$_st" = set ] && login_shell "$_sh" && _fl="$_fl syslogin"
    grep -q "^$_u:" "$SHADOW" 2>/dev/null || _fl="$_fl noshadow"
    { [ "$_uid" = 0 ] || case " $_admins " in *" $_u "*) true ;; *) false ;; esac; } && _fl="$_fl admin"
    [ "$_st" = empty ] && printf 'HIGH|%s has NO password: anyone can log in as it\n' "$_u" >>"$W/notes"
    [ "$_uid" = 0 ] && [ "$_u" != root ] && printf 'HIGH|%s has UID 0: it IS root under another name\n' "$_u" >>"$W/notes"

    _a=k; _why=""
    if inlist "$_u" "$EXCLUDE"; then _why="--exclude"
    elif [ -n "$USERS" ] && ! inlist "$_u" "$USERS"; then _why="not in --users"
    elif [ "$_uid" = 0 ] && [ "$_u" != root ]; then _a=d; _why="extra UID 0 account (root under another name)"
    elif [ -n "$KEEP" ] && [ "$_human" = 1 ] && [ "$_u" != root ] && ! onkeep "$_u"; then _a=d; _why="not on the team list"
    elif [ "$_st" != set ] && [ "$_st" != empty ]; then _why="no usable password ($_st)"
    elif [ "$_u" = root ] && [ "$NOROOT" = 1 ]; then _why="--no-root"
    elif [ -n "$ME" ] && [ "$_u" = "$ME" ] && [ "$INCME" = 0 ]; then _why="you are logged in as it (--include-me)"
    elif [ -n "$(given_pw "$_u")" ]; then _a=s; _why="from --passwords"
    else _a=r; _why="random"
    fi
    if { [ "$_a" = r ] || [ "$_a" = s ]; } && ! login_shell "$_sh"; then
        _why="$_why; service account (no login shell) - check no service logs in with the old password"
    fi
    printf '%s|%s|%s|%s|%s|%s|%s\n' "$_u" "$_uid" "$_sh" "$_st" "$_a" "$_why" "$_fl" >>"$W/plan"
done <"$W/accounts"
# Domain / LDAP / NIS accounts the system knows but /etc/passwd does not.
if [ -z "$R" ] && cc_have getent; then
    getent passwd 2>/dev/null | cut -d: -f1 | while IFS= read -r _g; do
        grep -q "^$_g:" "$PASSWD" || printf '%s\n' "$_g"
    done >"$W/remote"
    [ -s "$W/remote" ] && printf 'NOTE|accounts from LDAP, the domain or NIS (not changed here; change them where they live): %s\n' "$(tr '\n' ' ' <"$W/remote")" >>"$W/notes"
fi
# Accounts in shadow but not passwd: a leftover or a planted entry.
awk -F: 'NR == FNR { p[$1] = 1; next } !($1 in p) { print $1 }' "$PASSWD" "$SHADOW" >"$W/onlyshadow"
[ -s "$W/onlyshadow" ] && printf 'HIGH|in /etc/shadow but not /etc/passwd: %s\n' "$(tr '\n' ' ' <"$W/onlyshadow")" >>"$W/notes"

# lastlog_of USER -> last login, short ("never" or a date), when lastlog works.
lastlog_of() {
    [ -z "$R" ] && cc_have lastlog || return 0
    lastlog -u "$1" 2>/dev/null | awk 'NR == 2 { if ($0 ~ /Never logged in/) print "never"; else print $(NF-5) " " $(NF-4) " " $(NF-3) }'
}
act_word() { case "$1" in r) echo random ;; s) echo set ;; d) echo disable ;; *) echo keep ;; esac; }

# show_table -> the account table with the current plan.
show_table() {
    cc_show "$C_CYN" "$(printf '  %-16s %6s  %-18s %-7s %-12s %-8s %s' USER UID SHELL PASSWORD "LAST LOGIN" ACTION "NOTES")"
    while IFS='|' read -r _u _uid _sh _st _a _why _fl; do
        _col=""; _note=$_why
        case "$_fl" in *uid0*|*empty*|*inpasswd*|*noshadow*|*syslogin*) _col=$C_RED ;; esac
        case "$_fl" in *uid0*) _note="UID 0 = ROOT; $_note" ;; esac
        case "$_fl" in *inpasswd*) _note="hash in /etc/passwd; $_note" ;; esac
        case "$_fl" in *syslogin*) _note="system account that can log in; $_note" ;; esac
        case "$_fl" in *noshadow*) _note="not in /etc/shadow; $_note" ;; esac
        case "$_fl" in *admin*) _note="admin; $_note" ;; esac
        if [ -z "$_col" ]; then case "$_a" in k) _col=$C_GRY ;; *) _col="" ;; esac; fi
        cc_show "$_col" "$(printf '  %-16s %6s  %-18s %-7s %-12s %-8s %s' "$_u" "$_uid" "$(basename "$_sh")" "$_st" "$(lastlog_of "$_u")" "$(act_word "$_a")" "$_note")"
    done <"$W/plan"
}

header "ACCOUNTS (every account in /etc/passwd)"
# Quiet ones in one line: no password and no login shell, nothing will change.
awk -F'|' '$5 == "k" && $4 != "set" && $4 != "empty" && $7 == "" { print }' "$W/plan" >"$W/quiet"
awk -F'|' '!($5 == "k" && $4 != "set" && $4 != "empty" && $7 == "") { print }' "$W/plan" >"$W/loud"
cp "$W/plan" "$W/plan.all"; cp "$W/loud" "$W/plan"
show_table
cp "$W/plan.all" "$W/plan"
_nq=$(grep -c . "$W/quiet")
[ -s "$W/quiet" ] && cc_show "$C_GRY" "  [-] $_nq system accounts with no password are kept: $(cut -d'|' -f1 "$W/quiet" | head -n 15 | tr '\n' ' ')$([ "$_nq" -gt 15 ] && echo "+$((_nq - 15)) more")"
if [ -s "$W/notes" ]; then
    while IFS='|' read -r _lv _tx; do
        case "$_lv" in HIGH) cc_show "$C_RED" "  [!] $_tx" ;; *) cc_show "$C_YEL" "  [*] $_tx" ;; esac
    done <"$W/notes"
fi

# ---- Questions ---------------------------------------------------------------------
# read_secret VAR PROMPT -> read a password from the terminal without echo.
#   Never logged, never in output.txt.
read_secret() {
    printf '%s' "$2" >/dev/tty
    stty -echo </dev/tty 2>/dev/null
    _cc_read "$1"; _rs_rc=$?
    stty echo </dev/tty 2>/dev/null
    printf '\n' >/dev/tty
    return "$_rs_rc"
}
# ask_password USER -> a typed password, entered twice, in TYPED (or empty).
ask_password() {
    TYPED=""
    while :; do
        read_secret _p1 "    New password for $1 (not shown): " || return 1
        read_secret _p2 "    Same password again: " || return 1
        if [ "$_p1" != "$_p2" ]; then printf '    They do not match. Again.\n' >/dev/tty; continue; fi
        case "$_p1" in *:*) printf '    No ":" please (it breaks chpasswd). Again.\n' >/dev/tty; continue ;; esac
        if [ "${#_p1}" -lt 8 ]; then printf '    At least 8 characters. Again.\n' >/dev/tty; continue; fi
        TYPED=$_p1; _p1=""; _p2=""
        return 0
    done
}
# set_plan USER ACTION WHY -> change one account's line in the plan.
set_plan() {
    awk -F'|' -v OFS='|' -v u="$1" -v a="$2" -v w="$3" '$1 == u { $5 = a; $6 = w } { print }' "$W/plan" >"$W/plan.t" && mv "$W/plan.t" "$W/plan"
}
# Typed passwords live only in this run's private work folder (mode 700),
# which is deleted at the end.
: >"$W/typed"; chmod 600 "$W/typed"

FORCED=""
header "QUESTIONS (Enter = the default in capitals)"
if [ "$CANAPPLY" = 1 ] && _cc_can_ask && cc_ask "Go through each account one by one?" Y "yes, ask me about each account" "no, use the actions in the table"; then
    _all=0
    cp "$W/loud" "$W/ask"
    while IFS='|' read -r _u _uid _sh _st _a0 _why0 _fl; do
        _a=$(awk -F'|' -v u="$_u" '$1 == u { print $5 }' "$W/plan")
        [ "$_all" = 1 ] && continue
        case "$_a" in r) _h="R/s/d/k/a" ;; s) _h="r/S/d/k/a" ;; d) _h="r/s/D/k/a" ;; *) _h="r/s/d/K/a" ;; esac
        while :; do
            printf '%s[?]%s %s (uid %s, %s, %s): [r]andom [s]et [d]isable [k]eep [a]ll the rest default  [%s]%s ' \
                "$C_CYN" "$C_OFF" "$_u" "$_uid" "$(basename "$_sh")" "$_st" "$_h" "$(_cc_left_txt)" >/dev/tty
            _cc_read _ans || { printf '\n' >/dev/tty; [ "$CC_TIMER_DEADLINE" -gt 0 ] && [ "$(cc_timer_left)" -eq 0 ] && cc_die 3 "the revert timer ran out while waiting for an answer. Nothing was changed. Run again (--timer gives more time)"; _ans=""; }
            case "$_ans" in ''|r|R|s|S|d|D|k|K|a|A) break ;; *) printf '    answer r, s, d, k or a\n' >/dev/tty ;; esac
        done
        _ans=$(printf '%s' "${_ans:-$_a}" | tr 'RSDKA' 'rsdka')
        [ -n "$CC_TEE" ] && printf '[?] %s: %s\n' "$_u" "$(act_word "$_ans")" >>"$CC_TEE"
        if [ "$_ans" = a ]; then _all=1; continue; fi
        # Extra yes for the account in use and for protected accounts.  A yes
        # for a protected account counts for that account only (FORCED).
        if [ "$_ans" != k ]; then
            if [ -n "$ME" ] && [ "$_u" = "$ME" ]; then
                cc_ask "  $_u is the account you are logged in as. Change it anyway?" N "yes, change it" "no, keep it" || { set_plan "$_u" k "you said keep"; continue; }
            fi
            if cc_is_protected account "$_u"; then
                if cc_ask "  $_u is on the protected list (scoring may log in as it). Change it anyway?" N "yes, change it (report the new password to scoring)" "no, keep it"; then
                    FORCED="$FORCED,$_u"
                else set_plan "$_u" k "protected"; continue; fi
            fi
        fi
        case "$_ans" in
            r) set_plan "$_u" r "random (you chose)" ;;
            d) set_plan "$_u" d "disable (you chose)" ;;
            k) set_plan "$_u" k "you said keep" ;;
            s) if [ -n "$(given_pw "$_u")" ] && cc_ask "  Use the password from --passwords for $_u?" Y "yes, use it" "no, I will type one"; then
                   set_plan "$_u" s "from --passwords"
               elif ask_password "$_u"; then
                   printf '%s\t%s\n' "$_u" "$TYPED" >>"$W/typed"; TYPED=""
                   set_plan "$_u" s "typed"
               else set_plan "$_u" k "no password typed"; fi ;;
        esac
    done <"$W/ask"
fi
# End the sessions of disabled accounts?  A lock does not end a login in progress.
if awk -F'|' '$5 == "d" { f = 1 } END { exit !f }' "$W/plan" && [ "$F_KICK" = 0 ] && cc_have pkill; then
    cc_ask "End the running sessions and processes of the accounts you disable?" Y "yes, log them out and stop their processes" "no, leave them running" && KICK=1
fi

# ---- Plan, then apply ------------------------------------------------------------
header "PLAN"
NCH=0
while IFS='|' read -r _u _uid _sh _st _a _why _fl; do
    case "$_a" in
        r|s|d) NCH=$((NCH + 1)); cc_show "$C_YEL" "  [~] $(act_word "$_a") $_u  ($_why)" ;;
    esac
done <"$W/plan"
[ "$NCH" -eq 0 ] && cc_show "$C_GRN" "  [ok] Nothing to change."

# Back up shadow and passwd ONCE, before the first change: the backup is the
# undo log's way back (and the revert timer's).  A second backup in the same
# run would overwrite the first copy with an already-changed file.
_backed=0
backup_once() {
    [ "$_backed" = 1 ] && return 0
    # FreeBSD: after the undo log copies master.passwd back, the password
    # database must be rebuilt.  Added first, so it runs last (bottom-up).
    case "$SHADOW" in */master.passwd) cc_undo_add "rebuild the password database" "pwd_mkdb -p $(cc_shquote "$SHADOW")" ;; esac
    cc_backup_file "$SHADOW" || return 1
    cc_backup_file "$PASSWD" || return 1
    _backed=1
}
row() { cc_csv_row "$CSV" "$1" "$2" "$3" "$4" "$5" "$6"; }
PWOUT="$CC_RUN_DIR/passwords.txt"
N_ROT=0; N_LOCK=0; N_SKIP=0; N_FAIL=0
: >"$W/show"
APPLIED=0
if [ "$NCH" -gt 0 ] && [ "$CANAPPLY" = 1 ]; then
    _ad=N; [ "$APPLY_FLAG" = 1 ] && _ad=Y
    if cc_ask "Apply these $NCH change(s)?" "$_ad" "yes, apply them now" "no, change nothing"; then
        if [ "$APPLY_FLAG" = 0 ] && [ -z "$CC_PROTECTED" ] && [ "$CC_NO_PROTECTED" != 1 ]; then
            cc_show "$C_YEL" "[*] No protected list (the accounts scoring logs in with)."
            if cc_ask "Change passwords without one?" N "yes, go on without a protected list" "no, stop"; then CC_NO_PROTECTED=1; CC_APPLY=1
            else cc_show "$C_YEL" "[*] Not applied."; fi
        else CC_APPLY=1; fi
        if [ "$CC_APPLY" = 1 ] && { cc_timer_fired || { [ "$CC_TIMER_DEADLINE" -gt 0 ] && [ "$(cc_timer_left)" -lt 3 ]; }; }; then
            cc_die 3 "the revert timer ran out before anything was changed. Nothing was changed. Run again (--timer gives more time)"
        fi
    fi
elif [ "$NCH" -gt 0 ]; then
    cc_show "$C_GRY" "$NCH change(s) planned. Dry run only, so nothing was changed."
fi
[ "$CC_APPLY" = 1 ] && { APPLIED=1; header "APPLYING"; }

# ---- Hashes hidden in /etc/passwd ------------------------------------------------
if [ "$CC_APPLY" = 1 ] && awk -F'|' '$5 != "x" && $5 != "*" && $5 !~ /^!/ { f = 1 } END { exit !f }' "$W/accounts"; then
    if [ -z "$PWCONV" ]; then
        cc_show "$C_RED" "  [x] pwconv not found: fix /etc/passwd by hand (set field 2 to x)"
    elif cc_guard path /etc/passwd; then
        backup_once && cc_run "move password hashes from /etc/passwd into /etc/shadow (pwconv)" "$PWCONV" \
            && cc_show "$C_GRN" "  [+] password hashes moved from /etc/passwd into /etc/shadow"
    fi
fi

_q=$CC_QUIET; CC_QUIET=1
while IFS='|' read -r _u _uid _sh _st _a _why _fl; do
    [ -n "$_u" ] || continue
    case "$_a" in
        k)  case "$_why" in "no usable password"*) ;; *) row "$_u" "$_uid" "$_sh" "$_st" kept "$_why" ;; esac
            continue ;;
        d)  if ! inlist "$_u" "$FORCED" && ! cc_guard account "$_u"; then row "$_u" "$_uid" "$_sh" "$_st" "skipped (protected)" "$_why"; N_SKIP=$((N_SKIP + 1)); continue; fi
            if [ "$CC_APPLY" = 1 ]; then
                backup_once || { row "$_u" "$_uid" "$_sh" "$_st" failed "backup failed"; continue; }
                cc_run "lock and expire account $_u ($_why)" lock_account "$_u"
                if [ $? -eq 0 ]; then
                    cc_undo_add "unlock $_u" "$(unlock_cmd "$_u")"
                    N_LOCK=$((N_LOCK + 1)); row "$_u" "$_uid" "$_sh" "$_st" locked "$_why"
                    cc_show "$C_GRN" "  [+] disabled $_u (locked and expired)"
                    if [ "$KICK" = 1 ] && cc_have pkill && [ -z "$R" ]; then
                        cc_run "end running processes of $_u" pkill -KILL -u "$_u" && cc_show "$C_GRN" "  [+] ended the sessions of $_u"
                    fi
                else N_FAIL=$((N_FAIL + 1)); row "$_u" "$_uid" "$_sh" "$_st" failed "$_why"; cc_show "$C_RED" "  [x] FAILED to disable $_u"; fi
            else
                N_LOCK=$((N_LOCK + 1)); row "$_u" "$_uid" "$_sh" "$_st" "would lock" "$_why"
            fi
            continue ;;
    esac
    # r or s: a new password.
    if ! inlist "$_u" "$FORCED" && ! cc_guard account "$_u"; then
        row "$_u" "$_uid" "$_sh" "$_st" "skipped (protected)" "on the protected list"
        N_SKIP=$((N_SKIP + 1)); continue
    fi
    _pw=""
    if [ "$_a" = s ]; then
        _pw=$(awk -F'\t' -v u="$_u" '$1 == u { p = $2 } END { print p }' "$W/typed")
        [ -n "$_pw" ] || _pw=$(given_pw "$_u")
    fi
    [ -n "$_pw" ] || _pw=$(cc_genpass "$LEN") || { row "$_u" "$_uid" "$_sh" "$_st" failed "no random password"; continue; }
    if [ "$CC_APPLY" != 1 ]; then
        row "$_u" "$_uid" "$_sh" "$_st" "would rotate" "$_why"; N_ROT=$((N_ROT + 1)); _pw=""; continue
    fi
    backup_once || { row "$_u" "$_uid" "$_sh" "$_st" failed "backup failed"; continue; }
    cc_run_quiet "new password for $_u" set_password "$_u" "$_pw"
    if [ $? -ne 0 ]; then
        row "$_u" "$_uid" "$_sh" "$_st" failed "$_why"; N_FAIL=$((N_FAIL + 1)); cc_show "$C_RED" "  [x] FAILED to change the password of $_u"
    else
        if [ ! -f "$PWOUT" ]; then
            (umask 077; printf '%-16s %-16s %-24s %s\n' HOST USER PASSWORD TIME >"$PWOUT")
            # If the run is undone, the passwords in this file are no longer
            # the real ones: the undo renames it so nobody hands it out.
            cc_undo_add "mark the passwords file as no longer valid" "mv $(cc_shquote "$PWOUT") $(cc_shquote "$CC_RUN_DIR/passwords-UNDONE-not-valid.txt")"
        fi
        printf '%-16s %-16s %-24s %s\n' "$CC_HOST" "$_u" "$_pw" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$PWOUT"
        [ "$PRINT" = 1 ] && printf '%s:%s\n' "$_u" "$_pw" >>"$W/show"
        row "$_u" "$_uid" "$_sh" "$_st" rotated "$_why"; N_ROT=$((N_ROT + 1))
        cc_show "$C_GRN" "  [+] new password for $_u ($_why)"
    fi
    _pw=""
done <"$W/plan"
CC_QUIET=$_q
: >"$W/typed"

# Samba keeps separate passwords; list its accounts so nobody assumes they changed.
if [ -z "$R" ] && cc_have pdbedit; then
    pdbedit -L 2>/dev/null | cut -d: -f1 | grep . >"$W/samba"
    [ -s "$W/samba" ] && printf 'NOTE|Samba accounts with their own (unchanged) passwords: %s - use smbpasswd if they must change\n' "$(tr '\n' ' ' <"$W/samba")" >>"$W/notes"
fi
if [ "$N_LOCK" -gt 0 ] && [ "$TOOLS" = shadow ] && [ -z "$USERMOD" ]; then
    printf 'NOTE|usermod not found: accounts were locked with "passwd -l" only, which does NOT stop SSH key logins - remove their keys (LX-22)\n' >>"$W/notes"
fi
if [ -z "$KEEP" ]; then
    # Only accounts someone can log in to: a usable (or empty) password.
    # Locked build accounts (nixbld1..32 and the like) are not worth a note.
    awk -F'|' -v m="$UID_MIN" '($2 >= m && $2 < 60000) && ($4 == "set" || $4 == "empty") && $5 != "d" { print $1 }' "$W/plan" >"$W/humans"
    [ -s "$W/humans" ] && printf 'NOTE|human accounts not disabled: %s (check each one is the team'"'"'s)\n' "$(tr '\n' ' ' <"$W/humans")" >>"$W/notes"
fi

# ---- Summary ------------------------------------------------------------------------
{
    printf 'LX-20 Linux password rotation | host %s | %s | %s\n\n' "$CC_HOST" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$([ "$CC_APPLY" = 1 ] && echo APPLIED || echo 'DRY RUN - nothing changed')"
    if [ "$CC_APPLY" = 1 ]; then
        printf 'Rotated: %d   Locked: %d   Skipped (protected): %d   Failed: %d\n\n' "$N_ROT" "$N_LOCK" "$N_SKIP" "$N_FAIL"
    else
        printf 'Would rotate: %d   Would lock: %d   Skipped (protected): %d\n\n' "$N_ROT" "$N_LOCK" "$N_SKIP"
    fi
    awk "$CC_AWK_CSV"'NR > 1 { csvsplit($0, f); printf "  %-16s %-6s %-20s %-8s %s\n", f[1], f[2], f[5], f[4], f[6] }' "$CSV"
    if [ -s "$W/notes" ]; then
        printf '\n'
        awk -F'|' '{ printf "  %-5s %s\n", $1, $2 }' "$W/notes"
    fi
    printf '\n'
    if [ -f "$PWOUT" ]; then
        printf 'New passwords: %s (mode 600)\n' "$PWOUT"
        printf '  Give them to the captain, then remove the file from this box:  rm %s\n' "$PWOUT"
        printf '%s\n' '[!] SCORED ACCOUNTS: submit each new password in the scoring engine (Quotient: password change request) NOW - until then its checks use the old one and fail.'
    elif [ "$CC_APPLY" != 1 ]; then
        printf 'Nothing was changed.\n'
    fi
    [ "$CC_APPLY" = 1 ] && [ "$CC_N_DONE" -gt 0 ] && printf 'Undo: sh %s/revert.sh --force (old passwords back), or %s\n' "$CC_RUN_DIR" "$CC_UNDO"
    printf 'All results: %s\n' "$CC_RUN_DIR"
} >"$CC_RUN_DIR/summary.txt"
cc_csv_pretty "$CSV" "$CC_RUN_DIR/accounts.txt" 80
header "SUMMARY"
awk -v R="$C_RED" -v Y="$C_YEL" -v G="$C_GRN" -v C="$C_CYN" -v D="$C_GRY" -v O="$C_OFF" '
    NR == 1                        { print C $0 O; next }
    /^  HIGH/ || / failed / || /Failed: [1-9]/ || /^\[!\] SCORED/ { print R $0 O; next }
    / rotated / || / locked /      { print G $0 O; next }
    /^  NOTE/ || /would/ || /^New passwords/ || /^  Give/ || /^  then remove/ { print Y $0 O; next }
    /^$/                           { print; next }
                                   { print D $0 O }
' "$CC_RUN_DIR/summary.txt"
cat "$CC_RUN_DIR/summary.txt" >>"$OUTF"
if [ "$PRINT" = 1 ] && [ -s "$W/show" ]; then
    # On screen only: never in output.txt or the log.
    printf '\nNew passwords (also in %s):\n' "$PWOUT"
    sed 's/^/  /' "$W/show"
fi
rm -rf "$W"
if [ "$APPLIED" = 1 ]; then
    header "KEEP OR REVERT"
    cc_show "$C_YEL" "[*] Before you answer: open a NEW SSH or console session and log in with the new password."
    cc_timer_finish
elif [ -n "$CC_TIMER_DIR" ]; then
    cc_timer_cancel; : >"$CC_TIMER_DIR/KEEP"
fi
cc_finish
