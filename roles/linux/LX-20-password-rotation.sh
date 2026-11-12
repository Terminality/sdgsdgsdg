#!/bin/sh
# =============================================================================
# ID:       LX-20
# NAME:     Linux password rotation
# ROLE:     Linux  (wave 2, first 15 minutes)
# KIND:     changes - dry run unless --apply
# VERSION:  1.0.0
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
# USAGE
#   sudo sh LX-20-password-rotation.sh                         dry run
#   sudo sh LX-20-password-rotation.sh --apply                 rotate every usable password
#   sudo sh LX-20-password-rotation.sh --apply --keep team.txt lock accounts not on the list
#
# OPTIONS
#   --keep FILE        the team's account list, one name per line (# comments).
#                      Human accounts not on it are locked and expired
#   --users a,b        rotate only these accounts
#   --exclude a,b      never touch these accounts
#   --passwords FILE   use these passwords instead of random ones: CSV lines
#                      "user,password" (for a password sheet made in advance)
#   --length N         length of random passwords (default 16)
#   --no-root          do not rotate root's password
#   --include-me       also rotate the account that ran sudo (skipped by
#                      default so you can still use sudo with your password)
#   --kick             also end every running process of a locked account
#   --print            show the new passwords on screen at the end
#   --root DIR         treat DIR as / when reading passwd, shadow and
#                      login.defs (for the tests; changes still go through
#                      the tools, see CCDC_CHPASSWD below)
#   --help             this text plus the common options
#
# OUTPUTS  (under --out, in LX-20_<host>_<UTC time>/)
#   summary.txt     what was rotated, locked and skipped (no passwords)
#   accounts.csv    user,uid,shell,password_state,action,note (no passwords)
#   passwords.csv   host,user,password,time - ONLY with --apply, mode 600.
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
#   chpasswd and usermod (shadow-utils or busybox) on Linux; pw on FreeBSD;
#   pwconv for the hidden-hash fix; /dev/urandom for passwords.
#   CCDC_CHPASSWD, CCDC_USERMOD and CCDC_PWCONV may name stand-in programs
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
LX-20 Linux password rotation - new passwords for every usable account
  sudo sh LX-20-password-rotation.sh [--apply] [options]

  --keep FILE        team account list; human accounts not on it are locked
  --users a,b        rotate only these accounts
  --exclude a,b      never touch these accounts
  --passwords FILE   "user,password" lines to use instead of random passwords
  --length N         random password length (default 16)
  --no-root          leave root's password alone
  --include-me       also rotate the account that ran sudo
  --kick             end running processes of locked accounts
  --print            show the new passwords on screen at the end
  --root DIR         read passwd/shadow under DIR (tests)
  --help             show this text

USAGE
    cc_usage_common
}

KEEP=""; USERS=""; EXCLUDE=""; PWFILE=""; LEN=16; NOROOT=0; INCME=0; KICK=0; PRINT=0; R=""
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --keep)       [ $# -ge 2 ] || cc_die 2 "--keep needs a file"; [ -r "$2" ] || cc_die 2 "--keep: cannot read $2"; KEEP=$2; shift 2 ;;
        --users)      [ $# -ge 2 ] || cc_die 2 "--users needs a list"; USERS=$2; shift 2 ;;
        --exclude)    [ $# -ge 2 ] || cc_die 2 "--exclude needs a list"; EXCLUDE=$2; shift 2 ;;
        --passwords)  [ $# -ge 2 ] || cc_die 2 "--passwords needs a file"; [ -r "$2" ] || cc_die 2 "--passwords: cannot read $2"; PWFILE=$2; shift 2 ;;
        --length)     [ $# -ge 2 ] || cc_die 2 "--length needs a number"; LEN=$2; shift 2 ;;
        --no-root)    NOROOT=1; shift ;;
        --include-me) INCME=1; shift ;;
        --kick)       KICK=1; shift ;;
        --print)      PRINT=1; shift ;;
        --root)       [ $# -ge 2 ] || cc_die 2 "--root needs a folder"; [ -d "$2" ] || cc_die 2 "--root: not a folder: $2"
                      R=$(cd "$2" && pwd); [ "$R" = / ] && R=""; shift 2 ;;
        --help|-h)    usage; exit 0 ;;
        *)            cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
case "$LEN" in ''|*[!0-9]*) cc_die 2 "--length needs a whole number" ;; esac
[ "$LEN" -ge 12 ] || cc_die 2 "--length must be at least 12"

cc_init "LX-20" "Linux password rotation" changes
cc_detect_os
[ -z "$R" ] && cc_require_root
cc_use_run_dir
W="$CC_RUN_DIR/.work"
(umask 077; mkdir -p "$W") || cc_die 3 "cannot create $W"
CSV=$(cc_csv_new accounts "user,uid,shell,password_state,action,note")
PASSWD="$R/etc/passwd"; SHADOW="$R/etc/shadow"
[ -r "$PASSWD" ] || cc_die 3 "cannot read $PASSWD"
[ -r "$SHADOW" ] || cc_die 3 "cannot read $SHADOW (run as root)"

# ---- Tools ----------------------------------------------------------------------
# Full paths (cc_which), so busybox sh cannot swap in its built-in versions.
if [ "$CC_OS_KERNEL" = freebsd ] && [ -z "${CCDC_CHPASSWD:-}" ]; then
    PW=$(cc_which pw) || cc_die 3 "pw not found"
    TOOLS=pw
else
    CHPASSWD=${CCDC_CHPASSWD:-$(cc_which chpasswd)} || CHPASSWD=""
    USERMOD=${CCDC_USERMOD:-$(cc_which usermod)} || USERMOD=""
    PWCONV=${CCDC_PWCONV:-$(cc_which pwconv)} || PWCONV=""
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
    else "$USERMOD" -L -e 1 "$1"; fi
}
unlock_cmd() {
    if [ "$TOOLS" = pw ]; then printf '%s unlock %s' "$PW" "$1"
    else printf "%s -U %s; %s -e '' %s" "$USERMOD" "$1" "$USERMOD" "$1"; fi
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
    awk -F',' '/^[ \t]*#/ || NF < 2 { next } { u = $1; p = substr($0, length($1) + 2); gsub(/\r/, "", p); gsub(/^[ \t]+|[ \t]+$/, "", u); print u "\t" p }' "$PWFILE" >"$W/given"
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
awk -F: 'NR == FNR { sh[$1] = $2; next }
    { u = $1; pf = $2; s = (u in sh) ? sh[u] : "(missing)"
      if (pf != "x" && pf != "*" && pf !~ /^!/) st = (pf == "" ? "empty" : "set")
      else if (s == "") st = "empty"
      else if (s ~ /^[!*]/ || s == "(missing)") st = (s ~ /^!/ ? "locked" : "none")
      else st = "set"
      print u "|" $3 "|" $7 "|" st "|" pf }' "$SHADOW" "$PASSWD" >"$W/accounts"

# login_shell SHELL -> true if SHELL lets someone log in.
login_shell() {
    case "$(basename "${1:-/bin/sh}")" in
        nologin|false|sync|shutdown|halt|git-shell) return 1 ;;
        *) return 0 ;;
    esac
}

# Back up shadow and passwd ONCE, before the first change: the backup is the
# undo log's way back.  A second backup in the same run would overwrite the
# first copy with an already-changed file.
_backed=0
backup_once() {
    [ "$_backed" = 1 ] && return 0
    cc_backup_file "$SHADOW" || return 1
    cc_backup_file "$PASSWD" || return 1
    _backed=1
}

# ---- Hashes hidden in /etc/passwd ------------------------------------------------
if awk -F'|' '$5 != "x" && $5 != "*" && $5 !~ /^!/ { f = 1 } END { exit !f }' "$W/accounts"; then
    awk -F'|' '$5 != "x" && $5 != "*" && $5 !~ /^!/ { print $1 }' "$W/accounts" >"$W/inpasswd"
    cc_warn "password hash or empty password in /etc/passwd itself (bypasses /etc/shadow): $(tr '\n' ' ' <"$W/inpasswd")"
    if [ -z "$PWCONV" ]; then
        cc_err "pwconv not found: fix /etc/passwd by hand (set field 2 to x)"
    elif cc_guard path /etc/passwd; then
        backup_once && cc_run "move password hashes from /etc/passwd into /etc/shadow (pwconv)" "$PWCONV"
    fi
fi

# ---- Decide and act --------------------------------------------------------------
row() { cc_csv_row "$CSV" "$1" "$2" "$3" "$4" "$5" "$6"; }
PWOUT="$CC_RUN_DIR/passwords.csv"
N_ROT=0; N_LOCK=0; N_SKIP=0; N_FAIL=0
: >"$W/show"; : >"$W/notes"

while IFS='|' read -r _u _uid _sh _st _pf; do
    [ -n "$_u" ] || continue
    _human=0
    { [ "$_uid" -ge "$UID_MIN" ] 2>/dev/null && [ "$_uid" -lt 60000 ]; } && _human=1
    [ "$_uid" = 0 ] && [ "$_u" != root ] && _human=1
    if inlist "$_u" "$EXCLUDE"; then row "$_u" "$_uid" "$_sh" "$_st" skipped "--exclude"; continue; fi
    if [ -n "$USERS" ] && ! inlist "$_u" "$USERS"; then continue; fi
    [ "$_st" = empty ] && printf 'HIGH|%s has NO password: anyone can log in as it\n' "$_u" >>"$W/notes"
    [ "$_uid" = 0 ] && [ "$_u" != root ] && printf 'HIGH|%s has UID 0: it IS root under another name\n' "$_u" >>"$W/notes"

    # 1. Lock accounts that are not on the team's list.
    if [ -n "$KEEP" ] && [ "$_human" = 1 ] && [ "$_u" != root ] && ! onkeep "$_u"; then
        if [ "$_u" = "$ME" ]; then row "$_u" "$_uid" "$_sh" "$_st" skipped "not on --keep, but it is the account running this script"; continue; fi
        if ! cc_guard account "$_u"; then row "$_u" "$_uid" "$_sh" "$_st" "skipped (protected)" "not on --keep"; N_SKIP=$((N_SKIP + 1)); continue; fi
        backup_once || { row "$_u" "$_uid" "$_sh" "$_st" failed "backup failed"; continue; }
        cc_run "lock and expire account $_u (not on the team list)" lock_account "$_u"
        _rc=$?
        if [ "$_rc" -eq 0 ]; then
            cc_undo_add "unlock $_u" "$(unlock_cmd "$_u")"
            N_LOCK=$((N_LOCK + 1))
            if [ "$CC_APPLY" = 1 ]; then _act=locked; else _act="would lock"; fi
            if [ "$KICK" = 1 ] && cc_have pkill; then cc_run "end running processes of $_u" pkill -KILL -u "$_u"; fi
        else _act=failed; N_FAIL=$((N_FAIL + 1)); fi
        row "$_u" "$_uid" "$_sh" "$_st" "$_act" "not on the team list"
        continue
    fi

    # 2. Rotate accounts that have a usable password.
    if [ "$_st" != set ] && [ "$_st" != empty ]; then
        cc_debug "$_u: no usable password ($_st), not rotated"
        continue
    fi
    if [ "$_u" = root ] && [ "$NOROOT" = 1 ]; then row "$_u" "$_uid" "$_sh" "$_st" skipped "--no-root"; continue; fi
    if [ -n "$ME" ] && [ "$_u" = "$ME" ] && [ "$INCME" = 0 ]; then
        row "$_u" "$_uid" "$_sh" "$_st" skipped "account that ran sudo (use --include-me)"
        printf 'NOTE|%s (you) was not rotated: change it by hand or rerun with --include-me\n' "$_u" >>"$W/notes"
        continue
    fi
    if ! cc_guard account "$_u"; then
        row "$_u" "$_uid" "$_sh" "$_st" "skipped (protected)" "on the protected list"
        N_SKIP=$((N_SKIP + 1)); continue
    fi
    _note="random"
    _pw=$(given_pw "$_u")
    if [ -n "$_pw" ]; then _note="from --passwords"; else _pw=$(cc_genpass "$LEN") || { row "$_u" "$_uid" "$_sh" "$_st" failed "no random password"; continue; }; fi
    login_shell "$_sh" || _note="$_note; service account (no login shell) - check no service logs in with the old password"
    backup_once || { row "$_u" "$_uid" "$_sh" "$_st" failed "backup failed"; continue; }
    cc_run_quiet "new password for $_u" set_password "$_u" "$_pw"
    _rc=$?
    if [ "$_rc" -ne 0 ]; then
        row "$_u" "$_uid" "$_sh" "$_st" failed "$_note"; N_FAIL=$((N_FAIL + 1))
    elif [ "$CC_APPLY" = 1 ]; then
        [ -f "$PWOUT" ] || (umask 077; printf 'host,user,password,time\n' >"$PWOUT")
        printf '%s,%s,%s,%s\n' "$CC_HOST" "$_u" "$_pw" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$PWOUT"
        [ "$PRINT" = 1 ] && printf '%s:%s\n' "$_u" "$_pw" >>"$W/show"
        row "$_u" "$_uid" "$_sh" "$_st" rotated "$_note"; N_ROT=$((N_ROT + 1))
    else
        row "$_u" "$_uid" "$_sh" "$_st" "would rotate" "$_note"; N_ROT=$((N_ROT + 1))
    fi
    _pw=""
done <"$W/accounts"

# Samba keeps separate passwords; list its accounts so nobody assumes they changed.
if [ -z "$R" ] && cc_have pdbedit; then
    pdbedit -L 2>/dev/null | cut -d: -f1 | grep . >"$W/samba"
    [ -s "$W/samba" ] && printf 'NOTE|Samba accounts with their own (unchanged) passwords: %s - use smbpasswd if they must change\n' "$(tr '\n' ' ' <"$W/samba")" >>"$W/notes"
fi
if [ -z "$KEEP" ]; then
    awk -F'|' -v m="$UID_MIN" '($2 >= m && $2 < 60000) && $4 != "none" { print $1 }' "$W/accounts" >"$W/humans"
    [ -s "$W/humans" ] && printf 'NOTE|human accounts (none locked without --keep): %s\n' "$(tr '\n' ' ' <"$W/humans")" >>"$W/notes"
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
        printf '  Give them to the captain (and the scoring portal if a scored account changed),\n'
        printf '  then remove the file from this box:  rm %s\n' "$PWOUT"
    elif [ "$CC_APPLY" != 1 ]; then
        printf 'Dry run: nothing changed.  Run again with --apply.\n'
    fi
    [ "$CC_APPLY" = 1 ] && [ "$CC_N_DONE" -gt 0 ] && printf 'Undo: %s restores /etc/shadow from the backup (old passwords back).\n' "$CC_UNDO"
    printf 'All results: %s\n' "$CC_RUN_DIR"
} >"$CC_RUN_DIR/summary.txt"
cat "$CC_RUN_DIR/summary.txt"
if [ "$PRINT" = 1 ] && [ -s "$W/show" ]; then
    printf '\nNew passwords (also in %s):\n' "$PWOUT"
    sed 's/^/  /' "$W/show"
fi
rm -rf "$W"
cc_finish
