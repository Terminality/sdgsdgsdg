#!/bin/sh
# =============================================================================
# ID:       SV-40
# NAME:     Mail password rotation
# ROLE:     Applications  (wave 2, first 15 minutes)
# KIND:     changes - dry run unless --apply
# VERSION:  1.0.0
#
# PURPOSE
#   The mail users' passwords are the webmail and IMAP logins red team tries
#   first.  This finds where the mail server keeps them and gives each mail
#   user a new one:
#     - Dovecot with system accounts (pam, shadow, passwd): the accounts that
#       have a mailbox, through chpasswd (other accounts are LX-20's job)
#     - Dovecot passwd-file users (/etc/dovecot/users and the like): a new
#       SHA512-CRYPT hash in the file, Dovecot's login cache emptied
#     - Postfix with Cyrus SASL (sasldb2): saslpasswd2
#     - SQL or LDAP users: listed where they are; change them there
#   Each new password is tested with a real IMAP login (993, or 143 with
#   STARTTLS); if that fails, the old one is put back on the spot.  Dovecot
#   master users (they can open ANY mailbox) are flagged.  Webmail
#   (Roundcube) and SMTP logins through Dovecot use the same passwords.
#   New passwords go to ONE file, passwords.txt (mode 600), never to the
#   screen or the logs.
#
#   QUESTIONS (Enter takes the default in capitals; a flag answers each):
#     which box                                  --box NAME
#     go through each user?                      --batch = no, defaults
#     each user: [r]andom [s]et [l]ock [k]eep [a]ll the rest default
#                                                --users / --exclude / --passwords
#     apply?                                     --apply
#
# USAGE
#   sudo sh SV-40-mail-passwords.sh                               dry run, asks
#   sudo sh SV-40-mail-passwords.sh --protected p.csv --apply     asks about each user
#   sudo sh SV-40-mail-passwords.sh --protected p.csv --apply --batch
#
# OPTIONS
#   --apply            make the changes (without it, dry run only)
#   --box NAME         splunk | webmail | ecomm | other (asked)
#   --users a,b        only these users (repeatable)
#   --exclude a,b      never these users (repeatable)
#   --all-accounts     system accounts: every human account with a password,
#                      not only the ones with a mailbox
#   --passwords FILE   use these passwords: lines "user password" or "user,password"
#   --length N         random password length (default 16)
#   --timer SECONDS    revert countdown (default 120); --no-timer
#   --root DIR         treat DIR as / (tests): no login tests, nothing reloaded
#   --no-color         no colours
#   --help             this text plus the common options
#
# OUTPUTS  (under --out, in mail-passwords-N/, mode 700)
#   output.txt, users.txt, plan.txt, summary.txt, run.txt, revert.sh
#   passwords.txt  the new passwords (mode 600) - hand them to the captain,
#                  then delete the file
#   before/        each user's old password hash (root only)
#
# WHAT IT CHANGES  (only with --apply)
#   /etc/shadow (through chpasswd / usermod -L), Dovecot passwd-file lines,
#   the sasldb2 database.  Every change has an undo line.
#
# DEPENDS ON
#   doveconf (Dovecot) or postconf (Postfix); chpasswd; openssl (hashes for
#   passwd-file users, and the IMAP login test); saslpasswd2 for sasldb.
#   BT_CHPASSWD, BT_USERMOD and BT_DOVECONF (a file holding
#   "doveconf -n" output) may name stand-ins: the tests use them.
#
# TESTED ON
#   Ubuntu 24.04 with Dovecot 2.3 (pam and passwd-file) and Postfix, under
#   dash, bash, busybox sh, ksh93, mksh and yash with gawk, mawk and busybox
#   awk: new passwords log in over IMAP and the old ones do not, a typed
#   password, a lock, a failed login put back, undo restores every hash.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - The scored IMAP and webmail checks log in as a mail user: put that user
#     on the protected list, or report its new password in the scoring portal.
#   - Users kept in SQL or LDAP are only listed.
#   - Dovecot 2.4's new config names are read for passwd-file paths only.
#
# DEBUGGING
#   --debug shows each command (never the passwords: they go on stdin).
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
SV-40 Mail password rotation - new passwords for the mail users (Dovecot, Postfix SASL)
  sudo sh SV-40-mail-passwords.sh                          dry run, asks
  sudo sh SV-40-mail-passwords.sh --protected p.csv --apply

  --apply            make the changes (without it, dry run only)
  --box NAME         splunk | webmail | ecomm | other
  --users a,b        only these users      --exclude a,b   never these
  --all-accounts     every human account, not only those with a mailbox
  --passwords FILE   "user password" lines instead of random passwords
  --length N         random password length (default 16)
  --timer SECONDS    revert countdown (default 120); --no-timer
  --root DIR         treat DIR as / (tests)
  --no-color         no colours
  --help             show this text
USAGE
    cc_usage_common
}

BOX=""; USERS=""; EXCLUDE=""; ALLACC=0; GIVEN=""; LEN=16; TIMER=120; NOTIMER=0; R=""; COLOR=1
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --apply)        CC_APPLY=1; shift ;;
        --box)          [ $# -ge 2 ] || cc_die 2 "--box needs a name"; BOX=$2; shift 2 ;;
        --users)        [ $# -ge 2 ] || cc_die 2 "--users needs a list"; USERS="$USERS,$2"; shift 2 ;;
        --exclude)      [ $# -ge 2 ] || cc_die 2 "--exclude needs a list"; EXCLUDE="$EXCLUDE,$2"; shift 2 ;;
        --all-accounts) ALLACC=1; shift ;;
        --passwords)    [ $# -ge 2 ] || cc_die 2 "--passwords needs a file"; [ -r "$2" ] || cc_die 2 "--passwords: cannot read $2"; GIVEN=$(cc_abspath "$2"); shift 2 ;;
        --length)       [ $# -ge 2 ] || cc_die 2 "--length needs a number"; LEN=$2; shift 2 ;;
        --timer)        [ $# -ge 2 ] || cc_die 2 "--timer needs seconds"; TIMER=$2; shift 2 ;;
        --no-timer)     NOTIMER=1; shift ;;
        --root)         [ $# -ge 2 ] || cc_die 2 "--root needs a folder"; [ -d "$2" ] || cc_die 2 "--root: not a folder: $2"; R=$(cd "$2" && pwd); [ "$R" = / ] && R=""; shift 2 ;;
        --no-color|--no-colour) COLOR=0; shift ;;
        --help|-h)      usage; exit 0 ;;
        *)              cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
case "$BOX" in ''|splunk|webmail|ecomm|other) ;; *) cc_die 2 "--box must be splunk, webmail, ecomm or other" ;; esac
for _n in "$LEN" "$TIMER"; do case "$_n" in ''|*[!0-9]*) cc_die 2 "--length and --timer need whole numbers" ;; esac; done
[ "$LEN" -ge 12 ] || cc_die 2 "--length must be at least 12"

cc_init "SV-40" "Mail password rotation" changes
cc_detect_os
# shellcheck disable=SC2034  # read by cc_color_init
[ "$COLOR" = 1 ] || CC_NOCOLOR=1
cc_color_init
cc_use_numbered_dir mail-passwords
rmdir "$CC_RUN_DIR/raw" 2>/dev/null
chmod 700 "$CC_RUN_DIR"
OUTF="$CC_RUN_DIR/output.txt"
grep -v '\[NOTE\]\|\[DEBUG\]' "$CC_LOG" >"$OUTF" 2>/dev/null || : >"$OUTF"
# shellcheck disable=SC2034  # CC_TEE is read by the library's log functions
CC_TEE=$OUTF
W="$CC_RUN_DIR/.work"; mkdir -p "$W"; chmod 700 "$W"
mkdir -p "$CC_RUN_DIR/before"; chmod 700 "$CC_RUN_DIR/before"
CC_CSV_DIR="$W/csv"; mkdir -p "$CC_CSV_DIR"
TAB=$(printf '\t')
header() { cc_show "" ""; cc_show "$C_CYN" "==========[ $1 ]=========="; }
inlist() { case ",$2," in *",$1,"*) return 0 ;; esac; return 1; }
ok_pw() { case "$1" in ''|*[!A-Za-z0-9_@%+=.,!?^*~-]*) return 1 ;; esac; [ "${#1}" -ge 8 ]; }
P() { printf '%s%s' "$R" "$1"; }

cc_show "$C_CYN" "SV-40 Mail password rotation | host $CC_HOST | results in $CC_RUN_DIR"
cc_show "" "Legend: ${C_RED}[!]${C_OFF} fix now   ${C_YEL}[*]${C_OFF} look at it   ${C_YEL}[~] would change${C_OFF}   ${C_GRN}[+] changed${C_OFF}   ${C_GRY}[-] left alone${C_OFF}   ${C_RED}[x] failed${C_OFF}"
[ -n "$R" ] && cc_show "$C_GRY" "Acting on $R as if it were / (no login tests, nothing reloaded)"

: >"$W/given"; chmod 600 "$W/given"
if [ -n "$GIVEN" ]; then
    tr ',' ' ' <"$GIVEN" | awk '/^[ \t]*#/ || NF < 2 { next } { print $1 "\t" $2 }' >"$W/given"
    while IFS="$TAB" read -r _u _p; do ok_pw "$_p" || cc_die 2 "--passwords: the password for $_u has a character I cannot use safely (letters, digits and _@%+=.,!?^*~-, at least 8)"; done <"$W/given"
fi
given_pw() { awk -F'\t' -v u="$1" '$1 == u { print $2; exit }' "$W/given"; }

# ---- Where the mail passwords live --------------------------------------------------
# $W/passdb: "driver|args|master"  (from doveconf -n)
if [ -n "${BT_DOVECONF:-}" ]; then cat "$BT_DOVECONF" >"$W/doveconf"
elif [ -z "$R" ] && cc_have doveconf; then doveconf -n >"$W/doveconf" 2>>"$CC_LOG"
else : >"$W/doveconf"; fi
awk '/^[ \t]*passdb( [^{]*)? *\{/ { on = 1; d = ""; a = ""; m = "no"; next }
     on && /^[ \t]*\}/ { print d "|" a "|" m; on = 0; next }
     on && /^[ \t]*driver *=/ { sub(/^[^=]*= */, ""); d = $0 }
     on && /^[ \t]*(args|passwd_file_path) *=/ { sub(/^[^=]*= */, ""); a = $0 }
     on && /^[ \t]*master *= *yes/ { m = "yes" }
     on && /^[ \t]*deny *= *yes/ { m = "deny" }' "$W/doveconf" >"$W/passdb"
SASLDB=""; SMTPVIA=""
if [ -z "$R" ] && cc_have postconf; then
    [ "$(postconf -h smtpd_sasl_auth_enable 2>/dev/null)" = yes ] && [ "$(postconf -h smtpd_sasl_type 2>/dev/null)" = cyrus ] && [ -f /etc/sasldb2 ] && SASLDB=/etc/sasldb2
    SMTPVIA=$(postconf -h smtpd_sasl_type 2>/dev/null)
fi
[ -f "$(P /etc/sasldb2)" ] && [ -n "$R" ] && SASLDB=/etc/sasldb2
: >"$W/notes"
STORES=""
while IFS='|' read -r _d _a _m; do
    # A deny passdb lists users who may NOT log in: no passwords there.
    [ "$_m" = deny ] && continue
    case "$_d" in
        pam|shadow|passwd|bsdauth) case " $STORES " in *" system "*) ;; *) STORES="$STORES system" ;; esac ;;
        passwd-file)
            # The file is the last word of args that is not key=value.
            _f=$(printf '%s\n' "$_a" | tr ' ' '\n' | grep -v '=' | tail -n 1)
            case "$_f" in *%*) _f=$(printf '%s' "$_f" | sed 's/%[a-zA-Z{}]*/*/g') ;; esac
            for _ff in $(P "$_f"); do
                [ -f "$_ff" ] || continue
                if [ "$_m" = yes ]; then
                    printf 'HIGH|Dovecot MASTER users in %s (they can open ANY mailbox): %s - one you did not set up is red team\n' "${_ff#"$R"}" "$(cut -d: -f1 "$_ff" | grep -v '^#' | tr '\n' ' ')" >>"$W/notes"
                fi
                STORES="$STORES file:${_ff#"$R"}"
            done ;;
        sql|ldap|dict) printf 'NOTE|Dovecot also checks %s (%s): those users are not changed here - change them where they live\n' "$_d" "$_a" >>"$W/notes" ;;
        static) printf 'HIGH|a Dovecot "static" passdb (%s): every user logs in with ONE password - remove it if it is not yours\n' "$_a" >>"$W/notes" ;;
        checkpassword) printf 'NOTE|Dovecot checkpassword (%s): a program decides logins - look at it\n' "$_a" >>"$W/notes" ;;
    esac
done <"$W/passdb"
[ -n "$SASLDB" ] && STORES="$STORES sasldb"
if [ ! -s "$W/passdb" ] && [ -z "$SASLDB" ]; then
    cc_show "$C_GRY" "No Dovecot passdb or Postfix SASL database found here: nothing to rotate (system accounts: LX-20)."
    rm -rf "$W"; cc_finish; exit 0
fi
case "$SMTPVIA" in dovecot) printf 'NOTE|Postfix logs SMTP users in through Dovecot: they get the same new passwords\n' >>"$W/notes" ;; esac

if [ -z "$BOX" ]; then
    cc_choose "Which box is this?" w "s=splunk" "w=webmail" "e=ecomm" "o=other"
    case "$CC_CHOICE" in s) BOX=splunk ;; w) BOX=webmail ;; e) BOX=ecomm ;; *) BOX=other ;; esac
fi
[ "$BOX" = webmail ] && cc_show "$C_YEL" "  webmail: the scored IMAP and webmail checks log in as a mail user. Put that user on the protected list, or report its new password."

# ---- Users ----------------------------------------------------------------------------
# $W/acc: "store|user|state|mailbox"   state: set | empty | locked
: >"$W/acc"
UID_MIN=$(awk '$1 == "UID_MIN" { print $2 }' "$(P /etc/login.defs)" 2>/dev/null)
case "$UID_MIN" in ''|*[!0-9]*) UID_MIN=1000 ;; esac
for _s in $STORES; do
    case "$_s" in
        system)
            awk -F: -v m="$UID_MIN" 'NR == FNR { p[$1] = $3 ":" $6 ":" $7; next }
                ($1 in p) { split(p[$1], a, ":"); if (a[1] + 0 < m || a[1] + 0 >= 60000) next
                  st = ($2 == "") ? "empty" : (($2 ~ /^[!*]/) ? "locked" : "set"); print $1 "|" a[2] "|" st }' \
                "$(P /etc/passwd)" "$(P /etc/shadow)" 2>/dev/null >"$W/sys"
            while IFS='|' read -r _u _h _st; do
                _mb=no
                for _x in "/var/mail/$_u" "/var/spool/mail/$_u" "$_h/Maildir" "$_h/mail"; do [ -e "$(P "$_x")" ] && { _mb=yes; break; }; done
                [ "$_mb" = no ] && [ "$ALLACC" = 0 ] && continue
                printf 'system|%s|%s|%s\n' "$_u" "$_st" "$_mb" >>"$W/acc"
            done <"$W/sys" ;;
        file:*)
            _f=${_s#file:}
            awk -F: '/^[ \t]*#/ || NF < 2 { next } { h = $2; sub(/^\{[A-Za-z0-9.-]*\}/, "", h)
                st = (h == "") ? "empty" : ((h ~ /^!/) ? "locked" : "set"); print $1 "|" st }' "$(P "$_f")" |
            while IFS='|' read -r _u _st; do printf '%s|%s|%s|-\n' "$_s" "$_u" "$_st"; done >>"$W/acc" ;;
        sasldb)
            if cc_have sasldblistusers2; then
                sasldblistusers2 -f "$(P "$SASLDB")" 2>/dev/null | sed -n 's/^\([^:]*\):.*/\1/p' | while IFS= read -r _u; do printf 'sasldb|%s|set|-\n' "$_u"; done >>"$W/acc"
            fi ;;
    esac
done
_miss=""
for _n in $(printf '%s,%s' "$USERS" "$EXCLUDE" | tr ',' ' '); do
    awk -F'|' -v u="$_n" '$2 == u { f = 1 } END { exit !f }' "$W/acc" || _miss="$_miss $_n"
done
[ -z "$_miss" ] || { rm -rf "$W"; cc_die 2 "no such mail user:$_miss (in --users or --exclude). Nothing was changed."; }

# $W/plan: "store|user|state|mailbox|action|why"
: >"$W/plan"
while IFS='|' read -r _s _u _st _mb; do
    _a=r; _why=random
    if [ "$_st" = locked ]; then _a=-; _why=locked
    elif inlist "$_u" "$EXCLUDE"; then _a=k; _why="--exclude"
    elif [ -n "$USERS" ] && ! inlist "$_u" "$USERS"; then _a=k; _why="not in --users"
    elif [ -n "$(given_pw "$_u")" ]; then _a=s; _why="from --passwords"
    elif [ "$_s" = system ] && [ -n "${SUDO_USER:-}" ] && [ "$_u" = "$SUDO_USER" ]; then _a=k; _why="you are logged in as it (LX-20 changes it)"
    fi
    [ "$_st" = empty ] && printf 'HIGH|%s (%s) has NO password\n' "$_u" "$_s" >>"$W/notes"
    printf '%s|%s|%s|%s|%s|%s\n' "$_s" "$_u" "$_st" "$_mb" "$_a" "$_why" >>"$W/plan"
done <"$W/acc"

act_word() { case "$1" in r) echo random ;; s) echo set ;; l) echo lock ;; k) echo keep ;; *) echo "-" ;; esac; }
header "1/4  mail users"
cc_show "$C_GRY" "  Passwords kept in:$(printf '%s' "$STORES" | sed 's/file:/ passwd-file /g')"
cc_show "$C_CYN" "$(printf '  %-28s %-20s %-8s %-8s %-7s %s' STORE USER PASSWORD MAILBOX ACTION NOTES)"
while IFS='|' read -r _s _u _st _mb _a _why; do
    _col=""; [ "$_st" = empty ] && _col=$C_RED; [ "$_a" = k ] || [ "$_a" = - ] && _col=$C_GRY
    cc_show "$_col" "$(printf '  %-28s %-20s %-8s %-8s %-7s %s' "$(printf '%s' "$_s" | cut -c1-28)" "$_u" "$_st" "$_mb" "$(act_word "$_a")" "$_why")"
done <"$W/plan"
[ -s "$W/plan" ] || cc_show "$C_GRY" "  (no mail users found$( [ "$ALLACC" = 0 ] && echo '; system accounts with no mailbox are left out: --all-accounts'))"
while IFS='|' read -r _lv _tx; do
    case "$_lv" in HIGH) cc_show "$C_RED" "  [!] $_tx" ;; *) cc_show "$C_YEL" "  [*] $_tx" ;; esac
done <"$W/notes"

# ---- Questions ------------------------------------------------------------------------
read_secret() {
    printf '%s' "$2" >/dev/tty
    stty -echo </dev/tty 2>/dev/null
    _cc_read "$1"; _rs_rc=$?
    stty echo </dev/tty 2>/dev/null
    printf '\n' >/dev/tty
    return "$_rs_rc"
}
ask_password() {
    TYPED=""
    while :; do
        read_secret _p1 "    New password for $1 (not shown): " || return 1
        read_secret _p2 "    Same password again: " || return 1
        if [ "$_p1" != "$_p2" ]; then printf '    They do not match. Again.\n' >/dev/tty; continue; fi
        if ! ok_pw "$_p1"; then printf '    At least 8 characters: letters, digits and _@%%+=.,!?^*~- only. Again.\n' >/dev/tty; continue; fi
        TYPED=$_p1; _p1=""; _p2=""; return 0
    done
}
set_plan() { awk -F'|' -v OFS='|' -v s="$1" -v u="$2" -v a="$3" -v w="$4" '$1 == s && $2 == u { $5 = a; $6 = w } { print }' "$W/plan" >"$W/plan.t" && mv "$W/plan.t" "$W/plan"; }
: >"$W/typed"; chmod 600 "$W/typed"
FORCED=""
CANAPPLY=0; { [ -n "$R" ] || cc_is_root; } && CANAPPLY=1
header "2/4  questions (Enter = the default in capitals)"
awk -F'|' '$5 != "-" && $6 !~ /^(--exclude|not in --users)/' "$W/plan" >"$W/ask"
if [ "$CANAPPLY" = 1 ] && _cc_can_ask && [ -s "$W/ask" ] && \
   cc_ask "Go through each user one by one?" Y "yes, ask me about each user" "no, use the actions in the table"; then
    _all=0
    while IFS='|' read -r _s _u _st _mb _a _why; do
        [ "$_all" = 1 ] && break
        _lk="l=lock it: nobody can log in as it (its mail stays)"; [ "$_s" = sasldb ] && _lk="l=(not for sasldb: use keep)"
        cc_choose "mail user $_u ($_s, password $_st)?" "$_a" \
            "r=random new password" "s=set one: you type it twice, it is not shown" "$_lk" "k=keep it as it is" "a=all the rest: take their defaults"
        _ans=$CC_CHOICE
        [ "$_ans" = l ] && [ "$_s" = sasldb ] && _ans=k
        [ "$_ans" = a ] && { _all=1; continue; }
        if [ "$_ans" != k ] && cc_is_protected account "$_u"; then
            if cc_ask "  $_u is on the protected list (scoring may log in as it). Change it anyway?" N "yes, change it (report the new password to scoring)" "no, keep it"; then
                FORCED="$FORCED,$_u"
            else set_plan "$_s" "$_u" k "protected"; continue; fi
        fi
        case "$_ans" in
            r) set_plan "$_s" "$_u" r "random (you chose)" ;;
            l) set_plan "$_s" "$_u" l "lock (you chose)" ;;
            k) set_plan "$_s" "$_u" k "you said keep" ;;
            s) if [ -n "$(given_pw "$_u")" ] && cc_ask "  Use the password from --passwords for $_u?" Y "yes, use it" "no, I will type one"; then
                   set_plan "$_s" "$_u" s "from --passwords"
               elif ask_password "$_u"; then
                   printf '%s\t%s\t%s\n' "$_s" "$_u" "$TYPED" >>"$W/typed"; TYPED=""
                   set_plan "$_s" "$_u" s "typed"
               else set_plan "$_s" "$_u" k "no password typed"; fi ;;
        esac
    done <"$W/ask"
fi

header "3/4  plan"
NCH=0
while IFS='|' read -r _s _u _st _mb _a _why; do
    case "$_a" in
        r|s|l) NCH=$((NCH + 1)); cc_show "$C_YEL" "  [~] $(act_word "$_a") $_u ($_s)  ($_why)" ;;
        k) cc_show "$C_GRY" "  [-] keep $_u ($_s)  ($_why)" ;;
    esac
done <"$W/plan"
[ "$NCH" -eq 0 ] && cc_show "$C_GRN" "  [ok] Nothing to change."
{ printf 'SV-40 plan | host %s\n\n' "$CC_HOST"; awk -F'|' '$5 != "-" { printf "  %-28s %-20s %-6s %s\n", $1, $2, $5, $6 }' "$W/plan"; } >"$CC_RUN_DIR/plan.txt"

# ---- Helpers for the changes ---------------------------------------------------------
CHPASSWD=${BT_CHPASSWD:-$(cc_which chpasswd)} || CHPASSWD=""
USERMOD=${BT_USERMOD:-$(cc_which usermod)} || USERMOD=""
PWOUT="$CC_RUN_DIR/passwords.txt"
pw_line() {
    [ -f "$PWOUT" ] || { (umask 077; printf 'New mail passwords on %s - give them to the captain, then delete this file\n\n' "$CC_HOST" >"$PWOUT")
        cc_undo_add "mark the passwords file as no longer valid" "mv $(cc_shquote "$PWOUT") $(cc_shquote "$CC_RUN_DIR/passwords-UNDONE-not-valid.txt")"; }
    printf '%-20s %-20s %-18s %s\n' "$1" "$2" "$3" "$(date -u +%H:%M:%SZ)" >>"$PWOUT"
}
# hash PASSWORD -> SHA512-CRYPT, password on stdin.
mkhash() { printf '%s\n' "$1" | openssl passwd -6 -stdin 2>>"$CC_LOG"; }
# file_line FILE USER NEWFIELD2 -> replace the user's password field.
file_line() {
    awk -F: -v OFS=: -v u="$2" -v h="$3" '!/^[ \t]*#/ && $1 == u { $2 = h } { print }' "$1" >"$1.ccnew" && cat "$1.ccnew" >"$1"; _fr=$?
    rm -f "$1.ccnew"; return "$_fr"
}
flush_cache() { [ -z "$R" ] && cc_have doveadm && doveadm auth cache flush >/dev/null 2>&1; return 0; }
# imap_test USER PASSWORD -> 0 works, 1 fails, 2 cannot test.
IMAPHOW=""
if [ -z "$R" ] && cc_have openssl; then
    if ss -ltn 2>/dev/null | grep -q ':993 '; then IMAPHOW=993; elif ss -ltn 2>/dev/null | grep -q ':143 '; then IMAPHOW=143; fi
fi
imap_test() {
    [ -n "$IMAPHOW" ] || return 2
    # A PAM login can take a few seconds the first time: wait for the
    # answer, and try once more before calling it a failure.
    for _wait in 4 8; do
        if [ "$IMAPHOW" = 993 ]; then
            _ir=$( (printf 'a LOGIN "%s" "%s"\n' "$1" "$2"; sleep "$_wait"; printf 'b LOGOUT\n'; sleep 1) | timeout 20 openssl s_client -connect 127.0.0.1:993 -quiet -crlf 2>/dev/null)
        else
            _ir=$( (printf 'a LOGIN "%s" "%s"\n' "$1" "$2"; sleep "$_wait"; printf 'b LOGOUT\n'; sleep 1) | timeout 20 openssl s_client -starttls imap -connect 127.0.0.1:143 -quiet -crlf 2>/dev/null)
        fi
        printf '%s\n' "$_ir" | grep -q '^a OK' && return 0
        printf '%s\n' "$_ir" | grep -q '^a NO' && return 1
    done
    return 1
}

# change STORE USER ACTION -> one user, tested; put back on the spot if the
#   new password does not log in.  Sets RES.
change() {
    _s=$1; _u=$2; _a=$3; RES=""; _pw=""
    if [ "$_a" = s ]; then
        _pw=$(awk -F'\t' -v s="$_s" -v u="$_u" '$1 == s && $2 == u { p = $3 } END { print p }' "$W/typed")
        [ -n "$_pw" ] || _pw=$(given_pw "$_u")
    fi
    [ "$_a" = l ] || [ -n "$_pw" ] || _pw=$(cc_genpass "$LEN") || { RES="failed: no random password"; return 1; }
    _sf="$CC_RUN_DIR/before/$(printf '%s-%s' "$_s" "$_u" | tr -c 'A-Za-z0-9._-' '_').txt"
    case "$_s" in
        system)
            [ -n "$CHPASSWD" ] || { RES="failed: chpasswd not found"; return 1; }
            (umask 077; awk -F: -v u="$_u" '$1 == u { print $1 ":" $2 }' "$(P /etc/shadow)" >"$_sf")
            [ -s "$_sf" ] || { RES="failed: could not save the old hash, not changed"; return 1; }
            _undo="$CHPASSWD -e < $(cc_shquote "$_sf")"
            cc_undo_add "old password back for $_u" "$_undo"
            if [ "$_a" = l ]; then
                if [ -n "$USERMOD" ]; then "$USERMOD" -L "$_u" >>"$CC_LOG" 2>&1; else passwd -l "$_u" >>"$CC_LOG" 2>&1; fi && { RES=locked; return 0; }
                RES="failed: could not lock"; return 1
            fi
            printf '%s:%s\n' "$_u" "$_pw" | "$CHPASSWD" 2>>"$CC_LOG" || { sh -c "$_undo" >>"$CC_LOG" 2>&1; RES="failed: chpasswd refused it"; _pw=""; return 1; } ;;
        file:*)
            _f=$(P "${_s#file:}")
            (umask 077; awk -F: -v u="$_u" '$1 == u' "$_f" >"$_sf")
            [ -s "$_sf" ] || { RES="failed: could not save the old line, not changed"; return 1; }
            # Undo: the saved line goes back in place of the user's line.
            _undo="awk -F: -v u=$(cc_shquote "$_u") 'NR == FNR { l = \$0; next } \$1 == u { print l; next } { print }' $(cc_shquote "$_sf") $(cc_shquote "$_f") > $(cc_shquote "$_f.ccold") && cat $(cc_shquote "$_f.ccold") > $(cc_shquote "$_f") && rm -f $(cc_shquote "$_f.ccold")"
            [ -z "$R" ] && cc_have doveadm && _undo="$_undo; doveadm auth cache flush >/dev/null 2>&1"
            cc_undo_add "old password back for $_u" "$_undo"
            if [ "$_a" = l ]; then
                _old=$(cut -d: -f2 "$_sf"); _sch=$(printf '%s' "$_old" | sed -n 's/^\({[A-Za-z0-9.-]*}\).*/\1/p')
                file_line "$_f" "$_u" "${_sch:-}!$(printf '%s' "$_old" | sed 's/^{[A-Za-z0-9.-]*}//')" && { flush_cache; RES=locked; return 0; }
                RES="failed: could not lock"; return 1
            fi
            _h=$(mkhash "$_pw") && [ -n "$_h" ] || { RES="failed: openssl could not make the hash"; _pw=""; return 1; }
            file_line "$_f" "$_u" "{SHA512-CRYPT}$_h" || { sh -c "$_undo" >>"$CC_LOG" 2>&1; RES="failed: could not write the file"; _pw=""; return 1; }
            flush_cache ;;
        sasldb)
            [ "$_a" = l ] && { RES="kept (sasldb has no lock)"; return 0; }
            if [ ! -f "$W/sasl.saved" ]; then
                cc_backup_file "$(P "$SASLDB")" >/dev/null || { RES="failed: could not back up $SASLDB"; return 1; }
                : >"$W/sasl.saved"
            fi
            printf '%s' "$_pw" | saslpasswd2 -p -f "$(P "$SASLDB")" "$_u" 2>>"$CC_LOG" || { RES="failed: saslpasswd2 refused it"; _pw=""; return 1; } ;;
    esac
    # Log in with it.
    _nt=""
    if [ "$_s" = sasldb ]; then _nt=1
    else
        imap_test "$_u" "$_pw"; _it=$?
        if [ "$_it" = 1 ]; then
            sh -c "$_undo" >>"$CC_LOG" 2>&1
            RES="failed: the new password did not log in over IMAP, old one put back"; _pw=""; return 1
        fi
        [ "$_it" = 2 ] && _nt=1
    fi
    pw_line "$_s" "$_u" "$_pw"; _pw=""
    RES="changed, IMAP login tested"; [ -n "$_nt" ] && RES="changed (login not tested here)"
    return 0
}

# ---- Apply --------------------------------------------------------------------------
header "4/4  apply"
CSV=$(cc_csv_new users "store,user,password_was,mailbox,action,result")
APPLIED=0; TIMER_ON=0; N_OK=0; N_FAIL=0; N_LOCK=0; GO=0
if [ "$NCH" -eq 0 ]; then :
elif [ "$CC_APPLY" != 1 ] || [ "$CANAPPLY" = 0 ]; then
    [ "$CANAPPLY" = 0 ] && cc_show "$C_YEL" "  [!] not root: showing the plan only"
    cc_show "$C_GRY" "  $NCH change(s) planned. Dry run: nothing was changed. Run again with --apply."
    # shellcheck disable=SC2034  # read by cc_finish
    CC_N_WOULD=$NCH
elif ! cc_ask "Apply these $NCH change(s)?" Y "yes, apply them (a revert timer undoes them unless you confirm from a NEW session)" "no, change nothing"; then
    cc_show "$C_GRY" "  Not applied. The plan is in $CC_RUN_DIR/plan.txt"
else
    GO=1
    if [ -z "$CC_PROTECTED" ] && [ "$CC_NO_PROTECTED" != 1 ]; then
        cc_show "$C_YEL" "  [*] No protected list: the user the scoring engine logs in with is not known."
        cc_ask "Change passwords without one?" N "yes, go on without a protected list" "no, stop" || { cc_show "$C_YEL" "  [*] Not applied."; GO=0; }
    fi
fi
while IFS='|' read -r _s _u _st _mb _a _why; do
    case "$_a" in
        r|s|l) [ "$GO" = 1 ] || cc_csv_row "$CSV" "$_s" "$_u" "$_st" "$_mb" "$(act_word "$_a")" "would change" ;;
        k) cc_csv_row "$CSV" "$_s" "$_u" "$_st" "$_mb" keep "$_why" ;;
    esac
done <"$W/plan"
if [ "$GO" = 1 ]; then
    APPLIED=1
    if [ "$NOTIMER" != 1 ] && [ -z "$R" ]; then
        cc_timer_start "$TIMER"; TIMER_ON=1
        cc_show "$C_YEL" "  [*] Revert timer started: every old password comes back in $((TIMER / 60)):$(printf '%02d' $((TIMER % 60))) unless you keep it at the end."
    fi
    while IFS='|' read -r _s _u _st _mb _a _why; do
        case "$_a" in r|s|l) ;; *) continue ;; esac
        if ! inlist "$_u" "$FORCED" && ! cc_guard account "$_u"; then
            cc_csv_row "$CSV" "$_s" "$_u" "$_st" "$_mb" "$(act_word "$_a")" "skipped (protected)"; cc_show "$C_YEL" "  [-] $_u: on the protected list, kept"; continue
        fi
        if change "$_s" "$_u" "$_a" </dev/null; then
            if [ "$_a" = l ]; then N_LOCK=$((N_LOCK + 1)); else N_OK=$((N_OK + 1)); fi
            cc_show "$C_GRN" "  [+] $_u ($_s): $RES"
        else
            N_FAIL=$((N_FAIL + 1)); cc_show "$C_RED" "  [x] $_u ($_s): $RES"
        fi
        cc_csv_row "$CSV" "$_s" "$_u" "$_st" "$_mb" "$(act_word "$_a")" "$RES"
    done <"$W/plan"
    : >"$W/typed"
fi

# ---- Summary ----------------------------------------------------------------------------
cc_csv_pretty "$CSV" "$CC_RUN_DIR/users.txt" 110
{
    printf '==========[ summary ]==========\n'
    # shellcheck disable=SC2034  # read by cc_finish
    CC_N_DONE=$((N_OK + N_LOCK))
    # shellcheck disable=SC2034  # read by cc_finish
    CC_N_FAIL=$N_FAIL
    printf 'SV-40 Mail password rotation | host %s | %s\n' "$CC_HOST" "$([ "$APPLIED" = 1 ] && echo APPLIED || echo 'DRY RUN - nothing changed')"
    [ "$APPLIED" = 1 ] && printf 'Changed: %d   Locked: %d   Failed (put back): %d\n' "$N_OK" "$N_LOCK" "$N_FAIL"
    awk "$CC_AWK_CSV"'NR > 1 { csvsplit($0, f); printf "  %-20s %-20s %-7s %s\n", substr(f[1], 1, 20), f[2], f[5], f[6] }' "$CSV"
    [ -s "$W/notes" ] && printf '\nFound:\n'
    awk -F'|' '{ printf "  %-5s %s\n", $1, $2 }' "$W/notes"
    [ -f "$PWOUT" ] && printf '\nNew passwords: %s (mode 600)\n  Give them to the captain (and the scoring portal if a scored user changed), then: rm %s\n' "$PWOUT" "$PWOUT"
    [ "$APPLIED" = 1 ] && [ -f "$CC_RUN_DIR/revert.sh" ] && printf 'Undo this run: sh %s/revert.sh --force\n' "$CC_RUN_DIR"
    printf 'Users: %s/users.txt\n' "$CC_RUN_DIR"
} >"$CC_RUN_DIR/summary.txt"
cc_show "" ""
while IFS= read -r _l; do
    case "$_l" in ==*|SV-40*) cc_show "$C_CYN" "$_l" ;; *'Failed (put back): '[1-9]*|*HIGH*|*failed*) cc_show "$C_RED" "$_l" ;; *NOTE*|*'New passwords'*|*'Give them'*) cc_show "$C_YEL" "$_l" ;; *) cc_show "" "$_l" ;; esac
done <"$CC_RUN_DIR/summary.txt"
rm -rf "$W"
if [ "$TIMER_ON" = 1 ]; then
    header "KEEP OR REVERT"
    cc_show "$C_YEL" "[*] Before you answer: log in to the webmail with one new password from a browser."
    cc_timer_finish || true
fi
cc_finish
