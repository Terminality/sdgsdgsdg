#!/bin/sh
# =============================================================================
# ID:       SV-31
# NAME:     Mail tamper check
# ROLE:     Applications  (wave 2, the webmail box; again after red team)
# KIND:     changes - dry run unless --apply
# VERSION:  1.0.0
#
# PURPOSE
#   Red team's quiet backdoors in a mail server: a copy of every mail sent to
#   them, a program run on every delivery, mail forwarded out, an open relay
#   for spam.  This reads Postfix, Dovecot, the aliases and every user's mail
#   files and offers to undo each one:
#
#     HIGH  always_bcc / sender_bcc_maps / recipient_bcc_maps (a copy of all
#           mail goes somewhere); mailbox_command / mailbox_transport (a
#           program on every delivery); a content_filter or master.cf "pipe"
#           service that runs a program Postfix does not ship; mynetworks
#           open to the world (open relay); relay rules without
#           reject/defer_unauth_destination; aliases and ~/.forward /
#           ~/.procmailrc that run a program ("| cmd") or :include: a file;
#           sieve scripts that run programs (vnd.dovecot.execute / pipe)
#     MED   aliases / .forward / virtual aliases / sieve that send mail to an
#           outside address; header_checks / body_checks that REDIRECT,
#           DISCARD or BCC; a relayhost or transport_maps entry (mail routed
#           elsewhere); a Dovecot post-login script; a big mail queue
#
#   Fixes (each asked, yes/no): remove the Postfix setting, comment out the
#   master.cf service or the alias line (then newaliases), quarantine the
#   .forward / .procmailrc / sieve file, set mynetworks to this box only.
#   After: postfix check, a reload, then SMTP (25) and IMAP (143) must
#   still answer - they are scored - or everything is put back.
#
#   QUESTIONS (Enter takes the default in capitals; a flag answers each):
#     which box                       --box NAME
#     each finding: fix it?           --batch takes the default shown
#     apply?                          --apply
#
# USAGE
#   sudo sh SV-31-mail-tamper.sh                                 look + dry run
#   sudo sh SV-31-mail-tamper.sh --protected p.csv --apply
#   sudo sh SV-31-mail-tamper.sh --protected p.csv --apply --batch
#
# OPTIONS
#   --apply            make the changes (without it, dry run only)
#   --box NAME         splunk | webmail | ecomm | other (asked)
#   --domain D         our mail domain(s), comma separated: forwarding to
#                      these is not "outside" (default: mydestination)
#   --queue N          a queue bigger than N mails is flagged (default 200)
#   --timer SECONDS    revert countdown (default 120); --no-timer
#   --root DIR         treat DIR as / (tests): nothing reloaded or tested
#   --no-color         no colours
#   --help             this text plus the common options
#
# OUTPUTS  (under --out, in mail-tamper-N/)
#   output.txt, findings.txt, plan.txt, summary.txt, run.txt, revert.sh
#
# DEPENDS ON
#   awk, sed; postfix (check, reload), newaliases, nc or curl for the
#   SMTP/IMAP check.
#
# TESTED ON
#   Ubuntu 24.04 with Postfix 3.8 and Dovecot 2.3 (live) and a fake root,
#   under dash, bash, busybox sh, ksh93, mksh and yash with gawk, mawk and
#   busybox awk.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - Exim and Sendmail are not read.  Database-backed (mysql:, pgsql:,
#     ldap:) maps are named, not opened.
#   - A real mail filter (amavis, spamassassin, rspamd) shows as MED
#     "content_filter": check the name and keep it.
#   - Banner, VRFY, HELO, relay basics: SV-30.  Mail passwords: SV-40.
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
SV-31 Mail tamper check - hidden copies, delivery programs, forwards, open relay
  sudo sh SV-31-mail-tamper.sh                            look + dry run
  sudo sh SV-31-mail-tamper.sh --protected p.csv --apply

  --apply            make the changes (without it, dry run only)
  --box NAME         splunk | webmail | ecomm | other
  --domain D         our mail domain(s), comma separated
  --queue N          flag a mail queue bigger than N (default 200)
  --timer SECONDS    revert countdown (default 120); --no-timer
  --root DIR         treat DIR as / (tests)
  --no-color         no colours
  --help             show this text
USAGE
    cc_usage_common
}

BOX=""; DOMAINS=""; QMAX=200; TIMER=120; NOTIMER=0; R=""; COLOR=1
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --apply)    CC_APPLY=1; shift ;;
        --box)      [ $# -ge 2 ] || cc_die 2 "--box needs a name"; BOX=$2; shift 2 ;;
        --domain)   [ $# -ge 2 ] || cc_die 2 "--domain needs a name"; DOMAINS="$DOMAINS,$2"; shift 2 ;;
        --queue)    [ $# -ge 2 ] || cc_die 2 "--queue needs a number"; QMAX=$2; shift 2 ;;
        --timer)    [ $# -ge 2 ] || cc_die 2 "--timer needs seconds"; TIMER=$2; shift 2 ;;
        --no-timer) NOTIMER=1; shift ;;
        --root)     [ $# -ge 2 ] || cc_die 2 "--root needs a folder"; [ -d "$2" ] || cc_die 2 "--root: not a folder: $2"; R=$(cd "$2" && pwd); [ "$R" = / ] && R=""; shift 2 ;;
        --no-color|--no-colour) COLOR=0; shift ;;
        --help|-h)  usage; exit 0 ;;
        *)          cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
case "$BOX" in ''|splunk|webmail|ecomm|other) ;; *) cc_die 2 "--box must be splunk, webmail, ecomm or other" ;; esac
for _n in "$QMAX" "$TIMER"; do case "$_n" in ''|*[!0-9]*) cc_die 2 "--queue and --timer need whole numbers" ;; esac; done

cc_init "SV-31" "Mail tamper check" changes
cc_detect_os
# shellcheck disable=SC2034  # read by cc_color_init
[ "$COLOR" = 1 ] || CC_NOCOLOR=1
cc_color_init
cc_use_numbered_dir mail-tamper
rmdir "$CC_RUN_DIR/raw" 2>/dev/null
OUTF="$CC_RUN_DIR/output.txt"
grep -v '\[NOTE\]\|\[DEBUG\]' "$CC_LOG" >"$OUTF" 2>/dev/null || : >"$OUTF"
# shellcheck disable=SC2034  # CC_TEE is read by the library's log functions
CC_TEE=$OUTF
W="$CC_RUN_DIR/.work"; mkdir -p "$W"
CC_CSV_DIR="$W/csv"; mkdir -p "$CC_CSV_DIR"
header() { cc_show "" ""; cc_show "$C_CYN" "==========[ $1 ]=========="; }
P() { printf '%s%s' "$R" "$1"; }

cc_show "$C_CYN" "SV-31 Mail tamper check | host $CC_HOST | results in $CC_RUN_DIR"
cc_show "" "Legend: ${C_RED}[!] HIGH${C_OFF}   ${C_YEL}[*] MED${C_OFF}   ${C_GRN}[ok]${C_OFF} fine   ${C_YEL}[~] would change${C_OFF}   ${C_GRN}[+] changed${C_OFF}   ${C_RED}[x] failed${C_OFF}"
[ -n "$R" ] && cc_show "$C_GRY" "Acting on $R as if it were / (nothing reloaded or tested)"

PF=/etc/postfix; MAIN="$PF/main.cf"; MASTER="$PF/master.cf"
if [ ! -f "$(P "$MAIN")" ] && [ ! -d "$(P /etc/dovecot)" ]; then
    cc_show "$C_GRY" "No Postfix or Dovecot here: nothing to check."; rm -rf "$W"; cc_finish; exit 0
fi
if [ -z "$BOX" ]; then
    cc_choose "Which box is this?" w "s=splunk" "w=webmail" "e=ecomm" "o=other"
    case "$CC_CHOICE" in s) BOX=splunk ;; w) BOX=webmail ;; e) BOX=ecomm ;; *) BOX=other ;; esac
fi
[ "$BOX" = webmail ] && cc_show "$C_GRY" "  webmail: SMTP (25) and IMAP (143) are scored: they are checked after any change."

# cf_get KEY -> the value from main.cf (last one wins; continuation lines joined).
cf_get() {
    awk -v k="$1" '
        /^[ \t]+[^ \t#]/ { if (on) { t = $0; sub(/^[ \t]+/, "", t); v = v " " t }; next }
        { on = 0 }
        /^[ \t]*#/ { next }
        { kk = $0; sub(/[ \t]*=.*/, "", kk) }
        index($0, "=") && kk == k { v = $0; sub(/^[^=]*=[ \t]*/, "", v); sub(/[ \t\r]+$/, "", v); on = 1 }
        END { print v }' "$(P "$MAIN")" 2>/dev/null
}
# The finding list, TAB separated (values can hold "|"):
#   level area where what fix arg default    (arg: two parts joined by ";")
TAB=$(printf '\t')
: >"$W/find"
f() { printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$(printf '%s' "$4" | tr '\t' ' ')" "$5" "$6" "$7" >>"$W/find"
    case "$1" in HIGH) cc_show "$C_RED" "  [!] $3: $4" ;; MED) cc_show "$C_YEL" "  [*] $3: $4" ;; esac; }
# outside ADDRESS-LIST -> the addresses that are not ours.
OURS=$(printf '%s' "$DOMAINS" | tr ',' ' ')
if [ -f "$(P "$MAIN")" ]; then
    _md=$(cf_get mydestination | tr ',' ' '); _mh=$(cf_get myhostname); _mo=$(cf_get mydomain)
    OURS="$OURS $(printf '%s' "$_md" | sed "s/\$myhostname/$_mh/g; s/\$mydomain/$_mo/g") $_mh $_mo localhost"
fi
outside() {
    printf '%s\n' "$1" | tr ', ' '\n\n' | grep '@' | sed 's/[<>"]//g' | while IFS= read -r _a; do
        _d=${_a##*@}; _in=0; for _o in $OURS; do [ "$_d" = "$_o" ] && _in=1; done
        [ "$_in" = 0 ] && printf '%s ' "$_a"
    done
}

# ---- Postfix main.cf -------------------------------------------------------------------
header "1/5  Postfix"
if [ -f "$(P "$MAIN")" ]; then
    for _k in always_bcc sender_bcc_maps recipient_bcc_maps; do
        _v=$(cf_get "$_k"); [ -n "$_v" ] && f HIGH postfix "main.cf $_k" "$_k = $_v: a copy of mail goes there" cf-unset "$_k" y
    done
    for _k in mailbox_command mailbox_transport fallback_transport mailbox_command_maps; do
        _v=$(cf_get "$_k")
        case "$_k=$_v" in *=|mailbox_transport=lmtp:unix:private/dovecot-lmtp|mailbox_transport=lmtp:unix:private/lmtp|mailbox_command=/usr/lib/dovecot/deliver*|mailbox_command=/usr/lib/dovecot/dovecot-lda*|mailbox_command=procmail*|mailbox_command=/usr/bin/procmail*) ;;
            *) f HIGH postfix "main.cf $_k" "$_k = $_v: runs on every delivery" cf-unset "$_k" y ;; esac
    done
    _cf=$(cf_get content_filter)
    case "$_cf" in '') ;; amavis*|*spamassassin*|*rspamd*|*clamsmtp*|*spamfilter*) f MED postfix "main.cf content_filter" "content_filter = $_cf: every mail goes through it (a known filter: keep it if it is yours)" cf-unset content_filter n ;;
        *) f HIGH postfix "main.cf content_filter" "content_filter = $_cf: every mail goes through it" cf-unset content_filter y ;; esac
    _rh=$(cf_get relayhost); [ -n "$_rh" ] && f MED postfix "main.cf relayhost" "relayhost = $_rh: outgoing mail goes through that server" cf-unset relayhost n
    _tm=$(cf_get transport_maps); [ -n "$_tm" ] && f MED postfix "main.cf transport_maps" "transport_maps = $_tm: mail for some domains is routed elsewhere (look at the map)" none - n
    for _k in header_checks body_checks; do
        _v=$(cf_get "$_k"); [ -n "$_v" ] || continue
        for _mf in $(printf '%s' "$_v" | tr ',' ' ' | sed 's/^[a-z]*://; s/ [a-z]*:/ /g'); do
            [ -f "$(P "$_mf")" ] && grep -Eiq '[[:space:]](REDIRECT|DISCARD|BCC|FILTER)[[:space:]]' "$(P "$_mf")" && \
                f MED postfix "$_mf" "$_k rules that REDIRECT/DISCARD/BCC/FILTER mail: $(grep -Ei '[[:space:]](REDIRECT|DISCARD|BCC|FILTER)[[:space:]]' "$(P "$_mf")" | head -n 2 | tr '\n' ' ')" none - n
        done
    done
    _mn=$(cf_get mynetworks)
    case " $_mn " in *" 0.0.0.0/0 "*|*" 0/0 "*|*" ::/0 "*|*"[::]/0"*|*" 0.0.0.0/1 "*|*" 128.0.0.0/1 "*)
        f HIGH postfix "main.cf mynetworks" "mynetworks = $_mn: EVERYONE may send mail through this box (open relay)" cf-set "mynetworks;127.0.0.0/8 [::1]/128" y ;; esac
    _rr="$(cf_get smtpd_relay_restrictions) $(cf_get smtpd_recipient_restrictions)"
    case "$_rr" in *reject_unauth_destination*|*defer_unauth_destination*) ;; *)
        case "$(cf_get smtpd_relay_restrictions)" in '') ;; *) f HIGH postfix "main.cf smtpd_relay_restrictions" "relay rules without reject_unauth_destination: mail to anywhere may be relayed" cf-set "smtpd_relay_restrictions;permit_mynetworks permit_sasl_authenticated reject_unauth_destination" y ;; esac ;;
    esac
    # Virtual aliases forwarding outside.
    _va=$(cf_get virtual_alias_maps)
    for _vm in $(printf '%s' "$_va" | tr ',' ' '); do
        case "$_vm" in hash:*|lmdb:*|btree:*|texthash:*) _vf=${_vm#*:} ;; *) continue ;; esac
        [ -f "$(P "$_vf")" ] || continue
        awk '!/^[ \t]*#/ && NF >= 2 { $1 = ""; print }' "$(P "$_vf")" | while IFS= read -r _to; do
            _o=$(outside "$_to"); [ -n "$_o" ] && f MED postfix "$_vf" "a virtual alias sends mail outside: $_o" none - n
        done
    done
fi
# master.cf services that run programs.
if [ -f "$(P "$MASTER")" ]; then
    awk '/^[ \t]*#/ { next } /^[^ \t]/ { if (s != "") print s "|" l; s = $1 "/" $2; l = $0; next } /^[ \t]+/ { t = $0; sub(/^[ \t]+/, " ", t); l = l t } END { if (s != "") print s "|" l }' "$(P "$MASTER")" |
    while IFS='|' read -r _sv _l; do
        case "$_l" in *[[:space:]]pipe[[:space:]]*|*[[:space:]]spawn[[:space:]]*) ;; *) continue ;; esac
        _argv=$(printf '%s' "$_l" | sed -n 's/.*argv=\([^ ]*\).*/\1/p')
        # The services Postfix's own master.cf ships (by program name), and
        # common filters.
        case "${_argv##*/}" in uux|bsmtp|scalemail-store|postfix-to-mailman.py|ifmail|maildrop|deliver|dovecot-lda|amavisd|amavisd-new|spamc|policyd-spf|postfix-policyd-spf-perl|mlmmj-receive) continue ;; esac
        f HIGH postfix "master.cf ${_sv%/*}" "a service that runs ${_argv:-a program}: $(printf '%s' "$_l" | cut -c1-120)" master-off "${_sv%/*};${_sv#*/}" y
    done
fi
[ -s "$W/find" ] || cc_show "$C_GRN" "  [ok] main.cf and master.cf"
NPF=$(grep -c . "$W/find")

# ---- Aliases and users' mail files --------------------------------------------------------
header "2/5  aliases, .forward, procmail"
for _af in /etc/aliases /etc/mail/aliases /etc/postfix/aliases; do
    [ -f "$(P "$_af")" ] || continue
    awk '/^[ \t]*#/ || /^[ \t]*$/ { next } { print NR "\t" $0 }' "$(P "$_af")" | while IFS="$TAB" read -r _n _l; do
        _to=${_l#*:}
        case "$_to" in *'|'*|*':include:'*) f HIGH aliases "$_af line $_n" "mail to ${_l%%:*} runs a program or reads a file: $_to" alias-off "$_af;$_n" y; continue ;; esac
        _o=$(outside "$_to"); [ -n "$_o" ] && f MED aliases "$_af line $_n" "mail to ${_l%%:*} is sent outside: $_o" alias-off "$_af;$_n" n
    done
done
awk -F: '{ print $1 "|" $6 }' "$(P /etc/passwd)" | while IFS='|' read -r _u _h; do
    [ -n "$_h" ] && [ "$_h" != / ] || continue
    for _x in .forward .procmailrc .mailfilter; do
        _ff="$_h/$_x"; [ -f "$(P "$_ff")" ] || continue
        if grep -Eq '^[^#]*(\||:include:|^[[:space:]]*\|)' "$(P "$_ff")"; then f HIGH user "$_ff" "$_u's mail runs a program: $(grep -E '\|' "$(P "$_ff")" | head -n 1 | cut -c1-100)" quarantine "$_ff" y
        else _o=$(outside "$(cat "$(P "$_ff")")"); [ -n "$_o" ] && f MED user "$_ff" "$_u's mail is forwarded outside: $_o" quarantine "$_ff" n; fi
    done
done
[ "$(grep -c . "$W/find")" -gt "$NPF" ] || cc_show "$C_GRN" "  [ok] no alias, .forward or procmail rule runs a program or sends mail out"
NAL=$(grep -c . "$W/find")

# ---- Dovecot: sieve and post-login ------------------------------------------------------
header "3/5  Dovecot"
if [ -d "$(P /etc/dovecot)" ]; then
    { find "$(P /etc/dovecot)" "$(P /var/lib/dovecot)" "$(P /var/mail)" "$(P /home)" "$(P /var/vmail)" -maxdepth 5 -type f \( -name '*.sieve' -o -name '.dovecot.sieve' \) 2>/dev/null; } | sort -u | while IFS= read -r _sf; do
        _l=${_sf#"$R"}
        if grep -Eq 'vnd\.dovecot\.(execute|pipe|filter)|^[^#]*(execute|pipe)[[:space:]]+:?' "$_sf"; then
            f HIGH sieve "$_l" "a sieve script that runs a program: $(grep -E 'execute|pipe' "$_sf" | grep -v '^#' | head -n 1 | cut -c1-100)" quarantine "$_l" y
        elif grep -q 'redirect' "$_sf"; then
            _o=$(outside "$(sed -n 's/.*redirect[^"]*"\([^"]*\)".*/\1/p' "$_sf" | tr '\n' ' ')")
            [ -n "$_o" ] && f MED sieve "$_l" "a sieve script forwards mail outside: $_o" quarantine "$_l" n
        fi
    done
    grep -rhs 'executable[[:space:]]*=.*imap-postlogin\|executable[[:space:]]*=.*script-login\|executable[[:space:]]*=.*postlogin' "$(P /etc/dovecot)" | grep -v '^[[:space:]]*#' | head -n 3 | while IFS= read -r _l; do
        f MED dovecot "/etc/dovecot" "a post-login script runs at every IMAP/POP login: $_l" none - n
    done
fi
[ "$(grep -c . "$W/find")" -gt "$NAL" ] || cc_show "$C_GRN" "  [ok] no sieve script or post-login script runs a program or forwards out"

# ---- The queue ------------------------------------------------------------------------------
header "4/5  the mail queue"
if [ -z "$R" ] && cc_have postqueue; then
    _q=$(postqueue -p 2>/dev/null | tail -n 1 | sed -n 's/.* in \([0-9]*\) Request.*/\1/p'); _q=${_q:-0}
    if [ "$_q" -gt "$QMAX" ]; then f MED queue postfix "$_q mails waiting in the queue: spam going out through this box? (postqueue -p | head; postsuper -d ALL deferred)" none - n
    else cc_show "$C_GRN" "  [ok] $_q mail(s) in the queue"; fi
else cc_show "$C_GRY" "  (not checked)"; fi

# ---- Questions and plan ------------------------------------------------------------------
fix_word() {
    case "$1" in
        cf-unset) echo "remove $2 from main.cf" ;;
        cf-set) echo "set ${2%%";"*} = ${2#*";"}" ;;
        master-off) echo "comment out the master.cf service ${2%%";"*}" ;;
        alias-off) echo "comment out ${2%%";"*} line ${2#*";"} (then newaliases)" ;;
        quarantine) echo "quarantine $2" ;;
    esac
}
header "5/5  fixes"
: >"$W/chosen"
while IFS="$TAB" read -r _lv _ar _wh _wt _fx _arg _df; do
    [ "$_fx" = none ] && continue
    _d=Y; [ "$_df" = n ] && _d=N
    cc_ask "[$_lv] $_wh: $(fix_word "$_fx" "$_arg")?" "$_d" "yes, $(fix_word "$_fx" "$_arg")" "no, leave it" && printf '%s\t%s\t%s\n' "$_fx" "$_arg" "$_wh" >>"$W/chosen"
done <"$W/find"
NCH=$(grep -c . "$W/chosen")
: >"$CC_RUN_DIR/plan.txt"
while IFS="$TAB" read -r _fx _arg _wh; do printf '%s\n' "$(fix_word "$_fx" "$_arg")" >>"$CC_RUN_DIR/plan.txt"; done <"$W/chosen"

# ---- Helpers for the changes -----------------------------------------------------------
backed() { grep -qxF "$1" "$W/backed" 2>/dev/null && return 0; cc_backup_file "$1" >/dev/null || return 1; printf '%s\n' "$1" >>"$W/backed"; }
cf_unset() {   # comment out KEY and its continuation lines
    _m=$(P "$MAIN"); backed "$_m" || return 1
    awk -v k="$1" '
        skip && /^[ \t]+[^ \t]/ { print "#SV-31: " $0; next }
        { skip = 0; kk = $0; sub(/[ \t]*=.*/, "", kk) }
        !/^[ \t]*#/ && index($0, "=") && kk == k { print "#SV-31: " $0; skip = 1; next }
        { print }' "$_m" >"$_m.n" && cat "$_m.n" >"$_m"; _r=$?; rm -f "$_m.n"; return "$_r"
}
cf_set() { cf_unset "$1" && printf '%s = %s\n' "$1" "$2" >>"$(P "$MAIN")"; }
master_off() {   # SERVICE TYPE
    _m=$(P "$MASTER"); backed "$_m" || return 1
    awk -v s="$1" -v t="$2" '
        on && /^[ \t]+/ { print "#SV-31: " $0; next }
        { on = 0 }
        $1 == s && $2 == t && !/^[ \t]*#/ { print "#SV-31: " $0; on = 1; next }
        { print }' "$_m" >"$_m.n" && cat "$_m.n" >"$_m"; _r=$?; rm -f "$_m.n"; return "$_r"
}
alias_off() {   # FILE LINE
    _m=$(P "$1"); backed "$_m" || return 1
    awk -v n="$2" 'NR == n { print "#SV-31: " $0; next } { print }' "$_m" >"$_m.n" && cat "$_m.n" >"$_m"; _r=$?; rm -f "$_m.n"
    printf '%s\n' "$1" >>"$W/newaliases"; return "$_r"
}
banners() {   # banners -> "SMTP IMAP" each ok/no/-
    _sm=-; _im=-
    if cc_have nc; then
        ss -ltn 2>/dev/null | grep -q ':25 ' && { _b=$( { sleep 2; } | timeout 6 nc -w 3 127.0.0.1 25 2>/dev/null | head -n 1); case "$_b" in 220*) _sm=ok ;; *) _sm=no ;; esac; }
        ss -ltn 2>/dev/null | grep -q ':143 ' && { _b=$( { sleep 2; } | timeout 6 nc -w 3 127.0.0.1 143 2>/dev/null | head -n 1); case "$_b" in '* OK'*) _im=ok ;; *) _im=no ;; esac; }
    fi
    printf '%s %s' "$_sm" "$_im"
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
    APPLIED=1; : >"$W/backed"; : >"$W/newaliases"
    U0=$(grep -c . "$CC_UNDO" 2>/dev/null)
    B0=$( [ -z "$R" ] && banners)
    if [ "$NOTIMER" != 1 ] && [ -z "$R" ]; then cc_timer_start "$TIMER"; TIMER_ON=1
        cc_show "$C_YEL" "  [*] Revert timer started: everything is undone in $((TIMER / 60)):$(printf '%02d' $((TIMER % 60))) unless you keep it at the end."; fi
    # Postfix reloads after its files come back on an undo.
    if [ -z "$R" ] && awk -F'\t' '$1 ~ /^(cf-|master|alias)/' "$W/chosen" | grep -q .; then
        cc_undo_add "newaliases and reload Postfix after its files are put back" "newaliases 2>/dev/null; postfix reload 2>/dev/null"
    fi
    while IFS="$TAB" read -r _fx _arg _wh; do
        case "$_fx" in
            cf-unset) cf_unset "$_arg" ;;
            cf-set) cf_set "${_arg%%;*}" "${_arg#*;}" ;;
            master-off) master_off "${_arg%%;*}" "${_arg#*;}" ;;
            alias-off) alias_off "${_arg%%;*}" "${_arg#*;}" ;;
            quarantine) cc_quarantine "$(P "$_arg")" >>"$CC_LOG" 2>&1 ;;
        esac
        if [ $? -eq 0 ]; then NOK=$((NOK + 1)); cc_show "$C_GRN" "  [+] $(fix_word "$_fx" "$_arg")"; else NBAD=$((NBAD + 1)); cc_show "$C_RED" "  [x] FAILED: $(fix_word "$_fx" "$_arg")"; fi
    done <"$W/chosen"
    if [ -z "$R" ]; then
        [ -s "$W/newaliases" ] && { newaliases >>"$CC_LOG" 2>&1 || cc_show "$C_RED" "  [x] newaliases failed"; }
        if [ -s "$W/backed" ] && grep -q postfix "$W/backed"; then
            if postfix check >>"$CC_LOG" 2>&1; then postfix reload >>"$CC_LOG" 2>&1 && cc_show "$C_GRN" "  [+] Postfix reloaded"
            else BROKE=1; cc_show "$C_RED" "  [x] postfix check FAILS after the changes"; fi
        fi
        sleep 2; B1=$(banners)
        set -- $B0; _s0=$1; _i0=$2; set -- $B1; _s1=$1; _i1=$2
        [ "$_s0" = ok ] && [ "$_s1" != ok ] && { BROKE=1; cc_show "$C_RED" "  [x] SMTP on 25 stopped answering"; }
        [ "$_i0" = ok ] && [ "$_i1" != ok ] && { BROKE=1; cc_show "$C_RED" "  [x] IMAP on 143 stopped answering"; }
        [ "$BROKE" = 0 ] && cc_show "$C_GRN" "  [+] SMTP: $_s1   IMAP: $_i1 (as before)"
        if [ "$BROKE" = 1 ]; then
            cc_show "$C_RED" "  Putting everything back now ..."
            awk -F'\t' -v n="${U0:-0}" 'NR > n { l[NR] = $4 } END { for (i = NR; i > n; i--) print l[i] }' "$CC_UNDO" >"$W/undo-now"
            while IFS= read -r _cmd; do sh -c "$_cmd" >>"$CC_LOG" 2>&1; done <"$W/undo-now"
            [ "$TIMER_ON" = 1 ] && cc_timer_cancel 2>/dev/null; TIMER_ON=0
        fi
    fi
else cc_show "$C_GRY" "  Not applied. The plan is in $CC_RUN_DIR/plan.txt"; fi
# shellcheck disable=SC2034  # read by cc_finish
CC_N_DONE=$NOK
# shellcheck disable=SC2034  # read by cc_finish
CC_N_FAIL=$NBAD

# ---- Summary ----------------------------------------------------------------------------
awk -F'\t' '{ printf "%-4s %-8s %-40s %s\n", $1, $2, $3, $4 }' "$W/find" >"$CC_RUN_DIR/findings.txt"
{
    printf '==========[ summary ]==========\n'
    printf 'SV-31 Mail tamper check | host %s | %s\n' "$CC_HOST" "$([ "$APPLIED" = 1 ] && { [ "$BROKE" = 1 ] && echo 'APPLIED, then PUT BACK (mail stopped answering)' || echo APPLIED; } || echo 'DRY RUN - nothing changed')"
    printf 'Found: %d HIGH, %d MED\n' "$(grep -c "^HIGH$TAB" "$W/find")" "$(grep -c "^MED$TAB" "$W/find")"
    awk -F'\t' '{ printf "  %-4s %s: %s\n", $1, $3, substr($4, 1, 110) }' "$W/find"
    [ -s "$CC_RUN_DIR/plan.txt" ] && { printf '\nChanges%s:\n' "$([ "$APPLIED" = 1 ] || echo ' planned')"; sed 's/^/  /' "$CC_RUN_DIR/plan.txt"; }
    [ "$APPLIED" = 1 ] && printf 'Done: %d   Failed: %d\n' "$NOK" "$NBAD"
    [ "$APPLIED" = 1 ] && [ -f "$CC_RUN_DIR/revert.sh" ] && printf 'Undo this run: sh %s/revert.sh --force\n' "$CC_RUN_DIR"
    printf '\nAlso: banner, VRFY, HELO SV-30; mail passwords SV-40; webmail SV-41.\n'
} >"$CC_RUN_DIR/summary.txt"
cc_show "" ""
while IFS= read -r _l; do
    case "$_l" in ==*|SV-31*) cc_show "$C_CYN" "$_l" ;; '  HIGH'*|*'PUT BACK'*) cc_show "$C_RED" "$_l" ;; '  MED'*) cc_show "$C_YEL" "$_l" ;; *) cc_show "" "$_l" ;; esac
done <"$CC_RUN_DIR/summary.txt"
rm -rf "$W"
if [ "$TIMER_ON" = 1 ]; then header "KEEP OR REVERT"; cc_show "$C_YEL" "[*] Before you answer: send a test mail and log in to the webmail."; cc_timer_finish || true; fi
cc_finish
