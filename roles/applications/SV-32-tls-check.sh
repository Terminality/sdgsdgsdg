#!/bin/sh
# =============================================================================
# ID:       SV-32
# NAME:     TLS certificate check
# ROLE:     Applications  (wave 1 look, wave 2 fixes)
# KIND:     changes - dry run unless --apply
# VERSION:  1.0.0
#
# PURPOSE
#   HTTPS, IMAPS, POP3S and SMTP with STARTTLS all hang on a certificate and
#   its private key.  Red team swaps the certificate, steals a key anyone
#   can read, or turns on old TLS so traffic can be broken.  This looks at:
#     files    every certificate and key named in the Apache, nginx,
#              Dovecot, Postfix, vsftpd and MariaDB/MySQL configs:
#              expired or about to, not matching its key, self-signed,
#              weak key (< 2048 bits), SHA-1 / MD5 signature, a key file
#              others can read
#     served   each TLS port on this box (443, 8443, 993, 995, 465, and
#              STARTTLS on 25, 587, 143, 110, 21, 3306): the certificate it
#              really serves, whether it still takes TLS 1.0 / 1.1 or weak
#              ciphers (RC4, 3DES, NULL, anonymous)
#     changes  a fingerprint baseline: a certificate that changed since the
#              first run is flagged (a swap)
#
#   QUESTIONS (Enter takes the default in capitals; a flag answers each):
#     a key others can read        [f]ix it (chmod 600) / [l]eave      f
#     a broken or expired cert     [n]ew self-signed one / [l]eave
#                                  (default n only when it was self-signed:
#                                   nothing a CA signed is replaced on its own)
#     old TLS / weak ciphers       [f]ix the config (TLS 1.2+, strong
#                                  ciphers; tested, reloaded, checked) / [l]   f
#     changed since the baseline   [k]eep flagging it / [u]se it as the
#                                  new baseline                         k
#     apply?                       --apply
#
# USAGE
#   sudo sh SV-32-tls-check.sh                                  look + dry run
#   sudo sh SV-32-tls-check.sh --protected p.csv --apply        asks each fix
#   sudo sh SV-32-tls-check.sh --protected p.csv --apply --batch
#
# OPTIONS
#   --apply            make the changes (without it, dry run only)
#   --port P[:PROTO[:SERVICE]]  also probe this port (repeatable); PROTO is
#                      a STARTTLS kind (smtp imap pop3 ftp mysql) or tls;
#                      SERVICE (apache2 nginx dovecot postfix) whose config
#                      to fix when the program is not seen
#   --host NAME        address to probe (default 127.0.0.1)
#   --days N           warn when a certificate ends within N days (default 14)
#   --no-probe         do not connect to the ports, files only
#   --root DIR         treat DIR as / for the files (tests): nothing reloaded
#   --no-color         no colours
#   --help             this text plus the common options
#
# OUTPUTS  (under --out, in tls-N/)
#   output.txt, certs.txt, served.txt, findings.txt, summary.txt
#   tls-baseline-HOST.txt (in --out): fingerprints only, never a key
#
# DEPENDS ON
#   openssl (the command), ss; timeout when there (a probe never hangs).
#
# TESTED ON
#   OpenSSL 3.0 on Ubuntu 24.04: certificates and configs in a fake root
#   (expired, weak, mismatched, readable key) and openssl s_server
#   stand-ins on high ports, under dash, bash, busybox sh, ksh93, mksh and
#   yash with gawk, mawk and busybox awk.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - A new self-signed certificate makes browsers and a scoring check that
#     verifies certificates complain.  That is why a CA-signed one is never
#     replaced by default.
#   - Old TLS off can lock out a very old client.  The fix is checked with a
#     TLS 1.2 connection and put back if the port stops answering.
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
SV-32 TLS certificate check - certificates, keys, what each port serves, old TLS
  sudo sh SV-32-tls-check.sh                             look + dry run
  sudo sh SV-32-tls-check.sh --protected p.csv --apply   asks each fix

  --apply            make the changes (without it, dry run only)
  --port P[:PROTO[:SERVICE]]  also probe this port; PROTO: tls smtp imap pop3 ftp mysql
                     SERVICE: apache2 nginx dovecot postfix (whose config to fix)
  --host NAME        address to probe (default 127.0.0.1)
  --days N           warn when a certificate ends within N days (default 14)
  --no-probe         files only, no connections
  --root DIR         treat DIR as / for the files (tests)
  --no-color         no colours
  --help             show this text
USAGE
    cc_usage_common
}

NL='
'
EXTRA=""; PHOST=127.0.0.1; DAYS=14; PROBE=1; R=""; COLOR=1
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --apply)    CC_APPLY=1; shift ;;
        --port)     [ $# -ge 2 ] || cc_die 2 "--port needs a port"; EXTRA="$EXTRA$2$NL"; shift 2 ;;
        --host)     [ $# -ge 2 ] || cc_die 2 "--host needs a name"; PHOST=$2; shift 2 ;;
        --days)     [ $# -ge 2 ] || cc_die 2 "--days needs a number"; DAYS=$2; shift 2 ;;
        --no-probe) PROBE=0; shift ;;
        --root)     [ $# -ge 2 ] || cc_die 2 "--root needs a folder"; [ -d "$2" ] || cc_die 2 "--root: not a folder: $2"; R=$(cd "$2" && pwd); [ "$R" = / ] && R=""; shift 2 ;;
        --no-color|--no-colour) COLOR=0; shift ;;
        --help|-h)  usage; exit 0 ;;
        *)          cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
case "$DAYS" in ''|*[!0-9]*) cc_die 2 "--days needs a whole number" ;; esac
printf '%s' "$EXTRA" | grep -v '^[0-9]\{1,5\}\(:\(tls\|smtp\|imap\|pop3\|ftp\|mysql\)\(:\(apache2\|nginx\|dovecot\|postfix\)\)\{0,1\}\)\{0,1\}$' | grep -q . && cc_die 2 "--port: PORT, PORT:PROTO or PORT:PROTO:SERVICE (tls smtp imap pop3 ftp mysql; apache2 nginx dovecot postfix)"
printf '%s' "$PHOST" | grep -q '^[A-Za-z0-9.:-]*$' || cc_die 2 "--host: a name or address"

cc_init "SV-32" "TLS certificate check" changes
cc_detect_os
# shellcheck disable=SC2034  # read by cc_color_init
[ "$COLOR" = 1 ] || CC_NOCOLOR=1
cc_color_init
cc_use_numbered_dir tls
rmdir "$CC_RUN_DIR/raw" 2>/dev/null
OUTF="$CC_RUN_DIR/output.txt"
grep -v '\[NOTE\]\|\[DEBUG\]' "$CC_LOG" >"$OUTF" 2>/dev/null || : >"$OUTF"
# shellcheck disable=SC2034  # CC_TEE is read by the library's log functions
CC_TEE=$OUTF
W="$CC_RUN_DIR/.work"; mkdir -p "$W"
US=$(printf '\037')
header() { cc_show "" ""; cc_show "$C_CYN" "==========[ $1 ]=========="; }
P() { printf '%s%s' "$R" "$1"; }
# real FILE -> the file a symlink chain ends at (inside --root too).  Edits and
# backups go to the real file: a backup of the link would restore nothing.
real() {
    _rf=$1; _ri=0
    while [ -h "$_rf" ] && [ "$_ri" -lt 10 ]; do
        _rl=$(readlink "$_rf"); case "$_rl" in /*) _rf="$R$_rl" ;; *) _rf="$(dirname "$_rf")/$_rl" ;; esac; _ri=$((_ri + 1))
    done
    printf '%s' "$_rf"
}
TO=""; cc_have timeout && TO="timeout 8"
cc_have openssl || { cc_show "$C_RED" "[x] the openssl command is missing (apt-get install openssl)"; rm -rf "$W"; cc_finish; exit 3; }

cc_show "$C_CYN" "SV-32 TLS certificate check | host $CC_HOST | results in $CC_RUN_DIR"
cc_show "" "Legend: ${C_RED}[!]${C_OFF} fix now   ${C_YEL}[*]${C_OFF} look at it   ${C_GRN}[ok]${C_OFF} fine   ${C_YEL}[~] would change${C_OFF}   ${C_GRN}[+] changed${C_OFF}   ${C_RED}[x] failed${C_OFF}"
[ -n "$R" ] && cc_show "$C_GRY" "Acting on $R as if it were / (nothing reloaded)"
: >"$W/find"   # level US service US what US fix US target US default
finding() { printf '%s\037%s\037%s\037%s\037%s\037%s\n' "$1" "$2" "$3" "$4" "$5" "$6" >>"$W/find"
    case "$1" in HIGH) cc_show "$C_RED" "  [!] $2: $3" ;; MED) cc_show "$C_YEL" "  [*] $2: $3" ;; esac; }

# ---- 1. Certificate files in the configs ----------------------------------------------------------
header "1/5  certificates in the configs"
# pairs FILES... (stdin: style) -> "service|conf|cert|key" from one service's configs
# awk reads KEY VALUE lines; cert and key pair up in the order they come.
pairs() {
    _svc=$1; _ck=$2; _kk=$3; shift 3
    for _f in "$@"; do
        [ -f "$_f" ] || continue
        awk -v s="$_svc" -v ck="$_ck" -v kk="$_kk" -v f="${_f#"$R"}" '
            { l = $0; sub(/^[ \t]+/, "", l); if (l ~ /^[#;]/) next
              n = split(l, w, /[ \t=]+/); if (n < 2) next; k = tolower(w[1]); v = w[2]
              if (v == "<" || v == "") v = w[3]; sub(/^</, "", v); gsub(/[";]/, "", v)
              if (k == ck) { if (c != "") out(); c = v } else if (k == kk) k2 = v; else next
              if (c != "" && k2 != "") out() }
            function out() { print s "|" f "|" c "|" (k2 == "" ? c : k2); c = ""; k2 = "" }  # awk, not shell: posix-ok
            END { if (c != "") out() }' "$_f"
    done
}
{
    pairs apache2 sslcertificatefile sslcertificatekeyfile "$(P /etc/apache2/sites-enabled)"/* "$(P /etc/apache2/mods-enabled)"/*.conf "$(P /etc/httpd/conf.d)"/*.conf "$(P /etc/httpd/conf/httpd.conf)"
    # snippets only when an enabled site includes them (Ubuntu's snakeoil.conf)
    _sn=$(cat "$(P /etc/nginx/sites-enabled)"/* "$(P /etc/nginx/conf.d)"/*.conf 2>/dev/null | sed -n 's|^[[:space:]]*include[[:space:]]\{1,\}\(snippets/[^;[:space:]]*\);.*|\1|p' | sort -u | while IFS= read -r _x; do printf '%s ' "$(P "/etc/nginx/$_x")"; done)
    # shellcheck disable=SC2086  # a list of files
    pairs nginx ssl_certificate ssl_certificate_key "$(P /etc/nginx/nginx.conf)" "$(P /etc/nginx/sites-enabled)"/* "$(P /etc/nginx/conf.d)"/*.conf $_sn
    pairs dovecot ssl_cert ssl_key "$(P /etc/dovecot/dovecot.conf)" "$(P /etc/dovecot/conf.d)"/*.conf
    pairs dovecot ssl_server_cert_file ssl_server_key_file "$(P /etc/dovecot/dovecot.conf)" "$(P /etc/dovecot/conf.d)"/*.conf
    pairs postfix smtpd_tls_cert_file smtpd_tls_key_file "$(P /etc/postfix/main.cf)"
    pairs vsftpd rsa_cert_file rsa_private_key_file "$(P /etc/vsftpd.conf)" "$(P /etc/vsftpd/vsftpd.conf)"
    pairs mysql ssl-cert ssl-key "$(P /etc/mysql/my.cnf)" "$(P /etc/mysql/mariadb.conf.d)"/*.cnf "$(P /etc/mysql/mysql.conf.d)"/*.cnf "$(P /etc/my.cnf)" "$(P /etc/my.cnf.d)"/*.cnf
    pairs mysql ssl_cert ssl_key "$(P /etc/mysql/my.cnf)" "$(P /etc/mysql/mariadb.conf.d)"/*.cnf "$(P /etc/mysql/mysql.conf.d)"/*.cnf "$(P /etc/my.cnf)" "$(P /etc/my.cnf.d)"/*.cnf
} | grep -v '|\$' | sort -u >"$W/pairs"
# one line per cert|key with every service that uses it
awk -F'|' '{ k = $3 "|" $4; if (!(k in s)) { o[++n] = k; s[k] = $1 } else if (index("," s[k] ",", "," $1 ",") == 0) s[k] = s[k] "," $1 }
    END { for (i = 1; i <= n; i++) print s[o[i]] "|" o[i] }' "$W/pairs" >"$W/certs"
# Debian's default snakeoil pair counts too when a service uses no explicit one.
[ -s "$W/certs" ] || { [ -f "$(P /etc/ssl/certs/ssl-cert-snakeoil.pem)" ] && printf 'default|/etc/ssl/certs/ssl-cert-snakeoil.pem|/etc/ssl/private/ssl-cert-snakeoil.key\n' >"$W/certs"; }
fp() { openssl x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//'; }
printf '%-16s %-44s %-22s %-26s %-6s %-10s %s\n' service certificate "name (CN)" "ends" bits signature notes >"$CC_RUN_DIR/certs.txt"
NCERT=0
while IFS='|' read -r _svc _c _k; do
    NCERT=$((NCERT + 1)); _rc=$(P "$_c"); _rk=$(P "$_k")
    cc_show "" ""
    cc_show "$C_CYN" "  $_c  (used by $_svc)"
    if [ ! -r "$_rc" ]; then finding HIGH "$_svc" "the certificate file is missing: $_c - the service will not start" new "$_c|$_k|$_svc" n; printf '%-16s %-44s missing\n' "$_svc" "$_c" >>"$CC_RUN_DIR/certs.txt"; continue; fi
    _txt=$(openssl x509 -in "$_rc" -noout -text 2>/dev/null)
    [ -n "$_txt" ] || { finding HIGH "$_svc" "not a certificate openssl can read: $_c" new "$_c|$_k|$_svc" l; continue; }
    _cn=$(openssl x509 -in "$_rc" -noout -subject 2>/dev/null | sed -n 's/.*CN *= *\([^,/]*\).*/\1/p')
    _sub=$(openssl x509 -in "$_rc" -noout -subject 2>/dev/null | sed 's/^subject= *//'); _iss=$(openssl x509 -in "$_rc" -noout -issuer 2>/dev/null | sed 's/^issuer= *//')
    _end=$(openssl x509 -in "$_rc" -noout -enddate 2>/dev/null | sed 's/^notAfter=//')
    _bits=$(printf '%s\n' "$_txt" | sed -n 's/.*Public-Key: (\([0-9]*\) bit).*/\1/p' | head -n 1)
    _alg=$(printf '%s\n' "$_txt" | sed -n 's/^ *Signature Algorithm: *//p' | head -n 1)
    _self=n; [ "$_sub" = "$_iss" ] && _self=y
    _ec=n; printf '%s' "$_txt" | grep -q 'id-ecPublicKey\|ED25519\|ED448' && _ec=y
    _notes=""; _dflt=l; [ "$_self" = y ] && { _dflt=n; _notes="self-signed "; }
    cc_show "" "    name $_cn | ends $_end | ${_bits:-?} bit | $_alg$([ "$_self" = y ] && echo ' | self-signed') | issuer $_iss"
    if ! openssl x509 -in "$_rc" -noout -checkend 0 >/dev/null 2>&1; then
        finding HIGH "$_svc" "EXPIRED on $_end: clients and scoring checks that verify it fail" new "$_c|$_k|$_svc" "$_dflt"; _notes="${_notes}EXPIRED "
    elif ! openssl x509 -in "$_rc" -noout -checkend $((DAYS * 86400)) >/dev/null 2>&1; then
        finding MED "$_svc" "ends within $DAYS days ($_end)" new "$_c|$_k|$_svc" "$_dflt"; _notes="${_notes}ends-soon "
    else cc_show "$C_GRN" "    [ok] valid until $_end"; fi
    if [ "$_ec" = n ] && [ -n "$_bits" ] && [ "$_bits" -lt 2048 ]; then finding MED "$_svc" "weak key: $_bits bit RSA (2048 or more)" new "$_c|$_k|$_svc" "$_dflt"; _notes="${_notes}weak-key "; fi
    case "$_alg" in *[Ss][Hh][Aa]1[Ww]*|*[Mm][Dd]5*|*-[Ss][Hh][Aa]1*) finding MED "$_svc" "weak signature: $_alg" new "$_c|$_k|$_svc" "$_dflt"; _notes="${_notes}weak-signature " ;; esac
    # the key
    if [ ! -e "$_rk" ]; then finding HIGH "$_svc" "the key file is missing: $_k - the service will not start" new "$_c|$_k|$_svc" "$_dflt"; _notes="${_notes}no-key "
    else
        _cpk=$(openssl x509 -in "$_rc" -noout -pubkey 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | cksum)
        _kpk=$(openssl pkey -in "$_rk" -passin pass: -pubout -outform DER 2>/dev/null | cksum)
        if [ ! -r "$_rk" ]; then finding MED "$_svc" "cannot read the key $_k (run as root to check it)" "" "" ""
        elif [ -z "$_kpk" ] || [ "$_kpk" = "$(printf '' | cksum)" ]; then finding MED "$_svc" "the key $_k cannot be read without a passphrase (or is not a key)" "" "" ""
        elif [ "$_cpk" != "$_kpk" ]; then finding HIGH "$_svc" "the certificate does NOT match its key $_k: TLS fails (a swapped certificate or key?)" new "$_c|$_k|$_svc" "$_dflt"; _notes="${_notes}KEY-MISMATCH "
        else cc_show "$C_GRN" "    [ok] matches its key $_k"; fi
        # who can read the key
        _ls=$(ls -lnL "$_rk" 2>/dev/null); _mode=$(printf '%s' "$_ls" | cut -c1-10); _ouid=$(printf '%s' "$_ls" | awk '{ print $3 }'); _ogid=$(printf '%s' "$_ls" | awk '{ print $4 }')
        _gname=$(awk -F: -v g="$_ogid" '$3 == g { print $1; exit }' "$(P /etc/group)" 2>/dev/null)
        case "$_mode" in
            ???????r??|????????w?) finding HIGH "$_svc" "the private key $_k can be read by every user ($_mode): anyone can decrypt or impersonate the site" perm "$_k" f ;;
            ????r?????) case "$_gname" in root|ssl-cert|ssl|mail|dovecot|postfix|www-data|nginx|apache|mysql|"") ;; *) finding MED "$_svc" "the private key $_k can be read by the group $_gname ($_mode)" perm "$_k" f ;; esac ;;
        esac
        _on=$(awk -F: -v u="$_ouid" '$3 == u { print $1; exit }' "$(P /etc/passwd)" 2>/dev/null)
        # MariaDB reads its key as the mysql user: that owner is right there.
        case "$_ouid:$_on:$_svc" in 0:*|:*|*:mysql:*mysql*) ;; *) finding MED "$_svc" "the private key $_k belongs to ${_on:-uid $_ouid}, not root" "" "" "" ;; esac
    fi
    printf '%-16s %-44s %-22s %-26s %-6s %-10s %s\n' "$_svc" "$_c" "${_cn:--}" "$_end" "${_bits:-?}" "$(printf '%s' "$_alg" | cut -c1-10)" "${_notes:-ok}" >>"$CC_RUN_DIR/certs.txt"
    printf '%s|%s|%s\n' "$_c" "$(fp "$_rc")" "$_svc" >>"$W/fps"
done <"$W/certs"
[ "$NCERT" -eq 0 ] && cc_show "$C_GRY" "  No certificate named in the Apache, nginx, Dovecot, Postfix, vsftpd or MariaDB configs."

# ---- 2. What the ports serve ----------------------------------------------------------------------
header "2/5  what each TLS port serves"
printf '%-6s %-6s %-16s %-10s %-9s %-8s %s\n' port kind program "TLS1.0/1.1" "weak-ciph" matches certificate >"$CC_RUN_DIR/served.txt"
: >"$W/ports"
if [ "$PROBE" = 1 ]; then
    if [ -z "$R" ]; then
        ss -ltnpH 2>/dev/null | awk '{ a = $4; sub(/.*:/, "", a); p = "-"; if (match($0, /\(\("[^"]+"/)) p = substr($0, RSTART + 3, RLENGTH - 4); print a "|" p }' | sort -t'|' -k1,1n -u | while IFS='|' read -r _p _prog; do
            case "$_p" in 443|8443|993|995|465|636|989|990|5986|8089) printf '%s|tls|%s\n' "$_p" "$_prog" ;; 25|587) printf '%s|smtp|%s\n' "$_p" "$_prog" ;; 143) printf '%s|imap|%s\n' "$_p" "$_prog" ;;
                110) printf '%s|pop3|%s\n' "$_p" "$_prog" ;; 21) printf '%s|ftp|%s\n' "$_p" "$_prog" ;; 3306) printf '%s|mysql|%s\n' "$_p" "$_prog" ;; esac
        done >>"$W/ports"
    fi
    printf '%s' "$EXTRA" | while IFS=: read -r _p _k _sv; do [ -n "$_p" ] && printf '%s|%s|%s\n' "$_p" "${_k:-tls}" "${_sv:--}"; done >>"$W/ports"
fi
# probe PORT KIND [s_client options] -> s_client output; 0 when a handshake happened
probe() {
    _pp=$1; _pk=$2; shift 2
    _st=""; [ "$_pk" = tls ] || _st="-starttls $_pk"
    # shellcheck disable=SC2086  # $TO and $_st are words on purpose
    $TO openssl s_client -connect "$PHOST:$_pp" -servername "$PHOST" $_st "$@" </dev/null >"$W/probe" 2>&1
    grep -q 'Cipher is [A-Z0-9]' "$W/probe" && ! grep -q 'Cipher is (NONE)' "$W/probe"
}
NPORT=0; : >"$W/fixtls"
while IFS='|' read -r _p _k _prog; do
    [ -n "$_p" ] || continue
    if ! probe "$_p" "$_k"; then
        case "$_k" in imap|pop3|ftp) finding MED "port $_p ($_prog)" "$_k without TLS: passwords cross the network in clear text (turn on STARTTLS)" "" "" "" ;; *) cc_show "$C_GRY" "  port $_p ($_k, $_prog): no TLS handshake" ;; esac
        printf '%-6s %-6s %-16s no TLS handshake\n' "$_p" "$_k" "$_prog" >>"$CC_RUN_DIR/served.txt"; continue; fi
    NPORT=$((NPORT + 1))
    _sfp=$(openssl x509 -in "$W/probe" -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//')
    _scn=$(openssl x509 -in "$W/probe" -noout -subject 2>/dev/null | sed -n 's/.*CN *= *\([^,/]*\).*/\1/p')
    _send=$(openssl x509 -in "$W/probe" -noout -enddate 2>/dev/null | sed 's/^notAfter=//')
    _file=$(awk -F'|' -v f="$_sfp" '$2 == f { printf "%s%s", (n++ ? ", " : ""), $1 }' "$W/fps" 2>/dev/null)
    _old=n; probe "$_p" "$_k" -tls1 -cipher 'DEFAULT@SECLEVEL=0' && _old=y
    [ "$_old" = n ] && probe "$_p" "$_k" -tls1_1 -cipher 'DEFAULT@SECLEVEL=0' && _old=y
    _weak=n; probe "$_p" "$_k" -tls1_2 -cipher 'RC4:3DES:DES:NULL:EXPORT:aNULL:eNULL:MD5@SECLEVEL=0' && _weak=y
    cc_show "$C_CYN" "  port $_p ($_k, $_prog): serves $_scn, ends $_send"
    printf '%-6s %-6s %-16s %-10s %-9s %-8s %s\n' "$_p" "$_k" "$_prog" "$_old" "$_weak" "$([ -n "$_file" ] && echo yes || echo NO)" "${_file:-$_scn}" >>"$CC_RUN_DIR/served.txt"
    _svc=$(case "$_prog" in apache2|httpd) echo apache2 ;; postfix) echo postfix ;; nginx) echo nginx ;; dovecot|imap-login|pop3-login) echo dovecot ;; master|smtpd) echo postfix ;; *) echo "" ;; esac)
    if [ -z "$_file" ] && [ -s "$W/fps" ]; then finding MED "port $_p" "serves a certificate ($_scn) that is not in any config file read above - another program or a swapped file?" "" "" ""
    elif [ -n "$_file" ]; then cc_show "$C_GRN" "    [ok] the certificate from $_file"; fi
    if [ "$_old" = y ] || [ "$_weak" = y ]; then
        _what=""; [ "$_old" = y ] && _what="TLS 1.0/1.1"; [ "$_weak" = y ] && _what="${_what:+$_what and }weak ciphers (RC4/3DES/NULL/anonymous)"
        if [ -n "$_svc" ] && ! grep -q "^$_svc|" "$W/fixtls"; then printf '%s|%s\n' "$_svc" "$_p" >>"$W/fixtls"; finding MED "port $_p ($_svc)" "still takes $_what" tls "$_svc|$_p" f
        else finding MED "port $_p ($_prog)" "still takes $_what - fix it in that program's config" "" "" ""; fi
    else cc_show "$C_GRN" "    [ok] TLS 1.2+ only, no weak ciphers"; fi
done <"$W/ports"
[ "$PROBE" = 1 ] && [ ! -s "$W/ports" ] && cc_show "$C_GRY" "  No TLS port is listening here."
[ "$PROBE" = 0 ] && cc_show "$C_GRY" "  Not probed (--no-probe)."

# ---- 3. Baseline ------------------------------------------------------------------------------------
header "3/5  changes since the baseline"
BASE="$CC_OUT/tls-baseline-$CC_HOST.txt"
if [ ! -s "$W/fps" ]; then cc_show "$C_GRY" "  No certificate to compare."
elif [ ! -f "$BASE" ]; then
    cut -d'|' -f1,2 "$W/fps" >"$BASE"; cc_show "$C_GRN" "  [ok] first run: fingerprints saved as the baseline ($BASE)"
else
    while IFS='|' read -r _c _f _svc; do
        _b=$(awk -F'|' -v c="$_c" '$1 == c { print $2; exit }' "$BASE")
        if [ -z "$_b" ]; then cc_show "$C_YEL" "  [*] new since the baseline (added to it): $_c"; printf '%s|%s\n' "$_c" "$_f" >>"$BASE"
        elif [ "$_b" != "$_f" ]; then finding HIGH "$_svc" "$_c CHANGED since the baseline (was ${_b%"${_b#???????????}"}..., now ${_f%"${_f#???????????}"}...): if your team did not change it, put back your backup copy" base "$_c|$_f" k
        else cc_show "$C_GRN" "  [ok] unchanged: $_c"; fi
    done <"$W/fps"
fi

# ---- 4. Questions and changes ---------------------------------------------------------------------
header "4/5  fixes"
: >"$W/plan"
while IFS="$US" read -r _lv _svc _what _fix _tg _d; do
    [ -n "$_fix" ] || continue
    _ak="$_fix ${_tg%%"|"*}"; grep -qxF "$_ak" "$W/asked" 2>/dev/null && continue
    printf '%s\n' "$_ak" >>"$W/asked"
    case "$_fix" in
        perm) cc_choose "$_svc: $_what. What now?" "$_d" "f=fix it: only the owner (and a service group) can read it (chmod 600 / 640)" "l=leave it" ;;
        new)  # every problem of this certificate in one question
              _what=$(awk -F"$US" -v c="${_tg%%"|"*}" '$4 == "new" && index($5, c "|") == 1 { printf "%s%s", (n++ ? "; " : ""), $3 }' "$W/find")
              cc_choose "$_svc, ${_tg%%"|"*}: $_what. What now?" "$_d" "n=new self-signed certificate and key (same name, 1 year; the old pair is backed up)" "l=leave it" ;;
        tls)  cc_choose "$_svc: $_what. What now?" "$_d" "f=fix the config: TLS 1.2 and 1.3 only, strong ciphers (tested, reloaded, put back if the port stops answering)" "l=leave it" ;;
        base) cc_choose "$_svc: $_what. What now?" "$_d" "k=keep flagging it (the baseline stays)" "u=use it as the new baseline (your team changed it)" ;;
    esac
    case "$CC_CHOICE" in f|n|u) printf '%s\037%s\037%s\n' "$_fix" "$_tg" "$_svc" >>"$W/plan" ;; esac
done <"$W/find"
plan_word() { case "$1" in perm) echo "only the owner can read $2" ;; new) echo "new self-signed certificate ${2%%"|"*}" ;; tls) echo "TLS 1.2+ and strong ciphers for ${2%%"|"*}" ;; base) echo "new baseline for ${2%%"|"*}" ;; esac; }
NCH=$(grep -c . "$W/plan")
while IFS="$US" read -r _fix _tg _svc; do cc_show "$C_YEL" "  [~] $(plan_word "$_fix" "$_tg")"; done <"$W/plan"
[ "$NCH" -eq 0 ] && cc_show "$C_GRN" "  [ok] Nothing to change."

# set_kv FILE STYLE KEY VALUE -> replace KEY's value in FILE (0: found)
# STYLE: sp "Key value" | ng "key value;" | eq "key = value"
set_kv() {
    awk -v st="$2" -v k="$3" -v v="$4" '
        { l = $0; sub(/^[ \t]+/, "", l); n = split(l, w, /[ \t=]+/) }
        n > 0 && tolower(w[1]) == tolower(k) && l !~ /^[#;]/ { i = $0; sub(/[^ \t].*$/, "", i)
            if (st == "sp") $0 = i k " " v; else if (st == "ng") $0 = i k " " v ";"; else $0 = i k " = " v; hit = 1 }
        { print } END { exit hit ? 0 : 1 }' "$1" >"$1.ccdc" && { cat "$1.ccdc" >"$1"; rm -f "$1.ccdc"; return 0; }
    rm -f "$1.ccdc"; return 1
}
# add_after FILE ANCHOR-KEY LINE -> put LINE (indented like the anchor) after each anchor line
add_after() {
    awk -v a="$2" -v t="$3" '{ print; l = $0; sub(/^[ \t]+/, "", l); n = split(l, w, /[ \t=]+/)
        if (n > 0 && tolower(w[1]) == tolower(a) && l !~ /^[#;]/) { i = $0; sub(/[^ \t].*$/, "", i); print i t } }' "$1" >"$1.ccdc" && cat "$1.ccdc" >"$1"; rm -f "$1.ccdc"
}
# put_kv KEY VALUE ANCHOR -> set KEY in the files of $W/tf (style $_st)
put_kv() {
    _hit=0; while IFS= read -r _f; do set_kv "$_f" "$_st" "$1" "$2" && _hit=1; done <"$W/tf"
    [ "$_hit" = 1 ] && return 0
    case "$_st" in sp) _line="$1 $2" ;; ng) _line="$1 $2;" ;; *) _line="$1 = $2" ;; esac
    while IFS= read -r _f; do add_after "$_f" "$3" "$_line"; done <"$W/tf"
}
conf_files() { awk -F'|' -v s="$1" '$1 == s { print $2 }' "$W/pairs" | sort -u; }
svc_test() {
    [ -z "$R" ] || return 0
    case "$1" in
        apache2) _x=$(cc_first apache2ctl apachectl) && "$_x" -t ;; nginx) nginx -t ;; dovecot) doveconf -n >/dev/null ;; postfix) postfix check ;;
    esac >>"$CC_LOG" 2>&1
}
svc_reload() {
    [ -z "$R" ] || return 0
    for _u in $(case "$1" in apache2) echo "apache2 httpd" ;; mysql) echo "mariadb mysql" ;; *) echo "$1" ;; esac); do
        if [ "$CC_INIT" = systemd ]; then systemctl is-active -q "$_u" 2>/dev/null || continue; systemctl reload-or-restart "$_u" </dev/null
        else [ -x "/etc/init.d/$_u" ] || continue; service "$_u" reload </dev/null || service "$_u" restart </dev/null; fi
        return
    done
}
svc_reload_cmd() { [ -z "$R" ] || { printf ':'; return; }; printf 'for u in %s; do if [ -d /run/systemd/system ]; then systemctl try-reload-or-restart "$u" 2>/dev/null; elif [ -x "/etc/init.d/$u" ]; then service "$u" reload || service "$u" restart; fi; done' "$(case "$1" in apache2) echo "apache2 httpd" ;; mysql) echo "mariadb mysql" ;; *) echo "$1" ;; esac)"; }

NOK=0; NBAD=0; APPLIED=0
if [ "$NCH" -eq 0 ]; then :
elif [ "$CC_APPLY" != 1 ] || { [ -z "$R" ] && ! cc_is_root; }; then
    [ -z "$R" ] && ! cc_is_root && cc_show "$C_YEL" "  [!] not root: showing the plan only"
    cc_show "$C_GRY" "  Dry run: nothing was changed. Run again with --apply."
    # shellcheck disable=SC2034  # read by cc_finish
    CC_N_WOULD=$NCH
elif cc_ask "Apply these $NCH change(s)?" Y "yes, apply them" "no, change nothing"; then
    APPLIED=1
    while IFS="$US" read -r _fix _tg _svc; do
        _ok=1
        case "$_fix" in
            perm)
                _rk=$(P "$_tg")
                if cc_guard path "$_tg"; then
                    _om=$(stat -c %a "$_rk" 2>/dev/null) || _om=600
                    # keep the group's read when the group is a service's (ssl-cert, mysql...)
                    _gn=$(awk -F: -v g="$(ls -lnL "$_rk" | awk '{ print $4 }')" '$3 == g { print $1; exit }' "$(P /etc/group)" 2>/dev/null)
                    _nm=600; case "$_gn" in ssl-cert|ssl|mail|dovecot|postfix|www-data|nginx|apache|mysql) _nm=640 ;; esac
                    chmod "$_nm" "$_rk" && cc_undo_add "mode $_om back on $_tg" "chmod $_om $(cc_shquote "$_rk")" || _ok=0
                else _ok=0; fi ;;
            new)
                _c=${_tg%%"|"*}; _k=${_tg#*"|"}; _k=${_k%%"|"*}; _rc=$(real "$(P "$_c")"); _rk=$(real "$(P "$_k")")
                _cn=$(openssl x509 -in "$_rc" -noout -subject 2>/dev/null | sed -n 's/.*CN *= *\([^,/]*\).*/\1/p'); [ -n "$_cn" ] || _cn=$CC_HOST
                _cn=$(printf '%s' "$_cn" | tr -cd 'A-Za-z0-9.*-')
                if cc_guard path "$_c" && cc_guard path "$_k"; then
                    for _s in $(printf '%s' "$_svc" | tr ',' ' '); do cc_undo_add "reload $_s" "$(svc_reload_cmd "$_s")"; done
                    [ -f "$_rc" ] && cc_backup_file "$_rc" >/dev/null; [ "$_rk" != "$_rc" ] && [ -f "$_rk" ] && cc_backup_file "$_rk" >/dev/null
                    [ -f "$_rc" ] || cc_undo_add "remove the new $_c" "rm -f $(cc_shquote "$_rc")"
                    [ -f "$_rk" ] || cc_undo_add "remove the new $_k" "rm -f $(cc_shquote "$_rk")"
                    mkdir -p "$(dirname "$_rc")" "$(dirname "$_rk")"
                    _san="DNS:$_cn"; [ "$_cn" != "$CC_HOST" ] && _san="$_san,DNS:$CC_HOST"
                    # -addext needs OpenSSL 1.1.1; older ones get no SAN
                    if (umask 077; openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 365 -keyout "$W/new.key" -out "$W/new.crt" -subj "/CN=$_cn" -addext "subjectAltName=$_san" >>"$CC_LOG" 2>&1 ||
                        openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 365 -keyout "$W/new.key" -out "$W/new.crt" -subj "/CN=$_cn" >>"$CC_LOG" 2>&1); then
                        if [ "$_rk" = "$_rc" ]; then cat "$W/new.crt" "$W/new.key" >"$_rc"; chmod 600 "$_rc"
                        else cat "$W/new.crt" >"$_rc"; chmod 644 "$_rc"; cat "$W/new.key" >"$_rk"; chmod 600 "$_rk"; fi
                        rm -f "$W/new.key" "$W/new.crt"
                        # our own change: the baseline follows it (no false "CHANGED" next run)
                        [ -f "$BASE" ] && { _nf=$(fp "$_rc"); awk -F'|' -v c="$_c" -v f="$_nf" 'BEGIN { OFS = "|" } $1 == c { $2 = f } { print }' "$BASE" >"$BASE.n" && cat "$BASE.n" >"$BASE"; rm -f "$BASE.n"; }
                        for _s in $(printf '%s' "$_svc" | tr ',' ' '); do svc_reload "$_s" >>"$CC_LOG" 2>&1; done
                        cc_show "$C_YEL" "    [*] a self-signed certificate: browsers warn; tell the team (and the scoring contact if they verify certificates)"
                    else _ok=0; fi
                else _ok=0; fi ;;
            tls)
                _s=${_tg%%"|"*}; _p=${_tg#*"|"}; _kind=tls
                _p2=$(awk -F'|' -v p="$_p" '$1 == p { print $2; exit }' "$W/ports"); [ -n "$_p2" ] && _kind=$_p2
                cc_undo_add "reload $_s" "$(svc_reload_cmd "$_s")"
                _files=$(conf_files "$_s"); [ "$_s" = nginx ] && _files="$_files$NL/etc/nginx/nginx.conf"
                [ -n "$_files" ] || { _ok=0; cc_show "$C_RED" "    [x] no config file of $_s known"; }
                printf '%s\n' "$_files" | sort -u | grep . | while IFS= read -r _f; do _f=$(real "$(P "$_f")"); [ -f "$_f" ] && printf '%s\n' "$_f"; done | sort -u >"$W/tf"
                while IFS= read -r _f; do cc_backup_file "$_f" >/dev/null; done <"$W/tf"
                case "$_s" in
                    apache2) _st=sp; set -- SSLProtocol "all -SSLv3 -TLSv1 -TLSv1.1" SSLCipherSuite "HIGH:!aNULL:!MD5:!3DES:!RC4" SSLCertificateFile ;;
                    nginx)   _st=ng; set -- ssl_protocols "TLSv1.2 TLSv1.3" ssl_ciphers "HIGH:!aNULL:!MD5:!3DES:!RC4" ssl_certificate ;;
                    dovecot) _st=eq; _an=ssl_cert; while IFS= read -r _f; do grep -q '^[[:space:]]*ssl_server_cert_file' "$_f" && _an=ssl_server_cert_file; done <"$W/tf"
                             set -- ssl_min_protocol "TLSv1.2" ssl_cipher_list "HIGH:!aNULL:!MD5:!3DES:!RC4" "$_an" ;;
                    postfix) _st=eq; set -- smtpd_tls_protocols "!SSLv2, !SSLv3, !TLSv1, !TLSv1.1" smtpd_tls_mandatory_protocols "!SSLv2, !SSLv3, !TLSv1, !TLSv1.1" smtpd_tls_cert_file ;;
                esac
                # Each setting: replace it where it is; nowhere -> add it after the certificate line.
                put_kv "$1" "$2" "$5"; put_kv "$3" "$4" "$5"
                if [ "$_s" = postfix ]; then
                    _mf=$(P /etc/postfix/main.cf)
                    set_kv "$_mf" eq smtpd_tls_exclude_ciphers "aNULL, MD5, 3DES, RC4" || printf 'smtpd_tls_exclude_ciphers = aNULL, MD5, 3DES, RC4\n' >>"$_mf"
                fi
                if ! svc_test "$_s"; then
                    cc_show "$C_RED" "    [x] $_s refuses the new config: put back"; _ok=0
                    while IFS= read -r _f; do _b="$CC_BACKUP_DIR$(cc_abspath "$_f")"; [ -f "$_b" ] && cat "$_b" >"$_f"; done <"$W/tf"
                else
                    svc_reload "$_s" >>"$CC_LOG" 2>&1
                    if [ -z "$R" ]; then
                        sleep 2
                        if ! probe "$_p" "$_kind" -tls1_2; then
                            cc_show "$C_RED" "    [x] port $_p stopped answering TLS 1.2: put back"; _ok=0
                            while IFS= read -r _f; do _b="$CC_BACKUP_DIR$(cc_abspath "$_f")"; [ -f "$_b" ] && cat "$_b" >"$_f"; done <"$W/tf"
                            svc_reload "$_s" >>"$CC_LOG" 2>&1
                        elif probe "$_p" "$_kind" -tls1 -cipher 'DEFAULT@SECLEVEL=0'; then cc_show "$C_YEL" "    [*] port $_p still takes TLS 1.0: a setting elsewhere wins (look for another $_s TLS line)"; fi
                    fi
                fi ;;
            base)
                _c=${_tg%%"|"*}; _f=${_tg#*"|"}
                cc_backup_file "$BASE" >/dev/null
                awk -F'|' -v c="$_c" -v f="$_f" 'BEGIN { OFS = "|" } $1 == c { $2 = f } { print }' "$BASE" >"$BASE.n" && cat "$BASE.n" >"$BASE"; rm -f "$BASE.n" ;;
        esac
        if [ "$_ok" = 1 ]; then NOK=$((NOK + 1)); cc_show "$C_GRN" "  [+] $(plan_word "$_fix" "$_tg")"; else NBAD=$((NBAD + 1)); cc_show "$C_RED" "  [x] $(plan_word "$_fix" "$_tg") FAILED"; fi
    done <"$W/plan"
else cc_show "$C_GRY" "  Not applied."; fi
# shellcheck disable=SC2034  # read by cc_finish
CC_N_DONE=$NOK
# shellcheck disable=SC2034  # read by cc_finish
CC_N_FAIL=$NBAD

# ---- 5. Summary ------------------------------------------------------------------------------------
header "5/5  summary"
awk -F"$US" '{ printf "%-4s %-22s %s\n", $1, $2, $3 }' "$W/find" >"$CC_RUN_DIR/findings.txt"
NH=$(grep -c "^HIGH$US" "$W/find"); NM=$(grep -c "^MED$US" "$W/find")
{
    printf '==========[ summary ]==========\n'
    printf 'SV-32 TLS certificate check | host %s | %s\n' "$CC_HOST" "$([ "$APPLIED" = 1 ] && echo APPLIED || echo 'DRY RUN - nothing changed')"
    printf 'Certificates: %d   TLS ports: %d   Fix now [!]: %d   Look at [*]: %d\n' "$NCERT" "$NPORT" "$NH" "$NM"
    [ -s "$W/plan" ] && { printf 'Changes%s:\n' "$([ "$APPLIED" = 1 ] || echo ' planned')"; while IFS="$US" read -r _fix _tg _svc; do printf '  %s\n' "$(plan_word "$_fix" "$_tg")"; done <"$W/plan"; }
    [ "$APPLIED" = 1 ] && printf 'Done: %d   Failed: %d\n' "$NOK" "$NBAD"
    printf 'Tables: certs.txt (each certificate), served.txt (each port), findings.txt\n'
} >"$CC_RUN_DIR/summary.txt"
while IFS= read -r _l; do case "$_l" in ==*|SV-32*) cc_show "$C_CYN" "$_l" ;; *'Failed: '[1-9]*) cc_show "$C_RED" "$_l" ;; *) cc_show "" "$_l" ;; esac; done <"$CC_RUN_DIR/summary.txt"
rm -rf "$W"
cc_finish
