#!/bin/sh
# Tests for roles/applications/SV-32-tls-check.sh.
# A fake root (--root) with Apache, Dovecot and Postfix configs pointing at
# test certificates: an expired self-signed one (web), a CA-signed one with
# the wrong key (mail), a 1024-bit SHA-1 one whose key everyone can read
# (smtp).  An openssl s_server on a high port takes TLS 1.0 and weak
# ciphers.  Checks: each problem is found; a dry run changes nothing; the
# defaults (self-signed replaced, CA-signed left, key chmod 600, Apache TLS
# config tightened); the baseline flags a change; the undo; the questions on
# a terminal.  Nothing outside the test folder is touched.
. "$(dirname "$0")/helper.sh"
SH=${TEST_SHELL:-sh}
C="$T_ROOT/roles/applications/SV-32-tls-check.sh"
export BT_SKIP_VERIFY=1
O="$T_TMP/out"; F="$T_TMP/root"; K="$T_TMP/keys"
command -v openssl >/dev/null 2>&1 || { echo "openssl missing: skipped"; t_done; exit 0; }
fpr() { openssl x509 -in "$1" -noout -fingerprint -sha256 | sed 's/.*=//'; }
# Test certificates, made once.
mkdir -p "$K/ca"; : >"$K/ca/index.txt"; echo 01 >"$K/ca/serial"
printf '[ca]\ndefault_ca=d\n[d]\ndatabase=%s/ca/index.txt\nnew_certs_dir=%s/ca\nserial=%s/ca/serial\ndefault_md=sha256\npolicy=p\n[p]\ncommonName=supplied\n' "$K" "$K" "$K" >"$K/cfg"
openssl req -new -newkey rsa:2048 -nodes -keyout "$K/web.key" -out "$K/web.csr" -subj /CN=shop.test >/dev/null 2>&1
openssl ca -selfsign -keyfile "$K/web.key" -in "$K/web.csr" -startdate 20200101000000Z -enddate 20210101000000Z -batch -config "$K/cfg" -out "$K/web.pem" >/dev/null 2>&1
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -keyout "$K/ca.key" -out "$K/ca.pem" -subj /CN=Test-CA >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -nodes -keyout "$K/mail.key" -out "$K/mail.csr" -subj /CN=mail.test >/dev/null 2>&1
openssl x509 -req -in "$K/mail.csr" -CA "$K/ca.pem" -CAkey "$K/ca.key" -CAcreateserial -days 300 -out "$K/mail.pem" >/dev/null 2>&1
openssl req -x509 -newkey rsa:1024 -sha1 -nodes -days 300 -keyout "$K/weak.key" -out "$K/weak.pem" -subj /CN=smtp.test >/dev/null 2>&1
openssl req -x509 -newkey rsa:2048 -nodes -days 300 -keyout "$K/other.key" -out "$K/other.pem" -subj /CN=other >/dev/null 2>&1
mkroot() {
    rm -rf "$F"; mkdir -p "$F/etc/ssl/certs" "$F/etc/ssl/private" "$F/etc/apache2/sites-enabled" "$F/etc/apache2/sites-available" "$F/etc/dovecot/conf.d" "$F/etc/postfix"
    cp "$K/web.pem" "$K/mail.pem" "$K/weak.pem" "$F/etc/ssl/certs/"; cp "$K/web.key" "$K/other.key" "$K/weak.key" "$F/etc/ssl/private/"
    chmod 600 "$F/etc/ssl/private/"*; chmod 644 "$F/etc/ssl/private/weak.key"
    printf '<VirtualHost *:443>\n    SSLEngine on\n    SSLProtocol all\n    SSLCertificateFile /etc/ssl/certs/web.pem\n    SSLCertificateKeyFile /etc/ssl/private/web.key\n</VirtualHost>\n' >"$F/etc/apache2/sites-available/default-ssl.conf"
    ln -s ../sites-available/default-ssl.conf "$F/etc/apache2/sites-enabled/default-ssl.conf"   # as a2ensite does
    printf 'ssl = required\nssl_cert = </etc/ssl/certs/mail.pem\nssl_key = </etc/ssl/private/other.key\n' >"$F/etc/dovecot/conf.d/10-ssl.conf"
    printf 'smtpd_tls_cert_file=/etc/ssl/certs/weak.pem\nsmtpd_tls_key_file=/etc/ssl/private/weak.key\n' >"$F/etc/postfix/main.cf"
    printf 'root:x:0:\nssl-cert:x:110:\n' >"$F/etc/group"; printf 'root:x:0:0::/root:/bin/sh\n' >"$F/etc/passwd"
}
SPID=""; SP=$((18000 + $$ % 1000))
if openssl s_server -help 2>&1 | grep -q -- '-accept' && command -v timeout >/dev/null 2>&1; then
    # timeout: it goes away on its own even if this test is killed
    timeout 300 openssl s_server -accept "$SP" -cert "$K/weak.pem" -key "$K/weak.key" -cipher 'ALL@SECLEVEL=0' -quiet </dev/null >/dev/null 2>&1 & SPID=$!
    sleep 1
fi
run() { $SH "$C" --out "$O" --no-color --root "$F" --no-protected "$@"; }

t_start "options"
$SH "$C" --port x >/dev/null 2>&1; t_eq "$?" 2 "a bad --port exits 2"
$SH "$C" --days x >/dev/null 2>&1; t_eq "$?" 2 "a bad --days exits 2"
out=$($SH "$C" --help 2>&1); t_has "$out" "--no-probe" "--help"

t_start "find"
mkroot
out=$(run --batch --port "$SP:tls:apache2" 2>&1)
t_has "$out" "[!] apache2: EXPIRED on Jan  1 00:00:00 2021 GMT" "an expired certificate is HIGH"
t_has "$out" "[!] dovecot: the certificate does NOT match its key /etc/ssl/private/other.key" "a key mismatch is HIGH"
t_has "$out" "[*] postfix: weak key: 1024 bit RSA" "a weak key"
t_has "$out" "[*] postfix: weak signature: sha1WithRSAEncryption" "a SHA-1 signature"
t_has "$out" "[!] postfix: the private key /etc/ssl/private/weak.key can be read by every user" "a readable key is HIGH"
t_has "$out" "[ok] matches its key /etc/ssl/private/web.key" "a matching key is fine"
t_hasnt "$out" "other.key can be read" "a key only root reads is fine"
if [ -n "$SPID" ]; then
    t_has "$out" "port $SP (apache2): still takes TLS 1.0/1.1 and weak ciphers" "old TLS and weak ciphers on a port"
    t_has "$out" "[ok] the certificate from /etc/ssl/certs/weak.pem" "the served certificate is matched to its file"
fi
t_has "$out" "first run: fingerprints saved as the baseline" "a baseline is saved"
t_has "$out" "/etc/ssl/certs/web.pem: EXPIRED on Jan  1 00:00:00 2021 GMT: clients and scoring checks that verify it fail. What now? [N/l] n (default)" "self-signed: default new"
t_has "$out" "/etc/ssl/certs/mail.pem: the certificate does NOT match its key /etc/ssl/private/other.key: TLS fails (a swapped certificate or key?). What now? [n/L] l (default)" "CA-signed: default leave"
t_has "$out" "weak key: 1024 bit RSA (2048 or more); weak signature: sha1WithRSAEncryption" "one question per certificate"
t_has "$out" "Dry run: nothing was changed" "dry run without --apply"
t_eq "$(fpr "$F/etc/ssl/certs/web.pem")" "$(fpr "$K/web.pem")" "a dry run changes no certificate"
_rd=$(ls -d "$O"/tls-[0-9]* | tail -n 1)
t_file "$_rd/certs.txt" "certs.txt"; t_file "$_rd/served.txt" "served.txt"
t_fail "the baseline holds no key" grep -q 'PRIVATE' "$O"/tls-baseline-*.txt
t_fail "no CSV files are left" sh -c "find '$O' -name '*.csv' | grep -q ."

t_start "apply the defaults (--batch)"
out=$(run --batch --apply --port "$SP:tls:apache2" 2>&1)
t_ok "the expired self-signed one is replaced" openssl x509 -in "$F/etc/ssl/certs/web.pem" -noout -checkend 86400
t_eq "$(openssl x509 -in "$F/etc/ssl/certs/web.pem" -noout -subject | sed 's/.* = //')" "shop.test" "with the same name"
t_eq "$(openssl x509 -in "$F/etc/ssl/certs/web.pem" -noout -pubkey | openssl sha256)" "$(openssl pkey -in "$F/etc/ssl/private/web.key" -pubout | openssl sha256)" "and a key that matches"
t_eq "$(fpr "$F/etc/ssl/certs/mail.pem")" "$(fpr "$K/mail.pem")" "the CA-signed one is left"
t_eq "$(ls -l "$F/etc/ssl/private/weak.key" | cut -c1-10)" "-rw-------" "the readable key is now 600"
if [ -n "$SPID" ]; then
    t_ok "Apache: SSLProtocol replaced" grep -q '^    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1$' "$F/etc/apache2/sites-enabled/default-ssl.conf"
    t_ok "Apache: SSLCipherSuite added after the certificate line" grep -q '^    SSLCipherSuite HIGH:!aNULL:!MD5:!3DES:!RC4$' "$F/etc/apache2/sites-enabled/default-ssl.conf"
fi

t_start "baseline"
out=$(run --batch --no-probe 2>&1)
t_hasnt "$out" "web.pem CHANGED" "our own new certificate is not flagged as a swap"
cp "$K/other.pem" "$F/etc/ssl/certs/mail.pem"   # a swap
out=$(run --batch --no-probe 2>&1)
t_has "$out" "/etc/ssl/certs/mail.pem CHANGED since the baseline" "a swapped certificate is HIGH"
t_has "$out" "[K/u] k (default)" "default: keep flagging"

t_start "undo"
awk -F'\t' '{ l[NR] = $4 } END { for (i = NR; i > 0; i--) print l[i] }' "$O"/undo-*.log >"$T_TMP/undo.sh"
sh "$T_TMP/undo.sh" >/dev/null 2>&1
t_eq "$(fpr "$F/etc/ssl/certs/web.pem")" "$(fpr "$K/web.pem")" "the old certificate is back"
t_eq "$(ls -l "$F/etc/ssl/private/weak.key" | cut -c1-10)" "-rw-r--r--" "the key mode is back"
t_fail "the Apache config is back (through its symlink)" grep -q SSLCipherSuite "$F/etc/apache2/sites-available/default-ssl.conf"
t_ok "the symlink is still a symlink" test -h "$F/etc/apache2/sites-enabled/default-ssl.conf"

if command -v script >/dev/null 2>&1; then
    t_start "questions on a terminal"
    mkroot; O2="$T_TMP/out2"
    # web: l; mail: n; weak (smtp): l; weak key perm: f; apply: Enter
    printf 'l\nn\nl\nf\n\n' >"$T_TMP/ans"
    tt=$(BT_NO_TTY=0 script -qc "$SH '$C' --out '$O2' --no-color --root '$F' --no-protected --no-probe --apply" /dev/null <"$T_TMP/ans" 2>&1)
    t_has "$tt" "[n] new self-signed certificate and key" "a certificate lists its answers"
    t_has "$tt" "[f] fix it: only the owner" "a key lists its answers"
    t_eq "$(fpr "$F/etc/ssl/certs/web.pem")" "$(fpr "$K/web.pem")" "l: the web certificate stays"
    t_ok "n: the mail certificate is new and matches its key" sh -c "[ \"\$(openssl x509 -in '$F/etc/ssl/certs/mail.pem' -noout -pubkey | openssl sha256)\" = \"\$(openssl pkey -in '$F/etc/ssl/private/other.key' -pubout | openssl sha256)\" ]"
    t_eq "$(fpr "$F/etc/ssl/certs/weak.pem")" "$(fpr "$K/weak.pem")" "l: the weak certificate stays"
    t_eq "$(ls -l "$F/etc/ssl/private/weak.key" | cut -c1-10)" "-rw-------" "f: the key is 600"
fi
[ -n "$SPID" ] && kill "$SPID" 2>/dev/null
t_done
