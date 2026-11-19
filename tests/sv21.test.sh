#!/bin/sh
# Tests for roles/applications/SV-21-web-hardening.sh.
# A fake root (--root): php.ini for apache2 and fpm, an Apache conf-enabled
# folder, a WordPress site owned by the web server with an upload folder.
# The dry run changes nothing; --apply sets the PHP settings, adds the Apache
# drop-in, locks the config file, adds DISALLOW_FILE_EDIT, takes the code from
# the web server but leaves uploads writable; a second run finds nothing to
# do; replaying the undo lines puts every file, mode and owner back; the
# questions list their answers on a terminal.  Nothing outside the fake root
# is touched (--root never reloads services or reads databases).
. "$(dirname "$0")/helper.sh"
SH=${TEST_SHELL:-sh}
C="$T_ROOT/roles/applications/SV-21-web-hardening.sh"
export BT_SKIP_VERIFY=1
O="$T_TMP/out"; F="$T_TMP/root"; S="$F/var/www/html/shop"

mkroot() {
    rm -rf "$F"
    mkdir -p "$F/etc/php/8.3/apache2" "$F/etc/php/8.3/fpm" "$F/etc/php/8.3/cli" "$F/etc/apache2/conf-enabled" \
        "$S/wp-content/uploads" "$S/wp-content/themes" "$S/wp-includes"
    printf 'root:x:0:0::/root:/bin/sh\nwww-data:x:33:33::/var/www:/usr/sbin/nologin\n' >"$F/etc/passwd"
    printf 'root:x:0:\nwww-data:x:33:\n' >"$F/etc/group"
    for d in apache2 fpm cli; do
        printf '[PHP]\nexpose_php = On\ndisplay_errors = On\n;log_errors = Off\nallow_url_include = On\ndisable_functions = pcntl_fork\n' >"$F/etc/php/8.3/$d/php.ini"
    done
    printf "<?php\ndefine( 'DB_NAME', 'shopdb' );\ndefine( 'DB_PASSWORD', 'SiteSecret41' );\n\$table_prefix = 'wp_';\n" >"$S/wp-config.php"
    printf "<?php\n\$wp_version = '6.4.2';\n" >"$S/wp-includes/version.php"
    printf '<?php echo "ok";\n' >"$S/index.php"
    printf '<?php\n' >"$S/xmlrpc.php"
    printf 'x\n' >"$S/wp-content/themes/style.css"
    chmod 644 "$S/wp-config.php"
    chown -R 33:33 "$S"
}
run() { $SH "$C" --root "$F" --out "$O" --no-color --batch --box ecomm "$@"; }
snap() { (cd "$F" && find . -exec ls -lnd {} + | awk '{ print $1, $3, $4, $NF }' | sort; find . -type f -exec cat {} +) | cksum; }

t_start "options"
$SH "$C" --level extreme >/dev/null 2>&1; t_eq "$?" 2 "a bad --level exits 2"
$SH "$C" --only php-everything >/dev/null 2>&1; t_eq "$?" 2 "an unknown fix exits 2"
$SH "$C" --admins maybe >/dev/null 2>&1; t_eq "$?" 2 "a bad --admins exits 2"
out=$($SH "$C" --help 2>&1); t_has "$out" "upload-nophp[service]" "--help lists the fixes with their risk"

if [ "$(id -u)" = 0 ]; then
    t_start "dry run"
    mkroot; before=$(snap)
    out=$(run --level access --only php-functions,code-readonly,php-urlinclude,php-errors,php-expose,app-config,wp-fileedit,upload-nophp,block-files,wp-xmlrpc 2>&1)
    t_has "$out" "WordPress   6.4.2" "the WordPress site and version are found"
    t_has "$out" "allow_url_include: On -> Off" "allow_url_include planned"
    t_hasnt "$out" "/etc/php/8.3/cli/php.ini" "the command line php.ini is left alone"
    t_has "$out" "no PHP in: /var/www/html/shop/wp-content/uploads" "the upload folder is planned"
    t_has "$out" "Dry run: nothing was changed" "dry run without --apply"
    t_eq "$(snap)" "$before" "a dry run changes nothing"
    d=$(ls -d "$O"/web-hardening-* | sort -t- -k3 -n | tail -n 1)
    for f in output.txt plan.txt summary.txt apps.txt; do t_file "$d/$f" "$f written"; done
    t_fail "no CSV files are left" sh -c "find '$O' -name '*.csv' | grep -q ."
    t_fail "no password in the output" grep -rq "SiteSecret41" "$d"

    t_start "apply"
    _u0=$(cat "$O"/undo-*.log 2>/dev/null | grep -c .)
    out=$(run --level access --only php-functions,code-readonly,php-urlinclude,php-errors,php-expose,app-config,wp-fileedit,upload-nophp,block-files,wp-xmlrpc --no-protected --apply --no-timer 2>&1)
    ini="$F/etc/php/8.3/apache2/php.ini"
    t_ok "allow_url_include Off" grep -q '^allow_url_include = Off' "$ini"
    t_ok "display_errors Off" grep -q '^display_errors = Off' "$ini"
    t_ok "log_errors On" grep -q '^log_errors = On' "$ini"
    t_ok "expose_php Off" grep -q '^expose_php = Off' "$ini"
    t_ok "disable_functions keeps the old entry and adds the new ones" grep -q '^disable_functions = pcntl_fork,system,exec,shell_exec,passthru,proc_open,popen,pcntl_exec$' "$ini"
    t_ok "the fpm php.ini too" grep -q '^expose_php = Off' "$F/etc/php/8.3/fpm/php.ini"
    t_ok "the cli php.ini is unchanged" grep -q '^expose_php = On' "$F/etc/php/8.3/cli/php.ini"
    dr="$F/etc/apache2/conf-enabled/zz-bt-web.conf"
    t_ok "drop-in: no PHP in uploads" grep -q '<Directory "/var/www/html/shop/wp-content/uploads">' "$dr"
    t_ok "drop-in: xmlrpc blocked" grep -q '<Files "xmlrpc.php">' "$dr"
    t_ok "drop-in: .git blocked" grep -q 'git|svn|hg' "$dr"
    t_eq "$(ls -ln "$S/wp-config.php" | awk '{ print $1, $3, $4 }')" "-rw-r----- 0 33" "wp-config.php is root:www-data 640"
    t_eq "$(sed -n 2p "$S/wp-config.php")" "define( 'DISALLOW_FILE_EDIT', true ); // BT SV-21" "DISALLOW_FILE_EDIT added"
    t_eq "$(ls -ln "$S/index.php" | awk '{ print $3 }')" 0 "the code belongs to root now"
    t_eq "$(ls -lnd "$S/wp-content/uploads" | awk '{ print $3 }')" 33 "uploads stay writable by the web server"
    t_has "$out" "nothing is restarted" "--root says nothing is restarted"
    d=$(ls -d "$O"/web-hardening-* | sort -t- -k3 -n | tail -n 1)
    t_file "$d/changes.txt" "changes.txt written"

    out=$(run --level access --only php-functions,code-readonly,php-urlinclude,php-errors,php-expose,app-config,wp-fileedit,upload-nophp,block-files,wp-xmlrpc 2>&1)
    t_has "$out" "Nothing to change" "a second run finds nothing to do"

    t_start "undo"
    cat "$O"/undo-*.log | awk -F'\t' -v n="$_u0" 'NR > n { l[NR] = $4 } END { for (i = NR; i > n; i--) print l[i] }' >"$T_TMP/undo.sh"
    sh "$T_TMP/undo.sh" >/dev/null 2>&1
    t_eq "$(snap)" "$before" "undo puts every file, mode and owner back"
    t_fail "undo removes the drop-in" test -f "$dr"

    t_start "questions on a terminal"
    if command -v script >/dev/null 2>&1; then
        mkroot
        # box: e | level: a | then Enter for each fix
        printf 'e\na\n\n\n\n\n\n\n\n\n\n\n\n' >"$T_TMP/ans"
        tt=$(BT_NO_TTY=0 script -qc "$SH '$C' --root '$F' --out '$O' --no-color --no-protected" /dev/null <"$T_TMP/ans" 2>&1)
        t_has "$tt" "[v] service: also no PHP in upload folders" "the level question lists its answers"
        t_has "$tt" "[y] yes, do it" "each fix lists its answers"
        t_has "$tt" "level access" "the typed level is used"
    fi
fi
t_done
