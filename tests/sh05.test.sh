#!/bin/sh
# Tests for roles/linux/SH-05-linux-enum.sh.
# Runs the real enum against this machine.  Checks that it works under
# every shell, produces its files, changes nothing, and - when run as root -
# flags problems planted in a private temp folder.
. "$(dirname "$0")/helper.sh"
SH=${TEST_SHELL:-sh}
C="$T_ROOT/roles/linux/SH-05-linux-enum.sh"
export CCDC_SKIP_VERIFY=1
# shellcheck disable=SC2086
run() { $SH "$C" "$@"; }

t_start "options"
run --nope >/dev/null 2>&1; t_eq "$?" 2 "unknown option exits 2"
run --profile huge >/dev/null 2>&1; t_eq "$?" 2 "unknown profile exits 2"
run --only system,bogus >/dev/null 2>&1; t_eq "$?" 2 "unknown section exits 2"
r=$(run --list 2>&1); t_has "$r" "autostart" "--list names the sections"
r=$(run --help 2>&1); t_has "$r" "--profile" "--help shows the options"

t_start "card profile runs and writes its files"
r=$(run --out "$T_TMP/o1" --profile card 2>"$T_TMP/err1"); t_eq "$?" 0 "exits 0"
RUN=$(ls -d "$T_TMP"/o1/linux-enum-*/ 2>/dev/null | head -n 1)
for f in summary.txt flags.txt facts.txt users.txt ports.txt services.txt autostart.txt sudo.txt; do t_file "$RUN/$f" "$f written"; done
for f in flags.csv facts.csv users.csv ports.csv; do t_file "$RUN/csv/$f" "csv/$f written"; done
t_has "$(sed -n 1,2p "$RUN/users.txt")" "USER " "users.txt is a readable table with a header"
t_has "$(sed -n 2p "$RUN/users.txt")" "----" "and a dashed line under it"
t_hasnt "$(cat "$RUN/users.txt")" '","' "users.txt is not CSV"
t_has "$r" "section        rows" "summary table printed"
t_has "$r" "==========[ 1/7  system ]==========" "a header per section, printed live"
t_has "$r" "[ok] nothing to fix here" "a section with nothing to fix says so"
t_hasnt "$r" "$(printf '\033')" "no colour codes when the output is not a terminal"
t_eq "$RUN" "$T_TMP/o1/linux-enum-1/" "the first run folder is linux-enum-1"
t_file "$RUN/output.txt" "output.txt written"
t_has "$(cat "$RUN/output.txt")" "==========[ 2/7  users ]==========" "output.txt has the live output"
t_has "$(cat "$RUN/run.txt")" "id=SH-05" "run.txt records the ID"
run --out "$T_TMP/o1" --only system >/dev/null 2>&1
t_file "$T_TMP/o1/linux-enum-2/summary.txt" "the next run is linux-enum-2"
t_has "$r" "Accounts that can log in:" "users summary line printed"
t_fail "card does not run the slow sections" test -f "$RUN/csv/suid.csv"
t_fail "work folder removed" test -d "$RUN/.work"
t_eq "$(head -n 1 "$RUN/csv/users.csv")" "user,uid,gid,home,shell,can_login,password,groups" "users.csv header"
t_ok "root is listed in users.csv" grep -q '^"root","0"' "$RUN/csv/users.csv"
t_hasnt "$(cat "$RUN"/csv/*.csv "$RUN"/*.txt "$T_TMP"/o1/*.log)" '$6$' "no password hash anywhere in the output"

t_start "--only and --skip"
run --out "$T_TMP/o2" --only system,users >/dev/null 2>&1; t_eq "$?" 0 "--only exits 0"
R2=$(ls -d "$T_TMP"/o2/linux-enum-*/ | head -n 1)
t_file "$R2/users.txt" "--only ran users"; t_fail "--only skipped ports" test -f "$R2/ports.txt"
run --out "$T_TMP/o3" --profile card --skip ports,sudo >/dev/null 2>&1
R3=$(ls -d "$T_TMP"/o3/linux-enum-*/ | head -n 1)
t_fail "--skip left ports out" test -f "$R3/ports.txt"; t_file "$R3/users.txt" "--skip kept the rest"

t_start "planted problems are flagged (root only)"
if [ "$(id -u)" = 0 ]; then
    P="$T_TMP/plant"; mkdir -p "$P"
    # A real file path is needed: under busybox, 'command -v find' prints the
    # applet name "find", not a path.
    for _fb in /usr/bin/find /bin/find; do [ -f "$_fb" ] && break; done
    cp "$_fb" "$P/find" && chmod 4755 "$P/find"
    printf 'type,value,note\n' >"$P/dummy"
    run --out "$T_TMP/o4" --only files >/dev/null 2>&1; t_eq "$?" 0 "files section exits 0"
    R4=$(ls -d "$T_TMP"/o4/linux-enum-*/ | head -n 1)
    t_ok "planted SUID copy of find is in suid.csv" grep -q "$P/find" "$R4/csv/suid.csv"
    t_ok "planted SUID copy of find is flagged HIGH" grep -q "\"HIGH\",\"files\",\"$P/find\"" "$R4/csv/flags.csv"
    rm -f "$P/find"
else
    t_start "(skipped: not root)"
fi

t_start "it changes nothing"
before=$(ls -la /etc | cksum)
run --out "$T_TMP/o5" --only system,users,ssh,sudo,pam >/dev/null 2>&1
t_eq "$(ls -la /etc | cksum)" "$before" "/etc listing unchanged"

t_done
