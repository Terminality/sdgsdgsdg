#!/bin/sh
# Tests for roles/network/SH-04-scan-diff.sh.
# Builds small SH-03 and SH-05 result folders by hand (the same CSV layout
# the real scripts write), then checks that the diff finds exactly the
# planted changes, raises the right flags, and picks the right folders.
. "$(dirname "$0")/helper.sh"
SH=${TEST_SHELL:-sh}
C="$T_ROOT/roles/network/SH-04-scan-diff.sh"
export BT_SKIP_VERIFY=1
# shellcheck disable=SC2086
run() { $SH "$C" "$@"; }
R="$T_TMP/runs"; O="$T_TMP/out"; mkdir -p "$R" "$O"

# mk DIR FILE LINE...  write a CSV (first LINE is the header) into a run folder
mk() { _d="$R/$1"; _f=$2; shift 2; mkdir -p "$_d"; : >"$_d/$_f"; for _l in "$@"; do printf '%s\n' "$_l" >>"$_d/$_f"; done; : >"$_d/summary.txt"; }

# ---- two network scans -------------------------------------------------------
A="SH-03_admin_20261111T140000Z"; B="SH-03_admin_20261111T150000Z"
mk $A hosts.csv 'ip,hostname,os' '"10.0.0.5","web","linux"' '"10.0.0.6","db","linux"'
mk $B hosts.csv 'ip,hostname,os' '"10.0.0.5","web","linux"' '"10.0.0.9","","linux"'
mk $A ports.csv 'ip,proto,port,service,version' '"10.0.0.5","tcp","80","http","nginx 1.24"' '"10.0.0.5","tcp","22","ssh","OpenSSH 9.6"'
mk $B ports.csv 'ip,proto,port,service,version' '"10.0.0.5","tcp","80","http","nginx 1.25"' '"10.0.0.5","tcp","4444","",""' '"10.0.0.5","tcp","22","ssh","OpenSSH 9.6"'
mk $A scored.csv 'host,ip,service,port,reachable' '"web","10.0.0.5","http","80","yes"' '"db","10.0.0.6","mysql","3306","yes"'
mk $B scored.csv 'host,ip,service,port,reachable' '"web","10.0.0.5","http","80","yes"' '"db","10.0.0.6","mysql","3306","no"'
# An unfinished (no summary.txt) later run must be ignored by the auto pick.
mkdir -p "$R/SH-03_admin_20261111T160000Z"

t_start "network scans (auto pick)"
out=$(run --runs "$R" --out "$O" 2>&1); rc=$?
t_eq "$rc" 0 "exit 0"
t_has "$out" "Earlier: $A" "picks the older finished run"
t_has "$out" "Later:   $B" "picks the newest finished run, skips the unfinished one"
d=$(printf '%s\n' "$out" | sed -n 's/^All results: //p')
f=$(cat "$d/csv/flags.csv"); c=$(cat "$d/csv/changes.csv")
t_has "$c" '"hosts","added","10.0.0.9"' "new host listed"
t_has "$c" '"hosts","removed","10.0.0.6"' "vanished host listed"
t_has "$c" '"ports","changed","10.0.0.5 | tcp | 80","http | nginx 1.24","http | nginx 1.25"' "version change listed"
t_has "$f" '"HIGH","ports","10.0.0.5 | tcp | 4444"' "backdoor port is HIGH"
t_hasnt "$f" '"MED","ports","10.0.0.5 | tcp | 4444"' "backdoor port is not also MED"
t_has "$f" '"HIGH","scored","db | 10.0.0.6 | mysql | 3306"' "scored service going down is HIGH"
t_hasnt "$c" '"22"' "unchanged port not listed"
t_file "$d/summary.txt" "summary written"
t_has "$d" "/diff-" "diff results go in a numbered diff-N folder"
t_has "$(sed -n 1p "$d/changes.txt")" "SECTION" "changes.txt is a readable table"
t_has "$(sed -n 3p "$d/changes.txt")" "added" "additions are listed first"
t_has "$(sed -n 3p "$d/flags.txt")" "HIGH" "flags.txt lists HIGH first"

# ---- two collector runs of one host -------------------------------------------
A="SH-05_web01_20261111T140000Z"; B="SH-05_web01_20261111T150000Z"
mk $A users.csv 'user,uid,gid,home,shell,can_login,password,groups' '"root","0","0","/root","/bin/bash","yes","set","root"' '"bob","1000","1000","/home/bob","/bin/bash","yes","set","bob"'
mk $B users.csv 'user,uid,gid,home,shell,can_login,password,groups' '"root","0","0","/root","/bin/bash","yes","set","root"' '"bob","1000","1000","/home/bob","/bin/bash","yes","set","bob,sudo"' '"sysupd","0","0","/tmp","/bin/sh","yes","empty","root"'
mk $A autostart.csv 'source,user,entry' '"/etc/crontab","root","17 * * * * run-parts"'
mk $B autostart.csv 'source,user,entry' '"/etc/crontab","root","17 * * * * run-parts"' '"/etc/cron.d/x","root","* * * * * /tmp/.x"'
mk $A ports.csv 'proto,address,port,exposure,pid,process,user,program' '"tcp","0.0.0.0","22","all","1","sshd","root","/usr/sbin/sshd"'
mk $B ports.csv 'proto,address,port,exposure,pid,process,user,program' '"tcp","0.0.0.0","22","all","9","sshd","root","/usr/sbin/sshd"' '"tcp","0.0.0.0","31337","all","7","nc","root","/usr/bin/nc"'
mk $A facts.csv 'key,value' '"collector_run_as_root","1"'
mk $B facts.csv 'key,value' '"collector_run_as_root","0"'
mk SH-05_db01_20261111T120000Z users.csv 'user,uid,gid,home,shell,can_login,password,groups'

t_start "collector runs (auto pick by host)"
out=$(run --runs "$R" --out "$O" --type sh05 2>&1); rc=$?
t_eq "$rc" 0 "exit 0"
t_has "$out" "Earlier: $A" "older run of the newest run's host"
t_has "$out" "root and the other was not" "warns about root / non-root runs"
t_has "$out" "skipped (not in both runs)" "a section missing from both runs is skipped"
d=$(printf '%s\n' "$out" | sed -n 's/^All results: //p')
f=$(cat "$d/csv/flags.csv")
t_has "$f" '"HIGH","users","sysupd"' "new account is HIGH"
t_has "$f" '"MED","users","bob"' "group change is MED"
t_has "$f" '"HIGH","autostart","/etc/cron.d/x | root | * * * * * /tmp/.x"' "new cron entry is HIGH"
t_has "$f" '"HIGH","ports","tcp | 0.0.0.0 | 31337"' "backdoor port listening is HIGH"
t_hasnt "$f" '"ports","tcp | 0.0.0.0 | 22"' "a PID change alone is not a change"

t_start "numbered linux-enum-N runs"
mk linux-enum-1 users.csv 'user,uid,gid,home,shell,can_login,password,groups' '"root","0","0","/root","/bin/bash","yes","set","root"'
mk linux-enum-2 users.csv 'user,uid,gid,home,shell,can_login,password,groups' '"root","0","0","/root","/bin/bash","yes","set","root"' '"evil","0","0","/tmp","/bin/sh","yes","set","root"'
printf 'id=SH-05\nhost=web01\ntime=20261111T160000Z\n' >"$R/linux-enum-1/run.txt"
printf 'id=SH-05\nhost=web01\ntime=20261111T170000Z\n' >"$R/linux-enum-2/run.txt"
out=$(run --runs "$R" --out "$O" --type sh05 2>&1); t_eq "$?" 0 "exit 0"
t_has "$out" "Earlier: linux-enum-1" "numbered runs are picked up, older first"
t_has "$out" "Later:   linux-enum-2" "and the newest is linux-enum-2"
d=$(printf '%s\n' "$out" | sed -n 's/^All results: //p')
t_has "$(cat "$d/csv/flags.csv")" '"HIGH","users","evil"' "a new root account between numbered runs is HIGH"
out=$(run --old "$R/linux-enum-1" --new "$R/linux-enum-2" --out "$O" 2>&1); t_eq "$?" 0 "--old/--new with numbered folders works"
out=$(run --old "$R/$A" --new "$R/linux-enum-2" --out "$O" 2>&1); t_eq "$?" 0 "an old-style and a numbered run can be compared"
mkdir -p "$R/LX-39_web01_20261111T170000Z"
out=$(run --old "$R/$A" --new "$R/LX-39_web01_20261111T170000Z" --out "$O" 2>&1); t_eq "$?" 2 "a fix script's run folder exits 2"
t_has "$out" "run the enum again" "and says to run the enum again"

mkdir -p "$R/linux-enum-3/csv"; mv "$R/linux-enum-2/users.csv" "$R/linux-enum-3/csv/users.csv"; : >"$R/linux-enum-3/summary.txt"
printf 'id=SH-05\nhost=web01\ntime=20261111T180000Z\n' >"$R/linux-enum-3/run.txt"
out=$(run --old "$R/linux-enum-1" --new "$R/linux-enum-3" --out "$O" 2>&1); t_eq "$?" 0 "CSV files kept in csv/ are found"
d=$(printf '%s\n' "$out" | sed -n 's/^All results: //p')
t_has "$(cat "$d/csv/flags.csv")" '"HIGH","users","evil"' "and compared"

t_start "explicit folders and errors"
out=$(run --old "$R/$A" --new "$R/$B" --out "$O" 2>&1); t_eq "$?" 0 "--old/--new works"
run --old "$R/$A" --out "$O" >/dev/null 2>&1; t_eq "$?" 2 "--old without --new exits 2"
run --old "$R/$A" --new "$R/SH-03_admin_20261111T150000Z" --out "$O" >/dev/null 2>&1; t_eq "$?" 2 "mixing SH-03 and SH-05 exits 2"
run --old "$R/$A" --new "$T_TMP" --out "$O" >/dev/null 2>&1; t_eq "$?" 2 "a folder that is not a run exits 2"
run --runs "$R" --out "$O" --type sh05 --host db01 >/dev/null 2>&1; t_eq "$?" 3 "only one run of a host exits 3"
run --type sh06 >/dev/null 2>&1; t_eq "$?" 2 "bad --type exits 2"
out=$(run --old "$R/$A" --new "$R/$A" --out "$O" 2>&1)
t_has "$out" "No differences." "a run compared with itself has no differences"
t_done
