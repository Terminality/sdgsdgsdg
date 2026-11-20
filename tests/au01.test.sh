#!/bin/sh
# Tests for roles/automation/AU-01-inv3-first15.sh.
. "$(dirname "$0")/helper.sh"
SH=${TEST_SHELL:-sh}
C="$T_ROOT/roles/automation/AU-01-inv3-first15.sh"
export CCDC_SKIP_VERIFY=1
run() { $SH "$C" "$@"; }

t_start "input validation"
run --out "$T_TMP/a" >/dev/null 2>&1; t_eq "$?" 2 "team is required"
run --team nope --out "$T_TMP/a" >/dev/null 2>&1; t_eq "$?" 2 "non-number refused"
run --team 0 --out "$T_TMP/a" >/dev/null 2>&1; t_eq "$?" 2 "team zero refused"
run --team 100 --out "$T_TMP/a" >/dev/null 2>&1; t_eq "$?" 2 "team 100 refused"
t_has "$(run --help 2>&1)" "--scan" "help documents optional scan"

t_start "team workspace"
r=$(run --team 7 --out "$T_TMP/out" 2>&1); t_eq "$?" 0 "controller exits zero"
R="$T_TMP/out/inv3-control-1"
for f in hosts.csv nat-map.csv protected.csv service-matrix.csv password-status.csv change-log.csv first15.txt; do
    t_file "$R/$f" "$f generated"
done
t_eq "$(tail -n +2 "$R/hosts.csv" | wc -l | tr -d ' ')" 10 "all ten packet hosts present"
t_ok "router internal address" grep -q '^vigra,192.168.220.2,' "$R/hosts.csv"
t_ok "team 7 NAT address" grep -q '^borgar,192.168.220.10,10.100.107.10,' "$R/nat-map.csv"
t_ok "service matrix gets external address" grep -q '^gufu,192.168.220.100,10.100.107.100,' "$R/service-matrix.csv"
t_ok "AD protected" grep -q '^service,NTDS,' "$R/protected.csv"
t_ok "one password row per host" test "$(tail -n +2 "$R/password-status.csv" | wc -l | tr -d ' ')" -eq 10
t_fail "password tracker has no password column" grep -qi 'new_password\|old_password\|password_value' "$R/password-status.csv"
t_has "$(cat "$R/first15.txt")" "Do not rotate all domain users" "DC bulk rotation warning"
t_has "$(cat "$R/first15.txt")" "sysupgrade -b" "OpenWRT backup step"
t_has "$r" "fill protected.csv" "terminal gives stop condition"

t_start "numbered runs and alternate team"
run --team 13 --out "$T_TMP/out" >/dev/null 2>&1; t_eq "$?" 0 "second run exits zero"
t_file "$T_TMP/out/inv3-control-2/nat-map.csv" "second run does not overwrite first"
t_ok "team 13 NAT address" grep -q '^djupi,192.168.220.222,10.100.113.222,' "$T_TMP/out/inv3-control-2/nat-map.csv"

t_start "scan requires a kit"
run --team 7 --scan --kit "$T_TMP/missing" --out "$T_TMP/scan" >/dev/null 2>&1
t_eq "$?" 3 "missing SH-03 is a requirement error"

t_done
