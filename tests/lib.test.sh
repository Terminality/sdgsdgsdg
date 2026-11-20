#!/bin/sh
# Tests for lib/lib.sh (LB-01).  Run through tests/run-tests.sh, or directly:
#     sh tests/lib.test.sh
# Each group builds a throw-away script that sources the library, because
# several library functions exit the shell (cc_die, cc_finish) and the test
# must survive that.
. "$(dirname "$0")/helper.sh"
LIB="$T_ROOT/lib/lib.sh"
SH=${TEST_SHELL:-sh}
OUT="$T_TMP/out"
S="$T_TMP/s"      # the throw-away scripts live here, apart from the output folder
mkdir -p "$S"
export BT_SKIP_VERIFY=1

# mk NAME BODY -> write a script that sources the lib and runs BODY.
mk() {
    printf '%s\n' ". \"$LIB\"" "$2" >"$S/$1.sh"
}
# $SH is left unquoted on purpose: TEST_SHELL may be two words ("busybox sh").
# shellcheck disable=SC2086
run() { $SH "$@"; }

t_start "flags and init"
mk init 'while [ $# -gt 0 ]; do if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi; case "$1" in --mine) MINE=$2; shift 2;; *) cc_die 2 "unknown option: $1";; esac; done
cc_init T-01 "init test" readonly
echo "apply=$CC_APPLY mine=${MINE:-} out=$CC_OUT host=$CC_HOST"
cc_finish'
r=$(run "$S/init.sh" --out "$OUT" --mine hello 2>/dev/null); t_eq "$?" 0 "readonly dry run exits 0"
t_has "$r" "apply=0 mine=hello" "dry run is the default and script options still parse"
r=$(run "$S/init.sh" --out="$OUT" --apply 2>/dev/null); t_has "$r" "apply=1" "--apply and --out=DIR forms work"
run "$S/init.sh" --out "$OUT" --bogus >/dev/null 2>&1; t_eq "$?" 2 "unknown option exits 2"
run "$S/init.sh" --out >/dev/null 2>&1; t_eq "$?" 2 "--out with no value exits 2"
t_ok "a log file was created" sh -c "ls '$OUT'/T-01_*.log"
r=$(run "$S/init.sh" --out "$OUT" 2>&1 >/dev/null); t_has "$r" "READ-ONLY" "a read-only script's banner says READ-ONLY"

t_start "output folder may not be inside the kit"
mkdir -p "$T_TMP/kit"; cp "$S/init.sh" "$T_TMP/kit/s.sh"
run "$T_TMP/kit/s.sh" --out "$T_TMP/kit/out" >/dev/null 2>&1; t_eq "$?" 2 "refuses --out inside the script's own folder"

t_start "apply without a protected list is refused for 'changes' scripts"
mk chg 'while [ $# -gt 0 ]; do cc_common_flag "$@" && { shift "$CC_SHIFT"; continue; }; shift; done
cc_init T-02 "change test" changes
cc_run "make marker" touch "$MARK"
cc_finish'
MARK="$T_TMP/marker"; export MARK
run "$S/chg.sh" --out "$OUT" --apply >/dev/null 2>&1; t_eq "$?" 3 "exit 3 with no protected list"
t_fail "nothing was changed" test -e "$MARK"
r=$(run "$S/chg.sh" --out "$OUT" 2>&1 >/dev/null); t_eq "$?" 0 "dry run needs no protected list"
t_has "$r" "DRY RUN" "a 'changes' script's banner says DRY RUN"
t_fail "dry run changed nothing" test -e "$MARK"
run "$S/chg.sh" --out "$OUT" --apply --no-protected >/dev/null 2>&1; t_eq "$?" 0 "--no-protected allows apply"
t_ok "apply made the change" test -e "$MARK"

t_start "cc_run counts failures and exits 5"
mk fail 'while [ $# -gt 0 ]; do cc_common_flag "$@" && { shift "$CC_SHIFT"; continue; }; shift; done
cc_init T-03 "fail test" changes
cc_run "this fails" false
cc_run "this works" true
cc_finish'
r=$(run "$S/fail.sh" --out "$OUT" --apply --no-protected 2>&1); t_eq "$?" 5 "exit 5 when a change failed"
t_has "$r" "changed=1" "one success counted"; t_has "$r" "failed=1" "one failure counted"

t_start "cc_run_quiet never logs the command line"
mk quiet 'while [ $# -gt 0 ]; do cc_common_flag "$@" && { shift "$CC_SHIFT"; continue; }; shift; done
cc_init T-04 "quiet test" changes
cc_run_quiet "set a password" echo S3cretValue
cc_finish'
r=$(run "$S/quiet.sh" --out "$OUT" --apply --no-protected 2>&1)
t_hasnt "$r" "S3cretValue" "secret is not printed"
t_fail "secret is not in any log" grep -rq S3cretValue "$OUT"

t_start "protected list"
cat >"$T_TMP/prot.csv" <<'P'
type,value,note
# comment line
port,80/tcp,scored web
port,53,dns both protocols
service,Apache2,scored
"account","svc-web","scoring login"
path,/var/www/html,site
P
printf 'service,sshd,windows line ending\r\n' >>"$T_TMP/prot.csv"
mk prot 'CC_PROTECTED=$PROT
chk() { if cc_is_protected "$1" "$2"; then echo yes; else echo no; fi; }
echo "a=$(chk port 80/tcp) b=$(chk port 80) c=$(chk port 80/udp) d=$(chk port 53/udp) e=$(chk port 8080) f=$(chk service apache2) g=$(chk account SVC-WEB) h=$(chk service sshd) i=$(chk account root) j=$(chk path /var/www/html)"'
PROT="$T_TMP/prot.csv"; export PROT
r=$(run "$S/prot.sh")
t_eq "$r" "a=yes b=yes c=no d=yes e=no f=yes g=yes h=yes i=no j=yes" "matching rules (case, quotes, CRLF, port forms)"
mk guard 'while [ $# -gt 0 ]; do cc_common_flag "$@" && { shift "$CC_SHIFT"; continue; }; shift; done
cc_init T-05 "guard test" changes
cc_guard port 80 && echo "port-allowed"
cc_guard port 8080 && echo "8080-allowed"
cc_guard account svc-web && echo "account-allowed"
cc_finish'
r=$(run "$S/guard.sh" --out "$OUT" --protected "$PROT" --apply 2>&1)
t_hasnt "$r" "port-allowed" "protected port refused"; t_has "$r" "8080-allowed" "unlisted port allowed"
t_hasnt "$r" "account-allowed" "protected account refused"; t_has "$r" "refused=2" "refusals counted"
r=$(run "$S/guard.sh" --out "$OUT" --protected "$PROT" --apply --force-scored 2>&1)
t_has "$r" "account-allowed" "--force-scored overrides for accounts"; t_hasnt "$r" "port-allowed" "--force-scored does not override ports"

t_start "backup, undo log and quarantine"
mk bk 'while [ $# -gt 0 ]; do cc_common_flag "$@" && { shift "$CC_SHIFT"; continue; }; shift; done
cc_init T-06 "backup test" changes
cc_backup_file "$TARGET" || cc_die 1 "backup failed"
[ "$CC_APPLY" = 1 ] && echo changed >"$TARGET"
cc_quarantine "$BAD"
echo "undo=$CC_UNDO"
cc_finish'
TARGET="$T_TMP/it'\''s a file.conf"; BAD="$T_TMP/bad file.sh"; export TARGET BAD
echo original >"$TARGET"; echo evil >"$BAD"
run "$S/bk.sh" --out "$OUT" >/dev/null 2>&1
t_eq "$(cat "$TARGET")" original "dry run leaves the file alone"; t_ok "dry run does not quarantine" test -e "$BAD"
r=$(run "$S/bk.sh" --out "$OUT" --apply --no-protected 2>/dev/null)
UNDO=$(printf '%s\n' "$r" | sed -n 's/^undo=//p')
t_eq "$(cat "$TARGET")" changed "apply changed the file"; t_fail "apply quarantined the bad file" test -e "$BAD"
t_file "$UNDO" "undo log exists"
# Roll back by running the undo commands newest first, exactly as an operator would.
[ -n "$UNDO" ] && awk -F'\t' '{ a[NR] = $4 } END { for (i = NR; i >= 1; i--) print a[i] }' "$UNDO" >"$T_TMP/undo.sh"
t_ok "undo commands run cleanly" run "$T_TMP/undo.sh"
t_eq "$(cat "$TARGET")" original "undo restored the file (name has a quote and spaces)"
t_ok "undo put the quarantined file back" test -e "$BAD"

t_start "passwords"
mk pw 'i=0; while [ $i -lt 20 ]; do cc_genpass 16; i=$((i+1)); done; cc_genpass 24'
r=$(run "$S/pw.sh" 2>&1)
t_eq "$(printf '%s\n' "$r" | wc -l | tr -d ' ')" 21 "21 passwords generated"
t_eq "$(printf '%s\n' "$r" | awk 'length($0) != 16 && NR <= 20' | wc -l | tr -d ' ')" 0 "length is 16"
t_eq "$(printf '%s\n' "$r" | tail -n 1 | awk '{print length($0)}')" 24 "custom length works"
t_eq "$(printf '%s\n' "$r" | grep -c '[^A-HJ-NP-Za-km-z2-9_-]')" 0 "only allowed characters (no look-alikes)"
t_eq "$(printf '%s\n' "$r" | grep -c '^[-_]')" 0 "never starts with - or _"
t_eq "$(printf '%s\n' "$r" | sort -u | wc -l | tr -d ' ')" 21 "all different"
t_eq "$(printf '%s\n' "$r" | grep '[A-Z]' | grep '[a-z]' | grep -c '[0-9]')" 21 "each has upper, lower and digit"

t_start "csv and findings"
mk csv 'while [ $# -gt 0 ]; do cc_common_flag "$@" && { shift "$CC_SHIFT"; continue; }; shift; done
cc_init T-07 "csv test" readonly
f=$(cc_csv_new things "a,b,c")
cc_csv_row "$f" "plain" "has \"quotes\", and comma" ""
cc_csv_row "$f" "" "two
lines" "x"
cc_finding "telnet running" FIX-TELNET safe "port 23 open"
cc_finding "smbv1 on" FIX-SMB1 service "scored share uses it" "port 445"
echo "csv=$f"; echo "find=$CC_FINDINGS"
cc_finish'
r=$(run "$S/csv.sh" --out "$OUT" 2>/dev/null)
F=$(printf '%s\n' "$r" | sed -n 's/^csv=//p'); FF=$(printf '%s\n' "$r" | sed -n 's/^find=//p')
t_eq "$(sed -n 2p "$F")" '"plain","has ""quotes"", and comma",""' "quotes doubled, empty last field kept"
t_eq "$(sed -n 3p "$F")" '"","two lines","x"' "line break flattened, empty first field kept"
t_eq "$(wc -l <"$F" | tr -d ' ')" 3 "one line per row"
t_has "$(sed -n 1p "$FF")" "host,script,weakness,fix_id,class" "findings header"
t_has "$(sed -n 3p "$FF")" '"FIX-SMB1","service","port 445"' "finding row has fix id, class and dependency"
mk badclass 'while [ $# -gt 0 ]; do cc_common_flag "$@" && { shift "$CC_SHIFT"; continue; }; shift; done
cc_init T-08 "bad class test" readonly
cc_finding w f wrongclass d'
run "$S/badclass.sh" --out "$OUT" >/dev/null 2>&1; t_eq "$?" 1 "bad finding class is rejected"

t_start "helpers"
mk help 'cc_detect_os
echo "kernel=$CC_OS_KERNEL init=$CC_INIT"
echo "first=$(cc_first definitely-not-a-tool sh)"
cc_first nope1 nope2 >/dev/null || echo "none=ok"
echo "which=$(cc_which sh)"
cc_which definitely-not-a-tool >/dev/null || echo "which-none=ok"
echo "q=$(cc_shquote "a'\''b c")"
echo "sum=$(printf abc >"$T/abc"; cc_sha256 "$T/abc")"'
T="$T_TMP"; export T
r=$(run "$S/help.sh" 2>/dev/null)
t_has "$r" "kernel=$(uname -s | tr 'A-Z' 'a-z')" "kernel detected"
t_has "$r" "first=sh" "cc_first skips missing tools"; t_has "$r" "none=ok" "cc_first fails when nothing exists"
t_has "$r" "which=/" "cc_which prints a full path"; t_has "$r" "which-none=ok" "cc_which fails for a missing program"
t_has "$r" "sum=ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" "sha256 of abc is correct"
t_eq "$(printf '%s\n' "$r" | sed -n 's/^q=//p')" "'a'\\''b c'" "shell quoting"

t_start "run folder, raw capture and flags"
mk flags 'while [ $# -gt 0 ]; do cc_common_flag "$@" && { shift "$CC_SHIFT"; continue; }; shift; done
cc_init T-10 "flags test" readonly
cc_use_run_dir
f=$(cc_csv_new things "a,b")
cc_save uname uname -s
cc_flag LOW users "bob" "low one"
cc_flag HIGH ports "4444/tcp" "nc listening, \"quoted\", with comma"
( cc_flag MED ssh "root" "flag written from a subshell" )
cc_flag HIGH files "/tmp/x" "second high"
echo "run=$CC_RUN_DIR"; echo "csv=$f"; echo "raw=$CC_LAST_SAVE"
cc_flag_report 2
cc_flag_report 30 >"$CC_RUN_DIR/report30.txt"
_first=$CC_RUN_DIR; cc_use_run_dir; echo "second=$CC_RUN_DIR"; CC_RUN_DIR=$_first; CC_CSV_DIR=$_first
cc_finish'
r=$(run "$S/flags.sh" --out "$OUT" 2>/dev/null)
RUN=$(printf '%s\n' "$r" | sed -n 's/^run=//p')
t_eq "$(printf '%s\n' "$r" | sed -n 's/^second=//p')" "$RUN-2" "a second run folder in the same second gets -2"
t_eq "$(printf '%s\n' "$r" | sed -n 's/^csv=//p')" "$RUN/things.csv" "CSV goes into the run folder"
t_ok "raw output saved" grep -q "$(uname -s)" "$RUN/raw/uname.txt"
t_has "$(sed -n 1p "$RUN/raw/uname.txt")" "# command: uname -s" "raw file records the command"
t_eq "$(wc -l <"$RUN/flags.csv" | tr -d ' ')" 5 "four flags plus header, including the one from a subshell"
t_has "$r" "Flags: 2 high, 1 medium, 1 low" "report counts from the file"
t_has "$r" "[ports] 4444/tcp: nc listening, \"quoted\", with comma" "report keeps quotes and commas intact"
t_hasnt "$r" "flag written from a subshell" "MAX=2 cuts the list after two lines"
t_has "$r" "1 more high/medium not shown" "report says how many were cut"
t_has "$(cat "$RUN/report30.txt")" "MED - look soon" "with room, MED lines are shown"
t_hasnt "$(cat "$RUN/report30.txt")" "low one" "LOW lines are never printed"
t_ok "summary line in the log names the run folder" grep -q "results: $RUN" "$OUT/$(basename "$RUN").log"
mk noflags 'while [ $# -gt 0 ]; do cc_common_flag "$@" && { shift "$CC_SHIFT"; continue; }; shift; done
cc_init T-11 "no flags" readonly; cc_flag_report; cc_finish'
r=$(run "$S/noflags.sh" --out "$OUT" 2>/dev/null); t_has "$r" "Flags: none" "no flags reported cleanly"
mk badsev 'while [ $# -gt 0 ]; do cc_common_flag "$@" && { shift "$CC_SHIFT"; continue; }; shift; done
cc_init T-12 "bad sev" readonly; cc_flag URGENT x y z'
run "$S/badsev.sh" --out "$OUT" >/dev/null 2>&1; t_eq "$?" 1 "bad severity is rejected"
mk csvp 'printf "%s\n" "\"a\",\"b,c\",\"d \"\"q\"\"\",\"\"" | awk "$CC_AWK_CSV"'"'"'{ n = csvsplit($0, f); print n "|" f[1] "|" f[2] "|" f[3] "|" f[4] "|" }'"'"
t_eq "$(run "$S/csvp.sh")" '4|a|b,c|d "q"||' "CSV parser handles commas, doubled quotes and empty fields"

t_start "numbered run folders"
mk numbered 'while [ $# -gt 0 ]; do cc_common_flag "$@" && { shift "$CC_SHIFT"; continue; }; shift; done
cc_init T-13 "numbered" readonly
cc_use_numbered_dir thing; echo "a=$CC_RUN_DIR"
cc_use_numbered_dir thing; echo "b=$CC_RUN_DIR"
cc_finish'
mkdir -p "$T_TMP/num/thing-9" "$T_TMP/num/thing-x" "$T_TMP/num/other-50"
r=$(run "$S/numbered.sh" --out "$T_TMP/num" 2>/dev/null)
t_eq "$(printf '%s\n' "$r" | sed -n 's/^a=//p')" "$T_TMP/num/thing-10" "next number after the highest existing one"
t_eq "$(printf '%s\n' "$r" | sed -n 's/^b=//p')" "$T_TMP/num/thing-11" "a second folder gets the next number"
t_has "$(cat "$T_TMP/num/thing-10/run.txt")" "id=T-13" "run.txt records the ID"
t_ok "raw folder created" test -d "$T_TMP/num/thing-10/raw"

t_start "readable tables"
mk pretty 'printf "%s\n" "name,note" "\"bob\",\"has, comma\"" "\"a\",\"0123456789012345\"" >"$T/p.csv"
cc_csv_pretty "$T/p.csv" "$T/p.txt" 10; cat "$T/p.txt"
printf "name,note\n" >"$T/e.csv"; cc_csv_pretty "$T/e.csv" "$T/e.txt"; cat "$T/e.txt"'
r=$(run "$S/pretty.sh" 2>/dev/null)
t_has "$r" "NAME  NOTE" "header in capitals, columns aligned"
t_has "$r" "----  ----------" "dashed line as wide as each column"
t_has "$r" "bob   has, comma" "commas inside a value kept"
t_has "$r" "a     0123456..." "long values cut with ..."
t_has "$r" "(nothing found)" "an empty CSV says so"

t_start "text tables (no CSV)"
mk tables 'while [ $# -gt 0 ]; do cc_common_flag "$@" && { shift "$CC_SHIFT"; continue; }; shift; done
CC_TABLES=1
cc_init T-14 "tables" readonly
cc_use_numbered_dir tab
f=$(cc_table_new ports ip proto port service)
cc_table_row "$f" 10.0.0.5 tcp 80 "a|b"
cc_table_row "$f" 10.0.0.100 udp 53 ""
cc_table_align "$f"
echo "file=$f"
awk "$CC_AWK_TABLE"'"'"'NR > 1 { n = tsplit($0, a); print "row=" n ":" a[1] ":" a[4] ":" }'"'"' "$f"
cc_flag LOW users bob "low one"
( cc_flag HIGH ports "4444/tcp" "from a subshell, with, commas" )
cc_flag MED ssh root "medium"
cc_table_sort_flags "$CC_RUN_DIR/flags.txt"
cc_flag_report 30
echo "flags=$CC_FLAGS"
cc_finish'
r=$(run "$S/tables.sh" --out "$T_TMP/tab" 2>/dev/null)
TF=$(printf '%s\n' "$r" | sed -n 's/^file=//p')
t_eq "$(sed -n 1p "$TF")" "ip         | proto | port | service" "header line, columns lined up"
t_eq "$(sed -n 2p "$TF")" "10.0.0.5   | tcp   | 80   | a/b" "a | inside a value becomes /"
t_has "$r" "row=4:10.0.0.5:a/b:" "tsplit gives the trimmed fields"
t_has "$r" "row=4:10.0.0.100::" "an empty value stays empty"
t_fail "no CSV in the run folder" sh -c "ls '$T_TMP/tab'/tab-1 | grep -q 'csv'"
t_has "$r" "Flags: 1 high, 1 medium, 1 low" "flags.txt: the report counts it, the subshell one too"
t_has "$r" "[ports] 4444/tcp: from a subshell, with, commas" "commas kept"
t_eq "$(sed -n 2p "$T_TMP/tab/tab-1/flags.txt" | cut -d'|' -f1 | tr -d ' ')" HIGH "flags sorted: HIGH first"
mk hostlist 'cc_hosts_rows "$1"'
printf '# name ip os role connect port user scored notes\nname ip os\nweb01 10.0.0.20 linux web ssh 22 root http:80;https:443 Ubuntu web box\nfw1 10.0.0.1 network edge ssh - admin - Palo Alto\n\n' >"$T_TMP/hosts.txt"
r=$(run "$S/hostlist.sh" "$T_TMP/hosts.txt")
t_eq "$(printf '%s\n' "$r" | sed -n 1p)" "web01|10.0.0.20|linux|web|ssh|22|root|http:80;https:443|Ubuntu web box|" "host list: columns, notes are the rest of the line"
t_eq "$(printf '%s\n' "$r" | sed -n 2p)" "fw1|10.0.0.1|network|edge|ssh||admin||Palo Alto|" "a - is an empty column"
t_eq "$(printf '%s\n' "$r" | grep -c .)" 2 "comments, a header line and blank lines skipped"
printf 'host,ip,os,role,connect,port,user,scored_services,notes,vendor\r\nr1,10.0.0.1,network,core,ssh,22,admin,,"Cisco, IOS",cisco-ios\r\n' >"$T_TMP/hosts.csv"
t_eq "$(run "$S/hostlist.sh" "$T_TMP/hosts.csv")" "r1|10.0.0.1|network|core|ssh|22|admin||Cisco, IOS|cisco-ios" "an older CSV host list is still read"

t_start "questions and the revert timer"
mk ask 'while [ $# -gt 0 ]; do cc_common_flag "$@" && { shift "$CC_SHIFT"; continue; }; shift; done
cc_init T-14 "ask" changes
cc_ask "yes question" Y && echo "q1=yes"
cc_ask "no question" N || echo "q2=no"
cc_ask_text "text question" other; echo "q3=$CC_ANSWER"
echo "now=$(cc_now)"
cc_use_numbered_dir timer
cc_timer_start 2
f="$CC_RUN_DIR/thing"; echo before >"$f"
cc_undo_add "put thing back" "echo before >$(cc_shquote "$f")"
echo after >"$f"
echo "dir=$CC_RUN_DIR"
cc_timer_finish
cc_finish'
r=$(BT_TIMER_METHOD=background; export BT_TIMER_METHOD; run "$S/ask.sh" --out "$T_TMP/ask" --batch --apply --no-protected 2>/dev/null)
t_has "$r" "q1=yes" "--batch: a Y question takes yes"
t_has "$r" "q2=no" "--batch: an N question takes no"
t_has "$r" "q3=other" "--batch: a text question takes its default"
t_has "$r" "[?] yes question [Y/n] y (default): yes" "the default taken is shown"
t_ok "cc_now is a number" sh -c "printf '%s' '$(printf '%s\n' "$r" | sed -n 's/^now=//p')' | grep -Eq '^[0-9]{9,}$'"
D=$(printf '%s\n' "$r" | sed -n 's/^dir=//p')
t_has "$r" "Changes kept (--batch)" "--batch keeps at the end"
t_file "$D/KEEP" "KEEP written"
r=$(BT_TIMER_METHOD=background; export BT_TIMER_METHOD; run "$S/ask.sh" --out "$T_TMP/ask2" --apply --no-protected </dev/null 2>/dev/null)
D=$(printf '%s\n' "$r" | sed -n 's/^dir=//p')
t_has "$r" "touch $D/KEEP" "no terminal: says how to keep"
sleep 4
t_eq "$(cat "$D/thing")" "before" "no answer: the timer put the change back"
t_has "$(cat "$D/revert.log")" "undone: put thing back" "revert.log says what was undone"

t_start "kit integrity check"
unset BT_SKIP_VERIFY
mkdir -p "$T_TMP/dist"; cp "$S/init.sh" "$T_TMP/dist/v.sh"
( cd "$T_TMP/dist" && sha256sum v.sh >MANIFEST.sha256 )
run "$T_TMP/dist/v.sh" --out "$OUT" >/dev/null 2>&1; t_eq "$?" 0 "untouched script passes the manifest check"
echo "# tampered" >>"$T_TMP/dist/v.sh"
r=$(run "$T_TMP/dist/v.sh" --out "$OUT" 2>&1); t_eq "$?" 3 "edited script is refused with exit 3"
t_has "$r" "KIT CHECK FAILED" "message explains why"
(BT_SKIP_VERIFY=1; export BT_SKIP_VERIFY; run "$T_TMP/dist/v.sh" --out "$OUT" >/dev/null 2>&1); t_eq "$?" 0 "BT_SKIP_VERIFY=1 bypasses the check"
# The hash file next to the script (what tools/build.sh writes now).
mkdir -p "$T_TMP/dist2"; cp "$S/init.sh" "$T_TMP/dist2/w.sh"
( cd "$T_TMP/dist2" && sha256sum w.sh >w.sh.sha256 )
run "$T_TMP/dist2/w.sh" --out "$OUT" >/dev/null 2>&1; t_eq "$?" 0 "SCRIPT.sha256 next to it: an untouched script passes"
echo "# tampered" >>"$T_TMP/dist2/w.sh"
r=$(run "$T_TMP/dist2/w.sh" --out "$OUT" 2>&1); t_eq "$?" 3 "and an edited one is refused"
t_has "$r" "w.sh.sha256" "naming the hash file"

t_start "which box: the shared list and the guess"
B="$T_TMP/boxroot"
mk box 'BOX=${1:-${BOX:-}}; cc_box_valid "${1:-}" || { echo "invalid ${1:-}"; exit 0; }; cc_box_ask "${2:-o}" "$B"; echo "BOX=$BOX"'
sed "s|\$B|$B|" "$S/box.sh" >"$S/box.t" && mv "$S/box.t" "$S/box.sh"
guess() { rm -rf "$B"; mkdir -p "$B"; for _f in "$@"; do mkdir -p "$B/${_f%/*}"; : >"$B/$_f"; done; }
bx() { (export BT_NO_TTY=1; run "$S/box.sh" "$@" 2>&1); }
guess;                                  t_has "$(bx '' o)" "BOX=other" "nothing found: other"
t_hasnt "$(bx '' o)" "looks like" "and no guess is shown"
guess etc/gitea/app.ini;                t_has "$(bx '' o)" "BOX=gitea" "Gitea is found"
t_has "$(bx '' o)" "This box looks like: gitea (/etc/gitea/app.ini)" "and says why"
guess opt/splunk/bin/splunk;            t_has "$(bx '' e)" "BOX=splunk" "Splunk wins over a script default"
guess etc/postfix/main.cf etc/dovecot/dovecot.conf; t_has "$(bx '' o)" "BOX=webmail" "postfix and dovecot: webmail"
guess etc/exports; echo '/srv 10.0.0.0/24(rw)' >"$B/etc/exports"; t_has "$(bx '' o)" "BOX=fileshare" "an NFS export: fileshare"
guess etc/samba/smb.conf; printf '[global]\n[homes]\n' >"$B/etc/samba/smb.conf"; t_has "$(bx '' o)" "BOX=other" "Samba with no shares is not a file share"
printf '[global]\n[data]\npath=/d\n' >"$B/etc/samba/smb.conf"; t_has "$(bx '' o)" "BOX=fileshare" "Samba with a share: fileshare"
guess etc/nginx/nginx.conf;             t_has "$(bx '' o)" "BOX=web" "a web server: web"
t_has "$(bx '' e)" "BOX=ecomm" "but a web server does not replace the ecomm default"
t_has "$(bx '' w)" "BOX=webmail" "or the webmail default"
t_has "$(bx gitea o)" "BOX=gitea" "every box kind is valid"
t_has "$(bx nope o)" "invalid nope" "an unknown one is not"
t_has "$(export BOX=fileshare; bx '' o)" "BOX=fileshare" "a given --box is kept, no question"

t_done
