#!/bin/sh
# =============================================================================
# ID:       SH-04
# NAME:     Scan diff
# ROLE:     Network  (wave 3)
# KIND:     readonly - reads two earlier result folders, touches no host
# VERSION:  1.0.0
#
# PURPOSE
#   Answers "what changed?" by comparing two earlier runs of the same script:
#     two network scans (SH-03)    hosts that appeared or vanished, ports
#                                  that opened or closed, versions that changed
#     two Linux collector runs     accounts, listening ports, services,
#     (SH-05) of one host          cron/startup entries, SSH keys, sudo rules,
#                                  SUID files and locked files that were
#                                  added, removed or changed
#   Run a baseline in the first minutes, run again later, and diff: the
#   additions are where to look for red team persistence.
#
# USAGE
#   sh SH-04-scan-diff.sh [--out DIR]                    newest two SH-03 runs
#   sh SH-04-scan-diff.sh --type sh05 --host web01       newest two SH-05 runs of web01
#                                                        (linux-enum-N folders too)
#   sh SH-04-scan-diff.sh --old DIR1 --new DIR2          two specific run folders
#
# OPTIONS
#   --old DIR       the earlier run folder (e.g. ~/ccdc-out/netscan-1)
#   --new DIR       the later run folder
#   --type T        sh03 or sh05: which runs to pick when --old/--new are not
#                   given (default sh03).  With folders given, the type comes
#                   from the folder names
#   --host NAME     for --type sh05 without folders: which host's runs
#                   (default: the host of the newest SH-05 run)
#   --runs DIR      where to look for run folders (default: the --out folder)
#   --max-lines N   changes listed on screen (default 40; all are in the CSV)
#   --max-flags N   HIGH/MED flags shown on screen (default 30)
#   --help          this text plus the common options
#
# OUTPUTS  (under --out, in SH-04_<host>_<UTC time>/)
#   One numbered folder per run: diff-1, diff-2, ... (higher = newer)
#   summary.txt   counts per section and the changes, newest-relevant first
#   changes.txt   every change as a readable table (added first)
#   flags.txt     every flag, HIGH first
#   csv/          the same as CSV: changes.csv, flags.csv
#   run.txt       ID, host and time
#
# WHAT IT CHANGES
#   Nothing.  It only reads CSV files written by SH-03 or SH-05.
#
# DEPENDS ON
#   awk, sort.  The CSV files of the two runs being compared.
#
# TESTED ON
#   Ubuntu 24.04 under dash, bash, busybox sh, ksh93, mksh and yash, with
#   prepared SH-03 and SH-05 result folders.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - It compares what the two runs saw.  If the first run was not root and
#     the second was, "added" may only mean "now visible".  The summary warns
#     when the two runs differ in this way.
#   - Processes and connections are not compared: they change every second.
#   - Both runs must use the same profile for a fair comparison; a section
#     missing from one run is reported as skipped, not as everything removed.
#
# DEBUGGING
#   --debug shows which folders and files were picked.  changes.csv has every
#   difference; compare it with the two runs' CSV files if a change looks odd.
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
SH-04 Scan diff - what changed between two runs of SH-03 or SH-05
  sh SH-04-scan-diff.sh                         compare the newest two network scans
  sh SH-04-scan-diff.sh --type sh05 [--host H]  compare the newest two collector runs of a host
  sh SH-04-scan-diff.sh --old DIR --new DIR     compare two specific run folders

  --old DIR / --new DIR   run folders to compare
  --type sh03|sh05        which runs to pick automatically (default sh03)
  --host NAME             host for --type sh05 (default: newest run's host)
  --runs DIR              where the run folders are (default: --out folder)
  --max-lines N           changes listed on screen (default 40)
  --max-flags N           HIGH/MED flags shown on screen (default 30)
  --help                  show this text

USAGE
    cc_usage_common
}

OLD=""; NEW=""; TYPE=""; HOSTSEL=""; RUNS=""; MAXLINES=40; MAXFLAGS=30
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --old)       [ $# -ge 2 ] || cc_die 2 "--old needs a folder"; OLD=$2; shift 2 ;;
        --new)       [ $# -ge 2 ] || cc_die 2 "--new needs a folder"; NEW=$2; shift 2 ;;
        --type)      [ $# -ge 2 ] || cc_die 2 "--type needs sh03 or sh05"; TYPE=$2; shift 2 ;;
        --host)      [ $# -ge 2 ] || cc_die 2 "--host needs a name"; HOSTSEL=$2; shift 2 ;;
        --runs)      [ $# -ge 2 ] || cc_die 2 "--runs needs a folder"; RUNS=$2; shift 2 ;;
        --max-lines) [ $# -ge 2 ] || cc_die 2 "--max-lines needs a number"; MAXLINES=$2; shift 2 ;;
        --max-flags) [ $# -ge 2 ] || cc_die 2 "--max-flags needs a number"; MAXFLAGS=$2; shift 2 ;;
        --help|-h)   usage; exit 0 ;;
        *)           cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done
case "$MAXLINES" in ''|*[!0-9]*) cc_die 2 "--max-lines needs a whole number" ;; esac
case "$MAXFLAGS" in ''|*[!0-9]*) cc_die 2 "--max-flags needs a whole number" ;; esac
case "$TYPE" in ''|sh03|sh05) ;; *) cc_die 2 "--type must be sh03 or sh05" ;; esac
if [ -n "$OLD$NEW" ] && { [ -z "$OLD" ] || [ -z "$NEW" ]; }; then cc_die 2 "give both --old and --new, or neither"; fi

cc_init "SH-04" "Scan diff" readonly
[ -n "$RUNS" ] || RUNS=$CC_OUT

# Run folders come in two shapes:
#   SH-05_web01_20261111T140000Z   older runs: ID, host and time in the name
#   linux-enum-3                   numbered runs: ID, host and time in run.txt
# run_info DIR KEY -> a value from DIR/run.txt (id, host or time).
run_info() { sed -n "s/^$2=//p" "$1/run.txt" 2>/dev/null | head -n 1; }
# run_type DIR -> sh03 or sh05.
run_type() {
    case "$(basename "$1")" in
        SH-03_*|netscan-*) echo sh03 ;;
        SH-05_*|linux-enum-*) echo sh05 ;;
        *) echo "" ;;
    esac
}
# run_host DIR -> the host the run was made on.  For named folders strip the
#   ID in front and the time at the end (keeps hosts whose names contain "_").
run_host() {
    if [ -f "$1/run.txt" ]; then run_info "$1" host
    else basename "$1" | sed 's/^SH-0[0-9]_//; s/_[^_]*$//'
    fi
}
# run_time DIR -> start time, e.g. 20261111T140000Z.  Sorts in time order as
#   plain text.
run_time() {
    if [ -f "$1/run.txt" ]; then run_info "$1" time
    else basename "$1" | sed 's/^.*_//'
    fi
}

if [ -n "$OLD" ]; then
    [ -d "$OLD" ] || cc_die 2 "not a folder: $OLD"
    [ -d "$NEW" ] || cc_die 2 "not a folder: $NEW"
    OLD=$(cc_abspath "$OLD"); NEW=$(cc_abspath "$NEW")
    TYPE=$(run_type "$NEW")
    [ -n "$TYPE" ] || cc_die 2 "$NEW is not an SH-03 or SH-05 run folder (its name must start with netscan-, linux-enum-, SH-03_ or SH-05_). To see what a fix script changed, run the enum again and compare the two enum runs"
    [ "$(run_type "$OLD")" = "$TYPE" ] || cc_die 2 "the two folders are from different scripts: $(basename "$OLD") and $(basename "$NEW")"
else
    [ -n "$TYPE" ] || TYPE=sh03
    _prefix=SH-03; [ "$TYPE" = sh05 ] && _prefix=SH-05
    [ -d "$RUNS" ] || cc_die 3 "no results folder: $RUNS (give --runs, or --old and --new)"
    # Build "time<TAB>host<TAB>folder" lines for every finished run (a run
    # folder with summary.txt; an interrupted run has none and is skipped),
    # then sort by time.  For SH-03 any host is fine (scans normally come
    # from one admin box); for SH-05 both runs must be of the same host.
    _tab=$(printf '\t')
    _cands=""
    for _d in "$RUNS"/"$_prefix"_* "$RUNS"/linux-enum-* "$RUNS"/netscan-*; do
        [ -d "$_d" ] && [ -f "$_d/summary.txt" ] || continue
        [ "$(run_type "$_d")" = "$TYPE" ] || continue
        _cands="$_cands$(run_time "$_d")$_tab$(run_host "$_d")$_tab$_d
"
    done
    _cands=$(printf '%s' "$_cands" | sort)
    if [ "$TYPE" = sh05 ]; then
        # Default host: the host of the newest SH-05 run.
        [ -n "$HOSTSEL" ] || HOSTSEL=$(printf '%s\n' "$_cands" | tail -n 1 | cut -f2)
        _cands=$(printf '%s\n' "$_cands" | awk -F'\t' -v h="$HOSTSEL" '$2 == h')
    fi
    _n=$(printf '%s\n' "$_cands" | grep -c .)
    cc_debug "found $_n finished $_prefix run(s)${HOSTSEL:+ of $HOSTSEL} in $RUNS"
    [ "$_n" -ge 2 ] || cc_die 3 "need two finished $_prefix runs${HOSTSEL:+ of $HOSTSEL} in $RUNS to compare, found $_n. Run $_prefix again, or give --old and --new"
    OLD=$(printf '%s\n' "$_cands" | tail -n 2 | head -n 1 | cut -f3-)
    NEW=$(printf '%s\n' "$_cands" | tail -n 1 | cut -f3-)
fi
if [ "$TYPE" = sh05 ] && [ "$(run_host "$OLD")" != "$(run_host "$NEW")" ]; then
    cc_warn "comparing two different hosts: $(run_host "$OLD") and $(run_host "$NEW")"
fi
cc_info "old: $OLD"
cc_info "new: $NEW"
cc_use_numbered_dir diff
CC_CSV_DIR="$CC_RUN_DIR/csv"
mkdir -p "$CC_CSV_DIR" || cc_die 3 "cannot create $CC_CSV_DIR"
# cfile DIR FILE -> where FILE is in a run folder: csv/FILE in runs that keep
#   their CSV files in csv/, DIR/FILE in older runs.
cfile() { if [ -f "$1/csv/$2" ]; then printf '%s\n' "$1/csv/$2"; else printf '%s\n' "$1/$2"; fi; }
W="$CC_RUN_DIR/.work"; mkdir -p "$W" || cc_die 3 "cannot create $W"
CH=$(cc_csv_new changes "section,change,key,old,new")
# Fields inside the work files are separated by the ASCII "unit separator"
# (octal 037), a character that never appears in the CSV values.  "|" cannot
# be used: keys like "tcp | 0.0.0.0 | 22" contain it.
US=$(printf '\037')

# diff_csv SECTION FILE KEYCOLS SHOWCOLS
#   Compare <old>/FILE with <new>/FILE.
#     KEYCOLS   comma-separated column names that identify a row (the "same
#               thing" in both runs), e.g. "proto,address,port"
#     SHOWCOLS  columns compared for "changed" and shown in old/new
#   Rows whose key is only in the new run are "added", only in the old run
#   "removed", in both with different SHOWCOLS "changed".  Writes rows to
#   changes.csv and "section|change|key|old|new" lines to $W/d_SECTION.
#   A file missing from either run is reported as skipped.
diff_csv() {
    _sec=$1; _file=$2
    _of=$(cfile "$OLD" "$_file"); _nf=$(cfile "$NEW" "$_file")
    if [ ! -f "$_of" ] || [ ! -f "$_nf" ]; then
        printf '%s|skipped (not in both runs)\n' "$_sec" >>"$W/skipped"
        return 0
    fi
    awk -v keys="$3" -v show="$4" -v sec="$_sec" -v ch="$CH" "$CC_AWK_CSV"'
        function q(s) { gsub(/"/, "\"\"", s); return "\"" s "\"" }  # awk, not shell: posix-ok
        function cols(spec, hdr, out,   n, k, i, j) {  # awk, not shell: posix-ok
            n = split(spec, k, ",")
            for (i = 1; i <= n; i++) { out[i] = 0; for (j = 1; j <= hdr[0]; j++) if (hdr[j] == k[i]) out[i] = j }
            out[0] = n
        }
        function pick(f, c,   i, s) { s = ""; for (i = 1; i <= c[0]; i++) s = s (i > 1 ? " | " : "") (c[i] ? f[c[i]] : ""); return s }  # awk, not shell: posix-ok
        FNR == 1 {
            file++; n = csvsplit($0, h); h[0] = n
            cols(keys, h, kc); cols(show, h, sc)
            next
        }
        {
            csvsplit($0, f); k = pick(f, kc); v = pick(f, sc)
            if (file == 1) { old[k] = v } else { new[k] = v; order[++m] = k }
        }
        END {
            for (i = 1; i <= m; i++) {
                k = order[i]
                if (!(k in old)) out("added", k, "", new[k])
                else if (old[k] != new[k]) out("changed", k, old[k], new[k])
            }
            for (k in old) if (!(k in new)) out("removed", k, old[k], "")
        }
        function out(c, k, o, n) {  # awk, not shell: posix-ok
            print q(sec) "," q(c) "," q(k) "," q(o) "," q(n) >> ch
            print sec "\037" c "\037" k "\037" o "\037" n
        }' "$_of" "$_nf" >"$W/d_$_sec"
    cat "$W/d_$_sec" >>"$W/all"
    cc_debug "$_sec: $(grep -c . "$W/d_$_sec") change(s)"
}

: >"$W/all"; : >"$W/skipped"; : >"$W/flagged"

# flag_rule SECTION CHANGE SEVERITY TEXT
#   Turn every change of one kind in one section into a flag.  TEXT is the
#   detail; the changed item (the key) becomes the flag's item.
flag_rule() {
    [ -f "$W/d_$1" ] || return 0
    # Skip items a stronger rule already flagged (the HIGH rules run first),
    # so one change gets one flag, not a HIGH and a MED.
    awk -F"$US" -v c="$2" -v done_file="$W/flagged" '
        BEGIN { while ((getline l < done_file) > 0) seen[l] = 1 }
        $2 == c && !(($1 FS $3) in seen)' "$W/d_$1" >"$W/rule"
    while IFS=$US read -r _s _c _k _o _n; do
        _extra=""
        [ "$_c" = changed ] && _extra=" (was: $_o; now: $_n)"
        # Show the new values only if they hold something besides separators
        # (e.g. a port whose owning program was not visible gives " | ").
        [ "$_c" = added ] && [ -n "$(printf '%s' "$_n" | tr -d ' |')" ] && _extra=" ($_n)"
        cc_flag "$3" "$1" "$_k" "$4$_extra"
        printf '%s%s%s\n' "$1" "$US" "$_k" >>"$W/flagged"
    done <"$W/rule"
}

# flag_where SECTION SEVERITY TEXT AWK-CONDITION
#   Like flag_rule, but for changes picked by an awk condition on the change
#   line ($1 section, $2 change, $3 key, $4 old, $5 new; the key's parts are
#   in kp[1], kp[2], ...).  Used for the HIGH special cases; they run before
#   the general rules, which then skip anything already flagged.
flag_where() {
    [ -f "$W/d_$1" ] || return 0
    awk -F"$US" '{ split($3, kp, " [|] ") } '"$4" "$W/d_$1" >"$W/rule"
    while IFS=$US read -r _s _c _k _o _n; do
        cc_flag "$2" "$1" "$_k" "$3"
        printf '%s%s%s\n' "$1" "$US" "$_k" >>"$W/flagged"
    done <"$W/rule"
}
# Ports that tools and backdoors use by default (bind shells, Metasploit,
# Docker API without TLS).  A new one of these is HIGH, not MED.
BACKDOOR_PORTS='^(1337|4444|4445|5555|6666|12345|31337|54321|2375)$'

if [ "$TYPE" = sh03 ]; then
    diff_csv hosts hosts.csv "ip" "hostname"
    diff_csv ports ports.csv "ip,proto,port" "service,version"
    diff_csv scored scored.csv "host,ip,service,port" "reachable"
    [ -f "$(cfile "$OLD" vulns.csv)" ] && diff_csv vulns vulns.csv "ip,proto,port,script" "state,title"
    # HIGH first.  The awk conditions are single-quoted on purpose: $2, $5
    # are awk fields, not shell variables.
    # ports keys are "ip | proto | port"; scored keys "host | ip | service | port".
    # shellcheck disable=SC2016
    flag_where scored HIGH "scored service was reachable and now is NOT: check it now" '$2 == "changed" && $5 == "no"'
    # shellcheck disable=SC2016
    flag_where ports HIGH "a backdoor-style port opened since the earlier scan" '$2 == "added" && kp[3] ~ /'"$BACKDOOR_PORTS"'/'
    flag_rule vulns added HIGH "new vuln or script finding since the earlier scan"
    flag_rule vulns removed LOW "vuln or script finding gone since the earlier scan"
    flag_rule scored added LOW "scored service check added (host list changed?)"
    flag_rule hosts added MED "host appeared since the earlier scan: find out what it is"
    flag_rule hosts removed MED "host no longer answers; if it runs a scored service, it is down"
    flag_rule ports added MED "port opened since the earlier scan"
    flag_rule ports removed MED "port closed since the earlier scan; if it is a scored service, it is down"
    flag_rule ports changed LOW "service or version changed"
else
    diff_csv users users.csv "user" "uid,shell,can_login,password,groups"
    diff_csv ports ports.csv "proto,address,port" "process,program"
    diff_csv services services.csv "name" "enabled,active"
    diff_csv autostart autostart.csv "source,user,entry" ""
    diff_csv ssh_keys ssh_keys.csv "user,file,fingerprint" "type,comment,options"
    diff_csv sudo sudo.csv "file,entry" ""
    diff_csv suid suid.csv "path" "mode,owner"
    diff_csv capabilities capabilities.csv "path" "capabilities"
    diff_csv immutable immutable.csv "path" "attributes"
    diff_csv pam pam.csv "file,entry" ""
    diff_csv firewall firewall.csv "tool" "status,detail"
    flag_rule users added HIGH "account created since the earlier run"
    flag_rule users changed MED "account changed (shell, password state, UID or groups)"
    flag_rule users removed MED "account removed since the earlier run"
    # ports keys are "proto | address | port".
    # shellcheck disable=SC2016
    flag_where ports HIGH "a backdoor-style port is now listening" '$2 == "added" && kp[3] ~ /'"$BACKDOOR_PORTS"'/'
    flag_rule ports added MED "new listening port"
    flag_rule ports removed MED "port stopped listening; if it is a scored service, it is down"
    flag_rule ports changed MED "a different program now owns this port"
    flag_rule services added MED "new service"
    flag_rule services changed LOW "service state changed"
    flag_rule autostart added HIGH "new scheduled or startup entry: a common way to keep access"
    flag_rule ssh_keys added HIGH "new SSH key accepted: a common way to keep access"
    flag_rule sudo added HIGH "new sudo rule"
    flag_rule suid added HIGH "new SUID/SGID program"
    flag_rule capabilities added HIGH "new file capability"
    flag_rule immutable added MED "file newly locked with chattr"
    flag_rule pam added HIGH "PAM login configuration changed"
    flag_rule pam removed MED "PAM line removed"
    flag_rule firewall changed MED "firewall state changed"
    # Same view in both runs?  A root run sees more than a non-root run.
    _ro=$(awk -F'","' '$1 == "\"collector_run_as_root" { gsub(/"/, "", $2); print $2 }' "$(cfile "$OLD" facts.csv)" 2>/dev/null)
    _rn=$(awk -F'","' '$1 == "\"collector_run_as_root" { gsub(/"/, "", $2); print $2 }' "$(cfile "$NEW" facts.csv)" 2>/dev/null)
    [ -n "$_ro" ] && [ "$_ro" != "$_rn" ] && cc_warn "one run was as root and the other was not; some 'added' or 'removed' items only reflect what each run could see"
fi

# ---- Summary ----------------------------------------------------------------
_label=SH-03; [ "$TYPE" = sh05 ] && _label=SH-05
{
    printf 'SH-04 Scan diff | %s | %s\n' "$_label" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'Earlier: %s\nLater:   %s\n\n' "$(basename "$OLD")" "$(basename "$NEW")"
    awk -F"$US" '
        { k = $1; a[k] += ($2 == "added"); r[k] += ($2 == "removed"); c[k] += ($2 == "changed"); if (!(k in seen)) { seen[k] = 1; order[++n] = k } }
        END {
            printf "%-13s %6s %8s %8s\n", "section", "added", "removed", "changed"
            for (i = 1; i <= n; i++) printf "%-13s %6d %8d %8d\n", order[i], a[order[i]], r[order[i]], c[order[i]]
            if (n == 0) print "No differences."
        }' "$W/all"
    [ -s "$W/skipped" ] && awk -F'|' '{ printf "%-13s %s\n", $1, $2 }' "$W/skipped"
    printf '\n'
    _tot=$(grep -c . "$W/all")
    if [ "$_tot" -gt 0 ]; then
        # Additions first: that is where new access hides.
        { awk -F"$US" '$2 == "added"' "$W/all"; awk -F"$US" '$2 == "changed"' "$W/all"; awk -F"$US" '$2 == "removed"' "$W/all"; } | head -n "$MAXLINES" | awk -F"$US" '
            { line = sprintf("  %-8s %-11s %s", toupper($2), $1, $3)
              if ($2 == "changed") line = line "  [" $4 " -> " $5 "]"
              if (length(line) > 200) line = substr(line, 1, 197) "..."
              print line }'
        [ "$_tot" -gt "$MAXLINES" ] && printf '  ... %d more in changes.txt\n' "$((_tot - MAXLINES))"
        printf '\n'
    fi
    # Read by cc_flag_report in the library.
    # shellcheck disable=SC2034
    CC_FLAGS_SHOW="$CC_RUN_DIR/flags.txt"
    cc_flag_report "$MAXFLAGS"
    printf '\nAll results: %s\n' "$CC_RUN_DIR"
} >"$CC_RUN_DIR/summary.txt"
# Readable tables: changes.txt (added, changed, removed) and flags.txt (HIGH first).
_ch=$(cfile "$CC_RUN_DIR" changes.csv)
if [ -f "$_ch" ]; then
    { head -n 1 "$_ch"; for _k in added changed removed; do awk -v k="$_k" -F'","' '$2 == k' "$_ch"; done; } >"$W/changes_sorted.csv"
    cc_csv_pretty "$W/changes_sorted.csv" "$CC_RUN_DIR/changes.txt" 80
fi
_fl=$(cfile "$CC_RUN_DIR" flags.csv)
if [ -f "$_fl" ]; then
    { head -n 1 "$_fl"; for _sv in HIGH MED LOW; do grep "^\"$_sv\"" "$_fl"; done; } >"$W/flags_sorted.csv"
    cc_csv_pretty "$W/flags_sorted.csv" "$CC_RUN_DIR/flags.txt" 200
else
    printf 'No flags.\n' >"$CC_RUN_DIR/flags.txt"
fi
cat "$CC_RUN_DIR/summary.txt"
rm -rf "$W"
cc_finish
