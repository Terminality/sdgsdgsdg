#!/bin/sh
# Tests for roles/linux/LX-31-backup.sh.
# Backs up the usual paths plus a planted folder, then checks the archive can
# be read, a file restores byte-for-byte into a scratch folder, the hash list
# catches a later change, the size limit refuses, and --copy-to works (scp to
# a local folder, which scp supports without a network).
. "$(dirname "$0")/helper.sh"
SH=${TEST_SHELL:-sh}
C="$T_ROOT/roles/linux/LX-31-backup.sh"
export CCDC_SKIP_VERIFY=1
# shellcheck disable=SC2086
run() { $SH "$C" "$@"; }
O="$T_TMP/out"; mkdir -p "$O"
D="$T_TMP/app"; mkdir -p "$D/conf"
printf 'listen 8080\n' >"$D/conf/app.conf"
printf 'secret=keep\n' >"$D/conf/.hidden"

t_start "options"
run --add "$T_TMP/no/such" >/dev/null 2>&1; t_eq "$?" 2 "missing --add path exits 2"
run --max-mb abc >/dev/null 2>&1; t_eq "$?" 2 "non-number --max-mb exits 2"

t_start "backup with an extra folder"
out=$(run --out "$O" --fast --no-homes --add "$D" 2>&1); rc=$?
t_eq "$rc" 0 "exit 0"
t_has "$out" "READ-ONLY" "banner says read-only"
d=$(printf '%s\n' "$out" | sed -n 's/^All results: //p')
t_file "$d/backup.tar.gz" "archive written"
t_file "$d/backup.tar.gz.sha256" "archive hash written"
t_file "$d/RESTORE.txt" "restore notes written"
c=$(cat "$d/contents.txt")
t_has "$c" "etc/passwd" "/etc is in the archive"
t_has "$c" "${D#/}/conf/app.conf" "the --add folder is in the archive"
t_has "$c" "${D#/}/conf/.hidden" "hidden files are included"
t_has "$(cat "$d/csv/included.csv")" "\"$D\",\"added\"" "included.csv lists the extra folder"
t_has "$(cat "$d/included.txt")" "PATH" "included.txt is a readable table"
t_eq "$d" "$O/backup-1" "the first run is backup-1"
t_file "$d/output.txt" "output.txt written"
t_has "$out" "==========[ 1/5  what will be backed up ]==========" "sections printed as it goes"
t_has "$out" "[+] $D  (added" "each path shown with its kind and size"
t_hasnt "$out" "$(printf '\033')" "no colour codes when piped"
t_has "$(cat "$d/files.sha256")" "$D/conf/app.conf" "files.sha256 lists the extra file"
t_ok "archive hash matches" sh -c "cd '$d' && sha256sum -c backup.tar.gz.sha256 >/dev/null 2>&1"
ls "$d/raw" >"$T_TMP/raw.txt" 2>/dev/null
t_has "$(cat "$T_TMP/raw.txt")" "kernel_settings.txt" "state snapshots saved"

t_start "leave out a path (--skip)"
out=$(run --out "$O" --fast --no-homes --no-webroots --add "$D" --skip "$D/conf/.hidden" 2>&1)
d2=$(printf '%s\n' "$out" | sed -n 's/^All results: //p')
t_eq "$d2" "$O/backup-2" "the next run is backup-2"
t_has "$(cat "$d2/contents.txt")" "${D#/}/conf/app.conf" "the rest of the folder is still in"
t_hasnt "$(cat "$d2/contents.txt")" ".hidden" "the left-out file is not in the archive"
t_hasnt "$(cat "$d2/files.sha256")" ".hidden" "nor in the hash list"
run --box mars >/dev/null 2>&1; t_eq "$?" 2 "bad --box exits 2"

t_start "restore and change detection"
mkdir -p "$T_TMP/restore"
tar -xzf "$d/backup.tar.gz" -C "$T_TMP/restore" "${D#/}/conf/app.conf" 2>/dev/null
t_ok "restored file matches the original" cmp "$D/conf/app.conf" "$T_TMP/restore${D}/conf/app.conf"
# Compare hashes directly: busybox's sha256sum prints -c results differently.
was=$(awk -v f="$D/conf/app.conf" '$2 == f { print $1 }' "$d/files.sha256")
t_eq "$was" "$(sha256sum "$D/conf/app.conf" | awk '{ print $1 }')" "hash list matches the file as backed up"
printf 'listen 9999\n' >"$D/conf/app.conf"
t_ok "hash list catches a changed file" test "$was" != "$(sha256sum "$D/conf/app.conf" | awk '{ print $1 }')"

t_start "limits and copy"
run --out "$O" --fast --no-homes --max-mb 0 >/dev/null 2>&1; t_eq "$?" 3 "over --max-mb with no one to ask: refuses with exit 3"
if command -v scp >/dev/null 2>&1; then
    mkdir -p "$T_TMP/offbox"
    out=$(run --out "$O" --fast --no-homes --no-webroots --copy-to "$T_TMP/offbox/" 2>&1); rc=$?
    t_eq "$rc" 0 "--copy-to exits 0"
    t_file "$T_TMP/offbox/backup.tar.gz" "the archive was copied"
    t_has "$out" "Copied off the box" "summary says it was copied"
    run --out "$O" --fast --no-homes --no-webroots --copy-to "$T_TMP/no/such/dir/" >/dev/null 2>&1
    t_eq "$?" 5 "a failed copy exits 5"
fi
t_start "questions answered at a terminal (needs 'script')"
if command -v script >/dev/null 2>&1 && script -qc true /dev/null >/dev/null 2>&1; then
    # Answers: homes? n; hash system programs? n; other paths: the app
    # folder; leave out: its hidden file; copy to: (Enter, none).
    printf 'n\nn\n%s\n%s\n\n' "$D" "$D/conf/.hidden" >"$T_TMP/answers"
    CCDC_NO_TTY=0 script -qc "$SH $C --out $T_TMP/o9 --box other --no-webroots --no-color" /dev/null <"$T_TMP/answers" >"$T_TMP/tty.out" 2>&1
    d9="$T_TMP/o9/backup-1"
    t_has "$(cat "$d9/contents.txt")" "${D#/}/conf/app.conf" "a typed path was backed up"
    t_hasnt "$(cat "$d9/contents.txt")" ".hidden" "a typed leave-out path was left out"
    t_fail "answered n to hashing system programs" test -s "$d9/system.sha256"
    t_has "$(cat "$d9/output.txt")" "[?] Other files or folders to back up? (comma list) $D" "the typed answer is in output.txt"
else
    t_start "(skipped: no 'script' command)"
fi
t_done
