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
t_has "$(cat "$d/included.csv")" "\"$D\",\"added\"" "included.csv lists the extra folder"
t_has "$(cat "$d/files.sha256")" "$D/conf/app.conf" "files.sha256 lists the extra file"
t_ok "archive hash matches" sh -c "cd '$d' && sha256sum -c backup.tar.gz.sha256 >/dev/null 2>&1"
ls "$d/raw" >"$T_TMP/raw.txt" 2>/dev/null
t_has "$(cat "$T_TMP/raw.txt")" "kernel_settings.txt" "state snapshots saved"

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
run --out "$O" --fast --no-homes --max-mb 0 >/dev/null 2>&1; t_eq "$?" 3 "--max-mb 0 refuses with exit 3"
if command -v scp >/dev/null 2>&1; then
    mkdir -p "$T_TMP/offbox"
    out=$(run --out "$O" --fast --no-homes --no-webroots --copy-to "$T_TMP/offbox/" 2>&1); rc=$?
    t_eq "$rc" 0 "--copy-to exits 0"
    t_file "$T_TMP/offbox/backup.tar.gz" "the archive was copied"
    t_has "$out" "Copied off the box" "summary says it was copied"
    run --out "$O" --fast --no-homes --no-webroots --copy-to "$T_TMP/no/such/dir/" >/dev/null 2>&1
    t_eq "$?" 5 "a failed copy exits 5"
fi
t_done
