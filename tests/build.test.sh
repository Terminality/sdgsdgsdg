#!/bin/sh
# Tests for tools/build.sh (LB-03) and the single-file scripts in dist/.
# Checks: dist/ matches the source; every built script runs from a folder
# with no lib/ next to it; the kit check passes on a clean copy and stops a
# changed one; line endings are right for each kind of script.
. "$(dirname "$0")/helper.sh"
SH=${TEST_SHELL:-sh}

t_start "dist/ is up to date with roles/ and lib/"
r=$(sh "$T_ROOT/tools/build.sh" --check 2>&1); rc=$?
t_eq "$rc" 0 "tools/build.sh --check passes (if not: run sh tools/build.sh)"
[ "$rc" -eq 0 ] || printf '%s\n' "$r" | head -n 10

if command -v git >/dev/null 2>&1 && git -C "$T_ROOT" rev-parse --git-dir >/dev/null 2>&1; then
    t_ok "dist/ is not ignored by git (people download from it)" sh -c "! git -C '$T_ROOT' check-ignore -q dist/MANIFEST.sha256"
fi

t_start "a fresh build into another folder"
r=$(sh "$T_ROOT/tools/build.sh" --out "$T_TMP/d" 2>&1); t_eq "$?" 0 "build exits 0"
t_file "$T_TMP/d/MANIFEST.sha256" "manifest written"
t_file "$T_TMP/d/linux/LX-39-safe-fixes.sh" "a Linux script built"
t_hasnt "$(cat "$T_TMP/d/linux/LX-39-safe-fixes.sh")" 'lib/lib.sh" ]' "the built script no longer looks for lib/lib.sh"
t_has "$(cat "$T_TMP/d/linux/LX-39-safe-fixes.sh")" "cc_timer_start()" "the library is inside the built script"
t_fail "no CR in a built shell script" grep -q "$(printf '\r')" "$T_TMP/d/linux/LX-39-safe-fixes.sh"
if ls "$T_TMP"/d/windows-ad/*.ps1 >/dev/null 2>&1; then
    t_ok "built PowerShell scripts use CRLF" grep -q "$(printf '\r')\$" "$T_TMP/d/windows-ad/WN-43-safe-fixes.ps1"
fi

t_start "every built shell script runs alone (no lib folder)"
mkdir -p "$T_TMP/alone"
for f in "$T_TMP"/d/*/*.sh; do
    cp "$f" "$T_TMP/alone/"
    # shellcheck disable=SC2086
    $SH "$T_TMP/alone/$(basename "$f")" --help >/dev/null 2>&1
    t_eq "$?" 0 "$(basename "$f") --help works on its own"
done
# shellcheck disable=SC2086
r=$(CCDC_SKIP_VERIFY=1 $SH "$T_TMP/alone/SH-05-linux-enum.sh" --out "$T_TMP/o" --only system 2>&1)
t_eq "$?" 0 "the built enum runs a section on its own"
t_has "$r" "==========[ 1/1  system ]==========" "and prints its output"

t_start "kit check: clean copy runs, changed copy is refused"
cp -R "$T_TMP/d" "$T_TMP/kit"
unset CCDC_SKIP_VERIFY
# shellcheck disable=SC2086
r=$($SH "$T_TMP/kit/linux/SH-05-linux-enum.sh" --out "$T_TMP/o2" --only system 2>&1)
t_eq "$?" 0 "a clean built script passes its own hash check"
printf '# changed\n' >>"$T_TMP/kit/linux/SH-05-linux-enum.sh"
# shellcheck disable=SC2086
r=$($SH "$T_TMP/kit/linux/SH-05-linux-enum.sh" --out "$T_TMP/o3" --only system 2>&1)
t_eq "$?" 3 "a changed script exits 3"
t_has "$r" "KIT CHECK FAILED" "and says why"

t_start "built PowerShell script runs alone (needs pwsh)"
PS=${PWSH:-}
[ -n "$PS" ] || PS=$(command -v pwsh 2>/dev/null || command -v powershell 2>/dev/null || true)
if [ -n "$PS" ] && [ -f "$T_TMP/d/windows-ad/WN-43-safe-fixes.ps1" ]; then
    cp "$T_TMP/d/windows-ad/WN-43-safe-fixes.ps1" "$T_TMP/alone/"
    r=$("$PS" -NoProfile -NonInteractive -File "$T_TMP/alone/WN-43-safe-fixes.ps1" -List 2>&1)
    t_has "$r" "wdigest" "WN-43 -List works with no lib folder"
else
    t_start "(skipped: no pwsh)"
fi
t_done
