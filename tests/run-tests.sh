#!/bin/sh
# =============================================================================
# tests/run-tests.sh - run every check the repo has, on this machine.
#
# This is the local half of AU-19 (the script test harness).  The remote half,
# which runs each script on a test VM of every target operating system, is not
# built yet.
#
# WHAT IT RUNS, IN ORDER
#   1. tests/lint-posix.sh      bash-only / GNU-only constructs in .sh files
#   2. tests/lint-ps2.sh        post-2.0 features in .ps1 files
#   3. syntax check             'sh -n' on every .sh file, once per shell found
#   4. shellcheck               if it is installed
#   5. tests/*.test.sh          once per shell found
#   6. tests/*.Tests.ps1        with pwsh or powershell, if either is installed
#
# USAGE
#   sh tests/run-tests.sh              run everything
#   sh tests/run-tests.sh -v           also show each test group as it runs
#   PWSH=/path/to/pwsh sh tests/run-tests.sh     name the PowerShell to use
#
# EXIT CODE  0 = everything passed, 1 = something failed (listed at the end)
#
# READING A FAILURE
#   Each failing step prints the shell it ran under.  Re-run just that one:
#       TEST_SHELL=dash dash tests/lib.test.sh
#   A test that passes in bash and fails in dash or ksh is a portability bug
#   in the script, not in the test.
# =============================================================================
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1
VERBOSE=0
[ "${1:-}" = "-v" ] && VERBOSE=1
FAILED=""
STEPS=0

# step NAME COMMAND...  -> run one step, remember it if it fails.
step() {
    _name=$1; shift
    STEPS=$((STEPS + 1))
    _log="${TMPDIR:-/tmp}/ccrun.$$.log"
    if "$@" >"$_log" 2>&1; then
        printf 'ok    %s\n' "$_name"
        [ "$VERBOSE" = 1 ] && sed 's/^/        /' "$_log"
    else
        printf 'FAIL  %s\n' "$_name"
        sed 's/^/        /' "$_log"
        FAILED="$FAILED
  $_name"
    fi
    rm -f "$_log"
}

# Which shells can we test with?  "busybox sh" is two words on purpose.
SHELLS=""
for s in sh dash bash ksh mksh yash; do
    command -v "$s" >/dev/null 2>&1 && SHELLS="$SHELLS $s"
done
command -v busybox >/dev/null 2>&1 && busybox sh -c 'exit 0' 2>/dev/null && HAVE_BB=1 || HAVE_BB=0
printf 'shells found:%s%s\n\n' "$SHELLS" "$([ "$HAVE_BB" = 1 ] && printf ' busybox-sh')"

step "lint: POSIX sh only" sh tests/lint-posix.sh
step "lint: PowerShell 2.0 only" sh tests/lint-ps2.sh

FILES=$(find . -name '*.sh' -not -path './dist/*' -not -path './.git/*' | sort)
for s in $SHELLS; do
    for f in $FILES; do
        "$s" -n "$f" 2>/dev/null || step "syntax: $s -n $f" "$s" -n "$f"
    done
    printf 'ok    syntax: every .sh file parses under %s\n' "$s"
done

if command -v shellcheck >/dev/null 2>&1; then
    # shellcheck disable=SC2086
    step "shellcheck" shellcheck -s sh -S warning $FILES
else
    printf 'skip  shellcheck (not installed)\n'
fi

for t in tests/*.test.sh; do
    [ -f "$t" ] || continue
    for s in $SHELLS; do
        step "$t under $s" env TEST_SHELL="$s" "$s" "$t"
    done
    [ "$HAVE_BB" = 1 ] && step "$t under busybox sh" env TEST_SHELL="busybox sh" busybox sh "$t"
done

PS=${PWSH:-}
[ -n "$PS" ] || PS=$(command -v pwsh 2>/dev/null || command -v powershell 2>/dev/null || true)
if [ -n "$PS" ]; then
    for t in tests/*.Tests.ps1; do
        [ -f "$t" ] || continue
        step "$t under $PS" "$PS" -NoProfile -NonInteractive -File "$t"
    done
else
    printf 'skip  PowerShell tests (no pwsh or powershell found; set PWSH=/path/to/pwsh)\n'
fi

printf '\n'
if [ -n "$FAILED" ]; then
    printf 'FAILED steps:%s\n' "$FAILED"
    exit 1
fi
printf 'all %s steps passed\n' "$STEPS"
exit 0
