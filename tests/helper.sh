#!/bin/sh
# =============================================================================
# tests/helper.sh - the tiny test framework used by every tests/*.test.sh file.
#
# No dependencies and plain POSIX sh, so the same tests run under every shell
# the kit supports.  tests/run-tests.sh (AU-19) runs each test file once per
# available shell.
#
# In a test file:
#     . "$(dirname "$0")/helper.sh"
#     t_start "what this group checks"
#     t_eq    "$actual" "expected"      "label"
#     t_ok    "label"  command args...     (passes when the command returns 0)
#     t_fail  "label"  command args...     (passes when it returns non-zero)
#     t_has   "$text" "needle"          "label"
#     t_file  /path                     "label"
#     t_done                                (prints totals, exits 1 on failure)
#
# T_TMP is a fresh private folder removed at the end.  T_ROOT is the repo root.
# =============================================================================

# T_ROOT and T_TMP are used by the test files that source this helper.
# shellcheck disable=SC2034
T_PASS=0
T_FAILED=0
T_ROOT=$(cd "$(dirname "$0")/.." && pwd)
# Scripts never stop to ask a question during the tests, even when the tests
# are run from a terminal (a test that wants a terminal unsets this).
CCDC_NO_TTY=1; export CCDC_NO_TTY
T_TMP="${TMPDIR:-/tmp}/cctest.$$"
(umask 077; mkdir -p "$T_TMP") || { echo "cannot create $T_TMP" >&2; exit 1; }
trap 'rm -rf "$T_TMP"' EXIT

t_start() { printf '  -- %s\n' "$1"; }
_t_pass() { T_PASS=$((T_PASS + 1)); }
_t_fail() { T_FAILED=$((T_FAILED + 1)); printf '     FAIL: %s\n' "$1"; [ -n "${2:-}" ] && printf '           %s\n' "$2"; return 0; }

t_eq() {
    if [ "$1" = "$2" ]; then _t_pass; else _t_fail "$3" "got [$1], wanted [$2]"; fi
}
t_ok() {
    _t_label=$1; shift
    if "$@" >/dev/null 2>&1; then _t_pass; else _t_fail "$_t_label" "command returned non-zero: $*"; fi
}
t_fail() {
    _t_label=$1; shift
    if "$@" >/dev/null 2>&1; then _t_fail "$_t_label" "command returned zero but should have failed: $*"; else _t_pass; fi
}
t_has() {
    case "$1" in *"$2"*) _t_pass ;; *) _t_fail "$3" "text does not contain [$2]" ;; esac
}
t_hasnt() {
    case "$1" in *"$2"*) _t_fail "$3" "text contains [$2] but must not" ;; *) _t_pass ;; esac
}
t_file() {
    if [ -e "$1" ]; then _t_pass; else _t_fail "$2" "missing: $1"; fi
}
t_done() {
    printf '  %s passed, %s failed\n' "$T_PASS" "$T_FAILED"
    [ "$T_FAILED" -eq 0 ]
}
