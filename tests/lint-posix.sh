#!/bin/sh
# =============================================================================
# tests/lint-posix.sh - catch shell features that are not plain POSIX sh.
#
# WHY   Every .sh file in the kit must run on dash, busybox, ksh and the /bin/sh
#       of BSD and Solaris.  A script written and tested only in bash can pass
#       there and then fail on the one old box that matters.
# HOW   Searches every .sh file under the repo (except dist/) for constructs
#       known to be bash-only or GNU-only.  Comment lines are skipped, and so
#       are the lint-*.sh files themselves (they contain the patterns).
#       A line that is safe for a reason the pattern cannot see can be excused
#       by ending it with the comment:   # posix-ok
# USAGE sh tests/lint-posix.sh            exit 0 = clean, 1 = problems listed
# NOTE  This is a pattern search, not a parser.  It finds the common mistakes;
#       the per-shell test runs in run-tests.sh find the rest.
# =============================================================================
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1
bad=0
# check DESCRIPTION REGEX
check() {
    hits=$(find . -name '*.sh' -not -name 'lint-*.sh' -not -path './dist/*' -not -path './.git/*' -exec grep -nE -- "$2" {} + 2>/dev/null \
        | grep -vE '^[^:]+:[0-9]+:[[:space:]]*#' | grep -v 'posix-ok')
    if [ -n "$hits" ]; then
        bad=1
        printf 'NOT POSIX - %s\n%s\n\n' "$1" "$hits"
    fi
}
check "'local' is not in POSIX sh; use a _prefixed global"          '^[[:space:]]*local[[:space:]]'
check "'[[ ]]' is bash/ksh only; use [ ]"                           '(^|[[:space:];])\[\[[[:space:]]'
check "'function name' keyword; write name() { ... }"               '^[[:space:]]*function[[:space:]]'
check "'echo -n/-e' is not portable; use printf"                    'echo[[:space:]]+-[ne]'
check "'source' is bash; use '.'"                                   '(^|[[:space:];])source[[:space:]]'
check "'==' inside [ ]; use a single '='"                           '\[[[:space:]][^]]*[[:space:]]==[[:space:]]'
check "'&>' redirect; use >file 2>&1"                               '&>'
check "'<<<' here-string; use printf | or a here-document"          '<<<'
check "arrays are not in POSIX sh"                                  '(^|[[:space:]])[A-Za-z_][A-Za-z0-9_]*=\('
check "\$'...' quoting is not in POSIX sh"                          "\\\$'"
check "'declare/typeset' are not in POSIX sh"                       '^[[:space:]]*(declare|typeset)[[:space:]]'
check "brace ranges {1..5} are bash only"                           '\{[0-9]+\.\.[0-9]+\}'
check "\$RANDOM is not in POSIX sh; read /dev/urandom"              '\$\{?RANDOM'
check "'set -o pipefail' is not in POSIX sh"                        'pipefail'
check "'head -c' is missing on Solaris; use dd bs=1 count=N"        'head[[:space:]]+-c'
check "'grep -P' is GNU only"                                       'grep[[:space:]]+-[A-Za-z]*P'
check "'sed -i' differs between GNU and BSD; write to a temp file"  'sed[[:space:]]+-i'
check "'readlink -f' is GNU only; use cc_abspath"                   'readlink[[:space:]]+-f'
[ "$bad" -eq 0 ] && echo "lint-posix: clean"
exit "$bad"
