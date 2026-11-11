#!/bin/sh
# The templates are real, runnable scripts.  This test keeps them that way, so
# a new script copied from one starts from something that works.
. "$(dirname "$0")/helper.sh"
SH=${TEST_SHELL:-sh}
export CCDC_SKIP_VERIFY=1
t_start "shell template runs as a dry run and writes its files"
# shellcheck disable=SC2086
r=$($SH "$T_ROOT/templates/script-template.sh" --out "$T_TMP/out" --example hello 2>&1); t_eq "$?" 0 "exits 0"
t_has "$r" "READ-ONLY" "the template starts as a read-only script"
t_ok "log written" sh -c "ls '$T_TMP/out'/XX-00_*.log"
t_ok "csv has the option value" sh -c "grep -q '\"example option\",\"hello\"' '$T_TMP/out'/XX-00_*_example.csv"
# shellcheck disable=SC2086
$SH "$T_ROOT/templates/script-template.sh" --nope >/dev/null 2>&1; t_eq "$?" 2 "unknown option exits 2"
# shellcheck disable=SC2086
r=$($SH "$T_ROOT/templates/script-template.sh" --help 2>&1); t_has "$r" "--apply" "--help lists the common options"
t_done
