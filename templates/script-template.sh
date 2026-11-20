#!/bin/sh
# =============================================================================
# ID:       XX-00                      <- the ID from docs/catalog.csv
# NAME:     Script template            <- the catalog name
# ROLE:     <official role>  (wave N)
# KIND:     readonly | changes         <- 'changes' if it can modify the system
#
# PURPOSE
#   One or two sentences: what problem this solves during the competition.
#
# USAGE
#   sh XX-00-name.sh [common options] [--example VALUE]
#   Run with --help for the full option list.
#
# INPUTS
#   --example VALUE   what this option means and what happens without it
#   Files read:       e.g. the protected list, /etc/passwd
#
# OUTPUTS  (all under the --out folder, never next to the script)
#   <ID>_<host>_<time>.log            everything printed, plus command output
#   <ID>_<host>_<time>_<name>.txt     describe each table and its columns
#                                     (built with cc_csv_new / cc_csv_row; the
#                                     library turns it into this .txt at the end)
#   undo-<host>.log                   one line per change, newest last
#
# WHAT IT CHANGES
#   List every kind of change, or "nothing - read only".
#
# DEPENDS ON
#   Tools: list each external command and its fallback (ss -> netstat -> lsof)
#   Other scripts whose output this one reads, if any.
#
# TESTED ON
#   List the OS versions it has really been run on.  Leave "not yet tested"
#   until it has.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   Anything an operator must know before trusting the output.
#
# DEBUGGING
#   --debug shows each decision.  sh -x shows each command.  The log file has
#   the full output of every command run through cc_run.
# =============================================================================

# >>> BT-LIB
# Development copy: find lib/lib.sh by walking up from this file.  The build
# step (tools/build.sh, LB-03) replaces this whole block with the library
# itself, so the built script is a single standalone file.
_cc_d=$(cd "$(dirname "$0")" && pwd)
while [ "$_cc_d" != "/" ] && [ ! -f "$_cc_d/lib/lib.sh" ]; do _cc_d=$(dirname "$_cc_d"); done
[ -f "$_cc_d/lib/lib.sh" ] || { echo "cannot find lib/lib.sh above $0" >&2; exit 3; }
. "$_cc_d/lib/lib.sh"
# <<< BT-LIB

usage() {
    cat <<'USAGE'
XX-00 Script template
  sh script-template.sh [options]

Options for this script:
  --example VALUE    an example option
  --help             show this text

USAGE
    cc_usage_common
}

# ---- 1. Parse options: common flags first, then this script's own ----------
EXAMPLE="default"
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --example) [ $# -ge 2 ] || cc_die 2 "--example needs a value"; EXAMPLE=$2; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) cc_die 2 "unknown option: $1 (try --help)" ;;
    esac
done

# ---- 2. Start: open the log, find the protected list, check the kit --------
cc_init "XX-00" "Script template" readonly
cc_detect_os
# cc_require_root          # uncomment if the script needs root

# ---- 3. The work ------------------------------------------------------------
# Inventory scripts write CSV rows and findings.  Scripts that change things
# call cc_guard before touching an item, cc_backup_file before editing a file,
# and make every change through cc_run so dry-run and logging are automatic.
CSV=$(cc_csv_new example "item,value") || cc_die 1 "cannot create the CSV file"
cc_csv_row "$CSV" "os family" "$CC_OS_FAMILY"
cc_csv_row "$CSV" "example option" "$EXAMPLE"
cc_info "wrote $CSV"

# ---- 4. Finish: print the summary and exit with the right code -------------
cc_finish
