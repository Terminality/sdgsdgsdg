#!/bin/sh
# =============================================================================
# tools/role-manuals.sh - build the per-role manuals:
#     docs/manual-linux.md, docs/manual-network.md, docs/manual-applications.md,
#     docs/manual-windows.md
#
# WHY   Each role gets one manual to read on the day: the playbook (first 15
#       minutes, what to run after, what to do when something happens) and a
#       deep dive for every script of that role.  The playbook is written by
#       hand in docs/playbooks/<role>.md; each deep dive is that script's
#       section of docs/MANUAL.md, copied in.  Nothing is written twice, so
#       the manuals cannot drift from docs/MANUAL.md: change those, run this.
# USAGE sh tools/role-manuals.sh            write the three manuals
#       sh tools/role-manuals.sh --check    exit 1 if one is out of date
# =============================================================================
set -u
cd "$(dirname "$0")/.." || exit 3
CHECK=0; [ "${1:-}" = --check ] && CHECK=1

# The scripts of each role, in the order the playbook runs them.
order() {
    case "$1" in
        linux)        echo "SH-05 LX-31 LX-20 LX-22 LX-25 LX-21 LX-26 LX-42 LX-45 LX-39 SV-26 LX-40 LX-41 LX-43 LX-44 LX-46" ;;
        network)      echo "SH-03 NW-01 NW-07 NW-12 NW-10 NW-21 NW-20 NW-30 SH-04" ;;
        applications) echo "SV-01 SV-14 SV-15 SV-50 SV-45 SV-46 SV-21 SV-20 SV-42 SV-30 SV-16 SV-32 SV-31 SV-40 SV-41 SV-44" ;;
        windows)      echo "SH-06 WN-35 WN-20 WN-25 WN-23 WN-43 WN-42 WN-16 WN-50" ;;
    esac
}

# section ID -> that script's section of docs/MANUAL.md, one heading level
#   down, its title as "### ID: name (dist/<role>/<file>)".
section() {
    awk -v id="$1" '
        /^## [0-9]+\. / { if (on) exit; if ($0 ~ "\\(" id "\\)$") { on = 1
            t = $0; sub(/^## [0-9]+\. /, "", t)
            path = t; sub(/^[^`]*`/, "", path); sub(/`.*/, "", path); sub(/^roles\//, "dist/", path)
            name = t; sub(/, `.*/, "", name)
            print "### " id ": " name " (`" path "`)"; next } }
        on && /^#/ { print "#" $0; next }
        on { print }
        END { if (!on) exit 1 }' docs/MANUAL.md
}

RC=0
for _r in linux network applications windows; do
    _out="docs/manual-$_r.md"; _tmp="$_out.new"
    {
        printf '<!-- Built by tools/role-manuals.sh from docs/playbooks/%s.md and docs/MANUAL.md. Edit those, then run it. -->\n\n' "$_r"
        cat "docs/playbooks/$_r.md"
        printf '\nScripts: '
        for _id in $(order "$_r"); do printf '[%s](#%s) ' "$_id" "$(section "$_id" | head -n 1 | sed 's/^### //' | tr 'A-Z' 'a-z' | sed 's/[^a-z0-9 -]//g; s/ /-/g')"; done
        printf '\n'
        for _id in $(order "$_r"); do
            printf '\n'
            section "$_id" || { echo "role-manuals: no section for $_id in docs/MANUAL.md" >&2; exit 1; }
        done
    } >"$_tmp" || { rm -f "$_tmp"; exit 1; }
    if [ "$CHECK" = 1 ]; then
        cmp -s "$_tmp" "$_out" || { echo "out of date: $_out (run: sh tools/role-manuals.sh)"; RC=1; }
        rm -f "$_tmp"
    else
        mv "$_tmp" "$_out"; echo "wrote $_out"
    fi
done
exit "$RC"
