#!/bin/sh
# =============================================================================
# tools/update-docs.sh - regenerate the per-role README files and docs/STATUS.md
# from docs/catalog.csv.
#
# WHY   docs/catalog.csv is the single list of every script: its ID, role,
#       wave, level, build status and file path.  The role READMEs and the
#       status page are views of that list, so they are generated, never
#       edited by hand.  Change the catalog, run this, commit both.
# USAGE sh tools/update-docs.sh
# INPUT docs/catalog.csv  (every field in double quotes; columns:
#       id,name,role,role_dir,wave,level,status,path,what_it_does,you_give_it)
# OUTPUT roles/<role_dir>/README.md (one per role) and docs/STATUS.md
# STATUS VALUES  planned  -> not written yet
#                built    -> written and passing the local tests
#                tested   -> also run on the real target systems
# NOTE  Repo maintenance tool; it is not one of the competition scripts and
#       does not use lib.sh.
# =============================================================================
ROOT=$(cd "$(dirname "$0")/.." && pwd)
CAT="$ROOT/docs/catalog.csv"
[ -r "$CAT" ] || { echo "cannot read $CAT" >&2; exit 1; }

# One awk pass per output keeps this readable.  Fields are split on the
# three-character sequence "," after the outer quotes are removed.
split_prog='
function fields(line, f,   n) {    # this is awk, not shell: posix-ok
    sub(/\r$/, "", line); sub(/^"/, "", line); sub(/"$/, "", line)
    n = split(line, f, "\",\"")
    for (i = 1; i <= n; i++) gsub(/""/, "\"", f[i])
    return n
}'

for dir in captain inject-lead network linux windows-ad applications detection-ir automation; do
    mkdir -p "$ROOT/roles/$dir"
    awk -v want="$dir" "$split_prog"'
    BEGIN {
        tag["captain"] = "priorities + communication"; tag["inject-lead"] = "deadlines + submissions"
        tag["network"] = "routes + firewall";          tag["linux"] = "hosts + services"
        tag["windows-ad"] = "identity + policy";       tag["applications"] = "web + databases"
        tag["detection-ir"] = "evidence + containment"; tag["automation"] = "safe changes + recovery"
    }
    NR == 1 { next }
    {
        fields($0, f)
        if (f[4] != want) next
        if (!n) role = f[3]
        n++; built += (f[7] != "planned")
        file = (f[8] == "") ? "" : "[`" f[8] "`](../../" f[8] ")"
        row[n] = "| " f[1] " | " f[2] " | " f[5] " | " f[6] " | " f[7] " | " file " |"
    }
    END {
        print "# " role " \342\200\224 " tag[want]
        print ""
        print "Scripts owned by this role. " built " of " n " are built."
        print ""
        print "This file is generated from `docs/catalog.csv` by `tools/update-docs.sh`. Do not edit it by hand."
        print ""
        print "| ID | Script | Wave | Level | Status | File |"
        print "| --- | --- | --- | --- | --- | --- |"
        for (i = 1; i <= n; i++) print row[i]
        print ""
        print "Script files in this folder are named `<ID>-<short-name>.sh` or `.ps1`. A script that moved here from another family keeps its original ID."
    }' "$CAT" >"$ROOT/roles/$dir/README.md"
done

awk "$split_prog"'
NR == 1 { next }
{
    fields($0, f)
    total++; w = f[5]; st = f[7]
    wave[w]++; if (st != "planned") wbuilt[w]++
    if (st != "planned") { nb++; b[nb] = "| " f[1] " | " f[2] " | " f[3] " | " st " | `" f[8] "` |" }
    if (w > maxw) maxw = w
}
END {
    goal[0] = "Foundation"; goal[1] = "Know what we have and what is scored"
    goal[2] = "Evict and lock, all at once"; goal[3] = "Close what should not be open"
    goal[4] = "Hunt, recover and report"; goal[5] = "Nice to have, and everything if-present"
    print "# Build status"
    print ""
    print (nb + 0) " of " total " scripts are built."
    print ""
    print "This file is generated from `docs/catalog.csv` by `tools/update-docs.sh`. Do not edit it by hand."
    print ""
    print "| Wave | Goal | Built | Total |"
    print "| --- | --- | --- | --- |"
    for (i = 0; i <= maxw; i++) print "| " i " | " goal[i] " | " (wbuilt[i] + 0) " | " (wave[i] + 0) " |"
    print ""
    print "## Built so far"
    print ""
    print "| ID | Script | Role | Status | File |"
    print "| --- | --- | --- | --- | --- |"
    for (i = 1; i <= nb; i++) print b[i]
    print ""
    print "`built` means written and passing the local tests. `tested` means it has also been run on the real target systems."
}' "$CAT" >"$ROOT/docs/STATUS.md"
echo "updated roles/*/README.md and docs/STATUS.md"
