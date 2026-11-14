#!/bin/sh
# =============================================================================
# tools/update-docs.sh - regenerate the per-role README files and docs/STATUS.md
# from docs/catalog.csv.
#
# WHY   docs/catalog.csv is the single list of every script: its ID, role,
#       tier, risk, build status and file path.  The role READMEs and the
#       status page are views of that list, so they are generated, never
#       edited by hand.  Change the catalog, run this, commit both.
# USAGE sh tools/update-docs.sh
# INPUT docs/catalog.csv  (every field in double quotes; columns:
#       id,name,role,role_dir,tier,risk,status,path,what_it_does,you_give_it)
# OUTPUT roles/<role_dir>/README.md (one per role) and docs/STATUS.md
# STATUS VALUES  planned  -> not written yet
#                built    -> written and passing the local tests
#                tested   -> also run on the real target systems
# TIERS  enum prep easy medium hard manage alert evict kit (docs/PLAN.md)
# RISK   none     -> changes nothing
#        safe     -> cannot break a scored service or your access
#        service  -> could break a scored service: checks it, reverts
#        access   -> could lock you out: countdown that reverts, plus undo
# NOTE  Repo maintenance tool; it is not one of the competition scripts and
#       does not use lib.sh.
# =============================================================================
ROOT=$(cd "$(dirname "$0")/.." && pwd)
CAT="$ROOT/docs/catalog.csv"
[ -r "$CAT" ] || { echo "cannot read $CAT" >&2; exit 1; }

# One awk pass per output keeps this readable.  Fields are split on the
# three-character sequence "," after the outer quotes are removed.
split_prog='
function tiername(t) {    # awk, not shell: posix-ok
    if (t == "enum") return "Enum (look only)"; if (t == "prep") return "Backup and prep"
    if (t == "easy") return "Hardening: easy"; if (t == "medium") return "Hardening: medium"
    if (t == "hard") return "Hardening: hard"; if (t == "manage") return "Management"
    if (t == "alert") return "Alerts"; if (t == "evict") return "Eviction"; if (t == "kit") return "Kit"
    return t
}
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
        row[n] = "| " f[1] " | " f[2] " | " tiername(f[5]) " | " f[6] " | " f[7] " | " file " |"
    }
    END {
        if (!n) {
            print "# " want
            print ""
            print "No core scripts are planned for this role. If you want scripts for it, write them yourself and follow `AGENTS.md`."
            print ""
            print "This file is generated from `docs/catalog.csv` by `tools/update-docs.sh`. Do not edit it by hand."
            exit
        }
        print "# " role " \342\200\224 " tag[want]
        print ""
        print "Scripts owned by this role. " built " of " n " are built."
        print ""
        print "This file is generated from `docs/catalog.csv` by `tools/update-docs.sh`. Do not edit it by hand."
        print ""
        print "| ID | Script | Tier | Risk | Status | File |"
        print "| --- | --- | --- | --- | --- | --- |"
        for (i = 1; i <= n; i++) print row[i]
        print ""
        print "Script files in this folder are named `<ID>-<short-name>.sh` or `.ps1`. What the tiers and risk levels mean, and the rules for each: `docs/PLAN.md`."
    }' "$CAT" >"$ROOT/roles/$dir/README.md"
done

awk "$split_prog"'
NR == 1 { next }
{
    fields($0, f)
    total++; t = f[5]; st = f[7]
    if (!(t in seen)) { seen[t] = 1; nt++; order[nt] = t }
    tot[t]++; if (st != "planned") { built[t]++; nb++ }
    line[t] = line[t] "| " f[1] " | " f[2] " | " f[6] " | " st " | " ((f[8] == "") ? "" : "`" f[8] "`") " |\n"
}
END {
    print "# Build status"
    print ""
    print (nb + 0) " of " total " scripts are built. The plan, tiers and rules: `docs/PLAN.md`."
    print ""
    print "This file is generated from `docs/catalog.csv` by `tools/update-docs.sh`. Do not edit it by hand."
    print ""
    print "| Tier | Built | Total |"
    print "| --- | --- | --- |"
    for (i = 1; i <= nt; i++) print "| " tiername(order[i]) " | " (built[order[i]] + 0) " | " tot[order[i]] " |"
    for (i = 1; i <= nt; i++) {
        print ""
        print "## " tiername(order[i])
        print ""
        print "| ID | Script | Risk | Status | File |"
        print "| --- | --- | --- | --- | --- |"
        printf "%s", line[order[i]]
    }
    print ""
    print "`built` means written and passing the local tests. `tested` means it has also been run on the real target systems. A \"To do\" in the catalog description is a change still owed to a built script."
}' "$CAT" >"$ROOT/docs/STATUS.md"
echo "updated roles/*/README.md and docs/STATUS.md"
