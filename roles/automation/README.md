# Automation — safe changes + recovery

Scripts owned by this role. 2 of 10 are built.

This file is generated from `docs/catalog.csv` by `tools/update-docs.sh`. Do not edit it by hand.

| ID | Script | Tier | Risk | Status | File |
| --- | --- | --- | --- | --- | --- |
| SH-09 | Protected list builder | Backup and prep | none | planned |  |
| SH-11 | Backup admin account | Backup and prep | access | planned |  |
| AU-12 | Restore and undo runner | Backup and prep | service | planned |  |
| AU-20 | Account manager | Management | access | planned |  |
| SH-08 | Service checker | Management | none | planned |  |
| LB-01 | Shell library (lib.sh) | Kit | none | built | [`lib/lib.sh`](../../lib/lib.sh) |
| LB-02 | PowerShell library (lib.ps1) | Kit | none | built | [`lib/lib.ps1`](../../lib/lib.ps1) |
| LB-03 | Build step | Kit | none | planned |  |
| AU-02 | Linux fan-out | Kit | service | planned |  |
| AU-30 | Local runner | Kit | none | planned |  |

Script files in this folder are named `<ID>-<short-name>.sh` or `.ps1`. What the tiers and risk levels mean, and the rules for each: `docs/PLAN.md`.
