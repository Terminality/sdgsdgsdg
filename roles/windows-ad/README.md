# Windows / AD — identity + policy

Scripts owned by this role. 7 of 9 are built.

This file is generated from `docs/catalog.csv` by `tools/update-docs.sh`. Do not edit it by hand.

| ID | Script | Tier | Risk | Status | File |
| --- | --- | --- | --- | --- | --- |
| SH-06 | Windows enum | Enum (look only) | none | built | [`roles/windows-ad/SH-06-windows-enum.ps1`](../../roles/windows-ad/SH-06-windows-enum.ps1) |
| WN-04 | AD enum | Enum (look only) | none | built | [`roles/windows-ad/WN-04-ad-enum.ps1`](../../roles/windows-ad/WN-04-ad-enum.ps1) |
| WN-35 | Windows backup | Backup and prep | none | built | [`roles/windows-ad/WN-35-backup.ps1`](../../roles/windows-ad/WN-35-backup.ps1) |
| WN-43 | Windows safe fixes | Hardening: easy | safe | built | [`roles/windows-ad/WN-43-safe-fixes.ps1`](../../roles/windows-ad/WN-43-safe-fixes.ps1) |
| WN-25 | Windows firewall | Hardening: hard | access | built | [`roles/windows-ad/WN-25-firewall.ps1`](../../roles/windows-ad/WN-25-firewall.ps1) |
| WN-27 | Windows remote access lockdown | Hardening: hard | access | planned |  |
| WN-23 | Account lockdown (Windows / AD) | Hardening: hard | access | planned |  |
| WN-20 | Windows password rotation | Management | access | built | [`roles/windows-ad/WN-20-password-rotation.ps1`](../../roles/windows-ad/WN-20-password-rotation.ps1) |
| WN-44 | Windows alerts | Alerts | none | built | [`roles/windows-ad/WN-44-windows-alerts.ps1`](../../roles/windows-ad/WN-44-windows-alerts.ps1) |

Script files in this folder are named `<ID>-<short-name>.sh` or `.ps1`. What the tiers and risk levels mean, and the rules for each: `docs/PLAN.md`.
