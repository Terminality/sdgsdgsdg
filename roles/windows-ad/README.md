# Windows / AD — identity + policy

Scripts owned by this role. 8 of 11 are built.

This file is generated from `docs/catalog.csv` by `tools/update-docs.sh`. Do not edit it by hand.

| ID | Script | Tier | Risk | Status | File |
| --- | --- | --- | --- | --- | --- |
| SH-06 | Windows enum | Enum (look only) | none | built | [`roles/windows-ad/SH-06-windows-enum.ps1`](../../roles/windows-ad/SH-06-windows-enum.ps1) |
| WN-04 | AD enum | Enum (look only) | none | planned |  |
| WN-35 | Windows backup | Backup and prep | none | built | [`roles/windows-ad/WN-35-backup.ps1`](../../roles/windows-ad/WN-35-backup.ps1) |
| WN-43 | Windows safe fixes | Hardening: easy | safe | built | [`roles/windows-ad/WN-43-safe-fixes.ps1`](../../roles/windows-ad/WN-43-safe-fixes.ps1) |
| WN-25 | Windows firewall | Hardening: hard | access | built | [`roles/windows-ad/WN-25-firewall.ps1`](../../roles/windows-ad/WN-25-firewall.ps1) |
| WN-27 | Windows remote access lockdown | Hardening: hard | access | planned |  |
| WN-23 | Account lockdown (Windows / AD) | Hardening: hard | access | built | [`roles/windows-ad/WN-23-ad-lockdown.ps1`](../../roles/windows-ad/WN-23-ad-lockdown.ps1) |
| WN-20 | Windows password rotation | Management | access | built | [`roles/windows-ad/WN-20-password-rotation.ps1`](../../roles/windows-ad/WN-20-password-rotation.ps1) |
| WN-44 | Windows alerts | Alerts | none | planned |  |
| WN-42 | Windows persistence sweep | Hardening: medium | service | built | [`roles/windows-ad/WN-42-persistence-sweep.ps1`](../../roles/windows-ad/WN-42-persistence-sweep.ps1) |
| WN-16 | Windows web shell hunter | wave2 | medium | built | [`roles/windows-ad/WN-16-webshell-hunter.ps1`](../../roles/windows-ad/WN-16-webshell-hunter.ps1) |

Script files in this folder are named `<ID>-<short-name>.sh` or `.ps1`. What the tiers and risk levels mean, and the rules for each: `docs/PLAN.md`.
