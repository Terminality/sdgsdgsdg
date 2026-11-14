# Linux — hosts + services

Scripts owned by this role. 8 of 12 are built.

This file is generated from `docs/catalog.csv` by `tools/update-docs.sh`. Do not edit it by hand.

| ID | Script | Tier | Risk | Status | File |
| --- | --- | --- | --- | --- | --- |
| SH-05 | Linux enum | Enum (look only) | none | built | [`roles/linux/SH-05-linux-enum.sh`](../../roles/linux/SH-05-linux-enum.sh) |
| LX-23 | SSH enum | Enum (look only) | none | planned |  |
| LX-31 | Linux backup | Backup and prep | none | built | [`roles/linux/LX-31-backup.sh`](../../roles/linux/LX-31-backup.sh) |
| LX-39 | Linux safe fixes | Hardening: easy | safe | built | [`roles/linux/LX-39-safe-fixes.sh`](../../roles/linux/LX-39-safe-fixes.sh) |
| LX-22 | SSH fixes | Hardening: medium | service | built | [`roles/linux/LX-22-ssh-hardening.sh`](../../roles/linux/LX-22-ssh-hardening.sh) |
| LX-27 | Admin and sudo cleanup | Hardening: medium | access | planned |  |
| LX-25 | Linux firewall | Hardening: hard | access | built | [`roles/linux/LX-25-firewall.sh`](../../roles/linux/LX-25-firewall.sh) |
| LX-26 | Linux remote access lockdown | Hardening: hard | access | planned |  |
| LX-21 | Account lockdown (Linux) | Hardening: hard | access | planned |  |
| LX-20 | Linux password rotation | Management | access | built | [`roles/linux/LX-20-password-rotation.sh`](../../roles/linux/LX-20-password-rotation.sh) |
| LX-40 | Linux alerts | Alerts | none | built | [`roles/linux/LX-40-change-watch.sh`](../../roles/linux/LX-40-change-watch.sh) |
| SV-26 | Brute-force and spam banning | Alerts | service | built | [`roles/linux/SV-26-banning.sh`](../../roles/linux/SV-26-banning.sh) |

Script files in this folder are named `<ID>-<short-name>.sh` or `.ps1`. What the tiers and risk levels mean, and the rules for each: `docs/PLAN.md`.
