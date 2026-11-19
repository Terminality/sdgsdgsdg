# Linux — hosts + services

Scripts owned by this role. 14 of 14 are built.

This file is generated from `docs/catalog.csv` by `tools/update-docs.sh`. Do not edit it by hand.

| ID | Script | Tier | Risk | Status | File |
| --- | --- | --- | --- | --- | --- |
| SH-05 | Linux enum | Enum (look only) | none | built | [`roles/linux/SH-05-linux-enum.sh`](../../roles/linux/SH-05-linux-enum.sh) |
| LX-31 | Linux backup | Backup and prep | none | built | [`roles/linux/LX-31-backup.sh`](../../roles/linux/LX-31-backup.sh) |
| LX-39 | Linux safe fixes | Hardening: easy | safe | built | [`roles/linux/LX-39-safe-fixes.sh`](../../roles/linux/LX-39-safe-fixes.sh) |
| LX-22 | SSH hardening | Hardening: medium | service | built | [`roles/linux/LX-22-ssh-hardening.sh`](../../roles/linux/LX-22-ssh-hardening.sh) |
| LX-25 | Linux firewall | Hardening: hard | access | built | [`roles/linux/LX-25-firewall.sh`](../../roles/linux/LX-25-firewall.sh) |
| LX-26 | Remote access lockdown (everything but SSH) | wave1 | medium | built | [`roles/linux/LX-26-remote-access.sh`](../../roles/linux/LX-26-remote-access.sh) |
| LX-21 | Account lockdown (Linux) | wave1 | medium | built | [`roles/linux/LX-21-account-lockdown.sh`](../../roles/linux/LX-21-account-lockdown.sh) |
| LX-20 | Linux password rotation | Management | access | built | [`roles/linux/LX-20-password-rotation.sh`](../../roles/linux/LX-20-password-rotation.sh) |
| LX-40 | Linux alerts | Alerts | none | built | [`roles/linux/LX-40-change-watch.sh`](../../roles/linux/LX-40-change-watch.sh) |
| LX-41 | Linux session & command logging | Alerts | none | built | [`roles/linux/LX-41-session-log.sh`](../../roles/linux/LX-41-session-log.sh) |
| LX-42 | Linux persistence sweep | Hardening: medium | service | built | [`roles/linux/LX-42-persistence-sweep.sh`](../../roles/linux/LX-42-persistence-sweep.sh) |
| LX-43 | Log shipping to Splunk | wave2 | medium | built | [`roles/linux/LX-43-log-shipping.sh`](../../roles/linux/LX-43-log-shipping.sh) |
| LX-45 | Rootkit and malware scan | wave2 | medium | built | [`roles/linux/LX-45-rootkit-scan.sh`](../../roles/linux/LX-45-rootkit-scan.sh) |
| SV-26 | Brute-force and spam banning | Alerts | service | built | [`roles/linux/SV-26-banning.sh`](../../roles/linux/SV-26-banning.sh) |

Script files in this folder are named `<ID>-<short-name>.sh` or `.ps1`. What the tiers and risk levels mean, and the rules for each: `docs/PLAN.md`.
