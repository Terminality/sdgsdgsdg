# Network — routes + firewall

Scripts owned by this role. 9 of 9 are built.

This file is generated from `docs/catalog.csv` by `tools/update-docs.sh`. Do not edit it by hand.

| ID | Script | Tier | Risk | Status | File |
| --- | --- | --- | --- | --- | --- |
| SH-03 | Network scan | Enum (look only) | none | built | [`roles/network/SH-03-network-scan.sh`](../../roles/network/SH-03-network-scan.sh) |
| SH-04 | Scan diff | Enum (look only) | none | built | [`roles/network/SH-04-scan-diff.sh`](../../roles/network/SH-04-scan-diff.sh) |
| NW-07 | Network device config audit | Enum (look only) | none | built | [`roles/network/NW-07-config-audit.sh`](../../roles/network/NW-07-config-audit.sh) |
| NW-01 | Network config backup and diff | Backup and prep | none | built | [`roles/network/NW-01-config-backup.sh`](../../roles/network/NW-01-config-backup.sh) |
| NW-10 | Network device password rotation | Management | access | built | [`roles/network/NW-10-device-passwords.sh`](../../roles/network/NW-10-device-passwords.sh) |
| NW-12 | Device accounts and sessions | Management | access | built | [`roles/network/NW-12-device-sessions.sh`](../../roles/network/NW-12-device-sessions.sh) |
| NW-21 | Network device hardening | Hardening: hard | access | built | [`roles/network/NW-21-device-hardening.sh`](../../roles/network/NW-21-device-hardening.sh) |
| NW-20 | Firewall ruleset | Hardening: hard | service | built | [`roles/network/NW-20-firewall-ruleset.sh`](../../roles/network/NW-20-firewall-ruleset.sh) |
| NW-30 | Device change watch | Alerts | none | built | [`roles/network/NW-30-device-watch.sh`](../../roles/network/NW-30-device-watch.sh) |

Script files in this folder are named `<ID>-<short-name>.sh` or `.ps1`. What the tiers and risk levels mean, and the rules for each: `docs/PLAN.md`.
