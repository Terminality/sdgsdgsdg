# Applications — web + databases

Scripts owned by this role. 16 of 16 are built.

This file is generated from `docs/catalog.csv` by `tools/update-docs.sh`. Do not edit it by hand.

| ID | Script | Tier | Risk | Status | File |
| --- | --- | --- | --- | --- | --- |
| SV-01 | Web and database enum (Linux) | Enum (look only) | none | built | [`roles/applications/SV-01-web-db-enum.sh`](../../roles/applications/SV-01-web-db-enum.sh) |
| SV-14 | Database backup | Backup and prep | none | built | [`roles/applications/SV-14-db-backup.sh`](../../roles/applications/SV-14-db-backup.sh) |
| SV-15 | Site backup and restore | Backup and prep | medium | built | [`roles/applications/SV-15-site-backup.sh`](../../roles/applications/SV-15-site-backup.sh) |
| SV-16 | Web shell hunter | wave2 | medium | built | [`roles/applications/SV-16-webshell-hunter.sh`](../../roles/applications/SV-16-webshell-hunter.sh) |
| SV-20 | Database hardening | wave2 | medium | built | [`roles/applications/SV-20-db-hardening.sh`](../../roles/applications/SV-20-db-hardening.sh) |
| SV-21 | PHP and web app hardening | wave2 | medium | built | [`roles/applications/SV-21-web-hardening.sh`](../../roles/applications/SV-21-web-hardening.sh) |
| SV-41 | Webmail (Roundcube) hardening | wave2 | medium | built | [`roles/applications/SV-41-roundcube-hardening.sh`](../../roles/applications/SV-41-roundcube-hardening.sh) |
| SV-42 | Database password rotation | wave2 | medium | built | [`roles/applications/SV-42-db-passwords.sh`](../../roles/applications/SV-42-db-passwords.sh) |
| SV-40 | Mail password rotation | wave2 | medium | built | [`roles/applications/SV-40-mail-passwords.sh`](../../roles/applications/SV-40-mail-passwords.sh) |
| SV-50 | Service recovery | any | medium | built | [`roles/applications/SV-50-service-recovery.sh`](../../roles/applications/SV-50-service-recovery.sh) |
| SV-44 | Splunk hardening and passwords | wave2 | medium | built | [`roles/applications/SV-44-splunk-hardening.sh`](../../roles/applications/SV-44-splunk-hardening.sh) |
| SV-45 | Gitea hardening | wave2 | medium | built | [`roles/applications/SV-45-gitea-hardening.sh`](../../roles/applications/SV-45-gitea-hardening.sh) |
| SV-46 | File share hardening (Samba and NFS) | wave2 | medium | built | [`roles/applications/SV-46-fileshare-hardening.sh`](../../roles/applications/SV-46-fileshare-hardening.sh) |
| SV-31 | Mail tamper check | wave2 | medium | built | [`roles/applications/SV-31-mail-tamper.sh`](../../roles/applications/SV-31-mail-tamper.sh) |
| SV-32 | TLS certificate check | wave1 | medium | built | [`roles/applications/SV-32-tls-check.sh`](../../roles/applications/SV-32-tls-check.sh) |
| SV-30 | Service hardening (FTP + legacy) | Hardening: easy | access | built | [`roles/applications/SV-30-service-hardening.sh`](../../roles/applications/SV-30-service-hardening.sh) |

Script files in this folder are named `<ID>-<short-name>.sh` or `.ps1`. What the tiers and risk levels mean, and the rules for each: `docs/PLAN.md`.
