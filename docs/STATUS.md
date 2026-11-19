# Build status

42 of 46 scripts are built. The plan, tiers and rules: `docs/PLAN.md`.

This file is generated from `docs/catalog.csv` by `tools/update-docs.sh`. Do not edit it by hand.

| Tier | Built | Total |
| --- | --- | --- |
| Enum (look only) | 6 | 7 |
| Backup and prep | 5 | 5 |
| wave2 | 12 | 12 |
| any | 1 | 1 |
| Hardening: easy | 3 | 3 |
| Hardening: medium | 2 | 2 |
| Hardening: hard | 2 | 4 |
| wave1 | 2 | 2 |
| Management | 3 | 3 |
| Alerts | 3 | 4 |
| Kit | 3 | 3 |

## Enum (look only)

| ID | Script | Risk | Status | File |
| --- | --- | --- | --- | --- |
| SH-05 | Linux enum | none | built | `roles/linux/SH-05-linux-enum.sh` |
| SH-06 | Windows enum | none | built | `roles/windows-ad/SH-06-windows-enum.ps1` |
| WN-04 | AD enum | none | planned |  |
| SV-01 | Web and database enum (Linux) | none | built | `roles/applications/SV-01-web-db-enum.sh` |
| SH-03 | Network scan | none | built | `roles/network/SH-03-network-scan.sh` |
| SH-04 | Scan diff | none | built | `roles/network/SH-04-scan-diff.sh` |
| NW-07 | Network device config audit | none | built | `roles/network/NW-07-config-audit.sh` |

## Backup and prep

| ID | Script | Risk | Status | File |
| --- | --- | --- | --- | --- |
| LX-31 | Linux backup | none | built | `roles/linux/LX-31-backup.sh` |
| WN-35 | Windows backup | none | built | `roles/windows-ad/WN-35-backup.ps1` |
| SV-14 | Database backup | none | built | `roles/applications/SV-14-db-backup.sh` |
| SV-15 | Site backup and restore | medium | built | `roles/applications/SV-15-site-backup.sh` |
| NW-01 | Network config backup and diff | none | built | `roles/network/NW-01-config-backup.sh` |

## wave2

| ID | Script | Risk | Status | File |
| --- | --- | --- | --- | --- |
| SV-16 | Web shell hunter | medium | built | `roles/applications/SV-16-webshell-hunter.sh` |
| SV-20 | Database hardening | medium | built | `roles/applications/SV-20-db-hardening.sh` |
| SV-21 | PHP and web app hardening | medium | built | `roles/applications/SV-21-web-hardening.sh` |
| SV-41 | Webmail (Roundcube) hardening | medium | built | `roles/applications/SV-41-roundcube-hardening.sh` |
| SV-42 | Database password rotation | medium | built | `roles/applications/SV-42-db-passwords.sh` |
| SV-40 | Mail password rotation | medium | built | `roles/applications/SV-40-mail-passwords.sh` |
| SV-44 | Splunk hardening and passwords | medium | built | `roles/applications/SV-44-splunk-hardening.sh` |
| SV-31 | Mail tamper check | medium | built | `roles/applications/SV-31-mail-tamper.sh` |
| LX-43 | Log shipping to Splunk | medium | built | `roles/linux/LX-43-log-shipping.sh` |
| LX-45 | Rootkit and malware scan | medium | built | `roles/linux/LX-45-rootkit-scan.sh` |
| LX-44 | AppArmor confinement | medium | built | `roles/linux/LX-44-apparmor.sh` |
| LX-46 | Safe security updates | medium | built | `roles/linux/LX-46-safe-updates.sh` |

## any

| ID | Script | Risk | Status | File |
| --- | --- | --- | --- | --- |
| SV-50 | Service recovery | medium | built | `roles/applications/SV-50-service-recovery.sh` |

## Hardening: easy

| ID | Script | Risk | Status | File |
| --- | --- | --- | --- | --- |
| SV-30 | Service hardening (FTP + legacy) | access | built | `roles/applications/SV-30-service-hardening.sh` |
| LX-39 | Linux safe fixes | safe | built | `roles/linux/LX-39-safe-fixes.sh` |
| WN-43 | Windows safe fixes | safe | built | `roles/windows-ad/WN-43-safe-fixes.ps1` |

## Hardening: medium

| ID | Script | Risk | Status | File |
| --- | --- | --- | --- | --- |
| LX-22 | SSH hardening | service | built | `roles/linux/LX-22-ssh-hardening.sh` |
| LX-42 | Linux persistence sweep | service | built | `roles/linux/LX-42-persistence-sweep.sh` |

## Hardening: hard

| ID | Script | Risk | Status | File |
| --- | --- | --- | --- | --- |
| WN-25 | Windows firewall | access | built | `roles/windows-ad/WN-25-firewall.ps1` |
| LX-25 | Linux firewall | access | built | `roles/linux/LX-25-firewall.sh` |
| WN-27 | Windows remote access lockdown | access | planned |  |
| WN-23 | Account lockdown (Windows / AD) | access | planned |  |

## wave1

| ID | Script | Risk | Status | File |
| --- | --- | --- | --- | --- |
| LX-26 | Remote access lockdown (everything but SSH) | medium | built | `roles/linux/LX-26-remote-access.sh` |
| LX-21 | Account lockdown (Linux) | medium | built | `roles/linux/LX-21-account-lockdown.sh` |

## Management

| ID | Script | Risk | Status | File |
| --- | --- | --- | --- | --- |
| LX-20 | Linux password rotation | access | built | `roles/linux/LX-20-password-rotation.sh` |
| WN-20 | Windows password rotation | access | built | `roles/windows-ad/WN-20-password-rotation.ps1` |
| NW-10 | Network device password rotation | access | built | `roles/network/NW-10-device-passwords.sh` |

## Alerts

| ID | Script | Risk | Status | File |
| --- | --- | --- | --- | --- |
| LX-40 | Linux alerts | none | built | `roles/linux/LX-40-change-watch.sh` |
| LX-41 | Linux session & command logging | none | built | `roles/linux/LX-41-session-log.sh` |
| WN-44 | Windows alerts | none | planned |  |
| SV-26 | Brute-force and spam banning | service | built | `roles/linux/SV-26-banning.sh` |

## Kit

| ID | Script | Risk | Status | File |
| --- | --- | --- | --- | --- |
| LB-01 | Shell library (lib.sh) | none | built | `lib/lib.sh` |
| LB-02 | PowerShell library (lib.ps1) | none | built | `lib/lib.ps1` |
| LB-03 | Build step | none | built | `tools/build.sh` |

`built` means written and passing the local tests. `tested` means it has also been run on the real target systems. A "To do" in the catalog description is a change still owed to a built script.
