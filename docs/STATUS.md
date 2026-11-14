# Build status

22 of 54 scripts are built. The plan, tiers and rules: `docs/PLAN.md`.

This file is generated from `docs/catalog.csv` by `tools/update-docs.sh`. Do not edit it by hand.

| Tier | Built | Total |
| --- | --- | --- |
| Enum (look only) | 6 | 11 |
| Backup and prep | 4 | 7 |
| Hardening: easy | 2 | 2 |
| Hardening: medium | 1 | 6 |
| Hardening: hard | 2 | 6 |
| Management | 3 | 10 |
| Alerts | 2 | 4 |
| Eviction | 0 | 3 |
| Kit | 2 | 5 |

## Enum (look only)

| ID | Script | Risk | Status | File |
| --- | --- | --- | --- | --- |
| SH-05 | Linux enum | none | built | `roles/linux/SH-05-linux-enum.sh` |
| SH-06 | Windows enum | none | built | `roles/windows-ad/SH-06-windows-enum.ps1` |
| WN-04 | AD enum | none | planned |  |
| LX-23 | SSH enum | none | planned |  |
| SV-01 | Web and database enum (Linux) | none | built | `roles/applications/SV-01-web-db-enum.sh` |
| SV-03 | Web and SQL Server enum (Windows) | none | planned |  |
| SV-04 | Mail enum | none | planned |  |
| SV-08 | Splunk enum | none | planned |  |
| SH-03 | Network scan | none | built | `roles/network/SH-03-network-scan.sh` |
| SH-04 | Scan diff | none | built | `roles/network/SH-04-scan-diff.sh` |
| NW-07 | Network device config audit | none | built | `roles/network/NW-07-config-audit.sh` |

## Backup and prep

| ID | Script | Risk | Status | File |
| --- | --- | --- | --- | --- |
| LX-31 | Linux backup | none | built | `roles/linux/LX-31-backup.sh` |
| WN-35 | Windows backup | none | built | `roles/windows-ad/WN-35-backup.ps1` |
| SV-14 | Database backup | none | built | `roles/applications/SV-14-db-backup.sh` |
| NW-01 | Network config backup and diff | none | built | `roles/network/NW-01-config-backup.sh` |
| SH-09 | Protected list builder | none | planned |  |
| SH-11 | Backup admin account | access | planned |  |
| AU-12 | Restore and undo runner | service | planned |  |

## Hardening: easy

| ID | Script | Risk | Status | File |
| --- | --- | --- | --- | --- |
| LX-39 | Linux safe fixes | safe | built | `roles/linux/LX-39-safe-fixes.sh` |
| WN-43 | Windows safe fixes | safe | built | `roles/windows-ad/WN-43-safe-fixes.ps1` |

## Hardening: medium

| ID | Script | Risk | Status | File |
| --- | --- | --- | --- | --- |
| LX-22 | SSH fixes | service | built | `roles/linux/LX-22-ssh-hardening.sh` |
| LX-27 | Admin and sudo cleanup | access | planned |  |
| SV-15 | Web hardening | service | planned |  |
| SV-09 | SQL Server hardening | service | planned |  |
| SV-17 | Mail hardening | service | planned |  |
| SV-10 | Splunk hardening | service | planned |  |

## Hardening: hard

| ID | Script | Risk | Status | File |
| --- | --- | --- | --- | --- |
| WN-25 | Windows firewall | access | built | `roles/windows-ad/WN-25-firewall.ps1` |
| LX-25 | Linux firewall | access | built | `roles/linux/LX-25-firewall.sh` |
| WN-27 | Windows remote access lockdown | access | planned |  |
| LX-26 | Linux remote access lockdown | access | planned |  |
| WN-23 | Account lockdown (Windows / AD) | access | planned |  |
| LX-21 | Account lockdown (Linux) | access | planned |  |

## Management

| ID | Script | Risk | Status | File |
| --- | --- | --- | --- | --- |
| LX-20 | Linux password rotation | access | built | `roles/linux/LX-20-password-rotation.sh` |
| WN-20 | Windows password rotation | access | built | `roles/windows-ad/WN-20-password-rotation.ps1` |
| NW-10 | Network device password rotation | access | built | `roles/network/NW-10-device-passwords.sh` |
| SV-20 | Application password rotation | service | planned |  |
| AU-16 | Credential sheet | none | planned |  |
| AU-20 | Account manager | access | planned |  |
| SH-08 | Service checker | none | planned |  |
| AU-17 | Inject helpers | none | planned |  |
| IN-01 | Inject tracker | none | planned |  |
| CP-01 | Run sheet | none | planned |  |

## Alerts

| ID | Script | Risk | Status | File |
| --- | --- | --- | --- | --- |
| LX-40 | Linux alerts | none | built | `roles/linux/LX-40-change-watch.sh` |
| WN-44 | Windows alerts | none | planned |  |
| AU-10 | Splunk forwarding and alert searches | service | planned |  |
| SV-26 | Brute-force and spam banning | service | built | `roles/linux/SV-26-banning.sh` |

## Eviction

| ID | Script | Risk | Status | File |
| --- | --- | --- | --- | --- |
| IR-03 | Persistence hunter (Linux) | service | planned |  |
| IR-04 | Persistence hunter (Windows) | service | planned |  |
| IR-28 | Session and credential purge | access | planned |  |

## Kit

| ID | Script | Risk | Status | File |
| --- | --- | --- | --- | --- |
| LB-01 | Shell library (lib.sh) | none | built | `lib/lib.sh` |
| LB-02 | PowerShell library (lib.ps1) | none | built | `lib/lib.ps1` |
| LB-03 | Build step | none | planned |  |
| AU-02 | Linux fan-out | service | planned |  |
| AU-30 | Local runner | none | planned |  |

`built` means written and passing the local tests. `tested` means it has also been run on the real target systems. A "To do" in the catalog description is a change still owed to a built script.
