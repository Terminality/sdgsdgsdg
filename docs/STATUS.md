# Build status

15 of 142 scripts are built.

This file is generated from `docs/catalog.csv` by `tools/update-docs.sh`. Do not edit it by hand.

| Wave | Goal | Built | Total |
| --- | --- | --- | --- |
| 0 | Foundation | 2 | 5 |
| 1 | Know what we have and what is scored | 6 | 30 |
| 2 | Evict and lock, all at once | 5 | 28 |
| 3 | Close what should not be open | 2 | 31 |
| 4 | Hunt, recover and report | 0 | 25 |
| 5 | Nice to have, and everything if-present | 0 | 23 |

## Built so far

| ID | Script | Role | Status | File |
| --- | --- | --- | --- | --- |
| LB-01 | Shell library (lib.sh) | Automation | built | `lib/lib.sh` |
| LB-02 | PowerShell library (lib.ps1) | Automation | built | `lib/lib.ps1` |
| NW-01 | Config backup and diff | Network | built | `roles/network/NW-01-config-backup.sh` |
| SH-03 | Network scan | Network | built | `roles/network/SH-03-network-scan.sh` |
| SH-05 | Linux collector | Linux | built | `roles/linux/SH-05-linux-collector.sh` |
| SV-01 | Web and database inventory | Applications | built | `roles/applications/SV-01-web-db-inventory.sh` |
| LX-20 | Password rotation | Linux | built | `roles/linux/LX-20-password-rotation.sh` |
| LX-22 | SSH hardening and key cleanup | Linux | built | `roles/linux/LX-22-ssh-hardening.sh` |
| LX-31 | Backup | Linux | built | `roles/linux/LX-31-backup.sh` |
| LX-39 | Linux safe fixes | Linux | built | `roles/linux/LX-39-safe-fixes.sh` |
| LX-40 | Linux change watch | Linux | built | `roles/linux/LX-40-change-watch.sh` |
| SV-14 | Database backup | Applications | built | `roles/applications/SV-14-db-backup.sh` |
| SH-04 | Scan diff | Network | built | `roles/network/SH-04-scan-diff.sh` |
| LX-25 | Firewall builder | Linux | built | `roles/linux/LX-25-firewall.sh` |
| SV-26 | Brute-force and spam banning | Linux | built | `roles/linux/SV-26-banning.sh` |

`built` means written and passing the local tests. `tested` means it has also been run on the real target systems.
