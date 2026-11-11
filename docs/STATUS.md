# Build status

5 of 142 scripts are built.

This file is generated from `docs/catalog.csv` by `tools/update-docs.sh`. Do not edit it by hand.

| Wave | Goal | Built | Total |
| --- | --- | --- | --- |
| 0 | Foundation | 2 | 5 |
| 1 | Know what we have and what is scored | 2 | 29 |
| 2 | Evict and lock, all at once | 0 | 29 |
| 3 | Close what should not be open | 1 | 31 |
| 4 | Hunt, recover and report | 0 | 25 |
| 5 | Nice to have, and everything if-present | 0 | 23 |

## Built so far

| ID | Script | Role | Status | File |
| --- | --- | --- | --- | --- |
| LB-01 | Shell library (lib.sh) | Automation | built | `lib/lib.sh` |
| LB-02 | PowerShell library (lib.ps1) | Automation | built | `lib/lib.ps1` |
| SH-03 | Network scan | Network | built | `roles/network/SH-03-network-scan.sh` |
| SH-05 | Linux collector | Linux | built | `roles/linux/SH-05-linux-collector.sh` |
| SH-04 | Scan diff | Network | built | `roles/network/SH-04-scan-diff.sh` |

`built` means written and passing the local tests. `tested` means it has also been run on the real target systems.
