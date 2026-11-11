# Changelog

What changed, newest first. Each entry names the scripts touched and how they were tested. Library versions follow `CC_LIB_VERSION` in `lib/lib.sh` and `$script:CcLibVersion` in `lib/lib.ps1`, which are always the same.

## 2026-11-11: Network scan

**Added**

- SH-03 Network scan (`roles/network/SH-03-network-scan.sh`): live hosts, open ports and versions; scored-service and host-list checks; `fast`, `full`, `udp` and `outside` profiles; nmap with python, bash and nc fallbacks.
- `tests/sh03.test.sh`.

**Tested**

- All four engines against listeners on 127.0.0.1, under dash, bash, busybox sh, ksh93, mksh and yash (33 checks each). Not yet on a real competition network.

## 2026-11-11: Linux collector and inventory helpers

**Added**

- SH-05 Linux collector (`roles/linux/SH-05-linux-collector.sh`): read-only inventory of a Linux or Unix host in 20 sections, with `card`, `full` and `triage` profiles and a one-page summary.
- `tests/sh05.test.sh`.
- `docs/CHANGELOG.md` (this file).

**Changed**

- Libraries 0.1.0 to 0.2.0: flags (`cc_flag`, `Add-CcFlag`) with a severity-ordered report, a per-run output folder, raw command capture, and a CSV-splitting awk function. Screen lines in the flag report are cut at 200 characters; the CSV keeps the full text.
- The POSIX lint no longer mistakes a regex ending in `$'` for bash quoting.

**Tested**

- SH-05 on Ubuntu 24.04 as root and as an unprivileged user, under dash, bash, busybox sh, ksh93, mksh and yash. Flag noise tuned on a real system from 62 high / 118 medium to 2 high / 3 medium.
- Library tests: 70 checks each for `lib.sh` (six shells) and `lib.ps1` (PowerShell 7.4 on Linux).

## 2026-11-11: Repository structure and shared libraries

**Added**

- Folder layout: `roles/` for the eight official roles, `lib/`, `templates/`, `config/`, `tests/`, `tools/`, `docs/`.
- LB-01 `lib/lib.sh` and LB-02 `lib/lib.ps1`, version 0.1.0.
- Script templates, the POSIX and PowerShell 2.0 lints, library tests, the test runner, `docs/MANUAL.md`, `docs/CONVENTIONS.md`, `docs/catalog.csv` with all 140 planned scripts, and `tools/update-docs.sh`.

**Tested**

- `lib.sh` under six shells; `lib.ps1` on PowerShell 7.4 on Linux. Neither on Windows, FreeBSD or Solaris.
