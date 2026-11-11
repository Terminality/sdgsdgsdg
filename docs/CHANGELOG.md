# Changelog

What changed, newest first. Each entry names the scripts touched and how they were tested. Library versions follow `CC_LIB_VERSION` in `lib/lib.sh` and `$script:CcLibVersion` in `lib/lib.ps1`, which are always the same.

## 2026-11-11: Linux safe fixes

**Added**

- LX-39 Linux safe fixes (`roles/linux/LX-39-safe-fixes.sh`): kernel network and memory settings; IPv6 off with `disable_ipv6` (loopback kept), never the boot option; no setuid core dumps; group/other bits removed from password, sudo, SSH, cron, startup, PAM and systemd files; world-writable files fixed in `/etc`, program folders and homes; sticky `/tmp`; logging services started; unowned `/etc/ld.so.preload` and rhosts-style files quarantined; extra `/etc/hosts` entries and IP forwarding reported. Dry run by default; undo line for every change.
- `tests/lx39.test.sh`, run entirely in a fake root with a stand-in sysctl.

**Tested**

- Under dash, bash, busybox sh, ksh93, mksh and yash (47 checks each): dry run changes nothing, apply fixes every planted problem, the undo log restores everything, a protected path is skipped, a second run finds nothing to do. Live apply on Ubuntu 24.04: Apache, nginx, MariaDB and PostgreSQL all still answer.

## 2026-11-11: Linux backup

**Added**

- LX-31 Backup (`roles/linux/LX-31-backup.sh`): one archive of /etc, crontabs, web roots (including those named in the Apache and nginx configs), dotfiles and SSH keys; SHA-256 of every archived file and of the system programs and service units; snapshots of firewall rules, services, ports, packages, routes and kernel settings; optional copy off the box with scp; restore notes.
- `tests/lx31.test.sh`.

**Changed**

- Libraries: read-only scripts now say READ-ONLY in the start banner instead of DRY RUN.

**Tested**

- Ubuntu 24.04 as root and as a normal user, under dash, bash, busybox sh, ksh93, mksh and yash (18 checks each). A file restored from the archive matches the original byte for byte; the hash list catches a later change.

## 2026-11-11: Web and database inventory

**Added**

- SV-01 Web and database inventory (`roles/applications/SV-01-web-db-inventory.sh`): web servers, sites and web roots; web shells, PHP in upload folders, database dumps, `.env` and `.git` in web roots; risky `php.ini` settings; app versions and their database user; MySQL/MariaDB and PostgreSQL accounts, settings, databases, triggers, events, user-defined functions and `pg_hba` rules; Redis and similar stores open to the network. Never records a password.
- `tests/sv01.test.sh`, including a check that a planted password never reaches the output.

**Changed**

- The plan merges the web and database inventories into SV-01 for Linux and Unix. SV-03 becomes its Windows twin (IIS and MSSQL).

**Tested**

- On Apache 2.4, nginx 1.24, PHP 8.3, MariaDB 10.11 and PostgreSQL 16 with planted problems, as root and as a normal user; under dash, bash, busybox sh, ksh93, mksh and yash (27 checks each), and with GNU awk, mawk and busybox awk.

## 2026-11-11: Scan diff

**Added**

- SH-04 Scan diff (`roles/network/SH-04-scan-diff.sh`): compares two network scans (SH-03) or two Linux collector runs (SH-05) of one host, lists what was added, removed or changed, and flags additions such as new accounts, SSH keys, cron entries and backdoor-style ports. Picks the newest two finished runs by itself.
- `tests/sh04.test.sh`.

**Changed**

- Libraries 0.2.0 to 0.2.1: two runs started in the same second no longer share a run folder; the second gets `-2` added to its name (`cc_use_run_dir`, `Use-CcRunDir`).

**Tested**

- SH-04 on real SH-03 and SH-05 runs taken before and after planting an account, a cron entry and listeners, and on hand-made run folders, under dash, bash, busybox sh, ksh93, mksh and yash (27 checks each). The PowerShell run-folder change was tested on PowerShell 7.4 only.

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
