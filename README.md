# CCDC-AI-SLOP

Blue-team scripts for the Collegiate Cyber Defense Competition, written with Claude. The plan is 140 scripts across the eight official team roles; `docs/STATUS.md` shows how many exist.

## Ready to use

| Script | What it does | How to run it |
| --- | --- | --- |
| Network scan (SH-03) | Live hosts, open ports and service versions. With the host list it checks every scored service is reachable and flags hosts that should not be there. Uses nmap, or python, bash or nc when nmap is missing | `sh roles/network/SH-03-network-scan.sh --target 10.0.2.0/24 --hosts config/hosts.csv --out ~/ccdc-out` |
| Scan diff (SH-04) | What changed between two network scans, or two collector runs of one host: new accounts, SSH keys, cron entries, sudo rules, SUID files and listening ports, with the additions flagged first | `sh roles/network/SH-04-scan-diff.sh --type sh05 --out /root/ccdc-out` |
| Linux collector (SH-05) | Read-only inventory of a Linux or Unix host: accounts, listening ports and their programs, services, cron and other autostart, SSH keys, sudo, processes, risky files, firewall, PAM, credentials files. One-page summary with the problems worst first | `sudo sh roles/linux/SH-05-linux-collector.sh --out /root/ccdc-out` |
| Web and database inventory (SV-01) | Web servers, sites and web roots; web shells, database dumps, .env and .git files in web roots; app versions; MySQL, MariaDB and PostgreSQL accounts with no password, remote root, backdoor functions and trust logins | `sudo sh roles/applications/SV-01-web-db-inventory.sh --out /root/ccdc-out` |
| Backup (LX-31) | Run first. Archives /etc, crontabs, web roots, dotfiles and SSH keys; hashes every file and the system programs; saves firewall rules, services and ports; can copy it all off the box | `sudo sh roles/linux/LX-31-backup.sh --out /root/ccdc-out --copy-to admin@10.0.0.5:/srv/backups/` |
| Linux safe fixes (LX-39) | Hardening that cannot break a scored service: kernel network settings, IPv6 off (the safe way), no setuid core dumps, tight modes on password, sudo, SSH, cron and startup files, sticky /tmp, logging on, rootkit preload and rhosts files quarantined. Dry run unless `--apply`; every change has an undo line | `sudo sh roles/linux/LX-39-safe-fixes.sh --out /root/ccdc-out --apply` |
| Linux password rotation (LX-20) | New random passwords for every account with a usable password (protected scoring accounts skipped); with a team list, locks and expires every other human account; fixes hashes hidden in /etc/passwd. New passwords go to one mode-600 file, never the screen or log | `sudo sh roles/linux/LX-20-password-rotation.sh --out /root/ccdc-out --apply --keep /root/team.txt` |
| SSH hardening and key cleanup (LX-22) | Removes every authorized key not on the team's list (service accounts too); safe sshd settings in a block at the top of sshd_config; tests with sshd -t, reloads without dropping sessions, puts the old config back if sshd stops listening. Password logins stay on for scoring | `sudo sh roles/linux/LX-22-ssh-hardening.sh --out /root/ccdc-out --apply --allow-keys /root/team.pub` |

The two shared libraries (`lib/lib.sh`, `lib/lib.ps1`) are also finished; every other script is built on them. Next up: the rest of the Linux first-15-minutes scripts (safe fixes, password rotation, SSH hardening, firewall, change watch), then Windows.

Nothing here has been run on real competition systems yet. Read "What has and hasn't been tested" before relying on it.

## Layout

```
lib/          shared libraries: lib.sh (Unix) and lib.ps1 (Windows)
roles/        one folder per official role; each script lives with its owner
  captain/  inject-lead/  network/  linux/
  windows-ad/  applications/  detection-ir/  automation/
templates/    runnable starting points for a new .sh or .ps1 script
config/       file formats the scripts read (examples only; real data is git-ignored)
tests/        lint checks, library tests, and the runner that executes all of them
tools/        repo maintenance (regenerate docs; the build step will live here)
docs/         MANUAL.md, CONVENTIONS.md, catalog.csv, STATUS.md
dist/         built standalone scripts (generated, not committed)
```

Where things go:

- A competition script goes in `roles/<role>/`, named `<ID>-<short-name>.sh` or `.ps1`, using the ID from `docs/catalog.csv`.
- Code two or more scripts need goes in `lib/`.
- Anything that only helps maintain this repository goes in `tools/`.
- Every script gets a test in `tests/` and a section in `docs/MANUAL.md`.

## How the scripts behave

Every script follows the same rules, enforced by the libraries:

- **Dry run by default.** A script changes nothing until run with `--apply` (`-Apply` on Windows).
- **Protected list.** A script refuses to touch anything listed in the protected list, and refuses to apply at all if there is no list.
- **Backup and undo.** Each change is backed up first and its undo command is appended to one `undo-<host>.log` per host.
- **Output never goes in the kit.** Logs, CSV files and backups go to a folder you choose with `--out`.
- **Same exit codes everywhere.** 0 ok, 2 usage, 3 missing requirement, 5 a change failed.

`docs/MANUAL.md` explains each of these, with problems and fixes.

## Quick start

```sh
# run every check
sh tests/run-tests.sh

# look at a Linux host (read-only)
sudo sh roles/linux/SH-05-linux-collector.sh --out /root/ccdc-out --profile card

# try the template scripts (dry run; writes only to the folder you name)
sh templates/script-template.sh --out /tmp/ccdc-out --debug
powershell -NoProfile -ExecutionPolicy Bypass -File templates\script-template.ps1 -Out C:\ccdc-out -DebugLog
```

To add a script: copy a template into the right `roles/` folder, rename it to its catalog ID, fill in the header, write a test, set its `status` and `path` in `docs/catalog.csv`, run `sh tools/update-docs.sh`, and add its section to the manual. `docs/CONVENTIONS.md` has the details.

## What has and hasn't been tested

| | Tested | Not tested |
| --- | --- | --- |
| `lib.sh` | dash, bash, busybox sh, ksh93, mksh, yash on Linux; shellcheck clean | FreeBSD, Solaris, and old Linux releases |
| `lib.ps1` | PowerShell 7.4 on Linux; a pattern check for post-2.0 features | Any real Windows, including PowerShell 2.0, 4.0 and 5.1 |
| Network scan (SH-03) | All four engines (nmap 7.94, python, bash, nc) against test listeners on 127.0.0.1, under six shells | A real competition network; the udp and full profiles at scale |
| Scan diff (SH-04) | Real SH-03 and SH-05 runs before and after planting a user, a cron entry and listeners, plus hand-made run folders, under six shells | Runs taken on a real competition network |
| Linux collector (SH-05) | Ubuntu 24.04 as root and as an unprivileged user, under the same six shells; a planted SUID binary is flagged | RHEL, SUSE, Alpine, FreeBSD, Solaris |
| Web and database inventory (SV-01) | Ubuntu 24.04 with Apache, nginx, PHP 8.3, MariaDB 10.11 and PostgreSQL 16 with planted problems, as root and as a normal user, under six shells and three awk versions | RHEL (httpd), FreeBSD, MySQL 8, IIS and MSSQL (Windows twin SV-03 not built yet) |
| Backup (LX-31) | Ubuntu 24.04 as root and as a normal user, under six shells; a file restored from the archive matches byte for byte; the hash list catches a later change; copy with scp | RHEL, Alpine, FreeBSD; copying to a real remote host |
| Linux safe fixes (LX-39) | A fake root with planted problems and a stand-in sysctl, under six shells: dry run, apply, full undo, protected list, second run. Live apply on Ubuntu 24.04 with Apache, nginx, MariaDB and PostgreSQL still answering afterwards; rsyslog started through its init script | systemd and OpenRC service starts; RHEL, Alpine; a real IPv6 network |
| Linux password rotation (LX-20) | Stand-in tools on a fake root under six shells: rotation, protected skip, locking, hidden-hash fix, no password leaks, full undo. Live with the real chpasswd and usermod: new passwords verify, old ones fail, the unlisted account is locked and expired | FreeBSD (pw), RHEL, Alpine; PAM password-quality rules |
| SSH hardening and key cleanup (LX-22) | Fake root and stand-in sshd under six shells (dry run, apply, protected keys, rejected config, undo, second run). Live with OpenSSH 9.6: the team key still logs in, planted keys are refused, password login still works, sshd reloaded and kept listening | systemd and OpenRC reloads; RHEL, Alpine; the restore-after-failed-reload path on a real box |

The Windows library is written to PowerShell 2.0 rules but has never run on Windows. Run `tests\lib.Tests.ps1` on your oldest and newest Windows test VMs before building on it.

## Documents

- [`docs/MANUAL.md`](docs/MANUAL.md): how to use what is built, what to watch for, problems and fixes
- [`docs/CONVENTIONS.md`](docs/CONVENTIONS.md): rules for writing a script
- [`docs/STATUS.md`](docs/STATUS.md): what is built
- [`docs/CHANGELOG.md`](docs/CHANGELOG.md): what changed, and when
- [`docs/catalog.csv`](docs/catalog.csv): all 140 planned scripts with role, wave and level
