# CCDC-AI-SLOP

Blue-team scripts for the Collegiate Cyber Defense Competition, written with Claude. The plan is 142 scripts across the eight official team roles; `docs/STATUS.md` shows how many exist.

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
| Linux firewall builder (LX-25) | Drops every incoming connection except SSH, scored ports, ports listening now (not backdoor-style ones), ping, DHCP and the admin/scoring hosts; IPv6 dropped. Own table/chains only; checked before loading; removed again after 2 minutes unless you confirm from a new session | `sudo sh roles/linux/LX-25-firewall.sh --out /root/ccdc-out --apply --admin 10.0.0.5` |
| Linux change watch (LX-40) | Baseline, then a check every minute: new or changed accounts, passwords, privileged groups, sudo/PAM/preload files, cron and timers, services, SSH keys, listening ports, SUID files, web root files, kernel modules. One alert per change, HIGH first, sendable off the box | `sudo sh roles/linux/LX-40-change-watch.sh --out /root/ccdc-out --loop 60 --alert-cmd "ssh admin@10.0.0.5 'cat >>alerts.log'"` |
| Brute-force and spam banning (SV-26) | Counts login failures per address in SSH, FTP, mail, IMAP/POP, web login and PAM logs; bans with a firewall entry that removes itself; never bans the scoring engine, the box itself or the gateway; reports mailboxes sending spam | `sudo sh roles/linux/SV-26-banning.sh --out /root/ccdc-out --apply --loop 60` |
| Database backup (SV-14) | Dumps every MySQL/MariaDB and PostgreSQL database and SQLite files in web roots; checks each dump reads back; hashes, restore commands, copy off the box | `sudo sh roles/applications/SV-14-db-backup.sh --out /root/ccdc-out --copy-to admin@10.0.0.5:/srv/backups/` |
| Network config backup and diff (NW-01) | Saves the running config of every firewall, router and switch (Cisco IOS/ASA, Palo Alto, FortiGate, VyOS, pfSense, OPNsense, MikroTik) and shows what changed since the last copy; a new admin, SNMP community, NAT or allow rule is HIGH; flags a changed device SSH key | `sh roles/network/NW-01-config-backup.sh --out ~/ccdc-out --hosts config/hosts.csv --password-env` |
| Network config audit (NW-07) | Reads the saved device configs and flags telnet or plain-HTTP management, default SNMP communities, clear-text and type 7 passwords, management open to any address, any-to-any allow rules and default admins; lists every account. Touches no device | `sh roles/network/NW-07-config-audit.sh --out ~/ccdc-out` |
| Device password rotation (NW-10) | Changes the login password on each firewall, router and switch (Cisco enable secret too, optionally) while keeping the first session open, tests the new password from a second session, then saves - or puts the old password back if the new one fails. New passwords only in a mode-600 file | `CCDC_NET_PASS=... sh roles/network/NW-10-device-passwords.sh --out ~/ccdc-out --hosts config/hosts.csv --apply` |

The two shared libraries (`lib/lib.sh`, `lib/lib.ps1`) are also finished; every other script is built on them. Next up: Windows (collector, backup, safe fixes, passwords, firewall, change watch).

Nothing here has been run on real competition systems yet. Read "What has and hasn't been tested" before relying on it.

## First 15 minutes: the order to run them

Each box needs the whole kit folder (scripts plus `lib/`); the single-file build is not written yet. Every script that changes things is a dry run until you add `--apply`, so run it once without, read the summary, then run it again with.

Linux box, as root:

1. `LX-31` backup, then `SV-14` if it has a database. Before anything changes.
2. `SH-05` collector (and `SV-01` on web or database servers). Read the HIGH flags.
3. `LX-20` passwords. Protected list first; `--exclude` or `--passwords` for accounts the team must keep or set by hand.
4. `LX-22` SSH keys and settings. Keep a second session open.
5. `LX-39` safe fixes.
6. `LX-25` firewall, last, and confirm it from a new session.
7. Leave running: `LX-40 --loop 60` (change watch) and `SV-26 --apply --loop 60` (banning).

Network devices, from the admin workstation: `NW-01` (save configs), `NW-07` (audit them), then `NW-10` on ONE device first, then the rest.

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
| Linux firewall builder (LX-25) | Stand-in nft, iptables and ss under six shells (port choice, rejected ruleset, rollback timer, confirm, remove). Live with nftables and iptables: from a separate network namespace, allowed ports answer and others are dropped; the timer removes the rules when nobody confirms | RHEL (firewalld present), Alpine; --save on a real reboot |
| Linux change watch (LX-40) | Fake root and stand-in ss under six shells: one planted change per section reported once with the right severity, quiet second check, --accept, --alert-cmd, no hash stored. Live: a planted account, cron job, sudo membership, SSH key, web shell, password change and listener each reported | RHEL, Alpine; long runs |
| Brute-force and spam banning (SV-26) | Sample logs for every service and stand-in firewalls under six shells. Live: real failed SSH logins from a separate network namespace got that address banned in nftables, SSH from it was dropped, and the ban expired by itself | RHEL (secure log), Alpine, journal-only systems, a real mail server |
| Database backup (SV-14) | Under six shells with MariaDB 10.11 and PostgreSQL 16: a table dropped after the backup came back with its rows, using the restore commands from RESTORE.txt | MySQL 8, RHEL, very large databases |
| Network config backup and diff (NW-01) | Against a real OpenSSH server (Linux profile: an added firewall rule shows as HIGH, its removal too); every vendor against sample output from a stand-in ssh under six shells, including unreachable devices, changed host keys, old-algorithm devices and password handling | Real Cisco, Palo Alto, FortiGate, VyOS, pfSense and MikroTik devices |
| Network config audit (NW-07) | A planted-problem and a clean sample config for each of seven vendors under six shells and three awk versions: every planted weakness found, no HIGH or MED on the clean configs, secrets masked | Configs from real devices |
| Device password rotation (NW-10) | Live against a real OpenSSH server (new password logs in, old one refused, nothing leaked). Every vendor, the Cisco privilege level, the Palo Alto hash, the enable secret and the automatic revert against a stand-in device under six shells | Real Cisco, Palo Alto, FortiGate, VyOS and MikroTik devices |

The Windows library is written to PowerShell 2.0 rules but has never run on Windows. Run `tests\lib.Tests.ps1` on your oldest and newest Windows test VMs before building on it.

## Documents

- [`docs/MANUAL.md`](docs/MANUAL.md): how to use what is built, what to watch for, problems and fixes
- [`docs/CONVENTIONS.md`](docs/CONVENTIONS.md): rules for writing a script
- [`docs/STATUS.md`](docs/STATUS.md): what is built
- [`docs/CHANGELOG.md`](docs/CHANGELOG.md): what changed, and when
- [`docs/catalog.csv`](docs/catalog.csv): all 142 planned scripts with role, wave and level
