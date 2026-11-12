# Changelog

What changed, newest first. Each entry names the scripts touched and how they were tested. Library versions follow `CC_LIB_VERSION` in `lib/lib.sh` and `$script:CcLibVersion` in `lib/lib.ps1`, which are always the same.

## 2026-11-12: Fixes from a full review

**Fixed**

- SV-26 (1.1.0): an attacker could choose which address got banned by logging in with an account name such as `x from 10.0.0.5 port 1`; with the plain iptables backend `0.0.0.0/0` would have blocked everything. The address is now taken from the end of the sshd line and every address must be one plain IPv4 or IPv6 address. The web rule counts login pages only, not every POST under `/admin` or `/login`.
- LX-25 (1.1.0): the rollback timer of an earlier, unconfirmed run removed the rules of a later run that had been confirmed. A timer now only acts while its own run is the live one.
- LX-22 (1.1.0): the default `PermitRootLogin prohibit-password` is no longer applied when root has a password but no SSH key that stays, or when root is on the protected list. New `--root-key-only`.
- LX-39 (1.1.0): `net.ipv6.conf.all.disable_ipv6` also switched IPv6 off on loopback, against what the header and manual said. Loopback is now switched back on afterwards, in the boot file too.
- NW-10 (1.1.0): the new password is written to `pending-password.csv` before it is sent and removed when the outcome is known, so stopping the script mid-change (Ctrl-C in a two-minute commit) no longer loses it. The Palo Alto hash is made with `openssl passwd -stdin` (the password was briefly on a command line). A protected device is matched by name as well as address. An unconfirmed revert records the tried password.
- LX-20 (1.1.0): a name in `--users` or `--exclude` that is not an account stops the script (a misspelled `--exclude` used to get the account rotated); `--ignore-missing` turns that into a warning. `--users` and `--exclude` can be repeated. Password-sheet names that are missing, locked or without a password are reported; spaces around sheet passwords are dropped; passwords with a comma are quoted in `passwords.csv`. FreeBSD reads `/etc/master.passwd` instead of stopping; without `usermod` (Alpine) accounts are locked with `passwd -l`.
- LX-40 (1.1.0): `--count N` never stopped for N of 2 or more on a box with SSH key files (the loop counter was overwritten inside the snapshot).

**Added**

- NW-10 `--passwords FILE`: a chosen new password per device.
- LX-40 `--suid-every N`: in a loop the whole-disk SUID scan runs on every Nth check (default 10).
- LX-25 warns that passive FTP needs a port range when port 21 is allowed.
- README: the first-15-minutes run order.

**Tested**

- New checks in the lx20, lx22, lx25, lx39, lx40, sv26 and nw10 tests under dash, bash, busybox sh, ksh93, mksh and yash. Not tried on real systems: the IPv6 loopback fix (the test machine's kernel has no IPv6), FreeBSD and Alpine account locking.

## 2026-11-11: Device password rotation

**Added**

- NW-10 Device password rotation (`roles/network/NW-10-device-passwords.sh`): change through an open session (commands fed through a FIFO), test from a second session, then save or revert through the first; Cisco IOS (privilege kept from NW-01's copy, optional enable secret), Cisco ASA, Palo Alto (SHA-256 crypt phash and commit), FortiGate, VyOS (commit and save), MikroTik, Linux; pfSense/OPNsense pointed to the GUI; protected devices and accounts skipped; passwords only in a mode-600 file.
- `tests/nw10.test.sh`.

**Tested**

- Live against a real OpenSSH server. Every vendor against a stand-in device that keeps password state, under dash, bash, busybox sh, ksh93, mksh and yash (29 checks each), including a device that ignores the change (old password put back and tested).

## 2026-11-11: Network config audit

**Added**

- NW-07 Network config audit (`roles/network/NW-07-config-audit.sh`): per-vendor rules for Cisco IOS, Cisco ASA, Palo Alto, FortiGate, VyOS, pfSense/OPNsense and MikroTik over NW-01's saved configs or given files; vendor recognised from the text; secrets masked.
- NW-01 now records each device's vendor next to its saved configs.
- `tests/nw07.test.sh`.

**Changed**

- `tests/lint-posix.sh`: the `source` check now needs a path or variable after the word, so config text such as `source any;` is not flagged.

**Tested**

- A planted-problem and a clean config per vendor under dash, bash, busybox sh, ksh93, mksh and yash and with GNU awk, mawk and busybox awk (41 checks each).

## 2026-11-11: Network config backup and diff

**Added**

- NW-01 Network config backup and diff (`roles/network/NW-01-config-backup.sh`): SSH fetch of the running config for Cisco IOS, Cisco ASA, Palo Alto, FortiGate, VyOS, pfSense, OPNsense, MikroTik and Linux; per-vendor clean-up of self-changing lines; diff against the previous copy with HIGH/MED flags and masked secrets; own known_hosts with a HIGH flag on a changed host key; automatic retry with old SSH algorithms; passwords only through sshpass's environment variable.
- `tests/nw01.test.sh`; the host list example explains how to name a device's vendor.

**Tested**

- End to end against a real OpenSSH server. Every vendor against sample output under dash, bash, busybox sh, ksh93, mksh and yash (37 checks each). Real network devices still to do.

## 2026-11-11: Database backup

**Added**

- SV-14 Database backup (`roles/applications/SV-14-db-backup.sh`): one dump per MySQL/MariaDB database including `mysql`, PostgreSQL roles plus a custom-format dump per database, SQLite files from web roots; each dump verified; SHA256SUMS; RESTORE.txt; `--copy-to`, `--keep`, `--max-mb`.
- `tests/sv14.test.sh` (the dump-drop-restore checks run only with `CCDC_TEST_DB=1`, so the suite never creates databases on a real server).

**Tested**

- Under dash, bash, busybox sh, ksh93, mksh and yash with MariaDB 10.11 and PostgreSQL 16 (15 checks each): a table dropped after the backup came back with its row in both engines. Testing found that the PostgreSQL restore command must feed the dump on stdin; RESTORE.txt now does.

## 2026-11-11: Brute-force and spam banning

**Added**

- SV-26 Brute-force and spam banning (`roles/linux/SV-26-banning.sh`): counts failures per address from SSH, FTP, SMTP (SASL and relay), IMAP/POP, web login and PAM log lines; bans with self-expiring entries (nft set timeouts, ipset timeouts, or tracked iptables rules); never bans protected hosts, `--ignore`, own addresses, loopback or the default gateway; reports mailboxes sending to many recipients. Reads only new log lines each run, so no date parsing.
- `tests/sv26.test.sh`.

**Tested**

- Sample logs and stand-in firewalls under dash, bash, busybox sh, ksh93, mksh and yash (28 checks each). The busybox run found that some busybox awks lack the `^` operator; the network-size calculation now multiplies instead. Live: real failed SSH logins from a separate network namespace were banned in nftables and the ban expired after its time.

## 2026-11-11: Linux change watch

**Added**

- LX-40 Linux change watch (`roles/linux/LX-40-change-watch.sh`): baseline and repeated checks of accounts, passwords (as a checksum, never the hash), groups, sudo/PAM/preload and startup files, cron and timers, unit files, SSH keys, listening ports, SUID files, web root files and kernel modules; one alert per change in `alerts.log`; `--loop`, `--accept`, `--alert-cmd`.
- `tests/lx40.test.sh`.

**Fixed**

- LX-20: reading shadow and passwd together now tells the files apart by name, so an empty shadow file cannot be mistaken for passwd (the same awk trap found while building LX-40).

**Tested**

- Fake root under dash, bash, busybox sh, ksh93, mksh and yash (21 checks each). Live on Ubuntu 24.04: every planted change reported once, and the second check was quiet.

## 2026-11-11: Linux firewall builder

**Added**

- LX-25 Linux firewall builder (`roles/linux/LX-25-firewall.sh`): incoming traffic limited to loopback, replies, ICMP, DHCP, SSH, scored ports, ports listening now (backdoor-style ports excluded) and admin/scoring hosts; IPv6 dropped; own nftables table or iptables chains; `nft -c` check; detached rollback timer cancelled by `keep-firewall.sh` from a new session; `--save`, `--remove`, `--strict`, `--restrict-out`, `--ssh-from`.
- `tests/lx25.test.sh`.

**Tested**

- Stand-in nft, iptables and ss under dash, bash, busybox sh, ksh93, mksh and yash (30 checks each). Live on Ubuntu 24.04 with nftables 1.0.9 and iptables 1.8.10, probing from a separate network namespace: allowed ports answer, a backdoor port and (with `--strict`) unlisted ports are dropped, `--ssh-from` limits SSH, and the timer removed the rules when nobody confirmed.

## 2026-11-11: SSH hardening and key cleanup

**Added**

- LX-22 SSH hardening and key cleanup (`roles/linux/LX-22-ssh-hardening.sh`): lists every authorized key of every account and removes keys not on the team's list (removed lines kept as evidence); a settings block at the top of `sshd_config`; `sshd -t` before installing; reload with a listening check and automatic restore; `~/.ssh/rc` and `/etc/ssh/sshrc` quarantined; loosening `Match` blocks, key commands and extra sshd processes reported.
- `tests/lx22.test.sh`.

**Tested**

- Fake root and stand-in sshd under dash, bash, busybox sh, ksh93, mksh and yash (34 checks each). Live with OpenSSH 9.6: after `--apply` the team key still logs in, the planted and forced-command keys are refused, and password login still works.

## 2026-11-11: Linux password rotation

**Added**

- LX-20 Linux password rotation (`roles/linux/LX-20-password-rotation.sh`): new random (or pre-chosen) passwords for every account with a usable password, skipping protected accounts and the account that ran sudo; with `--keep`, locks and expires human and extra UID 0 accounts not on the team list; moves hashes hidden in `/etc/passwd` into `/etc/shadow`; writes new passwords only to a mode-600 file.
- `cc_which` in `lib/lib.sh`: full path of a program, so busybox sh cannot swap in its built-in version.
- `tests/lx20.test.sh`.

**Tested**

- Stand-in chpasswd, usermod and pwconv on a fake root under dash, bash, busybox sh, ksh93, mksh and yash (32 checks each), including a check that no password reaches the log, summary, accounts file or undo log. Live with the real tools on throwaway accounts: new passwords verify, old ones are rejected, the unlisted account is locked and expired.

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
