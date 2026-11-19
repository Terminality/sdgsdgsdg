# CCDC-AI-SLOP

Blue-team scripts for the Collegiate Cyber Defense Competition, written with Claude.

**Start here:** [`docs/PLAN.md`](docs/PLAN.md) (the plan), [`docs/ENVIRONMENT.md`](docs/ENVIRONMENT.md) (what is scored), [`AGENTS.md`](AGENTS.md) (rules for changing the repo). Core scripts are for Linux, Windows / AD and Network only; other roles write their own.

## Getting a script onto a box

Use the files in **[`dist/`](dist/)**: each one is a single standalone file with the library already inside. Copy one file and run it, no `lib` folder needed:

```
sudo sh LX-39-safe-fixes.sh
```

Copy `dist/MANIFEST.sha256` too if you want each script to check it wasn't changed. The scripts in `roles/` are the source and still need `lib/` next to them.

## Ready to use

| Script | What it does | How to run it |
| --- | --- | --- |
| Network scan (SH-03) | Live hosts, open ports and service versions. With the host list it checks every scored service is reachable and flags hosts that should not be there. Uses nmap, or python, bash or nc when nmap is missing | `sh roles/network/SH-03-network-scan.sh --target 10.0.2.0/24 --hosts config/hosts.csv --out ~/ccdc-out` |
| Scan diff (SH-04) | What changed between two network scans, or two enum runs of one host: new accounts, SSH keys, cron entries, sudo rules, SUID files and listening ports, with the additions flagged first | `sh roles/network/SH-04-scan-diff.sh --type sh05 --out /root/ccdc-out` |
| Linux enum (SH-05) | Read-only inventory of a Linux or Unix host: accounts, listening ports and their programs, services, cron and other autostart, SSH keys, sudo, processes, risky files, firewall, PAM, credentials files. One-page summary with the problems worst first | `sudo sh roles/linux/SH-05-linux-enum.sh --out /root/ccdc-out` |
| Web and database enum (SV-01) | Asks what to look at, then shows web servers, sites, which URL path serves which folder or app, languages and app servers (flags dev/debug servers), web roots with web shells, dumps, .env and .git, risky PHP settings, apps and their databases, MySQL/PostgreSQL accounts | `sudo sh roles/applications/SV-01-web-db-enum.sh --out /root/ccdc-out` |
| Backup (LX-31) | Run first. Archives /etc, crontabs, web roots, dotfiles and SSH keys; hashes every file and the system programs; saves firewall rules, services and ports; can copy it all off the box | `sudo sh roles/linux/LX-31-backup.sh --out /root/ccdc-out --copy-to admin@10.0.0.5:/srv/backups/` |
| Linux safe fixes (LX-39) | Hardening that cannot break a scored service: kernel network settings, IPv6 off (the safe way), no setuid core dumps, tight modes on password, sudo, SSH, cron and startup files, sticky /tmp, logging on, rootkit preload and rhosts files quarantined. Dry run unless `--apply`; every change has an undo line | `sudo sh roles/linux/LX-39-safe-fixes.sh --out /root/ccdc-out --apply` |
| Linux password rotation (LX-20) | New random passwords for every account with a usable password (protected scoring accounts skipped); with a team list, locks and expires every other human account; fixes hashes hidden in /etc/passwd. New passwords go to one mode-600 file, never the screen or log | `sudo sh roles/linux/LX-20-password-rotation.sh --out /root/ccdc-out --apply --keep /root/team.txt` |
| Account lockdown (LX-21) | Every account one by one: second root, empty passwords, extra admins, sudo NOPASSWD, planted SSH keys, service accounts with a shell; keep / lock / take admin away / remove keys | `sudo sh roles/linux/LX-21-account-lockdown.sh --protected p.csv --apply` |
| SSH hardening and key cleanup (LX-22) | Removes every authorized key not on the team's list (service accounts too); safe sshd settings in a block at the top of sshd_config; tests with sshd -t, reloads without dropping sessions, puts the old config back if sshd stops listening. Password logins stay on for scoring | `sudo sh roles/linux/LX-22-ssh-hardening.sh --out /root/ccdc-out --apply --allow-keys /root/team.pub` |
| Linux firewall builder (LX-25) | Drops every incoming connection except SSH, scored ports, ports listening now (not backdoor-style ones), ping, DHCP and the admin/scoring hosts; IPv6 dropped. Own table/chains only; checked before loading; removed again after 2 minutes unless you confirm from a new session | `sudo sh roles/linux/LX-25-firewall.sh --out /root/ccdc-out --apply --admin 10.0.0.5` |
| Linux change watch (LX-40) | Asks what to watch, takes a baseline, then checks every minute: accounts, passwords, admin groups, sudo/PAM/preload files, cron, boot units, stopped services, SSH keys, new listeners and new outgoing connections (reverse shells) with the process behind them, SUID files, web roots, kernel modules. One alert per change, HIGH first, sendable off the box | `sudo sh roles/linux/LX-40-change-watch.sh --loop 60 --team 10.0.0.0/24` |
| Brute-force and spam banning (SV-26) | Asks the limits, ban length, services and who never to ban, then counts login failures per address (SSH, FTP, mail, web login, PAM) and bans the ones over the limit with a firewall ban that ends by itself. Never bans your team, scoring, this box or the gateway. Reports spam from a compromised mailbox | `sudo sh roles/linux/SV-26-banning.sh --protected p.csv --apply --loop 60` |
| Database backup (SV-14) | Dumps every MySQL/MariaDB and PostgreSQL database and SQLite files in web roots; checks each dump reads back; hashes, restore commands, copy off the box | `sudo sh roles/applications/SV-14-db-backup.sh --out /root/ccdc-out --copy-to admin@10.0.0.5:/srv/backups/` |
| Site backup and restore (SV-15) | Backs up each web site (files, hashes, its database, web server configs); `--check` lists defaced, deleted and new files (web shells); `--restore` puts back only what changed | `sudo sh roles/applications/SV-15-site-backup.sh --backup --batch` |
| Web shell hunter (SV-16) | Finds web shells by what is in the files (request data run as code, eval of encoded code, PHP in uploads or images, .htaccess tricks, changed WordPress core), shows the line, quarantines; `--watch --auto-quarantine` | `sudo sh roles/applications/SV-16-webshell-hunter.sh --protected p.csv --apply` |
| Database hardening (SV-20) | Lists every MySQL/MariaDB account and the app using it; fixes anonymous accounts, remote root, no-password accounts, FILE rights, app passwords (written into the app config), bind, backdoor UDFs - site checked after, put back if it breaks | `sudo sh roles/applications/SV-20-db-hardening.sh --protected p.csv --apply --level service` |
| PHP and web app hardening (SV-21) | Finds the web apps; PHP settings, config files root-only, no PHP in upload folders (web shells stop), blocks .git/.env/backups and xmlrpc, new WordPress admins, code read-only - site checked after, put back if it breaks | `sudo sh roles/applications/SV-21-web-hardening.sh --protected p.csv --apply --level service` |
| Mail tamper check (SV-31) | Mail backdoors: hidden BCC copies, programs run on every delivery, rogue master.cf services, open relay, aliases/.forward/sieve that run programs or forward mail out; each fix asked, mail checked after | `sudo sh roles/applications/SV-31-mail-tamper.sh --protected p.csv --apply` |
| Webmail (Roundcube) hardening (SV-41) | Roundcube: known holes for its version, logins sent to another server, installer left on, password-logging debug, default des_key, downloadable logs and config; login page checked after | `sudo sh roles/applications/SV-41-roundcube-hardening.sh --protected p.csv --apply` |
| Database password rotation (SV-42) | New passwords for every MySQL/MariaDB and PostgreSQL account; app configs updated in the same step; each login tested; site checked after, put back if it breaks | `sudo sh roles/applications/SV-42-db-passwords.sh --protected p.csv --apply` |
| Mail password rotation (SV-40) | New passwords for the mail users wherever Dovecot keeps them (system accounts, passwd-file, sasldb); each tested by an IMAP login; flags master users | `sudo sh roles/applications/SV-40-mail-passwords.sh --protected p.csv --apply` |
| Service recovery (SV-50) | Why a scored service is down (stopped, masked, broken config, port taken, firewall, tampered files, full disk) and the fix; `--watch 30 --auto-restart` keeps them up | `sudo sh roles/applications/SV-50-service-recovery.sh --protected p.csv --apply` |
| Splunk hardening and passwords (SV-44) | Splunk backdoors (scripted inputs, planted apps, deployment server, extra admins, default password) out; new Splunk passwords; test search after, put back if it fails | `sudo sh roles/applications/SV-44-splunk-hardening.sh --protected p.csv --apply` |
| Network config backup and diff (NW-01) | Saves the running config of every firewall, router and switch (Cisco IOS/ASA, Palo Alto, FortiGate, VyOS, pfSense, OPNsense, MikroTik) and shows what changed since the last copy; a new admin, SNMP community, NAT or allow rule is HIGH; flags a changed device SSH key | `sh roles/network/NW-01-config-backup.sh --out ~/ccdc-out --hosts config/hosts.csv --password-env` |
| Network config audit (NW-07) | Reads the saved device configs and flags telnet or plain-HTTP management, default SNMP communities, clear-text and type 7 passwords, management open to any address, any-to-any allow rules and default admins; lists every account. Touches no device | `sh roles/network/NW-07-config-audit.sh --out ~/ccdc-out` |
| Device password rotation (NW-10) | Changes the login password on each firewall, router and switch (Cisco enable secret too, optionally) while keeping the first session open, tests the new password from a second session, then saves - or puts the old password back if the new one fails. New passwords only in a mode-600 file | `CCDC_NET_PASS=... sh roles/network/NW-10-device-passwords.sh --out ~/ccdc-out --hosts config/hosts.csv --apply` |
| Windows enum (SH-06) | Read-only inventory of a Windows host: accounts and admins, listening ports and their programs, services, Run keys, debugger and sticky-keys backdoors, WMI subscriptions, tasks, weak settings (WDigest, UAC, SMBv1, Zerologon, RDP), firewall, Defender exclusions, processes, recent log clears and new admins. One-page summary, worst first | `powershell -NoProfile -ExecutionPolicy Bypass -File roles\windows-ad\SH-06-windows-enum.ps1 -Out C:\ccdc-out` |
| Windows backup (WN-35) | Run first after the enum. Saves firewall rules, security policy, audit policy, tasks, key registry areas, IIS sites, DNS zones, DHCP, GPOs and SYSVOL, each with the command that puts it back; hashes everything; copies it off the box | `powershell -NoProfile -ExecutionPolicy Bypass -File roles\windows-ad\WN-35-backup.ps1 -Out C:\ccdc-out -CopyTo \\10.0.0.5\backups` |
| Windows password rotation (WN-20) | New passwords for every enabled local account (every domain user on a DC). Skips service accounts, the protected list and built-ins; `-Exclude` stops on a typo; `-Passwords` sets chosen ones. Passwords only in an admin-only file | `powershell -NoProfile -ExecutionPolicy Bypass -File roles\windows-ad\WN-20-password-rotation.ps1 -Out C:\ccdc-out -Apply -Exclude mark.jacobs` |
| Windows safe fixes (WN-43) | Fixes that cannot break a scored service: SMBv1 and WDigest off, Zerologon enforced on DCs, UAC on, Guest off, sticky-keys and debugger backdoors, port forwards, WMI persistence, Defender exclusions removed, auditing on, and more. Every change recorded; `-Undo latest -Apply` puts the run back | `powershell -NoProfile -ExecutionPolicy Bypass -File roles\windows-ad\WN-43-safe-fixes.ps1 -Out C:\ccdc-out -Apply` |
| Windows firewall (WN-25) | Default-deny inbound on every profile; opens scored, protected and safe listening ports and everything from the admin/scoring addresses; turns off allow-all and backdoor rules. Rolls itself back in 5 minutes unless kept from a new connection; `-Undo` restores the old firewall exactly | `powershell -NoProfile -ExecutionPolicy Bypass -File roles\windows-ad\WN-25-firewall.ps1 -Out C:\ccdc-out -Apply -AdminFrom 10.0.0.5` |

The two shared libraries (`lib/lib.sh`, `lib/lib.ps1`) are also finished; every other script is built on them. `tools/build.sh` pastes them into each script to make `dist/`. Next up: the planned scripts in `docs/STATUS.md`.

Nothing here has been run on real competition systems yet. Read "What has and hasn't been tested" before relying on it.

## First 15 minutes: the order to run them

Each box needs the whole kit folder (scripts plus `lib/`); the single-file build is not written yet. Every script that changes things is a dry run until you add `--apply`, so run it once without, read the summary, then run it again with.

### Linux box (run as root on each box)

1. `LX-31` backup, then `SV-15 --backup` on web boxes (sites and their databases) and `SV-14` for any other database. Before anything changes.
2. `SH-05` enum (and `SV-01` on web or database servers). Read the HIGH flags.
3. `LX-20` passwords. Protected list first; `--exclude` or `--passwords` for accounts the team must keep or set by hand.
   Then `LX-21` accounts: lock the ones red team made, take admin away, remove planted SSH keys.
4. `LX-22` SSH keys and settings. Keep a second session open.
5. `LX-39` safe fixes.
6. `LX-25` firewall, last, and confirm it from a new session.
7. Leave running: `LX-40 --batch --loop 60` (change watch) and `SV-26 --protected p.csv --apply --batch --loop 60` (banning).

### Network devices: firewalls, routers, switches (run from the admin workstation)

Works with Cisco IOS and ASA, Palo Alto, FortiGate, VyOS, pfSense, OPNsense and MikroTik. List the devices in the host list (`config/hosts.csv`) or name one with `--device NAME,ADDRESS,VENDOR`.

1. `NW-01` config backup. Saves every device's running config before anything changes. Run it again later to see what changed.
2. `NW-07` config audit. Reads the saved configs and flags telnet, default SNMP communities, weak passwords, open management and any-to-any rules. Touches no device.
3. `NW-10` device passwords. Try it on ONE device first (`--device`), then the rest. Use `--passwords FILE` for devices that need a chosen password; put devices or accounts it must not touch on the protected list.
4. `NW-01` again, so the password change becomes the new saved copy.
5. `SH-03` network scan with `--hosts`, to check every scored service still answers.

### Windows

Run in an elevated PowerShell window: `powershell -NoProfile -ExecutionPolicy Bypass -File <script> -Out C:\ccdc-out`. More scripts are being added in this order.

1. `SH-06` enum. Read the HIGH flags first.
2. `WN-35` backup, with `-CopyTo` a share off the box. Before anything changes.
3. `WN-20` passwords. Dry run first; `-Exclude` the accounts the team keeps; scoring accounts on the protected list.
4. `WN-43` safe fixes. `-Undo latest -Apply` puts the run back if anything breaks.
5. `WN-25` firewall, last, with `-AdminFrom` your team's addresses. Confirm with `keep-firewall.ps1` from a new session, or it rolls back by itself.

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
sudo sh roles/linux/SH-05-linux-enum.sh --out /root/ccdc-out --profile card

# try the template scripts (dry run; writes only to the folder you name)
sh templates/script-template.sh --out /tmp/ccdc-out --debug
powershell -NoProfile -ExecutionPolicy Bypass -File templates\script-template.ps1 -Out C:\ccdc-out -DebugLog
```

To add a script: copy a template into the right `roles/` folder, rename it to its catalog ID, fill in the header, write a test, set its `status` and `path` in `docs/catalog.csv`, run `sh tools/update-docs.sh`, and add its section to the manual. `docs/CONVENTIONS.md` has the details.

## What has and hasn't been tested

| | Tested | Not tested |
| --- | --- | --- |
| `lib.sh` | dash, bash, busybox sh, ksh93, mksh, yash on Linux; shellcheck clean | FreeBSD, Solaris, and old Linux releases |
| `lib.ps1` | Windows PowerShell 5.1 on real Windows (build 26100); PowerShell 7.4 on Linux; a pattern check for post-2.0 features | PowerShell 2.0 and 4.0 (Server 2008 R2, 2012) |
| Network scan (SH-03) | All four engines (nmap 7.94, python, bash, nc) against test listeners on 127.0.0.1, under six shells | A real competition network; the udp and full profiles at scale |
| Scan diff (SH-04) | Real SH-03 and SH-05 runs before and after planting a user, a cron entry and listeners, plus hand-made run folders, under six shells | Runs taken on a real competition network |
| Linux enum (SH-05) | Ubuntu 24.04 as root and as an unprivileged user, under the same six shells; a planted SUID binary is flagged | RHEL, SUSE, Alpine, FreeBSD, Solaris |
| Web and database enum (SV-01) | Ubuntu 24.04 with Apache, nginx, PHP 8.3, MariaDB 10.11 and PostgreSQL 16 with planted problems, as root and as a normal user, under six shells and three awk versions | RHEL (httpd), FreeBSD, MySQL 8, IIS and MSSQL (Windows twin SV-03 not built yet) |
| Backup (LX-31) | Ubuntu 24.04 as root and as a normal user, under six shells; a file restored from the archive matches byte for byte; the hash list catches a later change; copy with scp | RHEL, Alpine, FreeBSD; copying to a real remote host |
| Linux safe fixes (LX-39) | A fake root with planted problems and a stand-in sysctl, under six shells: dry run, apply, full undo, protected list, second run. Live apply on Ubuntu 24.04 with Apache, nginx, MariaDB and PostgreSQL still answering afterwards; rsyslog started through its init script | systemd and OpenRC service starts; RHEL, Alpine; a real IPv6 network |
| Linux password rotation (LX-20) | Stand-in tools on a fake root under six shells: rotation, protected skip, locking, hidden-hash fix, no password leaks, full undo. Live with the real chpasswd and usermod: new passwords verify, old ones fail, the unlisted account is locked and expired | FreeBSD (pw), RHEL, Alpine; PAM password-quality rules |
| Account lockdown (LX-21) | Fake root with planted accounts under seven shells and three awks (each finding, batch defaults, typed answers, undo); live: a real account locked with usermod and put back exactly | LDAP / AD accounts (not seen) |
| Mail tamper check (SV-31) | Fake root with planted backdoors under seven shells and three awks (each found at its level, stock services not flagged, defaults, typed answers, undo); live Postfix 3.8: five backdoors removed, SMTP/IMAP still answering, undo put them back | Exim, Sendmail, SQL/LDAP maps |
| Webmail (Roundcube) hardening (SV-41) | Fake root (a tarball and a packaged install) under seven shells and three awks; live roundcube-core 1.6.6 behind Apache: five planted problems fixed, installer and SQL went to 403, login page stayed up, undo restored | nginx (lines written to a file) |
| SSH hardening and key cleanup (LX-22) | Fake root and stand-in sshd under six shells (dry run, apply, protected keys, rejected config, undo, second run). Live with OpenSSH 9.6: the team key still logs in, planted keys are refused, password login still works, sshd reloaded and kept listening | systemd and OpenRC reloads; RHEL, Alpine; the restore-after-failed-reload path on a real box |
| Linux firewall builder (LX-25) | Stand-in nft, iptables and ss under six shells (port choice, rejected ruleset, rollback timer, confirm, remove). Live with nftables and iptables: from a separate network namespace, allowed ports answer and others are dropped; the timer removes the rules when nobody confirms | RHEL (firewalld present), Alpine; --save on a real reboot |
| Linux change watch (LX-40) | Fake root with stand-in ss, systemctl and /proc under seven shells and three awks: one planted change per section reported once with the right severity and words; a reverse shell, an unknown outgoing connection, updates, the team address and a new SSH address each handled; quiet second check, --accept, new web folder, questions on a terminal, no hash stored. Live in a network namespace: a listener and two outgoing connections caught with their processes | RHEL, Alpine; long runs |
| Brute-force and spam banning (SV-26) | Sample logs for every service, stand-in firewalls, seven shells and three awks: limits, never-ban reasons, web limit, spam, counted once, rotation, dry loop, --services, --list/--unban/--unban-all, questions on a terminal, log injection. Live with real nftables in a network namespace: ban, list, unban-all | RHEL (firewalld) |
| Database backup (SV-14) | Under six shells with MariaDB 10.11 and PostgreSQL 16: a table dropped after the backup came back with its rows, using the restore commands from RESTORE.txt | MySQL 8, RHEL, very large databases |
| Site backup and restore (SV-15) | Seven shells, three awks: deface, delete, plant a web shell, wipe the folder; check finds each, restore fixes each, undo brings it back; real MariaDB database restored and reverted | RHEL, PostgreSQL apps |
| Web shell hunter (SV-16) | Planted shells in a WordPress-style site under seven shells and three awks (each type found at the right level, quarantine, undo, questions, watch + auto-quarantine); live Apache: a needed file found by one-at-a-time retry, the store stayed up | Real plugins at scale (false positives) |
| Database hardening (SV-20) | Real MariaDB under seven shells and three awks: every fix applied, app password works, nothing leaked, undo restores all; live with a PHP page logging in like the store | MySQL 8, RHEL |
| PHP and web app hardening (SV-21) | Fake root under seven shells and three awks: every fix, second run clean, undo restores every file and owner; live Apache + PHP 8.3: web shell in uploads 403, xmlrpc/.git/.sql 403, red admin demoted, a broken page put back automatically | nginx (report only), RHEL |
| Database password rotation (SV-42) | Real MariaDB 10.11 and PostgreSQL 16 under seven shells and three awks: app account rotated with config, empty password, typed answer lock, nothing leaked, undo restores all; live: a hard-coded password page broke and everything was put back | MySQL 8, RHEL |
| Mail password rotation (SV-40) | Fake root with stand-in tools under seven shells and three awks (system, passwd-file, master/static flags, lock, undo); live Dovecot 2.3 with pam and passwd-file: new passwords log in over IMAP, old ones do not, a failed login put back, undo restores all | Dovecot SQL/LDAP (listed only), RHEL |
| Splunk hardening and passwords (SV-44) | A stand-in Splunk (real file layout, REST answers) under seven shells and three awks: every finding, every fix, typed password, undo, a failed search put back | **A real Splunk** |
| Service recovery (SV-50) | Real Apache under seven shells and three awks: stopped, DROP rule on 80, a program holding 80, broken config (not started), watch with auto-restart; live on a box where every service was down: all eight found and brought back | systemd (container has SysV init), Splunk, RHEL |
| Network config backup and diff (NW-01) | Against a real OpenSSH server (Linux profile: an added firewall rule shows as HIGH, its removal too); every vendor against sample output from a stand-in ssh under six shells, including unreachable devices, changed host keys, old-algorithm devices and password handling | Real Cisco, Palo Alto, FortiGate, VyOS, pfSense and MikroTik devices |
| Network config audit (NW-07) | A planted-problem and a clean sample config for each of seven vendors under six shells and three awk versions: every planted weakness found, no HIGH or MED on the clean configs, secrets masked | Configs from real devices |
| Device password rotation (NW-10) | Live against a real OpenSSH server (new password logs in, old one refused, nothing leaked). Every vendor, the Cisco privilege level, the Palo Alto hash, the enable secret and the automatic revert against a stand-in device under six shells | Real Cisco, Palo Alto, FortiGate, VyOS and MikroTik devices |
| Windows enum (SH-06) | Four live runs on Windows 11 with Windows PowerShell 5.1, elevated and not (all sections in about 9 seconds); replayed data under PowerShell 7: a domain controller with about 70 planted problems (all found) and a clean workstation | A real server or domain controller |
| Windows backup (WN-35) | Windows 11 with Windows PowerShell 5.1, elevated: all eight workstation items saved in 6 seconds. PowerShell 7 on Linux with stand-in programs and a fake DC with IIS, DNS and DHCP: every item, RESTORE.txt, hashes, size limit, copy off the box, failures | A real server: IIS, DNS, DHCP, GPO and AD items |
| Windows password rotation (WN-20) | PowerShell 7 against stand-in accounts: typo stop, exclusions, password sheet (spaces, commas, disabled and missing names), service and SPN accounts, protected list, rejected password, domain mode, killed mid-change | Real Windows (test on a throwaway VM) |
| Windows safe fixes (WN-43) | PowerShell 7 against stand-in state of a badly configured DC: every fix, a second run changing nothing, `-Undo` restoring the exact starting state (twice: safe fixes and the `-Include` ones), protected items, failures, a fix that does not stick, a key that cannot be backed up | Real Windows (test on a throwaway VM) |
| Windows firewall (WN-25) | PowerShell 7 against stand-in firewall state: the plan, apply, the rollback firing (state back exactly), keep, `-Undo`, `-Remove`, `-Strict` on a DC, a failed export changing nothing, two changes at once refused, a second run adding no duplicates, a leftover rollback task | Real Windows (test on a throwaway VM) |

The Windows library passes its tests on Windows PowerShell 5.1. It is written to PowerShell 2.0 rules, but has not yet run on 2.0 or 4.0.

## Documents

- [`docs/MANUAL.md`](docs/MANUAL.md): how to use what is built, what to watch for, problems and fixes
- [`docs/CONVENTIONS.md`](docs/CONVENTIONS.md): rules for writing a script
- [`docs/STATUS.md`](docs/STATUS.md): what is built
- [`docs/CHANGELOG.md`](docs/CHANGELOG.md): what changed, and when
- [`docs/PLAN.md`](docs/PLAN.md): the plan, tiers and lockout rule
- [`docs/ENVIRONMENT.md`](docs/ENVIRONMENT.md): scored services
- [`AGENTS.md`](AGENTS.md): rules for changing the repo
- [`docs/catalog.csv`](docs/catalog.csv): the script list
