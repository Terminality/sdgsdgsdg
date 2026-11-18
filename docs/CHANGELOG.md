# Changelog

What changed, newest first. Each entry names the scripts touched and how they were tested. Library versions follow `CC_LIB_VERSION` in `lib/lib.sh` and `$script:CcLibVersion` in `lib/lib.ps1`, which are always the same.

## 2026-11-18: Brute-force banning rebuilt (SV-26 v2)

- Questions: failure limit, web limit, ban length, services to watch, never-ban addresses (team and scoring engine), seconds between checks. Flags answer each; `--batch` does one check; answers saved as next defaults.
- New look: 4 sections (setup; logs, firewall and never-ban list with reasons; checks; summary), colours, `[!] BANNED` / `[*] WOULD BAN` / `[*] NOT BANNED` with the reason / `[*] SPAM?` / `[-] watching`, accounts tried under each ban.
- New: `--services` (ssh ftp mail web pam), `--team` (same as `--ignore`), `--unban-all`, `--list` shows why each address was banned; warns when no team or scoring address was given.
- Run folder `banning-N/` with output.txt, bans.txt, offenders.txt, summary.txt and CSVs; history stays in `ban-<host>/`.
- A dry loop now reads each line once (its counts live in the run folder, the real state is untouched).
- Tested: 66 checks under seven shells and three awks (sample logs, stand-in firewalls, questions on a terminal); live in a network namespace with real nftables: ban, list, unban-all.

## 2026-11-17: Linux change watch rebuilt (LX-40 v2)

- New look: sections, colours, `[!] [*] [-]` markers, two lines per alert (what changed, then what it means), summary at the end (also on Ctrl-C).
- Questions: keep or retake the baseline, how often to check, watch connections, team addresses, extra web folders, SUID scan. Flags answer each; `--batch` does one check. Answers are saved as the next defaults.
- New: **connections**. New outgoing connections with the program, user and command line behind them (a shell, interpreter or /tmp program calling out is HIGH: reverse shell), new addresses on SSH/RDP/database/SMB ports. Team addresses, loopback and web visitors are never alerted; each connection is reported once.
- New: **running services**. A service stopping is MED ("if it is scored, it is down"); auditd, rsyslog, splunk, wazuh and similar stopping is HIGH.
- New listeners show their pid, user and command line; a shell or /tmp program listening is HIGH.
- Plainer alerts: says who was added to sudo, flags an empty password, a service account given a shell, what each config file controls.
- Each run gets `changewatch-N/` with output.txt, alerts.txt, connections.txt, summary.txt and CSVs; the baseline stays in `watch-<host>/`. A web folder added later joins the baseline quietly.
- Tested: fake root with stand-in ss/systemctl/proc, 74 checks under seven shells and three awks; live in a network namespace (a listener and two outgoing connections caught with their processes).

## 2026-11-17: Persistence sweep (LX-42) and SSH hardening rebuilt (LX-22 v2)

**LX-42 persistence sweep (new)**
- Asks: full scan or which areas, extra folders, how far back is "recent", package check, accounts to leave out.
- 13 areas: cron and at; systemd units, overrides, user units, generators; rc.local, init.d and hook folders (motd, network, DHCP, sleep), udev, apt hooks, logrotate, inetd/xinetd, autostart; every authorized_keys and sshd key settings; shell startup files (reverse shells, `alias sudo`, LD_PRELOAD, PATH, history hiding); ld.so.preload and LD_PRELOAD in services and processes; extra UID 0, service accounts that can log in, sudoers; pam_exec/pam_permit and unpackaged PAM modules; boot modules, modules with no file, modprobe and core_pattern hooks; planted and hidden files, shadowed commands, unpackaged or modified system programs, SUID/caps; deleted or fake-kernel processes and connected shells; web shells; mail hooks and polkit.
- HIGH/MED/LOW with plain explanations. "Not from a package" is checked against the package database.
- With --apply: asks about each finding; files go to quarantine, lines are removed after a backup, units stopped first, SUID taken off; revert timer and revert.sh.
- Tested: a fake root with 60+ planted examples next to clean look-alikes (all found, none of the clean ones), a clean root (no HIGH or MED), removal and undo, seven shells and three awks. Live on a container it found a planted web shell and nothing false among the system programs after tuning.

**LX-22 SSH hardening v2**
- Five sections in the new look: SSH now, every key (numbered, fingerprint, why it looks planted), questions, the plan (before -> after), apply.
- Asks keep or remove for each key (planted-looking keys default to remove), and on or off for each setting with the current value and what it does; settings already right are not asked. New settings: client-alive, LogLevel VERBOSE, modern crypto (opt-in), password logins off (opt-in).
- Revert timer with confirm from a new session; a revert reloads sshd. Numbered folders, output.txt, keys.txt, settings.txt.
- Tested: 84 checks under seven shells and three awks; the generated config with every option passes the real OpenSSH 9.6 `sshd -t`; a real sshd with it lets the kept key in and refuses the removed key and passwords.

## 2026-11-16: Linux firewall rebuilt around the open ports (LX-25 v2)

- Lists every listening port with the program, pid, account and full command line behind it (so the script behind `python3` shows), where it is bound (all addresses or this box only), what the port normally is in plain words, and whether it was a scored service in past competitions (docs/ENVIRONMENT.md) or is on the protected list.
- Asks keep or drop for each port, with a default: scored and normal services keep, unknown keep but marked CHECK, rarely-needed services drop, backdoor-style ports and programs running from /tmp, /dev/shm or a deleted file drop. `--keep` and `--drop` answer in advance.
- Also asks: team addresses, ports to open that are not listening now, SSH from the team only, limit outgoing, block IPv6, and "load these rules now?".
- New look: five sections, colours, `firewall-N` folders, `output.txt`, `ports.txt`, CSV in `csv/`. Says if ufw or firewalld is also running.
- Unchanged underneath: own table/chains only, `nft -c` check, the rollback timer confirmed from a new session, `--save`, `--remove`.
- Tested with stand-ins under seven shells and three awks (71 checks), and live in a separate network namespace: rules load, a 4444 listener is dropped, the timer removes the rules when nobody confirms.

## 2026-11-16: Review of the recent scripts: bugs fixed, gaps filled

**LX-41 session & command logging**
- Bug: with auditd on, the script logged its own helper commands, and each one it processed started more. It now runs from its state folder and skips audit events with that working folder, and each pass is a fixed handful of awk runs however many log lines arrived (a brute force or a scanner no longer makes it fall behind).
- Bug: the user of a command was read from `auid=` instead of `uid=`. Both are read now: the login account is who did it, `bob as root` is bob after sudo/su, and root commands from a non-admin's session alert.
- Bug: `--setup-auditd` armed a revert timer that nothing ever answered, so the rule was removed after two minutes, and no undo line was written. No timer now; undo lines are written; it offers to keep the rule after a reboot.
- Bug: `sudo` lines with a pid (`sudo[123]:`, journald) were not read; a denied sudo was logged as a command that ran; failed logins were counted twice; alert counts in the pass line missed brute-force alerts.
- New: repeats held back (`--repeat-after`), daemons logged but not alerted, a login that succeeds after many failures, slow brute force across checks, new accounts / added to sudo / password changes, su to root by a non-admin, refused web probes counted per address, URL-decoded request matching, log-wiped check. Logs keep each event's own time.

**SV-30 service hardening**
- Bug: FTP config changes never took effect on a live box (vsftpd reads its config at start). It now restarts the daemon after changes, checks it is running and listening, and puts the config back if not; a revert restarts it too.
- Bug: with two files changed in one run, the second edit of a file overwrote its backup with the already-changed copy, so revert did not restore the original.
- Bug: editing vsftpd.conf reset its mode to 644 (undoing `ftp-perms`); an existing `/etc/ftpusers` that was added to was reported as FAILED; `--force-scored` did nothing for services; `*.socket` units were never found.
- New: asks the level when `--level` is not given; `ftp-logging`; pure-ftpd anonymous off; proftpd `<Anonymous>` block detection; `/etc/vsftpd/ftpusers` on RHEL.

**SH-03 network scan**
- Bug: UDP ports nmap marks `open|filtered` (no answer) were listed and flagged as open.
- Test bug: under ksh the fake nmap stayed on PATH for the real-nmap test (the "flaky" ksh failure in the full run).

## 2026-11-15: Service hardening, graded by risk (SV-30)

- New script: hardens FTP first (anonymous off, deny root/system accounts, lock the config perms, chroot users), then telnet, rsh/rlogin/rexec, TFTP, SNMP and the old inetd services.
- Every action is tagged **safe / service / access**, and `--level` decides how far it goes: safe (no user-visible change), service (apply, then check the service still answers and auto-undo if it broke), access (disable a daemon, under the revert timer and skipped for a scored service).
- Dry run by default, sqlmap-style questions per action with the risk shown, `--apply` to act, `--only`/`--skip`/`--exclude`, `--force-scored`. vsftpd config is edited in full; proftpd/pure-ftpd are detected and the change reported. Same look, undo and revert timer as LX-39.
- Tested under six shells against a fake root with vsftpd/proftpd configs: detection, the safe FTP fixes, idempotence, the level gate (chroot only at service level), `--exclude`, an access action via `--only`, and the protected-list requirement.

## 2026-11-15: LX-41 web-shell and process-origin detection

- A command run by a web-server account (`www-data`, `apache`, `nginx`, ...) is now always HIGH: that is the web shell executing. `--web-user` adds accounts.
- A process whose folder or program is in `/tmp`, `/var/tmp`, `/dev/shm`, a web root, or is a deleted binary is flagged HIGH ("where it runs from").
- New web section: reads apache/nginx access logs (auto-found, or `--access-log`) into `web.log` and alerts on requests to a known web-shell filename, requests with command-injection markers (`cmd=`, `shell_exec`, `base64_decode`, `;id`, `/bin/sh`, ...), and requests to a script that was dropped into a web root after watching began (`--webroot` maps the URL to the file). Still read-only.
- Tested under six shells: web-user command, process origin, injection request, known shell name, dropped-shell request, and that plain requests are only logged.

## 2026-11-15: Linux session & command logging (LX-41)

- New read-only monitor: reads the auth log and, when auditd is recording execve, the audit log. Logs every login (with source address and key vs password), failed and brute-force attempts, sudo/su and the command each sudo ran, and every command, to `logins.log`, `priv.log` and `commands.log` in a stable `sesslog-<host>/` folder. Privileged commands are captured even without auditd.
- Console alerts in LX-40's format, with `--loop`, `--count` and `--alert-cmd`. An **admin allowlist** (auto-detected sudo/wheel members plus whoever runs it, extendable with `--admin`) keeps your own team's logins and commands quiet unless the command itself is dangerous (reverse shell, `curl|sh`, `base64 -d|sh`, `nc -e`, wiping history, adding a user). Non-admin or unknown users alert; `--all-commands`/`--alert-own` make everything show.
- Stays read-only by default. `--setup-auditd` opts in to adding the one execve audit rule (reversible, revert timer) so every command is captured; otherwise it prints the rule.
- auditd execve records are reconstructed per event id, with hex-encoded arguments decoded. Incremental re-reads (a byte/line cursor per source, rotation-aware) so each pass reports only what is new.
- Tested under dash, bash, ksh, mksh, yash and busybox sh on fixture auth and audit logs: login/sudo/command parsing, hex decoding, the allowlist, brute-force detection, incremental re-reads, and that no shadow hash is ever written.

## 2026-11-14: Network scan checks for nmap

- SH-03 says up front whether nmap is installed. If not, it explains what you lose, prints the install command for this box and asks whether to keep going with the fallback. `--engine nmap` without nmap stops with the install command.

## 2026-11-14: Network scan: more questions

- SH-03 also asks how aggressive (nmap timing 1-5, `--speed`), how many top ports (`--top-ports`), extra ports to always scan (`--extra-ports`), which hosts get the full scan (asked after the quick scan, `--full-hosts`), and whether to run only safe vuln scripts or all of them (`--vuln-all`).
- The target question says it takes one host, a range or a subnet.

## 2026-11-14: Network scan asks questions, scans in stages, flags vulns

- SH-03 asks like sqlmap: what to scan (defaults to your own network), quick top-1000 scan, full all-port scan, versions, default scripts, vuln scripts (safe ones only), OS and UDP (root). Each has a flag; `--batch` takes the defaults; `--profile` still works as a preset.
- Runs nmap in stages (quick, full on the hosts that are up, details on just the open ports, UDP) and shows nmap's own output live, coloured. Service fingerprint dumps are cut from the screen.
- New `vulns.txt`: VULNERABLE script results, known CVEs per version with the worst score, anonymous FTP, empty DB passwords, SMB signing off. These are flagged, plus a port that answers like a shell.
- Looks like the enum: numbered `netscan-N` folders, `output.txt`, readable `.txt` tables, CSV in `csv/`, coloured summary of ports per host and vulns.
- SH-04 finds `netscan-N` runs and flags new vulns between two scans.
- Tested with a stand-in nmap (stages, merge, vuln parsing, questions in a terminal, SH-04) and real nmap and python on 127.0.0.1, under dash, bash, ksh, mksh, yash and busybox sh.

## 2026-11-14: Linux password rotation asks about every account

- LX-20 shows every account in a table (UID, shell, password state, last login, default action) with hidden accounts in red: a second UID 0, an empty password, a hash in /etc/passwd, a system account that can log in, an account in only one of passwd/shadow; domain/LDAP accounts in a note.
- Then per account: `[r]`andom, `[s]`et (typed twice, hidden, never logged), `[d]`isable (locked and expired, stops SSH keys), `[k]`eep, `[a]`ll the rest. The current account and protected accounts need an extra yes, which counts for that account only. It asks whether to end the sessions of disabled accounts.
- Plan, `Apply?`, then a 5-minute revert timer (`--timer`, `--no-timer`) restores /etc/shadow and /etc/passwd unless kept; an undone run renames passwords.csv to passwords-UNDONE-not-valid.csv.
- Extra UID 0 accounts are disabled by default. Numbered `passwords-N` folders, `output.txt`, `accounts.txt`. Flags and `--batch` work as before.

## 2026-11-14: Linux backup asks questions

- LX-31 asks like sqlmap: which box (offers Splunk's config, the mail folders ...), web roots (listed with sizes), home dotfiles and keys, hashing system programs, and typed answers for extra paths, paths to leave out (new `--skip`) and where to copy it. Over `--max-mb` it asks instead of stopping.
- LX-31 looks like the enum: sections as it goes, colours, numbered `backup-N` folders, `output.txt`, `included.txt`.
- A folder holding a left-out path is split into its parts, so leaving something out works with every tar, busybox's included.
- Revert timer (library): under yash, a script run inside `$( )` or a pipe waited for the timer before finishing (yash kept a copy of the output pipe); the background job is now started from a redirected subshell.

## 2026-11-14: dist/ committed; shell and line-ending fixes

- `dist/` was left out by an old `.gitignore` line; it is committed now, with a test that fails if it is ignored again.
- LX-39 `uid0`/`emptypw` and SH-05's facts table: `${x%%|*}` is a pattern operator in ksh and mksh, so accounts were expired but not locked, and facts.csv lost its keys under those shells. The `|` is quoted now; SH-05's test checks the facts keys.
- WN-35's test built its stand-in programs from CRLF text after a fresh checkout and failed on Linux; carriage returns are stripped.

## 2026-11-14: Single-file scripts (build step)

- `tools/build.sh` (LB-03): copies every script into `dist/<role>/` with the library pasted in, so you copy one file and run it. Writes `dist/MANIFEST.sha256`; a built script checks itself against it when the manifest is next to it. `--check` reports whether `dist/` is out of date.
- `dist/` is committed and kept byte-exact (`.gitattributes`: no line-ending conversion; LF for `.sh`, CRLF for `.ps1`).
- `tests/build.test.sh`: `dist/` up to date, every built script runs with no `lib/`, a changed copy is refused, line endings, and a built PowerShell script runs alone.
- Rule added to `AGENTS.md`: rebuild `dist/` after changing `roles/` or `lib/`.

## 2026-11-14: Linux safe fixes: leave-alone lists, account and SUID fixes

- LX-39 asks "Leave any alone?" after each fix that acts on named items (accounts, paths, kernel settings, services), or takes `--exclude a,b`.
- New LX-39 fixes: `uid0` (lock and expire extra UID 0 accounts), `emptypw` (lock empty-password accounts), `suid` (remove SUID from GTFOBins programs and from files in /tmp, /home ...). The account questions list what was found first. Passwords are never logged; undo only removes the `!`.
- More kernel settings in `sysctl`: unprivileged BPF off, protected FIFOs and regular files, RFC 1337.
- Fixed: shellcheck warning in the new library code; the timer tests failed under the slow yash shell; the LX-39 test's mode helper ignored the SUID bit.

## 2026-11-14: Linux safe fixes asks questions and reverts on its own

- LX-39 asks like sqlmap: which box (splunk / webmail / ecomm / other), then one question per fix; Enter takes the default; flags answer in advance; `--batch` takes every default.
- LX-39 shows a dry-run plan, asks `Apply these N change(s)?`, applies, then asks `Keep these changes?`. A 2-minute revert timer starts with the script (`--timer`, `--no-timer`): unless kept, everything the run changed is undone by a systemd timer or detached job, so it still happens if the session dies. `revert.sh --force` undoes a run later.
- LX-39 looks like the enum: linpeas-style sections and colours, numbered `safe-fixes-N` folders, `output.txt`, readable `plan.txt` and `fixes.txt`. A file is no longer listed twice in one plan.
- lib.sh: `--batch`, `cc_ask`, `cc_ask_text`, `cc_color_init`, `cc_show`, `cc_now`, `cc_timer_start`, `cc_timer_finish`; changes are refused once the timer has run out. Tests never wait for answers (`CCDC_NO_TTY`).
- Fixed: the SH-05 privesc test failed under ksh (a test bug, not a script bug) and a lint false alarm.

## 2026-11-14: Linux enum privesc section

- SH-05 `privesc` section (in the card profile): root cron jobs, start-up scripts and root services whose files others can change; writable key files and a readable shadow file; risky PATH folders and `.` on the PATH; sudo rules for GTFOBins programs and kept LD_PRELOAD; old sudo (Baron Samedit), pkexec (PwnKit) and kernels (Dirty COW, Dirty Pipe), checked against the package changelog or kernel build date to avoid false alarms.

## 2026-11-14: Linux enum output

- SH-05 prints like linpeas: a header per section as it runs, red `[!] FIX` for HIGH, yellow `[*] LOOK` for MED, green key facts. `--low` shows LOW flags too, `--no-color` turns colours off. Same output saved to `output.txt`.
- SH-05 run folders are numbered: `linux-enum-1`, `linux-enum-2`, ... `run.txt` keeps the ID, host and time.
- SH-04 compares the numbered folders, including against older `SH-05_...` folders.
- SH-05 and SH-04 write a readable table per file (`users.txt`, `ports.txt`, `flags.txt` HIGH first, `changes.txt` additions first); the CSV copies move to `csv/`. SH-04 results go in numbered `diff-N` folders.
- SH-05 colour-codes the end summary: red sections and fixes (HIGH), yellow (MED), green for clean sections and key facts. summary.txt stays plain.
- SH-05 saves the whole terminal output, warnings and info lines included, to `output.txt`.
- lib.sh: `cc_use_numbered_dir NAME`, `cc_csv_pretty CSV TXT`., and `CC_TEE` (copy of screen lines to a file).
- Rules: output must be human-readable in a terminal (`AGENTS.md`, `docs/CONVENTIONS.md`, `docs/PLAN.md`).

## 2026-11-14: New direction

- Added `docs/PLAN.md`, `docs/ENVIRONMENT.md`, `AGENTS.md`, `CLAUDE.md`.
- Catalog cut to 28 core scripts for Linux, Windows / AD and Network. Columns `tier` and `risk` replace `wave` and `level`.
- Collectors renamed to enum: `SH-05-linux-enum.sh`, `SH-06-windows-enum.ps1`, `SV-01-web-db-enum.sh`. Script contents unchanged.

## 2026-11-12: Windows review fixes

**Fixed**
- WN-43: removing a port forward (`portproxy`) now restarts the IP Helper service, because the forward kept listening until it restarted; `-Undo` restarts it again so a put-back forward works. Skipped (with a note) when `iphlpsvc` is on the protected list.
- WN-43 `auditing`: also sets `SCENoApplyLegacyAuditPolicy`, so an old-style audit policy from Group Policy (a DC's default policy has one) no longer overwrites the subcategory settings at the next refresh. `netsh`: the DHCP and WINS server helpers count as Windows ones.
- WN-20: a password given in `-Passwords` for an account that is then skipped (service account, protected, not in `-Users` ...) is reported, not only for disabled accounts.
- WN-35 `dhcp`: uses `Export-DhcpServer` where it exists (Server 2012 and later) so the DHCP service keeps answering; `netsh dhcp` is the fallback.

**Tested** wn43 109 -> 112, wn20 49 -> 51; all PowerShell tests, both lints and the shell suite pass.
## 2026-11-12: Windows firewall

**Added**

- WN-25 Windows firewall (`roles/windows-ad/WN-25-firewall.ps1`): default-deny inbound with the scored, protected and safe listening ports open, admin and scoring addresses allowed, AD ports on DCs; allow-all and backdoor rules turned off; export first, SYSTEM rollback task, keep script, `-Undo`, `-Remove`, `-Strict`; dropped-connection logging. A rerun removes its own rules that are no longer wanted (so a new `-Exclude` really closes the port); `-Strict` keeps Windows core networking (DHCP, IPv6 neighbour discovery); discovery UDP ports (SSDP, WS-Discovery, mDNS, LLMNR) are not opened.
- `tests/wn25.Tests.ps1` (stand-in state via `CCDC_WN25_FAKE`).
- Review fixes before merge: a rollback task left behind by a run kept from a non-elevated window no longer blocks the next run (kept runs are recognised, the leftover task removed, and a rollback that finds the run kept deletes its task); a second run no longer adds every rule again (an existing rule is kept when identical, replaced when its addresses changed; addresses compared in Windows' mask form).

**Tested**

- PowerShell 7.4 on Linux against stand-in state (89 checks). Not yet run on Windows.

## 2026-11-12: Windows safe fixes

**Added**

- WN-43 Windows safe fixes (`roles/windows-ad/WN-43-safe-fixes.ps1`): 20 safe fixes, 8 more with `-Include`, an undo plan written before every change and `-Undo` to replay it; keys are changed only after a successful backup; Defender and sfc results checked afterwards.
- `tests/wn43.Tests.ps1` (stand-in state via `CCDC_WN43_FAKE`).

**Tested**

- PowerShell 7.4 on Linux against stand-in state (109 checks), including undo back to the exact starting state. Not yet run on Windows.

## 2026-11-12: Windows password rotation

**Added**

- WN-20 Windows password rotation (`roles/windows-ad/WN-20-password-rotation.ps1`): local accounts, or domain users on a DC, through ADSI; `-Exclude`/`-Users` with the typo stop, `-Passwords` sheet, service-account and SPN detection, protected list, logon test after each change, pending file against an interrupted change.
- `tests/wn20.Tests.ps1` (stand-in accounts via `CCDC_WN20_FAKE`).

**Tested**

- PowerShell 7.4 on Linux against stand-in accounts (49 checks). Not yet run on Windows.

## 2026-11-12: Windows backup

**Added**

- WN-35 Windows backup (`roles/windows-ad/WN-35-backup.ps1`): 17 items with a restore command each, hashes, `-CopyTo`, `-MaxMB`; the AD database only with `-AdDatabase`; the AD Recycle Bin reported, not turned on.
- `tests/wn35.Tests.ps1`.

**Tested**

- PowerShell 7.4 on Linux with stand-in programs (57 checks). Not yet run on Windows.

## 2026-11-12: Windows collector

**Added**

- SH-06 Windows collector (`roles/windows-ad/SH-06-windows-collector.ps1`): 20 sections in three profiles; every source is saved under `raw\` and can be replayed with `-FromRaw`; password-like account descriptions and the Winlogon password are never copied; attack strings in the checks are split up so antivirus does not flag the file.
- `tests/sh06.Tests.ps1`.

**Changed after the first live run (Windows 11, not elevated)**

- Process owners come from one `tasklist /v` call instead of one WMI call per process (73 s down to seconds).
- Firewall rules are read from the registry, which shows what limits a rule (app package, interface, addresses); `netsh` hid those, so Store-app rules looked like allow-all.
- Per-user folders (AppData, user Temp, Downloads) are MED instead of HIGH; Users\Public, Windows\Temp, PerfLogs and the Recycle Bin stay HIGH.
- Service-install events are flagged only when the program looks suspicious.
- Second live run: process owners are read only when elevated (`Get-Process -IncludeUserName`, else `tasklist /v`); any source taking 5 s or more is named in the summary; a URL in a command line counts only beside a shell or download tool (Chromium apps pass crash-report URLs); repeated identical events are one flag with a count; "password not required" is LOW.
- Third live run (elevated, about 8 s in all): a task command line with characters such as `<`, `>` or quotes no longer stops the tasks section; startup-folder shortcuts are judged by their target; a driver registered in a temp folder is MED even when not running; Tailscale hosts entries and Windows' service virtual accounts (S-1-5-99 and similar) are no longer flagged MED.

**Tested**

- The library on real Windows PowerShell 5.1 (71 checks). SH-06 by replaying a planted-problem domain controller and a clean workstation under PowerShell 7.4 (114 checks). Not yet run live on Windows.

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
