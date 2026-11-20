<!-- Built by tools/role-manuals.sh from docs/playbooks/linux.md and docs/MANUAL.md. Edit those, then run it. -->

# Linux manual

For whoever defends the Linux boxes. Every command here uses the standalone scripts in `dist/linux/` (and two from `dist/applications/`). Each one is a single file: copy it to the box and run it with `sh`.

Flókið Linux boxes (inside `192.168.220.x`, outside `10.100.N.x`, N = team number):

| Box | Last octet | OS | Scored service |
| --- | --- | --- | --- |
| Gufu | .100 | Rocky Linux (SELinux, firewalld) | Gitea |
| Kvígindis | .44 | Ubuntu 24.04 | furniture help site |
| Skerja | .97 | Alpine 3.23 (OpenRC, busybox) | tickets |
| Thorska | .231 | Fedora 44 (SELinux, firewalld) | Home Manager |
| Haf | .67 | Lubuntu 22 | "Wabbit" (RabbitMQ?) |
| Kolla | .30 | Alpine (OpenRC, busybox) | file share |
| Djupi | ? | Linux Mint 22.3 | POS |

## How every script works

- **Dry run first.** Without `--apply` nothing changes. Run it once, read the plan, then run it again with `--apply`.
- **Questions.** Each script asks its questions one at a time: `[?] Question [Y/n]`. Enter takes the answer in capitals. Every question has a flag that answers it in advance; `--batch` takes every default with no questions.
- **The box question.** Most scripts ask "Which box is this?" and guess the answer from the files (`This box looks like: gitea (/etc/gitea/app.ini)`). Enter takes the guess. The answer keeps that box's scored ports and services safe.
- **The look.** Sections are numbered `==========[ 2/6  users ]==========`. The legend line at the top says what each mark means: `[!]` HIGH or broken, `[*]` look at it, `[ok]` fine, `[~]` would change, `[+]` changed, `[x]` failed.
- **Results.** Each run gets a numbered folder in `~/bt-out` (as root: `/root/bt-out`): `linux-enum-1`, `ssh-hardening-2`, ... with `output.txt` (the screen without colours), `summary.txt` and the tables as `.txt`. The log and the undo log sit in `~/bt-out` itself.
- **Never locked out.** Anything that can cut you off (firewall, SSH, accounts) starts a **revert timer** (120 s). Open a **new** SSH session and log in; only then answer "keep". If you can't get back in, do nothing: the timer puts everything back.
- **Undo.** Every change has an undo line. `sh ~/bt-out/<run-folder>/revert.sh --force` undoes one run.
- **The protected list.** `~/bt-out/protected.txt`: things no script may touch. Scripts that change things refuse `--apply` without it (or `--no-protected`).

## Before you start (once per box, 2 minutes)

1. Copy the kit to the box from the admin workstation:

   ```bash
   scp -r dist/linux dist/applications root@192.168.220.100:/root/kit/
   ```

   Keep each `SCRIPT.sh.sha256` next to its script: the script then checks it was not changed and refuses to run if it was.

2. Write the protected list on the box. One line each: type, value, note. At least the scored ports and the account the scoring engine logs in with:

   ```
   port      22/tcp      we log in from outside
   port      3000/tcp    scored Gitea
   service   gitea       scored
   account   git         Gitea's git user
   ```

   Save it as `/root/bt-out/protected.txt`. `config/protected.example.txt` has more examples.

3. Find your team number (for the `10.100.N.x` addresses): the network person's SH-03 run asks for it.

## The first 15 minutes (each Linux box)

Do these in order. Times are for one box.

| When | Script | What it does | Command |
| --- | --- | --- | --- |
| 0-2 min | **SH-05** Linux enum | A picture of the box: who can log in, what listens, what starts on boot, who can become root, SELinux. Changes nothing | `sh SH-05-linux-enum.sh --profile card` |
| 2-4 min | **LX-31** Backup | One archive of every config that matters, with hashes, before anything changes | `sh LX-31-backup.sh --batch` |
| 4-6 min | **LX-20** Passwords | New passwords for every account that can log in; locks the ones not on your team list | `sh LX-20-password-rotation.sh` |
| 6-8 min | **LX-22** SSH | Root login, keys, settings. Password logins stay on unless you say otherwise; the Gitea keys are kept | `sh LX-22-ssh-hardening.sh --apply` |
| 8-11 min | **LX-25** Firewall | Only the ports this box needs. SSH and the scored ports stay open; the revert timer runs | `sh LX-25-firewall.sh --apply` |
| 11-13 min | **LX-21** Accounts | Extra root accounts, sudo rights, empty passwords, accounts made recently | `sh LX-21-account-lockdown.sh --apply` |
| 13-15 min | **LX-26** Remote access | Everything but SSH that lets someone in: VNC, xrdp, telnet, tunnels, remote-desktop tools | `sh LX-26-remote-access.sh --apply` |

What to look at after each one:

- **SH-05:** the `SUMMARY` at the end. Every `[!] HIGH` is something to deal with now: an extra UID 0 account, a key in root's `authorized_keys` you don't know, a cron line that downloads and runs something, SELinux switched off. Each flag says what to do.
- **LX-31:** the last lines give the archive and the copy command. Copy it off the box (`--copy-to user@admin-box:/path/`) when you can.
- **LX-20:** the new passwords are in `passwords.txt` in its run folder (mode 600, only there). Give the team the ones they need. The scoring account must be on the protected list, or its password changes and the service goes red.
- **LX-22 and LX-25:** when the timer starts, **open a new SSH session from outside** and log in before you answer "keep".

## After the first 15 minutes

Run these next, roughly in this order, then keep the watchers running:

| Script | What it does | When | Command |
| --- | --- | --- | --- |
| **LX-42** Persistence sweep | Every place a backdoor can hide: cron, systemd, rc files, shell profiles, SSH keys, PAM, LD_PRELOAD, udev, motd, setuid files. Asks what to remove | Right after the first 15 min | `sh LX-42-persistence-sweep.sh --apply` |
| **LX-45** Rootkit and malware scan | Hidden processes and ports, miners, fake kernel threads, programs in `/dev/shm`, ClamAV over the web root and the shares | After LX-42 | `sh LX-45-rootkit-scan.sh --apply` |
| **LX-39** Safe fixes | Small fixes that cannot break a service: kernel settings, file permissions, core dumps | Any time | `sh LX-39-safe-fixes.sh --apply` |
| **SV-26** Banning | Blocks addresses that keep failing logins; never your team, the scoring engine or the router | Once logins are under control | `sh SV-26-banning.sh --apply --loop 60` |
| **LX-40** Change watch | Alerts the moment something changes: new account, key, cron line, listening port, outgoing connection | Leave it running | `nohup sh LX-40-change-watch.sh --batch --loop 60 &` |
| **LX-41** Session log | Who logs in and what they run | Leave it running | `nohup sh LX-41-session-log.sh --loop 30 &` |
| **LX-43** Log shipping | Sends logs to the Splunk box (if there is one) | When a log box exists | `sh LX-43-log-shipping.sh --send --to ADDRESS --apply` |
| **LX-44** AppArmor / SELinux | Ubuntu, Mint, Lubuntu: AppArmor profiles. Rocky, Fedora: shows SELinux and how to turn it on | When things are calm | `sh LX-44-apparmor.sh` |
| **LX-46** Safe updates | Security updates only, one package at a time, with the service checked after each | When things are calm | `sh LX-46-safe-updates.sh --apply` |
| **SH-05** again | A second full picture; compare with the first | Every hour or so | `sh SH-05-linux-enum.sh`, then `sh SH-04-scan-diff.sh --type sh05` |

### When something happens

| What you see | Run |
| --- | --- |
| A scored service went red | `sh SV-50-service-recovery.sh --apply` (in `dist/applications/`): says why it is down and offers the fix |
| You think red team is on the box | `sh SH-05-linux-enum.sh --profile triage` (copies the logs too), then LX-42 and LX-45 |
| A strange account or SSH key | LX-21, then LX-22 |
| Someone keeps guessing passwords | SV-26 |
| A new listening port or outgoing connection | LX-40's alert names the program; LX-26 if it is a remote-access tool |
| SELinux denies a scored service (Gufu, Thorska) | SV-50 names the denial and the fix (`restorecon`), never "turn SELinux off" |
| You locked something you need | `sh ~/bt-out/<run-folder>/revert.sh --force` |
| The scoring engine got banned | `sh SV-26-banning.sh --apply --unban-all` |

### Notes for this network

- **Alpine (Skerja, Kolla):** busybox, OpenRC (`rc-service`, `rc-update`), no `ss` (the scripts use `netstat`), `apk`. Every script here works on it.
- **Rocky and Fedora (Gufu, Thorska):** firewalld (LX-25 opens the kept ports there too), SELinux (SH-05 checks it; files put back by an undo get their label back).
- **Gufu (Gitea):** LX-22 keeps the Gitea users' SSH keys and the `git` account; LX-25 keeps 3000, 2222, 80, 443 open with `--box gitea` (guessed).
- **Kolla (file share):** LX-25 keeps 139, 445, 137, 138, 2049, 111 with `--box fileshare` (guessed); LX-45 scans the shared folders.
- The applications person runs the `SV-` scripts on the same boxes: agree who runs the firewall (LX-25) so it is done once.

## Deep dive: every Linux script

Each section below is the full reference for one script: how to run it, every question and its flag, what each check means, what it writes, and what to do when something goes wrong. They are in the order above.

Scripts: [SH-05](#sh-05-linux-enum-distlinuxsh-05-linux-enumsh) [LX-31](#lx-31-backup-distlinuxlx-31-backupsh) [LX-20](#lx-20-linux-password-rotation-distlinuxlx-20-password-rotationsh) [LX-22](#lx-22-ssh-hardening-and-key-cleanup-distlinuxlx-22-ssh-hardeningsh) [LX-25](#lx-25-linux-firewall-builder-distlinuxlx-25-firewallsh) [LX-21](#lx-21-account-lockdown-distlinuxlx-21-account-lockdownsh) [LX-26](#lx-26-remote-access-lockdown-distlinuxlx-26-remote-accesssh) [LX-42](#lx-42-linux-persistence-sweep-distlinuxlx-42-persistence-sweepsh) [LX-45](#lx-45-rootkit-and-malware-scan-distlinuxlx-45-rootkit-scansh) [LX-39](#lx-39-linux-safe-fixes-distlinuxlx-39-safe-fixessh) [SV-26](#sv-26-brute-force-and-spam-banning-distlinuxsv-26-banningsh) [LX-40](#lx-40-linux-change-watch-distlinuxlx-40-change-watchsh) [LX-41](#lx-41-linux-session--command-logging-distlinuxlx-41-session-logsh) [LX-43](#lx-43-log-shipping-to-splunk-distlinuxlx-43-log-shippingsh) [LX-44](#lx-44-apparmor-confinement-distlinuxlx-44-apparmorsh) [LX-46](#lx-46-safe-security-updates-distlinuxlx-46-safe-updatessh) 

### SH-05: Linux enum (`dist/linux/SH-05-linux-enum.sh`)

Read-only inventory of one Linux or Unix host. Run it first on every Linux box: it shows who can log in, what is listening, what starts on boot or on a schedule, who can become root, what is running, and the usual hiding places. It changes nothing.

#### How to run it

```sh
sudo sh SH-05-linux-enum.sh --out /root/bt-out              # full, about a minute
sudo sh SH-05-linux-enum.sh --out /root/bt-out --profile card   # quick look, seconds
sudo sh SH-05-linux-enum.sh --out /root/bt-out --profile triage # full plus a copy of the logs
sudo sh SH-05-linux-enum.sh --out /root/bt-out --only ports,processes
```

Run it as root. As a normal user it still works, but the summary marks several sections `partial`.

| Option | What it does |
| --- | --- |
| `--profile card` | system, users, ports, services, autostart, ssh, sudo, privesc. Use it in the first minutes |
| `--profile full` (default) | card plus processes, connections, sessions, packages, files, firewall, pam, mac, trust, creds, containers, modules |
| `--profile triage` | full plus copying the logs. Use it when you think the box is compromised, before anything else changes |
| `--only a,b` / `--skip a,b` | Pick sections. `--list` shows the names |
| `--fast` | Skip the two slow disk searches (files, creds) |
| `--max-flags N` | How many HIGH/MED flags to print in the end summary (default 30) |
| `--low` | Also show LOW flags while it runs |
| `--no-color` | No colours (they are also off when output goes to a file or pipe) |

While it runs it prints like linpeas: a header per section, then what it found. **Red `[!] FIX`** = HIGH, fix now. **Yellow `[*] LOOK`** = MED, look soon. Green = key facts. `[ok]` = nothing to fix in that section. The summary comes at the end.

#### What it produces

Each run gets a numbered folder: `<out>/linux-enum-1`, `linux-enum-2`, ... Higher number = newer run.

| File | Contents |
| --- | --- |
| `output.txt` | Everything shown while it ran, without colours |
| `<section>.txt` | Each section as a ` | ` table (`users.txt`, `ports.txt`, ...); SH-04 compares two runs from these |
| `flags.txt` | Every flag including LOW, HIGH first |
| `summary.txt` | The end summary: key facts, a row per section, the HIGH and MED flags |
| `run.txt` | Script ID, host and start time (SH-04 uses it) |
| `privesc.txt` | Ways to become root, like linpeas checks: files root runs (cron, services, start-up) that others can change, writable key files (`/etc/passwd`, sudoers, root's files), a readable shadow file, risky PATH folders or `.` on the PATH, sudo rules for shell-escape programs (vim, less, find ...) or keeping LD_PRELOAD, and old sudo, pkexec or kernel versions with known root bugs (Baron Samedit, PwnKit, Dirty COW, Dirty Pipe) unless the package changelog shows the fix |

The section tables:

| File | Contents |
| --- | --- |
| `facts.txt`, `addresses.txt` | Host name, OS, kernel, init system, uptime, IPv6 on or off, addresses, DNS |
| `users.txt` | Every account: UID, shell, whether it can log in, password state (`set`, `EMPTY`, `locked`; never the hash), groups |
| `ports.txt` | Listening ports: protocol, address, port, `any` or `local`, pid, process, user, program file |
| `services.txt` | Services with enabled and running state |
| `autostart.txt` | cron, at, timers, rc.local, and suspicious lines from startup files, motd scripts and udev rules |
| `ssh_config.txt`, `ssh_keys.txt` | Effective sshd settings; every authorized key with its account, file, fingerprint and options |
| `sudo.txt` | sudoers, doas and polkit rules |
| `processes.txt`, `connections.txt`, `sessions.txt` | Every process with its program file; live connections; who is logged in |
| `packages.txt` | Installed packages and versions |
| `suid.txt`, `capabilities.txt`, `world_writable.txt`, `immutable.txt` | Risky file permissions |
| `firewall.txt`, `pam.txt`, `mac.txt`, `trust.txt`, `modules.txt`, `containers.txt` | One per section |
| `creds.txt`, `private_keys.txt`, `history.txt` | Files holding password-like settings (file, line and setting name only), private key files, shell history sizes |
| `raw/*.txt` | Untouched tool output: `iptables-save`, `sshd -T`, `ss`, `last` and others |
| `logs/` | Triage only: copies of auth, syslog, web and audit logs, with SHA-256 in `logs.txt` |

#### Reading the summary

The screen shows one page. The section table tells you where to look:

```
section        rows  high   med   low  note
users            31     1     0     2
ports             9     1     1     0  partial: process shown only for your own sockets
```

- **rows** is how much was collected.
- **high / med / low** are the flags from that section.
- **note** says when a section is incomplete and why.

Only HIGH and MED flags are printed. LOW flags are in `flags.txt`.

| Severity | Meaning | Examples |
| --- | --- | --- |
| HIGH | Likely red team activity or an open door. Look now | Second UID-0 account, empty password, shell listening on a port, process running from a deleted file, reverse-shell cron job, SUID `find`, keys on a service account, locked `/etc/passwd`, changed `pam_unix.so` |
| MED | Risky or unusual. Look soon | Passwordless sudo, root accepts SSH keys, backdoor-style port number, no host firewall, IPv6 unfiltered |
| LOW | Worth knowing. Not shown | Extra hosts-file entries, `nullok`, locally created service files |

#### What to watch for

- **A flag is a pointer, not a verdict.** Some flags are legitimate on your box. In testing, this sandbox's own launcher was flagged HIGH because it decodes a base64 payload, which is exactly what a malicious one does. Look, then decide.
- **Run it again after you change things.** Two runs compared side by side show what changed. The scan diff and change watch will automate this later.
- **It sees what the operating system reports.** A kernel rootkit can hide processes, files and ports from every tool it uses.
- **Accounts come from `/etc/passwd`.** LDAP or FreeIPA users are not listed.
- **Passwords are never recorded.** `users.txt` shows only whether a password is set; `creds.txt` shows only the file, line and setting name.
- **Triage copies logs into the output folder.** Copy that folder off the host; a red team that owns the box can delete it.
- **Time.** About a minute for `full` on a normal server. The files and creds sections walk the disk and take most of that. Use `--fast` or `card` under time pressure.

#### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| Summary says `root: NO - partial` | Not run as root | `sudo sh ...`, and pass `--out` because `~` changes under sudo |
| `ports` note: `process unknown` | `/proc/<pid>/fd` is unreadable, even for root, in some containers | Expected there; the port list itself is complete |
| `ports` note: `no ss, netstat, sockstat or /proc/net` | Not Linux and no tools (for example Solaris) | Read `raw/netstat_an.txt` |
| `Addresses: none found` | No `ip` or `ifconfig`, and no `/proc/net/fib_trie` | Run `ip addr` or `ifconfig` by hand if either exists |
| `ssh` note: `no sshd configuration found` | SSH server not installed | Nothing to fix |
| A sudo, cron or ssh setting you know is there is missing | Not root, so the file was unreadable | Rerun as root; check the section note |
| `docker ... 'docker ps' failed` | Docker daemon stopped, or the user is not in the docker group | Rerun as root; `systemctl status docker` |
| `firewall` says NOT-filtered but you set rules | Rules exist in a tool the enum does not read, or need root | Check `raw/` for the tool's output; run as root |
| A flag looks wrong | The check is too broad for your box | Check `raw/` to see what the tool printed. Report the flag line so the check can be tightened |
| It runs for many minutes | A very large disk or network home folders | `--fast`, or `--skip files,creds` |
| `cannot find lib/lib.sh` (exit 3) | The script was copied without the `lib/` folder | Copy the whole kit, or use the built single-file version once the build step exists |
| `$'\r': command not found` | The file got Windows line endings in transit | `tr -d '\r' < SH-05-linux-enum.sh > fixed.sh` |

---


### LX-31: Backup (`dist/linux/LX-31-backup.sh`)

Run first, before any script that changes the box. One archive of the files that decide how the box behaves, a hash of every one of them, and a snapshot of the state that is not in files. If a fix breaks a scored service, you put back the one file that broke. If the red team changes something, the hash list proves which file.

#### How to run it

Just run it. It asks questions like sqlmap: Enter takes the default.

```sh
sudo sh LX-31-backup.sh                                   # asks, then backs up
sudo sh LX-31-backup.sh --batch                           # no questions, the defaults
sudo sh LX-31-backup.sh --box splunk --copy-to admin@10.0.0.5:/srv/backups/splunk/
```

The questions:

1. **Which box?** splunk / webmail / ecomm / fileshare / gitea / web / other (guessed for you). It offers that box's important folders, for example Splunk's `/opt/splunk/etc` (config, users, apps) or the mail folders on webmail. For ecomm it reminds you to run SV-14 for the database.
2. **Web roots?** It lists the ones it found, with sizes.
3. **Home-folder dotfiles and SSH keys?**
4. **Hash system programs?** Takes 10 to 60 seconds, and later shows which programs were replaced.
5. **Other files or folders to back up?** Type a comma list.
6. **Anything to leave out?** Type a comma list of paths. A folder that contains one is backed up without it.
7. **Copy it off the box?** Type `user@host:/path/`, or press Enter for no.

Then each step prints as a section: what will be backed up (each path with its size), the archive, the hash lists, the system state, the copy. If the backup is bigger than `--max-mb`, it asks before going on.

| Option | What it does |
| --- | --- |
| `--add PATH` | Also back up a file or folder (repeat). Use it for scored content outside the usual places, such as `/opt/app` |
| `--skip PATH` | Leave a file or folder out (repeat) |
| `--box NAME` | splunk, webmail, ecomm or other: answers that question |
| `--batch` | Never ask: take every default |
| `--no-color` | No colours |
| `--webroot DIR` | Back up DIR as a web root (repeat). The usual web roots and those named in the Apache and nginx configs are included already |
| `--no-webroots` | Leave web roots out, when they are huge |
| `--no-homes` | Leave out home-folder dotfiles and `.ssh` folders |
| `--fast` | Skip hashing system programs and service units (saves 10 to 60 seconds) |
| `--max-mb N` | Ask before a backup bigger than N MB (default 2048). With no one to ask, it stops |
| `--copy-to DEST` | Copy the archive and hash lists off the box with `scp` when done. Asks for a password if no key is set up |

It changes nothing on the host, so it runs without `--apply` and needs no protected list. Run it as root; as a normal user it warns and backs up what it can read.

#### What goes in

| Kind | Paths |
| --- | --- |
| config | `/etc`, `/usr/local/etc`, cron and at spools, BIND zone folders, `/root/.ssh` |
| home | Top-level dotfiles of root and every account (shell startup files), and every `.ssh` folder |
| webroot | `/var/www`, `/srv/www`, `/srv/http`, `/usr/share/nginx/html` and the others in the usual places, plus every `DocumentRoot`, `root` and `alias` folder in the Apache and nginx configs |
| added | Anything given with `--add`, typed into the question, or the box's folders you said yes to |

Paths that do not exist are skipped, so the same command works on any distribution.

Not included: databases (use SV-14, which dumps them safely while they run) and whole home folders.

#### What it produces

In a numbered folder: `<out>/backup-1`, `backup-2`, ...

| File | Contents |
| --- | --- |
| `output.txt` | Everything shown on screen, without colours |
| `included.txt` | Every path asked for, its size, and whether it was read fully |
| `backup.tar.gz` | The archive. Paths inside are relative to `/` (`etc/passwd`). Mode 600 |
| `backup.tar.gz.sha256` | Hash of the archive, to check a copy is intact |
| `files.sha256` | SHA-256 of every file in the archive |
| `system.sha256` | SHA-256 of programs in `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/usr/local/*bin`, `/usr/libexec` and of systemd unit files (hashed, not archived) |
| `contents.txt` | The archive's file list |
| `raw/` | Firewall rules (iptables, nftables, ufw, firewalld, pf), services and timers, listening ports, packages, addresses, routes, kernel settings, mounts, accounts, root's crontab |
| `RESTORE.txt` | The restore commands for this backup |
| `summary.txt` | What was saved and how big |

#### Restoring

```sh
cd /root/bt-out/backup-3
sha256sum -c backup.tar.gz.sha256                                  # the archive is intact
tar -tzf backup.tar.gz | grep sshd_config                         # find a file
cp -p /etc/ssh/sshd_config /etc/ssh/sshd_config.before-restore
tar -xzf backup.tar.gz -C / etc/ssh/sshd_config                   # put ONE file back
sha256sum -c files.sha256 2>/dev/null | grep -v ': OK$'           # what changed since the backup
sha256sum -c system.sha256 2>/dev/null | grep -v ': OK$'          # programs replaced since the backup
iptables-restore < raw/firewall_iptables.txt                       # firewall rules as they were
```

Unpack into a scratch folder (`-C /tmp/restore`) to compare with `diff -r` before putting anything back.

#### What to watch for

- **The archive holds `/etc/shadow`, SSH host keys and passwords in config files.** Keep the output folder private and copy it only to the team's own machine.
- **Copy it off the box.** A red team with root can delete a backup kept on the same host. Use `--copy-to`, or pull it from the admin workstation with the `scp` line in the summary.
- **Never restore all of `/etc` at once.** That also rolls back every password change and fix made since. Put back only what broke.
- **Run it again after you have hardened the box.** That backup is the known-good state, and its hash lists are the better baseline for the change watch.
- **A changed program in `system.sha256` is serious.** Package updates also change programs, so check the package manager's log before calling it a rootkit.

#### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `the backup would be about N MB, more than --max-mb` (exit 3) | Big web roots or a big `/etc`, and you answered no (or no one could be asked) | Look at the sizes it listed; leave big paths out (the question or `--skip`), `--no-webroots`, or a larger `--max-mb` |
| `not enough free space` (exit 3) | The output folder's disk is nearly full | `--out` on another disk or a USB stick |
| `tar exited 1` or `2` warning | A file changed or could not be read while archiving | Harmless when the summary shows entries; check the log for the file names |
| `the archive could not be read back` (exit 5) | Disk full or tar failed | Check the log; free space and run again |
| `COPY FAILED` (exit 5) | Wrong destination, no route, or the password was refused | Test with `scp somefile DEST` by hand; the backup is still on the box |
| `partial (some files unreadable)` in `included.txt` | Not root, or files the account cannot read | Run as root |

---


### LX-20: Linux password rotation (`dist/linux/LX-20-password-rotation.sh`)

New random passwords for every account that has a usable password, root included. With a team list, it also locks every human account that is not on it. The new passwords go to one private file for the captain, never to the screen or the log.

Run the backup (LX-31) first. **Put every account the scoring engine logs in with on the protected list**, or scoring breaks.

#### How to run it

Just run it. It asks like sqlmap: Enter takes the default.

```sh
sudo sh LX-20-password-rotation.sh          # asks about every account
sudo sh LX-20-password-rotation.sh --apply --batch   # defaults, no questions
sudo sh LX-20-password-rotation.sh --apply --batch --keep /root/team.txt --kick
```

What a run looks like:

1. **Revert timer: 5 minutes** (`--timer` to change it). Unless you keep the changes at the end, `/etc/shadow` and `/etc/passwd` go back: old passwords, nothing locked. It runs outside the script, so it happens even if your session died.
2. **The account table:** every account with UID, shell, password state (set, empty, locked), last login, and the default action. **Hidden accounts are in red:** a second UID 0, an empty password, a hash in `/etc/passwd`, a system account that can log in, an account in only one of `passwd`/`shadow`. System accounts with no password are summed up in one line. Domain/LDAP accounts are listed in a note.
3. **"Go through each account one by one?"** `n` takes the actions in the table. `y` asks about each one:
   - `r` random password
   - `s` set one: typed twice, not shown, never logged
   - `d` disable: locked **and** expired, so SSH keys stop working too
   - `k` keep
   - `a` the default for all the rest

   The account you're logged in as, and accounts on the protected list, need an extra yes.
4. **"End the running sessions of the accounts you disable?"** A lock doesn't end a login already in progress.
5. **The plan,** then `Apply these N change(s)?`, then each change as it's made.
6. **"Keep these changes?"** Open a **new** session and log in with the new password first. `n`, or no answer before the timer, puts everything back.

| Option | What it does |
| --- | --- |
| `--keep FILE` | The team's account list, one name per line. Human accounts (UID at or above `UID_MIN`, usually 1000) and any extra UID 0 account NOT on it are locked and expired. Expiry also blocks SSH key logins, which a locked password alone does not |
| `--users a,b` | Rotate (and lock) only these accounts. Repeatable; the lists add up |
| `--exclude a,b` | Never touch these accounts. Repeatable; the lists add up. Comma-separated, no spaces |
| `--ignore-missing` | A name in `--users` or `--exclude` that is not an account on this box normally STOPS the script before anything changes (a misspelled name would otherwise get the account rotated). This option only warns instead, for one list used on many boxes |
| `--passwords FILE` | Use these passwords instead of random ones: `user password` lines (a space between; an older `user,password` file still works), for a sheet made in advance. Passwords must be 8+ characters with no `:`; spaces around the name and password are dropped. Names not on this box, and accounts that are locked or have no password (setting one would unlock them), are listed in the summary and not changed |
| `--length N` | Random password length (default 16, minimum 12) |
| `--no-root` | Leave root's password alone |
| `--include-me` | Also rotate the account that ran `sudo`. Skipped by default so you can still use `sudo` |
| `--kick` | Also end every running process of a locked account (logs out a red team session) |
| `--print` | Show the new passwords on screen at the end (never saved to `output.txt`) |
| `--timer SECONDS` | Revert timer length (default 300) |
| `--no-timer` | No revert timer (you accept the risk) |
| `--batch` | Never ask: take every default. With `--apply`, the changes are kept |
| `--no-color` | No colours |

Random passwords use letters and digits without look-alikes (`0 O 1 l I`) plus `_` and `-`, so they survive being typed into shells, SQL and web forms.

#### What it does to each account

| Account | Action |
| --- | --- |
| Usable password (hash set, or EMPTY) | New password |
| On the protected list | Skipped; listed as `skipped (protected)` |
| Human account not on `--keep` | Locked and expired (password kept, so unlocking restores it) |
| Extra UID 0 account | Disabled (locked and expired) by default: it is root under another name |
| Password hash in `/etc/passwd` itself | Moved into `/etc/shadow` with `pwconv`, then rotated. A hash there is used instead of the shadow one, so changing only shadow would leave the old password working |
| System account without a password (`*`, `!`) | Left alone |
| Service account with a password but no login shell | Rotated, with a note: check no service logs in with its old password |

Accounts below `UID_MIN` are never locked: services and cron jobs run as them.

#### What it produces

In a numbered folder: `<out>/passwords-1`, `passwords-2`, ...

| File | Contents |
| --- | --- |
| `output.txt` | Everything shown on screen. Never a password |
| `accounts.txt` | Every account and what was done, as a table. No passwords |
| `revert.sh` | Undoes this run: old passwords back, locks removed (`sh revert.sh --force`) |
| `summary.txt` | Counts, every account and what happened, warnings (empty passwords, extra UID 0, Samba accounts). No passwords |
| `passwords.txt` | `HOST USER PASSWORD TIME` in columns, mode 600, written only when changes are applied. If the run is undone it is renamed `passwords-UNDONE-not-valid.txt`, so nobody hands out passwords that no longer work |

`/etc/shadow` and `/etc/passwd` are backed up before the first change. The undo log restores them from that backup, which also brings back the OLD passwords: that way no password hash is ever written into a log.

#### What to watch for

- **The passwords file is the most sensitive thing on the box.** Copy it to the captain (or read it out), then `rm` it. Its path is in the summary.
- **Scored accounts.** If the competition requires a scored account's password to change, change it through their password-change process and put the account on the protected list here.
- **Samba has its own passwords.** The summary lists Samba accounts if `pdbedit` exists; change those with `smbpasswd` if needed.
- **LDAP, Active Directory and NIS accounts** are not in `/etc/shadow` and are not touched.
- **Locking does not end open sessions.** Use `--kick`, and check `w` / `who` afterwards.

#### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `chpasswd not found` (exit 3) | Minimal image without shadow-utils | Install the `passwd` / `shadow` package, or busybox |
| `cannot read /etc/shadow` (exit 3) | Not root | `sudo` |
| An account shows `failed` | `chpasswd` refused (PAM password-quality rules can reject some passwords) | Rerun; a new random password is made each time. Check the log for the message |
| You cannot `sudo` any more | You rotated your own account with `--include-me` | Your new password is in `passwords.txt`; read it from the root shell you still have |
| Scoring broke right after | A scored account was rotated | Put it on the protected list and set the old password back: the undo log restores `/etc/shadow` |

---


### LX-22: SSH hardening and key cleanup (`dist/linux/LX-22-ssh-hardening.sh`)

Shows every SSH key on the box and every important sshd setting, asks key by key whether to keep it and setting by setting whether to turn it on or off, then installs the result with a revert timer. A changed password does not stop a red team that planted a key; this does. Keep a second root session open while applying.

#### How to run it

```sh
sudo sh LX-22-ssh-hardening.sh                        # look and plan: asks, changes nothing
sudo sh LX-22-ssh-hardening.sh --apply
sudo sh LX-22-ssh-hardening.sh --apply --batch        # recommended answers, no questions
sudo sh LX-22-ssh-hardening.sh --apply --allow-keys team.pub   # keep only the team's keys
```

#### What you see

1. **SSH now**: sshd version and ports, root login and password login as they are now, Match blocks that loosen things, extra key sources, extra sshd processes, `~/.ssh/rc` files.
2. **Keys**: every key of every account, numbered, with fingerprint, comment and file. Red `[!]` = looks planted (forced command, a service account, an account with no shell); yellow `[*]` = check it (root's keys, a file changed in the last 7 days, a key kept outside the home folder).
3. **Questions**.
4. **The plan**: each setting `before -> after`, the keys to remove; the new config is tested with `sshd -t`.
5. **Apply**, the reload check, then keep-or-revert.

#### The questions

| Question | Default | Flag |
| --- | --- | --- |
| Which box is this? `[s]plunk [w]ebmail [e]comm [f]ileshare [g]itea [b] web [o]ther` | other | `--box` (SSH is treated as scored on splunk, webmail and gitea) |
| Gitea keeps N user keys for git over SSH: `[k]eep them all` / `[o]ne by one` (only when there are some) | keep | `--gitea-keys keep\|ask` |
| Keep key #N? (one per key) | yes; **no** for keys that look planted | `--allow-keys FILE`, `--remove-all-keys`, `--keep-all-keys` |
| Move `~/.ssh/rc` to quarantine? (runs at every login) | yes | |
| Allow root to log in over SSH? `[y]` yes, `[n]` no, `[k]` key-only, `[l]` leave | `k` if root keeps a key; otherwise `l`, so root is never locked out | `--root-login yes/no/key-only/leave` |
| Turn off empty-password logins? | yes | `--set emptypw=no` to skip |
| Turn off host-based / .rhosts logins? | yes | `rhosts` |
| Stop users setting environment at login? | yes | `userenv` |
| Turn off X11 forwarding? | yes | `x11` |
| Turn off agent forwarding? | yes | `agent` |
| Limit tries per connection to 4? | yes | `maxauth` |
| Drop connections not logged in after 30s? | yes | `grace` |
| Drop dead idle sessions? | yes | `alive` |
| Log which key logged in (LogLevel VERBOSE)? | yes | `loglevel` |
| Turn OFF password logins? | **no** (scoring logs in with passwords) | `--no-passwords` |
| Turn off TCP forwarding and tunnels? | **no** | `--no-forwarding` |
| Modern ciphers only? | **no** (old clients may fail) | `--strong-crypto` |
| Only these accounts may log in | none | `--allow-users` |
| Apply these changes now? | yes | `--batch` |

Each question shows the current value and one line on what it does. A setting that is already right is shown as `[ok]` and not asked. `--set KEY=yes|no` answers one setting in advance.

#### Safety

- **Block at the top.** sshd uses the first value it reads, so the marked block at the top of `sshd_config` wins over the rest of the file and `sshd_config.d`. Nothing else in the file is changed.
- **Tested first.** The new config must pass `sshd -t` or it is not installed.
- **Reload check.** sshd is reloaded (open sessions stay up); if it stops listening the old config is put back at once. On **Ubuntu 24.04 and Mint 22** systemd holds the port (`ssh.socket`) and starts an sshd for each login: no reload is needed, and the next login uses the new config.
- **Gitea's keys.** Gitea (also Forgejo, Gogs, GitLab) writes each user's key into the `git` account with a forced command that only runs git. Those are shown as Gitea's in one line, kept by default, and the `git` account is added to `AllowUsers`. A forced command with anything more in it (`; bash`) is still flagged as planted. Manage Gitea's keys in its web admin.
- **Alpine** has no `ss`: the listening check uses busybox `netstat`.
- **Revert timer.** Everything is undone after `--timer` seconds (default 120) unless you confirm, after logging in from a NEW session. A revert also reloads sshd.
- **Evidence.** Removed keys are kept in `quarantine/`; rc files are moved there, not deleted.
- **Protected accounts** keep their keys; a protected root keeps its login.

#### What it produces

In `ssh-hardening-N/`: `output.txt`, `summary.txt`, `keys.txt`, `settings.txt`, `quarantine/`, `revert.sh` (after a live apply).

#### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `sshd -t rejected the new config` (exit 5) | A setting this sshd version does not know (often `--strong-crypto` on an old OpenSSH) | Run again without that option |
| Scoring's SSH check fails after applying | Password logins off, `AllowUsers`, or crypto | Let the timer revert, or `revert.sh`; apply again without that answer |
| A key file could not be rewritten | `chattr +i` | `lsattr FILE`, `chattr -i FILE`, run again |
| Root login was left alone | root has a password and no key that stays | Give root a team key, or answer `no` once another admin account can sudo |

---


### LX-25: Linux firewall builder (`dist/linux/LX-25-firewall.sh`)

Shows every open port on the box, says what each one is and which program is behind it, asks port by port whether to keep it or drop it, then builds a firewall that drops everything you did not keep. Run it LAST of the Linux hardening, and keep a second session open.

#### How to run it

```sh
sudo sh LX-25-firewall.sh                       # look and plan: asks, changes nothing
sudo sh LX-25-firewall.sh --apply    # ask, then load the rules
## then, from a NEW ssh session, within 2 minutes:
sudo sh /root/bt-out/firewall-1/keep-firewall.sh
## once scoring is green, keep the rules across a reboot:
sudo sh LX-25-firewall.sh --save --apply
```

#### What you see

Five sections, colour-coded (KEEP green, DROP red, CHECK yellow, local grey):

1. **The firewall now**: which backend it will use, whether LX-25 rules are already live, and whether ufw or firewalld is also running.
2. **Open ports**: one block per listening port.

   ```
   KEEP  tcp 80     HTTP            all addresses  apache2 (pid 812, runs as root)
         command: /usr/sbin/apache2 -k start
         what:    HTTP: the web server. Scored (web store, webmail) in past competitions.
         advice:  a scored service in past competitions
   DROP  tcp 4444   backdoor-style  all addresses  nc (pid 3321, runs as www-data)
         command: nc -lvp 4444 -e /bin/sh
         what:    Not a normal service port: this number is a favourite for backdoors ...
         advice:  suspicious: a bare nc listener is a classic backdoor
   ```

   The command line shows the script behind an interpreter (`python3 /opt/app/server.py`). "Scored in past competitions" comes from `docs/ENVIRONMENT.md`; it is a hint, so check the team packet.
3. **Questions** (Enter takes the default).
4. **The plan**: what stays open, what is dropped, who is always allowed.
5. **Apply**, then the summary.

#### The questions

| Question | Default | Flag that answers it |
| --- | --- | --- |
| Which box is this? (its scored ports stay open, not asked) `[s]plunk [w]ebmail [e]comm [f]ileshare [g]itea [b] web [o]ther` | other | `--box` |
| Your team's addresses that must always get in | none | `--admin CIDR` (repeat) |
| Keep PORT open? (one per listening port) | see below | `--keep 80,53/udp` / `--drop 3306` |
| Other ports to open that are not listening now | none | `--allow 8089/tcp,9000-9010/tcp` |
| SSH only from your team's addresses? (only asked if you gave some; the answer says a teammate from anywhere else is locked out) | no | `--ssh-from CIDR` |
| Also limit outgoing traffic? | no | `--restrict-out` / `--no-restrict-out` |
| Block IPv6? | yes | `--drop-ipv6` / `--keep-ipv6` |
| Load these rules now? (with `--apply`) | yes | `--batch` |
| No rollback timer? (only with `--confirm-timeout 0`, only at a terminal) | no: the 120 s timer is used | none: with `--batch` it is never skipped |

**It never cuts you off without a way back:** SSH is always kept (unless you limit it to listed addresses yourself), and the rules come out again by themselves unless you confirm from a NEW session. `--confirm-timeout 0` (no timer) needs a person at a terminal and a second yes; with `--batch` or no terminal the 120-second timer is used anyway.

Default for each port:

| Port is... | Default | Asked? |
| --- | --- | --- |
| SSH, DHCP client, on the protected list, scored on this `--box` (fileshare: 139, 445, 137-138/udp, 2049, 111; gitea: 3000, 2222, 80, 443; web: 80, 443) | keep | no |
| Loopback only (127.0.0.1) | left alone: outsiders cannot reach it anyway | no |
| A scored service in past competitions (22, 25, 53, 80, 143, 443, 993, 123/udp, 1433, 8000, 8089, 9997) | keep | yes |
| A normal service, a database, FTP | keep, with a note on when to drop it | yes |
| Unknown | keep, marked CHECK: find out what it is | yes |
| Rarely needed (telnet, rsh, TFTP, SNMP, rpcbind, CUPS, mDNS, VNC, Webmin) | drop | yes |
| A backdoor-style number, a bare `nc`/`socat` listener, a program running from `/tmp` or `/dev/shm`, a deleted program file | drop | yes |

`--strict` turns every "keep" default into "drop" except SSH, DHCP and the protected list. Dropping a port only blocks it from outside; the program keeps running, so also look at what started it.

Other options: `--backend nft|iptables`, `--confirm-timeout N` (default 120; `0` = no timer, console only), `--save` and `--remove` (with `--apply`), `--no-color`, `--batch`.

Always allowed, whatever you answer: loopback, replies to the box's own connections, **ping** (every box has a ping check), DHCP replies, and everything from your team's addresses and the protected hosts (the scoring engine).

#### Safety

- **Own rules only.** nftables: table `inet bt`. iptables: chains `BT-IN`/`BT-OUT`, jumped to from the top of `INPUT`/`OUTPUT`. Nothing else is flushed, so Docker, fail2ban, firewalld and ufw keep their rules. `FORWARD` is never touched.
- **Checked first.** The nft ruleset is checked with `nft -c` before loading; if loading fails, whatever loaded is removed.
- **Rollback timer.** After `--apply`, a detached timer removes the rules after `--confirm-timeout` seconds unless `keep-firewall.sh` is run. Run it from a NEW ssh session: that proves new connections still get in, which an open session cannot (open sessions survive any rule). At a terminal the script also asks; answering `y` removes the rules at once.
- **Not saved for reboot** until you run `--save --apply`. Until then a reboot is a last-resort undo.

#### What it produces

In `<out>/firewall-N/` (next free number):

| File | Contents |
| --- | --- |
| `output.txt` | Everything shown on screen, without colour |
| `summary.txt` | State (live, rolled back, dry run), what is open and why, what is dropped, the confirm command |
| `ports.txt` | Every listening port: where it is bound, program, pid, account, what it is, the decision and why, the command line |
| `ruleset.nft` or `ruleset.iptables.sh` | The exact rules |
| `rollback.sh` | Removes the rules (also in the undo log) |
| `keep-firewall.sh` | Cancels the rollback timer |
| `ROLLED_BACK` | Appears when the timer removed the rules |

Dropped packets are logged with the prefix `BT-DROP` (`journalctl -k | grep BT-DROP`, or `dmesg`), limited to 10 a minute.

#### What to watch for

- **A scored service that is down right now** is not listening, so it is not in the list. Open its port at the "other ports" question, with `--allow`, or put it on the protected list.
- **Unknown ports are kept by default** (marked CHECK) so nothing scored breaks. Read the command line shown with each one; drop what you do not need. `--strict` is the tight option once the protected list is right.
- **Without root** the program behind another account's port shows as `?`.
- **Other firewalls still apply.** A port allowed here can still be blocked by ufw or firewalld rules.
- **Fan-out:** without a terminal the script does not ask; confirm from the admin workstation with `ssh root@box sh .../keep-firewall.sh`, which is itself the "new connection" test.

#### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| A port shows program `?` | Not root, or a kernel service | Run with `sudo` |
| `nft rejected the ruleset` (exit 5) | A rule this nft version does not understand | Read the log line; try `--backend iptables` |
| Scoring went red right after applying | A scored port was not open | Wait for the timer or run `rollback.sh`; add the port to the protected list or `--allow`; apply again |
| `too late: the rules were already rolled back` | `keep-firewall.sh` ran after the timer | Apply again and confirm sooner, or use a longer `--confirm-timeout` |
| SSH locked out | `--ssh-from` without your address | Wait for the timer (that is what it is for); from the console run `rollback.sh` |
| Rules gone after a reboot | `--save --apply` was not run | Apply, confirm, then `--save --apply` |
| Under yash, output only appears when the timer ends | yash waits for the detached timer when the script's output is piped | Run it at a terminal, or with another shell |

---


### LX-21: Account lockdown (`dist/linux/LX-21-account-lockdown.sh`)

After passwords (LX-20), this goes through **every account, one by one**, shows what it can do, and asks what to do with it. It's the account side of getting red team out: the users they made, a second root, planted SSH keys, sudo rules.

#### How to run it

```sh
sudo sh LX-21-account-lockdown.sh                                  # look + dry run
sudo sh LX-21-account-lockdown.sh --apply        # asks about each account
sudo sh LX-21-account-lockdown.sh --apply --batch
```

**Put your team's accounts and the scoring account on the protected list first.** They're never locked, and anything else needs an extra yes.

#### What it shows for every account

UID, login shell, password (set / empty / locked / a hash in `/etc/passwd`), admin groups (`sudo wheel admin docker lxd lxc libvirt disk shadow`: each one is as good as root), its sudo lines (and NOPASSWD), SSH keys (and options like `command=`), and when its password last changed.

| Level | Found |
| --- | --- |
| HIGH | A second UID 0; an empty password; a hash in `/etc/passwd`; a service account (www-data, mysql...) that can log in with a password or a key |
| MED | An admin that isn't protected; sudo lines / NOPASSWD; SSH key options; a password changed in the last `--days` (2); a service account with a login shell |

Clean accounts that can't log in aren't shown (they're in `accounts.txt`).

#### The questions

| Question | Answers | Flag |
| --- | --- | --- |
| Which box is this? | `[s]plunk [w]ebmail [e]comm [f]ileshare [g]itea [b] web [o]ther` (guessed from the box's files) | `--box` |
| Go through the flagged accounts one by one? | `[y]` / `[n]` (the defaults) | `--batch` |
| Each account | `[k]eep` `[l]ock` `[d]` take admin away `[r]emove its SSH keys` `[b]oth d and r` `[n]o-login shell` `[a]ll the rest default`: only the answers that fit are shown | `--all` asks about every account |
| A protected account | extra `[y]` / `[n]`, default no | protected list |
| Each sudo line for everyone / a group / a missing user | `[y]` comment it out / `[n]` | |
| Apply? | `[y]` / `[n]` | `--apply` |

Defaults: a second UID 0, an empty password and a hash in `/etc/passwd` → **lock**. A service account with a shell → **no-login shell**. Everything else → **keep**.

#### What the answers do

- **Lock**: `usermod -L` and the account expired, so SSH keys stop too. Its files stay.
- **Take admin away**: out of the admin groups (not its primary group), and its own sudo lines commented out with `# LX-21: `.
- **Remove its SSH keys**: `authorized_keys` moved to quarantine.
- **No-login shell**: `/usr/sbin/nologin`. The service keeps running.
- **Sudo lines** are only changed after `visudo -c` accepts the result.

#### Safety

- Dry run unless `--apply`. Revert timer (120 s): **log in again from a NEW terminal** and check sudo works before you keep it.
- Root and the account you're using are never locked.
- Each account's lines are saved in `before/` first, and the undo puts them back exactly (tested on a real account).

#### What it produces

In `accounts-N/`: `output.txt`, `accounts.txt` (every account and the decision), `plan.txt`, `changes.txt`, `summary.txt`, `before/`, `revert.sh`.

#### What to watch for

- **An already logged-in session stays logged in.** LX-40 shows it; kill it by hand.
- **LDAP / AD accounts** (sssd, winbind) aren't in `/etc/passwd`, so they're not seen.
- Cron jobs, PAM, services and the rest red team plants: **LX-42**.


### LX-26: Remote access lockdown (`dist/linux/LX-26-remote-access.sh`)

SSH is LX-22. This covers **every other way in**: a remote screen, a shell in a web browser, a tunnel out past the firewall, a shell listening on a port. It looks at running programs, listening ports and installed services.

#### How to run it

```sh
sudo sh LX-26-remote-access.sh                                  # look + dry run
sudo sh LX-26-remote-access.sh --apply        # asks about each one
sudo sh LX-26-remote-access.sh --apply --batch
```

#### What it finds

| Level | Found |
| --- | --- |
| HIGH | **Tunnels out:** ngrok, chisel, frpc/frps, cloudflared, bore, gost, ligolo, rathole, inlets, wstunnel, sshx, `ssh -R`. **Mesh VPNs:** Tailscale, ZeroTier. **DNS and ICMP tunnels:** iodine, dnscat2, ptunnel. **Web terminals:** ttyd, gotty, shellinabox, wetty, tmate, code-server, Jupyter. **Bind/reverse shells:** `nc -e`, `ncat --exec`, `socat ... exec:`, a shell whose keyboard is a network connection. **Remote desktops:** x11vnc, Xvnc, vncserver, xrdp, NoMachine, TeamViewer, AnyDesk, RustDesk, Vino, KRfb, GNOME Remote Desktop, MeshCentral, Guacamole, DWService, Chrome Remote Desktop, xpra. |
| MED | **Admin panels:** Webmin (10000), Cockpit (9090), Usermin, ISPConfig, Virtualmin. **Quick file servers:** `python -m http.server`, `php -S`, busybox httpd. **Desktop control:** KDE Connect, Barrier, Synergy, Input Leap (keyboard and mouse from another machine; the Mint and Lubuntu desktops). |
| LOW | **Database panels:** phpMyAdmin, Adminer (listed only) |

Things on a scored port for the box, or on the protected list, are shown as kept and never offered.

#### The questions

| Question | Answers | Flag |
| --- | --- | --- |
| Which box is this? | `[s]plunk [w]ebmail [e]comm [f]ileshare [g]itea [b] web [o]ther` (guessed from the box's files) | `--box` |
| Each finding | `[s]top` / `[k]eep` / `[a]ll the rest default` (default: stop for HIGH, keep for MED) | `--batch` |
| Stop these? | `[y]` / `[n]` | `--apply` |

#### What "stop" does

- **A service** (xrdp, webmin, cockpit...): stopped and disabled at boot. The undo enables and starts it again.
- **A program:** killed (then `kill -9` if needed).
- **A program file in `/tmp`, `/var/tmp`, `/dev/shm` or a home folder:** quarantined, so it can't just be started again.

#### What it produces

In `remote-access-N/`: `output.txt`, `findings.txt`, `plan.txt`, `summary.txt`, `revert.sh` (services only; killed programs aren't restarted).

#### What to watch for

- **It comes back?** A cron job, service or `.bashrc` restarts it: find that with **LX-42**, then run LX-26 again.
- **A remote desktop your team uses:** put its port on the protected list.
- telnet, rsh, FTP, SNMP and the other old services: **SV-30**.
- **Alpine** has no `ss`: the ports come from busybox `netstat`.


### LX-42: Linux persistence sweep (`dist/linux/LX-42-persistence-sweep.sh`)

Finds the ways an attacker makes sure they get back in or their code keeps running, then (with `--apply`) asks finding by finding whether to remove it. Run it after the enum and the safe fixes, and again whenever the red team has been on the box.

#### How to run it

```sh
sudo sh LX-42-persistence-sweep.sh                    # asks what to scan, then looks
sudo sh LX-42-persistence-sweep.sh --batch            # full scan, no questions
sudo sh LX-42-persistence-sweep.sh --areas cron,ssh,systemd
sudo sh LX-42-persistence-sweep.sh --apply   # look, then ask what to remove
```

#### The questions

| Question | Default | Flag |
| --- | --- | --- |
| Do a full scan? | yes | `--full` |
| (if no) Which areas? | cron systemd ssh shell accounts | `--areas a,b` |
| Other folders to search for planted programs and web shells | none | `--scan-dir /opt` |
| How many days back counts as recently changed? | 7 | `--since N` |
| Compare key system programs with their packages? | yes | `--pkg-check` / `--no-pkg-check` |
| Accounts to leave out | none | `--ignore-user` (and `--ignore-path`) |
| (with `--apply`) Remove finding #N? one per finding | **no** (`--yes-high`: yes for HIGH) | |

#### What it looks at

| Area | Where |
| --- | --- |
| cron | /etc/crontab, cron.d, cron.hourly/daily/..., every user crontab, `at` jobs |
| systemd | units, timers, drop-in overrides, user units, generators |
| boot | rc.local, init.d, motd / network / DHCP / sleep hook folders, udev rules, apt hooks, logrotate scripts, inetd/xinetd, desktop autostart |
| ssh | every authorized_keys (forced commands, service accounts, accounts with no shell), sshd settings that add keys or commands, ~/.ssh/rc, /etc/ssh/sshrc |
| shell | /etc/profile, profile.d, every user's bashrc/profile/zshrc: reverse shells, `alias sudo=...`, LD_PRELOAD, PATH tricks, history hiding |
| preload | /etc/ld.so.preload, linker config, LD_PRELOAD in service settings and running processes |
| accounts | extra UID 0, hashes in /etc/passwd, service accounts that can log in, sudoers (NOPASSWD ALL), docker/lxd/disk groups |
| pam | pam_exec, pam_permit as sufficient, PAM modules no package installed, nsswitch |
| kernel | modules loaded at boot or loaded now with no file on disk, modprobe `install` tricks, core_pattern and modprobe hooks |
| files | programs in /tmp and /dev/shm, `...` folders, files in /dev, commands shadowed in /usr/local/bin, system programs no package installed or that do not match their package, SUID/SGID (GTFOBins), capabilities, immutable files, Python startup hooks |
| procs | deleted programs, programs run from /tmp or memory, fake kernel-thread names, shells holding a connection |
| web | web shell code, scripts in upload folders, recently changed scripts, `.htaccess`/php.ini tricks |
| misc | mail aliases and `.forward` that run programs, polkit rules, a world-writable docker socket |

**HIGH** = almost certainly planted or dangerous. **MED** = unusual, look at it. **LOW** = context (in `findings.txt`; `--low` shows them). "Not from a package" means the package database does not know the file; in a place only packages write to, that is the clearest sign.

#### Removing

With `--apply` it asks about each HIGH and MED finding that can be removed. Files are **moved** to `quarantine/`, never deleted; single lines (a cron entry, a key, a line in .bashrc) are taken out after a backup; units are stopped and disabled first; SUID is taken off. All of it is undone by `revert.sh` and by the revert timer. Killing a process is asked separately (default no) and cannot be undone.

#### What to watch for

- **Removing persistence does not remove the attacker.** Change passwords (LX-20), check the logs (LX-41) for how they got in.
- **Hand-installed software** (in /opt, /usr/local) is "not from a package" too: it shows as MED or LOW unless something else is wrong.
- **A kernel rootkit can hide files** from any scanner; the kernel area and the package check are the tell-tales.
- **Without root** other accounts' files and processes cannot be read.

#### Outputs

In `persistence-N/`: `output.txt`, `summary.txt` (counts per area, HIGH and MED list), `findings.txt` (every finding, numbered), `quarantine/`, `revert.sh`. No password hash is ever written.

---


### LX-45: Rootkit and malware scan (`dist/linux/LX-45-rootkit-scan.sh`)

LX-42 finds what red team leaves to come back. This finds **what hides**: a rootkit that lies to `ps`, `ss` and `ls`, a hidden kernel module, a replaced `ps` or `sshd`, a miner, malware in the temp and web folders.

#### How to run it

```sh
sudo sh LX-45-rootkit-scan.sh                                  # scan, dry run
sudo sh LX-45-rootkit-scan.sh --apply        # asks about each finding
sudo sh LX-45-rootkit-scan.sh --apply --batch
```

#### What it checks

| Area | Found |
| --- | --- |
| Hidden processes | A process in `/proc` that `ps` doesn't show (checked twice, a second apart) |
| Hidden ports | A port listening in `/proc/net/tcp` that `ss` doesn't show (`netstat` where there is no `ss`, like Alpine) |
| Kernel modules | A module in `/sys/module` that `lsmod` doesn't list; known rootkit module names (diamorphine, reptile, suterusu...); the kernel's taint flags (out-of-tree, unsigned) |
| Replaced programs | `ps ss netstat ls find top lsof ssh sshd sudo su login passwd w who last grep cat crontab systemctl ip kill pgrep du df stat md5sum`... that don't match their package (`dpkg -V` / `rpm -V` / `apk audit`), or belong to no package. On Alpine a link to busybox counts as busybox, which is checked; `doas`, `rc-service` and `openrc` too |
| Rootkit files | Paths known rootkits use (reptile, azazel, jynx, bdvl, beurk, processhider...), programs in `/dev` or `/dev/shm` |
| Fake kernel threads | A process named like `[kworker/0:1]` that has a program file |
| Miners | Known miner program names, `stratum+tcp://` and `--donate-level` on a command line; connections to mining-pool ports |
| Sniffers | Network cards in promiscuous mode |
| Malware | **ClamAV** over `/tmp /var/tmp /dev/shm /var/www /srv /home /root` and Roundcube (+ `--scan DIR`), and if you say so the shared folders (Samba `path =`, NFS `/etc/exports`, Gitea's `/var/lib/gitea`); **rkhunter** and **chkrootkit** warnings, when installed |

`/etc/ld.so.preload` (the usual userland rootkit) is LX-42's check.

#### The questions

| Question | Answers | Flag |
| --- | --- | --- |
| Also scan the shared folders? (only when the box shares some outside the usual folders) | `[y]` / `[n]`, default yes | `--shares` / `--no-shares` |
| Each process finding | `[k]ill` / `[l]eave` / `[a]ll the rest default` | `--batch` |
| Each file finding | `[q]uarantine` / `[l]eave` / `[a]ll the rest default` | `--batch` |
| Do these? | `[y]` / `[n]` | `--apply` |

#### What it changes

Only with `--apply`: processes killed, files quarantined (the undo puts files back). **Kernel modules are never unloaded**, because unloading a rootkit module often crashes the box. Find what loads it (LX-42 kernel), remove that, and reboot.

#### What it produces

In `rootkit-N/`: `output.txt`, `findings.txt`, `summary.txt`, `clamav.txt` / `rkhunter.txt` / `chkrootkit.txt` when they ran. Quarantined files go to the quarantine folder; their undo lines (put them back) to the undo log.

#### What to watch for

- **A kernel rootkit can hide from `/proc` too.** If nothing shows but the box still feels wrong, scan it from another box (SH-03): a port open there but not in `ss` is hidden.
- **Run it twice before acting** on a "hidden" finding: a process that ended between the two views can show once.
- **ClamAV needs signatures** (`freshclam`). Without internet, there are none, and it says so instead of "found nothing".
- **It never installs or downloads anything.** For ClamAV, rkhunter and chkrootkit it says whether each is installed; a missing one is skipped with the command to get it yourself: Ubuntu and Mint `apt-get install clamav`; Rocky needs EPEL first (`dnf install epel-release`); Fedora `dnf install clamav`; Alpine `apk add clamav` with the community repository on. `--install` and `--no-install` are still accepted and do nothing.


### LX-39: Linux safe fixes (`dist/linux/LX-39-safe-fixes.sh`)

Hardening that cannot break a scored service, so it can run on every Linux box in the first minutes without study. It only removes risky settings and permissions; it never changes an owner, never deletes a file, and never touches a service that serves anything.

Run the backup (LX-31) first.

#### How to run it

Just run it. It asks questions like sqlmap: Enter takes the default (the capital letter).

```sh
sudo sh LX-39-safe-fixes.sh                        # asks everything, then asks before applying
sudo sh LX-39-safe-fixes.sh --apply --batch        # no questions: defaults, apply, keep
sudo sh LX-39-safe-fixes.sh --batch                # no questions, dry run only
sudo sh LX-39-safe-fixes.sh --apply --skip ipv6    # flags answer questions in advance
```

What a run looks like:

1. **Revert timer starts: 2 minutes.** If you don't keep the changes before it runs out (for example because you got kicked off), everything this run changed is put back. It runs outside the script (a systemd timer, or a detached job), so a dead SSH session doesn't stop it.
2. **Questions:** which box this is (splunk / webmail / ecomm / other), then one per fix. For fixes that act on accounts or SUID files it first lists what it found. After a yes, a fix that acts on named items asks **"Leave any alone?"**: type a comma list (account names, paths, settings, services) or press Enter for none. The time left is shown.
3. **Plan:** a dry run shows every change (yellow `[~]`), then asks `Apply these N change(s)?`
4. **Applying:** each change shown as it's made (green `[+]`, red `[x]` if it failed).
5. **Keep or revert:** open a **new** SSH or console session and log in. Then `y` keeps the changes; `n`, or no answer before the timer, undoes them.

With no terminal (run remotely) and no `--batch`, it says how to keep the changes from another session: `touch <run folder>/KEEP`.

| Option | What it does |
| --- | --- |
| `--box NAME` | splunk, webmail, ecomm or other: answers the box question |
| `--exclude a,b` | Items no fix may touch: paths (`/etc/crontab`), account names (`bob`), kernel settings (`net.ipv4.tcp_syncookies`), services (`auditd`). Answers every "leave any alone?" question |
| `--timer SECONDS` | Revert timer length (default 120) |
| `--no-timer` | No revert timer (you accept the risk) |
| `--batch` | Never ask: take every default. With `--apply`, the changes are kept |
| `--no-color` | No colours |
| `--only` / `--skip` | Run or leave out fixes by name (see `--list`) |
| `--keep-ipv6` | Leave IPv6 on |
| `--no-forwarding` | Also turn IP forwarding off. Routers, firewalls and Docker hosts need it on |
| `--root DIR` | Treat DIR as `/` for the file fixes, for fixing a mounted disk image. Kernel settings and services still act on the running system |

Without a protected list it asks whether to go on (`--no-protected` answers yes). A path on the protected list is skipped.

#### The fixes

| Fix | What it does | Why it is safe |
| --- | --- | --- |
| `sysctl` | SYN cookies on; full address-space randomization; no unprivileged BPF; protected FIFOs and regular files in sticky folders; RFC 1337 TIME-WAIT protection; source-routed packets and ICMP redirects refused and not sent; odd-source packets logged; symlink and hardlink protection; kernel pointers and kernel log hidden from normal accounts | None of these change what a service listens on or answers |
| `ipv6` | IPv6 off on every interface except loopback (`lo` is switched back on after `all` is switched off, so `::1` stays), with the kernel setting `disable_ipv6`, written for boot too. Only tried against a stand-in so far: after the first real run check `ip -6 addr show lo` | Services listening on `[::]` keep working for IPv4. NOT the `ipv6.disable=1` boot option, which stops such services from starting at all. Services bound to one specific IPv6 address are listed first under "check by hand" |
| `forwarding` | IP forwarding off. It asks first whether the box routes traffic or runs Docker. With no one to ask, only with `--no-forwarding` | Routers, firewalls and Docker need forwarding |
| `coredumps` | No core dumps from setuid programs; core size limit 0 for every account | A core dump of a login program can hold password hashes |
| `perms` | Removes group and other write (and other read on secrets) from `/etc/passwd`, `/etc/group`, `/etc/shadow`, `/etc/gshadow`, sudo files, SSH host keys and `sshd_config`, `/root`, cron files, shell startup files, `ld.so` config, PAM and systemd unit folders; removes world-write from anything in `/etc`, program folders and home folders | Only bits are removed. Owners and groups stay, so `shadow` stays readable by the `shadow` group on Debian and by `ssh_keys` on Red Hat |
| `tmp` | Sticky bit on `/tmp`, `/var/tmp`, `/dev/shm` | Normal on every distribution |
| `logging` | Starts and enables rsyslog, syslog-ng and auditd if they are installed but stopped | Logging is never scored against you |
| `preload` | If `/etc/ld.so.preload` loads a library no package owns, the file is moved to quarantine. `LD_PRELOAD` and `LD_LIBRARY_PATH` lines in `/etc/environment` are commented out | That file is the classic user-mode rootkit hook. A library owned by a package (a logger such as snoopy) is reported and left alone |
| `trust` | `.rhosts`, `.shosts`, `/etc/hosts.equiv`, `/etc/shosts.equiv` moved to quarantine | They let other machines log in with no password |
| `uid0` | Accounts other than root with UID 0 are locked (`!` before the password) and expired, so no password or SSH key logs in | A second UID 0 account is a backdoor. The password itself is never logged; undo removes the `!` and puts the old expiry back |
| `emptypw` | Accounts with an empty password are locked | Anyone could log in as them. Scoring never uses an account with no password |
| `suid` | Removes the SUID bit from programs that should never have it (copies of bash, find, vim, python ... from GTFOBins) and from any SUID file in `/tmp`, `/var/tmp`, `/dev/shm`, `/home`, `/root` | The normal SUID programs (passwd, sudo, su, mount, ping, pkexec ...) are not on the list and are never touched |
| `hosts` | Reports `/etc/hosts` lines that pin a name to an address. Never changes the file | Scoring can depend on `/etc/hosts`; a red team uses it to redirect updates and logins |

IP forwarding left on is reported under "check by hand" even without `--no-forwarding`.

#### What it produces

In a numbered folder: `<out>/safe-fixes-1`, `safe-fixes-2`, ...

| File | Contents |
| --- | --- |
| `output.txt` | Everything shown on screen, without colours |
| `summary.txt` | Counts per fix, every change (or would-be change), and the items to check by hand |
| `plan.txt` | What it would change |
| `fixes.txt` | What it did: fix, item, before, after, status |
| `revert.sh` | Undoes this run: `sh revert.sh --force` |
| `revert.log`, `KEEP`, `REVERTED` | The revert timer's record |

Every change adds an undo command to `<out>/undo-<host>.log`. Changed files are copied to `<out>/backup/<host>/` first; quarantined files go to `<out>/quarantine/<host>/`.

Kernel settings are written to `/etc/sysctl.d/99-zz-bt-safe.conf`, a name read last at boot, so they win over `/etc/sysctl.conf`.

#### Undo

This run only, at any time (even after keeping it):

```sh
sudo sh /root/bt-out/safe-fixes-3/revert.sh --force
```

Everything every script changed on the host: run the undo log's commands from the bottom up:

```sh
awk -F'\t' '{ l[NR] = $4 } END { for (i = NR; i >= 1; i--) print l[i] }' /root/bt-out/undo-web01.log > /tmp/undo.sh
less /tmp/undo.sh        # read it first: it holds every change made by every script on this host
sh /tmp/undo.sh
```

To undo only this script, keep the lines whose second field is `LX-39`.

#### What to watch for

- **Dry run first on one box.** The summary shows exactly what will change.
- **A container may refuse some kernel settings.** Those show as `failed` in `fixes.csv`; everything else still applies.
- **A quarantined `ld.so.preload` is evidence.** Hash it and keep it for the incident report. After moving it, run the enum again: a rootkit that hid files stops hiding them.
- **The boot file can be beaten by a file named later** (for example `99-zzz.conf`). The change watch reports new files in `/etc/sysctl.d`.

#### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `Staying in dry run ... no protected list` | You answered no to going on without a protected list | Build one, pass `--protected FILE`, or answer yes / pass `--no-protected` |
| `the revert timer ran out while waiting for an answer` (exit 3) | The questions took longer than the timer. Nothing was changed | Run again faster, use flags or `--batch`, or `--timer 300` |
| The changes were undone a couple of minutes later | Nobody answered "keep", or you were kicked off | That's the timer working. Check `revert.log`, fix whatever locked you out, run again |
| `Dry run only (not root)` | Not run with sudo | `sudo` |
| `this script must be run as root` (exit 3) | `--apply` as a normal user | `sudo` |
| Kernel settings `failed` | Read-only `/proc/sys` (containers) | Nothing to do on that box; the host kernel decides |
| `skipped (not on this kernel)` | Old or trimmed kernel without that setting | Harmless |
| A service stopped answering on IPv6 | It was bound to a specific IPv6 address (listed under "check by hand") | Undo the two `disable_ipv6` lines, or bind the service to its IPv4 address |
| `logging` shows nothing | No rsyslog, syslog-ng or auditd installed | Install one if logs matter for the box |

---


### SV-26: Brute-force and spam banning (`dist/linux/SV-26-banning.sh`)

Reads the login logs, counts failed logins per address, and bans an address that passes the limit. Every ban ends by itself after the ban time, so a mistake fixes itself. Spam from a compromised mailbox is reported, not banned.

#### How to run it

```sh
sudo sh SV-26-banning.sh                                       # asks; dry run (shows who would be banned)
sudo sh SV-26-banning.sh --apply          # asks, then bans
sudo sh SV-26-banning.sh --apply --batch --loop 60 --team 10.0.0.0/24
sudo sh SV-26-banning.sh --list                                # who is banned and why
sudo sh SV-26-banning.sh --apply --unban 10.6.6.66             # lift one ban
sudo sh SV-26-banning.sh --apply --unban-all                   # lift every ban now
```

Keep it running with `nohup ... &`, `tmux` or `screen`.

#### The questions

Enter takes the default. A flag answers each one ahead of time; `--batch` (or no terminal) takes the defaults and checks **once**. Answers are saved and become the next run's defaults.

| Question | Default | Flag |
| --- | --- | --- |
| Failed logins (SSH, FTP, mail) before a ban | 10 | `--max-fails N` |
| Web login attempts before a ban | 30 | `--web-max N` |
| Ban length in minutes | 30 | `--ban-time MIN` |
| Services to watch | all | `--services "ssh mail"` (ssh ftp mail web pam) |
| Never ban these: your team and the scoring engine | last answer | `--team` / `--ignore ADDR` |
| Seconds between checks (0 = once) | 60 | `--loop N` / `--once` |

**Give it the scoring engine's address.** After a password change the scoring engine fails logins too, and you don't want it banned.

Other options: `--window MIN` (counting window, 10), `--mail-max N` (spam warning, 200), `--log FILE` (read only these logs), `--history N` (lines read on the first check, 2000), `--count N`, `--backend nft|ipset|iptables`, `--state DIR`, `--no-color`.

#### What the screen shows

1. **Setup**: your answers.
2. **Logs, firewall, never-ban list**: each log and what it tells you, the firewall it uses, and every never-banned address with the reason (your answer, protected list, this box, the default gateway).
3. **Checks**: one line per check, then each address worst first:
   - `[!] BANNED` (or `[*] WOULD BAN` in a dry run) with services, counts and the accounts tried
   - `[*] NOT BANNED`: over the limit but on the never-ban list, with why (look at it)
   - `[*] SPAM?`: a mailbox sending to lots of people
   - `[-] watching`: under the limit for now
4. **Summary**: totals, who was banned, and the files.

#### What it counts

| Service | Log lines |
| --- | --- |
| ssh | `Failed password`, invalid-user scans, `maximum authentication attempts exceeded` |
| ftp | vsftpd `FAIL LOGIN`, proftpd `Login failed`, pure-ftpd `Authentication failed` |
| mail | postfix SASL failures and `Relay access denied`, dovecot `auth failed` |
| web | `POST` to login pages (`wp-login.php`, `xmlrpc.php`, Joomla, `/user/login`, Roundcube, phpMyAdmin, `/login`) and any 401. Other admin pages are not counted |
| pam | any `authentication failure ... rhost=` |
| spam (report only) | postfix `from=<sender> ... nrcpt=N`, summed per sender |

It reads `/var/log/auth.log` or `secure`, the FTP logs, `mail.log` or `maillog`, and the Apache and nginx access logs. With no SSH log file, it reads the journal. Each check reads only what's new since the last one, and the window is the sum of the checks in the last 10 minutes. A rotated log is read from the start again.

#### Never banned

Your team answer, protected hosts, this box, loopback and the **default gateway**. With NAT, every outside client looks like the gateway, so banning it would cut off scoring. These show up as `NOT BANNED` so you can decide.

#### What it produces

Each run gets `<out>/banning-N/`: `output.txt` (the screen without colour), `bans.txt`, `offenders.txt` (every address with failures, per check, and the verdict), `summary.txt` and `run.txt`.

These are kept in `<out>/ban-<host>/`: `bans.csv` (every ban ever), `events.log`, `hits`, `offsets`, `settings`. A dry run keeps its counts in the run folder only, so it never touches the real state, and a dry loop still reads each line once.

The firewall is nftables table `inet bt_ban` (address sets with timeouts and one drop rule). Without nftables it uses ipset `bt_ban` plus one iptables rule, or one iptables rule per address that a later check removes when it's due. `--unban-all` removes it all. There's no revert timer, because every ban already ends by itself.

#### What to watch for

- **Accounts tried** show what the red team is guessing. If a real account is on the list, change its password.
- **`SPAM?`** means a local mailbox is sending to lots of people, so its password is probably known. Change it and check the mail queue.
- **Many addresses with a few tries each** stay under the limit. Lower the limit, or block the range with the firewall script (LX-25).
- **First check:** it reads the last 2000 lines of each log, so old failures can trigger bans straight away. Do a dry run first.

#### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `0 new failed login(s)` during an attack | The service logs somewhere else or in another format | Pass the log with `--log`, run with `--debug` |
| `no login logs found` | Not root, or no syslog | Run with sudo; `--log FILE` |
| The scoring engine got banned | Not on the never-ban list | `--apply --unban ADDR`, then give it to the never-ban question |
| `NOT BANNED ... default gateway` | Traffic comes in NATed | Ban by hand only if you're sure |
| `no firewall tool found` (exit 3) | No nft, ipset or iptables | Install nftables |
| Bans gone after a reboot | They're timed and not saved, on purpose | Keep it running in a loop |

---


### LX-40: Linux change watch (`dist/linux/LX-40-change-watch.sh`)

Takes a baseline of every place a red team uses to get back in, then checks again (once, or every minute) and prints one alert per change in plain words, worst first. New in 2.0: it also watches **connections**, so a reverse shell calling out shows up with the program, user and command line behind it.

It changes nothing on the host. Start it once the box is hardened.

#### How to run it

```sh
sudo sh LX-40-change-watch.sh                      # asks, then watches
sudo sh LX-40-change-watch.sh --batch              # one check, defaults
sudo sh LX-40-change-watch.sh --loop 60 --team 10.0.0.0/24
## keep it running, alerts copied off the box:
nohup sudo sh LX-40-change-watch.sh --batch --loop 60 \
    --alert-cmd "ssh admin@10.0.0.5 'cat >>/srv/alerts/web01.log'" >/root/bt-out/watch.out 2>&1 &
sudo sh LX-40-change-watch.sh --accept             # after changing things on purpose
```

#### The questions

Enter takes the default. A flag answers each one ahead of time; `--batch` (or no terminal) takes the defaults and does **one** check.

| Question | Default | Flag |
| --- | --- | --- |
| Use the existing baseline? (No = take a new one) | Yes | `--use-baseline` / `--baseline` |
| Seconds between checks (0 = once) | 60 | `--loop N` / `--once` |
| Watch connections too? | Yes | `--conns` / `--no-conns` |
| Your team's addresses (never alerted) | last answer | `--team "10.0.0.5 10.0.0.0/24"` |
| Other web folders to watch | none | `--webroot DIR` |
| Scan the disk for new SUID programs? | Yes | `--suid` / `--no-suid` |

Your answers are saved and become the next run's defaults. With no baseline yet, the first run just takes one.

Other options: `--count N` (stop after N checks), `--suid-every N` (in a loop, the SUID scan runs every Nth check, default 10), `--alert-cmd CMD` (new alert lines go to CMD's stdin), `--state DIR`, `--no-color`.

#### What it watches

| Section | What | Severity |
| --- | --- | --- |
| users | New accounts, UID 0, a service account given a login shell | HIGH |
| passwords | Changed (MED), removed/empty (HIGH), unlocked (MED). Only a checksum is kept, never the hash | |
| groups | Says who was added: admin groups (sudo, wheel, docker ...) HIGH, others LOW | |
| files | sudoers, PAM, ld.so.preload, login scripts, hosts, DNS, sshd_config, sysctl, each with what it controls | HIGH for sudo/PAM/preload or new |
| cron | Cron files, at/anacron spools, systemd timers | HIGH |
| units | Boot service files | added HIGH |
| running | A running service stopping (MED, "if it is scored, it is down"); auditd/rsyslog/splunk/wazuh stopping HIGH | |
| keys | authorized_keys added or changed | HIGH |
| ports | New listener with its pid, user and command line. A shell, interpreter, nc, or a program from /tmp listening is HIGH; so is a known backdoor port | |
| connections | New outgoing connection with the program behind it: a shell/interpreter/temp-folder program or attacker port is HIGH (reverse shell), the web server account calling out is HIGH, package updates LOW, anything else MED. New address on SSH, RDP, database or SMB ports is MED (who got in). Team addresses, loopback and web visitors are never alerted | |
| suid | New SUID/SGID program | HIGH |
| web | Files in the web roots: new program file HIGH | |
| modules | Kernel module loaded | HIGH |

#### What it produces

Each run gets `<out>/changewatch-N/`: `output.txt` (the screen without colour), `alerts.txt` and `connections.txt` (tables), `summary.txt`, `run.txt`.

The state stays in `<out>/watch-<host>/`: `baseline/` and `last/` snapshots, `alerts.log` (every alert ever, one line each), `changes-since-baseline.txt`, `conns-seen`, `settings`.

#### What to watch for

- **Your own changes show up too.** Run `--accept` after the team changes something on purpose.
- **Connections are sampled at each check.** One that opens and closes between checks is missed; a reverse shell stays open, so it is caught.
- **Run it as root**, or it cannot see passwords, other accounts' keys or which program owns a connection.
- **Send alerts off the box** with `--alert-cmd`. A red team with root can stop the script.
- **"stopped listening" or "service stopped" on a scored service** means it is down: fix that first.
- **A new web folder** added later joins the baseline quietly, so its existing files aren't alerted.

#### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| Hundreds of alerts on the first check | Baseline taken before hardening | `--accept`, then watch |
| Lots of MED outgoing connections | Agents or apps that call out | Add their address to `--team`, or `--accept` (once reported, a connection is not reported again) |
| `passwords`, `keys`, connection programs empty | Not root | Run with sudo |
| Checks are slow | SUID scan on a big disk | Raise `--suid-every`, or `--no-suid` |
| The loop stopped when the session closed | Started without `nohup` | `nohup ... &`, `tmux` or `screen` |

---


### LX-41: Linux session & command logging (`dist/linux/LX-41-session-log.sh`)

Watches who logs in and what they run, saves it to log files, and prints an alert for anything that looks like the red team. It pairs with LX-40: LX-40 watches config and persistence **state**, this one watches **events** — logins and commands. It reads logs the box already keeps, so it changes nothing (unless you pass `--setup-auditd`).

#### How to run it

```sh
sudo sh LX-41-session-log.sh                        # one pass, from now
sudo sh LX-41-session-log.sh --loop 30              # keep watching (Ctrl-C stops)
sudo sh LX-41-session-log.sh --admin "alice bob"    # your admin accounts stay quiet
## keep it running, alerts copied to the admin box:
nohup sudo sh LX-41-session-log.sh --loop 30 \
  --alert-cmd "ssh log@10.0.0.5 'cat >>/srv/alerts/web01.log'" &
sudo sh LX-41-session-log.sh --setup-auditd         # turn on full command logging (a change)
```

#### What it logs

| Section | From | What |
| --- | --- | --- |
| logins | the auth log (`auth.log`/`secure`, or journald) | every login with its source address and key-vs-password, failed logins, brute force, sessions |
| priv | the auth log | every `sudo` and `su`, and the command each `sudo` ran, and failures |
| commands | auditd (if recording execve) | every command with user, tty and folder |

Privileged commands (`sudo`/`su`) are always captured from the auth log. **Every** command needs auditd. The script says whether auditd is on and, if not, prints the one rule to add — or adds it with `--setup-auditd`.

#### Catching a web shell

A web server almost never runs shell commands, so LX-41 treats the web layer specially:

- **A command run by the web-server account** (`www-data`, `apache`, `nginx`, `httpd`, ...) is always **HIGH** — that is the web shell executing. `--web-user NAME` adds accounts.
- **Where a process runs from:** a program or working folder in `/tmp`, `/var/tmp`, `/dev/shm`, a web root, or a deleted binary is **HIGH**.
- **Requests that were refused** (404/403) are a scanner guessing: they are counted per address and reported as one line, not one each.
- **The web access log** (apache/nginx, auto-found, or `--access-log FILE`) goes to `web.log`, and these requests alert: a known web-shell filename (`wso.php`, `c99.php`, ...), command-injection markers (`cmd=`, `shell_exec`, `base64_decode`, `;id`, `/bin/sh`, ...), and a request to a script that was **dropped into a web root after watching began** (`--webroot DIR` maps the URL to the file). So you see each command the attacker sends to the shell.

#### Your own commands don't flood the alerts

An **admin allowlist** decides what reaches the console. It starts from the `sudo`/`wheel`/`adm` group members plus whoever is running the script, and you add to it with `--admin "alice bob"` or `--admin-file`. For those accounts, a normal login or command is **logged but not alerted**. It only alerts on them if the command itself is dangerous. Everyone else alerts.

| Severity | When |
| --- | --- |
| HIGH | A dangerous command by anyone (reverse shell, `curl\|sh`, `base64 -d\|sh`, `nc -e`, wiping history). A login or command by an account not in `/etc/passwd`. Root logging in over the network with a password. A burst of failed logins from one address |
| MED | A login or command by a non-admin account. A sudo auth failure |
| LOW (file only, `--low` to show) | An admin doing something sensitive (`useradd`, editing sudoers, `wget`), kept for the record |

`--all-commands` alerts on every command; `--alert-own` also alerts on admins' normal commands.

Three things keep the console readable when a box is busy:

- **Repeats are held back.** The same alert is shown once, then kept quiet for `--repeat-after` seconds (default 600; `0` shows every repeat). A scoring engine that logs in every minute shows up once. The pass line says how many repeats were held back, and every event is still in its log file.
- **Who ran it is the login account.** `bob as root` means bob after `sudo` or `su`. Root commands from a non-admin's session alert; your admins' do not.
- **Daemons are logged, not alerted.** A service account with no terminal (postfix, a cron job) is doing its job. Web-server accounts are the exception: they always alert.

It also flags from the auth log: a login that **succeeds after many failures** from the same address, a slow brute force that adds up across checks, `sudo` by an account that is not allowed, `su` to root by a non-admin, a **new account**, an account **added to sudo/wheel**, and password changes. And it says so if the auth or audit log is suddenly empty or gone.

#### Options

| Option | What it does |
| --- | --- |
| `--loop N` / `--count N` | re-check every N seconds (min 5); stop after N checks |
| `--admin "U1 U2"` / `--admin-file F` | accounts to keep quiet, on top of the auto-detected ones |
| `--alert-own` / `--all-commands` | make admin / all commands show |
| `--low` | also show LOW alerts on the console |
| `--repeat-after N` | show the same alert again only after N seconds (default 600; 0 = always) |
| `--from-start` | process existing log history on the first pass (default: from now) |
| `--alert-cmd CMD` | run CMD with the new alert lines on its stdin (send them off-box) |
| `--setup-auditd` | add the auditd execve rule so every command is logged, and offer to keep it after a reboot (the one change; undo lines are written) |
| `--auth-log` / `--audit-log` | point at specific log files |
| `--max-mb N` | roll a log over at N MB (default 50) |
| `--state DIR` | where the logs and read-positions live (default `<out>/sesslog-<host>`) |

#### Outputs

In the state folder (`<out>/sesslog-<host>/`): `alerts.log` (the flagged subset, same format as LX-40), `logins.log`, `priv.log`, `commands.log`. A restart keeps the same files and read-positions and carries on.

#### What to watch for

- **Without auditd you still get logins and every `sudo` command** — the privileged ones that matter most. `--setup-auditd` adds the rest.
- **The alert is a pointer, not a verdict.** A clean-looking command by an admin isn't alerted; read `commands.log` for the whole picture.
- **The red team can stop auditd or delete logs.** LX-40 alerts if the audit service disappears; keep the off-box copy (`--alert-cmd`) as the real record.
- **Keep it hard to kill, not hidden.** Run it under `nohup`/`tmux`/`screen`, or as a plain systemd service, so it restarts — that beats trying to hide it, which looks like malware to the graders.

#### Problems and fixes

| What you see | Why | Fix |
| --- | --- | --- |
| `not running as root` warning, nothing logged | The auth and audit logs need root | `sudo` |
| `auditd is not logging commands` | No execve rule loaded | `--setup-auditd`, or add the printed `auditctl` line |
| Only `sudo` commands show up | Same as above | Turn on auditd |
| Your own admin work fills the console | Those accounts aren't on the allowlist | `--admin "name"`, or check the auto-detected list in the start line |
| The loop stopped when the session closed | Started without `nohup` | Use `nohup ... &`, `tmux` or `screen` |


---


### LX-43: Log shipping to Splunk (`dist/linux/LX-43-log-shipping.sh`)

Red team clears the logs on the box they're on. Logs that already went to the Splunk box are safe, and one search there shows every box. Run it on **the Splunk box first** (receive), **then every other Linux box** (send).

#### How to run it

```sh
sudo sh LX-43-log-shipping.sh --receive --apply                         # on the Splunk box
sudo sh LX-43-log-shipping.sh --send --to 10.0.0.20 --apply             # on every other box
sudo sh LX-43-log-shipping.sh --send --to 10.0.0.20 --apply --batch --logs all
```

Then open the port on the Splunk box (`LX-25`) and on any firewall between the boxes.

#### The questions

| Question | Answers | Flag |
| --- | --- | --- |
| What does this box do with logs? | `[s]end` its logs / `[r]eceive` (this IS the Splunk box); default r when Splunk is installed | `--send` / `--receive` |
| Port | typed, Enter = 1514 | `--port` |
| TCP or UDP? | `[t]` TCP (nothing lost, waits on disk) / `[u]` UDP | `--udp` |
| The Splunk box's address (send) | typed | `--to` |
| Which logs? (send) | `[a]ll` found / `[s]ystem only` / `[p]ick` one by one | `--logs all\|system` |
| Apply? | `[y]` / `[n]` | `--apply` |

#### What it does

- **Receive:** writes the Splunk app `etc/apps/bt_receiver` with a `[tcp://1514]` input (sourcetype syslog, the sender's address as host, `--index`, default main), then restarts Splunk (asked) and checks the port listens.
- **Send:** writes `/etc/rsyslog.d/90-bt-splunk.conf`:
  - the system logs: auth, syslog (`*.info`), mail, cron, kern
  - the service log files it finds, read with `imfile`: Apache/httpd/nginx access and error, `mail.log`/`maillog`, Dovecot, Roundcube errors and user logins, MySQL/MariaDB/PostgreSQL, `audit.log`, fail2ban, Splunk's own log
  - a disk-backed queue, so logs wait while Splunk is down and are sent later
- The config is checked with `rsyslogd -N1`, rsyslog restarts (the script makes sure a new rsyslog is running), and a test line `BT-LX43-TEST-HOST-TIME` is sent. **Search Splunk for it.**
- Another forward already in the rsyslog config is flagged: red team can send copies of your logs out too.

#### What it produces

In `logship-N/`: `output.txt`, `plan.txt`, `summary.txt` (with the test line and the search to run), `revert.sh`.

#### What to watch for

- **No test line in Splunk?** The port isn't open on the Splunk box, or `--receive` wasn't run there.
- **Plain syslog isn't encrypted.** Fine inside the team network.
- **A box with only journald:** `apt-get install rsyslog` first.
- **The receiver hasn't been run on a real Splunk yet.** Check `splunk list tcp` after the restart.


### LX-44: AppArmor confinement (`dist/linux/LX-44-apparmor.sh`)

AppArmor gives a program a list of what it may touch, and the kernel holds it to that list **even when the program is hacked**. With Apache confined, a web shell inside it cannot run `bash`, read `/root` or write outside the upload folders. It comes with Ubuntu and Debian; nothing to install.

#### How to run it

```sh
sudo sh LX-44-apparmor.sh                                  # status, dry run
sudo sh LX-44-apparmor.sh --apply        # step by step
```

Run it three times, with time between:

| Run | Step | What happens |
| --- | --- | --- |
| 1 | **complain** | The profile is loaded but **nothing is blocked**: AppArmor only logs what it would block. Now use the site: log in, buy, upload, read mail. |
| 2 | **learn** | The log lines are sorted. Normal ones (reads, logs, capabilities) are offered for the profile. Writes into the site code are asked on their own (an upload, or a web shell?). Programs it ran are **never** added: a shell, `curl`, `nc` or `python` is shown as `[!]`. So are secrets and system files (`/etc/shadow`, SSH keys, `/root`, writes into `/etc` or `/usr`) and dangerous capabilities (`sys_module`, `sys_admin`). Look at the site with SV-16 first. |
| 3 | **enforce** | Everything not in the profile is blocked. The service is checked right after; if it stopped answering, it goes back to complain on its own. A revert timer also runs. |

#### The services

| Service | Profile |
| --- | --- |
| apache2, nginx | The kit's `bt-apache2` / `bt-nginx`: sites read only, upload and cache folders writable (found on their own, more with `--writable DIR`), PHP mail through Postfix allowed, no shells |
| php-fpm | The package's own profile when there is one (Ubuntu 24.04), else `bt-php-fpm` |
| mariadb / mysql | The package's own profile when there is one, else `bt-mysqld` |
| postfix, dovecot | Not covered: they run many helper programs |

**Rocky and Fedora** use SELinux, not AppArmor: it says so, shows SELinux now and after a reboot (`SELINUX=` in `/etc/selinux/config`), how to turn it on when it is permissive, and that a disabled one needs a relabel and a reboot. Nothing is changed. **Alpine** has AppArmor off unless booted with it: it says so and stops (exit 0).

#### The questions

| State | Answers | Flag |
| --- | --- | --- |
| unconfined | `[c]omplain` (default) / `[e]nforce now` / `[k]eep` | `--batch` takes complain |
| complain | `[l]earn` (default when there are lines) / `[e]nforce` (default after 10 quiet minutes) / `[c]` stay | `--batch` |
| enforced | `[k]eep` (default) / `[c]` back to complain | `--batch` |
| Loaded, but the running service started before it | `[r]estart it` (default) / `[k]eep` | `--batch` |
| Add the normal lines? / the writes into the site code? | `[y]` / `[n]` (site code: default no) | `--batch` |
| Restart the service so it runs under its profile? | `[y]` / `[n]` | `--batch` |
| Apply? | `[y]` / `[n]` | `--apply` |

#### What it changes

Only with `--apply`: profiles in `/etc/apparmor.d/bt-*`, learned rules in `/etc/apparmor.d/local/bt-*`, `force-complain/` links for packaged profiles. Every change has an undo line; `revert.sh` puts back an enforce.

#### What it produces

In `apparmor-N/`: `output.txt`, `status.txt` (mode of each service), `plan.txt`, `learned-NAME.txt` (the sorted log lines), `summary.txt`, `revert.sh`.

#### What to watch for

- **Not yet tried on a real AppArmor kernel** (the test box is a container). Do the whole cycle on a practice VM first.
- **Enforcing too early breaks features quietly**: the home page loads but upload fails. The check only loads the home page. Click through everything before you confirm.
- A running service only picks up a new profile after a restart (asked).


### LX-46: Safe security updates (`dist/linux/LX-46-safe-updates.sh`)

Patches the holes red team will use (OpenSSH, OpenSSL, sudo, Apache, PHP, the database, mail) **one group at a time**, checking the services after each group and rolling a group back if it broke one.

#### How to run it

```sh
sudo sh LX-46-safe-updates.sh                                  # list, dry run
sudo sh LX-46-safe-updates.sh --apply        # step by step
sudo sh LX-46-safe-updates.sh --apply --batch   # security updates only, no kernel
```

#### What it does

| Step | What happens |
| --- | --- |
| Sources | Flags package sources that are not the distribution's (`[*]`) and sources with no signature check (`[!]`: anything served there gets installed). Flags held packages, pins that block updates (Pin-Priority below 0) and an apt proxy. |
| List | Pending updates grouped by service: ssh, openssl, sudo, web, php, database, mail, dns, ftp, system, kernel. Security apart. Full list in `updates.txt`. |
| Before each group | Saves the old packages in `old-packages/` (from apt's cache, else the mirror) and notes the listening ports (below 32768), the web page answer and the database. |
| Install | Your config files are always kept. A new default config from the package shows as `[*]` (`.dpkg-dist`); compare it later, don't copy it over. |
| After each group | Checks every port that listened before still listens, the web page and the database. If one stopped: roll back that group. |
| After all | Offers to restart services still running the old (unpatched) library code. Says if a reboot is needed. |

#### The questions

| Question | Answers | Flag |
| --- | --- | --- |
| Refresh the package lists first? | `[y]` / `[n]` | `--no-refresh` |
| Each held package | `[k]eep held` (default) / `[r]elease it` | `--batch` |
| Each group of security updates | `[u]pdate` (default) / `[s]kip` | `--batch` |
| The kernel (needs a reboot) | `[u]pdate` / `[s]kip` (default) | `--kernel` |
| Non-security updates | `[u]pdate` / `[s]kip` (default) | `--all` |
| A service broke after a group | `[r]oll back` (default) / `[l]eave` | `--batch` |
| Restart services on old code? | `[y]` / `[n]` | `--no-restart` |
| Apply? | `[y]` / `[n]` | `--apply` |

A group whose service is on the protected list is skipped.

#### What it produces

In `updates-N/`: `output.txt`, `sources.txt`, `updates.txt`, `versions-before.txt`, `versions-after.txt`, `old-packages/`, `summary.txt`. The rollback lines go in the undo log.

#### What to watch for

- **The rollback needs the old package.** If the mirror no longer has it, you are told and asked before that group (default skip).
- **The check sees ports, the web page and the database, not every feature.** Click through the site after the web or PHP group.
- **Updates restart services.** A scoring check in those seconds fails. Do it early, one group at a time.
- **Not yet tried on a real Red Hat box** (the dnf path) or with a real update and rollback; the tests use stand-ins.

