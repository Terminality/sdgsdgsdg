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
