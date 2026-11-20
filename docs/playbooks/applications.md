# Applications manual

For whoever defends the scored applications on the Linux boxes: the web sites, the databases behind them, Gitea, the file share, RabbitMQ. Every command here uses the standalone scripts in `dist/applications/`. Copy them to the box and run them there with `sh` (as root).

Flókið applications:

| Box | Last octet | Application | Scripts |
| --- | --- | --- | --- |
| Gufu (Rocky) | .100 | Gitea | SV-45, SV-50 |
| Kolla (Alpine) | .30 | file share (Samba / NFS) | SV-46, SV-50 |
| Kvígindis (Ubuntu 24.04) | .44 | furniture help site | SV-01, SV-21, SV-20/42, SV-16 |
| Skerja (Alpine 3.23) | .97 | tickets | SV-01, SV-21, SV-20/42, SV-16 |
| Thorska (Fedora 44) | .231 | Home Manager | SV-01, SV-21, SV-50 |
| Djupi (Mint 22.3) | .222 | POS | SV-01, SV-21, SV-20/42, SV-16 |
| Haf (Lubuntu 22) | .67 | "Wabbit" (RabbitMQ?) | SV-50 |

## How every script works

- **Dry run first.** Without `--apply` nothing changes. Read the plan, then run again with `--apply`.
- **Questions.** One at a time, `[?] Question [Y/n]`; Enter takes the answer in capitals; every question has a flag; `--batch` takes the defaults.
- **The box question.** "Which box is this?" is guessed from the files (`This box looks like: gitea`); Enter takes the guess.
- **Levels.** SV-20, SV-21 and SV-30 ask how far to go: `safe` (cannot break anything), `service` (might change how a scored service behaves: checked after, put back if it broke), `access` (could remove a service).
- **The site is checked after.** Every script that changes a web site, database or service tests it afterwards (login page, test search, port) and **puts everything back** if it broke.
- **Revert timer.** 120 s; keep the changes only after you checked the service from outside.
- **Results** in `~/bt-out/<name>-N/`: `output.txt`, `summary.txt`, `plan.txt`, the tables as `.txt`, `revert.sh`.
- **Protected list** `~/bt-out/protected.txt`: the scored ports, services and the accounts the scoring engine logs in with (database user, Gitea user, share user). A change to anything on it is refused.

## Before you start (2 minutes)

1. Copy the kit to the box: `scp -r dist/applications root@192.168.220.100:/root/kit/`.
2. Write `~/bt-out/protected.txt` with the scored service and its login, e.g. `account shopuser the site logs in to MySQL as this`.
3. Agree with the Linux person who runs what on the box: they run the LX scripts (passwords, SSH, firewall), you run the SV scripts.

## The first 15 minutes (each application box)

| When | Script | What it does | Command |
| --- | --- | --- | --- |
| 0-2 min | **SV-01** Web and DB enum | Every web server, site, URL path and the folder or app behind it, PHP, web roots, files that should not be there (web shells, dumps, `.git`), every database account. Changes nothing | `sh SV-01-web-db-enum.sh` |
| 2-4 min | **SV-14** Database backup | A dump of every database, with hashes and the restore commands | `sh SV-14-db-backup.sh` |
| 2-4 min | **SV-15** Site backup | A copy of every site's files and config: `--check` later shows what changed, `--restore` puts it back | `sh SV-15-site-backup.sh --backup --batch` |
| 4-6 min | **SV-50** Service recovery | Is every scored service up, and if not, why (stopped, broken config, port taken, firewall, SELinux, containers) | `sh SV-50-service-recovery.sh` |
| 6-15 min | the hardening script for this box | see below | |

The hardening script for each box:

| Box | Script | Command |
| --- | --- | --- |
| Gitea (Gufu) | **SV-45** Gitea hardening: install page, sign-ups, git hooks, migrations and webhooks into the network, planted hooks | `sh SV-45-gitea-hardening.sh --apply` |
| File share (Kolla) | **SV-46** File share hardening: SMB1, NTLMv1, lines that run programs as root, guest write, NFS `no_root_squash` | `sh SV-46-fileshare-hardening.sh --apply` |
| Web app with a database | **SV-21** PHP and web app hardening, then **SV-20** database hardening, then **SV-42** database passwords | `sh SV-21-web-hardening.sh --apply --level service` |
| Any box with FTP, telnet, SNMP | **SV-30** Service hardening | `sh SV-30-service-hardening.sh --apply` |

What to look at after each one:

- **SV-01:** the `SUMMARY`. `[!]` web shells, dumps, `.env` or `.git` in a web root, database accounts with no password or reachable from anywhere. `apps.txt` names which database account each app uses: **put it on the protected list** before anything changes passwords.
- **SV-14 / SV-15:** where the backup is; copy it off the box.
- **SV-50:** `[!]` lines say why a service is down and the fix it offers.
- **The hardening scripts:** the last section says if the site, login page or service still answers. If it says `PUT BACK`, nothing changed: read why.

## After the first 15 minutes

| Script | What it does | When | Command |
| --- | --- | --- | --- |
| **SV-16** Web shell hunter | Finds web shells by what is in the files; quarantines them; `--watch` keeps looking | Right after, then leave it watching | `sh SV-16-webshell-hunter.sh --apply`, later `--watch 60 --auto-quarantine --apply` |
| **SV-42** Database passwords | New passwords for every database account, the app config updated in the same step, the site checked | When the site works and is backed up | `sh SV-42-db-passwords.sh --apply` |
| **SV-20** Database hardening | Anonymous accounts, remote root, FILE rights, backdoor functions, bind address | After SV-42 | `sh SV-20-db-hardening.sh --apply --level service` |
| **SV-15 --check** | What changed in the sites since the backup | Every 30 min, and after any alert | `sh SV-15-site-backup.sh --check --batch` |
| **SV-32** TLS check | Expired or swapped certificates, keys anyone can read, old TLS | When calm | `sh SV-32-tls-check.sh --apply` |
| **SV-50 --watch** | Checks every 30 s and restarts what goes down | Leave it running | `nohup sh SV-50-service-recovery.sh --watch 30 --auto-restart --apply &` |
| **SV-31, SV-40, SV-41** | Mail: backdoors in the mail system, mail passwords, Roundcube | Only on a mail box | see the deep dives |
| **SV-44** | Splunk backdoors and passwords | Only on a Splunk box | see the deep dive |

### When something happens

| What you see | Run |
| --- | --- |
| A scored service went red | `sh SV-50-service-recovery.sh --apply` |
| The site was defaced or files are missing | `sh SV-15-site-backup.sh --check`, then `--restore --apply` |
| A web shell or odd PHP file | SV-16 |
| The database is gone or wiped | SV-14's `RESTORE.txt` has the command for each dump |
| The site says "database error" after a password change | SV-42 puts it back by itself if its own test fails; otherwise its `revert.sh` |
| Gitea login page broken after a change | SV-45 put it back if it noticed; else `sh ~/bt-out/gitea-N/revert.sh --force` |
| Gitea blocked by SELinux (Gufu) | SV-50 names the denial and `restorecon` |
| A container stopped | SV-50 asks to start it (the containers question) |

### Notes for this network

- **Gitea (Gufu):** SV-45 asks before closing sign-ups: say no if the scoring engine creates accounts. SV-50 reads Gitea's port from `app.ini`.
- **File share (Kolla):** SV-46 never turns off guest access by default (the scoring engine may connect as a guest).
- **Alpine (Skerja, Kolla):** OpenRC services, PHP in `/etc/php83`, Apache config in `/etc/apache2/conf.d`. The scripts handle all of it.
- **RabbitMQ (Haf) and Home Assistant:** SV-50 checks them (5672 and the management page on 15672; 8123).

## Deep dive: every application script

Each section below is the full reference for one script: how to run it, every question and its flag, what each check means, what it writes, and what to do when something goes wrong. They are in the order above.
