<!-- Built by tools/role-manuals.sh from docs/playbooks/applications.md and docs/MANUAL.md. Edit those, then run it. -->

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

Scripts: [SV-01](#sv-01-web-and-database-enum-distapplicationssv-01-web-db-enumsh) [SV-14](#sv-14-database-backup-distapplicationssv-14-db-backupsh) [SV-15](#sv-15-site-backup-and-restore-distapplicationssv-15-site-backupsh) [SV-50](#sv-50-service-recovery-distapplicationssv-50-service-recoverysh) [SV-45](#sv-45-gitea-hardening-distapplicationssv-45-gitea-hardeningsh) [SV-46](#sv-46-file-share-hardening-samba-and-nfs-distapplicationssv-46-fileshare-hardeningsh) [SV-21](#sv-21-php-and-web-app-hardening-distapplicationssv-21-web-hardeningsh) [SV-20](#sv-20-database-hardening-distapplicationssv-20-db-hardeningsh) [SV-42](#sv-42-database-password-rotation-distapplicationssv-42-db-passwordssh) [SV-30](#sv-30-service-hardening-ftp--legacy-distapplicationssv-30-service-hardeningsh) [SV-16](#sv-16-web-shell-hunter-distapplicationssv-16-webshell-huntersh) [SV-32](#sv-32-tls-certificate-check-distapplicationssv-32-tls-checksh) [SV-31](#sv-31-mail-tamper-check-distapplicationssv-31-mail-tampersh) [SV-40](#sv-40-mail-password-rotation-distapplicationssv-40-mail-passwordssh) [SV-41](#sv-41-webmail-roundcube-hardening-distapplicationssv-41-roundcube-hardeningsh) [SV-44](#sv-44-splunk-hardening-and-passwords-distapplicationssv-44-splunk-hardeningsh) 

### SV-01: Web and database enum (`dist/applications/SV-01-web-db-enum.sh`)

Shows what web sites and databases are on a Linux or Unix host and what is wrong with them: the web servers, every site, **which URL path serves which folder or app**, **which languages and app servers run** (PHP, Python, Node.js, Java, Ruby, .NET), the web roots, PHP settings, web apps and databases. Run it on every box that serves a web site or holds a database, right after the Linux enum. It only reads, and never records a password.

Same look as the Linux enum: numbered sections with flags shown live (`[!] FIX` red, `[*] LOOK` yellow), what was found in green, and a summary at the end.

#### The questions

Enter takes the default, and a flag answers each one ahead of time. `--batch` takes all the defaults.

| Question | Default | Flag |
| --- | --- | --- |
| Look at everything? (no = pick the sections) | yes | `--only` / `--skip` |
| Search file contents for web shells and phpinfo pages? | yes | `--fast` (no) / `--deep` (yes) |
| Other web folders to look in? | none | `--webroot DIR` |
| Log in to the databases (read-only)? | yes | `--no-db` / `--db` |

#### How to run it

```sh
sudo sh SV-01-web-db-enum.sh --out /root/bt-out
sudo sh SV-01-web-db-enum.sh --out /root/bt-out --fast                 # skip the web shell content search
sudo sh SV-01-web-db-enum.sh --webroot /opt/app/public                   # a web root the configs don't show
sudo sh SV-01-web-db-enum.sh --only mysql --mysql-cnf /root/my.cnf       # when root can't log in through the socket
```

| Option | What it does |
| --- | --- |
| `--only` / `--skip` | Run or leave out sections: `servers sites paths runtimes webroots php apps mysql postgres datastores` |
| `--fast` | Skip reading file contents (the web shell and phpinfo search). Names, owners and settings are still checked |
| `--webroot DIR` | Also scan this folder as a web root. Repeat for more |
| `--apache-conf FILE` / `--nginx-conf FILE` | Read these config files directly instead of asking the server which files it uses. For when `apachectl` or `nginx` is missing, broken or replaced |
| `--mysql-cnf FILE` | A MySQL client file with a user and password (a `[client]` section). Make it mode 600 and delete it after |

Run it as root. As a normal user it still runs, but it cannot read most configs, log in to PostgreSQL, or see every file; the section table marks those sections `partial`.

**How it logs in to the databases.** MySQL/MariaDB: `--mysql-cnf` if given, then `root` through the local socket (normal on Debian and Ubuntu), then the Debian maintenance account in `/etc/mysql/debian.cnf`, then the client's own defaults. PostgreSQL: as the `postgres` account through the local socket. Queries are SELECT and SHOW only.

#### What it produces

In `<out>/web-enum-N/`: `output.txt` (the screen without colour), `summary.txt`, `run.txt`, and a readable `.txt` table for each of these:

| File | Contents |
| --- | --- |
| `summary.txt` | Web servers, sites, web roots, apps, databases; a section table; HIGH and MED flags |
| `servers.txt`, `fpm_pools.txt` | Each web server and PHP-FPM pool: version, running or not, the account it runs as |
| `sites.txt` | Each Apache virtual host and nginx server block: name, listen address, TLS, web root, config file and line |
| `paths.csv` | Each URL path and what serves it: web roots, aliases, CGI folders, proxies to an app (`ProxyPass`, `proxy_pass`), PHP and uWSGI handlers, status pages |
| `runtimes.csv` | Languages installed (with version), app servers running (gunicorn, uwsgi, Node, Java/Tomcat, puma, dotnet ...), app folders (`package.json`, `manage.py`, `Gemfile`, `.war` ...), and unknown programs on web ports |
| `webroots.txt` | Each web root: owner, mode, file counts, files owned by the web account, world-writable files |
| `files.txt` | Every file that should not be in a web root, with its kind (`webshell`, `upload_code`, `dump`, `env`, `vcs`, `phpinfo`, `config_readable`, `backup`) |
| `php.txt` | The risky settings of each `php.ini`, after its `conf.d` overrides |
| `apps.csv` | Each web app found: version, folder, config file, database name, user and host (never the password) |
| `db_users.txt` | MySQL and PostgreSQL accounts: how they log in, empty password, superuser, file access, grant rights |
| `db_settings.txt`, `db_databases.txt`, `db_objects.txt` | Server settings; databases with size; triggers, events, routines and user-defined functions |
| `pg_hba.txt` | PostgreSQL login rules |
| `datastores.txt` | Redis, memcached, MongoDB, Elasticsearch and CouchDB: where they listen and whether they answer without a password |

#### What it flags

| Severity | When |
| --- | --- |
| HIGH | A development or debug server running (`manage.py runserver`, `flask run`, `php -S`, `node --inspect`, `npm run dev`, Java debug agent): anyone who reaches it can run code; a URL path that serves `/`, `/etc`, `/root` or logs; a file that looks like a web shell; a program file in an upload or media folder; a database dump or `.env` inside a web root; a web server or PHP-FPM pool running entirely as root; `allow_url_include` on; a database account with no password; MySQL root or an admin account allowed from other hosts; a user-defined function (the `lib_mysqludf_sys` backdoor); a PostgreSQL `trust` rule for network logins; logging in to MySQL with no name or password; a Redis or similar store open to the network without a password |
| MED | A server-status page open to everyone; an unknown program serving web traffic on a web port; an app server running as root; directory listing on; a web root owned by the web account; world-writable files in a web root; `.git` folders, backups and phpinfo pages in a web root; app configs every local account can read; MySQL `secure_file_priv` empty; accounts with the FILE privilege; anonymous MySQL accounts; triggers and scheduled events; extra PostgreSQL superusers; `trust` for local logins; a database or data store listening on a network address |
| LOW | Server version shown in headers; PHP `display_errors`, `expose_php` on, `disable_functions` empty; MySQL `local_infile` on; accounts allowed from any address; PostgreSQL `password` (clear text) logins |

#### What to watch for

- **Read before you delete.** A web shell flag means the file matched a known pattern. Read it, copy it for the incident report, then quarantine it. A security plugin's signature list can also match.
- **"Owned by the web account" is common and still worth fixing.** Many WordPress installs are owned by `www-data` so plugins can update. It is also how one flaw becomes a defaced site. Changing owners can break uploads and updates, so it is a fix for later, not the first 15 minutes.
- **Database accounts the apps use are listed in `apps.txt`.** Before changing a database password, find which app uses that account and update its config at the same time, or the site goes down.
- **Triggers, events and user-defined functions are rare in competition apps.** One that the app did not create is a strong sign of red team persistence.
- **Some checks need tools.** Without a MySQL client or `psql` the database accounts are not listed; without `redis-cli` or `curl` the "answers without a password" column says `not checked`.

#### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `MySQL/MariaDB: found, but could not log in` | root needs a password and there is no `debian.cnf` | Give `--mysql-cnf` with a working user and password |
| `accounts not readable with default client settings` | Logged in with an account that cannot read `mysql.user`, usually as a normal user | Run as root |
| `PostgreSQL: found, but could not log in` | Not root, or the `postgres` account cannot log in through the socket | Run as root; check `pg_hba.conf` has a `local ... peer` line for postgres |
| A site is missing from `sites.csv` | Its config is in a file Apache or nginx loads in an unusual way | Compare with `raw/apache_S.txt` or `raw/nginx_T.txt`; add its folder with `--webroot` |
| The run is slow on a large site | The content search reads every PHP file under 2 MB | `--fast`, or `--skip webroots` and run that section on its own later |
| `sites.txt` empty, but a web server is running | `apachectl` or `nginx` missing or not in PATH | Point at the configs with `--apache-conf` / `--nginx-conf` |

---


### SV-14: Database backup (`dist/applications/SV-14-db-backup.sh`)

Dumps every database on a Linux or Unix host, checks each dump can be read back, hashes them, and can copy them off the box. Copying a running database's files does not give a usable backup; a dump does. Run it in the first minutes, next to the Linux backup (LX-31).

#### How to run it

```sh
sudo sh SV-14-db-backup.sh --out /root/bt-out
sudo sh SV-14-db-backup.sh --out /root/bt-out --copy-to admin@10.0.0.5:/srv/backups/db01/
sudo sh SV-14-db-backup.sh --out /root/bt-out --mysql-cnf /root/my.cnf --keep 3
```

| Option | What it does |
| --- | --- |
| `--only mysql,postgres,sqlite` | Which engines (default: all that are found) |
| `--mysql-cnf FILE` | MySQL client file with a user and password (`[client]` section), when root cannot log in through the socket |
| `--sqlite FILE` | Also back up this SQLite file (repeat) |
| `--max-mb N` | Refuse if the databases add up to more than N MB (default 4096); also refuses when the disk is too full |
| `--keep N` | Keep only the newest N SV-14 backups of this host in the output folder |
| `--copy-to DEST` | Copy the dumps, hashes and restore notes off the box with `scp` |

It changes nothing in the databases or on the host, so it needs no `--apply`.

#### What it dumps

| Engine | Files | How |
| --- | --- | --- |
| MySQL / MariaDB | `mysql_<db>.sql.gz`, one per database, including `mysql` (accounts and grants) | `mysqldump`/`mariadb-dump --single-transaction --routines --triggers --events`; checked with `gzip -t` and the "Dump completed" line |
| PostgreSQL | `pg_globals.sql.gz` (roles), `pg_<db>.dump` per database | `pg_dumpall --globals-only` and `pg_dump -Fc` as the `postgres` account; checked with `pg_restore -l` |
| SQLite | `sqlite_<n>_<name>` | Files in web roots, `/var/lib/grafana` and `/opt` that start with the SQLite header, and `--sqlite` files; `sqlite3 .backup` when available, else a copy |

Login for MySQL follows SV-01: `--mysql-cnf`, then root through the socket, then `/etc/mysql/debian.cnf`, then the client's defaults. It never prompts.

#### What it produces

In `<out>/SV-14_<host>_<UTC time>/` (mode 700, files 600): the dumps, `SHA256SUMS`, `dumps.txt` (engine, database, file, size, status), `RESTORE.txt` with the commands for each dump, and `summary.txt`.

#### Restoring

```sh
cd /root/bt-out/SV-14_db01_<time>
sha256sum -c SHA256SUMS
gzip -dc mysql_wordpress.sql.gz | mysql                                           # REPLACES the database
sudo -u postgres pg_restore --clean --if-exists -d shopdb < pg_shopdb.dump         # REPLACES its objects
sudo -u postgres createdb restore_check && sudo -u postgres pg_restore -d restore_check < pg_shopdb.dump   # compare first
```

PostgreSQL dumps are fed on stdin (`<`): the `postgres` account cannot open files in the private backup folder itself. `RESTORE.txt` also shows how to load a MySQL dump under another name to compare, and how to cut one table out of a dump.

#### What to watch for

- **The dumps hold every password hash and every row**, including the `mysql` system database. Keep them private and copy them only to the team's machine.
- **Restoring a whole database undoes everything since the dump**, including legitimate changes (orders, posts). Restore one table, or compare first, when you can.
- **The `mysql` database dump restores accounts too.** Load it only to undo account changes, and change the passwords again afterwards.
- **MyISAM tables** are dumped without a lock; one that is written during the dump can be a moment inconsistent.
- **MongoDB, Redis and MSSQL** are not covered.

#### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `MySQL/MariaDB is running but could not log in` | root needs a password and there is no `debian.cnf` | `--mysql-cnf` with a working account |
| `PostgreSQL is running: run as root` | Not root | `sudo` |
| A MySQL dump `FAILED` | Disk full, a crashed table, or no rights to a database | Read the log; `mysqlcheck` the database; check free space |
| `the databases add up to about N MB` (exit 3) | Bigger than `--max-mb` | Raise `--max-mb`, or `--out` on a bigger disk |
| `pg_restore: could not open input file ... Permission denied` | Passing the file name to `pg_restore` run as postgres | Feed it on stdin: `pg_restore ... < FILE` |
| SQLite marked "may be inconsistent" | No `sqlite3`, and the app may write while it is copied | Install `sqlite3`, or stop the app for the copy |

---


### SV-15: Site backup and restore (`dist/applications/SV-15-site-backup.sh`)

Keeps every web site restorable. It backs up each site's files and database, checks a site against the backup at any time, and puts back **only what changed** when the red team defaces a page, deletes files, plants a web shell or wipes the database. Your own fixes elsewhere stay put.

**Back up after cleaning.** A web shell that is already there goes into the backup and looks normal to the check. Run SV-01 first.

#### How to run it

```sh
sudo sh SV-15-site-backup.sh                                   # asks what to do
sudo sh SV-15-site-backup.sh --backup --batch                  # back up every site
sudo sh SV-15-site-backup.sh --check --batch                   # what changed? (changes nothing)
sudo sh SV-15-site-backup.sh --restore                         # dry run: shows what it would put back
sudo sh SV-15-site-backup.sh --restore --apply
```

#### The questions

| Question | Answers | Flag |
| --- | --- | --- |
| What do you want to do? | `[b]` back up, `[c]` check, `[r]` restore (default: back up if there is no backup yet, else check) | `--backup` / `--check` / `--restore` |
| Which sites? (backup) | all, or names | `--site NAME` |
| Back up each site's database too? | yes / no | `--db` / `--no-db` |
| Copy the backup off the box? | an scp destination | `--copy-to DEST` |
| Per site (restore) | `[a]` all back to the backup, `[f]` files only, `[q]` quarantine new files only, `[n]` nothing | `--what all/files/new/none` |
| Put the database back too? (restore) | yes / no (default no) | `--restore-db` / `--no-restore-db` |

#### What it does

- **Finds the sites** from the Apache and nginx configs, every folder in `/var/www`, and `--webroot DIR`.
- **Finds each site's database** in the app's own config: WordPress, Joomla, Drupal, PrestaShop, OpenCart, Magento, Roundcube or `.env`. MySQL/MariaDB and PostgreSQL are dumped. SQLite files are already in the file archive. A database on another host is reported, not dumped.
- **Backup** writes `site-backup-N/`. For each site: `files.tar.gz`, a hash of every file (`files.sha256`) and the database dump. Once per box: the Apache, nginx and PHP configs. The folder is mode 700, because it holds dumps and passwords.
- **Check** compares each site with the newest backup (or `--from DIR`):
  - **CHANGED** files: a page means "defaced?", code means "backdoor added?", and a changed `.htaccess` is HIGH
  - **DELETED** files
  - **NEW** files: a new `.php`/`.jsp`/`.asp`/`.sh` is HIGH ("web shell?"), anything else LOW
  - changed web server and PHP config files
- **Restore** does the same comparison, then for each site puts back changed and deleted files (owners and modes kept), moves new files to quarantine, and loads the database if you said so. The current files and database are saved first, and a revert timer runs. Afterwards it checks again that the site matches. A site whose files are unchanged is still offered a database restore.

#### What to watch for

- **Real uploads since the backup show as NEW.** They are moved to quarantine, not deleted, so look before saying `[a]`, or use `[f]`.
- **Database restore loses everything since the backup**, including real orders or mail. The current database is saved in `before/` and the revert puts it back.
- **Web server configs are reported, not restored,** because a bad config breaks the site on restart. `RESTORE.txt` in the backup shows how to put one back and test it.
- **Permissions are not compared,** only content. LX-40 watches for permission changes.
- **Back up again after big fixes,** so the check compares against the clean state. `--keep N` drops old backups.

#### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `no site backup found` (exit 3) | No `--backup` yet in this `--out` | Run `--backup` first, or `--from DIR` |
| `database ...: could not log in` | root cannot log in through the socket | `--mysql-cnf FILE` with a `[client]` user and password |
| The backup is too big | Media or caches | `--exclude '*/cache/*'`, or raise `--max-mb` |
| A site is missing | Its folder is outside the usual places | `--webroot DIR` |

---


### SV-50: Service recovery (`dist/applications/SV-50-service-recovery.sh`)

Run this when a scored service goes red. It checks every service on the box the same way, finds **why** it's down, and offers the fix. A plain restart often fails because red team broke something underneath.

Services: web (apache2, httpd, nginx), php-fpm (also Alpine's `php-fpm83`), database (mariadb, mysql, postgresql), mail (dovecot, postfix), splunk, ssh, time (chrony, ntp), file shares (Samba, NFS), Gitea (or Forgejo; its port from `HTTP_PORT` in `app.ini`, else 3000), RabbitMQ (5672, and the management page on 15672), Home Assistant (8123), the Docker service, and **Docker or Podman containers**. Only the ones installed are checked. With two web servers, only the one in use counts. Works with systemd, OpenRC (Alpine) and SysV.

#### How to run it

```sh
sudo sh SV-50-service-recovery.sh                                    # check everything, dry run
sudo sh SV-50-service-recovery.sh --apply          # check and fix (asks each fix)
sudo sh SV-50-service-recovery.sh --apply --batch --services web,mysql
sudo sh SV-50-service-recovery.sh --watch 30 --auto-restart --apply   # keep it running
```

#### The questions

| Question | Answers | Flag |
| --- | --- | --- |
| Which box is this? | `[s]plunk [w]ebmail [e]comm [f]ileshare [g]itea [b] web [o]ther` (guessed) | `--box` |
| Check which services? | `[a]ll` found / `[s]` only the scored ones for this box | `--services` |
| Check the containers too? | `[Y]` / `[n]` (only when Docker or Podman has containers) | `--no-containers`, or `containers` in `--services` |
| Each fix | `[y]` / `[n]` | `--fix KINDS` answers yes for those kinds |

#### What it checks, per service

| Check | Found | Fix offered |
| --- | --- | --- |
| Running? | stopped, failed | start / restart (**only if the config test passes**) |
| Masked / disabled at boot? | masked, or disabled when scored (Alpine: not in an OpenRC runlevel) | unmask, enable (`rc-update add` on Alpine) |
| Config loads? | `apache2ctl -t`, `nginx -t`, `php-fpm -t`, `postfix check`, `doveconf`, `sshd -t`, `testparm` (Samba) | none: error lines shown, never restarted on a broken config |
| Port | another program holds it | stop it (default yes if it runs from /tmp, /dev/shm or a deleted file) |
| Answers? | HTTP status (5xx with a DB error points at the database; Gitea too), IMAP/SMTP/SSH banners, DB ping, chronyc, Samba (`smbclient -L`), NFS (`showmount -e`) | restart if running but not answering |
| Firewall | iptables DROP/REJECT on the port; nftables shown; a port **firewalld** (Rocky, Fedora) or **ufw** (Ubuntu, Mint) does not allow | remove the rule; open the port in firewalld (now and permanent) or ufw |
| Tampered | config changed in the last 2 hours (also `/etc/samba`, `/etc/exports`, `/etc/gitea`), systemd override (`ExecStart=/bin/true`), package files changed (`dpkg -V`, `rpm -V`) | shown with what to do (SV-15 restore, `apt-get install --reinstall`, `dnf reinstall`) |

**Containers:** each one that stopped is shown with its last log lines and the fix is asked: start it (default yes; default **no** when it ended with exit 0, which may be a one-off job), unpause a paused one. One that keeps restarting is shown with its log only. After a start it must be running; the undo stops it again.

**For the whole box:** disk or inodes full, `/tmp` not writable or wrong mode, programs killed for lack of memory.

Fixes run in order: unmask, firewall, kill, enable, start, containers. Each fixed service is tested again (up to 10 s).

#### Watch mode (the automation)

`--watch 30` checks every 30 seconds and prints a line the moment a service goes down or comes back, with the reason. Everything is also logged to `watch.txt`.

Adding `--auto-restart --apply` restarts what goes down, but only if its config test passes. It stops after 3 restarts in 10 minutes and tells you, so a crash loop isn't hidden. Run it in a spare terminal or `tmux` for the whole competition.

#### Safety

- Dry run unless `--apply`. A protected list is needed like every change script (`--no-protected` to skip).
- **No revert timer**: these fixes bring services up, and undoing them would take them down again. Unmask, enable and firewall changes still have undo lines (`revert.sh`).
- A config error is never "fixed" by guessing: it's shown so you can fix it, or restore it with SV-15.

#### What it produces

In `recovery-N/`: `output.txt`, `status.txt` (every check for every service), `summary.txt`, `watch.txt` (with `--watch`), `revert.sh`.

#### What to watch for

- **Up here, down on the scoreboard:** the box answers but something in between doesn't. Check the network firewall (NW scripts) and that the scoring IP isn't banned (`SV-26 --unban-all`).
- **A defaced or wiped site still answers 200.** Use `SV-15 --check`.
- **A program on the port that is yours** (a second web server, a proxy): answer `n` to stopping it.

#### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `config test FAILS` | A bad config line (red team, or a hardening script) | Fix the line shown, or `SV-15 --restore`, then run again |
| `still DOWN` after start | Something the checks don't cover | The log lines under it; `journalctl -u NAME` |
| `HTTP 500 ... database error` | The database is down or its password changed | Fix mysql first (this script), or SV-42's undo |
| `restarted 3 times in 10 minutes` | It crashes right after starting | Run without `--watch` to see why |


### SV-45: Gitea hardening (`dist/applications/SV-45-gitea-hardening.sh`)

Gitea (or Forgejo) is scored: people log in, browse and clone. It is also an easy way in. This reads `app.ini` and the repositories, shows what is wrong and offers the fixes. Run it on the Gitea box (Gufu).

#### How to run it

```sh
sudo sh SV-45-gitea-hardening.sh                                  # look + dry run
sudo sh SV-45-gitea-hardening.sh --apply        # asks about each fix
sudo sh SV-45-gitea-hardening.sh --apply --batch --skip no-register
```

#### What it shows

| Section | Shows |
| --- | --- |
| 1/4 what this Gitea is | config file, version, web port, git over SSH (sshd or Gitea's own), the user it runs as, public repositories, plain HTTP, Actions |
| 2/4 settings | the install page (HIGH), sign-ups (MED), git hooks users can add (HIGH), migrations into the inside network (HIGH), webhooks into the inside network (MED), `app.ini` readable by everyone (MED) |
| 3/4 hooks and admins | hooks in repositories that Gitea did not put there (HIGH: they run on every push), admin accounts (sqlite; otherwise the command to list them) |
| 4/4 questions and changes | one question per fix, then apply |

#### The fixes (each asked; Enter = yes)

| Fix | What it does |
| --- | --- |
| `install-lock` | `[security] INSTALL_LOCK = true` |
| `no-register` | `[service] DISABLE_REGISTRATION = true`. Say no if the scoring engine signs up users |
| `git-hooks` | `[security] DISABLE_GIT_HOOKS = true` |
| `local-migrate` | `[migrations] ALLOW_LOCALNETWORKS = false` |
| `webhook-local` | `[webhook] ALLOWED_HOST_LIST = external` |
| `repo-hooks` | Quarantines each planted hook (Gitea's own and git's `.sample` files stay) |
| `config-perms` | `app.ini` to the Gitea user's group, mode 640 |

Settings are written in their section with a `; BT SV-45` line above them (Gitea ignores comments at the end of a line). Plain HTTP and public repositories are only reported: the scoring engine may need them.

#### Safety

- Dry run unless `--apply`. Revert timer (120 s).
- After the changes: Gitea is restarted, then **the login page must load again within 20 seconds**, or everything is put back and Gitea restarted.
- Nothing is printed from `app.ini` except the setting names: no passwords or keys.

#### With the other scripts

LX-22 keeps Gitea's SSH keys and the git user; LX-25 `--box gitea` keeps ports 3000, 2222, 80, 443 open; SV-50 `--box gitea` brings it back if it goes down; SV-16 for web shells. All of them guess `gitea` as the box when they find `app.ini`.


### SV-46: File share hardening (Samba and NFS) (`dist/applications/SV-46-fileshare-hardening.sh`)

A file share is scored: someone connects and reads or writes a file. It is also an easy way in. This reads `smb.conf`, `/etc/exports` and `/etc/exports.d/*.exports`, shows every share and what is wrong, and offers the fixes. Run it on the file-share box (Kolla).

#### How to run it

```sh
sudo sh SV-46-fileshare-hardening.sh                                  # look + dry run
sudo sh SV-46-fileshare-hardening.sh --apply        # asks about each fix
sudo sh SV-46-fileshare-hardening.sh --apply --batch --skip root-squash
```

#### What it shows

| Section | Shows |
| --- | --- |
| 1/3 Samba | SMB1 (HIGH), lanman auth (HIGH) and NTLMv1 (MED), who may connect, `include` files, **lines that run programs** (`root preexec`, `postexec`, `magic script`, `add user script` ...: HIGH), wide links, every share (path, read-write or read-only, guests or users), guest shares anyone can write to (HIGH) or read (MED), `force user = root`, `admin users`, share folders anyone can write to, `smb.conf` writable by everyone (HIGH), the Samba users (`pdbedit`) |
| 2/3 NFS | every export and who gets it, `no_root_squash` (HIGH), `insecure` (MED), read-write to everyone (MED) |
| 3/3 questions and changes | one question per fix, then apply |

#### The fixes (each asked; Enter = the default)

| Fix | Default | What it does |
| --- | --- | --- |
| `smb1-off` | yes | `server min protocol = SMB2_02` |
| `ntlmv1-off` | yes | `ntlm auth = ntlmv2-only`, `lanman auth = no` |
| `exec-lines` | yes | Comments out each line that runs a program (`# BT SV-46 off: ...`) |
| `wide-links` | yes | `wide links = no`, `allow insecure wide links = no` in those shares |
| `guest-write` | **no** | `guest ok = no` on shares anyone can write to. Guests can no longer connect: say yes only if the scoring engine logs in with a user. `--only guest-write` chooses it |
| `conf-perms` | yes | `smb.conf` not writable by other users |
| `root-squash` | yes | NFS `no_root_squash` becomes `root_squash` |
| `nfs-insecure` | yes | NFS `insecure` is dropped |

Who may connect (`hosts allow`, the NFS client list) is **only reported**: only you know the team's addresses.

#### Safety

- Dry run unless `--apply`. Revert timer (120 s).
- After the changes: `testparm` must pass, Samba re-reads its config (`smbcontrol`, else a restart of smbd / smb / samba) and **must still listen on 445**; `exportfs -ra` must work. If not, everything is put back.

#### With the other scripts

LX-25 `--box fileshare` keeps 139, 445, 137, 138, 2049, 111 open; SV-50 `--box fileshare` brings Samba and NFS back if they go down; LX-45 scans the shared folders for malware. All of them guess `fileshare` when they find a share.

### SV-21: PHP and web app hardening (`dist/applications/SV-21-web-hardening.sh`)

Makes the web apps hard to take over and makes an uploaded web shell useless, without taking the site down. It finds the apps first (WordPress, Joomla, Drupal, PrestaShop, OpenCart, Magento, Roundcube), then offers each fix, graded like SV-20. After the changes, the site must still load, or everything is put back.

**Back up first** (SV-15).

#### How to run it

```sh
sudo sh SV-21-web-hardening.sh                                         # dry run, asks
sudo sh SV-21-web-hardening.sh --apply --level service
sudo sh SV-21-web-hardening.sh --apply --batch --level safe --url http://127.0.0.1/shop/
```

#### The questions

| Question | Answers | Flag |
| --- | --- | --- |
| Which box is this? | `[s]plunk [w]ebmail [e]comm [f]ileshare [g]itea [b] web [o]ther` (guessed from the box's files) | `--box` |
| How far should I go? | `[s]afe`, `[v]` service, `[a]ccess` | `--level` |
| Each fix | `[y]` do it / `[n]` skip it (access-level fixes default to no) | `--only` / `--skip` |
| Each new WordPress admin | `[k]eep` / `[d]emote` to subscriber | `--admins` |
| Apply these changes? | `[y]` / `[n]` | `--batch` |

#### The fixes

| Fix | Level | What it does |
| --- | --- | --- |
| `php-urlinclude` | safe | `allow_url_include = Off` (no including code from another server) |
| `php-errors` | safe | `display_errors = Off`, `log_errors = On` (error pages show paths and SQL) |
| `php-expose` | safe | `expose_php = Off` (no PHP version in the headers) |
| `app-config` | safe | App config files (they hold the database password) become `root:www-data 640` |
| `wp-fileedit` | safe | WordPress: `DISALLOW_FILE_EDIT`, no editing theme/plugin code from the admin panel |
| `upload-nophp` | service | PHP can't run in upload folders: an uploaded web shell gets 403 |
| `block-files` | service | `.git`, `.env`, backups, `.sql` dumps and archives can't be downloaded |
| `wp-xmlrpc` | service | Blocks `xmlrpc.php` (password guessing, many tries per request) |
| `wp-admins` | service | Lists WordPress admins; ones made in the last `--days` days are asked about one by one |
| `php-functions` | access | `disable_functions` adds system, exec, shell_exec, passthru, proc_open, popen, pcntl_exec (keeps what was there) |
| `code-readonly` | access | The web server account no longer owns the site's code; upload, cache and temp folders are left alone |

PHP settings go into the apache2, fpm and cgi `php.ini`, never the command line one. Apache rules go in one file, `zz-bt-web.conf`. **nginx is not edited:** the lines go into `nginx-bt.conf` in the run folder to include by hand.

**Reported, not changed:** phpinfo pages, app versions.

#### Safety

- **Site check:** `--url` (default the home page and each app folder) is loaded before and after. Worse afterwards (stopped working, or a PHP/database error shows) puts everything back on the spot. Retried for 10 seconds for PHP's cache.
- **Config test** (`apache2ctl -t`, `php-fpm -t`) before each reload. A failed test puts everything back.
- **Undo:** every file is backed up, every owner and mode recorded (`owners-*.txt` for `code-readonly`), the drop-in removed, demoted admins made admins again. The revert timer runs as usual.

#### What it produces

In `web-hardening-N/`: `output.txt`, `apps.txt`, `plan.txt`, `changes.txt`, `summary.txt`, `nginx-bt.conf` (when nginx is there), `owners-*.txt`, `revert.sh`.

#### What to watch for

- **`php-functions`** can break features that run programs (image tools, some mail, backup plugins). The site check only loads pages: click through checkout after it. A broken feature says "has been disabled for security reasons".
- **`code-readonly`** stops updates and plugin installs from the admin panel. That's the point during the competition.
- **A new admin you made yourself:** answer `k`. Put team accounts on the protected list.

#### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `no known app found` | The site is outside /var/www, /srv, /opt | `--webroot DIR` |
| `could not read wp_users` | WordPress not set up, or root can't log in | `--mysql-cnf FILE` |
| `APPLIED, then PUT BACK` | The site broke after a change | Look at `changes.txt`, rerun with `--skip` for that fix |
| A web shell in uploads still runs on nginx | nginx is not edited | Include `nginx-bt.conf` in the server block, `nginx -t`, reload |


### SV-20: Database hardening (`dist/applications/SV-20-db-hardening.sh`)

Locks down MySQL/MariaDB behind the web apps without breaking them. It lists every database account and **which app uses it**, read from the apps' own configs. Then it offers each fix, graded like SV-30. After the changes, the site must still load, or everything is put back.

**Back up first** (SV-15 or SV-14).

#### How to run it

```sh
sudo sh SV-20-db-hardening.sh                                         # dry run, asks
sudo sh SV-20-db-hardening.sh --apply --level service
sudo sh SV-20-db-hardening.sh --apply --batch --level safe --url http://127.0.0.1/shop/
```

#### The questions

| Question | Answers | Flag |
| --- | --- | --- |
| Which box is this? | `[s]plunk [w]ebmail [e]comm [f]ileshare [g]itea [b] web [o]ther` | `--box` |
| Which box is this? (its scored ports are never offered) | `[s]plunk [w]ebmail [e]comm [f]ileshare (139, 445, 2049, 111) [g]itea (3000, 2222, 80, 443) [b] web: a ticket, help-desk or shop site (80, 443) [o]ther` | `--box splunk\|webmail\|ecomm\|fileshare\|gitea\|web\|other` |
| How far should I go? | `[s]afe`, `[v]` service, `[a]ccess` | `--level` |
| Each fix | `[y]` do it / `[n]` skip it (access-level fixes default to no) | `--only` / `--skip` |
| Apply these changes? | `[y]` / `[n]` | `--batch` |

#### The fixes

| Fix | Level | What it does |
| --- | --- | --- |
| `db-anon` | safe | Drops anonymous accounts (`''@host`: anyone gets in) |
| `db-testdb` | safe | Drops the `test` database, only if it is empty |
| `db-infile` | safe | `local_infile` off now and after restarts |
| `db-remoteroot` | service | Drops root accounts allowed from other hosts |
| `db-emptypw` | service | Locks accounts with **no password** that no app uses |
| `db-file` | service | Takes the FILE right (read/write any file: a web shell into the web root) from accounts other than root and the server's own admins |
| `db-apppw` | service | A new random password for each app's database account, written into the app's config in the same step (WordPress, Joomla, PrestaShop, OpenCart, Roundcube, `.env`) |
| `db-bind` | access | Listens on 127.0.0.1 only, when every app is on this box (restarts the database) |
| `db-udf` | access | Drops user-defined functions such as `sys_exec` from lib_mysqludf_sys, the classic way to run commands through the database |

**Reported, not changed:** accounts with SUPER/FILE/GRANT, unused accounts allowed from any host with admin rights (red: planted?), triggers and scheduled events, an empty `secure_file_priv`, where the server listens, and PostgreSQL `trust` logins.

#### Safety

- **Site check:** before and after the changes it loads `--url` (default `http://127.0.0.1/`). If the site worked before and doesn't now, or a database error appears, everything this run changed is put back on the spot. A site that was broken before and works afterwards counts as fine. PHP rereads its config only every few seconds, so a failure is retried for 10 seconds before it counts.
- **Undo:** each account is saved before it changes (`before/`, root only, since it holds password hashes). The undo restores dropped accounts and old passwords in both the database and the config, gives rights back, and removes the drop-in config file. The revert timer runs as usual.
- **Passwords:** new app passwords go only into the app config and `passwords.txt` (mode 600), never the screen or the logs.

#### What it produces

In `db-hardening-N/` (mode 700): `output.txt`, `accounts.txt` (every account, how it logs in, its rights, which app uses it), `plan.txt`, `changes.txt`, `summary.txt`, `passwords.txt` (only with `db-apppw`), `before/`, and `revert.sh`.

#### What to watch for

- **An app whose config isn't recognised** keeps its password. `db-apppw` only changes accounts it can also write into the app's config.
- **A scoring check that logs in to the database directly** isn't known to the script. Put that account on the protected list.
- **Dropping a UDF can't always be undone:** the undo needs the `.so` file, and a planted function is usually broken anyway. Delete the `.so` from the plugin folder by hand.
- **`db-bind`** says so if another config file still sets `bind-address` after the script's file.

#### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `could not log in` (exit 3) | root can't log in through the socket | `--mysql-cnf FILE` with a `[client]` user and password |
| `cannot check the site` | No curl/wget, or nothing on `--url` | Give the store's address with `--url`, or install curl |
| `APPLIED, then PUT BACK` | The site broke after a change | Look at `changes.txt`, then rerun with `--skip` for that fix |
| An app account is listed `used by: -` | Its config is outside /var/www, /srv, /opt | `--webroot DIR` |



### SV-42: Database password rotation (`dist/applications/SV-42-db-passwords.sh`)

New passwords for every MySQL/MariaDB and PostgreSQL account that logs in with one. If an app uses the account, its config gets the new password in the same step, so the store keeps working. Each new password is tested by logging in with it.

#### How to run it

```sh
sudo sh SV-42-db-passwords.sh                                    # dry run, asks
sudo sh SV-42-db-passwords.sh --apply          # asks about each account
sudo sh SV-42-db-passwords.sh --apply --batch --url http://127.0.0.1/shop/
```

#### The questions

| Question | Answers | Flag |
| --- | --- | --- |
| Which box is this? | `[s]plunk [w]ebmail [e]comm [f]ileshare [g]itea [b] web [o]ther` (guessed from the box's files) | `--box` |
| Go through each account one by one? | `[y]` / `[n]` (use the table's defaults) | `--batch` |
| Each account | `[r]andom` `[s]et` (typed twice, not shown) `[l]ock` `[k]eep` `[a]ll the rest default` | `--users`, `--exclude`, `--passwords` |
| A protected account | extra `[y]` / `[n]`, default no | protected list |
| Apply these changes? | `[y]` / `[n]` | `--apply` |

#### What it does

- **Lists every account:** where it can log in from, how it logs in, which app uses it. HIGH: no password, a PostgreSQL superuser that isn't `postgres`, `trust` lines in pg_hba.conf.
- **Leaves alone** accounts that log in by OS account only (unix_socket, peer), locked accounts and roles that can't log in. Root on Debian/Ubuntu MariaDB is one of these.
- **App accounts:** new password in the database and in the config: WordPress, Joomla, PrestaShop, OpenCart (both configs), Roundcube, `.env`, and `[client]` files like `/root/.my.cnf`.
- **Keeps a unix_socket login** when an account has both.
- **The account it logs in with** is changed last.
- **Tests each new password** by logging in. If that fails, the old one goes back on the spot. An account allowed only from another host is marked "not tested".
- **Site check:** `--url` (default the home page and each app folder) must still load afterwards. If not, every old password comes back.

#### Safety

- Dry run unless `--apply`. Revert timer (120 s). Every account is saved first in `before/` (root only, it holds the hashes).
- The undo puts back the old password (even an empty one), unlocks what was locked, restores the configs, and renames `passwords.txt` to `passwords-UNDONE-not-valid.txt`.
- New passwords only go in `passwords.txt` (mode 600), never on screen or in the logs.

#### What it produces

In `db-passwords-N/` (mode 700): `output.txt`, `accounts.txt`, `plan.txt`, `summary.txt`, `passwords.txt`, `before/`, `revert.sh`.

#### What to watch for

- **The scoring engine may log in to the database itself.** Put that account on the protected list, or report the new password in the scoring portal.
- **"used by: -"** means no config names the account. A hard-coded password in a PHP file isn't found, but the site check catches it and puts everything back.
- **PostgreSQL apps:** only `.env` configs are updated.
- **`trust` in pg_hba.conf** lets anyone in without any password. Fix that first.

#### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `nothing to rotate` | Can't log in to either database | Run as root, or `--mysql-cnf FILE` |
| `failed: the new password did not work` | The login test failed (pg_hba, host limits) | Old password is back; check the log |
| `APPLIED, then PUT BACK` | The site broke | An app uses an account its config check missed: `--exclude` it, or `--webroot DIR` |
| `no such database account` (exit 2) | A typo in `--users`/`--exclude` | Fix the name |


### SV-30: Service hardening (FTP + legacy) (`dist/applications/SV-30-service-hardening.sh`)

Hardens the insecure services on a Linux box — FTP first, then telnet, rsh/rlogin/rexec, TFTP, SNMP and the old inetd services. Every action is graded by how risky it is, and the script only goes as far as the level you pick.

#### Levels

| `--level` | Does | Behaviour |
| --- | --- | --- |
| **safe** (Enter) | only `safe` actions | applies; can't lock anyone out. FTP config changes need a restart of the FTP daemon, which the script does and checks |
| **service** | adds `service` actions | applies, checks the service still answers, **undoes just that change if it broke** |
| **access** | adds `access` actions | can disable a daemon; covered by the revert timer and **skipped for a scored service** |

Each level includes the ones before it. If you don't pass `--level`, it asks. It shows the plan first (dry run), asks about each action (Enter takes the default; `safe`/`service` default yes, `access` defaults no unless you name it in `--only`), then `--apply` makes the changes with the revert timer running.

#### How to run it

```sh
sh SV-30-service-hardening.sh                                    # dry run, safe, asks
sudo sh SV-30-service-hardening.sh --apply  # apply the safe FTP fixes
sudo sh SV-30-service-hardening.sh --apply --level service
sudo sh SV-30-service-hardening.sh --apply --level access --only ftp-disable
```

`--apply` needs a protected list (`--protected FILE`, or `--no-protected` to accept the risk) — that's what stops it disabling a scored service by accident. `--exclude vsftpd` leaves a service alone; `--force-scored` allows disabling one the host list marks scored.

#### FTP, graded

| Action | Risk | Effect |
| --- | --- | --- |
| `ftp-anon` | safe | turn off anonymous login |
| `ftp-accounts` | safe | deny root/system accounts FTP (`/etc/ftpusers`) |
| `ftp-perms` | safe | lock the config file to 600 |
| `ftp-logging` | safe | log transfers (`xferlog_enable`), hide the version banner |
| `ftp-chroot` | service | jail users to their home (adds `allow_writeable_chroot` so it doesn't break) |
| `ftp-tls` | service | reports the lines to require FTPS/TLS |
| `ftp-disable` | access | stop and disable the FTP service |

vsftpd config is edited in full. pure-ftpd: anonymous off is written (`conf/NoAnonymous`). proftpd: an `<Anonymous>` block is reported for you to remove.

**After FTP config changes it restarts the FTP daemon** (it only reads its config at start), checks it is running and listening again, and puts the config back if it is not. Open FTP sessions drop for a moment. A daemon that was stopped is left stopped. The other services: `telnet-disable`, `rsh-disable`, `tftp-disable`, `snmp-default` (flags default community strings), `snmp-disable`, `legacy-disable` (finger/echo/chargen/daytime/discard).

#### Outputs

In `service-hardening-N/`: `output.txt`, `plan.txt`, `changes.txt`, `summary.txt` and `revert.sh` (when a live apply changed something). Same look and undo as LX-39.

#### What to watch for

- **A `service`-level change is verified by whether the service still runs** after a reload; if it stopped, that one change is put back automatically.
- **Don't disable a scored service.** Keep `--force-scored` off and pass your scored services in the protected list — `access` actions skip anything protected.
- **ftp-tls and snmp-default are reported, not applied** — TLS needs a cert and a new SNMP community must be coordinated, so they're yours to set.


---


### SV-16: Web shell hunter (`dist/applications/SV-16-webshell-hunter.sh`)

Finds the PHP files red team uses to get back into a site: web shells. SV-15 only sees files that changed since its backup, so a shell planted before the backup is backed up too. This one looks at what's inside each file.

#### How to run it

```sh
sudo sh SV-16-webshell-hunter.sh                                     # scan, dry run
sudo sh SV-16-webshell-hunter.sh --apply           # asks about each file
sudo sh SV-16-webshell-hunter.sh --apply --batch --url http://127.0.0.1/shop/
sudo sh SV-16-webshell-hunter.sh --watch 60 --auto-quarantine --apply   # keep watching
```

#### What it looks for

| Level | Found |
| --- | --- |
| HIGH | Request data run as code (`system($_GET..)`, `eval($_POST..)`, `assert($_REQUEST..)`, `$_GET['f']($_GET['a'])`, backticks); `eval(base64_decode(..))` and other decoded code; `preg_replace` with `/e`; known shell names (c99, r57, WSO, b374k, weevely, p0wny...); PHP in an upload or image folder; PHP inside a `.jpg`/`.png`/`.txt`; `.htaccess` that makes other files run as PHP or uses `auto_prepend_file`; a WordPress core file that differs from wordpress.org; a file in `wp-admin`/`wp-includes` WordPress doesn't ship |
| MED | Functions that run programs (`shell_exec`, `passthru`, `proc_open`, `popen`); decoding functions; hex-escaped strings; long base64 blobs; PHP in a cache/temp folder |
| LOW | Changed in the last `--hours` (24); owned by the web server account; a hidden `.name.php` |

A file is HIGH if any HIGH reason matches, MED if any MED reason does. The matching line is shown, so you can tell a shell from a normal plugin. WordPress's empty `index.php` ("Silence is golden") is skipped, and core files that match wordpress.org drop their MED/LOW hints.

**WordPress check:** it fetches the checksums for the installed version from wordpress.org. If that's blocked, save the page `https://api.wordpress.org/core/checksums/1.0/?version=X&locale=en_US` elsewhere and pass `--wp-checksums FILE`.

#### The questions

| Question | Answers | Flag |
| --- | --- | --- |
| Each HIGH/MED file | `[q]uarantine` `[k]eep` `[a]ll the rest default` (default: HIGH out, MED kept) | `--batch` |
| Quarantine these? | `[y]` / `[n]` | `--apply` |

#### Safety

- Dry run unless `--apply`. It only ever moves files to quarantine; the undo puts them back. Revert timer (120 s).
- **Site check:** `--url` must still load afterwards. If not, everything goes back, then the files are tried **one at a time**. A file the site needs is put back and listed: clean that one by hand (remove the bad lines, keep the rest).
- The check waits for PHP's cache (opcache), so a moved file can't look fine for a few seconds and then break the site.

#### Watch mode

`--watch 60` checks every 60 seconds for new or changed PHP files and scans them right away. `--auto-quarantine --apply` moves HIGH ones out at once (and back if the site stops loading). Everything goes into `watch.txt`.

#### What it produces

In `webshells-N/`: `output.txt`, `findings.txt` (every file, its score and reasons), `summary.txt`, `watch.txt`, `revert.sh`.

#### What to watch for

- **Backup, file manager and page builder plugins** use exec functions, so MED is normal for them. Read the line before quarantining.
- **A clever shell can avoid every pattern.** Look at the LOW hints too (`--show-low`): changed lately, owned by the web server.
- **Shells kept in the database** (an option holding PHP) aren't seen. SV-15 compares the database.
- After cleaning: run `SV-15 --backup` so the clean site is the one you restore to, and `SV-21 upload-nophp` so PHP can't run in uploads at all.

#### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `not checked against wordpress.org` | wordpress.org unreachable | `--wp-checksums FILE` |
| `the site needs FILE: put back` | The shell is inside a file the site loads | Remove only the bad lines, then run again |
| Lots of MED in one plugin | It runs programs legitimately | Keep it (`k`), or check the plugin's version |


### SV-32: TLS certificate check (`dist/applications/SV-32-tls-check.sh`)

HTTPS, IMAPS and SMTP all hang on a certificate and its private key. Red team swaps the certificate, steals a key anyone can read, or turns old TLS back on. This checks the files, what each port really serves, and whether anything changed.

#### How to run it

```sh
sudo sh SV-32-tls-check.sh                                  # look, dry run
sudo sh SV-32-tls-check.sh --apply        # asks each fix
sudo sh SV-32-tls-check.sh --apply --batch
```

Run it once early: the first run saves the fingerprints as the baseline (`tls-baseline-HOST.txt` in `--out`). Later runs flag a certificate that changed.

#### What it checks

| Where | Found |
| --- | --- |
| Certificate files (Apache, nginx, Dovecot, Postfix, vsftpd, MariaDB configs) | Missing; expired `[!]` or ending within `--days` (14); not matching its key `[!]`; self-signed; key under 2048 bits; SHA-1/MD5 signature |
| Key files | Readable by every user `[!]`; readable by an odd group; not owned by root; needs a passphrase |
| Ports (443, 8443, 993, 995, 465; STARTTLS on 25, 587, 143, 110, 21, 3306; `--port`) | The certificate really served, and which file it is; TLS 1.0/1.1 accepted; weak ciphers (RC4, 3DES, NULL, anonymous) accepted; IMAP, POP3 or FTP with no TLS at all (passwords in clear text) |
| Baseline | A certificate whose fingerprint changed since the first run `[!]` |

#### The questions

| Finding | Answers | Flag |
| --- | --- | --- |
| A certificate with problems (all of them in one question) | `[n]ew self-signed` / `[l]eave`; default new only if it was self-signed already, so a CA-signed one is never replaced on its own | `--batch` |
| A key others can read | `[f]ix` (default: 600, or 640 when its group is a service group such as ssl-cert or mysql) / `[l]eave` | `--batch` |
| A port with old TLS or weak ciphers | `[f]ix the config` (default) / `[l]eave` | `--batch` |
| Changed since the baseline | `[k]eep flagging` (default) / `[u]se as the new baseline` | `--batch` |
| Apply? | `[y]` / `[n]` | `--apply` |

#### What it changes

Only with `--apply`. Every change has an undo line (the old files are backed up first).

- **New self-signed**: same name (CN), RSA 2048, SHA-256, one year; the services using it are reloaded.
- **TLS config**: Apache `SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1` + `SSLCipherSuite HIGH:!aNULL:!MD5:!3DES:!RC4`; nginx `ssl_protocols TLSv1.2 TLSv1.3`; Dovecot `ssl_min_protocol = TLSv1.2`; Postfix `smtpd_tls_protocols` / `smtpd_tls_mandatory_protocols` without TLS 1.0/1.1 and `smtpd_tls_exclude_ciphers`. Checked with the service's own config test, reloaded, then a TLS 1.2 connection: if the port stops answering, the old config is put back.

#### What it produces

In `tls-N/`: `output.txt`, `certs.txt` (each certificate), `served.txt` (each port), `findings.txt`, `summary.txt`. The baseline holds fingerprints only, never a key.

#### What to watch for

- **A new self-signed certificate makes browsers warn**, and a scoring check that verifies certificates fails. Tell the team before you replace a CA-signed one.
- **Old TLS off can lock out a very old client.** Rare, but check the scoring results after.
- A port served by a program the script does not know (not Apache, nginx, Dovecot, Postfix): pass `--port PORT:tls:SERVICE` to say whose config it is, or fix it by hand.


### SV-31: Mail tamper check (`dist/applications/SV-31-mail-tamper.sh`)

The quiet backdoors red team leaves in a mail server: a copy of every mail sent to them, a program run on every delivery, mail forwarded out, an open relay. It reads Postfix, Dovecot, the aliases and every user's mail files, then offers to undo each one.

#### How to run it

```sh
sudo sh SV-31-mail-tamper.sh                                  # look + dry run
sudo sh SV-31-mail-tamper.sh --apply        # asks about each fix
sudo sh SV-31-mail-tamper.sh --apply --batch --domain shop.local
```

#### What it finds

| Level | Found |
| --- | --- |
| HIGH | `always_bcc`, `sender_bcc_maps`, `recipient_bcc_maps` (a copy of mail goes somewhere); `mailbox_command` / `mailbox_transport` that isn't Dovecot or procmail (a program on every delivery); an unknown `content_filter`; a `master.cf` pipe service running a program Postfix doesn't ship; `mynetworks` open to the world; relay rules without `reject_unauth_destination`; aliases, `.forward` or `.procmailrc` that run a program (`"\| cmd"`) or `:include:` a file; sieve scripts that run programs |
| MED | Aliases, `.forward`, virtual aliases or sieve scripts sending mail outside your domains; `header_checks`/`body_checks` that REDIRECT / DISCARD / BCC; a `relayhost` or `transport_maps`; a known filter (amavis, spamassassin, rspamd); a Dovecot post-login script; a big mail queue (spam going out?) |

"Outside" means not one of `mydestination`, `myhostname`, `mydomain` or `--domain`.

#### The questions

| Question | Answers | Flag |
| --- | --- | --- |
| Which box is this? | `[s]plunk [w]ebmail [e]comm [f]ileshare [g]itea [b] web [o]ther` (guessed from the box's files) | `--box` |
| Each fix | `[y]` / `[n]`: default yes for HIGH, no for MED | `--batch` |
| Apply? | `[y]` / `[n]` | `--apply` |

#### The fixes

- A Postfix setting is commented out with `#SV-31: `, together with its continuation lines.
- `mynetworks` is set to `127.0.0.0/8 [::1]/128`, and the relay rules get `reject_unauth_destination`.
- A `master.cf` service or an alias line is commented out (then `newaliases`).
- `.forward`, `.procmailrc` and sieve files are moved to quarantine.

#### Safety

- Dry run unless `--apply`. Revert timer (120 s).
- After the changes: `postfix check`, a reload, and **SMTP (25) and IMAP (143) must still answer** (they're scored), or everything is put back.
- The undo restores every file and reloads Postfix.

#### What it produces

In `mail-tamper-N/`: `output.txt`, `findings.txt`, `plan.txt`, `summary.txt`, `revert.sh`.

#### What to watch for

- **A real filter (amavis, rspamd)** shows as MED. Keep it if it's yours.
- **Exim and Sendmail** aren't read. **SQL/LDAP maps** are named, not opened.
- Banner, VRFY, HELO: **SV-30**. Mail passwords: **SV-40**.


### SV-40: Mail password rotation (`dist/applications/SV-40-mail-passwords.sh`)

New passwords for the mail users: the IMAP, SMTP and webmail logins. It reads Dovecot's config to find where the passwords live, then changes them there. Each new password is tested with a real IMAP login.

#### How to run it

```sh
sudo sh SV-40-mail-passwords.sh                                  # dry run, asks
sudo sh SV-40-mail-passwords.sh --apply        # asks about each user
sudo sh SV-40-mail-passwords.sh --apply --batch
```

#### The questions

| Question | Answers | Flag |
| --- | --- | --- |
| Which box is this? | `[s]plunk [w]ebmail [e]comm [f]ileshare [g]itea [b] web [o]ther` (guessed from the box's files) | `--box` |
| Go through each user one by one? | `[y]` / `[n]` (use the table's defaults) | `--batch` |
| Each user | `[r]andom` `[s]et` (typed twice, not shown) `[l]ock` `[k]eep` `[a]ll the rest default` | `--users`, `--exclude`, `--passwords` |
| A protected user | extra `[y]` / `[n]`, default no | protected list |
| Apply these changes? | `[y]` / `[n]` | `--apply` |

#### Where the passwords are

| Dovecot / Postfix uses | What SV-40 does |
| --- | --- |
| System accounts (`pam`, `shadow`, `passwd`) | Changes the accounts that have a mailbox (`/var/mail/USER`, `~/Maildir`, `~/mail`) with chpasswd. `--all-accounts` takes every human account. Root is never included (LX-20 changes it). |
| `passwd-file` (e.g. `/etc/dovecot/users`) | Writes a new `{SHA512-CRYPT}` hash in the user's line, keeps the rest of the line, empties Dovecot's login cache |
| Postfix Cyrus SASL (`/etc/sasldb2`) | `saslpasswd2` (not tested by login) |
| `sql`, `ldap` | Listed only: change them where they live |

**Flagged:** Dovecot **master** users (they can open any mailbox), a `static` passdb (one password for everyone), users with no password.

#### Safety

- Dry run unless `--apply`. Revert timer (120 s). The old hash of each user is saved in `before/` (root only).
- Each new password is tested by an IMAP login (993, or 143 with STARTTLS). If the login fails, the old password goes back on the spot.
- The undo puts every old hash and line back, and renames `passwords.txt` to `passwords-UNDONE-not-valid.txt`.
- New passwords only go in `passwords.txt` (mode 600).

#### What it produces

In `mail-passwords-N/` (mode 700): `output.txt`, `users.txt`, `plan.txt`, `summary.txt`, `passwords.txt`, `before/`, `revert.sh`.

#### What to watch for

- **The scored IMAP and webmail checks log in as a mail user.** Put that user on the protected list, or report its new password in the scoring portal.
- **Webmail (Roundcube)** and Postfix SMTP through Dovecot use these same passwords. Nothing else to change.
- **System mail users are also Linux logins.** Running LX-20 afterwards would change them again. Use `--exclude` there, or run only one of the two.

#### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `nothing to rotate` | No Dovecot passdb or SASL database | Mail is somewhere else: check `doveconf -n` |
| `no mail users found` | System accounts have no mailbox yet | `--all-accounts` |
| `failed: the new password did not log in` | IMAP refused it (wrong passdb order, a deny list) | The old password is back; check `doveconf -n` |
| `login not tested here` | No IMAP on 993/143, or openssl missing | Log in from the webmail yourself |


### SV-41: Webmail (Roundcube) hardening (`dist/applications/SV-41-roundcube-hardening.sh`)

`webmail-interactive` is scored: someone logs in to Roundcube and reads mail. Roundcube is also an easy way in. This finds each Roundcube (packaged in `/usr/share/roundcube`, or a tarball under `/var/www`, `/srv`, `/opt`), shows what's wrong and offers the fixes.

#### How to run it

```sh
sudo sh SV-41-roundcube-hardening.sh                                  # look + dry run
sudo sh SV-41-roundcube-hardening.sh --apply        # asks about each fix
sudo sh SV-41-roundcube-hardening.sh --apply --batch --url http://127.0.0.1/roundcube/
```

#### What it checks

| Check | Found |
| --- | --- |
| Version | **CVE-2025-49113** (any logged-in user runs commands; fixed 1.6.11 / 1.5.10), **CVE-2024-42009** (an email that steals mail; 1.6.8 / 1.5.8), 1.4 and older (no fixes). For a distribution package it reads the changelog: a backported fix shows as `[ok]`. If there's no changelog, it tells you to check `apt changelog roundcube-core`. |
| Where logins go | `imap_host` / `default_host` / `smtp_host` that aren't this box: every webmail password goes there (HIGH) |
| Installer | `enable_installer = true` (HIGH); the `installer/` folder |
| Debug | `sql_debug`, `imap_debug`, `smtp_debug` write passwords and mail to the logs (HIGH); `debug_level` that shows errors to users |
| des_key | The published default, or shorter than 24 characters (HIGH) |
| log_logins | Off: you can't see who logged in |
| Plugins | Every enabled plugin, and plugin files newer than Roundcube itself (added later?) |
| Files | Config readable by everyone; logs, temp, config downloadable (HIGH); SQL, bin, composer.json downloadable (MED) |

#### The questions

| Question | Answers | Flag |
| --- | --- | --- |
| Which box is this? | `[s]plunk [w]ebmail [e]comm [f]ileshare [g]itea [b] web [o]ther` (guessed from the box's files) | `--box` |
| Each fix | `[y]` / `[n]` | `--only` / `--skip` |
| Apply? | `[y]` / `[n]` | `--apply` |

#### The fixes

| Fix | What it does |
| --- | --- |
| `installer` | Quarantines `installer/` and sets `enable_installer = false` |
| `debug-off` | Debug options off, `debug_level = 1` |
| `des-key` | A new random 24-character key (everyone logs in again) |
| `log-logins` | `log_logins = true` |
| `config-perms` | Config files `root:www-data 640` |
| `block-dirs` | Apache drop-in `zz-bt-roundcube.conf` denying installer, logs, temp, config, SQL, bin (and where Debian's links point). nginx: lines written to `nginx-bt.conf`. |

Settings are written as `$config['key'] = value; // BT SV-41`. **Logins sent elsewhere are only reported**: only you know which mail server is right.

#### Safety

- Dry run unless `--apply`. Revert timer (120 s).
- After the changes: Apache config test and reload, then **the login page must still load**, or everything is put back.

#### What it produces

In `roundcube-N/`: `output.txt`, `findings.txt`, `plan.txt`, `summary.txt`, `revert.sh` (and `nginx-bt.conf` with nginx).

#### What to watch for

- **Upgrading isn't done here.** Use `apt-get install --only-upgrade roundcube-core`, or a new release for a tarball.
- **Web shells inside Roundcube:** `SV-16 --webroot /usr/share/roundcube`. Mail passwords: **SV-40**. Its database password: **SV-42**. Mail backdoors: **SV-31**.


### SV-44: Splunk hardening and passwords (`dist/applications/SV-44-splunk-hardening.sh`)

For the Splunk box. Splunk is three scored checks (`splunk-mgmt` on 8089, `splunk-query`, and the box) and an easy backdoor: a **scripted input** or **alert script** runs any command as the Splunk user, again and again. This finds those, gives the Splunk users new passwords, and checks that a search still runs afterwards.

> **Not yet run on a real Splunk.** It's tested against a stand-in with Splunk's real file layout and REST answers. Read the dry run first, and try it on a test box if you can.

#### How to run it

```sh
sudo sh SV-44-splunk-hardening.sh                                 # look + dry run (asks for the admin login)
sudo sh SV-44-splunk-hardening.sh --apply
sudo sh SV-44-splunk-hardening.sh --apply --batch --auth-file admin.txt --exclude scorer
```

`admin.txt` is one line, `admin CURRENTPASSWORD`. Delete it after.

#### The questions

| Question | Answers | Flag |
| --- | --- | --- |
| Splunk admin user and its current password | typed (not shown) | `--auth-file` |
| Each fix | `[y]` / `[n]` | `--only` / `--skip` |
| Go through each Splunk user? | `[y]` / `[n]` | `--batch` |
| Each user | `[r]andom` `[s]et` `[k]eep` `[a]ll the rest random` | `--users` / `--exclude` |
| Each app that didn't come with Splunk | `[q]uarantine` / `[k]eep` | `--quarantine NAMES` |
| Restart Splunk now? | `[y]` / `[n]` | `--batch` = yes |

#### What it finds (never changed)

- **The old default password** `admin` / `changeme` still working (HIGH).
- **Users and roles:** every admin, and roles that can make admins (`edit_user`, `admin_all_objects` ...).
- **Apps that didn't come with Splunk**, with programs in `bin/` and when they changed (HIGH if both programs and a recent change).
- **Scripted inputs** (HIGH in apps that didn't come with Splunk), **alert scripts**.
- **Scripted login** (`authType = Scripted`), LDAP/SAML.
- **A deployment server** (it can push any app, and any command, to this Splunk), **forwarding** to another server, **HEC tokens**.
- Who splunkd runs as (root makes every backdoor root), secrets anyone can read, `user-seed.conf` left over.

#### The fixes (each asked)

| Fix | Default | What it does |
| --- | --- | --- |
| `passwords` | yes | New password per user through the REST API on 8089, each tested by logging in. The admin you log in with goes last (Splunk needs its old password). |
| `scripts-off` | yes | `disabled = 1` for scripted inputs in apps that didn't come with Splunk (in that app's `local/inputs.conf`) |
| `app-quarantine` | no | Moves an app you choose out of `etc/apps` |
| `deploy-off` | no | Removes `deploymentclient.conf` |
| `secrets-perms` | yes | `etc/passwd` and `splunk.secret` mode 600, `user-seed.conf` removed |

#### Safety

- Dry run unless `--apply`. Revert timer (120 s).
- After file changes Splunk restarts (asked), then 8089 must answer and a test search must run, which is what `splunk-query` scores. If either fails, everything is put back and Splunk restarted again.
- Undo: files back, `etc/passwd` back plus a restart (no old password is kept on disk), quarantined apps back.
- New passwords only go in `passwords.txt` (mode 600).

#### What to watch for

- **`splunk-query` logs in as a Splunk user.** `--exclude` it or put it on the protected list, or report its new password in the scoring portal.
- **A restart takes about a minute**, so 8089 is down for that long.
- **A forwarder on another box** sending here keeps working: passwords and `pass4SymmKey` aren't involved in plain forwarding.

#### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `could not log in to 8089` | Wrong admin password, or 8089 moved | Check `web.conf mgmtHostPort`; the file checks still run |
| `Splunk refused the change (HTTP 400)` | Password rules (length, complexity) | `--length 24`, or set one with `[s]` |
| `the test search FAILS` | A quarantined app or disabled input was needed | It's put back; skip that one next time |
| `splunkd is not running` | Down | `SV-50 --services splunk` |

