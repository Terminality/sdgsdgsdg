# Changelog

What changed, newest first. Each entry names the scripts touched and how they were tested. Library versions follow `CC_LIB_VERSION` in `lib/lib.sh` and `$script:CcLibVersion` in `lib/lib.ps1`, which are always the same.

## 2026-11-19: Device change watch (NW-30, new)

- **NW-30** reads every firewall, router and switch every few minutes (the same read-only show commands as NW-01) and compares it with a trusted baseline: NW-01's copy, the earlier watch's, or read now (asked per device).
- Each added, removed or moved line is shown once, with the section it is in, HIGH/MED, what it may mean and a suggested undo that is never sent. It stays open until it goes away (shown) or you say it was ours (`[n]ot ours` / `[o]urs` / `[e]ach one`; `--batch` never says ours).
- Noise is dropped before comparing: time stamps, counters, Cisco size lines, FortiGate headers and `ENC` values, MikroTik line wraps, pfSense revision times. Secrets masked in all output. A changed SSH host key is HIGH.
- Output in `.txt` files; no CSV.
- Tested: 77 checks with a stand-in device for every brand under seven shells and three awks, including the questions on a terminal, the loop and Ctrl-C; the Linux brand against this box's real nft (a table added, then gone). Not yet on real network devices.

## 2026-11-19: Network device hardening (NW-21, new)

- **NW-21** reads each firewall, router and switch (Cisco IOS and ASA, Palo Alto, FortiGate, VyOS, MikroTik) and checks: telnet and plain HTTP management, management open to any address, SSH version 1, idle timeout, default SNMP communities (others reported, value never shown), MikroTik MAC telnet/WinBox, log server (`--log-host`), time server (`--ntp`), login banner, Cisco password encryption.
- Asked per finding: `[f]ix` (default) / `[l]eave` / `[a]ll the rest`. Then per device one session stays open: the changes go in, a NEW login from this box is tried, and for management changes you confirm a login from another team machine within `--timer` seconds. Not confirmed, or the new login fails: everything is put back through the open session. An undo script per device (needs `BT_NET_PASS`).
- After saving, each device is read again and every finding is checked.
- Tested: 106 checks with a stand-in device for every brand under seven shells and three awks; the Cisco IOS stand-in applies the commands, so the after-check, the undo and the put-back after a failed login are real. Not yet on real devices.

## 2026-11-19: Device accounts and sessions (NW-12, new)

- **NW-12** reads every local admin account and every logged-in session on each firewall, router and switch (Cisco IOS and ASA, Palo Alto, FortiGate, VyOS, MikroTik, Linux; pfSense/OPNsense pointed at the web GUI). The first run saves the account names as a baseline; an account added later is `[!]`.
- Asked per session: `[k]ick` / `[l]eave` (default kick when it is not from `--team`); per account: `[d]isable` / `[k]eep` (default disable when new since the first run). Its own login and the login account are never touched. Each change is checked by reading the device again.
- Disable is the brand's most reversible way: MikroTik and Linux disable/lock (undo turns it back on); Cisco, VyOS, FortiGate remove it and the undo puts back the account's lines from NW-01's saved copy, read at undo time so no password hash is copied; Palo Alto has no undo (the question says so). FortiGate sessions get the command to end them by hand.
- Account and session names come from the device (red team picks them): a name with a quote, `;` or other odd character is flagged and never put into a command.
- Found while testing: busybox awk may be built without `^` (powers), so the address-range check multiplies instead; `who` is empty on a box without `/var/run/utmp`.
- Tested: 64 checks with a stand-in device for every brand under seven shells and three awks; live against OpenSSH with throwaway accounts (a rogue session kicked, its account locked, the undo unlocked it, no password written anywhere).

## 2026-11-19: TLS certificate check (SV-32, new)

- **SV-32** reads every certificate and key named in the Apache, nginx, Dovecot, Postfix, vsftpd and MariaDB configs: expired or ending soon, not matching its key, self-signed, weak key, SHA-1/MD5 signature, a key others can read. Then connects to each TLS port (443, 993, 995, 465, STARTTLS on 25, 587, 143, 110, 21, 3306): the certificate it really serves, TLS 1.0/1.1, weak ciphers. A fingerprint baseline flags a certificate swapped since the first run (fingerprints only, never a key).
- Asked once per certificate (every problem in one question): `[n]ew self-signed` / `[l]eave` - default new only when it was self-signed already. A readable key: `[f]ix` (chmod 600). Old TLS on a port: `[f]ix the config` (tested with the service's own check, reloaded, put back if the port stops answering TLS 1.2). A changed certificate: `[k]eep flagging` / `[u]se as the new baseline`.
- Found while testing: one certificate file can be copied to several places (Dovecot and Postfix share the snakeoil pair), so a served certificate lists every file it matches; the undo's reload now checks for a running systemd, not just the systemctl command.
- Review fixes: config files and certificates that are symlinks (Apache's sites-enabled, Let's Encrypt's live/) are edited and backed up through to the real file - before, the backup was the link itself and the undo restored nothing; a new self-signed certificate made by this script updates the baseline (no false "CHANGED" next run); certificates new since the baseline are added to it; a key fix keeps the group's read for a service group (640 for ssl-cert, mysql...) so MariaDB can still read its own key, and a mysql-owned key is not flagged; IMAP, POP3 and FTP without TLS are flagged (passwords in clear text); Dovecot 2.4's `ssl_server_cert_file` and nginx snippets included by a site are read; a key that cannot be read without root says so; a new certificate is still made on OpenSSL older than 1.1.1 (no SAN).
- Tested: 42 checks under seven shells and three awks; the Postfix fix live on the test box.

## 2026-11-19: Safe security updates (LX-46, new)

- **LX-46** first shows where updates come from: package sources that are not the distribution's, sources with no signature check (`[trusted=yes]`, `gpgcheck=0`, `AllowUnauthenticated`) and held packages (red team holds openssh so it never gets patched).
- Then lists pending updates grouped by service (ssh, openssl, sudo, web, php, database, mail, dns, ftp, system), security apart. Asked per group: `[u]pdate` / `[s]kip`; security defaults to update, the kernel and non-security updates to skip.
- Before each group it saves the old packages (`apt-get download`) and the listening ports; your config files are always kept (`--force-confold`). After each group it checks the ports, the web page and the database; if one stopped, `[r]oll back` / `[l]eave` (default roll back). Services still on old library code are offered a restart.
- Found while testing: after a group is left broken, the next groups were blamed for the same closed port, so the checks now compare against the state after each group.
- Review fixes: only ports below 32768 are compared (a short-lived high port closing on its own looked like a broken service, and the default answer is roll back); the old package is taken from apt's own cache when the mirror no longer has it (fewer groups skipped for lack of a rollback); a group with nothing saved no longer claims a rollback; the dnf rollback undoes its own transaction by number, not "last"; apt pins that block updates (Pin-Priority below 0) and an apt proxy are flagged next to holds.
- Tested: 39 checks under seven shells and three awks with stand-in apt-get, apt-mark, dpkg-query and ss; no real package is installed by the tests.

## 2026-11-19: AppArmor confinement (LX-44, new)

- **LX-44** puts apache2, nginx, php-fpm and mariadb/mysql under AppArmor in three steps: **complain** (the profile is loaded, nothing is blocked, AppArmor logs what it would block), **learn** (the logged accesses are sorted: normal ones offered for the profile, writes into the site code asked on their own, programs it ran never added - a shell or curl is flagged as a web shell), **enforce** (the service is checked right after; if it stopped answering it goes back to complain, and a revert timer runs).
- Asked per service by its state: unconfined `[c]omplain` / `[e]nforce` / `[k]eep`; complain `[l]earn` / `[e]nforce` / `[c]` stay; enforced `[k]eep` / `[c]` back. A profile the package ships (php-fpm, mysqld) is used instead of the kit's.
- Found while testing: AppArmor refuses `w` and `a` in one rule, so learned append+write lines keep only `w`.
- Review fixes: the learning step never adds secrets or system files (`/etc/shadow`, SSH keys, `/root`, writes into `/etc`, `/usr`, cron) or dangerous capabilities (`sys_module`, `sys_admin`...) - they are shown as `[!]` (before, a web shell reading `/etc/shadow` during complain would have been offered as "normal"); a service started before its profile was loaded is seen (it logs nothing, so 10 quiet minutes no longer make enforce the default) and a restart is offered; the check after enforce only rolls back if the service answered before, and follows HTTPS; `*`, `?`, `[`, `{` in a learned path are escaped; a profile file left from an earlier run is backed up, not deleted, by the undo; the undo calls apparmor_parser by its full path (the revert timer may have a short PATH); the kernel journal is read when the log files have no AppArmor lines.
- Tested: 51 checks under seven shells and three awks in a fake root; every profile and learned rule is checked by the real AppArmor 4.0 parser. Not yet run on a kernel with AppArmor on.

## 2026-11-19: Rootkit and malware scan (LX-45, new)

- **LX-45** looks for what hides: processes in /proc that ps doesn't show, listening ports in /proc/net that ss doesn't show (both checked twice, a second apart), kernel modules hidden from lsmod or with a rootkit's name, kernel taint, core programs (ps, ss, ls, ssh, sudo, login...) that don't match their package, known rootkit paths, programs in /dev and /dev/shm, fake kernel threads, miners, promiscuous interfaces, and ClamAV/rkhunter/chkrootkit when installed (installing them is offered).
- Asked per finding: `[k]ill` / `[q]uarantine` / `[l]eave` / `[a]ll the rest`. Kernel modules are reported, not unloaded.
- Found while testing: dpkg lists merged-/usr programs as `/bin/ss`, so both spellings are tried; the miner search must not match its own command line, so it reads one ps snapshot and matches program names; zombies are skipped; /dev's search must not repeat /dev/shm.
- Review fixes: the hidden-process check is skipped when `ps` sees less than half of `/proc` (a cut-down ps would have made every process "hidden", with kill as the default); the protected list now guards kills (process name) and quarantines (path) - it was checked with a type that never matches; before a kill the pid must still be the same program (a pid reused while you answered is left alone); a file with the immutable flag is unlocked to quarantine it; symlinked programs (alternatives) are looked up by their target; the summary says where quarantined files and their undo lines are.
- Tested: 25 checks under seven shells and three awks with harmless stand-ins. The ClamAV part only runs where ClamAV has signatures (not on the test box).

## 2026-11-18: Remote access lockdown (LX-26, new)

- **LX-26** covers every way in except SSH (that's LX-22): tunnels out (ngrok, chisel, frp, cloudflared, bore, ligolo, `ssh -R`), web terminals (ttyd, gotty, shellinabox, wetty, tmate), bind and reverse shells (`nc -e`, `ncat --exec`, `socat exec:`, a shell whose input is a network socket), remote desktops (VNC, xrdp, NoMachine, TeamViewer, AnyDesk, RustDesk), admin panels (Webmin, Cockpit), quick file servers (`python -m http.server`, `php -S`), and database panels (listed).
- Asked per finding: `[s]top [k]eep [a]ll the rest` (default stop for HIGH). Services are stopped and disabled (the undo brings them back); programs are killed; a program file in a temp or home folder is quarantined. Scored ports and protected services are never offered.
- Found while testing: `read` with a tab separator merges empty fields (tab is whitespace), so the findings use the unit separator; zombie processes are skipped.
- Tested: 18 checks under seven shells and three awks with harmless stand-in programs.

## 2026-11-18: Log shipping to Splunk (LX-43, new)

- **LX-43 --receive** (the Splunk box): a Splunk syslog input (TCP 1514 by default) as its own app, `bt_receiver`, then a restart (asked).
- **LX-43 --send** (every other box): rsyslog sends auth, syslog, kern, mail and cron, plus the service log files it finds (Apache/nginx, mail, Dovecot, Roundcube, MySQL/MariaDB/PostgreSQL, audit, fail2ban), disk-buffered so nothing is lost while Splunk is down. Config checked with `rsyslogd -N1`; then a test line to search for in Splunk. Another forward already configured is flagged.
- Found while testing: some init scripts have no `restart` and the old rsyslog kept running on the old config, so the script now checks for a NEW rsyslog process and falls back to stop + start; the shipping ruleset must be defined before the file inputs that use it.
- Tested: 31 checks under seven shells and three awks; live rsyslog to a local listener. The receiver hasn't been run on a real Splunk.

## 2026-11-18: Webmail (Roundcube) hardening (SV-41, new)

- **SV-41** finds each Roundcube and checks: its version against CVE-2025-49113 (logged-in users run code; fixed 1.6.11 / 1.5.10) and CVE-2024-42009 (1.6.8 / 1.5.8), reading the distribution changelog for backported fixes; logins sent to a server that isn't this box; the installer; debug options that write passwords to logs; the default `des_key`; `log_logins`; plugin files newer than Roundcube itself; readable configs; logs, config, SQL and bin downloadable from the web.
- Fixes asked: installer quarantined and turned off, debug off, a new 24-character `des_key`, `log_logins` on, config 640, an Apache drop-in denying installer/logs/temp/config/SQL/bin. The login page must still load after, or everything is put back.
- Found while testing: a tarball install must read its own `config/` before `/etc/roundcube`; the package changelog only counts for the packaged copy; packaged plugin folders get new dates but their files keep old ones.
- Tested: 35 checks under seven shells and three awks; live with roundcube-core 1.6.6 behind Apache.

## 2026-11-18: Mail tamper check (SV-31, new)

- **SV-31** finds mail backdoors and offers to undo each one: `always_bcc` / bcc maps (a copy of all mail), `mailbox_command` / `mailbox_transport` (a program on every delivery), unknown `content_filter`, `master.cf` pipe services that run a program Postfix doesn't ship, an open `mynetworks`, relay rules without `reject_unauth_destination`, aliases / `.forward` / `.procmailrc` that run a program or forward outside, sieve scripts that execute or redirect out, `header_checks` redirects, Dovecot post-login scripts, a big queue.
- Fixes: the setting commented out (with its continuation lines), the service or alias line commented out (then newaliases), files quarantined, mynetworks set to this box. After: `postfix check`, reload, and SMTP 25 / IMAP 143 must still answer or it is all put back.
- Found while testing: field values hold `|` (alias pipes, `name|value` pairs), so findings are now tab-separated; Debian's stock `uucp` service runs `uux` without a path, so standard services are matched by program name.
- Tested: 39 checks under seven shells and three awks; live Postfix with five planted backdoors.

## 2026-11-18: Account lockdown (LX-21, new)

- **LX-21** goes through every account one by one: a second UID 0, empty passwords, hashes in /etc/passwd, admin groups (sudo, wheel, docker, lxd, disk ...), its sudo lines and NOPASSWD, SSH keys and key options, service accounts with a login shell, passwords changed in the last 2 days. Each account worth a decision is asked: `[k]eep [l]ock [d] take admin away [r]emove keys [b]oth [n]o-login shell [a]ll the rest`. Root, you and protected accounts are never locked.
- Sudo lines that give everyone or a whole group root, or that name a user that doesn't exist, are asked about on their own and commented out after a visudo check.
- Lock = `usermod -L` plus an expired account, so SSH keys stop too. The undo puts each account's saved lines back exactly.
- Found while testing: `sudoers.d` has a dot in its own name, so "skip files with a dot" must look at the file name only; ksh reads a bare `|` in `${x%%|*}` as "or" (again), so tests/lint-posix.sh now catches it.
- Tested: 39 checks under seven shells and three awks; live with a throwaway account (usermod, restored exactly).

## 2026-11-18: Web shell hunter (SV-16, new)

- **SV-16** looks inside the site's files for web shells: request data run as code, eval of encoded code, `preg_replace /e`, known shell names, PHP in upload folders or inside images, `.htaccess` handlers and `auto_prepend_file`, WordPress core files that differ from wordpress.org (or that it doesn't ship). It shows the matching line, asks per file (`[q]uarantine [k]eep [a]ll`), and checks the site after.
- If the site breaks, everything goes back and the files are retried one at a time; a file the site needs is put back and listed to clean by hand.
- `--watch N --auto-quarantine --apply` catches new shells as they land.
- Found while testing: folder names must be checked only inside the web root (a site under `/tmp` made every file "in a temp folder"); MED points must never add up to HIGH; PHP's opcache keeps a moved file "working" for ~2 s, so the site check looks at 3 s and 6 s.
- Tested: 39 checks under seven shells and three awks; live with Apache.

## 2026-11-18: Splunk hardening and passwords (SV-44, new)

- **SV-44** finds Splunk's backdoors (scripted inputs and alert scripts, apps that didn't come with Splunk, a deployment server, scripted login, extra admins and roles that make admins, the old `changeme` password, readable secrets) and offers: new passwords for each Splunk user through REST (each login tested), scripted inputs in planted apps disabled, apps quarantined, the deployment client removed, secrets locked down.
- After a restart, 8089 must answer and a test search must run (what splunk-query scores), or everything is put back.
- No password is kept on disk for the undo: `etc/passwd` comes back and Splunk restarts.
- Tested: 44 checks against a stand-in Splunk under seven shells and three awks. Not yet run on a real Splunk.

## 2026-11-18: Service recovery (SV-50, new)

- **SV-50** checks every service on the box (web, php-fpm, database, mail, Splunk, SSH, time) the same way: running, masked or disabled, config test, port held by another program, answers the way scoring tests, firewall drops, tampered configs / systemd overrides / package files; and once for the box: disk, inodes, /tmp, out of memory. Each fix is asked; a service is only started on a config that passes its test.
- `--watch N --auto-restart --apply` keeps checking and restarts what goes down (at most 3 times in 10 minutes each).
- One script for all services: the checks are the same, only the names, ports and tests differ (a table in the script).
- Tested: 29 checks with a real Apache under seven shells and three awks (BT_TEST_SVC=1); first real use found all eight services down after a container restart and brought them back.

## 2026-11-18: Mail password rotation (SV-40, new)

- **SV-40** reads Dovecot's config to find where mail passwords live and changes them there, asking about each user (`[r]andom [s]et [l]ock [k]eep [a]ll`): system accounts that have a mailbox (chpasswd), passwd-file users (new SHA512-CRYPT hash), Postfix sasldb. SQL/LDAP users are listed. Master users, a static passdb and empty passwords are flagged.
- Each new password is tested with a real IMAP login; a failure puts the old one back. Undo restores every hash.
- Found while testing: "a OK" from LOGOUT looked like a good login, so the login and logout now use different tags; a PAM login can take a few seconds, so the test waits and tries twice.
- Tested: 36 checks under seven shells and three awks, including a live Dovecot login test (BT_TEST_MAIL=1).

## 2026-11-18: Database password rotation (SV-42, new)

- **SV-42** gives every MySQL/MariaDB and PostgreSQL account that has a password a new one, asking about each account (`[r]andom [s]et [l]ock [k]eep [a]ll`). App accounts get the new password in their config in the same step. A unix_socket login is kept, and the account the script logs in with is changed last.
- Each new password is tested by logging in; a failure puts the old one back. The site must still load afterwards, or every old password comes back. Undo restores old (even empty) passwords and unlocks locked accounts.
- Found while testing: an account with no password needs `IDENTIFIED BY ''` in its undo; a lock needs `ACCOUNT UNLOCK`.
- Tested: 31 checks with a real MariaDB and PostgreSQL under seven shells and three awks; live with a page using a hard-coded password (put back automatically).

## 2026-11-18: PHP and web app hardening (SV-21, new)

- **SV-21** finds the web apps and offers fixes by level: safe (allow_url_include, display_errors, expose_php, app config files root:www-data 640, WordPress DISALLOW_FILE_EDIT), service (no PHP in upload folders, block .git/.env/backups/dumps, block xmlrpc.php, new WordPress admins kept or demoted), access (disable_functions for web shell functions, code read-only for the web server). nginx lines are written to a file to include by hand.
- Config test before reload; the site must still load afterwards, or everything is put back on the spot. Undo restores every file, owner and admin role.
- Tested: 38 checks on a fake root under seven shells and three awks; live with Apache and PHP 8.3: a web shell in uploads, xmlrpc.php, .git and a .sql dump all went from 200 to 403, the site stayed up, a red admin was demoted, and a page that needed shell_exec was put back automatically.

## 2026-11-18: Database hardening (SV-20, new); text files only in SV-15 and SV-20

- **SV-20** lists every MySQL/MariaDB account with the app that uses it, then offers fixes by level: safe (anonymous accounts, empty test database, local_infile), service (remote root, accounts with no password, FILE right, new app passwords written into the app's config), access (bind to 127.0.0.1, drop backdoor UDFs). Reports SUPER/GRANT accounts, planted-looking admin accounts, triggers, events, secure_file_priv, PostgreSQL trust.
- The site must still load afterwards (retried for PHP's cache); if it got worse, everything is put back on the spot. Undo restores accounts, old passwords (database and config), rights and settings. New passwords only in `passwords.txt` (mode 600).
- Found live: a password undo must use ALTER USER (CREATE USER fails on an existing account); PHP opcache can keep an old config, so configs are touched after writing and after restoring; a restart undo must be recorded before the config it reverts; the database service name is detected.
- **No CSV files** in SV-15 and SV-20 output: tables are `.txt` only.
- Tested: 31 checks with a real MariaDB under seven shells and three awks; live with a PHP page that logs in like the store.

## 2026-11-18: Site backup and restore (SV-15, new)

- **backup**: every site the web servers serve plus `/var/www`: files (archive + a hash of every file), the site's database read from its app config (WordPress, Joomla, Drupal, PrestaShop, OpenCart, Magento, Roundcube, `.env`), web server and PHP configs. Private `site-backup-N/` folder, optional copy off the box.
- **check**: what changed since the backup: changed (defaced pages, edited code, `.htaccess` HIGH), deleted, new (program files HIGH: web shell?), and changed web server configs. Changes nothing.
- **restore**: per site `[a]` all back, `[f]` files only, `[q]` quarantine new files, `[n]` nothing, plus the database if you say so. Only what changed is touched; the current state is saved first; revert timer; checks the site matches afterwards. A wiped site folder is rebuilt.
- Tested: 46 checks under seven shells and three awks (plus the database with real MariaDB: changed, restored, reverted). Found on the way: in ksh/mksh an unquoted `|` in `${x%%|*}` is a pattern "or".

## 2026-11-18: Web and database enum rebuilt (SV-01 v2)

- New look, same as the Linux enum: numbered sections with titles, flags shown live (`[!] FIX`, `[*] LOOK`), what was found in green, coloured summary. Run folder `web-enum-N/` with output.txt, a `.txt` table per result and CSVs in `csv/`.
- Questions: look at everything or pick sections, search file contents, other web folders, log in to the databases. Flags answer each (`--only`, `--fast`/`--deep`, `--webroot`, `--no-db`/`--db`).
- New **paths** section: which URL path serves which folder or app (web roots, aliases, CGI, `ProxyPass`/`proxy_pass` to apps, PHP/uWSGI handlers, status pages), listed on screen. Flags paths that serve `/`, `/etc`, `/root` or logs, and open server-status pages.
- New **runtimes** section: languages installed with versions, app servers running, app folders, and unknown programs on web ports. Flags development and debug servers (anyone who reaches them can run code) and app servers running as root.
- Also: a lint fix in SV-30 left by PR #49.
- Tested: 49 checks under seven shells and three awks; live on Ubuntu with Apache, nginx configs, PHP 8.3 and a planted WordPress site.

## 2026-11-18: Scored-service hardening (SV-30, LX-22)

Both scripts ask which box this is (`[s]plunk [w]ebmail [e]comm [o]ther`) and keep the scored checks working.
- **SV-30 web** (`ecomm-http`, `webmail-interactive`): hides the Apache, nginx and PHP versions (`ServerTokens Prod`, `ServerSignature Off`, `server_tokens off`, `expose_php Off`), turns off TRACE, and at the service level folder listings. Reports `.git`, backups, dumps, phpinfo pages and the Roundcube installer and version; moves them to quarantine at the access level.
- **SV-30 mail** (`webmail-smtp`, `webmail-imap`): Postfix greeting without name/OS, VRFY off (no username checking), HELO required (service level), open-relay check; Dovecot greeting without name, 5-second delay after a failed login; plaintext IMAP only reported.
- **SV-30 time and Splunk** (`splunk-chrony`, `splunk-mgmt`, `splunk-query`): chrony remote control limited to localhost, and a warning if chrony serves time to nobody; Splunk web UI and accounts reported, never changed.
- **Every changed service** is config-tested, restarted, and must answer on the same ports (and the website with the same status). If not, its files are put back. A revert also restarts each service.
- **LX-22**: says when SSH is scored on the box; `MaxStartups 10:30:60`; `DebianBanner no` (hides the Ubuntu build); replaces `/etc/issue`, `/etc/issue.net` with a plain warning shown before SSH login and turns off the update-motd scripts.
- Tested: fake root under seven shells and three awks; live with real Apache, Postfix, Dovecot and chrony: banners hidden, every service still answering, a failed Apache config test put back, and a revert restoring the old banners.

## 2026-11-18: Clearer questions in every script

Every question now says what each answer does, in the password-rotation style, with the default in capitals:

```
[?] Allow root to log in over SSH? (now: key-only (prohibit-password))
      [y] yes, with a password or a key (not recommended)
      [n] no, root cannot log in over SSH at all (log in as yourself, then sudo)
      [k] key-only, root needs an SSH key; passwords are refused
      [l] leave it as it is
      Answer [y/n/K/l]:
```

- Typed answers show what to type: `type: addresses or networks separated by spaces, like 10.0.0.5 10.0.0.0/24`.
- A wrong answer is refused and asked again (no more guessing what "y" means).
- Choice questions use letters: SV-30 level `[s]afe [v] service [a]ccess`; LX-31/LX-39 box `[s]plunk [w]ebmail [e]comm [o]ther`.
- LX-22 root login: `y`, `n`, `k`, `l`; `--root-login yes` added.
- Applies to LX-20, LX-22, LX-25, LX-31, LX-39, LX-40, LX-41, LX-42, SV-26, SV-30, SH-03, and the `dist/` copies.

## 2026-11-18: Linux review pass

Every Linux script was run for real (dry run or read-only) on Ubuntu 24.04 under dash and busybox sh, with the output read line by line, plus a search for known portability traps.
- **LX-40:** a team *network* (`10.0.0.0/24`) stopped the whole connection watch under busybox awk (no `^` operator: "Math support is not compiled in"). Now multiplies instead; the test uses a network.
- **All scripts:** errors from reading a file that vanished (`/proc/PID/...`) leaked to the screen under busybox sh, because `<file` was opened before `2>/dev/null`. Order swapped in LX-25, LX-40, LX-41, LX-42, SH-05, SV-26, SV-30.
- **LX-20:** the "human accounts not disabled" note listed locked build accounts (nixbld1..32); now only accounts someone can log in to. The kept-accounts line shows 15 names + a count.
- **LX-39:** the "found" line before a question shows 6 items + a count instead of every path.
- **LX-22, SH-05:** `PermitRootLogin without-password` reads like "root logs in without a password"; now shown as `key-only (without-password)`.
- Tests: every changed script under dash, ksh and busybox sh.

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
- lib.sh: `--batch`, `cc_ask`, `cc_ask_text`, `cc_color_init`, `cc_show`, `cc_now`, `cc_timer_start`, `cc_timer_finish`; changes are refused once the timer has run out. Tests never wait for answers (`BT_NO_TTY`).
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
- `tests/wn25.Tests.ps1` (stand-in state via `BT_WN25_FAKE`).
- Review fixes before merge: a rollback task left behind by a run kept from a non-elevated window no longer blocks the next run (kept runs are recognised, the leftover task removed, and a rollback that finds the run kept deletes its task); a second run no longer adds every rule again (an existing rule is kept when identical, replaced when its addresses changed; addresses compared in Windows' mask form).

**Tested**

- PowerShell 7.4 on Linux against stand-in state (89 checks). Not yet run on Windows.

## 2026-11-12: Windows safe fixes

**Added**

- WN-43 Windows safe fixes (`roles/windows-ad/WN-43-safe-fixes.ps1`): 20 safe fixes, 8 more with `-Include`, an undo plan written before every change and `-Undo` to replay it; keys are changed only after a successful backup; Defender and sfc results checked afterwards.
- `tests/wn43.Tests.ps1` (stand-in state via `BT_WN43_FAKE`).

**Tested**

- PowerShell 7.4 on Linux against stand-in state (109 checks), including undo back to the exact starting state. Not yet run on Windows.

## 2026-11-12: Windows password rotation

**Added**

- WN-20 Windows password rotation (`roles/windows-ad/WN-20-password-rotation.ps1`): local accounts, or domain users on a DC, through ADSI; `-Exclude`/`-Users` with the typo stop, `-Passwords` sheet, service-account and SPN detection, protected list, logon test after each change, pending file against an interrupted change.
- `tests/wn20.Tests.ps1` (stand-in accounts via `BT_WN20_FAKE`).

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
- `tests/sv14.test.sh` (the dump-drop-restore checks run only with `BT_TEST_DB=1`, so the suite never creates databases on a real server).

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
