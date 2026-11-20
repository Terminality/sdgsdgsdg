<!-- Built by tools/role-manuals.sh from docs/playbooks/network.md and docs/MANUAL.md. Edit those, then run it. -->

# Network manual

For whoever defends the network: the router and the view of every box from outside. Every command here uses the standalone scripts in `dist/network/`. Run them from the **admin workstation** (a Linux machine or WSL), not on the router: they log in to the router over SSH.

Flókið network:

| Thing | Address |
| --- | --- |
| Inside network | `192.168.220.0/24` |
| Outside network | `10.100.1XX.0/24`, XX = your team number (team 2: `10.100.102.0/24`). 1:1 NAT: `10.100.1XX.Y` is `192.168.220.Y`, only from outside the router |
| Router "Vigra" | OpenWRT, `192.168.220.2`; log in as `root` |
| Boxes | .10 Borgar (Windows), .30 Kolla (file share), .44 Kvígindis, .67 Haf, .79 Vattar (Windows AD), .97 Skerja, .100 Gufu (Gitea), .231 Thorska, .222 Djupi |

## How every script works

- **Dry run first.** Without `--apply` nothing changes on the router. Read the plan, then run again with `--apply`.
- **Questions.** One at a time, `[?] Question [Y/n]`; Enter takes the answer in capitals; every question has a flag; `--batch` takes the defaults.
- **Which devices.** Each NW script asks: use the host list (`hosts.txt` or `config/hosts.txt` in the folder you run from), or one device: its address, what it is (`[o]` OpenWRT is first), a name, the login (`root` for OpenWRT).
- **The password** is asked once, hidden, and never written anywhere. Or set it in `BT_NET_PASS` for the whole session: `export BT_NET_PASS='...'` (type a space before it so it stays out of the history).
- **The look.** Numbered sections `==========[ 2/5  ... ]==========`, a legend line, results in `~/bt-out/<name>-N/` with `output.txt` and `.txt` tables.
- **Never locked out.** The router stays reachable over SSH from outside (we log in from remote): SSH on the WAN is left on unless you choose otherwise, team sessions and accounts are never kicked by default, and a firewall change has a revert timer: log in again from a **new** session before you answer "keep".

## Before you start (2 minutes)

1. On the admin workstation, have `dist/network/` and a working `ssh`. `sshpass` is needed for password logins from a script; if it is missing, the scripts say so and how to get it.
2. Know your team number (N). If you don't, SH-03 asks and you can press Enter to scan only the inside.

## The first 15 minutes

| When | Script | What it does | Command |
| --- | --- | --- | --- |
| 0-4 min | **SH-03** Network scan | Every box inside and outside: open ports, versions, what each box looks like (router, domain controller, Gitea, file share, web app, RabbitMQ ...). Writes host-list rows | `sh SH-03-network-scan.sh` (asks the team number) |
| 4-5 min | make the host list | Copy SH-03's `suggested-hosts.txt` to `hosts.txt` in the folder you run from; fix the names | `cp ~/bt-out/netscan-1/suggested-hosts.txt hosts.txt` |
| 5-7 min | **NW-01** Config backup | Saves the router's whole config (`uci export`, nftables, passwords file, keys, cron, start-up). Later runs show what changed | `sh NW-01-config-backup.sh` |
| 7-8 min | **NW-07** Config audit | Reads the saved config offline: telnet, LuCI over plain HTTP, management open to everyone, default accounts, SSH keys. Touches nothing | `sh NW-07-config-audit.sh` |
| 8-10 min | **NW-12** Accounts and sessions | Who is logged in to the router now, every account, SSH keys. Dry run: look first | `sh NW-12-device-sessions.sh` |
| 10-12 min | **NW-10** Router password | New root password: the typed shared password is the default. Tests it from a second session before keeping it | `sh NW-10-device-passwords.sh --apply` |
| 12-15 min | **NW-21** Router hardening | Telnet off, LuCI limited, logging, NTP. SSH from outside stays on by default; risky changes always ask a person | `sh NW-21-device-hardening.sh --apply` |

What to look at after each one:

- **SH-03:** the "what each box looks like" table. Match each address to the diagram. A port you did not expect (4444, 31337, a second SSH) is red team. `roles.txt` has the table.
- **NW-01:** the first run is the baseline. Every later run prints `[!] HIGH` for a new account, SSH key, firewall rule, port forward or cron line.
- **NW-07:** each `[!]` says the setting and the fix; NW-21 makes most of them.
- **NW-12:** a session from an address that is not yours, an account you don't know, a key you don't know. `--kick-outside` and `--disable-new` act on them, only when you choose.
- **NW-10:** say who needs the new password **before** it changes (the script reminds you).

## After the first 15 minutes

| Script | What it does | When | Command |
| --- | --- | --- | --- |
| **NW-20** Firewall ruleset | A firewall table on the router (`inet bt_fw`): only the scored ports to each box, SSH and RDP (`--login-ports`) to every box, the port forwards kept. Persisted with a uci include; one command takes it out | When the boxes are up and you know the scored ports | `sh NW-20-firewall-ruleset.sh --apply` |
| **NW-30** Device watch | Logs in every N seconds and alerts on a change: new account, rule, forward, cron line, start-up script, config | Leave it running | `sh NW-30-device-watch.sh --every 60` |
| **SH-03 + SH-04** | Scan again and compare: new open ports, ports gone, changed versions | Every 30-60 min | `sh SH-03-network-scan.sh --batch`, then `sh SH-04-scan-diff.sh` |
| **NW-01** again | What changed on the router since the baseline | After any alert | `sh NW-01-config-backup.sh` |

### When something happens

| What you see | Run |
| --- | --- |
| A scored service is down but the box says it is up | NW-20's plan: is the port allowed? SH-03 from outside: does it answer? |
| NW-30 alerts on a change | NW-01 (what changed), NW-12 (who is logged in) |
| An unknown session on the router | NW-12 `--kick-outside --apply` (never kicks your own) |
| The router password leaked | NW-10 `--apply` |
| A port appears on a box | SH-04 shows it; tell the Linux or Windows person which box |
| The firewall broke something | `sh NW-20-firewall-ruleset.sh --remove --apply` |

### Notes for this network

- **A router reset costs -100 points**, and resets only happen at the cutover times (every 30 minutes, e.g. 10:00 or 10:30). Run the read-only scripts first and say "no" when unsure.
- The packet recommends keeping **syslog** and **WAN configuration access** on: NW-21 leaves SSH from outside, syslog and LuCI on the WAN as they are unless you say otherwise.
- **1:1 NAT:** from outside, `10.100.1XX.Y` is `192.168.220.Y` (team 2: `10.100.102.10` is Borgar). The scoring engine and your VPN come in from outside.

- Every NW script knows **OpenWRT**: `uci`, fw4/nftables, dropbear, LuCI (uhttpd), `ubus` sessions, busybox `passwd`. None has been run on a real OpenWRT router yet: start with the read-only ones (NW-01, NW-07, NW-12 without `--apply`).
- **SSH from outside stays on** (NW-21 `sshwan` defaults to leave). LuCI on the WAN is a separate finding (`webany`).
- NW-20 keeps 22 and 3389 open to every scored box (`--login-ports`; `none` closes them).
- The other NW scripts also know Cisco IOS and ASA, Palo Alto, FortiGate, VyOS, pfSense, OPNsense and MikroTik, for other networks.

## Deep dive: every network script

Each section below is the full reference for one script: how to run it, every question and its flag, what each check means, what it writes, and what to do when something goes wrong. They are in the order above.

Scripts: [SH-03](#sh-03-network-scan-distnetworksh-03-network-scansh) [NW-01](#nw-01-network-config-backup-and-diff-distnetworknw-01-config-backupsh) [NW-07](#nw-07-network-config-audit-distnetworknw-07-config-auditsh) [NW-12](#nw-12-device-accounts-and-sessions-distnetworknw-12-device-sessionssh) [NW-10](#nw-10-device-password-rotation-distnetworknw-10-device-passwordssh) [NW-21](#nw-21-network-device-hardening-distnetworknw-21-device-hardeningsh) [NW-20](#nw-20-firewall-ruleset-distnetworknw-20-firewall-rulesetsh) [NW-30](#nw-30-device-change-watch-distnetworknw-30-device-watchsh) [SH-04](#sh-04-scan-diff-distnetworksh-04-scan-diffsh) 

### SH-03: Network scan (`dist/network/SH-03-network-scan.sh`)

Finds live hosts and open ports, what runs on them, and what looks vulnerable. Run it from the admin workstation. It sends probes and changes nothing on any host.

#### How to run it

```sh
sh SH-03-network-scan.sh                                        # asks everything
sh SH-03-network-scan.sh --target 10.0.2.0/24 --batch            # all defaults, no questions
sudo sh SH-03-network-scan.sh --target 10.0.2.0/24 --vuln --udp --hosts config/hosts.txt
sh SH-03-network-scan.sh --targets-file subnets.txt --profile outside --hosts hosts.txt   # from outside the firewall
```

**What each box looks like.** After the checks, one line per address says what it probably is, from its open ports and the versions it shows: the router (OpenWRT: dropbear, LuCI), a Windows domain controller (88 + 389), Gitea (3000), a file share (Samba 445, NFS 2049), a Windows box (RDP, WinRM), RabbitMQ (5672, 15672), Home Assistant (8123), a web app (80, 443), or SSH only. This is how the boxes on the team diagram are matched to their addresses on the day. `roles.txt` has the table; `suggested-hosts.txt` has host-list rows ready to copy into `config/hosts.txt` (give them real names).

It asks like sqlmap (Enter takes the default, a flag answers in advance):

| Question | Default | Flag |
| --- | --- | --- |
| What to scan: one host, a range or a subnet; several with spaces | your own network | `--target` |
| Your team number? It adds the outside range `10.100.1XX.0/24` (team 2: `10.100.102.0/24`) | skip | `--team-number N` (`none` skips) |
| How aggressive: 1-2 slow and quiet, 3 normal, 4 fast, 5 fastest (can miss ports) | 4 | `--speed N` |
| Quick scan of the top ports | yes | `--quick` / `--no-quick` |
| How many top ports | 1000 | `--top-ports N` |
| Other ports to always scan, e.g. `8080,9000-9100` | none | `--extra-ports` / `--no-extra-ports` |
| Full scan, all 65535 ports | yes | `--full` / `--no-full` |
| Which hosts get the full scan (asked after the quick scan, when more than one is up) | all up | `--full-hosts "10.0.2.5 10.0.2.7"` |
| Service and version on each open port | yes | `--services` / `--no-services` |
| nmap default scripts (anonymous FTP, SMB signing, ...) | yes | `--scripts` / `--no-scripts` |
| nmap vuln scripts | no | `--vuln` / `--no-vuln` |
| Only the safe vuln scripts (no = all of them; some can crash a service) | yes | `--vuln-all` for all |
| OS guess (root) | yes | `--os` / `--no-os` |
| Top 25 UDP ports (root) | no | `--udp` / `--no-udp` |

Then it runs nmap in stages and shows nmap's own output as it goes: quick scan, full scan, details (versions, scripts, OS) on just the open ports, then UDP. Open ports are green, `VULNERABLE` red.

| Option | What it does |
| --- | --- |
| `--hosts` | The host list. Turns on the scored-service and unknown-host checks |
| `--profile fast` | Preset: quick scan + versions, no questions |
| `--profile full` | Preset: quick + full + versions (+ OS as root) |
| `--profile udp` | Preset: UDP only. Needs root |
| `--profile outside` | Like fast, but also scans hosts that drop ping. Run it from outside to see what the red team sees |
| `--ports` | Only these ports, e.g. `22,80,8000-8100` (replaces the quick and full scans) |
| `--engine` | Force `nmap`, `python`, `bash` or `nc` |
| `--no-dns` / `--pn` | Skip name lookups / treat every address as up |

**It checks for nmap first.** If nmap is missing it says so, prints the install command for your box (`sudo apt install nmap`, `dnf`, `yum`, `zypper`, `apk`, `pacman`) and asks whether to keep going without it. **Without nmap** it falls back to python3, then bash, then `nc -z`: 53 common TCP ports, a banner instead of a version, no scripts, no UDP, at most 1024 addresses.

#### What it produces

In `<out>/netscan-N/` (next free number):

| File | Contents |
| --- | --- |
| `output.txt` | Everything shown on screen, no colour |
| `summary.txt` | Counts, open ports per host, vulns, scored services, HIGH and MED flags |
| `hosts.txt`, `ports.txt` | Live hosts; every open port with service and version |
| `vulns.txt` | What the scripts found: `VULNERABLE` results, known CVEs for a version (with the worst score), anonymous FTP, empty database passwords, SMB signing off, PUT/DELETE allowed |
| `flags.txt` | Every flag, HIGH first |
| `scored.txt` | With `--hosts`: each scored service and whether it answered |

The `.txt` tables have their column names on the first line and columns separated by ` | `, so they can be read and also parsed (SH-04 and NW-20 read them). No CSV files.
| `raw/` | nmap's own output per stage (`1-quick`, `2-full`, `3-details`, `4-udp`) |

#### What it flags

| Severity | When |
| --- | --- |
| HIGH | A script says `VULNERABLE`. A version with a known CVE scored 9 or more. Anonymous FTP, an empty database password. A port that answers like a shell. A scored service that does not answer. Docker API on 2375. vsftpd 2.3.4, ProFTPD 1.3.3c/1.3.5, UnrealIRCd, Samba 3.0.20-3.0.25, distccd, Windows XP/2003 |
| MED | `LIKELY VULNERABLE`, CVE score 7 or more, PUT/DELETE allowed. A host up but not on the host list, or on it but silent. Telnet, rsh, TFTP, SNMP, VNC, Redis, MongoDB, Elasticsearch, memcached. Backdoor-style ports such as 4444 and 31337. With `outside`: Windows admin ports, and anything that is not a scored service |
| LOW | Databases reachable over the network, FTP, SMB signing off, lower CVE scores |

#### What to watch for

- **The full scan is slow**: minutes per host. nmap prints progress every minute. Say no to it for a first look, then run it.
- **Vuln scripts only point.** Nothing found does not mean safe; a hit means check that service now. By default only "safe" ones run, so they will not knock a scored service over. `--vuln-all` can.
- **Speed 5 can miss ports** on a slow or busy network. Use 3 if results look thin.
- **"Not reachable" means not reachable from where you ran it.** A firewall may block your workstation but allow the scoring engine. Check from the scoring side before changing anything.
- **Run it again later and compare** with the scan diff (SH-04). New ports and new vulns are flagged.
- **Scans are visible** in IDS and firewall logs. Fine on your own network.

#### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `nothing to scan` (exit 2) | No target and no terminal to ask | Add `--target` |
| `has N addresses; the python engine is limited to 1024` | Range too big without nmap | Install nmap, scan smaller pieces, or raise `--max-hosts` |
| `UDP scanning needs root` / OS skipped | Raw packets need root | `sudo` |
| `nmap produced no results` | A target nmap cannot parse, or no permission | Read `output.txt` |
| Hosts you know are up are missing | They drop ping and no top-1000 port answered | `--pn`, or `--profile outside` |
| Service ends in `?` or is `unknown` | nmap was unsure | Check `raw/3-details.nmap`; the fingerprint is there |
| Every scored service fails | Wrong addresses in the host list, or your workstation is firewalled off | Check `config/hosts.txt`; scan from another machine |

---


### NW-01: Network config backup and diff (`dist/network/NW-01-config-backup.sh`)

Logs in to every firewall, router and switch over SSH, saves its running configuration, and shows what changed since the last saved copy. Run it first (the copy you restore from) and again every few minutes (the change watch for network gear).

It only sends "show" commands. Nothing on the devices changes.

#### How to run it

```sh
sh NW-01-config-backup.sh --out ~/bt-out --hosts config/hosts.txt                        # SSH keys
BT_NET_PASS='...' sh NW-01-config-backup.sh --out ~/bt-out --hosts config/hosts.txt --password-env
sh NW-01-config-backup.sh --out ~/bt-out --device fw01,10.0.2.1,paloalto,admin --ask-password
## every 5 minutes:
while :; do sh NW-01-config-backup.sh --out ~/bt-out --hosts config/hosts.txt --password-env; sleep 300; done
```

Run it from the admin workstation (a Linux box that can reach the devices' management addresses).

**Without flags it asks.** If there is a `config/hosts.txt` it offers that; otherwise it asks for each device's address, what it is (`[o]` OpenWRT first), a short name and the login name (root for OpenWRT, pfSense and OPNsense). Then how to log in: a password typed now (hidden, never saved), the one in `BT_NET_PASS`, or SSH keys. Every answer has a flag; `--batch` uses SSH keys as before.

| Option | What it does |
| --- | --- |
| `--hosts FILE` | Host list. Rows with `os` = `network` take the vendor from the notes ("Palo Alto", "Cisco IOS", "Cisco ASA", "FortiGate", "VyOS", "pfSense", "OPNsense", "MikroTik") or a `vendor` column; a vendor name in `os` works too |
| `--device SPEC` | `NAME,ADDRESS,VENDOR[,USER[,PORT]]` (repeat) |
| `--user NAME` | Login name when the list gives none (default `admin`) |
| `--password-env` | Password from `$BT_NET_PASS`, handed to `sshpass -e` in the environment (never on a command line) |
| `--ask-password` | Ask once, without echo |
| `--keys` | Log in with SSH keys (no question) |
| `--enable-env` | Cisco: send `enable` with `$BT_NET_ENABLE` when the login is below privilege 15 |
| `--legacy-ssh` | Allow old SSH algorithms from the start. Also tried automatically when a device refuses the modern ones |

Without a password option, SSH keys are used and the script never prompts.

#### Vendors

| Vendor | Commands sent | Log in as |
| --- | --- | --- |
| `cisco-ios` | `terminal length 0`, `show running-config` | A privilege 15 account (or `--enable-env`) |
| `cisco-asa` | `terminal pager 0`, `show running-config` | An admin, usually with `--enable-env` |
| `paloalto` | `set cli pager off`, `show config running` | An admin |
| `fortigate` | `show` | An admin |
| `vyos` | `show configuration commands` | The VyOS user |
| `pfsense`, `opnsense` | `cat /conf/config.xml` | `root` (admin lands in the menu) |
| `mikrotik` | `/export` | An admin |
| `linux` | `iptables-save`, `nft list ruleset`, `ip addr`, `ip route` | root (named with a `vendor` column or `--device`) |
| `openwrt` | `uci export` (every setting), `nft list ruleset` (fw4), `ip addr`, `ip route`, `/etc/passwd`, root's SSH keys, cron, `/etc/rc.d`, `/etc/rc.local` | `root` |

Before comparing, lines that change by themselves are dropped: prompts and echoed commands, Cisco "Last configuration change" and NVRAM lines, ASA checksums and serial lines, the FortiGate file version, nftables packet counters, OpenWRT's DHCP lease times. On screen each device gets one line: `[ok]` saved, `[*]` saved and something changed, `[!]` not saved and why.

#### What it produces

| Where | What |
| --- | --- |
| `<out>/NW-01_<host>_<time>/summary.txt` | Per device: lines, lines added and removed, status; then the flags |
| `.../devices.txt` | Table: device, address, vendor, status, lines, added, removed, sha256 |
| `.../<device>.diff` | Unified diff against the previous copy (holds secrets; mode 600) |
| `.../flags.txt` | One flag per changed line, secrets masked, HIGH first |
| `<out>/net-configs/<device>/<time>.cfg` | Every saved config as received (mode 600) |
| `<out>/net-configs/known_hosts` | The devices' SSH host keys |

A changed line about accounts, passwords, SNMP, NAT, permits/allows/accepts, telnet, the web management server, AAA, crypto, tunnels, routes, rules, policies or SSH is HIGH. Any other change is MED.

#### What to watch for

- **The saved configs hold password hashes, SNMP communities and VPN keys.** Everything printed is masked; the files are not.
- **Check the first copy of each device looks complete.** A short file usually means the account cannot see the whole config (Cisco below privilege 15).
- **A changed SSH host key is HIGH and stops that device's backup.** The device was replaced or reinstalled, or someone is in the middle. Find out which, then delete its line from `known_hosts`.
- **The vendor commands are written from the vendors' documentation and tested against sample output, not real devices.** Run it once on the real gear before relying on it, and send any surprise to whoever maintains the kit.

#### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `backup FAILED: Permission denied` | Wrong user or password, or keys not installed | Check by hand: `ssh USER@ADDRESS`; for passwords use `--password-env` |
| `password logins need sshpass` (exit 3) | sshpass not installed on the admin box | `apt install sshpass`, or use keys |
| `empty answer (no rights to show the config?)` | Account cannot run the show command, or pfSense admin menu | Use a privilege 15 / admin account; pfSense: `root` |
| `no matching key exchange method` in the log | Very old device | Retried automatically; if it still fails, check `ssh -Q kex` on the admin box |
| `os is network but the vendor is unknown` | Notes do not name a vendor | Add the vendor to the notes or a `vendor` column |
| Every run shows the same lines changed | A line that changes by itself (a clock, a counter) | Send the line format to whoever maintains the kit; it belongs in the clean-up list |

---


### NW-07: Network config audit (`dist/network/NW-07-config-audit.sh`)

Reads the configs NW-01 saved and flags the weaknesses a red team uses first on network gear. It touches no device; run it right after the first NW-01 backup.

#### How to run it

```sh
sh NW-07-config-audit.sh --out ~/bt-out                                  # every device NW-01 saved
sh NW-07-config-audit.sh --out ~/bt-out --file r1.cfg --file fw1.txt     # configs copied by hand
sh NW-07-config-audit.sh --out ~/bt-out --file fw1.txt,paloalto          # name the vendor
```

Without `--file` it offers the newest config NW-01 saved for each device; with none saved it asks for a file and, when it cannot tell, what device it is from. The screen shows one line per device (`[!]` HIGH found, `[*]` MED, `[ok]` nothing), then the findings worst first.

| Option | What it does |
| --- | --- |
| `--configs DIR` | NW-01's saved configs (default `<out>/net-configs`); the newest copy of each device is read |
| `--file F[,VENDOR]` | Audit this file (repeat). The vendor is recognised from the text when not given |
| `--max-flags N` | Findings shown on screen (default 40) |

#### What it checks

| Vendor | HIGH | MED | LOW / INFO |
| --- | --- | --- | --- |
| Cisco IOS | telnet on VTY lines; `no login` on any line; `enable password`; account with type 0/7 password; default or read-write SNMP community | VTY without `access-class`; VTY without `transport input` (older IOS allow telnet); `ip http server`; type 7 line passwords; default-looking account names; no `enable secret`; SSH v1; small servers | HTTPS server; MD5 enable secret; no password encryption, SSH v2 or log server; finger; source routing; local accounts |
| Cisco ASA | telnet; ASDM (`http`) from 0.0.0.0; unhashed enable or account password; default SNMP community; `permit ip any any` | SSH from 0.0.0.0; `permit tcp/udp any any`; default-looking accounts | no log server; accounts |
| Palo Alto | `disable-telnet no`; telnet in a management profile; default SNMP community; a security rule with any source, destination and application that allows | `disable-http no`; HTTP in a management profile; the default `admin` account; no `permitted-ip` | SNMP v2c; admin accounts |
| FortiGate | `telnet` in an interface's `allowaccess`; default SNMP community; a policy accepting all to all for ALL services | `http` in `allowaccess`; an admin without `trusthost` | SNMP v2c; admin accounts |
| VyOS | telnet service; default or read-write SNMP community; plaintext password | | HTTPS API; SSH on every address; accounts |
| pfSense / OPNsense | default or read-write SNMP community; a WAN rule passing any to any | web GUI over plain HTTP | accounts |
| MikroTik | telnet on; default SNMP community | telnet not disabled (on by default); `www`, `ftp` or `api` on | accounts |
| OpenWRT | the outside (wan) zone accepts or forwards everything; wan to lan forwarding; router SSH or LuCI open from the outside; any-any allow from outside; UPnP on; default SNMP community; a second UID 0 account; telnet at boot | SSH (dropbear) on every interface; LuCI over plain HTTP; a management or database port forwarded in; root SSH keys; root cron jobs; commands in `/etc/rc.local`; an extra LuCI login | no remote log server; time client off; **the port forwards** (on a NAT router those are the scored paths); accounts |

Default or guessable SNMP communities: `public`, `private`, `cisco`, `community`, `admin`, `default`, `secret`, `password`, `snmp`, `monitor`, `manager`, `read`, `write`, `test`, `bt`.

#### What it produces

In `<out>/NW-07_<host>_<UTC time>/`: `summary.txt` (per device: vendor, counts, accounts; then the findings worst first), `findings.txt` (a table: device, vendor, severity, finding, detail) and `flags.txt`. Every config line shown has its secrets masked.

#### What to watch for

- **A finding is a lead, not a verdict.** An "any to any" rule may be the path the scoring engine uses; check before removing it.
- **It reads the config, not the running state.** Where a vendor's default is unsafe and does not appear in the config (older Cisco VTY lines, MikroTik telnet), that is reported as MED.
- **Palo Alto** is read in the brace format NW-01 saves (`show config running`), not the `set` format.
- **Fix with care.** Turning telnet or HTTP management off from the session you are using can cut you off. NW-11 (management hardening) will do it safely.

#### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `no saved configs` (exit 3) | NW-01 has not run with this `--out` | Run NW-01 first, or give `--file` |
| `vendor not recognised` | A config whose first lines do not identify the vendor | Name it: `--file FILE,VENDOR` |
| A device has no findings at all | Wrong vendor, or the saved config is incomplete | Check NW-01's copy is the full config; give the vendor |
| A finding that is wrong for your device | The rule follows the vendor's documented syntax; your version may differ | Send the config line to whoever maintains the kit |

---


### NW-12: Device accounts and sessions (`dist/network/NW-12-device-sessions.sh`)

A red team's first move on a firewall or router is to log in with an extra admin account and stay logged in. This shows every admin account and everyone logged in, on every device, then kicks and disables what is not yours.

#### How to run it

```sh
BT_NET_PASS='pw' sh NW-12-device-sessions.sh --hosts config/hosts.txt --team 10.0.0.0/24            # look, dry run
BT_NET_PASS='pw' sh NW-12-device-sessions.sh --hosts config/hosts.txt --team 10.0.0.0/24 --apply    # asks each
sh NW-12-device-sessions.sh --apply      # asks which devices, the password (hidden) and your team
```

Run it **once early**: that run saves the account names as the baseline (`net-accounts-baseline.txt` in `--out`). Later runs flag an account added since. Then run NW-10: a kicked session can log in again until the password changes.

#### What it shows

| What | Judged |
| --- | --- |
| Each admin account | `[ok]` the login account, `--known` ones, protected ones; `[!]` new since the first run; `[*]` the rest on the first run (are they yours?) |
| Each session | `[ok]` this script's own login (your login account from this box's address, `--me`); `[ok]` from `--team`; `[*]` on the console; `[!]` from anywhere else |
| Odd names | An account or session with a quote, `;` or other odd character: `[!]`, never put into a command |

#### The questions

| Question | Answers | Flag |
| --- | --- | --- |
| Use the host list `config/hosts.txt`? (when there is one) / else each device: address, what it is (`[o]` OpenWRT first), name, login | | `--hosts`, `--device` |
| Device password (hidden, never saved) | typed | `BT_NET_PASS` (used as it is), `--ask-password` |
| Your team's addresses? (their sessions are left alone) | addresses or networks, or Enter for none | `--team` |
| Each session not yours | `[k]ick` / `[l]eave` (the default: it may be a teammate) / `[a]ll the rest default` | `--kick-outside` makes kick the default for sessions from outside `--team` |
| Each account to look at | `[d]isable` / `[k]eep` (the default: a teammate may have made it) / `[a]ll the rest default` | `--disable-new` makes disable the default for accounts new since the first run; `--known` |
| Do these? | `[y]` / `[n]` | `--apply` |

An account you keep (with `--apply`) joins the baseline and is not asked about again.

**It never kicks the team off a device by itself:** nothing is kicked or disabled unless you answer `k` or `d` for it, so `--batch` kicks and disables nothing (unless `--kick-outside` / `--disable-new` are given).

#### What each brand does

| Brand | Disable | Kick | Undo |
| --- | --- | --- | --- |
| Cisco IOS / ASA | `no username`, `write memory` | `clear line vty N` / `ssh disconnect N` | puts back the account's line from NW-01's saved copy |
| Palo Alto | `delete mgt-config users`, `commit` | `delete admin-sessions username` (all of that account's sessions; never your own account) | **none** (the question says so) |
| FortiGate | `delete` in `config system admin` | not automatic: the command is shown (its session numbers shift) | from NW-01's saved copy |
| VyOS | `delete system login user`, `commit`, `save` | `pkill -t pts/N` | from NW-01's saved copy |
| MikroTik | `/user disable` | `/user active request-logout` | `/user enable` |
| Linux | `usermod -L -e 1` | `pkill -t pts/N` | `usermod -U` |
| OpenWRT | `!` before the hash in `/etc/shadow`, shell set to `/bin/false` (no `usermod` there) | SSH: `kill` its dropbear process; web (LuCI): `ubus call session destroy` | the `!` comes off, the old shell goes back |
| pfSense / OPNsense | web GUI only: listed | | |

**OpenWRT:** accounts come from `/etc/passwd` and `/etc/shadow` (every UID 0 account, every account with a shell; `NO PASSWORD` is shown); SSH sessions are dropbear's connections (`netstat -tnp`), with their owner; web (LuCI) sessions come from `ubus` and do not say where they come from, so they default to **leave**. Two UID 0 accounts share one uid: a session of uid 0 is shown as root, and this script's own login is never kicked.

The undo reads the account's lines from NW-01's copy **when it runs**, so no password hash is copied into the results. Without an NW-01 copy there is no undo for that account, and the question says so. An undo script needs `BT_NET_PASS` set.

#### What it produces

In `device-sessions-N/`: `output.txt`, `accounts.txt`, `sessions.txt`, `plan.txt`, `summary.txt`, `undo/DEVICE-ACCOUNT.sh`.

#### What to watch for

- **Not yet run on real Cisco, Palo Alto, FortiGate, VyOS or MikroTik devices.** The stand-in answers follow each brand's documentation. Run it without `--apply` first and check it lists what the web GUI shows.
- **A teammate outside `--team` looks like red team.** Give `--team`, and read each question.
- **Only local accounts.** TACACS/RADIUS logins live on that server.
- **Linux without `/var/run/utmp`** (some containers) shows no sessions.


### NW-10: Device password rotation (`dist/network/NW-10-device-passwords.sh`)

Changes the password of the account used to log in to each firewall, router and switch (and, for Cisco, optionally the enable secret) without risking a lock-out. Run NW-01 first: Cisco privilege levels are read from its saved configs.

#### How it avoids lock-outs

1. It logs in with the current password and sends the change, keeping that session **open**.
2. It opens a **second, new** session with the new password.
3. If the new login works, it saves the config through the first session (`write memory` on Cisco; Palo Alto and VyOS commit). If it fails, it sets the **old password back** through the first session, tests the old password, and reports the device as failed.

If the first session closes early (some devices end the session after a password change), the script tests the new password directly and says whether the config may need saving by hand.

#### How to run it

```sh
export BT_NET_PASS='current password'
sh NW-10-device-passwords.sh --out ~/bt-out --hosts config/hosts.txt                       # dry run
sh NW-10-device-passwords.sh --out ~/bt-out --device r1,10.0.0.1,cisco-ios,admin --apply   # ONE device first
sh NW-10-device-passwords.sh --out ~/bt-out --hosts config/hosts.txt --apply
```

| Option | What it does |
| --- | --- |
| `--hosts FILE` / `--device SPEC` | The devices, as for NW-01. Without them it asks: the host list `config/hosts.txt` if there is one, else each device (address, what it is with `[o]` OpenWRT first, a name, the login) |
| `--user NAME` | Default login account (`admin`) |
| `--ask-password` | Ask for the CURRENT password instead of `$BT_NET_PASS` (also asked, hidden, when `BT_NET_PASS` is not set) |
| `--random` | A new random password per device, without the question "New passwords? `[t]`ype one for every device (hidden, typed twice; the default: one password the team is told) / `[r]`andom per device" |
| `--passwords FILE` | Chosen new passwords: `device password` lines (a space between; `#` starts a comment), by device name or address (same characters as below, 8+). Devices not in the file get a random password. A name that is no device in this run is reported. An older `device,password` file is still read |
| `--new-password-env` | Use `$BT_NET_NEWPASS` for every device (letters, digits and `_ . , @ % + = -`, 12+ characters). Default: a new random password per device |
| `--enable-env` | Cisco: log in through `enable` with `$BT_NET_ENABLE` |
| `--enable-too` | Cisco: also set a new enable secret; the test login must reach privilege 15 with it |
| `--length N` | Random password length (default 16) |
| `--wait N` / `--commit-wait N` | Seconds before testing a change (default 5) / for a Palo Alto commit (default 120) |
| `--revert-after N` | MikroTik: the device puts the old password back by itself after N seconds unless the new one was proven (default 90) |
| `--configs DIR` | NW-01's saved configs (default `<out>/net-configs`) |
| `--legacy-ssh` | Allow old SSH algorithms |

With `--apply` it first says that everyone who logs in with the current password (teammates, a scoring engine; on OpenWRT also the web page) needs the new one, then asks once, "Change the password on N device(s) now?", before anything is sent (`--batch` says yes). Leave out a device a scoring engine logs in to (`--protected`). Each device gets one line on screen: `[+]` changed and the new login tested, `[~]` would change, `[-]` skipped, `[x]` failed with the old password put back. The new passwords are only in `passwords.txt` (mode 600).

Password logins need `sshpass` on the admin workstation. Every password travels in an environment variable, on the session's input, or (MikroTik) in a mode-600 ssh config file that is deleted right after; never on a command line. Device output is never logged (it can echo the new password).

#### What it sends

| Vendor | Change | Saved by |
| --- | --- | --- |
| `cisco-ios` | `username U privilege N secret NEW` (N read from NW-01's copy) | `write memory` after the test |
| `cisco-asa` | `username U password NEW privilege N` | `write memory` |
| `paloalto` | `set mgt-config users U phash HASH` (SHA-256 crypt made with `openssl`), `commit` | the commit |
| `fortigate` | `config system admin` / `edit U` / `set password NEW OLD` | immediate |
| `vyos` | `set system login user U authentication plaintext-password` (stored hashed), `commit`, `save` | `save` |
| `mikrotik` | one command: first `/system scheduler add name="bt-nw10-revert" interval=Ns` (sets the OLD password back), then `/user set [find name="U"] password="NEW"`. New login works: the scheduled job is removed and its removal checked. It fails: the device puts the old password back by itself; the old login is tested after the wait | immediate |
| `linux` | `chpasswd` (or `sudo -n chpasswd`) | immediate |
| `openwrt` | `printf 'NEW\nNEW\n' \| passwd root` in the open session (busybox `passwd`; `printf` is built into the shell, so the password is on no command line). The same password is the web (LuCI) login | immediate |
| `pfsense`, `opnsense` | not changed: listed with "change it in the web GUI" | |

#### What it produces

In `<out>/NW-10_<host>_<UTC time>/`: `summary.txt`, `devices.txt` (a table: device, address, vendor, account, status) and, with `--apply`, `passwords.txt` (a table, mode 600). Give the passwords to the captain, then delete the file. Run NW-01 again afterwards: the changed account lines show up as expected changes.

There is no undo-log line: a password cannot be put back without storing it. The previous password is the team's old one.

#### What to watch for

- **Try one device first.** The vendor commands follow each vendor's documentation and were tested against a stand-in device, not real gear.
- **Scored logins.** If the scoring engine logs in to a device, put that device (type `host`, its address) or account on the protected list, or report the new password the way the competition requires.
- **AAA logins** (TACACS+, RADIUS, LDAP) are changed on the AAA server, not here. A Cisco account that is not in the saved config is skipped for this reason.
- **`REVERT NOT CONFIRMED`** means the new password failed AND the old one could not be confirmed. Go to that device's console now.
- **MikroTik:** RouterOS may not read commands from a session's input, so it does not get the open-session revert; the device itself puts the old password back after `--revert-after` seconds. Until the new password is proven, the old one sits in the scheduled job `bt-nw10-revert`. If the job cannot be removed, the summary says so: remove it by hand (`/system scheduler remove [find name=bt-nw10-revert]`) or the old password comes back. A current password with characters RouterOS reads as code (`$`, `\`, quotes) is refused: change that device in WinBox.

#### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `could not log in with the current password` | Wrong `BT_NET_PASS`, wrong account, device unreachable | Check by hand with `ssh`; nothing was changed |
| `account not found in NW-01's saved config` | Cisco: NW-01 not run, or AAA login | Run NW-01; change AAA accounts on the AAA server |
| `new password did not work; old password restored and tested` | The device refused the change (password rules, privilege) | Read the device's password policy; try `--new-password-env` with a password that meets it |
| `config may not be SAVED` | The device closed the first session early | Log in and save (`write memory`) by hand |
| Palo Alto shows failed after a long wait | The commit took longer than `--commit-wait` | Raise `--commit-wait` |
| `sshpass not found` (exit 3) | Not installed | `apt install sshpass` |

---


### NW-21: Network device hardening (`dist/network/NW-21-device-hardening.sh`)

Locks down how the firewalls, routers and switches themselves are managed: who can log in to them, over what, and where their logs go.

#### How to run it

```sh
BT_NET_PASS='pw' sh NW-21-device-hardening.sh --hosts config/hosts.txt --team 10.0.0.0/24 --log-host 10.0.0.20 --ntp 10.0.0.20            # look, dry run
BT_NET_PASS='pw' sh NW-21-device-hardening.sh --device fw1,10.0.0.1,paloalto --team 10.0.0.0/24 --log-host 10.0.0.20 --ntp 10.0.0.20 --apply   # ONE device first
```

Run NW-01 before (backup) and after (the changes become the saved copy).

#### What it checks

| Check | Cisco IOS | Cisco ASA | Palo Alto | FortiGate | VyOS | MikroTik |
| --- | --- | --- | --- | --- | --- | --- |
| Telnet / plain HTTP management | `transport input ssh`, `no ip http server` | `no telnet` lines | `disable-telnet` / `disable-http yes` | `allowaccess` without telnet/http | `delete service telnet` | `/ip service disable` telnet, ftp, www, api |
| Management open to any address | ACL `BT-MGMT` on the vty lines | `ssh` / `http` lines for the team only | `permitted-ip` | `trusthost` per admin | reported (NW-20) | `address=` on ssh, winbox |
| Idle timeout (`--timeout`, 10) | `exec-timeout` | `ssh timeout` | `idle-timeout` | `admintimeout` | | |
| Default SNMP community | removed | removed | reported | reported | removed | reported |
| Log server (`--log-host`) | `logging host` | `logging host` | reported (web GUI) | `syslogd setting` | `syslog remote` | remote logging action |
| Time server (`--ntp`) | `ntp server` | `ntp server` | `ntp-servers` | `system ntp` | `ntp server` | `ntp client` |
| Banner (`--banner`) | `banner login` | `banner login` | `login-banner` | `pre-login-banner` | `banner pre-login` | `/system note` |
| Other | SSH v2, `service password-encryption` | | | | | MAC telnet / WinBox off |

A non-default SNMP community is reported, but its value is never shown or written. The management limit always keeps this box (`--me`, else found with `ip route get`). Linux devices: use LX-22 and LX-25. pfSense / OPNsense: the web GUI places are listed.

**OpenWRT** (log in as root). Every fix is a `uci` setting, committed, and only that service reloaded; every one has an undo line:

| Found | Fix |
| --- | --- |
| Web admin (LuCI) over plain HTTP | `uhttpd.main.redirect_https=1` |
| The web admin on every address | on the router's lan address (a management change: you confirm a login from another team machine) |
| SSH on the outside (wan) | shown, **left by default**: the team logs in from outside. `[f]ix` puts SSH on `lan` only. To limit who may connect from outside, use NW-20 |
| UPnP on | off, and `miniupnpd` disabled |
| Telnet started at boot | stopped and disabled |
| No SSH idle timeout | `IdleTimeout` = `--timeout` minutes |
| Logs not sent to `--log-host` / time not from `--ntp` | `log_ip` / added to `system.ntp.server` |
| No login banner | `/etc/bt-banner` and dropbear's `BannerFile` |
| Default SNMP community | reported only |

#### The questions

| Question | Answers | Flag |
| --- | --- | --- |
| Which devices: the host list `config/hosts.txt`, or each typed (OpenWRT first) | | `--hosts`, `--device` |
| Device password (hidden) | | `BT_NET_PASS`, `--ask-password` |
| Your team's addresses? (management is limited to them and this box) | addresses or networks, Enter = do not limit | `--team` |
| Send the devices' logs to a log server? / Take the time from a time server? | an address, Enter = no | `--log-host`, `--ntp` |
| Each finding | `[f]ix` (default) / `[l]eave` / `[a]ll the rest default` | `--batch` |
| Do these? | `[y]` / `[n]` | `--apply` |
| After a management or telnet change: log in from another team machine, keep? | `[y]` within `--timer` seconds (60), else put back | none: a person answers |

**It never locks the team out.** A change that can stop someone logging in (a management limit, telnet or HTTP management off, SSH or the web admin limited) is:
- never the default for a limit on who may log in: the default is `[l]eave`, and the question says who would be locked out (`--fix-access` makes fix the default; the confirmation below still happens)
- never kept without a person confirming a login from ANOTHER machine within `--timer` seconds
- with `--batch` or no terminal: not made at all, only shown ("left: ... run without --batch"). The other fixes (logging, time, banner, SNMP, idle timeout) still go in.

#### How a device is changed

1. One SSH session to the device stays open; the changes go in through it.
2. A NEW login from this box is tried. If it fails, everything is put back through the open session, and a new login is tried again.
3. For a management limit or telnet change, it asks you to log in from another team machine. No answer in time, or `n`: put back.
4. Saved (`write memory`, `commit`, `save`), then the device is read again and each finding checked: `[+]` fixed or `[x]` still there.

#### What it produces

In `device-hardening-N/`: `output.txt`, `findings.txt`, `plan.txt`, `summary.txt`, `undo/DEVICE.sh` (puts the device back; needs `BT_NET_PASS`).

#### What to watch for

- **Not yet run on real devices.** The commands follow each brand's documentation. Run without `--apply`, then `--apply` on ONE device (`--device`).
- **The management limit locks out anyone outside `--team`**, including a scoring engine that logs in to the device. Put its address in `--team`, or the device on the protected list.
- **The confirm countdown only expires by itself in shells with `read -t`** (bash, ksh, mksh, yash, busybox); in dash it waits for an answer.
- **If this script is killed during the countdown**, the open session dies with it and the changes stay (Cisco and VyOS: unsaved, a reload undoes them).


### NW-20: Firewall ruleset (`dist/network/NW-20-firewall-ruleset.sh`)

Puts a short set of named `bt-` rules at the TOP of the network firewall, so from outside only the scored services can be reached. The old rules stay where they were (below), nothing is deleted, and everything can be taken out again.

#### How to run it

```sh
sh SH-03-netscan.sh --hosts config/hosts.txt                                     # first: the ports to offer
BT_NET_PASS='pw' sh NW-20-firewall-ruleset.sh --device fw1,10.0.0.1,paloalto --team 10.0.0.0/24            # look, dry run
BT_NET_PASS='pw' sh NW-20-firewall-ruleset.sh --device fw1,10.0.0.1,paloalto --team 10.0.0.0/24 --apply    # asks each step
BT_NET_PASS='pw' sh NW-20-firewall-ruleset.sh --device fw1,10.0.0.1,paloalto --remove --apply              # take it all out
```

Run NW-01 before (backup) and after. The scored boxes come from `--allow ADDR:PORTS` (repeat), from `--file LIST.txt` (one box per line: `10.0.0.5  80 443 53/udp  # webmail`), from the newest SH-03 scan (offered port by port), or typed in.

#### The rules

| Rule | Default | What it does |
| --- | --- | --- |
| `bt-team` | on | Your team's addresses (`--team`, and `--remote`: where you log in from outside) may reach anything |
| login ports | on | `22,3389` (`--login-ports`) are added to every scored box's rule, from any address, so the team can always log in from outside; `--login-ports none` closes them |
| `bt-in-ADDR` | on | ANY address to each scored box, its scored ports only (any address, so the scoring engine always gets through) |
| `bt-ping` | on | Ping in to the scored boxes (every box has a ping check) |
| `bt-in-block` | on | Everything else coming in from outside: blocked and logged |
| `bt-out-ADDR` | off | With outgoing limits: the servers may start connections only to DNS (`--dns`), NTP (`--ntp`) and what you list (`--out-allow`) |
| `bt-out-block` | off | With outgoing limits: anything else the servers start is blocked and logged (stops web-shell callbacks, reverse shells and most exfil) |
| threat prevention | off | Palo Alto: virus, spyware, vulnerability profiles; FortiGate: IPS and AV, on the scored rules |

Replies to allowed connections always pass, so a scored service still answers when outgoing limits are on.

#### The questions

| Question | Answers | Flag |
| --- | --- | --- |
| Each port from the SH-03 scan: reachable from outside? | `[k]eep` open / `[b]lock` (scored-looking ports default keep) | `--allow`, `--file` |
| Is this list of scored boxes and ports right? | `[Y/n]` | `--batch` |
| Your team's addresses | typed | `--team` |
| Addresses you log in to the boxes from outside the firewall (remote teammates, VPN)? | typed, Enter = none | `--remote` |
| Ports you log in to the boxes on from outside? (kept open to every box from any address) | `22,3389`, or `none` | `--login-ports` |
| Limit what the scored servers can START out? | `[y/N]`, then DNS, NTP, more places | `--restrict-out`, `--dns`, `--ntp`, `--out-allow` |
| Threat prevention on the scored rules? | `[y/N]` | `--threat` |
| Each rule, in plain words | `[K/s]` keep / skip | `--batch` |
| Which zone / interface is outside, which has the servers | picked from the device's list (`a` = all of them, Palo Alto and FortiGate); without a terminal it never guesses | `--outside`, `--inside` (`all`) |
| Nothing answers from here: go on anyway? | `[y/N]` | |
| Put these rules on DEVICE now? | `[Y/n]` | `--apply` |
| Check the SCOREBOARD: keep them? | `[Y/n]` within `--timer` seconds (120), else put back | `--batch` keeps |
| With `--remove`: take NW-20's rules off DEVICE now? | `[Y/n]` | `--apply` |

#### Per brand

| Brand | What is sent | Taken out by |
| --- | --- | --- |
| Palo Alto | service objects, `bt-` security rules moved to the top, `commit` | deleting the `bt-` rules and services, `commit` |
| Cisco ASA | access list `BT-IN` bound to the outside interface (it takes the place of the old one); with outgoing limits `BT-OUT` on the inside, ending `permit ip any any`; `write memory` | the old access list bound again, `BT-IN` / `BT-OUT` cleared |
| FortiGate | address objects `bt-a-ADDR`, services, policies 9101 and up, moved before the first other policy | the policies, then the services, then the addresses deleted |
| MikroTik | forward-chain rules with comments `bt-...`, placed on top | `/ip firewall filter remove [find comment~"^bt-"]` |
| Linux router | its own nftables table `inet bt_fw` (forward hook, runs before the others), checked with `nft -c` first | `nft delete table inet bt_fw` |
| OpenWRT | the same `inet bt_fw` table, kept in `/etc/bt_fw.nft` and loaded by fw4 at every reload and boot (a uci `include`); the router's enabled port forwards are kept open (asked, `--no-forwards` to drop them), each to its inside address and port | `nft delete table inet bt_fw`, the uci include removed, the file deleted |
| pfSense / OPNsense | the plan as web GUI steps in `plan.txt` | by hand |
| Cisco IOS / VyOS | the plan in `plan.txt`, not applied | by hand |

NAT: Palo Alto and FortiGate match the OUTSIDE address of a box. Their NAT rules and virtual IPs that lead to a scored box are read, and those names are added to its rules (shown, and listed in `plan.txt`). ASA, MikroTik, Linux and OpenWRT match the inside address (on OpenWRT the forward chain sees a port forward after it was turned into the inside address and port).

#### How the firewall is changed

1. Every scored box:port and ping is tried from this box. If nothing answers, it stops and asks.
2. One session to the firewall stays open; the rules go in through it.
3. The undo is written before anything is sent. After `--wait` seconds (Palo Alto: once the commit says it worked, at most `--commit-wait`) the same tries run again. Anything that answered before and no longer does: everything is put back at once, by itself, through the open session. The same happens if the firewall refused a command, a Palo Alto commit did not work, or a new login fails.
4. Ctrl-C while a firewall is being changed puts it back too.
5. It asks you to check the scoreboard. No answer in time, or `n`: put back.

#### Putting it back later

- `sh firewall-ruleset-N/undo/DEVICE.sh` (needs `BT_NET_PASS`), or
- `sh NW-20-firewall-ruleset.sh --device ... --remove --apply` (uses `nw20-DEVICE.undo` in `--out`, kept between runs).

Running it again deletes the earlier `bt-` rules first and puts the new ones on; putting a second run back leaves no `bt-` rules at all. The ASA undo still puts the ORIGINAL access list back.

#### What it produces

In `firewall-ruleset-N/`: `output.txt`, `scored.txt`, `plan.txt` (every rule in plain words, per device), `commands-DEVICE.txt` (exactly what is sent), `checks.txt` (before and after), `summary.txt`, `undo/DEVICE.sh`.

#### What to watch for

- **Not yet run on a real Palo Alto, ASA, FortiGate or MikroTik.** The commands follow each brand's documentation. Run without `--apply`, read `plan.txt` and `commands-DEVICE.txt`, then `--apply` on ONE firewall.
- **A missed scored port is blocked.** Check the list against the competition packet before saying yes.
- **The checks run from this box.** If this box is inside, its tries may not cross the firewall: watch the scoreboard during the countdown.
- **ASA outgoing limits** sit on the servers' interface, so they also stop the servers reaching other inside networks (the team stays open). List those with `--out-allow`.
- **Outgoing limits** stop updates and anything the servers fetch (package mirrors, an outside database). List those with `--out-allow`, or leave the limits off.
- **The countdown only expires by itself in shells with `read -t`** (bash, ksh, mksh, yash, busybox); dash waits for the answer.


### NW-30: Device change watch (`dist/network/NW-30-device-watch.sh`)

Reads every firewall, router and switch every few minutes and shows what changed since the config you trust. Read-only: it sends the same show commands as NW-01 and never changes a device.

#### How to run it

```sh
BT_NET_PASS='pw' sh NW-30-device-watch.sh --hosts config/hosts.txt                     # asks, then watches until Ctrl-C
BT_NET_PASS='pw' sh NW-30-device-watch.sh --device fw1,10.0.0.1,paloalto --every 60
BT_NET_PASS='pw' sh NW-30-device-watch.sh --hosts config/hosts.txt --once --batch     # one round (cron)
```

Run NW-01 first, after your own hardening: its copy is the best baseline.

#### The questions

| Question | Answers | Flag |
| --- | --- | --- |
| Watch these devices? | `[Y/n]` | `--batch` |
| Each device: which config is the trusted one? | `[k]eep` the earlier watch's baseline / `[n]` NW-01's copy / `[f]resh`, read now (the first one there is the default) | `--baseline keep\|nw01\|fresh` |
| How often? | every 1, 2 (default), 5 or 10 minutes | `--every SECONDS` |
| For how long? | until Ctrl-C (default) / once / an hour / four hours | `--for MINUTES`, `--once`, `--rounds N` |
| New changes on DEVICE: made by your team? | `[n]ot ours` (default) / `[o]urs` / `[e]ach one` | none: `--batch` leaves every change open |

Only a person can say a change was ours. When every new line carries NW-20 or NW-21's names (`bt-`, `BT-IN`, `BT-MGMT`), Enter says ours.

#### What it shows for each change

```
[!] HIGH added: username evil privilege 15 secret 5 ****
      account: an account added or changed: a back door?
      undo (not sent): configure terminal / no username evil privilege 15 secret 5 ****
```

- **added, removed or moved.** Each line is compared with the section it sits in, so `shutdown` under one interface is not the same as under another. Moved means a rule changed places (above or below another).
- **HIGH** for accounts, passwords and keys, SNMP, scheduled jobs, AAA, VPN and tunnels, NAT, management access, firewall rules, logging, routes, anything turned off. **MED** for the rest.
- **The undo** is a suggestion for Cisco, VyOS, FortiGate, Linux iptables and MikroTik, and a place to look for Palo Alto and pfSense / OPNsense. It is never sent: check it, then type it.
- **OpenWRT** (`--device router,192.168.220.2,openwrt,root`): every uci setting, the fw4 rules, accounts, root's SSH keys, cron and boot scripts are watched, the same read as NW-01 (so NW-01's copy can be the baseline). Counters and DHCP lease times are not changes. A change shows its uci section (`package firewall > config redirect`) and a uci undo (`uci delete ...; uci commit firewall; fw4 reload`); an account, key or cron line says which file to edit.
- A change is shown once. It stays on the open list until it goes away ("back as in the baseline") or you say it was ours. If a change you said was ours is later undone by someone, that is shown as HIGH.
- A changed SSH host key is HIGH and that device is no longer read. A device that cannot be read is tried again next round.

#### What it produces

In `device-watch-N/`: `output.txt`, `changes.txt` (every change: time, device, level, kind, line, section), `undo-hints.txt`, `rounds.txt`, `summary.txt` (what is still open). In `--out/net-watch/DEVICE/` (mode 700, kept between runs): the baseline, the lines you said were ours, the open list, and each changed read (mode 600).

#### What to watch for

- **Not yet run on real devices.** Run `--once` first: a quiet device must show no change. A line that changes by itself on every read is noise; report the brand and the line.
- **Secrets are shown as `****`.** The full read is in `net-watch/DEVICE/copies/`.
- **FortiGate secrets (`ENC ...`)** read differently each time, so they are hidden before comparing: a changed secret is not seen (a new admin still is).
- **Ctrl-C stops it cleanly**; the summary is still written.


### SH-04: Scan diff (`dist/network/SH-04-scan-diff.sh`)

Answers "what changed since last time?" by comparing two earlier runs of the network scan (SH-03) or two runs of the Linux enum (SH-05) on the same host. It only reads their CSV files; it touches no host and needs no root.

The point: run SH-03 and SH-05 in the first minutes as a baseline, run them again later, and diff. Anything **added** is where to look for red team persistence.

#### How to run it

```sh
sh SH-04-scan-diff.sh --out ~/bt-out                        # the newest two network scans
sh SH-04-scan-diff.sh --out /root/bt-out --type sh05        # the newest two enum runs of the newest run's host
sh SH-04-scan-diff.sh --out /root/bt-out --type sh05 --host web01
sh SH-04-scan-diff.sh --old ~/bt-out/netscan-1 --new ~/bt-out/netscan-2
```

| Option | What it does |
| --- | --- |
| `--old` / `--new` | The two run folders to compare. Give both or neither. The type comes from the folder names |
| `--type sh03` (default) / `sh05` | Which runs to pick when no folders are given |
| `--host` | With `--type sh05`: whose runs. Default: the host of the newest SH-05 run |
| `--runs` | Where the run folders are, if not in the `--out` folder (e.g. enum results copied off each box into one folder) |
| `--max-lines` | Changes listed on screen (default 40; every change is in `changes.txt`) |
| `--max-flags` | HIGH and MED flags shown on screen (default 30) |

**Which runs it picks.** Run folders are named `<ID>_<host>_<UTC time>`, so the newest two by time are compared. Folders without `summary.txt` are skipped: those are runs that were stopped part way and would look like everything was removed.

#### What it compares

| Run type | Section | A row is the same thing when these match | Compared for "changed" |
| --- | --- | --- | --- |
| SH-03 | hosts | address | name |
| SH-03 | ports | address, protocol, port | service, version |
| SH-03 | scored | host, address, service, port | reachable |
| SH-03 | vulns | address, protocol, port, script | state, title |
| SH-05 | users | user | UID, shell, can log in, password state, groups |
| SH-05 | ports | protocol, address, port | process, program |
| SH-05 | services | name | enabled, active |
| SH-05 | autostart | source, user, entry | |
| SH-05 | ssh_keys | user, file, fingerprint | type, comment, options |
| SH-05 | sudo, pam | file, entry | |
| SH-05 | suid | path | mode, owner |
| SH-05 | capabilities | path | capabilities |
| SH-05 | immutable | path | attributes |
| SH-05 | firewall | tool | status, detail |

Processes and connections are not compared: they change every second. Line numbers and PIDs are left out of the comparison on purpose, so editing a file above a sudo rule or restarting sshd does not show as a change.

#### What it produces

In a numbered folder: `<out>/diff-1`, `diff-2`, ...

| File | Contents |
| --- | --- |
| `summary.txt` | Per-section counts of added, removed and changed; the changes (added first); the HIGH and MED flags |
| `changes.txt` | Every difference as a table (columns separated by ` | `), additions first |
| `flags.txt` | Every flag, HIGH first |

It reads SH-03's `.txt` tables, or the `csv/` folder of scans made before that change, so an older scan and a newer one still compare.

#### What it flags

| Severity | When |
| --- | --- |
| HIGH | SH-03: a scored service that answered before and does not now; a new vuln or script finding; a backdoor-style port (4444, 31337, 1337, 2375 and others) newly open. SH-05: a new account, cron or startup entry, SSH key, sudo rule, SUID program, file capability or PAM line; a backdoor-style port newly listening |
| MED | SH-03: a host appeared or vanished; a port opened or closed. SH-05: an account changed or removed; a listening port added, removed or taken over by another program; a new service; a file newly locked with `chattr`; a PAM line removed; the firewall state changed |
| LOW | SH-03: a service version changed; a scored-service check added. SH-05: a service started, stopped, enabled or disabled |

Each change gets one flag: a backdoor port that is HIGH is not also listed as MED.

#### What to watch for

- **Changes you made show up too.** Removing a user, closing a port or adding a firewall rule appear as changes. Compare against what the team did (the undo log and the changelog in your notes) before chasing them.
- **Compare like with like.** Two enum runs should use the same profile. A section that is in only one run is reported as `skipped (not in both runs)`, not as everything removed. The summary warns when one enum run was as root and the other was not, because a root run sees more.
- **"Removed" on a scored port is an outage.** A port that closed between two scans of a scored host needs checking right away.
- **Take a fresh baseline after you clean up.** Otherwise every later diff repeats your own changes. Keep the old runs; the diff only reads them.
- **The newest two may not be the two you want.** If a run was made from a different machine or with different targets, give `--old` and `--new` yourself.

#### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `need two finished SH-03 runs ... found 1` (exit 3) | Only one finished run in the folder, or the runs are elsewhere | Run the scan again, point `--runs` at the folder, or give `--old` and `--new` |
| `... is not an SH-03 or SH-05 run folder` (exit 2) | The folder was renamed, or you gave the parent folder | Give the run folder itself; its name must start with `SH-03_`, `SH-05_` or `linux-enum-`. To see what a fix script changed, run the enum again and compare the two enum folders |
| `the two folders are from different scripts` (exit 2) | One SH-03 run and one SH-05 run | Compare runs of the same script |
| `comparing two different hosts` warning | `--old`/`--new` point at enum runs of two machines | Usually a mistake; pick two runs of one host |
| Everything in a section shows as added | The earlier run had that section empty (e.g. not root, or a different profile) | Rerun both the same way; check the warning about root |
| Lots of port changes between scans | Different targets or engines (the fallbacks check 53 ports, nmap 1000) | Scan the same targets with the same engine and profile |
| A changed item looks wrong | The comparison is by the columns in the table above | Look up the key in both runs' tables; `changes.txt` has the old and new values |

---

