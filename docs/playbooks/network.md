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
| 0-1 min | the host list | The 10 boxes from the team packet, ready made | `cp config/hosts.flokid.txt hosts.txt` |
| 1-5 min | **SH-03** Network scan | Every box inside and outside: open ports, versions, what each box looks like (router, domain controller, Gitea, file share, web app, RabbitMQ ...). With `--hosts` it flags every machine that is up but **not in the packet** (the packet says there may be more) | `sh SH-03-network-scan.sh --hosts hosts.txt` (asks the team number) |
| 5-7 min | **NW-01** Config backup | Saves the router's whole config (`uci export`, nftables, passwords file, keys, cron, start-up). Later runs show what changed | `sh NW-01-config-backup.sh` |
| 7-8 min | **NW-07** Config audit | Reads the saved config offline: telnet, LuCI over plain HTTP, management open to everyone, default accounts, SSH keys. Touches nothing | `sh NW-07-config-audit.sh` |
| 8-10 min | **NW-12** Accounts and sessions | Who is logged in to the router now, every account, SSH keys. Dry run: look first | `sh NW-12-device-sessions.sh` |
| 10-12 min | **NW-10** Router password | New root password: the typed shared password is the default. Tests it from a second session before keeping it | `sh NW-10-device-passwords.sh --apply` |
| 12-15 min | **NW-21** Router hardening | Telnet off, LuCI limited, logging, NTP. SSH from outside stays on by default; risky changes always ask a person | `sh NW-21-device-hardening.sh --apply` |

What to look at after each one:

- **SH-03:** `host is up but not on the host list` = a server the packet did not list: enum it, it may be scored by hand (Orange Team) or be red team's way in. Add it to `hosts.txt`. Then the "what each box looks like" table. Match each address to the diagram. A port you did not expect (4444, 31337, a second SSH) is red team. `roles.txt` has the table.
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
