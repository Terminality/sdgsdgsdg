# WRCCDC 2026 Invitational 3 runbook

This is the packet-specific addendum for Flokid. The live Quotient service list,
announcements and credentials always override this document.

## Environment

Internal network: `192.168.220.0/24`. From outside the OpenWRT router, a team
reaches `10.100.1XX.Y`, where `XX` is its team number and `Y` is the internal
last octet. AU-01 calculates both addresses and creates the working files.

| Host | Address | OS | Known purpose |
| --- | --- | --- | --- |
| vigra | .2 | OpenWRT | Router |
| kolla | .30 | Alpine | Fileshare |
| borgar | .10 | Windows Server 2022 | Food ordering |
| gufu | .100 | Rocky Linux | Gitea |
| vattar | .79 | Windows Server 2019 | Active Directory |
| haf | .67 | Lubuntu 22 | Wabbit |
| kvigindis | .44 | Ubuntu 24.04 | Furniture help |
| skerja | .97 | Alpine 3.23 | Employee/customer tickets |
| thorska | .231 | Fedora 44 | Home manager |
| djupi | .222 | Linux Mint 22.3 | Point of sale |

The packet says other hosts or services may exist. Treat this table as a seed,
not proof of the complete environment.

## Before competition

1. Link every competitor's Discord account through SSO.
2. Test NetBird VPN with only one approved end device per person.
3. Put the verified `dist/` kit on the approved jump box.
4. Confirm whether team-authored tools have been approved for this event.
5. Assign captain, automation, network, Windows/AD, Linux/application, IR and
   inject owners.

## First 15 minutes

Create a private control folder:

```sh
sh dist/automation/AU-01-inv3-first15.sh --team TEAM_NUMBER \
  --out ~/ccdc-control --kit dist --scan
```

The controller writes the inventory, NAT map, starter protected list, service
matrix, change log and first-15 guide. It performs no remote mutation.

### 0:00-0:03

- Captain opens SSO, Quotient, the ticket portal and private Discord channels.
- One teammate remains in private Discord voice for Orange Team.
- Automation copies exact live checks into `service-matrix.csv`.
- Add scorer addresses, accounts, ports, services and paths to `protected.csv`.
- One named owner takes each host. Two teammates never change one host.

### 0:03-0:08

- Run SH-03 from the jump box.
- On vigra, preserve `/etc/config`, UCI output, routes, firewall and NAT.
- Run SH-06 on borgar and vattar; add WN-04 on vattar.
- Run SH-05 on each Linux host; add SV-01 to application/database hosts.
- Record unexpected hosts, ports and dependencies. Do not close them yet.

### 0:08-0:12

- Run WN-35 on Windows and LX-31 on Linux.
- Run SV-14 when a database is discovered.
- Copy backups off-host before calling them complete.
- Start WN-44 on Windows and LX-40/LX-41 on Linux.

### 0:12-0:15

- Test every listed business workflow, not only its listening port.
- Reconcile live hosts and services with the packet and Quotient.
- Prioritize HIGH findings that threaten access, data or scored services.
- Make one controlled change at a time with a named owner and rollback.
- Stop and roll back on the first new failure caused by a team change.

Credential rotation is handled by the team's separate procedure and is outside
AU-01. This runbook does not generate, change, store or track passwords.

## Router stop conditions

Do not change vigra when the NAT map, scoring source, WAN management path or a
restorable configuration backup is unknown. A router reset costs 100 points,
resets occur only during 30-minute cutover windows, and losing Black Team
access can trigger a reset. Red Team can modify or reboot the router.

## Scoring, tickets and injects

About 8-12 services are checked every 2-4 minutes. An SLA occurs after five
failed checks; do not use that as a rollback timer. Roll back a team change on
its first new failure.

- Quotient: service status and injects; use the team's approved credential
  procedure for any required password-change request.
- Ticket portal: scoring adjustments, support and detailed incident reports.
- Private Discord: announcements and Orange/Black/White Team communication.
- Manual services require a real business workflow, not merely an open port.

Inject files must be lowercase PDFs named like `inject04_team13.pdf`, identify
only the team number and cite any external template. The packet prohibits AI
for inject submissions. Do not use this repository or an AI assistant to write,
rewrite or polish inject prose.

## Evidence and incident reports

For an incident record UTC time, host, account, source, PID/process, affected
service, immutable evidence path and hash, containment, restoration, business
test and scoring result. Submit a detailed report through the ticket portal;
do not submit only "we were hacked."
