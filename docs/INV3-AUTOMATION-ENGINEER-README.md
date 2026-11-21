# Invitational 3 automation engineer runbook

This is the competition-day README for the automation engineer on the final
Invitational 3 network. It tells you what to run, what to distribute, what to
track and when automation must stop.

The packet, live Quotient checks and organizer announcements override this
document. Use standalone scripts from `dist/`, not source files from `roles/`.

## Your job

- Generate the team workspace and NAT map.
- Convert live Quotient data into protected and service lists.
- Verify and distribute the smallest script bundle each owner needs.
- Run read-only network discovery from the approved jump box.
- Track enumeration, off-host backup, monitoring and validation.
- Record every mutation and rollback.
- Stop fan-out after the first new access, service or scoring failure.

You do not remotely apply password, firewall, persistence-removal or hardening
scripts to every host. The owner runs mutations locally and validates the real
business workflow.

## Final network

| Host | Internal address | Platform | Business service |
| --- | --- | --- | --- |
| vigra | `192.168.220.2` | OpenWRT | Router, firewall and NAT |
| borgar | `192.168.220.10` | Windows Server 2022 | Food ordering |
| kolla | `192.168.220.30` | Alpine Linux | Fileshare |
| kvigindis | `192.168.220.44` | Ubuntu 24.04 | Furniture help site |
| haf | `192.168.220.67` | Lubuntu 22 | Wabbit, exact product unknown |
| vattar | `192.168.220.79` | Windows Server 2019 | Active Directory and DNS |
| skerja | `192.168.220.97` | Alpine 3.23 | Employee and customer tickets |
| gufu | `192.168.220.100` | Rocky Linux | Gitea |
| djupi | `192.168.220.222` | Linux Mint 22.3 | Point of sale |
| thorska | `192.168.220.231` | Fedora 44 | Home Manager, exact product unknown |

External mapping is `10.100.1XX.Y`, where `XX` is the two-digit team number and
`Y` is the internal address's final octet. Team 7 uses `10.100.107.Y`.
Confirm the formula against the live packet.

## Before competition

From a trusted Linux workstation:

```sh
git switch invitational-readiness
git pull --ff-only
sh tools/build.sh
sh tests/inv3-01.test.sh
sh tests/lint-ps2.sh
sha256sum -c dist/MANIFEST.sha256
```

Do not distribute the kit if a hash fails. Rebuild from the trusted checkout.
Keep an offline copy of `dist/` on approved transfer media or the jump box.

## Start of competition

Set the real team number:

```sh
TEAM_NUMBER=7
KIT="$PWD/dist"
CONTROL="$HOME/ccdc-control"
```

Create the control workspace:

```sh
sh "$KIT/automation/INV3-01-first15-setup.sh" \
  --team "$TEAM_NUMBER" \
  --out "$CONTROL" \
  --kit "$KIT"
```

Set `RUN` to the numbered directory printed by the script:

```sh
RUN="$CONTROL/inv3-control-1"
ls -la "$RUN"
less "$RUN/first15.txt"
```

Expected output:

```text
hosts.csv
nat-map.csv
protected.csv
service-matrix.csv
hardening-status.csv
change-log.csv
first15.txt
```

INV3-01 changes no competition host and does not rotate passwords.

## Fill these files before mutations

### protected.csv

Add live scorer sources, accounts, ports, services and required paths from
Quotient. The generated file is only a starter.

```text
type,value,note
host,SCORER_IP,live scoring source
account,SCORER_ACCOUNT,used by Quotient
port,REAL_PORT/tcp,confirmed scored service
service,REAL_SERVICE,required dependency
path,REAL_PATH,required application data
```

Never put a password in this file.

### service-matrix.csv

For every live check, record the owner, port, scoring account name,
dependencies, local test, remote test, business test and Quotient result.

An open port is not a working service. Test the real workflow: place an
approved order, perform the required Gitea action, update a test ticket and run
an approved POS transaction.

### hardening-status.csv

Do not approve a mutation until these are `yes`:

```text
inventory_complete
backup_off_host
monitoring_started
protected_list_current
business_tested
```

Firewall planning and fresh-session validation are last.

### change-log.csv

Record the UTC time, owner, host, exact command, precheck, postcheck, Quotient
result, rollback and final decision for every mutation.

## Run read-only discovery

Review `hosts.csv`, then run from the approved jump box:

```sh
sh "$KIT/network/SH-03-network-scan.sh" \
  --target 192.168.220.0/24 \
  --hosts "$RUN/hosts.csv" \
  --profile wrccdc \
  --out "$RUN/discovery"
```

Record missing packet hosts, unexpected hosts, new listeners, required
services that are down and address mismatches. Do not launch intrusive scans
or continuous full-port scans during scoring.

## Distribute only the baseline bundle

Every owner gets `dist/MANIFEST.sha256` plus the minimum files for the host.

### Linux baseline

For kolla, gufu, haf, kvigindis, skerja, thorska and djupi:

```text
dist/linux/SH-05-linux-enum.sh
dist/linux/LX-31-backup.sh
dist/linux/LX-40-change-watch.sh
dist/linux/LX-41-session-log.sh
dist/applications/SV-01-web-db-enum.sh
dist/applications/SV-14-db-backup.sh
dist/MANIFEST.sha256
```

Example transfer:

```sh
scp "$KIT/linux/SH-05-linux-enum.sh" \
  TEAMUSER@192.168.220.30:/tmp/
```

Only send mutation scripts after the baseline gate passes:

```text
LX-20-password-rotation.sh
LX-22-ssh-hardening.sh
LX-25-firewall.sh
LX-39-safe-fixes.sh
LX-42-persistence-sweep.sh
SV-30-service-hardening.sh
```

### Windows baseline

For borgar and vattar:

```text
dist/windows-ad/SH-06-windows-enum.ps1
dist/windows-ad/WN-35-backup.ps1
dist/windows-ad/WN-44-windows-alerts.ps1
dist/windows-ad/WN-04-ad-enum.ps1       vattar only
dist/MANIFEST.sha256
```

Use RDP drive redirection or the approved share. Copy scripts to `C:\ccdc` and
do not run them directly from `\\tsclient`.

Verify a Windows file:

```powershell
certutil -hashfile C:\ccdc\SH-06-windows-enum.ps1 SHA256
```

Only send these after baseline review:

```text
WN-20-password-rotation.ps1
WN-43-safe-fixes.ps1
WN-25-firewall.ps1
```

### Router baseline

Give the network owner:

```text
dist/network/SH-03-network-scan.sh
dist/network/NW-01-config-backup.sh
dist/network/NW-07-config-audit.sh
dist/network/NW-10-device-passwords.sh
dist/MANIFEST.sha256
```

The network owner confirms console recovery and OpenWRT authentication before
NW-10. Never automate replacement of the router firewall or NAT rules.

## Commands owners run and report back

### Linux inventory

```sh
sudo sh SH-05-linux-enum.sh \
  --out /root/ccdc-out \
  --profile full
```

On application or database hosts:

```sh
sudo sh SV-01-web-db-enum.sh --out /root/ccdc-out
```

### Linux backup

```sh
sudo sh LX-31-backup.sh \
  --out /root/ccdc-out \
  --copy-to APPROVED_OFF_HOST_PATH
```

After SV-01 confirms a supported database:

```sh
sudo sh SV-14-db-backup.sh \
  --out /root/ccdc-out \
  --copy-to APPROVED_OFF_HOST_PATH
```

### Linux monitoring

```sh
sudo sh LX-40-change-watch.sh \
  --out /root/ccdc-out \
  --batch \
  --loop 30 \
  --team 192.168.220.0/24
```

In a second session:

```sh
sudo sh LX-41-session-log.sh \
  --out /root/ccdc-out \
  --loop 30
```

### Windows inventory

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File C:\ccdc\SH-06-windows-enum.ps1 `
  -Out C:\ccdc-out `
  -Profile full
```

On vattar:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File C:\ccdc\WN-04-ad-enum.ps1 `
  -Out C:\ccdc-out
```

### Windows backup and monitoring

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File C:\ccdc\WN-35-backup.ps1 `
  -Out C:\ccdc-out `
  -CopyTo APPROVED_OFF_HOST_PATH
```

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File C:\ccdc\WN-44-windows-alerts.ps1 `
  -Out C:\ccdc-out `
  -Loop 30
```

## Controlled password changes

Password changes are opt-in and run one host at a time. Before approval:

1. Protected scoring accounts are current.
2. Service, task, app-pool, database and integration identities are known.
3. A verified off-host backup exists.
4. The owner has a second session open.
5. New-login and business tests are ready.
6. The rollback timer is enabled where supported.

Linux dry run:

```sh
sudo sh LX-20-password-rotation.sh \
  --out /root/ccdc-out \
  --protected /root/ccdc-out/protected.csv \
  --keep /root/team.txt
```

After review, add `--apply`. Do not use `--batch`, `--kick` or `--no-timer`
on the first run.

Windows dry run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File C:\ccdc\WN-20-password-rotation.ps1 `
  -Out C:\ccdc-out `
  -Protected C:\ccdc-out\protected.csv `
  -Users approved1,approved2
```

After review, add `-Apply`. Do not use `-IncludeServices`. Do not rotate
`krbtgt` as a routine opening action.

Router dry run, only when normal OpenWRT SSH and `chpasswd` are confirmed:

```sh
sh NW-10-device-passwords.sh \
  --out ~/ccdc-out \
  --device vigra,192.168.220.2,linux,DISCOVERED_ADMIN \
  --protected protected.csv
```

## Safe fixes after baseline

Linux dry run:

```sh
sudo sh LX-39-safe-fixes.sh \
  --out /root/ccdc-out \
  --protected /root/ccdc-out/protected.csv
```

Windows dry run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File C:\ccdc\WN-43-safe-fixes.ps1 `
  -Out C:\ccdc-out `
  -Protected C:\ccdc-out\protected.csv
```

The owner reviews the plan and adds `--apply` or `-Apply`. If a Windows safe
fix breaks validation:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File C:\ccdc\WN-43-safe-fixes.ps1 `
  -Out C:\ccdc-out `
  -Undo latest `
  -Apply
```

## Persistence review

Run Linux persistence review read-only first:

```sh
sudo sh LX-42-persistence-sweep.sh --out /root/ccdc-out
```

A finding is a lead, not proof. Verify ownership, package state, timestamps,
hashes and logs. Preserve evidence before an apply run. On Windows, use WN-43's
dry-run findings; do not bulk-remove unfamiliar tasks, services, WMI entries or
registry values.

## Firewall is last

Do not approve firewalling until every scored port, admin source, application
dependency and Windows dynamic dependency is mapped.

Linux dry run:

```sh
sudo sh LX-25-firewall.sh \
  --out /root/ccdc-out \
  --protected /root/ccdc-out/protected.csv \
  --admin TEAM_SOURCE_CIDR
```

Windows dry run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File C:\ccdc\WN-25-firewall.ps1 `
  -Out C:\ccdc-out `
  -Protected C:\ccdc-out\protected.csv `
  -AdminFrom TEAM_SOURCE_CIDR
```

Apply to one host. Keep the old session open, test a new session and confirm
the generated keep action. If access fails, allow the rollback timer to restore
the prior firewall.

Do not use a generic firewall policy on vattar. AD/DNS requires DNS, Kerberos,
LDAP/LDAPS, SMB, global catalog, RPC endpoint mapper and dynamic RPC.

## Validate after every mutation

Record all five results:

```text
1. On-host service test
2. Internal remote test
3. Mapped external test when permitted
4. Complete business-workflow test
5. Quotient result for at least two cycles
```

For access changes, also require a fresh SSH, RDP or WinRM session. Roll back
on the first new failure caused by the change. Do not wait for five failures.

## Continuous automation loop

```text
Quotient and announcements
-> service-matrix status
-> alerts and owner reports
-> one confirmed issue
-> backup and rollback check
-> one controlled change
-> five-part validation
-> log keep or revert
```

Every 5 to 10 minutes:

- Check Quotient and announcements.
- Ask each owner for service and access status.
- Review new LX-40, LX-41 and WN-44 alerts.
- Update `service-matrix.csv` and `hardening-status.csv`.
- Copy new evidence and backups off-host.
- Confirm there is only one change owner per host.

Use SH-04 to compare deliberate network baselines instead of continuously
scanning:

```sh
sh "$KIT/network/SH-04-scan-diff.sh" \
  --type sh03 \
  --runs "$RUN/discovery" \
  --out "$RUN/diffs"
```

## Stop automation immediately when

- SSH, RDP, WinRM or console access is lost.
- A business workflow or Quotient fails after a team change.
- The protected list is incomplete or old.
- The only backup is on the host being changed.
- Two people are changing the same host.
- The application or service identity is unknown.
- A command would touch a service/scorer account or firewall without review.
- Script output differs from the approved plan or reports a failed step.

Stop the fan-out, preserve output, revert the last controlled change and return
the host to its last known-good state.

## Owner handoff format

```text
UTC time:
Host and service:
Script and exact options:
Output directory:
Finding or change:
Backup off-host:
Local test:
Internal test:
Business test:
Quotient result:
Fresh-session result:
Rollback path:
Kept or reverted:
```

Never include a password, token, private key or credential file.

## End of event

1. Stop monitoring loops cleanly and preserve their final output.
2. Copy evidence, backups, change log and service matrix to approved storage.
3. Confirm password files exist only in approved restricted storage.
4. Remove temporary credential copies according to event rules.
5. Do not commit competition credentials, findings or output to Git.
6. Record unresolved services, temporary mitigations and rollback information.

## Rule to remember

```text
inventory -> protect -> backup -> monitor -> dry run -> one change
-> fresh access -> business test -> Quotient -> keep or revert
```
