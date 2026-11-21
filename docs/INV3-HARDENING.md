# Invitational 3 hardening guide

This guide applies the existing kit to the packet's actual Linux and Windows
hosts. It deliberately excludes credential rotation; use the team's separate
approved process.

Use [`INV3-VULNERABILITY-CHECKLIST.md`](INV3-VULNERABILITY-CHECKLIST.md) to
decide what needs attention. This guide controls how to change it safely.

The live Quotient list and discovered dependencies override every suggested
port or service. Never apply one generic firewall policy to all hosts.

## Required gate before hardening

For a host to move from discovery into hardening, its owner must have:

- A current SH-05 or SH-06 run; WN-04 as well for vattar.
- A restorable LX-31 or WN-35 backup copied off-host.
- Its exact Quotient checks and scoring sources in `protected.csv`.
- Process-to-port mapping and application/service identities recorded.
- A repeatable business-function test with a last known-good result.
- A second SSH, RDP, WinRM or console session where access could be affected.
- A named rollback path and a change-log entry.

If any item is missing, stay in read-only discovery.

## Safe hardening order

```text
inventory -> backup -> monitoring -> dry run -> one safe change
-> local test -> internal test -> business test -> Quotient
-> keep or roll back -> next change -> firewall last
```

Do not fan out mutation scripts. Apply to one host, validate, then continue.

## Linux command pattern

Copy only the needed standalone files from `dist/` onto each host.

### 1. Inventory and backup

```sh
sudo sh SH-05-linux-enum.sh --out /root/ccdc-out --profile full
sudo sh LX-31-backup.sh --out /root/ccdc-out --copy-to APPROVED_OFF_HOST_PATH
sudo sh SV-01-web-db-enum.sh --out /root/ccdc-out
```

Run SV-01 only where an application or database is present. Run SV-14 after it
identifies a supported database and before changing that database or app.

### 2. Start monitoring

```sh
sudo sh LX-40-change-watch.sh --out /root/ccdc-out --batch --loop 30 \
  --team 192.168.220.0/24
sudo sh LX-41-session-log.sh --out /root/ccdc-out --loop 30
```

### 3. Safe fixes, dry run first

```sh
sudo sh LX-39-safe-fixes.sh --out /root/ccdc-out \
  --protected /root/ccdc-out/protected.csv
```

Review every proposed fix with the host owner. Apply on one host:

```sh
sudo sh LX-39-safe-fixes.sh --out /root/ccdc-out \
  --protected /root/ccdc-out/protected.csv --apply
```

Do not keep the run until the business test and scoring remain healthy. The
script's timer reverts changes unless they are confirmed.

### 4. Persistence response

Use LX-42 read-only first:

```sh
sudo sh LX-42-persistence-sweep.sh --out /root/ccdc-out
```

Preserve evidence and verify package/application ownership before applying.
When applied, remove one confirmed malicious finding at a time; LX-42 moves it
to quarantine and provides a revert path.

### 5. SSH and firewall last

Run LX-22 without `--apply`, review authorized keys and settings, and preserve
any scorer or business SSH access. The packet says SSH may be manually scored.

Build a host-specific protected list from the actual listener/process map.
Then dry-run LX-25:

```sh
sudo sh LX-25-firewall.sh --out /root/ccdc-out \
  --protected /root/ccdc-out/protected.csv --admin TEAM_SOURCE_CIDR
```

Apply only with a second session and independent validation. Confirm from the
new session; otherwise allow the timer to remove the firewall change.

## Windows command pattern

Copy these standalone scripts through RDP redirected drive, the approved jump
box share or an internal temporary transfer service:

```text
SH-06-windows-enum.ps1
WN-35-backup.ps1
WN-43-safe-fixes.ps1
WN-44-windows-alerts.ps1
WN-25-firewall.ps1
WN-04-ad-enum.ps1       vattar only
```

### 1. Inventory and backup

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File C:\ccdc\SH-06-windows-enum.ps1 `
  -Out C:\ccdc-out -Profile full

powershell -NoProfile -ExecutionPolicy Bypass -File C:\ccdc\WN-35-backup.ps1 `
  -Out C:\ccdc-out -CopyTo APPROVED_OFF_HOST_PATH
```

On vattar also run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File C:\ccdc\WN-04-ad-enum.ps1 `
  -Out C:\ccdc-out
```

### 2. Start monitoring

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File C:\ccdc\WN-44-windows-alerts.ps1 `
  -Out C:\ccdc-out -Loop 30
```

### 3. Safe fixes, dry run first

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File C:\ccdc\WN-43-safe-fixes.ps1 `
  -Out C:\ccdc-out -Protected C:\ccdc-out\protected.csv
```

Review the plan, then add `-Apply`. WN-43 targets controls such as WDigest,
SMBv1, UAC, Guest, debugger/sticky-keys backdoors, port forwards, Defender
exclusions, auditing, Winlogon/AppInit and WMI persistence. It does not make an
unknown service dependency safe; the owner still validates the application.

Undo the latest run if validation fails:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File C:\ccdc\WN-43-safe-fixes.ps1 `
  -Out C:\ccdc-out -Undo latest -Apply
```

### 4. Windows firewall last

Do not use WN-25 until every scored service, Windows dynamic dependency, admin
source and application listener is in the protected list. Dry run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File C:\ccdc\WN-25-firewall.ps1 `
  -Out C:\ccdc-out -Protected C:\ccdc-out\protected.csv `
  -AdminFrom TEAM_SOURCE_CIDR
```

Apply with a console or second RDP/WinRM session open. Confirm from a fresh
connection using the generated keep script. If that fails, let the scheduled
rollback restore the old firewall.

## Per-host Linux plan

### kolla - Alpine fileshare

Preserve the discovered share protocol, authenticated users, data paths and
ACLs. Alpine uses OpenRC, so validate with `rc-status`, `rc-service`, share
client access and active sessions. Run LX-39 only after the share workflow is
repeatable. Do not firewall until SMB/NFS/FTP and their required auxiliary
ports are proven. Never quarantine customer files based only on their names.

### gufu - Rocky Linux Gitea

Protect Gitea HTTP/HTTPS, SSH Git if used, the reverse proxy, database path,
repository storage, LFS/attachments and `app.ini`. Take a Gitea-aware backup
plus LX-31/SV-14. Start LX-40/LX-41, apply LX-39, then review LX-42 findings.
Do not alter repository hooks, the `git` account, SELinux labels or database
connectivity until ownership is known. Firewall direct port 3000 only if the
proxy and Quotient never use it.

### haf - Lubuntu Wabbit

Wabbit is unidentified. Run discovery, backup and monitoring, but do not apply
service-specific or firewall changes until the binary, unit, port, data and
business workflow are known. LX-39 may be applied one fix at a time after its
dry run. Treat unknown persistence findings as evidence to verify, not an
automatic delete list.

### kvigindis - Ubuntu furniture help site

Protect the web listener, virtual host, proxy/application service, web root,
uploads, TLS, database and required DNS/AD access. Use SV-01 and SV-14 where
applicable. Apply LX-39, then address confirmed web shells through LX-42 one at
a time. Validate the actual help workflow and dynamic content after every
change; a `200` response from a static default page is insufficient.

### skerja - Alpine ticketing

Protect OpenRC services, web/app listeners, database, attachments, session
store and notification dependency. Back up database and uploaded files before
hardening. Apply LX-39 only after create/view/update ticket tests are stable.
Firewall only after every application and database flow is mapped.

### thorska - Fedora Home Manager

Record systemd services, firewalld zones and SELinux state. Do not disable
SELinux or firewalld to hide an application error. Apply LX-39 in reviewed
units, preserve application labels and use logs to correct a real denial.
Validate authentication, expected data and an approved reversible update.

### djupi - Linux Mint point of sale

Protect the graphical/session path, POS process, local or remote database,
device integrations and transaction data. Coordinate with Orange Team before
testing transactions. Use LX-39 conservatively and do not stop desktop/session
services merely because they look unnecessary on a server. Firewall only after
the full POS workflow and backend connections are mapped.

## Per-host Windows plan

### borgar - Windows Server 2022 food ordering

Use SH-06/WN-35/WN-44 first. Identify IIS or other web service, app pools,
scheduled tasks, Windows services, service identities, database connections,
content/data and logs. Apply WN-43 in dry run and validate a complete approved
food order after each fix. WN-25 is last; preserve the application listener,
WinRM/RDP used by the team, database flows and any manual scoring path.

### vattar - Windows Server 2019 Active Directory/DNS

Use SH-06, WN-04, WN-35 and WN-44. Preserve NTDS, DNS, Netlogon, KDC, SYSVOL,
LDAP/LDAPS, Kerberos, SMB, global catalog, RPC endpoint mapper and required
dynamic RPC. Apply WN-43 only after AD/DNS backups and test DNS, `dcdiag`,
authentication and an AD-dependent application after every change. WN-25 on a
domain controller is the highest-risk host firewall action; do not apply it
until the complete AD port set and scoring sources are confirmed.

## Validation record

After every mutation, put this in `change-log.csv` or the equivalent record:

```text
UTC time and owner
host and business service
script and exact options
protected-list version
pre-change local/business/Quotient result
post-change local/internal/business/Quotient result
fresh-session access result
rollback path and timer
kept or reverted
```

Do not store credentials in this record.
