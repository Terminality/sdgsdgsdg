# Invitational 3 first-15 role cards

These cards tell each role what to copy, where to go and what to run. Use only
the standalone files from `dist/`; each already contains its library. Live
Quotient, packet updates and captain direction override this page.

Password rotation is opt-in and controlled. Never rotate an account until its
use is known. Protect scorer, service, scheduled-task, IIS app-pool, database,
application and automation accounts. Keep the first session open, test a new
session and the business workflow, then keep the change or let it revert.

## Moving the files

### Windows through RDP

Before connecting, open `mstsc` -> **Show Options** -> **Local Resources** ->
**More** -> enable the drive or folder containing the kit. On the server, copy
only your files from `\\tsclient\DRIVE\...\dist\windows-ad\` to `C:\ccdc`.
Do not run directly from the redirected drive. If drive redirection is blocked,
use the competition-approved jump-box share or clipboard for one script at a
time. Never paste passwords into RDP clipboard history.

Verify a copied file against `dist\MANIFEST.sha256` from a trusted workstation.
On older Windows, `certutil -hashfile C:\ccdc\SCRIPT.ps1 SHA256` gives the hash.

### Linux and OpenWRT

Prefer the approved jump box and copy one standalone file with `scp`, SFTP or
the competition-provided share. Example from the jump box:

```sh
scp dist/linux/SH-05-linux-enum.sh TEAMUSER@192.168.220.30:/tmp/
```

Then move it to a root-only directory, set mode 700 and verify its SHA-256
against `dist/MANIFEST.sha256`. Do not start an unauthenticated ad-hoc web
server or place scripts/password files in a public share.

## Captain and inject lead

Go to SSO, Quotient, the portal and private Discord. Assign one owner per host,
record live scored services/accounts/sources in `protected.csv`, and approve
high-risk changes. The inject lead tracks deadlines and writes submissions;
the packet requires human-authored inject PDFs.

Copy/run: no host script. Keep AU-01's `service-matrix.csv`, `change-log.csv`
and `hardening-status.csv` open.

## Automation

Go to the approved jump box. Copy:

```text
dist/automation/AU-01-inv3-first15.sh
dist/network/SH-03-network-scan.sh
dist/MANIFEST.sha256
```

Run AU-01 locally; it changes no remote host:

```sh
sh AU-01-inv3-first15.sh --team TEAM_NUMBER --out ~/ccdc-control --kit DIST_PATH
```

Distribute only the role's files below. Do not fan out mutation or password
scripts. Stop automation on the first new access, business or scoring failure.

## Network - vigra `.2`

Copy `SH-03-network-scan.sh` and `NW-10-device-passwords.sh`. First back up the
OpenWRT configuration and record interfaces, routes, NAT/firewall, management
account and a console recovery path. Run SH-03 read-only.

For the management account, dry-run one device first. Build the NW-10 host row
with the discovered vendor/account; do not guess. Apply only after putting
scorer/automation accounts in `protected.csv`:

```sh
sh NW-10-device-passwords.sh --out ~/ccdc-out \
  --device vigra,192.168.220.2,linux,DISCOVERED_ADMIN \
  --protected protected.csv
# Review, then repeat with --apply. Validate a second login before keeping it.
```

Use the `linux` driver only after confirming vigra uses normal OpenWRT SSH and
`passwd`/`chpasswd` authentication. If it does not, use the native console
carefully and document it; do not force a wrong driver. Do not change
firewall/NAT in the password phase.

## Windows/AD - borgar `.10`, vattar `.79`

Copy:

```text
SH-06-windows-enum.ps1
WN-04-ad-enum.ps1             vattar only
WN-35-backup.ps1
WN-44-windows-alerts.ps1
WN-20-password-rotation.ps1
WN-43-safe-fixes.ps1          after first 15/dry run first
WN-25-firewall.ps1            last, not first 15
```

Run elevated enumeration and backup first. On vattar, run WN-04 and identify
domain, scorer, service, task, app-pool, SPN and application accounts. Dry-run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File C:\ccdc\WN-20-password-rotation.ps1 `
  -Out C:\ccdc-out -Protected C:\ccdc-out\protected.csv
```

After review, use `-Users approved1,approved2 -Apply` to rotate a small explicit
set. Leave service-related accounts excluded; WN-20 skips detected ones unless
someone dangerously adds `-IncludeServices`. Test new RDP/WinRM/domain login,
DNS/AD and the ordering workflow. Never rotate `krbtgt` with WN-20; WN-22 is a
separate two-step incident procedure, not a routine first-15 action.

## Linux/app 1 - kolla `.30`, gufu `.100`, haf `.67`

Copy:

```text
SH-05-linux-enum.sh
LX-31-backup.sh
LX-40-change-watch.sh
LX-41-session-log.sh
LX-20-password-rotation.sh
SV-01-web-db-enum.sh          application/database hosts
SV-14-database-backup.sh      only after database discovery
```

Inventory, back up off-host and identify service identities first. Create a
team account file with one approved interactive username per line and protect
scorer/service accounts. Dry-run on one host:

```sh
sudo sh LX-20-password-rotation.sh --out /root/ccdc-out \
  --protected /root/ccdc-out/protected.csv --keep /root/team.txt
```

Apply interactively after review. Do not use `--batch`, `--kick`, `--no-timer`
or broad `--users` in the first 15. Test a new SSH session and the fileshare,
Gitea or Wabbit workflow before answering that changes should be kept.

## Linux/app 2 - kvigindis `.44`, skerja `.97`, thorska `.231`, djupi `.222`

Use the same Linux file set and sequence as Linux/app 1. Before account changes,
map the help-site, ticketing, Home Manager and POS service identities plus any
database/worker/session accounts. Coordinate a POS test with Orange Team. Never
lock a graphical-session or application account solely because it is not a
normal human username.

## Detection/IR

Copy no mutation script initially. Collect each host's SH-05/SH-06/WN-04,
LX-40/LX-41/WN-44 and application logs into access-controlled evidence folders.
Record UTC, host, owner, hash, source and chain of custody. Use
`INV3-VULNERABILITY-CHECKLIST.md` to prioritize and give the host owner one
specific finding at a time. Preserve suspicious files before containment.

## Minute-by-minute gate

| Time | Required result |
| --- | --- |
| 0:00-0:03 | Roles assigned; Quotient copied; owners and protected scorer accounts recorded |
| 0:03-0:08 | Read-only inventory; listeners/processes/accounts/service identities mapped |
| 0:08-0:12 | Off-host backups and monitoring started; explicit account plan dry-run |
| 0:12-0:15 | Approved interactive accounts rotated one host at a time; fresh login and business checks pass |

If account dependencies are still unknown at minute 12, do not race the clock.
Keep the system available, finish mapping and rotate safely after minute 15.

## Password-file handling

LX-20, WN-20 and NW-10 write new credentials only to restricted output files.
Immediately give the necessary account data to the captain through the team's
approved private channel, verify access, copy the restricted record to approved
secure storage, and remove temporary copies from redirected drives and hosts.
Never commit, paste into chat/Discord, print to a shared screen or put password
files in the general evidence folder. Record only that rotation succeeded, who
holds the credential and when validation passed.
