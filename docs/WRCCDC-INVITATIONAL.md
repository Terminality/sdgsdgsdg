# WRCCDC invitational runbook

This runbook turns the kit into an operator checklist. It is based on the
December 20, 2025 Invitational #5 packet and older public WRCCDC material.
The current packet and Quotient always win when they disagree with this file.

No script can make a team win. The advantage comes from preserving services,
making one controlled change at a time, detecting Red Team changes quickly and
submitting complete inject evidence before the deadline.

When a script flags something, follow `docs/RESPONSE-MATRIX.md`. It maps the
finding to verification, the least disruptive response, service validation and
recovery. Do not improvise a bulk fix from a single alert.

## Non-negotiable local rules

- Do not change the WCComps SSO profile settings.
- Do not migrate or containerize scored services unless an inject allows it.
- Do not run automation that deliberately breaks normal operations.
- Passwords must be genuinely unique, not one pattern with a changing suffix.
- Use Quotient for password-change requests.
- Determine the current event's AI and inject-writing rules before using any
  generated text in a submission. The Invitational #5 packet required PDF
  submissions and contained strict AI-writing penalties.
- Keep one teammate in the Discord voice channel for Orange Team checks.
- Never identify the school in filenames or submissions; use the team number.

## Packet-derived map

Copy `config/wrccdc-invitational5.hosts.example.csv` to a private working file
and correct it from Quotient and live discovery. Never commit credentials.

The packet conflicts with itself about Cowbell: the table says MySQL while the
diagram says PostgreSQL. Treat both 3306 and 5432 as candidates until SV-01 and
network discovery show the real dependency.

## First 15 minutes

### Automation engineer

You own execution safety, not every system decision. Before competition day,
place the verified `dist/` kit and `MANIFEST.sha256` on the approved jump box.
Keep private host/protected files outside Git and prepare writable off-host
folders for backups, alerts and evidence.

During play:

1. Start read-only discovery and backups in parallel with host owners.
2. Maintain the canonical host/service/dependency sheet.
3. Refuse mutation jobs without a current protected list and named owner.
4. For every change record requester, host, script, options, start time, health
   check, result and rollback location.
5. Stop fan-out when one host fails validation. Diagnose that host before
   continuing to similar systems.
6. Never confirm an access-risk change yourself from the session that applied
   it; the host owner confirms from a fresh connection.
7. Keep raw evidence unchanged. Give copies to the incident/inject leads.

Recommended concurrency: read-only enum and backup can fan out. Passwords,
firewalls, remote access and service hardening are serial per service family.

### Captain

1. Open Quotient, the ticket portal and team Discord.
2. Put one teammate in the voice channel.
3. Record scored services, exact check messages and password-change rules.
4. Assign one owner per host and one inject/evidence lead.
5. Announce every risky change before it happens.

### Network operator - look first

```sh
sh dist/network/SH-03-network-scan.sh \
  --target 192.168.1.0/24 \
  --hosts config/wrccdc-invitational5.hosts.example.csv \
  --profile wrccdc --out ~/ccdc-out
```

Then back up and audit the router:

```sh
sh dist/network/NW-01-config-backup.sh --hosts PRIVATE-HOSTS.csv --out ~/ccdc-out
sh dist/network/NW-07-config-audit.sh --out ~/ccdc-out
```

Do not change Milkware until its interfaces, routes, one-to-one NAT, VPN path
and scoring path are recorded. A service that works locally can still fail
through the router.

### Windows/AD operator - look and back up

On MilkFarm:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\dist\windows-ad\SH-06-windows-enum.ps1 -Out C:\ccdc-out -Profile full
powershell -NoProfile -ExecutionPolicy Bypass -File .\dist\windows-ad\WN-04-ad-enum.ps1 -Out C:\ccdc-out
powershell -NoProfile -ExecutionPolicy Bypass -File .\dist\windows-ad\WN-35-backup.ps1 -Out C:\ccdc-out -CopyTo \\JUMPBOX\backups
```

On Moocrosoft and Wagyu, run SH-06 and WN-35 before changing anything. Confirm
IIS, application-pool, scheduled-task and service-account dependencies before
password rotation.

### Linux/application operator - look and back up

```sh
sudo sh dist/linux/SH-05-linux-enum.sh --out /root/ccdc-out --profile full
sudo sh dist/linux/LX-31-backup.sh --out /root/ccdc-out --copy-to admin@JUMPBOX:/srv/backups/
sudo sh dist/applications/SV-01-web-db-enum.sh --out /root/ccdc-out
sudo sh dist/applications/SV-14-db-backup.sh --out /root/ccdc-out --copy-to admin@JUMPBOX:/srv/backups/
```

## Start monitoring

On MilkFarm, Moocrosoft and Wagyu:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\dist\windows-ad\WN-44-windows-alerts.ps1 -Out C:\ccdc-out -Loop 30 -SendTo \\JUMPBOX\alerts
```

On every Linux host:

```sh
sudo sh dist/linux/LX-40-change-watch.sh --out /root/ccdc-out --batch --loop 30 --team 192.168.1.0/24
sudo sh dist/linux/LX-41-session-log.sh --out /root/ccdc-out --loop 30
```

## Safe changes

1. Copy the protected example to the output folder and update it from Quotient.
2. Rotate administrator, root and default credentials first.
3. Use unique passwords and preserve service identities until their consumers
   are documented.
4. Apply WN-43/LX-39 in dry-run mode, review the plan, then apply one host.
5. Test the actual business function after every change.

## Closing ports safely

Do not kill listeners or disable arbitrary services just because a port looks
unfamiliar. First map the PID to its executable/account and decide whether it
is a scored service, application dependency, management path or Red Team tool.

Windows dry run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\dist\windows-ad\WN-25-firewall.ps1 `
  -Out C:\ccdc-out -Protected C:\ccdc-out\protected.csv `
  -AdminFrom 192.168.1.0/24 -Exclude 4444/tcp,31337/tcp
```

Apply only with a console or second RDP session open:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\dist\windows-ad\WN-25-firewall.ps1 `
  -Out C:\ccdc-out -Protected C:\ccdc-out\protected.csv `
  -AdminFrom 192.168.1.0/24 -Exclude 4444/tcp,31337/tcp -Apply
```

Open a new connection and run the generated `keep-firewall.ps1`. If the new
connection fails, do nothing: the scheduled rollback restores the old state.

Linux dry run and apply:

```sh
sudo sh dist/linux/LX-25-firewall.sh --out /root/ccdc-out \
  --protected /root/ccdc-out/protected.csv --admin 192.168.1.0/24
sudo sh dist/linux/LX-25-firewall.sh --out /root/ccdc-out \
  --protected /root/ccdc-out/protected.csv --admin 192.168.1.0/24 --apply
```

Confirm from a fresh SSH session. Never use an outbound deny-all policy: mail,
DNS, time, AD, application databases and scoring may depend on outbound flows.

## Service validation loop

After every meaningful change:

1. Test locally on the server.
2. Test from the jump box using the internal address.
3. Test the mapped competition address when permitted.
4. Check Quotient for at least two scoring cycles.
5. Ask Orange Team to retry a failed manual check when appropriate.
6. Roll back your change before blaming Red Team or Operations.

Run SH-03 again with only the expected ports for a quick confirmation:

```sh
sh dist/network/SH-03-network-scan.sh --hosts PRIVATE-HOSTS.csv \
  --ports 22,25,53,80,88,135,139,143,389,443,445,464,587,636,993,1433,3268,3269,3306,3389,5432,5985,5986 \
  --pn --batch --out ~/ccdc-out
```

## When an alert fires

1. Record UTC time, host, account, source address, PID and service impact.
2. Preserve logs and take screenshots before cleaning up.
3. Verify whether the change came from a teammate or Orange Team.
4. Contain the smallest possible scope.
5. Restore and validate the business service.
6. Submit an incident report with observations, evidence and timestamps.

Incident reports can recover points when they match Red Team activity. A vague
statement such as "we were hacked" is not evidence.

## What not to automate

- SSO settings or Discord linking.
- Quotient submissions or password-change requests without an official API.
- Bulk account disabling before Orange Team/scoring accounts are known.
- Database or application-pool password changes without dependency updates.
- Router/NAT replacement.
- Firewall confirmation from the same connection that made the change.
- Inject prose. Collect evidence automatically; have a teammate write and
  review the required PDF under the current event rules.
