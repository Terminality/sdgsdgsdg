# Findings to action matrix

Use this after enumeration and alerts. A finding is a prompt to verify, not
permission to mutate a host. The current packet, Quotient and the host owner
decide whether a service/account is legitimate.

## Stop conditions

Stop automation and notify the captain/host owner when:

- A previously passing scored service fails after a team change.
- The protected list is missing, stale or conflicts with Quotient.
- The only working SSH/RDP/WinRM session would be affected.
- A service identity or application dependency is unknown.
- Router/NAT changes would affect more than one host.
- A backup cannot be restored or copied off-host.
- Multiple teammates are changing the same host.

## Windows and AD

| Finding | Verify first | Controlled response | Validate | Recovery |
| --- | --- | --- | --- | --- |
| Unknown domain admin | Team roster, account creation/change events, active sessions | Preserve evidence; use WN-20 for a unique password or planned WN-23 for disable/removal | DNS, Kerberos, LDAP, RDP, Orange Team account checks | Restore membership/account state from evidence; reset through approved workflow |
| SPN user or service account | Services, tasks, IIS app pools and SQL dependencies | Protect it; rotate only after every consumer can be updated | Restart/reload consumer and perform actual app login/query | Restore prior service credential/configuration |
| Unconstrained delegation/no-preauth | Whether a legacy scored service requires it | Make a documented manual change during a maintenance window; do not bulk-fix | Kerberos auth and dependent application workflow | Restore original account-control value |
| Suspicious GPO/SYSVOL script | GPO link, owner, timestamps and packet requirements | Back up with WN-35; disable/unlink only the malicious item | `gpupdate`, domain login, DNS and required policy behavior | Restore GPO/SYSVOL backup |
| New service/task/listener | Requester, binary hash/path, parent process, event evidence | Preserve evidence; stop/quarantine only after owner confirms it is not required | Scored ports and business workflow | Restore from WN-35 or undo log; restart required service |
| Defender/firewall disabled | GPO ownership and whether competition image intentionally disables it | WN-43 for safe controls; WN-25 for firewall | Two scoring cycles plus fresh RDP/WinRM session | WN-43 `-Undo`; WN-25 automatic rollback or `-Undo` |
| Unexpected inbound port | PID, executable, account and service dependency | Add to WN-25 `-Exclude`; do not kill first | Fresh remote session and external SH-03 validation | Let timer roll back or run WN-25 `-Undo latest -Apply` |

## Linux and applications

| Finding | Verify first | Controlled response | Validate | Recovery |
| --- | --- | --- | --- | --- |
| Unknown account/key | Team roster, service ownership, recent auth logs | LX-20/LX-22 with protected list | New SSH session, scored user login | Revert script and backup passwd/shadow/authorized_keys |
| Persistence finding | Package ownership, process/service dependency | LX-42 moves files to quarantine; remove one finding at a time | Required service plus SH-03 | `revert.sh`; restore quarantined item |
| Unexpected port | PID, command, owner and app dependency | LX-25 drop rule; do not kill listener first | Internal and mapped-address checks | Timer rollback or LX-25 remove/revert |
| Web-shell indicator | Preserve file/log/process evidence | Quarantine with LX-42; rotate affected credentials; patch entry point | HTTP workflow and database dependency | Restore legitimate file from LX-31/application backup |
| Database exposure | Confirm which hosts legitimately connect | Restrict source addresses; do not change app credentials independently | Query from app server and customer workflow | Restore DB/firewall config and credential |
| Mail brute force/spam | Log source, Orange Team use and scoring sources | SV-26 with complete protected list | SMTP/IMAP/webmail login | `--unban`, `--unban-all`, firewall rollback |

## Network

| Finding | Verify first | Controlled response | Validate | Recovery |
| --- | --- | --- | --- | --- |
| Unknown host | MAC/vendor, VM inventory, ARP, packet and owner | Isolate only after captain/Black Team confirmation | Known services and router reachability | Remove isolation rule |
| New router rule/NAT | Compare NW-01 snapshots and identify requester | Restore the single unauthorized line, not the entire config | Internal service and mapped competition address | Load known-good NW-01 config or reverse line |
| Telnet/HTTP management | Whether it is the only current management path | Establish and test SSH/HTTPS first; then disable legacy path | New independent management session | Console/backup config restore |
| Default SNMP community | Monitoring dependency and allowed source | Replace with unique value and update monitoring together | Poll from monitoring host | Restore both ends temporarily |
| Any-to-any allow rule | Direction, source, destination and service need | Replace with explicit service/source rules | SH-03 from admin and scoring perspectives | Restore prior rule from NW-01 |

## Mandatory after-action record

For every mutation capture:

```text
UTC time:
Requester / host owner:
Host and service:
Finding and evidence path:
Script and exact options:
Protected-list version:
Pre-change health result:
Post-change local result:
Post-change jump-box result:
Quotient/Orange result:
Rollback path and timer:
Kept or reverted:
```

Do not store passwords in this record.
