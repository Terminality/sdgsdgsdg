# Environment: what is scored

The scored services from our practice scoreboard. We expect the competition environment to be the same; update this file the moment the team packet says otherwise. The protected list builder (SH-09), the service checker (SH-08) and the run sheet (CP-01) read it.

The OS and the accounts the scorer uses are our best guess from the check names. **Confirm them from the team packet before relying on them.**

| Box | Likely OS | Scored checks | Ports to keep open |
| --- | --- | --- | --- |
| ad | Windows Server, domain controller | `ad-dns`, `ad-ping`, `ad-winrm` | 53 tcp/udp, 5985/5986, ICMP, plus AD ports for the domain |
| ecomm | Linux or Windows web server | `ecomm-http`, `ecomm-ping` | 80/443, ICMP |
| mssql | Windows Server | `mssql-mssql`, `mssql-ping`, `mssql-rdp`, `mssql-smb` | 1433, 3389, 445, ICMP |
| splunk | Linux | `splunk-chrony`, `splunk-mgmt`, `splunk-ping`, `splunk-query`, `splunk-ssh` | 123/udp, 8089, 8000, 22, 9997 (forwarders), ICMP |
| webmail | Linux | `webmail-imap`, `mail-interactive`, `webmail-ping`, `webmail-smtp`, `webmail-ssh` | 25, 143/993, 80/443, 22, ICMP |

On the practice scoreboard `ad-winrm`, every Splunk check and `mail-interactive` were red. Prepare most for those.

## Things to know before touching anything

- **Every box has a ping check.** Never block ICMP.
- **SSH is scored on splunk and webmail.** The scorer almost certainly logs in with a password: password logins stay on.
- **Windows checks probably use domain accounts** (WinRM on ad; RDP and SMB on mssql). Rotating those passwords without reporting them, or AD going down, turns several checks red at once. Find the scorer's accounts and put them on the protected list.
- **WinRM is scored.** Do not turn it off; limit who can use it (firewall to admin and scorer addresses, strong passwords).
- **RDP is scored on mssql**, so an RDP lockout there costs points as well as access. Every RDP change is an `access` change (see `docs/PLAN.md`).
- **The web store probably uses the SQL Server.** Changing a SQL login's password without changing the store's config breaks `ecomm-http` too.
- **splunk-chrony: the Splunk box is also a time server.** chronyd must keep running, allow clients, and UDP 123 must be open.
- **splunk-query probably needs real data.** The forwarders on the other boxes must keep sending, or the check fails even with Splunk up. Splunk is also our best detection tool: give the box an owner.
- **mail-interactive is a chain:** webmail login, IMAP, SMTP and probably DNS. When it goes red, check each piece. It logs in as mail users, so do not rotate mail user passwords without reporting them.
- **AD DNS may serve the names the other checks use.** If records are deleted, several checks fail at once. WN-35 backs up the zones.
- **No SSH or RDP check on ecomm**, so remote access there can be locked down harder.

## Scripts per box (built now, planned in brackets)

| Box | Enum | Prep | Hardening | Watch |
| --- | --- | --- | --- | --- |
| ad | SH-06, (WN-04 AD enum) | WN-35 | WN-43, WN-25 (allow 53, 5985/5986), (WN-27 remote access, WN-23 accounts) | (WN-44) |
| mssql | SH-06, (SV-03) | WN-35, (SV-14 for SQL Server) | WN-43 defaults only, WN-25 (allow 1433, 3389, 445), (SV-09) | (WN-44) |
| ecomm | SH-05 + SV-01, or SH-06 + (SV-03) | LX-31/WN-35, SV-14 | LX-39, (SV-15), LX-25/WN-25 (allow 80/443) | LX-40 |
| splunk | SH-05, (SV-08) | LX-31 | LX-39, LX-22, LX-25 (allow 22, 123/udp, 8000, 8089, 9997), (SV-10) | LX-40, (AU-10) |
| webmail | SH-05, (SV-04), (LX-23) | LX-31, SV-14 | LX-39, LX-22, LX-25 (allow 22, 25, 143, 993, 80/443), (SV-17) | LX-40, SV-26 |

Passwords: LX-20 / WN-20 with the scorer's accounts excluded or reported; application passwords with (SV-20); everything onto the credential sheet (AU-16).
