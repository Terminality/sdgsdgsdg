# Scored services

**These services come from past competitions and practice. They are not set in stone.** Check the team packet each time and update this file. OS and scoring accounts are guesses.

| Box | OS (guess) | Checks | Keep open |
| --- | --- | --- | --- |
| ad | Windows DC | dns, ping, winrm | 53, 5985/5986, ICMP, AD ports |
| ecomm | ? | http, ping | 80/443, ICMP |
| mssql | Windows | mssql, ping, rdp, smb | 1433, 3389, 445, ICMP |
| splunk | Linux | chrony, mgmt, ping, query, ssh | 123/udp, 8089, 8000, 22, 9997, ICMP |
| webmail | Linux | imap, smtp, ssh, webmail login, ping | 25, 143/993, 80/443, 22, ICMP |

Red on the practice scoreboard: ad-winrm, all Splunk checks, mail-interactive.

## Don't break these

- Never block ping. Every box has a ping check.
- Keep SSH password logins on (splunk, webmail).
- Don't turn off WinRM (ad) or RDP (mssql). They are scored.
- Find the accounts the scorer uses before changing passwords. Report any change to scoring.
- The web store probably uses the SQL Server. Changing a SQL password breaks the store unless you update its config.
- Splunk is also a time server. Keep chronyd running and UDP 123 open.
- splunk-query needs data. Keep the forwarders sending.
- Don't change mail user passwords without reporting them (webmail login check).
- AD DNS may hold the names other checks use. Back up the zones (WN-35).
