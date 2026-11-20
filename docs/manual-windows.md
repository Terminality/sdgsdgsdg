<!-- Built by tools/role-manuals.sh from docs/playbooks/windows.md and docs/MANUAL.md. Edit those, then run it. -->

# Windows manual

For whoever defends the Windows boxes. Every command here uses the standalone scripts in `dist/windows-ad/`. Each one is a single `.ps1` file: copy it to the box and run it in an **elevated** PowerShell window ("Run as administrator").

Flókið Windows boxes (inside `192.168.220.x`; from outside `10.100.1XX.x`, XX = team number):

| Box | Last octet | OS | Scored service |
| --- | --- | --- | --- |
| Borgar | .10 | Windows Server 2022 | food ordering service (a web site: likely IIS) |
| Vattar | .79 | Windows Server 2019 | Active Directory (the domain controller: AD, DNS, Kerberos, LDAP) |

## How every script works

- **Start it like this** (the execution policy blocks scripts otherwise):

  ```powershell
  powershell -NoProfile -ExecutionPolicy Bypass -File .\WN-20-password-rotation.ps1
  ```

- **Dry run first.** Without `-Apply` nothing changes. Read the plan, then run again with `-Apply`, or answer "yes" to "Apply these changes?" at the end of the questions.
- **Questions.** One at a time: `[?] Question` with each answer listed under it, then `Answer [y/N]:`. Enter takes the answer in capitals. Every question has a parameter that answers it in advance (`-Box`, `-Admins`, `-Apply` ...); `-Batch` takes every default.
- **The box question.** "Which box is this?" is guessed from the machine (`This box looks like: dc (a domain controller)`). Enter takes the guess.
- **The look.** Sections are numbered `==========[ 2/4  plan ]==========`, with a legend line at the top: `[!]` HIGH, `[*]` MED, `[ok]` fine, `[~]` would change, `[+]` changed, `[x]` failed.
- **Results.** Each run gets a numbered folder in `%USERPROFILE%\bt-out` (`windows-enum-1`, `firewall-2` ...) with `output.txt` (the screen), `summary.txt` and `.txt` tables. No CSV.
- **Never locked out.** Firewall, accounts and fixes start a **revert timer**: a one-time scheduled task (as SYSTEM) that undoes the change by itself unless you answer "keep". It still fires if your RDP session drops. Before answering "keep", open a **new** RDP session and log in. WN-25 uses its own: run `keep-firewall.ps1` from the new session.
- **Undo.** Every change has an undo line; `revert.ps1 -Force` in the run folder undoes that run. WN-25 and WN-43 also have `-Undo latest`.
- **The protected list.** `%USERPROFILE%\bt-out\protected.txt`: the scored ports, services and the accounts the scoring engine logs in with. Scripts that change things refuse `-Apply` without it (or `-NoProtected`).

## Before you start (once per box, 2 minutes)

1. Copy `dist\windows-ad\` to the box (over RDP: copy and paste, or from a share) into `C:\kit`. Keep each `SCRIPT.ps1.sha256` next to its script: the script then refuses to run if it was changed.
2. Write `%USERPROFILE%\bt-out\protected.txt`, one line each. At 9 AM, fill it in from the scoring engine:

   ```
   port      80/tcp       food ordering site
   port      3389/tcp     we log in by RDP
   service   W3SVC        IIS: the food ordering site
   account   svc_web      the scoring engine logs in as this
   ```

3. Open a second RDP session to each box and leave it open: it is your way back in if a change goes wrong.

## The first 15 minutes

Borgar and Vattar differ at minute 10: Vattar runs the AD lockdown.

| When | Script | What it does | Command |
| --- | --- | --- | --- |
| 0-2 min | **SH-06** Windows enum | A first look: accounts and admins, listening ports and their programs, services, scheduled tasks, Run keys, weak security settings, Defender, firewall. Changes nothing | `.\SH-06-windows-enum.ps1 -Profile card` |
| 2-4 min | **WN-35** Backup | Registry areas, firewall, security policy, tasks, IIS (Borgar), DNS and AD lists (Vattar), with the command to put each back | `.\WN-35-backup.ps1` |
| 4-7 min | **WN-20** Passwords | New passwords: local accounts on Borgar, every domain account on Vattar. Each account is asked: random, typed, keep | `.\WN-20-password-rotation.ps1` |
| 7-10 min | **WN-25** Firewall | Inbound blocked except the scored ports, what is listening, RDP; rolls itself back unless you run `keep-firewall.ps1` from a NEW session | `.\WN-25-firewall.ps1` |
| 10-13 min | Vattar: **WN-23** AD lockdown | Unknown members of the admin groups, accounts open to AS-REP roasting, password not required, delegation, new accounts, Guest | `.\WN-23-ad-lockdown.ps1 -Admins youradmin` |
| 10-13 min | Borgar: **WN-43** Safe fixes | 20 fixes that cannot break a service: WDigest, SMBv1, sticky keys, Defender, auditing ... | `.\WN-43-safe-fixes.ps1` |
| 13-15 min | **WN-43** on Vattar / **WN-42** quick on Borgar | the other one of the two | `.\WN-42-persistence-sweep.ps1 -Areas tasks,runkeys,services,wmi` |

What to look at after each one:

- **SH-06:** the `SUMMARY`. Every `[!] HIGH` is something to deal with now: an unknown admin, a task or Run key from a temp folder, WDigest on, Defender off, a firewall rule that allows everything.
- **WN-35:** the summary says where the backup is. Use `-CopyTo \\otherbox\share`, or answer the copy question: a red team with admin rights can delete a backup kept on the box.
- **WN-20:** the new passwords are in `passwords.txt` in its run folder (Administrators only). Give them to the captain, then delete the file. **Submit the scored accounts' new passwords in the scoring engine** (the red line in the summary).
- **WN-25:** when it says ROLLBACK at HH:MM, open a NEW RDP session; if it works, run `keep-firewall.ps1` from there.
- **WN-23:** name your admins with `-Admins` so every other member of Domain Admins is offered for removal.

## After the first 15 minutes

| Script | What it does | When | Command |
| --- | --- | --- | --- |
| **WN-42** Persistence sweep | Every place a red team leaves a way back in: scheduled tasks, Run keys, startup folders, Winlogon, services, WMI subscriptions, debuggers, local admins | Right after the first 15 min, then whenever you suspect red team | `.\WN-42-persistence-sweep.ps1` |
| **WN-43** Safe fixes again | Red team turns things back off | Every hour or after an incident | `.\WN-43-safe-fixes.ps1 -Apply -Batch` |
| **SH-06** full | A full picture, including processes, connections, sessions, shares, software, events | When things are calm, and to compare | `.\SH-06-windows-enum.ps1` |
| **WN-23** again (Vattar) | New admins or accounts since the last run | Every hour | `.\WN-23-ad-lockdown.ps1 -Admins youradmin` |

### When something happens

| What you see | Run |
| --- | --- |
| You think red team is on the box | `SH-06 -Profile triage` (copies the event logs too), then WN-42 |
| A new admin or account | WN-23 on Vattar; WN-42 `-Areas admins` on Borgar |
| A scored service went red | check the firewall first: `WN-25 -Undo latest` puts the old one back; then the service (`services.msc`, IIS Manager) |
| Locked out of RDP after the firewall | do nothing: the rollback task puts the old firewall back at the time it showed |
| Something a fix broke | `revert.ps1 -Force` in that run's folder, or `-Undo latest` (WN-25, WN-43) |
| Sticky keys gives a command prompt at the login screen | WN-43 (`stickykeys`, `debuggers`) |

### Notes for this network

- **Vattar is the domain controller.** WN-20 changes domain passwords there; WN-23 locks the admin groups; WN-25 keeps the AD ports (DNS 53, Kerberos 88, LDAP 389/636, SMB 445, RPC) open by itself. Group Policy is not touched by any script here.
- **Borgar serves the food ordering site.** WN-25 `-Box web` (guessed if IIS is there) keeps 80 and 443 open. There is no IIS hardening script yet: check the site's folder for files that should not be there by hand.
- **RDP is how you get in.** WN-25 keeps 3389 open when it is listening; the packet says the boxes may also be reached over VNC or telnet - SH-06 lists what listens.
- Passwords for scored accounts go to the scoring engine (Quotient), not to a ticket.
- Nothing here has run on a real Windows box yet: do a dry run first, and keep a second RDP session open.

## Deep dive: every Windows script

Each section below is the full reference for one script: how to run it, every question and its parameter, what each check means, what it writes, and what to do when something goes wrong. They are in the order above.

Scripts: [SH-06](#sh-06-windows-enum-distwindows-adsh-06-windows-enumps1) [WN-35](#wn-35-windows-backup-distwindows-adwn-35-backupps1) [WN-20](#wn-20-windows-password-rotation-distwindows-adwn-20-password-rotationps1) [WN-25](#wn-25-windows-firewall-distwindows-adwn-25-firewallps1) [WN-23](#wn-23-account-lockdown-windows--ad-distwindows-adwn-23-ad-lockdownps1) [WN-43](#wn-43-windows-safe-fixes-distwindows-adwn-43-safe-fixesps1) [WN-42](#wn-42-windows-persistence-sweep-distwindows-adwn-42-persistence-sweepps1) 

### SH-06: Windows enum (`dist/windows-ad/SH-06-windows-enum.ps1`)

Read-only inventory of a Windows host: the Windows twin of SH-05. Run it first on every Windows box, in an elevated PowerShell window. It changes nothing.

#### How to run it

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File SH-06-windows-enum.ps1 -Out C:\bt-out
powershell -NoProfile -ExecutionPolicy Bypass -File SH-06-windows-enum.ps1 -Out C:\bt-out -Profile card     # about a minute
powershell -NoProfile -ExecutionPolicy Bypass -File SH-06-windows-enum.ps1 -Out C:\bt-out -Only users,ports
```

| Option | What it does |
| --- | --- |
| `-Profile card\|full\|triage` | `card`: system, users, ports, services, autostart, tasks, security, firewall, defender. `full` (default): card plus processes, connections, sessions, shares, software, updates, events, drivers, rights, roles. `triage`: full plus a copy of the event logs |
| `-Only a,b` / `-Skip a,b` | Choose sections; `-List` shows them |
| `-EventHours N` | How far back the events section looks (default 24) |
| `-MaxFlags N` | HIGH/MED flags shown on screen (default 30) |
| `-FromRaw DIR` | Read a saved `raw` folder instead of this host. Send someone the `raw` folder of a run and they can replay it anywhere, PowerShell 7 on Linux included |

#### What you get

It looks like the Linux scripts: a title line, the legend, a numbered header per section (`==========[ 3/9  ports ]==========`) with its row count and how many flags it raised, then the `SUMMARY` with the HIGH flags in red and MED in yellow.

**The question:** "How much to look at?" `[c]` card (about a minute), `[F]` full, `[t]` triage (full plus a copy of the event logs). `-Profile`, `-Only` or `-Skip` answer it; `-Batch` takes full.

`<out>\windows-enum-N\` (a new number each run) holds `output.txt` (the screen without colours), `summary.txt`, `flags.txt`, one `.txt` table per section, `run.txt` and `raw\` with everything as read (`-FromRaw` replays it). No CSV is left. Run it without elevation and the summary says which sections are incomplete.

#### What it flags

| Section | HIGH | MED | LOW |
| --- | --- | --- | --- |
| system | hosts file sends a Microsoft, update or antivirus name elsewhere | any other hosts entry | |
| users | Guest enabled; enabled account ending in `$`; password-like text in a description (not copied); Everyone, Users or Domain Users inside Administrators, Remote Desktop Users or Domain/Enterprise Admins | account without a required password | each admin and RDP group member; built-in Administrator enabled |
| ports | cmd, PowerShell, netcat-style tools listening; backdoor ports (4444, 1337, 31337 ...); listener run from Temp, AppData, Users\Public, ProgramData | Telnet | FTP; listener whose process is gone |
| services | service that runs a command line or a shell; service program in an unusual folder; Event Log or Defender service stopped | unquoted path with spaces (privilege escalation); Remote Registry or Telnet running; Print Spooler on a DC | service running as a named account (changing its password breaks it); SNMP |
| autostart | suspicious Run key (machine or user); Userinit or Shell changed; debugger key (sticky keys); SilentProcessExit; AppInit DLLs loaded; WMI event subscription; sethc/utilman/osk replaced by cmd or PowerShell | startup-folder file; unknown netsh helper or LSA package; BootExecute changed; AppInit DLL set but not loaded | ordinary Run entries |
| tasks | task running a suspicious command or a program from an unusual folder | non-Microsoft task running a shell | other non-Microsoft tasks |
| security | WDigest on; UAC off; EveryoneIncludesAnonymous; null sessions; AlwaysInstallElevated; stored Winlogon password (not copied); port forwards (portproxy); Zerologon enforcement off or allow-list set | SMBv1 server on; SMB signing off on a DC; NTLMv1/LM; LM hashes; anonymous SAM listing; RDP without NLA; LocalAccountTokenFilterPolicy; audit policy cleared; logons not audited | LSA protection off; LLMNR on; script block logging off; SMB signing off elsewhere; Zerologon key unset |
| firewall | a profile OFF; allow-all inbound default; an enabled inbound rule allowing everything; rule for a shell, netcat or a program in Temp; rule opening a backdoor port | | |
| defender | antivirus or real-time protection off; policy keys turning it off; exclusion of a drive, a script/program extension or a user/temp folder | any other exclusion | |
| processes | system program name (lsass, svchost, csrss ...) from the wrong folder; two lsass; netcat-style tool; suspicious command line (encoded PowerShell, download cradle, hidden window); a shell started by IIS, Apache, Tomcat or SQL Server | program run from an unusual folder | |
| connections | a shell or netcat-style tool with a live connection; connection to a backdoor port | program in an unusual folder with a live connection | |
| shares | | Everyone, Anonymous or Guest with Full or Change on a share | every non-default share |
| software | | remote-access tools (AnyDesk, TeamViewer, ScreenConnect, VNC, ngrok ...) | |
| updates | DC whose newest update is before September 2020 (Zerologon) | newest update over a year old | |
| events | Security or other event log cleared | in the look-back: account created, enabled or reset; member added to a group; service installed; task created; Defender or Event Log start type changed | |
| drivers | running driver from an unusual folder | running driver outside Windows | |
| rights | Everyone, Anonymous or Guests allowed to log on interactively or by RDP | debug, impersonate, backup, restore, load-driver, take-ownership or token rights held by a non-default account | |

#### Problems and fixes

| What you see | Why | Fix |
| --- | --- | --- |
| "running scripts is disabled" | Execution policy | Start it with `powershell -NoProfile -ExecutionPolicy Bypass -File ...` as shown |
| Antivirus deletes or blocks the file | Some checks contain the text of attack commands | The risky words are already split up; if it still happens, note the threat name from Windows Security, Protection history, and report it |
| Sections note "could not be read" | Not elevated, or the tool is missing on this Windows version | Run as administrator; `raw\<name>.error.txt` has the reason |
| Firewall or audit sections empty on a non-English Windows | netsh and auditpol text is read in English | The raw files still hold the output; read them by hand |
| `users` is very long on a DC | A DC's "local" users are the domain's users | Expected; use `-Skip users` for a quick look |
| A flag is legitimate (a Defender exclusion for SQL, a vendor task) | Flags are pointers, not verdicts | Check it, then move on |

---


### WN-35: Windows backup (`dist/windows-ad/WN-35-backup.ps1`)

Saves the settings and files a hardening step or the red team is most likely to break, each with the command that puts it back. Run it right after the enum (SH-06) and before anything is changed. Run it in an elevated window. It changes nothing on the host.

#### How to run it

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File WN-35-backup.ps1 -Out C:\bt-out -CopyTo \\10.0.0.5\backups
powershell -NoProfile -ExecutionPolicy Bypass -File WN-35-backup.ps1 -Out C:\bt-out -Path C:\xampp\htdocs,C:\App\config
powershell -NoProfile -ExecutionPolicy Bypass -File WN-35-backup.ps1 -Out C:\bt-out -Only firewall,secpolicy
```

| Option | What it does |
| --- | --- |
| `-CopyTo DEST` | Copy the finished backup to a share or folder. Do this: a red team with admin rights can delete a backup kept on the box |
| `-Path a,b` | Also back up these files or folders (application folders, XAMPP, config files) |
| `-NoWebRoots` | Leave website files out; IIS settings are still saved |
| `-MaxMB N` | Skip any single folder bigger than N MB (default 500). It is listed as not saved |
| `-AdDatabase` | Domain controller: also save the AD database (ntdsutil IFM). It holds every domain password hash: copy it off and delete it from the DC |
| `-Only a,b` / `-List` | Run only some items |
| `-Box NAME`, `-Batch`, `-NoColor` | Answer the box question; take every default; no colours |

#### The questions

| Question | Answers | Parameter |
| --- | --- | --- |
| Which box is this? | `[d]` domain controller `[b]` web (IIS) `[e]` ecomm `[f]` fileshare `[s]` database `[o]` other (guessed) | `-Box` |
| Back up the website files too? | `[Y]` / `[n]` | `-NoWebRoots` answers no |
| Other folders to back up? | folders separated by commas (Enter = none) | `-Path` |
| Also save the AD database? (domain controller only; it holds every password hash) | `[y]` / `[N]` | `-AdDatabase` answers yes |
| Copy the backup off the box? | a share or folder (Enter = no) | `-CopyTo` |

It looks like the Linux scripts: a title line, the legend, `==========[ 1/3  questions ]==========`, then each item as it is saved (`[+]` saved, `[x]` failed, `[-]` skipped) and the summary. Results go in `<out>\backup-N\` with `output.txt`, `items.txt` and `run.txt`.

#### What it saves

| Item | When | What | How it is put back (RESTORE.txt) |
| --- | --- | --- | --- |
| registry | always | services, Run keys, Winlogon, debugger keys, LSA, RDP, Session Manager, netsh helpers, Defender, policies | `reg import` per area |
| firewall | always | every rule and profile setting | `netsh advfirewall import` |
| secpolicy | always | password and lockout policy, user rights, security options | `secedit /configure` (puts back every setting: read first) |
| auditpol | always | every audit subcategory | `auditpol /restore` |
| tasks | always | every scheduled task's XML | `schtasks /create /xml` |
| hosts | always | `drivers\etc` | copy back |
| users, services | always | lists as `.txt` tables (no passwords) for comparison | recreate by hand |
| iis, web | IIS installed | settings folder; every site's folder from `applicationHost.config` | copy back between `iisreset /stop` and `/start` |
| dns | DNS server | every zone (dnscmd export), server settings | `dnscmd /zoneadd ... /load` |
| dhcp | DHCP server | scopes, options, reservations, leases | `netsh dhcp server import` |
| gpo | domain controller | every GPO (`Backup-GPO`) and an HTML report | `Restore-GPO` |
| sysvol | domain controller | logon scripts and policy files | copy one file back |
| ad | domain controller | lists of every user, group, computer and OU; AD Recycle Bin state | Recycle Bin (it reports the command to turn it on; that cannot be undone, so it is not done) |
| addb | only with `-AdDatabase` | AD database (install-from-media) | authoritative restore |

Every saved file is hashed in `SHA256SUMS.txt`. The backup folder is limited to Administrators and SYSTEM.

#### Problems and fixes

| What you see | Why | Fix |
| --- | --- | --- |
| Most items FAILED | Not an elevated window | Run as administrator |
| `web ... over -MaxMB` | A site folder is bigger than the limit | Raise `-MaxMB`, or copy that folder by hand |
| `gpo` failed on a DC | GroupPolicy module missing | Install the Group Policy Management feature, or skip it with `-Only` |
| A DNS zone FAILED | dnscmd could not export it (cache or system zones are skipped on purpose) | The DNS settings and the dns folder copy are still saved |
| `COPY FAILED` | The share is unreachable or not writable | Check the path and rights; the backup on the box is complete |
| `addb` failed: space in the path | ntdsutil cannot take it | Use `-Out C:\bt-out` |

---


### WN-20: Windows password rotation (`dist/windows-ad/WN-20-password-rotation.ps1`)

Gives every enabled account a new password: local accounts on any Windows box, and every domain user when run on a domain controller. The new passwords go to one file for the captain, never to the screen or the log. Dry run unless `-Apply`. Run in an elevated window; on a DC as a domain admin.

#### How to run it

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File WN-20-password-rotation.ps1 -Out C:\bt-out                         # dry run: read the list
powershell -NoProfile -ExecutionPolicy Bypass -File WN-20-password-rotation.ps1 -Out C:\bt-out -Apply -Exclude mark.jacobs,admin
powershell -NoProfile -ExecutionPolicy Bypass -File WN-20-password-rotation.ps1 -Out C:\bt-out -Apply -Passwords C:\team\sheet.csv
```

| Option | What it does |
| --- | --- |
| `-Exclude a,b` | Never touch these accounts. One comma-separated list (PowerShell does not allow the option twice) |
| `-Users a,b` | Change only these accounts |
| `-IgnoreMissing` | A name in `-Exclude` or `-Users` that is not an account here normally STOPS the script before anything changes (a typo would change the account you meant to keep). This only warns instead |
| `-Passwords FILE` | `account,password` lines: chosen passwords for those accounts, random for the rest. Spaces around both are dropped; a password may contain commas. Names not here and disabled accounts are listed and not changed |
| `-Length N` | Random password length (default 16, at least 12). Random passwords always have upper case, lower case and digits, so they pass Windows' complexity rule |
| `-IncludeMe` | Also change the account running the script |
| `-IncludeDisabled` | Also give disabled accounts a new password (they stay disabled) |
| `-IncludeServices` | Also change accounts that run services, tasks or IIS app pools here, or have an SPN |
| `-Print` | Show the new passwords on screen at the end |

#### What it never changes

Guest, DefaultAccount, WDAGUtilityAccount and krbtgt (that has its own two-step reset, WN-22); accounts on the protected list; the account running the script; disabled accounts; and accounts that run a service, scheduled task or IIS app pool on this box or have an SPN (changing those breaks the service until it is given the new password). Each is listed in `accounts.csv` with the reason. It never enables, disables or unlocks an account, and never sets "must change password at next logon" (that would break scored logins).

#### What you get

`accounts.csv` (account, scope, state, action, note), `summary.txt`, and with `-Apply` `passwords.csv` (host, account, password, time) readable by Administrators and SYSTEM only. Each change is followed by a logon test with the new password; a failed test is marked in `accounts.csv`. If the script is stopped while changing one account, `pending-password.csv` is left behind: that account has either its old password or the one in that file.

#### Problems and fixes

| What you see | Why | Fix |
| --- | --- | --- |
| `no such account here: ...` | A name in `-Exclude` / `-Users` is misspelled or not on this box | Fix it, or add `-IgnoreMissing` |
| `FAILED ... does not meet the password policy requirements` | The domain's policy rejected the password (length, complexity, history) | Use a longer `-Length`, or a different sheet password; the old password still works |
| A service stopped working after the change | Its account was changed with `-IncludeServices` or runs it from another box | Give the service the new password from `passwords.csv` (`sc.exe config NAME password= ...` or the Services console) |
| `the new password did not work in a test logon` | A policy, a lockout or replication delay on a DC | Wait a minute and log on by hand; on a DC check replication |
| Refused: no protected list | `-Apply` needs one | Build `protected.txt` (accounts the scoring engine uses), or pass `-NoProtected` |

---


### WN-25: Windows firewall (`dist/windows-ad/WN-25-firewall.ps1`)

Turns the Windows firewall on for every profile with inbound blocked by default, and allows in only what is scored or in use. The whole firewall is exported first; a rollback task puts it back after a few minutes unless someone confirms from a new connection. Run it in an elevated **Windows PowerShell** (`powershell.exe`) window.

#### How to run it

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File WN-25-firewall.ps1 -Out C:\bt-out                          # dry run: read the plan
powershell -NoProfile -ExecutionPolicy Bypass -File WN-25-firewall.ps1 -Out C:\bt-out -Apply -AdminFrom 10.0.0.5
##   then from a NEW RDP / remote session, within 5 minutes:
powershell -NoProfile -ExecutionPolicy Bypass -File C:\bt-out\WN-25_<host>_<time>\keep-firewall.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File WN-25-firewall.ps1 -Out C:\bt-out -Undo latest -Apply      # put the old firewall back
```


#### The questions

It looks like LX-25: the questions, the plan (`[+]` allowed in, `[-]` not opened and why, `[x]` rules turned off), the change, and the summary.

| Question | Default | Parameter |
| --- | --- | --- |
| Which box is this? (its scored ports stay open: web and ecomm 80, 443; fileshare 139, 445; database 1433) | the guess | `-Box` |
| Addresses that may reach everything here (your team, the scoring engine)? | none | `-AdminFrom` |
| Other ports to keep open, even if nothing listens on them yet? | none | `-Allow` |
| Allow ping? | yes | `-NoPing` answers no |
| Also turn off every other inbound allow rule (strict)? | no | `-Strict` answers yes |
| Load this firewall now? (put back by itself unless you run `keep-firewall.ps1` from a NEW connection) | **no** | `-Apply` |

`-Batch` takes every default: a dry run unless `-Apply` is given.
#### What it allows in

| Source | Rule |
| --- | --- |
| Protected list `port` entries | Always, even when nothing listens now (a scored service that is down) |
| `-Allow 80/tcp,53/udp,5000-5100/tcp` | Always |
| Listening now | Every port something listens on, except: loopback only; ports 49152 and up; known backdoor ports (4444, 1337, 31337 ...); a shell, netcat or tunnel listening; a program in Temp, AppData, Users\Public, Downloads; `-Exclude`. Each one left closed is in `not-allowed.txt` with the reason |
| Protected list `host` entries and `-AdminFrom` | Everything from those addresses (the scoring engine, the team's machines). Names are not used, only addresses and networks |
| Ping | ICMP echo, unless `-NoPing` |
| Domain controller | DNS, Kerberos, LDAP, LDAPS, global catalog, SMB, RPC (endpoint mapper and dynamic), NTP, password change |

If the protected list and `-Exclude` disagree, the protected list wins and the run says so.

#### What it turns off

Existing inbound allow rules that undo the firewall: one that allows every port, protocol and address with no other limit; one for a shell, netcat or a program in an odd folder; one opening a backdoor port. Rules limited to an app package, an interface, some local addresses or a service are not "allow everything". With `-Strict`, every inbound allow rule that is not ours is turned off, except Active Directory's on a DC.

#### Safety and undo

| What | How |
| --- | --- |
| Before anything | `netsh advfirewall export` of the whole firewall to `firewall-before.wfw`. If that fails, nothing changes |
| Rollback timer | A SYSTEM scheduled task (`BT-WN25-rollback`) imports that export after `-ConfirmMinutes` (default 5) - it runs even if your session is gone. Allow rules go in before the profiles block, so the box is never closed with nothing open |
| Keep | `keep-firewall.ps1` from a NEW connection cancels the rollback: proof the team can still get in |
| Roll back now | `rollback.ps1` in the run folder |
| Later | `-Undo latest -Apply` (or a run folder) imports the export: every rule and setting back exactly |
| Only our rules | `-Remove` deletes the rules in group `BT` and nothing else |
| Two changes at once | Refused while a rollback is waiting |

#### Logs

`firewall-N\` (a new number each run) with `output.txt`, `plan.txt` (each allow rule and why), `disabled.txt` (each rule turned off and why), `not-allowed.txt` (each listener not opened and why), `run.txt`, `summary.txt`, the script log, and Windows' own dropped-connection log at `%windir%\System32\LogFiles\Firewall\pfirewall.log` (turned on unless `-NoLog`).

#### Problems and fixes

| What you see | Why | Fix |
| --- | --- | --- |
| A scored service stopped answering | It was down when the firewall ran and is not on the protected list | Add it: `-Allow 25/tcp`, or put it in the protected list and run again (after keeping or rolling back) |
| Refused: a change is still waiting | The last run is neither kept nor rolled back | Run its `keep-firewall.ps1`, or `rollback.ps1` |
| "could not create the rollback task" | Task Scheduler service off or not elevated | Nothing changed; fix that, or use `-NoTimer` only at the console |
| A rule comes back | Domain Group Policy firewall rules | Fix the GPO |
| "run this with Windows PowerShell" | Started with `pwsh` | Use `powershell.exe` |

---


### WN-23: Account lockdown (Windows / AD) (`dist/windows-ad/WN-23-ad-lockdown.ps1`)

Run it on the domain controller (Vattar) early: red team's favourite moves there are adding themselves to an admin group, making a new account, or switching on a setting that hands out a crackable hash. It reads Active Directory through ADSI (no AD module), shows what it finds, and asks about each fix. Group Policy is not read or changed.

#### How to run it

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File WN-23-ad-lockdown.ps1                                   # look + dry run
powershell -NoProfile -ExecutionPolicy Bypass -File WN-23-ad-lockdown.ps1 -Apply -Admins blueadmin,Administrator
powershell -NoProfile -ExecutionPolicy Bypass -File WN-23-ad-lockdown.ps1 -Apply -Batch -Admins blueadmin -Approved C:\team\users.txt
```

#### What it finds

| Finding | Level | Fix offered (default) |
| --- | --- | --- |
| A member of Domain Admins, Enterprise Admins, Schema Admins, Administrators, Account Operators, Backup Operators, Server Operators, Print Operators or DnsAdmins that is not yours | HIGH with `-Admins` or when made in the last `-Hours`; MED otherwise | remove from the group (**yes** when `-Admins` names your admins; **no** without it: it could be a teammate) |
| No Kerberos pre-authentication (AS-REP roasting) | HIGH | require it (yes) |
| Password not required | HIGH | require one (yes) |
| Reversible encryption | HIGH | turn it off (yes) |
| A user trusted for unconstrained delegation | HIGH | turn it off (yes) |
| An account made in the last `-Hours` hours (default 24) | HIGH | disable (**no**: it could be a teammate) |
| An enabled account not in `-Approved` (only when given) | MED | disable (yes) |
| Guest enabled | HIGH | disable (yes) |
| A user with an SPN (Kerberoastable), a computer with unconstrained delegation, password never expires, the krbtgt password age | MED / LOW | reported only (passwords: WN-20; krbtgt: WN-22) |

Never touched: the account running it, the built-in Administrator, krbtgt and accounts on the protected list.

#### The questions

| Question | Answers | Parameter |
| --- | --- | --- |
| Each finding | `[f]`ix it, `[k]`eep it, `[a]`ll the rest: their default | `-Admins`, `-Approved`, `-Only` / `-Skip` |
| Apply these N change(s)? | `[y]` / `[N]` | `-Apply` |
| No protected list: change AD without one? | `[y]` / `[N]` | `-NoProtected` |

`-Batch` takes every default: a dry run unless `-Apply` is given.

#### Safety and output

- Dry run unless `-Apply`. With `-Apply` the revert timer runs (120 s, `-Timer`): every change is undone by itself unless you answer "keep" after logging in from a NEW session. Each change has an undo line; `revert.ps1 -Force` in the run folder undoes the run later.
- `-Admins` names that are not accounts stop the script before anything changes (a typo would remove the admin you meant to keep).
- In `<out>\ad-lockdown-N\`: `output.txt`, `findings.txt` (level, kind, account, what was found, what was done), `summary.txt`, `run.txt`, `undo.txt`, `revert.ps1`.
- Not yet run against a real domain: try it on a VM first.


### WN-43: Windows safe fixes (`dist/windows-ad/WN-43-safe-fixes.ps1`)

Fixes the settings red teams weaken or hide in, choosing only fixes that cannot break a scored service. Dry run unless `-Apply`; every change is recorded first so `-Undo` can put the run back exactly. Run it in an elevated **Windows PowerShell** (`powershell.exe`) window; it refuses to run under PowerShell 7.

#### How to run it

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File WN-43-safe-fixes.ps1 -Out C:\bt-out                           # dry run: read the list
powershell -NoProfile -ExecutionPolicy Bypass -File WN-43-safe-fixes.ps1 -Out C:\bt-out -Apply                    # the safe fixes
powershell -NoProfile -ExecutionPolicy Bypass -File WN-43-safe-fixes.ps1 -Out C:\bt-out -Apply -Include rdpnla    # plus one more
powershell -NoProfile -ExecutionPolicy Bypass -File WN-43-safe-fixes.ps1 -Out C:\bt-out -Undo latest -Apply       # put the last run back
```

| Option | What it does |
| --- | --- |
| `-Only a,b` / `-Skip a,b` | Make only these fixes / all safe fixes but these |
| `-Include a,b` | Also make these "might affect a service" fixes |
| `-Undo latest\|RUNFOLDER` | Replay that run's `undo-plan.txt` backwards. Dry run unless `-Apply`. A run can be undone once |
| `-List` | List the fixes |


#### The questions

It looks like LX-39: the questions, each fix as it is made (`[+]` fixed, `[~]` would fix, `[x]` failed, `[-]` left: check it), then the summary. Already-fine checks are only counted.

| Question | Answers | Parameter |
| --- | --- | --- |
| Which safe fixes? | `[A]`ll 20 / `[c]`hoose each (then one yes/no question per fix) | `-Only`, `-Skip` |
| Each "might affect a service" fix (firewall, latfp, ntlm, lsappl, rdpnla, spooler, remotereg, smbsigning) | `[y]` / `[N]` | `-Include` |
| Apply these fixes now? | `[y]` / `[N]` | `-Apply` |
| Keep these changes? (the revert timer: undone by themselves unless kept from a NEW session) | `[y]` / `[N]` | `-Batch` keeps; `-NoTimer` for no timer |

`-Batch` takes every default: a dry run unless `-Apply` is given. `-Undo latest` still puts a whole run back at any time.
#### The fixes

| Fix | What it does | Undo |
| --- | --- | --- |
| wdigest | `UseLogonCredential` 0: passwords not kept readable in memory | yes |
| smb1 | SMBv1 server off (`Set-SmbServerConfiguration`, or the registry and a reboot on Windows 7 / 2008 R2). Refused when 445/tcp is protected | yes |
| zerologon | DC only: `FullSecureChannelProtection` 1, `vulnerable_channel_allowlist` removed | yes |
| uac | `EnableLUA` back to 1 if someone set 0 (after a reboot) | yes |
| guest | Guest account disabled (not if protected) | yes |
| debuggers | IFEO `Debugger` removed on the logon-screen programs always, and on any other program when the debugger is a shell or in an odd folder; `SilentProcessExit` monitors removed. A real tool as debugger (Process Explorer) is left and listed | yes |
| stickykeys | sethc, utilman, osk, magnify, narrator, displayswitch or atbroker that is a copy of cmd, PowerShell or explorer is repaired with `sfc /scanfile`, then re-hashed to check | no, on purpose |
| portproxy | every `netsh interface portproxy` forward removed (not on a protected port) | yes |
| defender | real-time protection on; exclusions (cmdlet and policy) removed; policy keys that turn Defender off removed. Checked afterwards: Tamper Protection can ignore a change silently | yes |
| eventlog | Event Log service running and automatic | yes |
| auditing | 13 audit subcategories (logon, account and group changes, process creation, task creation, policy changes, Kerberos, credential validation; directory changes on a DC) on for success and failure, by GUID so any language works; command lines and PowerShell script blocks logged; Security log at least 512 MB | yes |
| anonymous | `EveryoneIncludesAnonymous` 0, `RestrictAnonymousSAM` 1, `RestrictNullSessAccess` 1, `NullSessionShares` removed | yes |
| lmhash | `NoLMHash` 1 | yes |
| installer | `AlwaysInstallElevated` 0 for the machine and every loaded user | yes |
| winlogon | `Userinit` and `Shell` back to Windows' own; stored `DefaultPassword` removed (never shown) and auto-logon off | yes |
| appinit | `AppInit_DLLs` emptied, `LoadAppInit_DLLs` 0 | yes |
| netsh | netsh helper DLLs that are not Windows' own removed | yes |
| wmi | WMI event subscriptions that run commands removed; their definitions saved as MOF | yes (`mofcomp`) |
| hosts | hosts lines that send Microsoft, update or antivirus names elsewhere removed; every other line kept | yes |
| llmnr | LLMNR off | yes |
| **only with `-Include`:** | | |
| firewall | every firewall profile on, with the rules there are now (WN-25 builds rules) | yes |
| latfp | `LocalAccountTokenFilterPolicy` 0: remote admin with local accounts stops | yes |
| ntlm | `LmCompatibilityLevel` 5: NTLMv2 only | yes |
| lsappl | LSA protection (after a reboot) | yes |
| rdpnla | RDP requires Network Level Authentication | yes |
| spooler | DC only: Print Spooler stopped and disabled | yes |
| remotereg | Remote Registry stopped and disabled | yes |
| smbsigning | SMB server requires signing | yes |

A registry key is always backed up before it is changed; if the backup fails, that key is not changed. Values the run creates are deleted again by `-Undo`. The run folder (with the backups, one of which can hold the stored logon password) is limited to Administrators and SYSTEM.

#### Problems and fixes

| What you see | Why | Fix |
| --- | --- | --- |
| "run this with Windows PowerShell" | Started with `pwsh` (PowerShell 7) | Use `powershell.exe` |
| defender `FAILED: still off afterwards` | Tamper Protection, or another antivirus is installed | Turn Tamper Protection off in Windows Security first, or leave Defender to the other product |
| `FAILED: the key could not be backed up` | Access denied on that key | Nothing was changed there; run elevated, or fix by hand |
| A fix comes back after an hour | Domain Group Policy set it again | Fix the GPO as well |
| stickykeys `sfc did not repair it` | The component store copy is damaged too | `DISM /Online /Cleanup-Image /RestoreHealth`, then run again |
| `-Undo` refused: already undone | Each run is undone once | Nothing to do |
| `-Undo` with `-Apply` refused: no protected list | Like any change | Add `-Protected FILE` or `-NoProtected` |

---


### WN-42: Windows persistence sweep (`dist/windows-ad/WN-42-persistence-sweep.ps1`)

Where a red team leaves a way back in on Windows, and what to do with each. The Windows twin of LX-42. Run it on Borgar and Vattar after the first 15 minutes, and again whenever you think red team was on the box.

#### How to run it

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File WN-42-persistence-sweep.ps1                     # look + dry run
powershell -NoProfile -ExecutionPolicy Bypass -File WN-42-persistence-sweep.ps1 -Apply              # asks about each
powershell -NoProfile -ExecutionPolicy Bypass -File WN-42-persistence-sweep.ps1 -Apply -Batch -Areas tasks,runkeys,wmi
```

#### Where it looks

| Area | What is HIGH (offered for removal, default yes) | Fix |
| --- | --- | --- |
| tasks | a command that downloads and runs, hidden PowerShell, or runs from a temp or user folder | the task is disabled (not deleted) |
| runkeys | the same, in Run / RunOnce (machine, 32-bit, every logged-on user) | the value is removed (its old value is in the undo) |
| startup | a script in a startup folder is MED; a file from a temp folder or with download-and-run code is HIGH | quarantined |
| winlogon | Userinit or Shell changed from Windows' own | set back |
| services | a service from a temp or user folder, or with download-and-run code | start mode Disabled, stopped |
| wmi | every WMI event subscription (a favourite fileless backdoor) | the binding is removed; filter and consumer stay, so the undo can bind them again |
| ifeo | a "debugger" on a program (it runs instead). Sticky keys and the other logon-screen tools are WN-43's | the value is removed |
| admins | members of Administrators and Remote Desktop Users (MED; not on a domain controller: WN-23) | removed from the group |

MED findings (a shell or script, an unknown admin) are offered with default **keep**; LOW ones (a non-Windows task, a normal Run value) are only listed in `findings.txt`. Each line shows what it runs.

#### The questions

| Question | Answers | Parameter |
| --- | --- | --- |
| Which areas to look in? | `[A]`ll / `[q]`uick (tasks, Run keys, services, WMI) | `-Areas` |
| Each finding | `[r]`emove, `[k]`eep, `[a]`ll the rest: their default | `-Exclude` names one never offered |
| Apply these N change(s)? | `[y]` / `[N]` | `-Apply` |

`-Batch` takes every default: a dry run unless `-Apply` is given.

#### Safety and output

- Dry run unless `-Apply`; the revert timer runs with `-Apply` (120 s, `-Timer`): everything is undone unless you answer "keep". `revert.ps1 -Force` in the run folder undoes the run later.
- Never touched: anything on the protected list (service, account, path, process), the account running it, the built-in Administrator.
- In `<out>\persistence-N\`: `output.txt`, `findings.txt` (level, area, name, what it runs, why, what was done), `summary.txt`, `run.txt`, `undo.txt`, `revert.ps1`.
- Not yet run on real Windows: try it on a VM first.
