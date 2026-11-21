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
| **WN-50** Service recovery | Why a scored service is down (stopped, disabled, a block rule, another program on its port, a stopped IIS app pool) and the fix; sets restart-on-crash | The moment a service goes red; `-Watch 30 -AutoRestart -Apply` in a spare window keeps them up | `.\WN-50-service-recovery.ps1` |
| **WN-43** Safe fixes again | Red team turns things back off | Every hour or after an incident | `.\WN-43-safe-fixes.ps1 -Apply -Batch` |
| **SH-06** full | A full picture, including processes, connections, sessions, shares, software, events | When things are calm, and to compare | `.\SH-06-windows-enum.ps1` |
| **WN-23** again (Vattar) | New admins or accounts since the last run | Every hour | `.\WN-23-ad-lockdown.ps1 -Admins youradmin` |

### When something happens

| What you see | Run |
| --- | --- |
| You think red team is on the box | `SH-06 -Profile triage` (copies the event logs too), then WN-42 |
| A new admin or account | WN-23 on Vattar; WN-42 `-Areas admins` on Borgar |
| A scored service went red | `WN-50 -Apply`: it finds why and offers the fix. Still red? `WN-25 -Undo latest` puts the old firewall back |
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
