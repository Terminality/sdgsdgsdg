# Plan and direction

This is the team's direction for the kit. Read it before adding or changing a script, and point any AI tool you use at it (`AGENTS.md` does that automatically). `docs/catalog.csv` is the list of scripts; `docs/ENVIRONMENT.md` is what is scored.

## Focus

A few big, solid scripts beat many niche ones. The catalog was cut from 142 ideas to the ~54 that matter for a CCDC network like ours. A new script needs a clear reason it cannot be a named fix inside an existing one.

## How the kit fits together

```
enum (look, change nothing)  ->  findings, each with a fix ID and a risk
                                       |
          pick lines, run only those fixes (dry run first, then --apply)
```

- **Enum scripts are big and thorough.** They change nothing, so they can afford to look everywhere. Each finding says what is wrong, its risk, and which fix handles it (`cc_finding` / `Add-CcFinding`).
- **Fix scripts are made of small named fixes.** One script per area (SSH, web, SQL Server, mail, Splunk, remote access ...), each fix runnable on its own: `--list`, `--only a,b`, `--skip c` (`-List`, `-Only`, `-Skip` on Windows). Running one fix never runs the others.
- **Focused enum scripts** go deeper on one area (SSH, AD, mail, Splunk, SQL Server) than the host enum can.

## Tiers

Every script is in one tier (`tier` column in the catalog). Run them roughly in this order.

| Tier | What | Examples |
| --- | --- | --- |
| `enum` | Look only, change nothing. Robust: a broken section must not stop the rest | Linux enum, Windows enum, AD enum, SSH enum, network scan |
| `prep` | Before any change: backups, protected list, backup admin account, restore | LX-31, WN-35, SV-14, SH-09, SH-11 |
| `easy` | Hardening that cannot break a scored service or your access | LX-39, WN-43 |
| `medium` | Hardening that could break a scored service. Checks the service after each fix and reverts if it stopped | SSH fixes, web, SQL Server, mail, Splunk hardening |
| `hard` | Anything that can kick you off the box or out of a service | firewalls, RDP/WinRM/SSH lockdown, account lockdown |
| `manage` | Day-to-day running: passwords, accounts, service checks, injects | password rotation, credential sheet, service checker |
| `alert` | Tell us when the red team does something | Linux alerts, Windows alerts, Splunk searches |
| `evict` | Get the red team out once they are in | persistence hunters, session purge |
| `kit` | Libraries, build, getting the kit onto boxes | lib.sh, lib.ps1, fan-out, local runner |

## Risk labels

Every script, and every named fix inside a fix script, has one (`risk` column).

| Risk | Meaning | Rule |
| --- | --- | --- |
| `none` | Changes nothing | Run freely |
| `safe` | Cannot break a scored service or access | May run in bulk ("all safe fixes") |
| `service` | Could break a scored service | Test the service after the change; revert if it stopped; recorded undo |
| `access` | Could lock you out (RDP, WinRM, SSH, firewall, passwords, logon rights, account lockdown) | Never runs in bulk. Only when named. **Countdown that reverts** plus **recorded undo** |

## The countdown rule (anything that can kick you off)

This exists because a practice fix turned RDP off and kicked us off the box.

1. Before the change, save what is needed to put it back.
2. Make the change, then start a **1-minute countdown** (default; an option makes it longer for slow logins).
3. Confirm by logging in **from a new session** (new RDP window, new SSH connection) and running the keep command. Confirming from the old session proves nothing: it is the one connection that survives.
4. If nobody confirms, the change is reverted automatically, by a job that does not depend on your session (scheduled task as SYSTEM, `at`/`systemd-run`/background job as root).
5. The undo stays recorded either way, so it can be reverted later if it breaks something else down the line (`-Undo` / `--undo`, or AU-12).

The firewalls (WN-25, LX-25) already work this way, with 5- and 2-minute timers; moving them to the shared 1-minute helper in the libraries is on the to-do list. Password rotation counts too: changing the password of the account you are logged in with gets the same countdown.

Before any `access` change on a box: keep a second session open and have the backup admin account (SH-11) in place.

## Every script, every time

- Dry run unless `--apply` / `-Apply`.
- Protected list checked before touching anything (built from `docs/ENVIRONMENT.md` by SH-09).
- Backup before change; undo recorded.
- Never record a password, hash or secret in output or logs. Password files are admin-only and are copied off the box and deleted.
- Never touch the scorer's accounts without reporting the new password (credential sheet, AU-16).
- Shell: POSIX `sh`. PowerShell: 2.0 rules. Details in `docs/CONVENTIONS.md`.

## Scripts, not binaries

The kit stays as plain scripts. Compiling them hides little (an admin can run or unpack a binary), antivirus quarantines script-to-exe binaries, and a binary cannot be fixed on the spot. What we protect instead:

- **Outputs:** password and findings files go off the box and are deleted there.
- **Integrity:** run from the admin machine or a read-only share where possible, check the kit hash (LB-03 writes it), do not leave the kit on boxes.
- **The repo and the Drive folder stay private** to the team. No real competition passwords in the repo, ever.

## Names

- "Enum", not "collector": SH-05 Linux enum, SH-06 Windows enum, SV-01 web and database enum. Some output keys still say `collector_...` so older runs can be compared; leave them.
- IDs never change. A script that changes job keeps its ID; a dropped idea's ID is not reused for something else.
