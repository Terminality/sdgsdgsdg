# Plan

## What we have

Right now we only have scripts for **Linux, Windows / AD and Network**. The full list is in `docs/catalog.csv`.

If you're on a different role and want scripts, go ahead and make them yourself. Just follow `AGENTS.md`.

The scripts that still need to be built are what we're planning for now, and that'll probably change as we go. Same with the services in `docs/ENVIRONMENT.md`: those are just what we've seen in past comps, so they could be different next time.

## How the scripts work

- **Enum scripts** just look around. They don't change anything.
- **Fix scripts** are a bunch of small fixes, and you can run just one if that's all you need (`--list`, `--only`, `--skip`, or `-List`, `-Only`, `-Skip` on Windows).
- Nothing actually changes until you add `--apply` (`-Apply` on Windows). Without it, it's a dry run.
- Output should be easy to read in a terminal: sections, plain words, readable tables. Not formatted for web pages.

## Tiers

| Tier | What it means |
| --- | --- |
| enum | Only looks |
| prep | Backups. Do these before changing anything |
| easy | Safe fixes. Won't break a service or lock you out |
| medium | Might break a scored service, so it checks the service and undoes the fix if it broke |
| hard | Might lock you out (firewall, RDP, WinRM, SSH, accounts) |
| manage | Passwords and accounts |
| alert | Lets you know when something changes |
| kit | The shared libraries |

## Risk labels

| Risk | What it means |
| --- | --- |
| none | Doesn't change anything |
| safe | Won't break a service or lock you out |
| service | Might break a scored service |
| access | Might lock you out |

## Lockout rule

We got kicked off a box in practice once, so anything marked `access` has to:

1. Only run when you ask for it by name. It never runs as part of "run everything".
2. Start a **1-minute countdown** after the change.
3. Undo itself unless you confirm **from a new session** (open a new RDP or SSH window and confirm from there).
4. Keep an undo so you can roll it back later too.

Before you run anything like that, keep a second session open and make sure there's a backup admin account with a password you know.

The firewall scripts already roll themselves back (5 minutes on Windows, 2 on Linux). They still need to be moved to 1 minute.

## Staying safe

- Don't put real competition passwords in the repo.
- Copy password and findings files off the box, then delete them from the box.
- Keep the repo private.
- Keep the scripts as scripts. Don't compile them into binaries.
