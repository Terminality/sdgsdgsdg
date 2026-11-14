# Plan

## Scope

Core scripts only, for three roles: **Linux, Windows / AD, Network.** The list is `docs/catalog.csv`.

The scripts are aimed at the services in `docs/ENVIRONMENT.md`. Those come from past competitions and can change.

Other roles: if you want scripts, write them yourself and follow `AGENTS.md`.

## How scripts work

- **Enum scripts** only look. They change nothing.
- **Fix scripts** are made of small named fixes. You can run one fix without running the rest (`--list`, `--only`, `--skip`; on Windows `-List`, `-Only`, `-Skip`).
- Everything is a dry run until you add `--apply` / `-Apply`.

## Tiers

| Tier | Meaning |
| --- | --- |
| enum | Looks only |
| prep | Backups. Run before any change |
| easy | Safe fixes. Can't break a service or lock you out |
| medium | Could break a scored service. Checks it and reverts if it breaks |
| hard | Could lock you out (firewall, RDP, WinRM, SSH, accounts) |
| manage | Passwords and accounts |
| alert | Tells you when something changes |
| kit | Shared libraries |

## Risk labels

| Risk | Meaning |
| --- | --- |
| none | Changes nothing |
| safe | Can't break a service or lock you out |
| service | Could break a scored service |
| access | Could lock you out |

## Lockout rule

Anything marked `access` must:

1. Run only when you name it. Never as part of "run everything".
2. Start a **1-minute countdown** after the change.
3. Revert by itself unless you confirm **from a new session** (new RDP or SSH window).
4. Keep an undo, so you can revert it later too.

Before an `access` change: keep a second session open, and have a backup admin account with a known password.

The firewall scripts already roll back (5 minutes on Windows, 2 on Linux). They still need to move to 1 minute.

## Safety

- Never put real competition passwords in the repo.
- Copy password and findings files off the box, then delete them there.
- Keep the repo private.
- Scripts stay as scripts, not compiled binaries.
