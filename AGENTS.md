# Instructions for AI tools (and people) changing this repository

Read these before writing anything. They are the team's decisions; do not work around them.

1. **Read `docs/PLAN.md` first.** It sets the direction: tiers, risk labels, the countdown rule, scripts not binaries.
2. **Work from the catalog.** Only build scripts listed in `docs/catalog.csv`, under their ID, in their role folder. To propose a new script, add it to the catalog in a separate merge request and say why it cannot be a named fix in an existing script. Do not add niche one-off scripts.
3. **Check what is scored:** `docs/ENVIRONMENT.md`. Nothing may break those services or remove the access the scorer uses.
4. **Enum scripts change nothing.** Fix scripts are made of named fixes, each runnable alone (`--list`, `--only`, `--skip`). Give every fix a risk label: `safe`, `service` or `access`.
5. **`access` fixes** (anything that can kick someone off RDP, WinRM, SSH, the firewall, a password, logon rights, accounts) never run in bulk, need a countdown that reverts unless confirmed from a new session, and a recorded undo. See "The countdown rule" in `docs/PLAN.md`.
6. **Follow `docs/CONVENTIONS.md`:** POSIX `sh` and PowerShell 2.0, the shared libraries, dry run by default, protected list, backups and undo, no secrets in output.
7. **Test without touching a real system.** Every script has a test in `tests/` that uses stand-in tools or fake state. Run `sh tests/run-tests.sh`, `sh tests/lint-ps2.sh` and the PowerShell tests before asking for a merge.
8. **Keep docs in step.** After changing the catalog run `sh tools/update-docs.sh` (role READMEs and `docs/STATUS.md` are generated; never edit them by hand). Update `docs/MANUAL.md`, `docs/CHANGELOG.md` and the README table for any script you add or change.
9. **One merge request per change,** never straight to `main`, with what changed, how it was tested, and what was not tested.
10. **Do not change a script you were not asked to change**, even to tidy it. Say what you would change instead.
