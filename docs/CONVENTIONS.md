# Conventions

Rules for writing a script in this repository. The libraries enforce most of them; the lint checks and tests catch the rest.

## Where a script lives and what it is called

- Read `docs/PLAN.md` first: tiers, risk labels and the countdown rule.
- One script per catalog entry. The ID, name, role, tier and risk come from `docs/catalog.csv`.
- File: `roles/<role_dir>/<ID>-<short-name>.sh` or `.ps1`, for example `roles/linux/LX-20-password-rotation.sh`.
- A script that covers both platforms is two files with the same ID, one `.sh` and one `.ps1`.
- The ID never changes, even if the script moves to another role. The folder is the owner.

## Adding a script

1. Copy `templates/script-template.sh` or `.ps1` into the role folder and rename it.
2. Fill in every section of the header. Leave "TESTED ON" as "not yet tested" until it has been run on a real target.
3. Write the script. Make every change through `cc_run` / `Invoke-CcChange`.
4. Add `tests/<id>.test.sh` or a group in a `.Tests.ps1` file.
5. Run `sh tests/run-tests.sh` until it passes.
6. In `docs/catalog.csv` set `status` to `built` and fill in `path`. Run `sh tools/update-docs.sh`.
7. Add a section to `docs/MANUAL.md`: how to use it, what to watch for, problems and fixes.
8. Add a line to `docs/CHANGELOG.md`, and to the "Ready to use" table in `README.md`.

## The header

Every script starts with the header block from the template: ID, NAME, ROLE, KIND, PURPOSE, USAGE, INPUTS, OUTPUTS, WHAT IT CHANGES, DEPENDS ON, TESTED ON, KNOWN LIMITS, DEBUGGING. The header is the first thing someone reads at 2 a.m. when the script misbehaves, so write it for that reader.

## Comments

- Say why, not what. `# old Solaris id has no -u` helps; `# get the uid` does not.
- Above every function: what it takes, what it returns, and what it changes.
- Mark every fallback with the system it is for, so nobody deletes it as dead code.
- When a line looks wrong but is deliberate, say so on that line.

## Rules every script follows

1. Inventory scripts never change anything. Scripts that change things do nothing without `--apply` / `-Apply`.
2. Back up before changing, and record the undo command (`cc_backup_file`, `cc_undo_add`, `Backup-CcFile`, `-Undo`).
3. A backup only counts once a copy is off the host.
4. Check the protected list before touching anything (`cc_guard`, `Test-CcAllowed`).
5. Protected accounts need the extra `--force-scored` / `-ForceScored` flag.
6. Firewall scripts keep the scoring engine and established connections allowed, and revert unless confirmed.
7. No password in a script, on a command line, or in a log. Use `cc_run_quiet` / `-Secret` for steps that handle one.
8. Generate passwords with `cc_genpass` / `New-CcPassword` only.
9. Return the standard exit codes and be safe to run twice.
10. Print a readable summary; put full detail in a CSV (`cc_csv_new`, `New-CcCsv`).
11. Never write next to the script. Output goes to the `--out` folder.
12. No internet and no package installs.
13. Work alone and under fan-out. Never prompt unless `cc_confirm` / `Confirm-Cc` is used, which honors `CCDC_ASSUME_YES=1`.
14. Block IPv6 unless a scored service or an inject needs it.
15. The kit's hash is checked before each run (automatic once `MANIFEST.sha256` exists).
16. The team automation account is on the protected list.
17. Output is for people reading a terminal, not for web pages: plain words, sections, aligned tables. Unusual items on screen; everything in readable `.txt` tables; CSV only as a copy in `csv/` for other scripts.

Detection and fixing are separate scripts. An enum script writes findings with `cc_finding` / `Add-CcFinding`, each with a fix ID and a risk (`safe`, `service`, `access`; see `docs/PLAN.md`). A fix script is made of named fixes, each runnable alone, and reads that file. An `access` fix never runs in bulk and uses the countdown that reverts unless confirmed from a new session.

## Inventory scripts

Scripts that only look (enum scripts, audits) follow the Linux enum's pattern:

- Call `cc_use_numbered_dir NAME` after starting, so each run gets a numbered folder (`linux-enum-1`, `linux-enum-2`, ...). Windows scripts still use `Use-CcRunDir`.
- Print a header per section as it runs, then what was found: red `[!] FIX` for HIGH, yellow `[*] LOOK` for MED (see SH-05).
- One readable `.txt` table per section (`cc_csv_pretty`), with the CSV copy in `csv/`. Keep raw tool output with `cc_save` / `Save-CcOutput`.
- Mark anything unusual with `cc_flag` / `Add-CcFlag`: `HIGH` (look now), `MED` (look soon), `LOW` (file only). Write the detail for someone who has never seen the box: what is wrong and why it matters.
- End with a one-page summary and `cc_flag_report` / `Show-CcFlagReport`. Only HIGH and MED reach the screen.
- Tune for precision. Run the script on a real system before calling it built, and tighten any check that flags normal things. A screen full of false alarms hides the real one.
- Never record a password, hash or secret value; record where it is and what it is called.
- In shell scripts, never put `| while read` around a loop that sets variables or counts; read from a file instead (`done <file`). The right side of a pipe is a subshell in dash and bash, so its changes are lost.

## Shell scripts: POSIX sh only

`#!/bin/sh`, and nothing bash-specific: no `local`, `[[ ]]`, arrays, `function`, `echo -n`, `source`, `==`, `&>`, `<<<`, `$RANDOM`, `pipefail`. No GNU-only flags: `head -c`, `grep -P`, `sed -i`, `readlink -f`. Do not use `set -e`; count errors and keep going.

Because there is no `local`, name temporary variables in a function `_<function>_<name>`. Avoid one-letter function names: `r` is a built-in alias in ksh.

When a tool may be missing, detect and fall back: `cc_first ss netstat lsof`.

A line that trips `tests/lint-posix.sh` for a reason the pattern cannot see can end with `# posix-ok`.

## PowerShell scripts: 2.0 only

No `ConvertTo-Json`, `[pscustomobject]`, `[ordered]`, CIM cmdlets, `$PSScriptRoot`, `-in`, `.Where()`, `Get-FileHash`, `Export-Csv -Append`, or the `Get-Net*`, `Get-Local*`, `Get-ScheduledTask` families. Write `[Parameter(Mandatory=$true)]` in full. Wrap anything that may be one item or none in `@( )` before reading `.Count`.

Declare the seven common parameters exactly as the template does and pass `$PSBoundParameters` to `Initialize-Cc`.

Run external programs inside a change with `Invoke-CcProgram`, and do not add `2>&1` yourself. On Windows PowerShell that redirect makes a program that prints a warning look like a failed step.

A newer cmdlet may be used when it is guarded and has an older fallback beside it; end that line with `# ps2-ok`.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Finished; nothing failed |
| 1 | Unexpected error |
| 2 | Usage error |
| 3 | Missing requirement: not root or admin, tool not found, no protected list, kit check failed |
| 4 | Refused: the only thing asked for is protected |
| 5 | Finished, but at least one change failed |
| 130 | Interrupted |
