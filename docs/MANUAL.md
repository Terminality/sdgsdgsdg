# Manual

How to use what is built, what to watch for, and what to do when something goes wrong. A script gets a section here when it is built; `docs/STATUS.md` lists what exists.

Built so far: the shell library (LB-01), the PowerShell library (LB-02), the network scan (SH-03), the scan diff (SH-04), the Linux enum (SH-05), the web and database inventory (SV-01), the script templates, and the test runner.

**Read this first.** The libraries pass their tests on Linux shells and on PowerShell 7. They have not been run on Windows, FreeBSD or Solaris. Section 8 says how to check them on your own test machines.

Contents:

1. Things every script has in common
2. The output folder
3. The protected list
4. The undo log and rolling back
5. Shell library, `lib/lib.sh` (LB-01)
6. PowerShell library, `lib/lib.ps1` (LB-02)
7. Script templates
8. Tests
9. Problems that apply to everything
10. Linux enum, `roles/linux/SH-05-linux-enum.sh` (SH-05)
11. Network scan, `roles/network/SH-03-network-scan.sh` (SH-03)
12. Scan diff, `roles/network/SH-04-scan-diff.sh` (SH-04)
13. Web and database enum, `roles/applications/SV-01-web-db-enum.sh` (SV-01)
14. Backup, `roles/linux/LX-31-backup.sh` (LX-31)
15. Linux safe fixes, `roles/linux/LX-39-safe-fixes.sh` (LX-39)
16. Linux password rotation, `roles/linux/LX-20-password-rotation.sh` (LX-20)
17. SSH hardening and key cleanup, `roles/linux/LX-22-ssh-hardening.sh` (LX-22)
18. Linux firewall builder, `roles/linux/LX-25-firewall.sh` (LX-25)
19. Linux change watch, `roles/linux/LX-40-change-watch.sh` (LX-40)
20. Brute-force and spam banning, `roles/linux/SV-26-banning.sh` (SV-26)
21. Database backup, `roles/applications/SV-14-db-backup.sh` (SV-14)
22. Network config backup and diff, `roles/network/NW-01-config-backup.sh` (NW-01)
23. Network config audit, `roles/network/NW-07-config-audit.sh` (NW-07)
24. Device password rotation, `roles/network/NW-10-device-passwords.sh` (NW-10)
25. Windows enum, `roles/windows-ad/SH-06-windows-enum.ps1` (SH-06)
26. Windows backup, `roles/windows-ad/WN-35-backup.ps1` (WN-35)
27. Windows password rotation, `roles/windows-ad/WN-20-password-rotation.ps1` (WN-20)
28. Windows safe fixes, `roles/windows-ad/WN-43-safe-fixes.ps1` (WN-43)
29. Windows firewall, `roles/windows-ad/WN-25-firewall.ps1` (WN-25)

---

## 1. Things every script has in common

Every script accepts the same options, because the libraries parse them.

| Unix | Windows | What it does |
| --- | --- | --- |
| *(nothing)* or `--dry-run` | *(nothing)* | Dry run: shows what would change and changes nothing |
| `--apply` | `-Apply` | Make the changes |
| `--out DIR` | `-Out DIR` | Folder for logs, CSV files, backups and the undo log |
| `--protected FILE` | `-Protected FILE` | Protected-list CSV |
| `--no-protected` | `-NoProtected` | Allow apply with no protected list. Dangerous |
| `--force-scored` | `-ForceScored` | Allow changes to protected accounts |
| `--quiet` | `-Quiet` | Print only warnings and errors |
| `--debug` | `-DebugLog` | Print debugging detail |
| `--version` | | Print the library version |

Environment variables do the same job when you don't want to type the options on every host: `CCDC_OUT`, `CCDC_PROTECTED`, `CCDC_ASSUME_YES=1` (answer yes to questions), `CCDC_SKIP_VERIFY=1` (skip the kit hash check), `CCDC_MANIFEST` (path to the manifest).

The habit to build: **run it dry, read the WOULD lines, then run it again with apply.**

Each line a script prints starts with a time, a level and the script ID:

| Level | Meaning |
| --- | --- |
| `INFO` | Progress |
| `WOULD` | Dry run: this is what apply would do |
| `DO` | Apply: this is being done now |
| `REFUSED` | Skipped because it is on the protected list |
| `FINDING` | A detection script found a weakness |
| `WARN` | Worth reading; the script carried on |
| `ERROR` | A step failed, or the script is stopping |
| `DEBUG` | Shown only with `--debug` / `-DebugLog` |

The last line is the summary: `done: changed=3 would-change=0 failed=1 refused=2 findings=0 exit=5`.

Exit codes:

| Code | Meaning | What to do |
| --- | --- | --- |
| 0 | Finished; nothing failed | Check the summary for refusals |
| 1 | Unexpected error | Read the last ERROR line and the log |
| 2 | Usage error | Fix the command line; try `--help` |
| 3 | Missing requirement | Not root or admin, a tool is missing, there is no protected list, or the kit check failed. The message says which |
| 4 | Refused | The only thing asked for is protected |
| 5 | A change failed | Open the log; the failed step's output is there |
| 130 | Interrupted | Some changes may have been made; check the undo log |

## 2. The output folder

Scripts never write next to themselves. Everything goes under the folder given by `--out` / `-Out`, then `CCDC_OUT`, then `~/ccdc-out`.

```
<out>/
  <ID>_<host>_<UTC time>.log               one per run: everything printed, plus command output
  <ID>_<host>_<UTC time>_<name>.csv        data a script produced
  <ID>_<host>_<UTC time>_findings.csv      weaknesses found by a detection script
  undo-<host>.log                          one per host, shared by every script
  protected.csv                            the protected list, if you keep it here
  backup/<host>/<UTC time>_<ID>/...        files as they were before a change, full path kept
  quarantine/<host>/<UTC time>_<ID>/...    suspicious files moved out of the way
```

On Unix the folder and the files the library creates are readable only by the user who ran the script.

**Watch for**

- The folder holds host details and may hold credential files that scripts write. Keep it off shared drives, and get a copy off the host: a backup that exists only on the machine the red team is on does not count.
- Times in file names and logs are UTC, so they sort correctly across hosts in different time zones.
- The output folder must not be inside the folder the script is in. The script stops with exit 2 if it is.

## 3. The protected list

A CSV of things no script may close, stop, block or change. `config/protected.example.csv` is a starting point.

```
type,value,note
port,80/tcp,scored web site
port,53,scored DNS (both protocols)
service,apache2,serves the scored site
account,svc-web,the scoring engine logs in as this user
path,/var/www/html,scored content
host,10.0.0.5,scoring engine address
```

- `type` is one of `port`, `service`, `account`, `path`, `host`, `process`.
- `value` is not case-sensitive.
- A port written `80` protects both protocols. `80/tcp` protects TCP only. A script asking about plain `80` is refused if `80/tcp` is listed: when in doubt the answer is "protected".
- Lines starting with `#` and blank lines are ignored. Quotes around fields and Windows line endings are fine.

How scripts use it:

- A script that changes things **will not apply at all** when it cannot find a protected list (exit 3). This is deliberate: the most common way to lose points is to harden before knowing what is scored.
- A protected item is skipped with a `REFUSED` line and counted in the summary. The script continues with everything else.
- `account` entries can be overridden with `--force-scored` / `-ForceScored`. Nothing else can; to change another protected item, edit the list.

**Watch for**

- The list is only as good as what is in it. A scored service missing from the list has no protection.
- Matching is exact apart from case. `apache2` does not protect `httpd`. List every name a service goes by on your hosts.
- `--no-protected` exists for the first minutes before the list is built. Do not make it a habit.
- The Windows library reads the list once per run. Edit the file, then start the script again.

## 4. The undo log and rolling back

Each host has one `undo-<host>.log`, shared by every script. Each change adds a line with four tab-separated fields:

```
2026-11-11T17:02:11Z    LX-22    restore /etc/ssh/sshd_config    cp -pR '/root/ccdc-out/backup/web01/..._LX-22/etc/ssh/sshd_config' '/etc/ssh/sshd_config'
```

Time, script ID, what it undoes, and the command that undoes it. The newest change is at the bottom.

To roll back by hand, run the commands from the bottom up. The undo walker (SH-12) will automate this once it is built. Until then:

```sh
# Unix: undo the last 3 changes on this host
tail -n 3 ~/ccdc-out/undo-$(uname -n | sed 's/\..*//').log | awk -F'\t' '{a[NR]=$4} END{for(i=NR;i>=1;i--)print a[i]}' | sh -x
```

```powershell
# Windows: undo the last 3 changes on this host
$lines = @(Get-Content "$HOME\ccdc-out\undo-$env:COMPUTERNAME.log" | Select-Object -Last 3)
[array]::Reverse($lines)
foreach ($l in $lines) { $cmd = ($l -split "`t")[3]; Write-Host $cmd; Invoke-Expression $cmd }
```

**Watch for**

- Read the commands before running them. Undoing a password lockdown or a firewall rule reopens what you closed.
- Undo restores files and settings. It does not restart services. Restart the service yourself after restoring its config.
- A dry run writes nothing to the undo log, because nothing changed.
- Undo order matters. Undoing an older change while a newer change to the same file is still in place restores the older copy over it.
- If the backup folder was deleted, the restore commands in the log will fail. This is another reason to copy the output folder off the host.

---

## 5. Shell library, `lib/lib.sh` (LB-01)

The shared code for every Unix script. You don't run it; scripts load it. Operators meet it through the common options, log lines and exit codes above. This section is for whoever writes or debugs a script.

### How a script uses it

Start from `templates/script-template.sh`. The shape is always:

```sh
# >>> CCDC-LIB          (loader lines from the template; the build step replaces this block)
# <<< CCDC-LIB
while [ $# -gt 0 ]; do
    if cc_common_flag "$@"; then shift "$CC_SHIFT"; continue; fi
    case "$1" in
        --port) PORT=$2; shift 2 ;;
        *) cc_die 2 "unknown option: $1" ;;
    esac
done
cc_init "LX-24" "Port and service closer" changes
cc_require_root
cc_guard port "$PORT" || cc_finish 4
cc_backup_file /etc/some.conf || cc_die 1 "backup failed"
cc_run "stop the service" service telnet stop
cc_finish
```

### Functions

| Function | What it does |
| --- | --- |
| `cc_common_flag "$@"` | Handles one common option; sets `CC_SHIFT`. Returns 1 if the option is not a common one |
| `cc_usage_common` | Prints the common options for `--help` |
| `cc_init ID NAME KIND` | Opens the log, sets the output paths, loads the protected list, checks the kit. `KIND` is `readonly` or `changes` |
| `cc_info` `cc_warn` `cc_err` `cc_debug` | Log a line at that level |
| `cc_die CODE MSG` | Log an error and exit |
| `cc_run DESC CMD...` | Dry run: log WOULD. Apply: run it, log its output, count the result |
| `cc_run_quiet DESC CMD...` | Same, but logs only the description. For anything involving a secret |
| `cc_backup_file PATH` | Copy a file or folder to the backup folder and record the restore command |
| `cc_undo_add DESC CMD` | Add a line to the undo log |
| `cc_is_protected TYPE VALUE` | Returns 0 if on the protected list |
| `cc_guard TYPE VALUE` | Returns 0 if it is OK to change; logs REFUSED and returns 1 if not |
| `cc_have TOOL` / `cc_need TOOL...` / `cc_first TOOL...` | Is a tool there; stop if not; print the first that exists |
| `cc_detect_os` | Sets `CC_OS_KERNEL`, `CC_OS_FAMILY`, `CC_OS_NAME`, `CC_OS_VERSION`, `CC_INIT`, `CC_PKG` |
| `cc_is_root` / `cc_require_root` | Check for root; stop with exit 3 if not |
| `cc_confirm QUESTION` | Ask the operator. `CCDC_ASSUME_YES=1` answers yes |
| `cc_genpass [LEN]` | Print a random password. Never logs it |
| `cc_sha256 FILE` | Print a file's SHA-256 using whichever tool exists |
| `cc_quarantine PATH` | Move a file to the quarantine folder, log its hash, record the undo |
| `cc_csv_new NAME HEADER` / `cc_csv_row FILE FIELD...` | Create a CSV in the output folder; append a quoted row |
| `cc_finding WEAKNESS FIX_ID CLASS DETAIL [DEP]` | Write a finding. `CLASS` is `safe`, `service` or `protected` |
| `cc_use_run_dir` | Inventory scripts: put this run's CSV files in one folder, `<out>/<ID>_<host>_<time>/` |
| `cc_save NAME CMD...` | Keep a read-only command's untouched output in `raw/NAME.txt` |
| `cc_flag SEV SECTION ITEM DETAIL` | Record something unusual. `SEV` is `HIGH`, `MED` or `LOW`. Goes to `flags.csv` and the log, not the screen |
| `cc_flag_report [MAX]` | Print HIGH then MED flags, at most MAX lines (default 30), then counts. LOW flags are counted, never listed |
| `CC_AWK_CSV` | An awk `csvsplit()` function for reading the kit's CSV files correctly |
| `cc_shquote STR` / `cc_abspath PATH` | Quote for a shell; make a path absolute |
| `cc_verify_self` | Check the running script against `MANIFEST.sha256` (called by `cc_init`) |
| `cc_finish [CODE]` | Print the summary and exit |

### What to watch for

- **`cc_run` logs the whole command line.** If any argument is a password, use `cc_run_quiet`. `cc_run_quiet` also throws away the command's output, so its error message will not be in the log.
- **`cc_run` takes a command and arguments, not a shell string.** `cc_run "x" echo a > file` redirects the output of `cc_run` itself, even in a dry run. For pipes or redirects use `cc_run "x" sh -c 'echo a > file'`.
- **Call `cc_backup_file` before the change, and stop if it returns 1.** The undo entry is only as good as the backup.
- **`cc_guard` returns 1 for "refused".** Use `cc_guard port "$p" || continue`. Writing `if cc_guard ...; then skip` is backwards.
- **`cc_genpass` prints the password and nothing else.** Capture it with `p=$(cc_genpass)` and send it only to the operator's credential file.
- **No `local`.** A new function's temporary variables must have their own prefix or they will overwrite another function's.
- **No `set -e`.** A failed step is counted and the script continues. Check the return value of `cc_run` if a later step depends on it.
- **The kit hash check does nothing yet.** It activates when a `MANIFEST.sha256` exists beside the scripts, which the build step (LB-03) will create.

### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `output folder ... is inside the kit folder` (exit 2) | `--out` points into the folder the script is in | Pass `--out` somewhere else, or set `CCDC_OUT` |
| `no protected list at ... - refusing to change anything` (exit 3) | Apply with no protected list | Create the list, or pass `--protected FILE`. In an emergency only, `--no-protected` |
| `cannot create output folder` / `not writable` (exit 3) | No permission, read-only disk, or disk full | Choose another `--out`. Check `df -h` and `mount` |
| `KIT CHECK FAILED` (exit 3) | The script file differs from the manifest: it was edited, or copied badly | Re-copy the kit from the admin workstation. If you edited it on purpose, rebuild, or set `CCDC_SKIP_VERIFY=1` for that run |
| `required tool not found: X` (exit 3) | The host lacks a command the script needs | Use the fallback path if the script has one. Otherwise add the tool to the offline bundle |
| `cc_genpass: could not generate a password` | `/dev/urandom` unreadable, or a `tr` that does not accept ranges (stock Solaris) | On Solaris put `/usr/xpg4/bin` first in `PATH` |
| `$'\r': command not found`, or `bad interpreter` | The file has Windows line endings | It was edited on Windows or copied through a tool that converted it. Re-copy from the repo, or run `tr -d '\r' < bad.sh > good.sh` |
| `quarantine FAILED` | The file is immutable, or on a read-only mount | `lsattr FILE`; `chattr -i FILE`; then re-run |
| A dry run prints nothing between the banner and the summary | Nothing needed changing, or `--quiet` is set | Add `--debug` to see each decision |
| The script hangs on a question under fan-out | `cc_confirm` is waiting for an answer | Set `CCDC_ASSUME_YES=1` when running unattended |
| `this script must be run as root` (exit 3) | Not root | `sudo sh script.sh ...`. Under sudo, `~` is root's home, so pass `--out` explicitly |
| Passes in bash, fails in `sh` on a target | A bash-only construct got in | Run `sh tests/lint-posix.sh`, then `TEST_SHELL=dash dash tests/<file>.test.sh` |

---

## 6. PowerShell library, `lib/lib.ps1` (LB-02)

The shared code for every Windows script, with the same behavior as `lib.sh`.

**This library has not been run on Windows.** It passes its tests on PowerShell 7 on Linux and a pattern check for features newer than PowerShell 2.0. Run `tests\lib.Tests.ps1` on a Windows test VM before building on it (section 8).

### Starting a script

```
powershell -NoProfile -ExecutionPolicy Bypass -File WN-20-ad-password-rotation.ps1 -Out C:\ccdc-out
```

`-ExecutionPolicy Bypass` applies to that one process and changes no system setting. `-NoProfile` stops a profile script the red team may have planted from running first.

### How a script uses it

Start from `templates/script-template.ps1`. The shape is always:

```powershell
param([switch]$Apply, [string]$Out, [string]$Protected, [switch]$NoProtected,
      [switch]$ForceScored, [switch]$Quiet, [switch]$DebugLog, [string]$ServiceName)
# >>> CCDC-LIB          (loader lines from the template; the build step replaces this block)
# <<< CCDC-LIB
Initialize-Cc -Id 'WN-24' -Name 'Port and service closer' -Kind changes -Bound $PSBoundParameters
Assert-CcAdmin
if (-not (Test-CcAllowed -Type service -Value $ServiceName)) { Complete-Cc -ExitCode 4 }
Invoke-CcChange -Description "stop $ServiceName" -Action { Stop-Service $ServiceName } `
                -Undo "Start-Service $ServiceName" | Out-Null
Complete-Cc
```

Library state is in one hashtable, `$Cc`: `$Cc.Apply`, `$Cc.Out`, `$Cc.Log`, `$Cc.Undo`, `$Cc.Host`, and the counters `$Cc.Done`, `$Cc.Would`, `$Cc.Failed`, `$Cc.Refused`.

### Functions

| Function | What it does |
| --- | --- |
| `Initialize-Cc -Id -Name -Kind -Bound` | Opens the log, sets the output paths, loads the protected list, checks the kit |
| `Write-CcLog -Level -Message` | Log a line |
| `Stop-Cc -Code -Message` | Log an error and exit |
| `Invoke-CcChange -Description -Action {} [-Undo] [-Secret]` | Dry run: log WOULD. Apply: run the block, log its output, count the result. Returns `$true` or `$false` |
| `Invoke-CcProgram -FilePath -Arguments` | Run an external program; return its output as text. Judge success by `$LASTEXITCODE` |
| `Backup-CcFile -Path` | Copy a file or folder to the backup folder and record the restore command |
| `Backup-CcRegistryKey -Key` | Export a registry key to a `.reg` file and record `reg import` |
| `Add-CcUndo -Description -Command` | Add a line to the undo log |
| `Test-CcProtected -Type -Value` | `$true` if on the protected list |
| `Test-CcAllowed -Type -Value` | `$true` if it is OK to change; logs REFUSED and returns `$false` if not |
| `Test-CcCommand NAME` | `$true` if a cmdlet or program exists |
| `Test-CcAdmin` / `Assert-CcAdmin` | Check for elevation; stop with exit 3 if not |
| `Get-CcOsInfo` | Hashtable: `Caption`, `Version`, `Build`, `ProductType`, `IsDC`, `IsServer`, `Is64Bit`, `PSVersion` |
| `Confirm-Cc QUESTION` | Ask the operator. `CCDC_ASSUME_YES=1` answers yes |
| `New-CcPassword [-Length]` | Return a random password. Never logs it |
| `Get-CcSha256 -Path` | A file's SHA-256 |
| `Move-CcQuarantine -Path` | Move a file to the quarantine folder, log its hash, record the undo |
| `New-CcCsv -Name -Header` / `Add-CcCsvRow -File -Values` | Create a CSV in the output folder; append a quoted row |
| `Add-CcFinding -Weakness -FixId -Class -Detail [-ProtectedDep]` | Write a finding |
| `Use-CcRunDir` | Inventory scripts: put this run's CSV files in one folder |
| `Save-CcOutput -Name -Command {}` | Keep a read-only block's untouched output in `raw\<Name>.txt`; an error is recorded in the file instead of stopping the script |
| `Add-CcFlag -Severity -Section -Item -Detail` | Record something unusual (`HIGH`, `MED`, `LOW`) |
| `Show-CcFlagReport [-Max]` / `Get-CcFlagReport` | Print, or return, the HIGH then MED flags and the counts |
| `ConvertTo-CcQuoted` / `Resolve-CcPath` | Quote for PowerShell; make a path absolute |
| `Test-CcSelf` | Check the running script against `MANIFEST.sha256` (called by `Initialize-Cc`) |
| `Complete-Cc [-ExitCode]` | Print the summary and exit |

### What to watch for

- **`Invoke-CcChange` returns a value.** If you don't use it, pipe it to `Out-Null`, or `True` appears in the script's output.
- **Run programs through `Invoke-CcProgram`.** Inside an action, do not call `netsh`, `reg.exe` or `sc.exe` with `2>&1` or `2>$null` after them. On Windows PowerShell that makes a program that prints a warning count as a failed step.
- **A program's failure is its exit code.** A program that prints an error and exits 0 counts as success. If a tool does that, check its output in the action and `throw`.
- **Use `-Secret` for any step that handles a password.** It keeps the block's output out of the log. The description is still logged, so do not put the password in the description.
- **The action runs in its own scope.** Assigning a variable inside `{ }` does not change the script's variable. Return the value from the block or use `$script:name`.
- **`-Undo` is a string that is run later, possibly by someone else.** Use full names and quoted paths; do not refer to variables that will not exist then.
- **`.Count` on one result.** PowerShell 2.0 gives nothing for `.Count` on a single object. Write `@(...).Count`.
- **Registry key names** for `Backup-CcRegistryKey` use the `reg.exe` form, `HKLM\SOFTWARE\...`. The `HKLM:\` form is converted for you.
- **The kit hash check does nothing yet,** for the same reason as in the shell library.

### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `running scripts is disabled on this system` | Execution policy | Start with `powershell -NoProfile -ExecutionPolicy Bypass -File ...` |
| `this script must run in an elevated ... window` (exit 3) | Not elevated | Right-click PowerShell, Run as administrator |
| `no protected list at ... - refusing to change anything` (exit 3) | Apply with no protected list | Create it, or pass `-Protected FILE`. In an emergency only, `-NoProtected` |
| `output folder ... is inside the kit folder` (exit 2) | `-Out` points into the script's folder | Pass `-Out` somewhere else |
| `KIT CHECK FAILED` (exit 3) | The script differs from the manifest | Re-copy the kit. If you edited it on purpose, rebuild, or set `$env:CCDC_SKIP_VERIFY='1'` |
| A red parser error naming `Mandatory`, `[ordered]` or an unknown cmdlet, on an old server only | A feature newer than PowerShell 2.0 got in | Run `sh tests/lint-ps2.sh` on the build machine; fix the line it names |
| `The term 'Get-...' is not recognized` | That cmdlet does not exist on this Windows version | Use the fallback (WMI, `netsh`, `net.exe`, `schtasks`). Check `$PSVersionTable.PSVersion` |
| `Cannot find an overload for "Contains"` or similar method errors | A .NET method that differs between versions | Note the PowerShell version and the line; that line needs a version-neutral form |
| A step shows FAILED although the program worked | The program was called directly with `2>&1` | Call it through `Invoke-CcProgram` |
| A step shows success although the program failed | The program exits 0 on error | Check its output in the action and `throw` |
| `could not read OS details from WMI` (warning) | The WMI service is stopped or broken | `Get-Service winmgmt`; start it. Scripts still run, with `ProductType` 0 |
| `quarantine FAILED ... file in use` | A running process holds the file | Stop the process first, then re-run |
| `Access is denied` writing the log | The output folder belongs to another user | Choose another `-Out` |
| Characters look wrong in the log | The file is UTF-8 without a marker and was opened in an old Notepad | Open it in another editor, or `Get-Content -Encoding UTF8` |

---

## 7. Script templates

`templates/script-template.sh` and `templates/script-template.ps1` are complete scripts that run. Each has the full header, the library loader, option parsing, one CSV output and the finish call.

```sh
sh templates/script-template.sh --out /tmp/ccdc-out --example hello --debug
```

Copy one to start a script; `docs/CONVENTIONS.md` lists the steps.

**Watch for**

- Keep the two marker lines `# >>> CCDC-LIB` and `# <<< CCDC-LIB` exactly as they are. The build step replaces everything between them.
- The loader walks up from the script's folder until it finds `lib/`. A script copied alone to a host, without `lib/`, stops with exit 3. Copy the whole repository for now; built single-file scripts come with the build step.
- Change `XX-00` in three places: the header, the `--help` text, and the `cc_init` / `Initialize-Cc` call.

## 8. Tests

```sh
sh tests/run-tests.sh          # everything
sh tests/run-tests.sh -v       # also show each test group
```

It runs, in order: the POSIX lint, the PowerShell 2.0 lint, a syntax check of every `.sh` file under every shell it finds, shellcheck if installed, every `tests/*.test.sh` under every shell, and every `tests/*.Tests.ps1` if PowerShell is installed. Exit 0 means everything passed.

| File | Checks |
| --- | --- |
| `tests/lint-posix.sh` | No bash-only or GNU-only constructs in `.sh` files |
| `tests/lint-ps2.sh` | No features newer than PowerShell 2.0 in `.ps1` files |
| `tests/lib.test.sh` | The shell library: options, dry run, protected list, backup and undo, quarantine, passwords, CSV, findings, kit check |
| `tests/lib.Tests.ps1` | The PowerShell library: the same list, plus program exit codes and `-Secret` |
| `tests/templates.test.sh` | The shell template runs and writes its files |
| `tests/sh03.test.sh` | The network scan: option checks, then both the python and nmap engines against two test listeners, including the scored-service and host-list checks |
| `tests/sh05.test.sh` | The Linux enum: options, every profile writes its files, nothing on the host changes, and (as root) a planted SUID binary is flagged HIGH |
| `tests/helper.sh` | The small test framework the `.test.sh` files use |

**Checking the Windows library on a real machine.** Copy the repository to a Windows test VM and run:

```
powershell -NoProfile -ExecutionPolicy Bypass -File tests\lib.Tests.ps1
```

Do this on the oldest and the newest Windows you expect to defend. It ends with `N passed, 0 failed`. A failure, or a red parser error before any test runs, means the library needs a fix for that version: note the PowerShell version (`$PSVersionTable.PSVersion`), the test name and the error text.

**Checking the shell library on BSD or Solaris.** Copy the repository and run `sh tests/lib.test.sh`.

**Watch for**

- The lints are pattern searches. They catch the common mistakes and nothing else.
- A test that passes under bash and fails under dash or ksh has found a real portability bug in the script.
- The tests create and delete a private folder under the temp directory and write nowhere else.

| Symptom | Cause | Fix |
| --- | --- | --- |
| `skip PowerShell tests` | No `pwsh` or `powershell` on the path | Install PowerShell, or `PWSH=/path/to/pwsh sh tests/run-tests.sh` |
| `skip shellcheck` | Not installed | Optional. `pip install shellcheck-py` or your package manager |
| A lint flags a line that is correct | The pattern cannot see the context | End the line with `# posix-ok` or `# ps2-ok`, and say why in a comment |
| One shell fails, the others pass | A construct that shell handles differently | Re-run that one: `TEST_SHELL=ksh ksh tests/lib.test.sh` |
| Tests fail with `Permission denied` under the temp directory | The temp directory is mounted `noexec` or is full | `TMPDIR=/some/other/dir sh tests/run-tests.sh` |

## 9. Problems that apply to everything

| Symptom | Cause | Fix |
| --- | --- | --- |
| A script worked in practice and fails at the event | A different OS version, a missing tool, or a red team change to the host | Run with `--debug` / `-DebugLog`. The first lines of the log name the host, mode and library version |
| Output disappears after a reboot | The output folder was under a temp directory | Use a persistent `--out`, and copy it off the host |
| Two people ran scripts on one host and the undo log is confusing | Both wrote to the same undo log, which is intended | Each line has the script ID and time; undo newest first |
| The clock on a host is wrong | Log times come from the host's clock, in UTC | Note the offset. The time sync check (AU-18) will report this once built |
| Git shows every line of a `.sh` file as changed | Line endings were converted | `.gitattributes` forces LF for `.sh`. Run `git add --renormalize .` |
| A script printed a password | A script passed a secret to `cc_log`, `cc_run` or a description | Treat that password as exposed and rotate it. Fix the script to use `cc_run_quiet` / `-Secret` |

---

## 10. Linux enum, `roles/linux/SH-05-linux-enum.sh` (SH-05)

Read-only inventory of one Linux or Unix host. Run it first on every Linux box: it shows who can log in, what is listening, what starts on boot or on a schedule, who can become root, what is running, and the usual hiding places. It changes nothing.

### How to run it

```sh
sudo sh SH-05-linux-enum.sh --out /root/ccdc-out              # full, about a minute
sudo sh SH-05-linux-enum.sh --out /root/ccdc-out --profile card   # quick look, seconds
sudo sh SH-05-linux-enum.sh --out /root/ccdc-out --profile triage # full plus a copy of the logs
sudo sh SH-05-linux-enum.sh --out /root/ccdc-out --only ports,processes
```

Run it as root. As a normal user it still works, but the summary marks several sections `partial`.

| Option | What it does |
| --- | --- |
| `--profile card` | system, users, ports, services, autostart, ssh, sudo, privesc. Use it in the first minutes |
| `--profile full` (default) | card plus processes, connections, sessions, packages, files, firewall, pam, mac, trust, creds, containers, modules |
| `--profile triage` | full plus copying the logs. Use it when you think the box is compromised, before anything else changes |
| `--only a,b` / `--skip a,b` | Pick sections. `--list` shows the names |
| `--fast` | Skip the two slow disk searches (files, creds) |
| `--max-flags N` | How many HIGH/MED flags to print in the end summary (default 30) |
| `--low` | Also show LOW flags while it runs |
| `--no-color` | No colours (they are also off when output goes to a file or pipe) |

While it runs it prints like linpeas: a header per section, then what it found. **Red `[!] FIX`** = HIGH, fix now. **Yellow `[*] LOOK`** = MED, look soon. Green = key facts. `[ok]` = nothing to fix in that section. The summary comes at the end.

### What it produces

Each run gets a numbered folder: `<out>/linux-enum-1`, `linux-enum-2`, ... Higher number = newer run.

| File | Contents |
| --- | --- |
| `output.txt` | Everything shown while it ran, without colours |
| `<section>.txt` | Each section as a readable table (`users.txt`, `ports.txt`, ...) |
| `flags.txt` | Every flag including LOW, HIGH first |
| `csv/` | The same data as CSV, for SH-04 |
| `summary.txt` | The end summary: key facts, a row per section, the HIGH and MED flags |
| `run.txt` | Script ID, host and start time (SH-04 uses it) |
| `privesc.txt` | Ways to become root, like linpeas checks: files root runs (cron, services, start-up) that others can change, writable key files (`/etc/passwd`, sudoers, root's files), a readable shadow file, risky PATH folders or `.` on the PATH, sudo rules for shell-escape programs (vim, less, find ...) or keeping LD_PRELOAD, and old sudo, pkexec or kernel versions with known root bugs (Baron Samedit, PwnKit, Dirty COW, Dirty Pipe) unless the package changelog shows the fix |

The tables below are named by their CSV file; each one is also a readable `.txt` in the run folder.

| File | Contents |
| --- | --- |
| `facts.csv`, `addresses.csv` | Host name, OS, kernel, init system, uptime, IPv6 on or off, addresses, DNS |
| `users.csv` | Every account: UID, shell, whether it can log in, password state (`set`, `EMPTY`, `locked`; never the hash), groups |
| `ports.csv` | Listening ports: protocol, address, port, `any` or `local`, pid, process, user, program file |
| `services.csv` | Services with enabled and running state |
| `autostart.csv` | cron, at, timers, rc.local, and suspicious lines from startup files, motd scripts and udev rules |
| `ssh_config.csv`, `ssh_keys.csv` | Effective sshd settings; every authorized key with its account, file, fingerprint and options |
| `sudo.csv` | sudoers, doas and polkit rules |
| `processes.csv`, `connections.csv`, `sessions.csv` | Every process with its program file; live connections; who is logged in |
| `packages.csv` | Installed packages and versions |
| `suid.csv`, `capabilities.csv`, `world_writable.csv`, `immutable.csv` | Risky file permissions |
| `firewall.csv`, `pam.csv`, `mac.csv`, `trust.csv`, `modules.csv`, `containers.csv` | One per section |
| `creds.csv`, `private_keys.csv`, `history.csv` | Files holding password-like settings (file, line and setting name only), private key files, shell history sizes |
| `raw/*.txt` | Untouched tool output: `iptables-save`, `sshd -T`, `ss`, `last` and others |
| `logs/` | Triage only: copies of auth, syslog, web and audit logs, with SHA-256 in `logs.csv` |

### Reading the summary

The screen shows one page. The section table tells you where to look:

```
section        rows  high   med   low  note
users            31     1     0     2
ports             9     1     1     0  partial: process shown only for your own sockets
```

- **rows** is how much was collected.
- **high / med / low** are the flags from that section.
- **note** says when a section is incomplete and why.

Only HIGH and MED flags are printed. LOW flags are in `flags.csv`.

| Severity | Meaning | Examples |
| --- | --- | --- |
| HIGH | Likely red team activity or an open door. Look now | Second UID-0 account, empty password, shell listening on a port, process running from a deleted file, reverse-shell cron job, SUID `find`, keys on a service account, locked `/etc/passwd`, changed `pam_unix.so` |
| MED | Risky or unusual. Look soon | Passwordless sudo, root accepts SSH keys, backdoor-style port number, no host firewall, IPv6 unfiltered |
| LOW | Worth knowing. Not shown | Extra hosts-file entries, `nullok`, locally created service files |

### What to watch for

- **A flag is a pointer, not a verdict.** Some flags are legitimate on your box. In testing, this sandbox's own launcher was flagged HIGH because it decodes a base64 payload, which is exactly what a malicious one does. Look, then decide.
- **Run it again after you change things.** Two runs compared side by side show what changed. The scan diff and change watch will automate this later.
- **It sees what the operating system reports.** A kernel rootkit can hide processes, files and ports from every tool it uses.
- **Accounts come from `/etc/passwd`.** LDAP or FreeIPA users are not listed.
- **Passwords are never recorded.** `users.csv` shows only whether a password is set; `creds.csv` shows only the file, line and setting name.
- **Triage copies logs into the output folder.** Copy that folder off the host; a red team that owns the box can delete it.
- **Time.** About a minute for `full` on a normal server. The files and creds sections walk the disk and take most of that. Use `--fast` or `card` under time pressure.

### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| Summary says `root: NO - partial` | Not run as root | `sudo sh ...`, and pass `--out` because `~` changes under sudo |
| `ports` note: `process unknown` | `/proc/<pid>/fd` is unreadable, even for root, in some containers | Expected there; the port list itself is complete |
| `ports` note: `no ss, netstat, sockstat or /proc/net` | Not Linux and no tools (for example Solaris) | Read `raw/netstat_an.txt` |
| `Addresses: none found` | No `ip` or `ifconfig`, and no `/proc/net/fib_trie` | Run `ip addr` or `ifconfig` by hand if either exists |
| `ssh` note: `no sshd configuration found` | SSH server not installed | Nothing to fix |
| A sudo, cron or ssh setting you know is there is missing | Not root, so the file was unreadable | Rerun as root; check the section note |
| `docker ... 'docker ps' failed` | Docker daemon stopped, or the user is not in the docker group | Rerun as root; `systemctl status docker` |
| `firewall` says NOT-filtered but you set rules | Rules exist in a tool the enum does not read, or need root | Check `raw/` for the tool's output; run as root |
| A flag looks wrong | The check is too broad for your box | Check `raw/` to see what the tool printed. Report the flag line so the check can be tightened |
| It runs for many minutes | A very large disk or network home folders | `--fast`, or `--skip files,creds` |
| `cannot find lib/lib.sh` (exit 3) | The script was copied without the `lib/` folder | Copy the whole kit, or use the built single-file version once the build step exists |
| `$'\r': command not found` | The file got Windows line endings in transit | `tr -d '\r' < SH-05-linux-enum.sh > fixed.sh` |

---

## 11. Network scan, `roles/network/SH-03-network-scan.sh` (SH-03)

Finds live hosts and open ports, what runs on them, and what looks vulnerable. Run it from the admin workstation. It sends probes and changes nothing on any host.

### How to run it

```sh
sh SH-03-network-scan.sh                                        # asks everything
sh SH-03-network-scan.sh --target 10.0.2.0/24 --batch            # all defaults, no questions
sudo sh SH-03-network-scan.sh --target 10.0.2.0/24 --vuln --udp --hosts config/hosts.csv
sh SH-03-network-scan.sh --targets-file subnets.txt --profile outside --hosts hosts.csv   # from outside the firewall
```

It asks like sqlmap (Enter takes the default, a flag answers in advance):

| Question | Default | Flag |
| --- | --- | --- |
| What to scan (IP, range, subnet; several with spaces) | your own network | `--target` |
| Quick scan, top 1000 ports | yes | `--quick` / `--no-quick` |
| Full scan, all 65535 ports, on the hosts that are up | yes | `--full` / `--no-full` |
| Service and version on each open port | yes | `--services` / `--no-services` |
| nmap default scripts (anonymous FTP, SMB signing, ...) | yes | `--scripts` / `--no-scripts` |
| nmap vuln scripts (only ones nmap marks safe) | no | `--vuln` / `--no-vuln` |
| OS guess (root) | yes | `--os` / `--no-os` |
| Top 25 UDP ports (root) | no | `--udp` / `--no-udp` |

Then it runs nmap in stages and shows nmap's own output as it goes: quick scan, full scan, details (versions, scripts, OS) on just the open ports, then UDP. Open ports are green, `VULNERABLE` red.

| Option | What it does |
| --- | --- |
| `--hosts` | The host list. Turns on the scored-service and unknown-host checks |
| `--profile fast` | Preset: quick scan + versions, no questions |
| `--profile full` | Preset: quick + full + versions (+ OS as root) |
| `--profile udp` | Preset: UDP only. Needs root |
| `--profile outside` | Like fast, but also scans hosts that drop ping. Run it from outside to see what the red team sees |
| `--ports` | Only these ports, e.g. `22,80,8000-8100` (replaces the quick and full scans) |
| `--engine` | Force `nmap`, `python`, `bash` or `nc` |
| `--no-dns` / `--pn` | Skip name lookups / treat every address as up |

**Without nmap** it falls back to python3, then bash, then `nc -z`: 53 common TCP ports, a banner instead of a version, no scripts, no UDP, at most 1024 addresses.

### What it produces

In `<out>/netscan-N/` (next free number):

| File | Contents |
| --- | --- |
| `output.txt` | Everything shown on screen, no colour |
| `summary.txt` | Counts, open ports per host, vulns, scored services, HIGH and MED flags |
| `hosts.txt`, `ports.txt` | Live hosts; every open port with service and version |
| `vulns.txt` | What the scripts found: `VULNERABLE` results, known CVEs for a version (with the worst score), anonymous FTP, empty database passwords, SMB signing off, PUT/DELETE allowed |
| `flags.txt` | Every flag, HIGH first |
| `scored.txt` | With `--hosts`: each scored service and whether it answered |
| `csv/` | The same tables as CSV (SH-04 reads these) |
| `raw/` | nmap's own output per stage (`1-quick`, `2-full`, `3-details`, `4-udp`) |

### What it flags

| Severity | When |
| --- | --- |
| HIGH | A script says `VULNERABLE`. A version with a known CVE scored 9 or more. Anonymous FTP, an empty database password. A port that answers like a shell. A scored service that does not answer. Docker API on 2375. vsftpd 2.3.4, ProFTPD 1.3.3c/1.3.5, UnrealIRCd, Samba 3.0.20-3.0.25, distccd, Windows XP/2003 |
| MED | `LIKELY VULNERABLE`, CVE score 7 or more, PUT/DELETE allowed. A host up but not on the host list, or on it but silent. Telnet, rsh, TFTP, SNMP, VNC, Redis, MongoDB, Elasticsearch, memcached. Backdoor-style ports such as 4444 and 31337. With `outside`: Windows admin ports, and anything that is not a scored service |
| LOW | Databases reachable over the network, FTP, SMB signing off, lower CVE scores |

### What to watch for

- **The full scan is slow**: minutes per host. nmap prints progress every minute. Say no to it for a first look, then run it.
- **Vuln scripts only point.** Nothing found does not mean safe; a hit means check that service now. Only "safe" ones run, so they will not knock a scored service over.
- **"Not reachable" means not reachable from where you ran it.** A firewall may block your workstation but allow the scoring engine. Check from the scoring side before changing anything.
- **Run it again later and compare** with the scan diff (SH-04). New ports and new vulns are flagged.
- **Scans are visible** in IDS and firewall logs. Fine on your own network.

### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `nothing to scan` (exit 2) | No target and no terminal to ask | Add `--target` |
| `has N addresses; the python engine is limited to 1024` | Range too big without nmap | Install nmap, scan smaller pieces, or raise `--max-hosts` |
| `UDP scanning needs root` / OS skipped | Raw packets need root | `sudo` |
| `nmap produced no results` | A target nmap cannot parse, or no permission | Read `output.txt` |
| Hosts you know are up are missing | They drop ping and no top-1000 port answered | `--pn`, or `--profile outside` |
| Service ends in `?` or is `unknown` | nmap was unsure | Check `raw/3-details.nmap`; the fingerprint is there |
| Every scored service fails | Wrong addresses in the host list, or your workstation is firewalled off | Check `config/hosts.csv`; scan from another machine |

---

## 12. Scan diff, `roles/network/SH-04-scan-diff.sh` (SH-04)

Answers "what changed since last time?" by comparing two earlier runs of the network scan (SH-03) or two runs of the Linux enum (SH-05) on the same host. It only reads their CSV files; it touches no host and needs no root.

The point: run SH-03 and SH-05 in the first minutes as a baseline, run them again later, and diff. Anything **added** is where to look for red team persistence.

### How to run it

```sh
sh SH-04-scan-diff.sh --out ~/ccdc-out                        # the newest two network scans
sh SH-04-scan-diff.sh --out /root/ccdc-out --type sh05        # the newest two enum runs of the newest run's host
sh SH-04-scan-diff.sh --out /root/ccdc-out --type sh05 --host web01
sh SH-04-scan-diff.sh --old ~/ccdc-out/netscan-1 --new ~/ccdc-out/netscan-2
```

| Option | What it does |
| --- | --- |
| `--old` / `--new` | The two run folders to compare. Give both or neither. The type comes from the folder names |
| `--type sh03` (default) / `sh05` | Which runs to pick when no folders are given |
| `--host` | With `--type sh05`: whose runs. Default: the host of the newest SH-05 run |
| `--runs` | Where the run folders are, if not in the `--out` folder (e.g. enum results copied off each box into one folder) |
| `--max-lines` | Changes listed on screen (default 40; every change is in `changes.csv`) |
| `--max-flags` | HIGH and MED flags shown on screen (default 30) |

**Which runs it picks.** Run folders are named `<ID>_<host>_<UTC time>`, so the newest two by time are compared. Folders without `summary.txt` are skipped: those are runs that were stopped part way and would look like everything was removed.

### What it compares

| Run type | Section | A row is the same thing when these match | Compared for "changed" |
| --- | --- | --- | --- |
| SH-03 | hosts | address | name |
| SH-03 | ports | address, protocol, port | service, version |
| SH-03 | scored | host, address, service, port | reachable |
| SH-03 | vulns | address, protocol, port, script | state, title |
| SH-05 | users | user | UID, shell, can log in, password state, groups |
| SH-05 | ports | protocol, address, port | process, program |
| SH-05 | services | name | enabled, active |
| SH-05 | autostart | source, user, entry | |
| SH-05 | ssh_keys | user, file, fingerprint | type, comment, options |
| SH-05 | sudo, pam | file, entry | |
| SH-05 | suid | path | mode, owner |
| SH-05 | capabilities | path | capabilities |
| SH-05 | immutable | path | attributes |
| SH-05 | firewall | tool | status, detail |

Processes and connections are not compared: they change every second. Line numbers and PIDs are left out of the comparison on purpose, so editing a file above a sudo rule or restarting sshd does not show as a change.

### What it produces

In a numbered folder: `<out>/diff-1`, `diff-2`, ...

| File | Contents |
| --- | --- |
| `summary.txt` | Per-section counts of added, removed and changed; the changes (added first); the HIGH and MED flags |
| `changes.txt` | Every difference as a readable table, additions first |
| `flags.txt` | Every flag, HIGH first |
| `csv/` | The same as CSV (`changes.csv`, `flags.csv`) |

### What it flags

| Severity | When |
| --- | --- |
| HIGH | SH-03: a scored service that answered before and does not now; a new vuln or script finding; a backdoor-style port (4444, 31337, 1337, 2375 and others) newly open. SH-05: a new account, cron or startup entry, SSH key, sudo rule, SUID program, file capability or PAM line; a backdoor-style port newly listening |
| MED | SH-03: a host appeared or vanished; a port opened or closed. SH-05: an account changed or removed; a listening port added, removed or taken over by another program; a new service; a file newly locked with `chattr`; a PAM line removed; the firewall state changed |
| LOW | SH-03: a service version changed; a scored-service check added. SH-05: a service started, stopped, enabled or disabled |

Each change gets one flag: a backdoor port that is HIGH is not also listed as MED.

### What to watch for

- **Changes you made show up too.** Removing a user, closing a port or adding a firewall rule appear as changes. Compare against what the team did (the undo log and the changelog in your notes) before chasing them.
- **Compare like with like.** Two enum runs should use the same profile. A section that is in only one run is reported as `skipped (not in both runs)`, not as everything removed. The summary warns when one enum run was as root and the other was not, because a root run sees more.
- **"Removed" on a scored port is an outage.** A port that closed between two scans of a scored host needs checking right away.
- **Take a fresh baseline after you clean up.** Otherwise every later diff repeats your own changes. Keep the old runs; the diff only reads them.
- **The newest two may not be the two you want.** If a run was made from a different machine or with different targets, give `--old` and `--new` yourself.

### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `need two finished SH-03 runs ... found 1` (exit 3) | Only one finished run in the folder, or the runs are elsewhere | Run the scan again, point `--runs` at the folder, or give `--old` and `--new` |
| `... is not an SH-03 or SH-05 run folder` (exit 2) | The folder was renamed, or you gave the parent folder | Give the run folder itself; its name must start with `SH-03_`, `SH-05_` or `linux-enum-`. To see what a fix script changed, run the enum again and compare the two enum folders |
| `the two folders are from different scripts` (exit 2) | One SH-03 run and one SH-05 run | Compare runs of the same script |
| `comparing two different hosts` warning | `--old`/`--new` point at enum runs of two machines | Usually a mistake; pick two runs of one host |
| Everything in a section shows as added | The earlier run had that section empty (e.g. not root, or a different profile) | Rerun both the same way; check the warning about root |
| Lots of port changes between scans | Different targets or engines (the fallbacks check 53 ports, nmap 1000) | Scan the same targets with the same engine and profile |
| A changed item looks wrong | The comparison is by the columns in the table above | Look up the key in both runs' CSV files; `changes.csv` has the old and new values |

---

## 13. Web and database enum, `roles/applications/SV-01-web-db-enum.sh` (SV-01)

Shows what web sites and databases are on a Linux or Unix host and what is wrong with them. Run it on every box that serves a web site or holds a database, right after the Linux enum. It only reads; it never records a password.

### How to run it

```sh
sudo sh SV-01-web-db-enum.sh --out /root/ccdc-out
sudo sh SV-01-web-db-enum.sh --out /root/ccdc-out --fast                 # skip the web shell content search
sudo sh SV-01-web-db-enum.sh --webroot /opt/app/public                   # a web root the configs don't show
sudo sh SV-01-web-db-enum.sh --only mysql --mysql-cnf /root/my.cnf       # when root can't log in through the socket
```

| Option | What it does |
| --- | --- |
| `--only` / `--skip` | Run or leave out sections: `servers sites webroots php apps mysql postgres datastores` |
| `--fast` | Skip reading file contents (the web shell and phpinfo search). Names, owners and settings are still checked |
| `--webroot DIR` | Also scan this folder as a web root. Repeat for more |
| `--apache-conf FILE` / `--nginx-conf FILE` | Read these config files directly instead of asking the server which files it uses. For when `apachectl` or `nginx` is missing, broken or replaced |
| `--mysql-cnf FILE` | A MySQL client file with a user and password (a `[client]` section). Make it mode 600 and delete it after |

Run it as root. As a normal user it still runs, but it cannot read most configs, log in to PostgreSQL, or see every file; the section table marks those sections `partial`.

**How it logs in to the databases.** MySQL/MariaDB: `--mysql-cnf` if given, then `root` through the local socket (normal on Debian and Ubuntu), then the Debian maintenance account in `/etc/mysql/debian.cnf`, then the client's own defaults. PostgreSQL: as the `postgres` account through the local socket. Queries are SELECT and SHOW only.

### What it produces

In `<out>/SV-01_<host>_<UTC time>/`:

| File | Contents |
| --- | --- |
| `summary.txt` | Web servers, sites, web roots, apps, databases; a section table; HIGH and MED flags |
| `servers.csv`, `fpm_pools.csv` | Each web server and PHP-FPM pool: version, running or not, the account it runs as |
| `sites.csv` | Each Apache virtual host and nginx server block: name, listen address, TLS, web root, config file and line |
| `webroots.csv` | Each web root: owner, mode, file counts, files owned by the web account, world-writable files |
| `files.csv` | Every file that should not be in a web root, with its kind (`webshell`, `upload_code`, `dump`, `env`, `vcs`, `phpinfo`, `config_readable`, `backup`) |
| `php.csv` | The risky settings of each `php.ini`, after its `conf.d` overrides |
| `apps.csv` | Each web app found: version, folder, config file, database name, user and host (never the password) |
| `db_users.csv` | MySQL and PostgreSQL accounts: how they log in, empty password, superuser, file access, grant rights |
| `db_settings.csv`, `db_databases.csv`, `db_objects.csv` | Server settings; databases with size; triggers, events, routines and user-defined functions |
| `pg_hba.csv` | PostgreSQL login rules |
| `datastores.csv` | Redis, memcached, MongoDB, Elasticsearch and CouchDB: where they listen and whether they answer without a password |

### What it flags

| Severity | When |
| --- | --- |
| HIGH | A file that looks like a web shell; a program file in an upload or media folder; a database dump or `.env` inside a web root; a web server or PHP-FPM pool running entirely as root; `allow_url_include` on; a database account with no password; MySQL root or an admin account allowed from other hosts; a user-defined function (the `lib_mysqludf_sys` backdoor); a PostgreSQL `trust` rule for network logins; logging in to MySQL with no name or password; a Redis or similar store open to the network without a password |
| MED | Directory listing on; a web root owned by the web account; world-writable files in a web root; `.git` folders, backups and phpinfo pages in a web root; app configs every local account can read; MySQL `secure_file_priv` empty; accounts with the FILE privilege; anonymous MySQL accounts; triggers and scheduled events; extra PostgreSQL superusers; `trust` for local logins; a database or data store listening on a network address |
| LOW | Server version shown in headers; PHP `display_errors`, `expose_php` on, `disable_functions` empty; MySQL `local_infile` on; accounts allowed from any address; PostgreSQL `password` (clear text) logins |

### What to watch for

- **Read before you delete.** A web shell flag means the file matched a known pattern. Read it, copy it for the incident report, then quarantine it. A security plugin's signature list can also match.
- **"Owned by the web account" is common and still worth fixing.** Many WordPress installs are owned by `www-data` so plugins can update. It is also how one flaw becomes a defaced site. Changing owners can break uploads and updates, so it is a fix for later, not the first 15 minutes.
- **Database accounts the apps use are listed in `apps.csv`.** Before changing a database password, find which app uses that account and update its config at the same time, or the site goes down.
- **Triggers, events and user-defined functions are rare in competition apps.** One that the app did not create is a strong sign of red team persistence.
- **Some checks need tools.** Without a MySQL client or `psql` the database accounts are not listed; without `redis-cli` or `curl` the "answers without a password" column says `not checked`.

### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `MySQL/MariaDB: found, but could not log in` | root needs a password and there is no `debian.cnf` | Give `--mysql-cnf` with a working user and password |
| `accounts not readable with default client settings` | Logged in with an account that cannot read `mysql.user`, usually as a normal user | Run as root |
| `PostgreSQL: found, but could not log in` | Not root, or the `postgres` account cannot log in through the socket | Run as root; check `pg_hba.conf` has a `local ... peer` line for postgres |
| A site is missing from `sites.csv` | Its config is in a file Apache or nginx loads in an unusual way | Compare with `raw/apache_S.txt` or `raw/nginx_T.txt`; add its folder with `--webroot` |
| The run is slow on a large site | The content search reads every PHP file under 2 MB | `--fast`, or `--skip webroots` and run that section on its own later |
| `sites.csv` empty, but a web server is running | `apachectl` or `nginx` missing or not in PATH | Point at the configs with `--apache-conf` / `--nginx-conf` |

---

## 14. Backup, `roles/linux/LX-31-backup.sh` (LX-31)

Run first, before any script that changes the box. One archive of the files that decide how the box behaves, a hash of every one of them, and a snapshot of the state that is not in files. If a fix breaks a scored service, you put back the one file that broke. If the red team changes something, the hash list proves which file.

### How to run it

Just run it. It asks questions like sqlmap: Enter takes the default.

```sh
sudo sh LX-31-backup.sh                                   # asks, then backs up
sudo sh LX-31-backup.sh --batch                           # no questions, the defaults
sudo sh LX-31-backup.sh --box splunk --copy-to admin@10.0.0.5:/srv/backups/splunk/
```

The questions:

1. **Which box?** splunk / webmail / ecomm / other. It offers that box's important folders, for example Splunk's `/opt/splunk/etc` (config, users, apps) or the mail folders on webmail. For ecomm it reminds you to run SV-14 for the database.
2. **Web roots?** It lists the ones it found, with sizes.
3. **Home-folder dotfiles and SSH keys?**
4. **Hash system programs?** Takes 10 to 60 seconds, and later shows which programs were replaced.
5. **Other files or folders to back up?** Type a comma list.
6. **Anything to leave out?** Type a comma list of paths. A folder that contains one is backed up without it.
7. **Copy it off the box?** Type `user@host:/path/`, or press Enter for no.

Then each step prints as a section: what will be backed up (each path with its size), the archive, the hash lists, the system state, the copy. If the backup is bigger than `--max-mb`, it asks before going on.

| Option | What it does |
| --- | --- |
| `--add PATH` | Also back up a file or folder (repeat). Use it for scored content outside the usual places, such as `/opt/app` |
| `--skip PATH` | Leave a file or folder out (repeat) |
| `--box NAME` | splunk, webmail, ecomm or other: answers that question |
| `--batch` | Never ask: take every default |
| `--no-color` | No colours |
| `--webroot DIR` | Back up DIR as a web root (repeat). The usual web roots and those named in the Apache and nginx configs are included already |
| `--no-webroots` | Leave web roots out, when they are huge |
| `--no-homes` | Leave out home-folder dotfiles and `.ssh` folders |
| `--fast` | Skip hashing system programs and service units (saves 10 to 60 seconds) |
| `--max-mb N` | Ask before a backup bigger than N MB (default 2048). With no one to ask, it stops |
| `--copy-to DEST` | Copy the archive and hash lists off the box with `scp` when done. Asks for a password if no key is set up |

It changes nothing on the host, so it runs without `--apply` and needs no protected list. Run it as root; as a normal user it warns and backs up what it can read.

### What goes in

| Kind | Paths |
| --- | --- |
| config | `/etc`, `/usr/local/etc`, cron and at spools, BIND zone folders, `/root/.ssh` |
| home | Top-level dotfiles of root and every account (shell startup files), and every `.ssh` folder |
| webroot | `/var/www`, `/srv/www`, `/srv/http`, `/usr/share/nginx/html` and the others in the usual places, plus every `DocumentRoot`, `root` and `alias` folder in the Apache and nginx configs |
| added | Anything given with `--add`, typed into the question, or the box's folders you said yes to |

Paths that do not exist are skipped, so the same command works on any distribution.

Not included: databases (use SV-14, which dumps them safely while they run) and whole home folders.

### What it produces

In a numbered folder: `<out>/backup-1`, `backup-2`, ...

| File | Contents |
| --- | --- |
| `output.txt` | Everything shown on screen, without colours |
| `included.txt` | Every path asked for, its size, and whether it was read fully (CSV copy in `csv/`) |
| `backup.tar.gz` | The archive. Paths inside are relative to `/` (`etc/passwd`). Mode 600 |
| `backup.tar.gz.sha256` | Hash of the archive, to check a copy is intact |
| `files.sha256` | SHA-256 of every file in the archive |
| `system.sha256` | SHA-256 of programs in `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/usr/local/*bin`, `/usr/libexec` and of systemd unit files (hashed, not archived) |
| `contents.txt` | The archive's file list |
| `raw/` | Firewall rules (iptables, nftables, ufw, firewalld, pf), services and timers, listening ports, packages, addresses, routes, kernel settings, mounts, accounts, root's crontab |
| `RESTORE.txt` | The restore commands for this backup |
| `summary.txt` | What was saved and how big |

### Restoring

```sh
cd /root/ccdc-out/backup-3
sha256sum -c backup.tar.gz.sha256                                  # the archive is intact
tar -tzf backup.tar.gz | grep sshd_config                         # find a file
cp -p /etc/ssh/sshd_config /etc/ssh/sshd_config.before-restore
tar -xzf backup.tar.gz -C / etc/ssh/sshd_config                   # put ONE file back
sha256sum -c files.sha256 2>/dev/null | grep -v ': OK$'           # what changed since the backup
sha256sum -c system.sha256 2>/dev/null | grep -v ': OK$'          # programs replaced since the backup
iptables-restore < raw/firewall_iptables.txt                       # firewall rules as they were
```

Unpack into a scratch folder (`-C /tmp/restore`) to compare with `diff -r` before putting anything back.

### What to watch for

- **The archive holds `/etc/shadow`, SSH host keys and passwords in config files.** Keep the output folder private and copy it only to the team's own machine.
- **Copy it off the box.** A red team with root can delete a backup kept on the same host. Use `--copy-to`, or pull it from the admin workstation with the `scp` line in the summary.
- **Never restore all of `/etc` at once.** That also rolls back every password change and fix made since. Put back only what broke.
- **Run it again after you have hardened the box.** That backup is the known-good state, and its hash lists are the better baseline for the change watch.
- **A changed program in `system.sha256` is serious.** Package updates also change programs, so check the package manager's log before calling it a rootkit.

### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `the backup would be about N MB, more than --max-mb` (exit 3) | Big web roots or a big `/etc`, and you answered no (or no one could be asked) | Look at the sizes it listed; leave big paths out (the question or `--skip`), `--no-webroots`, or a larger `--max-mb` |
| `not enough free space` (exit 3) | The output folder's disk is nearly full | `--out` on another disk or a USB stick |
| `tar exited 1` or `2` warning | A file changed or could not be read while archiving | Harmless when the summary shows entries; check the log for the file names |
| `the archive could not be read back` (exit 5) | Disk full or tar failed | Check the log; free space and run again |
| `COPY FAILED` (exit 5) | Wrong destination, no route, or the password was refused | Test with `scp somefile DEST` by hand; the backup is still on the box |
| `partial (some files unreadable)` in `included.txt` | Not root, or files the account cannot read | Run as root |

---

## 15. Linux safe fixes, `roles/linux/LX-39-safe-fixes.sh` (LX-39)

Hardening that cannot break a scored service, so it can run on every Linux box in the first minutes without study. It only removes risky settings and permissions; it never changes an owner, never deletes a file, and never touches a service that serves anything.

Run the backup (LX-31) first.

### How to run it

Just run it. It asks questions like sqlmap: Enter takes the default (the capital letter).

```sh
sudo sh LX-39-safe-fixes.sh                        # asks everything, then asks before applying
sudo sh LX-39-safe-fixes.sh --apply --batch        # no questions: defaults, apply, keep
sudo sh LX-39-safe-fixes.sh --batch                # no questions, dry run only
sudo sh LX-39-safe-fixes.sh --apply --skip ipv6    # flags answer questions in advance
```

What a run looks like:

1. **Revert timer starts: 2 minutes.** If you don't keep the changes before it runs out (for example because you got kicked off), everything this run changed is put back. It runs outside the script (a systemd timer, or a detached job), so a dead SSH session doesn't stop it.
2. **Questions:** which box this is (splunk / webmail / ecomm / other), then one per fix. For fixes that act on accounts or SUID files it first lists what it found. After a yes, a fix that acts on named items asks **"Leave any alone?"**: type a comma list (account names, paths, settings, services) or press Enter for none. The time left is shown.
3. **Plan:** a dry run shows every change (yellow `[~]`), then asks `Apply these N change(s)?`
4. **Applying:** each change shown as it's made (green `[+]`, red `[x]` if it failed).
5. **Keep or revert:** open a **new** SSH or console session and log in. Then `y` keeps the changes; `n`, or no answer before the timer, undoes them.

With no terminal (run remotely) and no `--batch`, it says how to keep the changes from another session: `touch <run folder>/KEEP`.

| Option | What it does |
| --- | --- |
| `--box NAME` | splunk, webmail, ecomm or other: answers the box question |
| `--exclude a,b` | Items no fix may touch: paths (`/etc/crontab`), account names (`bob`), kernel settings (`net.ipv4.tcp_syncookies`), services (`auditd`). Answers every "leave any alone?" question |
| `--timer SECONDS` | Revert timer length (default 120) |
| `--no-timer` | No revert timer (you accept the risk) |
| `--batch` | Never ask: take every default. With `--apply`, the changes are kept |
| `--no-color` | No colours |
| `--only` / `--skip` | Run or leave out fixes by name (see `--list`) |
| `--keep-ipv6` | Leave IPv6 on |
| `--no-forwarding` | Also turn IP forwarding off. Routers, firewalls and Docker hosts need it on |
| `--root DIR` | Treat DIR as `/` for the file fixes, for fixing a mounted disk image. Kernel settings and services still act on the running system |

Without a protected list it asks whether to go on (`--no-protected` answers yes). A path on the protected list is skipped.

### The fixes

| Fix | What it does | Why it is safe |
| --- | --- | --- |
| `sysctl` | SYN cookies on; full address-space randomization; no unprivileged BPF; protected FIFOs and regular files in sticky folders; RFC 1337 TIME-WAIT protection; source-routed packets and ICMP redirects refused and not sent; odd-source packets logged; symlink and hardlink protection; kernel pointers and kernel log hidden from normal accounts | None of these change what a service listens on or answers |
| `ipv6` | IPv6 off on every interface except loopback (`lo` is switched back on after `all` is switched off, so `::1` stays), with the kernel setting `disable_ipv6`, written for boot too. Only tried against a stand-in so far: after the first real run check `ip -6 addr show lo` | Services listening on `[::]` keep working for IPv4. NOT the `ipv6.disable=1` boot option, which stops such services from starting at all. Services bound to one specific IPv6 address are listed first under "check by hand" |
| `forwarding` | IP forwarding off. It asks first whether the box routes traffic or runs Docker. With no one to ask, only with `--no-forwarding` | Routers, firewalls and Docker need forwarding |
| `coredumps` | No core dumps from setuid programs; core size limit 0 for every account | A core dump of a login program can hold password hashes |
| `perms` | Removes group and other write (and other read on secrets) from `/etc/passwd`, `/etc/group`, `/etc/shadow`, `/etc/gshadow`, sudo files, SSH host keys and `sshd_config`, `/root`, cron files, shell startup files, `ld.so` config, PAM and systemd unit folders; removes world-write from anything in `/etc`, program folders and home folders | Only bits are removed. Owners and groups stay, so `shadow` stays readable by the `shadow` group on Debian and by `ssh_keys` on Red Hat |
| `tmp` | Sticky bit on `/tmp`, `/var/tmp`, `/dev/shm` | Normal on every distribution |
| `logging` | Starts and enables rsyslog, syslog-ng and auditd if they are installed but stopped | Logging is never scored against you |
| `preload` | If `/etc/ld.so.preload` loads a library no package owns, the file is moved to quarantine. `LD_PRELOAD` and `LD_LIBRARY_PATH` lines in `/etc/environment` are commented out | That file is the classic user-mode rootkit hook. A library owned by a package (a logger such as snoopy) is reported and left alone |
| `trust` | `.rhosts`, `.shosts`, `/etc/hosts.equiv`, `/etc/shosts.equiv` moved to quarantine | They let other machines log in with no password |
| `uid0` | Accounts other than root with UID 0 are locked (`!` before the password) and expired, so no password or SSH key logs in | A second UID 0 account is a backdoor. The password itself is never logged; undo removes the `!` and puts the old expiry back |
| `emptypw` | Accounts with an empty password are locked | Anyone could log in as them. Scoring never uses an account with no password |
| `suid` | Removes the SUID bit from programs that should never have it (copies of bash, find, vim, python ... from GTFOBins) and from any SUID file in `/tmp`, `/var/tmp`, `/dev/shm`, `/home`, `/root` | The normal SUID programs (passwd, sudo, su, mount, ping, pkexec ...) are not on the list and are never touched |
| `hosts` | Reports `/etc/hosts` lines that pin a name to an address. Never changes the file | Scoring can depend on `/etc/hosts`; a red team uses it to redirect updates and logins |

IP forwarding left on is reported under "check by hand" even without `--no-forwarding`.

### What it produces

In a numbered folder: `<out>/safe-fixes-1`, `safe-fixes-2`, ...

| File | Contents |
| --- | --- |
| `output.txt` | Everything shown on screen, without colours |
| `summary.txt` | Counts per fix, every change (or would-be change), and the items to check by hand |
| `plan.txt` | What it would change |
| `fixes.txt` | What it did: fix, item, before, after, status |
| `revert.sh` | Undoes this run: `sh revert.sh --force` |
| `revert.log`, `KEEP`, `REVERTED` | The revert timer's record |
| `csv/` | `plan.csv`, `fixes.csv` |

Every change adds an undo command to `<out>/undo-<host>.log`. Changed files are copied to `<out>/backup/<host>/` first; quarantined files go to `<out>/quarantine/<host>/`.

Kernel settings are written to `/etc/sysctl.d/99-zz-ccdc-safe.conf`, a name read last at boot, so they win over `/etc/sysctl.conf`.

### Undo

This run only, at any time (even after keeping it):

```sh
sudo sh /root/ccdc-out/safe-fixes-3/revert.sh --force
```

Everything every script changed on the host: run the undo log's commands from the bottom up:

```sh
awk -F'\t' '{ l[NR] = $4 } END { for (i = NR; i >= 1; i--) print l[i] }' /root/ccdc-out/undo-web01.log > /tmp/undo.sh
less /tmp/undo.sh        # read it first: it holds every change made by every script on this host
sh /tmp/undo.sh
```

To undo only this script, keep the lines whose second field is `LX-39`.

### What to watch for

- **Dry run first on one box.** The summary shows exactly what will change.
- **A container may refuse some kernel settings.** Those show as `failed` in `fixes.csv`; everything else still applies.
- **A quarantined `ld.so.preload` is evidence.** Hash it and keep it for the incident report. After moving it, run the enum again: a rootkit that hid files stops hiding them.
- **The boot file can be beaten by a file named later** (for example `99-zzz.conf`). The change watch reports new files in `/etc/sysctl.d`.

### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `Staying in dry run ... no protected list` | You answered no to going on without a protected list | Build one, pass `--protected FILE`, or answer yes / pass `--no-protected` |
| `the revert timer ran out while waiting for an answer` (exit 3) | The questions took longer than the timer. Nothing was changed | Run again faster, use flags or `--batch`, or `--timer 300` |
| The changes were undone a couple of minutes later | Nobody answered "keep", or you were kicked off | That's the timer working. Check `revert.log`, fix whatever locked you out, run again |
| `Dry run only (not root)` | Not run with sudo | `sudo` |
| `this script must be run as root` (exit 3) | `--apply` as a normal user | `sudo` |
| Kernel settings `failed` | Read-only `/proc/sys` (containers) | Nothing to do on that box; the host kernel decides |
| `skipped (not on this kernel)` | Old or trimmed kernel without that setting | Harmless |
| A service stopped answering on IPv6 | It was bound to a specific IPv6 address (listed under "check by hand") | Undo the two `disable_ipv6` lines, or bind the service to its IPv4 address |
| `logging` shows nothing | No rsyslog, syslog-ng or auditd installed | Install one if logs matter for the box |

---

## 16. Linux password rotation, `roles/linux/LX-20-password-rotation.sh` (LX-20)

New random passwords for every account that has a usable password, root included. With a team list, it also locks every human account that is not on it. The new passwords go to one private file for the captain, never to the screen or the log.

Run the backup (LX-31) first. **Put every account the scoring engine logs in with on the protected list**, or scoring breaks.

### How to run it

Just run it. It asks like sqlmap: Enter takes the default.

```sh
sudo sh LX-20-password-rotation.sh --protected /root/protected.csv          # asks about every account
sudo sh LX-20-password-rotation.sh --apply --batch --protected /root/protected.csv   # defaults, no questions
sudo sh LX-20-password-rotation.sh --apply --batch --protected /root/protected.csv --keep /root/team.txt --kick
```

What a run looks like:

1. **Revert timer: 5 minutes** (`--timer` to change it). Unless you keep the changes at the end, `/etc/shadow` and `/etc/passwd` go back: old passwords, nothing locked. It runs outside the script, so it happens even if your session died.
2. **The account table:** every account with UID, shell, password state (set, empty, locked), last login, and the default action. **Hidden accounts are in red:** a second UID 0, an empty password, a hash in `/etc/passwd`, a system account that can log in, an account in only one of `passwd`/`shadow`. System accounts with no password are summed up in one line. Domain/LDAP accounts are listed in a note.
3. **"Go through each account one by one?"** `n` takes the actions in the table. `y` asks about each one:
   - `r` random password
   - `s` set one: typed twice, not shown, never logged
   - `d` disable: locked **and** expired, so SSH keys stop working too
   - `k` keep
   - `a` the default for all the rest

   The account you're logged in as, and accounts on the protected list, need an extra yes.
4. **"End the running sessions of the accounts you disable?"** A lock doesn't end a login already in progress.
5. **The plan,** then `Apply these N change(s)?`, then each change as it's made.
6. **"Keep these changes?"** Open a **new** session and log in with the new password first. `n`, or no answer before the timer, puts everything back.

| Option | What it does |
| --- | --- |
| `--keep FILE` | The team's account list, one name per line. Human accounts (UID at or above `UID_MIN`, usually 1000) and any extra UID 0 account NOT on it are locked and expired. Expiry also blocks SSH key logins, which a locked password alone does not |
| `--users a,b` | Rotate (and lock) only these accounts. Repeatable; the lists add up |
| `--exclude a,b` | Never touch these accounts. Repeatable; the lists add up. Comma-separated, no spaces |
| `--ignore-missing` | A name in `--users` or `--exclude` that is not an account on this box normally STOPS the script before anything changes (a misspelled name would otherwise get the account rotated). This option only warns instead, for one list used on many boxes |
| `--passwords FILE` | Use these passwords instead of random ones: `user,password` lines, for a sheet made in advance. Passwords must be 8+ characters with no `:`; spaces around the name and password are dropped. Names not on this box, and accounts that are locked or have no password (setting one would unlock them), are listed in the summary and not changed |
| `--length N` | Random password length (default 16, minimum 12) |
| `--no-root` | Leave root's password alone |
| `--include-me` | Also rotate the account that ran `sudo`. Skipped by default so you can still use `sudo` |
| `--kick` | Also end every running process of a locked account (logs out a red team session) |
| `--print` | Show the new passwords on screen at the end (never saved to `output.txt`) |
| `--timer SECONDS` | Revert timer length (default 300) |
| `--no-timer` | No revert timer (you accept the risk) |
| `--batch` | Never ask: take every default. With `--apply`, the changes are kept |
| `--no-color` | No colours |

Random passwords use letters and digits without look-alikes (`0 O 1 l I`) plus `_` and `-`, so they survive being typed into shells, SQL and web forms.

### What it does to each account

| Account | Action |
| --- | --- |
| Usable password (hash set, or EMPTY) | New password |
| On the protected list | Skipped; listed as `skipped (protected)` |
| Human account not on `--keep` | Locked and expired (password kept, so unlocking restores it) |
| Extra UID 0 account | Disabled (locked and expired) by default: it is root under another name |
| Password hash in `/etc/passwd` itself | Moved into `/etc/shadow` with `pwconv`, then rotated. A hash there is used instead of the shadow one, so changing only shadow would leave the old password working |
| System account without a password (`*`, `!`) | Left alone |
| Service account with a password but no login shell | Rotated, with a note: check no service logs in with its old password |

Accounts below `UID_MIN` are never locked: services and cron jobs run as them.

### What it produces

In a numbered folder: `<out>/passwords-1`, `passwords-2`, ...

| File | Contents |
| --- | --- |
| `output.txt` | Everything shown on screen. Never a password |
| `accounts.txt` | Every account and what was done, as a table (CSV copy in `csv/`). No passwords |
| `revert.sh` | Undoes this run: old passwords back, locks removed (`sh revert.sh --force`) |
| `summary.txt` | Counts, every account and what happened, warnings (empty passwords, extra UID 0, Samba accounts). No passwords |
| `passwords.csv` | `host,user,password,time`, mode 600, written only when changes are applied. If the run is undone it is renamed `passwords-UNDONE-not-valid.csv`, so nobody hands out passwords that no longer work |

`/etc/shadow` and `/etc/passwd` are backed up before the first change. The undo log restores them from that backup, which also brings back the OLD passwords: that way no password hash is ever written into a log.

### What to watch for

- **The passwords file is the most sensitive thing on the box.** Copy it to the captain (or read it out), then `rm` it. Its path is in the summary.
- **Scored accounts.** If the competition requires a scored account's password to change, change it through their password-change process and put the account on the protected list here.
- **Samba has its own passwords.** The summary lists Samba accounts if `pdbedit` exists; change those with `smbpasswd` if needed.
- **LDAP, Active Directory and NIS accounts** are not in `/etc/shadow` and are not touched.
- **Locking does not end open sessions.** Use `--kick`, and check `w` / `who` afterwards.

### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `chpasswd not found` (exit 3) | Minimal image without shadow-utils | Install the `passwd` / `shadow` package, or busybox |
| `cannot read /etc/shadow` (exit 3) | Not root | `sudo` |
| An account shows `failed` | `chpasswd` refused (PAM password-quality rules can reject some passwords) | Rerun; a new random password is made each time. Check the log for the message |
| You cannot `sudo` any more | You rotated your own account with `--include-me` | Your new password is in `passwords.csv`; read it from the root shell you still have |
| Scoring broke right after | A scored account was rotated | Put it on the protected list and set the old password back: the undo log restores `/etc/shadow` |

---

## 17. SSH hardening and key cleanup, `roles/linux/LX-22-ssh-hardening.sh` (LX-22)

A changed password does not stop a red team that planted an SSH key. This lists every authorized key on the box, removes the ones not on the team's list, puts safe settings at the top of `sshd_config`, and reloads sshd without dropping open sessions. If sshd stops listening after the reload, it puts the old config back by itself.

Password logins are left on: scoring engines usually log in with passwords.

### How to run it

```sh
sudo sh LX-22-ssh-hardening.sh --out /root/ccdc-out                                   # dry run: lists every key
sudo sh LX-22-ssh-hardening.sh --out /root/ccdc-out --apply --protected /root/protected.csv
sudo sh LX-22-ssh-hardening.sh --out /root/ccdc-out --apply --protected /root/protected.csv --allow-keys /root/team.pub
```

Keep a second root session open while applying, as with any SSH change.

| Option | What it does |
| --- | --- |
| `--allow-keys FILE` | The team's public keys (`authorized_keys` format) or fingerprints (`SHA256:...`). Every other key is removed from every account |
| `--remove-all-keys` | Remove every authorized key |
| `--no-root-login` | `PermitRootLogin no`. The default is `prohibit-password`: root by key only. The default is NOT applied when root has a password but no SSH key that stays (root could no longer log in by SSH at all) or when root is on the protected list; root login is then left as it is and the summary says so |
| `--root-key-only` | `PermitRootLogin prohibit-password` even if root has no key |
| `--keep-root-login` | Leave `PermitRootLogin` alone |
| `--no-forwarding` | Also `AllowTcpForwarding no`, `PermitTunnel no`, `GatewayPorts no` (stops pivoting through the box) |
| `--allow-users LIST` | `AllowUsers`: only these accounts may log in by SSH. Accounts on the protected list are added automatically. Easy to lock yourself out with |
| `--banner FILE` | Shown before login |
| `--no-reload` | Install the config but do not reload sshd |

Without `--allow-keys` or `--remove-all-keys`, keys are only listed.

### What it does

| Part | Detail |
| --- | --- |
| Keys | Reads every `AuthorizedKeysFile` (from `sshd -T`) of EVERY account, including service accounts such as `www-data`, a favourite hiding place. Keys not allowed are removed; comments and allowed keys stay exactly as they were. The removed lines are saved under the quarantine folder as evidence. Accounts on the protected list keep their keys |
| Settings | A marked block at the very top of `sshd_config` (sshd uses the first value it reads, so the block wins over the rest of the file and `sshd_config.d`): `PermitEmptyPasswords no`, `PermitRootLogin prohibit-password`, `HostbasedAuthentication no`, `IgnoreRhosts yes`, `PermitUserEnvironment no`, `X11Forwarding no`, `AllowAgentForwarding no`, `MaxAuthTries 4`, `LoginGraceTime 30`. Running it again replaces the block; it never adds a second |
| Test, then reload | The new file is tested with `sshd -t` and installed only if it passes. sshd is reloaded (open sessions stay up), then checked: if it is no longer listening, the old config goes back and sshd is reloaded or started again |
| Login scripts | `~/.ssh/rc` and `/etc/ssh/sshrc` run commands at every login; they are moved to quarantine |
| Reported | `Match` blocks that loosen login settings, `AuthorizedKeysCommand` and similar, extra sshd processes on other ports or configs, keys with forced commands or environment options, `~/.ssh/environment` files, symlinked key files |

### What it produces

In `<out>/LX-22_<host>_<UTC time>/`:

| File | Contents |
| --- | --- |
| `summary.txt` | Config status, reload result, each setting before and after, the effective values from `sshd -T`, every key and what happened to it, things to check by hand |
| `keys.csv` | `user,file,type,fingerprint,comment,options,action` |
| `settings.csv` | `setting,before,after,status` |

`sshd_config` and every rewritten key file are backed up first; the undo log restores them.

### Getting the team's keys

On the admin workstation, the team's public key is usually `~/.ssh/id_ed25519.pub`. Put every teammate's public key (or its `SHA256:` fingerprint from `ssh-keygen -lf key.pub`) in one file and pass it with `--allow-keys`.

### What to watch for

- **Check the key list before removing.** Run once without `--allow-keys`: `keys.csv` shows every key with its comment. Fan-out tools (the team's own automation) use keys too.
- **A scoring engine that logs in with a key** needs that account on the protected list.
- **`Match` blocks are reported, not changed.** A red team can add `Match User x` with looser settings at the end of the file; read the report.
- **Immutable key files.** A red team can `chattr +i` an `authorized_keys` file. Rewriting it then fails and the report says so: `lsattr` it, `chattr -i` it, run again.

### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `sshd rejected the new config` (exit 5) | The existing config has an error, or this sshd is too old for a setting | Read the log for the line; fix it and run again. The config was NOT changed |
| `sshd not found ... sshd_config NOT changed` | No sshd on PATH or in the sbin folders | Keys are still handled; check the SSH server package |
| `FAILED: sshd stopped listening; old config restored` | sshd did not come back after the reload | The script restored the old config; check `ss -ltnp`, start sshd by hand if needed, read the log |
| A teammate cannot log in by key any more | Their key was not on `--allow-keys` | Add it and run again, or restore the file from the undo log |
| `could not rewrite it (immutable?)` | `chattr +i` on the key file | `chattr -i FILE` and run again |

---

## 18. Linux firewall builder, `roles/linux/LX-25-firewall.sh` (LX-25)

Drops every incoming connection the box does not need. Run it LAST of the Linux hardening, after the backup, safe fixes, passwords and SSH, and keep a second session open.

### How to run it

```sh
sudo sh LX-25-firewall.sh --out /root/ccdc-out --protected /root/protected.csv                  # dry run: prints the rules
sudo sh LX-25-firewall.sh --out /root/ccdc-out --protected /root/protected.csv --apply --admin 10.0.0.5
# then, from a NEW ssh session, within 2 minutes:
sudo sh /root/ccdc-out/LX-25_web01_<time>/keep-firewall.sh
# once scoring is confirmed green, keep the rules across a reboot:
sudo sh LX-25-firewall.sh --out /root/ccdc-out --save --apply
```

| Option | What it does |
| --- | --- |
| `--allow SPEC` | Also allow `80`, `80/tcp`, `53/udp` or `8000-8100/tcp` (repeat or comma-separate) |
| `--admin CIDR` | Allow everything from this address or network (the team's workstations). Repeat for more |
| `--ssh-from CIDR` | SSH only from these addresses. Leave it out if the scoring engine checks SSH |
| `--strict` | Allow only scored ports, `--allow`, SSH and DHCP; NOT every port that is listening |
| `--restrict-out` | Also limit outgoing traffic to DNS, DHCP, NTP, HTTP(S), replies and the admin addresses. Stops reverse shells; can break software that calls out |
| `--keep-ipv6` | Do not drop IPv6 |
| `--backend nft\|iptables` | Default: nft when it works |
| `--confirm-timeout N` | Seconds before the automatic rollback (default 120). `0` = no timer: only when you are at the console |
| `--save` | With `--apply`: save the live ccdc rules for reboot |
| `--remove` | With `--apply`: remove the ccdc rules |

### What it allows

| Allowed | Why |
| --- | --- |
| Loopback, replies to the box's own connections | Nothing works without them |
| ICMP (ping, errors) | Scoring often pings; path MTU needs ICMP errors |
| UDP 68 (and 546 with `--keep-ipv6`) | DHCP replies: without them a DHCP box loses its address at lease renewal |
| SSH, on the port `sshd -T` reports | Team access (limited with `--ssh-from`) |
| Every port on the protected list (type `port`) | Scored services, even if down right now |
| Every port listening on a network address now | Running services keep working. Not with `--strict` |
| Everything from `--admin` and protected hosts (type `host`) | The team and the scoring engine |

Not allowed, and listed under "NOT allowed": ports listening on backdoor-style numbers (1337, 4444, 4445, 5555, 6666, 6667, 12345, 31337, 54321, 2375 Docker API), and listeners on 127.0.0.1 only (they need no rule). IPv6 is dropped except loopback.

### Safety

- **Own rules only.** nftables: table `inet ccdc`. iptables: chains `CCDC-IN`/`CCDC-OUT`, jumped to from the top of `INPUT`/`OUTPUT`. Nothing else is flushed, so Docker, fail2ban, firewalld and ufw keep their rules. `FORWARD` is never touched.
- **Checked first.** The nft ruleset is checked with `nft -c` before loading; if loading fails, whatever loaded is removed.
- **Rollback timer.** After `--apply`, a detached timer removes the rules after `--confirm-timeout` seconds unless `keep-firewall.sh` is run. Run it from a NEW ssh session: that proves new connections still get in, which an open session cannot (open sessions survive any rule). At a terminal the script also asks; answering `y` removes the rules at once.
- **Not saved for reboot** until you run `--save --apply`. Until then a reboot is a last-resort undo.

### What it produces

In `<out>/LX-25_<host>_<UTC time>/`:

| File | Contents |
| --- | --- |
| `summary.txt` | State (live, rolled back, dry run), allowed ports and why, what is not allowed, the confirm command |
| `ports.csv` | `proto,port,allowed,reason` |
| `ruleset.nft` or `ruleset.iptables.sh` | The exact rules |
| `rollback.sh` | Removes the rules (also in the undo log) |
| `keep-firewall.sh` | Cancels the rollback timer |
| `ROLLED_BACK` | Appears when the timer removed the rules |

Dropped packets are logged with the prefix `CCDC-DROP` (`journalctl -k | grep CCDC-DROP`, or `dmesg`), limited to 10 a minute.

### What to watch for

- **A scored service that is down right now** is not listening, so its port opens only if it is on the protected list or in `--allow`. Keep the protected list complete.
- **Port 2024, 8000 and other unknown listeners** are opened by default because they are listening. Read the allowed list; anything you do not recognise is worth a look with the enum (SH-05) before you `--save`. `--strict` is the tight option once the protected list is right.
- **Other firewalls still apply.** A port allowed here can still be blocked by ufw or firewalld rules.
- **Fan-out:** without a terminal the script does not ask; confirm from the admin workstation with `ssh root@box sh .../keep-firewall.sh`, which is itself the "new connection" test.

### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `nft rejected the ruleset` (exit 5) | A rule this nft version does not understand | Read the log line; try `--backend iptables` |
| Scoring went red right after applying | A scored port was not open | Wait for the timer or run `rollback.sh`; add the port to the protected list or `--allow`; apply again |
| `too late: the rules were already rolled back` | `keep-firewall.sh` ran after the timer | Apply again and confirm sooner, or use a longer `--confirm-timeout` |
| SSH locked out | `--ssh-from` without your address | Wait for the timer (that is what it is for); from the console run `rollback.sh` |
| Rules gone after a reboot | `--save --apply` was not run | Apply, confirm, then `--save --apply` |
| Under yash, output only appears when the timer ends | yash waits for the detached timer when the script's output is piped | Run it at a terminal, or with another shell |

---

## 19. Linux change watch, `roles/linux/LX-40-change-watch.sh` (LX-40)

Takes a quick baseline of every place a red team uses to keep access, then checks again, once or every minute, and raises one alert per change. Start it once the box is hardened, and send the alerts off the box.

It changes nothing on the host. A check takes about a second (a few seconds with the SUID scan on a big disk).

### How to run it

```sh
sudo sh LX-40-change-watch.sh --out /root/ccdc-out --baseline      # after hardening
sudo sh LX-40-change-watch.sh --out /root/ccdc-out                 # one check
# keep it running, alerts copied to the admin workstation:
nohup sudo sh LX-40-change-watch.sh --out /root/ccdc-out --loop 60 \
    --alert-cmd "ssh admin@10.0.0.5 'cat >>/srv/alerts/web01.log'" >/root/ccdc-out/watch.out 2>&1 &
sudo sh LX-40-change-watch.sh --out /root/ccdc-out --accept        # after changing things on purpose
```

| Option | What it does |
| --- | --- |
| `--baseline` / `--accept` | Take a new baseline from the current state. Use `--accept` after reviewing changes the team made |
| `--loop N` | Check every N seconds (at least 10) until stopped |
| `--count N` | With `--loop`: stop after N checks |
| `--webroot DIR` | Also watch DIR (the usual web roots are watched already) |
| `--no-suid` | Skip the SUID/SGID scan, which reads the whole root file system |
| `--suid-every N` | With `--loop`: run that scan only on every Nth check (default 10). A new SUID file is then reported up to N checks late; the other sections are checked every time |
| `--alert-cmd CMD` | After a check that found changes, run CMD with the new alert lines on its stdin (`ssh ... 'cat >>file'`, `logger -t ccdc`, `mail ...`) |
| `--state DIR` | Where the baseline lives (default `<out>/watch-<host>`) |

The first check with no baseline takes one.

### What it watches

| Section | What | Severity |
| --- | --- | --- |
| users | Accounts added, removed, or changed (an account turned into UID 0 is HIGH) | added HIGH |
| passwords | A password changed: compared as a short checksum of the shadow field, never the hash | MED |
| groups | Members of every group; `sudo`, `wheel`, `admin`, `root`, `adm`, `docker`, `lxd`, `disk`, `shadow` changes are HIGH | HIGH / LOW |
| files | sudoers, PAM, `/etc/security`, `ld.so.preload` and `ld.so.conf`, profile and shell startup files, `/etc/environment`, hosts, resolv.conf, nsswitch, sshd config, sysctl files | HIGH for sudo/PAM/preload or any new file, else MED |
| cron | `/etc/crontab`, cron folders, user crontabs, at and anacron spools, systemd timers | added or changed HIGH |
| units | systemd unit files, init.d scripts, `rc.local` | added HIGH, changed MED |
| keys | Every account's `authorized_keys` (hash and key count) | added or changed HIGH |
| ports | Listening TCP/UDP ports and their programs | backdoor-style port HIGH, else MED; a port that stopped is MED (a scored service may be down) |
| suid | SUID/SGID programs | added HIGH |
| web | Files in web roots by size and time | new program file HIGH, new or removed file MED, changed LOW/MED |
| modules | Loaded kernel modules | added HIGH |

### What it produces

In the state folder (`<out>/watch-<host>/`):

| File | Contents |
| --- | --- |
| `alerts.log` | Every alert ever raised: `time SEVERITY section change item - detail`, HIGH first within each check |
| `changes-since-baseline.txt` | Everything that differs from the baseline now |
| `baseline/`, `last/` | The snapshots, one plain-text file per section, no secrets |

Each check alerts only on what changed since the previous check, so one change is reported once; `changes-since-baseline.txt` keeps the running total.

### What to watch for

- **Your own changes show up too.** After the team changes something on purpose, run `--accept`.
- **Send alerts off the box.** A red team with root can stop this script or edit its files. `--alert-cmd` is the way out.
- **Web files are compared by size and time**, not content, to stay fast. A careful attacker can keep both the same; the backup's hash list (LX-31) catches that: `sha256sum -c files.sha256`.
- **"stopped listening" on a scored port** means the service is down: check it first.
- **Package updates** change unit files and programs. Check the package log before treating those as an attack.

### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| Hundreds of alerts on the first check | The baseline was taken before hardening | `--accept`, then watch |
| `passwords` and `keys` never change | Not root, so shadow and other homes cannot be read | Run as root |
| Checks are slow | The SUID scan on a large disk | It already runs only every 10th check in a loop; raise `--suid-every`, or use `--no-suid` |
| `--alert-cmd failed` warning | The command failed (no SSH key, host down) | Alerts are still in `alerts.log`; test the command by hand: `echo test \| CMD` |
| The loop stopped when the session closed | Started without `nohup` | Use `nohup ... &`, `tmux` or `screen` |

---

## 20. Brute-force and spam banning, `roles/linux/SV-26-banning.sh` (SV-26)

Reads the login logs, counts failures per source address, and bans an address that passes the limit. The ban removes itself after `--ban-time` minutes, so a mistake fixes itself. Spam from a compromised mailbox is reported, not banned.

### How to run it

```sh
sudo sh SV-26-banning.sh --out /root/ccdc-out --protected /root/protected.csv                 # dry run
sudo sh SV-26-banning.sh --out /root/ccdc-out --protected /root/protected.csv --apply --loop 60
sudo sh SV-26-banning.sh --out /root/ccdc-out --list                                           # current bans
sudo sh SV-26-banning.sh --out /root/ccdc-out --apply --unban 10.6.6.66
```

Keep it running with `nohup ... &`, `tmux` or `screen`. Put the scoring engine on the protected list as a `host`: after a password change it fails logins too.

| Option | What it does |
| --- | --- |
| `--max-fails N` | Failures (SSH, FTP, mail, PAM) in the window that earn a ban (default 10) |
| `--web-max N` | Web login attempts that earn a ban (default 30; real users log in once, a guesser hundreds of times). Counted: POSTs to login pages (`wp-login.php`, `xmlrpc.php`, `/login`, `/user/login`, `/administrator/`, phpMyAdmin) and any 401 answer. Other admin pages are not counted |
| `--window MIN` | Counting window (default 10) |
| `--ban-time MIN` | Ban length (default 30) |
| `--mail-max N` | Recipients per sender in the window before a spam warning (default 200) |
| `--ignore CIDR` | Never ban this address or network (repeat) |
| `--log FILE` | Read ONLY these logs (repeat), not the usual ones or the journal |
| `--history N` | Lines read from each log on the very first run (default 2000) |
| `--loop N` / `--count N` | Run every N seconds; stop after N runs |
| `--backend` | `nft` (default when it works), `ipset`, or `iptables` |
| `--list` / `--unban IP` | Show bans / remove one (with `--apply`) |

### What it counts

| Service | Log lines |
| --- | --- |
| SSH | `Failed password for ...`, invalid-user scans that disconnect before a password, `maximum authentication attempts exceeded` |
| FTP | vsftpd `FAIL LOGIN`, proftpd `Login failed`, pure-ftpd `Authentication failed` |
| SMTP | postfix `SASL ... authentication failed`, `Relay access denied` |
| IMAP/POP | dovecot `auth failed ... rip=` |
| Web | `POST` to `wp-login.php`, `xmlrpc.php`, Joomla `/administrator`, `/user/login`, Roundcube, phpMyAdmin, `/login`, `/admin`; any HTTP 401 |
| Other | any PAM `authentication failure ... rhost=` |
| Spam (report only) | postfix `from=<sender> ... nrcpt=N`, summed per sender |

Logs read by default: `/var/log/auth.log` or `/var/log/secure`, FTP logs, `/var/log/mail.log` or `maillog`, Apache and nginx access logs. When there is no SSH log file, the journal is read instead.

**How the window works without parsing dates:** each run reads only what was added to each log since the last run, and stores those counts with the run's time. The window is the sum of runs in the last `--window` minutes. A log that got shorter (rotated) is read from the start again.

### Never banned

Protected hosts (type `host`), `--ignore` addresses, this box's own addresses, loopback, and the **default gateway**. When the network NATs traffic, every outside client looks like the gateway, and banning it would cut off the scoring engine. These show as `NOT BANNED` when they pass the limit, so you can decide.

### What it produces

In `<out>/ban-<host>/`:

| File | Contents |
| --- | --- |
| `bans.csv` | `time,address,services,failures,accounts_tried,until,action` |
| `events.log` | One line per run, bans, the `NOT BANNED` and `SPAM?` warnings |
| `hits`, `offsets` | The window counts and how far each log was read |

Firewall: nftables table `inet ccdc_ban` (two address sets with per-entry timeouts, one drop rule); or ipset `ccdc_ban` plus one iptables rule; or one iptables rule per address, removed by a later run when due. The undo log removes it all. A dry run keeps no state, so it can be repeated.

### What to watch for

- **Accounts tried** in `bans.csv` tell you what the red team is guessing: if a real team account is on the list, change its password.
- **`SPAM?`** means a local mailbox is sending to many people: its password is probably known. Change it (SV-12 / LX-20) and check the mail queue.
- **Many addresses, few tries each** stay under the limit. Lower `--max-fails`, or block the range with the firewall builder.
- **First run.** It reads the last 2000 lines of each log, so old failures can trigger bans straight away. Do a dry run first.

### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `0 new failure line(s)` while an attack runs | The service logs somewhere else, or in a different format | Find the log, pass it with `--log`, run with `--debug`; send the line format to whoever maintains the kit |
| The scoring engine got banned | Not on the protected list | `--unban` it, add it as `host` to the protected list |
| `NOT BANNED (default gateway ...)` | Traffic arrives NATed through the gateway | Ban by hand only if you are sure; better, firewall at the edge |
| `no firewall tool found` (exit 3) | No nft, ipset or iptables | Install nftables |
| Bans gone after a reboot | They are timed and not saved, on purpose | Keep it running in a loop |

---

## 21. Database backup, `roles/applications/SV-14-db-backup.sh` (SV-14)

Dumps every database on a Linux or Unix host, checks each dump can be read back, hashes them, and can copy them off the box. Copying a running database's files does not give a usable backup; a dump does. Run it in the first minutes, next to the Linux backup (LX-31).

### How to run it

```sh
sudo sh SV-14-db-backup.sh --out /root/ccdc-out
sudo sh SV-14-db-backup.sh --out /root/ccdc-out --copy-to admin@10.0.0.5:/srv/backups/db01/
sudo sh SV-14-db-backup.sh --out /root/ccdc-out --mysql-cnf /root/my.cnf --keep 3
```

| Option | What it does |
| --- | --- |
| `--only mysql,postgres,sqlite` | Which engines (default: all that are found) |
| `--mysql-cnf FILE` | MySQL client file with a user and password (`[client]` section), when root cannot log in through the socket |
| `--sqlite FILE` | Also back up this SQLite file (repeat) |
| `--max-mb N` | Refuse if the databases add up to more than N MB (default 4096); also refuses when the disk is too full |
| `--keep N` | Keep only the newest N SV-14 backups of this host in the output folder |
| `--copy-to DEST` | Copy the dumps, hashes and restore notes off the box with `scp` |

It changes nothing in the databases or on the host, so it needs no `--apply`.

### What it dumps

| Engine | Files | How |
| --- | --- | --- |
| MySQL / MariaDB | `mysql_<db>.sql.gz`, one per database, including `mysql` (accounts and grants) | `mysqldump`/`mariadb-dump --single-transaction --routines --triggers --events`; checked with `gzip -t` and the "Dump completed" line |
| PostgreSQL | `pg_globals.sql.gz` (roles), `pg_<db>.dump` per database | `pg_dumpall --globals-only` and `pg_dump -Fc` as the `postgres` account; checked with `pg_restore -l` |
| SQLite | `sqlite_<n>_<name>` | Files in web roots, `/var/lib/grafana` and `/opt` that start with the SQLite header, and `--sqlite` files; `sqlite3 .backup` when available, else a copy |

Login for MySQL follows SV-01: `--mysql-cnf`, then root through the socket, then `/etc/mysql/debian.cnf`, then the client's defaults. It never prompts.

### What it produces

In `<out>/SV-14_<host>_<UTC time>/` (mode 700, files 600): the dumps, `SHA256SUMS`, `dumps.csv` (`engine,database,file,size_kb,status`), `RESTORE.txt` with the commands for each dump, and `summary.txt`.

### Restoring

```sh
cd /root/ccdc-out/SV-14_db01_<time>
sha256sum -c SHA256SUMS
gzip -dc mysql_wordpress.sql.gz | mysql                                           # REPLACES the database
sudo -u postgres pg_restore --clean --if-exists -d shopdb < pg_shopdb.dump         # REPLACES its objects
sudo -u postgres createdb restore_check && sudo -u postgres pg_restore -d restore_check < pg_shopdb.dump   # compare first
```

PostgreSQL dumps are fed on stdin (`<`): the `postgres` account cannot open files in the private backup folder itself. `RESTORE.txt` also shows how to load a MySQL dump under another name to compare, and how to cut one table out of a dump.

### What to watch for

- **The dumps hold every password hash and every row**, including the `mysql` system database. Keep them private and copy them only to the team's machine.
- **Restoring a whole database undoes everything since the dump**, including legitimate changes (orders, posts). Restore one table, or compare first, when you can.
- **The `mysql` database dump restores accounts too.** Load it only to undo account changes, and change the passwords again afterwards.
- **MyISAM tables** are dumped without a lock; one that is written during the dump can be a moment inconsistent.
- **MongoDB, Redis and MSSQL** are not covered.

### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `MySQL/MariaDB is running but could not log in` | root needs a password and there is no `debian.cnf` | `--mysql-cnf` with a working account |
| `PostgreSQL is running: run as root` | Not root | `sudo` |
| A MySQL dump `FAILED` | Disk full, a crashed table, or no rights to a database | Read the log; `mysqlcheck` the database; check free space |
| `the databases add up to about N MB` (exit 3) | Bigger than `--max-mb` | Raise `--max-mb`, or `--out` on a bigger disk |
| `pg_restore: could not open input file ... Permission denied` | Passing the file name to `pg_restore` run as postgres | Feed it on stdin: `pg_restore ... < FILE` |
| SQLite marked "may be inconsistent" | No `sqlite3`, and the app may write while it is copied | Install `sqlite3`, or stop the app for the copy |

---

## 22. Network config backup and diff, `roles/network/NW-01-config-backup.sh` (NW-01)

Logs in to every firewall, router and switch over SSH, saves its running configuration, and shows what changed since the last saved copy. Run it first (the copy you restore from) and again every few minutes (the change watch for network gear).

It only sends "show" commands. Nothing on the devices changes.

### How to run it

```sh
sh NW-01-config-backup.sh --out ~/ccdc-out --hosts config/hosts.csv                        # SSH keys
CCDC_NET_PASS='...' sh NW-01-config-backup.sh --out ~/ccdc-out --hosts config/hosts.csv --password-env
sh NW-01-config-backup.sh --out ~/ccdc-out --device fw01,10.0.2.1,paloalto,admin --ask-password
# every 5 minutes:
while :; do sh NW-01-config-backup.sh --out ~/ccdc-out --hosts config/hosts.csv --password-env; sleep 300; done
```

Run it from the admin workstation (a Linux box that can reach the devices' management addresses).

| Option | What it does |
| --- | --- |
| `--hosts FILE` | Host list. Rows with `os` = `network` take the vendor from the notes ("Palo Alto", "Cisco IOS", "Cisco ASA", "FortiGate", "VyOS", "pfSense", "OPNsense", "MikroTik") or a `vendor` column; a vendor name in `os` works too |
| `--device SPEC` | `NAME,ADDRESS,VENDOR[,USER[,PORT]]` (repeat) |
| `--user NAME` | Login name when the list gives none (default `admin`) |
| `--password-env` | Password from `$CCDC_NET_PASS`, handed to `sshpass -e` in the environment (never on a command line) |
| `--ask-password` | Ask once, without echo |
| `--enable-env` | Cisco: send `enable` with `$CCDC_NET_ENABLE` when the login is below privilege 15 |
| `--legacy-ssh` | Allow old SSH algorithms from the start. Also tried automatically when a device refuses the modern ones |

Without a password option, SSH keys are used and the script never prompts.

### Vendors

| Vendor | Commands sent | Log in as |
| --- | --- | --- |
| `cisco-ios` | `terminal length 0`, `show running-config` | A privilege 15 account (or `--enable-env`) |
| `cisco-asa` | `terminal pager 0`, `show running-config` | An admin, usually with `--enable-env` |
| `paloalto` | `set cli pager off`, `show config running` | An admin |
| `fortigate` | `show` | An admin |
| `vyos` | `show configuration commands` | The VyOS user |
| `pfsense`, `opnsense` | `cat /conf/config.xml` | `root` (admin lands in the menu) |
| `mikrotik` | `/export` | An admin |
| `linux` | `iptables-save`, `nft list ruleset`, `ip addr`, `ip route` | root (named with a `vendor` column or `--device`) |

Before comparing, lines that change by themselves are dropped: prompts and echoed commands, Cisco "Last configuration change" and NVRAM lines, ASA checksums and serial lines, the FortiGate file version, nftables packet counters.

### What it produces

| Where | What |
| --- | --- |
| `<out>/NW-01_<host>_<time>/summary.txt` | Per device: lines, lines added and removed, status; then the flags |
| `.../devices.csv` | `device,address,vendor,status,lines,added,removed,sha256` |
| `.../<device>.diff` | Unified diff against the previous copy (holds secrets; mode 600) |
| `.../flags.csv` | One flag per changed line, secrets masked |
| `<out>/net-configs/<device>/<time>.cfg` | Every saved config as received (mode 600) |
| `<out>/net-configs/known_hosts` | The devices' SSH host keys |

A changed line about accounts, passwords, SNMP, NAT, permits/allows/accepts, telnet, the web management server, AAA, crypto, tunnels, routes, rules, policies or SSH is HIGH. Any other change is MED.

### What to watch for

- **The saved configs hold password hashes, SNMP communities and VPN keys.** Everything printed is masked; the files are not.
- **Check the first copy of each device looks complete.** A short file usually means the account cannot see the whole config (Cisco below privilege 15).
- **A changed SSH host key is HIGH and stops that device's backup.** The device was replaced or reinstalled, or someone is in the middle. Find out which, then delete its line from `known_hosts`.
- **The vendor commands are written from the vendors' documentation and tested against sample output, not real devices.** Run it once on the real gear before relying on it, and send any surprise to whoever maintains the kit.

### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `backup FAILED: Permission denied` | Wrong user or password, or keys not installed | Check by hand: `ssh USER@ADDRESS`; for passwords use `--password-env` |
| `password logins need sshpass` (exit 3) | sshpass not installed on the admin box | `apt install sshpass`, or use keys |
| `empty answer (no rights to show the config?)` | Account cannot run the show command, or pfSense admin menu | Use a privilege 15 / admin account; pfSense: `root` |
| `no matching key exchange method` in the log | Very old device | Retried automatically; if it still fails, check `ssh -Q kex` on the admin box |
| `os is network but the vendor is unknown` | Notes do not name a vendor | Add the vendor to the notes or a `vendor` column |
| Every run shows the same lines changed | A line that changes by itself (a clock, a counter) | Send the line format to whoever maintains the kit; it belongs in the clean-up list |

---

## 23. Network config audit, `roles/network/NW-07-config-audit.sh` (NW-07)

Reads the configs NW-01 saved and flags the weaknesses a red team uses first on network gear. It touches no device; run it right after the first NW-01 backup.

### How to run it

```sh
sh NW-07-config-audit.sh --out ~/ccdc-out                                  # every device NW-01 saved
sh NW-07-config-audit.sh --out ~/ccdc-out --file r1.cfg --file fw1.txt     # configs copied by hand
sh NW-07-config-audit.sh --out ~/ccdc-out --file fw1.txt,paloalto          # name the vendor
```

| Option | What it does |
| --- | --- |
| `--configs DIR` | NW-01's saved configs (default `<out>/net-configs`); the newest copy of each device is read |
| `--file F[,VENDOR]` | Audit this file (repeat). The vendor is recognised from the text when not given |
| `--max-flags N` | Findings shown on screen (default 40) |

### What it checks

| Vendor | HIGH | MED | LOW / INFO |
| --- | --- | --- | --- |
| Cisco IOS | telnet on VTY lines; `no login` on any line; `enable password`; account with type 0/7 password; default or read-write SNMP community | VTY without `access-class`; VTY without `transport input` (older IOS allow telnet); `ip http server`; type 7 line passwords; default-looking account names; no `enable secret`; SSH v1; small servers | HTTPS server; MD5 enable secret; no password encryption, SSH v2 or log server; finger; source routing; local accounts |
| Cisco ASA | telnet; ASDM (`http`) from 0.0.0.0; unhashed enable or account password; default SNMP community; `permit ip any any` | SSH from 0.0.0.0; `permit tcp/udp any any`; default-looking accounts | no log server; accounts |
| Palo Alto | `disable-telnet no`; telnet in a management profile; default SNMP community; a security rule with any source, destination and application that allows | `disable-http no`; HTTP in a management profile; the default `admin` account; no `permitted-ip` | SNMP v2c; admin accounts |
| FortiGate | `telnet` in an interface's `allowaccess`; default SNMP community; a policy accepting all to all for ALL services | `http` in `allowaccess`; an admin without `trusthost` | SNMP v2c; admin accounts |
| VyOS | telnet service; default or read-write SNMP community; plaintext password | | HTTPS API; SSH on every address; accounts |
| pfSense / OPNsense | default or read-write SNMP community; a WAN rule passing any to any | web GUI over plain HTTP | accounts |
| MikroTik | telnet on; default SNMP community | telnet not disabled (on by default); `www`, `ftp` or `api` on | accounts |

Default or guessable SNMP communities: `public`, `private`, `cisco`, `community`, `admin`, `default`, `secret`, `password`, `snmp`, `monitor`, `manager`, `read`, `write`, `test`, `ccdc`.

### What it produces

In `<out>/NW-07_<host>_<UTC time>/`: `summary.txt` (per device: vendor, counts, accounts; then the findings worst first), `findings.csv` (`device,vendor,severity,finding,detail`) and `flags.csv`. Every config line shown has its secrets masked.

### What to watch for

- **A finding is a lead, not a verdict.** An "any to any" rule may be the path the scoring engine uses; check before removing it.
- **It reads the config, not the running state.** Where a vendor's default is unsafe and does not appear in the config (older Cisco VTY lines, MikroTik telnet), that is reported as MED.
- **Palo Alto** is read in the brace format NW-01 saves (`show config running`), not the `set` format.
- **Fix with care.** Turning telnet or HTTP management off from the session you are using can cut you off. NW-11 (management hardening) will do it safely.

### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `no saved configs` (exit 3) | NW-01 has not run with this `--out` | Run NW-01 first, or give `--file` |
| `vendor not recognised` | A config whose first lines do not identify the vendor | Name it: `--file FILE,VENDOR` |
| A device has no findings at all | Wrong vendor, or the saved config is incomplete | Check NW-01's copy is the full config; give the vendor |
| A finding that is wrong for your device | The rule follows the vendor's documented syntax; your version may differ | Send the config line to whoever maintains the kit |

---

## 24. Device password rotation, `roles/network/NW-10-device-passwords.sh` (NW-10)

Changes the password of the account used to log in to each firewall, router and switch (and, for Cisco, optionally the enable secret) without risking a lock-out. Run NW-01 first: Cisco privilege levels are read from its saved configs.

### How it avoids lock-outs

1. It logs in with the current password and sends the change, keeping that session **open**.
2. It opens a **second, new** session with the new password.
3. If the new login works, it saves the config through the first session (`write memory` on Cisco; Palo Alto and VyOS commit). If it fails, it sets the **old password back** through the first session, tests the old password, and reports the device as failed.

If the first session closes early (some devices end the session after a password change), the script tests the new password directly and says whether the config may need saving by hand.

### How to run it

```sh
export CCDC_NET_PASS='current password'
sh NW-10-device-passwords.sh --out ~/ccdc-out --hosts config/hosts.csv                       # dry run
sh NW-10-device-passwords.sh --out ~/ccdc-out --device r1,10.0.0.1,cisco-ios,admin --apply   # ONE device first
sh NW-10-device-passwords.sh --out ~/ccdc-out --hosts config/hosts.csv --apply --protected protected.csv
```

| Option | What it does |
| --- | --- |
| `--hosts FILE` / `--device SPEC` | The devices, as for NW-01 |
| `--user NAME` | Default login account (`admin`) |
| `--ask-password` | Ask for the CURRENT password instead of `$CCDC_NET_PASS` |
| `--passwords FILE` | Chosen new passwords: `device,password` lines, by device name or address (same characters as below, 8+). Devices not in the file get a random password. A name that is no device in this run is reported |
| `--new-password-env` | Use `$CCDC_NET_NEWPASS` for every device (letters, digits and `_ . , @ % + = -`, 12+ characters). Default: a new random password per device |
| `--enable-env` | Cisco: log in through `enable` with `$CCDC_NET_ENABLE` |
| `--enable-too` | Cisco: also set a new enable secret; the test login must reach privilege 15 with it |
| `--length N` | Random password length (default 16) |
| `--wait N` / `--commit-wait N` | Seconds before testing a change (default 5) / for a Palo Alto commit (default 120) |
| `--configs DIR` | NW-01's saved configs (default `<out>/net-configs`) |
| `--legacy-ssh` | Allow old SSH algorithms |

Password logins need `sshpass` on the admin workstation. Every password travels in an environment variable or on the session's input, never on a command line, and device output is never logged (it can echo the new password).

### What it sends

| Vendor | Change | Saved by |
| --- | --- | --- |
| `cisco-ios` | `username U privilege N secret NEW` (N read from NW-01's copy) | `write memory` after the test |
| `cisco-asa` | `username U password NEW privilege N` | `write memory` |
| `paloalto` | `set mgt-config users U phash HASH` (SHA-256 crypt made with `openssl`), `commit` | the commit |
| `fortigate` | `config system admin` / `edit U` / `set password NEW OLD` | immediate |
| `vyos` | `set system login user U authentication plaintext-password` (stored hashed), `commit`, `save` | `save` |
| `mikrotik` | `/user set [find name="U"] password="NEW"` | immediate |
| `linux` | `chpasswd` (or `sudo -n chpasswd`) | immediate |
| `pfsense`, `opnsense` | not changed: listed with "change it in the web GUI" | |

### What it produces

In `<out>/NW-10_<host>_<UTC time>/`: `summary.txt`, `devices.csv` (`device,address,vendor,account,status`) and, with `--apply`, `passwords.csv` (mode 600). Give the passwords to the captain, then delete the file. Run NW-01 again afterwards: the changed account lines show up as expected changes.

There is no undo-log line: a password cannot be put back without storing it. The previous password is the team's old one.

### What to watch for

- **Try one device first.** The vendor commands follow each vendor's documentation and were tested against a stand-in device, not real gear.
- **Scored logins.** If the scoring engine logs in to a device, put that device (type `host`, its address) or account on the protected list, or report the new password the way the competition requires.
- **AAA logins** (TACACS+, RADIUS, LDAP) are changed on the AAA server, not here. A Cisco account that is not in the saved config is skipped for this reason.
- **`REVERT NOT CONFIRMED`** means the new password failed AND the old one could not be confirmed. Go to that device's console now.

### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `could not log in with the current password` | Wrong `CCDC_NET_PASS`, wrong account, device unreachable | Check by hand with `ssh`; nothing was changed |
| `account not found in NW-01's saved config` | Cisco: NW-01 not run, or AAA login | Run NW-01; change AAA accounts on the AAA server |
| `new password did not work; old password restored and tested` | The device refused the change (password rules, privilege) | Read the device's password policy; try `--new-password-env` with a password that meets it |
| `config may not be SAVED` | The device closed the first session early | Log in and save (`write memory`) by hand |
| Palo Alto shows failed after a long wait | The commit took longer than `--commit-wait` | Raise `--commit-wait` |
| `sshpass not found` (exit 3) | Not installed | `apt install sshpass` |

---

## 25. Windows enum, `roles/windows-ad/SH-06-windows-enum.ps1` (SH-06)

Read-only inventory of a Windows host: the Windows twin of SH-05. Run it first on every Windows box, in an elevated PowerShell window. It changes nothing.

### How to run it

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File SH-06-windows-enum.ps1 -Out C:\ccdc-out
powershell -NoProfile -ExecutionPolicy Bypass -File SH-06-windows-enum.ps1 -Out C:\ccdc-out -Profile card     # about a minute
powershell -NoProfile -ExecutionPolicy Bypass -File SH-06-windows-enum.ps1 -Out C:\ccdc-out -Only users,ports
```

| Option | What it does |
| --- | --- |
| `-Profile card\|full\|triage` | `card`: system, users, ports, services, autostart, tasks, security, firewall, defender. `full` (default): card plus processes, connections, sessions, shares, software, updates, events, drivers, rights, roles. `triage`: full plus a copy of the event logs |
| `-Only a,b` / `-Skip a,b` | Choose sections; `-List` shows them |
| `-EventHours N` | How far back the events section looks (default 24) |
| `-MaxFlags N` | HIGH/MED flags shown on screen (default 30) |
| `-FromRaw DIR` | Read a saved `raw` folder instead of this host. Send someone the `raw` folder of a run and they can replay it anywhere, PowerShell 7 on Linux included |

### What you get

`<out>\SH-06_<host>_<time>\` holds `summary.txt` (also printed), `flags.csv`, one CSV per section and `raw\` with everything as read. Run it without elevation and the summary says which sections are incomplete.

### What it flags

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

### Problems and fixes

| What you see | Why | Fix |
| --- | --- | --- |
| "running scripts is disabled" | Execution policy | Start it with `powershell -NoProfile -ExecutionPolicy Bypass -File ...` as shown |
| Antivirus deletes or blocks the file | Some checks contain the text of attack commands | The risky words are already split up; if it still happens, note the threat name from Windows Security, Protection history, and report it |
| Sections note "could not be read" | Not elevated, or the tool is missing on this Windows version | Run as administrator; `raw\<name>.error.txt` has the reason |
| Firewall or audit sections empty on a non-English Windows | netsh and auditpol text is read in English | The raw files still hold the output; read them by hand |
| `users` is very long on a DC | A DC's "local" users are the domain's users | Expected; use `-Skip users` for a quick look |
| A flag is legitimate (a Defender exclusion for SQL, a vendor task) | Flags are pointers, not verdicts | Check it, then move on |

---

## 26. Windows backup, `roles/windows-ad/WN-35-backup.ps1` (WN-35)

Saves the settings and files a hardening step or the red team is most likely to break, each with the command that puts it back. Run it right after the enum (SH-06) and before anything is changed. Run it in an elevated window. It changes nothing on the host.

### How to run it

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File WN-35-backup.ps1 -Out C:\ccdc-out -CopyTo \\10.0.0.5\backups
powershell -NoProfile -ExecutionPolicy Bypass -File WN-35-backup.ps1 -Out C:\ccdc-out -Path C:\xampp\htdocs,C:\App\config
powershell -NoProfile -ExecutionPolicy Bypass -File WN-35-backup.ps1 -Out C:\ccdc-out -Only firewall,secpolicy
```

| Option | What it does |
| --- | --- |
| `-CopyTo DEST` | Copy the finished backup to a share or folder. Do this: a red team with admin rights can delete a backup kept on the box |
| `-Path a,b` | Also back up these files or folders (application folders, XAMPP, config files) |
| `-NoWebRoots` | Leave website files out; IIS settings are still saved |
| `-MaxMB N` | Skip any single folder bigger than N MB (default 500). It is listed as not saved |
| `-AdDatabase` | Domain controller: also save the AD database (ntdsutil IFM). It holds every domain password hash: copy it off and delete it from the DC |
| `-Only a,b` / `-List` | Run only some items |

### What it saves

| Item | When | What | How it is put back (RESTORE.txt) |
| --- | --- | --- | --- |
| registry | always | services, Run keys, Winlogon, debugger keys, LSA, RDP, Session Manager, netsh helpers, Defender, policies | `reg import` per area |
| firewall | always | every rule and profile setting | `netsh advfirewall import` |
| secpolicy | always | password and lockout policy, user rights, security options | `secedit /configure` (puts back every setting: read first) |
| auditpol | always | every audit subcategory | `auditpol /restore` |
| tasks | always | every scheduled task's XML | `schtasks /create /xml` |
| hosts | always | `drivers\etc` | copy back |
| users, services | always | lists (no passwords) for comparison | recreate by hand |
| iis, web | IIS installed | settings folder; every site's folder from `applicationHost.config` | copy back between `iisreset /stop` and `/start` |
| dns | DNS server | every zone (dnscmd export), server settings | `dnscmd /zoneadd ... /load` |
| dhcp | DHCP server | scopes, options, reservations, leases | `netsh dhcp server import` |
| gpo | domain controller | every GPO (`Backup-GPO`) and an HTML report | `Restore-GPO` |
| sysvol | domain controller | logon scripts and policy files | copy one file back |
| ad | domain controller | lists of every user, group, computer and OU; AD Recycle Bin state | Recycle Bin (it reports the command to turn it on; that cannot be undone, so it is not done) |
| addb | only with `-AdDatabase` | AD database (install-from-media) | authoritative restore |

Every saved file is hashed in `SHA256SUMS.txt`. The backup folder is limited to Administrators and SYSTEM.

### Problems and fixes

| What you see | Why | Fix |
| --- | --- | --- |
| Most items FAILED | Not an elevated window | Run as administrator |
| `web ... over -MaxMB` | A site folder is bigger than the limit | Raise `-MaxMB`, or copy that folder by hand |
| `gpo` failed on a DC | GroupPolicy module missing | Install the Group Policy Management feature, or skip it with `-Only` |
| A DNS zone FAILED | dnscmd could not export it (cache or system zones are skipped on purpose) | The DNS settings and the dns folder copy are still saved |
| `COPY FAILED` | The share is unreachable or not writable | Check the path and rights; the backup on the box is complete |
| `addb` failed: space in the path | ntdsutil cannot take it | Use `-Out C:\ccdc-out` |

---

## 27. Windows password rotation, `roles/windows-ad/WN-20-password-rotation.ps1` (WN-20)

Gives every enabled account a new password: local accounts on any Windows box, and every domain user when run on a domain controller. The new passwords go to one file for the captain, never to the screen or the log. Dry run unless `-Apply`. Run in an elevated window; on a DC as a domain admin.

### How to run it

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File WN-20-password-rotation.ps1 -Out C:\ccdc-out                         # dry run: read the list
powershell -NoProfile -ExecutionPolicy Bypass -File WN-20-password-rotation.ps1 -Out C:\ccdc-out -Apply -Exclude mark.jacobs,admin
powershell -NoProfile -ExecutionPolicy Bypass -File WN-20-password-rotation.ps1 -Out C:\ccdc-out -Apply -Passwords C:\team\sheet.csv
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

### What it never changes

Guest, DefaultAccount, WDAGUtilityAccount and krbtgt (that has its own two-step reset, WN-22); accounts on the protected list; the account running the script; disabled accounts; and accounts that run a service, scheduled task or IIS app pool on this box or have an SPN (changing those breaks the service until it is given the new password). Each is listed in `accounts.csv` with the reason. It never enables, disables or unlocks an account, and never sets "must change password at next logon" (that would break scored logins).

### What you get

`accounts.csv` (account, scope, state, action, note), `summary.txt`, and with `-Apply` `passwords.csv` (host, account, password, time) readable by Administrators and SYSTEM only. Each change is followed by a logon test with the new password; a failed test is marked in `accounts.csv`. If the script is stopped while changing one account, `pending-password.csv` is left behind: that account has either its old password or the one in that file.

### Problems and fixes

| What you see | Why | Fix |
| --- | --- | --- |
| `no such account here: ...` | A name in `-Exclude` / `-Users` is misspelled or not on this box | Fix it, or add `-IgnoreMissing` |
| `FAILED ... does not meet the password policy requirements` | The domain's policy rejected the password (length, complexity, history) | Use a longer `-Length`, or a different sheet password; the old password still works |
| A service stopped working after the change | Its account was changed with `-IncludeServices` or runs it from another box | Give the service the new password from `passwords.csv` (`sc.exe config NAME password= ...` or the Services console) |
| `the new password did not work in a test logon` | A policy, a lockout or replication delay on a DC | Wait a minute and log on by hand; on a DC check replication |
| Refused: no protected list | `-Apply` needs one | Build `protected.csv` (accounts the scoring engine uses), or pass `-NoProtected` |

---

## 28. Windows safe fixes, `roles/windows-ad/WN-43-safe-fixes.ps1` (WN-43)

Fixes the settings red teams weaken or hide in, choosing only fixes that cannot break a scored service. Dry run unless `-Apply`; every change is recorded first so `-Undo` can put the run back exactly. Run it in an elevated **Windows PowerShell** (`powershell.exe`) window; it refuses to run under PowerShell 7.

### How to run it

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File WN-43-safe-fixes.ps1 -Out C:\ccdc-out                           # dry run: read the list
powershell -NoProfile -ExecutionPolicy Bypass -File WN-43-safe-fixes.ps1 -Out C:\ccdc-out -Apply                    # the safe fixes
powershell -NoProfile -ExecutionPolicy Bypass -File WN-43-safe-fixes.ps1 -Out C:\ccdc-out -Apply -Include rdpnla    # plus one more
powershell -NoProfile -ExecutionPolicy Bypass -File WN-43-safe-fixes.ps1 -Out C:\ccdc-out -Undo latest -Apply       # put the last run back
```

| Option | What it does |
| --- | --- |
| `-Only a,b` / `-Skip a,b` | Make only these fixes / all safe fixes but these |
| `-Include a,b` | Also make these "might affect a service" fixes |
| `-Undo latest\|RUNFOLDER` | Replay that run's `undo-plan.csv` backwards. Dry run unless `-Apply`. A run can be undone once |
| `-List` | List the fixes |

### The fixes

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

### Problems and fixes

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

## 29. Windows firewall, `roles/windows-ad/WN-25-firewall.ps1` (WN-25)

Turns the Windows firewall on for every profile with inbound blocked by default, and allows in only what is scored or in use. The whole firewall is exported first; a rollback task puts it back after a few minutes unless someone confirms from a new connection. Run it in an elevated **Windows PowerShell** (`powershell.exe`) window.

### How to run it

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File WN-25-firewall.ps1 -Out C:\ccdc-out                          # dry run: read the plan
powershell -NoProfile -ExecutionPolicy Bypass -File WN-25-firewall.ps1 -Out C:\ccdc-out -Apply -AdminFrom 10.0.0.5
#   then from a NEW RDP / remote session, within 5 minutes:
powershell -NoProfile -ExecutionPolicy Bypass -File C:\ccdc-out\WN-25_<host>_<time>\keep-firewall.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File WN-25-firewall.ps1 -Out C:\ccdc-out -Undo latest -Apply      # put the old firewall back
```

### What it allows in

| Source | Rule |
| --- | --- |
| Protected list `port` entries | Always, even when nothing listens now (a scored service that is down) |
| `-Allow 80/tcp,53/udp,5000-5100/tcp` | Always |
| Listening now | Every port something listens on, except: loopback only; ports 49152 and up; known backdoor ports (4444, 1337, 31337 ...); a shell, netcat or tunnel listening; a program in Temp, AppData, Users\Public, Downloads; `-Exclude`. Each one left closed is in `not-allowed.csv` with the reason |
| Protected list `host` entries and `-AdminFrom` | Everything from those addresses (the scoring engine, the team's machines). Names are not used, only addresses and networks |
| Ping | ICMP echo, unless `-NoPing` |
| Domain controller | DNS, Kerberos, LDAP, LDAPS, global catalog, SMB, RPC (endpoint mapper and dynamic), NTP, password change |

If the protected list and `-Exclude` disagree, the protected list wins and the run says so.

### What it turns off

Existing inbound allow rules that undo the firewall: one that allows every port, protocol and address with no other limit; one for a shell, netcat or a program in an odd folder; one opening a backdoor port. Rules limited to an app package, an interface, some local addresses or a service are not "allow everything". With `-Strict`, every inbound allow rule that is not ours is turned off, except Active Directory's on a DC.

### Safety and undo

| What | How |
| --- | --- |
| Before anything | `netsh advfirewall export` of the whole firewall to `firewall-before.wfw`. If that fails, nothing changes |
| Rollback timer | A SYSTEM scheduled task (`CCDC-WN25-rollback`) imports that export after `-ConfirmMinutes` (default 5) - it runs even if your session is gone. Allow rules go in before the profiles block, so the box is never closed with nothing open |
| Keep | `keep-firewall.ps1` from a NEW connection cancels the rollback: proof the team can still get in |
| Roll back now | `rollback.ps1` in the run folder |
| Later | `-Undo latest -Apply` (or a run folder) imports the export: every rule and setting back exactly |
| Only our rules | `-Remove` deletes the rules in group `CCDC` and nothing else |
| Two changes at once | Refused while a rollback is waiting |

### Logs

`plan.csv` (each allow rule and why), `disabled.csv` (each rule turned off and why), `not-allowed.csv` (each listener not opened and why), `summary.txt`, the script log, and Windows' own dropped-connection log at `%windir%\System32\LogFiles\Firewall\pfirewall.log` (turned on unless `-NoLog`).

### Problems and fixes

| What you see | Why | Fix |
| --- | --- | --- |
| A scored service stopped answering | It was down when the firewall ran and is not on the protected list | Add it: `-Allow 25/tcp`, or put it in the protected list and run again (after keeping or rolling back) |
| Refused: a change is still waiting | The last run is neither kept nor rolled back | Run its `keep-firewall.ps1`, or `rollback.ps1` |
| "could not create the rollback task" | Task Scheduler service off or not elevated | Nothing changed; fix that, or use `-NoTimer` only at the console |
| A rule comes back | Domain Group Policy firewall rules | Fix the GPO |
| "run this with Windows PowerShell" | Started with `pwsh` | Use `powershell.exe` |
