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
30. Linux session & command logging, `roles/linux/LX-41-session-log.sh` (LX-41)
31. Service hardening (FTP + legacy), `roles/applications/SV-30-service-hardening.sh` (SV-30)
32. Linux persistence sweep, `roles/linux/LX-42-persistence-sweep.sh` (LX-42)
33. Site backup and restore, `roles/applications/SV-15-site-backup.sh` (SV-15)
34. Database hardening, `roles/applications/SV-20-db-hardening.sh` (SV-20)
35. PHP and web app hardening, `roles/applications/SV-21-web-hardening.sh` (SV-21)
36. Database password rotation, `roles/applications/SV-42-db-passwords.sh` (SV-42)
37. Mail password rotation, `roles/applications/SV-40-mail-passwords.sh` (SV-40)
38. Service recovery, `roles/applications/SV-50-service-recovery.sh` (SV-50)
39. Splunk hardening and passwords, `roles/applications/SV-44-splunk-hardening.sh` (SV-44)
40. Web shell hunter, `roles/applications/SV-16-webshell-hunter.sh` (SV-16)
41. Account lockdown, `roles/linux/LX-21-account-lockdown.sh` (LX-21)

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
| What to scan: one host, a range or a subnet; several with spaces | your own network | `--target` |
| How aggressive: 1-2 slow and quiet, 3 normal, 4 fast, 5 fastest (can miss ports) | 4 | `--speed N` |
| Quick scan of the top ports | yes | `--quick` / `--no-quick` |
| How many top ports | 1000 | `--top-ports N` |
| Other ports to always scan, e.g. `8080,9000-9100` | none | `--extra-ports` / `--no-extra-ports` |
| Full scan, all 65535 ports | yes | `--full` / `--no-full` |
| Which hosts get the full scan (asked after the quick scan, when more than one is up) | all up | `--full-hosts "10.0.2.5 10.0.2.7"` |
| Service and version on each open port | yes | `--services` / `--no-services` |
| nmap default scripts (anonymous FTP, SMB signing, ...) | yes | `--scripts` / `--no-scripts` |
| nmap vuln scripts | no | `--vuln` / `--no-vuln` |
| Only the safe vuln scripts (no = all of them; some can crash a service) | yes | `--vuln-all` for all |
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

**It checks for nmap first.** If nmap is missing it says so, prints the install command for your box (`sudo apt install nmap`, `dnf`, `yum`, `zypper`, `apk`, `pacman`) and asks whether to keep going without it. **Without nmap** it falls back to python3, then bash, then `nc -z`: 53 common TCP ports, a banner instead of a version, no scripts, no UDP, at most 1024 addresses.

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
- **Vuln scripts only point.** Nothing found does not mean safe; a hit means check that service now. By default only "safe" ones run, so they will not knock a scored service over. `--vuln-all` can.
- **Speed 5 can miss ports** on a slow or busy network. Use 3 if results look thin.
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

Shows what web sites and databases are on a Linux or Unix host and what is wrong with them: the web servers, every site, **which URL path serves which folder or app**, **which languages and app servers run** (PHP, Python, Node.js, Java, Ruby, .NET), the web roots, PHP settings, web apps and databases. Run it on every box that serves a web site or holds a database, right after the Linux enum. It only reads, and never records a password.

Same look as the Linux enum: numbered sections with flags shown live (`[!] FIX` red, `[*] LOOK` yellow), what was found in green, and a summary at the end.

### The questions

Enter takes the default, and a flag answers each one ahead of time. `--batch` takes all the defaults.

| Question | Default | Flag |
| --- | --- | --- |
| Look at everything? (no = pick the sections) | yes | `--only` / `--skip` |
| Search file contents for web shells and phpinfo pages? | yes | `--fast` (no) / `--deep` (yes) |
| Other web folders to look in? | none | `--webroot DIR` |
| Log in to the databases (read-only)? | yes | `--no-db` / `--db` |

### How to run it

```sh
sudo sh SV-01-web-db-enum.sh --out /root/ccdc-out
sudo sh SV-01-web-db-enum.sh --out /root/ccdc-out --fast                 # skip the web shell content search
sudo sh SV-01-web-db-enum.sh --webroot /opt/app/public                   # a web root the configs don't show
sudo sh SV-01-web-db-enum.sh --only mysql --mysql-cnf /root/my.cnf       # when root can't log in through the socket
```

| Option | What it does |
| --- | --- |
| `--only` / `--skip` | Run or leave out sections: `servers sites paths runtimes webroots php apps mysql postgres datastores` |
| `--fast` | Skip reading file contents (the web shell and phpinfo search). Names, owners and settings are still checked |
| `--webroot DIR` | Also scan this folder as a web root. Repeat for more |
| `--apache-conf FILE` / `--nginx-conf FILE` | Read these config files directly instead of asking the server which files it uses. For when `apachectl` or `nginx` is missing, broken or replaced |
| `--mysql-cnf FILE` | A MySQL client file with a user and password (a `[client]` section). Make it mode 600 and delete it after |

Run it as root. As a normal user it still runs, but it cannot read most configs, log in to PostgreSQL, or see every file; the section table marks those sections `partial`.

**How it logs in to the databases.** MySQL/MariaDB: `--mysql-cnf` if given, then `root` through the local socket (normal on Debian and Ubuntu), then the Debian maintenance account in `/etc/mysql/debian.cnf`, then the client's own defaults. PostgreSQL: as the `postgres` account through the local socket. Queries are SELECT and SHOW only.

### What it produces

In `<out>/web-enum-N/`: `output.txt` (the screen without colour), `summary.txt`, `run.txt`, and a readable `.txt` table for each of these (the CSVs are in `csv/`):

| File | Contents |
| --- | --- |
| `summary.txt` | Web servers, sites, web roots, apps, databases; a section table; HIGH and MED flags |
| `servers.csv`, `fpm_pools.csv` | Each web server and PHP-FPM pool: version, running or not, the account it runs as |
| `sites.csv` | Each Apache virtual host and nginx server block: name, listen address, TLS, web root, config file and line |
| `paths.csv` | Each URL path and what serves it: web roots, aliases, CGI folders, proxies to an app (`ProxyPass`, `proxy_pass`), PHP and uWSGI handlers, status pages |
| `runtimes.csv` | Languages installed (with version), app servers running (gunicorn, uwsgi, Node, Java/Tomcat, puma, dotnet ...), app folders (`package.json`, `manage.py`, `Gemfile`, `.war` ...), and unknown programs on web ports |
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
| HIGH | A development or debug server running (`manage.py runserver`, `flask run`, `php -S`, `node --inspect`, `npm run dev`, Java debug agent): anyone who reaches it can run code; a URL path that serves `/`, `/etc`, `/root` or logs; a file that looks like a web shell; a program file in an upload or media folder; a database dump or `.env` inside a web root; a web server or PHP-FPM pool running entirely as root; `allow_url_include` on; a database account with no password; MySQL root or an admin account allowed from other hosts; a user-defined function (the `lib_mysqludf_sys` backdoor); a PostgreSQL `trust` rule for network logins; logging in to MySQL with no name or password; a Redis or similar store open to the network without a password |
| MED | A server-status page open to everyone; an unknown program serving web traffic on a web port; an app server running as root; directory listing on; a web root owned by the web account; world-writable files in a web root; `.git` folders, backups and phpinfo pages in a web root; app configs every local account can read; MySQL `secure_file_priv` empty; accounts with the FILE privilege; anonymous MySQL accounts; triggers and scheduled events; extra PostgreSQL superusers; `trust` for local logins; a database or data store listening on a network address |
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

Shows every SSH key on the box and every important sshd setting, asks key by key whether to keep it and setting by setting whether to turn it on or off, then installs the result with a revert timer. A changed password does not stop a red team that planted a key; this does. Keep a second root session open while applying.

### How to run it

```sh
sudo sh LX-22-ssh-hardening.sh                        # look and plan: asks, changes nothing
sudo sh LX-22-ssh-hardening.sh --apply --protected /root/protected.csv
sudo sh LX-22-ssh-hardening.sh --apply --batch        # recommended answers, no questions
sudo sh LX-22-ssh-hardening.sh --apply --allow-keys team.pub   # keep only the team's keys
```

### What you see

1. **SSH now**: sshd version and ports, root login and password login as they are now, Match blocks that loosen things, extra key sources, extra sshd processes, `~/.ssh/rc` files.
2. **Keys**: every key of every account, numbered, with fingerprint, comment and file. Red `[!]` = looks planted (forced command, a service account, an account with no shell); yellow `[*]` = check it (root's keys, a file changed in the last 7 days, a key kept outside the home folder).
3. **Questions**.
4. **The plan**: each setting `before -> after`, the keys to remove; the new config is tested with `sshd -t`.
5. **Apply**, the reload check, then keep-or-revert.

### The questions

| Question | Default | Flag |
| --- | --- | --- |
| Keep key #N? (one per key) | yes; **no** for keys that look planted | `--allow-keys FILE`, `--remove-all-keys`, `--keep-all-keys` |
| Move `~/.ssh/rc` to quarantine? (runs at every login) | yes | |
| Allow root to log in over SSH? `[y]` yes, `[n]` no, `[k]` key-only, `[l]` leave | `k` if root keeps a key; otherwise `l`, so root is never locked out | `--root-login yes/no/key-only/leave` |
| Turn off empty-password logins? | yes | `--set emptypw=no` to skip |
| Turn off host-based / .rhosts logins? | yes | `rhosts` |
| Stop users setting environment at login? | yes | `userenv` |
| Turn off X11 forwarding? | yes | `x11` |
| Turn off agent forwarding? | yes | `agent` |
| Limit tries per connection to 4? | yes | `maxauth` |
| Drop connections not logged in after 30s? | yes | `grace` |
| Drop dead idle sessions? | yes | `alive` |
| Log which key logged in (LogLevel VERBOSE)? | yes | `loglevel` |
| Turn OFF password logins? | **no** (scoring logs in with passwords) | `--no-passwords` |
| Turn off TCP forwarding and tunnels? | **no** | `--no-forwarding` |
| Modern ciphers only? | **no** (old clients may fail) | `--strong-crypto` |
| Only these accounts may log in | none | `--allow-users` |
| Apply these changes now? | yes | `--batch` |

Each question shows the current value and one line on what it does. A setting that is already right is shown as `[ok]` and not asked. `--set KEY=yes|no` answers one setting in advance.

### Safety

- **Block at the top.** sshd uses the first value it reads, so the marked block at the top of `sshd_config` wins over the rest of the file and `sshd_config.d`. Nothing else in the file is changed.
- **Tested first.** The new config must pass `sshd -t` or it is not installed.
- **Reload check.** sshd is reloaded (open sessions stay up); if it stops listening the old config is put back at once.
- **Revert timer.** Everything is undone after `--timer` seconds (default 120) unless you confirm, after logging in from a NEW session. A revert also reloads sshd.
- **Evidence.** Removed keys are kept in `quarantine/`; rc files are moved there, not deleted.
- **Protected accounts** keep their keys; a protected root keeps its login.

### What it produces

In `ssh-hardening-N/`: `output.txt`, `summary.txt`, `keys.txt`, `settings.txt`, `csv/`, `quarantine/`, `revert.sh` (after a live apply).

### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `sshd -t rejected the new config` (exit 5) | A setting this sshd version does not know (often `--strong-crypto` on an old OpenSSH) | Run again without that option |
| Scoring's SSH check fails after applying | Password logins off, `AllowUsers`, or crypto | Let the timer revert, or `revert.sh`; apply again without that answer |
| A key file could not be rewritten | `chattr +i` | `lsattr FILE`, `chattr -i FILE`, run again |
| Root login was left alone | root has a password and no key that stays | Give root a team key, or answer `no` once another admin account can sudo |

---

## 18. Linux firewall builder, `roles/linux/LX-25-firewall.sh` (LX-25)

Shows every open port on the box, says what each one is and which program is behind it, asks port by port whether to keep it or drop it, then builds a firewall that drops everything you did not keep. Run it LAST of the Linux hardening, and keep a second session open.

### How to run it

```sh
sudo sh LX-25-firewall.sh                       # look and plan: asks, changes nothing
sudo sh LX-25-firewall.sh --apply --protected /root/protected.csv    # ask, then load the rules
# then, from a NEW ssh session, within 2 minutes:
sudo sh /root/ccdc-out/firewall-1/keep-firewall.sh
# once scoring is green, keep the rules across a reboot:
sudo sh LX-25-firewall.sh --save --apply
```

### What you see

Five sections, colour-coded (KEEP green, DROP red, CHECK yellow, local grey):

1. **The firewall now**: which backend it will use, whether CCDC rules are already live, and whether ufw or firewalld is also running.
2. **Open ports**: one block per listening port.

   ```
   KEEP  tcp 80     HTTP            all addresses  apache2 (pid 812, runs as root)
         command: /usr/sbin/apache2 -k start
         what:    HTTP: the web server. Scored (web store, webmail) in past competitions.
         advice:  a scored service in past competitions
   DROP  tcp 4444   backdoor-style  all addresses  nc (pid 3321, runs as www-data)
         command: nc -lvp 4444 -e /bin/sh
         what:    Not a normal service port: this number is a favourite for backdoors ...
         advice:  suspicious: a bare nc listener is a classic backdoor
   ```

   The command line shows the script behind an interpreter (`python3 /opt/app/server.py`). "Scored in past competitions" comes from `docs/ENVIRONMENT.md`; it is a hint, so check the team packet.
3. **Questions** (Enter takes the default).
4. **The plan**: what stays open, what is dropped, who is always allowed.
5. **Apply**, then the summary.

### The questions

| Question | Default | Flag that answers it |
| --- | --- | --- |
| Your team's addresses that must always get in | none | `--admin CIDR` (repeat) |
| Keep PORT open? (one per listening port) | see below | `--keep 80,53/udp` / `--drop 3306` |
| Other ports to open that are not listening now | none | `--allow 8089/tcp,9000-9010/tcp` |
| SSH only from your team's addresses? (only asked if you gave some) | no | `--ssh-from CIDR` |
| Also limit outgoing traffic? | no | `--restrict-out` / `--no-restrict-out` |
| Block IPv6? | yes | `--drop-ipv6` / `--keep-ipv6` |
| Load these rules now? (with `--apply`) | yes | `--batch` |

Default for each port:

| Port is... | Default | Asked? |
| --- | --- | --- |
| SSH, DHCP client, on the protected list | keep | no |
| Loopback only (127.0.0.1) | left alone: outsiders cannot reach it anyway | no |
| A scored service in past competitions (22, 25, 53, 80, 143, 443, 993, 123/udp, 1433, 8000, 8089, 9997) | keep | yes |
| A normal service, a database, FTP | keep, with a note on when to drop it | yes |
| Unknown | keep, marked CHECK: find out what it is | yes |
| Rarely needed (telnet, rsh, TFTP, SNMP, rpcbind, CUPS, mDNS, VNC, Webmin) | drop | yes |
| A backdoor-style number, a bare `nc`/`socat` listener, a program running from `/tmp` or `/dev/shm`, a deleted program file | drop | yes |

`--strict` turns every "keep" default into "drop" except SSH, DHCP and the protected list. Dropping a port only blocks it from outside; the program keeps running, so also look at what started it.

Other options: `--backend nft|iptables`, `--confirm-timeout N` (default 120; `0` = no timer, console only), `--save` and `--remove` (with `--apply`), `--no-color`, `--batch`.

Always allowed, whatever you answer: loopback, replies to the box's own connections, **ping** (every box has a ping check), DHCP replies, and everything from your team's addresses and the protected hosts (the scoring engine).

### Safety

- **Own rules only.** nftables: table `inet ccdc`. iptables: chains `CCDC-IN`/`CCDC-OUT`, jumped to from the top of `INPUT`/`OUTPUT`. Nothing else is flushed, so Docker, fail2ban, firewalld and ufw keep their rules. `FORWARD` is never touched.
- **Checked first.** The nft ruleset is checked with `nft -c` before loading; if loading fails, whatever loaded is removed.
- **Rollback timer.** After `--apply`, a detached timer removes the rules after `--confirm-timeout` seconds unless `keep-firewall.sh` is run. Run it from a NEW ssh session: that proves new connections still get in, which an open session cannot (open sessions survive any rule). At a terminal the script also asks; answering `y` removes the rules at once.
- **Not saved for reboot** until you run `--save --apply`. Until then a reboot is a last-resort undo.

### What it produces

In `<out>/firewall-N/` (next free number):

| File | Contents |
| --- | --- |
| `output.txt` | Everything shown on screen, without colour |
| `summary.txt` | State (live, rolled back, dry run), what is open and why, what is dropped, the confirm command |
| `ports.txt` | Every listening port: where it is bound, program, pid, account, what it is, the decision and why, the command line |
| `csv/ports.csv` | The same as CSV |
| `ruleset.nft` or `ruleset.iptables.sh` | The exact rules |
| `rollback.sh` | Removes the rules (also in the undo log) |
| `keep-firewall.sh` | Cancels the rollback timer |
| `ROLLED_BACK` | Appears when the timer removed the rules |

Dropped packets are logged with the prefix `CCDC-DROP` (`journalctl -k | grep CCDC-DROP`, or `dmesg`), limited to 10 a minute.

### What to watch for

- **A scored service that is down right now** is not listening, so it is not in the list. Open its port at the "other ports" question, with `--allow`, or put it on the protected list.
- **Unknown ports are kept by default** (marked CHECK) so nothing scored breaks. Read the command line shown with each one; drop what you do not need. `--strict` is the tight option once the protected list is right.
- **Without root** the program behind another account's port shows as `?`.
- **Other firewalls still apply.** A port allowed here can still be blocked by ufw or firewalld rules.
- **Fan-out:** without a terminal the script does not ask; confirm from the admin workstation with `ssh root@box sh .../keep-firewall.sh`, which is itself the "new connection" test.

### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| A port shows program `?` | Not root, or a kernel service | Run with `sudo` |
| `nft rejected the ruleset` (exit 5) | A rule this nft version does not understand | Read the log line; try `--backend iptables` |
| Scoring went red right after applying | A scored port was not open | Wait for the timer or run `rollback.sh`; add the port to the protected list or `--allow`; apply again |
| `too late: the rules were already rolled back` | `keep-firewall.sh` ran after the timer | Apply again and confirm sooner, or use a longer `--confirm-timeout` |
| SSH locked out | `--ssh-from` without your address | Wait for the timer (that is what it is for); from the console run `rollback.sh` |
| Rules gone after a reboot | `--save --apply` was not run | Apply, confirm, then `--save --apply` |
| Under yash, output only appears when the timer ends | yash waits for the detached timer when the script's output is piped | Run it at a terminal, or with another shell |

---

## 19. Linux change watch, `roles/linux/LX-40-change-watch.sh` (LX-40)

Takes a baseline of every place a red team uses to get back in, then checks again (once, or every minute) and prints one alert per change in plain words, worst first. New in 2.0: it also watches **connections**, so a reverse shell calling out shows up with the program, user and command line behind it.

It changes nothing on the host. Start it once the box is hardened.

### How to run it

```sh
sudo sh LX-40-change-watch.sh                      # asks, then watches
sudo sh LX-40-change-watch.sh --batch              # one check, defaults
sudo sh LX-40-change-watch.sh --loop 60 --team 10.0.0.0/24
# keep it running, alerts copied off the box:
nohup sudo sh LX-40-change-watch.sh --batch --loop 60 \
    --alert-cmd "ssh admin@10.0.0.5 'cat >>/srv/alerts/web01.log'" >/root/ccdc-out/watch.out 2>&1 &
sudo sh LX-40-change-watch.sh --accept             # after changing things on purpose
```

### The questions

Enter takes the default. A flag answers each one ahead of time; `--batch` (or no terminal) takes the defaults and does **one** check.

| Question | Default | Flag |
| --- | --- | --- |
| Use the existing baseline? (No = take a new one) | Yes | `--use-baseline` / `--baseline` |
| Seconds between checks (0 = once) | 60 | `--loop N` / `--once` |
| Watch connections too? | Yes | `--conns` / `--no-conns` |
| Your team's addresses (never alerted) | last answer | `--team "10.0.0.5 10.0.0.0/24"` |
| Other web folders to watch | none | `--webroot DIR` |
| Scan the disk for new SUID programs? | Yes | `--suid` / `--no-suid` |

Your answers are saved and become the next run's defaults. With no baseline yet, the first run just takes one.

Other options: `--count N` (stop after N checks), `--suid-every N` (in a loop, the SUID scan runs every Nth check, default 10), `--alert-cmd CMD` (new alert lines go to CMD's stdin), `--state DIR`, `--no-color`.

### What it watches

| Section | What | Severity |
| --- | --- | --- |
| users | New accounts, UID 0, a service account given a login shell | HIGH |
| passwords | Changed (MED), removed/empty (HIGH), unlocked (MED). Only a checksum is kept, never the hash | |
| groups | Says who was added: admin groups (sudo, wheel, docker ...) HIGH, others LOW | |
| files | sudoers, PAM, ld.so.preload, login scripts, hosts, DNS, sshd_config, sysctl, each with what it controls | HIGH for sudo/PAM/preload or new |
| cron | Cron files, at/anacron spools, systemd timers | HIGH |
| units | Boot service files | added HIGH |
| running | A running service stopping (MED, "if it is scored, it is down"); auditd/rsyslog/splunk/wazuh stopping HIGH | |
| keys | authorized_keys added or changed | HIGH |
| ports | New listener with its pid, user and command line. A shell, interpreter, nc, or a program from /tmp listening is HIGH; so is a known backdoor port | |
| connections | New outgoing connection with the program behind it: a shell/interpreter/temp-folder program or attacker port is HIGH (reverse shell), the web server account calling out is HIGH, package updates LOW, anything else MED. New address on SSH, RDP, database or SMB ports is MED (who got in). Team addresses, loopback and web visitors are never alerted | |
| suid | New SUID/SGID program | HIGH |
| web | Files in the web roots: new program file HIGH | |
| modules | Kernel module loaded | HIGH |

### What it produces

Each run gets `<out>/changewatch-N/`: `output.txt` (the screen without colour), `alerts.txt` and `connections.txt` (tables; CSVs in `csv/`), `summary.txt`, `run.txt`.

The state stays in `<out>/watch-<host>/`: `baseline/` and `last/` snapshots, `alerts.log` (every alert ever, one line each), `changes-since-baseline.txt`, `conns-seen`, `settings`.

### What to watch for

- **Your own changes show up too.** Run `--accept` after the team changes something on purpose.
- **Connections are sampled at each check.** One that opens and closes between checks is missed; a reverse shell stays open, so it is caught.
- **Run it as root**, or it cannot see passwords, other accounts' keys or which program owns a connection.
- **Send alerts off the box** with `--alert-cmd`. A red team with root can stop the script.
- **"stopped listening" or "service stopped" on a scored service** means it is down: fix that first.
- **A new web folder** added later joins the baseline quietly, so its existing files aren't alerted.

### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| Hundreds of alerts on the first check | Baseline taken before hardening | `--accept`, then watch |
| Lots of MED outgoing connections | Agents or apps that call out | Add their address to `--team`, or `--accept` (once reported, a connection is not reported again) |
| `passwords`, `keys`, connection programs empty | Not root | Run with sudo |
| Checks are slow | SUID scan on a big disk | Raise `--suid-every`, or `--no-suid` |
| The loop stopped when the session closed | Started without `nohup` | `nohup ... &`, `tmux` or `screen` |

---

## 20. Brute-force and spam banning, `roles/linux/SV-26-banning.sh` (SV-26)

Reads the login logs, counts failed logins per address, and bans an address that passes the limit. Every ban ends by itself after the ban time, so a mistake fixes itself. Spam from a compromised mailbox is reported, not banned.

### How to run it

```sh
sudo sh SV-26-banning.sh                                       # asks; dry run (shows who would be banned)
sudo sh SV-26-banning.sh --protected /root/protected.csv --apply          # asks, then bans
sudo sh SV-26-banning.sh --protected /root/protected.csv --apply --batch --loop 60 --team 10.0.0.0/24
sudo sh SV-26-banning.sh --list                                # who is banned and why
sudo sh SV-26-banning.sh --apply --unban 10.6.6.66             # lift one ban
sudo sh SV-26-banning.sh --apply --unban-all                   # lift every ban now
```

Keep it running with `nohup ... &`, `tmux` or `screen`.

### The questions

Enter takes the default. A flag answers each one ahead of time; `--batch` (or no terminal) takes the defaults and checks **once**. Answers are saved and become the next run's defaults.

| Question | Default | Flag |
| --- | --- | --- |
| Failed logins (SSH, FTP, mail) before a ban | 10 | `--max-fails N` |
| Web login attempts before a ban | 30 | `--web-max N` |
| Ban length in minutes | 30 | `--ban-time MIN` |
| Services to watch | all | `--services "ssh mail"` (ssh ftp mail web pam) |
| Never ban these: your team and the scoring engine | last answer | `--team` / `--ignore ADDR` |
| Seconds between checks (0 = once) | 60 | `--loop N` / `--once` |

**Give it the scoring engine's address.** After a password change the scoring engine fails logins too, and you don't want it banned.

Other options: `--window MIN` (counting window, 10), `--mail-max N` (spam warning, 200), `--log FILE` (read only these logs), `--history N` (lines read on the first check, 2000), `--count N`, `--backend nft|ipset|iptables`, `--state DIR`, `--no-color`.

### What the screen shows

1. **Setup**: your answers.
2. **Logs, firewall, never-ban list**: each log and what it tells you, the firewall it uses, and every never-banned address with the reason (your answer, protected list, this box, the default gateway).
3. **Checks**: one line per check, then each address worst first:
   - `[!] BANNED` (or `[*] WOULD BAN` in a dry run) with services, counts and the accounts tried
   - `[*] NOT BANNED`: over the limit but on the never-ban list, with why (look at it)
   - `[*] SPAM?`: a mailbox sending to lots of people
   - `[-] watching`: under the limit for now
4. **Summary**: totals, who was banned, and the files.

### What it counts

| Service | Log lines |
| --- | --- |
| ssh | `Failed password`, invalid-user scans, `maximum authentication attempts exceeded` |
| ftp | vsftpd `FAIL LOGIN`, proftpd `Login failed`, pure-ftpd `Authentication failed` |
| mail | postfix SASL failures and `Relay access denied`, dovecot `auth failed` |
| web | `POST` to login pages (`wp-login.php`, `xmlrpc.php`, Joomla, `/user/login`, Roundcube, phpMyAdmin, `/login`) and any 401. Other admin pages are not counted |
| pam | any `authentication failure ... rhost=` |
| spam (report only) | postfix `from=<sender> ... nrcpt=N`, summed per sender |

It reads `/var/log/auth.log` or `secure`, the FTP logs, `mail.log` or `maillog`, and the Apache and nginx access logs. With no SSH log file, it reads the journal. Each check reads only what's new since the last one, and the window is the sum of the checks in the last 10 minutes. A rotated log is read from the start again.

### Never banned

Your team answer, protected hosts, this box, loopback and the **default gateway**. With NAT, every outside client looks like the gateway, so banning it would cut off scoring. These show up as `NOT BANNED` so you can decide.

### What it produces

Each run gets `<out>/banning-N/`: `output.txt` (the screen without colour), `bans.txt`, `offenders.txt` (every address with failures, per check, and the verdict; CSVs in `csv/`), `summary.txt` and `run.txt`.

These are kept in `<out>/ban-<host>/`: `bans.csv` (every ban ever), `events.log`, `hits`, `offsets`, `settings`. A dry run keeps its counts in the run folder only, so it never touches the real state, and a dry loop still reads each line once.

The firewall is nftables table `inet ccdc_ban` (address sets with timeouts and one drop rule). Without nftables it uses ipset `ccdc_ban` plus one iptables rule, or one iptables rule per address that a later check removes when it's due. `--unban-all` removes it all. There's no revert timer, because every ban already ends by itself.

### What to watch for

- **Accounts tried** show what the red team is guessing. If a real account is on the list, change its password.
- **`SPAM?`** means a local mailbox is sending to lots of people, so its password is probably known. Change it and check the mail queue.
- **Many addresses with a few tries each** stay under the limit. Lower the limit, or block the range with the firewall script (LX-25).
- **First check:** it reads the last 2000 lines of each log, so old failures can trigger bans straight away. Do a dry run first.

### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `0 new failed login(s)` during an attack | The service logs somewhere else or in another format | Pass the log with `--log`, run with `--debug` |
| `no login logs found` | Not root, or no syslog | Run with sudo; `--log FILE` |
| The scoring engine got banned | Not on the never-ban list | `--apply --unban ADDR`, then give it to the never-ban question |
| `NOT BANNED ... default gateway` | Traffic comes in NATed | Ban by hand only if you're sure |
| `no firewall tool found` (exit 3) | No nft, ipset or iptables | Install nftables |
| Bans gone after a reboot | They're timed and not saved, on purpose | Keep it running in a loop |

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

---

## 30. Linux session & command logging, `roles/linux/LX-41-session-log.sh` (LX-41)

Watches who logs in and what they run, saves it to log files, and prints an alert for anything that looks like the red team. It pairs with LX-40: LX-40 watches config and persistence **state**, this one watches **events** — logins and commands. It reads logs the box already keeps, so it changes nothing (unless you pass `--setup-auditd`).

### How to run it

```sh
sudo sh LX-41-session-log.sh                        # one pass, from now
sudo sh LX-41-session-log.sh --loop 30              # keep watching (Ctrl-C stops)
sudo sh LX-41-session-log.sh --admin "alice bob"    # your admin accounts stay quiet
# keep it running, alerts copied to the admin box:
nohup sudo sh LX-41-session-log.sh --loop 30 \
  --alert-cmd "ssh log@10.0.0.5 'cat >>/srv/alerts/web01.log'" &
sudo sh LX-41-session-log.sh --setup-auditd         # turn on full command logging (a change)
```

### What it logs

| Section | From | What |
| --- | --- | --- |
| logins | the auth log (`auth.log`/`secure`, or journald) | every login with its source address and key-vs-password, failed logins, brute force, sessions |
| priv | the auth log | every `sudo` and `su`, and the command each `sudo` ran, and failures |
| commands | auditd (if recording execve) | every command with user, tty and folder |

Privileged commands (`sudo`/`su`) are always captured from the auth log. **Every** command needs auditd. The script says whether auditd is on and, if not, prints the one rule to add — or adds it with `--setup-auditd`.

### Catching a web shell

A web server almost never runs shell commands, so LX-41 treats the web layer specially:

- **A command run by the web-server account** (`www-data`, `apache`, `nginx`, `httpd`, ...) is always **HIGH** — that is the web shell executing. `--web-user NAME` adds accounts.
- **Where a process runs from:** a program or working folder in `/tmp`, `/var/tmp`, `/dev/shm`, a web root, or a deleted binary is **HIGH**.
- **Requests that were refused** (404/403) are a scanner guessing: they are counted per address and reported as one line, not one each.
- **The web access log** (apache/nginx, auto-found, or `--access-log FILE`) goes to `web.log`, and these requests alert: a known web-shell filename (`wso.php`, `c99.php`, ...), command-injection markers (`cmd=`, `shell_exec`, `base64_decode`, `;id`, `/bin/sh`, ...), and a request to a script that was **dropped into a web root after watching began** (`--webroot DIR` maps the URL to the file). So you see each command the attacker sends to the shell.

### Your own commands don't flood the alerts

An **admin allowlist** decides what reaches the console. It starts from the `sudo`/`wheel`/`adm` group members plus whoever is running the script, and you add to it with `--admin "alice bob"` or `--admin-file`. For those accounts, a normal login or command is **logged but not alerted**. It only alerts on them if the command itself is dangerous. Everyone else alerts.

| Severity | When |
| --- | --- |
| HIGH | A dangerous command by anyone (reverse shell, `curl\|sh`, `base64 -d\|sh`, `nc -e`, wiping history). A login or command by an account not in `/etc/passwd`. Root logging in over the network with a password. A burst of failed logins from one address |
| MED | A login or command by a non-admin account. A sudo auth failure |
| LOW (file only, `--low` to show) | An admin doing something sensitive (`useradd`, editing sudoers, `wget`), kept for the record |

`--all-commands` alerts on every command; `--alert-own` also alerts on admins' normal commands.

Three things keep the console readable when a box is busy:

- **Repeats are held back.** The same alert is shown once, then kept quiet for `--repeat-after` seconds (default 600; `0` shows every repeat). A scoring engine that logs in every minute shows up once. The pass line says how many repeats were held back, and every event is still in its log file.
- **Who ran it is the login account.** `bob as root` means bob after `sudo` or `su`. Root commands from a non-admin's session alert; your admins' do not.
- **Daemons are logged, not alerted.** A service account with no terminal (postfix, a cron job) is doing its job. Web-server accounts are the exception: they always alert.

It also flags from the auth log: a login that **succeeds after many failures** from the same address, a slow brute force that adds up across checks, `sudo` by an account that is not allowed, `su` to root by a non-admin, a **new account**, an account **added to sudo/wheel**, and password changes. And it says so if the auth or audit log is suddenly empty or gone.

### Options

| Option | What it does |
| --- | --- |
| `--loop N` / `--count N` | re-check every N seconds (min 5); stop after N checks |
| `--admin "U1 U2"` / `--admin-file F` | accounts to keep quiet, on top of the auto-detected ones |
| `--alert-own` / `--all-commands` | make admin / all commands show |
| `--low` | also show LOW alerts on the console |
| `--repeat-after N` | show the same alert again only after N seconds (default 600; 0 = always) |
| `--from-start` | process existing log history on the first pass (default: from now) |
| `--alert-cmd CMD` | run CMD with the new alert lines on its stdin (send them off-box) |
| `--setup-auditd` | add the auditd execve rule so every command is logged, and offer to keep it after a reboot (the one change; undo lines are written) |
| `--auth-log` / `--audit-log` | point at specific log files |
| `--max-mb N` | roll a log over at N MB (default 50) |
| `--state DIR` | where the logs and read-positions live (default `<out>/sesslog-<host>`) |

### Outputs

In the state folder (`<out>/sesslog-<host>/`): `alerts.log` (the flagged subset, same format as LX-40), `logins.log`, `priv.log`, `commands.log`. A restart keeps the same files and read-positions and carries on.

### What to watch for

- **Without auditd you still get logins and every `sudo` command** — the privileged ones that matter most. `--setup-auditd` adds the rest.
- **The alert is a pointer, not a verdict.** A clean-looking command by an admin isn't alerted; read `commands.log` for the whole picture.
- **The red team can stop auditd or delete logs.** LX-40 alerts if the audit service disappears; keep the off-box copy (`--alert-cmd`) as the real record.
- **Keep it hard to kill, not hidden.** Run it under `nohup`/`tmux`/`screen`, or as a plain systemd service, so it restarts — that beats trying to hide it, which looks like malware to the graders.

### Problems and fixes

| What you see | Why | Fix |
| --- | --- | --- |
| `not running as root` warning, nothing logged | The auth and audit logs need root | `sudo` |
| `auditd is not logging commands` | No execve rule loaded | `--setup-auditd`, or add the printed `auditctl` line |
| Only `sudo` commands show up | Same as above | Turn on auditd |
| Your own admin work fills the console | Those accounts aren't on the allowlist | `--admin "name"`, or check the auto-detected list in the start line |
| The loop stopped when the session closed | Started without `nohup` | Use `nohup ... &`, `tmux` or `screen` |


---

## 31. Service hardening (FTP + legacy), `roles/applications/SV-30-service-hardening.sh` (SV-30)

Hardens the insecure services on a Linux box — FTP first, then telnet, rsh/rlogin/rexec, TFTP, SNMP and the old inetd services. Every action is graded by how risky it is, and the script only goes as far as the level you pick.

### Levels

| `--level` | Does | Behaviour |
| --- | --- | --- |
| **safe** (Enter) | only `safe` actions | applies; can't lock anyone out. FTP config changes need a restart of the FTP daemon, which the script does and checks |
| **service** | adds `service` actions | applies, checks the service still answers, **undoes just that change if it broke** |
| **access** | adds `access` actions | can disable a daemon; covered by the revert timer and **skipped for a scored service** |

Each level includes the ones before it. If you don't pass `--level`, it asks. It shows the plan first (dry run), asks about each action (Enter takes the default; `safe`/`service` default yes, `access` defaults no unless you name it in `--only`), then `--apply` makes the changes with the revert timer running.

### How to run it

```sh
sh SV-30-service-hardening.sh                                    # dry run, safe, asks
sudo sh SV-30-service-hardening.sh --apply --protected prot.csv  # apply the safe FTP fixes
sudo sh SV-30-service-hardening.sh --apply --level service --protected prot.csv
sudo sh SV-30-service-hardening.sh --apply --level access --only ftp-disable --protected prot.csv
```

`--apply` needs a protected list (`--protected FILE`, or `--no-protected` to accept the risk) — that's what stops it disabling a scored service by accident. `--exclude vsftpd` leaves a service alone; `--force-scored` allows disabling one the host list marks scored.

### FTP, graded

| Action | Risk | Effect |
| --- | --- | --- |
| `ftp-anon` | safe | turn off anonymous login |
| `ftp-accounts` | safe | deny root/system accounts FTP (`/etc/ftpusers`) |
| `ftp-perms` | safe | lock the config file to 600 |
| `ftp-logging` | safe | log transfers (`xferlog_enable`), hide the version banner |
| `ftp-chroot` | service | jail users to their home (adds `allow_writeable_chroot` so it doesn't break) |
| `ftp-tls` | service | reports the lines to require FTPS/TLS |
| `ftp-disable` | access | stop and disable the FTP service |

vsftpd config is edited in full. pure-ftpd: anonymous off is written (`conf/NoAnonymous`). proftpd: an `<Anonymous>` block is reported for you to remove.

**After FTP config changes it restarts the FTP daemon** (it only reads its config at start), checks it is running and listening again, and puts the config back if it is not. Open FTP sessions drop for a moment. A daemon that was stopped is left stopped. The other services: `telnet-disable`, `rsh-disable`, `tftp-disable`, `snmp-default` (flags default community strings), `snmp-disable`, `legacy-disable` (finger/echo/chargen/daytime/discard).

### Outputs

In `service-hardening-N/`: `output.txt`, `plan.txt`, `changes.txt`, `summary.txt`, `csv/`, and `revert.sh` (when a live apply changed something). Same look and undo as LX-39.

### What to watch for

- **A `service`-level change is verified by whether the service still runs** after a reload; if it stopped, that one change is put back automatically.
- **Don't disable a scored service.** Keep `--force-scored` off and pass your scored services in the protected list — `access` actions skip anything protected.
- **ftp-tls and snmp-default are reported, not applied** — TLS needs a cert and a new SNMP community must be coordinated, so they're yours to set.


---

## 32. Linux persistence sweep, `roles/linux/LX-42-persistence-sweep.sh` (LX-42)

Finds the ways an attacker makes sure they get back in or their code keeps running, then (with `--apply`) asks finding by finding whether to remove it. Run it after the enum and the safe fixes, and again whenever the red team has been on the box.

### How to run it

```sh
sudo sh LX-42-persistence-sweep.sh                    # asks what to scan, then looks
sudo sh LX-42-persistence-sweep.sh --batch            # full scan, no questions
sudo sh LX-42-persistence-sweep.sh --areas cron,ssh,systemd
sudo sh LX-42-persistence-sweep.sh --apply --protected /root/protected.csv   # look, then ask what to remove
```

### The questions

| Question | Default | Flag |
| --- | --- | --- |
| Do a full scan? | yes | `--full` |
| (if no) Which areas? | cron systemd ssh shell accounts | `--areas a,b` |
| Other folders to search for planted programs and web shells | none | `--scan-dir /opt` |
| How many days back counts as recently changed? | 7 | `--since N` |
| Compare key system programs with their packages? | yes | `--pkg-check` / `--no-pkg-check` |
| Accounts to leave out | none | `--ignore-user` (and `--ignore-path`) |
| (with `--apply`) Remove finding #N? one per finding | **no** (`--yes-high`: yes for HIGH) | |

### What it looks at

| Area | Where |
| --- | --- |
| cron | /etc/crontab, cron.d, cron.hourly/daily/..., every user crontab, `at` jobs |
| systemd | units, timers, drop-in overrides, user units, generators |
| boot | rc.local, init.d, motd / network / DHCP / sleep hook folders, udev rules, apt hooks, logrotate scripts, inetd/xinetd, desktop autostart |
| ssh | every authorized_keys (forced commands, service accounts, accounts with no shell), sshd settings that add keys or commands, ~/.ssh/rc, /etc/ssh/sshrc |
| shell | /etc/profile, profile.d, every user's bashrc/profile/zshrc: reverse shells, `alias sudo=...`, LD_PRELOAD, PATH tricks, history hiding |
| preload | /etc/ld.so.preload, linker config, LD_PRELOAD in service settings and running processes |
| accounts | extra UID 0, hashes in /etc/passwd, service accounts that can log in, sudoers (NOPASSWD ALL), docker/lxd/disk groups |
| pam | pam_exec, pam_permit as sufficient, PAM modules no package installed, nsswitch |
| kernel | modules loaded at boot or loaded now with no file on disk, modprobe `install` tricks, core_pattern and modprobe hooks |
| files | programs in /tmp and /dev/shm, `...` folders, files in /dev, commands shadowed in /usr/local/bin, system programs no package installed or that do not match their package, SUID/SGID (GTFOBins), capabilities, immutable files, Python startup hooks |
| procs | deleted programs, programs run from /tmp or memory, fake kernel-thread names, shells holding a connection |
| web | web shell code, scripts in upload folders, recently changed scripts, `.htaccess`/php.ini tricks |
| misc | mail aliases and `.forward` that run programs, polkit rules, a world-writable docker socket |

**HIGH** = almost certainly planted or dangerous. **MED** = unusual, look at it. **LOW** = context (in `findings.txt`; `--low` shows them). "Not from a package" means the package database does not know the file; in a place only packages write to, that is the clearest sign.

### Removing

With `--apply` it asks about each HIGH and MED finding that can be removed. Files are **moved** to `quarantine/`, never deleted; single lines (a cron entry, a key, a line in .bashrc) are taken out after a backup; units are stopped and disabled first; SUID is taken off. All of it is undone by `revert.sh` and by the revert timer. Killing a process is asked separately (default no) and cannot be undone.

### What to watch for

- **Removing persistence does not remove the attacker.** Change passwords (LX-20), check the logs (LX-41) for how they got in.
- **Hand-installed software** (in /opt, /usr/local) is "not from a package" too: it shows as MED or LOW unless something else is wrong.
- **A kernel rootkit can hide files** from any scanner; the kernel area and the package check are the tell-tales.
- **Without root** other accounts' files and processes cannot be read.

### Outputs

In `persistence-N/`: `output.txt`, `summary.txt` (counts per area, HIGH and MED list), `findings.txt` (every finding, numbered), `csv/`, `quarantine/`, `revert.sh`. No password hash is ever written.

---

## 33. Site backup and restore, `roles/applications/SV-15-site-backup.sh` (SV-15)

Keeps every web site restorable. It backs up each site's files and database, checks a site against the backup at any time, and puts back **only what changed** when the red team defaces a page, deletes files, plants a web shell or wipes the database. Your own fixes elsewhere stay put.

**Back up after cleaning.** A web shell that is already there goes into the backup and looks normal to the check. Run SV-01 first.

### How to run it

```sh
sudo sh SV-15-site-backup.sh                                   # asks what to do
sudo sh SV-15-site-backup.sh --backup --batch                  # back up every site
sudo sh SV-15-site-backup.sh --check --batch                   # what changed? (changes nothing)
sudo sh SV-15-site-backup.sh --restore                         # dry run: shows what it would put back
sudo sh SV-15-site-backup.sh --restore --protected p.csv --apply
```

### The questions

| Question | Answers | Flag |
| --- | --- | --- |
| What do you want to do? | `[b]` back up, `[c]` check, `[r]` restore (default: back up if there is no backup yet, else check) | `--backup` / `--check` / `--restore` |
| Which sites? (backup) | all, or names | `--site NAME` |
| Back up each site's database too? | yes / no | `--db` / `--no-db` |
| Copy the backup off the box? | an scp destination | `--copy-to DEST` |
| Per site (restore) | `[a]` all back to the backup, `[f]` files only, `[q]` quarantine new files only, `[n]` nothing | `--what all/files/new/none` |
| Put the database back too? (restore) | yes / no (default no) | `--restore-db` / `--no-restore-db` |

### What it does

- **Finds the sites** from the Apache and nginx configs, every folder in `/var/www`, and `--webroot DIR`.
- **Finds each site's database** in the app's own config: WordPress, Joomla, Drupal, PrestaShop, OpenCart, Magento, Roundcube or `.env`. MySQL/MariaDB and PostgreSQL are dumped. SQLite files are already in the file archive. A database on another host is reported, not dumped.
- **Backup** writes `site-backup-N/`. For each site: `files.tar.gz`, a hash of every file (`files.sha256`) and the database dump. Once per box: the Apache, nginx and PHP configs. The folder is mode 700, because it holds dumps and passwords.
- **Check** compares each site with the newest backup (or `--from DIR`):
  - **CHANGED** files: a page means "defaced?", code means "backdoor added?", and a changed `.htaccess` is HIGH
  - **DELETED** files
  - **NEW** files: a new `.php`/`.jsp`/`.asp`/`.sh` is HIGH ("web shell?"), anything else LOW
  - changed web server and PHP config files
- **Restore** does the same comparison, then for each site puts back changed and deleted files (owners and modes kept), moves new files to quarantine, and loads the database if you said so. The current files and database are saved first, and a revert timer runs. Afterwards it checks again that the site matches. A site whose files are unchanged is still offered a database restore.

### What to watch for

- **Real uploads since the backup show as NEW.** They are moved to quarantine, not deleted, so look before saying `[a]`, or use `[f]`.
- **Database restore loses everything since the backup**, including real orders or mail. The current database is saved in `before/` and the revert puts it back.
- **Web server configs are reported, not restored,** because a bad config breaks the site on restart. `RESTORE.txt` in the backup shows how to put one back and test it.
- **Permissions are not compared,** only content. LX-40 watches for permission changes.
- **Back up again after big fixes,** so the check compares against the clean state. `--keep N` drops old backups.

### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `no site backup found` (exit 3) | No `--backup` yet in this `--out` | Run `--backup` first, or `--from DIR` |
| `database ...: could not log in` | root cannot log in through the socket | `--mysql-cnf FILE` with a `[client]` user and password |
| The backup is too big | Media or caches | `--exclude '*/cache/*'`, or raise `--max-mb` |
| A site is missing | Its folder is outside the usual places | `--webroot DIR` |

---

## 34. Database hardening, `roles/applications/SV-20-db-hardening.sh` (SV-20)

Locks down MySQL/MariaDB behind the web apps without breaking them. It lists every database account and **which app uses it**, read from the apps' own configs. Then it offers each fix, graded like SV-30. After the changes, the site must still load, or everything is put back.

**Back up first** (SV-15 or SV-14).

### How to run it

```sh
sudo sh SV-20-db-hardening.sh                                         # dry run, asks
sudo sh SV-20-db-hardening.sh --protected p.csv --apply --level service
sudo sh SV-20-db-hardening.sh --protected p.csv --apply --batch --level safe --url http://127.0.0.1/shop/
```

### The questions

| Question | Answers | Flag |
| --- | --- | --- |
| Which box is this? | `[s]plunk [w]ebmail [e]comm [o]ther` | `--box` |
| How far should I go? | `[s]afe`, `[v]` service, `[a]ccess` | `--level` |
| Each fix | `[y]` do it / `[n]` skip it (access-level fixes default to no) | `--only` / `--skip` |
| Apply these changes? | `[y]` / `[n]` | `--batch` |

### The fixes

| Fix | Level | What it does |
| --- | --- | --- |
| `db-anon` | safe | Drops anonymous accounts (`''@host`: anyone gets in) |
| `db-testdb` | safe | Drops the `test` database, only if it is empty |
| `db-infile` | safe | `local_infile` off now and after restarts |
| `db-remoteroot` | service | Drops root accounts allowed from other hosts |
| `db-emptypw` | service | Locks accounts with **no password** that no app uses |
| `db-file` | service | Takes the FILE right (read/write any file: a web shell into the web root) from accounts other than root and the server's own admins |
| `db-apppw` | service | A new random password for each app's database account, written into the app's config in the same step (WordPress, Joomla, PrestaShop, OpenCart, Roundcube, `.env`) |
| `db-bind` | access | Listens on 127.0.0.1 only, when every app is on this box (restarts the database) |
| `db-udf` | access | Drops user-defined functions such as `sys_exec` from lib_mysqludf_sys, the classic way to run commands through the database |

**Reported, not changed:** accounts with SUPER/FILE/GRANT, unused accounts allowed from any host with admin rights (red: planted?), triggers and scheduled events, an empty `secure_file_priv`, where the server listens, and PostgreSQL `trust` logins.

### Safety

- **Site check:** before and after the changes it loads `--url` (default `http://127.0.0.1/`). If the site worked before and doesn't now, or a database error appears, everything this run changed is put back on the spot. A site that was broken before and works afterwards counts as fine. PHP rereads its config only every few seconds, so a failure is retried for 10 seconds before it counts.
- **Undo:** each account is saved before it changes (`before/`, root only, since it holds password hashes). The undo restores dropped accounts and old passwords in both the database and the config, gives rights back, and removes the drop-in config file. The revert timer runs as usual.
- **Passwords:** new app passwords go only into the app config and `passwords.txt` (mode 600), never the screen or the logs.

### What it produces

In `db-hardening-N/` (mode 700): `output.txt`, `accounts.txt` (every account, how it logs in, its rights, which app uses it), `plan.txt`, `changes.txt`, `summary.txt`, `passwords.txt` (only with `db-apppw`), `before/`, and `revert.sh`.

### What to watch for

- **An app whose config isn't recognised** keeps its password. `db-apppw` only changes accounts it can also write into the app's config.
- **A scoring check that logs in to the database directly** isn't known to the script. Put that account on the protected list.
- **Dropping a UDF can't always be undone:** the undo needs the `.so` file, and a planted function is usually broken anyway. Delete the `.so` from the plugin folder by hand.
- **`db-bind`** says so if another config file still sets `bind-address` after the script's file.

### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `could not log in` (exit 3) | root can't log in through the socket | `--mysql-cnf FILE` with a `[client]` user and password |
| `cannot check the site` | No curl/wget, or nothing on `--url` | Give the store's address with `--url`, or install curl |
| `APPLIED, then PUT BACK` | The site broke after a change | Look at `changes.txt`, then rerun with `--skip` for that fix |
| An app account is listed `used by: -` | Its config is outside /var/www, /srv, /opt | `--webroot DIR` |


## 35. PHP and web app hardening, `roles/applications/SV-21-web-hardening.sh` (SV-21)

Makes the web apps hard to take over and makes an uploaded web shell useless, without taking the site down. It finds the apps first (WordPress, Joomla, Drupal, PrestaShop, OpenCart, Magento, Roundcube), then offers each fix, graded like SV-20. After the changes, the site must still load, or everything is put back.

**Back up first** (SV-15).

### How to run it

```sh
sudo sh SV-21-web-hardening.sh                                         # dry run, asks
sudo sh SV-21-web-hardening.sh --protected p.csv --apply --level service
sudo sh SV-21-web-hardening.sh --protected p.csv --apply --batch --level safe --url http://127.0.0.1/shop/
```

### The questions

| Question | Answers | Flag |
| --- | --- | --- |
| Which box is this? | `[s]plunk [w]ebmail [e]comm [o]ther` | `--box` |
| How far should I go? | `[s]afe`, `[v]` service, `[a]ccess` | `--level` |
| Each fix | `[y]` do it / `[n]` skip it (access-level fixes default to no) | `--only` / `--skip` |
| Each new WordPress admin | `[k]eep` / `[d]emote` to subscriber | `--admins` |
| Apply these changes? | `[y]` / `[n]` | `--batch` |

### The fixes

| Fix | Level | What it does |
| --- | --- | --- |
| `php-urlinclude` | safe | `allow_url_include = Off` (no including code from another server) |
| `php-errors` | safe | `display_errors = Off`, `log_errors = On` (error pages show paths and SQL) |
| `php-expose` | safe | `expose_php = Off` (no PHP version in the headers) |
| `app-config` | safe | App config files (they hold the database password) become `root:www-data 640` |
| `wp-fileedit` | safe | WordPress: `DISALLOW_FILE_EDIT`, no editing theme/plugin code from the admin panel |
| `upload-nophp` | service | PHP can't run in upload folders: an uploaded web shell gets 403 |
| `block-files` | service | `.git`, `.env`, backups, `.sql` dumps and archives can't be downloaded |
| `wp-xmlrpc` | service | Blocks `xmlrpc.php` (password guessing, many tries per request) |
| `wp-admins` | service | Lists WordPress admins; ones made in the last `--days` days are asked about one by one |
| `php-functions` | access | `disable_functions` adds system, exec, shell_exec, passthru, proc_open, popen, pcntl_exec (keeps what was there) |
| `code-readonly` | access | The web server account no longer owns the site's code; upload, cache and temp folders are left alone |

PHP settings go into the apache2, fpm and cgi `php.ini`, never the command line one. Apache rules go in one file, `zz-ccdc-web.conf`. **nginx is not edited:** the lines go into `nginx-ccdc.conf` in the run folder to include by hand.

**Reported, not changed:** phpinfo pages, app versions.

### Safety

- **Site check:** `--url` (default the home page and each app folder) is loaded before and after. Worse afterwards (stopped working, or a PHP/database error shows) puts everything back on the spot. Retried for 10 seconds for PHP's cache.
- **Config test** (`apache2ctl -t`, `php-fpm -t`) before each reload. A failed test puts everything back.
- **Undo:** every file is backed up, every owner and mode recorded (`owners-*.txt` for `code-readonly`), the drop-in removed, demoted admins made admins again. The revert timer runs as usual.

### What it produces

In `web-hardening-N/`: `output.txt`, `apps.txt`, `plan.txt`, `changes.txt`, `summary.txt`, `nginx-ccdc.conf` (when nginx is there), `owners-*.txt`, `revert.sh`.

### What to watch for

- **`php-functions`** can break features that run programs (image tools, some mail, backup plugins). The site check only loads pages: click through checkout after it. A broken feature says "has been disabled for security reasons".
- **`code-readonly`** stops updates and plugin installs from the admin panel. That's the point during the competition.
- **A new admin you made yourself:** answer `k`. Put team accounts on the protected list.

### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `no known app found` | The site is outside /var/www, /srv, /opt | `--webroot DIR` |
| `could not read wp_users` | WordPress not set up, or root can't log in | `--mysql-cnf FILE` |
| `APPLIED, then PUT BACK` | The site broke after a change | Look at `changes.txt`, rerun with `--skip` for that fix |
| A web shell in uploads still runs on nginx | nginx is not edited | Include `nginx-ccdc.conf` in the server block, `nginx -t`, reload |

## 36. Database password rotation, `roles/applications/SV-42-db-passwords.sh` (SV-42)

New passwords for every MySQL/MariaDB and PostgreSQL account that logs in with one. If an app uses the account, its config gets the new password in the same step, so the store keeps working. Each new password is tested by logging in with it.

### How to run it

```sh
sudo sh SV-42-db-passwords.sh                                    # dry run, asks
sudo sh SV-42-db-passwords.sh --protected p.csv --apply          # asks about each account
sudo sh SV-42-db-passwords.sh --protected p.csv --apply --batch --url http://127.0.0.1/shop/
```

### The questions

| Question | Answers | Flag |
| --- | --- | --- |
| Which box is this? | `[s]plunk [w]ebmail [e]comm [o]ther` | `--box` |
| Go through each account one by one? | `[y]` / `[n]` (use the table's defaults) | `--batch` |
| Each account | `[r]andom` `[s]et` (typed twice, not shown) `[l]ock` `[k]eep` `[a]ll the rest default` | `--users`, `--exclude`, `--passwords` |
| A protected account | extra `[y]` / `[n]`, default no | protected list |
| Apply these changes? | `[y]` / `[n]` | `--apply` |

### What it does

- **Lists every account:** where it can log in from, how it logs in, which app uses it. HIGH: no password, a PostgreSQL superuser that isn't `postgres`, `trust` lines in pg_hba.conf.
- **Leaves alone** accounts that log in by OS account only (unix_socket, peer), locked accounts and roles that can't log in. Root on Debian/Ubuntu MariaDB is one of these.
- **App accounts:** new password in the database and in the config: WordPress, Joomla, PrestaShop, OpenCart (both configs), Roundcube, `.env`, and `[client]` files like `/root/.my.cnf`.
- **Keeps a unix_socket login** when an account has both.
- **The account it logs in with** is changed last.
- **Tests each new password** by logging in. If that fails, the old one goes back on the spot. An account allowed only from another host is marked "not tested".
- **Site check:** `--url` (default the home page and each app folder) must still load afterwards. If not, every old password comes back.

### Safety

- Dry run unless `--apply`. Revert timer (120 s). Every account is saved first in `before/` (root only, it holds the hashes).
- The undo puts back the old password (even an empty one), unlocks what was locked, restores the configs, and renames `passwords.txt` to `passwords-UNDONE-not-valid.txt`.
- New passwords only go in `passwords.txt` (mode 600), never on screen or in the logs.

### What it produces

In `db-passwords-N/` (mode 700): `output.txt`, `accounts.txt`, `plan.txt`, `summary.txt`, `passwords.txt`, `before/`, `revert.sh`.

### What to watch for

- **The scoring engine may log in to the database itself.** Put that account on the protected list, or report the new password in the scoring portal.
- **"used by: -"** means no config names the account. A hard-coded password in a PHP file isn't found, but the site check catches it and puts everything back.
- **PostgreSQL apps:** only `.env` configs are updated.
- **`trust` in pg_hba.conf** lets anyone in without any password. Fix that first.

### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `nothing to rotate` | Can't log in to either database | Run as root, or `--mysql-cnf FILE` |
| `failed: the new password did not work` | The login test failed (pg_hba, host limits) | Old password is back; check the log |
| `APPLIED, then PUT BACK` | The site broke | An app uses an account its config check missed: `--exclude` it, or `--webroot DIR` |
| `no such database account` (exit 2) | A typo in `--users`/`--exclude` | Fix the name |

## 37. Mail password rotation, `roles/applications/SV-40-mail-passwords.sh` (SV-40)

New passwords for the mail users: the IMAP, SMTP and webmail logins. It reads Dovecot's config to find where the passwords live, then changes them there. Each new password is tested with a real IMAP login.

### How to run it

```sh
sudo sh SV-40-mail-passwords.sh                                  # dry run, asks
sudo sh SV-40-mail-passwords.sh --protected p.csv --apply        # asks about each user
sudo sh SV-40-mail-passwords.sh --protected p.csv --apply --batch
```

### The questions

| Question | Answers | Flag |
| --- | --- | --- |
| Which box is this? | `[s]plunk [w]ebmail [e]comm [o]ther` | `--box` |
| Go through each user one by one? | `[y]` / `[n]` (use the table's defaults) | `--batch` |
| Each user | `[r]andom` `[s]et` (typed twice, not shown) `[l]ock` `[k]eep` `[a]ll the rest default` | `--users`, `--exclude`, `--passwords` |
| A protected user | extra `[y]` / `[n]`, default no | protected list |
| Apply these changes? | `[y]` / `[n]` | `--apply` |

### Where the passwords are

| Dovecot / Postfix uses | What SV-40 does |
| --- | --- |
| System accounts (`pam`, `shadow`, `passwd`) | Changes the accounts that have a mailbox (`/var/mail/USER`, `~/Maildir`, `~/mail`) with chpasswd. `--all-accounts` takes every human account. Root is never included (LX-20 changes it). |
| `passwd-file` (e.g. `/etc/dovecot/users`) | Writes a new `{SHA512-CRYPT}` hash in the user's line, keeps the rest of the line, empties Dovecot's login cache |
| Postfix Cyrus SASL (`/etc/sasldb2`) | `saslpasswd2` (not tested by login) |
| `sql`, `ldap` | Listed only: change them where they live |

**Flagged:** Dovecot **master** users (they can open any mailbox), a `static` passdb (one password for everyone), users with no password.

### Safety

- Dry run unless `--apply`. Revert timer (120 s). The old hash of each user is saved in `before/` (root only).
- Each new password is tested by an IMAP login (993, or 143 with STARTTLS). If the login fails, the old password goes back on the spot.
- The undo puts every old hash and line back, and renames `passwords.txt` to `passwords-UNDONE-not-valid.txt`.
- New passwords only go in `passwords.txt` (mode 600).

### What it produces

In `mail-passwords-N/` (mode 700): `output.txt`, `users.txt`, `plan.txt`, `summary.txt`, `passwords.txt`, `before/`, `revert.sh`.

### What to watch for

- **The scored IMAP and webmail checks log in as a mail user.** Put that user on the protected list, or report its new password in the scoring portal.
- **Webmail (Roundcube)** and Postfix SMTP through Dovecot use these same passwords. Nothing else to change.
- **System mail users are also Linux logins.** Running LX-20 afterwards would change them again. Use `--exclude` there, or run only one of the two.

### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `nothing to rotate` | No Dovecot passdb or SASL database | Mail is somewhere else: check `doveconf -n` |
| `no mail users found` | System accounts have no mailbox yet | `--all-accounts` |
| `failed: the new password did not log in` | IMAP refused it (wrong passdb order, a deny list) | The old password is back; check `doveconf -n` |
| `login not tested here` | No IMAP on 993/143, or openssl missing | Log in from the webmail yourself |

## 38. Service recovery, `roles/applications/SV-50-service-recovery.sh` (SV-50)

Run this when a scored service goes red. It checks every service on the box the same way, finds **why** it's down, and offers the fix. A plain restart often fails because red team broke something underneath.

Services: web (apache2, httpd, nginx), php-fpm, database (mariadb, mysql, postgresql), mail (dovecot, postfix), splunk, ssh, time (chrony, ntp). Only the ones installed are checked. With two web servers, only the one in use counts.

### How to run it

```sh
sudo sh SV-50-service-recovery.sh                                    # check everything, dry run
sudo sh SV-50-service-recovery.sh --protected p.csv --apply          # check and fix (asks each fix)
sudo sh SV-50-service-recovery.sh --protected p.csv --apply --batch --services web,mysql
sudo sh SV-50-service-recovery.sh --protected p.csv --watch 30 --auto-restart --apply   # keep it running
```

### The questions

| Question | Answers | Flag |
| --- | --- | --- |
| Which box is this? | `[s]plunk [w]ebmail [e]comm [o]ther` | `--box` |
| Check which services? | `[a]ll` found / `[s]` only the scored ones for this box | `--services` |
| Each fix | `[y]` / `[n]` | `--fix KINDS` answers yes for those kinds |

### What it checks, per service

| Check | Found | Fix offered |
| --- | --- | --- |
| Running? | stopped, failed | start / restart (**only if the config test passes**) |
| Masked / disabled at boot? | masked, or disabled when scored | unmask, enable |
| Config loads? | `apache2ctl -t`, `nginx -t`, `php-fpm -t`, `postfix check`, `doveconf`, `sshd -t` | none: error lines shown, never restarted on a broken config |
| Port | another program holds it | stop it (default yes if it runs from /tmp, /dev/shm or a deleted file) |
| Answers? | HTTP status (5xx with a DB error points at the database), IMAP/SMTP/SSH banners, DB ping, chronyc | restart if running but not answering |
| Firewall | iptables DROP/REJECT on the port; nftables shown | remove the rule |
| Tampered | config changed in the last 2 hours, systemd override (`ExecStart=/bin/true`), package files changed (`dpkg -V`) | shown with what to do (SV-15 restore, `apt-get install --reinstall`) |

**For the whole box:** disk or inodes full, `/tmp` not writable or wrong mode, programs killed for lack of memory.

Fixes run in order: unmask, firewall, kill, enable, start. Each fixed service is tested again (up to 10 s).

### Watch mode (the automation)

`--watch 30` checks every 30 seconds and prints a line the moment a service goes down or comes back, with the reason. Everything is also logged to `watch.txt`.

Adding `--auto-restart --apply` restarts what goes down, but only if its config test passes. It stops after 3 restarts in 10 minutes and tells you, so a crash loop isn't hidden. Run it in a spare terminal or `tmux` for the whole competition.

### Safety

- Dry run unless `--apply`. A protected list is needed like every change script (`--no-protected` to skip).
- **No revert timer**: these fixes bring services up, and undoing them would take them down again. Unmask, enable and firewall changes still have undo lines (`revert.sh`).
- A config error is never "fixed" by guessing: it's shown so you can fix it, or restore it with SV-15.

### What it produces

In `recovery-N/`: `output.txt`, `status.txt` (every check for every service), `summary.txt`, `watch.txt` (with `--watch`), `revert.sh`.

### What to watch for

- **Up here, down on the scoreboard:** the box answers but something in between doesn't. Check the network firewall (NW scripts) and that the scoring IP isn't banned (`SV-26 --unban-all`).
- **A defaced or wiped site still answers 200.** Use `SV-15 --check`.
- **A program on the port that is yours** (a second web server, a proxy): answer `n` to stopping it.

### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `config test FAILS` | A bad config line (red team, or a hardening script) | Fix the line shown, or `SV-15 --restore`, then run again |
| `still DOWN` after start | Something the checks don't cover | The log lines under it; `journalctl -u NAME` |
| `HTTP 500 ... database error` | The database is down or its password changed | Fix mysql first (this script), or SV-42's undo |
| `restarted 3 times in 10 minutes` | It crashes right after starting | Run without `--watch` to see why |

## 39. Splunk hardening and passwords, `roles/applications/SV-44-splunk-hardening.sh` (SV-44)

For the Splunk box. Splunk is three scored checks (`splunk-mgmt` on 8089, `splunk-query`, and the box) and an easy backdoor: a **scripted input** or **alert script** runs any command as the Splunk user, again and again. This finds those, gives the Splunk users new passwords, and checks that a search still runs afterwards.

> **Not yet run on a real Splunk.** It's tested against a stand-in with Splunk's real file layout and REST answers. Read the dry run first, and try it on a test box if you can.

### How to run it

```sh
sudo sh SV-44-splunk-hardening.sh                                 # look + dry run (asks for the admin login)
sudo sh SV-44-splunk-hardening.sh --protected p.csv --apply
sudo sh SV-44-splunk-hardening.sh --protected p.csv --apply --batch --auth-file admin.txt --exclude scorer
```

`admin.txt` is one line, `admin CURRENTPASSWORD`. Delete it after.

### The questions

| Question | Answers | Flag |
| --- | --- | --- |
| Splunk admin user and its current password | typed (not shown) | `--auth-file` |
| Each fix | `[y]` / `[n]` | `--only` / `--skip` |
| Go through each Splunk user? | `[y]` / `[n]` | `--batch` |
| Each user | `[r]andom` `[s]et` `[k]eep` `[a]ll the rest random` | `--users` / `--exclude` |
| Each app that didn't come with Splunk | `[q]uarantine` / `[k]eep` | `--quarantine NAMES` |
| Restart Splunk now? | `[y]` / `[n]` | `--batch` = yes |

### What it finds (never changed)

- **The old default password** `admin` / `changeme` still working (HIGH).
- **Users and roles:** every admin, and roles that can make admins (`edit_user`, `admin_all_objects` ...).
- **Apps that didn't come with Splunk**, with programs in `bin/` and when they changed (HIGH if both programs and a recent change).
- **Scripted inputs** (HIGH in apps that didn't come with Splunk), **alert scripts**.
- **Scripted login** (`authType = Scripted`), LDAP/SAML.
- **A deployment server** (it can push any app, and any command, to this Splunk), **forwarding** to another server, **HEC tokens**.
- Who splunkd runs as (root makes every backdoor root), secrets anyone can read, `user-seed.conf` left over.

### The fixes (each asked)

| Fix | Default | What it does |
| --- | --- | --- |
| `passwords` | yes | New password per user through the REST API on 8089, each tested by logging in. The admin you log in with goes last (Splunk needs its old password). |
| `scripts-off` | yes | `disabled = 1` for scripted inputs in apps that didn't come with Splunk (in that app's `local/inputs.conf`) |
| `app-quarantine` | no | Moves an app you choose out of `etc/apps` |
| `deploy-off` | no | Removes `deploymentclient.conf` |
| `secrets-perms` | yes | `etc/passwd` and `splunk.secret` mode 600, `user-seed.conf` removed |

### Safety

- Dry run unless `--apply`. Revert timer (120 s).
- After file changes Splunk restarts (asked), then 8089 must answer and a test search must run, which is what `splunk-query` scores. If either fails, everything is put back and Splunk restarted again.
- Undo: files back, `etc/passwd` back plus a restart (no old password is kept on disk), quarantined apps back.
- New passwords only go in `passwords.txt` (mode 600).

### What to watch for

- **`splunk-query` logs in as a Splunk user.** `--exclude` it or put it on the protected list, or report its new password in the scoring portal.
- **A restart takes about a minute**, so 8089 is down for that long.
- **A forwarder on another box** sending here keeps working: passwords and `pass4SymmKey` aren't involved in plain forwarding.

### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `could not log in to 8089` | Wrong admin password, or 8089 moved | Check `web.conf mgmtHostPort`; the file checks still run |
| `Splunk refused the change (HTTP 400)` | Password rules (length, complexity) | `--length 24`, or set one with `[s]` |
| `the test search FAILS` | A quarantined app or disabled input was needed | It's put back; skip that one next time |
| `splunkd is not running` | Down | `SV-50 --services splunk` |

## 40. Web shell hunter, `roles/applications/SV-16-webshell-hunter.sh` (SV-16)

Finds the PHP files red team uses to get back into a site: web shells. SV-15 only sees files that changed since its backup, so a shell planted before the backup is backed up too. This one looks at what's inside each file.

### How to run it

```sh
sudo sh SV-16-webshell-hunter.sh                                     # scan, dry run
sudo sh SV-16-webshell-hunter.sh --protected p.csv --apply           # asks about each file
sudo sh SV-16-webshell-hunter.sh --protected p.csv --apply --batch --url http://127.0.0.1/shop/
sudo sh SV-16-webshell-hunter.sh --protected p.csv --watch 60 --auto-quarantine --apply   # keep watching
```

### What it looks for

| Level | Found |
| --- | --- |
| HIGH | Request data run as code (`system($_GET..)`, `eval($_POST..)`, `assert($_REQUEST..)`, `$_GET['f']($_GET['a'])`, backticks); `eval(base64_decode(..))` and other decoded code; `preg_replace` with `/e`; known shell names (c99, r57, WSO, b374k, weevely, p0wny...); PHP in an upload or image folder; PHP inside a `.jpg`/`.png`/`.txt`; `.htaccess` that makes other files run as PHP or uses `auto_prepend_file`; a WordPress core file that differs from wordpress.org; a file in `wp-admin`/`wp-includes` WordPress doesn't ship |
| MED | Functions that run programs (`shell_exec`, `passthru`, `proc_open`, `popen`); decoding functions; hex-escaped strings; long base64 blobs; PHP in a cache/temp folder |
| LOW | Changed in the last `--hours` (24); owned by the web server account; a hidden `.name.php` |

A file is HIGH if any HIGH reason matches, MED if any MED reason does. The matching line is shown, so you can tell a shell from a normal plugin. WordPress's empty `index.php` ("Silence is golden") is skipped, and core files that match wordpress.org drop their MED/LOW hints.

**WordPress check:** it fetches the checksums for the installed version from wordpress.org. If that's blocked, save the page `https://api.wordpress.org/core/checksums/1.0/?version=X&locale=en_US` elsewhere and pass `--wp-checksums FILE`.

### The questions

| Question | Answers | Flag |
| --- | --- | --- |
| Each HIGH/MED file | `[q]uarantine` `[k]eep` `[a]ll the rest default` (default: HIGH out, MED kept) | `--batch` |
| Quarantine these? | `[y]` / `[n]` | `--apply` |

### Safety

- Dry run unless `--apply`. It only ever moves files to quarantine; the undo puts them back. Revert timer (120 s).
- **Site check:** `--url` must still load afterwards. If not, everything goes back, then the files are tried **one at a time**. A file the site needs is put back and listed: clean that one by hand (remove the bad lines, keep the rest).
- The check waits for PHP's cache (opcache), so a moved file can't look fine for a few seconds and then break the site.

### Watch mode

`--watch 60` checks every 60 seconds for new or changed PHP files and scans them right away. `--auto-quarantine --apply` moves HIGH ones out at once (and back if the site stops loading). Everything goes into `watch.txt`.

### What it produces

In `webshells-N/`: `output.txt`, `findings.txt` (every file, its score and reasons), `summary.txt`, `watch.txt`, `revert.sh`.

### What to watch for

- **Backup, file manager and page builder plugins** use exec functions, so MED is normal for them. Read the line before quarantining.
- **A clever shell can avoid every pattern.** Look at the LOW hints too (`--show-low`): changed lately, owned by the web server.
- **Shells kept in the database** (an option holding PHP) aren't seen. SV-15 compares the database.
- After cleaning: run `SV-15 --backup` so the clean site is the one you restore to, and `SV-21 upload-nophp` so PHP can't run in uploads at all.

### Problems and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `not checked against wordpress.org` | wordpress.org unreachable | `--wp-checksums FILE` |
| `the site needs FILE: put back` | The shell is inside a file the site loads | Remove only the bad lines, then run again |
| Lots of MED in one plugin | It runs programs legitimately | Keep it (`k`), or check the plugin's version |

## 41. Account lockdown, `roles/linux/LX-21-account-lockdown.sh` (LX-21)

After passwords (LX-20), this goes through **every account, one by one**, shows what it can do, and asks what to do with it. It's the account side of getting red team out: the users they made, a second root, planted SSH keys, sudo rules.

### How to run it

```sh
sudo sh LX-21-account-lockdown.sh                                  # look + dry run
sudo sh LX-21-account-lockdown.sh --protected p.csv --apply        # asks about each account
sudo sh LX-21-account-lockdown.sh --protected p.csv --apply --batch
```

**Put your team's accounts and the scoring account on the protected list first.** They're never locked, and anything else needs an extra yes.

### What it shows for every account

UID, login shell, password (set / empty / locked / a hash in `/etc/passwd`), admin groups (`sudo wheel admin docker lxd lxc libvirt disk shadow`: each one is as good as root), its sudo lines (and NOPASSWD), SSH keys (and options like `command=`), and when its password last changed.

| Level | Found |
| --- | --- |
| HIGH | A second UID 0; an empty password; a hash in `/etc/passwd`; a service account (www-data, mysql...) that can log in with a password or a key |
| MED | An admin that isn't protected; sudo lines / NOPASSWD; SSH key options; a password changed in the last `--days` (2); a service account with a login shell |

Clean accounts that can't log in aren't shown (they're in `accounts.txt`).

### The questions

| Question | Answers | Flag |
| --- | --- | --- |
| Which box is this? | `[s]plunk [w]ebmail [e]comm [o]ther` | `--box` |
| Go through the flagged accounts one by one? | `[y]` / `[n]` (the defaults) | `--batch` |
| Each account | `[k]eep` `[l]ock` `[d]` take admin away `[r]emove its SSH keys` `[b]oth d and r` `[n]o-login shell` `[a]ll the rest default`: only the answers that fit are shown | `--all` asks about every account |
| A protected account | extra `[y]` / `[n]`, default no | protected list |
| Each sudo line for everyone / a group / a missing user | `[y]` comment it out / `[n]` | |
| Apply? | `[y]` / `[n]` | `--apply` |

Defaults: a second UID 0, an empty password and a hash in `/etc/passwd` → **lock**. A service account with a shell → **no-login shell**. Everything else → **keep**.

### What the answers do

- **Lock**: `usermod -L` and the account expired, so SSH keys stop too. Its files stay.
- **Take admin away**: out of the admin groups (not its primary group), and its own sudo lines commented out with `# LX-21: `.
- **Remove its SSH keys**: `authorized_keys` moved to quarantine.
- **No-login shell**: `/usr/sbin/nologin`. The service keeps running.
- **Sudo lines** are only changed after `visudo -c` accepts the result.

### Safety

- Dry run unless `--apply`. Revert timer (120 s): **log in again from a NEW terminal** and check sudo works before you keep it.
- Root and the account you're using are never locked.
- Each account's lines are saved in `before/` first, and the undo puts them back exactly (tested on a real account).

### What it produces

In `accounts-N/`: `output.txt`, `accounts.txt` (every account and the decision), `plan.txt`, `changes.txt`, `summary.txt`, `before/`, `revert.sh`.

### What to watch for

- **An already logged-in session stays logged in.** LX-40 shows it; kill it by hand.
- **LDAP / AD accounts** (sssd, winbind) aren't in `/etc/passwd`, so they're not seen.
- Cron jobs, PAM, services and the rest red team plants: **LX-42**.
