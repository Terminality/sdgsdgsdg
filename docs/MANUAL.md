# Manual

How to use what is built, what to watch for, and what to do when something goes wrong. A script gets a section here when it is built; `docs/STATUS.md` lists what exists.

Built so far: the shell library (LB-01), the PowerShell library (LB-02), the Linux collector (SH-05), the script templates, and the test runner.

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
10. Linux collector, `roles/linux/SH-05-linux-collector.sh` (SH-05)

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
| `tests/sh05.test.sh` | The Linux collector: options, every profile writes its files, nothing on the host changes, and (as root) a planted SUID binary is flagged HIGH |
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

## 10. Linux collector, `roles/linux/SH-05-linux-collector.sh` (SH-05)

Read-only inventory of one Linux or Unix host. Run it first on every Linux box: it shows who can log in, what is listening, what starts on boot or on a schedule, who can become root, what is running, and the usual hiding places. It changes nothing.

### How to run it

```sh
sudo sh SH-05-linux-collector.sh --out /root/ccdc-out              # full, about a minute
sudo sh SH-05-linux-collector.sh --out /root/ccdc-out --profile card   # quick look, seconds
sudo sh SH-05-linux-collector.sh --out /root/ccdc-out --profile triage # full plus a copy of the logs
sudo sh SH-05-linux-collector.sh --out /root/ccdc-out --only ports,processes
```

Run it as root. As a normal user it still works, but the summary marks several sections `partial`.

| Option | What it does |
| --- | --- |
| `--profile card` | system, users, ports, services, autostart, ssh, sudo. Use it in the first minutes |
| `--profile full` (default) | card plus processes, connections, sessions, packages, files, firewall, pam, mac, trust, creds, containers, modules |
| `--profile triage` | full plus copying the logs. Use it when you think the box is compromised, before anything else changes |
| `--only a,b` / `--skip a,b` | Pick sections. `--list` shows the names |
| `--fast` | Skip the two slow disk searches (files, creds) |
| `--max-flags N` | How many HIGH/MED flags to print (default 30) |

### What it produces

Everything for one run is in `<out>/SH-05_<host>_<UTC time>/`:

| File | Contents |
| --- | --- |
| `summary.txt` | The page printed on screen: key facts, a row per section, the HIGH and MED flags |
| `flags.csv` | Every flag, including LOW: severity, section, item, detail, time |
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
| `firewall` says NOT-filtered but you set rules | Rules exist in a tool the collector does not read, or need root | Check `raw/` for the tool's output; run as root |
| A flag looks wrong | The check is too broad for your box | Check `raw/` to see what the tool printed. Report the flag line so the check can be tightened |
| It runs for many minutes | A very large disk or network home folders | `--fast`, or `--skip files,creds` |
| `cannot find lib/lib.sh` (exit 3) | The script was copied without the `lib/` folder | Copy the whole kit, or use the built single-file version once the build step exists |
| `$'\r': command not found` | The file got Windows line endings in transit | `tr -d '\r' < SH-05-linux-collector.sh > fixed.sh` |
