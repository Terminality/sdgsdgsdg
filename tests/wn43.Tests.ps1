# =============================================================================
# Tests for WN-43 Windows safe fixes.
#   pwsh -NoProfile -File tests/wn43.Tests.ps1
#
# Everything the script reads or changes goes through $env:BT_WN43_FAKE: a
# folder of stand-in state (registry.csv, accounts.csv, services.csv,
# smb.csv, defender.csv, auditpol.csv, logs.csv, wmi.csv, files.csv,
# firewall.csv, hosts).  The tests plant a badly configured domain
# controller, apply the fixes, check each one, run again (nothing may
# change), then -Undo and check the state is EXACTLY as it started.  No real
# setting is read or changed, on Linux or on Windows.
# =============================================================================
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $here
$wn43 = Join-Path (Join-Path (Join-Path $root 'roles') 'windows-ad') 'WN-43-safe-fixes.ps1'
$psExe = (Get-Process -Id $PID).Path
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('cctest_wn43_' + $PID)
$out = Join-Path $tmp 'out'; $fake = Join-Path $tmp 'fake'
$env:BT_SKIP_VERIFY = '1'; $env:BT_WN43_FAKE = $fake
$env:BT_TEST_SCHTASKS = Join-Path ([IO.Path]::GetTempPath()) ('cctest_wn43_sch_' + $PID + '.log')   # the revert timer's task is only written down
$script:pass = 0; $script:fail = 0
function T-Start($t) { Write-Host "  -- $t" }
function T-Eq($got, $want, $label) { if ("$got" -ceq "$want") { $script:pass++ } else { $script:fail++; Write-Host "     FAIL: $label"; Write-Host "           got [$got], wanted [$want]" } }
function T-True($cond, $label) { if ($cond) { $script:pass++ } else { $script:fail++; Write-Host "     FAIL: $label" } }
function T-Has($text, $needle, $label) { T-True ("$text".Contains($needle)) "$label (missing [$needle])" }
function T-HasNot($text, $needle, $label) { T-True (-not "$text".Contains($needle)) "$label (found [$needle])" }
function Run([string[]]$a) {
    $all = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $wn43) + @($a)
    $text = (& $psExe @all 2>&1 | Out-String)
    $dir = ''; if ($text -match 'All results: (\S+)') { $dir = $matches[1].Trim() }
    return @{ Code = $LASTEXITCODE; Text = $text; Dir = $dir }
}
function Csv($name, [string[]]$lines) { [IO.File]::WriteAllLines((Join-Path $fake $name), $lines) }
function Reg($k, $n) { foreach ($r in @(Import-Csv -LiteralPath (Join-Path $fake 'registry.csv'))) { if ($r.key -eq $k -and $r.name -eq $n) { return $r.data } }; return '(none)' }
function Row($file, $col, $val, $want) { foreach ($r in @(Import-Csv -LiteralPath (Join-Path $fake $file))) { if ($r.$col -eq $val) { return $r.$want } }; return '(none)' }
# Snapshot of the whole stand-in state; csv lines sorted so order does not matter.
function Snap {
    $s = @()
    foreach ($f in @(Get-ChildItem -LiteralPath $fake | Where-Object { -not $_.PSIsContainer -and $_.Name -ne 'restarts.txt' } | Sort-Object Name)) {
        $lines = @([IO.File]::ReadAllLines($f.FullName))
        # CSV compared by value, not by quoting style; rows sorted.
        if ($f.Extension -eq '.csv') { $lines = @($lines | ConvertFrom-Csv | ForEach-Object { (@($_.PSObject.Properties | ForEach-Object { [string]$_.Value })) -join '|' } | Sort-Object) }
        $s += ('== ' + $f.Name); $s += $lines
    }
    return ($s -join "`n")
}
$CCS = 'HKLM\SYSTEM\CurrentControlSet'; $NT = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion'; $CV = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion'
$U = 'HKU\S-1-5-21-1-2-3-1106'
function Plant {
    if (Test-Path -LiteralPath $fake) { Remove-Item -LiteralPath $fake -Recurse -Force }
    New-Item -ItemType Directory -Path $fake -Force | Out-Null
    Csv 'registry.csv' @('"key","name","type","data"',
        "`"$CCS\Control\SecurityProviders\WDigest`",`"UseLogonCredential`",`"DWord`",`"1`"",
        "`"$CCS\Services\Netlogon\Parameters`",`"FullSecureChannelProtection`",`"DWord`",`"0`"",
        "`"$CCS\Services\Netlogon\Parameters`",`"vulnerable_channel_allowlist`",`"String`",`"O:SYG:SYD:(A;;RC;;;WD)`"",
        "`"$CCS\Services\Netlogon\Parameters`",`"DBFlag`",`"String`",`"0x0`"",
        "`"$CV\Policies\System`",`"EnableLUA`",`"DWord`",`"0`"",
        "`"$CV\Policies\System`",`"LocalAccountTokenFilterPolicy`",`"DWord`",`"1`"",
        "`"$NT\Image File Execution Options\sethc.exe`",`"Debugger`",`"String`",`"C:\Windows\System32\cmd.exe`"",
        "`"$NT\Image File Execution Options\notepad.exe`",`"Debugger`",`"String`",`"C:\Users\Public\x.exe`"",
        "`"$NT\Image File Execution Options\taskmgr.exe`",`"Debugger`",`"String`",`"C:\Tools\procexp64.exe`"",
        "`"$NT\Image File Execution Options\winword.exe`",`"MitigationOptions`",`"Binary`",`"00`"",
        "`"$NT\SilentProcessExit\lsass.exe`",`"MonitorProcess`",`"String`",`"C:\ProgramData\dump.exe`"",
        "`"$CCS\Services\PortProxy\v4tov4\tcp`",`"0.0.0.0/8443`",`"String`",`"10.6.6.6/443`"",
        "`"$CCS\Services\PortProxy\v4tov4\tcp`",`"0.0.0.0/3390`",`"String`",`"10.6.6.6/3389`"",
        "`"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`",`"DisableAntiSpyware`",`"DWord`",`"1`"",
        "`"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths`",`"C:\Temp`",`"String`",`"0`"",
        "`"$CCS\Control\Lsa`",`"EveryoneIncludesAnonymous`",`"DWord`",`"1`"",
        "`"$CCS\Control\Lsa`",`"RestrictAnonymousSAM`",`"DWord`",`"0`"",
        "`"$CCS\Control\Lsa`",`"NoLMHash`",`"DWord`",`"0`"",
        "`"$CCS\Control\Lsa`",`"LmCompatibilityLevel`",`"DWord`",`"1`"",
        "`"$CCS\Services\LanmanServer\Parameters`",`"RestrictNullSessAccess`",`"DWord`",`"0`"",
        "`"$CCS\Services\LanmanServer\Parameters`",`"NullSessionShares`",`"MultiString`",`"Public | Data`"",
        "`"HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer`",`"AlwaysInstallElevated`",`"DWord`",`"1`"",
        "`"$U\Software\Policies\Microsoft\Windows\Installer`",`"AlwaysInstallElevated`",`"DWord`",`"1`"",
        "`"$NT\Winlogon`",`"Userinit`",`"String`",`"C:\Windows\system32\userinit.exe,C:\Windows\Temp\x.exe`"",
        "`"$NT\Winlogon`",`"Shell`",`"String`",`"explorer.exe`"",
        "`"$NT\Winlogon`",`"AutoAdminLogon`",`"String`",`"1`"",
        "`"$NT\Winlogon`",`"DefaultUserName`",`"String`",`"Administrator`"",
        "`"$NT\Winlogon`",`"DefaultPassword`",`"String`",`"Planted-Secret-Pw-42`"",
        "`"$NT\Windows`",`"AppInit_DLLs`",`"String`",`"C:\ProgramData\hook.dll`"",
        "`"$NT\Windows`",`"LoadAppInit_DLLs`",`"DWord`",`"1`"",
        "`"HKLM\SOFTWARE\Microsoft\NetSh`",`"ifmon`",`"String`",`"ifmon.dll`"",
        "`"HKLM\SOFTWARE\Microsoft\NetSh`",`"helper`",`"String`",`"C:\Windows\Temp\nethelp.dll`"",
        "`"$CCS\Control\Terminal Server\WinStations\RDP-Tcp`",`"UserAuthentication`",`"DWord`",`"0`"")
    Csv 'accounts.csv' @('name,sid,disabled', 'Administrator,S-1-5-21-1-2-3-500,False', 'Guest,S-1-5-21-1-2-3-501,False')
    Csv 'smb.csv' @('setting,value', 'EnableSMB1Protocol,True')
    Csv 'services.csv' @('name,state,startmode', 'EventLog,Stopped,Disabled', 'Spooler,Running,Auto', 'RemoteRegistry,Running,Auto', 'iphlpsvc,Running,Auto')
    Csv 'defender.csv' @('kind,value', 'realtime,off', 'Paths,C:\', 'Extensions,ps1')
    Csv 'auditpol.csv' @('guid,setting', '{0CCE9215-69AE-11D9-BED3-505054503030},No Auditing', '{0CCE922B-69AE-11D9-BED3-505054503030},Success')
    Csv 'logs.csv' @('name,max', 'Security,20971520')
    Csv 'wmi.csv' @('name,class,command', 'Updater,CommandLineEventConsumer,cmd.exe /c C:\ProgramData\u.bat')
    Csv 'files.csv' @('name,sha', 'cmd.exe,aaaa', 'powershell.exe,bbbb', 'explorer.exe,cccc', 'sethc.exe,aaaa', 'utilman.exe,dddd', 'osk.exe,eeee')
    Csv 'firewall.csv' @('profile,state', 'Domain,OFF', 'Private,ON', 'Public,ON')
    [IO.File]::WriteAllLines((Join-Path $fake 'hosts'), [string[]]@('# hosts', '127.0.0.1 localhost', '10.6.6.6 update.microsoft.com windowsupdate.com', '10.0.0.20 intranet.corp.local'))
    [IO.File]::WriteAllText((Join-Path $fake 'is-dc'), '')
}
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
$prot = Join-Path $tmp 'protected.csv'; [IO.File]::WriteAllLines($prot, [string[]]@('type,value,note', 'account,scoring,x'))

T-Start 'options'
$r = Run @('-List'); T-Eq $r.Code 0 '-List exits 0'; T-Has $r.Text 'stickykeys' '-List names the fixes'
$r = Run @('-Out', $out, '-Only', 'nosuch'); T-Eq $r.Code 2 'an unknown fix exits 2'
Plant
$r = Run @('-Out', $out, '-Apply'); T-Eq $r.Code 3 '-Apply without a protected list is refused'

T-Start 'dry run changes nothing'
Plant; $before = Snap
$r = Run @('-Out', $out)
T-Eq $r.Code 0 'exits 0'
T-Eq (Snap) $before 'stand-in state unchanged'
T-Has $r.Text 'Would fix' 'lists what it would fix'
T-True (-not (Test-Path -LiteralPath (Join-Path $r.Dir 'undo-plan.txt'))) 'no undo plan in a dry run'

T-Start 'apply the safe fixes to a badly configured DC'
Plant; $start = Snap
$r = Run @('-Out', $out, '-Apply', '-Protected', $prot)
$run1 = $r.Dir
T-Eq $r.Code 0 'exits 0'
T-Eq (Reg "$CCS\Control\SecurityProviders\WDigest" 'UseLogonCredential') '0' 'wdigest off'
T-Eq (Row 'smb.csv' 'setting' 'EnableSMB1Protocol' 'value') 'False' 'SMBv1 off'
T-Eq (Reg "$CCS\Services\Netlogon\Parameters" 'FullSecureChannelProtection') '1' 'Zerologon enforced'
T-Eq (Reg "$CCS\Services\Netlogon\Parameters" 'vulnerable_channel_allowlist') '(none)' 'Zerologon allow-list removed'
T-Eq (Reg "$CCS\Services\Netlogon\Parameters" 'DBFlag') '0x0' 'other values in the same key kept'
T-Eq (Reg "$CV\Policies\System" 'EnableLUA') '1' 'UAC on'
T-Has $r.Text 'Takes effect after a reboot: UAC on' 'says UAC needs a reboot'
T-Eq (Row 'accounts.csv' 'name' 'Guest' 'disabled') 'True' 'Guest disabled'
T-Eq (Row 'accounts.csv' 'name' 'Administrator' 'disabled') 'False' 'Administrator untouched'
T-Eq (Reg "$NT\Image File Execution Options\sethc.exe" 'Debugger') '(none)' 'sethc debugger removed'
T-Eq (Reg "$NT\Image File Execution Options\notepad.exe" 'Debugger') '(none)' 'debugger in Users\Public removed'
T-Eq (Reg "$NT\Image File Execution Options\taskmgr.exe" 'Debugger') 'C:\Tools\procexp64.exe' 'a real tool as debugger is left (and listed)'
T-Eq (Reg "$NT\Image File Execution Options\winword.exe" 'MitigationOptions') '00' 'other IFEO values untouched'
T-Eq (Reg "$NT\SilentProcessExit\lsass.exe" 'MonitorProcess') '(none)' 'SilentProcessExit removed'
T-Eq (Row 'files.csv' 'name' 'sethc.exe' 'sha') 'original-sethc.exe' 'sethc replaced by cmd is repaired (sfc)'
T-Eq (Row 'files.csv' 'name' 'utilman.exe' 'sha') 'dddd' 'an unchanged logon-screen program is left'
T-Eq (Reg "$CCS\Services\PortProxy\v4tov4\tcp" '0.0.0.0/8443') '(none)' 'port forward removed'
T-Has ([IO.File]::ReadAllText((Join-Path $fake 'restarts.txt'))) 'iphlpsvc' 'IP Helper restarted so the removed forwards stop listening'
T-Eq (Reg "$CCS\Control\Lsa" 'SCENoApplyLegacyAuditPolicy') '1' 'subcategory audit settings win over an old-style GPO audit policy'
T-Eq (Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender' 'DisableAntiSpyware') '(none)' 'policy turning Defender off removed'
T-Eq (Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths' 'C:\Temp') '(none)' 'policy exclusion removed'
T-Eq (Row 'defender.csv' 'kind' 'realtime' 'value') 'on' 'real-time protection on'
T-Eq (Row 'defender.csv' 'kind' 'Paths' 'value') '(none)' 'path exclusion removed'
T-Eq (Row 'defender.csv' 'kind' 'Extensions' 'value') '(none)' 'extension exclusion removed'
T-Eq (Row 'services.csv' 'name' 'EventLog' 'state') 'Running' 'Event Log running'
T-Eq (Row 'services.csv' 'name' 'EventLog' 'startmode') 'Auto' 'Event Log automatic'
T-Eq (Row 'auditpol.csv' 'guid' '{0CCE9215-69AE-11D9-BED3-505054503030}' 'setting') 'Success and Failure' 'logons audited'
T-Eq (Row 'auditpol.csv' 'guid' '{0CCE923C-69AE-11D9-BED3-505054503030}' 'setting') 'Success and Failure' 'directory changes audited on a DC'
T-Eq (Reg "$CV\Policies\System\Audit" 'ProcessCreationIncludeCmdLine_Enabled') '1' 'command lines logged'
T-Eq (Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging') '1' 'PowerShell logged'
T-Eq (Row 'logs.csv' 'name' 'Security' 'max') ([string](512MB)) 'Security log 512 MB'
T-Eq (Reg "$CCS\Control\Lsa" 'EveryoneIncludesAnonymous') '0' 'anonymous is not everyone'
T-Eq (Reg "$CCS\Control\Lsa" 'RestrictAnonymousSAM') '1' 'anonymous cannot list accounts'
T-Eq (Reg "$CCS\Services\LanmanServer\Parameters" 'RestrictNullSessAccess') '1' 'null sessions restricted'
T-Eq (Reg "$CCS\Services\LanmanServer\Parameters" 'NullSessionShares') '(none)' 'null-session shares removed'
T-Eq (Reg "$CCS\Control\Lsa" 'NoLMHash') '1' 'no LM hashes'
T-Eq (Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated') '0' 'AlwaysInstallElevated off (machine)'
T-Eq (Reg "$U\Software\Policies\Microsoft\Windows\Installer" 'AlwaysInstallElevated') '0' 'AlwaysInstallElevated off (user)'
T-True ((Reg "$NT\Winlogon" 'Userinit') -match 'system32\\userinit\.exe,$') 'Userinit back to Windows own'
T-Eq (Reg "$NT\Winlogon" 'DefaultPassword') '(none)' 'stored logon password removed'
T-Eq (Reg "$NT\Winlogon" 'AutoAdminLogon') '0' 'auto-logon off'
T-Eq (Reg "$NT\Winlogon" 'DefaultUserName') 'Administrator' 'the rest of Winlogon untouched'
T-Eq (Reg "$NT\Windows" 'AppInit_DLLs') '' 'AppInit DLLs cleared'
T-Eq (Reg "$NT\Windows" 'LoadAppInit_DLLs') '0' 'AppInit loading off'
T-Eq (Reg 'HKLM\SOFTWARE\Microsoft\NetSh' 'helper') '(none)' 'unknown netsh helper removed'
T-Eq (Reg 'HKLM\SOFTWARE\Microsoft\NetSh' 'ifmon') 'ifmon.dll' 'Windows netsh helper kept'
T-Eq (Row 'wmi.csv' 'name' 'Updater' 'command') '(none)' 'WMI subscription removed'
$h = [IO.File]::ReadAllText((Join-Path $fake 'hosts'))
T-HasNot $h 'update.microsoft.com' 'redirect of Microsoft update removed from hosts'
T-Has $h 'intranet.corp.local' 'every other hosts line kept'
T-Eq (Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast') '0' 'LLMNR off'
# not run without -Include
T-Eq (Row 'firewall.csv' 'profile' 'Domain' 'state') 'OFF' 'firewall not touched without -Include'
T-Eq (Row 'services.csv' 'name' 'Spooler' 'state') 'Running' 'Spooler not touched without -Include'
T-Eq (Reg "$CCS\Control\Lsa" 'LmCompatibilityLevel') '1' 'NTLM level not touched without -Include'
T-Eq (Reg "$CV\Policies\System" 'LocalAccountTokenFilterPolicy') '1' 'LocalAccountTokenFilterPolicy not touched without -Include'
T-Has $r.Text 'Not run (might affect a service; add with -Include): firewall, latfp' 'summary lists the fixes not run'
# secrets and records
$all = $r.Text + [IO.File]::ReadAllText((Join-Path $run1 'fixes.txt')) + [IO.File]::ReadAllText((Join-Path $run1 'summary.txt')) + [IO.File]::ReadAllText(@(Get-ChildItem -LiteralPath $out -Filter 'WN-43_*.log' | Sort-Object Name)[-1].FullName)
T-HasNot $all 'Planted-Secret-Pw-42' 'the stored password is never shown or logged'
T-True (@(Import-Csv -LiteralPath (Join-Path $run1 'undo-plan.txt')).Count -gt 20) 'undo plan written'
T-Has ([IO.File]::ReadAllText((Join-Path $out ('undo-' + (@(Get-ChildItem -LiteralPath $out -Filter 'undo-*.log')[0].Name -replace '^undo-|\.log$', '') + '.log')))) 'WN-43 restore registry key' 'plain undo commands in the host undo log'
T-Has $r.Text '-Undo safe-fixes-' 'summary says how to put the run back'

T-Start 'a second run changes nothing'
$r = Run @('-Out', $out, '-Apply', '-Protected', $prot)
T-Eq $r.Code 0 'exits 0'
T-Has $r.Text 'Fixed (0):' 'nothing left to fix'

T-Start '-Undo puts the state back exactly'
$r = Run @('-Out', $out, '-Undo', $run1)
T-Eq $r.Code 0 'undo dry run exits 0'
T-Has $r.Text 'nothing was put back' 'undo is a dry run without -Apply'
$r = Run @('-Out', $out, '-Undo', $run1, '-Apply', '-Protected', $prot)
T-Eq $r.Code 0 'undo exits 0'
$after = Snap
# The repaired sticky-keys program is not undone on purpose.
$expect = $start.Replace('sethc.exe|aaaa', 'sethc.exe|original-sethc.exe')
$ex = @($expect -split "`n"); $af = @($after -split "`n")
$diff = @(Compare-Object $ex $af | ForEach-Object { $_.SideIndicator + ' ' + $_.InputObject })
T-Eq ($diff -join ' || ') '' 'every changed setting is back as it was (only the repaired sticky-keys program stays repaired)'
T-Eq (Reg "$NT\Winlogon" 'DefaultPassword') 'Planted-Secret-Pw-42' 'the stored password value came back from the admin-only key backup'
T-True (Test-Path -LiteralPath (Join-Path $run1 'UNDONE')) 'the run is marked undone'
$r = Run @('-Out', $out, '-Undo', $run1, '-Apply', '-Protected', $prot)
T-Eq $r.Code 2 'undoing the same run twice is refused'

T-Eq (@([IO.File]::ReadAllLines((Join-Path $fake 'restarts.txt')) | Where-Object { $_ -eq 'iphlpsvc' }).Count) 2 'undo restarts IP Helper again so the put-back forwards listen'

T-Start '-Include the service fixes, then -Undo latest'
Plant; $start = Snap
$r = Run @('-Out', $out, '-Apply', '-Protected', $prot, '-Only', 'firewall,latfp,ntlm,lsappl,rdpnla,spooler,remotereg,smbsigning')
T-Eq $r.Code 0 'exits 0'
T-Eq (Row 'firewall.csv' 'profile' 'Domain' 'state') 'ON' 'firewall profile on'
T-Eq (Reg "$CV\Policies\System" 'LocalAccountTokenFilterPolicy') '0' 'LocalAccountTokenFilterPolicy off'
T-Eq (Reg "$CCS\Control\Lsa" 'LmCompatibilityLevel') '5' 'NTLMv2 only'
T-Eq (Reg "$CCS\Control\Lsa" 'RunAsPPL') '1' 'LSA protection'
T-Eq (Reg "$CCS\Control\Terminal Server\WinStations\RDP-Tcp" 'UserAuthentication') '1' 'RDP NLA'
T-Eq (Row 'services.csv' 'name' 'Spooler' 'startmode') 'Disabled' 'Spooler disabled on a DC'
T-Eq (Row 'services.csv' 'name' 'RemoteRegistry' 'state') 'Stopped' 'Remote Registry stopped'
T-Eq (Reg "$CCS\Services\LanmanServer\Parameters" 'RequireSecuritySignature') '1' 'SMB signing required'
T-Eq (Reg "$CV\Policies\System" 'EnableLUA') '0' '-Only ran only those fixes'
$r = Run @('-Out', $out, '-Undo', 'latest', '-Apply', '-Protected', $prot)
T-Eq $r.Code 0 'undo latest exits 0'
T-Eq (Snap) $start 'state back exactly, including values that did not exist before (RunAsPPL, RequireSecuritySignature)'

T-Start 'protected items are refused'
Plant
$p2 = Join-Path $tmp 'prot2.csv'
[IO.File]::WriteAllLines($p2, [string[]]@('type,value,note', 'account,Guest,scored', 'service,RemoteRegistry,monitoring', 'port,445/tcp,file share', 'port,8443/tcp,web'))
$r = Run @('-Out', $out, '-Apply', '-Protected', $p2, '-Include', 'remotereg')
T-Eq (Row 'accounts.csv' 'name' 'Guest' 'disabled') 'False' 'protected Guest left enabled'
T-Eq (Row 'services.csv' 'name' 'RemoteRegistry' 'state') 'Running' 'protected service left running'
T-Eq (Row 'smb.csv' 'setting' 'EnableSMB1Protocol' 'value') 'True' 'SMBv1 left on when 445/tcp is protected'
T-Eq (Reg "$CCS\Services\PortProxy\v4tov4\tcp" '0.0.0.0/8443') '10.6.6.6/443' 'a port forward on a protected port is left'
T-Eq (Reg "$CCS\Services\PortProxy\v4tov4\tcp" '0.0.0.0/3390') '(none)' 'the other port forward is removed'
T-Has $r.Text 'refused: protected' 'refusals listed'

T-Start 'a failing fix is reported and the rest still run'
Plant
$env:BT_WN43_FAIL = 'defrt'
$r = Run @('-Out', $out, '-Apply', '-Protected', $prot, '-Only', 'defender,wdigest')
Remove-Item Env:\BT_WN43_FAIL
T-Eq $r.Code 5 'exits 5'
T-Has $r.Text 'Tamper Protection blocked the change' 'the reason is shown'
T-Eq (Reg "$CCS\Control\SecurityProviders\WDigest" 'UseLogonCredential') '0' 'the other fixes still ran'

T-Start 'a fix that does not stick is caught'
Plant
$env:BT_WN43_FAIL = 'defrt-silent'
$r = Run @('-Out', $out, '-Apply', '-Protected', $prot, '-Only', 'defender')
T-Eq $r.Code 5 'real-time protection still off afterwards: exits 5'
T-Has $r.Text 'still off afterwards' 'and says so'
T-Has ([IO.File]::ReadAllText((Join-Path $r.Dir 'fixes.txt'))) 'still off afterwards' 'fixes.txt has the corrected result'
Plant
$env:BT_WN43_FAIL = 'sfc'
$r = Run @('-Out', $out, '-Apply', '-Protected', $prot, '-Only', 'stickykeys')
Remove-Item Env:\BT_WN43_FAIL
T-Eq $r.Code 5 'sfc that does not repair: exits 5'
T-Has $r.Text 'sfc did not repair it' 'and says so'

T-Start 'a key that cannot be backed up is not changed'
Plant; $before = Snap
$env:BT_WN43_FAIL = 'export'
$r = Run @('-Out', $out, '-Apply', '-Protected', $prot, '-Only', 'wdigest,winlogon,llmnr')
Remove-Item Env:\BT_WN43_FAIL
T-Eq $r.Code 5 'exits 5'
T-Eq (Reg "$CCS\Control\SecurityProviders\WDigest" 'UseLogonCredential') '1' 'existing key without a backup: not changed'
T-Eq (Reg "$NT\Winlogon" 'DefaultPassword') 'Planted-Secret-Pw-42' 'Winlogon without a backup: not changed'
T-Has $r.Text 'could not be backed up' 'and says why'
T-Eq (Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast') '0' 'a key that did not exist needs no backup: LLMNR still set (undo deletes the value)'

T-Start 'not a domain controller'
Plant; Remove-Item -LiteralPath (Join-Path $fake 'is-dc')
$r = Run @('-Out', $out, '-Apply', '-Protected', $prot, '-Only', 'zerologon,spooler,auditing')
T-Eq (Reg "$CCS\Services\Netlogon\Parameters" 'FullSecureChannelProtection') '0' 'Zerologon fix only on a DC'
T-Eq (Row 'services.csv' 'name' 'Spooler' 'state') 'Running' 'Spooler left alone off a DC'
T-Eq (Row 'auditpol.csv' 'guid' '{0CCE923C-69AE-11D9-BED3-505054503030}' 'setting') '(none)' 'directory-change auditing only on a DC'

T-Start 'Server Core: no explorer.exe, so Shell is only reported'
Plant
$f = Join-Path $fake 'registry.csv'; $rows = @(Import-Csv -LiteralPath $f); foreach ($x in $rows) { if ($x.name -eq 'Shell') { $x.data = 'cmd.exe' } }; $rows | Export-Csv -LiteralPath $f -NoTypeInformation
[IO.File]::WriteAllText((Join-Path $fake 'no-explorer'), '')
$r = Run @('-Out', $out, '-Protected', $prot, '-Apply', '-Batch', '-Only', 'winlogon')
T-Eq (Reg "$NT\Winlogon" 'Shell') 'cmd.exe' 'Shell is not set to a missing explorer.exe'
T-Has $r.Text 'no explorer.exe here (Server Core?)' 'and it says why'
T-Eq (Reg "$NT\Winlogon" 'Userinit') 'C:\Windows\system32\userinit.exe,' 'Userinit is still fixed'
Remove-Item -LiteralPath (Join-Path $fake 'no-explorer') -Force
$rows = @(Import-Csv -LiteralPath $f); foreach ($x in $rows) { if ($x.name -eq 'Shell') { $x.data = 'cmd.exe' } }; $rows | Export-Csv -LiteralPath $f -NoTypeInformation
$r = Run @('-Out', $out, '-Protected', $prot, '-Apply', '-Batch', '-Only', 'winlogon')
T-Eq (Reg "$NT\Winlogon" 'Shell') 'explorer.exe' 'with explorer.exe there, Shell is set back as before'

T-Start 'the look and the questions'
Plant
$r = Run @('-Out', $out, '-Protected', $prot, '-Batch')
T-Has $r.Text 'WN-43 Windows safe fixes | host' 'the title line'
T-Has $r.Text '==========[ 1/3  questions (Enter = the default in capitals) ]==========' 'numbered headers'
T-Has $r.Text '[?] Which safe fixes? (they cannot break a scored service) [A/c] a (default): all 20 of them' 'which fixes: all by default'
T-Has $r.Text '[?] Might affect a service - rdpnla: RDP requires Network Level Authentication? [y/N] n (default)' 'each service fix: default no'
T-Has $r.Text '==========[ 2/3  dry run: what would change ]==========' '-Batch without -Apply: a dry run'
T-Has $r.Text '[~] wdigest' 'what would change is shown as it is found'
T-True ($r.Dir -match 'safe-fixes-\d+$') 'a numbered safe-fixes-N folder'
T-True (@(Get-ChildItem -LiteralPath $r.Dir -Recurse -Filter '*.csv').Count -eq 0) 'no CSV in the results'
# c: choose each - only wdigest; no service fixes; apply: y; keep: y
Plant
$ans = @('c', 'y'); for ($i = 1; $i -lt 20; $i++) { $ans += 'n' }; for ($i = 0; $i -lt 8; $i++) { $ans += 'n' }; $ans += 'y'; $ans += 'y'
$env:BT_TEST_ANSWERS = ($ans -join ';')
$r = Run @('-Out', $out, '-Protected', $prot)
Remove-Item Env:\BT_TEST_ANSWERS
T-Has $r.Text '[?] wdigest: passwords no longer kept readable in memory?' 'c: each safe fix is asked'
T-Eq (Reg "$CCS\Control\SecurityProviders\WDigest" 'UseLogonCredential') '0' 'y: wdigest fixed'
T-Has $r.Text 'fixes run: wdigest' 'only the chosen fix ran'
T-Has $r.Text '[?] Apply these 1 fix(es) now?' 'then: apply?'
T-Has $r.Text 'Revert timer: everything is undone at' 'the revert timer runs'
T-Has $r.Text 'Changes kept' 'keep: y'

Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $env:BT_TEST_SCHTASKS -Force -ErrorAction SilentlyContinue
Write-Host ("  {0} passed, {1} failed" -f $script:pass, $script:fail)
if ($script:fail -gt 0) { exit 1 }
exit 0
