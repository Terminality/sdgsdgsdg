# =============================================================================
# ID:       WN-42
# NAME:     Windows persistence sweep
# ROLE:     Windows / AD  (wave 2, after the first 15 minutes)
# KIND:     changes - dry run unless -Apply; a revert timer undoes it unless kept
# VERSION:  1.0.0
#
# PURPOSE
#   Where a red team leaves a way back in on Windows, and what to do with
#   each.  The Windows twin of LX-42.  It looks in:
#     tasks       scheduled tasks (the XML files): a command from a temp or
#                 user folder, an encoded PowerShell, a download-and-run
#     runkeys     Run / RunOnce (machine, 32-bit, every loaded user)
#     startup     the startup folders (all users and each user)
#     winlogon    Userinit and Shell changed from Windows' own
#     services    a service whose program sits in a temp or user folder, or
#                 runs a shell or script
#     wmi         WMI event subscriptions (a favourite fileless backdoor)
#     ifeo        a "debugger" set on a program (runs instead of it); the
#                 logon-screen ones (sethc, utilman ...) are WN-43's
#     admins      members of the local Administrators and Remote Desktop
#                 Users groups (not on a domain controller: WN-23 there)
#   Each finding is HIGH (looks planted: offered for removal, default yes),
#   MED (unusual: offered, default keep) or LOW (listed only).
#
#   The look and the questions are the same as the Linux scripts (LX-42).
#   QUESTIONS (Enter takes the default in capitals; a parameter answers each):
#     which areas to look in          -Areas a,b (Enter = all)
#     each finding: [r]emove [k]eep [a]ll the rest: their default
#     apply these changes?            -Apply (Enter = no: a dry run)
#
# USAGE
#   powershell -NoProfile -ExecutionPolicy Bypass -File WN-42-persistence-sweep.ps1                look + dry run
#   powershell ... WN-42-persistence-sweep.ps1 -Apply                                             asks each
#   powershell ... WN-42-persistence-sweep.ps1 -Apply -Batch -Areas tasks,runkeys,wmi
#   Run in an elevated window.
#
# OPTIONS
#   -Areas a,b         tasks runkeys startup winlogon services wmi ifeo admins
#   -Exclude a,b       names never offered (a task, value, service or account)
#   -Timer SECONDS     revert countdown (default 120); -NoTimer
#   -Batch             no questions: the defaults (a dry run unless -Apply)
#   -NoColor           no colours
#   Common options (-Apply, -Out, -Protected, -NoProtected, -ForceScored,
#   -Quiet, -DebugLog) come from the library.
#
# OUTPUTS  (under -Out, one numbered folder per run: persistence-1, -2, ...)
#   output.txt      everything shown on screen, without colour
#   findings.txt    level, area, name, what it runs, why, what was done
#   summary.txt     the summary page
#   run.txt         id, host, time
#   undo.txt, revert.ps1   this run's undo (the revert timer runs it)
#
# WHAT IT CHANGES  (only with -Apply, only what you chose)
#   tasks: disabled (not deleted).  runkeys, winlogon, ifeo: the value is
#   removed or set back to Windows' own (the old value is in the undo line).
#   startup: the file is quarantined.  services: start mode Disabled and
#   stopped.  wmi: the binding is removed (filter and consumer stay, so the
#   undo can bind them again).  admins: removed from the group.  Nothing on
#   the protected list, and never the account running this script.
#
# DEPENDS ON
#   The registry, the task XML files in System32\Tasks, WMI (Get-WmiObject),
#   ADSI (WinNT), schtasks.exe and sc.exe: Windows 7 / Server 2008 R2 and
#   later.  $env:BT_WN42_FAKE names a folder of stand-in state (one CSV per
#   area) for the tests: then nothing real is read or changed.
#
# TESTED ON
#   PowerShell 7 on Linux against stand-in state (tests/wn42.Tests.ps1).
#   NOT yet run on real Windows: run it on a throwaway VM first.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - A HIGH finding is a pointer, not a verdict: read the command first.
#   - Only users whose registry hive is loaded (logged on) are read for
#     their Run keys.
#   - Sticky keys and the logon-screen debuggers are fixed by WN-43.
#
# DEBUGGING
#   -DebugLog shows every item read and why it was or was not flagged.
# =============================================================================
param(
    [switch]$Apply, [string]$Out, [string]$Protected, [switch]$NoProtected,
    [switch]$ForceScored, [switch]$Quiet, [switch]$DebugLog,
    [string]$Areas = '',
    [string[]]$Exclude = @(),
    [int]$Timer = 120,
    [switch]$NoTimer,
    [switch]$Help,
    [switch]$Batch,
    [switch]$NoColor
)

if ($Help) {
    Write-Host 'WN-42 Windows persistence sweep - tasks, Run keys, startup, Winlogon, services, WMI, debuggers, admins'
    Write-Host '  -Areas a,b      tasks runkeys startup winlogon services wmi ifeo admins (asked; Enter = all)'
    Write-Host '  -Exclude a,b    names never offered'
    Write-Host '  -Timer SECONDS -NoTimer -Batch -NoColor'
    Write-Host '  -Apply -Out DIR -Protected FILE -NoProtected -Quiet -DebugLog'
    exit 0
}

# >>> BT-LIB
# Development copy: find lib/lib.ps1 by walking up from this file.  The build
# step (tools/build.sh, LB-03) replaces this whole block with the library
# itself, so the built script is a single standalone file.
$ccDir = Split-Path -Parent $MyInvocation.MyCommand.Path
while ($ccDir -and -not (Test-Path -LiteralPath (Join-Path (Join-Path $ccDir 'lib') 'lib.ps1'))) { $ccDir = Split-Path -Parent $ccDir }
if (-not $ccDir) { Write-Host 'cannot find lib/lib.ps1 above this script'; exit 3 }
. (Join-Path (Join-Path $ccDir 'lib') 'lib.ps1')
# <<< BT-LIB

# ---- Options ----------------------------------------------------------------
$AllAreas = @('tasks', 'runkeys', 'startup', 'winlogon', 'services', 'wmi', 'ifeo', 'admins')
$areaL = @($Areas -split '[,\s]+' | Where-Object { $_ } | ForEach-Object { $_.ToLower() })
foreach ($n in $areaL) { if (-not ($AllAreas -contains $n)) { Write-Host ("unknown area '{0}' ({1})" -f $n, ($AllAreas -join ' ')); exit 2 } }
$Exclude = @(@($Exclude) | Where-Object { $_ } | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ })
if ($Timer -lt 30) { Write-Host '-Timer must be 30 seconds or more'; exit 2 }
function Lc($s) { if ($null -eq $s) { return '' }; return ([string]$s).ToLower() }
function Nz($s) { if ($null -eq $s) { return '' }; return [string]$s }
function Q([string]$s) { return ConvertTo-CcQuoted $s }

# ---- Start ------------------------------------------------------------------
Initialize-Cc -Id 'WN-42' -Name 'Windows persistence sweep' -Kind changes -Bound $PSBoundParameters
$Fake = $env:BT_WN42_FAKE
if ($Fake) { Write-CcLog -Level WARN -Message "TEST MODE: stand-in state from $Fake; nothing real is read or changed" }
Use-CcNumberedDir 'persistence'
Write-CcShow -Color Cyan -Text ('WN-42 Windows persistence sweep | host {0} | results in {1}' -f $Cc.Host, $Cc.RunDir)
Write-CcLegend -Marks @('Red=[!] HIGH: looks planted', 'Yellow=[*] MED: unusual', 'DarkGray=[-] LOW: listed', 'Green=[+] removed')
$IsDC = $false
if ($Fake) { $IsDC = Test-Path -LiteralPath (Join-Path $Fake 'is-dc') } else { $IsDC = (Get-CcOsInfo).IsDC; if ($Cc.Apply) { Assert-CcAdmin } }
$me0 = [Environment]::UserName; if (-not $me0) { $me0 = $env:USERNAME }; $Me = Lc $me0

Write-CcHeader '1/4  questions and looking'
if ($areaL.Count -eq 0) {
    $ac = Read-CcChoice -Question 'Which areas to look in?' -Default a -Options @('a=all of them', 'q=quick: tasks, Run keys, services, WMI')
    if ($ac -eq 'q') { $areaL = @('tasks', 'runkeys', 'services', 'wmi') } else { $areaL = $AllAreas }
}
function Want([string]$a) { return ($areaL -contains $a) }

# ---- What looks planted -----------------------------------------------------------
# Odd folder: temp, user profile data, Public, PerfLogs, ProgramData top level, the recycle bin.
$OddRe = '(\\users\\public\\|\\perflogs\\|\\windows\\temp\\|\\temp\\|\\tmp\\|\\appdata\\|\\downloads\\|\\programdata\\[^\\]+\.(exe|dll|bat|cmd|ps1|vbs|js|hta)|\$recycle\.bin|\\windows\\tasks\\|\\fonts\\[^\\]+\.(exe|dll))'
# Download-and-run or hidden code.  Built from pieces so antivirus does not
# mistake this check for the attack.
$BadRe = '(' + (@('-enc(odedcommand)?\s', 'frombase64string', 'downloadstring', 'downloadfile', 'invoke-expression', '\biex\b', 'net\.webclient', 'invoke-webrequest', 'mshta\s+(http|vbscript|javascript)', 'rundll32\s+javascript', 'regsvr32\s.*\/i:http', 'certutil.*-urlcache', 'bitsadmin.*\/transfer', '-w(indowstyle)?\s+hid', '\\\\[0-9]{1,3}\.[0-9]{1,3}\.', 'nc(at)?(\.exe)?\s.*-e\s') -join '|') + ')'  # ps2-ok (text to look for, not a call)
$ShellRe = '(^|\\|\s|")(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32)(\.exe)?("|\s|$)'
# Judge COMMAND -> @(level, why)
function Judge([string]$cmd) {
    $c = Lc $cmd
    if ($c -match $BadRe) { return @('HIGH', 'download-and-run or hidden code') }
    if ($c -match $OddRe) { return @('HIGH', 'runs from a temp or user folder') }
    if ($c -match '\.(ps1|vbs|js|jse|hta|bat|cmd)\b' -and $c -match $ShellRe) { return @('MED', 'runs a script') }
    if ($c -match $ShellRe) { return @('MED', 'runs a shell') }
    return @('LOW', '')
}

# ---- Reading (or the stand-in) ------------------------------------------------------
# Every area gives rows: Id, Name, Run (what it runs), Extra (whatever the change needs).
function F-Rows([string]$area) {
    $p = Join-Path $Fake ($area + '.csv')
    if (-not (Test-Path -LiteralPath $p)) { return @() }
    return @([IO.File]::ReadAllLines($p) | ConvertFrom-Csv | Where-Object { $_.state -ne 'off' } | ForEach-Object { New-Object PSObject -Property @{ Id = $_.id; Name = $_.name; Run = $_.run; Extra = $_.extra } })
}
function R-Tasks {
    if ($Fake) { return @(F-Rows 'tasks') }
    $root = Join-Path $env:SystemRoot 'System32\Tasks'
    $out = @()
    foreach ($f in @(Get-ChildItem -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer })) {
        try { [xml]$x = [IO.File]::ReadAllText($f.FullName) } catch { continue }
        $name = '\' + $f.FullName.Substring($root.Length + 1)
        if ($x.Task.Settings.Enabled -eq 'false') { continue }
        $run = @()
        foreach ($e in @($x.Task.Actions.Exec)) { if ($e) { $run += ((Nz $e.Command) + ' ' + (Nz $e.Arguments)).Trim() } }
        if ($run.Count -eq 0) { continue }
        $out += New-Object PSObject -Property @{ Id = $name; Name = $name; Run = ($run -join ' ; '); Extra = (Nz $x.Task.RegistrationInfo.Author) }
    }
    return $out
}
$RunKeys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce')
function R-RunKeys {
    if ($Fake) { return @(F-Rows 'runkeys') }
    $keys = @($RunKeys)
    foreach ($h in @(Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' })) {
        $keys += ('Registry::HKEY_USERS\' + $h.PSChildName + '\Software\Microsoft\Windows\CurrentVersion\Run')
        $keys += ('Registry::HKEY_USERS\' + $h.PSChildName + '\Software\Microsoft\Windows\CurrentVersion\RunOnce')
    }
    $out = @()
    foreach ($k in $keys) {
        $i = Get-Item -LiteralPath $k -ErrorAction SilentlyContinue
        if (-not $i) { continue }
        foreach ($v in @($i.GetValueNames())) {
            if ($v -eq '') { continue }
            $out += New-Object PSObject -Property @{ Id = ($k + '|' + $v); Name = ($v + '  (' + ($k -replace '^Registry::', '' -replace '^HKLM:', 'HKLM') + ')'); Run = [string]$i.GetValue($v); Extra = $k }
        }
    }
    return $out
}
function R-Startup {
    if ($Fake) { return @(F-Rows 'startup') }
    $dirs = @((Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp'))
    foreach ($u in @(Get-ChildItem -LiteralPath (Split-Path -Parent $env:PUBLIC) -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer })) { $dirs += (Join-Path $u.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup') }
    $out = @()
    foreach ($d in $dirs) { foreach ($f in @(Get-ChildItem -LiteralPath $d -Force -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer -and $_.Name -ne 'desktop.ini' })) { $out += New-Object PSObject -Property @{ Id = $f.FullName; Name = $f.FullName; Run = $f.FullName; Extra = '' } } }
    return $out
}
$WinlogonKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$WinlogonOk = @{ Userinit = 'C:\Windows\system32\userinit.exe,'; Shell = 'explorer.exe' }
function R-Winlogon {
    if ($Fake) { return @(F-Rows 'winlogon') }
    $out = @()
    foreach ($n in @('Userinit', 'Shell')) {
        $v = (Get-ItemProperty -LiteralPath $WinlogonKey -Name $n -ErrorAction SilentlyContinue).$n
        $out += New-Object PSObject -Property @{ Id = $n; Name = $n; Run = (Nz $v); Extra = '' }
    }
    return $out
}
function R-Services {
    if ($Fake) { return @(F-Rows 'services') }
    $s = @()
    if (Test-CcCommand 'Get-WmiObject') { $s = @(Get-WmiObject -Class Win32_Service -ErrorAction SilentlyContinue) } else { $s = @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue) }  # ps2-ok
    return @($s | Where-Object { $_.StartMode -ne 'Disabled' } | ForEach-Object { New-Object PSObject -Property @{ Id = $_.Name; Name = ($_.Name + ' (' + $_.DisplayName + ')'); Run = (Nz $_.PathName); Extra = ($_.StartMode + '|' + $_.State) } })
}
function R-Wmi {
    if ($Fake) { return @(F-Rows 'wmi') }
    $out = @()
    try {
        $cons = @{}
        foreach ($c in @(Get-WmiObject -Namespace root\subscription -Class __EventConsumer -ErrorAction Stop)) {
            $what = Nz $c.CommandLineTemplate; if (-not $what) { $what = Nz $c.ScriptText }; if (-not $what) { $what = Nz $c.ExecutablePath }
            $cons[$c.__RELPATH] = $what
        }
        foreach ($b in @(Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction Stop)) {
            $cp = [string]$b.Consumer; $rel = $cp.Substring($cp.IndexOf(':') + 1)
            $run = $cons[$rel]; if (-not $run) { $run = $rel }
            $out += New-Object PSObject -Property @{ Id = [string]$b.__PATH; Name = ($rel + ' <- ' + (([string]$b.Filter) -replace '^.*:', '')); Run = $run; Extra = ([string]$b.Filter + '|' + $cp) }
        }
    } catch { Write-CcLog -Level WARN -Message ('WMI subscriptions not read: ' + $_.Exception.Message) }
    return $out
}
$IfeoKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
$LogonScreen = @('sethc.exe', 'utilman.exe', 'osk.exe', 'magnify.exe', 'narrator.exe', 'displayswitch.exe', 'atbroker.exe')
function R-Ifeo {
    if ($Fake) { return @(F-Rows 'ifeo') }
    $out = @()
    foreach ($k in @(Get-ChildItem -LiteralPath $IfeoKey -ErrorAction SilentlyContinue)) {
        $d = $k.GetValue('Debugger')
        if ($d) { $out += New-Object PSObject -Property @{ Id = $k.PSChildName; Name = $k.PSChildName; Run = [string]$d; Extra = '' } }
    }
    return $out
}
function R-Admins {
    if ($Fake) { return @(F-Rows 'admins') }
    $out = @()
    foreach ($g in @('Administrators', 'Remote Desktop Users')) {
        try {
            $grp = [ADSI]('WinNT://' + $env:COMPUTERNAME + '/' + $g + ',group')
            foreach ($m in @($grp.psbase.Invoke('Members'))) {
                $p = [string]$m.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $m, $null)
                $n = ($p -replace '^WinNT://', '') -replace '/', '\'
                $sid = ''; try { $sid = (New-Object Security.Principal.SecurityIdentifier([byte[]]$m.GetType().InvokeMember('objectSid', 'GetProperty', $null, $m, $null), 0)).Value } catch { }
                $out += New-Object PSObject -Property @{ Id = ($g + '|' + $n); Name = ($n + ' in ' + $g); Run = ''; Extra = $sid }
            }
        } catch { }
    }
    return $out
}

# ---- Look ----------------------------------------------------------------------------
$finds = New-Object System.Collections.ArrayList
function Find([string]$lvl, [string]$area, $row, [string]$why, [string]$fix) {
    $ex = $false; foreach ($e in $Exclude) { if ((Lc $row.Name).Contains($e) -or (Lc $row.Id).Contains($e)) { $ex = $true } }
    if ($ex) { Write-CcShow -Color DarkGray -Text ('  [-] {0}: {1} - left (-Exclude)' -f $area, $row.Name); return }
    $pr = $false
    if ($script:Cc.Protected) {
        $acct = (($row.Name -split ' in ')[0] -replace '^.*\\', '')
        foreach ($t in @(@('path', $row.Run), @('service', $row.Id), @('account', $acct), @('process', $row.Id))) { if ($t[1] -and (Test-CcProtected -Type $t[0] -Value $t[1])) { $pr = $true } }
    }
    if ($pr) {
        Write-CcShow -Color DarkGray -Text ('  [-] {0}: {1} - left (protected list)' -f $area, $row.Name); return
    }
    [void]$finds.Add((New-Object PSObject -Property @{ Level = $lvl; Area = $area; Row = $row; Why = $why; Fix = $fix; Done = '' }))
}
$counts = @{}
if (Want 'tasks') {
    $rows = @(R-Tasks); $counts['tasks'] = $rows.Count
    foreach ($t in $rows) {
        $j = Judge $t.Run
        if ($j[0] -eq 'LOW' -and -not ((Lc $t.Name).StartsWith('\microsoft\'))) { $j = @('LOW', 'not one of Windows'' own tasks') }
        if ($j[0] -eq 'LOW' -and (Lc $t.Name).StartsWith('\microsoft\')) { continue }
        Find $j[0] 'tasks' $t $j[1] ('disable the task ' + $t.Name)
    }
}
if (Want 'runkeys') { $rows = @(R-RunKeys); $counts['runkeys'] = $rows.Count; foreach ($r in $rows) { $j = Judge $r.Run; Find $j[0] 'runkeys' $r $(if ($j[1]) { $j[1] } else { 'starts at every logon' }) ('remove the Run value ' + $r.Name) } }
if (Want 'startup') { $rows = @(R-Startup); $counts['startup'] = $rows.Count; foreach ($r in $rows) { $j = Judge $r.Run; $l = $j[0]; if ($l -eq 'LOW' -and $r.Run -match '\.(bat|cmd|ps1|vbs|js|hta|exe)$') { $l = 'MED' }; Find $l 'startup' $r $(if ($j[1]) { $j[1] } else { 'starts at every logon' }) ('quarantine ' + $r.Name) } }
if (Want 'winlogon') {
    $rows = @(R-Winlogon); $counts['winlogon'] = $rows.Count
    foreach ($r in $rows) { if ((Lc $r.Run).TrimEnd(',', ' ') -ne (Lc $WinlogonOk[$r.Id]).TrimEnd(',', ' ')) { Find 'HIGH' 'winlogon' $r ('changed from Windows'' own (' + $WinlogonOk[$r.Id] + '): runs at every logon') ('set ' + $r.Id + ' back to ' + $WinlogonOk[$r.Id]) } }
}
if (Want 'services') { $rows = @(R-Services); $counts['services'] = $rows.Count; foreach ($r in $rows) { $j = Judge $r.Run; if ($j[0] -ne 'LOW') { Find $j[0] 'services' $r $j[1] ('disable and stop the service ' + $r.Id) } } }
if (Want 'wmi') { $rows = @(R-Wmi); $counts['wmi'] = $rows.Count; foreach ($r in $rows) { $j = Judge $r.Run; $l = 'HIGH'; $w = 'a WMI event subscription runs this'; if ($j[1]) { $w += ': ' + $j[1] }; Find $l 'wmi' $r $w ('remove the WMI binding ' + $r.Name) } }
if (Want 'ifeo') {
    $rows = @(R-Ifeo); $counts['ifeo'] = $rows.Count
    foreach ($r in $rows) {
        if ($LogonScreen -contains (Lc $r.Id)) { Write-CcShow -Color Red -Text ('  [!] ifeo: {0} runs {1} instead (a logon-screen backdoor): WN-43 removes it' -f $r.Id, $r.Run); continue }
        Find 'HIGH' 'ifeo' $r ('runs instead of ' + $r.Id) ('remove the debugger on ' + $r.Id)
    }
}
if (Want 'admins') {
    if ($IsDC) { Write-CcShow -Color DarkGray -Text '  [-] admins: a domain controller - the admin groups are WN-23''s' }
    else {
        $rows = @(R-Admins); $counts['admins'] = $rows.Count
        foreach ($r in $rows) {
            $acct = Lc (($r.Name -split ' in ')[0] -replace '^.*\\', '')
            if ($acct -eq $Me -or ($r.Extra -like '*-500') -or @('domain admins', 'administrator') -contains $acct) { continue }
            Find 'MED' 'admins' $r 'can log in as an administrator or by Remote Desktop: yours?' ('remove ' + $r.Name.Replace(' in ', ' from '))
        }
    }
}
$order = @{ HIGH = 1; MED = 2; LOW = 3 }
$sorted = @($finds | Sort-Object @{ Expression = { $order[$_.Level] } }, Area, @{ Expression = { $_.Row.Name } })
foreach ($a in $areaL) { if ($counts.ContainsKey($a)) { Write-CcShow -Text ('  {0,-9} {1} read' -f $a, $counts[$a]) } }
foreach ($x in $sorted) {
    $c = @{ HIGH = 'Red'; MED = 'Yellow'; LOW = 'DarkGray' }[$x.Level]; $m = @{ HIGH = '[!]'; MED = '[*]'; LOW = '[-]' }[$x.Level]
    $run = $x.Row.Run; if ($run.Length -gt 110) { $run = $run.Substring(0, 107) + '...' }
    Write-CcShow -Color $c -Text ('  {0} {1,-4} {2}: {3}{4}' -f $m, $x.Level, $x.Area, $x.Row.Name, $(if ($x.Why) { ' - ' + $x.Why } else { '' }))
    if ($run -and $run -ne $x.Row.Name) { Write-CcShow -Color DarkGray -Text ('        runs: ' + $run) }
}
if ($sorted.Count -eq 0) { Write-CcShow -Color Green -Text '  [ok] nothing found' }

# ---- 2/4 Questions -------------------------------------------------------------------
Write-CcHeader '2/4  questions (Enter = the default in capitals)'
$ask = @($sorted | Where-Object { $_.Level -ne 'LOW' })
$rest = $false
foreach ($x in $ask) {
    $d = 'k'; if ($x.Level -eq 'HIGH') { $d = 'r' }
    $ch = $d
    if (-not $rest -and (Test-CcCanAsk)) {
        $ch = Read-CcChoice -Question ('{0} {1}: {2}?' -f $x.Level, $x.Area, $x.Row.Name) -Default $d -Options @(('r=remove: ' + $x.Fix), 'k=keep it', 'a=all the rest: their default (HIGH removed, MED kept)')
        if ($ch -eq 'a') { $rest = $true; $ch = $d }
    } elseif (-not (Test-CcCanAsk)) { Write-CcShow -Color Cyan -Text ('[?] {0}: {1} -> {2} (default)' -f $x.Area, $x.Row.Name, $(if ($d -eq 'r') { 'remove' } else { 'keep' })) }
    $x.Done = $(if ($ch -eq 'r') { 'chosen' } else { 'kept' })
}
$todo = @($ask | Where-Object { $_.Done -eq 'chosen' })
if ($todo.Count -gt 0 -and -not $Cc.Apply -and (Test-CcCanAsk)) {
    if (Read-CcAsk -Question ('Apply these {0} change(s)?' -f $todo.Count) -Default N -Yes 'yes, remove them now (a revert timer runs)' -No 'no, change nothing (dry run)') {
        if (-not $Cc.Protected -and -not $Cc.NoProtected) {
            Write-CcShow -Color Yellow -Text '[*] No protected list (the scored services, accounts and paths).'
            if (Read-CcAsk -Question 'Remove them without one?' -Default N -Yes 'yes, go on without a protected list' -No 'no, stop') { $Cc.NoProtected = $true; $Cc.Apply = $true }
        } else { $Cc.Apply = $true }
        if ($Cc.Apply -and -not $Fake) { Assert-CcAdmin }
    }
}

# ---- Changing (each with its undo line) ----------------------------------------------
# Stand-in: the row's state goes 'off'; the undo turns it back 'on'.
function F-Off([string]$area, [string]$id) {
    $f = Join-Path $Fake ($area + '.csv')
    Add-CcUndo -Description ('{0} {1} back' -f $area, $id) -Command ('$f = ' + (Q $f) + '; $r = @(Import-Csv -LiteralPath $f); foreach ($x in $r) { if ($x.id -eq ' + (Q $id) + ') { $x.state = ''on'' } }; $r | Export-Csv -LiteralPath $f -NoTypeInformation')
    $rows = @(Import-Csv -LiteralPath $f); foreach ($x in $rows) { if ($x.id -eq $id) { $x.state = 'off' } }; $rows | Export-Csv -LiteralPath $f -NoTypeInformation
}
function Do-Fix($x) {
    $r = $x.Row
    if ($Fake) { F-Off $x.Area $r.Id; return }
    switch ($x.Area) {
        'tasks' {
            Add-CcUndo -Description ('enable the task ' + $r.Id) -Command ('schtasks.exe /change /tn ' + (Q $r.Id) + ' /enable')
            $o = Invoke-CcProgram -FilePath 'schtasks.exe' -Arguments @('/change', '/tn', $r.Id, '/disable'); if ($LASTEXITCODE -ne 0) { throw ($o -join ' ') }
        }
        'runkeys' {
            $p = $r.Id -split '\|', 2
            Add-CcUndo -Description ('the Run value ' + $p[1] + ' back') -Command ('New-ItemProperty -LiteralPath ' + (Q $p[0]) + ' -Name ' + (Q $p[1]) + ' -Value ' + (Q $r.Run) + ' -Force | Out-Null')
            Remove-ItemProperty -LiteralPath $p[0] -Name $p[1] -ErrorAction Stop
        }
        'startup' { if (-not (Move-CcQuarantine -Path $r.Id)) { throw 'quarantine failed' } }
        'winlogon' {
            Add-CcUndo -Description ($r.Id + ' back') -Command ('Set-ItemProperty -LiteralPath ' + (Q $WinlogonKey) + ' -Name ' + (Q $r.Id) + ' -Value ' + (Q $r.Run))
            Set-ItemProperty -LiteralPath $WinlogonKey -Name $r.Id -Value $WinlogonOk[$r.Id] -ErrorAction Stop
        }
        'services' {
            $p = $r.Extra -split '\|', 2; $mode = @{ Auto = 'auto'; Manual = 'demand'; Boot = 'boot'; System = 'system' }[$p[0]]; if (-not $mode) { $mode = 'demand' }
            $u = 'sc.exe config ' + (Q $r.Id) + ' start= ' + $mode; if ($p[1] -eq 'Running') { $u += '; sc.exe start ' + (Q $r.Id) }
            Add-CcUndo -Description ('the service ' + $r.Id + ' back') -Command $u
            [void](Invoke-CcProgram -FilePath 'sc.exe' -Arguments @('config', $r.Id, 'start=', 'disabled')); if ($LASTEXITCODE -ne 0) { throw 'sc config failed' }
            [void](Invoke-CcProgram -FilePath 'sc.exe' -Arguments @('stop', $r.Id))
        }
        'wmi' {
            $p = $r.Extra -split '\|', 2
            Add-CcUndo -Description ('the WMI binding ' + $r.Name + ' back') -Command ('Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{ Filter = [wmi]' + (Q $p[0]) + '; Consumer = [wmi]' + (Q $p[1]) + ' } | Out-Null')
            ([wmi]$r.Id).Delete()
        }
        'ifeo' {
            $k = Join-Path $IfeoKey $r.Id
            Add-CcUndo -Description ('the debugger on ' + $r.Id + ' back') -Command ('Set-ItemProperty -LiteralPath ' + (Q $k) + ' -Name Debugger -Value ' + (Q $r.Run))
            Remove-ItemProperty -LiteralPath $k -Name Debugger -ErrorAction Stop
        }
        'admins' {
            $p = $r.Id -split '\|', 2; $n = $p[1]
            Add-CcUndo -Description ($n + ' back in ' + $p[0]) -Command ('net.exe localgroup ' + (Q $p[0]) + ' ' + (Q $n) + ' /add')
            [void](Invoke-CcProgram -FilePath 'net.exe' -Arguments @('localgroup', $p[0], $n, '/delete')); if ($LASTEXITCODE -ne 0) { throw 'net localgroup failed' }
        }
    }
}
Write-CcHeader $(if ($Cc.Apply) { '3/4  removing' } else { '3/4  dry run: nothing is changed' })
$ok = 0; $bad = 0
if ($todo.Count -eq 0) { Write-CcShow -Color Green -Text '  [ok] nothing to change' }
elseif (-not $Cc.Apply) {
    foreach ($x in $todo) { Write-CcShow -Color Yellow -Text ('  [~] ' + $x.Fix); $Cc.Would++; $x.Done = 'would ' + $x.Fix }
    Write-CcShow -Color DarkGray -Text '  Dry run: nothing was changed. Run again with -Apply.'
} else {
    if (-not $NoTimer) { Start-CcTimer -Seconds $Timer }
    foreach ($x in $todo) {
        $xx = $x
        if (Invoke-CcChange -Description $x.Fix -Action { Do-Fix $xx }) { $ok++; $x.Done = 'done: ' + $x.Fix; Write-CcShow -Color Green -Text ('  [+] ' + $x.Fix) }
        else { $bad++; $x.Done = 'FAILED: ' + $x.Fix; Write-CcShow -Color Red -Text ('  [x] FAILED: ' + $x.Fix) }
    }
}

# ---- 4/4 Summary -----------------------------------------------------------------------
$tab = New-CcTable -Name findings -Columns @('level', 'area', 'name', 'runs', 'why', 'done')
foreach ($x in $sorted) { Add-CcTableRow -File $tab -Values @($x.Level, $x.Area, $x.Row.Name, $x.Row.Run, $x.Why, $(if ($x.Done) { $x.Done } else { 'listed' })) }
Format-CcTable -File $tab
$sum = @()
$sum += ('WN-42 Windows persistence sweep  {0}  {1}' -f [DateTime]::UtcNow.ToString("yyyy-MM-dd HH:mm 'UTC'"), $(if ($Cc.Apply) { 'APPLIED' } else { 'DRY RUN' }))
$sum += ('Areas: {0}' -f ($areaL -join ' '))
$sum += ('Found: {0} HIGH, {1} MED, {2} LOW (LOW only in findings.txt)' -f @($sorted | Where-Object { $_.Level -eq 'HIGH' }).Count, @($sorted | Where-Object { $_.Level -eq 'MED' }).Count, @($sorted | Where-Object { $_.Level -eq 'LOW' }).Count)
foreach ($x in $ask) { $sum += ('  {0,-4} {1,-8} {2}  -> {3}' -f $x.Level, $x.Area, $x.Row.Name, $x.Done) }
if ($Cc.Apply) { $sum += ''; $sum += ('Done: {0}   Failed: {1}' -f $ok, $bad) }
$sum += ''
$sum += 'Also: sticky keys and logon-screen debuggers WN-43; AD admins WN-23; passwords WN-20.'
[IO.File]::WriteAllLines((Join-Path $Cc.RunDir 'summary.txt'), [string[]]$sum)
Write-CcHeader '4/4  summary'
foreach ($l in $sum) {
    $col = ''
    if ($l -like 'WN-42 *') { $col = 'Cyan' } elseif ($l -like '  HIGH*' -or $l -like '*FAILED*') { $col = 'Red' } elseif ($l -like '  MED*') { $col = 'Yellow' }
    Write-CcShow -Color $col -Text $l
}
if ($Cc.Apply -and $todo.Count -gt 0 -and -not $NoTimer) { [void](Complete-CcTimer) }
Write-Host ('All results: ' + $Cc.RunDir)   # always shown, even with -Quiet
if ($bad -gt 0) { Complete-Cc -ExitCode 5 }
Complete-Cc
