# =============================================================================
# ID:       WN-44
# NAME:     Windows alerts
# ROLE:     Windows / AD
# KIND:     readonly
#
# PURPOSE
#   Watches the Windows changes Red Team commonly makes: accounts/admins,
#   services, scheduled tasks, listeners, firewall/Defender state and high-value
#   Security/System/PowerShell events. It never blocks or kills anything.
#
# USAGE
#   powershell -NoProfile -ExecutionPolicy Bypass -File WN-44-windows-alerts.ps1 -Out C:\ccdc-out
#   powershell ... WN-44-windows-alerts.ps1 -Out C:\ccdc-out -Loop 30 -SendTo \\jumpbox\alerts
#
# OUTPUTS
#   baseline\, current\, alerts.txt, events.txt and summary.txt in one numbered
#   run folder. -SendTo copies the small alert files off-host after each check.
#
# WHAT IT CHANGES
#   Nothing on the monitored host. It only writes under -Out and optionally an
#   operator-provided alert share.
#
# DEPENDS ON
#   WMI, netstat, net.exe, schtasks.exe, netsh.exe and wevtutil.exe.
#
# TESTED ON
#   Syntax and option behavior under PowerShell 7. Not yet endurance-tested on
#   real Server 2016/2019; run it on a disposable VM first.
# =============================================================================
param(
    [switch]$Apply, [string]$Out, [string]$Protected, [switch]$NoProtected,
    [switch]$ForceScored, [switch]$Quiet, [switch]$DebugLog,
    [int]$Loop = 0,
    [int]$EventHours = 1,
    [switch]$NoEvents,
    [string]$SendTo = '',
    [string[]]$AdminFrom = @(),
    [switch]$Accept,
    [switch]$Help
)

if ($Help) {
    Write-Host 'WN-44 Windows alerts - accounts, admins, services, tasks, listeners, firewall, Defender and event logs'
    Write-Host '  -Loop N       repeat every N seconds (0 = one check)'
    Write-Host '  -EventHours N first-run event look-back (default 1)'
    Write-Host '  -NoEvents     skip event-log queries (fast state-only check)'
    Write-Host '  -SendTo PATH  copy alerts.txt and events.txt to an off-host share'
    Write-Host '  -Accept       replace the saved baseline after this check'
    Write-Host '  -AdminFrom IP[,IP] quiet expected remote-admin addresses in event notes'
    exit 0
}
if ($Apply) { Write-Host 'WN-44 is read-only; do not use -Apply'; exit 2 }
if ($Loop -ne 0 -and $Loop -lt 10) { Write-Host '-Loop must be 0 or at least 10 seconds'; exit 2 }
if ($EventHours -lt 1 -or $EventHours -gt 168) { Write-Host '-EventHours must be 1..168'; exit 2 }

# >>> CCDC-LIB
$ccDir = Split-Path -Parent $MyInvocation.MyCommand.Path
while ($ccDir -and -not (Test-Path -LiteralPath (Join-Path (Join-Path $ccDir 'lib') 'lib.ps1'))) { $ccDir = Split-Path -Parent $ccDir }
if (-not $ccDir) { Write-Host 'cannot find lib/lib.ps1 above this script'; exit 3 }
. (Join-Path (Join-Path $ccDir 'lib') 'lib.ps1')
# <<< CCDC-LIB

Initialize-Cc -Id 'WN-44' -Name 'Windows alerts' -Kind readonly -Bound $PSBoundParameters
Use-CcRunDir
$baseDir = Join-Path $Cc.RunDir 'baseline'
$prevDir = Join-Path $Cc.RunDir 'previous'
$curDir = Join-Path $Cc.RunDir 'current'
New-Item -ItemType Directory -Path $baseDir -Force | Out-Null
New-Item -ItemType Directory -Path $prevDir -Force | Out-Null
New-Item -ItemType Directory -Path $curDir -Force | Out-Null
$alertsFile = Join-Path $Cc.RunDir 'alerts.txt'
$eventsFile = Join-Path $Cc.RunDir 'events.txt'
$cursorFile = Join-Path $Cc.RunDir 'event-cursor.txt'
$AdminFrom = @(@($AdminFrom) | Where-Object { $_ } | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })

function Write-CsvObjects([string]$path, [object[]]$objects, [string[]]$props) {
    $lines = @()
    if (@($objects).Count -gt 0) { $lines = @($objects | Select-Object -Property $props | ConvertTo-Csv -NoTypeInformation) }
    else { $lines = @(ConvertTo-CcCsvLine -Values $props) }
    [IO.File]::WriteAllLines($path, [string[]]$lines)
}
function Cmd-Lines([string]$file, [string[]]$args) {
    if (-not (Get-Command $file -ErrorAction SilentlyContinue)) { return @() }
    return @(& $file @args 2>$null | ForEach-Object { ([string]$_).TrimEnd() } | Where-Object { $_ })
}
function Snapshot([string]$dir) {
    # Local users/groups work on old Windows. Domain changes are also captured
    # by the Security event stream on a DC.
    [IO.File]::WriteAllLines((Join-Path $dir 'users.txt'), [string[]](Cmd-Lines 'net.exe' @('user')))
    [IO.File]::WriteAllLines((Join-Path $dir 'admins.txt'), [string[]](Cmd-Lines 'net.exe' @('localgroup','Administrators')))
    try {
        $services = @(Get-WmiObject Win32_Service -ErrorAction Stop)
        Write-CsvObjects (Join-Path $dir 'services.csv') $services @('Name','State','StartMode','StartName','PathName')
    } catch { [IO.File]::WriteAllText((Join-Path $dir 'services.error.txt'), $_.Exception.Message) }
    [IO.File]::WriteAllLines((Join-Path $dir 'tasks.txt'), [string[]](Cmd-Lines 'schtasks.exe' @('/query','/fo','csv','/v')))
    [IO.File]::WriteAllLines((Join-Path $dir 'netstat.txt'), [string[]](Cmd-Lines 'netstat.exe' @('-ano')))
    [IO.File]::WriteAllLines((Join-Path $dir 'firewall.txt'), [string[]](Cmd-Lines 'netsh.exe' @('advfirewall','show','allprofiles')))
    $def = @()
    try {
        if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) { # ps2-ok
            $def = @(Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,BehaviorMonitorEnabled,RealTimeProtectionEnabled,IoavProtectionEnabled,NISEnabled) # ps2-ok
        } else {
            # Server 2008 R2 / PowerShell 2 fallback: record the Defender service
            # state. It has less detail but still detects a stopped/disabled AV.
            $svc = @(Get-WmiObject Win32_Service -Filter "Name='WinDefend'" -ErrorAction SilentlyContinue)
            if ($svc.Count -gt 0) {
                $on = ($svc[0].State -eq 'Running' -and $svc[0].StartMode -ne 'Disabled')
                $def = @(New-Object PSObject -Property @{ AMServiceEnabled=$on; AntivirusEnabled=$on; BehaviorMonitorEnabled='unknown'; RealTimeProtectionEnabled='unknown'; IoavProtectionEnabled='unknown'; NISEnabled='unknown' })
            }
        }
    } catch { }
    Write-CsvObjects (Join-Path $dir 'defender.csv') $def @('AMServiceEnabled','AntivirusEnabled','BehaviorMonitorEnabled','RealTimeProtectionEnabled','IoavProtectionEnabled','NISEnabled')
}
function Normalize-Line([string]$line) {
    # Remove volatile netstat connection rows: listeners are the durable signal.
    if ($line -match '(?i)ESTABLISHED|TIME_WAIT|CLOSE_WAIT|SYN_SENT') { return '' }
    return $line.Trim()
}
function Compare-Snapshot([string]$oldDir, [string]$newDir) {
    $items = @('users.txt','admins.txt','services.csv','tasks.txt','netstat.txt','firewall.txt','defender.csv')
    $found = @()
    foreach ($name in $items) {
        $aPath = Join-Path $oldDir $name; $bPath = Join-Path $newDir $name
        $a = @(); $b = @()
        if (Test-Path -LiteralPath $aPath) { $a = @([IO.File]::ReadAllLines($aPath) | ForEach-Object { Normalize-Line $_ } | Where-Object { $_ }) }
        if (Test-Path -LiteralPath $bPath) { $b = @([IO.File]::ReadAllLines($bPath) | ForEach-Object { Normalize-Line $_ } | Where-Object { $_ }) }
        foreach ($d in @(Compare-Object -ReferenceObject $a -DifferenceObject $b)) {
            $direction = 'removed'; if ($d.SideIndicator -eq '=>') { $direction = 'added' }
            $sev = 'MED'
            if ($name -eq 'admins.txt' -or $name -eq 'defender.csv' -or $name -eq 'firewall.txt') { $sev = 'HIGH' }
            if ($name -eq 'services.csv' -and $direction -eq 'added') { $sev = 'HIGH' }
            if ($name -eq 'netstat.txt' -and $direction -eq 'added') { $sev = 'HIGH' }
            $found += ("{0}`t{1}`t{2}`t{3}" -f $sev,$name,$direction,([string]$d.InputObject))
        }
    }
    return $found
}
function Event-Text {
    if ($NoEvents) { return @() }
    if (-not (Get-Command wevtutil.exe -ErrorAction SilentlyContinue)) { return @() }
    $ms = $EventHours * 60 * 60 * 1000
    if (Test-Path -LiteralPath $cursorFile) {
        $then = [DateTime]::Parse([IO.File]::ReadAllText($cursorFile)).ToUniversalTime()
        $ms = [int][Math]::Max(1000,([DateTime]::UtcNow - $then).TotalMilliseconds)
    }
    $out = @()
    $sets = @(
        @('Security','4624,4625,4672,4697,4698,4702,4719,4720,4722,4724,4725,4726,4728,4732,4738,4756,4765,4766,1102'),
        @('System','7040,7045,7036'),
        @('Microsoft-Windows-Windows Defender/Operational','5001,5007,5010'),
        @('Microsoft-Windows-PowerShell/Operational','4103,4104')
    )
    foreach ($set in $sets) {
        $expr = ($set[1] -split ',' | ForEach-Object { 'EventID=' + $_ }) -join ' or '
        $q = "*[System[(($expr)) and TimeCreated[timediff(@SystemTime) <= $ms]]]"
        $lines = @(& wevtutil.exe qe $set[0] "/q:$q" /f:text 2>$null | ForEach-Object { [string]$_ })
        if ($lines.Count -gt 0) { $out += ('===== ' + $set[0] + ' ====='); $out += $lines }
    }
    [IO.File]::WriteAllText($cursorFile, [DateTime]::UtcNow.ToString('o'))
    return $out
}
function Copy-Alerts {
    if (-not $SendTo) { return }
    try {
        if (-not (Test-Path -LiteralPath $SendTo)) { New-Item -ItemType Directory -Path $SendTo -Force | Out-Null }
        $stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
        if (Test-Path -LiteralPath $alertsFile) { Copy-Item -LiteralPath $alertsFile -Destination (Join-Path $SendTo ($env:COMPUTERNAME + '-alerts-' + $stamp + '.txt')) -Force }
        if (Test-Path -LiteralPath $eventsFile) { Copy-Item -LiteralPath $eventsFile -Destination (Join-Path $SendTo ($env:COMPUTERNAME + '-events-' + $stamp + '.txt')) -Force }
    } catch { Write-CcLog -Level WARN -Message ('could not copy alerts off-host: ' + $_.Exception.Message) }
}

Snapshot $curDir
$hasBase = Test-Path -LiteralPath (Join-Path $baseDir 'users.txt')
if (-not $hasBase) {
    foreach ($f in @(Get-ChildItem -LiteralPath $curDir | Where-Object { -not $_.PSIsContainer })) { Copy-Item -LiteralPath $f.FullName -Destination (Join-Path $baseDir $f.Name) -Force }
    foreach ($f in @(Get-ChildItem -LiteralPath $curDir | Where-Object { -not $_.PSIsContainer })) { Copy-Item -LiteralPath $f.FullName -Destination (Join-Path $prevDir $f.Name) -Force }
    Write-CcLog -Level INFO -Message 'baseline created; later checks report differences from it'
}

$checks = 0; $totalAlerts = 0
do {
    if ($checks -gt 0) { Start-Sleep -Seconds $Loop; Snapshot $curDir }
    $stamp = [DateTime]::UtcNow.ToString('s') + 'Z'
    # Compare to the immediately previous check so each change is reported
    # once. The original baseline remains available for incident review.
    $changes = @(Compare-Snapshot $prevDir $curDir)
    $events = @(Event-Text)
    if ($changes.Count -gt 0) {
        [IO.File]::AppendAllText($alertsFile, ("===== $stamp =====`r`n" + ($changes -join "`r`n") + "`r`n"))
        foreach ($c in $changes) { if ($c -like 'HIGH*') { Write-Host ('[!] ' + $c) } else { Write-Host ('[*] ' + $c) } }
        $totalAlerts += $changes.Count
    }
    if ($events.Count -gt 0) { [IO.File]::AppendAllText($eventsFile, ("===== $stamp =====`r`n" + ($events -join "`r`n") + "`r`n")) }
    Copy-Alerts
    if ($Accept) {
        foreach ($f in @(Get-ChildItem -LiteralPath $curDir | Where-Object { -not $_.PSIsContainer })) { Copy-Item -LiteralPath $f.FullName -Destination (Join-Path $baseDir $f.Name) -Force }
        Write-CcLog -Level INFO -Message 'current state accepted as the new baseline'
    }
    foreach ($f in @(Get-ChildItem -LiteralPath $curDir | Where-Object { -not $_.PSIsContainer })) { Copy-Item -LiteralPath $f.FullName -Destination (Join-Path $prevDir $f.Name) -Force }
    $checks++
} while ($Loop -gt 0)

$summary = @('WN-44 Windows alerts',('Checks: ' + $checks),('State changes reported: ' + $totalAlerts),('Alerts: ' + $alertsFile),('Events: ' + $eventsFile),'Next: verify the requester and service dependency; follow docs/RESPONSE-MATRIX.md before containment.',('All results: ' + $Cc.RunDir))
[IO.File]::WriteAllLines((Join-Path $Cc.RunDir 'summary.txt'), [string[]]$summary)
foreach ($line in $summary) { Write-Host $line }
Complete-Cc
